use crate::fs::InMemoryFS;
use crate::log::summary::{SUMMARY_FOOTER_SIZE, SUMMARY_MAGIC, SummaryFooter};
use crate::remote::config::{ConfiguredRemote, RemoteMode, RemoteRegistry};
use crate::remote::{RemoteObject, RemoteStore};
use crate::storage::Storage;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime};

/// Helper to stream a file from local `Storage` to a `RemoteStore`.
pub fn upload_storage_file(
    storage: &dyn Storage,
    remote: &dyn RemoteStore,
    filename: &str,
    expected_md5: Option<&[u8; 16]>,
) -> io::Result<()> {
    let reader = storage.open_reader(filename)?;
    let len = reader.len()?;

    struct StorageReadAdapter<'a> {
        reader: &'a dyn crate::storage::StorageReader,
        offset: u64,
        total_len: u64,
    }

    impl<'a> Read for StorageReadAdapter<'a> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.offset >= self.total_len {
                return Ok(0);
            }
            let to_read = (buf.len() as u64).min(self.total_len - self.offset) as usize;
            self.reader.read_exact_at(self.offset, &mut buf[..to_read])?;
            self.offset += to_read as u64;
            Ok(to_read)
        }
    }

    let mut adapter = StorageReadAdapter {
        reader: reader.as_ref(),
        offset: 0,
        total_len: len,
    };

    remote.put_object(filename, &mut adapter, len, expected_md5)
}

struct StreamingMd5Writer<W: Write> {
    inner: W,
    hasher: md5::Context,
    bytes_written: u64,
}

impl<W: Write> StreamingMd5Writer<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: md5::Context::new(),
            bytes_written: 0,
        }
    }

    fn finish(mut self) -> io::Result<(W, u64, [u8; 16])> {
        self.inner.flush()?;
        let digest = *self.hasher.compute();
        Ok((self.inner, self.bytes_written, digest))
    }
}

impl<W: Write> Write for StreamingMd5Writer<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        let chunk = &buf[..n];
        self.hasher.consume(chunk);
        self.bytes_written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Helper to cross-copy a log file from one `RemoteStore` to another using streaming with inline MD5 verification.
pub fn cross_copy_file(
    src_remote: &dyn RemoteStore,
    dst_remote: &dyn RemoteStore,
    filename: &str,
    expected_len: u64,
    expected_md5: &[u8; 16],
) -> io::Result<()> {
    let dir = tempfile::tempdir()?;
    let tmp_file_path = dir.path().join(filename);

    let (tmp_file, bytes_written, computed_md5) = {
        let file = std::fs::File::create(&tmp_file_path)?;
        let mut writer = StreamingMd5Writer::new(file);
        src_remote.get_object(filename, &mut writer)?;
        writer.finish()?
    };

    if bytes_written != expected_len {
        let _ = std::fs::remove_file(&tmp_file_path);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "cross_copy_file {}: downloaded size {} does not match expected {}",
                filename, bytes_written, expected_len
            ),
        ));
    }

    if &computed_md5 != expected_md5 {
        let _ = std::fs::remove_file(&tmp_file_path);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "cross_copy_file {}: downloaded MD5 {} does not match expected {}",
                filename,
                hex::encode(computed_md5),
                hex::encode(expected_md5)
            ),
        ));
    }

    drop(tmp_file);
    let mut read_file = std::fs::File::open(&tmp_file_path)?;
    dst_remote.put_object(filename, &mut read_file, expected_len, Some(expected_md5))?;
    Ok(())
}

struct SummaryStreamingVerifier<W: Write> {
    inner: W,
    md5_hasher: md5::Context,
    blake3_hasher: blake3::Hasher,
    tail_buf: Vec<u8>,
    total_bytes: u64,
}

impl<W: Write> SummaryStreamingVerifier<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            md5_hasher: md5::Context::new(),
            blake3_hasher: blake3::Hasher::new(),
            tail_buf: Vec::with_capacity(SUMMARY_FOOTER_SIZE),
            total_bytes: 0,
        }
    }

    fn finish(mut self, expected_len: u64, filename: &str) -> io::Result<(W, u64, [u8; 16])> {
        self.inner.flush()?;

        if self.total_bytes != expected_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "cross_copy_summary {}: downloaded size {} does not match expected {}",
                    filename, self.total_bytes, expected_len
                ),
            ));
        }

        if self.total_bytes < SUMMARY_FOOTER_SIZE as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "cross_copy_summary {}: file size {} is smaller than footer size {}",
                    filename, self.total_bytes, SUMMARY_FOOTER_SIZE
                ),
            ));
        }

        if self.tail_buf.len() != SUMMARY_FOOTER_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "cross_copy_summary {}: tail buffer has {} bytes, expected {}",
                    filename,
                    self.tail_buf.len(),
                    SUMMARY_FOOTER_SIZE
                ),
            ));
        }

        let footer = SummaryFooter::from_bytes(&self.tail_buf).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("cross_copy_summary {}: failed to parse summary footer: {}", filename, e),
            )
        })?;

        if footer.magic != *SUMMARY_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("cross_copy_summary {}: invalid magic {:?}", filename, footer.magic),
            ));
        }

        let computed_checksum: [u8; 32] = *self.blake3_hasher.finalize().as_bytes();
        if computed_checksum != footer.checksum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "cross_copy_summary {}: BLAKE3 checksum mismatch: expected {}, got {}",
                    filename,
                    hex::encode(footer.checksum),
                    hex::encode(computed_checksum)
                ),
            ));
        }

        let computed_md5 = *self.md5_hasher.compute();
        Ok((self.inner, self.total_bytes, computed_md5))
    }
}

impl<W: Write> Write for SummaryStreamingVerifier<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        let chunk = &buf[..n];

        self.md5_hasher.consume(chunk);
        self.total_bytes += n as u64;

        let total_avail = self.tail_buf.len() + n;
        if total_avail <= SUMMARY_FOOTER_SIZE {
            self.tail_buf.extend_from_slice(chunk);
        } else {
            let overflow = total_avail - SUMMARY_FOOTER_SIZE;
            let tail_len = self.tail_buf.len();
            if overflow <= tail_len {
                self.blake3_hasher.update(&self.tail_buf[..overflow]);
                self.tail_buf.drain(..overflow);
                self.tail_buf.extend_from_slice(chunk);
            } else {
                self.blake3_hasher.update(&self.tail_buf);
                self.tail_buf.clear();
                let from_chunk = overflow - tail_len;
                self.blake3_hasher.update(&chunk[..from_chunk]);
                self.tail_buf.extend_from_slice(&chunk[from_chunk..]);
            }
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Helper to cross-copy a `.summary` checkpoint file from one `RemoteStore` to another,
/// verifying its internal BLAKE3 signature streaming locally, and computing its MD5 to pass on upload.
pub fn cross_copy_summary(
    src_remote: &dyn RemoteStore,
    dst_remote: &dyn RemoteStore,
    filename: &str,
    expected_len: u64,
) -> io::Result<()> {
    let dir = tempfile::tempdir()?;
    let tmp_file_path = dir.path().join(filename);

    let (tmp_file, bytes_written, computed_md5) = {
        let file = std::fs::File::create(&tmp_file_path)?;
        let mut writer = SummaryStreamingVerifier::new(file);
        src_remote.get_object(filename, &mut writer)?;
        writer.finish(expected_len, filename)?
    };

    drop(tmp_file);
    let mut read_file = std::fs::File::open(&tmp_file_path)?;
    dst_remote.put_object(filename, &mut read_file, bytes_written, Some(&computed_md5))?;
    Ok(())
}

/// Reads a `.summary` file from local storage, verifying its BLAKE3 signature and computing its MD5 in a single pass.
pub fn verify_summary_storage_file(storage: &dyn Storage, filename: &str) -> io::Result<(u64, [u8; 16])> {
    let reader = storage.open_reader(filename)?;
    let len = reader.len()?;
    // `io::sink()` is the standard library null sink (zero-sized `/dev/null` writer)
    // that immediately discards written bytes without buffering or allocating memory.
    let mut verifier = SummaryStreamingVerifier::new(io::sink());
    let mut buf = [0u8; 64 * 1024];
    let mut offset = 0u64;
    while offset < len {
        let to_read = std::cmp::min((len - offset) as usize, buf.len());
        reader.read_exact_at(offset, &mut buf[..to_read])?;
        verifier.write_all(&buf[..to_read])?;
        offset += to_read as u64;
    }
    let (_, total_bytes, md5_digest) = verifier.finish(len, filename)?;
    Ok((total_bytes, md5_digest))
}

/// Live operational telemetry for a single remote target.
#[derive(Debug, Clone, Default)]
pub struct RemoteSyncTelemetry {
    pub name: String,
    pub synced_generation: u32,
    pub active_part: Option<(u32, u32)>,
    pub last_sync_time: Option<SystemTime>,
    pub last_error: Option<String>,
}

/// In-memory telemetry table capturing real-time replication status across all remotes.
#[derive(Debug, Default)]
pub struct ReplicationTelemetry {
    pub remotes: HashMap<String, RemoteSyncTelemetry>,
}

impl ReplicationTelemetry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_synced_gen(&mut self, remote_name: &str, generation_num: u32, now: SystemTime) {
        let entry = self
            .remotes
            .entry(remote_name.to_string())
            .or_insert_with(|| RemoteSyncTelemetry {
                name: remote_name.to_string(),
                ..Default::default()
            });
        if generation_num >= entry.synced_generation {
            entry.synced_generation = generation_num;
            entry.last_sync_time = Some(now);
            entry.last_error = None;
        }
    }

    pub fn record_active_part(&mut self, remote_name: &str, generation_num: u32, part_idx: u32, now: SystemTime) {
        let entry = self
            .remotes
            .entry(remote_name.to_string())
            .or_insert_with(|| RemoteSyncTelemetry {
                name: remote_name.to_string(),
                ..Default::default()
            });
        entry.active_part = Some((generation_num, part_idx));
        entry.last_sync_time = Some(now);
        entry.last_error = None;
    }

    pub fn record_error(&mut self, remote_name: &str, error: &str) {
        let entry = self
            .remotes
            .entry(remote_name.to_string())
            .or_insert_with(|| RemoteSyncTelemetry {
                name: remote_name.to_string(),
                ..Default::default()
            });
        entry.last_error = Some(error.to_string());
    }
}

/// Formats a complete human-readable report of replication status across all remotes.
pub fn format_remotes_status(fs: &InMemoryFS) -> String {
    let mut out = String::new();

    let manifest = fs.manifest.read().unwrap().clone();
    let head_gen = fs.log_writer.as_ref().map(|w| w.generation());
    let last_sealed_gen = manifest.logs.iter().map(|l| l.generation).max().unwrap_or(0);

    let head_gen_str = match head_gen {
        Some(head) => head.to_string(),
        None => "None (read-only / detached log writer)".to_string(),
    };

    let remotes_info = {
        let reg_lock = fs.remote_registry.read().unwrap();
        match reg_lock.as_ref() {
            Some(reg) => {
                let r = reg.read().unwrap();
                r.remotes.clone()
            }
            None => std::collections::BTreeMap::new(),
        }
    };

    if remotes_info.is_empty() {
        out.push_str("No remotes configured.\n\n");
        out.push_str(&format!("Volume Head Generation: {}\n", head_gen_str));
        out.push_str(&format!("Sealed Generations:     {}\n", last_sealed_gen));
        return out;
    }

    let telemetry_guard = fs.replication_telemetry.read().unwrap();
    let now = fs.clock.now();

    out.push_str(&format!(
        "=== Remote Status (Volume Head Generation: {}) ===\n\n",
        head_gen_str
    ));

    for (name, config) in &remotes_info {
        out.push_str(&format!("[Remote: {}]\n", name));

        let target_str = match (&config.bucket, &config.path) {
            (Some(b), _) => format!("s3 (bucket: {}, prefix: {})", b, config.prefix),
            (_, Some(p)) => format!("local/nfs ({})", p.display()),
            _ => "unknown".to_string(),
        };
        out.push_str(&format!("  Target:             {}\n", target_str));
        out.push_str(&format!("  Read Priority:      {}\n", config.read_priority));
        out.push_str(&format!("  Mode:               {}\n", config.mode));
        out.push_str(&format!(
            "  Partial Logs:       {}\n",
            if config.upload_partial_logs() {
                "Enabled"
            } else {
                "Disabled"
            }
        ));

        let telem = telemetry_guard.remotes.get(name);
        let synced_gen = telem.map_or(0, |t| t.synced_generation);
        let lag = last_sealed_gen.saturating_sub(synced_gen);

        let status_str = match config.mode {
            RemoteMode::ReadOnly => "Read-Only Upstream",
            RemoteMode::WriteOnly => {
                if lag == 0 {
                    "Up to date (Archive)"
                } else {
                    "Syncing (Archive)"
                }
            }
            RemoteMode::ReadWrite => {
                if lag == 0 {
                    "Up to date"
                } else {
                    "Syncing"
                }
            }
        };
        out.push_str(&format!("  Status:             {}\n", status_str));
        out.push_str(&format!("  Synced Generation:  {} / {}\n", synced_gen, last_sealed_gen));
        out.push_str(&format!("  Replication Lag:    {} sealed generation(s)\n", lag));

        if let Some(t) = telem {
            if let Some((part_gen, part)) = t.active_part {
                out.push_str(&format!("  Active Part:        {:06}.part{:04}.log\n", part_gen, part));
            }
            if let Some(t_time) = t.last_sync_time {
                let elapsed = now.duration_since(t_time).unwrap_or_default().as_secs();
                out.push_str(&format!("  Last Sync:          {}s ago\n", elapsed));
            }
            if let Some(ref err) = t.last_error {
                out.push_str(&format!("  Last Error:         {}\n", err));
            }
        }

        out.push('\n');
    }

    if let Some(cache) = fs.log_cache.as_ref().and_then(|lc| lc.block_cache.as_ref()) {
        let coalesced = cache.coalescer().coalesced_requests();
        let leader = cache.coalescer().leader_requests();
        if coalesced > 0 || leader > 0 {
            out.push_str("=== Remote Read Optimization ===\n");
            out.push_str(&format!("  Leader Fetches:     {}\n", leader));
            out.push_str(&format!(
                "  Coalesced Reads:    {} (saved network range requests)\n",
                coalesced
            ));
            out.push_str(&format!("  In-Flight Fetches:  {}\n", cache.coalescer().in_flight()));
            out.push('\n');
        }
    }

    out
}

/// Autonomous background replication and tiered pruning worker.
pub struct RemoteReplicationWorker {
    running: Arc<AtomicBool>,
    thread_handle: Option<JoinHandle<()>>,
    fs: Arc<InMemoryFS>,
    registry: Arc<RwLock<RemoteRegistry>>,
    log_dir: PathBuf,
}

/// Default background poll interval when no roll/summary events trigger replication (60 seconds).
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(60);

impl RemoteReplicationWorker {
    /// Starts the background replication worker thread with default 60-second interval.
    pub fn start(fs: Arc<InMemoryFS>, registry: Arc<RwLock<RemoteRegistry>>, log_dir: PathBuf) -> Self {
        Self::start_with_interval(fs, registry, log_dir, DEFAULT_POLL_INTERVAL)
    }

    /// Starts the background replication worker thread with a configurable maintenance poll interval.
    pub fn start_with_interval(
        fs: Arc<InMemoryFS>,
        registry: Arc<RwLock<RemoteRegistry>>,
        log_dir: PathBuf,
        poll_interval: Duration,
    ) -> Self {
        fs.set_remote_registry(Arc::clone(&registry));
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = Arc::clone(&running);
        let fs_clone = Arc::clone(&fs);
        let registry_clone = Arc::clone(&registry);
        let log_dir_clone = log_dir.clone();

        let thread_handle = thread::spawn(move || {
            let mut last_part_sync = fs_clone.clock.now();
            let mut uploaded_part_offsets: std::collections::HashMap<u32, (u64, u32)> =
                std::collections::HashMap::new();
            let mut last_audit = SystemTime::UNIX_EPOCH; // Run initial audit on startup
            let mut confirmed_generations: std::collections::HashMap<String, std::collections::HashSet<u32>> =
                std::collections::HashMap::new();
            let mut confirmed_summaries: std::collections::HashMap<String, std::collections::HashSet<String>> =
                std::collections::HashMap::new();

            let (notifier_lock, notifier_cvar) = &*fs_clone.replication_notifier;

            while running_clone.load(Ordering::SeqCst) {
                if let Err(e) = Self::run_cycle_with_audit(
                    &fs_clone,
                    &registry_clone,
                    &log_dir_clone,
                    &mut last_part_sync,
                    &mut uploaded_part_offsets,
                    &mut last_audit,
                    &mut confirmed_generations,
                    &mut confirmed_summaries,
                    false,
                ) {
                    log::warn!("Remote replication worker cycle error: {}", e);
                }

                // Wait on the replication notifier condition variable.
                // When a log rolls or summary exports, notify_replication() wakes this thread immediately!
                let check_slice = Duration::from_millis(100).min(poll_interval);
                let slices = (poll_interval.as_millis() / check_slice.as_millis().max(1)).max(1);
                for _ in 0..slices {
                    if !running_clone.load(Ordering::SeqCst) {
                        break;
                    }
                    let mut guard = notifier_lock.lock().unwrap();
                    if *guard {
                        *guard = false;
                        break;
                    }
                    let (new_guard, _) = notifier_cvar.wait_timeout(guard, check_slice).unwrap();
                    guard = new_guard;
                    if *guard {
                        *guard = false;
                        break;
                    }
                }
            }

            // Final drain cycle on unmount/shutdown
            log::info!("Flushing remaining remote sync tasks before shutdown...");
            let _ = Self::run_cycle_with_audit(
                &fs_clone,
                &registry_clone,
                &log_dir_clone,
                &mut last_part_sync,
                &mut uploaded_part_offsets,
                &mut last_audit,
                &mut confirmed_generations,
                &mut confirmed_summaries,
                true,
            );
        });

        Self {
            running,
            thread_handle: Some(thread_handle),
            fs,
            registry,
            log_dir,
        }
    }

    /// Explicitly and synchronously triggers an immediate remote replication cycle (fast path).
    pub fn sync_now(&self) -> io::Result<()> {
        self.sync_now_with_audit(false)
    }

    /// Explicitly and synchronously triggers an immediate remote replication cycle with full consistency audit.
    pub fn audit_now(&self) -> io::Result<()> {
        self.sync_now_with_audit(true)
    }

    pub fn sync_now_with_audit(&self, force_audit: bool) -> io::Result<()> {
        let mut last_part_sync = SystemTime::UNIX_EPOCH;
        let mut uploaded_parts = std::collections::HashMap::new();
        let mut last_audit = if force_audit {
            SystemTime::UNIX_EPOCH
        } else {
            self.fs.clock.now()
        };
        let mut confirmed_generations = std::collections::HashMap::new();
        let mut confirmed_summaries = std::collections::HashMap::new();
        Self::run_cycle_with_audit(
            &self.fs,
            &self.registry,
            &self.log_dir,
            &mut last_part_sync,
            &mut uploaded_parts,
            &mut last_audit,
            &mut confirmed_generations,
            &mut confirmed_summaries,
            force_audit,
        )
    }

    pub fn run_cycle(
        fs: &InMemoryFS,
        registry: &Arc<RwLock<RemoteRegistry>>,
        log_dir: &Path,
        last_part_sync: &mut SystemTime,
        uploaded_parts: &mut std::collections::HashMap<u32, (u64, u32)>,
    ) -> io::Result<()> {
        let mut last_audit = SystemTime::UNIX_EPOCH;
        let mut confirmed_generations = std::collections::HashMap::new();
        let mut confirmed_summaries = std::collections::HashMap::new();
        Self::run_cycle_with_audit(
            fs,
            registry,
            log_dir,
            last_part_sync,
            uploaded_parts,
            &mut last_audit,
            &mut confirmed_generations,
            &mut confirmed_summaries,
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    // TODO(too-many-lines): extract this into smaller units.
    #[allow(clippy::too_many_lines)]
    pub fn run_cycle_with_audit(
        fs: &InMemoryFS,
        registry: &Arc<RwLock<RemoteRegistry>>,
        _log_dir: &Path,
        last_part_sync: &mut SystemTime,
        uploaded_parts: &mut std::collections::HashMap<u32, (u64, u32)>,
        last_audit: &mut SystemTime,
        confirmed_generations: &mut std::collections::HashMap<String, std::collections::HashSet<u32>>,
        confirmed_summaries: &mut std::collections::HashMap<String, std::collections::HashSet<String>>,
        force_audit: bool,
    ) -> io::Result<()> {
        let (policy, stores) = {
            let reg = registry.read().unwrap();
            (reg.policy.clone(), reg.build_all_stores())
        };

        if stores.is_empty() {
            return Ok(());
        }

        let storage = match fs.log_cache.as_ref() {
            Some(c) => Arc::clone(c.storage()),
            None => return Ok(()),
        };

        let (active_gen, active_offset) = match fs.log_writer {
            Some(ref w) => (w.generation(), w.current_offset()),
            None => return Ok(()),
        };

        let now = fs.clock.now();
        let audit_elapsed = now.duration_since(*last_audit).unwrap_or_default().as_secs();
        let is_audit = force_audit || audit_elapsed >= policy.audit_interval_secs;

        if is_audit {
            *last_audit = now;
            confirmed_generations.clear();
            confirmed_summaries.clear();
        }

        // Pre-fetch object listings from each remote store once per cycle: O(1) listing requests per remote.
        let mut store_listings: Vec<Option<HashMap<String, RemoteObject>>> = Vec::with_capacity(stores.len());
        for r in &stores {
            match r.store.list_objects("") {
                Ok(objs) => {
                    let map: HashMap<String, RemoteObject> = objs.into_iter().map(|o| (o.key.clone(), o)).collect();
                    store_listings.push(Some(map));
                }
                Err(e) => {
                    log::warn!(
                        "list_objects failed on remote '{}': {}. Remote will be skipped for this cycle",
                        r.name,
                        e
                    );
                    fs.replication_telemetry
                        .write()
                        .unwrap()
                        .record_error(&r.name, &e.to_string());
                    store_listings.push(None);
                }
            }
        }

        // Age-based rolling belongs to the flusher, which owns the log writer and checks
        // `max_log_age` at the end of every cycle - including the idle ones. `max_log_age_secs`
        // reaches it as the writer's own limit, set at mount.

        // Sync sealed generations to all writable remotes
        let manifest = fs.manifest.read().unwrap().clone();
        for log_entry in &manifest.logs {
            let gen_num = log_entry.generation;
            let filename = &log_entry.filename;

            // Only completed manifest generations (skip active writer generation)
            if gen_num >= active_gen {
                continue;
            }

            let expected_len = log_entry.total_bytes;
            let expected_md5 = &log_entry.md5;

            for (r_idx, r) in stores.iter().enumerate() {
                if !r.mode.is_writable() {
                    continue;
                }

                // If not in a full audit cycle, skip if this remote already confirmed this generation
                if !is_audit
                    && confirmed_generations
                        .get(&r.name)
                        .is_some_and(|set| set.contains(&gen_num))
                {
                    continue;
                }

                let Some(ref map) = store_listings[r_idx] else {
                    continue;
                };

                let needs_upload = match map.get(filename) {
                    Some(obj) => obj.size != expected_len || obj.etag_md5() != Some(*expected_md5),
                    None => true,
                };

                let mut upload_succeeded = false;
                if needs_upload {
                    if storage.exists(filename) {
                        log::info!(
                            "Replicating sealed {} ({} bytes) to remote '{}'...",
                            filename,
                            expected_len,
                            r.name
                        );
                        match upload_storage_file(storage.as_ref(), r.store.as_ref(), filename, Some(expected_md5)) {
                            Ok(()) => upload_succeeded = true,
                            Err(e) => {
                                log::warn!("upload_storage_file {} to remote '{}' failed: {}", filename, r.name, e);
                                fs.replication_telemetry
                                    .write()
                                    .unwrap()
                                    .record_error(&r.name, &e.to_string());
                            }
                        }
                    } else {
                        // Cross-copy from another remote holding this generation
                        for (src_idx, src) in stores.iter().enumerate() {
                            if src.name == r.name {
                                continue;
                            }
                            if let Some(Some(src_map)) = store_listings.get(src_idx)
                                && let Some(src_obj) = src_map.get(filename)
                                && src_obj.size == expected_len
                            {
                                log::info!(
                                    "Cross-copying {} ({} bytes) from remote '{}' to remote '{}'...",
                                    filename,
                                    expected_len,
                                    src.name,
                                    r.name
                                );
                                match cross_copy_file(
                                    src.store.as_ref(),
                                    r.store.as_ref(),
                                    filename,
                                    expected_len,
                                    expected_md5,
                                ) {
                                    Ok(()) => {
                                        upload_succeeded = true;
                                        break;
                                    }
                                    Err(e) => {
                                        log::warn!(
                                            "cross_copy_file {} from '{}' to '{}' failed: {}",
                                            filename,
                                            src.name,
                                            r.name,
                                            e
                                        );
                                    }
                                }
                            }
                        }
                    }
                } else {
                    upload_succeeded = true;
                }

                let verified_on_remote = if needs_upload {
                    if upload_succeeded {
                        match r.store.head_object(filename) {
                            Ok(Some(obj)) if obj.size == expected_len && obj.etag_md5() == Some(*expected_md5) => {
                                if let Some(Some(map)) = store_listings.get_mut(r_idx) {
                                    map.insert(filename.clone(), obj);
                                }
                                true
                            }
                            Ok(Some(obj)) => {
                                log::warn!(
                                    "Post-upload verification for {} on remote '{}' failed: expected size {}, MD5 {}, got size {}, ETag {:?}",
                                    filename,
                                    r.name,
                                    expected_len,
                                    hex::encode(expected_md5),
                                    obj.size,
                                    obj.etag
                                );
                                fs.replication_telemetry
                                    .write()
                                    .unwrap()
                                    .record_error(&r.name, "post-upload verification failed (size or MD5 mismatch)");
                                false
                            }
                            Ok(None) => {
                                log::warn!(
                                    "Post-upload verification for {} on remote '{}' failed: object not found",
                                    filename,
                                    r.name
                                );
                                fs.replication_telemetry
                                    .write()
                                    .unwrap()
                                    .record_error(&r.name, "post-upload verification failed (object not found)");
                                false
                            }
                            Err(e) => {
                                log::warn!(
                                    "Post-upload head_object for {} on remote '{}' failed: {}",
                                    filename,
                                    r.name,
                                    e
                                );
                                fs.replication_telemetry
                                    .write()
                                    .unwrap()
                                    .record_error(&r.name, &e.to_string());
                                false
                            }
                        }
                    } else {
                        false
                    }
                } else {
                    true
                };

                if verified_on_remote {
                    // Clean up any obsolete transient parts on this remote once consolidated log is verified,
                    // but ONLY if partial logs were enabled for this remote (avoiding unnecessary DELETE calls
                    // for append-only / write-only remotes).
                    if r.upload_partial_logs {
                        let prefix = format!("{:06}.part", gen_num);
                        let part_keys: Vec<String> = if let Some(Some(map)) = store_listings.get(r_idx) {
                            map.keys().filter(|k| k.starts_with(&prefix)).cloned().collect()
                        } else {
                            Vec::new()
                        };
                        for part_key in part_keys {
                            if r.store.delete_object(&part_key).is_ok()
                                && let Some(Some(map)) = store_listings.get_mut(r_idx)
                            {
                                map.remove(&part_key);
                            }
                        }
                    }

                    confirmed_generations.entry(r.name.clone()).or_default().insert(gen_num);

                    fs.replication_telemetry
                        .write()
                        .unwrap()
                        .record_synced_gen(&r.name, gen_num, now);
                }
            }
        }

        // 3. Sync .summary checkpoint files to writable remotes
        let local_files = storage.list_files()?;
        let mut summary_files: std::collections::BTreeSet<String> = local_files
            .iter()
            .filter(|f| f.ends_with(".summary"))
            .cloned()
            .collect();
        // Also check if any remotes have summary files not in local storage (during full audit)
        if is_audit {
            for listing in store_listings.iter().flatten() {
                for key in listing.keys() {
                    if key.ends_with(".summary") {
                        summary_files.insert(key.clone());
                    }
                }
            }
        }

        for sum_file in &summary_files {
            let local_exists = storage.exists(sum_file);
            let local_len = if local_exists {
                storage.file_len(sum_file).unwrap_or(0)
            } else {
                0
            };

            let mut verified_local_md5: Option<Result<[u8; 16], String>> = None;

            for (r_idx, r) in stores.iter().enumerate() {
                if !r.mode.is_writable() {
                    continue;
                }

                // If not in a full audit cycle, skip if this remote already confirmed this summary
                if !is_audit
                    && confirmed_summaries
                        .get(&r.name)
                        .is_some_and(|set| set.contains(sum_file))
                {
                    continue;
                }

                let Some(ref map) = store_listings[r_idx] else {
                    continue;
                };

                let needs_sync = match map.get(sum_file) {
                    None => true,
                    Some(h) if local_exists => h.size != local_len,
                    _ => false,
                };

                let mut sync_succeeded = false;
                if needs_sync {
                    if local_exists {
                        let md5_res = verified_local_md5.get_or_insert_with(|| {
                            verify_summary_storage_file(storage.as_ref(), sum_file)
                                .map(|(_, md5)| md5)
                                .map_err(|e| e.to_string())
                        });

                        match md5_res {
                            Ok(sum_md5) => {
                                log::info!("Syncing summary {} to remote '{}'...", sum_file, r.name);
                                match upload_storage_file(storage.as_ref(), r.store.as_ref(), sum_file, Some(sum_md5)) {
                                    Ok(()) => sync_succeeded = true,
                                    Err(e) => {
                                        log::warn!("upload summary {} to '{}' failed: {}", sum_file, r.name, e);
                                        fs.replication_telemetry
                                            .write()
                                            .unwrap()
                                            .record_error(&r.name, &e.to_string());
                                    }
                                }
                            }
                            Err(e) => {
                                log::error!(
                                    "Local summary {} verification failed (BLAKE3 mismatch or corruption): {}. Skipping upload to remote '{}'",
                                    sum_file,
                                    e,
                                    r.name
                                );
                                fs.replication_telemetry.write().unwrap().record_error(&r.name, e);
                            }
                        }
                    } else {
                        // Find a peer remote that has this summary
                        for (src_idx, src) in stores.iter().enumerate() {
                            if src.name == r.name {
                                continue;
                            }
                            if let Some(Some(src_map)) = store_listings.get(src_idx)
                                && let Some(src_head) = src_map.get(sum_file)
                            {
                                log::info!(
                                    "Cross-copying summary {} ({} bytes) from remote '{}' to '{}'...",
                                    sum_file,
                                    src_head.size,
                                    src.name,
                                    r.name
                                );
                                match cross_copy_summary(src.store.as_ref(), r.store.as_ref(), sum_file, src_head.size)
                                {
                                    Ok(()) => {
                                        sync_succeeded = true;
                                        break;
                                    }
                                    Err(e) => {
                                        log::warn!("cross_copy summary {} failed: {}", sum_file, e);
                                    }
                                }
                            }
                        }
                    }
                } else {
                    sync_succeeded = true;
                }

                let verified_on_remote = if needs_sync {
                    if sync_succeeded {
                        match r.store.head_object(sum_file) {
                            Ok(Some(obj)) if (if local_exists { obj.size == local_len } else { true }) => {
                                if let Some(Some(map)) = store_listings.get_mut(r_idx) {
                                    map.insert(sum_file.clone(), obj);
                                }
                                true
                            }
                            _ => false,
                        }
                    } else {
                        false
                    }
                } else {
                    true
                };

                if verified_on_remote {
                    confirmed_summaries
                        .entry(r.name.clone())
                        .or_default()
                        .insert(sum_file.clone());
                }
            }
        }

        // 4. Active generation part-chunk upload (every active_sync_interval_secs)
        let time_since_last_part = now.duration_since(*last_part_sync).unwrap_or_default();

        if time_since_last_part.as_secs() >= policy.active_sync_interval_secs {
            let (last_offset, part_idx) = uploaded_parts
                .entry(active_gen)
                // From offset 0: the first part carries the file header, whose key salt a
                // bootstrap needs to decrypt the records in the parts that follow.
                .or_insert((0, 0));
            // A file holding only its header has nothing worth shipping yet.
            if active_offset > crate::log::record::FILE_HEADER_SIZE as u64 && active_offset > *last_offset {
                let part_len = active_offset - *last_offset;
                let part_filename = format!("{:06}.part{:04}.log", active_gen, *part_idx);

                let wants_parts = stores
                    .iter()
                    .any(|r| r.mode == RemoteMode::ReadWrite && r.upload_partial_logs);

                if wants_parts {
                    // Read slice from local active log
                    let active_filename = crate::log::log_filename(active_gen);
                    if let Ok(reader) = storage.open_reader(&active_filename) {
                        let mut part_bytes = vec![0u8; part_len as usize];
                        if reader.read_exact_at(*last_offset, &mut part_bytes).is_ok() {
                            let part_md5: [u8; 16] = *md5::compute(&part_bytes);
                            let mut any_part_success = false;
                            for r in &stores {
                                if r.mode != RemoteMode::ReadWrite || !r.upload_partial_logs {
                                    continue;
                                }
                                log::info!(
                                    "Uploading active incremental part {} ({} bytes) to remote '{}'...",
                                    part_filename,
                                    part_len,
                                    r.name
                                );
                                match r.store.put_object(
                                    &part_filename,
                                    &mut &part_bytes[..],
                                    part_len,
                                    Some(&part_md5),
                                ) {
                                    Ok(()) => {
                                        any_part_success = true;
                                        fs.replication_telemetry
                                            .write()
                                            .unwrap()
                                            .record_active_part(&r.name, active_gen, *part_idx, now);
                                    }
                                    Err(e) => {
                                        log::warn!(
                                            "put_object active part {} to '{}' failed: {}",
                                            part_filename,
                                            r.name,
                                            e
                                        );
                                        fs.replication_telemetry
                                            .write()
                                            .unwrap()
                                            .record_error(&r.name, &e.to_string());
                                    }
                                }
                            }
                            if any_part_success {
                                *last_offset = active_offset;
                                *part_idx += 1;
                            }
                        }
                    }
                }
            }
            *last_part_sync = now;
        }

        // 5. Tiered storage local eviction / pruning
        Self::prune_eligible_local_logs(fs, &storage, &manifest, active_gen, &policy, &stores, &store_listings);

        Ok(())
    }

    fn prune_eligible_local_logs(
        fs: &InMemoryFS,
        storage: &Arc<dyn Storage>,
        manifest: &crate::log::LogManifest,
        active_gen: u32,
        policy: &crate::remote::config::ReplicationPolicy,
        stores: &[ConfiguredRemote],
        store_listings: &[Option<HashMap<String, RemoteObject>>],
    ) {
        let now = fs.clock.now();
        let last_summary_gen = fs.last_summary_generation.load(Ordering::SeqCst);

        // Pre-filter candidate logs eligible for local pruning before dispatching remote queries.
        // Core Guardrails (strictly engine-enforced, cannot be overridden by user prune rules):
        // 1. Summaries, and especially the latest summary snapshot, are strictly pinned and never pruned locally.
        // 2. Active log writer generation cannot be pruned.
        // 3. Uncovered logs (generation > last_summary_gen) cannot be pruned.
        // 4. Local summary covering the log generation must exist on disk.
        let mut candidates = Vec::new();
        for log_entry in &manifest.logs {
            let gen_num = log_entry.generation;
            let filename = &log_entry.filename;

            // Invariant 1: Cannot prune active generation
            if gen_num >= active_gen {
                continue;
            }

            // Invariant 2: Cannot prune local log if no local summary covers it
            if gen_num > last_summary_gen {
                continue;
            }
            let summary_file = format!("{:06}.summary", last_summary_gen);
            if !storage.exists(&summary_file) {
                continue;
            }

            if !storage.exists(filename) {
                continue;
            }

            let sealed_time = log_entry.sealed_at.unwrap_or(log_entry.created_at);
            let age = now.duration_since(sealed_time).unwrap_or_default();

            candidates.push((log_entry, age));
        }

        if candidates.is_empty() {
            return;
        }

        let prune_expr = &policy.prune_rule;

        for (log_entry, age) in candidates {
            let gen_num = log_entry.generation;
            let filename = &log_entry.filename;

            // Collect set of confirmed remote stores with matching size and ETag/MD5
            let mut confirmed_remotes = std::collections::HashSet::new();
            for (i, r) in stores.iter().enumerate() {
                let Some(map) = &store_listings[i] else {
                    continue;
                };

                if let Some(remote_obj) = map.get(filename)
                    && remote_obj.size == log_entry.total_bytes
                    && remote_obj.etag_md5() == Some(log_entry.md5)
                {
                    confirmed_remotes.insert(r.name.as_str());
                }
            }

            let ctx = crate::remote::policy::PruneContext::new(age, &confirmed_remotes, stores);

            if prune_expr.evaluate(&ctx) {
                log::info!(
                    "Pruning local sealed {} ({} days old, verified on remotes: {:?})...",
                    filename,
                    age.as_secs() / 86400,
                    confirmed_remotes
                );
                if storage.remove_file(filename).is_ok() {
                    // Finding 8: invalidate cached reader so unlinked fd is dropped and disk space is freed!
                    if let Some(ref cache) = fs.log_cache {
                        cache.invalidate(gen_num);
                    }
                }
            }
        }
    }

    /// Stops the background worker and joins its thread.
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        self.fs.notify_replication();
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for RemoteReplicationWorker {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::mock::MockRemoteStore;
    use crate::storage::MemoryStorage;

    #[test]
    fn test_upload_storage_file_and_cross_copy() {
        let storage = Arc::new(MemoryStorage::new());
        let mut writer = storage
            .open_writer("000001.log", crate::storage::WriteMode::CreateNew)
            .unwrap();
        writer.append(b"sealed log contents 12345678").unwrap();
        drop(writer);

        let remote1 = Arc::new(MockRemoteStore::new());
        let remote2 = Arc::new(MockRemoteStore::new());

        let expected_md5: [u8; 16] = *md5::compute(b"sealed log contents 12345678");

        // Upload from local storage to remote 1
        upload_storage_file(storage.as_ref(), remote1.as_ref(), "000001.log", Some(&expected_md5)).unwrap();

        let head = remote1.head_object("000001.log").unwrap().unwrap();
        assert_eq!(head.size, 28);
        assert_eq!(head.etag_md5(), Some(expected_md5));

        // Cross-copy from remote 1 to remote 2 with streaming inline MD5 verification
        cross_copy_file(remote1.as_ref(), remote2.as_ref(), "000001.log", 28, &expected_md5).unwrap();

        let head2 = remote2.head_object("000001.log").unwrap().unwrap();
        assert_eq!(head2.size, 28);
        assert_eq!(head2.etag_md5(), Some(expected_md5));
    }

    #[test]
    fn test_cross_copy_file_md5_mismatch() {
        let remote1 = Arc::new(MockRemoteStore::new());
        let remote2 = Arc::new(MockRemoteStore::new());

        let data = b"corrupted log payload";
        remote1
            .put_object("000001.log", &mut &data[..], data.len() as u64, None)
            .unwrap();

        let wrong_md5 = [0x55u8; 16];
        let err = cross_copy_file(
            remote1.as_ref(),
            remote2.as_ref(),
            "000001.log",
            data.len() as u64,
            &wrong_md5,
        )
        .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("downloaded MD5"));
        assert!(remote2.head_object("000001.log").unwrap().is_none());
    }

    #[test]
    fn test_cross_copy_summary_streaming_blake3_and_md5() {
        let remote1 = Arc::new(MockRemoteStore::new());
        let remote2 = Arc::new(MockRemoteStore::new());

        let body = b"header_and_inode_snapshot_body_data_1234567890";
        let checksum: [u8; 32] = *blake3::hash(body).as_bytes();
        let footer = SummaryFooter::new(10, 1, checksum);
        let mut full_summary = body.to_vec();
        full_summary.extend_from_slice(&footer.to_bytes());

        let total_len = full_summary.len() as u64;
        let expected_md5: [u8; 16] = *md5::compute(&full_summary);

        remote1
            .put_object("000001.summary", &mut &full_summary[..], total_len, None)
            .unwrap();

        cross_copy_summary(remote1.as_ref(), remote2.as_ref(), "000001.summary", total_len).unwrap();

        let head2 = remote2.head_object("000001.summary").unwrap().unwrap();
        assert_eq!(head2.size, total_len);
        assert_eq!(head2.etag_md5(), Some(expected_md5));
    }

    #[test]
    fn test_cross_copy_summary_corrupted_blake3_rejected() {
        let remote1 = Arc::new(MockRemoteStore::new());
        let remote2 = Arc::new(MockRemoteStore::new());

        let body = b"header_and_inode_snapshot_body_data_1234567890";
        let checksum: [u8; 32] = *blake3::hash(body).as_bytes();
        let footer = SummaryFooter::new(10, 1, checksum);
        let mut full_summary = body.to_vec();
        full_summary.extend_from_slice(&footer.to_bytes());

        // Corrupt a byte in the summary body
        full_summary[5] ^= 0xff;

        let total_len = full_summary.len() as u64;
        remote1
            .put_object("000001.summary", &mut &full_summary[..], total_len, None)
            .unwrap();

        let err = cross_copy_summary(remote1.as_ref(), remote2.as_ref(), "000001.summary", total_len).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("BLAKE3 checksum mismatch"));
        assert!(remote2.head_object("000001.summary").unwrap().is_none());
    }

    #[test]
    fn test_cross_copy_summary_corrupted_magic_rejected() {
        let remote1 = Arc::new(MockRemoteStore::new());
        let remote2 = Arc::new(MockRemoteStore::new());

        let data = [0u8; 100];
        // Ensure invalid footer magic
        let total_len = data.len() as u64;
        remote1
            .put_object("000001.summary", &mut &data[..], total_len, None)
            .unwrap();

        let err = cross_copy_summary(remote1.as_ref(), remote2.as_ref(), "000001.summary", total_len).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(remote2.head_object("000001.summary").unwrap().is_none());
    }

    #[test]
    fn test_verify_summary_storage_file_valid_and_corrupt() {
        let storage = Arc::new(MemoryStorage::new());

        let body = b"header_and_inode_snapshot_body_data_1234567890";
        let checksum: [u8; 32] = *blake3::hash(body).as_bytes();
        let footer = SummaryFooter::new(10, 1, checksum);
        let mut full_summary = body.to_vec();
        full_summary.extend_from_slice(&footer.to_bytes());

        let expected_len = full_summary.len() as u64;
        let expected_md5: [u8; 16] = *md5::compute(&full_summary);

        let mut writer = storage
            .open_writer("000001.summary", crate::storage::WriteMode::CreateNew)
            .unwrap();
        writer.append(&full_summary).unwrap();
        drop(writer);

        // Valid verification in single pass
        let (len, md5_digest) = verify_summary_storage_file(storage.as_ref(), "000001.summary").unwrap();
        assert_eq!(len, expected_len);
        assert_eq!(md5_digest, expected_md5);

        // Corrupted body in storage
        let mut corrupt_summary = full_summary.clone();
        corrupt_summary[5] ^= 0xff;
        let mut writer = storage
            .open_writer("000002.summary", crate::storage::WriteMode::CreateNew)
            .unwrap();
        writer.append(&corrupt_summary).unwrap();
        drop(writer);

        let err = verify_summary_storage_file(storage.as_ref(), "000002.summary").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("BLAKE3 checksum mismatch"));
    }

    #[test]
    fn test_default_poll_interval() {
        assert_eq!(DEFAULT_POLL_INTERVAL, Duration::from_secs(60));
    }
}
