//! In-memory filesystem state and the LSM delta overlay.
//!
//! The overlay is layered `base` <- `flushing` <- `live`; see [`InMemoryFS`] for how the
//! three relate. This module holds the shared types and the struct itself, with the
//! behavior split across focused submodules:
//!
//! - [`layers`] - [`InodeLayerStack`], the race-free snapshot/fold abstraction every
//!   layered read goes through.
//! - [`handles`] - POSIX file and directory handle tracking.
//! - [`overlay`] - staging mutations into `live` and resolving reads across all layers.
//! - [`flush`] - freezing `live`, synthesizing log records, and folding batches into `base`.

pub mod arena;
mod flush;
mod handles;
mod layers;
mod overlay;
pub mod virtual_files;

pub use crate::operations::locks::{FlockState, FlockWaiter, LockManager, RangeLock, RangeLockWaiter};
pub use arena::WriteArena;
pub use layers::{InodeLayerStack, ReadPlan, ReadSlice, ReadSliceSource};
pub use virtual_files::{VIRTUAL_FH_FLAG, VIRTUAL_INO_BASE, VirtualFileRegistry};

use crate::clock::{Clock, SystemClock};
use crate::log::{BackgroundFlusher, LogFileCache, LogManifest, LogWriter};
use crate::node::{EntryDelta, Node};
use crate::storage::Storage;
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::SystemTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileHandle {
    pub ino: u64,
    pub flags: u32,
}

pub type DirSnapshot = Arc<Vec<(String, u64)>>;
pub type FileHandleMap = HashMap<u64, FileHandle>;
pub type DirectoryHandleMap = HashMap<u64, DirSnapshot>;

/// An immutable frozen batch of mutations being written to the log, holding its
/// corresponding write arena chunk buffers.
#[derive(Debug, Clone)]
pub struct FlushBatch {
    pub id: u64,
    pub entries: HashMap<u64, EntryDelta>,
    pub arena: WriteArena,
}

impl FlushBatch {
    pub fn new(id: u64, entries: HashMap<u64, EntryDelta>, arena: WriteArena) -> Self {
        assert!(!entries.is_empty(), "FlushBatch must contain at least one entry");
        Self { id, entries, arena }
    }
}

/// Consolidated mutable filesystem state protected by `InMemoryFS::inner`.
pub struct FsInner {
    /// Resting consolidated state loaded from `.summary` at mount, folded forward over generations.
    pub base: HashMap<u64, Arc<Node>>,
    /// Ordered queue of immutable frozen snapshots waiting to be written/flushed to disk.
    pub flushing: VecDeque<FlushBatch>,
    /// Monotonically increasing ID generator for flushing batches.
    pub next_batch_id: u64,
    /// Current generation's active mutable delta layer receiving live operations.
    pub live: HashMap<u64, EntryDelta>,
    /// Active write arena staging extent payload allocations for `live`.
    pub live_arena: WriteArena,
    /// Active open file handles keyed by allocated file handle ID (`fh`).
    pub file_handles: FileHandleMap,
    /// Active open directory handle snapshots keyed by allocated file handle ID (`fh`).
    pub dir_handles: DirectoryHandleMap,
    /// Open descriptor reference count per inode for fast POSIX unlinking checks.
    pub open_counts: HashMap<u64, u32>,
    /// Active open virtual file handles holding frozen point-in-time snapshot strings.
    pub virtual_handles: HashMap<u64, Vec<u8>>,
    /// Timestamp of the latest recovered operation / summary snapshot (if recovered).
    pub recovered_time: Option<SystemTime>,
}

pub struct InMemoryFS {
    /// Consolidated critical section protecting all in-memory metadata, layer overlay,
    /// file/dir handles, open counts, and write arena buffers.
    pub inner: Mutex<FsInner>,
    /// Independent whole-file BSD flock and POSIX byte-range record lock manager.
    pub locks: LockManager,
    /// Atomic counter for allocating unique file and directory handle IDs (`fh`).
    pub next_fh: AtomicU64,
    /// Authoritative manifest of all active log generations and lineage.
    pub manifest: Arc<RwLock<LogManifest>>,
    pub next_inode: AtomicU64,
    pub last_tx_id: AtomicU64,
    pub clock: Arc<dyn Clock>,
    pub log_writer: Option<Arc<LogWriter>>,
    pub log_cache: Option<Arc<LogFileCache>>,
    pub staged_bytes: AtomicUsize,
    pub max_buffer_size: usize,
    pub staged_ops: AtomicUsize,
    pub max_staged_ops: usize,
    /// Largest payload written as a single data record. Bounds how much must be read and
    /// decrypted to serve a read of any byte within it - see `DEFAULT_MAX_EXTENT_SIZE`.
    pub max_extent_size: usize,
    /// Maximum frozen batches allowed to queue up before mutations are refused. See
    /// `check_flush_capacity`.
    pub max_flush_queue_depth: usize,
    pub flush_interval: AtomicU64,
    pub(crate) flusher: Mutex<Option<BackgroundFlusher>>,
    pub flush_lock: Mutex<()>,
    /// When false, `read()` never touches atime (like a `noatime` mount) - defaults to true.
    pub track_atime: bool,
    /// When true, filesystem is mounted strictly read-only (EROFS).
    pub read_only: std::sync::atomic::AtomicBool,
    /// Active VolumeHeader holding unlocked Data Encryption Keys.
    pub volume_key: Arc<crate::crypto::VolumeKey>,
    /// Volume identity and key-check material, carried alongside the key it belongs to.
    ///
    /// Deliberately not part of `LogManifest`: the manifest describes log generation
    /// lineage, and folding volume identity into it meant every encrypted summary stored
    /// the header twice - once as the plaintext blob a reader actually consults, and again
    /// inside the encrypted manifest where nothing read it. Two copies of a
    /// security-relevant fact with nothing checking they agree is the shape of bug this
    /// module has already paid for.
    pub volume_header: crate::crypto::VolumeHeader,
    /// Dynamic virtual files registered in the filesystem root (`/`).
    pub(crate) virtual_files: Arc<virtual_files::VirtualFileRegistry>,
    /// Optional live RemoteRegistry instance for remote status reporting.
    pub remote_registry: RwLock<Option<Arc<RwLock<crate::remote::RemoteRegistry>>>>,
    /// Live telemetry counters and synchronization state across all remotes.
    pub replication_telemetry: Arc<RwLock<crate::remote::worker::ReplicationTelemetry>>,
    /// Threshold in bytes of committed log data before automatically exporting an intermediate .summary file on log roll (0 to disable).
    pub summary_interval_bytes: AtomicU64,
    /// Threshold in rolled generations before automatically exporting an intermediate .summary file on log roll (0 to disable).
    pub summary_interval_generations: AtomicU64,
    /// Cumulative data bytes flushed to the log since the last summary was exported.
    pub bytes_since_last_summary: AtomicU64,
    /// Number of generations rolled since the last summary was exported.
    pub generations_since_last_summary: AtomicU64,
    /// Generation number of the last exported summary file.
    pub last_summary_generation: AtomicU64,
    /// Condition variable and flag to immediately notify the background replication worker of new logs/summaries.
    pub replication_notifier: Arc<(Mutex<bool>, Condvar)>,
}

impl InMemoryFS {
    pub fn new() -> Self {
        Self::with_clock(Arc::new(SystemClock))
    }

    pub fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self::with_clock_and_log(clock, None)
    }

    pub fn with_clock_and_uids(clock: Arc<dyn Clock>, uid: u32, gid: u32) -> Self {
        let fs = Self::with_clock(clock.clone());
        let now = clock.now();
        if let Some(root) = fs.inner.lock().unwrap().base.get_mut(&1) {
            *root = Arc::new(Node::new_dir(1, 0o755, uid, gid, now));
        }
        fs
    }

    pub fn with_log(log_writer: Arc<LogWriter>) -> Self {
        Self::with_clock_and_log(Arc::new(SystemClock), Some(log_writer))
    }

    pub fn with_clock_and_log(clock: Arc<dyn Clock>, log_writer: Option<Arc<LogWriter>>) -> Self {
        let mut map = HashMap::new();
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        let now = clock.now();

        // Start with only the root directory (Inode 1), which is empty, nlink is 2 (parent entry and '.' link)
        map.insert(1, Arc::new(Node::new_dir(1, 0o755, uid, gid, now)));

        let log_cache = log_writer
            .as_ref()
            .map(|w| Arc::new(LogFileCache::with_storage(w.storage().clone())));

        // The writer owns the volume's volume_key; without one this is a plaintext volume.
        let volume_key = log_writer
            .as_ref()
            .map(|w| Arc::clone(w.volume_key()))
            .unwrap_or_else(|| Arc::new(crate::crypto::VolumeKey::plaintext()));

        let start_gen = log_writer.as_ref().map_or(1, |w| w.generation());
        let manifest = Arc::new(RwLock::new(LogManifest::new_with_time(start_gen, now)));

        let virtual_files = Arc::new(virtual_files::VirtualFileRegistry::new());

        let inner = FsInner {
            base: map,
            flushing: VecDeque::new(),
            next_batch_id: 1,
            live: HashMap::new(),
            live_arena: WriteArena::new(),
            file_handles: HashMap::new(),
            dir_handles: HashMap::new(),
            open_counts: HashMap::new(),
            virtual_handles: HashMap::new(),
            recovered_time: None,
        };

        let fs = Self {
            inner: Mutex::new(inner),
            locks: LockManager::new(),
            next_fh: AtomicU64::new(1),
            manifest,
            next_inode: AtomicU64::new(2),
            last_tx_id: AtomicU64::new(0),
            clock,
            log_writer,
            log_cache,
            staged_bytes: AtomicUsize::new(0),
            max_buffer_size: 128 * 1024 * 1024,
            staged_ops: AtomicUsize::new(0),
            max_staged_ops: crate::cli::DEFAULT_MAX_BUFFER_OPS,
            max_extent_size: crate::cli::DEFAULT_MAX_EXTENT_SIZE,
            max_flush_queue_depth: crate::cli::DEFAULT_MAX_FLUSH_QUEUE_DEPTH,
            flush_interval: AtomicU64::new(0),
            flusher: Mutex::new(None),
            flush_lock: Mutex::new(()),
            track_atime: true,
            read_only: std::sync::atomic::AtomicBool::new(false),
            volume_key,
            volume_header: crate::crypto::VolumeHeader::plaintext(),
            virtual_files,
            remote_registry: RwLock::new(None),
            replication_telemetry: Arc::new(RwLock::new(crate::remote::worker::ReplicationTelemetry::new())),
            summary_interval_bytes: AtomicU64::new(crate::cli::DEFAULT_SUMMARY_INTERVAL_BYTES),
            summary_interval_generations: AtomicU64::new(crate::cli::DEFAULT_SUMMARY_INTERVAL_GENERATIONS),
            bytes_since_last_summary: AtomicU64::new(0),
            generations_since_last_summary: AtomicU64::new(0),
            last_summary_generation: AtomicU64::new(0),
            replication_notifier: Arc::new((Mutex::new(false), Condvar::new())),
        };
        fs.register_runtime_status();
        fs
    }

    /// Attaches an active `LogWriter` to the filesystem instance, registering its active generation in the manifest.
    pub fn attach_log_writer(&mut self, writer: Arc<LogWriter>) {
        let generation = writer.generation();
        let now = self.clock.now();
        {
            let mut manifest = self.manifest.write().unwrap();
            if manifest.get_by_generation(generation).is_none() {
                manifest.record_roll(generation, now, crate::log::record::FILE_HEADER_SIZE as u64);
            }
        }
        self.log_writer = Some(writer);
    }

    /// Wakes up the background replication worker thread immediately.
    pub fn notify_replication(&self) {
        let (lock, cvar) = &*self.replication_notifier;
        let mut pending = lock.lock().unwrap();
        *pending = true;
        cvar.notify_all();
    }

    pub fn set_summary_intervals(&self, bytes: u64, generations: u64) {
        self.summary_interval_bytes.store(bytes, Ordering::SeqCst);
        self.summary_interval_generations.store(generations, Ordering::SeqCst);
    }

    pub fn set_remote_registry(&self, registry: Arc<RwLock<crate::remote::RemoteRegistry>>) {
        *self.remote_registry.write().unwrap() = Some(registry);
        self.register_remote_status();
    }

    pub fn register_remote_status(&self) {
        self.virtual_files
            .register(".remotes", crate::remote::worker::format_remotes_status);
    }

    pub fn register_runtime_status(&self) {
        self.virtual_files
            .register(".status", crate::stats::format_runtime_status);
    }

    /// Returns true if `ino` is a synthesized virtual file.
    pub fn is_virtual_ino(&self, ino: u64) -> bool {
        self.virtual_files.is_virtual_ino(ino)
    }

    /// Returns all registered root directory virtual entries `(name, ino)`.
    pub fn list_virtual_entries(&self) -> Vec<(String, u64)> {
        self.virtual_files.list_entries()
    }

    pub fn with_clock_and_storage(clock: Arc<dyn Clock>, storage: Arc<dyn Storage>) -> Self {
        let mut fs = Self::with_clock(clock);
        fs.set_storage(storage);
        fs
    }

    pub fn with_clock_storage_and_volume_key(
        clock: Arc<dyn Clock>,
        storage: Arc<dyn Storage>,
        volume_key: Arc<crate::crypto::VolumeKey>,
    ) -> Self {
        let mut fs = Self::with_clock(clock);
        fs.set_storage(storage);
        fs.volume_key = volume_key;
        fs
    }

    /// Sets the volume's header and key together, rejecting a pair that disagrees.
    ///
    /// The two are separate fields but describe one volume, and only agreeing values are
    /// coherent: the header is written to the summary in plaintext while the key encrypts
    /// its body, so a mismatched pair produces a snapshot that announces itself as
    /// unencrypted yet cannot be reopened by the key that wrote it.
    pub fn set_volume(
        &mut self,
        volume_header: crate::crypto::VolumeHeader,
        volume_key: Arc<crate::crypto::VolumeKey>,
    ) -> std::io::Result<()> {
        if volume_header.cipher != volume_key.cipher() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "volume header describes a {} volume but the key is for {}",
                    volume_header.cipher,
                    volume_key.cipher()
                ),
            ));
        }
        self.volume_header = volume_header;
        self.volume_key = volume_key;
        Ok(())
    }

    pub fn set_read_only(&self, ro: bool) {
        self.read_only.store(ro, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn is_read_only(&self) -> bool {
        self.read_only.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn recovered_time(&self) -> Option<SystemTime> {
        self.inner.lock().unwrap().recovered_time
    }

    pub fn set_recovered_time(&self, time: Option<SystemTime>) {
        self.inner.lock().unwrap().recovered_time = time;
    }

    pub fn set_storage(&mut self, storage: Arc<dyn Storage>) {
        self.log_cache = Some(Arc::new(LogFileCache::with_storage(storage)));
    }

    pub fn set_log_dir(&mut self, log_dir: impl AsRef<Path>) {
        self.set_storage(Arc::new(crate::storage::OsStorage::new(log_dir)));
    }

    pub(crate) fn allocate_inode(&self) -> u64 {
        self.next_inode.fetch_add(1, Ordering::SeqCst)
    }
}

impl Drop for InMemoryFS {
    fn drop(&mut self) {
        self.destroy();
        let _ = self.sync_and_export_summary();
    }
}

impl Default for InMemoryFS {
    fn default() -> Self {
        Self::new()
    }
}

pub fn find_parent_inode(fs: &InMemoryFS, child_ino: u64) -> Option<u64> {
    fs.get_parent_dir_inode(child_ino)
}
