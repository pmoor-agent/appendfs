use crate::crypto::{LogFileKey, VolumeKey};
use crate::log::manifest::LogFileInfo;
use crate::log::record::{FILE_HEADER_SIZE, FileHeader};
use crate::remote::RemoteReadTarget;
use crate::remote::block_cache::{BlockCache, DEFAULT_DECRYPTED_CACHE_SIZE, DecryptedRecordCache};
use crate::remote::tiered_reader::TieredStorageReader;
use crate::storage::{OsStorage, Storage, StorageReader};
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};

/// An open log file: its reader, and the key its records are encrypted under, derived once
/// from the salt in its header (see [`crate::crypto::VolumeKey::log_file_key`]).
#[derive(Clone)]
pub struct OpenLog {
    pub reader: Arc<dyn StorageReader>,
    pub file_key: Arc<LogFileKey>,
}

/// Thread-safe cache holding open log file reader handles to eliminate repeated open calls,
/// with two-tiered caching (in-memory decrypted payload LRU + on-disk raw block cache)
/// and sparse remote reading.
#[allow(clippy::type_complexity)]
pub struct LogFileCache {
    storage: Arc<dyn Storage>,
    cache: Mutex<HashMap<u32, OpenLog>>,
    pub decrypted_cache: Arc<DecryptedRecordCache>,
    pub block_cache: Option<Arc<dyn BlockCache>>,
    pub remotes: Arc<RwLock<Vec<RemoteReadTarget>>>,
    pub manifest: Option<Arc<RwLock<crate::log::LogManifest>>>,
    pub active_writer: Arc<RwLock<Option<std::sync::Weak<crate::log::LogWriter>>>>,
    /// Whether logs in the manifest that are still present locally are read through `block_cache` too.
    /// Off by default: the local file already holds those blocks, so caching them only pays
    /// off once the log is pruned, and costs a second copy on disk until then.
    cache_local_reads: bool,
}

impl LogFileCache {
    pub fn new(log_dir: impl AsRef<Path>) -> Self {
        let storage = Arc::new(OsStorage::new(log_dir));
        Self::with_storage(storage)
    }

    pub fn with_storage(storage: Arc<dyn Storage>) -> Self {
        Self::with_storage_and_manifest(storage, None)
    }

    pub fn with_storage_and_manifest(
        storage: Arc<dyn Storage>,
        manifest: Option<Arc<RwLock<crate::log::LogManifest>>>,
    ) -> Self {
        Self {
            storage,
            cache: Mutex::new(HashMap::new()),
            decrypted_cache: Arc::new(DecryptedRecordCache::new(DEFAULT_DECRYPTED_CACHE_SIZE)),
            block_cache: None,
            remotes: Arc::new(RwLock::new(Vec::new())),
            manifest,
            active_writer: Arc::new(RwLock::new(None)),
            cache_local_reads: false,
        }
    }

    pub fn with_remote_support(
        storage: Arc<dyn Storage>,
        block_cache: Option<Arc<dyn BlockCache>>,
        remotes: impl IntoIterator<Item = impl Into<RemoteReadTarget>>,
        manifest: Option<Arc<RwLock<crate::log::LogManifest>>>,
    ) -> Self {
        Self {
            storage,
            cache: Mutex::new(HashMap::new()),
            decrypted_cache: Arc::new(DecryptedRecordCache::new(DEFAULT_DECRYPTED_CACHE_SIZE)),
            block_cache,
            remotes: Arc::new(RwLock::new(remotes.into_iter().map(Into::into).collect())),
            manifest,
            active_writer: Arc::new(RwLock::new(None)),
            cache_local_reads: false,
        }
    }

    /// Attaches the active `LogWriter` via a `Weak` reference so the key salt for the currently
    /// open unsealed generation can be resolved without reading its file header from disk,
    /// while allowing the writer to be dropped and release its volume lock normally.
    pub fn set_active_writer(&self, writer: &Arc<crate::log::LogWriter>) {
        if let Ok(mut guard) = self.active_writer.write() {
            *guard = Some(Arc::downgrade(writer));
        }
    }

    /// Makes reads of logs in the manifest that are still present locally copy their blocks into `block_cache`,
    /// so they remain readable without a remote fetch after the local log is pruned.
    pub fn with_cache_local_reads(mut self, cache_local_reads: bool) -> Self {
        self.cache_local_reads = cache_local_reads;
        self
    }

    /// Sets the byte capacity for the in-memory decrypted record cache.
    pub fn set_decrypted_cache_size(&self, max_bytes: usize) {
        self.decrypted_cache.set_max_bytes(max_bytes);
    }

    /// Invalidates and drops any cached reader for the given generation so unlinked disk space is reclaimed.
    pub fn invalidate(&self, generation: u32) {
        let mut guard = self.cache.lock().unwrap();
        guard.remove(&generation);
    }

    /// Returns the number of currently open log reader storage handles cached in memory.
    pub fn open_readers_count(&self) -> usize {
        self.cache.lock().unwrap().len()
    }

    /// Retrieves an open log file, reading and verifying its `FileHeader` and deriving its key
    /// from `volume_key` on first open. The derived key is cached with the file, which is sound
    /// because a volume has exactly one key for its lifetime (see `VolumeKey`).
    /// If the log file was pruned locally, falls back to `TieredStorageReader` over S3 range requests.
    pub fn get_or_open(&self, manifest_entry: &LogFileInfo, volume_key: &VolumeKey) -> io::Result<OpenLog> {
        let generation = manifest_entry.generation;
        let mut guard = self.cache.lock().unwrap();
        if let Some(open) = guard.get(&generation) {
            return Ok(open.clone());
        }
        let reader = self.open_reader(manifest_entry)?;

        let file_key = if let Some(key_salt) = manifest_entry.key_salt {
            Arc::new(volume_key.log_file_key(&key_salt))
        } else {
            let mut header_buf = [0u8; FILE_HEADER_SIZE];
            reader.read_exact_at(0, &mut header_buf)?;
            let header =
                FileHeader::from_bytes(&header_buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            if let Some(ref m) = self.manifest
                && let Ok(mut man) = m.try_write()
                && let Some(log_entry) = man.logs.iter_mut().find(|l| l.generation == generation)
            {
                log_entry.update_from_file_header(&header);
            }
            Arc::new(volume_key.log_file_key(&header.key_salt))
        };

        let open = OpenLog { reader, file_key };
        guard.insert(generation, open.clone());
        Ok(open)
    }

    /// Opens a reader for `manifest_entry`, locally or - once the local file has been pruned -
    /// over the remotes.
    fn open_reader(&self, manifest_entry: &LogFileInfo) -> io::Result<Arc<dyn StorageReader>> {
        let generation = manifest_entry.generation;
        let filename = manifest_entry.filename.clone();
        let mut expected_len = manifest_entry.total_bytes;

        let in_manifest = self
            .manifest
            .as_ref()
            .and_then(|m| m.read().ok())
            .map(|m| m.get_by_generation(generation).is_some())
            .unwrap_or(false);

        // If expected_len is not yet in manifest but local file exists:
        if in_manifest
            && expected_len == 0
            && let Ok(r) = self.storage.open_reader(&filename)
            && let Ok(l) = r.len()
        {
            expected_len = l;
        }

        // If generation is in the manifest and local reads are cached, use the unified TieredStorageReader.
        // This checks OnDiskBlockCache first, falling back to local storage (Tier 0) to pre-warm the cache,
        // and falling back to remotes if the local file was purged. Otherwise a local file is read
        // directly, and the TieredStorageReader below only takes over once it has been purged.
        if self.cache_local_reads
            && let Some(ref bc) = self.block_cache
            && in_manifest
            && expected_len > 0
        {
            let remotes = self.remotes.read().unwrap().clone();
            return Ok(Arc::new(TieredStorageReader::with_local_storage(
                generation,
                filename,
                expected_len,
                Some(self.storage.clone()),
                remotes,
                Arc::clone(bc),
            )));
        }

        let open_res = self.storage.open_reader(&filename);

        let reader: Arc<dyn StorageReader> = match open_res {
            Ok(r) => r,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let remotes = self.remotes.read().unwrap().clone();
                if remotes.is_empty() {
                    return Err(e);
                }

                if expected_len == 0 {
                    return Err(e);
                }

                let block_cache = match self.block_cache {
                    Some(ref bc) => Arc::clone(bc),
                    None => return Err(e),
                };

                Arc::new(TieredStorageReader::with_local_storage(
                    generation,
                    filename,
                    expected_len,
                    Some(self.storage.clone()),
                    remotes,
                    block_cache,
                ))
            }
            Err(e) => return Err(e),
        };
        Ok(reader)
    }

    /// Returns the cached decrypted record payload for `(generation, record_log_offset)` if present in memory.
    pub fn get_cached_record(&self, generation: u32, record_log_offset: u64) -> Option<Arc<Vec<u8>>> {
        self.decrypted_cache.get(generation, 0, record_log_offset)
    }

    /// Stores a decrypted record payload for `(generation, record_log_offset)` in the cache.
    pub fn insert_cached_record(&self, generation: u32, record_log_offset: u64, payload: Arc<Vec<u8>>) {
        self.decrypted_cache.insert(generation, 0, record_log_offset, payload);
    }

    /// Reads an extent payload slice directly from the in-memory decrypted record cache or decodes it from disk.
    ///
    /// If the decrypted payload for `(generation, record_log_offset)` is already present in `decrypted_cache`,
    /// it is copied directly with ZERO disk I/O and ZERO decryption overhead.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub fn read_extent_payload(
        &self,
        generation: u32,
        record_log_offset: u64,
        record_size: u32,
        payload_offset: u32,
        slice_offset: u32,
        dst_buf: &mut [u8],
        volume_key: &crate::crypto::VolumeKey,
    ) -> io::Result<usize> {
        let manifest_entry = self
            .manifest
            .as_ref()
            .and_then(|m| m.read().ok())
            .and_then(|m| m.get_by_generation(generation).cloned())
            .or_else(|| {
                self.active_writer
                    .read()
                    .ok()
                    .and_then(|w| w.as_ref().and_then(|weak| weak.upgrade()))
                    .filter(|w| w.generation() == generation)
                    .and_then(|w| w.active_log_info())
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "log generation {} not found in manifest or active log writer",
                        generation
                    ),
                )
            })?;
        let revision = manifest_entry.revision;

        let decrypted: Arc<Vec<u8>> =
            if let Some(cached) = self.decrypted_cache.get(generation, revision, record_log_offset) {
                cached
            } else {
                if (record_size as usize) < crate::log::record::RECORD_HEADER_SIZE {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("record_size {} is smaller than record header size", record_size),
                    ));
                }
                let open = self.get_or_open(&manifest_entry, volume_key)?;
                let mut raw_record = vec![0u8; record_size as usize];
                open.reader.read_exact_at(record_log_offset, &mut raw_record)?;

                let mut header_buf = [0u8; crate::log::record::RECORD_HEADER_SIZE];
                header_buf.copy_from_slice(&raw_record[..crate::log::record::RECORD_HEADER_SIZE]);
                let header = crate::log::record::RecordHeader::from_bytes(&header_buf)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

                let raw_payload = &raw_record[crate::log::record::RECORD_HEADER_SIZE..];
                if raw_payload.len() != header.payload_len as usize {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "record_size {} implies payload_len {}, but header declared {}",
                            record_size,
                            raw_payload.len(),
                            header.payload_len
                        ),
                    ));
                }

                let dec = crate::log::codec::decode(
                    &open.file_key,
                    crate::log::codec::RecordId {
                        sequence: header.sequence,
                        op_code: header.op_code as u8,
                        inode: header.inode,
                    },
                    raw_payload,
                    &header.auth_tag,
                )?;

                let arc_dec = Arc::new(dec);
                self.decrypted_cache
                    .insert(generation, revision, record_log_offset, Arc::clone(&arc_dec));
                arc_dec
            };

        let start = payload_offset as u64 + slice_offset as u64;
        let slice = usize::try_from(start)
            .ok()
            .zip(
                start
                    .checked_add(dst_buf.len() as u64)
                    .and_then(|end| usize::try_from(end).ok()),
            )
            .and_then(|(start, end)| decrypted.get(start..end))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "extent in generation {} at record offset {} wants {} bytes from payload offset {}, \
                         but that record holds only {} bytes",
                        generation,
                        record_log_offset,
                        dst_buf.len(),
                        start,
                        decrypted.len()
                    ),
                )
            })?;

        dst_buf.copy_from_slice(slice);
        Ok(dst_buf.len())
    }

    pub fn storage(&self) -> &Arc<dyn Storage> {
        &self.storage
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::SystemClock;
    use crate::crypto::VolumeKey;
    use crate::log::writer::LogWriter;
    use crate::storage::MemoryStorage;

    #[test]
    fn test_log_file_cache_open_and_verify() {
        let storage = Arc::new(MemoryStorage::new());
        let clock = SystemClock;
        let writer = LogWriter::create(
            storage.clone(),
            1,
            Arc::new(clock),
            crate::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            VolumeKey::plaintext_arc(),
        )
        .unwrap();
        writer.flush().unwrap();

        let cache = LogFileCache::with_storage(storage);

        let info = LogFileInfo {
            version: crate::log::record::CURRENT_VERSION,
            generation: 1,
            revision: 0,
            filename: crate::log::log_filename(1),
            created_at: std::time::SystemTime::UNIX_EPOCH,
            record_count: 0,
            total_bytes: 0,
            total_data_bytes: 0,
            md5: [0u8; 16],
            sealed_at: None,
            key_salt: None,
        };

        // First access opens and verifies header
        let file1 = cache.get_or_open(&info, &VolumeKey::plaintext()).unwrap();

        // Second access returns cached handle
        let file2 = cache.get_or_open(&info, &VolumeKey::plaintext()).unwrap();
        assert!(Arc::ptr_eq(&file1.reader, &file2.reader));
    }

    #[test]
    fn test_log_file_cache_decrypted_lru_hit() {
        let storage = Arc::new(MemoryStorage::new());
        let clock = SystemClock;
        let key = VolumeKey::plaintext_arc();
        let writer = Arc::new(
            LogWriter::create(
                storage.clone(),
                1,
                Arc::new(clock),
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                key.clone(),
            )
            .unwrap(),
        );

        let payload = b"cached extent data 123456789";
        let (gen_num, offset, rec_size) = writer.append_data(10, payload).unwrap();
        writer.flush().unwrap();

        let cache = LogFileCache::with_storage(storage);
        cache.set_active_writer(&writer);

        // First read populates in-memory decrypted cache
        let mut buf1 = [0u8; 6];
        cache
            .read_extent_payload(gen_num, offset, rec_size, 0, 0, &mut buf1, &key)
            .unwrap();
        assert_eq!(&buf1, b"cached");

        // Verify entry is in decrypted cache
        assert!(cache.decrypted_cache.get(gen_num, 0, offset).is_some());
        assert!(cache.get_cached_record(gen_num, offset).is_some());

        // Second read hits in-memory cache directly
        let mut buf2 = [0u8; 6];
        cache
            .read_extent_payload(gen_num, offset, rec_size, 7, 0, &mut buf2, &key)
            .unwrap();
        assert_eq!(&buf2, b"extent");
    }

    #[test]
    fn test_log_file_cache_bypasses_block0_when_salt_in_manifest() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(crate::storage::OsStorage::new(temp_dir.path()));
        let clock = Arc::new(SystemClock);
        let key = VolumeKey::plaintext_arc();
        let writer = LogWriter::create(
            storage.clone(),
            1,
            clock.clone(),
            crate::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            key.clone(),
        )
        .unwrap();

        // Write 1 MiB of padding data so next record is strictly in block 1 (offset >= 1024*1024)
        let padding = vec![0x42u8; 1024 * 1024];
        writer.append_data(10, &padding).unwrap();

        // Write target record in block 1
        let payload = b"block 1 payload data";
        let (gen_num, offset, rec_size) = writer.append_data(11, payload).unwrap();
        assert!(offset >= 1024 * 1024, "offset {} must be >= 1 MiB", offset);
        writer.flush().unwrap();
        let sealed_info = writer.seal_active().unwrap().unwrap();
        assert!(sealed_info.key_salt.is_some());

        let cache_dir = temp_dir.path().join(".cache");
        let block_cache = Arc::new(
            crate::remote::OnDiskBlockCache::new(&cache_dir, 64 * 1024 * 1024, clock).expect("create block cache"),
        );

        let manifest = Arc::new(RwLock::new(crate::log::LogManifest {
            logs: vec![sealed_info],
        }));

        let cache = LogFileCache::with_remote_support(
            storage.clone(),
            Some(block_cache.clone()),
            Vec::<crate::remote::RemoteReadTarget>::new(),
            Some(manifest),
        )
        .with_cache_local_reads(true);

        // Read the target record from block 1
        let mut buf = [0u8; 7];
        cache
            .read_extent_payload(gen_num, offset, rec_size, 0, 0, &mut buf, &key)
            .unwrap();
        assert_eq!(&buf, b"block 1");

        // Verify: block 1 (000001_000001.bin) IS in cache
        assert!(cache_dir.join("000001_000001.bin").exists(), "block 1 should be cached");

        // Crucial verification: block 0 (000001_000000.bin) is NOT in cache!
        assert!(
            !cache_dir.join("000001_000000.bin").exists(),
            "block 0 must NOT be read or cached into OnDiskBlockCache when key_salt is in manifest!"
        );
    }

    #[test]
    fn test_log_file_cache_reads_block0_when_salt_is_none() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(crate::storage::OsStorage::new(temp_dir.path()));
        let clock = Arc::new(SystemClock);
        let key = VolumeKey::plaintext_arc();
        let writer = LogWriter::create(
            storage.clone(),
            1,
            clock.clone(),
            crate::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            key.clone(),
        )
        .unwrap();

        // Write 1 MiB of padding data so next record is strictly in block 1 (offset >= 1024*1024)
        let padding = vec![0x42u8; 1024 * 1024];
        writer.append_data(10, &padding).unwrap();

        let payload = b"block 1 payload data";
        let (gen_num, offset, rec_size) = writer.append_data(11, payload).unwrap();
        assert!(offset >= 1024 * 1024);
        writer.flush().unwrap();
        let mut sealed_info = writer.seal_active().unwrap().unwrap();
        // Simulate legacy v1 manifest without key_salt
        sealed_info.key_salt = None;

        let cache_dir = temp_dir.path().join(".cache");
        let block_cache = Arc::new(
            crate::remote::OnDiskBlockCache::new(&cache_dir, 64 * 1024 * 1024, clock).expect("create block cache"),
        );

        let manifest = Arc::new(RwLock::new(crate::log::LogManifest {
            logs: vec![sealed_info],
        }));

        let cache = LogFileCache::with_remote_support(
            storage.clone(),
            Some(block_cache.clone()),
            Vec::<crate::remote::RemoteReadTarget>::new(),
            Some(manifest),
        )
        .with_cache_local_reads(true);

        let mut buf = [0u8; 7];
        cache
            .read_extent_payload(gen_num, offset, rec_size, 0, 0, &mut buf, &key)
            .unwrap();
        assert_eq!(&buf, b"block 1");

        // When key_salt is None, block 0 MUST be cached because FileHeader was read
        assert!(
            cache_dir.join("000001_000000.bin").exists(),
            "block 0 is cached when key_salt is None"
        );
    }

    #[test]
    fn test_log_file_cache_bypasses_block0_for_active_writer_log() {
        let temp_dir = tempfile::tempdir().unwrap();
        let os_storage = Arc::new(crate::storage::OsStorage::new(temp_dir.path()));
        let clock = Arc::new(SystemClock);
        let key = VolumeKey::plaintext_arc();

        // Custom reader and storage that track offsets passed to read_exact_at
        struct TrackingReader {
            reader: Arc<dyn crate::storage::StorageReader>,
            offsets: Arc<Mutex<Vec<u64>>>,
        }
        impl crate::storage::StorageReader for TrackingReader {
            fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
                self.offsets.lock().unwrap().push(offset);
                self.reader.read_exact_at(offset, buf)
            }
            fn len(&self) -> std::io::Result<u64> {
                self.reader.len()
            }
        }

        struct TrackingStorage {
            inner: Arc<dyn Storage>,
            offsets: Arc<Mutex<Vec<u64>>>,
        }
        impl Storage for TrackingStorage {
            fn open_reader(&self, filename: &str) -> std::io::Result<Arc<dyn crate::storage::StorageReader>> {
                let r = self.inner.open_reader(filename)?;
                Ok(Arc::new(TrackingReader {
                    reader: r,
                    offsets: Arc::clone(&self.offsets),
                }))
            }
            fn open_writer(
                &self,
                filename: &str,
                mode: crate::storage::WriteMode,
            ) -> std::io::Result<Box<dyn crate::storage::StorageWriter>> {
                self.inner.open_writer(filename, mode)
            }
            fn exists(&self, filename: &str) -> bool {
                self.inner.exists(filename)
            }
            fn file_len(&self, filename: &str) -> std::io::Result<u64> {
                self.inner.file_len(filename)
            }
            fn remove_file(&self, filename: &str) -> std::io::Result<()> {
                self.inner.remove_file(filename)
            }
            fn rename(&self, from: &str, to: &str) -> std::io::Result<()> {
                self.inner.rename(from, to)
            }
            fn acquire_exclusive_lock(&self) -> std::io::Result<Box<dyn crate::storage::StorageLock>> {
                self.inner.acquire_exclusive_lock()
            }
            fn list_files(&self) -> std::io::Result<Vec<String>> {
                self.inner.list_files()
            }
        }

        let read_offsets = Arc::new(Mutex::new(Vec::new()));
        let tracking_storage: Arc<dyn Storage> = Arc::new(TrackingStorage {
            inner: os_storage.clone(),
            offsets: Arc::clone(&read_offsets),
        });

        let writer = Arc::new(
            LogWriter::create(
                os_storage.clone(),
                1,
                clock.clone(),
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                key.clone(),
            )
            .unwrap(),
        );

        // Write 1 MiB of padding data so next record is strictly in block 1 (offset >= 1024*1024)
        let padding = vec![0x42u8; 1024 * 1024];
        writer.append_data(10, &padding).unwrap();

        let payload = b"block 1 active data";
        let (gen_num, offset, rec_size) = writer.append_data(11, payload).unwrap();
        assert!(offset >= 1024 * 1024);
        writer.flush().unwrap();

        // Note: gen_num is NOT sealed and NOT present in the manifest!
        let manifest = Arc::new(RwLock::new(crate::log::LogManifest::new()));

        let cache = LogFileCache::with_remote_support(
            tracking_storage,
            None,
            Vec::<crate::remote::RemoteReadTarget>::new(),
            Some(manifest),
        );

        // Funnel active writer to the cache
        cache.set_active_writer(&writer);

        // Read the target record from block 1 of the unsealed active log
        let mut buf = [0u8; 7];
        cache
            .read_extent_payload(gen_num, offset, rec_size, 0, 0, &mut buf, &key)
            .unwrap();
        assert_eq!(&buf, b"block 1");

        // Verify: read was issued directly to `offset`
        let recorded = read_offsets.lock().unwrap().clone();
        assert!(recorded.contains(&offset), "record offset {} must be read", offset);

        // Crucial verification: offset 0 (FileHeader) was NEVER read because key salt was obtained from active writer!
        assert!(
            !recorded.contains(&0),
            "offset 0 must NOT be read when active writer funnels key salt! Recorded offsets: {:?}",
            recorded
        );
    }

    #[test]
    fn test_read_extent_payload_fails_if_untracked_generation() {
        let storage = Arc::new(crate::storage::MemoryStorage::new());
        let manifest = Arc::new(RwLock::new(crate::log::LogManifest::new()));
        let cache = LogFileCache::with_storage_and_manifest(storage, Some(manifest));
        let key = VolumeKey::plaintext();

        let mut buf = [0u8; 10];
        let err = cache
            .read_extent_payload(999, 100, 50, 0, 0, &mut buf, &key)
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(err.to_string().contains("not found in manifest or active log writer"));
    }
}
