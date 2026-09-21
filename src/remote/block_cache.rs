use crate::clock::Clock;
use std::collections::{HashMap, VecDeque};
use std::fs::{self, File, FileTimes, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

/// 1 MiB aligned block chunk size for remote over-fetching and on-disk caching.
pub const BLOCK_SIZE: u64 = 1024 * 1024;

/// Computes the block index for a given byte offset.
pub fn block_index(offset: u64) -> u64 {
    offset / BLOCK_SIZE
}

/// Computes the start byte offset of a block index.
pub fn block_start_offset(block_idx: u64) -> u64 {
    block_idx * BLOCK_SIZE
}

/// Monotonically increasing nonce for unique temporary cache file generation.
static NEXT_TMP_NONCE: AtomicU64 = AtomicU64::new(1);

/// Maximum age of orphaned temporary block cache files (`*.tmp.*`) before being purged by `prune_if_needed`.
pub const TMP_FILE_MAX_AGE: Duration = Duration::from_secs(3600);

/// Throttle duration for refreshing block cache `mtime` on read access (10 minutes).
pub const BLOCK_TOUCH_THROTTLE: Duration = Duration::from_secs(600);

/// Default in-memory decrypted record cache size (128 MiB).
pub const DEFAULT_DECRYPTED_CACHE_SIZE: usize = 128 * 1024 * 1024;

/// In-memory LRU cache storing decrypted record payloads to eliminate repeated AEAD decryptions,
/// bounded by total byte size.
#[derive(Debug)]
pub struct DecryptedRecordCache {
    max_bytes: AtomicUsize,
    entries: Mutex<DecryptedLruInner>,
}

#[derive(Debug)]
struct DecryptedLruInner {
    map: HashMap<(u64, u32, u64), Arc<Vec<u8>>>,
    queue: VecDeque<(u64, u32, u64)>,
    current_bytes: usize,
}

impl Default for DecryptedRecordCache {
    fn default() -> Self {
        Self::new(DEFAULT_DECRYPTED_CACHE_SIZE)
    }
}

impl DecryptedRecordCache {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes: AtomicUsize::new(max_bytes),
            entries: Mutex::new(DecryptedLruInner {
                map: HashMap::new(),
                queue: VecDeque::new(),
                current_bytes: 0,
            }),
        }
    }

    /// Maximum byte capacity of this cache.
    pub fn max_bytes(&self) -> usize {
        self.max_bytes.load(Ordering::SeqCst)
    }

    /// Dynamically updates the maximum byte capacity, evicting oldest entries if necessary.
    pub fn set_max_bytes(&self, max_bytes: usize) {
        self.max_bytes.store(max_bytes, Ordering::SeqCst);
        let mut guard = self.entries.lock().unwrap();
        while guard.current_bytes > max_bytes && !guard.queue.is_empty() {
            if let Some(removed) = guard.queue.pop_front().and_then(|k| guard.map.remove(&k)) {
                guard.current_bytes = guard.current_bytes.saturating_sub(removed.len());
            }
        }
    }

    /// Current approximate byte memory consumed by cached payloads.
    pub fn current_bytes(&self) -> usize {
        self.entries.lock().unwrap().current_bytes
    }

    /// Number of cached record payloads.
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap().map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.lock().unwrap().map.is_empty()
    }

    pub fn get(&self, generation: u64, revision: u32, record_log_offset: u64) -> Option<Arc<Vec<u8>>> {
        let mut guard = self.entries.lock().unwrap();
        let key = (generation, revision, record_log_offset);
        if let Some(val) = guard.map.get(&key) {
            let res = Arc::clone(val);
            // Move key to back of queue (most recently used)
            if let Some(pos) = guard.queue.iter().position(|k| *k == key) {
                guard.queue.remove(pos);
                guard.queue.push_back(key);
            }
            Some(res)
        } else {
            None
        }
    }

    pub fn insert(&self, generation: u64, revision: u32, record_log_offset: u64, payload: Arc<Vec<u8>>) {
        let mut guard = self.entries.lock().unwrap();
        let key = (generation, revision, record_log_offset);
        let new_len = payload.len();

        let max_b = self.max_bytes.load(Ordering::SeqCst);

        // If a single record exceeds max_bytes, don't cache it
        if new_len > max_b {
            return;
        }

        if let Some(old_len) = guard.map.get(&key).map(|p| p.len()) {
            guard.current_bytes = guard.current_bytes.saturating_sub(old_len) + new_len;
            guard.map.insert(key, payload);
            if let Some(pos) = guard.queue.iter().position(|k| *k == key) {
                guard.queue.remove(pos);
                guard.queue.push_back(key);
            }
            return;
        }

        while guard.current_bytes + new_len > max_b && !guard.queue.is_empty() {
            if let Some(removed) = guard.queue.pop_front().and_then(|k| guard.map.remove(&k)) {
                guard.current_bytes = guard.current_bytes.saturating_sub(removed.len());
            }
        }

        guard.current_bytes += new_len;
        guard.map.insert(key, payload);
        guard.queue.push_back(key);
    }

    pub fn clear(&self) {
        let mut guard = self.entries.lock().unwrap();
        guard.map.clear();
        guard.queue.clear();
        guard.current_bytes = 0;
    }
}

/// Persistent on-disk LRU block cache storing raw encrypted 1 MiB chunks in `<log_dir>/.cache/`.
pub struct OnDiskBlockCache {
    cache_dir: PathBuf,
    max_bytes: u64,
    access_lock: Mutex<()>,
    coalescer: Arc<super::RemoteReadCoalescer>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for OnDiskBlockCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnDiskBlockCache")
            .field("cache_dir", &self.cache_dir)
            .field("max_bytes", &self.max_bytes)
            .field("coalescer", &self.coalescer)
            .finish()
    }
}

impl OnDiskBlockCache {
    pub fn new(cache_dir: impl AsRef<Path>, max_bytes: u64, clock: Arc<dyn Clock>) -> io::Result<Self> {
        Self::with_coalescer(cache_dir, max_bytes, clock, Arc::new(super::RemoteReadCoalescer::new()))
    }

    pub fn with_coalescer(
        cache_dir: impl AsRef<Path>,
        max_bytes: u64,
        clock: Arc<dyn Clock>,
        coalescer: Arc<super::RemoteReadCoalescer>,
    ) -> io::Result<Self> {
        let p = cache_dir.as_ref().to_path_buf();
        fs::create_dir_all(&p)?;
        Ok(Self {
            cache_dir: p,
            max_bytes,
            access_lock: Mutex::new(()),
            coalescer,
            clock,
        })
    }

    pub fn coalescer(&self) -> &Arc<super::RemoteReadCoalescer> {
        &self.coalescer
    }

    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    fn block_path(&self, file_stem: &str, block_idx: u64) -> PathBuf {
        let stem = clean_file_stem(file_stem);
        self.cache_dir.join(format!("{}_{:06}.bin", stem, block_idx))
    }

    pub fn read_block(&self, file_stem: &str, block_idx: u64) -> io::Result<Option<Vec<u8>>> {
        let path = self.block_path(file_stem, block_idx);
        let mut file = match File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };

        let meta = match file.metadata() {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };

        if let Ok(mtime) = meta.modified() {
            let now = self.clock.now();
            if now.duration_since(mtime).unwrap_or_default() > BLOCK_TOUCH_THROTTLE {
                let times = FileTimes::new().set_modified(now);
                let _ = file.set_times(times);
            }
        }

        let mut buf = Vec::with_capacity(meta.len() as usize);
        file.read_to_end(&mut buf)?;
        Ok(Some(buf))
    }

    fn write_and_rename_block(&self, file_stem: &str, block_idx: u64, data: &[u8]) -> io::Result<()> {
        let target_path = self.block_path(file_stem, block_idx);
        let stem = clean_file_stem(file_stem);
        let nonce = NEXT_TMP_NONCE.fetch_add(1, Ordering::Relaxed);
        let tmp_path = self.cache_dir.join(format!(
            "{}_{:06}.tmp.{}.{}",
            stem,
            block_idx,
            std::process::id(),
            nonce
        ));

        let write_res = (|| -> io::Result<()> {
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp_path)?;
            file.write_all(data)?;
            file.flush()?;
            fs::rename(&tmp_path, &target_path)?;
            Ok(())
        })();

        if let Err(err) = write_res {
            let _ = fs::remove_file(&tmp_path);
            return Err(err);
        }

        Ok(())
    }

    pub fn write_block(&self, file_stem: &str, block_idx: u64, data: &[u8]) -> io::Result<()> {
        let _guard = self.access_lock.lock().unwrap();
        self.write_and_rename_block(file_stem, block_idx, data)?;
        self.prune_if_needed()?;
        Ok(())
    }

    pub fn read_blocks(&self, file_stem: &str, start_block: u64, count: usize) -> io::Result<Vec<Option<Vec<u8>>>> {
        let mut results = Vec::with_capacity(count);
        for i in 0..count {
            results.push(self.read_block(file_stem, start_block + i as u64)?);
        }
        Ok(results)
    }

    pub fn write_blocks(&self, file_stem: &str, start_block: u64, data: &[u8]) -> io::Result<()> {
        let _guard = self.access_lock.lock().unwrap();
        let mut offset = 0;
        let mut block_idx = start_block;

        while offset < data.len() {
            let chunk_len = (BLOCK_SIZE as usize).min(data.len() - offset);
            let chunk = &data[offset..offset + chunk_len];
            self.write_and_rename_block(file_stem, block_idx, chunk)?;
            offset += chunk_len;
            block_idx += 1;
        }

        self.prune_if_needed()?;
        Ok(())
    }

    fn prune_if_needed(&self) -> io::Result<()> {
        let mut entries = Vec::new();
        let mut total_size = 0u64;
        let now = self.clock.now();

        for entry in fs::read_dir(&self.cache_dir)? {
            let entry = entry?;
            let path = entry.path();
            let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");

            if file_name.contains(".tmp.") || file_name.ends_with(".tmp") {
                if let Ok(meta) = entry.metadata()
                    && let Ok(mtime) = meta.modified()
                    && now.duration_since(mtime).unwrap_or_default() > TMP_FILE_MAX_AGE
                {
                    let _ = fs::remove_file(&path);
                }
            } else if path.extension().and_then(|s| s.to_str()) == Some("bin")
                && let Ok(meta) = entry.metadata()
            {
                let len = meta.len();
                let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                total_size += len;
                entries.push((path, len, mtime));
            }
        }

        if total_size <= self.max_bytes {
            return Ok(());
        }

        // Sort oldest first
        entries.sort_by_key(|(_, _, mtime)| *mtime);

        for (path, len, _) in entries {
            if total_size <= self.max_bytes {
                break;
            }
            let _ = fs::remove_file(path);
            total_size = total_size.saturating_sub(len);
        }

        Ok(())
    }
}

/// Helper extracting a sanitized file stem from a filename or relative path.
pub fn clean_file_stem(name: &str) -> &str {
    let filename = name.rsplit('/').next().unwrap_or(name);
    if let Some(stem) = filename.strip_suffix(".log") {
        stem
    } else if let Some(stem) = filename.strip_suffix(".summary") {
        stem
    } else {
        filename
    }
}

/// Common interface for local 1 MiB raw block caches (on-disk or in-memory).
pub trait BlockCache: Send + Sync + std::fmt::Debug {
    /// Reads a 1 MiB block from cache if present.
    fn read_block(&self, file_stem: &str, block_idx: u64) -> io::Result<Option<Vec<u8>>>;
    /// Writes a 1 MiB block into cache, pruning oldest entries if capacity is exceeded.
    fn write_block(&self, file_stem: &str, block_idx: u64, data: &[u8]) -> io::Result<()>;
    /// Reads multiple consecutive blocks starting from `start_block` up to `count` blocks.
    fn read_blocks(&self, file_stem: &str, start_block: u64, count: usize) -> io::Result<Vec<Option<Vec<u8>>>> {
        let mut results = Vec::with_capacity(count);
        for i in 0..count {
            results.push(self.read_block(file_stem, start_block + i as u64)?);
        }
        Ok(results)
    }
    /// Writes multiple consecutive blocks starting from `start_block`, chunking `data` into 1 MiB blocks.
    fn write_blocks(&self, file_stem: &str, start_block: u64, data: &[u8]) -> io::Result<()> {
        let mut offset = 0;
        let mut block_idx = start_block;
        while offset < data.len() {
            let chunk_len = (BLOCK_SIZE as usize).min(data.len() - offset);
            self.write_block(file_stem, block_idx, &data[offset..offset + chunk_len])?;
            offset += chunk_len;
            block_idx += 1;
        }
        Ok(())
    }
    /// Prunes excess cached blocks if capacity is exceeded.
    fn prune_if_needed(&self) -> io::Result<()>;
    /// Reference to the single-flight request coalescer associated with this block cache.
    fn coalescer(&self) -> &Arc<super::RemoteReadCoalescer>;
    /// Returns a short human-readable summary of this block cache implementation and its limits.
    fn summary(&self) -> String {
        format!("{:?}", self)
    }
}

impl BlockCache for OnDiskBlockCache {
    fn read_block(&self, file_stem: &str, block_idx: u64) -> io::Result<Option<Vec<u8>>> {
        self.read_block(file_stem, block_idx)
    }

    fn read_blocks(&self, file_stem: &str, start_block: u64, count: usize) -> io::Result<Vec<Option<Vec<u8>>>> {
        self.read_blocks(file_stem, start_block, count)
    }

    fn write_block(&self, file_stem: &str, block_idx: u64, data: &[u8]) -> io::Result<()> {
        self.write_block(file_stem, block_idx, data)
    }

    fn write_blocks(&self, file_stem: &str, start_block: u64, data: &[u8]) -> io::Result<()> {
        self.write_blocks(file_stem, start_block, data)
    }

    fn prune_if_needed(&self) -> io::Result<()> {
        self.prune_if_needed()
    }

    fn coalescer(&self) -> &Arc<super::RemoteReadCoalescer> {
        self.coalescer()
    }

    fn summary(&self) -> String {
        format!(
            "On-Disk (limit: {}, dir: {})",
            crate::stats::format_bytes(self.max_bytes),
            self.cache_dir.display()
        )
    }
}

#[derive(Debug)]
struct MemoryCacheEntry {
    last_access: u64,
    data: Vec<u8>,
}

/// In-memory LRU block cache storing raw encrypted 1 MiB chunks without touching local disk.
#[derive(Debug)]
pub struct MemoryBlockCache {
    entries: Mutex<HashMap<(String, u64), MemoryCacheEntry>>,
    access_counter: std::sync::atomic::AtomicU64,
    max_bytes: usize,
    coalescer: Arc<super::RemoteReadCoalescer>,
}

impl MemoryBlockCache {
    pub fn new(max_bytes: usize) -> Self {
        Self::with_coalescer(max_bytes, Arc::new(super::RemoteReadCoalescer::new()))
    }

    pub fn with_coalescer(max_bytes: usize, coalescer: Arc<super::RemoteReadCoalescer>) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            access_counter: std::sync::atomic::AtomicU64::new(1),
            max_bytes,
            coalescer,
        }
    }

    /// Clears all cached blocks from memory.
    pub fn clear(&self) {
        self.entries.lock().unwrap().clear();
    }
}

impl BlockCache for MemoryBlockCache {
    fn read_block(&self, file_stem: &str, block_idx: u64) -> io::Result<Option<Vec<u8>>> {
        let stem = clean_file_stem(file_stem);
        let mut guard = self.entries.lock().unwrap();
        if let Some(entry) = guard.get_mut(&(stem.to_string(), block_idx)) {
            entry.last_access = self.access_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Ok(Some(entry.data.clone()));
        }
        Ok(None)
    }

    fn write_block(&self, file_stem: &str, block_idx: u64, data: &[u8]) -> io::Result<()> {
        let stem = clean_file_stem(file_stem);
        let ticket = self.access_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut guard = self.entries.lock().unwrap();
        guard.insert(
            (stem.to_string(), block_idx),
            MemoryCacheEntry {
                last_access: ticket,
                data: data.to_vec(),
            },
        );
        drop(guard);
        self.prune_if_needed()
    }

    fn prune_if_needed(&self) -> io::Result<()> {
        let mut guard = self.entries.lock().unwrap();
        let mut current_bytes: usize = guard.values().map(|v| v.data.len()).sum();
        if current_bytes > self.max_bytes {
            let mut items: Vec<((String, u64), u64, usize)> = guard
                .iter()
                .map(|(k, v)| (k.clone(), v.last_access, v.data.len()))
                .collect();
            items.sort_by_key(|(_, access, _)| *access);

            for (k, _, len) in items {
                if current_bytes <= self.max_bytes {
                    break;
                }
                guard.remove(&k);
                current_bytes = current_bytes.saturating_sub(len);
            }
        }
        Ok(())
    }

    fn coalescer(&self) -> &Arc<super::RemoteReadCoalescer> {
        &self.coalescer
    }

    fn summary(&self) -> String {
        format!(
            "In-Memory (limit: {})",
            crate::stats::format_bytes(self.max_bytes as u64)
        )
    }
}

/// Unified two-tiered cache containing on-disk raw blocks and in-memory decrypted payloads.
#[derive(Debug)]
pub struct TieredCache {
    pub on_disk: OnDiskBlockCache,
    pub decrypted: DecryptedRecordCache,
}

impl TieredCache {
    pub fn new(
        cache_dir: impl AsRef<Path>,
        max_disk_bytes: u64,
        max_decrypted_bytes: usize,
        clock: Arc<dyn Clock>,
    ) -> io::Result<Self> {
        let on_disk = OnDiskBlockCache::new(cache_dir, max_disk_bytes, clock)?;
        let decrypted = DecryptedRecordCache::new(max_decrypted_bytes);
        Ok(Self { on_disk, decrypted })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decrypted_lru_cache() {
        // 6 bytes limit: holds exactly two 3-byte records
        let cache = DecryptedRecordCache::new(6);
        assert!(cache.get(1, 0, 100).is_none());
        assert_eq!(cache.current_bytes(), 0);

        cache.insert(1, 0, 100, Arc::new(vec![1, 2, 3]));
        assert_eq!(cache.current_bytes(), 3);

        cache.insert(1, 0, 200, Arc::new(vec![4, 5, 6]));
        assert_eq!(cache.current_bytes(), 6);

        assert_eq!(cache.get(1, 0, 100).unwrap().as_slice(), &[1, 2, 3]);

        // Insert 3rd entry (3 bytes) evicts oldest (which is 200 because 100 was just accessed)
        cache.insert(1, 0, 300, Arc::new(vec![7, 8, 9]));
        assert_eq!(cache.current_bytes(), 6);
        assert_eq!(cache.len(), 2);
        assert!(cache.get(1, 0, 200).is_none());
        assert!(cache.get(1, 0, 100).is_some());
        assert!(cache.get(1, 0, 300).is_some());

        // Oversized payload (> 6 bytes) is rejected and not cached
        cache.insert(1, 0, 400, Arc::new(vec![0u8; 10]));
        assert!(cache.get(1, 0, 400).is_none());
        assert_eq!(cache.len(), 2);
        assert!(cache.get(1, 0, 3).is_none());

        cache.clear();
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.current_bytes(), 0);
    }

    #[test]
    fn test_decrypted_lru_cache_zero_limit_is_noop() {
        let cache = DecryptedRecordCache::new(0);
        cache.insert(1, 0, 1, Arc::new(vec![1, 2, 3]));
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.current_bytes(), 0);
        assert!(cache.get(1, 0, 1).is_none());
    }

    #[test]
    fn test_decrypted_lru_cache_resize() {
        let cache = DecryptedRecordCache::new(10);
        cache.insert(1, 0, 1, Arc::new(vec![1; 4]));
        cache.insert(1, 0, 2, Arc::new(vec![2; 4]));
        assert_eq!(cache.current_bytes(), 8);

        // Resize smaller evicts LRU (key 1)
        cache.set_max_bytes(5);
        assert_eq!(cache.current_bytes(), 4);
        assert!(cache.get(1, 0, 1).is_none());
        assert!(cache.get(1, 0, 2).is_some());

        // Resize larger allows more elements
        cache.set_max_bytes(20);
        cache.insert(1, 0, 3, Arc::new(vec![3; 10]));
        assert_eq!(cache.current_bytes(), 14);
        assert!(cache.get(1, 0, 2).is_some());
        assert!(cache.get(1, 0, 3).is_some());
    }

    #[test]
    fn test_decrypted_record_cache_dynamic_resizing() {
        let cache = DecryptedRecordCache::new(100);
        cache.insert(1, 0, 1, Arc::new(vec![1; 30]));
        cache.insert(1, 0, 2, Arc::new(vec![2; 30]));
        cache.insert(1, 0, 3, Arc::new(vec![3; 30]));
        assert_eq!(cache.current_bytes(), 90);
        assert_eq!(cache.len(), 3);

        // Dynamically shrink limit to 50 bytes: must evict entry 1 and 2
        cache.set_max_bytes(50);
        assert_eq!(cache.max_bytes(), 50);
        assert!(cache.current_bytes() <= 50);
        assert_eq!(cache.len(), 1);
        assert!(cache.get(1, 0, 1).is_none());
        assert!(cache.get(1, 0, 2).is_none());
        assert!(cache.get(1, 0, 3).is_some());
    }

    #[test]
    fn test_on_disk_block_cache_write_read_and_prune() {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(crate::clock::SystemClock);
        let cache = OnDiskBlockCache::new(dir.path(), 2500, clock).unwrap(); // max 2500 bytes

        assert_eq!(cache.read_block("000001", 0).unwrap(), None);

        let data1 = vec![0xAA; 1000];
        cache.write_block("000001", 0, &data1).unwrap();
        assert_eq!(cache.read_block("000001", 0).unwrap().unwrap(), data1);

        let data2 = vec![0xBB; 1000];
        cache.write_block("000001", 1, &data2).unwrap();

        // 3rd write causes prune
        let data3 = vec![0xCC; 1000];
        cache.write_block("000001", 2, &data3).unwrap();

        // One of the older blocks was pruned to stay under 2500 bytes
        let remaining = [
            cache.read_block("000001", 0).unwrap().is_some(),
            cache.read_block("000001", 1).unwrap().is_some(),
            cache.read_block("000001", 2).unwrap().is_some(),
        ];
        assert_eq!(remaining.iter().filter(|&&b| b).count(), 2);
    }

    #[test]
    fn test_revision_block_cache_separation() {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(crate::clock::SystemClock);
        let cache = OnDiskBlockCache::new(dir.path(), 50000, clock).unwrap();

        let base_data = vec![0x11; 512];
        let r1_data = vec![0x22; 512];

        // Write block 0 for base generation 1 (from 000001.log)
        cache.write_block("000001.log", 0, &base_data).unwrap();

        // Write block 0 for revision 1 of generation 1 (from 000001_r1.log)
        cache.write_block("000001_r1.log", 0, &r1_data).unwrap();

        // Must read distinct data without aliasing or collision
        assert_eq!(cache.read_block("000001", 0).unwrap().unwrap(), base_data);
        assert_eq!(cache.read_block("000001_r1", 0).unwrap().unwrap(), r1_data);
    }

    #[test]
    fn test_on_disk_block_cache_tmp_file_pruning_with_clock() {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(crate::clock::AdvancingClock::new(SystemTime::now()));
        let cache = OnDiskBlockCache::new(dir.path(), 100_000, clock.clone()).unwrap();

        // Write a valid block
        let data = vec![0x42; 100];
        cache.write_block("000001", 0, &data).unwrap();
        assert!(dir.path().join("000001_000000.bin").exists());

        // Create an orphaned temporary file
        let orphaned_tmp = dir.path().join("000001_000001.tmp.12345.1");
        fs::write(&orphaned_tmp, b"incomplete write").unwrap();
        assert!(orphaned_tmp.exists());

        // Right now, age < TMP_FILE_MAX_AGE, so pruning will NOT remove it
        cache.prune_if_needed().unwrap();
        assert!(orphaned_tmp.exists(), "fresh tmp file must not be pruned");

        // Advance clock past TMP_FILE_MAX_AGE (1 hour)
        clock.advance(TMP_FILE_MAX_AGE + Duration::from_secs(10));

        // Now prune should remove the orphaned tmp file
        cache.prune_if_needed().unwrap();
        assert!(!orphaned_tmp.exists(), "aged tmp file must be pruned");

        // The valid block should still be intact
        assert_eq!(cache.read_block("000001", 0).unwrap().unwrap(), data);
    }

    #[test]
    fn test_on_disk_block_cache_lru_touch_on_read() {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(crate::clock::AdvancingClock::new(SystemTime::now()));
        // Capacity for exactly 2 blocks of 1000 bytes
        let cache = OnDiskBlockCache::new(dir.path(), 2500, clock.clone()).unwrap();

        let data0 = vec![0xAA; 1000];
        let data1 = vec![0xBB; 1000];
        let data2 = vec![0xCC; 1000];

        // 1. Write block 0
        cache.write_block("000001", 0, &data0).unwrap();

        // 2. Advance time and write block 1
        clock.advance(Duration::from_secs(60));
        cache.write_block("000001", 1, &data1).unwrap();

        // 3. Advance past BLOCK_TOUCH_THROTTLE
        clock.advance(BLOCK_TOUCH_THROTTLE + Duration::from_secs(30));

        // 4. Access block 0: this refreshes its mtime up to current clock time!
        assert_eq!(cache.read_block("000001", 0).unwrap().unwrap(), data0);

        // 5. Advance time slightly and write block 2 (causing capacity prune)
        clock.advance(Duration::from_secs(5));
        cache.write_block("000001", 2, &data2).unwrap();

        // 6. Verify LRU behavior:
        // Under FIFO, block 0 would have been pruned since it was created first.
        // Under LRU with touch-on-read, block 0 was accessed recently, so block 1 (untouched) is pruned!
        assert!(
            cache.read_block("000001", 0).unwrap().is_some(),
            "Block 0 was recently read and must be retained by LRU"
        );
        assert!(
            cache.read_block("000001", 1).unwrap().is_none(),
            "Block 1 was not accessed and must be pruned"
        );
        assert!(
            cache.read_block("000001", 2).unwrap().is_some(),
            "Block 2 was just written and must be retained"
        );
    }

    #[test]
    fn test_memory_block_cache_write_read_and_prune() {
        let cache = MemoryBlockCache::new(2500);

        assert_eq!(cache.read_block("000001", 0).unwrap(), None);

        let data1 = vec![0xAA; 1000];
        cache.write_block("000001", 0, &data1).unwrap();
        assert_eq!(cache.read_block("000001", 0).unwrap().unwrap(), data1);

        let data2 = vec![0xBB; 1000];
        cache.write_block("000001", 1, &data2).unwrap();

        let data3 = vec![0xCC; 1000];
        cache.write_block("000001", 2, &data3).unwrap();

        let remaining = [
            cache.read_block("000001", 0).unwrap().is_some(),
            cache.read_block("000001", 1).unwrap().is_some(),
            cache.read_block("000001", 2).unwrap().is_some(),
        ];
        assert_eq!(remaining.iter().filter(|&&b| b).count(), 2);
    }
}
