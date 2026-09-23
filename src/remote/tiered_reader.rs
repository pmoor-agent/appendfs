use crate::remote::RemoteReadTarget;
use crate::remote::block_cache::{BLOCK_SIZE, BlockCache};
use crate::storage::{Storage, StorageReader};
use std::hash::{Hash, Hasher};
use std::io;
use std::sync::Arc;

/// A `StorageReader` backed by local storage, remote S3/NFS stores, and a local on-disk block cache.
///
/// For sealed log files, `TieredStorageReader` provides a unified read path:
/// 1. Checks `OnDiskBlockCache` first.
/// 2. Falls back to local storage (if present). If found locally, it reads the chunk directly
///    and saves the 1 MiB block into `OnDiskBlockCache` (pre-warming the cache).
/// 3. If missing locally, falls back to remote stores using streaming range queries (GET).
///    Remotes are queried by priority (lower numbers first). Equal-priority remotes are load-balanced
///    pseudo-randomly but deterministically via a hash of `(filename, block_idx)`.
pub struct TieredStorageReader {
    pub generation: u32,
    pub filename: String,
    pub expected_len: u64,
    pub local_storage: Option<Arc<dyn Storage>>,
    pub remotes: Vec<RemoteReadTarget>,
    pub block_cache: Arc<dyn BlockCache>,
    pub coalescer: Arc<crate::remote::RemoteReadCoalescer>,
}

impl TieredStorageReader {
    pub fn new(
        generation: u32,
        filename: impl Into<String>,
        expected_len: u64,
        remotes: impl IntoIterator<Item = impl Into<RemoteReadTarget>>,
        block_cache: Arc<dyn BlockCache>,
    ) -> Self {
        Self::with_local_storage(generation, filename, expected_len, None, remotes, block_cache)
    }

    pub fn with_local_storage(
        generation: u32,
        filename: impl Into<String>,
        expected_len: u64,
        local_storage: Option<Arc<dyn Storage>>,
        remotes: impl IntoIterator<Item = impl Into<RemoteReadTarget>>,
        block_cache: Arc<dyn BlockCache>,
    ) -> Self {
        let mut remotes: Vec<RemoteReadTarget> = remotes.into_iter().map(Into::into).collect();
        remotes.sort_by(|a, b| (a.priority, &a.name).cmp(&(b.priority, &b.name)));
        let coalescer = Arc::clone(block_cache.coalescer());
        Self {
            generation,
            filename: filename.into(),
            expected_len,
            local_storage,
            remotes,
            block_cache,
            coalescer,
        }
    }

    pub fn with_coalescer(mut self, coalescer: Arc<crate::remote::RemoteReadCoalescer>) -> Self {
        self.coalescer = coalescer;
        self
    }

    fn fetch_range_from_remotes(&self, start_offset: u64, total_len: u64) -> io::Result<Vec<u8>> {
        if start_offset >= self.expected_len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "start offset {} exceeds file length {}",
                    start_offset, self.expected_len
                ),
            ));
        }

        let actual_len = total_len.min(self.expected_len - start_offset);

        // 1. Check local storage first (Tier 0: local file still present before purge)
        if let Some(ref storage) = self.local_storage
            && let Ok(reader) = storage.open_reader(&self.filename)
        {
            let mut buf = vec![0u8; actual_len as usize];
            if reader.read_exact_at(start_offset, &mut buf).is_ok() {
                return Ok(buf);
            }
        }

        let mut last_err = None;

        // 2. Query remotes by priority tier (lower priority number first).
        // Within an equal-priority tier, distribute traffic pseudo-randomly but
        // deterministically based on hash(filename, start_block).
        let start_block = start_offset / BLOCK_SIZE;
        let mut idx = 0;
        while idx < self.remotes.len() {
            let priority = self.remotes[idx].priority;
            let group_start = idx;
            while idx < self.remotes.len() && self.remotes[idx].priority == priority {
                idx += 1;
            }
            let group = &self.remotes[group_start..idx];

            let start_offset_hash = if group.len() > 1 {
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                self.filename.hash(&mut hasher);
                start_block.hash(&mut hasher);
                (hasher.finish() as usize) % group.len()
            } else {
                0
            };

            for i in 0..group.len() {
                let candidate = &group[(start_offset_hash + i) % group.len()];
                let _permit = candidate.acquire_permit();
                let mut buf = Vec::with_capacity(actual_len as usize);
                match candidate
                    .store
                    .get_object_range(&self.filename, start_offset, actual_len, &mut buf)
                {
                    Ok(bytes_read) => {
                        if bytes_read == actual_len {
                            return Ok(buf);
                        }
                        last_err = Some(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            format!(
                                "remote '{}' returned short range read ({} of {} bytes)",
                                candidate.name, bytes_read, actual_len
                            ),
                        ));
                    }
                    Err(e) => {
                        log::warn!(
                            "Tiered read failed for {} (gen {}, offset {} len {}) on remote '{}': {}. Trying next remote...",
                            self.filename,
                            self.generation,
                            start_offset,
                            actual_len,
                            candidate.name,
                            e
                        );
                        last_err = Some(e);
                    }
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "No remotes available to fetch range [{}, {}) of {}",
                    start_offset,
                    start_offset + actual_len,
                    self.filename
                ),
            )
        }))
    }

    /// Fetches a batch of blocks, checking the local [`BlockCache`] first, coalescing concurrent in-flight
    /// fetches via [`RemoteReadCoalescer`], and issuing contiguous multi-megabyte Range GETs to remotes
    /// for any missing adjacent blocks.
    pub fn fetch_blocks_batch(&self, blocks: &[u64]) -> io::Result<std::collections::HashMap<u64, Arc<Vec<u8>>>> {
        let mut result = std::collections::HashMap::new();
        let mut missing = Vec::new();

        for &b in blocks {
            if let Ok(Some(cached)) = self.block_cache.read_block(&self.filename, b) {
                result.insert(b, Arc::new(cached));
            } else {
                missing.push(b);
            }
        }

        if missing.is_empty() {
            return Ok(result);
        }

        let (mut guard, followers) = self.coalescer.register_batch(&self.filename, &missing);
        let leader_blocks = guard.leader_blocks();

        // Identify contiguous runs of leader blocks to fetch in single batched S3 range requests
        let mut runs: Vec<(u64, u64)> = Vec::new();
        for &b in &leader_blocks {
            if let Some(last) = runs.last_mut()
                && last.1 + 1 == b
            {
                last.1 = b;
                continue;
            }
            runs.push((b, b));
        }

        for (run_start, run_end) in runs {
            let byte_start = run_start * BLOCK_SIZE;
            let byte_end = ((run_end + 1) * BLOCK_SIZE).min(self.expected_len);
            let total_len = byte_end.saturating_sub(byte_start);

            if total_len == 0 {
                continue;
            }

            match self.fetch_range_from_remotes(byte_start, total_len) {
                Ok(fetched_bytes) => {
                    let mut curr_offset = 0;
                    for b in run_start..=run_end {
                        let b_start = b * BLOCK_SIZE;
                        let b_len = (BLOCK_SIZE).min(self.expected_len.saturating_sub(b_start)) as usize;
                        let chunk = &fetched_bytes[curr_offset..curr_offset + b_len];
                        curr_offset += b_len;

                        let _ = self.block_cache.write_block(&self.filename, b, chunk);
                        let arc_data = Arc::new(chunk.to_vec());
                        result.insert(b, Arc::clone(&arc_data));
                        guard.complete(b, Ok(arc_data));
                    }
                }
                Err(err) => {
                    for b in run_start..=run_end {
                        guard.complete(b, Err(&err));
                    }
                    return Err(err);
                }
            }
        }

        for follower in followers {
            let data = follower.wait()?;
            result.insert(follower.block_idx, data);
        }

        Ok(result)
    }

    /// Retrieves a single 1 MiB block from cache or fetches it from remotes.
    pub fn get_or_fetch_block(&self, block_idx: u64) -> io::Result<Arc<Vec<u8>>> {
        let mut map = self.fetch_blocks_batch(&[block_idx])?;
        map.remove(&block_idx)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("block {} not found", block_idx)))
    }
}

impl StorageReader for TieredStorageReader {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        if offset
            .checked_add(buf.len() as u64)
            .is_none_or(|end| end > self.expected_len)
        {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "read_exact_at range [{}, {}) exceeds file length {}",
                    offset,
                    offset + buf.len() as u64,
                    self.expected_len
                ),
            ));
        }

        if buf.is_empty() {
            return Ok(());
        }

        let start_block = offset / BLOCK_SIZE;
        let end_block = (offset + buf.len() as u64 - 1) / BLOCK_SIZE;
        let blocks_to_fetch: Vec<u64> = (start_block..=end_block).collect();
        let blocks_data = self.fetch_blocks_batch(&blocks_to_fetch)?;

        let mut buf_offset = 0;
        let mut current_file_offset = offset;
        let mut remaining = buf.len();

        for b in start_block..=end_block {
            let block_data = blocks_data.get(&b).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("missing block {} after batch fetch", b),
                )
            })?;
            let offset_in_block = (current_file_offset % BLOCK_SIZE) as usize;
            let bytes_in_this_block = (block_data.len().saturating_sub(offset_in_block)).min(remaining);
            if bytes_in_this_block == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("short block read at block index {}", b),
                ));
            }

            buf[buf_offset..buf_offset + bytes_in_this_block]
                .copy_from_slice(&block_data[offset_in_block..offset_in_block + bytes_in_this_block]);

            buf_offset += bytes_in_this_block;
            current_file_offset += bytes_in_this_block as u64;
            remaining -= bytes_in_this_block;
        }

        Ok(())
    }

    fn len(&self) -> io::Result<u64> {
        Ok(self.expected_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::block_cache::MemoryBlockCache;
    use crate::remote::mock::MockRemoteStore;
    use crate::remote::{CountingRemoteStore, RemoteStore};

    #[test]
    fn test_tiered_reader_with_block_cache_and_failover() {
        let cache = Arc::new(MemoryBlockCache::new(50 * 1024 * 1024));

        let remote1 = Arc::new(MockRemoteStore::new());
        let remote2 = Arc::new(MockRemoteStore::new());

        let payload = vec![0x42u8; 2 * 1024 * 1024]; // 2 MiB file across 2 blocks
        remote2
            .put_object("000001.log", &mut &payload[..], payload.len() as u64, None)
            .unwrap();

        // Remote 1 is empty; Remote 2 has the file
        let remotes: Vec<(String, Arc<dyn RemoteStore>)> =
            vec![("remote1".to_string(), remote1), ("remote2".to_string(), remote2)];

        let reader = TieredStorageReader::new(1, "000001.log", payload.len() as u64, remotes, cache.clone());
        assert_eq!(reader.len().unwrap(), 2 * 1024 * 1024);

        // Read 100 bytes from block 0
        let mut slice = [0u8; 100];
        reader.read_exact_at(500, &mut slice).unwrap();
        assert_eq!(slice, [0x42u8; 100]);

        // Block 0 is now cached
        assert!(cache.read_block("000001", 0).unwrap().is_some());
        assert!(cache.read_block("000001", 1).unwrap().is_none());

        // Read spanning across block 0 and block 1 boundary
        let cross_offset = BLOCK_SIZE - 50;
        let mut cross_buf = [0u8; 100];
        reader.read_exact_at(cross_offset, &mut cross_buf).unwrap();
        assert_eq!(cross_buf, [0x42u8; 100]);

        // Block 1 is now also cached
        assert!(cache.read_block("000001", 1).unwrap().is_some());
    }

    #[test]
    fn test_tiered_reader_with_local_storage_tier0() {
        use crate::storage::{MemoryStorage, WriteMode};

        let cache = Arc::new(MemoryBlockCache::new(50 * 1024 * 1024));

        let memory_storage = Arc::new(MemoryStorage::new());
        let payload = vec![0x99u8; 1024 * 1024]; // 1 MiB block
        {
            let mut writer = memory_storage.open_writer("000001.log", WriteMode::CreateNew).unwrap();
            writer.append(&payload).unwrap();
            writer.sync().unwrap();
        }

        // Remotes list is EMPTY - data exists solely in local memory_storage!
        let remotes: Vec<(String, Arc<dyn RemoteStore>)> = Vec::new();
        let reader = TieredStorageReader::with_local_storage(
            1,
            "000001.log",
            payload.len() as u64,
            Some(memory_storage.clone()),
            remotes,
            cache.clone(),
        );

        assert!(cache.read_block("000001", 0).unwrap().is_none());

        // Read from reader: should read from local storage AND write to block cache!
        let mut slice = [0u8; 64];
        reader.read_exact_at(128, &mut slice).unwrap();
        assert_eq!(slice, [0x99u8; 64]);

        // Block 0 MUST now be pre-warmed in block cache!
        assert!(cache.read_block("000001", 0).unwrap().is_some());

        // Now drop/truncate the local file to simulate local log purging!
        memory_storage.remove_file("000001.log").unwrap();
        assert!(!memory_storage.exists("000001.log"));

        // Subsequent read MUST still succeed directly from block cache!
        let mut slice2 = [0u8; 64];
        reader.read_exact_at(256, &mut slice2).unwrap();
        assert_eq!(slice2, [0x99u8; 64]);
    }

    #[test]
    fn test_tiered_reader_equal_priority_deterministic_distribution() {
        let cache = Arc::new(MemoryBlockCache::new(50 * 1024 * 1024));

        let store_a = Arc::new(MockRemoteStore::new());
        let store_b = Arc::new(MockRemoteStore::new());

        let total_blocks = 8;
        let payload = vec![0x77u8; (total_blocks * BLOCK_SIZE) as usize];
        store_a
            .put_object("000001.log", &mut &payload[..], payload.len() as u64, None)
            .unwrap();
        store_b
            .put_object("000001.log", &mut &payload[..], payload.len() as u64, None)
            .unwrap();

        // Wrap in CountingRemoteStore to monitor per-remote traffic
        let counting_a = Arc::new(CountingRemoteStore::new(store_a.clone()));
        let counting_b = Arc::new(CountingRemoteStore::new(store_b.clone()));

        // Both stores have equal priority 100
        let remotes = vec![
            RemoteReadTarget::new("store_a", counting_a.clone(), 100),
            RemoteReadTarget::new("store_b", counting_b.clone(), 100),
        ];

        let reader = TieredStorageReader::new(1, "000001.log", payload.len() as u64, remotes, cache.clone());

        // Fetch each block individually
        for b in 0..total_blocks {
            let offset = b * BLOCK_SIZE + 10;
            let mut slice = [0u8; 32];
            reader.read_exact_at(offset, &mut slice).unwrap();
            assert_eq!(slice, [0x77u8; 32]);
        }

        let reads_a = counting_a.range_reads();
        let reads_b = counting_b.range_reads();

        // Total reads must equal total_blocks
        assert_eq!(reads_a + reads_b, total_blocks as usize);
        // Traffic must be distributed to BOTH stores, not all to one!
        assert!(reads_a > 0, "store_a must receive read traffic, got {}", reads_a);
        assert!(reads_b > 0, "store_b must receive read traffic, got {}", reads_b);
    }

    #[test]
    fn test_tiered_reader_multi_block_batch_range_fetch() {
        let cache = Arc::new(MemoryBlockCache::new(50 * 1024 * 1024));
        let mock_remote = Arc::new(MockRemoteStore::new());

        let total_blocks = 5;
        let mut payload = Vec::with_capacity((total_blocks * BLOCK_SIZE) as usize);
        for b in 0..total_blocks {
            payload.extend_from_slice(&vec![(b + 1) as u8; BLOCK_SIZE as usize]);
        }
        mock_remote
            .put_object("000001.log", &mut &payload[..], payload.len() as u64, None)
            .unwrap();

        let counting_remote = Arc::new(CountingRemoteStore::new(mock_remote));
        let remotes = vec![RemoteReadTarget::new("s3", counting_remote.clone(), 100)];
        let reader = TieredStorageReader::new(1, "000001.log", payload.len() as u64, remotes, cache.clone());

        // Read 3 MiB spanning blocks 1, 2, 3 in a single read_exact_at
        let read_offset = BLOCK_SIZE;
        let read_len = (3 * BLOCK_SIZE) as usize;
        let mut buf = vec![0u8; read_len];
        reader.read_exact_at(read_offset, &mut buf).unwrap();

        // Verify data correctness
        assert_eq!(&buf[0..BLOCK_SIZE as usize], &vec![2u8; BLOCK_SIZE as usize][..]);
        assert_eq!(
            &buf[BLOCK_SIZE as usize..2 * BLOCK_SIZE as usize],
            &vec![3u8; BLOCK_SIZE as usize][..]
        );
        assert_eq!(
            &buf[2 * BLOCK_SIZE as usize..3 * BLOCK_SIZE as usize],
            &vec![4u8; BLOCK_SIZE as usize][..]
        );

        // Crucial assertion: Exactly 1 contiguous Range GET request was issued to the remote!
        assert_eq!(
            counting_remote.range_reads(),
            1,
            "Expected exactly 1 batched range read across 3 blocks, got {}",
            counting_remote.range_reads()
        );

        // All 3 constituent blocks MUST now be in the local block cache!
        assert!(cache.read_block("000001", 1).unwrap().is_some());
        assert!(cache.read_block("000001", 2).unwrap().is_some());
        assert!(cache.read_block("000001", 3).unwrap().is_some());

        // Subsequent read of block 2 must be served directly from cache (0 new remote requests)
        let mut slice = [0u8; 128];
        reader.read_exact_at(2 * BLOCK_SIZE + 50, &mut slice).unwrap();
        assert_eq!(slice, [3u8; 128]);
        assert_eq!(counting_remote.range_reads(), 1);
    }

    #[test]
    fn test_tiered_reader_with_concurrency_limiter() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::thread;
        use std::time::Duration;

        let cache = Arc::new(MemoryBlockCache::new(50 * 1024 * 1024));
        let mock_remote = Arc::new(MockRemoteStore::new());

        let total_blocks = 10;
        let payload = vec![0xABu8; (total_blocks * BLOCK_SIZE) as usize];
        mock_remote
            .put_object("000001.log", &mut &payload[..], payload.len() as u64, None)
            .unwrap();

        let max_permits = 2;
        let target = RemoteReadTarget::new("s3", mock_remote, 100).with_concurrency_limit(max_permits);
        let limiter = target.limiter.clone().unwrap();

        let reader = Arc::new(TieredStorageReader::new(
            1,
            "000001.log",
            payload.len() as u64,
            vec![target],
            cache,
        ));

        let active_max = Arc::new(AtomicUsize::new(0));
        let num_threads = 8;
        let mut handles = Vec::new();

        for i in 0..num_threads {
            let r = Arc::clone(&reader);
            let l = Arc::clone(&limiter);
            let a = Arc::clone(&active_max);
            handles.push(thread::spawn(move || {
                let cur = l.active_count();
                a.fetch_max(cur, Ordering::SeqCst);

                let offset = (i as u64) * BLOCK_SIZE;
                let mut buf = [0u8; 256];
                r.read_exact_at(offset, &mut buf).unwrap();
                assert_eq!(buf, [0xABu8; 256]);
                thread::sleep(Duration::from_millis(10));
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(limiter.active_count(), 0);
        assert!(
            active_max.load(Ordering::SeqCst) <= max_permits,
            "Active requests exceeded concurrency limit: got {}",
            active_max.load(Ordering::SeqCst)
        );
    }
}
