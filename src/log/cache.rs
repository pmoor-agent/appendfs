use crate::log::record::{FILE_HEADER_SIZE, FileHeader};
use crate::storage::{OsStorage, Storage, StorageReader};
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Thread-safe cache holding open log file reader handles to eliminate repeated open calls.
pub struct LogFileCache {
    storage: Arc<dyn Storage>,
    cache: Mutex<HashMap<u64, Arc<dyn StorageReader>>>,
}

impl LogFileCache {
    pub fn new(log_dir: impl AsRef<Path>) -> Self {
        let storage = Arc::new(OsStorage::new(log_dir));
        Self::with_storage(storage)
    }

    pub fn with_storage(storage: Arc<dyn Storage>) -> Self {
        Self {
            storage,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Retrieves an open log reader handle, verifying the `FileHeader` on first open.
    pub fn get_or_open(&self, generation: u64) -> io::Result<Arc<dyn StorageReader>> {
        let mut guard = self.cache.lock().unwrap();
        if let Some(reader) = guard.get(&generation) {
            return Ok(Arc::clone(reader));
        }

        let filename = format!("{:06}.log", generation);
        let reader = self.storage.open_reader(&filename)?;

        let mut header_buf = [0u8; FILE_HEADER_SIZE];
        reader.read_exact_at(0, &mut header_buf)?;

        FileHeader::from_bytes(&header_buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        guard.insert(generation, Arc::clone(&reader));
        Ok(reader)
    }

    pub fn storage(&self) -> &Arc<dyn Storage> {
        &self.storage
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::SystemClock;
    use crate::log::writer::LogWriter;
    use crate::storage::MemoryStorage;

    #[test]
    fn test_log_file_cache_open_and_verify() {
        let storage = Arc::new(MemoryStorage::new());
        let clock = SystemClock;
        let writer =
            LogWriter::create_with_storage(storage.clone(), 1, &clock, crate::cli::DEFAULT_MAX_LOG_SIZE, 1)
                .unwrap();
        writer.sync().unwrap();

        let cache = LogFileCache::with_storage(storage);

        // First access opens and verifies header
        let file1 = cache.get_or_open(1).unwrap();

        // Second access returns cached handle
        let file2 = cache.get_or_open(1).unwrap();
        assert!(Arc::ptr_eq(&file1, &file2));
    }
}
