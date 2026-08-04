use crate::log::record::{FILE_HEADER_SIZE, FileHeader};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Thread-safe cache holding open log file handles to eliminate repeated `open`/`close` syscalls.
pub struct LogFileCache {
    log_dir: PathBuf,
    cache: Mutex<HashMap<u64, Arc<Mutex<File>>>>,
}

impl LogFileCache {
    pub fn new(log_dir: impl AsRef<Path>) -> Self {
        Self {
            log_dir: log_dir.as_ref().to_path_buf(),
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Retrieves an open log file handle, verifying the `FileHeader` on first open.
    pub fn get_or_open(&self, generation: u64) -> io::Result<Arc<Mutex<File>>> {
        let mut guard = self.cache.lock().unwrap();
        if let Some(file_arc) = guard.get(&generation) {
            return Ok(Arc::clone(file_arc));
        }

        let filename = format!("{:06}.log", generation);
        let path = self.log_dir.join(filename);

        let mut file = File::open(&path)?;

        // Verify FileHeader on first open
        let mut header_buf = [0u8; FILE_HEADER_SIZE];
        file.read_exact(&mut header_buf)?;

        FileHeader::from_bytes(&header_buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let file_arc = Arc::new(Mutex::new(file));
        guard.insert(generation, Arc::clone(&file_arc));

        Ok(file_arc)
    }

    pub fn log_dir(&self) -> &Path {
        &self.log_dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::SystemClock;
    use crate::log::writer::LogWriter;
    use tempfile::tempdir;

    #[test]
    fn test_log_file_cache_open_and_verify() {
        let dir = tempdir().unwrap();
        let clock = SystemClock;
        let writer = LogWriter::create(dir.path(), 1, &clock).unwrap();
        writer.sync().unwrap();

        let cache = LogFileCache::new(dir.path());

        // First access opens and verifies header
        let file1 = cache.get_or_open(1).unwrap();

        // Second access returns cached handle
        let file2 = cache.get_or_open(1).unwrap();
        assert!(Arc::ptr_eq(&file1, &file2));
    }
}
