use crate::storage::{Storage, StorageLock, StorageReader, StorageWriter, WriteMode};
use std::io;
use std::sync::Arc;

/// A read-only wrapper around a [`Storage`] instance that permits reads while
/// rejecting all mutating operations and exclusive locks.
#[derive(Clone)]
pub struct ReadOnlyStorage {
    inner: Arc<dyn Storage>,
}

impl std::fmt::Debug for ReadOnlyStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadOnlyStorage").finish()
    }
}

impl ReadOnlyStorage {
    /// Wraps `inner` storage in a read-only decorator.
    pub fn new(inner: Arc<dyn Storage>) -> Self {
        Self { inner }
    }

    /// Returns a reference to the inner storage.
    pub fn inner(&self) -> &Arc<dyn Storage> {
        &self.inner
    }

    /// Consumes the wrapper and returns the inner storage.
    pub fn into_inner(self) -> Arc<dyn Storage> {
        self.inner
    }
}

impl Storage for ReadOnlyStorage {
    fn list_files(&self) -> io::Result<Vec<String>> {
        self.inner.list_files()
    }

    fn exists(&self, name: &str) -> bool {
        self.inner.exists(name)
    }

    fn file_len(&self, name: &str) -> io::Result<u64> {
        self.inner.file_len(name)
    }

    fn remove_file(&self, _name: &str) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "cannot remove files from read-only storage",
        ))
    }

    fn rename(&self, _from: &str, _to: &str) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "cannot rename files on read-only storage",
        ))
    }

    fn open_reader(&self, name: &str) -> io::Result<Arc<dyn StorageReader>> {
        self.inner.open_reader(name)
    }

    fn open_writer(&self, _name: &str, _mode: WriteMode) -> io::Result<Box<dyn StorageWriter>> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "cannot open writer on read-only storage",
        ))
    }

    fn acquire_exclusive_lock(&self) -> io::Result<Box<dyn StorageLock>> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "cannot acquire exclusive lock on read-only storage",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;

    #[test]
    fn test_read_only_storage_delegates_reads_and_rejects_writes() {
        let mem = Arc::new(MemoryStorage::new());
        mem.insert_file("000001.log", b"log data".to_vec());
        let ro = ReadOnlyStorage::new(mem.clone());

        // Reads pass through
        assert!(ro.exists("000001.log"));
        assert!(!ro.exists("nonexistent.log"));
        assert_eq!(ro.file_len("000001.log").unwrap(), 8);
        assert_eq!(ro.list_files().unwrap(), vec!["000001.log".to_string()]);

        let reader = ro.open_reader("000001.log").unwrap();
        let mut buf = [0u8; 8];
        reader.read_exact_at(0, &mut buf).unwrap();
        assert_eq!(&buf, b"log data");

        // Writes and mutations fail with PermissionDenied
        assert!(matches!(
            ro.open_writer("000002.log", WriteMode::CreateNew),
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied
        ));

        let remove_err = ro.remove_file("000001.log").unwrap_err();
        assert_eq!(remove_err.kind(), io::ErrorKind::PermissionDenied);

        let rename_err = ro.rename("000001.log", "renamed.log").unwrap_err();
        assert_eq!(rename_err.kind(), io::ErrorKind::PermissionDenied);

        let lock_err = ro.acquire_exclusive_lock().unwrap_err();
        assert_eq!(lock_err.kind(), io::ErrorKind::PermissionDenied);

        // Underlying storage was not mutated
        assert!(mem.exists("000001.log"));
        assert!(!mem.exists("000002.log"));
        assert!(!mem.exists("renamed.log"));
    }
}
