use std::io;
use std::sync::Arc;

pub mod fault;
pub mod memory;
pub mod os;

pub use fault::FaultStorage;
pub use memory::MemoryStorage;
pub use os::OsStorage;

/// Read-only access to a stored file. Completely stateless and thread-safe.
pub trait StorageReader: Send + Sync {
    /// Read exact buffer slice at the given byte offset (positional read / pread).
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()>;

    /// Returns the total length of the file in bytes.
    fn len(&self) -> io::Result<u64>;

    /// Returns `true` if the file length is 0.
    fn is_empty(&self) -> io::Result<bool> {
        Ok(self.len()? == 0)
    }

    /// Convenience helper to read a new byte vector.
    fn read_vec(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        self.read_exact_at(offset, &mut buf)?;
        Ok(buf)
    }
}

/// Appendable write handle for an active log or summary file.
pub trait StorageWriter: Send + Sync {
    /// Appends data to the end of the file.
    fn append(&mut self, data: &[u8]) -> io::Result<()>;

    /// Truncates the file to `len` bytes (used for write rollback on error).
    fn truncate(&mut self, len: u64) -> io::Result<()>;

    /// Flushes any buffered data and ensures persistence.
    fn sync(&mut self) -> io::Result<()>;

    /// Returns the current length / write offset of the file.
    fn len(&self) -> io::Result<u64>;

    /// Returns `true` if the file length is 0.
    fn is_empty(&self) -> io::Result<bool> {
        Ok(self.len()? == 0)
    }
}

/// Volume log storage container interface.
pub trait Storage: Send + Sync {
    /// Lists all file names in the volume (e.g. `["000001.log", "000001.summary"]`).
    fn list_files(&self) -> io::Result<Vec<String>>;

    /// Checks if a file exists.
    fn exists(&self, name: &str) -> bool;

    /// Returns the length of a file in bytes if it exists.
    fn file_len(&self, name: &str) -> io::Result<u64> {
        let reader = self.open_reader(name)?;
        reader.len()
    }

    /// Removes a file if it exists.
    fn remove_file(&self, name: &str) -> io::Result<()>;

    /// Atomically renames a file (e.g. `000001.summary.tmp` -> `000001.summary`).
    fn rename(&self, from: &str, to: &str) -> io::Result<()>;

    /// Opens a file for reading.
    fn open_reader(&self, name: &str) -> io::Result<Arc<dyn StorageReader>>;

    /// Opens a file for append-writing. If `create_new` is true, fails if it already exists.
    fn open_writer(&self, name: &str, create_new: bool) -> io::Result<Box<dyn StorageWriter>>;
}

impl<T: StorageReader + ?Sized> StorageReader for Arc<T> {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        (**self).read_exact_at(offset, buf)
    }

    fn len(&self) -> io::Result<u64> {
        (**self).len()
    }
}

impl<T: Storage + ?Sized> Storage for Arc<T> {
    fn list_files(&self) -> io::Result<Vec<String>> {
        (**self).list_files()
    }

    fn exists(&self, name: &str) -> bool {
        (**self).exists(name)
    }

    fn file_len(&self, name: &str) -> io::Result<u64> {
        (**self).file_len(name)
    }

    fn remove_file(&self, name: &str) -> io::Result<()> {
        (**self).remove_file(name)
    }

    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        (**self).rename(from, to)
    }

    fn open_reader(&self, name: &str) -> io::Result<Arc<dyn StorageReader>> {
        (**self).open_reader(name)
    }

    fn open_writer(&self, name: &str, create_new: bool) -> io::Result<Box<dyn StorageWriter>> {
        (**self).open_writer(name, create_new)
    }
}

impl<T: Storage + ?Sized> Storage for &T {
    fn list_files(&self) -> io::Result<Vec<String>> {
        (**self).list_files()
    }

    fn exists(&self, name: &str) -> bool {
        (**self).exists(name)
    }

    fn file_len(&self, name: &str) -> io::Result<u64> {
        (**self).file_len(name)
    }

    fn remove_file(&self, name: &str) -> io::Result<()> {
        (**self).remove_file(name)
    }

    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        (**self).rename(from, to)
    }

    fn open_reader(&self, name: &str) -> io::Result<Arc<dyn StorageReader>> {
        (**self).open_reader(name)
    }

    fn open_writer(&self, name: &str, create_new: bool) -> io::Result<Box<dyn StorageWriter>> {
        (**self).open_writer(name, create_new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_storage_crud_and_truncation() {
        let storage = MemoryStorage::new();
        assert!(!storage.exists("test.log"));

        let mut writer = storage.open_writer("test.log", true).unwrap();
        writer.append(b"hello world").unwrap();
        assert_eq!(writer.len().unwrap(), 11);
        writer.truncate(5).unwrap();
        assert_eq!(writer.len().unwrap(), 5);
        writer.append(b" there!").unwrap();
        assert_eq!(writer.len().unwrap(), 12);
        drop(writer);

        let reader = storage.open_reader("test.log").unwrap();
        assert_eq!(reader.len().unwrap(), 12);
        let mut buf = [0u8; 12];
        reader.read_exact_at(0, &mut buf).unwrap();
        assert_eq!(&buf, b"hello there!");

        let mut slice = [0u8; 6];
        reader.read_exact_at(6, &mut slice).unwrap();
        assert_eq!(&slice, b"there!");

        storage.rename("test.log", "test.renamed").unwrap();
        assert!(!storage.exists("test.log"));
        assert!(storage.exists("test.renamed"));

        let files = storage.list_files().unwrap();
        assert_eq!(files, vec!["test.renamed".to_string()]);

        storage.remove_file("test.renamed").unwrap();
        assert!(!storage.exists("test.renamed"));
    }

    #[test]
    fn test_os_storage_crud_and_positional_reads() {
        let dir = tempfile::tempdir().unwrap();
        let storage = OsStorage::new(dir.path());

        let mut writer = storage.open_writer("os_test.bin", true).unwrap();
        writer.append(b"0123456789ABCDEF").unwrap();
        writer.sync().unwrap();
        assert_eq!(writer.len().unwrap(), 16);
        writer.truncate(10).unwrap();
        assert_eq!(writer.len().unwrap(), 10);
        drop(writer);

        let reader = storage.open_reader("os_test.bin").unwrap();
        assert_eq!(reader.len().unwrap(), 10);
        let mut buf = [0u8; 4];
        reader.read_exact_at(6, &mut buf).unwrap();
        assert_eq!(&buf, b"6789");

        storage.rename("os_test.bin", "os_test_2.bin").unwrap();
        assert!(storage.exists("os_test_2.bin"));
        assert_eq!(storage.file_len("os_test_2.bin").unwrap(), 10);

        let files = storage.list_files().unwrap();
        assert_eq!(files, vec!["os_test_2.bin".to_string()]);
    }

    #[test]
    fn test_fault_storage_injection_and_bitflips() {
        let mem = Arc::new(MemoryStorage::new());
        let fault = FaultStorage::new(mem);

        // Fail open
        fault.fail_on_file("protected.log", io::ErrorKind::PermissionDenied);
        let err = match fault.open_writer("protected.log", true) {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        };
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);

        // Write limit with partial write
        let mut writer = fault.open_writer("data.log", true).unwrap();
        writer.append(b"initial 10").unwrap();
        assert_eq!(writer.len().unwrap(), 10);

        fault.fail_writes_after_bytes(15, true);
        let err = writer.append(b"1234567890").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
        // Partial write succeeded up to 15 bytes total
        assert_eq!(writer.len().unwrap(), 15);
        drop(writer);

        // Inject bitflip at byte 0
        fault.inject_bitflip("data.log", 0, 0x01);
        let reader = fault.open_reader("data.log").unwrap();
        let mut first_byte = [0u8; 1];
        reader.read_exact_at(0, &mut first_byte).unwrap();
        assert_eq!(first_byte[0], b'i' ^ 0x01);
    }
}
