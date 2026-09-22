use crate::storage::StorageWriter;
use std::io;

/// Default buffer capacity for `BufferedStorageWriter` (64 KiB).
pub const DEFAULT_STORAGE_BUFFER_CAPACITY: usize = 64 * 1024;

/// A buffering decorator for any `StorageWriter` that coalesces small appends in userspace memory.
pub struct BufferedStorageWriter<W: StorageWriter = Box<dyn StorageWriter>> {
    inner: W,
    buffer: Vec<u8>,
    flushed_len: u64,
}

impl<W: StorageWriter> BufferedStorageWriter<W> {
    /// Creates a new `BufferedStorageWriter` with the default 64 KiB buffer capacity.
    pub fn new(inner: W) -> io::Result<Self> {
        Self::with_capacity(inner, DEFAULT_STORAGE_BUFFER_CAPACITY)
    }

    /// Creates a new `BufferedStorageWriter` with a custom buffer capacity.
    pub fn with_capacity(inner: W, capacity: usize) -> io::Result<Self> {
        let flushed_len = inner.len()?;
        Ok(Self {
            inner,
            buffer: Vec::with_capacity(capacity),
            flushed_len,
        })
    }

    /// Flushes unwritten buffered data to the underlying storage writer.
    pub fn flush_buffer(&mut self) -> io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        self.inner.append(&self.buffer)?;
        self.flushed_len += self.buffer.len() as u64;
        self.buffer.clear();
        Ok(())
    }
}

impl<W: StorageWriter> StorageWriter for BufferedStorageWriter<W> {
    fn append(&mut self, data: &[u8]) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let capacity = self.buffer.capacity();

        if self.buffer.len() + data.len() <= capacity {
            self.buffer.extend_from_slice(data);
            return Ok(());
        }

        self.flush_buffer()?;

        if data.len() >= capacity {
            self.inner.append(data)?;
            self.flushed_len += data.len() as u64;
        } else {
            self.buffer.extend_from_slice(data);
        }
        Ok(())
    }

    fn truncate(&mut self, len: u64) -> io::Result<()> {
        let current_len = self.flushed_len + self.buffer.len() as u64;

        if len > current_len {
            self.flush_buffer()?;
            self.inner.truncate(len)?;
            self.flushed_len = len;
            return Ok(());
        }

        if len > self.flushed_len {
            // Truncating within the buffered region: ensure the underlying file is
            // cleanly truncated to flushed_len in case a prior failed write left partial bytes.
            self.inner.truncate(self.flushed_len)?;
            let keep = (len - self.flushed_len) as usize;
            self.buffer.truncate(keep);
            return Ok(());
        }

        self.buffer.clear();
        self.inner.truncate(len)?;
        self.flushed_len = len;
        Ok(())
    }

    fn sync(&mut self) -> io::Result<()> {
        self.flush_buffer()?;
        self.inner.sync()
    }

    fn len(&self) -> io::Result<u64> {
        Ok(self.flushed_len + self.buffer.len() as u64)
    }
}

impl<W: StorageWriter> Drop for BufferedStorageWriter<W> {
    fn drop(&mut self) {
        let _ = self.flush_buffer();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::memory::MemoryStorage;
    use crate::storage::{FaultStorage, Storage, WriteMode};
    use std::sync::Arc;

    #[test]
    fn test_buffered_writer_with_memory_storage() {
        let storage = MemoryStorage::new();
        let raw = storage.open_writer("test.bin", WriteMode::CreateNew).unwrap();
        let mut writer = BufferedStorageWriter::with_capacity(raw, 1024).unwrap();

        assert_eq!(writer.len().unwrap(), 0);
        assert!(writer.is_empty().unwrap());

        let data = vec![0xAB; 100];
        writer.append(&data).unwrap();

        // Staged in buffer, fake backend still empty
        assert_eq!(writer.len().unwrap(), 100);
        assert_eq!(storage.get_file_bytes("test.bin").unwrap().len(), 0);

        writer.sync().unwrap();
        assert_eq!(writer.len().unwrap(), 100);
        assert_eq!(storage.get_file_bytes("test.bin").unwrap(), data);
    }

    #[test]
    fn test_buffered_writer_truncate_within_buffer() {
        let storage = MemoryStorage::new();
        let raw = storage.open_writer("test.bin", WriteMode::CreateNew).unwrap();
        let mut writer = BufferedStorageWriter::with_capacity(raw, 200).unwrap();

        writer.append(b"hello world").unwrap(); // 11 bytes
        assert_eq!(writer.len().unwrap(), 11);
        assert_eq!(storage.get_file_bytes("test.bin").unwrap().len(), 0);

        // Truncate to 5 bytes ("hello") in buffer (pure memory manipulation, 0 backend writes)
        writer.truncate(5).unwrap();
        assert_eq!(writer.len().unwrap(), 5);
        assert_eq!(storage.get_file_bytes("test.bin").unwrap().len(), 0);

        // Append more data
        writer.append(b" rust").unwrap();
        assert_eq!(writer.len().unwrap(), 10);

        writer.sync().unwrap();
        assert_eq!(storage.get_file_bytes("test.bin").unwrap(), b"hello rust");
    }

    #[test]
    fn test_buffered_writer_truncate_across_flushed_boundary() {
        let storage = MemoryStorage::new();
        let raw = storage.open_writer("test.bin", WriteMode::CreateNew).unwrap();
        let mut writer = BufferedStorageWriter::with_capacity(raw, 100).unwrap();

        writer.append(b"0123456789ABCDEF").unwrap(); // 16 bytes
        writer.sync().unwrap();
        assert_eq!(storage.get_file_bytes("test.bin").unwrap().len(), 16);

        // Buffer 10 more bytes
        writer.append(b"GHIJKLMNOP").unwrap();
        assert_eq!(writer.len().unwrap(), 26);
        assert_eq!(storage.get_file_bytes("test.bin").unwrap().len(), 16);

        // Truncate to 10 bytes (below flushed 16 bytes)
        writer.truncate(10).unwrap();
        assert_eq!(writer.len().unwrap(), 10);
        assert_eq!(storage.get_file_bytes("test.bin").unwrap().len(), 10);

        writer.append(b"XXXXX").unwrap();
        assert_eq!(writer.len().unwrap(), 15);
        writer.sync().unwrap();
        assert_eq!(storage.get_file_bytes("test.bin").unwrap(), b"0123456789XXXXX");
    }

    #[test]
    fn test_buffered_writer_overflow_and_large_writes() {
        let storage = MemoryStorage::new();
        let raw = storage.open_writer("test.bin", WriteMode::CreateNew).unwrap();
        let mut writer = BufferedStorageWriter::with_capacity(raw, 100).unwrap();

        // 1. Write 60 bytes (buffered)
        writer.append(&[b'A'; 60]).unwrap();
        assert_eq!(storage.get_file_bytes("test.bin").unwrap().len(), 0);
        assert_eq!(writer.len().unwrap(), 60);

        // 2. Write 50 bytes (overflow: flushes 60, buffers 50)
        writer.append(&[b'B'; 50]).unwrap();
        assert_eq!(storage.get_file_bytes("test.bin").unwrap().len(), 60);
        assert_eq!(writer.len().unwrap(), 110);

        // 3. Write 150 bytes (direct large write: flushes 50, writes 150 directly to backend)
        writer.append(&[b'C'; 150]).unwrap();
        assert_eq!(storage.get_file_bytes("test.bin").unwrap().len(), 260);
        assert_eq!(writer.len().unwrap(), 260);

        let bytes = storage.get_file_bytes("test.bin").unwrap();
        assert_eq!(&bytes[0..60], &[b'A'; 60]);
        assert_eq!(&bytes[60..110], &[b'B'; 50]);
        assert_eq!(&bytes[110..260], &[b'C'; 150]);
    }

    #[test]
    fn test_buffered_writer_zero_capacity() {
        let storage = MemoryStorage::new();
        let raw = storage.open_writer("test.bin", WriteMode::CreateNew).unwrap();
        let mut writer = BufferedStorageWriter::with_capacity(raw, 0).unwrap();

        writer.append(b"unbuffered write").unwrap();
        assert_eq!(storage.get_file_bytes("test.bin").unwrap(), b"unbuffered write");
        assert_eq!(writer.len().unwrap(), 16);
    }

    #[test]
    fn test_buffered_writer_truncate_extending() {
        let storage = MemoryStorage::new();
        let raw = storage.open_writer("test.bin", WriteMode::CreateNew).unwrap();
        let mut writer = BufferedStorageWriter::with_capacity(raw, 100).unwrap();

        writer.append(b"abcde").unwrap();
        writer.truncate(10).unwrap();
        assert_eq!(writer.len().unwrap(), 10);

        writer.sync().unwrap();
        let bytes = storage.get_file_bytes("test.bin").unwrap();
        assert_eq!(bytes.len(), 10);
        assert_eq!(&bytes[0..5], b"abcde");
        assert_eq!(&bytes[5..10], &[0u8; 5]);
    }

    #[test]
    fn test_buffered_writer_drop_flushes_unwritten_buffer() {
        let storage = MemoryStorage::new();
        let raw = storage.open_writer("test.bin", WriteMode::CreateNew).unwrap();
        let mut writer = BufferedStorageWriter::with_capacity(raw, 1024).unwrap();

        writer.append(b"dropped data").unwrap();
        assert_eq!(storage.get_file_bytes("test.bin").unwrap().len(), 0);

        drop(writer);
        assert_eq!(storage.get_file_bytes("test.bin").unwrap(), b"dropped data");
    }

    #[test]
    fn test_buffered_writer_with_fault_storage() {
        let mem = Arc::new(MemoryStorage::new());
        let fault = FaultStorage::new(mem.clone());
        let raw = fault.open_writer("test.bin", WriteMode::CreateNew).unwrap();
        let mut writer = BufferedStorageWriter::with_capacity(raw, 50).unwrap();

        // Set fault limit after 70 bytes
        fault.fail_writes_after_bytes(70, false);

        // 1. Write 40 bytes (buffered in RAM, fault storage not hit)
        writer.append(&[0x11; 40]).unwrap();
        assert_eq!(writer.len().unwrap(), 40);

        // 2. Write 40 bytes (total 80 > capacity 50: flushes first 40 bytes to disk,
        // and buffers next 40 bytes in userspace RAM; on-disk = 40 <= limit 70)
        writer.append(&[0x22; 40]).unwrap();
        assert_eq!(writer.len().unwrap(), 80);

        // 3. Sync flushes the remaining 40 bytes to disk (total disk = 80 > limit 70 -> fails!)
        let err = writer.sync().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);

        // Rollback to initial
        writer.truncate(0).unwrap();
        assert_eq!(writer.len().unwrap(), 0);

        // Clear fault and retry cleanly
        fault.clear_write_limit();
        writer.append(b"recovered write").unwrap();
        writer.sync().unwrap();
        assert_eq!(mem.get_file_bytes("test.bin").unwrap(), b"recovered write");
    }

    #[test]
    fn test_buffered_writer_truncate_cleans_partial_write_in_buffered_region() {
        let mem = Arc::new(MemoryStorage::new());
        let fault = FaultStorage::new(mem.clone());
        let raw = fault.open_writer("test.bin", WriteMode::CreateNew).unwrap();
        let mut writer = BufferedStorageWriter::with_capacity(raw, 100).unwrap();

        // 1. Flush 50 bytes cleanly to disk
        writer.append(&[0x11; 50]).unwrap();
        writer.sync().unwrap();
        assert_eq!(mem.get_file_bytes("test.bin").unwrap().len(), 50);

        // 2. Buffer 40 more bytes (logical len = 90)
        writer.append(&[0x22; 40]).unwrap();
        assert_eq!(writer.len().unwrap(), 90);

        // 3. Set fault limit to fail after 70 bytes with partial write (writes 40/2 = 20 bytes before error)
        fault.fail_writes_after_bytes(70, true);
        assert!(writer.sync().is_err());
        // On disk, 50 + 20 = 70 bytes are now written (torn partial write!)
        assert_eq!(mem.get_file_bytes("test.bin").unwrap().len(), 70);

        // 4. Now truncate to 60 bytes (within the buffered region: flushed=50, target=60 < 90)
        fault.clear_write_limit();
        writer.truncate(60).unwrap();
        assert_eq!(writer.len().unwrap(), 60);
        // Underlying storage must have been rolled back to flushed_len (50)!
        assert_eq!(mem.get_file_bytes("test.bin").unwrap().len(), 50);

        // 5. Now sync: it should write the 10 buffered bytes cleanly from 50 to 60
        writer.sync().unwrap();
        assert_eq!(mem.get_file_bytes("test.bin").unwrap().len(), 60);
        let bytes = mem.get_file_bytes("test.bin").unwrap();
        assert_eq!(&bytes[0..50], &[0x11; 50]);
        assert_eq!(&bytes[50..60], &[0x22; 10]);
    }
}
