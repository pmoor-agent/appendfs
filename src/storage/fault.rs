use crate::storage::{Storage, StorageReader, StorageWriter, WriteMode};
use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

/// Storage wrapper capable of injecting fine-grained faults for test verification.
#[derive(Clone)]
pub struct FaultStorage {
    inner: Arc<dyn Storage>,
    max_append_bytes: Arc<AtomicU64>,
    write_partial_on_fail: Arc<AtomicBool>,
    fail_sync: Arc<AtomicBool>,
    fail_lock_records: Arc<AtomicBool>,
    fail_on_open: Arc<RwLock<HashMap<String, io::ErrorKind>>>,
    bitflips: Arc<RwLock<Vec<(String, u64, u8)>>>,
    truncated: Arc<Mutex<Vec<TruncatedTail>>>,
}

/// Bytes a `truncate` cut off the end of a file, as they were just before the cut.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TruncatedTail {
    pub filename: String,
    pub offset: u64,
    pub bytes: Vec<u8>,
}

impl FaultStorage {
    pub fn new(inner: Arc<dyn Storage>) -> Self {
        Self {
            inner,
            max_append_bytes: Arc::new(AtomicU64::new(0)),
            write_partial_on_fail: Arc::new(AtomicBool::new(false)),
            fail_sync: Arc::new(AtomicBool::new(false)),
            fail_lock_records: Arc::new(AtomicBool::new(false)),
            fail_on_open: Arc::new(RwLock::new(HashMap::new())),
            bitflips: Arc::new(RwLock::new(Vec::new())),
            truncated: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Every tail cut off by a writer's `truncate`, in order.
    ///
    /// A rollback erases what a failed attempt wrote, but on a real disk those bytes can
    /// outlive the truncate; this keeps them so a test can compare them with the retry.
    pub fn truncated_tails(&self) -> Vec<TruncatedTail> {
        self.truncated.lock().unwrap().clone()
    }

    /// Sets whether `sync` should fail with simulated I/O error.
    pub fn fail_syncs(&self, fail: bool) {
        self.fail_sync.store(fail, Ordering::SeqCst);
    }

    /// Sets whether recording a lock's holder should fail with a simulated I/O error.
    pub fn fail_lock_records(&self, fail: bool) {
        self.fail_lock_records.store(fail, Ordering::SeqCst);
    }

    /// Sets a byte threshold after which `append` will fail with simulated ENOSPC / EFBIG.
    pub fn fail_writes_after_bytes(&self, limit: u64, write_partial: bool) {
        self.max_append_bytes.store(limit, Ordering::SeqCst);
        self.write_partial_on_fail.store(write_partial, Ordering::SeqCst);
    }

    /// Clears any write limit.
    pub fn clear_write_limit(&self) {
        self.max_append_bytes.store(0, Ordering::SeqCst);
        self.write_partial_on_fail.store(false, Ordering::SeqCst);
    }

    /// Injects an error when opening a specific file.
    pub fn fail_on_file(&self, filename: &str, error_kind: io::ErrorKind) {
        self.fail_on_open
            .write()
            .unwrap()
            .insert(filename.to_string(), error_kind);
    }

    /// Clears any injected open failure for a specific file.
    pub fn clear_fail_on_file(&self, filename: &str) {
        self.fail_on_open.write().unwrap().remove(filename);
    }

    /// Clears all injected faults (write limits, open errors, bitflips).
    pub fn clear_all_faults(&self) {
        self.clear_write_limit();
        self.fail_sync.store(false, Ordering::SeqCst);
        self.fail_lock_records.store(false, Ordering::SeqCst);
        self.fail_on_open.write().unwrap().clear();
        self.bitflips.write().unwrap().clear();
    }

    /// Injects a bitflip at a specific byte offset in a file on read.
    pub fn inject_bitflip(&self, filename: &str, offset: u64, bit_mask: u8) {
        self.bitflips
            .write()
            .unwrap()
            .push((filename.to_string(), offset, bit_mask));
    }
}

pub struct FaultStorageReader {
    inner: Arc<dyn StorageReader>,
    filename: String,
    bitflips: Arc<RwLock<Vec<(String, u64, u8)>>>,
}

impl StorageReader for FaultStorageReader {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        self.inner.read_exact_at(offset, buf)?;

        let flips = self.bitflips.read().unwrap();
        for (f_name, flip_offset, mask) in flips.iter() {
            if f_name == &self.filename {
                let start = offset;
                let end = offset + buf.len() as u64;
                if *flip_offset >= start && *flip_offset < end {
                    let idx = (*flip_offset - start) as usize;
                    buf[idx] ^= *mask;
                }
            }
        }
        Ok(())
    }

    fn len(&self) -> io::Result<u64> {
        self.inner.len()
    }
}

pub struct FaultStorageWriter {
    inner: Box<dyn StorageWriter>,
    storage: Arc<dyn Storage>,
    filename: String,
    truncated: Arc<Mutex<Vec<TruncatedTail>>>,
    max_append_bytes: Arc<AtomicU64>,
    write_partial_on_fail: Arc<AtomicBool>,
    fail_sync: Arc<AtomicBool>,
}

impl StorageWriter for FaultStorageWriter {
    fn append(&mut self, data: &[u8]) -> io::Result<()> {
        let limit = self.max_append_bytes.load(Ordering::SeqCst);
        if limit > 0 {
            let cur_len = self.inner.len()?;
            if cur_len + data.len() as u64 > limit {
                if self.write_partial_on_fail.load(Ordering::SeqCst) {
                    let partial_len = (data.len() / 2).max(1);
                    let _ = self.inner.append(&data[..partial_len]);
                }
                return Err(io::Error::other("simulated ENOSPC / EFBIG write failure"));
            }
        }
        self.inner.append(data)
    }

    fn truncate(&mut self, len: u64) -> io::Result<()> {
        let current_len = self.inner.len()?;
        if len < current_len {
            let mut bytes = vec![0u8; (current_len - len) as usize];
            self.storage
                .open_reader(&self.filename)?
                .read_exact_at(len, &mut bytes)?;
            self.truncated.lock().unwrap().push(TruncatedTail {
                filename: self.filename.clone(),
                offset: len,
                bytes,
            });
        }
        self.inner.truncate(len)
    }

    fn sync(&mut self) -> io::Result<()> {
        if self.fail_sync.load(Ordering::SeqCst) {
            return Err(io::Error::other("simulated sync failure"));
        }
        self.inner.sync()
    }

    fn len(&self) -> io::Result<u64> {
        self.inner.len()
    }
}

impl Storage for FaultStorage {
    fn list_files(&self) -> io::Result<Vec<String>> {
        self.inner.list_files()
    }

    fn exists(&self, name: &str) -> bool {
        self.inner.exists(name)
    }

    fn remove_file(&self, name: &str) -> io::Result<()> {
        self.inner.remove_file(name)
    }

    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        self.inner.rename(from, to)
    }

    fn open_reader(&self, name: &str) -> io::Result<Arc<dyn StorageReader>> {
        if let Some(err_kind) = self.fail_on_open.read().unwrap().get(name) {
            return Err(io::Error::new(*err_kind, format!("fault injected on {}", name)));
        }
        let reader = self.inner.open_reader(name)?;
        Ok(Arc::new(FaultStorageReader {
            inner: reader,
            filename: name.to_string(),
            bitflips: Arc::clone(&self.bitflips),
        }))
    }

    fn open_writer(&self, name: &str, mode: WriteMode) -> io::Result<Box<dyn StorageWriter>> {
        if let Some(err_kind) = self.fail_on_open.read().unwrap().get(name) {
            return Err(io::Error::new(*err_kind, format!("fault injected on {}", name)));
        }
        let writer = self.inner.open_writer(name, mode)?;
        Ok(Box::new(FaultStorageWriter {
            inner: writer,
            storage: Arc::clone(&self.inner),
            filename: name.to_string(),
            truncated: Arc::clone(&self.truncated),
            max_append_bytes: Arc::clone(&self.max_append_bytes),
            write_partial_on_fail: Arc::clone(&self.write_partial_on_fail),
            fail_sync: Arc::clone(&self.fail_sync),
        }))
    }

    fn acquire_exclusive_lock(&self) -> io::Result<Box<dyn crate::storage::StorageLock>> {
        Ok(Box::new(FaultLock {
            inner: self.inner.acquire_exclusive_lock()?,
            fail_records: Arc::clone(&self.fail_lock_records),
        }))
    }
}

#[derive(Debug)]
pub struct FaultLock {
    inner: Box<dyn crate::storage::StorageLock>,
    fail_records: Arc<AtomicBool>,
}

impl crate::storage::StorageLock for FaultLock {
    fn record_holder(&self) -> io::Result<()> {
        if self.fail_records.load(Ordering::SeqCst) {
            return Err(io::Error::other("simulated failure recording the lock holder"));
        }
        self.inner.record_holder()
    }
}
