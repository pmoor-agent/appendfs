use crate::error::FsError;
use crate::fs::{FlushReason, InMemoryFS};
use crate::operations::dir::fsyncdir_response;
use crate::operations::read_write::{fsync_response, open_core, read_response, release_core, write_handle_core};
use std::thread;
use std::time::{Duration, Instant};

mod test_fs;

pub use test_fs::{SnapshotNode, TestFS, TestFSBuilder};

/// Blocking, handle-managing shortcuts for driving an `InMemoryFS` from tests.
///
/// Production code reaches the filesystem through the FUSE entry points, which hand back
/// deferred replies and expect the caller to manage file handles. Tests usually just want
/// the outcome, so these wrap those same entry points and wait for the result.
pub trait FsTestExt {
    /// Writes `buf` at `offset` through a read-write handle opened and released around the
    /// call, so the caller does not need one of its own.
    fn write_at(&self, ino: u64, buf: &[u8], offset: i64) -> Result<usize, FsError>;

    /// Reads up to `size` bytes at `offset` through a read-only handle opened and released
    /// around the call.
    fn read_at(&self, ino: u64, offset: i64, size: usize) -> Result<Vec<u8>, FsError>;

    /// Reads up to `size` bytes at `offset` through the open handle `fh`, waiting for the
    /// reply if the read was deferred to the read pool.
    fn read_blocking(&self, ino: u64, fh: u64, offset: i64, size: usize) -> Result<Vec<u8>, FsError>;

    /// Runs `fsync` on `fh` and waits for the flush it triggers to become durable.
    fn fsync_blocking(&self, ino: u64, fh: u64) -> Result<(), FsError>;

    /// Runs `fsyncdir` on `ino` and waits for the flush it triggers to become durable.
    fn fsyncdir_blocking(&self, ino: u64) -> Result<(), FsError>;
}

impl FsTestExt for InMemoryFS {
    fn write_at(&self, ino: u64, buf: &[u8], offset: i64) -> Result<usize, FsError> {
        let fh = open_core(self, ino, libc::O_RDWR as u32)?;
        let res = write_handle_core(self, ino, fh, buf, offset);
        let _ = release_core(self, ino, fh);
        res
    }

    fn read_at(&self, ino: u64, offset: i64, size: usize) -> Result<Vec<u8>, FsError> {
        let fh = open_core(self, ino, libc::O_RDONLY as u32)?;
        let res = self.read_blocking(ino, fh, offset, size);
        let _ = release_core(self, ino, fh);
        res
    }

    fn read_blocking(&self, ino: u64, fh: u64, offset: i64, size: usize) -> Result<Vec<u8>, FsError> {
        let reply = read_response(self, ino, fh, offset, size).wait()?;
        Ok(reply.into_bytes().expect("read replied without a data buffer"))
    }

    fn fsync_blocking(&self, ino: u64, fh: u64) -> Result<(), FsError> {
        fsync_response(self, ino, fh, FlushReason::Fsync).wait().map(|_| ())
    }

    fn fsyncdir_blocking(&self, ino: u64) -> Result<(), FsError> {
        fsyncdir_response(self, ino, false).wait().map(|_| ())
    }
}

/// Repeatedly executes `condition` until it returns `true` or `timeout` has elapsed.
///
/// Checks the condition every 5 milliseconds (or upon timeout). Returns `true` if the
/// condition was met within the timeout period, or `false` otherwise.
pub fn wait_until<F>(mut condition: F, timeout: Duration) -> bool
where
    F: FnMut() -> bool,
{
    let start = Instant::now();
    while start.elapsed() < timeout {
        if condition() {
            return true;
        }
        thread::sleep(Duration::from_millis(5));
    }
    condition()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn test_wait_until_immediate_true() {
        assert!(wait_until(|| true, Duration::from_millis(50)));
    }

    #[test]
    fn test_wait_until_eventual_true() {
        let flag = Arc::new(AtomicBool::new(false));
        let flag_clone = Arc::clone(&flag);
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            flag_clone.store(true, Ordering::SeqCst);
        });
        assert!(wait_until(|| flag.load(Ordering::SeqCst), Duration::from_secs(1)));
    }

    #[test]
    fn test_wait_until_timeout() {
        assert!(!wait_until(|| false, Duration::from_millis(20)));
    }
}
