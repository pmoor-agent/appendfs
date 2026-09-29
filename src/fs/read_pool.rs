//! Bounded worker threadpool for asynchronous cold disk and remote reads.

use crate::error::FsError;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

type Job = Box<dyn FnOnce() + Send + 'static>;

/// A dedicated threadpool for offloading cold disk and remote read requests
/// away from the single-threaded FUSE event loop.
pub struct ReadThreadPool {
    sender: Mutex<Option<Sender<Job>>>,
    workers: Mutex<Vec<JoinHandle<()>>>,
    num_workers: usize,
}

impl ReadThreadPool {
    /// Creates a new [`ReadThreadPool`] with the specified number of worker threads.
    ///
    /// The worker count is clamped to `1..=16`.
    pub fn new(workers: usize) -> Self {
        let num_workers = workers.clamp(1, 16);
        let (tx, rx) = mpsc::channel::<Job>();
        let rx = Arc::new(Mutex::new(rx));
        let mut handles = Vec::with_capacity(num_workers);

        for i in 0..num_workers {
            let rx = Arc::clone(&rx);
            let handle = thread::Builder::new()
                .name(format!("appendfs-read-{}", i))
                .spawn(move || {
                    while let Ok(job) = rx.lock().unwrap().recv() {
                        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
                    }
                })
                .expect("failed to spawn read worker thread");
            handles.push(handle);
        }

        Self {
            sender: Mutex::new(Some(tx)),
            workers: Mutex::new(handles),
            num_workers,
        }
    }

    /// Submits a task for asynchronous execution on the threadpool.
    ///
    /// Returns [`FsError::EIO`] if the pool has been shut down.
    pub fn spawn(&self, f: impl FnOnce() + Send + 'static) -> Result<(), FsError> {
        let sender = self.sender.lock().unwrap();
        if let Some(ref tx) = *sender {
            tx.send(Box::new(f)).map_err(|_| FsError::EIO)
        } else {
            Err(FsError::EIO)
        }
    }

    /// Returns the configured number of worker threads for this pool.
    pub fn num_workers(&self) -> usize {
        self.num_workers
    }

    /// Signals all workers to stop and joins their threads.
    pub fn shutdown(&self) {
        if let Some(tx) = self.sender.lock().unwrap().take() {
            drop(tx);
            let mut workers = self.workers.lock().unwrap();
            for handle in workers.drain(..) {
                let _ = handle.join();
            }
        }
    }
}

impl Drop for ReadThreadPool {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl std::fmt::Debug for ReadThreadPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadThreadPool")
            .field("num_workers", &self.num_workers)
            .field("is_active", &self.sender.lock().unwrap().is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn test_read_thread_pool_execution() {
        let pool = ReadThreadPool::new(4);
        assert_eq!(pool.num_workers(), 4);

        let counter = Arc::new(AtomicUsize::new(0));
        let num_tasks = 20;

        for _ in 0..num_tasks {
            let counter_clone = Arc::clone(&counter);
            pool.spawn(move || {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            })
            .unwrap();
        }

        // Wait for all tasks to complete
        for _ in 0..100 {
            if counter.load(Ordering::SeqCst) == num_tasks {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        assert_eq!(counter.load(Ordering::SeqCst), num_tasks);
        pool.shutdown();
    }

    #[test]
    fn test_read_thread_pool_shutdown_spawn_fails() {
        let pool = ReadThreadPool::new(4);
        pool.shutdown();
        let res = pool.spawn(|| {});
        assert!(res.is_err());
    }
}
