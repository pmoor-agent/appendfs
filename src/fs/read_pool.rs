//! Bounded worker threadpool for asynchronous cold disk and remote reads.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};

type Task = Box<dyn FnOnce() + Send + 'static>;

#[derive(Default)]
struct PoolState {
    queue: VecDeque<Task>,
    shutdown: bool,
}

struct WorkerState {
    handles: Vec<JoinHandle<()>>,
    pid: u32,
}

/// A dedicated threadpool for offloading cold disk and remote read requests
/// away from the single-threaded FUSE event loop.
pub struct ReadThreadPool {
    state: Arc<(Mutex<PoolState>, Condvar)>,
    workers: Mutex<Option<WorkerState>>,
    num_workers: usize,
    is_shutdown: AtomicBool,
}

impl ReadThreadPool {
    /// Creates a new [`ReadThreadPool`] configured for the specified number of worker threads.
    ///
    /// The worker count is clamped to `1..=16`.
    ///
    /// Note: Worker threads are not started immediately in `new()`, but on `start()` or lazily
    /// on the first `spawn()`. This ensures that a thread started prior to a background mount's
    /// `fuse_daemonize` fork does not become orphaned in the child process.
    pub fn new(workers: usize) -> Self {
        let num_workers = workers.clamp(1, 16);
        let state = Arc::new((Mutex::new(PoolState::default()), Condvar::new()));

        Self {
            state,
            workers: Mutex::new(None),
            num_workers,
            is_shutdown: AtomicBool::new(false),
        }
    }

    /// Starts the worker threads if not already running in the current process.
    ///
    /// If called after a `fork()`, any handles from the parent process are dropped
    /// (preventing deadlocks when joining) and new threads are spawned for this process.
    pub fn start(&self) {
        if self.is_shutdown.load(Ordering::SeqCst) {
            return;
        }
        let current_pid = std::process::id();
        let mut workers_guard = self.workers.lock().unwrap();
        if let Some(ref inner) = *workers_guard {
            if inner.pid == current_pid {
                return;
            }
            // Fork occurred: reset pool state for the child process.
            let mut state_lock = self.state.0.lock().unwrap();
            state_lock.shutdown = false;
            state_lock.queue.clear();
            self.is_shutdown.store(false, Ordering::SeqCst);
        }

        let num_workers = self.num_workers;
        let mut handles = Vec::with_capacity(num_workers);
        for i in 0..num_workers {
            let state_clone = Arc::clone(&self.state);
            let handle = thread::Builder::new()
                .name(format!("appendfs-read-{}", i))
                .spawn(move || {
                    loop {
                        let mut lock = state_clone.0.lock().unwrap();
                        while lock.queue.is_empty() && !lock.shutdown {
                            lock = state_clone.1.wait(lock).unwrap();
                        }
                        if lock.shutdown && lock.queue.is_empty() {
                            break;
                        }
                        let task = match lock.queue.pop_front() {
                            Some(t) => t,
                            None => continue,
                        };
                        drop(lock);

                        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(task));
                    }
                })
                .expect("failed to spawn read worker thread");
            handles.push(handle);
        }

        *workers_guard = Some(WorkerState {
            handles,
            pid: current_pid,
        });
    }

    fn ensure_started(&self) {
        let current_pid = std::process::id();
        let needs_start = match self.workers.lock().unwrap().as_ref() {
            Some(inner) => inner.pid != current_pid,
            None => true,
        };
        if needs_start {
            self.start();
        }
    }

    /// Submits a task for asynchronous execution on the threadpool.
    ///
    /// If the pool is shutting down, the task is dropped without execution.
    pub fn spawn(&self, f: impl FnOnce() + Send + 'static) {
        if self.is_shutdown.load(Ordering::SeqCst) {
            return;
        }
        self.ensure_started();
        let mut lock = self.state.0.lock().unwrap();
        if !lock.shutdown {
            lock.queue.push_back(Box::new(f));
            self.state.1.notify_one();
        }
    }

    /// Returns the configured number of worker threads for this pool.
    pub fn num_workers(&self) -> usize {
        self.num_workers
    }

    /// Signals all workers to stop and joins their threads.
    pub fn shutdown(&self) {
        if self.is_shutdown.swap(true, Ordering::SeqCst) {
            return;
        }
        {
            let mut lock = self.state.0.lock().unwrap();
            lock.shutdown = true;
            self.state.1.notify_all();
        }
        let current_pid = std::process::id();
        let mut workers_guard = self.workers.lock().unwrap();
        if let Some(inner) = workers_guard.take()
            && inner.pid == current_pid
        {
            for handle in inner.handles {
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
            .field("is_shutdown", &self.is_shutdown.load(Ordering::Relaxed))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

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
            });
        }

        // Wait for all tasks to complete
        for _ in 0..100 {
            if counter.load(Ordering::SeqCst) == num_tasks {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(counter.load(Ordering::SeqCst), num_tasks);

        pool.shutdown();
    }
}
