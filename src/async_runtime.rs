//! Shared asynchronous runtime management for AppendFS.

use std::future::Future;
use std::sync::{Arc, Condvar, LazyLock, Mutex};
use tokio::runtime::{Builder, Handle, Runtime};

/// Coordinates and tracks in-flight asynchronous operations (e.g. cold storage reads,
/// async fsyncs) to ensure safe, graceful shutdown without use-after-free.
#[derive(Debug, Default)]
pub struct AsyncTracker {
    in_flight: Mutex<usize>,
    cond: Condvar,
}

impl AsyncTracker {
    pub fn new() -> Self {
        Self {
            in_flight: Mutex::new(0),
            cond: Condvar::new(),
        }
    }

    /// Increments the in-flight counter and returns an RAII guard that will
    /// decrement the counter and signal waiting drainers when dropped.
    pub fn begin(self: &Arc<Self>) -> AsyncOpGuard {
        let mut count = self.in_flight.lock().unwrap();
        *count += 1;
        AsyncOpGuard {
            tracker: Arc::clone(self),
        }
    }

    /// Returns the number of currently in-flight async operations.
    pub fn in_flight(&self) -> usize {
        *self.in_flight.lock().unwrap()
    }

    /// Blocks until all in-flight asynchronous operations have completed and dropped their guards.
    pub fn drain(&self) {
        let mut count = self.in_flight.lock().unwrap();
        while *count > 0 {
            count = self.cond.wait(count).unwrap();
        }
    }
}

/// RAII guard for an in-flight asynchronous operation.
///
/// When dropped, decrements the tracked in-flight count and notifies any drainers if count reaches 0.
#[derive(Debug)]
pub struct AsyncOpGuard {
    tracker: Arc<AsyncTracker>,
}

impl Drop for AsyncOpGuard {
    fn drop(&mut self) {
        let mut count = self.tracker.in_flight.lock().unwrap();
        *count -= 1;
        if *count == 0 {
            self.tracker.cond.notify_all();
        }
    }
}

static GLOBAL_ASYNC_RUNTIME: LazyLock<Runtime> = LazyLock::new(|| {
    let workers = std::thread::available_parallelism()
        .map(|n| n.get().max(16))
        .unwrap_or(16);
    Builder::new_multi_thread()
        .worker_threads(workers)
        .thread_name("appendfs-io")
        .enable_all()
        .build()
        .expect("failed to initialize appendfs async runtime")
});

/// Spawns a future on the active Tokio runtime if one exists on the current thread,
/// or on the shared multi-threaded background runtime.
pub fn spawn<F>(future: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    if let Ok(handle) = Handle::try_current() {
        handle.spawn(future);
    } else {
        GLOBAL_ASYNC_RUNTIME.spawn(future);
    }
}

/// Blocks on a future on the current thread, running it to completion.
pub fn block_on<F: Future>(future: F) -> F::Output {
    if let Ok(handle) = Handle::try_current() {
        tokio::task::block_in_place(|| handle.block_on(future))
    } else {
        GLOBAL_ASYNC_RUNTIME.block_on(future)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_async_tracker_drain() {
        let tracker = Arc::new(AsyncTracker::new());
        assert_eq!(tracker.in_flight(), 0);

        let g1 = tracker.begin();
        let g2 = tracker.begin();
        assert_eq!(tracker.in_flight(), 2);

        let tracker_clone = Arc::clone(&tracker);
        let drained = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let drained_clone = Arc::clone(&drained);

        let handle = std::thread::spawn(move || {
            tracker_clone.drain();
            drained_clone.store(true, std::sync::atomic::Ordering::SeqCst);
        });

        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!drained.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(tracker.in_flight(), 2);

        drop(g1);
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!drained.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(tracker.in_flight(), 1);

        drop(g2);
        handle.join().unwrap();
        assert!(drained.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(tracker.in_flight(), 0);
    }
}
