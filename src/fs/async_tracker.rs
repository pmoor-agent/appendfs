//! Tracks in-flight asynchronous operations to coordinate safe shutdown.

use std::sync::{Arc, Condvar, Mutex};

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
