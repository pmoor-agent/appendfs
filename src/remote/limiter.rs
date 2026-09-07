use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};

/// A panic-safe synchronous counting semaphore / concurrency limiter.
///
/// Used at the lowest storage tier to bound concurrent network requests
/// and prevent S3 connection exhaustion, memory bloat, and cache thrashing.
#[derive(Debug)]
pub struct ConcurrencyLimiter {
    max_permits: usize,
    available: Mutex<usize>,
    cond: Condvar,
    active_count: AtomicUsize,
    total_acquired: AtomicUsize,
}

impl ConcurrencyLimiter {
    pub fn new(max_permits: usize) -> Self {
        assert!(max_permits > 0, "max_permits must be greater than zero");
        Self {
            max_permits,
            available: Mutex::new(max_permits),
            cond: Condvar::new(),
            active_count: AtomicUsize::new(0),
            total_acquired: AtomicUsize::new(0),
        }
    }

    pub fn max_permits(&self) -> usize {
        self.max_permits
    }

    pub fn active_count(&self) -> usize {
        self.active_count.load(Ordering::SeqCst)
    }

    pub fn available_permits(&self) -> usize {
        *self.available.lock().unwrap()
    }

    pub fn total_acquired(&self) -> usize {
        self.total_acquired.load(Ordering::SeqCst)
    }

    /// Acquires a permit, blocking until one becomes available.
    pub fn acquire(self: &Arc<Self>) -> ConcurrencyPermit {
        let mut avail = self.available.lock().unwrap();
        while *avail == 0 {
            avail = self.cond.wait(avail).unwrap();
        }
        *avail -= 1;
        self.active_count.fetch_add(1, Ordering::SeqCst);
        self.total_acquired.fetch_add(1, Ordering::SeqCst);
        ConcurrencyPermit {
            limiter: Arc::clone(self),
        }
    }

    /// Attempts to acquire a permit without blocking.
    pub fn try_acquire(self: &Arc<Self>) -> Option<ConcurrencyPermit> {
        let mut avail = self.available.lock().unwrap();
        if *avail > 0 {
            *avail -= 1;
            self.active_count.fetch_add(1, Ordering::SeqCst);
            self.total_acquired.fetch_add(1, Ordering::SeqCst);
            Some(ConcurrencyPermit {
                limiter: Arc::clone(self),
            })
        } else {
            None
        }
    }

    fn release(&self) {
        let mut avail = self.available.lock().unwrap();
        *avail += 1;
        self.active_count.fetch_sub(1, Ordering::SeqCst);
        self.cond.notify_one();
    }
}

/// RAII permit guarding a concurrent slot in [`ConcurrencyLimiter`].
#[derive(Debug)]
pub struct ConcurrencyPermit {
    limiter: Arc<ConcurrencyLimiter>,
}

impl Drop for ConcurrencyPermit {
    fn drop(&mut self) {
        self.limiter.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_concurrency_limiter_bounds_active_workers() {
        let max_permits = 3;
        let limiter = Arc::new(ConcurrencyLimiter::new(max_permits));
        let active_max = Arc::new(AtomicUsize::new(0));
        let num_threads = 10;
        let mut handles = Vec::new();

        for _ in 0..num_threads {
            let l = Arc::clone(&limiter);
            let a = Arc::clone(&active_max);
            handles.push(thread::spawn(move || {
                let _permit = l.acquire();
                let cur = l.active_count();
                a.fetch_max(cur, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(20));
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(limiter.active_count(), 0);
        assert_eq!(limiter.available_permits(), max_permits);
        assert_eq!(limiter.total_acquired(), num_threads);
        assert!(
            active_max.load(Ordering::SeqCst) <= max_permits,
            "Active workers exceeded max permits"
        );
    }

    #[test]
    fn test_concurrency_limiter_try_acquire() {
        let limiter = Arc::new(ConcurrencyLimiter::new(1));
        let p1 = limiter.try_acquire();
        assert!(p1.is_some());
        let p2 = limiter.try_acquire();
        assert!(p2.is_none());
        drop(p1);
        let p3 = limiter.try_acquire();
        assert!(p3.is_some());
    }

    #[test]
    fn test_concurrency_limiter_panic_safety() {
        let limiter = Arc::new(ConcurrencyLimiter::new(1));

        let l = Arc::clone(&limiter);
        let h = thread::spawn(move || {
            let _permit = l.acquire();
            panic!("worker crashed");
        });

        assert!(h.join().is_err());
        // Permit must have been released upon thread panic unwind!
        assert_eq!(limiter.active_count(), 0);
        assert_eq!(limiter.available_permits(), 1);
        let p = limiter.try_acquire();
        assert!(p.is_some());
    }
}
