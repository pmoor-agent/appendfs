use std::thread;
use std::time::{Duration, Instant};

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
