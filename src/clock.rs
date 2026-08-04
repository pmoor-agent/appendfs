use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Trait abstracting system time measurement for testability.
pub trait Clock: Send + Sync {
    fn now(&self) -> SystemTime;
}

/// Default system clock implementation backed by `std::time::SystemTime::now()`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// Converts a `SystemTime` instance to a (seconds, nanoseconds) tuple since UNIX epoch.
pub fn system_time_to_unix(time: SystemTime) -> (i64, u32) {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => (duration.as_secs() as i64, duration.subsec_nanos()),
        Err(err) => {
            let duration = err.duration();
            (-(duration.as_secs() as i64), duration.subsec_nanos())
        }
    }
}

/// Creates a `SystemTime` instance from a (seconds, nanoseconds) tuple since UNIX epoch.
pub fn unix_to_system_time(secs: i64, nsecs: u32) -> SystemTime {
    if secs >= 0 {
        UNIX_EPOCH + Duration::new(secs as u64, nsecs)
    } else {
        UNIX_EPOCH - Duration::new((-secs) as u64, nsecs)
    }
}

/// Fixed-time clock for deterministic tests - e.g. asserting exact timestamps survive
/// a crash/recovery cycle, which a real wall clock can't do reliably (real time keeps
/// moving between the write and the check).
#[derive(Debug, Clone, Copy)]
pub struct MockClock(pub SystemTime);

impl Clock for MockClock {
    fn now(&self) -> SystemTime {
        self.0
    }
}

/// Shared, advanceable clock for deterministic multi-instance tests where several
/// independent components need to observe the *same* simulated time (unlike
/// `MockClock`, whose value is fixed at construction and never changes). Cloning
/// shares the same underlying time - advancing through any clone advances it for all
/// of them.
#[derive(Debug, Clone)]
pub struct AdvancingClock(Arc<Mutex<SystemTime>>);

impl AdvancingClock {
    pub fn new(start: SystemTime) -> Self {
        Self(Arc::new(Mutex::new(start)))
    }

    /// Advances the simulated time by `duration` and returns the new value.
    pub fn advance(&self, duration: Duration) -> SystemTime {
        let mut guard = self.0.lock().unwrap();
        *guard += duration;
        *guard
    }
}

impl Clock for AdvancingClock {
    fn now(&self) -> SystemTime {
        *self.0.lock().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_clock_now() {
        let clock = SystemClock;
        let now = clock.now();
        assert!(now >= UNIX_EPOCH);
    }

    #[test]
    fn test_mock_clock() {
        let fixed_time = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let mock = MockClock(fixed_time);
        assert_eq!(mock.now(), fixed_time);

        let (secs, nsecs) = system_time_to_unix(fixed_time);
        assert_eq!(secs, 1_700_000_000);
        assert_eq!(nsecs, 0);
        assert_eq!(unix_to_system_time(secs, nsecs), fixed_time);
    }

    #[test]
    fn test_advancing_clock_shared_across_clones() {
        let start = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let clock = AdvancingClock::new(start);
        let handle_a = clock.clone();
        let handle_b = clock.clone();

        assert_eq!(handle_a.now(), start);
        assert_eq!(handle_b.now(), start);

        handle_a.advance(Duration::from_secs(5));

        // Advancing through one handle is visible through every other handle too.
        assert_eq!(handle_a.now(), start + Duration::from_secs(5));
        assert_eq!(handle_b.now(), start + Duration::from_secs(5));
        assert_eq!(clock.now(), start + Duration::from_secs(5));
    }
}
