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

#[cfg(test)]
mod tests {
    use super::*;

    struct MockClock(SystemTime);

    impl Clock for MockClock {
        fn now(&self) -> SystemTime {
            self.0
        }
    }

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
}
