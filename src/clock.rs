use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Fixed offset added to every default [`Clock::monotonic`] reading.
///
/// Measuring straight from the epoch would make each reading equal to wall-clock time, so a
/// caller could compare one against a timestamp, or assert on its absolute value, and appear
/// to be right. Offsetting breaks that coupling and leaves every difference between readings
/// - the only thing that means anything - unchanged.
///
/// The value is arbitrary; it happens to be the epoch's distance from 1981-02-05. Adding
/// rather than subtracting is what keeps it safe: several mocked clocks in this crate start
/// within seconds of the epoch, and an origin placed after them would floor `duration_since`
/// at zero, leaving `elapsed_since` reporting nothing while still looking like it worked.
pub const MONOTONIC_OFFSET: Duration = Duration::from_secs(350_179_200);

/// Trait abstracting system time measurement for testability.
pub trait Clock: Send + Sync {
    fn now(&self) -> SystemTime;

    /// Reading from a monotonically non-decreasing source, for measuring elapsed time.
    ///
    /// The origin is arbitrary and means nothing on its own: only the difference between two
    /// readings is meaningful, which [`Clock::elapsed_since`] computes. See
    /// [`MONOTONIC_OFFSET`] for why the default is not simply time since the epoch.
    ///
    /// Wall-clock time is the wrong instrument for a duration - `now()` can step backwards
    /// across an NTP correction, yielding a negative or absurd interval - so measurements
    /// take this instead. The default derives it from `now()`, which is what a mocked clock
    /// wants: a fixed clock reports zero elapsed time, and an advancing one reports exactly
    /// what the test advanced it by. [`SystemClock`] overrides it with a real monotonic
    /// source.
    fn monotonic(&self) -> Duration {
        MONOTONIC_OFFSET + self.now().duration_since(UNIX_EPOCH).unwrap_or_default()
    }

    /// Time elapsed since an earlier [`Clock::monotonic`] reading.
    ///
    /// Saturates at zero rather than panicking, so a clock that does go backwards degrades
    /// to an understated measurement instead of taking the caller down.
    fn elapsed_since(&self, earlier: Duration) -> Duration {
        self.monotonic().saturating_sub(earlier)
    }
}

/// Default system clock implementation backed by `std::time::SystemTime::now()`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

/// Process-wide origin for [`SystemClock::monotonic`], fixed at its first use.
fn instant_origin() -> Instant {
    static ORIGIN: OnceLock<Instant> = OnceLock::new();
    *ORIGIN.get_or_init(Instant::now)
}

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }

    fn monotonic(&self) -> Duration {
        instant_origin().elapsed()
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

pub fn default_epoch() -> SystemTime {
    UNIX_EPOCH
}

/// Formats a `SystemTime` as `<unix_secs>.<nanos>s (YYYY-MM-DD HH:MM:SS)` in local civil time.
pub fn format_local_civil_time(time: SystemTime) -> String {
    let (secs, nsecs) = system_time_to_unix(time);
    match jiff::Timestamp::try_from(time) {
        Ok(ts) => {
            let zoned = ts.to_zoned(jiff::tz::TimeZone::system());
            format!("{}.{:09}s ({})", secs, nsecs, zoned.strftime("%Y-%m-%d %H:%M:%S"))
        }
        Err(_) => format!("{}.{:09}s (unknown time)", secs, nsecs),
    }
}

/// Formats a `SystemTime` as `<unix_secs>.<nanos>s (YYYY-MM-DD HH:MM:SS UTC)`.
pub fn format_utc_civil_time(time: SystemTime) -> String {
    let (secs, nsecs) = system_time_to_unix(time);
    match jiff::Timestamp::try_from(time) {
        Ok(ts) => {
            let zoned = ts.to_zoned(jiff::tz::TimeZone::UTC);
            format!("{}.{:09}s ({} UTC)", secs, nsecs, zoned.strftime("%Y-%m-%d %H:%M:%S"))
        }
        Err(_) => format!("{}.{:09}s (unknown time)", secs, nsecs),
    }
}

/// Parses a human-readable or unix timestamp string into `SystemTime`.
/// Supports unix seconds (`1755424800`), decimals (`1755424800.5`),
/// ISO 8601 / RFC 3339 (`2026-08-17T10:00:00Z`), `2026-08-17 10:00:00`, and `2026-08-17`.
pub fn parse_timestamp(input: &str) -> Result<SystemTime, String> {
    let trimmed = input.trim();
    if let Ok(secs_f) = trimmed.parse::<f64>() {
        let secs = secs_f.floor() as i64;
        let nsecs = ((secs_f - secs_f.floor()) * 1_000_000_000.0) as u32;
        return Ok(unix_to_system_time(secs, nsecs));
    }

    if let Ok(ts) = trimmed.parse::<jiff::Timestamp>() {
        return Ok(SystemTime::from(ts));
    }

    let without_z = trimmed.trim_end_matches('Z');
    if let Ok(dt) = without_z.parse::<jiff::civil::DateTime>()
        && let Ok(zoned) = dt.to_zoned(jiff::tz::TimeZone::UTC)
    {
        return Ok(SystemTime::from(zoned.timestamp()));
    }

    if let Ok(date) = without_z.parse::<jiff::civil::Date>()
        && let Ok(zoned) = date
            .to_datetime(jiff::civil::Time::midnight())
            .to_zoned(jiff::tz::TimeZone::UTC)
    {
        return Ok(SystemTime::from(zoned.timestamp()));
    }

    Err(format!(
        "Invalid timestamp '{}'. Expected unix seconds or ISO date (e.g. '2026-08-17T10:00:00Z')",
        input
    ))
}

/// Parses a human-readable duration string (e.g. "30d", "24h", "60m", "120s", "1h 30m", "500ms") into a `std::time::Duration`.
///
/// Requires an explicit unit designator; raw numbers without units (such as "42") are rejected.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err("empty duration".to_string());
    }
    let span: jiff::Span = trimmed.parse().map_err(|e| format!("invalid duration '{s}': {e}"))?;
    if span.is_negative() {
        return Err(format!("duration cannot be negative: '{s}'"));
    }
    let signed_dur = span
        .to_duration(jiff::SpanRelativeTo::days_are_24_hours())
        .map_err(|e| format!("duration out of range '{s}': {e}"))?;
    signed_dur
        .try_into()
        .map_err(|e| format!("duration out of range '{s}': {e}"))
}

/// Formats a `std::time::Duration` into a friendly human-readable duration string (e.g. "30d", "1d", "1h", "2m", "42s", "0s").
pub fn format_duration(d: Duration) -> String {
    let Ok(span) = jiff::Span::try_from(d) else {
        return format!("{}s", d.as_secs());
    };
    let round_config = jiff::SpanRound::new()
        .largest(jiff::Unit::Day)
        .relative(jiff::SpanRelativeTo::days_are_24_hours());
    match span.round(round_config) {
        Ok(rounded) => jiff::fmt::friendly::SpanPrinter::new()
            .spacing(jiff::fmt::friendly::Spacing::None)
            .span_to_string(&rounded),
        Err(_) => format!("{}s", d.as_secs()),
    }
}

pub mod serde_system_time {
    use super::*;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(time: &SystemTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        system_time_to_unix(*time).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SystemTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (sec, nsec) = <(i64, u32)>::deserialize(deserializer)?;
        Ok(unix_to_system_time(sec, nsec))
    }
}

pub mod serde_system_time_opt {
    use super::*;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(time: &Option<SystemTime>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let opt_tuple = time.map(system_time_to_unix);
        opt_tuple.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<SystemTime>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt_tuple = <Option<(i64, u32)>>::deserialize(deserializer)?;
        Ok(opt_tuple.map(|(sec, nsec)| unix_to_system_time(sec, nsec)))
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
    use serde::{Deserialize, Serialize};

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

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct TimestampTestWrapper {
        #[serde(with = "serde_system_time")]
        time: SystemTime,
        #[serde(with = "serde_system_time_opt")]
        opt_some: Option<SystemTime>,
        #[serde(default, with = "serde_system_time_opt")]
        opt_none: Option<SystemTime>,
    }

    #[test]
    fn test_serde_system_time_round_trip() {
        let post_epoch = UNIX_EPOCH + Duration::new(1_720_000_000, 123_456_789);
        let pre_epoch = UNIX_EPOCH - Duration::new(100_000, 500);

        let test_obj = TimestampTestWrapper {
            time: post_epoch,
            opt_some: Some(pre_epoch),
            opt_none: None,
        };

        let bytes = crate::wire::serialize(&test_obj).unwrap();
        let deserialized: TimestampTestWrapper = crate::wire::deserialize(&bytes).unwrap();
        assert_eq!(test_obj, deserialized);
    }

    #[test]
    fn test_system_clock_monotonic_does_not_run_backwards() {
        let clock = SystemClock;
        let first = clock.monotonic();
        let second = clock.monotonic();
        assert!(second >= first, "monotonic must be non-decreasing");
        // The origin is fixed at first use, so readings measure from process start rather
        // than being a fresh zero each call.
        assert!(clock.elapsed_since(first) < Duration::from_secs(60));
    }

    #[test]
    fn test_monotonic_readings_are_not_timestamps() {
        // The origin is arbitrary, and this is what keeps it honest: a reading must not be
        // usable as - or equal to - wall-clock time, or callers will couple to it by accident.
        let now = UNIX_EPOCH + Duration::from_secs(1_766_000_000);
        let clock = MockClock(now);
        let wall = now.duration_since(UNIX_EPOCH).unwrap();

        assert_ne!(clock.monotonic(), wall, "a reading must not equal the unix timestamp");
        assert_eq!(clock.monotonic(), wall + MONOTONIC_OFFSET);
    }

    #[test]
    fn test_clock_near_the_epoch_still_measures_elapsed_time() {
        // The reason the origin precedes the epoch. Several mocked clocks in this crate
        // start seconds after it; an origin later than that would floor them at zero and
        // measure nothing, silently.
        let clock = AdvancingClock::new(UNIX_EPOCH + Duration::from_secs(1));
        let start = clock.monotonic();
        assert!(
            start > Duration::ZERO,
            "a near-epoch clock must not clamp to the origin"
        );

        clock.advance(Duration::from_millis(250));
        assert_eq!(clock.elapsed_since(start), Duration::from_millis(250));
    }

    #[test]
    fn test_mock_clock_reports_zero_elapsed() {
        let clock = MockClock(UNIX_EPOCH + Duration::from_secs(1_700_000_000));
        let start = clock.monotonic();
        assert_eq!(
            clock.elapsed_since(start),
            Duration::ZERO,
            "a fixed clock must make durations reproducible, not merely small"
        );
    }

    #[test]
    fn test_advancing_clock_reports_exactly_what_was_advanced() {
        let clock = AdvancingClock::new(UNIX_EPOCH + Duration::from_secs(1_700_000_000));
        let start = clock.monotonic();
        clock.advance(Duration::from_millis(1500));
        assert_eq!(clock.elapsed_since(start), Duration::from_millis(1500));
    }

    #[test]
    fn test_elapsed_since_saturates_rather_than_panicking() {
        let clock = AdvancingClock::new(UNIX_EPOCH + Duration::from_secs(100));
        // A reading from "later" than the clock, as a backwards step would produce.
        let future = clock.monotonic() + Duration::from_secs(10);
        assert_eq!(clock.elapsed_since(future), Duration::ZERO);
    }

    #[test]
    fn test_format_local_civil_time() {
        let time = unix_to_system_time(1786953681, 901426641);
        let formatted = format_local_civil_time(time);
        assert!(formatted.starts_with("1786953681.901426641s ("));
        assert!(formatted.ends_with(')'));
        // Verify format inside parentheses is YYYY-MM-DD HH:MM:SS
        let civil_part = &formatted[formatted.find('(').unwrap() + 1..formatted.len() - 1];
        assert_eq!(civil_part.len(), 19);
        assert_eq!(&civil_part[4..5], "-");
        assert_eq!(&civil_part[7..8], "-");
        assert_eq!(&civil_part[10..11], " ");
        assert_eq!(&civil_part[13..14], ":");
        assert_eq!(&civil_part[16..17], ":");
    }

    #[test]
    fn test_format_utc_civil_time() {
        let time = unix_to_system_time(1700000330, 0);
        let formatted = format_utc_civil_time(time);
        assert_eq!(formatted, "1700000330.000000000s (2023-11-14 22:18:50 UTC)");
    }

    #[test]
    fn test_parse_timestamp_unix_seconds_and_decimals() {
        let t1 = parse_timestamp("1755424800").unwrap();
        assert_eq!(t1, unix_to_system_time(1755424800, 0));

        let t2 = parse_timestamp("1755424800.5").unwrap();
        assert_eq!(t2, unix_to_system_time(1755424800, 500_000_000));
    }

    #[test]
    fn test_parse_timestamp_rfc3339_and_civil() {
        let expected = unix_to_system_time(1786960800, 0); // 2026-08-17 10:00:00 UTC

        // RFC 3339 UTC with Z
        assert_eq!(parse_timestamp("2026-08-17T10:00:00Z").unwrap(), expected);
        // RFC 3339 with explicit timezone offset (+02:00 -> 10:00 UTC is 12:00 local)
        assert_eq!(parse_timestamp("2026-08-17T12:00:00+02:00").unwrap(), expected);
        // ISO 8601 with fractional seconds
        assert_eq!(
            parse_timestamp("2026-08-17T10:00:00.250Z").unwrap(),
            unix_to_system_time(1786960800, 250_000_000)
        );
        // Civil date-time with space
        assert_eq!(parse_timestamp("2026-08-17 10:00:00").unwrap(), expected);
        // Civil date-time with T (no offset)
        assert_eq!(parse_timestamp("2026-08-17T10:00:00").unwrap(), expected);
        // Civil date only (midnight UTC)
        let expected_date = unix_to_system_time(1786924800, 0); // 2026-08-17 00:00:00 UTC
        assert_eq!(parse_timestamp("2026-08-17").unwrap(), expected_date);
    }

    #[test]
    fn test_parse_timestamp_invalid() {
        assert!(parse_timestamp("").is_err());
        assert!(parse_timestamp("not a timestamp").is_err());
        assert!(parse_timestamp("2026-13-40").is_err());
        assert!(parse_timestamp("2026-08-17 25:00:00").is_err());
    }

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("30d").unwrap(), Duration::from_secs(30 * 86400));
        assert_eq!(parse_duration("1d").unwrap(), Duration::from_secs(86400));
        assert_eq!(parse_duration("24h").unwrap(), Duration::from_secs(86400));
        assert_eq!(parse_duration("60m").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_duration("120s").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_duration("0s").unwrap(), Duration::from_secs(0));
        assert_eq!(parse_duration("1h 30m").unwrap(), Duration::from_secs(5400));
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));

        // Raw numbers without units must be rejected
        assert!(parse_duration("42").is_err());
        assert!(parse_duration("0").is_err());
        assert!(parse_duration("").is_err());
        assert!(parse_duration("   ").is_err());
        assert!(parse_duration("invalid").is_err());
        assert!(parse_duration("-5s").is_err());
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::from_secs(0)), "0s");
        assert_eq!(format_duration(Duration::from_secs(42)), "42s");
        assert_eq!(format_duration(Duration::from_secs(120)), "2m");
        assert_eq!(format_duration(Duration::from_secs(3600)), "1h");
        assert_eq!(format_duration(Duration::from_secs(3665)), "1h1m5s");
        assert_eq!(format_duration(Duration::from_secs(86400)), "1d");
        assert_eq!(format_duration(Duration::from_secs(106041)), "1d5h27m21s");
        assert_eq!(format_duration(Duration::from_secs(30 * 86400)), "30d");

        // Roundtrip checks
        for secs in [0, 42, 120, 3600, 3665, 86400, 106041, 30 * 86400] {
            let dur = Duration::from_secs(secs);
            let formatted = format_duration(dur);
            assert_eq!(parse_duration(&formatted).unwrap(), dur);
        }
    }
}
