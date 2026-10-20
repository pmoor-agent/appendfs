//! Where diagnostic logs go.
//!
//! A backgrounded mount has no stderr: libfuse's `fuse_daemonize` redirects stdout and
//! stderr to `/dev/null`, so every `log::` record from a normal (non-`--foreground`) mount
//! was being discarded. Long-running mounts are exactly the ones worth having logs for, so
//! they write to a file inside the volume's own log directory instead.
//!
//! Each run gets its own file, named for the millisecond it started. There is no rotation to
//! reason about, runs do not interleave their records, and a crashed run's log stays exactly
//! as it was left rather than being overwritten by the restart.
//!
//! A file is the only destination. Anything a user is meant to read is printed directly, so
//! logging has no reason to compete for the terminal - and `--log-path` reaches the terminal
//! anyway via `/dev/stderr`, or discards via `/dev/null`, which is why there is no separate
//! flag for either.
//!
//! Times are the machine's local time, in file names and records alike, because that is
//! what whoever reads them is going to compare against. Records carry their UTC offset, so
//! they stay unambiguous across a daylight saving change and between machines.
//!
//! Every run opens with its own command line, so a log identifies what it was for without
//! being cross-referenced against anything. Credential values are redacted first: several
//! flags take a secret key as an argument, and a log file is not the place for one.
//!
//! The files live in a `logs/` subdirectory rather than beside the `.log` and `.summary`
//! generation files. `Storage::list_files` is non-recursive and returns only files, so
//! nothing in a subdirectory can be mistaken for a volume file by recovery, replication, or
//! pruning - the same reasoning that puts the block cache in `.cache/`.
//!
//! Logging never takes the filesystem down: if the file cannot be opened or written, the
//! mount continues and the records are dropped.

use jiff::Zoned;
use jiff::tz::TimeZone;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Subdirectory of the volume log directory holding diagnostic logs.
pub const LOG_SUBDIR: &str = "logs";

/// Default filter applied when neither `--log-level` nor `RUST_LOG` says otherwise.
pub const DEFAULT_LOG_LEVEL: &str = "info";

/// The directory a volume's diagnostic logs are written to.
pub fn log_directory(log_dir: &Path) -> PathBuf {
    log_dir.join(LOG_SUBDIR)
}

/// Names one run's log file: `appendfs-<YYYYMMDD>-<HHMMSS>.<mmm>.log` in the time zone
/// `started` is in, which sorts chronologically.
///
/// The milliseconds keep two runs started within the same second - `init` followed by
/// `mount` in a script - in files of their own. A pid would too, but a backgrounded mount
/// opens its log before libfuse forks it into the daemon, so the pid at hand would be the
/// parent's, which exits straight away.
///
/// The name carries no offset, so the hour repeated when daylight saving ends sorts out of
/// order. The first record inside the file does carry one.
pub fn log_file_name(started: &Zoned) -> String {
    started.strftime("appendfs-%Y%m%d-%H%M%S.%3f.log").to_string()
}

/// The log file for a run starting at `started`.
pub fn log_file_path(log_dir: &Path, started: &Zoned) -> PathBuf {
    log_directory(log_dir).join(log_file_name(started))
}

/// A record's timestamp: RFC 3339 to the millisecond, with its UTC offset.
fn record_timestamp(now: &Zoned) -> String {
    now.strftime("%Y-%m-%dT%H:%M:%S%.3f%:z").to_string()
}

/// A log file that drops records rather than failing.
struct LogSink {
    /// `None` once writing has failed; records are dropped rather than propagated.
    file: Option<File>,
}

impl LogSink {
    fn create(path: &Path) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        // `append` rather than truncate: an explicit `--log-path` may name an existing file
        // - or a character device like `/dev/stderr` - and truncating would be wrong for both.
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self { file: Some(file) })
    }
}

impl Write for LogSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // A logging failure must not surface as a filesystem error, so this reports success
        // either way and simply stops writing.
        match self.file {
            Some(ref mut file) => {
                if file.write_all(buf).is_err() {
                    self.file = None;
                }
                Ok(buf.len())
            }
            None => Ok(buf.len()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(ref mut file) = self.file {
            let _ = file.flush();
        }
        Ok(())
    }
}

/// Starts logging to `path`, or reports why it could not.
///
/// Returns the path in use, or `None` if it could not be opened - in which case records are
/// discarded and the command proceeds regardless, since a volume on read-only media is still
/// worth mounting.
pub fn init(path: &Path, level: &str) -> Option<PathBuf> {
    let builder = &mut env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level));
    // Resolved once: the system zone's rules already cover daylight saving changes.
    let tz = TimeZone::system();
    // env_logger's own layout, but in local time: its built-in timestamps are UTC only.
    builder.format(move |buf, record| {
        let now = Zoned::new(jiff::Timestamp::now(), tz.clone());
        writeln!(
            buf,
            "[{} {:<5} {}] {}",
            record_timestamp(&now),
            record.level(),
            record.target(),
            record.args()
        )
    });
    match LogSink::create(path) {
        Ok(sink) => {
            builder.target(env_logger::Target::Pipe(Box::new(sink))).init();
            Some(path.to_path_buf())
        }
        Err(e) => {
            eprintln!(
                "Warning: could not open log file {}: {}; logging disabled",
                path.display(),
                e
            );
            None
        }
    }
}

/// The log file for this run under `log_dir`.
///
/// Canonicalized because `fuse_daemonize` chdirs to `/` shortly after a mount sets this up.
pub fn run_log_path(log_dir: &Path) -> PathBuf {
    let root = fs::canonicalize(log_dir).unwrap_or_else(|_| log_dir.to_path_buf());
    log_file_path(&root, &Zoned::now())
}

/// Resolves a requested log destination (from `--log-path`) into a concrete log file path.
///
/// If `path` is an existing directory, or if it does not exist but syntactically denotes
/// a directory (ends with a directory separator, or its last component is `.` or `..`),
/// a timestamped log file (`appendfs-<YYYYMMDD>-<HHMMSS>.<mmm>.log`) is placed directly inside it.
/// Otherwise, `path` is treated as the exact log file destination.
pub fn resolve_log_path(path: &Path, started: &Zoned) -> PathBuf {
    let is_dir = path.is_dir() || {
        let raw = path.as_os_str().as_encoded_bytes();
        raw.ends_with(b"/")
            || raw.ends_with(&[std::path::MAIN_SEPARATOR as u8])
            || path
                .components()
                .next_back()
                .is_some_and(|c| matches!(c, std::path::Component::CurDir | std::path::Component::ParentDir))
    };

    if is_dir {
        let dir =
            fs::canonicalize(path).unwrap_or_else(|_| std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf()));
        dir.join(log_file_name(started))
    } else {
        std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
    }
}

/// Whether a flag's value is a credential that must not reach a log file.
///
/// `--secret-access-key` and friends take the secret itself as an argument. The `-env` and
/// `-file` variants only name where to look, but they match too: over-redacting costs a log
/// line some detail, while under-redacting writes a key to disk.
fn is_secret_flag(arg: &str) -> bool {
    let name = arg.trim_start_matches('-');
    name.contains("secret") || name.contains("access-key")
}

/// This run's command line, with credential values replaced by `<redacted>`.
pub fn redacted_command_line() -> String {
    redact_args(std::env::args())
}

fn redact_args<I: IntoIterator<Item = String>>(args: I) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut redact_value = false;

    for arg in args {
        if redact_value {
            out.push("<redacted>".to_string());
            redact_value = false;
            continue;
        }
        // `--flag=value` hides the secret inside a single argument.
        if arg.starts_with('-')
            && let Some((flag, _)) = arg.split_once('=')
            && is_secret_flag(flag)
        {
            out.push(format!("{}=<redacted>", flag));
            continue;
        }
        if arg.starts_with('-') && is_secret_flag(&arg) {
            redact_value = true;
        }
        out.push(arg);
    }
    out.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// 2025-12-17 19:33:20.042 UTC, as seen from a zone `offset_hours` east of it.
    fn started_at(offset_hours: i8) -> Zoned {
        let tz = TimeZone::fixed(jiff::tz::offset(offset_hours));
        jiff::Timestamp::from_millisecond(1_766_000_000_042)
            .unwrap()
            .to_zoned(tz)
    }

    #[test]
    fn test_log_file_name_identifies_the_run_in_local_time() {
        assert_eq!(log_file_name(&started_at(0)), "appendfs-20251217-193320.042.log");
        assert_eq!(log_file_name(&started_at(-8)), "appendfs-20251217-113320.042.log");
        assert_eq!(log_file_name(&started_at(9)), "appendfs-20251218-043320.042.log");
    }

    #[test]
    fn test_runs_in_the_same_second_get_files_of_their_own() {
        let started = started_at(2);
        let after = |d: Duration| started.checked_add(d).unwrap();
        let next = after(Duration::from_millis(1));
        assert_ne!(log_file_name(&started), log_file_name(&next));

        // And a later run sorts after an earlier one, across a second boundary too.
        assert!(log_file_name(&started) < log_file_name(&next));
        assert!(log_file_name(&after(Duration::from_millis(957))) < log_file_name(&after(Duration::from_secs(1))));
    }

    #[test]
    fn test_record_timestamp_is_local_with_its_offset() {
        assert_eq!(record_timestamp(&started_at(0)), "2025-12-17T19:33:20.042+00:00");
        assert_eq!(record_timestamp(&started_at(-8)), "2025-12-17T11:33:20.042-08:00");
    }

    #[test]
    fn test_command_line_redacts_credentials() {
        let args = [
            "appendfs",
            "remote",
            "add",
            "/srv/vol",
            "aws",
            "--bucket",
            "backups",
            "--access-key-id",
            "AKIAEXAMPLE",
            "--secret-access-key",
            "s3cr3t-do-not-log",
        ];
        let line = redact_args(args.iter().map(|s| s.to_string()));

        assert!(
            !line.contains("s3cr3t-do-not-log"),
            "secret leaked into the log: {}",
            line
        );
        assert!(!line.contains("AKIAEXAMPLE"), "key id leaked into the log: {}", line);
        assert!(
            line.contains("--secret-access-key <redacted>") && line.contains("--access-key-id <redacted>"),
            "the flags themselves should still be visible: {}",
            line
        );
        // Everything else survives, which is the point of logging the command line at all.
        assert!(line.contains("remote add /srv/vol aws --bucket backups"), "{}", line);
    }

    #[test]
    fn test_command_line_redacts_the_inline_form_too() {
        let args = ["appendfs", "init", "/srv/vol", "--remote-secret-access-key=s3cr3t"];
        let line = redact_args(args.iter().map(|s| s.to_string()));
        assert!(!line.contains("s3cr3t"), "inline secret leaked: {}", line);
        assert_eq!(line, "appendfs init /srv/vol --remote-secret-access-key=<redacted>");
    }

    #[test]
    fn test_command_line_keeps_non_secret_arguments() {
        // A path that merely mentions a key is not a secret, and over-redacting paths would
        // make the log useless for the case it exists for.
        let args = [
            "appendfs",
            "mount",
            "/srv/vol",
            "/mnt",
            "--key-file",
            "/etc/appendfs.key",
        ];
        let line = redact_args(args.iter().map(|s| s.to_string()));
        assert_eq!(line, "appendfs mount /srv/vol /mnt --key-file /etc/appendfs.key");
    }

    #[test]
    fn test_log_lives_where_storage_cannot_see_it() {
        // The guarantee that keeps a diagnostic log from ever being mistaken for a volume
        // file: `list_files` is non-recursive and file-only, so a subdirectory is invisible.
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::OsStorage::new(dir.path());
        let path = log_file_path(dir.path(), &Zoned::now());

        let mut sink = LogSink::create(&path).unwrap();
        sink.write_all(b"a log record\n").unwrap();
        sink.flush().unwrap();

        assert!(path.exists());
        let listed = crate::storage::Storage::list_files(&storage).unwrap();
        assert!(
            listed.is_empty(),
            "the log directory must look empty to volume code, got {:?}",
            listed
        );
    }

    #[test]
    fn test_a_second_run_leaves_the_first_run_intact() {
        // A crashed run's log has to survive the restart that follows it.
        let dir = tempfile::tempdir().unwrap();
        let started = started_at(0);

        let first = log_file_path(dir.path(), &started);
        let mut sink = LogSink::create(&first).unwrap();
        sink.write_all(b"from the first run\n").unwrap();
        sink.flush().unwrap();
        drop(sink);

        let second = log_file_path(dir.path(), &started.checked_add(Duration::from_secs(5)).unwrap());
        let mut sink = LogSink::create(&second).unwrap();
        sink.write_all(b"from the second run\n").unwrap();
        sink.flush().unwrap();

        assert_eq!(fs::read_to_string(&first).unwrap(), "from the first run\n");
        assert_eq!(fs::read_to_string(&second).unwrap(), "from the second run\n");
    }

    #[test]
    fn test_writes_keep_succeeding_after_the_file_is_lost() {
        // A filesystem must not fail because its log file did.
        let dir = tempfile::tempdir().unwrap();
        let path = log_file_path(dir.path(), &Zoned::now());
        let mut sink = LogSink::create(&path).unwrap();
        sink.write_all(b"before\n").unwrap();
        sink.file = None;
        assert!(sink.write_all(b"after\n").is_ok(), "a lost log file must be survivable");
        assert!(sink.flush().is_ok());
    }

    #[test]
    fn test_resolve_log_path_existing_directory() {
        let dir = tempfile::tempdir().unwrap();
        let started = started_at(0);
        let resolved = resolve_log_path(dir.path(), &started);
        let canonical_dir = fs::canonicalize(dir.path()).unwrap();
        assert_eq!(resolved, canonical_dir.join("appendfs-20251217-193320.042.log"));
    }

    #[test]
    fn test_resolve_log_path_nonexistent_directory_with_trailing_slash() {
        let dir = tempfile::tempdir().unwrap();
        let started = started_at(0);
        let new_dir_path_str = format!("{}/sub_dir/", dir.path().display());
        let resolved = resolve_log_path(Path::new(&new_dir_path_str), &started);
        let expected_dir = std::path::absolute(dir.path().join("sub_dir")).unwrap();
        assert_eq!(resolved, expected_dir.join("appendfs-20251217-193320.042.log"));
    }

    #[test]
    fn test_resolve_log_path_dot_and_dotdot() {
        let started = started_at(0);
        let cur = resolve_log_path(Path::new("."), &started);
        let canonical_cur = fs::canonicalize(".").unwrap();
        assert_eq!(cur, canonical_cur.join("appendfs-20251217-193320.042.log"));

        let parent = resolve_log_path(Path::new(".."), &started);
        let canonical_parent = fs::canonicalize("..").unwrap();
        assert_eq!(parent, canonical_parent.join("appendfs-20251217-193320.042.log"));
    }

    #[test]
    fn test_resolve_log_path_exact_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let started = started_at(0);
        let file_path = dir.path().join("existing.log");
        fs::write(&file_path, b"init").unwrap();
        let resolved = resolve_log_path(&file_path, &started);
        assert_eq!(resolved, file_path);
    }

    #[test]
    fn test_resolve_log_path_exact_nonexistent_file() {
        let dir = tempfile::tempdir().unwrap();
        let started = started_at(0);
        let file_path = dir.path().join("not_yet.log");
        let resolved = resolve_log_path(&file_path, &started);
        assert_eq!(resolved, file_path);
    }

    #[test]
    fn test_resolve_log_path_special_devices() {
        let started = started_at(0);
        assert_eq!(
            resolve_log_path(Path::new("/dev/null"), &started),
            PathBuf::from("/dev/null")
        );
        assert_eq!(
            resolve_log_path(Path::new("/dev/stderr"), &started),
            PathBuf::from("/dev/stderr")
        );
    }
}
