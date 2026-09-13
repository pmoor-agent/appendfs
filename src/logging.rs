//! Where diagnostic logs go.
//!
//! A backgrounded mount has no stderr: libfuse's `fuse_daemonize` redirects stdout and
//! stderr to `/dev/null`, so every `log::` record from a normal (non-`--foreground`) mount
//! was being discarded. Long-running mounts are exactly the ones worth having logs for, so
//! they write to a file inside the volume's own log directory instead.
//!
//! Each run gets its own file, named for the time it started and its pid. There is no
//! rotation to reason about, two mounts of the same volume cannot interleave their records,
//! and a crashed run's log stays exactly as it was left rather than being overwritten by the
//! restart.
//!
//! A file is the only destination. Anything a user is meant to read is printed directly, so
//! logging has no reason to compete for the terminal - and `--log-file` reaches the terminal
//! anyway via `/dev/stderr`, or discards via `/dev/null`, which is why there is no separate
//! flag for either.
//!
//! The files live in a `logs/` subdirectory rather than beside the `.log` and `.summary`
//! generation files. `Storage::list_files` is non-recursive and returns only files, so
//! nothing in a subdirectory can be mistaken for a volume file by recovery, replication, or
//! pruning - the same reasoning that puts the block cache in `.cache/`.
//!
//! Logging never takes the filesystem down: if the file cannot be opened or written, the
//! mount continues and the records are dropped.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Subdirectory of the volume log directory holding diagnostic logs.
pub const LOG_SUBDIR: &str = "logs";

/// Default filter applied when neither `--log-level` nor `RUST_LOG` says otherwise.
pub const DEFAULT_LOG_LEVEL: &str = "info";

/// The directory a volume's diagnostic logs are written to.
pub fn log_directory(log_dir: &Path) -> PathBuf {
    log_dir.join(LOG_SUBDIR)
}

/// Names one run's log file: `appendfs-<YYYYMMDD>-<HHMMSS>-<pid>.log`.
///
/// The timestamp sorts chronologically and the pid disambiguates two mounts started within
/// the same second, so a name is never reused and no run can clobber another's log.
pub fn log_file_name(started: SystemTime, pid: u32) -> String {
    format!("appendfs-{}-{}.log", crate::clock::format_utc_compact(started), pid)
}

/// The log file for a run starting now.
pub fn log_file_path(log_dir: &Path, started: SystemTime, pid: u32) -> PathBuf {
    log_directory(log_dir).join(log_file_name(started, pid))
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
        // `append` rather than truncate: an explicit `--log-file` may name an existing file
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

/// The default log destination for a command, or `None` for one that should not write logs.
///
/// Only the mount commands get one. They daemonize away from the terminal and run for weeks,
/// which is what a log file is for; a one-shot command prints what its caller needs to see
/// and has no business leaving a file behind in the volume.
pub fn default_path_for(log_dir: Option<&Path>) -> Option<PathBuf> {
    let log_dir = log_dir?;
    // Canonicalized because `fuse_daemonize` chdirs to `/` shortly after this.
    let root = fs::canonicalize(log_dir).unwrap_or_else(|_| log_dir.to_path_buf());
    Some(log_file_path(&root, SystemTime::now(), std::process::id()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn test_log_file_name_identifies_the_run() {
        let started = UNIX_EPOCH + Duration::from_secs(1_766_000_000);
        assert_eq!(log_file_name(started, 4242), "appendfs-20251217-193320-4242.log");
    }

    #[test]
    fn test_concurrent_runs_never_share_a_file() {
        // Two mounts of the same volume starting in the same second must not interleave
        // their records, which is what the pid is for.
        let started = UNIX_EPOCH + Duration::from_secs(1_766_000_000);
        assert_ne!(log_file_name(started, 1), log_file_name(started, 2));

        // And a later run sorts after an earlier one.
        assert!(log_file_name(started, 9) < log_file_name(started + Duration::from_secs(1), 1));
    }

    #[test]
    fn test_log_lives_where_storage_cannot_see_it() {
        // The guarantee that keeps a diagnostic log from ever being mistaken for a volume
        // file: `list_files` is non-recursive and file-only, so a subdirectory is invisible.
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::OsStorage::new(dir.path());
        let path = log_file_path(dir.path(), SystemTime::now(), std::process::id());

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
        let started = UNIX_EPOCH + Duration::from_secs(1_766_000_000);

        let first = log_file_path(dir.path(), started, 1);
        let mut sink = LogSink::create(&first).unwrap();
        sink.write_all(b"from the first run\n").unwrap();
        sink.flush().unwrap();
        drop(sink);

        let second = log_file_path(dir.path(), started + Duration::from_secs(5), 2);
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
        let path = log_file_path(dir.path(), SystemTime::now(), std::process::id());
        let mut sink = LogSink::create(&path).unwrap();
        sink.write_all(b"before\n").unwrap();
        sink.file = None;
        assert!(sink.write_all(b"after\n").is_ok(), "a lost log file must be survivable");
        assert!(sink.flush().is_ok());
    }
}
