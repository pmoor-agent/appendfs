//! Where diagnostic logs go.
//!
//! A backgrounded mount has no stderr: libfuse's `fuse_daemonize` redirects stdout and
//! stderr to `/dev/null`, so every `log::` record from a normal (non-`--foreground`) mount
//! was being discarded. Long-running mounts are exactly the ones worth having logs for, so
//! they write to a file inside the volume's own log directory instead.
//!
//! The file lives in a `logs/` subdirectory rather than beside the `.log` and `.summary`
//! generation files. `Storage::list_files` is non-recursive and returns only files, so
//! nothing in a subdirectory can be mistaken for a volume file by recovery, replication, or
//! pruning - the same reasoning that puts the block cache in `.cache/`.
//!
//! Logging never takes the filesystem down: if the file cannot be opened or written, the
//! mount continues and the records are dropped.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Subdirectory of the volume log directory holding diagnostic logs.
pub const LOG_SUBDIR: &str = "logs";

/// Filename written inside [`LOG_SUBDIR`].
pub const LOG_FILENAME: &str = "appendfs.log";

/// Default size at which the log rotates. Two files are kept, so this bounds the footprint
/// at roughly twice this value.
pub const DEFAULT_LOG_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// Default filter applied when neither `--log-level` nor `RUST_LOG` says otherwise.
pub const DEFAULT_LOG_LEVEL: &str = "info";

/// The conventional location of a volume's diagnostic log.
pub fn default_log_path(log_dir: &Path) -> PathBuf {
    log_dir.join(LOG_SUBDIR).join(LOG_FILENAME)
}

/// A log file that renames itself out of the way once it grows past `max_bytes`.
///
/// One previous generation is kept, as `<name>.1`. That is enough to survive the rotation
/// that happens just as something interesting is being logged, without the bookkeeping of a
/// full retention policy.
struct RotatingLog {
    path: PathBuf,
    /// `None` once opening has failed; records are dropped rather than propagated.
    file: Option<File>,
    written: u64,
    max_bytes: u64,
    tee_stderr: bool,
}

impl RotatingLog {
    fn open(path: PathBuf, max_bytes: u64, tee_stderr: bool) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        // Appending to an existing log, so rotation has to account for what is already there.
        let written = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Self {
            path,
            file: Some(file),
            written,
            max_bytes,
            tee_stderr,
        })
    }

    fn rotate(&mut self) {
        // Close before renaming so the reopened handle is the new file, not the old inode.
        self.file = None;
        let mut backup = self.path.clone().into_os_string();
        backup.push(".1");
        let _ = fs::rename(&self.path, PathBuf::from(backup));
        self.file = OpenOptions::new().create(true).append(true).open(&self.path).ok();
        self.written = 0;
    }
}

impl Write for RotatingLog {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.tee_stderr {
            let _ = io::stderr().write_all(buf);
        }

        // Rotate on the record that would cross the limit, never mid-record, so a rotated
        // file never ends with half a line.
        if self.written > 0 && self.written.saturating_add(buf.len() as u64) > self.max_bytes {
            self.rotate();
        }

        // A logging failure must not surface as a filesystem error, so this reports success
        // either way and simply stops writing.
        match self.file {
            Some(ref mut file) => match file.write(buf) {
                Ok(n) => {
                    self.written += n as u64;
                    Ok(buf.len())
                }
                Err(_) => {
                    self.file = None;
                    Ok(buf.len())
                }
            },
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

/// Builds the env_logger filter, letting `RUST_LOG` override `level` as usual.
fn builder(level: &str) -> env_logger::Builder {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level))
}

/// Initializes stderr logging, for the one-shot commands that stay in the foreground and
/// whose output the caller is watching.
pub fn init_stderr(level: &str) {
    builder(level).init();
}

/// Initializes logging for a mount: a rotating file under the volume's log directory, plus
/// stderr while running in the foreground.
///
/// `log_dir` is canonicalized first, because `fuse_daemonize` chdirs to `/` and rotation
/// reopens the log by path afterwards. Returns the path being written to, or `None` if the
/// file could not be opened - in which case logging falls back to stderr and the mount
/// proceeds regardless, since a volume on read-only media is still worth mounting.
pub fn init_for_mount(
    log_dir: &Path,
    explicit_path: Option<&Path>,
    max_bytes: u64,
    level: &str,
    foreground: bool,
) -> Option<PathBuf> {
    let path = match explicit_path {
        Some(p) => p.to_path_buf(),
        None => default_log_path(&fs::canonicalize(log_dir).unwrap_or_else(|_| log_dir.to_path_buf())),
    };
    let path = fs::canonicalize(&path).unwrap_or(path);

    match RotatingLog::open(path.clone(), max_bytes, foreground) {
        Ok(sink) => {
            builder(level).target(env_logger::Target::Pipe(Box::new(sink))).init();
            Some(path)
        }
        Err(e) => {
            builder(level).init();
            log::warn!("Could not open log file {}: {}; logging to stderr", path.display(), e);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_log_path_is_below_the_volume_directory() {
        let path = default_log_path(Path::new("/srv/vol"));
        assert_eq!(path, PathBuf::from("/srv/vol/logs/appendfs.log"));
    }

    #[test]
    fn test_log_lives_where_storage_cannot_see_it() {
        // The guarantee that keeps a diagnostic log from ever being mistaken for a volume
        // file: `list_files` is non-recursive and file-only, so a subdirectory is invisible.
        let dir = tempfile::tempdir().unwrap();
        let storage = crate::storage::OsStorage::new(dir.path());
        let mut sink = RotatingLog::open(default_log_path(dir.path()), 1024, false).unwrap();
        sink.write_all(b"a log record\n").unwrap();
        sink.flush().unwrap();

        assert!(dir.path().join("logs").join(LOG_FILENAME).exists());
        let listed = crate::storage::Storage::list_files(&storage).unwrap();
        assert!(
            listed.is_empty(),
            "the log directory must look empty to volume code, got {:?}",
            listed
        );
    }

    #[test]
    fn test_rotation_keeps_one_previous_generation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("logs").join(LOG_FILENAME);
        let mut sink = RotatingLog::open(path.clone(), 64, false).unwrap();

        for i in 0..40 {
            sink.write_all(format!("record {:03} padding padding\n", i).as_bytes())
                .unwrap();
        }
        sink.flush().unwrap();

        let backup = PathBuf::from({
            let mut b = path.clone().into_os_string();
            b.push(".1");
            b
        });
        assert!(path.exists(), "the active log must exist after rotating");
        assert!(backup.exists(), "one previous generation must be kept");

        // Bounded: each file holds at most one record beyond the limit, and nothing else
        // accumulates alongside them.
        let entries: Vec<_> = fs::read_dir(dir.path().join("logs")).unwrap().flatten().collect();
        assert_eq!(entries.len(), 2, "rotation must not accumulate files");
        for entry in entries {
            assert!(
                entry.metadata().unwrap().len() <= 64 + 32,
                "each generation stays near the limit"
            );
        }

        // The newest records survive; rotation drops the oldest, not the newest.
        let active = fs::read_to_string(&path).unwrap();
        assert!(active.contains("record 039"), "active log holds the newest record");
    }

    #[test]
    fn test_rotation_never_splits_a_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("logs").join(LOG_FILENAME);
        let mut sink = RotatingLog::open(path.clone(), 32, false).unwrap();
        for i in 0..10 {
            sink.write_all(format!("{:02}: a complete record\n", i).as_bytes())
                .unwrap();
        }
        sink.flush().unwrap();

        for file in fs::read_dir(dir.path().join("logs")).unwrap().flatten() {
            let contents = fs::read_to_string(file.path()).unwrap();
            for line in contents.lines() {
                assert!(
                    line.ends_with("a complete record"),
                    "rotation split a record: {:?}",
                    line
                );
            }
        }
    }

    #[test]
    fn test_writes_keep_succeeding_after_the_file_is_lost() {
        // A filesystem must not fail because its log file did.
        let dir = tempfile::tempdir().unwrap();
        let mut sink = RotatingLog::open(default_log_path(dir.path()), 1024, false).unwrap();
        sink.write_all(b"before\n").unwrap();
        sink.file = None;
        assert!(sink.write_all(b"after\n").is_ok(), "a lost log file must be survivable");
        assert!(sink.flush().is_ok());
    }
}
