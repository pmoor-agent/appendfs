use crate::clock::{Clock, SystemClock};
use crate::lock_pool::LockPool;
use crate::log::{LogBuffer, LogFileCache, LogWriter, export_summary};
use crate::node::{Node, SyncNode};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

pub struct InMemoryFS {
    pub inodes: RwLock<HashMap<u64, Arc<SyncNode>>>,
    pub next_inode: AtomicU64,
    pub last_tx_id: AtomicU64,
    pub lock_pool: LockPool,
    pub clock: Arc<dyn Clock>,
    pub snapshot_rwlock: Arc<RwLock<()>>,
    pub log_writer: Option<Arc<LogWriter>>,
    pub log_buffer: Arc<LogBuffer>,
    pub log_cache: Option<Arc<LogFileCache>>,
    /// When false, `read()` never touches atime (like a `noatime` mount) - defaults to
    /// true to match real filesystem behavior. Reads are never logged (logging every
    /// read would defeat the point of an append-only log), so an atime bumped only by
    /// reads can never be reconstructed by replay; disabling this makes atime fully
    /// log-derived, which in turn makes exported `.summary` snapshots byte-for-byte
    /// reproducible from the log alone - see `log::summary::export_summary`.
    pub track_atime: bool,
    /// Serializes every directory-structure mutation (mkdir/create/symlink/unlink/
    /// rmdir/rename/link) - held for each call's entire duration, with the resulting
    /// log record staged while still holding it. Two things this buys, together:
    ///
    /// 1. **Log order matches memory order.** Each of those ops mutates its
    ///    directory `entries` (and any affected `nlink`) under fine-grained per-inode
    ///    locks, but used to stage its log record only after releasing them - so two
    ///    concurrent ops could commit their in-memory effects in one order but append
    ///    their log records in the other. For commutative ops that just silently
    ///    diverges `entries` Vec ordering between live state and a post-crash replay;
    ///    for genuinely conflicting ops (two renames racing to overwrite the same
    ///    destination name), replay can pick a different winner than what actually
    ///    happened live - a crash-recovered filesystem showing different content than
    ///    what was there right before the crash. Staging the record before releasing
    ///    this lock makes that structurally impossible: only one directory op's
    ///    memory-mutation-then-log-append sequence can be "in flight" at a time.
    ///
    /// 2. **No cross-op lock ordering to get right.** Rename in particular needs to
    ///    lock a dynamically-discovered second or third inode (an overwrite target, an
    ///    ancestor during the loop-prevention check) whose bucket isn't known until
    ///    after the first lock is already held, which can't be reconciled with a
    ///    fixed global bucket-acquisition order another concurrent op might also be
    ///    using - the deadlock and cycle-formation bugs this project hit while relying
    ///    solely on the striped `lock_pool` for that. With only one directory op ever
    ///    in flight, there's no *other* directory op to race against for these locks
    ///    in the first place.
    ///
    /// File-content operations (read/write/setattr) deliberately don't take this -
    /// they only ever need one inode's `lock_pool` bucket, so they stay fully
    /// concurrent with each other and with whichever directory op currently holds
    /// this lock, which is what actually matters for throughput in an archival
    /// workload (many files read/written in parallel; directory churn is rare).
    pub dir_lock: Mutex<()>,
}

impl InMemoryFS {
    pub fn new() -> Self {
        Self::with_clock(Arc::new(SystemClock))
    }

    pub fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self::with_clock_and_log(clock, None)
    }

    pub fn with_log(log_writer: Arc<LogWriter>) -> Self {
        Self::with_clock_and_log(Arc::new(SystemClock), Some(log_writer))
    }

    pub fn with_clock_and_log(clock: Arc<dyn Clock>, log_writer: Option<Arc<LogWriter>>) -> Self {
        let mut map = HashMap::new();
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        let now = clock.now();

        // Start with only the root directory (Inode 1), which is empty, nlink is 2 (parent entry and '.' link)
        map.insert(
            1,
            Arc::new(SyncNode::new(Node::Directory {
                entries: Vec::new(),
                perm: 0o755,
                nlink: 2,
                uid,
                gid,
                atime: now,
                mtime: now,
                ctime: now,
            })),
        );

        let log_cache = log_writer.as_ref().and_then(|w| {
            let path = w.path();
            path.parent().map(|p| Arc::new(LogFileCache::new(p)))
        });

        Self {
            inodes: RwLock::new(map),
            next_inode: AtomicU64::new(2),
            last_tx_id: AtomicU64::new(0),
            lock_pool: LockPool::new(),
            clock,
            snapshot_rwlock: Arc::new(RwLock::new(())),
            log_writer,
            log_buffer: Arc::new(LogBuffer::new()),
            log_cache,
            track_atime: true,
            dir_lock: Mutex::new(()),
        }
    }

    pub fn set_log_dir(&mut self, log_dir: impl AsRef<Path>) {
        self.log_cache = Some(Arc::new(LogFileCache::new(log_dir)));
    }

    pub(crate) fn allocate_inode(&self) -> u64 {
        self.next_inode.fetch_add(1, Ordering::SeqCst)
    }

    /// Flushes staged log buffer data to OS file buffers.
    pub fn flush_log(&self) -> std::io::Result<()> {
        if let Some(ref writer) = self.log_writer {
            self.log_buffer.flush(writer)?;
        }
        Ok(())
    }

    /// Performs an explicit physical hardware disk sync (called by FUSE `fsync` / `fsyncdir` or unmount).
    pub fn sync_log(&self) -> std::io::Result<()> {
        if let Some(ref writer) = self.log_writer {
            self.log_buffer.flush(writer)?;
            writer.sync()?;
        }
        Ok(())
    }

    /// Exports a single-file summary snapshot of the current in-memory filesystem state.
    pub fn export_summary(&self, log_dir: impl AsRef<Path>) -> std::io::Result<PathBuf> {
        self.sync_log()?;
        let generation = self.log_writer.as_ref().map_or(1, |w| w.generation());
        let last_tx_id = self.log_writer.as_ref().map_or_else(
            || self.last_tx_id.load(Ordering::SeqCst),
            |w| w.last_tx_id(),
        );
        export_summary(self, log_dir, generation, last_tx_id)
    }

    /// Automatically flushes logs, syncs disk, and exports a single-file summary snapshot on unmount.
    pub fn sync_and_export_summary(&self) -> std::io::Result<Option<PathBuf>> {
        self.sync_log()?;
        if let Some(ref writer) = self.log_writer {
            if let Some(log_dir) = writer.path().parent() {
                match self.export_summary(log_dir) {
                    Ok(p) => return Ok(Some(p)),
                    Err(e) => {
                        log::warn!("sync_and_export_summary error: {}", e);
                        return Err(e);
                    }
                }
            }
        }
        Ok(None)
    }
}

impl Drop for InMemoryFS {
    fn drop(&mut self) {
        let _ = self.sync_and_export_summary();
    }
}

impl Default for InMemoryFS {
    fn default() -> Self {
        Self::new()
    }
}

// Helper to trace parent inodes upwards to scan for parent directories. Takes its own
// brief snapshot of the inode map (cloning the `Arc`s) rather than borrowing a
// caller-held guard, and never holds `fs.inodes`'s lock while acquiring a `lock_pool`
// bucket - see the deadlock explanation at rename_core's call site in
// `operations/links.rs`, which is the only caller.
pub(crate) fn find_parent_inode(fs: &InMemoryFS, child_ino: u64) -> Option<u64> {
    let snapshot: Vec<(u64, Arc<SyncNode>)> = {
        let map = fs.inodes.read().unwrap();
        map.iter().map(|(ino, arc)| (*ino, Arc::clone(arc))).collect()
    };
    for (parent_ino, node_arc) in snapshot {
        let _guard = fs.lock_pool.read(parent_ino);
        let node = unsafe { node_arc.read() };
        if let Node::Directory { entries, .. } = node {
            if entries.iter().any(|(_, ino)| *ino == child_ino) {
                return Some(parent_ino);
            }
        }
    }
    None
}
