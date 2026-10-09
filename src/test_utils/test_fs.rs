//! A test volume: an `InMemoryFS` together with the storage, clock and remotes behind it.
//!
//! [`TestFS::builder`] initializes a volume and opens it the way a real mount does
//! (`init_volume`, then `recover_fs`, then [`InMemoryFS::next_log_writer`]), so tests run
//! against the same assembly as production rather than a hand-built approximation of it.
//! [`TestFS::clean_remount`] and [`TestFS::unclean_crash`] reopen the same storage the
//! same way.

use crate::FsTestExt;
use crate::clock::{Clock, SystemClock};
use crate::crypto::{VolumeHeader, VolumeKey};
use crate::error::FsError;
use crate::fs::InMemoryFS;
use crate::log::{LogFileCache, RecoveryTarget, init_volume_with_clock_and_uids, recover_fs};
use crate::remote::{
    BlockCache, FailingRemoteStore, LatencyRemoteStore, MemoryBlockCache, MockRemoteStore, PruneExpr, RemoteReadTarget,
    RemoteRegistry, RemoteReplicationWorker, RemoteTargetConfig,
};
use crate::shim::{FileAttr, FileType};
use crate::storage::{FaultStorage, MemoryStorage, Storage};
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

/// Per-inode snapshot entry produced by `TestFS::get_tree_snapshot` - built entirely
/// from the same core handlers real FUSE dispatch uses (`getattr_core`, `list_dir_core`,
/// `readlink_core`, `FsTestExt::read_blocking`), never by reading `fs.inodes` directly.
#[derive(Debug, Clone)]
pub enum SnapshotNode {
    Directory {
        attr: FileAttr,
        entries: Vec<(String, u64)>,
        xattrs: HashMap<String, Vec<u8>>,
    },
    File {
        attr: FileAttr,
        content: Vec<u8>,
        xattrs: HashMap<String, Vec<u8>>,
    },
    Symlink {
        attr: FileAttr,
        target: String,
        xattrs: HashMap<String, Vec<u8>>,
    },
    Special {
        attr: FileAttr,
        xattrs: HashMap<String, Vec<u8>>,
    },
}

/// Configures a [`TestFS`]. Every option has a default, so `TestFS::builder().build()` is a
/// plaintext, in-memory volume on the system clock.
///
/// Setup failures panic rather than return an error, so the panicking entry points carry
/// `#[track_caller]` and report the test line that asked for the volume.
pub struct TestFSBuilder {
    clock: Arc<dyn Clock>,
    storage: Option<Arc<dyn Storage>>,
    fault_injection: bool,
    max_log_size: u64,
    volume_header: VolumeHeader,
    volume_key: Arc<VolumeKey>,
    root_owner: Option<(u32, u32)>,
    remotes: usize,
}

impl TestFSBuilder {
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Puts the volume in `storage` instead of a fresh `MemoryStorage`, for tests that need
    /// to reach the files themselves, e.g. through a directory on disk.
    pub fn storage(mut self, storage: Arc<dyn Storage>) -> Self {
        self.storage = Some(storage);
        self
    }

    /// Routes all volume I/O through a `FaultStorage`, kept in [`TestFS::fault`], so a test
    /// can make writes fail at chosen moments.
    pub fn fault_injection(mut self) -> Self {
        self.fault_injection = true;
        self
    }

    /// Caps each log generation at `bytes`, also after a remount.
    pub fn max_log_size(mut self, bytes: u64) -> Self {
        self.max_log_size = bytes;
        self
    }

    /// Initializes the volume with `header`, unlocked by `key`, instead of as plaintext.
    pub fn volume(mut self, header: VolumeHeader, key: Arc<VolumeKey>) -> Self {
        self.volume_header = header;
        self.volume_key = key;
        self
    }

    /// Makes `uid:gid` own the root directory instead of the user running the test.
    pub fn root_owner(mut self, uid: u32, gid: u32) -> Self {
        self.root_owner = Some((uid, gid));
        self
    }

    /// Attaches `count` in-memory remotes, readable through a shared block cache. Each sits
    /// behind a `LatencyRemoteStore` and a `FailingRemoteStore` so tests can slow it down or
    /// take it offline.
    pub fn remotes(mut self, count: usize) -> Self {
        self.remotes = count;
        self
    }

    #[track_caller]
    pub fn build(self) -> TestFS {
        let base = self.storage.unwrap_or_else(|| Arc::new(MemoryStorage::new()));
        let (storage, fault) = if self.fault_injection {
            let fault = Arc::new(FaultStorage::new(base));
            (Arc::clone(&fault) as Arc<dyn Storage>, Some(fault))
        } else {
            (base, None)
        };
        let (uid, gid) = self.root_owner.unwrap_or_else(crate::shim::current_uid_gid);
        init_volume_with_clock_and_uids(
            Arc::clone(&storage),
            &self.volume_key,
            self.volume_header,
            Arc::clone(&self.clock),
            uid,
            gid,
        )
        .expect("initialize test volume");

        let mut remotes = Vec::new();
        let mut latency_remotes = Vec::new();
        let mut memory_remotes = Vec::new();
        let mut remote_registry = None;
        let mut block_cache = None;
        if self.remotes > 0 {
            let mut registry = RemoteRegistry::new();
            registry.policy.prune_rule = PruneExpr::immediate_readable(1);
            registry.policy.max_log_age_secs = 3600;
            registry.policy.active_sync_interval_secs = 0;
            for i in 0..self.remotes {
                let memory = Arc::new(MockRemoteStore::new());
                let latency = Arc::new(LatencyRemoteStore::new(memory.clone()));
                let failing = Arc::new(FailingRemoteStore::new(latency.clone()));
                let mut config = RemoteTargetConfig::new(format!("bucket-{}", i));
                config.read_priority = remote_read_priority(i);
                registry.add_remote(remote_name(i), config);
                registry.set_store_override(remote_name(i), failing.clone());
                memory_remotes.push(memory);
                latency_remotes.push(latency);
                remotes.push(failing);
            }
            remote_registry = Some(Arc::new(RwLock::new(registry)));
            block_cache = Some(Arc::new(MemoryBlockCache::new(50 * 1024 * 1024)) as Arc<dyn BlockCache>);
        }

        let mut test_fs = TestFS {
            fs: open_volume(&storage, &self.clock, &self.volume_key, self.max_log_size).expect("open test volume"),
            storage,
            fault,
            remotes,
            latency_remotes,
            memory_remotes,
            remote_registry,
            block_cache,
            volume_key: self.volume_key,
            max_log_size: self.max_log_size,
        };
        test_fs.connect_remotes();
        test_fs
    }
}

/// Recovers the volume in `storage` and opens its next generation for writing, as a
/// read-write mount does.
///
/// Fails if recovery fails or another writer still holds the volume's lock.
pub fn open_volume(
    storage: &Arc<dyn Storage>,
    clock: &Arc<dyn Clock>,
    volume_key: &Arc<VolumeKey>,
    max_log_size: u64,
) -> io::Result<InMemoryFS> {
    let mut fs = recover_fs(
        Arc::clone(storage),
        RecoveryTarget::Latest,
        Arc::clone(clock),
        Arc::clone(volume_key),
    )?;
    let writer = fs.next_log_writer(Arc::clone(storage), max_log_size)?;
    fs.attach_log_writer(Arc::new(writer));
    Ok(fs)
}

fn remote_name(index: usize) -> String {
    format!("remote{}", index)
}

fn remote_read_priority(index: usize) -> u32 {
    10 + index as u32
}

/// The replication worker only uses its log directory for on-disk volumes; test volumes
/// live in memory unless a test supplies its own storage.
const LOG_DIR: &str = "/memory";

pub struct TestFS {
    pub fs: InMemoryFS,
    pub storage: Arc<dyn Storage>,
    /// Present only for volumes built with [`TestFSBuilder::fault_injection`]; the handle
    /// used to inject and clear write failures. Survives remounts and crashes so faults can
    /// be injected repeatedly across a run.
    pub fault: Option<Arc<FaultStorage>>,
    /// The remotes as the volume sees them; empty unless built with [`TestFSBuilder::remotes`].
    pub remotes: Vec<Arc<FailingRemoteStore>>,
    pub latency_remotes: Vec<Arc<LatencyRemoteStore>>,
    pub memory_remotes: Vec<Arc<MockRemoteStore>>,
    pub remote_registry: Option<Arc<RwLock<RemoteRegistry>>>,
    pub block_cache: Option<Arc<dyn BlockCache>>,
    volume_key: Arc<VolumeKey>,
    max_log_size: u64,
}

impl TestFS {
    pub fn builder() -> TestFSBuilder {
        TestFSBuilder {
            clock: Arc::new(SystemClock),
            storage: None,
            fault_injection: false,
            max_log_size: crate::cli::DEFAULT_MAX_LOG_SIZE,
            volume_header: VolumeHeader::plaintext(),
            volume_key: VolumeKey::plaintext_arc(),
            root_owner: None,
            remotes: 0,
        }
    }

    /// Points the filesystem's reads and replication at the remotes, as a mount with
    /// configured remotes does.
    fn connect_remotes(&mut self) {
        let Some(registry) = &self.remote_registry else {
            return;
        };
        let read_targets: Vec<RemoteReadTarget> = self
            .remotes
            .iter()
            .enumerate()
            .map(|(i, remote)| RemoteReadTarget::new(remote_name(i), remote.clone(), remote_read_priority(i)))
            .collect();
        self.fs.log_cache = Some(Arc::new(LogFileCache::with_remote_support(
            Arc::clone(&self.storage),
            self.block_cache.clone(),
            read_targets,
            Some(Arc::clone(&self.fs.manifest)),
        )));
        self.fs.set_remote_registry(Arc::clone(registry));
    }

    /// Shuts down cleanly - sealing the active generation if remotes should receive it, and
    /// exporting a summary - then recovers the volume into a fresh instance.
    #[track_caller]
    pub fn clean_remount(self) -> Self {
        if !self.remotes.is_empty() {
            let _ = self.fs.force_roll_active_log();
        }
        let _ = self.fs.sync_and_export_summary();
        self.reopen()
    }

    /// Drops the instance after only waiting for in-flight flushes, as a crash would, then
    /// recovers the volume into a fresh instance.
    ///
    /// Inode numbers handed out to operations that never became durable are not reused
    /// afterwards, so a test's model of the tree stays unambiguous.
    #[track_caller]
    pub fn unclean_crash(self) -> Self {
        let next_inode = self.fs.next_inode.load(Ordering::SeqCst);
        let _ = self.fs.quiesce();
        let recovered = self.reopen();
        recovered.fs.next_inode.fetch_max(next_inode, Ordering::SeqCst);
        recovered
    }

    #[track_caller]
    fn reopen(self) -> Self {
        let TestFS {
            mut fs,
            storage,
            fault,
            remotes,
            latency_remotes,
            memory_remotes,
            remote_registry,
            block_cache,
            volume_key,
            max_log_size,
        } = self;
        let clock = Arc::clone(&fs.clock);
        let max_extent_size = fs.max_extent_size;
        // Without its writer the old instance can no longer append on its way out, and it
        // releases the volume's storage lock for the next one. It must be gone before
        // recovery starts, since dropping it runs its shutdown sequence.
        fs.log_writer = None;
        drop(fs);

        let mut reopened = TestFS {
            fs: open_volume(&storage, &clock, &volume_key, max_log_size).expect("reopen test volume"),
            storage,
            fault,
            remotes,
            latency_remotes,
            memory_remotes,
            remote_registry,
            block_cache,
            volume_key,
            max_log_size,
        };
        reopened.fs.max_extent_size = max_extent_size;
        reopened.connect_remotes();
        reopened
    }

    /// Runs one synchronous replication cycle across all remotes.
    pub fn sync_remotes(&self) {
        if let Some(registry) = &self.remote_registry {
            let mut last_part_sync = SystemTime::UNIX_EPOCH;
            let mut uploaded_parts = HashMap::new();
            let _ = RemoteReplicationWorker::run_cycle(
                &self.fs,
                registry,
                Path::new(LOG_DIR),
                &mut last_part_sync,
                &mut uploaded_parts,
            );
        }
    }

    /// Overrides the data-extent cap, so a test can exercise record chunking without having
    /// to write megabytes. Carried across `clean_remount` / `unclean_crash`.
    pub fn set_max_extent_size(&mut self, size: usize) {
        self.fs.max_extent_size = size;
    }

    pub fn lookup(&self, parent: u64, name: &str) -> Option<u64> {
        self.fs.lookup_child(parent, name)
    }

    pub fn mkdir(&self, parent: u64, name: &str, mode: u32) -> Result<u64, FsError> {
        crate::operations::dir::mkdir_core(&self.fs, parent, name, mode, 1000, 1000).map(|attr| attr.ino)
    }

    pub fn create(&self, parent: u64, name: &str, mode: u32) -> Result<u64, FsError> {
        crate::operations::read_write::create_core(&self.fs, parent, name, mode, 0, 1000, 1000).map(|attr| attr.ino)
    }

    pub fn write(&self, ino: u64, offset: u64, buf: &[u8]) -> Result<usize, FsError> {
        self.fs.write_at(ino, buf, offset as i64)
    }

    pub fn read(&self, ino: u64, offset: u64, len: usize) -> Result<Vec<u8>, FsError> {
        self.fs.read_at(ino, offset as i64, len)
    }

    pub fn read_handle(&self, ino: u64, fh: u64, offset: u64, len: usize) -> Result<Vec<u8>, FsError> {
        self.fs.read_blocking(ino, fh, offset as i64, len)
    }

    pub fn read_all(&self, ino: u64) -> Result<Vec<u8>, FsError> {
        let fh = self.open(ino, libc::O_RDONLY as u32)?;
        let mut result = Vec::new();
        let chunk_size = 64 * 1024;
        let mut offset = 0i64;
        let res = loop {
            match self.fs.read_blocking(ino, fh, offset, chunk_size) {
                Ok(chunk) => {
                    if chunk.is_empty() {
                        break Ok(result);
                    }
                    let read_len = chunk.len();
                    result.extend_from_slice(&chunk);
                    if read_len < chunk_size {
                        break Ok(result);
                    }
                    offset += read_len as i64;
                }
                Err(err) => break Err(err),
            }
        };
        let _ = self.release(ino, fh);
        res
    }

    pub fn punch(&self, ino: u64, offset: u64, len: u64) -> Result<(), FsError> {
        crate::operations::read_write::punch_hole_core(&self.fs, ino, offset, len)
    }

    pub fn unlink(&self, parent: u64, name: &str) -> Result<(), FsError> {
        crate::operations::links::unlink_core(&self.fs, parent, name)
    }

    pub fn rmdir(&self, parent: u64, name: &str) -> Result<(), FsError> {
        crate::operations::dir::rmdir_core(&self.fs, parent, name)
    }

    pub fn symlink(&self, parent: u64, name: &str, target: &str) -> Result<u64, FsError> {
        crate::operations::links::symlink_core(&self.fs, parent, name, target, 1000, 1000).map(|attr| attr.ino)
    }

    pub fn link(&self, ino: u64, newparent: u64, newname: &str) -> Result<(), FsError> {
        crate::operations::links::link_core(&self.fs, ino, newparent, newname).map(|_| ())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn setattr(
        &self,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<SystemTime>,
        mtime: Option<SystemTime>,
    ) -> Result<(), FsError> {
        use crate::operations::read_write::{
            FUSE_SET_ATTR_ATIME, FUSE_SET_ATTR_GID, FUSE_SET_ATTR_MODE, FUSE_SET_ATTR_MTIME, FUSE_SET_ATTR_SIZE,
            FUSE_SET_ATTR_UID, setattr_core,
        };

        let mut to_set = 0u32;
        if mode.is_some() {
            to_set |= FUSE_SET_ATTR_MODE;
        }
        if uid.is_some() {
            to_set |= FUSE_SET_ATTR_UID;
        }
        if gid.is_some() {
            to_set |= FUSE_SET_ATTR_GID;
        }
        if size.is_some() {
            to_set |= FUSE_SET_ATTR_SIZE;
        }
        if atime.is_some() {
            to_set |= FUSE_SET_ATTR_ATIME;
        }
        if mtime.is_some() {
            to_set |= FUSE_SET_ATTR_MTIME;
        }

        setattr_core(
            &self.fs,
            ino,
            mode.unwrap_or(0),
            uid.unwrap_or(0),
            gid.unwrap_or(0),
            size.unwrap_or(0) as i64,
            atime.unwrap_or(std::time::UNIX_EPOCH),
            mtime.unwrap_or(std::time::UNIX_EPOCH),
            to_set,
        )
        .map(|_| ())
    }

    pub fn readlink(&self, ino: u64) -> Result<String, FsError> {
        crate::operations::links::readlink_core(&self.fs, ino)
    }

    pub fn rename(&self, parent: u64, name: &str, newparent: u64, newname: &str) -> Result<(), FsError> {
        crate::operations::links::rename_core(&self.fs, parent, name, newparent, newname)
    }

    pub fn opendir(&self, ino: u64) -> Result<u64, FsError> {
        crate::operations::dir::opendir_core(&self.fs, ino, 0)
    }

    pub fn releasedir(&self, ino: u64, fh: u64) -> Result<(), FsError> {
        crate::operations::dir::releasedir_core(&self.fs, ino, fh)
    }

    pub fn open(&self, ino: u64, flags: u32) -> Result<u64, FsError> {
        crate::operations::read_write::open_core(&self.fs, ino, flags)
    }

    pub fn release(&self, ino: u64, fh: u64) -> Result<(), FsError> {
        crate::operations::read_write::release_core(&self.fs, ino, fh)
    }

    pub fn setxattr(&self, ino: u64, name: &str, value: &[u8], flags: i32) -> Result<(), FsError> {
        crate::operations::xattr::setxattr_core(&self.fs, ino, name, value, flags).map(|_| ())
    }

    /// Runs the real two-phase getxattr protocol (query size, then fetch with that
    /// size) rather than just requesting a large fixed buffer, so this exercises the
    /// same size/ERANGE path a real xattr syscall would.
    pub fn getxattr(&self, ino: u64, name: &str) -> Result<Vec<u8>, FsError> {
        use crate::shim::FuseResponse;
        match crate::operations::xattr::getxattr_core(&self.fs, ino, name, 0)? {
            // A 0-length value is indistinguishable from "just tell me the size" at
            // size 0 - same ambiguity a real getxattr(2) caller has - so short-circuit
            // instead of re-querying with size 0 and hitting that same branch again.
            FuseResponse::XattrSize(0) => Ok(Vec::new()),
            FuseResponse::XattrSize(size) => {
                match crate::operations::xattr::getxattr_core(&self.fs, ino, name, size)? {
                    FuseResponse::Buf(data) => Ok(data.to_vec()),
                    FuseResponse::XattrSize(_) => unreachable!("size query answered with another size"),
                    _ => unreachable!("unexpected getxattr response"),
                }
            }
            FuseResponse::Buf(_) => unreachable!("size-0 query returned data"),
            _ => unreachable!("unexpected getxattr response"),
        }
    }

    pub fn removexattr(&self, ino: u64, name: &str) -> Result<(), FsError> {
        crate::operations::xattr::removexattr_core(&self.fs, ino, name).map(|_| ())
    }

    /// Same two-phase size-then-data protocol as `getxattr`; returns the decoded,
    /// null-separated attribute names.
    pub fn listxattr(&self, ino: u64) -> Result<Vec<String>, FsError> {
        use crate::shim::FuseResponse;
        let buf = match crate::operations::xattr::listxattr_core(&self.fs, ino, 0)? {
            // See the same-value comment in `getxattr` - size 0 has no second call to make.
            FuseResponse::XattrSize(0) => Vec::new(),
            FuseResponse::XattrSize(size) => match crate::operations::xattr::listxattr_core(&self.fs, ino, size)? {
                FuseResponse::Buf(data) => data.to_vec(),
                FuseResponse::XattrSize(_) => unreachable!("size query answered with another size"),
                _ => unreachable!("unexpected listxattr response"),
            },
            FuseResponse::Buf(data) => data.to_vec(),
            _ => unreachable!("unexpected listxattr response"),
        };
        Ok(buf
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect())
    }

    /// Resolves the full set of an inode's xattrs (name -> value) for snapshot
    /// comparison, via the same public getxattr/listxattr path a real caller would use.
    fn xattr_snapshot(&self, ino: u64) -> HashMap<String, Vec<u8>> {
        let names = self.listxattr(ino).unwrap_or_default();
        names
            .into_iter()
            .filter_map(|name| {
                let value = self.getxattr(ino, &name).ok()?;
                Some((name, value))
            })
            .collect()
    }

    pub fn get_tree_snapshot(&self) -> HashMap<u64, SnapshotNode> {
        let mut snapshot = HashMap::new();
        let mut visited = std::collections::HashSet::new();
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(1u64);
        visited.insert(1u64);

        while let Some(ino) = queue.pop_front() {
            let attr = match crate::operations::read_write::getattr_core(&self.fs, ino) {
                Ok(attr) => attr,
                Err(_) => continue,
            };

            let xattrs = self.xattr_snapshot(ino);
            match attr.file_type {
                FileType::Directory => {
                    let mut entries = crate::operations::dir::list_dir_core(&self.fs, ino).unwrap_or_default();
                    entries.retain(|(_, child_ino)| *child_ino < 0xFFFF_FFFF_0000_0000);
                    for (_, child_ino) in &entries {
                        if visited.insert(*child_ino) {
                            queue.push_back(*child_ino);
                        }
                    }
                    snapshot.insert(ino, SnapshotNode::Directory { attr, entries, xattrs });
                }
                FileType::RegularFile => {
                    let content = self.read(ino, 0, attr.size as usize).unwrap_or_default();
                    snapshot.insert(ino, SnapshotNode::File { attr, content, xattrs });
                }
                FileType::Symlink => {
                    let target = crate::operations::links::readlink_core(&self.fs, ino).unwrap_or_default();
                    snapshot.insert(ino, SnapshotNode::Symlink { attr, target, xattrs });
                }
                FileType::NamedPipe | FileType::CharDevice | FileType::BlockDevice | FileType::Socket => {
                    snapshot.insert(ino, SnapshotNode::Special { attr, xattrs });
                }
            }
        }

        snapshot
    }
}
