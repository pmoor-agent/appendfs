//! A test volume: an `AppendFs` together with the storage, clock and remotes behind it.
//!
//! [`TestFs::builder`] initializes a volume and opens it the way a real mount does
//! (`init_volume`, then `recover_fs`, then [`AppendFs::next_log_writer`]), so tests run
//! against the same assembly as production rather than a hand-built approximation of it.
//! [`TestFs::clean_remount`] and [`TestFs::unclean_crash`] reopen the same storage the
//! same way.

use crate::clock::{Clock, SystemClock};
use crate::crypto::{VolumeHeader, VolumeKey};
use crate::fs::AppendFs;
use crate::log::{LogFileCache, RecoveryTarget, init_volume_with_clock_and_uids, recover_fs};
use crate::remote::{
    BlockCache, FailingRemoteStore, LatencyRemoteStore, MemoryBlockCache, MockRemoteStore, PruneExpr, RemoteReadTarget,
    RemoteRegistry, RemoteReplicationWorker, RemoteTargetConfig,
};
use crate::storage::{FaultStorage, MemoryStorage, Storage};
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

/// Configures a [`TestFs`]. Every option has a default, so `TestFs::builder().build()` is a
/// plaintext, in-memory volume on the system clock.
///
/// Setup failures panic rather than return an error, so the panicking entry points carry
/// `#[track_caller]` and report the test line that asked for the volume.
pub struct TestFsBuilder {
    clock: Arc<dyn Clock>,
    storage: Option<Arc<dyn Storage>>,
    fault_injection: bool,
    max_log_size: u64,
    volume_header: VolumeHeader,
    volume_key: Arc<VolumeKey>,
    root_owner: Option<(u32, u32)>,
    remotes: usize,
}

impl TestFsBuilder {
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

    /// Routes all volume I/O through a `FaultStorage`, kept in [`TestFs::fault`], so a test
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
    pub fn build(self) -> TestFs {
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

        let mut test_fs = TestFs {
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
) -> io::Result<AppendFs> {
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

pub struct TestFs {
    pub fs: AppendFs,
    pub storage: Arc<dyn Storage>,
    /// Present only for volumes built with [`TestFsBuilder::fault_injection`]; the handle
    /// used to inject and clear write failures. Survives remounts and crashes so faults can
    /// be injected repeatedly across a run.
    pub fault: Option<Arc<FaultStorage>>,
    /// The remotes as the volume sees them; empty unless built with [`TestFsBuilder::remotes`].
    pub remotes: Vec<Arc<FailingRemoteStore>>,
    pub latency_remotes: Vec<Arc<LatencyRemoteStore>>,
    pub memory_remotes: Vec<Arc<MockRemoteStore>>,
    pub remote_registry: Option<Arc<RwLock<RemoteRegistry>>>,
    pub block_cache: Option<Arc<dyn BlockCache>>,
    volume_key: Arc<VolumeKey>,
    max_log_size: u64,
}

impl TestFs {
    pub fn builder() -> TestFsBuilder {
        TestFsBuilder {
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
        let TestFs {
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

        let mut reopened = TestFs {
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
}
