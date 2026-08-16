use appendfs::InMemoryFS;
use appendfs::LogWriter;
use appendfs::clock::{AdvancingClock, Clock, MockClock, SystemClock};
use appendfs::log::{CreatePayload, MkdirPayload, OpCode, recover_fs};
use appendfs::node::Node;
use appendfs::shim::{FileAttr, FileType};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime};

struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0x123456789ABCDEF0 } else { seed },
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn gen_range(&mut self, min: usize, max: usize) -> usize {
        if min >= max {
            return min;
        }
        min + (self.next_u64() as usize % (max - min + 1))
    }
}

pub struct TestFS {
    pub fs: InMemoryFS,
    pub log_dir: PathBuf,
    pub _temp_dir: Option<Arc<tempfile::TempDir>>,
}

/// Per-inode snapshot entry produced by `TestFS::get_tree_snapshot` - built entirely
/// from the same core handlers real FUSE dispatch uses (`getattr_core`, `list_dir_core`,
/// `readlink_core`, `read_core`), never by reading `fs.inodes` directly.
#[derive(Debug, Clone)]
pub enum SnapshotNode {
    Directory {
        attr: FileAttr,
        entries: Vec<(String, u64)>,
    },
    File {
        attr: FileAttr,
        content: Vec<u8>,
    },
    Symlink {
        attr: FileAttr,
        target: String,
    },
}

impl TestFS {
    pub fn new_temp(max_log_size: Option<u64>) -> Self {
        Self::new_temp_with_clock(max_log_size, Arc::new(SystemClock))
    }

    pub fn new_temp_with_clock(max_log_size: Option<u64>, clock: Arc<dyn Clock>) -> Self {
        let temp_dir = tempfile::tempdir().unwrap();
        let log_dir = temp_dir.path().to_path_buf();
        let writer = if let Some(max_size) = max_log_size {
            Arc::new(
                appendfs::LogWriter::create_with_max_size(&log_dir, 1, &*clock, max_size).unwrap(),
            )
        } else {
            Arc::new(appendfs::LogWriter::create(&log_dir, 1, &*clock).unwrap())
        };

        let mut fs = InMemoryFS::with_clock_and_log(clock, Some(writer));
        fs.set_log_dir(&log_dir);
        Self {
            fs,
            log_dir,
            _temp_dir: Some(Arc::new(temp_dir)),
        }
    }

    pub fn from_instance(
        fs: InMemoryFS,
        log_dir: &Path,
        temp_dir: Option<Arc<tempfile::TempDir>>,
    ) -> Self {
        Self {
            fs,
            log_dir: log_dir.to_path_buf(),
            _temp_dir: temp_dir,
        }
    }

    pub fn allocate_inode(&self) -> u64 {
        self.fs.next_inode.fetch_add(1, Ordering::SeqCst)
    }

    pub fn mkdir(&self, parent: u64, name: &str, mode: u32) -> Result<u64, i32> {
        appendfs::operations::dir::mkdir_core(&self.fs, parent, name, mode, 1000, 1000)
            .map(|attr| attr.ino)
    }

    pub fn create(&self, parent: u64, name: &str, mode: u32) -> Result<u64, i32> {
        appendfs::operations::read_write::create_core(&self.fs, parent, name, mode, 0, 1000, 1000)
            .map(|attr| attr.ino)
    }

    pub fn write(&self, ino: u64, offset: u64, buf: &[u8]) -> Result<usize, i32> {
        appendfs::operations::read_write::write_core(&self.fs, ino, buf, offset as i64)
    }

    pub fn read(&self, ino: u64, offset: u64, len: usize) -> Result<Vec<u8>, i32> {
        appendfs::operations::read_write::read_core(&self.fs, ino, len, offset as i64)
    }

    pub fn unlink(&self, parent: u64, name: &str) -> Result<(), i32> {
        appendfs::operations::links::unlink_core(&self.fs, parent, name)
    }

    pub fn rmdir(&self, parent: u64, name: &str) -> Result<(), i32> {
        appendfs::operations::dir::rmdir_core(&self.fs, parent, name)
    }

    /// Mirrors `operations::links::symlink`.
    pub fn symlink(&self, parent: u64, name: &str, target: &str) -> Result<u64, i32> {
        appendfs::operations::links::symlink_core(&self.fs, parent, name, target, 1000, 1000)
            .map(|attr| attr.ino)
    }

    /// Mirrors `operations::links::link` (hard links).
    pub fn link(&self, ino: u64, newparent: u64, newname: &str) -> Result<(), i32> {
        appendfs::operations::links::link_core(&self.fs, ino, newparent, newname).map(|_| ())
    }

    /// Mirrors `operations::read_write::setattr` in full: any combination of
    /// mode/uid/gid/size/atime/mtime, matching the real bitmask-of-fields semantics
    /// (size is silently ignored for Directory/Symlink, mode is silently ignored for
    /// Symlink - production has no handling code for those, and doesn't error either).
    pub fn setattr(
        &self,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<SystemTime>,
        mtime: Option<SystemTime>,
    ) -> Result<(), i32> {
        use appendfs::operations::read_write::{
            FUSE_SET_ATTR_ATIME, FUSE_SET_ATTR_GID, FUSE_SET_ATTR_MODE, FUSE_SET_ATTR_MTIME,
            FUSE_SET_ATTR_SIZE, FUSE_SET_ATTR_UID, setattr_core,
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

    /// Mirrors `operations::links::readlink`.
    pub fn readlink(&self, ino: u64) -> Result<String, i32> {
        appendfs::operations::links::readlink_core(&self.fs, ino)
    }

    /// Mirrors `operations::links::rename`.
    pub fn rename(
        &self,
        parent: u64,
        name: &str,
        newparent: u64,
        newname: &str,
    ) -> Result<(), i32> {
        appendfs::operations::links::rename_core(&self.fs, parent, name, newparent, newname)
    }

    /// Captures full snapshot of all inode metadata and file byte contents for tree parity assertions.
    /// Walks the tree from root via the same core handlers real FUSE dispatch uses
    /// (`getattr_core`/`list_dir_core`/`readlink_core`/`read_core`) instead of reading
    /// `fs.inodes` directly. Every live inode is reachable this way: nlink only stays
    /// above zero while at least one directory entry points to it, so a BFS from root
    /// visits the same complete set `fs.inodes` itself would enumerate - hardlinked
    /// inodes are just visited via more than one entry, hence the `visited` dedup.
    pub fn get_tree_snapshot(&self) -> HashMap<u64, SnapshotNode> {
        let mut snapshot = HashMap::new();
        let mut visited = std::collections::HashSet::new();
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(1u64);
        visited.insert(1u64);

        while let Some(ino) = queue.pop_front() {
            let attr = match appendfs::operations::read_write::getattr_core(&self.fs, ino) {
                Ok(attr) => attr,
                Err(_) => continue,
            };

            match attr.file_type {
                FileType::Directory => {
                    let entries =
                        appendfs::operations::dir::list_dir_core(&self.fs, ino).unwrap_or_default();
                    for (_, child_ino) in &entries {
                        if visited.insert(*child_ino) {
                            queue.push_back(*child_ino);
                        }
                    }
                    snapshot.insert(ino, SnapshotNode::Directory { attr, entries });
                }
                FileType::RegularFile => {
                    let content = self.read(ino, 0, attr.size as usize).unwrap_or_default();
                    snapshot.insert(ino, SnapshotNode::File { attr, content });
                }
                FileType::Symlink => {
                    let target = appendfs::operations::links::readlink_core(&self.fs, ino)
                        .unwrap_or_default();
                    snapshot.insert(ino, SnapshotNode::Symlink { attr, target });
                }
            }
        }

        snapshot
    }

    /// Cleanly unmounts and recovers filesystem via summary fast-load.
    pub fn clean_remount(self) -> Self {
        let log_dir = self.log_dir.clone();
        let temp_dir = self._temp_dir.clone();
        // Preserve the original instance's clock rather than defaulting to
        // SystemClock - recover_fs always constructs a fresh InMemoryFS internally
        // (SystemClock-backed), so without this override, a recovered instance would
        // silently diverge onto real wall-clock time even when the pre-crash instance
        // was using a shared/deterministic clock (e.g. for timestamp-comparison tests).
        let clock = self.fs.clock.clone();
        let _ = self.fs.sync_and_export_summary();
        drop(self);
        let mut recovered = recover_fs(&log_dir).unwrap();
        recovered.clock = clock.clone();
        let next_gen = appendfs::find_latest_generation(&log_dir) + 1;
        let start_tx = recovered.last_tx_id.load(Ordering::SeqCst) + 1;
        let writer = Arc::new(
            appendfs::LogWriter::create_with_max_size_and_start_tx(
                &log_dir,
                next_gen,
                &*clock,
                appendfs::cli::DEFAULT_MAX_LOG_SIZE,
                start_tx,
            )
            .unwrap(),
        );
        recovered.log_writer = Some(writer);
        recovered.set_log_dir(&log_dir);
        Self::from_instance(recovered, &log_dir, temp_dir)
    }

    /// Uncleanly crashes (flushes log, drops instance without summary) and recovers via log replay.
    pub fn unclean_crash(mut self) -> Self {
        let log_dir = self.log_dir.clone();
        let temp_dir = self._temp_dir.clone();
        // See clean_remount's comment - preserve the original clock across recovery.
        let clock = self.fs.clock.clone();
        let _ = self.fs.sync_log();
        self.fs.log_writer = None;
        drop(self);
        let mut recovered = recover_fs(&log_dir).unwrap();
        recovered.clock = clock.clone();
        let next_gen = appendfs::find_latest_generation(&log_dir) + 1;
        let start_tx = recovered.last_tx_id.load(Ordering::SeqCst) + 1;
        let writer = Arc::new(
            appendfs::LogWriter::create_with_max_size_and_start_tx(
                &log_dir,
                next_gen,
                &*clock,
                appendfs::cli::DEFAULT_MAX_LOG_SIZE,
                start_tx,
            )
            .unwrap(),
        );
        recovered.log_writer = Some(writer);
        recovered.set_log_dir(&log_dir);
        Self::from_instance(recovered, &log_dir, temp_dir)
    }
}

#[test]
fn test_differential_fuzzing_and_crash_recovery() {
    for seed in 1..=5 {
        println!(
            "=== RUNNING DIFFERENTIAL STRESS TEST WITH SEED {} ===",
            seed
        );
        let mut prng = SimpleRng::new(seed);

        // Shared, advanceable clock: all 4 instances (and, per clean_remount/
        // unclean_crash, their post-recovery selves) observe the exact same
        // simulated time, advanced once per step below - unlike a real wall clock,
        // this makes atime/mtime/ctime comparisons across instances exact rather
        // than flaky, so they can be checked at every checkpoint alongside content.
        let clock = AdvancingClock::new(std::time::UNIX_EPOCH + Duration::from_secs(1_700_000_000));
        let fs_baseline = TestFS::new_temp_with_clock(None, Arc::new(clock.clone()));
        let fs_micro = TestFS::new_temp_with_clock(Some(256), Arc::new(clock.clone()));
        let mut fs_remount = TestFS::new_temp_with_clock(None, Arc::new(clock.clone()));
        let mut fs_crash = TestFS::new_temp_with_clock(None, Arc::new(clock.clone()));

        // Keep track of created subdirectories (inode IDs) to perform operations on
        let mut active_dirs = vec![1u64];
        let mut active_files = Vec::<u64>::new();

        // Crash/remount checkpoints land at random steps rather than a fixed cadence,
        // so recovery gets exercised against varied in-flight-batch states (whatever
        // happened to be staged/flushed at that particular random moment) instead of
        // always the same handful of points every run. Drawn up front, before the step
        // loop's own op selection, so the two random streams don't interleave in a way
        // that's confusing to reason about. Step 200 is always included so the final
        // state is guaranteed to get validated even if no random draw lands there.
        let num_random_checkpoints = 3;
        let mut checkpoints: Vec<usize> = (0..num_random_checkpoints)
            .map(|_| prng.gen_range(1, 199))
            .collect();
        checkpoints.push(200);
        checkpoints.sort_unstable();
        checkpoints.dedup();
        println!("    checkpoints for seed {}: {:?}", seed, checkpoints);

        for step in 1..=200 {
            // Advance before each step so consecutive operations land at genuinely
            // different timestamps - otherwise every ctime/mtime/atime in the whole
            // run would coincide, and a missing timestamp update would be
            // indistinguishable from a correct one.
            clock.advance(Duration::from_secs(1));
            let op_choice = prng.gen_range(0, 11);
            match op_choice {
                0 => {
                    // Create directory
                    let parent = active_dirs[prng.gen_range(0, active_dirs.len() - 1)];
                    let name = format!("dir_s{}_step{}", seed, step);
                    let res1 = fs_baseline.mkdir(parent, &name, 0o755);
                    let res2 = fs_micro.mkdir(parent, &name, 0o755);
                    let res3 = fs_remount.mkdir(parent, &name, 0o755);
                    let res4 = fs_crash.mkdir(parent, &name, 0o755);

                    assert_eq!(res1, res2);
                    assert_eq!(res1, res3);
                    assert_eq!(res1, res4);

                    if let Ok(ino) = res1 {
                        active_dirs.push(ino);
                    }
                }
                1 => {
                    // Create file
                    let parent = active_dirs[prng.gen_range(0, active_dirs.len() - 1)];
                    let name = format!("file_s{}_step{}.txt", seed, step);
                    let res1 = fs_baseline.create(parent, &name, 0o644);
                    let res2 = fs_micro.create(parent, &name, 0o644);
                    let res3 = fs_remount.create(parent, &name, 0o644);
                    let res4 = fs_crash.create(parent, &name, 0o644);

                    assert_eq!(res1, res2);
                    assert_eq!(res1, res3);
                    assert_eq!(res1, res4);

                    if let Ok(ino) = res1 {
                        active_files.push(ino);
                    }
                }
                2 => {
                    // Write to file
                    if !active_files.is_empty() {
                        let ino = active_files[prng.gen_range(0, active_files.len() - 1)];
                        let offset = (prng.gen_range(0, 10) * 16) as u64;
                        let payload_len = prng.gen_range(16, 256);
                        let payload: Vec<u8> =
                            (0..payload_len).map(|i| ((step + i) % 256) as u8).collect();

                        let res1 = fs_baseline.write(ino, offset, &payload);
                        let res2 = fs_micro.write(ino, offset, &payload);
                        let res3 = fs_remount.write(ino, offset, &payload);
                        let res4 = fs_crash.write(ino, offset, &payload);

                        assert_eq!(res1, res2);
                        assert_eq!(res1, res3);
                        assert_eq!(res1, res4);
                    }
                }
                3 => {
                    // Unlink file
                    if !active_files.is_empty() && prng.gen_range(0, 3) == 0 {
                        let idx = prng.gen_range(0, active_files.len() - 1);
                        let ino = active_files[idx];
                        // Unlink requires parent & name. Find name in root/dirs.
                        let (parent_to_unlink, name_to_unlink) = {
                            if let Some(p) = appendfs::fs::find_parent_inode(&fs_baseline.fs, ino) {
                                let entries = fs_baseline.fs.list_directory(p).unwrap_or_default();
                                let name = entries
                                    .into_iter()
                                    .find(|(_, child)| *child == ino)
                                    .map(|(n, _)| n);
                                (p, name)
                            } else {
                                (1u64, None)
                            }
                        };

                        if let Some(name) = name_to_unlink {
                            let res1 = fs_baseline.unlink(parent_to_unlink, &name);
                            let res2 = fs_micro.unlink(parent_to_unlink, &name);
                            let res3 = fs_remount.unlink(parent_to_unlink, &name);
                            let res4 = fs_crash.unlink(parent_to_unlink, &name);

                            assert_eq!(res1, res2);
                            assert_eq!(res1, res3);
                            assert_eq!(res1, res4);

                            if res1.is_ok() {
                                let still_alive = fs_baseline.fs.get_attr(ino).is_some();
                                if !still_alive {
                                    active_files.remove(idx);
                                }
                            }
                        }
                    }
                }
                4 => {
                    // Rename: move or overwrite between existing active files/dirs (excluding root).
                    // Biased towards colliding with an existing destination name so the
                    // overwrite-and-reclaim path (which crash recovery is known to replay
                    // incorrectly) gets exercised, not just plain moves.
                    let mut renameable: Vec<u64> =
                        active_dirs.iter().cloned().filter(|&i| i != 1).collect();
                    renameable.extend(active_files.iter().cloned());

                    if !renameable.is_empty() {
                        let src_ino = renameable[prng.gen_range(0, renameable.len() - 1)];

                        let src_loc = {
                            if let Some(p) =
                                appendfs::fs::find_parent_inode(&fs_baseline.fs, src_ino)
                            {
                                let entries = fs_baseline.fs.list_directory(p).unwrap_or_default();
                                entries
                                    .into_iter()
                                    .find(|(_, child)| *child == src_ino)
                                    .map(|(n, _)| (p, n))
                            } else {
                                None
                            }
                        };

                        if let Some((src_parent, src_name)) = src_loc {
                            let dest_parent = active_dirs[prng.gen_range(0, active_dirs.len() - 1)];

                            // Pick an existing entry in dest_parent to collide with. When
                            // dest_parent == src_parent and this picks the source's own entry,
                            // that exercises the literal self-rename (name == newname) no-op path.
                            let existing_name = {
                                let entries = fs_baseline
                                    .fs
                                    .list_directory(dest_parent)
                                    .unwrap_or_default();
                                if entries.is_empty() {
                                    None
                                } else {
                                    let idx = prng.gen_range(0, entries.len() - 1);
                                    Some(entries[idx].0.clone())
                                }
                            };

                            let dest_name = if prng.gen_range(0, 1) == 0 {
                                existing_name
                                    .unwrap_or_else(|| format!("renamed_s{}_step{}", seed, step))
                            } else {
                                format!("renamed_s{}_step{}", seed, step)
                            };

                            let res1 =
                                fs_baseline.rename(src_parent, &src_name, dest_parent, &dest_name);
                            let res2 =
                                fs_micro.rename(src_parent, &src_name, dest_parent, &dest_name);
                            let res3 =
                                fs_remount.rename(src_parent, &src_name, dest_parent, &dest_name);
                            let res4 =
                                fs_crash.rename(src_parent, &src_name, dest_parent, &dest_name);

                            assert_eq!(res1, res2, "rename result mismatch (baseline vs micro)");
                            assert_eq!(res1, res3, "rename result mismatch (baseline vs remount)");
                            assert_eq!(res1, res4, "rename result mismatch (baseline vs crash)");
                        }
                    }
                }
                5 => {
                    // Rmdir: pick a random non-root directory; ENOTEMPTY is a valid,
                    // consistently-reproduced outcome, not a skip condition.
                    let candidates: Vec<u64> =
                        active_dirs.iter().cloned().filter(|&i| i != 1).collect();
                    if !candidates.is_empty() {
                        let idx = prng.gen_range(0, candidates.len() - 1);
                        let ino = candidates[idx];

                        let loc = {
                            if let Some(p) = appendfs::fs::find_parent_inode(&fs_baseline.fs, ino) {
                                let entries = fs_baseline.fs.list_directory(p).unwrap_or_default();
                                entries
                                    .into_iter()
                                    .find(|(_, child)| *child == ino)
                                    .map(|(n, _)| (p, n))
                            } else {
                                None
                            }
                        };

                        if let Some((parent, name)) = loc {
                            let res1 = fs_baseline.rmdir(parent, &name);
                            let res2 = fs_micro.rmdir(parent, &name);
                            let res3 = fs_remount.rmdir(parent, &name);
                            let res4 = fs_crash.rmdir(parent, &name);

                            assert_eq!(res1, res2, "rmdir result mismatch (baseline vs micro)");
                            assert_eq!(res1, res3, "rmdir result mismatch (baseline vs remount)");
                            assert_eq!(res1, res4, "rmdir result mismatch (baseline vs crash)");

                            if res1.is_ok() {
                                active_dirs.retain(|&i| i != ino);
                            }
                        }
                    }
                }
                6 => {
                    // Symlink
                    let parent = active_dirs[prng.gen_range(0, active_dirs.len() - 1)];
                    let name = format!("symlink_s{}_step{}", seed, step);
                    let target = format!("target_s{}_step{}", seed, step);

                    let res1 = fs_baseline.symlink(parent, &name, &target);
                    let res2 = fs_micro.symlink(parent, &name, &target);
                    let res3 = fs_remount.symlink(parent, &name, &target);
                    let res4 = fs_crash.symlink(parent, &name, &target);

                    assert_eq!(res1, res2, "symlink result mismatch (baseline vs micro)");
                    assert_eq!(res1, res3, "symlink result mismatch (baseline vs remount)");
                    assert_eq!(res1, res4, "symlink result mismatch (baseline vs crash)");

                    if let Ok(ino) = res1 {
                        active_files.push(ino);
                    }
                }
                7 => {
                    // Link: add a second name for an existing file/symlink.
                    if !active_files.is_empty() {
                        let ino = active_files[prng.gen_range(0, active_files.len() - 1)];
                        let newparent = active_dirs[prng.gen_range(0, active_dirs.len() - 1)];
                        let newname = format!("hardlink_s{}_step{}", seed, step);

                        let res1 = fs_baseline.link(ino, newparent, &newname);
                        let res2 = fs_micro.link(ino, newparent, &newname);
                        let res3 = fs_remount.link(ino, newparent, &newname);
                        let res4 = fs_crash.link(ino, newparent, &newname);

                        assert_eq!(res1, res2, "link result mismatch (baseline vs micro)");
                        assert_eq!(res1, res3, "link result mismatch (baseline vs remount)");
                        assert_eq!(res1, res4, "link result mismatch (baseline vs crash)");
                    }
                }
                8 => {
                    // Setattr: mode/uid/gid/size in a random combination, matching
                    // real usage (a single call can set any subset). Size exercises
                    // both shrink and grow, including growing back past a size that
                    // was previously shrunk away. atime/mtime deliberately excluded
                    // here - exact-timestamp comparison across 4 independently-timed
                    // instances using a real wall clock is inherently flaky; see
                    // test_setattr_times_survive_crash_recovery for that path instead.
                    if !active_files.is_empty() {
                        let ino = active_files[prng.gen_range(0, active_files.len() - 1)];

                        let mut mode = None;
                        let mut uid = None;
                        let mut gid = None;
                        let mut size = None;
                        if prng.gen_range(0, 1) == 0 {
                            mode = Some(0o600 + prng.gen_range(0, 0o177) as u32);
                        }
                        if prng.gen_range(0, 1) == 0 {
                            uid = Some(prng.gen_range(1000, 2000) as u32);
                        }
                        if prng.gen_range(0, 1) == 0 {
                            gid = Some(prng.gen_range(1000, 2000) as u32);
                        }
                        if prng.gen_range(0, 1) == 0 {
                            size = Some(prng.gen_range(0, 300) as u64);
                        }
                        // Never let this degenerate into a pure no-op call.
                        if mode.is_none() && uid.is_none() && gid.is_none() && size.is_none() {
                            size = Some(prng.gen_range(0, 300) as u64);
                        }

                        let res1 = fs_baseline.setattr(ino, mode, uid, gid, size, None, None);
                        let res2 = fs_micro.setattr(ino, mode, uid, gid, size, None, None);
                        let res3 = fs_remount.setattr(ino, mode, uid, gid, size, None, None);
                        let res4 = fs_crash.setattr(ino, mode, uid, gid, size, None, None);

                        assert_eq!(res1, res2, "setattr result mismatch (baseline vs micro)");
                        assert_eq!(res1, res3, "setattr result mismatch (baseline vs remount)");
                        assert_eq!(res1, res4, "setattr result mismatch (baseline vs crash)");
                    }
                }
                9 => {
                    // Readlink: non-symlink targets consistently return EINVAL across
                    // instances, which is still valid coverage, not just a skip.
                    if !active_files.is_empty() {
                        let ino = active_files[prng.gen_range(0, active_files.len() - 1)];

                        let res1 = fs_baseline.readlink(ino);
                        let res2 = fs_micro.readlink(ino);
                        let res3 = fs_remount.readlink(ino);
                        let res4 = fs_crash.readlink(ino);

                        assert_eq!(res1, res2, "readlink result mismatch (baseline vs micro)");
                        assert_eq!(res1, res3, "readlink result mismatch (baseline vs remount)");
                        assert_eq!(res1, res4, "readlink result mismatch (baseline vs crash)");
                    }
                }
                _ => {
                    // Read file & verify consistency across active instances
                    if !active_files.is_empty() {
                        let ino = active_files[prng.gen_range(0, active_files.len() - 1)];
                        let res1 = fs_baseline.read(ino, 0, 4096);
                        let res2 = fs_micro.read(ino, 0, 4096);
                        let res3 = fs_remount.read(ino, 0, 4096);
                        let res4 = fs_crash.read(ino, 0, 4096);

                        assert_eq!(res1, res2);
                        assert_eq!(res1, res3);
                        assert_eq!(res1, res4);
                    }
                }
            }

            // At each randomly-drawn checkpoint step, simulate clean remount & unclean
            // crash recovery.
            if checkpoints.contains(&step) {
                fs_remount = fs_remount.clean_remount();
                fs_crash = fs_crash.unclean_crash();

                // Assert complete tree & content parity across all 4 instances
                let snap_baseline = fs_baseline.get_tree_snapshot();
                let snap_micro = fs_micro.get_tree_snapshot();
                let snap_remount = fs_remount.get_tree_snapshot();
                let snap_crash = fs_crash.get_tree_snapshot();

                assert_eq!(snap_baseline.len(), snap_micro.len());
                assert_eq!(snap_baseline.len(), snap_remount.len());
                assert_eq!(snap_baseline.len(), snap_crash.len());

                for (ino, snap) in &snap_baseline {
                    let micro_snap = snap_micro.get(ino).expect("inode missing in micro");
                    let remount_snap = snap_remount.get(ino).expect("inode missing in remount");
                    let crash_snap = snap_crash.get(ino).expect("inode missing in crash");

                    match (snap, micro_snap, remount_snap, crash_snap) {
                        (
                            SnapshotNode::Directory {
                                attr: a1,
                                entries: e1,
                            },
                            SnapshotNode::Directory {
                                attr: a2,
                                entries: e2,
                            },
                            SnapshotNode::Directory {
                                attr: a3,
                                entries: e3,
                            },
                            SnapshotNode::Directory {
                                attr: a4,
                                entries: e4,
                            },
                        ) => {
                            // Exact Vec order, not just set-equality: live rename does
                            // an in-place update for same-parent renames (preserving
                            // the entry's position), and recovery replay must
                            // reproduce that exactly, not just the resulting set of
                            // names - a real, once-actual bug (recovery used to
                            // unconditionally remove+push even for same-parent
                            // renames) was invisible to a sorted comparison and only
                            // surfaced via byte-for-byte .summary comparison - see
                            // test_summary_export_is_deterministic.
                            assert_eq!(
                                e1, e2,
                                "Directory entries mismatch at inode {} (baseline vs micro)",
                                ino
                            );
                            assert_eq!(
                                e1, e3,
                                "Directory entries mismatch at inode {} (baseline vs remount)",
                                ino
                            );
                            assert_eq!(
                                e1, e4,
                                "Directory entries mismatch at inode {} (baseline vs crash)",
                                ino
                            );
                            assert_eq!(
                                (a1.atime, a1.mtime, a1.ctime),
                                (a2.atime, a2.mtime, a2.ctime),
                                "Directory atime/mtime/ctime mismatch at inode {} (baseline vs micro)",
                                ino
                            );
                            assert_eq!(
                                (a1.atime, a1.mtime, a1.ctime),
                                (a3.atime, a3.mtime, a3.ctime),
                                "Directory atime/mtime/ctime mismatch at inode {} (baseline vs remount)",
                                ino
                            );
                            // atime deliberately excluded here: reads bump atime in
                            // memory but are never logged (logging every read would
                            // defeat the point of an append-only log), so an
                            // atime-from-read is not crash-durable - only mtime/ctime,
                            // which are always backed by a logged op, are.
                            assert_eq!(
                                (a1.mtime, a1.ctime),
                                (a4.mtime, a4.ctime),
                                "Directory mtime/ctime mismatch at inode {} (baseline vs crash)",
                                ino
                            );
                        }
                        (
                            SnapshotNode::File {
                                attr: a1,
                                content: c1,
                            },
                            SnapshotNode::File {
                                attr: a2,
                                content: c2,
                            },
                            SnapshotNode::File {
                                attr: a3,
                                content: c3,
                            },
                            SnapshotNode::File {
                                attr: a4,
                                content: c4,
                            },
                        ) => {
                            assert_eq!(
                                c1, c2,
                                "Content mismatch at inode {} (baseline vs micro)",
                                ino
                            );
                            assert_eq!(
                                c1, c3,
                                "Content mismatch at inode {} (baseline vs remount)",
                                ino
                            );
                            assert_eq!(
                                c1, c4,
                                "Content mismatch at inode {} (baseline vs crash)",
                                ino
                            );
                            assert_eq!(
                                a1.size, a2.size,
                                "File size mismatch at inode {} (baseline vs micro)",
                                ino
                            );
                            assert_eq!(
                                a1.size, a3.size,
                                "File size mismatch at inode {} (baseline vs remount)",
                                ino
                            );
                            assert_eq!(
                                a1.size, a4.size,
                                "File size mismatch at inode {} (baseline vs crash)",
                                ino
                            );
                            assert_eq!(
                                a1.nlink, a2.nlink,
                                "File nlink mismatch at inode {} (baseline vs micro)",
                                ino
                            );
                            assert_eq!(
                                a1.nlink, a3.nlink,
                                "File nlink mismatch at inode {} (baseline vs remount)",
                                ino
                            );
                            assert_eq!(
                                a1.nlink, a4.nlink,
                                "File nlink mismatch at inode {} (baseline vs crash)",
                                ino
                            );
                            assert_eq!(
                                (a1.perm, a1.uid, a1.gid),
                                (a2.perm, a2.uid, a2.gid),
                                "File perm/uid/gid mismatch at inode {} (baseline vs micro)",
                                ino
                            );
                            assert_eq!(
                                (a1.perm, a1.uid, a1.gid),
                                (a3.perm, a3.uid, a3.gid),
                                "File perm/uid/gid mismatch at inode {} (baseline vs remount)",
                                ino
                            );
                            assert_eq!(
                                (a1.perm, a1.uid, a1.gid),
                                (a4.perm, a4.uid, a4.gid),
                                "File perm/uid/gid mismatch at inode {} (baseline vs crash)",
                                ino
                            );
                            assert_eq!(
                                (a1.atime, a1.mtime, a1.ctime),
                                (a2.atime, a2.mtime, a2.ctime),
                                "File atime/mtime/ctime mismatch at inode {} (baseline vs micro)",
                                ino
                            );
                            assert_eq!(
                                (a1.atime, a1.mtime, a1.ctime),
                                (a3.atime, a3.mtime, a3.ctime),
                                "File atime/mtime/ctime mismatch at inode {} (baseline vs remount)",
                                ino
                            );
                            // atime deliberately excluded - see the Directory arm's
                            // comment above.
                            assert_eq!(
                                (a1.mtime, a1.ctime),
                                (a4.mtime, a4.ctime),
                                "File mtime/ctime mismatch at inode {} (baseline vs crash)",
                                ino
                            );
                        }
                        (
                            SnapshotNode::Symlink {
                                attr: a1,
                                target: t1,
                            },
                            SnapshotNode::Symlink {
                                attr: a2,
                                target: t2,
                            },
                            SnapshotNode::Symlink {
                                attr: a3,
                                target: t3,
                            },
                            SnapshotNode::Symlink {
                                attr: a4,
                                target: t4,
                            },
                        ) => {
                            assert_eq!(
                                t1, t2,
                                "Symlink target mismatch at inode {} (baseline vs micro)",
                                ino
                            );
                            assert_eq!(
                                t1, t3,
                                "Symlink target mismatch at inode {} (baseline vs remount)",
                                ino
                            );
                            assert_eq!(
                                t1, t4,
                                "Symlink target mismatch at inode {} (baseline vs crash)",
                                ino
                            );
                            assert_eq!(
                                a1.nlink, a2.nlink,
                                "Symlink nlink mismatch at inode {} (baseline vs micro)",
                                ino
                            );
                            assert_eq!(
                                a1.nlink, a3.nlink,
                                "Symlink nlink mismatch at inode {} (baseline vs remount)",
                                ino
                            );
                            assert_eq!(
                                a1.nlink, a4.nlink,
                                "Symlink nlink mismatch at inode {} (baseline vs crash)",
                                ino
                            );
                            assert_eq!(
                                (a1.uid, a1.gid),
                                (a2.uid, a2.gid),
                                "Symlink uid/gid mismatch at inode {} (baseline vs micro)",
                                ino
                            );
                            assert_eq!(
                                (a1.uid, a1.gid),
                                (a3.uid, a3.gid),
                                "Symlink uid/gid mismatch at inode {} (baseline vs remount)",
                                ino
                            );
                            assert_eq!(
                                (a1.uid, a1.gid),
                                (a4.uid, a4.gid),
                                "Symlink uid/gid mismatch at inode {} (baseline vs crash)",
                                ino
                            );
                            assert_eq!(
                                (a1.atime, a1.mtime, a1.ctime),
                                (a2.atime, a2.mtime, a2.ctime),
                                "Symlink atime/mtime/ctime mismatch at inode {} (baseline vs micro)",
                                ino
                            );
                            assert_eq!(
                                (a1.atime, a1.mtime, a1.ctime),
                                (a3.atime, a3.mtime, a3.ctime),
                                "Symlink atime/mtime/ctime mismatch at inode {} (baseline vs remount)",
                                ino
                            );
                            // atime deliberately excluded - see the Directory arm's
                            // comment above.
                            assert_eq!(
                                (a1.mtime, a1.ctime),
                                (a4.mtime, a4.ctime),
                                "Symlink mtime/ctime mismatch at inode {} (baseline vs crash)",
                                ino
                            );
                        }
                        _ => panic!("Node type mismatch for inode {}", ino),
                    }
                }
            }
        }
    }
}

#[test]
fn test_crash_mid_flush_discards_uncommitted_trailing_batch() {
    let dir = tempfile::tempdir().unwrap();
    let clock = SystemClock;
    let writer = LogWriter::create(dir.path(), 1, &clock).unwrap();

    // Batch 1: mkdir "committed_dir" under root (ino 1), properly committed with a
    // trailing BatchCommit - simulates a flush() call that completed successfully.
    let mkdir_payload = MkdirPayload {
        parent: 1,
        name: "committed_dir".to_string(),
        mode: 0o755,
        uid: 1000,
        gid: 1000,
        created_at: (0, 0),
    };
    let bytes = bincode::serialize(&mkdir_payload).unwrap();
    writer.append_record(OpCode::Mkdir, 2, &bytes).unwrap();
    writer.emit_batch_commit(1, &clock).unwrap();

    // Batch 2: create "should_not_exist.txt" inside root, but WITHOUT ever writing its
    // BatchCommit trailer - simulates a crash exactly mid-flush, after the record was
    // physically appended but before the batch was confirmed complete.
    let create_payload = CreatePayload {
        parent: 1,
        name: "should_not_exist.txt".to_string(),
        mode: 0o644,
        uid: 1000,
        gid: 1000,
        created_at: (0, 0),
    };
    let bytes = bincode::serialize(&create_payload).unwrap();
    writer.append_record(OpCode::Create, 3, &bytes).unwrap();
    // Deliberately no emit_batch_commit() call here - this is the crash point.

    writer.sync().unwrap();
    drop(writer);

    let recovered = recover_fs(dir.path()).unwrap();
    let map = recovered.snapshot_all();

    let root = map.get(&1).unwrap();
    let entries = match unsafe { root.read() } {
        Node::Directory { entries, .. } => entries.clone(),
        _ => panic!("root is not a directory"),
    };

    assert!(
        entries.iter().any(|(name, _)| name == "committed_dir"),
        "committed batch's directory should have survived recovery"
    );
    assert!(
        !entries
            .iter()
            .any(|(name, _)| name == "should_not_exist.txt"),
        "uncommitted trailing batch should have been discarded, not partially applied"
    );
    assert!(
        !map.contains_key(&3),
        "the uncommitted create's inode should not exist in recovered state at all"
    );
}

#[test]
fn test_crash_mid_flush_with_record_count_mismatch_fails_recovery() {
    // Exercises the defensive record_count cross-check: since every individual
    // record's own checksum already passed by the time recovery reaches a
    // BatchCommit, a record_count that still doesn't match what was actually
    // buffered can only mean a bug in the writer - not an expected crash-recovery
    // scenario - so this must hard-fail recovery entirely, not be silently discarded.
    let dir = tempfile::tempdir().unwrap();
    let clock = SystemClock;
    let writer = LogWriter::create(dir.path(), 1, &clock).unwrap();

    let create_payload = CreatePayload {
        parent: 1,
        name: "orphan.txt".to_string(),
        mode: 0o644,
        uid: 1000,
        gid: 1000,
        created_at: (0, 0),
    };
    let bytes = bincode::serialize(&create_payload).unwrap();
    writer.append_record(OpCode::Create, 2, &bytes).unwrap();
    // Claim 2 records preceded this trailer, when only 1 actually did.
    writer.emit_batch_commit(2, &clock).unwrap();
    writer.sync().unwrap();
    drop(writer);

    let result = recover_fs(dir.path());
    assert!(
        result.is_err(),
        "a BatchCommit with a mismatched record_count must fail recovery hard"
    );
}

#[test]
fn test_bitrot_in_committed_record_fails_recovery_hard() {
    // End-to-end: a fully committed, previously-valid batch whose payload bytes get
    // corrupted on disk afterwards (simulating real bitrot, not a torn write) must
    // cause recover_fs to refuse to mount, not silently reconstruct wrong state.
    let dir = tempfile::tempdir().unwrap();
    let clock = SystemClock;
    let writer = LogWriter::create(dir.path(), 1, &clock).unwrap();

    let create_payload = CreatePayload {
        parent: 1,
        name: "important.txt".to_string(),
        mode: 0o644,
        uid: 1000,
        gid: 1000,
        created_at: (0, 0),
    };
    let bytes = bincode::serialize(&create_payload).unwrap();
    writer.append_record(OpCode::Create, 2, &bytes).unwrap();
    writer.emit_batch_commit(1, &clock).unwrap();
    writer.sync().unwrap();
    let path = writer.path();
    drop(writer);

    // Sanity check: recovery succeeds and sees the file before any corruption.
    let recovered = recover_fs(dir.path()).unwrap();
    assert!(recovered.get_attr(2).is_some());
    drop(recovered);

    // Flip one bit inside the Create record's payload region, well past the file
    // header (24B) and this record's header (25B) - simulating a bitrotted byte in
    // otherwise-intact, previously-committed data.
    use std::io::{Read, Seek, SeekFrom, Write};
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let corrupt_offset = 24 + 25 + 2; // a few bytes into the CreatePayload
    file.seek(SeekFrom::Start(corrupt_offset)).unwrap();
    let mut byte = [0u8; 1];
    file.read_exact(&mut byte).unwrap();
    byte[0] ^= 0xFF;
    file.seek(SeekFrom::Start(corrupt_offset)).unwrap();
    file.write_all(&byte).unwrap();
    drop(file);

    let result = recover_fs(dir.path());
    assert!(
        result.is_err(),
        "bitrot in a previously-committed record must be detected and hard-fail recovery, not be silently applied"
    );
}

#[test]
fn test_truncate_shrink_then_grow_repro() {
    // Targeted repro: write full content, shrink via truncate, write a small amount,
    // then grow back past the shrink point without covering it with a new write -
    // POSIX requires that newly-exposed region to read as zeros (a hole), not
    // whatever was physically there before the shrink.
    let fs = TestFS::new_temp(None);
    let ino = fs.create(1, "f.txt", 0o644).unwrap();

    let full: Vec<u8> = (0..100u32).map(|i| (i % 256) as u8).collect();
    fs.write(ino, 0, &full).unwrap();
    fs.setattr(ino, None, None, None, Some(50), None, None)
        .unwrap();
    fs.write(ino, 0, b"XY").unwrap();
    fs.setattr(ino, None, None, None, Some(80), None, None)
        .unwrap(); // grow back past the shrink point at 50

    let content = fs.read(ino, 0, 80).unwrap();
    // Bytes [50..80) were "deleted" by the truncate to 50 and never rewritten -
    // POSIX says they must read as zero.
    assert!(
        content[50..80].iter().all(|&b| b == 0),
        "expected zeros in the newly-grown region [50,80), got {:?}",
        &content[50..80]
    );
}

#[test]
fn test_partial_overwrite_read_repro() {
    // Isolates write-overlap handling from truncate entirely: write 100 bytes, then
    // overwrite just the first 2, then verify the untouched tail [2,100) still reads
    // back as the original content.
    let fs = TestFS::new_temp(None);
    let ino = fs.create(1, "f.txt", 0o644).unwrap();

    let full: Vec<u8> = (0..100u32).map(|i| (i % 256) as u8).collect();
    fs.write(ino, 0, &full).unwrap();
    fs.write(ino, 0, b"XY").unwrap();

    let content = fs.read(ino, 0, 100).unwrap();
    assert_eq!(&content[0..2], b"XY");
    assert_eq!(
        &content[2..100],
        &full[2..100],
        "tail bytes after partial overwrite changed unexpectedly"
    );
}

#[test]
fn test_partial_read_does_not_corrupt_subsequent_reads() {
    // RangeMap::query() is documented (and used throughout read()) as read-only, but
    // if it internally clones+trims via a value type whose clone() shares mutable
    // state (SharedExtentState), a PARTIAL read can permanently corrupt the stored
    // extent as a side effect - subsequent, unrelated reads would then see wrong data.
    let fs = TestFS::new_temp(None);
    let ino = fs.create(1, "f.txt", 0o644).unwrap();

    let full: Vec<u8> = (0..100u32).map(|i| (i % 256) as u8).collect();
    fs.write(ino, 0, &full).unwrap();

    // A partial read, not touching the entry's own boundaries at either end.
    let partial = fs.read(ino, 10, 20).unwrap();
    assert_eq!(&partial[..], &full[10..30]);

    // A subsequent FULL read must still return the original, untouched content -
    // the earlier partial read must not have mutated anything.
    let full_readback = fs.read(ino, 0, 100).unwrap();
    assert_eq!(
        full_readback, full,
        "a prior partial read corrupted subsequent full-file reads"
    );
}

#[test]
fn test_setattr_times_survive_crash_recovery() {
    // setattr's atime/mtime handling used to update the live node but never populate
    // SetattrPayload - meaning those changes were never durably logged at all, and an
    // unclean crash (raw log replay, no summary) would silently lose them. Uses a
    // MockClock so timestamps compare exactly rather than fighting a real wall clock.
    let fixed_atime = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
    let fixed_mtime = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_100);
    let clock: Arc<dyn Clock> = Arc::new(MockClock(fixed_atime));

    let fs = TestFS::new_temp_with_clock(None, clock);
    let ino = fs.create(1, "f.txt", 0o644).unwrap();
    fs.setattr(
        ino,
        None,
        None,
        None,
        None,
        Some(fixed_atime),
        Some(fixed_mtime),
    )
    .unwrap();

    let fs = fs.unclean_crash();

    let attr = fs.fs.get_attr(ino).unwrap();
    assert_eq!(
        attr.atime, fixed_atime,
        "atime did not survive crash recovery"
    );
    assert_eq!(
        attr.mtime, fixed_mtime,
        "mtime did not survive crash recovery"
    );
}

#[test]
fn test_write_mtime_survives_crash_recovery() {
    // Isolates Write's op_time end-to-end: two writes, an intervening setattr that
    // touches only ctime, then an unclean crash - mtime must reflect the *last write*,
    // not the create time or the setattr's op_time.
    let start = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
    let clock = AdvancingClock::new(start);
    let fs = TestFS::new_temp_with_clock(None, Arc::new(clock.clone()));

    let ino = fs.create(1, "f.txt", 0o644).unwrap(); // t=1_700_000_000
    clock.advance(Duration::from_secs(10));
    fs.write(ino, 0, b"hello").unwrap(); // t=1_700_000_010
    clock.advance(Duration::from_secs(10));
    fs.write(ino, 100, b"world").unwrap(); // t=1_700_000_020 - disjoint range, no elision
    clock.advance(Duration::from_secs(10));
    fs.setattr(ino, Some(0o600), None, None, None, None, None)
        .unwrap(); // t=1_700_000_030 - ctime only

    let expected_mtime = start + Duration::from_secs(20);
    let expected_ctime = start + Duration::from_secs(30);

    let fs = fs.unclean_crash();

    let attr = fs.fs.get_attr(ino).unwrap();
    assert_eq!(
        attr.mtime, expected_mtime,
        "mtime did not survive crash recovery"
    );
    assert_eq!(
        attr.ctime, expected_ctime,
        "ctime did not survive crash recovery"
    );
}

#[test]
fn test_setattr_size_change_updates_mtime_and_survives_crash_recovery() {
    // setattr's SIZE branch is the one to_set bit that (per POSIX truncate semantics)
    // touches mtime as well as ctime, unlike mode/uid/gid, which only ever touch
    // ctime. Recovery's replay used to apply op_time to ctime uniformly and never to
    // mtime at all, so a crash right after a truncate would resurrect the file with a
    // stale mtime from whenever it was created/last written, not from the truncate.
    let start = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
    let clock = AdvancingClock::new(start);
    let fs = TestFS::new_temp_with_clock(None, Arc::new(clock.clone()));

    let ino = fs.create(1, "f.txt", 0o644).unwrap(); // t=1_700_000_000
    clock.advance(Duration::from_secs(10));
    fs.write(ino, 0, b"hello world").unwrap(); // t=1_700_000_010
    clock.advance(Duration::from_secs(10));
    // mode-only setattr: touches ctime, must NOT touch mtime.
    fs.setattr(ino, Some(0o600), None, None, None, None, None)
        .unwrap(); // t=1_700_000_020
    clock.advance(Duration::from_secs(10));
    // size-only setattr (truncate): must touch BOTH mtime and ctime.
    fs.setattr(ino, None, None, None, Some(5), None, None)
        .unwrap(); // t=1_700_000_030

    let expected_mtime = start + Duration::from_secs(30);
    let expected_ctime = start + Duration::from_secs(30);

    let fs = fs.unclean_crash();

    let attr = fs.fs.get_attr(ino).unwrap();
    assert_eq!(attr.size, 5, "size did not survive crash recovery");
    assert_eq!(
        attr.mtime, expected_mtime,
        "mtime should reflect the truncate, not create/write time"
    );
    assert_eq!(
        attr.ctime, expected_ctime,
        "ctime did not survive crash recovery"
    );
}

/// One tracked (parent, name, inode) entry, for `test_summary_export_is_deterministic`'s
/// own scratch bookkeeping - deliberately independent of `fs.inodes`, so the test picks
/// valid random targets without reaching into the filesystem's internals.
struct TrackedEntry {
    parent: u64,
    name: String,
    ino: u64,
    is_dir: bool,
}

#[test]
fn test_summary_export_is_deterministic() {
    // export_summary had two independent sources of nondeterminism: (1) its data
    // section iterated fs.inodes (a HashMap) directly instead of sorting like the index
    // section already did, so two summaries capturing identical filesystem state could
    // still land with inode records in a different physical order; (2) atime bumped by
    // plain reads is never logged, so a freshly-replayed instance has no way to
    // reconstruct it. This test builds a filesystem with atime tracking disabled (so
    // atime is fully log-derived, like every other field), exports its summary, then
    // reprocesses just the raw .log files from scratch (ignoring any summary shortcut)
    // and asserts the two summaries are byte-for-byte identical.
    for seed in 1..=5 {
        let mut prng = SimpleRng::new(seed);
        let start = std::time::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let clock = AdvancingClock::new(start);
        let mut fs = TestFS::new_temp_with_clock(None, Arc::new(clock.clone()));
        fs.fs.track_atime = false;

        let mut entries: Vec<TrackedEntry> = Vec::new();
        let mut dirs = vec![1u64];
        let mut files = Vec::<u64>::new(); // files and symlinks - anything read/write/link-able

        for step in 1..=150usize {
            clock.advance(Duration::from_secs(1));
            match prng.gen_range(0, 8) {
                0 => {
                    let parent = dirs[prng.gen_range(0, dirs.len() - 1)];
                    let name = format!("dir_{}_{}", seed, step);
                    if let Ok(ino) = fs.mkdir(parent, &name, 0o755) {
                        dirs.push(ino);
                        entries.push(TrackedEntry {
                            parent,
                            name,
                            ino,
                            is_dir: true,
                        });
                    }
                }
                1 => {
                    let parent = dirs[prng.gen_range(0, dirs.len() - 1)];
                    let name = format!("file_{}_{}.txt", seed, step);
                    if let Ok(ino) = fs.create(parent, &name, 0o644) {
                        files.push(ino);
                        entries.push(TrackedEntry {
                            parent,
                            name,
                            ino,
                            is_dir: false,
                        });
                    }
                }
                2 => {
                    if !files.is_empty() {
                        let ino = files[prng.gen_range(0, files.len() - 1)];
                        let offset = (prng.gen_range(0, 10) * 16) as u64;
                        let len = prng.gen_range(16, 128);
                        let payload: Vec<u8> = (0..len).map(|i| ((step + i) % 256) as u8).collect();
                        let _ = fs.write(ino, offset, &payload);
                    }
                }
                3 => {
                    if !files.is_empty() {
                        let ino = files[prng.gen_range(0, files.len() - 1)];
                        let mode = (prng.gen_range(0, 1) == 0)
                            .then(|| 0o600 + prng.gen_range(0, 0o177) as u32);
                        let size =
                            (prng.gen_range(0, 1) == 0).then(|| prng.gen_range(0, 200) as u64);
                        let _ = fs.setattr(ino, mode, None, None, size, None, None);
                    }
                }
                4 => {
                    let parent = dirs[prng.gen_range(0, dirs.len() - 1)];
                    let name = format!("symlink_{}_{}", seed, step);
                    let target = format!("target_{}_{}", seed, step);
                    if let Ok(ino) = fs.symlink(parent, &name, &target) {
                        files.push(ino);
                        entries.push(TrackedEntry {
                            parent,
                            name,
                            ino,
                            is_dir: false,
                        });
                    }
                }
                5 => {
                    if !files.is_empty() {
                        let ino = files[prng.gen_range(0, files.len() - 1)];
                        let newparent = dirs[prng.gen_range(0, dirs.len() - 1)];
                        let newname = format!("hardlink_{}_{}", seed, step);
                        if fs.link(ino, newparent, &newname).is_ok() {
                            entries.push(TrackedEntry {
                                parent: newparent,
                                name: newname,
                                ino,
                                is_dir: false,
                            });
                        }
                    }
                }
                6 => {
                    let candidates: Vec<usize> =
                        (0..entries.len()).filter(|&i| !entries[i].is_dir).collect();
                    if !candidates.is_empty() {
                        let idx = candidates[prng.gen_range(0, candidates.len() - 1)];
                        let e = entries.remove(idx);
                        let _ = fs.unlink(e.parent, &e.name);
                    }
                }
                7 => {
                    let candidates: Vec<usize> = (0..entries.len())
                        .filter(|&i| entries[i].ino != 1)
                        .collect();
                    if !candidates.is_empty() {
                        let idx = candidates[prng.gen_range(0, candidates.len() - 1)];
                        let newparent = dirs[prng.gen_range(0, dirs.len() - 1)];
                        let newname = format!("renamed_{}_{}", seed, step);
                        let (parent, name) = (entries[idx].parent, entries[idx].name.clone());
                        if fs.rename(parent, &name, newparent, &newname).is_ok() {
                            entries[idx].parent = newparent;
                            entries[idx].name = newname;
                        }
                    }
                }
                _ => {
                    if !files.is_empty() {
                        let ino = files[prng.gen_range(0, files.len() - 1)];
                        let _ = fs.read(ino, 0, 4096);
                    }
                }
            }
        }

        // Export a summary from the live instance - InMemoryFS::export_summary flushes
        // first, so every extent is guaranteed Disk-backed (SharedExtentState refuses to
        // serialize a still-Staged one) before either summary below gets written.
        let _generation = fs.fs.log_writer.as_ref().unwrap().generation();
        let written_path = fs
            .fs
            .export_summary(&fs.log_dir)
            .expect("export_summary failed on the live instance");

        // Reprocess: copy only the raw .log files into a fresh directory (deliberately
        // excluding any .summary file), so recover_fs has no fast-path available and is
        // forced to fully replay from generation 1 - exactly the "reprocess all the
        // logs" scenario this test exists to check.
        let replay_dir = tempfile::tempdir().unwrap();
        for entry in std::fs::read_dir(&fs.log_dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("log") {
                std::fs::copy(&path, replay_dir.path().join(entry.file_name())).unwrap();
            }
        }
        let mut replayed = recover_fs(replay_dir.path()).expect("recover_fs failed on replay");
        replayed.track_atime = false;
        let regenerated_path = replayed
            .export_summary(replay_dir.path())
            .expect("export_summary failed on the replayed instance");

        let written_bytes = std::fs::read(&written_path).unwrap();
        let regenerated_bytes = std::fs::read(&regenerated_path).unwrap();
        assert_eq!(
            written_bytes,
            regenerated_bytes,
            "summary export is not byte-for-byte deterministic for seed {} \
             (written {} bytes, regenerated {} bytes)",
            seed,
            written_bytes.len(),
            regenerated_bytes.len()
        );
    }
}
