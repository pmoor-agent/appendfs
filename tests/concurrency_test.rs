// Threaded concurrency stress test. Unlike tests/fuzz_test.rs (which is deliberately
// single-threaded and deterministic, comparing independent FS instances step-by-step),
// this test hammers a *single shared* InMemoryFS from multiple real OS threads at once,
// directly through the same `*_core` functions real FUSE dispatch uses. The goal isn't
// reproducibility of a specific interleaving - it's shaking out data races and lock
// misuse around the striped `lock_pool` / `SyncNode` unsafe-cell design that a
// single-threaded fuzz test structurally cannot exercise.
use appendfs::InMemoryFS;
use appendfs::LogWriter;
use appendfs::clock::{Clock, SystemClock};
use appendfs::log::{SummaryReader, recover_fs};
use appendfs::node::Node;
use appendfs::operations::dir::{list_dir_core, mkdir_core, rmdir_core};
use appendfs::operations::links::{
    link_core, readlink_core, rename_core, symlink_core, unlink_core,
};
use appendfs::operations::read_write::{
    FUSE_SET_ATTR_SIZE, create_core, getattr_core, read_core, setattr_core, write_core,
};
use appendfs::shim::FileType;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

struct Rng {
    state: u64,
}

impl Rng {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0xDEADBEEFCAFEBABE } else { seed },
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

    // Inclusive on both ends.
    fn gen_range(&mut self, min: usize, max: usize) -> usize {
        if min >= max {
            return min;
        }
        min + (self.next_u64() as usize % (max - min + 1))
    }
}

const UID: u32 = 1000;
const GID: u32 = 1000;
const NUM_THREADS: usize = 8;
const OPS_PER_THREAD: usize = 400;
const DIR_NAMES: [&str; 4] = ["d0", "d1", "d2", "d3"];
const FILE_NAMES: [&str; 4] = ["f0", "f1", "f2", "f3"];

fn pick_entry(fs: &InMemoryFS, dir_ino: u64, rng: &mut Rng) -> Option<(String, u64)> {
    match list_dir_core(fs, dir_ino) {
        Ok(entries) if !entries.is_empty() => {
            let idx = rng.gen_range(0, entries.len() - 1);
            Some(entries[idx].clone())
        }
        _ => None,
    }
}

// Picks a directory to operate on: usually one of the top-level shared dirs, but
// sometimes a subdirectory discovered inside one of them, so nesting (and therefore
// multi-hop ancestor walks during directory rename's loop-prevention check) emerges
// organically as threads race to create/rename/remove entries.
fn pick_target_dir(fs: &InMemoryFS, shared: &[u64], rng: &mut Rng) -> u64 {
    let base = shared[rng.gen_range(0, shared.len() - 1)];
    if rng.gen_range(0, 1) == 0 {
        return base;
    }
    if let Ok(entries) = list_dir_core(fs, base) {
        let dirs: Vec<u64> = entries
            .iter()
            .filter_map(|(_, ino)| match getattr_core(fs, *ino) {
                Ok(a) if a.file_type == FileType::Directory => Some(*ino),
                _ => None,
            })
            .collect();
        if !dirs.is_empty() {
            return dirs[rng.gen_range(0, dirs.len() - 1)];
        }
    }
    base
}

fn worker(fs: Arc<InMemoryFS>, shared_dirs: Arc<Vec<u64>>, seed: u64) {
    let mut rng = Rng::new(seed);
    for _ in 0..OPS_PER_THREAD {
        let dir_a = pick_target_dir(&fs, &shared_dirs, &mut rng);
        let dir_b = pick_target_dir(&fs, &shared_dirs, &mut rng);
        match rng.gen_range(0, 8) {
            0 => {
                let name = DIR_NAMES[rng.gen_range(0, DIR_NAMES.len() - 1)];
                let _ = mkdir_core(&fs, dir_a, name, 0o755, UID, GID);
            }
            1 => {
                let name = FILE_NAMES[rng.gen_range(0, FILE_NAMES.len() - 1)];
                if let Ok(attr) = create_core(&fs, dir_a, name, 0o644, 0, UID, GID) {
                    let data = vec![b'x'; rng.gen_range(1, 64)];
                    let _ = write_core(&fs, attr.ino, &data, 0);
                }
            }
            2 => {
                if let Some((_, ino)) = pick_entry(&fs, dir_a, &mut rng) {
                    let data = vec![b'y'; rng.gen_range(1, 64)];
                    let offset = rng.gen_range(0, 128) as i64;
                    let _ = write_core(&fs, ino, &data, offset);
                }
            }
            3 => {
                if let Some((_, ino)) = pick_entry(&fs, dir_a, &mut rng) {
                    let _ = read_core(&fs, ino, 64, 0);
                }
            }
            4 => {
                if let Some((_, ino)) = pick_entry(&fs, dir_a, &mut rng) {
                    let size = rng.gen_range(0, 32) as i64;
                    let now = SystemTime::now();
                    let _ = setattr_core(&fs, ino, 0, UID, GID, size, now, now, FUSE_SET_ATTR_SIZE);
                }
            }
            5 => {
                let name = FILE_NAMES[rng.gen_range(0, FILE_NAMES.len() - 1)];
                let _ = symlink_core(&fs, dir_a, name, "sometarget", UID, GID);
            }
            6 => {
                if let Some((_, ino)) = pick_entry(&fs, dir_a, &mut rng) {
                    let name = FILE_NAMES[rng.gen_range(0, FILE_NAMES.len() - 1)];
                    let _ = link_core(&fs, ino, dir_b, name);
                }
            }
            7 => {
                if let Some((name, ino)) = pick_entry(&fs, dir_a, &mut rng) {
                    match getattr_core(&fs, ino) {
                        Ok(attr) if attr.file_type == FileType::Directory => {
                            let _ = rmdir_core(&fs, dir_a, &name);
                        }
                        Ok(_) => {
                            let _ = unlink_core(&fs, dir_a, &name);
                        }
                        Err(_) => {}
                    }
                }
            }
            _ => {
                if let Some((name, _)) = pick_entry(&fs, dir_a, &mut rng) {
                    let newname = FILE_NAMES[rng.gen_range(0, FILE_NAMES.len() - 1)];
                    let _ = rename_core(&fs, dir_a, &name, dir_b, newname);
                }
            }
        }
    }
}

// Walks the entire tree from root using only the same core handlers real FUSE dispatch
// uses (never touching `fs.inodes` directly beyond a final orphan-count check), and
// asserts filesystem-wide invariants that must hold once all threads have quiesced:
//   - every reachable entry resolves (no dangling directory entries)
//   - every directory has nlink == 2 (this FS doesn't do POSIX subdir-nlink accounting,
//     so this is the invariant that actually holds - see mkdir_core/rmdir_core)
//   - every directory is reachable from exactly one parent (directories can't be
//     hardlinked - link_core rejects them with EPERM)
//   - every file/symlink's reported nlink matches the number of directory entries in
//     the final tree that actually point at it
//   - no inode exists in `fs.inodes` that isn't reachable from root (no leaks, and no
//     cycles disconnected from root - a cycle's members would all show up here as
//     simultaneously present-but-unreachable)
fn verify_tree_invariants(fs: &InMemoryFS) {
    let mut visited: HashSet<u64> = HashSet::new();
    let mut queue: VecDeque<u64> = VecDeque::new();
    visited.insert(1);
    queue.push_back(1);
    let mut link_counts: HashMap<u64, u32> = HashMap::new();

    while let Some(ino) = queue.pop_front() {
        let attr =
            getattr_core(fs, ino).unwrap_or_else(|e| panic!("getattr({}) failed: {}", ino, e));
        match attr.file_type {
            FileType::Directory => {
                assert_eq!(
                    attr.nlink, 2,
                    "directory inode {} has unexpected nlink {} (expected 2)",
                    ino, attr.nlink
                );
                let entries = list_dir_core(fs, ino)
                    .unwrap_or_else(|e| panic!("list_dir({}) failed: {}", ino, e));
                for (name, child_ino) in entries {
                    let child_attr = getattr_core(fs, child_ino).unwrap_or_else(|e| {
                        panic!(
                            "dangling entry {:?} -> inode {} in dir {}: getattr failed: {}",
                            name, child_ino, ino, e
                        )
                    });
                    if child_attr.file_type == FileType::Directory {
                        assert!(
                            visited.insert(child_ino),
                            "directory inode {} reachable from more than one parent \
                             (topology corruption - directories cannot be hardlinked)",
                            child_ino
                        );
                        queue.push_back(child_ino);
                    } else {
                        *link_counts.entry(child_ino).or_insert(0) += 1;
                        visited.insert(child_ino);
                    }
                }
            }
            FileType::Symlink => {
                readlink_core(fs, ino)
                    .unwrap_or_else(|e| panic!("readlink({}) failed: {}", ino, e));
            }
            FileType::RegularFile => {}
        }
    }

    for (ino, count) in &link_counts {
        let attr = getattr_core(fs, *ino).unwrap();
        assert_eq!(
            attr.nlink, *count,
            "inode {} nlink mismatch: attr reports {}, but {} directory entries point at it",
            ino, attr.nlink, count
        );
    }

    let snapshot = fs.snapshot_all();
    let total_inodes = snapshot.len();
    if visited.len() != total_inodes {
        let mut orphans: Vec<u64> = snapshot
            .keys()
            .copied()
            .filter(|k| !visited.contains(k))
            .collect();
        orphans.sort_unstable();
        eprintln!("orphaned/unreachable inodes: {:?}", orphans);
    }
    assert_eq!(
        visited.len(),
        total_inodes,
        "orphaned or leaked inodes: {} reachable from root, but fs.snapshot_all() holds {}",
        visited.len(),
        total_inodes
    );
}

// Root (inode 1) is created implicitly at `InMemoryFS` construction, never through a
// log record, so nothing in replay ever touches its timestamps - when recovering
// without a `.summary` file (as this test forces, to exercise a full log replay),
// `recovery.rs` approximates root's atime/mtime/ctime from the oldest log file's
// header, which only carries second precision (see the comment at
// `recover_fs_with_clock`'s call to `InMemoryFS::with_clock`). A real `SystemClock`
// live timestamp almost never lands on an exact second, so root's timestamps are
// expected to differ between live and replay - a known, pre-existing, and
// already-documented lossy-recovery approximation, unrelated to what this comparison
// is actually checking (whether concurrent directory-structure mutations replay in
// the same order they committed live). Every other inode is fully log-derived and
// compared exactly.
fn normalize_for_compare(ino: u64, mut node: Node) -> Node {
    if ino == 1 {
        if let Node::Directory {
            atime,
            mtime,
            ctime,
            ..
        } = &mut node
        {
            *atime = UNIX_EPOCH;
            *mtime = UNIX_EPOCH;
            *ctime = UNIX_EPOCH;
        }
    }
    node
}

// After the concurrent stress run, replaying the log from scratch must reproduce
// byte-for-byte the same filesystem state that's live in memory. This is the property
// `InMemoryFS::dir_lock` exists to guarantee: every directory-structure mutation
// stages its log record while still holding that lock, so the log's record order
// always matches the order those mutations actually landed in memory - no concurrent
// interleaving between threads can produce a live state the log can't reconstruct.
// Mirrors tests/fuzz_test.rs's test_summary_export_is_deterministic, but against this
// test's genuinely concurrent log instead of a single-threaded one.
fn verify_log_replay_matches_live(fs: &InMemoryFS, log_dir: &std::path::Path, seed: u64) {
    let _generation = fs.log_writer.as_ref().unwrap().generation();
    let written_path = fs.export_summary(log_dir).unwrap_or_else(|e| {
        panic!(
            "export_summary failed on the live instance (seed {}): {}",
            seed, e
        )
    });

    // Reprocess: copy only the raw .log files into a fresh directory (excluding the
    // .summary file just written), so recover_fs has no fast-path available and is
    // forced to fully replay from generation 1.
    let replay_dir = tempfile::tempdir().unwrap();
    for entry in std::fs::read_dir(log_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("log") {
            std::fs::copy(&path, replay_dir.path().join(entry.file_name())).unwrap();
        }
    }
    let mut replayed = recover_fs(replay_dir.path())
        .unwrap_or_else(|e| panic!("recover_fs failed on replay (seed {}): {}", seed, e));
    replayed.track_atime = false;
    let regenerated_path = replayed
        .export_summary(replay_dir.path())
        .unwrap_or_else(|e| {
            panic!(
                "export_summary failed on the replayed instance (seed {}): {}",
                seed, e
            )
        });

    // Compare tree *content* (the inode map), not raw summary bytes - `next_inode` can
    // legitimately differ between the two: a failed create/mkdir/symlink (EEXIST,
    // common here since names are drawn from a small shared pool) still burns an inode
    // number live (`fs.allocate_inode()` runs unconditionally, before the name check),
    // but a failed call never stages a log record - so recovery, which derives
    // next_inode from the highest inode number that actually appears in some logged
    // record, has no way to see that gap. That never corrupts anything (the skipped
    // number was never live-assigned to any real node, so reusing it post-recovery
    // can't collide with one); it's excluded here deliberately, not overlooked.
    let mut written_reader = SummaryReader::open(&written_path).unwrap();
    let mut regenerated_reader = SummaryReader::open(&regenerated_path).unwrap();
    let written_inodes = written_reader.read_all_inodes().unwrap();
    let regenerated_inodes = regenerated_reader.read_all_inodes().unwrap();

    let mut written_keys: Vec<u64> = written_inodes.keys().copied().collect();
    let mut regenerated_keys: Vec<u64> = regenerated_inodes.keys().copied().collect();
    written_keys.sort_unstable();
    regenerated_keys.sort_unstable();
    assert_eq!(
        written_keys, regenerated_keys,
        "log replay does not reproduce the live filesystem's inode set for seed {}",
        seed
    );

    for ino in written_keys {
        // Safe: both maps were just built fresh by this thread from summary files on
        // disk, never shared with or touched by any other thread - no lock_pool guard
        // needed for a single-owner read.
        let live_node = unsafe { written_inodes[&ino].read() }.clone();
        let replayed_node = unsafe { regenerated_inodes[&ino].read() }.clone();
        let live_bytes = bincode::serialize(&normalize_for_compare(ino, live_node)).unwrap();
        let replayed_bytes =
            bincode::serialize(&normalize_for_compare(ino, replayed_node)).unwrap();
        assert_eq!(
            live_bytes, replayed_bytes,
            "log replay diverges from the live filesystem state at inode {} for seed {} \
             - the log's record order (or its replay semantics) diverged from what \
             actually landed in memory",
            ino, seed
        );
    }
}

fn run_concurrent_stress(seed: u64) {
    let temp_dir = tempfile::tempdir().unwrap();
    let log_dir = temp_dir.path().to_path_buf();
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let writer = Arc::new(LogWriter::create(&log_dir, 1, &*clock).unwrap());
    let mut fs = InMemoryFS::with_clock_and_log(Arc::clone(&clock), Some(Arc::clone(&writer)));
    // Reads bump atime in memory but are never logged (logging every read would defeat
    // the point of an append-only log), so with atime tracking on, a live instance and
    // its log replay would legitimately differ on atime alone - disabling it here keeps
    // every field log-derived, which is what the replay comparison below needs.
    fs.track_atime = false;
    let fs = Arc::new(fs);

    let mut shared_dirs = Vec::new();
    for i in 0..4 {
        let attr = mkdir_core(&fs, 1, &format!("shared{}", i), 0o755, UID, GID)
            .expect("setup mkdir failed");
        shared_dirs.push(attr.ino);
    }
    let shared_dirs = Arc::new(shared_dirs);

    let handles: Vec<_> = (0..NUM_THREADS)
        .map(|i| {
            let fs = Arc::clone(&fs);
            let shared_dirs = Arc::clone(&shared_dirs);
            let thread_seed = seed.wrapping_mul(1_000_003).wrapping_add(i as u64 + 1);
            thread::spawn(move || worker(fs, shared_dirs, thread_seed))
        })
        .collect();

    for (i, handle) in handles.into_iter().enumerate() {
        handle
            .join()
            .unwrap_or_else(|_| panic!("worker thread {} panicked (seed {})", i, seed));
    }

    verify_tree_invariants(&fs);
    verify_log_replay_matches_live(&fs, &log_dir, seed);
}

#[test]
fn test_concurrent_stress() {
    // Matches this project's established sweep style (see tests/fuzz_test.rs): a small
    // committed seed count for normal CI runs, widened temporarily for one-off sweeps.
    for seed in 1..=5u64 {
        run_concurrent_stress(seed);
    }
}
