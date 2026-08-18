use crate::clock::{Clock, SystemClock};
use crate::log::{
    BackgroundFlusher, CreatePayload, ExtentState, GenerationLiveStats, LinkPayload, LogFileCache,
    LogManifest, LogWriter, MkdirPayload, OpCode, RECORD_HEADER_SIZE, RenamePayload, RmdirPayload,
    SetattrPayload, SharedExtentState, SymlinkPayload, UnlinkPayload, WriteMeta,
};
use crate::node::{
    AttrDelta, DirectoryDelta, EntryDelta, FileDelta, Node, NodeDelta, SymlinkDelta,
};
use crate::range_map::RangeMap;
use crate::shim::{FileAttr, FileType};
use crate::storage::Storage;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};

pub struct InMemoryFS {
    /// Resting consolidated state loaded from `.summary` at mount, folded forward over
    /// time by `fold_flush`. Never holds a `Tombstone`.
    pub base: RwLock<HashMap<u64, Arc<Node>>>,
    /// Ordered queue of immutable frozen snapshots waiting to be written/flushed to disk.
    /// New batches are pushed to the back; flusher drains from the front.
    pub flushing: RwLock<VecDeque<HashMap<u64, EntryDelta>>>,
    /// Current generation's active mutable delta layer receiving live operations.
    pub live: RwLock<HashMap<u64, EntryDelta>>,
    /// Active open file descriptor reference counts per inode for POSIX unlinking semantics.
    pub open_handles: RwLock<HashMap<u64, u32>>,
    /// Authoritative manifest of all active log generations and lineage.
    pub manifest: Arc<RwLock<LogManifest>>,
    pub next_inode: AtomicU64,
    pub last_tx_id: AtomicU64,
    pub clock: Arc<dyn Clock>,
    pub log_writer: Option<Arc<LogWriter>>,
    pub log_cache: Option<Arc<LogFileCache>>,
    pub staged_bytes: AtomicUsize,
    pub max_buffer_size: usize,
    pub staged_ops: AtomicUsize,
    pub max_staged_ops: usize,
    /// Maximum frozen batches allowed to queue up before mutations are refused. See
    /// `check_flush_capacity`.
    pub max_flush_queue_depth: usize,
    pub flush_interval: AtomicU64,
    pub(crate) flusher: Mutex<Option<BackgroundFlusher>>,
    pub flush_lock: Mutex<()>,
    /// When false, `read()` never touches atime (like a `noatime` mount) - defaults to true.
    pub track_atime: bool,
    /// When true, filesystem is mounted strictly read-only (EROFS).
    pub read_only: std::sync::atomic::AtomicBool,
    /// Timestamp of the latest recovered operation / summary snapshot (if recovered).
    pub recovered_time: RwLock<Option<SystemTime>>,
    /// Serializes every directory-structure mutation (mkdir/create/symlink/unlink/rmdir/rename/link).
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
            Arc::new(Node::Directory {
                parent: 1,
                entries: Vec::new(),
                perm: 0o755,
                nlink: 2,
                uid,
                gid,
                atime: now,
                mtime: now,
                ctime: now,
            }),
        );

        let log_cache = log_writer.as_ref().map(|w| {
            Arc::new(LogFileCache::with_storage(w.storage().clone()))
        });

        let start_gen = log_writer.as_ref().map_or(1, |w| w.generation());
        let manifest = Arc::new(RwLock::new(LogManifest::new_with_time(
            start_gen, "main", now,
        )));

        Self {
            base: RwLock::new(map),
            flushing: RwLock::new(VecDeque::new()),
            live: RwLock::new(HashMap::new()),
            open_handles: RwLock::new(HashMap::new()),
            manifest,
            next_inode: AtomicU64::new(2),
            last_tx_id: AtomicU64::new(0),
            clock,
            log_writer,
            log_cache,
            staged_bytes: AtomicUsize::new(0),
            max_buffer_size: 128 * 1024 * 1024,
            staged_ops: AtomicUsize::new(0),
            max_staged_ops: crate::cli::DEFAULT_MAX_BUFFER_OPS,
            max_flush_queue_depth: crate::cli::DEFAULT_MAX_FLUSH_QUEUE_DEPTH,
            flush_interval: AtomicU64::new(0),
            flusher: Mutex::new(None),
            flush_lock: Mutex::new(()),
            track_atime: true,
            read_only: std::sync::atomic::AtomicBool::new(false),
            recovered_time: RwLock::new(None),
            dir_lock: Mutex::new(()),
        }
    }

    pub fn with_clock_and_storage(clock: Arc<dyn Clock>, storage: Arc<dyn Storage>) -> Self {
        let mut fs = Self::with_clock(clock);
        fs.set_storage(storage);
        fs
    }

    pub fn set_read_only(&self, ro: bool) {
        self.read_only
            .store(ro, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn is_read_only(&self) -> bool {
        self.read_only.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn recovered_time(&self) -> Option<SystemTime> {
        *self.recovered_time.read().unwrap()
    }

    pub fn set_recovered_time(&self, time: Option<SystemTime>) {
        *self.recovered_time.write().unwrap() = time;
    }

    pub fn set_storage(&mut self, storage: Arc<dyn Storage>) {
        self.log_cache = Some(Arc::new(LogFileCache::with_storage(storage)));
    }

    pub fn set_log_dir(&mut self, log_dir: impl AsRef<Path>) {
        self.set_storage(Arc::new(crate::storage::OsStorage::new(log_dir)));
    }

    pub(crate) fn allocate_inode(&self) -> u64 {
        self.next_inode.fetch_add(1, Ordering::SeqCst)
    }

    // --- POSIX Open File Descriptor Tracking ---

    pub fn open_handle(&self, ino: u64) {
        let mut handles = self.open_handles.write().unwrap();
        *handles.entry(ino).or_insert(0) += 1;
    }

    pub fn release_handle(&self, ino: u64) {
        let mut handles = self.open_handles.write().unwrap();
        if let Some(count) = handles.get_mut(&ino) {
            *count = count.saturating_sub(1);
        }
        if handles.get(&ino) == Some(&0) {
            handles.remove(&ino);
        }
        let remaining = handles.get(&ino).copied().unwrap_or(0);
        if remaining == 0
            && let Some(attr) = self.get_attr(ino)
                && attr.nlink == 0 {
                    self.tombstone(ino);
                }
    }

    pub fn open_count(&self, ino: u64) -> u32 {
        self.open_handles
            .read()
            .unwrap()
            .get(&ino)
            .copied()
            .unwrap_or(0)
    }

    // --- In-Memory Delta Layer Mutations ---

    pub fn insert_new_node(&self, ino: u64, delta: NodeDelta) {
        self.live
            .write()
            .unwrap()
            .insert(ino, EntryDelta::Node(delta));
    }

    pub fn tombstone(&self, ino: u64) {
        self.live
            .write()
            .unwrap()
            .insert(ino, EntryDelta::Tombstone);
    }

    pub fn add_dir_entry(&self, parent: u64, name: &str, child_ino: u64, now: SystemTime) {
        let mut live = self.live.write().unwrap();
        let entry = live
            .entry(parent)
            .or_insert_with(|| EntryDelta::Node(NodeDelta::Directory(DirectoryDelta::default())));
        if let EntryDelta::Node(NodeDelta::Directory(d)) = entry {
            d.removed.remove(name);
            d.added.insert(name.to_string(), child_ino);
            d.attr_delta.mtime = Some(now);
            d.attr_delta.ctime = Some(now);
        }
    }

    pub fn remove_dir_entry(&self, parent: u64, name: &str, now: SystemTime) {
        let mut live = self.live.write().unwrap();
        let entry = live
            .entry(parent)
            .or_insert_with(|| EntryDelta::Node(NodeDelta::Directory(DirectoryDelta::default())));
        if let EntryDelta::Node(NodeDelta::Directory(d)) = entry {
            d.added.remove(name);
            d.removed.insert(name.to_string());
            d.attr_delta.mtime = Some(now);
            d.attr_delta.ctime = Some(now);
        }
    }

    pub fn update_dir_parent(&self, ino: u64, new_parent: u64) {
        let mut live = self.live.write().unwrap();
        let entry = live
            .entry(ino)
            .or_insert_with(|| EntryDelta::Node(NodeDelta::Directory(DirectoryDelta::default())));
        if let EntryDelta::Node(NodeDelta::Directory(d)) = entry {
            d.parent = Some(new_parent);
        }
    }

    pub fn get_parent_dir_inode(&self, ino: u64) -> Option<u64> {
        if ino == 1 {
            return Some(1);
        }

        // 1. Check live delta
        if let Some(entry) = self.live.read().unwrap().get(&ino) {
            match entry {
                EntryDelta::Tombstone => return None,
                EntryDelta::Node(NodeDelta::Directory(d)) => {
                    if let Some(p) = d.parent {
                        return Some(p);
                    }
                }
                _ => return None,
            }
        }

        // 2. Check flushing deltas (newest to oldest)
        {
            let flushing_read = self.flushing.read().unwrap();
            for flushing_map in flushing_read.iter().rev() {
                if let Some(entry) = flushing_map.get(&ino) {
                    match entry {
                        EntryDelta::Tombstone => return None,
                        EntryDelta::Node(NodeDelta::Directory(d)) => {
                            if let Some(p) = d.parent {
                                return Some(p);
                            }
                        }
                        _ => return None,
                    }
                }
            }
        }

        // 3. Check base
        if let Some(arc) = self.base.read().unwrap().get(&ino) {
            let node = arc.as_ref();
            if let Node::Directory { parent, .. } = node {
                return Some(*parent);
            }
        }

        None
    }

    pub fn update_attr_delta(&self, ino: u64, delta: AttrDelta) {
        let mut live = self.live.write().unwrap();
        match live.get_mut(&ino) {
            // Already deleted in this batch. The fallback below reconstructs a node delta
            // from the lower layers, which for a tombstoned inode would replace the
            // tombstone and bring the inode back from the dead - still carrying its old
            // link count, but with nothing referencing it.
            Some(EntryDelta::Tombstone) => return,
            Some(EntryDelta::Node(node_delta)) => {
                match node_delta {
                    NodeDelta::Directory(d) => merge_attr_delta(&mut d.attr_delta, &delta),
                    NodeDelta::File(f) => merge_attr_delta(&mut f.attr_delta, &delta),
                    NodeDelta::Symlink(s) => merge_attr_delta(&mut s.attr_delta, &delta),
                }
                return;
            }
            None => {}
        }

        // Inode not in live yet - query existing type from lower layers without re-acquiring live lock.
        // A tombstone found in `flushing` is authoritative and must NOT fall through to
        // `base`: `base` still holds the pre-delete node until that tombstone's batch is
        // folded, and since inode numbers are never reused, a tombstone anywhere below
        // `live` means this inode is gone for good. Collapsing "explicitly tombstoned"
        // and "not found at all" into the same `None` (as a bare `Option<FileType>`
        // would) made this fall through to `base` and resurrect the inode - exactly the
        // live-side counterpart of the `live`-tombstone case handled above.
        let mut file_type = None;
        let mut found_in_flushing = false;
        {
            let flushing_read = self.flushing.read().unwrap();
            for flushing_map in flushing_read.iter().rev() {
                if let Some(entry) = flushing_map.get(&ino) {
                    found_in_flushing = true;
                    match entry {
                        EntryDelta::Tombstone => {
                            file_type = None;
                            break;
                        }
                        EntryDelta::Node(NodeDelta::Directory(_)) => {
                            file_type = Some(FileType::Directory);
                            break;
                        }
                        EntryDelta::Node(NodeDelta::File(_)) => {
                            file_type = Some(FileType::RegularFile);
                            break;
                        }
                        EntryDelta::Node(NodeDelta::Symlink(_)) => {
                            file_type = Some(FileType::Symlink);
                            break;
                        }
                    }
                }
            }
        }
        if file_type.is_none() && !found_in_flushing {
            file_type = self
                .base
                .read()
                .unwrap()
                .get(&ino)
                .map(|arc| match arc.as_ref() {
                    Node::Directory { .. } => FileType::Directory,
                    Node::File { .. } => FileType::RegularFile,
                    Node::Symlink { .. } => FileType::Symlink,
                });
        }

        match file_type {
            Some(FileType::Directory) => {
                live.insert(
                    ino,
                    EntryDelta::Node(NodeDelta::Directory(DirectoryDelta {
                        parent: None,
                        added: HashMap::new(),
                        removed: HashSet::new(),
                        attr_delta: delta,
                    })),
                );
            }
            Some(FileType::RegularFile) => {
                live.insert(
                    ino,
                    EntryDelta::Node(NodeDelta::File(FileDelta {
                        extents: RangeMap::new(),
                        size: None,
                        truncate_mask: None,
                        attr_delta: delta,
                    })),
                );
            }
            Some(FileType::Symlink) => {
                live.insert(
                    ino,
                    EntryDelta::Node(NodeDelta::Symlink(SymlinkDelta {
                        target: None,
                        attr_delta: delta,
                    })),
                );
            }
            None => {}
        }
    }

    /// Whether `ino` still resolves in the layers *below* `live`.
    ///
    /// Callers that would insert a fresh delta for an inode absent from `live` must check
    /// this while holding the `live` write lock. Validating with `get_attr` first is not
    /// enough: the inode can be unlinked in the window before the lock is taken, and once
    /// its tombstone has been frozen out of `live` it is invisible to `live.entry(..)`, so
    /// the new delta folds into `base` *after* the tombstone and resurrects the inode -
    /// with `delta_to_node`'s defaults (uid/gid 0, atime at the epoch) and no directory
    /// referencing it.
    pub fn exists_below_live(&self, ino: u64) -> bool {
        {
            let flushing = self.flushing.read().unwrap();
            for batch in flushing.iter().rev() {
                match batch.get(&ino) {
                    Some(EntryDelta::Tombstone) => return false,
                    Some(EntryDelta::Node(_)) => return true,
                    None => {}
                }
            }
        }
        self.base.read().unwrap().contains_key(&ino)
    }

    // --- Overlay Query & Resolution Methods ---

    /// Resolves full `FileAttr` for an inode across `flushing` -> `base`, deliberately
    /// skipping `live`. Used by mutators that already hold `live`'s write lock and need
    /// the authoritative pre-live state *as of right now* - unlike a `get_attr` call
    /// made before taking that lock, which can go stale if a flush freezes `live` out
    /// from under the caller in the window between the read and the lock acquisition.
    ///
    /// Reads `flushing` *before* `base`, even though `base` is logically the older
    /// layer: `fold_flushed_batch` writes a batch's delta into `base` and only pops it
    /// out of `flushing` afterward, so a batch is briefly visible in both places at
    /// once, never in neither. Reading `base` first (as this used to) can straddle that
    /// transition - a `base` read that lands *before* the fold's write, followed by a
    /// `flushing` read that lands *after* the pop, sees neither the old value (base
    /// hadn't been touched... it had, we just read too early) nor the new one, silently
    /// dropping the update. Reading `flushing` first closes the gap: if a batch is
    /// already gone from `flushing` by the time we check, the fold that removed it
    /// happened-before that observation, and the fold's `base` write happened-before
    /// its own pop - so by transitivity our later `base` read is guaranteed fresh.
    pub fn attr_below_live(&self, ino: u64) -> Option<FileAttr> {
        let flushing_entries: Vec<EntryDelta> = self
            .flushing
            .read()
            .unwrap()
            .iter()
            .filter_map(|batch| batch.get(&ino).cloned())
            .collect();
        let base_node = self.base.read().unwrap().get(&ino).cloned();

        let mut attr: Option<FileAttr> = base_node.map(|arc| node_to_attr(ino, arc.as_ref()));
        for entry in &flushing_entries {
            match entry {
                EntryDelta::Tombstone => {
                    attr = None;
                }
                EntryDelta::Node(delta) => {
                    if let Some(ref mut a) = attr {
                        apply_node_delta(a, delta);
                    } else {
                        let mut a = delta_to_initial_attr(ino, delta);
                        apply_node_delta(&mut a, delta);
                        attr = Some(a);
                    }
                }
            }
        }

        attr
    }

    /// Resolves full `FileAttr` for an inode across `live` -> `flushing` -> `base`.
    ///
    /// Reads `live` before delegating to `attr_below_live` for the same reason that
    /// function reads `flushing` before `base`: `begin_flush` empties `live` into
    /// `flushing` in two separate lock acquisitions, so a `live` read landing in that
    /// gap must be followed by a `flushing`/`base` read that is guaranteed to already
    /// see it - which is exactly what reading `live` first, then delegating, gives us.
    pub fn get_attr(&self, ino: u64) -> Option<FileAttr> {
        let live_entry = self.live.read().unwrap().get(&ino).cloned();
        let mut attr = self.attr_below_live(ino);

        if let Some(entry) = live_entry {
            match entry {
                EntryDelta::Tombstone => {
                    attr = None;
                }
                EntryDelta::Node(delta) => {
                    if let Some(ref mut a) = attr {
                        apply_node_delta(a, &delta);
                    } else {
                        let mut a = delta_to_initial_attr(ino, &delta);
                        apply_node_delta(&mut a, &delta);
                        attr = Some(a);
                    }
                }
            }
        }

        attr
    }

    /// Looks up a child entry by `name` inside `parent` directory across layers.
    pub fn lookup_child(&self, parent: u64, name: &str) -> Option<u64> {
        if let Some(entry) = self.live.read().unwrap().get(&parent) {
            match entry {
                EntryDelta::Tombstone => return None,
                EntryDelta::Node(NodeDelta::Directory(d)) => {
                    if d.removed.contains(name) {
                        return None;
                    }
                    if let Some(&ino) = d.added.get(name) {
                        return Some(ino);
                    }
                }
                _ => return None,
            }
        }

        {
            let flushing_read = self.flushing.read().unwrap();
            for flushing_map in flushing_read.iter().rev() {
                if let Some(entry) = flushing_map.get(&parent) {
                    match entry {
                        EntryDelta::Tombstone => return None,
                        EntryDelta::Node(NodeDelta::Directory(d)) => {
                            if d.removed.contains(name) {
                                return None;
                            }
                            if let Some(&ino) = d.added.get(name) {
                                return Some(ino);
                            }
                        }
                        _ => return None,
                    }
                }
            }
        }

        if let Some(arc) = self.base.read().unwrap().get(&parent) {
            let node = arc.as_ref();
            if let Node::Directory { entries, .. } = node
                && let Some((_, ino)) = entries.iter().find(|(entry_name, _)| entry_name == name) {
                    return Some(*ino);
                }
        }

        None
    }

    /// Lists all consolidated entries of directory `parent` across layers.
    pub fn list_directory(&self, parent: u64) -> Option<Vec<(String, u64)>> {
        let attr = self.get_attr(parent)?;
        if attr.file_type != FileType::Directory {
            return None;
        }

        // Clone newest-layer-first (live, then flushing, then base) before applying any
        // of them, so a concurrent `begin_flush`/`fold_flushed_batch` transition can't
        // be caught mid-move and silently drop a directory-entry change - see
        // `attr_below_live`'s comment for the full argument.
        let live_dir: Option<DirectoryDelta> = match self.live.read().unwrap().get(&parent) {
            Some(EntryDelta::Node(NodeDelta::Directory(d))) => Some(d.clone()),
            _ => None,
        };
        let flushing_dirs: Vec<DirectoryDelta> = self
            .flushing
            .read()
            .unwrap()
            .iter()
            .filter_map(|batch| match batch.get(&parent) {
                Some(EntryDelta::Node(NodeDelta::Directory(d))) => Some(d.clone()),
                _ => None,
            })
            .collect();

        let mut map: HashMap<String, u64> = HashMap::new();

        if let Some(arc) = self.base.read().unwrap().get(&parent) {
            let node = arc.as_ref();
            if let Node::Directory { entries, .. } = node {
                for (name, child_ino) in entries {
                    map.insert(name.clone(), *child_ino);
                }
            }
        }

        for d in &flushing_dirs {
            for name in &d.removed {
                map.remove(name);
            }
            for (name, child_ino) in &d.added {
                map.insert(name.clone(), *child_ino);
            }
        }

        if let Some(d) = &live_dir {
            for name in &d.removed {
                map.remove(name);
            }
            for (name, child_ino) in &d.added {
                map.insert(name.clone(), *child_ino);
            }
        }

        let mut list: Vec<(String, u64)> = map.into_iter().collect();
        list.sort_by(|a, b| a.0.cmp(&b.0));
        Some(list)
    }

    /// Reads target of a symlink across layers.
    pub fn read_link(&self, ino: u64) -> Option<String> {
        if let Some(entry) = self.live.read().unwrap().get(&ino) {
            match entry {
                EntryDelta::Tombstone => return None,
                EntryDelta::Node(NodeDelta::Symlink(s)) => {
                    if let Some(ref t) = s.target {
                        return Some(t.clone());
                    }
                }
                _ => return None,
            }
        }

        {
            let flushing_read = self.flushing.read().unwrap();
            for flushing_map in flushing_read.iter().rev() {
                if let Some(entry) = flushing_map.get(&ino) {
                    match entry {
                        EntryDelta::Tombstone => return None,
                        EntryDelta::Node(NodeDelta::Symlink(s)) => {
                            if let Some(ref t) = s.target {
                                return Some(t.clone());
                            }
                        }
                        _ => return None,
                    }
                }
            }
        }

        if let Some(arc) = self.base.read().unwrap().get(&ino) {
            let node = arc.as_ref();
            if let Node::Symlink { target, .. } = node {
                return Some(target.clone());
            }
        }

        None
    }

    /// Reads file data at `[offset, offset + size)` resolving extents across layers.
    pub fn read_file_data(&self, ino: u64, offset: u64, size: usize) -> Result<Vec<u8>, i32> {
        let attr = self.get_attr(ino).ok_or(libc::ENOENT)?;
        if attr.file_type != FileType::RegularFile {
            return Err(libc::EISDIR);
        }

        let file_size = attr.size as u64;
        if offset >= file_size {
            return Ok(Vec::new());
        }

        let read_len = std::cmp::min(size as u64, file_size - offset);
        let mut read_buf = vec![0u8; read_len as usize];
        let mut filled = vec![false; read_len as usize];

        // 1. Live layer
        let mut current_truncate_mask = u64::MAX;
        if let Some(EntryDelta::Node(NodeDelta::File(f))) = self.live.read().unwrap().get(&ino) {
            for (ext_start, ext_len, shared_state) in f.extents.query(offset, read_len) {
                self.copy_extent_data(
                    &mut read_buf,
                    &mut filled,
                    offset,
                    read_len,
                    ext_start,
                    ext_len,
                    &shared_state,
                );
            }
            if let Some(mask) = f.truncate_mask {
                current_truncate_mask = std::cmp::min(current_truncate_mask, mask);
            }
        }

        // 2. Flushing layers (from newest to oldest: iter().rev())
        {
            let flushing_guard = self.flushing.read().unwrap();
            for flushing_map in flushing_guard.iter().rev() {
                if let Some(EntryDelta::Node(NodeDelta::File(f))) = flushing_map.get(&ino) {
                    let max_read =
                        std::cmp::min(read_len, current_truncate_mask.saturating_sub(offset));
                    if max_read > 0 {
                        for (ext_start, ext_len, shared_state) in f.extents.query(offset, max_read)
                        {
                            self.copy_extent_data(
                                &mut read_buf,
                                &mut filled,
                                offset,
                                read_len,
                                ext_start,
                                ext_len,
                                &shared_state,
                            );
                        }
                    }
                    if let Some(mask) = f.truncate_mask {
                        current_truncate_mask = std::cmp::min(current_truncate_mask, mask);
                    }
                }
            }
        }

        // 3. Base layer
        if let Some(arc) = self.base.read().unwrap().get(&ino) {
            let node = arc.as_ref();
            if let Node::File { range_map, .. } = node {
                let max_base_read =
                    std::cmp::min(read_len, current_truncate_mask.saturating_sub(offset));
                if max_base_read > 0 {
                    for (ext_start, ext_len, shared_state) in range_map.query(offset, max_base_read)
                    {
                        self.copy_extent_data(
                            &mut read_buf,
                            &mut filled,
                            offset,
                            read_len,
                            ext_start,
                            ext_len,
                            &shared_state,
                        );
                    }
                }
            }
        }

        if self.track_atime {
            let now = self.clock.now();
            self.update_attr_delta(
                ino,
                AttrDelta {
                    atime: Some(now),
                    ..Default::default()
                },
            );
        }

        Ok(read_buf)
    }

    #[allow(clippy::too_many_arguments)]
    fn copy_extent_data(
        &self,
        dst_buf: &mut [u8],
        filled: &mut [bool],
        read_start: u64,
        read_len: u64,
        ext_start: u64,
        ext_len: u64,
        shared_state: &SharedExtentState,
    ) {
        let seg_start = std::cmp::max(read_start, ext_start);
        let seg_end = std::cmp::min(read_start + read_len, ext_start + ext_len);
        if seg_start >= seg_end {
            return;
        }

        let seg_len = (seg_end - seg_start) as usize;
        let dst_offset = (seg_start - read_start) as usize;
        let slice_inner_offset = (seg_start - ext_start) as usize;

        if filled[dst_offset..dst_offset + seg_len].iter().all(|&b| b) {
            return;
        }

        let mut temp_buf = vec![0u8; seg_len];
        let mut bytes_read = 0usize;

        let state = shared_state.read_state();
        match state {
            ExtentState::Staged {
                data,
                payload_offset,
                length: _,
            } => {
                let src_start = payload_offset as usize + slice_inner_offset;
                let src_end = std::cmp::min(src_start + seg_len, data.len());
                let actual_len = std::cmp::min(seg_len, src_end.saturating_sub(src_start));
                if actual_len > 0 && src_start < data.len() {
                    temp_buf[..actual_len]
                        .copy_from_slice(&data[src_start..src_start + actual_len]);
                    bytes_read = actual_len;
                }
            }
            ExtentState::Disk {
                generation,
                record_log_offset,
                payload_offset,
                length: _,
            } => {
                if let Some(ref cache) = self.log_cache
                    && let Ok(reader) = cache.get_or_open(generation) {
                        let disk_seek_pos = record_log_offset
                            + crate::log::RECORD_HEADER_SIZE as u64
                            + payload_offset as u64
                            + slice_inner_offset as u64;
                        if reader.read_exact_at(disk_seek_pos, &mut temp_buf).is_ok() {
                            bytes_read = seg_len;
                        }
                    }
            }
        }

        for i in 0..bytes_read {
            if !filled[dst_offset + i] {
                dst_buf[dst_offset + i] = temp_buf[i];
                filled[dst_offset + i] = true;
            }
        }
    }

    /// Merges all layers into a consolidated snapshot map.
    ///
    /// Clones `live`, then `flushing`, then `base` - newest layer first - before
    /// applying any of them, for the same reason `get_attr`/`attr_below_live` do:
    /// `begin_flush` and `fold_flushed_batch` each move data one layer down (never up)
    /// in two separate lock acquisitions, so cloning oldest-first can straddle a
    /// transition and silently miss the batch that moved. Cloning newest-first closes
    /// that gap - see `attr_below_live`'s comment for the full happens-before argument.
    /// The clones are then applied in the normal oldest-to-newest logical order.
    pub fn snapshot_all(&self) -> HashMap<u64, Arc<Node>> {
        let live_snapshot: HashMap<u64, EntryDelta> = self.live.read().unwrap().clone();
        let flushing_snapshot: VecDeque<HashMap<u64, EntryDelta>> =
            self.flushing.read().unwrap().clone();
        let mut result: HashMap<u64, Arc<Node>> = self.base.read().unwrap().clone();

        for flushing_map in flushing_snapshot.iter() {
            for (ino, entry) in flushing_map {
                match entry {
                    EntryDelta::Tombstone => {
                        result.remove(ino);
                    }
                    EntryDelta::Node(delta) => {
                        if let Some(existing_arc) = result.get(ino).cloned() {
                            let mut node_clone = (*existing_arc).clone();
                            apply_delta_to_node(&mut node_clone, delta);
                            result.insert(*ino, Arc::new(node_clone));
                        } else {
                            result.insert(*ino, Arc::new(delta_to_node(delta)));
                        }
                    }
                }
            }
        }

        for (ino, entry) in live_snapshot.iter() {
            match entry {
                EntryDelta::Tombstone => {
                    result.remove(ino);
                }
                EntryDelta::Node(delta) => {
                    if let Some(existing_arc) = result.get(ino).cloned() {
                        let mut node_clone = (*existing_arc).clone();
                        apply_delta_to_node(&mut node_clone, delta);
                        result.insert(*ino, Arc::new(node_clone));
                    } else {
                        result.insert(*ino, Arc::new(delta_to_node(delta)));
                    }
                }
            }
        }

        result.retain(|_ino, arc| {
            let node = arc.as_ref();
            match node {
                Node::File { nlink, .. } | Node::Symlink { nlink, .. } => *nlink > 0,
                Node::Directory { .. } => true,
            }
        });

        result
    }

    // --- Flush & Fold Pipelines ---

    /// Freezes `live` into the `flushing` queue.
    pub fn begin_flush(&self) {
        let _dir_guard = self.dir_lock.lock().unwrap();
        let mut live_guard = self.live.write().unwrap();
        if !live_guard.is_empty() {
            let frozen = std::mem::take(&mut *live_guard);
            self.flushing.write().unwrap().push_back(frozen);
        }
    }

    pub fn current_flushing(&self) -> VecDeque<HashMap<u64, EntryDelta>> {
        self.flushing.read().unwrap().clone()
    }

    /// Merges a flushed batch into `base`.
    pub fn fold_flushed_batch(&self, flushed: HashMap<u64, EntryDelta>) {
        let mut base = self.base.write().unwrap();
        for (ino, entry) in flushed {
            match entry {
                EntryDelta::Tombstone => {
                    base.remove(&ino);
                }
                EntryDelta::Node(delta) => {
                    if let Some(existing_arc) = base.get(&ino).cloned() {
                        let mut node_clone = (*existing_arc).clone();
                        apply_delta_to_node(&mut node_clone, &delta);
                        base.insert(ino, Arc::new(node_clone));
                    } else {
                        base.insert(ino, Arc::new(delta_to_node(&delta)));
                    }
                }
            }
        }
    }

    fn synthesize_and_write_flushing_layer(
        &self,
        frozen: &mut HashMap<u64, EntryDelta>,
        writer: &LogWriter,
    ) -> std::io::Result<()> {
        // Estimate size for log rolling
        let mut estimated_bytes: u64 = RECORD_HEADER_SIZE as u64 + 64; // FlushCommit
        for entry in frozen.values() {
            match entry {
                EntryDelta::Node(NodeDelta::File(f)) => {
                    for (_, entry) in f.extents.iter() {
                        if let ExtentState::Staged { length, .. } = entry.value.read_state() {
                            estimated_bytes += RECORD_HEADER_SIZE as u64 + 32 + length as u64;
                        }
                    }
                    if f.size.is_some() || f.truncate_mask.is_some() || f.attr_delta.mode.is_some()
                    {
                        estimated_bytes += RECORD_HEADER_SIZE as u64 + 64;
                    }
                }
                EntryDelta::Node(NodeDelta::Directory(d)) => {
                    estimated_bytes +=
                        (d.added.len() + d.removed.len()) as u64 * (RECORD_HEADER_SIZE as u64 + 64);
                    if d.attr_delta.mode.is_some() {
                        estimated_bytes += RECORD_HEADER_SIZE as u64 + 64;
                    }
                }
                EntryDelta::Node(NodeDelta::Symlink(_)) => {
                    estimated_bytes += RECORD_HEADER_SIZE as u64 + 128;
                }
                EntryDelta::Tombstone => {
                    estimated_bytes += RECORD_HEADER_SIZE as u64 + 64;
                }
            }
        }
        if let Some(next_gen) = writer.roll_if_needed(estimated_bytes, &*self.clock)? {
            let mut manifest = self.manifest.write().unwrap();
            manifest.record_roll(
                next_gen,
                format!("{:06}.log", next_gen),
                self.clock.now(),
                crate::log::record::FILE_HEADER_SIZE as u64,
            );
        }

        let batch_gen = writer.generation();
        let batch_start_offset = writer.current_offset();

        let write_res = (|| -> std::io::Result<()> {
            let base_map = self.base.read().unwrap();
            let mut inos: Vec<u64> = frozen.keys().cloned().collect();
            inos.sort();

            let mut written_count = 0;
            let mut flushed_data_bytes = 0u64;
            let now = self.clock.now();

            // True when `base` already maps this exact name to this exact child. Such an
            // "addition" is not a new reference at all: it is a name that was removed and
            // put back within the batch (a rename away and back), which `add_dir_entry`
            // records as a bare addition because it clears the matching removal. Treating it
            // as real makes synthesis emit a Link, or pair it with an unrelated removal to
            // form a Rename, and either way replay ends up with the entry twice.
            let entry_already_in_base = |parent: u64, name: &str, child: u64| -> bool {
                base_map
                    .get(&parent)
                    .map(|arc| match &**arc {
                        Node::Directory { entries, .. } => {
                            entries.iter().any(|(n, c)| n == name && *c == child)
                        }
                        _ => false,
                    })
                    .unwrap_or(false)
            };

            // 1. Build map of added entries: for each new inode, record its primary creation parent
            let mut primary_creation: HashMap<u64, (u64, String)> = HashMap::new();
            let mut all_added: HashMap<u64, Vec<(u64, String)>> = HashMap::new();
            for &parent_ino in &inos {
                if let Some(EntryDelta::Node(NodeDelta::Directory(d))) = frozen.get(&parent_ino) {
                    let mut added_entries: Vec<(&String, &u64)> = d.added.iter().collect();
                    added_entries.sort_by_key(|(name, _)| *name);
                    for (name, &child_ino) in added_entries {
                        if !base_map.contains_key(&child_ino)
                            && !primary_creation.contains_key(&child_ino)
                        {
                            primary_creation.insert(child_ino, (parent_ino, name.clone()));
                            continue;
                        }
                        if entry_already_in_base(parent_ino, name, child_ino) {
                            continue;
                        }
                        all_added
                            .entry(child_ino)
                            .or_default()
                            .push((parent_ino, name.clone()));
                    }
                }
            }

            // 2. Identify Renames (paired removal + addition for an inode) vs Unlinks/Rmdirs
            let mut renamed_additions: HashSet<(u64, String)> = HashSet::new();
            let mut renames_to_emit: Vec<(u64, u64, String, u64, String, SystemTime)> = Vec::new();
            let mut unlinks_to_emit: Vec<(u64, u64, String, bool, SystemTime)> = Vec::new();

            for &parent_ino in &inos {
                let (d_removed, d_added, op_time) = match frozen.get(&parent_ino) {
                    Some(EntryDelta::Node(NodeDelta::Directory(d))) => (
                        &d.removed,
                        Some(&d.added),
                        d.attr_delta.mtime.unwrap_or(now),
                    ),
                    Some(EntryDelta::Tombstone) => {
                        static EMPTY_REMOVED: std::sync::LazyLock<HashSet<String>> =
                            std::sync::LazyLock::new(HashSet::new);
                        (&*EMPTY_REMOVED, None, now)
                    }
                    _ => continue,
                };

                let mut removed_entries: Vec<(String, u64, bool)> = Vec::new();

                if let Some(base_arc) = base_map.get(&parent_ino) {
                    let node = base_arc.as_ref();
                    if let Node::Directory { entries, .. } = node {
                        for (name, c_ino) in entries {
                            let was_removed = d_added.is_none()
                                || d_removed.contains(name)
                                || d_added
                                    .unwrap()
                                    .get(name)
                                    .map(|new_ino| new_ino != c_ino)
                                    .unwrap_or(false);
                            if was_removed {
                                let mut is_dir = false;
                                if let Some(child_arc) = base_map.get(c_ino) {
                                    if let Node::Directory { .. } = child_arc.as_ref() {
                                        is_dir = true;
                                    }
                                } else if let Some(EntryDelta::Node(NodeDelta::Directory(_))) =
                                    frozen.get(c_ino)
                                {
                                    is_dir = true;
                                }
                                removed_entries.push((name.clone(), *c_ino, is_dir));
                            }
                        }
                    }
                }

                removed_entries.sort_by(|a, b| a.0.cmp(&b.0));

                for (name, child_ino, is_dir) in removed_entries {
                    if let Some((new_parent, new_name)) =
                        all_added.get_mut(&child_ino).and_then(|v| v.pop())
                    {
                        renamed_additions.insert((new_parent, new_name.clone()));
                        renames_to_emit
                            .push((child_ino, parent_ino, name, new_parent, new_name, op_time));
                    } else {
                        unlinks_to_emit.push((child_ino, parent_ino, name, is_dir, op_time));
                    }
                }
            }

            // Phase 1: Unlinks and Rmdirs
            for (child_ino, parent_ino, name, is_dir, op_time) in unlinks_to_emit {
                if is_dir {
                    let payload = RmdirPayload {
                        parent: parent_ino,
                        name,
                        op_time,
                    };
                    let bytes = bincode::serialize(&payload)
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                    writer.append_record(OpCode::Rmdir, child_ino, &bytes)?;
                } else {
                    let payload = UnlinkPayload {
                        parent: parent_ino,
                        name,
                        op_time,
                    };
                    let bytes = bincode::serialize(&payload)
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                    writer.append_record(OpCode::Unlink, child_ino, &bytes)?;
                }
                written_count += 1;
            }

            // Phase 2: Mkdir
            for &ino in &inos {
                if let Some(EntryDelta::Node(NodeDelta::Directory(d))) = frozen.get(&ino)
                    && !base_map.contains_key(&ino)
                        && let Some((parent, name)) = primary_creation.get(&ino).cloned() {
                            let op_time = d.attr_delta.ctime.unwrap_or(now);

                            if parent >= ino && !base_map.contains_key(&parent) {
                                let tmp_name = format!(".agy_tmp_{}", ino);
                                let payload = MkdirPayload {
                                    parent: 1,
                                    name: tmp_name.clone(),
                                    mode: d.attr_delta.mode.unwrap_or(0o755),
                                    uid: d.attr_delta.uid.unwrap_or(0),
                                    gid: d.attr_delta.gid.unwrap_or(0),
                                    created_at: op_time,
                                };
                                let bytes = bincode::serialize(&payload).map_err(|e| {
                                    std::io::Error::new(std::io::ErrorKind::InvalidData, e)
                                })?;
                                writer.append_record(OpCode::Mkdir, ino, &bytes)?;
                                written_count += 1;

                                renames_to_emit.push((ino, 1, tmp_name, parent, name, op_time));
                            } else {
                                let payload = MkdirPayload {
                                    parent,
                                    name,
                                    mode: d.attr_delta.mode.unwrap_or(0o755),
                                    uid: d.attr_delta.uid.unwrap_or(0),
                                    gid: d.attr_delta.gid.unwrap_or(0),
                                    created_at: op_time,
                                };
                                let bytes = bincode::serialize(&payload).map_err(|e| {
                                    std::io::Error::new(std::io::ErrorKind::InvalidData, e)
                                })?;
                                writer.append_record(OpCode::Mkdir, ino, &bytes)?;
                                written_count += 1;
                            }
                        }
            }

            // Phase 3: Create and Symlink
            for &ino in &inos {
                match frozen.get(&ino) {
                    Some(EntryDelta::Node(NodeDelta::File(f))) => {
                        if !base_map.contains_key(&ino)
                            && let Some((parent, name)) = primary_creation.get(&ino).cloned() {
                                let op_time = f.attr_delta.ctime.unwrap_or(now);
                                let payload = CreatePayload {
                                    parent,
                                    name,
                                    mode: f.attr_delta.mode.unwrap_or(0o644),
                                    uid: f.attr_delta.uid.unwrap_or(0),
                                    gid: f.attr_delta.gid.unwrap_or(0),
                                    created_at: op_time,
                                };
                                let bytes = bincode::serialize(&payload).map_err(|e| {
                                    std::io::Error::new(std::io::ErrorKind::InvalidData, e)
                                })?;
                                writer.append_record(OpCode::Create, ino, &bytes)?;
                                written_count += 1;
                            }
                    }
                    Some(EntryDelta::Node(NodeDelta::Symlink(s))) => {
                        if !base_map.contains_key(&ino)
                            && let Some((parent, name)) = primary_creation.get(&ino).cloned() {
                                let op_time = s.attr_delta.ctime.unwrap_or(now);
                                let payload = SymlinkPayload {
                                    parent,
                                    name,
                                    target: s.target.clone().unwrap_or_default(),
                                    uid: s.attr_delta.uid.unwrap_or(0),
                                    gid: s.attr_delta.gid.unwrap_or(0),
                                    created_at: op_time,
                                };
                                let bytes = bincode::serialize(&payload).map_err(|e| {
                                    std::io::Error::new(std::io::ErrorKind::InvalidData, e)
                                })?;
                                writer.append_record(OpCode::Symlink, ino, &bytes)?;
                                written_count += 1;
                            }
                    }
                    _ => {}
                }
            }

            // Phase 4: Renames, ordered so that a rename *into* a name is emitted after the
            // rename that frees that name.
            //
            // These records are reconstructed from the batch's net effect, so the order they
            // were discovered in has nothing to do with the order they actually happened. If
            // one is replayed while its destination is still occupied, recovery treats the
            // occupant as an overwrite victim - and for a directory that means deleting it
            // outright, taking its whole subtree with it. Live never allows that (renaming
            // onto a non-empty directory is ENOTEMPTY), so it is purely an artifact of the
            // emission order.
            //
            // A name has one occupant, so each rename has at most one predecessor and this is
            // a forest rather than a general DAG.
            let mut vacated_by: HashMap<(u64, &str), usize> = HashMap::new();
            for (idx, r) in renames_to_emit.iter().enumerate() {
                vacated_by.insert((r.1, r.2.as_str()), idx);
            }
            let mut predecessor: Vec<Option<usize>> = vec![None; renames_to_emit.len()];
            for (idx, r) in renames_to_emit.iter().enumerate() {
                if let Some(&freed_by) = vacated_by.get(&(r.3, r.4.as_str()))
                    && freed_by != idx
                {
                    predecessor[idx] = Some(freed_by);
                }
            }
            let mut emitted = vec![false; renames_to_emit.len()];
            let mut ordered_renames: Vec<(u64, u64, String, u64, String, SystemTime)> =
                Vec::with_capacity(renames_to_emit.len());
            loop {
                let mut progressed = false;
                for idx in 0..renames_to_emit.len() {
                    if !emitted[idx] && predecessor[idx].is_none_or(|p| emitted[p]) {
                        emitted[idx] = true;
                        ordered_renames.push(renames_to_emit[idx].clone());
                        progressed = true;
                    }
                }
                if !progressed {
                    break;
                }
            }
            // Anything left is a dependency cycle (names swapped among themselves) - since
            // each name has exactly one occupant, every node has at most one predecessor,
            // so an unresolved component can only be a simple cycle, never a general DAG.
            // A plain sequence of Renames structurally cannot represent a cycle: whichever
            // one replays first finds its destination still occupied by a sibling that, in
            // live, had already moved on - and recovery's rename-overwrite semantics then
            // deletes that sibling for real (decrementing its nlink for a link it no longer
            // held), corrupting its link count and, once its remaining real links are later
            // unlinked, dropping it from the fs entirely even though live still has it.
            //
            // Break each cycle the same way Phase 2 breaks Mkdir ordering cycles: reroute
            // one member through a scratch name under root. That member's first hop (into
            // scratch) frees its source without needing anything freed first, which lets
            // the rest of the cycle proceed in dependency order; its second hop (scratch to
            // the real destination) runs last, once whichever rename frees that name has run.
            let mut visited = vec![false; renames_to_emit.len()];
            for start in 0..renames_to_emit.len() {
                if emitted[start] || visited[start] {
                    continue;
                }
                let mut cycle = Vec::new();
                let mut cur = start;
                while !emitted[cur] && !visited[cur] {
                    visited[cur] = true;
                    cycle.push(cur);
                    cur = predecessor[cur].expect("unresolved rename must be part of a cycle");
                }
                let breaker = cycle[0];
                let (child_ino, parent, name, new_parent, new_name, op_time) =
                    renames_to_emit[breaker].clone();
                let tmp_name = format!(".agy_tmp_rename_{}", child_ino);
                ordered_renames.push((child_ino, parent, name, 1, tmp_name.clone(), op_time));
                emitted[breaker] = true;
                for &idx in cycle[1..].iter().rev() {
                    emitted[idx] = true;
                    ordered_renames.push(renames_to_emit[idx].clone());
                }
                ordered_renames.push((child_ino, 1, tmp_name, new_parent, new_name, op_time));
            }

            for (child_ino, parent, name, new_parent, new_name, op_time) in ordered_renames {
                let payload = RenamePayload {
                    parent,
                    name,
                    new_parent,
                    new_name,
                    op_time,
                };
                let bytes = bincode::serialize(&payload)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                writer.append_record(OpCode::Rename, child_ino, &bytes)?;
                written_count += 1;
            }

            // Phase 5: Hardlinks
            for &parent_ino in &inos {
                if let Some(EntryDelta::Node(NodeDelta::Directory(d))) = frozen.get(&parent_ino) {
                    let mut added_entries: Vec<(&String, &u64)> = d.added.iter().collect();
                    added_entries.sort_by_key(|(name, _)| *name);
                    for (name, &child_ino) in added_entries {
                        if primary_creation.get(&child_ino) == Some(&(parent_ino, name.clone())) {
                            continue;
                        }
                        if renamed_additions.contains(&(parent_ino, name.clone())) {
                            continue;
                        }
                        if entry_already_in_base(parent_ino, name, child_ino) {
                            continue;
                        }
                        let child_ctime = match frozen.get(&child_ino) {
                            Some(EntryDelta::Node(NodeDelta::File(f))) => f.attr_delta.ctime,
                            Some(EntryDelta::Node(NodeDelta::Symlink(s))) => s.attr_delta.ctime,
                            Some(EntryDelta::Node(NodeDelta::Directory(cd))) => cd.attr_delta.ctime,
                            _ => None,
                        };
                        let op_time = child_ctime.or(d.attr_delta.mtime).unwrap_or(now);
                        let payload = LinkPayload {
                            ino: child_ino,
                            new_parent: parent_ino,
                            new_name: name.clone(),
                            op_time,
                        };
                        let bytes = bincode::serialize(&payload)
                            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                        writer.append_record(OpCode::Link, child_ino, &bytes)?;
                        written_count += 1;
                    }
                }
            }

            // Phase 5b: Shrinking truncates, emitted *before* the writes below.
            //
            // `apply_delta_to_node` folds a file delta as truncate(mask) -> apply extents ->
            // set size, so the log has to replay in that same order. A batch that truncates
            // down and then grows again (truncate to 3, write/extend back to 6) collapses in
            // Phase 7 into a single Setattr carrying only the *final* size, which loses the
            // shrink entirely - recovery would keep the bytes past the truncation point and
            // resurrect data the live filesystem had already dropped. Emitting the shrink as
            // its own record first reproduces the intermediate state.
            for &ino in &inos {
                if let Some(EntryDelta::Node(NodeDelta::File(f))) = frozen.get(&ino)
                    && let Some(mask) = f.truncate_mask
                    && f.size.is_some_and(|final_size| final_size > mask)
                {
                    let op_time = f.attr_delta.ctime.or(f.attr_delta.mtime).unwrap_or(now);
                    let payload = SetattrPayload {
                        mode: None,
                        uid: None,
                        gid: None,
                        size: Some(mask),
                        atime: None,
                        mtime: None,
                        op_time,
                    };
                    let bytes = bincode::serialize(&payload)
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                    writer.append_record(OpCode::Setattr, ino, &bytes)?;
                    written_count += 1;
                }
            }

            // Phase 6: Synthesize File Writes (with extent coalescing)
            for &ino in &inos {
                if !base_map.contains_key(&ino) && !primary_creation.contains_key(&ino) {
                    continue;
                }
                if let Some(EntryDelta::Node(NodeDelta::File(f))) = frozen.get_mut(&ino) {
                    if f.extents.is_empty() {
                        continue;
                    }

                    struct StagedSlice {
                        file_offset: u64,
                        data: Arc<Vec<u8>>,
                        payload_offset: u32,
                        length: u32,
                    }

                    let mut staged_slices = Vec::new();
                    for (offset, entry) in f.extents.iter() {
                        if let ExtentState::Staged {
                            data,
                            payload_offset,
                            length,
                        } = entry.value.read_state()
                        {
                            staged_slices.push(StagedSlice {
                                file_offset: *offset,
                                data,
                                payload_offset,
                                length,
                            });
                        }
                    }

                    let mut idx = 0;
                    while idx < staged_slices.len() {
                        let mut run_end = idx + 1;
                        while run_end < staged_slices.len() {
                            let prev = &staged_slices[run_end - 1];
                            let curr = &staged_slices[run_end];
                            if prev.file_offset + prev.length as u64 == curr.file_offset {
                                run_end += 1;
                            } else {
                                break;
                            }
                        }

                        let run = &staged_slices[idx..run_end];
                        let start_offset = run[0].file_offset;
                        let write_meta = WriteMeta {
                            file_offset: start_offset,
                            op_time: f.attr_delta.mtime.unwrap_or(now),
                        };
                        let mut payload = bincode::serialize(&write_meta)
                            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                        let meta_size = payload.len() as u32;

                        let mut total_length: u64 = 0;
                        for item in run {
                            total_length += item.length as u64;
                            let slice = &item.data[item.payload_offset as usize
                                ..(item.payload_offset + item.length) as usize];
                            payload.extend_from_slice(slice);
                        }

                        let (_, generation, record_log_offset) =
                            writer.append_record(OpCode::Write, ino, &payload)?;
                        written_count += 1;
                        flushed_data_bytes += total_length;

                        // Collapse the entire contiguous run into a single consolidated RangeEntry in f.extents
                        let consolidated_extent = SharedExtentState::new_disk(
                            generation,
                            record_log_offset,
                            meta_size,
                            total_length as u32,
                        );
                        f.extents
                            .insert(start_offset, total_length, consolidated_extent);

                        idx = run_end;
                    }
                }
            }

            // Phase 7: Synthesize Setattr updates
            for &ino in &inos {
                if !base_map.contains_key(&ino) && !primary_creation.contains_key(&ino) {
                    continue;
                }
                match frozen.get(&ino) {
                    Some(EntryDelta::Node(NodeDelta::File(f))) => {
                        if f.attr_delta.nlink == Some(0) {
                            continue;
                        }
                        let has_explicit_attr = f.attr_delta.mode.is_some()
                            || f.attr_delta.uid.is_some()
                            || f.attr_delta.gid.is_some()
                            || f.attr_delta.mtime.is_some()
                            || f.attr_delta.ctime.is_some()
                            || f.truncate_mask.is_some()
                            || (f.extents.is_empty() && f.size.is_some());
                        if has_explicit_attr {
                            let op_time = f.attr_delta.ctime.or(f.attr_delta.mtime).unwrap_or(now);
                            let payload = SetattrPayload {
                                mode: f.attr_delta.mode,
                                uid: f.attr_delta.uid,
                                gid: f.attr_delta.gid,
                                size: if f.truncate_mask.is_some() || f.extents.is_empty() {
                                    f.size
                                } else {
                                    None
                                },
                                atime: f.attr_delta.atime,
                                mtime: f.attr_delta.mtime,
                                op_time,
                            };
                            let bytes = bincode::serialize(&payload).map_err(|e| {
                                std::io::Error::new(std::io::ErrorKind::InvalidData, e)
                            })?;
                            writer.append_record(OpCode::Setattr, ino, &bytes)?;
                            written_count += 1;
                        }
                    }
                    Some(EntryDelta::Node(NodeDelta::Directory(d))) => {
                        if d.attr_delta.mode.is_some()
                            || d.attr_delta.uid.is_some()
                            || d.attr_delta.gid.is_some()
                            || d.attr_delta.mtime.is_some()
                            || d.attr_delta.ctime.is_some()
                        {
                            let op_time = d.attr_delta.ctime.or(d.attr_delta.mtime).unwrap_or(now);
                            let payload = SetattrPayload {
                                mode: d.attr_delta.mode,
                                uid: d.attr_delta.uid,
                                gid: d.attr_delta.gid,
                                size: None,
                                atime: d.attr_delta.atime,
                                mtime: d.attr_delta.mtime,
                                op_time,
                            };
                            let bytes = bincode::serialize(&payload).map_err(|e| {
                                std::io::Error::new(std::io::ErrorKind::InvalidData, e)
                            })?;
                            writer.append_record(OpCode::Setattr, ino, &bytes)?;
                            written_count += 1;
                        }
                    }
                    Some(EntryDelta::Node(NodeDelta::Symlink(s)))
                        if (s.attr_delta.mode.is_some()
                            || s.attr_delta.uid.is_some()
                            || s.attr_delta.gid.is_some()
                            || s.attr_delta.mtime.is_some()
                            || s.attr_delta.ctime.is_some())
                        => {
                            let op_time = s.attr_delta.ctime.or(s.attr_delta.mtime).unwrap_or(now);
                            let payload = SetattrPayload {
                                mode: s.attr_delta.mode,
                                uid: s.attr_delta.uid,
                                gid: s.attr_delta.gid,
                                size: None,
                                atime: s.attr_delta.atime,
                                mtime: s.attr_delta.mtime,
                                op_time,
                            };
                            let bytes = bincode::serialize(&payload).map_err(|e| {
                                std::io::Error::new(std::io::ErrorKind::InvalidData, e)
                            })?;
                            writer.append_record(OpCode::Setattr, ino, &bytes)?;
                            written_count += 1;
                        }
                    _ => {}
                }
            }

            drop(base_map);

            // 5. Emit FlushCommit
            writer.emit_flush_commit(written_count, &*self.clock)?;

            writer.flush()?;

            let active_gen = writer.generation();
            let active_offset = writer.current_offset();
            {
                let mut manifest = self.manifest.write().unwrap();
                if let Some(entry) = manifest.get_mut_by_generation(active_gen) {
                    entry.record_count += written_count + 1; // including FlushCommit
                    entry.total_data_bytes += flushed_data_bytes;
                    entry.total_bytes = active_offset;
                }
            }
            Ok(())
        })();

        if let Err(e) = write_res {
            let _ = writer.rollback_to(batch_gen, batch_start_offset);
            return Err(e);
        }

        Ok(())
    }

    pub fn flush_log(&self) -> std::io::Result<()> {
        let _flush_guard = self.flush_lock.lock().unwrap();
        let Some(ref writer) = self.log_writer else {
            return Ok(());
        };

        // Freeze any active live mutations into the flushing queue
        self.begin_flush();

        // Drain flushing batches from the front of the queue
        loop {
            let mut batch = {
                let mut flushing_write = self.flushing.write().unwrap();
                match flushing_write.front_mut() {
                    Some(b) => {
                        if b.is_empty() {
                            flushing_write.pop_front();
                            continue;
                        }
                        b.clone()
                    }
                    None => break,
                }
            };

            // Attempt to write and commit this batch
            self.synthesize_and_write_flushing_layer(&mut batch, writer)?;

            // On success: fold into base and pop from flushing queue
            self.fold_flushed_batch(batch);
            self.flushing.write().unwrap().pop_front();
        }

        self.staged_bytes.store(0, Ordering::Relaxed);
        self.staged_ops.store(0, Ordering::Relaxed);
        Ok(())
    }

    /// Number of frozen batches currently waiting to be written to the log.
    pub fn flush_queue_depth(&self) -> usize {
        self.flushing.read().unwrap().len()
    }

    /// Admission control for mutating operations, called before any state is changed.
    ///
    /// The flush queue only drains while the log is actually writable, so on a full or
    /// failing disk it would otherwise grow without bound while userspace still saw every
    /// write succeed - until the mount was OOM-killed and every unflushed byte was lost.
    /// Once `max_flush_queue_depth` batches have piled up, try to drain them synchronously;
    /// if that still fails, refuse the mutation so the backlog stays bounded and the error
    /// reaches userspace instead of being swallowed.
    pub fn check_flush_capacity(&self) -> Result<(), i32> {
        if self.log_writer.is_none() || self.flush_queue_depth() < self.max_flush_queue_depth {
            return Ok(());
        }
        self.flush_log().map_err(|e| {
            log::error!(
                "refusing mutation: {} flush batches queued and the log is not draining: {}",
                self.flush_queue_depth(),
                e
            );
            // Surface the real errno (e.g. ENOSPC) when there is one, EIO otherwise.
            e.raw_os_error().unwrap_or(libc::EIO)
        })
    }

    /// Increments mutation counters (ops & bytes) and triggers an automatic flush if thresholds are reached.
    pub fn notify_mutation(&self, additional_bytes: usize) {
        let staged_b = if additional_bytes > 0 {
            self.staged_bytes
                .fetch_add(additional_bytes, Ordering::Relaxed)
                + additional_bytes
        } else {
            self.staged_bytes.load(Ordering::Relaxed)
        };
        let staged_o = self.staged_ops.fetch_add(1, Ordering::Relaxed) + 1;

        if staged_b >= self.max_buffer_size || staged_o >= self.max_staged_ops {
            let _ = self.flush_log();
        }
    }

    /// Initializes background services (e.g. periodic flusher) upon FUSE mount.
    pub fn init(self: &Arc<Self>) {
        if self.is_read_only() {
            return;
        }
        let interval_secs = self.flush_interval.load(Ordering::SeqCst);
        if interval_secs > 0 {
            let self_clone = Arc::clone(self);
            let mut flusher = self.flusher.lock().unwrap();
            *flusher = Some(BackgroundFlusher::start(
                move || self_clone.flush_log(),
                Duration::from_secs(interval_secs),
            ));
            log::info!(
                "Started background periodic log flusher (interval: {} seconds)",
                interval_secs
            );
        }
    }

    /// Cleanly stops background services upon FUSE unmount.
    pub fn destroy(&self) {
        if self.is_read_only() {
            return;
        }
        let mut flusher = self.flusher.lock().unwrap();
        if let Some(mut f) = flusher.take() {
            f.stop();
        }
    }

    pub fn sync_log(&self) -> std::io::Result<()> {
        self.flush_log()?;
        if let Some(ref writer) = self.log_writer {
            writer.sync()?;
        }
        Ok(())
    }

    /// Dynamically calculates live extent statistics across all active files and log generations.
    pub fn calculate_generation_live_stats(&self) -> Vec<GenerationLiveStats> {
        let manifest = self.manifest.read().unwrap().clone();
        let base = self.base.read().unwrap();

        let mut live_map: HashMap<u64, (u64, u32)> = HashMap::new();
        for node_arc in base.values() {
            let node = node_arc.as_ref();
            if let Node::File { range_map, .. } = node {
                for (_, entry) in range_map.iter() {
                    if let ExtentState::Disk {
                        generation, length, ..
                    } = entry.value.read_state()
                    {
                        let stats = live_map.entry(generation).or_insert((0, 0));
                        stats.0 += length as u64;
                        stats.1 += 1;
                    }
                }
            }
        }

        let mut result = Vec::new();
        for log in &manifest.logs {
            let (live_bytes, live_extents) =
                live_map.get(&log.generation).copied().unwrap_or((0, 0));
            let live_ratio = if log.total_data_bytes > 0 {
                live_bytes as f64 / log.total_data_bytes as f64
            } else {
                0.0
            };
            result.push(GenerationLiveStats {
                generation: log.generation,
                filename: log.filename.clone(),
                record_count: log.record_count,
                total_bytes: log.total_bytes,
                total_data_bytes: log.total_data_bytes,
                live_bytes,
                live_extents,
                live_ratio,
            });
        }
        result
    }

    /// Performs a comprehensive, read-only integrity check of the filesystem state.
    pub fn check_integrity(
        &self,
        log_dir: Option<&Path>,
        verify_data: bool,
    ) -> crate::check::IntegrityReport {
        crate::check::check_fs_integrity(self, log_dir, verify_data)
    }

    /// Exports a single-file summary snapshot of the current in-memory filesystem state.
    pub fn export_summary(&self, log_dir: impl AsRef<Path>) -> std::io::Result<PathBuf> {
        self.sync_log()?;
        let snapshot = self.snapshot_all();
        let generation = self.log_writer.as_ref().map_or(1, |w| w.generation());
        let last_tx_id = self.log_writer.as_ref().map_or_else(
            || self.last_tx_id.load(Ordering::SeqCst),
            |w| w.last_tx_id(),
        );
        let next_inode = self.next_inode.load(Ordering::SeqCst);
        let manifest = self.manifest.read().unwrap().clone();
        let now = self.clock.now();
        crate::log::summary::export_summary_with_time(
            &snapshot, &manifest, log_dir, generation, last_tx_id, next_inode, now,
        )
    }

    /// Exports a single-file summary snapshot to a custom `Storage` instance.
    pub fn export_summary_to_storage(&self, storage: &dyn Storage) -> std::io::Result<String> {
        self.sync_log()?;
        let snapshot = self.snapshot_all();
        let generation = self.log_writer.as_ref().map_or(1, |w| w.generation());
        let last_tx_id = self.log_writer.as_ref().map_or_else(
            || self.last_tx_id.load(Ordering::SeqCst),
            |w| w.last_tx_id(),
        );
        let next_inode = self.next_inode.load(Ordering::SeqCst);
        let manifest = self.manifest.read().unwrap().clone();
        let now = self.clock.now();
        crate::log::summary::export_summary_with_time_to_storage(
            &snapshot, &manifest, storage, generation, last_tx_id, next_inode, now,
        )
    }

    pub fn sync_and_export_summary(&self) -> std::io::Result<Option<PathBuf>> {
        self.sync_log()?;
        if let Some(ref writer) = self.log_writer {
            if !writer.is_open() {
                // Read-only session where no log records were ever flushed or written
                return Ok(None);
            }
            let storage = writer.storage();
            match self.export_summary_to_storage(storage.as_ref()) {
                Ok(filename) => return Ok(Some(PathBuf::from(filename))),
                Err(e) => {
                    log::warn!("sync_and_export_summary error: {}", e);
                    return Err(e);
                }
            }
        }
        Ok(None)
    }
}

impl Drop for InMemoryFS {
    fn drop(&mut self) {
        self.destroy();
        let _ = self.sync_and_export_summary();
    }
}

impl Default for InMemoryFS {
    fn default() -> Self {
        Self::new()
    }
}

// --- Helper Functions ---

fn node_to_attr(ino: u64, node: &Node) -> FileAttr {
    match node {
        Node::Directory {
            perm,
            nlink,
            uid,
            gid,
            atime,
            mtime,
            ctime,
            ..
        } => FileAttr {
            ino,
            file_type: FileType::Directory,
            perm: *perm,
            nlink: *nlink,
            uid: *uid,
            gid: *gid,
            size: 0,
            atime: *atime,
            mtime: *mtime,
            ctime: *ctime,
        },
        Node::File {
            size,
            perm,
            nlink,
            uid,
            gid,
            atime,
            mtime,
            ctime,
            ..
        } => FileAttr {
            ino,
            file_type: FileType::RegularFile,
            perm: *perm,
            nlink: *nlink,
            uid: *uid,
            gid: *gid,
            size: *size as i64,
            atime: *atime,
            mtime: *mtime,
            ctime: *ctime,
        },
        Node::Symlink {
            target,
            nlink,
            uid,
            gid,
            atime,
            mtime,
            ctime,
        } => FileAttr {
            ino,
            file_type: FileType::Symlink,
            perm: 0o777,
            nlink: *nlink,
            uid: *uid,
            gid: *gid,
            size: target.len() as i64,
            atime: *atime,
            mtime: *mtime,
            ctime: *ctime,
        },
    }
}

fn delta_to_initial_attr(ino: u64, delta: &NodeDelta) -> FileAttr {
    match delta {
        NodeDelta::Directory(d) => {
            let mut attr = FileAttr {
                ino,
                file_type: FileType::Directory,
                perm: d.attr_delta.mode.unwrap_or(0o755),
                nlink: d.attr_delta.nlink.unwrap_or(2),
                uid: d.attr_delta.uid.unwrap_or(0),
                gid: d.attr_delta.gid.unwrap_or(0),
                size: 0,
                atime: d.attr_delta.atime.unwrap_or(SystemTime::UNIX_EPOCH),
                mtime: d.attr_delta.mtime.unwrap_or(SystemTime::UNIX_EPOCH),
                ctime: d.attr_delta.ctime.unwrap_or(SystemTime::UNIX_EPOCH),
            };
            apply_attr_delta(&mut attr, &d.attr_delta);
            attr
        }
        NodeDelta::File(f) => {
            let mut attr = FileAttr {
                ino,
                file_type: FileType::RegularFile,
                perm: f.attr_delta.mode.unwrap_or(0o644),
                nlink: f.attr_delta.nlink.unwrap_or(1),
                uid: f.attr_delta.uid.unwrap_or(0),
                gid: f.attr_delta.gid.unwrap_or(0),
                size: f.size.unwrap_or(0) as i64,
                atime: f.attr_delta.atime.unwrap_or(SystemTime::UNIX_EPOCH),
                mtime: f.attr_delta.mtime.unwrap_or(SystemTime::UNIX_EPOCH),
                ctime: f.attr_delta.ctime.unwrap_or(SystemTime::UNIX_EPOCH),
            };
            apply_attr_delta(&mut attr, &f.attr_delta);
            attr
        }
        NodeDelta::Symlink(s) => {
            let mut attr = FileAttr {
                ino,
                file_type: FileType::Symlink,
                perm: 0o777,
                nlink: s.attr_delta.nlink.unwrap_or(1),
                uid: s.attr_delta.uid.unwrap_or(0),
                gid: s.attr_delta.gid.unwrap_or(0),
                size: s.target.as_ref().map_or(0, |t| t.len() as i64),
                atime: s.attr_delta.atime.unwrap_or(SystemTime::UNIX_EPOCH),
                mtime: s.attr_delta.mtime.unwrap_or(SystemTime::UNIX_EPOCH),
                ctime: s.attr_delta.ctime.unwrap_or(SystemTime::UNIX_EPOCH),
            };
            apply_attr_delta(&mut attr, &s.attr_delta);
            attr
        }
    }
}

fn apply_node_delta(attr: &mut FileAttr, delta: &NodeDelta) {
    match delta {
        NodeDelta::Directory(d) => apply_attr_delta(attr, &d.attr_delta),
        NodeDelta::File(f) => {
            if let Some(s) = f.size {
                attr.size = s as i64;
            }
            apply_attr_delta(attr, &f.attr_delta);
        }
        NodeDelta::Symlink(s) => {
            if let Some(ref t) = s.target {
                attr.size = t.len() as i64;
            }
            apply_attr_delta(attr, &s.attr_delta);
        }
    }
}

fn apply_attr_delta(attr: &mut FileAttr, delta: &AttrDelta) {
    if let Some(m) = delta.mode {
        attr.perm = m & 0o777;
    }
    if let Some(u) = delta.uid {
        attr.uid = u;
    }
    if let Some(g) = delta.gid {
        attr.gid = g;
    }
    if let Some(n) = delta.nlink {
        attr.nlink = n;
    }
    if let Some(a) = delta.atime {
        attr.atime = a;
    }
    if let Some(m) = delta.mtime {
        attr.mtime = m;
    }
    if let Some(c) = delta.ctime {
        attr.ctime = c;
    }
}

fn merge_attr_delta(target: &mut AttrDelta, incoming: &AttrDelta) {
    if incoming.mode.is_some() {
        target.mode = incoming.mode;
    }
    if incoming.uid.is_some() {
        target.uid = incoming.uid;
    }
    if incoming.gid.is_some() {
        target.gid = incoming.gid;
    }
    if incoming.nlink.is_some() {
        target.nlink = incoming.nlink;
    }
    if incoming.atime.is_some() {
        target.atime = incoming.atime;
    }
    if incoming.mtime.is_some() {
        target.mtime = incoming.mtime;
    }
    if incoming.ctime.is_some() {
        target.ctime = incoming.ctime;
    }
}

fn apply_delta_to_node(node: &mut Node, delta: &NodeDelta) {
    match (node, delta) {
        (
            Node::Directory {
                parent,
                entries,
                perm,
                nlink,
                uid,
                gid,
                atime,
                mtime,
                ctime,
            },
            NodeDelta::Directory(d),
        ) => {
            if let Some(p) = d.parent {
                *parent = p;
            }
            for rem in &d.removed {
                entries.retain(|(name, _)| name != rem);
            }
            for (name, child_ino) in &d.added {
                entries.retain(|(existing_name, _)| existing_name != name);
                entries.push((name.clone(), *child_ino));
            }
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            if let Some(m) = d.attr_delta.mode {
                *perm = m & 0o777;
            }
            if let Some(n) = d.attr_delta.nlink {
                *nlink = n;
            }
            if let Some(u) = d.attr_delta.uid {
                *uid = u;
            }
            if let Some(g) = d.attr_delta.gid {
                *gid = g;
            }
            if let Some(a) = d.attr_delta.atime {
                *atime = a;
            }
            if let Some(m) = d.attr_delta.mtime {
                *mtime = m;
            }
            if let Some(c) = d.attr_delta.ctime {
                *ctime = c;
            }
        }
        (
            Node::File {
                range_map,
                size,
                perm,
                nlink,
                uid,
                gid,
                atime,
                mtime,
                ctime,
            },
            NodeDelta::File(f),
        ) => {
            if let Some(mask) = f.truncate_mask {
                range_map.truncate(mask);
            }
            for (start, entry) in f.extents.iter() {
                range_map.insert(*start, entry.length, entry.value.clone());
            }
            if let Some(s) = f.size {
                *size = s;
            }
            if let Some(m) = f.attr_delta.mode {
                *perm = m & 0o777;
            }
            if let Some(n) = f.attr_delta.nlink {
                *nlink = n;
            }
            if let Some(u) = f.attr_delta.uid {
                *uid = u;
            }
            if let Some(g) = f.attr_delta.gid {
                *gid = g;
            }
            if let Some(a) = f.attr_delta.atime {
                *atime = a;
            }
            if let Some(m) = f.attr_delta.mtime {
                *mtime = m;
            }
            if let Some(c) = f.attr_delta.ctime {
                *ctime = c;
            }
        }
        (
            Node::Symlink {
                target,
                nlink,
                uid,
                gid,
                atime,
                mtime,
                ctime,
            },
            NodeDelta::Symlink(s),
        ) => {
            if let Some(ref t) = s.target {
                *target = t.clone();
            }
            if let Some(n) = s.attr_delta.nlink {
                *nlink = n;
            }
            if let Some(u) = s.attr_delta.uid {
                *uid = u;
            }
            if let Some(g) = s.attr_delta.gid {
                *gid = g;
            }
            if let Some(a) = s.attr_delta.atime {
                *atime = a;
            }
            if let Some(m) = s.attr_delta.mtime {
                *mtime = m;
            }
            if let Some(c) = s.attr_delta.ctime {
                *ctime = c;
            }
        }
        _ => {}
    }
}

fn delta_to_node(delta: &NodeDelta) -> Node {
    match delta {
        NodeDelta::Directory(d) => {
            let mut entries: Vec<(String, u64)> =
                d.added.iter().map(|(k, v)| (k.clone(), *v)).collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            Node::Directory {
                parent: d.parent.unwrap_or(1),
                entries,
                perm: d.attr_delta.mode.unwrap_or(0o755),
                nlink: d.attr_delta.nlink.unwrap_or(2),
                uid: d.attr_delta.uid.unwrap_or(0),
                gid: d.attr_delta.gid.unwrap_or(0),
                atime: d.attr_delta.atime.unwrap_or(SystemTime::UNIX_EPOCH),
                mtime: d.attr_delta.mtime.unwrap_or(SystemTime::UNIX_EPOCH),
                ctime: d.attr_delta.ctime.unwrap_or(SystemTime::UNIX_EPOCH),
            }
        }
        NodeDelta::File(f) => {
            let mut range_map = RangeMap::new();
            for (start, entry) in f.extents.iter() {
                range_map.insert(*start, entry.length, entry.value.clone());
            }
            Node::File {
                range_map,
                size: f.size.unwrap_or(0),
                perm: f.attr_delta.mode.unwrap_or(0o644),
                nlink: f.attr_delta.nlink.unwrap_or(1),
                uid: f.attr_delta.uid.unwrap_or(0),
                gid: f.attr_delta.gid.unwrap_or(0),
                atime: f.attr_delta.atime.unwrap_or(SystemTime::UNIX_EPOCH),
                mtime: f.attr_delta.mtime.unwrap_or(SystemTime::UNIX_EPOCH),
                ctime: f.attr_delta.ctime.unwrap_or(SystemTime::UNIX_EPOCH),
            }
        }
        NodeDelta::Symlink(s) => Node::Symlink {
            target: s.target.clone().unwrap_or_default(),
            nlink: s.attr_delta.nlink.unwrap_or(1),
            uid: s.attr_delta.uid.unwrap_or(0),
            gid: s.attr_delta.gid.unwrap_or(0),
            atime: s.attr_delta.atime.unwrap_or(SystemTime::UNIX_EPOCH),
            mtime: s.attr_delta.mtime.unwrap_or(SystemTime::UNIX_EPOCH),
            ctime: s.attr_delta.ctime.unwrap_or(SystemTime::UNIX_EPOCH),
        },
    }
}

pub fn find_parent_inode(fs: &InMemoryFS, child_ino: u64) -> Option<u64> {
    fs.get_parent_dir_inode(child_ino)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::LogWriter;
    use crate::operations::read_write::write_core;

    #[test]
    fn test_flush_coalesces_micro_writes_into_single_base_range_entry() {
        let temp_dir = tempfile::tempdir().unwrap();
        let clock = SystemClock;
        let writer = Arc::new(LogWriter::create(temp_dir.path(), 1024 * 1024, &clock).unwrap());
        let fs = InMemoryFS::with_log(writer);

        let ino = fs.allocate_inode();
        fs.insert_new_node(
            ino,
            NodeDelta::File(FileDelta {
                attr_delta: AttrDelta {
                    mode: Some(0o644),
                    nlink: Some(1),
                    ..Default::default()
                },
                ..Default::default()
            }),
        );
        fs.add_dir_entry(1, "micro.txt", ino, std::time::SystemTime::now());

        // Perform 50 sequential 1-byte writes in live
        for i in 0..50u64 {
            let byte = vec![(i % 256) as u8];
            write_core(&fs, ino, &byte, i as i64).unwrap();
        }

        // Verify that live has 50 individual extent entries before flush
        {
            let live = fs.live.read().unwrap();
            if let Some(EntryDelta::Node(NodeDelta::File(f))) = live.get(&ino) {
                assert_eq!(f.extents.len(), 50);
            } else {
                panic!("File not found in live layer");
            }
        }

        // Flush to disk and fold into base
        fs.sync_log().unwrap();

        // Verify that base has exactly 1 consolidated extent of length 50
        {
            let base = fs.base.read().unwrap();
            let node_arc = base.get(&ino).expect("inode missing in base");
            let node = node_arc.as_ref();
            if let Node::File {
                range_map, size, ..
            } = node
            {
                assert_eq!(*size, 50);
                assert_eq!(
                    range_map.len(),
                    1,
                    "Expected exactly 1 consolidated RangeEntry in base!"
                );
                let (start, entry) = range_map.iter().next().unwrap();
                assert_eq!(*start, 0);
                assert_eq!(entry.length, 50);
                assert!(matches!(
                    entry.value.read_state(),
                    crate::log::ExtentState::Disk { length: 50, .. }
                ));
            } else {
                panic!("Expected Node::File in base");
            }
        }

        // Read back data to ensure integrity
        let data = fs.read_file_data(ino, 0, 50).unwrap();
        let expected: Vec<u8> = (0..50u8).collect();
        assert_eq!(data, expected);
    }

    #[test]
    fn test_directory_parent_tracking_across_mkdir_rename_and_flush() {
        let clock = Arc::new(crate::clock::MockClock(SystemTime::UNIX_EPOCH));
        let fs = InMemoryFS::with_clock(clock);

        // Root inode 1 parent is 1
        assert_eq!(fs.get_parent_dir_inode(1), Some(1));

        // Create dir1 (child of root)
        let dir1 = crate::operations::dir::mkdir_core(&fs, 1, "dir1", 0o755, 1000, 1000)
            .unwrap()
            .ino;
        assert_eq!(fs.get_parent_dir_inode(dir1), Some(1));

        // Create dir2 (child of dir1)
        let dir2 = crate::operations::dir::mkdir_core(&fs, dir1, "dir2", 0o755, 1000, 1000)
            .unwrap()
            .ino;
        assert_eq!(fs.get_parent_dir_inode(dir2), Some(dir1));

        // Create dir3 (child of root)
        let dir3 = crate::operations::dir::mkdir_core(&fs, 1, "dir3", 0o755, 1000, 1000)
            .unwrap()
            .ino;
        assert_eq!(fs.get_parent_dir_inode(dir3), Some(1));

        // Move dir2 from dir1 into dir3
        crate::operations::links::rename_core(&fs, dir1, "dir2", dir3, "dir2_moved").unwrap();
        assert_eq!(fs.get_parent_dir_inode(dir2), Some(dir3));

        // Fold live to base
        fs.begin_flush();
        while let Some(batch) = fs.flushing.write().unwrap().pop_front() {
            fs.fold_flushed_batch(batch);
        }

        // Verify parent relations are preserved in base after fold
        assert_eq!(fs.get_parent_dir_inode(1), Some(1));
        assert_eq!(fs.get_parent_dir_inode(dir1), Some(1));
        assert_eq!(fs.get_parent_dir_inode(dir3), Some(1));
        assert_eq!(fs.get_parent_dir_inode(dir2), Some(dir3));
    }

    #[test]
    fn test_generation_live_stats_and_manifest_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(SystemClock);
        let writer = Arc::new(LogWriter::create(dir.path(), 1, &*clock).unwrap());
        let fs = InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));

        let ino1 = fs.allocate_inode();
        fs.base.write().unwrap().insert(
            ino1,
            Arc::new(Node::File {
                range_map: RangeMap::new(),
                size: 0,
                perm: 0o644,
                nlink: 1,
                uid: 1000,
                gid: 1000,
                atime: clock.now(),
                mtime: clock.now(),
                ctime: clock.now(),
            }),
        );
        fs.add_dir_entry(1, "file1.bin", ino1, clock.now());

        // Write 100 bytes to file1 in gen 1
        let data1 = vec![0xAA; 100];
        crate::operations::read_write::write_core(&fs, ino1, &data1, 0).unwrap();
        fs.sync_log().unwrap();

        // Check manifest and stats after gen 1 write
        let stats = fs.calculate_generation_live_stats();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].generation, 1);
        assert_eq!(stats[0].filename, "000001.log");
        assert_eq!(stats[0].total_data_bytes, 100);
        assert_eq!(stats[0].live_bytes, 100);
        assert_eq!(stats[0].live_extents, 1);
        assert!((stats[0].live_ratio - 1.0).abs() < 1e-6);

        // Overwrite 40 bytes of file1 (offset 0..40)
        let overwrite_data = vec![0xBB; 40];
        crate::operations::read_write::write_core(&fs, ino1, &overwrite_data, 0).unwrap();
        fs.sync_log().unwrap();

        // Now gen 1 only has 60 live bytes (offset 40..100) and gen 1 total data is 140 bytes
        let stats = fs.calculate_generation_live_stats();
        assert_eq!(stats[0].total_data_bytes, 140);
        assert_eq!(stats[0].live_bytes, 100); // 60 from 1st write + 40 from 2nd write (both landed in gen 1)
        assert_eq!(stats[0].live_extents, 2);
        assert!((stats[0].live_ratio - (100.0 / 140.0)).abs() < 1e-6);

        // Export summary snapshot
        let summary_path = fs.export_summary(dir.path()).unwrap();
        assert!(summary_path.exists());

        // Recover filesystem and verify manifest is restored identically
        let recovered = crate::log::recover_fs(dir.path()).unwrap();
        let recovered_stats = recovered.calculate_generation_live_stats();
        assert_eq!(recovered_stats.len(), 1);
        assert_eq!(recovered_stats[0].generation, 1);
        assert_eq!(recovered_stats[0].total_data_bytes, 140);
        assert_eq!(recovered_stats[0].live_bytes, 100);
        assert_eq!(recovered_stats[0].live_extents, 2);
    }

    #[test]
    fn test_rm_rf_directory_tree_emits_unlinks_for_all_children_and_recovers_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(SystemClock);
        let writer = Arc::new(LogWriter::create(dir.path(), 1, &*clock).unwrap());
        let fs = InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));

        // 1. Create /Gletscher, /Gletscher/sub, and files
        let gletscher_attr =
            crate::operations::dir::mkdir_core(&fs, 1, "Gletscher", 0o755, 1000, 1000).unwrap();
        let gletscher_ino = gletscher_attr.ino;

        let file1_attr = crate::operations::read_write::create_core(
            &fs,
            gletscher_ino,
            "file1.txt",
            0o644,
            0,
            1000,
            1000,
        )
        .unwrap();
        crate::operations::read_write::write_core(&fs, file1_attr.ino, &[1, 2, 3, 4], 0).unwrap();

        let file2_attr = crate::operations::read_write::create_core(
            &fs,
            gletscher_ino,
            "file2.txt",
            0o644,
            0,
            1000,
            1000,
        )
        .unwrap();
        crate::operations::read_write::write_core(&fs, file2_attr.ino, &[5, 6, 7, 8], 0).unwrap();

        let sub_attr =
            crate::operations::dir::mkdir_core(&fs, gletscher_ino, "sub", 0o755, 1000, 1000)
                .unwrap();
        let sub_ino = sub_attr.ino;

        let file3_attr = crate::operations::read_write::create_core(
            &fs,
            sub_ino,
            "file3.txt",
            0o644,
            0,
            1000,
            1000,
        )
        .unwrap();
        crate::operations::read_write::write_core(&fs, file3_attr.ino, &[9, 10, 11, 12], 0)
            .unwrap();

        // Flush creation to disk
        fs.sync_log().unwrap();

        // Verify live stats show 3 files and 12 live bytes
        let stats_before = fs.calculate_generation_live_stats();
        assert_eq!(stats_before[0].live_bytes, 12);
        assert_eq!(stats_before[0].live_extents, 3);

        // 2. Perform rm -rf /Gletscher
        crate::operations::links::unlink_core(&fs, sub_ino, "file3.txt").unwrap();
        crate::operations::dir::rmdir_core(&fs, gletscher_ino, "sub").unwrap();
        crate::operations::links::unlink_core(&fs, gletscher_ino, "file1.txt").unwrap();
        crate::operations::links::unlink_core(&fs, gletscher_ino, "file2.txt").unwrap();
        crate::operations::dir::rmdir_core(&fs, 1, "Gletscher").unwrap();

        // Flush deletion to disk
        fs.sync_log().unwrap();

        // Check live stats in memory
        let stats_after = fs.calculate_generation_live_stats();
        assert_eq!(stats_after[0].live_bytes, 0);
        assert_eq!(stats_after[0].live_extents, 0);

        // 3. Inspect the log dump to verify Unlink and Rmdir records were written
        let log_file = dir.path().join("000001.log");
        let dump_text = crate::dump::dump_log_file(&log_file, 1).unwrap();
        assert!(dump_text.contains("Unlink"));
        assert!(dump_text.contains("Rmdir"));
        assert!(dump_text.contains("file1.txt"));
        assert!(dump_text.contains("file2.txt"));
        assert!(dump_text.contains("file3.txt"));
        assert!(dump_text.contains("Gletscher"));
        assert!(dump_text.contains("sub"));

        // 4. Recover filesystem and verify no orphaned nodes remain
        let recovered = crate::log::recover_fs(dir.path()).unwrap();
        let base = recovered.base.read().unwrap();
        assert_eq!(base.len(), 1); // ONLY root directory (inode 1) remains!
        assert!(base.contains_key(&1));

        let rec_stats = recovered.calculate_generation_live_stats();
        assert_eq!(rec_stats[0].live_bytes, 0);
        assert_eq!(rec_stats[0].live_extents, 0);
    }

    #[test]
    fn test_hardlink_survives_rm_rf_of_other_parent_directory() {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(SystemClock);
        let writer = Arc::new(LogWriter::create(dir.path(), 1, &*clock).unwrap());
        let fs = InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));

        // 1. Create /keep and /Gletscher directories
        let keep_attr =
            crate::operations::dir::mkdir_core(&fs, 1, "keep", 0o755, 1000, 1000).unwrap();
        let gletscher_attr =
            crate::operations::dir::mkdir_core(&fs, 1, "Gletscher", 0o755, 1000, 1000).unwrap();

        // 2. Create /keep/shared.txt (inode N, nlink 1) and write data
        let file_attr = crate::operations::read_write::create_core(
            &fs,
            keep_attr.ino,
            "shared.txt",
            0o644,
            0,
            1000,
            1000,
        )
        .unwrap();
        crate::operations::read_write::write_core(
            &fs,
            file_attr.ino,
            b"persistent shared content",
            0,
        )
        .unwrap();

        // 3. Create hard link /Gletscher/shared_link.txt -> inode N (nlink becomes 2)
        let link_attr = crate::operations::links::link_core(
            &fs,
            file_attr.ino,
            gletscher_attr.ino,
            "shared_link.txt",
        )
        .unwrap();
        assert_eq!(link_attr.nlink, 2);

        // Commit everything to disk
        fs.sync_log().unwrap();

        let stats1 = fs.calculate_generation_live_stats();
        assert_eq!(stats1[0].live_bytes, 25);
        assert_eq!(stats1[0].live_extents, 1);

        // 4. Delete /Gletscher via rm -rf (/Gletscher/shared_link.txt unlinked, /Gletscher rmdir'd)
        crate::operations::links::unlink_core(&fs, gletscher_attr.ino, "shared_link.txt").unwrap();
        crate::operations::dir::rmdir_core(&fs, 1, "Gletscher").unwrap();

        // Verify that /keep/shared.txt still has nlink 1 in memory
        let keep_file_attr = fs.get_attr(file_attr.ino).unwrap();
        assert_eq!(keep_file_attr.nlink, 1);

        // Commit deletion to disk
        fs.sync_log().unwrap();

        // Check in-memory live stats: data is STILL alive because /keep/shared.txt exists!
        let stats2 = fs.calculate_generation_live_stats();
        assert_eq!(stats2[0].live_bytes, 25);
        assert_eq!(stats2[0].live_extents, 1);

        // 5. Crash-recovery: Recover filesystem and verify /keep/shared.txt survived with full data!
        let recovered = crate::log::recover_fs(dir.path()).unwrap();
        let rec_file_attr = recovered
            .get_attr(file_attr.ino)
            .expect("shared.txt must survive recovery");
        assert_eq!(rec_file_attr.nlink, 1);

        let data =
            crate::operations::read_write::read_core(&recovered, file_attr.ino, 25, 0).unwrap();
        assert_eq!(&data, b"persistent shared content");

        let rec_stats = recovered.calculate_generation_live_stats();
        assert_eq!(rec_stats[0].live_bytes, 25);
        assert_eq!(rec_stats[0].live_extents, 1);
    }

    #[test]
    fn test_exists_below_live_sees_a_tombstone_frozen_out_of_live() {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(SystemClock);
        let writer = Arc::new(LogWriter::create(dir.path(), 1, &*clock).unwrap());
        let fs = InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));

        let attr =
            crate::operations::read_write::create_core(&fs, 1, "f.txt", 0o644, 0, 1000, 1000)
                .unwrap();
        fs.sync_log().unwrap();
        assert!(fs.exists_below_live(attr.ino));

        crate::operations::links::unlink_core(&fs, 1, "f.txt").unwrap();
        assert!(
            fs.exists_below_live(attr.ino),
            "base still describes the inode until the tombstone's batch folds"
        );

        // Freeze the tombstone out of `live`. From here `live.entry(ino)` sees nothing, so
        // a writer that validated before taking the lock would insert a fresh delta and
        // resurrect the inode at the next fold - this predicate is what stops it.
        fs.begin_flush();
        assert!(!fs.live.read().unwrap().contains_key(&attr.ino));
        assert!(
            !fs.exists_below_live(attr.ino),
            "a tombstone frozen out of live must still report the inode as gone"
        );
    }

    #[test]
    fn test_attr_update_does_not_resurrect_a_tombstoned_inode() {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(SystemClock);
        let writer = Arc::new(LogWriter::create(dir.path(), 1, &*clock).unwrap());
        let fs = InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));

        let attr =
            crate::operations::read_write::create_core(&fs, 1, "f.txt", 0o644, 0, 1000, 1000)
                .unwrap();
        // Fold it into `base`, so the lower layers still describe the inode after deletion.
        fs.sync_log().unwrap();
        crate::operations::links::unlink_core(&fs, 1, "f.txt").unwrap();
        assert!(fs.get_attr(attr.ino).is_none(), "unlinked file must be gone");

        // A late attribute update - an atime bump racing the unlink, say - must not rebuild
        // the node from `base` and bring it back carrying its old link count, unreferenced
        // by any directory.
        fs.update_attr_delta(
            attr.ino,
            AttrDelta {
                atime: Some(clock.now()),
                ..Default::default()
            },
        );
        assert!(
            fs.get_attr(attr.ino).is_none(),
            "attribute update resurrected a deleted inode"
        );
        assert!(
            !fs.snapshot_all().contains_key(&attr.ino),
            "resurrected inode leaked into the snapshot as an orphan"
        );
    }

    #[test]
    fn test_mutation_threshold_triggers_automatic_flush() {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(SystemClock);
        let writer = Arc::new(LogWriter::create(dir.path(), 1, &*clock).unwrap());
        let mut fs = InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));
        // Set small operation threshold of 5 ops
        fs.max_staged_ops = 5;

        // Perform 4 create operations - not flushed yet
        for i in 0..4 {
            let name = format!("file_{}.txt", i);
            crate::operations::read_write::create_core(&fs, 1, &name, 0o644, 0, 1000, 1000)
                .unwrap();
        }
        assert_eq!(fs.staged_ops.load(Ordering::SeqCst), 4);
        assert_eq!(fs.manifest.read().unwrap().logs[0].record_count, 0);

        // 5th operation reaches threshold and triggers automatic flush!
        crate::operations::read_write::create_core(&fs, 1, "file_4.txt", 0o644, 0, 1000, 1000)
            .unwrap();

        // Staged ops reset to 0 after automatic flush
        assert_eq!(fs.staged_ops.load(Ordering::SeqCst), 0);
        assert_eq!(fs.manifest.read().unwrap().logs[0].record_count, 12); // 5 creates + 6 setattrs + 1 FlushCommit
    }

    #[test]
    fn test_unlinked_open_file_does_not_resurrect_on_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(SystemClock);
        let writer = Arc::new(LogWriter::create(dir.path(), 1, &*clock).unwrap());
        let fs = InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));

        // Create a temp file
        let file_attr = crate::operations::read_write::create_core(
            &fs,
            1,
            "temp_scratch.bin",
            0o644,
            0,
            1000,
            1000,
        )
        .unwrap();
        let ino = file_attr.ino;

        // Open handle (like a POSIX process keeping file open)
        *fs.open_handles.write().unwrap().entry(ino).or_insert(0) += 1;

        // Write data
        crate::operations::read_write::write_core(&fs, ino, &[0xCC; 128], 0).unwrap();

        // Unlink while open in same live batch
        crate::operations::links::unlink_core(&fs, 1, "temp_scratch.bin").unwrap();

        // Flush log to disk
        fs.sync_log().unwrap();

        // Recover filesystem from log
        let recovered = crate::log::recover_fs(dir.path()).unwrap();
        let base = recovered.base.read().unwrap();

        // Only root inode (1) should exist; NO resurrected /file_{ino} or phantom entries!
        assert_eq!(base.len(), 1, "Expected only root inode in base");
        assert!(base.contains_key(&1));
        assert!(!base.contains_key(&ino));

        let entries = recovered.list_directory(1).unwrap();
        assert!(
            entries.is_empty(),
            "Root directory must be completely empty"
        );
    }

    #[test]
    fn test_truncate_down_then_extend_across_flush_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(SystemClock);
        let writer = Arc::new(LogWriter::create(dir.path(), 1, &*clock).unwrap());
        let fs = InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));

        // Create file and write 100 bytes (0xAA)
        let file_attr =
            crate::operations::read_write::create_core(&fs, 1, "data.bin", 0o644, 0, 1000, 1000)
                .unwrap();
        let ino = file_attr.ino;
        crate::operations::read_write::write_core(&fs, ino, &[0xAA; 100], 0).unwrap();

        // Truncate down to 20 bytes
        let now = clock.now();
        crate::operations::read_write::setattr_core(
            &fs,
            ino,
            0,
            0,
            0,
            20,
            now,
            now,
            crate::operations::read_write::FUSE_SET_ATTR_SIZE,
        )
        .unwrap();

        // Flush down-truncation to disk (so base layer now holds the 20-byte state)
        fs.sync_log().unwrap();

        // Extend file size to 100 bytes in a NEW live delta layer without writing bytes
        crate::operations::read_write::setattr_core(
            &fs,
            ino,
            0,
            0,
            0,
            100,
            now,
            now,
            crate::operations::read_write::FUSE_SET_ATTR_SIZE,
        )
        .unwrap();

        // Read all 100 bytes: [0..20] must be 0xAA, [20..100] must be zeroes (0x00), NOT stale data!
        let read_data = crate::operations::read_write::read_core(&fs, ino, 100, 0).unwrap();
        assert_eq!(read_data.len(), 100);
        assert_eq!(&read_data[0..20], &[0xAA; 20]);
        assert_eq!(
            &read_data[20..100],
            &[0x00; 80],
            "Stale data must not survive truncate-down across flush!"
        );

        // Flush and verify reading again from base
        fs.sync_log().unwrap();
        let read_data_after_flush =
            crate::operations::read_write::read_core(&fs, ino, 100, 0).unwrap();
        assert_eq!(&read_data_after_flush[0..20], &[0xAA; 20]);
        assert_eq!(&read_data_after_flush[20..100], &[0x00; 80]);
    }

    #[test]
    fn test_multi_batch_flushing_queue_and_layer_resolution() {
        let clock = Arc::new(SystemClock);
        let fs = InMemoryFS::with_clock(clock.clone());

        // 1. Create file in batch 1
        let f =
            crate::operations::read_write::create_core(&fs, 1, "test.txt", 0o644, 0, 1000, 1000)
                .unwrap();
        let ino = f.ino;
        crate::operations::read_write::write_core(&fs, ino, &[0x11; 50], 0).unwrap();

        // Freeze into flushing queue (batch 1)
        fs.begin_flush();
        assert_eq!(fs.flushing.read().unwrap().len(), 1);

        // 2. Overwrite in batch 2 (live layer)
        crate::operations::read_write::write_core(&fs, ino, &[0x22; 20], 10).unwrap();

        // Freeze into flushing queue (batch 2)
        fs.begin_flush();
        assert_eq!(fs.flushing.read().unwrap().len(), 2);

        // 3. In live layer, truncate to 40 bytes
        let now = clock.now();
        crate::operations::read_write::setattr_core(
            &fs,
            ino,
            0,
            0,
            0,
            40,
            now,
            now,
            crate::operations::read_write::FUSE_SET_ATTR_SIZE,
        )
        .unwrap();

        // Verify read across live -> batch 2 -> batch 1 -> base
        let data = fs.read_file_data(ino, 0, 50).unwrap();
        assert_eq!(data.len(), 40);
        assert_eq!(&data[0..10], &[0x11; 10]);
        assert_eq!(&data[10..30], &[0x22; 20]);
        assert_eq!(&data[30..40], &[0x11; 10]);

        // Drain flushing batches into base
        while let Some(batch) = fs.flushing.write().unwrap().pop_front() {
            fs.fold_flushed_batch(batch);
        }
        assert_eq!(fs.flushing.read().unwrap().len(), 0);

        // Read again after folding
        let data_after_fold = fs.read_file_data(ino, 0, 50).unwrap();
        assert_eq!(data_after_fold, data);
    }

    #[test]
    fn test_flush_io_error_retries_and_does_not_wedge() {
        let mem = Arc::new(crate::storage::MemoryStorage::new());
        let fault_storage = crate::storage::FaultStorage::new(mem);
        let storage = Arc::new(fault_storage.clone());

        crate::log::init_volume_with_storage(storage.clone(), Some("main")).unwrap();

        let clock = Arc::new(SystemClock);
        // Set tiny max_log_size (50 bytes) so the next flush rolls to 000002.log
        let writer = Arc::new(
            LogWriter::create_with_storage(storage.clone(), 1, &*clock, 50, 1).unwrap(),
        );
        let mut fs = InMemoryFS::with_clock_and_storage(clock.clone(), storage.clone());
        fs.log_writer = Some(writer);

        // 1. First batch: write data to file1 and flush (populates gen 1 past header size)
        let f1 =
            crate::operations::read_write::create_core(&fs, 1, "file1.txt", 0o644, 0, 1000, 1000)
                .unwrap();
        crate::operations::read_write::write_core(&fs, f1.ino, b"initial payload", 0).unwrap();
        fs.flush_log().unwrap();

        // 2. Second batch: write data to file2
        let f2 =
            crate::operations::read_write::create_core(&fs, 1, "file2.txt", 0o644, 0, 1000, 1000)
                .unwrap();
        crate::operations::read_write::write_core(&fs, f2.ino, b"second payload", 0).unwrap();

        // 3. Inject permission error on opening 000002.log to simulate I/O failure when rolling
        fault_storage.fail_on_file("000002.log", std::io::ErrorKind::PermissionDenied);

        // 4. Attempt flush - should fail with I/O error on roll creation
        let flush_res = fs.flush_log();
        assert!(
            flush_res.is_err(),
            "Expected flush_log to fail on simulated I/O error"
        );

        // Verify filesystem is NOT wedged: flushing queue still retains the batch, live mutations still work!
        assert_eq!(
            fs.flushing.read().unwrap().len(),
            1,
            "Failed batch must remain in flushing queue"
        );

        // Live operations continue working smoothly
        let f3 =
            crate::operations::read_write::create_core(&fs, 1, "file3.txt", 0o644, 0, 1000, 1000)
                .unwrap();
        crate::operations::read_write::write_core(&fs, f3.ino, b"third payload", 0).unwrap();

        // 5. Restore normal write access by clearing injected fault
        fault_storage.clear_fail_on_file("000002.log");

        // 6. Retry flush - must succeed and drain ALL batches
        let retry_res = fs.flush_log();
        assert!(
            retry_res.is_ok(),
            "Retried flush must succeed once I/O is restored: {:?}",
            retry_res
        );
        assert_eq!(
            fs.flushing.read().unwrap().len(),
            0,
            "Flushing queue must be completely drained"
        );

        // Verify all three files are intact in memory and base
        let d1 = crate::operations::read_write::read_core(&fs, f1.ino, 15, 0).unwrap();
        assert_eq!(&d1, b"initial payload");
        let d2 = crate::operations::read_write::read_core(&fs, f2.ino, 14, 0).unwrap();
        assert_eq!(&d2, b"second payload");
        let d3 = crate::operations::read_write::read_core(&fs, f3.ino, 13, 0).unwrap();
        assert_eq!(&d3, b"third payload");

        // 7. Crash-recovery: Recover filesystem and verify all files recovered cleanly
        let recovered = crate::log::recover_fs_with_storage(storage.clone()).unwrap();
        assert!(recovered.get_attr(f1.ino).is_some());
        assert!(recovered.get_attr(f2.ino).is_some());
        assert!(recovered.get_attr(f3.ino).is_some());
        let rec_d1 = crate::operations::read_write::read_core(&recovered, f1.ino, 15, 0).unwrap();
        assert_eq!(&rec_d1, b"initial payload");
        let rec_d2 = crate::operations::read_write::read_core(&recovered, f2.ino, 14, 0).unwrap();
        assert_eq!(&rec_d2, b"second payload");
        let rec_d3 = crate::operations::read_write::read_core(&recovered, f3.ino, 13, 0).unwrap();
        assert_eq!(&rec_d3, b"third payload");
    }

    #[test]
    fn test_flush_mid_batch_failure_rolls_back_and_retries_cleanly() {
        let mem = Arc::new(crate::storage::MemoryStorage::new());
        let fault_storage = crate::storage::FaultStorage::new(mem);
        let storage = Arc::new(fault_storage.clone());
        let clock = Arc::new(SystemClock);
        let writer = Arc::new(
            LogWriter::create_with_storage(
                storage.clone(),
                1,
                &*clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
            )
            .unwrap(),
        );
        let fs = InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));

        // 1. Initial batch with 2 files flushed cleanly
        let mut initial_inos = Vec::new();
        for i in 1..=2 {
            let name = format!("init_{}.txt", i);
            let f = crate::operations::read_write::create_core(&fs, 1, &name, 0o644, 0, 1000, 1000)
                .unwrap();
            crate::operations::read_write::write_core(&fs, f.ino, b"initial payload", 0).unwrap();
            initial_inos.push(f.ino);
        }
        fs.flush_log().unwrap();

        let initial_offset = storage.file_len("000001.log").unwrap();

        // 2. Stage a second batch with 8 files
        let mut batch2_inos = Vec::new();
        for i in 1..=8 {
            let name = format!("batch2_file_{}.bin", i);
            let f = crate::operations::read_write::create_core(&fs, 1, &name, 0o644, 0, 1000, 1000)
                .unwrap();
            let payload = vec![(i as u8) * 0x11; 128];
            crate::operations::read_write::write_core(&fs, f.ino, &payload, 0).unwrap();
            batch2_inos.push((f.ino, payload));
        }

        // 3. Set fault threshold slightly larger than initial_offset to force simulated ENOSPC mid-batch with partial torn write
        fault_storage.fail_writes_after_bytes(initial_offset + 300, true);

        // 4. Attempt flush - MUST fail with simulated mid-record write error
        let flush_res = fs.flush_log();
        assert!(
            flush_res.is_err(),
            "Expected flush to fail with simulated mid-record write error"
        );

        // 5. Verify the file in storage was rolled back to initial_offset!
        let rolled_back_len = storage.file_len("000001.log").unwrap();
        assert_eq!(
            rolled_back_len, initial_offset,
            "Log file must be rolled back to batch_start_offset on mid-batch failure"
        );

        // 6. Clear fault injection
        fault_storage.clear_write_limit();

        // 7. Retry flush - MUST succeed cleanly
        let retry_res = fs.flush_log();
        assert!(
            retry_res.is_ok(),
            "Retried flush must succeed: {:?}",
            retry_res
        );
        assert_eq!(fs.flushing.read().unwrap().len(), 0);

        // 8. Recover filesystem and verify 100% data integrity without checksum mismatches!
        let recovered = crate::log::recover_fs_with_storage(storage.clone())
            .expect("Recovery must succeed cleanly");
        for ino in initial_inos {
            assert!(recovered.get_attr(ino).is_some());
            let d = crate::operations::read_write::read_core(&recovered, ino, 15, 0).unwrap();
            assert_eq!(&d, b"initial payload");
        }
        for (ino, payload) in batch2_inos {
            assert!(recovered.get_attr(ino).is_some());
            let d = crate::operations::read_write::read_core(&recovered, ino, payload.len(), 0)
                .unwrap();
            assert_eq!(d, payload);
        }

        let report = crate::check::check_volume_with_storage(storage, true).unwrap();
        assert!(
            report.is_clean(),
            "Integrity check must be clean: {:?}",
            report.issues
        );
    }

    #[test]
    fn test_flush_queue_is_bounded_and_reports_failure_when_log_stops_draining() {
        let mem = Arc::new(crate::storage::MemoryStorage::new());
        let fault_storage = crate::storage::FaultStorage::new(mem);
        let storage = Arc::new(fault_storage.clone());
        let clock = Arc::new(SystemClock);
        let writer = Arc::new(
            LogWriter::create_with_storage(
                storage.clone(),
                1,
                &*clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
            )
            .unwrap(),
        );
        let mut fs = InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));
        fs.max_staged_ops = 1; // freeze a batch on every mutation
        fs.max_flush_queue_depth = 4;

        // 1. The disk fills up: nothing more can ever be appended to the log.
        fault_storage.fail_writes_after_bytes(crate::log::record::FILE_HEADER_SIZE as u64, false);

        // 2. Keep mutating well past the queue bound.
        let mut accepted = 0;
        let mut refused = 0;
        let mut last_errno = 0;
        for i in 0..50 {
            let name = format!("f{}.txt", i);
            match crate::operations::read_write::create_core(&fs, 1, &name, 0o644, 0, 1000, 1000) {
                Ok(_) => accepted += 1,
                Err(e) => {
                    refused += 1;
                    last_errno = e;
                }
            }
        }

        // 3. Userspace must be told, rather than every write silently "succeeding".
        assert!(
            refused > 0,
            "mutations must start failing once the log stops draining"
        );
        assert_eq!(last_errno, libc::EIO, "failure must surface as an errno");
        assert!(
            accepted <= fs.max_flush_queue_depth,
            "only the batches that fit in the queue may be accepted, got {}",
            accepted
        );

        // 4. The backlog must stay bounded instead of growing with every mutation.
        assert!(
            fs.flush_queue_depth() <= fs.max_flush_queue_depth,
            "flush queue must stay bounded, got {}",
            fs.flush_queue_depth()
        );

        // 5. An explicit sync still reports the underlying failure.
        assert!(fs.sync_log().is_err());

        // 6. Once the disk recovers, the queued batches drain and mutations resume.
        fault_storage.clear_write_limit();
        fs.sync_log().unwrap();
        assert_eq!(fs.flush_queue_depth(), 0);
        crate::operations::read_write::create_core(&fs, 1, "after.txt", 0o644, 0, 1000, 1000)
            .expect("mutations must be accepted again once the log drains");
    }
}
