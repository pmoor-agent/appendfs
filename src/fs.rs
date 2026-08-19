use crate::clock::{Clock, SystemClock};
use crate::log::{
    BackgroundFlusher, CreatePayload, ExtentState, GenerationLiveStats, LinkPayload, LogFileCache, LogManifest,
    LogWriter, MkdirPayload, MknodPayload, OpCode, RECORD_HEADER_SIZE, RemovexattrPayload, RenamePayload, RmdirPayload,
    SetattrPayload, SetxattrPayload, SharedExtentState, SymlinkPayload, UnlinkPayload, WriteMeta,
};
use crate::node::{
    AttrDelta, DirectoryDelta, EntryDelta, FileDelta, Node, NodeDelta, NodeKind, SpecialDelta, SymlinkDelta,
};
use crate::range_map::RangeMap;
use crate::shim::{FileAttr, FileType};
use crate::storage::Storage;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileHandle {
    pub ino: u64,
    pub flags: u32,
}

pub type DirSnapshot = Arc<Vec<(String, u64)>>;
pub type FileHandleMap = HashMap<u64, FileHandle>;
pub type DirectoryHandleMap = HashMap<u64, DirSnapshot>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlockState {
    Shared(HashSet<u64>),
    Exclusive(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeLock {
    pub lock_type: i16,
    pub start: u64,
    pub end: u64,
    pub owner: u64,
    pub pid: i32,
}

// --- Layer Stack Snapshot & Fold Abstraction ---

/// Borrowed snapshot view of an inode's layer hierarchy (`base` plus chronological `deltas`).
/// Constructed while holding all necessary layer read locks, enabling race-free,
/// zero-copy folding directly under the locks.
pub struct InodeLayerStack<'a> {
    pub ino: u64,
    pub base: Option<&'a Arc<Node>>,
    /// Chronological list of entry deltas ordered from oldest to newest (`flushing[0]` ... `flushing[n]`, `[live]`).
    pub deltas: Vec<&'a EntryDelta>,
}

impl<'a> InodeLayerStack<'a> {
    /// Resolves full `FileAttr` across `base` and `deltas` (folded oldest to newest).
    pub fn attr(&self) -> Option<FileAttr> {
        let mut attr = self.base.map(|arc| arc.to_attr(self.ino));
        for delta in &self.deltas {
            match delta {
                EntryDelta::Tombstone => {
                    attr = None;
                }
                EntryDelta::Node(d) => {
                    let a = attr.get_or_insert_with(|| d.initial_attr(self.ino));
                    d.apply_to_attr(a);
                }
            }
        }
        attr
    }

    /// Checks if the inode exists (is not tombstoned and present in deltas or base).
    pub fn exists(&self) -> bool {
        if let Some(delta) = self.deltas.last() {
            return matches!(delta, EntryDelta::Node(_));
        }
        self.base.is_some()
    }

    /// Resolves the file type of the inode (checking newest deltas first).
    pub fn file_type(&self) -> Option<FileType> {
        if let Some(delta) = self.deltas.last() {
            return match delta {
                EntryDelta::Tombstone => None,
                EntryDelta::Node(d) => Some(match d {
                    NodeDelta::Directory(_) => FileType::Directory,
                    NodeDelta::File(_) => FileType::RegularFile,
                    NodeDelta::Symlink(_) => FileType::Symlink,
                    NodeDelta::Fifo(_) => FileType::NamedPipe,
                    NodeDelta::CharDevice(_) => FileType::CharDevice,
                    NodeDelta::BlockDevice(_) => FileType::BlockDevice,
                    NodeDelta::Socket(_) => FileType::Socket,
                }),
            };
        }
        self.base.map(|arc| arc.file_type())
    }

    /// Looks up a child entry by `name` inside directory `self.ino`.
    pub fn lookup_child(&self, name: &str) -> Option<u64> {
        for delta in self.deltas.iter().rev() {
            match delta {
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

        if let Some(arc) = self.base {
            let node = arc.as_ref();
            if let NodeKind::Directory { entries, .. } = &node.kind
                && let Some((_, ino)) = entries.iter().find(|(entry_name, _)| entry_name == name)
            {
                return Some(*ino);
            }
        }

        None
    }

    /// Lists all consolidated directory entries across layers in alphabetical order.
    pub fn list_directory(&self) -> Option<Vec<(String, u64)>> {
        let attr = self.attr()?;
        if attr.file_type != FileType::Directory {
            return None;
        }

        let mut map: HashMap<String, u64> = HashMap::new();

        if let Some(arc) = self.base {
            let node = arc.as_ref();
            if let NodeKind::Directory { entries, .. } = &node.kind {
                for (name, child_ino) in entries {
                    map.insert(name.clone(), *child_ino);
                }
            }
        }

        for delta in &self.deltas {
            match delta {
                EntryDelta::Tombstone => {
                    map.clear();
                }
                EntryDelta::Node(NodeDelta::Directory(d)) => {
                    for name in &d.removed {
                        map.remove(name);
                    }
                    for (name, child_ino) in &d.added {
                        map.insert(name.clone(), *child_ino);
                    }
                }
                _ => {}
            }
        }

        let mut list: Vec<(String, u64)> = map.into_iter().collect();
        list.sort_by(|a, b| a.0.cmp(&b.0));
        Some(list)
    }

    /// Reads target of a symlink across layers.
    pub fn read_link(&self) -> Option<String> {
        for delta in self.deltas.iter().rev() {
            match delta {
                EntryDelta::Tombstone => return None,
                EntryDelta::Node(NodeDelta::Symlink(s)) => {
                    if let Some(ref t) = s.target {
                        return Some(t.clone());
                    }
                }
                _ => return None,
            }
        }

        if let Some(arc) = self.base {
            let node = arc.as_ref();
            if let NodeKind::Symlink { target, .. } = &node.kind {
                return Some(target.clone());
            }
        }

        None
    }

    /// Returns the parent directory inode.
    pub fn parent_dir_inode(&self) -> Option<u64> {
        if self.ino == 1 {
            return Some(1);
        }

        for delta in self.deltas.iter().rev() {
            match delta {
                EntryDelta::Tombstone => return None,
                EntryDelta::Node(NodeDelta::Directory(d)) => {
                    if let Some(p) = d.parent {
                        return Some(p);
                    }
                }
                _ => return None,
            }
        }

        if let Some(arc) = self.base {
            let node = arc.as_ref();
            if let NodeKind::Directory { parent, .. } = &node.kind {
                return Some(*parent);
            }
        }

        None
    }

    /// Resolves an extended attribute value by `name`.
    pub fn get_xattr(&self, name: &str) -> Option<Vec<u8>> {
        for delta in self.deltas.iter().rev() {
            match delta {
                EntryDelta::Tombstone => return None,
                EntryDelta::Node(d) => {
                    if let Some(ref xattrs) = d.attr_delta().xattrs
                        && let Some(val_opt) = xattrs.get(name)
                    {
                        return val_opt.clone();
                    }
                }
            }
        }

        if let Some(arc) = self.base
            && let Some(ref xattrs) = arc.meta.xattrs
        {
            return xattrs.get(name).cloned();
        }

        None
    }

    /// Lists all extended attribute names across layers in alphabetical order.
    pub fn list_xattrs(&self) -> Option<Vec<String>> {
        let _attr = self.attr()?;
        let mut names: BTreeSet<String> = BTreeSet::new();

        if let Some(arc) = self.base
            && let Some(ref xattrs) = arc.meta.xattrs
        {
            for k in xattrs.keys() {
                names.insert(k.clone());
            }
        }

        for delta in &self.deltas {
            match delta {
                EntryDelta::Tombstone => {
                    names.clear();
                }
                EntryDelta::Node(d) => {
                    if let Some(ref xattrs) = d.attr_delta().xattrs {
                        for (k, v) in xattrs {
                            if v.is_some() {
                                names.insert(k.clone());
                            } else {
                                names.remove(k);
                            }
                        }
                    }
                }
            }
        }

        Some(names.into_iter().collect())
    }

    /// Reads file data resolving extents across layers.
    pub fn read_file_data(&self, offset: u64, size: usize, fs: &InMemoryFS) -> Result<Vec<u8>, i32> {
        let attr = self.attr().ok_or(libc::ENOENT)?;
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

        let mut current_truncate_mask = u64::MAX;
        let mut hit_tombstone = false;
        for delta in self.deltas.iter().rev() {
            match delta {
                EntryDelta::Tombstone => {
                    hit_tombstone = true;
                    break;
                }
                EntryDelta::Node(NodeDelta::File(f)) => {
                    let max_read = std::cmp::min(read_len, current_truncate_mask.saturating_sub(offset));
                    if max_read > 0 {
                        for (ext_start, ext_len, shared_state) in f.extents.query(offset, max_read) {
                            fs.copy_extent_data(
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
                _ => {}
            }
        }

        if !hit_tombstone && let Some(arc) = self.base {
            let node = arc.as_ref();
            if let NodeKind::File { range_map, .. } = &node.kind {
                let max_base_read = std::cmp::min(read_len, current_truncate_mask.saturating_sub(offset));
                if max_base_read > 0 {
                    for (ext_start, ext_len, shared_state) in range_map.query(offset, max_base_read) {
                        fs.copy_extent_data(
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

        Ok(read_buf)
    }
}

pub struct InMemoryFS {
    /// Resting consolidated state loaded from `.summary` at mount, folded forward over
    /// generations.
    pub base: RwLock<HashMap<u64, Arc<Node>>>,
    /// Ordered queue of immutable frozen snapshots waiting to be written/flushed to disk.
    /// New batches are pushed to the back; flusher drains from the front.
    pub flushing: RwLock<VecDeque<HashMap<u64, EntryDelta>>>,
    /// Current generation's active mutable delta layer receiving live operations.
    pub live: RwLock<HashMap<u64, EntryDelta>>,
    /// Active open file handles keyed by allocated file handle ID (`fh`).
    pub file_handles: RwLock<FileHandleMap>,
    /// Active open directory handle snapshots keyed by allocated file handle ID (`fh`).
    pub dir_handles: RwLock<DirectoryHandleMap>,
    /// Active whole-file BSD flock locks keyed by inode number.
    pub flock_table: Mutex<HashMap<u64, FlockState>>,
    pub flock_cond: Condvar,
    /// Active POSIX byte-range record locks keyed by inode number.
    pub range_lock_table: Mutex<HashMap<u64, Vec<RangeLock>>>,
    pub range_lock_cond: Condvar,
    /// Open descriptor reference count per inode for fast POSIX unlinking checks.
    pub open_counts: RwLock<HashMap<u64, u32>>,
    /// Atomic counter for allocating unique file and directory handle IDs (`fh`).
    pub next_fh: AtomicU64,
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
        map.insert(1, Arc::new(Node::new_dir(1, 0o755, uid, gid, now)));

        let log_cache = log_writer
            .as_ref()
            .map(|w| Arc::new(LogFileCache::with_storage(w.storage().clone())));

        let start_gen = log_writer.as_ref().map_or(1, |w| w.generation());
        let manifest = Arc::new(RwLock::new(LogManifest::new_with_time(start_gen, "main", now)));

        Self {
            base: RwLock::new(map),
            flushing: RwLock::new(VecDeque::new()),
            live: RwLock::new(HashMap::new()),
            file_handles: RwLock::new(HashMap::new()),
            dir_handles: RwLock::new(HashMap::new()),
            flock_table: Mutex::new(HashMap::new()),
            flock_cond: Condvar::new(),
            range_lock_table: Mutex::new(HashMap::new()),
            range_lock_cond: Condvar::new(),
            open_counts: RwLock::new(HashMap::new()),
            next_fh: AtomicU64::new(1),
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
        self.read_only.store(ro, std::sync::atomic::Ordering::SeqCst);
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

    // --- POSIX File Handle Tracking ---

    pub fn open_file_handle(&self, ino: u64, flags: u32) -> u64 {
        let fh = self.allocate_fh();
        self.file_handles.write().unwrap().insert(fh, FileHandle { ino, flags });
        *self.open_counts.write().unwrap().entry(ino).or_insert(0) += 1;
        fh
    }

    pub fn get_file_handle(&self, fh: u64) -> Option<FileHandle> {
        self.file_handles.read().unwrap().get(&fh).copied()
    }

    pub fn release_file_handle(&self, fh: u64, ino: u64) -> Result<(), i32> {
        let handle = self.file_handles.write().unwrap().remove(&fh).ok_or(libc::EBADF)?;
        if handle.ino != ino {
            return Err(libc::EBADF);
        }

        // Clean up any BSD flock held by this handle
        self.release_flock(ino, fh);

        let mut counts = self.open_counts.write().unwrap();
        if let Some(count) = counts.get_mut(&ino) {
            *count = count.saturating_sub(1);
        }
        if counts.get(&ino) == Some(&0) {
            counts.remove(&ino);
            // Clean up POSIX range locks if all handles on inode are closed
            self.range_lock_table.lock().unwrap().remove(&ino);
            self.range_lock_cond.notify_all();
        }
        let remaining = counts.get(&ino).copied().unwrap_or(0);
        if remaining == 0
            && let Some(attr) = self.get_attr(ino)
            && attr.nlink == 0
        {
            self.tombstone(ino);
        }
        Ok(())
    }

    pub fn release_flock(&self, ino: u64, fh: u64) {
        let mut table = self.flock_table.lock().unwrap();
        if let Some(state) = table.get_mut(&ino) {
            match state {
                FlockState::Shared(set) => {
                    set.remove(&fh);
                    if set.is_empty() {
                        table.remove(&ino);
                    }
                }
                FlockState::Exclusive(holder) => {
                    if *holder == fh {
                        table.remove(&ino);
                    }
                }
            }
            self.flock_cond.notify_all();
        }
    }

    pub fn open_count(&self, ino: u64) -> u32 {
        self.open_counts.read().unwrap().get(&ino).copied().unwrap_or(0)
    }

    // --- Directory Handle Snapshot Management ---

    pub fn allocate_fh(&self) -> u64 {
        self.next_fh.fetch_add(1, Ordering::SeqCst)
    }

    pub fn open_dir_handle(&self, ino: u64) -> Option<u64> {
        let entries = self.list_directory(ino)?;
        let fh = self.allocate_fh();
        self.dir_handles.write().unwrap().insert(fh, Arc::new(entries));
        Some(fh)
    }

    pub fn get_dir_handle(&self, fh: u64) -> Option<Arc<Vec<(String, u64)>>> {
        self.dir_handles.read().unwrap().get(&fh).cloned()
    }

    pub fn release_dir_handle(&self, fh: u64) -> Result<(), i32> {
        self.dir_handles.write().unwrap().remove(&fh).ok_or(libc::EBADF)?;
        Ok(())
    }

    // --- In-Memory Delta Layer Mutations ---

    pub fn insert_new_node(&self, ino: u64, delta: NodeDelta) {
        self.live.write().unwrap().insert(ino, EntryDelta::Node(delta));
    }

    pub fn tombstone(&self, ino: u64) {
        self.live.write().unwrap().insert(ino, EntryDelta::Tombstone);
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
        self.with_inode_layers(ino, |layers| layers.parent_dir_inode())
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
                node_delta.attr_delta_mut().merge_from(&delta);
                return;
            }
            None => {}
        }

        // Inode not in live yet - query existing type from lower layers without re-acquiring live lock.
        let file_type = self.with_inode_layers_below_live(ino, |layers| layers.file_type());

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
            Some(FileType::NamedPipe) => {
                live.insert(
                    ino,
                    EntryDelta::Node(NodeDelta::Fifo(SpecialDelta {
                        rdev: 0,
                        attr_delta: delta,
                    })),
                );
            }
            Some(FileType::CharDevice) => {
                live.insert(
                    ino,
                    EntryDelta::Node(NodeDelta::CharDevice(SpecialDelta {
                        rdev: 0,
                        attr_delta: delta,
                    })),
                );
            }
            Some(FileType::BlockDevice) => {
                live.insert(
                    ino,
                    EntryDelta::Node(NodeDelta::BlockDevice(SpecialDelta {
                        rdev: 0,
                        attr_delta: delta,
                    })),
                );
            }
            Some(FileType::Socket) => {
                live.insert(
                    ino,
                    EntryDelta::Node(NodeDelta::Socket(SpecialDelta {
                        rdev: 0,
                        attr_delta: delta,
                    })),
                );
            }
            None => {}
        }
    }

    // --- Overlay Query & Resolution Methods ---

    /// Acquires read locks across all three layers (`live`, `flushing`, `base`) atomically in
    /// consistent safe order and invokes `f` with the combined `InodeLayerStack` for `ino`.
    /// Zero-copy folding executes directly under the read locks.
    pub fn with_inode_layers<R>(&self, ino: u64, f: impl FnOnce(InodeLayerStack<'_>) -> R) -> R {
        let live = self.live.read().unwrap();
        let flushing = self.flushing.read().unwrap();
        let base = self.base.read().unwrap();

        let base_entry = base.get(&ino);
        let mut deltas = Vec::with_capacity(flushing.len() + 1);
        for batch in flushing.iter() {
            if let Some(entry) = batch.get(&ino) {
                deltas.push(entry);
            }
        }
        if let Some(entry) = live.get(&ino) {
            deltas.push(entry);
        }

        let stack = InodeLayerStack {
            ino,
            base: base_entry,
            deltas,
        };

        f(stack)
    }

    /// Acquires read locks across `flushing` and `base` layers (skipping `live`) for callers
    /// that already hold `live.write()`.
    pub fn with_inode_layers_below_live<R>(&self, ino: u64, f: impl FnOnce(InodeLayerStack<'_>) -> R) -> R {
        let flushing = self.flushing.read().unwrap();
        let base = self.base.read().unwrap();

        let base_entry = base.get(&ino);
        let mut deltas = Vec::with_capacity(flushing.len());
        for batch in flushing.iter() {
            if let Some(entry) = batch.get(&ino) {
                deltas.push(entry);
            }
        }

        let stack = InodeLayerStack {
            ino,
            base: base_entry,
            deltas,
        };

        f(stack)
    }

    /// Executes `f` while holding read locks on all three layers (`live`, `flushing`, `base`).
    pub fn with_layers<R>(
        &self,
        f: impl FnOnce(&HashMap<u64, EntryDelta>, &VecDeque<HashMap<u64, EntryDelta>>, &HashMap<u64, Arc<Node>>) -> R,
    ) -> R {
        let live = self.live.read().unwrap();
        let flushing = self.flushing.read().unwrap();
        let base = self.base.read().unwrap();
        f(&live, &flushing, &base)
    }

    /// Validates whether an inode exists in the layers below `live` (flushing -> base).
    pub fn exists_below_live(&self, ino: u64) -> bool {
        self.with_inode_layers_below_live(ino, |layers| layers.exists())
    }

    /// Resolves full `FileAttr` for an inode across `flushing` -> `base`, skipping `live`.
    /// Used by mutators holding `live.write()`.
    pub fn attr_below_live(&self, ino: u64) -> Option<FileAttr> {
        self.with_inode_layers_below_live(ino, |layers| layers.attr())
    }

    /// Resolves full `FileAttr` for an inode across `live` -> `flushing` -> `base`.
    pub fn get_attr(&self, ino: u64) -> Option<FileAttr> {
        self.with_inode_layers(ino, |layers| layers.attr())
    }

    /// Resolves full `FileAttr`s for a slice of inode IDs across `live` -> `flushing` -> `base`
    /// in a single atomic snapshot pass while holding all three layer read locks concurrently.
    pub fn get_attrs_batch(&self, inos: &[u64]) -> HashMap<u64, FileAttr> {
        self.with_layers(|live, flushing, base| {
            let mut result = HashMap::with_capacity(inos.len());
            for &ino in inos {
                let base_entry = base.get(&ino);
                let mut deltas = Vec::with_capacity(flushing.len() + 1);
                for batch in flushing.iter() {
                    if let Some(entry) = batch.get(&ino) {
                        deltas.push(entry);
                    }
                }
                if let Some(entry) = live.get(&ino) {
                    deltas.push(entry);
                }
                let stack = InodeLayerStack {
                    ino,
                    base: base_entry,
                    deltas,
                };
                if let Some(attr) = stack.attr() {
                    result.insert(ino, attr);
                }
            }
            result
        })
    }

    /// Looks up a child entry by `name` inside `parent` directory across layers.
    pub fn lookup_child(&self, parent: u64, name: &str) -> Option<u64> {
        self.with_inode_layers(parent, |layers| layers.lookup_child(name))
    }

    /// Lists all consolidated entries of directory `parent` across layers in alphabetical order.
    pub fn list_directory(&self, parent: u64) -> Option<Vec<(String, u64)>> {
        self.with_inode_layers(parent, |layers| layers.list_directory())
    }

    /// Reads target of a symlink across layers.
    pub fn read_link(&self, ino: u64) -> Option<String> {
        self.with_inode_layers(ino, |layers| layers.read_link())
    }

    /// Resolves an extended attribute value for an inode across live -> flushing -> base layers.
    pub fn get_xattr(&self, ino: u64, name: &str) -> Option<Vec<u8>> {
        self.with_inode_layers(ino, |layers| layers.get_xattr(name))
    }

    /// Lists all extended attribute names for an inode across all layers in alphabetical order.
    pub fn list_xattrs(&self, ino: u64) -> Option<Vec<String>> {
        self.with_inode_layers(ino, |layers| layers.list_xattrs())
    }

    /// Stages a set/replace mutation for an extended attribute.
    pub fn set_xattr(&self, ino: u64, name: &str, value: Vec<u8>, now: SystemTime) {
        let mut xattrs = HashMap::new();
        xattrs.insert(name.to_string(), Some(value));
        let delta = AttrDelta {
            ctime: Some(now),
            xattrs: Some(xattrs),
            ..Default::default()
        };
        self.update_attr_delta(ino, delta);
    }

    /// Stages a removal mutation for an extended attribute.
    pub fn remove_xattr(&self, ino: u64, name: &str, now: SystemTime) {
        let mut xattrs = HashMap::new();
        xattrs.insert(name.to_string(), None);
        let delta = AttrDelta {
            ctime: Some(now),
            xattrs: Some(xattrs),
            ..Default::default()
        };
        self.update_attr_delta(ino, delta);
    }

    /// Reads file data at `[offset, offset + size)` resolving extents across layers.
    pub fn read_file_data(&self, ino: u64, offset: u64, size: usize) -> Result<Vec<u8>, i32> {
        let read_buf = self.with_inode_layers(ino, |layers| layers.read_file_data(offset, size, self))?;

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
                    temp_buf[..actual_len].copy_from_slice(&data[src_start..src_start + actual_len]);
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
                    && let Ok(reader) = cache.get_or_open(generation)
                {
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

    /// Merges all layers into a consolidated snapshot map atomically while holding all 3 layer guards.
    pub fn snapshot_all(&self) -> HashMap<u64, Arc<Node>> {
        self.with_layers(|live, flushing, base| {
            let mut result: HashMap<u64, Arc<Node>> = base.clone();

            for flushing_map in flushing.iter() {
                for (ino, entry) in flushing_map {
                    match entry {
                        EntryDelta::Tombstone => {
                            result.remove(ino);
                        }
                        EntryDelta::Node(delta) => {
                            if let Some(existing_arc) = result.get(ino).cloned() {
                                let mut node_clone = (*existing_arc).clone();
                                delta.apply_to_node(&mut node_clone);
                                result.insert(*ino, Arc::new(node_clone));
                            } else {
                                result.insert(*ino, Arc::new(delta.to_node()));
                            }
                        }
                    }
                }
            }

            for (ino, entry) in live.iter() {
                match entry {
                    EntryDelta::Tombstone => {
                        result.remove(ino);
                    }
                    EntryDelta::Node(delta) => {
                        if let Some(existing_arc) = result.get(ino).cloned() {
                            let mut node_clone = (*existing_arc).clone();
                            delta.apply_to_node(&mut node_clone);
                            result.insert(*ino, Arc::new(node_clone));
                        } else {
                            result.insert(*ino, Arc::new(delta.to_node()));
                        }
                    }
                }
            }

            result.retain(|_ino, arc| arc.meta.nlink > 0 || arc.is_dir());

            result
        })
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
                        delta.apply_to_node(&mut node_clone);
                        base.insert(ino, Arc::new(node_clone));
                    } else {
                        base.insert(ino, Arc::new(delta.to_node()));
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
                    if f.size.is_some() || f.truncate_mask.is_some() || f.attr_delta.mode.is_some() {
                        estimated_bytes += RECORD_HEADER_SIZE as u64 + 64;
                    }
                }
                EntryDelta::Node(NodeDelta::Directory(d)) => {
                    estimated_bytes += (d.added.len() + d.removed.len()) as u64 * (RECORD_HEADER_SIZE as u64 + 64);
                    if d.attr_delta.mode.is_some() {
                        estimated_bytes += RECORD_HEADER_SIZE as u64 + 64;
                    }
                }
                EntryDelta::Node(NodeDelta::Symlink(_)) => {
                    estimated_bytes += RECORD_HEADER_SIZE as u64 + 128;
                }
                EntryDelta::Node(
                    NodeDelta::Fifo(_) | NodeDelta::CharDevice(_) | NodeDelta::BlockDevice(_) | NodeDelta::Socket(_),
                ) => {
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
                    .map(|arc| match &arc.kind {
                        NodeKind::Directory { entries, .. } => entries.iter().any(|(n, c)| n == name && *c == child),
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
                        if !base_map.contains_key(&child_ino) && !primary_creation.contains_key(&child_ino) {
                            primary_creation.insert(child_ino, (parent_ino, name.clone()));
                            continue;
                        }
                        if entry_already_in_base(parent_ino, name, child_ino) {
                            continue;
                        }
                        all_added.entry(child_ino).or_default().push((parent_ino, name.clone()));
                    }
                }
            }

            // 2. Identify Renames (paired removal + addition for an inode) vs Unlinks/Rmdirs
            let mut renamed_additions: HashSet<(u64, String)> = HashSet::new();
            let mut renames_to_emit: Vec<(u64, u64, String, u64, String, SystemTime)> = Vec::new();
            let mut unlinks_to_emit: Vec<(u64, u64, String, bool, SystemTime)> = Vec::new();

            for &parent_ino in &inos {
                let (d_removed, d_added, op_time) = match frozen.get(&parent_ino) {
                    Some(EntryDelta::Node(NodeDelta::Directory(d))) => {
                        (&d.removed, Some(&d.added), d.attr_delta.mtime.unwrap_or(now))
                    }
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
                    if let NodeKind::Directory { entries, .. } = &node.kind {
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
                                    if child_arc.is_dir() {
                                        is_dir = true;
                                    }
                                } else if let Some(EntryDelta::Node(NodeDelta::Directory(_))) = frozen.get(c_ino) {
                                    is_dir = true;
                                }
                                removed_entries.push((name.clone(), *c_ino, is_dir));
                            }
                        }
                    }
                }

                removed_entries.sort_by(|a, b| a.0.cmp(&b.0));

                for (name, child_ino, is_dir) in removed_entries {
                    if let Some((new_parent, new_name)) = all_added.get_mut(&child_ino).and_then(|v| v.pop()) {
                        renamed_additions.insert((new_parent, new_name.clone()));
                        renames_to_emit.push((child_ino, parent_ino, name, new_parent, new_name, op_time));
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

            // Phase 2: Mkdir (topologically ordered: parent directories emitted before their subdirectories)
            let mut pending_mkdirs: Vec<u64> = inos
                .iter()
                .copied()
                .filter(|&ino| {
                    matches!(frozen.get(&ino), Some(EntryDelta::Node(NodeDelta::Directory(_))))
                        && !base_map.contains_key(&ino)
                        && primary_creation.contains_key(&ino)
                })
                .collect();

            let mut created_dirs: HashSet<u64> = HashSet::new();
            let mut ordered_mkdir_inos: Vec<u64> = Vec::with_capacity(pending_mkdirs.len());

            while !pending_mkdirs.is_empty() {
                let mut progressed = false;
                pending_mkdirs.retain(|&ino| {
                    let (parent, _) = primary_creation.get(&ino).unwrap();
                    if base_map.contains_key(parent) || created_dirs.contains(parent) {
                        created_dirs.insert(ino);
                        ordered_mkdir_inos.push(ino);
                        progressed = true;
                        false
                    } else {
                        true
                    }
                });

                if !progressed {
                    // Fallback to guarantee termination in case of malformed hierarchies
                    let ino = pending_mkdirs.remove(0);
                    created_dirs.insert(ino);
                    ordered_mkdir_inos.push(ino);
                }
            }

            for ino in ordered_mkdir_inos {
                if let Some(EntryDelta::Node(NodeDelta::Directory(d))) = frozen.get(&ino)
                    && let Some((parent, name)) = primary_creation.get(&ino).cloned()
                {
                    let op_time = d.attr_delta.created_at.or(d.attr_delta.ctime).unwrap_or(now);
                    let payload = MkdirPayload {
                        parent,
                        name,
                        mode: d.attr_delta.mode.unwrap_or(0o755),
                        uid: d.attr_delta.uid.unwrap_or(0),
                        gid: d.attr_delta.gid.unwrap_or(0),
                        created_at: op_time,
                    };
                    let bytes = bincode::serialize(&payload)
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                    writer.append_record(OpCode::Mkdir, ino, &bytes)?;
                    written_count += 1;
                }
            }

            // Phase 3: Create, Symlink, and Mknod
            for &ino in &inos {
                match frozen.get(&ino) {
                    Some(EntryDelta::Node(NodeDelta::File(f))) => {
                        if !base_map.contains_key(&ino)
                            && let Some((parent, name)) = primary_creation.get(&ino).cloned()
                        {
                            let op_time = f.attr_delta.created_at.or(f.attr_delta.ctime).unwrap_or(now);
                            let payload = CreatePayload {
                                parent,
                                name,
                                mode: f.attr_delta.mode.unwrap_or(0o644),
                                uid: f.attr_delta.uid.unwrap_or(0),
                                gid: f.attr_delta.gid.unwrap_or(0),
                                created_at: op_time,
                            };
                            let bytes = bincode::serialize(&payload)
                                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                            writer.append_record(OpCode::Create, ino, &bytes)?;
                            written_count += 1;
                        }
                    }
                    Some(EntryDelta::Node(NodeDelta::Symlink(s))) => {
                        if !base_map.contains_key(&ino)
                            && let Some((parent, name)) = primary_creation.get(&ino).cloned()
                        {
                            let op_time = s.attr_delta.created_at.or(s.attr_delta.ctime).unwrap_or(now);
                            let payload = SymlinkPayload {
                                parent,
                                name,
                                target: s.target.clone().unwrap_or_default(),
                                uid: s.attr_delta.uid.unwrap_or(0),
                                gid: s.attr_delta.gid.unwrap_or(0),
                                created_at: op_time,
                            };
                            let bytes = bincode::serialize(&payload)
                                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                            writer.append_record(OpCode::Symlink, ino, &bytes)?;
                            written_count += 1;
                        }
                    }
                    Some(EntryDelta::Node(NodeDelta::Fifo(s))) => {
                        if !base_map.contains_key(&ino)
                            && let Some((parent, name)) = primary_creation.get(&ino).cloned()
                        {
                            let op_time = s.attr_delta.created_at.or(s.attr_delta.ctime).unwrap_or(now);
                            let payload = MknodPayload {
                                parent,
                                name,
                                mode: (s.attr_delta.mode.unwrap_or(0o644) & 0o7777) | libc::S_IFIFO,
                                rdev: 0,
                                uid: s.attr_delta.uid.unwrap_or(0),
                                gid: s.attr_delta.gid.unwrap_or(0),
                                created_at: op_time,
                            };
                            let bytes = bincode::serialize(&payload)
                                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                            writer.append_record(OpCode::Mknod, ino, &bytes)?;
                            written_count += 1;
                        }
                    }
                    Some(EntryDelta::Node(NodeDelta::CharDevice(s))) => {
                        if !base_map.contains_key(&ino)
                            && let Some((parent, name)) = primary_creation.get(&ino).cloned()
                        {
                            let op_time = s.attr_delta.created_at.or(s.attr_delta.ctime).unwrap_or(now);
                            let payload = MknodPayload {
                                parent,
                                name,
                                mode: (s.attr_delta.mode.unwrap_or(0o660) & 0o7777) | libc::S_IFCHR,
                                rdev: s.rdev,
                                uid: s.attr_delta.uid.unwrap_or(0),
                                gid: s.attr_delta.gid.unwrap_or(0),
                                created_at: op_time,
                            };
                            let bytes = bincode::serialize(&payload)
                                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                            writer.append_record(OpCode::Mknod, ino, &bytes)?;
                            written_count += 1;
                        }
                    }
                    Some(EntryDelta::Node(NodeDelta::BlockDevice(s))) => {
                        if !base_map.contains_key(&ino)
                            && let Some((parent, name)) = primary_creation.get(&ino).cloned()
                        {
                            let op_time = s.attr_delta.created_at.or(s.attr_delta.ctime).unwrap_or(now);
                            let payload = MknodPayload {
                                parent,
                                name,
                                mode: (s.attr_delta.mode.unwrap_or(0o660) & 0o7777) | libc::S_IFBLK,
                                rdev: s.rdev,
                                uid: s.attr_delta.uid.unwrap_or(0),
                                gid: s.attr_delta.gid.unwrap_or(0),
                                created_at: op_time,
                            };
                            let bytes = bincode::serialize(&payload)
                                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                            writer.append_record(OpCode::Mknod, ino, &bytes)?;
                            written_count += 1;
                        }
                    }
                    Some(EntryDelta::Node(NodeDelta::Socket(s))) => {
                        if !base_map.contains_key(&ino)
                            && let Some((parent, name)) = primary_creation.get(&ino).cloned()
                        {
                            let op_time = s.attr_delta.created_at.or(s.attr_delta.ctime).unwrap_or(now);
                            let payload = MknodPayload {
                                parent,
                                name,
                                mode: (s.attr_delta.mode.unwrap_or(0o777) & 0o7777) | libc::S_IFSOCK,
                                rdev: 0,
                                uid: s.attr_delta.uid.unwrap_or(0),
                                gid: s.attr_delta.gid.unwrap_or(0),
                                created_at: op_time,
                            };
                            let bytes = bincode::serialize(&payload)
                                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                            writer.append_record(OpCode::Mknod, ino, &bytes)?;
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
                let (child_ino, parent, name, new_parent, new_name, op_time) = renames_to_emit[breaker].clone();
                let tmp_name = format!(".agy_tmp_rename_{}", child_ino);
                ordered_renames.push((child_ino, parent, name, parent, tmp_name.clone(), op_time));
                emitted[breaker] = true;
                for &idx in cycle[1..].iter().rev() {
                    emitted[idx] = true;
                    ordered_renames.push(renames_to_emit[idx].clone());
                }
                ordered_renames.push((child_ino, parent, tmp_name, new_parent, new_name, op_time));
            }

            for (child_ino, parent, name, new_parent, new_name, op_time) in ordered_renames {
                let payload = RenamePayload {
                    old_parent: parent,
                    old_name: name,
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
                            Some(EntryDelta::Node(NodeDelta::Fifo(s)))
                            | Some(EntryDelta::Node(NodeDelta::CharDevice(s)))
                            | Some(EntryDelta::Node(NodeDelta::BlockDevice(s)))
                            | Some(EntryDelta::Node(NodeDelta::Socket(s))) => s.attr_delta.ctime,
                            _ => None,
                        };
                        let op_time = d.attr_delta.mtime.or(d.attr_delta.ctime).or(child_ctime).unwrap_or(now);
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
                            let slice =
                                &item.data[item.payload_offset as usize..(item.payload_offset + item.length) as usize];
                            payload.extend_from_slice(slice);
                        }

                        let (_, generation, record_log_offset) = writer.append_record(OpCode::Write, ino, &payload)?;
                        written_count += 1;
                        flushed_data_bytes += total_length;

                        // Collapse the entire contiguous run into a single consolidated RangeEntry in f.extents
                        let consolidated_extent =
                            SharedExtentState::new_disk(generation, record_log_offset, meta_size, total_length as u32);
                        f.extents.insert(start_offset, total_length, consolidated_extent);

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
                            let bytes = bincode::serialize(&payload)
                                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
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
                            let bytes = bincode::serialize(&payload)
                                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                            writer.append_record(OpCode::Setattr, ino, &bytes)?;
                            written_count += 1;
                        }
                    }
                    Some(EntryDelta::Node(NodeDelta::Symlink(s)))
                        if (s.attr_delta.mode.is_some()
                            || s.attr_delta.uid.is_some()
                            || s.attr_delta.gid.is_some()
                            || s.attr_delta.mtime.is_some()
                            || s.attr_delta.ctime.is_some()) =>
                    {
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
                        let bytes = bincode::serialize(&payload)
                            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                        writer.append_record(OpCode::Setattr, ino, &bytes)?;
                        written_count += 1;
                    }
                    Some(
                        EntryDelta::Node(NodeDelta::Fifo(s))
                        | EntryDelta::Node(NodeDelta::CharDevice(s))
                        | EntryDelta::Node(NodeDelta::BlockDevice(s))
                        | EntryDelta::Node(NodeDelta::Socket(s)),
                    ) if (s.attr_delta.mode.is_some()
                        || s.attr_delta.uid.is_some()
                        || s.attr_delta.gid.is_some()
                        || s.attr_delta.mtime.is_some()
                        || s.attr_delta.ctime.is_some()) =>
                    {
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
                        let bytes = bincode::serialize(&payload)
                            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                        writer.append_record(OpCode::Setattr, ino, &bytes)?;
                        written_count += 1;
                    }
                    _ => {}
                }
            }

            // 4b. Emit Setxattr / Removexattr records
            for (&ino, entry) in frozen.iter() {
                if let EntryDelta::Node(node_delta) = entry {
                    let attr_delta = node_delta.attr_delta();
                    if let Some(ref xattr_changes) = attr_delta.xattrs {
                        let op_time = attr_delta.ctime.or(attr_delta.mtime).unwrap_or(now);
                        for (name, val_opt) in xattr_changes {
                            match val_opt {
                                Some(val) => {
                                    let payload = SetxattrPayload {
                                        name: name.clone(),
                                        value: val.clone(),
                                        flags: 0,
                                        op_time,
                                    };
                                    let bytes = bincode::serialize(&payload)
                                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                                    writer.append_record(OpCode::Setxattr, ino, &bytes)?;
                                    written_count += 1;
                                }
                                None => {
                                    let payload = RemovexattrPayload {
                                        name: name.clone(),
                                        op_time,
                                    };
                                    let bytes = bincode::serialize(&payload)
                                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                                    writer.append_record(OpCode::Removexattr, ino, &bytes)?;
                                    written_count += 1;
                                }
                            }
                        }
                    }
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
            self.staged_bytes.fetch_add(additional_bytes, Ordering::Relaxed) + additional_bytes
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
            if let NodeKind::File { range_map, .. } = &node.kind {
                for (_, entry) in range_map.iter() {
                    if let ExtentState::Disk { generation, length, .. } = entry.value.read_state() {
                        let stats = live_map.entry(generation).or_insert((0, 0));
                        stats.0 += length as u64;
                        stats.1 += 1;
                    }
                }
            }
        }

        let mut result = Vec::new();
        for log in &manifest.logs {
            let (live_bytes, live_extents) = live_map.get(&log.generation).copied().unwrap_or((0, 0));
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
    pub fn check_integrity(&self, log_dir: Option<&Path>, verify_data: bool) -> crate::check::IntegrityReport {
        crate::check::check_fs_integrity(self, log_dir, verify_data)
    }

    /// Exports a single-file summary snapshot of the current in-memory filesystem state.
    pub fn export_summary(&self, log_dir: impl AsRef<Path>) -> std::io::Result<PathBuf> {
        self.sync_log()?;
        let snapshot = self.snapshot_all();
        let generation = self.log_writer.as_ref().map_or(1, |w| w.generation());
        let last_tx_id = self
            .log_writer
            .as_ref()
            .map_or_else(|| self.last_tx_id.load(Ordering::SeqCst), |w| w.last_tx_id());
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
        let last_tx_id = self
            .log_writer
            .as_ref()
            .map_or_else(|| self.last_tx_id.load(Ordering::SeqCst), |w| w.last_tx_id());
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

pub fn find_parent_inode(fs: &InMemoryFS, child_ino: u64) -> Option<u64> {
    fs.get_parent_dir_inode(child_ino)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::LogWriter;
    use crate::node::InodeMeta;
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
            if let NodeKind::File { range_map, size, .. } = &node.kind {
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
                panic!("Expected NodeKind::File in base");
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
            Arc::new(Node {
                meta: InodeMeta::new(0o644, 1, 1000, 1000, clock.now()),
                kind: NodeKind::File {
                    range_map: RangeMap::new(),
                    size: 0,
                },
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
        let gletscher_attr = crate::operations::dir::mkdir_core(&fs, 1, "Gletscher", 0o755, 1000, 1000).unwrap();
        let gletscher_ino = gletscher_attr.ino;

        let file1_attr =
            crate::operations::read_write::create_core(&fs, gletscher_ino, "file1.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::write_core(&fs, file1_attr.ino, &[1, 2, 3, 4], 0).unwrap();

        let file2_attr =
            crate::operations::read_write::create_core(&fs, gletscher_ino, "file2.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::write_core(&fs, file2_attr.ino, &[5, 6, 7, 8], 0).unwrap();

        let sub_attr = crate::operations::dir::mkdir_core(&fs, gletscher_ino, "sub", 0o755, 1000, 1000).unwrap();
        let sub_ino = sub_attr.ino;

        let file3_attr =
            crate::operations::read_write::create_core(&fs, sub_ino, "file3.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::write_core(&fs, file3_attr.ino, &[9, 10, 11, 12], 0).unwrap();

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
        let keep_attr = crate::operations::dir::mkdir_core(&fs, 1, "keep", 0o755, 1000, 1000).unwrap();
        let gletscher_attr = crate::operations::dir::mkdir_core(&fs, 1, "Gletscher", 0o755, 1000, 1000).unwrap();

        // 2. Create /keep/shared.txt (inode N, nlink 1) and write data
        let file_attr =
            crate::operations::read_write::create_core(&fs, keep_attr.ino, "shared.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::write_core(&fs, file_attr.ino, b"persistent shared content", 0).unwrap();

        // 3. Create hard link /Gletscher/shared_link.txt -> inode N (nlink becomes 2)
        let link_attr =
            crate::operations::links::link_core(&fs, file_attr.ino, gletscher_attr.ino, "shared_link.txt").unwrap();
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

        let data = crate::operations::read_write::read_core(&recovered, file_attr.ino, 25, 0).unwrap();
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

        let attr = crate::operations::read_write::create_core(&fs, 1, "f.txt", 0o644, 0, 1000, 1000).unwrap();
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

        let attr = crate::operations::read_write::create_core(&fs, 1, "f.txt", 0o644, 0, 1000, 1000).unwrap();
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
            crate::operations::read_write::create_core(&fs, 1, &name, 0o644, 0, 1000, 1000).unwrap();
        }
        assert_eq!(fs.staged_ops.load(Ordering::SeqCst), 4);
        assert_eq!(fs.manifest.read().unwrap().logs[0].record_count, 0);

        // 5th operation reaches threshold and triggers automatic flush!
        crate::operations::read_write::create_core(&fs, 1, "file_4.txt", 0o644, 0, 1000, 1000).unwrap();

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
        let file_attr =
            crate::operations::read_write::create_core(&fs, 1, "temp_scratch.bin", 0o644, 0, 1000, 1000).unwrap();
        let ino = file_attr.ino;

        // Open handle (like a POSIX process keeping file open)
        let _fh = fs.open_file_handle(ino, 0);

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
        assert!(entries.is_empty(), "Root directory must be completely empty");
    }

    #[test]
    fn test_truncate_down_then_extend_across_flush_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(SystemClock);
        let writer = Arc::new(LogWriter::create(dir.path(), 1, &*clock).unwrap());
        let fs = InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));

        // Create file and write 100 bytes (0xAA)
        let file_attr = crate::operations::read_write::create_core(&fs, 1, "data.bin", 0o644, 0, 1000, 1000).unwrap();
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
        let read_data_after_flush = crate::operations::read_write::read_core(&fs, ino, 100, 0).unwrap();
        assert_eq!(&read_data_after_flush[0..20], &[0xAA; 20]);
        assert_eq!(&read_data_after_flush[20..100], &[0x00; 80]);
    }

    #[test]
    fn test_multi_batch_flushing_queue_and_layer_resolution() {
        let clock = Arc::new(SystemClock);
        let fs = InMemoryFS::with_clock(clock.clone());

        // 1. Create file in batch 1
        let f = crate::operations::read_write::create_core(&fs, 1, "test.txt", 0o644, 0, 1000, 1000).unwrap();
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
        let writer = Arc::new(LogWriter::create_with_storage(storage.clone(), 1, &*clock, 50, 1).unwrap());
        let mut fs = InMemoryFS::with_clock_and_storage(clock.clone(), storage.clone());
        fs.log_writer = Some(writer);

        // 1. First batch: write data to file1 and flush (populates gen 1 past header size)
        let f1 = crate::operations::read_write::create_core(&fs, 1, "file1.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::write_core(&fs, f1.ino, b"initial payload", 0).unwrap();
        fs.flush_log().unwrap();

        // 2. Second batch: write data to file2
        let f2 = crate::operations::read_write::create_core(&fs, 1, "file2.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::write_core(&fs, f2.ino, b"second payload", 0).unwrap();

        // 3. Inject permission error on opening 000002.log to simulate I/O failure when rolling
        fault_storage.fail_on_file("000002.log", std::io::ErrorKind::PermissionDenied);

        // 4. Attempt flush - should fail with I/O error on roll creation
        let flush_res = fs.flush_log();
        assert!(flush_res.is_err(), "Expected flush_log to fail on simulated I/O error");

        // Verify filesystem is NOT wedged: flushing queue still retains the batch, live mutations still work!
        assert_eq!(
            fs.flushing.read().unwrap().len(),
            1,
            "Failed batch must remain in flushing queue"
        );

        // Live operations continue working smoothly
        let f3 = crate::operations::read_write::create_core(&fs, 1, "file3.txt", 0o644, 0, 1000, 1000).unwrap();
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
            LogWriter::create_with_storage(storage.clone(), 1, &*clock, crate::cli::DEFAULT_MAX_LOG_SIZE, 1).unwrap(),
        );
        let fs = InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));

        // 1. Initial batch with 2 files flushed cleanly
        let mut initial_inos = Vec::new();
        for i in 1..=2 {
            let name = format!("init_{}.txt", i);
            let f = crate::operations::read_write::create_core(&fs, 1, &name, 0o644, 0, 1000, 1000).unwrap();
            crate::operations::read_write::write_core(&fs, f.ino, b"initial payload", 0).unwrap();
            initial_inos.push(f.ino);
        }
        fs.flush_log().unwrap();

        let initial_offset = storage.file_len("000001.log").unwrap();

        // 2. Stage a second batch with 8 files
        let mut batch2_inos = Vec::new();
        for i in 1..=8 {
            let name = format!("batch2_file_{}.bin", i);
            let f = crate::operations::read_write::create_core(&fs, 1, &name, 0o644, 0, 1000, 1000).unwrap();
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
        assert!(retry_res.is_ok(), "Retried flush must succeed: {:?}", retry_res);
        assert_eq!(fs.flushing.read().unwrap().len(), 0);

        // 8. Recover filesystem and verify 100% data integrity without checksum mismatches!
        let recovered = crate::log::recover_fs_with_storage(storage.clone()).expect("Recovery must succeed cleanly");
        for ino in initial_inos {
            assert!(recovered.get_attr(ino).is_some());
            let d = crate::operations::read_write::read_core(&recovered, ino, 15, 0).unwrap();
            assert_eq!(&d, b"initial payload");
        }
        for (ino, payload) in batch2_inos {
            assert!(recovered.get_attr(ino).is_some());
            let d = crate::operations::read_write::read_core(&recovered, ino, payload.len(), 0).unwrap();
            assert_eq!(d, payload);
        }

        let report = crate::check::check_volume_with_storage(storage, true).unwrap();
        assert!(report.is_clean(), "Integrity check must be clean: {:?}", report.issues);
    }

    #[test]
    fn test_flush_queue_is_bounded_and_reports_failure_when_log_stops_draining() {
        let mem = Arc::new(crate::storage::MemoryStorage::new());
        let fault_storage = crate::storage::FaultStorage::new(mem);
        let storage = Arc::new(fault_storage.clone());
        let clock = Arc::new(SystemClock);
        let writer = Arc::new(
            LogWriter::create_with_storage(storage.clone(), 1, &*clock, crate::cli::DEFAULT_MAX_LOG_SIZE, 1).unwrap(),
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
        assert!(refused > 0, "mutations must start failing once the log stops draining");
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

    #[test]
    fn test_dir_handle_snapshot_isolation_and_lifecycle() {
        let fs = InMemoryFS::new();
        let now = fs.clock.now();

        // 1. Create two files under root
        crate::operations::read_write::create_core(&fs, 1, "alpha.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::create_core(&fs, 1, "bravo.txt", 0o644, 0, 1000, 1000).unwrap();

        // 2. Open a directory handle on root
        let fh1 = fs
            .open_dir_handle(1)
            .expect("open_dir_handle must succeed on directory");
        assert!(fh1 > 0);

        let snap1 = fs.get_dir_handle(fh1).expect("Handle snapshot must exist");
        assert_eq!(snap1.len(), 2);
        assert_eq!(snap1[0].0, "alpha.txt");
        assert_eq!(snap1[1].0, "bravo.txt");

        // 3. Mutate directory: add charlie.txt, delete alpha.txt
        crate::operations::read_write::create_core(&fs, 1, "charlie.txt", 0o644, 0, 1000, 1000).unwrap();
        fs.remove_dir_entry(1, "alpha.txt", now);

        // 4. fh1 MUST retain its original snapshot (alpha, bravo)
        let snap1_recheck = fs.get_dir_handle(fh1).expect("Handle snapshot must still exist");
        assert_eq!(snap1_recheck.len(), 2);
        assert_eq!(snap1_recheck[0].0, "alpha.txt");
        assert_eq!(snap1_recheck[1].0, "bravo.txt");

        // 5. A new directory handle on root gets the new snapshot (bravo, charlie)
        let fh2 = fs
            .open_dir_handle(1)
            .expect("open_dir_handle must succeed on directory");
        assert_ne!(fh1, fh2);
        let snap2 = fs.get_dir_handle(fh2).expect("Second handle snapshot must exist");
        assert_eq!(snap2.len(), 2);
        assert_eq!(snap2[0].0, "bravo.txt");
        assert_eq!(snap2[1].0, "charlie.txt");

        // 6. Release fh1
        assert_eq!(fs.release_dir_handle(fh1), Ok(()));
        assert!(fs.get_dir_handle(fh1).is_none());
        assert!(fs.get_dir_handle(fh2).is_some());
        assert_eq!(fs.release_dir_handle(fh1), Err(libc::EBADF));

        // 7. Release fh2
        assert_eq!(fs.release_dir_handle(fh2), Ok(()));
        assert!(fs.get_dir_handle(fh2).is_none());

        // 8. open_dir_handle on a non-directory returns None
        let alpha_ino = snap1[0].1;
        assert!(fs.open_dir_handle(alpha_ino).is_none());
    }

    #[test]
    fn test_file_handle_lifecycle_and_unlinking() {
        let fs = InMemoryFS::new();

        // 1. Create a file
        let attr = crate::operations::read_write::create_core(&fs, 1, "test.txt", 0o644, 0, 1000, 1000).unwrap();
        let ino = attr.ino;

        // 2. Open two file handles
        let fh1 = fs.open_file_handle(ino, libc::O_RDONLY as u32);
        let fh2 = fs.open_file_handle(ino, libc::O_WRONLY as u32);
        assert_ne!(fh1, fh2);
        assert_eq!(fs.open_count(ino), 2);
        assert_eq!(fs.get_file_handle(fh1).unwrap().ino, ino);
        assert_eq!(fs.get_file_handle(fh2).unwrap().ino, ino);

        // 3. Unlink the file while handles are still open
        crate::operations::links::unlink_core(&fs, 1, "test.txt").unwrap();

        // Inode must still exist (not tombstoned) because open_count is 2
        assert!(fs.get_attr(ino).is_some());
        assert_eq!(fs.get_attr(ino).unwrap().nlink, 0);

        // 4. Release first handle
        assert_eq!(fs.release_file_handle(fh1, ino), Ok(()));
        assert!(fs.get_file_handle(fh1).is_none());
        assert!(fs.get_file_handle(fh2).is_some());
        assert_eq!(fs.open_count(ino), 1);
        assert!(fs.get_attr(ino).is_some());
        assert_eq!(fs.release_file_handle(fh1, ino), Err(libc::EBADF));

        // 5. Release second handle -> count drops to 0, inode gets tombstoned
        assert_eq!(fs.release_file_handle(fh2, ino), Ok(()));
        assert!(fs.get_file_handle(fh2).is_none());
        assert_eq!(fs.open_count(ino), 0);
        assert!(
            fs.get_attr(ino).is_none(),
            "Unlinked file with 0 handles must be tombstoned"
        );
    }

    #[test]
    fn test_get_attrs_batch_across_layers() {
        let fs = InMemoryFS::new();

        // 1. Create file1 in live -> freeze to flushing -> fold to base
        let attr1 = crate::operations::read_write::create_core(&fs, 1, "file1.txt", 0o644, 0, 1000, 1000).unwrap();
        fs.begin_flush();
        let batch = fs.flushing.write().unwrap().pop_front().unwrap();
        fs.fold_flushed_batch(batch);

        // 2. Create file2 in live -> freeze to flushing (stays in flushing)
        let attr2 = crate::operations::read_write::create_core(&fs, 1, "file2.txt", 0o644, 0, 1000, 1000).unwrap();
        fs.begin_flush();

        // 3. Create file3 in live (stays in live)
        let attr3 = crate::operations::read_write::create_core(&fs, 1, "file3.txt", 0o644, 0, 1000, 1000).unwrap();

        // 4. Create and unlink file4 (tombstoned)
        let attr4 = crate::operations::read_write::create_core(&fs, 1, "file4.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::links::unlink_core(&fs, 1, "file4.txt").unwrap();

        // Inode 999 does not exist
        let inos = vec![1, attr1.ino, attr2.ino, attr3.ino, attr4.ino, 999];
        let batch_map = fs.get_attrs_batch(&inos);

        // Verify root, file1, file2, file3 are present with matching attributes
        assert!(batch_map.contains_key(&1));
        assert_eq!(batch_map.get(&1).unwrap(), &fs.get_attr(1).unwrap());

        assert!(batch_map.contains_key(&attr1.ino));
        assert_eq!(batch_map.get(&attr1.ino).unwrap(), &fs.get_attr(attr1.ino).unwrap());

        assert!(batch_map.contains_key(&attr2.ino));
        assert_eq!(batch_map.get(&attr2.ino).unwrap(), &fs.get_attr(attr2.ino).unwrap());

        assert!(batch_map.contains_key(&attr3.ino));
        assert_eq!(batch_map.get(&attr3.ino).unwrap(), &fs.get_attr(attr3.ino).unwrap());

        // Tombstoned inode 4 and non-existent inode 999 must NOT be present
        assert!(!batch_map.contains_key(&attr4.ino));
        assert!(!batch_map.contains_key(&999));
    }
}
