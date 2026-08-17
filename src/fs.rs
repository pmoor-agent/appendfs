use crate::clock::{Clock, SystemClock};
use crate::lock_pool::LockPool;
use crate::log::{
    CreatePayload, ExtentState, GenerationLiveStats, LinkPayload, LogFileCache, LogManifest,
    LogWriter, MkdirPayload, OpCode, RECORD_HEADER_SIZE, RenamePayload, RmdirPayload,
    SetattrPayload, SharedExtentState, SymlinkPayload, UnlinkPayload, WriteMeta,
};
use crate::node::{
    AttrDelta, DirectoryDelta, EntryDelta, FileDelta, Node, NodeDelta, SymlinkDelta, SyncNode,
};
use crate::range_map::RangeMap;
use crate::shim::{FileAttr, FileType};
use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};

/// Returned by `InMemoryFS::begin_flush` when a previous flush hasn't folded yet.
#[derive(Debug)]
pub struct FlushInProgress;

pub struct InMemoryFS {
    /// Resting consolidated state loaded from `.summary` at mount, folded forward over
    /// time by `fold_flush`. Never holds a `Tombstone`.
    pub base: RwLock<HashMap<u64, Arc<SyncNode>>>,
    /// Immutable frozen snapshot currently being written/flushed to disk in the background.
    pub flushing: RwLock<Option<HashMap<u64, EntryDelta>>>,
    /// Current generation's active mutable delta layer receiving live operations.
    pub live: RwLock<HashMap<u64, EntryDelta>>,
    /// Active open file descriptor reference counts per inode for POSIX unlinking semantics.
    pub open_handles: RwLock<HashMap<u64, u32>>,
    /// Authoritative manifest of all active log generations and lineage.
    pub manifest: Arc<RwLock<LogManifest>>,
    pub next_inode: AtomicU64,
    pub last_tx_id: AtomicU64,
    pub lock_pool: LockPool,
    pub clock: Arc<dyn Clock>,
    pub log_writer: Option<Arc<LogWriter>>,
    pub log_cache: Option<Arc<LogFileCache>>,
    pub staged_bytes: AtomicUsize,
    pub max_buffer_size: usize,
    pub flush_lock: Mutex<()>,
    /// When false, `read()` never touches atime (like a `noatime` mount) - defaults to true.
    pub track_atime: bool,
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
            Arc::new(SyncNode::new(Node::Directory {
                parent: 1,
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

        let start_gen = log_writer.as_ref().map_or(1, |w| w.generation());
        let manifest = Arc::new(RwLock::new(LogManifest::new(start_gen, "main")));

        Self {
            base: RwLock::new(map),
            flushing: RwLock::new(None),
            live: RwLock::new(HashMap::new()),
            open_handles: RwLock::new(HashMap::new()),
            manifest,
            next_inode: AtomicU64::new(2),
            last_tx_id: AtomicU64::new(0),
            lock_pool: LockPool::new(),
            clock,
            log_writer,
            log_cache,
            staged_bytes: AtomicUsize::new(0),
            max_buffer_size: 128 * 1024 * 1024,
            flush_lock: Mutex::new(()),
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
        if remaining == 0 {
            if let Some(attr) = self.get_attr(ino) {
                if attr.nlink == 0 {
                    self.tombstone(ino);
                }
            }
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

        // 2. Check flushing delta
        if let Some(flushing) = self.flushing.read().unwrap().as_ref() {
            if let Some(entry) = flushing.get(&ino) {
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

        // 3. Check base
        if let Some(arc) = self.base.read().unwrap().get(&ino) {
            let node = unsafe { arc.read() };
            if let Node::Directory { parent, .. } = node {
                return Some(*parent);
            }
        }

        None
    }

    pub fn update_attr_delta(&self, ino: u64, delta: AttrDelta) {
        let mut live = self.live.write().unwrap();
        if let Some(EntryDelta::Node(node_delta)) = live.get_mut(&ino) {
            match node_delta {
                NodeDelta::Directory(d) => merge_attr_delta(&mut d.attr_delta, &delta),
                NodeDelta::File(f) => merge_attr_delta(&mut f.attr_delta, &delta),
                NodeDelta::Symlink(s) => merge_attr_delta(&mut s.attr_delta, &delta),
            }
            return;
        }

        // Inode not in live yet - query existing type from lower layers without re-acquiring live lock
        let file_type = if let Some(flushing) = self.flushing.read().unwrap().as_ref() {
            if let Some(entry) = flushing.get(&ino) {
                match entry {
                    EntryDelta::Tombstone => None,
                    EntryDelta::Node(NodeDelta::Directory(_)) => Some(FileType::Directory),
                    EntryDelta::Node(NodeDelta::File(_)) => Some(FileType::RegularFile),
                    EntryDelta::Node(NodeDelta::Symlink(_)) => Some(FileType::Symlink),
                }
            } else {
                None
            }
        } else {
            None
        }
        .or_else(|| {
            self.base.read().unwrap().get(&ino).map(|arc| {
                let node = unsafe { arc.read() };
                match node {
                    Node::Directory { .. } => FileType::Directory,
                    Node::File { .. } => FileType::RegularFile,
                    Node::Symlink { .. } => FileType::Symlink,
                }
            })
        });

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

    // --- Overlay Query & Resolution Methods ---

    /// Resolves full `FileAttr` for an inode across `live` -> `flushing` -> `base`.
    pub fn get_attr(&self, ino: u64) -> Option<FileAttr> {
        let live_entry = self.live.read().unwrap().get(&ino).cloned();
        if let Some(EntryDelta::Tombstone) = live_entry {
            return None;
        }

        let flushing_entry = self
            .flushing
            .read()
            .unwrap()
            .as_ref()
            .and_then(|f| f.get(&ino).cloned());
        if let Some(EntryDelta::Tombstone) = flushing_entry {
            if live_entry.is_none() {
                return None;
            }
        }

        let base_node = self.base.read().unwrap().get(&ino).map(|arc| {
            let n = unsafe { arc.read() };
            n.clone()
        });

        let mut attr = if let Some(ref node) = base_node {
            node_to_attr(ino, node)
        } else if let Some(EntryDelta::Node(ref delta)) = flushing_entry {
            delta_to_initial_attr(ino, delta)
        } else if let Some(EntryDelta::Node(ref delta)) = live_entry {
            delta_to_initial_attr(ino, delta)
        } else {
            return None;
        };

        if let Some(EntryDelta::Node(ref delta)) = flushing_entry {
            apply_node_delta(&mut attr, delta);
        }
        if let Some(EntryDelta::Node(ref delta)) = live_entry {
            apply_node_delta(&mut attr, delta);
        }

        Some(attr)
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

        if let Some(flushing) = self.flushing.read().unwrap().as_ref() {
            if let Some(entry) = flushing.get(&parent) {
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

        if let Some(arc) = self.base.read().unwrap().get(&parent) {
            let node = unsafe { arc.read() };
            if let Node::Directory { entries, .. } = node {
                if let Some((_, ino)) = entries.iter().find(|(entry_name, _)| entry_name == name) {
                    return Some(*ino);
                }
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

        let mut map: HashMap<String, u64> = HashMap::new();

        if let Some(arc) = self.base.read().unwrap().get(&parent) {
            let node = unsafe { arc.read() };
            if let Node::Directory { entries, .. } = node {
                for (name, child_ino) in entries {
                    map.insert(name.clone(), *child_ino);
                }
            }
        }

        if let Some(flushing) = self.flushing.read().unwrap().as_ref() {
            if let Some(EntryDelta::Node(NodeDelta::Directory(d))) = flushing.get(&parent) {
                for name in &d.removed {
                    map.remove(name);
                }
                for (name, child_ino) in &d.added {
                    map.insert(name.clone(), *child_ino);
                }
            }
        }

        if let Some(EntryDelta::Node(NodeDelta::Directory(d))) =
            self.live.read().unwrap().get(&parent)
        {
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

        if let Some(flushing) = self.flushing.read().unwrap().as_ref() {
            if let Some(entry) = flushing.get(&ino) {
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

        if let Some(arc) = self.base.read().unwrap().get(&ino) {
            let node = unsafe { arc.read() };
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

        let truncate_mask = self
            .live
            .read()
            .unwrap()
            .get(&ino)
            .and_then(|e| match e {
                EntryDelta::Node(NodeDelta::File(f)) => f.truncate_mask,
                _ => None,
            })
            .or_else(|| {
                self.flushing
                    .read()
                    .unwrap()
                    .as_ref()
                    .and_then(|f| f.get(&ino))
                    .and_then(|e| match e {
                        EntryDelta::Node(NodeDelta::File(f)) => f.truncate_mask,
                        _ => None,
                    })
            })
            .unwrap_or(u64::MAX);

        let live_extents = if let Some(EntryDelta::Node(NodeDelta::File(f))) =
            self.live.read().unwrap().get(&ino)
        {
            f.extents.query(offset, read_len)
        } else {
            Vec::new()
        };

        let mut filled = vec![false; read_len as usize];

        for (ext_start, ext_len, shared_state) in live_extents {
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

        // Query flushing layer for gaps
        if let Some(flushing) = self.flushing.read().unwrap().as_ref() {
            if let Some(EntryDelta::Node(NodeDelta::File(f))) = flushing.get(&ino) {
                let max_flushing_read =
                    std::cmp::min(read_len, truncate_mask.saturating_sub(offset));
                if max_flushing_read > 0 {
                    for (ext_start, ext_len, shared_state) in
                        f.extents.query(offset, max_flushing_read)
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

        // Query base layer for remaining gaps
        if let Some(arc) = self.base.read().unwrap().get(&ino) {
            let node = unsafe { arc.read() };
            if let Node::File { range_map, .. } = node {
                let max_base_read = std::cmp::min(read_len, truncate_mask.saturating_sub(offset));
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
                if let Some(ref cache) = self.log_cache {
                    if let Ok(file_arc) = cache.get_or_open(generation) {
                        let mut f = file_arc.lock().unwrap();
                        let disk_seek_pos = record_log_offset
                            + crate::log::RECORD_HEADER_SIZE as u64
                            + payload_offset as u64
                            + slice_inner_offset as u64;
                        if f.seek(SeekFrom::Start(disk_seek_pos)).is_ok() {
                            if f.read_exact(&mut temp_buf).is_ok() {
                                bytes_read = seg_len;
                            }
                        }
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

    /// Merges all three layers into a consolidated snapshot map.
    pub fn snapshot_all(&self) -> HashMap<u64, Arc<SyncNode>> {
        let mut result: HashMap<u64, Arc<SyncNode>> = self.base.read().unwrap().clone();

        if let Some(flushing) = self.flushing.read().unwrap().as_ref() {
            for (ino, entry) in flushing {
                match entry {
                    EntryDelta::Tombstone => {
                        result.remove(ino);
                    }
                    EntryDelta::Node(delta) => {
                        if let Some(existing_arc) = result.get(ino).cloned() {
                            let mut node_clone = unsafe { existing_arc.read() }.clone();
                            apply_delta_to_node(&mut node_clone, delta);
                            result.insert(*ino, Arc::new(SyncNode::new(node_clone)));
                        } else {
                            result.insert(*ino, Arc::new(SyncNode::new(delta_to_node(delta))));
                        }
                    }
                }
            }
        }

        for (ino, entry) in self.live.read().unwrap().iter() {
            match entry {
                EntryDelta::Tombstone => {
                    result.remove(ino);
                }
                EntryDelta::Node(delta) => {
                    if let Some(existing_arc) = result.get(ino).cloned() {
                        let mut node_clone = unsafe { existing_arc.read() }.clone();
                        apply_delta_to_node(&mut node_clone, delta);
                        result.insert(*ino, Arc::new(SyncNode::new(node_clone)));
                    } else {
                        result.insert(*ino, Arc::new(SyncNode::new(delta_to_node(delta))));
                    }
                }
            }
        }

        result.retain(|_ino, arc| {
            let node = unsafe { arc.read() };
            match node {
                Node::File { nlink, .. } | Node::Symlink { nlink, .. } => *nlink > 0,
                Node::Directory { .. } => true,
            }
        });

        result
    }

    // --- Flush & Fold Pipelines ---

    /// Freezes `live` into `flushing`.
    pub fn begin_flush(&self) -> Result<(), FlushInProgress> {
        let _dir_guard = self.dir_lock.lock().unwrap();
        let _bucket_guards = self.lock_pool.write_all();

        let mut flushing_guard = self.flushing.write().unwrap();
        if flushing_guard.is_some() {
            return Err(FlushInProgress);
        }
        let frozen = std::mem::take(&mut *self.live.write().unwrap());
        *flushing_guard = Some(frozen);
        Ok(())
    }

    pub fn begin_flush_blocking(&self) {
        loop {
            match self.begin_flush() {
                Ok(()) => return,
                Err(FlushInProgress) => std::thread::sleep(Duration::from_millis(10)),
            }
        }
    }

    pub fn current_flushing(&self) -> Option<HashMap<u64, EntryDelta>> {
        self.flushing.read().unwrap().clone()
    }

    /// Merges `flushing` into `base` and resets `flushing = None`.
    pub fn fold_flush(&self) {
        let mut flushing_guard = self.flushing.write().unwrap();
        let Some(flushed) = flushing_guard.take() else {
            return;
        };
        let mut base = self.base.write().unwrap();
        for (ino, entry) in flushed {
            match entry {
                EntryDelta::Tombstone => {
                    base.remove(&ino);
                }
                EntryDelta::Node(delta) => {
                    if let Some(existing_arc) = base.get(&ino).cloned() {
                        let mut node_clone = unsafe { existing_arc.read() }.clone();
                        apply_delta_to_node(&mut node_clone, &delta);
                        base.insert(ino, Arc::new(SyncNode::new(node_clone)));
                    } else {
                        base.insert(ino, Arc::new(SyncNode::new(delta_to_node(&delta))));
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
                    estimated_bytes += (d.added.len() + d.removed.len()) as u64
                        * (RECORD_HEADER_SIZE as u64 + 64);
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
                crate::log::record::FILE_HEADER_SIZE as u64,
            );
        }

        let base_map = self.base.read().unwrap();
        let mut inos: Vec<u64> = frozen.keys().cloned().collect();
        inos.sort();

        let mut written_count = 0;
        let mut flushed_data_bytes = 0u64;
        let now = self.clock.now();

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
                let node = unsafe { base_arc.read() };
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
                                if let Node::Directory { .. } = unsafe { child_arc.read() } {
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
                    renames_to_emit.push((
                        child_ino,
                        parent_ino,
                        name,
                        new_parent,
                        new_name,
                        op_time,
                    ));
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
            if let Some(EntryDelta::Node(NodeDelta::Directory(d))) = frozen.get(&ino) {
                if !base_map.contains_key(&ino) {
                    let (parent, name) = primary_creation
                        .get(&ino)
                        .cloned()
                        .unwrap_or_else(|| (1, format!("dir_{}", ino)));
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
                        let bytes = bincode::serialize(&payload)
                            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
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
                        let bytes = bincode::serialize(&payload)
                            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                        writer.append_record(OpCode::Mkdir, ino, &bytes)?;
                        written_count += 1;
                    }
                }
            }
        }

        // Phase 3: Create and Symlink
        for &ino in &inos {
            match frozen.get(&ino) {
                Some(EntryDelta::Node(NodeDelta::File(f))) => {
                    if !base_map.contains_key(&ino) {
                        let (parent, name) = primary_creation
                            .get(&ino)
                            .cloned()
                            .unwrap_or_else(|| (1, format!("file_{}", ino)));
                        let op_time = f.attr_delta.ctime.unwrap_or(now);
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
                    if !base_map.contains_key(&ino) {
                        let (parent, name) = primary_creation
                            .get(&ino)
                            .cloned()
                            .unwrap_or_else(|| (1, format!("symlink_{}", ino)));
                        let op_time = s.attr_delta.ctime.unwrap_or(now);
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
                _ => {}
            }
        }

        // Phase 4: Renames
        for (child_ino, parent, name, new_parent, new_name, op_time) in renames_to_emit {
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

        // Phase 6: Synthesize File Writes (with extent coalescing)
        for &ino in &inos {
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
                    f.extents.insert(start_offset, total_length, consolidated_extent);

                    idx = run_end;
                }
            }
        }

        // Phase 7: Synthesize Setattr updates
        for &ino in &inos {
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
                Some(EntryDelta::Node(NodeDelta::Symlink(s))) => {
                    if s.attr_delta.mode.is_some()
                        || s.attr_delta.uid.is_some()
                        || s.attr_delta.gid.is_some()
                        || s.attr_delta.mtime.is_some()
                        || s.attr_delta.ctime.is_some()
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
    }

    pub fn flush_log(&self) -> std::io::Result<()> {
        let _flush_guard = self.flush_lock.lock().unwrap();
        let Some(ref writer) = self.log_writer else {
            return Ok(());
        };

        self.begin_flush_blocking();
        {
            let mut flushing_write = self.flushing.write().unwrap();
            let Some(ref mut frozen) = *flushing_write else {
                return Ok(());
            };
            if frozen.is_empty() {
                drop(flushing_write);
                self.fold_flush();
                return Ok(());
            }

            self.synthesize_and_write_flushing_layer(frozen, writer)?;
        }
        self.fold_flush();
        self.staged_bytes.store(0, Ordering::Relaxed);
        Ok(())
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
            let node = unsafe { node_arc.read() };
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
        crate::log::export_summary(
            &snapshot,
            &manifest,
            log_dir,
            generation,
            last_tx_id,
            next_inode,
        )
    }

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
            let node = unsafe { node_arc.read() };
            if let Node::File { range_map, size, .. } = node {
                assert_eq!(*size, 50);
                assert_eq!(range_map.len(), 1, "Expected exactly 1 consolidated RangeEntry in base!");
                let (start, entry) = range_map.iter().next().unwrap();
                assert_eq!(*start, 0);
                assert_eq!(entry.length, 50);
                assert!(matches!(entry.value.read_state(), crate::log::ExtentState::Disk { length: 50, .. }));
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
        let dir1 = crate::operations::dir::mkdir_core(&fs, 1, "dir1", 0o755, 1000, 1000).unwrap().ino;
        assert_eq!(fs.get_parent_dir_inode(dir1), Some(1));

        // Create dir2 (child of dir1)
        let dir2 = crate::operations::dir::mkdir_core(&fs, dir1, "dir2", 0o755, 1000, 1000).unwrap().ino;
        assert_eq!(fs.get_parent_dir_inode(dir2), Some(dir1));

        // Create dir3 (child of root)
        let dir3 = crate::operations::dir::mkdir_core(&fs, 1, "dir3", 0o755, 1000, 1000).unwrap().ino;
        assert_eq!(fs.get_parent_dir_inode(dir3), Some(1));

        // Move dir2 from dir1 into dir3
        crate::operations::links::rename_core(&fs, dir1, "dir2", dir3, "dir2_moved").unwrap();
        assert_eq!(fs.get_parent_dir_inode(dir2), Some(dir3));

        // Fold live to base
        {
            let mut live = fs.live.write().unwrap();
            let mut flushing = fs.flushing.write().unwrap();
            *flushing = Some(std::mem::take(&mut *live));
        }
        fs.fold_flush();

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
            Arc::new(SyncNode::new(Node::File {
                range_map: RangeMap::new(),
                size: 0,
                perm: 0o644,
                nlink: 1,
                uid: 1000,
                gid: 1000,
                atime: clock.now(),
                mtime: clock.now(),
                ctime: clock.now(),
            })),
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

        let file1_attr = crate::operations::read_write::create_core(&fs, gletscher_ino, "file1.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::write_core(&fs, file1_attr.ino, &[1, 2, 3, 4], 0).unwrap();

        let file2_attr = crate::operations::read_write::create_core(&fs, gletscher_ino, "file2.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::write_core(&fs, file2_attr.ino, &[5, 6, 7, 8], 0).unwrap();

        let sub_attr = crate::operations::dir::mkdir_core(&fs, gletscher_ino, "sub", 0o755, 1000, 1000).unwrap();
        let sub_ino = sub_attr.ino;

        let file3_attr = crate::operations::read_write::create_core(&fs, sub_ino, "file3.txt", 0o644, 0, 1000, 1000).unwrap();
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
        let file_attr = crate::operations::read_write::create_core(&fs, keep_attr.ino, "shared.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::write_core(&fs, file_attr.ino, b"persistent shared content", 0).unwrap();

        // 3. Create hard link /Gletscher/shared_link.txt -> inode N (nlink becomes 2)
        let link_attr = crate::operations::links::link_core(&fs, file_attr.ino, gletscher_attr.ino, "shared_link.txt").unwrap();
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
        let rec_file_attr = recovered.get_attr(file_attr.ino).expect("shared.txt must survive recovery");
        assert_eq!(rec_file_attr.nlink, 1);

        let data = crate::operations::read_write::read_core(&recovered, file_attr.ino, 25, 0).unwrap();
        assert_eq!(&data, b"persistent shared content");

        let rec_stats = recovered.calculate_generation_live_stats();
        assert_eq!(rec_stats[0].live_bytes, 25);
        assert_eq!(rec_stats[0].live_extents, 1);
    }
}
