//! Staging mutations into `live`, and resolving reads across the whole overlay.
//!
//! Mutations only ever touch `live`; the lower layers are immutable until a flush folds
//! into them. Reads go through [`InMemoryFS::with_layer_stack`], which takes all three
//! layer locks in a safe order - see [`super::layers`] for why the order matters.

use super::{FlushBatch, FsInner, InMemoryFS, InodeLayerStack, is_virtual_ino};
// Only the test-only by-inode read helpers at the bottom of this file return these.
#[cfg(any(test, feature = "testing"))]
use super::ReadPlan;
#[cfg(any(test, feature = "testing"))]
use crate::error::FsError;
use crate::extent_map::ExtentMap;
use crate::node::{
    AttrDelta, DirectoryDelta, EntryDelta, FileDelta, Node, NodeDelta, NodeKind, SpecialDelta, SymlinkDelta,
};
use crate::shim::{FileAttr, FileType};
use crate::sync::OpTag;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::SystemTime;

impl FsInner {
    // --- In-Memory Delta Layer Mutations ---

    pub fn insert_new_node(&mut self, ino: u64, delta: NodeDelta) {
        self.live.insert(ino, EntryDelta::Node(delta));
    }

    pub fn tombstone(&mut self, ino: u64) {
        self.live.insert(ino, EntryDelta::Tombstone);
    }

    pub fn add_dir_entry(&mut self, parent: u64, name: &str, child_ino: u64, now: SystemTime) {
        let entry = self
            .live
            .entry(parent)
            .or_insert_with(|| EntryDelta::Node(NodeDelta::Directory(DirectoryDelta::default())));
        if let EntryDelta::Node(NodeDelta::Directory(d)) = entry {
            d.removed.remove(name);
            d.added.insert(name.to_string(), child_ino);
            d.attr_delta.mtime = Some(now);
            d.attr_delta.ctime = Some(now);
        }
    }

    pub fn remove_dir_entry(&mut self, parent: u64, name: &str, now: SystemTime) {
        let entry = self
            .live
            .entry(parent)
            .or_insert_with(|| EntryDelta::Node(NodeDelta::Directory(DirectoryDelta::default())));
        if let EntryDelta::Node(NodeDelta::Directory(d)) = entry {
            d.added.remove(name);
            d.removed.insert(name.to_string());
            d.attr_delta.mtime = Some(now);
            d.attr_delta.ctime = Some(now);
        }
    }

    pub fn update_dir_parent(&mut self, ino: u64, new_parent: u64) {
        let entry = self
            .live
            .entry(ino)
            .or_insert_with(|| EntryDelta::Node(NodeDelta::Directory(DirectoryDelta::default())));
        if let EntryDelta::Node(NodeDelta::Directory(d)) = entry {
            d.parent = Some(new_parent);
        }
    }

    pub fn get_parent_dir_inode(&self, ino: u64) -> Option<u64> {
        self.with_inode_layers(ino, |layers| layers.parent_dir_inode())
    }

    pub fn update_attr_delta(&mut self, ino: u64, delta: AttrDelta) {
        match self.live.get_mut(&ino) {
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
                self.live.insert(
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
                self.live.insert(
                    ino,
                    EntryDelta::Node(NodeDelta::File(FileDelta {
                        extents: ExtentMap::new(),
                        size: None,
                        attr_delta: delta,
                    })),
                );
            }
            Some(FileType::Symlink) => {
                self.live.insert(
                    ino,
                    EntryDelta::Node(NodeDelta::Symlink(SymlinkDelta {
                        target: None,
                        attr_delta: delta,
                    })),
                );
            }
            Some(FileType::NamedPipe) => {
                self.live.insert(
                    ino,
                    EntryDelta::Node(NodeDelta::Fifo(SpecialDelta {
                        rdev: 0,
                        attr_delta: delta,
                    })),
                );
            }
            Some(FileType::CharDevice) => {
                self.live.insert(
                    ino,
                    EntryDelta::Node(NodeDelta::CharDevice(SpecialDelta {
                        rdev: 0,
                        attr_delta: delta,
                    })),
                );
            }
            Some(FileType::BlockDevice) => {
                self.live.insert(
                    ino,
                    EntryDelta::Node(NodeDelta::BlockDevice(SpecialDelta {
                        rdev: 0,
                        attr_delta: delta,
                    })),
                );
            }
            Some(FileType::Socket) => {
                self.live.insert(
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

    pub fn with_inode_layers<R>(&self, ino: u64, f: impl FnOnce(InodeLayerStack<'_>) -> R) -> R {
        let base_entry = self.base.get(&ino);
        let mut deltas = Vec::with_capacity(self.flushing.len() + 1);
        for batch in self.flushing.iter() {
            if let Some(entry) = batch.entries.get(&ino) {
                deltas.push(entry);
            }
        }
        if let Some(entry) = self.live.get(&ino) {
            deltas.push(entry);
        }

        let stack = InodeLayerStack {
            ino,
            base: base_entry,
            deltas,
        };

        f(stack)
    }

    pub fn with_inode_layers_below_live<R>(&self, ino: u64, f: impl FnOnce(InodeLayerStack<'_>) -> R) -> R {
        let base_entry = self.base.get(&ino);
        let mut deltas = Vec::with_capacity(self.flushing.len());
        for batch in self.flushing.iter() {
            if let Some(entry) = batch.entries.get(&ino) {
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

    pub fn exists_below_live(&self, ino: u64) -> bool {
        self.with_inode_layers_below_live(ino, |layers| layers.exists())
    }

    pub fn attr_below_live(&self, ino: u64) -> Option<FileAttr> {
        self.with_inode_layers_below_live(ino, |layers| layers.attr())
    }

    pub fn get_attr(&self, ino: u64) -> Option<FileAttr> {
        self.with_inode_layers(ino, |layers| layers.attr())
    }

    pub fn lookup_child(&self, parent: u64, name: &str) -> Option<u64> {
        self.with_inode_layers(parent, |layers| layers.lookup_child(name))
    }

    pub fn list_directory(&self, parent: u64) -> Option<Vec<(String, u64)>> {
        self.with_inode_layers(parent, |layers| layers.list_directory())
    }

    pub fn read_link(&self, ino: u64) -> Option<String> {
        self.with_inode_layers(ino, |layers| layers.read_link())
    }

    pub fn get_xattr(&self, ino: u64, name: &str) -> Option<Vec<u8>> {
        self.with_inode_layers(ino, |layers| layers.get_xattr(name))
    }

    pub fn list_xattrs(&self, ino: u64) -> Option<Vec<String>> {
        self.with_inode_layers(ino, |layers| layers.list_xattrs())
    }

    pub fn snapshot_all(&self) -> HashMap<u64, Arc<Node>> {
        let mut result: HashMap<u64, Arc<Node>> = self.base.clone();

        for batch in self.flushing.iter() {
            for (ino, entry) in &batch.entries {
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

        for (ino, entry) in self.live.iter() {
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
    }

    /// Computes active inode counts and total logical byte size across all overlay layers in a single pass.
    pub fn inode_counts(&self) -> InodeCounts {
        let mut dirs = 0;
        let mut files = 0;
        let mut symlinks = 0;
        let mut named_pipes = 0;
        let mut char_devices = 0;
        let mut block_devices = 0;
        let mut sockets = 0;
        let mut total_logical_bytes = 0;

        let mut count_ft = |ft: FileType| match ft {
            FileType::Directory => dirs += 1,
            FileType::RegularFile => files += 1,
            FileType::Symlink => symlinks += 1,
            FileType::NamedPipe => named_pipes += 1,
            FileType::CharDevice => char_devices += 1,
            FileType::BlockDevice => block_devices += 1,
            FileType::Socket => sockets += 1,
        };

        let overlay_cap = self.live.len() + self.flushing.iter().map(|b| b.entries.len()).sum::<usize>();
        let mut seen_overlay = HashSet::with_capacity(overlay_cap);

        let mut process_node_delta = |ino: u64, d: &NodeDelta| {
            count_ft(d.file_type());
            if let NodeDelta::File(f) = d {
                let size = if let Some(s) = f.size {
                    s
                } else {
                    self.with_inode_layers(ino, |layers| layers.attr().map(|a| a.size as u64).unwrap_or(0))
                };
                total_logical_bytes += size;
            }
        };

        for (&ino, delta) in &self.live {
            seen_overlay.insert(ino);
            match delta {
                EntryDelta::Node(d) => process_node_delta(ino, d),
                EntryDelta::Tombstone => {}
            }
        }

        for batch in self.flushing.iter().rev() {
            for (&ino, delta) in &batch.entries {
                if seen_overlay.insert(ino) {
                    match delta {
                        EntryDelta::Node(d) => process_node_delta(ino, d),
                        EntryDelta::Tombstone => {}
                    }
                }
            }
        }

        for (&ino, node) in &self.base {
            if !seen_overlay.contains(&ino) {
                count_ft(node.file_type());
                if let NodeKind::File { size, .. } = &node.kind {
                    total_logical_bytes += size;
                }
            }
        }

        InodeCounts {
            directories: dirs,
            files,
            symlinks,
            named_pipes,
            char_devices,
            block_devices,
            sockets,
            total_logical_bytes,
        }
    }

    /// Captures a point-in-time snapshot of internal metrics while the lock is already held.
    pub fn stats_snapshot(&self) -> InnerStatsSnapshot {
        let (file_handles_count, virt_handles_count, dir_handles_count) = self.handle_counts();
        InnerStatsSnapshot {
            recovered_time: self.recovered_time,
            inode_counts: self.inode_counts(),
            live_len: self.live.len(),
            flushing_batches: self.flushing.len(),
            base_len: self.base.len(),
            staged_bytes: self.staged_bytes,
            staged_ops: self.staged_ops,
            flushing_bytes: self.flushing_bytes,
            flushing_ops: self.flushing_ops,
            file_handles_count,
            virt_handles_count,
            dir_handles_count,
            open_inodes_count: self.open_counts.len(),
            flock_count: self.locks.flock_count(),
            range_lock_count: self.locks.range_lock_count(),
        }
    }
}

/// Category breakdown of active inodes across all overlay layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InodeCounts {
    pub directories: usize,
    pub files: usize,
    pub symlinks: usize,
    pub named_pipes: usize,
    pub char_devices: usize,
    pub block_devices: usize,
    pub sockets: usize,
    pub total_logical_bytes: u64,
}

impl InodeCounts {
    /// Total number of active inodes across all types.
    pub fn total_active(&self) -> usize {
        self.directories + self.files + self.symlinks + self.special()
    }

    /// Total number of special files (named pipes, char devices, block devices, and sockets).
    pub fn special(&self) -> usize {
        self.named_pipes + self.char_devices + self.block_devices + self.sockets
    }
}

/// Point-in-time snapshot of internal mutable filesystem metrics collected under a single lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InnerStatsSnapshot {
    pub recovered_time: Option<SystemTime>,
    pub inode_counts: InodeCounts,
    pub live_len: usize,
    pub flushing_batches: usize,
    pub base_len: usize,
    pub staged_bytes: usize,
    pub staged_ops: usize,
    pub flushing_bytes: usize,
    pub flushing_ops: usize,
    pub file_handles_count: usize,
    pub virt_handles_count: usize,
    pub dir_handles_count: usize,
    pub open_inodes_count: usize,
    pub flock_count: usize,
    pub range_lock_count: usize,
}

impl InMemoryFS {
    /// Takes a point-in-time snapshot of internal filesystem metrics using a single mutex lock.
    pub fn stats_snapshot(&self) -> InnerStatsSnapshot {
        self.inner.lock(OpTag::Stats).unwrap().stats_snapshot()
    }

    /// Computes active inode counts across the overlay layers using a single mutex lock.
    pub fn inode_counts(&self) -> InodeCounts {
        self.inner.lock(OpTag::Stats).unwrap().inode_counts()
    }

    pub fn get_parent_dir_inode(&self, ino: u64) -> Option<u64> {
        self.inner.lock(OpTag::Lookup).unwrap().get_parent_dir_inode(ino)
    }

    // --- Overlay Query & Resolution Methods ---

    pub fn with_layers<R>(
        &self,
        tag: OpTag,
        f: impl FnOnce(&HashMap<u64, EntryDelta>, &VecDeque<Arc<FlushBatch>>, &HashMap<u64, Arc<Node>>) -> R,
    ) -> R {
        let inner = self.inner.lock(tag).unwrap();
        f(&inner.live, &inner.flushing, &inner.base)
    }

    pub fn get_attr_locked(&self, inner: &FsInner, ino: u64) -> Option<FileAttr> {
        if is_virtual_ino(ino) {
            return Some(self.virtual_files.file_attr(ino, 0, self.clock.now()));
        }
        inner.get_attr(ino)
    }

    pub fn get_attr(&self, ino: u64) -> Option<FileAttr> {
        self.get_attr_locked(&self.inner.lock(OpTag::GetAttr).unwrap(), ino)
    }

    pub fn lookup_child_locked(&self, inner: &FsInner, parent: u64, name: &str) -> Option<u64> {
        if parent == 1
            && let Some(ino) = self.virtual_files.get_ino_by_name(name)
        {
            return Some(ino);
        }
        inner.lookup_child(parent, name)
    }

    pub fn lookup_child(&self, parent: u64, name: &str) -> Option<u64> {
        self.lookup_child_locked(&self.inner.lock(OpTag::Lookup).unwrap(), parent, name)
    }

    pub fn list_directory(&self, parent: u64) -> Option<Vec<(String, u64)>> {
        self.inner.lock(OpTag::ReadDir).unwrap().list_directory(parent)
    }

    pub fn read_link(&self, ino: u64) -> Option<String> {
        self.inner.lock(OpTag::ReadLink).unwrap().read_link(ino)
    }

    pub fn get_xattr(&self, ino: u64, name: &str) -> Option<Vec<u8>> {
        self.inner.lock(OpTag::Xattr).unwrap().get_xattr(ino, name)
    }

    pub fn list_xattrs(&self, ino: u64) -> Option<Vec<String>> {
        self.inner.lock(OpTag::Xattr).unwrap().list_xattrs(ino)
    }

    /// Plans a read by inode alone, without an open handle.
    ///
    /// Test-only. Real reads arrive with a file handle and go through
    /// [`InMemoryFS::plan_read_handle`], which additionally validates the handle and serves
    /// virtual files; this exists so tests can read an inode without opening it first.
    #[cfg(any(test, feature = "testing"))]
    pub fn plan_read_file_data(&self, ino: u64, offset: u64, size: usize) -> Result<ReadPlan, FsError> {
        self.with_inner(OpTag::ReadPlan, |inner| {
            inner.check_shutdown(false)?;
            let plan = inner.with_inode_layers(ino, |layers| {
                layers.plan_read_file_data(offset, size, self.log_cache.as_deref())
            })?;

            if self.track_atime && plan.total_len > 0 && inner.shutdown_state == super::ShutdownState::Running {
                let now = self.clock.now();
                inner.update_attr_delta(
                    ino,
                    AttrDelta {
                        atime: Some(now),
                        ..Default::default()
                    },
                );
                inner.record_mutation(0);
            }

            Ok(plan)
        })
    }

    /// Reads file contents by inode alone, without an open handle. Test-only; see
    /// [`InMemoryFS::plan_read_file_data`].
    #[cfg(any(test, feature = "testing"))]
    pub fn read_file_data(&self, ino: u64, offset: u64, size: usize) -> Result<Vec<u8>, FsError> {
        let plan = self.plan_read_file_data(ino, offset, size)?;
        self.execute_read_plan_sync(plan)
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn snapshot_all(&self) -> HashMap<u64, Arc<Node>> {
        self.inner.lock_for_tests().unwrap().snapshot_all()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::{Clock, SystemClock};
    use crate::log::LogWriter;
    use crate::storage::Storage;

    #[test]
    fn test_exists_below_live_sees_a_tombstone_frozen_out_of_live() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = Arc::new(SystemClock);
        let writer = Arc::new(
            LogWriter::create(
                storage,
                1,
                &*clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                crate::crypto::VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        let fs = InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));

        let attr = crate::operations::read_write::create_core(&fs, 1, "f.txt", 0o644, 0, 1000, 1000).unwrap();
        fs.quiesce().unwrap();
        assert!(fs.inner.lock_for_tests().unwrap().exists_below_live(attr.ino));

        crate::operations::links::unlink_core(&fs, 1, "f.txt").unwrap();
        assert!(
            fs.inner.lock_for_tests().unwrap().exists_below_live(attr.ino),
            "base still describes the inode until the tombstone's batch folds"
        );

        // Freeze the tombstone out of `live`. From here `live.entry(ino)` sees nothing, so
        // a writer that validated before taking the lock would insert a fresh delta and
        // resurrect the inode at the next fold - this predicate is what stops it.
        fs.freeze_now();
        assert!(!fs.inner.lock_for_tests().unwrap().live.contains_key(&attr.ino));
        assert!(
            !fs.inner.lock_for_tests().unwrap().exists_below_live(attr.ino),
            "a tombstone frozen out of live must still report the inode as gone"
        );
    }

    #[test]
    fn test_attr_update_does_not_resurrect_a_tombstoned_inode() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = Arc::new(SystemClock);
        let writer = Arc::new(
            LogWriter::create(
                storage,
                1,
                &*clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                crate::crypto::VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        let fs = InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));

        let attr = crate::operations::read_write::create_core(&fs, 1, "f.txt", 0o644, 0, 1000, 1000).unwrap();
        // Fold it into `base`, so the lower layers still describe the inode after deletion.
        fs.quiesce().unwrap();
        crate::operations::links::unlink_core(&fs, 1, "f.txt").unwrap();
        assert!(fs.get_attr(attr.ino).is_none(), "unlinked file must be gone");

        // A late attribute update - an atime bump racing the unlink, say - must not rebuild
        // the node from `base` and bring it back carrying its old link count, unreferenced
        // by any directory.
        fs.with_inner_for_tests(|inner| {
            inner.update_attr_delta(
                attr.ino,
                AttrDelta {
                    atime: Some(clock.now()),
                    ..Default::default()
                },
            );
        });
        assert!(
            fs.get_attr(attr.ino).is_none(),
            "attribute update resurrected a deleted inode"
        );
        assert!(
            !fs.snapshot_all().contains_key(&attr.ino),
            "resurrected inode leaked into the snapshot as an orphan"
        );
    }
}
