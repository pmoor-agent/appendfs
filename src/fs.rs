use crate::clock::{Clock, SystemClock};
use crate::lock_pool::LockPool;
use crate::node::{Node, SyncNode};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

pub struct InMemoryFS {
    pub(crate) inodes: RwLock<HashMap<u64, Arc<SyncNode>>>,
    pub(crate) next_inode: AtomicU64,
    pub(crate) lock_pool: LockPool,
    pub(crate) clock: Arc<dyn Clock>,
}

impl InMemoryFS {
    pub fn new() -> Self {
        Self::with_clock(Arc::new(SystemClock))
    }

    pub fn with_clock(clock: Arc<dyn Clock>) -> Self {
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
        Self {
            inodes: RwLock::new(map),
            next_inode: AtomicU64::new(2),
            lock_pool: LockPool::new(),
            clock,
        }
    }

    pub(crate) fn allocate_inode(&self) -> u64 {
        self.next_inode.fetch_add(1, Ordering::SeqCst)
    }
}

impl Default for InMemoryFS {
    fn default() -> Self {
        Self::new()
    }
}

// Helper to trace parent inodes upwards to scan for parent directories.
// Assumes map read lock is already held.
pub(crate) fn find_parent_inode(
    inodes: &HashMap<u64, Arc<SyncNode>>,
    child_ino: u64,
) -> Option<u64> {
    for (parent_ino, node_arc) in inodes {
        // Safe as we only acquire read locks and the parent-child relationship is read-only here
        let node = unsafe { node_arc.read() };
        if let Node::Directory { entries, .. } = node {
            if entries.iter().any(|(_, ino)| *ino == child_ino) {
                return Some(*parent_ino);
            }
        }
    }
    None
}
