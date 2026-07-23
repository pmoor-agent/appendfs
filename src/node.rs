use std::cell::UnsafeCell;
use std::time::SystemTime;

// Structure representing an in-memory node (file, directory, or symlink)
pub enum Node {
    Directory {
        entries: Vec<(String, u64)>,
        perm: u32,
        nlink: u32,
        uid: u32,
        gid: u32,
        atime: SystemTime,
        mtime: SystemTime,
        ctime: SystemTime,
    },
    File {
        content: Vec<u8>,
        perm: u32,
        nlink: u32,
        uid: u32,
        gid: u32,
        atime: SystemTime,
        mtime: SystemTime,
        ctime: SystemTime,
    },
    Symlink {
        target: String,
        nlink: u32,
        uid: u32,
        gid: u32,
        atime: SystemTime,
        mtime: SystemTime,
        ctime: SystemTime,
    },
}

// Thread-safe cell wrapping Node to achieve interior mutability without per-inode lock overhead.
// Safety is guaranteed by acquiring the corresponding bucket lock from LockPool.
pub struct SyncNode(UnsafeCell<Node>);
unsafe impl Send for SyncNode {}
unsafe impl Sync for SyncNode {}

impl SyncNode {
    pub fn new(node: Node) -> Self {
        Self(UnsafeCell::new(node))
    }

    // Safety: Caller must hold the read (or write) lock for this node's bucket in the LockPool.
    pub unsafe fn read(&self) -> &Node {
        unsafe { &*self.0.get() }
    }

    // Safety: Caller must hold the write lock for this node's bucket in the LockPool.
    pub unsafe fn write(&self) -> &mut Node {
        unsafe { &mut *self.0.get() }
    }
}
