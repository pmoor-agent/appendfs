pub mod shim;

use shim::{FileAttr, FileType, Filesystem, Request};
use std::cell::UnsafeCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

// Structure representing an in-memory node (file, directory, or symlink)
pub enum Node {
    Directory {
        entries: Vec<(String, u64)>,
        perm: u32,
        nlink: u32,
    },
    File {
        content: Vec<u8>,
        perm: u32,
        nlink: u32,
    },
    Symlink {
        target: String,
        nlink: u32,
    },
}

// Thread-safe cell wrapping Node to achieve interior mutability without per-inode lock overhead.
// Safety is guaranteed by acquiring the corresponding bucket lock from LockPool.
pub struct SyncNode(UnsafeCell<Node>);
unsafe impl Send for SyncNode {}
unsafe impl Sync for SyncNode {}

impl SyncNode {
    fn new(node: Node) -> Self {
        Self(UnsafeCell::new(node))
    }

    // Safety: Caller must hold the read (or write) lock for this node's bucket in the LockPool.
    unsafe fn read(&self) -> &Node {
        unsafe { &*self.0.get() }
    }

    // Safety: Caller must hold the write lock for this node's bucket in the LockPool.
    unsafe fn write(&self) -> &mut Node {
        unsafe { &mut *self.0.get() }
    }
}

// Centralized fixed-size lock pool using striped locks.
// Maps inode numbers to locks deterministically: idx = ino % 1024.
const BUCKET_COUNT: usize = 1024;

struct LockPool {
    locks: Vec<RwLock<()>>,
}

impl LockPool {
    fn new() -> Self {
        let mut locks = Vec::with_capacity(BUCKET_COUNT);
        for _ in 0..BUCKET_COUNT {
            locks.push(RwLock::new(()));
        }
        Self { locks }
    }

    fn read(&self, ino: u64) -> std::sync::RwLockReadGuard<'_, ()> {
        let idx = (ino % BUCKET_COUNT as u64) as usize;
        self.locks[idx].read().unwrap()
    }

    fn write(&self, ino: u64) -> std::sync::RwLockWriteGuard<'_, ()> {
        let idx = (ino % BUCKET_COUNT as u64) as usize;
        self.locks[idx].write().unwrap()
    }

    // Acquires write locks for two inodes in a deadlock-safe manner.
    // Handles bucket collisions gracefully by only locking once.
    fn write_two(
        &self,
        ino1: u64,
        ino2: u64,
    ) -> (
        std::sync::RwLockWriteGuard<'_, ()>,
        Option<std::sync::RwLockWriteGuard<'_, ()>>,
    ) {
        let idx1 = (ino1 % BUCKET_COUNT as u64) as usize;
        let idx2 = (ino2 % BUCKET_COUNT as u64) as usize;

        if idx1 == idx2 {
            let guard = self.locks[idx1].write().unwrap();
            (guard, None)
        } else if idx1 < idx2 {
            let guard1 = self.locks[idx1].write().unwrap();
            let guard2 = self.locks[idx2].write().unwrap();
            (guard1, Some(guard2))
        } else {
            let guard2 = self.locks[idx2].write().unwrap();
            let guard1 = self.locks[idx1].write().unwrap();
            (guard1, Some(guard2))
        }
    }
}

pub struct InMemoryFS {
    inodes: RwLock<HashMap<u64, Arc<SyncNode>>>,
    next_inode: AtomicU64,
    lock_pool: LockPool,
}

impl InMemoryFS {
    pub fn new() -> Self {
        let mut map = HashMap::new();
        // Start with only the root directory (Inode 1), which is empty, nlink is 2 (parent entry and '.' link)
        map.insert(
            1,
            Arc::new(SyncNode::new(Node::Directory {
                entries: Vec::new(),
                perm: 0o755,
                nlink: 2,
            })),
        );
        Self {
            inodes: RwLock::new(map),
            next_inode: AtomicU64::new(2),
            lock_pool: LockPool::new(),
        }
    }

    fn allocate_inode(&self) -> u64 {
        self.next_inode.fetch_add(1, Ordering::SeqCst)
    }
}

// Helper to trace parent inodes upwards to scan for parent directories.
// Assumes map read lock is already held.
fn find_parent_inode(inodes: &HashMap<u64, Arc<SyncNode>>, child_ino: u64) -> Option<u64> {
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

impl Filesystem for InMemoryFS {
    fn getattr(&self, req: Request, ino: u64) {
        println!("TRACE: getattr(ino={})", ino);
        let node_arc = {
            let map = self.inodes.read().unwrap();
            match map.get(&ino) {
                Some(n) => Arc::clone(n),
                None => {
                    req.reply_err(libc::ENOENT);
                    return;
                }
            }
        };

        let _guard = self.lock_pool.read(ino);
        let node = unsafe { node_arc.read() };
        match node {
            Node::Directory { perm, nlink, .. } => {
                req.reply_attr(
                    &FileAttr {
                        ino,
                        file_type: FileType::Directory,
                        perm: *perm,
                        nlink: *nlink,
                        size: 0,
                    },
                    1.0,
                );
            }
            Node::File {
                content,
                perm,
                nlink,
            } => {
                req.reply_attr(
                    &FileAttr {
                        ino,
                        file_type: FileType::RegularFile,
                        perm: *perm,
                        nlink: *nlink,
                        size: content.len() as i64,
                    },
                    1.0,
                );
            }
            Node::Symlink { target, nlink } => {
                req.reply_attr(
                    &FileAttr {
                        ino,
                        file_type: FileType::Symlink,
                        perm: 0o777,
                        nlink: *nlink,
                        size: target.len() as i64,
                    },
                    1.0,
                );
            }
        }
    }

    fn lookup(&self, req: Request, parent: u64, name: &str) {
        println!("TRACE: lookup(parent={}, name={})", parent, name);
        let parent_node_arc = {
            let map = self.inodes.read().unwrap();
            match map.get(&parent) {
                Some(n) => Arc::clone(n),
                None => {
                    req.reply_err(libc::ENOENT);
                    return;
                }
            }
        };

        // Lookup child inode inside directory
        let child_ino = {
            let _guard = self.lock_pool.read(parent);
            let parent_node = unsafe { parent_node_arc.read() };
            match parent_node {
                Node::Directory { entries, .. } => {
                    match entries.iter().find(|(entry_name, _)| entry_name == name) {
                        Some((_, ino)) => *ino,
                        None => {
                            req.reply_err(libc::ENOENT);
                            return;
                        }
                    }
                }
                _ => {
                    req.reply_err(libc::ENOTDIR);
                    return;
                }
            }
        };

        // Query child attributes
        let child_node_arc = {
            let map = self.inodes.read().unwrap();
            match map.get(&child_ino) {
                Some(n) => Arc::clone(n),
                None => {
                    req.reply_err(libc::ENOENT);
                    return;
                }
            }
        };

        let _guard = self.lock_pool.read(child_ino);
        let child_node = unsafe { child_node_arc.read() };
        match child_node {
            Node::Directory { perm, nlink, .. } => {
                req.reply_entry(
                    &FileAttr {
                        ino: child_ino,
                        file_type: FileType::Directory,
                        perm: *perm,
                        nlink: *nlink,
                        size: 0,
                    },
                    1.0,
                    1.0,
                );
            }
            Node::File {
                content,
                perm,
                nlink,
            } => {
                req.reply_entry(
                    &FileAttr {
                        ino: child_ino,
                        file_type: FileType::RegularFile,
                        perm: *perm,
                        nlink: *nlink,
                        size: content.len() as i64,
                    },
                    1.0,
                    1.0,
                );
            }
            Node::Symlink { target, nlink } => {
                req.reply_entry(
                    &FileAttr {
                        ino: child_ino,
                        file_type: FileType::Symlink,
                        perm: 0o777,
                        nlink: *nlink,
                        size: target.len() as i64,
                    },
                    1.0,
                    1.0,
                );
            }
        }
    }

    fn readdir(&self, req: Request, ino: u64, size: usize, offset: i64) {
        println!(
            "TRACE: readdir(ino={}, size={}, offset={})",
            ino, size, offset
        );
        let entries = {
            let node_arc = {
                let map = self.inodes.read().unwrap();
                match map.get(&ino) {
                    Some(n) => Arc::clone(n),
                    None => {
                        req.reply_err(libc::ENOENT);
                        return;
                    }
                }
            };
            let _guard = self.lock_pool.read(ino);
            let node = unsafe { node_arc.read() };
            match node {
                Node::Directory { entries, .. } => entries.clone(),
                _ => {
                    req.reply_err(libc::ENOTDIR);
                    return;
                }
            }
        };

        let mut db = shim::DirectoryBuffer::new(req);
        db.add(".", ino, FileType::Directory);
        db.add("..", 1, FileType::Directory); // Simple root parent is root

        let map = self.inodes.read().unwrap();
        for (name, child_ino) in &entries {
            if let Some(child_node_arc) = map.get(child_ino) {
                let _guard = self.lock_pool.read(*child_ino);
                let child_node = unsafe { child_node_arc.read() };
                let file_type = match child_node {
                    Node::Directory { .. } => FileType::Directory,
                    Node::File { .. } => FileType::RegularFile,
                    Node::Symlink { .. } => FileType::Symlink,
                };
                db.add(name, *child_ino, file_type);
            }
        }
        drop(map);

        db.reply(offset, size);
    }

    fn read(&self, req: Request, ino: u64, size: usize, offset: i64) {
        println!("TRACE: read(ino={}, size={}, offset={})", ino, size, offset);
        let node_arc = {
            let map = self.inodes.read().unwrap();
            match map.get(&ino) {
                Some(n) => Arc::clone(n),
                None => {
                    req.reply_err(libc::ENOENT);
                    return;
                }
            }
        };

        let _guard = self.lock_pool.read(ino);
        let node = unsafe { node_arc.read() };
        match node {
            Node::File { content, .. } => {
                let len = content.len();
                if offset >= len as i64 {
                    req.reply_buf(&[]);
                    return;
                }
                let start = offset as usize;
                let end = std::cmp::min(start + size, len);
                req.reply_buf(&content[start..end]);
            }
            _ => {
                req.reply_err(libc::EISDIR);
            }
        }
    }

    fn open(&self, req: Request, ino: u64, flags: u32) {
        println!("TRACE: open(ino={}, flags=0x{:x})", ino, flags);
        if (flags & libc::O_TRUNC as u32) != 0 {
            let node_arc = {
                let map = self.inodes.read().unwrap();
                match map.get(&ino) {
                    Some(n) => Arc::clone(n),
                    None => {
                        req.reply_err(libc::ENOENT);
                        return;
                    }
                }
            };
            let _guard = self.lock_pool.write(ino);
            let node = unsafe { node_arc.write() };
            match node {
                Node::File { content, .. } => {
                    println!("TRACE: truncating file to 0 inside open");
                    content.clear();
                }
                _ => {
                    req.reply_err(libc::EISDIR);
                    return;
                }
            }
        }
        req.reply_open(0);
    }

    fn write(&self, req: Request, ino: u64, buf: &[u8], offset: i64) {
        println!(
            "TRACE: write(ino={}, len={}, offset={})",
            ino,
            buf.len(),
            offset
        );
        let node_arc = {
            let map = self.inodes.read().unwrap();
            match map.get(&ino) {
                Some(n) => Arc::clone(n),
                None => {
                    req.reply_err(libc::ENOENT);
                    return;
                }
            }
        };

        let _guard = self.lock_pool.write(ino);
        let node = unsafe { node_arc.write() };
        match node {
            Node::File { content, .. } => {
                let len = content.len();
                let start = offset as usize;
                let end = start + buf.len();

                if end > len {
                    content.resize(end, 0);
                }

                content[start..end].copy_from_slice(buf);
                req.reply_write(buf.len());
            }
            _ => {
                req.reply_err(libc::EISDIR);
            }
        }
    }

    fn setattr(&self, req: Request, ino: u64, size: i64, to_set: u32) {
        println!(
            "TRACE: setattr(ino={}, size={}, to_set={})",
            ino, size, to_set
        );
        let node_arc = {
            let map = self.inodes.read().unwrap();
            match map.get(&ino) {
                Some(n) => Arc::clone(n),
                None => {
                    req.reply_err(libc::ENOENT);
                    return;
                }
            }
        };

        const FUSE_SET_ATTR_SIZE: u32 = 1 << 3;

        let _guard = self.lock_pool.write(ino);
        let node = unsafe { node_arc.write() };
        match node {
            Node::File {
                content,
                perm,
                nlink,
            } => {
                if (to_set & FUSE_SET_ATTR_SIZE) != 0 {
                    println!("TRACE: truncating file to {}", size);
                    content.resize(size as usize, 0);
                }
                req.reply_attr(
                    &FileAttr {
                        ino,
                        file_type: FileType::RegularFile,
                        perm: *perm,
                        nlink: *nlink,
                        size: content.len() as i64,
                    },
                    1.0,
                );
            }
            Node::Directory { perm, nlink, .. } => {
                req.reply_attr(
                    &FileAttr {
                        ino,
                        file_type: FileType::Directory,
                        perm: *perm,
                        nlink: *nlink,
                        size: 0,
                    },
                    1.0,
                );
            }
            Node::Symlink { target, nlink } => {
                req.reply_attr(
                    &FileAttr {
                        ino,
                        file_type: FileType::Symlink,
                        perm: 0o777,
                        nlink: *nlink,
                        size: target.len() as i64,
                    },
                    1.0,
                );
            }
        }
    }

    fn create(&self, req: Request, parent: u64, name: &str, mode: u32, flags: u32) {
        println!(
            "TRACE: create(parent={}, name={}, mode=0o{:o}, flags=0x{:x})",
            parent, name, mode, flags
        );
        let parent_node_arc = {
            let map = self.inodes.read().unwrap();
            match map.get(&parent) {
                Some(n) => Arc::clone(n),
                None => {
                    req.reply_err(libc::ENOENT);
                    return;
                }
            }
        };

        let new_ino = self.allocate_inode();

        {
            let _guard = self.lock_pool.write(parent);
            let parent_node = unsafe { parent_node_arc.write() };
            match parent_node {
                Node::Directory { entries, .. } => {
                    if entries.iter().any(|(entry_name, _)| entry_name == name) {
                        req.reply_err(libc::EEXIST);
                        return;
                    }
                    entries.push((name.to_string(), new_ino));
                }
                _ => {
                    req.reply_err(libc::ENOTDIR);
                    return;
                }
            }
        }

        let new_node = Arc::new(SyncNode::new(Node::File {
            content: Vec::new(),
            perm: mode & 0o777,
            nlink: 1,
        }));

        let mut map = self.inodes.write().unwrap();
        map.insert(new_ino, Arc::clone(&new_node));
        drop(map);

        req.reply_create(
            &FileAttr {
                ino: new_ino,
                file_type: FileType::RegularFile,
                perm: mode & 0o777,
                nlink: 1,
                size: 0,
            },
            1.0,
            1.0,
            0,
        );
    }

    fn unlink(&self, req: Request, parent: u64, name: &str) {
        println!("TRACE: unlink(parent={}, name={})", parent, name);
        let parent_node_arc = {
            let map = self.inodes.read().unwrap();
            match map.get(&parent) {
                Some(n) => Arc::clone(n),
                None => {
                    req.reply_err(libc::ENOENT);
                    return;
                }
            }
        };

        let (removed_ino, child_node_arc) = {
            let _guard = self.lock_pool.write(parent);
            let parent_node = unsafe { parent_node_arc.write() };
            match parent_node {
                Node::Directory { entries, .. } => {
                    if let Some(pos) = entries
                        .iter()
                        .position(|(entry_name, _)| entry_name == name)
                    {
                        let (_, child_ino) = entries.remove(pos);

                        let map = self.inodes.read().unwrap();
                        let n_opt = map.get(&child_ino).map(Arc::clone);
                        (Some(child_ino), n_opt)
                    } else {
                        req.reply_err(libc::ENOENT);
                        (None, None)
                    }
                }
                _ => {
                    req.reply_err(libc::ENOTDIR);
                    (None, None)
                }
            }
        };

        if let Some(child_ino) = removed_ino {
            let mut should_delete = false;
            if let Some(node_arc) = child_node_arc {
                let _child_guard = self.lock_pool.write(child_ino);
                let child_node = unsafe { node_arc.write() };
                match child_node {
                    Node::File { nlink, .. } => {
                        if *nlink > 0 {
                            *nlink -= 1;
                        }
                        if *nlink == 0 {
                            should_delete = true;
                        }
                    }
                    Node::Symlink { nlink, .. } => {
                        if *nlink > 0 {
                            *nlink -= 1;
                        }
                        if *nlink == 0 {
                            should_delete = true;
                        }
                    }
                    Node::Directory { nlink, .. } => {
                        if *nlink > 0 {
                            *nlink -= 1;
                        }
                        if *nlink == 0 {
                            should_delete = true;
                        }
                    }
                }
            }

            if should_delete {
                let mut map = self.inodes.write().unwrap();
                map.remove(&child_ino);
            }
            req.reply_err(0);
        }
    }

    fn mkdir(&self, req: Request, parent: u64, name: &str, mode: u32) {
        println!(
            "TRACE: mkdir(parent={}, name={}, mode=0o{:o})",
            parent, name, mode
        );
        let parent_node_arc = {
            let map = self.inodes.read().unwrap();
            match map.get(&parent) {
                Some(n) => Arc::clone(n),
                None => {
                    req.reply_err(libc::ENOENT);
                    return;
                }
            }
        };

        let new_ino = self.allocate_inode();

        {
            let _guard = self.lock_pool.write(parent);
            let parent_node = unsafe { parent_node_arc.write() };
            match parent_node {
                Node::Directory { entries, .. } => {
                    if entries.iter().any(|(entry_name, _)| entry_name == name) {
                        req.reply_err(libc::EEXIST);
                        return;
                    }
                    entries.push((name.to_string(), new_ino));
                }
                _ => {
                    req.reply_err(libc::ENOTDIR);
                    return;
                }
            }
        }

        let new_node = Arc::new(SyncNode::new(Node::Directory {
            entries: Vec::new(),
            perm: mode & 0o777,
            nlink: 2, // '.' and parent entry
        }));

        let mut map = self.inodes.write().unwrap();
        map.insert(new_ino, Arc::clone(&new_node));
        drop(map);

        req.reply_entry(
            &FileAttr {
                ino: new_ino,
                file_type: FileType::Directory,
                perm: mode & 0o777,
                nlink: 2,
                size: 0,
            },
            1.0,
            1.0,
        );
    }

    fn rmdir(&self, req: Request, parent: u64, name: &str) {
        println!("TRACE: rmdir(parent={}, name={})", parent, name);
        let parent_node_arc = {
            let map = self.inodes.read().unwrap();
            match map.get(&parent) {
                Some(n) => Arc::clone(n),
                None => {
                    req.reply_err(libc::ENOENT);
                    return;
                }
            }
        };

        let removed_ino = {
            let _guard = self.lock_pool.write(parent);
            let parent_node = unsafe { parent_node_arc.write() };
            match parent_node {
                Node::Directory { entries, .. } => {
                    if let Some(pos) = entries
                        .iter()
                        .position(|(entry_name, _)| entry_name == name)
                    {
                        let (_, child_ino) = entries[pos];

                        let child_node_arc = {
                            let map = self.inodes.read().unwrap();
                            match map.get(&child_ino) {
                                Some(n) => Arc::clone(n),
                                None => {
                                    req.reply_err(libc::ENOENT);
                                    return;
                                }
                            }
                        };

                        {
                            let _child_guard = self.lock_pool.read(child_ino);
                            let child_node = unsafe { child_node_arc.read() };
                            match child_node {
                                Node::Directory {
                                    entries: child_entries,
                                    ..
                                } => {
                                    if !child_entries.is_empty() {
                                        req.reply_err(libc::ENOTEMPTY);
                                        return;
                                    }
                                }
                                _ => {
                                    req.reply_err(libc::ENOTDIR);
                                    return;
                                }
                            }
                        }

                        entries.remove(pos);
                        Some(child_ino)
                    } else {
                        req.reply_err(libc::ENOENT);
                        None
                    }
                }
                _ => {
                    req.reply_err(libc::ENOTDIR);
                    None
                }
            }
        };

        if let Some(child_ino) = removed_ino {
            let mut map = self.inodes.write().unwrap();
            map.remove(&child_ino);
            drop(map);
            req.reply_err(0);
        }
    }

    fn symlink(&self, req: Request, link: &str, parent: u64, name: &str) {
        println!(
            "TRACE: symlink(parent={}, name={}, link={})",
            parent, name, link
        );
        let parent_node_arc = {
            let map = self.inodes.read().unwrap();
            match map.get(&parent) {
                Some(n) => Arc::clone(n),
                None => {
                    req.reply_err(libc::ENOENT);
                    return;
                }
            }
        };

        let new_ino = self.allocate_inode();

        {
            let _guard = self.lock_pool.write(parent);
            let parent_node = unsafe { parent_node_arc.write() };
            match parent_node {
                Node::Directory { entries, .. } => {
                    if entries.iter().any(|(entry_name, _)| entry_name == name) {
                        req.reply_err(libc::EEXIST);
                        return;
                    }
                    entries.push((name.to_string(), new_ino));
                }
                _ => {
                    req.reply_err(libc::ENOTDIR);
                    return;
                }
            }
        }

        let new_node = Arc::new(SyncNode::new(Node::Symlink {
            target: link.to_string(),
            nlink: 1,
        }));

        let mut map = self.inodes.write().unwrap();
        map.insert(new_ino, Arc::clone(&new_node));
        drop(map);

        req.reply_entry(
            &FileAttr {
                ino: new_ino,
                file_type: FileType::Symlink,
                perm: 0o777,
                nlink: 1,
                size: link.len() as i64,
            },
            1.0,
            1.0,
        );
    }

    fn readlink(&self, req: Request, ino: u64) {
        println!("TRACE: readlink(ino={})", ino);
        let node_arc = {
            let map = self.inodes.read().unwrap();
            match map.get(&ino) {
                Some(n) => Arc::clone(n),
                None => {
                    req.reply_err(libc::ENOENT);
                    return;
                }
            }
        };

        let _guard = self.lock_pool.read(ino);
        let node = unsafe { node_arc.read() };
        match node {
            Node::Symlink { target, .. } => {
                req.reply_readlink(target);
            }
            _ => {
                req.reply_err(libc::EINVAL);
            }
        }
    }

    fn rename(&self, req: Request, parent: u64, name: &str, newparent: u64, newname: &str) {
        println!(
            "TRACE: rename(parent={}, name={}, newparent={}, newname={})",
            parent, name, newparent, newname
        );

        // Retrieve inodes map read lock to check source type and perform loop check
        {
            let map = self.inodes.read().unwrap();
            let parent_node_arc = match map.get(&parent) {
                Some(n) => Arc::clone(n),
                None => {
                    req.reply_err(libc::ENOENT);
                    return;
                }
            };
            let _guard = self.lock_pool.read(parent);
            let parent_node = unsafe { parent_node_arc.read() };
            let source_ino = match parent_node {
                Node::Directory { entries, .. } => {
                    match entries.iter().find(|(entry_name, _)| entry_name == name) {
                        Some((_, ino)) => *ino,
                        None => {
                            req.reply_err(libc::ENOENT);
                            return;
                        }
                    }
                }
                _ => {
                    req.reply_err(libc::ENOTDIR);
                    return;
                }
            };

            // Check if source node is a directory
            let is_dir = match map.get(&source_ino) {
                Some(node_arc) => {
                    let _child_guard = self.lock_pool.read(source_ino);
                    matches!(unsafe { node_arc.read() }, Node::Directory { .. })
                }
                None => false,
            };

            if is_dir {
                // Loop prevention check: trace parent directories of newparent up to root.
                // If we encounter source_ino, it's an error (EINVAL).
                let mut curr = newparent;
                while curr != 1 {
                    if curr == source_ino {
                        req.reply_err(libc::EINVAL);
                        return;
                    }
                    if let Some(p) = find_parent_inode(&*map, curr) {
                        curr = p;
                    } else {
                        break;
                    }
                }
            }
        };

        let parent_node_arc = {
            let map = self.inodes.read().unwrap();
            match map.get(&parent) {
                Some(n) => Arc::clone(n),
                None => {
                    req.reply_err(libc::ENOENT);
                    return;
                }
            }
        };

        let newparent_node_arc = {
            let map = self.inodes.read().unwrap();
            match map.get(&newparent) {
                Some(n) => Arc::clone(n),
                None => {
                    req.reply_err(libc::ENOENT);
                    return;
                }
            }
        };

        let mut overwritten_ino = None;

        {
            // Lock parent and newparent via LockPool
            let _guard = self.lock_pool.write_two(parent, newparent);

            let parent_node = unsafe { parent_node_arc.write() };
            let newparent_node = unsafe { newparent_node_arc.write() };

            if parent == newparent {
                if let Node::Directory { entries, .. } = parent_node {
                    // Find source entry index
                    let src_pos = match entries.iter().position(|(n, _)| n == name) {
                        Some(pos) => pos,
                        None => {
                            req.reply_err(libc::ENOENT);
                            return;
                        }
                    };
                    let (_, src_ino) = entries[src_pos];

                    // Check if destination entry exists
                    if let Some(dest_pos) = entries.iter().position(|(n, _)| n == newname) {
                        let (_, dest_ino) = entries[dest_pos];

                        let map = self.inodes.read().unwrap();
                        let src_node_arc = map.get(&src_ino).unwrap();
                        let dest_node_arc = map.get(&dest_ino).unwrap();

                        let src_is_dir = {
                            let _g = self.lock_pool.read(src_ino);
                            matches!(unsafe { src_node_arc.read() }, Node::Directory { .. })
                        };
                        let dest_is_dir = {
                            let _g = self.lock_pool.read(dest_ino);
                            matches!(unsafe { dest_node_arc.read() }, Node::Directory { .. })
                        };

                        if src_is_dir != dest_is_dir {
                            if src_is_dir {
                                req.reply_err(libc::ENOTDIR);
                            } else {
                                req.reply_err(libc::EISDIR);
                            }
                            return;
                        }
                        if dest_is_dir {
                            let _g = self.lock_pool.read(dest_ino);
                            if let Node::Directory {
                                entries: dest_entries,
                                ..
                            } = unsafe { dest_node_arc.read() }
                            {
                                if !dest_entries.is_empty() {
                                    req.reply_err(libc::ENOTEMPTY);
                                    return;
                                }
                            }
                        }
                        overwritten_ino = Some(dest_ino);

                        // Perform overwrite by removing dest and updating src entry name
                        entries.remove(dest_pos);
                        let new_src_pos = entries.iter().position(|(n, _)| n == name).unwrap();
                        entries[new_src_pos].0 = newname.to_string();
                    } else {
                        // Normal rename (change name)
                        entries[src_pos].0 = newname.to_string();
                    }
                } else {
                    req.reply_err(libc::ENOTDIR);
                    return;
                }
            } else {
                match (parent_node, newparent_node) {
                    (
                        Node::Directory {
                            entries: src_entries,
                            ..
                        },
                        Node::Directory {
                            entries: dest_entries,
                            ..
                        },
                    ) => {
                        let src_pos = match src_entries.iter().position(|(n, _)| n == name) {
                            Some(pos) => pos,
                            None => {
                                req.reply_err(libc::ENOENT);
                                return;
                            }
                        };
                        let (_, src_ino) = src_entries[src_pos];

                        if let Some(dest_pos) = dest_entries.iter().position(|(n, _)| n == newname)
                        {
                            let (_, dest_ino) = dest_entries[dest_pos];
                            let map = self.inodes.read().unwrap();
                            let src_node_arc = map.get(&src_ino).unwrap();
                            let dest_node_arc = map.get(&dest_ino).unwrap();

                            let src_is_dir = {
                                let _g = self.lock_pool.read(src_ino);
                                matches!(unsafe { src_node_arc.read() }, Node::Directory { .. })
                            };
                            let dest_is_dir = {
                                let _g = self.lock_pool.read(dest_ino);
                                matches!(unsafe { dest_node_arc.read() }, Node::Directory { .. })
                            };

                            if src_is_dir != dest_is_dir {
                                if src_is_dir {
                                    req.reply_err(libc::ENOTDIR);
                                } else {
                                    req.reply_err(libc::EISDIR);
                                }
                                return;
                            }
                            if dest_is_dir {
                                let _g = self.lock_pool.read(dest_ino);
                                if let Node::Directory {
                                    entries: dest_subentries,
                                    ..
                                } = unsafe { dest_node_arc.read() }
                                {
                                    if !dest_subentries.is_empty() {
                                        req.reply_err(libc::ENOTEMPTY);
                                        return;
                                    }
                                }
                            }
                            overwritten_ino = Some(dest_ino);
                            dest_entries.remove(dest_pos);
                        }

                        // Relocate entry
                        src_entries.remove(src_pos);
                        dest_entries.push((newname.to_string(), src_ino));
                    }
                    _ => {
                        req.reply_err(libc::ENOTDIR);
                        return;
                    }
                }
            }
        }

        // If there was an overwritten inode, decrement its link count and delete if 0
        if let Some(dest_ino) = overwritten_ino {
            let mut should_delete = false;
            let node_arc = {
                let map = self.inodes.read().unwrap();
                map.get(&dest_ino).map(Arc::clone)
            };
            if let Some(arc) = node_arc {
                let _g = self.lock_pool.write(dest_ino);
                let node = unsafe { arc.write() };
                match node {
                    Node::File { nlink, .. } => {
                        if *nlink > 0 {
                            *nlink -= 1;
                        }
                        if *nlink == 0 {
                            should_delete = true;
                        }
                    }
                    Node::Symlink { nlink, .. } => {
                        if *nlink > 0 {
                            *nlink -= 1;
                        }
                        if *nlink == 0 {
                            should_delete = true;
                        }
                    }
                    Node::Directory { nlink, .. } => {
                        if *nlink > 0 {
                            *nlink -= 1;
                        }
                        if *nlink == 0 {
                            should_delete = true;
                        }
                    }
                }
            }
            if should_delete {
                let mut map = self.inodes.write().unwrap();
                map.remove(&dest_ino);
            }
        }

        req.reply_err(0);
    }

    fn link(&self, req: Request, ino: u64, newparent: u64, newname: &str) {
        println!(
            "TRACE: link(ino={}, newparent={}, newname={})",
            ino, newparent, newname
        );
        let map = self.inodes.read().unwrap();
        let node_arc = match map.get(&ino) {
            Some(n) => Arc::clone(n),
            None => {
                req.reply_err(libc::ENOENT);
                return;
            }
        };
        let newparent_node_arc = match map.get(&newparent) {
            Some(n) => Arc::clone(n),
            None => {
                req.reply_err(libc::ENOENT);
                return;
            }
        };
        drop(map);

        // Lock both the target node and the parent directory
        let _guard = self.lock_pool.write_two(ino, newparent);

        let node = unsafe { node_arc.write() };
        let newparent_node = unsafe { newparent_node_arc.write() };

        // Restrict hard links on directories to prevent loop generation
        if matches!(node, Node::Directory { .. }) {
            req.reply_err(libc::EPERM);
            return;
        }

        match newparent_node {
            Node::Directory { entries, .. } => {
                if entries.iter().any(|(entry_name, _)| entry_name == newname) {
                    req.reply_err(libc::EEXIST);
                    return;
                }
                entries.push((newname.to_string(), ino));
            }
            _ => {
                req.reply_err(libc::ENOTDIR);
                return;
            }
        }

        // Increment link count of the source node
        let file_type = match node {
            Node::File { nlink, .. } => {
                *nlink += 1;
                FileType::RegularFile
            }
            Node::Symlink { nlink, .. } => {
                *nlink += 1;
                FileType::Symlink
            }
            _ => unreachable!(),
        };

        let perm = match node {
            Node::File { perm, .. } => *perm,
            Node::Symlink { .. } => 0o777,
            _ => unreachable!(),
        };

        let size = match node {
            Node::File { content, .. } => content.len() as i64,
            Node::Symlink { target, .. } => target.len() as i64,
            _ => unreachable!(),
        };

        let nlink = match node {
            Node::File { nlink, .. } => *nlink,
            Node::Symlink { nlink, .. } => *nlink,
            _ => unreachable!(),
        };

        req.reply_entry(
            &FileAttr {
                ino,
                file_type,
                perm,
                nlink,
                size,
            },
            1.0,
            1.0,
        );
    }

    fn fsync(&self, req: Request, ino: u64, datasync: bool) {
        println!("TRACE: fsync(ino={}, datasync={})", ino, datasync);
        req.reply_err(0);
    }

    fn release(&self, req: Request, ino: u64) {
        println!("TRACE: release(ino={})", ino);
        req.reply_err(0);
    }

    fn releasedir(&self, req: Request, ino: u64) {
        println!("TRACE: releasedir(ino={})", ino);
        req.reply_err(0);
    }

    fn fsyncdir(&self, req: Request, ino: u64, datasync: bool) {
        println!("TRACE: fsyncdir(ino={}, datasync={})", ino, datasync);
        req.reply_err(0);
    }
}

pub fn mount(args: Vec<String>, fs: InMemoryFS) -> Result<(), i32> {
    shim::mount(args, fs)
}
