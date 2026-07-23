use crate::fs::InMemoryFS;
use crate::node::{Node, SyncNode};
use crate::shim::{FileAttr, FileType, Request};
use std::sync::Arc;

pub fn getattr(fs: &InMemoryFS, req: Request, ino: u64) {
    println!("TRACE: getattr(ino={})", ino);
    let node_arc = {
        let map = fs.inodes.read().unwrap();
        match map.get(&ino) {
            Some(n) => Arc::clone(n),
            None => {
                req.reply_err(libc::ENOENT);
                return;
            }
        }
    };

    let _guard = fs.lock_pool.read(ino);
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

pub fn read(fs: &InMemoryFS, req: Request, ino: u64, size: usize, offset: i64) {
    println!("TRACE: read(ino={}, size={}, offset={})", ino, size, offset);
    let node_arc = {
        let map = fs.inodes.read().unwrap();
        match map.get(&ino) {
            Some(n) => Arc::clone(n),
            None => {
                req.reply_err(libc::ENOENT);
                return;
            }
        }
    };

    let _guard = fs.lock_pool.read(ino);
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

pub fn open(fs: &InMemoryFS, req: Request, ino: u64, flags: u32) {
    println!("TRACE: open(ino={}, flags=0x{:x})", ino, flags);
    if (flags & libc::O_TRUNC as u32) != 0 {
        let node_arc = {
            let map = fs.inodes.read().unwrap();
            match map.get(&ino) {
                Some(n) => Arc::clone(n),
                None => {
                    req.reply_err(libc::ENOENT);
                    return;
                }
            }
        };
        let _guard = fs.lock_pool.write(ino);
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

pub fn write(fs: &InMemoryFS, req: Request, ino: u64, buf: &[u8], offset: i64) {
    println!(
        "TRACE: write(ino={}, len={}, offset={})",
        ino,
        buf.len(),
        offset
    );
    let node_arc = {
        let map = fs.inodes.read().unwrap();
        match map.get(&ino) {
            Some(n) => Arc::clone(n),
            None => {
                req.reply_err(libc::ENOENT);
                return;
            }
        }
    };

    let _guard = fs.lock_pool.write(ino);
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

pub fn setattr(fs: &InMemoryFS, req: Request, ino: u64, size: i64, to_set: u32) {
    println!(
        "TRACE: setattr(ino={}, size={}, to_set={})",
        ino, size, to_set
    );
    let node_arc = {
        let map = fs.inodes.read().unwrap();
        match map.get(&ino) {
            Some(n) => Arc::clone(n),
            None => {
                req.reply_err(libc::ENOENT);
                return;
            }
        }
    };

    const FUSE_SET_ATTR_SIZE: u32 = 1 << 3;

    let _guard = fs.lock_pool.write(ino);
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

pub fn create(fs: &InMemoryFS, req: Request, parent: u64, name: &str, mode: u32, flags: u32) {
    println!(
        "TRACE: create(parent={}, name={}, mode=0o{:o}, flags=0x{:x})",
        parent, name, mode, flags
    );
    let parent_node_arc = {
        let map = fs.inodes.read().unwrap();
        match map.get(&parent) {
            Some(n) => Arc::clone(n),
            None => {
                req.reply_err(libc::ENOENT);
                return;
            }
        }
    };

    let new_ino = fs.allocate_inode();

    {
        let _guard = fs.lock_pool.write(parent);
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

    let mut map = fs.inodes.write().unwrap();
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

pub fn fsync(_fs: &InMemoryFS, req: Request, ino: u64, datasync: bool) {
    println!("TRACE: fsync(ino={}, datasync={})", ino, datasync);
    req.reply_err(0);
}

pub fn release(_fs: &InMemoryFS, req: Request, ino: u64) {
    println!("TRACE: release(ino={})", ino);
    req.reply_err(0);
}
