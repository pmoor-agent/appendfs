use crate::fs::InMemoryFS;
use crate::node::Node;
use crate::shim::{self, FileAttr, FileType, Request};
use std::sync::Arc;

pub fn lookup(fs: &InMemoryFS, req: Request, parent: u64, name: &str) {
    println!("TRACE: lookup(parent={}, name={})", parent, name);
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

    // Lookup child inode inside directory
    let child_ino = {
        let _guard = fs.lock_pool.read(parent);
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
        let map = fs.inodes.read().unwrap();
        match map.get(&child_ino) {
            Some(n) => Arc::clone(n),
            None => {
                req.reply_err(libc::ENOENT);
                return;
            }
        }
    };

    let _guard = fs.lock_pool.read(child_ino);
    let child_node = unsafe { child_node_arc.read() };
    match child_node {
        Node::Directory {
            perm,
            nlink,
            uid,
            gid,
            atime,
            mtime,
            ctime,
            ..
        } => {
            req.reply_entry(
                &FileAttr {
                    ino: child_ino,
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
                1.0,
                1.0,
            );
        }
        Node::File {
            content,
            perm,
            nlink,
            uid,
            gid,
            atime,
            mtime,
            ctime,
        } => {
            req.reply_entry(
                &FileAttr {
                    ino: child_ino,
                    file_type: FileType::RegularFile,
                    perm: *perm,
                    nlink: *nlink,
                    uid: *uid,
                    gid: *gid,
                    size: content.len() as i64,
                    atime: *atime,
                    mtime: *mtime,
                    ctime: *ctime,
                },
                1.0,
                1.0,
            );
        }
        Node::Symlink {
            target,
            nlink,
            uid,
            gid,
            atime,
            mtime,
            ctime,
        } => {
            req.reply_entry(
                &FileAttr {
                    ino: child_ino,
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
                1.0,
                1.0,
            );
        }
    }
}

pub fn readdir(fs: &InMemoryFS, req: Request, ino: u64, size: usize, offset: i64) {
    println!(
        "TRACE: readdir(ino={}, size={}, offset={})",
        ino, size, offset
    );
    let entries = {
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

    let map = fs.inodes.read().unwrap();
    for (name, child_ino) in &entries {
        if let Some(child_node_arc) = map.get(child_ino) {
            let _guard = fs.lock_pool.read(*child_ino);
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

pub fn mkdir(fs: &InMemoryFS, req: Request, parent: u64, name: &str, mode: u32) {
    let uid = req.uid();
    let gid = req.gid();
    let now = fs.clock.now();
    println!(
        "TRACE: mkdir(parent={}, name={}, mode=0o{:o}, uid={}, gid={})",
        parent, name, mode, uid, gid
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

    let new_node = Arc::new(crate::node::SyncNode::new(Node::Directory {
        entries: Vec::new(),
        perm: mode & 0o777,
        nlink: 2, // '.' and parent entry
        uid,
        gid,
        atime: now,
        mtime: now,
        ctime: now,
    }));

    let mut map = fs.inodes.write().unwrap();
    map.insert(new_ino, Arc::clone(&new_node));
    drop(map);

    req.reply_entry(
        &FileAttr {
            ino: new_ino,
            file_type: FileType::Directory,
            perm: mode & 0o777,
            nlink: 2,
            uid,
            gid,
            size: 0,
            atime: now,
            mtime: now,
            ctime: now,
        },
        1.0,
        1.0,
    );
}

pub fn rmdir(fs: &InMemoryFS, req: Request, parent: u64, name: &str) {
    println!("TRACE: rmdir(parent={}, name={})", parent, name);
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

    let removed_ino = {
        let _guard = fs.lock_pool.write(parent);
        let parent_node = unsafe { parent_node_arc.write() };
        match parent_node {
            Node::Directory { entries, .. } => {
                if let Some(pos) = entries
                    .iter()
                    .position(|(entry_name, _)| entry_name == name)
                {
                    let (_, child_ino) = entries[pos];

                    let child_node_arc = {
                        let map = fs.inodes.read().unwrap();
                        match map.get(&child_ino) {
                            Some(n) => Arc::clone(n),
                            None => {
                                req.reply_err(libc::ENOENT);
                                return;
                            }
                        }
                    };

                    {
                        let _child_guard = fs.lock_pool.read(child_ino);
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
        let mut map = fs.inodes.write().unwrap();
        map.remove(&child_ino);
        drop(map);
        req.reply_err(0);
    }
}

pub fn releasedir(_fs: &InMemoryFS, req: Request, ino: u64) {
    println!("TRACE: releasedir(ino={})", ino);
    req.reply_err(0);
}

pub fn fsyncdir(_fs: &InMemoryFS, req: Request, ino: u64, datasync: bool) {
    println!("TRACE: fsyncdir(ino={}, datasync={})", ino, datasync);
    req.reply_err(0);
}
