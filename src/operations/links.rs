use crate::fs::{InMemoryFS, find_parent_inode};
use crate::node::{Node, SyncNode};
use crate::shim::{FileAttr, FileType, Request};
use std::sync::Arc;

pub fn unlink(fs: &InMemoryFS, req: Request, parent: u64, name: &str) {
    println!("TRACE: unlink(parent={}, name={})", parent, name);
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

    let (removed_ino, child_node_arc) = {
        let _guard = fs.lock_pool.write(parent);
        let parent_node = unsafe { parent_node_arc.write() };
        match parent_node {
            Node::Directory { entries, .. } => {
                if let Some(pos) = entries
                    .iter()
                    .position(|(entry_name, _)| entry_name == name)
                {
                    let (_, child_ino) = entries.remove(pos);

                    let map = fs.inodes.read().unwrap();
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
            let _child_guard = fs.lock_pool.write(child_ino);
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
            let mut map = fs.inodes.write().unwrap();
            map.remove(&child_ino);
        }
        req.reply_err(0);
    }
}

pub fn symlink(fs: &InMemoryFS, req: Request, link: &str, parent: u64, name: &str) {
    println!(
        "TRACE: symlink(parent={}, name={}, link={})",
        parent, name, link
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

    let new_node = Arc::new(SyncNode::new(Node::Symlink {
        target: link.to_string(),
        nlink: 1,
    }));

    let mut map = fs.inodes.write().unwrap();
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

pub fn readlink(fs: &InMemoryFS, req: Request, ino: u64) {
    println!("TRACE: readlink(ino={})", ino);
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
        Node::Symlink { target, .. } => {
            req.reply_readlink(target);
        }
        _ => {
            req.reply_err(libc::EINVAL);
        }
    }
}

pub fn rename(
    fs: &InMemoryFS,
    req: Request,
    parent: u64,
    name: &str,
    newparent: u64,
    newname: &str,
) {
    println!(
        "TRACE: rename(parent={}, name={}, newparent={}, newname={})",
        parent, name, newparent, newname
    );

    // Retrieve inodes map read lock to check source type and perform loop check
    {
        let map = fs.inodes.read().unwrap();
        let parent_node_arc = match map.get(&parent) {
            Some(n) => Arc::clone(n),
            None => {
                req.reply_err(libc::ENOENT);
                return;
            }
        };
        let _guard = fs.lock_pool.read(parent);
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
                let _child_guard = fs.lock_pool.read(source_ino);
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
        let map = fs.inodes.read().unwrap();
        match map.get(&parent) {
            Some(n) => Arc::clone(n),
            None => {
                req.reply_err(libc::ENOENT);
                return;
            }
        }
    };

    let newparent_node_arc = {
        let map = fs.inodes.read().unwrap();
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
        let _guard = fs.lock_pool.write_two(parent, newparent);

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

                    let map = fs.inodes.read().unwrap();
                    let src_node_arc = map.get(&src_ino).unwrap();
                    let dest_node_arc = map.get(&dest_ino).unwrap();

                    let src_is_dir = {
                        let _g = fs.lock_pool.read(src_ino);
                        matches!(unsafe { src_node_arc.read() }, Node::Directory { .. })
                    };
                    let dest_is_dir = {
                        let _g = fs.lock_pool.read(dest_ino);
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
                        let _g = fs.lock_pool.read(dest_ino);
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

                    if let Some(dest_pos) = dest_entries.iter().position(|(n, _)| n == newname) {
                        let (_, dest_ino) = dest_entries[dest_pos];
                        let map = fs.inodes.read().unwrap();
                        let src_node_arc = map.get(&src_ino).unwrap();
                        let dest_node_arc = map.get(&dest_ino).unwrap();

                        let src_is_dir = {
                            let _g = fs.lock_pool.read(src_ino);
                            matches!(unsafe { src_node_arc.read() }, Node::Directory { .. })
                        };
                        let dest_is_dir = {
                            let _g = fs.lock_pool.read(dest_ino);
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
                            let _g = fs.lock_pool.read(dest_ino);
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
            let map = fs.inodes.read().unwrap();
            map.get(&dest_ino).map(Arc::clone)
        };
        if let Some(arc) = node_arc {
            let _g = fs.lock_pool.write(dest_ino);
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
            let mut map = fs.inodes.write().unwrap();
            map.remove(&dest_ino);
        }
    }

    req.reply_err(0);
}

pub fn link(fs: &InMemoryFS, req: Request, ino: u64, newparent: u64, newname: &str) {
    println!(
        "TRACE: link(ino={}, newparent={}, newname={})",
        ino, newparent, newname
    );
    let map = fs.inodes.read().unwrap();
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
    let _guard = fs.lock_pool.write_two(ino, newparent);

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
