use crate::fs::{InMemoryFS, find_parent_inode};
use crate::log::{LinkPayload, OpCode, RenamePayload, SymlinkPayload, UnlinkPayload};
use crate::node::{Node, SyncNode};
use crate::shim::{FileAttr, FileType, Request};
use std::sync::Arc;

/// Core unlink logic - see `dir::mkdir_core`'s doc comment for why this split exists.
pub fn unlink_core(fs: &InMemoryFS, parent: u64, name: &str) -> Result<(), i32> {
    let _snap_guard = fs.snapshot_rwlock.read().unwrap();
    // Held for the whole call - see `InMemoryFS::dir_lock`'s doc comment.
    let _dir_guard = fs.dir_lock.lock().unwrap();
    log::trace!("unlink(parent={}, name={})", parent, name);
    let parent_node_arc = {
        let map = fs.inodes.read().unwrap();
        match map.get(&parent) {
            Some(n) => Arc::clone(n),
            None => return Err(libc::ENOENT),
        }
    };

    let (child_ino, child_node_arc) = {
        let _guard = fs.lock_pool.write(parent);
        let parent_node = unsafe { parent_node_arc.write() };
        match parent_node {
            Node::Directory { entries, .. } => {
                if let Some(pos) = entries
                    .iter()
                    .position(|(entry_name, _)| entry_name == name)
                {
                    let (_, child_ino) = entries[pos];

                    // Scoped tightly and dropped before the lock_pool call below -
                    // never hold `fs.inodes`'s lock across a `lock_pool` acquisition
                    // (see the deadlock explanation at rename_core's loop-prevention
                    // check).
                    let n_opt = {
                        let map = fs.inodes.read().unwrap();
                        map.get(&child_ino).map(Arc::clone)
                    };

                    // POSIX: unlink() must reject directories with EISDIR - only
                    // rmdir() may remove them (and only when empty). Must check before
                    // removing the entry below, not after.
                    //
                    // `read_or_reuse`, not a plain `read` - child_ino's bucket can
                    // collide with parent's (striped over only 1024 buckets), and
                    // `_guard` above already holds parent's bucket as a writer;
                    // re-acquiring the same std::sync::RwLock read-after-write on the
                    // same thread is not guaranteed deadlock-free and reliably
                    // self-deadlocks in practice.
                    if let Some(ref arc) = n_opt {
                        let _child_guard = fs.lock_pool.read_or_reuse(child_ino, &[parent]);
                        if matches!(unsafe { arc.read() }, Node::Directory { .. }) {
                            return Err(libc::EISDIR);
                        }
                    }

                    entries.remove(pos);
                    (child_ino, n_opt)
                } else {
                    return Err(libc::ENOENT);
                }
            }
            _ => return Err(libc::ENOTDIR),
        }
    };

    if let Some(node_arc) = child_node_arc {
        let _child_guard = fs.lock_pool.write(child_ino);
        let child_node = unsafe { node_arc.write() };
        let should_delete = match child_node {
            Node::File { nlink, .. } => {
                if *nlink > 0 {
                    *nlink -= 1;
                }
                *nlink == 0
            }
            Node::Symlink { nlink, .. } => {
                if *nlink > 0 {
                    *nlink -= 1;
                }
                *nlink == 0
            }
            // Unreachable: directories are rejected with EISDIR above, before the
            // entry (and thus this arm's only path to being reached) is removed.
            Node::Directory { .. } => unreachable!("unlink_core: directory should have been rejected with EISDIR"),
        };
        // Reclaim right here, still holding `_child_guard` - releasing it between
        // deciding to delete and actually deleting (as this used to) lets a
        // concurrent link_core, which found this inode still present just before the
        // decrement, "resurrect" it in that gap: increment its nlink and add a brand
        // new entry pointing to it, all before this thread's now-stale `should_delete`
        // decision deletes it anyway - silently discarding that new entry along with
        // the inode, orphaning whatever directory it was just linked into.
        if should_delete {
            let mut map = fs.inodes.write().unwrap();
            map.remove(&child_ino);
        }
    }

    // Staged while still holding `_dir_guard` - see `InMemoryFS::dir_lock`.
    let payload = UnlinkPayload {
        parent,
        name: name.to_string(),
    };
    if let Ok(bytes) = bincode::serialize(&payload) {
        fs.log_buffer
            .stage_op(OpCode::Unlink, child_ino, bytes, fs.log_writer.as_deref());
    }

    Ok(())
}

pub fn unlink(fs: &InMemoryFS, req: Request, parent: u64, name: &str) {
    match unlink_core(fs, parent, name) {
        Ok(()) => req.reply_err(0),
        Err(e) => req.reply_err(e),
    }
}

/// Core symlink logic - see `dir::mkdir_core`'s doc comment for why this split exists.
pub fn symlink_core(
    fs: &InMemoryFS,
    parent: u64,
    name: &str,
    target: &str,
    uid: u32,
    gid: u32,
) -> Result<FileAttr, i32> {
    let _snap_guard = fs.snapshot_rwlock.read().unwrap();
    // Held for the whole call - see `InMemoryFS::dir_lock`'s doc comment.
    let _dir_guard = fs.dir_lock.lock().unwrap();
    let now = fs.clock.now();
    log::trace!(
        "symlink(parent={}, name={}, link={}, uid={}, gid={})",
        parent,
        name,
        target,
        uid,
        gid
    );
    let parent_node_arc = {
        let map = fs.inodes.read().unwrap();
        match map.get(&parent) {
            Some(n) => Arc::clone(n),
            None => return Err(libc::ENOENT),
        }
    };

    let new_ino = fs.allocate_inode();

    // Insert into `fs.inodes` *before* the entry becomes visible in the parent's
    // `entries` below - see mkdir_core's identical comment for why the reverse order
    // (entry visible, node unresolvable) is a real, exploitable race.
    let new_node = Arc::new(SyncNode::new(Node::Symlink {
        target: target.to_string(),
        nlink: 1,
        uid,
        gid,
        atime: now,
        mtime: now,
        ctime: now,
    }));
    {
        let mut map = fs.inodes.write().unwrap();
        map.insert(new_ino, Arc::clone(&new_node));
    }

    {
        let _guard = fs.lock_pool.write(parent);
        let parent_node = unsafe { parent_node_arc.write() };
        match parent_node {
            Node::Directory { entries, .. } => {
                if entries.iter().any(|(entry_name, _)| entry_name == name) {
                    let mut map = fs.inodes.write().unwrap();
                    map.remove(&new_ino);
                    return Err(libc::EEXIST);
                }
                entries.push((name.to_string(), new_ino));
            }
            _ => {
                let mut map = fs.inodes.write().unwrap();
                map.remove(&new_ino);
                return Err(libc::ENOTDIR);
            }
        }
    }

    // Staged while still holding `_dir_guard` - see `InMemoryFS::dir_lock`.
    let payload = SymlinkPayload {
        parent,
        name: name.to_string(),
        target: target.to_string(),
        uid,
        gid,
        created_at: crate::clock::system_time_to_unix(now),
    };
    if let Ok(bytes) = bincode::serialize(&payload) {
        fs.log_buffer
            .stage_op(OpCode::Symlink, new_ino, bytes, fs.log_writer.as_deref());
    }

    Ok(FileAttr {
        ino: new_ino,
        file_type: FileType::Symlink,
        perm: 0o777,
        nlink: 1,
        uid,
        gid,
        size: target.len() as i64,
        atime: now,
        mtime: now,
        ctime: now,
    })
}

pub fn symlink(fs: &InMemoryFS, req: Request, link: &str, parent: u64, name: &str) {
    let uid = req.uid();
    let gid = req.gid();
    match symlink_core(fs, parent, name, link, uid, gid) {
        Ok(attr) => req.reply_entry(&attr, 1.0, 1.0),
        Err(e) => req.reply_err(e),
    }
}

/// Core readlink logic - see `dir::mkdir_core`'s doc comment for why this split exists.
pub fn readlink_core(fs: &InMemoryFS, ino: u64) -> Result<String, i32> {
    log::trace!("readlink(ino={})", ino);
    let node_arc = {
        let map = fs.inodes.read().unwrap();
        match map.get(&ino) {
            Some(n) => Arc::clone(n),
            None => return Err(libc::ENOENT),
        }
    };

    let _guard = fs.lock_pool.read(ino);
    let node = unsafe { node_arc.read() };
    match node {
        Node::Symlink { target, .. } => Ok(target.clone()),
        _ => Err(libc::EINVAL),
    }
}

pub fn readlink(fs: &InMemoryFS, req: Request, ino: u64) {
    match readlink_core(fs, ino) {
        Ok(target) => req.reply_readlink(&target),
        Err(e) => req.reply_err(e),
    }
}

/// Core rename logic - see `dir::mkdir_core`'s doc comment for why this split exists.
pub fn rename_core(
    fs: &InMemoryFS,
    parent: u64,
    name: &str,
    newparent: u64,
    newname: &str,
) -> Result<(), i32> {
    let _snap_guard = fs.snapshot_rwlock.read().unwrap();
    // Held for the whole call - see `InMemoryFS::dir_lock`'s doc comment. In
    // particular, this is what makes the loop-prevention check below safe against
    // forming a cycle: with only one directory-structure mutation ever in flight,
    // there's no other concurrent rename whose not-yet-committed move this check
    // could miss (the two-cross-parent-renames-each-move-the-other-under-itself race
    // that produced an actual disconnected cycle before this lock existed).
    let _dir_guard = fs.dir_lock.lock().unwrap();
    log::trace!(
        "rename(parent={}, name={}, newparent={}, newname={})",
        parent,
        name,
        newparent,
        newname
    );

    // `fs.inodes` acquisitions below stay scoped to just cloning an `Arc` out, never
    // spanning a `lock_pool` call - readers (lookup/readdir/getattr) don't take
    // `dir_lock`, so a long-held `fs.inodes` read guard could still starve-cycle
    // against one of them via std::sync::RwLock's writer preference, even though no
    // other directory-structure mutation can be running concurrently.
    let source_ino = {
        let parent_node_arc = {
            let map = fs.inodes.read().unwrap();
            match map.get(&parent) {
                Some(n) => Arc::clone(n),
                None => return Err(libc::ENOENT),
            }
        };
        let source_ino = {
            let _guard = fs.lock_pool.read(parent);
            let parent_node = unsafe { parent_node_arc.read() };
            match parent_node {
                Node::Directory { entries, .. } => {
                    match entries.iter().find(|(entry_name, _)| entry_name == name) {
                        Some((_, ino)) => *ino,
                        None => return Err(libc::ENOENT),
                    }
                }
                _ => return Err(libc::ENOTDIR),
            }
        };

        // Check if source node is a directory
        let source_node_arc = {
            let map = fs.inodes.read().unwrap();
            map.get(&source_ino).cloned()
        };
        let is_dir = match source_node_arc {
            Some(node_arc) => {
                let _guard = fs.lock_pool.read(source_ino);
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
                    return Err(libc::EINVAL);
                }
                if let Some(p) = find_parent_inode(fs, curr) {
                    curr = p;
                } else {
                    break;
                }
            }
        }
        source_ino
    };

    let parent_node_arc = {
        let map = fs.inodes.read().unwrap();
        match map.get(&parent) {
            Some(n) => Arc::clone(n),
            None => return Err(libc::ENOENT),
        }
    };

    let newparent_node_arc = {
        let map = fs.inodes.read().unwrap();
        match map.get(&newparent) {
            Some(n) => Arc::clone(n),
            None => return Err(libc::ENOENT),
        }
    };

    let mut overwritten_ino = None;

    {
        // Lock parent and newparent via LockPool - just for content-access safety
        // against concurrent file-content ops (write/setattr) on these same inodes;
        // `dir_lock` above already rules out any other directory-structure mutation,
        // so there's no other multi-lock acquisition here to order against.
        let _guard = fs.lock_pool.write_two(parent, newparent);

        let parent_node = unsafe { parent_node_arc.write() };
        let newparent_node = unsafe { newparent_node_arc.write() };

        if parent == newparent {
            if let Node::Directory { entries, .. } = parent_node {
                // Find source entry index
                let src_pos = match entries.iter().position(|(n, _)| n == name) {
                    Some(pos) => pos,
                    None => return Err(libc::ENOENT),
                };
                let (_, src_ino) = entries[src_pos];

                // POSIX: renaming a name onto itself is a no-op success, not a
                // self-overwrite. Without this, dest_pos == src_pos below, and
                // removing "the destination" removes the only entry named `name`,
                // making the subsequent re-lookup-by-name panic.
                if name == newname {
                    return Ok(());
                }

                // Check if destination entry exists
                if let Some(dest_pos) = entries.iter().position(|(n, _)| n == newname) {
                    let (_, dest_ino) = entries[dest_pos];

                    // Cloned out and the map guard dropped immediately - never hold
                    // `fs.inodes`'s lock across a `lock_pool` acquisition below (see the
                    // deadlock explanation at this function's loop-prevention check).
                    let (src_node_arc, dest_node_arc) = {
                        let map = fs.inodes.read().unwrap();
                        (
                            Arc::clone(map.get(&src_ino).unwrap()),
                            Arc::clone(map.get(&dest_ino).unwrap()),
                        )
                    };

                    let src_is_dir = {
                        let _g = fs.lock_pool.read_or_reuse(src_ino, &[parent, newparent]);
                        matches!(unsafe { src_node_arc.read() }, Node::Directory { .. })
                    };
                    let dest_is_dir = {
                        let _g = fs.lock_pool.read_or_reuse(dest_ino, &[parent, newparent]);
                        matches!(unsafe { dest_node_arc.read() }, Node::Directory { .. })
                    };

                    if src_is_dir != dest_is_dir {
                        return Err(if src_is_dir {
                            libc::ENOTDIR
                        } else {
                            libc::EISDIR
                        });
                    }
                    // Held from the emptiness check through the entry removal below,
                    // not just the check - otherwise a concurrent mkdir/create/symlink
                    // using dest_ino as ITS parent can slip a new child in during the
                    // gap, and this thread would go on to remove dest_ino's own entry
                    // (and later reclaim its inode) anyway, silently orphaning that new
                    // child (its only path to root just vanished, but it stays in
                    // `fs.inodes` forever since nothing else ever touches it again).
                    let _dest_dir_guard = if dest_is_dir {
                        let g = fs.lock_pool.read_or_reuse(dest_ino, &[parent, newparent]);
                        if let Node::Directory {
                            entries: dest_entries,
                            ..
                        } = unsafe { dest_node_arc.read() }
                        {
                            if !dest_entries.is_empty() {
                                return Err(libc::ENOTEMPTY);
                            }
                        }
                        g
                    } else {
                        None
                    };
                    overwritten_ino = Some(dest_ino);

                    // Perform overwrite by removing dest and updating src entry name
                    entries.remove(dest_pos);
                    let new_src_pos = entries.iter().position(|(n, _)| n == name).unwrap();
                    entries[new_src_pos].0 = newname.to_string();

                    if dest_is_dir {
                        // Reclaim right here, still holding `_dest_dir_guard` from the
                        // emptiness check above - directories can never be hardlinked,
                        // so the entry just removed was definitively dest_ino's only
                        // reference. Deferring this to the generic nlink-based cleanup
                        // below (as it used to) reopens the exact same race: releasing
                        // dest_ino's lock between "confirmed empty and unlinked" and
                        // "actually reclaimed" lets a concurrent mkdir/create/symlink
                        // targeting dest_ino as its parent slip a new child in during
                        // that gap, which then gets silently orphaned when this thread
                        // deletes dest_ino anyway.
                        let mut map = fs.inodes.write().unwrap();
                        map.remove(&dest_ino);
                    }
                } else {
                    // Normal rename (change name)
                    entries[src_pos].0 = newname.to_string();
                }
            } else {
                return Err(libc::ENOTDIR);
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
                        None => return Err(libc::ENOENT),
                    };
                    let (_, src_ino) = src_entries[src_pos];

                    if let Some(dest_pos) = dest_entries.iter().position(|(n, _)| n == newname) {
                        let (_, dest_ino) = dest_entries[dest_pos];
                        // Cloned out and the map guard dropped immediately - never hold
                        // `fs.inodes`'s lock across a `lock_pool` acquisition below (see
                        // the deadlock explanation at this function's loop-prevention
                        // check).
                        let (src_node_arc, dest_node_arc) = {
                            let map = fs.inodes.read().unwrap();
                            (
                                Arc::clone(map.get(&src_ino).unwrap()),
                                Arc::clone(map.get(&dest_ino).unwrap()),
                            )
                        };

                        let src_is_dir = {
                            let _g = fs.lock_pool.read_or_reuse(src_ino, &[parent, newparent]);
                            matches!(unsafe { src_node_arc.read() }, Node::Directory { .. })
                        };
                        let dest_is_dir = {
                            let _g = fs.lock_pool.read_or_reuse(dest_ino, &[parent, newparent]);
                            matches!(unsafe { dest_node_arc.read() }, Node::Directory { .. })
                        };

                        if src_is_dir != dest_is_dir {
                            return Err(if src_is_dir {
                                libc::ENOTDIR
                            } else {
                                libc::EISDIR
                            });
                        }
                        // Held from the emptiness check through the entry removal below
                        // - see the identical comment on the same-parent branch above
                        // for why releasing it right after the check (as this used to)
                        // is a real, exploitable race.
                        let _dest_dir_guard = if dest_is_dir {
                            let g = fs.lock_pool.read_or_reuse(dest_ino, &[parent, newparent]);
                            if let Node::Directory {
                                entries: dest_subentries,
                                ..
                            } = unsafe { dest_node_arc.read() }
                            {
                                if !dest_subentries.is_empty() {
                                    return Err(libc::ENOTEMPTY);
                                }
                            }
                            g
                        } else {
                            None
                        };
                        overwritten_ino = Some(dest_ino);
                        dest_entries.remove(dest_pos);

                        if dest_is_dir {
                            // Reclaim right here, still holding `_dest_dir_guard` - see
                            // the identical comment on the same-parent branch above.
                            let mut map = fs.inodes.write().unwrap();
                            map.remove(&dest_ino);
                        }
                    }

                    // Relocate entry
                    src_entries.remove(src_pos);
                    dest_entries.push((newname.to_string(), src_ino));
                }
                _ => return Err(libc::ENOTDIR),
            }
        }
    }

    // If there was an overwritten inode, decrement its link count and delete if 0.
    // (For directories this is a harmless no-op: the directory-overwrite branches
    // above already reclaimed dest_ino inline, still holding its lock continuously
    // from the emptiness check through the removal, so `map.get` below finds nothing.)
    if let Some(dest_ino) = overwritten_ino {
        let node_arc = {
            let map = fs.inodes.read().unwrap();
            map.get(&dest_ino).map(Arc::clone)
        };
        if let Some(arc) = node_arc {
            let _g = fs.lock_pool.write(dest_ino);
            let node = unsafe { arc.write() };
            let should_delete = match node {
                Node::File { nlink, .. } => {
                    if *nlink > 0 {
                        *nlink -= 1;
                    }
                    *nlink == 0
                }
                Node::Symlink { nlink, .. } => {
                    if *nlink > 0 {
                        *nlink -= 1;
                    }
                    *nlink == 0
                }
                Node::Directory { .. } => false,
            };
            // Reclaim right here, still holding `_g` - see unlink_core's identical
            // comment for why releasing the lock between deciding to delete and
            // actually deleting lets a concurrent link_core resurrect this inode in
            // the gap, only to have it deleted out from under its brand new entry.
            if should_delete {
                let mut map = fs.inodes.write().unwrap();
                map.remove(&dest_ino);
            }
        }
    }

    // Staged while still holding `_dir_guard` - see `InMemoryFS::dir_lock`.
    let payload = RenamePayload {
        parent,
        name: name.to_string(),
        new_parent: newparent,
        new_name: newname.to_string(),
    };
    if let Ok(bytes) = bincode::serialize(&payload) {
        fs.log_buffer
            .stage_op(OpCode::Rename, source_ino, bytes, fs.log_writer.as_deref());
    }

    Ok(())
}

pub fn rename(
    fs: &InMemoryFS,
    req: Request,
    parent: u64,
    name: &str,
    newparent: u64,
    newname: &str,
) {
    match rename_core(fs, parent, name, newparent, newname) {
        Ok(()) => req.reply_err(0),
        Err(e) => req.reply_err(e),
    }
}

/// Core link logic - see `dir::mkdir_core`'s doc comment for why this split exists.
pub fn link_core(
    fs: &InMemoryFS,
    ino: u64,
    newparent: u64,
    newname: &str,
) -> Result<FileAttr, i32> {
    let _snap_guard = fs.snapshot_rwlock.read().unwrap();
    // Held for the whole call - see `InMemoryFS::dir_lock`'s doc comment.
    let _dir_guard = fs.dir_lock.lock().unwrap();
    log::trace!(
        "link(ino={}, newparent={}, newname={})",
        ino,
        newparent,
        newname
    );
    let map = fs.inodes.read().unwrap();
    let node_arc = match map.get(&ino) {
        Some(n) => Arc::clone(n),
        None => return Err(libc::ENOENT),
    };
    let newparent_node_arc = match map.get(&newparent) {
        Some(n) => Arc::clone(n),
        None => return Err(libc::ENOENT),
    };
    drop(map);

    // Lock both the target node and the parent directory - just for content-access
    // safety against concurrent file-content ops on these same inodes; `dir_lock`
    // above already rules out any other directory-structure mutation.
    let _guard = fs.lock_pool.write_two(ino, newparent);

    let node = unsafe { node_arc.write() };
    let newparent_node = unsafe { newparent_node_arc.write() };

    // Restrict hard links on directories to prevent loop generation
    if matches!(node, Node::Directory { .. }) {
        return Err(libc::EPERM);
    }

    match newparent_node {
        Node::Directory { entries, .. } => {
            if entries.iter().any(|(entry_name, _)| entry_name == newname) {
                return Err(libc::EEXIST);
            }
            entries.push((newname.to_string(), ino));
        }
        _ => return Err(libc::ENOTDIR),
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
        Node::File { size, .. } => *size as i64,
        Node::Symlink { target, .. } => target.len() as i64,
        _ => unreachable!(),
    };

    let nlink = match node {
        Node::File { nlink, .. } => *nlink,
        Node::Symlink { nlink, .. } => *nlink,
        _ => unreachable!(),
    };

    let uid = match node {
        Node::File { uid, .. } => *uid,
        Node::Symlink { uid, .. } => *uid,
        _ => unreachable!(),
    };

    let gid = match node {
        Node::File { gid, .. } => *gid,
        Node::Symlink { gid, .. } => *gid,
        _ => unreachable!(),
    };

    let atime = match node {
        Node::File { atime, .. } => *atime,
        Node::Symlink { atime, .. } => *atime,
        _ => unreachable!(),
    };

    let mtime = match node {
        Node::File { mtime, .. } => *mtime,
        Node::Symlink { mtime, .. } => *mtime,
        _ => unreachable!(),
    };

    let ctime = match node {
        Node::File { ctime, .. } => *ctime,
        Node::Symlink { ctime, .. } => *ctime,
        _ => unreachable!(),
    };

    // Staged while still holding `_dir_guard` - see `InMemoryFS::dir_lock`.
    let payload = LinkPayload {
        ino,
        new_parent: newparent,
        new_name: newname.to_string(),
    };
    if let Ok(bytes) = bincode::serialize(&payload) {
        fs.log_buffer
            .stage_op(OpCode::Link, ino, bytes, fs.log_writer.as_deref());
    }

    Ok(FileAttr {
        ino,
        file_type,
        perm,
        nlink,
        uid,
        gid,
        size,
        atime,
        mtime,
        ctime,
    })
}

pub fn link(fs: &InMemoryFS, req: Request, ino: u64, newparent: u64, newname: &str) {
    match link_core(fs, ino, newparent, newname) {
        Ok(attr) => req.reply_entry(&attr, 1.0, 1.0),
        Err(e) => req.reply_err(e),
    }
}
