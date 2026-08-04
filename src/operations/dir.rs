use crate::fs::InMemoryFS;
use crate::log::{MkdirPayload, OpCode, RmdirPayload};
use crate::node::Node;
use crate::shim::{self, FileAttr, FileType, Request};
use std::sync::Arc;

pub fn lookup(fs: &InMemoryFS, req: Request, parent: u64, name: &str) {
    log::trace!("lookup(parent={}, name={})", parent, name);
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
            size,
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

/// Core "list this directory's entries" logic - see `mkdir_core`'s doc comment for why
/// this split exists. Just the entries themselves, not the FUSE-specific `.`/`..`
/// synthesis or offset/size-paginated `DirectoryBuffer` marshaling `readdir` layers on
/// top - callers outside a real FUSE mount (the fuzz test) have no use for either.
pub fn list_dir_core(fs: &InMemoryFS, ino: u64) -> Result<Vec<(String, u64)>, i32> {
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
        Node::Directory { entries, .. } => Ok(entries.clone()),
        _ => Err(libc::ENOTDIR),
    }
}

pub fn readdir(fs: &InMemoryFS, req: Request, ino: u64, size: usize, offset: i64) {
    log::trace!("readdir(ino={}, size={}, offset={})", ino, size, offset);
    let entries = match list_dir_core(fs, ino) {
        Ok(entries) => entries,
        Err(e) => {
            req.reply_err(e);
            return;
        }
    };

    let mut db = shim::DirectoryBuffer::new(req);
    db.add(".", ino, FileType::Directory);
    db.add("..", 1, FileType::Directory); // Simple root parent is root

    // Snapshot the child Arcs and drop the map guard before the loop below - never hold
    // `fs.inodes`'s lock across a `lock_pool` acquisition (see the deadlock explanation
    // at rename_core's loop-prevention check in operations/links.rs).
    let child_arcs: Vec<(u64, Arc<crate::node::SyncNode>)> = {
        let map = fs.inodes.read().unwrap();
        entries
            .iter()
            .filter_map(|(_, child_ino)| map.get(child_ino).map(|arc| (*child_ino, Arc::clone(arc))))
            .collect()
    };
    let child_types: std::collections::HashMap<u64, FileType> = child_arcs
        .into_iter()
        .map(|(child_ino, child_node_arc)| {
            let _guard = fs.lock_pool.read(child_ino);
            let file_type = match unsafe { child_node_arc.read() } {
                Node::Directory { .. } => FileType::Directory,
                Node::File { .. } => FileType::RegularFile,
                Node::Symlink { .. } => FileType::Symlink,
            };
            (child_ino, file_type)
        })
        .collect();
    for (name, child_ino) in &entries {
        if let Some(file_type) = child_types.get(child_ino) {
            db.add(name, *child_ino, *file_type);
        }
    }

    db.reply(offset, size);
}

/// Core mkdir logic, independent of the FUSE request/reply plumbing - this is the
/// single source of truth both the real FUSE dispatch (`mkdir` below) and the fuzz
/// test's `TestFS` call, so a fix here can't drift out of sync with a hand-duplicated
/// copy. `uid`/`gid` come from the FUSE request context in production, but are just
/// plain params here since that context doesn't exist outside a real mount.
pub fn mkdir_core(
    fs: &InMemoryFS,
    parent: u64,
    name: &str,
    mode: u32,
    uid: u32,
    gid: u32,
) -> Result<FileAttr, i32> {
    let _snap_guard = fs.snapshot_rwlock.read().unwrap();
    // Held for the whole call - see `InMemoryFS::dir_lock`'s doc comment. Makes the
    // log record staged below always land in the same order as the entry it
    // describes, and means the only other thing that could touch `parent` at all
    // while this runs is a file-content op via `lock_pool` (never another
    // directory-structure mutation), so there's no TOCTOU window to re-check for.
    let _dir_guard = fs.dir_lock.lock().unwrap();
    let now = fs.clock.now();
    log::trace!(
        "mkdir(parent={}, name={}, mode=0o{:o}, uid={}, gid={})",
        parent,
        name,
        mode,
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
    // `entries` below - readers (lookup/readdir/getattr) don't take `dir_lock`, so a
    // concurrent one could otherwise follow the freshly-visible entry and find
    // `new_ino` briefly absent from the map.
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
                    // Roll back the insert above - the name lost the race.
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
    let payload = MkdirPayload {
        parent,
        name: name.to_string(),
        mode: mode & 0o777,
        created_at: crate::clock::system_time_to_unix(now),
        uid,
        gid,
    };
    if let Ok(bytes) = bincode::serialize(&payload) {
        fs.log_buffer
            .stage_op(OpCode::Mkdir, new_ino, bytes, fs.log_writer.as_deref());
    }

    Ok(FileAttr {
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
    })
}

pub fn mkdir(fs: &InMemoryFS, req: Request, parent: u64, name: &str, mode: u32) {
    let uid = req.uid();
    let gid = req.gid();
    match mkdir_core(fs, parent, name, mode, uid, gid) {
        Ok(attr) => req.reply_entry(&attr, 1.0, 1.0),
        Err(e) => req.reply_err(e),
    }
}

/// Core rmdir logic - see `mkdir_core`'s doc comment for why this split exists.
pub fn rmdir_core(fs: &InMemoryFS, parent: u64, name: &str) -> Result<(), i32> {
    let _snap_guard = fs.snapshot_rwlock.read().unwrap();
    let _dir_guard = fs.dir_lock.lock().unwrap();
    log::trace!("rmdir(parent={}, name={})", parent, name);
    let parent_node_arc = {
        let map = fs.inodes.read().unwrap();
        match map.get(&parent) {
            Some(n) => Arc::clone(n),
            None => return Err(libc::ENOENT),
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
                            None => return Err(libc::ENOENT),
                        }
                    };

                    // Held from the emptiness check all the way through the map
                    // removal below, not just the check - otherwise a concurrent
                    // mkdir/create/symlink using child_ino as ITS parent can slip a new
                    // child in during the gap (whether between the check and the entry
                    // removal, or between the entry removal and the map removal), and
                    // this thread would go on to remove child_ino's own entry and
                    // reclaim its inode anyway, silently orphaning that new child - see
                    // the identical race in rename_core's directory-overwrite path.
                    // `read_or_reuse`, not a plain `read` - child_ino's bucket can
                    // collide with parent's (striped over only 1024 buckets), and
                    // `_guard` above already holds parent's bucket as a writer;
                    // re-acquiring the same std::sync::RwLock read-after-write on the
                    // same thread is not guaranteed deadlock-free (see LockPool's own
                    // doc comment on read_or_reuse) - and reliably self-deadlocks in
                    // practice.
                    let _child_guard = fs.lock_pool.read_or_reuse(child_ino, &[parent]);
                    let child_node = unsafe { child_node_arc.read() };
                    match child_node {
                        Node::Directory {
                            entries: child_entries,
                            ..
                        } => {
                            if !child_entries.is_empty() {
                                return Err(libc::ENOTEMPTY);
                            }
                        }
                        _ => return Err(libc::ENOTDIR),
                    }

                    entries.remove(pos);
                    {
                        let mut map = fs.inodes.write().unwrap();
                        map.remove(&child_ino);
                    }
                    child_ino
                } else {
                    return Err(libc::ENOENT);
                }
            }
            _ => return Err(libc::ENOTDIR),
        }
    };

    // Staged while still holding `_dir_guard` - see `InMemoryFS::dir_lock`.
    let payload = RmdirPayload {
        parent,
        name: name.to_string(),
    };
    if let Ok(bytes) = bincode::serialize(&payload) {
        fs.log_buffer
            .stage_op(OpCode::Rmdir, removed_ino, bytes, fs.log_writer.as_deref());
    }

    Ok(())
}

pub fn rmdir(fs: &InMemoryFS, req: Request, parent: u64, name: &str) {
    match rmdir_core(fs, parent, name) {
        Ok(()) => req.reply_err(0),
        Err(e) => req.reply_err(e),
    }
}

pub fn releasedir(_fs: &InMemoryFS, req: Request, ino: u64) {
    log::trace!("releasedir(ino={})", ino);
    req.reply_err(0);
}

pub fn fsyncdir(fs: &InMemoryFS, req: Request, ino: u64, datasync: bool) {
    log::trace!("fsyncdir(ino={}, datasync={})", ino, datasync);
    let _ = fs.sync_log();
    req.reply_err(0);
}
