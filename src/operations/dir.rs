use crate::fs::InMemoryFS;
use crate::node::{AttrDelta, DirectoryDelta, NodeDelta};
use crate::shim::{self, FileAttr, FileType, Request};
use std::collections::HashMap;

pub fn lookup(fs: &InMemoryFS, req: Request, parent: u64, name: &str) {
    log::trace!("lookup(parent={}, name={})", parent, name);
    let parent_attr = match fs.get_attr(parent) {
        Some(attr) => attr,
        None => {
            req.reply_err(libc::ENOENT);
            return;
        }
    };
    if parent_attr.file_type != FileType::Directory {
        req.reply_err(libc::ENOTDIR);
        return;
    }

    let child_ino = match fs.lookup_child(parent, name) {
        Some(ino) => ino,
        None => {
            req.reply_err(libc::ENOENT);
            return;
        }
    };

    match fs.get_attr(child_ino) {
        Some(attr) => req.reply_entry(&attr, 1.0, 1.0),
        None => req.reply_err(libc::ENOENT),
    }
}

pub fn list_dir_core(fs: &InMemoryFS, ino: u64) -> Result<Vec<(String, u64)>, i32> {
    let attr = fs.get_attr(ino).ok_or(libc::ENOENT)?;
    if attr.file_type != FileType::Directory {
        return Err(libc::ENOTDIR);
    }
    fs.list_directory(ino).ok_or(libc::ENOENT)
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
    db.add("..", 1, FileType::Directory);

    for (name, child_ino) in &entries {
        if let Some(attr) = fs.get_attr(*child_ino) {
            db.add(name, *child_ino, attr.file_type);
        }
    }

    db.reply(offset, size);
}

pub fn mkdir_core(
    fs: &InMemoryFS,
    parent: u64,
    name: &str,
    mode: u32,
    uid: u32,
    gid: u32,
) -> Result<FileAttr, i32> {
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

    let parent_attr = fs.get_attr(parent).ok_or(libc::ENOENT)?;
    if parent_attr.file_type != FileType::Directory {
        return Err(libc::ENOTDIR);
    }

    if fs.lookup_child(parent, name).is_some() {
        return Err(libc::EEXIST);
    }

    let new_ino = fs.allocate_inode();
    let new_delta = NodeDelta::Directory(DirectoryDelta {
        added: HashMap::new(),
        removed: std::collections::HashSet::new(),
        attr_delta: AttrDelta {
            mode: Some(mode & 0o777),
            nlink: Some(2),
            uid: Some(uid),
            gid: Some(gid),
            atime: Some(now),
            mtime: Some(now),
            ctime: Some(now),
        },
    });

    fs.insert_new_node(new_ino, new_delta);
    fs.add_dir_entry(parent, name, new_ino, now);

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

pub fn rmdir_core(fs: &InMemoryFS, parent: u64, name: &str) -> Result<(), i32> {
    let _dir_guard = fs.dir_lock.lock().unwrap();
    let now = fs.clock.now();
    log::trace!("rmdir(parent={}, name={})", parent, name);

    let parent_attr = fs.get_attr(parent).ok_or(libc::ENOENT)?;
    if parent_attr.file_type != FileType::Directory {
        return Err(libc::ENOTDIR);
    }

    let child_ino = fs.lookup_child(parent, name).ok_or(libc::ENOENT)?;
    let child_attr = fs.get_attr(child_ino).ok_or(libc::ENOENT)?;
    if child_attr.file_type != FileType::Directory {
        return Err(libc::ENOTDIR);
    }

    let entries = fs.list_directory(child_ino).ok_or(libc::ENOENT)?;
    if !entries.is_empty() {
        return Err(libc::ENOTEMPTY);
    }

    fs.remove_dir_entry(parent, name, now);
    fs.tombstone(child_ino);

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
