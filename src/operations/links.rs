use crate::fs::{InMemoryFS, find_parent_inode};
use crate::node::{AttrDelta, NodeDelta, SymlinkDelta};
use crate::shim::{FileAttr, FileType, Request};

pub fn unlink_core(fs: &InMemoryFS, parent: u64, name: &str) -> Result<(), i32> {
    let _dir_guard = fs.dir_lock.lock().unwrap();
    let now = fs.clock.now();
    log::trace!("unlink(parent={}, name={})", parent, name);

    let parent_attr = fs.get_attr(parent).ok_or(libc::ENOENT)?;
    if parent_attr.file_type != FileType::Directory {
        return Err(libc::ENOTDIR);
    }

    let child_ino = fs.lookup_child(parent, name).ok_or(libc::ENOENT)?;
    let child_attr = fs.get_attr(child_ino).ok_or(libc::ENOENT)?;

    if child_attr.file_type == FileType::Directory {
        return Err(libc::EISDIR);
    }

    fs.remove_dir_entry(parent, name, now);

    let new_nlink = child_attr.nlink.saturating_sub(1);
    fs.update_attr_delta(
        child_ino,
        AttrDelta {
            nlink: Some(new_nlink),
            ctime: Some(now),
            ..Default::default()
        },
    );

    if new_nlink == 0 && fs.open_count(child_ino) == 0 {
        fs.tombstone(child_ino);
    }

    Ok(())
}

pub fn unlink(fs: &InMemoryFS, req: Request, parent: u64, name: &str) {
    match unlink_core(fs, parent, name) {
        Ok(()) => req.reply_err(0),
        Err(e) => req.reply_err(e),
    }
}

pub fn symlink_core(
    fs: &InMemoryFS,
    parent: u64,
    name: &str,
    target: &str,
    uid: u32,
    gid: u32,
) -> Result<FileAttr, i32> {
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

    let parent_attr = fs.get_attr(parent).ok_or(libc::ENOENT)?;
    if parent_attr.file_type != FileType::Directory {
        return Err(libc::ENOTDIR);
    }

    if fs.lookup_child(parent, name).is_some() {
        return Err(libc::EEXIST);
    }

    let new_ino = fs.allocate_inode();
    let new_delta = NodeDelta::Symlink(SymlinkDelta {
        target: Some(target.to_string()),
        attr_delta: AttrDelta {
            mode: Some(0o777),
            nlink: Some(1),
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

pub fn readlink_core(fs: &InMemoryFS, ino: u64) -> Result<String, i32> {
    log::trace!("readlink(ino={})", ino);
    fs.read_link(ino).ok_or(libc::EINVAL)
}

pub fn readlink(fs: &InMemoryFS, req: Request, ino: u64) {
    match readlink_core(fs, ino) {
        Ok(target) => req.reply_readlink(&target),
        Err(e) => req.reply_err(e),
    }
}

pub fn rename_core(
    fs: &InMemoryFS,
    parent: u64,
    name: &str,
    newparent: u64,
    newname: &str,
) -> Result<(), i32> {
    let _dir_guard = fs.dir_lock.lock().unwrap();
    let now = fs.clock.now();
    log::trace!(
        "rename(parent={}, name={}, newparent={}, newname={})",
        parent,
        name,
        newparent,
        newname
    );

    let parent_attr = fs.get_attr(parent).ok_or(libc::ENOENT)?;
    if parent_attr.file_type != FileType::Directory {
        return Err(libc::ENOTDIR);
    }
    let newparent_attr = fs.get_attr(newparent).ok_or(libc::ENOENT)?;
    if newparent_attr.file_type != FileType::Directory {
        return Err(libc::ENOTDIR);
    }

    let source_ino = fs.lookup_child(parent, name).ok_or(libc::ENOENT)?;
    let source_attr = fs.get_attr(source_ino).ok_or(libc::ENOENT)?;

    if source_attr.file_type == FileType::Directory {
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

    if parent == newparent && name == newname {
        return Ok(());
    }

    if let Some(dest_ino) = fs.lookup_child(newparent, newname) {
        let dest_attr = fs.get_attr(dest_ino).ok_or(libc::ENOENT)?;

        let src_is_dir = source_attr.file_type == FileType::Directory;
        let dest_is_dir = dest_attr.file_type == FileType::Directory;

        if src_is_dir != dest_is_dir {
            return Err(if src_is_dir {
                libc::ENOTDIR
            } else {
                libc::EISDIR
            });
        }

        if dest_is_dir {
            let dest_entries = fs.list_directory(dest_ino).ok_or(libc::ENOENT)?;
            if !dest_entries.is_empty() {
                return Err(libc::ENOTEMPTY);
            }
            fs.remove_dir_entry(newparent, newname, now);
            fs.tombstone(dest_ino);
        } else {
            fs.remove_dir_entry(newparent, newname, now);
            let new_dest_nlink = dest_attr.nlink.saturating_sub(1);
            fs.update_attr_delta(
                dest_ino,
                AttrDelta {
                    nlink: Some(new_dest_nlink),
                    ctime: Some(now),
                    ..Default::default()
                },
            );
            if new_dest_nlink == 0 && fs.open_count(dest_ino) == 0 {
                fs.tombstone(dest_ino);
            }
        }
    }

    fs.remove_dir_entry(parent, name, now);
    fs.add_dir_entry(newparent, newname, source_ino, now);

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

pub fn link_core(
    fs: &InMemoryFS,
    ino: u64,
    newparent: u64,
    newname: &str,
) -> Result<FileAttr, i32> {
    let _dir_guard = fs.dir_lock.lock().unwrap();
    let now = fs.clock.now();
    log::trace!(
        "link(ino={}, newparent={}, newname={})",
        ino,
        newparent,
        newname
    );

    let target_attr = fs.get_attr(ino).ok_or(libc::ENOENT)?;
    if target_attr.file_type == FileType::Directory {
        return Err(libc::EPERM);
    }

    let newparent_attr = fs.get_attr(newparent).ok_or(libc::ENOENT)?;
    if newparent_attr.file_type != FileType::Directory {
        return Err(libc::ENOTDIR);
    }

    if fs.lookup_child(newparent, newname).is_some() {
        return Err(libc::EEXIST);
    }

    let new_nlink = target_attr.nlink + 1;
    fs.update_attr_delta(
        ino,
        AttrDelta {
            nlink: Some(new_nlink),
            ctime: Some(now),
            ..Default::default()
        },
    );

    fs.add_dir_entry(newparent, newname, ino, now);

    fs.get_attr(ino).ok_or(libc::ENOENT)
}

pub fn link(fs: &InMemoryFS, req: Request, ino: u64, newparent: u64, newname: &str) {
    match link_core(fs, ino, newparent, newname) {
        Ok(attr) => req.reply_entry(&attr, 1.0, 1.0),
        Err(e) => req.reply_err(e),
    }
}
