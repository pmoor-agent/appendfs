use crate::fs::InMemoryFS;
use crate::log::SharedExtentState;
use crate::node::{AttrDelta, EntryDelta, FileDelta, NodeDelta};
use crate::range_map::RangeMap;
use crate::shim::{FileAttr, FileType, Request};
use std::sync::Arc;
use std::time::SystemTime;

pub const FUSE_SET_ATTR_MODE: u32 = 1 << 0;
pub const FUSE_SET_ATTR_UID: u32 = 1 << 1;
pub const FUSE_SET_ATTR_GID: u32 = 1 << 2;
pub const FUSE_SET_ATTR_SIZE: u32 = 1 << 3;
pub const FUSE_SET_ATTR_ATIME: u32 = 1 << 4;
pub const FUSE_SET_ATTR_MTIME: u32 = 1 << 5;

pub fn getattr_core(fs: &InMemoryFS, ino: u64) -> Result<FileAttr, i32> {
    log::trace!("getattr(ino={})", ino);
    fs.get_attr(ino).ok_or(libc::ENOENT)
}

pub fn getattr(fs: &InMemoryFS, req: Request, ino: u64) {
    match getattr_core(fs, ino) {
        Ok(attr) => req.reply_attr(&attr, 1.0),
        Err(e) => req.reply_err(e),
    }
}

pub fn read_core(fs: &InMemoryFS, ino: u64, size: usize, offset: i64) -> Result<Vec<u8>, i32> {
    log::trace!("read(ino={}, size={}, offset={})", ino, size, offset);
    if offset < 0 {
        return Err(libc::EINVAL);
    }
    fs.read_file_data(ino, offset as u64, size)
}

pub fn read(fs: &InMemoryFS, req: Request, ino: u64, size: usize, offset: i64) {
    match read_core(fs, ino, size, offset) {
        Ok(buf) => req.reply_buf(&buf),
        Err(e) => req.reply_err(e),
    }
}

pub fn open(fs: &InMemoryFS, req: Request, ino: u64, flags: u32) {
    log::trace!("open(ino={}, flags=0x{:x})", ino, flags);
    let attr = match fs.get_attr(ino) {
        Some(a) => a,
        None => {
            req.reply_err(libc::ENOENT);
            return;
        }
    };
    if attr.file_type != FileType::RegularFile {
        req.reply_err(libc::EISDIR);
        return;
    }

    fs.open_handle(ino);

    if (flags & libc::O_TRUNC as u32) != 0 {
        let now = fs.clock.now();
        let _ = setattr_core(
            fs,
            ino,
            0,
            0,
            0,
            0,
            now,
            now,
            FUSE_SET_ATTR_SIZE | FUSE_SET_ATTR_MTIME,
        );
    }
    req.reply_open(0);
}

pub fn write_core(fs: &InMemoryFS, ino: u64, buf: &[u8], offset: i64) -> Result<usize, i32> {
    log::trace!("write(ino={}, len={}, offset={})", ino, buf.len(), offset);
    if offset < 0 {
        return Err(libc::EINVAL);
    }

    let attr = fs.get_attr(ino).ok_or(libc::ENOENT)?;
    if attr.file_type != FileType::RegularFile {
        return Err(libc::EISDIR);
    }

    let now = fs.clock.now();
    let file_offset = offset as u64;
    let write_len = buf.len() as u64;

    let data = Arc::new(buf.to_vec());
    let shared_state = SharedExtentState::new_staged(Arc::clone(&data), 0, buf.len() as u32);

    {
        let mut live = fs.live.write().unwrap();
        let entry = live
            .entry(ino)
            .or_insert_with(|| EntryDelta::Node(NodeDelta::File(FileDelta::default())));
        if let EntryDelta::Node(NodeDelta::File(f)) = entry {
            f.extents
                .insert(file_offset, write_len, shared_state.clone());
            let current_size = f.size.unwrap_or(attr.size as u64);
            f.size = Some(std::cmp::max(current_size, file_offset + write_len));
            f.attr_delta.mtime = Some(now);
            f.attr_delta.ctime = Some(now);
        }
    }

    fs.notify_mutation(write_len as usize);

    Ok(buf.len())
}

pub fn write(fs: &InMemoryFS, req: Request, ino: u64, buf: &[u8], offset: i64) {
    match write_core(fs, ino, buf, offset) {
        Ok(count) => req.reply_write(count),
        Err(e) => req.reply_err(e),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn setattr_core(
    fs: &InMemoryFS,
    ino: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    size: i64,
    atime: SystemTime,
    mtime: SystemTime,
    to_set: u32,
) -> Result<FileAttr, i32> {
    log::trace!(
        "setattr(ino={}, mode=0o{:o}, uid={}, gid={}, size={}, to_set=0x{:x})",
        ino,
        mode,
        uid,
        gid,
        size,
        to_set
    );

    let attr = fs.get_attr(ino).ok_or(libc::ENOENT)?;
    let now = fs.clock.now();

    let mut attr_delta = AttrDelta::default();

    if (to_set & FUSE_SET_ATTR_MODE) != 0 {
        attr_delta.mode = Some(mode & 0o777);
        attr_delta.ctime = Some(now);
    }
    if (to_set & FUSE_SET_ATTR_UID) != 0 {
        attr_delta.uid = Some(uid);
        attr_delta.ctime = Some(now);
    }
    if (to_set & FUSE_SET_ATTR_GID) != 0 {
        attr_delta.gid = Some(gid);
        attr_delta.ctime = Some(now);
    }
    if (to_set & FUSE_SET_ATTR_ATIME) != 0 {
        attr_delta.atime = Some(atime);
        attr_delta.ctime = Some(now);
    }
    if (to_set & FUSE_SET_ATTR_MTIME) != 0 {
        attr_delta.mtime = Some(mtime);
        attr_delta.ctime = Some(now);
    }

    if (to_set & FUSE_SET_ATTR_SIZE) != 0 && attr.file_type == FileType::RegularFile {
        log::trace!("truncating file to {}", size);
        let new_size = size as u64;
        let mut live = fs.live.write().unwrap();
        let entry = live
            .entry(ino)
            .or_insert_with(|| EntryDelta::Node(NodeDelta::File(FileDelta::default())));
        if let EntryDelta::Node(NodeDelta::File(f)) = entry {
            f.extents.truncate(new_size);
            f.size = Some(new_size);
            f.truncate_mask = Some(match f.truncate_mask {
                Some(prev) => std::cmp::min(prev, new_size),
                None => new_size,
            });
            f.attr_delta.mtime = Some(now);
            f.attr_delta.ctime = Some(now);
        }
    }

    fs.update_attr_delta(ino, attr_delta);

    fs.notify_mutation(0);

    let updated_attr = fs.get_attr(ino).ok_or(libc::ENOENT)?;
    Ok(updated_attr)
}

#[allow(clippy::too_many_arguments)]
pub fn setattr(
    fs: &InMemoryFS,
    req: Request,
    ino: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    size: i64,
    atime: SystemTime,
    mtime: SystemTime,
    to_set: u32,
) {
    match setattr_core(fs, ino, mode, uid, gid, size, atime, mtime, to_set) {
        Ok(attr) => req.reply_attr(&attr, 1.0),
        Err(e) => req.reply_err(e),
    }
}

pub fn create_core(
    fs: &InMemoryFS,
    parent: u64,
    name: &str,
    mode: u32,
    flags: u32,
    uid: u32,
    gid: u32,
) -> Result<FileAttr, i32> {
    let attr = {
        let _dir_guard = fs.dir_lock.lock().unwrap();
        let now = fs.clock.now();
        log::trace!(
            "create(parent={}, name={}, mode=0o{:o}, flags=0x{:x}, uid={}, gid={})",
            parent,
            name,
            mode,
            flags,
            uid,
            gid
        );

        if name.len() > 255 {
            return Err(libc::ENAMETOOLONG);
        }

        let parent_attr = fs.get_attr(parent).ok_or(libc::ENOENT)?;
        if parent_attr.file_type != FileType::Directory {
            return Err(libc::ENOTDIR);
        }

        if fs.lookup_child(parent, name).is_some() {
            return Err(libc::EEXIST);
        }

        let new_ino = fs.allocate_inode();
        let new_delta = NodeDelta::File(FileDelta {
            extents: RangeMap::new(),
            size: Some(0),
            truncate_mask: None,
            attr_delta: AttrDelta {
                mode: Some(mode & 0o777),
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

        FileAttr {
            ino: new_ino,
            file_type: FileType::RegularFile,
            perm: mode & 0o777,
            nlink: 1,
            uid,
            gid,
            size: 0,
            atime: now,
            mtime: now,
            ctime: now,
        }
    };

    fs.notify_mutation(0);

    Ok(attr)
}

pub fn create(fs: &InMemoryFS, req: Request, parent: u64, name: &str, mode: u32, flags: u32) {
    let uid = req.uid();
    let gid = req.gid();
    match create_core(fs, parent, name, mode, flags, uid, gid) {
        Ok(attr) => {
            fs.open_handle(attr.ino);
            req.reply_create(&attr, 1.0, 1.0, 0);
        }
        Err(e) => req.reply_err(e),
    }
}

pub fn fsync(fs: &InMemoryFS, req: Request, ino: u64, datasync: bool) {
    log::trace!("fsync(ino={}, datasync={})", ino, datasync);
    let _ = fs.sync_log();
    req.reply_err(0);
}

pub fn release(fs: &InMemoryFS, req: Request, ino: u64) {
    log::trace!("release(ino={})", ino);
    fs.release_handle(ino);
    req.reply_err(0);
}
