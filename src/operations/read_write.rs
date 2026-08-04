use crate::fs::InMemoryFS;
use crate::log::record::RECORD_HEADER_SIZE;
use crate::log::{CreatePayload, ExtentState, OpCode, SetattrPayload, SharedExtentState};
use crate::node::{Node, SyncNode};
use crate::range_map::RangeMap;
use crate::shim::{FileAttr, FileType, Request};
use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;
use std::time::SystemTime;

/// `to_set` bitmask flags for `setattr_core`, matching the values libfuse passes
/// through from the kernel - exposed so callers outside a real FUSE mount (the fuzz
/// test's `TestFS`) can build a `to_set` that `setattr_core` will interpret correctly.
pub const FUSE_SET_ATTR_MODE: u32 = 1 << 0;
pub const FUSE_SET_ATTR_UID: u32 = 1 << 1;
pub const FUSE_SET_ATTR_GID: u32 = 1 << 2;
pub const FUSE_SET_ATTR_SIZE: u32 = 1 << 3;
pub const FUSE_SET_ATTR_ATIME: u32 = 1 << 4;
pub const FUSE_SET_ATTR_MTIME: u32 = 1 << 5;

/// Core getattr logic - see `dir::mkdir_core`'s doc comment for why this split exists.
pub fn getattr_core(fs: &InMemoryFS, ino: u64) -> Result<FileAttr, i32> {
    log::trace!("getattr(ino={})", ino);
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
        Node::Directory {
            perm,
            nlink,
            uid,
            gid,
            atime,
            mtime,
            ctime,
            ..
        } => Ok(FileAttr {
            ino,
            file_type: FileType::Directory,
            perm: *perm,
            nlink: *nlink,
            uid: *uid,
            gid: *gid,
            size: 0,
            atime: *atime,
            mtime: *mtime,
            ctime: *ctime,
        }),
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
        } => Ok(FileAttr {
            ino,
            file_type: FileType::RegularFile,
            perm: *perm,
            nlink: *nlink,
            uid: *uid,
            gid: *gid,
            size: *size as i64,
            atime: *atime,
            mtime: *mtime,
            ctime: *ctime,
        }),
        Node::Symlink {
            target,
            nlink,
            uid,
            gid,
            atime,
            mtime,
            ctime,
        } => Ok(FileAttr {
            ino,
            file_type: FileType::Symlink,
            perm: 0o777,
            nlink: *nlink,
            uid: *uid,
            gid: *gid,
            size: target.len() as i64,
            atime: *atime,
            mtime: *mtime,
            ctime: *ctime,
        }),
    }
}

pub fn getattr(fs: &InMemoryFS, req: Request, ino: u64) {
    match getattr_core(fs, ino) {
        Ok(attr) => req.reply_attr(&attr, 1.0),
        Err(e) => req.reply_err(e),
    }
}

/// Core read logic - see `dir::mkdir_core`'s doc comment for why this split exists.
pub fn read_core(fs: &InMemoryFS, ino: u64, size: usize, offset: i64) -> Result<Vec<u8>, i32> {
    log::trace!("read(ino={}, size={}, offset={})", ino, size, offset);
    let node_arc = {
        let map = fs.inodes.read().unwrap();
        match map.get(&ino) {
            Some(n) => Arc::clone(n),
            None => return Err(libc::ENOENT),
        }
    };

    let now = fs.clock.now();
    let _guard = fs.lock_pool.write(ino);
    let node = unsafe { node_arc.write() };
    match node {
        Node::File {
            range_map,
            size: file_size,
            atime,
            ..
        } => {
            if fs.track_atime {
                *atime = now;
            }
            let file_len = *file_size;
            if offset >= file_len as i64 {
                return Ok(Vec::new());
            }
            let read_start = offset as u64;
            let read_len = std::cmp::min(size as u64, file_len - read_start);

            let extents = range_map.query(read_start, read_len);
            let mut read_buf = vec![0u8; read_len as usize];

            for (extent_start, extent_len, shared_state) in extents {
                let state = shared_state.read_state();
                let dst_offset = (extent_start - read_start) as usize;

                match state {
                    ExtentState::Staged {
                        data,
                        payload_offset,
                        length,
                    } => {
                        let src_start = payload_offset as usize;
                        let src_end = std::cmp::min(src_start + length as usize, data.len());
                        let copy_len = std::cmp::min(extent_len as usize, src_end - src_start);
                        read_buf[dst_offset..dst_offset + copy_len]
                            .copy_from_slice(&data[src_start..src_start + copy_len]);
                    }
                    ExtentState::Disk {
                        generation,
                        record_log_offset,
                        payload_offset,
                        length,
                    } => {
                        if let Some(ref cache) = fs.log_cache {
                            if let Ok(file_arc) = cache.get_or_open(generation) {
                                let mut f = file_arc.lock().unwrap();
                                let disk_seek_pos = record_log_offset
                                    + RECORD_HEADER_SIZE as u64
                                    + payload_offset as u64;
                                if f.seek(SeekFrom::Start(disk_seek_pos)).is_ok() {
                                    let copy_len =
                                        std::cmp::min(extent_len as usize, length as usize);
                                    let _ = f.read_exact(
                                        &mut read_buf[dst_offset..dst_offset + copy_len],
                                    );
                                }
                            }
                        }
                    }
                }
            }

            Ok(read_buf)
        }
        _ => Err(libc::EISDIR),
    }
}

pub fn read(fs: &InMemoryFS, req: Request, ino: u64, size: usize, offset: i64) {
    match read_core(fs, ino, size, offset) {
        Ok(buf) => req.reply_buf(&buf),
        Err(e) => req.reply_err(e),
    }
}

pub fn open(fs: &InMemoryFS, req: Request, ino: u64, flags: u32) {
    log::trace!("open(ino={}, flags=0x{:x})", ino, flags);
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
        let now = fs.clock.now();
        let _guard = fs.lock_pool.write(ino);
        let node = unsafe { node_arc.write() };
        match node {
            Node::File {
                range_map,
                size,
                mtime,
                ctime,
                ..
            } => {
                log::trace!("truncating file to 0 inside open");
                range_map.clear();
                *size = 0;
                *mtime = now;
                *ctime = now;
            }
            _ => {
                req.reply_err(libc::EISDIR);
                return;
            }
        }
    }
    req.reply_open(0);
}

/// Core write logic - see `dir::mkdir_core`'s doc comment for why this split exists.
pub fn write_core(fs: &InMemoryFS, ino: u64, buf: &[u8], offset: i64) -> Result<usize, i32> {
    // Computed as early as possible - right as these bytes arrive from the kernel -
    // so LogBuffer::flush's chain-verify check catches in-memory corruption that
    // happens anywhere later in the pipeline, not just during the flush itself.
    let ingest_checksum = blake3::hash(buf);

    let _snap_guard = fs.snapshot_rwlock.read().unwrap();
    log::trace!("write(ino={}, len={}, offset={})", ino, buf.len(), offset);
    let node_arc = {
        let map = fs.inodes.read().unwrap();
        match map.get(&ino) {
            Some(n) => Arc::clone(n),
            None => return Err(libc::ENOENT),
        }
    };

    let now = fs.clock.now();
    let _guard = fs.lock_pool.write(ino);
    let node = unsafe { node_arc.write() };
    match node {
        Node::File {
            range_map,
            size,
            mtime,
            ctime,
            ..
        } => {
            let file_offset = offset as u64;
            let write_len = buf.len() as u64;

            let data = Arc::new(buf.to_vec());
            let shared_state =
                SharedExtentState::new_staged(Arc::clone(&data), 0, buf.len() as u32);

            range_map.insert(file_offset, write_len, shared_state.clone());
            *size = std::cmp::max(*size, file_offset + write_len);
            *mtime = now;
            *ctime = now;

            fs.log_buffer.stage_write(
                ino,
                file_offset,
                shared_state,
                data,
                ingest_checksum,
                crate::clock::system_time_to_unix(now),
                fs.log_writer.as_deref(),
            );
            Ok(buf.len())
        }
        _ => Err(libc::EISDIR),
    }
}

pub fn write(fs: &InMemoryFS, req: Request, ino: u64, buf: &[u8], offset: i64) {
    match write_core(fs, ino, buf, offset) {
        Ok(count) => req.reply_write(count),
        Err(e) => req.reply_err(e),
    }
}

/// Core setattr logic - see `dir::mkdir_core`'s doc comment for why this split exists.
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
    let _snap_guard = fs.snapshot_rwlock.read().unwrap();
    log::trace!(
        "setattr(ino={}, mode=0o{:o}, uid={}, gid={}, size={}, to_set=0x{:x})",
        ino,
        mode,
        uid,
        gid,
        size,
        to_set
    );
    let node_arc = {
        let map = fs.inodes.read().unwrap();
        match map.get(&ino) {
            Some(n) => Arc::clone(n),
            None => return Err(libc::ENOENT),
        }
    };

    let now = fs.clock.now();
    let _guard = fs.lock_pool.write(ino);
    let node = unsafe { node_arc.write() };

    let mut setattr_payload = SetattrPayload {
        mode: None,
        uid: None,
        gid: None,
        size: None,
        atime: None,
        mtime: None,
        op_time: crate::clock::system_time_to_unix(now),
    };

    match node {
        Node::File {
            range_map,
            size: node_size,
            perm,
            nlink,
            uid: node_uid,
            gid: node_gid,
            atime: node_atime,
            mtime: node_mtime,
            ctime: node_ctime,
        } => {
            if (to_set & FUSE_SET_ATTR_MODE) != 0 {
                *perm = mode & 0o777;
                *node_ctime = now;
                setattr_payload.mode = Some(*perm);
            }
            if (to_set & FUSE_SET_ATTR_UID) != 0 {
                *node_uid = uid;
                *node_ctime = now;
                setattr_payload.uid = Some(uid);
            }
            if (to_set & FUSE_SET_ATTR_GID) != 0 {
                *node_gid = gid;
                *node_ctime = now;
                setattr_payload.gid = Some(gid);
            }
            if (to_set & FUSE_SET_ATTR_SIZE) != 0 {
                log::trace!("truncating file to {}", size);
                let new_size = size as u64;
                if new_size < *node_size {
                    // Actually remove/trim range map entries beyond new_size - a later
                    // grow back past this point must read zeros, not stale bytes.
                    range_map.truncate(new_size);
                }
                *node_size = new_size;
                *node_mtime = now;
                *node_ctime = now;
                setattr_payload.size = Some(new_size);
            }
            if (to_set & FUSE_SET_ATTR_ATIME) != 0 {
                *node_atime = atime;
                *node_ctime = now;
                setattr_payload.atime = Some(crate::clock::system_time_to_unix(atime));
            }
            if (to_set & FUSE_SET_ATTR_MTIME) != 0 {
                *node_mtime = mtime;
                *node_ctime = now;
                setattr_payload.mtime = Some(crate::clock::system_time_to_unix(mtime));
            }

            if let Ok(bytes) = bincode::serialize(&setattr_payload) {
                fs.log_buffer
                    .stage_op(OpCode::Setattr, ino, bytes, fs.log_writer.as_deref());
            }

            Ok(FileAttr {
                ino,
                file_type: FileType::RegularFile,
                perm: *perm,
                nlink: *nlink,
                uid: *node_uid,
                gid: *node_gid,
                size: *node_size as i64,
                atime: *node_atime,
                mtime: *node_mtime,
                ctime: *node_ctime,
            })
        }
        Node::Directory {
            perm,
            nlink,
            uid: node_uid,
            gid: node_gid,
            atime: node_atime,
            mtime: node_mtime,
            ctime: node_ctime,
            ..
        } => {
            if (to_set & FUSE_SET_ATTR_MODE) != 0 {
                *perm = mode & 0o777;
                *node_ctime = now;
                setattr_payload.mode = Some(*perm);
            }
            if (to_set & FUSE_SET_ATTR_UID) != 0 {
                *node_uid = uid;
                *node_ctime = now;
                setattr_payload.uid = Some(uid);
            }
            if (to_set & FUSE_SET_ATTR_GID) != 0 {
                *node_gid = gid;
                *node_ctime = now;
                setattr_payload.gid = Some(gid);
            }
            if (to_set & FUSE_SET_ATTR_ATIME) != 0 {
                *node_atime = atime;
                *node_ctime = now;
                setattr_payload.atime = Some(crate::clock::system_time_to_unix(atime));
            }
            if (to_set & FUSE_SET_ATTR_MTIME) != 0 {
                *node_mtime = mtime;
                *node_ctime = now;
                setattr_payload.mtime = Some(crate::clock::system_time_to_unix(mtime));
            }

            if let Ok(bytes) = bincode::serialize(&setattr_payload) {
                fs.log_buffer
                    .stage_op(OpCode::Setattr, ino, bytes, fs.log_writer.as_deref());
            }

            Ok(FileAttr {
                ino,
                file_type: FileType::Directory,
                perm: *perm,
                nlink: *nlink,
                uid: *node_uid,
                gid: *node_gid,
                size: 0,
                atime: *node_atime,
                mtime: *node_mtime,
                ctime: *node_ctime,
            })
        }
        Node::Symlink {
            target,
            nlink,
            uid: node_uid,
            gid: node_gid,
            atime: node_atime,
            mtime: node_mtime,
            ctime: node_ctime,
        } => {
            if (to_set & FUSE_SET_ATTR_UID) != 0 {
                *node_uid = uid;
                *node_ctime = now;
                setattr_payload.uid = Some(uid);
            }
            if (to_set & FUSE_SET_ATTR_GID) != 0 {
                *node_gid = gid;
                *node_ctime = now;
                setattr_payload.gid = Some(gid);
            }
            if (to_set & FUSE_SET_ATTR_ATIME) != 0 {
                *node_atime = atime;
                *node_ctime = now;
                setattr_payload.atime = Some(crate::clock::system_time_to_unix(atime));
            }
            if (to_set & FUSE_SET_ATTR_MTIME) != 0 {
                *node_mtime = mtime;
                *node_ctime = now;
                setattr_payload.mtime = Some(crate::clock::system_time_to_unix(mtime));
            }

            if let Ok(bytes) = bincode::serialize(&setattr_payload) {
                fs.log_buffer
                    .stage_op(OpCode::Setattr, ino, bytes, fs.log_writer.as_deref());
            }

            Ok(FileAttr {
                ino,
                file_type: FileType::Symlink,
                perm: 0o777,
                nlink: *nlink,
                uid: *node_uid,
                gid: *node_gid,
                size: target.len() as i64,
                atime: *node_atime,
                mtime: *node_mtime,
                ctime: *node_ctime,
            })
        }
    }
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

/// Core create logic - see `dir::mkdir_core`'s doc comment for why this split exists.
/// `flags` isn't used for anything beyond the trace log (matching the original
/// handler), kept only so that log line stays intact for both callers.
pub fn create_core(
    fs: &InMemoryFS,
    parent: u64,
    name: &str,
    mode: u32,
    flags: u32,
    uid: u32,
    gid: u32,
) -> Result<FileAttr, i32> {
    let _snap_guard = fs.snapshot_rwlock.read().unwrap();
    // Held for the whole call - see `InMemoryFS::dir_lock`'s doc comment.
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
    let new_node = Arc::new(SyncNode::new(Node::File {
        range_map: RangeMap::new(),
        size: 0,
        perm: mode & 0o777,
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
    let payload = CreatePayload {
        parent,
        name: name.to_string(),
        mode: mode & 0o777,
        uid,
        gid,
        created_at: crate::clock::system_time_to_unix(now),
    };
    if let Ok(bytes) = bincode::serialize(&payload) {
        fs.log_buffer
            .stage_op(OpCode::Create, new_ino, bytes, fs.log_writer.as_deref());
    }

    Ok(FileAttr {
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
    })
}

pub fn create(fs: &InMemoryFS, req: Request, parent: u64, name: &str, mode: u32, flags: u32) {
    let uid = req.uid();
    let gid = req.gid();
    match create_core(fs, parent, name, mode, flags, uid, gid) {
        Ok(attr) => req.reply_create(&attr, 1.0, 1.0, 0),
        Err(e) => req.reply_err(e),
    }
}

pub fn fsync(fs: &InMemoryFS, req: Request, ino: u64, datasync: bool) {
    log::trace!("fsync(ino={}, datasync={})", ino, datasync);
    let _ = fs.sync_log();
    req.reply_err(0);
}

pub fn release(_fs: &InMemoryFS, req: Request, ino: u64) {
    log::trace!("release(ino={})", ino);
    req.reply_err(0);
}
