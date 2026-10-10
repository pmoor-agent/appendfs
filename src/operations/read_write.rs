use crate::error::FsError;
use crate::extent_map::{Extent, ExtentMap};
use crate::fs::{AppendFs, FileHandle, FlushReason, FsInnerGuard, execute_read_plan, is_virtual_ino};
use crate::node::{AttrDelta, EntryDelta, FileDelta, NodeDelta};
use crate::shim::{
    DeferredCompletion, DeferredResult, DeferredToken, FileAttr, FileType, FuseResponse, RequestContext,
};
use crate::sync::OpTag;
use std::sync::Arc;
use std::time::SystemTime;

pub const FUSE_SET_ATTR_MODE: u32 = 1 << 0;
pub const FUSE_SET_ATTR_UID: u32 = 1 << 1;
pub const FUSE_SET_ATTR_GID: u32 = 1 << 2;
pub const FUSE_SET_ATTR_SIZE: u32 = 1 << 3;
pub const FUSE_SET_ATTR_ATIME: u32 = 1 << 4;
pub const FUSE_SET_ATTR_MTIME: u32 = 1 << 5;

pub fn getattr_core(fs: &AppendFs, ino: u64) -> Result<FileAttr, FsError> {
    log::trace!("getattr(ino={})", ino);
    fs.with_inner(OpTag::GetAttr, |inner| {
        inner.check_shutdown(false)?;
        fs.get_attr_locked(inner, ino).ok_or(FsError::ENOENT)
    })
}

pub fn getattr_response(fs: &AppendFs, ino: u64) -> Result<FuseResponse<'static>, FsError> {
    getattr_core(fs, ino).map(FuseResponse::attr)
}

pub fn read_response(
    fs: &AppendFs,
    ino: u64,
    fh: u64,
    offset: i64,
    size: usize,
) -> DeferredResult<FuseResponse<'static>> {
    log::trace!("read(ino={}, fh={}, size={}, offset={})", ino, fh, size, offset);
    if offset < 0 {
        return DeferredResult::err(FsError::EINVAL);
    }

    let plan = match fs.plan_read_handle(ino, fh, offset as u64, size) {
        Ok(p) => p,
        Err(e) => return DeferredResult::err(e),
    };

    if !plan.has_cold_slices {
        // Fast path: 100% in-memory (zeros, staged buffers, or decrypted record cache hits)
        return DeferredResult::ready(
            execute_read_plan(plan, fs.log_cache.as_deref(), &fs.volume_key).map(FuseResponse::buf),
        );
    }

    let pool = fs.read_pool.read().unwrap().clone();
    let Some(pool) = pool else {
        // Without an active read threadpool (e.g. in unit tests or standalone tools),
        // execute synchronously on the caller thread.
        return DeferredResult::ready(
            execute_read_plan(plan, fs.log_cache.as_deref(), &fs.volume_key).map(FuseResponse::buf),
        );
    };

    // Cold read offload: dispatch to the dedicated read threadpool
    let (token, receiver) = DeferredToken::new();
    let guard = fs.begin_async_op();
    let log_cache = fs.log_cache.clone();
    let volume_key = fs.volume_key.clone();

    if let Err(e) = pool.spawn(move || {
        let _guard = guard;
        let res = execute_read_plan(plan, log_cache.as_deref(), &volume_key);
        token.complete(res.map(FuseResponse::buf));
    }) {
        return DeferredResult::err(e);
    }

    DeferredResult::deferred(receiver)
}

pub fn open_core(fs: &AppendFs, ino: u64, flags: u32) -> Result<u64, FsError> {
    let write_requested = (flags as i32 & (libc::O_WRONLY | libc::O_RDWR | libc::O_TRUNC | libc::O_APPEND)) != 0;

    if is_virtual_ino(ino) {
        if write_requested {
            return Err(FsError::EACCES);
        }
        // Virtual files generate content outside the inner lock to prevent lock-ordering inversions
        // or self-deadlocks (since status generators query filesystem layer state).
        let content = fs.virtual_files.generate_content(ino, fs).unwrap_or_default();
        fs.with_inner(OpTag::Open, |inner| {
            inner.check_shutdown(write_requested)?;
            let attr = fs.get_attr_locked(inner, ino).ok_or(FsError::ENOENT)?;
            if attr.file_type != FileType::RegularFile {
                return Err(FsError::EISDIR);
            }
            let fh = inner.allocate_fh();
            inner.insert_file_handle(
                fh,
                FileHandle::Virtual {
                    ino,
                    flags,
                    data: Arc::new(content.into_bytes()),
                },
            );
            Ok(fh)
        })
    } else {
        // Regular files: validate, open, and optionally truncate in a single critical section!
        let now = fs.clock.now();
        let trunc = (flags & libc::O_TRUNC as u32) != 0;
        fs.with_inner(OpTag::Open, |inner| {
            inner.check_shutdown(write_requested)?;
            let attr = inner.get_attr(ino).ok_or(FsError::ENOENT)?;
            if attr.file_type != FileType::RegularFile {
                return Err(FsError::EISDIR);
            }
            let fh = inner.allocate_fh();
            inner.insert_file_handle(fh, FileHandle::Regular { ino, flags });
            if trunc {
                let entry = inner
                    .live
                    .entry(ino)
                    .or_insert_with(|| EntryDelta::Node(NodeDelta::File(FileDelta::default())));
                if let EntryDelta::Node(NodeDelta::File(f)) = entry {
                    let mask_len = u64::MAX;
                    f.extents.insert(0, Extent::new_zero(mask_len));
                    f.size = Some(0);
                    f.attr_delta.mtime = Some(now);
                    f.attr_delta.ctime = Some(now);
                }
                inner.record_mutation(0);
            }
            Ok(fh)
        })
    }
}

pub fn open_response(fs: &AppendFs, ino: u64, flags: u32) -> Result<FuseResponse<'static>, FsError> {
    let is_virtual = is_virtual_ino(ino);
    open_core(fs, ino, flags).map(|fh| {
        FuseResponse::open(
            fh,
            /* direct_io = */ is_virtual,
            /* keep_cache = */ !is_virtual,
        )
    })
}

pub fn write_handle_core(fs: &AppendFs, ino: u64, fh: u64, buf: &[u8], offset: i64) -> Result<usize, FsError> {
    log::trace!("write(ino={}, fh={}, len={}, offset={})", ino, fh, buf.len(), offset);
    if is_virtual_ino(ino) {
        return Err(FsError::EPERM);
    }

    if offset < 0 {
        return Err(FsError::EINVAL);
    }

    let now = fs.clock.now();
    let file_offset = offset as u64;
    let write_len = buf.len() as u64;

    fs.with_inner(OpTag::Write, |inner| {
        inner.check_shutdown(true)?;
        inner.validate_regular_handle(ino, fh)?;
        let attr = inner.get_attr(ino).ok_or(FsError::ENOENT)?;
        if attr.file_type != FileType::RegularFile {
            return Err(FsError::EBADF);
        }

        if !inner.live.contains_key(&ino) && !inner.exists_below_live(ino) {
            return Err(FsError::ENOENT);
        }

        let slices = inner.live_arena.append(buf);

        let entry = inner
            .live
            .entry(ino)
            .or_insert_with(|| EntryDelta::Node(NodeDelta::File(FileDelta::default())));
        if let EntryDelta::Node(NodeDelta::File(f)) = entry {
            let mut cur_offset = file_offset;
            for (chunk_data, payload_offset, slice_len) in slices {
                let extent = Extent::new_staged(chunk_data, payload_offset, slice_len);
                f.extents.insert(cur_offset, extent);
                cur_offset += slice_len as u64;
            }
            let current_size = f.size.unwrap_or(attr.size as u64);
            f.size = Some(std::cmp::max(current_size, file_offset + write_len));
            f.attr_delta.mtime = Some(now);
            f.attr_delta.ctime = Some(now);
        }
        inner.record_mutation(write_len as usize);
        Ok(buf.len())
    })
}

pub fn write_response(
    fs: &AppendFs,
    ino: u64,
    fh: u64,
    buf: &[u8],
    offset: i64,
) -> Result<FuseResponse<'static>, FsError> {
    write_handle_core(fs, ino, fh, buf, offset).map(FuseResponse::write)
}

#[allow(clippy::too_many_arguments)]
pub fn setattr_core(
    fs: &AppendFs,
    ino: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    size: i64,
    atime: SystemTime,
    mtime: SystemTime,
    to_set: u32,
) -> Result<FileAttr, FsError> {
    log::trace!(
        "setattr(ino={}, mode=0o{:o}, uid={}, gid={}, size={}, to_set=0x{:x})",
        ino,
        mode,
        uid,
        gid,
        size,
        to_set
    );

    if is_virtual_ino(ino) {
        return Err(FsError::EPERM);
    }

    let now = fs.clock.now();

    let mut attr_delta = AttrDelta::default();

    if (to_set & FUSE_SET_ATTR_MODE) != 0 {
        attr_delta.mode = Some(mode & 0o7777);
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

    fs.with_inner(OpTag::SetAttr, |inner| {
        inner.check_shutdown(true)?;
        let attr = inner.get_attr(ino).ok_or(FsError::ENOENT)?;

        if (to_set & FUSE_SET_ATTR_SIZE) != 0 && attr.file_type == FileType::RegularFile {
            log::trace!("truncating file to {}", size);
            let new_size = size as u64;
            let entry = inner
                .live
                .entry(ino)
                .or_insert_with(|| EntryDelta::Node(NodeDelta::File(FileDelta::default())));
            if let EntryDelta::Node(NodeDelta::File(f)) = entry {
                let mask_len = u64::MAX - new_size;
                f.extents.insert(new_size, Extent::new_zero(mask_len));
                f.size = Some(new_size);
                f.attr_delta.mtime = Some(now);
                f.attr_delta.ctime = Some(now);
            }
        }

        inner.update_attr_delta(ino, attr_delta);
        inner.record_mutation(0);
        inner.get_attr(ino).ok_or(FsError::ENOENT)
    })
}

/// Internal helper: punches a zero hole in `[offset, offset + len)` within an already-locked `FsInner`.
fn punch_hole_locked(
    inner: &mut FsInnerGuard<'_>,
    ino: u64,
    offset: u64,
    len: u64,
    now: SystemTime,
) -> Result<(), FsError> {
    let attr = inner.get_attr(ino).ok_or(FsError::ENOENT)?;
    if attr.file_type != FileType::RegularFile {
        return Err(FsError::EISDIR);
    }

    let file_size = attr.size as u64;
    let end = std::cmp::min(offset.saturating_add(len), file_size);
    if len == 0 || offset >= end {
        return Ok(());
    }

    if !inner.live.contains_key(&ino) && !inner.exists_below_live(ino) {
        return Err(FsError::ENOENT);
    }
    let entry = inner
        .live
        .entry(ino)
        .or_insert_with(|| EntryDelta::Node(NodeDelta::File(FileDelta::default())));
    if let EntryDelta::Node(NodeDelta::File(f)) = entry {
        f.extents.insert(offset, Extent::new_zero(end - offset));
        f.attr_delta.mtime = Some(now);
        f.attr_delta.ctime = Some(now);
    }
    inner.record_mutation(0);
    Ok(())
}

/// Deallocates `[offset, offset + len)`, leaving it reading as zeros without changing the
/// file size - the core of `fallocate(FALLOC_FL_PUNCH_HOLE)`.
///
/// This is truncate's interior-range sibling, and works the same way: rather than removing
/// the range from the live delta's extent map - which would leave the layer with no opinion
/// and let the read fall through to `base`, resurrecting the punched data - it inserts an
/// explicit `ExtentState::Zero` that masks whatever lies below.
pub fn punch_hole_core(fs: &AppendFs, ino: u64, offset: u64, len: u64) -> Result<(), FsError> {
    log::trace!("punch_hole(ino={}, offset={}, len={})", ino, offset, len);
    let now = fs.clock.now();
    fs.with_inner(OpTag::Fallocate, |inner| {
        inner.check_shutdown(true)?;
        punch_hole_locked(inner, ino, offset, len, now)
    })
}

/// Internal helper: raises a file's recorded size to `new_size` within an already-locked `FsInner`.
fn grow_size_locked(inner: &mut FsInnerGuard<'_>, ino: u64, new_size: u64, now: SystemTime) -> Result<(), FsError> {
    let attr = inner.get_attr(ino).ok_or(FsError::ENOENT)?;
    let entry = inner
        .live
        .entry(ino)
        .or_insert_with(|| EntryDelta::Node(NodeDelta::File(FileDelta::default())));
    if let EntryDelta::Node(NodeDelta::File(f)) = entry {
        let current = f.size.unwrap_or(attr.size as u64);
        if new_size > current {
            f.size = Some(new_size);
            f.attr_delta.mtime = Some(now);
            f.attr_delta.ctime = Some(now);
        }
    }
    inner.record_mutation(0);
    Ok(())
}

/// `fallocate(2)`.
///
/// Hole punching and zeroing are the modes that carry real weight here: they are how a
/// caller tells a log-structured filesystem that data is dead, which is what lets
/// compaction reclaim it.
///
/// Plain allocation cannot be honoured literally - there is no space to reserve in an
/// append-only log - so it only extends the file. That is a partial lie, but the honest
/// alternative is worse: glibc's `posix_fallocate` responds to `EOPNOTSUPP` by writing
/// zeros over the whole range by hand, so refusing a 1 GiB preallocation would push 1 GiB
/// of zeros through the write path.
pub fn fallocate_core(fs: &AppendFs, ino: u64, mode: i32, offset: i64, length: i64) -> Result<(), FsError> {
    log::trace!(
        "fallocate(ino={}, mode=0x{:x}, offset={}, length={})",
        ino,
        mode,
        offset,
        length
    );
    if is_virtual_ino(ino) {
        return Err(FsError::EPERM);
    }
    if offset < 0 || length <= 0 {
        return Err(FsError::EINVAL);
    }

    const SUPPORTED: i32 = libc::FALLOC_FL_KEEP_SIZE | libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_ZERO_RANGE;
    if mode & !SUPPORTED != 0 {
        // Notably COLLAPSE_RANGE and INSERT_RANGE, which shift every byte above the range
        // and would mean re-keying every extent above `offset` in every layer - including
        // expressing that shift in a delta relative to `base`. Refusing is spec-legal.
        return Err(FsError::EOPNOTSUPP);
    }

    if mode & libc::FALLOC_FL_PUNCH_HOLE != 0 && mode & libc::FALLOC_FL_KEEP_SIZE == 0 {
        return Err(FsError::EINVAL);
    }

    let start = offset as u64;
    let len = length as u64;
    let end = start.saturating_add(len);
    let now = fs.clock.now();

    fs.with_inner(OpTag::Fallocate, |inner| {
        inner.check_shutdown(true)?;
        let attr = inner.get_attr(ino).ok_or(FsError::ENOENT)?;
        if attr.file_type != FileType::RegularFile {
            return Err(FsError::EISDIR);
        }

        if mode & libc::FALLOC_FL_PUNCH_HOLE != 0 {
            return punch_hole_locked(inner, ino, start, len, now);
        }

        if mode & libc::FALLOC_FL_ZERO_RANGE != 0 {
            punch_hole_locked(inner, ino, start, len, now)?;
            if mode & libc::FALLOC_FL_KEEP_SIZE == 0 {
                grow_size_locked(inner, ino, end, now)?;
            }
            return Ok(());
        }

        if mode & libc::FALLOC_FL_KEEP_SIZE != 0 {
            return Ok(());
        }

        grow_size_locked(inner, ino, end, now)
    })
}

pub fn fallocate_response(
    fs: &AppendFs,
    ino: u64,
    mode: i32,
    offset: i64,
    length: i64,
) -> Result<FuseResponse<'static>, FsError> {
    fallocate_core(fs, ino, mode, offset, length).map(|()| FuseResponse::ok())
}

#[allow(clippy::too_many_arguments)]
pub fn setattr_response(
    fs: &AppendFs,
    ino: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    size: i64,
    atime: SystemTime,
    mtime: SystemTime,
    to_set: u32,
) -> Result<FuseResponse<'static>, FsError> {
    setattr_core(fs, ino, mode, uid, gid, size, atime, mtime, to_set).map(FuseResponse::attr)
}
#[allow(clippy::too_many_arguments)]
fn create_internal(
    fs: &AppendFs,
    parent: u64,
    name: &str,
    mode: u32,
    flags: u32,
    uid: u32,
    gid: u32,
    open_handle: bool,
) -> Result<(FileAttr, Option<u64>), FsError> {
    fs.with_inner(OpTag::Create, |inner| {
        inner.check_shutdown(true)?;
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
            return Err(FsError::ENAMETOOLONG);
        }

        let parent_attr = inner.get_attr(parent).ok_or(FsError::ENOENT)?;
        if parent_attr.file_type != FileType::Directory {
            return Err(FsError::ENOTDIR);
        }

        if fs.lookup_child_locked(inner, parent, name).is_some() {
            return Err(FsError::EEXIST);
        }

        let new_ino = fs.allocate_inode();
        let new_delta = NodeDelta::File(FileDelta {
            extents: ExtentMap::new(),
            size: Some(0),
            attr_delta: AttrDelta {
                mode: Some(mode & 0o7777),
                nlink: Some(1),
                uid: Some(uid),
                gid: Some(gid),
                atime: Some(now),
                mtime: Some(now),
                ctime: Some(now),
                created_at: Some(now),
                xattrs: None,
            },
        });

        inner.insert_new_node(new_ino, new_delta);
        inner.add_dir_entry(parent, name, new_ino, now);
        inner.record_mutation(name.len());

        let fh = if open_handle {
            let fh = inner.allocate_fh();
            inner.insert_file_handle(fh, FileHandle::Regular { ino: new_ino, flags });
            Some(fh)
        } else {
            None
        };

        Ok((
            FileAttr {
                ino: new_ino,
                file_type: FileType::RegularFile,
                perm: mode & 0o7777,
                nlink: 1,
                uid,
                gid,
                rdev: 0,
                size: 0,
                atime: now,
                mtime: now,
                ctime: now,
            },
            fh,
        ))
    })
}

pub fn create_core(
    fs: &AppendFs,
    parent: u64,
    name: &str,
    mode: u32,
    flags: u32,
    uid: u32,
    gid: u32,
) -> Result<FileAttr, FsError> {
    create_internal(fs, parent, name, mode, flags, uid, gid, false).map(|(attr, _)| attr)
}

pub fn create_response(
    fs: &AppendFs,
    ctx: RequestContext,
    parent: u64,
    name: &str,
    mode: u32,
    flags: u32,
) -> Result<FuseResponse<'static>, FsError> {
    create_internal(fs, parent, name, mode, flags, ctx.uid, ctx.gid, true)
        .map(|(attr, fh)| FuseResponse::create(attr, fh.unwrap()))
}

pub struct FsyncDeferred(pub crate::fs::BatchCompletion);

impl DeferredCompletion<FuseResponse<'static>> for FsyncDeferred {
    fn on_complete(
        self: Box<Self>,
        callback: Box<dyn FnOnce(Result<FuseResponse<'static>, FsError>) + Send + 'static>,
    ) {
        self.0.add_callback(Box::new(move |result| {
            let res = result.map(|()| FuseResponse::ok()).map_err(FsError::from);
            callback(res);
        }));
    }
}

pub fn fsync_response(fs: &AppendFs, ino: u64, fh: u64, reason: FlushReason) -> DeferredResult<FuseResponse<'static>> {
    let completion = match fs.rollover_for_fsync(ino, fh, reason) {
        Ok(c) => c,
        Err(e) => return DeferredResult::err(e),
    };

    let Some(completion) = completion else {
        return DeferredResult::ok_void();
    };

    fs.wake_flusher();
    DeferredResult::deferred(FsyncDeferred(completion))
}

pub fn release_core(fs: &AppendFs, ino: u64, fh: u64) -> Result<(), FsError> {
    fs.release_file_handle(fh, ino)
}

pub fn release_response(fs: &AppendFs, ino: u64, fh: u64) -> Result<FuseResponse<'static>, FsError> {
    release_core(fs, ino, fh).map(|()| FuseResponse::ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::AppendFs;
    use crate::test_utils::FsTestExt;
    use crate::test_utils::TestFs;
    use crate::{Storage, SystemClock};

    fn file_with(fs: &AppendFs, contents: &[u8]) -> u64 {
        let attr = create_core(fs, 1, "f.bin", 0o644, 0, 1000, 1000).unwrap();
        fs.write_at(attr.ino, contents, 0).unwrap();
        attr.ino
    }

    #[test]
    fn test_fallocate_mode_dispatch() {
        let fs = TestFs::builder().build().fs;
        let ino = file_with(&fs, &[0xAB; 512]);

        // Modes that shift file contents are refused outright. Silently ignoring the flag
        // and allocating instead would leave the caller's data at the wrong offsets.
        for mode in [libc::FALLOC_FL_COLLAPSE_RANGE, libc::FALLOC_FL_INSERT_RANGE] {
            assert_eq!(fallocate_core(&fs, ino, mode, 0, 128), Err(FsError::EOPNOTSUPP));
        }

        // `vfs_fallocate` screens this pairing before FUSE sees it, but the check still has
        // to hold for direct callers.
        assert_eq!(
            fallocate_core(&fs, ino, libc::FALLOC_FL_PUNCH_HOLE, 0, 128),
            Err(FsError::EINVAL)
        );

        assert_eq!(fallocate_core(&fs, ino, 0, -1, 128), Err(FsError::EINVAL));
        assert_eq!(fallocate_core(&fs, ino, 0, 0, 0), Err(FsError::EINVAL));

        // KEEP_SIZE alone has nothing to reserve, so it must leave the file untouched.
        assert_eq!(fallocate_core(&fs, ino, libc::FALLOC_FL_KEEP_SIZE, 0, 4096), Ok(()));
        assert_eq!(fs.get_attr(ino).unwrap().size, 512);

        // Plain allocation extends, and the new range reads as zeros.
        assert_eq!(fallocate_core(&fs, ino, 0, 512, 512), Ok(()));
        assert_eq!(fs.get_attr(ino).unwrap().size, 1024);
        let data = fs.read_file_data(ino, 0, 1024).unwrap();
        assert_eq!(&data[..512], &[0xAB; 512]);
        assert!(data[512..].iter().all(|&b| b == 0));

        // ...but allocating within the existing size must never shrink it.
        assert_eq!(fallocate_core(&fs, ino, 0, 0, 16), Ok(()));
        assert_eq!(fs.get_attr(ino).unwrap().size, 1024);
    }

    #[test]
    fn test_fallocate_zero_range_honours_keep_size() {
        // Without KEEP_SIZE, zeroing past EOF grows the file.
        let fs = TestFs::builder().build().fs;
        let ino = file_with(&fs, &[0xCD; 512]);
        fallocate_core(&fs, ino, libc::FALLOC_FL_ZERO_RANGE, 256, 512).unwrap();
        assert_eq!(fs.get_attr(ino).unwrap().size, 768);
        let data = fs.read_file_data(ino, 0, 768).unwrap();
        assert_eq!(&data[..256], &[0xCD; 256]);
        assert!(data[256..].iter().all(|&b| b == 0));

        // With KEEP_SIZE it zeroes the live part without extending.
        let fs2 = TestFs::builder().build().fs;
        let ino2 = file_with(&fs2, &[0xCD; 512]);
        fallocate_core(
            &fs2,
            ino2,
            libc::FALLOC_FL_ZERO_RANGE | libc::FALLOC_FL_KEEP_SIZE,
            256,
            512,
        )
        .unwrap();
        assert_eq!(
            fs2.get_attr(ino2).unwrap().size,
            512,
            "KEEP_SIZE must suppress the extension"
        );
        let data2 = fs2.read_file_data(ino2, 0, 512).unwrap();
        assert_eq!(&data2[..256], &[0xCD; 256]);
        assert!(data2[256..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_fallocate_rejected_on_read_only_mount() {
        let fs = TestFs::builder().build().fs;
        let ino = file_with(&fs, &[0xEF; 128]);
        fs.set_read_only();
        assert_eq!(
            fallocate_core(&fs, ino, libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE, 0, 64),
            Err(FsError::EROFS)
        );
        assert_eq!(punch_hole_core(&fs, ino, 0, 64), Err(FsError::EROFS));
    }

    #[test]
    fn test_setattr_and_fallocate_single_lock_acquisition() {
        let fs = TestFs::builder().build().fs;
        let ino = file_with(&fs, &[0xAA; 1024]);

        // 1. setattr_core: mode and size change
        let pre_stats = fs.inner.op_stats();
        let pre_setattr = pre_stats.iter().find(|s| s.tag == OpTag::SetAttr).unwrap().count;
        let pre_getattr = pre_stats.iter().find(|s| s.tag == OpTag::GetAttr).unwrap().count;
        let pre_total = fs.inner.lock_count();

        let updated = setattr_core(
            &fs,
            ino,
            0o755,
            1001,
            1002,
            512,
            SystemTime::UNIX_EPOCH,
            SystemTime::UNIX_EPOCH,
            FUSE_SET_ATTR_MODE | FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID | FUSE_SET_ATTR_SIZE,
        )
        .unwrap();
        assert_eq!(updated.size, 512);
        assert_eq!(updated.perm, 0o755);

        let post_stats = fs.inner.op_stats();
        let post_setattr = post_stats.iter().find(|s| s.tag == OpTag::SetAttr).unwrap().count;
        let post_getattr = post_stats.iter().find(|s| s.tag == OpTag::GetAttr).unwrap().count;
        let post_total = fs.inner.lock_count();

        // Exactly 1 lock acquisition tagged OpTag::SetAttr, 0 GetAttr
        assert_eq!(post_setattr - pre_setattr, 1);
        assert_eq!(post_getattr - pre_getattr, 0);
        assert_eq!(post_total - pre_total, 1);

        // 2. punch_hole_core
        let pre_stats = fs.inner.op_stats();
        let pre_fallocate = pre_stats.iter().find(|s| s.tag == OpTag::Fallocate).unwrap().count;
        let pre_total = fs.inner.lock_count();

        punch_hole_core(&fs, ino, 100, 50).unwrap();

        let post_stats = fs.inner.op_stats();
        let post_fallocate = post_stats.iter().find(|s| s.tag == OpTag::Fallocate).unwrap().count;
        let post_total = fs.inner.lock_count();

        assert_eq!(post_fallocate - pre_fallocate, 1);
        assert_eq!(post_total - pre_total, 1);

        // 3. fallocate_core with ZERO_RANGE (zeroing + extending file)
        let pre_stats = fs.inner.op_stats();
        let pre_fallocate = pre_stats.iter().find(|s| s.tag == OpTag::Fallocate).unwrap().count;
        let pre_total = fs.inner.lock_count();

        fallocate_core(&fs, ino, libc::FALLOC_FL_ZERO_RANGE, 400, 300).unwrap();

        let post_stats = fs.inner.op_stats();
        let post_fallocate = post_stats.iter().find(|s| s.tag == OpTag::Fallocate).unwrap().count;
        let post_total = fs.inner.lock_count();

        // Exactly 1 lock acquisition tagged OpTag::Fallocate
        assert_eq!(post_fallocate - pre_fallocate, 1);
        assert_eq!(post_total - pre_total, 1);
        assert_eq!(fs.get_attr(ino).unwrap().size, 700);
    }

    #[test]
    fn test_fsync_single_lock_acquisition() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = Arc::new(SystemClock);
        let fs = TestFs::builder()
            .storage(storage.clone())
            .clock(clock.clone())
            .build()
            .fs;
        let file = create_core(&fs, 1, "fsync_lock.bin", 0o644, 0, 1000, 1000).unwrap();
        let fh = open_core(&fs, file.ino, libc::O_RDWR as u32).unwrap();
        fs.write_at(file.ino, b"test", 0).unwrap();

        let pre_total = fs.inner.lock_count();
        let pre_stats = fs.inner.op_stats();
        let pre_flush = pre_stats.iter().find(|s| s.tag == OpTag::Flush).unwrap().count;

        // Call the fsync rollover with open file handle fh
        let res = fs.rollover_for_fsync(file.ino, fh, FlushReason::Fsync);
        assert!(res.is_ok());

        let post_total = fs.inner.lock_count();
        let post_stats = fs.inner.op_stats();
        let post_flush = post_stats.iter().find(|s| s.tag == OpTag::Flush).unwrap().count;

        // Exactly 1 lock acquisition performed for both handle validation and live rollover
        assert_eq!(post_total - pre_total, 1);
        assert_eq!(post_flush - pre_flush, 1);
    }

    #[test]
    fn test_fsync_and_fsyncdir() {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = Arc::new(SystemClock);
        let fs = TestFs::builder()
            .storage(storage.clone())
            .clock(clock.clone())
            .build()
            .fs;
        let file = create_core(&fs, 1, "fsync.bin", 0o644, 0, 1000, 1000).unwrap();
        let fh = open_core(&fs, file.ino, libc::O_RDWR as u32).unwrap();
        fs.write_at(file.ino, b"fsync test", 0).unwrap();

        let res = fs.fsync_blocking(file.ino, fh);
        assert_eq!(res, Ok(()));

        let dir_res = fs.fsyncdir_blocking(1);
        assert_eq!(dir_res, Ok(()));
    }

    #[test]
    fn test_file_create_name_length_boundaries() {
        let fs = TestFs::builder().build().fs;

        // 255-byte name should succeed for create
        let name_255 = "f".repeat(255);
        let attr_255 = create_core(&fs, 1, &name_255, 0o644, 0, 1000, 1000).unwrap();
        assert_eq!(attr_255.file_type, FileType::RegularFile);

        // 256-byte name should fail with ENAMETOOLONG
        let name_256 = "f".repeat(256);
        assert_eq!(
            create_core(&fs, 1, &name_256, 0o644, 0, 1000, 1000),
            Err(FsError::ENAMETOOLONG)
        );
    }
}
