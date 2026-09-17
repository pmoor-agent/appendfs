use crate::error::FsError;
use crate::extent_map::ExtentMap;
use crate::fs::InMemoryFS;
use crate::node::{AttrDelta, FileDelta, NodeDelta, SpecialDelta};
use crate::shim::{FileAttr, FileType, FuseResponse, RequestContext};
use crate::sync::OpTag;

pub fn mknod_core(
    fs: &InMemoryFS,
    parent: u64,
    name: &str,
    mode: u32,
    rdev: u32,
    uid: u32,
    gid: u32,
) -> Result<FileAttr, FsError> {
    if fs.is_read_only() {
        return Err(FsError::EROFS);
    }

    fs.with_inner(OpTag::Mknod, |inner| {
        let now = fs.clock.now();
        log::trace!(
            "mknod(parent={}, name={}, mode=0o{:o}, rdev={}, uid={}, gid={})",
            parent,
            name,
            mode,
            rdev,
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

        let file_type_bits = mode & libc::S_IFMT;
        let perm = mode & 0o7777;
        let new_ino = fs.allocate_inode();

        let attr_delta = AttrDelta {
            mode: Some(perm),
            nlink: Some(1),
            uid: Some(uid),
            gid: Some(gid),
            atime: Some(now),
            mtime: Some(now),
            ctime: Some(now),
            created_at: Some(now),
            xattrs: None,
        };

        let (new_delta, file_type, actual_rdev) = match file_type_bits {
            libc::S_IFIFO => (
                NodeDelta::Fifo(SpecialDelta { rdev: 0, attr_delta }),
                FileType::NamedPipe,
                0,
            ),
            libc::S_IFCHR => (
                NodeDelta::CharDevice(SpecialDelta { rdev, attr_delta }),
                FileType::CharDevice,
                rdev,
            ),
            libc::S_IFBLK => (
                NodeDelta::BlockDevice(SpecialDelta { rdev, attr_delta }),
                FileType::BlockDevice,
                rdev,
            ),
            libc::S_IFSOCK => (
                NodeDelta::Socket(SpecialDelta { rdev: 0, attr_delta }),
                FileType::Socket,
                0,
            ),
            _ => (
                NodeDelta::File(FileDelta {
                    extents: ExtentMap::new(),
                    size: Some(0),
                    attr_delta,
                }),
                FileType::RegularFile,
                0,
            ),
        };

        inner.insert_new_node(new_ino, new_delta);
        inner.add_dir_entry(parent, name, new_ino, now);
        inner.record_mutation(name.len());

        Ok(FileAttr {
            ino: new_ino,
            file_type,
            perm,
            nlink: 1,
            uid,
            gid,
            rdev: actual_rdev,
            size: 0,
            atime: now,
            mtime: now,
            ctime: now,
        })
    })
}

pub fn mknod_response(
    fs: &InMemoryFS,
    ctx: RequestContext,
    parent: u64,
    name: &str,
    mode: u32,
    rdev: u32,
) -> Result<FuseResponse<'static>, FsError> {
    mknod_core(fs, parent, name, mode, rdev, ctx.uid, ctx.gid).map(FuseResponse::entry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::SystemClock;
    use std::sync::Arc;

    #[test]
    fn test_mknod_special_file_types() {
        let fs = InMemoryFS::with_clock(Arc::new(SystemClock));

        // 1. Create a FIFO
        let fifo_attr = mknod_core(&fs, 1, "test_fifo", libc::S_IFIFO | 0o644, 0, 1000, 1000).unwrap();
        assert_eq!(fifo_attr.file_type, FileType::NamedPipe);
        assert_eq!(fifo_attr.perm, 0o644);
        assert_eq!(fifo_attr.rdev, 0);

        // 2. Create a Character Device
        let chr_attr = mknod_core(&fs, 1, "test_chr", libc::S_IFCHR | 0o660, 0x1234, 1000, 1000).unwrap();
        assert_eq!(chr_attr.file_type, FileType::CharDevice);
        assert_eq!(chr_attr.perm, 0o660);
        assert_eq!(chr_attr.rdev, 0x1234);

        // 3. Create a Block Device
        let blk_attr = mknod_core(&fs, 1, "test_blk", libc::S_IFBLK | 0o660, 0x5678, 1000, 1000).unwrap();
        assert_eq!(blk_attr.file_type, FileType::BlockDevice);
        assert_eq!(blk_attr.perm, 0o660);
        assert_eq!(blk_attr.rdev, 0x5678);

        // 4. Create a Socket
        let sock_attr = mknod_core(&fs, 1, "test_sock", libc::S_IFSOCK | 0o777, 0, 1000, 1000).unwrap();
        assert_eq!(sock_attr.file_type, FileType::Socket);
        assert_eq!(sock_attr.perm, 0o777);
        assert_eq!(sock_attr.rdev, 0);

        // 5. Lookups verify attributes persist across get_attr
        let queried_fifo = fs.get_attr(fifo_attr.ino).unwrap();
        assert_eq!(queried_fifo.file_type, FileType::NamedPipe);

        let queried_chr = fs.get_attr(chr_attr.ino).unwrap();
        assert_eq!(queried_chr.file_type, FileType::CharDevice);
        assert_eq!(queried_chr.rdev, 0x1234);

        let queried_blk = fs.get_attr(blk_attr.ino).unwrap();
        assert_eq!(queried_blk.file_type, FileType::BlockDevice);
        assert_eq!(queried_blk.rdev, 0x5678);

        let queried_sock = fs.get_attr(sock_attr.ino).unwrap();
        assert_eq!(queried_sock.file_type, FileType::Socket);
    }

    #[test]
    fn test_mknod_name_length_boundaries() {
        let fs = InMemoryFS::new();

        let name_255 = "p".repeat(255);
        let name_256 = "p".repeat(256);

        // 255-byte FIFO succeeds
        let fifo_attr = mknod_core(&fs, 1, &name_255, libc::S_IFIFO | 0o644, 0, 1000, 1000).unwrap();
        assert_eq!(fifo_attr.file_type, FileType::NamedPipe);

        // 256-byte FIFO fails with ENAMETOOLONG
        assert_eq!(
            mknod_core(&fs, 1, &name_256, libc::S_IFIFO | 0o644, 0, 1000, 1000),
            Err(FsError::ENAMETOOLONG)
        );
    }
}
