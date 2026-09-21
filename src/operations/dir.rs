use crate::error::FsError;
#[cfg(any(test, feature = "testing"))]
use crate::fs::find_parent_inode;
use crate::fs::{DirHandle, InMemoryFS};
use crate::node::{AttrDelta, DirectoryDelta, NodeDelta};
use crate::shim::{DeferredResult, DirEntry, DirEntryPlus, FileAttr, FileType, FuseResponse, RequestContext};
use crate::sync::OpTag;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

pub fn lookup_core(fs: &InMemoryFS, parent: u64, name: &str) -> Result<FileAttr, FsError> {
    log::trace!("lookup(parent={}, name={})", parent, name);
    if name.len() > 255 {
        return Err(FsError::ENAMETOOLONG);
    }
    let inner = fs.inner.lock(OpTag::Lookup).unwrap();
    inner.check_shutdown(false)?;
    let parent_attr = fs.get_attr_locked(&inner, parent).ok_or(FsError::ENOENT)?;
    if parent_attr.file_type != FileType::Directory {
        return Err(FsError::ENOTDIR);
    }

    if name == "." {
        return Ok(parent_attr);
    }
    if name == ".." {
        let dotdot_ino = if parent == 1 {
            1
        } else {
            inner.get_parent_dir_inode(parent).unwrap_or(1)
        };
        return fs.get_attr_locked(&inner, dotdot_ino).ok_or(FsError::ENOENT);
    }

    let child_ino = fs.lookup_child_locked(&inner, parent, name).ok_or(FsError::ENOENT)?;
    fs.get_attr_locked(&inner, child_ino).ok_or(FsError::ENOENT)
}

pub fn lookup_response(fs: &InMemoryFS, parent: u64, name: &str) -> Result<FuseResponse<'static>, FsError> {
    lookup_core(fs, parent, name).map(FuseResponse::entry)
}

pub fn list_dir_core(fs: &InMemoryFS, ino: u64) -> Result<Vec<(String, u64)>, FsError> {
    let inner = fs.inner.lock(OpTag::ReadDir).unwrap();
    inner.check_shutdown(false)?;
    let attr = fs.get_attr_locked(&inner, ino).ok_or(FsError::ENOENT)?;
    if attr.file_type != FileType::Directory {
        return Err(FsError::ENOTDIR);
    }
    let mut entries = inner.list_directory(ino).ok_or(FsError::ENOENT)?;
    drop(inner);
    if ino == 1 {
        let mut map: BTreeMap<String, u64> = entries.into_iter().collect();
        for (name, v_ino) in fs.list_virtual_entries() {
            map.entry(name).or_insert(v_ino);
        }
        entries = map.into_iter().collect();
    }
    Ok(entries)
}

fn iter_dir_items(
    ino: u64,
    dotdot_ino: u64,
    entries: &[(String, u64)],
    offset: i64,
) -> impl Iterator<Item = (&str, u64, i64)> {
    let offset = offset as usize;
    let dot = (offset == 0).then_some((".", ino, 1));
    let dotdot = (offset <= 1).then_some(("..", dotdot_ino, 2));
    let start_entry_idx = offset.saturating_sub(2);
    let rest = entries
        .iter()
        .enumerate()
        .skip(start_entry_idx)
        .map(|(idx, (name, child_ino))| (name.as_str(), *child_ino, (idx + 3) as i64));

    dot.into_iter().chain(dotdot).chain(rest)
}

#[cfg(any(test, feature = "testing"))]
pub struct DirItem<'a> {
    pub name: &'a str,
    pub ino: u64,
    pub next_offset: i64,
}

#[cfg(any(test, feature = "testing"))]
pub fn iter_dir_entries_with_parent<'a>(
    ino: u64,
    dotdot_ino: u64,
    entries: &'a [(String, u64)],
    offset: i64,
) -> impl Iterator<Item = DirItem<'a>> {
    iter_dir_items(ino, dotdot_ino, entries, offset).map(|(name, ino, next_offset)| DirItem { name, ino, next_offset })
}

#[cfg(any(test, feature = "testing"))]
pub fn iter_dir_entries<'a>(
    fs: &InMemoryFS,
    ino: u64,
    entries: &'a [(String, u64)],
    offset: i64,
) -> impl Iterator<Item = DirItem<'a>> {
    let dotdot_ino = if ino == 1 {
        1
    } else {
        find_parent_inode(fs, ino).unwrap_or(1)
    };
    iter_dir_entries_with_parent(ino, dotdot_ino, entries, offset)
}

pub fn opendir_core(fs: &InMemoryFS, ino: u64, flags: u32) -> Result<u64, FsError> {
    fs.with_inner(OpTag::OpenDir, |inner| {
        inner.check_shutdown(false)?;
        let attr = fs.get_attr_locked(inner, ino).ok_or(FsError::ENOENT)?;
        if attr.file_type != FileType::Directory {
            return Err(FsError::ENOTDIR);
        }
        let mut entries = inner.list_directory(ino).ok_or(FsError::ENOENT)?;
        if ino == 1 {
            let mut map: BTreeMap<String, u64> = entries.into_iter().collect();
            for (name, v_ino) in fs.list_virtual_entries() {
                map.entry(name).or_insert(v_ino);
            }
            entries = map.into_iter().collect();
        }
        let fh = inner.allocate_fh();
        inner.insert_dir_handle(
            fh,
            DirHandle {
                ino,
                flags,
                entries: Arc::new(entries),
            },
        );
        Ok(fh)
    })
}

pub fn opendir_response(fs: &InMemoryFS, ino: u64, flags: u32) -> Result<FuseResponse<'static>, FsError> {
    opendir_core(fs, ino, flags)
        .map(|fh| FuseResponse::open(fh, /* direct_io = */ false, /* keep_cache = */ false))
}

pub fn readdir_entries(
    fs: &InMemoryFS,
    ino: u64,
    _size: usize,
    offset: i64,
    fh: u64,
) -> Result<Vec<DirEntry>, FsError> {
    log::trace!("readdir(ino={}, offset={}, fh={})", ino, offset, fh);
    fs.with_inner(OpTag::ReadDir, |inner| {
        inner.check_shutdown(false)?;
        let dir = inner.get_dir_handle(ino, fh)?;
        let parent_ino = if ino == 1 {
            1
        } else {
            inner.get_parent_dir_inode(ino).unwrap_or(1)
        };
        let mut items = Vec::new();
        for (name, item_ino, next_offset) in iter_dir_items(ino, parent_ino, &dir.entries, offset) {
            if let Some(attr) = fs.get_attr_locked(inner, item_ino) {
                items.push(DirEntry {
                    ino: item_ino,
                    offset: next_offset,
                    file_type: attr.file_type,
                    name: name.to_string(),
                });
            }
        }
        Ok(items)
    })
}

pub fn readdirplus_entries(
    fs: &InMemoryFS,
    ino: u64,
    _size: usize,
    offset: i64,
    fh: u64,
) -> Result<Vec<DirEntryPlus>, FsError> {
    log::trace!("readdirplus(ino={}, offset={}, fh={})", ino, offset, fh);
    fs.with_inner(OpTag::ReadDir, |inner| {
        inner.check_shutdown(false)?;
        let dir = inner.get_dir_handle(ino, fh)?;
        let parent_ino = if ino == 1 {
            1
        } else {
            inner.get_parent_dir_inode(ino).unwrap_or(1)
        };
        let mut items = Vec::new();
        for (name, item_ino, next_offset) in iter_dir_items(ino, parent_ino, &dir.entries, offset) {
            if let Some(attr) = fs.get_attr_locked(inner, item_ino) {
                items.push(DirEntryPlus {
                    ino: item_ino,
                    offset: next_offset,
                    name: name.to_string(),
                    attr,
                });
            }
        }
        Ok(items)
    })
}

pub fn readdir_response(
    fs: &InMemoryFS,
    ino: u64,
    size: usize,
    offset: i64,
    fh: u64,
) -> Result<FuseResponse<'static>, FsError> {
    readdir_entries(fs, ino, size, offset, fh).map(|entries| FuseResponse::readdir(entries, size))
}

pub fn readdirplus_response(
    fs: &InMemoryFS,
    ino: u64,
    size: usize,
    offset: i64,
    fh: u64,
) -> Result<FuseResponse<'static>, FsError> {
    readdirplus_entries(fs, ino, size, offset, fh).map(|entries| FuseResponse::readdirplus(entries, size))
}

pub fn mkdir_core(
    fs: &InMemoryFS,
    parent: u64,
    name: &str,
    mode: u32,
    uid: u32,
    gid: u32,
) -> Result<FileAttr, FsError> {
    fs.with_inner(OpTag::Mkdir, |inner| {
        inner.check_shutdown(true)?;
        let now = fs.clock.now();
        log::trace!(
            "mkdir(parent={}, name={}, mode=0o{:o}, uid={}, gid={})",
            parent,
            name,
            mode,
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
        let new_delta = NodeDelta::Directory(DirectoryDelta {
            parent: Some(parent),
            added: HashMap::new(),
            removed: std::collections::HashSet::new(),
            attr_delta: AttrDelta {
                mode: Some(mode & 0o7777),
                nlink: Some(2),
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
        inner.update_attr_delta(
            parent,
            AttrDelta {
                nlink: Some(parent_attr.nlink + 1),
                ctime: Some(now),
                ..Default::default()
            },
        );
        inner.record_mutation(name.len());

        Ok(FileAttr {
            ino: new_ino,
            file_type: FileType::Directory,
            perm: mode & 0o7777,
            nlink: 2,
            uid,
            gid,
            rdev: 0,
            size: 0,
            atime: now,
            mtime: now,
            ctime: now,
        })
    })
}

pub fn mkdir_response(
    fs: &InMemoryFS,
    ctx: RequestContext,
    parent: u64,
    name: &str,
    mode: u32,
) -> Result<FuseResponse<'static>, FsError> {
    mkdir_core(fs, parent, name, mode, ctx.uid, ctx.gid).map(FuseResponse::entry)
}

pub fn rmdir_core(fs: &InMemoryFS, parent: u64, name: &str) -> Result<(), FsError> {
    fs.with_inner(OpTag::Rmdir, |inner| {
        inner.check_shutdown(true)?;
        let now = fs.clock.now();
        log::trace!("rmdir(parent={}, name={})", parent, name);

        if name.len() > 255 {
            return Err(FsError::ENAMETOOLONG);
        }

        let parent_attr = inner.get_attr(parent).ok_or(FsError::ENOENT)?;
        if parent_attr.file_type != FileType::Directory {
            return Err(FsError::ENOTDIR);
        }

        let child_ino = fs.lookup_child_locked(inner, parent, name).ok_or(FsError::ENOENT)?;
        let child_attr = fs.get_attr_locked(inner, child_ino).ok_or(FsError::ENOENT)?;
        if child_attr.file_type != FileType::Directory {
            return Err(FsError::ENOTDIR);
        }

        let entries = inner.list_directory(child_ino).ok_or(FsError::ENOENT)?;
        if !entries.is_empty() {
            return Err(FsError::ENOTEMPTY);
        }

        inner.remove_dir_entry(parent, name, now);
        inner.update_attr_delta(
            parent,
            AttrDelta {
                nlink: Some(parent_attr.nlink.saturating_sub(1)),
                ctime: Some(now),
                ..Default::default()
            },
        );
        inner.tombstone(child_ino);
        inner.record_mutation(name.len());
        Ok(())
    })
}

pub fn rmdir_response(fs: &InMemoryFS, parent: u64, name: &str) -> Result<FuseResponse<'static>, FsError> {
    rmdir_core(fs, parent, name).map(|()| FuseResponse::ok())
}

pub fn releasedir_core(fs: &InMemoryFS, ino: u64, fh: u64) -> Result<(), FsError> {
    fs.release_dir_handle(fh, ino)
}

pub fn releasedir_response(fs: &InMemoryFS, ino: u64, fh: u64) -> Result<FuseResponse<'static>, FsError> {
    releasedir_core(fs, ino, fh).map(|()| FuseResponse::ok())
}

#[cfg(any(test, feature = "testing"))]
pub async fn fsyncdir_core(fs: &InMemoryFS) -> Result<(), FsError> {
    crate::operations::read_write::fsync_core_with_reason(fs, 0, 0, crate::fs::FlushReason::Fsyncdir).await
}

pub fn fsyncdir_response(fs: &InMemoryFS, ino: u64, datasync: bool) -> DeferredResult<FuseResponse<'static>> {
    log::trace!("fsyncdir(ino={}, datasync={})", ino, datasync);
    crate::operations::read_write::fsync_response(fs, 0, 0, crate::fs::FlushReason::Fsyncdir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_directory_nlink_tracking_across_mkdir_rmdir_and_rename() {
        let fs = InMemoryFS::new();
        // Initial root (inode 1) starts with nlink 2
        assert_eq!(fs.get_attr(1).unwrap().nlink, 2);

        // 1. mkdir "d1" in root -> root nlink becomes 3, d1 has nlink 2
        let d1 = mkdir_core(&fs, 1, "d1", 0o755, 1000, 1000).unwrap();
        assert_eq!(d1.nlink, 2);
        assert_eq!(fs.get_attr(1).unwrap().nlink, 3);

        // 2. mkdir "d2" in root -> root nlink becomes 4, d2 has nlink 2
        let d2 = mkdir_core(&fs, 1, "d2", 0o755, 1000, 1000).unwrap();
        assert_eq!(d2.nlink, 2);
        assert_eq!(fs.get_attr(1).unwrap().nlink, 4);

        // 3. mkdir "sub" inside "d1" -> d1 nlink becomes 3, sub has nlink 2
        let sub = mkdir_core(&fs, d1.ino, "sub", 0o755, 1000, 1000).unwrap();
        assert_eq!(sub.nlink, 2);
        assert_eq!(fs.get_attr(d1.ino).unwrap().nlink, 3);

        // 4. Move "sub" from "d1" to "d2" -> d1 drops to 2, d2 increases to 3
        crate::operations::links::rename_core(&fs, d1.ino, "sub", d2.ino, "sub").unwrap();
        assert_eq!(fs.get_attr(d1.ino).unwrap().nlink, 2);
        assert_eq!(fs.get_attr(d2.ino).unwrap().nlink, 3);
        assert_eq!(fs.get_attr(sub.ino).unwrap().nlink, 2);

        // 5. rmdir "sub" from "d2" -> d2 drops back to 2
        rmdir_core(&fs, d2.ino, "sub").unwrap();
        assert_eq!(fs.get_attr(d2.ino).unwrap().nlink, 2);

        // 6. rmdir "d1" from root -> root drops to 3
        rmdir_core(&fs, 1, "d1").unwrap();
        assert_eq!(fs.get_attr(1).unwrap().nlink, 3);

        // 7. rmdir "d2" from root -> root drops to 2
        rmdir_core(&fs, 1, "d2").unwrap();
        assert_eq!(fs.get_attr(1).unwrap().nlink, 2);
    }

    #[test]
    fn test_lookup_core_single_lock_acquisition_tagged_lookup() {
        let fs = InMemoryFS::new();
        let file = crate::operations::read_write::create_core(&fs, 1, "test.txt", 0o644, 0, 1000, 1000).unwrap();

        let pre_stats = fs.inner.op_stats();
        let pre_lookup = pre_stats.iter().find(|s| s.tag == OpTag::Lookup).unwrap().count;
        let pre_getattr = pre_stats.iter().find(|s| s.tag == OpTag::GetAttr).unwrap().count;
        let pre_total = fs.inner.lock_count();

        let attr = lookup_core(&fs, 1, "test.txt").unwrap();
        assert_eq!(attr.ino, file.ino);

        let post_stats = fs.inner.op_stats();
        let post_lookup = post_stats.iter().find(|s| s.tag == OpTag::Lookup).unwrap().count;
        let post_getattr = post_stats.iter().find(|s| s.tag == OpTag::GetAttr).unwrap().count;
        let post_total = fs.inner.lock_count();

        // Exactly 1 lock acquisition, tagged OpTag::Lookup
        assert_eq!(post_lookup - pre_lookup, 1);
        assert_eq!(post_getattr - pre_getattr, 0);
        assert_eq!(post_total - pre_total, 1);

        // Test "." and ".."
        let dot_attr = lookup_core(&fs, 1, ".").unwrap();
        assert_eq!(dot_attr.ino, 1);
        let dotdot_attr = lookup_core(&fs, 1, "..").unwrap();
        assert_eq!(dotdot_attr.ino, 1);

        // Test virtual file lookup
        let v_attr = lookup_core(&fs, 1, ".status").unwrap();
        assert_eq!(v_attr.ino, fs.lookup_child(1, ".status").unwrap());
    }

    #[test]
    fn test_list_dir_core_single_lock_acquisition_tagged_readdir() {
        let fs = InMemoryFS::new();
        let _ = mkdir_core(&fs, 1, "sub1", 0o755, 1000, 1000).unwrap();

        let pre_stats = fs.inner.op_stats();
        let pre_readdir = pre_stats.iter().find(|s| s.tag == OpTag::ReadDir).unwrap().count;
        let pre_getattr = pre_stats.iter().find(|s| s.tag == OpTag::GetAttr).unwrap().count;
        let pre_total = fs.inner.lock_count();

        let entries = list_dir_core(&fs, 1).unwrap();
        assert!(entries.iter().any(|(name, _)| name == "sub1"));
        assert!(entries.iter().any(|(name, _)| name == ".status"));

        let post_stats = fs.inner.op_stats();
        let post_readdir = post_stats.iter().find(|s| s.tag == OpTag::ReadDir).unwrap().count;
        let post_getattr = post_stats.iter().find(|s| s.tag == OpTag::GetAttr).unwrap().count;
        let post_total = fs.inner.lock_count();

        // Exactly 1 lock acquisition, tagged OpTag::ReadDir
        assert_eq!(post_readdir - pre_readdir, 1);
        assert_eq!(post_getattr - pre_getattr, 0);
        assert_eq!(post_total - pre_total, 1);
    }

    #[test]
    fn test_directory_name_length_boundaries() {
        let fs = InMemoryFS::new();

        // 255-byte name should succeed for mkdir
        let name_255 = "d".repeat(255);
        let attr_255 = mkdir_core(&fs, 1, &name_255, 0o755, 1000, 1000).unwrap();
        assert_eq!(attr_255.file_type, FileType::Directory);

        // lookup_core should find it
        let looked_up = lookup_core(&fs, 1, &name_255).unwrap();
        assert_eq!(looked_up.ino, attr_255.ino);

        // 256-byte name should fail with ENAMETOOLONG
        let name_256 = "d".repeat(256);
        assert_eq!(
            mkdir_core(&fs, 1, &name_256, 0o755, 1000, 1000),
            Err(FsError::ENAMETOOLONG)
        );
        assert_eq!(lookup_core(&fs, 1, &name_256), Err(FsError::ENAMETOOLONG));

        // rmdir_core with 256-byte name should return ENAMETOOLONG
        assert_eq!(rmdir_core(&fs, 1, &name_256), Err(FsError::ENAMETOOLONG));

        // rmdir_core with 255-byte name should succeed
        assert_eq!(rmdir_core(&fs, 1, &name_255), Ok(()));
        assert_eq!(lookup_core(&fs, 1, &name_255), Err(FsError::ENOENT));
    }
}
