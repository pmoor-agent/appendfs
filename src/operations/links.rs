use crate::fs::InMemoryFS;
use crate::node::{AttrDelta, NodeDelta, SymlinkDelta};
use crate::shim::{FileAttr, FileType, Request};
use crate::sync::OpTag;

pub fn unlink_core(fs: &InMemoryFS, parent: u64, name: &str) -> Result<(), i32> {
    if fs.is_read_only() {
        return Err(libc::EROFS);
    }

    fs.with_inner(OpTag::Unlink, |inner| {
        let now = fs.clock.now();
        log::trace!("unlink(parent={}, name={})", parent, name);

        if name.len() > 255 {
            return Err(libc::ENAMETOOLONG);
        }

        let parent_attr = inner.get_attr(parent).ok_or(libc::ENOENT)?;
        if parent_attr.file_type != FileType::Directory {
            return Err(libc::ENOTDIR);
        }

        let child_ino = fs.lookup_child_locked(inner, parent, name).ok_or(libc::ENOENT)?;
        if fs.is_virtual_ino(child_ino) {
            return Err(libc::EPERM);
        }
        let child_attr = fs.get_attr_locked(inner, child_ino).ok_or(libc::ENOENT)?;

        if child_attr.file_type == FileType::Directory {
            return Err(libc::EISDIR);
        }

        inner.remove_dir_entry(parent, name, now);

        let new_nlink = child_attr.nlink.saturating_sub(1);
        inner.update_attr_delta(
            child_ino,
            AttrDelta {
                nlink: Some(new_nlink),
                ctime: Some(now),
                ..Default::default()
            },
        );

        let open_count = inner.open_counts.get(&child_ino).copied().unwrap_or(0);
        if new_nlink == 0 && open_count == 0 {
            inner.tombstone(child_ino);
        }
        inner.record_mutation(name.len());
        Ok(())
    })
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
    if fs.is_read_only() {
        return Err(libc::EROFS);
    }

    fs.with_inner(OpTag::Symlink, |inner| {
        let now = fs.clock.now();
        log::trace!(
            "symlink(parent={}, name={}, link={}, uid={}, gid={})",
            parent,
            name,
            target,
            uid,
            gid
        );

        if name.len() > 255 {
            return Err(libc::ENAMETOOLONG);
        }

        let parent_attr = inner.get_attr(parent).ok_or(libc::ENOENT)?;
        if parent_attr.file_type != FileType::Directory {
            return Err(libc::ENOTDIR);
        }

        if fs.lookup_child_locked(inner, parent, name).is_some() {
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
                created_at: Some(now),
                xattrs: None,
            },
        });

        inner.insert_new_node(new_ino, new_delta);
        inner.add_dir_entry(parent, name, new_ino, now);
        inner.record_mutation(name.len() + target.len());

        Ok(FileAttr {
            ino: new_ino,
            file_type: FileType::Symlink,
            perm: 0o777,
            nlink: 1,
            uid,
            gid,
            rdev: 0,
            size: target.len() as i64,
            atime: now,
            mtime: now,
            ctime: now,
        })
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

// TODO(too-many-lines): extract this into smaller units.
#[allow(clippy::too_many_lines)]
pub fn rename_core(fs: &InMemoryFS, parent: u64, name: &str, newparent: u64, newname: &str) -> Result<(), i32> {
    if fs.is_read_only() {
        return Err(libc::EROFS);
    }

    fs.with_inner(OpTag::Rename, |inner| {
        let now = fs.clock.now();
        log::trace!(
            "rename(parent={}, name={}, newparent={}, newname={})",
            parent,
            name,
            newparent,
            newname
        );

        if name.len() > 255 || newname.len() > 255 {
            return Err(libc::ENAMETOOLONG);
        }

        let parent_attr = inner.get_attr(parent).ok_or(libc::ENOENT)?;
        if parent_attr.file_type != FileType::Directory {
            return Err(libc::ENOTDIR);
        }
        let newparent_attr = inner.get_attr(newparent).ok_or(libc::ENOENT)?;
        if newparent_attr.file_type != FileType::Directory {
            return Err(libc::ENOTDIR);
        }

        let source_ino = fs.lookup_child_locked(inner, parent, name).ok_or(libc::ENOENT)?;
        if fs.is_virtual_ino(source_ino) {
            return Err(libc::EPERM);
        }
        let source_attr = fs.get_attr_locked(inner, source_ino).ok_or(libc::ENOENT)?;

        if source_attr.file_type == FileType::Directory {
            let mut curr = newparent;
            while curr != 1 {
                if curr == source_ino {
                    return Err(libc::EINVAL);
                }
                if let Some(p) = inner.get_parent_dir_inode(curr) {
                    curr = p;
                } else {
                    break;
                }
            }
        }

        if parent == newparent && name == newname {
            return Ok(());
        }

        let src_is_dir = source_attr.file_type == FileType::Directory;

        let mut dest_was_dir = false;
        if let Some(dest_ino) = fs.lookup_child_locked(inner, newparent, newname) {
            if fs.is_virtual_ino(dest_ino) {
                return Err(libc::EPERM);
            }
            // POSIX: when old and new resolve to different directory entries for the same
            // file - two hardlinks to one inode - rename succeeds and does nothing. Without
            // this the destination is treated as a victim and its link count is dropped,
            // which also desynchronizes the log: synthesis emits a bare Rename whose replay
            // does not reproduce that decrement.
            if dest_ino == source_ino {
                return Ok(());
            }

            let dest_attr = fs.get_attr_locked(inner, dest_ino).ok_or(libc::ENOENT)?;
            let dest_is_dir = dest_attr.file_type == FileType::Directory;

            if src_is_dir != dest_is_dir {
                return Err(if src_is_dir { libc::ENOTDIR } else { libc::EISDIR });
            }

            if dest_is_dir {
                let dest_entries = inner.list_directory(dest_ino).ok_or(libc::ENOENT)?;
                if !dest_entries.is_empty() {
                    return Err(libc::ENOTEMPTY);
                }
                dest_was_dir = true;
                inner.remove_dir_entry(newparent, newname, now);
                inner.tombstone(dest_ino);
            } else {
                inner.remove_dir_entry(newparent, newname, now);
                let new_dest_nlink = dest_attr.nlink.saturating_sub(1);
                inner.update_attr_delta(
                    dest_ino,
                    AttrDelta {
                        nlink: Some(new_dest_nlink),
                        ctime: Some(now),
                        ..Default::default()
                    },
                );
                let open_count = inner.open_counts.get(&dest_ino).copied().unwrap_or(0);
                if new_dest_nlink == 0 && open_count == 0 {
                    inner.tombstone(dest_ino);
                }
            }
        }

        inner.remove_dir_entry(parent, name, now);
        inner.add_dir_entry(newparent, newname, source_ino, now);
        if src_is_dir && parent != newparent {
            inner.update_dir_parent(source_ino, newparent);
        }
        if src_is_dir {
            // Two independent effects on subdirectory counts, composed rather than
            // handled as one combined case: moving to a different parent costs `parent`
            // a subdirectory and gains `newparent` one; clobbering an existing empty
            // directory at the destination costs `newparent` a subdirectory, regardless
            // of whether that's the same directory as `parent`. Handling them as a
            // single "cross-parent move, minus a same-parent-rename special case" (as
            // this used to) missed the case where they're `parent == newparent` *and*
            // dest_was_dir: renaming a directory onto an existing empty sibling in the
            // same parent removes a subdirectory (the clobbered sibling) without adding
            // one (the source was already counted), and nothing here applied that half
            // when the "cross-parent" condition gating the whole block was false.
            let mut parent_delta: i64 = 0;
            let mut newparent_delta: i64 = 0;
            if parent != newparent {
                parent_delta -= 1;
                newparent_delta += 1;
            }
            if dest_was_dir {
                newparent_delta -= 1;
            }
            if parent_delta != 0 {
                inner.update_attr_delta(
                    parent,
                    AttrDelta {
                        nlink: Some((parent_attr.nlink as i64 + parent_delta) as u32),
                        ctime: Some(now),
                        ..Default::default()
                    },
                );
            }
            if newparent_delta != 0 {
                inner.update_attr_delta(
                    newparent,
                    AttrDelta {
                        nlink: Some((newparent_attr.nlink as i64 + newparent_delta) as u32),
                        ctime: Some(now),
                        ..Default::default()
                    },
                );
            }
        }
        inner.record_mutation(name.len() + newname.len());
        Ok(())
    })
}

pub fn rename(fs: &InMemoryFS, req: Request, parent: u64, name: &str, newparent: u64, newname: &str) {
    match rename_core(fs, parent, name, newparent, newname) {
        Ok(()) => req.reply_err(0),
        Err(e) => req.reply_err(e),
    }
}

pub fn link_core(fs: &InMemoryFS, ino: u64, newparent: u64, newname: &str) -> Result<FileAttr, i32> {
    if fs.is_read_only() {
        return Err(libc::EROFS);
    }

    fs.with_inner(OpTag::Link, |inner| {
        let now = fs.clock.now();
        log::trace!("link(ino={}, newparent={}, newname={})", ino, newparent, newname);

        if newname.len() > 255 {
            return Err(libc::ENAMETOOLONG);
        }

        let target_attr = fs.get_attr_locked(inner, ino).ok_or(libc::ENOENT)?;
        if target_attr.file_type == FileType::Directory || fs.is_virtual_ino(ino) {
            return Err(libc::EPERM);
        }
        if target_attr.nlink == 0 {
            return Err(libc::ENOENT);
        }

        let newparent_attr = inner.get_attr(newparent).ok_or(libc::ENOENT)?;
        if newparent_attr.file_type != FileType::Directory {
            return Err(libc::ENOTDIR);
        }

        if fs.lookup_child_locked(inner, newparent, newname).is_some() {
            return Err(libc::EEXIST);
        }

        let new_nlink = target_attr.nlink + 1;
        inner.update_attr_delta(
            ino,
            AttrDelta {
                nlink: Some(new_nlink),
                ctime: Some(now),
                ..Default::default()
            },
        );

        inner.add_dir_entry(newparent, newname, ino, now);
        inner.record_mutation(newname.len());
        let mut attr = target_attr;
        attr.nlink = new_nlink;
        attr.ctime = now;
        Ok(attr)
    })
}

pub fn link(fs: &InMemoryFS, req: Request, ino: u64, newparent: u64, newname: &str) {
    match link_core(fs, ino, newparent, newname) {
        Ok(attr) => req.reply_entry(&attr, 1.0, 1.0),
        Err(e) => req.reply_err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::InMemoryFS;
    use crate::operations::read_write::create_core;

    #[test]
    fn test_links_and_rename_name_length_boundaries() {
        let fs = InMemoryFS::new();
        let file = create_core(&fs, 1, "orig.txt", 0o644, 0, 1000, 1000).unwrap();

        let name_255 = "l".repeat(255);
        let name_256 = "l".repeat(256);

        // Symlink: 255 bytes succeeds, 256 bytes fails with ENAMETOOLONG
        let sym_attr = symlink_core(&fs, 1, &name_255, "orig.txt", 1000, 1000).unwrap();
        assert_eq!(sym_attr.file_type, FileType::Symlink);
        assert_eq!(
            symlink_core(&fs, 1, &name_256, "orig.txt", 1000, 1000),
            Err(libc::ENAMETOOLONG)
        );

        // Hardlink: 255 bytes succeeds, 256 bytes fails with ENAMETOOLONG
        let hard_name_255 = "h".repeat(255);
        let hard_attr = link_core(&fs, file.ino, 1, &hard_name_255).unwrap();
        assert_eq!(hard_attr.nlink, 2);
        assert_eq!(link_core(&fs, file.ino, 1, &name_256), Err(libc::ENAMETOOLONG));

        // Rename:
        // Source 256 bytes fails
        assert_eq!(rename_core(&fs, 1, &name_256, 1, "dest.txt"), Err(libc::ENAMETOOLONG));
        // Target 256 bytes fails
        assert_eq!(rename_core(&fs, 1, "orig.txt", 1, &name_256), Err(libc::ENAMETOOLONG));
        // Target 255 bytes succeeds
        let ren_name_255 = "r".repeat(255);
        assert_eq!(rename_core(&fs, 1, &hard_name_255, 1, &ren_name_255), Ok(()));

        // Unlink: 256 bytes fails with ENAMETOOLONG
        assert_eq!(unlink_core(&fs, 1, &name_256), Err(libc::ENAMETOOLONG));

        // Unlink: 255 bytes succeeds
        assert_eq!(unlink_core(&fs, 1, &name_255), Ok(()));
        assert_eq!(unlink_core(&fs, 1, &ren_name_255), Ok(()));
        assert_eq!(unlink_core(&fs, 1, "orig.txt"), Ok(()));
    }
}
