//! POSIX file and directory handle tracking.
//!
//! File handles own the open-count bookkeeping that keeps an unlinked-but-open inode
//! alive, and releasing one also drops any BSD flock and POSIX range locks it held.
//! Directory handles hold an immutable snapshot of the listing taken at `opendir`, so a
//! paginated `readdir` is isolated from concurrent mutations.

use super::{DirHandle, FileHandle, Handle, InMemoryFS, ReadPlan, ReadSlice, ReadSliceSource};
use crate::sync::OpTag;
use std::sync::Arc;
use std::sync::atomic::Ordering;

impl InMemoryFS {
    // --- POSIX File & Directory Handle Tracking ---

    pub fn open_file_handle(&self, ino: u64, flags: u32) -> u64 {
        let is_virtual = self.virtual_files.is_virtual_ino(ino);
        let file_handle = if is_virtual {
            let content = self.virtual_files.generate_content(ino, self).unwrap_or_default();
            FileHandle::Virtual {
                ino,
                flags,
                data: Arc::new(content.into_bytes()),
            }
        } else {
            FileHandle::Regular { ino, flags }
        };

        let fh = self.allocate_fh();
        self.with_inner(OpTag::Handle, |inner| {
            inner.handles.insert(fh, Handle::File(file_handle));
            *inner.open_counts.entry(ino).or_insert(0) += 1;
        });
        fh
    }

    /// Validates and extracts an open file handle (either regular or virtual) for the given inode and handle ID.
    ///
    /// Returns:
    /// - `Err(libc::EBADF)` if the handle does not exist or was opened for a different inode.
    /// - `Err(libc::EISDIR)` if the handle refers to a directory.
    pub fn extract_file_handle(&self, ino: u64, fh: u64) -> Result<FileHandle, i32> {
        self.with_inner(OpTag::Handle, |inner| {
            let handle = inner.handles.get(&fh).ok_or(libc::EBADF)?;
            if handle.ino() != ino {
                return Err(libc::EBADF);
            }
            match handle {
                Handle::File(f) => Ok(f.clone()),
                Handle::Directory(_) => Err(libc::EISDIR),
            }
        })
    }

    /// Validates and extracts a directory handle for the given inode and handle ID.
    ///
    /// Returns:
    /// - `Err(libc::EBADF)` if the handle does not exist or was opened for a different inode.
    /// - `Err(libc::ENOTDIR)` if the handle refers to a file.
    pub fn extract_dir_handle(&self, ino: u64, fh: u64) -> Result<DirHandle, i32> {
        self.with_inner(OpTag::Handle, |inner| {
            let handle = inner.handles.get(&fh).ok_or(libc::EBADF)?;
            if handle.ino() != ino {
                return Err(libc::EBADF);
            }
            match handle {
                Handle::Directory(d) => Ok(d.clone()),
                Handle::File(_) => Err(libc::ENOTDIR),
            }
        })
    }

    pub fn plan_read_handle(&self, ino: u64, fh: u64, offset: u64, size: usize) -> Result<ReadPlan, i32> {
        let handle = self.extract_file_handle(ino, fh)?;
        match handle {
            FileHandle::Virtual { data, .. } => {
                let start = (offset as usize).min(data.len());
                let end = (start + size).min(data.len());
                let slice_len = end - start;
                Ok(ReadPlan {
                    total_len: slice_len,
                    has_cold_slices: false,
                    slices: if slice_len > 0 {
                        vec![ReadSlice {
                            dst_offset: 0,
                            len: slice_len,
                            source: ReadSliceSource::Cache {
                                data,
                                src_offset: start,
                            },
                        }]
                    } else {
                        Vec::new()
                    },
                })
            }
            FileHandle::Regular { .. } => self.plan_read_file_data(ino, offset, size),
        }
    }

    pub fn read_handle(&self, ino: u64, fh: u64, offset: u64, size: usize) -> Result<Vec<u8>, i32> {
        let plan = self.plan_read_handle(ino, fh, offset, size)?;
        self.execute_read_plan_sync(plan)
    }

    pub fn release_file_handle(&self, fh: u64, ino: u64) -> Result<(), i32> {
        let is_last_handle = self.with_inner(OpTag::Handle, |inner| {
            match inner.handles.get(&fh) {
                Some(h) if h.ino() == ino && !h.is_dir() => {
                    inner.handles.remove(&fh);
                }
                _ => return Err(libc::EBADF),
            }

            let remaining = if let Some(count) = inner.open_counts.get_mut(&ino) {
                *count = count.saturating_sub(1);
                let rem = *count;
                if rem == 0 {
                    inner.open_counts.remove(&ino);
                    if let Some(attr) = inner.get_attr(ino)
                        && attr.nlink == 0
                    {
                        inner.tombstone(ino);
                    }
                }
                rem
            } else {
                0
            };

            Ok(remaining == 0)
        })?;

        // Clean up locks outside inner critical section
        self.locks.release_flock(ino, fh);
        if is_last_handle {
            self.locks.release_range_locks(ino, fh);
        } else {
            self.locks.cancel_range_lock_waiters(ino, fh);
        }
        Ok(())
    }

    pub fn release_flock(&self, ino: u64, fh: u64) {
        self.locks.release_flock(ino, fh);
    }

    pub fn cancel_range_lock_waiters(&self, ino: u64, fh: u64) {
        self.locks.cancel_range_lock_waiters(ino, fh);
    }

    pub fn release_range_locks(&self, ino: u64, fh: u64) {
        self.locks.release_range_locks(ino, fh);
    }

    pub fn open_count(&self, ino: u64) -> u32 {
        self.with_inner(OpTag::Handle, |inner| inner.open_counts.get(&ino).copied().unwrap_or(0))
    }

    // --- Directory Handle Snapshot Management ---

    pub fn allocate_fh(&self) -> u64 {
        self.next_fh.fetch_add(1, Ordering::SeqCst)
    }

    pub fn open_dir_handle(&self, ino: u64, flags: u32, entries: Vec<(String, u64)>) -> u64 {
        let fh = self.allocate_fh();
        self.with_inner(OpTag::Handle, |inner| {
            inner.handles.insert(
                fh,
                Handle::Directory(DirHandle {
                    ino,
                    flags,
                    entries: Arc::new(entries),
                }),
            );
        });
        fh
    }

    pub fn release_dir_handle(&self, fh: u64, ino: u64) -> Result<(), i32> {
        self.with_inner(OpTag::Handle, |inner| match inner.handles.get(&fh) {
            Some(h) if h.ino() == ino && h.is_dir() => {
                inner.handles.remove(&fh);
                Ok(())
            }
            _ => Err(libc::EBADF),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dir_handle_snapshot_isolation_and_lifecycle() {
        let fs = InMemoryFS::new();
        let now = fs.clock.now();

        // 1. Create two files under root
        crate::operations::read_write::create_core(&fs, 1, "alpha.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::create_core(&fs, 1, "bravo.txt", 0o644, 0, 1000, 1000).unwrap();

        // 2. Open a directory handle on root
        let fh1 = crate::operations::dir::opendir_core(&fs, 1, 0).expect("opendir_core must succeed on directory");
        assert!(fh1 > 0);

        let snap1 = fs
            .extract_dir_handle(1, fh1)
            .expect("Handle snapshot must exist")
            .entries;
        assert_eq!(snap1.len(), 3);
        assert_eq!(snap1[0].0, ".status");
        assert_eq!(snap1[1].0, "alpha.txt");
        assert_eq!(snap1[2].0, "bravo.txt");

        // 3. Mutate directory: add charlie.txt, delete alpha.txt
        crate::operations::read_write::create_core(&fs, 1, "charlie.txt", 0o644, 0, 1000, 1000).unwrap();
        fs.remove_dir_entry(1, "alpha.txt", now);

        // 4. fh1 MUST retain its original snapshot (.status, alpha, bravo)
        let snap1_recheck = fs
            .extract_dir_handle(1, fh1)
            .expect("Handle snapshot must still exist")
            .entries;
        assert_eq!(snap1_recheck.len(), 3);
        assert_eq!(snap1_recheck[0].0, ".status");
        assert_eq!(snap1_recheck[1].0, "alpha.txt");
        assert_eq!(snap1_recheck[2].0, "bravo.txt");

        // 5. A new directory handle on root gets the new snapshot (.status, bravo, charlie)
        let fh2 = crate::operations::dir::opendir_core(&fs, 1, 0).expect("opendir_core must succeed on directory");
        assert_ne!(fh1, fh2);
        let snap2 = fs
            .extract_dir_handle(1, fh2)
            .expect("Second handle snapshot must exist")
            .entries;
        assert_eq!(snap2.len(), 3);
        assert_eq!(snap2[0].0, ".status");
        assert_eq!(snap2[1].0, "bravo.txt");
        assert_eq!(snap2[2].0, "charlie.txt");

        // 6. Release fh1
        assert_eq!(fs.release_dir_handle(fh1, 999), Err(libc::EBADF));
        assert_eq!(fs.release_dir_handle(fh1, 1), Ok(()));
        assert_eq!(fs.extract_dir_handle(1, fh1), Err(libc::EBADF));
        assert!(fs.extract_dir_handle(1, fh2).is_ok());
        assert_eq!(fs.release_dir_handle(fh1, 1), Err(libc::EBADF));

        // 7. Release fh2
        assert_eq!(fs.release_dir_handle(fh2, 1), Ok(()));
        assert_eq!(fs.extract_dir_handle(1, fh2), Err(libc::EBADF));

        // 8. opendir_core on a non-directory returns ENOTDIR
        let alpha_ino = snap1[0].1;
        assert_eq!(
            crate::operations::dir::opendir_core(&fs, alpha_ino, 0),
            Err(libc::ENOTDIR)
        );
    }

    #[test]
    fn test_file_handle_lifecycle_and_unlinking() {
        let fs = InMemoryFS::new();

        // 1. Create a file
        let attr = crate::operations::read_write::create_core(&fs, 1, "test.txt", 0o644, 0, 1000, 1000).unwrap();
        let ino = attr.ino;

        // 2. Open two file handles
        let fh1 = fs.open_file_handle(ino, libc::O_RDONLY as u32);
        let fh2 = fs.open_file_handle(ino, libc::O_WRONLY as u32);
        assert_ne!(fh1, fh2);
        assert_eq!(fs.open_count(ino), 2);
        assert_eq!(fs.extract_file_handle(ino, fh1).unwrap().ino(), ino);
        assert_eq!(fs.extract_file_handle(ino, fh2).unwrap().ino(), ino);

        // 3. Unlink the file while handles are still open
        crate::operations::links::unlink_core(&fs, 1, "test.txt").unwrap();

        // Inode must still exist (not tombstoned) because open_count is 2
        assert!(fs.get_attr(ino).is_some());
        assert_eq!(fs.get_attr(ino).unwrap().nlink, 0);

        // 4. Release first handle
        assert_eq!(fs.release_file_handle(fh1, ino), Ok(()));
        assert_eq!(fs.extract_file_handle(ino, fh1), Err(libc::EBADF));
        assert!(fs.extract_file_handle(ino, fh2).is_ok());
        assert_eq!(fs.open_count(ino), 1);
        assert!(fs.get_attr(ino).is_some());
        assert_eq!(fs.release_file_handle(fh1, ino), Err(libc::EBADF));

        // 5. Release second handle -> count drops to 0, inode gets tombstoned
        assert_eq!(fs.release_file_handle(fh2, ino), Ok(()));
        assert_eq!(fs.extract_file_handle(ino, fh2), Err(libc::EBADF));
        assert_eq!(fs.open_count(ino), 0);
        assert!(
            fs.get_attr(ino).is_none(),
            "Unlinked file with 0 handles must be tombstoned"
        );
    }

    #[test]
    fn test_unified_handle_map_regular_virtual_and_directory() {
        let fs = InMemoryFS::new();
        let attr = crate::operations::read_write::create_core(&fs, 1, "data.bin", 0o644, 0, 1000, 1000).unwrap();
        let reg_ino = attr.ino;
        let v_ino = fs.lookup_child(1, ".status").expect(".status must exist");

        let fh_reg = fs.open_file_handle(reg_ino, libc::O_RDWR as u32);
        let fh_virt = fs.open_file_handle(v_ino, libc::O_RDONLY as u32);
        let fh_dir = crate::operations::dir::opendir_core(&fs, 1, 0).expect("opendir must succeed");

        assert_ne!(fh_reg, fh_virt);
        assert_ne!(fh_reg, fh_dir);
        assert_ne!(fh_virt, fh_dir);

        // All handles use regular sequential IDs
        assert!(fh_reg > 0);
        assert!(fh_virt > 0);
        assert!(fh_dir > 0);

        // All 3 handles exist in the unified map
        {
            let inner = fs.inner.lock().unwrap();
            assert_eq!(inner.handles.len(), 3);
            assert_eq!(inner.handle_counts(), (1, 1, 1));
            assert!(inner.handles.contains_key(&fh_reg));
            assert!(inner.handles.contains_key(&fh_virt));
            assert!(inner.handles.contains_key(&fh_dir));
        }

        // --- extract_file_handle validation ---
        let h_reg = fs
            .extract_file_handle(reg_ino, fh_reg)
            .expect("Regular handle must exist");
        assert_eq!(h_reg.ino(), reg_ino);
        assert!(h_reg.is_regular());
        assert!(!h_reg.is_virtual());

        let h_virt = fs
            .extract_file_handle(v_ino, fh_virt)
            .expect("Virtual handle must exist");
        assert_eq!(h_virt.ino(), v_ino);
        assert!(!h_virt.is_regular());
        assert!(h_virt.is_virtual());

        // Open count tracking for both regular and virtual files
        assert_eq!(fs.open_count(reg_ino), 1);
        assert_eq!(fs.open_count(v_ino), 1);

        // Directory handle fails extract_file_handle with EISDIR
        assert_eq!(fs.extract_file_handle(1, fh_dir).unwrap_err(), libc::EISDIR);
        // Inode mismatch fails with EBADF
        assert_eq!(fs.extract_file_handle(999, fh_reg).unwrap_err(), libc::EBADF);
        // Unknown handle ID fails with EBADF
        assert_eq!(fs.extract_file_handle(reg_ino, 99999).unwrap_err(), libc::EBADF);

        // --- extract_dir_handle validation ---
        let dir_h = fs
            .extract_dir_handle(1, fh_dir)
            .expect("extract_dir_handle must succeed");
        assert_eq!(dir_h.ino, 1);
        assert!(!dir_h.entries.is_empty());
        assert_eq!(fs.extract_dir_handle(999, fh_dir).unwrap_err(), libc::EBADF);
        // File handles fail extract_dir_handle with ENOTDIR
        assert_eq!(fs.extract_dir_handle(reg_ino, fh_reg).unwrap_err(), libc::ENOTDIR);
        assert_eq!(fs.extract_dir_handle(v_ino, fh_virt).unwrap_err(), libc::ENOTDIR);
        assert_eq!(fs.extract_dir_handle(1, 99999).unwrap_err(), libc::EBADF);

        // --- flock on virtual file handles is supported ---
        assert_eq!(
            crate::operations::locks::flock_core(&fs, v_ino, fh_virt, 1001, libc::LOCK_SH),
            Ok(())
        );
        assert_eq!(
            crate::operations::locks::flock_core(&fs, v_ino, fh_virt, 1001, libc::LOCK_UN),
            Ok(())
        );
        // Locking a directory handle fails with EISDIR
        assert_eq!(
            crate::operations::locks::flock_core(&fs, 1, fh_dir, 1001, libc::LOCK_SH),
            Err(libc::EISDIR)
        );

        // Reading directory handle via plan_read_handle fails with EISDIR
        assert_eq!(fs.plan_read_handle(1, fh_dir, 0, 100).unwrap_err(), libc::EISDIR);

        // Releasing dir handle via release_file_handle fails with EBADF
        assert_eq!(fs.release_file_handle(fh_dir, 1), Err(libc::EBADF));

        // Releasing file handle via release_dir_handle fails with EBADF
        assert_eq!(fs.release_dir_handle(fh_reg, reg_ino), Err(libc::EBADF));
        assert_eq!(fs.release_dir_handle(fh_virt, v_ino), Err(libc::EBADF));

        // Inode mismatch on release must fail with EBADF for both
        assert_eq!(fs.release_file_handle(fh_virt, reg_ino), Err(libc::EBADF));
        assert_eq!(fs.release_file_handle(fh_reg, v_ino), Err(libc::EBADF));
        assert_eq!(fs.release_dir_handle(fh_dir, 999), Err(libc::EBADF));

        // Releasing virtual handle with correct inode succeeds and clears open count
        assert_eq!(fs.release_file_handle(fh_virt, v_ino), Ok(()));
        assert_eq!(fs.open_count(v_ino), 0);
        assert_eq!(fs.extract_file_handle(v_ino, fh_virt), Err(libc::EBADF));
        assert_eq!(fs.release_file_handle(fh_virt, v_ino), Err(libc::EBADF));

        // Release directory handle
        assert_eq!(fs.release_dir_handle(fh_dir, 1), Ok(()));
        assert_eq!(fs.extract_dir_handle(1, fh_dir), Err(libc::EBADF));
        assert_eq!(fs.release_dir_handle(fh_dir, 1), Err(libc::EBADF));

        // Regular handle is still present and functional
        assert!(fs.extract_file_handle(reg_ino, fh_reg).is_ok());
        assert_eq!(fs.open_count(reg_ino), 1);
        assert_eq!(fs.release_file_handle(fh_reg, reg_ino), Ok(()));
        assert_eq!(fs.open_count(reg_ino), 0);
        assert_eq!(fs.extract_file_handle(reg_ino, fh_reg), Err(libc::EBADF));

        // Unified map is now empty
        {
            let inner = fs.inner.lock().unwrap();
            assert!(inner.handles.is_empty());
        }
    }
}
