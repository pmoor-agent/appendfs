//! POSIX file and directory handle tracking.
//!
//! File handles own the open-count bookkeeping that keeps an unlinked-but-open inode
//! alive, and releasing one also drops any BSD flock and POSIX range locks it held.
//! Directory handles hold an immutable snapshot of the listing taken at `opendir`, so a
//! paginated `readdir` is isolated from concurrent mutations.

use super::{
    DirHandle, DirSnapshot, Handle, HandleKind, InMemoryFS, ReadPlan, ReadSlice, ReadSliceSource, VirtualHandle,
};
use std::sync::Arc;
use std::sync::atomic::Ordering;

impl InMemoryFS {
    // --- POSIX File & Directory Handle Tracking ---

    pub fn open_file_handle(&self, ino: u64, flags: u32) -> u64 {
        let is_virtual = self.virtual_files.is_virtual_ino(ino);
        let kind = if is_virtual {
            let content = self.virtual_files.generate_content(ino, self).unwrap_or_default();
            HandleKind::Virtual(Arc::new(content.into_bytes()))
        } else {
            HandleKind::Regular
        };

        let fh = self.allocate_fh();
        let mut inner = self.inner.lock().unwrap();
        inner.handles.insert(fh, Handle { ino, flags, kind });
        if !is_virtual {
            *inner.open_counts.entry(ino).or_insert(0) += 1;
        }
        fh
    }

    pub fn get_handle(&self, fh: u64) -> Option<Handle> {
        self.inner.lock().unwrap().handles.get(&fh).cloned()
    }

    pub fn get_file_handle(&self, fh: u64) -> Option<Handle> {
        let h = self.inner.lock().unwrap().handles.get(&fh).cloned()?;
        if h.is_dir() { None } else { Some(h) }
    }

    /// Validates and extracts a directory handle for the given inode and handle ID.
    ///
    /// Returns:
    /// - `Err(libc::EBADF)` if the handle does not exist or was opened for a different inode.
    /// - `Err(libc::ENOTDIR)` if the handle refers to a regular or virtual file.
    pub fn extract_dir_handle(&self, ino: u64, fh: u64) -> Result<DirHandle, i32> {
        let handle = self.get_handle(fh).ok_or(libc::EBADF)?;
        if handle.ino != ino {
            return Err(libc::EBADF);
        }
        match handle.kind {
            HandleKind::Directory(entries) => Ok(DirHandle {
                ino: handle.ino,
                flags: handle.flags,
                entries,
            }),
            _ => Err(libc::ENOTDIR),
        }
    }

    /// Validates and extracts an open file handle (either regular or virtual) for the given inode and handle ID.
    ///
    /// Returns:
    /// - `Err(libc::EBADF)` if the handle does not exist or was opened for a different inode.
    /// - `Err(libc::EISDIR)` if the handle refers to a directory.
    pub fn extract_file_handle(&self, ino: u64, fh: u64) -> Result<Handle, i32> {
        let handle = self.get_handle(fh).ok_or(libc::EBADF)?;
        if handle.ino != ino {
            return Err(libc::EBADF);
        }
        if handle.is_dir() {
            return Err(libc::EISDIR);
        }
        Ok(handle)
    }

    /// Validates and extracts an open regular file handle for the given inode and handle ID.
    ///
    /// Returns:
    /// - `Err(libc::EBADF)` if the handle does not exist, was opened for a different inode, or is a virtual file.
    /// - `Err(libc::EISDIR)` if the handle refers to a directory.
    pub fn extract_regular_handle(&self, ino: u64, fh: u64) -> Result<Handle, i32> {
        let handle = self.extract_file_handle(ino, fh)?;
        if !handle.is_regular() {
            return Err(libc::EBADF);
        }
        Ok(handle)
    }

    /// Validates and extracts an open virtual file handle for the given inode and handle ID.
    ///
    /// Returns:
    /// - `Err(libc::EBADF)` if the handle does not exist, was opened for a different inode, or is a regular file.
    /// - `Err(libc::EISDIR)` if the handle refers to a directory.
    pub fn extract_virtual_handle(&self, ino: u64, fh: u64) -> Result<VirtualHandle, i32> {
        let handle = self.extract_file_handle(ino, fh)?;
        match handle.kind {
            HandleKind::Virtual(data) => Ok(VirtualHandle {
                ino: handle.ino,
                flags: handle.flags,
                data,
            }),
            _ => Err(libc::EBADF),
        }
    }

    pub fn plan_read_handle(&self, ino: u64, fh: u64, offset: u64, size: usize) -> Result<ReadPlan, i32> {
        let handle = self.extract_file_handle(ino, fh)?;
        match handle.kind {
            HandleKind::Virtual(buf) => {
                let start = (offset as usize).min(buf.len());
                let end = (start + size).min(buf.len());
                let slice_len = end - start;
                Ok(ReadPlan {
                    total_len: slice_len,
                    has_cold_slices: false,
                    slices: if slice_len > 0 {
                        vec![ReadSlice {
                            dst_offset: 0,
                            len: slice_len,
                            source: ReadSliceSource::Cache {
                                data: buf,
                                src_offset: start,
                            },
                        }]
                    } else {
                        Vec::new()
                    },
                })
            }
            HandleKind::Regular => self.plan_read_file_data(ino, offset, size),
            HandleKind::Directory(_) => unreachable!("extract_file_handle rejects directory handles"),
        }
    }

    pub fn read_handle(&self, ino: u64, fh: u64, offset: u64, size: usize) -> Result<Vec<u8>, i32> {
        let plan = self.plan_read_handle(ino, fh, offset, size)?;
        self.execute_read_plan_sync(plan)
    }

    pub fn release_file_handle(&self, fh: u64, ino: u64) -> Result<(), i32> {
        let is_last_handle = {
            let mut inner = self.inner.lock().unwrap();
            let handle = match inner.handles.get(&fh) {
                Some(h) if h.ino == ino && !h.is_dir() => inner.handles.remove(&fh).unwrap(),
                _ => return Err(libc::EBADF),
            };

            if handle.is_virtual() {
                return Ok(());
            }

            if let Some(count) = inner.open_counts.get_mut(&ino) {
                *count = count.saturating_sub(1);
            }
            let is_last = if inner.open_counts.get(&ino) == Some(&0) {
                inner.open_counts.remove(&ino);
                true
            } else {
                false
            };

            let remaining = inner.open_counts.get(&ino).copied().unwrap_or(0);
            if remaining == 0
                && let Some(attr) = inner.get_attr(ino)
                && attr.nlink == 0
            {
                inner.tombstone(ino);
            }

            is_last
        };

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
        self.inner.lock().unwrap().open_counts.get(&ino).copied().unwrap_or(0)
    }

    // --- Directory Handle Snapshot Management ---

    pub fn allocate_fh(&self) -> u64 {
        self.next_fh.fetch_add(1, Ordering::SeqCst)
    }

    pub fn open_dir_handle(&self, ino: u64, flags: u32, entries: Vec<(String, u64)>) -> u64 {
        let fh = self.allocate_fh();
        self.inner.lock().unwrap().handles.insert(
            fh,
            Handle {
                ino,
                flags,
                kind: HandleKind::Directory(Arc::new(entries)),
            },
        );
        fh
    }

    pub fn get_dir_handle(&self, fh: u64) -> Option<DirSnapshot> {
        match self.inner.lock().unwrap().handles.get(&fh) {
            Some(h) => match &h.kind {
                HandleKind::Directory(entries) => Some(Arc::clone(entries)),
                _ => None,
            },
            None => None,
        }
    }

    pub fn release_dir_handle(&self, fh: u64, ino: u64) -> Result<(), i32> {
        let mut inner = self.inner.lock().unwrap();
        match inner.handles.get(&fh) {
            Some(h) if h.ino == ino && h.is_dir() => {
                inner.handles.remove(&fh);
                Ok(())
            }
            _ => Err(libc::EBADF),
        }
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

        let snap1 = fs.get_dir_handle(fh1).expect("Handle snapshot must exist");
        assert_eq!(snap1.len(), 3);
        assert_eq!(snap1[0].0, ".status");
        assert_eq!(snap1[1].0, "alpha.txt");
        assert_eq!(snap1[2].0, "bravo.txt");

        // 3. Mutate directory: add charlie.txt, delete alpha.txt
        crate::operations::read_write::create_core(&fs, 1, "charlie.txt", 0o644, 0, 1000, 1000).unwrap();
        fs.remove_dir_entry(1, "alpha.txt", now);

        // 4. fh1 MUST retain its original snapshot (.status, alpha, bravo)
        let snap1_recheck = fs.get_dir_handle(fh1).expect("Handle snapshot must still exist");
        assert_eq!(snap1_recheck.len(), 3);
        assert_eq!(snap1_recheck[0].0, ".status");
        assert_eq!(snap1_recheck[1].0, "alpha.txt");
        assert_eq!(snap1_recheck[2].0, "bravo.txt");

        // 5. A new directory handle on root gets the new snapshot (.status, bravo, charlie)
        let fh2 = crate::operations::dir::opendir_core(&fs, 1, 0).expect("opendir_core must succeed on directory");
        assert_ne!(fh1, fh2);
        let snap2 = fs.get_dir_handle(fh2).expect("Second handle snapshot must exist");
        assert_eq!(snap2.len(), 3);
        assert_eq!(snap2[0].0, ".status");
        assert_eq!(snap2[1].0, "bravo.txt");
        assert_eq!(snap2[2].0, "charlie.txt");

        // 6. Release fh1
        assert_eq!(fs.release_dir_handle(fh1, 999), Err(libc::EBADF));
        assert_eq!(fs.release_dir_handle(fh1, 1), Ok(()));
        assert!(fs.get_dir_handle(fh1).is_none());
        assert!(fs.get_dir_handle(fh2).is_some());
        assert_eq!(fs.release_dir_handle(fh1, 1), Err(libc::EBADF));

        // 7. Release fh2
        assert_eq!(fs.release_dir_handle(fh2, 1), Ok(()));
        assert!(fs.get_dir_handle(fh2).is_none());

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
        assert_eq!(fs.get_file_handle(fh1).unwrap().ino, ino);
        assert_eq!(fs.get_file_handle(fh2).unwrap().ino, ino);

        // 3. Unlink the file while handles are still open
        crate::operations::links::unlink_core(&fs, 1, "test.txt").unwrap();

        // Inode must still exist (not tombstoned) because open_count is 2
        assert!(fs.get_attr(ino).is_some());
        assert_eq!(fs.get_attr(ino).unwrap().nlink, 0);

        // 4. Release first handle
        assert_eq!(fs.release_file_handle(fh1, ino), Ok(()));
        assert!(fs.get_file_handle(fh1).is_none());
        assert!(fs.get_file_handle(fh2).is_some());
        assert_eq!(fs.open_count(ino), 1);
        assert!(fs.get_attr(ino).is_some());
        assert_eq!(fs.release_file_handle(fh1, ino), Err(libc::EBADF));

        // 5. Release second handle -> count drops to 0, inode gets tombstoned
        assert_eq!(fs.release_file_handle(fh2, ino), Ok(()));
        assert!(fs.get_file_handle(fh2).is_none());
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
            assert_eq!(inner.file_handles_count(), 2);
            assert_eq!(inner.dir_handles_count(), 1);
            assert!(inner.handles.contains_key(&fh_reg));
            assert!(inner.handles.contains_key(&fh_virt));
            assert!(inner.handles.contains_key(&fh_dir));
        }

        // Check get_file_handle properties
        let h_reg = fs.get_file_handle(fh_reg).expect("Regular handle must exist");
        assert_eq!(h_reg.ino, reg_ino);
        assert!(h_reg.is_regular());
        assert!(!h_reg.is_virtual());
        assert!(!h_reg.is_dir());

        let h_virt = fs.get_file_handle(fh_virt).expect("Virtual handle must exist");
        assert_eq!(h_virt.ino, v_ino);
        assert!(!h_virt.is_regular());
        assert!(h_virt.is_virtual());
        assert!(!h_virt.is_dir());

        // Directory handle is not returned by get_file_handle
        assert!(fs.get_file_handle(fh_dir).is_none());

        // Directory handle is returned by get_dir_handle
        let dir_snap = fs.get_dir_handle(fh_dir).expect("Directory snapshot must exist");
        assert!(!dir_snap.is_empty());
        assert!(fs.get_dir_handle(fh_reg).is_none());
        assert!(fs.get_dir_handle(fh_virt).is_none());

        // --- extract_dir_handle validation ---
        let dir_h = fs
            .extract_dir_handle(1, fh_dir)
            .expect("extract_dir_handle must succeed");
        assert_eq!(dir_h.ino, 1);
        assert!(!dir_h.entries.is_empty());
        assert_eq!(fs.extract_dir_handle(999, fh_dir).unwrap_err(), libc::EBADF);
        assert_eq!(fs.extract_dir_handle(reg_ino, fh_reg).unwrap_err(), libc::ENOTDIR);
        assert_eq!(fs.extract_dir_handle(v_ino, fh_virt).unwrap_err(), libc::ENOTDIR);
        assert_eq!(fs.extract_dir_handle(1, 99999).unwrap_err(), libc::EBADF);

        // --- extract_file_handle validation ---
        let file_h_reg = fs
            .extract_file_handle(reg_ino, fh_reg)
            .expect("extract_file_handle must succeed on regular");
        assert!(file_h_reg.is_regular());
        let file_h_virt = fs
            .extract_file_handle(v_ino, fh_virt)
            .expect("extract_file_handle must succeed on virtual");
        assert!(file_h_virt.is_virtual());
        assert_eq!(fs.extract_file_handle(1, fh_dir).unwrap_err(), libc::EISDIR);
        assert_eq!(fs.extract_file_handle(999, fh_reg).unwrap_err(), libc::EBADF);
        assert_eq!(fs.extract_file_handle(reg_ino, 99999).unwrap_err(), libc::EBADF);

        // --- extract_regular_handle validation ---
        let reg_h = fs
            .extract_regular_handle(reg_ino, fh_reg)
            .expect("extract_regular_handle must succeed");
        assert_eq!(reg_h.ino, reg_ino);
        assert_eq!(fs.extract_regular_handle(v_ino, fh_virt).unwrap_err(), libc::EBADF);
        assert_eq!(fs.extract_regular_handle(1, fh_dir).unwrap_err(), libc::EISDIR);
        assert_eq!(fs.extract_regular_handle(999, fh_reg).unwrap_err(), libc::EBADF);
        assert_eq!(fs.extract_regular_handle(reg_ino, 99999).unwrap_err(), libc::EBADF);

        // --- extract_virtual_handle validation ---
        let virt_h = fs
            .extract_virtual_handle(v_ino, fh_virt)
            .expect("extract_virtual_handle must succeed");
        assert_eq!(virt_h.ino, v_ino);
        assert!(!virt_h.data.is_empty());
        assert_eq!(fs.extract_virtual_handle(reg_ino, fh_reg).unwrap_err(), libc::EBADF);
        assert_eq!(fs.extract_virtual_handle(1, fh_dir).unwrap_err(), libc::EISDIR);
        assert_eq!(fs.extract_virtual_handle(999, fh_virt).unwrap_err(), libc::EBADF);
        assert_eq!(fs.extract_virtual_handle(v_ino, 99999).unwrap_err(), libc::EBADF);

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

        // Releasing virtual handle with correct inode succeeds
        assert_eq!(fs.release_file_handle(fh_virt, v_ino), Ok(()));
        assert!(fs.get_file_handle(fh_virt).is_none());
        assert_eq!(fs.release_file_handle(fh_virt, v_ino), Err(libc::EBADF));

        // Release directory handle
        assert_eq!(fs.release_dir_handle(fh_dir, 1), Ok(()));
        assert!(fs.get_dir_handle(fh_dir).is_none());
        assert_eq!(fs.release_dir_handle(fh_dir, 1), Err(libc::EBADF));

        // Regular handle is still present and functional
        assert!(fs.get_file_handle(fh_reg).is_some());
        assert_eq!(fs.release_file_handle(fh_reg, reg_ino), Ok(()));
        assert!(fs.get_file_handle(fh_reg).is_none());

        // Unified map is now empty
        {
            let inner = fs.inner.lock().unwrap();
            assert!(inner.handles.is_empty());
        }
    }
}
