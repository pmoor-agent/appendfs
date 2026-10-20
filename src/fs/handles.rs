//! POSIX file and directory handle tracking.
//!
//! File handles own the open-count bookkeeping that keeps an unlinked-but-open inode
//! alive, and releasing one also drops any BSD flock and POSIX range locks it held.
//! Directory handles hold an immutable snapshot of the listing taken at `opendir`, so a
//! paginated `readdir` is isolated from concurrent mutations.

use super::{AppendFs, FileHandle, ReadPlan, ReadSlice, ReadSliceSource, ShutdownState};
#[cfg(any(test, feature = "testing"))]
use super::{DirHandle, execute_read_plan, is_virtual_ino};
use crate::error::FsError;
use crate::node::AttrDelta;
use crate::operations::locks::LockManager;
use crate::sync::OpTag;
use std::sync::Arc;

impl AppendFs {
    // --- POSIX File & Directory Handle Tracking ---

    #[cfg(any(test, feature = "testing"))]
    pub fn open_file_handle(&self, ino: u64, flags: u32) -> u64 {
        let is_virtual = is_virtual_ino(ino);
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

        self.with_inner(OpTag::Handle, |inner| {
            let fh = inner.allocate_fh();
            inner.insert_file_handle(fh, file_handle);
            fh
        })
    }

    /// Test-only helper to inspect file handle state.
    ///
    /// Not available in production builds to prevent re-introducing two-lock handle access patterns.
    #[cfg(any(test, feature = "testing"))]
    pub fn extract_file_handle(&self, ino: u64, fh: u64) -> Result<FileHandle, FsError> {
        self.with_inner(OpTag::Handle, |inner| inner.get_file_handle(ino, fh).cloned())
    }

    /// Test-only helper to inspect directory handle state.
    ///
    /// Not available in production builds to prevent re-introducing two-lock handle access patterns.
    #[cfg(any(test, feature = "testing"))]
    pub fn extract_dir_handle(&self, ino: u64, fh: u64) -> Result<DirHandle, FsError> {
        self.with_inner(OpTag::Handle, |inner| inner.get_dir_handle(ino, fh).cloned())
    }

    pub fn plan_read_handle(&self, ino: u64, fh: u64, offset: u64, size: usize) -> Result<ReadPlan, FsError> {
        self.with_inner(OpTag::ReadPlan, |inner| {
            inner.check_shutdown(false)?;
            let handle = inner.get_file_handle(ino, fh)?;
            match handle {
                FileHandle::Virtual { data, .. } => {
                    let data = Arc::clone(data);
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
                FileHandle::Regular { .. } => {
                    self.ensure_log_cache_active_writer();
                    let plan = inner.with_inode_layers(ino, |layers| {
                        layers.plan_read_file_data(offset, size, self.log_cache.as_deref())
                    })?;

                    if self.track_atime && plan.total_len > 0 && inner.shutdown_state == ShutdownState::Running {
                        let now = self.clock.now();
                        inner.update_attr_delta(
                            ino,
                            AttrDelta {
                                atime: Some(now),
                                ..Default::default()
                            },
                        );
                        inner.record_mutation(0);
                    }

                    Ok(plan)
                }
            }
        })
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn read_handle(&self, ino: u64, fh: u64, offset: u64, size: usize) -> Result<Vec<u8>, FsError> {
        let plan = self.plan_read_handle(ino, fh, offset, size)?;
        execute_read_plan(plan, self.log_cache.as_deref(), &self.volume_key)
    }

    pub fn release_file_handle(&self, fh: u64, ino: u64) -> Result<(), FsError> {
        self.with_inner(OpTag::Handle, |inner| {
            match inner.handles.get(&fh) {
                Some(h) if h.ino() == ino && !h.is_dir() => {
                    inner.handles.remove(&fh);
                }
                _ => return Err(FsError::EBADF),
            }

            let is_last_handle = if let Some(count) = inner.open_counts.get_mut(&ino) {
                *count = count.saturating_sub(1);
                let rem = *count;
                if rem == 0 {
                    inner.open_counts.remove(&ino);
                    if let Some(attr) = inner.get_attr(ino)
                        && attr.nlink == 0
                    {
                        inner.tombstone(ino);
                        inner.record_mutation(0);
                    }
                    true
                } else {
                    false
                }
            } else {
                false
            };

            LockManager::release_file_handle(inner, is_last_handle, ino, fh);
            Ok(())
        })
    }

    pub fn release_flock(&self, ino: u64, fh: u64) {
        self.with_inner(OpTag::Handle, |inner| LockManager::release_flock(inner, ino, fh));
    }

    pub fn cancel_range_lock_waiters(&self, ino: u64, fh: u64) {
        self.with_inner(OpTag::Handle, |inner| {
            LockManager::cancel_range_lock_waiters(inner, ino, fh)
        });
    }

    pub fn release_range_locks(&self, ino: u64, fh: u64) {
        self.with_inner(OpTag::Handle, |inner| LockManager::release_range_locks(inner, ino, fh));
    }

    pub fn open_count(&self, ino: u64) -> u32 {
        self.with_inner(OpTag::Handle, |inner| inner.open_counts.get(&ino).copied().unwrap_or(0))
    }

    // --- Directory Handle Snapshot Management ---

    #[cfg(any(test, feature = "testing"))]
    pub fn allocate_fh(&self) -> u64 {
        self.with_inner(OpTag::Handle, |inner| inner.allocate_fh())
    }

    pub fn release_dir_handle(&self, fh: u64, ino: u64) -> Result<(), FsError> {
        self.with_inner(OpTag::Handle, |inner| match inner.handles.get(&fh) {
            Some(h) if h.ino() == ino && h.is_dir() => {
                inner.handles.remove(&fh);
                Ok(())
            }
            _ => Err(FsError::EBADF),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::FsTestExt;
    use crate::test_utils::TestFs;

    #[test]
    fn test_dir_handle_snapshot_isolation_and_lifecycle() {
        let fs = TestFs::builder().build().fs;

        // 1. Create two files under root
        fs.create_file(1, "alpha.txt", 0o644).unwrap();
        fs.create_file(1, "bravo.txt", 0o644).unwrap();

        // 2. Open a directory handle on root
        let fh1 = fs.open_dir(1).expect("opendir_core must succeed on directory");
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
        fs.create_file(1, "charlie.txt", 0o644).unwrap();
        fs.remove_file(1, "alpha.txt").unwrap();

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
        let fh2 = fs.open_dir(1).expect("opendir_core must succeed on directory");
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
        assert_eq!(fs.release_dir_handle(fh1, 999), Err(FsError::EBADF));
        assert_eq!(fs.release_dir_handle(fh1, 1), Ok(()));
        assert_eq!(fs.extract_dir_handle(1, fh1), Err(FsError::EBADF));
        assert!(fs.extract_dir_handle(1, fh2).is_ok());
        assert_eq!(fs.release_dir_handle(fh1, 1), Err(FsError::EBADF));

        // 7. Release fh2
        assert_eq!(fs.release_dir_handle(fh2, 1), Ok(()));
        assert_eq!(fs.extract_dir_handle(1, fh2), Err(FsError::EBADF));

        // 8. opendir_core on a non-directory returns ENOTDIR
        let alpha_ino = snap1[0].1;
        assert_eq!(fs.open_dir(alpha_ino), Err(FsError::ENOTDIR));
    }

    #[test]
    fn test_file_handle_lifecycle_and_unlinking() {
        let fs = TestFs::builder().build().fs;

        // 1. Create a file
        let ino = fs.create_file(1, "test.txt", 0o644).unwrap();

        // 2. Open two file handles
        let fh1 = fs.open_file_handle(ino, libc::O_RDONLY as u32);
        let fh2 = fs.open_file_handle(ino, libc::O_WRONLY as u32);
        assert_ne!(fh1, fh2);
        assert_eq!(fs.open_count(ino), 2);
        assert_eq!(fs.extract_file_handle(ino, fh1).unwrap().ino(), ino);
        assert_eq!(fs.extract_file_handle(ino, fh2).unwrap().ino(), ino);

        // 3. Unlink the file while handles are still open
        fs.remove_file(1, "test.txt").unwrap();

        // Inode must still exist (not tombstoned) because open_count is 2
        assert!(fs.get_attr(ino).is_some());
        assert_eq!(fs.get_attr(ino).unwrap().nlink, 0);

        // 4. Release first handle
        assert_eq!(fs.release_file_handle(fh1, ino), Ok(()));
        assert_eq!(fs.extract_file_handle(ino, fh1), Err(FsError::EBADF));
        assert!(fs.extract_file_handle(ino, fh2).is_ok());
        assert_eq!(fs.open_count(ino), 1);
        assert!(fs.get_attr(ino).is_some());
        assert_eq!(fs.release_file_handle(fh1, ino), Err(FsError::EBADF));

        // 5. Release second handle -> count drops to 0, inode gets tombstoned
        assert_eq!(fs.release_file_handle(fh2, ino), Ok(()));
        assert_eq!(fs.extract_file_handle(ino, fh2), Err(FsError::EBADF));
        assert_eq!(fs.open_count(ino), 0);
        assert!(
            fs.get_attr(ino).is_none(),
            "Unlinked file with 0 handles must be tombstoned"
        );
    }

    #[test]
    fn test_unified_handle_map_regular_virtual_and_directory() {
        let fs = TestFs::builder().build().fs;
        let reg_ino = fs.create_file(1, "data.bin", 0o644).unwrap();
        let v_ino = fs.lookup_child(1, ".status").expect(".status must exist");

        let fh_reg = fs.open_file_handle(reg_ino, libc::O_RDWR as u32);
        let fh_virt = fs.open_file_handle(v_ino, libc::O_RDONLY as u32);
        let fh_dir = fs.open_dir(1).expect("opendir must succeed");

        assert_ne!(fh_reg, fh_virt);
        assert_ne!(fh_reg, fh_dir);
        assert_ne!(fh_virt, fh_dir);

        // All handles use regular sequential IDs
        assert!(fh_reg > 0);
        assert!(fh_virt > 0);
        assert!(fh_dir > 0);

        // All 3 handles exist in the unified map
        {
            let inner = fs.inner.lock_for_tests().unwrap();
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
        assert_eq!(fs.extract_file_handle(1, fh_dir).unwrap_err(), FsError::EISDIR);
        // Inode mismatch fails with EBADF
        assert_eq!(fs.extract_file_handle(999, fh_reg).unwrap_err(), FsError::EBADF);
        // Unknown handle ID fails with EBADF
        assert_eq!(fs.extract_file_handle(reg_ino, 99999).unwrap_err(), FsError::EBADF);

        // --- extract_dir_handle validation ---
        let dir_h = fs
            .extract_dir_handle(1, fh_dir)
            .expect("extract_dir_handle must succeed");
        assert_eq!(dir_h.ino, 1);
        assert!(!dir_h.entries.is_empty());
        assert_eq!(fs.extract_dir_handle(999, fh_dir).unwrap_err(), FsError::EBADF);
        // File handles fail extract_dir_handle with ENOTDIR
        assert_eq!(fs.extract_dir_handle(reg_ino, fh_reg).unwrap_err(), FsError::ENOTDIR);
        assert_eq!(fs.extract_dir_handle(v_ino, fh_virt).unwrap_err(), FsError::ENOTDIR);
        assert_eq!(fs.extract_dir_handle(1, 99999).unwrap_err(), FsError::EBADF);

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
            Err(FsError::EISDIR)
        );

        // Reading directory handle via plan_read_handle fails with EISDIR
        assert_eq!(fs.plan_read_handle(1, fh_dir, 0, 100).unwrap_err(), FsError::EISDIR);

        // Releasing dir handle via release_file_handle fails with EBADF
        assert_eq!(fs.release_file_handle(fh_dir, 1), Err(FsError::EBADF));

        // Releasing file handle via release_dir_handle fails with EBADF
        assert_eq!(fs.release_dir_handle(fh_reg, reg_ino), Err(FsError::EBADF));
        assert_eq!(fs.release_dir_handle(fh_virt, v_ino), Err(FsError::EBADF));

        // Inode mismatch on release must fail with EBADF for both
        assert_eq!(fs.release_file_handle(fh_virt, reg_ino), Err(FsError::EBADF));
        assert_eq!(fs.release_file_handle(fh_reg, v_ino), Err(FsError::EBADF));
        assert_eq!(fs.release_dir_handle(fh_dir, 999), Err(FsError::EBADF));

        // Releasing virtual handle with correct inode succeeds and clears open count
        assert_eq!(fs.release_file_handle(fh_virt, v_ino), Ok(()));
        assert_eq!(fs.open_count(v_ino), 0);
        assert_eq!(fs.extract_file_handle(v_ino, fh_virt), Err(FsError::EBADF));
        assert_eq!(fs.release_file_handle(fh_virt, v_ino), Err(FsError::EBADF));

        // Release directory handle
        assert_eq!(fs.release_dir_handle(fh_dir, 1), Ok(()));
        assert_eq!(fs.extract_dir_handle(1, fh_dir), Err(FsError::EBADF));
        assert_eq!(fs.release_dir_handle(fh_dir, 1), Err(FsError::EBADF));

        // Regular handle is still present and functional
        assert!(fs.extract_file_handle(reg_ino, fh_reg).is_ok());
        assert_eq!(fs.open_count(reg_ino), 1);
        assert_eq!(fs.release_file_handle(fh_reg, reg_ino), Ok(()));
        assert_eq!(fs.open_count(reg_ino), 0);
        assert_eq!(fs.extract_file_handle(reg_ino, fh_reg), Err(FsError::EBADF));

        // Unified map is now empty
        {
            let inner = fs.inner.lock_for_tests().unwrap();
            assert!(inner.handles.is_empty());
        }
    }
}
