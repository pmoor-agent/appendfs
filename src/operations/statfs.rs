use crate::error::FsError;
use crate::fs::AppendFs;
use crate::shim::{FuseResponse, StatfsAttr};

/// Filesystem block size reported by `statfs` (4 KiB).
pub const STATFS_BLOCK_SIZE: u64 = 4096;

/// Virtual free capacity reported when backed by non-OS storage (1 PiB).
pub const VIRTUAL_FREE_BYTES: u64 = 1u64 << 50;

/// Virtual free block count corresponding to [`VIRTUAL_FREE_BYTES`].
pub const VIRTUAL_FREE_BLOCKS: u64 = VIRTUAL_FREE_BYTES / STATFS_BLOCK_SIZE;

/// Virtual free inode count reported for read-write mounts.
pub const VIRTUAL_FREE_INODES: u64 = 1_000_000_000;

/// Computes POSIX `statfs` / `statvfs` capacity, usage, and inode counts for `fs`.
pub fn statfs_response(fs: &AppendFs, ino: u64) -> Result<FuseResponse<'static>, FsError> {
    log::trace!("statfs(ino={})", ino);
    let active_inodes = fs.inode_counts().total_active() as u64;
    let used_blocks = fs.physical_log_bytes().div_ceil(STATFS_BLOCK_SIZE);

    if fs.is_read_only() {
        return Ok(FuseResponse::statfs(StatfsAttr {
            blocks: used_blocks,
            bfree: 0,
            bavail: 0,
            files: active_inodes,
            ffree: 0,
            bsize: STATFS_BLOCK_SIZE as u32,
            namelen: 255,
        }));
    }

    let (bfree, bavail) = available_blocks(fs);
    let blocks = used_blocks.saturating_add(bfree);

    Ok(FuseResponse::statfs(StatfsAttr {
        blocks,
        bfree,
        bavail,
        files: active_inodes,
        ffree: VIRTUAL_FREE_INODES,
        bsize: STATFS_BLOCK_SIZE as u32,
        namelen: 255,
    }))
}

fn available_blocks(fs: &AppendFs) -> (u64, u64) {
    let Some(storage) = fs.storage() else {
        return (VIRTUAL_FREE_BLOCKS, VIRTUAL_FREE_BLOCKS);
    };

    match storage.space_info() {
        Ok(Some(info)) => (
            info.free_bytes / STATFS_BLOCK_SIZE,
            info.avail_bytes / STATFS_BLOCK_SIZE,
        ),
        Ok(None) => (VIRTUAL_FREE_BLOCKS, VIRTUAL_FREE_BLOCKS),
        Err(err) => {
            log::warn!(
                "statfs: failed to query backing storage space: {}; falling back to virtual capacity",
                err
            );
            (VIRTUAL_FREE_BLOCKS, VIRTUAL_FREE_BLOCKS)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::{RemoteRegistry, RemoteTargetConfig};
    use crate::shim::statvfs_space;
    use crate::storage::{OsStorage, Storage};
    use crate::test_utils::{FsTestExt, TestFs};
    use std::sync::{Arc, RwLock};

    fn unwrap_statfs(res: Result<FuseResponse<'static>, FsError>) -> StatfsAttr {
        match res.expect("statfs must succeed") {
            FuseResponse::Statfs(attr) => attr,
            other => panic!("expected FuseResponse::Statfs, got {:?}", other),
        }
    }

    #[test]
    fn test_statfs_memory_storage_uses_virtual_capacity_and_physical_usage() {
        let test_fs = TestFs::builder().build();
        let fs = &test_fs.fs;

        let initial = unwrap_statfs(statfs_response(fs, 1));
        assert_eq!(initial.bsize, STATFS_BLOCK_SIZE as u32);
        assert_eq!(initial.namelen, 255);
        assert_eq!(initial.files, 1);
        assert_eq!(initial.ffree, VIRTUAL_FREE_INODES);
        assert_eq!(initial.bfree, VIRTUAL_FREE_BLOCKS);
        assert_eq!(initial.bavail, VIRTUAL_FREE_BLOCKS);
        assert_eq!(initial.blocks, VIRTUAL_FREE_BLOCKS);

        // Write and flush 64 KiB into the active log generation, then roll to seal it
        let ino = fs.create_file(1, "data.bin", 0o644).unwrap();
        fs.write_at(ino, &vec![0xABu8; 64 * 1024], 0).unwrap();
        fs.quiesce().unwrap();

        let after_flush = unwrap_statfs(statfs_response(fs, 1));
        let active_used_bytes = fs.physical_log_bytes();
        assert!(active_used_bytes >= 64 * 1024);
        let expected_used_blocks = active_used_bytes.div_ceil(STATFS_BLOCK_SIZE);
        assert_eq!(after_flush.files, 2);
        assert_eq!(after_flush.bfree, VIRTUAL_FREE_BLOCKS);
        assert_eq!(after_flush.blocks, expected_used_blocks + VIRTUAL_FREE_BLOCKS);
        assert_eq!(after_flush.blocks - after_flush.bfree, expected_used_blocks);

        // Roll the active log into the manifest and verify sealed bytes remain counted
        fs.force_roll_active_log().unwrap();
        let after_roll = unwrap_statfs(statfs_response(fs, 1));
        assert_eq!(after_roll.blocks - after_roll.bfree, expected_used_blocks);
    }

    #[test]
    fn test_statfs_os_storage_queries_backing_filesystem() {
        let dir = tempfile::tempdir().unwrap();
        let os_storage: Arc<dyn Storage> = Arc::new(OsStorage::new(dir.path()));
        let test_fs = TestFs::builder().storage(os_storage).build();
        let fs = &test_fs.fs;

        let host_space = statvfs_space(dir.path()).unwrap();
        let stat = unwrap_statfs(statfs_response(fs, 1));

        // Compare within a small tolerance in case background OS activity shifts free blocks
        let expected_bfree = host_space.free_bytes / STATFS_BLOCK_SIZE;
        let expected_bavail = host_space.avail_bytes / STATFS_BLOCK_SIZE;
        let tolerance_blocks = (64 * 1024 * 1024) / STATFS_BLOCK_SIZE;
        assert!(
            stat.bfree.abs_diff(expected_bfree) <= tolerance_blocks,
            "expected bfree near {}, got {}",
            expected_bfree,
            stat.bfree
        );
        assert!(
            stat.bavail.abs_diff(expected_bavail) <= tolerance_blocks,
            "expected bavail near {}, got {}",
            expected_bavail,
            stat.bavail
        );
        assert_eq!(stat.blocks, stat.bfree);
    }

    #[test]
    fn test_statfs_missing_dir_fallback_and_read_only_behavior() {
        let dir = tempfile::tempdir().unwrap();
        let os_storage: Arc<dyn Storage> = Arc::new(OsStorage::new(dir.path()));
        let mut test_fs = TestFs::builder().storage(os_storage).build();

        // ReadWrite remote configured with replication_log_dir still uses local disk ceiling.
        let mut rw_reg = RemoteRegistry::new();
        rw_reg.add_remote("s3", RemoteTargetConfig::new("backup-bucket"));
        test_fs.fs.replication_log_dir = Some(dir.path().to_path_buf());
        test_fs.fs.set_remote_registry(Arc::new(RwLock::new(rw_reg)));
        let host_space = statvfs_space(dir.path()).unwrap();
        let remote_stat = unwrap_statfs(statfs_response(&test_fs.fs, 1));
        let tolerance_blocks = (64 * 1024 * 1024) / STATFS_BLOCK_SIZE;
        assert!(remote_stat.bavail.abs_diff(host_space.avail_bytes / STATFS_BLOCK_SIZE) <= tolerance_blocks);

        // Missing backing directory falls back gracefully to virtual capacity.
        let missing_dir = dir.path().join("does_not_exist");
        assert!(statvfs_space(&missing_dir).is_err());
        test_fs.fs.set_log_dir(&missing_dir);
        let fallback_stat = unwrap_statfs(statfs_response(&test_fs.fs, 1));
        assert_eq!(fallback_stat.bfree, VIRTUAL_FREE_BLOCKS);
        assert_eq!(fallback_stat.bavail, VIRTUAL_FREE_BLOCKS);

        // Read-only mount reports zero free blocks and zero free inodes.
        let ino = test_fs.fs.create_file(1, "ro.txt", 0o644).unwrap();
        test_fs.fs.write_at(ino, b"hello", 0).unwrap();
        test_fs.fs.quiesce().unwrap();
        let expected_used = test_fs.fs.physical_log_bytes().div_ceil(STATFS_BLOCK_SIZE);
        test_fs.fs.set_read_only();
        let ro_stat = unwrap_statfs(statfs_response(&test_fs.fs, 1));
        assert_eq!(ro_stat.bfree, 0);
        assert_eq!(ro_stat.bavail, 0);
        assert_eq!(ro_stat.ffree, 0);
        assert_eq!(ro_stat.blocks, expected_used);
    }
}
