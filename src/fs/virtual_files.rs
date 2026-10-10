use crate::fs::AppendFs;
use crate::shim::{FileAttr, FileType};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

/// Base inode for synthesized virtual files.
/// Inode space starts at `0xFFFF_FFFF_0000_0001` to guarantee complete separation
/// from on-disk persisted inodes.
pub const VIRTUAL_INO_BASE: u64 = 0xFFFF_FFFF_0000_0001;

/// Dynamic content generator for a virtual file.
pub type VirtualFileGenerator = Arc<dyn Fn(&AppendFs) -> String + Send + Sync>;

/// Registration entry for a virtual file.
pub struct VirtualFileEntry {
    pub name: String,
    pub ino: u64,
    pub generator: VirtualFileGenerator,
}

/// Generic registry managing virtual control and telemetry files in the filesystem root (`/`).
#[derive(Default)]
pub struct VirtualFileRegistry {
    entries: RwLock<Vec<VirtualFileEntry>>,
    name_to_ino: RwLock<HashMap<String, u64>>,
    ino_to_idx: RwLock<HashMap<u64, usize>>,
    next_ino: AtomicU64,
}

/// Checks if an inode falls into the virtual inode range.
#[inline]
pub fn is_virtual_ino(ino: u64) -> bool {
    ino >= VIRTUAL_INO_BASE
}

impl VirtualFileRegistry {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(Vec::new()),
            name_to_ino: RwLock::new(HashMap::new()),
            ino_to_idx: RwLock::new(HashMap::new()),
            next_ino: AtomicU64::new(VIRTUAL_INO_BASE),
        }
    }

    /// Registers a new virtual file in the root directory.
    pub fn register<F>(&self, name: impl Into<String>, generator: F) -> u64
    where
        F: Fn(&AppendFs) -> String + Send + Sync + 'static,
    {
        let name = name.into();
        let mut name_map = self.name_to_ino.write().unwrap();
        if let Some(&existing_ino) = name_map.get(&name) {
            // Update existing generator
            let ino_idx = self.ino_to_idx.read().unwrap();
            if let Some(&idx) = ino_idx.get(&existing_ino) {
                let mut entries = self.entries.write().unwrap();
                entries[idx].generator = Arc::new(generator);
                return existing_ino;
            }
        }

        let ino = self.next_ino.fetch_add(1, Ordering::SeqCst);
        let mut entries = self.entries.write().unwrap();
        let idx = entries.len();

        entries.push(VirtualFileEntry {
            name: name.clone(),
            ino,
            generator: Arc::new(generator),
        });

        name_map.insert(name, ino);
        self.ino_to_idx.write().unwrap().insert(ino, idx);
        ino
    }

    /// Resolves an inode by name.
    pub fn get_ino_by_name(&self, name: &str) -> Option<u64> {
        self.name_to_ino.read().unwrap().get(name).copied()
    }

    /// Generates content for a virtual file by inode.
    pub fn generate_content(&self, ino: u64, fs: &AppendFs) -> Option<String> {
        let idx = *self.ino_to_idx.read().unwrap().get(&ino)?;
        let entries = self.entries.read().unwrap();
        let entry = entries.get(idx)?;
        Some((entry.generator)(fs))
    }

    /// Returns all registered root directory virtual entries `(name, ino)`.
    pub fn list_entries(&self) -> Vec<(String, u64)> {
        let entries = self.entries.read().unwrap();
        entries.iter().map(|e| (e.name.clone(), e.ino)).collect()
    }

    /// Builds a synthetic `FileAttr` for a virtual file.
    pub fn file_attr(&self, ino: u64, size: u64, now: SystemTime) -> FileAttr {
        FileAttr {
            ino,
            file_type: FileType::RegularFile,
            perm: 0o444, // read-only file
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            size: size as i64,
            atime: now,
            mtime: now,
            ctime: now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::FsError;
    use crate::operations::dir::{iter_dir_entries, list_dir_core};
    use crate::operations::links::{rename_core, unlink_core};
    use crate::operations::read_write::{
        create_core, fallocate_core, open_core, release_core, setattr_core, write_handle_core,
    };
    use crate::test_utils::FsTestExt;
    use crate::test_utils::TestFs;

    #[test]
    fn test_virtual_file_registry_crud() {
        let registry = VirtualFileRegistry::new();
        let ino = registry.register(".status", |_| "status: ok\n".to_string());

        assert!(is_virtual_ino(ino));
        assert!(!is_virtual_ino(1));
        assert_eq!(registry.get_ino_by_name(".status"), Some(ino));
        assert_eq!(registry.get_ino_by_name(".nonexistent"), None);

        let list = registry.list_entries();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0], (".status".to_string(), ino));

        let fs = TestFs::builder().build().fs;
        let content = registry.generate_content(ino, &fs).unwrap();
        assert_eq!(content, "status: ok\n");
    }

    #[test]
    fn test_virtual_file_handle_lifecycle_and_snapshot_isolation() {
        use std::sync::atomic::AtomicUsize;

        let fs = TestFs::builder().build().fs;
        let call_count = Arc::new(AtomicUsize::new(0));
        let count_clone = Arc::clone(&call_count);

        let v_ino = fs.virtual_files.register(".counter", move |_| {
            let n = count_clone.fetch_add(1, Ordering::SeqCst);
            format!("counter: {}\n", n)
        });

        // 1. Open first handle: freezes counter = 0
        let fh1 = fs.open_file_handle(v_ino, 0);
        assert!(fh1 > 0);

        // 2. Open second handle: freezes counter = 1
        let fh2 = fs.open_file_handle(v_ino, 0);
        assert!(fh2 > 0);

        // 3. Read sequentially through each handle: yields frozen content
        let data1 = fs.read_blocking(v_ino, fh1, 0, 100).unwrap();
        assert_eq!(data1, b"counter: 0\n");
        let data2 = fs.read_blocking(v_ino, fh2, 0, 100).unwrap();
        assert_eq!(data2, b"counter: 1\n");

        // 4. Invalid handle returns EBADF
        assert_eq!(fs.read_blocking(v_ino, 9999, 0, 100), Err(FsError::EBADF));

        // 5. Open a third handle: freezes counter = 2
        let fh3 = fs.open_file_handle(v_ino, 0);
        let data3 = fs.read_blocking(v_ino, fh3, 0, 100).unwrap();
        assert_eq!(data3, b"counter: 2\n");
        fs.release_file_handle(fh3, v_ino).unwrap();

        // 5. Release fh1: handle is freed and subsequent read returns EBADF
        fs.release_file_handle(fh1, v_ino).unwrap();
        assert_eq!(fs.read_blocking(v_ino, fh1, 0, 100), Err(FsError::EBADF));
        // fh2 remains untouched
        assert_eq!(fs.read_blocking(v_ino, fh2, 0, 100).unwrap(), b"counter: 1\n");

        fs.release_file_handle(fh2, v_ino).unwrap();
        assert_eq!(fs.read_blocking(v_ino, fh2, 0, 100), Err(FsError::EBADF));
    }

    #[test]
    fn test_root_directory_pagination_with_virtual_files() {
        let fs = TestFs::builder().build().fs;
        fs.register_remote_status();

        // Register two additional virtual files (along with default .remotes)
        let ino_v1 = fs.virtual_files.register(".virtual1", |_| "v1".to_string());
        let ino_v2 = fs.virtual_files.register(".virtual2", |_| "v2".to_string());

        // Create two regular files in root directory
        let f1 = create_core(&fs, 1, "file1.txt", 0o644, 0, 1000, 1000).unwrap();
        let f2 = create_core(&fs, 1, "file2.txt", 0o644, 0, 1000, 1000).unwrap();

        // Snapshot directory listing via list_dir_core
        let entries = list_dir_core(&fs, 1).unwrap();
        // Entries must contain: file1.txt, file2.txt, .remotes, .status, .virtual1, .virtual2
        assert_eq!(entries.len(), 6);
        assert!(entries.iter().any(|(name, ino)| name == "file1.txt" && *ino == f1.ino));
        assert!(entries.iter().any(|(name, ino)| name == "file2.txt" && *ino == f2.ino));
        assert!(entries.iter().any(|(name, _)| name == ".remotes"));
        assert!(entries.iter().any(|(name, _)| name == ".status"));
        assert!(entries.iter().any(|(name, ino)| name == ".virtual1" && *ino == ino_v1));
        assert!(entries.iter().any(|(name, ino)| name == ".virtual2" && *ino == ino_v2));

        // Test pagination through iter_dir_entries
        // Page 1: offset 0
        let items_all: Vec<_> = iter_dir_entries(&fs, 1, &entries, 0).collect();
        // Dot (1) + DotDot (1) + 6 entries = 8 items
        assert_eq!(items_all.len(), 8);
        assert_eq!(items_all[0].name, ".");
        assert_eq!(items_all[0].next_offset, 1);
        assert_eq!(items_all[1].name, "..");
        assert_eq!(items_all[1].next_offset, 2);

        // Verify get_attr resolves all items including virtual files!
        let inos: Vec<u64> = items_all.iter().map(|item| item.ino).collect();
        let mut unique_inos = std::collections::HashSet::new();
        let mut attrs_count = 0;
        for &ino in &inos {
            if unique_inos.insert(ino) && fs.get_attr(ino).is_some() {
                attrs_count += 1;
            }
        }
        assert_eq!(attrs_count, 7); // 1 (root) + 2 regular + 4 virtual

        // Page 2: simulate reading with offset = 2 (skip . and ..)
        let items_p2: Vec<_> = iter_dir_entries(&fs, 1, &entries, 2).collect();
        assert_eq!(items_p2.len(), 6);
        assert_eq!(items_p2[0].next_offset, 3);
        assert_eq!(items_p2[5].next_offset, 8);

        // Page 3: simulate reading with offset = 5 (middle of entries)
        let items_p3: Vec<_> = iter_dir_entries(&fs, 1, &entries, 5).collect();
        assert_eq!(items_p3.len(), 3);
        assert_eq!(items_p3[0].name, items_all[5].name);
        assert_eq!(items_p3[1].name, items_all[6].name);
        assert_eq!(items_p3[2].name, items_all[7].name);

        // Page 4: simulate end of directory offset = 8
        let items_end: Vec<_> = iter_dir_entries(&fs, 1, &entries, 8).collect();
        assert_eq!(items_end.len(), 0);
    }

    #[test]
    fn test_virtual_files_mutation_protection() {
        let fs = TestFs::builder().build().fs;
        fs.register_remote_status();
        let v_ino = fs.virtual_files.get_ino_by_name(".remotes").unwrap();

        // 1. Opening for writing is refused, and a write that arrives on a read-only handle
        //    anyway is rejected with EPERM
        assert_eq!(fs.write_at(v_ino, b"mutate", 0), Err(FsError::EACCES));
        let fh = open_core(&fs, v_ino, libc::O_RDONLY as u32).unwrap();
        assert_eq!(write_handle_core(&fs, v_ino, fh, b"mutate", 0), Err(FsError::EPERM));
        release_core(&fs, v_ino, fh).unwrap();

        // 2. Setattr is rejected with EPERM
        assert_eq!(
            setattr_core(&fs, v_ino, 0o777, 0, 0, 0, fs.clock.now(), fs.clock.now(), 0x1),
            Err(FsError::EPERM)
        );

        // 3. Fallocate is rejected with EPERM
        assert_eq!(
            fallocate_core(
                &fs,
                v_ino,
                libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                0,
                100
            ),
            Err(FsError::EPERM)
        );

        // 4. Unlink is rejected with EPERM
        assert_eq!(unlink_core(&fs, 1, ".remotes"), Err(FsError::EPERM));

        // 5. Rename is rejected with EPERM
        assert_eq!(rename_core(&fs, 1, ".remotes", 1, "renamed.txt"), Err(FsError::EPERM));

        // 6. Creating over an existing virtual file returns EEXIST
        assert_eq!(
            create_core(&fs, 1, ".remotes", 0o644, 0, 1000, 1000),
            Err(FsError::EEXIST)
        );

        // 7. Hardlinking a virtual file is rejected with EPERM
        assert_eq!(
            crate::operations::links::link_core(&fs, v_ino, 1, "link.txt"),
            Err(FsError::EPERM)
        );

        // 8. Xattr operations on virtual files are rejected / empty
        assert_eq!(
            crate::operations::xattr::setxattr_core(&fs, v_ino, "user.v", b"val", 0),
            Err(FsError::EPERM)
        );
        assert_eq!(
            crate::operations::xattr::removexattr_core(&fs, v_ino, "user.v"),
            Err(FsError::EPERM)
        );
        assert_eq!(
            crate::operations::xattr::getxattr_core(&fs, v_ino, "user.v", 0),
            Err(FsError::ENODATA)
        );
        assert_eq!(
            crate::operations::xattr::listxattr_core(&fs, v_ino, 0),
            Ok(crate::shim::FuseResponse::xattr_size(0))
        );

        // 9. Status virtual file has identical mutation protections
        let status_ino = fs.virtual_files.get_ino_by_name(".status").unwrap();
        assert_eq!(fs.write_at(status_ino, b"mutate", 0), Err(FsError::EACCES));
        assert_eq!(unlink_core(&fs, 1, ".status"), Err(FsError::EPERM));
        assert_eq!(rename_core(&fs, 1, ".status", 1, "renamed.txt"), Err(FsError::EPERM));
    }

    #[test]
    fn test_remotes_virtual_file_formatting_and_telemetry() {
        // A read-only mount has no log writer, so it reports no head generation.
        let mut read_only = TestFs::builder().build().fs;
        read_only.log_writer = None;
        read_only.set_read_only();
        read_only.register_remote_status();
        let v_ino = read_only.lookup_child(1, ".remotes").unwrap();
        let fh1 = read_only.open_file_handle(v_ino, 0);
        let initial_bytes = read_only.read_blocking(v_ino, fh1, 0, 4096).unwrap();
        let initial_status = String::from_utf8(initial_bytes).unwrap();
        read_only.release_file_handle(fh1, v_ino).unwrap();
        assert!(initial_status.contains("No remotes configured."));
        assert!(initial_status.contains("Volume Head Generation: None (read-only / detached log writer)"));

        // A read-write mount writes generation 1 next.
        let fs = TestFs::builder().build().fs;
        fs.register_remote_status();
        let v_ino = fs.lookup_child(1, ".remotes").unwrap();

        // Configure remotes
        let mut registry = crate::remote::config::RemoteRegistry::new();
        let mut nas_cfg = crate::remote::config::RemoteTargetConfig::new_path("/mnt/nas");
        nas_cfg.read_priority = 10;
        registry.add_remote("nas", nas_cfg);

        let mut s3_cfg = crate::remote::config::RemoteTargetConfig::new("backup-bucket");
        s3_cfg.read_priority = 100;
        s3_cfg.prefix = "logs/".to_string();
        registry.add_remote("s3", s3_cfg);

        fs.set_remote_registry(Arc::new(RwLock::new(registry)));

        // Record telemetry
        {
            let now = fs.clock.now();
            let mut telem = fs.replication_telemetry.write().unwrap();
            telem.record_synced_gen("nas", 1, now);
            telem.record_active_part("nas", 2, 3, now);
        }

        let fh2 = fs.open_file_handle(v_ino, 0);
        let updated_bytes = fs.read_blocking(v_ino, fh2, 0, 4096).unwrap();
        let updated_status = String::from_utf8(updated_bytes).unwrap();
        fs.release_file_handle(fh2, v_ino).unwrap();

        assert!(updated_status.contains("=== Remote Status (Volume Head Generation: 1) ==="));
        assert!(updated_status.contains("[Remote: nas]"));
        assert!(updated_status.contains("Target:             local/nfs (/mnt/nas)"));
        assert!(updated_status.contains("Read Priority:      10"));
        assert!(updated_status.contains("Status:             Up to date"));
        assert!(updated_status.contains("Active Part:        000002.part0003.log"));

        assert!(updated_status.contains("[Remote: s3]"));
        assert!(updated_status.contains("Target:             s3 (bucket: backup-bucket, prefix: logs/)"));
        assert!(updated_status.contains("Read Priority:      100"));
    }
}
