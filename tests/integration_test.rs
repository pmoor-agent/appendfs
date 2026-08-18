mod common;
use common::TestMount;
use std::fs;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[test]
fn test_fuse_filesystem() {
    let log_dir = tempfile::Builder::new().prefix("appendfs_test_log_").tempdir().unwrap();
    let mount_dir = tempfile::Builder::new().prefix("appendfs_test_").tempdir().unwrap();
    let mut mount = TestMount::mount_custom(log_dir, mount_dir, appendfs::InMemoryFS::new(), false);
    let mount_path = mount.path().to_path_buf();

    // Perform directory listing verification (should be empty initially)
    let entries: Vec<String> = fs::read_dir(&mount_path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_str().unwrap().to_string())
        .collect();
    assert!(entries.is_empty(), "Expected directory to be empty, got: {:?}", entries);

    // Verify statfs / statvfs reports root inode count (1)
    let path_c = std::ffi::CString::new(mount.path_str()).unwrap();
    let mut statvfs_buf: libc::statvfs = unsafe { std::mem::zeroed() };
    let res = unsafe { libc::statvfs(path_c.as_ptr(), &mut statvfs_buf) };
    assert_eq!(res, 0);
    assert_eq!(statvfs_buf.f_files, 1);

    // Create a new file (hello.txt)
    let file_hello = mount_path.join("hello.txt");
    assert!(!file_hello.exists());

    let content = "Hello world from dynamic FUSE!\n";
    fs::write(&file_hello, content).unwrap();
    assert!(file_hello.exists());

    let read_content = fs::read_to_string(&file_hello).unwrap();
    assert_eq!(read_content, content);

    // Verify file ownership (UID/GID) and initial permissions
    let meta = fs::metadata(&file_hello).unwrap();
    assert_eq!(meta.uid(), unsafe { libc::getuid() });
    assert_eq!(meta.gid(), unsafe { libc::getgid() });
    assert_eq!(meta.permissions().mode() & 0o777, 0o644);

    // Verify chmod (setattr mode)
    fs::set_permissions(&file_hello, fs::Permissions::from_mode(0o600)).unwrap();
    let updated_meta = fs::metadata(&file_hello).unwrap();
    assert_eq!(updated_meta.permissions().mode() & 0o777, 0o600);

    // Verify initial timestamps and custom timestamp update (setattr mtime/atime)
    let mtime_1 = meta.modified().unwrap();
    assert!(mtime_1 >= std::time::UNIX_EPOCH);

    let custom_time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
    let utimes_res = unsafe {
        let path_c = std::ffi::CString::new(file_hello.to_str().unwrap()).unwrap();
        let times = [
            libc::timeval {
                tv_sec: 1_700_000_000,
                tv_usec: 0,
            },
            libc::timeval {
                tv_sec: 1_700_000_000,
                tv_usec: 0,
            },
        ];
        libc::utimes(path_c.as_ptr(), times.as_ptr())
    };
    assert_eq!(utimes_res, 0);

    let updated_meta_time = fs::metadata(&file_hello).unwrap();
    assert_eq!(updated_meta_time.modified().unwrap(), custom_time);

    // Verify truncate / write at offset
    let file = fs::OpenOptions::new().write(true).open(&file_hello).unwrap();
    file.set_len(5).unwrap();
    drop(file);
    assert_eq!(fs::metadata(&file_hello).unwrap().len(), 5);
    assert_eq!(fs::read_to_string(&file_hello).unwrap(), "Hello");

    // Write beyond current size (create a sparse gap)
    {
        use std::io::Seek;
        let mut file = fs::OpenOptions::new().write(true).open(&file_hello).unwrap();
        file.seek(std::io::SeekFrom::Start(10)).unwrap();
        file.write_all(b"world!").unwrap();
    }
    assert_eq!(fs::metadata(&file_hello).unwrap().len(), 16);
    let bytes = fs::read(&file_hello).unwrap();
    assert_eq!(&bytes[0..5], b"Hello");
    assert_eq!(&bytes[5..10], &[0, 0, 0, 0, 0]); // sparse zero-fill
    assert_eq!(&bytes[10..16], b"world!");

    // Create a directory (subdir)
    let sub_dir = mount_path.join("subdir");
    assert!(!sub_dir.exists());
    fs::create_dir(&sub_dir).unwrap();
    assert!(sub_dir.exists());
    assert!(sub_dir.is_dir());

    // Create nested file (subdir/nested.txt)
    let nested_file = sub_dir.join("nested.txt");
    fs::write(&nested_file, "nested content").unwrap();
    assert!(nested_file.exists());
    assert_eq!(fs::read_to_string(&nested_file).unwrap(), "nested content");

    // Test directory listing of root
    let root_entries: Vec<String> = fs::read_dir(&mount_path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_str().unwrap().to_string())
        .collect();
    assert!(root_entries.contains(&"hello.txt".to_string()));
    assert!(root_entries.contains(&"subdir".to_string()));

    // Test directory listing of subdir
    let sub_entries: Vec<String> = fs::read_dir(&sub_dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_str().unwrap().to_string())
        .collect();
    assert_eq!(sub_entries, vec!["nested.txt".to_string()]);

    // Test rename (hello.txt -> hello_renamed.txt)
    let file_renamed = mount_path.join("hello_renamed.txt");
    fs::rename(&file_hello, &file_renamed).unwrap();
    assert!(!file_hello.exists());
    assert!(file_renamed.exists());
    assert_eq!(fs::read(&file_renamed).unwrap(), bytes);

    // Test moving across directories (hello_renamed.txt -> subdir/moved.txt)
    let file_moved = sub_dir.join("moved.txt");
    fs::rename(&file_renamed, &file_moved).unwrap();
    assert!(!file_renamed.exists());
    assert!(file_moved.exists());
    assert_eq!(fs::read(&file_moved).unwrap(), bytes);

    // Test symlink (subdir/sym -> moved.txt)
    let symlink_path = sub_dir.join("sym");
    std::os::unix::fs::symlink("moved.txt", &symlink_path).unwrap();
    assert!(symlink_path.exists());
    assert_eq!(
        fs::read_link(&symlink_path).unwrap(),
        std::path::PathBuf::from("moved.txt")
    );
    assert_eq!(fs::read(&symlink_path).unwrap(), bytes);

    // Test hard link (subdir/moved.txt -> hello_hard.txt in root)
    let file_hard = mount_path.join("hello_hard.txt");
    fs::hard_link(&file_moved, &file_hard).unwrap();
    assert!(file_hard.exists());
    let meta_moved = fs::metadata(&file_moved).unwrap();
    let meta_hard = fs::metadata(&file_hard).unwrap();
    assert_eq!(meta_moved.ino(), meta_hard.ino());
    assert_eq!(meta_moved.nlink(), 2);
    assert_eq!(meta_hard.nlink(), 2);

    // Write through hard link, read from original
    fs::write(&file_hard, "Modified via link!").unwrap();
    assert_eq!(fs::read_to_string(&file_moved).unwrap(), "Modified via link!");

    // Test unlink nested file
    fs::remove_file(&nested_file).unwrap();
    assert!(!nested_file.exists());

    // Test unlink symlink
    fs::remove_file(&symlink_path).unwrap();
    assert!(!symlink_path.exists());

    // Test rmdir failure on non-empty directory
    let rmdir_err = fs::remove_dir(&sub_dir);
    assert!(rmdir_err.is_err());

    // Remove moved.txt to make subdir empty
    fs::remove_file(&file_moved).unwrap();
    assert!(!file_moved.exists());

    // Test rmdir success on empty directory
    fs::remove_dir(&sub_dir).unwrap();
    assert!(!sub_dir.exists());

    // Assert hello.txt is gone
    assert!(!file_hello.exists());

    // Assert hello_hard.txt still exists, has nlink 1, and can be read/written
    assert!(file_hard.exists());
    let meta_hard = fs::metadata(&file_hard).unwrap();
    assert_eq!(meta_hard.nlink(), 1);
    assert_eq!(fs::read_to_string(&file_hard).unwrap(), "Modified via link!");

    // Verify fsync support by calling sync_all on a file handle
    {
        use std::fs::OpenOptions;
        let file = OpenOptions::new().write(true).open(&file_hard).unwrap();
        file.sync_data().unwrap();
        file.sync_all().unwrap();
    }

    // Verify fsyncdir support using opendir/dirfd/fsync (the only way to trigger FUSE fsyncdir)
    {
        use std::ffi::CString;
        let dir_path = CString::new(mount.path_str()).unwrap();
        unsafe {
            let dirp = libc::opendir(dir_path.as_ptr());
            assert!(!dirp.is_null(), "opendir failed");
            let fd = libc::dirfd(dirp);
            assert!(fd >= 0, "dirfd failed");
            let rc = libc::fsync(fd);
            assert_eq!(rc, 0, "fsync on dir fd failed: {}", std::io::Error::last_os_error());
            let rc = libc::fdatasync(fd);
            assert_eq!(rc, 0, "fdatasync on dir fd failed: {}", std::io::Error::last_os_error());
            libc::closedir(dirp);
        }
    }

    // Cleanup hello_hard.txt
    fs::remove_file(&file_hard).unwrap();
    assert!(!file_hard.exists());
    // Verify directory is empty again
    let entries_after: Vec<String> = fs::read_dir(&mount_path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_str().unwrap().to_string())
        .collect();
    assert!(
        entries_after.is_empty(),
        "Expected directory to be empty after deletion, got: {:?}",
        entries_after
    );

    // Verify non-UTF8 filename lookup returns ENOENT without panicking
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let mut non_utf8_path = mount_path.as_os_str().as_bytes().to_vec();
        non_utf8_path.push(b'/');
        non_utf8_path.extend_from_slice(b"bad_\xff\xfe_file.txt");
        let c_path = CString::new(non_utf8_path).unwrap();
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        let res = unsafe { libc::stat(c_path.as_ptr(), st.as_mut_ptr()) };
        assert_eq!(res, -1);
        assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::ENOENT));
    }

    mount.unmount();
}

#[test]
fn test_fuse_with_log_writer() {
    let clock = appendfs::SystemClock;
    let log_dir = tempfile::Builder::new().prefix("appendfs_log_dir_").tempdir().unwrap();

    let writer = Arc::new(appendfs::LogWriter::create(log_dir.path(), 1, &clock).unwrap());
    let fs = appendfs::InMemoryFS::with_log(Arc::clone(&writer));

    let mount_dir = tempfile::Builder::new()
        .prefix("appendfs_log_mount_")
        .tempdir()
        .unwrap();
    let mut mount = TestMount::mount_custom(log_dir, mount_dir, fs, false);
    let mount_path = mount.path().to_path_buf();

    // Perform operations on mounted filesystem
    let sub_dir = mount_path.join("docs");
    fs::create_dir(&sub_dir).unwrap();

    let file_path = sub_dir.join("logged_file.txt");
    let content = "Testing persistent appendfs logging engine!";
    fs::write(&file_path, content).unwrap();

    let read_back = fs::read_to_string(&file_path).unwrap();
    assert_eq!(read_back, content);

    // Call sync to trigger log flush to LogWriter disk file
    let file = fs::OpenOptions::new().write(true).open(&file_path).unwrap();
    file.sync_data().unwrap();
    drop(file);

    // Verify .log file exists in log_dir and has size > FILE_HEADER_SIZE (24 bytes)
    let log_file_path = mount.log_path.join("000001.log");
    assert!(log_file_path.exists());
    let log_size = fs::metadata(&log_file_path).unwrap().len();
    assert!(
        log_size > 24,
        "Log file should contain logged record entries beyond header, size = {}",
        log_size
    );

    mount.unmount();
}

#[test]
fn test_recovery_after_remount() {
    let mut mount = TestMount::new_rw();
    let mount_path = mount.path().to_path_buf();

    // Perform mutations
    let sub_dir = mount_path.join("photos");
    fs::create_dir(&sub_dir).unwrap();

    let photo1 = sub_dir.join("vacation.png");
    fs::write(&photo1, "RAW_PHOTO_DATA_123456789").unwrap();

    let symlink_path = mount_path.join("fav_photo.png");
    std::os::unix::fs::symlink("photos/vacation.png", &symlink_path).unwrap();

    // Flush and sync to disk
    let f = fs::OpenOptions::new().write(true).open(&photo1).unwrap();
    f.sync_data().unwrap();
    drop(f);

    // Remount generation 2
    mount.remount_rw();

    // Verify recovered filesystem contents
    let recovered_photo = mount.path().join("photos").join("vacation.png");
    assert!(recovered_photo.exists());
    let data = fs::read_to_string(&recovered_photo).unwrap();
    assert_eq!(data, "RAW_PHOTO_DATA_123456789");

    let recovered_symlink = mount.path().join("fav_photo.png");
    assert!(recovered_symlink.exists());
    let target = fs::read_link(&recovered_symlink).unwrap();
    assert_eq!(target.to_str().unwrap(), "photos/vacation.png");
}

#[test]
fn test_fuse_stress() {
    let log_dir = tempfile::Builder::new()
        .prefix("appendfs_stress_log_")
        .tempdir()
        .unwrap();
    let mount_dir = tempfile::Builder::new().prefix("appendfs_test_").tempdir().unwrap();
    let mut mount = TestMount::mount_custom(log_dir, mount_dir, appendfs::InMemoryFS::new(), false);
    let mount_path = mount.path().to_path_buf();

    // Create 4 subdirectories for the threads
    for i in 0..4 {
        let subdir = mount_path.join(format!("dir_{}", i));
        fs::create_dir(&subdir).unwrap();
        assert!(subdir.is_dir());
    }

    // Spawn 4 writer threads
    let mut threads = Vec::new();
    for thread_idx in 0..4 {
        let mount_path_clone = mount_path.clone();
        let writer = thread::spawn(move || {
            let subdir = mount_path_clone.join(format!("dir_{}", thread_idx));
            for iter_idx in 0..50 {
                let file_path = subdir.join(format!("file_{}.txt", iter_idx));
                let expected_content = format!("thread {} iteration {}", thread_idx, iter_idx);

                // Write the file
                fs::write(&file_path, &expected_content).unwrap();

                // Read and verify
                let read_content = fs::read_to_string(&file_path).unwrap();
                assert_eq!(read_content, expected_content);

                // Delete the file
                fs::remove_file(&file_path).unwrap();
                assert!(!file_path.exists());
            }
        });
        threads.push(writer);
    }

    // Spawn a 5th reader thread that lists directories concurrently
    let mount_path_clone = mount_path.clone();
    let reader = thread::spawn(move || {
        for iter_idx in 0..20 {
            thread::sleep(Duration::from_millis(10));
            // Read target thread dir
            let target_dir = mount_path_clone.join(format!("dir_{}", iter_idx % 4));
            if let Ok(entries) = fs::read_dir(&target_dir) {
                // Just iterate over them to trigger readdir/lookup calls
                for entry in entries {
                    let _ = entry;
                }
            }
            // List root directory
            if let Ok(entries) = fs::read_dir(&mount_path_clone) {
                for entry in entries {
                    let _ = entry;
                }
            }
        }
    });
    threads.push(reader);

    // Wait for all threads to finish
    for t in threads {
        t.join().unwrap();
    }

    // Clean up: remove subdirectories and assert empty
    for i in 0..4 {
        let subdir = mount_path.join(format!("dir_{}", i));

        // Assert directory is empty
        let entries: Vec<String> = fs::read_dir(&subdir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_str().unwrap().to_string())
            .collect();
        assert!(
            entries.is_empty(),
            "Expected directory dir_{} to be empty, got: {:?}",
            i,
            entries
        );

        // Remove directory
        fs::remove_dir(&subdir).unwrap();
        assert!(!subdir.exists());
    }

    mount.unmount();
}

#[test]
fn test_log_rolling() {
    let clock: Arc<dyn appendfs::clock::Clock> = Arc::new(appendfs::clock::SystemClock);

    let log_dir = tempfile::Builder::new()
        .prefix("appendfs_rolling_logs_")
        .tempdir()
        .unwrap();
    let log_path = log_dir.path().to_path_buf();

    // Create a LogWriter with a tiny max_log_size of 512 bytes to force rolling
    let writer = Arc::new(appendfs::LogWriter::create_with_max_size(&log_path, 1, &*clock, 512).unwrap());

    let mut fs_instance = appendfs::InMemoryFS::with_clock_and_log(Arc::clone(&clock), Some(Arc::clone(&writer)));
    fs_instance.set_log_dir(&log_path);

    let mount_dir = tempfile::Builder::new()
        .prefix("appendfs_rolling_mount_")
        .tempdir()
        .unwrap();
    let mut mount = TestMount::mount_custom(log_dir, mount_dir, fs_instance, false);
    let mount_path = mount.path().to_path_buf();

    // Write enough data to force multiple generation rolls (512 bytes threshold).
    for i in 1..=5 {
        let file_path = mount_path.join(format!("chunk_{}.txt", i));
        let content = format!("LOG_ROLLING_PAYLOAD_{}_DATA_{}", i, "X".repeat(200));
        let file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&file_path)
            .unwrap();
        (&file).write_all(content.as_bytes()).unwrap();
        file.sync_all().unwrap();
        drop(file);

        // Read back data to verify read path across generations
        let read_back = fs::read_to_string(&file_path).unwrap();
        assert_eq!(read_back, content);
    }

    // Unmount initial filesystem to trigger unmount log sync
    mount.unmount();

    // Count generated .log files in log_path
    let mut log_files = Vec::new();
    for entry in fs::read_dir(&log_path).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("log") {
            log_files.push(path);
        }
    }

    assert!(
        log_files.len() > 1,
        "Expected log rolling to create multiple .log files, found: {}",
        log_files.len()
    );

    // Verify recovery across all rolled generation log files
    let recovered_fs = appendfs::recover_fs(&log_path).unwrap();
    let mount_dir_rec = tempfile::Builder::new()
        .prefix("appendfs_rolling_rec_mount_")
        .tempdir()
        .unwrap();
    let dummy_log = tempfile::Builder::new()
        .prefix("appendfs_dummy_log_")
        .tempdir()
        .unwrap();
    let mut mount_rec = TestMount::mount_custom(dummy_log, mount_dir_rec, recovered_fs, false);

    for i in 1..=5 {
        let file_path = mount_rec.path().join(format!("chunk_{}.txt", i));
        let expected_content = format!("LOG_ROLLING_PAYLOAD_{}_DATA_{}", i, "X".repeat(200));
        assert!(file_path.exists());
        let read_back = fs::read_to_string(&file_path).unwrap();
        assert_eq!(read_back, expected_content);
    }

    mount_rec.unmount();
}

#[test]
fn test_summary_single_file_export_and_recovery() {
    let clock: Arc<dyn appendfs::clock::Clock> = Arc::new(appendfs::clock::SystemClock);

    let log_dir = tempfile::Builder::new()
        .prefix("appendfs_summary_logs_")
        .tempdir()
        .unwrap();
    let log_path = log_dir.path().to_path_buf();

    let writer = Arc::new(appendfs::LogWriter::create(&log_path, 1, &*clock).unwrap());

    let mut fs_instance = appendfs::InMemoryFS::with_clock_and_log(Arc::clone(&clock), Some(Arc::clone(&writer)));
    fs_instance.set_log_dir(&log_path);

    let mount_dir = tempfile::Builder::new()
        .prefix("appendfs_summary_mount_")
        .tempdir()
        .unwrap();
    let mut mount = TestMount::mount_custom(log_dir, mount_dir, fs_instance, false);
    let mount_path = mount.path().to_path_buf();

    // Populate filesystem with initial structure
    let docs_dir = mount_path.join("docs");
    fs::create_dir(&docs_dir).unwrap();

    let file1 = docs_dir.join("file1.txt");
    fs::write(&file1, "SNAPSHOT_FILE_1_CONTENT").unwrap();

    let file2 = docs_dir.join("file2.txt");
    fs::write(&file2, "SNAPSHOT_FILE_2_CONTENT").unwrap();

    // Unmount initial filesystem to flush log buffer to disk
    mount.unmount();

    // Recover filesystem state from log and export single-file summary snapshot (000001.summary)
    let summary_file_path = log_path.join("000001.summary");
    let fs_tmp = appendfs::recover_fs(&log_path).unwrap();
    let summary_path = fs_tmp.export_summary(&log_path).unwrap();

    assert!(summary_path.exists());
    assert_eq!(summary_path, summary_file_path);

    // Inspect summary snapshot using SummaryReader
    let reader = appendfs::SummaryReader::open(&summary_path).unwrap();
    assert_eq!(reader.header.generation, 1);
    assert_eq!(reader.footer.entry_count, 4); // root (1), docs dir (2), file1 (3), file2 (4)

    // Perform O(log N) binary search lookups on index entries
    let index_entries = reader.index_entries().to_vec();
    for entry in &index_entries {
        let node_opt = reader.read_node(entry.inode).unwrap();
        assert!(node_opt.is_some());
    }

    // Verify recovery: recover_fs should fast-load state from 000001.summary
    let recovered_fs = appendfs::recover_fs(&log_path).unwrap();

    let mount_dir_rec = tempfile::Builder::new()
        .prefix("appendfs_summary_rec_mount_")
        .tempdir()
        .unwrap();
    let dummy_log_rec = tempfile::Builder::new()
        .prefix("appendfs_dummy_log_")
        .tempdir()
        .unwrap();
    let mut mount_rec = TestMount::mount_custom(dummy_log_rec, mount_dir_rec, recovered_fs, false);

    let rec_file1 = mount_rec.path().join("docs").join("file1.txt");
    assert!(rec_file1.exists());
    assert_eq!(fs::read_to_string(&rec_file1).unwrap(), "SNAPSHOT_FILE_1_CONTENT");

    let rec_file2 = mount_rec.path().join("docs").join("file2.txt");
    assert!(rec_file2.exists());
    assert_eq!(fs::read_to_string(&rec_file2).unwrap(), "SNAPSHOT_FILE_2_CONTENT");

    mount_rec.unmount();
}

#[test]
fn test_large_directory_readdir_and_readdirplus() {
    let dummy_log = tempfile::Builder::new()
        .prefix("appendfs_dummy_log_")
        .tempdir()
        .unwrap();
    let temp_dir = tempfile::Builder::new()
        .prefix("appendfs_large_dir_")
        .tempdir()
        .unwrap();
    let mut mount = TestMount::mount_custom(dummy_log, temp_dir, appendfs::InMemoryFS::new(), false);
    let mount_path = mount.path().to_path_buf();

    let large_dir = mount_path.join("large_dir");
    fs::create_dir(&large_dir).unwrap();

    let num_files = 1500;
    for i in 0..num_files {
        let file_path = large_dir.join(format!("file_{:05}.txt", i));
        fs::write(&file_path, format!("data_{}", i)).unwrap();
    }

    // Test readdir / readdirplus with standard Rust read_dir
    let mut read_entries = Vec::new();
    for entry in fs::read_dir(&large_dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().into_string().unwrap();
        let meta = entry.metadata().unwrap();
        assert!(meta.is_file());
        read_entries.push(name);
    }
    read_entries.sort();
    assert_eq!(read_entries.len(), num_files);
    for (i, entry) in read_entries.iter().enumerate().take(num_files) {
        assert_eq!(entry, &format!("file_{:05}.txt", i));
    }

    // Test with command line `ls -la`
    let output = Command::new("ls").arg("-la").arg(&large_dir).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("file_00000.txt"));
    assert!(stdout.contains("file_01499.txt"));

    mount.unmount();
}

#[test]
fn test_manifest_and_live_stats_across_fuse_mount_and_recovery() {
    let clock = Arc::new(appendfs::SystemClock);
    let log_dir = tempfile::Builder::new()
        .prefix("appendfs_manifest_log_")
        .tempdir()
        .unwrap();
    let log_path = log_dir.path().to_path_buf();

    // 2KB max log size to trigger rolling across writes
    let writer = Arc::new(appendfs::LogWriter::create_with_max_size(&log_path, 1, &*clock, 2048).unwrap());
    let fs = appendfs::InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));

    let temp_dir = tempfile::Builder::new()
        .prefix("appendfs_manifest_mount_")
        .tempdir()
        .unwrap();
    let mut mount = TestMount::mount_custom(log_dir, temp_dir, fs, false);
    let mount_path = mount.path().to_path_buf();

    // Helper function to write and fsync
    let write_and_sync = |path: &std::path::Path, data: &[u8]| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .unwrap();
        file.write_all(data).unwrap();
        file.sync_all().unwrap();
        drop(file);
    };

    // Write file1 (1KB) in gen 1
    let file1 = mount_path.join("file1.bin");
    write_and_sync(&file1, &vec![0x11; 1000]);

    // Write file2 (1.5KB) -> forces rolling to generation 2
    let file2 = mount_path.join("file2.bin");
    write_and_sync(&file2, &vec![0x22; 1500]);

    // Write file3 (1.5KB) -> forces rolling to generation 3
    let file3 = mount_path.join("file3.bin");
    write_and_sync(&file3, &vec![0x33; 1500]);

    // Overwrite file1 completely with 500 bytes -> gen 1 now has 0 live bytes!
    write_and_sync(&file1, &vec![0x99; 500]);

    mount.unmount();

    // Recover filesystem
    let recovered_fs = appendfs::recover_fs(&log_path).unwrap();
    let stats = recovered_fs.calculate_generation_live_stats();

    assert!(stats.len() >= 3, "Expected at least 3 generations");
    // Gen 1 file1 was overwritten in gen 3, so gen 1 live_bytes is 0!
    let gen1 = stats.iter().find(|s| s.generation == 1).unwrap();
    assert_eq!(gen1.live_bytes, 0);
    assert_eq!(gen1.live_ratio, 0.0);

    // Gen 2 (file2) is fully live
    let gen2 = stats.iter().find(|s| s.generation == 2).unwrap();
    assert_eq!(gen2.live_bytes, 1500);
    assert_eq!(gen2.live_extents, 1);
    assert!((gen2.live_ratio - 1.0).abs() < 1e-6);
}

#[test]
fn test_volume_init_mount_and_stats_flow() {
    let clock = Arc::new(appendfs::SystemClock);
    let log_dir = tempfile::Builder::new().prefix("appendfs_init_vol_").tempdir().unwrap();
    let log_path = log_dir.path().to_path_buf();

    // 1. Explicitly initialize empty volume
    let summary_path = appendfs::init_volume(&log_path, Some("work")).unwrap();
    assert!(summary_path.exists());
    assert_eq!(summary_path.file_name().unwrap(), "000000.summary");

    // 2. Mount initialized volume
    let mut fs_instance = appendfs::recover_fs(&log_path).unwrap();
    let next_gen = fs_instance.manifest.read().unwrap().next_generation;
    assert_eq!(next_gen, 1);

    let writer =
        Arc::new(appendfs::LogWriter::create_with_max_size(&log_path, next_gen, &*clock, 1024 * 1024).unwrap());
    fs_instance.log_writer = Some(Arc::clone(&writer));
    fs_instance.set_log_dir(&log_path);

    let temp_dir = tempfile::Builder::new()
        .prefix("appendfs_init_mount_")
        .tempdir()
        .unwrap();
    let dummy_log = tempfile::Builder::new()
        .prefix("appendfs_dummy_log_")
        .tempdir()
        .unwrap();
    let mut mount = TestMount::mount_custom(dummy_log, temp_dir, fs_instance, false);
    let mount_path = mount.path().to_path_buf();

    // Create a directory and file
    let docs = mount_path.join("docs");
    fs::create_dir(&docs).unwrap();
    let note = docs.join("note.txt");
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&note)
            .unwrap();
        file.write_all(b"hello appendfs volume").unwrap();
        file.sync_all().unwrap();
    }

    // 3. Inspect volume with stats WHILE THE FUSE MOUNT IS ACTIVELY RUNNING
    {
        let live_recovered_fs = appendfs::recover_fs(&log_path).unwrap();
        let live_stats = appendfs::VolumeStats::collect(&live_recovered_fs);
        assert_eq!(live_stats.branch, "work");
        assert_eq!(live_stats.total_inodes, 3);
        assert_eq!(live_stats.directory_count, 2);
        assert_eq!(live_stats.file_count, 1);
        assert_eq!(live_stats.total_logical_bytes, 21);
    }

    // Unmount
    mount.unmount();

    // 4. Inspect volume with stats after clean unmount
    let recovered_fs = appendfs::recover_fs(&log_path).unwrap();
    let stats = appendfs::VolumeStats::collect(&recovered_fs);

    assert_eq!(stats.branch, "work");
    assert_eq!(stats.total_inodes, 3); // root (1) + docs (2) + note.txt (3)
    assert_eq!(stats.directory_count, 2);
    assert_eq!(stats.file_count, 1);
    assert_eq!(stats.symlink_count, 0);
    assert_eq!(stats.total_logical_bytes, 21);

    let display = stats.display_text();
    assert!(display.contains("Branch:              work"));
    assert!(display.contains("Total Inodes:        3 (2 directories, 1 files, 0 symlinks)"));
    assert!(display.contains("000001.log"));

    // 5. Test dump command on the generated 000001.log file
    let log_file = log_path.join("000001.log");
    assert!(log_file.exists());

    // Summary level (verbosity 0)
    let dump_v0 = appendfs::dump_log_file(&log_file, 0).unwrap();
    assert!(dump_v0.contains("File Size:"));
    assert!(dump_v0.contains("Committed Flushes:"));
    assert!(dump_v0.contains("Trailing Batch:      None"));
    assert!(dump_v0.contains("Create"));
    assert!(dump_v0.contains("Write"));

    // Record stream level (verbosity 1)
    let dump_v1 = appendfs::dump_log_file(&log_file, 1).unwrap();
    assert!(dump_v1.contains("Create"));
    assert!(dump_v1.contains("Write"));
    assert!(dump_v1.contains("note.txt"));
    assert!(dump_v1.contains("[COMMITTED]"));

    // Full hex payload level (verbosity 2)
    let dump_v2 = appendfs::dump_file(&log_file, 2).unwrap();
    assert!(dump_v2.contains("hello appendfs v"));
    assert!(dump_v2.contains("olume"));

    // 6. Test dump command on the initial summary file 000000.summary
    let summary_file = log_path.join("000000.summary");
    assert!(summary_file.exists());
    let dump_sum_v0 = appendfs::dump_file(&summary_file, 0).unwrap();
    assert!(dump_sum_v0.contains("=== appendfs Summary File Dump ==="));
    assert!(dump_sum_v0.contains("Branch:              work"));
    assert!(dump_sum_v0.contains("Total Inodes:        1"));
    assert!(dump_sum_v0.contains("Checksum (BLAKE3):"));
    assert!(dump_sum_v0.contains("VERIFIED"));

    let dump_sum_v1 = appendfs::dump_file(&summary_file, 1).unwrap();
    assert!(dump_sum_v1.contains("Summary Inode Records"));
    assert!(dump_sum_v1.contains("Directory  \"/\""));
}

#[test]
fn test_lazy_log_creation_and_clean_read_only_unmount() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path();

    // 1. Initialize volume
    appendfs::init_volume(log_path, Some("main")).unwrap();

    // Verify only 000000.summary exists
    let files: Vec<_> = std::fs::read_dir(log_path)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    assert_eq!(files, vec!["000000.summary"]);

    // 2. Simulate Mount 1: Read-only mount session
    {
        let mut fs = appendfs::recover_fs(log_path).unwrap();
        let writer = std::sync::Arc::new(
            appendfs::LogWriter::create_lazy(log_path, 1, appendfs::cli::DEFAULT_MAX_LOG_SIZE, 1).unwrap(),
        );
        fs.log_writer = Some(writer);
        fs.set_log_dir(log_path);

        // Perform read-only operations
        let root_entries = fs.list_directory(1).unwrap();
        assert_eq!(root_entries.len(), 0);

        // Drop fs (simulating unmount)
    }

    // Assert that the log directory remains 100% clean and untouched (ignoring .lock)!
    let mut files_after_ro: Vec<_> = std::fs::read_dir(log_path)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .filter(|f| f != ".lock")
        .collect();
    files_after_ro.sort();
    assert_eq!(files_after_ro, vec!["000000.summary"]);

    // 3. Simulate Mount 2: Mutation session
    {
        let mut fs = appendfs::recover_fs(log_path).unwrap();
        let writer = std::sync::Arc::new(
            appendfs::LogWriter::create_lazy(log_path, 1, appendfs::cli::DEFAULT_MAX_LOG_SIZE, 1).unwrap(),
        );
        fs.log_writer = Some(writer);
        fs.set_log_dir(log_path);

        // Create directory and file
        let dir_attr = appendfs::operations::dir::mkdir_core(&fs, 1, "testdir", 0o755, 1000, 1000).unwrap();
        let file_attr =
            appendfs::operations::read_write::create_core(&fs, dir_attr.ino, "data.txt", 0o644, 0, 1000, 1000).unwrap();
        appendfs::operations::read_write::write_core(&fs, file_attr.ino, b"hello lazy log", 0).unwrap();

        // Flush & unmount
        fs.sync_log().unwrap();
    }

    // Assert that 000001.log and 000001.summary were created cleanly
    let mut files_after_write: Vec<_> = std::fs::read_dir(log_path)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .filter(|f| f != ".lock")
        .collect();
    files_after_write.sort();
    assert_eq!(
        files_after_write,
        vec!["000000.summary", "000001.log", "000001.summary"]
    );

    // 4. Verify recovery restores the written state
    let recovered = appendfs::recover_fs(log_path).unwrap();
    let root_entries = recovered.list_directory(1).unwrap();
    assert_eq!(root_entries.len(), 1);
    assert_eq!(root_entries[0].0, "testdir");
}

#[test]
fn test_bulk_metadata_rm_rf_triggers_automatic_flush() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path();

    appendfs::init_volume(log_path, Some("main")).unwrap();

    let mut fs = appendfs::recover_fs(log_path).unwrap();
    let writer = std::sync::Arc::new(
        appendfs::LogWriter::create_lazy(log_path, 1, appendfs::cli::DEFAULT_MAX_LOG_SIZE, 1).unwrap(),
    );
    fs.log_writer = Some(writer);
    fs.set_log_dir(log_path);
    // Set threshold to 10 operations
    fs.max_staged_ops = 10;

    // 1. Create a tree with 1 directory and 15 files
    let dir_attr = appendfs::operations::dir::mkdir_core(&fs, 1, "bigdir", 0o755, 1000, 1000).unwrap();
    let mut file_names = Vec::new();
    for i in 0..15 {
        let name = format!("f_{}.txt", i);
        appendfs::operations::read_write::create_core(&fs, dir_attr.ino, &name, 0o644, 0, 1000, 1000).unwrap();
        file_names.push(name);
    }

    // 2. Perform rm -rf (15 unlinks + 1 rmdir)
    for name in &file_names {
        appendfs::operations::links::unlink_core(&fs, dir_attr.ino, name).unwrap();
    }
    appendfs::operations::dir::rmdir_core(&fs, 1, "bigdir").unwrap();

    // Verify that the manifest records flushes triggered automatically by operation count!
    let manifest = fs.manifest.read().unwrap();
    assert!(!manifest.logs.is_empty());
    let total_records: u32 = manifest.logs.iter().map(|l| l.record_count).sum();
    assert!(
        total_records > 0,
        "metadata unlinks must have been automatically flushed to log"
    );
}

#[test]
fn test_background_flusher_in_mount_session() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path();

    appendfs::init_volume(log_path, Some("main")).unwrap();

    let mut fs = appendfs::recover_fs(log_path).unwrap();
    let writer = std::sync::Arc::new(
        appendfs::LogWriter::create_lazy(log_path, 1, appendfs::cli::DEFAULT_MAX_LOG_SIZE, 1).unwrap(),
    );
    fs.log_writer = Some(writer);
    fs.set_log_dir(log_path);
    // Set 1-second flush interval and high op threshold so automatic threshold does not trigger
    fs.max_staged_ops = 10_000;
    fs.flush_interval.store(1, std::sync::atomic::Ordering::SeqCst);

    let fs = std::sync::Arc::new(fs);
    fs.init();

    // Perform only 2 operations
    let dir_attr = appendfs::operations::dir::mkdir_core(&fs, 1, "periodic_dir", 0o755, 1000, 1000).unwrap();
    appendfs::operations::read_write::create_core(&fs, dir_attr.ino, "periodic_file.txt", 0o644, 0, 1000, 1000)
        .unwrap();

    // Staged ops should be 2 initially
    assert_eq!(fs.staged_ops.load(std::sync::atomic::Ordering::SeqCst), 2);

    // Sleep for 1.3 seconds so background flusher fires
    std::thread::sleep(std::time::Duration::from_millis(1300));

    // Staged ops should have been flushed to 0 by the background flusher
    assert_eq!(fs.staged_ops.load(std::sync::atomic::Ordering::SeqCst), 0);
    let manifest = fs.manifest.read().unwrap();
    assert!(!manifest.logs.is_empty());
    assert!(manifest.logs[0].record_count > 0);

    fs.destroy();
}

#[test]
fn test_check_volume_identifies_clean_and_orphaned_volume() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path();

    appendfs::init_volume(log_path, Some("main")).unwrap();

    let mut fs = appendfs::recover_fs(log_path).unwrap();
    let writer = std::sync::Arc::new(
        appendfs::LogWriter::create_lazy(log_path, 1, appendfs::cli::DEFAULT_MAX_LOG_SIZE, 1).unwrap(),
    );
    fs.log_writer = Some(writer);
    fs.set_log_dir(log_path);

    // 1. Populate valid filesystem tree
    let d = appendfs::operations::dir::mkdir_core(&fs, 1, "sub", 0o755, 1000, 1000).unwrap();
    let f1 = appendfs::operations::read_write::create_core(&fs, d.ino, "hello.txt", 0o644, 0, 1000, 1000).unwrap();
    appendfs::operations::read_write::write_core(&fs, f1.ino, b"integrity test data", 0).unwrap();
    let _l = appendfs::operations::links::link_core(&fs, f1.ino, 1, "hardlink.txt").unwrap();

    fs.sync_log().unwrap();

    // 2. Check clean volume
    let report = appendfs::check_volume(log_path, true).unwrap();
    assert!(report.is_clean(), "Clean volume must pass check: {:?}", report.issues);
    assert_eq!(report.error_count(), 0);
    assert_eq!(report.orphaned_inodes.len(), 0);
    assert_eq!(report.directories, 2);
    assert_eq!(report.regular_files, 1);

    let output = report.format_report(Some(log_path), true);
    assert!(output.contains("VERDICT: CLEAN"));
    assert!(output.contains("[PASS] Inode Reachability"));

    // 3. Inject an orphaned inode into base and verify check detects it
    let orphan_ino = 888;
    let orphan_node = appendfs::Node::File {
        range_map: appendfs::RangeMap::new(),
        size: 256,
        perm: 0o644,
        nlink: 1,
        uid: 1000,
        gid: 1000,
        atime: std::time::SystemTime::UNIX_EPOCH,
        mtime: std::time::SystemTime::UNIX_EPOCH,
        ctime: std::time::SystemTime::UNIX_EPOCH,
    };
    fs.base
        .write()
        .unwrap()
        .insert(orphan_ino, std::sync::Arc::new(orphan_node));

    let corrupted_report = appendfs::check_fs_integrity(&fs, Some(log_path), true);
    assert!(!corrupted_report.is_clean());
    assert_eq!(corrupted_report.orphaned_inodes, vec![888]);
    assert_eq!(corrupted_report.error_count(), 1);

    let corrupted_output = corrupted_report.format_report(Some(log_path), false);
    assert!(corrupted_output.contains("VERDICT: CORRUPT"));
    assert!(corrupted_output.contains("ORPHAN_INODE"));
    assert!(corrupted_output.contains("Inode 888"));
}

#[test]
fn test_mount_ro_rejects_mutations_and_enables_point_in_time_time_travel() {
    let mut mount = TestMount::new_rw();
    let mount_path = mount.path().to_path_buf();
    let log_path = mount.log_path.clone();

    // 2. RW Mount: create directory and file (Tx 1 & 2)
    let step1_dir = mount_path.join("step1");
    fs::create_dir(&step1_dir).unwrap();
    let file1 = step1_dir.join("file1.txt");
    fs::write(&file1, "version 1 content").unwrap();

    // 3. RW Mount 2: append changes (Tx 3 & 4)
    mount.remount_rw();

    let step2_dir = mount.path().join("step2");
    fs::create_dir(&step2_dir).unwrap();
    let file2 = step2_dir.join("file2.txt");
    fs::write(&file2, "version 2 content").unwrap();

    mount.unmount();

    // Count summary and log files before RO mount
    let mut files_before_ro: Vec<String> = fs::read_dir(&log_path)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    files_before_ro.sort();

    // 4. RO Mount (Latest state)
    mount.remount_ro(appendfs::RecoveryTarget::Latest);

    // Read operations must succeed
    let file1 = mount.path().join("step1/file1.txt");
    assert_eq!(fs::read_to_string(&file1).unwrap(), "version 1 content");
    let file2 = mount.path().join("step2/file2.txt");
    assert_eq!(fs::read_to_string(&file2).unwrap(), "version 2 content");

    // Mutation operations must fail with EROFS / PermissionDenied
    assert!(fs::write(&file1, "tampered").is_err(), "Write on RO mount must fail");
    assert!(
        fs::create_dir(mount.path().join("forbidden_dir")).is_err(),
        "Mkdir on RO mount must fail"
    );
    assert!(fs::remove_file(&file1).is_err(), "Unlink on RO mount must fail");

    mount.unmount();

    // Verify RO mount never created/modified summary or log files
    let mut files_after_ro: Vec<String> = fs::read_dir(&log_path)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    files_after_ro.sort();
    assert_eq!(
        files_before_ro, files_after_ro,
        "RO mount must never write to disk files"
    );

    // 5. RO Mount with Point-in-Time Historical Recovery (TxId cutoff before step2)
    mount.remount_ro(appendfs::RecoveryTarget::TxId(4));

    // step1 exists
    let file1 = mount.path().join("step1/file1.txt");
    assert!(file1.exists(), "step1/file1.txt must exist at historical point-in-time");
    assert_eq!(fs::read_to_string(&file1).unwrap(), "version 1 content");

    // step2 does NOT exist at this historical point in time
    let step2 = mount.path().join("step2");
    assert!(!step2.exists(), "step2 must NOT exist at historical point-in-time");
}

#[test]
fn test_double_mount_rw_protection_and_concurrent_ro_mount() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path();

    appendfs::init_volume(log_path, Some("main")).unwrap();

    // 1. First RW Mount: acquires exclusive lock
    let mut fs1 = appendfs::recover_fs(log_path).unwrap();
    let writer1 = appendfs::LogWriter::create_lazy(log_path, 1, appendfs::cli::DEFAULT_MAX_LOG_SIZE, 1)
        .expect("First RW mount must successfully acquire exclusive volume lock");
    fs1.log_writer = Some(std::sync::Arc::new(writer1));
    fs1.set_log_dir(log_path);

    // 2. Second concurrent RW Mount attempt: must fail with WouldBlock
    let err = appendfs::LogWriter::create_lazy(log_path, 1, appendfs::cli::DEFAULT_MAX_LOG_SIZE, 1).unwrap_err();
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::WouldBlock,
        "Second RW mount must fail with WouldBlock"
    );
    assert!(
        err.to_string().contains("already locked in read-write mode"),
        "Error message should clearly explain volume lock collision: {}",
        err
    );

    // 3. Concurrent RO Mount/Recovery: must succeed even while RW is actively mounted!
    let ro_fs = appendfs::recover_fs_to_target(log_path, appendfs::RecoveryTarget::Latest)
        .expect("RO recovery must succeed concurrently while RW mount is active");
    assert!(ro_fs.list_directory(1).is_some());

    // 4. Drop first RW mount (unmount / release lock)
    drop(fs1);

    // 5. Subsequent RW Mount: must now succeed cleanly
    let writer2 = appendfs::LogWriter::create_lazy(log_path, 1, appendfs::cli::DEFAULT_MAX_LOG_SIZE, 1)
        .expect("Subsequent RW mount must succeed after previous RW mount is dropped");
    drop(writer2);
}
