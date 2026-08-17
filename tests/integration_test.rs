use std::fs;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn unmount_fuse(mount_path: &str) {
    for _ in 0..50 {
        if let Ok(s) = Command::new("fusermount3")
            .arg("-u")
            .arg(mount_path)
            .status()
        {
            if s.success() {
                return;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    let _ = Command::new("fusermount3")
        .arg("-u")
        .arg("-z")
        .arg(mount_path)
        .status();
}

#[test]
fn test_fuse_filesystem() {
    let fs = appendfs::InMemoryFS::new();

    // Create a unique temporary directory under /tmp
    let temp_dir = tempfile::Builder::new()
        .prefix("appendfs_test_")
        .tempdir()
        .unwrap();
    let mount_path = temp_dir.path().to_path_buf();
    let mount_path_str = mount_path.to_str().unwrap().to_string();

    fs::set_permissions(&mount_path, fs::Permissions::from_mode(0o755)).unwrap();

    // Record initial device ID of mount_path BEFORE spawning mount thread
    let initial_dev = fs::metadata(&mount_path).unwrap().dev();

    // Spawn FUSE mounting in a background thread
    let mount_path_clone = mount_path.clone();
    let handle = thread::spawn(move || {
        let args = vec![
            "test_fs".to_string(),
            mount_path_clone.to_str().unwrap().to_string(),
            "-f".to_string(), // foreground
        ];
        if let Err(e) = appendfs::mount(args, fs) {
            eprintln!("FUSE mount error: {}", e);
        }
    });

    // Wait for FUSE to be mounted by monitoring the device ID change
    let mut mounted = false;
    for _ in 0..200 {
        if let Ok(meta) = fs::metadata(&mount_path) {
            if meta.dev() != initial_dev {
                mounted = true;
                break;
            }
        }
        if handle.is_finished() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(mounted, "FUSE mount timed out or device ID did not change");

    // Perform directory listing verification (should be empty initially)
    let entries: Vec<String> = fs::read_dir(&mount_path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_str().unwrap().to_string())
        .collect();
    assert!(
        entries.is_empty(),
        "Expected directory to be empty, got: {:?}",
        entries
    );

    // Verify statfs / statvfs reports root inode count (1)
    let path_c = std::ffi::CString::new(mount_path_str.as_str()).unwrap();
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
    let f = fs::OpenOptions::new()
        .write(true)
        .open(&file_hello)
        .unwrap();
    let times = fs::FileTimes::new().set_modified(custom_time);
    f.set_times(times).unwrap();
    drop(f);

    let meta_touched = fs::metadata(&file_hello).unwrap();
    assert_eq!(meta_touched.modified().unwrap(), custom_time);

    // Write/Overwrite verification (with truncation)
    let new_content = "Integration test overwrite!";
    fs::write(&file_hello, new_content).unwrap();
    let content_after_write = fs::read_to_string(&file_hello).unwrap();
    assert_eq!(content_after_write, new_content);

    // Append verification
    let append_content = "\nAppended line.";
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(&file_hello)
        .unwrap();
    use std::io::Write;
    file.write_all(append_content.as_bytes()).unwrap();
    drop(file);

    let content_after_append = fs::read_to_string(&file_hello).unwrap();
    assert_eq!(
        content_after_append,
        format!("{}{}", new_content, append_content)
    );

    // Symlink verification
    let file_link = mount_path.join("hello_link.txt");
    std::os::unix::fs::symlink("hello.txt", &file_link).unwrap();
    assert!(file_link.exists());

    // Verify readlink returns the target string
    let target = fs::read_link(&file_link).unwrap();
    assert_eq!(target.to_str().unwrap(), "hello.txt");

    // Verify resolved read retrieves hello.txt's contents
    let link_content = fs::read_to_string(&file_link).unwrap();
    assert_eq!(link_content, format!("{}{}", new_content, append_content));

    // Delete the symlink
    fs::remove_file(&file_link).unwrap();
    assert!(!file_link.exists());

    // Rename and Relocate verification
    // Create a subdirectory rename_dir
    let rename_dir = mount_path.join("rename_dir");
    fs::create_dir(&rename_dir).unwrap();
    assert!(rename_dir.is_dir());

    // Local rename: move hello.txt to rename_dir/test_rename.txt
    let test_rename = rename_dir.join("test_rename.txt");
    fs::rename(&file_hello, &test_rename).unwrap();
    assert!(!file_hello.exists());
    assert!(test_rename.exists());
    let renamed_content = fs::read_to_string(&test_rename).unwrap();
    assert_eq!(
        renamed_content,
        format!("{}{}", new_content, append_content)
    );

    // Move across directories: move rename_dir/test_rename.txt to root/test_moved.txt
    let test_moved = mount_path.join("test_moved.txt");
    fs::rename(&test_rename, &test_moved).unwrap();
    assert!(!test_rename.exists());
    assert!(test_moved.exists());
    let moved_content = fs::read_to_string(&test_moved).unwrap();
    assert_eq!(moved_content, renamed_content);

    // Self-rename: renaming a path onto itself is a POSIX no-op success, not an
    // overwrite. Note: the kernel VFS resolves both paths to the same dentry and
    // short-circuits before issuing a FUSE request, so this never actually reaches
    // our rename() handler — it's a smoke check on rename()'s no-op contract, not
    // a regression guard for the same-parent/same-name overwrite path internally.
    fs::rename(&test_moved, &test_moved).unwrap();
    assert!(test_moved.exists());
    let self_renamed_content = fs::read_to_string(&test_moved).unwrap();
    assert_eq!(self_renamed_content, moved_content);

    // Cleanup moved file and directory
    fs::remove_file(&test_moved).unwrap();
    assert!(!test_moved.exists());
    fs::remove_dir(&rename_dir).unwrap();
    assert!(!rename_dir.exists());
    // 12. Hard Link verification
    let file_hello = mount_path.join("hello.txt");
    fs::write(&file_hello, "Hello, Hard Link!").unwrap();

    // Create hard link hello_hard.txt
    let file_hard = mount_path.join("hello_hard.txt");
    fs::hard_link(&file_hello, &file_hard).unwrap();
    assert!(file_hard.exists());

    // Verify both read the same content
    let hello_content = fs::read_to_string(&file_hello).unwrap();
    let hard_content = fs::read_to_string(&file_hard).unwrap();
    assert_eq!(hello_content, "Hello, Hard Link!");
    assert_eq!(hard_content, "Hello, Hard Link!");

    // Verify metadata nlink is 2
    use std::os::unix::fs::MetadataExt;
    let meta_hello = fs::metadata(&file_hello).unwrap();
    assert_eq!(meta_hello.nlink(), 2);

    // Modify through the hard link and assert changes reflect in original
    fs::write(&file_hard, "Modified via link!").unwrap();
    assert_eq!(
        fs::read_to_string(&file_hello).unwrap(),
        "Modified via link!"
    );

    // Unlink original hello.txt
    fs::remove_file(&file_hello).unwrap();
    assert!(!file_hello.exists());

    // Assert hello_hard.txt still exists, has nlink 1, and can be read/written
    assert!(file_hard.exists());
    let meta_hard = fs::metadata(&file_hard).unwrap();
    assert_eq!(meta_hard.nlink(), 1);
    assert_eq!(
        fs::read_to_string(&file_hard).unwrap(),
        "Modified via link!"
    );

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
        let dir_path = CString::new(mount_path.to_str().unwrap()).unwrap();
        unsafe {
            let dirp = libc::opendir(dir_path.as_ptr());
            assert!(!dirp.is_null(), "opendir failed");
            let fd = libc::dirfd(dirp);
            assert!(fd >= 0, "dirfd failed");
            let rc = libc::fsync(fd);
            assert_eq!(
                rc,
                0,
                "fsync on dir fd failed: {}",
                std::io::Error::last_os_error()
            );
            let rc = libc::fdatasync(fd);
            assert_eq!(
                rc,
                0,
                "fdatasync on dir fd failed: {}",
                std::io::Error::last_os_error()
            );
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
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ENOENT)
        );
    }

    // Clean up: unmount using fusermount3
    unmount_fuse(&mount_path_str);
    handle.join().unwrap();
}

#[test]
fn test_fuse_with_log_writer() {
    let clock = appendfs::SystemClock;
    let log_dir = tempfile::Builder::new()
        .prefix("appendfs_log_dir_")
        .tempdir()
        .unwrap();

    let writer = Arc::new(appendfs::LogWriter::create(log_dir.path(), 1, &clock).unwrap());
    let fs = appendfs::InMemoryFS::with_log(Arc::clone(&writer));

    let mount_dir = tempfile::Builder::new()
        .prefix("appendfs_log_mount_")
        .tempdir()
        .unwrap();
    let mount_path = mount_dir.path().to_path_buf();
    let mount_path_str = mount_path.to_str().unwrap().to_string();

    fs::set_permissions(&mount_path, fs::Permissions::from_mode(0o755)).unwrap();
    let initial_dev = fs::metadata(&mount_path).unwrap().dev();

    let mount_path_clone = mount_path.clone();
    let handle = thread::spawn(move || {
        let args = vec![
            "test_log_fs".to_string(),
            mount_path_clone.to_str().unwrap().to_string(),
            "-f".to_string(),
        ];
        if let Err(e) = appendfs::mount(args, fs) {
            eprintln!("FUSE mount error: {}", e);
        }
    });

    let mut mounted = false;
    for _ in 0..200 {
        if let Ok(meta) = fs::metadata(&mount_path) {
            if meta.dev() != initial_dev {
                mounted = true;
                break;
            }
        }
        if handle.is_finished() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(mounted, "FUSE mount timed out");

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
    let log_file_path = log_dir.path().join("000001.log");
    assert!(log_file_path.exists());
    let log_size = fs::metadata(&log_file_path).unwrap().len();
    assert!(
        log_size > 24,
        "Log file should contain logged record entries beyond header, size = {}",
        log_size
    );

    // Clean up FUSE
    unmount_fuse(&mount_path_str);
    handle.join().unwrap();
}

#[test]
fn test_recovery_after_remount() {
    let clock = appendfs::SystemClock;
    let log_dir = tempfile::Builder::new()
        .prefix("appendfs_recovery_log_dir_")
        .tempdir()
        .unwrap();

    let log_path = log_dir.path().to_path_buf();

    // Initial session: mount filesystem and perform mutations
    {
        let writer = Arc::new(appendfs::LogWriter::create(&log_path, 1, &clock).unwrap());
        let fs = appendfs::InMemoryFS::with_log(Arc::clone(&writer));

        let mount_dir = tempfile::Builder::new()
            .prefix("appendfs_recovery_mount1_")
            .tempdir()
            .unwrap();
        let mount_path = mount_dir.path().to_path_buf();
        let mount_path_str = mount_path.to_str().unwrap().to_string();

        fs::set_permissions(&mount_path, fs::Permissions::from_mode(0o755)).unwrap();
        let initial_dev = fs::metadata(&mount_path).unwrap().dev();

        let mount_path_clone = mount_path.clone();
        let handle = thread::spawn(move || {
            let args = vec![
                "test_rec1".to_string(),
                mount_path_clone.to_str().unwrap().to_string(),
                "-f".to_string(),
            ];
            let _ = appendfs::mount(args, fs);
        });

        for _ in 0..200 {
            if let Ok(meta) = fs::metadata(&mount_path) {
                if meta.dev() != initial_dev {
                    break;
                }
            }
            thread::sleep(Duration::from_millis(50));
        }

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

        // Unmount first session
        unmount_fuse(&mount_path_str);
        handle.join().unwrap();
    }

    // Recovery session: recover filesystem state purely from log_dir
    let mut recovered_fs = appendfs::recover_fs(&log_path).unwrap();

    // Attach a new LogWriter for generation 2 on the recovered instance
    let writer2 = Arc::new(appendfs::LogWriter::create(&log_path, 2, &clock).unwrap());
    recovered_fs.log_writer = Some(writer2);

    let mount_dir2 = tempfile::Builder::new()
        .prefix("appendfs_recovery_mount2_")
        .tempdir()
        .unwrap();
    let mount_path2 = mount_dir2.path().to_path_buf();
    let mount_path_str2 = mount_path2.to_str().unwrap().to_string();

    fs::set_permissions(&mount_path2, fs::Permissions::from_mode(0o755)).unwrap();
    let initial_dev2 = fs::metadata(&mount_path2).unwrap().dev();

    let mount_path_clone2 = mount_path2.clone();
    let handle2 = thread::spawn(move || {
        let args = vec![
            "test_rec2".to_string(),
            mount_path_clone2.to_str().unwrap().to_string(),
            "-f".to_string(),
        ];
        let _ = appendfs::mount(args, recovered_fs);
    });

    for _ in 0..200 {
        if let Ok(meta) = fs::metadata(&mount_path2) {
            if meta.dev() != initial_dev2 {
                break;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }

    // Verify recovered filesystem contents
    let recovered_photo = mount_path2.join("photos").join("vacation.png");
    assert!(recovered_photo.exists());
    let data = fs::read_to_string(&recovered_photo).unwrap();
    assert_eq!(data, "RAW_PHOTO_DATA_123456789");

    let recovered_symlink = mount_path2.join("fav_photo.png");
    assert!(recovered_symlink.exists());
    let target = fs::read_link(&recovered_symlink).unwrap();
    assert_eq!(target.to_str().unwrap(), "photos/vacation.png");

    // Clean up FUSE mount 2
    unmount_fuse(&mount_path_str2);
    handle2.join().unwrap();
}

#[test]
fn test_fuse_stress() {
    let fs = appendfs::InMemoryFS::new();

    // Create a unique temporary directory under /tmp
    let temp_dir = tempfile::Builder::new()
        .prefix("appendfs_test_")
        .tempdir()
        .unwrap();
    let mount_path = temp_dir.path().to_path_buf();
    let mount_path_str = mount_path.to_str().unwrap().to_string();

    fs::set_permissions(&mount_path, fs::Permissions::from_mode(0o755)).unwrap();

    // Record initial device ID of mount_path BEFORE spawning mount thread
    let initial_dev = fs::metadata(&mount_path).unwrap().dev();

    // Spawn FUSE mounting in a background thread
    let mount_path_clone = mount_path.clone();
    let handle = thread::spawn(move || {
        let args = vec![
            "test_fs_stress".to_string(),
            mount_path_clone.to_str().unwrap().to_string(),
            "-f".to_string(), // foreground
        ];
        if let Err(e) = appendfs::mount(args, fs) {
            eprintln!("FUSE mount error: {}", e);
        }
    });

    // Wait for FUSE to be mounted by monitoring the device ID change
    let mut mounted = false;
    for _ in 0..200 {
        if let Ok(meta) = fs::metadata(&mount_path) {
            if meta.dev() != initial_dev {
                mounted = true;
                break;
            }
        }
        if handle.is_finished() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(mounted, "FUSE mount timed out or device ID did not change");

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

    // Clean up FUSE: unmount using fusermount3
    unmount_fuse(&mount_path_str);
    handle.join().unwrap();
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
    let writer =
        Arc::new(appendfs::LogWriter::create_with_max_size(&log_path, 1, &*clock, 512).unwrap());

    let mut fs_instance =
        appendfs::InMemoryFS::with_clock_and_log(Arc::clone(&clock), Some(Arc::clone(&writer)));
    fs_instance.set_log_dir(&log_path);

    let mount_dir = tempfile::Builder::new()
        .prefix("appendfs_rolling_mount_")
        .tempdir()
        .unwrap();
    let mount_path = mount_dir.path().to_path_buf();
    let mount_path_str = mount_path.to_str().unwrap().to_string();

    fs::set_permissions(&mount_path, fs::Permissions::from_mode(0o755)).unwrap();
    let initial_dev = fs::metadata(&mount_path).unwrap().dev();

    let mount_path_clone = mount_path.clone();
    let handle = thread::spawn(move || {
        let args = vec![
            "test_rolling".to_string(),
            mount_path_clone.to_str().unwrap().to_string(),
            "-f".to_string(),
        ];
        let _ = appendfs::mount(args, fs_instance);
    });

    for _ in 0..200 {
        if let Ok(meta) = fs::metadata(&mount_path) {
            if meta.dev() != initial_dev {
                break;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }

    // Write enough data to force multiple generation rolls (512 bytes threshold).
    // Each write is followed by an explicit fsync: LogWriter now only ever rolls
    // *between* flush batches, never mid-batch, so triggering a separate flush per
    // write (rather than letting them all land in one batch at unmount) is what
    // actually exercises rolling here.
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
    unmount_fuse(&mount_path_str);
    handle.join().unwrap();

    // Count generated .log files in log_dir
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
    let mount_path_rec = mount_dir_rec.path().to_path_buf();
    let mount_path_rec_str = mount_path_rec.to_str().unwrap().to_string();

    fs::set_permissions(&mount_path_rec, fs::Permissions::from_mode(0o755)).unwrap();
    let initial_dev_rec = fs::metadata(&mount_path_rec).unwrap().dev();

    let mount_path_rec_clone = mount_path_rec.clone();
    let handle_rec = thread::spawn(move || {
        let args = vec![
            "test_rolling_rec".to_string(),
            mount_path_rec_clone.to_str().unwrap().to_string(),
            "-f".to_string(),
        ];
        let _ = appendfs::mount(args, recovered_fs);
    });

    for _ in 0..200 {
        if let Ok(meta) = fs::metadata(&mount_path_rec) {
            if meta.dev() != initial_dev_rec {
                break;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }

    for i in 1..=5 {
        let file_path = mount_path_rec.join(format!("chunk_{}.txt", i));
        let expected_content = format!("LOG_ROLLING_PAYLOAD_{}_DATA_{}", i, "X".repeat(200));
        assert!(file_path.exists());
        let read_back = fs::read_to_string(&file_path).unwrap();
        assert_eq!(read_back, expected_content);
    }

    // Unmount recovered filesystem
    unmount_fuse(&mount_path_rec_str);
    handle_rec.join().unwrap();
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

    let mut fs_instance =
        appendfs::InMemoryFS::with_clock_and_log(Arc::clone(&clock), Some(Arc::clone(&writer)));
    fs_instance.set_log_dir(&log_path);

    let mount_dir = tempfile::Builder::new()
        .prefix("appendfs_summary_mount_")
        .tempdir()
        .unwrap();
    let mount_path = mount_dir.path().to_path_buf();
    let mount_path_str = mount_path.to_str().unwrap().to_string();

    fs::set_permissions(&mount_path, fs::Permissions::from_mode(0o755)).unwrap();
    let initial_dev = fs::metadata(&mount_path).unwrap().dev();

    let mount_path_clone = mount_path.clone();
    let handle = thread::spawn(move || {
        let args = vec![
            "test_summary".to_string(),
            mount_path_clone.to_str().unwrap().to_string(),
            "-f".to_string(),
        ];
        let _ = appendfs::mount(args, fs_instance);
    });

    for _ in 0..200 {
        if let Ok(meta) = fs::metadata(&mount_path) {
            if meta.dev() != initial_dev {
                break;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }

    // Populate filesystem with initial structure
    let docs_dir = mount_path.join("docs");
    fs::create_dir(&docs_dir).unwrap();

    let file1 = docs_dir.join("file1.txt");
    fs::write(&file1, "SNAPSHOT_FILE_1_CONTENT").unwrap();

    let file2 = docs_dir.join("file2.txt");
    fs::write(&file2, "SNAPSHOT_FILE_2_CONTENT").unwrap();

    // Unmount initial filesystem to flush log buffer to disk
    unmount_fuse(&mount_path_str);
    handle.join().unwrap();

    // Recover filesystem state from log and export single-file summary snapshot (000001.summary)
    let summary_file_path = log_path.join("000001.summary");
    let fs_tmp = appendfs::recover_fs(&log_path).unwrap();
    let summary_path = fs_tmp.export_summary(&log_path).unwrap();

    assert!(summary_path.exists());
    assert_eq!(summary_path, summary_file_path);

    // Inspect summary snapshot using SummaryReader
    let mut reader = appendfs::SummaryReader::open(&summary_path).unwrap();
    assert_eq!(reader.header.generation, 1);
    assert_eq!(reader.footer.entry_count, 4); // root (1), docs dir (2), file1 (3), file2 (4)

    // Perform O(log N) binary search lookups on index entries
    let index_entries = reader.index_entries().to_vec();
    for entry in &index_entries {
        let node_opt = reader.read_node(entry.inode).unwrap();
        assert!(node_opt.is_some());
    }

    // Verify recovery: recover_fs should fast-load state from 000001.summary and replay file3.txt
    let recovered_fs = appendfs::recover_fs(&log_path).unwrap();

    let mount_dir_rec = tempfile::Builder::new()
        .prefix("appendfs_summary_rec_mount_")
        .tempdir()
        .unwrap();
    let mount_path_rec = mount_dir_rec.path().to_path_buf();
    let mount_path_rec_str = mount_path_rec.to_str().unwrap().to_string();

    fs::set_permissions(&mount_path_rec, fs::Permissions::from_mode(0o755)).unwrap();
    let initial_dev_rec = fs::metadata(&mount_path_rec).unwrap().dev();

    let mount_path_rec_clone = mount_path_rec.clone();
    let handle_rec = thread::spawn(move || {
        let args = vec![
            "test_summary_rec".to_string(),
            mount_path_rec_clone.to_str().unwrap().to_string(),
            "-f".to_string(),
        ];
        let _ = appendfs::mount(args, recovered_fs);
    });

    for _ in 0..200 {
        if let Ok(meta) = fs::metadata(&mount_path_rec) {
            if meta.dev() != initial_dev_rec {
                break;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }

    let rec_file1 = mount_path_rec.join("docs").join("file1.txt");
    assert!(rec_file1.exists());
    assert_eq!(
        fs::read_to_string(&rec_file1).unwrap(),
        "SNAPSHOT_FILE_1_CONTENT"
    );

    let rec_file2 = mount_path_rec.join("docs").join("file2.txt");
    assert!(rec_file2.exists());
    assert_eq!(
        fs::read_to_string(&rec_file2).unwrap(),
        "SNAPSHOT_FILE_2_CONTENT"
    );

    // Unmount recovered filesystem
    unmount_fuse(&mount_path_rec_str);
    handle_rec.join().unwrap();
}

#[test]
fn test_large_directory_readdir_and_readdirplus() {
    let fs = appendfs::InMemoryFS::new();

    let temp_dir = tempfile::Builder::new()
        .prefix("appendfs_large_dir_")
        .tempdir()
        .unwrap();
    let mount_path = temp_dir.path().to_path_buf();
    let mount_path_str = mount_path.to_str().unwrap().to_string();

    fs::set_permissions(&mount_path, fs::Permissions::from_mode(0o755)).unwrap();
    let initial_dev = fs::metadata(&mount_path).unwrap().dev();

    let mount_path_clone = mount_path.clone();
    let handle = thread::spawn(move || {
        let args = vec![
            "test_large_dir".to_string(),
            mount_path_clone.to_str().unwrap().to_string(),
            "-f".to_string(),
        ];
        let _ = appendfs::mount(args, fs);
    });

    for _ in 0..200 {
        if let Ok(meta) = fs::metadata(&mount_path) {
            if meta.dev() != initial_dev {
                break;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }

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
    for i in 0..num_files {
        assert_eq!(read_entries[i], format!("file_{:05}.txt", i));
    }

    // Test with command line `ls -la`
    let output = Command::new("ls")
        .arg("-la")
        .arg(&large_dir)
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("file_00000.txt"));
    assert!(stdout.contains("file_01499.txt"));

    unmount_fuse(&mount_path_str);
    handle.join().unwrap();
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
    let writer = Arc::new(
        appendfs::LogWriter::create_with_max_size(&log_path, 1, &*clock, 2048).unwrap(),
    );
    let fs = appendfs::InMemoryFS::with_clock_and_log(clock.clone(), Some(writer));

    let temp_dir = tempfile::Builder::new()
        .prefix("appendfs_manifest_mount_")
        .tempdir()
        .unwrap();
    let mount_path = temp_dir.path().to_path_buf();
    let mount_path_str = mount_path.to_str().unwrap().to_string();

    fs::set_permissions(&mount_path, fs::Permissions::from_mode(0o755)).unwrap();
    let initial_dev = fs::metadata(&mount_path).unwrap().dev();

    let mount_path_clone = mount_path.clone();
    let handle = thread::spawn(move || {
        let args = vec![
            "test_manifest".to_string(),
            mount_path_clone.to_str().unwrap().to_string(),
            "-f".to_string(),
        ];
        let _ = appendfs::mount(args, fs);
    });

    for _ in 0..200 {
        if let Ok(meta) = fs::metadata(&mount_path) {
            if meta.dev() != initial_dev {
                break;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }

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

    unmount_fuse(&mount_path_str);
    handle.join().unwrap();

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
    let log_dir = tempfile::Builder::new()
        .prefix("appendfs_init_vol_")
        .tempdir()
        .unwrap();
    let log_path = log_dir.path().to_path_buf();

    // 1. Explicitly initialize empty volume
    let summary_path = appendfs::init_volume(&log_path, Some("work")).unwrap();
    assert!(summary_path.exists());
    assert_eq!(summary_path.file_name().unwrap(), "000000.summary");

    // 2. Mount initialized volume
    let mut fs_instance = appendfs::recover_fs(&log_path).unwrap();
    let next_gen = fs_instance.manifest.read().unwrap().next_generation;
    assert_eq!(next_gen, 1);

    let writer = Arc::new(
        appendfs::LogWriter::create_with_max_size(&log_path, next_gen, &*clock, 1024 * 1024).unwrap(),
    );
    fs_instance.log_writer = Some(Arc::clone(&writer));
    fs_instance.set_log_dir(&log_path);

    let temp_dir = tempfile::Builder::new()
        .prefix("appendfs_init_mount_")
        .tempdir()
        .unwrap();
    let mount_path = temp_dir.path().to_path_buf();
    let mount_path_str = mount_path.to_str().unwrap().to_string();

    fs::set_permissions(&mount_path, fs::Permissions::from_mode(0o755)).unwrap();
    let initial_dev = fs::metadata(&mount_path).unwrap().dev();

    let mount_path_clone = mount_path.clone();
    let handle = thread::spawn(move || {
        let args = vec![
            "test_init_mount".to_string(),
            mount_path_clone.to_str().unwrap().to_string(),
            "-f".to_string(),
        ];
        let _ = appendfs::mount(args, fs_instance);
    });

    for _ in 0..200 {
        if let Ok(meta) = fs::metadata(&mount_path) {
            if meta.dev() != initial_dev {
                break;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }

    // Create a directory and file
    let docs = mount_path.join("docs");
    fs::create_dir(&docs).unwrap();
    let note = docs.join("note.txt");
    fs::write(&note, "hello appendfs volume").unwrap();

    // Unmount
    unmount_fuse(&mount_path_str);
    handle.join().unwrap();

    // 3. Inspect volume with stats
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
}
