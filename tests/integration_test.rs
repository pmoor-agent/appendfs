use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::thread;
use std::time::Duration;

#[test]
fn test_fuse_filesystem() {
    let fs = appendfs_fuse::InMemoryFS::new();

    // Create a unique temporary directory under /tmp
    let temp_dir = tempfile::Builder::new().prefix("appendfs_test_").tempdir().unwrap();
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
        if let Err(e) = appendfs_fuse::mount(args, fs) {
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

    // Create a new file (hello.txt)
    let file_hello = mount_path.join("hello.txt");
    assert!(!file_hello.exists());

    let content = "Hello world from dynamic FUSE!\n";
    fs::write(&file_hello, content).unwrap();
    assert!(file_hello.exists());

    let read_content = fs::read_to_string(&file_hello).unwrap();
    assert_eq!(read_content, content);

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

    // Clean up: unmount using fusermount3 -u
    let status = Command::new("fusermount3")
        .arg("-u")
        .arg(&mount_path_str)
        .status()
        .unwrap();
    assert!(status.success(), "Failed to unmount FUSE mount");

    // Wait for the background mount thread to exit
    handle.join().unwrap();
}

#[test]
fn test_fuse_stress() {
    let fs = appendfs_fuse::InMemoryFS::new();

    // Create a unique temporary directory under /tmp
    let temp_dir = tempfile::Builder::new().prefix("appendfs_test_").tempdir().unwrap();
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
        if let Err(e) = appendfs_fuse::mount(args, fs) {
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

    // Clean up FUSE: unmount using fusermount3 -u
    let status = Command::new("fusermount3")
        .arg("-u")
        .arg(&mount_path_str)
        .status()
        .unwrap();
    assert!(status.success(), "Failed to unmount FUSE mount");

    // Wait for the background mount thread to exit
    handle.join().unwrap();
}
