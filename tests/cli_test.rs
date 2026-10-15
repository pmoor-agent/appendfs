// Drives the mounted filesystem through raw syscalls that std does not expose.
#![allow(unsafe_code)]
use appendfs::{FakeS3Server, RemoteStore};
use std::io::Write;
use std::process::{Command, Stdio};
use tempfile::TempDir;

#[test]
fn test_cli_stats_on_empty_directory_fails() {
    let temp_dir = TempDir::new().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .arg("stats")
        .arg(temp_dir.path())
        .output()
        .expect("failed to run appendfs stats");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No appendfs volume found in"),
        "expected error about missing volume, got: {}",
        stderr
    );
    assert!(stderr.contains("directory contains no summary files"));
}

#[test]
fn test_cli_fsck_on_empty_directory_fails() {
    let temp_dir = TempDir::new().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .arg("fsck")
        .arg(temp_dir.path())
        .output()
        .expect("failed to run appendfs fsck");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No appendfs volume found in"),
        "expected error about missing volume, got: {}",
        stderr
    );
    assert!(stderr.contains("directory contains no summary files"));
}

#[test]
fn test_cli_fails_on_directory_with_logs_but_no_summary() {
    let temp_dir = TempDir::new().unwrap();
    // Create an orphaned log file without any summary file
    std::fs::write(temp_dir.path().join("000001.log"), b"some log data").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .arg("stats")
        .arg(temp_dir.path())
        .output()
        .expect("failed to run appendfs stats");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No appendfs volume found in"),
        "expected error about missing volume, got: {}",
        stderr
    );
    assert!(stderr.contains("directory contains no summary files"));
}

#[test]
fn test_cli_init_plaintext_generates_random_volume_id() {
    let temp_dir1 = TempDir::new().unwrap();
    let temp_dir2 = TempDir::new().unwrap();

    let output1 = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .arg("init")
        .arg(temp_dir1.path())
        .output()
        .expect("failed to run appendfs init");
    assert!(output1.status.success());
    let stdout1 = String::from_utf8_lossy(&output1.stdout);
    assert!(stdout1.contains("Volume ID:"));

    let output2 = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .arg("init")
        .arg(temp_dir2.path())
        .output()
        .expect("failed to run appendfs init");
    assert!(output2.status.success());
    let stdout2 = String::from_utf8_lossy(&output2.stdout);
    assert!(stdout2.contains("Volume ID:"));

    // Extract Volume IDs
    let parse_vol_id = |text: &str| -> String {
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("  Volume ID:") {
                return rest.trim().to_string();
            }
        }
        panic!("Volume ID not found in: {}", text);
    };

    let id1 = parse_vol_id(&stdout1);
    let id2 = parse_vol_id(&stdout2);

    assert_ne!(id1, "00000000000000000000000000000000");
    assert_ne!(id2, "00000000000000000000000000000000");
    assert_ne!(id1, id2);

    // `stats` reports volume identity as well as statistics, so the volume ID is visible
    // without a separate command.
    let stats_output = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .arg("stats")
        .arg(temp_dir1.path())
        .output()
        .expect("failed to run appendfs stats");
    assert!(stats_output.status.success());
    let stats_stdout = String::from_utf8_lossy(&stats_output.stdout);
    assert!(stats_stdout.contains(&format!("Volume ID:     {}", id1)));

    // Verify passing --key-file to stats on plaintext volume fails cleanly
    let key_stats = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .arg("stats")
        .arg("--key-file")
        .arg("/dev/null")
        .arg(temp_dir1.path())
        .output()
        .expect("failed to run appendfs stats --key-file");
    assert!(!key_stats.status.success());
    let key_stderr = String::from_utf8_lossy(&key_stats.stderr);
    assert!(key_stderr.contains("Volume is not encrypted; --key-file does not apply to it"));
}

#[test]
fn test_cli_remote_add_and_list_upload_partial_logs() {
    let temp_dir = TempDir::new().unwrap();
    let init_out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .arg("init")
        .arg(temp_dir.path())
        .output()
        .expect("failed to run appendfs init");
    assert!(init_out.status.success());

    // 1. Add NFS remote (default upload_partial_logs = true)
    let nfs_out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args([
            "remote",
            "add",
            temp_dir.path().to_str().unwrap(),
            "nfs",
            "--path",
            "/mnt/nfs_backup",
        ])
        .output()
        .expect("failed to run remote add nfs");
    assert!(
        nfs_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&nfs_out.stderr)
    );

    // 2. Add S3 remote with --no-upload-partial-logs and --storage-class
    let s3_out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args([
            "remote",
            "add",
            temp_dir.path().to_str().unwrap(),
            "s3_backup",
            "--bucket",
            "my-appendfs-bucket",
            "--no-upload-partial-logs",
            "--storage-class",
            "INTELLIGENT_TIERING",
        ])
        .output()
        .expect("failed to run remote add s3_backup");
    assert!(
        s3_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&s3_out.stderr)
    );

    // 3. Verify `remote list` output shows partial_logs status and storage_class
    let list_out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args(["remote", "list", temp_dir.path().to_str().unwrap()])
        .output()
        .expect("failed to run remote list");
    assert!(list_out.status.success());
    let stdout = String::from_utf8_lossy(&list_out.stdout);
    assert!(stdout.contains("nfs: type='local/nfs'"));
    assert!(stdout.contains("partial_logs=Enabled"));
    assert!(stdout.contains("s3_backup: type='s3'"));
    assert!(stdout.contains("partial_logs=Disabled"));
    assert!(stdout.contains("storage_class='INTELLIGENT_TIERING'"));

    // 4. Verify remotes.toml was written correctly
    let storage = appendfs::storage::OsStorage::new(temp_dir.path());
    let registry = appendfs::remote::RemoteRegistry::load_from_storage(&storage).unwrap();
    assert!(registry.remotes["nfs"].upload_partial_logs());
    assert_eq!(registry.remotes["nfs"].storage_class, None);
    assert!(!registry.remotes["s3_backup"].upload_partial_logs());
    assert_eq!(
        registry.remotes["s3_backup"].storage_class.as_deref(),
        Some("INTELLIGENT_TIERING")
    );

    // 5. Verify passing both --upload-partial-logs and --no-upload-partial-logs fails
    let conflict_out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args([
            "remote",
            "add",
            temp_dir.path().to_str().unwrap(),
            "invalid_remote",
            "--bucket",
            "my-bucket",
            "--upload-partial-logs",
            "--no-upload-partial-logs",
        ])
        .output()
        .expect("failed to run remote add with conflicting flags");
    assert!(!conflict_out.status.success());
    let stderr = String::from_utf8_lossy(&conflict_out.stderr);
    assert!(
        stderr.contains("cannot be used with") || stderr.contains("Cannot specify both"),
        "expected conflict error, got: {}",
        stderr
    );
}

#[test]
fn test_cli_remote_add_mode_and_glacier_validation() {
    let temp_dir = TempDir::new().unwrap();
    let init_out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .arg("init")
        .arg(temp_dir.path())
        .output()
        .expect("failed to run appendfs init");
    assert!(init_out.status.success());

    // 1. Add write-only Glacier remote without specifying upload_partial_logs (should default to false)
    let glacier_out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args([
            "remote",
            "add",
            temp_dir.path().to_str().unwrap(),
            "glacier",
            "--bucket",
            "my-glacier-bucket",
            "--mode",
            "write-only",
            "--storage-class",
            "DEEP_ARCHIVE",
        ])
        .output()
        .expect("failed to run remote add glacier");
    assert!(
        glacier_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&glacier_out.stderr)
    );

    // 2. Verify `remote list` shows mode='Write-Only' and partial_logs=Disabled
    let list_out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args(["remote", "list", temp_dir.path().to_str().unwrap()])
        .output()
        .expect("failed to run remote list");
    assert!(list_out.status.success());
    let stdout = String::from_utf8_lossy(&list_out.stdout);
    assert!(stdout.contains("glacier: type='s3'"));
    assert!(stdout.contains("mode='Write-Only'"));
    assert!(stdout.contains("partial_logs=Disabled"));
    assert!(stdout.contains("storage_class='DEEP_ARCHIVE'"));

    // 3. Verify remotes.toml was written with mode = "write-only" and upload_partial_logs = false
    let storage = appendfs::storage::OsStorage::new(temp_dir.path());
    let registry = appendfs::remote::RemoteRegistry::load_from_storage(&storage).unwrap();
    assert_eq!(
        registry.remotes["glacier"].mode,
        appendfs::remote::RemoteMode::WriteOnly
    );
    assert!(!registry.remotes["glacier"].upload_partial_logs());
    assert_eq!(
        registry.remotes["glacier"].storage_class.as_deref(),
        Some("DEEP_ARCHIVE")
    );

    // 4. Verify adding a write-only remote with --upload-partial-logs fails validation
    let bad_glacier_out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args([
            "remote",
            "add",
            temp_dir.path().to_str().unwrap(),
            "bad_glacier",
            "--bucket",
            "bad-glacier-bucket",
            "--mode",
            "write-only",
            "--upload-partial-logs",
        ])
        .output()
        .expect("failed to run remote add bad_glacier");
    assert!(!bad_glacier_out.status.success());
    let stderr = String::from_utf8_lossy(&bad_glacier_out.stderr);
    assert!(
        stderr.contains("upload_partial_logs can only be true for read-write mode"),
        "expected validation error, got: {}",
        stderr
    );

    // 5. Verify adding a read-only remote with --upload-partial-logs also fails validation
    let bad_ro_out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args([
            "remote",
            "add",
            temp_dir.path().to_str().unwrap(),
            "bad_ro",
            "--bucket",
            "bad-ro-bucket",
            "--mode",
            "read-only",
            "--upload-partial-logs",
        ])
        .output()
        .expect("failed to run remote add bad_ro");
    assert!(!bad_ro_out.status.success());
    let stderr = String::from_utf8_lossy(&bad_ro_out.stderr);
    assert!(
        stderr.contains("upload_partial_logs can only be true for read-write mode"),
        "expected validation error, got: {}",
        stderr
    );
}

#[test]
fn test_cli_mount_args_flush_queue_bounds_defaults_and_overrides() {
    use appendfs::cli::{
        Cli, Commands, DEFAULT_MAX_FLUSH_QUEUE_BYTES, DEFAULT_MAX_FLUSH_QUEUE_DEPTH, DEFAULT_MAX_FLUSH_QUEUE_OPS,
    };
    use clap::Parser;

    // Test defaults
    let cli = Cli::try_parse_from(["appendfs", "mount", "/tmp/log", "/tmp/mnt"]).unwrap();
    match cli.command {
        Commands::Mount(args) => {
            assert_eq!(args.max_flush_queue_depth, DEFAULT_MAX_FLUSH_QUEUE_DEPTH);
            assert_eq!(args.max_flush_queue_depth, 16);
            assert_eq!(args.max_flush_queue_bytes, DEFAULT_MAX_FLUSH_QUEUE_BYTES);
            assert_eq!(args.max_flush_queue_ops, DEFAULT_MAX_FLUSH_QUEUE_OPS);
        }
        _ => panic!("expected Commands::Mount"),
    }

    // Test explicit flags
    let cli = Cli::try_parse_from([
        "appendfs",
        "mount",
        "/tmp/log",
        "/tmp/mnt",
        "--max-flush-queue-depth",
        "32",
        "--max-flush-queue-bytes",
        "67108864",
        "--max-flush-queue-ops",
        "5000",
    ])
    .unwrap();
    match cli.command {
        Commands::Mount(args) => {
            assert_eq!(args.max_flush_queue_depth, 32);
            assert_eq!(args.max_flush_queue_bytes, 67_108_864);
            assert_eq!(args.max_flush_queue_ops, 5000);
        }
        _ => panic!("expected Commands::Mount"),
    }
}

#[test]
fn test_cli_mount_foreground_unmounts_on_sigint() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::thread;
    use std::time::Duration;

    let log_dir = TempDir::new().unwrap();
    let mount_dir = TempDir::new().unwrap();
    std::fs::set_permissions(mount_dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();

    let init_out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args(["init", log_dir.path().to_str().unwrap()])
        .output()
        .expect("failed to init volume");
    assert!(init_out.status.success());

    let initial_dev = std::fs::metadata(mount_dir.path()).unwrap().dev();

    let mut child = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args([
            "mount",
            log_dir.path().to_str().unwrap(),
            mount_dir.path().to_str().unwrap(),
            "-f",
        ])
        .spawn()
        .expect("failed to spawn appendfs mount");

    // Wait for FUSE mount to become ready
    let mut mounted = false;
    for _ in 0..200 {
        if let Ok(meta) = std::fs::metadata(mount_dir.path())
            && meta.dev() != initial_dev
        {
            mounted = true;
            break;
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!("appendfs mount exited prematurely with: {:?}", status);
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(mounted, "timed out waiting for FUSE filesystem to mount");

    // Write a file to verify operational filesystem and persistent flush on unmount
    let test_file = mount_dir.path().join("before_interrupt.txt");
    std::fs::write(&test_file, b"data persisted across sigint").unwrap();
    assert_eq!(std::fs::read(&test_file).unwrap(), b"data persisted across sigint");

    // Send SIGINT (Ctrl+C) to foreground appendfs process
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGINT);
    }

    // Wait for child to exit cleanly
    let mut exited = false;
    let mut exit_status = None;
    for _ in 0..100 {
        if let Ok(Some(status)) = child.try_wait() {
            exited = true;
            exit_status = Some(status);
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    if !exited {
        let _ = child.kill();
        let _ = child.wait();
        panic!("child failed to exit after SIGINT");
    }

    let status = exit_status.unwrap();
    assert!(
        status.success(),
        "appendfs should exit successfully (0) on SIGINT unmount, got {:?}",
        status
    );

    // Verify mount point is cleanly unmounted and restored to underlying directory
    let after_dev = std::fs::metadata(mount_dir.path()).unwrap().dev();
    assert_eq!(
        after_dev, initial_dev,
        "mount point device ID should be restored to initial underlying directory"
    );
    assert!(
        std::fs::read_dir(mount_dir.path()).unwrap().next().is_none(),
        "underlying directory should now be empty"
    );

    // Verify volume integrity and that written data was synced/exported
    let fsck_out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args(["fsck", log_dir.path().to_str().unwrap()])
        .output()
        .expect("failed to run appendfs fsck");
    assert!(
        fsck_out.status.success(),
        "volume fsck failed: {}",
        String::from_utf8_lossy(&fsck_out.stderr)
    );

    // Remount to verify volume recovers and the file is accessible
    let mut remount_child = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args([
            "mount",
            log_dir.path().to_str().unwrap(),
            mount_dir.path().to_str().unwrap(),
            "-f",
        ])
        .spawn()
        .expect("failed to spawn remount child");

    let mut remounted = false;
    for _ in 0..200 {
        if let Ok(meta) = std::fs::metadata(mount_dir.path())
            && meta.dev() != initial_dev
        {
            remounted = true;
            break;
        }
        if let Ok(Some(status)) = remount_child.try_wait() {
            panic!("remount child exited prematurely: {:?}", status);
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(remounted, "timed out waiting for remount");

    let read_back = std::fs::read(mount_dir.path().join("before_interrupt.txt")).unwrap();
    assert_eq!(read_back, b"data persisted across sigint");

    unsafe {
        libc::kill(remount_child.id() as libc::pid_t, libc::SIGINT);
    }
    assert!(remount_child.wait().unwrap().success());
}

#[test]
fn test_cli_mount_foreground_unmounts_on_sigint_when_busy() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::thread;
    use std::time::Duration;

    let log_dir = TempDir::new().unwrap();
    let mount_dir = TempDir::new().unwrap();
    std::fs::set_permissions(mount_dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();

    let init_out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args(["init", log_dir.path().to_str().unwrap()])
        .output()
        .expect("failed to init volume");
    assert!(init_out.status.success());

    let initial_dev = std::fs::metadata(mount_dir.path()).unwrap().dev();

    let mut child = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args([
            "mount",
            log_dir.path().to_str().unwrap(),
            mount_dir.path().to_str().unwrap(),
            "-f",
        ])
        .spawn()
        .expect("failed to spawn appendfs mount");

    // Wait for FUSE mount to become ready
    let mut mounted = false;
    for _ in 0..200 {
        if let Ok(meta) = std::fs::metadata(mount_dir.path())
            && meta.dev() != initial_dev
        {
            mounted = true;
            break;
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!("appendfs mount exited prematurely with: {:?}", status);
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(mounted, "timed out waiting for FUSE filesystem to mount");

    let test_file = mount_dir.path().join("busy_file.txt");
    std::fs::write(&test_file, b"held open by external fd").unwrap();

    // Keep an open file descriptor in this test process to make the filesystem busy
    let open_file = std::fs::File::open(&test_file).unwrap();

    // Send SIGINT (Ctrl+C) to foreground appendfs process while filesystem is busy
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGINT);
    }

    // Wait for child to exit cleanly (lazy detach ensures unmount succeeds without blocking)
    let mut exited = false;
    let mut exit_status = None;
    for _ in 0..100 {
        if let Ok(Some(status)) = child.try_wait() {
            exited = true;
            exit_status = Some(status);
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    if !exited {
        let _ = child.kill();
        let _ = child.wait();
        panic!("child failed to exit after SIGINT while busy");
    }

    let status = exit_status.unwrap();
    assert!(
        status.success(),
        "appendfs should exit successfully (0) on SIGINT unmount even when busy, got {:?}",
        status
    );

    // Verify mount point is cleanly unmounted from VFS hierarchy
    let after_dev = std::fs::metadata(mount_dir.path()).unwrap().dev();
    assert_eq!(
        after_dev, initial_dev,
        "mount point device ID should be detached and restored to underlying directory"
    );

    // Close the file descriptor now that unmount completed
    drop(open_file);
}

/// A backgrounded mount is the case that used to lose every log record: libfuse redirects
/// stderr to /dev/null when it daemonizes, and stderr was the only place logs went.
#[test]
fn test_cli_backgrounded_mount_writes_logs_into_the_volume_log_directory() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::thread;
    use std::time::Duration;

    let log_dir = TempDir::new().unwrap();
    let mount_dir = TempDir::new().unwrap();
    std::fs::set_permissions(mount_dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();

    let init_out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args(["init", log_dir.path().to_str().unwrap()])
        .output()
        .expect("failed to init volume");
    assert!(init_out.status.success());

    let initial_dev = std::fs::metadata(mount_dir.path()).unwrap().dev();
    let before = log_file_count(log_dir.path());

    // No `-f`: the process daemonizes and the parent exits straight away.
    let parent = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args([
            "mount",
            log_dir.path().to_str().unwrap(),
            mount_dir.path().to_str().unwrap(),
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn appendfs mount");
    let parent_pid = parent.id();
    let out = parent.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "mount failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The operator is told where the logs went, since a daemonized mount leaves no other clue.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Logging to") && stdout.contains("logs/appendfs-"),
        "startup must report the log location, got: {}",
        stdout
    );

    let mut mounted = false;
    for _ in 0..200 {
        if let Ok(meta) = std::fs::metadata(mount_dir.path())
            && meta.dev() != initial_dev
        {
            mounted = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(mounted, "timed out waiting for FUSE filesystem to mount");

    std::fs::write(mount_dir.path().join("payload.txt"), b"logged activity").unwrap();

    // The volume lock names the daemon serving the mount, not the parent that forked it and
    // exited - otherwise a second mount's "already locked by PID" points nowhere.
    let lock_pid: u32 = std::fs::read_to_string(log_dir.path().join(".lock"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert_ne!(lock_pid, parent_pid, "the lock must not name the exited parent");
    let cmdline = std::fs::read(format!("/proc/{}/cmdline", lock_pid)).unwrap_or_default();
    assert!(
        String::from_utf8_lossy(&cmdline).contains("mount"),
        "the lock must name the running mount daemon, PID {}",
        lock_pid
    );

    let unmounted = appendfs::wait_until(
        || {
            matches!(Command::new("fusermount3").arg("-u").arg(mount_dir.path()).status(),
                     Ok(s) if s.success())
        },
        Duration::from_secs(5),
    );
    assert!(unmounted, "failed to unmount");

    // One file for this run, named for when it started.
    let logs_dir = log_dir.path().join("logs");
    assert!(
        appendfs::wait_until(
            || {
                std::fs::read_dir(&logs_dir)
                    .map(|entries| {
                        entries.flatten().any(|e| {
                            e.file_name().to_string_lossy().starts_with("appendfs-")
                                && e.metadata().map(|m| m.len() > 0).unwrap_or(false)
                        })
                    })
                    .unwrap_or(false)
            },
            Duration::from_secs(5)
        ),
        "a backgrounded mount must still leave logs in {}",
        logs_dir.display()
    );
    assert_eq!(
        log_file_count(log_dir.path()),
        before + 1,
        "the mount must leave exactly one log file of its own"
    );

    // The volume itself is unaffected: the log lives in a subdirectory, so nothing that
    // scans the log directory for generations or summaries can see it.
    let fsck = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args(["fsck", log_dir.path().to_str().unwrap()])
        .output()
        .expect("failed to run fsck");
    assert!(
        fsck.status.success(),
        "fsck must not be confused by the log directory: {}",
        String::from_utf8_lossy(&fsck.stderr)
    );
}

/// `--log-file /dev/null` is how logging is turned off; there is no separate flag for it.
#[test]
fn test_cli_log_file_dev_null_leaves_no_log_behind() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::thread;
    use std::time::Duration;

    let log_dir = TempDir::new().unwrap();
    let mount_dir = TempDir::new().unwrap();
    std::fs::set_permissions(mount_dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();

    assert!(
        Command::new(env!("CARGO_BIN_EXE_appendfs"))
            .args(["init", log_dir.path().to_str().unwrap()])
            .output()
            .expect("failed to init volume")
            .status
            .success()
    );

    let initial_dev = std::fs::metadata(mount_dir.path()).unwrap().dev();
    let before = log_file_count(log_dir.path());
    let out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args([
            "mount",
            log_dir.path().to_str().unwrap(),
            mount_dir.path().to_str().unwrap(),
            "--log-file",
            "/dev/null",
        ])
        .output()
        .expect("failed to spawn appendfs mount");
    assert!(
        out.status.success(),
        "mount failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mut mounted = false;
    for _ in 0..200 {
        if let Ok(meta) = std::fs::metadata(mount_dir.path())
            && meta.dev() != initial_dev
        {
            mounted = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(mounted, "timed out waiting for FUSE filesystem to mount");

    std::fs::write(mount_dir.path().join("payload.txt"), b"no logs wanted").unwrap();
    assert!(
        appendfs::wait_until(
            || {
                matches!(Command::new("fusermount3").arg("-u").arg(mount_dir.path()).status(),
                         Ok(s) if s.success())
            },
            Duration::from_secs(5),
        ),
        "failed to unmount"
    );

    assert_eq!(
        log_file_count(log_dir.path()),
        before,
        "/dev/null must leave no log of its own behind"
    );
}

/// Every command logs, so a one-shot run leaves its own file in the volume alongside the
/// mounts, and each run's log says what that run was.
#[test]
fn test_cli_one_shot_commands_log_into_the_volume_with_their_command_line() {
    let log_dir = TempDir::new().unwrap();
    let logs = log_dir.path().join("logs");

    for args in [
        vec!["init", log_dir.path().to_str().unwrap()],
        vec!["stats", log_dir.path().to_str().unwrap()],
        vec!["fsck", log_dir.path().to_str().unwrap()],
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
            .args(&args)
            .output()
            .unwrap_or_else(|e| panic!("failed to run {:?}: {}", args, e));
        assert!(
            out.status.success(),
            "{:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // One file per run, including the `init` that created the directory in the first place.
    let written: Vec<_> = std::fs::read_dir(&logs)
        .expect("every command must log into the volume")
        .flatten()
        .collect();
    assert_eq!(written.len(), 3, "each run gets its own file, got {:?}", written);

    // Each log opens with the command line that produced it.
    let mut commands: Vec<String> = written
        .iter()
        .map(|e| {
            std::fs::read_to_string(e.path())
                .unwrap()
                .lines()
                .next()
                .unwrap_or_default()
                .to_string()
        })
        .collect();
    commands.sort();
    assert!(
        commands.iter().any(|l| l.contains("init")),
        "a run's log must identify it: {:?}",
        commands
    );
    assert!(commands.iter().any(|l| l.contains("stats")), "{:?}", commands);
    assert!(commands.iter().any(|l| l.contains("fsck")), "{:?}", commands);
}

/// Credentials passed on the command line must not reach the log file.
#[test]
fn test_cli_does_not_log_credentials() {
    let log_dir = TempDir::new().unwrap();
    assert!(
        Command::new(env!("CARGO_BIN_EXE_appendfs"))
            .args(["init", log_dir.path().to_str().unwrap()])
            .output()
            .unwrap()
            .status
            .success()
    );

    let out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args([
            "remote",
            "add",
            log_dir.path().to_str().unwrap(),
            "aws",
            "--bucket",
            "backups",
            "--access-key-id",
            "AKIAEXAMPLEKEYID",
            "--secret-access-key",
            "s3cr3t-must-not-be-logged",
        ])
        .output()
        .expect("failed to run remote add");
    assert!(
        out.status.success(),
        "remote add failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    for entry in std::fs::read_dir(log_dir.path().join("logs")).unwrap().flatten() {
        let contents = std::fs::read_to_string(entry.path()).unwrap();
        assert!(
            !contents.contains("s3cr3t-must-not-be-logged"),
            "secret key leaked into {}",
            entry.path().display()
        );
        assert!(
            !contents.contains("AKIAEXAMPLEKEYID"),
            "access key id leaked into {}",
            entry.path().display()
        );
    }
}

/// A mistyped path must not scatter `logs/` directories across the filesystem.
#[test]
fn test_cli_does_not_create_a_volume_directory_that_does_not_exist() {
    let parent = TempDir::new().unwrap();
    let missing = parent.path().join("typo");

    let out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args(["stats", missing.to_str().unwrap()])
        .output()
        .expect("failed to run stats");
    assert!(!out.status.success(), "stats on a missing volume must fail");
    assert!(
        !missing.exists(),
        "a mistyped path must not be created just to log into"
    );
}

/// Number of log files currently in a volume's `logs/` directory.
fn log_file_count(log_dir: &std::path::Path) -> usize {
    std::fs::read_dir(log_dir.join("logs"))
        .map(|entries| entries.flatten().count())
        .unwrap_or(0)
}

#[test]
fn test_cli_mount_ro_batch_id_flag_and_no_tx_id_alias() {
    let out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args(["mount-ro", "--help"])
        .output()
        .expect("failed to run mount-ro --help");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--batch-id"));
    assert!(!stdout.contains("--tx-id"));
}

/// SIGKILLs every other process holding `path` open, found by scanning `/proc/*/fd`.
fn kill_other_processes_holding(path: &std::path::Path) {
    for proc_entry in std::fs::read_dir("/proc").unwrap().flatten() {
        let Ok(pid) = proc_entry.file_name().to_string_lossy().parse::<libc::pid_t>() else {
            continue;
        };
        if pid as u32 == std::process::id() {
            continue;
        }
        let Ok(fds) = std::fs::read_dir(proc_entry.path().join("fd")) else {
            continue;
        };
        if fds
            .flatten()
            .any(|fd| std::fs::read_link(fd.path()).is_ok_and(|p| p == path))
        {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
    }
}

/// A background mount (no `-f`) forks in `fuse_daemonize`, and `fork` carries only the
/// calling thread into the daemon. Threads started before it - the delayed response queue's,
/// the replication worker's - used to vanish, so replication never ran and unmount hung
/// forever joining them, right after writing the final summary.
#[test]
fn test_cli_background_mount_exits_after_unmount_and_replicates() {
    use std::os::unix::io::AsRawFd;
    use std::time::Duration;

    let log_dir = TempDir::new().unwrap();
    let mount_dir = TempDir::new().unwrap();
    let remote_dir = TempDir::new().unwrap();
    let log = log_dir.path().to_str().unwrap();
    let mount = mount_dir.path().to_str().unwrap();

    let run = |args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "appendfs {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    };
    run(&["init", log]);
    run(&[
        "remote",
        "add",
        log,
        "backup",
        "--path",
        remote_dir.path().to_str().unwrap(),
    ]);
    // Without `-f`, this returns once the daemon it forked has taken over the mount.
    run(&["mount", log, mount]);

    std::fs::write(mount_dir.path().join("hello.txt"), b"written through the daemon").unwrap();
    // Retried: the kernel can briefly report the mount busy right after a file on it closes.
    assert!(
        appendfs::wait_until(
            || matches!(Command::new("fusermount3").args(["-u", mount]).status(), Ok(s) if s.success()),
            Duration::from_secs(5),
        ),
        "failed to unmount"
    );

    // The daemon holds the volume lock for as long as it runs.
    let lock_path = log_dir.path().join(".lock");
    let lock = std::fs::File::open(&lock_path).unwrap();
    let exited = appendfs::wait_until(
        || unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        Duration::from_secs(10),
    );
    if !exited {
        kill_other_processes_holding(&lock_path);
    }
    assert!(exited, "background mount daemon did not exit after unmount");

    for name in ["000001.log", "000001.summary"] {
        assert!(
            remote_dir.path().join(name).exists(),
            "{} was not replicated to the remote",
            name
        );
    }
}

#[test]
fn test_cli_stats_and_dump_extension_breakdown() {
    let fixture_src = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v1");
    let temp_dir = TempDir::new().unwrap();

    // Copy fixture files to temp directory to avoid polluting fixture with logs
    for entry in std::fs::read_dir(&fixture_src).unwrap().flatten() {
        if entry.path().is_file() {
            std::fs::copy(entry.path(), temp_dir.path().join(entry.file_name())).unwrap();
        }
    }

    // Verify `appendfs stats` outputs the File Extension Breakdown table
    let stats_out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args(["stats", temp_dir.path().to_str().unwrap()])
        .output()
        .expect("failed to run appendfs stats");
    assert!(stats_out.status.success());
    let stats_str = String::from_utf8_lossy(&stats_out.stdout);
    assert!(stats_str.contains("--- File Extension Breakdown ---"));
    assert!(stats_str.contains("EXTENSION                   FILES   % OF FILES    TOTAL BYTES   % OF BYTES"));
    assert!(stats_str.contains(".dat                            1        16.7%      32.00 KiB        70.7%"));
    assert!(stats_str.contains(".bin                            3        50.0%      13.20 KiB        29.2%"));
    assert!(stats_str.contains(".txt                            2        33.3%           40 B         0.1%"));

    // Verify `appendfs dump` on .summary file outputs the File Extension Breakdown table
    let summary_file = temp_dir.path().join("000001.summary");
    let dump_out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args(["dump", summary_file.to_str().unwrap()])
        .output()
        .expect("failed to run appendfs dump");
    assert!(dump_out.status.success());
    let dump_str = String::from_utf8_lossy(&dump_out.stdout);
    assert!(dump_str.contains("--- File Extension Breakdown ---"));
    assert!(dump_str.contains("EXTENSION                   FILES   % OF FILES    TOTAL BYTES   % OF BYTES"));
    assert!(dump_str.contains(".dat                            1        16.7%      32.00 KiB        70.7%"));
    assert!(dump_str.contains(".bin                            3        50.0%      13.20 KiB        29.2%"));
    assert!(dump_str.contains(".txt                            2        33.3%           40 B         0.1%"));

    // Verify `appendfs stats` and `appendfs dump` match identically from "--- Inode Breakdown ---" onwards
    let dump_idx = dump_str
        .find("--- Inode Breakdown ---")
        .expect("dump must contain '--- Inode Breakdown ---'");
    let stats_idx = stats_str
        .find("--- Inode Breakdown ---")
        .expect("stats must contain '--- Inode Breakdown ---'");
    assert_eq!(&dump_str[dump_idx..], &stats_str[stats_idx..]);
}

/// Unlocks key file text the way the CLI does, answering an encrypted file's prompt with
/// `passphrase`.
fn unlock_key_file(text: &str, passphrase: &str) -> std::io::Result<[u8; 32]> {
    appendfs::crypto::KeyFile::parse(text)
        .map_err(std::io::Error::other)?
        .unlock(|| Ok(zeroize::Zeroizing::new(passphrase.to_string())))
        .map(|key| key.key)
}

fn is_encrypted_key_file(text: &str) -> bool {
    appendfs::crypto::KeyFile::parse(text).unwrap().is_encrypted()
}

fn run_appendfs_with_input(args: &[&str], input: &[u8]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn appendfs");
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().expect("failed to wait for appendfs")
}

#[test]
fn test_cli_key_init_raw_and_permissions() {
    let temp_dir = TempDir::new().unwrap();
    let key_file = temp_dir.path().join("raw.key");

    let out = run_appendfs_with_input(&["key", "init", "-o", key_file.to_str().unwrap()], b"\n");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Generated unencrypted key file:"));

    assert!(key_file.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&key_file).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o400);
    }

    let content = std::fs::read_to_string(&key_file).unwrap();
    assert!(content.contains("-----BEGIN APPENDFS KEY-----"));
    assert!(content.contains("-----END APPENDFS KEY-----"));
    assert!(!is_encrypted_key_file(&content));
}

#[test]
fn test_cli_key_init_fails_if_parent_dir_missing() {
    let temp_dir = TempDir::new().unwrap();
    let key_file = temp_dir.path().join("nonexistent_subdir/raw.key");

    let out = run_appendfs_with_input(&["key", "init", "-o", key_file.to_str().unwrap()], b"\n");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("does not exist") || stderr.contains("No such file or directory"),
        "unexpected stderr: {}",
        stderr
    );
    assert!(!key_file.exists());
}

#[test]
fn test_cli_key_init_pem_and_permissions() {
    let temp_dir = TempDir::new().unwrap();
    let key_file = temp_dir.path().join("enc.key");

    let out = run_appendfs_with_input(&["key", "init", "-o", key_file.to_str().unwrap()], b"my_secret_pass\n");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Generated passphrase-encrypted key file:"));

    assert!(key_file.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&key_file).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o400);
    }

    let content = std::fs::read_to_string(&key_file).unwrap();
    assert!(content.contains("-----BEGIN APPENDFS ENCRYPTED KEY-----"));
    assert!(content.contains("-----END APPENDFS ENCRYPTED KEY-----"));

    // Can decrypt with correct passphrase
    assert!(unlock_key_file(&content, "my_secret_pass").is_ok());

    // Fails with wrong passphrase
    assert!(unlock_key_file(&content, "wrong_pass").is_err());
}

/// `key init` pointed at an existing key file must leave it alone: replacing a volume's
/// only key with a fresh random one would lose the volume.
#[test]
fn test_cli_key_init_never_overwrites() {
    let temp_dir = TempDir::new().unwrap();
    let key_file = temp_dir.path().join("volume.key");

    let out = run_appendfs_with_input(&["key", "init", "-o", key_file.to_str().unwrap()], b"\n");
    assert!(out.status.success());
    let original = std::fs::read(&key_file).unwrap();

    let out = run_appendfs_with_input(&["key", "init", "-o", key_file.to_str().unwrap()], b"\n");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("already exists"), "{}", stderr);
    assert_eq!(std::fs::read(&key_file).unwrap(), original);
}

#[test]
fn test_cli_key_change_passphrase_workflow() {
    use std::os::unix::fs::PermissionsExt;
    let temp_dir = TempDir::new().unwrap();
    let path = |name: &str| temp_dir.path().join(name);
    let change = |from: &str, to: &str, input: &[u8]| {
        run_appendfs_with_input(
            &[
                "key",
                "change-passphrase",
                path(from).to_str().unwrap(),
                "-o",
                path(to).to_str().unwrap(),
            ],
            input,
        )
    };
    let read = |name: &str| {
        let text = std::fs::read_to_string(path(name)).unwrap();
        assert_eq!(
            std::fs::metadata(path(name)).unwrap().permissions().mode() & 0o777,
            0o400,
            "{}",
            name
        );
        text
    };

    // 1. Init unencrypted PEM key (empty passphrase)
    let out = run_appendfs_with_input(&["key", "init", "-o", path("0.key").to_str().unwrap()], b"\n");
    assert!(out.status.success());
    let pem_0 = read("0.key");
    assert!(!is_encrypted_key_file(&pem_0));
    let initial_key = unlock_key_file(&pem_0, "").unwrap();

    // 2. Empty new passphrase on an unencrypted key: still unencrypted
    let out = change("0.key", "1.key", b"\n");
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("still without passphrase protection"));
    let pem_1 = read("1.key");
    assert!(!is_encrypted_key_file(&pem_1));
    assert_eq!(unlock_key_file(&pem_1, "").unwrap(), initial_key);

    // 3. Add passphrase_one
    let out = change("1.key", "2.key", b"passphrase_one\n");
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("Wrote passphrase-protected key file"));
    let pem_2 = read("2.key");
    assert!(is_encrypted_key_file(&pem_2));
    assert_eq!(unlock_key_file(&pem_2, "passphrase_one").unwrap(), initial_key);

    // 4. A wrong current passphrase fails and writes nothing
    let out = change("2.key", "wrong.key", b"wrong_pass\n");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("cannot unlock key file"), "{}", stderr);
    assert!(!path("wrong.key").exists());

    // 5. passphrase_one -> passphrase_two
    let out = change("2.key", "3.key", b"passphrase_one\npassphrase_two\n");
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("Wrote key file with the new passphrase"));
    let pem_3 = read("3.key");
    assert!(unlock_key_file(&pem_3, "passphrase_one").is_err());
    assert_eq!(unlock_key_file(&pem_3, "passphrase_two").unwrap(), initial_key);

    // 6. passphrase_two -> none
    let out = change("3.key", "4.key", b"passphrase_two\n\n");
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("without passphrase protection"));
    let pem_4 = read("4.key");
    assert!(!is_encrypted_key_file(&pem_4));
    assert_eq!(unlock_key_file(&pem_4, "").unwrap(), initial_key);

    // Every input was left exactly as it was.
    assert_eq!(read("0.key"), pem_0);
    assert_eq!(read("2.key"), pem_2);
    assert_eq!(read("3.key"), pem_3);

    // 7. Writing over an existing file - the input itself included - is refused before any
    //    prompt, and leaves it untouched
    for target in ["3.key", "0.key"] {
        let out = change("3.key", target, b"passphrase_two\nnew\n");
        assert!(!out.status.success());
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("already exists"), "{}", stderr);
    }
    assert_eq!(read("3.key"), pem_3);
    assert_eq!(read("0.key"), pem_0);

    // 8. A bare hex key from before key files had an envelope is refused, and left as it was
    let legacy_content = format!("{}\n", hex::encode(initial_key));
    std::fs::write(path("legacy.key"), &legacy_content).unwrap();
    let out = change("legacy.key", "upgraded.key", b"new_pass_for_legacy\n");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("is not a valid key file"), "{}", stderr);
    assert_eq!(std::fs::read_to_string(path("legacy.key")).unwrap(), legacy_content);
    assert!(!path("upgraded.key").exists());
}

#[test]
fn test_volume_lifecycle_with_encrypted_key_file() {
    let temp_dir = TempDir::new().unwrap();
    let key_file = temp_dir.path().join("volume.key");
    let new_key_file = temp_dir.path().join("volume-new.key");
    let log_dir = temp_dir.path().join("volume_logs");
    let mount_dir = temp_dir.path().join("mnt");
    let restore_dir = temp_dir.path().join("restored");

    std::fs::create_dir_all(&mount_dir).unwrap();

    // 1. Generate encrypted key file
    let out = run_appendfs_with_input(&["key", "init", "-o", key_file.to_str().unwrap()], b"secret_pass_1\n");
    assert!(out.status.success());

    // 2. Initialize volume with this key file
    let out = run_appendfs_with_input(
        &[
            "init",
            "--key-file",
            key_file.to_str().unwrap(),
            log_dir.to_str().unwrap(),
        ],
        b"secret_pass_1\n",
    );
    assert!(
        out.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Stats with correct passphrase succeeds
    let out = run_appendfs_with_input(
        &[
            "stats",
            "--key-file",
            key_file.to_str().unwrap(),
            log_dir.to_str().unwrap(),
        ],
        b"secret_pass_1\n",
    );
    assert!(out.status.success());

    // Stats with wrong passphrase fails
    let out = run_appendfs_with_input(
        &[
            "stats",
            "--key-file",
            key_file.to_str().unwrap(),
            log_dir.to_str().unwrap(),
        ],
        b"wrong_pass\n",
    );
    assert!(!out.status.success());

    // 3. Mount volume in background daemon, write some files, unmount
    let mount_out = run_appendfs_with_input(
        &[
            "mount",
            "--key-file",
            key_file.to_str().unwrap(),
            log_dir.to_str().unwrap(),
            mount_dir.to_str().unwrap(),
        ],
        b"secret_pass_1\n",
    );
    assert!(
        mount_out.status.success(),
        "mount failed: {}",
        String::from_utf8_lossy(&mount_out.stderr)
    );

    let test_file = mount_dir.join("test_doc.txt");
    std::fs::write(&test_file, b"data protected by encrypted key file").unwrap();

    // Unmount
    assert!(
        appendfs::wait_until(
            || matches!(
                Command::new("fusermount3").args(["-u", mount_dir.to_str().unwrap()]).status(),
                Ok(s) if s.success()
            ),
            std::time::Duration::from_secs(5),
        ),
        "failed to unmount"
    );

    // Wait for background mount daemon to exit and release lock
    let lock_path = log_dir.join(".lock");
    {
        let lock = std::fs::File::open(&lock_path).unwrap();
        use std::os::unix::io::AsRawFd;
        let exited = appendfs::wait_until(
            || unsafe {
                let res = libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB);
                if res == 0 {
                    libc::flock(lock.as_raw_fd(), libc::LOCK_UN);
                    true
                } else {
                    false
                }
            },
            std::time::Duration::from_secs(10),
        );
        assert!(exited, "mount daemon did not release lock");
    }

    // 4. Write the key under a new passphrase, secret_pass_2; everything after uses that file
    let out = run_appendfs_with_input(
        &[
            "key",
            "change-passphrase",
            key_file.to_str().unwrap(),
            "-o",
            new_key_file.to_str().unwrap(),
        ],
        b"secret_pass_1\nsecret_pass_2\n",
    );
    assert!(out.status.success());
    let key_file = new_key_file;

    // 5. Mount with secret_pass_2, verify file content
    let mount_out = run_appendfs_with_input(
        &[
            "mount",
            "--key-file",
            key_file.to_str().unwrap(),
            log_dir.to_str().unwrap(),
            mount_dir.to_str().unwrap(),
        ],
        b"secret_pass_2\n",
    );
    assert!(
        mount_out.status.success(),
        "second mount failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&mount_out.stdout),
        String::from_utf8_lossy(&mount_out.stderr)
    );

    let read_back = std::fs::read(&test_file).unwrap();
    assert_eq!(read_back, b"data protected by encrypted key file");

    assert!(
        appendfs::wait_until(
            || matches!(
                Command::new("fusermount3").args(["-u", mount_dir.to_str().unwrap()]).status(),
                Ok(s) if s.success()
            ),
            std::time::Duration::from_secs(5),
        ),
        "failed to unmount second time"
    );

    {
        let lock = std::fs::File::open(&lock_path).unwrap();
        use std::os::unix::io::AsRawFd;
        let exited = appendfs::wait_until(
            || unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            std::time::Duration::from_secs(10),
        );
        assert!(exited, "second mount daemon did not release lock");
    }

    // 6. Test disaster recovery with Python restore.py
    let restore_script = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/restore.py");
    let mut restore = Command::new("python3")
        .args([
            restore_script.to_str().unwrap(),
            log_dir.to_str().unwrap(),
            restore_dir.to_str().unwrap(),
            "--key-file",
            key_file.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    restore.stdin.take().unwrap().write_all(b"secret_pass_2\n").unwrap();
    let out = restore.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "restore.py failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let restored_file = restore_dir.join("test_doc.txt");
    assert_eq!(
        std::fs::read(restored_file).unwrap(),
        b"data protected by encrypted key file"
    );
}

#[test]
fn test_init_from_remote_credentials_file_validation() {
    let temp_dir = TempDir::new().unwrap();
    let log_dir = temp_dir.path().join("vol_bootstrap");
    let missing_creds = temp_dir.path().join("non_existent_creds.txt");

    // 1. Missing credentials file via --remote-credentials-file must fail early
    let out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args([
            "init",
            log_dir.to_str().unwrap(),
            "--from-remote",
            "origin",
            "--remote-bucket",
            "my-bucket",
            "--remote-credentials-file",
            missing_creds.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run init");

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("does not exist") || stderr.contains("No such file or directory"),
        "stderr was: {}",
        stderr
    );

    // 2. Missing credentials file via --credentials-file alias must also fail early
    let out_alias = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args([
            "init",
            log_dir.to_str().unwrap(),
            "--from-remote",
            "origin",
            "--remote-bucket",
            "my-bucket",
            "--credentials-file",
            missing_creds.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run init");

    assert!(!out_alias.status.success());
    let stderr_alias = String::from_utf8_lossy(&out_alias.stderr);
    assert!(
        stderr_alias.contains("does not exist") || stderr_alias.contains("No such file or directory"),
        "stderr was: {}",
        stderr_alias
    );

    // 3. Invalid credentials file (single line) must fail
    let invalid_creds = temp_dir.path().join("invalid_creds.txt");
    std::fs::write(&invalid_creds, "ONLY_ONE_LINE\n").unwrap();

    let out_invalid = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args([
            "init",
            log_dir.to_str().unwrap(),
            "--from-remote",
            "origin",
            "--remote-bucket",
            "my-bucket",
            "--remote-credentials-file",
            invalid_creds.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run init");

    assert!(!out_invalid.status.success());
    let stderr_invalid = String::from_utf8_lossy(&out_invalid.stderr);
    assert!(
        stderr_invalid.contains("does not contain valid access key and secret key"),
        "stderr was: {}",
        stderr_invalid
    );

    // 4. Remote add with missing credentials file must also fail early
    let out_remote_add = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args([
            "remote",
            "add",
            temp_dir.path().to_str().unwrap(),
            "origin",
            "--bucket",
            "my-bucket",
            "--credentials-file",
            missing_creds.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run remote add");

    assert!(!out_remote_add.status.success());
    let stderr_add = String::from_utf8_lossy(&out_remote_add.stderr);
    assert!(
        stderr_add.contains("does not exist") || stderr_add.contains("No such file or directory"),
        "stderr was: {}",
        stderr_add
    );
}

#[test]
fn test_init_from_remote_with_credentials_file_e2e() {
    let temp_dir = TempDir::new().unwrap();
    let source_dir = temp_dir.path().join("source_vol");

    // Initialize source volume so we have a valid volume summary
    let init_out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args(["init", source_dir.to_str().unwrap()])
        .output()
        .expect("failed to init source vol");
    assert!(init_out.status.success());

    // The CLI auto-selects path-style addressing for a 127.0.0.1 endpoint.
    let server = FakeS3Server::start("test-bucket");
    let summary_bytes = std::fs::read(source_dir.join("000000.summary")).unwrap();
    server
        .store()
        .put_object(
            "000000.summary",
            &mut summary_bytes.as_slice(),
            summary_bytes.len() as u64,
            None,
        )
        .unwrap();

    // Write INI-style credentials file to verify full parsing
    let creds_file = temp_dir.path().join("aws_creds.ini");
    std::fs::write(
        &creds_file,
        "[default]\naws_access_key_id = BOOTSTRAP_KEY_123\naws_secret_access_key = BOOTSTRAP_SECRET_456\n",
    )
    .unwrap();

    let bootstrap_dir = temp_dir.path().join("bootstrapped_vol");
    let out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args([
            "init",
            bootstrap_dir.to_str().unwrap(),
            "--from-remote",
            "cloud_origin",
            "--remote-bucket",
            "test-bucket",
            "--remote-endpoint",
            &server.endpoint(),
            "--remote-credentials-file",
            creds_file.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run bootstrap init");

    assert!(
        out.status.success(),
        "bootstrap init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(bootstrap_dir.join("000000.summary").exists());
    assert!(bootstrap_dir.join("remotes.toml").exists());

    let remotes_toml = std::fs::read_to_string(bootstrap_dir.join("remotes.toml")).unwrap();
    assert!(remotes_toml.contains("credentials_file"));
    assert!(remotes_toml.contains(creds_file.to_str().unwrap()));

    let requests = server.requests();
    assert_eq!(requests.len(), 2, "requests: {:?}", requests);
    for request in &requests {
        let auth = request.header("authorization").expect("authorization header");
        assert!(auth.contains("BOOTSTRAP_KEY_123"), "{}", auth);
    }
    assert_eq!(
        std::fs::read(bootstrap_dir.join("000000.summary")).unwrap(),
        summary_bytes
    );
}

#[test]
fn test_remote_add_path_style_flags() {
    let temp_dir = TempDir::new().unwrap();
    let vol_dir = temp_dir.path().join("vol");

    // Initialize volume
    let init_out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args(["init", vol_dir.to_str().unwrap()])
        .output()
        .expect("failed to init vol");
    assert!(init_out.status.success());

    // 1. --path-style as a boolean flag without explicit value defaults to true
    let add_out1 = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args([
            "remote",
            "add",
            vol_dir.to_str().unwrap(),
            "gcs_store",
            "--bucket",
            "my-gcs-bucket",
            "--endpoint",
            "https://storage.europe-west4.rep.googleapis.com",
            "--path-style",
        ])
        .output()
        .expect("failed to run remote add");
    assert!(
        add_out1.status.success(),
        "remote add failed: {}",
        String::from_utf8_lossy(&add_out1.stderr)
    );

    let remotes_toml1 = std::fs::read_to_string(vol_dir.join("remotes.toml")).unwrap();
    assert!(remotes_toml1.contains("force_path_style = true"));

    // 2. --path-style false explicitly sets false
    let add_out2 = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args([
            "remote",
            "add",
            vol_dir.to_str().unwrap(),
            "s3_virtual",
            "--bucket",
            "my-aws-bucket",
            "--endpoint",
            "https://s3.amazonaws.com",
            "--path-style",
            "false",
        ])
        .output()
        .expect("failed to run remote add");
    assert!(
        add_out2.status.success(),
        "remote add failed: {}",
        String::from_utf8_lossy(&add_out2.stderr)
    );

    let remotes_toml2 = std::fs::read_to_string(vol_dir.join("remotes.toml")).unwrap();
    assert!(remotes_toml2.contains("force_path_style = false"));
}

#[test]
fn test_init_from_remote_path_style_flag_and_toml_persistence() {
    let temp_dir = TempDir::new().unwrap();
    let source_dir = temp_dir.path().join("source_vol");

    // Initialize source volume so we have a valid volume summary
    let init_out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args(["init", source_dir.to_str().unwrap()])
        .output()
        .expect("failed to init source vol");
    assert!(init_out.status.success());

    let server = FakeS3Server::start("my-bucket");
    let summary_bytes = std::fs::read(source_dir.join("000000.summary")).unwrap();
    server
        .store()
        .put_object(
            "000000.summary",
            &mut summary_bytes.as_slice(),
            summary_bytes.len() as u64,
            None,
        )
        .unwrap();

    let creds_file = temp_dir.path().join("creds.txt");
    std::fs::write(&creds_file, "TEST_KEY\nTEST_SECRET\n").unwrap();

    let bootstrap_dir = temp_dir.path().join("bootstrapped_vol");
    let out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args([
            "init",
            bootstrap_dir.to_str().unwrap(),
            "--from-remote",
            "gcs_backup",
            "--remote-bucket",
            "my-bucket",
            "--remote-endpoint",
            &server.endpoint(),
            "--remote-credentials-file",
            creds_file.to_str().unwrap(),
            "--remote-path-style",
        ])
        .output()
        .expect("failed to run bootstrap init");

    assert!(
        out.status.success(),
        "bootstrap init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Verify remotes.toml persists force_path_style = true
    let remotes_toml = std::fs::read_to_string(bootstrap_dir.join("remotes.toml")).unwrap();
    assert!(remotes_toml.contains("force_path_style = true"));

    let requests: Vec<_> = server
        .requests()
        .iter()
        .map(|r| format!("{} {}", r.method, r.path))
        .collect();
    assert_eq!(requests, ["GET /my-bucket", "GET /my-bucket/000000.summary"]);
    assert_eq!(server.requests()[0].query_param("list-type"), Some("2"));

    // Also verify --path-style alias works on init
    let bootstrap_dir2 = temp_dir.path().join("bootstrapped_vol2");
    let out2 = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args([
            "init",
            bootstrap_dir2.to_str().unwrap(),
            "--from-remote",
            "gcs_backup2",
            "--remote-bucket",
            "my-bucket",
            "--remote-endpoint",
            "https://storage.europe-west4.rep.googleapis.com",
            "--credentials-file",
            creds_file.to_str().unwrap(),
            "--path-style",
        ])
        .output()
        .expect("failed to parse init with aliases");

    // The command might fail at network connection because https://storage.europe-west4... is not real credentials,
    // but the argument parsing should succeed (not exit with clap usage error).
    let stderr2 = String::from_utf8_lossy(&out2.stderr);
    assert!(
        !stderr2.contains("error: unexpected argument") && !stderr2.contains("Usage:"),
        "clap failed on --path-style alias: {}",
        stderr2
    );
}
