use std::process::Command;
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
fn test_cli_check_on_empty_directory_fails() {
    let temp_dir = TempDir::new().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .arg("check")
        .arg(temp_dir.path())
        .output()
        .expect("failed to run appendfs check");

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

    // Verify passing --passphrase to stats on plaintext volume fails cleanly
    let pass_stats = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .arg("stats")
        .arg("--passphrase")
        .arg(temp_dir1.path())
        .output()
        .expect("failed to run appendfs stats --passphrase");
    assert!(!pass_stats.status.success());
    let pass_stderr = String::from_utf8_lossy(&pass_stats.stderr);
    assert!(pass_stderr.contains("Volume is not encrypted; --passphrase does not apply to it"));

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

    // 2. Add S3 remote with --no-upload-partial-logs
    let s3_out = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .args([
            "remote",
            "add",
            temp_dir.path().to_str().unwrap(),
            "s3_backup",
            "--bucket",
            "my-appendfs-bucket",
            "--no-upload-partial-logs",
        ])
        .output()
        .expect("failed to run remote add s3_backup");
    assert!(
        s3_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&s3_out.stderr)
    );

    // 3. Verify `remote list` output shows partial_logs status
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

    // 4. Verify remotes.toml was written correctly
    let storage = appendfs::storage::OsStorage::new(temp_dir.path());
    let registry = appendfs::remote::RemoteRegistry::load_from_storage(&storage).unwrap();
    assert!(registry.remotes["nfs"].upload_partial_logs);
    assert!(!registry.remotes["s3_backup"].upload_partial_logs);

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
