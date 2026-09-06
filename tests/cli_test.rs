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

    // Verify `appendfs key` on plaintext volume also displays the random volume ID
    let key_output = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .arg("key")
        .arg(temp_dir1.path())
        .output()
        .expect("failed to run appendfs key");
    assert!(key_output.status.success());
    let key_stdout = String::from_utf8_lossy(&key_output.stdout);
    assert!(key_stdout.contains(&format!("Volume ID:     {}", id1)));

    // Verify `appendfs stats` succeeds on initialized plaintext volume
    let stats_output = Command::new(env!("CARGO_BIN_EXE_appendfs"))
        .arg("stats")
        .arg(temp_dir1.path())
        .output()
        .expect("failed to run appendfs stats");
    assert!(stats_output.status.success());

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
