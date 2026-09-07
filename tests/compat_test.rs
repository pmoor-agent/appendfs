//! Compatibility tests verifying that earlier on-disk storage format versions can be
//! reliably recovered, loaded, and written to by the current codebase.
//!
//! # Generating Golden Fixtures
//! To generate or regenerate golden fixtures for any version:
//! ```bash
//! # For v1:
//! cargo run --bin generate_compat_fixture tests/fixtures/v1
//!
//! # For a new format version (e.g. v2):
//! cargo run --bin generate_compat_fixture tests/fixtures/v2
//! ```
//!
//! Any subdirectories placed into `tests/fixtures/` are automatically discovered
//! and tested by `test_all_fixture_versions`.

use appendfs::compat::{create_canonical_compat_volume, verify_compat_tree};
use appendfs::operations::read_write::{create_core, open_core, read_core, release_core, write_core};
use appendfs::storage::OsStorage;
use appendfs::{InMemoryFS, LogWriter, RecoveryTarget, Storage, VolumeKey, recover_fs};

fn read_test(fs: &InMemoryFS, ino: u64, size: usize, offset: i64) -> Vec<u8> {
    let fh = open_core(fs, ino, libc::O_RDONLY as u32).expect("open file");
    let data = read_core(fs, ino, fh, offset, size).expect("read file");
    release_core(fs, ino, fh).expect("release file");
    data
}

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;

fn fixture_v1_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v1")
}

/// Tests recovery when the latest summary file is missing, forcing full log replay and
/// reconstruction from the earliest summary and all subsequent log records.
pub fn verify_recovery_with_latest_summary_missing(fixture_dir: &Path) {
    let temp = tempfile::tempdir().unwrap();
    let temp_path = temp.path();

    // Copy 000000.summary and 000001.log, explicitly omitting 000001.summary.
    // This forces recovery to replay 000001.log from scratch across all 3 flush batches.
    fs::copy(fixture_dir.join("000000.summary"), temp_path.join("000000.summary")).expect("copy 000000.summary");
    fs::copy(fixture_dir.join("000001.log"), temp_path.join("000001.log")).expect("copy 000001.log");

    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(temp_path));
    let clock: Arc<dyn appendfs::Clock> = Arc::new(appendfs::SystemClock);

    let mut fs = recover_fs(
        storage.clone(),
        RecoveryTarget::Latest,
        clock.clone(),
        VolumeKey::plaintext_arc(),
    )
    .expect("recovery from 000000.summary + 000001.log must succeed");

    // 1. Verify reconstructed filesystem tree, files, symlinks, special files, and xattrs
    verify_compat_tree(&fs);

    // 2. Verify forward mutability on top of the reconstructed volume
    let next_gen = appendfs::find_latest_generation_in_storage(storage.as_ref()) + 1;
    let start_tx = fs.last_tx_id.load(Ordering::SeqCst) + 1;
    let writer = Arc::new(
        LogWriter::create(
            storage.clone(),
            next_gen,
            clock.as_ref(),
            appendfs::cli::DEFAULT_MAX_LOG_SIZE,
            start_tx,
            VolumeKey::plaintext_arc(),
        )
        .unwrap(),
    );
    fs.log_writer = Some(writer);
    fs.set_log_dir(temp_path);

    let new_file = create_core(&fs, 1, "new_after_reconstruction.txt", 0o644, 0, 1000, 1000)
        .expect("create file after reconstruction");
    write_core(&fs, new_file.ino, b"reconstruction test forward write works!", 0).expect("write after reconstruction");
    fs.flush_log().expect("flush after reconstruction");

    let read_back = read_test(&fs, new_file.ino, 40, 0);
    assert_eq!(read_back, b"reconstruction test forward write works!");
}

/// Tests recovery directly from the latest exported summary snapshot file.
pub fn verify_recovery_from_latest_summary_snapshot(fixture_dir: &Path) {
    let temp = tempfile::tempdir().unwrap();
    let temp_path = temp.path();

    // Copy all files in fixture_dir (e.g. 000000.summary, 000001.log, and 000001.summary)
    for entry in fs::read_dir(fixture_dir).unwrap().flatten() {
        if entry.path().is_file() {
            fs::copy(entry.path(), temp_path.join(entry.file_name())).unwrap();
        }
    }

    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(temp_path));
    let clock: Arc<dyn appendfs::Clock> = Arc::new(appendfs::SystemClock);

    let mut fs = recover_fs(
        storage.clone(),
        RecoveryTarget::Latest,
        clock.clone(),
        VolumeKey::plaintext_arc(),
    )
    .expect("recovery from latest summary snapshot must succeed");

    // 1. Verify filesystem state loaded directly from the summary snapshot
    verify_compat_tree(&fs);

    // 2. Verify forward mutability
    let next_gen = appendfs::find_latest_generation_in_storage(storage.as_ref()) + 1;
    let start_tx = fs.last_tx_id.load(Ordering::SeqCst) + 1;
    let writer = Arc::new(
        LogWriter::create(
            storage.clone(),
            next_gen,
            clock.as_ref(),
            appendfs::cli::DEFAULT_MAX_LOG_SIZE,
            start_tx,
            VolumeKey::plaintext_arc(),
        )
        .unwrap(),
    );
    fs.log_writer = Some(writer);
    fs.set_log_dir(temp_path);

    let new_file =
        create_core(&fs, 1, "new_after_summary.txt", 0o644, 0, 1000, 1000).expect("create file after summary");
    write_core(&fs, new_file.ino, b"summary test forward write works!", 0).expect("write after summary");
    fs.flush_log().expect("flush after summary");

    let read_back = read_test(&fs, new_file.ino, 33, 0);
    assert_eq!(read_back, b"summary test forward write works!");
}

#[test]
fn test_v1_log_reconstruction_with_latest_summary_missing() {
    verify_recovery_with_latest_summary_missing(&fixture_v1_dir());
}

#[test]
fn test_v1_recovery_from_latest_summary_snapshot() {
    verify_recovery_from_latest_summary_snapshot(&fixture_v1_dir());
}

#[test]
fn test_v1_deterministic_reproducibility() {
    let temp = tempfile::tempdir().unwrap();
    create_canonical_compat_volume(temp.path()).expect("create canonical compat volume");

    let fixture_dir = fixture_v1_dir();
    for name in &["000000.summary", "000001.log", "000001.summary"] {
        let actual_bytes = fs::read(temp.path().join(name)).expect("read generated file");
        let expected_bytes = fs::read(fixture_dir.join(name)).expect("read fixture file");
        assert_eq!(
            actual_bytes,
            expected_bytes,
            "Generated file {} differs from checked-in fixture in {}",
            name,
            fixture_dir.display()
        );
    }
}

#[test]
fn test_all_fixture_versions() {
    let fixtures_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    assert!(fixtures_dir.is_dir(), "tests/fixtures directory must exist");

    let mut versions: Vec<PathBuf> = fs::read_dir(&fixtures_dir)
        .unwrap()
        .flatten()
        .filter(|e| e.path().is_dir())
        .map(|e| e.path())
        .collect();
    versions.sort();

    assert!(
        !versions.is_empty(),
        "at least one fixture version directory must exist"
    );

    for version_dir in &versions {
        let version_name = version_dir.file_name().unwrap().to_string_lossy();
        println!("Running compatibility checks on fixture: {}", version_name);
        verify_recovery_with_latest_summary_missing(version_dir);
        verify_recovery_from_latest_summary_snapshot(version_dir);
        verify_python_restore_script(version_dir);
    }
}

/// Verifies that the standalone Python restore script (scripts/restore.py) can successfully
/// replay all log batches from the golden fixture and reconstruct identical file data.
pub fn verify_python_restore_script(fixture_dir: &Path) {
    let script_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/restore.py");
    if !script_path.is_file() {
        return;
    }

    let temp = tempfile::tempdir().unwrap();
    let dest_path = temp.path();

    let status = std::process::Command::new("python3")
        .arg(&script_path)
        .arg(fixture_dir)
        .arg(dest_path)
        .status();

    let Ok(status) = status else {
        println!("python3 not available, skipping python restore script verification");
        return;
    };

    assert!(
        status.success(),
        "scripts/restore.py failed on {}",
        fixture_dir.display()
    );

    // Verify key files restored by scripts/restore.py
    let hello = fs::read(dest_path.join("hello.txt")).expect("read hello.txt");
    assert_eq!(hello, b"Hello, AppendFS v1 compatibility world!\n");

    let data_bin = fs::read(dest_path.join("dir_a/subdir_1/data.bin")).expect("read data.bin");
    assert_eq!(data_bin, appendfs::compat::compat_data_bin());

    let multi = fs::read(dest_path.join("dir_b/multi_extent.dat")).expect("read multi_extent.dat");
    assert_eq!(multi, appendfs::compat::compat_multi_extent_full());

    let sparse = fs::read(dest_path.join("sparse_file.bin")).expect("read sparse_file.bin");
    assert_eq!(sparse.len(), 4196);
    assert_eq!(&sparse[..4096], &[0u8; 4096]);
    assert_eq!(&sparse[4096..], &[0xAA; 100]);

    assert!(dest_path.join("dir_empty").is_dir());
    assert!(dest_path.join("dir_a/subdir_1/deep").is_dir());
    assert_eq!(
        fs::read_link(dest_path.join("symlink_rel")).unwrap(),
        Path::new("hello.txt")
    );
}

#[test]
fn test_python_restore_integrity_checks() {
    let script_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/restore.py");
    if !script_path.is_file() {
        return;
    }

    let py_code = r#"
import sys, tempfile, struct
from pathlib import Path
sys.path.insert(0, 'scripts')
import restore

# 1. Generation gap
with tempfile.TemporaryDirectory() as tmpdir:
    p = Path(tmpdir)
    (p / '000001.log').touch()
    (p / '000003.log').touch()
    try:
        restore.find_log_files(p)
        assert False, "expected gap error"
    except ValueError as e:
        assert "gap detected" in str(e)

# 2. tx_id gap/inversion
v1_log = Path("tests/fixtures/v1/000001.log").read_bytes()
op, tx, ino, plen, tag = struct.unpack(">BQQI16s", v1_log[32:69])
rec2_start = 32 + 37 + plen
op2, tx2, ino2, plen2, tag2 = struct.unpack(">BQQI16s", v1_log[rec2_start:rec2_start + 37])
corrupted = bytearray(v1_log)
corrupted[rec2_start + 1:rec2_start + 9] = struct.pack(">Q", tx2 + 5)
with tempfile.TemporaryDirectory() as tmpdir:
    p = Path(tmpdir)
    (p / "000001.log").write_bytes(corrupted)
    r = restore.Restorer(p / "out", restore.VolumeDecryptor(None))
    try:
        r.replay_log_file(p / "000001.log")
        assert False, "expected tx gap error"
    except ValueError as e:
        assert "Transaction ID gap/inversion" in str(e)

# 3. FlushCommit count mismatch
corrupted = bytearray(v1_log)
offset = 32
while offset < len(v1_log):
    op, tx, ino, plen, tag = struct.unpack(">BQQI16s", v1_log[offset:offset + 37])
    if op == 4:
        corrupted[offset + 37 + 12:offset + 37 + 16] = struct.pack(">I", 999)
        break
    offset += 37 + plen
with tempfile.TemporaryDirectory() as tmpdir:
    p = Path(tmpdir)
    (p / "000001.log").write_bytes(corrupted)
    r = restore.Restorer(p / "out", restore.VolumeDecryptor(None))
    try:
        r.replay_log_file(p / "000001.log")
        assert False, "expected count mismatch error"
    except ValueError as e:
        assert "FlushCommit record count mismatch" in str(e)

# 4. Write to tombstoned inode
with tempfile.TemporaryDirectory() as tmpdir:
    p = Path(tmpdir)
    r = restore.Restorer(p / "out", restore.VolumeDecryptor(None))
    r.tombstoned_inodes.add(42)
    dummy = bytearray(struct.pack(">4sIQIqI", restore.FILE_MAGIC, 1, 1, 0, 0, 0))
    dummy.extend(struct.pack(">BQQI16s", restore.OP_DATA, 1, 42, 4, b"\x00" * 16))
    dummy.extend(b"test")
    (p / "000001.log").write_bytes(dummy)
    try:
        r.replay_log_file(p / "000001.log")
        assert False, "expected tombstone error"
    except ValueError as e:
        assert "previously deleted/tombstoned inode 42" in str(e)

# 5. Data to non-file inode
with tempfile.TemporaryDirectory() as tmpdir:
    p = Path(tmpdir)
    r = restore.Restorer(p / "out", restore.VolumeDecryptor(None))
    dummy = bytearray(struct.pack(">4sIQIqI", restore.FILE_MAGIC, 1, 1, 0, 0, 0))
    dummy.extend(struct.pack(">BQQI16s", restore.OP_DATA, 1, 1, 4, b"\x00" * 16))
    dummy.extend(b"test")
    (p / "000001.log").write_bytes(dummy)
    try:
        r.replay_log_file(p / "000001.log")
        assert False, "expected non-file data error"
    except ValueError as e:
        assert "data record targets non-file inode 1" in str(e)
"#;

    let status = std::process::Command::new("python3")
        .arg("-c")
        .arg(py_code)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status();

    let Ok(status) = status else {
        println!("python3 not available, skipping python restore integrity verification");
        return;
    };

    assert!(status.success(), "scripts/restore.py integrity tests failed");
}
