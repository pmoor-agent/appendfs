use appendfs::compat::CompatClock;
use appendfs::log::init_volume_with_clock_and_uids;
use appendfs::operations::dir::mkdir_core;
use appendfs::operations::read_write::{
    FUSE_SET_ATTR_MODE, create_core, open_core, release_core, setattr_core, write_handle_core,
};
use appendfs::storage::OsStorage;
use appendfs::{Clock, InMemoryFS, LogWriter, Storage, VolumeHeader, VolumeKey};

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

#[test]
fn test_python_restore_with_readonly_file_and_directory() {
    let script_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/restore.py");
    if !script_path.is_file() {
        return;
    }

    let vol_temp = tempfile::tempdir().unwrap();
    let vol_dir = vol_temp.path();

    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(vol_dir));
    let clock = Arc::new(CompatClock::new());
    init_volume_with_clock_and_uids(
        storage.clone(),
        &VolumeKey::plaintext(),
        VolumeHeader::plaintext(),
        clock.clone(),
        1000,
        1000,
    )
    .unwrap();

    let writer = Arc::new(
        LogWriter::create(
            storage.clone(),
            1,
            clock.as_ref(),
            appendfs::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            VolumeKey::plaintext_arc(),
        )
        .map_err(std::io::Error::other)
        .unwrap(),
    );

    let mut fs = InMemoryFS::with_clock_and_uids(clock.clone(), 1000, 1000);
    fs.volume_header = VolumeHeader::plaintext();
    fs.log_writer = Some(writer);
    fs.set_log_dir(vol_dir);

    // Batch 1:
    // Create readonly_file.txt, write initial data, chmod 0444
    let file = create_core(&fs, 1, "readonly_file.txt", 0o644, 0, 1000, 1000).unwrap();
    let fh = open_core(&fs, file.ino, libc::O_RDWR as u32).unwrap();
    write_handle_core(&fs, file.ino, fh, b"Initial data", 0).unwrap();
    release_core(&fs, file.ino, fh).unwrap();
    setattr_core(
        &fs,
        file.ino,
        0o444,
        1000,
        1000,
        0,
        std::time::UNIX_EPOCH,
        std::time::UNIX_EPOCH,
        FUSE_SET_ATTR_MODE,
    )
    .unwrap();

    // Create readonly_dir with mode 0555 and a nested file
    let dir = mkdir_core(&fs, 1, "readonly_dir", 0o755, 1000, 1000).unwrap();
    let nested = create_core(&fs, dir.ino, "nested.txt", 0o644, 0, 1000, 1000).unwrap();
    let n_fh = open_core(&fs, nested.ino, libc::O_RDWR as u32).unwrap();
    write_handle_core(&fs, nested.ino, n_fh, b"Nested content", 0).unwrap();
    release_core(&fs, nested.ino, n_fh).unwrap();
    setattr_core(
        &fs,
        dir.ino,
        0o555,
        1000,
        1000,
        0,
        std::time::UNIX_EPOCH,
        std::time::UNIX_EPOCH,
        FUSE_SET_ATTR_MODE,
    )
    .unwrap();

    fs.quiesce().unwrap();

    // Batch 2:
    // Rewrite readonly_file.txt with new data
    let fh2 = open_core(&fs, file.ino, libc::O_RDWR as u32).unwrap();
    write_handle_core(&fs, file.ino, fh2, b"Rewritten content on readonly file", 0).unwrap();
    release_core(&fs, file.ino, fh2).unwrap();

    fs.quiesce().unwrap();
    drop(fs);

    // Now restore via scripts/restore.py with -v flag
    let dest_temp = tempfile::tempdir().unwrap();
    let dest_path = dest_temp.path();

    let output = std::process::Command::new("python3")
        .arg(&script_path)
        .arg("-v")
        .arg(vol_dir)
        .arg(dest_path)
        .output()
        .expect("execute python3");

    assert!(
        output.status.success(),
        "scripts/restore.py must succeed on readonly rewrites"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Finalizing POSIX permissions and timestamps"),
        "stdout must mention finalizing attributes in -v mode: {stdout}"
    );

    let content = fs::read(dest_path.join("readonly_file.txt")).unwrap();
    assert_eq!(content, b"Rewritten content on readonly file");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let file_perms = fs::metadata(dest_path.join("readonly_file.txt"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_perms, 0o444);

        let dir_perms = fs::metadata(dest_path.join("readonly_dir"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_perms, 0o555);
    }

    let nested_read = fs::read(dest_path.join("readonly_dir/nested.txt")).unwrap();
    assert_eq!(nested_read, b"Nested content");
}

#[test]
fn test_python_restore_across_log_rollover() {
    let script_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/restore.py");
    if !script_path.is_file() {
        return;
    }

    let vol_temp = tempfile::tempdir().unwrap();
    let vol_dir = vol_temp.path();

    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(vol_dir));
    let clock = Arc::new(CompatClock::new());
    init_volume_with_clock_and_uids(
        storage.clone(),
        &VolumeKey::plaintext(),
        VolumeHeader::plaintext(),
        clock.clone(),
        1000,
        1000,
    )
    .unwrap();

    let writer = Arc::new(
        LogWriter::create(
            storage.clone(),
            1,
            clock.as_ref(),
            appendfs::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            VolumeKey::plaintext_arc(),
        )
        .map_err(std::io::Error::other)
        .unwrap(),
    );

    let mut fs = InMemoryFS::with_clock_and_uids(clock.clone(), 1000, 1000);
    fs.volume_header = VolumeHeader::plaintext();
    fs.log_writer = Some(writer);
    fs.set_log_dir(vol_dir);

    // Create directories
    let d1 = mkdir_core(&fs, 1, "eth", 0o755, 1000, 1000).unwrap();
    let d2 = mkdir_core(&fs, d1.ino, "visionen", 0o755, 1000, 1000).unwrap();
    let d3 = mkdir_core(&fs, d2.ino, "2000", 0o755, 1000, 1000).unwrap();

    // Create file
    let file = create_core(&fs, d3.ino, "test.pdf", 0o600, 0, 1000, 1000).unwrap();
    let fh = open_core(&fs, file.ino, libc::O_RDWR as u32).unwrap();

    // Write first chunk: 512 KiB of 0x42 ('B')
    let chunk1 = vec![0x42u8; 512 * 1024];
    write_handle_core(&fs, file.ino, fh, &chunk1, 0).unwrap();

    // Flush batch 1 into log 000001.log
    fs.quiesce().unwrap();

    // Force rollover to 000002.log
    let roll_res = fs.force_roll_active_log().unwrap();
    assert!(roll_res.is_some());

    // Write second chunk: 1.26 MiB (~1324234 bytes) of 0x43 ('C')
    let chunk2_len = 1324234;
    let chunk2 = vec![0x43u8; chunk2_len];
    write_handle_core(&fs, file.ino, fh, &chunk2, chunk1.len() as i64).unwrap();
    release_core(&fs, file.ino, fh).unwrap();

    setattr_core(
        &fs,
        file.ino,
        0o640,
        1000,
        1000,
        0,
        std::time::UNIX_EPOCH,
        std::time::UNIX_EPOCH,
        FUSE_SET_ATTR_MODE,
    )
    .unwrap();

    // Flush batch 2 into log 000002.log
    fs.quiesce().unwrap();
    drop(fs);

    // Run restore
    let dest_temp = tempfile::tempdir().unwrap();
    let dest_path = dest_temp.path();

    let output = std::process::Command::new("python3")
        .arg(&script_path)
        .arg("-v")
        .arg(vol_dir)
        .arg(dest_path)
        .output()
        .expect("execute python3");

    assert!(output.status.success(), "restore failed: {:?}", output);

    let restored_file = dest_path.join("eth/visionen/2000/test.pdf");
    assert!(restored_file.is_file(), "restored file must exist");

    let content = fs::read(&restored_file).unwrap();
    assert_eq!(
        content.len(),
        chunk1.len() + chunk2.len(),
        "length must match total size"
    );
    assert_eq!(&content[..chunk1.len()], &chunk1[..], "first 512 KiB must match chunk1");
    assert_eq!(&content[chunk1.len()..], &chunk2[..], "remainder must match chunk2");
}

#[test]
fn test_python_restore_file_rename() {
    use appendfs::operations::links::rename_core;

    let script_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/restore.py");
    if !script_path.is_file() {
        return;
    }

    let vol_temp = tempfile::tempdir().unwrap();
    let vol_dir = vol_temp.path();

    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(vol_dir));
    let clock = Arc::new(CompatClock::new());
    init_volume_with_clock_and_uids(
        storage.clone(),
        &VolumeKey::plaintext(),
        VolumeHeader::plaintext(),
        clock.clone(),
        1000,
        1000,
    )
    .unwrap();

    let writer = Arc::new(
        LogWriter::create(
            storage.clone(),
            1,
            clock.as_ref(),
            appendfs::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            VolumeKey::plaintext_arc(),
        )
        .map_err(std::io::Error::other)
        .unwrap(),
    );

    let mut fs = InMemoryFS::with_clock_and_uids(clock.clone(), 1000, 1000);
    fs.volume_header = VolumeHeader::plaintext();
    fs.log_writer = Some(writer);
    fs.set_log_dir(vol_dir);

    // Create file as temp.txt, write data
    let file = create_core(&fs, 1, "temp.txt", 0o644, 0, 1000, 1000).unwrap();
    let fh = open_core(&fs, file.ino, libc::O_RDWR as u32).unwrap();
    write_handle_core(&fs, file.ino, fh, b"Hello World from temp file", 0).unwrap();
    release_core(&fs, file.ino, fh).unwrap();

    // Flush batch 1
    fs.quiesce().unwrap();

    // Rename temp.txt -> final.txt
    rename_core(&fs, 1, "temp.txt", 1, "final.txt").unwrap();

    // Flush batch 2
    fs.quiesce().unwrap();
    drop(fs);

    // Run restore
    let dest_temp = tempfile::tempdir().unwrap();
    let dest_path = dest_temp.path();

    let output = std::process::Command::new("python3")
        .arg(&script_path)
        .arg("-v")
        .arg(vol_dir)
        .arg(dest_path)
        .output()
        .expect("execute python3");

    assert!(output.status.success(), "restore failed: {:?}", output);

    let restored_file = dest_path.join("final.txt");
    assert!(restored_file.is_file(), "final.txt must exist after rename");
    let content = fs::read(&restored_file).unwrap();
    assert_eq!(content, b"Hello World from temp file");
}

#[test]
fn test_python_restore_rsync_style_write_across_rollover_and_rename() {
    use appendfs::operations::links::rename_core;

    let script_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/restore.py");
    if !script_path.is_file() {
        return;
    }

    let vol_temp = tempfile::tempdir().unwrap();
    let vol_dir = vol_temp.path();

    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(vol_dir));
    let clock = Arc::new(CompatClock::new());
    init_volume_with_clock_and_uids(
        storage.clone(),
        &VolumeKey::plaintext(),
        VolumeHeader::plaintext(),
        clock.clone(),
        1000,
        1000,
    )
    .unwrap();

    let writer = Arc::new(
        LogWriter::create(
            storage.clone(),
            1,
            clock.as_ref(),
            appendfs::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            VolumeKey::plaintext_arc(),
        )
        .map_err(std::io::Error::other)
        .unwrap(),
    );

    let mut fs = InMemoryFS::with_clock_and_uids(clock.clone(), 1000, 1000);
    fs.volume_header = VolumeHeader::plaintext();
    fs.log_writer = Some(writer);
    fs.set_log_dir(vol_dir);

    // Directory hierarchy
    let d1 = mkdir_core(&fs, 1, "eth", 0o755, 1000, 1000).unwrap();
    let d2 = mkdir_core(&fs, d1.ino, "visionen", 0o755, 1000, 1000).unwrap();
    let d3 = mkdir_core(&fs, d2.ino, "2000", 0o755, 1000, 1000).unwrap();

    // Create temp file like rsync: .visionen.januar.2000.web.pdf.XXXXXX
    let temp_name = ".visionen.januar.2000.web.pdf.tmp123";
    let final_name = "visionen.januar.2000.web.pdf";
    let file = create_core(&fs, d3.ino, temp_name, 0o600, 0, 1000, 1000).unwrap();
    let fh = open_core(&fs, file.ino, libc::O_RDWR as u32).unwrap();

    // Write chunk 1: 512 KiB
    let chunk1 = vec![0x42u8; 512 * 1024];
    write_handle_core(&fs, file.ino, fh, &chunk1, 0).unwrap();

    // Flush batch 1 in Log 1
    fs.quiesce().unwrap();

    // Log rolls over
    fs.force_roll_active_log().unwrap();

    // Write chunk 2: 1.26 MiB (~1324234 bytes)
    let chunk2_len = 1324234;
    let chunk2 = vec![0x43u8; chunk2_len];
    write_handle_core(&fs, file.ino, fh, &chunk2, chunk1.len() as i64).unwrap();
    release_core(&fs, file.ino, fh).unwrap();

    // Chmod 0640, set mtime
    setattr_core(
        &fs,
        file.ino,
        0o640,
        1000,
        1000,
        0,
        std::time::UNIX_EPOCH,
        std::time::UNIX_EPOCH,
        FUSE_SET_ATTR_MODE,
    )
    .unwrap();

    // Atomic rename
    rename_core(&fs, d3.ino, temp_name, d3.ino, final_name).unwrap();

    // Flush batch 2 in Log 2
    fs.quiesce().unwrap();
    drop(fs);

    // Run restore
    let dest_temp = tempfile::tempdir().unwrap();
    let dest_path = dest_temp.path();

    let output = std::process::Command::new("python3")
        .arg(&script_path)
        .arg("-v")
        .arg(vol_dir)
        .arg(dest_path)
        .output()
        .expect("execute python3");

    assert!(output.status.success(), "restore failed: {:?}", output);

    let restored_file = dest_path.join("eth/visionen/2000").join(final_name);
    assert!(restored_file.is_file(), "final file must exist after restore");

    let content = fs::read(&restored_file).unwrap();
    assert_eq!(content.len(), chunk1.len() + chunk2.len(), "length must match");
    assert_eq!(&content[..chunk1.len()], &chunk1[..], "first 512 KiB must match chunk1");
    assert_eq!(&content[chunk1.len()..], &chunk2[..], "tail must match chunk2");
}

#[test]
fn test_python_restore_directory_rename_and_move() {
    use appendfs::operations::links::rename_core;

    let script_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/restore.py");
    if !script_path.is_file() {
        return;
    }

    let vol_temp = tempfile::tempdir().unwrap();
    let vol_dir = vol_temp.path();

    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(vol_dir));
    let clock = Arc::new(CompatClock::new());
    init_volume_with_clock_and_uids(
        storage.clone(),
        &VolumeKey::plaintext(),
        VolumeHeader::plaintext(),
        clock.clone(),
        1000,
        1000,
    )
    .unwrap();

    let writer = Arc::new(
        LogWriter::create(
            storage.clone(),
            1,
            clock.as_ref(),
            appendfs::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            VolumeKey::plaintext_arc(),
        )
        .map_err(std::io::Error::other)
        .unwrap(),
    );

    let mut fs = InMemoryFS::with_clock_and_uids(clock.clone(), 1000, 1000);
    fs.volume_header = VolumeHeader::plaintext();
    fs.log_writer = Some(writer);
    fs.set_log_dir(vol_dir);

    // Create dirA, dirB, and nested file dirA/child.txt
    let dir_a = mkdir_core(&fs, 1, "dirA", 0o755, 1000, 1000).unwrap();
    let dir_b = mkdir_core(&fs, 1, "dirB", 0o755, 1000, 1000).unwrap();
    let child = create_core(&fs, dir_a.ino, "child.txt", 0o644, 0, 1000, 1000).unwrap();
    let fh = open_core(&fs, child.ino, libc::O_RDWR as u32).unwrap();
    write_handle_core(&fs, child.ino, fh, b"child file inside dirA", 0).unwrap();
    release_core(&fs, child.ino, fh).unwrap();

    fs.quiesce().unwrap();

    // Move dirA into dirB as sub_dir
    rename_core(&fs, 1, "dirA", dir_b.ino, "sub_dir").unwrap();

    fs.quiesce().unwrap();
    drop(fs);

    // Restore
    let dest_temp = tempfile::tempdir().unwrap();
    let dest_path = dest_temp.path();

    let output = std::process::Command::new("python3")
        .arg(&script_path)
        .arg("-v")
        .arg(vol_dir)
        .arg(dest_path)
        .output()
        .expect("execute python3");

    assert!(output.status.success(), "restore failed: {:?}", output);

    assert!(!dest_path.join("dirA").exists(), "dirA must not exist at old location");
    let moved_file = dest_path.join("dirB/sub_dir/child.txt");
    assert!(moved_file.is_file(), "child.txt must exist at new location");
    let content = fs::read(&moved_file).unwrap();
    assert_eq!(content, b"child file inside dirA");
}

#[test]
fn test_python_restore_overwrite_rename() {
    use appendfs::operations::links::rename_core;

    let script_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/restore.py");
    if !script_path.is_file() {
        return;
    }

    let vol_temp = tempfile::tempdir().unwrap();
    let vol_dir = vol_temp.path();

    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(vol_dir));
    let clock = Arc::new(CompatClock::new());
    init_volume_with_clock_and_uids(
        storage.clone(),
        &VolumeKey::plaintext(),
        VolumeHeader::plaintext(),
        clock.clone(),
        1000,
        1000,
    )
    .unwrap();

    let writer = Arc::new(
        LogWriter::create(
            storage.clone(),
            1,
            clock.as_ref(),
            appendfs::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            VolumeKey::plaintext_arc(),
        )
        .map_err(std::io::Error::other)
        .unwrap(),
    );

    let mut fs = InMemoryFS::with_clock_and_uids(clock.clone(), 1000, 1000);
    fs.volume_header = VolumeHeader::plaintext();
    fs.log_writer = Some(writer);
    fs.set_log_dir(vol_dir);

    // Create file1 and file2
    let f1 = create_core(&fs, 1, "source.txt", 0o644, 0, 1000, 1000).unwrap();
    let fh1 = open_core(&fs, f1.ino, libc::O_RDWR as u32).unwrap();
    write_handle_core(&fs, f1.ino, fh1, b"new content", 0).unwrap();
    release_core(&fs, f1.ino, fh1).unwrap();

    let f2 = create_core(&fs, 1, "target.txt", 0o644, 0, 1000, 1000).unwrap();
    let fh2 = open_core(&fs, f2.ino, libc::O_RDWR as u32).unwrap();
    write_handle_core(&fs, f2.ino, fh2, b"old content that will be overwritten", 0).unwrap();
    release_core(&fs, f2.ino, fh2).unwrap();

    fs.quiesce().unwrap();

    // Overwrite target.txt with source.txt
    rename_core(&fs, 1, "source.txt", 1, "target.txt").unwrap();

    fs.quiesce().unwrap();
    drop(fs);

    // Restore
    let dest_temp = tempfile::tempdir().unwrap();
    let dest_path = dest_temp.path();

    let output = std::process::Command::new("python3")
        .arg(&script_path)
        .arg("-v")
        .arg(vol_dir)
        .arg(dest_path)
        .output()
        .expect("execute python3");

    assert!(output.status.success(), "restore failed: {:?}", output);

    assert!(!dest_path.join("source.txt").exists(), "source.txt must not exist");
    let target_file = dest_path.join("target.txt");
    assert!(target_file.is_file(), "target.txt must exist");
    let content = fs::read(&target_file).unwrap();
    assert_eq!(content, b"new content");
}

#[test]
fn test_python_restore_hardlinks_and_unlink() {
    use appendfs::operations::links::{link_core, unlink_core};

    let script_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/restore.py");
    if !script_path.is_file() {
        return;
    }

    let vol_temp = tempfile::tempdir().unwrap();
    let vol_dir = vol_temp.path();

    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(vol_dir));
    let clock = Arc::new(CompatClock::new());
    init_volume_with_clock_and_uids(
        storage.clone(),
        &VolumeKey::plaintext(),
        VolumeHeader::plaintext(),
        clock.clone(),
        1000,
        1000,
    )
    .unwrap();

    let writer = Arc::new(
        LogWriter::create(
            storage.clone(),
            1,
            clock.as_ref(),
            appendfs::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            VolumeKey::plaintext_arc(),
        )
        .map_err(std::io::Error::other)
        .unwrap(),
    );

    let mut fs = InMemoryFS::with_clock_and_uids(clock.clone(), 1000, 1000);
    fs.volume_header = VolumeHeader::plaintext();
    fs.log_writer = Some(writer);
    fs.set_log_dir(vol_dir);

    // Create file
    let f = create_core(&fs, 1, "original.txt", 0o644, 0, 1000, 1000).unwrap();
    let fh = open_core(&fs, f.ino, libc::O_RDWR as u32).unwrap();
    write_handle_core(&fs, f.ino, fh, b"hardlinked data", 0).unwrap();
    release_core(&fs, f.ino, fh).unwrap();

    // Create hardlink
    link_core(&fs, f.ino, 1, "link1.txt").unwrap();
    link_core(&fs, f.ino, 1, "link2.txt").unwrap();

    fs.quiesce().unwrap();

    // Unlink original.txt, leaving link1.txt and link2.txt
    unlink_core(&fs, 1, "original.txt").unwrap();

    fs.quiesce().unwrap();
    drop(fs);

    // Restore
    let dest_temp = tempfile::tempdir().unwrap();
    let dest_path = dest_temp.path();

    let output = std::process::Command::new("python3")
        .arg(&script_path)
        .arg("-v")
        .arg(vol_dir)
        .arg(dest_path)
        .output()
        .expect("execute python3");

    assert!(output.status.success(), "restore failed: {:?}", output);

    assert!(!dest_path.join("original.txt").exists(), "original.txt was unlinked");
    let l1 = dest_path.join("link1.txt");
    let l2 = dest_path.join("link2.txt");
    assert!(l1.is_file(), "link1.txt must exist");
    assert!(l2.is_file(), "link2.txt must exist");
    assert_eq!(fs::read(&l1).unwrap(), b"hardlinked data");
    assert_eq!(fs::read(&l2).unwrap(), b"hardlinked data");

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            fs::metadata(&l1).unwrap().ino(),
            fs::metadata(&l2).unwrap().ino(),
            "link1 and link2 must share the same physical inode"
        );
    }
}

#[test]
fn test_python_restore_hardlinks_same_name_in_different_dirs() {
    use appendfs::operations::links::link_core;

    let script_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/restore.py");
    if !script_path.is_file() {
        return;
    }

    let vol_temp = tempfile::tempdir().unwrap();
    let vol_dir = vol_temp.path();

    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(vol_dir));
    let clock = Arc::new(CompatClock::new());
    init_volume_with_clock_and_uids(
        storage.clone(),
        &VolumeKey::plaintext(),
        VolumeHeader::plaintext(),
        clock.clone(),
        1000,
        1000,
    )
    .unwrap();

    let writer = Arc::new(
        LogWriter::create(
            storage.clone(),
            1,
            clock.as_ref(),
            appendfs::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            VolumeKey::plaintext_arc(),
        )
        .map_err(std::io::Error::other)
        .unwrap(),
    );

    let mut fs = InMemoryFS::with_clock_and_uids(clock.clone(), 1000, 1000);
    fs.volume_header = VolumeHeader::plaintext();
    fs.log_writer = Some(writer);
    fs.set_log_dir(vol_dir);

    // Create dir1 and dir2
    let d1 = mkdir_core(&fs, 1, "dir1", 0o755, 1000, 1000).unwrap();
    let d2 = mkdir_core(&fs, 1, "dir2", 0o755, 1000, 1000).unwrap();

    // Create dir1/shared.dat
    let f = create_core(&fs, d1.ino, "shared.dat", 0o644, 0, 1000, 1000).unwrap();
    let fh = open_core(&fs, f.ino, libc::O_RDWR as u32).unwrap();
    write_handle_core(&fs, f.ino, fh, b"initial shared payload", 0).unwrap();
    release_core(&fs, f.ino, fh).unwrap();

    // Hardlink to dir2/shared.dat (same filename, different parent)
    link_core(&fs, f.ino, d2.ino, "shared.dat").unwrap();

    fs.quiesce().unwrap();

    // Log roll
    fs.force_roll_active_log().unwrap();

    // Write more data in new log
    let fh2 = open_core(&fs, f.ino, libc::O_RDWR as u32).unwrap();
    write_handle_core(&fs, f.ino, fh2, b" -- appended after rollover", 22).unwrap();
    release_core(&fs, f.ino, fh2).unwrap();

    fs.quiesce().unwrap();
    drop(fs);

    // Restore
    let dest_temp = tempfile::tempdir().unwrap();
    let dest_path = dest_temp.path();

    let output = std::process::Command::new("python3")
        .arg(&script_path)
        .arg("-v")
        .arg(vol_dir)
        .arg(dest_path)
        .output()
        .expect("execute python3");

    assert!(output.status.success(), "restore failed: {:?}", output);

    let p1 = dest_path.join("dir1/shared.dat");
    let p2 = dest_path.join("dir2/shared.dat");
    assert!(p1.is_file(), "dir1/shared.dat must exist");
    assert!(p2.is_file(), "dir2/shared.dat must exist");
    assert_eq!(
        fs::read(&p1).unwrap(),
        b"initial shared payload -- appended after rollover"
    );
    assert_eq!(
        fs::read(&p2).unwrap(),
        b"initial shared payload -- appended after rollover"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            fs::metadata(&p1).unwrap().ino(),
            fs::metadata(&p2).unwrap().ino(),
            "both hardlinks must share physical inode"
        );
    }
}

#[test]
fn test_python_restore_directory_overwrite_rename() {
    use appendfs::operations::links::rename_core;

    let script_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/restore.py");
    if !script_path.is_file() {
        return;
    }

    let vol_temp = tempfile::tempdir().unwrap();
    let vol_dir = vol_temp.path();

    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(vol_dir));
    let clock = Arc::new(CompatClock::new());
    init_volume_with_clock_and_uids(
        storage.clone(),
        &VolumeKey::plaintext(),
        VolumeHeader::plaintext(),
        clock.clone(),
        1000,
        1000,
    )
    .unwrap();

    let writer = Arc::new(
        LogWriter::create(
            storage.clone(),
            1,
            clock.as_ref(),
            appendfs::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            VolumeKey::plaintext_arc(),
        )
        .map_err(std::io::Error::other)
        .unwrap(),
    );

    let mut fs = InMemoryFS::with_clock_and_uids(clock.clone(), 1000, 1000);
    fs.volume_header = VolumeHeader::plaintext();
    fs.log_writer = Some(writer);
    fs.set_log_dir(vol_dir);

    // Create dir_a with file inside
    let dir_a = mkdir_core(&fs, 1, "dir_a", 0o755, 1000, 1000).unwrap();
    let file = create_core(&fs, dir_a.ino, "inner.txt", 0o644, 0, 1000, 1000).unwrap();
    let fh = open_core(&fs, file.ino, libc::O_RDWR as u32).unwrap();
    write_handle_core(&fs, file.ino, fh, b"inside dir_a", 0).unwrap();
    release_core(&fs, file.ino, fh).unwrap();

    // Create empty dir_b
    let _dir_b = mkdir_core(&fs, 1, "dir_b", 0o755, 1000, 1000).unwrap();

    fs.quiesce().unwrap();

    // Rename dir_a to overwrite dir_b
    rename_core(&fs, 1, "dir_a", 1, "dir_b").unwrap();

    fs.quiesce().unwrap();
    drop(fs);

    // Restore
    let dest_temp = tempfile::tempdir().unwrap();
    let dest_path = dest_temp.path();

    let output = std::process::Command::new("python3")
        .arg(&script_path)
        .arg("-v")
        .arg(vol_dir)
        .arg(dest_path)
        .output()
        .expect("execute python3");

    assert!(output.status.success(), "restore failed: {:?}", output);

    assert!(!dest_path.join("dir_a").exists(), "dir_a must not exist");
    let inner_file = dest_path.join("dir_b/inner.txt");
    assert!(inner_file.is_file(), "dir_b/inner.txt must exist");
    assert_eq!(fs::read(&inner_file).unwrap(), b"inside dir_a");
}

#[test]
fn test_python_restore_sparse_hole_and_expansion() {
    use appendfs::operations::read_write::fallocate_core;

    let script_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/restore.py");
    if !script_path.is_file() {
        return;
    }

    let vol_temp = tempfile::tempdir().unwrap();
    let vol_dir = vol_temp.path();

    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(vol_dir));
    let clock = Arc::new(CompatClock::new());
    init_volume_with_clock_and_uids(
        storage.clone(),
        &VolumeKey::plaintext(),
        VolumeHeader::plaintext(),
        clock.clone(),
        1000,
        1000,
    )
    .unwrap();

    let writer = Arc::new(
        LogWriter::create(
            storage.clone(),
            1,
            clock.as_ref(),
            appendfs::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            VolumeKey::plaintext_arc(),
        )
        .map_err(std::io::Error::other)
        .unwrap(),
    );

    let mut fs = InMemoryFS::with_clock_and_uids(clock.clone(), 1000, 1000);
    fs.volume_header = VolumeHeader::plaintext();
    fs.log_writer = Some(writer);
    fs.set_log_dir(vol_dir);

    // Create file
    let file = create_core(&fs, 1, "sparse.bin", 0o644, 0, 1000, 1000).unwrap();
    let fh = open_core(&fs, file.ino, libc::O_RDWR as u32).unwrap();

    // Write chunk at offset 0 (4 KiB)
    let chunk0 = vec![0xAAu8; 4096];
    write_handle_core(&fs, file.ino, fh, &chunk0, 0).unwrap();

    // Write chunk at offset 64 KiB (leaving a hole 4 KiB..64 KiB)
    let chunk1 = vec![0xBBu8; 4096];
    write_handle_core(&fs, file.ino, fh, &chunk1, 64 * 1024).unwrap();

    fs.quiesce().unwrap();

    // Log roll
    fs.force_roll_active_log().unwrap();

    // Punch hole inside chunk0: punch 1 KiB..3 KiB
    fallocate_core(
        &fs,
        file.ino,
        libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
        1024,
        2048,
    )
    .unwrap();
    release_core(&fs, file.ino, fh).unwrap();

    fs.quiesce().unwrap();
    drop(fs);

    // Restore
    let dest_temp = tempfile::tempdir().unwrap();
    let dest_path = dest_temp.path();

    let output = std::process::Command::new("python3")
        .arg(&script_path)
        .arg("-v")
        .arg(vol_dir)
        .arg(dest_path)
        .output()
        .expect("execute python3");

    assert!(output.status.success(), "restore failed: {:?}", output);

    let restored_file = dest_path.join("sparse.bin");
    assert!(restored_file.is_file(), "sparse.bin must exist");
    let content = fs::read(&restored_file).unwrap();
    assert_eq!(content.len(), 68 * 1024);

    // 0..1024: 0xAA
    assert_eq!(&content[0..1024], &[0xAAu8; 1024]);
    // 1024..3072: 0x00 (punched hole)
    assert_eq!(&content[1024..3072], &[0x00u8; 2048]);
    // 3072..4096: 0xAA
    assert_eq!(&content[3072..4096], &[0xAAu8; 1024]);
    // 4096..65536: 0x00 (expansion hole)
    assert_eq!(&content[4096..65536], &[0x00u8; 61440]);
    // 65536..69632: 0xBB
    assert_eq!(&content[65536..69632], &[0xBBu8; 4096]);
}

#[test]
fn test_python_restore_rejects_record_after_seal() {
    let script_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/restore.py");
    if !script_path.is_file() {
        return;
    }

    let vol_temp = tempfile::tempdir().unwrap();
    let vol_dir = vol_temp.path();

    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(vol_dir));
    let clock = Arc::new(CompatClock::new());
    init_volume_with_clock_and_uids(
        storage.clone(),
        &VolumeKey::plaintext(),
        VolumeHeader::plaintext(),
        clock.clone(),
        1000,
        1000,
    )
    .unwrap();

    let writer = Arc::new(
        LogWriter::create(
            storage.clone(),
            1,
            clock.as_ref(),
            10_000,
            1,
            VolumeKey::plaintext_arc(),
        )
        .unwrap(),
    );

    let mut fs = InMemoryFS::with_clock_and_uids(clock.clone(), 1000, 1000);
    fs.volume_header = VolumeHeader::plaintext();
    fs.log_writer = Some(writer.clone());
    fs.set_log_dir(vol_dir);

    mkdir_core(&fs, 1, "dir1", 0o755, 1000, 1000).unwrap();
    fs.quiesce().unwrap();

    // Seal gen 1 cleanly
    writer.seal_active(clock.as_ref()).unwrap();
    fs.log_writer = None;
    drop(fs);
    drop(writer);

    // Append an extraneous record after seal directly to 000001.log
    let log_file = vol_dir.join("000001.log");
    let mut log_bytes = fs::read(&log_file).unwrap();
    let extra_payload = b"extraneous";
    let (_, cipher, tag) = appendfs::log::codec::encode(
        &VolumeKey::plaintext(),
        appendfs::compress::Compression::None,
        appendfs::log::codec::RecordId {
            generation: 1,
            // Past every sequence the writer used in this generation.
            sequence: 1_000,
            op_code: appendfs::log::OpCode::Data as u8,
            inode: 2,
        },
        extra_payload,
    )
    .unwrap();
    let extra_header = appendfs::log::record::RecordHeader {
        op_code: appendfs::log::OpCode::Data,
        inode: 2,
        payload_len: cipher.len() as u32,
        sequence: 1_000,
        auth_tag: tag,
    };
    log_bytes.extend_from_slice(&extra_header.to_bytes());
    log_bytes.extend_from_slice(&cipher);
    fs::write(&log_file, log_bytes).unwrap();

    // Restore must fail
    let dest_temp = tempfile::tempdir().unwrap();
    let dest_path = dest_temp.path();

    let output = std::process::Command::new("python3")
        .arg(&script_path)
        .arg(vol_dir)
        .arg(dest_path)
        .output()
        .expect("execute python3");

    assert!(!output.status.success(), "restore should fail on record after seal");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("extraneous record op=1 found after Seal record"),
        "expected extraneous record error, got: {}",
        stderr
    );
}

#[test]
fn test_python_restore_rejects_seal_record_count_mismatch() {
    let script_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/restore.py");
    if !script_path.is_file() {
        return;
    }

    let vol_temp = tempfile::tempdir().unwrap();
    let vol_dir = vol_temp.path();

    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(vol_dir));
    let clock = Arc::new(CompatClock::new());
    init_volume_with_clock_and_uids(
        storage.clone(),
        &VolumeKey::plaintext(),
        VolumeHeader::plaintext(),
        clock.clone(),
        1000,
        1000,
    )
    .unwrap();

    let writer = Arc::new(
        LogWriter::create(
            storage.clone(),
            1,
            clock.as_ref(),
            10_000,
            1,
            VolumeKey::plaintext_arc(),
        )
        .unwrap(),
    );

    let mut fs = InMemoryFS::with_clock_and_uids(clock.clone(), 1000, 1000);
    fs.volume_header = VolumeHeader::plaintext();
    fs.log_writer = Some(writer.clone());
    fs.set_log_dir(vol_dir);

    mkdir_core(&fs, 1, "dir1", 0o755, 1000, 1000).unwrap();
    fs.quiesce().unwrap();

    // Seal gen 1 cleanly
    writer.seal_active(clock.as_ref()).unwrap();
    fs.log_writer = None;
    drop(fs);
    drop(writer);

    // Read valid records without the seal
    let log_file = vol_dir.join("000001.log");
    let mut reader =
        appendfs::log::LogReader::open(storage.as_ref(), "000001.log", VolumeKey::plaintext_arc()).unwrap();
    let mut valid_records = Vec::new();
    for r in &mut reader {
        let rec = r.unwrap();
        if rec.header.op_code != appendfs::log::OpCode::Seal {
            valid_records.push(rec);
        }
    }
    drop(reader);

    // Reconstruct 000001.log with valid records + bad seal count
    let file_header = appendfs::log::record::FileHeader::new(1, clock.now());
    let mut new_bytes = file_header.to_bytes().to_vec();
    for rec in valid_records {
        let h = rec.header.to_bytes();
        new_bytes.extend_from_slice(&h);
        new_bytes.extend_from_slice(&rec.payload);
    }

    let bad_seal = appendfs::log::record::SealPayload {
        timestamp: clock.now(),
        record_count: 999, // Mismatch!
    };
    let bad_payload = appendfs::wire::serialize(&bad_seal).unwrap();
    let (_, cipher, tag) = appendfs::log::codec::encode(
        &VolumeKey::plaintext(),
        appendfs::compress::Compression::None,
        appendfs::log::codec::RecordId {
            generation: 1,
            // Past every sequence the writer used in this generation.
            sequence: 1_000,
            op_code: appendfs::log::OpCode::Seal as u8,
            inode: 0,
        },
        &bad_payload,
    )
    .unwrap();
    let tagged_header = appendfs::log::record::RecordHeader {
        op_code: appendfs::log::OpCode::Seal,
        inode: 0,
        payload_len: cipher.len() as u32,
        sequence: 1_000,
        auth_tag: tag,
    };
    new_bytes.extend_from_slice(&tagged_header.to_bytes());
    new_bytes.extend_from_slice(&cipher);
    fs::write(&log_file, new_bytes).unwrap();

    // Restore must fail
    let dest_temp = tempfile::tempdir().unwrap();
    let dest_path = dest_temp.path();

    let output = std::process::Command::new("python3")
        .arg(&script_path)
        .arg(vol_dir)
        .arg(dest_path)
        .output()
        .expect("execute python3");

    assert!(
        !output.status.success(),
        "restore should fail on seal record count mismatch"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Seal record count mismatch"),
        "expected seal count mismatch error, got: {}",
        stderr
    );
}
