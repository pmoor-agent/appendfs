use appendfs::FsTestExt;
use appendfs::compat::CompatClock;
use appendfs::operations::read_write::{FUSE_SET_ATTR_MODE, open_core, release_core, setattr_core, write_handle_core};
use appendfs::storage::OsStorage;
use appendfs::{Clock, Storage, TestFs, VolumeKey};

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
    let TestFs { fs, .. } = TestFs::builder()
        .storage(storage)
        .clock(clock.clone())
        .root_owner(1000, 1000)
        .build();

    // Batch 1:
    // Create readonly_file.txt, write initial data, chmod 0444
    let file = fs.create_file(1, "readonly_file.txt", 0o644).unwrap();
    let fh = open_core(&fs, file, libc::O_RDWR as u32).unwrap();
    write_handle_core(&fs, file, fh, b"Initial data", 0).unwrap();
    release_core(&fs, file, fh).unwrap();
    setattr_core(
        &fs,
        file,
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
    let dir = fs.make_dir(1, "readonly_dir", 0o755).unwrap();
    let nested = fs.create_file(dir, "nested.txt", 0o644).unwrap();
    let n_fh = open_core(&fs, nested, libc::O_RDWR as u32).unwrap();
    write_handle_core(&fs, nested, n_fh, b"Nested content", 0).unwrap();
    release_core(&fs, nested, n_fh).unwrap();
    setattr_core(
        &fs,
        dir,
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
    let fh2 = open_core(&fs, file, libc::O_RDWR as u32).unwrap();
    write_handle_core(&fs, file, fh2, b"Rewritten content on readonly file", 0).unwrap();
    release_core(&fs, file, fh2).unwrap();

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
    let TestFs { fs, .. } = TestFs::builder()
        .storage(storage)
        .clock(clock.clone())
        .root_owner(1000, 1000)
        .build();

    // Create directories
    let d1 = fs.make_dir(1, "eth", 0o755).unwrap();
    let d2 = fs.make_dir(d1, "visionen", 0o755).unwrap();
    let d3 = fs.make_dir(d2, "2000", 0o755).unwrap();

    // Create file
    let file = fs.create_file(d3, "test.pdf", 0o600).unwrap();
    let fh = open_core(&fs, file, libc::O_RDWR as u32).unwrap();

    // Write first chunk: 512 KiB of 0x42 ('B')
    let chunk1 = vec![0x42u8; 512 * 1024];
    write_handle_core(&fs, file, fh, &chunk1, 0).unwrap();

    // Flush batch 1 into log 000001.log
    fs.quiesce().unwrap();

    // Force rollover to 000002.log
    let roll_res = fs.force_roll_active_log().unwrap();
    assert!(roll_res.is_some());

    // Write second chunk: 1.26 MiB (~1324234 bytes) of 0x43 ('C')
    let chunk2_len = 1324234;
    let chunk2 = vec![0x43u8; chunk2_len];
    write_handle_core(&fs, file, fh, &chunk2, chunk1.len() as i64).unwrap();
    release_core(&fs, file, fh).unwrap();

    setattr_core(
        &fs,
        file,
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
    let TestFs { fs, .. } = TestFs::builder()
        .storage(storage)
        .clock(clock.clone())
        .root_owner(1000, 1000)
        .build();

    // Create file as temp.txt, write data
    let file = fs.create_file(1, "temp.txt", 0o644).unwrap();
    let fh = open_core(&fs, file, libc::O_RDWR as u32).unwrap();
    write_handle_core(&fs, file, fh, b"Hello World from temp file", 0).unwrap();
    release_core(&fs, file, fh).unwrap();

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
    let TestFs { fs, .. } = TestFs::builder()
        .storage(storage)
        .clock(clock.clone())
        .root_owner(1000, 1000)
        .build();

    // Directory hierarchy
    let d1 = fs.make_dir(1, "eth", 0o755).unwrap();
    let d2 = fs.make_dir(d1, "visionen", 0o755).unwrap();
    let d3 = fs.make_dir(d2, "2000", 0o755).unwrap();

    // Create temp file like rsync: .visionen.januar.2000.web.pdf.XXXXXX
    let temp_name = ".visionen.januar.2000.web.pdf.tmp123";
    let final_name = "visionen.januar.2000.web.pdf";
    let file = fs.create_file(d3, temp_name, 0o600).unwrap();
    let fh = open_core(&fs, file, libc::O_RDWR as u32).unwrap();

    // Write chunk 1: 512 KiB
    let chunk1 = vec![0x42u8; 512 * 1024];
    write_handle_core(&fs, file, fh, &chunk1, 0).unwrap();

    // Flush batch 1 in Log 1
    fs.quiesce().unwrap();

    // Log rolls over
    fs.force_roll_active_log().unwrap();

    // Write chunk 2: 1.26 MiB (~1324234 bytes)
    let chunk2_len = 1324234;
    let chunk2 = vec![0x43u8; chunk2_len];
    write_handle_core(&fs, file, fh, &chunk2, chunk1.len() as i64).unwrap();
    release_core(&fs, file, fh).unwrap();

    // Chmod 0640, set mtime
    setattr_core(
        &fs,
        file,
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
    rename_core(&fs, d3, temp_name, d3, final_name).unwrap();

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
    let TestFs { fs, .. } = TestFs::builder()
        .storage(storage)
        .clock(clock.clone())
        .root_owner(1000, 1000)
        .build();

    // Create dirA, dirB, and nested file dirA/child.txt
    let dir_a = fs.make_dir(1, "dirA", 0o755).unwrap();
    let dir_b = fs.make_dir(1, "dirB", 0o755).unwrap();
    let child = fs.create_file(dir_a, "child.txt", 0o644).unwrap();
    let fh = open_core(&fs, child, libc::O_RDWR as u32).unwrap();
    write_handle_core(&fs, child, fh, b"child file inside dirA", 0).unwrap();
    release_core(&fs, child, fh).unwrap();

    fs.quiesce().unwrap();

    // Move dirA into dirB as sub_dir
    rename_core(&fs, 1, "dirA", dir_b, "sub_dir").unwrap();

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
    let TestFs { fs, .. } = TestFs::builder()
        .storage(storage)
        .clock(clock.clone())
        .root_owner(1000, 1000)
        .build();

    // Create file1 and file2
    let f1 = fs.create_file(1, "source.txt", 0o644).unwrap();
    let fh1 = open_core(&fs, f1, libc::O_RDWR as u32).unwrap();
    write_handle_core(&fs, f1, fh1, b"new content", 0).unwrap();
    release_core(&fs, f1, fh1).unwrap();

    let f2 = fs.create_file(1, "target.txt", 0o644).unwrap();
    let fh2 = open_core(&fs, f2, libc::O_RDWR as u32).unwrap();
    write_handle_core(&fs, f2, fh2, b"old content that will be overwritten", 0).unwrap();
    release_core(&fs, f2, fh2).unwrap();

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
    let TestFs { fs, .. } = TestFs::builder()
        .storage(storage)
        .clock(clock.clone())
        .root_owner(1000, 1000)
        .build();

    // Create file
    let f = fs.create_file(1, "original.txt", 0o644).unwrap();
    let fh = open_core(&fs, f, libc::O_RDWR as u32).unwrap();
    write_handle_core(&fs, f, fh, b"hardlinked data", 0).unwrap();
    release_core(&fs, f, fh).unwrap();

    // Create hardlink
    link_core(&fs, f, 1, "link1.txt").unwrap();
    link_core(&fs, f, 1, "link2.txt").unwrap();

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
    let TestFs { fs, .. } = TestFs::builder()
        .storage(storage)
        .clock(clock.clone())
        .root_owner(1000, 1000)
        .build();

    // Create dir1 and dir2
    let d1 = fs.make_dir(1, "dir1", 0o755).unwrap();
    let d2 = fs.make_dir(1, "dir2", 0o755).unwrap();

    // Create dir1/shared.dat
    let f = fs.create_file(d1, "shared.dat", 0o644).unwrap();
    let fh = open_core(&fs, f, libc::O_RDWR as u32).unwrap();
    write_handle_core(&fs, f, fh, b"initial shared payload", 0).unwrap();
    release_core(&fs, f, fh).unwrap();

    // Hardlink to dir2/shared.dat (same filename, different parent)
    link_core(&fs, f, d2, "shared.dat").unwrap();

    fs.quiesce().unwrap();

    // Log roll
    fs.force_roll_active_log().unwrap();

    // Write more data in new log
    let fh2 = open_core(&fs, f, libc::O_RDWR as u32).unwrap();
    write_handle_core(&fs, f, fh2, b" -- appended after rollover", 22).unwrap();
    release_core(&fs, f, fh2).unwrap();

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
    let TestFs { fs, .. } = TestFs::builder()
        .storage(storage)
        .clock(clock.clone())
        .root_owner(1000, 1000)
        .build();

    // Create dir_a with file inside
    let dir_a = fs.make_dir(1, "dir_a", 0o755).unwrap();
    let file = fs.create_file(dir_a, "inner.txt", 0o644).unwrap();
    let fh = open_core(&fs, file, libc::O_RDWR as u32).unwrap();
    write_handle_core(&fs, file, fh, b"inside dir_a", 0).unwrap();
    release_core(&fs, file, fh).unwrap();

    // Create empty dir_b
    let _dir_b = fs.make_dir(1, "dir_b", 0o755).unwrap();

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
    let TestFs { fs, .. } = TestFs::builder()
        .storage(storage)
        .clock(clock.clone())
        .root_owner(1000, 1000)
        .build();

    // Create file
    let file = fs.create_file(1, "sparse.bin", 0o644).unwrap();
    let fh = open_core(&fs, file, libc::O_RDWR as u32).unwrap();

    // Write chunk at offset 0 (4 KiB)
    let chunk0 = vec![0xAAu8; 4096];
    write_handle_core(&fs, file, fh, &chunk0, 0).unwrap();

    // Write chunk at offset 64 KiB (leaving a hole 4 KiB..64 KiB)
    let chunk1 = vec![0xBBu8; 4096];
    write_handle_core(&fs, file, fh, &chunk1, 64 * 1024).unwrap();

    fs.quiesce().unwrap();

    // Log roll
    fs.force_roll_active_log().unwrap();

    // Punch hole inside chunk0: punch 1 KiB..3 KiB
    fallocate_core(
        &fs,
        file,
        libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
        1024,
        2048,
    )
    .unwrap();
    release_core(&fs, file, fh).unwrap();

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
    let TestFs { mut fs, .. } = TestFs::builder()
        .storage(storage.clone())
        .clock(clock.clone())
        .root_owner(1000, 1000)
        .max_log_size(10_000)
        .build();
    let writer = fs.log_writer.clone().unwrap();

    fs.make_dir(1, "dir1", 0o755).unwrap();
    fs.quiesce().unwrap();

    // Seal gen 1 cleanly
    writer.seal_active().unwrap();
    fs.log_writer = None;
    drop(fs);
    drop(writer);

    // Append an extraneous record after seal directly to 000001.log
    let log_file = vol_dir.join("000001.log");
    let mut log_bytes = fs::read(&log_file).unwrap();
    let file_salt =
        appendfs::log::record::FileHeader::from_bytes(log_bytes[..appendfs::log::FILE_HEADER_SIZE].try_into().unwrap())
            .unwrap()
            .key_salt;
    let extra_payload = b"extraneous";
    let (_, cipher, tag) = appendfs::log::codec::encode(
        &VolumeKey::plaintext().log_file_key(&file_salt),
        appendfs::compress::Compression::None,
        appendfs::log::codec::RecordId {
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
    let TestFs { mut fs, .. } = TestFs::builder()
        .storage(storage.clone())
        .clock(clock.clone())
        .root_owner(1000, 1000)
        .max_log_size(10_000)
        .build();
    let writer = fs.log_writer.clone().unwrap();

    fs.make_dir(1, "dir1", 0o755).unwrap();
    fs.quiesce().unwrap();

    // Seal gen 1 cleanly
    writer.seal_active().unwrap();
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
    // Keep the original header: it carries the salt the kept records are keyed by.
    let original = fs::read(&log_file).unwrap();
    let file_header =
        appendfs::log::record::FileHeader::from_bytes(original[..appendfs::log::FILE_HEADER_SIZE].try_into().unwrap())
            .unwrap();
    let file_salt = file_header.key_salt;
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
        &VolumeKey::plaintext().log_file_key(&file_salt),
        appendfs::compress::Compression::None,
        appendfs::log::codec::RecordId {
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
