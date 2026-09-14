use appendfs::compat::CompatClock;
use appendfs::log::init_volume_with_clock_and_uids;
use appendfs::operations::dir::mkdir_core;
use appendfs::operations::read_write::{
    FUSE_SET_ATTR_MODE, create_core, open_core, release_core, setattr_core, write_handle_core,
};
use appendfs::storage::OsStorage;
use appendfs::{InMemoryFS, LogWriter, Storage, VolumeHeader, VolumeKey};

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
