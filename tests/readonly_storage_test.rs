use appendfs::crypto::VolumeKey;
use appendfs::fs::InMemoryFS;
use appendfs::log::{LogFileCache, LogWriter};
use appendfs::remote::OnDiskBlockCache;
use appendfs::storage::{MemoryStorage, ReadOnlyStorage, Storage, WriteMode};
use std::io;
use std::sync::Arc;

#[test]
fn test_read_only_storage_prohibits_all_mutations() {
    let mem = Arc::new(MemoryStorage::new());
    mem.insert_file("000001.log", b"test data".to_vec());
    let ro = ReadOnlyStorage::new(mem.clone());

    // Reads succeed
    assert!(ro.exists("000001.log"));
    assert_eq!(ro.file_len("000001.log").unwrap(), 9);
    assert_eq!(ro.list_files().unwrap(), vec!["000001.log".to_string()]);

    let reader = ro.open_reader("000001.log").unwrap();
    let mut buf = [0u8; 9];
    reader.read_exact_at(0, &mut buf).unwrap();
    assert_eq!(&buf, b"test data");

    // All mutating operations fail with PermissionDenied
    assert!(matches!(
        ro.open_writer("000002.log", WriteMode::CreateNew),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied
    ));

    let err_remove = ro.remove_file("000001.log").unwrap_err();
    assert_eq!(err_remove.kind(), io::ErrorKind::PermissionDenied);

    let err_rename = ro.rename("000001.log", "000002.log").unwrap_err();
    assert_eq!(err_rename.kind(), io::ErrorKind::PermissionDenied);

    let err_lock = ro.acquire_exclusive_lock().unwrap_err();
    assert_eq!(err_lock.kind(), io::ErrorKind::PermissionDenied);
}

#[test]
fn test_log_writer_creation_fails_on_read_only_storage() {
    let mem: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let ro_storage: Arc<dyn Storage> = Arc::new(ReadOnlyStorage::new(mem));

    let res = LogWriter::create_lazy(
        ro_storage,
        1,
        appendfs::cli::DEFAULT_MAX_LOG_SIZE,
        1,
        VolumeKey::plaintext_arc(),
    );
    assert!(res.is_err(), "LogWriter creation must fail on ReadOnlyStorage");
    assert_eq!(res.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
}

#[test]
#[should_panic(expected = "cannot attach a log writer to a read-only filesystem")]
fn test_attach_log_writer_panics_on_read_only_mount() {
    let mut fs = InMemoryFS::new();
    fs.set_read_only();

    let mem: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let writer = Arc::new(
        LogWriter::create_lazy(
            mem,
            1,
            appendfs::cli::DEFAULT_MAX_LOG_SIZE,
            1,
            VolumeKey::plaintext_arc(),
        )
        .unwrap(),
    );
    fs.attach_log_writer(writer);
}

#[test]
fn test_read_only_storage_works_alongside_writable_on_disk_cache() {
    let dir = tempfile::tempdir().unwrap();
    let cache_dir = dir.path().join(".cache");

    // Underlying volume storage is read-only
    let mem = Arc::new(MemoryStorage::new());
    mem.insert_file("000001.log", b"log header and content".to_vec());
    let ro_storage: Arc<dyn Storage> = Arc::new(ReadOnlyStorage::new(mem));

    // On-disk block cache operates in cache_dir and remains read-write
    let block_cache = Arc::new(OnDiskBlockCache::new(&cache_dir, 1024 * 1024).unwrap());

    let log_cache = LogFileCache::with_remote_support(
        ro_storage.clone(),
        Some(block_cache.clone()),
        Vec::<appendfs::remote::RemoteReadTarget>::new(),
        None,
    );

    // Reading through log cache works
    assert!(ro_storage.exists("000001.log"));
    assert!(matches!(
        ro_storage.open_writer("000002.log", WriteMode::CreateNew),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied
    ));

    // On-disk block cache can write and read cached chunks without issues
    let chunk_payload = b"cached chunk data from remote";
    block_cache.write_block("000001", 0, chunk_payload).unwrap();
    let read_cached = block_cache.read_block("000001", 0).unwrap();
    assert_eq!(read_cached.as_deref(), Some(&chunk_payload[..]));

    drop(log_cache);
}
