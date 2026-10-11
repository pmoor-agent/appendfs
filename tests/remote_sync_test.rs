use appendfs::CheckOptions;
use appendfs::Clock;
use appendfs::FsError;
use appendfs::FsTestExt;
use appendfs::Storage;
use appendfs::TestFs;
use appendfs::clock::SystemClock;
use appendfs::crypto::{VolumeHeader, VolumeKey};
use appendfs::log::{LogFileCache, LogWriter, init_volume};
use appendfs::remote::bootstrap_from_remote;
use appendfs::remote::worker::{cross_copy_file, cross_copy_summary, upload_storage_file};
use appendfs::remote::{
    BlockCache, CountingRemoteStore, FailingRemoteStore, LatencyRemoteStore, LocalDirRemoteStore, MemoryBlockCache,
    MockRemoteStore, PruneContext, PruneExpr, RemoteMode, RemoteRegistry, RemoteStore, RemoteTargetConfig,
    check_remote_integrity,
};
use appendfs::storage::MemoryStorage;
use appendfs::wait_until;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tempfile::TempDir;

#[test]
fn test_remote_replication_and_authenticated_md5_ledger() {
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let clock = Arc::new(SystemClock);

    // 1. Initialize volume
    let TestFs { fs, .. } = TestFs::builder()
        .storage(storage.clone())
        .clock(clock.clone())
        .max_log_size(1024 * 1024)
        .build();
    assert!(storage.exists("000000.summary"));
    let writer = fs.log_writer.clone().unwrap();

    // 2. Append records to multiple generations

    // Write file 1 (gen 1)
    let root = 1;
    let file1_ino = fs.create_file(root, "file1.txt", 0o644).unwrap();
    let file_ino = file1_ino;
    let content1 = b"Generation 1 payload: The quick brown fox jumps over the lazy dog";
    fs.write_at(file_ino, content1, 0).unwrap();
    fs.quiesce().unwrap();

    // Force roll to generation 2 (seals gen 1)
    let sealed = writer.force_roll().unwrap().unwrap();
    assert_eq!(sealed.generation, 1);
    fs.manifest.write().unwrap().record_sealed_log(sealed);

    // Write file 2 (gen 2)
    let file2_ino = fs.create_file(root, "file2.txt", 0o644).unwrap();
    let content2 = b"Generation 2 payload: All good things come to an end";
    fs.write_at(file2_ino, content2, 0).unwrap();
    fs.quiesce().unwrap();

    // Export summary snapshot (computes and populates sealed generation 1 MD5 into manifest!)
    let exported_summary = fs.export_summary(storage.as_ref()).unwrap();
    assert_eq!(exported_summary, "000002.summary");

    // Verify generation 1 MD5 is now recorded in the manifest ledger
    let manifest = fs.manifest.read().unwrap().clone();
    let gen1_info = manifest.get_by_generation(1).unwrap();
    let gen1_md5 = gen1_info.md5;

    let gen2_info = manifest.get_by_generation(2).unwrap();
    let gen2_md5 = gen2_info.md5;

    // 3. Setup two mock remote targets: "aws" (writable) and "b2" (writable)
    let remote_aws = Arc::new(MockRemoteStore::new());
    let remote_b2 = Arc::new(MockRemoteStore::new());

    // Upload sealed 000001.log, 000002.log and 000002.summary to remotes
    upload_storage_file(storage.as_ref(), remote_aws.as_ref(), "000001.log", Some(&gen1_md5)).unwrap();
    upload_storage_file(storage.as_ref(), remote_aws.as_ref(), "000002.log", Some(&gen2_md5)).unwrap();
    upload_storage_file(storage.as_ref(), remote_aws.as_ref(), "000002.summary", None).unwrap();

    // Verify remote_aws object matches
    let aws_head = remote_aws.head_object("000001.log").unwrap().unwrap();
    assert_eq!(aws_head.size, gen1_info.total_bytes);
    assert_eq!(aws_head.etag_md5(), Some(gen1_md5));

    // Cross-copy from aws to b2
    cross_copy_file(
        remote_aws.as_ref(),
        remote_b2.as_ref(),
        "000001.log",
        gen1_info.total_bytes,
        &gen1_md5,
    )
    .unwrap();
    cross_copy_file(
        remote_aws.as_ref(),
        remote_b2.as_ref(),
        "000002.log",
        gen2_info.total_bytes,
        &gen2_md5,
    )
    .unwrap();
    let b2_head = remote_b2.head_object("000001.log").unwrap().unwrap();
    assert_eq!(b2_head.size, gen1_info.total_bytes);
    assert_eq!(b2_head.etag_md5(), Some(gen1_md5));

    // Cross-copy summary from aws to b2 with BLAKE3 validation and inline MD5 computation
    let sum2_len = storage.file_len("000002.summary").unwrap();
    cross_copy_summary(remote_aws.as_ref(), remote_b2.as_ref(), "000002.summary", sum2_len).unwrap();
    let b2_sum_head = remote_b2.head_object("000002.summary").unwrap().unwrap();
    assert_eq!(b2_sum_head.size, sum2_len);
    assert!(b2_sum_head.etag_md5().is_some());

    // 4. Run integrity check on remote_aws against manifest
    let report = check_remote_integrity(
        remote_aws.as_ref(),
        "aws",
        &manifest,
        &CheckOptions::metadata_only(),
        None,
    );
    assert!(
        report.is_clean(),
        "Remote integrity check must pass with matching MD5 and size"
    );

    // Corrupt remote object on remote_aws: change bytes and length
    remote_aws
        .put_object("000001.log", &mut &[0u8; 10][..], 10, None)
        .unwrap();
    let corrupt_report = check_remote_integrity(
        remote_aws.as_ref(),
        "aws",
        &manifest,
        &CheckOptions::metadata_only(),
        None,
    );
    assert!(
        !corrupt_report.is_clean(),
        "Integrity check must catch size and MD5 mismatch"
    );
}

#[test]
fn test_tiered_eviction_and_sparse_remote_extent_reads() {
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let clock = Arc::new(SystemClock);

    let TestFs { mut fs, .. } = TestFs::builder()
        .storage(storage.clone())
        .clock(clock.clone())
        .max_log_size(1024 * 1024)
        .build();
    let writer = fs.log_writer.clone().unwrap();

    // Write a large extent across multiple KB in generation 1
    let file_ino = fs.create_file(1, "archival.dat", 0o644).unwrap();
    let ino = file_ino;
    let original_bytes: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
    fs.write_at(ino, &original_bytes, 0).unwrap();
    fs.quiesce().unwrap();

    // Roll to generation 2
    let sealed = writer.force_roll().unwrap().unwrap();
    assert_eq!(sealed.generation, 1);
    fs.manifest.write().unwrap().record_sealed_log(sealed);
    fs.export_summary(storage.as_ref()).unwrap();

    let manifest = fs.manifest.read().unwrap().clone();
    let gen1_info = manifest.get_by_generation(1).unwrap();
    let gen1_md5 = gen1_info.md5;

    // Upload 000001.log to remote store
    let mock = Arc::new(MockRemoteStore::new());
    upload_storage_file(storage.as_ref(), mock.as_ref(), "000001.log", Some(&gen1_md5)).unwrap();

    // Wrap mock in FailingRemoteStore to test network failover
    let failing_remote = Arc::new(FailingRemoteStore::new(mock.clone()));

    // SIMULATE TIERED LOCAL EVICTION: Delete 000001.log from storage!
    assert!(storage.exists("000001.log"));
    storage.remove_file("000001.log").unwrap();
    assert!(!storage.exists("000001.log"), "000001.log was pruned from storage");

    // Setup TieredCache with MemoryBlockCache
    let block_cache = Arc::new(MemoryBlockCache::new(50 * 1024 * 1024));
    let remotes = vec![("mock_s3".to_string(), failing_remote.clone() as Arc<dyn RemoteStore>)];

    let log_cache = Arc::new(LogFileCache::with_remote_support(
        storage.clone(),
        Some(block_cache.clone()),
        remotes,
        Some(Arc::clone(&fs.manifest)),
    ));
    fs.log_cache = Some(log_cache);

    // Read back archival.dat from the filesystem:
    // Local file is GONE, so TieredStorageReader should fetch 1MB aligned block from remote,
    // cache it in memory block cache, and return exact bytes!
    let read_back = fs.read_at(ino, 0, original_bytes.len()).unwrap();
    assert_eq!(
        read_back, original_bytes,
        "Sparse remote extent read matched original bytes bit-for-bit!"
    );

    // Verify that the memory block cache now holds block 0
    assert!(
        block_cache.read_block("000001", 0).unwrap().is_some(),
        "Block 0 must now be cached in block cache"
    );

    // Second read hits in-memory decrypted cache and block cache directly (even if remote goes down!)
    failing_remote.fail_next_n_requests(10);
    let read_back2 = fs.read_at(ino, 500, 100).unwrap();
    assert_eq!(read_back2, &original_bytes[500..600]);
}

#[test]
fn test_disaster_recovery_bootstrap_from_remote() {
    let storage = Arc::new(appendfs::storage::MemoryStorage::new());
    let clock = Arc::new(SystemClock);
    let volume_key = VolumeKey::plaintext_arc();

    let TestFs { fs, .. } = TestFs::builder()
        .storage(storage.clone())
        .clock(clock.clone())
        .max_log_size(1024 * 1024)
        .build();

    let file_ino = fs.create_file(1, "important.txt", 0o644).unwrap();
    let ino = file_ino;
    fs.write_at(ino, b"disaster recovery data", 0).unwrap();
    fs.quiesce().unwrap();

    let summary_file = fs.export_summary(storage.as_ref()).unwrap();

    // Upload to remote
    let remote = Arc::new(MockRemoteStore::new());
    upload_storage_file(storage.as_ref(), remote.as_ref(), &summary_file, None).unwrap();
    upload_storage_file(storage.as_ref(), remote.as_ref(), "000001.log", None).unwrap();

    // Now, create a completely fresh, empty in-memory destination storage (simulating a fresh machine)
    let fresh_storage = Arc::new(appendfs::storage::MemoryStorage::new());

    let mut remote_cfg = RemoteTargetConfig::new("backup-bucket");
    remote_cfg.region = "us-east-1".to_string();

    // Bootstrap from remote!
    let recovered_summary =
        bootstrap_from_remote(remote.as_ref(), fresh_storage.as_ref(), "origin", remote_cfg).unwrap();

    assert_eq!(recovered_summary, summary_file);
    assert!(fresh_storage.exists(&summary_file));
    assert!(fresh_storage.exists("remotes.toml"));

    // Recover volume in the fresh storage
    let fresh_fs = appendfs::recover_fs(fresh_storage, appendfs::RecoveryTarget::Latest, clock, volume_key).unwrap();
    let base = fresh_fs.inner.lock_for_tests().unwrap().base.clone();
    assert!(base.len() >= 2); // root + important.txt
}

#[test]
fn test_read_only_remote_and_cloud_forking() {
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let clock = Arc::new(SystemClock);

    let TestFs { fs, .. } = TestFs::builder()
        .storage(storage.clone())
        .clock(clock.clone())
        .max_log_size(1024 * 1024)
        .build();
    let writer = fs.log_writer.clone().unwrap();

    // Write file in generation 1
    let file_ino = fs.create_file(1, "base.txt", 0o644).unwrap();
    let ino = file_ino;
    fs.write_at(ino, b"upstream base file contents", 0).unwrap();
    fs.quiesce().unwrap();

    // Roll to generation 2
    let sealed = writer.force_roll().unwrap().unwrap();
    assert_eq!(sealed.generation, 1);
    fs.manifest.write().unwrap().record_sealed_log(sealed);
    let summary_file = fs.export_summary(storage.as_ref()).unwrap();
    assert_eq!(summary_file, "000001.summary");

    // Setup an upstream read-only remote
    let upstream_remote = Arc::new(MockRemoteStore::new());
    upload_storage_file(storage.as_ref(), upstream_remote.as_ref(), "000001.log", None).unwrap();
    upload_storage_file(storage.as_ref(), upstream_remote.as_ref(), &summary_file, None).unwrap();

    // Setup a downstream writable remote
    let _downstream_remote = Arc::new(MockRemoteStore::new());

    let mut registry = RemoteRegistry::new();
    let upstream_cfg = RemoteTargetConfig::new("upstream-bucket").with_mode(RemoteMode::ReadOnly);
    registry.add_remote("upstream", upstream_cfg);

    let downstream_cfg = RemoteTargetConfig::new("downstream-bucket");
    registry.add_remote("downstream", downstream_cfg);

    // Verify configured stores
    let stores = registry.build_all_stores();
    assert_eq!(stores.len(), 2);

    let up = stores.iter().find(|r| r.name == "upstream").unwrap();
    assert_eq!(
        up.mode,
        RemoteMode::ReadOnly,
        "Upstream remote must be marked read-only"
    );
    assert!(!up.upload_partial_logs);

    let down = stores.iter().find(|r| r.name == "downstream").unwrap();
    assert_eq!(down.mode, RemoteMode::ReadWrite, "Downstream remote must be writable");
    assert!(down.upload_partial_logs);
}

/// Bootstrapping an encrypted volume whose newest generation exists only as active parts
/// must reproduce that generation's own file header: the header carries the salt its
/// records' key is derived from, so a header made up during bootstrap would leave every
/// record in the rebuilt file unreadable.
#[test]
fn test_bootstrap_rebuilds_encrypted_active_log_from_parts() {
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let clock = Arc::new(SystemClock);
    let master = appendfs::crypto::MasterKey::new([0x42u8; 32]);
    let (header, key) = VolumeHeader::new_encrypted(
        &master,
        [0u8; 16],
        appendfs::crypto::KeySource::KeyFile,
        appendfs::compress::Compression::None,
    )
    .unwrap();
    let volume_key = Arc::new(key);

    let TestFs { fs, .. } = TestFs::builder()
        .storage(storage.clone())
        .clock(clock.clone())
        .max_log_size(1024 * 1024)
        .volume(header, volume_key.clone())
        .build();

    let remote = Arc::new(MockRemoteStore::new());
    upload_storage_file(storage.as_ref(), remote.as_ref(), "000000.summary", None).unwrap();

    let mut registry = RemoteRegistry::new();
    registry.policy.active_sync_interval_secs = 0;
    registry.policy.prune_rule = PruneExpr::immediate_readable(1);
    registry.add_remote("primary", RemoteTargetConfig::new("my-bucket"));
    registry.set_store_override("primary", remote.clone());
    let registry_arc = Arc::new(std::sync::RwLock::new(registry));

    let fs_arc = Arc::new(fs);
    let mut last_part_sync = std::time::SystemTime::UNIX_EPOCH;
    let mut uploaded_parts = std::collections::HashMap::new();

    // Two batches, each shipped as its own part of the still-active generation 1.
    let file = fs_arc.create_file(1, "active.txt", 0o644).unwrap();
    fs_arc.write_at(file, b"first part ", 0).unwrap();
    fs_arc.quiesce().unwrap();
    appendfs::remote::RemoteReplicationWorker::run_cycle(
        &fs_arc,
        &registry_arc,
        Path::new("/memory"),
        &mut last_part_sync,
        &mut uploaded_parts,
    )
    .unwrap();
    fs_arc.write_at(file, b"second part", 11).unwrap();
    fs_arc.quiesce().unwrap();
    last_part_sync = std::time::SystemTime::UNIX_EPOCH;
    appendfs::remote::RemoteReplicationWorker::run_cycle(
        &fs_arc,
        &registry_arc,
        Path::new("/memory"),
        &mut last_part_sync,
        &mut uploaded_parts,
    )
    .unwrap();
    assert!(remote.head_object("000001.part0001.log").unwrap().is_some());
    assert!(
        remote.head_object("000001.log").unwrap().is_none(),
        "generation 1 must still be active"
    );

    let fresh_storage = Arc::new(MemoryStorage::new());
    bootstrap_from_remote(
        remote.as_ref(),
        fresh_storage.as_ref(),
        "origin",
        RemoteTargetConfig::new("my-bucket"),
    )
    .unwrap();
    let original = storage.open_reader("000001.log").unwrap();
    let mut original_bytes = vec![0u8; original.len().unwrap() as usize];
    original.read_exact_at(0, &mut original_bytes).unwrap();
    assert!(
        fresh_storage.get_file_bytes("000001.log").unwrap() == original_bytes,
        "the rebuilt active log must match the original byte for byte, header included"
    );

    let recovered = appendfs::recover_fs(fresh_storage, appendfs::RecoveryTarget::Latest, clock, volume_key).unwrap();
    assert_eq!(
        recovered.read_file_data(file, 0, 22).unwrap(),
        b"first part second part"
    );
}

#[test]
fn test_active_log_part_sync_and_consolidation_on_seal() {
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let clock = Arc::new(SystemClock);

    let TestFs { fs, .. } = TestFs::builder()
        .storage(storage.clone())
        .clock(clock.clone())
        .max_log_size(1024 * 1024)
        .build();
    let writer = fs.log_writer.clone().unwrap();

    let remote = Arc::new(MockRemoteStore::new());

    // Setup registry with active_sync_interval = 0 (sync on every tick)
    let mut registry = RemoteRegistry::new();
    registry.policy.active_sync_interval_secs = 0;
    registry.policy.prune_rule = PruneExpr::immediate_readable(1);
    let target = RemoteTargetConfig::new("my-bucket");
    registry.add_remote("primary", target);
    registry.set_store_override("primary", remote.clone());
    let registry_arc = Arc::new(std::sync::RwLock::new(registry));

    let fs_arc = Arc::new(fs);
    let mut last_part_sync = std::time::SystemTime::UNIX_EPOCH;
    let mut uploaded_parts = std::collections::HashMap::new();

    // 1. Write first chunk of active data
    let file1_ino = fs_arc.create_file(1, "active_file.txt", 0o644).unwrap();
    let ino = file1_ino;
    fs_arc
        .write_at(ino, b"Part 0 slice: hello appendfs active sync!", 0)
        .unwrap();
    fs_arc.quiesce().unwrap();

    // Run sync cycle -> uploads 000001.part0000.log!
    appendfs::remote::RemoteReplicationWorker::run_cycle(
        &fs_arc,
        &registry_arc,
        Path::new("/memory"),
        &mut last_part_sync,
        &mut uploaded_parts,
    )
    .unwrap();

    // Verify part0000 exists on remote!
    let part0 = remote.head_object("000001.part0000.log").unwrap();
    assert!(
        part0.is_some(),
        "Active incremental part0000 must be uploaded to remote"
    );
    assert!(part0.unwrap().size > 0);

    // 2. Write second chunk of active data
    fs_arc
        .write_at(ino, b"Part 1 slice: more mutations appended!", 100)
        .unwrap();
    fs_arc.quiesce().unwrap();

    last_part_sync = std::time::SystemTime::UNIX_EPOCH; // reset timer to force next upload
    appendfs::remote::RemoteReplicationWorker::run_cycle(
        &fs_arc,
        &registry_arc,
        Path::new("/memory"),
        &mut last_part_sync,
        &mut uploaded_parts,
    )
    .unwrap();

    let part1 = remote.head_object("000001.part0001.log").unwrap();
    assert!(
        part1.is_some(),
        "Active incremental part0001 must be uploaded to remote"
    );

    // 3. Roll generation: seals generation 1 into generation 2!
    let sealed = writer.force_roll().unwrap().unwrap();
    assert_eq!(sealed.generation, 1);
    fs_arc.manifest.write().unwrap().record_sealed_log(sealed);
    fs_arc.export_summary(storage.as_ref()).unwrap();

    // Run sync cycle after roll: should upload full 000001.log and delete transient parts!
    appendfs::remote::RemoteReplicationWorker::run_cycle(
        &fs_arc,
        &registry_arc,
        Path::new("/memory"),
        &mut last_part_sync,
        &mut uploaded_parts,
    )
    .unwrap();

    // Full 000001.log must exist
    let sealed_log = remote.head_object("000001.log").unwrap();
    assert!(sealed_log.is_some(), "Sealed unified log 000001.log must be on remote");

    // Transient parts MUST be cleaned up!
    let remaining_parts = remote.list_objects("000001.part").unwrap();
    assert!(
        remaining_parts.is_empty(),
        "Transient active parts must be deleted upon generation consolidation!"
    );
}

#[test]
fn test_active_log_part_ships_only_synced_bytes() {
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let clock = Arc::new(SystemClock);

    let TestFs { fs, .. } = TestFs::builder()
        .storage(storage.clone())
        .clock(clock.clone())
        .max_log_size(1024 * 1024)
        .build();
    let writer = fs.log_writer.clone().unwrap();

    let remote = Arc::new(MockRemoteStore::new());
    let mut registry = RemoteRegistry::new();
    registry.policy.active_sync_interval_secs = 0;
    registry.add_remote("primary", RemoteTargetConfig::new("my-bucket"));
    registry.set_store_override("primary", remote.clone());
    let registry_arc = Arc::new(std::sync::RwLock::new(registry));

    let fs_arc = Arc::new(fs);
    let mut last_part_sync = std::time::SystemTime::UNIX_EPOCH;
    let mut uploaded_parts = std::collections::HashMap::new();
    let mut run_cycle = |last_part_sync: &mut std::time::SystemTime| {
        appendfs::remote::RemoteReplicationWorker::run_cycle(
            &fs_arc,
            &registry_arc,
            Path::new("/memory"),
            last_part_sync,
            &mut uploaded_parts,
        )
        .unwrap();
    };

    // A record at least as large as the writer's userspace buffer goes straight to the file, so
    // mid-batch the file holds exactly what has been written so far. None of it is committed or
    // synced yet, and a failed batch would be rolled back, so it must stay local.
    let payload = vec![0x5a; 4 * appendfs::storage::DEFAULT_STORAGE_BUFFER_CAPACITY];
    writer.append_data(10, &payload).unwrap();
    run_cycle(&mut last_part_sync);
    assert!(remote.head_object("000001.part0000.log").unwrap().is_none());

    writer.emit_flush_commit(1, payload.len() as u64, clock.now()).unwrap();
    writer.flush().unwrap();
    last_part_sync = std::time::SystemTime::UNIX_EPOCH;
    run_cycle(&mut last_part_sync);
    let part0 = remote.head_object("000001.part0000.log").unwrap().unwrap();
    assert_eq!(part0.size, writer.current_offset());
}

#[test]
fn test_local_dir_remote_store_streaming_and_md5_sidecars() {
    let dir = TempDir::new().unwrap();
    let store = LocalDirRemoteStore::new(dir.path());

    let data = b"AppendFS streaming replication to local/NFS filesystem targets";
    let real_md5: [u8; 16] = *md5::compute(data);

    // Upload with valid MD5
    store
        .put_object("000001.log", &mut &data[..], data.len() as u64, Some(&real_md5))
        .unwrap();

    // Verify head_object finds object and parses ETag from .md5 sidecar file
    let obj = store.head_object("000001.log").unwrap().unwrap();
    assert_eq!(obj.size, data.len() as u64);
    assert_eq!(obj.etag_md5(), Some(real_md5));

    // Verify physical .md5 sidecar file exists on disk
    assert!(dir.path().join("000001.log.md5").exists());

    // Range read
    let mut range_buf = Vec::new();
    let bytes_copied = store.get_object_range("000001.log", 9, 9, &mut range_buf).unwrap();
    assert_eq!(bytes_copied, 9);
    assert_eq!(range_buf, b"streaming");

    // Full read
    let mut full_buf = Vec::new();
    store.get_object("000001.log", &mut full_buf).unwrap();
    assert_eq!(full_buf, data);

    // Upload with bad MD5 fails with InvalidData BadDigest
    let fake_md5 = [0xFF; 16];
    let err = store
        .put_object("bad.log", &mut &data[..], data.len() as u64, Some(&fake_md5))
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("BadDigest"));
    assert!(!dir.path().join("bad.log").exists());

    // If .md5 sidecar is missing, etag is None (unverified) without reading entire file
    fs::remove_file(dir.path().join("000001.log.md5")).unwrap();
    let obj_no_md5 = store.head_object("000001.log").unwrap().unwrap();
    assert_eq!(obj_no_md5.etag, None);

    // Delete object cleans up both data and .md5
    store.delete_object("000001.log").unwrap();
    assert!(store.head_object("000001.log").unwrap().is_none());
}

#[test]
fn test_nfs_local_volume_replication_and_pruning() {
    let nfs_dir = TempDir::new().unwrap();
    let storage = Arc::new(MemoryStorage::new());
    let clock = Arc::new(SystemClock);

    let TestFs { mut fs, .. } = TestFs::builder()
        .storage(storage.clone())
        .clock(clock.clone())
        .max_log_size(1024 * 1024)
        .build();
    let writer = fs.log_writer.clone().unwrap();
    fs.log_cache = Some(Arc::new(LogFileCache::with_storage(storage.clone())));

    // Setup RemoteRegistry pointing to a local directory representing an NFS share
    let mut registry = RemoteRegistry::new();
    let nas_cfg = RemoteTargetConfig::new_path(nfs_dir.path());
    registry.add_remote("nas", nas_cfg);
    registry.policy.prune_rule = PruneExpr::immediate_readable(1);
    let registry_arc = Arc::new(std::sync::RwLock::new(registry));

    // 1. Write file in generation 1
    let root = 1u64;
    let file_ino = fs.create_file(root, "nfs_file.txt", 0o644).unwrap();
    let payload = b"Data that will replicate to NFS NAS share and be read tier-cached!";
    fs.write_at(file_ino, payload, 0).unwrap();
    fs.quiesce().unwrap();

    // Force roll to generation 2 (seals generation 1)
    let sealed = writer.force_roll().unwrap().unwrap();
    assert_eq!(sealed.generation, 1);
    let sealed_md5 = sealed.md5;
    fs.manifest.write().unwrap().record_sealed_log(sealed);
    fs.export_summary(storage.as_ref()).unwrap();

    // 2. Run replication cycle: uploads 000001.log and summary to NFS share
    let fs_arc = Arc::new(fs);
    let mut last_part_sync = std::time::SystemTime::now();
    let mut uploaded_parts = std::collections::HashMap::new();
    appendfs::remote::RemoteReplicationWorker::run_cycle(
        &fs_arc,
        &registry_arc,
        Path::new("/unused"),
        &mut last_part_sync,
        &mut uploaded_parts,
    )
    .unwrap();

    // Verify NFS share has 000001.log and sibling 000001.log.md5
    assert!(nfs_dir.path().join("000001.log").exists());
    assert!(nfs_dir.path().join("000001.log.md5").exists());
    let md5_content = fs::read_to_string(nfs_dir.path().join("000001.log.md5")).unwrap();
    assert_eq!(md5_content.trim(), hex::encode(sealed_md5));

    // 3. Verify integrity check passes on the NFS remote
    let nas_store = registry_arc.read().unwrap().get_remote("nas").unwrap().build_store();
    let report = check_remote_integrity(
        nas_store.as_ref(),
        "nas",
        &fs_arc.manifest.read().unwrap(),
        &CheckOptions::metadata_only(),
        None,
    );
    assert!(report.is_clean(), "Integrity check against NFS remote must pass");

    // 4. Prune local 000001.log to simulate tiered storage eviction
    storage.remove_file("000001.log").unwrap();
    assert!(!storage.exists("000001.log"));

    // 5. Setup tiered reader attached to LogFileCache
    let mut fs = Arc::try_unwrap(fs_arc).ok().unwrap();
    let block_cache = Arc::new(MemoryBlockCache::new(50 * 1024 * 1024));
    let remotes = vec![("nas".to_string(), nas_store.clone() as Arc<dyn RemoteStore>)];
    let log_cache = Arc::new(LogFileCache::with_remote_support(
        storage.clone(),
        Some(block_cache.clone()),
        remotes,
        Some(Arc::clone(&fs.manifest)),
    ));
    fs.log_cache = Some(log_cache);

    // Read back nfs_file.txt from the filesystem:
    // Local 000001.log is GONE, so TieredStorageReader should fetch 1MB aligned block from NFS remote,
    // cache it in block cache, and return exact bytes!
    let read_back = fs.read_at(file_ino, 0, payload.len()).unwrap();
    assert_eq!(
        read_back, payload,
        "Sparse NFS remote extent read matched original payload bit-for-bit!"
    );

    // Verify block cache populated
    assert!(
        block_cache.read_block("000001", 0).unwrap().is_some(),
        "Block 0 must now be cached"
    );
}

#[test]
fn test_local_read_populates_block_cache_before_purge() {
    let storage = Arc::new(MemoryStorage::new());
    let clock = Arc::new(SystemClock);

    let TestFs { mut fs, .. } = TestFs::builder()
        .storage(storage.clone())
        .clock(clock.clone())
        .max_log_size(1024 * 1024)
        .build();
    let writer = fs.log_writer.clone().unwrap();

    // 1. Write file in generation 1
    let root = 1u64;
    let file1_ino = fs.create_file(root, "hot_file.txt", 0o644).unwrap();
    let payload1 = b"Hot file content that will be pre-warmed into block cache from local disk";
    fs.write_at(file1_ino, payload1, 0).unwrap();
    fs.quiesce().unwrap();

    // 2. Force roll to generation 2 (seals generation 1)
    let sealed = writer.force_roll().unwrap().unwrap();
    assert_eq!(sealed.generation, 1);
    fs.manifest.write().unwrap().record_sealed_log(sealed);
    fs.export_summary(storage.as_ref()).unwrap();

    // 3. Write file in active generation 2
    let file2_ino = fs.create_file(root, "active_file.txt", 0o644).unwrap();
    let payload2 = b"Active generation content that reads directly without block caching";
    fs.write_at(file2_ino, payload2, 0).unwrap();
    fs.quiesce().unwrap();

    // 4. Attach LogFileCache with MemoryBlockCache (NO remotes configured!), caching local reads
    let block_cache = Arc::new(MemoryBlockCache::new(50 * 1024 * 1024));
    let log_cache = Arc::new(
        LogFileCache::with_remote_support(
            storage.clone(),
            Some(block_cache.clone()),
            Vec::<appendfs::remote::RemoteReadTarget>::new(), // Zero remotes!
            Some(Arc::clone(&fs.manifest)),
        )
        .with_cache_local_reads(true),
    );
    fs.log_cache = Some(log_cache.clone());

    // Verify cache is empty before any reads
    assert!(block_cache.read_block("000001", 0).unwrap().is_none());
    assert!(block_cache.read_block("000002", 0).unwrap().is_none());

    // 5. Read sealed generation 1 file while 000001.log is STILL in storage:
    // Should read from storage AND pre-warm into block cache!
    let read_sealed = fs.read_at(file1_ino, 0, payload1.len()).unwrap();
    assert_eq!(read_sealed, payload1);

    // Block 0 of generation 1 MUST now be cached!
    assert!(block_cache.read_block("000001", 0).unwrap().is_some());

    // 6. Read active generation 2 file:
    // Must NOT write to block cache because active generation avoids partial block caching!
    let read_active = fs.read_at(file2_ino, 0, payload2.len()).unwrap();
    assert_eq!(read_active, payload2);
    assert!(block_cache.read_block("000002", 0).unwrap().is_none());

    // 7. Clear in-memory decrypted cache so the next read MUST hit storage / block cache
    log_cache.decrypted_cache.clear();

    // 8. Physically DELETE 000001.log from storage (simulate 30-day purge)
    storage.remove_file("000001.log").unwrap();
    assert!(!storage.exists("000001.log"));

    // 9. Read sealed file again:
    // 000001.log is GONE, NO remotes exist, but read MUST succeed directly from block cache!
    let read_cached_after_purge = fs.read_at(file1_ino, 0, payload1.len()).unwrap();
    assert_eq!(
        read_cached_after_purge, payload1,
        "Read succeeded directly from pre-warmed block cache after local log was purged!"
    );
}

#[test]
fn test_local_read_skips_block_cache_by_default() {
    let storage = Arc::new(MemoryStorage::new());
    let clock = Arc::new(SystemClock);

    let TestFs { mut fs, .. } = TestFs::builder()
        .storage(storage.clone())
        .clock(clock.clone())
        .max_log_size(1024 * 1024)
        .build();
    let writer = fs.log_writer.clone().unwrap();

    let ino = fs.create_file(1, "file.txt", 0o644).unwrap();
    let payload = b"Sealed content read straight from the local log";
    fs.write_at(ino, payload, 0).unwrap();
    fs.quiesce().unwrap();

    let sealed = writer.force_roll().unwrap().unwrap();
    fs.manifest.write().unwrap().record_sealed_log(sealed);

    let block_cache = Arc::new(MemoryBlockCache::new(50 * 1024 * 1024));
    let log_cache = Arc::new(LogFileCache::with_remote_support(
        storage.clone(),
        Some(block_cache.clone()),
        Vec::<appendfs::remote::RemoteReadTarget>::new(),
        Some(Arc::clone(&fs.manifest)),
    ));
    fs.log_cache = Some(log_cache.clone());

    // The sealed log is still local, so it is read directly and nothing is copied into the cache.
    assert_eq!(fs.read_at(ino, 0, payload.len()).unwrap(), payload);
    assert!(block_cache.read_block("000001", 0).unwrap().is_none());

    // Once it is purged there is no second copy to fall back on, and no remote either.
    log_cache.decrypted_cache.clear();
    storage.remove_file("000001.log").unwrap();
    log_cache.invalidate(1);
    assert!(fs.read_at(ino, 0, payload.len()).is_err());
}

#[test]
fn test_remote_read_priority_prefers_lower_priority_remotes() {
    let storage = Arc::new(MemoryStorage::new());
    let clock = Arc::new(SystemClock);

    let TestFs { mut fs, .. } = TestFs::builder()
        .storage(storage.clone())
        .clock(clock.clone())
        .max_log_size(1024 * 1024)
        .build();
    let writer = fs.log_writer.clone().unwrap();

    // 1. Write file into generation 1
    let root = 1u64;
    let file_ino = fs.create_file(root, "archived.txt", 0o644).unwrap();
    let payload = b"Remote data that should be fetched from NAS before falling back to S3";
    fs.write_at(file_ino, payload, 0).unwrap();
    fs.quiesce().unwrap();

    // 2. Roll to generation 2 (seals generation 1)
    let sealed = writer.force_roll().unwrap().unwrap();
    assert_eq!(sealed.generation, 1);
    fs.manifest.write().unwrap().record_sealed_log(sealed);
    fs.export_summary(storage.as_ref()).unwrap();

    // 3. Read raw 000001.log bytes from storage
    let raw_log_bytes = storage.get_file_bytes("000001.log").unwrap();

    // 4. Create two mock stores: NAS (priority 10) and S3 (priority 100)
    let nas_store = Arc::new(MockRemoteStore::new());
    let s3_store = Arc::new(MockRemoteStore::new());

    // Upload 000001.log to BOTH stores
    nas_store
        .put_object("000001.log", &mut &raw_log_bytes[..], raw_log_bytes.len() as u64, None)
        .unwrap();
    s3_store
        .put_object("000001.log", &mut &raw_log_bytes[..], raw_log_bytes.len() as u64, None)
        .unwrap();

    // Configure registry with S3 added first, but NAS having lower numerical priority (10 < 100)
    let mut registry = RemoteRegistry::new();
    let mut s3_cfg = RemoteTargetConfig::new("my-cloud-s3");
    s3_cfg.read_priority = 100;
    registry.add_remote("s3", s3_cfg);
    let counting_s3 = Arc::new(CountingRemoteStore::new(s3_store.clone()));
    registry.set_store_override("s3", counting_s3.clone());

    let mut nas_cfg = RemoteTargetConfig::new_path("/mnt/nas");
    nas_cfg.read_priority = 10;
    registry.add_remote("nas", nas_cfg);
    let counting_nas_back = Arc::new(CountingRemoteStore::new(nas_store.clone()));
    let nas_failing = Arc::new(FailingRemoteStore::new(counting_nas_back.clone()));
    let counting_nas_front = Arc::new(CountingRemoteStore::new(nas_failing.clone()));
    registry.set_store_override("nas", counting_nas_front.clone());

    // Verify build_read_stores order: "nas" (10) MUST come before "s3" (100)
    let remote_stores = registry.build_read_stores();
    assert_eq!(remote_stores[0].name, "nas");
    assert_eq!(remote_stores[1].name, "s3");

    // 5. Delete local 000001.log to force remote tiered reading
    storage.remove_file("000001.log").unwrap();

    // 6. Setup LogFileCache with block_cache and ordered remote_stores
    let block_cache = Arc::new(MemoryBlockCache::new(50 * 1024 * 1024));
    let log_cache = Arc::new(LogFileCache::with_remote_support(
        storage.clone(),
        Some(block_cache.clone()),
        remote_stores,
        Some(Arc::clone(&fs.manifest)),
    ));
    fs.log_cache = Some(log_cache.clone());

    // 7. Perform read: should query NAS first, succeed, and NOT touch S3!
    let read1 = fs.read_at(file_ino, 0, payload.len()).unwrap();
    assert_eq!(read1, payload);

    assert_eq!(
        counting_nas_front.range_reads(),
        1,
        "NAS front must receive read request"
    );
    assert_eq!(counting_nas_back.range_reads(), 1, "NAS served read");
    assert_eq!(counting_s3.total_requests(), 0, "S3 must NOT be called");

    // 8. Test failover: clear block cache and decrypted cache, make NAS fail next request
    block_cache.clear();
    log_cache.decrypted_cache.clear();
    nas_failing.fail_next_n_requests(1);

    // 9. Perform read: NAS fails, so it fails over to S3!
    let read2 = fs.read_at(file_ino, 0, payload.len()).unwrap();
    assert_eq!(read2, payload);

    assert_eq!(counting_nas_front.range_reads(), 2, "NAS was tried first and failed");
    assert_eq!(counting_nas_back.range_reads(), 1, "NAS backend only served 1 read");
    assert_eq!(counting_s3.range_reads(), 1, "S3 served failover read");
}

#[test]
fn test_latency_remote_store_in_tiered_reading() {
    use std::time::{Duration, Instant};

    let storage = Arc::new(MemoryStorage::new());
    let clock = Arc::new(SystemClock);

    let TestFs { mut fs, .. } = TestFs::builder()
        .storage(storage.clone())
        .clock(clock.clone())
        .max_log_size(1024 * 1024)
        .build();
    let writer = fs.log_writer.clone().unwrap();

    let file_ino = fs.create_file(1, "latency_test.dat", 0o644).unwrap();
    let payload = b"Testing latency injection on tiered remote store reads";
    fs.write_at(file_ino, payload, 0).unwrap();
    fs.quiesce().unwrap();

    let sealed = writer.force_roll().unwrap().unwrap();
    assert_eq!(sealed.generation, 1);
    fs.manifest.write().unwrap().record_sealed_log(sealed);
    fs.export_summary(storage.as_ref()).unwrap();

    let raw_log_bytes = storage.get_file_bytes("000001.log").unwrap();
    let mock_store = Arc::new(MockRemoteStore::new());
    mock_store
        .put_object("000001.log", &mut &raw_log_bytes[..], raw_log_bytes.len() as u64, None)
        .unwrap();

    // Wrap in LatencyRemoteStore and inject 20ms delay on get_object_range
    let latency_store = Arc::new(LatencyRemoteStore::new(mock_store.clone()));
    latency_store.set_method_delay("get_object_range", Duration::from_millis(20));

    // Delete local 000001.log to force remote tiered read
    storage.remove_file("000001.log").unwrap();

    let block_cache = Arc::new(MemoryBlockCache::new(50 * 1024 * 1024));
    let counting_store = Arc::new(CountingRemoteStore::new(latency_store.clone()));
    let remotes = vec![(
        "delayed_remote".to_string(),
        counting_store.clone() as Arc<dyn RemoteStore>,
    )];
    let log_cache = Arc::new(LogFileCache::with_remote_support(
        storage.clone(),
        Some(block_cache.clone()),
        remotes,
        Some(Arc::clone(&fs.manifest)),
    ));
    fs.log_cache = Some(log_cache.clone());

    // 1st read: misses cache, queries latency_store, takes >= 19ms
    let start1 = Instant::now();
    let read1 = fs.read_at(file_ino, 0, payload.len()).unwrap();
    let elapsed1 = start1.elapsed();
    assert_eq!(read1, payload);
    assert!(
        elapsed1 >= Duration::from_millis(19),
        "1st read should include injected latency, took {:?}",
        elapsed1
    );
    assert_eq!(counting_store.range_reads(), 1);

    // 2nd read: served directly from cache, near instantaneous (< 10ms)
    let start2 = Instant::now();
    let read2 = fs.read_at(file_ino, 0, payload.len()).unwrap();
    let elapsed2 = start2.elapsed();
    assert_eq!(read2, payload);
    assert!(
        elapsed2 < Duration::from_millis(10),
        "2nd read should hit cache without latency, took {:?}",
        elapsed2
    );
    assert_eq!(counting_store.range_reads(), 1);
}

#[test]
fn test_virtual_remotes_status_file_lifecycle_and_content() {
    use appendfs::operations::dir::list_dir_core;

    let storage = Arc::new(MemoryStorage::new());
    let clock = Arc::new(SystemClock);

    let TestFs { mut fs, .. } = TestFs::builder()
        .storage(storage.clone())
        .clock(clock.clone())
        .max_log_size(100 * 1024 * 1024)
        .build();
    let writer = fs.log_writer.clone().unwrap();
    fs.log_cache = Some(Arc::new(LogFileCache::with_storage(storage.clone())));

    // Configure 2 remotes (NAS and S3)
    let nas_store = Arc::new(MockRemoteStore::new());
    let s3_store = Arc::new(MockRemoteStore::new());

    let mut registry = RemoteRegistry::new();
    let mut nas_cfg = RemoteTargetConfig::new_path("/mnt/nas");
    nas_cfg.read_priority = 10;
    registry.add_remote("nas", nas_cfg);
    registry.set_store_override("nas", nas_store.clone());

    let mut s3_cfg = RemoteTargetConfig::new("my-s3-bucket");
    s3_cfg.read_priority = 100;
    s3_cfg.prefix = "logs/".to_string();
    registry.add_remote("s3", s3_cfg);
    registry.set_store_override("s3", s3_store.clone());

    let registry_arc = Arc::new(std::sync::RwLock::new(registry));
    fs.set_remote_registry(Arc::clone(&registry_arc));

    let fs_arc = Arc::new(fs);

    // 1. Root directory listing contains .remotes
    let entries = list_dir_core(&fs_arc, 1).unwrap();
    let remotes_entry = entries.iter().find(|(name, _)| name == ".remotes");
    assert!(
        remotes_entry.is_some(),
        ".remotes must appear in root directory listing"
    );
    let remotes_ino = remotes_entry.unwrap().1;
    let attr = fs_arc.get_attr(remotes_ino).unwrap();
    assert_eq!(attr.file_type, appendfs::shim::FileType::RegularFile);

    // 2. Lookup child .remotes on parent 1
    assert_eq!(fs_arc.lookup_child(1, ".remotes"), Some(remotes_ino));

    // 3. Write data, roll log, and run replication cycle
    let file = fs_arc.create_file(1, "test.txt", 0o644).unwrap();
    fs_arc.write_at(file, b"data before roll", 0).unwrap();
    fs_arc.quiesce().unwrap();

    let sealed = writer.force_roll().unwrap().unwrap();
    assert_eq!(sealed.generation, 1);
    fs_arc.manifest.write().unwrap().record_sealed_log(sealed);
    fs_arc.export_summary(storage.as_ref()).unwrap();

    // Run replication cycle
    let mut last_part = std::time::SystemTime::now();
    let mut uploaded_parts = std::collections::HashMap::new();
    appendfs::remote::RemoteReplicationWorker::run_cycle(
        &fs_arc,
        &registry_arc,
        Path::new("/unused"),
        &mut last_part,
        &mut uploaded_parts,
    )
    .unwrap();

    // 4. Open virtual file handle
    let fh = fs_arc.open_file(remotes_ino, libc::O_RDONLY as u32).unwrap();

    // 5. Read .remotes content
    let content_bytes = fs_arc.read_blocking(remotes_ino, fh, 0, 4096).unwrap();
    let content_str = String::from_utf8(content_bytes).unwrap();

    assert!(content_str.contains("=== Remote Status (Volume Head Generation: 2) ==="));
    assert!(content_str.contains("[Remote: nas]"));
    assert!(content_str.contains("Target:             local/nfs (/mnt/nas)"));
    assert!(content_str.contains("Read Priority:      10"));
    assert!(content_str.contains("Status:             Up to date"));
    assert!(content_str.contains("Synced Generation:  1 / 1"));
    assert!(content_str.contains("Replication Lag:    0 sealed generation(s)"));

    assert!(content_str.contains("[Remote: s3]"));
    assert!(content_str.contains("Target:             s3 (bucket: my-s3-bucket, prefix: logs/)"));
    assert!(content_str.contains("Read Priority:      100"));
    assert!(content_str.contains("Status:             Up to date"));
    assert!(content_str.contains("Synced Generation:  1 / 1"));

    // 6. Release file handle
    fs_arc.release_file(remotes_ino, fh).unwrap();
    assert_eq!(
        fs_arc.read_blocking(remotes_ino, fh, 0, 4096),
        Err(FsError::EBADF),
        "Reading from released handle must return EBADF"
    );
}

#[test]
fn test_tiered_storage_reader_coalesces_concurrent_remote_reads() {
    use appendfs::remote::TieredStorageReader;
    use appendfs::storage::StorageReader;
    use std::sync::Barrier;
    use std::thread;
    use std::time::Duration;

    let cache = Arc::new(MemoryBlockCache::new(50 * 1024 * 1024));

    // 2 MiB payload with deterministic bytes
    let payload = vec![0x77u8; 2 * 1024 * 1024];

    let mock = Arc::new(MockRemoteStore::new());
    mock.put_object("000001.log", &mut &payload[..], payload.len() as u64, None)
        .unwrap();

    // Wrap in LatencyRemoteStore (30ms per request) to create a clear concurrency window
    let latency_store = Arc::new(LatencyRemoteStore::new(mock));
    latency_store.set_fixed_delay(Duration::from_millis(30));

    // Wrap in CountingRemoteStore to verify exactly 1 remote request per block
    let counting_store = Arc::new(CountingRemoteStore::new(latency_store));

    let remotes: Vec<appendfs::remote::RemoteReadTarget> = vec![appendfs::remote::RemoteReadTarget::new(
        "s3",
        counting_store.clone(),
        100,
    )];

    let reader = Arc::new(TieredStorageReader::new(
        1,
        "000001.log",
        payload.len() as u64,
        remotes,
        cache.clone(),
    ));

    let num_threads = 8;
    let barrier = Arc::new(Barrier::new(num_threads));
    let mut handles = Vec::new();

    for i in 0..num_threads {
        let r = Arc::clone(&reader);
        let b = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            // Synchronize thread start so they hit the reader concurrently
            b.wait();
            // Read various offsets within block 0
            let offset = (i as u64) * 1024;
            let mut buf = [0u8; 512];
            r.read_exact_at(offset, &mut buf).unwrap();
            assert_eq!(buf, [0x77u8; 512]);
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    // Crucial assertions:
    // 1. Exactly 1 range read was issued to the remote store for block 0 (instead of 8!)
    assert_eq!(
        counting_store.range_reads(),
        1,
        "Expected exactly 1 remote range read for block 0 due to coalescing, got {}",
        counting_store.range_reads()
    );

    // 2. The coalescer recorded 1 leader fetch and 7 coalesced requests
    assert_eq!(reader.coalescer.leader_requests(), 1);
    assert_eq!(reader.coalescer.coalesced_requests(), (num_threads - 1) as u64);
    assert_eq!(reader.coalescer.total_requests(), num_threads as u64);

    // 3. Block 0 is now cached
    assert!(cache.read_block("000001", 0).unwrap().is_some());
}

#[test]
fn test_event_driven_immediate_replication_on_log_roll() {
    let storage = Arc::new(MemoryStorage::new());
    let clock = Arc::new(SystemClock);

    let TestFs { mut fs, .. } = TestFs::builder()
        .storage(storage.clone())
        .clock(clock.clone())
        .max_log_size(1024 * 1024)
        .build();
    let writer = fs.log_writer.clone().unwrap();
    fs.log_cache = Some(Arc::new(LogFileCache::with_storage(storage.clone())));
    let fs_arc = Arc::new(fs);

    let mut registry = RemoteRegistry::new();
    let remote = Arc::new(MockRemoteStore::new());
    registry.add_remote("mock", RemoteTargetConfig::new("mock-bucket"));
    registry.set_store_override("mock", remote.clone());
    let registry_arc = Arc::new(std::sync::RwLock::new(registry));

    // Start background replication worker with a 1-HOUR poll interval.
    // If it were relying solely on periodic polling, it would take 3600s to replicate!
    let mut worker = appendfs::remote::RemoteReplicationWorker::start_with_interval(
        fs_arc.clone(),
        registry_arc.clone(),
        std::path::PathBuf::from("/unused"),
        std::time::Duration::from_secs(3600),
    );

    // Write data to active log
    let file1 = fs_arc.create_file(1, "test_file.txt", 0o644).unwrap();
    fs_arc.write_at(file1, b"Data to seal into generation 1", 0).unwrap();
    fs_arc.quiesce().unwrap();

    // Force roll generation 1 -> 2. This seals generation 1 and notifies the worker via Condvar!
    let sealed = writer.force_roll().unwrap().unwrap();
    assert_eq!(sealed.generation, 1);
    fs_arc.manifest.write().unwrap().record_sealed_log(sealed);
    fs_arc.notify_replication();

    // Poll for up to 2 seconds for the remote to receive 000001.log
    assert!(
        wait_until(
            || remote.head_object("000001.log").unwrap().is_some(),
            std::time::Duration::from_secs(2)
        ),
        "Log generation 1 must be replicated immediately via event-driven wake-up without waiting for the 3600s poll interval!"
    );

    worker.stop();
}

#[test]
fn test_audit_interval_skips_confirmed_files_until_audit() {
    let storage = Arc::new(MemoryStorage::new());
    let clock = Arc::new(SystemClock);

    let TestFs { mut fs, .. } = TestFs::builder()
        .storage(storage.clone())
        .clock(clock.clone())
        .max_log_size(1024 * 1024)
        .build();
    let writer = fs.log_writer.clone().unwrap();
    fs.log_cache = Some(Arc::new(LogFileCache::with_storage(storage.clone())));
    let fs_arc = Arc::new(fs);

    let raw_remote = Arc::new(MockRemoteStore::new());
    let counting_store = Arc::new(CountingRemoteStore::new(raw_remote.clone()));

    let mut registry = RemoteRegistry::new();
    registry.policy.audit_interval_secs = 14400; // 4 hours
    registry.add_remote("counting", RemoteTargetConfig::new("counting-bucket"));
    registry.set_store_override("counting", counting_store.clone());
    let registry_arc = Arc::new(std::sync::RwLock::new(registry));

    // Write data to active log
    let file1 = fs_arc.create_file(1, "audit_test.txt", 0o644).unwrap();
    fs_arc.write_at(file1, b"Audit test data payload", 0).unwrap();
    fs_arc.quiesce().unwrap();

    // Seal generation 1
    let sealed = writer.force_roll().unwrap().unwrap();
    assert_eq!(sealed.generation, 1);
    fs_arc.manifest.write().unwrap().record_sealed_log(sealed);

    let mut last_part_sync = std::time::SystemTime::UNIX_EPOCH;
    let mut uploaded_parts = std::collections::HashMap::new();
    let mut last_audit = std::time::SystemTime::now(); // Recent audit
    let mut confirmed_gens = std::collections::HashMap::new();
    let mut confirmed_sums = std::collections::HashMap::new();

    // 1. First incremental cycle: generation 1 is not confirmed, so it gets probed and uploaded
    appendfs::remote::RemoteReplicationWorker::run_cycle_with_audit(
        &fs_arc,
        &registry_arc,
        Path::new("/unused"),
        &mut last_part_sync,
        &mut uploaded_parts,
        &mut last_audit,
        &mut confirmed_gens,
        &mut confirmed_sums,
        false,
        None,
        None,
    )
    .unwrap();

    assert_eq!(
        counting_store.puts(),
        2,
        "000001.log and 000000.summary must be uploaded"
    );
    let head_calls_initial = counting_store.heads();
    assert!(
        head_calls_initial >= 2,
        "head_object must be checked for log and summary"
    );

    // 2. Second incremental cycle (no new files, audit interval has not elapsed):
    // Should skip head_object for confirmed 000001.log!
    appendfs::remote::RemoteReplicationWorker::run_cycle_with_audit(
        &fs_arc,
        &registry_arc,
        Path::new("/unused"),
        &mut last_part_sync,
        &mut uploaded_parts,
        &mut last_audit,
        &mut confirmed_gens,
        &mut confirmed_sums,
        false,
        None,
        None,
    )
    .unwrap();

    assert_eq!(
        counting_store.heads(),
        head_calls_initial,
        "Incremental cycle must NOT call head_object on confirmed generations!"
    );

    // 3. Full audit cycle (force_audit = true, simulating 4-hour elapsed audit):
    // Audits via batch listing without O(N) head_object probes!
    appendfs::remote::RemoteReplicationWorker::run_cycle_with_audit(
        &fs_arc,
        &registry_arc,
        Path::new("/unused"),
        &mut last_part_sync,
        &mut uploaded_parts,
        &mut last_audit,
        &mut confirmed_gens,
        &mut confirmed_sums,
        true,
        None,
        None,
    )
    .unwrap();

    assert_eq!(
        counting_store.heads(),
        head_calls_initial,
        "Full audit cycle must verify remote integrity via batch listing without O(N) head_object calls!"
    );
    assert_eq!(
        counting_store.lists(),
        3,
        "Full audit cycle issues batch list_objects rather than individual head_object queries"
    );
}

#[test]
fn test_last_summary_generation_restored_on_recovery_and_allows_pruning() {
    let nfs_dir = TempDir::new().unwrap();
    let storage = Arc::new(MemoryStorage::new());
    let clock = Arc::new(SystemClock);
    let volume_key = VolumeKey::plaintext_arc();

    let TestFs { fs, .. } = TestFs::builder()
        .storage(storage.clone())
        .clock(clock.clone())
        .max_log_size(1024 * 1024)
        .build();
    let writer = fs.log_writer.clone().unwrap();

    // Write file in generation 1
    let root = 1u64;
    let file_ino = fs.create_file(root, "test.txt", 0o644).unwrap();
    fs.write_at(file_ino, b"data to replicate and prune", 0).unwrap();
    fs.quiesce().unwrap();

    fs.export_summary(storage.as_ref()).unwrap();
    assert_eq!(fs.last_summary_generation.load(Ordering::SeqCst), 1);

    // Drop filesystem and writer, simulating a restart/remount
    drop(writer);
    drop(fs);

    // Remove 000002.summary (emitted on clean drop) to simulate recovery from 000001.summary
    if storage.exists("000002.summary") {
        storage.remove_file("000002.summary").unwrap();
    }

    // Recover filesystem
    let mut recovered_fs = appendfs::recover_fs(
        storage.clone(),
        appendfs::RecoveryTarget::Latest,
        clock.clone(),
        volume_key.clone(),
    )
    .unwrap();

    // Verify last_summary_generation was restored from 000001.summary
    assert_eq!(
        recovered_fs.last_summary_generation.load(Ordering::SeqCst),
        1,
        "last_summary_generation must be seeded from recovered summary file"
    );

    let writer2 = recovered_fs.next_log_writer(storage.clone(), 1024 * 1024).unwrap();
    recovered_fs.attach_log_writer(Arc::new(writer2));
    recovered_fs.log_cache = Some(Arc::new(LogFileCache::with_storage(storage.clone())));

    // Configure remote registry with 0-second retention to test pruning
    let mut registry = RemoteRegistry::new();
    let nas_cfg = RemoteTargetConfig::new_path(nfs_dir.path());
    registry.add_remote("nas", nas_cfg);
    registry.policy.prune_rule = PruneExpr::immediate_readable(1);
    let registry_arc = Arc::new(std::sync::RwLock::new(registry));

    let fs_arc = Arc::new(recovered_fs);
    let mut last_part_sync = std::time::SystemTime::now();
    let mut uploaded_parts = std::collections::HashMap::new();

    // Run cycle: should replicate 000001.log and prune it immediately without waiting for a new summary!
    assert!(storage.exists("000001.log"));
    appendfs::remote::RemoteReplicationWorker::run_cycle(
        &fs_arc,
        &registry_arc,
        Path::new("/unused"),
        &mut last_part_sync,
        &mut uploaded_parts,
    )
    .unwrap();

    // Verify 000001.log was pruned from storage
    assert!(
        !storage.exists("000001.log"),
        "000001.log must be pruned immediately after restart without waiting for a new summary"
    );
    // Verify it exists in the remote store
    assert!(nfs_dir.path().join("000001.log").exists());
}

#[test]
fn test_ro_mount_with_all_but_latest_summary_purged_locally() {
    let storage = Arc::new(MemoryStorage::new());
    let start_time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
    let clock = Arc::new(appendfs::clock::AdvancingClock::new(start_time));
    let volume_key = VolumeKey::plaintext_arc();

    // 1. Initialize volume with deterministic clock
    let TestFs { fs, .. } = TestFs::builder()
        .storage(storage.clone())
        .clock(clock.clone())
        .max_log_size(1024 * 1024)
        .build();
    let writer = fs.log_writer.clone().unwrap();

    // Write file A in generation 1
    let file_a = fs.create_file(1, "file_a.txt", 0o644).unwrap();
    let payload_a = b"Generation 1: Data for file A that will be pruned locally";
    fs.write_at(file_a, payload_a, 0).unwrap();
    fs.quiesce().unwrap();

    // Roll to generation 2 (sealing gen 1)
    clock.advance(std::time::Duration::from_secs(60));
    let sealed = writer.force_roll().unwrap().unwrap();
    assert_eq!(sealed.generation, 1);
    fs.manifest.write().unwrap().record_sealed_log(sealed);
    let summary1 = fs.export_summary(storage.as_ref()).unwrap();
    assert_eq!(summary1, "000001.summary");

    // Timestamp after generation 1 roll and summary1 export, but before file B write
    let post_gen1_time = clock.now() + std::time::Duration::from_secs(10);

    // Write file B in generation 2
    clock.advance(std::time::Duration::from_secs(60));
    let file_b = fs.create_file(1, "file_b.txt", 0o644).unwrap();
    let payload_b = b"Generation 2: Data for file B";
    fs.write_at(file_b, payload_b, 0).unwrap();
    fs.quiesce().unwrap();

    // Roll to generation 3 (sealing gen 2) and export summary 2
    clock.advance(std::time::Duration::from_secs(60));
    let sealed = writer.force_roll().unwrap().unwrap();
    assert_eq!(sealed.generation, 2);
    fs.manifest.write().unwrap().record_sealed_log(sealed);
    let summary2 = fs.export_summary(storage.as_ref()).unwrap();
    assert_eq!(summary2, "000002.summary");

    // 2. Setup mock remote store and upload all files from local storage to remote
    let mock_remote = Arc::new(MockRemoteStore::new());
    for file in storage.list_files().unwrap() {
        upload_storage_file(storage.as_ref(), mock_remote.as_ref(), &file, None).unwrap();
    }

    // Configure remote registry in storage
    let mut registry = RemoteRegistry::new();
    let remote_cfg = RemoteTargetConfig::new("mock-s3");
    registry.add_remote("s3", remote_cfg);
    registry.set_store_override("s3", mock_remote.clone());
    registry.save_to_storage(storage.as_ref()).unwrap();
    let remote_stores = registry.build_read_stores();

    // 3. SIMULATE LOCAL PURGING: delete all but 000002.summary
    storage.remove_file("000000.summary").unwrap();
    storage.remove_file("000001.summary").unwrap();
    storage.remove_file("000001.log").unwrap();
    storage.remove_file("000002.log").unwrap();

    assert!(!storage.exists("000000.summary"));
    assert!(!storage.exists("000001.summary"));
    assert!(!storage.exists("000001.log"));
    assert!(!storage.exists("000002.log"));
    assert!(storage.exists("000002.summary"));

    // =========================================================================
    // Scenario 1: Mount R/O with Latest state
    // =========================================================================
    // prepare_remote_recovery_for_target sees 000002.summary exists and is eligible for Latest
    let chosen = appendfs::prepare_remote_recovery_for_target(
        storage.as_ref(),
        appendfs::RecoveryTarget::Latest,
        volume_key.clone(),
        &remote_stores,
    )
    .unwrap();
    assert_eq!(chosen, Some("000002.summary".to_string()));

    // Fast-recover from 000002.summary
    let mut fs_latest = appendfs::recover_fs(
        storage.clone(),
        appendfs::RecoveryTarget::Latest,
        clock.clone(),
        volume_key.clone(),
    )
    .unwrap();
    fs_latest.set_read_only();

    // Attach remote tiered storage support
    let block_cache = Arc::new(MemoryBlockCache::new(50 * 1024 * 1024));
    let log_cache = Arc::new(LogFileCache::with_remote_support(
        storage.clone(),
        Some(block_cache.clone()),
        remote_stores.clone(),
        Some(Arc::clone(&fs_latest.manifest)),
    ));
    fs_latest.log_cache = Some(log_cache);

    // Verify both files exist in metadata
    assert!(fs_latest.lookup_child(1, "file_a.txt").is_some());
    assert!(fs_latest.lookup_child(1, "file_b.txt").is_some());

    // Read file_a (written in gen 1, which was purged locally!):
    // Should fetch from mock_remote via TieredStorageReader and return exact payload
    let read_a = fs_latest.read_at(file_a, 0, payload_a.len()).unwrap();
    assert_eq!(read_a, payload_a);

    // Read file_b (written in gen 2, also purged locally!):
    let read_b = fs_latest.read_at(file_b, 0, payload_b.len()).unwrap();
    assert_eq!(read_b, payload_b);

    // =========================================================================
    // Scenario 2: Mount R/O with past timestamp target (generation 1)
    // =========================================================================
    // 000001.summary is STILL missing locally
    assert!(!storage.exists("000001.summary"));

    // prepare_remote_recovery_for_target uses 000002.summary's manifest to discover
    // that generation 1 is the appropriate snapshot for post_gen1_time,
    // and downloads 000001.summary from the remote store!
    let chosen_past = appendfs::prepare_remote_recovery_for_target(
        storage.as_ref(),
        appendfs::RecoveryTarget::Timestamp(post_gen1_time),
        volume_key.clone(),
        &remote_stores,
    )
    .unwrap();
    assert_eq!(chosen_past, Some("000001.summary".to_string()));

    // Verify 000001.summary was indeed downloaded from remote to local storage!
    assert!(storage.exists("000001.summary"));

    // Fast-recover with Timestamp(post_gen1_time)
    let mut fs_past = appendfs::recover_fs(
        storage.clone(),
        appendfs::RecoveryTarget::Timestamp(post_gen1_time),
        clock.clone(),
        volume_key.clone(),
    )
    .unwrap();
    fs_past.set_read_only();

    let log_cache_past = Arc::new(LogFileCache::with_remote_support(
        storage.clone(),
        Some(block_cache.clone()),
        remote_stores.clone(),
        Some(Arc::clone(&fs_past.manifest)),
    ));
    fs_past.log_cache = Some(log_cache_past);

    // In generation 1, file_a exists, but file_b does NOT exist yet!
    assert!(
        fs_past.lookup_child(1, "file_a.txt").is_some(),
        "file_a must exist at gen 1 timestamp"
    );
    assert!(
        fs_past.lookup_child(1, "file_b.txt").is_none(),
        "file_b must NOT exist at gen 1 timestamp"
    );

    // Reading file_a from the historical past mount fetches from remote and succeeds!
    let read_past_a = fs_past.read_at(file_a, 0, payload_a.len()).unwrap();
    assert_eq!(read_past_a, payload_a);

    // =========================================================================
    // Scenario 3: Mount R/O with target generation 1
    // =========================================================================
    // Delete 000001.summary again
    storage.remove_file("000001.summary").unwrap();
    assert!(!storage.exists("000001.summary"));

    let chosen_gen1 = appendfs::prepare_remote_recovery_for_target(
        storage.as_ref(),
        appendfs::RecoveryTarget::Generation(1),
        volume_key.clone(),
        &remote_stores,
    )
    .unwrap();
    assert_eq!(chosen_gen1, Some("000001.summary".to_string()));
    assert!(storage.exists("000001.summary"));

    let mut fs_gen1 = appendfs::recover_fs(
        storage.clone(),
        appendfs::RecoveryTarget::Generation(1),
        clock.clone(),
        volume_key.clone(),
    )
    .unwrap();
    fs_gen1.set_read_only();
    let log_cache_gen1 = Arc::new(LogFileCache::with_remote_support(
        storage.clone(),
        Some(block_cache),
        remote_stores,
        Some(Arc::clone(&fs_gen1.manifest)),
    ));
    fs_gen1.log_cache = Some(log_cache_gen1);

    assert!(fs_gen1.lookup_child(1, "file_a.txt").is_some());
    assert!(fs_gen1.lookup_child(1, "file_b.txt").is_none());
    let read_gen1_a = fs_gen1.read_at(file_a, 0, payload_a.len()).unwrap();
    assert_eq!(read_gen1_a, payload_a);
}

#[test]
fn test_remote_listing_md5_optimization_in_pruning_and_integrity_check() {
    let storage = Arc::new(MemoryStorage::new());
    let start_time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
    let clock = Arc::new(appendfs::clock::AdvancingClock::new(start_time));

    // 1. Initialize volume with clock
    let TestFs { mut fs, .. } = TestFs::builder()
        .storage(storage.clone())
        .clock(clock.clone())
        .max_log_size(1024 * 1024)
        .build();
    let writer = fs.log_writer.clone().unwrap();
    fs.log_cache = Some(Arc::new(LogFileCache::with_storage(storage.clone())));
    let fs_arc = Arc::new(fs);

    // Create 3 sealed log generations
    for gen_idx in 1..=3 {
        let filename = format!("file_{}.txt", gen_idx);
        let file = fs_arc.create_file(1, &filename, 0o644).unwrap();
        let payload = format!("Payload for generation {}", gen_idx);
        fs_arc.write_at(file, payload.as_bytes(), 0).unwrap();
        fs_arc.quiesce().unwrap();

        // Roll and export summary
        let sealed = writer.force_roll().unwrap().unwrap();
        assert_eq!(sealed.generation, gen_idx);
        fs_arc.manifest.write().unwrap().record_sealed_log(sealed);
        fs_arc.sync_and_export_summary().unwrap();
    }

    let manifest = fs_arc.manifest.read().unwrap().clone();
    assert_eq!(manifest.logs.len(), 3); // Gens 1, 2, 3 sealed; active Gen 4 not in manifest

    // Set up remote with CountingRemoteStore
    let raw_remote = Arc::new(MockRemoteStore::new());
    let counting_store = Arc::new(CountingRemoteStore::new(raw_remote.clone()));

    let mut registry = RemoteRegistry::new();
    registry.add_remote("counting", RemoteTargetConfig::new("test-bucket"));
    registry.set_store_override("counting", counting_store.clone());
    // Set high retention so first cycle only replicates, does not prune
    registry.policy.prune_rule = PruneExpr::parse("older_than(1h) && readable(1)").unwrap();
    let registry_arc = Arc::new(std::sync::RwLock::new(registry));

    let mut last_part_sync = std::time::SystemTime::UNIX_EPOCH;
    let mut uploaded_parts = std::collections::HashMap::new();
    let mut last_audit = std::time::SystemTime::UNIX_EPOCH;
    let mut confirmed_gens = std::collections::HashMap::new();
    let mut confirmed_sums = std::collections::HashMap::new();

    // 2. Replicate all sealed generations and summaries to remote
    appendfs::remote::RemoteReplicationWorker::run_cycle_with_audit(
        &fs_arc,
        &registry_arc,
        Path::new("/unused"),
        &mut last_part_sync,
        &mut uploaded_parts,
        &mut last_audit,
        &mut confirmed_gens,
        &mut confirmed_sums,
        true,
        None,
        None,
    )
    .unwrap();

    // Verify all 3 sealed generations exist on remote
    for gen_idx in 1..=3 {
        let name = format!("{:06}.log", gen_idx);
        assert!(raw_remote.head_object(&name).unwrap().is_some());
    }

    // =========================================================================
    // Part A: Test check_remote_integrity optimization
    // =========================================================================
    counting_store.metrics().reset();

    // Batch listing should perform 1 list_objects call and 0 head_object calls
    let report = check_remote_integrity(
        counting_store.as_ref(),
        "counting",
        &manifest,
        &CheckOptions::metadata_only(),
        None,
    );
    assert!(report.is_clean(), "Integrity report must be clean");
    assert_eq!(
        counting_store.lists(),
        1,
        "check_remote_integrity must issue exactly 1 batch list_objects request"
    );
    assert_eq!(
        counting_store.heads(),
        0,
        "check_remote_integrity must NOT issue individual head_object requests"
    );

    // If list_objects fails, check_remote_integrity returns an error report without making head_object calls
    let failing_raw = Arc::new(FailingRemoteStore::new(raw_remote.clone()));
    let failing_counting = Arc::new(CountingRemoteStore::new(failing_raw.clone()));
    failing_raw.fail_method("list_objects");

    let failure_report = check_remote_integrity(
        failing_counting.as_ref(),
        "failing",
        &manifest,
        &CheckOptions::metadata_only(),
        None,
    );
    assert!(
        !failure_report.is_clean(),
        "Integrity check must fail when remote listing fails"
    );
    assert_eq!(failure_report.issues.len(), 1);
    assert_eq!(failure_report.issues[0].code, "REMOTE_LIST_FAILED");
    assert_eq!(failing_counting.lists(), 1, "list_objects was attempted once");
    assert_eq!(
        failing_counting.heads(),
        0,
        "No head_object calls should be made when list_objects fails"
    );

    // =========================================================================
    // Part B: Test retention pruning batch listing with ETags (MD5)
    // =========================================================================
    // Configure 0 retention so all sealed generations 1, 2, 3 are eligible for local pruning
    {
        let mut reg = registry_arc.write().unwrap();
        reg.policy.prune_rule = PruneExpr::immediate_readable(1);
    }

    // Ensure all 3 local log files exist before pruning
    assert!(storage.exists("000001.log"));
    assert!(storage.exists("000002.log"));
    assert!(storage.exists("000003.log"));

    counting_store.metrics().reset();

    // Run cycle: should check quorum via 1 list_objects call with ETags and prune all 3 logs!
    appendfs::remote::RemoteReplicationWorker::run_cycle_with_audit(
        &fs_arc,
        &registry_arc,
        Path::new("/unused"),
        &mut last_part_sync,
        &mut uploaded_parts,
        &mut last_audit,
        &mut confirmed_gens,
        &mut confirmed_sums,
        false, // incremental, confirmed_gens avoids Step 2 probes
        None,
        None,
    )
    .unwrap();

    // All 3 local logs must be pruned
    assert!(!storage.exists("000001.log"), "000001.log must be pruned");
    assert!(!storage.exists("000002.log"), "000002.log must be pruned");
    assert!(!storage.exists("000003.log"), "000003.log must be pruned");

    // Quorum MD5 verification must have used 1 list_objects and 0 head_object calls!
    assert_eq!(
        counting_store.lists(),
        1,
        "Pruning quorum verification must issue exactly 1 batch list_objects request"
    );
    assert_eq!(
        counting_store.heads(),
        0,
        "Pruning quorum verification must NOT issue individual head_object requests"
    );

    // =========================================================================
    // Part C: Test that failing list_objects skips remote without falling back to head_object
    // =========================================================================
    let file4 = fs_arc.create_file(1, "file_4.txt", 0o644).unwrap();
    fs_arc.write_at(file4, b"Payload for generation 4", 0).unwrap();
    fs_arc.quiesce().unwrap();

    let sealed = writer.force_roll().unwrap().unwrap();
    assert_eq!(sealed.generation, 4);
    fs_arc.manifest.write().unwrap().record_sealed_log(sealed);
    fs_arc.sync_and_export_summary().unwrap();

    // Set store to failing_counting which fails list_objects
    {
        let mut reg = registry_arc.write().unwrap();
        reg.set_store_override("counting", failing_counting.clone());
    }

    assert!(storage.exists("000004.log"));
    failing_counting.metrics().reset();

    // First cycle with list_objects failing:
    // With pure listing-based verification, replication and pruning are skipped when listing fails,
    // avoiding any uncoordinated O(N) head_object probes.
    appendfs::remote::RemoteReplicationWorker::run_cycle_with_audit(
        &fs_arc,
        &registry_arc,
        Path::new("/unused"),
        &mut last_part_sync,
        &mut uploaded_parts,
        &mut last_audit,
        &mut confirmed_gens,
        &mut confirmed_sums,
        false,
        None,
        None,
    )
    .unwrap();

    // 000004.log must NOT be pruned because listing failed on the remote
    assert!(
        storage.exists("000004.log"),
        "000004.log must NOT be pruned when remote listing fails"
    );
    assert_eq!(failing_counting.lists(), 1, "Attempted 1 list_objects call");
    assert_eq!(
        failing_counting.heads(),
        0,
        "No head_object fallback calls should be issued when listing fails"
    );

    // Reset metrics and run another cycle while list_objects is still failing:
    failing_counting.metrics().reset();
    appendfs::remote::RemoteReplicationWorker::run_cycle_with_audit(
        &fs_arc,
        &registry_arc,
        Path::new("/unused"),
        &mut last_part_sync,
        &mut uploaded_parts,
        &mut last_audit,
        &mut confirmed_gens,
        &mut confirmed_sums,
        false,
        None,
        None,
    )
    .unwrap();

    assert!(
        storage.exists("000004.log"),
        "000004.log must still NOT be pruned when listing continues to fail"
    );
    assert_eq!(failing_counting.lists(), 1, "Attempted 1 list_objects call");
    assert_eq!(
        failing_counting.heads(),
        0,
        "No head_object fallback calls should be issued during pruning"
    );

    // Now clear the failure so list_objects succeeds on the next cycle
    failing_raw.clear_fail_method("list_objects");
    failing_counting.metrics().reset();

    appendfs::remote::RemoteReplicationWorker::run_cycle_with_audit(
        &fs_arc,
        &registry_arc,
        Path::new("/unused"),
        &mut last_part_sync,
        &mut uploaded_parts,
        &mut last_audit,
        &mut confirmed_gens,
        &mut confirmed_sums,
        false,
        None,
        None,
    )
    .unwrap();

    // 000004.log should now be cleanly replicated and pruned via batch listing
    assert!(
        !storage.exists("000004.log"),
        "000004.log must be pruned once remote listing succeeds"
    );
    assert_eq!(
        failing_counting.lists(),
        1,
        "Replication and pruning used 1 list_objects request"
    );
    // 1 head_object call per newly uploaded file (000004.log and 000001.summary)
    assert_eq!(
        failing_counting.heads(),
        2,
        "Post-upload verification issued 1 head_object call per uploaded file (log + summary)"
    );

    // On subsequent cycles without new uploads, exactly 0 head_object calls are made
    failing_counting.metrics().reset();
    appendfs::remote::RemoteReplicationWorker::run_cycle_with_audit(
        &fs_arc,
        &registry_arc,
        Path::new("/unused"),
        &mut last_part_sync,
        &mut uploaded_parts,
        &mut last_audit,
        &mut confirmed_gens,
        &mut confirmed_sums,
        false,
        None,
        None,
    )
    .unwrap();
    assert_eq!(failing_counting.lists(), 1, "1 batch listing for the cycle");
    assert_eq!(
        failing_counting.heads(),
        0,
        "No head_object calls when no uploads are needed"
    );
}

#[test]
fn test_per_remote_upload_partial_logs_behavior() {
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let clock = Arc::new(SystemClock);
    let volume_key = VolumeKey::plaintext_arc();

    let TestFs { fs, .. } = TestFs::builder()
        .storage(storage.clone())
        .clock(clock.clone())
        .max_log_size(1024 * 1024)
        .build();
    let writer = fs.log_writer.clone().unwrap();

    let nfs_mock = Arc::new(MockRemoteStore::new());
    let s3_raw = Arc::new(MockRemoteStore::new());
    let s3_counting = Arc::new(CountingRemoteStore::new(s3_raw.clone()));

    // Setup registry: nfs has upload_partial_logs = true, s3 has upload_partial_logs = false
    let mut registry = RemoteRegistry::new();
    registry.policy.active_sync_interval_secs = 0; // trigger on every tick
    registry.policy.prune_rule = PruneExpr::immediate_readable(1);

    let nfs_cfg = RemoteTargetConfig::new_path("/mnt/nfs/appendfs");
    assert!(
        nfs_cfg.upload_partial_logs(),
        "new_path must default upload_partial_logs to true"
    );
    registry.add_remote("nfs", nfs_cfg);
    registry.set_store_override("nfs", nfs_mock.clone());

    let s3_cfg = RemoteTargetConfig::new("my-s3-bucket").with_upload_partial_logs(false);
    assert!(!s3_cfg.upload_partial_logs());
    registry.add_remote("s3", s3_cfg.clone());
    registry.set_store_override("s3", s3_counting.clone());

    let registry_arc = Arc::new(std::sync::RwLock::new(registry));
    let fs_arc = Arc::new(fs);
    fs_arc.set_remote_registry(registry_arc.clone());

    let mut last_part_sync = std::time::SystemTime::UNIX_EPOCH;
    let mut uploaded_parts = std::collections::HashMap::new();

    // 1. Write first chunk of active data
    let file1_ino = fs_arc.create_file(1, "active_doc.txt", 0o644).unwrap();
    let ino = file1_ino;
    fs_arc
        .write_at(ino, b"Chunk 0: real-time mutations for NFS only!", 0)
        .unwrap();
    fs_arc.quiesce().unwrap();

    // Run replication cycle
    appendfs::remote::RemoteReplicationWorker::run_cycle(
        &fs_arc,
        &registry_arc,
        Path::new("/unused"),
        &mut last_part_sync,
        &mut uploaded_parts,
    )
    .unwrap();

    // NFS must have part0000, S3 must NOT have part0000
    assert!(
        nfs_mock.head_object("000001.part0000.log").unwrap().is_some(),
        "NFS must receive active part0000"
    );
    assert!(
        s3_counting.head_object("000001.part0000.log").unwrap().is_none(),
        "S3 with upload_partial_logs=false must NOT receive active part0000"
    );

    // Telemetry check
    {
        let telem = fs_arc.replication_telemetry.read().unwrap();
        assert_eq!(telem.remotes["nfs"].active_part, Some((1, 0)));
        assert!(telem.remotes.get("s3").is_none_or(|t| t.active_part.is_none()));
    }

    // 2. Write second chunk of active data
    fs_arc.write_at(ino, b"Chunk 1: more mutations appended!", 100).unwrap();
    fs_arc.quiesce().unwrap();

    last_part_sync = std::time::SystemTime::UNIX_EPOCH;
    appendfs::remote::RemoteReplicationWorker::run_cycle(
        &fs_arc,
        &registry_arc,
        Path::new("/unused"),
        &mut last_part_sync,
        &mut uploaded_parts,
    )
    .unwrap();

    assert!(
        nfs_mock.head_object("000001.part0001.log").unwrap().is_some(),
        "NFS must receive active part0001"
    );
    assert!(
        s3_counting.head_object("000001.part0001.log").unwrap().is_none(),
        "S3 must NOT receive active part0001"
    );

    // 3. Roll generation: seals gen 1 into gen 2 and exports summary
    let sealed = writer.force_roll().unwrap().unwrap();
    assert_eq!(sealed.generation, 1);
    fs_arc.manifest.write().unwrap().record_sealed_log(sealed);
    fs_arc.export_summary(storage.as_ref()).unwrap();

    // Run cycle after seal
    appendfs::remote::RemoteReplicationWorker::run_cycle(
        &fs_arc,
        &registry_arc,
        Path::new("/unused"),
        &mut last_part_sync,
        &mut uploaded_parts,
    )
    .unwrap();

    // Both remotes must have sealed 000001.log
    assert!(
        nfs_mock.head_object("000001.log").unwrap().is_some(),
        "NFS must receive sealed 000001.log"
    );
    assert!(
        s3_counting.head_object("000001.log").unwrap().is_some(),
        "S3 must receive sealed 000001.log"
    );

    // NFS parts were cleaned up
    assert!(
        nfs_mock.list_objects("000001.part").unwrap().is_empty(),
        "NFS transient parts must be cleaned up on seal"
    );

    // CRUCIAL: S3 received ZERO delete_object calls!
    assert_eq!(
        s3_counting.deletes(),
        0,
        "S3 remote with upload_partial_logs=false must never issue delete_object calls"
    );

    // Check .remotes virtual file status output
    let status = appendfs::remote::worker::format_remotes_status(&fs_arc);
    assert!(status.contains("[Remote: nfs]"));
    assert!(status.contains("Partial Logs:       Enabled"));
    assert!(status.contains("[Remote: s3]"));
    assert!(status.contains("Partial Logs:       Disabled"));

    // 4. Disaster recovery / bootstrap from S3 (which has no parts)
    let fresh_storage = Arc::new(MemoryStorage::new());
    let recovered_summary =
        appendfs::remote::bootstrap_from_remote(s3_raw.as_ref(), fresh_storage.as_ref(), "s3", s3_cfg).unwrap();
    assert!(fresh_storage.exists(&recovered_summary));
    assert!(fresh_storage.exists("remotes.toml"));

    let fresh_fs = appendfs::recover_fs(fresh_storage, appendfs::RecoveryTarget::Latest, clock, volume_key).unwrap();
    let base = fresh_fs.inner.lock_for_tests().unwrap().base.clone();
    assert!(base.len() >= 2); // root + active_doc.txt
}

#[test]
fn test_unsealed_manifest_logs_are_synced_and_pruned() {
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let mock_time = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
    let clock = Arc::new(appendfs::clock::MockClock(mock_time));
    let volume_key = VolumeKey::plaintext_arc();

    init_volume(storage.clone(), &volume_key, VolumeHeader::plaintext(), clock.clone()).unwrap();

    // 1. Write an unsealed log file (generation 1) without an OpCode::Seal record
    let writer = LogWriter::create(storage.clone(), 1, clock.clone(), 10_000_000, 1, volume_key.clone()).unwrap();
    writer
        .append_raw_for_test(appendfs::log::OpCode::InodeDelta, 1, b"unsealed record payload")
        .unwrap();
    writer.emit_flush_commit(1, 23, clock.now()).unwrap();
    writer.flush().unwrap();
    // Drop writer directly without rolling/sealing -> simulates crash / unsealed log
    drop(writer);

    // 2. Recover filesystem -> gen 1 recovered into manifest without a seal record
    let mut fs = appendfs::recover_fs(
        storage.clone(),
        appendfs::RecoveryTarget::Latest,
        clock.clone(),
        volume_key.clone(),
    )
    .unwrap();
    {
        let manifest = fs.manifest.read().unwrap();
        assert_eq!(manifest.logs.len(), 1);
        assert_eq!(manifest.logs[0].generation, 1);
        assert!(!manifest.logs[0].is_sealed(), "gen 1 is unsealed");
        assert_eq!(manifest.logs[0].sealed_at, None);
    }

    // 3. Mount log writer for gen 2 and export summary covering gen 1
    let gen2_writer = fs.next_log_writer(storage.clone(), 10_000_000).unwrap();
    assert_eq!(gen2_writer.generation(), 2);
    fs.attach_log_writer(Arc::new(gen2_writer));
    let exported = fs.export_summary(storage.as_ref()).unwrap();
    assert_eq!(exported, "000001.summary");

    let fs_arc = Arc::new(fs);

    // 4. Configure remote target
    let mock_remote = Arc::new(MockRemoteStore::new());
    let mut registry = RemoteRegistry::new();
    registry.add_remote("remote1", RemoteTargetConfig::new("test-bucket"));
    registry.set_store_override("remote1", mock_remote.clone());
    registry.policy.prune_rule = PruneExpr::immediate_readable(1);
    let registry_arc = Arc::new(std::sync::RwLock::new(registry));

    let mut last_part_sync = std::time::SystemTime::UNIX_EPOCH;
    let mut uploaded_parts = std::collections::HashMap::new();

    // 5. Run replication worker cycle
    appendfs::remote::RemoteReplicationWorker::run_cycle(
        &fs_arc,
        &registry_arc,
        Path::new("/unused"),
        &mut last_part_sync,
        &mut uploaded_parts,
    )
    .unwrap();

    // Verify unsealed 000001.log WAS replicated to the remote
    assert!(
        mock_remote.head_object("000001.log").unwrap().is_some(),
        "unsealed generation 1 log in manifest must be replicated to remote"
    );

    // Verify unsealed 000001.log WAS pruned locally after confirmation on remote
    assert!(
        !storage.exists("000001.log"),
        "unsealed generation 1 log in manifest must be pruned locally when retention criteria met"
    );
}

#[test]
fn test_post_upload_md5_verification_failure_and_recovery() {
    use appendfs::remote::RemoteObject;
    use std::io::{Read, Write};

    #[derive(Debug)]
    struct TamperedEtagStore {
        inner: Arc<MockRemoteStore>,
        tamper_head: std::sync::atomic::AtomicBool,
    }

    impl RemoteStore for TamperedEtagStore {
        fn list_objects(&self, prefix: &str) -> std::io::Result<Vec<RemoteObject>> {
            self.inner.list_objects(prefix)
        }

        fn head_object(&self, key: &str) -> std::io::Result<Option<RemoteObject>> {
            let mut obj = self.inner.head_object(key)?;
            if self.tamper_head.load(Ordering::SeqCst)
                && key.ends_with(".log")
                && let Some(ref mut o) = obj
            {
                // Inject a corrupted/mismatched MD5 digest in the ETag
                o.etag = Some("\"0123456789abcdef0123456789abcdef\"".to_string());
            }
            Ok(obj)
        }

        fn put_object(
            &self,
            key: &str,
            reader: &mut dyn Read,
            len: u64,
            content_md5: Option<&[u8; 16]>,
        ) -> std::io::Result<()> {
            self.inner.put_object(key, reader, len, content_md5)
        }

        fn get_object(&self, key: &str, writer: &mut dyn Write) -> std::io::Result<u64> {
            self.inner.get_object(key, writer)
        }

        fn get_object_range(&self, key: &str, offset: u64, len: u64, writer: &mut dyn Write) -> std::io::Result<u64> {
            self.inner.get_object_range(key, offset, len, writer)
        }

        fn delete_object(&self, key: &str) -> std::io::Result<()> {
            self.inner.delete_object(key)
        }
    }

    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let clock = Arc::new(SystemClock);

    let TestFs { mut fs, .. } = TestFs::builder()
        .storage(storage.clone())
        .clock(clock.clone())
        .max_log_size(1024 * 1024)
        .build();
    let writer = fs.log_writer.clone().unwrap();
    fs.log_cache = Some(Arc::new(LogFileCache::with_storage(storage.clone())));

    let raw_store = Arc::new(MockRemoteStore::new());
    let tampered_store = Arc::new(TamperedEtagStore {
        inner: raw_store.clone(),
        tamper_head: std::sync::atomic::AtomicBool::new(true),
    });

    let mut registry = RemoteRegistry::new();
    let mut cfg = RemoteTargetConfig::new("test-bucket");
    cfg.upload_partial_logs = Some(true);
    registry.add_remote("backup", cfg);
    registry.set_store_override("backup", tampered_store.clone());
    registry.policy.prune_rule = PruneExpr::immediate_readable(1);
    let registry_arc = Arc::new(std::sync::RwLock::new(registry));

    // 1. Write an active part in generation 1 and sync it
    let root = 1u64;
    let file_ino = fs.create_file(root, "test_file.txt", 0o644).unwrap();
    fs.write_at(file_ino, b"Active part data before seal", 0).unwrap();
    fs.quiesce().unwrap();

    let mut last_part_sync = std::time::SystemTime::UNIX_EPOCH;
    let mut uploaded_parts = std::collections::HashMap::new();
    let mut last_audit = std::time::SystemTime::UNIX_EPOCH;
    let mut confirmed_gens = std::collections::HashMap::new();
    let mut confirmed_sums = std::collections::HashMap::new();

    let fs_arc = Arc::new(fs);

    // Sync active part: 000001.part0000.log is uploaded to remote
    appendfs::remote::RemoteReplicationWorker::run_cycle_with_audit(
        &fs_arc,
        &registry_arc,
        Path::new("/unused"),
        &mut last_part_sync,
        &mut uploaded_parts,
        &mut last_audit,
        &mut confirmed_gens,
        &mut confirmed_sums,
        false,
        None,
        None,
    )
    .unwrap();

    assert!(
        raw_store.head_object("000001.part0000.log").unwrap().is_some(),
        "Active part0000 must be uploaded to remote"
    );

    // 2. Force roll to generation 2 (seals generation 1)
    let sealed = writer.force_roll().unwrap().unwrap();
    assert_eq!(sealed.generation, 1);
    fs_arc.manifest.write().unwrap().record_sealed_log(sealed);
    fs_arc.export_summary(storage.as_ref()).unwrap();

    // Reset part timer to run replication with tamper_head = true
    last_part_sync = std::time::SystemTime::UNIX_EPOCH;

    // 3. Run replication cycle with tampered ETag in post-upload check
    appendfs::remote::RemoteReplicationWorker::run_cycle_with_audit(
        &fs_arc,
        &registry_arc,
        Path::new("/unused"),
        &mut last_part_sync,
        &mut uploaded_parts,
        &mut last_audit,
        &mut confirmed_gens,
        &mut confirmed_sums,
        false,
        None,
        None,
    )
    .unwrap();

    // 000001.log WAS uploaded to raw_store by upload_storage_file,
    // but post-upload check failed due to ETag MD5 mismatch!
    assert!(raw_store.head_object("000001.log").unwrap().is_some());

    // Because post-upload MD5 verification failed:
    // a. Transient active part was NOT cleaned up!
    assert!(
        raw_store.head_object("000001.part0000.log").unwrap().is_some(),
        "Transient part must NOT be cleaned up when post-upload MD5 verification fails"
    );
    // b. Generation was NOT confirmed!
    assert!(
        !confirmed_gens.get("backup").is_some_and(|s| s.contains(&1)),
        "Generation 1 must NOT be confirmed when post-upload MD5 check fails"
    );
    // c. Local log file was NOT pruned!
    assert!(
        storage.exists("000001.log"),
        "Local 000001.log must NOT be pruned when post-upload MD5 verification fails"
    );
    // d. Telemetry recorded verification error!
    assert!(
        fs_arc
            .replication_telemetry
            .read()
            .unwrap()
            .remotes
            .get("backup")
            .unwrap()
            .last_error
            .is_some(),
        "Telemetry must record the post-upload verification error"
    );

    // 4. Clear tampering: post-upload head_object will now return the real matching ETag MD5
    tampered_store.tamper_head.store(false, Ordering::SeqCst);
    last_part_sync = std::time::SystemTime::UNIX_EPOCH;

    appendfs::remote::RemoteReplicationWorker::run_cycle_with_audit(
        &fs_arc,
        &registry_arc,
        Path::new("/unused"),
        &mut last_part_sync,
        &mut uploaded_parts,
        &mut last_audit,
        &mut confirmed_gens,
        &mut confirmed_sums,
        false,
        None,
        None,
    )
    .unwrap();

    // Now post-upload verification succeeds:
    // a. Transient active part is deleted!
    assert!(
        raw_store.head_object("000001.part0000.log").unwrap().is_none(),
        "Transient part must be deleted once post-upload verification succeeds"
    );
    // b. Generation 1 is confirmed!
    assert!(
        confirmed_gens.get("backup").unwrap().contains(&1),
        "Generation 1 must be confirmed on remote"
    );
    // c. Local log file is safely pruned!
    assert!(
        !storage.exists("000001.log"),
        "Local 000001.log must be pruned once remote verification succeeds"
    );
}

#[test]
fn test_write_only_glacier_remote_replication_and_prune_safety() {
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let clock = Arc::new(SystemClock);

    let TestFs { fs, .. } = TestFs::builder()
        .storage(storage.clone())
        .clock(clock.clone())
        .max_log_size(1024 * 1024)
        .build();
    let writer = fs.log_writer.clone().unwrap();

    let live_remote = Arc::new(MockRemoteStore::new());
    let glacier_remote = Arc::new(MockRemoteStore::new());

    let mut registry = RemoteRegistry::new();
    let s3_live_cfg = RemoteTargetConfig::new("s3-live-bucket").with_mode(RemoteMode::ReadWrite);
    let glacier_cfg = RemoteTargetConfig::new("glacier-bucket")
        .with_mode(RemoteMode::WriteOnly)
        .with_storage_class("DEEP_ARCHIVE");

    // upload_partial_logs should default to true for live, false for glacier
    assert!(s3_live_cfg.upload_partial_logs());
    assert!(!glacier_cfg.upload_partial_logs());

    registry.add_remote("s3_live", s3_live_cfg);
    registry.add_remote("glacier", glacier_cfg);
    registry.set_store_override("s3_live", live_remote.clone());
    registry.set_store_override("glacier", glacier_remote.clone());
    registry.policy.prune_rule = PruneExpr::immediate_readable(1);
    registry.policy.active_sync_interval_secs = 0; // immediate partial sync

    // 1. Verify build_read_stores EXCLUDES write-only glacier remote
    let read_stores = registry.build_read_stores();
    assert_eq!(read_stores.len(), 1);
    assert_eq!(read_stores[0].name, "s3_live");

    let fs_arc = Arc::new(fs);
    let registry_arc = Arc::new(std::sync::RwLock::new(registry));
    fs_arc.set_remote_registry(registry_arc.clone());

    // 2. Perform write in active generation 1
    let file1_ino = fs_arc.create_file(1, "test.txt", 0o644).unwrap();
    let ino = file1_ino;
    fs_arc.write_at(ino, b"data-for-active-part", 0).unwrap();
    fs_arc.quiesce().unwrap();

    let mut last_part_sync = std::time::SystemTime::UNIX_EPOCH;
    let mut uploaded_parts = std::collections::HashMap::new();

    // 3. Run worker cycle: live remote gets active part, glacier remote does NOT
    appendfs::remote::RemoteReplicationWorker::run_cycle(
        &fs_arc,
        &registry_arc,
        Path::new("/unused"),
        &mut last_part_sync,
        &mut uploaded_parts,
    )
    .unwrap();

    assert!(
        live_remote.head_object("000001.part0000.log").unwrap().is_some(),
        "live remote must receive active part"
    );
    assert!(
        glacier_remote.head_object("000001.part0000.log").unwrap().is_none(),
        "glacier write-only remote must NOT receive active parts"
    );

    // 4. Seal generation 1 and roll to generation 2
    let sealed = writer.force_roll().unwrap().unwrap();
    assert_eq!(sealed.generation, 1);
    fs_arc.manifest.write().unwrap().record_sealed_log(sealed);
    let summary_file = fs_arc.export_summary(storage.as_ref()).unwrap();

    // 5. Run worker cycle: both remotes receive sealed 000001.log and summary
    appendfs::remote::RemoteReplicationWorker::run_cycle(
        &fs_arc,
        &registry_arc,
        Path::new("/unused"),
        &mut last_part_sync,
        &mut uploaded_parts,
    )
    .unwrap();

    assert!(
        live_remote.head_object("000001.log").unwrap().is_some(),
        "live remote must receive sealed 000001.log"
    );
    assert!(
        glacier_remote.head_object("000001.log").unwrap().is_some(),
        "glacier remote must receive sealed 000001.log"
    );
    assert!(
        glacier_remote.head_object(&summary_file).unwrap().is_some(),
        "glacier remote must receive summary"
    );

    // 6. Test eviction quorum safety:
    // Create a standalone scenario where ONLY glacier has confirmed a sealed file.
    // Since glacier is write-only, prune_local_cache must NOT prune the local file!
    let isolated_storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let TestFs { fs: iso_fs, .. } = TestFs::builder()
        .storage(isolated_storage.clone())
        .clock(clock.clone())
        .max_log_size(1024 * 1024)
        .build();
    let iso_writer = iso_fs.log_writer.clone().unwrap();

    let iso_fs_arc = Arc::new(iso_fs);
    let iso_file_ino = iso_fs_arc.create_file(1, "important.txt", 0o644).unwrap();
    iso_fs_arc.write_at(iso_file_ino, b"crucial data", 0).unwrap();
    iso_fs_arc.quiesce().unwrap();
    let iso_sealed = iso_writer.force_roll().unwrap().unwrap();
    iso_fs_arc.manifest.write().unwrap().record_sealed_log(iso_sealed);
    let _ = iso_fs_arc.export_summary(isolated_storage.as_ref()).unwrap();

    assert!(isolated_storage.exists("000001.log"));

    // Upload 000001.log ONLY to a write-only glacier remote
    let lone_glacier = Arc::new(MockRemoteStore::new());
    let gen1_md5 = iso_fs_arc.manifest.read().unwrap().get_by_generation(1).unwrap().md5;
    upload_storage_file(
        isolated_storage.as_ref(),
        lone_glacier.as_ref(),
        "000001.log",
        Some(&gen1_md5),
    )
    .unwrap();

    let mut lone_registry = RemoteRegistry::new();
    let lone_glacier_cfg = RemoteTargetConfig::new("lone-glacier")
        .with_mode(RemoteMode::WriteOnly)
        .with_storage_class("DEEP_ARCHIVE");
    lone_registry.add_remote("glacier", lone_glacier_cfg);
    lone_registry.set_store_override("glacier", lone_glacier.clone());
    lone_registry.policy.prune_rule = PruneExpr::immediate_readable(1);

    let lone_reg_arc = Arc::new(std::sync::RwLock::new(lone_registry));
    let mut lone_part_sync = std::time::SystemTime::UNIX_EPOCH;
    let mut lone_parts = std::collections::HashMap::new();

    appendfs::remote::RemoteReplicationWorker::run_cycle(
        &iso_fs_arc,
        &lone_reg_arc,
        Path::new("/unused"),
        &mut lone_part_sync,
        &mut lone_parts,
    )
    .unwrap();

    // CRITICAL INVARIANT: 000001.log must NOT be pruned locally because the only remote that confirmed it is write-only!
    assert!(
        isolated_storage.exists("000001.log"),
        "local file must NOT be pruned when only confirmed on write-only remotes!"
    );
}

#[test]
fn test_prune_rule_multi_tier_lifecycle_with_glacier() {
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let clock = Arc::new(SystemClock);

    let TestFs { fs, .. } = TestFs::builder()
        .storage(storage.clone())
        .clock(clock.clone())
        .max_log_size(1024 * 1024)
        .build();
    let writer = fs.log_writer.clone().unwrap();

    let nfs_remote = Arc::new(MockRemoteStore::new());
    let glacier_remote = Arc::new(MockRemoteStore::new());

    let mut registry = RemoteRegistry::new();
    let nfs_cfg = RemoteTargetConfig::new_path("/tmp/nfs").with_mode(RemoteMode::ReadWrite);
    let glacier_cfg = RemoteTargetConfig::new("glacier-bucket")
        .with_mode(RemoteMode::WriteOnly)
        .with_storage_class("DEEP_ARCHIVE");

    registry.add_remote("nfs", nfs_cfg);
    registry.add_remote("glacier", glacier_cfg);
    registry.set_store_override("nfs", nfs_remote.clone());
    registry.set_store_override("glacier", glacier_remote.clone());

    // 1. Verify safety validation rejects an unsafe prune_rule that allows solely glacier
    registry.policy.prune_rule = PruneExpr::parse("older_than(0s) && glacier").unwrap();
    assert!(
        registry.validate().is_err(),
        "Prune rule satisfied solely by write-only glacier remote must fail validation"
    );

    // 2. Set multi-tier rule requiring BOTH nfs (readable) AND glacier (write-only archive)
    registry.policy.prune_rule = PruneExpr::parse("older_than(0s) && oneof(nfs) && oneof(glacier)").unwrap();
    assert!(registry.validate().is_ok());

    let fs_arc = Arc::new(fs);
    let registry_arc = Arc::new(std::sync::RwLock::new(registry));
    fs_arc.set_remote_registry(registry_arc.clone());

    // Create file and seal generation 1
    let file1_ino = fs_arc.create_file(1, "test.txt", 0o644).unwrap();
    fs_arc.write_at(file1_ino, b"multi-tier prune data", 0).unwrap();
    fs_arc.quiesce().unwrap();
    let sealed = writer.force_roll().unwrap().unwrap();
    fs_arc.manifest.write().unwrap().record_sealed_log(sealed);
    let _ = fs_arc.export_summary(storage.as_ref()).unwrap();

    assert!(storage.exists("000001.log"));

    // Scenario: Test evaluation with partial confirmations
    let stores = registry_arc.read().unwrap().build_all_stores();
    let mut confirmed = std::collections::HashSet::from(["glacier"]);
    let ctx_partial = PruneContext::new(Duration::from_secs(10), &confirmed, &stores);
    assert!(
        !registry_arc.read().unwrap().policy.prune_rule.evaluate(&ctx_partial),
        "Prune rule requiring nfs && glacier must not be satisfied when only glacier confirmed"
    );

    confirmed.insert("nfs");
    let ctx_full = PruneContext::new(Duration::from_secs(10), &confirmed, &stores);
    assert!(
        registry_arc.read().unwrap().policy.prune_rule.evaluate(&ctx_full),
        "Prune rule must be satisfied when both nfs and glacier are confirmed"
    );

    // Run worker cycle: replicates to both remotes, confirms both, and prunes local log!
    let mut last_part_sync = std::time::SystemTime::UNIX_EPOCH;
    let mut uploaded_parts = std::collections::HashMap::new();

    appendfs::remote::RemoteReplicationWorker::run_cycle(
        &fs_arc,
        &registry_arc,
        Path::new("/unused"),
        &mut last_part_sync,
        &mut uploaded_parts,
    )
    .unwrap();

    assert!(
        glacier_remote.head_object("000001.log").unwrap().is_some(),
        "glacier remote must have received 000001.log"
    );
    assert!(
        nfs_remote.head_object("000001.log").unwrap().is_some(),
        "nfs remote must have received 000001.log"
    );
    assert!(
        !storage.exists("000001.log"),
        "000001.log must be pruned locally once both nfs and glacier confirmed it!"
    );
}

#[test]
fn test_shutdown_drain_syncs_latest_sealed_log_and_skips_earlier_backlog() {
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let clock = Arc::new(SystemClock);

    let TestFs { mut fs, .. } = TestFs::builder()
        .storage(storage.clone())
        .clock(clock.clone())
        .max_log_size(1024 * 1024)
        .build();
    let writer = fs.log_writer.clone().unwrap();

    // Gen 1:
    let f1 = fs.create_file(1, "f1.txt", 0o644).unwrap();
    fs.write_at(f1, b"data 1", 0).unwrap();
    fs.quiesce().unwrap();
    let sealed1 = writer.force_roll().unwrap().unwrap();
    fs.manifest.write().unwrap().record_sealed_log(sealed1);

    // Gen 2:
    let f2 = fs.create_file(1, "f2.txt", 0o644).unwrap();
    fs.write_at(f2, b"data 2", 0).unwrap();
    fs.quiesce().unwrap();
    let sealed2 = writer.force_roll().unwrap().unwrap();
    fs.manifest.write().unwrap().record_sealed_log(sealed2);

    // Gen 3:
    let f3 = fs.create_file(1, "f3.txt", 0o644).unwrap();
    fs.write_at(f3, b"data 3", 0).unwrap();
    fs.quiesce().unwrap();
    let sealed3 = writer.force_roll().unwrap().unwrap();
    fs.manifest.write().unwrap().record_sealed_log(sealed3);

    let summary = fs.export_summary(storage.as_ref()).unwrap();
    fs.log_cache = Some(Arc::new(LogFileCache::with_storage(storage.clone())));
    let fs_arc = Arc::new(fs);

    let mock_remote = Arc::new(MockRemoteStore::new());
    let mut registry = RemoteRegistry::new();
    registry.add_remote("mock", RemoteTargetConfig::new("test-bucket"));
    registry.set_store_override("mock", mock_remote.clone());
    let registry_arc = Arc::new(std::sync::RwLock::new(registry));

    // Remote has nothing (missing 000001.log, 000002.log, 000003.log)
    appendfs::remote::RemoteReplicationWorker::drain_on_shutdown(&fs_arc, &registry_arc).unwrap();

    // Verify remote received the latest sealed log (000003.log) and summary,
    // while skipping earlier backlog logs (000001.log, 000002.log) and older summaries to avoid wasting bandwidth.
    assert!(mock_remote.head_object("000001.log").unwrap().is_none());
    assert!(mock_remote.head_object("000002.log").unwrap().is_none());
    assert!(mock_remote.head_object("000003.log").unwrap().is_some());
    assert!(mock_remote.head_object("000000.summary").unwrap().is_none());
    assert!(mock_remote.head_object(&summary).unwrap().is_some());
}

#[test]
fn test_shutdown_drain_prunes_eligible_local_logs() {
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let clock = Arc::new(SystemClock);

    let TestFs { mut fs, .. } = TestFs::builder()
        .storage(storage.clone())
        .clock(clock.clone())
        .max_log_size(1024 * 1024)
        .build();
    let writer = fs.log_writer.clone().unwrap();

    let f1 = fs.create_file(1, "f1.txt", 0o644).unwrap();
    fs.write_at(f1, b"data 1", 0).unwrap();
    fs.quiesce().unwrap();
    let sealed1 = writer.force_roll().unwrap().unwrap();
    fs.manifest.write().unwrap().record_sealed_log(sealed1);

    let summary = fs.export_summary(storage.as_ref()).unwrap();
    fs.log_cache = Some(Arc::new(LogFileCache::with_storage(storage.clone())));
    let fs_arc = Arc::new(fs);

    let mock_remote = Arc::new(MockRemoteStore::new());
    let mut registry = RemoteRegistry::new();
    registry.add_remote("mock", RemoteTargetConfig::new("test-bucket"));
    registry.set_store_override("mock", mock_remote.clone());
    registry.policy.prune_rule = PruneExpr::parse("older_than(0s) && oneof(mock)").unwrap();
    let registry_arc = Arc::new(std::sync::RwLock::new(registry));

    assert!(storage.exists("000001.log"));

    appendfs::remote::RemoteReplicationWorker::drain_on_shutdown(&fs_arc, &registry_arc).unwrap();

    // Verify 000001.log was replicated to mock remote AND pruned locally
    assert!(mock_remote.head_object("000001.log").unwrap().is_some());
    assert!(mock_remote.head_object(&summary).unwrap().is_some());
    assert!(
        !storage.exists("000001.log"),
        "000001.log must be pruned locally during shutdown drain"
    );
}

#[test]
fn test_shutdown_drain_replicates_only_missing_latest_sealed_log_and_summary() {
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let clock = Arc::new(SystemClock);

    let TestFs { mut fs, .. } = TestFs::builder()
        .storage(storage.clone())
        .clock(clock.clone())
        .max_log_size(1024 * 1024)
        .build();
    let writer = fs.log_writer.clone().unwrap();

    // Gen 1:
    let f1 = fs.create_file(1, "f1.txt", 0o644).unwrap();
    fs.write_at(f1, b"data 1", 0).unwrap();
    fs.quiesce().unwrap();
    let sealed1 = writer.force_roll().unwrap().unwrap();
    let sealed1_md5 = sealed1.md5;
    fs.manifest.write().unwrap().record_sealed_log(sealed1);

    // Gen 2:
    let f2 = fs.create_file(1, "f2.txt", 0o644).unwrap();
    fs.write_at(f2, b"data 2", 0).unwrap();
    fs.quiesce().unwrap();
    let sealed2 = writer.force_roll().unwrap().unwrap();
    fs.manifest.write().unwrap().record_sealed_log(sealed2);

    let summary = fs.export_summary(storage.as_ref()).unwrap();
    fs.log_cache = Some(Arc::new(LogFileCache::with_storage(storage.clone())));
    let fs_arc = Arc::new(fs);

    let mock_remote = Arc::new(MockRemoteStore::new());
    // Pre-populate remote with 000001.log: only 000002.log (the latest sealed log) is missing!
    upload_storage_file(storage.as_ref(), mock_remote.as_ref(), "000001.log", Some(&sealed1_md5)).unwrap();

    let mut registry = RemoteRegistry::new();
    registry.add_remote("mock", RemoteTargetConfig::new("test-bucket"));
    registry.set_store_override("mock", mock_remote.clone());
    let registry_arc = Arc::new(std::sync::RwLock::new(registry));

    appendfs::remote::RemoteReplicationWorker::drain_on_shutdown(&fs_arc, &registry_arc).unwrap();

    // Verify 000002.log and summary WERE replicated because ONLY the latest sealed log was missing
    assert!(mock_remote.head_object("000002.log").unwrap().is_some());
    assert!(mock_remote.head_object(&summary).unwrap().is_some());
}

#[test]
fn test_shutdown_drain_syncs_latest_summary_and_skips_earlier_summaries() {
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let clock = Arc::new(SystemClock);

    let TestFs { mut fs, .. } = TestFs::builder()
        .storage(storage.clone())
        .clock(clock.clone())
        .max_log_size(1024 * 1024)
        .build();
    let writer = fs.log_writer.clone().unwrap();

    // Gen 1:
    let f1 = fs.create_file(1, "f1.txt", 0o644).unwrap();
    fs.write_at(f1, b"data 1", 0).unwrap();
    fs.quiesce().unwrap();
    let sealed1 = writer.force_roll().unwrap().unwrap();
    fs.manifest.write().unwrap().record_sealed_log(sealed1);
    let sum1 = fs.export_summary(storage.as_ref()).unwrap();
    assert_eq!(sum1, "000001.summary");

    // Gen 2:
    let f2 = fs.create_file(1, "f2.txt", 0o644).unwrap();
    fs.write_at(f2, b"data 2", 0).unwrap();
    fs.quiesce().unwrap();
    let sealed2 = writer.force_roll().unwrap().unwrap();
    fs.manifest.write().unwrap().record_sealed_log(sealed2);
    let sum2 = fs.export_summary(storage.as_ref()).unwrap();
    assert_eq!(sum2, "000002.summary");

    // Gen 3:
    let f3 = fs.create_file(1, "f3.txt", 0o644).unwrap();
    fs.write_at(f3, b"data 3", 0).unwrap();
    fs.quiesce().unwrap();
    let sealed3 = writer.force_roll().unwrap().unwrap();
    fs.manifest.write().unwrap().record_sealed_log(sealed3);
    let sum3 = fs.export_summary(storage.as_ref()).unwrap();
    assert_eq!(sum3, "000003.summary");

    // Storage now has 000000.summary, 000001.summary, 000002.summary, and 000003.summary
    assert!(storage.exists("000000.summary"));
    assert!(storage.exists("000001.summary"));
    assert!(storage.exists("000002.summary"));
    assert!(storage.exists("000003.summary"));

    fs.log_cache = Some(Arc::new(LogFileCache::with_storage(storage.clone())));
    let fs_arc = Arc::new(fs);

    let mock_remote = Arc::new(MockRemoteStore::new());
    let mut registry = RemoteRegistry::new();
    registry.add_remote("mock", RemoteTargetConfig::new("test-bucket"));
    registry.set_store_override("mock", mock_remote.clone());
    let registry_arc = Arc::new(std::sync::RwLock::new(registry));

    appendfs::remote::RemoteReplicationWorker::drain_on_shutdown(&fs_arc, &registry_arc).unwrap();

    // Verify remote received ONLY the latest summary (000003.summary) and latest log (000003.log)
    assert!(mock_remote.head_object("000000.summary").unwrap().is_none());
    assert!(mock_remote.head_object("000001.summary").unwrap().is_none());
    assert!(mock_remote.head_object("000002.summary").unwrap().is_none());
    assert!(mock_remote.head_object("000003.summary").unwrap().is_some());
    assert!(mock_remote.head_object("000001.log").unwrap().is_none());
    assert!(mock_remote.head_object("000002.log").unwrap().is_none());
    assert!(mock_remote.head_object("000003.log").unwrap().is_some());
}

#[test]
fn test_worker_syncs_only_latest_summary_cross_copy() {
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let clock = Arc::new(SystemClock);

    let TestFs { mut fs, .. } = TestFs::builder()
        .storage(storage.clone())
        .clock(clock.clone())
        .max_log_size(1024 * 1024)
        .build();
    let writer = fs.log_writer.clone().unwrap();

    let f1 = fs.create_file(1, "f1.txt", 0o644).unwrap();
    fs.write_at(f1, b"data 1", 0).unwrap();
    fs.quiesce().unwrap();
    let sealed1 = writer.force_roll().unwrap().unwrap();
    fs.manifest.write().unwrap().record_sealed_log(sealed1);
    let sum1 = fs.export_summary(storage.as_ref()).unwrap();

    let f2 = fs.create_file(1, "f2.txt", 0o644).unwrap();
    fs.write_at(f2, b"data 2", 0).unwrap();
    fs.quiesce().unwrap();
    let sealed2 = writer.force_roll().unwrap().unwrap();
    fs.manifest.write().unwrap().record_sealed_log(sealed2);
    let sum2 = fs.export_summary(storage.as_ref()).unwrap();

    // Populate remote1 with 000001.summary and 000002.summary
    let remote1 = Arc::new(MockRemoteStore::new());
    let remote2 = Arc::new(MockRemoteStore::new());

    upload_storage_file(storage.as_ref(), remote1.as_ref(), &sum1, None).unwrap();
    upload_storage_file(storage.as_ref(), remote1.as_ref(), &sum2, None).unwrap();

    // Remove summaries from local storage so remote2 must cross-copy from remote1
    storage.remove_file(&sum1).unwrap();
    storage.remove_file(&sum2).unwrap();
    assert!(!storage.exists(&sum1));
    assert!(!storage.exists(&sum2));

    fs.log_cache = Some(Arc::new(LogFileCache::with_storage(storage.clone())));
    let fs_arc = Arc::new(fs);

    let mut registry = RemoteRegistry::new();
    registry.add_remote("r1", RemoteTargetConfig::new("bucket-1"));
    registry.set_store_override("r1", remote1.clone());
    registry.add_remote("r2", RemoteTargetConfig::new("bucket-2"));
    registry.set_store_override("r2", remote2.clone());
    let registry_arc = Arc::new(std::sync::RwLock::new(registry));

    // Drain on shutdown: should cross-copy ONLY the latest summary (000002.summary), skipping older 000001.summary
    appendfs::remote::RemoteReplicationWorker::drain_on_shutdown(&fs_arc, &registry_arc).unwrap();

    // Remote 2 must cross-copy ONLY the latest summary (000002.summary), skipping older 000001.summary
    assert!(remote2.head_object(&sum1).unwrap().is_none());
    assert!(remote2.head_object(&sum2).unwrap().is_some());
}

#[test]
fn test_replication_worker_active_round_interrupted_on_stop() {
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let clock = Arc::new(SystemClock);

    let TestFs { mut fs, .. } = TestFs::builder()
        .storage(storage.clone())
        .clock(clock.clone())
        .max_log_size(1024 * 1024)
        .build();
    let writer = fs.log_writer.clone().unwrap();

    // Create 3 sealed logs
    for i in 1..=3 {
        let file = fs.create_file(1, &format!("f{}.txt", i), 0o644).unwrap();
        fs.write_at(file, &[b'X'; 50000], 0).unwrap();
        fs.quiesce().unwrap();
        let sealed = writer.force_roll().unwrap().unwrap();
        fs.manifest.write().unwrap().record_sealed_log(sealed);
    }
    fs.export_summary(storage.as_ref()).unwrap();
    fs.log_cache = Some(Arc::new(LogFileCache::with_storage(storage.clone())));
    let fs_arc = Arc::new(fs);

    // Setup a remote with LatencyRemoteStore so replication takes time
    let raw_mock = Arc::new(MockRemoteStore::new());
    let latency_remote = Arc::new(LatencyRemoteStore::new(raw_mock.clone()));
    latency_remote.set_fixed_delay(std::time::Duration::from_millis(100));

    let mut registry = RemoteRegistry::new();
    registry.add_remote("latency", RemoteTargetConfig::new("test-bucket"));
    registry.set_store_override("latency", latency_remote);
    let registry_arc = Arc::new(std::sync::RwLock::new(registry));

    // Start background replication worker
    let mut worker = appendfs::remote::RemoteReplicationWorker::start_with_interval(
        fs_arc.clone(),
        registry_arc.clone(),
        Path::new("/unused").to_path_buf(),
        std::time::Duration::from_secs(10),
    );

    // Immediately stop the worker while replication is in-flight
    let start_stop = std::time::Instant::now();
    worker.stop();
    let stop_duration = start_stop.elapsed();

    // worker.stop() should return promptly rather than hanging for seconds/minutes
    assert!(
        stop_duration < std::time::Duration::from_secs(3),
        "worker.stop() must interrupt and return promptly"
    );

    // Since there was a backlog of 3 files, the shutdown drain also should not have transferred all 3 files
    let remote_objs = raw_mock.list_objects("").unwrap();
    assert!(
        remote_objs.len() < 4,
        "Active round must have been interrupted without completing the entire backlog"
    );
}

fn read_storage_file(storage: &dyn Storage, name: &str) -> Vec<u8> {
    let r = storage.open_reader(name).unwrap();
    let mut b = vec![0u8; r.len().unwrap() as usize];
    r.read_exact_at(0, &mut b).unwrap();
    b
}

#[test]
fn test_pre_synced_remote_reflects_up_to_date_status_without_lockstep_lag() {
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let mock_time = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
    let clock = Arc::new(appendfs::clock::MockClock(mock_time));

    // Create 5 sealed log generations (1..=5) and active generation 6
    let TestFs { mut fs, .. } = TestFs::builder()
        .storage(storage.clone())
        .clock(clock.clone())
        .max_log_size(1024 * 1024)
        .build();
    let writer = fs.log_writer.clone().unwrap();

    let root = 1u64;
    for g in 1..=5 {
        let file_ino = fs.create_file(root, &format!("file_{}.txt", g), 0o644).unwrap();
        fs.write_at(file_ino, format!("Content for gen {}", g).as_bytes(), 0)
            .unwrap();
        fs.quiesce().unwrap();

        let sealed = writer.force_roll().unwrap().unwrap();
        assert_eq!(sealed.generation, g);
        fs.manifest.write().unwrap().record_sealed_log(sealed);
        fs.export_summary(storage.as_ref()).unwrap();
    }

    fs.log_cache = Some(Arc::new(LogFileCache::with_storage(storage.clone())));
    let fs_arc = Arc::new(fs);

    // Setup two remotes:
    // 1. aws-glacier: Write-Only archive, only holds generations 1 and 2
    // 2. gcs-netherlands: Read-Write, holds all generations 1..5 (synced in previous run)
    let glacier_raw = Arc::new(MockRemoteStore::new());
    let gcs_raw = Arc::new(MockRemoteStore::new());

    // Pre-populate gcs-netherlands with all 5 generations and summaries
    for g in 1..=5 {
        let log_file = format!("{:06}.log", g);
        let bytes = read_storage_file(storage.as_ref(), &log_file);
        let md5: [u8; 16] = *md5::compute(&bytes);
        gcs_raw
            .put_object(
                &log_file,
                &mut std::io::Cursor::new(&bytes),
                bytes.len() as u64,
                Some(&md5),
            )
            .unwrap();

        let sum_file = format!("{:06}.summary", g);
        if storage.exists(&sum_file) {
            let sum_bytes = read_storage_file(storage.as_ref(), &sum_file);
            let sum_md5: [u8; 16] = *md5::compute(&sum_bytes);
            gcs_raw
                .put_object(
                    &sum_file,
                    &mut std::io::Cursor::new(&sum_bytes),
                    sum_bytes.len() as u64,
                    Some(&sum_md5),
                )
                .unwrap();
        }
    }
    if storage.exists("000000.summary") {
        let b = read_storage_file(storage.as_ref(), "000000.summary");
        let m: [u8; 16] = *md5::compute(&b);
        gcs_raw
            .put_object(
                "000000.summary",
                &mut std::io::Cursor::new(&b),
                b.len() as u64,
                Some(&m),
            )
            .unwrap();
    }

    // Pre-populate aws-glacier with only generations 1 and 2
    for g in 1..=2 {
        let log_file = format!("{:06}.log", g);
        let bytes = read_storage_file(storage.as_ref(), &log_file);
        let md5: [u8; 16] = *md5::compute(&bytes);
        glacier_raw
            .put_object(
                &log_file,
                &mut std::io::Cursor::new(&bytes),
                bytes.len() as u64,
                Some(&md5),
            )
            .unwrap();
    }

    // Inject failure on aws-glacier so it fails all uploads and remains stuck at gen 2 during replication
    let glacier_failing = Arc::new(FailingRemoteStore::new(glacier_raw.clone()));
    glacier_failing.fail_method("put_object");

    let mut registry = RemoteRegistry::new();
    let mut glacier_cfg = RemoteTargetConfig::new("appendfs-glacier-bucket");
    glacier_cfg.mode = RemoteMode::WriteOnly;
    registry.add_remote("aws-glacier", glacier_cfg);
    registry.set_store_override("aws-glacier", glacier_failing);

    let mut gcs_cfg = RemoteTargetConfig::new("appendfs-remote");
    gcs_cfg.mode = RemoteMode::ReadWrite;
    registry.add_remote("gcs-netherlands", gcs_cfg);
    registry.set_store_override("gcs-netherlands", gcs_raw);

    let registry_arc = Arc::new(std::sync::RwLock::new(registry));
    fs_arc.set_remote_registry(registry_arc.clone());

    // Run replication cycle
    let mut last_part_sync = std::time::SystemTime::UNIX_EPOCH;
    let mut uploaded_parts = std::collections::HashMap::new();
    appendfs::remote::RemoteReplicationWorker::run_cycle(
        &fs_arc,
        &registry_arc,
        Path::new("/unused"),
        &mut last_part_sync,
        &mut uploaded_parts,
    )
    .unwrap();

    let status = appendfs::remote::worker::format_remotes_status(&fs_arc);

    // Verify gcs-netherlands is NOT held back at generation 2:
    // It must report Up to date, 5 / 5 synced generations, and 0 lag!
    assert!(status.contains("[Remote: gcs-netherlands]"));
    assert!(status.contains(
        "Status:             Up to date\n  Synced Generation:  5 / 5\n  Replication Lag:    0 sealed generation(s)"
    ));

    // Verify aws-glacier accurately reports its lag and error without corrupting gcs-netherlands:
    assert!(status.contains("[Remote: aws-glacier]"));
    assert!(status.contains("Status:             Syncing (Archive)\n  Synced Generation:  2 / 5\n  Replication Lag:    3 sealed generation(s)"));
    assert!(status.contains("Last Error:"));
}

#[test]
fn test_prioritized_replication_rw_and_low_lag_replicates_before_archive_backlog() {
    use appendfs::remote::RemoteObject;
    use std::sync::Mutex;

    #[derive(Debug)]
    struct OrderTrackingStore {
        inner: Arc<MockRemoteStore>,
        name: String,
        ops: Arc<Mutex<Vec<String>>>,
    }

    impl RemoteStore for OrderTrackingStore {
        fn list_objects(&self, prefix: &str) -> std::io::Result<Vec<RemoteObject>> {
            self.inner.list_objects(prefix)
        }
        fn head_object(&self, key: &str) -> std::io::Result<Option<RemoteObject>> {
            self.inner.head_object(key)
        }
        fn put_object(
            &self,
            key: &str,
            reader: &mut dyn std::io::Read,
            len: u64,
            content_md5: Option<&[u8; 16]>,
        ) -> std::io::Result<()> {
            self.ops.lock().unwrap().push(format!("{}: {}", self.name, key));
            self.inner.put_object(key, reader, len, content_md5)
        }
        fn get_object(&self, key: &str, writer: &mut dyn std::io::Write) -> std::io::Result<u64> {
            self.inner.get_object(key, writer)
        }
        fn get_object_range(
            &self,
            key: &str,
            offset: u64,
            len: u64,
            writer: &mut dyn std::io::Write,
        ) -> std::io::Result<u64> {
            self.inner.get_object_range(key, offset, len, writer)
        }
        fn delete_object(&self, key: &str) -> std::io::Result<()> {
            self.inner.delete_object(key)
        }
    }

    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let mock_time = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
    let clock = Arc::new(appendfs::clock::MockClock(mock_time));

    // Create 4 sealed log generations (1..=4) and active generation 5
    let TestFs { mut fs, .. } = TestFs::builder()
        .storage(storage.clone())
        .clock(clock.clone())
        .max_log_size(1024 * 1024)
        .build();
    let writer = fs.log_writer.clone().unwrap();

    let root = 1u64;
    for g in 1..=4 {
        let file_ino = fs.create_file(root, &format!("f_{}.txt", g), 0o644).unwrap();
        fs.write_at(file_ino, format!("Content {}", g).as_bytes(), 0).unwrap();
        fs.quiesce().unwrap();

        let sealed = writer.force_roll().unwrap().unwrap();
        assert_eq!(sealed.generation, g);
        fs.manifest.write().unwrap().record_sealed_log(sealed);
        fs.export_summary(storage.as_ref()).unwrap();
    }

    fs.log_cache = Some(Arc::new(LogFileCache::with_storage(storage.clone())));
    let fs_arc = Arc::new(fs);

    // Setup:
    // gcs-netherlands (ReadWrite): missing ONLY generation 4 (lag 1)
    // aws-glacier (WriteOnly): missing generations 2, 3, 4 (lag 3)
    let gcs_raw = Arc::new(MockRemoteStore::new());
    for g in 1..=3 {
        let log_file = format!("{:06}.log", g);
        let bytes = read_storage_file(storage.as_ref(), &log_file);
        let md5: [u8; 16] = *md5::compute(&bytes);
        gcs_raw
            .put_object(
                &log_file,
                &mut std::io::Cursor::new(&bytes),
                bytes.len() as u64,
                Some(&md5),
            )
            .unwrap();
    }

    let glacier_raw = Arc::new(MockRemoteStore::new());
    let log_file = format!("{:06}.log", 1);
    let bytes = read_storage_file(storage.as_ref(), &log_file);
    let md5: [u8; 16] = *md5::compute(&bytes);
    glacier_raw
        .put_object(
            &log_file,
            &mut std::io::Cursor::new(&bytes),
            bytes.len() as u64,
            Some(&md5),
        )
        .unwrap();

    let ops = Arc::new(Mutex::new(Vec::new()));
    let gcs_tracking = Arc::new(OrderTrackingStore {
        inner: gcs_raw.clone(),
        name: "gcs".to_string(),
        ops: ops.clone(),
    });
    let glacier_tracking = Arc::new(OrderTrackingStore {
        inner: glacier_raw.clone(),
        name: "glacier".to_string(),
        ops: ops.clone(),
    });

    let mut registry = RemoteRegistry::new();
    let mut glacier_cfg = RemoteTargetConfig::new("glacier-bucket");
    glacier_cfg.mode = RemoteMode::WriteOnly;
    registry.add_remote("aws-glacier", glacier_cfg);
    registry.set_store_override("aws-glacier", glacier_tracking);

    let mut gcs_cfg = RemoteTargetConfig::new("gcs-bucket");
    gcs_cfg.mode = RemoteMode::ReadWrite;
    registry.add_remote("gcs-netherlands", gcs_cfg);
    registry.set_store_override("gcs-netherlands", gcs_tracking);

    let registry_arc = Arc::new(std::sync::RwLock::new(registry));
    fs_arc.set_remote_registry(registry_arc.clone());

    let mut last_part_sync = std::time::SystemTime::UNIX_EPOCH;
    let mut uploaded_parts = std::collections::HashMap::new();
    appendfs::remote::RemoteReplicationWorker::run_cycle(
        &fs_arc,
        &registry_arc,
        Path::new("/unused"),
        &mut last_part_sync,
        &mut uploaded_parts,
    )
    .unwrap();

    let recorded = ops.lock().unwrap().clone();
    // gcs (ReadWrite, lag 1) must sync 000004.log BEFORE glacier (WriteOnly, lag 3) syncs 000002.log
    let gcs_first_log = recorded
        .iter()
        .position(|op| op == "gcs: 000004.log")
        .expect("gcs must upload 000004.log");
    let glacier_first_log = recorded
        .iter()
        .position(|op| op == "glacier: 000002.log")
        .expect("glacier must upload 000002.log");
    assert!(
        gcs_first_log < glacier_first_log,
        "ReadWrite remote with lowest lag must replicate before WriteOnly archive remote backlog: {:?}",
        recorded
    );

    // Both remotes should now be fully up-to-date!
    let status = appendfs::remote::worker::format_remotes_status(&fs_arc);
    assert!(status.contains("[Remote: gcs-netherlands]\n  Target:             s3 (bucket: gcs-bucket, prefix: )\n  Read Priority:      100\n  Mode:               Read-Write\n  Partial Logs:       Enabled\n  Status:             Up to date\n  Synced Generation:  4 / 4\n  Replication Lag:    0 sealed generation(s)"));
    assert!(status.contains("[Remote: aws-glacier]\n  Target:             s3 (bucket: glacier-bucket, prefix: )\n  Read Priority:      100\n  Mode:               Write-Only\n  Partial Logs:       Disabled\n  Status:             Up to date (Archive)\n  Synced Generation:  4 / 4\n  Replication Lag:    0 sealed generation(s)"));
}
