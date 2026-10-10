use appendfs::TestFs;
use appendfs::clock::MockClock;
use appendfs::error::FsError;
use appendfs::operations::dir::{
    lookup_response, mkdir_response, opendir_response, releasedir_response, rmdir_response,
};
use appendfs::operations::links::{
    link_response, readlink_response, rename_response, symlink_response, unlink_response,
};
use appendfs::operations::locks::getlk_response;
use appendfs::operations::read_write::{
    create_response, fallocate_response, getattr_response, open_response, read_response, release_response,
    setattr_response, write_response,
};
use appendfs::operations::special::mknod_response;
use appendfs::operations::statfs::statfs_response;
use appendfs::operations::xattr::{getxattr_response, listxattr_response, removexattr_response, setxattr_response};
use appendfs::shim::{
    DeferredResult, DeferredToken, FileAttr, FileType, Filesystem, FuseResponse, ReplyData, RequestContext, ShimFlock,
    StatfsAttr,
};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

fn mock_time() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

#[test]
fn test_reply_data_conversions() {
    let slice: &[u8] = b"hello";
    let borrowed: ReplyData = slice.into();
    assert_eq!(&*borrowed, b"hello");
    assert_eq!(borrowed.as_slice(), b"hello");

    let vec = vec![1, 2, 3];
    let owned: ReplyData = vec.into();
    assert_eq!(&*owned, &[1, 2, 3]);
    assert_eq!(owned.as_slice(), &[1, 2, 3]);

    let cloned = borrowed.to_owned();
    assert_eq!(cloned.as_slice(), b"hello");
}

#[test]
fn test_fuse_response_constructors() {
    let now = mock_time();
    let attr = FileAttr {
        ino: 42,
        file_type: FileType::RegularFile,
        perm: 0o644,
        nlink: 1,
        uid: 1000,
        gid: 1000,
        rdev: 0,
        size: 100,
        atime: now,
        mtime: now,
        ctime: now,
    };

    // ok
    assert_eq!(FuseResponse::ok(), FuseResponse::Ok);

    // entry
    let entry = FuseResponse::entry(attr);
    assert_eq!(entry, FuseResponse::Entry(attr));

    // attr
    let attr_resp = FuseResponse::attr(attr);
    assert_eq!(attr_resp, FuseResponse::Attr(attr));

    // open
    let open = FuseResponse::open(7, /* direct_io = */ true, /* keep_cache = */ false);
    assert_eq!(
        open,
        FuseResponse::Open {
            fh: 7,
            direct_io: true,
            keep_cache: false
        }
    );

    // write
    let write = FuseResponse::write(128);
    assert_eq!(write, FuseResponse::Write(128));

    // create
    let create = FuseResponse::create(attr, 9);
    assert_eq!(create, FuseResponse::Create { attr, fh: 9 });

    // buf
    let buf = FuseResponse::buf(b"test".as_slice());
    assert_eq!(buf, FuseResponse::Buf(ReplyData::Borrowed(b"test")));

    // readlink
    let readlink = FuseResponse::readlink("target");
    assert_eq!(readlink, FuseResponse::Readlink("target".to_string()));

    // statfs
    let stat = StatfsAttr {
        blocks: 100,
        bfree: 80,
        bavail: 80,
        files: 50,
        ffree: 40,
        bsize: 4096,
        namelen: 255,
    };
    let statfs = FuseResponse::statfs(stat);
    assert_eq!(statfs, FuseResponse::Statfs(stat));

    // lock
    let flock = ShimFlock {
        lock_type: libc::F_WRLCK as i16,
        whence: libc::SEEK_SET as i16,
        start: 0,
        len: 10,
        pid: 1234,
    };
    let lock = FuseResponse::lock(flock);
    assert_eq!(lock, FuseResponse::Lock(flock));

    // xattr_size
    let xattr_size = FuseResponse::xattr_size(64);
    assert_eq!(xattr_size, FuseResponse::XattrSize(64));

    // to_static
    let static_buf = buf.to_static();
    assert_eq!(static_buf, FuseResponse::Buf(ReplyData::Owned(b"test".to_vec())));
}

#[test]
fn test_all_fuse_response_handlers() {
    let clock = Arc::new(MockClock(mock_time()));
    let fs = TestFs::builder().clock(clock).build().fs;

    // 1. getattr
    let attr_res = getattr_response(&fs, 1);
    assert!(matches!(attr_res, Ok(FuseResponse::Attr(..))));

    // 2. lookup
    let lookup_res = lookup_response(&fs, 1, ".");
    assert!(matches!(lookup_res, Ok(FuseResponse::Entry(..))));

    // 3. opendir
    let opendir_res = opendir_response(&fs, 1, 0);
    assert!(matches!(opendir_res, Ok(FuseResponse::Open { .. })));
    let dir_fh = match opendir_res.unwrap() {
        FuseResponse::Open { fh, .. } => fh,
        _ => unreachable!(),
    };

    // 4. releasedir
    let releasedir_res = releasedir_response(&fs, 1, dir_fh);
    assert_eq!(releasedir_res, Ok(FuseResponse::ok()));

    // 6. mkdir
    let ctx = RequestContext::new(1000, 1000, 0);
    let mkdir_res = mkdir_response(&fs, ctx, 1, "testdir", 0o755);
    assert!(matches!(mkdir_res, Ok(FuseResponse::Entry(..))));

    // 7. create file
    let create_res = create_response(
        &fs,
        ctx,
        1,
        "testfile.txt",
        0o644,
        (libc::O_CREAT | libc::O_RDWR) as u32,
    );
    assert!(matches!(create_res, Ok(FuseResponse::Create { .. })));
    let (file_ino, file_fh) = match create_res.unwrap() {
        FuseResponse::Create { attr, fh, .. } => (attr.ino, fh),
        _ => unreachable!(),
    };

    // 8. open file
    let open_res = open_response(&fs, file_ino, libc::O_RDONLY as u32);
    assert!(matches!(open_res, Ok(FuseResponse::Open { .. })));

    // 9. write
    let write_res = write_response(&fs, file_ino, file_fh, b"hello world", 0);
    assert_eq!(write_res, Ok(FuseResponse::write(11)));

    // 10. read
    let read_res = read_response(&fs, file_ino, file_fh, 0, 11);
    assert_eq!(read_res.wait(), Ok(FuseResponse::buf(b"hello world".as_slice())));

    // 11. getlk
    let lock_query = ShimFlock {
        lock_type: libc::F_WRLCK as i16,
        whence: libc::SEEK_SET as i16,
        start: 0,
        len: 100,
        pid: 0,
    };
    let getlk_res = getlk_response(&fs, file_ino, file_fh, 1, lock_query);
    assert!(matches!(getlk_res, Ok(FuseResponse::Lock(..))));

    // 12. release file
    let release_res = release_response(&fs, file_ino, file_fh);
    assert_eq!(release_res, Ok(FuseResponse::ok()));

    // 12. setattr
    let now = mock_time();
    let setattr_res = setattr_response(&fs, file_ino, 0o777, 1001, 1001, 11, now, now, 0o7777);
    assert!(matches!(setattr_res, Ok(FuseResponse::Attr(..))));

    // 13. fallocate
    let falloc_res = fallocate_response(&fs, file_ino, 0, 0, 1024);
    assert_eq!(falloc_res, Ok(FuseResponse::ok()));

    // 14. mknod
    let mknod_res = mknod_response(&fs, ctx, 1, "fifo_node", libc::S_IFIFO | 0o644, 0);
    assert!(matches!(mknod_res, Ok(FuseResponse::Entry(..))));

    // 15. xattr
    let setxattr_res = setxattr_response(&fs, file_ino, "user.test", b"val", 0);
    assert_eq!(setxattr_res, Ok(FuseResponse::ok()));

    let getxattr_res = getxattr_response(&fs, file_ino, "user.test", 100);
    assert_eq!(getxattr_res, Ok(FuseResponse::buf(b"val".as_slice())));

    let getxattr_size_res = getxattr_response(&fs, file_ino, "user.test", 0);
    assert_eq!(getxattr_size_res, Ok(FuseResponse::xattr_size(3)));

    let listxattr_res = listxattr_response(&fs, file_ino, 100);
    assert!(matches!(listxattr_res, Ok(FuseResponse::Buf(..))));

    let listxattr_size_res = listxattr_response(&fs, file_ino, 0);
    assert!(matches!(listxattr_size_res, Ok(FuseResponse::XattrSize(..))));

    let removexattr_res = removexattr_response(&fs, file_ino, "user.test");
    assert_eq!(removexattr_res, Ok(FuseResponse::ok()));

    // 16. symlink & readlink
    let sym_res = symlink_response(&fs, ctx, "target_path", 1, "mysym");
    assert!(matches!(sym_res, Ok(FuseResponse::Entry(..))));
    let sym_ino = match sym_res.as_ref().unwrap() {
        FuseResponse::Entry(a, ..) => a.ino,
        _ => unreachable!(),
    };

    let readlink_res = readlink_response(&fs, sym_ino);
    assert_eq!(readlink_res, Ok(FuseResponse::readlink("target_path")));

    // 17. link
    let link_res = link_response(&fs, file_ino, 1, "hardlink.txt");
    assert!(matches!(link_res, Ok(FuseResponse::Entry(..))));

    // 18. rename
    let rename_res = rename_response(&fs, 1, "hardlink.txt", 1, "renamed.txt");
    assert_eq!(rename_res, Ok(FuseResponse::ok()));

    // 19. unlink
    let unlink_res = unlink_response(&fs, 1, "renamed.txt");
    assert_eq!(unlink_res, Ok(FuseResponse::ok()));

    // 20. statfs
    let statfs_res = statfs_response(&fs, 1);
    assert!(matches!(statfs_res, Ok(FuseResponse::Statfs(..))));

    // 21. rmdir
    let rmdir_res = rmdir_response(&fs, 1, "testdir");
    assert_eq!(rmdir_res, Ok(FuseResponse::ok()));
}

#[test]
fn test_deferred_result_mechanics() {
    use std::sync::atomic::{AtomicBool, Ordering};

    // 1. Ready result ok
    let ready_ok: DeferredResult<FuseResponse<'static>> = DeferredResult::ok(FuseResponse::ok());
    assert!(ready_ok.is_ready());
    assert!(!ready_ok.is_deferred());
    assert_eq!(ready_ok.into_ready(), Some(Ok(FuseResponse::ok())));

    // 2. Ready result err
    let ready_err: DeferredResult<FuseResponse<'static>> = DeferredResult::err(FsError::EACCES);
    assert!(ready_err.is_ready());
    assert_eq!(ready_err.into_ready(), Some(Err(FsError::EACCES)));

    // 3. on_complete for ready result runs synchronously
    let ran = Arc::new(AtomicBool::new(false));
    let ran_clone = Arc::clone(&ran);
    let ready = DeferredResult::ok(FuseResponse::write(42));
    ready.on_complete(Box::new(move |res| {
        assert_eq!(res, Ok(FuseResponse::write(42)));
        ran_clone.store(true, Ordering::SeqCst);
    }));
    assert!(ran.load(Ordering::SeqCst));

    // 4. DeferredToken and DeferredReceiver (immediate completion)
    let (_token0, receiver0) = DeferredToken::<FuseResponse<'static>>::new();
    let deferred0 = DeferredResult::deferred(receiver0);
    assert_eq!(deferred0.into_ready(), None);

    let (token, receiver) = DeferredToken::new();
    let deferred = DeferredResult::deferred(receiver);
    assert!(!deferred.is_ready());
    assert!(deferred.is_deferred());

    token.complete(Ok(FuseResponse::ok()));
    assert_eq!(deferred.wait(), Ok(FuseResponse::ok()));

    // 5. DeferredToken dropped -> cancels with ECANCELED
    let (token2, receiver2) = DeferredToken::<FuseResponse<'static>>::new();
    let deferred2 = DeferredResult::deferred(receiver2);
    drop(token2);
    assert_eq!(deferred2.wait(), Err(FsError::ECANCELED));

    // 6. Callback registered before token completion
    let (token3, receiver3) = DeferredToken::new();
    let deferred3 = DeferredResult::deferred(receiver3);
    let cb_called = Arc::new(AtomicBool::new(false));
    let cb_called_clone = Arc::clone(&cb_called);
    deferred3.on_complete(Box::new(move |res| {
        assert_eq!(res, Ok(FuseResponse::write(100)));
        cb_called_clone.store(true, Ordering::SeqCst);
    }));
    assert!(!cb_called.load(Ordering::SeqCst));
    token3.complete(Ok(FuseResponse::write(100)));
    assert!(cb_called.load(Ordering::SeqCst));

    // 7. Callback registered after token completion
    let (token4, receiver4) = DeferredToken::new();
    let deferred4 = DeferredResult::deferred(receiver4);
    token4.complete(Ok(FuseResponse::ok()));
    let cb_called2 = Arc::new(AtomicBool::new(false));
    let cb_called2_clone = Arc::clone(&cb_called2);
    deferred4.on_complete(Box::new(move |res| {
        assert_eq!(res, Ok(FuseResponse::ok()));
        cb_called2_clone.store(true, Ordering::SeqCst);
    }));
    assert!(cb_called2.load(Ordering::SeqCst));

    // 8. wait() blocks while token completes asynchronously on another thread
    let (token5, receiver5) = DeferredToken::new();
    let deferred5 = DeferredResult::deferred(receiver5);
    let handle = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(10));
        token5.complete(Ok(FuseResponse::write(999)));
    });
    let res = deferred5.wait();
    assert_eq!(res, Ok(FuseResponse::write(999)));
    handle.join().unwrap();
}

#[test]
fn test_filesystem_trait_all_methods() {
    let clock = Arc::new(MockClock(mock_time()));
    let append_fs = TestFs::builder().clock(clock).build().fs;
    let fs: &dyn Filesystem = &append_fs;
    let ctx = RequestContext {
        uid: 1000,
        gid: 1000,
        pid: 1234,
    };

    // 1. mkdir via trait
    let mkdir_res = fs.mkdir(ctx, 1, "dir1", 0o755);
    assert!(matches!(mkdir_res, Ok(FuseResponse::Entry(..))));
    let dir_ino = match mkdir_res.unwrap() {
        FuseResponse::Entry(attr, ..) => attr.ino,
        _ => unreachable!(),
    };

    // 2. lookup via trait
    let lookup_res = fs.lookup(1, "dir1");
    assert!(matches!(lookup_res, Ok(FuseResponse::Entry(..))));

    // 3. getattr via trait
    let getattr_res = fs.getattr(dir_ino);
    assert!(matches!(getattr_res, Ok(FuseResponse::Attr(..))));

    // 4. opendir via trait
    let opendir_res = fs.opendir(dir_ino, 0);
    assert!(matches!(opendir_res, Ok(FuseResponse::Open { .. })));
    let dir_fh = match opendir_res.unwrap() {
        FuseResponse::Open { fh, .. } => fh,
        _ => unreachable!(),
    };

    // 5. readdir and readdirplus via trait
    let readdir_res = fs.readdir(dir_ino, 4096, 0, dir_fh);
    assert!(readdir_res.is_ok());
    let entries = match readdir_res.unwrap() {
        FuseResponse::Readdir { entries, .. } => entries,
        _ => unreachable!(),
    };
    assert!(entries.iter().any(|e| e.name == "."));
    assert!(entries.iter().any(|e| e.name == ".."));

    let readdirplus_res = fs.readdirplus(dir_ino, 4096, 0, dir_fh);
    assert!(readdirplus_res.is_ok());
    let entries_plus = match readdirplus_res.unwrap() {
        FuseResponse::ReaddirPlus { entries, .. } => entries,
        _ => unreachable!(),
    };
    assert!(entries_plus.iter().any(|e| e.name == "."));

    // 6. create via trait
    let create_res = fs.create(ctx, dir_ino, "file1.txt", 0o644, (libc::O_CREAT | libc::O_RDWR) as u32);
    assert!(matches!(create_res, Ok(FuseResponse::Create { .. })));
    let (file_ino, file_fh) = match create_res.unwrap() {
        FuseResponse::Create { attr, fh, .. } => (attr.ino, fh),
        _ => unreachable!(),
    };

    // 7. write via trait
    let write_res = fs.write(file_ino, b"trait test", 0, file_fh);
    assert_eq!(write_res, Ok(FuseResponse::write(10)));

    // 8. read via trait (returns DeferredResult)
    let read_res = fs.read(file_ino, 10, 0, file_fh);
    assert_eq!(read_res.wait(), Ok(FuseResponse::buf(b"trait test".as_slice())));

    // 9. open via trait
    let open_res = fs.open(file_ino, libc::O_RDONLY as u32);
    assert!(matches!(open_res, Ok(FuseResponse::Open { .. })));

    // 10. fsync via trait (returns DeferredResult)
    let fsync_res = fs.fsync(file_ino, false, file_fh);
    assert_eq!(fsync_res.wait(), Ok(FuseResponse::ok()));

    // 11. flock via trait (returns DeferredResult)
    let flock_res = fs.flock(file_ino, file_fh, 1, libc::LOCK_EX);
    assert_eq!(flock_res.wait(), Ok(FuseResponse::ok()));

    let flock_un = fs.flock(file_ino, file_fh, 1, libc::LOCK_UN);
    assert_eq!(flock_un.wait(), Ok(FuseResponse::ok()));

    // 12. getlk and setlk via trait
    let shim_lock = ShimFlock {
        lock_type: libc::F_WRLCK as i16,
        whence: libc::SEEK_SET as i16,
        start: 0,
        len: 10,
        pid: 0,
    };
    let getlk_res = fs.getlk(file_ino, file_fh, 1, shim_lock);
    assert!(matches!(getlk_res, Ok(FuseResponse::Lock(..))));

    let setlk_res = fs.setlk(file_ino, file_fh, 1, shim_lock, false);
    assert_eq!(setlk_res.wait(), Ok(FuseResponse::ok()));

    // 13. xattrs via trait
    let setxattr_res = fs.setxattr(file_ino, "user.trait", b"value", 0);
    assert_eq!(setxattr_res, Ok(FuseResponse::ok()));

    let getxattr_res = fs.getxattr(file_ino, "user.trait", 100);
    assert_eq!(getxattr_res, Ok(FuseResponse::buf(b"value".as_slice())));

    let listxattr_res = fs.listxattr(file_ino, 100);
    assert!(matches!(listxattr_res, Ok(FuseResponse::Buf(..))));

    let removexattr_res = fs.removexattr(file_ino, "user.trait");
    assert_eq!(removexattr_res, Ok(FuseResponse::ok()));

    // 14. setattr via trait
    let now = mock_time();
    let setattr_res = fs.setattr(file_ino, 0o600, 1000, 1000, 10, now, now, 0o7777);
    assert!(matches!(setattr_res, Ok(FuseResponse::Attr(..))));

    // 15. fallocate via trait
    let fallocate_res = fs.fallocate(file_ino, 0, 0, 1024, file_fh);
    assert_eq!(fallocate_res, Ok(FuseResponse::ok()));

    // 16. mknod via trait
    let mknod_res = fs.mknod(ctx, dir_ino, "fifo1", libc::S_IFIFO | 0o644, 0);
    assert!(matches!(mknod_res, Ok(FuseResponse::Entry(..))));

    // 17. symlink and readlink via trait
    let sym_res = fs.symlink(ctx, "target", dir_ino, "sym1");
    assert!(matches!(sym_res, Ok(FuseResponse::Entry(..))));
    let sym_ino = match sym_res.unwrap() {
        FuseResponse::Entry(attr, ..) => attr.ino,
        _ => unreachable!(),
    };
    let readlink_res = fs.readlink(sym_ino);
    assert_eq!(readlink_res, Ok(FuseResponse::readlink("target")));

    // 18. link via trait
    let link_res = fs.link(file_ino, dir_ino, "file1_hard.txt");
    assert!(matches!(link_res, Ok(FuseResponse::Entry(..))));

    // 19. rename via trait
    let rename_res = fs.rename(dir_ino, "file1_hard.txt", dir_ino, "file1_renamed.txt");
    assert_eq!(rename_res, Ok(FuseResponse::ok()));

    // 20. unlink via trait
    let unlink_res = fs.unlink(dir_ino, "file1_renamed.txt");
    assert_eq!(unlink_res, Ok(FuseResponse::ok()));

    // 21. release and releasedir via trait
    let release_res = fs.release(file_ino, file_fh);
    assert_eq!(release_res, Ok(FuseResponse::ok()));

    let releasedir_res = fs.releasedir(dir_ino, dir_fh);
    assert_eq!(releasedir_res, Ok(FuseResponse::ok()));

    // 22. fsyncdir via trait
    let fsyncdir_res = fs.fsyncdir(dir_ino, false);
    assert_eq!(fsyncdir_res.wait(), Ok(FuseResponse::ok()));

    // 23. statfs via trait
    let statfs_res = fs.statfs(1);
    assert!(matches!(statfs_res, Ok(FuseResponse::Statfs(..))));

    // 24. rmdir via trait
    let rmdir_fail = fs.rmdir(1, "dir1");
    assert_eq!(rmdir_fail, Err(FsError::ENOTEMPTY));

    // Cleanup children to allow rmdir
    let _ = fs.unlink(dir_ino, "file1.txt");
    let _ = fs.unlink(dir_ino, "fifo1");
    let _ = fs.unlink(dir_ino, "sym1");
    let rmdir_ok = fs.rmdir(1, "dir1");
    assert_eq!(rmdir_ok, Ok(FuseResponse::ok()));
}

#[test]
fn test_open_cache_flags_and_timeout_delineation() {
    let fs = TestFs::builder().build().fs;

    // Create a regular file
    let ctx = RequestContext::new(1000, 1000, 0);
    let create_res = create_response(&fs, ctx, 1, "test.txt", 0o644, (libc::O_CREAT | libc::O_RDWR) as u32).unwrap();
    let regular_ino = match create_res {
        FuseResponse::Create { attr, .. } => attr.ino,
        _ => panic!("expected FuseResponse::Create"),
    };

    // 1. Regular file open: direct_io = false, keep_cache = true
    let reg_open = open_response(&fs, regular_ino, libc::O_RDONLY as u32).unwrap();
    assert!(
        matches!(
            reg_open,
            FuseResponse::Open {
                direct_io: false,
                keep_cache: true,
                ..
            }
        ),
        "Regular files must have direct_io=false and keep_cache=true"
    );

    // 2. Virtual file open (.status): direct_io = true, keep_cache = false
    let status_ino = fs.lookup_child(1, ".status").expect(".status must exist");
    let virt_open = open_response(&fs, status_ino, libc::O_RDONLY as u32).unwrap();
    assert!(
        matches!(
            virt_open,
            FuseResponse::Open {
                direct_io: true,
                keep_cache: false,
                ..
            }
        ),
        "Virtual files must have direct_io=true and keep_cache=false"
    );

    // 3. Directory open: direct_io = false, keep_cache = false
    let dir_open = opendir_response(&fs, 1, 0).unwrap();
    assert!(
        matches!(
            dir_open,
            FuseResponse::Open {
                direct_io: false,
                keep_cache: false,
                ..
            }
        ),
        "Directory handles must have direct_io=false and keep_cache=false"
    );

    // 4. Timeouts: 1 hour (3600s) for regular inodes, 0.0s for virtual inodes
    assert_eq!(FuseResponse::DEFAULT_TIMEOUT, 3600.0);
    assert_eq!(FuseResponse::timeout_for_ino(1), 3600.0);
    assert_eq!(FuseResponse::timeout_for_ino(regular_ino), 3600.0);
    assert_eq!(FuseResponse::timeout_for_ino(status_ino), 0.0);
}

#[test]
fn test_cold_read_deferred_threadpool_execution() {
    use appendfs::FsTestExt;
    use appendfs::operations::read_write::{create_core, open_core};
    use appendfs::storage::MemoryStorage;

    let storage = Arc::new(MemoryStorage::new());
    let clock = Arc::new(appendfs::clock::SystemClock);
    let mut fs = TestFs::builder()
        .storage(storage.clone())
        .clock(clock.clone())
        .build()
        .fs;

    let file = create_core(&fs, 1, "deferred_read.txt", 0o644, 0, 1000, 1000).unwrap();
    let fh = open_core(&fs, file.ino, libc::O_RDWR as u32).unwrap();
    let payload = b"cold read deferred threadpool test".to_vec();
    fs.write_at(file.ino, &payload, 0).unwrap();

    // 1. In-memory read before flush: must be 100% in-memory and immediately Ready
    let in_mem_res = read_response(&fs, file.ino, fh, 0, payload.len());
    assert!(in_mem_res.is_ready());
    assert_eq!(in_mem_res.wait().unwrap().into_bytes().unwrap(), payload);

    // 2. Flush to disk and clear in-memory decrypted record cache
    fs.quiesce().unwrap();
    fs.log_cache.as_ref().unwrap().decrypted_cache.clear();

    // 3. Cold read with absent pool (default): must execute synchronously and be immediately Ready
    let cold_sync = read_response(&fs, file.ino, fh, 0, payload.len());
    assert!(cold_sync.is_ready());
    assert_eq!(cold_sync.wait().unwrap().into_bytes().unwrap(), payload);

    // 4. Enable read pool, clear cache again, and execute cold read: must be Deferred and executed on ReadThreadPool
    fs.log_cache.as_ref().unwrap().decrypted_cache.clear();
    fs.set_read_parallelism(4);
    fs.enable_read_pool();
    let cold_async = read_response(&fs, file.ino, fh, 0, payload.len());
    assert!(cold_async.is_deferred());

    let final_res = cold_async.wait().unwrap();
    assert_eq!(final_res.into_bytes().unwrap(), payload);
}
