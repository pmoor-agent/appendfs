use crate::fs::{FlockState, InMemoryFS, RangeLock};
use crate::shim::{Request, ShimFlock};
use std::collections::HashSet;
use std::sync::Arc;

pub fn flock(fs: &Arc<InMemoryFS>, req: Request, ino: u64, fh: u64, lock_owner: u64, op: i32) {
    log::trace!("flock(ino={}, fh={}, lock_owner={}, op={})", ino, fh, lock_owner, op);
    let non_blocking = (op & libc::LOCK_NB) != 0;
    if non_blocking {
        match flock_core(fs, ino, fh, lock_owner, op) {
            Ok(()) => req.reply_err(0),
            Err(err) => req.reply_err(err),
        }
        return;
    }

    // Try acquiring non-blocking first (zero context switch or suspension if uncontented)
    let try_op = op | libc::LOCK_NB;
    match flock_core(fs, ino, fh, lock_owner, try_op) {
        Ok(()) => {
            req.reply_err(0);
        }
        Err(libc::EWOULDBLOCK) => {
            let fs_clone = Arc::clone(fs);
            crate::async_runtime::spawn(async move {
                let res = tokio::task::spawn_blocking(move || flock_core(&fs_clone, ino, fh, lock_owner, op))
                    .await
                    .unwrap_or(Err(libc::EIO));

                match res {
                    Ok(()) => req.reply_err(0),
                    Err(err) => req.reply_err(err),
                }
            });
        }
        Err(err) => {
            req.reply_err(err);
        }
    }
}

pub fn getlk(fs: &InMemoryFS, req: Request, ino: u64, fh: u64, lock_owner: u64, lock: ShimFlock) {
    log::trace!(
        "getlk(ino={}, fh={}, lock_owner={}, lock={:?})",
        ino,
        fh,
        lock_owner,
        lock
    );
    match getlk_core(fs, ino, fh, lock_owner, lock) {
        Ok(reply_lock) => req.reply_lock(&reply_lock),
        Err(err) => req.reply_err(err),
    }
}

pub fn setlk(fs: &Arc<InMemoryFS>, req: Request, ino: u64, fh: u64, lock_owner: u64, lock: ShimFlock, sleep: bool) {
    log::trace!(
        "setlk(ino={}, fh={}, lock_owner={}, lock={:?}, sleep={})",
        ino,
        fh,
        lock_owner,
        lock,
        sleep
    );
    if !sleep {
        match setlk_core(fs, ino, fh, lock_owner, lock, false) {
            Ok(()) => req.reply_err(0),
            Err(err) => req.reply_err(err),
        }
        return;
    }

    // Blocking POSIX lock (F_SETLKW): try non-blocking inline first (zero context switch if uncontented)
    match setlk_core(fs, ino, fh, lock_owner, lock, false) {
        Ok(()) => {
            req.reply_err(0);
        }
        Err(libc::EWOULDBLOCK) => {
            let fs_clone = Arc::clone(fs);
            crate::async_runtime::spawn(async move {
                let res = tokio::task::spawn_blocking(move || setlk_core(&fs_clone, ino, fh, lock_owner, lock, true))
                    .await
                    .unwrap_or(Err(libc::EIO));

                match res {
                    Ok(()) => req.reply_err(0),
                    Err(err) => req.reply_err(err),
                }
            });
        }
        Err(err) => {
            req.reply_err(err);
        }
    }
}

pub fn flock_core(fs: &InMemoryFS, ino: u64, fh: u64, _lock_owner: u64, op: i32) -> Result<(), i32> {
    // 1. Verify file handle is valid and matches inode
    let handle = fs.get_file_handle(fh).ok_or(libc::EBADF)?;
    if handle.ino != ino {
        return Err(libc::EBADF);
    }

    // 2. Extract operation flags
    let non_blocking = (op & libc::LOCK_NB) != 0;
    let base_op = op & !libc::LOCK_NB;

    let mut table = fs.flock_table.lock().unwrap();
    match base_op {
        libc::LOCK_SH => loop {
            match table.get_mut(&ino) {
                None => {
                    let mut set = HashSet::new();
                    set.insert(fh);
                    table.insert(ino, FlockState::Shared(set));
                    fs.flock_cond.notify_all();
                    return Ok(());
                }
                Some(FlockState::Shared(set)) => {
                    set.insert(fh);
                    return Ok(());
                }
                Some(FlockState::Exclusive(holder)) => {
                    if *holder == fh {
                        // Downgrade exclusive -> shared
                        let mut set = HashSet::new();
                        set.insert(fh);
                        table.insert(ino, FlockState::Shared(set));
                        fs.flock_cond.notify_all();
                        return Ok(());
                    } else if non_blocking {
                        return Err(libc::EWOULDBLOCK);
                    } else {
                        table = fs.flock_cond.wait(table).unwrap();
                    }
                }
            }
        },
        libc::LOCK_EX => loop {
            match table.get_mut(&ino) {
                None => {
                    table.insert(ino, FlockState::Exclusive(fh));
                    return Ok(());
                }
                Some(FlockState::Shared(set)) => {
                    if set.len() == 1 && set.contains(&fh) {
                        // Upgrade shared -> exclusive
                        table.insert(ino, FlockState::Exclusive(fh));
                        return Ok(());
                    } else if non_blocking {
                        return Err(libc::EWOULDBLOCK);
                    } else {
                        table = fs.flock_cond.wait(table).unwrap();
                    }
                }
                Some(FlockState::Exclusive(holder)) => {
                    if *holder == fh {
                        // Idempotent re-acquisition by same handle
                        return Ok(());
                    } else if non_blocking {
                        return Err(libc::EWOULDBLOCK);
                    } else {
                        table = fs.flock_cond.wait(table).unwrap();
                    }
                }
            }
        },
        libc::LOCK_UN => {
            if let Some(state) = table.get_mut(&ino) {
                match state {
                    FlockState::Shared(set) => {
                        set.remove(&fh);
                        if set.is_empty() {
                            table.remove(&ino);
                        }
                    }
                    FlockState::Exclusive(holder) => {
                        if *holder == fh {
                            table.remove(&ino);
                        }
                    }
                }
                fs.flock_cond.notify_all();
            }
            Ok(())
        }
        _ => Err(libc::EINVAL),
    }
}

fn normalize_range(fs: &InMemoryFS, ino: u64, lock: &ShimFlock) -> Result<(u64, u64), i32> {
    let start_offset = match lock.whence as i32 {
        libc::SEEK_SET => lock.start,
        libc::SEEK_CUR | libc::SEEK_END => {
            let attr = fs.get_attr(ino).ok_or(libc::ENOENT)?;
            attr.size.saturating_add(lock.start)
        }
        _ => return Err(libc::EINVAL),
    };

    if start_offset < 0 {
        return Err(libc::EINVAL);
    }
    let start = start_offset as u64;

    if lock.len < 0 {
        return Err(libc::EINVAL);
    }

    let end = if lock.len == 0 {
        u64::MAX
    } else {
        start.checked_add(lock.len as u64).ok_or(libc::EINVAL)?
    };

    Ok((start, end))
}

fn ranges_overlap(s1: u64, e1: u64, s2: u64, e2: u64) -> bool {
    std::cmp::max(s1, s2) < std::cmp::min(e1, e2)
}

fn coalesce_ranges(ranges: &mut Vec<RangeLock>) {
    if ranges.len() <= 1 {
        return;
    }
    ranges.sort_by_key(|a| (a.owner, a.lock_type, a.start));
    let mut merged = Vec::with_capacity(ranges.len());
    for r in ranges.drain(..) {
        if let Some(last) = merged.last_mut() {
            let last_lock: &mut RangeLock = last;
            if last_lock.owner == r.owner && last_lock.lock_type == r.lock_type && last_lock.end >= r.start {
                last_lock.end = std::cmp::max(last_lock.end, r.end);
                continue;
            }
        }
        merged.push(r);
    }
    *ranges = merged;
}

pub fn getlk_core(fs: &InMemoryFS, ino: u64, fh: u64, lock_owner: u64, lock: ShimFlock) -> Result<ShimFlock, i32> {
    let handle = fs.get_file_handle(fh).ok_or(libc::EBADF)?;
    if handle.ino != ino {
        return Err(libc::EBADF);
    }

    let (start, end) = normalize_range(fs, ino, &lock)?;
    let req_type = lock.lock_type;

    let table = fs.range_lock_table.lock().unwrap();
    if let Some(ranges) = table.get(&ino) {
        for r in ranges {
            if ranges_overlap(start, end, r.start, r.end)
                && r.owner != lock_owner
                && (req_type == libc::F_WRLCK as i16 || r.lock_type == libc::F_WRLCK as i16)
            {
                let len = if r.end == u64::MAX { 0 } else { (r.end - r.start) as i64 };
                return Ok(ShimFlock {
                    lock_type: r.lock_type,
                    whence: libc::SEEK_SET as i16,
                    start: r.start as i64,
                    len,
                    pid: r.pid,
                });
            }
        }
    }

    // No conflict found
    Ok(ShimFlock {
        lock_type: libc::F_UNLCK as i16,
        whence: lock.whence,
        start: lock.start,
        len: lock.len,
        pid: 0,
    })
}

pub fn setlk_core(
    fs: &InMemoryFS,
    ino: u64,
    fh: u64,
    lock_owner: u64,
    lock: ShimFlock,
    sleep: bool,
) -> Result<(), i32> {
    let handle = fs.get_file_handle(fh).ok_or(libc::EBADF)?;
    if handle.ino != ino {
        return Err(libc::EBADF);
    }

    let (start, end) = normalize_range(fs, ino, &lock)?;
    let req_type = lock.lock_type;

    let mut table = fs.range_lock_table.lock().unwrap();

    if req_type == libc::F_RDLCK as i16 || req_type == libc::F_WRLCK as i16 {
        loop {
            let ranges = table.entry(ino).or_default();

            // 1. Check for conflicts with other owners
            let mut conflict = false;
            for r in ranges.iter() {
                if r.owner != lock_owner
                    && ranges_overlap(start, end, r.start, r.end)
                    && (req_type == libc::F_WRLCK as i16 || r.lock_type == libc::F_WRLCK as i16)
                {
                    conflict = true;
                    break;
                }
            }

            if conflict {
                if !sleep {
                    return Err(libc::EWOULDBLOCK);
                } else {
                    table = fs.range_lock_cond.wait(table).unwrap();
                    continue;
                }
            }

            // 2. Remove/modify existing ranges belonging to THIS owner that overlap with [start, end)
            let mut new_ranges = Vec::new();
            for r in ranges.drain(..) {
                if r.owner == lock_owner && ranges_overlap(start, end, r.start, r.end) {
                    if r.start < start {
                        new_ranges.push(RangeLock {
                            lock_type: r.lock_type,
                            start: r.start,
                            end: start,
                            owner: r.owner,
                            pid: r.pid,
                        });
                    }
                    if r.end > end {
                        new_ranges.push(RangeLock {
                            lock_type: r.lock_type,
                            start: end,
                            end: r.end,
                            owner: r.owner,
                            pid: r.pid,
                        });
                    }
                } else {
                    new_ranges.push(r);
                }
            }

            // 3. Add new range lock
            new_ranges.push(RangeLock {
                lock_type: req_type,
                start,
                end,
                owner: lock_owner,
                pid: lock.pid,
            });

            // 4. Coalesce adjacent or overlapping ranges with same owner and lock_type
            coalesce_ranges(&mut new_ranges);
            let ranges_ref = table.entry(ino).or_default();
            *ranges_ref = new_ranges;

            // 5. Notify any other waiting lock requests
            fs.range_lock_cond.notify_all();
            return Ok(());
        }
    } else if req_type == libc::F_UNLCK as i16 {
        let ranges = table.entry(ino).or_default();
        let mut new_ranges = Vec::new();
        for r in ranges.drain(..) {
            if r.owner == lock_owner && ranges_overlap(start, end, r.start, r.end) {
                if r.start < start {
                    new_ranges.push(RangeLock {
                        lock_type: r.lock_type,
                        start: r.start,
                        end: start,
                        owner: r.owner,
                        pid: r.pid,
                    });
                }
                if r.end > end {
                    new_ranges.push(RangeLock {
                        lock_type: r.lock_type,
                        start: end,
                        end: r.end,
                        owner: r.owner,
                        pid: r.pid,
                    });
                }
            } else {
                new_ranges.push(r);
            }
        }
        if new_ranges.is_empty() {
            table.remove(&ino);
        } else {
            *ranges = new_ranges;
        }

        // Notify waiting lock requests that ranges have been unlocked
        fs.range_lock_cond.notify_all();
        Ok(())
    } else {
        Err(libc::EINVAL)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_flock_shared_concurrent_and_exclusive_exclusion() {
        let fs = InMemoryFS::new();
        let attr = crate::operations::read_write::create_core(&fs, 1, "test.txt", 0o644, 0, 1000, 1000).unwrap();
        let ino = attr.ino;

        let fh1 = fs.open_file_handle(ino, libc::O_RDWR as u32);
        let fh2 = fs.open_file_handle(ino, libc::O_RDWR as u32);

        // 1. Both acquire shared lock concurrently
        assert_eq!(flock_core(&fs, ino, fh1, 100, libc::LOCK_SH), Ok(()));
        assert_eq!(flock_core(&fs, ino, fh2, 200, libc::LOCK_SH), Ok(()));

        // 2. Exclusive lock fails with non-blocking while shared locks held
        assert_eq!(
            flock_core(&fs, ino, fh1, 100, libc::LOCK_EX | libc::LOCK_NB),
            Err(libc::EWOULDBLOCK)
        );
        assert_eq!(
            flock_core(&fs, ino, fh2, 200, libc::LOCK_EX | libc::LOCK_NB),
            Err(libc::EWOULDBLOCK)
        );

        // 3. Unlock fh2 -> fh1 can now upgrade to exclusive!
        assert_eq!(flock_core(&fs, ino, fh2, 200, libc::LOCK_UN), Ok(()));
        assert_eq!(flock_core(&fs, ino, fh1, 100, libc::LOCK_EX), Ok(()));

        // 4. fh2 cannot acquire shared or exclusive while fh1 holds exclusive
        assert_eq!(
            flock_core(&fs, ino, fh2, 200, libc::LOCK_SH | libc::LOCK_NB),
            Err(libc::EWOULDBLOCK)
        );
        assert_eq!(
            flock_core(&fs, ino, fh2, 200, libc::LOCK_EX | libc::LOCK_NB),
            Err(libc::EWOULDBLOCK)
        );

        // 5. Downgrade fh1 from exclusive to shared
        assert_eq!(flock_core(&fs, ino, fh1, 100, libc::LOCK_SH), Ok(()));
        // fh2 can now acquire shared
        assert_eq!(flock_core(&fs, ino, fh2, 200, libc::LOCK_SH), Ok(()));

        // 6. Release handle cleans up locks
        assert_eq!(fs.release_file_handle(fh1, ino), Ok(()));
        assert_eq!(fs.release_file_handle(fh2, ino), Ok(()));
        assert!(fs.flock_table.lock().unwrap().get(&ino).is_none());
    }

    #[test]
    fn test_posix_range_locking_and_conflicts() {
        let fs = InMemoryFS::new();
        let attr = crate::operations::read_write::create_core(&fs, 1, "test.txt", 0o644, 0, 1000, 1000).unwrap();
        let ino = attr.ino;

        let fh1 = fs.open_file_handle(ino, libc::O_RDWR as u32);
        let fh2 = fs.open_file_handle(ino, libc::O_RDWR as u32);

        let owner1 = 1001;
        let owner2 = 1002;

        // 1. Owner 1 acquires read lock on [0..100)
        let rlock1 = ShimFlock {
            lock_type: libc::F_RDLCK as i16,
            whence: libc::SEEK_SET as i16,
            start: 0,
            len: 100,
            pid: 100,
        };
        assert_eq!(setlk_core(&fs, ino, fh1, owner1, rlock1, false), Ok(()));

        // 2. Owner 2 acquires overlapping read lock on [50..150) -> OK
        let rlock2 = ShimFlock {
            lock_type: libc::F_RDLCK as i16,
            whence: libc::SEEK_SET as i16,
            start: 50,
            len: 100,
            pid: 200,
        };
        assert_eq!(setlk_core(&fs, ino, fh2, owner2, rlock2, false), Ok(()));

        // 3. Owner 2 attempts write lock on [0..50) -> conflicts with Owner 1's read lock on [0..100)
        let wlock2 = ShimFlock {
            lock_type: libc::F_WRLCK as i16,
            whence: libc::SEEK_SET as i16,
            start: 0,
            len: 50,
            pid: 200,
        };
        assert_eq!(setlk_core(&fs, ino, fh2, owner2, wlock2, false), Err(libc::EWOULDBLOCK));

        // 4. Query conflict with getlk
        let qlock = getlk_core(&fs, ino, fh2, owner2, wlock2).unwrap();
        assert_eq!(qlock.lock_type, libc::F_RDLCK as i16);
        assert_eq!(qlock.start, 0);
        assert_eq!(qlock.pid, 100);

        // 5. Unlock part of Owner 1's range [25..75) -> splits into [0..25) and [75..100)
        let unlock1 = ShimFlock {
            lock_type: libc::F_UNLCK as i16,
            whence: libc::SEEK_SET as i16,
            start: 25,
            len: 50,
            pid: 100,
        };
        assert_eq!(setlk_core(&fs, ino, fh1, owner1, unlock1, false), Ok(()));

        let table = fs.range_lock_table.lock().unwrap();
        let ranges = table.get(&ino).unwrap();
        let owner1_ranges: Vec<_> = ranges.iter().filter(|r| r.owner == owner1).collect();
        assert_eq!(owner1_ranges.len(), 2);
        assert_eq!((owner1_ranges[0].start, owner1_ranges[0].end), (0, 25));
        assert_eq!((owner1_ranges[1].start, owner1_ranges[1].end), (75, 100));
    }

    #[test]
    fn test_posix_blocking_range_lock_setlkw() {
        let fs = Arc::new(InMemoryFS::new());
        let attr = crate::operations::read_write::create_core(&fs, 1, "test_block.txt", 0o644, 0, 1000, 1000).unwrap();
        let ino = attr.ino;

        let fh1 = fs.open_file_handle(ino, libc::O_RDWR as u32);
        let fh2 = fs.open_file_handle(ino, libc::O_RDWR as u32);

        let owner1 = 5001;
        let owner2 = 5002;

        // Owner 1 acquires exclusive write lock on [0..100)
        let wlock1 = ShimFlock {
            lock_type: libc::F_WRLCK as i16,
            whence: libc::SEEK_SET as i16,
            start: 0,
            len: 100,
            pid: 100,
        };
        assert_eq!(setlk_core(&fs, ino, fh1, owner1, wlock1, false), Ok(()));

        let acquired = Arc::new(AtomicBool::new(false));
        let acquired_clone = Arc::clone(&acquired);
        let fs_clone = Arc::clone(&fs);

        // Spawn Thread 2 trying to acquire conflicting write lock with sleep = true (F_SETLKW)
        let handle = thread::spawn(move || {
            let wlock2 = ShimFlock {
                lock_type: libc::F_WRLCK as i16,
                whence: libc::SEEK_SET as i16,
                start: 50,
                len: 100,
                pid: 200,
            };
            let res = setlk_core(&fs_clone, ino, fh2, owner2, wlock2, true);
            assert_eq!(res, Ok(()));
            acquired_clone.store(true, Ordering::SeqCst);
        });

        // Verify Thread 2 is blocked while Owner 1 holds lock
        thread::sleep(Duration::from_millis(50));
        assert!(
            !acquired.load(Ordering::SeqCst),
            "Thread 2 should be blocked on F_SETLKW"
        );

        // Owner 1 unlocks [0..100)
        let unlock1 = ShimFlock {
            lock_type: libc::F_UNLCK as i16,
            whence: libc::SEEK_SET as i16,
            start: 0,
            len: 100,
            pid: 100,
        };
        assert_eq!(setlk_core(&fs, ino, fh1, owner1, unlock1, false), Ok(()));

        // Thread 2 should now unblock and acquire the lock
        handle.join().unwrap();
        assert!(
            acquired.load(Ordering::SeqCst),
            "Thread 2 should have acquired the lock after unblocking"
        );
    }
}
