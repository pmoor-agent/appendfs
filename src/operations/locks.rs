use crate::error::FsError;
use crate::fs::{AppendFs, FsInner, FsInnerGuard};
use crate::shim::{DeferredResult, DeferredToken, FuseResponse, ShimFlock};
use crate::sync::OpTag;
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlockState {
    Shared(HashSet<u64>),
    Exclusive(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeLock {
    pub lock_type: i16,
    pub start: u64,
    pub end: u64,
    pub owner: u64,
    pub pid: i32,
}

pub struct FlockWaiter {
    pub token: DeferredToken<FuseResponse<'static>>,
    pub fh: u64,
    pub lock_owner: u64,
    pub op: i32,
}

pub struct RangeLockWaiter {
    pub token: DeferredToken<FuseResponse<'static>>,
    pub fh: u64,
    pub lock_owner: u64,
    pub lock: ShimFlock,
    pub start: u64,
    pub end: u64,
}

pub(crate) fn can_grant_flock(table: &HashMap<u64, FlockState>, ino: u64, fh: u64, base_op: i32) -> bool {
    match base_op {
        libc::LOCK_SH => match table.get(&ino) {
            None => true,
            Some(FlockState::Shared(_)) => true,
            Some(FlockState::Exclusive(holder)) => *holder == fh,
        },
        libc::LOCK_EX => match table.get(&ino) {
            None => true,
            Some(FlockState::Shared(set)) => set.len() == 1 && set.contains(&fh),
            Some(FlockState::Exclusive(holder)) => *holder == fh,
        },
        _ => false,
    }
}

pub(crate) fn grant_flock(table: &mut HashMap<u64, FlockState>, ino: u64, fh: u64, base_op: i32) {
    match base_op {
        libc::LOCK_SH => match table.get_mut(&ino) {
            None => {
                let mut set = HashSet::new();
                set.insert(fh);
                table.insert(ino, FlockState::Shared(set));
            }
            Some(FlockState::Shared(set)) => {
                set.insert(fh);
            }
            Some(FlockState::Exclusive(holder)) => {
                if *holder == fh {
                    let mut set = HashSet::new();
                    set.insert(fh);
                    table.insert(ino, FlockState::Shared(set));
                }
            }
        },
        libc::LOCK_EX => {
            table.insert(ino, FlockState::Exclusive(fh));
        }
        _ => {}
    }
}

/// Internal tables for whole-file BSD flock and POSIX byte-range record locks.
#[derive(Default)]
pub struct LockManager {
    /// Active whole-file BSD flock locks keyed by inode number.
    pub flock_table: HashMap<u64, FlockState>,
    /// Pending parked FUSE BSD flock requests waiting on lock acquisition.
    pub flock_waiters: HashMap<u64, VecDeque<FlockWaiter>>,
    /// Active POSIX byte-range record locks keyed by inode number.
    pub range_lock_table: HashMap<u64, Vec<RangeLock>>,
    /// Pending parked FUSE POSIX byte-range record lock requests waiting on lock acquisition.
    pub range_lock_waiters: HashMap<u64, VecDeque<RangeLockWaiter>>,
}

impl std::fmt::Debug for LockManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LockManager")
            .field("flock_count", &self.flock_count())
            .field("range_lock_count", &self.range_lock_count())
            .field("flock_waiter_count", &self.flock_waiter_count())
            .field("range_lock_waiter_count", &self.range_lock_waiter_count())
            .finish()
    }
}

impl LockManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.flock_table.is_empty()
            && self.range_lock_table.is_empty()
            && self.flock_waiters.is_empty()
            && self.range_lock_waiters.is_empty()
    }

    pub fn flock_count(&self) -> usize {
        self.flock_table.len()
    }

    pub fn range_lock_count(&self) -> usize {
        self.range_lock_table.len()
    }

    pub fn flock_waiter_count(&self) -> usize {
        self.flock_waiters.values().map(|q| q.len()).sum()
    }

    pub fn range_lock_waiter_count(&self) -> usize {
        self.range_lock_waiters.values().map(|q| q.len()).sum()
    }

    pub fn wake_flock_waiters_state(&mut self, ino: u64) -> Vec<DeferredToken<FuseResponse<'static>>> {
        let mut ready_replies = Vec::new();
        if let Some(queue) = self.flock_waiters.get_mut(&ino) {
            while let Some(front) = queue.front() {
                let base_op = front.op & !libc::LOCK_NB;
                if can_grant_flock(&self.flock_table, ino, front.fh, base_op) {
                    let waiter = queue.pop_front().unwrap();
                    grant_flock(&mut self.flock_table, ino, waiter.fh, base_op);
                    ready_replies.push(waiter.token);
                    if base_op == libc::LOCK_EX {
                        break;
                    }
                } else {
                    break;
                }
            }
            if queue.is_empty() {
                self.flock_waiters.remove(&ino);
            }
        }
        ready_replies
    }

    pub fn wake_range_lock_waiters_state(&mut self, ino: u64) -> Vec<DeferredToken<FuseResponse<'static>>> {
        let mut ready_replies = Vec::new();
        if let Some(queue) = self.range_lock_waiters.get_mut(&ino) {
            let mut i = 0;
            while i < queue.len() {
                let waiter = &queue[i];
                let req_type = waiter.lock.lock_type;
                let ranges = self.range_lock_table.entry(ino).or_default();

                let conflict = check_range_conflict(ranges, waiter.lock_owner, waiter.start, waiter.end, req_type);

                let mut prior_waiter_conflict = false;
                for prior in queue.iter().take(i) {
                    if prior.lock_owner != waiter.lock_owner
                        && ranges_overlap(waiter.start, waiter.end, prior.start, prior.end)
                        && (req_type == libc::F_WRLCK as i16 || prior.lock.lock_type == libc::F_WRLCK as i16)
                    {
                        prior_waiter_conflict = true;
                        break;
                    }
                }

                if !conflict && !prior_waiter_conflict {
                    let waiter = queue.remove(i).unwrap();
                    let ranges = self.range_lock_table.entry(ino).or_default();
                    grant_range_lock(
                        ranges,
                        waiter.lock_owner,
                        waiter.start,
                        waiter.end,
                        req_type,
                        waiter.lock.pid,
                    );
                    ready_replies.push(waiter.token);
                } else {
                    i += 1;
                }
            }
            if queue.is_empty() {
                self.range_lock_waiters.remove(&ino);
            }
        }
        ready_replies
    }

    pub fn release_flock_state(
        &mut self,
        ino: u64,
        fh: u64,
    ) -> (
        Vec<DeferredToken<FuseResponse<'static>>>,
        Vec<DeferredToken<FuseResponse<'static>>>,
    ) {
        let mut canceled_replies = Vec::new();
        if let Some(state) = self.flock_table.get_mut(&ino) {
            match state {
                FlockState::Shared(set) => {
                    set.remove(&fh);
                    if set.is_empty() {
                        self.flock_table.remove(&ino);
                    }
                }
                FlockState::Exclusive(holder) => {
                    if *holder == fh {
                        self.flock_table.remove(&ino);
                    }
                }
            }
        }
        if let Some(queue) = self.flock_waiters.get_mut(&ino) {
            let mut kept = VecDeque::with_capacity(queue.len());
            for w in queue.drain(..) {
                if w.fh == fh {
                    canceled_replies.push(w.token);
                } else {
                    kept.push_back(w);
                }
            }
            if kept.is_empty() {
                self.flock_waiters.remove(&ino);
            } else {
                *queue = kept;
            }
        }
        let ready_replies = self.wake_flock_waiters_state(ino);
        (canceled_replies, ready_replies)
    }

    pub fn cancel_range_lock_waiters_state(&mut self, ino: u64, fh: u64) -> Vec<DeferredToken<FuseResponse<'static>>> {
        let mut canceled_replies = Vec::new();
        if let Some(queue) = self.range_lock_waiters.get_mut(&ino) {
            let mut kept = VecDeque::with_capacity(queue.len());
            for w in queue.drain(..) {
                if w.fh == fh {
                    canceled_replies.push(w.token);
                } else {
                    kept.push_back(w);
                }
            }
            if kept.is_empty() {
                self.range_lock_waiters.remove(&ino);
            } else {
                *queue = kept;
            }
        }
        canceled_replies
    }

    pub fn release_range_locks_state(
        &mut self,
        ino: u64,
        fh: u64,
    ) -> (
        Vec<DeferredToken<FuseResponse<'static>>>,
        Vec<DeferredToken<FuseResponse<'static>>>,
    ) {
        let canceled = self.cancel_range_lock_waiters_state(ino, fh);
        self.range_lock_table.remove(&ino);
        let ready = self.wake_range_lock_waiters_state(ino);
        (canceled, ready)
    }

    pub fn release_file_handle_state(
        &mut self,
        is_last_handle: bool,
        ino: u64,
        fh: u64,
    ) -> (
        Vec<DeferredToken<FuseResponse<'static>>>,
        Vec<DeferredToken<FuseResponse<'static>>>,
    ) {
        let (flock_canceled, flock_ready) = self.release_flock_state(ino, fh);
        let (range_canceled, range_ready) = if is_last_handle {
            self.release_range_locks_state(ino, fh)
        } else {
            (self.cancel_range_lock_waiters_state(ino, fh), Vec::new())
        };
        let mut all_canceled = flock_canceled;
        all_canceled.extend(range_canceled);
        let mut all_ready = flock_ready;
        all_ready.extend(range_ready);
        (all_canceled, all_ready)
    }

    pub fn unlock_range_state(&mut self, ino: u64, lock_owner: u64, start: u64, end: u64) {
        if let Some(ranges) = self.range_lock_table.get_mut(&ino) {
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
                self.range_lock_table.remove(&ino);
            } else {
                *ranges = new_ranges;
            }
        }
    }

    /// Releases the whole-file BSD flock held by `fh` on `ino` and defers notifying canceled/ready waiters.
    pub fn release_flock(inner: &mut FsInnerGuard<'_>, ino: u64, fh: u64) {
        let (canceled, ready) = inner.locks.release_flock_state(ino, fh);
        Self::defer_replies(inner, canceled, ready);
    }

    /// Cancels all pending POSIX range lock waiters for `fh` on `ino` and defers replying EBADF.
    pub fn cancel_range_lock_waiters(inner: &mut FsInnerGuard<'_>, ino: u64, fh: u64) {
        let canceled = inner.locks.cancel_range_lock_waiters_state(ino, fh);
        if !canceled.is_empty() {
            inner.defer(move || {
                for r in canceled {
                    r.complete(Err(FsError::EBADF));
                }
            });
        }
    }

    /// Releases all POSIX range locks held on `ino` and defers waking pending waiters and replying EBADF to canceled requests for `fh`.
    pub fn release_range_locks(inner: &mut FsInnerGuard<'_>, ino: u64, fh: u64) {
        let (canceled, ready) = inner.locks.release_range_locks_state(ino, fh);
        Self::defer_replies(inner, canceled, ready);
    }

    /// Releases all locks held by a file handle when the handle is closed.
    pub fn release_file_handle(inner: &mut FsInnerGuard<'_>, is_last_handle: bool, ino: u64, fh: u64) {
        let (canceled, ready) = inner.locks.release_file_handle_state(is_last_handle, ino, fh);
        Self::defer_replies(inner, canceled, ready);
    }

    /// Unlocks a POSIX byte range on `ino` and defers notifying any ready range lock waiters.
    pub fn unlock_range(inner: &mut FsInnerGuard<'_>, ino: u64, lock_owner: u64, start: u64, end: u64) {
        inner.locks.unlock_range_state(ino, lock_owner, start, end);
        Self::wake_range_lock_waiters(inner, ino);
    }

    /// Wakes any pending range lock waiters on `ino` and defers replying success.
    pub fn wake_range_lock_waiters(inner: &mut FsInnerGuard<'_>, ino: u64) {
        let ready = inner.locks.wake_range_lock_waiters_state(ino);
        if !ready.is_empty() {
            inner.defer(move || {
                for r in ready {
                    r.complete(Ok(FuseResponse::ok()));
                }
            });
        }
    }

    /// Wakes any pending flock waiters on `ino` and defers replying success.
    pub fn wake_flock_waiters(inner: &mut FsInnerGuard<'_>, ino: u64) {
        let ready = inner.locks.wake_flock_waiters_state(ino);
        if !ready.is_empty() {
            inner.defer(move || {
                for r in ready {
                    r.complete(Ok(FuseResponse::ok()));
                }
            });
        }
    }

    /// Drains every parked flock and range-lock waiter across all inodes, replying `EIO` to
    /// each. Used by shutdown once the filesystem is `Stopped`, so a client parked waiting on
    /// a lock another client never released gets a definitive reply instead of hanging forever.
    /// Unlike the per-`(ino, fh)` cancellation used on handle release, which only covers one
    /// waiter's own handle, this clears everyone still queued behind it.
    pub fn cancel_all_waiters(inner: &mut FsInnerGuard<'_>) {
        let mut tokens = Vec::new();
        for (_, queue) in inner.locks.flock_waiters.drain() {
            tokens.extend(queue.into_iter().map(|w| w.token));
        }
        for (_, queue) in inner.locks.range_lock_waiters.drain() {
            tokens.extend(queue.into_iter().map(|w| w.token));
        }
        if !tokens.is_empty() {
            inner.defer(move || {
                for token in tokens {
                    token.complete(Err(FsError::EIO));
                }
            });
        }
    }

    fn defer_replies(
        inner: &mut FsInnerGuard<'_>,
        canceled: Vec<DeferredToken<FuseResponse<'static>>>,
        ready: Vec<DeferredToken<FuseResponse<'static>>>,
    ) {
        if !canceled.is_empty() || !ready.is_empty() {
            inner.defer(move || {
                for r in canceled {
                    r.complete(Err(FsError::EBADF));
                }
                for r in ready {
                    r.complete(Ok(FuseResponse::ok()));
                }
            });
        }
    }
}

pub fn wake_flock_waiters(fs: &AppendFs, ino: u64) {
    fs.with_inner(OpTag::Lock, |inner| LockManager::wake_flock_waiters(inner, ino));
}

pub fn flock_response(
    fs: &AppendFs,
    ino: u64,
    fh: u64,
    lock_owner: u64,
    op: i32,
) -> DeferredResult<FuseResponse<'static>> {
    log::trace!("flock(ino={}, fh={}, lock_owner={}, op={})", ino, fh, lock_owner, op);

    let non_blocking = (op & libc::LOCK_NB) != 0;
    let base_op = op & !libc::LOCK_NB;

    if base_op != libc::LOCK_UN && base_op != libc::LOCK_SH && base_op != libc::LOCK_EX {
        return DeferredResult::err(FsError::EINVAL);
    }

    let mut inner = fs.lock_inner(OpTag::Lock);
    if let Err(err) = inner.validate_file_handle(ino, fh) {
        return DeferredResult::err(err);
    }
    // Unlocking is allowed through a read-only shutdown so clients can still clean up; a
    // fully `Stopped` filesystem rejects it regardless (`check_shutdown` ignores `mutating`
    // in that phase).
    if let Err(err) = inner.check_shutdown(base_op != libc::LOCK_UN) {
        return DeferredResult::err(err);
    }

    if base_op == libc::LOCK_UN {
        LockManager::release_flock(&mut inner, ino, fh);
        return DeferredResult::ok_void();
    }

    let has_waiters = inner.locks.flock_waiters.get(&ino).is_some_and(|q| !q.is_empty());

    if !has_waiters && can_grant_flock(&inner.locks.flock_table, ino, fh, base_op) {
        grant_flock(&mut inner.locks.flock_table, ino, fh, base_op);
        return DeferredResult::ok_void();
    }

    if non_blocking {
        return DeferredResult::err(FsError::EWOULDBLOCK);
    }

    // Blocking request with contention: park token in the waiter queue (0 threads used)
    let (token, rx) = DeferredToken::new();
    inner
        .locks
        .flock_waiters
        .entry(ino)
        .or_default()
        .push_back(FlockWaiter {
            token,
            fh,
            lock_owner,
            op,
        });
    DeferredResult::deferred(rx)
}

pub fn getlk_response(
    fs: &AppendFs,
    ino: u64,
    fh: u64,
    lock_owner: u64,
    lock: ShimFlock,
) -> Result<FuseResponse<'static>, FsError> {
    getlk_core(fs, ino, fh, lock_owner, lock).map(FuseResponse::lock)
}

pub(crate) fn check_range_conflict(ranges: &[RangeLock], lock_owner: u64, start: u64, end: u64, req_type: i16) -> bool {
    for r in ranges {
        if r.owner != lock_owner
            && ranges_overlap(start, end, r.start, r.end)
            && (req_type == libc::F_WRLCK as i16 || r.lock_type == libc::F_WRLCK as i16)
        {
            return true;
        }
    }
    false
}

pub(crate) fn grant_range_lock(
    ranges: &mut Vec<RangeLock>,
    lock_owner: u64,
    start: u64,
    end: u64,
    req_type: i16,
    pid: i32,
) {
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
    new_ranges.push(RangeLock {
        lock_type: req_type,
        start,
        end,
        owner: lock_owner,
        pid,
    });
    coalesce_ranges(&mut new_ranges);
    *ranges = new_ranges;
}

pub fn wake_range_lock_waiters(fs: &AppendFs, ino: u64) {
    fs.with_inner(OpTag::Lock, |inner| LockManager::wake_range_lock_waiters(inner, ino));
}

// TODO(too-many-lines): extract this into smaller units.
#[allow(clippy::too_many_lines)]
pub fn setlk_response(
    fs: &AppendFs,
    ino: u64,
    fh: u64,
    lock_owner: u64,
    lock: ShimFlock,
    sleep: bool,
) -> DeferredResult<FuseResponse<'static>> {
    log::trace!(
        "setlk(ino={}, fh={}, lock_owner={}, lock={:?}, sleep={})",
        ino,
        fh,
        lock_owner,
        lock,
        sleep
    );

    let mut inner = fs.lock_inner(OpTag::Lock);
    if let Err(err) = inner.validate_file_handle(ino, fh) {
        return DeferredResult::err(err);
    }

    let (start, end) = match normalize_range(&inner, ino, &lock) {
        Ok(range) => range,
        Err(err) => return DeferredResult::err(err),
    };

    let req_type = lock.lock_type;

    // Unlocking is allowed through a read-only shutdown so clients can still clean up; a
    // fully `Stopped` filesystem rejects it regardless (`check_shutdown` ignores `mutating`
    // in that phase).
    if let Err(err) = inner.check_shutdown(req_type != libc::F_UNLCK as i16) {
        return DeferredResult::err(err);
    }

    if req_type == libc::F_UNLCK as i16 {
        LockManager::unlock_range(&mut inner, ino, lock_owner, start, end);
        return DeferredResult::ok_void();
    }

    if req_type != libc::F_RDLCK as i16 && req_type != libc::F_WRLCK as i16 {
        return DeferredResult::err(FsError::EINVAL);
    }

    let conflict = {
        let ranges = inner.locks.range_lock_table.entry(ino).or_default();
        check_range_conflict(ranges, lock_owner, start, end, req_type)
    };

    let mut waiter_conflict = false;
    if let Some(queue) = inner.locks.range_lock_waiters.get(&ino) {
        for prior in queue {
            if prior.lock_owner != lock_owner
                && ranges_overlap(start, end, prior.start, prior.end)
                && (req_type == libc::F_WRLCK as i16 || prior.lock.lock_type == libc::F_WRLCK as i16)
            {
                waiter_conflict = true;
                break;
            }
        }
    }

    if !conflict && !waiter_conflict {
        let ranges = inner.locks.range_lock_table.entry(ino).or_default();
        grant_range_lock(ranges, lock_owner, start, end, req_type, lock.pid);
        return DeferredResult::ok_void();
    }

    if !sleep {
        return DeferredResult::err(FsError::EWOULDBLOCK);
    }

    let (token, rx) = DeferredToken::new();
    inner
        .locks
        .range_lock_waiters
        .entry(ino)
        .or_default()
        .push_back(RangeLockWaiter {
            token,
            fh,
            lock_owner,
            lock,
            start,
            end,
        });
    DeferredResult::deferred(rx)
}

pub fn flock_core(fs: &AppendFs, ino: u64, fh: u64, _lock_owner: u64, op: i32) -> Result<(), FsError> {
    let base_op = op & !libc::LOCK_NB;

    if base_op != libc::LOCK_UN && base_op != libc::LOCK_SH && base_op != libc::LOCK_EX {
        return Err(FsError::EINVAL);
    }

    fs.with_inner(OpTag::Lock, |inner| {
        inner.validate_file_handle(ino, fh)?;
        inner.check_shutdown(base_op != libc::LOCK_UN)?;

        if base_op == libc::LOCK_UN {
            LockManager::release_flock(inner, ino, fh);
            return Ok(());
        }

        if can_grant_flock(&inner.locks.flock_table, ino, fh, base_op) {
            grant_flock(&mut inner.locks.flock_table, ino, fh, base_op);
            return Ok(());
        }

        Err(FsError::EWOULDBLOCK)
    })
}

fn normalize_range(inner: &FsInner, ino: u64, lock: &ShimFlock) -> Result<(u64, u64), FsError> {
    let start_offset = match lock.whence as i32 {
        libc::SEEK_SET => lock.start,
        libc::SEEK_CUR | libc::SEEK_END => {
            let attr = inner.get_attr(ino).ok_or(FsError::ENOENT)?;
            attr.size.saturating_add(lock.start)
        }
        _ => return Err(FsError::EINVAL),
    };

    if start_offset < 0 {
        return Err(FsError::EINVAL);
    }
    let start = start_offset as u64;

    if lock.len < 0 {
        return Err(FsError::EINVAL);
    }

    let end = if lock.len == 0 {
        u64::MAX
    } else {
        start.checked_add(lock.len as u64).ok_or(FsError::EINVAL)?
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

pub fn getlk_core(fs: &AppendFs, ino: u64, fh: u64, lock_owner: u64, lock: ShimFlock) -> Result<ShimFlock, FsError> {
    let inner = fs.inner.lock(OpTag::Lock).unwrap();
    inner.check_shutdown(false)?;
    inner.validate_file_handle(ino, fh)?;
    let (start, end) = normalize_range(&inner, ino, &lock)?;

    let req_type = lock.lock_type;

    if req_type != libc::F_RDLCK as i16 && req_type != libc::F_WRLCK as i16 {
        return Err(FsError::EINVAL);
    }

    if let Some(ranges) = inner.locks.range_lock_table.get(&ino) {
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
    fs: &AppendFs,
    ino: u64,
    fh: u64,
    lock_owner: u64,
    lock: ShimFlock,
    _sleep: bool,
) -> Result<(), FsError> {
    fs.with_inner(OpTag::Lock, |inner| {
        inner.validate_file_handle(ino, fh)?;
        let (start, end) = normalize_range(inner, ino, &lock)?;

        let req_type = lock.lock_type;
        inner.check_shutdown(req_type != libc::F_UNLCK as i16)?;

        if req_type == libc::F_RDLCK as i16 || req_type == libc::F_WRLCK as i16 {
            let ranges = inner.locks.range_lock_table.entry(ino).or_default();
            if check_range_conflict(ranges, lock_owner, start, end, req_type) {
                return Err(FsError::EWOULDBLOCK);
            }

            grant_range_lock(ranges, lock_owner, start, end, req_type, lock.pid);
            Ok(())
        } else if req_type == libc::F_UNLCK as i16 {
            LockManager::unlock_range(inner, ino, lock_owner, start, end);
            Ok(())
        } else {
            Err(FsError::EINVAL)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestFs;

    #[test]
    fn test_flock_shared_concurrent_and_exclusive_exclusion() {
        let fs = TestFs::builder().build().fs;
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
            Err(FsError::EWOULDBLOCK)
        );
        assert_eq!(
            flock_core(&fs, ino, fh2, 200, libc::LOCK_EX | libc::LOCK_NB),
            Err(FsError::EWOULDBLOCK)
        );

        // 3. Unlock fh2 -> fh1 can now upgrade to exclusive!
        assert_eq!(flock_core(&fs, ino, fh2, 200, libc::LOCK_UN), Ok(()));
        assert_eq!(flock_core(&fs, ino, fh1, 100, libc::LOCK_EX), Ok(()));

        // 4. fh2 cannot acquire shared or exclusive while fh1 holds exclusive
        assert_eq!(
            flock_core(&fs, ino, fh2, 200, libc::LOCK_SH | libc::LOCK_NB),
            Err(FsError::EWOULDBLOCK)
        );
        assert_eq!(
            flock_core(&fs, ino, fh2, 200, libc::LOCK_EX | libc::LOCK_NB),
            Err(FsError::EWOULDBLOCK)
        );

        // 5. Downgrade fh1 from exclusive to shared
        assert_eq!(flock_core(&fs, ino, fh1, 100, libc::LOCK_SH), Ok(()));
        // fh2 can now acquire shared
        assert_eq!(flock_core(&fs, ino, fh2, 200, libc::LOCK_SH), Ok(()));

        // 6. Release handle cleans up locks
        assert_eq!(fs.release_file_handle(fh1, ino), Ok(()));
        assert_eq!(fs.release_file_handle(fh2, ino), Ok(()));
        let inner = fs.inner.lock_for_tests().unwrap();
        assert_eq!(inner.locks.flock_count(), 0);
        assert!(inner.locks.is_empty());
    }

    #[test]
    fn test_posix_range_locking_and_conflicts() {
        let fs = TestFs::builder().build().fs;
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
        assert_eq!(
            setlk_core(&fs, ino, fh2, owner2, wlock2, false),
            Err(FsError::EWOULDBLOCK)
        );

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

        let inner = fs.inner.lock_for_tests().unwrap();
        let ranges = inner.locks.range_lock_table.get(&ino).unwrap();
        let owner1_ranges: Vec<_> = ranges.iter().filter(|r| r.owner == owner1).collect();
        assert_eq!(owner1_ranges.len(), 2);
        assert_eq!((owner1_ranges[0].start, owner1_ranges[0].end), (0, 25));
        assert_eq!((owner1_ranges[1].start, owner1_ranges[1].end), (75, 100));
    }

    #[test]
    fn test_lock_manager_waiter_waking() {
        let mut lm = LockManager::new();
        let ino = 42;
        let make_waiter_token = || DeferredToken::new().0;

        // Test flock waiter queuing & waking
        grant_flock(&mut lm.flock_table, ino, 1, libc::LOCK_EX);
        lm.flock_waiters.entry(ino).or_default().push_back(FlockWaiter {
            token: make_waiter_token(),
            fh: 2,
            lock_owner: 200,
            op: libc::LOCK_SH,
        });
        assert_eq!(lm.flock_waiter_count(), 1);

        // While ino is locked exclusively by fh=1, waking yields no ready requests
        let ready = lm.wake_flock_waiters_state(ino);
        assert!(ready.is_empty());

        // Release fh=1
        let (canceled, ready) = lm.release_flock_state(ino, 1);
        assert!(canceled.is_empty());
        assert_eq!(ready.len(), 1);
        assert_eq!(lm.flock_waiter_count(), 0);

        // Test range lock waiter queuing & waking
        let ranges = lm.range_lock_table.entry(ino).or_default();
        grant_range_lock(ranges, 100, 0, 100, libc::F_WRLCK as i16, 10);
        lm.range_lock_waiters
            .entry(ino)
            .or_default()
            .push_back(RangeLockWaiter {
                token: make_waiter_token(),
                fh: 2,
                lock_owner: 200,
                lock: ShimFlock {
                    lock_type: libc::F_WRLCK as i16,
                    whence: libc::SEEK_SET as i16,
                    start: 50,
                    len: 50,
                    pid: 20,
                },
                start: 50,
                end: 100,
            });
        assert_eq!(lm.range_lock_waiter_count(), 1);

        // Release range locks for fh=1
        let (canceled, ready) = lm.release_range_locks_state(ino, 1);
        assert!(canceled.is_empty());
        assert_eq!(ready.len(), 1);
        assert_eq!(lm.range_lock_waiter_count(), 0);

        // Test release_file_handle (flock + range lock waiters + handle release)
        grant_flock(&mut lm.flock_table, ino, 10, libc::LOCK_EX);
        lm.flock_waiters.entry(ino).or_default().push_back(FlockWaiter {
            token: make_waiter_token(),
            fh: 20,
            lock_owner: 300,
            op: libc::LOCK_SH,
        });
        let ranges = lm.range_lock_table.entry(ino).or_default();
        grant_range_lock(ranges, 100, 0, 100, libc::F_WRLCK as i16, 10);
        lm.range_lock_waiters
            .entry(ino)
            .or_default()
            .push_back(RangeLockWaiter {
                token: make_waiter_token(),
                fh: 10,
                lock_owner: 100,
                lock: ShimFlock {
                    lock_type: libc::F_WRLCK as i16,
                    whence: libc::SEEK_SET as i16,
                    start: 0,
                    len: 100,
                    pid: 10,
                },
                start: 0,
                end: 100,
            });

        // Releasing handle 10 when not last handle cancels range waiter for fh=10 and wakes flock waiter
        let (canceled, ready) = lm.release_file_handle_state(false, ino, 10);
        assert_eq!(canceled.len(), 1);
        assert_eq!(ready.len(), 1);

        // Releasing handle 10 when last handle clears all remaining range locks
        let (canceled, ready) = lm.release_file_handle_state(true, ino, 10);
        assert!(canceled.is_empty());
        assert!(ready.is_empty());
        assert!(!lm.range_lock_table.contains_key(&ino));
    }
}
