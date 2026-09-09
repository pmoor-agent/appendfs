use crate::fs::{FsInner, InMemoryFS};
use crate::shim::{Request, ShimFlock};
use crate::sync::OpTag;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Condvar, Mutex};

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
    pub req: Request,
    pub fh: u64,
    pub lock_owner: u64,
    pub op: i32,
}

pub struct RangeLockWaiter {
    pub req: Request,
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
pub struct LockManagerState {
    /// Active whole-file BSD flock locks keyed by inode number.
    pub flock_table: HashMap<u64, FlockState>,
    /// Pending parked FUSE BSD flock requests waiting on lock acquisition.
    pub flock_waiters: HashMap<u64, VecDeque<FlockWaiter>>,
    /// Active POSIX byte-range record locks keyed by inode number.
    pub range_lock_table: HashMap<u64, Vec<RangeLock>>,
    /// Pending parked FUSE POSIX byte-range record lock requests waiting on lock acquisition.
    pub range_lock_waiters: HashMap<u64, VecDeque<RangeLockWaiter>>,
}

impl LockManagerState {
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

    pub fn wake_flock_waiters(&mut self, ino: u64) -> Vec<Request> {
        let mut ready_replies = Vec::new();
        if let Some(queue) = self.flock_waiters.get_mut(&ino) {
            while let Some(front) = queue.front() {
                let base_op = front.op & !libc::LOCK_NB;
                if can_grant_flock(&self.flock_table, ino, front.fh, base_op) {
                    let waiter = queue.pop_front().unwrap();
                    grant_flock(&mut self.flock_table, ino, waiter.fh, base_op);
                    ready_replies.push(waiter.req);
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

    pub fn wake_range_lock_waiters(&mut self, ino: u64) -> Vec<Request> {
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
                    ready_replies.push(waiter.req);
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

    pub fn release_flock(&mut self, ino: u64, fh: u64) -> (Vec<Request>, Vec<Request>) {
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
                    canceled_replies.push(w.req);
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
        let ready_replies = self.wake_flock_waiters(ino);
        (canceled_replies, ready_replies)
    }

    pub fn cancel_range_lock_waiters(&mut self, ino: u64, fh: u64) -> Vec<Request> {
        let mut canceled_replies = Vec::new();
        if let Some(queue) = self.range_lock_waiters.get_mut(&ino) {
            let mut kept = VecDeque::with_capacity(queue.len());
            for w in queue.drain(..) {
                if w.fh == fh {
                    canceled_replies.push(w.req);
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

    pub fn release_range_locks(&mut self, ino: u64, fh: u64) -> (Vec<Request>, Vec<Request>) {
        let canceled = self.cancel_range_lock_waiters(ino, fh);
        self.range_lock_table.remove(&ino);
        let ready = self.wake_range_lock_waiters(ino);
        (canceled, ready)
    }
}

/// Encompasses in-memory locking data structures and parked waiter queues
/// for both whole-file BSD flock and POSIX byte-range record locks.
/// Manages its own internal mutex and condition variable independently of filesystem metadata.
pub struct LockManager {
    pub state: Mutex<LockManagerState>,
    pub cond: Condvar,
}

impl Default for LockManager {
    fn default() -> Self {
        Self {
            state: Mutex::new(LockManagerState::default()),
            cond: Condvar::new(),
        }
    }
}

impl std::fmt::Debug for LockManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LockManager")
            .field("flock_count", &self.flock_count())
            .field("range_lock_count", &self.range_lock_count())
            .finish()
    }
}

impl LockManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.state.lock().unwrap().is_empty()
    }

    pub fn flock_count(&self) -> usize {
        self.state.lock().unwrap().flock_count()
    }

    pub fn range_lock_count(&self) -> usize {
        self.state.lock().unwrap().range_lock_count()
    }

    pub fn flock_waiter_count(&self) -> usize {
        self.state.lock().unwrap().flock_waiter_count()
    }

    pub fn range_lock_waiter_count(&self) -> usize {
        self.state.lock().unwrap().range_lock_waiter_count()
    }

    pub fn wake_flock_waiters(&self, ino: u64) {
        let replies = {
            let mut state = self.state.lock().unwrap();
            let r = state.wake_flock_waiters(ino);
            self.cond.notify_all();
            r
        };
        for req in replies {
            req.reply_err(0);
        }
    }

    pub fn wake_range_lock_waiters(&self, ino: u64) {
        let replies = {
            let mut state = self.state.lock().unwrap();
            let r = state.wake_range_lock_waiters(ino);
            self.cond.notify_all();
            r
        };
        for req in replies {
            req.reply_err(0);
        }
    }

    pub fn release_flock(&self, ino: u64, fh: u64) {
        let (canceled, ready) = {
            let mut state = self.state.lock().unwrap();
            let res = state.release_flock(ino, fh);
            self.cond.notify_all();
            res
        };
        for r in canceled {
            r.reply_err(libc::EBADF);
        }
        for r in ready {
            r.reply_err(0);
        }
    }

    pub fn cancel_range_lock_waiters(&self, ino: u64, fh: u64) {
        let canceled = {
            let mut state = self.state.lock().unwrap();
            state.cancel_range_lock_waiters(ino, fh)
        };
        for r in canceled {
            r.reply_err(libc::EBADF);
        }
    }

    pub fn release_range_locks(&self, ino: u64, fh: u64) {
        let (canceled, ready) = {
            let mut state = self.state.lock().unwrap();
            let res = state.release_range_locks(ino, fh);
            self.cond.notify_all();
            res
        };
        for r in canceled {
            r.reply_err(libc::EBADF);
        }
        for r in ready {
            r.reply_err(0);
        }
    }
}

pub fn wake_flock_waiters(fs: &InMemoryFS, ino: u64) {
    fs.locks.wake_flock_waiters(ino);
}

pub fn flock(fs: &InMemoryFS, req: Request, ino: u64, fh: u64, lock_owner: u64, op: i32) {
    log::trace!("flock(ino={}, fh={}, lock_owner={}, op={})", ino, fh, lock_owner, op);

    // 1. Verify file handle
    if let Err(err) = fs.with_inner(OpTag::Handle, |inner| inner.validate_file_handle(ino, fh)) {
        req.reply_err(err);
        return;
    }

    let non_blocking = (op & libc::LOCK_NB) != 0;
    let base_op = op & !libc::LOCK_NB;

    if base_op == libc::LOCK_UN {
        fs.locks.release_flock(ino, fh);
        req.reply_err(0);
        return;
    }

    if base_op != libc::LOCK_SH && base_op != libc::LOCK_EX {
        req.reply_err(libc::EINVAL);
        return;
    }

    let mut state = fs.locks.state.lock().unwrap();
    let has_waiters = state.flock_waiters.get(&ino).is_some_and(|q| !q.is_empty());

    if !has_waiters && can_grant_flock(&state.flock_table, ino, fh, base_op) {
        grant_flock(&mut state.flock_table, ino, fh, base_op);
        fs.locks.cond.notify_all();
        drop(state);
        req.reply_err(0);
        return;
    }

    if non_blocking {
        drop(state);
        req.reply_err(libc::EWOULDBLOCK);
        return;
    }

    // Blocking request with contention: park request in the waiter queue (0 threads used)
    state.flock_waiters.entry(ino).or_default().push_back(FlockWaiter {
        req,
        fh,
        lock_owner,
        op,
    });
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

pub fn wake_range_lock_waiters(fs: &InMemoryFS, ino: u64) {
    fs.locks.wake_range_lock_waiters(ino);
}

// TODO(too-many-lines): extract this into smaller units.
#[allow(clippy::too_many_lines)]
pub fn setlk(fs: &InMemoryFS, req: Request, ino: u64, fh: u64, lock_owner: u64, lock: ShimFlock, sleep: bool) {
    log::trace!(
        "setlk(ino={}, fh={}, lock_owner={}, lock={:?}, sleep={})",
        ino,
        fh,
        lock_owner,
        lock,
        sleep
    );

    let (start, end) = {
        let inner = fs.inner.lock_tag(OpTag::Handle).unwrap();
        if let Err(err) = inner.validate_file_handle(ino, fh) {
            req.reply_err(err);
            return;
        }
        match normalize_range(&inner, ino, &lock) {
            Ok(range) => range,
            Err(err) => {
                req.reply_err(err);
                return;
            }
        }
    };

    let req_type = lock.lock_type;

    if req_type == libc::F_UNLCK as i16 {
        let mut state = fs.locks.state.lock().unwrap();
        if let Some(ranges) = state.range_lock_table.get_mut(&ino) {
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
                state.range_lock_table.remove(&ino);
            } else {
                *ranges = new_ranges;
            }
        }

        let ready = state.wake_range_lock_waiters(ino);
        if !ready.is_empty() {
            fs.locks.cond.notify_all();
        }
        drop(state);
        for req in ready {
            req.reply_err(0);
        }
        req.reply_err(0);
        return;
    }

    if req_type != libc::F_RDLCK as i16 && req_type != libc::F_WRLCK as i16 {
        req.reply_err(libc::EINVAL);
        return;
    }

    let mut state = fs.locks.state.lock().unwrap();
    let conflict = {
        let ranges = state.range_lock_table.entry(ino).or_default();
        check_range_conflict(ranges, lock_owner, start, end, req_type)
    };

    let mut waiter_conflict = false;
    if let Some(queue) = state.range_lock_waiters.get(&ino) {
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
        let ranges = state.range_lock_table.entry(ino).or_default();
        grant_range_lock(ranges, lock_owner, start, end, req_type, lock.pid);
        fs.locks.cond.notify_all();
        drop(state);
        req.reply_err(0);
        return;
    }

    if !sleep {
        drop(state);
        req.reply_err(libc::EWOULDBLOCK);
        return;
    }

    state
        .range_lock_waiters
        .entry(ino)
        .or_default()
        .push_back(RangeLockWaiter {
            req,
            fh,
            lock_owner,
            lock,
            start,
            end,
        });
}

pub fn flock_core(fs: &InMemoryFS, ino: u64, fh: u64, _lock_owner: u64, op: i32) -> Result<(), i32> {
    fs.with_inner(OpTag::Handle, |inner| inner.validate_file_handle(ino, fh))?;

    let non_blocking = (op & libc::LOCK_NB) != 0;
    let base_op = op & !libc::LOCK_NB;

    match base_op {
        libc::LOCK_SH => {
            let mut state = fs.locks.state.lock().unwrap();
            loop {
                match state.flock_table.get_mut(&ino) {
                    None => {
                        let mut set = HashSet::new();
                        set.insert(fh);
                        state.flock_table.insert(ino, FlockState::Shared(set));
                        fs.locks.cond.notify_all();
                        return Ok(());
                    }
                    Some(FlockState::Shared(set)) => {
                        set.insert(fh);
                        return Ok(());
                    }
                    Some(FlockState::Exclusive(holder)) => {
                        if *holder == fh {
                            let mut set = HashSet::new();
                            set.insert(fh);
                            state.flock_table.insert(ino, FlockState::Shared(set));
                            fs.locks.cond.notify_all();
                            return Ok(());
                        } else if non_blocking {
                            return Err(libc::EWOULDBLOCK);
                        } else {
                            state = fs.locks.cond.wait(state).unwrap();
                        }
                    }
                }
            }
        }
        libc::LOCK_EX => {
            let mut state = fs.locks.state.lock().unwrap();
            loop {
                match state.flock_table.get_mut(&ino) {
                    None => {
                        state.flock_table.insert(ino, FlockState::Exclusive(fh));
                        fs.locks.cond.notify_all();
                        return Ok(());
                    }
                    Some(FlockState::Shared(set)) => {
                        if set.len() == 1 && set.contains(&fh) {
                            state.flock_table.insert(ino, FlockState::Exclusive(fh));
                            fs.locks.cond.notify_all();
                            return Ok(());
                        } else if non_blocking {
                            return Err(libc::EWOULDBLOCK);
                        } else {
                            state = fs.locks.cond.wait(state).unwrap();
                        }
                    }
                    Some(FlockState::Exclusive(holder)) => {
                        if *holder == fh {
                            return Ok(());
                        } else if non_blocking {
                            return Err(libc::EWOULDBLOCK);
                        } else {
                            state = fs.locks.cond.wait(state).unwrap();
                        }
                    }
                }
            }
        }
        libc::LOCK_UN => {
            fs.locks.release_flock(ino, fh);
            Ok(())
        }
        _ => Err(libc::EINVAL),
    }
}

fn normalize_range(inner: &FsInner, ino: u64, lock: &ShimFlock) -> Result<(u64, u64), i32> {
    let start_offset = match lock.whence as i32 {
        libc::SEEK_SET => lock.start,
        libc::SEEK_CUR | libc::SEEK_END => {
            let attr = inner.get_attr(ino).ok_or(libc::ENOENT)?;
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
    let (start, end) = {
        let inner = fs.inner.lock_tag(OpTag::Handle).unwrap();
        inner.validate_file_handle(ino, fh)?;
        normalize_range(&inner, ino, &lock)?
    };

    let req_type = lock.lock_type;

    if req_type != libc::F_RDLCK as i16 && req_type != libc::F_WRLCK as i16 {
        return Err(libc::EINVAL);
    }

    let state = fs.locks.state.lock().unwrap();
    if let Some(ranges) = state.range_lock_table.get(&ino) {
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
    let (start, end) = {
        let inner = fs.inner.lock_tag(OpTag::Handle).unwrap();
        inner.validate_file_handle(ino, fh)?;
        normalize_range(&inner, ino, &lock)?
    };

    let req_type = lock.lock_type;

    if req_type == libc::F_RDLCK as i16 || req_type == libc::F_WRLCK as i16 {
        let mut state = fs.locks.state.lock().unwrap();
        loop {
            let ranges = state.range_lock_table.entry(ino).or_default();

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
                    state = fs.locks.cond.wait(state).unwrap();
                    continue;
                }
            }

            // 2. Grant lock
            grant_range_lock(ranges, lock_owner, start, end, req_type, lock.pid);
            fs.locks.cond.notify_all();
            return Ok(());
        }
    } else if req_type == libc::F_UNLCK as i16 {
        let ready = {
            let mut state = fs.locks.state.lock().unwrap();
            if let Some(ranges) = state.range_lock_table.get_mut(&ino) {
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
                    state.range_lock_table.remove(&ino);
                } else {
                    *ranges = new_ranges;
                }
            }

            let ready = state.wake_range_lock_waiters(ino);
            fs.locks.cond.notify_all();
            ready
        };
        for req in ready {
            req.reply_err(0);
        }
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
        assert_eq!(fs.locks.flock_count(), 0);
        assert!(fs.locks.is_empty());
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

        let state = fs.locks.state.lock().unwrap();
        let ranges = state.range_lock_table.get(&ino).unwrap();
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
