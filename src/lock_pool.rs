use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

// Centralized fixed-size lock pool using striped locks.
// Maps inode numbers to locks deterministically: idx = ino % 1024.
pub const BUCKET_COUNT: usize = 1024;

pub struct LockPool {
    locks: Vec<RwLock<()>>,
}

impl LockPool {
    pub fn new() -> Self {
        let mut locks = Vec::with_capacity(BUCKET_COUNT);
        for _ in 0..BUCKET_COUNT {
            locks.push(RwLock::new(()));
        }
        Self { locks }
    }

    pub fn read(&self, ino: u64) -> RwLockReadGuard<'_, ()> {
        let idx = (ino % BUCKET_COUNT as u64) as usize;
        self.locks[idx].read().unwrap()
    }

    pub fn write(&self, ino: u64) -> RwLockWriteGuard<'_, ()> {
        let idx = (ino % BUCKET_COUNT as u64) as usize;
        self.locks[idx].write().unwrap()
    }

    // Acquires write locks for two inodes in a deadlock-safe manner.
    // Handles bucket collisions gracefully by only locking once.
    pub fn write_two(
        &self,
        ino1: u64,
        ino2: u64,
    ) -> (RwLockWriteGuard<'_, ()>, Option<RwLockWriteGuard<'_, ()>>) {
        let idx1 = (ino1 % BUCKET_COUNT as u64) as usize;
        let idx2 = (ino2 % BUCKET_COUNT as u64) as usize;

        if idx1 == idx2 {
            let guard = self.locks[idx1].write().unwrap();
            (guard, None)
        } else if idx1 < idx2 {
            let guard1 = self.locks[idx1].write().unwrap();
            let guard2 = self.locks[idx2].write().unwrap();
            (guard1, Some(guard2))
        } else {
            let guard2 = self.locks[idx2].write().unwrap();
            let guard1 = self.locks[idx1].write().unwrap();
            (guard1, Some(guard2))
        }
    }

    // Acquires a read lock for `ino`'s bucket, unless that bucket is already covered by a
    // lock the caller holds for one of `already_locked` (e.g. from `write_two`, or an outer
    // `read`/`write` guard still in scope), in which case returns `None`. Buckets are striped
    // (ino % BUCKET_COUNT), so an unrelated inode can collide with an already-locked bucket,
    // and re-acquiring the same std::sync::RwLock from the same thread — even read-after-read,
    // and especially read-after-write — is not guaranteed deadlock-free. Any lock already held
    // on that bucket gives at least read-level protection, so skipping is sound, not just safe.
    pub fn read_or_reuse(
        &self,
        ino: u64,
        already_locked: &[u64],
    ) -> Option<RwLockReadGuard<'_, ()>> {
        let idx = (ino % BUCKET_COUNT as u64) as usize;
        let collides = already_locked
            .iter()
            .any(|&held| (held % BUCKET_COUNT as u64) as usize == idx);
        if collides { None } else { Some(self.read(ino)) }
    }

    // Acquires every bucket's write lock, in ascending index order (the same order
    // `write_two` already uses for its two locks), so this can never deadlock against
    // any other multi-bucket acquisition in this codebase. Used only for the brief
    // live->flushing swap during a flush - the guards are dropped immediately after
    // the swap, never held across any I/O.
    pub fn write_all(&self) -> Vec<RwLockWriteGuard<'_, ()>> {
        self.locks.iter().map(|l| l.write().unwrap()).collect()
    }
}
