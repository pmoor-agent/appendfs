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
}
