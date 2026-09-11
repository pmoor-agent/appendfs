//! Drives flush cycles.
//!
//! The flusher is the only component permitted to write flush batches to the log or fold
//! them into `base`. FUSE threads may append to `live` and freeze `live` into `flushing`;
//! everything past that point belongs here.
//!
//! Cycles run in one of two modes. A mounted filesystem starts a [`Flusher`] thread that
//! wakes on demand and after an interval of inactivity. Everything else - tests, one-shot
//! CLI tools, fixture generation - leaves it in the default inline mode, where a cycle runs
//! on the thread that asked for it. Both modes go through the same `wake` / `quiesce` calls,
//! so no caller has to know which one it is talking to.

use super::InMemoryFS;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::thread::JoinHandle;
use std::time::Duration;

/// How long the background thread waits before retrying a cycle that failed, rather than
/// sitting out the full inactivity interval while a transient error keeps the queue stalled.
const RETRY_DELAY: Duration = Duration::from_millis(100);

#[derive(Default)]
struct Wakeup {
    /// A cycle has been requested since the thread last ran one.
    wake: bool,
    /// The thread has been asked to exit.
    stop: bool,
}

/// Thread management and cycle serialization for [`InMemoryFS`] flushing.
pub(crate) struct Flusher {
    wakeup: Arc<(Mutex<Wakeup>, Condvar)>,
    /// `Some` once a background thread is running.
    thread: Mutex<Option<JoinHandle<()>>>,
    /// True while a background thread is running, so callers can pick between waking it and
    /// running the cycle themselves without locking `thread`.
    background: AtomicBool,
    /// Serializes flush cycles. Uncontended in background mode, where only one thread runs
    /// them; in inline mode it keeps concurrent callers from writing to the log at once.
    cycle_lock: Mutex<()>,
    /// Error from the most recent failed cycle, for `quiesce` callers that cannot observe
    /// the cycle's return value because a background thread ran it.
    last_error: Mutex<Option<std::io::Error>>,
}

impl Default for Flusher {
    fn default() -> Self {
        Self::new()
    }
}

impl Flusher {
    pub(crate) fn new() -> Self {
        Self {
            wakeup: Arc::new((Mutex::new(Wakeup::default()), Condvar::new())),
            thread: Mutex::new(None),
            background: AtomicBool::new(false),
            cycle_lock: Mutex::new(()),
            last_error: Mutex::new(None),
        }
    }

    /// Returns true once a background thread is running cycles.
    pub(crate) fn is_background(&self) -> bool {
        self.background.load(Ordering::SeqCst)
    }

    /// Starts the background thread, which runs a cycle whenever one is requested and, if
    /// `interval` is set, after that long without one. Idempotent.
    ///
    /// The thread holds only a `Weak` reference: an `Arc` here would form a cycle through
    /// `InMemoryFS::flusher` and keep the filesystem alive forever.
    pub(crate) fn start(&self, fs: &Arc<InMemoryFS>, interval: Option<Duration>) {
        let mut thread = self.thread.lock().unwrap();
        if thread.is_some() {
            return;
        }

        let weak = Arc::downgrade(fs);
        let wakeup = Arc::clone(&self.wakeup);
        let handle = std::thread::Builder::new()
            .name("appendfs-flusher".to_string())
            .spawn(move || run_background(&weak, &wakeup, interval))
            .expect("failed to spawn flusher thread");

        *thread = Some(handle);
        self.background.store(true, Ordering::SeqCst);
        log::info!(
            "Started flusher thread (inactivity interval: {})",
            interval.map_or_else(|| "disabled".to_string(), |i| format!("{}s", i.as_secs()))
        );
    }

    /// Poses as (or stops posing as) a mounted filesystem, without a thread behind it, so
    /// tests can exercise the paths that wait for a background flusher.
    #[cfg(test)]
    pub(crate) fn set_background_for_tests(&self, on: bool) {
        self.background.store(on, Ordering::SeqCst);
    }

    /// Requests a cycle from the background thread. No-op in inline mode, where the caller
    /// runs the cycle itself.
    pub(crate) fn notify(&self) {
        let (lock, cvar) = &*self.wakeup;
        let mut state = lock.lock().unwrap();
        state.wake = true;
        cvar.notify_one();
    }

    /// Signals the background thread to exit and joins it. Idempotent.
    ///
    /// Returns whether a thread was actually running, which tells `destroy` whether anything
    /// still queued has lost the thread that would have written it.
    pub(crate) fn stop(&self) -> bool {
        {
            let (lock, cvar) = &*self.wakeup;
            let mut state = lock.lock().unwrap();
            state.stop = true;
            cvar.notify_all();
        }
        let handle = self.thread.lock().unwrap().take();
        let was_running = handle.is_some();
        if let Some(handle) = handle {
            let _ = handle.join();
        }
        self.background.store(false, Ordering::SeqCst);
        was_running
    }

    /// Runs `cycle` with the cycle lock held, recording its outcome for `quiesce` callers
    /// that cannot see the return value directly.
    pub(crate) fn run_locked<T, F>(&self, cycle: F) -> std::io::Result<T>
    where
        F: FnOnce() -> std::io::Result<T>,
    {
        let _guard = self.cycle_lock.lock().unwrap();
        let result = cycle();
        let mut last = self.last_error.lock().unwrap();
        match &result {
            Ok(_) => *last = None,
            Err(e) => *last = Some(std::io::Error::new(e.kind(), e.to_string())),
        }
        result
    }

    /// Takes the error from the most recent failed cycle, if it has not been observed yet.
    pub(crate) fn take_error(&self) -> Option<std::io::Error> {
        self.last_error.lock().unwrap().take()
    }
}

impl Drop for Flusher {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn run_background(weak: &Weak<InMemoryFS>, wakeup: &Arc<(Mutex<Wakeup>, Condvar)>, interval: Option<Duration>) {
    let (lock, cvar) = &**wakeup;
    let mut delay = interval;
    loop {
        {
            let mut state = lock.lock().unwrap();
            while !state.stop && !state.wake {
                match delay {
                    Some(d) => {
                        let (guard, timeout) = cvar.wait_timeout(state, d).unwrap();
                        state = guard;
                        if timeout.timed_out() {
                            break;
                        }
                    }
                    None => state = cvar.wait(state).unwrap(),
                }
            }
            if state.stop {
                return;
            }
            state.wake = false;
        }

        // Dropped between the wake-up and here: nothing left to flush into.
        let Some(fs) = weak.upgrade() else { return };
        // Back off briefly rather than sitting out the whole interval, so a transient
        // failure does not strand committed mutations in the queue.
        delay = match fs.run_flush_cycle() {
            Ok(()) => interval,
            Err(e) => {
                log::error!("Flush cycle failed: {}", e);
                Some(RETRY_DELAY)
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::SystemClock;
    use crate::fs::InMemoryFS;
    use crate::log::LogWriter;
    use crate::operations::read_write::{create_core, write_core};
    use crate::storage::Storage;

    fn test_fs() -> Arc<InMemoryFS> {
        let storage: Arc<dyn Storage> = Arc::new(crate::storage::MemoryStorage::new());
        let clock = SystemClock;
        let writer = Arc::new(
            LogWriter::create(
                storage,
                1,
                &clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                crate::crypto::VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        Arc::new(InMemoryFS::with_log(writer))
    }

    fn stage_a_write(fs: &InMemoryFS, name: &str) {
        let file = create_core(fs, 1, name, 0o644, 0, 1000, 1000).unwrap();
        write_core(fs, file.ino, b"payload", 0).unwrap();
    }

    #[test]
    fn test_background_flusher_drains_queue_when_notified() {
        let fs = test_fs();
        // No inactivity interval: the only thing that can drain this queue is the notify.
        fs.flusher.start(&fs, None);

        stage_a_write(&fs, "notified.bin");
        assert!(fs.freeze_now());
        assert_eq!(fs.flush_queue_depth(), 1);

        fs.flusher.notify();
        assert!(crate::wait_until(
            || fs.flush_queue_depth() == 0,
            Duration::from_secs(3)
        ));
        fs.destroy();
    }

    #[test]
    fn test_background_flusher_flushes_live_after_inactivity() {
        let fs = test_fs();
        fs.flusher.start(&fs, Some(Duration::from_millis(50)));

        // Left in `live`, well below any staged threshold, and never frozen by the writer:
        // only the inactivity tick can move it.
        stage_a_write(&fs, "idle.bin");
        assert!(fs.staged_bytes() > 0);

        assert!(crate::wait_until(
            || fs.staged_bytes() == 0 && fs.flush_queue_depth() == 0,
            Duration::from_secs(3)
        ));
        fs.destroy();
    }

    #[test]
    fn test_quiesce_waits_for_the_background_flusher_to_drain() {
        let fs = test_fs();
        fs.flusher.start(&fs, None);

        stage_a_write(&fs, "queued.bin");
        assert!(fs.freeze_now());
        stage_a_write(&fs, "still-live.bin");

        // Returns only once both the queued batch and the still-live write are on disk.
        fs.quiesce().unwrap();
        assert_eq!(fs.flush_queue_depth(), 0);
        assert_eq!(fs.staged_bytes(), 0);
        fs.destroy();
    }

    #[test]
    fn test_flusher_thread_does_not_keep_the_filesystem_alive() {
        let fs = test_fs();
        fs.flusher.start(&fs, Some(Duration::from_millis(20)));
        let weak = Arc::downgrade(&fs);

        // Joins the thread, so nothing holds an upgraded reference by the time we drop.
        fs.destroy();
        drop(fs);

        assert!(
            weak.upgrade().is_none(),
            "flusher thread must hold a Weak reference, not an Arc"
        );
    }
}
