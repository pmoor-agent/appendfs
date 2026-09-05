use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

#[derive(Default)]
struct FlusherState {
    stop: bool,
    triggered: bool,
}

/// Background thread manager that periodically triggers a flush routine.
pub struct BackgroundFlusher {
    state: Arc<(Mutex<FlusherState>, Condvar)>,
    thread_handle: Option<JoinHandle<()>>,
}

impl BackgroundFlusher {
    /// Starts a periodic background flusher thread that runs every `interval`.
    pub fn start<F>(flush_fn: F, interval: Duration) -> Self
    where
        F: Fn() -> std::io::Result<()> + Send + 'static,
    {
        let pair = Arc::new((Mutex::new(FlusherState::default()), Condvar::new()));
        let pair_clone = Arc::clone(&pair);

        let handle = thread::spawn(move || {
            let (lock, cvar) = &*pair_clone;
            let mut state = lock.lock().unwrap();
            while !state.stop {
                if !state.triggered {
                    let result = cvar.wait_timeout(state, interval).unwrap();
                    state = result.0;
                }
                state.triggered = false;
                if !state.stop {
                    drop(state);
                    if let Err(e) = flush_fn() {
                        log::error!("Background flush failed: {}", e);
                    }
                    state = lock.lock().unwrap();
                }
            }
        });

        Self {
            state: pair,
            thread_handle: Some(handle),
        }
    }

    /// Wakes up the background flusher thread immediately to execute a flush cycle
    /// without waiting for the next periodic interval timeout.
    pub fn trigger(&self) {
        let (lock, cvar) = &*self.state;
        let mut state = lock.lock().unwrap();
        state.triggered = true;
        cvar.notify_one();
    }

    /// Signals the background flusher thread to exit immediately and joins it.
    pub fn stop(&mut self) {
        let (lock, cvar) = &*self.state;
        let mut state = lock.lock().unwrap();
        if !state.stop {
            state.stop = true;
            cvar.notify_all();
        }
        drop(state);

        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for BackgroundFlusher {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn test_background_flusher_periodic_trigger() {
        let count = Arc::new(AtomicUsize::new(0));
        let count_clone = Arc::clone(&count);

        let mut flusher = BackgroundFlusher::start(
            move || {
                count_clone.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            Duration::from_millis(50),
        );

        assert!(crate::wait_until(
            || count.load(Ordering::SeqCst) >= 2,
            Duration::from_secs(3)
        ));

        flusher.stop();
    }

    #[test]
    fn test_background_flusher_manual_trigger() {
        let count = Arc::new(AtomicUsize::new(0));
        let count_clone = Arc::clone(&count);

        // Long periodic interval (10 seconds)
        let mut flusher = BackgroundFlusher::start(
            move || {
                count_clone.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            Duration::from_secs(10),
        );

        assert_eq!(count.load(Ordering::SeqCst), 0);

        // Trigger manually
        flusher.trigger();
        assert!(crate::wait_until(
            || count.load(Ordering::SeqCst) == 1,
            Duration::from_secs(3)
        ));

        flusher.trigger();
        assert!(crate::wait_until(
            || count.load(Ordering::SeqCst) == 2,
            Duration::from_secs(3)
        ));

        flusher.stop();
    }
}
