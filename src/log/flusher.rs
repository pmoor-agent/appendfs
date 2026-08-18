use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Background thread manager that periodically triggers a flush routine.
pub struct BackgroundFlusher {
    stop_signal: Arc<(Mutex<bool>, Condvar)>,
    thread_handle: Option<JoinHandle<()>>,
}

impl BackgroundFlusher {
    /// Starts a periodic background flusher thread that runs every `interval`.
    pub fn start<F>(flush_fn: F, interval: Duration) -> Self
    where
        F: Fn() -> std::io::Result<()> + Send + 'static,
    {
        let pair = Arc::new((Mutex::new(false), Condvar::new()));
        let pair_clone = Arc::clone(&pair);

        let handle = thread::spawn(move || {
            let (lock, cvar) = &*pair_clone;
            let mut stop = lock.lock().unwrap();
            while !*stop {
                let result = cvar.wait_timeout(stop, interval).unwrap();
                stop = result.0;
                if !*stop && let Err(e) = flush_fn() {
                    log::error!("Background flush failed: {}", e);
                }
            }
        });

        Self {
            stop_signal: pair,
            thread_handle: Some(handle),
        }
    }

    /// Signals the background flusher thread to exit immediately and joins it.
    pub fn stop(&mut self) {
        let (lock, cvar) = &*self.stop_signal;
        let mut stop = lock.lock().unwrap();
        if !*stop {
            *stop = true;
            cvar.notify_all();
        }
        drop(stop);

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

        thread::sleep(Duration::from_millis(150));

        assert!(count.load(Ordering::SeqCst) >= 2);

        flusher.stop();
    }
}
