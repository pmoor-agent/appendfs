use crate::log::buffer::LogBuffer;
use crate::log::writer::LogWriter;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Background thread manager that periodically flushes `LogBuffer` data to `LogWriter`.
pub struct BackgroundFlusher {
    stop_signal: Arc<(Mutex<bool>, Condvar)>,
    thread_handle: Option<JoinHandle<()>>,
}

impl BackgroundFlusher {
    /// Starts a periodic background flusher thread that runs every `interval`.
    pub fn start(
        log_buffer: Arc<LogBuffer>,
        log_writer: Arc<LogWriter>,
        interval: Duration,
    ) -> Self {
        let pair = Arc::new((Mutex::new(false), Condvar::new()));
        let pair_clone = Arc::clone(&pair);

        let handle = thread::spawn(move || {
            let (lock, cvar) = &*pair_clone;
            let mut stop = lock.lock().unwrap();
            while !*stop {
                let result = cvar.wait_timeout(stop, interval).unwrap();
                stop = result.0;
                if !*stop {
                    if let Err(e) = log_buffer.flush(&log_writer) {
                        log::error!("Background flush failed: {}", e);
                    }
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
    use crate::clock::SystemClock;
    use crate::log::record::OpCode;
    use tempfile::tempdir;

    #[test]
    fn test_background_flusher_periodic_trigger() {
        let dir = tempdir().unwrap();
        let clock = SystemClock;
        let writer = Arc::new(LogWriter::create(dir.path(), 1, &clock).unwrap());
        let buffer = Arc::new(LogBuffer::new());

        // Stage an operation
        buffer.stage_op(OpCode::Mkdir, 2, vec![1, 2, 3], None);
        assert_eq!(buffer.pending_bytes(), 3);

        // Start flusher with a 50ms interval
        let mut flusher = BackgroundFlusher::start(
            Arc::clone(&buffer),
            Arc::clone(&writer),
            Duration::from_millis(50),
        );

        // Wait for flusher thread to wake up and flush
        thread::sleep(Duration::from_millis(150));

        assert_eq!(buffer.pending_bytes(), 0);

        flusher.stop();
    }
}
