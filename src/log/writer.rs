use crate::cli::DEFAULT_MAX_LOG_SIZE;
use crate::clock::Clock;
use crate::log::record::{FILE_HEADER_SIZE, FileHeader, FlushCommitPayload, OpCode, RecordHeader};
use std::fs::{File, OpenOptions, create_dir_all};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

struct ActiveLogFile {
    file: File,
    generation: u64,
    current_offset: u64,
    log_path: PathBuf,
}

enum ActiveLogState {
    Unopened { generation: u64 },
    Open(ActiveLogFile),
}

fn open_generation_file(
    log_dir: &Path,
    generation: u64,
    clock: &dyn Clock,
) -> io::Result<ActiveLogFile> {
    create_dir_all(log_dir)?;

    let filename = format!("{:06}.log", generation);
    let log_path = log_dir.join(filename);

    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&log_path)?;

    let now = clock.now();
    let file_header = FileHeader::new(generation, now);
    file.write_all(&file_header.to_bytes())?;
    file.flush()?;

    Ok(ActiveLogFile {
        file,
        generation,
        current_offset: FILE_HEADER_SIZE as u64,
        log_path,
    })
}

/// Active log writer managing append-only writes to generation log files with automatic rolling.
pub struct LogWriter {
    active_state: Mutex<ActiveLogState>,
    tx_id: AtomicU64,
    log_dir: PathBuf,
    max_log_size: u64,
    #[cfg(test)]
    pub fault_after_bytes: AtomicU64,
}

impl LogWriter {
    /// Creates a new generation log file inside `log_dir` with default 1 GiB max log size limit.
    pub fn create(
        log_dir: impl AsRef<Path>,
        generation: u64,
        clock: &dyn Clock,
    ) -> io::Result<Self> {
        Self::create_with_max_size(log_dir, generation, clock, DEFAULT_MAX_LOG_SIZE)
    }

    /// Creates a new generation log file inside `log_dir` with a custom maximum log file size.
    pub fn create_with_max_size(
        log_dir: impl AsRef<Path>,
        generation: u64,
        clock: &dyn Clock,
        max_log_size: u64,
    ) -> io::Result<Self> {
        Self::create_with_max_size_and_start_tx(log_dir, generation, clock, max_log_size, 1)
    }

    /// Creates a new generation log file with custom max log size and initial `tx_id`.
    pub fn create_with_max_size_and_start_tx(
        log_dir: impl AsRef<Path>,
        generation: u64,
        clock: &dyn Clock,
        max_log_size: u64,
        start_tx_id: u64,
    ) -> io::Result<Self> {
        let log_dir = log_dir.as_ref().to_path_buf();
        let active_file = open_generation_file(&log_dir, generation, clock)?;

        Ok(Self {
            active_state: Mutex::new(ActiveLogState::Open(active_file)),
            tx_id: AtomicU64::new(start_tx_id),
            log_dir,
            max_log_size,
            #[cfg(test)]
            fault_after_bytes: AtomicU64::new(0),
        })
    }

    /// Creates a lazy log writer that does NOT create a `.log` file on disk until the first write.
    pub fn create_lazy(
        log_dir: impl AsRef<Path>,
        generation: u64,
        max_log_size: u64,
        start_tx_id: u64,
    ) -> Self {
        let log_dir = log_dir.as_ref().to_path_buf();
        Self {
            active_state: Mutex::new(ActiveLogState::Unopened { generation }),
            tx_id: AtomicU64::new(start_tx_id),
            log_dir,
            max_log_size,
            #[cfg(test)]
            fault_after_bytes: AtomicU64::new(0),
        }
    }

    /// Returns `true` if a physical `.log` file has been created on disk.
    pub fn is_open(&self) -> bool {
        let state = match self.active_state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        matches!(*state, ActiveLogState::Open(_))
    }

    /// Rolls to a new generation log file (or opens the initial lazy log file) if needed.
    ///
    /// - If currently unopened (lazy), opens generation `generation` on disk and returns `Some(generation)`.
    /// - If open and the active file would exceed `max_log_size` upon receiving `estimated_additional_bytes`,
    ///   rolls to `generation + 1` and returns `Some(generation + 1)`.
    /// - Otherwise returns `None`.
    pub fn roll_if_needed(
        &self,
        estimated_additional_bytes: u64,
        clock: &dyn Clock,
    ) -> io::Result<Option<u64>> {
        let mut state = match self.active_state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };

        match &mut *state {
            ActiveLogState::Unopened { generation } => {
                let gen_num = *generation;
                let active_file = open_generation_file(&self.log_dir, gen_num, clock)?;
                *state = ActiveLogState::Open(active_file);
                log::info!(
                    "Lazily opened initial log file for generation {} in {:?}",
                    gen_num,
                    self.log_dir
                );
                Ok(Some(gen_num))
            }
            ActiveLogState::Open(active) => {
                if active.current_offset <= FILE_HEADER_SIZE as u64
                    || active.current_offset + estimated_additional_bytes <= self.max_log_size
                {
                    return Ok(None);
                }

                active.file.flush()?;
                active.file.sync_data()?;

                let next_gen = active.generation + 1;
                let next_active = open_generation_file(&self.log_dir, next_gen, clock)?;

                log::info!(
                    "Rolled log file to generation {} ({:?})",
                    next_gen,
                    next_active.log_path
                );

                *active = next_active;
                Ok(Some(next_gen))
            }
        }
    }

    /// Appends a record (`RecordHeader` + payload bytes) to the active log file.
    /// Never rolls to a new generation file - see `roll_if_needed`.
    /// Returns `(tx_id, generation, record_log_offset)`.
    pub fn append_record(
        &self,
        op_code: OpCode,
        inode: u64,
        payload: &[u8],
    ) -> io::Result<(u64, u64, u64)> {
        let tx = self.tx_id.fetch_add(1, Ordering::SeqCst);
        let header = RecordHeader {
            op_code,
            tx_id: tx,
            inode,
            payload_len: payload.len() as u32,
            checksum: crate::log::record::checksum_payload(payload),
        };
        let header_bytes = header.to_bytes();
        let total_bytes = header_bytes.len() + payload.len();

        let mut state = match self.active_state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };

        let active = match &mut *state {
            ActiveLogState::Open(a) => a,
            ActiveLogState::Unopened { generation } => {
                let gen_num = *generation;
                let active_file =
                    open_generation_file(&self.log_dir, gen_num, &crate::clock::SystemClock)?;
                *state = ActiveLogState::Open(active_file);
                match &mut *state {
                    ActiveLogState::Open(a) => a,
                    _ => unreachable!(),
                }
            }
        };

        let record_log_offset = active.current_offset;
        let write_result = (|| -> io::Result<()> {
            #[cfg(test)]
            {
                let limit = self.fault_after_bytes.load(Ordering::SeqCst);
                if limit > 0 && record_log_offset + total_bytes as u64 > limit {
                    // Write partial header bytes to disk to simulate a torn mid-record write
                    let _ = active
                        .file
                        .write_all(&header_bytes[..header_bytes.len() / 2]);
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "simulated ENOSPC / EFBIG mid-record write",
                    ));
                }
            }
            active.file.write_all(&header_bytes)?;
            if !payload.is_empty() {
                active.file.write_all(payload)?;
            }
            Ok(())
        })();

        if let Err(e) = write_result {
            let _ = active.file.set_len(record_log_offset);
            let _ = active.file.seek(SeekFrom::Start(record_log_offset));
            active.current_offset = record_log_offset;
            return Err(e);
        }

        active.current_offset += total_bytes as u64;

        let generation = active.generation;
        Ok((tx, generation, record_log_offset))
    }

    /// Rolls back the active log file to `offset` if it is currently in `generation`
    /// and its offset is past `offset`. Truncates the underlying file on disk and seeks back.
    pub fn rollback_to(&self, generation: u64, offset: u64) -> io::Result<()> {
        let mut state = match self.active_state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        if let ActiveLogState::Open(active) = &mut *state {
            if active.generation == generation && active.current_offset > offset {
                let _ = active.file.set_len(offset);
                let _ = active.file.seek(SeekFrom::Start(offset));
                active.current_offset = offset;
            }
        }
        Ok(())
    }

    /// Emits the `OpCode::FlushCommit` trailer confirming `record_count` records
    /// (everything since the previous commit) as a complete, replay-safe batch.
    pub fn emit_flush_commit(&self, record_count: u32, clock: &dyn Clock) -> io::Result<u64> {
        let now = clock.now();
        let commit_payload = FlushCommitPayload {
            timestamp: now,
            record_count,
        };

        let payload_bytes = bincode::serialize(&commit_payload)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let (tx, _, _) = self.append_record(OpCode::FlushCommit, 0, &payload_bytes)?;
        Ok(tx)
    }

    /// Flushes unwritten internal buffers to the OS page cache.
    pub fn flush(&self) -> io::Result<()> {
        let mut state = match self.active_state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        if let ActiveLogState::Open(active) = &mut *state {
            active.file.flush()
        } else {
            Ok(())
        }
    }

    /// Performs a physical hardware disk sync (`fsync` / `fdatasync`).
    pub fn sync(&self) -> io::Result<()> {
        let mut state = match self.active_state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        if let ActiveLogState::Open(active) = &mut *state {
            active.file.flush()?;
            active.file.sync_all()
        } else {
            Ok(())
        }
    }

    /// Returns the active generation sequence number.
    pub fn generation(&self) -> u64 {
        let state = match self.active_state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        match &*state {
            ActiveLogState::Unopened { generation } => *generation,
            ActiveLogState::Open(active) => active.generation,
        }
    }

    /// Returns the current byte offset of the active log file.
    pub fn current_offset(&self) -> u64 {
        let state = match self.active_state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        match &*state {
            ActiveLogState::Unopened { .. } => 0,
            ActiveLogState::Open(active) => active.current_offset,
        }
    }

    /// Returns the filesystem path to the active log file.
    pub fn path(&self) -> PathBuf {
        let state = match self.active_state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        match &*state {
            ActiveLogState::Unopened { generation } => {
                self.log_dir.join(format!("{:06}.log", generation))
            }
            ActiveLogState::Open(active) => active.log_path.clone(),
        }
    }

    /// Returns the last transaction ID assigned by this writer.
    pub fn last_tx_id(&self) -> u64 {
        self.tx_id.load(Ordering::SeqCst).saturating_sub(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::SystemClock;
    use crate::log::reader::LogReader;
    use tempfile::tempdir;

    #[test]
    fn test_log_writer_create_and_append() {
        let dir = tempdir().unwrap();
        let clock = SystemClock;
        let writer = LogWriter::create(dir.path(), 1, &clock).unwrap();

        assert_eq!(writer.generation(), 1);
        let (tx, gen_num, offset) = writer
            .append_record(OpCode::Create, 100, b"test_data")
            .unwrap();
        assert_eq!(tx, 1);
        assert_eq!(gen_num, 1);
        assert_eq!(offset, FILE_HEADER_SIZE as u64);
    }

    #[test]
    fn test_append_record_never_rolls_mid_batch() {
        let dir = tempdir().unwrap();
        let clock = SystemClock;
        // Tiny max size: a single record already exceeds it.
        let writer = LogWriter::create_with_max_size(dir.path(), 1, &clock, 30).unwrap();

        // Without an explicit roll_if_needed call, append_record must keep appending
        // to generation 1 regardless of exceeding max_log_size.
        for _ in 0..5 {
            let (_, gen_num, _) = writer
                .append_record(OpCode::Create, 1, b"0123456789")
                .unwrap();
            assert_eq!(gen_num, 1);
        }
        assert_eq!(writer.generation(), 1);
    }

    #[test]
    fn test_roll_if_needed_rolls_between_batches() {
        let dir = tempdir().unwrap();
        let clock = SystemClock;
        let writer = LogWriter::create_with_max_size(dir.path(), 1, &clock, 60).unwrap();

        writer
            .append_record(OpCode::Create, 1, b"0123456789")
            .unwrap();
        assert_eq!(writer.generation(), 1);

        // Estimate for the next batch would exceed max_log_size - rolls now, before
        // any of the next batch's records are written.
        writer.roll_if_needed(1000, &clock).unwrap();
        assert_eq!(writer.generation(), 2);

        let (_, gen_num, _) = writer
            .append_record(OpCode::Create, 2, b"0123456789")
            .unwrap();
        assert_eq!(gen_num, 2);
    }

    #[test]
    fn test_emit_flush_commit_round_trip() {
        let dir = tempdir().unwrap();
        let clock = SystemClock;
        let writer = LogWriter::create(dir.path(), 1, &clock).unwrap();

        writer.append_record(OpCode::Create, 1, b"payload").unwrap();
        writer.append_record(OpCode::Write, 1, b"more").unwrap();
        writer.emit_flush_commit(2, &clock).unwrap();

        let records: Vec<_> = LogReader::open(writer.path())
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(records.len(), 3);
        assert_eq!(records[2].header.op_code, OpCode::FlushCommit);
        let payload: FlushCommitPayload = bincode::deserialize(&records[2].payload).unwrap();
        assert_eq!(payload.record_count, 2);
    }

    #[test]
    fn test_lazy_log_writer_creates_no_file_until_first_write() {
        let dir = tempdir().unwrap();
        let clock = SystemClock;
        let writer = LogWriter::create_lazy(dir.path(), 1, DEFAULT_MAX_LOG_SIZE, 1);

        assert!(!writer.is_open());
        assert_eq!(writer.generation(), 1);
        let expected_path = dir.path().join("000001.log");
        assert!(
            !expected_path.exists(),
            "lazy writer must not create a file on disk yet"
        );

        // Calling roll_if_needed opens the initial generation on disk
        let opened_gen = writer.roll_if_needed(100, &clock).unwrap();
        assert_eq!(opened_gen, Some(1));
        assert!(writer.is_open());
        assert!(expected_path.exists(), "file must now exist on disk");

        // Subsequent roll_if_needed within limits does not roll
        let no_roll = writer.roll_if_needed(100, &clock).unwrap();
        assert_eq!(no_roll, None);
    }
}
