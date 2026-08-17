use crate::cli::DEFAULT_MAX_LOG_SIZE;
use crate::clock::Clock;
use crate::log::record::{
    BatchCommitPayload, FILE_HEADER_SIZE, FileHeader, OpCode, RECORD_HEADER_SIZE, RecordHeader,
};
use std::fs::{File, OpenOptions, create_dir_all};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

struct ActiveLogFile {
    file: File,
    generation: u64,
    current_offset: u64,
    log_path: PathBuf,
}

/// Active log writer managing append-only writes to generation log files with automatic rolling.
pub struct LogWriter {
    active_file: Mutex<ActiveLogFile>,
    tx_id: AtomicU64,
    log_dir: PathBuf,
    max_log_size: u64,
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
        create_dir_all(&log_dir)?;

        let filename = format!("{:06}.log", generation);
        let log_path = log_dir.join(filename);

        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&log_path)?;

        let now_unix = clock
            .now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let file_header = FileHeader::new(generation, now_unix);
        file.write_all(&file_header.to_bytes())?;
        file.flush()?;

        let active_file = ActiveLogFile {
            file,
            generation,
            current_offset: FILE_HEADER_SIZE as u64,
            log_path,
        };

        Ok(Self {
            active_file: Mutex::new(active_file),
            tx_id: AtomicU64::new(start_tx_id),
            log_dir,
            max_log_size,
        })
    }

    /// Rolls to a new generation log file if the active file, having already been
    /// written up to its current offset, would exceed `max_log_size` upon receiving
    /// at least `estimated_additional_bytes` more.
    ///
    /// Must be called at most once per flush batch, *before* writing any
    /// of that batch's records - never mid-batch. `append_record` itself never rolls,
    /// so a whole batch (its records plus its `BatchCommit` trailer) always lands in
    /// exactly one generation file, which is what lets recovery treat "buffer records
    /// since the last commit" as a purely per-file operation, never needing to carry
    /// state across a generation boundary. The tradeoff: a single large batch can push
    /// a generation file somewhat past `max_log_size`.
    pub fn roll_if_needed(
        &self,
        estimated_additional_bytes: u64,
        clock: &dyn Clock,
    ) -> io::Result<()> {
        let mut active = match self.active_file.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };

        if active.current_offset <= FILE_HEADER_SIZE as u64
            || active.current_offset + estimated_additional_bytes <= self.max_log_size
        {
            return Ok(());
        }

        active.file.flush()?;
        active.file.sync_data()?;

        let next_gen = active.generation + 1;
        let next_filename = format!("{:06}.log", next_gen);
        let next_path = self.log_dir.join(next_filename);

        let mut next_file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&next_path)?;

        let now_unix = clock
            .now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let file_header = FileHeader::new(next_gen, now_unix);
        next_file.write_all(&file_header.to_bytes())?;
        next_file.flush()?;

        log::info!(
            "Rolled log file to generation {} ({:?})",
            next_gen,
            next_path
        );

        active.file = next_file;
        active.generation = next_gen;
        active.current_offset = FILE_HEADER_SIZE as u64;
        active.log_path = next_path;

        Ok(())
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
        let total_bytes = RECORD_HEADER_SIZE + payload.len();

        let mut active = match self.active_file.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };

        let record_log_offset = active.current_offset;
        active.file.write_all(&header_bytes)?;
        if !payload.is_empty() {
            active.file.write_all(payload)?;
        }
        active.current_offset += total_bytes as u64;

        let generation = active.generation;
        Ok((tx, generation, record_log_offset))
    }

    /// Emits the `OpCode::BatchCommit` trailer confirming `record_count` records
    /// (everything since the previous commit) as a complete, replay-safe batch.
    pub fn emit_batch_commit(&self, record_count: u32, clock: &dyn Clock) -> io::Result<u64> {
        let now = clock.now();
        let commit_payload = BatchCommitPayload {
            timestamp: now,
            record_count,
        };

        let payload_bytes = bincode::serialize(&commit_payload)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let (tx, _, _) = self.append_record(OpCode::BatchCommit, 0, &payload_bytes)?;
        Ok(tx)
    }

    /// Flushes unwritten internal buffers to the OS page cache.
    pub fn flush(&self) -> io::Result<()> {
        let mut active = match self.active_file.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        active.file.flush()
    }

    /// Performs a physical hardware disk sync (`fsync` / `fdatasync`).
    pub fn sync(&self) -> io::Result<()> {
        let mut active = match self.active_file.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        active.file.flush()?;
        active.file.sync_data()
    }

    /// Returns the active generation sequence number.
    pub fn generation(&self) -> u64 {
        let active = match self.active_file.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        active.generation
    }

    /// Returns the filesystem path to the active log file.
    pub fn path(&self) -> PathBuf {
        let active = match self.active_file.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        active.log_path.clone()
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
    fn test_emit_batch_commit_round_trip() {
        let dir = tempdir().unwrap();
        let clock = SystemClock;
        let writer = LogWriter::create(dir.path(), 1, &clock).unwrap();

        writer.append_record(OpCode::Create, 1, b"payload").unwrap();
        writer.append_record(OpCode::Write, 1, b"more").unwrap();
        writer.emit_batch_commit(2, &clock).unwrap();

        let records: Vec<_> = LogReader::open(writer.path())
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(records.len(), 3);
        assert_eq!(records[2].header.op_code, OpCode::BatchCommit);
        let payload: BatchCommitPayload = bincode::deserialize(&records[2].payload).unwrap();
        assert_eq!(payload.record_count, 2);
    }
}
