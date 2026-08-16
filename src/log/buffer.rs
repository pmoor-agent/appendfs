use crate::log::extent::SharedExtentState;
use crate::log::record::{BatchCommitPayload, OpCode, RECORD_HEADER_SIZE, WriteMeta};
use crate::log::writer::LogWriter;
use crate::range_map::{RangeMap, RangeValue};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Condvar, Mutex};

/// Default threshold to trigger size-based auto-flushing (4 MiB).
pub const DEFAULT_FLUSH_THRESHOLD: u64 = 4 * 1024 * 1024;

/// Default maximum allowed pending bytes before back-pressure stalling (32 MiB).
pub const DEFAULT_MAX_PENDING_BYTES: u64 = 32 * 1024 * 1024;

/// Staged mutation in memory awaiting flush to `LogWriter`.
pub enum StagedMutation {
    Op {
        op_code: OpCode,
        inode: u64,
        payload: Vec<u8>,
    },
    Write {
        inode: u64,
        file_offset: u64,
        shared_state: SharedExtentState,
        data: Arc<Vec<u8>>,
        // Full (untruncated) BLAKE3 hash of `data`, computed at ingestion time (right
        // when the FUSE write() handler received these bytes) - see the chain-verify
        // check in `flush()`. Kept in memory only; the on-disk record checksum is a
        // separate, truncated value computed at flush time in `LogWriter::append_record`.
        ingest_checksum: blake3::Hash,
        // Wall-clock time this write happened (ingestion time, not flush time) -
        // carried into WriteMeta so recovery can apply it to mtime/ctime instead of
        // stamping the replay time.
        op_time: (i64, u32),
    },
}

#[derive(Default)]
struct ActiveBatch {
    mutations: Vec<StagedMutation>,
}

/// Marks which `batch.mutations` index currently "owns" a byte range, for the sole
/// purpose of `fully_superseded_within_batch`'s local simulation below. Carries no
/// position-relative data, so trimming it is a no-op - it's always the same
/// originating mutation regardless of how much of its range survives.
#[derive(Clone, Copy)]
struct BatchOwner(usize);

impl RangeValue for BatchOwner {
    fn trim_right(&mut self, _new_len: u64) {}
    fn trim_left(&mut self, _shift: u64) {}
}

/// Double-buffered staging buffer managing in-memory mutations, range maps, auto-flushes,
/// and back-pressure write stalling.
pub struct LogBuffer {
    active_batch: Mutex<ActiveBatch>,
    pending_bytes: Mutex<u64>,
    backpressure_condvar: Condvar,
    flush_threshold: u64,
    max_pending_bytes: u64,
    // Held for the full duration of `flush()`, not just batch extraction. Guarantees
    // at most one flush is ever physically writing to the log file at a time, so a
    // batch's records and its trailing BatchCommit always form one uninterrupted run -
    // required for the commit-count in that trailer to be unambiguous. Concurrent
    // flush() calls (e.g. a background timer racing an explicit fsync) simply queue
    // here; new writers staging into the *next* batch are unaffected.
    flush_lock: Mutex<()>,
}

impl LogBuffer {
    pub fn new() -> Self {
        Self::with_thresholds(DEFAULT_FLUSH_THRESHOLD, DEFAULT_MAX_PENDING_BYTES)
    }

    pub fn with_thresholds(flush_threshold: u64, max_pending_bytes: u64) -> Self {
        Self {
            active_batch: Mutex::new(ActiveBatch::default()),
            pending_bytes: Mutex::new(0),
            backpressure_condvar: Condvar::new(),
            flush_threshold,
            max_pending_bytes,
            flush_lock: Mutex::new(()),
        }
    }

    /// Returns the current total pending staged bytes in memory.
    pub fn pending_bytes(&self) -> u64 {
        *self.pending_bytes.lock().unwrap()
    }

    /// Enforces back-pressure stalling if total pending bytes exceed `max_pending_bytes`.
    fn check_backpressure(&self, new_bytes: u64) {
        let mut pending = self.pending_bytes.lock().unwrap();
        while *pending + new_bytes > self.max_pending_bytes {
            log::trace!(
                "Back-pressure stalling write, pending_bytes={}, max={}",
                *pending,
                self.max_pending_bytes
            );
            pending = self.backpressure_condvar.wait(pending).unwrap();
        }
        *pending += new_bytes;
    }

    /// Stages a metadata operation and triggers an auto-flush if `flush_threshold` is reached.
    pub fn stage_op(
        &self,
        op_code: OpCode,
        inode: u64,
        payload: Vec<u8>,
        log_writer: Option<&LogWriter>,
    ) {
        let bytes_len = payload.len() as u64;
        self.check_backpressure(bytes_len);

        let should_flush = {
            let mut guard = self.active_batch.lock().unwrap();
            guard.mutations.push(StagedMutation::Op {
                op_code,
                inode,
                payload,
            });
            let pending = self.pending_bytes.lock().unwrap();
            *pending >= self.flush_threshold
        };

        if should_flush {
            if let Some(writer) = log_writer {
                let _ = self.flush(writer);
            }
        }
    }

    /// Stages a file write operation and triggers an auto-flush if `flush_threshold` is reached.
    ///
    /// `ingest_checksum` must be computed by the caller over `data` as early as
    /// possible - ideally right where the raw bytes are first received from FUSE,
    /// before this staged copy could be affected by any later in-memory corruption.
    /// `flush()` recomputes and compares it immediately before writing, as a
    /// chain-verify check independent of the on-disk record checksum.
    pub fn stage_write(
        &self,
        inode: u64,
        file_offset: u64,
        shared_state: SharedExtentState,
        data: Arc<Vec<u8>>,
        ingest_checksum: blake3::Hash,
        op_time: (i64, u32),
        log_writer: Option<&LogWriter>,
    ) {
        let bytes_len = data.len() as u64;
        self.check_backpressure(bytes_len);

        let should_flush = {
            let mut guard = self.active_batch.lock().unwrap();
            guard.mutations.push(StagedMutation::Write {
                inode,
                file_offset,
                shared_state,
                data,
                ingest_checksum,
                op_time,
            });
            let pending = self.pending_bytes.lock().unwrap();
            *pending >= self.flush_threshold
        };

        if should_flush {
            if let Some(writer) = log_writer {
                let _ = self.flush(writer);
            }
        }
    }

    /// Returns the `batch.mutations` indices of Write mutations that are fully covered
    /// by a strictly later Write mutation to the same inode, *within this same slice*.
    ///
    /// This deliberately never looks at the live, globally-shared `RangeMap`: another
    /// write staged into a *later* (not-yet-flushed) batch could concurrently
    /// supersede one of these writes without being part of this flush at all - eliding
    /// on that signal would let this flush report success having durably written
    /// neither the superseded write's bytes nor its replacement's, silently losing
    /// data despite the caller being told the flush succeeded. Restricting this to
    /// positions within `mutations` guarantees that whatever supersedes an elided
    /// write is written in this exact call, before it can return successfully.
    fn fully_superseded_within_batch(mutations: &[StagedMutation]) -> HashSet<usize> {
        let mut by_inode: HashMap<u64, Vec<(usize, u64, u64)>> = HashMap::new();
        for (i, m) in mutations.iter().enumerate() {
            if let StagedMutation::Write {
                inode,
                file_offset,
                data,
                ..
            } = m
            {
                by_inode
                    .entry(*inode)
                    .or_default()
                    .push((i, *file_offset, data.len() as u64));
            }
        }

        let mut elided = HashSet::new();
        for writes in by_inode.into_values() {
            if writes.len() < 2 {
                continue; // nothing else in this batch could possibly supersede a lone write
            }
            // Simulate just this inode's writes from this batch, in original staging
            // order, to see what each one's range resolves to once later writes in
            // the same batch have landed on top of it.
            let mut local: RangeMap<BatchOwner> = RangeMap::new();
            for &(i, offset, len) in &writes {
                local.insert(offset, len, BatchOwner(i));
            }
            for &(i, offset, len) in &writes {
                let survives = local
                    .query(offset, len)
                    .into_iter()
                    .any(|(_, _, owner)| owner.0 == i);
                if !survives {
                    elided.insert(i);
                }
            }
        }
        elided
    }

    /// Estimates the total bytes this batch (its records plus its trailing
    /// `BatchCommit`) is about to append, for `LogWriter::roll_if_needed` - elided
    /// writes contribute nothing, since they're never physically written.
    fn estimate_batch_bytes(mutations: &[StagedMutation], elided: &HashSet<usize>) -> u64 {
        let write_meta_size = bincode::serialize(&WriteMeta {
            file_offset: 0,
            op_time: (0, 0),
        })
        .map(|b| b.len())
        .unwrap_or(0) as u64;
        let trailer_payload_size = bincode::serialize(&BatchCommitPayload {
            timestamp_sec: 0,
            timestamp_nsec: 0,
            record_count: 0,
        })
        .map(|b| b.len())
        .unwrap_or(0) as u64;

        let mut total = RECORD_HEADER_SIZE as u64 + trailer_payload_size;
        for (i, m) in mutations.iter().enumerate() {
            match m {
                StagedMutation::Op { payload, .. } => {
                    total += RECORD_HEADER_SIZE as u64 + payload.len() as u64;
                }
                StagedMutation::Write { data, .. } if !elided.contains(&i) => {
                    total += RECORD_HEADER_SIZE as u64 + write_meta_size + data.len() as u64;
                }
                StagedMutation::Write { .. } => {}
            }
        }
        total
    }

    /// Flushes all staged in-memory mutations into `log_writer`, transitioning extent states
    /// from `Staged` to `Disk` and unblocking stalled writers.
    pub fn flush(&self, log_writer: &LogWriter) -> std::io::Result<()> {
        // Serializes this flush against any other concurrently-running flush() call, so
        // this batch's records and its trailing BatchCommit always land as one
        // uninterrupted run in the log file - see the flush_lock field doc.
        let _flush_guard = self.flush_lock.lock().unwrap();

        let batch = {
            let mut guard = self.active_batch.lock().unwrap();
            if guard.mutations.is_empty() {
                return Ok(());
            }
            std::mem::take(&mut *guard)
        };

        let clock = crate::clock::SystemClock;
        let mut bytes_flushed = 0u64;
        let elided = Self::fully_superseded_within_batch(&batch.mutations);

        // Roll to a new generation file now, if needed, based on an estimate of what
        // this whole batch (records + trailer) is about to write - never mid-batch,
        // so the batch always lands entirely in one generation file. Elided writes
        // contribute nothing (they're never physically written).
        let estimated_bytes = Self::estimate_batch_bytes(&batch.mutations, &elided);
        log_writer.roll_if_needed(estimated_bytes, &clock)?;

        let mut written_count: u32 = 0;

        for (i, mutation) in batch.mutations.into_iter().enumerate() {
            match mutation {
                StagedMutation::Op {
                    op_code,
                    inode,
                    payload,
                } => {
                    bytes_flushed += payload.len() as u64;
                    log_writer.append_record(op_code, inode, &payload)?;
                    written_count += 1;
                }
                StagedMutation::Write {
                    inode,
                    file_offset,
                    shared_state,
                    data,
                    ingest_checksum,
                    op_time,
                } => {
                    // Byte accounting always reflects what was staged, regardless of
                    // whether we end up physically writing it below - this is what
                    // check_backpressure counted when the write was staged.
                    bytes_flushed += data.len() as u64;

                    if elided.contains(&i) {
                        continue;
                    }

                    // Chain-verify: these bytes must be identical to what was received
                    // at ingestion. A mismatch means something corrupted them while
                    // sitting in memory waiting to be flushed - writing them now would
                    // produce a record whose on-disk checksum matches itself perfectly
                    // (computed from the already-corrupted bytes), making the
                    // corruption permanently undetectable from that point on. There is
                    // no recovery path from proven in-memory corruption, so this is a
                    // hard stop rather than an error to propagate and continue past.
                    let current_hash = blake3::hash(&data);
                    if current_hash != ingest_checksum {
                        panic!(
                            "in-memory corruption detected before flush: staged write for inode {} at offset {} (len {}) no longer matches its ingestion-time checksum (expected {}, computed {})",
                            inode,
                            file_offset,
                            data.len(),
                            ingest_checksum,
                            current_hash
                        );
                    }

                    let write_meta = WriteMeta {
                        file_offset,
                        op_time,
                    };
                    let mut payload = bincode::serialize(&write_meta)
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

                    let meta_size = payload.len() as u32; // Offset after WriteMeta
                    payload.extend_from_slice(&data);

                    let (_, generation, record_log_offset) =
                        log_writer.append_record(OpCode::Write, inode, &payload)?;
                    written_count += 1;

                    // Resolves the shared write slot, making every RangeMap fragment
                    // derived from this write visible as Disk in one update - including
                    // any that were split off (forked) before this flush ran.
                    shared_state.resolve_write(generation, record_log_offset, meta_size);
                }
            }
        }

        // Trailer goes LAST, after every other record in this batch: its presence (and
        // matching record_count) is what tells recovery this whole run is complete and
        // safe to replay. A crash before this point leaves a trailing, uncommitted run
        // that recovery must discard rather than partially apply.
        log_writer.emit_batch_commit(written_count, &clock)?;

        log_writer.flush()?;

        // Subtract flushed bytes and unblock writers stalled on back-pressure
        {
            let mut pending = self.pending_bytes.lock().unwrap();
            if *pending >= bytes_flushed {
                *pending -= bytes_flushed;
            } else {
                *pending = 0;
            }
            self.backpressure_condvar.notify_all();
        }

        Ok(())
    }
}

impl Default for LogBuffer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::SystemClock;
    use crate::log::ExtentState;
    use tempfile::tempdir;

    #[test]
    fn test_log_buffer_staging_and_flush() {
        let dir = tempdir().unwrap();
        let clock = SystemClock;
        let writer = LogWriter::create(dir.path(), 1, &clock).unwrap();
        let buffer = LogBuffer::new();

        let data = Arc::new(vec![1, 2, 3, 4, 5]);
        let shared_state = SharedExtentState::new_staged(Arc::clone(&data), 0, 5);
        let checksum = blake3::hash(&data);

        buffer.stage_write(10, 0, shared_state.clone(), data, checksum, (0, 0), None);

        assert!(matches!(
            shared_state.read_state(),
            ExtentState::Staged { .. }
        ));

        buffer.flush(&writer).unwrap();

        assert!(matches!(
            shared_state.read_state(),
            ExtentState::Disk { .. }
        ));
    }

    #[test]
    fn test_size_based_auto_flush() {
        let dir = tempdir().unwrap();
        let clock = SystemClock;
        let writer = LogWriter::create(dir.path(), 1, &clock).unwrap();

        // 100 byte threshold
        let buffer = LogBuffer::with_thresholds(100, 1000);

        let data = Arc::new(vec![0u8; 150]);
        let shared_state = SharedExtentState::new_staged(Arc::clone(&data), 0, 150);
        let checksum = blake3::hash(&data);

        // Staging 150 bytes should cross the 100 byte threshold and trigger auto-flush
        buffer.stage_write(
            10,
            0,
            shared_state.clone(),
            data,
            checksum,
            (0, 0),
            Some(&writer),
        );

        // State should automatically transition to Disk
        assert!(matches!(
            shared_state.read_state(),
            ExtentState::Disk { .. }
        ));
    }

    #[test]
    #[should_panic(expected = "in-memory corruption detected")]
    fn test_flush_panics_on_ingest_checksum_mismatch() {
        let dir = tempdir().unwrap();
        let clock = SystemClock;
        let writer = LogWriter::create(dir.path(), 1, &clock).unwrap();
        let buffer = LogBuffer::new();

        let data = Arc::new(vec![1, 2, 3, 4, 5]);
        let shared_state = SharedExtentState::new_staged(Arc::clone(&data), 0, 5);
        // Deliberately wrong checksum - simulates the data having been corrupted in
        // memory sometime after ingestion but before flush.
        let wrong_checksum = blake3::hash(b"not the staged bytes");

        buffer.stage_write(10, 0, shared_state, data, wrong_checksum, (0, 0), None);
        let _ = buffer.flush(&writer);
    }
}
