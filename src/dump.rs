use crate::log::record::{
    BatchCommitPayload, CreatePayload, FILE_HEADER_SIZE, FileHeader, LinkPayload,
    MkdirPayload, OpCode, RECORD_HEADER_SIZE, RecordHeader,
    RenamePayload, RmdirPayload, SetattrPayload, SymlinkPayload, UnlinkPayload, WriteMeta,
    checksum_payload,
};
use std::fmt::Write as FmtWrite;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::time::SystemTime;

/// Represents the status of a single decoded record or EOF anomaly.
#[derive(Debug, Clone)]
pub enum DumpRecordEntry {
    Valid {
        offset: u64,
        header: RecordHeader,
        payload: Vec<u8>,
        is_committed: bool,
    },
    TornRecord {
        offset: u64,
        reason: String,
        partial_bytes: Vec<u8>,
    },
}

/// Statistics collected for a single OpCode.
#[derive(Debug, Default, Clone)]
pub struct OpCodeStats {
    pub count: usize,
    pub payload_bytes: u64,
}

/// Bucket for the write payload size histogram.
#[derive(Debug, Clone)]
pub struct WriteBucket {
    pub label: &'static str,
    pub min_bytes: u64,
    pub max_bytes: u64,
    pub count: usize,
    pub total_bytes: u64,
}

impl WriteBucket {
    pub fn new(label: &'static str, min_bytes: u64, max_bytes: u64) -> Self {
        Self {
            label,
            min_bytes,
            max_bytes,
            count: 0,
            total_bytes: 0,
        }
    }

    pub fn matches(&self, size: u64) -> bool {
        size >= self.min_bytes && size <= self.max_bytes
    }

    pub fn add(&mut self, size: u64) {
        self.count += 1;
        self.total_bytes += size;
    }
}

/// Reads and analyzes a single `.log` file, formatting the output based on `verbosity`:
/// - `verbosity == 0`: High-level summary, flush counts, OpCode breakdown, and write histogram.
/// - `verbosity == 1`: Summary + all individual records (write payloads summarized by length).
/// - `verbosity >= 2`: Summary + all records + full hex/ASCII data dumps for writes.
pub fn dump_log_file(path: impl AsRef<Path>, verbosity: u8) -> io::Result<String> {
    let path = path.as_ref();
    let mut file = File::open(path)?;
    let file_len = file.metadata()?.len();

    if file_len < FILE_HEADER_SIZE as u64 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!(
                "Log file {:?} is smaller than the 24-byte FileHeader ({} bytes)",
                path, file_len
            ),
        ));
    }

    let mut header_buf = [0u8; FILE_HEADER_SIZE];
    file.read_exact(&mut header_buf)?;
    let file_header = FileHeader::from_bytes(&header_buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let mut records: Vec<DumpRecordEntry> = Vec::new();
    let mut current_offset = FILE_HEADER_SIZE as u64;

    let mut op_counts: [OpCodeStats; 11] = Default::default();
    let mut write_buckets = vec![
        WriteBucket::new("< 64 B", 0, 63),
        WriteBucket::new("64 B .. 511 B", 64, 511),
        WriteBucket::new("512 B .. 4 KiB", 512, 4095),
        WriteBucket::new("4 KiB .. 64 KiB", 4096, 65535),
        WriteBucket::new("64 KiB .. 1 MiB", 65536, 1048575),
        WriteBucket::new("> 1 MiB", 1048576, u64::MAX),
    ];

    let mut total_flush_batches = 0usize;
    let mut total_data_bytes = 0u64;
    let mut uncommitted_records_count = 0usize;

    // First pass: Read all records and detect batch commit boundaries
    let mut last_commit_idx: Option<usize> = None;

    while current_offset < file_len {
        let remaining_file_bytes = file_len - current_offset;
        if remaining_file_bytes < RECORD_HEADER_SIZE as u64 {
            let mut partial = vec![0u8; remaining_file_bytes as usize];
            let _ = file.read_exact(&mut partial);
            records.push(DumpRecordEntry::TornRecord {
                offset: current_offset,
                reason: format!(
                    "Truncated record header ({} of {} bytes present at EOF)",
                    remaining_file_bytes, RECORD_HEADER_SIZE
                ),
                partial_bytes: partial,
            });
            break;
        }

        let record_offset = current_offset;
        let mut rec_hdr_buf = [0u8; RECORD_HEADER_SIZE];
        if let Err(e) = file.read_exact(&mut rec_hdr_buf) {
            records.push(DumpRecordEntry::TornRecord {
                offset: record_offset,
                reason: format!("Failed reading record header: {}", e),
                partial_bytes: Vec::new(),
            });
            break;
        }

        let header = match RecordHeader::from_bytes(&rec_hdr_buf) {
            Ok(h) => h,
            Err(e) => {
                records.push(DumpRecordEntry::TornRecord {
                    offset: record_offset,
                    reason: format!("Corrupted record header: {}", e),
                    partial_bytes: rec_hdr_buf.to_vec(),
                });
                break;
            }
        };

        let available_payload = file_len.saturating_sub(record_offset + RECORD_HEADER_SIZE as u64);
        if (available_payload as u64) < header.payload_len as u64 {
            let mut partial = vec![0u8; available_payload as usize];
            let _ = file.read_exact(&mut partial);
            records.push(DumpRecordEntry::TornRecord {
                offset: record_offset,
                reason: format!(
                    "Truncated record payload ({} of {} bytes present at EOF)",
                    available_payload, header.payload_len
                ),
                partial_bytes: partial,
            });
            break;
        }

        let mut payload = vec![0u8; header.payload_len as usize];
        if let Err(e) = file.read_exact(&mut payload) {
            records.push(DumpRecordEntry::TornRecord {
                offset: record_offset,
                reason: format!("Failed reading full payload: {}", e),
                partial_bytes: Vec::new(),
            });
            break;
        }

        if checksum_payload(&payload) != header.checksum {
            records.push(DumpRecordEntry::TornRecord {
                offset: record_offset,
                reason: "Payload BLAKE3 checksum mismatch (corrupted / bitrot)".to_string(),
                partial_bytes: payload,
            });
            break;
        }

        let is_commit = header.op_code == OpCode::BatchCommit;
        let rec_idx = records.len();
        records.push(DumpRecordEntry::Valid {
            offset: record_offset,
            header,
            payload: payload.clone(),
            is_committed: false, // will update below
        });

        current_offset += RECORD_HEADER_SIZE as u64 + header.payload_len as u64;

        let op_idx = header.op_code as usize;
        if op_idx < op_counts.len() {
            op_counts[op_idx].count += 1;
            op_counts[op_idx].payload_bytes += header.payload_len as u64;
        }

        if header.op_code == OpCode::Write {
            let mut cursor = std::io::Cursor::new(&payload);
            if let Ok(_meta) = bincode::deserialize_from::<_, WriteMeta>(&mut cursor) {
                let meta_bytes = cursor.position() as usize;
                let data_len = payload.len().saturating_sub(meta_bytes) as u64;
                for b in &mut write_buckets {
                    if b.matches(data_len) {
                        b.add(data_len);
                        break;
                    }
                }
                total_data_bytes += data_len;
            }
        }

        if is_commit {
            total_flush_batches += 1;
            // Mark all preceding records up to this commit as committed
            let start = last_commit_idx.map_or(0, |i| i + 1);
            for r in &mut records[start..=rec_idx] {
                if let DumpRecordEntry::Valid { is_committed, .. } = r {
                    *is_committed = true;
                }
            }
            last_commit_idx = Some(rec_idx);
        }
    }

    // Count uncommitted trailing records
    let start_uncommitted = last_commit_idx.map_or(0, |i| i + 1);
    for r in &records[start_uncommitted..] {
        if matches!(r, DumpRecordEntry::Valid { .. }) {
            uncommitted_records_count += 1;
        }
    }

    let mut out = String::new();
    writeln!(out, "=== appendfs Log File Dump ===").unwrap();
    writeln!(out, "File:                {:?}", path).unwrap();
    writeln!(out, "Generation:          {}", file_header.generation).unwrap();
    writeln!(out, "Format Version:      {}", file_header.version).unwrap();
    writeln!(
        out,
        "Created At:          {}",
        format_system_time(file_header.created_at)
    )
    .unwrap();
    writeln!(out, "File Size:           {}", format_bytes(file_len)).unwrap();
    writeln!(
        out,
        "Total Valid Records: {}",
        records
            .iter()
            .filter(|r| matches!(r, DumpRecordEntry::Valid { .. }))
            .count()
    )
    .unwrap();
    writeln!(
        out,
        "Total Data Payload:  {}",
        format_bytes(total_data_bytes)
    )
    .unwrap();
    writeln!(out).unwrap();

    // Flush batch statistics
    writeln!(out, "--- Flush Batch Statistics ---").unwrap();
    writeln!(
        out,
        "Committed Flushes:   {}",
        total_flush_batches
    )
    .unwrap();
    if total_flush_batches > 0 {
        let avg_records = (records.len().saturating_sub(uncommitted_records_count)) as f64
            / total_flush_batches as f64;
        let avg_data = total_data_bytes as f64 / total_flush_batches as f64;
        writeln!(
            out,
            "Avg Records / Flush: {:.1}",
            avg_records
        )
        .unwrap();
        writeln!(
            out,
            "Avg Data / Flush:    {}",
            format_bytes(avg_data as u64)
        )
        .unwrap();
    }
    if uncommitted_records_count > 0 {
        writeln!(
            out,
            "Trailing Batch:      {} UNCOMMITTED records (interrupted flush before BatchCommit)",
            uncommitted_records_count
        )
        .unwrap();
    } else {
        writeln!(
            out,
            "Trailing Batch:      None (cleanly committed at EOF)"
        )
        .unwrap();
    }
    writeln!(out).unwrap();

    // OpCode breakdown table
    writeln!(out, "--- Record Breakdown by OpCode ---").unwrap();
    writeln!(
        out,
        "{:<14} {:>10} {:>14} {:>12}",
        "OP CODE", "COUNT", "TOTAL BYTES", "% OF RECORDS"
    )
    .unwrap();
    writeln!(
        out,
        "{:-<14} {:-<10} {:-<14} {:-<12}",
        "", "", "", ""
    )
    .unwrap();

    let total_valid = records
        .iter()
        .filter(|r| matches!(r, DumpRecordEntry::Valid { .. }))
        .count();

    for code in 1..=10u8 {
        if let Ok(opcode) = OpCode::try_from(code) {
            let stats = &op_counts[code as usize];
            let pct = if total_valid > 0 {
                stats.count as f64 / total_valid as f64 * 100.0
            } else {
                0.0
            };
            let pct_str = format!("{:.1}%", pct);
            writeln!(
                out,
                "{:<14} {:>10} {:>14} {:>12}",
                opcode,
                stats.count,
                format_bytes(stats.payload_bytes),
                pct_str
            )
            .unwrap();
        }
    }
    writeln!(out).unwrap();

    // Write size histogram
    let total_writes = op_counts[OpCode::Write as usize].count;
    if total_writes > 0 {
        writeln!(out, "--- Write Payload Size Histogram ---").unwrap();
        writeln!(
            out,
            "{:<18} {:>8} {:>14}   {}",
            "SIZE RANGE", "COUNT", "TOTAL BYTES", "DISTRIBUTION"
        )
        .unwrap();
        writeln!(
            out,
            "{:-<18} {:-<8} {:-<14}   {:-<20}",
            "", "", "", ""
        )
        .unwrap();

        for b in &write_buckets {
            let pct = (b.count as f64 / total_writes as f64) * 100.0;
            let bar_len = (pct / 5.0).round() as usize;
            let bar: String = "█".repeat(bar_len);
            writeln!(
                out,
                "{:<18} {:>8} {:>14}   {:<20} ({:.1}%)",
                b.label,
                b.count,
                format_bytes(b.total_bytes),
                bar,
                pct
            )
            .unwrap();
        }
        writeln!(out).unwrap();
    }

    // Detail record stream for verbosity >= 1
    if verbosity >= 1 {
        writeln!(out, "=== Sequential Record Stream ===").unwrap();
        for (i, entry) in records.iter().enumerate() {
            match entry {
                DumpRecordEntry::Valid {
                    offset,
                    header,
                    payload,
                    is_committed,
                } => {
                    let commit_tag = if *is_committed {
                        "[COMMITTED]"
                    } else {
                        "[UNCOMMITTED TRAILING BATCH]"
                    };

                    writeln!(
                        out,
                        "#{:<5} [0x{:08x} / {:<8}] {:<14} inode {:<5} tx {:<5} len {:<8} checksum {:02x}{:02x}{:02x}{:02x} {}",
                        i + 1,
                        offset,
                        offset,
                        header.op_code,
                        header.inode,
                        header.tx_id,
                        format_bytes(header.payload_len as u64),
                        header.checksum[0],
                        header.checksum[1],
                        header.checksum[2],
                        header.checksum[3],
                        commit_tag,
                    )
                    .unwrap();

                    // Decode payload details
                    format_payload_details(&mut out, header.op_code, payload, verbosity >= 2);
                }
                DumpRecordEntry::TornRecord {
                    offset,
                    reason,
                    partial_bytes,
                } => {
                    writeln!(
                        out,
                        "#{:<5} [0x{:08x} / {:<8}] *** TORN RECORD / ANOMALY AT EOF ***",
                        i + 1,
                        offset,
                        offset
                    )
                    .unwrap();
                    writeln!(out, "      Error: {}", reason).unwrap();
                    if !partial_bytes.is_empty() && verbosity >= 2 {
                        writeln!(out, "      Partial Bytes ({} bytes):", partial_bytes.len())
                            .unwrap();
                        out.push_str(&format_hexdump(partial_bytes, 256));
                    }
                }
            }
        }
    }

    Ok(out)
}

fn format_payload_details(out: &mut String, opcode: OpCode, payload: &[u8], dump_data_hex: bool) {
    match opcode {
        OpCode::Create => {
            if let Ok(c) = bincode::deserialize::<CreatePayload>(payload) {
                writeln!(
                    out,
                    "      parent: {}, name: {:?}, mode: 0o{:o}, uid: {}, gid: {}, created_at: {}",
                    c.parent,
                    c.name,
                    c.mode,
                    c.uid,
                    c.gid,
                    format_system_time(c.created_at)
                )
                .unwrap();
            } else {
                writeln!(out, "      [Failed to deserialize CreatePayload]").unwrap();
            }
        }
        OpCode::Mkdir => {
            if let Ok(m) = bincode::deserialize::<MkdirPayload>(payload) {
                writeln!(
                    out,
                    "      parent: {}, name: {:?}, mode: 0o{:o}, uid: {}, gid: {}, created_at: {}",
                    m.parent,
                    m.name,
                    m.mode,
                    m.uid,
                    m.gid,
                    format_system_time(m.created_at)
                )
                .unwrap();
            } else {
                writeln!(out, "      [Failed to deserialize MkdirPayload]").unwrap();
            }
        }
        OpCode::Write => {
            let mut cursor = std::io::Cursor::new(payload);
            if let Ok(w) = bincode::deserialize_from::<_, WriteMeta>(&mut cursor) {
                let meta_bytes = cursor.position() as usize;
                let data_slice = if payload.len() >= meta_bytes {
                    &payload[meta_bytes..]
                } else {
                    &[]
                };
                writeln!(
                    out,
                    "      file_offset: {}, data_len: {}, op_time: {}",
                    w.file_offset,
                    format_bytes(data_slice.len() as u64),
                    format_system_time(w.op_time)
                )
                .unwrap();

                if dump_data_hex && !data_slice.is_empty() {
                    out.push_str(&format_hexdump(data_slice, 256));
                }
            } else {
                writeln!(out, "      [Failed to deserialize WriteMeta]").unwrap();
            }
        }
        OpCode::Unlink => {
            if let Ok(u) = bincode::deserialize::<UnlinkPayload>(payload) {
                writeln!(
                    out,
                    "      parent: {}, name: {:?}, op_time: {}",
                    u.parent,
                    u.name,
                    format_system_time(u.op_time)
                )
                .unwrap();
            } else {
                writeln!(out, "      [Failed to deserialize UnlinkPayload]").unwrap();
            }
        }
        OpCode::Rmdir => {
            if let Ok(r) = bincode::deserialize::<RmdirPayload>(payload) {
                writeln!(
                    out,
                    "      parent: {}, name: {:?}, op_time: {}",
                    r.parent,
                    r.name,
                    format_system_time(r.op_time)
                )
                .unwrap();
            } else {
                writeln!(out, "      [Failed to deserialize RmdirPayload]").unwrap();
            }
        }
        OpCode::Symlink => {
            if let Ok(s) = bincode::deserialize::<SymlinkPayload>(payload) {
                writeln!(
                    out,
                    "      parent: {}, name: {:?}, target: {:?}, uid: {}, gid: {}, created_at: {}",
                    s.parent,
                    s.name,
                    s.target,
                    s.uid,
                    s.gid,
                    format_system_time(s.created_at)
                )
                .unwrap();
            } else {
                writeln!(out, "      [Failed to deserialize SymlinkPayload]").unwrap();
            }
        }
        OpCode::Rename => {
            if let Ok(r) = bincode::deserialize::<RenamePayload>(payload) {
                writeln!(
                    out,
                    "      parent: {}, name: {:?} -> new_parent: {}, new_name: {:?}, op_time: {}",
                    r.parent,
                    r.name,
                    r.new_parent,
                    r.new_name,
                    format_system_time(r.op_time)
                )
                .unwrap();
            } else {
                writeln!(out, "      [Failed to deserialize RenamePayload]").unwrap();
            }
        }
        OpCode::Setattr => {
            if let Ok(s) = bincode::deserialize::<SetattrPayload>(payload) {
                let mut changes = Vec::new();
                if let Some(m) = s.mode {
                    changes.push(format!("mode: 0o{:o}", m));
                }
                if let Some(u) = s.uid {
                    changes.push(format!("uid: {}", u));
                }
                if let Some(g) = s.gid {
                    changes.push(format!("gid: {}", g));
                }
                if let Some(sz) = s.size {
                    changes.push(format!("size: {}", sz));
                }
                if let Some(a) = s.atime {
                    changes.push(format!("atime: {}", format_system_time(a)));
                }
                if let Some(m) = s.mtime {
                    changes.push(format!("mtime: {}", format_system_time(m)));
                }
                writeln!(
                    out,
                    "      changes: [{}], op_time: {}",
                    changes.join(", "),
                    format_system_time(s.op_time)
                )
                .unwrap();
            } else {
                writeln!(out, "      [Failed to deserialize SetattrPayload]").unwrap();
            }
        }
        OpCode::Link => {
            if let Ok(l) = bincode::deserialize::<LinkPayload>(payload) {
                writeln!(
                    out,
                    "      target_ino: {}, new_parent: {}, new_name: {:?}, op_time: {}",
                    l.ino,
                    l.new_parent,
                    l.new_name,
                    format_system_time(l.op_time)
                )
                .unwrap();
            } else {
                writeln!(out, "      [Failed to deserialize LinkPayload]").unwrap();
            }
        }
        OpCode::BatchCommit => {
            if let Ok(b) = bincode::deserialize::<BatchCommitPayload>(payload) {
                writeln!(
                    out,
                    "      batch_record_count: {}, commit_timestamp: {}",
                    b.record_count,
                    format_system_time(b.timestamp)
                )
                .unwrap();
            } else {
                writeln!(out, "      [Failed to deserialize BatchCommitPayload]").unwrap();
            }
        }
    }
}

/// Formats a byte slice into standard 16-bytes-per-line hex and ASCII dump.
pub fn format_hexdump(data: &[u8], max_bytes: usize) -> String {
    let mut out = String::new();
    let display_len = std::cmp::min(data.len(), max_bytes);
    for chunk_offset in (0..display_len).step_by(16) {
        let chunk_end = std::cmp::min(chunk_offset + 16, display_len);
        let chunk = &data[chunk_offset..chunk_end];

        let _ = write!(out, "      {:08x}  ", chunk_offset);

        for i in 0..16 {
            if i == 8 {
                out.push(' ');
            }
            if chunk_offset + i < chunk_end {
                let _ = write!(out, "{:02x} ", chunk[i]);
            } else {
                out.push_str("   ");
            }
        }

        out.push_str(" |");
        for &b in chunk {
            if b.is_ascii_graphic() || b == b' ' {
                out.push(b as char);
            } else {
                out.push('.');
            }
        }
        out.push_str("|\n");
    }
    if data.len() > max_bytes {
        let _ = writeln!(
            out,
            "      ... [{} more data bytes omitted]",
            data.len() - max_bytes
        );
    }
    out
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if bytes >= GB {
        format!("{:.2} GiB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MiB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KiB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

fn format_system_time(time: SystemTime) -> String {
    crate::clock::format_local_civil_time(time)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::{Clock, SystemClock};
    use crate::log::LogWriter;
    use tempfile::tempdir;

    #[test]
    fn test_dump_log_file_summary_and_verbosity() {
        let dir = tempdir().unwrap();
        let clock = SystemClock;
        let writer = LogWriter::create(dir.path(), 1, &clock).unwrap();

        // Write Create record
        let create_p = CreatePayload {
            parent: 1,
            name: "test.txt".to_string(),
            mode: 0o644,
            uid: 1000,
            gid: 1000,
            created_at: clock.now(),
        };
        let create_bytes = bincode::serialize(&create_p).unwrap();
        writer
            .append_record(OpCode::Create, 2, &create_bytes)
            .unwrap();

        // Write Write record with 100 bytes
        let write_m = WriteMeta {
            file_offset: 0,
            op_time: clock.now(),
        };
        let mut write_bytes = bincode::serialize(&write_m).unwrap();
        write_bytes.extend_from_slice(&vec![0x42; 100]);
        writer
            .append_record(OpCode::Write, 2, &write_bytes)
            .unwrap();

        // Commit batch
        writer.emit_batch_commit(2, &clock).unwrap();
        drop(writer);

        let log_path = dir.path().join("000001.log");
        assert!(log_path.exists());

        // Level 0: Summary
        let summary_dump = dump_log_file(&log_path, 0).unwrap();
        assert!(summary_dump.contains("Total Valid Records: 3"));
        assert!(summary_dump.contains("Committed Flushes:   1"));
        assert!(summary_dump.contains("Trailing Batch:      None"));
        assert!(summary_dump.contains("Write"));
        assert!(summary_dump.contains("64 B .. 511 B"));

        // Level 1: Records
        let v1_dump = dump_log_file(&log_path, 1).unwrap();
        assert!(v1_dump.contains("Sequential Record Stream"));
        assert!(v1_dump.contains("Create"));
        assert!(v1_dump.contains("Write"));
        assert!(v1_dump.contains("BatchCommit"));
        assert!(v1_dump.contains("[COMMITTED]"));

        // Level 2: Full Hex
        let v2_dump = dump_log_file(&log_path, 2).unwrap();
        assert!(v2_dump.contains("42 42 42 42"));
    }

    #[test]
    fn test_dump_log_file_detects_interrupted_flush_trailing_records() {
        let dir = tempdir().unwrap();
        let clock = SystemClock;
        let writer = LogWriter::create(dir.path(), 1, &clock).unwrap();

        // Write Create and Write records WITHOUT BatchCommit trailer
        let create_p = CreatePayload {
            parent: 1,
            name: "uncommitted.txt".to_string(),
            mode: 0o644,
            uid: 1000,
            gid: 1000,
            created_at: clock.now(),
        };
        let create_bytes = bincode::serialize(&create_p).unwrap();
        writer
            .append_record(OpCode::Create, 2, &create_bytes)
            .unwrap();
        drop(writer);

        let log_path = dir.path().join("000001.log");
        let dump = dump_log_file(&log_path, 1).unwrap();
        assert!(dump.contains("Trailing Batch:      1 UNCOMMITTED records"));
        assert!(dump.contains("[UNCOMMITTED TRAILING BATCH]"));
    }
}
