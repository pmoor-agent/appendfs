use crate::log::ExtentState;
use crate::log::record::{
    DecodedPayload, FILE_HEADER_SIZE, FileHeader, OpCode, RECORD_HEADER_SIZE, RecordHeader, checksum_payload,
};
use crate::log::summary::{SUMMARY_MAGIC, SummaryReader};
use crate::node::NodeKind;
use crate::storage::{OsStorage, Storage, StorageReader};
use std::collections::{HashMap, VecDeque};
use std::fmt::Write as FmtWrite;
use std::io;
use std::path::Path;
use std::time::SystemTime;

/// Dispatches dumping from a `Storage` instance based on magic bytes or extension.
pub fn dump_file_with_storage(storage: &dyn Storage, filename: &str, verbosity: u8) -> io::Result<String> {
    let reader = storage.open_reader(filename)?;
    let mut magic = [0u8; 4];
    if reader.len()? < 4 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("File {:?} is too small ({} bytes)", filename, reader.len()?),
        ));
    }
    reader.read_exact_at(0, &mut magic)?;

    if magic == crate::log::record::FILE_MAGIC || filename.ends_with(".log") {
        dump_log_reader_with_path(reader.as_ref(), Some(filename), verbosity)
    } else if &magic == SUMMARY_MAGIC || filename.ends_with(".summary") {
        dump_summary_file_with_storage(storage, filename, verbosity)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Unrecognized file format for {:?} (expected .log with APPF magic or .summary with APPS magic)",
                filename
            ),
        ))
    }
}

/// Dispatches dumping to either `dump_log_file` or `dump_summary_file` based on magic bytes or extension.
pub fn dump_file(path: impl AsRef<Path>, verbosity: u8) -> io::Result<String> {
    let path = path.as_ref();
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let filename = path.file_name().and_then(|s| s.to_str()).unwrap_or("").to_string();
    let storage = OsStorage::new(parent);
    dump_file_with_storage(&storage, &filename, verbosity)
}

/// Bucket for the extents per file fragmentation histogram.
#[derive(Debug, Clone)]
pub struct ExtentsBucket {
    pub label: &'static str,
    pub min: usize,
    pub max: usize,
    pub count: usize,
}

impl ExtentsBucket {
    pub fn new(label: &'static str, min: usize, max: usize) -> Self {
        Self {
            label,
            min,
            max,
            count: 0,
        }
    }

    pub fn matches(&self, extents: usize) -> bool {
        extents >= self.min && extents <= self.max
    }
}

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
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let filename = path.file_name().and_then(|s| s.to_str()).unwrap_or("").to_string();
    let storage = OsStorage::new(parent);
    let reader = storage.open_reader(&filename)?;
    dump_log_reader_with_path(reader.as_ref(), Some(&path.to_string_lossy()), verbosity)
}

/// Reads and analyzes a `.log` file from a `StorageReader`.
pub fn dump_log_reader(reader: &dyn StorageReader, verbosity: u8) -> io::Result<String> {
    dump_log_reader_with_path(reader, None, verbosity)
}

pub fn dump_log_reader_with_path(
    reader: &dyn StorageReader,
    display_path: Option<&str>,
    verbosity: u8,
) -> io::Result<String> {
    let file_len = reader.len()?;

    if file_len < FILE_HEADER_SIZE as u64 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!(
                "Log file {:?} is smaller than the 24-byte FileHeader ({} bytes)",
                display_path.unwrap_or("<log>"),
                file_len
            ),
        ));
    }

    let mut header_buf = [0u8; FILE_HEADER_SIZE];
    reader.read_exact_at(0, &mut header_buf)?;
    let file_header = FileHeader::from_bytes(&header_buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

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
            let _ = reader.read_exact_at(current_offset, &mut partial);
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
        if let Err(e) = reader.read_exact_at(record_offset, &mut rec_hdr_buf) {
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
        if available_payload < header.payload_len as u64 {
            let mut partial = vec![0u8; available_payload as usize];
            let _ = reader.read_exact_at(record_offset + RECORD_HEADER_SIZE as u64, &mut partial);
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
        if let Err(e) = reader.read_exact_at(record_offset + RECORD_HEADER_SIZE as u64, &mut payload) {
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

        let is_commit = header.op_code == OpCode::FlushCommit;
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

        let log_rec = crate::log::reader::LogRecord {
            header,
            payload: payload.clone(),
            record_log_offset: record_offset,
        };
        if let Ok(DecodedPayload::Write { data, .. }) = log_rec.decode() {
            let data_len = data.len() as u64;
            for b in &mut write_buckets {
                if b.matches(data_len) {
                    b.add(data_len);
                    break;
                }
            }
            total_data_bytes += data_len;
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
    if let Some(p) = display_path {
        writeln!(out, "File:                {:?}", p).unwrap();
    } else {
        writeln!(out, "File:                <in-memory>").unwrap();
    }
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
    writeln!(out, "Total Data Payload:  {}", format_bytes(total_data_bytes)).unwrap();
    writeln!(out).unwrap();

    // Flush batch statistics
    writeln!(out, "--- Flush Batch Statistics ---").unwrap();
    writeln!(out, "Committed Flushes:   {}", total_flush_batches).unwrap();
    if total_flush_batches > 0 {
        let avg_records = (records.len().saturating_sub(uncommitted_records_count)) as f64 / total_flush_batches as f64;
        let avg_data = total_data_bytes as f64 / total_flush_batches as f64;
        writeln!(out, "Avg Records / Flush: {:.1}", avg_records).unwrap();
        writeln!(out, "Avg Data / Flush:    {}", format_bytes(avg_data as u64)).unwrap();
    }
    if uncommitted_records_count > 0 {
        writeln!(
            out,
            "Trailing Batch:      {} UNCOMMITTED records (interrupted flush before FlushCommit)",
            uncommitted_records_count
        )
        .unwrap();
    } else {
        writeln!(out, "Trailing Batch:      None (cleanly committed at EOF)").unwrap();
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
    writeln!(out, "{:-<14} {:-<10} {:-<14} {:-<12}", "", "", "", "").unwrap();

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
            "{:<18} {:>8} {:>14}   DISTRIBUTION",
            "SIZE RANGE", "COUNT", "TOTAL BYTES"
        )
        .unwrap();
        writeln!(out, "{:-<18} {:-<8} {:-<14}   {:-<20}", "", "", "", "").unwrap();

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
                        writeln!(out, "      Partial Bytes ({} bytes):", partial_bytes.len()).unwrap();
                        out.push_str(&format_hexdump(partial_bytes, 256));
                    }
                }
            }
        }
    }

    Ok(out)
}

/// Reads and analyzes a single `.summary` snapshot file, formatting the output based on `verbosity`:
/// - `verbosity == 0`: Summary metadata, whole-file checksum, inode breakdown, extent fragmentation stats, histogram, top fragmented files, manifest table.
/// - `verbosity == 1`: Summary + complete inode listing / directory tree.
/// - `verbosity >= 2`: Summary + complete inode listing + detailed physical extent range mappings for all files.
pub fn dump_summary_file_with_storage(storage: &dyn Storage, filename: &str, verbosity: u8) -> io::Result<String> {
    let reader = SummaryReader::open_with_storage(storage, filename)?;
    dump_summary_reader_with_path(&reader, Some(filename), verbosity)
}

/// Reads and analyzes a single `.summary` snapshot file, formatting the output based on `verbosity`.
pub fn dump_summary_file(path: impl AsRef<Path>, verbosity: u8) -> io::Result<String> {
    let path = path.as_ref();
    let reader = SummaryReader::open(path)?;
    dump_summary_reader_with_path(&reader, Some(&path.to_string_lossy()), verbosity)
}

/// Reads and analyzes a `.summary` snapshot from an existing `SummaryReader`.
pub fn dump_summary_reader(reader: &SummaryReader, verbosity: u8) -> io::Result<String> {
    dump_summary_reader_with_path(reader, None, verbosity)
}

pub fn dump_summary_reader_with_path(
    reader: &SummaryReader,
    display_path: Option<&str>,
    verbosity: u8,
) -> io::Result<String> {
    let file_len = reader.reader().len()?;

    let inodes = reader.read_all_inodes()?;

    // Sort index entries by inode ascending
    let mut sorted_inodes: Vec<u64> = reader.index_entries().iter().map(|e| e.inode).collect();
    sorted_inodes.sort_unstable();

    // Inode type counters
    let mut dir_count = 0usize;
    let mut file_count = 0usize;
    let mut symlink_count = 0usize;
    let mut total_logical_bytes = 0u64;

    let mut total_file_extents = 0usize;
    let mut max_file_extents = 0usize;

    // Extents per file buckets
    let mut extent_buckets = vec![
        ExtentsBucket::new("1 extent (contiguous)", 1, 1),
        ExtentsBucket::new("2 - 4 extents", 2, 4),
        ExtentsBucket::new("5 - 16 extents", 5, 16),
        ExtentsBucket::new("17 - 64 extents", 17, 64),
        ExtentsBucket::new("> 64 extents", 65, usize::MAX),
    ];

    // File fragmentation list for top-N ranking
    struct FileFragInfo {
        inode: u64,
        size: u64,
        extents: usize,
        path: String,
    }
    let mut file_frag_list: Vec<FileFragInfo> = Vec::new();

    // Build path map by BFS traversal from root directory (inode 1)
    let mut path_map: HashMap<u64, String> = HashMap::new();
    path_map.insert(1, "/".to_string());
    let mut queue = VecDeque::new();
    queue.push_back(1u64);

    while let Some(dir_ino) = queue.pop_front() {
        let dir_path = path_map
            .get(&dir_ino)
            .cloned()
            .unwrap_or_else(|| format!("<inode {}>", dir_ino));
        if let Some(sync_node) = inodes.get(&dir_ino) {
            let node = sync_node.as_ref();
            if let NodeKind::Directory { entries, .. } = &node.kind {
                for (name, child_ino) in entries {
                    let child_path = if dir_ino == 1 {
                        format!("/{}", name)
                    } else {
                        format!("{}/{}", dir_path, name)
                    };
                    path_map.insert(*child_ino, child_path);
                    if let Some(child_sync) = inodes.get(child_ino) {
                        let child_node = child_sync.as_ref();
                        if child_node.is_dir() {
                            queue.push_back(*child_ino);
                        }
                    }
                }
            }
        }
    }

    for &ino in &sorted_inodes {
        if let Some(sync_node) = inodes.get(&ino) {
            let node = sync_node.as_ref();
            match &node.kind {
                NodeKind::Directory { .. } => {
                    dir_count += 1;
                }
                NodeKind::Symlink { .. } => {
                    symlink_count += 1;
                }
                NodeKind::File { range_map, size, .. } => {
                    file_count += 1;
                    total_logical_bytes += *size;
                    let num_extents = range_map.len();
                    total_file_extents += num_extents;
                    if num_extents > max_file_extents {
                        max_file_extents = num_extents;
                    }
                    if num_extents > 0 {
                        for b in &mut extent_buckets {
                            if b.matches(num_extents) {
                                b.count += 1;
                                break;
                            }
                        }
                    }
                    let p = path_map
                        .get(&ino)
                        .cloned()
                        .unwrap_or_else(|| format!("<inode {}>", ino));
                    file_frag_list.push(FileFragInfo {
                        inode: ino,
                        size: *size,
                        extents: num_extents,
                        path: p,
                    });
                }
                NodeKind::Fifo
                | NodeKind::CharDevice { .. }
                | NodeKind::BlockDevice { .. }
                | NodeKind::Socket => {}
            }
        }
    }

    // Sort top fragmented files
    file_frag_list.sort_by(|a, b| b.extents.cmp(&a.extents).then_with(|| b.size.cmp(&a.size)));

    let mut out = String::new();
    writeln!(out, "=== appendfs Summary File Dump ===").unwrap();
    if let Some(p) = display_path {
        writeln!(out, "File:                {:?}", p).unwrap();
    } else {
        writeln!(out, "File:                <in-memory>").unwrap();
    }
    writeln!(out, "Branch:              {}", reader.manifest.branch).unwrap();
    writeln!(out, "Generation:          {}", reader.header.generation).unwrap();
    writeln!(out, "Format Version:      {}", reader.header.version).unwrap();
    writeln!(out, "Last Transaction ID: {}", reader.header.last_tx_id).unwrap();
    writeln!(out, "Next Inode:          {}", reader.header.next_inode).unwrap();
    writeln!(out, "File Size:           {}", format_bytes(file_len)).unwrap();

    // Checksum display
    let checksum_hex = reader
        .footer
        .checksum
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    writeln!(out, "Checksum (BLAKE3):   {} (VERIFIED)", checksum_hex).unwrap();
    writeln!(out).unwrap();

    // Inode Breakdown
    writeln!(out, "--- Inode Breakdown ---").unwrap();
    writeln!(
        out,
        "Total Inodes:        {} ({} directories, {} regular files, {} symlinks)",
        sorted_inodes.len(),
        dir_count,
        file_count,
        symlink_count
    )
    .unwrap();
    writeln!(out, "Logical Data Size:   {}", format_bytes(total_logical_bytes)).unwrap();
    writeln!(out).unwrap();

    // File Extents & Fragmentation Stats
    writeln!(out, "--- File Extent & Fragmentation Statistics ---").unwrap();
    writeln!(out, "Total Regular Files: {}", file_count).unwrap();
    writeln!(out, "Total File Extents:  {}", total_file_extents).unwrap();
    let avg_extents = if file_count > 0 {
        total_file_extents as f64 / file_count as f64
    } else {
        0.0
    };
    writeln!(out, "Avg Extents / File:  {:.2}", avg_extents).unwrap();
    writeln!(out, "Max Extents in File: {}", max_file_extents).unwrap();
    writeln!(out).unwrap();

    if file_count > 0 {
        writeln!(out, "Extents / File Distribution:").unwrap();
        writeln!(
            out,
            "{:<24} {:>8} {:>12}   DISTRIBUTION",
            "EXTENTS RANGE", "FILES", "% OF FILES"
        )
        .unwrap();
        writeln!(out, "{:-<24} {:-<8} {:-<12}   {:-<20}", "", "", "", "").unwrap();

        for b in &extent_buckets {
            let pct = (b.count as f64 / file_count as f64) * 100.0;
            let bar_len = (pct / 5.0).round() as usize;
            let bar: String = "█".repeat(bar_len);
            let pct_str = format!("{:.1}%", pct);
            writeln!(out, "{:<24} {:>8} {:>12}   {:<20}", b.label, b.count, pct_str, bar).unwrap();
        }
        writeln!(out).unwrap();

        // Top fragmented files (if any have > 1 extent)
        let multi_extent_files: Vec<_> = file_frag_list.iter().filter(|f| f.extents > 1).take(5).collect();
        if !multi_extent_files.is_empty() {
            writeln!(out, "--- Top Fragmented Files ---").unwrap();
            writeln!(
                out,
                "{:<8} {:>12} {:>9} {:>16}   PATH",
                "INODE", "SIZE", "EXTENTS", "AVG EXTENT SIZE"
            )
            .unwrap();
            writeln!(out, "{:-<8} {:-<12} {:-<9} {:-<16}   {:-<30}", "", "", "", "", "").unwrap();
            for f in multi_extent_files {
                let avg_sz = if f.extents > 0 { f.size / f.extents as u64 } else { 0 };
                writeln!(
                    out,
                    "{:<8} {:>12} {:>9} {:>16}   {}",
                    f.inode,
                    format_bytes(f.size),
                    f.extents,
                    format_bytes(avg_sz),
                    f.path
                )
                .unwrap();
            }
            writeln!(out).unwrap();
        }
    }

    // Log Manifest Section
    writeln!(out, "--- Tracked Log Generations Manifest ---").unwrap();
    writeln!(
        out,
        "Next Generation:     {} ({})",
        reader.manifest.next_generation, reader.manifest.next_filename
    )
    .unwrap();
    if reader.manifest.logs.is_empty() {
        writeln!(out, "Tracked Logs:        0 active log generation files").unwrap();
    } else {
        writeln!(
            out,
            "Tracked Logs:        {} log generation files",
            reader.manifest.logs.len()
        )
        .unwrap();
        writeln!(out).unwrap();
        writeln!(
            out,
            "{:<14} {:>10} {:>12} {:>12} {:>12} {:>8} {:>12}  STATUS",
            "LOG FILE", "RECORDS", "LOG SIZE", "DATA SIZE", "LIVE DATA", "EXTENTS", "LIVE RATIO"
        )
        .unwrap();
        writeln!(
            out,
            "{:-<14} {:-<10} {:-<12} {:-<12} {:-<12} {:-<8} {:-<12}  {:-<24}",
            "", "", "", "", "", "", "", ""
        )
        .unwrap();

        // Compute live bytes and extents from snapshot inodes
        let mut live_map: HashMap<u64, (u64, u32)> = HashMap::new();
        for sync_node in inodes.values() {
            let node = sync_node.as_ref();
            if let NodeKind::File { range_map, .. } = &node.kind {
                for (_, entry) in range_map.iter() {
                    if let ExtentState::Disk { generation, length, .. } = entry.value.read_state() {
                        let stats = live_map.entry(generation).or_insert((0, 0));
                        stats.0 += length as u64;
                        stats.1 += 1;
                    }
                }
            }
        }

        for g in &reader.manifest.logs {
            let (live_bytes, live_extents) = live_map.get(&g.generation).copied().unwrap_or((0, 0));
            let live_ratio = if g.total_data_bytes > 0 {
                live_bytes as f64 / g.total_data_bytes as f64
            } else {
                0.0
            };
            let (status, ratio_str) =
                crate::stats::format_generation_status(g.total_data_bytes, live_bytes, live_ratio, g.record_count);
            writeln!(
                out,
                "{:<14} {:>10} {:>12} {:>12} {:>12} {:>8} {:>12}  {}",
                g.filename,
                g.record_count,
                format_bytes(g.total_bytes),
                format_bytes(g.total_data_bytes),
                format_bytes(live_bytes),
                live_extents,
                ratio_str,
                status
            )
            .unwrap();
        }
    }
    writeln!(out).unwrap();

    // Verbose Level 1: Inode Tree / Details
    if verbosity >= 1 {
        writeln!(out, "=== Summary Inode Records ===").unwrap();
        for (i, &ino) in sorted_inodes.iter().enumerate() {
            if let Some(sync_node) = inodes.get(&ino) {
                let node = sync_node.as_ref();
                let path_str = path_map.get(&ino).map(|p| p.as_str()).unwrap_or("");
                match &node.kind {
                    NodeKind::Directory { entries, .. } => {
                        writeln!(
                            out,
                            "#{:<5} [Inode {:<5}] Directory  {:?} (mode 0o{:o}, uid {}, gid {}, entries: {}, mtime: {})",
                            i + 1,
                            ino,
                            path_str,
                            node.meta.perm,
                            node.meta.uid,
                            node.meta.gid,
                            entries.len(),
                            format_system_time(node.meta.mtime)
                        )
                        .unwrap();
                        if !entries.is_empty() {
                            let mut sorted_entries = entries.clone();
                            sorted_entries.sort_by(|a, b| a.0.cmp(&b.0));
                            let entry_strs: Vec<String> = sorted_entries
                                .iter()
                                .map(|(name, child_ino)| format!("{:?} -> Inode {}", name, child_ino))
                                .collect();
                            writeln!(out, "      entries: [{}]", entry_strs.join(", ")).unwrap();
                        }
                    }
                    NodeKind::Symlink { target, .. } => {
                        writeln!(
                            out,
                            "#{:<5} [Inode {:<5}] Symlink    {:?} -> {:?} (uid {}, gid {}, mtime: {})",
                            i + 1,
                            ino,
                            path_str,
                            target,
                            node.meta.uid,
                            node.meta.gid,
                            format_system_time(node.meta.mtime)
                        )
                        .unwrap();
                    }
                    NodeKind::File { range_map, size, .. } => {
                        writeln!(
                            out,
                            "#{:<5} [Inode {:<5}] RegularFile {:?} (size {}, extents {}, mode 0o{:o}, uid {}, gid {}, mtime: {})",
                            i + 1,
                            ino,
                            path_str,
                            format_bytes(*size),
                            range_map.len(),
                            node.meta.perm,
                            node.meta.uid,
                            node.meta.gid,
                            format_system_time(node.meta.mtime)
                        )
                        .unwrap();

                        // Verbose Level 2: Physical Extents Dump
                        if verbosity >= 2 {
                            if range_map.is_empty() {
                                writeln!(out, "      extents: (empty / 0 bytes)").unwrap();
                            } else {
                                writeln!(out, "      extents ({}):", range_map.len()).unwrap();
                                for (ext_idx, (&start, entry)) in range_map.iter().enumerate() {
                                    let state_desc = match entry.value.read_state() {
                                        ExtentState::Disk {
                                            generation,
                                            record_log_offset,
                                            payload_offset,
                                            length,
                                        } => {
                                            format!(
                                                "{:06}.log [record offset 0x{:08x} / {:<8}, payload offset {:<4}, len {}]",
                                                generation,
                                                record_log_offset,
                                                record_log_offset,
                                                payload_offset,
                                                format_bytes(length as u64)
                                            )
                                        }
                                        ExtentState::Staged {
                                            data,
                                            payload_offset,
                                            length,
                                        } => {
                                            format!(
                                                "Staged Memory Buffer [payload offset {}, len {}, data buf {}]",
                                                payload_offset,
                                                format_bytes(length as u64),
                                                format_bytes(data.len() as u64)
                                            )
                                        }
                                    };
                                    writeln!(
                                        out,
                                        "        [{:>2}] [0x{:08x} .. 0x{:08x}] ({:>10}) -> {}",
                                        ext_idx + 1,
                                        start,
                                        start + entry.length,
                                        format_bytes(entry.length),
                                        state_desc
                                    )
                                    .unwrap();
                                }
                            }
                        }
                    }
                    NodeKind::Fifo => {
                        writeln!(
                            out,
                            "#{:<5} [Inode {:<5}] FIFO       {:?} (mode 0o{:o}, uid {}, gid {}, mtime: {})",
                            i + 1,
                            ino,
                            path_str,
                            node.meta.perm,
                            node.meta.uid,
                            node.meta.gid,
                            format_system_time(node.meta.mtime)
                        )
                        .unwrap();
                    }
                    NodeKind::CharDevice { rdev } => {
                        writeln!(
                            out,
                            "#{:<5} [Inode {:<5}] CharDev    {:?} (rdev 0x{:x}, mode 0o{:o}, uid {}, gid {}, mtime: {})",
                            i + 1,
                            ino,
                            path_str,
                            rdev,
                            node.meta.perm,
                            node.meta.uid,
                            node.meta.gid,
                            format_system_time(node.meta.mtime)
                        )
                        .unwrap();
                    }
                    NodeKind::BlockDevice { rdev } => {
                        writeln!(
                            out,
                            "#{:<5} [Inode {:<5}] BlockDev   {:?} (rdev 0x{:x}, mode 0o{:o}, uid {}, gid {}, mtime: {})",
                            i + 1,
                            ino,
                            path_str,
                            rdev,
                            node.meta.perm,
                            node.meta.uid,
                            node.meta.gid,
                            format_system_time(node.meta.mtime)
                        )
                        .unwrap();
                    }
                    NodeKind::Socket => {
                        writeln!(
                            out,
                            "#{:<5} [Inode {:<5}] Socket     {:?} (mode 0o{:o}, uid {}, gid {}, mtime: {})",
                            i + 1,
                            ino,
                            path_str,
                            node.meta.perm,
                            node.meta.uid,
                            node.meta.gid,
                            format_system_time(node.meta.mtime)
                        )
                        .unwrap();
                    }
                }
            }
        }
    }

    Ok(out)
}

fn format_payload_details(out: &mut String, opcode: OpCode, payload: &[u8], dump_data_hex: bool) {
    let dummy_header = crate::log::record::RecordHeader {
        op_code: opcode,
        tx_id: 0,
        inode: 0,
        payload_len: payload.len() as u32,
        checksum: [0; crate::log::record::RECORD_CHECKSUM_SIZE],
    };
    let dummy_record = crate::log::reader::LogRecord {
        header: dummy_header,
        payload: payload.to_vec(),
        record_log_offset: 0,
    };
    match dummy_record.decode() {
        Ok(crate::log::record::DecodedPayload::Create(c)) => {
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
        }
        Ok(crate::log::record::DecodedPayload::Mkdir(m)) => {
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
        }
        Ok(crate::log::record::DecodedPayload::Write { meta: w, data }) => {
            writeln!(
                out,
                "      file_offset: {}, data_len: {}, op_time: {}",
                w.file_offset,
                format_bytes(data.len() as u64),
                format_system_time(w.op_time)
            )
            .unwrap();

            if dump_data_hex && !data.is_empty() {
                out.push_str(&format_hexdump(data, 256));
            }
        }
        Ok(crate::log::record::DecodedPayload::Unlink(u)) => {
            writeln!(
                out,
                "      parent: {}, name: {:?}, op_time: {}",
                u.parent,
                u.name,
                format_system_time(u.op_time)
            )
            .unwrap();
        }
        Ok(crate::log::record::DecodedPayload::Rmdir(r)) => {
            writeln!(
                out,
                "      parent: {}, name: {:?}, op_time: {}",
                r.parent,
                r.name,
                format_system_time(r.op_time)
            )
            .unwrap();
        }
        Ok(crate::log::record::DecodedPayload::Symlink(s)) => {
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
        }
        Ok(crate::log::record::DecodedPayload::Rename(r)) => {
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
        }
        Ok(crate::log::record::DecodedPayload::Setattr(s)) => {
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
        }
        Ok(crate::log::record::DecodedPayload::Link(l)) => {
            writeln!(
                out,
                "      target_ino: {}, new_parent: {}, new_name: {:?}, op_time: {}",
                l.ino,
                l.new_parent,
                l.new_name,
                format_system_time(l.op_time)
            )
            .unwrap();
        }
        Ok(crate::log::record::DecodedPayload::FlushCommit(b)) => {
            writeln!(
                out,
                "      batch_record_count: {}, commit_timestamp: {}",
                b.record_count,
                format_system_time(b.timestamp)
            )
            .unwrap();
        }
        Ok(crate::log::record::DecodedPayload::Mknod(m)) => {
            writeln!(
                out,
                "      parent: {}, name: {:?}, mode: 0o{:o}, rdev: 0x{:x}, uid: {}, gid: {}, created_at: {}",
                m.parent,
                m.name,
                m.mode,
                m.rdev,
                m.uid,
                m.gid,
                format_system_time(m.created_at)
            )
            .unwrap();
        }
        Err(_) => {
            writeln!(out, "      [Failed to deserialize {}Payload]", opcode).unwrap();
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
            if let Some(&b) = chunk.get(i) {
                let _ = write!(out, "{:02x} ", b);
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
        let _ = writeln!(out, "      ... [{} more data bytes omitted]", data.len() - max_bytes);
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
    use crate::log::record::{CreatePayload, WriteMeta};
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
        writer.append_record(OpCode::Create, 2, &create_bytes).unwrap();

        // Write Write record with 100 bytes
        let write_m = WriteMeta {
            file_offset: 0,
            op_time: clock.now(),
        };
        let mut write_bytes = bincode::serialize(&write_m).unwrap();
        write_bytes.extend_from_slice(&[0x42; 100]);
        writer.append_record(OpCode::Write, 2, &write_bytes).unwrap();

        // Commit batch
        writer.emit_flush_commit(2, &clock).unwrap();
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
        assert!(v1_dump.contains("FlushCommit"));
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

        // Write Create and Write records WITHOUT FlushCommit trailer
        let create_p = CreatePayload {
            parent: 1,
            name: "uncommitted.txt".to_string(),
            mode: 0o644,
            uid: 1000,
            gid: 1000,
            created_at: clock.now(),
        };
        let create_bytes = bincode::serialize(&create_p).unwrap();
        writer.append_record(OpCode::Create, 2, &create_bytes).unwrap();
        drop(writer);

        let log_path = dir.path().join("000001.log");
        let dump = dump_log_file(&log_path, 1).unwrap();
        assert!(dump.contains("Trailing Batch:      1 UNCOMMITTED records"));
        assert!(dump.contains("[UNCOMMITTED TRAILING BATCH]"));
    }

    #[test]
    fn test_dump_summary_file_summary_and_verbosity_levels() {
        use crate::fs::InMemoryFS;
        use crate::log::summary::{export_summary, init_volume};
        use crate::log::{LogManifest, SharedExtentState};
        use crate::node::{InodeMeta, Node, NodeKind};
        use crate::range_map::RangeMap;
        use std::sync::Arc;

        let dir = tempdir().unwrap();
        init_volume(dir.path(), Some("feature-branch")).unwrap();

        let summary_path = dir.path().join("000000.summary");
        assert!(summary_path.exists());

        // Level 0: Summary
        let dump_v0 = dump_file(&summary_path, 0).unwrap();
        assert!(dump_v0.contains("=== appendfs Summary File Dump ==="));
        assert!(dump_v0.contains("Branch:              feature-branch"));
        assert!(dump_v0.contains("Total Inodes:        1 (1 directories, 0 regular files, 0 symlinks)"));
        assert!(dump_v0.contains("Checksum (BLAKE3):"));
        assert!(dump_v0.contains("VERIFIED"));

        // Create an InMemoryFS with fragmented files
        let fs = InMemoryFS::new();
        let now = SystemClock.now();

        // Create directory /docs (inode 2)
        let dir_node = Arc::new(Node {
            meta: InodeMeta::new(0o755, 2, 1000, 1000, now),
            kind: NodeKind::Directory {
                parent: 1,
                entries: vec![("fragmented.bin".to_string(), 3)],
            },
        });

        // Create fragmented file (inode 3) with 2 extents
        let mut rmap = RangeMap::new();
        rmap.insert(0, 4096, SharedExtentState::new_disk(1, 100, 20, 4096));
        rmap.insert(4096, 4096, SharedExtentState::new_disk(2, 200, 20, 4096));

        let file_node = Arc::new(Node {
            meta: InodeMeta::new(0o644, 1, 1000, 1000, now),
            kind: NodeKind::File {
                range_map: rmap,
                size: 8192,
            },
        });

        // Root directory (inode 1)
        let root_node = Arc::new(Node {
            meta: InodeMeta::new(0o755, 2, 0, 0, now),
            kind: NodeKind::Directory {
                parent: 1,
                entries: vec![("docs".to_string(), 2)],
            },
        });

        {
            let mut base = fs.base.write().unwrap();
            base.insert(1, root_node);
            base.insert(2, dir_node);
            base.insert(3, file_node);
        }

        let snapshot = fs.snapshot_all();
        let manifest = LogManifest {
            branch: "feature-branch".to_string(),
            logs: vec![
                crate::log::LogFileInfo {
                    generation: 1,
                    filename: "000001.log".to_string(),
                    created_at: std::time::UNIX_EPOCH,
                    record_count: 50,
                    total_bytes: 5000,
                    total_data_bytes: 4096,
                },
                crate::log::LogFileInfo {
                    generation: 2,
                    filename: "000002.log".to_string(),
                    created_at: std::time::UNIX_EPOCH,
                    record_count: 50,
                    total_bytes: 5000,
                    total_data_bytes: 4096,
                },
            ],
            next_generation: 3,
            next_filename: "000003.log".to_string(),
        };

        export_summary(&snapshot, &manifest, dir.path(), 1, 100, 4).unwrap();
        let snapshot_path = dir.path().join("000001.summary");

        // Level 0: Fragmentation Stats & Top Fragmented Files
        let dump_snap_v0 = dump_file(&snapshot_path, 0).unwrap();
        assert!(dump_snap_v0.contains("Total Regular Files: 1"));
        assert!(dump_snap_v0.contains("Total File Extents:  2"));
        assert!(dump_snap_v0.contains("Avg Extents / File:  2.00"));
        assert!(dump_snap_v0.contains("Max Extents in File: 2"));
        assert!(dump_snap_v0.contains("2 - 4 extents"));
        assert!(dump_snap_v0.contains("Top Fragmented Files"));
        assert!(dump_snap_v0.contains("/docs/fragmented.bin"));
        assert!(dump_snap_v0.contains("000001.log"));
        assert!(dump_snap_v0.contains("000002.log"));

        // Level 1: Inode Tree Listing
        let dump_snap_v1 = dump_file(&snapshot_path, 1).unwrap();
        assert!(dump_snap_v1.contains("Summary Inode Records"));
        assert!(dump_snap_v1.contains("Directory  \"/\""));
        assert!(dump_snap_v1.contains("Directory  \"/docs\""));
        assert!(dump_snap_v1.contains("RegularFile \"/docs/fragmented.bin\""));

        // Level 2: Full Physical Extent Mappings
        let dump_snap_v2 = dump_file(&snapshot_path, 2).unwrap();
        assert!(dump_snap_v2.contains("extents (2):"));
        assert!(dump_snap_v2.contains("000001.log [record offset 0x00000064 / 100"));
        assert!(dump_snap_v2.contains("000002.log [record offset 0x000000c8 / 200"));
    }
}
