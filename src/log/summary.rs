use crate::fs::InMemoryFS;
use crate::log::SharedExtentState;
use crate::node::Node;
use crate::range_map::RangeMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{File, OpenOptions, rename};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;

pub const SUMMARY_HEADER_SIZE: usize = 44;
// 28 bytes (manifest_offset + index_offset + entry_count + magic) + 32-byte BLAKE3 checksum.
pub const SUMMARY_FOOTER_SIZE: usize = 60;
pub const SUMMARY_INDEX_ENTRY_SIZE: usize = 16;
pub const SUMMARY_MAGIC: &[u8; 4] = b"APPS";
// Bumped for SummaryHeader's created_at field.
pub const CURRENT_SUMMARY_VERSION: u32 = 4;

/// 44-byte header written at offset 0 of `{:06}.summary`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SummaryHeader {
    pub magic: [u8; 4],
    pub version: u32,
    pub generation: u64,
    pub last_tx_id: u64,
    pub next_inode: u64,
    #[serde(with = "crate::clock::serde_system_time")]
    pub created_at: std::time::SystemTime,
}

impl SummaryHeader {
    pub fn new(generation: u64, last_tx_id: u64, next_inode: u64) -> Self {
        Self::new_with_time(
            generation,
            last_tx_id,
            next_inode,
            std::time::SystemTime::now(),
        )
    }

    pub fn new_with_time(
        generation: u64,
        last_tx_id: u64,
        next_inode: u64,
        created_at: std::time::SystemTime,
    ) -> Self {
        Self {
            magic: *SUMMARY_MAGIC,
            version: CURRENT_SUMMARY_VERSION,
            generation,
            last_tx_id,
            next_inode,
            created_at,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("SummaryHeader serialization failed")
    }

    pub fn from_bytes(buf: &[u8]) -> io::Result<Self> {
        bincode::deserialize(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

/// Footer written at EOF (last `SUMMARY_FOOTER_SIZE` bytes) of `{:06}.summary`.
///
/// `checksum` is a full (untruncated) BLAKE3 hash of everything in the file *before*
/// the footer - the header, every inode record, the manifest, and the index array.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SummaryFooter {
    pub manifest_offset: u64,
    pub index_offset: u64,
    pub entry_count: u64,
    pub magic: [u8; 4],
    pub checksum: [u8; 32],
}

impl SummaryFooter {
    pub fn new(
        manifest_offset: u64,
        index_offset: u64,
        entry_count: u64,
        checksum: [u8; 32],
    ) -> Self {
        Self {
            manifest_offset,
            index_offset,
            entry_count,
            magic: *SUMMARY_MAGIC,
            checksum,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("SummaryFooter serialization failed")
    }

    pub fn from_bytes(buf: &[u8]) -> io::Result<Self> {
        bincode::deserialize(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

/// Fixed 16-byte index entry mapping `inode -> byte_offset` in the `.summary` file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SummaryIndexEntry {
    pub inode: u64,
    pub offset: u64,
}

impl SummaryIndexEntry {
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("SummaryIndexEntry serialization failed")
    }

    pub fn from_bytes(buf: &[u8]) -> io::Result<Self> {
        bincode::deserialize(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

/// Exports a single-file summary snapshot of an inodes snapshot map into `log_dir`.
pub fn export_summary(
    snapshot: &HashMap<u64, Arc<Node>>,
    manifest: &crate::log::LogManifest,
    log_dir: impl AsRef<Path>,
    generation: u64,
    last_tx_id: u64,
    next_inode: u64,
) -> io::Result<PathBuf> {
    export_summary_with_time(
        snapshot,
        manifest,
        log_dir,
        generation,
        last_tx_id,
        next_inode,
        std::time::SystemTime::now(),
    )
}

/// Exports a single-file summary snapshot of an inodes snapshot map into `log_dir` with custom created_at timestamp.
pub fn export_summary_with_time(
    snapshot: &HashMap<u64, Arc<Node>>,
    manifest: &crate::log::LogManifest,
    log_dir: impl AsRef<Path>,
    generation: u64,
    last_tx_id: u64,
    next_inode: u64,
    created_at: std::time::SystemTime,
) -> io::Result<PathBuf> {
    let log_dir = log_dir.as_ref();

    let mut inodes_snapshot: Vec<(u64, Arc<Node>)> = snapshot
        .iter()
        .map(|(ino, arc)| (*ino, Arc::clone(arc)))
        .collect();
    // Sort by inode so physical serialization order is deterministic
    inodes_snapshot.sort_by_key(|(ino, _)| *ino);

    let filename = format!("{:06}.summary", generation);
    let tmp_path = log_dir.join(format!("{:06}.summary.tmp", generation));
    let final_path = log_dir.join(filename);

    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&tmp_path)?;

    // Hashes everything written before the footer, incrementally, so verifying on
    // read doesn't need a second full pass over the file.
    let mut hasher = blake3::Hasher::new();

    // 1. Write SummaryHeader at offset 0
    let header = SummaryHeader::new_with_time(generation, last_tx_id, next_inode, created_at);
    let header_bytes = header.to_bytes();
    file.write_all(&header_bytes)?;
    hasher.update(&header_bytes);

    let mut current_offset = header_bytes.len() as u64;
    let mut index_entries = Vec::with_capacity(inodes_snapshot.len());

    // 2. Serialize all inode nodes into data payload body
    for (inode, node_arc) in &inodes_snapshot {
        let node = node_arc.as_ref();
        let mut node_to_serialize = node.clone();
        if let Node::Directory {
            ref mut entries, ..
        } = node_to_serialize
        {
            entries.sort_by(|a, b| a.0.cmp(&b.0));
        } else if let Node::File {
            ref mut range_map, ..
        } = node_to_serialize
        {
            let entries: Vec<(u64, u64, SharedExtentState)> = range_map
                .iter()
                .map(|(start, e)| (*start, e.length, e.value.clone()))
                .collect();
            let mut coalesced: RangeMap<SharedExtentState> = RangeMap::new();
            let mut current: Option<(u64, u64, SharedExtentState)> = None;

            for (start, len, state) in entries {
                if let Some((cur_start, cur_len, cur_state)) = current.take() {
                    let mut merged = false;
                    if cur_start + cur_len == start {
                        if let (
                            crate::log::ExtentState::Disk {
                                generation: g1,
                                record_log_offset: r1,
                                payload_offset: p1,
                                length: l1,
                            },
                            crate::log::ExtentState::Disk {
                                generation: g2,
                                record_log_offset: r2,
                                payload_offset: p2,
                                length: l2,
                            },
                        ) = (cur_state.read_state(), state.read_state())
                        {
                            if g1 == g2
                                && r1 == r2
                                && p1 + l1 == p2
                                && l1 + l2 == (cur_len + len) as u32
                            {
                                let new_state = SharedExtentState::new_disk(g1, r1, p1, l1 + l2);
                                current = Some((cur_start, cur_len + len, new_state));
                                merged = true;
                            }
                        }
                    }
                    if !merged {
                        coalesced.insert(cur_start, cur_len, cur_state);
                        current = Some((start, len, state));
                    }
                } else {
                    current = Some((start, len, state));
                }
            }
            if let Some((cur_start, cur_len, cur_state)) = current {
                coalesced.insert(cur_start, cur_len, cur_state);
            }
            *range_map = coalesced;
        }
        let payload = bincode::serialize(&node_to_serialize)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        index_entries.push(SummaryIndexEntry {
            inode: *inode,
            offset: current_offset,
        });

        // Record header in summary file: inode (8 bytes) + payload_len (4 bytes) + payload
        let inode_bytes = inode.to_le_bytes();
        let payload_len_bytes = (payload.len() as u32).to_le_bytes();
        file.write_all(&inode_bytes)?;
        file.write_all(&payload_len_bytes)?;
        file.write_all(&payload)?;
        hasher.update(&inode_bytes);
        hasher.update(&payload_len_bytes);
        hasher.update(&payload);

        current_offset += 8 + 4 + payload.len() as u64;
    }

    // 3. Serialize and write LogManifest
    let manifest_offset = current_offset;
    let manifest_bytes =
        bincode::serialize(manifest).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let manifest_len_bytes = (manifest_bytes.len() as u32).to_le_bytes();
    file.write_all(&manifest_len_bytes)?;
    file.write_all(&manifest_bytes)?;
    hasher.update(&manifest_len_bytes);
    hasher.update(&manifest_bytes);
    current_offset += 4 + manifest_bytes.len() as u64;

    // 4. Sort index entries by inode ascending
    index_entries.sort_by_key(|entry| entry.inode);

    // 5. Append index entries
    let index_offset = current_offset;
    for entry in &index_entries {
        let entry_bytes = entry.to_bytes();
        file.write_all(&entry_bytes)?;
        hasher.update(&entry_bytes);
    }

    // 6. Append SummaryFooter at EOF
    let checksum: [u8; 32] = *hasher.finalize().as_bytes();
    let footer = SummaryFooter::new(
        manifest_offset,
        index_offset,
        index_entries.len() as u64,
        checksum,
    );
    file.write_all(&footer.to_bytes())?;

    file.flush()?;
    file.sync_data()?;
    drop(file);

    // 7. Atomically rename .tmp -> .summary
    rename(&tmp_path, &final_path)?;

    log::info!(
        "Exported single-file summary snapshot at {:?} (generation: {}, inodes: {}, last_tx_id: {})",
        final_path,
        generation,
        index_entries.len(),
        last_tx_id
    );

    Ok(final_path)
}

pub fn export_fs_summary(
    fs: &InMemoryFS,
    log_dir: impl AsRef<Path>,
    generation: u64,
    last_tx_id: u64,
) -> io::Result<PathBuf> {
    let snapshot = fs.snapshot_all();
    let next_inode = fs.next_inode.load(Ordering::SeqCst);
    let manifest = fs.manifest.read().unwrap().clone();
    export_summary(
        &snapshot, &manifest, log_dir, generation, last_tx_id, next_inode,
    )
}

/// Explicitly initializes a fresh, empty appendfs volume at `log_dir`.
/// Creates `000000.summary` containing the root directory (inode 1) and an initial LogManifest.
pub fn init_volume(log_dir: impl AsRef<Path>, branch: Option<&str>) -> io::Result<PathBuf> {
    let log_dir = log_dir.as_ref();
    std::fs::create_dir_all(log_dir)?;

    // Verify directory does not already contain an initialized volume (.summary or .log)
    if let Ok(entries) = std::fs::read_dir(log_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    if ext == "summary" || ext == "log" {
                        return Err(io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            format!(
                                "Volume already initialized at {:?} (found existing {} file {:?})",
                                log_dir,
                                ext,
                                path.file_name().unwrap_or_default()
                            ),
                        ));
                    }
                }
            }
        }
    }

    let fs = InMemoryFS::new();
    let snapshot = fs.snapshot_all();
    let branch_name = branch.unwrap_or("main");
    let manifest = crate::log::LogManifest {
        branch: branch_name.to_string(),
        logs: Vec::new(),
        next_generation: 1,
        next_filename: "000001.log".to_string(),
    };

    export_summary(&snapshot, &manifest, log_dir, 0, 0, 2)
}

/// Reader for single-file `{:06}.summary` snapshot files.
pub struct SummaryReader {
    file: File,
    pub header: SummaryHeader,
    pub footer: SummaryFooter,
    pub manifest: crate::log::LogManifest,
    index_entries: Vec<SummaryIndexEntry>,
}

impl SummaryReader {
    /// Opens a `.summary` file, reads header and EOF footer, loads manifest and index entries.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        let mut file = File::open(path)?;

        // 1. Read SummaryHeader at offset 0
        let mut header_buf = [0u8; SUMMARY_HEADER_SIZE];
        file.read_exact(&mut header_buf)?;
        let header = SummaryHeader::from_bytes(&header_buf)?;

        // 2. Read SummaryFooter at EOF
        let file_len = file.metadata()?.len();
        file.seek(SeekFrom::End(-(SUMMARY_FOOTER_SIZE as i64)))?;
        let mut footer_buf = [0u8; SUMMARY_FOOTER_SIZE];
        file.read_exact(&mut footer_buf)?;
        let footer = SummaryFooter::from_bytes(&footer_buf)?;

        // 3. Verify the whole-file checksum before trusting anything in this summary
        let content_len = file_len.saturating_sub(SUMMARY_FOOTER_SIZE as u64);
        file.seek(SeekFrom::Start(0))?;
        let mut hasher = blake3::Hasher::new();
        let mut remaining = content_len;
        let mut buf = [0u8; 8192];
        while remaining > 0 {
            let chunk = std::cmp::min(remaining, buf.len() as u64) as usize;
            file.read_exact(&mut buf[..chunk])?;
            hasher.update(&buf[..chunk]);
            remaining -= chunk as u64;
        }
        if hasher.finalize().as_bytes() != &footer.checksum {
            panic!(
                "summary checksum mismatch in {:?}: this data has been corrupted (possible bitrot)",
                path
            );
        }

        // 4. Read LogManifest from manifest_offset
        file.seek(SeekFrom::Start(footer.manifest_offset))?;
        let mut manifest_len_buf = [0u8; 4];
        file.read_exact(&mut manifest_len_buf)?;
        let manifest_len = u32::from_le_bytes(manifest_len_buf) as usize;
        let mut manifest_buf = vec![0u8; manifest_len];
        file.read_exact(&mut manifest_buf)?;
        let manifest: crate::log::LogManifest = bincode::deserialize(&manifest_buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // 5. Read index array from index_offset
        file.seek(SeekFrom::Start(footer.index_offset))?;
        let mut index_entries = Vec::with_capacity(footer.entry_count as usize);
        for _ in 0..footer.entry_count {
            let mut entry_buf = [0u8; SUMMARY_INDEX_ENTRY_SIZE];
            file.read_exact(&mut entry_buf)?;
            index_entries.push(SummaryIndexEntry::from_bytes(&entry_buf)?);
        }

        Ok(Self {
            file,
            header,
            footer,
            manifest,
            index_entries,
        })
    }

    /// Performs binary search lookup on index array to get the byte offset of a target inode.
    pub fn lookup_offset(&self, inode: u64) -> Option<u64> {
        self.index_entries
            .binary_search_by_key(&inode, |e| e.inode)
            .ok()
            .map(|pos| self.index_entries[pos].offset)
    }

    /// Reads and deserializes a specific inode's `Node` directly from disk by seeking to its offset.
    pub fn read_node(&mut self, inode: u64) -> io::Result<Option<Node>> {
        let offset = match self.lookup_offset(inode) {
            Some(off) => off,
            None => return Ok(None),
        };

        self.file.seek(SeekFrom::Start(offset))?;

        let mut header_buf = [0u8; 12];
        self.file.read_exact(&mut header_buf)?;

        let ino = u64::from_le_bytes(header_buf[0..8].try_into().unwrap());
        if ino != inode {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Inode mismatch at offset {}: expected {}, found {}",
                    offset, inode, ino
                ),
            ));
        }

        let payload_len = u32::from_le_bytes(header_buf[8..12].try_into().unwrap()) as usize;
        let mut payload = vec![0u8; payload_len];
        self.file.read_exact(&mut payload)?;

        let node: Node = bincode::deserialize(&payload)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        Ok(Some(node))
    }

    /// Reads all inode entries to reconstruct an `InMemoryFS` map for recovery.
    pub fn read_all_inodes(&mut self) -> io::Result<HashMap<u64, Arc<Node>>> {
        let inodes: Vec<u64> = self.index_entries.iter().map(|e| e.inode).collect();
        let mut map = HashMap::with_capacity(inodes.len());
        for inode in inodes {
            if let Some(node) = self.read_node(inode)? {
                map.insert(inode, Arc::new(node));
            }
        }
        Ok(map)
    }

    pub fn index_entries(&self) -> &[SummaryIndexEntry] {
        &self.index_entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_summary_bincode_serialization() {
        let header = SummaryHeader::new(5, 100, 42);
        let header_bytes = header.to_bytes();
        assert_eq!(header_bytes.len(), SUMMARY_HEADER_SIZE);
        let decoded_header = SummaryHeader::from_bytes(&header_bytes).unwrap();
        assert_eq!(header, decoded_header);

        let footer = SummaryFooter::new(512, 1024, 10, [0xAB; 32]);
        let footer_bytes = footer.to_bytes();
        assert_eq!(footer_bytes.len(), SUMMARY_FOOTER_SIZE);
        let decoded_footer = SummaryFooter::from_bytes(&footer_bytes).unwrap();
        assert_eq!(footer, decoded_footer);

        let entry = SummaryIndexEntry {
            inode: 7,
            offset: 2048,
        };
        let entry_bytes = entry.to_bytes();
        assert_eq!(entry_bytes.len(), SUMMARY_INDEX_ENTRY_SIZE);
        let decoded_entry = SummaryIndexEntry::from_bytes(&entry_bytes).unwrap();
        assert_eq!(entry, decoded_entry);
    }

    #[test]
    fn test_summary_export_and_reader() {
        let dir = tempdir().unwrap();
        let fs = InMemoryFS::new();

        let path = export_fs_summary(&fs, dir.path(), 1, 10).unwrap();
        assert!(path.exists());

        let mut reader = SummaryReader::open(&path).unwrap();
        assert_eq!(reader.header.generation, 1);
        assert_eq!(reader.header.last_tx_id, 10);
        assert_eq!(reader.footer.entry_count, 1); // Root inode (1)

        let root_node = reader.read_node(1).unwrap().unwrap();
        assert!(matches!(root_node, Node::Directory { .. }));

        let all_inodes = reader.read_all_inodes().unwrap();
        assert_eq!(all_inodes.len(), 1);
        assert!(all_inodes.contains_key(&1));
    }

    #[test]
    #[should_panic(expected = "summary checksum mismatch")]
    fn test_bitrot_in_summary_body_is_detected() {
        let dir = tempdir().unwrap();
        let fs = InMemoryFS::new();
        let path = export_fs_summary(&fs, dir.path(), 1, 10).unwrap();

        // Flip one bit inside the body (header + inode records + index), well before
        // the footer - simulating bitrot in previously-valid, already-exported data.
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let corrupt_offset = SUMMARY_HEADER_SIZE as u64 + 2;
        file.seek(SeekFrom::Start(corrupt_offset)).unwrap();
        let mut byte = [0u8; 1];
        file.read_exact(&mut byte).unwrap();
        byte[0] ^= 0xFF;
        file.seek(SeekFrom::Start(corrupt_offset)).unwrap();
        file.write_all(&byte).unwrap();
        drop(file);

        // Bitrot in the whole-file checksum must panic, not return an Err a caller
        // could silently swallow and fall back past - see SummaryReader::open.
        let _ = SummaryReader::open(&path);
    }

    #[test]
    fn test_init_volume_creates_valid_summary_and_manifest() {
        let dir = tempdir().unwrap();
        let summary_path = init_volume(dir.path(), Some("feature-test")).unwrap();
        assert!(summary_path.exists());
        assert_eq!(summary_path.file_name().unwrap(), "000000.summary");

        // Verify SummaryReader opens it cleanly
        let mut reader = SummaryReader::open(&summary_path).unwrap();
        assert_eq!(reader.header.generation, 0);
        assert_eq!(reader.header.last_tx_id, 0);
        assert_eq!(reader.header.next_inode, 2);
        assert_eq!(reader.footer.entry_count, 1);
        assert_eq!(reader.manifest.branch, "feature-test");
        assert_eq!(reader.manifest.next_generation, 1);
        assert_eq!(reader.manifest.next_filename, "000001.log");
        assert!(reader.manifest.logs.is_empty());

        let root_node = reader.read_node(1).unwrap().unwrap();
        assert!(matches!(root_node, Node::Directory { .. }));

        // Re-initializing on the same directory must fail with AlreadyExists
        let re_init = init_volume(dir.path(), Some("feature-test"));
        assert!(re_init.is_err());
        assert_eq!(re_init.unwrap_err().kind(), io::ErrorKind::AlreadyExists);
    }
}
