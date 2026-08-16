use crate::fs::InMemoryFS;
use crate::node::{Node, SyncNode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{File, OpenOptions, rename};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;

pub const SUMMARY_HEADER_SIZE: usize = 32;
// 20 bytes (index_offset + entry_count + magic) + 32-byte BLAKE3 checksum.
pub const SUMMARY_FOOTER_SIZE: usize = 52;
pub const SUMMARY_INDEX_ENTRY_SIZE: usize = 16;
pub const SUMMARY_MAGIC: &[u8; 4] = b"APPS";
// Bumped for SummaryFooter's new checksum field (a breaking format change) and for
// consistency with the log format's own version bump for the same reason - old
// summaries are cleanly rejected rather than misparsed.
pub const CURRENT_SUMMARY_VERSION: u32 = 2;

/// 32-byte header written at offset 0 of `{:06}.summary`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SummaryHeader {
    pub magic: [u8; 4],
    pub version: u32,
    pub generation: u64,
    pub last_tx_id: u64,
    pub next_inode: u64,
}

impl SummaryHeader {
    pub fn new(generation: u64, last_tx_id: u64, next_inode: u64) -> Self {
        Self {
            magic: *SUMMARY_MAGIC,
            version: CURRENT_SUMMARY_VERSION,
            generation,
            last_tx_id,
            next_inode,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }

    pub fn from_bytes(buf: &[u8]) -> io::Result<Self> {
        let header: Self =
            bincode::deserialize(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if &header.magic != SUMMARY_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid SummaryHeader magic bytes",
            ));
        }
        if header.version != CURRENT_SUMMARY_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unsupported SummaryHeader version: {}", header.version),
            ));
        }
        Ok(header)
    }
}

/// Footer written at EOF (last `SUMMARY_FOOTER_SIZE` bytes) of `{:06}.summary`.
///
/// `checksum` is a full (untruncated) BLAKE3 hash of everything in the file *before*
/// the footer - the header, every inode record, and the index array. Unlike the log's
/// per-record checksums (truncated to 4 bytes to bound overhead on many small
/// records), space isn't a concern for a single whole-snapshot checksum, and this file
/// is the root of trust for fast-path recovery, so it gets the strongest check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SummaryFooter {
    pub index_offset: u64,
    pub entry_count: u64,
    pub magic: [u8; 4],
    pub checksum: [u8; 32],
}

impl SummaryFooter {
    pub fn new(index_offset: u64, entry_count: u64, checksum: [u8; 32]) -> Self {
        Self {
            index_offset,
            entry_count,
            magic: *SUMMARY_MAGIC,
            checksum,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }

    pub fn from_bytes(buf: &[u8]) -> io::Result<Self> {
        let footer: Self =
            bincode::deserialize(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if &footer.magic != SUMMARY_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid SummaryFooter magic bytes",
            ));
        }
        Ok(footer)
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
        bincode::serialize(self).unwrap()
    }

    pub fn from_bytes(buf: &[u8]) -> io::Result<Self> {
        bincode::deserialize(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

/// Exports a single-file summary snapshot of an inodes snapshot map into `log_dir`.
pub fn export_summary(
    snapshot: &HashMap<u64, Arc<SyncNode>>,
    log_dir: impl AsRef<Path>,
    generation: u64,
    last_tx_id: u64,
    next_inode: u64,
) -> io::Result<PathBuf> {
    let log_dir = log_dir.as_ref();

    let mut inodes_snapshot: Vec<(u64, Arc<SyncNode>)> = snapshot
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
    let header = SummaryHeader::new(generation, last_tx_id, next_inode);
    let header_bytes = header.to_bytes();
    file.write_all(&header_bytes)?;
    hasher.update(&header_bytes);

    let mut current_offset = header_bytes.len() as u64;
    let mut index_entries = Vec::with_capacity(inodes_snapshot.len());

    // 2. Serialize all inode nodes into data payload body
    for (inode, sync_node_arc) in &inodes_snapshot {
        let node = unsafe { sync_node_arc.read() };
        let mut node_to_serialize = node.clone();
        if let Node::Directory {
            ref mut entries, ..
        } = node_to_serialize
        {
            entries.sort_by(|a, b| a.0.cmp(&b.0));
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

    // 3. Sort index entries by inode ascending
    index_entries.sort_by_key(|entry| entry.inode);

    // 4. Append index entries
    let index_offset = current_offset;
    for entry in &index_entries {
        let entry_bytes = entry.to_bytes();
        file.write_all(&entry_bytes)?;
        hasher.update(&entry_bytes);
    }

    // 5. Append SummaryFooter at EOF
    let checksum: [u8; 32] = *hasher.finalize().as_bytes();
    let footer = SummaryFooter::new(index_offset, index_entries.len() as u64, checksum);
    file.write_all(&footer.to_bytes())?;

    file.flush()?;
    file.sync_data()?;
    drop(file);

    // 6. Atomically rename .tmp -> .summary
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
    export_summary(&snapshot, log_dir, generation, last_tx_id, next_inode)
}

/// Reader for single-file `{:06}.summary` snapshot files.
pub struct SummaryReader {
    file: File,
    pub header: SummaryHeader,
    pub footer: SummaryFooter,
    index_entries: Vec<SummaryIndexEntry>,
}

impl SummaryReader {
    /// Opens a `.summary` file, reads header and EOF footer, and loads index entries.
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

        // 3. Verify the whole-file checksum before trusting anything in this summary -
        // it's the root of trust for fast-path recovery. Streamed in chunks so memory
        // use stays bounded regardless of how many inodes the snapshot covers.
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
            // Unlike a bad magic/version (which just means "not a valid summary" - a
            // stray file, or an old format, neither of which implies corruption), a
            // checksum mismatch is proof that previously-valid, already-exported data
            // has rotted. There's no safe way to continue past proven corruption of
            // the root of trust for fast-path recovery, so this panics rather than
            // returning an Err a caller could silently swallow and fall back past.
            panic!(
                "summary checksum mismatch in {:?}: this data has been corrupted (possible bitrot)",
                path
            );
        }

        // 4. Read index array from index_offset
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
    pub fn read_all_inodes(&mut self) -> io::Result<HashMap<u64, Arc<SyncNode>>> {
        let inodes: Vec<u64> = self.index_entries.iter().map(|e| e.inode).collect();
        let mut map = HashMap::with_capacity(inodes.len());
        for inode in inodes {
            if let Some(node) = self.read_node(inode)? {
                map.insert(inode, Arc::new(SyncNode::new(node)));
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

        let footer = SummaryFooter::new(1024, 10, [0xAB; 32]);
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
}
