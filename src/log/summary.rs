use crate::fs::InMemoryFS;
use crate::log::SharedExtentState;
use crate::node::Node;
use crate::range_map::RangeMap;
use crate::storage::{OsStorage, Storage, StorageReader};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
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

/// Exports a single-file summary snapshot to a custom `Storage` instance.
pub fn export_summary_with_time_to_storage(
    snapshot: &HashMap<u64, Arc<Node>>,
    manifest: &crate::log::LogManifest,
    storage: &dyn Storage,
    generation: u64,
    last_tx_id: u64,
    next_inode: u64,
    created_at: std::time::SystemTime,
) -> io::Result<String> {
    let mut inodes_snapshot: Vec<(u64, Arc<Node>)> = snapshot
        .iter()
        .map(|(ino, arc)| (*ino, Arc::clone(arc)))
        .collect();
    // Sort by inode so physical serialization order is deterministic
    inodes_snapshot.sort_by_key(|(ino, _)| *ino);

    let filename = format!("{:06}.summary", generation);
    let tmp_filename = format!("{:06}.summary.tmp", generation);

    let mut writer = storage.open_writer(&tmp_filename, false)?;

    // Hashes everything written before the footer
    let mut hasher = blake3::Hasher::new();

    // 1. Write SummaryHeader at offset 0
    let header = SummaryHeader::new_with_time(generation, last_tx_id, next_inode, created_at);
    let header_bytes = header.to_bytes();
    writer.append(&header_bytes)?;
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
            let mut coalesced = RangeMap::new();
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
                                length: _,
                            },
                            crate::log::ExtentState::Disk {
                                generation: g2,
                                record_log_offset: r2,
                                payload_offset: p2,
                                length: _,
                            },
                        ) = (cur_state.read_state(), state.read_state())
                        {
                            if g1 == g2
                                && r1 == r2
                                && p1 as u64 + cur_len == p2 as u64
                            {
                                let new_state = SharedExtentState::new_disk(
                                    g1,
                                    r1,
                                    p1,
                                    (cur_len + len) as u32,
                                );
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

        let inode_bytes = inode.to_le_bytes();
        let payload_len_bytes = (payload.len() as u32).to_le_bytes();
        writer.append(&inode_bytes)?;
        writer.append(&payload_len_bytes)?;
        writer.append(&payload)?;
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
    writer.append(&manifest_len_bytes)?;
    writer.append(&manifest_bytes)?;
    hasher.update(&manifest_len_bytes);
    hasher.update(&manifest_bytes);
    current_offset += 4 + manifest_bytes.len() as u64;

    // 4. Sort index entries by inode ascending
    index_entries.sort_by_key(|entry| entry.inode);

    // 5. Append index entries
    let index_offset = current_offset;
    for entry in &index_entries {
        let entry_bytes = entry.to_bytes();
        writer.append(&entry_bytes)?;
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
    writer.append(&footer.to_bytes())?;

    writer.sync()?;
    drop(writer);

    // 7. Atomically rename .tmp -> .summary
    storage.rename(&tmp_filename, &filename)?;

    log::info!(
        "Exported single-file summary snapshot {} (generation: {}, inodes: {}, last_tx_id: {})",
        filename,
        generation,
        index_entries.len(),
        last_tx_id
    );

    Ok(filename)
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
    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(log_dir));
    let filename = export_summary_with_time_to_storage(
        snapshot, manifest, &storage, generation, last_tx_id, next_inode, created_at,
    )?;
    Ok(log_dir.join(filename))
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

/// Initializes a fresh, empty appendfs volume on a `Storage` instance.
pub fn init_volume_with_storage(storage: Arc<dyn Storage>, branch: Option<&str>) -> io::Result<()> {
    let files = storage.list_files()?;
    for file in files {
        if file.ends_with(".summary") || file.ends_with(".log") {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("Volume already initialized (found existing file {})", file),
            ));
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

    export_summary_with_time_to_storage(
        &snapshot,
        &manifest,
        &storage,
        0,
        0,
        2,
        std::time::SystemTime::now(),
    )?;

    Ok(())
}

/// Explicitly initializes a fresh, empty appendfs volume at `log_dir`.
/// Creates `000000.summary` containing the root directory (inode 1) and an initial LogManifest.
pub fn init_volume(log_dir: impl AsRef<Path>, branch: Option<&str>) -> io::Result<PathBuf> {
    let log_dir = log_dir.as_ref();
    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(log_dir));
    init_volume_with_storage(storage, branch)?;
    Ok(log_dir.join("000000.summary"))
}

/// Reader for single-file `{:06}.summary` snapshot files.
pub struct SummaryReader {
    reader: Arc<dyn StorageReader>,
    pub header: SummaryHeader,
    pub footer: SummaryFooter,
    pub manifest: crate::log::LogManifest,
    index_entries: Vec<SummaryIndexEntry>,
}

impl SummaryReader {
    /// Opens a `.summary` file from a `Storage` instance.
    pub fn open_with_storage(storage: &dyn Storage, filename: &str) -> io::Result<Self> {
        let reader = storage.open_reader(filename)?;
        let file_len = reader.len()?;

        if file_len < (SUMMARY_HEADER_SIZE + SUMMARY_FOOTER_SIZE) as u64 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("summary file {} is too short ({} bytes)", filename, file_len),
            ));
        }

        // 1. Read SummaryHeader at offset 0
        let mut header_buf = [0u8; SUMMARY_HEADER_SIZE];
        reader.read_exact_at(0, &mut header_buf)?;
        let header = SummaryHeader::from_bytes(&header_buf)?;

        // 2. Read SummaryFooter at EOF
        let footer_offset = file_len - SUMMARY_FOOTER_SIZE as u64;
        let mut footer_buf = [0u8; SUMMARY_FOOTER_SIZE];
        reader.read_exact_at(footer_offset, &mut footer_buf)?;
        let footer = SummaryFooter::from_bytes(&footer_buf)?;

        // 3. Verify the whole-file checksum before trusting anything in this summary
        let content_len = file_len.saturating_sub(SUMMARY_FOOTER_SIZE as u64);
        let mut hasher = blake3::Hasher::new();
        let mut offset = 0u64;
        let mut buf = [0u8; 8192];
        while offset < content_len {
            let chunk = std::cmp::min(content_len - offset, buf.len() as u64) as usize;
            reader.read_exact_at(offset, &mut buf[..chunk])?;
            hasher.update(&buf[..chunk]);
            offset += chunk as u64;
        }

        if hasher.finalize().as_bytes() != &footer.checksum {
            panic!(
                "summary checksum mismatch in {}: this data has been corrupted (possible bitrot)",
                filename
            );
        }

        // 4. Read LogManifest from manifest_offset
        let mut manifest_len_buf = [0u8; 4];
        reader.read_exact_at(footer.manifest_offset, &mut manifest_len_buf)?;
        let manifest_len = u32::from_le_bytes(manifest_len_buf) as usize;
        let mut manifest_buf = vec![0u8; manifest_len];
        reader.read_exact_at(footer.manifest_offset + 4, &mut manifest_buf)?;
        let manifest: crate::log::LogManifest = bincode::deserialize(&manifest_buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // 5. Read index array from index_offset
        let mut index_entries = Vec::with_capacity(footer.entry_count as usize);
        let mut index_read_offset = footer.index_offset;
        for _ in 0..footer.entry_count {
            let mut entry_buf = [0u8; SUMMARY_INDEX_ENTRY_SIZE];
            reader.read_exact_at(index_read_offset, &mut entry_buf)?;
            index_entries.push(SummaryIndexEntry::from_bytes(&entry_buf)?);
            index_read_offset += SUMMARY_INDEX_ENTRY_SIZE as u64;
        }

        Ok(Self {
            reader,
            header,
            footer,
            manifest,
            index_entries,
        })
    }

    /// Opens a `.summary` file from a local filesystem path.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(parent));
        Self::open_with_storage(&storage, &filename)
    }

    /// Returns the slice of all index entries in this summary file.
    pub fn index_entries(&self) -> &[SummaryIndexEntry] {
        &self.index_entries
    }

    /// Returns the underlying storage reader.
    pub fn reader(&self) -> &Arc<dyn StorageReader> {
        &self.reader
    }

    /// Performs binary search lookup on index array to get the byte offset of a target inode.
    pub fn lookup_offset(&self, inode: u64) -> Option<u64> {
        self.index_entries
            .binary_search_by_key(&inode, |entry| entry.inode)
            .ok()
            .map(|idx| self.index_entries[idx].offset)
    }

    /// Reads and deserializes a single `Node` for `inode` from this summary file.
    pub fn read_inode(&self, inode: u64) -> io::Result<Option<Node>> {
        let Some(offset) = self.lookup_offset(inode) else {
            return Ok(None);
        };

        let mut meta_buf = [0u8; 12];
        self.reader.read_exact_at(offset, &mut meta_buf)?;
        let read_inode = u64::from_le_bytes(meta_buf[0..8].try_into().unwrap());
        if read_inode != inode {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "summary index mismatch: expected inode {}, found {}",
                    inode, read_inode
                ),
            ));
        }

        let payload_len = u32::from_le_bytes(meta_buf[8..12].try_into().unwrap()) as usize;
        let mut payload = vec![0u8; payload_len];
        self.reader.read_exact_at(offset + 12, &mut payload)?;

        let node = bincode::deserialize::<Node>(&payload)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        Ok(Some(node))
    }

    /// Alias for `read_inode`.
    pub fn read_node(&self, inode: u64) -> io::Result<Option<Node>> {
        self.read_inode(inode)
    }

    /// Iterates through all `(inode, Node)` stored in this summary file in ascending inode order.
    pub fn iter_inodes(&self) -> impl Iterator<Item = io::Result<(u64, Node)>> + '_ {
        self.index_entries.iter().map(move |entry| {
            let node = self.read_inode(entry.inode)?.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("inode {} in index but not found in file", entry.inode),
                )
            })?;
            Ok((entry.inode, node))
        })
    }

    /// Reads all inodes into an in-memory HashMap.
    pub fn read_all_inodes(&self) -> io::Result<HashMap<u64, Arc<Node>>> {
        let mut map = HashMap::with_capacity(self.footer.entry_count as usize);
        for res in self.iter_inodes() {
            let (ino, node) = res?;
            map.insert(ino, Arc::new(node));
        }
        Ok(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;
    use std::time::SystemTime;

    #[test]
    fn test_summary_bincode_serialization() {
        let storage = Arc::new(MemoryStorage::new());
        let mut snapshot: HashMap<u64, Arc<Node>> = HashMap::new();

        let root_entries = vec![("hello.txt".to_string(), 2)];
        snapshot.insert(
            1,
            Arc::new(Node::Directory {
                parent: 1,
                entries: root_entries,
                perm: 0o755,
                nlink: 2,
                uid: 1000,
                gid: 1000,
                atime: SystemTime::UNIX_EPOCH,
                mtime: SystemTime::UNIX_EPOCH,
                ctime: SystemTime::UNIX_EPOCH,
            }),
        );

        let mut rmap = RangeMap::new();
        rmap.insert(0, 100, SharedExtentState::new_disk(1, 24, 0, 100));
        snapshot.insert(
            2,
            Arc::new(Node::File {
                range_map: rmap,
                size: 100,
                perm: 0o644,
                nlink: 1,
                uid: 1000,
                gid: 1000,
                atime: SystemTime::UNIX_EPOCH,
                mtime: SystemTime::UNIX_EPOCH,
                ctime: SystemTime::UNIX_EPOCH,
            }),
        );

        let manifest = crate::log::LogManifest {
            branch: "main".to_string(),
            logs: Vec::new(),
            next_generation: 2,
            next_filename: "000002.log".to_string(),
        };

        let filename = export_summary_with_time_to_storage(
            &snapshot,
            &manifest,
            storage.as_ref(),
            1,
            42,
            3,
            SystemTime::now(),
        )
        .unwrap();

        let reader = SummaryReader::open_with_storage(storage.as_ref(), &filename).unwrap();
        assert_eq!(reader.header.generation, 1);
        assert_eq!(reader.header.last_tx_id, 42);
        assert_eq!(reader.header.next_inode, 3);
        assert_eq!(reader.manifest.branch, "main");
        assert_eq!(reader.footer.entry_count, 2);

        let node1 = reader.read_inode(1).unwrap().unwrap();
        match node1 {
            Node::Directory { entries, .. } => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].0, "hello.txt");
            }
            _ => panic!("expected directory"),
        }

        let node2 = reader.read_inode(2).unwrap().unwrap();
        match node2 {
            Node::File { range_map, .. } => {
                assert_eq!(range_map.len(), 1);
                let extent = range_map.query(0, 100);
                assert_eq!(extent.len(), 1);
                assert_eq!(extent[0].1, 100);
            }
            _ => panic!("expected file"),
        }

        assert!(reader.read_inode(999).unwrap().is_none());
    }

    #[test]
    fn test_summary_export_and_reader() {
        let storage = Arc::new(MemoryStorage::new());
        let mut snapshot: HashMap<u64, Arc<Node>> = HashMap::new();

        for i in 1..=50 {
            snapshot.insert(
                i,
                Arc::new(Node::File {
                    range_map: RangeMap::new(),
                    size: i * 10,
                    perm: 0o644,
                    nlink: 1,
                    uid: 1000,
                    gid: 1000,
                    atime: SystemTime::UNIX_EPOCH,
                    mtime: SystemTime::UNIX_EPOCH,
                    ctime: SystemTime::UNIX_EPOCH,
                }),
            );
        }

        let manifest = crate::log::LogManifest {
            branch: "test".to_string(),
            logs: Vec::new(),
            next_generation: 5,
            next_filename: "000005.log".to_string(),
        };

        let filename = export_summary_with_time_to_storage(
            &snapshot,
            &manifest,
            storage.as_ref(),
            4,
            999,
            51,
            SystemTime::now(),
        )
        .unwrap();

        let reader = SummaryReader::open_with_storage(storage.as_ref(), &filename).unwrap();
        assert_eq!(reader.footer.entry_count, 50);

        let all_inodes: Vec<u64> = reader
            .iter_inodes()
            .map(|res| res.unwrap().0)
            .collect();
        assert_eq!(all_inodes.len(), 50);
        for i in 1..=50 {
            assert_eq!(all_inodes[(i - 1) as usize], i);
        }
    }

    #[test]
    fn test_init_volume_creates_valid_summary_and_manifest() {
        let storage = Arc::new(MemoryStorage::new());
        init_volume_with_storage(storage.clone(), Some("dev")).unwrap();

        assert!(storage.exists("000000.summary"));

        let reader = SummaryReader::open_with_storage(storage.as_ref(), "000000.summary").unwrap();
        assert_eq!(reader.header.generation, 0);
        assert_eq!(reader.header.last_tx_id, 0);
        assert_eq!(reader.header.next_inode, 2);
        assert_eq!(reader.manifest.branch, "dev");
        assert_eq!(reader.manifest.next_generation, 1);
        assert_eq!(reader.manifest.next_filename, "000001.log");

        let root = reader.read_inode(1).unwrap().unwrap();
        match root {
            Node::Directory { entries, .. } => {
                assert!(entries.is_empty());
            }
            _ => panic!("expected directory root"),
        }
    }

    #[test]
    #[should_panic(expected = "summary checksum mismatch")]
    fn test_bitrot_in_summary_body_is_detected() {
        let storage = Arc::new(MemoryStorage::new());
        init_volume_with_storage(storage.clone(), None).unwrap();

        // Mutate a byte in the middle of 000000.summary
        let mut bytes = storage.get_file_bytes("000000.summary").unwrap();
        bytes[20] ^= 0xFF;
        storage.insert_file("000000.summary", bytes);

        // Opening corrupted summary file must panic with bitrot detected
        let _ = SummaryReader::open_with_storage(storage.as_ref(), "000000.summary");
    }
}
