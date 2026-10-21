use crate::crypto::VolumeKey;
use crate::extent_map::ExtentMap;
use crate::fs::AppendFs;
use crate::node::{Node, NodeKind};
use crate::storage::{BufferedStorageWriter, Storage, StorageReader, StorageWriter, WriteMode};
use crate::sync::OpTag;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
use std::sync::Arc;

// 20 bytes (manifest_offset + entry_count + magic) + 32-byte BLAKE3 checksum.
pub const SUMMARY_FOOTER_SIZE: usize = 52;
pub const SUMMARY_MAGIC: &[u8; 4] = b"APPS";
pub const CURRENT_SUMMARY_VERSION: u32 = 2;
pub const SUMMARY_HEADER_SIZE: usize = 66;

/// Fixed-size header written at offset 0 of `{:06}.summary` (or `{:06}_r{}.summary`),
/// exactly `SUMMARY_HEADER_SIZE` bytes - readers seek past it by that constant, so the two must agree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SummaryHeader {
    pub magic: [u8; 4],
    pub version: u32,
    pub generation: u32,
    pub revision: u16,
    pub last_batch_id: u64,
    pub next_inode: u64,
    #[serde(with = "crate::clock::serde_system_time")]
    pub created_at: std::time::SystemTime,
    /// IV for the encrypted body. Zero for unencrypted volumes.
    pub iv: [u8; 12],
    /// Length of the plaintext VolumeHeader blob that follows this header.
    pub volume_header_len: u32,
    /// Length of the uncompressed summary body in bytes.
    pub uncompressed_len: u64,
}

impl SummaryHeader {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        generation: u32,
        revision: u16,
        last_batch_id: u64,
        next_inode: u64,
        created_at: std::time::SystemTime,
        iv: [u8; 12],
        volume_header_len: u32,
        uncompressed_len: u64,
    ) -> Self {
        Self {
            magic: *SUMMARY_MAGIC,
            version: CURRENT_SUMMARY_VERSION,
            generation,
            revision,
            last_batch_id,
            next_inode,
            created_at,
            iv,
            volume_header_len,
            uncompressed_len,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        crate::wire::serialize(self).expect("SummaryHeader serialization failed")
    }

    pub fn from_bytes(buf: &[u8]) -> io::Result<Self> {
        let header: Self = crate::wire::deserialize(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if header.magic != *SUMMARY_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("not an appendfs summary file (bad magic {:?})", header.magic),
            ));
        }
        if header.version == 0 || header.version > CURRENT_SUMMARY_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unsupported summary format version {} (supported: 1..={})",
                    header.version, CURRENT_SUMMARY_VERSION
                ),
            ));
        }
        Ok(header)
    }
}

/// Footer written at EOF (last `SUMMARY_FOOTER_SIZE` bytes) of `{:06}.summary`.
///
/// `manifest_offset` is the byte offset of the manifest within the uncompressed summary body.
/// `checksum` is a full (untruncated) BLAKE3 hash of everything in the file *before*
/// the footer - the header, volume header, and compressed/encrypted body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SummaryFooter {
    pub manifest_offset: u64,
    pub entry_count: u64,
    pub magic: [u8; 4],
    pub checksum: [u8; 32],
}

impl SummaryFooter {
    pub fn new(manifest_offset: u64, entry_count: u64, checksum: [u8; 32]) -> Self {
        Self {
            manifest_offset,
            entry_count,
            magic: *SUMMARY_MAGIC,
            checksum,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        crate::wire::serialize(self).expect("SummaryFooter serialization failed")
    }

    pub fn from_bytes(buf: &[u8]) -> io::Result<Self> {
        crate::wire::deserialize(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

/// Serializes every inode, then the manifest, into `buf`.
///
/// Returns `(manifest_offset, entry_count)` for the footer.
fn write_summary_body(
    buf: &mut Vec<u8>,
    inodes: &[(u64, Arc<Node>)],
    manifest: &crate::log::LogManifest,
) -> io::Result<(u64, u64)> {
    for (inode, node_arc) in inodes {
        let mut node_to_serialize = node_arc.as_ref().clone();
        match node_to_serialize.kind {
            NodeKind::Directory { ref mut entries, .. } => entries.sort_by(|a, b| a.0.cmp(&b.0)),
            NodeKind::File { ref mut extent_map, .. } => *extent_map = coalesce_extents(extent_map),
            _ => {}
        }

        let payload =
            crate::wire::serialize(&node_to_serialize).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        buf.extend_from_slice(&inode.to_be_bytes());
        buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(&payload);
    }

    let manifest_offset = buf.len() as u64;
    let manifest_bytes = crate::wire::serialize(manifest).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    buf.extend_from_slice(&(manifest_bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(&manifest_bytes);

    Ok((manifest_offset, inodes.len() as u64))
}

/// Merges adjacent extents that are physically contiguous in the same log record, so a
/// sequential write reloads as one extent rather than one per flush chunk.
fn coalesce_extents(extent_map: &ExtentMap) -> ExtentMap {
    extent_map.coalesce()
}

/// Returns the physical filename for a given summary snapshot (e.g. "000001.summary").
pub fn summary_filename(generation: u32) -> String {
    summary_filename_with_revision(generation, 0)
}

/// Returns the physical filename for a given summary generation and revision (e.g. "000001_r2.summary").
pub fn summary_filename_with_revision(generation: u32, revision: u16) -> String {
    if revision == 0 {
        format!("{:06}.summary", generation)
    } else {
        format!("{:06}_r{}.summary", generation, revision)
    }
}

/// Finds the latest summary filename from an iterator of filenames or object keys.
///
/// Filenames are parsed via `parse_summary_filename`, comparing `(generation, revision)`
/// to return the filename with the highest generation and revision.
pub fn latest_summary_filename<'a, I>(files: I) -> Option<String>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut latest: Option<((u32, u16), &str)> = None;
    for file in files {
        if let Some((generation, rev)) = crate::log::manifest::parse_summary_filename(file)
            && latest.as_ref().is_none_or(|(gr, _)| (generation, rev) > *gr)
        {
            latest = Some(((generation, rev), file));
        }
    }
    latest.map(|(_, f)| f.to_string())
}

/// Finds the newest `.summary` file in a storage volume.
pub fn latest_summary_file(storage: &dyn Storage) -> io::Result<Option<String>> {
    let files = storage.list_files()?;
    Ok(latest_summary_filename(files.iter().map(String::as_str)))
}

/// Everything that goes into one summary snapshot.
///
/// Grouped into a struct rather than passed positionally: the eight-argument version needed
/// `#[allow(clippy::too_many_arguments)]`, and suppressing that lint is what made squeezing
/// the volume header through the `LogManifest` look preferable to adding a ninth parameter.
pub struct SummarySnapshot<'a> {
    pub inodes: &'a HashMap<u64, Arc<Node>>,
    pub manifest: &'a crate::log::LogManifest,
    /// Volume identity and key-check material, written unencrypted ahead of the body.
    pub volume_header: &'a crate::crypto::VolumeHeader,
    pub generation: u32,
    pub revision: u16,
    pub last_batch_id: u64,
    pub next_inode: u64,
    pub created_at: std::time::SystemTime,
}

/// Exports a single-file summary snapshot to a `Storage` instance.
///
/// When `volume_key` carries a real cipher the inode body is written encrypted; a plaintext
/// key writes the body as-is. The volume header is always written unencrypted, ahead of the
/// body, so a reader can identify the volume and check a key before decrypting anything.
pub fn export_summary(
    snapshot: &SummarySnapshot<'_>,
    storage: &dyn Storage,
    volume_key: &VolumeKey,
) -> io::Result<String> {
    export_summary_with_iv(snapshot, storage, volume_key, None)
}

/// Exports a single-file summary snapshot to a `Storage` instance, optionally specifying an explicit IV.
pub fn export_summary_with_iv(
    snapshot: &SummarySnapshot<'_>,
    storage: &dyn Storage,
    volume_key: &VolumeKey,
    explicit_iv: Option<[u8; 12]>,
) -> io::Result<String> {
    let SummarySnapshot {
        inodes,
        manifest,
        volume_header,
        generation,
        revision,
        last_batch_id,
        next_inode,
        created_at,
    } = *snapshot;
    let mut inodes_snapshot: Vec<(u64, Arc<Node>)> = inodes.iter().map(|(ino, arc)| (*ino, Arc::clone(arc))).collect();
    // Sort by inode so physical serialization order is deterministic
    inodes_snapshot.sort_by_key(|(ino, _)| *ino);

    let filename = summary_filename_with_revision(generation, revision);
    let tmp_filename = format!("{}.tmp", filename);

    let raw_writer = storage.open_writer(&tmp_filename, WriteMode::Overwrite)?;
    let mut writer = BufferedStorageWriter::new(raw_writer)?;
    let mut hasher = blake3::Hasher::new();

    let is_encrypted = volume_key.cipher().is_encrypted();
    let iv = if is_encrypted {
        explicit_iv.unwrap_or_else(crate::crypto::generate_random_iv)
    } else {
        [0u8; 12]
    };
    // Always written, even for an unencrypted volume. The blob used to be encryption-only,
    // which silently discarded any other volume-wide setting it carries - compression was
    // lost on plaintext volumes because there was nowhere to record it.
    let volume_header_bytes =
        crate::wire::serialize(volume_header).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let mut uncompressed_body = Vec::new();
    let (manifest_offset, entry_count) = write_summary_body(&mut uncompressed_body, &inodes_snapshot, manifest)?;

    let header = SummaryHeader::new(
        generation,
        revision,
        last_batch_id,
        next_inode,
        created_at,
        iv,
        volume_header_bytes.len() as u32,
        uncompressed_body.len() as u64,
    );
    let header_bytes = header.to_bytes();
    writer.append(&header_bytes)?;
    hasher.update(&header_bytes);

    if !volume_header_bytes.is_empty() {
        writer.append(&volume_header_bytes)?;
        hasher.update(&volume_header_bytes);
    }

    let compressed_body = crate::compress::compress_zstd_unconditional(&uncompressed_body)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("summary compression failed: {}", e)))?;

    if is_encrypted {
        let ciphertext = volume_key
            .encrypt_summary(&iv, &header_bytes, &compressed_body)
            .map_err(io::Error::other)?;
        writer.append(&ciphertext)?;
        hasher.update(&ciphertext);
    } else {
        writer.append(&compressed_body)?;
        hasher.update(&compressed_body);
    }

    let checksum: [u8; 32] = *hasher.finalize().as_bytes();
    let footer = SummaryFooter::new(manifest_offset, entry_count, checksum);
    writer.append(&footer.to_bytes())?;

    writer.sync()?;
    let size = writer.len()?;
    drop(writer);

    storage.rename(&tmp_filename, &filename)?;

    log::info!(
        "Exported summary snapshot {} (generation: {}, inodes: {}, last_batch_id: {}, size: {})",
        filename,
        generation,
        inodes_snapshot.len(),
        last_batch_id,
        crate::stats::format_bytes(size)
    );

    Ok(filename)
}

/// Initializes a fresh, empty appendfs volume on a `Storage` instance, with its root
/// directory owned by the invoking user and timestamped by `clock`.
///
/// Creates `000000.summary` containing the root directory (inode 1) and an initial
/// LogManifest.
pub fn init_volume(
    storage: Arc<dyn Storage>,
    volume_key: &VolumeKey,
    volume_header: crate::crypto::VolumeHeader,
    clock: Arc<dyn crate::clock::Clock>,
) -> io::Result<String> {
    let (uid, gid) = crate::shim::current_uid_gid();
    init_volume_with_clock_and_uids(storage, volume_key, volume_header, clock, uid, gid)
}

/// Initializes a volume with an explicit root owner.
///
/// Only for callers that need the resulting bytes to be identical on every machine, which
/// means the compat fixture generator and nothing else. Ordinary callers want
/// [`init_volume`], because a root owned by anyone other than the invoking user produces a
/// volume that mounts and then refuses every write: the FUSE shim always passes
/// `-odefault_permissions`, so the kernel enforces the recorded uid against the caller.
pub fn init_volume_with_clock_and_uids(
    storage: Arc<dyn Storage>,
    volume_key: &VolumeKey,
    volume_header: crate::crypto::VolumeHeader,
    clock: Arc<dyn crate::clock::Clock>,
    uid: u32,
    gid: u32,
) -> io::Result<String> {
    init_volume_with_clock_uids_and_iv(storage, volume_key, volume_header, clock, uid, gid, None)
}

/// Initializes a volume with an explicit root owner and optional explicit IV for generation 0 summary.
pub fn init_volume_with_clock_uids_and_iv(
    storage: Arc<dyn Storage>,
    volume_key: &VolumeKey,
    volume_header: crate::crypto::VolumeHeader,
    clock: Arc<dyn crate::clock::Clock>,
    uid: u32,
    gid: u32,
    explicit_iv: Option<[u8; 12]>,
) -> io::Result<String> {
    let files = storage.list_files()?;
    for file in files {
        if file.ends_with(".summary") || file.ends_with(".log") {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("Volume already initialized (found existing file {})", file),
            ));
        }
    }

    let fs = AppendFs::with_clock_and_uids(clock.clone(), uid, gid);
    let snapshot = fs.inner.lock(OpTag::Flush).unwrap().snapshot_all();
    let manifest = crate::log::LogManifest::new();

    export_summary_with_iv(
        &SummarySnapshot {
            inodes: &snapshot,
            manifest: &manifest,
            volume_header: &volume_header,
            generation: 0,
            revision: 0,
            last_batch_id: 0,
            next_inode: 2,
            created_at: clock.now(),
        },
        storage.as_ref(),
        volume_key,
        explicit_iv,
    )
}

/// Reader for single-file `{:06}.summary` snapshot files.
pub struct SummaryReader {
    reader: Arc<dyn StorageReader>,
    pub header: SummaryHeader,
    pub footer: SummaryFooter,
    pub manifest: crate::log::LogManifest,
    /// Parsed from the plaintext blob, so callers get volume identity without a second read.
    pub volume_header: crate::crypto::VolumeHeader,
    pub decompressed_body: Vec<u8>,
    pub volume_key: Arc<VolumeKey>,
}

/// Slices `body`, returning a clean error rather than panicking when the range is out of
/// bounds.
///
/// Offsets in the footer are attacker-controllable: the footer's BLAKE3 checksum carries no
/// key, so anyone able to rewrite the file can recompute it. Indexing the decrypted body
/// with them directly turns a tampered summary into a panic instead of an error.
fn body_slice<'a>(body: &'a [u8], start: u64, len: u64, what: &str) -> io::Result<&'a [u8]> {
    let range = usize::try_from(start)
        .ok()
        .zip(start.checked_add(len).and_then(|end| usize::try_from(end).ok()))
        .and_then(|(start, end)| body.get(start..end));

    range.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "summary {} at {}..+{} lies outside the {}-byte body",
                what,
                start,
                len,
                body.len()
            ),
        )
    })
}

/// Reads the plaintext VolumeHeader blob that follows a summary header.
///
/// Shared by [`SummaryReader::read_volume_header`], which identifies a volume before any key
/// exists, and [`SummaryReader::open`], which needs the same value once one does.
fn parse_volume_header_blob(
    reader: &dyn StorageReader,
    header: &SummaryHeader,
) -> io::Result<crate::crypto::VolumeHeader> {
    if header.volume_header_len == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "summary declares a 0-byte volume header",
        ));
    }

    // Bound the declared length by the file before allocating: this value is read straight
    // off disk, so a forged one would otherwise size a multi-gigabyte buffer that is only
    // discovered to be wrong once the read fails.
    let file_len = reader.len()?;
    if header.volume_header_len as u64 > file_len.saturating_sub(SUMMARY_HEADER_SIZE as u64) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "summary declares a {}-byte volume header, more than its {} bytes can hold",
                header.volume_header_len, file_len
            ),
        ));
    }

    let mut buf = vec![0u8; header.volume_header_len as usize];
    reader.read_exact_at(SUMMARY_HEADER_SIZE as u64, &mut buf)?;
    crate::wire::deserialize(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Verifies that the BLAKE3 checksum of bytes 0..content_len matches expected_checksum.
fn verify_summary_checksum(
    reader: &dyn StorageReader,
    content_len: u64,
    expected_checksum: &[u8; 32],
    filename: &str,
) -> io::Result<()> {
    let mut hasher = blake3::Hasher::new();
    let mut offset = 0u64;
    let mut buf = [0u8; 8192];
    while offset < content_len {
        let chunk = std::cmp::min(content_len - offset, buf.len() as u64) as usize;
        reader.read_exact_at(offset, &mut buf[..chunk])?;
        hasher.update(&buf[..chunk]);
        offset += chunk as u64;
    }

    if hasher.finalize().as_bytes() != expected_checksum {
        panic!(
            "summary checksum mismatch in {}: this data has been corrupted (possible bitrot)",
            filename
        );
    }
    Ok(())
}

/// Reads, decrypts (if encrypted), and decompresses the summary body from disk.
fn read_and_decompress_summary_body(
    reader: &dyn StorageReader,
    header: &SummaryHeader,
    header_buf: &[u8; SUMMARY_HEADER_SIZE],
    footer_offset: u64,
    volume_key: &VolumeKey,
    filename: &str,
) -> io::Result<Vec<u8>> {
    let body_offset = SUMMARY_HEADER_SIZE as u64 + header.volume_header_len as u64;
    let body_len = footer_offset.checked_sub(body_offset).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "summary file {} declares a {}-byte volume header, which overruns the file",
                filename, header.volume_header_len
            ),
        )
    })? as usize;
    let mut body_bytes = vec![0u8; body_len];
    reader.read_exact_at(body_offset, &mut body_bytes)?;

    let compressed_bytes = if volume_key.cipher().is_encrypted() {
        volume_key
            .decrypt_summary(&header.iv, header_buf, &body_bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
    } else {
        body_bytes
    };

    let uncompressed_len = usize::try_from(header.uncompressed_len).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "summary uncompressed length {} exceeds platform address space",
                header.uncompressed_len
            ),
        )
    })?;
    crate::compress::decompress_zstd_exact(&compressed_bytes, uncompressed_len)
}

impl SummaryReader {
    /// Reads and parses the `SummaryHeader` from an open reader, validating length, magic, and version,
    /// and returning the parsed header along with the raw header bytes.
    fn read_summary_header_from_reader(
        reader: &dyn StorageReader,
        filename: &str,
    ) -> io::Result<(SummaryHeader, [u8; SUMMARY_HEADER_SIZE])> {
        if reader.len()? < SUMMARY_HEADER_SIZE as u64 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("summary file {} is too short", filename),
            ));
        }

        let mut header_buf = [0u8; SUMMARY_HEADER_SIZE];
        reader.read_exact_at(0, &mut header_buf)?;
        let header = SummaryHeader::from_bytes(&header_buf)?;
        Ok((header, header_buf))
    }

    /// Reads and parses the `SummaryHeader` from offset 0 of a `.summary` file, validating
    /// file size, magic, and format version without reading, decrypting, or decompressing the body.
    pub fn read_summary_header(storage: &dyn Storage, filename: &str) -> io::Result<SummaryHeader> {
        let reader = storage.open_reader(filename)?;
        Self::read_summary_header_from_reader(reader.as_ref(), filename).map(|(h, _)| h)
    }

    /// Reads the VolumeHeader metadata from a summary file without requiring full body decryption.
    pub fn read_volume_header(storage: &dyn Storage, filename: &str) -> io::Result<crate::crypto::VolumeHeader> {
        let reader = storage.open_reader(filename)?;
        let (header, _) = Self::read_summary_header_from_reader(reader.as_ref(), filename)?;
        parse_volume_header_blob(reader.as_ref(), &header)
    }

    /// Opens a `.summary` file from a `Storage` instance.
    pub fn open(storage: &dyn Storage, filename: &str, volume_key: Arc<VolumeKey>) -> io::Result<Self> {
        let reader = storage.open_reader(filename)?;
        let file_len = reader.len()?;

        if file_len < (SUMMARY_HEADER_SIZE + SUMMARY_FOOTER_SIZE) as u64 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("summary file {} is too short ({} bytes)", filename, file_len),
            ));
        }

        // 1. Read SummaryHeader at offset 0
        let (header, header_buf) = Self::read_summary_header_from_reader(reader.as_ref(), filename)?;

        // 1b. Parse the plaintext volume header blob, if any.
        let volume_header = parse_volume_header_blob(reader.as_ref(), &header)?;

        // The volume says how it is encrypted and the caller supplies a key; if those
        // disagree, decide nothing and say so. Routing purely on the key would read an
        // encrypted body as plaintext (garbage, reported as corruption), and routing purely
        // on the file would trust an unauthenticated byte. Requiring agreement means a
        // flipped `cipher` is *detected* rather than either trusted or silently ignored.
        if volume_header.cipher != volume_key.cipher() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "summary file {} is a {} volume but the supplied key is for {}",
                    filename,
                    volume_header.cipher,
                    volume_key.cipher()
                ),
            ));
        }

        // 2. Read SummaryFooter at EOF
        let footer_offset = file_len - SUMMARY_FOOTER_SIZE as u64;
        let mut footer_buf = [0u8; SUMMARY_FOOTER_SIZE];
        reader.read_exact_at(footer_offset, &mut footer_buf)?;
        let footer = SummaryFooter::from_bytes(&footer_buf)?;

        // 3. Verify the whole-file checksum before trusting anything in this summary
        let content_len = file_len.saturating_sub(SUMMARY_FOOTER_SIZE as u64);
        verify_summary_checksum(reader.as_ref(), content_len, &footer.checksum, filename)?;

        let decompressed_body = read_and_decompress_summary_body(
            reader.as_ref(),
            &header,
            &header_buf,
            footer_offset,
            &volume_key,
            filename,
        )?;

        // `entry_count` also comes from the rewritable footer, and it sizes allocations.
        // Bound it by what the decompressed body could possibly hold before trusting it, or a
        // forged count aborts the process on an oversized allocation.
        footer
            .entry_count
            .checked_mul(12)
            .filter(|bytes| *bytes <= decompressed_body.len() as u64)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "summary file {} claims {} entries, more than its {} decompressed bytes can hold",
                        filename,
                        footer.entry_count,
                        decompressed_body.len()
                    ),
                )
            })?;

        if footer.manifest_offset > decompressed_body.len() as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "summary file {} has manifest_offset {} beyond decompressed body length {}",
                    filename,
                    footer.manifest_offset,
                    decompressed_body.len()
                ),
            ));
        }

        // 4. Read LogManifest from manifest_offset
        let len_bytes = body_slice(&decompressed_body, footer.manifest_offset, 4, "manifest length")?;
        let manifest_len = u32::from_be_bytes(len_bytes.try_into().unwrap()) as u64;
        let manifest_bytes = body_slice(&decompressed_body, footer.manifest_offset + 4, manifest_len, "manifest")?;
        let manifest: crate::log::LogManifest = if header.version == 1 {
            let manifest_v1: crate::log::manifest::LogManifestV1 =
                crate::wire::deserialize(manifest_bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            manifest_v1.into_v2()
        } else {
            crate::wire::deserialize(manifest_bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        };

        Ok(Self {
            reader,
            header,
            footer,
            manifest,
            volume_header,
            decompressed_body,
            volume_key,
        })
    }

    /// Returns the underlying storage reader.
    pub fn reader(&self) -> &Arc<dyn StorageReader> {
        &self.reader
    }

    /// Reads and deserializes all inodes sequentially from this summary file into an in-memory HashMap.
    pub fn read_all_inodes(&self) -> io::Result<HashMap<u64, Arc<Node>>> {
        let slice = body_slice(&self.decompressed_body, 0, self.footer.manifest_offset, "inode records")?;
        parse_inodes_slice(slice, self.footer.entry_count)
    }

    /// Reads and deserializes a single `Node` for `inode` from this summary file.
    #[cfg(any(test, feature = "testing"))]
    pub fn read_inode(&self, inode: u64) -> io::Result<Option<Node>> {
        let inodes = self.read_all_inodes()?;
        Ok(inodes.get(&inode).map(|arc| arc.as_ref().clone()))
    }

    /// Iterates through all `(inode, Node)` stored in this summary file in ascending inode order.
    #[cfg(any(test, feature = "testing"))]
    pub fn iter_inodes(&self) -> io::Result<impl Iterator<Item = (u64, Node)>> {
        let inodes = self.read_all_inodes()?;
        let mut entries: Vec<(u64, Node)> = inodes
            .into_iter()
            .map(|(ino, arc)| (ino, Arc::try_unwrap(arc).unwrap_or_else(|a| (*a).clone())))
            .collect();
        entries.sort_by_key(|(ino, _)| *ino);
        Ok(entries.into_iter())
    }
}

/// Parses a sequential slice of `[inode: u64][len: u32][payload]` records into a HashMap.
fn parse_inodes_slice(slice: &[u8], expected_count: u64) -> io::Result<HashMap<u64, Arc<Node>>> {
    let mut map = HashMap::with_capacity(expected_count as usize);
    let mut offset = 0;
    while offset < slice.len() {
        if offset + 12 > slice.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "corrupted summary inode framing",
            ));
        }
        let ino = u64::from_be_bytes(slice[offset..offset + 8].try_into().unwrap());
        let payload_len = u32::from_be_bytes(slice[offset + 8..offset + 12].try_into().unwrap()) as usize;
        offset += 12;
        if offset + payload_len > slice.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "corrupted summary inode payload",
            ));
        }
        let payload = &slice[offset..offset + payload_len];
        let node: Node =
            crate::wire::deserialize(payload).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        map.insert(ino, Arc::new(node));
        offset += payload_len;
    }
    if map.len() as u64 != expected_count {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "summary inode count mismatch: expected {} inodes, parsed {}",
                expected_count,
                map.len()
            ),
        ));
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extent_map::Extent;
    use crate::node::InodeMeta;
    use crate::storage::{FaultStorage, MemoryStorage};
    use std::time::SystemTime;

    #[test]
    fn test_summary_bincode_serialization() {
        let storage = Arc::new(MemoryStorage::new());
        let mut snapshot: HashMap<u64, Arc<Node>> = HashMap::new();

        let root_entries = vec![("hello.txt".to_string(), 2)];
        snapshot.insert(
            1,
            Arc::new(Node {
                meta: InodeMeta::new(0o755, 2, 1000, 1000, SystemTime::UNIX_EPOCH),
                kind: NodeKind::Directory {
                    parent: 1,
                    entries: root_entries,
                },
            }),
        );

        let mut rmap = ExtentMap::new();
        rmap.insert(0, Extent::new_disk(1, 24, 137, 0, 100));
        snapshot.insert(
            2,
            Arc::new(Node {
                meta: InodeMeta::new(0o644, 1, 1000, 1000, SystemTime::UNIX_EPOCH),
                kind: NodeKind::File {
                    extent_map: rmap,
                    size: 100,
                },
            }),
        );

        let manifest = crate::log::LogManifest::new();

        let filename = export_summary(
            &SummarySnapshot {
                inodes: &snapshot,
                manifest: &manifest,
                volume_header: &crate::crypto::VolumeHeader::plaintext(),
                generation: 1,
                revision: 0,
                last_batch_id: 42,
                next_inode: 3,
                created_at: SystemTime::now(),
            },
            storage.as_ref(),
            &VolumeKey::plaintext(),
        )
        .unwrap();

        let reader = SummaryReader::open(storage.as_ref(), &filename, VolumeKey::plaintext_arc()).unwrap();
        assert_eq!(reader.header.generation, 1);
        assert_eq!(reader.header.last_batch_id, 42);
        assert_eq!(reader.header.next_inode, 3);
        assert_eq!(reader.footer.entry_count, 2);

        let node1 = reader.read_inode(1).unwrap().unwrap();
        match node1.kind {
            NodeKind::Directory { entries, .. } => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].0, "hello.txt");
            }
            _ => panic!("expected directory"),
        }

        let node2 = reader.read_inode(2).unwrap().unwrap();
        match node2.kind {
            NodeKind::File { extent_map, .. } => {
                assert_eq!(extent_map.len(), 1);
                let extent = extent_map.query(0, 100);
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
                Arc::new(Node {
                    meta: InodeMeta::new(0o644, 1, 1000, 1000, SystemTime::UNIX_EPOCH),
                    kind: NodeKind::File {
                        extent_map: ExtentMap::new(),
                        size: i * 10,
                    },
                }),
            );
        }

        let manifest = crate::log::LogManifest::new();

        let filename = export_summary(
            &SummarySnapshot {
                inodes: &snapshot,
                manifest: &manifest,
                volume_header: &crate::crypto::VolumeHeader::plaintext(),
                generation: 4,
                revision: 0,
                last_batch_id: 999,
                next_inode: 51,
                created_at: SystemTime::now(),
            },
            storage.as_ref(),
            &VolumeKey::plaintext(),
        )
        .unwrap();

        let reader = SummaryReader::open(storage.as_ref(), &filename, VolumeKey::plaintext_arc()).unwrap();
        assert_eq!(reader.footer.entry_count, 50);

        let all_inodes: Vec<u64> = reader.iter_inodes().unwrap().map(|(ino, _)| ino).collect();
        assert_eq!(all_inodes.len(), 50);
        for i in 1..=50 {
            assert_eq!(all_inodes[(i - 1) as usize], i);
        }
    }

    #[test]
    fn test_init_volume_creates_valid_summary_and_manifest() {
        let storage = Arc::new(MemoryStorage::new());
        init_volume(
            storage.clone(),
            &crate::crypto::VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
            std::sync::Arc::new(crate::clock::SystemClock),
        )
        .unwrap();

        assert!(storage.exists("000000.summary"));

        let reader = SummaryReader::open(storage.as_ref(), "000000.summary", VolumeKey::plaintext_arc()).unwrap();
        assert_eq!(reader.header.generation, 0);
        assert_eq!(reader.header.last_batch_id, 0);
        assert_eq!(reader.header.next_inode, 2);
        assert!(reader.manifest.logs.is_empty());

        let root = reader.read_inode(1).unwrap().unwrap();
        match root.kind {
            NodeKind::Directory { entries, .. } => {
                assert!(entries.is_empty());
            }
            _ => panic!("expected directory root"),
        }
    }

    #[test]
    fn test_header_serializes_to_exactly_the_declared_size() {
        // Readers seek past the header by SUMMARY_HEADER_SIZE to reach the volume header
        // blob, so a field added or removed without updating the constant would silently
        // misalign every subsequent offset rather than fail loudly.
        let header = SummaryHeader::new(1, 0, 2, 3, SystemTime::UNIX_EPOCH, [0u8; 12], 0, 0);
        assert_eq!(header.to_bytes().len(), SUMMARY_HEADER_SIZE);
    }

    #[test]
    fn test_summary_from_a_different_format_version_is_rejected() {
        let storage = Arc::new(MemoryStorage::new());
        init_volume(
            storage.clone(),
            &crate::crypto::VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
            std::sync::Arc::new(crate::clock::SystemClock),
        )
        .unwrap();

        // Restamp the version field (bytes 4..8) as a different format version. The volume header
        // blob that follows would still deserialize into something plausible, so without
        // an explicit version check this would be misread rather than refused.
        let mut bytes = storage.get_file_bytes("000000.summary").unwrap();
        bytes[4..8].copy_from_slice(&(CURRENT_SUMMARY_VERSION + 1).to_be_bytes());
        storage.insert_file("000000.summary", bytes);

        let Err(err) = SummaryReader::open(storage.as_ref(), "000000.summary", VolumeKey::plaintext_arc()) else {
            panic!("summary from a different format version must not open");
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("unsupported summary format version"),
            "expected a version error, got: {}",
            err
        );
    }

    #[test]
    fn test_volume_header_is_readable_without_the_key() {
        let storage = Arc::new(MemoryStorage::new());
        let master = crate::crypto::MasterKey::new([0x5Au8; 32]);
        let (header, key) =
            crate::crypto::VolumeHeader::new_encrypted(&master, crate::compress::Compression::None).unwrap();
        let expected_id = header.volume_id;

        init_volume(
            storage.clone(),
            &key,
            header,
            std::sync::Arc::new(crate::clock::SystemClock),
        )
        .unwrap();

        // The point of keeping this blob in plaintext: identify the volume and validate a
        // key before any body decryption is attempted.
        let read_back = SummaryReader::read_volume_header(storage.as_ref(), "000000.summary").unwrap();
        assert_eq!(read_back.cipher, crate::crypto::CipherSuite::ChaCha20Poly1305);
        assert_eq!(read_back.volume_id, expected_id);
        assert!(read_back.unlock(&master).is_ok());

        let wrong = crate::crypto::MasterKey::new([0x00u8; 32]);
        assert_eq!(
            read_back.unlock(&wrong).unwrap_err(),
            crate::crypto::CryptoError::WrongKey
        );
    }

    #[test]
    fn test_zero_volume_header_len_fails_with_invalid_data() {
        let storage = Arc::new(MemoryStorage::new());
        let header = SummaryHeader::new(0, 0, 0, 2, std::time::SystemTime::UNIX_EPOCH, [0u8; 12], 0, 0);
        let header_bytes = header.to_bytes();
        let mut writer = storage.open_writer("000000.summary", WriteMode::CreateNew).unwrap();
        writer.append(&header_bytes).unwrap();
        writer.sync().unwrap();

        let err = SummaryReader::read_volume_header(storage.as_ref(), "000000.summary").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("0-byte volume header"));
    }

    #[test]
    #[should_panic(expected = "summary checksum mismatch")]
    fn test_bitrot_in_summary_body_is_detected() {
        let storage = Arc::new(MemoryStorage::new());
        init_volume(
            storage.clone(),
            &crate::crypto::VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
            std::sync::Arc::new(crate::clock::SystemClock),
        )
        .unwrap();

        // Mutate a byte in the middle of 000000.summary
        let mut bytes = storage.get_file_bytes("000000.summary").unwrap();
        bytes[20] ^= 0xFF;
        storage.insert_file("000000.summary", bytes);

        // Opening corrupted summary file must panic with bitrot detected
        let _ = SummaryReader::open(storage.as_ref(), "000000.summary", VolumeKey::plaintext_arc());
    }

    #[test]
    fn test_stale_tmp_from_failed_export_does_not_corrupt_next_summary() {
        let mem = Arc::new(MemoryStorage::new());
        let storage = Arc::new(FaultStorage::new(mem.clone()));

        let mut snapshot: HashMap<u64, Arc<Node>> = HashMap::new();
        snapshot.insert(
            1,
            Arc::new(Node {
                meta: InodeMeta::new(0o755, 2, 1000, 1000, SystemTime::UNIX_EPOCH),
                kind: NodeKind::Directory {
                    parent: 1,
                    entries: vec![("a.txt".to_string(), 2)],
                },
            }),
        );

        let manifest = crate::log::LogManifest::new();

        // A first export dies partway, leaving a partial 000001.summary.tmp behind.
        storage.fail_writes_after_bytes(16, true);
        let failed = export_summary(
            &SummarySnapshot {
                inodes: &snapshot,
                manifest: &manifest,
                volume_header: &crate::crypto::VolumeHeader::plaintext(),
                generation: 1,
                revision: 0,
                last_batch_id: 42,
                next_inode: 3,
                created_at: SystemTime::UNIX_EPOCH,
            },
            storage.as_ref(),
            &VolumeKey::plaintext(),
        );
        assert!(failed.is_err(), "injected write fault should fail the export");
        let stale = mem
            .get_file_bytes("000001.summary.tmp")
            .expect("failed export should leave a stale tmp");
        assert!(!stale.is_empty(), "stale tmp should hold the partial export");

        // Retrying on a healthy backend must not prefix the stale bytes to the new summary.
        storage.clear_write_limit();
        let filename = export_summary(
            &SummarySnapshot {
                inodes: &snapshot,
                manifest: &manifest,
                volume_header: &crate::crypto::VolumeHeader::plaintext(),
                generation: 1,
                revision: 0,
                last_batch_id: 42,
                next_inode: 3,
                created_at: SystemTime::UNIX_EPOCH,
            },
            storage.as_ref(),
            &VolumeKey::plaintext(),
        )
        .unwrap();

        let reader = SummaryReader::open(storage.as_ref(), &filename, VolumeKey::plaintext_arc()).unwrap();
        assert_eq!(reader.header.generation, 1);
        assert_eq!(reader.footer.entry_count, 1);
        match reader.read_inode(1).unwrap().unwrap().kind {
            NodeKind::Directory { entries, .. } => assert_eq!(entries[0].0, "a.txt"),
            _ => panic!("expected directory root"),
        }
    }

    #[test]
    fn test_summary_body_is_zstd_compressed_on_disk() {
        let storage = Arc::new(MemoryStorage::new());
        init_volume(
            storage.clone(),
            &VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
            std::sync::Arc::new(crate::clock::SystemClock),
        )
        .unwrap();

        let bytes = storage.get_file_bytes("000000.summary").unwrap();
        let header = SummaryHeader::from_bytes(&bytes[..SUMMARY_HEADER_SIZE]).unwrap();
        let body_offset = SUMMARY_HEADER_SIZE + header.volume_header_len as usize;

        // Check for zstd magic number (0xFD2FB528 in little-endian) at body_offset
        assert_eq!(
            &bytes[body_offset..body_offset + 4],
            &[0x28, 0xb5, 0x2f, 0xfd],
            "Unencrypted summary body must start with zstd magic"
        );

        let reader = SummaryReader::open(storage.as_ref(), "000000.summary", VolumeKey::plaintext_arc()).unwrap();
        assert_eq!(reader.footer.entry_count, 1);
        let root = reader.read_inode(1).unwrap().unwrap();
        assert!(root.is_dir());
    }

    #[test]
    fn test_encrypted_summary_body_compression_round_trip() {
        let storage = Arc::new(MemoryStorage::new());
        let master = crate::crypto::MasterKey::new([0x42u8; 32]);
        let (header, key) =
            crate::crypto::VolumeHeader::new_encrypted(&master, crate::compress::Compression::None).unwrap();

        init_volume(
            storage.clone(),
            &key,
            header,
            std::sync::Arc::new(crate::clock::SystemClock),
        )
        .unwrap();

        let reader = SummaryReader::open(storage.as_ref(), "000000.summary", Arc::new(key)).unwrap();
        assert_eq!(reader.footer.entry_count, 1);
        let root = reader.read_inode(1).unwrap().unwrap();
        assert!(root.is_dir());
    }

    #[test]
    fn test_corrupted_compressed_summary_body_returns_error() {
        let storage = Arc::new(MemoryStorage::new());
        init_volume(
            storage.clone(),
            &VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
            std::sync::Arc::new(crate::clock::SystemClock),
        )
        .unwrap();

        // Overwrite the compressed body with garbage, but recompute the BLAKE3 checksum
        // so that the checksum verification passes and the zstd decompressor is exercised.
        let mut bytes = storage.get_file_bytes("000000.summary").unwrap();
        let header = SummaryHeader::from_bytes(&bytes[..SUMMARY_HEADER_SIZE]).unwrap();
        let body_offset = SUMMARY_HEADER_SIZE + header.volume_header_len as usize;
        let footer_offset = bytes.len() - SUMMARY_FOOTER_SIZE;

        // Corrupt the body bytes with non-zstd garbage
        for b in &mut bytes[body_offset..footer_offset] {
            *b = 0xFF;
        }

        // Recompute BLAKE3 checksum over content before footer
        let new_checksum = *blake3::hash(&bytes[..footer_offset]).as_bytes();
        let len = bytes.len();
        bytes[len - 32..].copy_from_slice(&new_checksum);
        storage.insert_file("000000.summary", bytes);

        let Err(err) = SummaryReader::open(storage.as_ref(), "000000.summary", VolumeKey::plaintext_arc()) else {
            panic!("expected error on corrupted body");
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_uncompressed_len_tampering_fails_aead() {
        let storage = Arc::new(MemoryStorage::new());
        let master = crate::crypto::MasterKey::new([0x42u8; 32]);
        let (header, key) =
            crate::crypto::VolumeHeader::new_encrypted(&master, crate::compress::Compression::None).unwrap();

        init_volume(
            storage.clone(),
            &key,
            header,
            std::sync::Arc::new(crate::clock::SystemClock),
        )
        .unwrap();

        // Tamper with uncompressed_len, the last field of SummaryHeader. Derived from
        // SUMMARY_HEADER_SIZE rather than hardcoded, so it follows the header's layout.
        let mut bytes = storage.get_file_bytes("000000.summary").unwrap();
        bytes[SUMMARY_HEADER_SIZE - 8..SUMMARY_HEADER_SIZE].copy_from_slice(&999999u64.to_be_bytes());

        // Recompute whole-file BLAKE3 checksum so footer verification passes
        let footer_offset = bytes.len() - SUMMARY_FOOTER_SIZE;
        let new_checksum = *blake3::hash(&bytes[..footer_offset]).as_bytes();
        let len = bytes.len();
        bytes[len - 32..].copy_from_slice(&new_checksum);
        storage.insert_file("000000.summary", bytes);

        // AEAD verification must fail because uncompressed_len is part of the AAD
        let Err(err) = SummaryReader::open(storage.as_ref(), "000000.summary", Arc::new(key)) else {
            panic!("expected AEAD authentication error when uncompressed_len is modified");
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_uncompressed_len_mismatch_fails_plaintext() {
        let storage = Arc::new(MemoryStorage::new());
        init_volume(
            storage.clone(),
            &VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
            std::sync::Arc::new(crate::clock::SystemClock),
        )
        .unwrap();

        // Tamper with uncompressed_len, the last field of SummaryHeader. Derived from
        // SUMMARY_HEADER_SIZE rather than hardcoded, so it follows the header's layout.
        let mut bytes = storage.get_file_bytes("000000.summary").unwrap();
        bytes[SUMMARY_HEADER_SIZE - 8..SUMMARY_HEADER_SIZE].copy_from_slice(&999999u64.to_be_bytes());

        // Recompute whole-file BLAKE3 checksum so footer verification passes
        let footer_offset = bytes.len() - SUMMARY_FOOTER_SIZE;
        let new_checksum = *blake3::hash(&bytes[..footer_offset]).as_bytes();
        let len = bytes.len();
        bytes[len - 32..].copy_from_slice(&new_checksum);
        storage.insert_file("000000.summary", bytes);

        // Decompression verification must fail due to uncompressed length mismatch
        let Err(err) = SummaryReader::open(storage.as_ref(), "000000.summary", VolumeKey::plaintext_arc()) else {
            panic!("expected decompression error on length mismatch");
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("mismatch"));
    }

    #[test]
    fn test_summary_reader_read_summary_header() {
        let storage = Arc::new(MemoryStorage::new());
        init_volume(
            storage.clone(),
            &VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
            std::sync::Arc::new(crate::clock::SystemClock),
        )
        .unwrap();

        // 1. Valid summary file: read_summary_header parses without full decompression
        let header = SummaryReader::read_summary_header(storage.as_ref(), "000000.summary").unwrap();
        assert_eq!(header.magic, *SUMMARY_MAGIC);
        assert_eq!(header.version, CURRENT_SUMMARY_VERSION);
        assert_eq!(header.generation, 0);
        assert_eq!(header.revision, 0);
        assert_eq!(header.last_batch_id, 0);
        assert_eq!(header.next_inode, 2);

        // 2. Truncated summary file (< header + footer size)
        storage.insert_file("short.summary", vec![0u8; 10]);
        let err = SummaryReader::read_summary_header(storage.as_ref(), "short.summary").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);

        // 3. Invalid magic
        let mut bad_magic_bytes = storage.get_file_bytes("000000.summary").unwrap();
        bad_magic_bytes[0..4].copy_from_slice(b"BAD!");
        storage.insert_file("bad_magic.summary", bad_magic_bytes);
        let err = SummaryReader::read_summary_header(storage.as_ref(), "bad_magic.summary").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_latest_summary_filename_and_file() {
        assert_eq!(latest_summary_filename(Vec::<&str>::new()), None);
        assert_eq!(latest_summary_filename(["not_a_summary.txt", "000001.log"]), None);

        let files = ["000000.summary", "000001.summary", "000003.summary", "000002.summary"];
        assert_eq!(latest_summary_filename(files), Some("000003.summary".to_string()));

        let files_with_rev = [
            "000003.summary",
            "000003_r1.summary",
            "000003_r3.summary",
            "000003_r2.summary",
        ];
        assert_eq!(
            latest_summary_filename(files_with_rev),
            Some("000003_r3.summary".to_string())
        );

        let mixed = ["prefix/000001.summary", "000004.summary", "000002_r5.summary"];
        assert_eq!(latest_summary_filename(mixed), Some("000004.summary".to_string()));

        let storage = Arc::new(MemoryStorage::new());
        assert_eq!(latest_summary_file(storage.as_ref()).unwrap(), None);

        storage.insert_file("000000.summary", vec![]);
        storage.insert_file("000005.summary", vec![]);
        storage.insert_file("000002.summary", vec![]);
        assert_eq!(
            latest_summary_file(storage.as_ref()).unwrap(),
            Some("000005.summary".to_string())
        );
    }
}
