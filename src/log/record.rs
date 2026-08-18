use serde::{Deserialize, Serialize};
use std::time::SystemTime;

pub const FILE_MAGIC: [u8; 4] = *b"APPF";
// Bumped for RecordHeader's new checksum field - a breaking format change, so old logs
// are cleanly rejected (FileHeader::from_bytes) rather than silently misparsed.
pub const CURRENT_VERSION: u32 = 2;
pub const FILE_HEADER_SIZE: usize = 24;
pub const RECORD_HEADER_SIZE: usize = 25;
pub const RECORD_CHECKSUM_SIZE: usize = 4;

/// Computes the truncated-BLAKE3 checksum stored in a record's header, over that
/// record's payload bytes. 4 bytes (1-in-4-billion false-negative rate) is far more
/// than needed to detect accidental bitrot/corruption - this is not a security
/// mechanism (an adversary who can modify the payload can trivially recompute a
/// matching checksum, since it's unkeyed), just a way for recovery to notice when a
/// record's content no longer matches what was actually written.
pub fn checksum_payload(payload: &[u8]) -> [u8; RECORD_CHECKSUM_SIZE] {
    let hash = blake3::hash(payload);
    let mut out = [0u8; RECORD_CHECKSUM_SIZE];
    out.copy_from_slice(&hash.as_bytes()[..RECORD_CHECKSUM_SIZE]);
    out
}

/// Fixed-size header written at offset 0 of every `.log` file.
#[repr(C)]
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileHeader {
    pub magic: [u8; 4],
    pub version: u32,
    pub generation: u64,
    #[serde(with = "crate::clock::serde_system_time")]
    pub created_at: SystemTime,
}

impl FileHeader {
    pub fn new(generation: u64, created_at: SystemTime) -> Self {
        Self {
            magic: FILE_MAGIC,
            version: CURRENT_VERSION,
            generation,
            created_at,
        }
    }

    pub fn to_bytes(&self) -> [u8; FILE_HEADER_SIZE] {
        let mut buf = [0u8; FILE_HEADER_SIZE];
        buf[0..4].copy_from_slice(&self.magic);
        buf[4..8].copy_from_slice(&self.version.to_le_bytes());
        buf[8..16].copy_from_slice(&self.generation.to_le_bytes());
        let (secs, _) = crate::clock::system_time_to_unix(self.created_at);
        buf[16..24].copy_from_slice(&secs.to_le_bytes());
        buf
    }

    pub fn from_bytes(bytes: &[u8; FILE_HEADER_SIZE]) -> Result<Self, &'static str> {
        let magic = [bytes[0], bytes[1], bytes[2], bytes[3]];
        if magic != FILE_MAGIC {
            return Err("Invalid log file magic bytes");
        }
        let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        if version != CURRENT_VERSION {
            return Err("Unsupported log format version");
        }
        let generation = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let created_at_sec = i64::from_le_bytes(bytes[16..24].try_into().unwrap());
        let created_at = crate::clock::unix_to_system_time(created_at_sec, 0);

        Ok(Self {
            magic,
            version,
            generation,
            created_at,
        })
    }
}

/// Operation codes identifying log record types.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpCode {
    Create = 1,
    Mkdir = 2,
    Write = 3,
    Unlink = 4,
    Rmdir = 5,
    Symlink = 6,
    Rename = 7,
    Setattr = 8,
    Link = 9,
    /// Trailer written once, after every other record belonging to one
    /// flush batch. Confirms that batch is complete and safe to replay - see
    /// `FlushCommitPayload`.
    FlushCommit = 10,
}

impl TryFrom<u8> for OpCode {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(OpCode::Create),
            2 => Ok(OpCode::Mkdir),
            3 => Ok(OpCode::Write),
            4 => Ok(OpCode::Unlink),
            5 => Ok(OpCode::Rmdir),
            6 => Ok(OpCode::Symlink),
            7 => Ok(OpCode::Rename),
            8 => Ok(OpCode::Setattr),
            9 => Ok(OpCode::Link),
            10 => Ok(OpCode::FlushCommit),
            _ => Err("Unknown operation code"),
        }
    }
}

impl std::fmt::Display for OpCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            OpCode::Create => "Create",
            OpCode::Mkdir => "Mkdir",
            OpCode::Write => "Write",
            OpCode::Unlink => "Unlink",
            OpCode::Rmdir => "Rmdir",
            OpCode::Symlink => "Symlink",
            OpCode::Rename => "Rename",
            OpCode::Setattr => "Setattr",
            OpCode::Link => "Link",
            OpCode::FlushCommit => "FlushCommit",
        };
        f.pad(name)
    }
}

/// Compact per-record header (25 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordHeader {
    pub op_code: OpCode,
    pub tx_id: u64,
    pub inode: u64,
    pub payload_len: u32,
    /// Truncated BLAKE3 checksum of the payload - see `checksum_payload`.
    pub checksum: [u8; RECORD_CHECKSUM_SIZE],
}

impl RecordHeader {
    pub fn to_bytes(&self) -> [u8; RECORD_HEADER_SIZE] {
        let mut buf = [0u8; RECORD_HEADER_SIZE];
        buf[0] = self.op_code as u8;
        buf[1..9].copy_from_slice(&self.tx_id.to_le_bytes());
        buf[9..17].copy_from_slice(&self.inode.to_le_bytes());
        buf[17..21].copy_from_slice(&self.payload_len.to_le_bytes());
        buf[21..25].copy_from_slice(&self.checksum);
        buf
    }

    pub fn from_bytes(bytes: &[u8; RECORD_HEADER_SIZE]) -> Result<Self, &'static str> {
        let op_code = OpCode::try_from(bytes[0])?;
        let tx_id = u64::from_le_bytes(bytes[1..9].try_into().unwrap());
        let inode = u64::from_le_bytes(bytes[9..17].try_into().unwrap());
        let payload_len = u32::from_le_bytes(bytes[17..21].try_into().unwrap());
        let checksum = bytes[21..25].try_into().unwrap();

        Ok(Self {
            op_code,
            tx_id,
            inode,
            payload_len,
            checksum,
        })
    }
}

/// Payload for the `OpCode::FlushCommit` trailer written once per flush
/// batch, after all of that batch's other records.
///
/// Recovery buffers records as it reads them and only replays them into filesystem
/// state once it reaches the matching `FlushCommit` for that run - a trailing group of
/// records at end-of-file with no `FlushCommit` after them (a crash mid-flush) is
/// discarded rather than partially applied. `record_count` is a defensive cross-check
/// only (this codebase has no per-record checksums yet): recovery verifies it matches
/// the number of records actually buffered since the previous commit, and treats a
/// mismatch the same as a missing trailer.
///
/// Also carries the flush's wall-clock time, for point-in-time replay/time-travel.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlushCommitPayload {
    #[serde(with = "crate::clock::serde_system_time")]
    pub timestamp: SystemTime,
    pub record_count: u32,
}

/// Metadata payload preceding write bytes for file write operations (`OP_WRITE`).
///
/// `op_time` is the wall-clock time this write happened, applied to mtime/ctime on
/// replay (not atime - a write doesn't update atime, matching live behavior). Without
/// it, replay has no choice but to stamp the *replay* time instead of when the write
/// actually occurred.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteMeta {
    pub file_offset: u64,
    #[serde(with = "crate::clock::serde_system_time")]
    pub op_time: SystemTime,
}

/// Structured metadata payload for file creation operations (`OP_CREATE`).
///
/// `created_at` is applied to atime/mtime/ctime of the new node on replay - see
/// `WriteMeta::op_time` for why this needs to be carried explicitly.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CreatePayload {
    pub parent: u64,
    pub name: String,
    pub mode: u32,
    #[serde(default)]
    pub uid: u32,
    #[serde(default)]
    pub gid: u32,
    #[serde(with = "crate::clock::serde_system_time")]
    pub created_at: SystemTime,
}

/// Structured metadata payload for directory creation operations (`OP_MKDIR`).
/// See `CreatePayload::created_at`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct MkdirPayload {
    pub parent: u64,
    pub name: String,
    pub mode: u32,
    #[serde(default)]
    pub uid: u32,
    #[serde(default)]
    pub gid: u32,
    #[serde(with = "crate::clock::serde_system_time")]
    pub created_at: SystemTime,
}

/// Structured metadata payload for file unlink operations (`OP_UNLINK`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UnlinkPayload {
    pub parent: u64,
    pub name: String,
    #[serde(default = "crate::clock::default_epoch", with = "crate::clock::serde_system_time")]
    pub op_time: SystemTime,
}

/// Structured metadata payload for directory rmdir operations (`OP_RMDIR`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RmdirPayload {
    pub parent: u64,
    pub name: String,
    #[serde(default = "crate::clock::default_epoch", with = "crate::clock::serde_system_time")]
    pub op_time: SystemTime,
}

/// Structured metadata payload for symlink creation operations (`OP_SYMLINK`).
/// See `CreatePayload::created_at`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SymlinkPayload {
    pub parent: u64,
    pub name: String,
    pub target: String,
    #[serde(default)]
    pub uid: u32,
    #[serde(default)]
    pub gid: u32,
    #[serde(with = "crate::clock::serde_system_time")]
    pub created_at: SystemTime,
}

/// Structured metadata payload for rename operations (`OP_RENAME`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RenamePayload {
    pub parent: u64,
    pub name: String,
    pub new_parent: u64,
    pub new_name: String,
    #[serde(default = "crate::clock::default_epoch", with = "crate::clock::serde_system_time")]
    pub op_time: SystemTime,
}

/// Structured metadata payload for setattr operations (`OP_SETATTR`).
///
/// `atime`/`mtime` carry the *user-requested* value when explicitly set (a `utimes()`
/// call can set either to an arbitrary value, not necessarily "now"). `op_time` is
/// different: it's the wall-clock time this setattr call happened, applied to ctime
/// whenever any other field is `Some` - mirroring live, which touches ctime inside
/// each individual to_set-bit branch, never on a call that changes nothing. `op_time`
/// is also applied to mtime specifically when `size` is `Some` (POSIX truncate
/// semantics touch both mtime and ctime, unlike mode/uid/gid, which only touch ctime).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SetattrPayload {
    #[serde(default)]
    pub mode: Option<u32>,
    #[serde(default)]
    pub uid: Option<u32>,
    #[serde(default)]
    pub gid: Option<u32>,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default, with = "crate::clock::serde_system_time_opt")]
    pub atime: Option<SystemTime>,
    #[serde(default, with = "crate::clock::serde_system_time_opt")]
    pub mtime: Option<SystemTime>,
    #[serde(default = "crate::clock::default_epoch", with = "crate::clock::serde_system_time")]
    pub op_time: SystemTime,
}

/// Structured metadata payload for hard link operations (`OP_LINK`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct LinkPayload {
    pub ino: u64,
    pub new_parent: u64,
    pub new_name: String,
    #[serde(default = "crate::clock::default_epoch", with = "crate::clock::serde_system_time")]
    pub op_time: SystemTime,
}

/// Unified typed representation of any decoded log record payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedPayload<'a> {
    Create(CreatePayload),
    Mkdir(MkdirPayload),
    Write { meta: WriteMeta, data: &'a [u8] },
    Unlink(UnlinkPayload),
    Rmdir(RmdirPayload),
    Symlink(SymlinkPayload),
    Rename(RenamePayload),
    Setattr(SetattrPayload),
    Link(LinkPayload),
    FlushCommit(FlushCommitPayload),
}

impl DecodedPayload<'_> {
    /// Extracts the timestamp associated with this operation (either creation time, operation time, or flush timestamp).
    pub fn op_time(&self) -> Option<SystemTime> {
        match self {
            DecodedPayload::Create(p) => Some(p.created_at),
            DecodedPayload::Mkdir(p) => Some(p.created_at),
            DecodedPayload::Write { meta, .. } => Some(meta.op_time),
            DecodedPayload::Unlink(p) => Some(p.op_time),
            DecodedPayload::Rmdir(p) => Some(p.op_time),
            DecodedPayload::Symlink(p) => Some(p.created_at),
            DecodedPayload::Rename(p) => Some(p.op_time),
            DecodedPayload::Setattr(p) => Some(p.op_time),
            DecodedPayload::Link(p) => Some(p.op_time),
            DecodedPayload::FlushCommit(p) => Some(p.timestamp),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_header_serialization() {
        let time = crate::clock::unix_to_system_time(1721838000, 0);
        let header = FileHeader::new(42, time);
        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), FILE_HEADER_SIZE);

        let deserialized = FileHeader::from_bytes(&bytes).unwrap();
        assert_eq!(header, deserialized);
    }

    #[test]
    fn test_record_header_serialization() {
        let header = RecordHeader {
            op_code: OpCode::Write,
            tx_id: 1001,
            inode: 5,
            payload_len: 4096,
            checksum: [0xAA, 0xBB, 0xCC, 0xDD],
        };
        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), RECORD_HEADER_SIZE);

        let deserialized = RecordHeader::from_bytes(&bytes).unwrap();
        assert_eq!(header, deserialized);
    }

    #[test]
    fn test_checksum_payload_detects_bitflip() {
        let original = b"the quick brown fox".to_vec();
        let checksum = checksum_payload(&original);

        let mut corrupted = original.clone();
        corrupted[3] ^= 0x01; // flip one bit
        assert_ne!(checksum_payload(&corrupted), checksum);

        assert_eq!(checksum_payload(&original), checksum);
    }

    #[test]
    fn test_bincode_payload_serialization() {
        let create = CreatePayload {
            parent: 1,
            name: "hello.txt".to_string(),
            mode: 0o644,
            uid: 1000,
            gid: 1000,
            created_at: crate::clock::unix_to_system_time(1_721_838_000, 0),
        };
        let bytes = bincode::serialize(&create).unwrap();
        let deserialized: CreatePayload = bincode::deserialize(&bytes).unwrap();
        assert_eq!(create, deserialized);
    }
}
