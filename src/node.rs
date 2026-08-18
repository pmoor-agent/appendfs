use crate::log::SharedExtentState;
use crate::range_map::RangeMap;
use crate::shim::FileType;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

/// Common POSIX metadata fields shared by all inode types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InodeMeta {
    pub perm: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    #[serde(with = "crate::clock::serde_system_time")]
    pub atime: SystemTime,
    #[serde(with = "crate::clock::serde_system_time")]
    pub mtime: SystemTime,
    #[serde(with = "crate::clock::serde_system_time")]
    pub ctime: SystemTime,
}

impl InodeMeta {
    pub fn new(perm: u32, nlink: u32, uid: u32, gid: u32, time: SystemTime) -> Self {
        Self {
            perm,
            nlink,
            uid,
            gid,
            atime: time,
            mtime: time,
            ctime: time,
        }
    }
}

/// Type-specific contents and payloads for inodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeKind {
    Directory {
        parent: u64,
        entries: Vec<(String, u64)>,
    },
    File {
        range_map: RangeMap<SharedExtentState>,
        size: u64,
    },
    Symlink {
        target: String,
    },
}

/// In-memory filesystem node with unified metadata and type-specific kind.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub meta: InodeMeta,
    pub kind: NodeKind,
}

impl Node {
    pub fn new_dir(parent: u64, perm: u32, uid: u32, gid: u32, time: SystemTime) -> Self {
        Self {
            meta: InodeMeta::new(perm, 2, uid, gid, time),
            kind: NodeKind::Directory {
                parent,
                entries: Vec::new(),
            },
        }
    }

    pub fn new_file(perm: u32, uid: u32, gid: u32, time: SystemTime) -> Self {
        Self {
            meta: InodeMeta::new(perm, 1, uid, gid, time),
            kind: NodeKind::File {
                range_map: RangeMap::new(),
                size: 0,
            },
        }
    }

    pub fn new_symlink(target: String, uid: u32, gid: u32, time: SystemTime) -> Self {
        Self {
            meta: InodeMeta::new(0o777, 1, uid, gid, time),
            kind: NodeKind::Symlink { target },
        }
    }

    pub fn is_dir(&self) -> bool {
        matches!(self.kind, NodeKind::Directory { .. })
    }

    pub fn is_file(&self) -> bool {
        matches!(self.kind, NodeKind::File { .. })
    }

    pub fn is_symlink(&self) -> bool {
        matches!(self.kind, NodeKind::Symlink { .. })
    }

    pub fn file_type(&self) -> FileType {
        match self.kind {
            NodeKind::Directory { .. } => FileType::Directory,
            NodeKind::File { .. } => FileType::RegularFile,
            NodeKind::Symlink { .. } => FileType::Symlink,
        }
    }

    pub fn apply_attr_delta(&mut self, delta: &AttrDelta) {
        if let Some(mode) = delta.mode {
            self.meta.perm = mode & 0o7777;
        }
        if let Some(uid) = delta.uid {
            self.meta.uid = uid;
        }
        if let Some(gid) = delta.gid {
            self.meta.gid = gid;
        }
        if let Some(nlink) = delta.nlink {
            self.meta.nlink = nlink;
        }
        if let Some(atime) = delta.atime {
            self.meta.atime = atime;
        }
        if let Some(mtime) = delta.mtime {
            self.meta.mtime = mtime;
        }
        if let Some(ctime) = delta.ctime {
            self.meta.ctime = ctime;
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttrDelta {
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub nlink: Option<u32>,
    #[serde(default, with = "crate::clock::serde_system_time_opt")]
    pub atime: Option<SystemTime>,
    #[serde(default, with = "crate::clock::serde_system_time_opt")]
    pub mtime: Option<SystemTime>,
    #[serde(default, with = "crate::clock::serde_system_time_opt")]
    pub ctime: Option<SystemTime>,
}

#[derive(Debug, Clone, Default)]
pub struct DirectoryDelta {
    pub parent: Option<u64>,
    pub added: std::collections::HashMap<String, u64>,
    pub removed: std::collections::HashSet<String>,
    pub attr_delta: AttrDelta,
}

#[derive(Debug, Clone, Default)]
pub struct FileDelta {
    pub extents: RangeMap<SharedExtentState>,
    pub size: Option<u64>,
    pub truncate_mask: Option<u64>,
    pub attr_delta: AttrDelta,
}

#[derive(Debug, Clone)]
pub struct SymlinkDelta {
    pub target: Option<String>,
    pub attr_delta: AttrDelta,
}

#[derive(Debug, Clone)]
pub enum NodeDelta {
    Directory(DirectoryDelta),
    File(FileDelta),
    Symlink(SymlinkDelta),
}

#[derive(Debug, Clone)]
pub enum EntryDelta {
    Node(NodeDelta),
    Tombstone,
}
