use crate::log::SharedExtentState;
use crate::range_map::RangeMap;
use crate::shim::FileType;
use std::collections::BTreeMap;
use std::sync::Arc;
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
    #[serde(default)]
    pub xattrs: Option<Arc<BTreeMap<String, Vec<u8>>>>,
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
            xattrs: None,
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
    Fifo,
    CharDevice {
        rdev: u32,
    },
    BlockDevice {
        rdev: u32,
    },
    Socket,
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

    pub fn new_fifo(perm: u32, uid: u32, gid: u32, time: SystemTime) -> Self {
        Self {
            meta: InodeMeta::new(perm, 1, uid, gid, time),
            kind: NodeKind::Fifo,
        }
    }

    pub fn new_char_device(rdev: u32, perm: u32, uid: u32, gid: u32, time: SystemTime) -> Self {
        Self {
            meta: InodeMeta::new(perm, 1, uid, gid, time),
            kind: NodeKind::CharDevice { rdev },
        }
    }

    pub fn new_block_device(rdev: u32, perm: u32, uid: u32, gid: u32, time: SystemTime) -> Self {
        Self {
            meta: InodeMeta::new(perm, 1, uid, gid, time),
            kind: NodeKind::BlockDevice { rdev },
        }
    }

    pub fn new_socket(perm: u32, uid: u32, gid: u32, time: SystemTime) -> Self {
        Self {
            meta: InodeMeta::new(perm, 1, uid, gid, time),
            kind: NodeKind::Socket,
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

    pub fn is_fifo(&self) -> bool {
        matches!(self.kind, NodeKind::Fifo)
    }

    pub fn is_char_device(&self) -> bool {
        matches!(self.kind, NodeKind::CharDevice { .. })
    }

    pub fn is_block_device(&self) -> bool {
        matches!(self.kind, NodeKind::BlockDevice { .. })
    }

    pub fn is_socket(&self) -> bool {
        matches!(self.kind, NodeKind::Socket)
    }

    pub fn is_special(&self) -> bool {
        matches!(
            self.kind,
            NodeKind::Fifo | NodeKind::CharDevice { .. } | NodeKind::BlockDevice { .. } | NodeKind::Socket
        )
    }

    pub fn rdev(&self) -> u32 {
        match self.kind {
            NodeKind::CharDevice { rdev } | NodeKind::BlockDevice { rdev } => rdev,
            _ => 0,
        }
    }

    pub fn file_type(&self) -> FileType {
        match self.kind {
            NodeKind::Directory { .. } => FileType::Directory,
            NodeKind::File { .. } => FileType::RegularFile,
            NodeKind::Symlink { .. } => FileType::Symlink,
            NodeKind::Fifo => FileType::NamedPipe,
            NodeKind::CharDevice { .. } => FileType::CharDevice,
            NodeKind::BlockDevice { .. } => FileType::BlockDevice,
            NodeKind::Socket => FileType::Socket,
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
        if let Some(ref xattr_changes) = delta.xattrs {
            let mut map = match self.meta.xattrs.take() {
                Some(arc) => (*arc).clone(),
                None => BTreeMap::new(),
            };
            for (key, val_opt) in xattr_changes {
                match val_opt {
                    Some(val) => {
                        map.insert(key.clone(), val.clone());
                    }
                    None => {
                        map.remove(key);
                    }
                }
            }
            if map.is_empty() {
                self.meta.xattrs = None;
            } else {
                self.meta.xattrs = Some(Arc::new(map));
            }
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
    #[serde(default, with = "crate::clock::serde_system_time_opt")]
    pub created_at: Option<SystemTime>,
    #[serde(default)]
    pub xattrs: Option<std::collections::HashMap<String, Option<Vec<u8>>>>,
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

#[derive(Debug, Clone, Default)]
pub struct SpecialDelta {
    pub rdev: u32,
    pub attr_delta: AttrDelta,
}

#[derive(Debug, Clone)]
pub enum NodeDelta {
    Directory(DirectoryDelta),
    File(FileDelta),
    Symlink(SymlinkDelta),
    Fifo(SpecialDelta),
    CharDevice(SpecialDelta),
    BlockDevice(SpecialDelta),
    Socket(SpecialDelta),
}

impl NodeDelta {
    pub fn attr_delta(&self) -> &AttrDelta {
        match self {
            NodeDelta::Directory(d) => &d.attr_delta,
            NodeDelta::File(f) => &f.attr_delta,
            NodeDelta::Symlink(s) => &s.attr_delta,
            NodeDelta::Fifo(s) | NodeDelta::CharDevice(s) | NodeDelta::BlockDevice(s) | NodeDelta::Socket(s) => {
                &s.attr_delta
            }
        }
    }

    pub fn attr_delta_mut(&mut self) -> &mut AttrDelta {
        match self {
            NodeDelta::Directory(d) => &mut d.attr_delta,
            NodeDelta::File(f) => &mut f.attr_delta,
            NodeDelta::Symlink(s) => &mut s.attr_delta,
            NodeDelta::Fifo(s) | NodeDelta::CharDevice(s) | NodeDelta::BlockDevice(s) | NodeDelta::Socket(s) => {
                &mut s.attr_delta
            }
        }
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum EntryDelta {
    Node(NodeDelta),
    Tombstone,
}
