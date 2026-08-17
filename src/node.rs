use crate::log::SharedExtentState;
use crate::range_map::RangeMap;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

// Structure representing an in-memory node (file, directory, or symlink)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Node {
    Directory {
        parent: u64,
        entries: Vec<(String, u64)>,
        perm: u32,
        nlink: u32,
        uid: u32,
        gid: u32,
        #[serde(with = "crate::clock::serde_system_time")]
        atime: SystemTime,
        #[serde(with = "crate::clock::serde_system_time")]
        mtime: SystemTime,
        #[serde(with = "crate::clock::serde_system_time")]
        ctime: SystemTime,
    },
    File {
        range_map: RangeMap<SharedExtentState>,
        size: u64,
        perm: u32,
        nlink: u32,
        uid: u32,
        gid: u32,
        #[serde(with = "crate::clock::serde_system_time")]
        atime: SystemTime,
        #[serde(with = "crate::clock::serde_system_time")]
        mtime: SystemTime,
        #[serde(with = "crate::clock::serde_system_time")]
        ctime: SystemTime,
    },
    Symlink {
        target: String,
        nlink: u32,
        uid: u32,
        gid: u32,
        #[serde(with = "crate::clock::serde_system_time")]
        atime: SystemTime,
        #[serde(with = "crate::clock::serde_system_time")]
        mtime: SystemTime,
        #[serde(with = "crate::clock::serde_system_time")]
        ctime: SystemTime,
    },
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
