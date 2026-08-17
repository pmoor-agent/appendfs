use appendfs::InMemoryFS;
use appendfs::clock::{Clock, SystemClock};
use appendfs::log::recover_fs_with_clock;
use appendfs::shim::{FileAttr, FileType};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::SystemTime;

/// Per-inode snapshot entry produced by `TestFS::get_tree_snapshot` - built entirely
/// from the same core handlers real FUSE dispatch uses (`getattr_core`, `list_dir_core`,
/// `readlink_core`, `read_core`), never by reading `fs.inodes` directly.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum SnapshotNode {
    Directory {
        attr: FileAttr,
        entries: Vec<(String, u64)>,
    },
    File {
        attr: FileAttr,
        content: Vec<u8>,
    },
    Symlink {
        attr: FileAttr,
        target: String,
    },
}

#[allow(dead_code)]
pub struct TestFS {
    pub fs: InMemoryFS,
    pub log_dir: PathBuf,
    pub _temp_dir: Option<Arc<tempfile::TempDir>>,
}

#[allow(dead_code)]
impl TestFS {
    pub fn new_temp(max_log_size: Option<u64>) -> Self {
        Self::new_temp_with_clock(max_log_size, Arc::new(SystemClock))
    }

    pub fn new_temp_with_clock(max_log_size: Option<u64>, clock: Arc<dyn Clock>) -> Self {
        let temp_dir = tempfile::tempdir().unwrap();
        let log_dir = temp_dir.path().to_path_buf();
        let writer = if let Some(max_size) = max_log_size {
            Arc::new(
                appendfs::LogWriter::create_with_max_size(&log_dir, 1, &*clock, max_size).unwrap(),
            )
        } else {
            Arc::new(appendfs::LogWriter::create(&log_dir, 1, &*clock).unwrap())
        };

        let mut fs = InMemoryFS::with_clock_and_log(clock, Some(writer));
        fs.set_log_dir(&log_dir);
        Self {
            fs,
            log_dir,
            _temp_dir: Some(Arc::new(temp_dir)),
        }
    }

    pub fn from_instance(
        fs: InMemoryFS,
        log_dir: &Path,
        temp_dir: Option<Arc<tempfile::TempDir>>,
    ) -> Self {
        Self {
            fs,
            log_dir: log_dir.to_path_buf(),
            _temp_dir: temp_dir,
        }
    }

    pub fn allocate_inode(&self) -> u64 {
        self.fs.next_inode.fetch_add(1, Ordering::SeqCst)
    }

    pub fn mkdir(&self, parent: u64, name: &str, mode: u32) -> Result<u64, i32> {
        appendfs::operations::dir::mkdir_core(&self.fs, parent, name, mode, 1000, 1000)
            .map(|attr| attr.ino)
    }

    pub fn create(&self, parent: u64, name: &str, mode: u32) -> Result<u64, i32> {
        appendfs::operations::read_write::create_core(&self.fs, parent, name, mode, 0, 1000, 1000)
            .map(|attr| attr.ino)
    }

    pub fn write(&self, ino: u64, offset: u64, buf: &[u8]) -> Result<usize, i32> {
        appendfs::operations::read_write::write_core(&self.fs, ino, buf, offset as i64)
    }

    pub fn read(&self, ino: u64, offset: u64, len: usize) -> Result<Vec<u8>, i32> {
        appendfs::operations::read_write::read_core(&self.fs, ino, len, offset as i64)
    }

    pub fn unlink(&self, parent: u64, name: &str) -> Result<(), i32> {
        appendfs::operations::links::unlink_core(&self.fs, parent, name)
    }

    pub fn rmdir(&self, parent: u64, name: &str) -> Result<(), i32> {
        appendfs::operations::dir::rmdir_core(&self.fs, parent, name)
    }

    pub fn symlink(&self, parent: u64, name: &str, target: &str) -> Result<u64, i32> {
        appendfs::operations::links::symlink_core(&self.fs, parent, name, target, 1000, 1000)
            .map(|attr| attr.ino)
    }

    pub fn link(&self, ino: u64, newparent: u64, newname: &str) -> Result<(), i32> {
        appendfs::operations::links::link_core(&self.fs, ino, newparent, newname).map(|_| ())
    }

    pub fn setattr(
        &self,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<SystemTime>,
        mtime: Option<SystemTime>,
    ) -> Result<(), i32> {
        use appendfs::operations::read_write::{
            FUSE_SET_ATTR_ATIME, FUSE_SET_ATTR_GID, FUSE_SET_ATTR_MODE, FUSE_SET_ATTR_MTIME,
            FUSE_SET_ATTR_SIZE, FUSE_SET_ATTR_UID, setattr_core,
        };

        let mut to_set = 0u32;
        if mode.is_some() {
            to_set |= FUSE_SET_ATTR_MODE;
        }
        if uid.is_some() {
            to_set |= FUSE_SET_ATTR_UID;
        }
        if gid.is_some() {
            to_set |= FUSE_SET_ATTR_GID;
        }
        if size.is_some() {
            to_set |= FUSE_SET_ATTR_SIZE;
        }
        if atime.is_some() {
            to_set |= FUSE_SET_ATTR_ATIME;
        }
        if mtime.is_some() {
            to_set |= FUSE_SET_ATTR_MTIME;
        }

        setattr_core(
            &self.fs,
            ino,
            mode.unwrap_or(0),
            uid.unwrap_or(0),
            gid.unwrap_or(0),
            size.unwrap_or(0) as i64,
            atime.unwrap_or(std::time::UNIX_EPOCH),
            mtime.unwrap_or(std::time::UNIX_EPOCH),
            to_set,
        )
        .map(|_| ())
    }

    pub fn readlink(&self, ino: u64) -> Result<String, i32> {
        appendfs::operations::links::readlink_core(&self.fs, ino)
    }

    pub fn rename(
        &self,
        parent: u64,
        name: &str,
        newparent: u64,
        newname: &str,
    ) -> Result<(), i32> {
        appendfs::operations::links::rename_core(&self.fs, parent, name, newparent, newname)
    }

    pub fn get_tree_snapshot(&self) -> HashMap<u64, SnapshotNode> {
        let mut snapshot = HashMap::new();
        let mut visited = std::collections::HashSet::new();
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(1u64);
        visited.insert(1u64);

        while let Some(ino) = queue.pop_front() {
            let attr = match appendfs::operations::read_write::getattr_core(&self.fs, ino) {
                Ok(attr) => attr,
                Err(_) => continue,
            };

            match attr.file_type {
                FileType::Directory => {
                    let entries =
                        appendfs::operations::dir::list_dir_core(&self.fs, ino).unwrap_or_default();
                    for (_, child_ino) in &entries {
                        if visited.insert(*child_ino) {
                            queue.push_back(*child_ino);
                        }
                    }
                    snapshot.insert(ino, SnapshotNode::Directory { attr, entries });
                }
                FileType::RegularFile => {
                    let content = self.read(ino, 0, attr.size as usize).unwrap_or_default();
                    snapshot.insert(ino, SnapshotNode::File { attr, content });
                }
                FileType::Symlink => {
                    let target = appendfs::operations::links::readlink_core(&self.fs, ino)
                        .unwrap_or_default();
                    snapshot.insert(ino, SnapshotNode::Symlink { attr, target });
                }
            }
        }

        snapshot
    }

    pub fn clean_remount(self) -> Self {
        let log_dir = self.log_dir.clone();
        let temp_dir = self._temp_dir.clone();
        let clock = self.fs.clock.clone();
        let _ = self.fs.sync_and_export_summary();
        drop(self);
        let mut recovered = recover_fs_with_clock(&log_dir, clock.clone()).unwrap();
        let next_gen = appendfs::find_latest_generation(&log_dir) + 1;
        let start_tx = recovered.last_tx_id.load(Ordering::SeqCst) + 1;
        let writer = Arc::new(
            appendfs::LogWriter::create_with_max_size_and_start_tx(
                &log_dir,
                next_gen,
                &*clock,
                appendfs::cli::DEFAULT_MAX_LOG_SIZE,
                start_tx,
            )
            .unwrap(),
        );
        recovered.log_writer = Some(writer);
        recovered.set_log_dir(&log_dir);
        Self::from_instance(recovered, &log_dir, temp_dir)
    }

    pub fn unclean_crash(mut self) -> Self {
        let log_dir = self.log_dir.clone();
        let temp_dir = self._temp_dir.clone();
        let clock = self.fs.clock.clone();
        let _ = self.fs.sync_log();
        self.fs.log_writer = None;
        drop(self);
        let mut recovered = recover_fs_with_clock(&log_dir, clock.clone()).unwrap();
        let next_gen = appendfs::find_latest_generation(&log_dir) + 1;
        let start_tx = recovered.last_tx_id.load(Ordering::SeqCst) + 1;
        let writer = Arc::new(
            appendfs::LogWriter::create_with_max_size_and_start_tx(
                &log_dir,
                next_gen,
                &*clock,
                appendfs::cli::DEFAULT_MAX_LOG_SIZE,
                start_tx,
            )
            .unwrap(),
        );
        recovered.log_writer = Some(writer);
        recovered.set_log_dir(&log_dir);
        Self::from_instance(recovered, &log_dir, temp_dir)
    }
}
