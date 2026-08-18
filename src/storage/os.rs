use crate::storage::{Storage, StorageReader, StorageWriter, WriteMode};
use std::fs::{File, OpenOptions, create_dir_all};
use std::io::{self, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// OS filesystem backed storage implementation rooted at a base directory.
#[derive(Debug, Clone)]
pub struct OsStorage {
    base_dir: PathBuf,
}

impl OsStorage {
    pub fn new(base_dir: impl AsRef<Path>) -> Self {
        Self {
            base_dir: base_dir.as_ref().to_path_buf(),
        }
    }

    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    fn full_path(&self, name: &str) -> PathBuf {
        self.base_dir.join(name)
    }
}

pub struct OsStorageReader {
    file: File,
}

impl StorageReader for OsStorageReader {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        self.file.read_exact_at(buf, offset)
    }

    fn len(&self) -> io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }
}

pub struct OsStorageWriter {
    file: File,
}

impl StorageWriter for OsStorageWriter {
    fn append(&mut self, data: &[u8]) -> io::Result<()> {
        self.file.write_all(data)
    }

    fn truncate(&mut self, len: u64) -> io::Result<()> {
        self.file.set_len(len)?;
        self.file.seek(SeekFrom::Start(len))?;
        Ok(())
    }

    fn sync(&mut self) -> io::Result<()> {
        self.file.flush()?;
        self.file.sync_data()
    }

    fn len(&self) -> io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }
}

impl Storage for OsStorage {
    fn list_files(&self) -> io::Result<Vec<String>> {
        if !self.base_dir.exists() {
            return Ok(Vec::new());
        }
        let mut files = Vec::new();
        for entry in std::fs::read_dir(&self.base_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file()
                && let Some(name) = path.file_name().and_then(|n| n.to_str())
            {
                files.push(name.to_string());
            }
        }
        files.sort();
        Ok(files)
    }

    fn exists(&self, name: &str) -> bool {
        self.full_path(name).is_file()
    }

    fn remove_file(&self, name: &str) -> io::Result<()> {
        let path = self.full_path(name);
        if path.exists() {
            std::fs::remove_file(path)
        } else {
            Ok(())
        }
    }

    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        create_dir_all(&self.base_dir)?;
        std::fs::rename(self.full_path(from), self.full_path(to))
    }

    fn open_reader(&self, name: &str) -> io::Result<Arc<dyn StorageReader>> {
        let file = File::open(self.full_path(name))?;
        Ok(Arc::new(OsStorageReader { file }))
    }

    fn open_writer(&self, name: &str, mode: WriteMode) -> io::Result<Box<dyn StorageWriter>> {
        create_dir_all(&self.base_dir)?;
        let path = self.full_path(name);
        let mut options = OpenOptions::new();
        options.write(true);
        match mode {
            WriteMode::CreateNew => options.create_new(true),
            WriteMode::Overwrite => options.create(true).truncate(true),
        };
        Ok(Box::new(OsStorageWriter {
            file: options.open(&path)?,
        }))
    }
}
