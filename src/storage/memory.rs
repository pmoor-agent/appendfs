use crate::storage::{Storage, StorageReader, StorageWriter, WriteMode};
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, RwLock};

pub type InMemoryFile = Arc<RwLock<Vec<u8>>>;
pub type MemoryStorageMap = Arc<RwLock<HashMap<String, InMemoryFile>>>;

/// In-memory storage implementation holding files in RAM.
#[derive(Debug, Clone, Default)]
pub struct MemoryStorage {
    files: MemoryStorageMap,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self {
            files: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Helper to dump file contents for assertions / debugging.
    pub fn get_file_bytes(&self, name: &str) -> Option<Vec<u8>> {
        self.files
            .read()
            .unwrap()
            .get(name)
            .map(|b| b.read().unwrap().clone())
    }

    /// Helper to directly insert or overwrite file bytes.
    pub fn insert_file(&self, name: &str, data: Vec<u8>) {
        self.files
            .write()
            .unwrap()
            .insert(name.to_string(), Arc::new(RwLock::new(data)));
    }
}

pub struct MemoryStorageReader {
    buffer: Arc<RwLock<Vec<u8>>>,
}

impl StorageReader for MemoryStorageReader {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let guard = self.buffer.read().unwrap();
        let start = offset as usize;
        let end = start + buf.len();
        if end > guard.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "read_exact_at range [{}..{}) exceeds file length {}",
                    start,
                    end,
                    guard.len()
                ),
            ));
        }
        buf.copy_from_slice(&guard[start..end]);
        Ok(())
    }

    fn len(&self) -> io::Result<u64> {
        Ok(self.buffer.read().unwrap().len() as u64)
    }
}

pub struct MemoryStorageWriter {
    buffer: Arc<RwLock<Vec<u8>>>,
}

impl StorageWriter for MemoryStorageWriter {
    fn append(&mut self, data: &[u8]) -> io::Result<()> {
        let mut guard = self.buffer.write().unwrap();
        guard.extend_from_slice(data);
        Ok(())
    }

    fn truncate(&mut self, len: u64) -> io::Result<()> {
        let mut guard = self.buffer.write().unwrap();
        guard.truncate(len as usize);
        Ok(())
    }

    fn sync(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn len(&self) -> io::Result<u64> {
        Ok(self.buffer.read().unwrap().len() as u64)
    }
}

impl Storage for MemoryStorage {
    fn list_files(&self) -> io::Result<Vec<String>> {
        let guard = self.files.read().unwrap();
        let mut names: Vec<String> = guard.keys().cloned().collect();
        names.sort();
        Ok(names)
    }

    fn exists(&self, name: &str) -> bool {
        self.files.read().unwrap().contains_key(name)
    }

    fn remove_file(&self, name: &str) -> io::Result<()> {
        self.files.write().unwrap().remove(name);
        Ok(())
    }

    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        let mut guard = self.files.write().unwrap();
        if let Some(buf) = guard.remove(from) {
            guard.insert(to.to_string(), buf);
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("file '{}' not found for rename", from),
            ))
        }
    }

    fn open_reader(&self, name: &str) -> io::Result<Arc<dyn StorageReader>> {
        let guard = self.files.read().unwrap();
        if let Some(buf) = guard.get(name) {
            Ok(Arc::new(MemoryStorageReader {
                buffer: Arc::clone(buf),
            }))
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("file '{}' not found", name),
            ))
        }
    }

    fn open_writer(&self, name: &str, mode: WriteMode) -> io::Result<Box<dyn StorageWriter>> {
        let mut guard = self.files.write().unwrap();
        if guard.contains_key(name) && mode == WriteMode::CreateNew {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("file '{}' already exists", name),
            ));
        }
        let buffer = guard
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(RwLock::new(Vec::new())))
            .clone();
        buffer.write().unwrap().clear();

        Ok(Box::new(MemoryStorageWriter { buffer }))
    }
}
