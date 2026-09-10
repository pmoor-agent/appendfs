//! Chunked buffer slab arena for staged file extents.
//!
//! Replaces per-write heap allocations with contiguous fixed-size chunk buffers.
//! Writes that exceed the remaining capacity of the current chunk are cleanly split
//! across chunk boundaries, guaranteeing 100% chunk packing density.

use std::sync::{Arc, RwLock};

/// Default capacity for an arena chunk buffer (16 MiB).
pub const DEFAULT_CHUNK_SIZE: usize = 16 * 1024 * 1024;

/// A contiguous, thread-safe memory chunk buffer for staging extent data.
#[derive(Debug, Clone)]
pub struct ArenaChunk {
    pub data: Arc<RwLock<Vec<u8>>>,
    pub capacity: usize,
}

impl ArenaChunk {
    pub fn new(capacity: usize) -> Self {
        Self {
            data: Arc::new(RwLock::new(Vec::with_capacity(capacity))),
            capacity,
        }
    }

    pub fn len(&self) -> usize {
        self.data.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn remaining(&self) -> usize {
        self.capacity.saturating_sub(self.len())
    }

    /// Appends data to this chunk, returning the starting byte offset within the chunk.
    pub fn append(&self, buf: &[u8]) -> u32 {
        let mut guard = self.data.write().unwrap();
        let offset = guard.len() as u32;
        guard.extend_from_slice(buf);
        offset
    }
}

/// Epoch-based chunked write arena associated with a flush layer.
#[derive(Debug, Clone)]
pub struct WriteArena {
    pub chunks: Vec<ArenaChunk>,
    pub chunk_size: usize,
}

impl Default for WriteArena {
    fn default() -> Self {
        Self::new()
    }
}

/// An allocated slice from an arena chunk: `(buffer, payload_offset, length)`.
pub type ArenaSlice = (Arc<RwLock<Vec<u8>>>, u32, u32);

impl WriteArena {
    pub fn new() -> Self {
        Self::with_chunk_size(DEFAULT_CHUNK_SIZE)
    }

    pub fn with_chunk_size(chunk_size: usize) -> Self {
        Self {
            chunks: Vec::new(),
            chunk_size,
        }
    }

    /// Appends data into the arena, splitting across chunk boundaries if necessary.
    ///
    /// Returns a list of `ArenaSlice` representing the allocated slices.
    pub fn append(&mut self, data: &[u8]) -> Vec<ArenaSlice> {
        assert!(data.len() < (1 << 31), "write payload length must be less than 2^31");
        let mut slices = Vec::new();
        let mut remaining_data = data;

        while !remaining_data.is_empty() {
            let chunk = match self.chunks.last() {
                Some(c) if c.remaining() > 0 => c.clone(),
                _ => {
                    let new_chunk = ArenaChunk::new(self.chunk_size.max(remaining_data.len()));
                    self.chunks.push(new_chunk.clone());
                    new_chunk
                }
            };

            let to_write = std::cmp::min(remaining_data.len(), chunk.remaining());
            assert!(to_write > 0, "to_write must be greater than 0 to make progress");
            let offset = chunk.append(&remaining_data[..to_write]);
            slices.push((Arc::clone(&chunk.data), offset, to_write as u32));
            remaining_data = &remaining_data[to_write..];
        }

        slices
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arena_append_and_chunk_split() {
        let mut arena = WriteArena::with_chunk_size(100);
        let slices1 = arena.append(&[1u8; 60]);
        assert_eq!(slices1.len(), 1);
        assert_eq!(slices1[0].1, 0);
        assert_eq!(slices1[0].2, 60);
        assert_eq!(arena.chunks.len(), 1);

        // Append 70 bytes: 40 fits in chunk 0, remaining 30 creates chunk 1
        let slices2 = arena.append(&[2u8; 70]);
        assert_eq!(slices2.len(), 2);
        assert_eq!(slices2[0].1, 60);
        assert_eq!(slices2[0].2, 40);
        assert_eq!(slices2[1].1, 0);
        assert_eq!(slices2[1].2, 30);
        assert_eq!(arena.chunks.len(), 2);

        // Verify content in chunk 0
        let c0 = arena.chunks[0].data.read().unwrap();
        assert_eq!(&c0[0..60], &[1u8; 60]);
        assert_eq!(&c0[60..100], &[2u8; 40]);

        // Verify content in chunk 1
        let c1 = arena.chunks[1].data.read().unwrap();
        assert_eq!(&c1[0..30], &[2u8; 30]);
    }

    #[test]
    fn test_arena_large_single_write() {
        let mut arena = WriteArena::with_chunk_size(100);
        let large_data = vec![7u8; 350];
        let slices = arena.append(&large_data);
        assert_eq!(slices.len(), 1);
        assert_eq!(slices[0].1, 0);
        assert_eq!(slices[0].2, 350);
        assert_eq!(arena.chunks.len(), 1);
        assert!(arena.chunks[0].capacity >= 350);
    }

    #[test]
    fn test_arena_default_chunk_size() {
        let arena = WriteArena::default();
        assert_eq!(arena.chunk_size, 16 * 1024 * 1024);
        assert_eq!(DEFAULT_CHUNK_SIZE, 16 * 1024 * 1024);
    }
}
