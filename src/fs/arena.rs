//! Chunked buffer slab arena for staged file extents.
//!
//! Replaces per-write heap allocations with contiguous fixed-size chunk buffers.
//! Writes that exceed the remaining capacity of the current chunk are cleanly split
//! across chunk boundaries, guaranteeing 100% chunk packing density.

use std::sync::{Arc, RwLock};

/// Default capacity for an arena chunk buffer (4 MiB).
pub const DEFAULT_CHUNK_SIZE: usize = 4 * 1024 * 1024;

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
    /// If `pool` has recycled chunks available, they will be used before allocating new ones.
    /// Returns a list of `ArenaSlice` representing the allocated slices.
    pub fn append(&mut self, data: &[u8], pool: &mut Vec<Arc<RwLock<Vec<u8>>>>) -> Vec<ArenaSlice> {
        let mut slices = Vec::new();
        let mut remaining_data = data;

        while !remaining_data.is_empty() {
            let chunk = match self.chunks.last() {
                Some(c) if c.remaining() > 0 => c.clone(),
                _ => {
                    let new_chunk = if let Some(pooled_buf) = pool.pop() {
                        let cap = pooled_buf.read().unwrap().capacity();
                        ArenaChunk {
                            data: pooled_buf,
                            capacity: cap,
                        }
                    } else {
                        ArenaChunk::new(self.chunk_size.max(remaining_data.len()))
                    };
                    self.chunks.push(new_chunk.clone());
                    new_chunk
                }
            };

            let to_write = std::cmp::min(remaining_data.len(), chunk.remaining());
            let offset = chunk.append(&remaining_data[..to_write]);
            slices.push((Arc::clone(&chunk.data), offset, to_write as u32));
            remaining_data = &remaining_data[to_write..];
        }

        slices
    }

    /// Recycles unused chunks (chunks with strong_count == 1) back into the pool.
    pub fn recycle_into(self, pool: &mut Vec<Arc<RwLock<Vec<u8>>>>) {
        for chunk in self.chunks {
            // Only recycle if no in-flight readers still hold an Arc to this chunk
            if Arc::strong_count(&chunk.data) == 1 {
                let is_ok = match chunk.data.write() {
                    Ok(mut guard) => {
                        guard.clear();
                        true
                    }
                    Err(_) => false,
                };
                if is_ok {
                    pool.push(chunk.data);
                }
            }
        }
    }
}
