use crate::range_map::RangeValue;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};

/// Represents the physical location and state of an extent slice.
///
/// This is a *resolved* view: `Staged` always means "only in memory right now" and
/// `Disk` always means "durably flushed", regardless of how the value is actually
/// stored internally. See `StoredExtent` for why that distinction matters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtentState {
    /// Data is staged in memory, not yet flushed to disk.
    Staged {
        data: Arc<Vec<u8>>,
        payload_offset: u32,
        length: u32,
    },
    /// Data is flushed to disk in a `.log` file.
    Disk {
        generation: u64,
        record_log_offset: u64, // Byte offset in .log file where RecordHeader starts
        payload_offset: u32,    // Offset within decrypted record payload
        length: u32,            // Length of slice
    },
    /// A hole: this range reads as zeros and occupies no space on disk.
    ///
    /// This is *not* the same as the range simply being absent from a file's extent map.
    /// Absence means "this layer has no opinion", so a read falls through to the layer
    /// below; `Zero` means "these bytes are zeros", masking whatever `base` holds. That
    /// distinction is what makes hole punching work in a delta layer rather than silently
    /// resurrecting the punched data at the next read. Folding into `base` may collapse
    /// `Zero` back to absence, since nothing sits below `base` to mask.
    ///
    /// The length is `u64`, unlike the other variants: a hole has no backing payload to
    /// index into, so the `u32` ceiling that bounds a real extent does not apply. That
    /// matters because truncating a file emits a hole spanning everything it discarded,
    /// which stays a single extent however large the file was.
    Zero { length: u64 },
}

impl ExtentState {
    pub fn length(&self) -> u64 {
        match self {
            ExtentState::Staged { length, .. } => *length as u64,
            ExtentState::Disk { length, .. } => *length as u64,
            ExtentState::Zero { length } => *length,
        }
    }

    /// Bytes this extent occupies on disk - zero for a hole. Drives `st_blocks`.
    pub fn allocated_len(&self) -> u64 {
        match self {
            ExtentState::Zero { .. } => 0,
            other => other.length(),
        }
    }
}

/// The actual, internally-stored representation behind `SharedExtentState`.
#[derive(Debug, Clone)]
enum StoredExtent {
    Staged {
        data: Arc<Vec<u8>>,
        payload_offset: u32,
        length: u32,
    },
    Disk {
        generation: u64,
        record_log_offset: u64,
        payload_offset: u32,
        length: u32,
    },
    Zero {
        length: u64,
    },
}

/// Shared smart pointer wrapping the extent state for O(1) zero-lookup in-place updates.
#[derive(Debug)]
pub struct SharedExtentState(Arc<RwLock<StoredExtent>>);

impl Clone for SharedExtentState {
    fn clone(&self) -> Self {
        self.fork()
    }
}

/// Generation number reserved to mean "this extent is a hole" on disk.
///
/// Real generations start at 1 (`init_volume` creates `000001.log`), so 0 is free. Using a
/// sentinel rather than widening `SerializedExtent`/`LogExtent` into an enum keeps the
/// on-disk shape flat: an enum discriminant would otherwise be paid on *every* extent in
/// every summary and delta record, and holes are the rare case.
///
/// When the sentinel is set, the descriptor is reinterpreted: a hole's length needs 64 bits
/// but the `length` field is only 32, so it is carried in `record_log_offset` instead - a
/// field that has no meaning for a hole anyway. `zero_extent_len` and `zero_extent_fields`
/// are the only places that encoding is applied; nothing else should read those fields
/// without checking the generation first.
pub const ZERO_EXTENT_GENERATION: u64 = 0;

/// Decodes a hole's length from an on-disk extent descriptor. See [`ZERO_EXTENT_GENERATION`].
pub fn zero_extent_len(record_log_offset: u64) -> u64 {
    record_log_offset
}

/// Encodes a hole as `(generation, record_log_offset, payload_offset, length)` for an
/// on-disk extent descriptor. See [`ZERO_EXTENT_GENERATION`].
pub fn zero_extent_fields(length: u64) -> (u64, u64, u32, u32) {
    (ZERO_EXTENT_GENERATION, length, 0, 0)
}

/// On-disk shape of a `SharedExtentState`, used for summary (de)serialization. Kept
/// identical to the pre-existing `ExtentState::Disk` field layout so `.summary` files
/// remain format-compatible. Summaries are only ever exported after `sync_log()`, so
/// every live extent is expected to already be resolvable to this shape - or to be a
/// hole, which carries `ZERO_EXTENT_GENERATION`.
#[derive(Serialize, Deserialize)]
struct SerializedExtent {
    generation: u64,
    record_log_offset: u64,
    payload_offset: u32,
    length: u32,
}

impl Serialize for SharedExtentState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self.read_state() {
            ExtentState::Disk {
                generation,
                record_log_offset,
                payload_offset,
                length,
            } => SerializedExtent {
                generation,
                record_log_offset,
                payload_offset,
                length,
            }
            .serialize(serializer),
            ExtentState::Zero { length } => {
                let (generation, record_log_offset, payload_offset, length) = zero_extent_fields(length);
                SerializedExtent {
                    generation,
                    record_log_offset,
                    payload_offset,
                    length,
                }
                .serialize(serializer)
            }
            ExtentState::Staged { .. } => Err(serde::ser::Error::custom(
                "cannot serialize an extent that has not been flushed to disk",
            )),
        }
    }
}

impl<'de> Deserialize<'de> for SharedExtentState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = SerializedExtent::deserialize(deserializer)?;
        if s.generation == ZERO_EXTENT_GENERATION {
            return Ok(Self::new_zero(zero_extent_len(s.record_log_offset)));
        }
        Ok(Self::new_disk(
            s.generation,
            s.record_log_offset,
            s.payload_offset,
            s.length,
        ))
    }
}

impl SharedExtentState {
    pub fn new_staged(data: Arc<Vec<u8>>, payload_offset: u32, length: u32) -> Self {
        Self(Arc::new(RwLock::new(StoredExtent::Staged {
            data,
            payload_offset,
            length,
        })))
    }

    pub fn new_disk(generation: u64, record_log_offset: u64, payload_offset: u32, length: u32) -> Self {
        Self(Arc::new(RwLock::new(StoredExtent::Disk {
            generation,
            record_log_offset,
            payload_offset,
            length,
        })))
    }

    /// Creates a hole of `length` bytes - reads as zeros, occupies nothing on disk.
    pub fn new_zero(length: u64) -> Self {
        Self(Arc::new(RwLock::new(StoredExtent::Zero { length })))
    }

    /// Clones the shared pointer without forking an independent state.
    pub fn share(&self) -> Self {
        Self(Arc::clone(&self.0))
    }

    fn raw(&self) -> StoredExtent {
        match self.0.read() {
            Ok(guard) => guard.clone(),
            Err(err) => err.into_inner().clone(),
        }
    }

    /// Resolves the current extent state as either in-memory (`Staged`) or durable (`Disk`).
    pub fn read_state(&self) -> ExtentState {
        match self.raw() {
            StoredExtent::Disk {
                generation,
                record_log_offset,
                payload_offset,
                length,
            } => ExtentState::Disk {
                generation,
                record_log_offset,
                payload_offset,
                length,
            },
            StoredExtent::Staged {
                data,
                payload_offset,
                length,
            } => ExtentState::Staged {
                data,
                payload_offset,
                length,
            },
            StoredExtent::Zero { length } => ExtentState::Zero { length },
        }
    }

    /// Produces an independent fragment: a *new* `Arc<RwLock<..>>`, seeded from the
    /// current state, that can be trimmed (`trim_left`/`trim_right`) without affecting
    /// `self` or any other fragment.
    pub fn fork(&self) -> Self {
        Self(Arc::new(RwLock::new(self.raw())))
    }

    /// Converts this extent directly to Disk state with exact disk payload offset and length.
    pub fn convert_to_disk(&self, generation: u64, record_log_offset: u64, payload_offset: u32, length: u32) {
        let mut state = match self.0.write() {
            Ok(guard) => guard,
            Err(err) => err.into_inner(),
        };
        *state = StoredExtent::Disk {
            generation,
            record_log_offset,
            payload_offset,
            length,
        };
    }
}

impl RangeValue for SharedExtentState {
    fn trim_right(&mut self, new_len: u64) {
        let mut state = match self.0.write() {
            Ok(guard) => guard,
            Err(err) => err.into_inner(),
        };
        match &mut *state {
            StoredExtent::Staged { length, .. } => {
                *length = std::cmp::min(*length, new_len as u32);
            }
            StoredExtent::Disk { length, .. } => {
                *length = std::cmp::min(*length, new_len as u32);
            }
            StoredExtent::Zero { length } => {
                *length = std::cmp::min(*length, new_len);
            }
        }
    }

    fn trim_left(&mut self, shift: u64) {
        let mut state = match self.0.write() {
            Ok(guard) => guard,
            Err(err) => err.into_inner(),
        };
        let shift_u32 = shift as u32;
        match &mut *state {
            StoredExtent::Staged {
                payload_offset, length, ..
            } => {
                *payload_offset += shift_u32;
                *length = length.saturating_sub(shift_u32);
            }
            StoredExtent::Disk {
                payload_offset, length, ..
            } => {
                *payload_offset += shift_u32;
                *length = length.saturating_sub(shift_u32);
            }
            // A hole has no backing payload to seek into, so trimming from the left is
            // just a shortening.
            StoredExtent::Zero { length } => {
                *length = length.saturating_sub(shift);
            }
        }
    }

    fn fork(&self) -> Self {
        SharedExtentState::fork(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shared_extent_state_trimming() {
        let state = SharedExtentState::new_staged(Arc::new(vec![1, 2, 3, 4, 5]), 0, 5);
        let mut clone = state.clone();

        clone.trim_left(2);
        assert_eq!(
            clone.read_state(),
            ExtentState::Staged {
                data: Arc::new(vec![1, 2, 3, 4, 5]),
                payload_offset: 2,
                length: 3,
            }
        );
        assert_eq!(
            state.read_state(),
            ExtentState::Staged {
                data: Arc::new(vec![1, 2, 3, 4, 5]),
                payload_offset: 0,
                length: 5,
            }
        );

        clone.trim_right(2);
        assert_eq!(
            clone.read_state(),
            ExtentState::Staged {
                data: Arc::new(vec![1, 2, 3, 4, 5]),
                payload_offset: 2,
                length: 2,
            }
        );
        assert_eq!(
            state.read_state(),
            ExtentState::Staged {
                data: Arc::new(vec![1, 2, 3, 4, 5]),
                payload_offset: 0,
                length: 5,
            }
        );
    }

    #[test]
    fn test_fork_is_independent_of_original_trimming() {
        let state = SharedExtentState::new_staged(Arc::new(vec![0u8; 10]), 0, 10);
        let mut forked = state.fork();

        // Trimming the fork must not affect the original, and vice versa.
        forked.trim_right(3);
        assert_eq!(state.read_state().length(), 10);
        assert_eq!(forked.read_state().length(), 3);

        let mut original = state.clone();
        original.trim_right(1);
        assert_eq!(original.read_state().length(), 1);
        assert_eq!(forked.read_state().length(), 3);
    }
}
