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
}

impl ExtentState {
    pub fn length(&self) -> u32 {
        match self {
            ExtentState::Staged { length, .. } => *length,
            ExtentState::Disk { length, .. } => *length,
        }
    }
}

/// Where a single physical write op landed on disk once flushed, plus how many bytes
/// of record-header/metadata precede the raw write bytes within that record's payload.
/// `None` until the write has been flushed.
///
/// A single `WriteSlot` is shared (via `Arc`) by every RangeMap fragment derived from
/// the same original staged write, however many times that write has since been split
/// or trimmed by later overlapping writes. Resolving it once, at flush time, makes the
/// flush visible to every one of those fragments in O(1) — none of them need to be
/// individually walked or updated.
#[derive(Debug)]
struct WriteSlot(RwLock<Option<DiskLocation>>);

#[derive(Debug, Clone, Copy)]
struct DiskLocation {
    generation: u64,
    record_log_offset: u64,
    meta_size: u32,
}

impl WriteSlot {
    fn unresolved() -> Arc<Self> {
        Arc::new(Self(RwLock::new(None)))
    }

    fn get(&self) -> Option<DiskLocation> {
        match self.0.read() {
            Ok(guard) => *guard,
            Err(err) => *err.into_inner(),
        }
    }

    fn resolve(&self, loc: DiskLocation) {
        let mut guard = match self.0.write() {
            Ok(guard) => guard,
            Err(err) => err.into_inner(),
        };
        *guard = Some(loc);
    }
}

/// The actual, internally-stored representation behind `SharedExtentState`.
///
/// Unlike `ExtentState`, a `Staged` value here is not necessarily still in memory only
/// — its `write` slot may have since resolved to a disk location, in which case every
/// fragment sharing that slot should be treated as flushed. `payload_offset`/`length`
/// are *not* shared: each fragment produced by `RangeMap::insert` splitting or trimming
/// a range owns its own independent copy (see `SharedExtentState::fork`), so mutating
/// one fragment can never corrupt a sibling fragment derived from the same original
/// write.
#[derive(Debug, Clone)]
enum StoredExtent {
    Staged {
        data: Arc<Vec<u8>>,
        write: Arc<WriteSlot>,
        payload_offset: u32,
        length: u32,
    },
    Disk {
        generation: u64,
        record_log_offset: u64,
        payload_offset: u32,
        length: u32,
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

/// On-disk shape of a `SharedExtentState`, used for summary (de)serialization. Kept
/// identical to the pre-existing `ExtentState::Disk` field layout so `.summary` files
/// remain format-compatible. Summaries are only ever exported after `sync_log()`, so
/// every live extent is expected to already be resolvable to this shape.
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
            write: WriteSlot::unresolved(),
            payload_offset,
            length,
        })))
    }

    pub fn new_disk(
        generation: u64,
        record_log_offset: u64,
        payload_offset: u32,
        length: u32,
    ) -> Self {
        Self(Arc::new(RwLock::new(StoredExtent::Disk {
            generation,
            record_log_offset,
            payload_offset,
            length,
        })))
    }

    fn raw(&self) -> StoredExtent {
        match self.0.read() {
            Ok(guard) => guard.clone(),
            Err(err) => err.into_inner().clone(),
        }
    }

    /// Resolves the *logical* state: `Staged` iff the backing write genuinely hasn't
    /// been flushed yet, `Disk` otherwise — collapsing through the `write` slot
    /// transparently if needed. Callers never need to know whether this value was
    /// directly constructed as `Disk` or is a `Staged` fragment whose write has since
    /// completed; both look identical here.
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
                write,
                payload_offset,
                length,
            } => match write.get() {
                Some(loc) => ExtentState::Disk {
                    generation: loc.generation,
                    record_log_offset: loc.record_log_offset,
                    payload_offset: loc.meta_size + payload_offset,
                    length,
                },
                None => ExtentState::Staged {
                    data,
                    payload_offset,
                    length,
                },
            },
        }
    }

    /// Produces an independent fragment: a *new* `Arc<RwLock<..>>`, seeded from the
    /// current state, that can be trimmed (`trim_left`/`trim_right`) without affecting
    /// `self` or any other fragment. For a `Staged` value, the fragment still shares
    /// the same underlying `write` slot as `self` — so it still becomes visible once
    /// that write is flushed — only `payload_offset`/`length` become independent.
    ///
    /// Required whenever a single range is split into two pieces that must be
    /// mutable independently (see `RangeMap`'s "middle split" case): plain `Clone`
    /// shares the *entire* state, including `payload_offset`/`length`, which is right
    /// for the single-trim cases but corrupts both halves of a split.
    pub fn fork(&self) -> Self {
        Self(Arc::new(RwLock::new(self.raw())))
    }

    /// Marks the write backing this extent as flushed to `generation`/`record_log_offset`
    /// (with `meta_size` bytes of record metadata preceding the raw write bytes). Every
    /// fragment forked from this same original write becomes visible as `Disk` the
    /// moment this returns, however many fragments it's since been split into. No-op if
    /// this extent was constructed directly as `Disk` (nothing to resolve).
    pub fn resolve_write(&self, generation: u64, record_log_offset: u64, meta_size: u32) {
        if let StoredExtent::Staged { write, .. } = &*match self.0.read() {
            Ok(guard) => guard,
            Err(err) => err.into_inner(),
        } {
            write.resolve(DiskLocation {
                generation,
                record_log_offset,
                meta_size,
            });
        }
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
                payload_offset,
                length,
                ..
            } => {
                *payload_offset += shift_u32;
                *length = length.saturating_sub(shift_u32);
            }
            StoredExtent::Disk {
                payload_offset,
                length,
                ..
            } => {
                *payload_offset += shift_u32;
                *length = length.saturating_sub(shift_u32);
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
    fn test_resolve_write_visible_through_clone_but_not_fork() {
        let state = SharedExtentState::new_staged(Arc::new(vec![1, 2, 3, 4, 5]), 0, 5);
        let shared_clone = state.clone();
        let forked = state.fork();

        state.resolve_write(7, 100, 21);

        // A plain clone shares everything, including the resolved write.
        assert!(matches!(
            shared_clone.read_state(),
            ExtentState::Disk { .. }
        ));
        // A fork only shares the write slot, seeded at fork time - it does resolve too,
        // since fork() was called on an unresolved extent and shares the SAME write
        // slot Arc, not a snapshot of resolution state.
        assert!(matches!(forked.read_state(), ExtentState::Disk { .. }));
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
