use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Trait implemented by value types stored in `RangeMap`.
/// Provides hooks for modifying values when ranges are split or trimmed due to overlaps.
pub trait RangeValue: Clone {
    /// Called when the right side of a range is cut off.
    /// `new_len` is the new length of the remaining left portion.
    fn trim_right(&mut self, new_len: u64);

    /// Called when the left side of a range is cut off.
    /// `shift` is the number of bytes cut off from the start of the range.
    fn trim_left(&mut self, shift: u64);

    /// Produces a value for use when a range is split into two pieces that must then be
    /// trimmed independently of each other (see the "middle split" case in `insert`).
    /// Defaults to `Clone::clone`, which is correct for plain value types. Types whose
    /// `Clone` impl shares mutable state (e.g. an `Arc<RwLock<..>>`-backed type) MUST
    /// override this to return genuinely independent storage — otherwise trimming one
    /// half of a split will silently corrupt the other half too.
    fn fork(&self) -> Self {
        self.clone()
    }
}

/// An entry in the `RangeMap` representing a continuous span of `length` bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeEntry<V> {
    pub length: u64,
    pub value: V,
}

/// A generic Interval/Range Map keyed by starting offset `u64`.
///
/// Inserting a new range into the map automatically trims, splits, or removes
/// any existing overlapping ranges using the `RangeValue` trait hooks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RangeMap<V> {
    map: BTreeMap<u64, RangeEntry<V>>,
}

impl<V> Default for RangeMap<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V> RangeMap<V> {
    /// Creates a new empty `RangeMap`.
    pub fn new() -> Self {
        Self { map: BTreeMap::new() }
    }

    /// Returns `true` if the range map contains no entries.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Returns the number of entries in the range map.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Clears all entries from the range map.
    pub fn clear(&mut self) {
        self.map.clear();
    }

    /// Iterates over all `(start_offset, RangeEntry)` pairs in order of `start_offset`.
    pub fn iter(&self) -> impl Iterator<Item = (&u64, &RangeEntry<V>)> {
        self.map.iter()
    }

    /// Inserts a new range `[new_start, new_start + new_len)` into the map with `new_value`.
    ///
    /// Any existing overlapping ranges are automatically trimmed, split, or overwritten.
    pub fn insert(&mut self, new_start: u64, new_len: u64, new_value: V)
    where
        V: RangeValue,
    {
        if new_len == 0 {
            return;
        }
        let new_end = new_start + new_len;

        // Collect all candidate start keys that begin before new_end
        let candidates: Vec<u64> = self.map.range(..new_end).map(|(&start, _)| start).collect();

        for start in candidates {
            let entry = match self.map.get(&start) {
                Some(e) => e.clone(),
                None => continue,
            };
            let end = start + entry.length;

            if end <= new_start {
                // Non-overlapping: entry strictly precedes new range
                continue;
            }

            if start < new_start && end > new_end {
                // Case 1: Middle split (new range falls strictly inside existing range).
                // Both halves must be independently trimmable from here on, so each gets
                // its own fork() rather than sharing entry.value between them — trimming
                // one must never be observable through the other (see RangeValue::fork).

                // Trim left portion: [start, new_start)
                let mut left_val = entry.value.fork();
                left_val.trim_right(new_start - start);
                self.map.insert(
                    start,
                    RangeEntry {
                        length: new_start - start,
                        value: left_val,
                    },
                );

                // Trim right portion: [new_end, end)
                let mut right_val = entry.value.fork();
                right_val.trim_left(new_end - start);
                self.map.insert(
                    new_end,
                    RangeEntry {
                        length: end - new_end,
                        value: right_val,
                    },
                );
            } else if start < new_start {
                // Case 2: Left overlap (existing range starts before new_start and ends inside new range)
                let mut left_val = entry.value;
                left_val.trim_right(new_start - start);
                self.map.insert(
                    start,
                    RangeEntry {
                        length: new_start - start,
                        value: left_val,
                    },
                );
            } else if end > new_end {
                // Case 3: Right overlap (existing range starts inside new range and extends after new_end)
                self.map.remove(&start);
                let mut right_val = entry.value;
                right_val.trim_left(new_end - start);
                self.map.insert(
                    new_end,
                    RangeEntry {
                        length: end - new_end,
                        value: right_val,
                    },
                );
            } else {
                // Case 4: Fully enclosed (new_start <= start && end <= new_end). Removing
                // the map entry alone isn't enough: something else (e.g. another extent reference)
                // may still hold this same value, so mark it explicitly empty.
                let mut val = entry.value;
                val.trim_right(0);
                self.map.remove(&start);
            }
        }

        // Insert the new range
        self.map.insert(
            new_start,
            RangeEntry {
                length: new_len,
                value: new_value,
            },
        );
    }

    /// Queries the map for all ranges overlapping `[query_start, query_start + query_len)`.
    /// Returns a list of `(start, length, trimmed_value)` for each overlapping segment.
    ///
    /// Read-only with respect to the map's own structure, but each returned value is
    /// trimmed to the query window - it must therefore be `fork()`ed, not `clone()`d,
    /// from the stored entry. `Clone` is free to share mutable state (as
    /// `SharedExtentState` does, deliberately, for the RangeMap<->flush-pipeline link),
    /// and trimming a *shared* clone silently corrupts the stored entry as a side
    /// effect of merely querying it - a plain partial read is enough to trigger it.
    pub fn query(&self, query_start: u64, query_len: u64) -> Vec<(u64, u64, V)>
    where
        V: RangeValue,
    {
        if query_len == 0 {
            return Vec::new();
        }
        let query_end = query_start + query_len;
        let mut results = Vec::new();

        for (&start, entry) in self.map.range(..query_end) {
            let end = start + entry.length;
            if end <= query_start {
                continue;
            }

            let seg_start = std::cmp::max(start, query_start);
            let seg_end = std::cmp::min(end, query_end);
            let seg_len = seg_end - seg_start;

            let mut val = entry.value.fork();
            if seg_start > start {
                val.trim_left(seg_start - start);
            }
            if seg_end < end {
                val.trim_right(seg_len);
            }

            results.push((seg_start, seg_len, val));
        }

        results
    }

    /// Removes/trims all entries so nothing beyond `new_len` remains: entries entirely
    /// at or past `new_len` are removed, and an entry straddling the boundary is
    /// trimmed to just its portion within `[0, new_len)`.
    ///
    /// For shrinking a file via truncate/setattr - without this, a later grow back
    /// past `new_len` (with no new write covering the newly-exposed region) would
    /// read back the old, supposedly-deleted bytes instead of the zero-filled hole
    /// POSIX requires, since nothing ever removed them from the map.
    pub fn truncate(&mut self, new_len: u64)
    where
        V: RangeValue,
    {
        let keys_beyond: Vec<u64> = self.map.range(new_len..).map(|(&k, _)| k).collect();
        for k in keys_beyond {
            self.map.remove(&k);
        }

        if let Some((&start, entry)) = self.map.range_mut(..new_len).next_back() {
            let end = start + entry.length;
            if end > new_len {
                entry.value.trim_right(new_len - start);
                entry.length = new_len - start;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TestSlice {
        file_id: u32,
        offset: u64,
        length: u64,
    }

    /// Arc-sharing wrapper mirroring SharedExtentState's Clone-shares/fork-independent
    /// split, so tests here can actually distinguish a `clone()` bug from a correct
    /// `fork()` - TestSlice's own Clone is already independent and can't tell the two
    /// apart.
    #[derive(Debug, Clone)]
    struct SharedSlice(Arc<Mutex<TestSlice>>);

    impl SharedSlice {
        fn new(slice: TestSlice) -> Self {
            Self(Arc::new(Mutex::new(slice)))
        }

        fn get(&self) -> TestSlice {
            self.0.lock().unwrap().clone()
        }
    }

    impl RangeValue for SharedSlice {
        fn trim_right(&mut self, new_len: u64) {
            self.0.lock().unwrap().trim_right(new_len);
        }

        fn trim_left(&mut self, shift: u64) {
            self.0.lock().unwrap().trim_left(shift);
        }

        fn fork(&self) -> Self {
            SharedSlice::new(self.get())
        }
    }

    impl RangeValue for TestSlice {
        fn trim_right(&mut self, new_len: u64) {
            self.length = new_len;
        }

        fn trim_left(&mut self, shift: u64) {
            self.offset += shift;
            self.length -= shift;
        }
    }

    #[test]
    fn test_user_example() {
        let mut range_map = RangeMap::new();

        // Initial setup:
        // [0, 1024) -> file 1 (A), offset 50, len 1024
        // [1024, 1200) -> file 2 (B), offset 90000, len 176
        range_map.insert(
            0,
            1024,
            TestSlice {
                file_id: 1,
                offset: 50,
                length: 1024,
            },
        );
        range_map.insert(
            1024,
            176,
            TestSlice {
                file_id: 2,
                offset: 90000,
                length: 176,
            },
        );

        // Perform write at offset 900:
        // [900, 1100) -> file 3 (C), offset 0, len 200
        range_map.insert(
            900,
            200,
            TestSlice {
                file_id: 3,
                offset: 0,
                length: 200,
            },
        );

        let entries: Vec<(u64, RangeEntry<TestSlice>)> = range_map.iter().map(|(&k, v)| (k, v.clone())).collect();

        assert_eq!(entries.len(), 3);

        // [0, 900) -> file 1, offset 50, length 900
        assert_eq!(
            entries[0],
            (
                0,
                RangeEntry {
                    length: 900,
                    value: TestSlice {
                        file_id: 1,
                        offset: 50,
                        length: 900
                    }
                }
            )
        );

        // [900, 1100) -> file 3, offset 0, length 200
        assert_eq!(
            entries[1],
            (
                900,
                RangeEntry {
                    length: 200,
                    value: TestSlice {
                        file_id: 3,
                        offset: 0,
                        length: 200
                    }
                }
            )
        );

        // [1100, 1200) -> file 2, offset 90076, length 100
        assert_eq!(
            entries[2],
            (
                1100,
                RangeEntry {
                    length: 100,
                    value: TestSlice {
                        file_id: 2,
                        offset: 90076,
                        length: 100
                    }
                }
            )
        );
    }

    #[test]
    fn test_middle_split() {
        let mut range_map = RangeMap::new();
        range_map.insert(
            0,
            1000,
            TestSlice {
                file_id: 1,
                offset: 0,
                length: 1000,
            },
        );

        // Insert inside range: [200, 500)
        range_map.insert(
            200,
            300,
            TestSlice {
                file_id: 2,
                offset: 0,
                length: 300,
            },
        );

        let entries: Vec<(u64, RangeEntry<TestSlice>)> = range_map.iter().map(|(&k, v)| (k, v.clone())).collect();

        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].0, 0);
        assert_eq!(entries[0].1.length, 200);
        assert_eq!(entries[0].1.value.offset, 0);

        assert_eq!(entries[1].0, 200);
        assert_eq!(entries[1].1.length, 300);
        assert_eq!(entries[1].1.value.file_id, 2);

        assert_eq!(entries[2].0, 500);
        assert_eq!(entries[2].1.length, 500);
        assert_eq!(entries[2].1.value.offset, 500);
    }

    #[test]
    fn test_full_overwrite() {
        let mut range_map = RangeMap::new();
        range_map.insert(
            100,
            100,
            TestSlice {
                file_id: 1,
                offset: 0,
                length: 100,
            },
        );
        range_map.insert(
            200,
            100,
            TestSlice {
                file_id: 2,
                offset: 0,
                length: 100,
            },
        );

        // Overwrite both completely: [50, 400)
        range_map.insert(
            50,
            350,
            TestSlice {
                file_id: 3,
                offset: 0,
                length: 350,
            },
        );

        assert_eq!(range_map.len(), 1);
        let (&start, entry) = range_map.iter().next().unwrap();
        assert_eq!(start, 50);
        assert_eq!(entry.length, 350);
        assert_eq!(entry.value.file_id, 3);
    }

    #[test]
    fn test_query() {
        let mut range_map = RangeMap::new();
        range_map.insert(
            0,
            100,
            TestSlice {
                file_id: 1,
                offset: 0,
                length: 100,
            },
        );
        range_map.insert(
            100,
            100,
            TestSlice {
                file_id: 2,
                offset: 10,
                length: 100,
            },
        );

        // Query across boundary: [50, 150)
        let results = range_map.query(50, 100);
        assert_eq!(results.len(), 2);
        assert_eq!(
            results[0],
            (
                50,
                50,
                TestSlice {
                    file_id: 1,
                    offset: 50,
                    length: 50
                }
            )
        );
        assert_eq!(
            results[1],
            (
                100,
                50,
                TestSlice {
                    file_id: 2,
                    offset: 10,
                    length: 50
                }
            )
        );
    }

    #[test]
    fn test_query_does_not_mutate_stored_state() {
        // Regression test: query() must be side-effect-free on the stored map, even
        // when a partial-overlap query forces a trim on the returned value. Uses
        // SharedSlice (Arc-sharing Clone, like the real SharedExtentState) because
        // TestSlice's own Clone is already independent and can't distinguish a
        // clone()-based bug from a correct fork()-based implementation.
        let mut range_map = RangeMap::new();
        range_map.insert(
            0,
            100,
            SharedSlice::new(TestSlice {
                file_id: 1,
                offset: 0,
                length: 100,
            }),
        );

        // Partial query, touching neither boundary exactly.
        let _ = range_map.query(10, 20);

        let entries: Vec<_> = range_map.iter().collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(*entries[0].0, 0);
        assert_eq!(entries[0].1.length, 100);
        assert_eq!(
            entries[0].1.value.get(),
            TestSlice {
                file_id: 1,
                offset: 0,
                length: 100
            },
            "query() must not have mutated the stored entry"
        );
    }

    #[test]
    fn test_truncate_removes_and_trims_entries() {
        let mut range_map = RangeMap::new();
        range_map.insert(
            0,
            50,
            TestSlice {
                file_id: 1,
                offset: 0,
                length: 50,
            },
        );
        range_map.insert(
            50,
            50,
            TestSlice {
                file_id: 2,
                offset: 0,
                length: 50,
            },
        );

        // Truncate to 30: fully removes the [50,100) entry, trims [0,50) down to [0,30).
        range_map.truncate(30);

        let entries: Vec<_> = range_map.iter().collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0],
            (
                &0,
                &RangeEntry {
                    length: 30,
                    value: TestSlice {
                        file_id: 1,
                        offset: 0,
                        length: 30
                    }
                }
            )
        );

        // Querying the now-freed [30,100) region must return nothing - a later grow
        // reads this as a hole, not stale data.
        assert!(range_map.query(30, 70).is_empty());
    }
}
