use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

/// Thread-safe buffer reference for staged extent payloads in memory.
pub type StagedBuffer = Arc<RwLock<Vec<u8>>>;

/// Generation number reserved to mean "this extent is a hole" on disk.
pub const ZERO_EXTENT_GENERATION: u64 = 0;

/// Decodes a hole's length from an on-disk extent descriptor.
#[inline]
pub fn zero_extent_len(record_log_offset: u64) -> u64 {
    record_log_offset
}

/// Represents the physical location and state of a file extent slice.
///
/// Plain value enum with zero heap allocations on clone for `Disk` and `Zero` variants,
/// and safe, independent trimming without interior mutability or locks.
#[derive(Debug, Clone)]
pub enum Extent {
    /// Data is staged in memory, not yet flushed to disk.
    Staged {
        data: StagedBuffer,
        payload_offset: u32,
        length: u32,
    },
    /// Data is flushed to disk in a `.log` file.
    Disk {
        generation: u64,
        record_log_offset: u64,
        record_size: u32,
        payload_offset: u32,
        length: u32,
    },
    /// A hole: this range reads as zeros and occupies no space on disk.
    Zero { length: u64 },
}

// RwLock<Vec<u8>> does not implement PartialEq. Extent implements PartialEq by comparing Staged
// buffers via pointer equality (Arc::ptr_eq) for O(1) lock-free comparison, required by PartialEq/Eq
// derives on ExtentEntry, ExtentMap, NodeKind, and Node.
impl PartialEq for Extent {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Staged {
                    data: d1,
                    payload_offset: p1,
                    length: l1,
                },
                Self::Staged {
                    data: d2,
                    payload_offset: p2,
                    length: l2,
                },
            ) => Arc::ptr_eq(d1, d2) && p1 == p2 && l1 == l2,
            (
                Self::Disk {
                    generation: g1,
                    record_log_offset: r1,
                    record_size: s1,
                    payload_offset: p1,
                    length: l1,
                },
                Self::Disk {
                    generation: g2,
                    record_log_offset: r2,
                    record_size: s2,
                    payload_offset: p2,
                    length: l2,
                },
            ) => g1 == g2 && r1 == r2 && s1 == s2 && p1 == p2 && l1 == l2,
            (Self::Zero { length: l1 }, Self::Zero { length: l2 }) => l1 == l2,
            _ => false,
        }
    }
}

impl Eq for Extent {}

#[derive(Serialize, Deserialize)]
struct SerializedExtent {
    generation: u64,
    record_log_offset: u64,
    record_size: u32,
    payload_offset: u32,
    length: u32,
}

impl SerializedExtent {
    #[inline]
    fn zero(length: u64) -> Self {
        Self {
            generation: ZERO_EXTENT_GENERATION,
            record_log_offset: length,
            record_size: 0,
            payload_offset: 0,
            length: 0,
        }
    }
}

impl Serialize for Extent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Extent::Disk {
                generation,
                record_log_offset,
                record_size,
                payload_offset,
                length,
            } => SerializedExtent {
                generation: *generation,
                record_log_offset: *record_log_offset,
                record_size: *record_size,
                payload_offset: *payload_offset,
                length: *length,
            }
            .serialize(serializer),
            Extent::Zero { length } => SerializedExtent::zero(*length).serialize(serializer),
            Extent::Staged { .. } => Err(serde::ser::Error::custom(
                "cannot serialize an extent that has not been flushed to disk",
            )),
        }
    }
}

impl<'de> Deserialize<'de> for Extent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = SerializedExtent::deserialize(deserializer)?;
        if s.generation == ZERO_EXTENT_GENERATION {
            Ok(Self::new_zero(zero_extent_len(s.record_log_offset)))
        } else {
            Ok(Self::new_disk(
                s.generation,
                s.record_log_offset,
                s.record_size,
                s.payload_offset,
                s.length,
            ))
        }
    }
}

impl Extent {
    #[inline]
    pub fn new_staged(data: StagedBuffer, payload_offset: u32, length: u32) -> Self {
        Self::Staged {
            data,
            payload_offset,
            length,
        }
    }

    pub fn new_staged_buffer(bytes: Vec<u8>, payload_offset: u32, length: u32) -> Self {
        Self::new_staged(Arc::new(RwLock::new(bytes)), payload_offset, length)
    }

    #[inline]
    pub fn new_disk(
        generation: u64,
        record_log_offset: u64,
        record_size: u32,
        payload_offset: u32,
        length: u32,
    ) -> Self {
        Self::Disk {
            generation,
            record_log_offset,
            record_size,
            payload_offset,
            length,
        }
    }

    #[inline]
    pub fn new_zero(length: u64) -> Self {
        Self::Zero { length }
    }

    #[inline]
    pub fn length(&self) -> u64 {
        match self {
            Self::Staged { length, .. } => *length as u64,
            Self::Disk { length, .. } => *length as u64,
            Self::Zero { length } => *length,
        }
    }

    /// Bytes this extent occupies on disk - zero for a hole. Drives `st_blocks`.
    #[inline]
    pub fn allocated_len(&self) -> u64 {
        match self {
            Self::Zero { .. } => 0,
            Self::Disk { record_size, .. } => *record_size as u64,
            Self::Staged { length, .. } => *length as u64,
        }
    }

    #[inline]
    pub fn trim_right(&mut self, new_len: u64) {
        match self {
            Self::Staged { length, .. } => {
                *length = std::cmp::min(*length, new_len as u32);
            }
            Self::Disk { length, .. } => {
                *length = std::cmp::min(*length, new_len as u32);
            }
            Self::Zero { length } => {
                *length = std::cmp::min(*length, new_len);
            }
        }
    }

    #[inline]
    pub fn trim_left(&mut self, shift: u64) {
        let shift_u32 = shift as u32;
        match self {
            Self::Staged {
                payload_offset, length, ..
            } => {
                *payload_offset += shift_u32;
                *length = length.saturating_sub(shift_u32);
            }
            Self::Disk {
                payload_offset, length, ..
            } => {
                *payload_offset += shift_u32;
                *length = length.saturating_sub(shift_u32);
            }
            Self::Zero { length } => {
                *length = length.saturating_sub(shift);
            }
        }
    }

    /// Attempts to coalesce `next` into `self` if both are contiguous slices of the same
    /// backing arena chunk or both are holes.
    pub fn try_coalesce_with(&mut self, next: &Extent) -> bool {
        match (self, next) {
            (
                Self::Staged {
                    data: d1,
                    payload_offset: p1,
                    length: l1,
                },
                Self::Staged {
                    data: d2,
                    payload_offset: p2,
                    length: l2,
                },
            ) => {
                if Arc::ptr_eq(d1, d2) && *p1 + *l1 == *p2 {
                    *l1 += *l2;
                    true
                } else {
                    false
                }
            }
            (Self::Zero { length: l1 }, Self::Zero { length: l2 }) => {
                *l1 += *l2;
                true
            }
            _ => false,
        }
    }

    /// Compatibility helper for existing code inspecting extent state.
    #[inline]
    pub fn read_state(&self) -> Self {
        self.clone()
    }

    /// Compatibility helper for shared pointers (now plain value clone).
    #[inline]
    pub fn share(&self) -> Self {
        self.clone()
    }

    #[inline]
    pub fn is_staged(&self) -> bool {
        matches!(self, Self::Staged { .. })
    }

    #[inline]
    pub fn is_disk(&self) -> bool {
        matches!(self, Self::Disk { .. })
    }

    #[inline]
    pub fn is_zero(&self) -> bool {
        matches!(self, Self::Zero { .. })
    }
}

/// An entry in `ExtentMap` representing an extent at `file_offset`.
///
/// The inner `Extent` is the single source of truth for the extent's length and physical location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtentEntry {
    pub file_offset: u64,
    pub extent: Extent,
}

impl ExtentEntry {
    /// Returns the logical byte length of this extent.
    #[inline]
    pub fn length(&self) -> u64 {
        self.extent.length()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ExtentMapInner {
    /// Compact sorted vector of disjoint extents. The default for files, append-only writes,
    /// and disk loading.
    Vector(Vec<ExtentEntry>),
    /// BTreeMap for files that have received non-sequential overwrites or middle splits.
    Tree(BTreeMap<u64, ExtentEntry>),
}

/// Specialized extent container for AppendFS files.
///
/// Starts as a sorted `Vector` of extents for cache-friendly $O(1)$ appends, fast sequential loading,
/// and $O(\log N)$ binary search queries. Seamlessly promotes to a `BTreeMap` on non-sequential
/// overwrites or middle splits.
///
/// # Thread Safety & Concurrency Model
///
/// `ExtentMap` is **thread-compatible** (`Send + Sync`):
/// - **External Synchronization for Mutation**: When mutable (`&mut self`), such as in the live
///   staging layer (`inner.live`), it is protected by the `InMemoryFS` inner mutex (`ActionMutex`).
/// - **Concurrent Lock-Free Reads**: All read operations (`query`, `iter`, `len`, `is_empty`) take `&self`
///   and perform zero internal mutation (Vector mode binary searches via `partition_point` without
///   allocating or promoting).
/// - **Flush Pipeline & Layered Snapshots**: Once a live delta is frozen into a `FlushBatch` or folded into
///   an immutable `Arc<Node>` in `base`, it is strictly read-only. Both the background flusher thread and
///   concurrent layered read walks ([`InodeLayerStack`]) query it safely in parallel without locks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtentMap {
    inner: ExtentMapInner,
}

impl Default for ExtentMap {
    fn default() -> Self {
        Self::new()
    }
}

impl ExtentMap {
    /// Creates an empty `ExtentMap` initialized in compact `Vector` mode.
    pub fn new() -> Self {
        Self {
            inner: ExtentMapInner::Vector(Vec::new()),
        }
    }

    /// Creates an empty `ExtentMap` in `Vector` mode preallocated with capacity.
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            inner: ExtentMapInner::Vector(Vec::with_capacity(cap)),
        }
    }

    /// Returns `true` if this map is currently stored in compact `Vector` mode.
    #[inline]
    pub fn is_vector(&self) -> bool {
        matches!(self.inner, ExtentMapInner::Vector(_))
    }

    /// Returns `true` if this map has promoted to `Tree` mode.
    #[inline]
    pub fn is_tree(&self) -> bool {
        matches!(self.inner, ExtentMapInner::Tree(_))
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        match &self.inner {
            ExtentMapInner::Vector(v) => v.is_empty(),
            ExtentMapInner::Tree(t) => t.is_empty(),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        match &self.inner {
            ExtentMapInner::Vector(v) => v.len(),
            ExtentMapInner::Tree(t) => t.len(),
        }
    }

    pub fn clear(&mut self) {
        match &mut self.inner {
            ExtentMapInner::Vector(v) => v.clear(),
            ExtentMapInner::Tree(t) => t.clear(),
        }
    }

    /// Iterates over all `(&file_offset, &ExtentEntry)` pairs in order of `file_offset`.
    pub fn iter(&self) -> ExtentMapIter<'_> {
        match &self.inner {
            ExtentMapInner::Vector(v) => ExtentMapIter::Vector { slice: v, idx: 0 },
            ExtentMapInner::Tree(t) => ExtentMapIter::Tree(t.iter()),
        }
    }

    /// Inserts a new extent `[new_start, new_start + new_len)` with `extent`.
    ///
    /// If the insert is append-only (starts at or after the end of the current file), it stays
    /// in high-performance `Vector` mode and attempts contiguous coalescing.
    ///
    /// If the insert overlaps earlier regions (random overwrite or middle split), the map
    /// promotes to a `BTreeMap` and handles splitting and trimming.
    pub fn insert(&mut self, new_start: u64, new_len: u64, new_extent: Extent) {
        if new_len == 0 {
            return;
        }

        match &mut self.inner {
            ExtentMapInner::Vector(vec) => {
                let is_append = match vec.last() {
                    None => true,
                    Some(last) => new_start >= last.file_offset + last.length(),
                };

                if is_append {
                    // Attempt contiguous coalescing with the last extent
                    if let Some(last) = vec.last_mut()
                        && last.file_offset + last.length() == new_start
                        && last.extent.try_coalesce_with(&new_extent)
                    {
                        return;
                    }
                    vec.push(ExtentEntry {
                        file_offset: new_start,
                        extent: new_extent,
                    });
                    return;
                }

                // Non-appending write: promote to Tree
                let mut tree = BTreeMap::new();
                for entry in vec.drain(..) {
                    tree.insert(entry.file_offset, entry);
                }
                self.inner = ExtentMapInner::Tree(tree);
            }
            ExtentMapInner::Tree(_) => {}
        }

        let ExtentMapInner::Tree(ref mut tree) = self.inner else {
            unreachable!();
        };
        Self::insert_into_tree(tree, new_start, new_len, new_extent);
    }

    fn insert_into_tree(tree: &mut BTreeMap<u64, ExtentEntry>, new_start: u64, new_len: u64, new_extent: Extent) {
        let new_end = new_start + new_len;

        let mut candidates = Vec::new();
        if let Some((&start, _)) = tree
            .range(..=new_start)
            .next_back()
            .filter(|&(start, entry)| *start + entry.length() > new_start)
        {
            candidates.push(start);
        }

        use std::ops::Bound;
        for (&start, _) in tree.range((Bound::Excluded(new_start), Bound::Excluded(new_end))) {
            candidates.push(start);
        }

        for start in candidates {
            let entry = match tree.get(&start) {
                Some(e) => e.clone(),
                None => continue,
            };
            let end = start + entry.length();

            if start < new_start && end > new_end {
                // Middle split
                let mut left_extent = entry.extent.clone();
                left_extent.trim_right(new_start - start);
                tree.insert(
                    start,
                    ExtentEntry {
                        file_offset: start,
                        extent: left_extent,
                    },
                );

                let mut right_extent = entry.extent;
                right_extent.trim_left(new_end - start);
                tree.insert(
                    new_end,
                    ExtentEntry {
                        file_offset: new_end,
                        extent: right_extent,
                    },
                );
            } else if start < new_start {
                // Left overlap: trim right
                let mut left_extent = entry.extent;
                left_extent.trim_right(new_start - start);
                tree.insert(
                    start,
                    ExtentEntry {
                        file_offset: start,
                        extent: left_extent,
                    },
                );
            } else if end > new_end {
                // Right overlap: trim left
                tree.remove(&start);
                let mut right_extent = entry.extent;
                right_extent.trim_left(new_end - start);
                tree.insert(
                    new_end,
                    ExtentEntry {
                        file_offset: new_end,
                        extent: right_extent,
                    },
                );
            } else {
                // Fully enclosed
                tree.remove(&start);
            }
        }

        tree.insert(
            new_start,
            ExtentEntry {
                file_offset: new_start,
                extent: new_extent,
            },
        );
    }

    /// Queries the map for all extents overlapping `[query_start, query_start + query_len)`.
    /// Returns a list of `(start, length, trimmed_extent)` for each overlapping segment.
    pub fn query(&self, query_start: u64, query_len: u64) -> Vec<(u64, u64, Extent)> {
        if query_len == 0 {
            return Vec::new();
        }
        let query_end = query_start + query_len;

        match &self.inner {
            ExtentMapInner::Vector(vec) => {
                if vec.is_empty() {
                    return Vec::new();
                }
                let mut results = Vec::new();

                let idx = vec.partition_point(|e| e.file_offset <= query_start);
                let start_idx = if idx > 0 && vec[idx - 1].file_offset + vec[idx - 1].length() > query_start {
                    idx - 1
                } else {
                    idx
                };

                for entry in &vec[start_idx..] {
                    if entry.file_offset >= query_end {
                        break;
                    }
                    let start = entry.file_offset;
                    let end = start + entry.length();
                    let seg_start = std::cmp::max(start, query_start);
                    let seg_end = std::cmp::min(end, query_end);
                    let seg_len = seg_end - seg_start;

                    let mut ext = entry.extent.clone();
                    if seg_start > start {
                        ext.trim_left(seg_start - start);
                    }
                    if seg_end < end {
                        ext.trim_right(seg_len);
                    }
                    results.push((seg_start, seg_len, ext));
                }

                results
            }
            ExtentMapInner::Tree(tree) => {
                let mut results = Vec::new();

                let prev_entry = tree
                    .range(..=query_start)
                    .next_back()
                    .filter(|&(start, entry)| *start + entry.length() > query_start)
                    .map(|(&start, entry)| (start, entry));

                use std::ops::Bound;
                let rest_entries = tree
                    .range((Bound::Excluded(query_start), Bound::Excluded(query_end)))
                    .map(|(&start, entry)| (start, entry));

                for (start, entry) in prev_entry.into_iter().chain(rest_entries) {
                    let end = start + entry.length();
                    let seg_start = std::cmp::max(start, query_start);
                    let seg_end = std::cmp::min(end, query_end);
                    let seg_len = seg_end - seg_start;

                    let mut ext = entry.extent.clone();
                    if seg_start > start {
                        ext.trim_left(seg_start - start);
                    }
                    if seg_end < end {
                        ext.trim_right(seg_len);
                    }
                    results.push((seg_start, seg_len, ext));
                }

                results
            }
        }
    }

    /// Truncates the map to `new_len`: removes all extents past `new_len` and trims
    /// any extent straddling the boundary.
    pub fn truncate(&mut self, new_len: u64) {
        match &mut self.inner {
            ExtentMapInner::Vector(vec) => {
                let idx = vec.partition_point(|e| e.file_offset < new_len);
                vec.truncate(idx);
                if idx > 0 {
                    let last = &mut vec[idx - 1];
                    let end = last.file_offset + last.length();
                    if end > new_len {
                        let trimmed_len = new_len - last.file_offset;
                        last.extent.trim_right(trimmed_len);
                    }
                }
            }
            ExtentMapInner::Tree(tree) => {
                let keys_beyond: Vec<u64> = tree.range(new_len..).map(|(&k, _)| k).collect();
                for k in keys_beyond {
                    tree.remove(&k);
                }
                if let Some((&start, entry)) = tree.range_mut(..new_len).next_back() {
                    let end = start + entry.length();
                    if end > new_len {
                        let trimmed_len = new_len - start;
                        entry.extent.trim_right(trimmed_len);
                    }
                }
            }
        }
    }

    /// Coalesces adjacent physically contiguous extents into a fresh compact `Vector`-backed `ExtentMap`.
    pub fn coalesce(&self) -> Self {
        let mut coalesced = Self::with_capacity(self.len());
        for (&start, entry) in self.iter() {
            coalesced.insert(start, entry.length(), entry.extent.clone());
        }
        coalesced
    }
}

pub enum ExtentMapIter<'a> {
    Vector { slice: &'a [ExtentEntry], idx: usize },
    Tree(std::collections::btree_map::Iter<'a, u64, ExtentEntry>),
}

impl<'a> Iterator for ExtentMapIter<'a> {
    type Item = (&'a u64, &'a ExtentEntry);

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Vector { slice, idx } => {
                if *idx < slice.len() {
                    let entry = &slice[*idx];
                    *idx += 1;
                    Some((&entry.file_offset, entry))
                } else {
                    None
                }
            }
            Self::Tree(it) => it.next(),
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Self::Vector { slice, idx } => {
                let remaining = slice.len().saturating_sub(*idx);
                (remaining, Some(remaining))
            }
            Self::Tree(it) => it.size_hint(),
        }
    }
}

impl<'a> ExactSizeIterator for ExtentMapIter<'a> {}

// Serialization: Emits a compact sequence of sorted ExtentEntry items.
impl Serialize for ExtentMap {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match &self.inner {
            ExtentMapInner::Vector(vec) => vec.serialize(serializer),
            ExtentMapInner::Tree(tree) => {
                use serde::ser::SerializeSeq;
                let mut seq = serializer.serialize_seq(Some(tree.len()))?;
                for entry in tree.values() {
                    seq.serialize_element(entry)?;
                }
                seq.end()
            }
        }
    }
}

// Deserialization: Reads entries directly into a compact Vector in a single allocation,
// avoiding B-tree allocations entirely during volume recovery and summary loads.
impl<'de> Deserialize<'de> for ExtentMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let vec = Vec::<ExtentEntry>::deserialize(deserializer)?;
        Ok(Self {
            inner: ExtentMapInner::Vector(vec),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_appends_stay_in_vector_mode() {
        let mut em = ExtentMap::new();
        assert!(em.is_vector());

        em.insert(0, 100, Extent::new_zero(100));
        assert!(em.is_vector());
        assert_eq!(em.len(), 1);

        // Contiguous zero extent should coalesce
        em.insert(100, 100, Extent::new_zero(100));
        assert!(em.is_vector());
        assert_eq!(em.len(), 1);
        let q = em.query(0, 200);
        assert_eq!(q.len(), 1);
        assert_eq!(q[0].0, 0);
        assert_eq!(q[0].1, 200);

        // Append with gap stays in vector mode
        em.insert(300, 50, Extent::new_zero(50));
        assert!(em.is_vector());
        assert_eq!(em.len(), 2);
    }

    #[test]
    fn test_overwrite_promotes_to_tree_mode() {
        let mut em = ExtentMap::new();
        em.insert(0, 100, Extent::new_zero(100));
        em.insert(100, 100, Extent::new_disk(1, 10, 100, 0, 100));
        assert!(em.is_vector());

        // Overwrite in the middle: triggers promotion to Tree
        em.insert(50, 100, Extent::new_disk(2, 20, 100, 0, 100));
        assert!(em.is_tree());

        let entries: Vec<_> = em.iter().map(|(&k, e)| (k, e.length())).collect();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0], (0, 50));
        assert_eq!(entries[1], (50, 100));
        assert_eq!(entries[2], (150, 50));
    }

    #[test]
    fn test_vector_query_and_boundary_cases() {
        let mut em = ExtentMap::new();
        em.insert(0, 50, Extent::new_disk(1, 0, 50, 0, 50));
        em.insert(50, 50, Extent::new_disk(2, 0, 50, 0, 50));
        em.insert(100, 50, Extent::new_disk(3, 0, 50, 0, 50));
        assert!(em.is_vector());

        // Query spanning boundary of first two
        let q = em.query(40, 20);
        assert_eq!(q.len(), 2);
        assert_eq!(q[0].0, 40);
        assert_eq!(q[0].1, 10);
        assert_eq!(q[1].0, 50);
        assert_eq!(q[1].1, 10);
        assert!(em.is_vector());

        // Query before any extent
        let q = em.query(0, 10);
        assert_eq!(q.len(), 1);
        assert_eq!(q[0].0, 0);
        assert_eq!(q[0].1, 10);

        // Query past end
        assert!(em.query(200, 50).is_empty());
    }

    #[test]
    fn test_vector_truncate() {
        let mut em = ExtentMap::new();
        em.insert(0, 50, Extent::new_disk(1, 0, 50, 0, 50));
        em.insert(50, 50, Extent::new_disk(2, 0, 50, 0, 50));
        em.insert(100, 50, Extent::new_disk(3, 0, 50, 0, 50));
        assert!(em.is_vector());

        // Truncate at 70: removes [100, 150) and trims [50, 100) down to [50, 70)
        em.truncate(70);
        assert!(em.is_vector());
        assert_eq!(em.len(), 2);

        let entries: Vec<_> = em.iter().map(|(&k, e)| (k, e.length())).collect();
        assert_eq!(entries[0], (0, 50));
        assert_eq!(entries[1], (50, 20));
        assert!(em.query(70, 50).is_empty());
    }

    #[test]
    fn test_staged_arena_contiguous_coalescing() {
        let buffer = Arc::new(RwLock::new(vec![0u8; 1024]));
        let mut em = ExtentMap::new();

        // 3 contiguous appends to the same arena buffer
        em.insert(0, 100, Extent::new_staged(Arc::clone(&buffer), 0, 100));
        em.insert(100, 150, Extent::new_staged(Arc::clone(&buffer), 100, 150));
        em.insert(250, 200, Extent::new_staged(Arc::clone(&buffer), 250, 200));

        assert!(em.is_vector());
        // All 3 contiguous appends should have merged into 1 extent entry!
        assert_eq!(em.len(), 1);
        let q = em.query(0, 500);
        assert_eq!(q.len(), 1);
        assert_eq!(q[0].0, 0);
        assert_eq!(q[0].1, 450);
    }

    #[test]
    fn test_wire_serialization_round_trip() {
        let mut em = ExtentMap::new();
        em.insert(0, 1024, Extent::new_disk(1, 100, 1056, 32, 1024));
        em.insert(1024, 2048, Extent::new_zero(2048));
        em.insert(3072, 4096, Extent::new_disk(2, 500, 4128, 32, 4096));

        let bytes = crate::wire::serialize(&em).expect("serialize ExtentMap");
        let decoded: ExtentMap = crate::wire::deserialize(&bytes).expect("deserialize ExtentMap");

        assert!(decoded.is_vector(), "deserialized map must start in Vector mode");
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded.query(0, 8000), em.query(0, 8000));
    }

    #[test]
    fn test_middle_split() {
        let mut em = ExtentMap::new();
        em.insert(0, 1000, Extent::new_disk(1, 0, 1000, 0, 1000));

        // Insert inside range: [200, 500)
        em.insert(200, 300, Extent::new_disk(2, 0, 300, 0, 300));
        assert!(em.is_tree());

        let entries: Vec<(u64, u64)> = em.iter().map(|(&k, v)| (k, v.length())).collect();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0], (0, 200));
        assert_eq!(entries[1], (200, 300));
        assert_eq!(entries[2], (500, 500));
    }

    #[test]
    fn test_full_overwrite() {
        let mut em = ExtentMap::new();
        em.insert(100, 100, Extent::new_disk(1, 0, 100, 0, 100));
        em.insert(200, 100, Extent::new_disk(2, 0, 100, 0, 100));

        // Overwrite both completely: [50, 400)
        em.insert(50, 350, Extent::new_disk(3, 0, 350, 0, 350));
        assert!(em.is_tree());

        assert_eq!(em.len(), 1);
        let (&start, entry) = em.iter().next().unwrap();
        assert_eq!(start, 50);
        assert_eq!(entry.length(), 350);
    }

    #[test]
    fn test_multi_interval_overwrite_and_gaps() {
        let mut em = ExtentMap::new();
        // [0, 100), [200, 300), [400, 500)
        em.insert(0, 100, Extent::new_disk(1, 0, 100, 0, 100));
        em.insert(200, 100, Extent::new_disk(2, 0, 100, 0, 100));
        em.insert(400, 100, Extent::new_disk(3, 0, 100, 0, 100));

        // Overwrite [50, 450)
        em.insert(50, 400, Extent::new_disk(4, 0, 400, 0, 400));
        assert!(em.is_tree());

        let entries: Vec<(u64, u64)> = em.iter().map(|(&k, v)| (k, v.length())).collect();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0], (0, 50));
        assert_eq!(entries[1], (50, 400));
        assert_eq!(entries[2], (450, 50));
    }

    #[test]
    fn test_tree_truncate() {
        let mut em = ExtentMap::new();
        em.insert(0, 100, Extent::new_disk(1, 0, 100, 0, 100));
        em.insert(50, 100, Extent::new_disk(2, 0, 100, 0, 100)); // triggers promotion to Tree
        assert!(em.is_tree());

        em.truncate(80);
        assert!(em.is_tree());
        let entries: Vec<(u64, u64)> = em.iter().map(|(&k, v)| (k, v.length())).collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], (0, 50));
        assert_eq!(entries[1], (50, 30));
        assert!(em.query(80, 100).is_empty());
    }

    #[test]
    fn test_query_does_not_mutate_stored_state() {
        let mut em = ExtentMap::new();
        em.insert(0, 100, Extent::new_disk(1, 0, 100, 0, 100));

        let _ = em.query(10, 20);

        let entries: Vec<_> = em.iter().collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(*entries[0].0, 0);
        assert_eq!(entries[0].1.length(), 100);
    }
}
