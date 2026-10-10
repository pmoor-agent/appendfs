use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

/// Thread-safe buffer reference for staged extent payloads in memory.
pub type StagedBuffer = Arc<RwLock<Vec<u8>>>;

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
        generation: u32,
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

/// Persisted `.summary` form of an [`Extent`]. `Staged` has no on-disk form: a summary is only
/// ever exported from flushed state.
#[derive(Serialize, Deserialize)]
enum SerializedExtent {
    Disk {
        generation: u32,
        record_log_offset: u64,
        record_size: u32,
        payload_offset: u32,
        length: u32,
    },
    Zero {
        length: u64,
    },
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
            } => SerializedExtent::Disk {
                generation: *generation,
                record_log_offset: *record_log_offset,
                record_size: *record_size,
                payload_offset: *payload_offset,
                length: *length,
            }
            .serialize(serializer),
            Extent::Zero { length } => SerializedExtent::Zero { length: *length }.serialize(serializer),
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
        Ok(match SerializedExtent::deserialize(deserializer)? {
            SerializedExtent::Disk {
                generation,
                record_log_offset,
                record_size,
                payload_offset,
                length,
            } => Self::new_disk(generation, record_log_offset, record_size, payload_offset, length),
            SerializedExtent::Zero { length } => Self::new_zero(length),
        })
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
        generation: u32,
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

#[derive(Debug, Clone)]
enum ExtentMapInner {
    /// Zero extents. Completely zero heap allocation.
    Empty,
    /// Exactly one extent stored inline without heap allocation.
    Single(ExtentEntry),
    /// Compact sorted vector of disjoint extents. Used for files with multiple extents.
    Vector(Vec<ExtentEntry>),
    /// BTreeMap for files that have received non-sequential overwrites or middle splits.
    Tree(BTreeMap<u64, ExtentEntry>),
}

impl PartialEq for ExtentMapInner {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Empty, Self::Empty) => true,
            (Self::Single(e1), Self::Single(e2)) => e1 == e2,
            (Self::Vector(v1), Self::Vector(v2)) => v1 == v2,
            (Self::Tree(t1), Self::Tree(t2)) => t1 == t2,
            _ => false,
        }
    }
}

impl Eq for ExtentMapInner {}

/// Specialized extent container for AppendFS files.
///
/// Starts inline as `Empty` or `Single` with zero heap allocations. Files with multiple sequential
/// appends promote to a sorted `Vector` of extents for cache-friendly $O(1)$ appends, fast sequential loading,
/// and $O(\log N)$ binary search queries. Seamlessly promotes to a `BTreeMap` on non-sequential
/// overwrites or middle splits.
///
/// # Thread Safety & Concurrency Model
///
/// `ExtentMap` is **thread-compatible** (`Send + Sync`):
/// - **External Synchronization for Mutation**: When mutable (`&mut self`), such as in the live
///   staging layer (`inner.live`), it is protected by the `AppendFs` inner mutex (`ActionMutex`).
/// - **Concurrent Lock-Free Reads**: All read operations (`query`, `iter`, `len`, `is_empty`) take `&self`
///   and perform zero internal mutation (Vector mode binary searches via `partition_point` without
///   allocating or promoting).
/// - **Flush Pipeline & Layered Snapshots**: Once a live delta is frozen into a `FlushBatch` or folded into
///   an immutable `Arc<Node>` in `base`, it is strictly read-only. Both the background flusher thread and
///   concurrent layered read walks ([`InodeLayerStack`]) query it safely in parallel without locks.
#[derive(Debug, Clone)]
pub struct ExtentMap {
    inner: ExtentMapInner,
}

impl PartialEq for ExtentMap {
    fn eq(&self, other: &Self) -> bool {
        if self.inner == other.inner {
            return true;
        }
        if self.len() != other.len() {
            return false;
        }
        self.iter().eq(other.iter())
    }
}

impl Eq for ExtentMap {}

impl Default for ExtentMap {
    fn default() -> Self {
        Self::new()
    }
}

impl ExtentMap {
    /// Creates an empty `ExtentMap` with zero heap allocations.
    pub fn new() -> Self {
        Self {
            inner: ExtentMapInner::Empty,
        }
    }

    /// Creates an empty `ExtentMap`. Preallocates `Vector` capacity only if `cap > 1`.
    pub fn with_capacity(cap: usize) -> Self {
        if cap <= 1 {
            Self::new()
        } else {
            Self {
                inner: ExtentMapInner::Vector(Vec::with_capacity(cap)),
            }
        }
    }

    /// Returns `true` if this map has zero extents and zero allocated storage.
    #[inline]
    pub fn is_empty_storage(&self) -> bool {
        matches!(self.inner, ExtentMapInner::Empty)
    }

    /// Returns `true` if this map stores exactly one extent inline without heap allocation.
    #[inline]
    pub fn is_single(&self) -> bool {
        matches!(self.inner, ExtentMapInner::Single(_))
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
            ExtentMapInner::Empty => true,
            ExtentMapInner::Single(_) => false,
            ExtentMapInner::Vector(v) => v.is_empty(),
            ExtentMapInner::Tree(t) => t.is_empty(),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        match &self.inner {
            ExtentMapInner::Empty => 0,
            ExtentMapInner::Single(_) => 1,
            ExtentMapInner::Vector(v) => v.len(),
            ExtentMapInner::Tree(t) => t.len(),
        }
    }

    pub fn clear(&mut self) {
        self.inner = ExtentMapInner::Empty;
    }

    /// Iterates over all `(&file_offset, &ExtentEntry)` pairs in order of `file_offset`.
    pub fn iter(&self) -> ExtentMapIter<'_> {
        match &self.inner {
            ExtentMapInner::Empty => ExtentMapIter::Empty,
            ExtentMapInner::Single(entry) => ExtentMapIter::Single(Some(entry)),
            ExtentMapInner::Vector(v) => ExtentMapIter::Vector { slice: v, idx: 0 },
            ExtentMapInner::Tree(t) => ExtentMapIter::Tree(t.iter()),
        }
    }

    /// Inserts a new extent `[file_offset, file_offset + extent.length())`.
    ///
    /// If empty or single, it stays inline with zero heap allocations.
    /// If the insert is append-only, it transitions to or stays in high-performance
    /// `Vector` mode and attempts contiguous coalescing.
    ///
    /// If the insert overlaps earlier regions (random overwrite or middle split), the map
    /// promotes to a `BTreeMap` and handles splitting and trimming.
    pub fn insert(&mut self, file_offset: u64, extent: Extent) {
        let new_len = extent.length();
        if new_len == 0 {
            return;
        }

        match &mut self.inner {
            ExtentMapInner::Empty => {
                self.inner = ExtentMapInner::Single(ExtentEntry { file_offset, extent });
                return;
            }
            ExtentMapInner::Single(entry) => {
                let entry_start = entry.file_offset;
                let entry_len = entry.length();
                let entry_end = entry_start + entry_len;
                let new_end = file_offset + new_len;

                // Case 1: Contiguous append that coalesces
                if entry_end == file_offset && entry.extent.try_coalesce_with(&extent) {
                    return;
                }

                // Case 2: Append after existing extent (with gap or non-coalescing)
                if file_offset >= entry_end {
                    let old_entry = match std::mem::replace(&mut self.inner, ExtentMapInner::Empty) {
                        ExtentMapInner::Single(e) => e,
                        _ => unreachable!(),
                    };
                    let mut vec = Vec::with_capacity(4);
                    vec.push(old_entry);
                    vec.push(ExtentEntry { file_offset, extent });
                    self.inner = ExtentMapInner::Vector(vec);
                    return;
                }

                // Case 3: Full overwrite of the single extent
                if file_offset <= entry_start && new_end >= entry_end {
                    *entry = ExtentEntry { file_offset, extent };
                    return;
                }

                // Case 4: Non-sequential write or partial overlap: promote to Tree
                let old_entry = match std::mem::replace(&mut self.inner, ExtentMapInner::Empty) {
                    ExtentMapInner::Single(e) => e,
                    _ => unreachable!(),
                };
                let mut tree = BTreeMap::new();
                tree.insert(old_entry.file_offset, old_entry);
                self.inner = ExtentMapInner::Tree(tree);
            }
            ExtentMapInner::Vector(vec) => {
                let is_append = match vec.last() {
                    None => true,
                    Some(last) => file_offset >= last.file_offset + last.length(),
                };

                if is_append {
                    // Attempt contiguous coalescing with the last extent
                    if let Some(last) = vec.last_mut()
                        && last.file_offset + last.length() == file_offset
                        && last.extent.try_coalesce_with(&extent)
                    {
                        return;
                    }
                    vec.push(ExtentEntry { file_offset, extent });
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
        Self::insert_into_tree(tree, file_offset, extent);
    }

    /// Inserts an `ExtentEntry` at its `file_offset`.
    #[inline]
    pub fn insert_entry(&mut self, entry: ExtentEntry) {
        self.insert(entry.file_offset, entry.extent);
    }

    fn insert_into_tree(tree: &mut BTreeMap<u64, ExtentEntry>, new_start: u64, new_extent: Extent) {
        let new_len = new_extent.length();
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
            ExtentMapInner::Empty => Vec::new(),
            ExtentMapInner::Single(entry) => {
                let start = entry.file_offset;
                let end = start + entry.length();
                if query_start >= end || query_end <= start {
                    return Vec::new();
                }
                let seg_start = std::cmp::max(start, query_start);
                let seg_end = std::cmp::min(end, query_end);
                let seg_len = seg_end - seg_start;
                if seg_len == 0 {
                    return Vec::new();
                }

                let mut ext = entry.extent.clone();
                if seg_start > start {
                    ext.trim_left(seg_start - start);
                }
                if seg_end < end {
                    ext.trim_right(seg_len);
                }
                vec![(seg_start, seg_len, ext)]
            }
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
        if new_len == 0 {
            self.inner = ExtentMapInner::Empty;
            return;
        }

        match &mut self.inner {
            ExtentMapInner::Empty => {}
            ExtentMapInner::Single(entry) => {
                let start = entry.file_offset;
                let end = start + entry.length();
                if new_len <= start {
                    self.inner = ExtentMapInner::Empty;
                } else if new_len < end {
                    let trimmed_len = new_len - start;
                    entry.extent.trim_right(trimmed_len);
                }
            }
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
                if vec.is_empty() {
                    self.inner = ExtentMapInner::Empty;
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
                if tree.is_empty() {
                    self.inner = ExtentMapInner::Empty;
                }
            }
        }
    }

    /// Coalesces adjacent physically contiguous extents into a fresh compact `ExtentMap`.
    pub fn coalesce(&self) -> Self {
        match &self.inner {
            ExtentMapInner::Empty => Self::new(),
            ExtentMapInner::Single(entry) => {
                let mut em = Self::new();
                em.insert_entry(entry.clone());
                em
            }
            ExtentMapInner::Vector(_) | ExtentMapInner::Tree(_) => {
                let mut coalesced = Self::with_capacity(self.len());
                for (_start, entry) in self.iter() {
                    coalesced.insert_entry(entry.clone());
                }
                if let ExtentMapInner::Vector(mut vec) = coalesced.inner {
                    if vec.is_empty() {
                        coalesced.inner = ExtentMapInner::Empty;
                    } else if vec.len() == 1 {
                        coalesced.inner = ExtentMapInner::Single(vec.pop().unwrap());
                    } else {
                        coalesced.inner = ExtentMapInner::Vector(vec);
                    }
                }
                coalesced
            }
        }
    }
}

pub enum ExtentMapIter<'a> {
    Empty,
    Single(Option<&'a ExtentEntry>),
    Vector { slice: &'a [ExtentEntry], idx: usize },
    Tree(std::collections::btree_map::Iter<'a, u64, ExtentEntry>),
}

impl<'a> Iterator for ExtentMapIter<'a> {
    type Item = (&'a u64, &'a ExtentEntry);

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Empty => None,
            Self::Single(opt) => opt.take().map(|entry| (&entry.file_offset, entry)),
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
            Self::Empty => (0, Some(0)),
            Self::Single(opt) => {
                let len = if opt.is_some() { 1 } else { 0 };
                (len, Some(len))
            }
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
            ExtentMapInner::Empty => {
                let empty: &[ExtentEntry] = &[];
                empty.serialize(serializer)
            }
            ExtentMapInner::Single(entry) => std::slice::from_ref(entry).serialize(serializer),
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

// Deserialization: Reads entries directly into Empty or Single mode without heap allocation,
// or into a compact Vector for multi-extent files, avoiding B-tree allocations entirely.
impl<'de> Deserialize<'de> for ExtentMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ExtentMapVisitor;

        impl<'de> serde::de::Visitor<'de> for ExtentMapVisitor {
            type Value = ExtentMap;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a sequence of ExtentEntry")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let first = match seq.next_element()? {
                    None => {
                        return Ok(ExtentMap {
                            inner: ExtentMapInner::Empty,
                        });
                    }
                    Some(first) => first,
                };

                let second = match seq.next_element()? {
                    None => {
                        return Ok(ExtentMap {
                            inner: ExtentMapInner::Single(first),
                        });
                    }
                    Some(second) => second,
                };

                let cap = seq.size_hint().map(|h| h + 2).unwrap_or(4);
                let mut vec = Vec::with_capacity(cap);
                vec.push(first);
                vec.push(second);
                while let Some(entry) = seq.next_element()? {
                    vec.push(entry);
                }
                Ok(ExtentMap {
                    inner: ExtentMapInner::Vector(vec),
                })
            }
        }

        deserializer.deserialize_seq(ExtentMapVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_summary_extent_round_trip() {
        let disk = Extent::new_disk(7, 1024, 137, 20, 100);
        let bytes = crate::wire::serialize(&disk).unwrap();
        assert_eq!(crate::wire::deserialize::<Extent>(&bytes).unwrap(), disk);

        // Longer than a u32 can hold, which the `Disk` variant's `length` could not carry.
        let hole = Extent::new_zero(u64::MAX - 5);
        let bytes = crate::wire::serialize(&hole).unwrap();
        assert_eq!(crate::wire::deserialize::<Extent>(&bytes).unwrap(), hole);

        assert!(crate::wire::serialize(&Extent::new_staged_buffer(vec![1], 0, 1)).is_err());
    }

    #[test]
    fn test_appends_stay_in_single_and_vector_mode() {
        let mut em = ExtentMap::new();
        assert!(em.is_empty_storage());
        assert_eq!(em.len(), 0);

        em.insert(0, Extent::new_zero(100));
        assert!(em.is_single());
        assert_eq!(em.len(), 1);

        // Contiguous zero extent should coalesce and stay in Single mode
        em.insert(100, Extent::new_zero(100));
        assert!(em.is_single());
        assert_eq!(em.len(), 1);
        let q = em.query(0, 200);
        assert_eq!(q.len(), 1);
        assert_eq!(q[0].0, 0);
        assert_eq!(q[0].1, 200);

        // Append with gap promotes to vector mode
        em.insert(300, Extent::new_zero(50));
        assert!(em.is_vector());
        assert_eq!(em.len(), 2);
    }

    #[test]
    fn test_overwrite_promotes_to_tree_mode() {
        let mut em = ExtentMap::new();
        em.insert(0, Extent::new_zero(100));
        assert!(em.is_single());
        em.insert(100, Extent::new_disk(1, 10, 100, 0, 100));
        assert!(em.is_vector());

        // Overwrite in the middle: triggers promotion to Tree
        em.insert(50, Extent::new_disk(2, 20, 100, 0, 100));
        assert!(em.is_tree());

        let entries: Vec<_> = em.iter().map(|(&k, e)| (k, e.length())).collect();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0], (0, 50));
        assert_eq!(entries[1], (50, 100));
        assert_eq!(entries[2], (150, 50));
    }

    #[test]
    fn test_single_extent_operations() {
        let mut em = ExtentMap::new();
        em.insert(100, Extent::new_disk(1, 10, 200, 0, 200));
        assert!(em.is_single());
        assert_eq!(em.len(), 1);

        // Query completely before
        assert!(em.query(0, 50).is_empty());
        assert!(em.query(50, 50).is_empty());

        // Query completely after
        assert!(em.query(300, 50).is_empty());
        assert!(em.query(350, 50).is_empty());

        // Query exact match
        let q = em.query(100, 200);
        assert_eq!(q.len(), 1);
        assert_eq!(q[0].0, 100);
        assert_eq!(q[0].1, 200);

        // Query partial overlap head
        let q = em.query(50, 100);
        assert_eq!(q.len(), 1);
        assert_eq!(q[0].0, 100);
        assert_eq!(q[0].1, 50);

        // Query partial overlap middle
        let q = em.query(150, 50);
        assert_eq!(q.len(), 1);
        assert_eq!(q[0].0, 150);
        assert_eq!(q[0].1, 50);

        // Query partial overlap tail
        let q = em.query(250, 100);
        assert_eq!(q.len(), 1);
        assert_eq!(q[0].0, 250);
        assert_eq!(q[0].1, 50);

        // Truncate past end leaves it intact
        em.truncate(400);
        assert!(em.is_single());
        assert_eq!(em.len(), 1);
        assert_eq!(em.query(100, 200)[0].1, 200);

        // Truncate inside trims right in place
        em.truncate(250);
        assert!(em.is_single());
        assert_eq!(em.len(), 1);
        assert_eq!(em.query(100, 200)[0].1, 150);

        // Full overwrite of single extent stays in Single mode
        em.insert(50, Extent::new_disk(2, 20, 300, 0, 300));
        assert!(em.is_single());
        assert_eq!(em.len(), 1);
        let q = em.query(0, 500);
        assert_eq!(q.len(), 1);
        assert_eq!(q[0].0, 50);
        assert_eq!(q[0].1, 300);

        // Truncate before start clears to Empty
        em.truncate(30);
        assert!(em.is_empty_storage());
        assert_eq!(em.len(), 0);
    }

    #[test]
    fn test_staged_arena_contiguous_coalescing() {
        let buffer = Arc::new(RwLock::new(vec![0u8; 1024]));
        let mut em = ExtentMap::new();

        // 3 contiguous appends to the same arena buffer
        em.insert(0, Extent::new_staged(Arc::clone(&buffer), 0, 100));
        em.insert(100, Extent::new_staged(Arc::clone(&buffer), 100, 150));
        em.insert(250, Extent::new_staged(Arc::clone(&buffer), 250, 200));

        // All 3 contiguous appends should coalesce and remain in Single mode!
        assert!(em.is_single());
        assert_eq!(em.len(), 1);
        let q = em.query(0, 500);
        assert_eq!(q.len(), 1);
        assert_eq!(q[0].0, 0);
        assert_eq!(q[0].1, 450);
    }

    #[test]
    fn test_wire_serialization_round_trip() {
        // 1. Empty map
        let em_empty = ExtentMap::new();
        let bytes_empty = crate::wire::serialize(&em_empty).expect("serialize empty ExtentMap");
        let decoded_empty: ExtentMap = crate::wire::deserialize(&bytes_empty).expect("deserialize empty ExtentMap");
        assert!(decoded_empty.is_empty_storage());
        assert_eq!(decoded_empty.len(), 0);

        // 2. Single extent map
        let mut em_single = ExtentMap::new();
        em_single.insert(0, Extent::new_disk(1, 100, 1056, 32, 1024));
        let bytes_single = crate::wire::serialize(&em_single).expect("serialize single ExtentMap");
        let decoded_single: ExtentMap = crate::wire::deserialize(&bytes_single).expect("deserialize single ExtentMap");
        assert!(
            decoded_single.is_single(),
            "deserialized single map must be in Single mode"
        );
        assert_eq!(decoded_single.len(), 1);
        assert_eq!(decoded_single.query(0, 2000), em_single.query(0, 2000));

        // 3. Multi extent map
        let mut em = ExtentMap::new();
        em.insert(0, Extent::new_disk(1, 100, 1056, 32, 1024));
        em.insert(1024, Extent::new_zero(2048));
        em.insert(3072, Extent::new_disk(2, 500, 4128, 32, 4096));

        let bytes = crate::wire::serialize(&em).expect("serialize ExtentMap");
        let decoded: ExtentMap = crate::wire::deserialize(&bytes).expect("deserialize ExtentMap");

        assert!(decoded.is_vector(), "deserialized multi map must start in Vector mode");
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded.query(0, 8000), em.query(0, 8000));
    }

    #[test]
    fn test_cross_mode_equality() {
        let mut em_single = ExtentMap::new();
        em_single.insert(0, Extent::new_disk(1, 10, 100, 0, 100));

        let mut em_vec = ExtentMap::with_capacity(2);
        em_vec.insert(0, Extent::new_disk(1, 10, 100, 0, 100));
        assert!(em_vec.is_vector());

        // Single vs Vector with 1 identical extent must be equal
        assert_eq!(em_single, em_vec);

        // Vector vs Tree with identical extents must be equal
        let mut em_tree = ExtentMap::new();
        em_tree.insert(0, Extent::new_disk(1, 10, 200, 0, 200));
        em_tree.insert(100, Extent::new_disk(2, 20, 50, 0, 50)); // promotes to Tree
        assert!(em_tree.is_tree());

        let mut em_vec2 = ExtentMap::new();
        for (&start, entry) in em_tree.iter() {
            em_vec2.insert(start, entry.extent.clone());
        }
        assert!(em_vec2.is_vector() || em_vec2.is_single());
        assert_eq!(em_tree, em_vec2);

        // Empty vs Vector with 0 elements
        let em_empty = ExtentMap::new();
        let em_empty_vec = ExtentMap::with_capacity(5);
        assert_eq!(em_empty, em_empty_vec);
    }

    #[test]
    fn test_coalesce_demotes_vector_to_single() {
        let mut em = ExtentMap::with_capacity(3);
        assert!(em.is_vector());
        em.insert(0, Extent::new_zero(100));
        em.insert(100, Extent::new_zero(100));
        // In with_capacity(3), it started in vector mode.
        let coalesced = em.coalesce();
        assert!(
            coalesced.is_single(),
            "coalescing to 1 extent should demote to Single mode"
        );
        assert_eq!(coalesced.len(), 1);
        assert_eq!(coalesced.query(0, 300)[0].1, 200);
    }

    #[test]
    fn test_middle_split() {
        let mut em = ExtentMap::new();
        em.insert(0, Extent::new_disk(1, 0, 1000, 0, 1000));

        // Insert inside range: [200, 500)
        em.insert(200, Extent::new_disk(2, 0, 300, 0, 300));
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
        em.insert(100, Extent::new_disk(1, 0, 100, 0, 100));
        em.insert(200, Extent::new_disk(2, 0, 100, 0, 100));

        // Overwrite both completely: [50, 400)
        em.insert(50, Extent::new_disk(3, 0, 350, 0, 350));
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
        em.insert(0, Extent::new_disk(1, 0, 100, 0, 100));
        em.insert(200, Extent::new_disk(2, 0, 100, 0, 100));
        em.insert(400, Extent::new_disk(3, 0, 100, 0, 100));

        // Overwrite [50, 450)
        em.insert(50, Extent::new_disk(4, 0, 400, 0, 400));
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
        em.insert(0, Extent::new_disk(1, 0, 100, 0, 100));
        em.insert(50, Extent::new_disk(2, 0, 100, 0, 100)); // triggers promotion to Tree
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
        em.insert(0, Extent::new_disk(1, 0, 100, 0, 100));

        let _ = em.query(10, 20);

        let entries: Vec<_> = em.iter().collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(*entries[0].0, 0);
        assert_eq!(entries[0].1.length(), 100);
    }

    #[test]
    fn test_struct_sizes() {
        assert_eq!(std::mem::size_of::<Extent>(), 32);
        assert_eq!(std::mem::size_of::<ExtentEntry>(), 40);
        assert_eq!(std::mem::size_of::<ExtentMap>(), 40);
        assert_eq!(std::mem::size_of::<ExtentMapInner>(), 40);
        assert_eq!(std::mem::size_of::<crate::node::NodeKind>(), 48);
        assert_eq!(std::mem::size_of::<crate::node::Node>(), 120);
    }

    #[test]
    fn test_randomized_differential_extent_map() {
        let seeds: u64 = std::env::var("FUZZ_SEEDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10);
        let steps: usize = std::env::var("FUZZ_STEPS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(300);

        for seed in 1..=seeds {
            run_randomized_extent_map_test(seed, steps);
        }
    }

    fn read_extent_bytes(ext: &Extent, disk_store: &std::collections::HashMap<(u32, u64), Vec<u8>>) -> Vec<u8> {
        match ext {
            Extent::Staged {
                data,
                payload_offset,
                length,
            } => {
                let buf = data.read().unwrap();
                let start = *payload_offset as usize;
                let end = start + *length as usize;
                buf[start..end].to_vec()
            }
            Extent::Disk {
                generation,
                record_log_offset,
                payload_offset,
                length,
                ..
            } => {
                let buf = &disk_store[&(*generation, *record_log_offset)];
                let start = *payload_offset as usize;
                let end = start + *length as usize;
                buf[start..end].to_vec()
            }
            Extent::Zero { length } => vec![0u8; *length as usize],
        }
    }

    fn run_randomized_extent_map_test(seed: u64, steps: usize) {
        use rand::rngs::StdRng;
        use rand::{Rng, SeedableRng};
        use std::collections::HashMap;

        let mut rng = StdRng::seed_from_u64(seed);
        const CAPACITY: usize = 1024 * 1024; // 1 MiB

        let mut shadow = vec![0u8; CAPACITY];
        let mut written = vec![false; CAPACITY];
        let mut min_written = usize::MAX;
        let mut max_written = 0usize;

        let mut em = ExtentMap::new();
        let mut disk_store: HashMap<(u32, u64), Vec<u8>> = HashMap::new();
        let mut next_disk_log_offset = 1000u64;

        // Optionally hold a reusable staged buffer to test contiguous coalescing
        type ActiveStagedBuffer = (Arc<RwLock<Vec<u8>>>, usize, usize);
        let mut last_staged_buffer: Option<ActiveStagedBuffer> = None;

        for step in 0..steps {
            // 10% chance of truncation when there are written extents
            if rng.gen_range(0..10) == 0 && max_written > 0 {
                let new_len = match rng.gen_range(0..4) {
                    0 => 0,                                                                      // Truncate to 0
                    1 if min_written > 0 => rng.gen_range(0..min_written), // Truncate before min_written
                    2 if min_written <= max_written => rng.gen_range(min_written..=max_written), // Truncate in the middle
                    _ if max_written < CAPACITY => rng.gen_range(max_written..CAPACITY),         // Truncate beyond end
                    _ => 0,
                };

                em.truncate(new_len as u64);
                last_staged_buffer = None;

                if new_len < max_written {
                    shadow[new_len..max_written].fill(0);
                    written[new_len..max_written].fill(false);
                    if let Some(last) = written[..new_len].iter().rposition(|&w| w) {
                        max_written = last + 1;
                        min_written = written[..new_len].iter().position(|&w| w).unwrap();
                    } else {
                        min_written = usize::MAX;
                        max_written = 0;
                    }
                }
                continue;
            }

            // Decide operation kind
            // We want to test various scenarios:
            // 0: Strict append
            // 1: Append with gap
            // 2: Entire range overwrite
            // 3: Strict prefix overwrite
            // 4: Strict suffix overwrite
            // 5: Middle split / overwrite
            // 6: Left overlap
            // 7: Right overlap
            // 8: Contiguous coalescing append (sharing backing buffer)
            // 9: Random range
            let op = rng.gen_range(0..10);

            let (start, len, is_contiguous_append) = match op {
                // Strict append
                0 if min_written < max_written && max_written < CAPACITY => {
                    let len = rng.gen_range(1..=(CAPACITY - max_written).min(64 * 1024));
                    (max_written, len, false)
                }
                // Append with gap
                1 if min_written < max_written && max_written + 16 < CAPACITY => {
                    let max_gap = (CAPACITY - max_written - 8).min(4096);
                    let gap = rng.gen_range(1..=max_gap);
                    let start = max_written + gap;
                    let len = rng.gen_range(1..=(CAPACITY - start).min(64 * 1024));
                    (start, len, false)
                }
                // Entire range overwrite
                2 if min_written < max_written && max_written < CAPACITY => {
                    let start = rng.gen_range(0..=min_written);
                    let end = rng.gen_range(max_written..=CAPACITY);
                    let len = end - start;
                    (start, len, false)
                }
                // Strict prefix overwrite
                3 if min_written < max_written => {
                    let len = rng.gen_range(1..=(max_written - min_written).min(32 * 1024));
                    (min_written, len, false)
                }
                // Strict suffix overwrite
                4 if min_written < max_written => {
                    let len = rng.gen_range(1..=(max_written - min_written).min(32 * 1024));
                    let start = max_written - len;
                    (start, len, false)
                }
                // Middle split / overwrite
                5 if min_written < max_written && max_written - min_written >= 4 => {
                    let start = rng.gen_range(min_written + 1..max_written - 2);
                    let max_len = (max_written - start - 1).min(16 * 1024);
                    let len = rng.gen_range(1..=max_len);
                    (start, len, false)
                }
                // Left overlap
                6 if min_written < max_written && min_written > 1 => {
                    let start = rng.gen_range(0..min_written);
                    let end = rng.gen_range(min_written + 1..=max_written);
                    (start, end - start, false)
                }
                // Right overlap
                7 if min_written < max_written && max_written + 1 < CAPACITY => {
                    let start = rng.gen_range(min_written..max_written);
                    let end = rng.gen_range(max_written + 1..CAPACITY);
                    (start, end - start, false)
                }
                // Contiguous coalescing append
                8 if last_staged_buffer.is_some() && last_staged_buffer.as_ref().unwrap().2 < CAPACITY => {
                    let (_, _, end_offset) = last_staged_buffer.as_ref().unwrap();
                    let start = *end_offset;
                    let len = rng.gen_range(1..=(CAPACITY - start).min(16 * 1024));
                    (start, len, true)
                }
                // Random range fallback
                _ => {
                    let start = rng.gen_range(0..CAPACITY - 1024);
                    let len = rng.gen_range(1..=(CAPACITY - start).min(64 * 1024));
                    (start, len, false)
                }
            };

            if len == 0 {
                continue;
            }

            let extent = if is_contiguous_append {
                let (buf, payload_offset, end_offset) = last_staged_buffer.as_mut().unwrap();
                let mut data = vec![0u8; len];
                rng.fill(&mut data[..]);
                // Ensure non-zero data bytes so they can be distinguished from holes
                for b in &mut data {
                    if *b == 0 {
                        *b = (step as u8).wrapping_add(1);
                    }
                }
                buf.write().unwrap().extend_from_slice(&data);
                let ext = Extent::new_staged(Arc::clone(buf), *payload_offset as u32, len as u32);
                *payload_offset += len;
                *end_offset += len;
                shadow[start..start + len].copy_from_slice(&data);
                ext
            } else {
                // Pick extent kind: 50% Staged, 35% Disk, 15% Zero
                let kind = rng.gen_range(0..100);
                if kind < 50 {
                    // Staged extent
                    let mut data = vec![0u8; len];
                    rng.fill(&mut data[..]);
                    for b in &mut data {
                        if *b == 0 {
                            *b = (step as u8).wrapping_add(1);
                        }
                    }
                    let buf = Arc::new(RwLock::new(data.clone()));
                    let ext = Extent::new_staged(Arc::clone(&buf), 0, len as u32);
                    last_staged_buffer = Some((buf, len, start + len));
                    shadow[start..start + len].copy_from_slice(&data);
                    ext
                } else if kind < 85 {
                    // Disk extent
                    let mut data = vec![0u8; len];
                    rng.fill(&mut data[..]);
                    for b in &mut data {
                        if *b == 0 {
                            *b = (step as u8).wrapping_add(1);
                        }
                    }
                    let generation = 1;
                    let log_offset = next_disk_log_offset;
                    next_disk_log_offset += len as u64;
                    disk_store.insert((generation, log_offset), data.clone());
                    let ext = Extent::new_disk(generation, log_offset, len as u32, 0, len as u32);
                    last_staged_buffer = None;
                    shadow[start..start + len].copy_from_slice(&data);
                    ext
                } else {
                    // Zero extent (hole)
                    let ext = Extent::new_zero(len as u64);
                    last_staged_buffer = None;
                    shadow[start..start + len].fill(0);
                    ext
                }
            };

            written[start..start + len].fill(true);
            min_written = min_written.min(start);
            max_written = max_written.max(start + len);
            em.insert(start as u64, extent);

            // Periodic mid-run sanity checks
            if step % 50 == 0 {
                // Verify ordering and disjointness
                let mut prev_end = 0u64;
                for (&k, entry) in em.iter() {
                    assert_eq!(k, entry.file_offset);
                    assert!(k >= prev_end, "overlapping extents at {k} < {prev_end}");
                    assert!(entry.length() > 0);
                    prev_end = k + entry.length();
                }
                assert_eq!(em.len(), em.iter().count());
                assert_eq!(em.is_empty(), em.iter().count() == 0);
            }

            // Periodic coalesce check
            if step % 100 == 0 && step > 0 && min_written < max_written {
                let coalesced = em.coalesce();
                let query_span = (max_written - min_written) as u64;
                let c_results = coalesced.query(min_written as u64, query_span);
                let mut c_reconstructed = vec![0u8; max_written - min_written];
                for (seg_start, seg_len, ext) in c_results {
                    let seg_bytes = read_extent_bytes(&ext, &disk_store);
                    let rel_start = (seg_start - min_written as u64) as usize;
                    let rel_end = rel_start + seg_len as usize;
                    c_reconstructed[rel_start..rel_end].copy_from_slice(&seg_bytes);
                }
                let mut expected = vec![0u8; max_written - min_written];
                expected.copy_from_slice(&shadow[min_written..max_written]);
                // Compare only written bytes
                for i in min_written..max_written {
                    if written[i] {
                        assert_eq!(c_reconstructed[i - min_written], expected[i - min_written]);
                    }
                }
            }
        }

        // Final verification
        if min_written == usize::MAX {
            assert_eq!(em.len(), 0);
            assert!(em.is_empty_storage());
            return;
        }

        assert!(min_written < max_written);
        let query_span = (max_written - min_written) as u64;
        let results = em.query(min_written as u64, query_span);

        let mut reconstructed = vec![0u8; max_written - min_written];
        let mut covered = vec![false; max_written - min_written];

        for (seg_start, seg_len, ext) in results {
            let seg_bytes = read_extent_bytes(&ext, &disk_store);
            assert_eq!(seg_bytes.len(), seg_len as usize);
            let rel_start = (seg_start - min_written as u64) as usize;
            let rel_end = rel_start + seg_len as usize;
            reconstructed[rel_start..rel_end].copy_from_slice(&seg_bytes);
            covered[rel_start..rel_end].fill(true);
        }

        // Verify that every byte in [min_written..max_written] matches the shadow array exactly
        for i in min_written..max_written {
            let rel = i - min_written;
            if written[i] {
                assert!(covered[rel], "offset {i} should be covered by an extent");
                assert_eq!(reconstructed[rel], shadow[i], "byte mismatch at file offset {i}");
            } else {
                assert!(
                    !covered[rel],
                    "unwritten gap offset {i} should not be covered by an extent"
                );
            }
        }

        // Test 50 random sub-range queries
        for _ in 0..50 {
            let q_start = rng.gen_range(0..CAPACITY - 512);
            let q_len = rng.gen_range(1..=16 * 1024);
            let q_end = (q_start + q_len).min(CAPACITY);
            let actual_q_len = q_end - q_start;

            let q_results = em.query(q_start as u64, actual_q_len as u64);
            let mut q_reconstructed = vec![0u8; actual_q_len];
            let mut q_covered = vec![false; actual_q_len];

            for (seg_start, seg_len, ext) in q_results {
                let seg_bytes = read_extent_bytes(&ext, &disk_store);
                assert_eq!(seg_bytes.len(), seg_len as usize);
                let rel_start = (seg_start - q_start as u64) as usize;
                let rel_end = rel_start + seg_len as usize;
                q_reconstructed[rel_start..rel_end].copy_from_slice(&seg_bytes);
                q_covered[rel_start..rel_end].fill(true);
            }

            for idx in 0..actual_q_len {
                let file_pos = q_start + idx;
                if written[file_pos] {
                    assert!(
                        q_covered[idx],
                        "subquery at {q_start}..{q_end}: offset {file_pos} should be covered"
                    );
                    assert_eq!(
                        q_reconstructed[idx], shadow[file_pos],
                        "subquery byte mismatch at offset {file_pos}"
                    );
                } else {
                    assert!(
                        !q_covered[idx],
                        "subquery at {q_start}..{q_end}: unwritten offset {file_pos} should not be covered"
                    );
                }
            }
        }

        // Storage invariant checks on original map
        assert_eq!(em.is_empty(), em.iter().count() == 0);
        assert_eq!(em.iter().count(), em.len());

        // Coalescing test at the end: verifies coalesced map reproduces exact content
        // and demotes to Single / Empty mode.
        let coalesced = em.coalesce();
        if coalesced.is_empty() {
            assert!(coalesced.is_empty_storage());
        } else if coalesced.len() == 1 {
            assert!(
                coalesced.is_single(),
                "coalesced map with 1 extent must demote to Single mode"
            );
        } else {
            assert!(
                coalesced.is_vector(),
                "coalesced map with >1 extents must be in Vector mode"
            );
        }
        let c_results = coalesced.query(min_written as u64, query_span);
        let mut c_reconstructed = vec![0u8; max_written - min_written];
        for (seg_start, seg_len, ext) in c_results {
            let seg_bytes = read_extent_bytes(&ext, &disk_store);
            let rel_start = (seg_start - min_written as u64) as usize;
            let rel_end = rel_start + seg_len as usize;
            c_reconstructed[rel_start..rel_end].copy_from_slice(&seg_bytes);
        }
        for i in min_written..max_written {
            if written[i] {
                assert_eq!(
                    c_reconstructed[i - min_written],
                    shadow[i],
                    "coalesced map byte mismatch at {i}"
                );
            }
        }
    }
}
