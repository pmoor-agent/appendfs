# `appendfs` Design & Architecture Specification

## 1. Executive Summary & Core Philosophy

`appendfs` is a high-performance, log-structured in-memory FUSE filesystem designed around an **append-only backing store** for personal archival storage.

Rather than mutating data in-place on disk, `appendfs` records all filesystem mutations (file writes, metadata changes, directory creations, deletions, renames, extended attributes) as an append-only stream of log files ordered by a **monotonic generation sequence number**.

### Core Guarantees:
- **Append-Only Backing Store:** Physical disk writes are 100% sequential and immutable. Old log files are never modified in-place.
- **In-Memory Staging & Deferred Flushing:** Writes are staged in memory and flushed to disk periodically or when requested by `fsync()` / POSIX sync semantics.
- **Complete Reconstructability & Time-Travel:** The full filesystem state (or any past point-in-time state) can be deterministically rebuilt by replaying logs up to a target sequence number.
- **Copy-On-Write Branching (Forking):** New read-write instances can fork from historical checkpoints, sharing ancestor logs while appending new mutations to a divergent branch sequence.
- **Zero-Trust Security & Multi-Cloud Archival:** Log payloads are compressed and encrypted at rest locally before fan-out replication to multiple S3-compatible cloud providers (e.g., AWS S3, Google Cloud Storage, Backblaze B2).
- **Deduplication & FastCDC:** Content-Defined Chunking de-duplicates identical blocks across files and generations.
- **Bitrot Resistance & Disaster Recovery:** All records contain AEAD authentication tags and BLAKE3 checksums, enabling standalone disaster recovery from raw cloud buckets using a master passphrase.

---

## 2. System Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              FUSE Kernel Interface                      │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ FUSE Low-Level Ops & xattrs
┌────────────────────────────────────▼────────────────────────────────────┐
│                             InMemoryFS Engine                           │
│  ┌─────────────────────────────────┐   ┌─────────────────────────────┐  │
│  │ Inode & Directory Metadata Tree │   │ ExtentMap Fragment Allocator│  │
│  └─────────────────────────────────┘   └─────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │            In-Memory Mutation & Write Staging Buffer              │  │
│  └───────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ FastCDC & Staged Flush
┌────────────────────────────────────▼────────────────────────────────────┐
│                 Log Engine & Data Protection Layer                      │
│  ┌─────────────────────────┐           ┌─────────────────────────────┐  │
│  │  Payload Compression    │           │  Authenticated Encryption   │  │
│  │  (zstd / lz4)           │           │  (ChaCha20-Poly1305/Argon2) │  │
│  └─────────────────────────┘           └─────────────────────────────┘  │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ Monotonic Generation Append
┌────────────────────────────────────▼────────────────────────────────────┐
│                    Local Storage & Tiered Cache                         │
│  ┌───────────────────┐    ┌───────────────────┐    ┌─────────────────┐  │
│  │ 000001_init.log   │    │ 000002_active.log │    │ 000002.summary  │  │
│  │ (Sealed/Evictable)│    │ (Active Generation)│   │ (Checkpoint)    │  │
│  └─────────┬─────────┘    └───────────────────┘    └─────────────────┘  │
└────────────┼────────────────────────────────────────────────────────────┘
             │ Multi-Cloud Fan-Out Replication Worker (Throttled)
             ├──────────────────────────────────────┐
┌────────────▼──────────────────────────┐  ┌────────▼──────────────────────────┐
│      Primary Cloud: AWS S3            │  │     Secondary Cloud: GCS / B2    │
│  ┌─────────────────────────────────┐  │  │  ┌──────────────────────────────┐ │
│  │ 000001_init.log (Encrypted)     │  │  │  │ 000001_init.log (Encrypted)  │ │
│  └─────────────────────────────────┘  │  │  └──────────────────────────────┘ │
└───────────────────────────────────────┘  └──────────────────────────────────┘
```

---

## 3. Log-Structured Storage & Staging Model

### 3.1 Monotonic Sequence / Generation Naming
- Each log file is named using a strictly increasing 64-bit **generation sequence number** as the primary sort key (e.g. `000001_1721838000.log`, `000002_1721841600.log`).
- The generation sequence number guarantees deterministic ordering during recovery, replay, and cloud syncing regardless of system clock skew.

### 3.2 LSM Delta-Overlay In-Memory Architecture & Flush Semantics
- `InMemoryFS` organizes in-memory filesystem state into a multi-layered Log-Structured Merge (LSM) overlay:
  1. **`base` (`RwLock<HashMap<u64, Arc<Node>>>`):** The resting, fully consolidated filesystem state. Nodes are stored in safe, immutable `Arc<Node>` pointers.
  2. **`flushing` (`RwLock<VecDeque<HashMap<u64, EntryDelta>>>`):** An ordered FIFO queue of frozen snapshot batches waiting to be serialized and committed to disk.
  3. **`live` (`RwLock<HashMap<u64, EntryDelta>>`):** Active in-memory mutations. Operations modify lightweight `EntryDelta` records without locking base nodes.
- **Top-Down Read Resolution:** Reads query `live` $\rightarrow$ `flushing.iter().rev()` (newest to oldest) $\rightarrow$ `base`.
- **Layered Truncate Masking:** When reading file data, if any upper layer recorded a truncation (`truncate_mask = Some(mask)`), the read range is clamped by the minimum truncate mask across all layers above the queried extent, preventing stale data resurrection when files are truncated down and subsequently extended.
- **Multi-Batch Ordered Flushing Queue & Resilient Retry:**
  - `begin_flush()` non-blockingly swaps the current `live` delta map into `flushing.push_back(frozen)`.
  - `flush_log()` synthesizes log records from `flushing.front()`. Upon successfully appending records and committing via `FlushCommit`, the batch is folded into `base` via `fold_flushed_batch` and popped from the queue.
  - If a flush fails due to an I/O or disk error, the unwritten batch is **retained at the front of `flushing`** and retried on the next flush cycle without wedging filesystem threads or losing live concurrent mutations.
- **Safe Concurrency & Elimination of Lock Pools:** Stripped unsafe raw cell locks in favor of idiomatic Rust `Arc<Node>` CoW semantics.

### 3.3 Log Record Types & Extended Attributes (`xattrs`)
Each entry in the log file consists of a header and an optional compressed/encrypted payload:
- **`RecordHeader`:** Transaction ID, Operation Type (`WRITE`, `CREATE`, `MKDIR`, `UNLINK`, `RENAME`, `SETATTR`, `SETXATTR`, `REMOVEXATTR`, `FLUSH_COMMIT`), Inode ID, Payload Length, Uncompressed Length, Encryption Nonce, and Checksum.
- **`WritePayload`:** Compressed & encrypted byte sequence belonging to a file write (optionally deduplicated via FastCDC).
- **`MetadataPayload`:** Serialized metadata update (permissions, UID/GID, target link paths, timestamps, extended attribute key-values).

### 3.4 In-Memory Index & Fragment Tracking (`ExtentMap`)
- Filesystem file content is tracked using the specialized `ExtentMap` data structure.
- Files start out in compact `Vector` mode (a sorted list of contiguous extents) optimized for $O(1)$ appends, contiguous arena chunk coalescing, and $O(\log N)$ binary search queries.
- On non-sequential overwrites or middle splits, `ExtentMap` seamlessly promotes in-place to an interval `BTreeMap` that trims and splits overlapping extents.
- Extents use a plain value `Extent` enum (`Staged`, `Disk`, `Zero`) without reference-counting indirection or interior locks.
- Upon flush or snapshot export, extents are persisted and cleanly deserialized directly back into compact `Vector` form.

---

## 4. State Recovery, Point-in-Time Mounts & Forking

### 4.1 Summary Checkpoints & Snapshot Manifests
- When `appendfs` is unmounted cleanly (or upon reaching a periodic checkpoint threshold), `appendfs` writes out a `.summary` snapshot file named with the matching generation sequence (e.g. `000002.summary`).
- **Snapshot Manifest Export (`manifest.json.gz`):** Alongside the summary, a human-readable JSON manifest is generated containing `path` $\rightarrow$ `BLAKE3 hash` $\rightarrow$ `size` $\rightarrow$ `mtime`. This enables offline file browsing and diffing without mounting FUSE.

### 4.2 Replay & Boot Pipeline
1. **Fast Path:** Locate the latest valid `.summary` snapshot file, deserialize it into memory, and determine `last_summary_generation`.
2. **Replay Path:** Replay any `.log` files with generation numbers greater than `last_summary_generation` in strictly ascending order.
3. **Fallback Replay:** If no `.summary` snapshot exists, `appendfs` replays all `.log` files in generation sequence order from `000001` upwards.

### 4.3 Time-Travel / Historical Read-Only Mounts
- `appendfs` supports mounting the filesystem at a target historical **sequence number** or **timestamp** ($T_{past}$) in **Read-Only** mode.
- The engine replays logs up to sequence $T_{past}$ and stops, providing an instant, immutable point-in-time view perfect for backup restoration and historical auditing.

### 4.4 Copy-On-Write Branching (Forking)
- `appendfs` supports **forking** a new read-write mount from any historical sequence checkpoint.
- The new branch treats the shared ancestor log files (`000001` .. `00000K`) as read-only base extents, and appends new mutations to its own unique divergent generation branch (e.g. `fork_b1_00000K+1.log`).

---

## 5. Multi-Cloud Replication & Data Protection

### 5.1 Zero-Trust Data Protection Pipeline
All data flushed to physical log files passes through the Data Protection Pipeline before hitting disk or cloud:

```
[Staged Payload] ──► [FastCDC / Dedup] ──► [Compress (zstd)] ──► [Encrypt (ChaCha20-Poly1305)] ──► [Write Local Log]
```

- **Content-Defined Deduplication (FastCDC):** Splits large payloads into content-defined chunks (1MB–4MB). Identical chunks across files/generations reuse existing block IDs.
- **Compression:** Reduces disk footprint and bandwidth requirements using fast block compression (`zstd` / `lz4`).
- **AEAD Encryption:** Authenticated Encryption with Associated Data ensures 100% confidentiality and tamper prevention.
- **Key Derivation:** Master key is derived using `Argon2id` / `HKDF` from a user master passphrase or keyfile.

### 5.2 Multi-Cloud Fan-Out Engine & Bandwidth Control
- **Least-Common-Denominator S3 Support:** Standard S3 API (`PutObject`, `GetObject`, `HeadObject`, `ListObjectsV2`) ensures out-of-the-box compatibility with AWS S3, Google Cloud Storage (S3 Interoperability API), Backblaze B2, Cloudflare R2, MinIO, and Wasabi.
- **Fan-Out Sync Worker:** When a generation log file is sealed, a background replication worker uploads the encrypted log file concurrently to all configured cloud targets (`[backends.aws_s3]`, `[backends.gcs]`).
- **Bandwidth Metering & Scheduling:** Support for `max_upload_mbps` throttling and time-window scheduling (e.g. upload only between 02:00 and 06:00).
- **Read Failover:** If one cloud provider is unreachable or throttled during a cache-miss read, `appendfs` transparently retries the read from an alternate configured cloud backend.

### 5.3 Local Cache Eviction & S3 Range Reads
- Sealed log files remain cached on local disk until a configurable storage threshold (e.g. 85% disk usage) is reached.
- Once confirmed uploaded to all cloud backends, local sealed log payloads can be purged to reclaim local disk space.
- On a read cache-miss, `appendfs` issues a targeted S3 HTTP Range Request (`Range: bytes=offset-(offset+len)`) to fetch only the required extent payload from the cloud into memory.

---

## 6. Maintenance, Integrity & Disaster Recovery

### 6.1 Log Compaction & Garbage Collection (`appendfs compact`)
- `appendfs` monitors the ratio of live (active) vs. dead (overwritten/deleted) extents inside sealed log files.
- When a sealed log file's live extent ratio drops below a threshold (e.g. < 30%), a compaction background job rewrites surviving live extents into a new compacted generation log and issues deletion calls for the dead log across all local and cloud backends.

### 6.2 Bitrot Protection & Scrubbing (`appendfs scrub`)
- A periodic background scrubbing job (or manual CLI command `appendfs scrub`) scans local and remote cloud logs, verifying BLAKE3 checksums and AEAD authentication tags to detect silent data corruption or bitrot before data loss occurs.

### 6.3 Standalone Disaster Recovery (`appendfs-recover`)
- If the local machine and state database are completely destroyed, the user can download a standalone binary (`appendfs-recover`), input their master passphrase, point it at their S3/GCS bucket, and **rebuild 100% of the filesystem state from scratch** anywhere in the world.
