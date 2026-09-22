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
- **Bitrot Resistance & Disaster Recovery:** Every record carries a 16-byte authentication tag - Poly1305 on encrypted volumes, a truncated BLAKE3 hash on plaintext ones - and every summary carries a full BLAKE3 checksum, enabling standalone disaster recovery from raw log files using only the volume's passphrase or key file.

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
│  │  (zstd)                 │           │  (ChaCha20-Poly1305/Argon2) │  │
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
Each entry in the log file consists of a fixed 29-byte header and an optional compressed/encrypted payload:
- **`RecordHeader` (29 bytes):** `op_code` (1) · `inode` (8) · `payload_len` (4) · `auth_tag` (16).
  - It deliberately carries **no nonce and no key id**. The nonce is *derived* from `(generation, revision, record_offset)` - coordinates a reader already knows - so it costs no bytes on disk and cannot be tampered with independently of the record it belongs to. A per-record key id would be unauthenticated, since the header is not covered by the tag, and clearing it used to downgrade an encrypted read into a raw one; whether a volume is encrypted is instead recorded once in the volume header, where the key check value vouches for it.
  - The header is authenticated indirectly: `op_code` and `inode` are bound as AEAD associated data (§5.1.2), and `payload_len` is implicit in the ciphertext length, so truncating or extending a record breaks its tag.
- **OpCodes:** `Data`, `DataZstd`, `InodeDelta`, `FlushCommit`, `Seal`.
- **`Data` / `DataZstd` payload:** the bytes of one inode's write, capped at `max_extent_size` (4 MiB default). The cap exists for the read path: a record is the unit of decryption, so an uncapped coalesced write would make reading any single byte decrypt the whole run.
- **`InodeDelta` payload:** a serialized `LogEntryDelta` carrying directory entries (**names**), symlink targets, xattr keys and values, mode, UID/GID, timestamps, and extent map updates. All of it sits inside the encrypted envelope; none of it appears in the header.
- **`FlushCommit`:** trailer written once per flush batch, carrying `batch_id`, timestamp and record count. Batch-id continuity is enforced on replay, so a missing interior generation is detected rather than silently skipped.
- **`Seal`:** terminal record marking a cleanly rolled and closed log file.

### 3.4 In-Memory Index & Fragment Tracking (`ExtentMap`)
- Filesystem file content is tracked using the specialized `ExtentMap` data structure.
- Files initialize inline (`Empty` or `Single` extent) with zero heap allocations, optimized for single-extent and empty files which represent the majority of filesystem inodes.
- Appending additional extents transitions the map to a compact sorted `Vector` mode for $O(1)$ appends, contiguous arena chunk coalescing, and $O(\log N)$ binary search queries.
- On non-sequential overwrites or middle splits, `ExtentMap` seamlessly promotes in-place to an interval `BTreeMap` that trims and splits overlapping extents.
- Extents use a plain value `Extent` enum (`Staged`, `Disk`, `Zero`) without reference-counting indirection or interior locks.
- Upon flush or snapshot export, extents are persisted and cleanly deserialized directly back into inline `Empty`/`Single` or compact `Vector` form with zero intermediate allocations.

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
[Staged Payload] ──► [Compress (zstd)] ──► [Encrypt (ChaCha20-Poly1305)] ──► [Write Local Log]
```

Compression precedes encryption because ciphertext does not compress, and it is cheap in that position because a record is already the unit of I/O - an AEAD authenticates a payload as a whole, so reading any byte of a record already fetches and processes all of it.

The two stages are exposed as **one operation** (`log::codec::encode`), not two a caller composes, and `LogWriter::append_record` is its only caller. There is therefore exactly one route from a payload in memory to bytes on disk, and it is not possible to perform half of the transformation. When the stages were separate, three read paths each had to remember to unwrap the compression envelope after decrypting, and one of them did not.

*(Content-defined deduplication is a planned addition; nothing sits between a staged payload and the log file today other than the two stages above.)*

#### 5.1.1 Key Hierarchy
- **Credential → master key.** A passphrase is stretched with `Argon2id` (64 MiB, t=3, p=1) over the volume's random 16-byte salt. A key file is 64 hex characters used directly as 256 bits, with no stretching - it already carries full entropy. Two-factor volumes run `Argon2id` over `key_file_bytes(32) || passphrase`, fixed-width part first so that no two distinct credential pairs can concatenate to the same material. The volume header records which of the three a volume needs (`KeySource`), so a mount asks for the right credential instead of inferring it from whichever flags were passed.
- **Master key → subkeys.** The master key encrypts nothing directly. `BLAKE3::derive_key` produces a **data key** and a **key-check key** under separate domain-separation contexts, which keeps the key check value's random IV and the data path's derived nonces in disjoint key spaces where they can never collide.
- **Key check value.** A bare Poly1305 tag over an *empty* message, with the volume ID as associated data, stored in the plaintext volume header. Encrypting nothing means it reveals no plaintext and costs exactly one tag. It is verified at mount, before recovery reads a single record, so a wrong credential is reported as **`WrongKey`** rather than surfacing as an authentication failure mid-replay - which is indistinguishable from bitrot and reads to a user like data loss. Binding the volume ID prevents a check value being transplanted between volumes to make a wrong key look right.
- **No wrapped key, no indirection.** The user's credential *is* the volume key. Losing it loses the volume, and changing it means re-encrypting every generation.

#### 5.1.2 Record Nonces & Associated Data
- **Derived nonces.** ChaCha20-Poly1305 fixes the nonce at 96 bits, shared between three coordinates:

  ```
  byte  0    1    2    3  |  4    5  |  6    7    8    9   10   11
       [ generation: 32 ] [ rev: 16 ] [    record_offset: 48     ]
  ```

  Uniqueness rests on `(generation, revision, record_offset)`: records are strictly append-only within a generation revision, so every record starts at a unique byte offset; `generation` increases monotonically across rolls; and `revision` advances when a generation is compacted or rewritten. Deriving beats storing a random nonce per record - a random 96-bit nonce would put the birthday bound within reach at filesystem record rates, quite apart from costing 12 bytes per record.
- **Bounds are enforced, not assumed.** 4.29 billion generations, 65,536 revisions, and 256 TiB per generation. Coordinates outside those ranges are refused (`CryptoError::NonceOverflow`) rather than wrapped: two records sharing a nonce under ChaCha20-Poly1305 leak the XOR of their plaintexts and the Poly1305 one-time key with it, so a refused flush is by far the cheaper outcome.
- **Associated data.** Each record binds `[op_code, record_offset, inode]`. The nonce already covers generation, revision and offset, and `payload_len` is covered implicitly by the ciphertext length, but `op_code` and `inode` have no such protection - without binding them an intact ciphertext could be relabelled as another record type or reattributed to another inode, grafting one file's data onto another. `payload_len` and the checksum are deliberately *excluded*, since both are derived from the ciphertext and feeding them in would make the associated data depend on the encryption's own output.
- **Tags.** A detached 16-byte tag per record, stored in the header. Plaintext volumes put a truncated BLAKE3 hash of `AAD || payload` in the same field, so every volume is tamper-evident whether or not it is encrypted.
- **Summaries.** The whole summary body - every inode, its names, and the manifest - is compressed and then encrypted under the data key with a random 96-bit IV, authenticated with the summary header as associated data. Only the volume header blob ahead of it is plaintext.

#### 5.1.3 What Is Stored in the Clear
The volume header must be readable *before* the key is known, so it is never encrypted: cipher suite, key source, compression mode, volume ID, Argon2 salt, and the key check value. Tampering with it is a denial of service, not a way in - a modified key source merely misdirects credential collection into deriving a key the check value then rejects.

An observer holding the raw files without the key therefore learns:
- Record boundaries, sizes, and opcodes; **inode numbers**, which are carried in the clear in each record header; log file creation timestamps; and write timing and volume.
- With compression enabled, how *compressible* each record was, which distinguishes text from already-compressed media. Records hold a single inode's bytes, so there is no cross-file mixing of the kind CRIME exploits, but an attacker who can write chosen bytes into the same file as a secret and watch record sizes learns something about it.

They do **not** learn file names, file contents, symlink targets, xattr keys or values, sizes, ownership, or timestamps - all of which live inside the encrypted payload. This is enforced by test: the compatibility suite walks each checked-in encrypted fixture, collects every name, file content, symlink target and xattr it contains, and asserts that none of those byte strings appears anywhere in the committed `.log` and `.summary` files.

Two limits worth stating plainly:
- **Rollback of the newest generations is not cryptographically detected.** Deleting an *interior* generation is caught by the batch-id continuity check, since `batch_id` lives inside the authenticated `FlushCommit` payload; truncating the tail looks like a volume that was simply unmounted earlier.
- **Confidentiality ends at the volume files.** Diagnostic logs record file names when run at `trace` level (the default is `info`), and `remotes.toml` stores a literal S3 secret key unless the `-env` credential variants are used.

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

### 6.2 Bitrot Protection & Scrubbing (`appendfs fsck`)
- `appendfs fsck` walks a volume's log and summary files, verifying summary BLAKE3 checksums and, with `--verify-data`, decrypting and authenticating every record payload. Because authentication is what detects corruption, a wrong credential is rejected up front by the key check value (§5.1.1) rather than being reported as widespread bitrot.
- `--remote` extends the check to a configured cloud target, comparing each sealed generation's stored MD5 against the remote object's ETag.
- *(A periodic background scrubbing job is planned; today the check is run on demand.)*

### 6.3 Standalone Disaster Recovery (`scripts/restore.py`)
- If the local machine and its state are completely destroyed, `scripts/restore.py` rebuilds the filesystem from raw log and summary files with nothing but the volume's passphrase or key file. It is a single-file reimplementation of the read path - Argon2id derivation, the key check value, record nonces, associated data, and zstd - deliberately kept independent of the main binary so that recovery never depends on being able to build this project, or on Rust, Cargo, or FUSE being available. Plaintext volumes restore with the standard library alone; encrypted ones additionally need `argon2`, `blake3`, `cryptography` and `zstandard`.
- The compatibility suite runs it against every checked-in fixture, including the encrypted ones, so the two implementations cannot drift apart unnoticed.
