# `appendfs` Design & Architecture Specification

## 1. Executive Summary & Core Philosophy

`appendfs` is a high-performance, append-only log-structured FUSE filesystem designed for personal archival storage.

Rather than mutating data in-place on disk, `appendfs` records all filesystem mutations (file writes, metadata changes, directory creations, deletions, renames, extended attributes) as an append-only stream of log files ordered by a **monotonic generation sequence number**.

### Core Guarantees:
- **Append-Only Backing Store:** Physical disk writes are 100% sequential and immutable. Old log files are never modified in-place.
- **LSM Staging & POSIX Durability:** Writes are staged in an in-memory delta overlay and committed to disk periodically, at dirty-size thresholds, or synchronously when requested by `fsync()` / `fsyncdir` / POSIX sync semantics.
- **Complete Reconstructability & Time-Travel:** The full filesystem state (or any past point-in-time state) can be deterministically rebuilt by replaying summaries and logs up to a target log generation, flush batch ID, or timestamp.
- **Copy-On-Write Cloud Branching (Forking):** New instances can bootstrap from a remote checkpoint (`appendfs init --from-remote`) and treat an upstream remote as read-only ancestor storage while appending new generations locally and to their own writable remotes.
- **Client-Side Encryption & Multi-Cloud Archival:** Log payloads are compressed and encrypted at rest locally before fan-out replication to multiple S3-compatible cloud providers (e.g., AWS S3, Google Cloud Storage, Backblaze B2, Cloudflare R2) or local/NFS paths.
- **Bitrot Resistance & Disaster Recovery:** Every record carries a 16-byte authentication tag - Poly1305 on encrypted volumes, a truncated BLAKE3 hash on plaintext ones - and every summary carries a full BLAKE3 checksum, enabling standalone disaster recovery from raw log files using only the volume's key file.

---

## 2. System Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              FUSE Kernel Interface                      │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ FUSE Low-Level Ops & xattrs
┌────────────────────────────────────▼────────────────────────────────────┐
│                              AppendFs Engine                            │
│  ┌─────────────────────────────────┐   ┌─────────────────────────────┐  │
│  │ Inode & Directory Metadata Tree │   │ ExtentMap Fragment Allocator│  │
│  └─────────────────────────────────┘   └─────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │            In-Memory Mutation & Write Staging Buffer              │  │
│  └───────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ Staged Batch Flush
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
│  │ 000001.log        │    │ 000002.log        │    │ 000001.summary  │  │
│  │ (Sealed/Evictable)│    │ (Active Generation)│   │ (Checkpoint)    │  │
│  └─────────┬─────────┘    └───────────────────┘    └─────────────────┘  │
└────────────┼────────────────────────────────────────────────────────────┘
             │ Multi-Cloud Fan-Out Replication Worker
             ├──────────────────────────────────────┐
┌────────────▼──────────────────────────┐  ┌────────▼──────────────────────────┐
│      Primary Cloud: AWS S3            │  │   Secondary Cloud / Local Target  │
│  ┌─────────────────────────────────┐  │  │  ┌──────────────────────────────┐ │
│  │ 000001.log (Encrypted)          │  │  │  │ 000001.log (Encrypted)       │ │
│  └─────────────────────────────────┘  │  │  └──────────────────────────────┘ │
└───────────────────────────────────────┘  └──────────────────────────────────┘
```

---

## 3. Log-Structured Storage & Staging Model

### 3.1 Monotonic Sequence / Generation Naming
- Each log file is named using a strictly increasing 32-bit **generation sequence number** as the primary sort key (e.g. `000001.log`, `000002.log`; a compacted revision of a generation adds an `_r<n>` suffix, e.g. `000002_r1.log`).
- Every `.log` file starts with a fixed 42-byte `FileHeader` (`APPF` magic, format version, `generation: u32`, `revision: u16`, `created_at` timestamp, and a random 16-byte `key_salt`). A generation is a `u32` and a compaction revision a `u16` everywhere either appears - in file headers, summary headers, the manifest, and extent descriptors. Log rolling refuses to advance past `u32::MAX` rather than wrapping back to generation 0.
- The generation sequence number guarantees deterministic ordering during recovery, replay, and cloud syncing regardless of system clock skew.

### 3.2 LSM Delta-Overlay In-Memory Architecture & Flush Semantics
- `AppendFs` organizes in-memory filesystem state into a three-layer Log-Structured Merge (LSM) overlay inside `FsInner`, protected by a consolidated `ActionMutex<FsInner>` (`AppendFs::inner`):
  1. **`base` (`HashMap<u64, Arc<Node>>`):** The resting, fully consolidated filesystem state loaded from `.summary` at mount and folded forward as batches commit. Nodes are stored as immutable `Arc<Node>` pointers.
  2. **`flushing` (`VecDeque<Arc<FlushBatch>>`):** An ordered FIFO queue of immutable frozen snapshot batches (holding `entries: HashMap<u64, EntryDelta>` and their associated `WriteArena` buffers) waiting to be serialized and committed to disk.
  3. **`live` (`HashMap<u64, EntryDelta>` + `live_arena: WriteArena`):** Active in-memory mutations. Operations modify lightweight `EntryDelta` records and stage write payloads into `live_arena` without mutating `base` nodes in place.
- **Race-Free Layered Read Resolution (`InodeLayerStack`):** Every read spanning layers constructs an `InodeLayerStack` while holding `inner`, capturing a consistent view of `base` and chronological deltas (`flushing[0..n]` followed by `live`) so a concurrent flush moving a batch from `live` $\rightarrow$ `flushing` $\rightarrow$ `base` can never be straddled or missed. For file reads, `plan_read` resolves extents into a `ReadPlan`; memory-resident slices (`Extent::Staged` or hits in the in-memory `DecryptedRecordCache`) are satisfied immediately without copying, while cold disk or remote reads are dispatched outside the lock on `ReadThreadPool`.
- **Layered Truncate Masking:** When reading file data, if any upper layer recorded a truncation (`truncate_mask = Some(mask)`), the read range is clamped by the minimum truncate mask across all layers above the queried extent, preventing stale data resurrection when files are truncated down and subsequently extended.
- **Multi-Batch Ordered Flushing Queue, Coalescing & Resilient Retry:**
  - `freeze_live()` swaps the current `live` delta map and `live_arena` into an immutable `Arc<FlushBatch>` at the back of `flushing`, subject to queue depth, byte, and operation limits (`max_flush_queue_depth`, `max_flush_queue_bytes`, `max_flush_queue_ops`). When the queue is saturated, incoming mutating FUSE requests are throttled asynchronously via `DelayedResponseQueue`.
  - `flush_log()` takes the front batch (or coalesces a group of eligible small batches) from `flushing` without holding `inner` during disk I/O, normalizes self-canceling directory deltas against `base`, synthesizes coalesced `Data`/`DataZstd` and `InodeDelta` log records plus a `FlushCommit` trailer, and syncs the log writer. Upon a successful sync, it re-acquires `inner`, pops the committed batch(es) via `pop_flushed_batch`, and folds their deltas into `base` via `fold_entries`.
  - If a flush fails due to an I/O or disk error, `LogWriter` rolls back the uncommitted tail and the unwritten batch is **retained at the front of `flushing`** to be retried on the next flush cycle without wedging filesystem threads or losing live concurrent mutations.

### 3.3 Log Record Types & Extended Attributes (`xattrs`)
Each entry in the log file consists of a fixed 37-byte header and an optional compressed/encrypted payload:
- **`RecordHeader` (37 bytes):** `op_code` (1) · `inode` (8) · `payload_len` (4) · `sequence` (8) · `auth_tag` (16).
  - `sequence` is the low 64 bits of the record's nonce (§5.1.2). It is stored rather than derived from the record's byte offset, so a record can be encrypted before anyone knows where in the file it will land.
  - It deliberately carries **no key id**. A per-record key id would be unauthenticated, since the header is not covered by the tag, and clearing it used to downgrade an encrypted read into a raw one; whether a volume is encrypted is instead recorded once in the volume header, where the key check value vouches for it.
  - The header is authenticated indirectly: `sequence` feeds the nonce, `op_code` and `inode` are bound as AEAD associated data (§5.1.2), and `payload_len` is implicit in the ciphertext length, so altering any of them, or truncating or extending a record, breaks its tag.
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

### 4.1 Summary Checkpoints & Log Manifest
- Volume initialization writes `000000.summary` containing the root directory (inode 1) and an initial `VolumeHeader`. During normal operation, `appendfs` writes a `.summary` snapshot file named with the matching generation sequence (e.g. `000002.summary`) on clean unmount, or during log rolls once `summary_interval_bytes` (default 10 GiB) or `summary_interval_generations` (default 10 generations) has elapsed since the previous summary.
- **Single-File Summary Layout:** Each `.summary` file consists of a 66-byte `SummaryHeader`, the plaintext `VolumeHeader`, a Zstd-compressed (and, on encrypted volumes, ChaCha20-Poly1305 encrypted) body containing all serialized `Node`s sorted by inode followed by the `LogManifest` (recording each sealed generation's filename, size, record count, timestamps, MD5 digest, and `key_salt`), and a 52-byte `SummaryFooter` storing the manifest offset, inode count, magic, and a 32-byte BLAKE3 checksum over everything preceding the footer.
- **Offline Catalog Inspection:** `appendfs dump -v <summary_file>` parses and prints the full directory/file tree, resolved paths, metadata attributes, and extent mappings directly from a `.summary` file without mounting FUSE.

### 4.2 Replay & Boot Pipeline
1. **Fast Path:** Locate the newest valid `.summary` snapshot file eligible for the recovery target, verify its BLAKE3 footer checksum and (if encrypted) AEAD authentication tag, deserialize its inodes and `LogManifest` into memory, and restore runtime counters (`last_summary_generation`, `next_inode`, `last_batch_id`).
2. **Replay Path:** Replay any `.log` files with generation numbers greater than `last_summary_generation` (up to the recovery target) in strictly ascending order, discarding any uncommitted trailing records after the final `FlushCommit`.
3. **Remote Historical Fetch:** On read-only mounts (`appendfs mount-ro`), if older summaries or intermediate `.log` files needed for a historical recovery target were pruned locally, `prepare_remote_recovery_for_target` automatically fetches and verifies them from configured readable remotes before replay.

### 4.3 Time-Travel / Historical Read-Only Mounts
- `appendfs mount-ro` supports mounting the filesystem at a target historical **timestamp** (`--at-time`), **flush batch ID** (`--batch-id`), or **log generation** (`--generation`) in read-only mode.
- The engine selects the latest eligible summary at or before the target and replays subsequent log records up to the target boundary, providing an instant, immutable point-in-time view for backup restoration and historical auditing.

### 4.4 Copy-On-Write Cloud Branching (Forking)
- `appendfs` supports bootstrapping a new volume from an existing remote (`appendfs init --from-remote <name>`) and configuring an upstream remote in `read-only` mode.
- The forked volume treats the ancestor log files (`000001.log` .. `00000K.log`) on the read-only upstream remote as shared base extents - fetching cold blocks on demand via `TieredStorageReader` without re-uploading them unless `--replicate-ancestors` is enabled - and writes new mutations to subsequent generations (`00000K+1.log`, ...) locally and to its own writable remotes. Because every log file derives its encryption key from a fresh random `key_salt` in its header (§5.1.1), a forked volume and its upstream never share a per-file key or reuse a nonce even when writing the same generation number.

---

## 5. Multi-Cloud Replication & Data Protection

### 5.1 Data Protection Pipeline

#### Threat Model
appendfs protects against two things, and design trade-offs are judged against them:
- **Privacy.** Nobody without the volume's credential can read file contents or the metadata listed in §5.1.3 - not a thief holding the disk, not a cloud provider holding the replicated log files, not anyone else who ends up with a copy.
- **Durability.** Data acknowledged by a flush survives crashes, power loss, and bitrot detection, and can be recovered from the raw log files alone (§6.3).

It deliberately does **not** try to defend against an adversary who can *write* to the volume. Someone able to modify log files can delete generations, truncate the tail, or move and replay intact records, and appendfs does not attempt to detect that cryptographically. The per-record tags and file checksums exist to catch corruption and bugs, not forgery: on a plaintext volume they are unkeyed hashes anyone can recompute.

Consequences worth keeping in mind:
- **Nonce uniqueness is a privacy property, and non-negotiable.** Two records encrypted under the same nonce leak the XOR of their plaintexts to anyone holding both, so every mechanism that could repeat a nonce - rollbacks, retries, crashes, restarts - has to be closed off even though tampering is out of scope.
- **Records are not bound to their position.** Nothing ties a record to its byte offset (§5.1.2), which is what lets payloads be encrypted before their placement is known.
- **Two writers on one key are safe.** A fork (§4.4) continues from the generation after its fork point under its upstream's key, while an upstream that keeps writing uses that same generation number next; two copies of one volume mounted read-write, or a remote restore while the original is still in use, do the same. None of these reuse a nonce, because every log file is encrypted under its own key derived from a random salt in its header (§5.1.1) - two files with the same generation number still never share a key.

All data flushed to physical log files passes through the Data Protection Pipeline before hitting disk or cloud:

```
[Staged Payload] ──► [Compress (zstd)] ──► [Encrypt (ChaCha20-Poly1305)] ──► [Write Local Log]
```

Compression precedes encryption because ciphertext does not compress, and it is cheap in that position because a record is already the unit of I/O - an AEAD authenticates a payload as a whole, so reading any byte of a record already fetches and processes all of it.

On the write path, `LogWriter` compresses and encrypts in place into a reusable record buffer (`ActiveLogFile::append_data_slices` / `append_serialized`); on the read path, decryption and decompression are exposed as **one operation** (`log::codec::decode`), not two steps a caller composes. There is therefore a single shared route from bytes on disk back to a payload in memory, and it is not possible for a reader to perform half of the transformation. When the stages were separate, three read paths each had to remember to unwrap the compression envelope after decrypting, and one of them did not.


#### 5.1.1 Key Hierarchy
- **Key file → master key.** The one credential is a key file holding the 256-bit master key in a small PEM-style envelope, used directly with no stretching - it already carries full entropy. The file may instead hold the key encrypted with ChaCha20-Poly1305 under an `Argon2id`-stretched passphrase (64 MiB, t=3, p=1 by default; the parameters, salt and nonce are recorded in the file). That passphrase protects the file, not the volume: adding, changing or removing it writes a new key file and leaves the volume untouched. Key files are only ever created, never written over - created read-only for their owner before any key material reaches them - so no command can destroy the only copy of a volume's key; retiring an old one is left to the user. The parser accepts exactly what `appendfs key init` writes and rejects anything else, rather than guessing at an encoding and silently producing the wrong key.
- **Retired credential modes.** Volumes could once be unlocked by a passphrase alone or by a key file *plus* a passphrase, both run through `Argon2id` over a per-volume salt, and the volume header still has room for which mode a volume chose and that salt. Both fields are now read and ignored - `cipher` alone says whether a key file is needed - and kept only because the header layout is positional. Such volumes keep working once the key their mode derived is put into a key file.
- **Master key → subkeys.** The master key encrypts nothing directly. `BLAKE3::derive_key` produces a **data key** and a **key-check key** under separate domain-separation contexts, which keeps the key check value's random IV and the data path's record nonces in disjoint key spaces where they can never collide.
- **Data key → one key per log file.** Each log file's header carries a random 16-byte `key_salt`, drawn when the file is created, and its records are encrypted under `BLAKE3::derive_key("appendfs log file key v1", data_key ‖ key_salt)`. A record nonce therefore only has to be unique within its own file (§5.1.2), and nothing about how generation numbers are allocated - across crashes, forks, or copies of the volume - can make two files share a key. Summaries are encrypted under the data key directly, each with a random IV.
- **Key check value.** A bare Poly1305 tag over an *empty* message, with the volume ID as associated data, stored in the plaintext volume header. Encrypting nothing means it reveals no plaintext and costs exactly one tag. It is verified at mount, before recovery reads a single record, so a wrong credential is reported as **`WrongKey`** rather than surfacing as an authentication failure mid-replay - which is indistinguishable from bitrot and reads to a user like data loss. Binding the volume ID prevents a check value being transplanted between volumes to make a wrong key look right.
- **No wrapped key, no indirection.** The key in the key file *is* the volume key. Losing it loses the volume, and changing it means re-encrypting every generation.

#### 5.1.2 Record Nonces & Associated Data
- **Nonces.** ChaCha20-Poly1305 fixes the nonce at 96 bits:

  ```
  byte  0    1    2    3  |  4    5    6    7    8    9   10   11
       [    zero: 32     ] [              sequence: 64              ]
  ```

  `sequence` is a counter stored in the record header. Because every log file has its own key (§5.1.1), a nonce only has to be unique within one file, and it is: the writer starts each file at sequence 0 and only ever advances the counter. A write that fails and is rolled back gives up its sequence numbers rather than handing them out again - the bytes of the failed attempt may already be on disk even after the truncate. The one rule this leaves is that **a log file is only ever appended to by the writer that created it**; every mount starts a new file, so none ever resumes one.

  No counter state needs persisting or restoring: a new file starts a new sequence. Recovery - and so every mount and `appendfs fsck` - and `restore.py` reject a file whose sequence does not strictly increase from record to record, since that is how a nonce-reuse bug in the writer would show. The sequence is not contiguous - a rollback leaves a gap.
- **Bounds.** `sequence` is a `u64`, which one file - capped by `max_log_size` - cannot come close to exhausting; the increment is still checked rather than wrapped.
- **Rewriting a generation** (compaction into a new revision, §6.1) means a new file and so a new key: records are re-encrypted as they are copied, which costs little next to the I/O of the copy itself.
- **Replicating a file** has to carry its header along. Active-generation parts are uploaded from offset 0 for this reason, and a bootstrap reassembles them verbatim rather than writing a header of its own.
- **Associated data.** Each record binds `[op_code, inode]`. The nonce covers the sequence, the per-file key covers which file the record belongs to, and `payload_len` is covered implicitly by the ciphertext length, but `op_code` and `inode` have no such protection - without binding them a writer bug that mislabelled a record's type or attributed it to the wrong inode would decrypt cleanly and graft one file's data onto another. `payload_len` and the checksum are deliberately *excluded*, since both are derived from the ciphertext and feeding them in would make the associated data depend on the encryption's own output. The record's byte offset is excluded too (see Threat Model).
- **Tags.** A detached 16-byte tag per record, stored in the header. Plaintext volumes put a truncated BLAKE3 hash of `AAD || payload` in the same field, so corruption is detected whether or not a volume is encrypted. Only the Poly1305 tag is keyed; the plaintext hash can be recomputed by anyone who edits the record.
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

### 5.2 Multi-Cloud Fan-Out Engine & Remote Modes
- **S3 & Local/NFS Targets (`remotes.toml`):** Standard S3 API (`PutObject`, `GetObject`, `HeadObject`, `ListObjectsV2`, `DeleteObject`) signed with AWS SigV4 ensures compatibility with AWS S3, Google Cloud Storage, Backblaze B2, Cloudflare R2, MinIO, and Wasabi, alongside local directory or NFS/SMB targets (`LocalDirRemoteStore` via `--path`). Each target under `[remotes.<name>]` supports an operating `mode` (`read-write`, `read-only` upstream, or `write-only` archive such as Glacier Deep Archive), `read_priority`, `max_concurrent_reads`, and optional S3 `storage_class`.
- **Fan-Out Sync Worker (`RemoteReplicationWorker`):** An autonomous background worker syncs sealed `.log` generations and `.summary` checkpoints to all writable remotes (`read-write` remotes prioritized ahead of `write-only` archives, and lower replication lag first), verifying remote object size and MD5/ETag after upload. For `read-write` remotes with `upload_partial_logs` enabled (the default), the worker also uploads incremental slices of the currently active log generation (`{:06}.part{:04}.log` every `active_sync_interval_secs`, default 1h) from offset 0 and cleans up transient `.part` objects once the consolidated sealed generation is verified. If a sealed log or summary has already been pruned locally, the worker can cross-copy it between peer remotes with streaming MD5 and BLAKE3 verification.
- **Priority, Load Balancing & Read Failover:** During cold remote reads, `TieredStorageReader` queries readable remotes in ascending `read_priority` order (default 10 for local/NFS paths, 100 for S3). Within an equal-priority tier, requests are distributed deterministically via a hash of `(filename, start_block)`, bounded per remote by `ConcurrencyLimiter` (`max_concurrent_reads`), and transparently fail over to the next candidate if a remote is unreachable or returns an error.

### 5.3 Tiered Storage, Caching & Range Reads
- **Policy-Driven Local Pruning (`PruneExpr`):** Local eviction of sealed `.log` files is governed by `policy.prune_rule` in `remotes.toml` (default: `older_than(30d) && readable(1)`), which supports boolean combinations (`&&`, `||`, `at_least(k, ...)`), age predicates (`older_than(...)`), named remote confirmations, and `readable(k)` thresholds. Engine-enforced guardrails never prune the active log generation, never prune a generation not yet covered by a local `.summary` file, pin `.summary` files locally, and reject any `prune_rule` that could be satisfied without at least one confirmed readable remote.
- **Two-Tier Read Cache (`DecryptedRecordCache` & `OnDiskBlockCache`):**
  1. `DecryptedRecordCache` (default 128 MiB in-memory LRU) caches decrypted and decompressed record payloads keyed by `(generation, revision, record_log_offset)`, serving repeated reads with zero disk I/O and zero decryption overhead.
  2. `OnDiskBlockCache` (default 16 GiB on-disk LRU in `<log_dir>/.cache/`) caches raw 1 MiB blocks (`BLOCK_SIZE = 1 MiB`) of sealed log files fetched from remotes (and optionally local reads when `--disk-cache-local-reads` is enabled).
- **Single-Flight Coalescing & Range Batching:** On a block cache miss, `RemoteReadCoalescer` deduplicates concurrent in-flight requests for the same 1 MiB block so only one leader fetch is issued while followers wait, and `TieredStorageReader` coalesces contiguous runs of missing 1 MiB blocks into a single multi-megabyte HTTP Range GET request (`Range: bytes=start-end`). Multi-extent cold reads are dispatched in parallel across `ReadThreadPool` worker threads.

---

## 6. Maintenance, Integrity & Disaster Recovery

### 6.1 Extent Elision, Live Ratio Tracking & Future Log Compaction
- **In-Memory Overwrite & Delta Elision:** Within a flush batch, `ExtentMap` trims and eliminates overwritten byte ranges before they ever reach disk, and directory deltas normalize self-canceling operations (such as creating and unlinking a file in the same batch) against `base`.
- **Live Extent Ratio Tracking & Revision Format:** `appendfs stats` computes the live vs. dead (overwritten/deleted) extent ratio for every sealed log generation, and the on-disk format and manifest carry a `u16` compaction revision number (`_r<n>` suffix, e.g. `000001_r1.log`) so compacted generations can be rewritten under a new per-file key salt.
- **Cross-Generation Compaction (Planned):** Background or CLI-driven garbage collection rewriting surviving extents across sealed generations (`appendfs compact`) is not yet implemented; historical log generations remain append-only and immutable once sealed.

### 6.2 Bitrot Protection & Scrubbing (`appendfs fsck`)
- `appendfs fsck` recovers the volume and runs multi-pass structural and cryptographic verification: checking directory hierarchy, link counts, orphan inodes, extent bounds, summary BLAKE3 checksums, and manifest lineage. Because authentication is what detects corruption, a wrong credential is rejected up front by the key check value (§5.1.1) rather than being reported as widespread bitrot.
- With `--verify-data`, `fsck` reads, decrypts, decompresses, and verifies the 16-byte authentication tag (`Poly1305` or `BLAKE3`) of every live data extent record. `--sample-percent <pct>` (with an optional reproducible `--seed <u64>`) verifies a deterministic random sample of live 1 MiB blocks, estimating remote network egress and prompting for confirmation (unless `-y` / `--yes` is passed).
- `--remotes <all|local|name,...>` extends verification to configured remote targets, checking remote object presence, file sizes, and MD5/ETag digests against the volume's manifest (and fetching missing blocks from readable remotes during `--verify-data` / `--sample-percent`).

### 6.3 Standalone Disaster Recovery (`scripts/restore.py`)
- If the local machine and its state are completely destroyed, `scripts/restore.py` rebuilds the filesystem from raw log and summary files with nothing but the volume's key file. It is a single-file Python reimplementation of the read path - key files and their Argon2id passphrase protection, the key check value, record nonces, associated data, BLAKE3 checksums/tags, and Zstd decompression (via `argon2-cffi`, `blake3`, `cryptography`, and `zstandard`) - deliberately kept independent of the main binary so that recovery never depends on being able to build this project, or on Rust, Cargo, or FUSE being available.
- The compatibility suite runs it against every checked-in fixture, including the encrypted ones, so the two implementations cannot drift apart unnoticed.
