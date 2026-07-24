# `appendfs` Design & Architecture Specification

## 1. Executive Summary & Core Philosophy

`appendfs` is a high-performance, log-structured in-memory FUSE filesystem designed around an **append-only backing store** for personal archival storage.

Rather than mutating data in-place on disk, `appendfs` records all filesystem mutations (file writes, metadata changes, directory creations, deletions, renames) as an append-only stream of log files ordered by a **monotonic generation sequence number**.

### Core Guarantees:
- **Append-Only Backing Store:** Physical disk writes are 100% sequential and immutable. Old log files are never modified in-place.
- **In-Memory Staging & Deferred Flushing:** Writes are staged in memory and flushed to disk periodically or when requested by `fsync()` / POSIX sync semantics.
- **Complete Reconstructability & Time-Travel:** The full filesystem state (or any past point-in-time state) can be deterministically rebuilt by replaying logs up to a target sequence number.
- **Copy-On-Write Branching (Forking):** New read-write instances can fork from historical checkpoints, sharing ancestor logs while appending new mutations to a divergent branch sequence.
- **Zero-Trust Security & Multi-Cloud Archival:** Log payloads are compressed and encrypted at rest locally before fan-out replication to multiple S3-compatible cloud providers (e.g., AWS S3, Google Cloud Storage, Backblaze B2).
- **Bitrot Resistance & Disaster Recovery:** All records contain AEAD authentication tags and BLAKE3 checksums, enabling standalone disaster recovery from raw cloud buckets using a master passphrase.

---

## 2. System Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              FUSE Kernel Interface                      │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ FUSE Low-Level Ops
┌────────────────────────────────────▼────────────────────────────────────┐
│                             InMemoryFS Engine                           │
│  ┌─────────────────────────────────┐   ┌─────────────────────────────┐  │
│  │ Inode & Directory Metadata Tree │   │ RangeMap Fragment Allocator │  │
│  └─────────────────────────────────┘   └─────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │            In-Memory Mutation & Write Staging Buffer              │  │
│  └───────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ Staged Flush (fsync / periodic)
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
             │ Multi-Cloud Fan-Out Replication Worker
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

### 3.2 In-Memory Write Staging & Flush Semantics
- Individual `write()` calls do **not** write to disk immediately. Writes are staged in an in-memory mutation buffer.
- Pending staged writes are flushed to the active log file under the following conditions:
  1. **Explicit Sync:** Client issues `fsync()`, `fsyncdir()`, or opens a file with `O_SYNC` / `O_DSYNC`.
  2. **Periodic Timer:** A background worker flushes staged data periodically (e.g., every 2–5 seconds).
  3. **Buffer Threshold:** Staged buffer size reaches a configured memory threshold (e.g., 4MB or 16MB).

### 3.3 Log Record Types
Each entry in the log file consists of a header and an optional compressed/encrypted payload:
- **`RecordHeader`:** Transaction ID, Operation Type (`WRITE`, `CREATE`, `MKDIR`, `UNLINK`, `RENAME`, `SETATTR`), Inode ID, Payload Length, Uncompressed Length, Encryption Nonce, and Checksum.
- **`WritePayload`:** Compressed & encrypted byte sequence belonging to a file write.
- **`MetadataPayload`:** Serialized metadata update (permissions, UID/GID, target link paths, timestamps).

### 3.4 In-Memory Index & Fragment Tracking (`RangeMap<V>`)
- Filesystem content is tracked using the `RangeMap<V>` data structure.
- When a staged write is flushed, `appendfs` receives physical `(gen_seq, log_offset, length)` extent descriptors.
- `RangeMap` inserts these extent slices into the target file's offset range `[file_offset, file_offset + length)`. Overlapping extent slices are trimmed or split in memory automatically without modifying previous log entries.

---

## 4. State Recovery, Point-in-Time Mounts & Forking

### 4.1 Summary Checkpoints (`.summary`)
- When `appendfs` is unmounted cleanly (or upon reaching a periodic checkpoint threshold), `appendfs` writes out a `.summary` snapshot file named with the matching generation sequence (e.g. `000002.summary`).
- The summary file contains:
  - The latest active Inode lookup table.
  - The complete `RangeMap` extent index mapping logical file ranges to physical log file locations.
  - The last applied generation sequence ID.

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
[Staged Mutation Payload] ──► [Compress (zstd)] ──► [Encrypt (ChaCha20-Poly1305 / Argon2id)] ──► [Write Local Log]
```

- **Compression:** Reduces disk footprint and bandwidth requirements using fast block compression (`zstd` / `lz4`).
- **AEAD Encryption:** Authenticated Encryption with Associated Data ensures 100% confidentiality and tamper prevention.
- **Key Derivation:** Master key is derived using `Argon2id` / `HKDF` from a user master passphrase or keyfile.

### 5.2 Multi-Cloud Fan-Out Engine
- **Least-Common-Denominator S3 Support:** Standard S3 API (`PutObject`, `GetObject`, `HeadObject`, `ListObjectsV2`) ensures out-of-the-box compatibility with AWS S3, Google Cloud Storage (S3 Interoperability API), Backblaze B2, Cloudflare R2, MinIO, and Wasabi.
- **Fan-Out Sync Worker:** When a generation log file is sealed, a background replication worker uploads the encrypted log file concurrently to all configured cloud targets (`[backends.aws_s3]`, `[backends.gcs]`).
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
