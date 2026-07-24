# `appendfs` Design & Architecture Specification

## 1. Executive Summary & Core Philosophy

`appendfs` is a high-performance, log-structured in-memory FUSE filesystem designed around an **append-only backing store**. 

Rather than mutating data in-place on disk, `appendfs` records all filesystem mutations (file writes, metadata changes, directory creations, deletions, renames) as an append-only stream of log files ordered by a **monotonic generation sequence number**.

### Core Guarantees:
- **Append-Only Backing Store:** Physical disk writes are 100% sequential and immutable. Old log files are never modified in-place.
- **In-Memory Staging & Deferred Flushing:** Writes are staged in memory and flushed to disk periodically or when requested by `fsync()` / POSIX sync semantics.
- **Complete Reconstructability & Time-Travel:** The full filesystem state (or any past point-in-time state) can be deterministically rebuilt by replaying logs up to a target sequence number.
- **Copy-On-Write Branching (Forking):** New read-write instances can fork from historical checkpoints, sharing ancestor logs while appending new mutations to a divergent branch sequence.
- **Zero-Trust Security & Cloud Readiness:** Log payloads are compressed and encrypted at rest before hitting physical storage, making closed log segments instantly ready for untrusted cloud object storage (e.g. S3, GCS) backup.

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
│  │  (e.g., zstd / lz4)     │           │  (e.g., ChaCha20-Poly1305)  │  │
│  └─────────────────────────┘           └─────────────────────────────┘  │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ Monotonic Generation Append
┌────────────────────────────────────▼────────────────────────────────────┐
│                           Physical Log Store                            │
│  ┌───────────────────┐    ┌───────────────────┐    ┌─────────────────┐  │
│  │ 000001_init.log   │    │ 000002_active.log │    │ 000002.summary  │  │
│  │ (Sealed/Cloud-ready)│  │ (Active Generation)│   │ (Checkpoint)    │  │
│  └───────────────────┘    └───────────────────┘    └─────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
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

## 5. Data Protection Layer (Compression & Encryption)

All data flushed to physical log files passes through the Data Protection Pipeline:

```
[Staged Mutation Payload] ──► [Compress (zstd)] ──► [Encrypt (ChaCha20-Poly1305 / AES-GCM)] ──► [Write to .log]
```

- **Compression:** Reduces disk footprint and bandwidth requirements using fast block compression (e.g. `zstd` / `lz4`).
- **Encryption:** Authenticated Encryption with Associated Data (AEAD) ensures confidentiality and tamper detection.
- **Cloud Security:** Because data payloads are encrypted locally before hitting disk, sealed log files can be backed up to zero-trust remote cloud storage (AWS S3, Google Cloud Storage, Cloudflare R2) without exposing plaintext data.

---

## 6. Future Roadmap & Cloud Archival

1. **Sealed Generation Lifecycle:**
   - Active log files remain local during a mount session.
   - Closed generation logs are marked as **Sealed** (read-only).
2. **Cloud Synchronization:**
   - Background workers sync sealed generation log files to cloud storage.
   - Local disk space can be reclaimed by purging local copies of sealed log files, reading missing extents on-demand from the cloud via range requests.
3. **Live Log Streaming:**
   - Optional streaming transport layer to stream mutation records to remote endpoints for real-time replication.
