# `appendfs` Design & Architecture Specification

## 1. Executive Summary & Core Philosophy

`appendfs` is a high-performance, log-structured in-memory FUSE filesystem designed around an **append-only backing store**. 

Rather than mutating data in-place on disk, `appendfs` records all filesystem mutations (file writes, metadata changes, directory creations, deletions, renames) as an append-only stream of log records.

### Core Guarantees:
- **Append-Only Backing Store:** Physical disk writes are 100% sequential and immutable. Old log files are never modified in-place.
- **Complete Reconstructability:** The full in-memory filesystem state can always be deterministically rebuilt from scratch by replaying the sequence of log files.
- **Zero-Trust Security & Cloud Readyness:** Log payloads are compressed and encrypted at rest before hitting physical storage, making closed log segments instantly ready for untrusted cloud object storage (e.g. S3, GCS) backup.

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
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ Log Streamer
┌────────────────────────────────────▼────────────────────────────────────┐
│                 Log Engine & Data Protection Layer                      │
│  ┌─────────────────────────┐           ┌─────────────────────────────┐  │
│  │  Payload Compression    │           │  Authenticated Encryption   │  │
│  │  (e.g., zstd / lz4)     │           │  (e.g., ChaCha20-Poly1305)  │  │
│  └─────────────────────────┘           └─────────────────────────────┘  │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ Append-Only Writes
┌────────────────────────────────────▼────────────────────────────────────┐
│                           Physical Log Store                            │
│  ┌───────────────────┐    ┌───────────────────┐    ┌─────────────────┐  │
│  │ log_000001.log    │    │ log_000002.log    │    │ 000002.summary  │  │
│  │ (Sealed/Cloud-ready)│  │ (Active Session)  │    │ (Checkpoint)    │  │
│  └───────────────────┘    └───────────────────┘    └─────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Log-Structured Storage Model

### 3.1 Active Log File per Mount Session
- Every time `appendfs` is mounted, a new active log file (e.g. `session_<timestamp>_<uuid>.log`) is created in the log directory.
- All mutating FUSE operations (`write`, `create`, `mkdir`, `chmod`, `chown`, `unlink`, `symlink`, `rename`, `setattr`) append a serialized record to the active log file and flush to disk.

### 3.2 Log Record Types
Each entry in the log file consists of a header and an optional compressed/encrypted payload:
- **`RecordHeader`:** Transaction ID, Operation Type (`WRITE`, `CREATE`, `MKDIR`, `UNLINK`, `RENAME`, `SETATTR`), Inode ID, Payload Length, Uncompressed Length, Encryption Nonce, and CRC32/HMAC checksum.
- **`WritePayload`:** Compressed & encrypted byte sequence belonging to a file write.
- **`MetadataPayload`:** Serialized metadata update (permissions, UID/GID, target link paths, timestamps).

### 3.3 In-Memory Index & Fragment Tracking (`RangeMap<V>`)
- Filesystem content is tracked using the `RangeMap<V>` data structure.
- When a file `write()` occurs, `appendfs` appends the payload bytes to the active log file, obtaining a physical `(log_file_id, log_offset, length)` descriptor.
- `RangeMap` inserts this slice into the target file's offset range `[file_offset, file_offset + length)`. Overlapping extent slices are trimmed or split in memory automatically without modifying previous log entries.

---

## 4. State Recovery & Checkpointing (Summary Files)

### 4.1 Summary Checkpoints (`.summary`)
- When `appendfs` is unmounted cleanly (or upon reaching a periodic checkpoint threshold), `appendfs` writes out a `.summary` snapshot file.
- The summary file contains:
  - The latest active Inode lookup table.
  - The complete `RangeMap` extent index mapping logical file ranges to physical log file locations.
  - The high-water mark sequence ID of the last replayed log record.

### 4.2 Replay & Boot Pipeline
When `appendfs` mounts:
1. **Fast Path:** Locate the latest valid `.summary` snapshot file, deserialize it into memory, and determine `last_summary_log_sequence`.
2. **Replay Path:** Replay any `.log` files created after `last_summary_log_sequence` in sequential order to apply un-checkpointed mutations.
3. **Fallback Replay:** If no `.summary` snapshot exists (or if summary files are deleted), `appendfs` scans and replays all `.log` files sequentially from log #1 to reconstruct 100% of the state deterministically.

---

## 5. Data Protection Layer (Compression & Encryption)

All data written to physical log files passes through the Data Protection Pipeline before hitting disk:

```
[Raw Mutation Payload] ──► [Compress (zstd)] ──► [Encrypt (ChaCha20-Poly1305 / AES-GCM)] ──► [Write to .log]
```

- **Compression:** Reduces disk footprint and bandwidth requirements for text/code payloads using fast block compression (e.g. `zstd` / `lz4`).
- **Encryption:** Authenticated Encryption with Associated Data (AEAD) ensures confidentiality and tamper detection.
- **Cloud Security:** Because data payloads are encrypted locally before hitting disk, sealed log files can be backed up to zero-trust remote cloud storage (AWS S3, Google Cloud Storage, Cloudflare R2) without exposing plaintext data.

---

## 6. Future Roadmap & Cloud Archival

1. **Local Log Lifecycle & Sealed Logs:**
   - Active log files remain local during a mount session.
   - When a session finishes or a log file reaches a max size (e.g. 64MB), it is marked as **Sealed** (read-only).
2. **Cloud Synchronization:**
   - Background workers can sync sealed log files to cloud storage.
   - Local disk space can be reclaimed by purging local copies of sealed log files, reading missing extents on-demand from the cloud via range requests.
3. **Live Log Streaming:**
   - Optional streaming transport layer to stream mutation records to remote endpoints for real-time replication.
