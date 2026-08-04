# `appendfs` Future Feature Backlog & TODO

## Future Enhancements & Backlog

- [ ] **Log File Revision Identifiers for Compaction:** Add a revision identifier to the log file naming scheme (e.g., `000001-00.log` or `000001_r0.log`) after the generation ID. This will allow future log compaction routines to rewrite existing log generations while preserving the original generation ID and advancing the revision number.
- [ ] **Multi-Write Batch Records (`OP_BATCH_WRITE`):** Batch small staged writes across multiple files into a single log record payload to minimize header overhead for high-frequency micro-writes.
- [ ] **Coalesce Adjacent Writes:** When flushing a batch, merge adjacent (contiguous or overlapping) staged writes to the same file into a single write record instead of one record per write, reducing per-record header/checksum overhead for high-frequency sequential writers. Apply the same coalescing when exporting a `.summary` file.
- [ ] **Elide Partially-Overwritten Bytes Within a Flush Batch:** `LogBuffer::flush` already skips writes fully superseded by a later write in the same batch (`fully_superseded_within_batch`), but a write that's only *partially* overwritten still has its full original buffer written to disk today, with just the extent pointer narrowed to the surviving sub-range - the superseded bytes still cost physical I/O. Slice staged writes down to just their currently-valid sub-ranges (accounting for partial overlap, not just full coverage) before writing.
- [ ] **Extended Attributes (`xattrs`):** Support POSIX extended attributes (`setxattr`, `getxattr`, `listxattr`, `removexattr`) for desktop metadata (e.g. macOS Finder tags, custom user attributes).
- [ ] **File Locking (`flock` / `fcntl`):** Support advisory/mandatory FUSE record locking for application concurrency (e.g. SQLite, Git, office applications).
- [ ] **Summary Catalog Exporter CLI:** Add a CLI command/utility (`appendfs catalog <summary_file>`) to parse and print a human-readable file manifest directly from a `.summary` snapshot file without mounting FUSE.
- [ ] **Live Log Streaming:** Optional real-time log streaming transport protocol for continuous remote replication to a secondary server/cluster.
