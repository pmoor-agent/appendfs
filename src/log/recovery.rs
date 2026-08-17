use crate::clock::{Clock, SystemClock};
use crate::fs::InMemoryFS;
use crate::log::extent::SharedExtentState;
use crate::log::reader::{LogReader, LogRecord};
use crate::log::record::{
    BatchCommitPayload, CreatePayload, LinkPayload, MkdirPayload, OpCode, RenamePayload,
    RmdirPayload, SetattrPayload, SymlinkPayload, UnlinkPayload, WriteMeta,
};
use crate::log::summary::SummaryReader;
use crate::node::{Node, SyncNode};
use crate::range_map::RangeMap;
use std::fs;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;

/// Rebuilds complete in-memory filesystem state from summary files and `.log` files
/// inside `log_dir`, using the real system clock for any timestamp not otherwise
/// carried by the log itself. See `recover_fs_with_clock` for injecting a different
/// clock (e.g. for deterministic tests).
pub fn recover_fs(log_dir: impl AsRef<Path>) -> io::Result<InMemoryFS> {
    recover_fs_with_clock(log_dir, Arc::new(SystemClock))
}

/// Same as `recover_fs`, but with an injectable clock instead of always defaulting to
/// `SystemClock` internally. Most timestamps are reconstructed exactly from what's
/// carried in the log regardless of this clock; it only matters for the (rare, and
/// arguably already a lossy edge case) fallback paths that don't have a recorded
/// timestamp to apply.
pub fn recover_fs_with_clock(
    log_dir: impl AsRef<Path>,
    clock: Arc<dyn Clock>,
) -> io::Result<InMemoryFS> {
    let log_dir = log_dir.as_ref();
    if !log_dir.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Log directory does not exist",
        ));
    }

    // 1. Scan for latest valid single-file .summary snapshot
    let mut latest_summary: Option<(u64, SummaryReader)> = None;
    if let Ok(entries) = fs::read_dir(log_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("summary") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    if let Ok(gen_num) = stem.parse::<u64>() {
                        // SummaryReader::open panics outright on a checksum mismatch
                        // (proven corruption - see its doc comment), so an Err reaching
                        // here only ever means "not a valid summary" (bad magic/stale
                        // version, or a stray file) - not corruption, so it's safe to
                        // just skip and fall back to an older summary or full replay.
                        match SummaryReader::open(&path) {
                            Ok(reader) => {
                                if latest_summary.as_ref().map_or(true, |(g, _)| gen_num > *g) {
                                    latest_summary = Some((gen_num, reader));
                                }
                            }
                            Err(e) => {
                                log::warn!("Ignoring unreadable summary {:?}: {}", path, e);
                            }
                        }
                    }
                }
            }
        }
    }

    let mut log_files = Vec::new();
    for entry in fs::read_dir(log_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("log") {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                if let Ok(gen_num) = stem.parse::<u64>() {
                    log_files.push((gen_num, path));
                }
            }
        }
    }

    log_files.sort_by_key(|(gen_num, _)| *gen_num);

    let mut fs_instance = InMemoryFS::with_clock(clock);
    fs_instance.set_log_dir(log_dir);

    // Root (inode 1) is created implicitly, never through a log record, so nothing in
    // replay ever touches its timestamps - `InMemoryFS::with_clock` just stamped it with
    // "now" at this recovery call, which is wrong whenever a summary isn't around to
    // supply the real value (handled below). The oldest surviving log file's FileHeader
    // was written at essentially the same moment the filesystem (and its root) was first
    // created - see `main.rs`, which creates `InMemoryFS::new()` immediately before the
    // generation-1 `LogWriter` - so it's the best available stand-in for root's actual
    // creation time.
    if latest_summary.is_none() {
        if let Some((_, oldest_path)) = log_files.first() {
            if let Ok(oldest_reader) = LogReader::open(oldest_path) {
                let created =
                    crate::clock::unix_to_system_time(oldest_reader.file_header().created_at, 0);
                if let Some(root_arc) = fs_instance.base.read().unwrap().get(&1) {
                    // SAFETY: Single-threaded pre-mount recovery phase; no concurrent LockPool access.
                    let root_node = unsafe { root_arc.write() };
                    if let Node::Directory {
                        atime,
                        mtime,
                        ctime,
                        ..
                    } = root_node
                    {
                        *atime = created;
                        *mtime = created;
                        *ctime = created;
                    }
                }
            }
        }
    }

    let mut min_log_gen = 0u64;
    let mut last_tx_id = 0u64;

    // 2. Fast-recover from summary file if available
    if let Some((summary_gen, mut reader)) = latest_summary {
        log::info!(
            "Fast-recovering appendfs state from summary file (generation: {}, inodes: {}, last_tx_id: {})...",
            summary_gen,
            reader.footer.entry_count,
            reader.header.last_tx_id
        );
        let inodes_map = reader.read_all_inodes()?;
        let next_ino = reader.header.next_inode;
        last_tx_id = reader.header.last_tx_id;

        *fs_instance.base.write().unwrap() = inodes_map;
        fs_instance.next_inode.store(next_ino, Ordering::SeqCst);
        min_log_gen = summary_gen;
    }

    let mut max_inode = fs_instance
        .next_inode
        .load(Ordering::SeqCst)
        .saturating_sub(1);

    // 3. Replay log files with generation > min_log_gen (since min_log_gen is fully snapshot by summary)
    for (gen_num, path) in log_files {
        if gen_num <= min_log_gen && min_log_gen > 0 {
            continue;
        }

        // Records are buffered here until a matching BatchCommit trailer confirms the
        // whole run is complete and safe to apply. LogWriter never rolls mid-batch (see
        // LogWriter::roll_if_needed), so a batch can never span two generation files -
        // this buffer is reset fresh per file, nothing needs to carry across the outer
        // loop. A non-empty `pending` left over at end-of-file means the writer crashed
        // partway through a flush: that trailing, uncommitted run is discarded below
        // rather than partially applied.
        let mut pending: Vec<LogRecord> = Vec::new();

        let reader = LogReader::open(&path)?;
        for record_res in reader {
            let record = match record_res {
                Ok(r) => r,
                Err(e) => {
                    // Gracefully stop replay on power-loss file truncation
                    if e.kind() == io::ErrorKind::UnexpectedEof {
                        break;
                    }
                    return Err(e);
                }
            };

            let header = record.header;
            if header.tx_id > last_tx_id {
                last_tx_id = header.tx_id;
            }
            let target_ino = header.inode;
            if target_ino > max_inode {
                max_inode = target_ino;
            }

            if header.op_code == OpCode::BatchCommit {
                let commit =
                    bincode::deserialize::<BatchCommitPayload>(&record.payload).map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "malformed BatchCommit payload in generation {}: {}",
                                gen_num, e
                            ),
                        )
                    })?;

                // Every individual record's own checksum already passed (LogReader
                // verifies that before yielding it) by the time we get here, so the
                // only way record_count can disagree with what was actually buffered
                // is a bug in the writer, not bitrot - fail hard rather than silently
                // dropping a batch that might otherwise be entirely valid.
                if commit.record_count as usize != pending.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "BatchCommit record_count mismatch in generation {}: claimed {} but buffered {}",
                            gen_num,
                            commit.record_count,
                            pending.len()
                        ),
                    ));
                }

                for buffered in pending.drain(..) {
                    apply_record(&fs_instance, gen_num, &buffered);
                }
            } else {
                pending.push(record);
            }
        }

        if !pending.is_empty() {
            log::warn!(
                "Discarding {} uncommitted record(s) at end of generation {} (crash mid-flush)",
                pending.len(),
                gen_num
            );
        }
    }

    if max_inode >= fs_instance.next_inode.load(Ordering::SeqCst) {
        fs_instance
            .next_inode
            .store(max_inode + 1, Ordering::SeqCst);
    }
    fs_instance.base.write().unwrap().retain(|_ino, arc| {
        // SAFETY: Single-threaded post-recovery cleanup; no concurrent LockPool access.
        let node = unsafe { arc.read() };
        match node {
            Node::File { nlink, .. } | Node::Symlink { nlink, .. } => *nlink > 0,
            Node::Directory { .. } => true,
        }
    });
    fs_instance.last_tx_id.store(last_tx_id, Ordering::SeqCst);

    Ok(fs_instance)
}

/// Applies one already-committed log record to `fs_instance`'s in-memory state. Only
/// ever called for records that were confirmed complete by a matching `BatchCommit` -
/// see `recover_fs`.
fn apply_record(fs_instance: &InMemoryFS, gen_num: u64, record: &LogRecord) {
    let header = &record.header;
    let target_ino = header.inode;

    match header.op_code {
        OpCode::Create => {
            if let Ok(create) = bincode::deserialize::<CreatePayload>(&record.payload) {
                let now =
                    crate::clock::unix_to_system_time(create.created_at.0, create.created_at.1);
                let new_node = Arc::new(SyncNode::new(Node::File {
                    range_map: RangeMap::new(),
                    size: 0,
                    perm: create.mode & 0o777,
                    nlink: 1,
                    uid: create.uid,
                    gid: create.gid,
                    atime: now,
                    mtime: now,
                    ctime: now,
                }));

                let mut map = fs_instance.base.write().unwrap();
                map.insert(target_ino, new_node);

                if let Some(parent_node_arc) = map.get(&create.parent) {
                    // SAFETY: Single-threaded pre-mount recovery phase; no concurrent LockPool access.
                    let parent_node = unsafe { parent_node_arc.write() };
                    if let Node::Directory {
                        entries,
                        mtime,
                        ctime,
                        ..
                    } = parent_node
                    {
                        entries.push((create.name, target_ino));
                        *mtime = now;
                        *ctime = now;
                    }
                }
            }
        }
        OpCode::Mkdir => {
            if let Ok(mkdir) = bincode::deserialize::<MkdirPayload>(&record.payload) {
                let now = crate::clock::unix_to_system_time(mkdir.created_at.0, mkdir.created_at.1);
                let new_node = Arc::new(SyncNode::new(Node::Directory {
                    parent: mkdir.parent,
                    entries: Vec::new(),
                    perm: mkdir.mode & 0o777,
                    nlink: 2,
                    uid: mkdir.uid,
                    gid: mkdir.gid,
                    atime: now,
                    mtime: now,
                    ctime: now,
                }));

                let mut map = fs_instance.base.write().unwrap();
                map.insert(target_ino, new_node);

                if let Some(parent_node_arc) = map.get(&mkdir.parent) {
                    let parent_node = unsafe { parent_node_arc.write() };
                    if let Node::Directory {
                        entries,
                        mtime,
                        ctime,
                        ..
                    } = parent_node
                    {
                        entries.push((mkdir.name, target_ino));
                        *mtime = now;
                        *ctime = now;
                    }
                }
            }
        }
        OpCode::Write => {
            if let Ok(write_meta) = bincode::deserialize::<WriteMeta>(&record.payload) {
                let meta_bytes = bincode::serialize(&write_meta).unwrap();
                let meta_size = meta_bytes.len() as u32;
                let payload_len = record.payload.len() as u32;
                let write_data_len = payload_len - meta_size;

                let shared_state = SharedExtentState::new_disk(
                    gen_num,
                    record.record_log_offset,
                    meta_size,
                    write_data_len,
                );

                let map = fs_instance.base.read().unwrap();
                if let Some(node_arc) = map.get(&target_ino) {
                    let node = unsafe { node_arc.write() };
                    if let Node::File {
                        range_map,
                        size,
                        mtime,
                        ctime,
                        ..
                    } = node
                    {
                        let end_offset = write_meta.file_offset + write_data_len as u64;
                        if end_offset > *size {
                            *size = end_offset;
                        }
                        let now = crate::clock::unix_to_system_time(
                            write_meta.op_time.0,
                            write_meta.op_time.1,
                        );
                        *mtime = now;
                        *ctime = now;
                        range_map.insert(
                            write_meta.file_offset,
                            write_data_len as u64,
                            shared_state,
                        );
                    }
                }
            }
        }
        OpCode::Unlink => {
            if let Ok(unlink) = bincode::deserialize::<UnlinkPayload>(&record.payload) {
                let now = crate::clock::unix_to_system_time(unlink.op_time.0, unlink.op_time.1);
                let mut map = fs_instance.base.write().unwrap();
                if let Some(parent_node_arc) = map.get(&unlink.parent) {
                    // SAFETY: Single-threaded pre-mount recovery phase; no concurrent LockPool access.
                    let parent_node = unsafe { parent_node_arc.write() };
                    if let Node::Directory {
                        entries,
                        mtime,
                        ctime,
                        ..
                    } = parent_node
                    {
                        entries.retain(|(name, ino)| !(name == &unlink.name && *ino == target_ino));
                        *mtime = now;
                        *ctime = now;
                    }
                }

                let mut should_delete = false;
                if let Some(child_node_arc) = map.get(&target_ino) {
                    // SAFETY: Single-threaded pre-mount recovery phase; no concurrent LockPool access.
                    let child_node = unsafe { child_node_arc.write() };
                    match child_node {
                        Node::File { nlink, ctime, .. } | Node::Symlink { nlink, ctime, .. } => {
                            if *nlink > 0 {
                                *nlink -= 1;
                                *ctime = now;
                            }
                            if *nlink == 0 {
                                should_delete = true;
                            }
                        }
                        // Directories carry a fixed nlink=2 for life (see mkdir_core)
                        // and can't be hardlinked, so live's unlink_core rejects them
                        // with EISDIR before ever staging an Unlink record - this arm
                        // only exists for defensiveness against pre-fix logs.
                        Node::Directory { .. } => {
                            should_delete = true;
                        }
                    }
                }
                if should_delete {
                    map.remove(&target_ino);
                }
            }
        }
        OpCode::Rmdir => {
            if let Ok(rmdir) = bincode::deserialize::<RmdirPayload>(&record.payload) {
                let now = crate::clock::unix_to_system_time(rmdir.op_time.0, rmdir.op_time.1);
                let mut map = fs_instance.base.write().unwrap();
                if let Some(parent_node_arc) = map.get(&rmdir.parent) {
                    // SAFETY: Single-threaded pre-mount recovery phase; no concurrent LockPool access.
                    let parent_node = unsafe { parent_node_arc.write() };
                    if let Node::Directory {
                        entries,
                        mtime,
                        ctime,
                        ..
                    } = parent_node
                    {
                        entries.retain(|(name, ino)| !(name == &rmdir.name && *ino == target_ino));
                        *mtime = now;
                        *ctime = now;
                    }
                }
                map.remove(&target_ino);
            }
        }
        OpCode::Symlink => {
            if let Ok(symlink) = bincode::deserialize::<SymlinkPayload>(&record.payload) {
                let now =
                    crate::clock::unix_to_system_time(symlink.created_at.0, symlink.created_at.1);
                let new_node = Arc::new(SyncNode::new(Node::Symlink {
                    target: symlink.target,
                    nlink: 1,
                    uid: symlink.uid,
                    gid: symlink.gid,
                    atime: now,
                    mtime: now,
                    ctime: now,
                }));

                let mut map = fs_instance.base.write().unwrap();
                map.insert(target_ino, new_node);

                if let Some(parent_node_arc) = map.get(&symlink.parent) {
                    // SAFETY: Single-threaded pre-mount recovery phase; no concurrent LockPool access.
                    let parent_node = unsafe { parent_node_arc.write() };
                    if let Node::Directory {
                        entries,
                        mtime,
                        ctime,
                        ..
                    } = parent_node
                    {
                        entries.push((symlink.name, target_ino));
                        *mtime = now;
                        *ctime = now;
                    }
                }
            }
        }
        OpCode::Rename => {
            if let Ok(rename) = bincode::deserialize::<RenamePayload>(&record.payload) {
                let now = crate::clock::unix_to_system_time(rename.op_time.0, rename.op_time.1);
                let mut map = fs_instance.base.write().unwrap();

                // Live's rename_core treats same-parent renames differently from
                // cross-parent ones: same-parent does an in-place rename of the
                // existing Vec entry (preserving its position - a self-rename to the
                // same name is the only case that skips logging entirely, so replay
                // never has to special-case it here), while cross-parent always
                // removes from the source Vec and pushes onto the destination Vec.
                // Replaying both cases as an unconditional remove-then-push (as this
                // used to do) reaches the same *set* of directory entries either way,
                // but silently reorders same-parent-renamed entries within their Vec -
                // invisible to comparisons that sort entries first, but a real
                // divergence from live, and the reason two logically-identical
                // filesystems could still export non-byte-identical .summary files.
                let overwritten_ino = if rename.parent == rename.new_parent {
                    let mut overwritten = None;
                    if let Some(parent_node_arc) = map.get(&rename.parent) {
                        // SAFETY: Single-threaded pre-mount recovery phase; no concurrent LockPool access.
                        let parent_node = unsafe { parent_node_arc.write() };
                        if let Node::Directory {
                            entries,
                            mtime,
                            ctime,
                            ..
                        } = parent_node
                        {
                            if let Some(dest_pos) =
                                entries.iter().position(|(n, ino)| n == &rename.new_name && *ino != target_ino)
                            {
                                overwritten = Some(entries.remove(dest_pos).1);
                            }
                            if let Some(src_pos) =
                                entries.iter().position(|(n, ino)| n == &rename.name && *ino == target_ino)
                            {
                                entries[src_pos].0 = rename.new_name.clone();
                            }
                            *mtime = now;
                            *ctime = now;
                        }
                    }
                    overwritten
                } else {
                    // Remove source entry
                    if let Some(parent_node_arc) = map.get(&rename.parent) {
                        // SAFETY: Single-threaded pre-mount recovery phase; no concurrent LockPool access.
                        let parent_node = unsafe { parent_node_arc.write() };
                        if let Node::Directory {
                            entries,
                            mtime,
                            ctime,
                            ..
                        } = parent_node
                        {
                            entries.retain(|(name, ino)| !(name == &rename.name && *ino == target_ino));
                            *mtime = now;
                            *ctime = now;
                        }
                    }

                    // Add new entry, capturing any destination inode it clobbers
                    if let Some(newparent_node_arc) = map.get(&rename.new_parent) {
                        // SAFETY: Single-threaded pre-mount recovery phase; no concurrent LockPool access.
                        let newparent_node = unsafe { newparent_node_arc.write() };
                        if let Node::Directory {
                            entries,
                            mtime,
                            ctime,
                            ..
                        } = newparent_node
                        {
                            let overwritten = entries
                                .iter()
                                .position(|(name, ino)| name == &rename.new_name && *ino != target_ino)
                                .map(|pos| entries.remove(pos).1);
                            entries.push((rename.new_name.clone(), target_ino));
                            *mtime = now;
                            *ctime = now;
                            overwritten
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                };

                if rename.parent != rename.new_parent {
                    if let Some(target_node_arc) = map.get(&target_ino) {
                        let target_node = unsafe { target_node_arc.write() };
                        if let Node::Directory { parent, .. } = target_node {
                            *parent = rename.new_parent;
                        }
                    }
                }

                // Mirror live rename's overwrite semantics: the clobbered destination
                // inode loses a link and is reclaimed once its nlink reaches zero.
                // Without this, replayed renames-that-overwrite leak the old inode.
                if let Some(dest_ino) = overwritten_ino {
                    if dest_ino != target_ino {
                        let mut should_delete = false;
                        if let Some(dest_node_arc) = map.get(&dest_ino) {
                            // SAFETY: Single-threaded pre-mount recovery phase; no concurrent LockPool access.
                            let dest_node = unsafe { dest_node_arc.write() };
                            match dest_node {
                                Node::File { nlink, ctime, .. }
                                | Node::Symlink { nlink, ctime, .. } => {
                                    if *nlink > 0 {
                                        *nlink -= 1;
                                        *ctime = now;
                                    }
                                    if *nlink == 0 {
                                        should_delete = true;
                                    }
                                }
                                // Directories carry a fixed nlink=2 for life (see
                                // mkdir_core) and can't be hardlinked, so the one entry
                                // just overwritten was necessarily their only reference -
                                // mirrors live rename_core's overwrite-reclaim fix.
                                Node::Directory { .. } => {
                                    should_delete = true;
                                }
                            }
                        }
                        if should_delete {
                            map.remove(&dest_ino);
                        }
                    }
                }
            }
        }
        OpCode::Setattr => {
            if let Ok(setattr) = bincode::deserialize::<SetattrPayload>(&record.payload) {
                let map = fs_instance.base.read().unwrap();
                if let Some(node_arc) = map.get(&target_ino) {
                    // SAFETY: Single-threaded pre-mount recovery phase; no concurrent LockPool access.
                    let node = unsafe { node_arc.write() };
                    let now =
                        crate::clock::unix_to_system_time(setattr.op_time.0, setattr.op_time.1);
                    // Mirrors live: ctime only moves when this call actually changed
                    // something, never on a to_set with no applicable bits. (atime from reads never moves ctime).

                    match node {
                        Node::File {
                            range_map,
                            perm,
                            uid,
                            gid,
                            size,
                            atime,
                            mtime,
                            ctime,
                            ..
                        } => {
                            if let Some(m) = setattr.mode {
                                *perm = m;
                            }
                            if let Some(u) = setattr.uid {
                                *uid = u;
                            }
                            if let Some(g) = setattr.gid {
                                *gid = g;
                            }
                            if let Some(s) = setattr.size {
                                // Mirrors the live setattr handler: shrinking must
                                // actually remove/trim range map entries beyond the
                                // new size, or replayed state would diverge from live
                                // (live now trims; replay used to just move the size
                                // marker, same as the bug this whole fix addresses).
                                if s < *size {
                                    range_map.truncate(s);
                                }
                                *size = s;
                                // Mirrors live: a size change touches mtime too, not
                                // just ctime (POSIX truncate semantics) - unlike
                                // mode/uid/gid, which only ever touch ctime.
                                *mtime = now;
                            }
                            if let Some((secs, nsecs)) = setattr.atime {
                                *atime = crate::clock::unix_to_system_time(secs, nsecs);
                            }
                            if let Some((secs, nsecs)) = setattr.mtime {
                                *mtime = crate::clock::unix_to_system_time(secs, nsecs);
                            }
                            *ctime = now;
                        }
                        Node::Directory {
                            perm,
                            uid,
                            gid,
                            atime,
                            mtime,
                            ctime,
                            ..
                        } => {
                            if let Some(m) = setattr.mode {
                                *perm = m;
                            }
                            if let Some(u) = setattr.uid {
                                *uid = u;
                            }
                            if let Some(g) = setattr.gid {
                                *gid = g;
                            }
                            if let Some((secs, nsecs)) = setattr.atime {
                                *atime = crate::clock::unix_to_system_time(secs, nsecs);
                            }
                            if let Some((secs, nsecs)) = setattr.mtime {
                                *mtime = crate::clock::unix_to_system_time(secs, nsecs);
                            }
                            *ctime = now;
                        }
                        Node::Symlink {
                            uid,
                            gid,
                            atime,
                            mtime,
                            ctime,
                            ..
                        } => {
                            if let Some(u) = setattr.uid {
                                *uid = u;
                            }
                            if let Some(g) = setattr.gid {
                                *gid = g;
                            }
                            if let Some((secs, nsecs)) = setattr.atime {
                                *atime = crate::clock::unix_to_system_time(secs, nsecs);
                            }
                            if let Some((secs, nsecs)) = setattr.mtime {
                                *mtime = crate::clock::unix_to_system_time(secs, nsecs);
                            }
                            *ctime = now;
                        }
                    }
                }
            }
        }
        OpCode::Link => {
            if let Ok(link) = bincode::deserialize::<LinkPayload>(&record.payload) {
                let now = crate::clock::unix_to_system_time(link.op_time.0, link.op_time.1);
                let map = fs_instance.base.write().unwrap();
                if let Some(newparent_node_arc) = map.get(&link.new_parent) {
                    // SAFETY: Single-threaded pre-mount recovery phase; no concurrent LockPool access.
                    let newparent_node = unsafe { newparent_node_arc.write() };
                    if let Node::Directory {
                        entries,
                        mtime,
                        ctime,
                        ..
                    } = newparent_node
                    {
                        entries.push((link.new_name, target_ino));
                        *mtime = now;
                        *ctime = now;
                    }
                }

                if let Some(node_arc) = map.get(&target_ino) {
                    // SAFETY: Single-threaded pre-mount recovery phase; no concurrent LockPool access.
                    let node = unsafe { node_arc.write() };
                    match node {
                        Node::File { nlink, ctime, .. } => {
                            *nlink += 1;
                            *ctime = now;
                        }
                        Node::Symlink { nlink, ctime, .. } => {
                            *nlink += 1;
                            *ctime = now;
                        }
                        Node::Directory { nlink, ctime, .. } => {
                            *nlink += 1;
                            *ctime = now;
                        }
                    }
                }
            }
        }
        OpCode::BatchCommit => {
            // Never buffered/applied - recover_fs handles these directly.
        }
    }
}
