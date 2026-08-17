use crate::clock::{Clock, SystemClock};
use crate::fs::InMemoryFS;
use crate::log::extent::SharedExtentState;
use crate::log::reader::{LogReader, LogRecord};
use crate::log::record::{
    CreatePayload, FlushCommitPayload, LinkPayload, MkdirPayload, OpCode, RenamePayload,
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
use std::time::SystemTime;

/// Target boundary for point-in-time recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryTarget {
    /// Replay all available logs and summaries up to the latest state.
    Latest,
    /// Replay up to and including transaction ID `tx_id`.
    TxId(u64),
    /// Replay up to and including the given wall-clock timestamp.
    Timestamp(std::time::SystemTime),
    /// Replay up to and including log generation `generation`.
    Generation(u64),
}

/// Rebuilds complete in-memory filesystem state from summary files and `.log` files
/// inside `log_dir`, using the real system clock for any timestamp not otherwise
/// carried by the log itself. See `recover_fs_with_clock` for injecting a different
/// clock (e.g. for deterministic tests).
pub fn recover_fs(log_dir: impl AsRef<Path>) -> io::Result<InMemoryFS> {
    recover_fs_to_target_with_clock(log_dir, RecoveryTarget::Latest, Arc::new(SystemClock))
}

/// Same as `recover_fs`, but with an injectable clock instead of always defaulting to
/// `SystemClock` internally.
pub fn recover_fs_with_clock(
    log_dir: impl AsRef<Path>,
    clock: Arc<dyn Clock>,
) -> io::Result<InMemoryFS> {
    recover_fs_to_target_with_clock(log_dir, RecoveryTarget::Latest, clock)
}

/// Rebuilds filesystem state from summary and log files up to the specified `target` point in time.
pub fn recover_fs_to_target(
    log_dir: impl AsRef<Path>,
    target: RecoveryTarget,
) -> io::Result<InMemoryFS> {
    recover_fs_to_target_with_clock(log_dir, target, Arc::new(SystemClock))
}

/// Rebuilds filesystem state up to `target` using an injectable clock.
pub fn recover_fs_to_target_with_clock(
    log_dir: impl AsRef<Path>,
    target: RecoveryTarget,
    clock: Arc<dyn Clock>,
) -> io::Result<InMemoryFS> {
    let log_dir = log_dir.as_ref();
    if !log_dir.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Log directory does not exist",
        ));
    }

    // 1. Scan for eligible single-file .summary snapshots matching the target
    let mut latest_summary: Option<(u64, SummaryReader)> = None;
    if let Ok(entries) = fs::read_dir(log_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("summary") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    if let Ok(gen_num) = stem.parse::<u64>() {
                        match SummaryReader::open(&path) {
                            Ok(reader) => {
                                let eligible = match target {
                                    RecoveryTarget::Latest => true,
                                    RecoveryTarget::TxId(max_tx) => reader.header.last_tx_id <= max_tx,
                                    RecoveryTarget::Timestamp(max_time) => reader.header.created_at <= max_time,
                                    RecoveryTarget::Generation(max_gen) => gen_num <= max_gen,
                                };
                                if eligible {
                                    if latest_summary.as_ref().map_or(true, |(g, _)| gen_num > *g) {
                                        latest_summary = Some((gen_num, reader));
                                    }
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

    let mut last_op_time: Option<SystemTime> = None;
    if latest_summary.is_none() {
        if let Some((_, oldest_path)) = log_files.first() {
            if let Ok(oldest_reader) = LogReader::open(oldest_path) {
                let created = oldest_reader.file_header().created_at;
                last_op_time = Some(created);
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
        last_op_time = Some(reader.header.created_at);

        *fs_instance.base.write().unwrap() = inodes_map;
        *fs_instance.manifest.write().unwrap() = reader.manifest.clone();
        fs_instance.next_inode.store(next_ino, Ordering::SeqCst);
        min_log_gen = summary_gen;
    }

    let mut max_inode = fs_instance
        .next_inode
        .load(Ordering::SeqCst)
        .saturating_sub(1);

    let mut target_cutoff_reached = false;

    // 3. Replay log files with generation > min_log_gen
    for (gen_num, path) in log_files {
        if gen_num <= min_log_gen && min_log_gen > 0 {
            continue;
        }

        if let RecoveryTarget::Generation(max_gen) = target {
            if gen_num > max_gen {
                break;
            }
        }

        let mut pending: Vec<LogRecord> = Vec::new();
        let mut committed_records_count = 0u32;
        let mut log_data_bytes = 0u64;

        let reader = LogReader::open(&path)?;
        let log_created_at = reader.file_header().created_at;
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

            if header.op_code == OpCode::FlushCommit {
                if header.tx_id > last_tx_id {
                    last_tx_id = header.tx_id;
                }

                let commit =
                    bincode::deserialize::<FlushCommitPayload>(&record.payload).map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "malformed FlushCommit payload in generation {}: {}",
                                gen_num, e
                            ),
                        )
                    })?;

                if commit.record_count as usize != pending.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "FlushCommit record_count mismatch in generation {}: claimed {} but buffered {}",
                            gen_num,
                            commit.record_count,
                            pending.len()
                        ),
                    ));
                }

                committed_records_count += commit.record_count + 1;

                for buffered in pending.drain(..) {
                    // Check if this record exceeds point-in-time recovery target
                    match target {
                        RecoveryTarget::TxId(max_tx) => {
                            if buffered.header.tx_id > max_tx {
                                target_cutoff_reached = true;
                                break;
                            }
                        }
                        RecoveryTarget::Timestamp(max_time) => {
                            if let Some(op_time) = record_op_time(&buffered) {
                                if op_time > max_time {
                                    target_cutoff_reached = true;
                                    break;
                                }
                            }
                        }
                        _ => {}
                    }

                    if buffered.header.tx_id > last_tx_id {
                        last_tx_id = buffered.header.tx_id;
                    }
                    let target_ino = buffered.header.inode;
                    if target_ino > max_inode {
                        max_inode = target_ino;
                    }

                    if buffered.header.op_code == OpCode::Write {
                        if let Ok(meta) = bincode::deserialize::<WriteMeta>(&buffered.payload) {
                            let meta_bytes = bincode::serialize(&meta).unwrap_or_default();
                            if buffered.payload.len() > meta_bytes.len() {
                                log_data_bytes +=
                                    (buffered.payload.len() - meta_bytes.len()) as u64;
                            }
                        }
                    }
                    if let Some(op_time) = record_op_time(&buffered) {
                        last_op_time = Some(op_time);
                    }
                    apply_record(&fs_instance, gen_num, &buffered);
                }

                if target_cutoff_reached {
                    break;
                }
            } else {
                pending.push(record);
            }
        }

        if !pending.is_empty() && !target_cutoff_reached {
            log::warn!(
                "Discarding {} uncommitted record(s) at end of generation {} (crash mid-flush)",
                pending.len(),
                gen_num
            );
        }

        let log_file_len = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        {
            let mut manifest = fs_instance.manifest.write().unwrap();
            if manifest.get_by_generation(gen_num).is_none() {
                if manifest.logs.len() == 1 && manifest.logs[0].generation == 1 && min_log_gen == 0 && gen_num == 1 {
                    let entry = &mut manifest.logs[0];
                    entry.created_at = log_created_at;
                    entry.record_count = committed_records_count;
                    entry.total_data_bytes = log_data_bytes;
                    entry.total_bytes = log_file_len;
                } else {
                    manifest.record_roll(
                        gen_num,
                        format!("{:06}.log", gen_num),
                        log_created_at,
                        crate::log::record::FILE_HEADER_SIZE as u64,
                    );
                    if let Some(entry) = manifest.get_mut_by_generation(gen_num) {
                        entry.record_count = committed_records_count;
                        entry.total_data_bytes = log_data_bytes;
                        entry.total_bytes = log_file_len;
                    }
                }
            } else if let Some(entry) = manifest.get_mut_by_generation(gen_num) {
                entry.created_at = log_created_at;
                entry.record_count = committed_records_count;
                entry.total_data_bytes = log_data_bytes;
                entry.total_bytes = log_file_len;
            }
        }

        if target_cutoff_reached {
            break;
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
    fs_instance.set_recovered_time(last_op_time);

    Ok(fs_instance)
}

/// Helper extracting operation timestamp from a deserialized record payload.
fn record_op_time(record: &LogRecord) -> Option<std::time::SystemTime> {
    match record.header.op_code {
        OpCode::Create => bincode::deserialize::<CreatePayload>(&record.payload)
            .ok()
            .map(|p| p.created_at),
        OpCode::Mkdir => bincode::deserialize::<MkdirPayload>(&record.payload)
            .ok()
            .map(|p| p.created_at),
        OpCode::Symlink => bincode::deserialize::<SymlinkPayload>(&record.payload)
            .ok()
            .map(|p| p.created_at),
        OpCode::Link => bincode::deserialize::<LinkPayload>(&record.payload)
            .ok()
            .map(|p| p.op_time),
        OpCode::Unlink => bincode::deserialize::<UnlinkPayload>(&record.payload)
            .ok()
            .map(|p| p.op_time),
        OpCode::Rmdir => bincode::deserialize::<RmdirPayload>(&record.payload)
            .ok()
            .map(|p| p.op_time),
        OpCode::Rename => bincode::deserialize::<RenamePayload>(&record.payload)
            .ok()
            .map(|p| p.op_time),
        OpCode::Setattr => bincode::deserialize::<SetattrPayload>(&record.payload)
            .ok()
            .map(|p| p.op_time),
        OpCode::Write => bincode::deserialize::<WriteMeta>(&record.payload)
            .ok()
            .map(|p| p.op_time),
        OpCode::FlushCommit => bincode::deserialize::<FlushCommitPayload>(&record.payload)
            .ok()
            .map(|p| p.timestamp),
    }
}

/// Applies one already-committed log record to `fs_instance`'s in-memory state. Only
/// ever called for records that were confirmed complete by a matching `FlushCommit` -
/// see `recover_fs`.
fn apply_record(fs_instance: &InMemoryFS, gen_num: u64, record: &LogRecord) {
    let header = &record.header;
    let target_ino = header.inode;

    match header.op_code {
        OpCode::Create => {
            if let Ok(create) = bincode::deserialize::<CreatePayload>(&record.payload) {
                let now = create.created_at;
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
                let now = mkdir.created_at;
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
                        let now = write_meta.op_time;
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
                let now = unlink.op_time;
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
                let now = rmdir.op_time;
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
                let now = symlink.created_at;
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
                let now = rename.op_time;
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
                    let now = setattr.op_time;
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
                            if let Some(t) = setattr.atime {
                                *atime = t;
                            }
                            if let Some(t) = setattr.mtime {
                                *mtime = t;
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
                            if let Some(t) = setattr.atime {
                                *atime = t;
                            }
                            if let Some(t) = setattr.mtime {
                                *mtime = t;
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
                            if let Some(t) = setattr.atime {
                                *atime = t;
                            }
                            if let Some(t) = setattr.mtime {
                                *mtime = t;
                            }
                            *ctime = now;
                        }
                    }
                }
            }
        }
        OpCode::Link => {
            if let Ok(link) = bincode::deserialize::<LinkPayload>(&record.payload) {
                let now = link.op_time;
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
        OpCode::FlushCommit => {
            // Never buffered/applied - recover_fs handles these directly.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::AdvancingClock;
    use crate::log::LogWriter;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn test_recovery_to_specific_tx_id() {
        let dir = tempfile::tempdir().unwrap();
        crate::init_volume(dir.path(), Some("main")).unwrap();

        let mut fs = recover_fs(dir.path()).unwrap();
        let clock = Arc::new(AdvancingClock::new(UNIX_EPOCH + Duration::from_secs(1000)));
        fs.clock = Arc::clone(&clock) as Arc<dyn Clock>;
        let writer = Arc::new(LogWriter::create(dir.path(), 1, &*clock).unwrap());
        fs.log_writer = Some(writer);
        fs.set_log_dir(dir.path());

        // Tx 1: Create dir "step1"
        let d1 = crate::operations::dir::mkdir_core(&fs, 1, "step1", 0o755, 1000, 1000).unwrap();
        fs.sync_log().unwrap();

        // Tx 2: Create file "file1.txt" inside "step1"
        let f1 = crate::operations::read_write::create_core(&fs, d1.ino, "file1.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::write_core(&fs, f1.ino, b"version 1", 0).unwrap();
        fs.sync_log().unwrap();

        // Tx 3: Create file "file2.txt" inside "step1"
        let f2 = crate::operations::read_write::create_core(&fs, d1.ino, "file2.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::write_core(&fs, f2.ino, b"version 2", 0).unwrap();
        fs.sync_log().unwrap();

        // 1. Recover to Latest -> step1, file1.txt, file2.txt all exist
        let fs_latest = recover_fs(dir.path()).unwrap();
        assert!(fs_latest.lookup_child(1, "step1").is_some());
        let d1_ino = fs_latest.lookup_child(1, "step1").unwrap();
        assert!(fs_latest.lookup_child(d1_ino, "file1.txt").is_some());
        assert!(fs_latest.lookup_child(d1_ino, "file2.txt").is_some());

        // 2. Recover to TxId(1) or TxId(4) -> only step1 exists, no file1.txt or file2.txt
        let fs_tx1 = recover_fs_to_target(dir.path(), RecoveryTarget::TxId(1)).unwrap();
        assert!(fs_tx1.lookup_child(1, "step1").is_some());
        let d1_tx1 = fs_tx1.lookup_child(1, "step1").unwrap();
        assert!(fs_tx1.lookup_child(d1_tx1, "file1.txt").is_none());
        assert!(fs_tx1.lookup_child(d1_tx1, "file2.txt").is_none());

        // 3. Recover to TxId(6) -> step1 and file1.txt exist, but not file2.txt
        let fs_tx6 = recover_fs_to_target(dir.path(), RecoveryTarget::TxId(6)).unwrap();
        let d1_tx6 = fs_tx6.lookup_child(1, "step1").unwrap();
        assert!(fs_tx6.lookup_child(d1_tx6, "file1.txt").is_some());
        assert!(fs_tx6.lookup_child(d1_tx6, "file2.txt").is_none());
    }

    #[test]
    fn test_recovery_to_specific_timestamp() {
        let dir = tempfile::tempdir().unwrap();
        crate::init_volume(dir.path(), Some("main")).unwrap();

        let mut fs = recover_fs(dir.path()).unwrap();
        let clock = Arc::new(AdvancingClock::new(UNIX_EPOCH + Duration::from_secs(1000)));
        fs.clock = Arc::clone(&clock) as Arc<dyn Clock>;
        let writer = Arc::new(LogWriter::create(dir.path(), 1, &*clock).unwrap());
        fs.log_writer = Some(writer);
        fs.set_log_dir(dir.path());

        // T = 1000: Create "early_dir"
        crate::operations::dir::mkdir_core(&fs, 1, "early_dir", 0o755, 1000, 1000).unwrap();
        fs.sync_log().unwrap();

        // Advance clock to T = 2000
        clock.advance(Duration::from_secs(1000));
        crate::operations::dir::mkdir_core(&fs, 1, "late_dir", 0o755, 1000, 1000).unwrap();
        fs.sync_log().unwrap();

        // Recover at T = 1500 -> early_dir exists, late_dir does not
        let fs_t1500 = recover_fs_to_target(dir.path(), RecoveryTarget::Timestamp(UNIX_EPOCH + Duration::from_secs(1500))).unwrap();
        assert!(fs_t1500.lookup_child(1, "early_dir").is_some());
        assert!(fs_t1500.lookup_child(1, "late_dir").is_none());

        // Recover at T = 2500 -> both exist
        let fs_t2500 = recover_fs_to_target(dir.path(), RecoveryTarget::Timestamp(UNIX_EPOCH + Duration::from_secs(2500))).unwrap();
        assert!(fs_t2500.lookup_child(1, "early_dir").is_some());
        assert!(fs_t2500.lookup_child(1, "late_dir").is_some());
    }
}
