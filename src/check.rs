use crate::crypto::LogFileKey;
use crate::fs::InMemoryFS;
use crate::log::LogFileCache;
use crate::log::extent::ExtentState;
use crate::log::record::{FILE_HEADER_SIZE, FileHeader, OpCode, RECORD_HEADER_SIZE, RecordHeader};
use crate::node::NodeKind;
use crate::sync::OpTag;
use rand::SeedableRng;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt;
use std::path::Path;
use std::sync::Arc;

/// Options controlling filesystem integrity verification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CheckOptions {
    /// Deep verify physical extent payloads and cryptographic checksums in `.log` files.
    pub verify_data: bool,
    /// Percentage of live data to sample and verify (0.0 < percent <= 100.0, default: 100.0).
    pub sample_percent: f64,
    /// Target remotes to verify (empty for local-only, "all", or specific remote names).
    pub remotes: Vec<String>,
    /// Deterministic seed for sampled block selection (if None, derived from manifest).
    pub seed: Option<u64>,
}

impl Default for CheckOptions {
    fn default() -> Self {
        Self {
            verify_data: false,
            sample_percent: 100.0,
            remotes: Vec::new(),
            seed: None,
        }
    }
}

impl CheckOptions {
    /// Creates a metadata-only verification option set (default).
    pub fn metadata_only() -> Self {
        Self::default()
    }

    /// Creates a full data verification option set (100% of live data).
    pub fn full_data() -> Self {
        Self {
            verify_data: true,
            sample_percent: 100.0,
            remotes: Vec::new(),
            seed: None,
        }
    }

    /// Creates a sampled data verification option set with a given percentage (0.0 < percent <= 100.0).
    pub fn sampled(sample_percent: f64, seed: Option<u64>) -> Self {
        Self {
            verify_data: true,
            sample_percent,
            remotes: Vec::new(),
            seed,
        }
    }
}

/// Severity level of an integrity issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IssueLevel {
    Info,
    Warning,
    Error,
}

impl fmt::Display for IssueLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IssueLevel::Info => write!(f, "INFO"),
            IssueLevel::Warning => write!(f, "WARN"),
            IssueLevel::Error => write!(f, "ERROR"),
        }
    }
}

/// An individual integrity inconsistency or violation found during a check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityIssue {
    pub level: IssueLevel,
    pub code: String,
    pub inode: Option<u64>,
    pub message: String,
}

impl IntegrityIssue {
    pub fn error(code: impl Into<String>, inode: Option<u64>, message: impl Into<String>) -> Self {
        Self {
            level: IssueLevel::Error,
            code: code.into(),
            inode,
            message: message.into(),
        }
    }

    pub fn warning(code: impl Into<String>, inode: Option<u64>, message: impl Into<String>) -> Self {
        Self {
            level: IssueLevel::Warning,
            code: code.into(),
            inode,
            message: message.into(),
        }
    }

    pub fn info(code: impl Into<String>, inode: Option<u64>, message: impl Into<String>) -> Self {
        Self {
            level: IssueLevel::Info,
            code: code.into(),
            inode,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IntegrityReport {
    pub total_inodes: usize,
    pub directories: usize,
    pub regular_files: usize,
    pub symlinks: usize,
    pub total_extents: usize,
    pub total_data_bytes: u64,
    pub orphaned_inodes: Vec<u64>,
    pub issues: Vec<IntegrityIssue>,
    pub sampled_records: usize,
    pub sampled_data_bytes: u64,
    pub sampled_blocks: usize,
    pub sample_percent: Option<f64>,
    pub remotes_checked: Vec<String>,
}

impl IntegrityReport {
    /// Returns true if no Error-level issues were found.
    pub fn is_clean(&self) -> bool {
        !self.issues.iter().any(|i| i.level == IssueLevel::Error)
    }

    /// Returns the number of Error-level issues.
    pub fn error_count(&self) -> usize {
        self.issues.iter().filter(|i| i.level == IssueLevel::Error).count()
    }

    /// Returns the number of Warning-level issues.
    pub fn warning_count(&self) -> usize {
        self.issues.iter().filter(|i| i.level == IssueLevel::Warning).count()
    }

    /// Merges another integrity report into this one.
    pub fn merge(&mut self, other: IntegrityReport) {
        if self.total_inodes == 0 {
            self.total_inodes = other.total_inodes;
            self.directories = other.directories;
            self.regular_files = other.regular_files;
            self.symlinks = other.symlinks;
            self.total_extents = other.total_extents;
            self.total_data_bytes = other.total_data_bytes;
        }
        self.orphaned_inodes.extend(other.orphaned_inodes);
        self.issues.extend(other.issues);
        self.sampled_records += other.sampled_records;
        self.sampled_data_bytes += other.sampled_data_bytes;
        self.sampled_blocks += other.sampled_blocks;
        if self.sample_percent.is_none() {
            self.sample_percent = other.sample_percent;
        }
        for r in other.remotes_checked {
            if !self.remotes_checked.contains(&r) {
                self.remotes_checked.push(r);
            }
        }
    }

    /// Formats the report as a clean, human-readable terminal output.
    // TODO(too-many-lines): extract this into smaller units.
    #[allow(clippy::too_many_lines)]
    pub fn format_report(&self, log_dir: Option<&Path>, verbose: bool) -> String {
        let mut out = String::new();
        out.push_str("=================================================================\n");
        out.push_str("               AppendFS Filesystem Integrity Check               \n");
        out.push_str("=================================================================\n\n");

        if let Some(dir) = log_dir {
            out.push_str(&format!("  Log Directory:     {}\n", dir.display()));
        }
        out.push_str(&format!(
            "  Total Inodes:      {} (Directories: {}, Files: {}, Symlinks: {})\n",
            self.total_inodes, self.directories, self.regular_files, self.symlinks
        ));
        out.push_str(&format!("  Total Extents:     {}\n", self.total_extents));
        out.push_str(&format!(
            "  Logical Data Size: {} bytes ({:.2} MiB)\n",
            self.total_data_bytes,
            self.total_data_bytes as f64 / (1024.0 * 1024.0)
        ));
        out.push('\n');

        let errors = self.error_count();
        let warnings = self.warning_count();

        out.push_str("------------------------- Check Summary -------------------------\n");
        if self.orphaned_inodes.is_empty() {
            out.push_str("  [PASS] Inode Reachability (0 orphaned inodes)\n");
        } else {
            out.push_str(&format!(
                "  [FAIL] Inode Reachability ({} orphaned inodes detected)\n",
                self.orphaned_inodes.len()
            ));
        }

        let nlink_issues = self.issues.iter().filter(|i| i.code == "NLINK_MISMATCH").count();
        if nlink_issues == 0 {
            out.push_str("  [PASS] Hardlink Reference Counts (nlink)\n");
        } else {
            out.push_str(&format!(
                "  [FAIL] Hardlink Reference Counts ({} nlink mismatches)\n",
                nlink_issues
            ));
        }

        let hierarchy_issues = self
            .issues
            .iter()
            .filter(|i| {
                i.code == "ROOT_MISSING"
                    || i.code == "ROOT_NOT_DIR"
                    || i.code == "ROOT_INVALID_PARENT"
                    || i.code == "DIR_CYCLE"
                    || i.code == "INVALID_PARENT"
                    || i.code == "DANGLING_ENTRY"
                    || i.code == "DUPLICATE_ENTRY"
                    || i.code == "INVALID_NAME"
            })
            .count();
        if hierarchy_issues == 0 {
            out.push_str("  [PASS] Directory Hierarchy & Tree Acyclicity\n");
        } else {
            out.push_str(&format!(
                "  [FAIL] Directory Hierarchy ({} structural issues)\n",
                hierarchy_issues
            ));
        }

        let extent_issues = self
            .issues
            .iter()
            .filter(|i| {
                i.code.starts_with("EXTENT_")
                    || i.code == "ZERO_LEN_EXTENT"
                    || i.code == "MISSING_LOG_FILE"
                    || i.code == "CORRUPT_LOG_RECORD"
            })
            .count();
        if extent_issues == 0 {
            if let Some(pct) = self.sample_percent {
                out.push_str(&format!(
                    "  [PASS] File Extents & Log Record Consistency ({:.3}% sample, {} records, {:.2} MiB across {} blocks)\n",
                    pct,
                    self.sampled_records,
                    self.sampled_data_bytes as f64 / (1024.0 * 1024.0),
                    self.sampled_blocks
                ));
            } else {
                out.push_str("  [PASS] File Extents & Log Record Consistency\n");
            }
        } else {
            out.push_str(&format!(
                "  [FAIL] File Extents ({} extent/data inconsistencies)\n",
                extent_issues
            ));
        }

        let manifest_issues = self
            .issues
            .iter()
            .filter(|i| i.code.starts_with("MANIFEST_") || i.code == "LOG_SIZE_MISMATCH")
            .count();
        if manifest_issues == 0 {
            out.push_str("  [PASS] Log Manifest & Physical Storage\n");
        } else {
            out.push_str(&format!(
                "  [FAIL] Log Manifest ({} manifest issues)\n",
                manifest_issues
            ));
        }

        if !self.remotes_checked.is_empty() {
            let remote_issues = self.issues.iter().filter(|i| i.code.starts_with("REMOTE_")).count();
            if remote_issues == 0 {
                out.push_str(&format!(
                    "  [PASS] Remote Stores & Manifest Consistency ({})\n",
                    self.remotes_checked.join(", ")
                ));
            } else {
                out.push_str(&format!(
                    "  [FAIL] Remote Stores ({} remote integrity issues across {})\n",
                    remote_issues,
                    self.remotes_checked.join(", ")
                ));
            }
        }

        out.push('\n');

        if !self.issues.is_empty() {
            out.push_str("------------------------- Issues Found --------------------------\n");
            for issue in &self.issues {
                if !verbose && issue.level == IssueLevel::Info {
                    continue;
                }
                let target = match issue.inode {
                    Some(ino) => format!(" (Inode {})", ino),
                    None => String::new(),
                };
                out.push_str(&format!(
                    "  [{}] {}{}: {}\n",
                    issue.level, issue.code, target, issue.message
                ));
            }
            out.push('\n');
        }

        out.push_str("=================================================================\n");
        if self.is_clean() {
            if warnings == 0 {
                out.push_str("  VERDICT: CLEAN - Volume is healthy with 0 errors.\n");
            } else {
                out.push_str(&format!(
                    "  VERDICT: CLEAN WITH WARNINGS (0 errors, {} warning(s)).\n",
                    warnings
                ));
            }
        } else {
            out.push_str(&format!(
                "  VERDICT: CORRUPT - Volume has {} error(s) and {} warning(s).\n",
                errors, warnings
            ));
        }
        out.push_str("=================================================================\n");

        out
    }
}

/// A candidate record from a live file extent for verification.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LiveRecord {
    pub inode: u64,
    pub generation: u32,
    pub record_log_offset: u64,
    pub record_size: u32,
}

/// Pre-flight plan for sampled data verification.
#[derive(Debug, Clone)]
pub struct VerificationPlan {
    pub sample_percent: f64,
    pub seed: u64,
    pub total_live_records: usize,
    pub total_live_bytes: u64,
    pub sampled_records: Vec<LiveRecord>,
    pub sampled_record_bytes: u64,
    /// 1 MiB blocks to fetch locally per generation: generation -> set of block indices.
    pub local_blocks: BTreeMap<u32, BTreeSet<u64>>,
    /// 1 MiB blocks to fetch per remote: remote_name -> (generation -> set of block indices).
    pub remote_blocks: BTreeMap<String, BTreeMap<u32, BTreeSet<u64>>>,
    /// Which target (None = local, Some(remote_name) = remote) is assigned to verify each sampled record.
    pub record_targets: Vec<(LiveRecord, Option<String>)>,
}

impl VerificationPlan {
    pub fn total_remote_egress_bytes(&self, manifest: &crate::log::LogManifest) -> u64 {
        let mut total = 0u64;
        for gen_map in self.remote_blocks.values() {
            for (&generation, blocks) in gen_map {
                let file_len = manifest
                    .get_by_generation(generation)
                    .map(|l| l.total_bytes)
                    .unwrap_or(0);
                for &b in blocks {
                    let start = b * crate::remote::block_cache::BLOCK_SIZE;
                    if start < file_len {
                        total += (file_len - start).min(crate::remote::block_cache::BLOCK_SIZE);
                    }
                }
            }
        }
        total
    }

    pub fn total_remote_requests(&self) -> usize {
        self.remote_blocks
            .values()
            .map(|gen_map| gen_map.values().map(|b| b.len()).sum::<usize>())
            .sum()
    }

    pub fn display_summary(&self, manifest: &crate::log::LogManifest) -> String {
        let mut out = String::new();
        out.push_str("=================================================================\n");
        out.push_str("             AppendFS Sampled Data Verification Plan             \n");
        out.push_str("=================================================================\n");
        out.push_str(&format!(
            "  Sample Rate:         {:.3}% (Seed: 0x{:016x})\n",
            self.sample_percent, self.seed
        ));
        out.push_str(&format!(
            "  Live Records:        {} sampled out of {} (totaling {:.2} MiB)\n",
            self.sampled_records.len(),
            self.total_live_records,
            self.sampled_record_bytes as f64 / (1024.0 * 1024.0)
        ));
        out.push('\n');
        out.push_str("  Planned Read Traffic:\n");

        let mut local_bytes = 0u64;
        let mut local_blocks_count = 0usize;
        for (&generation, blocks) in &self.local_blocks {
            local_blocks_count += blocks.len();
            let file_len = manifest
                .get_by_generation(generation)
                .map(|l| l.total_bytes)
                .unwrap_or(0);
            for &b in blocks {
                let start = b * crate::remote::block_cache::BLOCK_SIZE;
                if start < file_len {
                    local_bytes += (file_len - start).min(crate::remote::block_cache::BLOCK_SIZE);
                }
            }
        }

        if local_blocks_count > 0 || self.remote_blocks.is_empty() {
            out.push_str(&format!(
                "    Local Storage:     {:.2} MiB ({} 1 MiB blocks)\n",
                local_bytes as f64 / (1024.0 * 1024.0),
                local_blocks_count
            ));
        }

        let mut total_remote_bytes = 0u64;
        let mut total_remote_reqs = 0usize;

        for (remote_name, gen_map) in &self.remote_blocks {
            let mut rem_bytes = 0u64;
            let mut rem_reqs = 0usize;
            for (&generation, blocks) in gen_map {
                rem_reqs += blocks.len();
                let file_len = manifest
                    .get_by_generation(generation)
                    .map(|l| l.total_bytes)
                    .unwrap_or(0);
                for &b in blocks {
                    let start = b * crate::remote::block_cache::BLOCK_SIZE;
                    if start < file_len {
                        rem_bytes += (file_len - start).min(crate::remote::block_cache::BLOCK_SIZE);
                    }
                }
            }
            total_remote_bytes += rem_bytes;
            total_remote_reqs += rem_reqs;
            out.push_str(&format!(
                "    Remote '{}':       {:.2} MiB ({} blocks / {} GET requests)\n",
                remote_name,
                rem_bytes as f64 / (1024.0 * 1024.0),
                rem_reqs,
                rem_reqs
            ));
        }

        if !self.remote_blocks.is_empty() {
            out.push_str("    -------------------------------------------------------------\n");
            out.push_str(&format!(
                "    Total Remote Egress: {:.2} MiB across {} GET range requests\n",
                total_remote_bytes as f64 / (1024.0 * 1024.0),
                total_remote_reqs
            ));
        }
        out.push_str("=================================================================\n");
        out
    }
}

/// Builds a deterministic verification plan covering approximately `options.sample_percent`% of
/// data records for each active log generation. Records crossing 1 MiB block boundaries automatically
/// expand the required fetch set to include the full span of blocks needed for complete decryption.
#[allow(clippy::too_many_lines)]
pub fn plan_sampled_verification(fs: &InMemoryFS, options: &CheckOptions) -> VerificationPlan {
    let manifest = fs.manifest.read().unwrap();
    let base_map = fs.inner.lock(OpTag::Stats).unwrap().base.clone();
    let mut unique_records: BTreeMap<(u32, u64), LiveRecord> = BTreeMap::new();

    for (&ino, node_arc) in &base_map {
        if let NodeKind::File { extent_map, .. } = &node_arc.as_ref().kind {
            for (_offset, entry) in extent_map.iter() {
                if let ExtentState::Disk {
                    generation,
                    record_log_offset,
                    record_size,
                    ..
                } = &entry.extent
                {
                    unique_records
                        .entry((*generation, *record_log_offset))
                        .or_insert(LiveRecord {
                            inode: ino,
                            generation: *generation,
                            record_log_offset: *record_log_offset,
                            record_size: *record_size,
                        });
                }
            }
        }
    }

    let mut records_by_gen: BTreeMap<u32, Vec<LiveRecord>> = BTreeMap::new();
    for rec in unique_records.into_values() {
        records_by_gen.entry(rec.generation).or_default().push(rec);
    }
    for records in records_by_gen.values_mut() {
        records.sort_by_key(|r| r.record_log_offset);
    }

    let seed = options.seed.unwrap_or_else(|| {
        let mut hasher = blake3::Hasher::new();
        for log in &manifest.logs {
            hasher.update(&log.generation.to_le_bytes());
            hasher.update(&log.total_bytes.to_le_bytes());
            hasher.update(&log.md5);
        }
        let hash = hasher.finalize();
        u64::from_le_bytes(hash.as_bytes()[..8].try_into().unwrap())
    });

    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

    let mut target_remotes = Vec::new();
    if !options.remotes.is_empty() {
        let reg_opt = fs.remote_registry.read().unwrap().clone();
        if let Some(reg_arc) = reg_opt {
            let reg = reg_arc.read().unwrap();
            if options.remotes.iter().any(|r| r == "all") {
                target_remotes = reg.remotes.keys().cloned().collect();
            } else {
                for r in &options.remotes {
                    if reg.remotes.contains_key(r) {
                        target_remotes.push(r.clone());
                    }
                }
            }
        } else {
            target_remotes = options.remotes.clone();
        }
    }

    let mut sampled_records = Vec::new();
    let mut sampled_record_bytes = 0u64;
    let mut total_live_records = 0usize;
    let mut total_live_bytes = 0u64;

    for (_gen, mut records) in records_by_gen {
        total_live_records += records.len();
        let gen_live_bytes: u64 = records.iter().map(|r| r.record_size as u64).sum();
        total_live_bytes += gen_live_bytes;

        if options.sample_percent >= 100.0 {
            for r in records {
                sampled_record_bytes += r.record_size as u64;
                sampled_records.push(r);
            }
        } else {
            records.shuffle(&mut rng);
            let target = ((gen_live_bytes as f64) * (options.sample_percent / 100.0)).ceil() as u64;
            let target = target.max(1).min(gen_live_bytes);
            let mut accumulated = 0u64;
            for r in records {
                accumulated += r.record_size as u64;
                sampled_record_bytes += r.record_size as u64;
                sampled_records.push(r);
                if accumulated >= target {
                    break;
                }
            }
        }
    }

    sampled_records.sort_by_key(|r| (r.generation, r.record_log_offset));

    const BLOCK_SIZE: u64 = crate::remote::block_cache::BLOCK_SIZE;
    let mut local_blocks: BTreeMap<u32, BTreeSet<u64>> = BTreeMap::new();
    let mut remote_blocks: BTreeMap<String, BTreeMap<u32, BTreeSet<u64>>> = BTreeMap::new();
    let mut record_targets = Vec::new();

    for (idx, record) in sampled_records.iter().enumerate() {
        let target_remote = if target_remotes.is_empty() {
            None
        } else {
            Some(target_remotes[idx % target_remotes.len()].clone())
        };

        let start_blk = record.record_log_offset / BLOCK_SIZE;
        let end_blk = (record.record_log_offset + record.record_size as u64 - 1) / BLOCK_SIZE;

        match &target_remote {
            None => {
                let set = local_blocks.entry(record.generation).or_default();
                for blk in start_blk..=end_blk {
                    set.insert(blk);
                }
            }
            Some(remote_name) => {
                let gen_map = remote_blocks.entry(remote_name.clone()).or_default();
                let set = gen_map.entry(record.generation).or_default();
                for blk in start_blk..=end_blk {
                    set.insert(blk);
                }
            }
        }

        record_targets.push((record.clone(), target_remote));
    }

    VerificationPlan {
        sample_percent: options.sample_percent,
        seed,
        total_live_records,
        total_live_bytes,
        sampled_records,
        sampled_record_bytes,
        local_blocks,
        remote_blocks,
        record_targets,
    }
}

/// Executes data verification for the sampled records in `plan`.
#[allow(clippy::too_many_lines)]
pub fn execute_sampled_verification(
    fs: &InMemoryFS,
    plan: &VerificationPlan,
    log_dir: Option<&Path>,
    report: &mut IntegrityReport,
) {
    if plan.sampled_records.is_empty() {
        report.sample_percent = Some(plan.sample_percent);
        return;
    }

    let manifest = fs.manifest.read().unwrap();
    const BLOCK_SIZE: u64 = crate::remote::block_cache::BLOCK_SIZE;

    // 1. Fetch remote blocks if needed
    let mut fetched_remote_blocks: HashMap<(String, u32, u64), Vec<u8>> = HashMap::new();
    let mut remote_file_keys: HashMap<(String, u32), Arc<LogFileKey>> = HashMap::new();

    if !plan.remote_blocks.is_empty() {
        let reg_opt = fs.remote_registry.read().unwrap().clone();
        let registry = if let Some(reg_arc) = reg_opt {
            reg_arc.read().unwrap().clone()
        } else if let Some(dir) = log_dir {
            crate::remote::RemoteRegistry::load_from_storage(&crate::storage::OsStorage::new(dir)).unwrap_or_default()
        } else if let Some(ref cache) = fs.log_cache {
            crate::remote::RemoteRegistry::load_from_storage(cache.storage().as_ref()).unwrap_or_default()
        } else {
            crate::remote::RemoteRegistry::default()
        };

        for (remote_name, gen_map) in &plan.remote_blocks {
            let store = match registry.store_overrides.get(remote_name) {
                Some(s) => s.clone(),
                None => match registry.get_remote(remote_name) {
                    Some(cfg) => cfg.build_store(),
                    None => {
                        report.issues.push(IntegrityIssue::error(
                            "REMOTE_UNKNOWN",
                            None,
                            format!("Remote '{}' is not configured in remotes.toml", remote_name),
                        ));
                        continue;
                    }
                },
            };

            for (&generation, blocks) in gen_map {
                let filename = manifest
                    .get_by_generation(generation)
                    .map(|l| l.filename.clone())
                    .unwrap_or_else(|| crate::log::log_filename(generation));

                // Fetch 42-byte FileHeader to derive LogFileKey
                let mut hdr_bytes = Vec::with_capacity(FILE_HEADER_SIZE);
                if let Err(e) = store.get_object_range(&filename, 0, FILE_HEADER_SIZE as u64, &mut hdr_bytes) {
                    report.issues.push(IntegrityIssue::error(
                        "REMOTE_READ_FAILED",
                        None,
                        format!(
                            "Failed to read header from remote '{}' for {}: {}",
                            remote_name, filename, e
                        ),
                    ));
                    continue;
                }
                let Ok(hdr_array): Result<[u8; FILE_HEADER_SIZE], _> = hdr_bytes.try_into() else {
                    report.issues.push(IntegrityIssue::error(
                        "REMOTE_CORRUPT_HEADER",
                        None,
                        format!("Invalid header length in {} on remote '{}'", filename, remote_name),
                    ));
                    continue;
                };
                let file_header = match FileHeader::from_bytes(&hdr_array) {
                    Ok(h) => h,
                    Err(e) => {
                        report.issues.push(IntegrityIssue::error(
                            "REMOTE_CORRUPT_HEADER",
                            None,
                            format!("Invalid header in {} on remote '{}': {}", filename, remote_name, e),
                        ));
                        continue;
                    }
                };
                let file_key = Arc::new(fs.volume_key.log_file_key(&file_header.key_salt));
                remote_file_keys.insert((remote_name.clone(), generation), file_key);

                // Fetch each block
                let manifest_len = manifest
                    .get_by_generation(generation)
                    .map(|l| l.total_bytes)
                    .or_else(|| {
                        fs.log_writer
                            .as_ref()
                            .filter(|w| w.generation() == generation)
                            .map(|w| w.current_offset())
                    })
                    .unwrap_or(0);
                for &b in blocks {
                    let start_offset = b * BLOCK_SIZE;
                    if start_offset < manifest_len {
                        let len = (manifest_len - start_offset).min(BLOCK_SIZE);
                        let mut block_buf = Vec::with_capacity(len as usize);
                        if let Err(e) = store.get_object_range(&filename, start_offset, len, &mut block_buf) {
                            report.issues.push(IntegrityIssue::error(
                                "REMOTE_READ_FAILED",
                                None,
                                format!(
                                    "Failed to fetch block {} of {} from remote '{}': {}",
                                    b, filename, remote_name, e
                                ),
                            ));
                        } else {
                            fetched_remote_blocks.insert((remote_name.clone(), generation, b), block_buf);
                        }
                    }
                }
            }
        }
    }

    // 2. Open local cache if local blocks exist
    let local_cache = fs
        .log_cache
        .clone()
        .or_else(|| log_dir.map(|d| Arc::new(LogFileCache::new(d))));

    // 3. Verify each record
    let mut verified_count = 0usize;
    let mut verified_bytes = 0u64;

    for (record, target) in &plan.record_targets {
        match target {
            Some(remote_name) => {
                let file_key = match remote_file_keys.get(&(remote_name.clone(), record.generation)) {
                    Some(k) => k,
                    None => continue,
                };
                let mut raw_record = Vec::with_capacity(record.record_size as usize);
                let mut cur_offset = record.record_log_offset;
                let end_offset = record.record_log_offset + record.record_size as u64;
                let mut failed = false;

                while cur_offset < end_offset {
                    let blk = cur_offset / BLOCK_SIZE;
                    let blk_start = blk * BLOCK_SIZE;
                    let offset_in_blk = (cur_offset - blk_start) as usize;
                    match fetched_remote_blocks.get(&(remote_name.clone(), record.generation, blk)) {
                        Some(blk_bytes) => {
                            let avail = blk_bytes.len().saturating_sub(offset_in_blk);
                            let remaining = (end_offset - cur_offset) as usize;
                            let take = avail.min(remaining);
                            if take == 0 {
                                failed = true;
                                break;
                            }
                            raw_record.extend_from_slice(&blk_bytes[offset_in_blk..offset_in_blk + take]);
                            cur_offset += take as u64;
                        }
                        None => {
                            failed = true;
                            break;
                        }
                    }
                }

                if failed || raw_record.len() != record.record_size as usize {
                    report.issues.push(IntegrityIssue::error(
                        "CORRUPT_LOG_RECORD",
                        Some(record.inode),
                        format!(
                            "Record at offset 0x{:x} in generation {} could not be assembled from remote '{}'",
                            record.record_log_offset, record.generation, remote_name
                        ),
                    ));
                    continue;
                }

                let mut hdr_buf = [0u8; RECORD_HEADER_SIZE];
                hdr_buf.copy_from_slice(&raw_record[..RECORD_HEADER_SIZE]);
                match RecordHeader::from_bytes(&hdr_buf) {
                    Err(e) => {
                        report.issues.push(IntegrityIssue::error(
                            "CORRUPT_LOG_RECORD",
                            Some(record.inode),
                            format!(
                                "Invalid record header at offset 0x{:x} in gen {} (remote '{}'): {}",
                                record.record_log_offset, record.generation, remote_name, e
                            ),
                        ));
                    }
                    Ok(rec_header) => {
                        let opcode = rec_header.op_code as u8;
                        if opcode != OpCode::Data as u8 && opcode != OpCode::DataZstd as u8 {
                            report.issues.push(IntegrityIssue::error(
                                "CORRUPT_LOG_RECORD",
                                Some(record.inode),
                                format!(
                                    "Record at offset 0x{:x} in gen {} has unexpected OpCode {}",
                                    record.record_log_offset, record.generation, opcode
                                ),
                            ));
                        } else if rec_header.inode != record.inode {
                            report.issues.push(IntegrityIssue::error(
                                "CORRUPT_LOG_RECORD",
                                Some(record.inode),
                                format!(
                                    "Record at offset 0x{:x} belongs to inode {}, expected {}",
                                    record.record_log_offset, rec_header.inode, record.inode
                                ),
                            ));
                        } else {
                            let payload = &raw_record[RECORD_HEADER_SIZE..];
                            match file_key.decrypt_record(
                                rec_header.sequence,
                                rec_header.op_code as u8,
                                rec_header.inode,
                                payload,
                                &rec_header.auth_tag,
                            ) {
                                Ok(_) => {
                                    verified_count += 1;
                                    verified_bytes += record.record_size as u64;
                                }
                                Err(e) => {
                                    report.issues.push(IntegrityIssue::error(
                                        "CORRUPT_LOG_RECORD",
                                        Some(record.inode),
                                        format!(
                                            "Authentication tag mismatch for record at offset 0x{:x} in gen {} (remote '{}'): {}",
                                            record.record_log_offset, record.generation, remote_name, e
                                        ),
                                    ));
                                }
                            }
                        }
                    }
                }
            }
            None => {
                // Local verification
                if let Some(ref c) = local_cache {
                    let log_filename = manifest
                        .get_by_generation(record.generation)
                        .map(|l| l.filename.clone())
                        .unwrap_or_else(|| crate::log::log_filename(record.generation));
                    if !c.storage().exists(&log_filename) {
                        report.issues.push(IntegrityIssue::error(
                            "MISSING_LOG_FILE",
                            Some(record.inode),
                            format!(
                                "File inode {} extent references generation {} ('{}'), which does not exist in storage",
                                record.inode, record.generation, log_filename
                            ),
                        ));
                        continue;
                    }

                    match c.storage().file_len(&log_filename) {
                        Ok(file_len) => {
                            if file_len < record.record_log_offset + record.record_size as u64 {
                                report.issues.push(IntegrityIssue::error(
                                    "EXTENT_PAST_LOG_EOF",
                                    Some(record.inode),
                                    format!(
                                        "File inode {} record at offset 0x{:x} in {} declares {} bytes, which runs past {} byte file",
                                        record.inode, record.record_log_offset, log_filename, record.record_size, file_len
                                    ),
                                ));
                                continue;
                            }
                        }
                        Err(e) => {
                            report.issues.push(IntegrityIssue::error(
                                "LOG_FILE_READ_ERROR",
                                Some(record.inode),
                                format!("Failed to read file size for {}: {}", log_filename, e),
                            ));
                            continue;
                        }
                    }

                    match c.get_or_open(record.generation, &fs.volume_key) {
                        Ok(open) => {
                            let mut raw_record = vec![0u8; record.record_size as usize];
                            if let Err(e) = open.reader.read_exact_at(record.record_log_offset, &mut raw_record) {
                                report.issues.push(IntegrityIssue::error(
                                    "CORRUPT_LOG_RECORD",
                                    Some(record.inode),
                                    format!(
                                        "Failed to read record at offset 0x{:x} in {}: {}",
                                        record.record_log_offset, log_filename, e
                                    ),
                                ));
                            } else {
                                let mut hdr_buf = [0u8; RECORD_HEADER_SIZE];
                                hdr_buf.copy_from_slice(&raw_record[..RECORD_HEADER_SIZE]);
                                match RecordHeader::from_bytes(&hdr_buf) {
                                    Err(e) => {
                                        report.issues.push(IntegrityIssue::error(
                                            "CORRUPT_LOG_RECORD",
                                            Some(record.inode),
                                            format!(
                                                "Invalid record header at offset 0x{:x} in {}: {}",
                                                record.record_log_offset, log_filename, e
                                            ),
                                        ));
                                    }
                                    Ok(rec_header) => {
                                        let opcode = rec_header.op_code as u8;
                                        if opcode != OpCode::Data as u8 && opcode != OpCode::DataZstd as u8 {
                                            report.issues.push(IntegrityIssue::error(
                                                "CORRUPT_LOG_RECORD",
                                                Some(record.inode),
                                                format!(
                                                    "Record at offset 0x{:x} in {} has OpCode {} instead of OpCode::Data / OpCode::DataZstd",
                                                    record.record_log_offset, log_filename, opcode
                                                ),
                                            ));
                                        } else if rec_header.inode != record.inode {
                                            report.issues.push(IntegrityIssue::error(
                                                "CORRUPT_LOG_RECORD",
                                                Some(record.inode),
                                                format!(
                                                    "Record at offset 0x{:x} in {} belongs to inode {}, expected inode {}",
                                                    record.record_log_offset, log_filename, rec_header.inode, record.inode
                                                ),
                                            ));
                                        } else {
                                            let payload = &raw_record[RECORD_HEADER_SIZE..];
                                            match open.file_key.decrypt_record(
                                                rec_header.sequence,
                                                rec_header.op_code as u8,
                                                rec_header.inode,
                                                payload,
                                                &rec_header.auth_tag,
                                            ) {
                                                Ok(_) => {
                                                    verified_count += 1;
                                                    verified_bytes += record.record_size as u64;
                                                }
                                                Err(e) => {
                                                    report.issues.push(IntegrityIssue::error(
                                                        "CORRUPT_LOG_RECORD",
                                                        Some(record.inode),
                                                        format!(
                                                            "Authentication tag mismatch for record at offset 0x{:x} in {}: {}",
                                                            record.record_log_offset, log_filename, e
                                                        ),
                                                    ));
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            report.issues.push(IntegrityIssue::error(
                                "LOG_FILE_READ_ERROR",
                                Some(record.inode),
                                format!("Failed to open log file {}: {}", log_filename, e),
                            ));
                        }
                    }
                }
            }
        }
    }

    report.sampled_records += verified_count;
    report.sampled_data_bytes += verified_bytes;
    report.sampled_blocks += plan.local_blocks.values().map(|b| b.len()).sum::<usize>()
        + plan
            .remote_blocks
            .values()
            .map(|m| m.values().map(|b| b.len()).sum::<usize>())
            .sum::<usize>();
    report.sample_percent = Some(plan.sample_percent);
}

/// Runs a read-only filesystem integrity check on the provided `InMemoryFS`.
// TODO(too-many-lines): extract this into smaller units.
#[allow(clippy::too_many_lines)]
pub fn check_fs_integrity(fs: &InMemoryFS, log_dir: Option<&Path>, options: &CheckOptions) -> IntegrityReport {
    let mut report = IntegrityReport::default();

    // 0. Extract manifest and base snapshot
    let manifest = fs.manifest.read().unwrap().clone();

    let base_map = fs.inner.lock(OpTag::Stats).unwrap().base.clone();
    report.total_inodes = base_map.len();

    for (&_ino, node_arc) in base_map.iter() {
        let node = node_arc.as_ref();
        match &node.kind {
            NodeKind::Directory { .. } => report.directories += 1,
            NodeKind::File { extent_map, size, .. } => {
                report.regular_files += 1;
                report.total_extents += extent_map.len();
                report.total_data_bytes += size;
            }
            NodeKind::Symlink { .. } => report.symlinks += 1,
            NodeKind::Fifo | NodeKind::CharDevice { .. } | NodeKind::BlockDevice { .. } | NodeKind::Socket => {}
        }
    }

    // Pass 1: Root Inode & Directory Hierarchy Traversal
    let mut reachable = HashSet::new();
    let mut ref_counts: HashMap<u64, u32> = HashMap::new();
    let mut subdirs_count: HashMap<u64, u32> = HashMap::new();

    let root_opt = base_map.get(&1);
    match root_opt {
        None => {
            report.issues.push(IntegrityIssue::error(
                "ROOT_MISSING",
                Some(1),
                "Root directory (inode 1) is missing from filesystem",
            ));
        }
        Some(root_arc) => {
            let root_node = root_arc.as_ref();
            match &root_node.kind {
                NodeKind::Directory { parent, .. } => {
                    if *parent != 1 {
                        report.issues.push(IntegrityIssue::error(
                            "ROOT_INVALID_PARENT",
                            Some(1),
                            format!("Root inode 1 has parent {}, expected 1", parent),
                        ));
                    }
                    reachable.insert(1);

                    // BFS Directory Traversal
                    let mut queue = VecDeque::new();
                    let mut active_path = HashSet::new();
                    active_path.insert(1);
                    queue.push_back((1u64, active_path));

                    while let Some((curr_dir_ino, current_ancestors)) = queue.pop_front() {
                        let curr_arc = match base_map.get(&curr_dir_ino) {
                            Some(a) => a,
                            None => continue,
                        };
                        let curr_node = curr_arc.as_ref();
                        let entries = match &curr_node.kind {
                            NodeKind::Directory { entries, .. } => entries,
                            _ => continue,
                        };

                        let mut seen_in_dir = HashSet::new();

                        for (name, child_ino) in entries {
                            let child_ino = *child_ino;
                            // Validate entry name
                            if name.is_empty() {
                                report.issues.push(IntegrityIssue::error(
                                    "INVALID_NAME",
                                    Some(curr_dir_ino),
                                    "Directory contains an entry with an empty filename",
                                ));
                            } else if name.len() > 255 {
                                report.issues.push(IntegrityIssue::error(
                                    "NAME_TOO_LONG",
                                    Some(curr_dir_ino),
                                    format!("Directory contains entry '{}' exceeding 255 bytes", name),
                                ));
                            } else if name.contains('/') || name.contains('\0') {
                                report.issues.push(IntegrityIssue::error(
                                    "INVALID_NAME",
                                    Some(curr_dir_ino),
                                    format!("Directory entry '{}' contains illegal characters ('/' or '\\0')", name),
                                ));
                            }

                            if !seen_in_dir.insert(name) {
                                report.issues.push(IntegrityIssue::error(
                                    "DUPLICATE_ENTRY",
                                    Some(curr_dir_ino),
                                    format!(
                                        "Directory inode {} contains duplicate entry name '{}'",
                                        curr_dir_ino, name
                                    ),
                                ));
                            }

                            // Check child existence
                            let child_arc = match base_map.get(&child_ino) {
                                Some(a) => a,
                                None => {
                                    report.issues.push(IntegrityIssue::error(
                                        "DANGLING_ENTRY",
                                        Some(curr_dir_ino),
                                        format!(
                                            "Directory entry '{}' in inode {} points to non-existent inode {}",
                                            name, curr_dir_ino, child_ino
                                        ),
                                    ));
                                    continue;
                                }
                            };

                            *ref_counts.entry(child_ino).or_default() += 1;

                            let child_node = child_arc.as_ref();
                            match &child_node.kind {
                                NodeKind::Directory { parent, .. } => {
                                    if child_ino == 1 {
                                        report.issues.push(IntegrityIssue::error(
                                            "ROOT_IN_SUBDIR",
                                            Some(curr_dir_ino),
                                            format!(
                                                "Directory inode {} contains entry '{}' pointing back to root (inode 1)",
                                                curr_dir_ino, name
                                            ),
                                        ));
                                        continue;
                                    }

                                    if current_ancestors.contains(&child_ino) {
                                        report.issues.push(IntegrityIssue::error(
                                            "DIR_CYCLE",
                                            Some(child_ino),
                                            format!(
                                                "Directory cycle detected: inode {} appears in its own directory ancestry",
                                                child_ino
                                            ),
                                        ));
                                        continue;
                                    }

                                    if *parent != curr_dir_ino {
                                        report.issues.push(IntegrityIssue::error(
                                            "INVALID_PARENT",
                                            Some(child_ino),
                                            format!(
                                                "Directory inode {} has parent field {}, but is contained in directory {}",
                                                child_ino, parent, curr_dir_ino
                                            ),
                                        ));
                                    }

                                    if reachable.contains(&child_ino) {
                                        report.issues.push(IntegrityIssue::error(
                                            "MULTIPLE_DIR_HARDLINKS",
                                            Some(child_ino),
                                            format!(
                                                "Directory inode {} has multiple directory entries pointing to it",
                                                child_ino
                                            ),
                                        ));
                                    }

                                    *subdirs_count.entry(curr_dir_ino).or_default() += 1;
                                    reachable.insert(child_ino);

                                    let mut next_ancestors = current_ancestors.clone();
                                    next_ancestors.insert(child_ino);
                                    queue.push_back((child_ino, next_ancestors));
                                }
                                NodeKind::File { .. }
                                | NodeKind::Symlink { .. }
                                | NodeKind::Fifo
                                | NodeKind::CharDevice { .. }
                                | NodeKind::BlockDevice { .. }
                                | NodeKind::Socket => {
                                    reachable.insert(child_ino);
                                }
                            }
                        }
                    }
                }
                _ => {
                    report.issues.push(IntegrityIssue::error(
                        "ROOT_NOT_DIR",
                        Some(1),
                        "Root inode 1 is not a directory",
                    ));
                }
            }
        }
    }

    // Pass 1.1: Orphan Inode Identification
    for (&ino, node_arc) in base_map.iter() {
        if !reachable.contains(&ino) {
            report.orphaned_inodes.push(ino);
            let node = node_arc.as_ref();
            let type_str = match &node.kind {
                NodeKind::Directory { entries, .. } => {
                    format!("Directory with {} entries", entries.len())
                }
                NodeKind::File { size, .. } => format!("RegularFile with {} bytes", size),
                NodeKind::Symlink { target, .. } => format!("Symlink -> '{}'", target),
                NodeKind::Fifo => "FIFO".to_string(),
                NodeKind::CharDevice { rdev } => format!("CharDevice (rdev=0x{:x})", rdev),
                NodeKind::BlockDevice { rdev } => format!("BlockDevice (rdev=0x{:x})", rdev),
                NodeKind::Socket => "Socket".to_string(),
            };
            report.issues.push(IntegrityIssue::error(
                "ORPHAN_INODE",
                Some(ino),
                format!(
                    "Orphaned inode {} ({}) exists in storage but is not reachable from root",
                    ino, type_str
                ),
            ));
        }
    }
    report.orphaned_inodes.sort();

    // Pass 2: Hardlink (nlink) Validation
    for (&ino, node_arc) in base_map.iter() {
        if !reachable.contains(&ino) {
            continue;
        }
        let node = node_arc.as_ref();
        if node.is_dir() {
            let expected_nlink = 2 + subdirs_count.get(&ino).copied().unwrap_or(0);
            if node.meta.nlink != expected_nlink {
                report.issues.push(IntegrityIssue::error(
                    "NLINK_MISMATCH",
                    Some(ino),
                    format!(
                        "Directory inode {} has nlink {}, expected {} (2 + {} subdirectories)",
                        ino,
                        node.meta.nlink,
                        expected_nlink,
                        subdirs_count.get(&ino).copied().unwrap_or(0)
                    ),
                ));
            }
        } else {
            let expected_nlink = ref_counts.get(&ino).copied().unwrap_or(0);
            if node.meta.nlink != expected_nlink {
                let kind_str = if node.is_file() { "File" } else { "Symlink" };
                report.issues.push(IntegrityIssue::error(
                    "NLINK_MISMATCH",
                    Some(ino),
                    format!(
                        "{} inode {} has nlink {}, expected {} (referenced by {} directory entries)",
                        kind_str, ino, node.meta.nlink, expected_nlink, expected_nlink
                    ),
                ));
            }
        }
    }

    // Pass 3: File Extent & ExtentMap Validation
    let mut active_generations: HashSet<u32> = manifest.logs.iter().map(|l| l.generation).collect();
    if let Some(ref w) = fs.log_writer {
        active_generations.insert(w.generation());
    }
    let cache = fs
        .log_cache
        .clone()
        .or_else(|| log_dir.map(|d| Arc::new(LogFileCache::new(d))));

    for (&ino, node_arc) in base_map.iter() {
        let node = node_arc.as_ref();
        if let NodeKind::File { extent_map, size, .. } = &node.kind {
            for (offset, entry) in extent_map.iter() {
                let file_offset = *offset;
                let extent_len = entry.length();

                if extent_len == 0 {
                    report.issues.push(IntegrityIssue::error(
                        "ZERO_LEN_EXTENT",
                        Some(ino),
                        format!("File inode {} has 0-length extent at offset {}", ino, file_offset),
                    ));
                }

                if file_offset + extent_len > *size {
                    report.issues.push(IntegrityIssue::error(
                        "EXTENT_PAST_EOF",
                        Some(ino),
                        format!(
                            "File inode {} has extent [{}..{}] exceeding file size {}",
                            ino,
                            file_offset,
                            file_offset + extent_len,
                            size
                        ),
                    ));
                }

                // `length` is deliberately ignored: it is the extent's logical size, and the
                // bytes a record occupies on disk are derived from the record header's
                // `payload_len` instead. Treating the logical length as a physical bound is
                // what made healthy compressed volumes look corrupt.
                if let ExtentState::Disk {
                    generation,
                    record_log_offset,
                    record_size,
                    payload_offset: _,
                    length: _,
                } = &entry.extent
                {
                    let generation = *generation;
                    let record_log_offset = *record_log_offset;
                    let record_size = *record_size;
                    if !active_generations.contains(&generation) {
                        report.issues.push(IntegrityIssue::error(
                            "EXTENT_UNKNOWN_GENERATION",
                            Some(ino),
                            format!(
                                "File inode {} extent [{}..{}] references unknown log generation {}",
                                ino,
                                file_offset,
                                file_offset + extent_len,
                                generation
                            ),
                        ));
                    }

                    if (record_size as usize) < RECORD_HEADER_SIZE {
                        report.issues.push(IntegrityIssue::error(
                            "EXTENT_INVALID_RECORD_SIZE",
                            Some(ino),
                            format!(
                                "File inode {} extent record at offset 0x{:x} declares record_size {} bytes, smaller than header size {}",
                                ino, record_log_offset, record_size, RECORD_HEADER_SIZE
                            ),
                        ));
                    }

                    let max_allowed_bytes =
                        manifest
                            .get_by_generation(generation)
                            .map(|l| l.total_bytes)
                            .or_else(|| {
                                fs.log_writer
                                    .as_ref()
                                    .filter(|w| w.generation() == generation)
                                    .map(|w| w.current_offset())
                            });

                    if let Some(max_bytes) = max_allowed_bytes
                        && record_log_offset + record_size as u64 > max_bytes
                    {
                        report.issues.push(IntegrityIssue::error(
                            "EXTENT_PAST_MANIFEST_EOF",
                            Some(ino),
                            format!(
                                "File inode {} extent record [0x{:x}..0x{:x}) in generation {} exceeds total bytes {}",
                                ino,
                                record_log_offset,
                                record_log_offset + record_size as u64,
                                generation,
                                max_bytes
                            ),
                        ));
                    }
                }
            }
        }
    }

    if options.verify_data {
        let plan = plan_sampled_verification(fs, options);
        execute_sampled_verification(fs, &plan, log_dir, &mut report);
    }

    // Pass 4: Manifest & Physical File Consistency
    let mut prev_gen = 0u32;
    for info in &manifest.logs {
        if info.generation == 0 {
            report.issues.push(IntegrityIssue::error(
                "MANIFEST_INVALID_GEN",
                None,
                format!("Log generation in manifest cannot be 0: {}", info.filename),
            ));
        } else if info.generation <= prev_gen {
            report.issues.push(IntegrityIssue::error(
                "MANIFEST_OUT_OF_ORDER",
                None,
                format!(
                    "Log generation {} in manifest is not strictly greater than previous generation {}",
                    info.generation, prev_gen
                ),
            ));
        }
        prev_gen = info.generation;

        if let Some(ref c) = cache
            && c.storage().exists(&info.filename)
            && let Ok(file_len) = c.storage().file_len(&info.filename)
            && file_len < info.total_bytes
        {
            report.issues.push(IntegrityIssue::warning(
                "LOG_SIZE_MISMATCH",
                None,
                format!(
                    "Physical log file '{}' in storage ({} bytes) is smaller than recorded in manifest ({} bytes)",
                    info.filename, file_len, info.total_bytes
                ),
            ));
        }
    }

    report
}

/// Helper function to recover a volume using Storage in read-only mode and run integrity checks.
pub fn check_volume(
    storage: Arc<dyn crate::storage::Storage>,
    options: &CheckOptions,
    volume_key: Arc<crate::crypto::VolumeKey>,
) -> std::io::Result<IntegrityReport> {
    let fs = crate::log::recover_fs(
        storage,
        crate::log::RecoveryTarget::Latest,
        std::sync::Arc::new(crate::clock::SystemClock),
        volume_key,
    )?;
    Ok(check_fs_integrity(&fs, None, options))
}

/// Verifies that objects on a remote store match the authenticated sizes and MD5 digests in the summary manifest.
pub fn check_remote_integrity(
    remote: &dyn crate::remote::RemoteStore,
    remote_name: &str,
    manifest: &crate::log::LogManifest,
) -> IntegrityReport {
    let mut report = IntegrityReport::default();

    // Batch-list all objects from the remote store to compare sizes and ETags (MD5)
    // in O(1) listing requests rather than dispatching individual head_object requests per log.
    let listed_objects: HashMap<String, crate::remote::RemoteObject> = match remote.list_objects("") {
        Ok(objs) => objs.into_iter().map(|o| (o.key.clone(), o)).collect(),
        Err(e) => {
            report.issues.push(IntegrityIssue::error(
                "REMOTE_LIST_FAILED",
                None,
                format!("Failed to list objects on remote '{}': {}", remote_name, e),
            ));
            return report;
        }
    };

    for log_entry in &manifest.logs {
        let expected_md5 = log_entry.md5;

        match listed_objects.get(&log_entry.filename) {
            Some(remote_obj) => {
                if remote_obj.size != log_entry.total_bytes {
                    report.issues.push(IntegrityIssue::error(
                        "REMOTE_SIZE_MISMATCH",
                        None,
                        format!(
                            "Remote '{}' object {} size mismatch: expected {} bytes, found {}",
                            remote_name, log_entry.filename, log_entry.total_bytes, remote_obj.size
                        ),
                    ));
                }
                match remote_obj.etag_md5() {
                    Some(remote_md5) => {
                        if remote_md5 != expected_md5 {
                            report.issues.push(IntegrityIssue::error(
                                "REMOTE_MD5_MISMATCH",
                                None,
                                format!(
                                    "Remote '{}' object {} MD5 mismatch: expected {}, got {}",
                                    remote_name,
                                    log_entry.filename,
                                    hex::encode(expected_md5),
                                    hex::encode(remote_md5)
                                ),
                            ));
                        }
                    }
                    None => {
                        report.issues.push(IntegrityIssue::warning(
                            "REMOTE_ETAG_UNPARSABLE",
                            None,
                            format!(
                                "Remote '{}' object {} has non-standard ETag: {:?}",
                                remote_name, log_entry.filename, remote_obj.etag
                            ),
                        ));
                    }
                }
            }
            None => {
                report.issues.push(IntegrityIssue::error(
                    "REMOTE_OBJECT_MISSING",
                    None,
                    format!("Remote '{}' is missing object {}", remote_name, log_entry.filename),
                ));
            }
        }
    }
    report.remotes_checked.push(remote_name.to_string());
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::SystemClock;
    use crate::crypto::VolumeKey;
    use crate::extent_map::ExtentMap;
    use crate::log::LogWriter;
    use crate::node::{InodeMeta, Node, NodeKind};
    use std::sync::Arc;

    #[test]
    fn test_clean_filesystem_integrity_passes() {
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::MemoryStorage::new());
        crate::init_volume(
            storage.clone(),
            &VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
        )
        .unwrap();

        let mut fs = crate::recover_fs(
            storage.clone(),
            crate::RecoveryTarget::Latest,
            Arc::new(SystemClock),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();
        let clock = Arc::new(SystemClock);
        let writer = Arc::new(
            LogWriter::create(
                storage.clone(),
                1,
                &*clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        fs.log_writer = Some(writer);
        fs.set_storage(storage.clone());

        // Create dir, file, symlink, hardlink
        let d = crate::operations::dir::mkdir_core(&fs, 1, "mydir", 0o755, 1000, 1000).unwrap();
        let f = crate::operations::read_write::create_core(&fs, d.ino, "file.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::write_core(&fs, f.ino, b"hello integrity checker", 0).unwrap();
        let _s = crate::operations::links::symlink_core(&fs, 1, "link_to_file", "mydir/file.txt", 1000, 1000).unwrap();
        let _h = crate::operations::links::link_core(&fs, f.ino, 1, "hardlink.txt").unwrap();

        fs.quiesce().unwrap();

        let report = check_volume(storage, &CheckOptions::full_data(), VolumeKey::plaintext_arc()).unwrap();
        assert!(report.is_clean(), "Report must be clean: {:?}", report.issues);
        assert_eq!(report.error_count(), 0);
        assert_eq!(report.orphaned_inodes.len(), 0);
        assert_eq!(report.directories, 2); // root + mydir
        assert_eq!(report.regular_files, 1);
        assert_eq!(report.symlinks, 1);
        assert_eq!(report.sampled_records, 1);
    }

    #[test]
    fn test_orphan_inode_detection() {
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::MemoryStorage::new());
        crate::init_volume(
            storage.clone(),
            &VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
        )
        .unwrap();

        let fs = crate::recover_fs(
            storage,
            crate::RecoveryTarget::Latest,
            Arc::new(SystemClock),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();
        // Inject an orphan inode 999 not linked into directory tree
        let orphan_ino = 999;
        let orphan_node = Node {
            meta: InodeMeta::new(0o644, 0, 1000, 1000, std::time::SystemTime::UNIX_EPOCH),
            kind: NodeKind::File {
                extent_map: ExtentMap::new(),
                size: 0,
            },
        };
        fs.inner
            .lock_for_tests()
            .unwrap()
            .base
            .insert(orphan_ino, Arc::new(orphan_node));

        let report = check_fs_integrity(&fs, None, &CheckOptions::metadata_only());
        assert!(!report.is_clean());
        assert_eq!(report.orphaned_inodes, vec![999]);
        let orphan_issue = report.issues.iter().find(|i| i.code == "ORPHAN_INODE").unwrap();
        assert_eq!(orphan_issue.inode, Some(999));
    }

    #[test]
    fn test_nlink_mismatch_detection() {
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::MemoryStorage::new());
        crate::init_volume(
            storage.clone(),
            &VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
        )
        .unwrap();

        let mut fs = crate::recover_fs(
            storage.clone(),
            crate::RecoveryTarget::Latest,
            Arc::new(SystemClock),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();
        let clock = Arc::new(SystemClock);
        let writer = Arc::new(
            LogWriter::create(
                storage.clone(),
                1,
                &*clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        fs.log_writer = Some(writer);
        fs.set_storage(storage);

        let f = crate::operations::read_write::create_core(&fs, 1, "test.txt", 0o644, 0, 1000, 1000).unwrap();
        fs.quiesce().unwrap();

        // Corrupt nlink on test.txt in base (set nlink to 5 instead of 1)
        {
            let mut inner = fs.inner.lock_for_tests().unwrap();
            let node_arc = inner.base.get_mut(&f.ino).unwrap();
            let mut node = (**node_arc).clone();
            node.meta.nlink = 5;
            *node_arc = Arc::new(node);
        }

        let report = check_fs_integrity(&fs, None, &CheckOptions::metadata_only());
        assert!(!report.is_clean());
        let issue = report.issues.iter().find(|i| i.code == "NLINK_MISMATCH").unwrap();
        assert_eq!(issue.inode, Some(f.ino));
    }

    #[test]
    fn test_extent_past_eof_detection() {
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::MemoryStorage::new());
        crate::init_volume(
            storage.clone(),
            &VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
        )
        .unwrap();

        let fs = crate::recover_fs(
            storage,
            crate::RecoveryTarget::Latest,
            Arc::new(SystemClock),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();

        // Inject file with extent beyond its size
        let mut rm = crate::extent_map::ExtentMap::new();
        rm.insert(100, crate::extent_map::Extent::new_staged_buffer(vec![0; 50], 0, 50));
        let bad_file = Node {
            meta: InodeMeta::new(0o644, 1, 1000, 1000, std::time::SystemTime::UNIX_EPOCH),
            kind: NodeKind::File {
                extent_map: rm,
                size: 120, // Extent ends at 150 > size 120!
            },
        };
        fs.inner.lock_for_tests().unwrap().base.insert(2, Arc::new(bad_file));
        // Link to root
        {
            let mut inner = fs.inner.lock_for_tests().unwrap();
            let root_arc = inner.base.get_mut(&1).unwrap();
            let mut root = (**root_arc).clone();
            if let NodeKind::Directory { entries, .. } = &mut root.kind {
                entries.push(("bad.txt".to_string(), 2));
            }
            *root_arc = Arc::new(root);
        }

        let report = check_fs_integrity(&fs, None, &CheckOptions::metadata_only());
        assert!(!report.is_clean());
        let issue = report.issues.iter().find(|i| i.code == "EXTENT_PAST_EOF").unwrap();
        assert_eq!(issue.inode, Some(2));
    }

    #[test]
    fn test_extent_past_manifest_eof_zero_io_detection() {
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::MemoryStorage::new());
        crate::init_volume(
            storage.clone(),
            &VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
        )
        .unwrap();

        let mut fs = crate::recover_fs(
            storage.clone(),
            crate::RecoveryTarget::Latest,
            Arc::new(SystemClock),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();
        let clock = Arc::new(SystemClock);
        let writer = Arc::new(
            LogWriter::create(
                storage.clone(),
                1,
                &*clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        fs.log_writer = Some(writer);
        fs.set_storage(storage.clone());

        let f = crate::operations::read_write::create_core(&fs, 1, "test.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::write_core(&fs, f.ino, b"small payload", 0).unwrap();
        fs.quiesce().unwrap();
        fs.export_summary(storage.as_ref()).unwrap();

        // Inject extent pointing past manifest total_bytes in log generation 1
        {
            let mut inner = fs.inner.lock_for_tests().unwrap();
            let node_arc = inner.base.get_mut(&f.ino).unwrap();
            let mut node = (**node_arc).clone();
            if let NodeKind::File { extent_map, size } = &mut node.kind {
                *size = 50_000_000;
                extent_map.insert(
                    0,
                    crate::extent_map::Extent::new_disk(
                        1,
                        999_999_999, // way past manifest total_bytes!
                        4096,
                        0,
                        4096,
                    ),
                );
            }
            *node_arc = Arc::new(node);
        }

        // Even with verify_data = false (pure metadata check), must catch EXTENT_PAST_MANIFEST_EOF
        let report = check_fs_integrity(&fs, None, &CheckOptions::metadata_only());
        assert!(!report.is_clean());
        let issue = report.issues.iter().find(|i| i.code == "EXTENT_PAST_MANIFEST_EOF");
        assert!(
            issue.is_some(),
            "Must report EXTENT_PAST_MANIFEST_EOF: {:?}",
            report.issues
        );
    }

    #[test]
    fn test_extent_invalid_record_size_detection() {
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::MemoryStorage::new());
        crate::init_volume(
            storage.clone(),
            &VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
        )
        .unwrap();

        let mut fs = crate::recover_fs(
            storage.clone(),
            crate::RecoveryTarget::Latest,
            Arc::new(SystemClock),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();
        let clock = Arc::new(SystemClock);
        let writer = Arc::new(
            LogWriter::create(
                storage.clone(),
                1,
                &*clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        fs.log_writer = Some(writer);
        fs.set_storage(storage);

        let f = crate::operations::read_write::create_core(&fs, 1, "test.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::write_core(&fs, f.ino, b"small payload", 0).unwrap();
        fs.quiesce().unwrap();

        // Inject extent with record_size smaller than RECORD_HEADER_SIZE (32 bytes)
        {
            let mut inner = fs.inner.lock_for_tests().unwrap();
            let node_arc = inner.base.get_mut(&f.ino).unwrap();
            let mut node = (**node_arc).clone();
            if let NodeKind::File { extent_map, .. } = &mut node.kind {
                extent_map.insert(
                    0,
                    crate::extent_map::Extent::new_disk(
                        1, 128, 10, // record_size 10 < RECORD_HEADER_SIZE 32!
                        0, 10,
                    ),
                );
            }
            *node_arc = Arc::new(node);
        }

        let report = check_fs_integrity(&fs, None, &CheckOptions::metadata_only());
        assert!(!report.is_clean());
        assert!(report.issues.iter().any(|i| i.code == "EXTENT_INVALID_RECORD_SIZE"));
    }

    #[test]
    fn test_directory_cycle_detection() {
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::MemoryStorage::new());
        crate::init_volume(
            storage.clone(),
            &VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
        )
        .unwrap();

        let fs = crate::recover_fs(
            storage,
            crate::RecoveryTarget::Latest,
            Arc::new(SystemClock),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();

        // Create cycle: /a (ino 2) -> /a/b (ino 3) -> /a/b/a (ino 2)
        let dir_a = Node {
            meta: InodeMeta::new(0o755, 2, 1000, 1000, std::time::SystemTime::UNIX_EPOCH),
            kind: NodeKind::Directory {
                parent: 1,
                entries: vec![("b".to_string(), 3)],
            },
        };
        let dir_b = Node {
            meta: InodeMeta::new(0o755, 2, 1000, 1000, std::time::SystemTime::UNIX_EPOCH),
            kind: NodeKind::Directory {
                parent: 2,
                entries: vec![("cycle_to_a".to_string(), 2)],
            },
        };

        {
            let mut inner = fs.inner.lock_for_tests().unwrap();
            inner.base.insert(2, Arc::new(dir_a));
            inner.base.insert(3, Arc::new(dir_b));
            let root_arc = inner.base.get_mut(&1).unwrap();
            let mut root = (**root_arc).clone();
            if let NodeKind::Directory { entries, .. } = &mut root.kind {
                entries.push(("a".to_string(), 2));
            }
            *root_arc = Arc::new(root);
        }

        let report = check_fs_integrity(&fs, None, &CheckOptions::metadata_only());
        assert!(!report.is_clean());
        let cycle_issue = report.issues.iter().find(|i| i.code == "DIR_CYCLE");
        assert!(cycle_issue.is_some(), "Must report DIR_CYCLE: {:?}", report.issues);
    }

    #[test]
    fn test_dangling_entry_and_invalid_parent_detection() {
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::MemoryStorage::new());
        crate::init_volume(
            storage.clone(),
            &VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
        )
        .unwrap();

        let fs = crate::recover_fs(
            storage,
            crate::RecoveryTarget::Latest,
            Arc::new(SystemClock),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();

        // 1. Root contains dangling entry to ino 404
        // 2. Dir 2 has parent field 999 instead of 1
        let dir_wrong_parent = Node {
            meta: InodeMeta::new(0o755, 2, 1000, 1000, std::time::SystemTime::UNIX_EPOCH),
            kind: NodeKind::Directory {
                parent: 999, // Mismatched parent!
                entries: vec![],
            },
        };

        {
            let mut inner = fs.inner.lock_for_tests().unwrap();
            inner.base.insert(2, Arc::new(dir_wrong_parent));
            let root_arc = inner.base.get_mut(&1).unwrap();
            let mut root = (**root_arc).clone();
            if let NodeKind::Directory { entries, .. } = &mut root.kind {
                entries.push(("dangling".to_string(), 404));
                entries.push(("wrong_parent_dir".to_string(), 2));
            }
            *root_arc = Arc::new(root);
        }

        let report = check_fs_integrity(&fs, None, &CheckOptions::metadata_only());
        assert!(!report.is_clean());
        assert!(report.issues.iter().any(|i| i.code == "DANGLING_ENTRY"));
        assert!(report.issues.iter().any(|i| i.code == "INVALID_PARENT"));
    }

    #[test]
    fn test_corrupt_log_record_checksum_detected() {
        let storage = Arc::new(crate::storage::MemoryStorage::new());
        crate::log::init_volume(
            storage.clone(),
            &VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
        )
        .unwrap();

        let mut fs = crate::log::recover_fs(
            storage.clone(),
            crate::RecoveryTarget::Latest,
            Arc::new(SystemClock),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();
        let clock = Arc::new(SystemClock);
        let writer = Arc::new(
            LogWriter::create(
                storage.clone(),
                1,
                &*clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        fs.log_writer = Some(writer);

        let f = crate::operations::read_write::create_core(&fs, 1, "data.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::write_core(&fs, f.ino, b"original clean payload bytes", 0).unwrap();
        fs.quiesce().unwrap();

        // 1. Initial check must be clean
        let record_offset = {
            let inner = fs.inner.lock_for_tests().unwrap();
            let base = &inner.base;
            let node_arc = base.get(&f.ino).unwrap();
            let node = node_arc.as_ref();
            if let NodeKind::File { extent_map, .. } = &node.kind {
                let entry = extent_map.iter().next().unwrap().1;
                if let ExtentState::Disk { record_log_offset, .. } = &entry.extent {
                    *record_log_offset
                } else {
                    panic!("Expected Disk extent");
                }
            } else {
                panic!("Expected File node");
            }
        };

        // 2. Corrupt a byte in 000001.log inside the Write record payload
        let mut bytes = storage.get_file_bytes("000001.log").unwrap();
        bytes[record_offset as usize + RECORD_HEADER_SIZE + 1] ^= 0xFF;
        storage.insert_file("000001.log", bytes);

        // 3. Re-check: must catch CORRUPT_LOG_RECORD
        let corrupt_report = check_fs_integrity(&fs, None, &CheckOptions::full_data());
        assert!(!corrupt_report.is_clean());
        assert!(corrupt_report.issues.iter().any(|i| i.code == "CORRUPT_LOG_RECORD"));
    }

    #[test]
    fn test_directory_entry_name_too_long_detected() {
        let storage: Arc<dyn crate::storage::Storage> = Arc::new(crate::storage::MemoryStorage::new());
        crate::init_volume(
            storage.clone(),
            &VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
        )
        .unwrap();

        let fs = crate::recover_fs(
            storage,
            crate::RecoveryTarget::Latest,
            Arc::new(SystemClock),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();

        // Inject a directory entry exceeding 255 bytes into root node in base
        let long_name = "x".repeat(256);
        let mut root_node = (*fs.inner.lock_for_tests().unwrap().base.get(&1).unwrap())
            .as_ref()
            .clone();
        if let NodeKind::Directory { entries, .. } = &mut root_node.kind {
            entries.push((long_name, 2));
        }
        let child_node = Node {
            meta: InodeMeta::new(0o644, 1, 1000, 1000, std::time::SystemTime::UNIX_EPOCH),
            kind: NodeKind::File {
                extent_map: ExtentMap::new(),
                size: 0,
            },
        };
        let mut inner = fs.inner.lock_for_tests().unwrap();
        inner.base.insert(1, Arc::new(root_node));
        inner.base.insert(2, Arc::new(child_node));
        drop(inner);

        let report = check_fs_integrity(&fs, None, &CheckOptions::metadata_only());
        assert!(!report.is_clean());
        assert!(report.issues.iter().any(|i| i.code == "NAME_TOO_LONG"));
    }

    #[test]
    fn test_sampled_verification_fractional_percentage() {
        let storage = Arc::new(crate::storage::MemoryStorage::new());
        crate::log::init_volume(
            storage.clone(),
            &VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
        )
        .unwrap();

        let mut fs = crate::log::recover_fs(
            storage.clone(),
            crate::RecoveryTarget::Latest,
            Arc::new(SystemClock),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();
        let clock = Arc::new(SystemClock);
        let writer = Arc::new(
            LogWriter::create(
                storage.clone(),
                1,
                &*clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        fs.log_writer = Some(writer);
        fs.set_storage(storage);

        // Create 20 files with distinct payloads
        for i in 0..20 {
            let name = format!("file_{}.txt", i);
            let f = crate::operations::read_write::create_core(&fs, 1, &name, 0o644, 0, 1000, 1000).unwrap();
            let payload = format!("Payload data for file index {}", i).repeat(100);
            crate::operations::read_write::write_core(&fs, f.ino, payload.as_bytes(), 0).unwrap();
        }
        fs.quiesce().unwrap();

        // 1. Sample at fractional percentage 0.05% with fixed seed
        let opts = CheckOptions::sampled(0.05, Some(42));
        let plan = plan_sampled_verification(&fs, &opts);
        assert!(!plan.sampled_records.is_empty(), "Should sample at least 1 record");
        assert!(plan.sampled_records.len() < 20, "Should sample subset of records");

        let report = check_fs_integrity(&fs, None, &opts);
        assert!(report.is_clean(), "Report must be clean: {:?}", report.issues);
        assert_eq!(report.sampled_records, plan.sampled_records.len());
        assert_eq!(report.sample_percent, Some(0.05));
    }

    #[test]
    fn test_multi_block_boundary_expansion() {
        let storage = Arc::new(crate::storage::MemoryStorage::new());
        crate::log::init_volume(
            storage.clone(),
            &VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
        )
        .unwrap();

        let fs = crate::log::recover_fs(
            storage.clone(),
            crate::RecoveryTarget::Latest,
            Arc::new(SystemClock),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();

        // Manually inject a file whose extent record crosses from block 0 into block 1:
        // offset 1_048_500, record_size = 200 => end_offset = 1_048_699 (crosses 1_048_576)
        let f_ino = 2;
        let mut extent_map = ExtentMap::new();
        extent_map.insert(0, crate::extent_map::Extent::new_disk(1, 1_048_500, 200, 0, 100));
        let file_node = Node {
            meta: InodeMeta::new(0o644, 1, 1000, 1000, std::time::SystemTime::UNIX_EPOCH),
            kind: NodeKind::File { extent_map, size: 100 },
        };

        {
            let mut inner = fs.inner.lock_for_tests().unwrap();
            inner.base.insert(f_ino, Arc::new(file_node));
            let root_arc = inner.base.get_mut(&1).unwrap();
            let mut root = (**root_arc).clone();
            if let NodeKind::Directory { entries, .. } = &mut root.kind {
                entries.push(("spanning.bin".to_string(), f_ino));
            }
            *root_arc = Arc::new(root);
        }

        let opts = CheckOptions::full_data();
        let plan = plan_sampled_verification(&fs, &opts);
        assert_eq!(plan.sampled_records.len(), 1);
        let blocks = plan.local_blocks.get(&1).unwrap();
        // Record at 1_048_500 spanning 200 bytes must require both block 0 and block 1!
        assert!(blocks.contains(&0), "Must require block 0");
        assert!(blocks.contains(&1), "Must require block 1 (boundary expansion)");
    }

    #[test]
    fn test_sampled_verification_remote_stores_and_corruption() {
        use crate::remote::mock::MockRemoteStore;
        use crate::remote::{RemoteMode, RemoteRegistry, RemoteStore, RemoteTargetConfig};

        let storage = Arc::new(crate::storage::MemoryStorage::new());
        crate::log::init_volume(
            storage.clone(),
            &VolumeKey::plaintext(),
            crate::crypto::VolumeHeader::plaintext(),
        )
        .unwrap();

        let mut fs = crate::log::recover_fs(
            storage.clone(),
            crate::RecoveryTarget::Latest,
            Arc::new(SystemClock),
            VolumeKey::plaintext_arc(),
        )
        .unwrap();
        let clock = Arc::new(SystemClock);
        let writer = Arc::new(
            LogWriter::create(
                storage.clone(),
                1,
                &*clock,
                crate::cli::DEFAULT_MAX_LOG_SIZE,
                1,
                VolumeKey::plaintext_arc(),
            )
            .unwrap(),
        );
        fs.log_writer = Some(writer);
        fs.set_storage(storage.clone());

        let f = crate::operations::read_write::create_core(&fs, 1, "cloud_file.txt", 0o644, 0, 1000, 1000).unwrap();
        crate::operations::read_write::write_core(&fs, f.ino, b"cloud data content verification", 0).unwrap();
        fs.quiesce().unwrap();
        fs.export_summary(storage.as_ref()).unwrap();

        // Set up two mock remotes: "backup1" and "backup2"
        let remote1 = Arc::new(MockRemoteStore::new());
        let remote2 = Arc::new(MockRemoteStore::new());

        // Replicate 000001.log and summary to remotes
        let log_bytes = storage.get_file_bytes("000001.log").unwrap();
        remote1
            .put_object(
                "000001.log",
                &mut std::io::Cursor::new(log_bytes.clone()),
                log_bytes.len() as u64,
                None,
            )
            .unwrap();
        remote2
            .put_object(
                "000001.log",
                &mut std::io::Cursor::new(log_bytes.clone()),
                log_bytes.len() as u64,
                None,
            )
            .unwrap();

        let mut registry = RemoteRegistry::default();
        let mut cfg1 = RemoteTargetConfig::new("backup1");
        cfg1.mode = RemoteMode::ReadWrite;
        registry.add_remote("backup1", cfg1);
        registry.set_store_override("backup1", remote1.clone());

        let mut cfg2 = RemoteTargetConfig::new("backup2");
        cfg2.mode = RemoteMode::ReadWrite;
        registry.add_remote("backup2", cfg2);
        registry.set_store_override("backup2", remote2.clone());

        fs.set_remote_registry(Arc::new(std::sync::RwLock::new(registry)));

        // 1. Verification across remotes must pass initially
        let opts = CheckOptions {
            verify_data: true,
            sample_percent: 100.0,
            remotes: vec!["backup1".to_string(), "backup2".to_string()],
            seed: Some(123),
        };
        let clean_report = check_fs_integrity(&fs, None, &opts);
        assert!(clean_report.is_clean(), "Must be clean: {:?}", clean_report.issues);
        assert!(clean_report.sampled_records > 0);

        // 2. Corrupt a byte in 000001.log on backup1
        let mut corrupted_log = log_bytes.clone();
        let rec_offset = FILE_HEADER_SIZE + RECORD_HEADER_SIZE + 2;
        corrupted_log[rec_offset] ^= 0xFF;
        remote1
            .put_object(
                "000001.log",
                &mut std::io::Cursor::new(corrupted_log),
                log_bytes.len() as u64,
                None,
            )
            .unwrap();

        // 3. Verifying against backup1 must detect corruption with remote name
        let opts1 = CheckOptions {
            verify_data: true,
            sample_percent: 100.0,
            remotes: vec!["backup1".to_string()],
            seed: Some(123),
        };
        let corrupt_report = check_fs_integrity(&fs, None, &opts1);
        assert!(!corrupt_report.is_clean());
        let issue = corrupt_report
            .issues
            .iter()
            .find(|i| i.code == "CORRUPT_LOG_RECORD")
            .unwrap();
        assert!(
            issue.message.contains("backup1"),
            "Issue message must mention corrupted remote: {}",
            issue.message
        );
    }
}
