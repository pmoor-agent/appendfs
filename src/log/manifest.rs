use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Metadata and physical counters for an individual `.log` generation file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogFileInfo {
    /// Monotonic generation sequence number (e.g. 1 for 000001.log).
    pub generation: u64,
    /// Compaction revision sequence number (0 for original uncompacted roll, 1+ for compacted revisions).
    #[serde(default)]
    pub revision: u32,
    /// Physical filename on disk (e.g. "000001.log" or "000001_r1.log").
    pub filename: String,
    /// Creation timestamp for this log generation.
    #[serde(with = "crate::clock::serde_system_time")]
    pub created_at: SystemTime,
    /// Total number of log records physically written into this file.
    pub record_count: u32,
    /// Total physical file size on disk (bytes).
    pub total_bytes: u64,
    /// Total uncompressed extent payload data bytes written.
    pub total_data_bytes: u64,
    /// Authenticated MD5 digest of the completed, sealed generation log file.
    ///
    /// This is `None` while the log file is actively receiving appends (the active generation),
    /// because checksums and physical size continuously evolve with each write. Once the generation
    /// is sealed (via log roll or size threshold), its final MD5 digest is computed and populated here.
    #[serde(default)]
    pub md5: Option<[u8; 16]>,
}

/// Returns the physical filename for a given log generation (e.g. "000001.log").
pub fn log_filename(generation: u64) -> String {
    log_filename_with_revision(generation, 0)
}

/// Returns the physical filename for a given log generation and revision (e.g. "000001_r2.log").
pub fn log_filename_with_revision(generation: u64, revision: u32) -> String {
    if revision == 0 {
        format!("{:06}.log", generation)
    } else {
        format!("{:06}_r{}.log", generation, revision)
    }
}

/// Parses a `.log` filename into its `(generation, revision)` components.
///
/// Supports both base names (e.g. "000001.log" -> (1, 0)) and revision names
/// (e.g. "000001_r2.log" -> (1, 2)). Returns `None` if the format is unrecognized.
pub fn parse_log_filename(filename: &str) -> Option<(u64, u32)> {
    parse_generation_revision_filename(filename, ".log")
}

/// Parses a `.summary` filename into its `(generation, revision)` components.
///
/// Supports both base names (e.g. "000001.summary" -> (1, 0)) and revision names
/// (e.g. "000001_r2.summary" -> (1, 2)). Returns `None` if the format is unrecognized.
pub fn parse_summary_filename(filename: &str) -> Option<(u64, u32)> {
    parse_generation_revision_filename(filename, ".summary")
}

fn parse_generation_revision_filename(filename: &str, extension: &str) -> Option<(u64, u32)> {
    let name = filename.rsplit('/').next().unwrap_or(filename);
    if !name.ends_with(extension) {
        return None;
    }
    let stem = &name[..name.len() - extension.len()];
    if let Some((gen_str, rev_str)) = stem.split_once("_r") {
        let generation = gen_str.parse::<u64>().ok()?;
        let rev = rev_str.parse::<u32>().ok()?;
        Some((generation, rev))
    } else {
        let generation = stem.parse::<u64>().ok()?;
        Some((generation, 0))
    }
}

impl LogFileInfo {
    pub fn new(generation: u64, created_at: SystemTime, initial_header_size: u64) -> Self {
        Self {
            generation,
            revision: 0,
            filename: log_filename(generation),
            created_at,
            record_count: 0,
            total_bytes: initial_header_size,
            total_data_bytes: 0,
            md5: None,
        }
    }

    pub fn new_with_revision(generation: u64, revision: u32, created_at: SystemTime, initial_header_size: u64) -> Self {
        Self {
            generation,
            revision,
            filename: log_filename_with_revision(generation, revision),
            created_at,
            record_count: 0,
            total_bytes: initial_header_size,
            total_data_bytes: 0,
            md5: None,
        }
    }
}

/// Authoritative manifest of all active log generations and lineage for the filesystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogManifest {
    /// Ordered list of active log files that back the extents in this filesystem state.
    pub logs: Vec<LogFileInfo>,
    /// Next generation sequence number to allocate.
    pub next_generation: u64,
}

impl LogManifest {
    pub fn new_with_time(start_generation: u64, created_at: SystemTime) -> Self {
        let next_generation = start_generation + 1;

        Self {
            logs: vec![LogFileInfo::new(
                start_generation,
                created_at,
                crate::log::record::FILE_HEADER_SIZE as u64,
            )],
            next_generation,
        }
    }

    /// Returns the physical filename for the next log generation (e.g. "000002.log").
    pub fn next_filename(&self) -> String {
        log_filename(self.next_generation)
    }

    /// Appends a new rolled log generation and advances `next_generation`.
    pub fn record_roll(&mut self, next_gen: u64, created_at: SystemTime, initial_header_size: u64) {
        self.record_roll_with_revision(next_gen, 0, created_at, initial_header_size);
    }

    /// Appends a new rolled log generation with an explicit revision and advances `next_generation` if applicable.
    pub fn record_roll_with_revision(
        &mut self,
        next_gen: u64,
        revision: u32,
        created_at: SystemTime,
        initial_header_size: u64,
    ) {
        if self
            .logs
            .iter()
            .any(|l| l.generation == next_gen && l.revision == revision)
        {
            return;
        }
        let entry = LogFileInfo::new_with_revision(next_gen, revision, created_at, initial_header_size);
        self.logs.push(entry);
        if next_gen >= self.next_generation {
            self.next_generation = next_gen + 1;
        }
    }

    /// Sets the MD5 digest for a specific sealed generation.
    pub fn set_generation_md5(&mut self, generation: u64, md5: [u8; 16]) {
        if let Some(entry) = self.get_mut_by_generation(generation) {
            // A generation is sealed once, so a second digest that disagrees means the file
            // changed under us or two sealers raced. Recording it silently would hand the
            // integrity checker a digest matching whichever write landed last.
            debug_assert!(
                entry.md5.is_none_or(|existing| existing == md5),
                "generation {} already sealed with a different md5",
                generation
            );
            if let Some(existing) = entry.md5
                && existing != md5
            {
                {
                    log::error!(
                        "Refusing to overwrite md5 of sealed generation {}: recorded {:x?}, got {:x?}",
                        generation,
                        existing,
                        md5
                    );
                    return;
                }
            }
            entry.md5 = Some(md5);
        }
    }

    /// Finds a mutable reference to a log file entry by generation number.
    pub fn get_mut_by_generation(&mut self, generation: u64) -> Option<&mut LogFileInfo> {
        self.logs.iter_mut().find(|l| l.generation == generation)
    }

    /// Finds a reference to a log file entry by generation number.
    pub fn get_by_generation(&self, generation: u64) -> Option<&LogFileInfo> {
        self.logs.iter().find(|l| l.generation == generation)
    }

    /// Computes and populates MD5 for any sealed log generation whose MD5 is not yet recorded.
    pub fn populate_sealed_md5s(&mut self, storage: &dyn crate::storage::Storage, active_gen: u64) {
        for entry in &mut self.logs {
            if entry.generation < active_gen
                && entry.md5.is_none()
                && storage.exists(&entry.filename)
                && let Ok(digest) = compute_storage_file_md5(storage, &entry.filename)
            {
                entry.md5 = Some(digest);
            }
        }
    }
}

/// Helper to compute MD5 digest of a stored file using streaming reads.
pub fn compute_storage_file_md5(storage: &dyn crate::storage::Storage, name: &str) -> std::io::Result<[u8; 16]> {
    let reader = storage.open_reader(name)?;
    let len = reader.len()?;
    let mut ctx = md5::Context::new();
    let mut offset = 0;
    let mut buf = [0u8; 64 * 1024];
    while offset < len {
        let chunk_len = ((len - offset) as usize).min(buf.len());
        reader.read_exact_at(offset, &mut buf[..chunk_len])?;
        ctx.consume(&buf[..chunk_len]);
        offset += chunk_len as u64;
    }
    Ok(*ctx.compute())
}

/// Dynamically computed live extent statistics for a single log generation.
#[derive(Debug, Clone, PartialEq)]
pub struct GenerationLiveStats {
    pub generation: u64,
    pub filename: String,
    pub record_count: u32,
    pub total_bytes: u64,
    pub total_data_bytes: u64,
    /// Total bytes still actively referenced by live file range maps.
    pub live_bytes: u64,
    /// Total number of active extent fragments referencing this generation.
    pub live_extents: u32,
    /// Ratio of live bytes to total data bytes written (0.0 to 1.0).
    pub live_ratio: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_manifest_creation_and_roll() {
        let mut manifest = LogManifest::new_with_time(1, SystemTime::UNIX_EPOCH);
        assert_eq!(manifest.logs.len(), 1);
        assert_eq!(manifest.logs[0].generation, 1);
        assert_eq!(manifest.logs[0].filename, "000001.log");
        assert_eq!(manifest.next_generation, 2);
        assert_eq!(manifest.next_filename(), "000002.log");

        manifest.record_roll(2, SystemTime::UNIX_EPOCH, crate::log::record::FILE_HEADER_SIZE as u64);
        assert_eq!(manifest.logs.len(), 2);
        assert_eq!(manifest.logs[1].generation, 2);
        assert_eq!(manifest.next_generation, 3);
        assert_eq!(manifest.next_filename(), "000003.log");

        let bytes = crate::wire::serialize(&manifest).unwrap();
        let deserialized: LogManifest = crate::wire::deserialize(&bytes).unwrap();
        assert_eq!(manifest, deserialized);
    }

    #[test]
    fn test_filename_parsing_and_revisions() {
        assert_eq!(log_filename(1), "000001.log");
        assert_eq!(log_filename_with_revision(1, 0), "000001.log");
        assert_eq!(log_filename_with_revision(1, 2), "000001_r2.log");

        assert_eq!(parse_log_filename("000001.log"), Some((1, 0)));
        assert_eq!(parse_log_filename("000001_r2.log"), Some((1, 2)));
        assert_eq!(parse_log_filename("/path/to/000042_r10.log"), Some((42, 10)));
        assert_eq!(parse_log_filename("invalid.log"), None);
        assert_eq!(parse_log_filename("000001.summary"), None);

        assert_eq!(parse_summary_filename("000001.summary"), Some((1, 0)));
        assert_eq!(parse_summary_filename("000001_r3.summary"), Some((1, 3)));
        assert_eq!(parse_summary_filename("/var/data/000100_r1.summary"), Some((100, 1)));
        assert_eq!(parse_summary_filename("000001.log"), None);

        let mut manifest = LogManifest::new_with_time(1, SystemTime::UNIX_EPOCH);
        manifest.record_roll_with_revision(1, 1, SystemTime::UNIX_EPOCH, 32);
        assert_eq!(manifest.logs.len(), 2);
        assert_eq!(manifest.logs[1].generation, 1);
        assert_eq!(manifest.logs[1].revision, 1);
        assert_eq!(manifest.logs[1].filename, "000001_r1.log");
    }
}
