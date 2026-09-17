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

/// Authoritative manifest of all sealed log generations and lineage for the filesystem.
///
/// The active log generation is managed exclusively by `LogWriter` and is never included in
/// `logs`. Once a generation is sealed (via log roll, idle age, or summary snapshot), it is
/// added to `logs` complete with its authenticated MD5 checksum and final counters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogManifest {
    /// Ordered list of sealed log files that back the extents in this filesystem state.
    pub logs: Vec<LogFileInfo>,
    /// Next generation sequence number to allocate.
    pub next_generation: u64,
}

impl LogManifest {
    pub fn new(start_generation: u64) -> Self {
        Self {
            logs: Vec::new(),
            next_generation: start_generation,
        }
    }

    pub fn new_with_time(start_generation: u64, _created_at: SystemTime) -> Self {
        Self::new(start_generation)
    }

    /// Returns the physical filename for the next log generation (e.g. "000002.log").
    pub fn next_filename(&self) -> String {
        log_filename(self.next_generation)
    }

    /// Records a sealed log file entry into the manifest and advances `next_generation`.
    pub fn record_sealed_log(&mut self, log: LogFileInfo) {
        debug_assert!(log.md5.is_some(), "sealed log must have an MD5 digest");
        if let Some(existing) = self
            .logs
            .iter_mut()
            .find(|l| l.generation == log.generation && l.revision == log.revision)
        {
            *existing = log;
        } else {
            if log.generation >= self.next_generation {
                self.next_generation = log.generation + 1;
            }
            self.logs.push(log);
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

    /// Ensures and validates that all sealed log entries in the manifest have an authenticated MD5.
    pub fn ensure_sealed_md5s(&self) -> Result<(), String> {
        let missing: Vec<u64> = self
            .logs
            .iter()
            .filter(|l| l.md5.is_none())
            .map(|l| l.generation)
            .collect();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "Sealed log generation(s) missing MD5 checksum in manifest: {:?}",
                missing
            ))
        }
    }
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
    fn test_log_manifest_creation_and_sealed_records() {
        let mut manifest = LogManifest::new(1);
        assert_eq!(manifest.logs.len(), 0);
        assert_eq!(manifest.next_generation, 1);
        assert_eq!(manifest.next_filename(), "000001.log");

        let log1 = LogFileInfo {
            generation: 1,
            revision: 0,
            filename: "000001.log".to_string(),
            created_at: SystemTime::UNIX_EPOCH,
            record_count: 5,
            total_bytes: 1024,
            total_data_bytes: 512,
            md5: Some([1u8; 16]),
        };
        manifest.record_sealed_log(log1);
        assert_eq!(manifest.logs.len(), 1);
        assert_eq!(manifest.logs[0].generation, 1);
        assert_eq!(manifest.next_generation, 2);
        assert_eq!(manifest.next_filename(), "000002.log");

        let log2 = LogFileInfo {
            generation: 2,
            revision: 0,
            filename: "000002.log".to_string(),
            created_at: SystemTime::UNIX_EPOCH,
            record_count: 3,
            total_bytes: 2048,
            total_data_bytes: 1024,
            md5: Some([2u8; 16]),
        };
        manifest.record_sealed_log(log2);
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

        let mut manifest = LogManifest::new(1);
        manifest.record_sealed_log(LogFileInfo {
            generation: 1,
            revision: 1,
            filename: "000001_r1.log".to_string(),
            created_at: SystemTime::UNIX_EPOCH,
            record_count: 1,
            total_bytes: 32,
            total_data_bytes: 0,
            md5: Some([42u8; 16]),
        });
        assert_eq!(manifest.logs.len(), 1);
        assert_eq!(manifest.logs[0].generation, 1);
        assert_eq!(manifest.logs[0].revision, 1);
        assert_eq!(manifest.logs[0].filename, "000001_r1.log");
    }

    #[test]
    fn test_ensure_sealed_md5s() {
        let mut manifest = LogManifest::new(1);
        // Empty manifest has all sealed logs with MD5
        assert!(manifest.ensure_sealed_md5s().is_ok());

        // Add sealed log with MD5
        manifest.record_sealed_log(LogFileInfo {
            generation: 1,
            revision: 0,
            filename: "000001.log".to_string(),
            created_at: SystemTime::UNIX_EPOCH,
            record_count: 10,
            total_bytes: 100,
            total_data_bytes: 50,
            md5: Some([42u8; 16]),
        });
        assert!(manifest.ensure_sealed_md5s().is_ok());

        // Corrupt an entry by clearing MD5
        manifest.logs[0].md5 = None;
        assert!(manifest.ensure_sealed_md5s().is_err());
    }
}
