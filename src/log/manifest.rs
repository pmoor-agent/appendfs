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
    pub md5: [u8; 16],
    /// Whether this log generation was cleanly sealed on rollover or shutdown.
    pub sealed: bool,
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

/// Authoritative manifest of all sealed log generations and lineage for the filesystem.
///
/// The active log generation is managed exclusively by `LogWriter` and is never included in
/// `logs`. Once a generation is sealed (via log roll, idle age, or summary snapshot), it is
/// added to `logs` complete with its authenticated MD5 checksum and final counters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct LogManifest {
    /// Ordered list of sealed log files that back the extents in this filesystem state.
    pub logs: Vec<LogFileInfo>,
}

impl LogManifest {
    pub fn new() -> Self {
        Self { logs: Vec::new() }
    }

    /// Records a sealed log file entry into the manifest.
    ///
    /// Panics if an entry for `(generation, revision)` has already been recorded in the manifest,
    /// or if a generation greater than `log.generation` already exists in the manifest.
    pub fn record_sealed_log(&mut self, log: LogFileInfo) {
        assert!(
            !self
                .logs
                .iter()
                .any(|l| l.generation == log.generation && l.revision == log.revision),
            "generation {} revision {} already recorded in manifest",
            log.generation,
            log.revision
        );
        assert!(
            !self.logs.iter().any(|l| l.generation > log.generation),
            "generation {} cannot be recorded: manifest already contains a greater generation",
            log.generation
        );
        self.logs.push(log);
    }

    /// Finds a reference to a log file entry by generation number.
    pub fn get_by_generation(&self, generation: u64) -> Option<&LogFileInfo> {
        self.logs.iter().find(|l| l.generation == generation)
    }

    /// Returns true if the volume was cleanly unmounted/sealed prior to summary export,
    /// or false if the last recorded log generation was unsealed (indicating an unclean crash recovery).
    pub fn last_shutdown_clean(&self) -> bool {
        self.logs.last().is_none_or(|l| l.sealed)
    }

    /// Returns true if all recorded log generations were cleanly sealed.
    pub fn all_logs_sealed(&self) -> bool {
        self.logs.iter().all(|l| l.sealed)
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
    /// Whether this log generation was cleanly sealed on rollover / shutdown.
    pub sealed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_manifest_creation_and_sealed_records() {
        let mut manifest = LogManifest::new();
        assert_eq!(manifest.logs.len(), 0);

        let log1 = LogFileInfo {
            generation: 1,
            revision: 0,
            filename: "000001.log".to_string(),
            created_at: SystemTime::UNIX_EPOCH,
            record_count: 5,
            total_bytes: 1024,
            total_data_bytes: 512,
            md5: [1u8; 16],
            sealed: true,
        };
        manifest.record_sealed_log(log1);
        assert_eq!(manifest.logs.len(), 1);
        assert_eq!(manifest.logs[0].generation, 1);

        let log2 = LogFileInfo {
            generation: 2,
            revision: 0,
            filename: "000002.log".to_string(),
            created_at: SystemTime::UNIX_EPOCH,
            record_count: 3,
            total_bytes: 2048,
            total_data_bytes: 1024,
            md5: [2u8; 16],
            sealed: true,
        };
        manifest.record_sealed_log(log2);
        assert_eq!(manifest.logs.len(), 2);
        assert_eq!(manifest.logs[1].generation, 2);

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

        let mut manifest = LogManifest::new();
        manifest.record_sealed_log(LogFileInfo {
            generation: 1,
            revision: 1,
            filename: "000001_r1.log".to_string(),
            created_at: SystemTime::UNIX_EPOCH,
            record_count: 1,
            total_bytes: 32,
            total_data_bytes: 0,
            md5: [42u8; 16],
            sealed: true,
        });
        assert_eq!(manifest.logs.len(), 1);
        assert_eq!(manifest.logs[0].generation, 1);
        assert_eq!(manifest.logs[0].revision, 1);
        assert_eq!(manifest.logs[0].filename, "000001_r1.log");
    }

    #[test]
    fn test_last_shutdown_clean_and_all_logs_sealed() {
        let mut manifest = LogManifest::new();
        assert!(manifest.last_shutdown_clean());
        assert!(manifest.all_logs_sealed());

        let log1 = LogFileInfo {
            generation: 1,
            revision: 0,
            filename: "000001.log".to_string(),
            created_at: SystemTime::UNIX_EPOCH,
            record_count: 5,
            total_bytes: 1024,
            total_data_bytes: 512,
            md5: [1u8; 16],
            sealed: true,
        };
        manifest.record_sealed_log(log1);
        assert!(manifest.last_shutdown_clean());
        assert!(manifest.all_logs_sealed());

        // Generation 2 wasn't cleanly sealed (crash)
        let log2 = LogFileInfo {
            generation: 2,
            revision: 0,
            filename: "000002.log".to_string(),
            created_at: SystemTime::UNIX_EPOCH,
            record_count: 2,
            total_bytes: 512,
            total_data_bytes: 256,
            md5: [2u8; 16],
            sealed: false,
        };
        manifest.record_sealed_log(log2);
        assert!(!manifest.last_shutdown_clean());
        assert!(!manifest.all_logs_sealed());

        // Generation 3 was sealed
        let mut manifest2 = LogManifest::new();
        manifest2.record_sealed_log(LogFileInfo {
            generation: 1,
            revision: 0,
            filename: "000001.log".to_string(),
            created_at: SystemTime::UNIX_EPOCH,
            record_count: 1,
            total_bytes: 100,
            total_data_bytes: 50,
            md5: [1u8; 16],
            sealed: false,
        });
        manifest2.record_sealed_log(LogFileInfo {
            generation: 2,
            revision: 0,
            filename: "000002.log".to_string(),
            created_at: SystemTime::UNIX_EPOCH,
            record_count: 1,
            total_bytes: 100,
            total_data_bytes: 50,
            md5: [2u8; 16],
            sealed: true,
        });
        // Last shutdown was clean (log2 was sealed), but not all logs were sealed (log1 wasn't)
        assert!(manifest2.last_shutdown_clean());
        assert!(!manifest2.all_logs_sealed());
    }

    #[test]
    #[should_panic(expected = "generation 1 revision 0 already recorded in manifest")]
    fn test_record_sealed_log_duplicate_panics() {
        let mut manifest = LogManifest::new();
        let log = LogFileInfo {
            generation: 1,
            revision: 0,
            filename: "000001.log".to_string(),
            created_at: SystemTime::UNIX_EPOCH,
            record_count: 5,
            total_bytes: 1024,
            total_data_bytes: 512,
            md5: [1u8; 16],
            sealed: true,
        };
        manifest.record_sealed_log(log.clone());
        manifest.record_sealed_log(log);
    }

    #[test]
    #[should_panic(expected = "manifest already contains a greater generation")]
    fn test_record_sealed_log_out_of_order_panics() {
        let mut manifest = LogManifest::new();
        let log2 = LogFileInfo {
            generation: 2,
            revision: 0,
            filename: "000002.log".to_string(),
            created_at: SystemTime::UNIX_EPOCH,
            record_count: 5,
            total_bytes: 1024,
            total_data_bytes: 512,
            md5: [2u8; 16],
            sealed: true,
        };
        let log1 = LogFileInfo {
            generation: 1,
            revision: 0,
            filename: "000001.log".to_string(),
            created_at: SystemTime::UNIX_EPOCH,
            record_count: 5,
            total_bytes: 1024,
            total_data_bytes: 512,
            md5: [1u8; 16],
            sealed: true,
        };
        manifest.record_sealed_log(log2);
        manifest.record_sealed_log(log1);
    }
}
