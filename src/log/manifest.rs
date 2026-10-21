use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Metadata and physical counters for an individual `.log` generation file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogFileInfo {
    /// Version of the log format (e.g. 1).
    pub version: u32,
    /// Monotonic generation sequence number (e.g. 1 for 000001.log).
    pub generation: u32,
    /// Compaction revision sequence number (0 for original uncompacted roll, 1+ for compacted revisions).
    pub revision: u16,
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
    /// Timestamp of the terminal Seal record if cleanly sealed, or None if unsealed/crashed.
    #[serde(with = "crate::clock::serde_system_time_opt")]
    pub sealed_at: Option<SystemTime>,
    /// Key salt from FileHeader used to derive the encryption key for this log file.
    /// `None` for legacy v1 summaries.
    #[serde(default)]
    pub key_salt: Option<[u8; 16]>,
}

/// Legacy format version 1 layout of `LogFileInfo` as serialized in v1 summaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogFileInfoV1 {
    pub version: u32,
    pub generation: u32,
    pub revision: u16,
    pub filename: String,
    #[serde(with = "crate::clock::serde_system_time")]
    pub created_at: SystemTime,
    pub record_count: u32,
    pub total_bytes: u64,
    pub total_data_bytes: u64,
    pub md5: [u8; 16],
    #[serde(with = "crate::clock::serde_system_time_opt")]
    pub sealed_at: Option<SystemTime>,
}

/// Legacy format version 1 layout of `LogManifest` as serialized in v1 summaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogManifestV1 {
    pub logs: Vec<LogFileInfoV1>,
}

impl LogManifestV1 {
    /// Converts a legacy v1 manifest into a v2 manifest, setting `key_salt` to `None`.
    pub fn into_v2(self) -> LogManifest {
        LogManifest {
            logs: self
                .logs
                .into_iter()
                .map(|l| LogFileInfo {
                    version: l.version,
                    generation: l.generation,
                    revision: l.revision,
                    filename: l.filename,
                    created_at: l.created_at,
                    record_count: l.record_count,
                    total_bytes: l.total_bytes,
                    total_data_bytes: l.total_data_bytes,
                    md5: l.md5,
                    sealed_at: l.sealed_at,
                    key_salt: None,
                })
                .collect(),
        }
    }
}

impl LogFileInfo {
    /// Whether this log generation was cleanly sealed on rollover or shutdown.
    pub fn is_sealed(&self) -> bool {
        self.sealed_at.is_some()
    }

    /// Reconstructs the log's `FileHeader` from manifest metadata if `key_salt` is present.
    pub fn file_header(&self) -> Option<crate::log::record::FileHeader> {
        let key_salt = self.key_salt?;
        Some(crate::log::record::FileHeader {
            magic: crate::log::record::FILE_MAGIC,
            version: self.version,
            generation: self.generation,
            revision: self.revision,
            created_at: self.created_at,
            key_salt,
        })
    }

    /// Updates all header-derived fields on this `LogFileInfo` from a `FileHeader`.
    ///
    /// By exhaustively matching every field of `FileHeader` (except `magic`),
    /// this guarantees at compile time that adding new fields to `FileHeader`
    /// requires updating `LogFileInfo` as well.
    pub fn update_from_file_header(&mut self, header: &crate::log::record::FileHeader) {
        let crate::log::record::FileHeader {
            magic: _,
            version,
            generation,
            revision,
            created_at,
            key_salt,
        } = *header;

        self.version = version;
        self.generation = generation;
        self.revision = revision;
        self.created_at = created_at;
        self.key_salt = Some(key_salt);
    }
}

/// Returns the physical filename for a given log generation (e.g. "000001.log").
pub fn log_filename(generation: u32) -> String {
    log_filename_with_revision(generation, 0)
}

/// Returns the physical filename for a given log generation and revision (e.g. "000001_r2.log").
pub fn log_filename_with_revision(generation: u32, revision: u16) -> String {
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
pub fn parse_log_filename(filename: &str) -> Option<(u32, u16)> {
    parse_generation_revision_filename(filename, ".log")
}

/// Parses a `.summary` filename into its `(generation, revision)` components.
///
/// Supports both base names (e.g. "000001.summary" -> (1, 0)) and revision names
/// (e.g. "000001_r2.summary" -> (1, 2)). Returns `None` if the format is unrecognized.
pub fn parse_summary_filename(filename: &str) -> Option<(u32, u16)> {
    parse_generation_revision_filename(filename, ".summary")
}

fn parse_generation_revision_filename(filename: &str, extension: &str) -> Option<(u32, u16)> {
    let name = filename.rsplit('/').next().unwrap_or(filename);
    if !name.ends_with(extension) {
        return None;
    }
    let stem = &name[..name.len() - extension.len()];
    if let Some((gen_str, rev_str)) = stem.split_once("_r") {
        let generation = gen_str.parse::<u32>().ok()?;
        let rev = rev_str.parse::<u16>().ok()?;
        Some((generation, rev))
    } else {
        let generation = stem.parse::<u32>().ok()?;
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
    pub fn get_by_generation(&self, generation: u32) -> Option<&LogFileInfo> {
        self.logs.iter().find(|l| l.generation == generation)
    }

    /// Returns the latest sealed log entry recorded in the manifest, if any.
    #[cfg(any(test, feature = "testing"))]
    pub fn latest_log(&self) -> Option<&LogFileInfo> {
        self.logs.last()
    }

    /// Returns the generation sequence number of the latest sealed log recorded in the manifest, if any.
    pub fn latest_generation(&self) -> Option<u32> {
        self.logs.last().map(|l| l.generation)
    }

    /// Returns true if the volume was cleanly unmounted/sealed prior to summary export,
    /// or false if the last recorded log generation was unsealed (indicating an unclean crash recovery).
    #[cfg(any(test, feature = "testing"))]
    pub fn last_shutdown_clean(&self) -> bool {
        self.logs.last().is_none_or(|l| l.is_sealed())
    }

    /// Returns true if all recorded log generations were cleanly sealed.
    #[cfg(any(test, feature = "testing"))]
    pub fn all_logs_sealed(&self) -> bool {
        self.logs.iter().all(|l| l.is_sealed())
    }
}

/// Dynamically computed live extent statistics for a single log generation.
#[derive(Debug, Clone, PartialEq)]
pub struct GenerationLiveStats {
    pub generation: u32,
    pub filename: String,
    pub record_count: u64,
    pub total_bytes: u64,
    pub total_data_bytes: u64,
    /// Total bytes still actively referenced by live file range maps.
    pub live_bytes: u64,
    /// Total number of active extent fragments referencing this generation.
    pub live_extents: u64,
    /// Ratio of live bytes to total data bytes written (0.0 to 1.0).
    pub live_ratio: f64,
    /// Whether this log generation was cleanly sealed on rollover / shutdown.
    pub sealed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_log_manifest_creation_and_sealed_records() {
        let mut manifest = LogManifest::new();
        assert_eq!(manifest.logs.len(), 0);

        let log1 = LogFileInfo {
            version: 1,
            generation: 1,
            revision: 0,
            filename: "000001.log".to_string(),
            created_at: SystemTime::UNIX_EPOCH,
            record_count: 5,
            total_bytes: 1024,
            total_data_bytes: 512,
            md5: [1u8; 16],
            sealed_at: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(10)),
            key_salt: Some([10u8; 16]),
        };
        assert!(log1.is_sealed());
        manifest.record_sealed_log(log1);
        assert_eq!(manifest.logs.len(), 1);
        assert_eq!(manifest.logs[0].generation, 1);

        let log2 = LogFileInfo {
            version: 1,
            generation: 2,
            revision: 0,
            filename: "000002.log".to_string(),
            created_at: SystemTime::UNIX_EPOCH,
            record_count: 3,
            total_bytes: 2048,
            total_data_bytes: 1024,
            md5: [2u8; 16],
            sealed_at: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(20)),
            key_salt: Some([20u8; 16]),
        };
        assert!(log2.is_sealed());
        manifest.record_sealed_log(log2);
        assert_eq!(manifest.logs.len(), 2);
        assert_eq!(manifest.logs[1].generation, 2);

        let bytes = crate::wire::serialize(&manifest).unwrap();
        let deserialized: LogManifest = crate::wire::deserialize(&bytes).unwrap();
        assert_eq!(manifest, deserialized);
    }

    #[test]
    fn test_v1_manifest_deserialization_and_conversion() {
        let v1 = LogManifestV1 {
            logs: vec![LogFileInfoV1 {
                version: 1,
                generation: 1,
                revision: 0,
                filename: "000001.log".to_string(),
                created_at: SystemTime::UNIX_EPOCH,
                record_count: 5,
                total_bytes: 1024,
                total_data_bytes: 512,
                md5: [1u8; 16],
                sealed_at: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(10)),
            }],
        };
        let bytes = crate::wire::serialize(&v1).unwrap();
        let deserialized_v1: LogManifestV1 = crate::wire::deserialize(&bytes).unwrap();
        assert_eq!(v1, deserialized_v1);

        let converted = deserialized_v1.into_v2();
        assert_eq!(converted.logs.len(), 1);
        assert_eq!(converted.logs[0].generation, 1);
        assert_eq!(converted.logs[0].key_salt, None);
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
            version: 1,
            generation: 1,
            revision: 1,
            filename: "000001_r1.log".to_string(),
            created_at: SystemTime::UNIX_EPOCH,
            record_count: 1,
            total_bytes: 32,
            total_data_bytes: 0,
            md5: [42u8; 16],
            sealed_at: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(5)),
            key_salt: Some([42u8; 16]),
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
            version: 1,
            generation: 1,
            revision: 0,
            filename: "000001.log".to_string(),
            created_at: SystemTime::UNIX_EPOCH,
            record_count: 5,
            total_bytes: 1024,
            total_data_bytes: 512,
            md5: [1u8; 16],
            sealed_at: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(10)),
            key_salt: Some([1u8; 16]),
        };
        manifest.record_sealed_log(log1);
        assert!(manifest.last_shutdown_clean());
        assert!(manifest.all_logs_sealed());

        // Generation 2 wasn't cleanly sealed (crash)
        let log2 = LogFileInfo {
            version: 1,
            generation: 2,
            revision: 0,
            filename: "000002.log".to_string(),
            created_at: SystemTime::UNIX_EPOCH,
            record_count: 2,
            total_bytes: 512,
            total_data_bytes: 256,
            md5: [2u8; 16],
            sealed_at: None,
            key_salt: Some([2u8; 16]),
        };
        manifest.record_sealed_log(log2);
        assert!(!manifest.last_shutdown_clean());
        assert!(!manifest.all_logs_sealed());

        // Generation 3 was sealed
        let mut manifest2 = LogManifest::new();
        manifest2.record_sealed_log(LogFileInfo {
            version: 1,
            generation: 1,
            revision: 0,
            filename: "000001.log".to_string(),
            created_at: SystemTime::UNIX_EPOCH,
            record_count: 1,
            total_bytes: 100,
            total_data_bytes: 50,
            md5: [1u8; 16],
            sealed_at: None,
            key_salt: Some([1u8; 16]),
        });
        manifest2.record_sealed_log(LogFileInfo {
            version: 1,
            generation: 2,
            revision: 0,
            filename: "000002.log".to_string(),
            created_at: SystemTime::UNIX_EPOCH,
            record_count: 1,
            total_bytes: 100,
            total_data_bytes: 50,
            md5: [2u8; 16],
            sealed_at: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(20)),
            key_salt: Some([2u8; 16]),
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
            version: 1,
            generation: 1,
            revision: 0,
            filename: "000001.log".to_string(),
            created_at: SystemTime::UNIX_EPOCH,
            record_count: 5,
            total_bytes: 1024,
            total_data_bytes: 512,
            md5: [1u8; 16],
            sealed_at: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(10)),
            key_salt: Some([1u8; 16]),
        };
        manifest.record_sealed_log(log.clone());
        manifest.record_sealed_log(log);
    }

    #[test]
    #[should_panic(expected = "manifest already contains a greater generation")]
    fn test_record_sealed_log_out_of_order_panics() {
        let mut manifest = LogManifest::new();
        let log2 = LogFileInfo {
            version: 1,
            generation: 2,
            revision: 0,
            filename: "000002.log".to_string(),
            created_at: SystemTime::UNIX_EPOCH,
            record_count: 5,
            total_bytes: 1024,
            total_data_bytes: 512,
            md5: [2u8; 16],
            sealed_at: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(20)),
            key_salt: Some([2u8; 16]),
        };
        let log1 = LogFileInfo {
            version: 1,
            generation: 1,
            revision: 0,
            filename: "000001.log".to_string(),
            created_at: SystemTime::UNIX_EPOCH,
            record_count: 5,
            total_bytes: 1024,
            total_data_bytes: 512,
            md5: [1u8; 16],
            sealed_at: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(10)),
            key_salt: Some([1u8; 16]),
        };
        manifest.record_sealed_log(log2);
        manifest.record_sealed_log(log1);
    }

    #[test]
    fn test_latest_log_and_generation() {
        let mut manifest = LogManifest::new();
        assert_eq!(manifest.latest_log(), None);
        assert_eq!(manifest.latest_generation(), None);

        let log1 = LogFileInfo {
            version: 1,
            generation: 1,
            revision: 0,
            filename: "000001.log".to_string(),
            created_at: SystemTime::UNIX_EPOCH,
            record_count: 5,
            total_bytes: 1024,
            total_data_bytes: 512,
            md5: [1u8; 16],
            sealed_at: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(10)),
            key_salt: Some([1u8; 16]),
        };
        manifest.record_sealed_log(log1.clone());
        assert_eq!(manifest.latest_log(), Some(&log1));
        assert_eq!(manifest.latest_generation(), Some(1));

        let log2 = LogFileInfo {
            version: 1,
            generation: 3,
            revision: 0,
            filename: "000003.log".to_string(),
            created_at: SystemTime::UNIX_EPOCH,
            record_count: 2,
            total_bytes: 512,
            total_data_bytes: 256,
            md5: [2u8; 16],
            sealed_at: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(20)),
            key_salt: Some([2u8; 16]),
        };
        manifest.record_sealed_log(log2.clone());
        assert_eq!(manifest.latest_log(), Some(&log2));
        assert_eq!(manifest.latest_generation(), Some(3));
    }

    #[test]
    fn test_all_file_header_fields_present_in_manifest() {
        use crate::log::record::{FILE_MAGIC, FileHeader};

        let header = FileHeader {
            magic: FILE_MAGIC,
            version: 1,
            generation: 42,
            revision: 3,
            created_at: SystemTime::UNIX_EPOCH + Duration::from_secs(12345),
            key_salt: [0x77; 16],
        };

        // 1. Compile-time enforcement:
        // Exhaustively destructure FileHeader without wildcard `..`.
        // If ANY field is added to FileHeader in the future, this pattern match
        // will fail compilation unless explicitly updated here.
        let FileHeader {
            magic: _,
            version,
            generation,
            revision,
            created_at,
            key_salt,
        } = header;

        // 2. Ensure each field is mapped to LogFileInfo:
        let mut info = LogFileInfo {
            version: 0,
            generation: 0,
            revision: 0,
            filename: "000042_r3.log".to_string(),
            created_at: SystemTime::UNIX_EPOCH,
            record_count: 5,
            total_bytes: 1024,
            total_data_bytes: 512,
            md5: [0u8; 16],
            sealed_at: None,
            key_salt: None,
        };

        info.update_from_file_header(&header);

        assert_eq!(info.version, version);
        assert_eq!(info.generation, generation);
        assert_eq!(info.revision, revision);
        assert_eq!(info.created_at, created_at);
        assert_eq!(info.key_salt, Some(key_salt));

        // 3. Verify LogFileInfo::file_header reconstructs the exact header:
        assert_eq!(info.file_header(), Some(header));
    }
}
