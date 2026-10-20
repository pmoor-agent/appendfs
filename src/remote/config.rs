use crate::remote::RemoteStore;
use crate::remote::s3::S3RemoteStore;
use crate::remote::sigv4::SigV4Signer;
use crate::storage::{Storage, WriteMode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const DEFAULT_REMOTES_FILENAME: &str = "remotes.toml";

/// Operating mode of a remote target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
#[clap(rename_all = "kebab-case")]
pub enum RemoteMode {
    /// Remote is actively read from and written to during normal operations.
    #[default]
    ReadWrite,
    /// Remote is read-only upstream (used for upstream volumes and zero-cost cloud forking); no writes are uploaded.
    ReadOnly,
    /// Remote is write-only archive (e.g. Amazon Glacier Deep Archive); used for disaster recovery, never queried for live reads.
    WriteOnly,
}

impl RemoteMode {
    /// Returns true if the remote can be read from during normal operations.
    pub fn is_readable(&self) -> bool {
        matches!(self, Self::ReadWrite | Self::ReadOnly)
    }

    /// Returns true if changes can be replicated/written to the remote.
    pub fn is_writable(&self) -> bool {
        matches!(self, Self::ReadWrite | Self::WriteOnly)
    }
}

impl std::fmt::Display for RemoteMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReadWrite => write!(f, "Read-Write"),
            Self::ReadOnly => write!(f, "Read-Only"),
            Self::WriteOnly => write!(f, "Write-Only"),
        }
    }
}

/// Configuration for a single remote target (e.g. AWS S3, Cloudflare R2, MinIO, or a local/NFS filesystem directory).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteTargetConfig {
    /// Local filesystem path for local directory or NFS NAS share remotes
    #[serde(default)]
    pub path: Option<PathBuf>,
    /// S3 bucket name (for S3-compatible cloud object stores)
    #[serde(default)]
    pub bucket: Option<String>,
    #[serde(default = "default_region")]
    pub region: String,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub prefix: String,
    #[serde(default)]
    pub mode: RemoteMode,
    #[serde(default)]
    pub replicate_ancestors: bool,
    /// Read priority (lower numerical values are queried first during remote reads; default 10 for path/NFS, 100 for S3)
    #[serde(default = "default_read_priority")]
    pub read_priority: u32,
    /// Maximum concurrent read requests to this remote (0 or None = unlimited)
    #[serde(default)]
    pub max_concurrent_reads: Option<usize>,
    #[serde(default)]
    pub access_key_id: Option<String>,
    #[serde(default)]
    pub secret_access_key: Option<String>,
    #[serde(default)]
    pub access_key_id_env: Option<String>,
    #[serde(default)]
    pub secret_access_key_env: Option<String>,
    #[serde(default)]
    pub credentials_file: Option<PathBuf>,
    /// Whether to upload incremental active log parts to this remote before generation seals (None = default based on mode).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_partial_logs: Option<bool>,
    /// S3 storage class for uploaded objects (e.g. "INTELLIGENT_TIERING", "STANDARD_IA", "GLACIER_IR", "DEEP_ARCHIVE").
    #[serde(default)]
    pub storage_class: Option<String>,
}

fn default_region() -> String {
    "us-east-1".to_string()
}

fn default_read_priority() -> u32 {
    100
}

/// Parses credentials from a string.
///
/// Supports:
/// 1. Key-value pairs (e.g. `aws_access_key_id = ...` and `aws_secret_access_key = ...`
///    or `access_key_id = ...` and `secret_access_key = ...`, including INI format sections like `[default]`).
/// 2. Simple two-line format: line 1 = access key ID, line 2 = secret access key
///    (ignoring comments starting with `#` or `;` and blank lines).
pub fn parse_credentials_content(content: &str) -> Option<(String, String)> {
    let mut key_id: Option<String> = None;
    let mut secret_key: Option<String> = None;
    let mut positional_lines = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            continue;
        }

        if let Some((k, v)) = trimmed.split_once('=') {
            let k = k.trim().to_ascii_lowercase();
            let v = v.trim().trim_matches('"').trim_matches('\'').to_string();
            if k == "aws_access_key_id" || k == "access_key_id" || k == "aws_access_key" {
                key_id = Some(v);
            } else if k == "aws_secret_access_key" || k == "secret_access_key" || k == "aws_secret_key" {
                secret_key = Some(v);
            }
        } else {
            positional_lines.push(trimmed.to_string());
        }
    }

    if let (Some(k), Some(s)) = (key_id, secret_key) {
        return Some((k, s));
    }

    if positional_lines.len() >= 2 {
        return Some((positional_lines[0].clone(), positional_lines[1].clone()));
    }

    None
}

/// Reads and parses credentials from a file.
pub fn read_credentials_file(path: &Path) -> io::Result<(String, String)> {
    let content = fs::read_to_string(path)?;
    parse_credentials_content(&content).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Credentials file '{}' does not contain valid access key and secret key",
                path.display()
            ),
        )
    })
}

impl RemoteTargetConfig {
    pub fn new(bucket: impl Into<String>) -> Self {
        Self {
            path: None,
            bucket: Some(bucket.into()),
            region: default_region(),
            endpoint: None,
            prefix: String::new(),
            mode: RemoteMode::ReadWrite,
            replicate_ancestors: false,
            read_priority: default_read_priority(),
            max_concurrent_reads: None,
            access_key_id: None,
            secret_access_key: None,
            access_key_id_env: None,
            secret_access_key_env: None,
            credentials_file: None,
            upload_partial_logs: None,
            storage_class: None,
        }
    }

    pub fn new_path(path: impl Into<PathBuf>) -> Self {
        Self {
            path: Some(path.into()),
            bucket: None,
            region: default_region(),
            endpoint: None,
            prefix: String::new(),
            mode: RemoteMode::ReadWrite,
            replicate_ancestors: false,
            read_priority: 10,
            max_concurrent_reads: None,
            access_key_id: None,
            secret_access_key: None,
            access_key_id_env: None,
            secret_access_key_env: None,
            credentials_file: None,
            upload_partial_logs: None,
            storage_class: None,
        }
    }

    pub fn with_mode(mut self, mode: RemoteMode) -> Self {
        self.mode = mode;
        if self.mode != RemoteMode::ReadWrite {
            self.upload_partial_logs = Some(false);
        }
        self
    }

    pub fn upload_partial_logs(&self) -> bool {
        self.upload_partial_logs.unwrap_or(self.mode == RemoteMode::ReadWrite)
    }

    pub fn with_storage_class(mut self, storage_class: impl Into<String>) -> Self {
        self.storage_class = Some(storage_class.into());
        self
    }

    pub fn with_upload_partial_logs(mut self, enabled: bool) -> Self {
        self.upload_partial_logs = Some(enabled);
        self
    }

    pub fn with_credentials_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.credentials_file = Some(path.into());
        self
    }

    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    pub fn validate(&self, name: &str) -> io::Result<()> {
        if self.upload_partial_logs == Some(true) && self.mode != RemoteMode::ReadWrite {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "remote '{}': upload_partial_logs can only be true for read-write mode (found mode: {})",
                    name, self.mode
                ),
            ));
        }
        Ok(())
    }

    /// Resolves AWS credentials according to precedence:
    /// 1. Custom env var names (`access_key_id_env`, `secret_access_key_env`)
    /// 2. Credentials file (`credentials_file`)
    /// 3. Direct literal configuration (`access_key_id`, `secret_access_key`)
    /// 4. Standard AWS env vars (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
    pub fn resolve_credentials(&self) -> Option<(String, String)> {
        // 1. Custom env vars
        if let (Some(key_var), Some(secret_var)) = (&self.access_key_id_env, &self.secret_access_key_env)
            && let (Ok(k), Ok(s)) = (std::env::var(key_var), std::env::var(secret_var))
        {
            return Some((k.trim().to_string(), s.trim().to_string()));
        }

        // 2. Credentials file
        if let Some(ref path) = self.credentials_file {
            match read_credentials_file(path) {
                Ok((k, s)) => return Some((k, s)),
                Err(e) => {
                    log::warn!("Failed to read credentials file '{}': {}", path.display(), e);
                }
            }
        }

        // 3. Direct literal keys
        if let (Some(k), Some(s)) = (&self.access_key_id, &self.secret_access_key) {
            return Some((k.trim().to_string(), s.trim().to_string()));
        }

        // 4. Default AWS environment variables
        if let (Ok(k), Ok(s)) = (
            std::env::var("AWS_ACCESS_KEY_ID"),
            std::env::var("AWS_SECRET_ACCESS_KEY"),
        ) {
            return Some((k.trim().to_string(), s.trim().to_string()));
        }

        None
    }

    /// Returns true if this remote target is backed by a local directory store (e.g. NFS/SMB NAS share, external drive).
    pub fn is_local_dir(&self) -> bool {
        self.path.is_some() || self.endpoint.as_deref().is_some_and(|ep| ep.starts_with("file://"))
    }

    /// Builds an `Arc<dyn RemoteStore>` client for this target.
    pub fn build_store(&self) -> Arc<dyn RemoteStore> {
        if let Some(ref path) = self.path {
            return Arc::new(crate::remote::LocalDirRemoteStore::new(path));
        }
        if let Some(local_path) = self.endpoint.as_deref().and_then(|ep| ep.strip_prefix("file://")) {
            return Arc::new(crate::remote::LocalDirRemoteStore::new(local_path));
        }
        Arc::new(self.build_s3_store())
    }

    pub(crate) fn build_s3_store(&self) -> S3RemoteStore {
        let bucket = self.bucket.as_deref().unwrap_or("appendfs-bucket");
        let creds = self.resolve_credentials();
        let signer = creds.map(|(k, s)| SigV4Signer::new(k, s, &self.region));

        S3RemoteStore::new(
            bucket,
            &self.region,
            self.endpoint.clone(),
            &self.prefix,
            signer,
            self.storage_class.clone(),
        )
    }
}

/// Global volume replication and tiered retention policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicationPolicy {
    /// Pruning rule expression that must be satisfied before local log files are evicted.
    /// Default: "older_than(30d) && readable(1)".
    #[serde(default)]
    pub prune_rule: crate::remote::policy::PruneExpr,
    /// Maximum time an active log can stay open before rolling (default: 86400s / 24 hours).
    #[serde(default = "default_max_log_age")]
    pub max_log_age_secs: u64,
    /// Frequency of intermediate active log part uploads (default: 3600s / 1 hour).
    #[serde(default = "default_active_sync_interval")]
    pub active_sync_interval_secs: u64,
    /// Frequency of full remote consistency and healing audits (default: 21600s / 6 hours).
    #[serde(default = "default_audit_interval")]
    pub audit_interval_secs: u64,
}

fn default_max_log_age() -> u64 {
    86400 // 24 hours
}
fn default_active_sync_interval() -> u64 {
    3600 // 1 hour
}
fn default_audit_interval() -> u64 {
    21600 // 6 hours
}

impl Default for ReplicationPolicy {
    fn default() -> Self {
        Self {
            prune_rule: crate::remote::policy::PruneExpr::default(),
            max_log_age_secs: default_max_log_age(),
            active_sync_interval_secs: default_active_sync_interval(),
            audit_interval_secs: default_audit_interval(),
        }
    }
}

/// A remote store configured with its runtime parameters and operational flags.
#[derive(Clone, Debug)]
pub struct ConfiguredRemote {
    pub name: String,
    pub store: Arc<dyn RemoteStore>,
    pub mode: RemoteMode,
    pub replicate_ancestors: bool,
    pub upload_partial_logs: bool,
}

/// Registry managing all configured remotes and policies for a volume (`remotes.toml`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteRegistry {
    #[serde(default)]
    pub policy: ReplicationPolicy,
    #[serde(default)]
    pub remotes: BTreeMap<String, RemoteTargetConfig>,
    #[serde(skip)]
    pub store_overrides: BTreeMap<String, Arc<dyn RemoteStore>>,
    #[serde(skip)]
    pub limiters:
        Arc<std::sync::Mutex<std::collections::HashMap<String, Arc<crate::remote::limiter::ConcurrencyLimiter>>>>,
}

impl Default for RemoteRegistry {
    fn default() -> Self {
        Self {
            policy: ReplicationPolicy::default(),
            remotes: BTreeMap::new(),
            store_overrides: BTreeMap::new(),
            limiters: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }
}

impl PartialEq for RemoteRegistry {
    fn eq(&self, other: &Self) -> bool {
        self.policy == other.policy && self.remotes == other.remotes
    }
}
impl Eq for RemoteRegistry {}

impl RemoteRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads configuration from `remotes.toml` in the given `Storage`, or returns default if absent.
    pub fn load_from_storage(storage: &dyn Storage) -> io::Result<Self> {
        if !storage.exists(DEFAULT_REMOTES_FILENAME) {
            return Ok(Self::default());
        }
        let reader = storage.open_reader(DEFAULT_REMOTES_FILENAME)?;
        let len = reader.len()?;
        let bytes = reader.read_vec(0, len as usize)?;
        let content = String::from_utf8(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let registry: Self = toml::from_str(&content).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        registry.validate()?;
        Ok(registry)
    }

    /// Validates all remote configurations in the registry.
    pub fn validate(&self) -> io::Result<()> {
        for (name, cfg) in &self.remotes {
            cfg.validate(name)?;
        }
        let stores = self.build_all_stores();
        self.policy
            .prune_rule
            .validate_safety(&stores)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        Ok(())
    }

    /// Persists configuration to `remotes.toml` in the given `Storage`.
    pub fn save_to_storage(&self, storage: &dyn Storage) -> io::Result<()> {
        self.validate()?;
        let content = toml::to_string_pretty(self).map_err(io::Error::other)?;
        let mut writer = storage.open_writer(DEFAULT_REMOTES_FILENAME, WriteMode::Overwrite)?;
        writer.append(content.as_bytes())?;
        writer.sync()
    }

    /// Loads configuration from `<log_dir>/remotes.toml`, or returns default if absent.
    pub fn load_from_dir(log_dir: &Path) -> io::Result<Self> {
        let storage = crate::storage::OsStorage::new(log_dir);
        Self::load_from_storage(&storage)
    }

    /// Persists configuration to `<log_dir>/remotes.toml`.
    pub fn save_to_dir(&self, log_dir: &Path) -> io::Result<()> {
        let storage = crate::storage::OsStorage::new(log_dir);
        self.save_to_storage(&storage)
    }

    pub fn add_remote(&mut self, name: impl Into<String>, config: RemoteTargetConfig) {
        self.remotes.insert(name.into(), config);
    }

    pub fn remove_remote(&mut self, name: &str) -> bool {
        self.remotes.remove(name).is_some()
    }

    pub fn get_remote(&self, name: &str) -> Option<&RemoteTargetConfig> {
        self.remotes.get(name)
    }

    /// Sets an in-memory RemoteStore override for testing.
    pub fn set_store_override(&mut self, name: impl Into<String>, store: Arc<dyn RemoteStore>) {
        self.store_overrides.insert(name.into(), store);
    }

    /// Returns all configured stores as `ConfiguredRemote` records,
    /// ordered by `read_priority` ascending (lower numerical priority tried first), breaking ties by name.
    pub fn build_all_stores(&self) -> Vec<ConfiguredRemote> {
        let mut entries: Vec<_> = self
            .remotes
            .iter()
            .map(|(name, cfg)| {
                let store = self
                    .store_overrides
                    .get(name)
                    .cloned()
                    .unwrap_or_else(|| cfg.build_store());
                (
                    cfg.read_priority,
                    name.clone(),
                    store,
                    cfg.mode,
                    cfg.replicate_ancestors,
                    cfg.upload_partial_logs(),
                )
            })
            .collect();
        entries.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));
        entries
            .into_iter()
            .map(|(_, name, store, mode, ra, upl)| ConfiguredRemote {
                name,
                store,
                mode,
                replicate_ancestors: ra,
                upload_partial_logs: upl,
            })
            .collect()
    }

    /// Returns configured stores sorted by `read_priority` (ascending), breaking ties by name.
    /// Only remotes whose mode is readable (`ReadWrite` or `ReadOnly`) are included.
    pub fn build_read_stores(&self) -> Vec<crate::remote::RemoteReadTarget> {
        let mut entries: Vec<_> = self
            .remotes
            .iter()
            .filter(|(_, cfg)| cfg.mode.is_readable())
            .map(|(name, cfg)| {
                let store = self
                    .store_overrides
                    .get(name)
                    .cloned()
                    .unwrap_or_else(|| cfg.build_store());
                let mut target =
                    crate::remote::RemoteReadTarget::new(name.clone(), store, cfg.read_priority).with_mode(cfg.mode);
                if let Some(max) = cfg.max_concurrent_reads.filter(|&m| m > 0) {
                    let mut lim_guard = self.limiters.lock().unwrap();
                    let limiter = lim_guard
                        .entry(name.clone())
                        .or_insert_with(|| Arc::new(crate::remote::limiter::ConcurrencyLimiter::new(max)));
                    target = target.with_limiter(Arc::clone(limiter));
                }
                target
            })
            .collect();
        entries.sort_by(|a, b| (a.priority, &a.name).cmp(&(b.priority, &b.name)));
        entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remote_registry_toml_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let mut registry = RemoteRegistry::new();
        registry.policy.prune_rule = crate::remote::policy::PruneExpr::parse("older_than(60d) && readable(2)").unwrap();

        let mut r1 = RemoteTargetConfig::new("my-aws-bucket");
        r1.region = "us-west-2".to_string();
        r1.prefix = "vol1".to_string();
        r1.access_key_id = Some("AKIA123".to_string());
        r1.secret_access_key = Some("SECRET123".to_string());
        r1.storage_class = Some("INTELLIGENT_TIERING".to_string());
        registry.add_remote("aws", r1);

        let mut r2 = RemoteTargetConfig::new("my-b2-bucket").with_mode(RemoteMode::ReadOnly);
        r2.endpoint = Some("https://s3.us-west-002.backblazeb2.com".to_string());
        r2.read_priority = 200;
        r2.access_key_id_env = Some("B2_KEY_ID".to_string());
        r2.secret_access_key_env = Some("B2_APP_KEY".to_string());
        registry.add_remote("b2", r2);

        let r3 = RemoteTargetConfig::new_path("/mnt/nfs_backup/appendfs_logs");
        registry.add_remote("nas", r3);

        let r4 = RemoteTargetConfig::new("my-glacier-bucket")
            .with_mode(RemoteMode::WriteOnly)
            .with_storage_class("DEEP_ARCHIVE");
        registry.add_remote("glacier", r4);

        registry.save_to_dir(dir.path()).unwrap();
        let loaded = RemoteRegistry::load_from_dir(dir.path()).unwrap();
        assert_eq!(registry, loaded);

        assert_eq!(loaded.remotes.len(), 4);
        assert_eq!(loaded.remotes["aws"].bucket.as_deref(), Some("my-aws-bucket"));
        assert_eq!(
            loaded.remotes["aws"].storage_class.as_deref(),
            Some("INTELLIGENT_TIERING")
        );
        assert_eq!(loaded.remotes["b2"].storage_class, None);
        assert_eq!(loaded.remotes["aws"].mode, RemoteMode::ReadWrite);
        assert_eq!(loaded.remotes["b2"].mode, RemoteMode::ReadOnly);
        assert_eq!(loaded.remotes["glacier"].mode, RemoteMode::WriteOnly);
        assert_eq!(loaded.remotes["nas"].read_priority, 10);
        assert_eq!(loaded.remotes["aws"].read_priority, 100);
        assert_eq!(loaded.remotes["b2"].read_priority, 200);
        assert_eq!(
            loaded.remotes["nas"].path.as_deref(),
            Some(Path::new("/mnt/nfs_backup/appendfs_logs"))
        );

        // Verify build_read_stores sorts by read_priority (10 -> 100 -> 200) and EXCLUDES WriteOnly glacier remote!
        let stores = loaded.build_read_stores();
        let names: Vec<_> = stores.into_iter().map(|t| t.name).collect();
        assert_eq!(names, vec!["nas", "aws", "b2"]);

        // Verify upload_partial_logs defaults: true for ReadWrite, false for ReadOnly and WriteOnly
        assert!(loaded.remotes["aws"].upload_partial_logs());
        assert!(loaded.remotes["nas"].upload_partial_logs());
        assert!(!loaded.remotes["b2"].upload_partial_logs());
        assert!(!loaded.remotes["glacier"].upload_partial_logs());
    }

    #[test]
    fn test_upload_partial_logs_startup_validation_errors() {
        // Attempting to set upload_partial_logs = true on a write-only remote must fail validation
        let invalid_toml = r#"
[remotes.glacier]
bucket = "glacier-bucket"
mode = "write-only"
upload_partial_logs = true
"#;
        let reg: RemoteRegistry = toml::from_str(invalid_toml).unwrap();
        let res = reg.validate();
        assert!(res.is_err());
        let err_msg = res.unwrap_err().to_string();
        assert!(err_msg.contains("upload_partial_logs can only be true for read-write mode"));

        // Attempting to set upload_partial_logs = true on a read-only remote must also fail validation
        let invalid_toml_ro = r#"
[remotes.upstream]
bucket = "upstream-bucket"
mode = "read-only"
upload_partial_logs = true
"#;
        let reg_ro: RemoteRegistry = toml::from_str(invalid_toml_ro).unwrap();
        let res_ro = reg_ro.validate();
        assert!(res_ro.is_err());
        let err_msg_ro = res_ro.unwrap_err().to_string();
        assert!(err_msg_ro.contains("upload_partial_logs can only be true for read-write mode"));
    }

    #[test]
    fn test_upload_partial_logs_config_toggle_and_toml_omission() {
        let toml_data = r#"
[remotes.s3]
bucket = "backup-bucket"
upload_partial_logs = false

[remotes.nfs]
path = "/mnt/nfs"
upload_partial_logs = true

[remotes.legacy]
bucket = "legacy-bucket"
"#;
        let registry: RemoteRegistry = toml::from_str(toml_data).unwrap();
        assert_eq!(registry.remotes.len(), 3);
        assert!(!registry.remotes["s3"].upload_partial_logs());
        assert!(registry.remotes["nfs"].upload_partial_logs());
        assert!(
            registry.remotes["legacy"].upload_partial_logs(),
            "omitted field should default to true"
        );

        let stores = registry.build_all_stores();
        let s3_store = stores.iter().find(|r| r.name == "s3").unwrap();
        assert!(!s3_store.upload_partial_logs);
        let nfs_store = stores.iter().find(|r| r.name == "nfs").unwrap();
        assert!(nfs_store.upload_partial_logs);
        let leg_store = stores.iter().find(|r| r.name == "legacy").unwrap();
        assert!(leg_store.upload_partial_logs);
    }

    #[test]
    fn test_replication_policy_defaults() {
        let policy = ReplicationPolicy::default();
        assert_eq!(policy.max_log_age_secs, 86400);
        assert_eq!(policy.active_sync_interval_secs, 3600);
        assert_eq!(policy.audit_interval_secs, 21600);
        assert_eq!(policy.prune_rule, crate::remote::policy::PruneExpr::default());
        assert_eq!(policy.prune_rule.to_string(), "older_than(30d) && readable(1)");
    }

    #[test]
    fn test_parse_credentials_content_two_line() {
        let content = "AKIA12345EXAMPLE\nwJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n";
        let parsed = parse_credentials_content(content).expect("should parse simple 2-line format");
        assert_eq!(parsed.0, "AKIA12345EXAMPLE");
        assert_eq!(parsed.1, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
    }

    #[test]
    fn test_parse_credentials_content_with_comments_and_empty_lines() {
        let content = r#"
# Primary AWS Credentials
; Alternative comment style

AKIA12345EXAMPLE

# Secret below
wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"#;
        let parsed = parse_credentials_content(content).expect("should parse 2-line format with comments");
        assert_eq!(parsed.0, "AKIA12345EXAMPLE");
        assert_eq!(parsed.1, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
    }

    #[test]
    fn test_parse_credentials_content_aws_ini_format() {
        let content = r#"
[default]
aws_access_key_id = AKIA12345EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"#;
        let parsed = parse_credentials_content(content).expect("should parse AWS INI format");
        assert_eq!(parsed.0, "AKIA12345EXAMPLE");
        assert_eq!(parsed.1, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
    }

    #[test]
    fn test_parse_credentials_content_quoted_and_key_value() {
        let content = r#"
ACCESS_KEY_ID="AKIA12345EXAMPLE"
SECRET_ACCESS_KEY='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
"#;
        let parsed = parse_credentials_content(content).expect("should parse quoted key-value format");
        assert_eq!(parsed.0, "AKIA12345EXAMPLE");
        assert_eq!(parsed.1, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
    }

    #[test]
    fn test_parse_credentials_content_invalid() {
        assert!(parse_credentials_content("").is_none());
        assert!(parse_credentials_content("# only comments\n; nothing else\n").is_none());
        assert!(parse_credentials_content("SINGLE_LINE_ONLY\n").is_none());
        assert!(parse_credentials_content("aws_access_key_id = AKIA123\n").is_none());
    }

    #[test]
    fn test_read_credentials_file() {
        let dir = tempfile::tempdir().unwrap();
        let valid_file = dir.path().join("creds.txt");
        fs::write(&valid_file, "KEY1\nSECRET1\n").unwrap();

        let (k, s) = read_credentials_file(&valid_file).unwrap();
        assert_eq!(k, "KEY1");
        assert_eq!(s, "SECRET1");

        let missing_file = dir.path().join("missing.txt");
        let err = read_credentials_file(&missing_file).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);

        let invalid_file = dir.path().join("invalid.txt");
        fs::write(&invalid_file, "ONLY_ONE_LINE\n").unwrap();
        let err = read_credentials_file(&invalid_file).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_resolve_credentials_precedence() {
        let dir = tempfile::tempdir().unwrap();
        let creds_file = dir.path().join("test_creds.txt");
        fs::write(&creds_file, "FILE_KEY\nFILE_SECRET\n").unwrap();

        // 1. Credentials file overrides literal keys
        let mut cfg = RemoteTargetConfig::new("bucket");
        cfg.access_key_id = Some("LITERAL_KEY".to_string());
        cfg.secret_access_key = Some("LITERAL_SECRET".to_string());
        cfg.credentials_file = Some(creds_file.clone());

        let creds = cfg.resolve_credentials().expect("should resolve credentials");
        assert_eq!(creds.0, "FILE_KEY");
        assert_eq!(creds.1, "FILE_SECRET");

        // 2. Without credentials file, falls back to literal keys
        cfg.credentials_file = None;
        let creds_literal = cfg.resolve_credentials().expect("should resolve literal keys");
        assert_eq!(creds_literal.0, "LITERAL_KEY");
        assert_eq!(creds_literal.1, "LITERAL_SECRET");

        // 3. Builder method with_credentials_file and store construction
        let cfg2 = RemoteTargetConfig::new("my-bucket").with_credentials_file(&creds_file);
        assert!(!cfg2.is_local_dir());
        let creds2 = cfg2.resolve_credentials().expect("should resolve from builder");
        assert_eq!(creds2.0, "FILE_KEY");
        assert_eq!(creds2.1, "FILE_SECRET");

        let store = cfg2.build_store();
        assert!(format!("{:?}", store).contains("S3RemoteStore"));
    }

    /// Pins the exact URLs and signatures for the two remote shapes in live use (AWS without an endpoint,
    /// GCS behind a regional endpoint), so changes to endpoint resolution or signing cannot silently
    /// change what is sent to AWS or GCS.
    #[test]
    fn test_live_remote_shapes_request_addressing_is_stable() {
        let registry: RemoteRegistry = toml::from_str(
            r#"
[remotes.aws-archive]
bucket = "example-archive-111122223333-eu-west-1-an"
region = "eu-west-1"
prefix = ""
mode = "write-only"
replicate_ancestors = false
read_priority = 100
access_key_id = "AKIDEXAMPLE"
secret_access_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
storage_class = "DEEP_ARCHIVE"

[remotes.gcs-regional]
bucket = "example-bucket"
region = "europe-west4"
endpoint = "https://storage.europe-west4.rep.googleapis.com"
prefix = ""
mode = "read-write"
replicate_ancestors = false
read_priority = 100
access_key_id = "GOOGEXAMPLE"
secret_access_key = "bGoa+V7g/yqDXvKRqq+JTFn4uQZbPiQJo4pf9RzJ"
# No longer read, but existing remotes.toml files still carry it and must keep loading.
force_path_style = true
upload_partial_logs = false
"#,
        )
        .unwrap();

        const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        const DATETIME: &str = "20261015T120000Z";
        let list_query = [
            ("list-type".to_string(), "2".to_string()),
            ("prefix".to_string(), "".to_string()),
        ];
        let put_headers = [
            ("Content-Length".to_string(), "1024".to_string()),
            ("Content-Type".to_string(), "application/octet-stream".to_string()),
        ];

        let mut actual = Vec::new();
        for (name, storage_class) in [("aws-archive", Some("DEEP_ARCHIVE")), ("gcs-regional", None)] {
            let store = registry.get_remote(name).unwrap().build_s3_store();
            let mut put_headers = put_headers.to_vec();
            if let Some(sc) = storage_class {
                put_headers.push(("x-amz-storage-class".to_string(), sc.to_string()));
            }
            for (method, key, query, headers, payload) in [
                ("GET", "", &list_query[..], &[][..], EMPTY_SHA256),
                ("GET", "000001.summary", &[][..], &[][..], EMPTY_SHA256),
                ("PUT", "000002.log", &[][..], &put_headers[..], "UNSIGNED-PAYLOAD"),
            ] {
                let prepared = store.prepare_request(method, key, query, headers, payload, DATETIME);
                actual.push((name, method, prepared.url, prepared.headers));
            }
        }

        let signed = |remote: &str, signed_headers: &str, signature: &str| {
            let (key_id, region) = match remote {
                "aws-archive" => ("AKIDEXAMPLE", "eu-west-1"),
                _ => ("GOOGEXAMPLE", "europe-west4"),
            };
            format!(
                "AWS4-HMAC-SHA256 Credential={}/20261015/{}/s3/aws4_request, SignedHeaders={}, Signature={}",
                key_id, region, signed_headers, signature
            )
        };
        let aws = "https://example-archive-111122223333-eu-west-1-an.s3.eu-west-1.amazonaws.com";
        let gcs = "https://storage.europe-west4.rep.googleapis.com/example-bucket";
        let get_headers = "host;x-amz-content-sha256;x-amz-date";
        let expected = [
            (
                "aws-archive",
                "GET",
                aws.to_string(),
                signed(
                    "aws-archive",
                    get_headers,
                    "8cf11a185b724d7b8be038f6669912eb8ec02c324842679cff14578ee1f5a52b",
                ),
            ),
            (
                "aws-archive",
                "GET",
                format!("{}/000001.summary", aws),
                signed(
                    "aws-archive",
                    get_headers,
                    "cf5f9f129737208f410ef500e57da08627562af484f7a3548e506cc0abd6a1bd",
                ),
            ),
            (
                "aws-archive",
                "PUT",
                format!("{}/000002.log", aws),
                signed(
                    "aws-archive",
                    "content-length;content-type;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class",
                    "37cf9ad1734c6a421f4009311a9c4e388d293c8c22048f854dee218e671406a1",
                ),
            ),
            (
                "gcs-regional",
                "GET",
                gcs.to_string(),
                signed(
                    "gcs-regional",
                    get_headers,
                    "0e6a4da69d75c02f68a370e2ac9c9d3531d8b8322814d2eb673a9ee753f6278f",
                ),
            ),
            (
                "gcs-regional",
                "GET",
                format!("{}/000001.summary", gcs),
                signed(
                    "gcs-regional",
                    get_headers,
                    "91b0f7ba6b0794dd0372998648e996007e72c2e5d99512d64f319b4960591e78",
                ),
            ),
            (
                "gcs-regional",
                "PUT",
                format!("{}/000002.log", gcs),
                signed(
                    "gcs-regional",
                    "content-length;content-type;host;x-amz-content-sha256;x-amz-date",
                    "0838742dc9618a123d21b8850a05d549bb062b035d8be228be885dc97467dd79",
                ),
            ),
        ];

        assert_eq!(actual.len(), expected.len());
        for ((name, method, url, headers), (exp_name, exp_method, exp_url, exp_auth)) in actual.iter().zip(&expected) {
            assert_eq!((*name, *method, url), (*exp_name, *exp_method, exp_url));
            let auth = headers.iter().find(|(k, _)| k == "Authorization").map(|(_, v)| v);
            assert_eq!(auth, Some(exp_auth), "{} {} {}", name, method, url);
            assert!(headers.contains(&("x-amz-date".to_string(), DATETIME.to_string())));
        }
    }

    #[test]
    fn test_custom_endpoints_are_addressed_path_style() {
        for (endpoint, expected_url) in [
            (
                "https://storage.googleapis.com",
                "https://storage.googleapis.com/my-bucket/k",
            ),
            (
                "https://s3.eu-central-1.amazonaws.com",
                "https://s3.eu-central-1.amazonaws.com/my-bucket/k",
            ),
            (
                "https://acct.r2.cloudflarestorage.com/",
                "https://acct.r2.cloudflarestorage.com/my-bucket/k",
            ),
            ("http://localhost:9000", "http://localhost:9000/my-bucket/k"),
        ] {
            let store = RemoteTargetConfig::new("my-bucket")
                .with_endpoint(endpoint)
                .build_s3_store();
            let prepared = store.prepare_request("GET", "k", &[], &[], "UNSIGNED-PAYLOAD", "20261015T120000Z");
            assert_eq!(prepared.url, expected_url, "endpoint {}", endpoint);
        }

        // Without an endpoint the target is AWS, addressed virtual-hosted style.
        let mut aws = RemoteTargetConfig::new("my-bucket");
        aws.region = "eu-west-1".to_string();
        let prepared =
            aws.build_s3_store()
                .prepare_request("GET", "k", &[], &[], "UNSIGNED-PAYLOAD", "20261015T120000Z");
        assert_eq!(prepared.url, "https://my-bucket.s3.eu-west-1.amazonaws.com/k");
    }
}
