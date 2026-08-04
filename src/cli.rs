use clap::Parser;
use std::fs;
use std::path::{Path, PathBuf};

/// Default maximum log file size before rolling to next generation (1 GiB).
pub const DEFAULT_MAX_LOG_SIZE: u64 = 1024 * 1024 * 1024;

#[derive(Parser, Debug)]
#[command(
    name = "appendfs",
    author,
    version,
    about = "High-performance log-structured FUSE filesystem"
)]
pub struct CliArgs {
    /// Target directory path where the FUSE filesystem will be mounted
    #[arg(required = true)]
    pub mount_point: PathBuf,

    /// Directory path where append-only .log files are stored and recovered
    #[arg(short = 'l', long = "log-dir", required = true)]
    pub log_dir: PathBuf,

    /// Run FUSE in foreground mode (do not daemonize)
    #[arg(short = 'f', long = "foreground", default_value_t = false)]
    pub foreground: bool,

    /// Interval in seconds for periodic background log flushing (default: 60, 0 to disable)
    #[arg(short = 'i', long = "flush-interval", default_value_t = 60)]
    pub flush_interval: u64,

    /// Maximum log file size in bytes before rolling to next generation (default: 1073741824 / 1 GiB)
    #[arg(short = 's', long = "max-log-size", default_value_t = DEFAULT_MAX_LOG_SIZE)]
    pub max_log_size: u64,

    /// Additional raw FUSE options passed to libfuse (e.g. -o allow_other)
    #[arg(short = 'o', value_delimiter = ',')]
    pub fuse_options: Vec<String>,
}

impl CliArgs {
    /// Formats CLI arguments into libfuse-compatible C-style argv.
    pub fn to_fuse_args(&self) -> Vec<String> {
        let mut fuse_args = vec![
            "appendfs".to_string(),
            self.mount_point.to_str().unwrap().to_string(),
        ];
        if self.foreground {
            fuse_args.push("-f".to_string());
        }
        for opt in &self.fuse_options {
            fuse_args.push("-o".to_string());
            fuse_args.push(opt.clone());
        }
        fuse_args
    }
}

/// Helper scanning `log_dir` for existing `.log` files to find the highest generation number.
pub fn find_latest_generation(log_dir: impl AsRef<Path>) -> u64 {
    let log_dir = log_dir.as_ref();
    if !log_dir.exists() {
        return 0;
    }

    let mut max_gen = 0u64;
    if let Ok(entries) = fs::read_dir(log_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("log") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    if let Ok(gen_num) = stem.parse::<u64>() {
                        if gen_num > max_gen {
                            max_gen = gen_num;
                        }
                    }
                }
            }
        }
    }
    max_gen
}
