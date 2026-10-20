#![cfg_attr(not(test), deny(clippy::too_many_lines))]
use appendfs::cli::{
    BackfillSaltsArgs, Cli, Commands, DumpArgs, FsckArgs, InitArgs, KeyChangePassphraseArgs, KeyCommands, KeyInitArgs,
    KeySubcommandArgs, MountArgs, MountCommonArgs, MountRoArgs, RemoteAddArgs, RemoteCommands, RemoteListArgs,
    RemoteRmArgs, RemoteSubcommandArgs, StatsArgs,
};
use appendfs::clock::SystemClock;
use appendfs::crypto::{
    CipherSuite, KeyFile, MasterKey, VolumeHeader, VolumeKey, format_encrypted_key_file, format_plain_key_file,
    prompt_passphrase, write_new_key_file,
};
use appendfs::log::SummaryReader;
use appendfs::storage::{OsStorage, Storage};
use appendfs::{
    CheckOptions, VolumeStats, check_fs_integrity, check_remote_integrity, dump_file, init_volume, latest_summary_file,
    plan_sampled_verification, recover_fs,
};

use clap::Parser;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use zeroize::Zeroizing;

fn load_remote_registry(storage: &dyn Storage) -> appendfs::remote::RemoteRegistry {
    match appendfs::remote::RemoteRegistry::load_from_storage(storage) {
        Ok(reg) => reg,
        Err(e) => {
            eprintln!(
                "Error loading '{}': {}",
                appendfs::remote::config::DEFAULT_REMOTES_FILENAME,
                e
            );
            std::process::exit(1);
        }
    }
}

struct VolumeHeaderInfo {
    storage: Arc<dyn Storage>,
    header: VolumeHeader,
}

struct OpenVolumeStorage {
    storage: Arc<dyn Storage>,
    volume_key: Arc<VolumeKey>,
}

struct OpenVolumeFs {
    fs: appendfs::AppendFs,
    storage: Arc<dyn Storage>,
}

/// Reads the volume header and validates that `log_dir` contains an initialized appendfs volume.
fn read_volume_header_info(log_dir: &Path) -> Result<VolumeHeaderInfo, String> {
    if !log_dir.exists() {
        return Err(format!(
            "Log directory '{}' does not exist.\nRun 'appendfs init {}' to create a new volume first.",
            log_dir.display(),
            log_dir.display()
        ));
    }

    let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(log_dir));
    let summary_file = latest_summary_file(storage.as_ref())
        .map_err(|e| format!("Error reading log directory '{}': {}", log_dir.display(), e))?;
    let summary_file = match summary_file {
        Some(sf) => sf,
        None => {
            return Err(format!(
                "No appendfs volume found in '{}' (directory contains no summary files).\nRun 'appendfs init {}' to create a new volume first.",
                log_dir.display(),
                log_dir.display()
            ));
        }
    };

    let header = SummaryReader::read_volume_header(storage.as_ref(), &summary_file).map_err(|e| e.to_string())?;

    Ok(VolumeHeaderInfo { storage, header })
}

/// Opens an appendfs volume's underlying storage and resolves/unlocks its volume key.
fn open_volume_storage(log_dir: &Path, key_file: Option<&Path>) -> Result<OpenVolumeStorage, String> {
    let VolumeHeaderInfo {
        storage,
        header: volume_header,
    } = read_volume_header_info(log_dir)?;

    if volume_header.cipher == CipherSuite::None {
        if key_file.is_some() {
            return Err("Volume is not encrypted; --key-file does not apply to it".to_string());
        }
        return Ok(OpenVolumeStorage {
            storage,
            volume_key: Arc::new(VolumeKey::plaintext_with_volume_id(volume_header.volume_id)),
        });
    }

    let Some(key_file) = key_file else {
        return Err("Volume is encrypted. Pass --key-file to unlock it.".to_string());
    };
    let master_key = MasterKey::from_file(key_file).map_err(|e| e.to_string())?;

    // The key check value is verified here, before recovery reads a single record. Without
    // it a wrong key would surface as an authentication failure mid-replay, which is
    // indistinguishable from bitrot and reads to the user like their volume is destroyed.
    let volume_key = volume_header.unlock(&master_key).map_err(|e| e.to_string())?;
    Ok(OpenVolumeStorage {
        storage,
        volume_key: Arc::new(volume_key),
    })
}

/// Opens an appendfs volume and recovers an in-memory filesystem instance up to `target`.
fn open_volume_fs(
    log_dir: &Path,
    key_file: Option<&Path>,
    target: appendfs::RecoveryTarget,
) -> Result<OpenVolumeFs, String> {
    let OpenVolumeStorage { storage, volume_key } = open_volume_storage(log_dir, key_file)?;
    let fs = recover_fs(storage.clone(), target, Arc::new(SystemClock), volume_key)
        .map_err(|e| format!("Failed to recover volume from '{}': {}", log_dir.display(), e))?;
    Ok(OpenVolumeFs { fs, storage })
}

fn main() {
    let cli = Cli::parse();
    init_logging(&cli);

    match cli.command {
        Commands::Init(args) => cmd_init(args),
        Commands::Mount(args) => cmd_mount(args),
        Commands::MountRo(args) => cmd_mount_ro(args),
        Commands::Stats(args) => cmd_stats(args),
        Commands::Dump(args) => cmd_dump(args),
        Commands::Fsck(args) => cmd_fsck(args),
        Commands::Remote(subargs) => cmd_remote(subargs),
        Commands::Key(subargs) => cmd_key(subargs),
        Commands::BackfillSalts(args) => cmd_backfill_salts(args),
    }
}

/// Points logging at a file, and says where, since a backgrounded mount leaves no other
/// trace of it.
fn init_logging(cli: &Cli) {
    let Some(path) = cli.log_file.clone().or_else(|| default_volume_log(&cli.command)) else {
        return;
    };

    if let Some(path) = appendfs::logging::init(&path, &cli.log_level) {
        println!("Logging to '{}' (level: {})", path.display(), cli.log_level);
    }

    // First record of every run: what this invocation was, credentials redacted. Makes a log
    // self-identifying without having to correlate it against shell history.
    log::info!("{}", appendfs::logging::redacted_command_line());
}

/// Where a command logs by default: a per-run file in the volume it is operating on.
fn default_volume_log(command: &Commands) -> Option<PathBuf> {
    let (volume_dir, may_create) = match command {
        // `init` is the one command entitled to create the directory it was handed.
        Commands::Init(args) => (args.log_dir.clone(), true),
        Commands::Mount(args) => (args.log_dir.clone(), false),
        Commands::MountRo(args) => (args.log_dir.clone(), false),
        Commands::Stats(args) => (args.log_dir.clone(), false),
        Commands::Fsck(args) => (args.log_dir.clone(), false),
        Commands::BackfillSalts(args) => (args.log_dir.clone(), false),
        // `dump` names a log file rather than a volume, so log beside it.
        Commands::Dump(args) => (args.file.parent()?.to_path_buf(), false),
        Commands::Remote(sub) => match sub.command {
            appendfs::cli::RemoteCommands::Add(ref a) => (a.log_dir.clone(), false),
            appendfs::cli::RemoteCommands::Rm(ref a) => (a.log_dir.clone(), false),
            appendfs::cli::RemoteCommands::List(ref a) => (a.log_dir.clone(), false),
        },
        Commands::Key(_) => return None,
    };

    // A mistyped path should not scatter `logs/` directories across the filesystem.
    if !may_create && !volume_dir.exists() {
        return None;
    }
    Some(appendfs::logging::run_log_path(&volume_dir))
}

// TODO(too-many-lines): split the --from-remote bootstrap path out of this handler.
#[allow(clippy::too_many_lines)]
fn cmd_init(args: InitArgs) {
    if let Some(ref remote_name) = args.from_remote {
        println!(
            "Bootstrapping volume in '{}' from remote '{}'...",
            args.log_dir.display(),
            remote_name
        );
        std::fs::create_dir_all(&args.log_dir).unwrap_or_default();
        let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(&args.log_dir));
        let registry = load_remote_registry(storage.as_ref());

        if args.remote_mode == appendfs::remote::RemoteMode::WriteOnly {
            eprintln!("Error: Cannot bootstrap an initial filesystem from a write-only remote.");
            std::process::exit(1);
        }

        if let Some(ref creds_path) = args.remote_credentials_file
            && let Err(e) = appendfs::remote::read_credentials_file(creds_path)
        {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
        if let Some(ref key_env) = args.remote_access_key_id_env
            && std::env::var(key_env).is_err()
        {
            eprintln!("Error: Environment variable '{}' is not set.", key_env);
            std::process::exit(1);
        }
        if let Some(ref secret_env) = args.remote_secret_access_key_env
            && std::env::var(secret_env).is_err()
        {
            eprintln!("Error: Environment variable '{}' is not set.", secret_env);
            std::process::exit(1);
        }

        let remote_cfg = if let Some(cfg) = registry.get_remote(remote_name) {
            if cfg.mode == appendfs::remote::RemoteMode::WriteOnly {
                eprintln!("Error: Cannot bootstrap an initial filesystem from a write-only remote.");
                std::process::exit(1);
            }
            let mut cfg = cfg.clone();
            if let Some(ref creds_file) = args.remote_credentials_file {
                cfg.credentials_file = Some(creds_file.clone());
            }
            if let Some(ref key_id) = args.remote_access_key_id {
                cfg.access_key_id = Some(key_id.clone());
            }
            if let Some(ref secret) = args.remote_secret_access_key {
                cfg.secret_access_key = Some(secret.clone());
            }
            if let Some(ref key_env) = args.remote_access_key_id_env {
                cfg.access_key_id_env = Some(key_env.clone());
            }
            if let Some(ref secret_env) = args.remote_secret_access_key_env {
                cfg.secret_access_key_env = Some(secret_env.clone());
            }
            cfg
        } else if let Some(ref path) = args.remote_path {
            let mut cfg = appendfs::remote::RemoteTargetConfig::new_path(path);
            cfg.mode = args.remote_mode;
            cfg
        } else if let Some(ref bucket) = args.remote_bucket {
            let mut cfg = appendfs::remote::RemoteTargetConfig::new(bucket);
            cfg.endpoint = args.remote_endpoint.clone();
            cfg.region = args.remote_region.clone();
            cfg.prefix = args.remote_prefix.clone();
            cfg.mode = args.remote_mode;
            cfg.access_key_id = args.remote_access_key_id.clone();
            cfg.secret_access_key = args.remote_secret_access_key.clone();
            cfg.access_key_id_env = args.remote_access_key_id_env.clone();
            cfg.secret_access_key_env = args.remote_secret_access_key_env.clone();
            cfg.credentials_file = args.remote_credentials_file.clone();
            cfg
        } else {
            eprintln!(
                "Error: Remote '{}' not found in remotes.toml, and neither --remote-path nor --remote-bucket was specified.",
                remote_name
            );
            std::process::exit(1);
        };

        let store = remote_cfg.build_store();
        match appendfs::remote::bootstrap_from_remote(store.as_ref(), storage.as_ref(), remote_name, remote_cfg) {
            Ok(summary_file) => {
                println!("Successfully bootstrapped volume from remote '{}'!", remote_name);
                println!("  Log Directory:   {}", args.log_dir.display());
                println!("  Latest Summary:  {}", summary_file);
                println!();
                println!(
                    "You can now mount this volume with 'appendfs mount {} <mountpoint>'",
                    args.log_dir.display()
                );
                return;
            }
            Err(e) => {
                eprintln!("Failed to bootstrap volume from remote: {}", e);
                std::process::exit(1);
            }
        }
    }

    println!("Initializing appendfs volume at '{}'...", args.log_dir.display());

    if let Some(ref key_file) = args.key_file {
        let master_key = match MasterKey::from_file(key_file) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        };

        let (volume_header, volume_key) = match VolumeHeader::new_encrypted(&master_key, args.compression()) {
            Ok(res) => res,
            Err(e) => {
                eprintln!("Failed to initialize volume encryption: {}", e);
                std::process::exit(1);
            }
        };
        let volume_id = hex_string(&volume_header.volume_id);

        let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(&args.log_dir));
        match init_volume(storage, &volume_key, volume_header, Arc::new(SystemClock)) {
            Ok(summary_filename) => {
                println!("Initialized encrypted appendfs volume successfully!");
                println!("  Log Directory:   {}", args.log_dir.display());
                println!("  Summary File:    {}", summary_filename);
                println!("  Cipher:          ChaCha20-Poly1305");
                println!("  Key File:        {}", key_file.display());
                println!("  Compression:     {}", args.compression());
                println!("  Volume ID:       {}", volume_id);
                println!("  Root Inode:      1 (/)");
                println!("  Next Generation: 1 (000001.log)");
                println!();
                println!("Back up your key file now: it is not stored in the volume and");
                println!("cannot be recovered. Losing it loses the volume. Its passphrase, if");
                println!("any, can be changed with 'appendfs key change-passphrase'.");
            }
            Err(e) => {
                eprintln!("Failed to initialize volume in '{}': {}", args.log_dir.display(), e);
                std::process::exit(1);
            }
        }
    } else {
        let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(&args.log_dir));
        // Compression is independent of encryption, so an unencrypted volume must
        // still honour --compress rather than silently dropping it.
        let mut volume_header = VolumeHeader::plaintext();
        volume_header.compression = args.compression();
        let volume_id = hex_string(&volume_header.volume_id);
        match init_volume(storage, &VolumeKey::plaintext(), volume_header, Arc::new(SystemClock)) {
            Ok(summary_filename) => {
                println!("Initialized empty appendfs volume successfully!");
                println!("  Log Directory:   {}", args.log_dir.display());
                println!("  Summary File:    {}", summary_filename);
                println!("  Cipher:          Plaintext (None)");
                println!("  Compression:     {}", args.compression());
                println!("  Volume ID:       {}", volume_id);
                println!("  Root Inode:      1 (/)");
                println!("  Next Generation: 1 (000001.log)");
            }
            Err(e) => {
                eprintln!("Failed to initialize volume in '{}': {}", args.log_dir.display(), e);
                std::process::exit(1);
            }
        }
    }
}

/// Builds the log reader cache for a mount: the in-memory decrypted record cache plus the
/// on-disk block cache, both sized and placed by the mount flags.
fn build_log_cache(
    args: &MountCommonArgs,
    storage: Arc<dyn Storage>,
    remote_stores: Vec<appendfs::remote::RemoteReadTarget>,
    manifest: &Arc<std::sync::RwLock<appendfs::log::LogManifest>>,
) -> Arc<appendfs::log::LogFileCache> {
    let cache_dir = args
        .disk_cache_dir
        .clone()
        .unwrap_or_else(|| args.log_dir.join(".cache"));
    let block_cache =
        match appendfs::remote::OnDiskBlockCache::new(&cache_dir, args.disk_cache_size, Arc::new(SystemClock)) {
            Ok(c) => Arc::new(c),
            Err(e) => {
                eprintln!("Failed to open disk cache directory '{}': {}", cache_dir.display(), e);
                std::process::exit(1);
            }
        };
    let log_cache = appendfs::log::LogFileCache::with_remote_support(
        storage,
        Some(block_cache),
        remote_stores,
        Some(Arc::clone(manifest)),
    )
    .with_cache_local_reads(args.disk_cache_local_reads);
    log_cache.set_decrypted_cache_size(args.decrypted_cache_size);
    Arc::new(log_cache)
}

fn cmd_mount(args: MountArgs) {
    let log_dir = &args.log_dir;
    println!(
        "Recovering appendfs state from log directory '{}'...",
        log_dir.display()
    );

    let OpenVolumeFs {
        fs: mut fs_instance,
        storage,
    } = match open_volume_fs(log_dir, args.key_file.as_deref(), appendfs::RecoveryTarget::Latest) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    // The flusher checks `max_log_age` at the end of every cycle, so this one limit covers
    // both the CLI flag and the remote policy's `max_log_age_secs`; the tighter wins.
    let registry = load_remote_registry(storage.as_ref());
    let max_log_age = appendfs::clock::parse_duration(&args.max_log_age)
        .ok()
        .map(|cli| cli.min(std::time::Duration::from_secs(registry.policy.max_log_age_secs)));
    let writer = match fs_instance.next_log_writer(storage.clone(), args.max_log_size) {
        Ok(w) => Arc::new(w.with_max_log_age(max_log_age)),
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    fs_instance.attach_log_writer(Arc::clone(&writer));
    fs_instance.max_buffer_size = args.flush_threshold;
    fs_instance.max_staged_ops = args.flush_threshold_ops;
    fs_instance.max_extent_size = args.max_extent_size;
    fs_instance.max_flush_queue_depth = args.max_flush_queue_depth;
    fs_instance.max_flush_queue_bytes = args.max_flush_queue_bytes;
    fs_instance.max_flush_queue_ops = args.max_flush_queue_ops;
    fs_instance.max_coalesce_batches = args.max_coalesce_batches;
    fs_instance.max_coalesce_bytes = args.max_coalesce_bytes;
    fs_instance.max_coalesce_ops = args.max_coalesce_ops;
    fs_instance.small_batch_max_bytes = args.small_batch_max_bytes;
    fs_instance.flush_interval.store(args.flush_interval, Ordering::SeqCst);
    fs_instance.set_summary_intervals(args.summary_interval_bytes, args.summary_interval_generations);
    fs_instance.track_atime = args.track_atime;
    fs_instance.set_read_parallelism(args.read_parallelism);

    fs_instance.set_log_cache(build_log_cache(
        &args,
        storage.clone(),
        registry.build_read_stores(),
        &fs_instance.manifest,
    ));

    // Only configured here: `init()` starts the worker once FUSE is up, since a thread started
    // now would not survive `fuse_daemonize` forking a background mount.
    if !args.no_sync && !registry.remotes.is_empty() {
        fs_instance.replication_log_dir = Some(log_dir.clone());
    }
    fs_instance.set_remote_registry(Arc::new(std::sync::RwLock::new(registry)));

    let fs_instance = Arc::new(fs_instance);

    println!(
        "Mounting appendfs at '{}' with log-dir '{}' (active generation: {}, flush-threshold: {} bytes, flush-ops: {}, flush-interval: {}s, max-log-size: {} bytes, max-extent-size: {} bytes, read-parallelism: {}, foreground: {})...",
        args.mount_point.display(),
        args.log_dir.display(),
        writer.generation(),
        args.flush_threshold,
        args.flush_threshold_ops,
        args.flush_interval,
        args.max_log_size,
        args.max_extent_size,
        args.read_parallelism,
        args.foreground
    );

    let fuse_args = args.to_fuse_args();
    if let Err(err) = appendfs::mount_arc(fuse_args, fs_instance) {
        log::error!("Failed to mount appendfs FUSE filesystem: {}", err);
        eprintln!("Failed to mount appendfs FUSE filesystem: {}", err);
        std::process::exit(1);
    }
    log::info!("Orderly shutdown complete");
}

fn cmd_mount_ro(args: MountRoArgs) {
    let log_dir = &args.log_dir;
    let target = if let Some(batch_id) = args.batch_id {
        appendfs::RecoveryTarget::BatchId(batch_id)
    } else if let Some(ref time_str) = args.at_time {
        match appendfs::parse_timestamp(time_str) {
            Ok(t) => appendfs::RecoveryTarget::Timestamp(t),
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    } else if let Some(target_gen) = args.generation {
        appendfs::RecoveryTarget::Generation(target_gen)
    } else {
        appendfs::RecoveryTarget::Latest
    };

    println!(
        "Recovering appendfs state (read-only, target: {:?}) from '{}'...",
        target,
        log_dir.display()
    );

    let OpenVolumeStorage { storage, volume_key } = match open_volume_storage(log_dir, args.key_file.as_deref()) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let registry = load_remote_registry(storage.as_ref());
    let remote_stores = registry.build_read_stores();

    if let Err(e) =
        appendfs::prepare_remote_recovery_for_target(storage.as_ref(), target, volume_key.clone(), &remote_stores)
    {
        log::warn!("Remote recovery preparation warning: {}", e);
    }

    let storage: Arc<dyn Storage> = Arc::new(appendfs::storage::ReadOnlyStorage::new(storage));

    let mut fs_instance = match recover_fs(storage.clone(), target, Arc::new(SystemClock), volume_key) {
        Ok(fs) => fs,
        Err(e) => {
            eprintln!("Failed to recover volume from '{}': {}", log_dir.display(), e);
            std::process::exit(1);
        }
    };
    fs_instance.set_storage(storage.clone());
    fs_instance.set_read_only();
    fs_instance.set_read_parallelism(args.read_parallelism);

    fs_instance.set_log_cache(build_log_cache(&args, storage, remote_stores, &fs_instance.manifest));

    let registry_arc = Arc::new(std::sync::RwLock::new(registry));
    fs_instance.set_remote_registry(Arc::clone(&registry_arc));

    let effective_batch_id = fs_instance.last_batch_id.load(Ordering::SeqCst);
    let effective_gen = {
        let manifest = fs_instance.manifest.read().unwrap();
        manifest.latest_generation().unwrap_or(1)
    };
    let effective_time_str = fs_instance
        .recovered_time()
        .map_or_else(|| "N/A".to_string(), appendfs::format_local_civil_time);

    println!(
        "Recovered appendfs state (read-only) -> Effective Version: generation {}, last batch_id: {}, timestamp: {}",
        effective_gen, effective_batch_id, effective_time_str
    );
    println!(
        "Mounting appendfs (read-only) at '{}' with log-dir '{}' (foreground: {})...",
        args.mount_point.display(),
        args.log_dir.display(),
        args.foreground
    );

    let fs_instance = Arc::new(fs_instance);
    let fuse_args = args.to_fuse_args();
    if let Err(err) = appendfs::mount_ro_arc(fuse_args, fs_instance) {
        log::error!("Failed to mount read-only appendfs FUSE filesystem: {}", err);
        eprintln!("Failed to mount read-only appendfs FUSE filesystem: {}", err);
        std::process::exit(1);
    }
    log::info!("Orderly shutdown complete");
}

fn cmd_stats(args: StatsArgs) {
    let VolumeHeaderInfo { header, .. } = match read_volume_header_info(&args.log_dir) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    // Printed before unlocking is attempted, so the credential a volume wants is visible
    // even when opening it fails - or before the passphrase prompt appears.
    print_volume_identity(&args.log_dir, &header);

    let OpenVolumeFs { fs, .. } = match open_volume_fs(
        &args.log_dir,
        args.key_file.as_deref(),
        appendfs::RecoveryTarget::Latest,
    ) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("Error: {}", e);
            print_credential_help(&header);
            std::process::exit(1);
        }
    };

    let stats = VolumeStats::collect(&fs);
    print!("{}", stats.display_text());
}

fn cmd_dump(args: DumpArgs) {
    let file_path = &args.file;
    if !file_path.exists() {
        eprintln!("Error: File '{}' does not exist.", file_path.display());
        std::process::exit(1);
    }

    let parent = file_path.parent().unwrap_or_else(|| Path::new("."));
    let filename = file_path.file_name().and_then(|s| s.to_str()).unwrap_or("").to_string();
    let storage = OsStorage::new(parent);

    // Without a key file this dumps the raw on-disk bytes, which is a valid way to inspect
    // structure. With one, the key resolves against the volume's summary - not against the
    // file being dumped, which is usually a .log and carries no volume header - and fails
    // loudly rather than quietly falling back to a ciphertext dump the user did not ask for.
    let volume_key = if let Some(key_file) = args.key_file.as_deref() {
        match open_volume_storage(parent, Some(key_file)) {
            Ok(res) => Some(res.volume_key),
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    match dump_file(&storage, &filename, args.verbose, volume_key.as_deref()) {
        Ok(output) => print!("{}", output),
        Err(e) => {
            eprintln!("Error dumping file '{}': {}", file_path.display(), e);
            std::process::exit(1);
        }
    }
}

fn confirm_remote_egress(plan: &appendfs::VerificationPlan, manifest: &appendfs::log::LogManifest) {
    use std::io::{IsTerminal, Write};
    print!("{}", plan.display_summary(manifest));
    if !std::io::stdin().is_terminal() {
        eprintln!("Error: Remote data verification requires interactive confirmation or the -y / --yes flag.");
        std::process::exit(1);
    }
    print!("Proceed with remote data verification? [y/N]: ");
    let _ = std::io::stdout().flush();
    let mut answer = String::new();
    if std::io::stdin().read_line(&mut answer).is_err() || !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes")
    {
        println!("Aborted by user.");
        std::process::exit(0);
    }
}

/// Prints `fsck` data verification progress to stderr, keeping stdout for the report.
///
/// On a terminal the line is redrawn in place every 0.1%. Otherwise a line is printed every
/// 10%, so the output of an unattended run stays short.
struct FsckProgress {
    label: String,
    tty: bool,
    last_step: Option<u64>,
}

impl FsckProgress {
    fn new(label: String) -> Self {
        use std::io::IsTerminal;
        Self {
            label,
            tty: std::io::stderr().is_terminal(),
            last_step: None,
        }
    }

    fn update(&mut self, done: u64, total: u64) {
        let per_mille = if total == 0 {
            1000
        } else {
            (done.min(total) as u128 * 1000 / total as u128) as u64
        };
        let step = if self.tty { per_mille } else { per_mille / 100 * 100 };
        if self.last_step == Some(step) {
            return;
        }
        self.last_step = Some(step);
        let line = format!(
            "{}: {} / {} ({}.{}%)",
            self.label,
            appendfs::stats::format_bytes(done.min(total)),
            appendfs::stats::format_bytes(total),
            per_mille / 10,
            per_mille % 10
        );
        if self.tty {
            // \x1b[K clears what is left of a longer previous line.
            eprint!("\r{}\x1b[K", line);
            if per_mille == 1000 {
                eprintln!();
            }
        } else {
            eprintln!("{}", line);
        }
    }
}

fn resolve_fsck_target_remotes(args: &FsckArgs, registry: &appendfs::remote::RemoteRegistry) -> Vec<String> {
    let mut target_remotes = Vec::new();
    if args.remotes.is_empty() {
        return target_remotes;
    }

    if args.remotes.iter().any(|r| r == "all") {
        target_remotes = registry.remotes.keys().cloned().collect();
        if target_remotes.is_empty() {
            eprintln!("Warning: --remotes all specified, but no remotes configured in remotes.toml.");
        } else if args.is_verify_data()
            && !registry.remotes.values().any(|c| c.mode.is_readable())
            && !args.remotes.iter().any(|r| r == "local")
        {
            eprintln!("Error: All configured remotes in 'all' are write-only and cannot be data verified.");
            std::process::exit(1);
        }
    } else {
        for r in &args.remotes {
            if r != "local" {
                match registry.get_remote(r) {
                    None => {
                        eprintln!("Error: Remote '{}' is not configured in remotes.toml.", r);
                        std::process::exit(1);
                    }
                    Some(cfg) if args.is_verify_data() && !cfg.mode.is_readable() => {
                        eprintln!(
                            "Error: Remote '{}' is configured as write-only and cannot be data verified.",
                            r
                        );
                        std::process::exit(1);
                    }
                    _ => {}
                }
            }
            target_remotes.push(r.clone());
        }
    }
    target_remotes
}

fn cmd_fsck(args: FsckArgs) {
    let log_dir = &args.log_dir;

    if let Some(pct) = args.sample_percent
        && (pct.is_nan() || pct <= 0.0 || pct > 100.0)
    {
        eprintln!(
            "Error: --sample-percent must be greater than 0.0 and at most 100.0 (got {})",
            pct
        );
        std::process::exit(1);
    }

    let OpenVolumeStorage { storage, volume_key } = match open_volume_storage(log_dir, args.key_file.as_deref()) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let registry = load_remote_registry(storage.as_ref());
    let target_remotes = resolve_fsck_target_remotes(&args, &registry);

    let mut check_options = CheckOptions {
        verify_data: args.is_verify_data(),
        sample_percent: args.effective_sample_percent().unwrap_or(100.0),
        remotes: target_remotes.clone(),
        seed: args.seed,
    };
    if check_options.verify_data && check_options.seed.is_none() {
        check_options.seed = Some(rand::random());
    }

    eprintln!("Recovering filesystem from '{}'...", log_dir.display());
    let mut fs = match recover_fs(
        storage.clone(),
        appendfs::log::RecoveryTarget::Latest,
        Arc::new(SystemClock),
        volume_key,
    ) {
        Ok(fs) => fs,
        Err(e) => {
            eprintln!("Failed to recover filesystem for integrity check: {}", e);
            std::process::exit(1);
        }
    };
    fs.set_storage(storage.clone());
    fs.set_remote_registry(Arc::new(std::sync::RwLock::new(registry.clone())));

    let mut combined_report = appendfs::IntegrityReport::default();
    let manifest = fs.manifest.read().unwrap().clone();

    // 1. If remotes were specified, check each remote's objects against manifest
    if !target_remotes.is_empty() {
        for remote_name in &target_remotes {
            if remote_name == "local" {
                continue;
            }
            if let Some(remote_cfg) = registry.get_remote(remote_name) {
                let store = registry
                    .store_overrides
                    .get(remote_name)
                    .cloned()
                    .unwrap_or_else(|| remote_cfg.build_store());
                let remote_opts = if remote_cfg.is_local_dir() && remote_cfg.mode.is_readable() {
                    check_options.clone()
                } else {
                    CheckOptions::metadata_only()
                };
                eprintln!("Checking remote '{}'...", remote_name);
                let mut progress = FsckProgress::new(format!("Verifying remote '{}'", remote_name));
                let remote_rep = check_remote_integrity(
                    store.as_ref(),
                    remote_name,
                    &manifest,
                    &remote_opts,
                    Some(&mut |done, total| progress.update(done, total)),
                );
                combined_report.merge(remote_rep);
            }
        }
    }

    // 2. Pre-flight check & confirmation for sampled / full remote verification
    let plan = if check_options.verify_data {
        let p = plan_sampled_verification(&fs, &check_options);
        let egress_bytes = p.total_remote_egress_bytes(&manifest);

        if egress_bytes > 0 && !args.yes {
            confirm_remote_egress(&p, &manifest);
        }
        Some(p)
    } else {
        None
    };

    // 3. Run filesystem integrity check (Pass 0-4 + sampled verification)
    eprintln!("Checking filesystem integrity...");
    let mut progress = FsckProgress::new("Verifying data".to_string());
    let fs_report = check_fs_integrity(
        &fs,
        Some(log_dir),
        &check_options,
        plan.as_ref(),
        Some(&mut |done, total| progress.update(done, total)),
    );
    combined_report.merge(fs_report);

    print!("{}", combined_report.format_report(Some(log_dir), args.verbose > 0));
    if !combined_report.is_clean() {
        std::process::exit(1);
    }
}

fn cmd_backfill_salts(args: BackfillSaltsArgs) {
    let OpenVolumeStorage { storage, volume_key } = match open_volume_storage(&args.log_dir, args.key_file.as_deref()) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let registry = load_remote_registry(storage.as_ref());
    let remote_stores = registry.build_read_stores();

    let cache_dir = args.log_dir.join(".cache");
    let block_cache: Arc<dyn appendfs::remote::BlockCache> =
        match appendfs::remote::OnDiskBlockCache::new(&cache_dir, 512 * 1024 * 1024, Arc::new(SystemClock)) {
            Ok(c) => Arc::new(c),
            Err(_) => Arc::new(appendfs::remote::MemoryBlockCache::new(64 * 1024 * 1024)),
        };

    let clock = SystemClock;
    match appendfs::backfill_summary_salts(
        storage,
        &volume_key,
        &clock,
        remote_stores,
        Some(block_cache),
        args.force,
    ) {
        Ok(Some(new_summary)) => {
            println!("Successfully backfilled key salts into new summary: {}", new_summary);
        }
        Ok(None) => {
            println!("Summary already contains all log key salts; no update needed.");
        }
        Err(e) => {
            eprintln!("Failed to backfill summary salts: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_remote(subargs: RemoteSubcommandArgs) {
    match subargs.command {
        RemoteCommands::Add(add_args) => cmd_remote_add(add_args),
        RemoteCommands::Rm(rm_args) => cmd_remote_rm(rm_args),
        RemoteCommands::List(list_args) => cmd_remote_list(list_args),
    }
}

fn cmd_remote_add(add_args: RemoteAddArgs) {
    let storage = OsStorage::new(&add_args.log_dir);
    let mut registry = load_remote_registry(&storage);
    let mut cfg = if let Some(ref p) = add_args.path {
        appendfs::remote::RemoteTargetConfig::new_path(p)
    } else if let Some(ref b) = add_args.bucket {
        appendfs::remote::RemoteTargetConfig::new(b)
    } else {
        eprintln!("Error: Either --path or --bucket must be specified when adding a remote.");
        std::process::exit(1);
    };
    cfg.endpoint = add_args.endpoint;
    cfg.region = add_args.region;
    cfg.prefix = add_args.prefix;
    cfg.mode = add_args.mode;
    cfg.replicate_ancestors = add_args.replicate_ancestors;
    if let Some(prio) = add_args.read_priority {
        cfg.read_priority = prio;
    }
    cfg.access_key_id = add_args.access_key_id;
    cfg.secret_access_key = add_args.secret_access_key;
    cfg.access_key_id_env = add_args.access_key_id_env;
    cfg.secret_access_key_env = add_args.secret_access_key_env;
    if let Some(ref creds_file) = add_args.credentials_file
        && let Err(e) = appendfs::remote::read_credentials_file(creds_file)
    {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
    cfg.credentials_file = add_args.credentials_file;
    cfg.storage_class = add_args.storage_class;
    if add_args.no_upload_partial_logs && add_args.upload_partial_logs.is_some() {
        eprintln!("Error: Cannot specify both --upload-partial-logs and --no-upload-partial-logs.");
        std::process::exit(1);
    }
    if add_args.no_upload_partial_logs {
        cfg.upload_partial_logs = Some(false);
    } else if let Some(upl) = add_args.upload_partial_logs {
        cfg.upload_partial_logs = Some(upl);
    }

    if let Err(e) = cfg.validate(&add_args.name) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    registry.add_remote(&add_args.name, cfg);
    if let Err(e) = registry.save_to_storage(&storage) {
        eprintln!("Failed to save remotes.toml in '{}': {}", add_args.log_dir.display(), e);
        std::process::exit(1);
    }
    println!(
        "Successfully added remote '{}' in '{}'",
        add_args.name,
        add_args.log_dir.display()
    );
}

fn cmd_remote_rm(rm_args: RemoteRmArgs) {
    let storage = OsStorage::new(&rm_args.log_dir);
    let mut registry = load_remote_registry(&storage);
    if registry.remove_remote(&rm_args.name) {
        if let Err(e) = registry.save_to_storage(&storage) {
            eprintln!("Failed to save remotes.toml in '{}': {}", rm_args.log_dir.display(), e);
            std::process::exit(1);
        }
        println!("Removed remote '{}' from '{}'", rm_args.name, rm_args.log_dir.display());
    } else {
        eprintln!("Error: Remote '{}' was not configured.", rm_args.name);
        std::process::exit(1);
    }
}

fn cmd_remote_list(list_args: RemoteListArgs) {
    let storage = OsStorage::new(&list_args.log_dir);
    let registry = load_remote_registry(&storage);
    if registry.remotes.is_empty() {
        println!("No remotes configured in '{}'.", list_args.log_dir.display());
    } else {
        println!("Configured remotes in '{}':", list_args.log_dir.display());
        let mut sorted_remotes: Vec<_> = registry.remotes.iter().collect();
        sorted_remotes.sort_by_key(|(name, cfg)| (cfg.read_priority, (*name).clone()));
        for (name, cfg) in sorted_remotes {
            if let Some(ref p) = cfg.path {
                println!(
                    "  - {}: type='local/nfs', path='{}', priority={}, mode='{}', partial_logs={}",
                    name,
                    p.display(),
                    cfg.read_priority,
                    cfg.mode,
                    if cfg.upload_partial_logs() {
                        "Enabled"
                    } else {
                        "Disabled"
                    },
                );
            } else {
                let sc_str = cfg
                    .storage_class
                    .as_deref()
                    .map(|sc| format!(", storage_class='{}'", sc))
                    .unwrap_or_default();
                println!(
                    "  - {}: type='s3', bucket='{}', priority={}, region='{}', mode='{}', partial_logs={}, endpoint={:?}, prefix='{}'{}",
                    name,
                    cfg.bucket.as_deref().unwrap_or(""),
                    cfg.read_priority,
                    cfg.region,
                    cfg.mode,
                    if cfg.upload_partial_logs() {
                        "Enabled"
                    } else {
                        "Disabled"
                    },
                    cfg.endpoint,
                    cfg.prefix,
                    sc_str
                );
            }
        }
    }
}

/// Prints a volume's identity: what it is and what unlocks it. Needs no credentials,
/// because the header sits in plaintext ahead of the encrypted summary body.
fn print_volume_identity(log_dir: &Path, header: &VolumeHeader) {
    println!("=== Volume ===");
    println!("Volume:        {}", log_dir.display());
    println!("Cipher Suite:  {}", header.cipher);
    println!("Compression:   {}", header.compression);
    println!("Volume ID:     {}", hex_string(&header.volume_id));
    println!();
}

/// Explains the credential situation. Only printed when the volume could not be opened,
/// which is exactly when someone needs to know what to supply.
fn print_credential_help(header: &VolumeHeader) {
    if header.cipher.is_encrypted() {
        eprintln!();
        eprintln!("Encrypted volumes are unlocked with --key-file; the key file is not");
        eprintln!("stored here. Back it up: losing it loses the volume.");
        if header.compression.is_enabled() {
            eprintln!();
            eprintln!("Compressed records reveal roughly how compressible their contents");
            eprintln!("were, which encryption alone does not. Sizes leak; contents do not.");
        }
    } else {
        eprintln!();
        eprintln!("Volume is unencrypted, and cannot be encrypted in place.");
        eprintln!("Encryption is chosen at init time - 'appendfs init --key-file <file>' -");
        eprintln!("and fixed for the life of the volume.");
    }
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn prompt_new_passphrase(prompt: &str, confirm_prompt: &str) -> Result<Zeroizing<String>, String> {
    use std::io::IsTerminal;
    let p1 = prompt_passphrase(prompt).map_err(|e| format!("Could not read passphrase: {}", e))?;
    if p1.is_empty() || !std::io::stdin().is_terminal() {
        return Ok(p1);
    }
    let p2 = prompt_passphrase(confirm_prompt).map_err(|e| format!("Could not read passphrase confirmation: {}", e))?;
    if p1 != p2 {
        return Err("Passphrases do not match".to_string());
    }
    Ok(p1)
}

/// Fails early if `path` is taken, so nobody types a passphrase only to be told the output
/// cannot be written. [`write_new_key_file`] enforces the same thing when it creates the file.
fn refuse_existing_output(path: &Path) -> Result<(), String> {
    if std::fs::symlink_metadata(path).is_ok() {
        return Err(format!(
            "'{}' already exists; key files are never overwritten",
            path.display()
        ));
    }
    Ok(())
}

/// Writes `key` to the new file `path`, wrapped under `passphrase` unless it is empty.
fn write_key_file(path: &Path, key: &MasterKey, passphrase: &str) -> Result<(), String> {
    let content = if passphrase.is_empty() {
        format_plain_key_file(key)
    } else {
        Zeroizing::new(
            format_encrypted_key_file(key, passphrase).map_err(|e| format!("Error encrypting key file: {}", e))?,
        )
    };
    write_new_key_file(path, content.as_bytes()).map_err(|e| e.to_string())
}

fn cmd_key(args: KeySubcommandArgs) {
    match args.command {
        KeyCommands::Init(subargs) => cmd_key_init(subargs),
        KeyCommands::ChangePassphrase(subargs) => cmd_key_change_passphrase(subargs),
    }
}

fn cmd_key_init(args: KeyInitArgs) {
    let output = &args.output;
    let result = (|| {
        refuse_existing_output(output)?;
        let passphrase = prompt_new_passphrase("Enter passphrase (empty for none): ", "Confirm passphrase: ")?;
        write_key_file(output, &MasterKey::generate(), &passphrase)?;
        Ok::<_, String>(if passphrase.is_empty() {
            format!("Generated unencrypted key file: {}", output.display())
        } else {
            format!("Generated passphrase-encrypted key file: {}", output.display())
        })
    })();
    match result {
        Ok(message) => println!("{}", message),
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_key_change_passphrase(args: KeyChangePassphraseArgs) {
    let (input, output) = (&args.key_file, &args.output);
    let result = (|| {
        refuse_existing_output(output)?;
        let key_file = KeyFile::read(input).map_err(|e| e.to_string())?;
        let was_encrypted = key_file.is_encrypted();
        let key = key_file
            .unlock(|| {
                prompt_passphrase(&format!(
                    "Enter current passphrase for key file '{}': ",
                    input.display()
                ))
            })
            .map_err(|e| format!("cannot unlock key file '{}': {}", input.display(), e))?;

        let passphrase = prompt_new_passphrase("Enter new passphrase (empty for none): ", "Confirm new passphrase: ")?;
        write_key_file(output, &key, &passphrase)?;

        let shown = output.display();
        Ok::<_, String>(match (was_encrypted, passphrase.is_empty()) {
            (true, false) => format!("Wrote key file with the new passphrase: {}", shown),
            (false, false) => format!("Wrote passphrase-protected key file: {}", shown),
            (true, true) => format!("Wrote key file without passphrase protection: {}", shown),
            (false, true) => format!("Wrote key file, still without passphrase protection: {}", shown),
        })
    })();
    match result {
        Ok(message) => {
            println!("{}", message);
            println!(
                "'{}' is unchanged. Once the new key file is safely in place, remove or shred it.",
                input.display()
            );
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}
