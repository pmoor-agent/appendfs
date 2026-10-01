#![cfg_attr(not(test), deny(clippy::too_many_lines))]
use appendfs::cli::{
    Cli, Commands, DumpArgs, FsckArgs, InitArgs, MountArgs, MountCommonArgs, MountRoArgs, RemoteAddArgs,
    RemoteCommands, RemoteListArgs, RemoteRmArgs, RemoteSubcommandArgs, StatsArgs,
};
use appendfs::clock::SystemClock;
use appendfs::crypto::{
    CipherSuite, KeySource, MasterKey, VolumeHeader, VolumeKey, generate_random_16, prompt_passphrase,
};
use appendfs::log::{LogWriter, SummaryReader};
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
    volume_header: VolumeHeader,
}

struct OpenVolumeFS {
    fs: appendfs::InMemoryFS,
    storage: Arc<dyn Storage>,
    volume_key: Arc<VolumeKey>,
    volume_header: VolumeHeader,
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
fn open_volume_storage(
    log_dir: &Path,
    key_file: Option<&Path>,
    passphrase_flag: bool,
) -> Result<OpenVolumeStorage, String> {
    let VolumeHeaderInfo {
        storage,
        header: volume_header,
    } = read_volume_header_info(log_dir)?;

    if volume_header.cipher == CipherSuite::None {
        if key_file.is_some() {
            return Err("Volume is not encrypted; --key-file does not apply to it".to_string());
        }
        if passphrase_flag {
            return Err("Volume is not encrypted; --passphrase does not apply to it".to_string());
        }
        return Ok(OpenVolumeStorage {
            storage,
            volume_key: Arc::new(VolumeKey::plaintext_with_volume_id(volume_header.volume_id)),
            volume_header,
        });
    }

    // Which credentials to collect comes from the volume, not from which flags happen to be
    // present. Guessing here would report a credential-type mismatch as a wrong key, which
    // sends the user hunting for the wrong problem.
    let source = volume_header.key_source;
    if key_file.is_some() && !source.needs_key_file() {
        return Err(format!(
            "Volume is unlocked by: {}. It does not use a key file, so --key-file does not apply.",
            source
        ));
    }
    if source.needs_key_file() && key_file.is_none() {
        return Err(format!(
            "Volume is unlocked by: {}. Pass --key-file to unlock it.",
            source
        ));
    }
    if passphrase_flag && !source.needs_passphrase() {
        return Err(format!(
            "Volume is unlocked by: {}. It does not use a passphrase, so --passphrase does not apply.",
            source
        ));
    }

    let passphrase = if source.needs_passphrase() {
        // Without a terminal this fails with a bare errno, which says nothing about *why* a
        // passphrase was wanted - the common case being a script mounting a two-factor
        // volume with only `--key-file`.
        // Wrapped so the passphrase is wiped when it goes out of scope rather than left in
        // freed heap memory for whatever allocates next.
        Some(Zeroizing::new(
            prompt_passphrase(&format!("Enter passphrase for volume '{}': ", log_dir.display())).map_err(|e| {
                format!(
                    "Volume is unlocked by: {}. Could not prompt for its passphrase: {}",
                    source, e
                )
            })?,
        ))
    } else {
        None
    };

    let master_key = match (key_file, passphrase.as_deref()) {
        (Some(kf), Some(pass)) => {
            MasterKey::from_file_and_passphrase(kf, pass, &volume_header.kdf_salt).map_err(|e| e.to_string())?
        }
        (Some(kf), None) => MasterKey::from_file(kf).map_err(|e| e.to_string())?,
        (None, Some(pass)) => MasterKey::from_passphrase(pass, &volume_header.kdf_salt)
            .map_err(|e| format!("Key derivation error: {}", e))?,
        (None, None) => {
            return Err(format!(
                "Volume is unlocked by: {}, but no credential was supplied.",
                source
            ));
        }
    };

    // The key check value is verified here, before recovery reads a single record. Without
    // it a wrong key would surface as an authentication failure mid-replay, which is
    // indistinguishable from bitrot and reads to the user like their volume is destroyed.
    let volume_key = volume_header.unlock(&master_key).map_err(|e| e.to_string())?;
    Ok(OpenVolumeStorage {
        storage,
        volume_key: Arc::new(volume_key),
        volume_header,
    })
}

/// Opens an appendfs volume and recovers an in-memory filesystem instance up to `target`.
fn open_volume_fs(
    log_dir: &Path,
    key_file: Option<&Path>,
    passphrase_flag: bool,
    target: appendfs::RecoveryTarget,
) -> Result<OpenVolumeFS, String> {
    let OpenVolumeStorage {
        storage,
        volume_key,
        volume_header,
    } = open_volume_storage(log_dir, key_file, passphrase_flag)?;
    let fs = recover_fs(storage.clone(), target, Arc::new(SystemClock), volume_key.clone())
        .map_err(|e| format!("Failed to recover volume from '{}': {}", log_dir.display(), e))?;
    Ok(OpenVolumeFS {
        fs,
        storage,
        volume_key,
        volume_header,
    })
}

/// Collects the credentials for a brand new volume, returning the key and the KDF salt to
/// record in its header.
///
/// Only `init` calls this, so passphrases are always confirmed and the salt is always freshly
/// minted; an existing volume's key is resolved by [`resolve_volume_key`] instead.
fn prompt_master_key(source: KeySource, key_file: Option<&Path>) -> Result<(MasterKey, [u8; 16]), String> {
    let passphrase = if source.needs_passphrase() {
        let ask =
            |prompt: &str| prompt_passphrase(prompt).map_err(|e| format!("Could not prompt for a passphrase: {}", e));
        let p1 = ask("Enter passphrase: ")?;
        let p2 = ask("Confirm passphrase: ")?;
        if p1 != p2 {
            return Err("Passphrases do not match".to_string());
        }
        if p1.is_empty() {
            return Err("Passphrase must not be empty".to_string());
        }
        Some(p1)
    } else {
        None
    };

    match (key_file, passphrase.as_deref()) {
        // A key file alone carries a full 256 bits, so there is nothing to stretch and the
        // salt stays zero and unused.
        (Some(kf), None) => Ok((MasterKey::from_file(kf).map_err(|e| e.to_string())?, [0u8; 16])),
        (Some(kf), Some(pass)) => {
            let salt = generate_random_16();
            let key = MasterKey::from_file_and_passphrase(kf, pass, &salt).map_err(|e| e.to_string())?;
            Ok((key, salt))
        }
        (None, Some(pass)) => {
            let salt = generate_random_16();
            let key = MasterKey::from_passphrase(pass, &salt).map_err(|e| format!("Key derivation error: {}", e))?;
            Ok((key, salt))
        }
        (None, None) => Err(format!(
            "Cannot initialize an encrypted volume with key source {}",
            source
        )),
    }
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
        // `dump` names a log file rather than a volume, so log beside it.
        Commands::Dump(args) => (args.file.parent()?.to_path_buf(), false),
        Commands::Remote(sub) => match sub.command {
            appendfs::cli::RemoteCommands::Add(ref a) => (a.log_dir.clone(), false),
            appendfs::cli::RemoteCommands::Rm(ref a) => (a.log_dir.clone(), false),
            appendfs::cli::RemoteCommands::List(ref a) => (a.log_dir.clone(), false),
        },
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

        let remote_cfg = if let Some(cfg) = registry.get_remote(remote_name) {
            if cfg.mode == appendfs::remote::RemoteMode::WriteOnly {
                eprintln!("Error: Cannot bootstrap an initial filesystem from a write-only remote.");
                std::process::exit(1);
            }
            cfg.clone()
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

    let key_source = args.key_source();
    if key_source != KeySource::None {
        let (master_key, salt) = match prompt_master_key(key_source, args.key_file.as_deref()) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        };

        let (volume_header, volume_key) =
            match VolumeHeader::new_encrypted(&master_key, salt, key_source, args.compression()) {
                Ok(res) => res,
                Err(e) => {
                    eprintln!("Failed to initialize volume encryption: {}", e);
                    std::process::exit(1);
                }
            };
        let volume_id = hex_string(&volume_header.volume_id);

        let storage: Arc<dyn Storage> = Arc::new(OsStorage::new(&args.log_dir));
        match init_volume(storage, &volume_key, volume_header) {
            Ok(summary_filename) => {
                println!("Initialized encrypted appendfs volume successfully!");
                println!("  Log Directory:   {}", args.log_dir.display());
                println!("  Summary File:    {}", summary_filename);
                println!("  Cipher:          ChaCha20-Poly1305");
                println!("  Unlocked by:     {}", key_source);
                println!("  Compression:     {}", args.compression());
                println!("  Volume ID:       {}", volume_id);
                println!("  Root Inode:      1 (/)");
                println!("  Next Generation: 1 (000001.log)");
                println!();
                println!("Back up your credentials now: they are not stored in the volume");
                println!("and cannot be recovered. Losing them loses the volume, and this");
                println!("choice cannot be changed later.");
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
        match init_volume(storage, &VolumeKey::plaintext(), volume_header) {
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

    let OpenVolumeFS {
        fs: mut fs_instance,
        storage,
        volume_key,
        volume_header,
    } = match open_volume_fs(
        log_dir,
        args.key_file.as_deref(),
        args.passphrase,
        appendfs::RecoveryTarget::Latest,
    ) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let next_gen = fs_instance.next_generation();

    let start_batch_id = fs_instance.last_batch_id.load(Ordering::SeqCst) + 1;

    // The volume header decides how writes are compressed; it was read back during
    // recovery, so a mount never has to be told separately.
    let compression = volume_header.compression;
    // The flusher checks `max_log_age` at the end of every cycle, so this one limit covers
    // both the CLI flag and the remote policy's `max_log_age_secs`; the tighter wins.
    let registry = load_remote_registry(storage.as_ref());
    let max_log_age = appendfs::clock::parse_duration(&args.max_log_age)
        .ok()
        .map(|cli| cli.min(std::time::Duration::from_secs(registry.policy.max_log_age_secs)));
    let writer = match LogWriter::create_lazy(storage.clone(), next_gen, args.max_log_size, start_batch_id, volume_key)
    {
        Ok(w) => Arc::new(w.with_compression(compression).with_max_log_age(max_log_age)),
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

    fs_instance.log_cache = Some(build_log_cache(
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
        next_gen,
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

    let OpenVolumeStorage {
        storage, volume_key, ..
    } = match open_volume_storage(log_dir, args.key_file.as_deref(), args.passphrase) {
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

    fs_instance.log_cache = Some(build_log_cache(&args, storage, remote_stores, &fs_instance.manifest));

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

    let OpenVolumeFS { fs, .. } = match open_volume_fs(
        &args.log_dir,
        args.key_file.as_deref(),
        args.passphrase,
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

    // Asking for neither credential dumps the raw on-disk bytes, which is a valid way
    // to inspect structure. Asking for either resolves against the volume's summary -
    // not against the file being dumped, which is usually a .log and carries no
    // volume header - and fails loudly rather than quietly falling back to a
    // ciphertext dump the user did not ask for. A passphrase volume needs the
    // explicit flag, since prompting whenever a volume happens to be encrypted would
    // make scripted raw dumps hang waiting on a terminal.
    let volume_key = if args.key_file.is_some() || args.passphrase {
        match open_volume_storage(parent, args.key_file.as_deref(), args.passphrase) {
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

    let OpenVolumeStorage {
        storage, volume_key, ..
    } = match open_volume_storage(log_dir, args.key_file.as_deref(), args.passphrase) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let registry = load_remote_registry(storage.as_ref());
    let mut target_remotes = Vec::new();
    if !args.remotes.is_empty() {
        if args.remotes.iter().any(|r| r == "all") {
            target_remotes = registry.remotes.keys().cloned().collect();
            if target_remotes.is_empty() {
                eprintln!("Warning: --remotes all specified, but no remotes configured in remotes.toml.");
            }
        } else {
            for r in &args.remotes {
                if r != "local" && registry.get_remote(r).is_none() {
                    eprintln!("Error: Remote '{}' is not configured in remotes.toml.", r);
                    std::process::exit(1);
                }
                target_remotes.push(r.clone());
            }
        }
    }

    let check_options = CheckOptions {
        verify_data: args.is_verify_data(),
        sample_percent: args.effective_sample_percent().unwrap_or(100.0),
        remotes: target_remotes.clone(),
        seed: args.seed,
    };

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
                let remote_rep = check_remote_integrity(store.as_ref(), remote_name, &manifest);
                combined_report.merge(remote_rep);
            }
        }
    }

    // 2. Pre-flight check & confirmation for sampled / full remote verification
    if check_options.verify_data {
        let plan = plan_sampled_verification(&fs, &check_options);
        let egress_bytes = plan.total_remote_egress_bytes(&manifest);

        if egress_bytes > 0 && !args.yes {
            confirm_remote_egress(&plan, &manifest);
        }
    }

    // 3. Run filesystem integrity check (Pass 0-4 + sampled verification)
    let fs_report = check_fs_integrity(&fs, Some(log_dir), &check_options);
    combined_report.merge(fs_report);

    print!("{}", combined_report.format_report(Some(log_dir), args.verbose > 0));
    if !combined_report.is_clean() {
        std::process::exit(1);
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
    cfg.credentials_file = add_args.credentials_file;
    cfg.force_path_style = add_args.path_style;
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
    if header.cipher.is_encrypted() {
        println!("Unlocked by:   {}", header.key_source);
    }
    println!();
}

/// Explains the credential situation. Only printed when the volume could not be opened,
/// which is exactly when someone needs to know what to supply.
fn print_credential_help(header: &VolumeHeader) {
    if header.cipher.is_encrypted() {
        eprintln!();
        eprintln!("Credentials are supplied per invocation and are not stored here.");
        eprintln!("Back them up: losing them loses the volume, and changing them means");
        eprintln!("re-encrypting into a fresh volume.");
        if header.compression.is_enabled() {
            eprintln!();
            eprintln!("Compressed records reveal roughly how compressible their contents");
            eprintln!("were, which encryption alone does not. Sizes leak; contents do not.");
        }
    } else {
        eprintln!();
        eprintln!("Volume is unencrypted, and cannot be encrypted in place.");
        eprintln!("Encryption is chosen at init time - 'appendfs init --key-file <file>'");
        eprintln!("and/or '--passphrase' - and fixed for the life of the volume.");
    }
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
