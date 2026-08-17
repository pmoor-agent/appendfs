use appendfs::cli::{Cli, Commands};
use appendfs::log::LogWriter;
use appendfs::{VolumeStats, init_volume, recover_fs};
use clap::Parser;
use std::sync::Arc;

fn main() {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Init(args) => {
            println!(
                "Initializing appendfs volume at '{:?}' (branch: {})...",
                args.log_dir, args.branch
            );
            match init_volume(&args.log_dir, Some(&args.branch)) {
                Ok(summary_path) => {
                    println!("Initialized empty appendfs volume successfully!");
                    println!("  Log Directory:   {:?}", args.log_dir);
                    println!(
                        "  Summary File:    {:?}",
                        summary_path.file_name().unwrap_or_default()
                    );
                    println!("  Branch:          {}", args.branch);
                    println!("  Root Inode:      1 (/)");
                    println!("  Next Generation: 1 (000001.log)");
                }
                Err(e) => {
                    eprintln!("Failed to initialize volume in '{:?}': {}", args.log_dir, e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Mount(args) => {
            let log_dir = &args.log_dir;
            if !log_dir.exists() {
                eprintln!("Error: Log directory '{:?}' does not exist.", log_dir);
                eprintln!(
                    "Run 'appendfs init {:?}' to create a new volume first.",
                    log_dir
                );
                std::process::exit(1);
            }

            println!(
                "Recovering appendfs state from log directory '{:?}'...",
                log_dir
            );
            let mut fs_instance = match recover_fs(log_dir) {
                Ok(fs) => fs,
                Err(e) => {
                    eprintln!("Failed to recover volume from '{:?}': {}", log_dir, e);
                    std::process::exit(1);
                }
            };

            let next_gen = {
                let manifest = fs_instance.manifest.read().unwrap();
                manifest.next_generation
            };

            let start_tx = fs_instance
                .last_tx_id
                .load(std::sync::atomic::Ordering::SeqCst)
                + 1;

            let writer = Arc::new(LogWriter::create_lazy(
                log_dir,
                next_gen,
                args.max_log_size,
                start_tx,
            ));

            fs_instance.log_writer = Some(Arc::clone(&writer));
            fs_instance.max_buffer_size = args.flush_threshold;
            fs_instance.max_staged_ops = args.flush_threshold_ops;
            fs_instance
                .flush_interval
                .store(args.flush_interval, std::sync::atomic::Ordering::SeqCst);
            fs_instance.set_log_dir(log_dir);

            let fs_instance = Arc::new(fs_instance);

            println!(
                "Mounting appendfs at '{:?}' with log-dir '{:?}' (active generation: {}, flush-threshold: {} bytes, flush-ops: {}, flush-interval: {}s, max-log-size: {} bytes, foreground: {})...",
                args.mount_point, args.log_dir, next_gen, args.flush_threshold, args.flush_threshold_ops, args.flush_interval, args.max_log_size, args.foreground
            );

            let fuse_args = args.to_fuse_args();
            if let Err(err) = appendfs::mount_arc(fuse_args, fs_instance) {
                eprintln!("Failed to mount appendfs FUSE filesystem: {}", err);
                std::process::exit(1);
            }
        }
        Commands::MountRo(args) | Commands::Mountro(args) => {
            let log_dir = &args.log_dir;
            if !log_dir.exists() {
                eprintln!("Error: Log directory '{:?}' does not exist.", log_dir);
                std::process::exit(1);
            }

            let target = if let Some(tx_id) = args.tx_id {
                appendfs::RecoveryTarget::TxId(tx_id)
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
                "Recovering appendfs state (read-only, target: {:?}) from '{:?}'...",
                target, log_dir
            );
            let mut fs_instance = match appendfs::recover_fs_to_target(log_dir, target) {
                Ok(fs) => fs,
                Err(e) => {
                    eprintln!("Failed to recover volume from '{:?}': {}", log_dir, e);
                    std::process::exit(1);
                }
            };
            fs_instance.set_log_dir(log_dir);
            fs_instance.set_read_only(true);

            let effective_tx_id = fs_instance.last_tx_id.load(std::sync::atomic::Ordering::SeqCst);
            let effective_gen = {
                let manifest = fs_instance.manifest.read().unwrap();
                manifest.logs.last().map(|l| l.generation).unwrap_or(1)
            };
            let effective_time_str = fs_instance.recovered_time().map_or_else(
                || "N/A".to_string(),
                |t| appendfs::format_local_civil_time(t),
            );

            println!(
                "Recovered appendfs state (read-only) -> Effective Version: generation {}, last tx_id: {}, timestamp: {}",
                effective_gen, effective_tx_id, effective_time_str
            );
            println!(
                "Mounting appendfs (read-only) at '{:?}' with log-dir '{:?}' (foreground: {})...",
                args.mount_point, args.log_dir, args.foreground
            );

            let fs_instance = Arc::new(fs_instance);
            let fuse_args = args.to_fuse_args();
            if let Err(err) = appendfs::mount_ro_arc(fuse_args, fs_instance) {
                eprintln!("Failed to mount read-only appendfs FUSE filesystem: {}", err);
                std::process::exit(1);
            }
        }
        Commands::Stats(args) => {
            let log_dir = &args.log_dir;
            if !log_dir.exists() {
                eprintln!("Error: Log directory '{:?}' does not exist.", log_dir);
                std::process::exit(1);
            }

            let fs = match recover_fs(log_dir) {
                Ok(fs) => fs,
                Err(e) => {
                    eprintln!("Failed to inspect volume from '{:?}': {}", log_dir, e);
                    std::process::exit(1);
                }
            };

            let stats = VolumeStats::collect(&fs);
            print!("{}", stats.display_text());
        }
        Commands::Dump(args) => {
            let file_path = &args.file;
            if !file_path.exists() {
                eprintln!("Error: File '{:?}' does not exist.", file_path);
                std::process::exit(1);
            }

            match appendfs::dump_file(file_path, args.verbose) {
                Ok(output) => print!("{}", output),
                Err(e) => {
                    eprintln!("Error dumping file '{:?}': {}", file_path, e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Check(args) | Commands::Fsck(args) => {
            let log_dir = &args.log_dir;
            if !log_dir.exists() {
                eprintln!("Error: Log directory '{:?}' does not exist.", log_dir);
                std::process::exit(1);
            }

            match appendfs::check_volume(log_dir, args.verify_data) {
                Ok(report) => {
                    print!("{}", report.format_report(Some(log_dir), args.verbose > 0));
                    if !report.is_clean() {
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("Failed to check volume integrity at '{:?}': {}", log_dir, e);
                    std::process::exit(1);
                }
            }
        }
    }
}
