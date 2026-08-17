use appendfs::cli::{Cli, Commands};
use appendfs::clock::SystemClock;
use appendfs::log::{BackgroundFlusher, LogWriter};
use appendfs::{VolumeStats, init_volume, recover_fs};
use clap::Parser;
use std::sync::Arc;
use std::time::Duration;

fn main() {
    env_logger::init();
    let cli = Cli::parse();
    let clock = SystemClock;

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
                    eprintln!("Error initializing volume: {}", e);
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

            let (next_gen, next_filename) = {
                let manifest = fs_instance.manifest.read().unwrap();
                (manifest.next_generation, manifest.next_filename.clone())
            };

            let start_tx = fs_instance
                .last_tx_id
                .load(std::sync::atomic::Ordering::SeqCst)
                + 1;

            let writer = Arc::new(
                LogWriter::create_with_max_size_and_start_tx(
                    log_dir,
                    next_gen,
                    &clock,
                    args.max_log_size,
                    start_tx,
                )
                .expect("Failed to create log writer for generation"),
            );

            {
                let mut manifest = fs_instance.manifest.write().unwrap();
                if manifest.get_by_generation(next_gen).is_none() {
                    manifest.record_roll(
                        next_gen,
                        next_filename,
                        appendfs::log::record::FILE_HEADER_SIZE as u64,
                    );
                }
            }

            fs_instance.log_writer = Some(Arc::clone(&writer));
            fs_instance.set_log_dir(log_dir);

            let fs_instance = Arc::new(fs_instance);
            let fs_clone = Arc::clone(&fs_instance);

            // Start background flusher thread if flush_interval > 0
            let _flusher_guard = if args.flush_interval > 0 {
                println!(
                    "Starting background periodic log flusher (interval: {} seconds)...",
                    args.flush_interval
                );
                Some(BackgroundFlusher::start(
                    move || fs_clone.flush_log(),
                    Duration::from_secs(args.flush_interval),
                ))
            } else {
                println!("Background periodic log flusher disabled.");
                None
            };

            println!(
                "Mounting appendfs at '{:?}' with log-dir '{:?}' (active generation: {}, max-log-size: {} bytes, foreground: {})...",
                args.mount_point, args.log_dir, next_gen, args.max_log_size, args.foreground
            );

            let fuse_args = args.to_fuse_args();
            if let Err(err) = appendfs::mount_arc(fuse_args, fs_instance) {
                eprintln!("Failed to mount appendfs FUSE filesystem: {}", err);
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
                eprintln!("Error: Log file '{:?}' does not exist.", file_path);
                std::process::exit(1);
            }

            match appendfs::dump_log_file(file_path, args.verbose) {
                Ok(output) => print!("{}", output),
                Err(e) => {
                    eprintln!("Error dumping log file '{:?}': {}", file_path, e);
                    std::process::exit(1);
                }
            }
        }
    }
}
