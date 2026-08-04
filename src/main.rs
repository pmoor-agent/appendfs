use appendfs::cli::{CliArgs, find_latest_generation};
use appendfs::clock::SystemClock;
use appendfs::log::{BackgroundFlusher, LogWriter};
use appendfs::{InMemoryFS, recover_fs};
use clap::Parser;
use std::sync::Arc;
use std::time::Duration;

fn main() {
    env_logger::init();
    let args = CliArgs::parse();
    let clock = SystemClock;
    let log_dir = &args.log_dir;

    let (mut fs_instance, next_gen) = if log_dir.exists() && find_latest_generation(log_dir) > 0 {
        let latest = find_latest_generation(log_dir);
        println!(
            "Recovering appendfs state from log directory '{:?}' (latest generation: {})...",
            log_dir, latest
        );
        let fs = recover_fs(log_dir).expect("Failed to recover log directory");
        (fs, latest + 1)
    } else {
        println!(
            "Initializing fresh appendfs log directory at '{:?}' (generation 1)...",
            log_dir
        );
        (InMemoryFS::new(), 1)
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
    fs_instance.log_writer = Some(Arc::clone(&writer));
    fs_instance.set_log_dir(log_dir);

    // Start background flusher thread if flush_interval > 0
    let _flusher_guard = if args.flush_interval > 0 {
        println!(
            "Starting background periodic log flusher (interval: {} seconds)...",
            args.flush_interval
        );
        Some(BackgroundFlusher::start(
            Arc::clone(&fs_instance.log_buffer),
            Arc::clone(&writer),
            Duration::from_secs(args.flush_interval),
        ))
    } else {
        println!("Background periodic log flusher disabled.");
        None
    };

    println!(
        "Mounting appendfs at '{:?}' with log-dir '{:?}' (generation: {}, max-log-size: {} bytes, foreground: {})...",
        args.mount_point, args.log_dir, next_gen, args.max_log_size, args.foreground
    );

    let fuse_args = args.to_fuse_args();
    if let Err(err) = appendfs::mount(fuse_args, fs_instance) {
        eprintln!("Failed to mount appendfs FUSE filesystem: {}", err);
        std::process::exit(1);
    }
}
