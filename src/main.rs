fn main() {
    let args: Vec<String> = std::env::args().collect();
    let fs = appendfs::InMemoryFS::new();

    println!("Starting concurrent low-level FUSE filesystem...");
    if let Err(err) = appendfs::mount(args, fs) {
        eprintln!("Failed to mount low-level FUSE filesystem: {}", err);
        std::process::exit(1);
    }
}
