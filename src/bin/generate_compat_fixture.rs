//! Generates deterministic AppendFS golden compatibility fixtures.
//!
//! # Usage
//! ```bash
//! # Regenerate v1 fixtures:
//! cargo run --bin generate_compat_fixture tests/fixtures/v1
//!
//! # Generate fixtures for a new format version (e.g. v2):
//! cargo run --bin generate_compat_fixture tests/fixtures/v2
//! ```

use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let out_dir = if args.len() > 1 {
        PathBuf::from(&args[1])
    } else {
        PathBuf::from("tests/fixtures/v1")
    };

    println!(
        "Generating AppendFS format compatibility fixtures in: {}",
        out_dir.display()
    );
    if let Err(e) = appendfs::compat::create_canonical_compat_volume(&out_dir) {
        eprintln!("Error generating compatibility fixture: {}", e);
        std::process::exit(1);
    }
    println!("Successfully generated fixtures:");
    println!("  - {}", out_dir.join("000000.summary").display());
    println!("  - {}", out_dir.join("000001.log").display());
    println!("  - {}", out_dir.join("000001.summary").display());
}
