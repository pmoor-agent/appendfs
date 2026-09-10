//! Generates deterministic AppendFS golden compatibility fixtures.
//!
//! # Usage
//! ```bash
//! # Regenerate v1 plaintext fixtures:
//! cargo run --bin generate_compat_fixture tests/fixtures/v1
//!
//! # Regenerate v1 encrypted fixtures:
//! cargo run --bin generate_compat_fixture tests/fixtures/v1_encrypted
//!
//! # Generate fixtures for a new format version (e.g. v2):
//! cargo run --bin generate_compat_fixture tests/fixtures/v2
//! ```

use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: generate_compat_fixture <directory>");
        std::process::exit(1);
    }
    let out_dir = PathBuf::from(&args[1]);
    let is_encrypted = out_dir.to_string_lossy().contains("encrypted");

    println!(
        "Generating AppendFS format compatibility fixtures in: {} (encrypted: {})",
        out_dir.display(),
        is_encrypted
    );

    let res = if is_encrypted {
        println!(
            "Using canonical passphrase: '{}'",
            appendfs::compat::COMPAT_ENCRYPTED_PASSPHRASE
        );
        appendfs::compat::create_canonical_compat_volume_encrypted(
            &out_dir,
            appendfs::compat::COMPAT_ENCRYPTED_PASSPHRASE,
        )
    } else {
        appendfs::compat::create_canonical_compat_volume(&out_dir)
    };

    if let Err(e) = res {
        eprintln!("Error generating compatibility fixture: {}", e);
        std::process::exit(1);
    }
    println!("Successfully generated fixtures:");
    for name in appendfs::compat::COMPAT_FIXTURE_FILES
        .iter()
        .chain(appendfs::compat::COMPAT_FIXTURE_DUMP_FILES.iter())
    {
        println!("  - {}", out_dir.join(name).display());
    }
}
