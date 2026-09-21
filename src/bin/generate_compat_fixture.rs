//! Generates deterministic AppendFS golden compatibility fixtures.
//!
//! # Usage
//! ```bash
//! # Regenerate all canonical golden fixtures:
//! cargo run --bin generate_compat_fixture
//! cargo run --bin generate_compat_fixture --all
//!
//! # Regenerate specific fixtures:
//! cargo run --bin generate_compat_fixture tests/fixtures/v1
//! cargo run --bin generate_compat_fixture tests/fixtures/v1_passphrase_compressed
//! cargo run --bin generate_compat_fixture tests/fixtures/v1_secret_key_passphrase_compressed
//!
//! # Generate fixtures for a new format version (e.g. v2):
//! cargo run --bin generate_compat_fixture tests/fixtures/v2
//! ```

use appendfs::compat::{
    COMPAT_ENCRYPTED_PASSPHRASE, COMPAT_FIXTURE_DUMP_FILES, COMPAT_FIXTURE_FILES, COMPAT_KEY_FILENAME,
    CompatFixtureConfig, create_canonical_compat_volume,
};
use std::path::{Path, PathBuf};

fn generate_one(out_dir: &Path, config: CompatFixtureConfig) {
    println!(
        "Generating AppendFS format compatibility fixtures in: {} (config: {:?})",
        out_dir.display(),
        config
    );
    if config.is_encrypted() {
        println!("Using canonical passphrase: '{}'", COMPAT_ENCRYPTED_PASSPHRASE);
    }

    if let Err(e) = create_canonical_compat_volume(out_dir, config) {
        eprintln!("Error generating compatibility fixture in {}: {}", out_dir.display(), e);
        std::process::exit(1);
    }
    println!("Successfully generated fixtures:");
    for name in COMPAT_FIXTURE_FILES.iter().chain(COMPAT_FIXTURE_DUMP_FILES.iter()) {
        println!("  - {}", out_dir.join(name).display());
    }
    if config == CompatFixtureConfig::SecretKeyPassphraseCompressed {
        println!("  - {}", out_dir.join(COMPAT_KEY_FILENAME).display());
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 1 || (args.len() == 2 && args[1] == "--all") {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let fixtures_dir = manifest_dir.join("tests/fixtures");
        for config in CompatFixtureConfig::ALL {
            let out_dir = fixtures_dir.join(config.default_dir_name());
            generate_one(&out_dir, config);
        }
        return;
    }

    if args.len() != 2 {
        eprintln!("Usage: generate_compat_fixture [--all | <directory>]");
        std::process::exit(1);
    }

    let out_dir = PathBuf::from(&args[1]);
    let config = CompatFixtureConfig::from_dir_path(&out_dir).unwrap_or(CompatFixtureConfig::UnencryptedUncompressed);

    generate_one(&out_dir, config);
}
