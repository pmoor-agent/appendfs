# AppendFS Format Compatibility Fixtures

This directory contains checked-in golden on-disk storage fixtures used by `tests/compat_test.rs` to guarantee backward compatibility across format versions.

## Fixture Versions

- `v1/`: Plaintext uncompressed golden files for format version 1 (`RecordHeader` version 1, `SummaryHeader` version 1).
  - `000000.summary`: Initial volume summary snapshot.
  - `000001.log`: 3 flushed commit batches covering directories, files, symlinks, special files, and extended attributes.
  - `000001.summary`: Exported snapshot of all populated inodes.
  - `*-dump.txt`: Golden dump inspection outputs for summary and log files.
  - `fsck-report.txt`: Golden filesystem integrity check report under 100% data verification.

- `v1_key_file_compressed/`: ChaCha20-Poly1305 encrypted golden files under the key in `key.pem`, with Zstd record compression.
  - `key.pem`: Canonical unencrypted key file.
  - `000000.summary`: Initial volume summary snapshot (encrypted with explicit deterministic IV).
  - `000001.log`: 3 flushed encrypted and compressed commit batches.
  - `000001.summary`: Exported snapshot of all populated inodes (encrypted with explicit deterministic IV).
  - `*-dump.txt`: Golden decrypted dump inspection outputs.
  - `fsck-report.txt`: Golden filesystem integrity check report under 100% data verification.

- `v1_passphrase_compressed/`: Legacy fixture from a retired credential mode: the volume key was derived with Argon2id from the passphrase `"passphrase"` alone. That derived key now sits in `key.pem`, itself encrypted under the passphrase `"passphrase"`. Recovery-only: nothing can generate this fixture any more.
  - `key.pem`: Passphrase-encrypted key file holding the derived volume key.
  - `000000.summary`: Initial volume summary snapshot (encrypted with explicit deterministic IV).
  - `000001.log`: 3 flushed encrypted and compressed commit batches.
  - `000001.summary`: Exported snapshot of all populated inodes (encrypted with explicit deterministic IV).
  - `*-dump.txt`: Golden decrypted dump inspection outputs.
  - `fsck-report.txt`: Golden filesystem integrity check report under 100% data verification.

- `v1_secret_key_passphrase_compressed/`: Legacy fixture from a retired credential mode: the volume key was derived with Argon2id from a key file plus the passphrase `"passphrase"`. That derived key now sits in `key.pem`, itself encrypted under the passphrase `"passphrase"`. Recovery-only: nothing can generate this fixture any more.
  - `key.pem`: Passphrase-encrypted key file holding the derived volume key.
  - `000000.summary`: Initial volume summary snapshot (encrypted with explicit deterministic IV).
  - `000001.log`: 3 flushed encrypted and compressed commit batches.
  - `000001.summary`: Exported snapshot of all populated inodes (encrypted with explicit deterministic IV).
  - `*-dump.txt`: Golden decrypted dump inspection outputs.
  - `fsck-report.txt`: Golden filesystem integrity check report under 100% data verification.

## Generating or Updating Fixtures

Fixtures are generated deterministically using a fixed mock timestamp and explicit IVs via `generate_compat_fixture`:

```bash
# Regenerate all golden fixtures:
cargo run --bin generate_compat_fixture

# Regenerate specific golden fixtures:
cargo run --bin generate_compat_fixture tests/fixtures/v1
cargo run --bin generate_compat_fixture tests/fixtures/v1_key_file_compressed

# Generate fixtures for a new format version (e.g. v2):
cargo run --bin generate_compat_fixture tests/fixtures/v2
cargo run --bin generate_compat_fixture tests/fixtures/v2_key_file_compressed
```

Any new version subdirectories added to `tests/fixtures/` are automatically discovered and tested by `tests/compat_test.rs`.

