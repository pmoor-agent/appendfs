# AppendFS Format Compatibility Fixtures

This directory contains checked-in golden on-disk storage fixtures used by `tests/compat_test.rs` to guarantee backward compatibility across format versions.

## Fixture Versions

- `v1/`: Plaintext golden files for format version 1 (`RecordHeader` version 1, `SummaryHeader` version 1).
  - `000000.summary`: Initial volume summary snapshot.
  - `000001.log`: 3 flushed commit batches covering directories, files, symlinks, special files, and extended attributes.
  - `000001.summary`: Exported snapshot of all populated inodes.

- `v1_encrypted/`: ChaCha20-Poly1305 encrypted golden files derived with Argon2id from canonical passphrase `"passphrase"`.
  - `000000.summary`: Initial volume summary snapshot (encrypted with explicit deterministic IV).
  - `000001.log`: 3 flushed encrypted commit batches.
  - `000001.summary`: Exported snapshot of all populated inodes (encrypted with explicit deterministic IV).

## Generating or Updating Fixtures

Fixtures are generated deterministically using a fixed mock timestamp and explicit IVs via `generate_compat_fixture`:

```bash
# Regenerate v1 plaintext fixtures:
cargo run --bin generate_compat_fixture tests/fixtures/v1

# Regenerate v1 encrypted fixtures:
cargo run --bin generate_compat_fixture tests/fixtures/v1_encrypted

# Generate fixtures for a new format version (e.g. v2):
cargo run --bin generate_compat_fixture tests/fixtures/v2
```

Any new version subdirectories added to `tests/fixtures/` are automatically discovered and tested by `tests/compat_test.rs`.

