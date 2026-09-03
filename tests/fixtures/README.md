# AppendFS Format Compatibility Fixtures

This directory contains checked-in golden on-disk storage fixtures used by `tests/compat_test.rs` to guarantee backward compatibility across format versions.

## Fixture Versions

- `v1/`: Golden files for format version 1 (`RecordHeader` version 1, `SummaryHeader` version 1).
  - `000000.summary`: Initial volume summary snapshot.
  - `000001.log`: 3 flushed commit batches covering directories, files, symlinks, special files, and extended attributes.
  - `000001.summary`: Exported snapshot of all populated inodes.

## Generating or Updating Fixtures

Fixtures are generated deterministically using a fixed mock timestamp via `generate_compat_fixture`:

```bash
# Regenerate v1 fixtures:
cargo run --bin generate_compat_fixture tests/fixtures/v1

# Generate fixtures for a new format version (e.g. v2):
cargo run --bin generate_compat_fixture tests/fixtures/v2
```

Any new version subdirectories added to `tests/fixtures/` are automatically discovered and tested by `tests/compat_test.rs`.
