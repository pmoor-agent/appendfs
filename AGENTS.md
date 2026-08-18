# AppendFS Development & Agent Guidelines

AppendFS is a high-performance append-only log-structured filesystem with FUSE support, crash recovery, snapshots, and point-in-time time travel.

## Common Commands

### Build
- `cargo build` (debug build)
- `cargo build --release` (optimized release build)

### Lint & Format
- `cargo fmt --check`
- `cargo clippy --all-targets`

### Standard Testing
- Run all tests (debug): `cargo test`
- Run all tests (release): `cargo test --release`
- Run specific test file: `cargo test --test <name>` (e.g. `cargo test --test integration_test`)

## Extended & Stress Testing

Certain test suites (differential fuzzing and concurrent stress testing) support configurable iterations via environment variables.

### Environment Variables

| Variable | Description | Default |
| :--- | :--- | :--- |
| `FUZZ_SEEDS` | Number of seed iterations to sweep across in `fuzz_test.rs` and `concurrency_test.rs`. | `5` |
| `FUZZ_STEPS` | Number of operations/steps per seed in `fuzz_test.rs` (fuzz & summary determinism) and per-thread op count in `concurrency_test.rs`. | `200` / `150` / `400` |

### Running Stress Sweeps

- **Recommended Extended Sanity / Soak Check (~1 minute each in release mode)**:
  - Concurrent stress soak (~90s):
    ```bash
    FUZZ_SEEDS=300 FUZZ_STEPS=8000 cargo test --release --test concurrency_test -- --nocapture
    ```
  - Fuzzing & crash recovery soak (~85s):
    ```bash
    FUZZ_SEEDS=500 FUZZ_STEPS=10000 cargo test --release --test fuzz_test -- --nocapture
    ```

- **Quick 10× Sanity Sweep (~5s total)**:
  ```bash
  FUZZ_SEEDS=50 FUZZ_STEPS=2000 cargo test --release
  ```

- **Custom sweeps**:
  ```bash
  FUZZ_STEPS=500 FUZZ_SEEDS=20 cargo test --release --test fuzz_test -- --nocapture
  ```
