pub mod fs_wrapper;
pub mod mount;
pub mod rng;

#[allow(unused_imports)]
pub use fs_wrapper::{SnapshotNode, TestFS};
#[allow(unused_imports)]
pub use mount::{TestMount, unmount_fuse};
#[allow(unused_imports)]
pub use rng::TestRng;

#[allow(dead_code)]
pub fn env_var_or<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|val| val.parse().ok())
        .unwrap_or(default)
}

#[allow(dead_code)]
pub fn fuzz_seeds(default: u64) -> u64 {
    env_var_or("FUZZ_SEEDS", default)
}

#[allow(dead_code)]
pub fn fuzz_steps(default: usize) -> usize {
    env_var_or("FUZZ_STEPS", default)
}
