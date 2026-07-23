pub mod fs;
pub mod lock_pool;
pub mod node;
pub mod operations;
pub mod shim;

pub use fs::InMemoryFS;
pub use node::{Node, SyncNode};

pub fn mount(args: Vec<String>, fs: InMemoryFS) -> Result<(), i32> {
    shim::mount(args, fs)
}
