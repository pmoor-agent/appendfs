use crate::fs::InMemoryFS;
use crate::shim::{FuseResponse, StatfsAttr};

pub fn statfs_response(fs: &InMemoryFS, ino: u64) -> Result<FuseResponse<'static>, i32> {
    log::trace!("statfs(ino={})", ino);
    let active_inodes = fs.inode_counts().total_active() as u64;

    Ok(FuseResponse::statfs(StatfsAttr {
        blocks: 1_000_000,
        bfree: 1_000_000,
        bavail: 1_000_000,
        files: active_inodes,
        ffree: 1_000_000,
        bsize: 4096,
        namelen: 255,
    }))
}
