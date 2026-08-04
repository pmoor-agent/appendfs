use crate::fs::InMemoryFS;
use crate::shim::{Request, StatfsAttr};

pub fn statfs(fs: &InMemoryFS, req: Request, ino: u64) {
    log::trace!("statfs(ino={})", ino);
    let active_inodes = {
        let map = fs.inodes.read().unwrap();
        map.len() as u64
    };

    req.reply_statfs(&StatfsAttr {
        blocks: 1_000_000,
        bfree: 1_000_000,
        bavail: 1_000_000,
        files: active_inodes,
        ffree: 1_000_000,
        bsize: 4096,
        namelen: 255,
    });
}
