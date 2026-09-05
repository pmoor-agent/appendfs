pub mod dir;
pub mod links;
pub mod locks;
pub mod read_write;
pub mod special;
pub mod statfs;
pub mod xattr;

use crate::fs::InMemoryFS;
use crate::shim::{Filesystem, Request, ShimFlock};
use std::time::SystemTime;

impl Filesystem for InMemoryFS {
    fn lookup(&self, req: Request, parent: u64, name: &str) {
        dir::lookup(self, req, parent, name);
    }

    fn getattr(&self, req: Request, ino: u64) {
        read_write::getattr(self, req, ino);
    }

    fn opendir(&self, req: Request, ino: u64, flags: u32) {
        dir::opendir(self, req, ino, flags);
    }

    fn readdir(&self, req: Request, ino: u64, size: usize, offset: i64, fh: u64) {
        dir::readdir(self, req, ino, size, offset, fh);
    }

    fn readdirplus(&self, req: Request, ino: u64, size: usize, offset: i64, fh: u64) {
        dir::readdirplus(self, req, ino, size, offset, fh);
    }

    fn read(&self, req: Request, ino: u64, size: usize, offset: i64, fh: u64) {
        read_write::read(self, req, ino, size, offset, fh);
    }

    fn open(&self, req: Request, ino: u64, flags: u32) {
        read_write::open(self, req, ino, flags);
    }

    fn write(&self, req: Request, ino: u64, buf: &[u8], offset: i64, fh: u64) {
        read_write::write(self, req, ino, buf, offset, fh);
    }

    fn setattr(
        &self,
        req: Request,
        ino: u64,
        mode: u32,
        uid: u32,
        gid: u32,
        size: i64,
        atime: SystemTime,
        mtime: SystemTime,
        to_set: u32,
    ) {
        read_write::setattr(self, req, ino, mode, uid, gid, size, atime, mtime, to_set);
    }

    fn create(&self, req: Request, parent: u64, name: &str, mode: u32, flags: u32) {
        read_write::create(self, req, parent, name, mode, flags);
    }

    fn mknod(&self, req: Request, parent: u64, name: &str, mode: u32, rdev: u32) {
        special::mknod(self, req, parent, name, mode, rdev);
    }

    fn unlink(&self, req: Request, parent: u64, name: &str) {
        links::unlink(self, req, parent, name);
    }

    fn mkdir(&self, req: Request, parent: u64, name: &str, mode: u32) {
        dir::mkdir(self, req, parent, name, mode);
    }

    fn rmdir(&self, req: Request, parent: u64, name: &str) {
        dir::rmdir(self, req, parent, name);
    }

    fn symlink(&self, req: Request, link: &str, parent: u64, name: &str) {
        links::symlink(self, req, link, parent, name);
    }

    fn readlink(&self, req: Request, ino: u64) {
        links::readlink(self, req, ino);
    }

    fn rename(&self, req: Request, parent: u64, name: &str, newparent: u64, newname: &str) {
        links::rename(self, req, parent, name, newparent, newname);
    }

    fn link(&self, req: Request, ino: u64, newparent: u64, newname: &str) {
        links::link(self, req, ino, newparent, newname);
    }

    fn fsync(&self, req: Request, ino: u64, _datasync: bool, fh: u64) {
        match read_write::fsync_core(self, ino, fh) {
            Ok(()) => req.reply_err(0),
            Err(e) => req.reply_err(e),
        }
    }

    fn fallocate(&self, req: Request, ino: u64, mode: i32, offset: i64, length: i64, fh: u64) {
        read_write::fallocate(self, req, ino, mode, offset, length, fh);
    }

    fn release(&self, req: Request, ino: u64, fh: u64) {
        read_write::release(self, req, ino, fh);
    }

    fn releasedir(&self, req: Request, ino: u64, fh: u64) {
        dir::releasedir(self, req, ino, fh);
    }

    fn fsyncdir(&self, req: Request, _ino: u64, _datasync: bool) {
        match dir::fsyncdir_core(self) {
            Ok(()) => req.reply_err(0),
            Err(e) => req.reply_err(e),
        }
    }

    fn statfs(&self, req: Request, ino: u64) {
        statfs::statfs(self, req, ino);
    }

    fn flock(&self, req: Request, ino: u64, fh: u64, lock_owner: u64, op: i32) {
        match locks::flock_core(self, ino, fh, lock_owner, op) {
            Ok(()) => req.reply_err(0),
            Err(e) => req.reply_err(e),
        }
    }

    fn getlk(&self, req: Request, ino: u64, fh: u64, lock_owner: u64, lock: ShimFlock) {
        locks::getlk(self, req, ino, fh, lock_owner, lock);
    }

    fn setlk(&self, req: Request, ino: u64, fh: u64, lock_owner: u64, lock: ShimFlock, sleep: bool) {
        match locks::setlk_core(self, ino, fh, lock_owner, lock, sleep) {
            Ok(()) => req.reply_err(0),
            Err(e) => req.reply_err(e),
        }
    }

    fn getxattr(&self, req: Request, ino: u64, name: &str, size: usize) {
        match xattr::getxattr_core(self, ino, name, size) {
            Ok(xattr::GetxattrResult::Size(sz)) => req.reply_xattr(sz),
            Ok(xattr::GetxattrResult::Data(data)) => req.reply_buf(&data),
            Err(err) => req.reply_err(err),
        }
    }

    fn setxattr(&self, req: Request, ino: u64, name: &str, value: &[u8], flags: i32) {
        match xattr::setxattr_core(self, ino, name, value, flags) {
            Ok(()) => req.reply_err(0),
            Err(err) => req.reply_err(err),
        }
    }

    fn listxattr(&self, req: Request, ino: u64, size: usize) {
        match xattr::listxattr_core(self, ino, size) {
            Ok(xattr::ListxattrResult::Size(sz)) => req.reply_xattr(sz),
            Ok(xattr::ListxattrResult::Data(data)) => req.reply_buf(&data),
            Err(err) => req.reply_err(err),
        }
    }

    fn removexattr(&self, req: Request, ino: u64, name: &str) {
        match xattr::removexattr_core(self, ino, name) {
            Ok(()) => req.reply_err(0),
            Err(err) => req.reply_err(err),
        }
    }
}
