pub mod dir;
pub mod links;
pub mod locks;
pub mod read_write;
pub mod statfs;

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

    fn fsync(&self, req: Request, ino: u64, datasync: bool, fh: u64) {
        read_write::fsync(self, req, ino, datasync, fh);
    }

    fn release(&self, req: Request, ino: u64, fh: u64) {
        read_write::release(self, req, ino, fh);
    }

    fn releasedir(&self, req: Request, ino: u64, fh: u64) {
        dir::releasedir(self, req, ino, fh);
    }

    fn fsyncdir(&self, req: Request, ino: u64, datasync: bool) {
        dir::fsyncdir(self, req, ino, datasync);
    }

    fn statfs(&self, req: Request, ino: u64) {
        statfs::statfs(self, req, ino);
    }

    fn flock(&self, req: Request, ino: u64, fh: u64, lock_owner: u64, op: i32) {
        locks::flock(self, req, ino, fh, lock_owner, op);
    }

    fn getlk(&self, req: Request, ino: u64, fh: u64, lock_owner: u64, lock: ShimFlock) {
        locks::getlk(self, req, ino, fh, lock_owner, lock);
    }

    fn setlk(&self, req: Request, ino: u64, fh: u64, lock_owner: u64, lock: ShimFlock, sleep: bool) {
        locks::setlk(self, req, ino, fh, lock_owner, lock, sleep);
    }
}
