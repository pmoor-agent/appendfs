pub mod dir;
pub mod links;
pub mod read_write;

use crate::fs::InMemoryFS;
use crate::shim::{Filesystem, Request};

impl Filesystem for InMemoryFS {
    fn lookup(&self, req: Request, parent: u64, name: &str) {
        dir::lookup(self, req, parent, name);
    }

    fn getattr(&self, req: Request, ino: u64) {
        read_write::getattr(self, req, ino);
    }

    fn readdir(&self, req: Request, ino: u64, size: usize, offset: i64) {
        dir::readdir(self, req, ino, size, offset);
    }

    fn read(&self, req: Request, ino: u64, size: usize, offset: i64) {
        read_write::read(self, req, ino, size, offset);
    }

    fn open(&self, req: Request, ino: u64, flags: u32) {
        read_write::open(self, req, ino, flags);
    }

    fn write(&self, req: Request, ino: u64, buf: &[u8], offset: i64) {
        read_write::write(self, req, ino, buf, offset);
    }

    fn setattr(&self, req: Request, ino: u64, size: i64, to_set: u32) {
        read_write::setattr(self, req, ino, size, to_set);
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

    fn fsync(&self, req: Request, ino: u64, datasync: bool) {
        read_write::fsync(self, req, ino, datasync);
    }

    fn release(&self, req: Request, ino: u64) {
        read_write::release(self, req, ino);
    }

    fn releasedir(&self, req: Request, ino: u64) {
        dir::releasedir(self, req, ino);
    }

    fn fsyncdir(&self, req: Request, ino: u64, datasync: bool) {
        dir::fsyncdir(self, req, ino, datasync);
    }
}
