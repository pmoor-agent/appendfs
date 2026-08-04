use crate::clock::system_time_to_unix;
use std::ffi::{CStr, CString, c_char, c_int};
use std::os::raw::c_void;
use std::time::SystemTime;

// High-level safe representation of file types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Directory,
    RegularFile,
    Symlink,
}

// High-level safe representation of file attributes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileAttr {
    pub ino: u64,
    pub file_type: FileType,
    pub perm: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: i64,
    pub atime: SystemTime,
    pub mtime: SystemTime,
    pub ctime: SystemTime,
}

// High-level safe representation of filesystem statistics
pub struct StatfsAttr {
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub bsize: u32,
    pub namelen: u32,
}

// Custom layout-stable representation for FFI communication
#[repr(C)]
struct ShimFileAttr {
    ino: u64,
    mode: u32,
    nlink: u32,
    uid: u32,
    gid: u32,
    size: i64,
    atime_sec: i64,
    atime_nsec: u32,
    mtime_sec: i64,
    mtime_nsec: u32,
    ctime_sec: i64,
    ctime_nsec: u32,
}

#[repr(C)]
struct ShimStatfsAttr {
    blocks: u64,
    bfree: u64,
    bavail: u64,
    files: u64,
    ffree: u64,
    bsize: u32,
    namelen: u32,
}

#[allow(non_camel_case_types)]
type shim_req_t = *mut c_void;

#[repr(C)]
struct RustLowlevelOps {
    lookup: Option<
        extern "C" fn(req: shim_req_t, parent: u64, name: *const c_char, userdata: *mut c_void),
    >,
    getattr: Option<extern "C" fn(req: shim_req_t, ino: u64, userdata: *mut c_void)>,
    readdir: Option<
        extern "C" fn(req: shim_req_t, ino: u64, size: usize, off: i64, userdata: *mut c_void),
    >,
    read: Option<
        extern "C" fn(req: shim_req_t, ino: u64, size: usize, off: i64, userdata: *mut c_void),
    >,
    open: Option<extern "C" fn(req: shim_req_t, ino: u64, flags: u32, userdata: *mut c_void)>,
    write: Option<
        extern "C" fn(
            req: shim_req_t,
            ino: u64,
            buf: *const u8,
            size: usize,
            off: i64,
            userdata: *mut c_void,
        ),
    >,
    setattr: Option<
        extern "C" fn(
            req: shim_req_t,
            ino: u64,
            mode: u32,
            uid: u32,
            gid: u32,
            size: i64,
            atime_sec: i64,
            atime_nsec: u32,
            mtime_sec: i64,
            mtime_nsec: u32,
            to_set: u32,
            userdata: *mut c_void,
        ),
    >,
    create: Option<
        extern "C" fn(
            req: shim_req_t,
            parent: u64,
            name: *const c_char,
            mode: u32,
            flags: u32,
            userdata: *mut c_void,
        ),
    >,
    unlink: Option<
        extern "C" fn(req: shim_req_t, parent: u64, name: *const c_char, userdata: *mut c_void),
    >,
    mkdir: Option<
        extern "C" fn(
            req: shim_req_t,
            parent: u64,
            name: *const c_char,
            mode: u32,
            userdata: *mut c_void,
        ),
    >,
    rmdir: Option<
        extern "C" fn(req: shim_req_t, parent: u64, name: *const c_char, userdata: *mut c_void),
    >,
    symlink: Option<
        extern "C" fn(
            req: shim_req_t,
            link: *const c_char,
            parent: u64,
            name: *const c_char,
            userdata: *mut c_void,
        ),
    >,
    readlink: Option<extern "C" fn(req: shim_req_t, ino: u64, userdata: *mut c_void)>,
    rename: Option<
        extern "C" fn(
            req: shim_req_t,
            parent: u64,
            name: *const c_char,
            newparent: u64,
            newname: *const c_char,
            userdata: *mut c_void,
        ),
    >,
    link: Option<
        extern "C" fn(
            req: shim_req_t,
            ino: u64,
            newparent: u64,
            newname: *const c_char,
            userdata: *mut c_void,
        ),
    >,
    fsync: Option<extern "C" fn(req: shim_req_t, ino: u64, datasync: c_int, userdata: *mut c_void)>,
    release: Option<extern "C" fn(req: shim_req_t, ino: u64, userdata: *mut c_void)>,
    releasedir: Option<extern "C" fn(req: shim_req_t, ino: u64, userdata: *mut c_void)>,
    fsyncdir:
        Option<extern "C" fn(req: shim_req_t, ino: u64, datasync: c_int, userdata: *mut c_void)>,
    statfs: Option<extern "C" fn(req: shim_req_t, ino: u64, userdata: *mut c_void)>,
}

unsafe extern "C" {
    fn run_fuse_ll(
        argc: c_int,
        argv: *const *const c_char,
        ops: *const RustLowlevelOps,
        userdata: *mut c_void,
    ) -> c_int;

    fn shim_reply_err(req: shim_req_t, err: c_int) -> c_int;
    fn shim_reply_entry(
        req: shim_req_t,
        attr: *const ShimFileAttr,
        attr_timeout: f64,
        entry_timeout: f64,
    ) -> c_int;
    fn shim_reply_attr(req: shim_req_t, attr: *const ShimFileAttr, attr_timeout: f64) -> c_int;
    fn shim_reply_buf(req: shim_req_t, buf: *const u8, size: usize) -> c_int;
    fn shim_reply_open(req: shim_req_t, fh: u64) -> c_int;
    fn shim_reply_write(req: shim_req_t, count: usize) -> c_int;
    fn shim_reply_create(
        req: shim_req_t,
        attr: *const ShimFileAttr,
        attr_timeout: f64,
        entry_timeout: f64,
        fh: u64,
    ) -> c_int;
    fn shim_reply_readlink(req: shim_req_t, link: *const c_char) -> c_int;
    fn shim_reply_statfs(req: shim_req_t, attr: *const ShimStatfsAttr) -> c_int;

    fn shim_add_direntry(
        req: shim_req_t,
        buf: *mut c_char,
        bufsize: usize,
        name: *const c_char,
        ino: u64,
        mode: u32,
        off: i64,
    ) -> usize;
}

pub struct Request {
    req: shim_req_t,
}

impl Request {
    pub fn reply_err(self, err: i32) {
        unsafe {
            shim_reply_err(self.req, err);
        }
    }

    pub fn reply_entry(self, attr: &FileAttr, attr_timeout: f64, entry_timeout: f64) {
        let (atime_sec, atime_nsec) = system_time_to_unix(attr.atime);
        let (mtime_sec, mtime_nsec) = system_time_to_unix(attr.mtime);
        let (ctime_sec, ctime_nsec) = system_time_to_unix(attr.ctime);

        let mode = match attr.file_type {
            FileType::Directory => libc::S_IFDIR | attr.perm,
            FileType::RegularFile => libc::S_IFREG | attr.perm,
            FileType::Symlink => libc::S_IFLNK | attr.perm,
        };

        let shim_attr = ShimFileAttr {
            ino: attr.ino,
            mode,
            nlink: attr.nlink,
            uid: attr.uid,
            gid: attr.gid,
            size: attr.size,
            atime_sec,
            atime_nsec,
            mtime_sec,
            mtime_nsec,
            ctime_sec,
            ctime_nsec,
        };

        unsafe {
            shim_reply_entry(self.req, &shim_attr, attr_timeout, entry_timeout);
        }
    }

    pub fn reply_attr(self, attr: &FileAttr, attr_timeout: f64) {
        let (atime_sec, atime_nsec) = system_time_to_unix(attr.atime);
        let (mtime_sec, mtime_nsec) = system_time_to_unix(attr.mtime);
        let (ctime_sec, ctime_nsec) = system_time_to_unix(attr.ctime);

        let mode = match attr.file_type {
            FileType::Directory => libc::S_IFDIR | attr.perm,
            FileType::RegularFile => libc::S_IFREG | attr.perm,
            FileType::Symlink => libc::S_IFLNK | attr.perm,
        };

        let shim_attr = ShimFileAttr {
            ino: attr.ino,
            mode,
            nlink: attr.nlink,
            uid: attr.uid,
            gid: attr.gid,
            size: attr.size,
            atime_sec,
            atime_nsec,
            mtime_sec,
            mtime_nsec,
            ctime_sec,
            ctime_nsec,
        };

        unsafe {
            shim_reply_attr(self.req, &shim_attr, attr_timeout);
        }
    }

    pub fn reply_buf(self, buf: &[u8]) {
        unsafe {
            shim_reply_buf(self.req, buf.as_ptr(), buf.len());
        }
    }

    pub fn reply_open(self, fh: u64) {
        unsafe {
            shim_reply_open(self.req, fh);
        }
    }

    pub fn reply_write(self, count: usize) {
        unsafe {
            shim_reply_write(self.req, count);
        }
    }

    pub fn reply_create(self, attr: &FileAttr, attr_timeout: f64, entry_timeout: f64, fh: u64) {
        let (atime_sec, atime_nsec) = system_time_to_unix(attr.atime);
        let (mtime_sec, mtime_nsec) = system_time_to_unix(attr.mtime);
        let (ctime_sec, ctime_nsec) = system_time_to_unix(attr.ctime);

        let mode = match attr.file_type {
            FileType::Directory => libc::S_IFDIR | attr.perm,
            FileType::RegularFile => libc::S_IFREG | attr.perm,
            FileType::Symlink => libc::S_IFLNK | attr.perm,
        };

        let shim_attr = ShimFileAttr {
            ino: attr.ino,
            mode,
            nlink: attr.nlink,
            uid: attr.uid,
            gid: attr.gid,
            size: attr.size,
            atime_sec,
            atime_nsec,
            mtime_sec,
            mtime_nsec,
            ctime_sec,
            ctime_nsec,
        };

        unsafe {
            shim_reply_create(self.req, &shim_attr, attr_timeout, entry_timeout, fh);
        }
    }

    pub fn reply_readlink(self, link: &str) {
        let c_link = CString::new(link).unwrap();
        unsafe {
            shim_reply_readlink(self.req, c_link.as_ptr());
        }
    }

    pub fn reply_statfs(self, attr: &StatfsAttr) {
        let shim_attr = ShimStatfsAttr {
            blocks: attr.blocks,
            bfree: attr.bfree,
            bavail: attr.bavail,
            files: attr.files,
            ffree: attr.ffree,
            bsize: attr.bsize,
            namelen: attr.namelen,
        };
        unsafe {
            shim_reply_statfs(self.req, &shim_attr);
        }
    }

    pub fn uid(&self) -> u32 {
        unsafe {
            let fuse_req = self.req as *mut c_void;
            let ctx = fuse_req_ctx_shim(fuse_req);
            ctx.uid
        }
    }

    pub fn gid(&self) -> u32 {
        unsafe {
            let fuse_req = self.req as *mut c_void;
            let ctx = fuse_req_ctx_shim(fuse_req);
            ctx.gid
        }
    }
}

#[repr(C)]
struct FuseCtx {
    uid: u32,
    gid: u32,
    pid: i32,
    umask: u32,
}

unsafe extern "C" {
    fn fuse_req_ctx_shim(req: shim_req_t) -> FuseCtx;
}

pub struct DirectoryBuffer {
    req: Request,
    buf: Vec<u8>,
}

impl DirectoryBuffer {
    pub fn new(req: Request) -> Self {
        Self {
            req,
            buf: Vec::new(),
        }
    }

    pub fn add(&mut self, name: &str, ino: u64, file_type: FileType) {
        let mode = match file_type {
            FileType::Directory => libc::S_IFDIR,
            FileType::RegularFile => libc::S_IFREG,
            FileType::Symlink => libc::S_IFLNK,
        };

        let c_name = CString::new(name).unwrap();
        let old_size = self.buf.len();

        // 256 bytes for dirent structure buffer space
        self.buf.resize(old_size + 512, 0);

        let next_off = (self.buf.len()) as i64;
        let bytes_written = unsafe {
            shim_add_direntry(
                self.req.req,
                self.buf[old_size..].as_mut_ptr() as *mut c_char,
                512,
                c_name.as_ptr(),
                ino,
                mode,
                next_off,
            )
        };

        self.buf.truncate(old_size + bytes_written);
    }

    pub fn reply(self, offset: i64, size: usize) {
        let offset = offset as usize;
        if offset >= self.buf.len() {
            self.req.reply_buf(&[]);
        } else {
            let end = std::cmp::min(offset + size, self.buf.len());
            self.req.reply_buf(&self.buf[offset..end]);
        }
    }
}

pub trait Filesystem {
    fn lookup(&self, req: Request, parent: u64, name: &str);
    fn getattr(&self, req: Request, ino: u64);
    fn readdir(&self, req: Request, ino: u64, size: usize, offset: i64);
    fn read(&self, req: Request, ino: u64, size: usize, offset: i64);
    fn open(&self, req: Request, ino: u64, flags: u32);
    fn write(&self, req: Request, ino: u64, buf: &[u8], offset: i64);
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
    );
    fn create(&self, req: Request, parent: u64, name: &str, mode: u32, flags: u32);
    fn unlink(&self, req: Request, parent: u64, name: &str);
    fn mkdir(&self, req: Request, parent: u64, name: &str, mode: u32);
    fn rmdir(&self, req: Request, parent: u64, name: &str);
    fn symlink(&self, req: Request, link: &str, parent: u64, name: &str);
    fn readlink(&self, req: Request, ino: u64);
    fn rename(&self, req: Request, parent: u64, name: &str, newparent: u64, newname: &str);
    fn link(&self, req: Request, ino: u64, newparent: u64, newname: &str);
    fn fsync(&self, req: Request, ino: u64, datasync: bool);
    fn release(&self, req: Request, ino: u64);
    fn releasedir(&self, req: Request, ino: u64);
    fn fsyncdir(&self, req: Request, ino: u64, datasync: bool);
    fn statfs(&self, req: Request, ino: u64);
}

// Lowlevel C callback bridges
extern "C" fn lookup_bridge(
    req: shim_req_t,
    parent: u64,
    name: *const c_char,
    userdata: *mut c_void,
) {
    let fs = unsafe { &*(userdata as *const Box<crate::fs::InMemoryFS>) };
    let name_str = unsafe { CStr::from_ptr(name) }.to_str().unwrap();
    fs.lookup(Request { req }, parent, name_str);
}

extern "C" fn getattr_bridge(req: shim_req_t, ino: u64, userdata: *mut c_void) {
    let fs = unsafe { &*(userdata as *const Box<crate::fs::InMemoryFS>) };
    fs.getattr(Request { req }, ino);
}

extern "C" fn readdir_bridge(
    req: shim_req_t,
    ino: u64,
    size: usize,
    off: i64,
    userdata: *mut c_void,
) {
    let fs = unsafe { &*(userdata as *const Box<crate::fs::InMemoryFS>) };
    fs.readdir(Request { req }, ino, size, off);
}

extern "C" fn read_bridge(req: shim_req_t, ino: u64, size: usize, off: i64, userdata: *mut c_void) {
    let fs = unsafe { &*(userdata as *const Box<crate::fs::InMemoryFS>) };
    fs.read(Request { req }, ino, size, off);
}

extern "C" fn open_bridge(req: shim_req_t, ino: u64, flags: u32, userdata: *mut c_void) {
    let fs = unsafe { &*(userdata as *const Box<crate::fs::InMemoryFS>) };
    fs.open(Request { req }, ino, flags);
}

extern "C" fn write_bridge(
    req: shim_req_t,
    ino: u64,
    buf: *const u8,
    size: usize,
    off: i64,
    userdata: *mut c_void,
) {
    let fs = unsafe { &*(userdata as *const Box<crate::fs::InMemoryFS>) };
    let buf_slice = unsafe { std::slice::from_raw_parts(buf, size) };
    fs.write(Request { req }, ino, buf_slice, off);
}

extern "C" fn setattr_bridge(
    req: shim_req_t,
    ino: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    size: i64,
    atime_sec: i64,
    atime_nsec: u32,
    mtime_sec: i64,
    mtime_nsec: u32,
    to_set: u32,
    userdata: *mut c_void,
) {
    let fs = unsafe { &*(userdata as *const Box<crate::fs::InMemoryFS>) };
    let atime = crate::clock::unix_to_system_time(atime_sec, atime_nsec);
    let mtime = crate::clock::unix_to_system_time(mtime_sec, mtime_nsec);
    fs.setattr(
        Request { req },
        ino,
        mode,
        uid,
        gid,
        size,
        atime,
        mtime,
        to_set,
    );
}

extern "C" fn create_bridge(
    req: shim_req_t,
    parent: u64,
    name: *const c_char,
    mode: u32,
    flags: u32,
    userdata: *mut c_void,
) {
    let fs = unsafe { &*(userdata as *const Box<crate::fs::InMemoryFS>) };
    let name_str = unsafe { CStr::from_ptr(name) }.to_str().unwrap();
    fs.create(Request { req }, parent, name_str, mode, flags);
}

extern "C" fn unlink_bridge(
    req: shim_req_t,
    parent: u64,
    name: *const c_char,
    userdata: *mut c_void,
) {
    let fs = unsafe { &*(userdata as *const Box<crate::fs::InMemoryFS>) };
    let name_str = unsafe { CStr::from_ptr(name) }.to_str().unwrap();
    fs.unlink(Request { req }, parent, name_str);
}

extern "C" fn mkdir_bridge(
    req: shim_req_t,
    parent: u64,
    name: *const c_char,
    mode: u32,
    userdata: *mut c_void,
) {
    let fs = unsafe { &*(userdata as *const Box<crate::fs::InMemoryFS>) };
    let name_str = unsafe { CStr::from_ptr(name) }.to_str().unwrap();
    fs.mkdir(Request { req }, parent, name_str, mode);
}

extern "C" fn rmdir_bridge(
    req: shim_req_t,
    parent: u64,
    name: *const c_char,
    userdata: *mut c_void,
) {
    let fs = unsafe { &*(userdata as *const Box<crate::fs::InMemoryFS>) };
    let name_str = unsafe { CStr::from_ptr(name) }.to_str().unwrap();
    fs.rmdir(Request { req }, parent, name_str);
}

extern "C" fn symlink_bridge(
    req: shim_req_t,
    link: *const c_char,
    parent: u64,
    name: *const c_char,
    userdata: *mut c_void,
) {
    let fs = unsafe { &*(userdata as *const Box<crate::fs::InMemoryFS>) };
    let link_str = unsafe { CStr::from_ptr(link) }.to_str().unwrap();
    let name_str = unsafe { CStr::from_ptr(name) }.to_str().unwrap();
    fs.symlink(Request { req }, link_str, parent, name_str);
}

extern "C" fn readlink_bridge(req: shim_req_t, ino: u64, userdata: *mut c_void) {
    let fs = unsafe { &*(userdata as *const Box<crate::fs::InMemoryFS>) };
    fs.readlink(Request { req }, ino);
}

extern "C" fn rename_bridge(
    req: shim_req_t,
    parent: u64,
    name: *const c_char,
    newparent: u64,
    newname: *const c_char,
    userdata: *mut c_void,
) {
    let fs = unsafe { &*(userdata as *const Box<crate::fs::InMemoryFS>) };
    let name_str = unsafe { CStr::from_ptr(name) }.to_str().unwrap();
    let newname_str = unsafe { CStr::from_ptr(newname) }.to_str().unwrap();
    fs.rename(Request { req }, parent, name_str, newparent, newname_str);
}

extern "C" fn link_bridge(
    req: shim_req_t,
    ino: u64,
    newparent: u64,
    newname: *const c_char,
    userdata: *mut c_void,
) {
    let fs = unsafe { &*(userdata as *const Box<crate::fs::InMemoryFS>) };
    let newname_str = unsafe { CStr::from_ptr(newname) }.to_str().unwrap();
    fs.link(Request { req }, ino, newparent, newname_str);
}

extern "C" fn fsync_bridge(req: shim_req_t, ino: u64, datasync: c_int, userdata: *mut c_void) {
    let fs = unsafe { &*(userdata as *const Box<crate::fs::InMemoryFS>) };
    fs.fsync(Request { req }, ino, datasync != 0);
}

extern "C" fn release_bridge(req: shim_req_t, ino: u64, userdata: *mut c_void) {
    let fs = unsafe { &*(userdata as *const Box<crate::fs::InMemoryFS>) };
    fs.release(Request { req }, ino);
}

extern "C" fn releasedir_bridge(req: shim_req_t, ino: u64, userdata: *mut c_void) {
    let fs = unsafe { &*(userdata as *const Box<crate::fs::InMemoryFS>) };
    fs.releasedir(Request { req }, ino);
}

extern "C" fn fsyncdir_bridge(req: shim_req_t, ino: u64, datasync: c_int, userdata: *mut c_void) {
    let fs = unsafe { &*(userdata as *const Box<crate::fs::InMemoryFS>) };
    fs.fsyncdir(Request { req }, ino, datasync != 0);
}

extern "C" fn statfs_bridge(req: shim_req_t, ino: u64, userdata: *mut c_void) {
    let fs = unsafe { &*(userdata as *const Box<crate::fs::InMemoryFS>) };
    fs.statfs(Request { req }, ino);
}

pub fn mount(args: Vec<String>, fs: crate::fs::InMemoryFS) -> Result<(), i32> {
    let c_args_owners: Vec<CString> = args
        .into_iter()
        .map(|arg| CString::new(arg).unwrap())
        .collect();

    let c_args: Vec<*const c_char> = c_args_owners.iter().map(|arg| arg.as_ptr()).collect();

    let ops = RustLowlevelOps {
        lookup: Some(lookup_bridge),
        getattr: Some(getattr_bridge),
        readdir: Some(readdir_bridge),
        read: Some(read_bridge),
        open: Some(open_bridge),
        write: Some(write_bridge),
        setattr: Some(setattr_bridge),
        create: Some(create_bridge),
        unlink: Some(unlink_bridge),
        mkdir: Some(mkdir_bridge),
        rmdir: Some(rmdir_bridge),
        symlink: Some(symlink_bridge),
        readlink: Some(readlink_bridge),
        rename: Some(rename_bridge),
        link: Some(link_bridge),
        fsync: Some(fsync_bridge),
        release: Some(release_bridge),
        releasedir: Some(releasedir_bridge),
        fsyncdir: Some(fsyncdir_bridge),
        statfs: Some(statfs_bridge),
    };

    let boxed_fs: Box<crate::fs::InMemoryFS> = Box::new(fs);
    let raw_userdata = Box::into_raw(Box::new(boxed_fs)) as *mut c_void;

    let code = unsafe { run_fuse_ll(c_args.len() as c_int, c_args.as_ptr(), &ops, raw_userdata) };

    // Clean up heap allocation and execute unmount flush/sync
    unsafe {
        let boxed_fs = Box::from_raw(raw_userdata as *mut Box<crate::fs::InMemoryFS>);
        let _ = boxed_fs.sync_and_export_summary();
    }

    if code == 0 { Ok(()) } else { Err(code) }
}
