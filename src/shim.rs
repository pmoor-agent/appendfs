use std::ffi::{CStr, CString, c_char, c_int};
use std::os::raw::c_void;

// High-level safe representation of file types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Directory,
    RegularFile,
    Symlink,
}

// High-level safe representation of file attributes
pub struct FileAttr {
    pub ino: u64,
    pub file_type: FileType,
    pub perm: u32,
    pub nlink: u32,
    pub size: i64,
}

// Custom layout-stable representation for FFI communication
#[repr(C)]
struct ShimFileAttr {
    ino: u64,
    mode: u32,
    nlink: u32,
    size: i64,
}

impl ShimFileAttr {
    fn from_attr(attr: &FileAttr) -> Self {
        let mode_flag = match attr.file_type {
            FileType::Directory => libc::S_IFDIR,
            FileType::RegularFile => libc::S_IFREG,
            FileType::Symlink => libc::S_IFLNK,
        };
        Self {
            ino: attr.ino,
            mode: (mode_flag | (attr.perm & 0o777)) as u32,
            nlink: attr.nlink,
            size: attr.size,
        }
    }
}

// Opaque request pointer wrapper for asynchronous responses
#[derive(Debug, Clone, Copy)]
pub struct Request(*mut c_void);

impl Request {
    pub fn reply_err(self, err: i32) -> i32 {
        unsafe { shim_reply_err(self.0, err) }
    }

    pub fn reply_attr(self, attr: &FileAttr, attr_timeout: f64) -> i32 {
        let shim_attr = ShimFileAttr::from_attr(attr);
        unsafe { shim_reply_attr(self.0, &shim_attr, attr_timeout) }
    }

    pub fn reply_entry(self, attr: &FileAttr, attr_timeout: f64, entry_timeout: f64) -> i32 {
        let shim_attr = ShimFileAttr::from_attr(attr);
        unsafe { shim_reply_entry(self.0, &shim_attr, attr_timeout, entry_timeout) }
    }

    pub fn reply_buf(self, buf: &[u8]) -> i32 {
        unsafe { shim_reply_buf(self.0, buf.as_ptr() as *const c_char, buf.len()) }
    }

    pub fn reply_open(self, fh: u64) -> i32 {
        unsafe { shim_reply_open(self.0, fh) }
    }

    pub fn reply_write(self, count: usize) -> i32 {
        unsafe { shim_reply_write(self.0, count) }
    }

    pub fn reply_create(
        self,
        attr: &FileAttr,
        attr_timeout: f64,
        entry_timeout: f64,
        fh: u64,
    ) -> i32 {
        let shim_attr = ShimFileAttr::from_attr(attr);
        unsafe { shim_reply_create(self.0, &shim_attr, attr_timeout, entry_timeout, fh) }
    }

    pub fn reply_readlink(self, target: &str) -> i32 {
        let c_str = CString::new(target).expect("Link target contained a null byte");
        unsafe { shim_reply_readlink(self.0, c_str.as_ptr()) }
    }
}

// Helper to pack directory entries into a buffer correctly sized for readdir replies
pub struct DirectoryBuffer {
    buf: Vec<u8>,
    req: Request,
}

impl DirectoryBuffer {
    pub fn new(req: Request) -> Self {
        Self {
            buf: Vec::new(),
            req,
        }
    }

    pub fn add(&mut self, name: &str, ino: u64, file_type: FileType) -> bool {
        let c_name = match CString::new(name) {
            Ok(s) => s,
            Err(_) => return false,
        };

        let mode_flag = match file_type {
            FileType::Directory => libc::S_IFDIR,
            FileType::RegularFile => libc::S_IFREG,
            FileType::Symlink => libc::S_IFLNK,
        } as u32;

        // Probe size by passing NULL as buffer
        let entry_size = unsafe {
            shim_add_direntry(
                self.req.0,
                std::ptr::null_mut(),
                0,
                c_name.as_ptr(),
                ino,
                mode_flag,
                0,
            )
        };

        let old_len = self.buf.len();
        let new_len = old_len + entry_size;
        self.buf.resize(new_len, 0);

        // Add entry, passing new_len as the offset of the NEXT entry in the directory stream
        unsafe {
            shim_add_direntry(
                self.req.0,
                self.buf[old_len..].as_mut_ptr() as *mut c_char,
                entry_size,
                c_name.as_ptr(),
                ino,
                mode_flag,
                new_len as i64,
            );
        }
        true
    }

    // Sends the reply with the correct slice corresponding to the requested offset and size
    pub fn reply(self, offset: i64, max_size: usize) -> i32 {
        let offset = offset as usize;
        if offset < self.buf.len() {
            let available = self.buf.len() - offset;
            let size_to_reply = std::cmp::min(available, max_size);
            self.req
                .reply_buf(&self.buf[offset..offset + size_to_reply])
        } else {
            self.req.reply_buf(&[])
        }
    }
}

// Low-level Filesystem trait
pub trait Filesystem {
    fn lookup(&self, req: Request, parent: u64, name: &str);
    fn getattr(&self, req: Request, ino: u64);
    fn readdir(&self, req: Request, ino: u64, size: usize, offset: i64);
    fn read(&self, req: Request, ino: u64, size: usize, offset: i64);
    fn open(&self, req: Request, _ino: u64, _flags: u32) {
        req.reply_open(0);
    }
    fn write(&self, req: Request, _ino: u64, _buf: &[u8], _offset: i64) {
        req.reply_err(libc::ENOSYS);
    }
    fn setattr(&self, req: Request, _ino: u64, _size: i64, _to_set: u32) {
        req.reply_err(libc::ENOSYS);
    }
    fn create(&self, req: Request, _parent: u64, _name: &str, _mode: u32, _flags: u32) {
        req.reply_err(libc::ENOSYS);
    }
    fn unlink(&self, req: Request, _parent: u64, _name: &str) {
        req.reply_err(libc::ENOSYS);
    }
    fn mkdir(&self, req: Request, _parent: u64, _name: &str, _mode: u32) {
        req.reply_err(libc::ENOSYS);
    }
    fn rmdir(&self, req: Request, _parent: u64, _name: &str) {
        req.reply_err(libc::ENOSYS);
    }
    fn symlink(&self, req: Request, _link: &str, _parent: u64, _name: &str) {
        req.reply_err(libc::ENOSYS);
    }
    fn readlink(&self, req: Request, _ino: u64) {
        req.reply_err(libc::ENOSYS);
    }
    fn rename(&self, req: Request, _parent: u64, _name: &str, _newparent: u64, _newname: &str) {
        req.reply_err(libc::ENOSYS);
    }
    fn link(&self, req: Request, _ino: u64, _newparent: u64, _newname: &str) {
        req.reply_err(libc::ENOSYS);
    }
    fn fsync(&self, req: Request, _ino: u64, _datasync: bool) {
        req.reply_err(0);
    }
    fn release(&self, req: Request, _ino: u64) {
        req.reply_err(0);
    }
    fn releasedir(&self, req: Request, _ino: u64) {
        req.reply_err(0);
    }
    fn fsyncdir(&self, req: Request, _ino: u64, _datasync: bool) {
        req.reply_err(0);
    }
}

// Private raw FFI functions linked from the C++ shim
unsafe extern "C" {
    fn run_fuse_ll(
        argc: c_int,
        argv: *const *const c_char,
        ops: *const RustLowlevelOps,
        userdata: *mut c_void,
    ) -> c_int;

    fn shim_reply_err(req: *mut c_void, err: c_int) -> c_int;
    fn shim_reply_attr(req: *mut c_void, attr: *const ShimFileAttr, attr_timeout: f64) -> c_int;
    fn shim_reply_entry(
        req: *mut c_void,
        attr: *const ShimFileAttr,
        attr_timeout: f64,
        entry_timeout: f64,
    ) -> c_int;
    fn shim_reply_buf(req: *mut c_void, buf: *const c_char, size: usize) -> c_int;
    fn shim_reply_open(req: *mut c_void, fh: u64) -> c_int;
    fn shim_reply_write(req: *mut c_void, count: usize) -> c_int;
    fn shim_reply_create(
        req: *mut c_void,
        attr: *const ShimFileAttr,
        attr_timeout: f64,
        entry_timeout: f64,
        fh: u64,
    ) -> c_int;
    fn shim_reply_readlink(req: *mut c_void, link: *const c_char) -> c_int;

    fn shim_add_direntry(
        req: *mut c_void,
        buf: *mut c_char,
        bufsize: usize,
        name: *const c_char,
        ino: u64,
        mode: u32,
        off: i64,
    ) -> usize;
}

// Layout matching the C++ rust_lowlevel_ops struct
#[repr(C)]
struct RustLowlevelOps {
    lookup: Option<
        unsafe extern "C" fn(
            req: *mut c_void,
            parent: u64,
            name: *const c_char,
            userdata: *mut c_void,
        ),
    >,
    getattr: Option<unsafe extern "C" fn(req: *mut c_void, ino: u64, userdata: *mut c_void)>,
    readdir: Option<
        unsafe extern "C" fn(
            req: *mut c_void,
            ino: u64,
            size: usize,
            offset: i64,
            userdata: *mut c_void,
        ),
    >,
    read: Option<
        unsafe extern "C" fn(
            req: *mut c_void,
            ino: u64,
            size: usize,
            offset: i64,
            userdata: *mut c_void,
        ),
    >,
    open:
        Option<unsafe extern "C" fn(req: *mut c_void, ino: u64, flags: u32, userdata: *mut c_void)>,
    write: Option<
        unsafe extern "C" fn(
            req: *mut c_void,
            ino: u64,
            buf: *const c_char,
            size: usize,
            offset: i64,
            userdata: *mut c_void,
        ),
    >,
    setattr: Option<
        unsafe extern "C" fn(
            req: *mut c_void,
            ino: u64,
            size: i64,
            to_set: u32,
            userdata: *mut c_void,
        ),
    >,
    create: Option<
        unsafe extern "C" fn(
            req: *mut c_void,
            parent: u64,
            name: *const c_char,
            mode: u32,
            flags: u32,
            userdata: *mut c_void,
        ),
    >,
    unlink: Option<
        unsafe extern "C" fn(
            req: *mut c_void,
            parent: u64,
            name: *const c_char,
            userdata: *mut c_void,
        ),
    >,
    mkdir: Option<
        unsafe extern "C" fn(
            req: *mut c_void,
            parent: u64,
            name: *const c_char,
            mode: u32,
            userdata: *mut c_void,
        ),
    >,
    rmdir: Option<
        unsafe extern "C" fn(
            req: *mut c_void,
            parent: u64,
            name: *const c_char,
            userdata: *mut c_void,
        ),
    >,
    symlink: Option<
        unsafe extern "C" fn(
            req: *mut c_void,
            link: *const c_char,
            parent: u64,
            name: *const c_char,
            userdata: *mut c_void,
        ),
    >,
    readlink: Option<unsafe extern "C" fn(req: *mut c_void, ino: u64, userdata: *mut c_void)>,
    rename: Option<
        unsafe extern "C" fn(
            req: *mut c_void,
            parent: u64,
            name: *const c_char,
            newparent: u64,
            newname: *const c_char,
            userdata: *mut c_void,
        ),
    >,
    link: Option<
        unsafe extern "C" fn(
            req: *mut c_void,
            ino: u64,
            newparent: u64,
            newname: *const c_char,
            userdata: *mut c_void,
        ),
    >,
    fsync: Option<
        unsafe extern "C" fn(req: *mut c_void, ino: u64, datasync: c_int, userdata: *mut c_void),
    >,
    release: Option<unsafe extern "C" fn(req: *mut c_void, ino: u64, userdata: *mut c_void)>,
    releasedir: Option<unsafe extern "C" fn(req: *mut c_void, ino: u64, userdata: *mut c_void)>,
    fsyncdir: Option<
        unsafe extern "C" fn(req: *mut c_void, ino: u64, datasync: c_int, userdata: *mut c_void),
    >,
}

#[inline]
fn get_fs<'a>(userdata: *mut c_void) -> &'a (dyn Filesystem + Send + Sync) {
    unsafe { &**(userdata as *const Box<dyn Filesystem + Send + Sync>) }
}

// C-to-Rust bridge callback for lookup
unsafe extern "C" fn lookup_bridge(
    req: *mut c_void,
    parent: u64,
    name: *const c_char,
    userdata: *mut c_void,
) {
    let name_str = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            Request(req).reply_err(libc::EINVAL);
            return;
        }
    };
    let fs = get_fs(userdata);
    fs.lookup(Request(req), parent, name_str);
}

// C-to-Rust bridge callback for getattr
unsafe extern "C" fn getattr_bridge(req: *mut c_void, ino: u64, userdata: *mut c_void) {
    let fs = get_fs(userdata);
    fs.getattr(Request(req), ino);
}

// C-to-Rust bridge callback for readdir
unsafe extern "C" fn readdir_bridge(
    req: *mut c_void,
    ino: u64,
    size: usize,
    offset: i64,
    userdata: *mut c_void,
) {
    let fs = get_fs(userdata);
    fs.readdir(Request(req), ino, size, offset);
}

// C-to-Rust bridge callback for read
unsafe extern "C" fn read_bridge(
    req: *mut c_void,
    ino: u64,
    size: usize,
    offset: i64,
    userdata: *mut c_void,
) {
    let fs = get_fs(userdata);
    fs.read(Request(req), ino, size, offset);
}

// C-to-Rust bridge callback for open
unsafe extern "C" fn open_bridge(req: *mut c_void, ino: u64, flags: u32, userdata: *mut c_void) {
    let fs = get_fs(userdata);
    fs.open(Request(req), ino, flags);
}

// C-to-Rust bridge callback for write
unsafe extern "C" fn write_bridge(
    req: *mut c_void,
    ino: u64,
    buf: *const c_char,
    size: usize,
    offset: i64,
    userdata: *mut c_void,
) {
    let src_buf = unsafe { std::slice::from_raw_parts(buf as *const u8, size) };
    let fs = get_fs(userdata);
    fs.write(Request(req), ino, src_buf, offset);
}

// C-to-Rust bridge callback for setattr
unsafe extern "C" fn setattr_bridge(
    req: *mut c_void,
    ino: u64,
    size: i64,
    to_set: u32,
    userdata: *mut c_void,
) {
    let fs = get_fs(userdata);
    fs.setattr(Request(req), ino, size, to_set);
}

// C-to-Rust bridge callback for create
unsafe extern "C" fn create_bridge(
    req: *mut c_void,
    parent: u64,
    name: *const c_char,
    mode: u32,
    flags: u32,
    userdata: *mut c_void,
) {
    let name_str = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            Request(req).reply_err(libc::EINVAL);
            return;
        }
    };
    let fs = get_fs(userdata);
    fs.create(Request(req), parent, name_str, mode, flags);
}

// C-to-Rust bridge callback for unlink
unsafe extern "C" fn unlink_bridge(
    req: *mut c_void,
    parent: u64,
    name: *const c_char,
    userdata: *mut c_void,
) {
    let name_str = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            Request(req).reply_err(libc::EINVAL);
            return;
        }
    };
    let fs = get_fs(userdata);
    fs.unlink(Request(req), parent, name_str);
}

// C-to-Rust bridge callback for mkdir
unsafe extern "C" fn mkdir_bridge(
    req: *mut c_void,
    parent: u64,
    name: *const c_char,
    mode: u32,
    userdata: *mut c_void,
) {
    let name_str = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            Request(req).reply_err(libc::EINVAL);
            return;
        }
    };
    let fs = get_fs(userdata);
    fs.mkdir(Request(req), parent, name_str, mode);
}

// C-to-Rust bridge callback for rmdir
unsafe extern "C" fn rmdir_bridge(
    req: *mut c_void,
    parent: u64,
    name: *const c_char,
    userdata: *mut c_void,
) {
    let name_str = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            Request(req).reply_err(libc::EINVAL);
            return;
        }
    };
    let fs = get_fs(userdata);
    fs.rmdir(Request(req), parent, name_str);
}

// C-to-Rust bridge callback for symlink
unsafe extern "C" fn symlink_bridge(
    req: *mut c_void,
    link: *const c_char,
    parent: u64,
    name: *const c_char,
    userdata: *mut c_void,
) {
    let link_str = match unsafe { CStr::from_ptr(link) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            Request(req).reply_err(libc::EINVAL);
            return;
        }
    };
    let name_str = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            Request(req).reply_err(libc::EINVAL);
            return;
        }
    };
    let fs = get_fs(userdata);
    fs.symlink(Request(req), link_str, parent, name_str);
}

// C-to-Rust bridge callback for readlink
unsafe extern "C" fn readlink_bridge(req: *mut c_void, ino: u64, userdata: *mut c_void) {
    let fs = get_fs(userdata);
    fs.readlink(Request(req), ino);
}

// C-to-Rust bridge callback for rename
unsafe extern "C" fn rename_bridge(
    req: *mut c_void,
    parent: u64,
    name: *const c_char,
    newparent: u64,
    newname: *const c_char,
    userdata: *mut c_void,
) {
    let name_str = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            Request(req).reply_err(libc::EINVAL);
            return;
        }
    };
    let newname_str = match unsafe { CStr::from_ptr(newname) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            Request(req).reply_err(libc::EINVAL);
            return;
        }
    };
    let fs = get_fs(userdata);
    fs.rename(Request(req), parent, name_str, newparent, newname_str);
}

// C-to-Rust bridge callback for link
unsafe extern "C" fn link_bridge(
    req: *mut c_void,
    ino: u64,
    newparent: u64,
    newname: *const c_char,
    userdata: *mut c_void,
) {
    let newname_str = match unsafe { CStr::from_ptr(newname) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            Request(req).reply_err(libc::EINVAL);
            return;
        }
    };
    let fs = get_fs(userdata);
    fs.link(Request(req), ino, newparent, newname_str);
}

// C-to-Rust bridge callback for fsync
unsafe extern "C" fn fsync_bridge(
    req: *mut c_void,
    ino: u64,
    datasync: c_int,
    userdata: *mut c_void,
) {
    let fs = get_fs(userdata);
    fs.fsync(Request(req), ino, datasync != 0);
}

// C-to-Rust bridge callback for release
unsafe extern "C" fn release_bridge(req: *mut c_void, ino: u64, userdata: *mut c_void) {
    let fs = get_fs(userdata);
    fs.release(Request(req), ino);
}

// C-to-Rust bridge callback for releasedir
unsafe extern "C" fn releasedir_bridge(req: *mut c_void, ino: u64, userdata: *mut c_void) {
    let fs = get_fs(userdata);
    fs.releasedir(Request(req), ino);
}

// C-to-Rust bridge callback for fsyncdir
unsafe extern "C" fn fsyncdir_bridge(
    req: *mut c_void,
    ino: u64,
    datasync: c_int,
    userdata: *mut c_void,
) {
    let fs = get_fs(userdata);
    fs.fsyncdir(Request(req), ino, datasync != 0);
}

// Public entrypoint to mount and run the filesystem
pub fn mount<F>(args: Vec<String>, fs: F) -> Result<(), i32>
where
    F: Filesystem + Send + Sync + 'static,
{
    let fs_box: Box<dyn Filesystem + Send + Sync> = Box::new(fs);
    let user_data_box = Box::new(fs_box);
    let raw_userdata = Box::into_raw(user_data_box) as *mut c_void;

    // Convert arguments to C-style strings
    let c_args_owners: Vec<CString> = args
        .into_iter()
        .map(|arg| CString::new(arg).expect("Argument contained a null byte"))
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
    };

    let code = unsafe { run_fuse_ll(c_args.len() as c_int, c_args.as_ptr(), &ops, raw_userdata) };

    // Clean up heap allocation for filesystem context
    unsafe {
        let _ = Box::from_raw(raw_userdata as *mut Box<dyn Filesystem + Send + Sync>);
    }

    if code == 0 { Ok(()) } else { Err(code) }
}
