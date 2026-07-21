#ifndef FUSE_SHIM_H
#define FUSE_SHIM_H

#include <cstdint>

extern "C" {
    typedef void* shim_req_t;

    // Simple custom C-compatible attributes struct to avoid system layout mismatches
    struct shim_file_attr {
        uint64_t ino;
        uint32_t mode;
        uint32_t nlink;
        int64_t size;
    };

    // Callback signatures that Rust will implement for low-level FUSE
    typedef void (*rust_lookup_t)(shim_req_t req, uint64_t parent, const char *name);
    typedef void (*rust_getattr_t)(shim_req_t req, uint64_t ino);
    typedef void (*rust_readdir_t)(shim_req_t req, uint64_t ino, size_t size, int64_t off);
    typedef void (*rust_read_t)(shim_req_t req, uint64_t ino, size_t size, int64_t off);
    typedef void (*rust_open_t)(shim_req_t req, uint64_t ino, uint32_t flags);
    typedef void (*rust_write_t)(shim_req_t req, uint64_t ino, const char *buf, size_t size, int64_t off);
    typedef void (*rust_setattr_t)(shim_req_t req, uint64_t ino, int64_t size, uint32_t to_set);
    typedef void (*rust_create_t)(shim_req_t req, uint64_t parent, const char *name, uint32_t mode, uint32_t flags);
    typedef void (*rust_unlink_t)(shim_req_t req, uint64_t parent, const char *name);
    typedef void (*rust_mkdir_t)(shim_req_t req, uint64_t parent, const char *name, uint32_t mode);
    typedef void (*rust_rmdir_t)(shim_req_t req, uint64_t parent, const char *name);
    typedef void (*rust_symlink_t)(shim_req_t req, const char *link, uint64_t parent, const char *name);
    typedef void (*rust_readlink_t)(shim_req_t req, uint64_t ino);
    typedef void (*rust_rename_t)(shim_req_t req, uint64_t parent, const char *name, uint64_t newparent, const char *newname);
    typedef void (*rust_link_t)(shim_req_t req, uint64_t ino, uint64_t newparent, const char *newname);
    typedef void (*rust_fsync_t)(shim_req_t req, uint64_t ino, int datasync);
    typedef void (*rust_release_t)(shim_req_t req, uint64_t ino);
    typedef void (*rust_releasedir_t)(shim_req_t req, uint64_t ino);
    typedef void (*rust_fsyncdir_t)(shim_req_t req, uint64_t ino, int datasync);

    struct rust_lowlevel_ops {
        rust_lookup_t lookup;
        rust_getattr_t getattr;
        rust_readdir_t readdir;
        rust_read_t read;
        rust_open_t open;
        rust_write_t write;
        rust_setattr_t setattr;
        rust_create_t create;
        rust_unlink_t unlink;
        rust_mkdir_t mkdir;
        rust_rmdir_t rmdir;
        rust_symlink_t symlink;
        rust_readlink_t readlink;
        rust_rename_t rename;
        rust_link_t link;
        rust_fsync_t fsync;
        rust_release_t release;
        rust_releasedir_t releasedir;
        rust_fsyncdir_t fsyncdir;
    };

    // Entrypoint to mount and run FUSE low-level loop
    int run_fuse_ll(int argc, char *argv[], const rust_lowlevel_ops *ops);

    // FUSE reply wrappers exposed to Rust
    int shim_reply_err(shim_req_t req, int err);
    int shim_reply_attr(shim_req_t req, const shim_file_attr *attr, double attr_timeout);
    int shim_reply_entry(shim_req_t req, const shim_file_attr *attr, double attr_timeout, double entry_timeout);
    int shim_reply_buf(shim_req_t req, const char *buf, size_t size);
    int shim_reply_open(shim_req_t req, uint64_t fh);
    int shim_reply_write(shim_req_t req, size_t count);
    int shim_reply_create(shim_req_t req, const shim_file_attr *attr, double attr_timeout, double entry_timeout, uint64_t fh);
    int shim_reply_readlink(shim_req_t req, const char *link);

    // Directory entry layout packing helper using individual fields instead of stat struct
    size_t shim_add_direntry(shim_req_t req, char *buf, size_t bufsize, const char *name, uint64_t ino, uint32_t mode, int64_t off);
}

#endif // FUSE_SHIM_H
