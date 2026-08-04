#define FUSE_USE_VERSION 31

#include <fuse3/fuse_lowlevel.h>
#include <fuse3/fuse_opt.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <sys/stat.h>

typedef void* shim_req_t;

struct shim_file_attr {
    uint64_t ino;
    uint32_t mode;
    uint32_t nlink;
    uint32_t uid;
    uint32_t gid;
    int64_t size;
    int64_t atime_sec;
    uint32_t atime_nsec;
    int64_t mtime_sec;
    uint32_t mtime_nsec;
    int64_t ctime_sec;
    uint32_t ctime_nsec;
};

struct shim_statfs_attr {
    uint64_t blocks;
    uint64_t bfree;
    uint64_t bavail;
    uint64_t files;
    uint64_t ffree;
    uint32_t bsize;
    uint32_t namelen;
};

struct shim_fuse_ctx {
    uint32_t uid;
    uint32_t gid;
    int32_t pid;
    uint32_t umask;
};

extern "C" {

typedef void (*shim_lookup_fn)(shim_req_t req, uint64_t parent, const char *name, void *userdata);
typedef void (*shim_getattr_fn)(shim_req_t req, uint64_t ino, void *userdata);
typedef void (*shim_readdir_fn)(shim_req_t req, uint64_t ino, size_t size, int64_t off, void *userdata);
typedef void (*shim_read_fn)(shim_req_t req, uint64_t ino, size_t size, int64_t off, void *userdata);
typedef void (*shim_open_fn)(shim_req_t req, uint64_t ino, uint32_t flags, void *userdata);
typedef void (*shim_write_fn)(shim_req_t req, uint64_t ino, const uint8_t *buf, size_t size, int64_t off, void *userdata);
typedef void (*shim_setattr_fn)(shim_req_t req, uint64_t ino, uint32_t mode, uint32_t uid, uint32_t gid, int64_t size, int64_t atime_sec, uint32_t atime_nsec, int64_t mtime_sec, uint32_t mtime_nsec, uint32_t to_set, void *userdata);
typedef void (*shim_create_fn)(shim_req_t req, uint64_t parent, const char *name, uint32_t mode, uint32_t flags, void *userdata);
typedef void (*shim_unlink_fn)(shim_req_t req, uint64_t parent, const char *name, void *userdata);
typedef void (*shim_mkdir_fn)(shim_req_t req, uint64_t parent, const char *name, uint32_t mode, void *userdata);
typedef void (*shim_rmdir_fn)(shim_req_t req, uint64_t parent, const char *name, void *userdata);
typedef void (*shim_symlink_fn)(shim_req_t req, const char *link, uint64_t parent, const char *name, void *userdata);
typedef void (*shim_readlink_fn)(shim_req_t req, uint64_t ino, void *userdata);
typedef void (*shim_rename_fn)(shim_req_t req, uint64_t parent, const char *name, uint64_t newparent, const char *newname, void *userdata);
typedef void (*shim_link_fn)(shim_req_t req, uint64_t ino, uint64_t newparent, const char *newname, void *userdata);
typedef void (*shim_fsync_fn)(shim_req_t req, uint64_t ino, int datasync, void *userdata);
typedef void (*shim_release_fn)(shim_req_t req, uint64_t ino, void *userdata);
typedef void (*shim_releasedir_fn)(shim_req_t req, uint64_t ino, void *userdata);
typedef void (*shim_fsyncdir_fn)(shim_req_t req, uint64_t ino, int datasync, void *userdata);
typedef void (*shim_statfs_fn)(shim_req_t req, uint64_t ino, void *userdata);

struct RustLowlevelOps {
    shim_lookup_fn lookup;
    shim_getattr_fn getattr;
    shim_readdir_fn readdir;
    shim_read_fn read;
    shim_open_fn open;
    shim_write_fn write;
    shim_setattr_fn setattr;
    shim_create_fn create;
    shim_unlink_fn unlink;
    shim_mkdir_fn mkdir;
    shim_rmdir_fn rmdir;
    shim_symlink_fn symlink;
    shim_readlink_fn readlink;
    shim_rename_fn rename;
    shim_link_fn link;
    shim_fsync_fn fsync;
    shim_release_fn release;
    shim_releasedir_fn releasedir;
    shim_fsyncdir_fn fsyncdir;
    shim_statfs_fn statfs;
};

} // extern "C"

struct ShimContext {
    RustLowlevelOps ops;
    void *userdata;
};

static std::mutex global_mount_lock;

static void ll_lookup(fuse_req_t req, fuse_ino_t parent, const char *name) {
    auto *ctx = static_cast<ShimContext*>(fuse_req_userdata(req));
    if (ctx && ctx->ops.lookup) {
        ctx->ops.lookup(static_cast<shim_req_t>(req), parent, name, ctx->userdata);
    } else {
        fuse_reply_err(req, 38); // ENOSYS
    }
}

static void ll_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    (void)fi;
    auto *ctx = static_cast<ShimContext*>(fuse_req_userdata(req));
    if (ctx && ctx->ops.getattr) {
        ctx->ops.getattr(static_cast<shim_req_t>(req), ino, ctx->userdata);
    } else {
        fuse_reply_err(req, 38);
    }
}

static void ll_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi) {
    (void)fi;
    auto *ctx = static_cast<ShimContext*>(fuse_req_userdata(req));
    if (ctx && ctx->ops.readdir) {
        ctx->ops.readdir(static_cast<shim_req_t>(req), ino, size, static_cast<int64_t>(off), ctx->userdata);
    } else {
        fuse_reply_err(req, 38);
    }
}

static void ll_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi) {
    (void)fi;
    auto *ctx = static_cast<ShimContext*>(fuse_req_userdata(req));
    if (ctx && ctx->ops.read) {
        ctx->ops.read(static_cast<shim_req_t>(req), ino, size, static_cast<int64_t>(off), ctx->userdata);
    } else {
        fuse_reply_err(req, 38);
    }
}

static void ll_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    auto *ctx = static_cast<ShimContext*>(fuse_req_userdata(req));
    if (ctx && ctx->ops.open) {
        ctx->ops.open(static_cast<shim_req_t>(req), ino, fi ? fi->flags : 0, ctx->userdata);
    } else {
        fuse_reply_err(req, 38);
    }
}

static void ll_write(fuse_req_t req, fuse_ino_t ino, const char *buf, size_t size, off_t off, struct fuse_file_info *fi) {
    (void)fi;
    auto *ctx = static_cast<ShimContext*>(fuse_req_userdata(req));
    if (ctx && ctx->ops.write) {
        ctx->ops.write(static_cast<shim_req_t>(req), ino, reinterpret_cast<const uint8_t*>(buf), size, static_cast<int64_t>(off), ctx->userdata);
    } else {
        fuse_reply_err(req, 38);
    }
}

static void ll_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr, int to_set, struct fuse_file_info *fi) {
    (void)fi;
    auto *ctx = static_cast<ShimContext*>(fuse_req_userdata(req));
    if (ctx && ctx->ops.setattr) {
        uint32_t mode = attr ? attr->st_mode : 0;
        uint32_t uid = attr ? attr->st_uid : 0;
        uint32_t gid = attr ? attr->st_gid : 0;
        int64_t size = attr ? attr->st_size : 0;
        int64_t atime_sec = attr ? attr->st_atim.tv_sec : 0;
        uint32_t atime_nsec = attr ? attr->st_atim.tv_nsec : 0;
        int64_t mtime_sec = attr ? attr->st_mtim.tv_sec : 0;
        uint32_t mtime_nsec = attr ? attr->st_mtim.tv_nsec : 0;
        ctx->ops.setattr(static_cast<shim_req_t>(req), ino, mode, uid, gid, size, atime_sec, atime_nsec, mtime_sec, mtime_nsec, static_cast<uint32_t>(to_set), ctx->userdata);
    } else {
        fuse_reply_err(req, 38);
    }
}

static void ll_create(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, struct fuse_file_info *fi) {
    auto *ctx = static_cast<ShimContext*>(fuse_req_userdata(req));
    if (ctx && ctx->ops.create) {
        ctx->ops.create(static_cast<shim_req_t>(req), parent, name, static_cast<uint32_t>(mode), fi ? fi->flags : 0, ctx->userdata);
    } else {
        fuse_reply_err(req, 38);
    }
}

static void ll_unlink(fuse_req_t req, fuse_ino_t parent, const char *name) {
    auto *ctx = static_cast<ShimContext*>(fuse_req_userdata(req));
    if (ctx && ctx->ops.unlink) {
        ctx->ops.unlink(static_cast<shim_req_t>(req), parent, name, ctx->userdata);
    } else {
        fuse_reply_err(req, 38);
    }
}

static void ll_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode) {
    auto *ctx = static_cast<ShimContext*>(fuse_req_userdata(req));
    if (ctx && ctx->ops.mkdir) {
        ctx->ops.mkdir(static_cast<shim_req_t>(req), parent, name, static_cast<uint32_t>(mode), ctx->userdata);
    } else {
        fuse_reply_err(req, 38);
    }
}

static void ll_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name) {
    auto *ctx = static_cast<ShimContext*>(fuse_req_userdata(req));
    if (ctx && ctx->ops.rmdir) {
        ctx->ops.rmdir(static_cast<shim_req_t>(req), parent, name, ctx->userdata);
    } else {
        fuse_reply_err(req, 38);
    }
}

static void ll_symlink(fuse_req_t req, const char *link, fuse_ino_t parent, const char *name) {
    auto *ctx = static_cast<ShimContext*>(fuse_req_userdata(req));
    if (ctx && ctx->ops.symlink) {
        ctx->ops.symlink(static_cast<shim_req_t>(req), link, parent, name, ctx->userdata);
    } else {
        fuse_reply_err(req, 38);
    }
}

static void ll_readlink(fuse_req_t req, fuse_ino_t ino) {
    auto *ctx = static_cast<ShimContext*>(fuse_req_userdata(req));
    if (ctx && ctx->ops.readlink) {
        ctx->ops.readlink(static_cast<shim_req_t>(req), ino, ctx->userdata);
    } else {
        fuse_reply_err(req, 38);
    }
}

static void ll_rename(fuse_req_t req, fuse_ino_t parent, const char *name, fuse_ino_t newparent, const char *newname, unsigned int flags) {
    (void)flags;
    auto *ctx = static_cast<ShimContext*>(fuse_req_userdata(req));
    if (ctx && ctx->ops.rename) {
        ctx->ops.rename(static_cast<shim_req_t>(req), parent, name, newparent, newname, ctx->userdata);
    } else {
        fuse_reply_err(req, 38);
    }
}

static void ll_link(fuse_req_t req, fuse_ino_t ino, fuse_ino_t newparent, const char *newname) {
    auto *ctx = static_cast<ShimContext*>(fuse_req_userdata(req));
    if (ctx && ctx->ops.link) {
        ctx->ops.link(static_cast<shim_req_t>(req), ino, newparent, newname, ctx->userdata);
    } else {
        fuse_reply_err(req, 38);
    }
}

static void ll_fsync(fuse_req_t req, fuse_ino_t ino, int datasync, struct fuse_file_info *fi) {
    (void)fi;
    auto *ctx = static_cast<ShimContext*>(fuse_req_userdata(req));
    if (ctx && ctx->ops.fsync) {
        ctx->ops.fsync(static_cast<shim_req_t>(req), ino, datasync, ctx->userdata);
    } else {
        fuse_reply_err(req, 38);
    }
}

static void ll_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    (void)fi;
    auto *ctx = static_cast<ShimContext*>(fuse_req_userdata(req));
    if (ctx && ctx->ops.release) {
        ctx->ops.release(static_cast<shim_req_t>(req), ino, ctx->userdata);
    } else {
        fuse_reply_err(req, 0);
    }
}

static void ll_releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    (void)fi;
    auto *ctx = static_cast<ShimContext*>(fuse_req_userdata(req));
    if (ctx && ctx->ops.releasedir) {
        ctx->ops.releasedir(static_cast<shim_req_t>(req), ino, ctx->userdata);
    } else {
        fuse_reply_err(req, 0);
    }
}

static void ll_fsyncdir(fuse_req_t req, fuse_ino_t ino, int datasync, struct fuse_file_info *fi) {
    (void)fi;
    auto *ctx = static_cast<ShimContext*>(fuse_req_userdata(req));
    if (ctx && ctx->ops.fsyncdir) {
        ctx->ops.fsyncdir(static_cast<shim_req_t>(req), ino, datasync, ctx->userdata);
    } else {
        fuse_reply_err(req, 38);
    }
}

static void ll_statfs(fuse_req_t req, fuse_ino_t ino) {
    auto *ctx = static_cast<ShimContext*>(fuse_req_userdata(req));
    if (ctx && ctx->ops.statfs) {
        ctx->ops.statfs(static_cast<shim_req_t>(req), ino, ctx->userdata);
    } else {
        fuse_reply_err(req, 38);
    }
}

extern "C" {

int run_fuse_ll(int argc, const char *const *argv, const RustLowlevelOps *ops, void *userdata) {
    std::unique_lock<std::mutex> mount_lock(global_mount_lock);

    struct fuse_args args = FUSE_ARGS_INIT(argc, const_cast<char**>(argv));
    struct fuse_cmdline_opts opts = {};
    struct fuse_lowlevel_ops ll_ops = {};
    struct fuse_session *se = nullptr;
    int ret = -1;

    ShimContext ctx;
    if (ops) {
        ctx.ops = *ops;
    } else {
        memset(&ctx.ops, 0, sizeof(ctx.ops));
    }
    ctx.userdata = userdata;

    if (fuse_parse_cmdline(&args, &opts) != 0) {
        goto err_out1;
    }

    if (opts.show_help) {
        printf("usage: %s [options] <mountpoint>\n\n", argv[0]);
        fuse_cmdline_help();
        fuse_lowlevel_help();
        ret = 0;
        goto err_out1;
    } else if (opts.show_version) {
        printf("FUSE library version %s\n", fuse_pkgversion());
        fuse_lowlevel_version();
        ret = 0;
        goto err_out1;
    }

    if (opts.mountpoint == nullptr) {
        printf("error: no mountpoint specified\n");
        ret = -1;
        goto err_out1;
    }

    // Always enforce kernel-side permission checks (uid/gid/mode) regardless
    // of what mount options the caller passed on the command line.
    if (fuse_opt_add_arg(&args, "-odefault_permissions") != 0) {
        ret = -1;
        goto err_out1;
    }

    ll_ops.lookup = ll_lookup;
    ll_ops.getattr = ll_getattr;
    ll_ops.readdir = ll_readdir;
    ll_ops.read = ll_read;
    ll_ops.open = ll_open;
    ll_ops.write = ll_write;
    ll_ops.setattr = ll_setattr;
    ll_ops.create = ll_create;
    ll_ops.unlink = ll_unlink;
    ll_ops.mkdir = ll_mkdir;
    ll_ops.rmdir = ll_rmdir;
    ll_ops.symlink = ll_symlink;
    ll_ops.readlink = ll_readlink;
    ll_ops.rename = ll_rename;
    ll_ops.link = ll_link;
    ll_ops.fsync = ll_fsync;
    ll_ops.release = ll_release;
    ll_ops.releasedir = ll_releasedir;
    ll_ops.fsyncdir = ll_fsyncdir;
    ll_ops.statfs = ll_statfs;

    se = fuse_session_new(&args, &ll_ops, sizeof(ll_ops), &ctx);
    if (se == nullptr) {
        goto err_out1;
    }

    if (fuse_session_mount(se, opts.mountpoint) != 0) {
        goto err_out2;
    }

    fuse_daemonize(opts.foreground);

    if (opts.singlethread) {
        ret = fuse_session_loop(se);
    } else {
        ret = fuse_session_loop_mt(se, 0);
    }

    fuse_session_unmount(se);
err_out2:
    fuse_session_destroy(se);
err_out1:
    free(opts.mountpoint);
    fuse_opt_free_args(&args);

    return ret;
}

int shim_reply_err(shim_req_t req, int err) {
    return fuse_reply_err(static_cast<fuse_req_t>(req), err);
}

int shim_reply_entry(shim_req_t req, const shim_file_attr *attr, double attr_timeout, double entry_timeout) {
    struct fuse_entry_param e = {};
    if (attr) {
        e.ino = attr->ino;
        e.generation = 1;
        e.attr.st_ino = attr->ino;
        e.attr.st_mode = attr->mode;
        e.attr.st_nlink = attr->nlink;
        e.attr.st_uid = attr->uid;
        e.attr.st_gid = attr->gid;
        e.attr.st_size = attr->size;
        e.attr.st_atim.tv_sec = attr->atime_sec;
        e.attr.st_atim.tv_nsec = attr->atime_nsec;
        e.attr.st_mtim.tv_sec = attr->mtime_sec;
        e.attr.st_mtim.tv_nsec = attr->mtime_nsec;
        e.attr.st_ctim.tv_sec = attr->ctime_sec;
        e.attr.st_ctim.tv_nsec = attr->ctime_nsec;
    }
    e.attr_timeout = attr_timeout;
    e.entry_timeout = entry_timeout;
    return fuse_reply_entry(static_cast<fuse_req_t>(req), &e);
}

int shim_reply_attr(shim_req_t req, const shim_file_attr *attr, double attr_timeout) {
    struct stat stbuf = {};
    if (attr) {
        stbuf.st_ino = attr->ino;
        stbuf.st_mode = attr->mode;
        stbuf.st_nlink = attr->nlink;
        stbuf.st_uid = attr->uid;
        stbuf.st_gid = attr->gid;
        stbuf.st_size = attr->size;
        stbuf.st_atim.tv_sec = attr->atime_sec;
        stbuf.st_atim.tv_nsec = attr->atime_nsec;
        stbuf.st_mtim.tv_sec = attr->mtime_sec;
        stbuf.st_mtim.tv_nsec = attr->mtime_nsec;
        stbuf.st_ctim.tv_sec = attr->ctime_sec;
        stbuf.st_ctim.tv_nsec = attr->ctime_nsec;
    }
    return fuse_reply_attr(static_cast<fuse_req_t>(req), &stbuf, attr_timeout);
}

int shim_reply_buf(shim_req_t req, const char *buf, size_t size) {
    return fuse_reply_buf(static_cast<fuse_req_t>(req), buf, size);
}

int shim_reply_open(shim_req_t req, uint64_t fh) {
    struct fuse_file_info fi = {};
    fi.fh = fh;
    return fuse_reply_open(static_cast<fuse_req_t>(req), &fi);
}

int shim_reply_write(shim_req_t req, size_t count) {
    return fuse_reply_write(static_cast<fuse_req_t>(req), count);
}

int shim_reply_create(shim_req_t req, const shim_file_attr *attr, double attr_timeout, double entry_timeout, uint64_t fh) {
    struct fuse_entry_param e = {};
    if (attr) {
        e.ino = attr->ino;
        e.generation = 1;
        e.attr.st_ino = attr->ino;
        e.attr.st_mode = attr->mode;
        e.attr.st_nlink = attr->nlink;
        e.attr.st_uid = attr->uid;
        e.attr.st_gid = attr->gid;
        e.attr.st_size = attr->size;
        e.attr.st_atim.tv_sec = attr->atime_sec;
        e.attr.st_atim.tv_nsec = attr->atime_nsec;
        e.attr.st_mtim.tv_sec = attr->mtime_sec;
        e.attr.st_mtim.tv_nsec = attr->mtime_nsec;
        e.attr.st_ctim.tv_sec = attr->ctime_sec;
        e.attr.st_ctim.tv_nsec = attr->ctime_nsec;
    }
    e.attr_timeout = attr_timeout;
    e.entry_timeout = entry_timeout;
    struct fuse_file_info fi = {};
    fi.fh = fh;
    return fuse_reply_create(static_cast<fuse_req_t>(req), &e, &fi);
}

int shim_reply_readlink(shim_req_t req, const char *link) {
    return fuse_reply_readlink(static_cast<fuse_req_t>(req), link);
}

int shim_reply_statfs(shim_req_t req, const shim_statfs_attr *attr) {
    struct statvfs stbuf = {};
    if (attr) {
        stbuf.f_bsize = attr->bsize;
        stbuf.f_frsize = attr->bsize;
        stbuf.f_blocks = attr->blocks;
        stbuf.f_bfree = attr->bfree;
        stbuf.f_bavail = attr->bavail;
        stbuf.f_files = attr->files;
        stbuf.f_ffree = attr->ffree;
        stbuf.f_favail = attr->ffree;
        stbuf.f_namemax = attr->namelen;
    }
    return fuse_reply_statfs(static_cast<fuse_req_t>(req), &stbuf);
}

size_t shim_add_direntry(shim_req_t req, char *buf, size_t bufsize, const char *name, uint64_t ino, uint32_t mode, int64_t off) {
    struct stat stbuf = {};
    stbuf.st_ino = ino;
    stbuf.st_mode = mode;
    return fuse_add_direntry(static_cast<fuse_req_t>(req), buf, bufsize, name, &stbuf, static_cast<off_t>(off));
}

shim_fuse_ctx fuse_req_ctx_shim(shim_req_t req) {
    const struct fuse_ctx *ctx = fuse_req_ctx(static_cast<fuse_req_t>(req));
    shim_fuse_ctx result = {};
    if (ctx) {
        result.uid = ctx->uid;
        result.gid = ctx->gid;
        result.pid = ctx->pid;
        result.umask = ctx->umask;
    }
    return result;
}

} // extern "C"
