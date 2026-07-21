#define FUSE_USE_VERSION 31
#include <fuse_lowlevel.h>
#include "fuse_shim.h"
#include <cstring>
#include <cerrno>
#include <cstdlib>
#include <cstdio>

static rust_lowlevel_ops g_ops;

static void ll_lookup(fuse_req_t req, fuse_ino_t parent, const char *name) {
    if (g_ops.lookup) {
        g_ops.lookup(static_cast<shim_req_t>(req), parent, name);
    } else {
        fuse_reply_err(req, ENOSYS);
    }
}

static void ll_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    (void) fi;
    if (g_ops.getattr) {
        g_ops.getattr(static_cast<shim_req_t>(req), ino);
    } else {
        fuse_reply_err(req, ENOSYS);
    }
}

static void ll_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
                       struct fuse_file_info *fi) {
    (void) fi;
    if (g_ops.readdir) {
        g_ops.readdir(static_cast<shim_req_t>(req), ino, size, static_cast<int64_t>(off));
    } else {
        fuse_reply_err(req, ENOSYS);
    }
}

static void ll_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
                    struct fuse_file_info *fi) {
    (void) fi;
    if (g_ops.read) {
        g_ops.read(static_cast<shim_req_t>(req), ino, size, static_cast<int64_t>(off));
    } else {
        fuse_reply_err(req, ENOSYS);
    }
}

static void ll_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    if (g_ops.open) {
        g_ops.open(static_cast<shim_req_t>(req), ino, fi->flags);
    } else {
        struct fuse_file_info default_fi = {};
        fuse_reply_open(req, &default_fi);
    }
}

static void ll_write(fuse_req_t req, fuse_ino_t ino, const char *buf, size_t size,
                     off_t off, struct fuse_file_info *fi) {
    (void) fi;
    if (g_ops.write) {
        g_ops.write(static_cast<shim_req_t>(req), ino, buf, size, static_cast<int64_t>(off));
    } else {
        fuse_reply_err(req, ENOSYS);
    }
}

static void ll_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr, int to_set,
                       struct fuse_file_info *fi) {
    (void) fi;
    if (g_ops.setattr) {
        g_ops.setattr(static_cast<shim_req_t>(req), ino, static_cast<int64_t>(attr->st_size), static_cast<uint32_t>(to_set));
    } else {
        fuse_reply_err(req, ENOSYS);
    }
}

static void ll_create(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode,
                      struct fuse_file_info *fi) {
    if (g_ops.create) {
        g_ops.create(static_cast<shim_req_t>(req), parent, name, static_cast<uint32_t>(mode), fi->flags);
    } else {
        fuse_reply_err(req, ENOSYS);
    }
}

static void ll_unlink(fuse_req_t req, fuse_ino_t parent, const char *name) {
    if (g_ops.unlink) {
        g_ops.unlink(static_cast<shim_req_t>(req), parent, name);
    } else {
        fuse_reply_err(req, ENOSYS);
    }
}

static void ll_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode) {
    if (g_ops.mkdir) {
        g_ops.mkdir(static_cast<shim_req_t>(req), parent, name, static_cast<uint32_t>(mode));
    } else {
        fuse_reply_err(req, ENOSYS);
    }
}

static void ll_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name) {
    if (g_ops.rmdir) {
        g_ops.rmdir(static_cast<shim_req_t>(req), parent, name);
    } else {
        fuse_reply_err(req, ENOSYS);
    }
}

static void ll_symlink(fuse_req_t req, const char *link, fuse_ino_t parent, const char *name) {
    if (g_ops.symlink) {
        g_ops.symlink(static_cast<shim_req_t>(req), link, parent, name);
    } else {
        fuse_reply_err(req, ENOSYS);
    }
}

static void ll_readlink(fuse_req_t req, fuse_ino_t ino) {
    if (g_ops.readlink) {
        g_ops.readlink(static_cast<shim_req_t>(req), ino);
    } else {
        fuse_reply_err(req, ENOSYS);
    }
}

static void ll_rename(fuse_req_t req, fuse_ino_t parent, const char *name,
                      fuse_ino_t newparent, const char *newname, unsigned int flags) {
    (void) flags;
    if (g_ops.rename) {
        g_ops.rename(static_cast<shim_req_t>(req), parent, name, newparent, newname);
    } else {
        fuse_reply_err(req, ENOSYS);
    }
}

static void ll_link(fuse_req_t req, fuse_ino_t ino, fuse_ino_t newparent, const char *newname) {
    if (g_ops.link) {
        g_ops.link(static_cast<shim_req_t>(req), ino, newparent, newname);
    } else {
        fuse_reply_err(req, ENOSYS);
    }
}

static void ll_fsync(fuse_req_t req, fuse_ino_t ino, int datasync, struct fuse_file_info *fi) {
    (void) fi;
    if (g_ops.fsync) {
        g_ops.fsync(static_cast<shim_req_t>(req), ino, datasync);
    } else {
        fuse_reply_err(req, ENOSYS);
    }
}

static void ll_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    (void) fi;
    if (g_ops.release) {
        g_ops.release(static_cast<shim_req_t>(req), ino);
    } else {
        fuse_reply_err(req, ENOSYS);
    }
}

static void ll_releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    (void) fi;
    if (g_ops.releasedir) {
        g_ops.releasedir(static_cast<shim_req_t>(req), ino);
    } else {
        fuse_reply_err(req, ENOSYS);
    }
}

static void ll_fsyncdir(fuse_req_t req, fuse_ino_t ino, int datasync, struct fuse_file_info *fi) {
    (void) fi;
    if (g_ops.fsyncdir) {
        g_ops.fsyncdir(static_cast<shim_req_t>(req), ino, datasync);
    } else {
        fuse_reply_err(req, ENOSYS);
    }
}

extern "C" {

int run_fuse_ll(int argc, char *argv[], const rust_lowlevel_ops *ops) {
    if (!ops) return -1;
    g_ops = *ops;

    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct fuse_session *se = nullptr;
    struct fuse_cmdline_opts opts = {};
    struct fuse_lowlevel_ops ll_ops = {};
    int ret = -1;

    if (fuse_parse_cmdline(&args, &opts) != 0) {
        return -1;
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

    se = fuse_session_new(&args, &ll_ops, sizeof(ll_ops), nullptr);
    if (se == nullptr) {
        goto err_out1;
    }

    if (fuse_set_signal_handlers(se) != 0) {
        goto err_out2;
    }

    if (fuse_session_mount(se, opts.mountpoint) != 0) {
        goto err_out3;
    }

    fuse_daemonize(opts.foreground);

    if (opts.singlethread) {
        ret = fuse_session_loop(se);
    } else {
        ret = fuse_session_loop_mt(se, 0);
    }

    fuse_session_unmount(se);
err_out3:
    fuse_remove_signal_handlers(se);
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

int shim_reply_attr(shim_req_t req, const shim_file_attr *attr, double attr_timeout) {
    struct stat stbuf = {};
    if (attr) {
        stbuf.st_ino = attr->ino;
        stbuf.st_mode = attr->mode;
        stbuf.st_nlink = attr->nlink;
        stbuf.st_size = attr->size;
    }
    return fuse_reply_attr(static_cast<fuse_req_t>(req), &stbuf, attr_timeout);
}

int shim_reply_entry(shim_req_t req, const shim_file_attr *attr, double attr_timeout, double entry_timeout) {
    struct fuse_entry_param e = {};
    if (attr) {
        e.ino = attr->ino;
        e.generation = 1;
        e.attr.st_ino = attr->ino;
        e.attr.st_mode = attr->mode;
        e.attr.st_nlink = attr->nlink;
        e.attr.st_size = attr->size;
    }
    e.attr_timeout = attr_timeout;
    e.entry_timeout = entry_timeout;
    return fuse_reply_entry(static_cast<fuse_req_t>(req), &e);
}

int shim_reply_buf(shim_req_t req, const char *buf, size_t size) {
    return fuse_reply_buf(static_cast<fuse_req_t>(req), size == 0 ? nullptr : buf, size);
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
        e.attr.st_size = attr->size;
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

size_t shim_add_direntry(shim_req_t req, char *buf, size_t bufsize, const char *name, uint64_t ino, uint32_t mode, int64_t off) {
    struct stat stbuf = {};
    stbuf.st_ino = ino;
    stbuf.st_mode = mode;
    return fuse_add_direntry(static_cast<fuse_req_t>(req), buf, bufsize, name, &stbuf, static_cast<off_t>(off));
}

} // extern "C"
