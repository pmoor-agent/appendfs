use crate::error::FsError;
use crate::fs::{InMemoryFS, is_virtual_ino};
use crate::node::AttrDelta;
use crate::shim::FuseResponse;
use crate::sync::OpTag;
use std::collections::HashMap;

pub const XATTR_NAME_MAX: usize = 255;
pub const XATTR_SIZE_MAX: usize = 65536;

pub fn getxattr_core(fs: &InMemoryFS, ino: u64, name: &str, size: usize) -> Result<FuseResponse<'static>, FsError> {
    let inner = fs.inner.lock(OpTag::Xattr).unwrap();
    inner.check_shutdown(false)?;
    if fs.get_attr_locked(&inner, ino).is_none() {
        return Err(FsError::ENOENT);
    }
    if is_virtual_ino(ino) {
        return Err(FsError::ENODATA);
    }

    let val = inner.get_xattr(ino, name).ok_or(FsError::ENODATA)?;
    drop(inner);
    if size == 0 {
        Ok(FuseResponse::xattr_size(val.len()))
    } else if size < val.len() {
        Err(FsError::ERANGE)
    } else {
        Ok(FuseResponse::buf(val))
    }
}

pub fn setxattr_core(
    fs: &InMemoryFS,
    ino: u64,
    name: &str,
    value: &[u8],
    flags: i32,
) -> Result<FuseResponse<'static>, FsError> {
    if is_virtual_ino(ino) {
        return Err(FsError::EPERM);
    }

    if name.is_empty() || name.len() > XATTR_NAME_MAX {
        return Err(FsError::ERANGE);
    }

    if value.len() > XATTR_SIZE_MAX {
        return Err(FsError::E2BIG);
    }

    let now = fs.clock.now();
    let mut xattrs = HashMap::new();
    xattrs.insert(name.to_string(), Some(value.to_vec()));
    let delta = AttrDelta {
        ctime: Some(now),
        xattrs: Some(xattrs),
        ..Default::default()
    };

    fs.with_inner(OpTag::Xattr, |inner| {
        inner.check_shutdown(true)?;
        if fs.get_attr_locked(inner, ino).is_none() {
            return Err(FsError::ENOENT);
        }

        let exists = inner.get_xattr(ino, name).is_some();
        if (flags & libc::XATTR_CREATE) != 0 && exists {
            return Err(FsError::EEXIST);
        }
        if (flags & libc::XATTR_REPLACE) != 0 && !exists {
            return Err(FsError::ENODATA);
        }

        inner.update_attr_delta(ino, delta);
        inner.record_mutation(name.len() + value.len());
        Ok(FuseResponse::ok())
    })
}

pub fn listxattr_core(fs: &InMemoryFS, ino: u64, size: usize) -> Result<FuseResponse<'static>, FsError> {
    let inner = fs.inner.lock(OpTag::Xattr).unwrap();
    inner.check_shutdown(false)?;
    if fs.get_attr_locked(&inner, ino).is_none() {
        return Err(FsError::ENOENT);
    }
    if is_virtual_ino(ino) {
        return Ok(if size == 0 {
            FuseResponse::xattr_size(0)
        } else {
            FuseResponse::buf(Vec::new())
        });
    }

    let keys = inner.list_xattrs(ino).ok_or(FsError::ENOENT)?;
    drop(inner);
    let mut buf = Vec::new();
    for key in keys {
        buf.extend_from_slice(key.as_bytes());
        buf.push(0); // null terminator
    }

    if size == 0 {
        Ok(FuseResponse::xattr_size(buf.len()))
    } else if size < buf.len() {
        Err(FsError::ERANGE)
    } else {
        Ok(FuseResponse::buf(buf))
    }
}

pub fn removexattr_core(fs: &InMemoryFS, ino: u64, name: &str) -> Result<FuseResponse<'static>, FsError> {
    if is_virtual_ino(ino) {
        return Err(FsError::EPERM);
    }

    let now = fs.clock.now();
    let mut xattrs = HashMap::new();
    xattrs.insert(name.to_string(), None);
    let delta = AttrDelta {
        ctime: Some(now),
        xattrs: Some(xattrs),
        ..Default::default()
    };

    fs.with_inner(OpTag::Xattr, |inner| {
        inner.check_shutdown(true)?;
        if fs.get_attr_locked(inner, ino).is_none() {
            return Err(FsError::ENOENT);
        }

        if inner.get_xattr(ino, name).is_none() {
            return Err(FsError::ENODATA);
        }

        inner.update_attr_delta(ino, delta);
        inner.record_mutation(name.len());
        Ok(FuseResponse::ok())
    })
}

pub use getxattr_core as getxattr_response;
pub use listxattr_core as listxattr_response;
pub use removexattr_core as removexattr_response;
pub use setxattr_core as setxattr_response;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TestFS;

    #[test]
    fn test_xattr_basic_crud_and_size_query() {
        let fs = TestFS::builder().build().fs;
        let attr = crate::operations::read_write::create_core(&fs, 1, "test.txt", 0o644, 0, 1000, 1000).unwrap();
        let ino = attr.ino;

        // 1. Missing attribute returns ENODATA
        assert_eq!(getxattr_core(&fs, ino, "user.comment", 0), Err(FsError::ENODATA));

        // 2. Set attribute
        assert_eq!(
            setxattr_core(&fs, ino, "user.comment", b"hello world", 0),
            Ok(FuseResponse::ok())
        );

        // 3. Query size (size == 0)
        assert_eq!(
            getxattr_core(&fs, ino, "user.comment", 0),
            Ok(FuseResponse::xattr_size(11))
        );

        // 4. Query with insufficient buffer -> ERANGE
        assert_eq!(getxattr_core(&fs, ino, "user.comment", 5), Err(FsError::ERANGE));

        // 5. Query with sufficient buffer -> Data
        assert_eq!(
            getxattr_core(&fs, ino, "user.comment", 20),
            Ok(FuseResponse::buf(b"hello world".to_vec()))
        );

        // 6. List attributes
        match listxattr_core(&fs, ino, 0).unwrap() {
            FuseResponse::XattrSize(sz) => assert_eq!(sz, "user.comment\0".len()),
            _ => panic!("Expected Size result"),
        }

        match listxattr_core(&fs, ino, 64).unwrap() {
            FuseResponse::Buf(data) => assert_eq!(data.as_slice(), b"user.comment\0"),
            _ => panic!("Expected Data result"),
        }

        // 7. Remove attribute
        assert_eq!(removexattr_core(&fs, ino, "user.comment"), Ok(FuseResponse::ok()));
        assert_eq!(getxattr_core(&fs, ino, "user.comment", 0), Err(FsError::ENODATA));
        assert_eq!(removexattr_core(&fs, ino, "user.comment"), Err(FsError::ENODATA));
    }

    #[test]
    fn test_xattr_create_and_replace_flags() {
        let fs = TestFS::builder().build().fs;
        let attr = crate::operations::read_write::create_core(&fs, 1, "flags.txt", 0o644, 0, 1000, 1000).unwrap();
        let ino = attr.ino;

        // REPLACE fails on nonexistent attribute
        assert_eq!(
            setxattr_core(&fs, ino, "user.tag", b"v1", libc::XATTR_REPLACE),
            Err(FsError::ENODATA)
        );

        // CREATE succeeds on nonexistent attribute
        assert_eq!(
            setxattr_core(&fs, ino, "user.tag", b"v1", libc::XATTR_CREATE),
            Ok(FuseResponse::ok())
        );

        // CREATE fails on existing attribute
        assert_eq!(
            setxattr_core(&fs, ino, "user.tag", b"v2", libc::XATTR_CREATE),
            Err(FsError::EEXIST)
        );

        // REPLACE succeeds on existing attribute
        assert_eq!(
            setxattr_core(&fs, ino, "user.tag", b"v2", libc::XATTR_REPLACE),
            Ok(FuseResponse::ok())
        );

        assert_eq!(
            getxattr_core(&fs, ino, "user.tag", 10),
            Ok(FuseResponse::buf(b"v2".to_vec()))
        );
    }

    #[test]
    fn test_xattr_multiple_attributes_deterministic_order() {
        let fs = TestFS::builder().build().fs;
        let attr = crate::operations::read_write::create_core(&fs, 1, "multi.txt", 0o644, 0, 1000, 1000).unwrap();
        let ino = attr.ino;

        setxattr_core(&fs, ino, "user.zebra", b"1", 0).unwrap();
        setxattr_core(&fs, ino, "user.apple", b"2", 0).unwrap();
        setxattr_core(&fs, ino, "user.mango", b"3", 0).unwrap();

        match listxattr_core(&fs, ino, 100).unwrap() {
            FuseResponse::Buf(data) => {
                assert_eq!(data.as_slice(), b"user.apple\0user.mango\0user.zebra\0");
            }
            _ => panic!("Expected Data result"),
        }
    }

    #[test]
    fn test_xattr_single_lock_acquisition_tagged_xattr() {
        let fs = TestFS::builder().build().fs;
        let attr = crate::operations::read_write::create_core(&fs, 1, "test.txt", 0o644, 0, 1000, 1000).unwrap();
        let ino = attr.ino;
        setxattr_core(&fs, ino, "user.tag", b"v1", 0).unwrap();

        // Test getxattr_core
        let pre_stats = fs.inner.op_stats();
        let pre_xattr = pre_stats.iter().find(|s| s.tag == OpTag::Xattr).unwrap().count;
        let pre_total = fs.inner.lock_count();

        let val = getxattr_core(&fs, ino, "user.tag", 10).unwrap();
        assert_eq!(val, FuseResponse::buf(b"v1".to_vec()));

        let post_stats = fs.inner.op_stats();
        let post_xattr = post_stats.iter().find(|s| s.tag == OpTag::Xattr).unwrap().count;
        let post_total = fs.inner.lock_count();

        assert_eq!(post_xattr - pre_xattr, 1);
        assert_eq!(post_total - pre_total, 1);

        // Test listxattr_core
        let pre_stats = fs.inner.op_stats();
        let pre_xattr = pre_stats.iter().find(|s| s.tag == OpTag::Xattr).unwrap().count;
        let pre_total = fs.inner.lock_count();

        let keys = listxattr_core(&fs, ino, 100).unwrap();
        assert_eq!(keys, FuseResponse::buf(b"user.tag\0".to_vec()));

        let post_stats = fs.inner.op_stats();
        let post_xattr = post_stats.iter().find(|s| s.tag == OpTag::Xattr).unwrap().count;
        let post_total = fs.inner.lock_count();

        assert_eq!(post_xattr - pre_xattr, 1);
        assert_eq!(post_total - pre_total, 1);

        // Test setxattr_core
        let pre_stats = fs.inner.op_stats();
        let pre_xattr = pre_stats.iter().find(|s| s.tag == OpTag::Xattr).unwrap().count;
        let pre_total = fs.inner.lock_count();

        setxattr_core(&fs, ino, "user.tag2", b"v2", 0).unwrap();

        let post_stats = fs.inner.op_stats();
        let post_xattr = post_stats.iter().find(|s| s.tag == OpTag::Xattr).unwrap().count;
        let post_total = fs.inner.lock_count();

        assert_eq!(post_xattr - pre_xattr, 1);
        assert_eq!(post_total - pre_total, 1);

        // Test removexattr_core
        let pre_stats = fs.inner.op_stats();
        let pre_xattr = pre_stats.iter().find(|s| s.tag == OpTag::Xattr).unwrap().count;
        let pre_total = fs.inner.lock_count();

        removexattr_core(&fs, ino, "user.tag2").unwrap();

        let post_stats = fs.inner.op_stats();
        let post_xattr = post_stats.iter().find(|s| s.tag == OpTag::Xattr).unwrap().count;
        let post_total = fs.inner.lock_count();

        assert_eq!(post_xattr - pre_xattr, 1);
        assert_eq!(post_total - pre_total, 1);
    }
}
