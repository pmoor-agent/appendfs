use std::fmt;

/// Strongly-typed POSIX filesystem error code.
///
/// A transparent newtype over `i32` preserving POSIX integer error semantics while
/// preventing accidental confusion with file handles, byte counts, or inode numbers.
#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FsError(pub i32);

impl FsError {
    pub const EPERM: Self = Self(libc::EPERM);
    pub const ENOENT: Self = Self(libc::ENOENT);
    pub const EIO: Self = Self(libc::EIO);
    pub const E2BIG: Self = Self(libc::E2BIG);
    pub const EBADF: Self = Self(libc::EBADF);
    pub const EAGAIN: Self = Self(libc::EAGAIN);
    pub const EWOULDBLOCK: Self = Self(libc::EWOULDBLOCK);
    pub const EACCES: Self = Self(libc::EACCES);
    pub const EEXIST: Self = Self(libc::EEXIST);
    pub const EXDEV: Self = Self(libc::EXDEV);
    pub const ENODEV: Self = Self(libc::ENODEV);
    pub const ENOTDIR: Self = Self(libc::ENOTDIR);
    pub const EISDIR: Self = Self(libc::EISDIR);
    pub const EINVAL: Self = Self(libc::EINVAL);
    pub const ENFILE: Self = Self(libc::ENFILE);
    pub const EMFILE: Self = Self(libc::EMFILE);
    pub const EFBIG: Self = Self(libc::EFBIG);
    pub const ENOSPC: Self = Self(libc::ENOSPC);
    pub const EROFS: Self = Self(libc::EROFS);
    pub const EMLINK: Self = Self(libc::EMLINK);
    pub const EBUSY: Self = Self(libc::EBUSY);
    pub const EDEADLK: Self = Self(libc::EDEADLK);
    pub const ENAMETOOLONG: Self = Self(libc::ENAMETOOLONG);
    pub const ENOTEMPTY: Self = Self(libc::ENOTEMPTY);
    pub const ENOSYS: Self = Self(libc::ENOSYS);
    pub const ENODATA: Self = Self(libc::ENODATA);
    pub const EOVERFLOW: Self = Self(libc::EOVERFLOW);
    pub const EOPNOTSUPP: Self = Self(libc::EOPNOTSUPP);
    pub const ENOTSUP: Self = Self(libc::ENOTSUP);
    pub const ECANCELED: Self = Self(libc::ECANCELED);
    pub const ERANGE: Self = Self(libc::ERANGE);

    /// Returns the raw POSIX error code as an integer.
    #[inline]
    pub const fn raw(self) -> i32 {
        self.0
    }

    /// Constructs an `FsError` from a raw POSIX error code.
    #[inline]
    pub const fn from_raw(code: i32) -> Self {
        Self(code)
    }
}

// Ergonomic FFI conversion
impl From<FsError> for i32 {
    #[inline]
    fn from(err: FsError) -> i32 {
        err.0
    }
}

impl PartialEq<i32> for FsError {
    #[inline]
    fn eq(&self, other: &i32) -> bool {
        self.0 == *other
    }
}

impl PartialEq<FsError> for i32 {
    #[inline]
    fn eq(&self, other: &FsError) -> bool {
        *self == other.0
    }
}

impl fmt::Display for FsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", std::io::Error::from_raw_os_error(self.0))
    }
}

impl std::error::Error for FsError {}

impl From<std::io::Error> for FsError {
    #[inline]
    fn from(err: std::io::Error) -> Self {
        match err.raw_os_error() {
            Some(errno) => FsError(errno),
            None => FsError::EIO,
        }
    }
}

impl From<FsError> for std::io::Error {
    #[inline]
    fn from(err: FsError) -> Self {
        std::io::Error::from_raw_os_error(err.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fs_error_constants_and_raw() {
        assert_eq!(FsError::ENOENT.raw(), libc::ENOENT);
        assert_eq!(FsError::EEXIST.raw(), libc::EEXIST);
        assert_eq!(FsError::EINVAL.raw(), libc::EINVAL);
        assert_eq!(FsError::EIO.raw(), libc::EIO);
        assert_eq!(FsError::EROFS.raw(), libc::EROFS);
        assert_eq!(FsError::ENOTEMPTY.raw(), libc::ENOTEMPTY);
        assert_eq!(i32::from(FsError::ENOENT), libc::ENOENT);
        assert_eq!(FsError::from_raw(libc::ENOENT), FsError::ENOENT);
    }

    #[test]
    fn test_fs_error_equality_with_i32() {
        assert_eq!(FsError::ENOENT, libc::ENOENT);
        assert_eq!(libc::ENOENT, FsError::ENOENT);
        assert_ne!(FsError::ENOENT, libc::EIO);
    }

    #[test]
    fn test_fs_error_display_and_io_error_conversion() {
        let err = FsError::ENOENT;
        let io_err: std::io::Error = err.into();
        assert_eq!(io_err.raw_os_error(), Some(libc::ENOENT));
        let converted_back: FsError = io_err.into();
        assert_eq!(converted_back, FsError::ENOENT);
        assert!(!err.to_string().is_empty());
    }
}
