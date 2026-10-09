use std::fmt;

/// Strongly-typed POSIX filesystem error code.
///
/// A transparent newtype over `i32` preserving POSIX integer error semantics while
/// preventing accidental confusion with file handles, byte counts, or inode numbers.
#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FsError(pub i32);

/// Defines an `FsError` constant per errno and the matching name lookup from one list, so
/// the two cannot drift apart. Where Linux gives two names the same value (`EAGAIN` and
/// `EWOULDBLOCK`, `EOPNOTSUPP` and `ENOTSUP`), the first one listed is the name reported.
macro_rules! errnos {
    ($($name:ident),* $(,)?) => {
        impl FsError {
            $(pub const $name: Self = Self(libc::$name);)*

            /// Returns the symbolic name of this errno, e.g. `"ENOENT"`, if it is one of the
            /// constants above.
            fn name(self) -> Option<&'static str> {
                $(if self.0 == libc::$name {
                    return Some(stringify!($name));
                })*
                None
            }
        }
    };
}

errnos! {
    EPERM,
    ENOENT,
    EIO,
    E2BIG,
    EBADF,
    EAGAIN,
    EWOULDBLOCK,
    EACCES,
    EEXIST,
    EXDEV,
    ENODEV,
    ENOTDIR,
    EISDIR,
    EINVAL,
    ENFILE,
    EMFILE,
    EFBIG,
    ENOSPC,
    EROFS,
    EMLINK,
    EBUSY,
    EDEADLK,
    ENAMETOOLONG,
    ENOTEMPTY,
    ENOSYS,
    ENODATA,
    EOVERFLOW,
    EOPNOTSUPP,
    ENOTSUP,
    ECANCELED,
    ERANGE,
}

impl fmt::Debug for FsError {
    /// Prints the errno by name, as it is written in code (`FsError::ENOENT`), so a failed
    /// `assert_eq!` on an error reads without a lookup table. Codes without a constant fall
    /// back to the number.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => write!(f, "FsError::{}", name),
            None => write!(f, "FsError({})", self.0),
        }
    }
}

impl FsError {
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
    fn test_fs_error_debug_prints_the_errno_name() {
        assert_eq!(format!("{:?}", FsError::EACCES), "FsError::EACCES");
        assert_eq!(format!("{:?}", Err::<(), _>(FsError::ENOENT)), "Err(FsError::ENOENT)");
        // Aliases share a value; the first name listed is the one reported.
        assert_eq!(format!("{:?}", FsError::EWOULDBLOCK), "FsError::EAGAIN");
        assert_eq!(format!("{:?}", FsError::ENOTSUP), "FsError::EOPNOTSUPP");
        // Codes without a constant fall back to the number.
        assert_eq!(
            format!("{:?}", FsError::from_raw(libc::ETIMEDOUT)),
            format!("FsError({})", libc::ETIMEDOUT)
        );
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
