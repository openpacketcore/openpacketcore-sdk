//! Narrow safe access to the Linux fs-verity ioctls used to seal snapshots.
//!
//! This crate intentionally supports one profile only: version 1, SHA-256,
//! 4096-byte blocks, and no salt or signature.  It accepts only already-open
//! file descriptors, so it neither accepts nor reports file paths or content.

#![allow(unsafe_code)]
#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::fmt;
use std::io;
use std::os::fd::BorrowedFd;

/// The number of bytes in the fixed SHA-256 fs-verity digest.
pub const DIGEST_BYTES: usize = 32;

/// Error returned by a fixed fs-verity operation.
///
/// The [`Self::Enable`] and [`Self::Measure`] variants retain the original
/// [`io::Error`], including its platform errno.  No variant contains a path
/// or a file's contents.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The kernel rejected the fixed-profile enable operation.
    Enable(io::Error),
    /// The kernel rejected the digest measurement operation.
    Measure(io::Error),
    /// The kernel returned a digest that is not the fixed SHA-256 profile.
    UnsupportedProfile {
        /// Digest algorithm returned by the kernel.
        algorithm: u16,
        /// Digest size returned by the kernel.
        digest_size: u16,
    },
    /// fs-verity is unavailable on this target platform.
    Unsupported,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Enable(_) => formatter.write_str("fs-verity enable failed"),
            Self::Measure(_) => formatter.write_str("fs-verity measurement failed"),
            Self::UnsupportedProfile {
                algorithm,
                digest_size,
            } => write!(
                formatter,
                "unsupported fs-verity digest profile: algorithm {algorithm}, size {digest_size}"
            ),
            Self::Unsupported => formatter.write_str("fs-verity is unsupported on this platform"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Enable(error) | Self::Measure(error) => Some(error),
            Self::UnsupportedProfile { .. } | Self::Unsupported => None,
        }
    }
}

/// Enable the fixed fs-verity profile and return its SHA-256 digest.
///
/// `fd` **must** be opened `O_RDONLY`, and the caller must close every writer
/// for the same inode before calling this function.  Those are kernel
/// requirements for enabling fs-verity; this descriptor-only boundary cannot
/// prove either condition.  On success, the file is sealed and this function
/// immediately measures the resulting fixed-profile digest.
pub fn enable_fixed_profile(fd: BorrowedFd<'_>) -> Result<[u8; DIGEST_BYTES], Error> {
    platform::enable_fixed_profile(fd)
}

/// Measure the fixed fs-verity SHA-256 digest of an already sealed file.
///
/// The descriptor need not be writable.  Measurement fails with
/// [`Error::Measure`] when the file is not sealed or the kernel rejects the
/// ioctl, and fails closed with [`Error::UnsupportedProfile`] if the kernel
/// returns any algorithm or digest size other than SHA-256/32 bytes.
pub fn measure(fd: BorrowedFd<'_>) -> Result<[u8; DIGEST_BYTES], Error> {
    platform::measure(fd)
}

#[cfg(target_os = "linux")]
mod platform {
    use super::{Error, DIGEST_BYTES};
    use std::os::fd::{AsRawFd, BorrowedFd};

    const FS_VERITY_VERSION: u32 = 1;
    const FS_VERITY_HASH_ALG_SHA256: u32 = 1;
    const FS_VERITY_BLOCK_SIZE: u32 = 4096;
    const FS_VERITY_DIGEST_ALG_SHA256: u16 = 1;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct EnableArg {
        version: u32,
        hash_algorithm: u32,
        block_size: u32,
        salt_size: u32,
        salt_ptr: u64,
        sig_size: u32,
        reserved1: u32,
        sig_ptr: u64,
        reserved2: [u64; 11],
    }

    impl EnableArg {
        const fn fixed_profile() -> Self {
            Self {
                version: FS_VERITY_VERSION,
                hash_algorithm: FS_VERITY_HASH_ALG_SHA256,
                block_size: FS_VERITY_BLOCK_SIZE,
                salt_size: 0,
                salt_ptr: 0,
                sig_size: 0,
                reserved1: 0,
                sig_ptr: 0,
                reserved2: [0; 11],
            }
        }
    }

    #[repr(C)]
    struct DigestBuffer {
        algorithm: u16,
        digest_size: u16,
        digest: [u8; DIGEST_BYTES],
    }

    impl DigestBuffer {
        const fn requested_sha256() -> Self {
            Self {
                algorithm: 0,
                digest_size: DIGEST_BYTES as u16,
                digest: [0; DIGEST_BYTES],
            }
        }
    }

    pub(super) fn enable_fixed_profile(fd: BorrowedFd<'_>) -> Result<[u8; DIGEST_BYTES], Error> {
        let enable = EnableArg::fixed_profile();
        // SAFETY: `enable` is a correctly laid out, fully initialized copy of
        // `struct fsverity_enable_arg`; `fd` remains valid for this call.
        let result = unsafe {
            libc::ioctl(
                fd.as_raw_fd(),
                linux_raw_sys::ioctl::FS_IOC_ENABLE_VERITY as libc::c_ulong,
                std::ptr::addr_of!(enable),
            )
        };
        if result == -1 {
            return Err(Error::Enable(std::io::Error::last_os_error()));
        }
        measure(fd)
    }

    pub(super) fn measure(fd: BorrowedFd<'_>) -> Result<[u8; DIGEST_BYTES], Error> {
        let mut digest = DigestBuffer::requested_sha256();
        // SAFETY: `digest` is a correctly laid out writable buffer for
        // `struct fsverity_digest` plus exactly 32 digest bytes; `fd` remains
        // valid for this call.
        let result = unsafe {
            libc::ioctl(
                fd.as_raw_fd(),
                linux_raw_sys::ioctl::FS_IOC_MEASURE_VERITY as libc::c_ulong,
                std::ptr::addr_of_mut!(digest),
            )
        };
        if result == -1 {
            return Err(Error::Measure(std::io::Error::last_os_error()));
        }
        digest_from_kernel(digest)
    }

    fn digest_from_kernel(digest: DigestBuffer) -> Result<[u8; DIGEST_BYTES], Error> {
        if digest.algorithm != FS_VERITY_DIGEST_ALG_SHA256
            || digest.digest_size != DIGEST_BYTES as u16
        {
            return Err(Error::UnsupportedProfile {
                algorithm: digest.algorithm,
                digest_size: digest.digest_size,
            });
        }
        Ok(digest.digest)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::fs::{File, OpenOptions};
        use std::io::Write as _;
        use std::mem::{align_of, offset_of, size_of};
        use std::os::fd::AsFd as _;

        #[test]
        fn fixed_enable_argument_layout_and_profile_are_deterministic() {
            let argument = EnableArg::fixed_profile();

            assert_eq!(size_of::<EnableArg>(), 128);
            assert_eq!(align_of::<EnableArg>(), 8);
            assert_eq!(offset_of!(EnableArg, salt_ptr), 16);
            assert_eq!(offset_of!(EnableArg, sig_ptr), 32);
            assert_eq!(argument.version, FS_VERITY_VERSION);
            assert_eq!(argument.hash_algorithm, FS_VERITY_HASH_ALG_SHA256);
            assert_eq!(argument.block_size, FS_VERITY_BLOCK_SIZE);
            assert_eq!(argument.salt_size, 0);
            assert_eq!(argument.salt_ptr, 0);
            assert_eq!(argument.sig_size, 0);
            assert_eq!(argument.reserved1, 0);
            assert_eq!(argument.sig_ptr, 0);
            assert_eq!(argument.reserved2, [0; 11]);
        }

        #[test]
        fn digest_parser_accepts_only_the_fixed_sha256_shape() {
            let mut accepted = DigestBuffer::requested_sha256();
            accepted.algorithm = FS_VERITY_DIGEST_ALG_SHA256;
            accepted.digest = [0x5a; DIGEST_BYTES];
            assert_eq!(digest_from_kernel(accepted).unwrap(), [0x5a; DIGEST_BYTES]);

            for (algorithm, digest_size) in [
                (0, DIGEST_BYTES as u16),
                (FS_VERITY_DIGEST_ALG_SHA256, 31),
                (2, 64),
            ] {
                let mut rejected = DigestBuffer::requested_sha256();
                rejected.algorithm = algorithm;
                rejected.digest_size = digest_size;
                match digest_from_kernel(rejected) {
                    Err(Error::UnsupportedProfile {
                        algorithm: actual_algorithm,
                        digest_size: actual_digest_size,
                    }) => {
                        assert_eq!(actual_algorithm, algorithm);
                        assert_eq!(actual_digest_size, digest_size);
                    }
                    result => panic!("unexpected digest parser result: {result:?}"),
                }
            }
        }

        #[test]
        fn linux_ioctl_qualification_is_explicit_about_unsupported_filesystems() {
            let mut temporary = tempfile::NamedTempFile::new().expect("create qualification file");
            temporary
                .write_all(b"fixed fs-verity qualification payload")
                .expect("write qualification file");
            temporary
                .as_file()
                .sync_all()
                .expect("sync qualification file");
            let path = temporary.into_temp_path();

            // Opening a new read-only handle is part of the public enable
            // contract. Consuming `NamedTempFile` first closes its writer, so
            // this test also satisfies the no-open-writers part of that contract.
            let reader = File::open(&path).expect("open qualification reader");
            let preseal = measure(reader.as_fd());
            match preseal {
                Err(Error::Measure(error)) if error.raw_os_error() == Some(libc::ENODATA) => {}
                Err(Error::Measure(error)) if is_unsupported(&error) => {
                    eprintln!("fs-verity unavailable on this filesystem: {error}");
                    return;
                }
                result => {
                    panic!("expected pre-seal ENODATA or unsupported filesystem, got {result:?}")
                }
            }

            let digest = match enable_fixed_profile(reader.as_fd()) {
                Ok(digest) => digest,
                Err(Error::Enable(error)) if is_unsupported(&error) => {
                    eprintln!("fs-verity enable unsupported on this filesystem: {error}");
                    return;
                }
                result => {
                    panic!("expected fs-verity enable or unsupported filesystem, got {result:?}")
                }
            };
            assert_eq!(digest.len(), DIGEST_BYTES);
            assert_eq!(
                measure(reader.as_fd()).expect("measure sealed file"),
                digest
            );

            match OpenOptions::new().write(true).open(&path) {
                Err(error) => assert_eq!(
                    error.raw_os_error(),
                    Some(libc::EPERM),
                    "sealed-file writable open failed for an unexpected reason"
                ),
                Ok(mut writer) => {
                    let error = writer
                        .write_all(b"x")
                        .expect_err("sealed file accepted a write");
                    assert_eq!(
                        error.raw_os_error(),
                        Some(libc::EPERM),
                        "sealed-file write failed for an unexpected reason"
                    );
                }
            }
        }

        fn is_unsupported(error: &std::io::Error) -> bool {
            matches!(
                error.raw_os_error(),
                Some(libc::ENOTTY | libc::EOPNOTSUPP | libc::ENOSYS)
            )
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use super::{Error, DIGEST_BYTES};
    use std::os::fd::BorrowedFd;

    pub(super) fn enable_fixed_profile(_fd: BorrowedFd<'_>) -> Result<[u8; DIGEST_BYTES], Error> {
        Err(Error::Unsupported)
    }

    pub(super) fn measure(_fd: BorrowedFd<'_>) -> Result<[u8; DIGEST_BYTES], Error> {
        Err(Error::Unsupported)
    }
}
