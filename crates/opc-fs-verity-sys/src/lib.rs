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

// The public interface is descriptor-only. `std::os::fd` is available on
// Unix targets, including the non-Linux targets that return `Unsupported`.
#[cfg(unix)]
use std::os::fd::BorrowedFd;

#[cfg(not(unix))]
compile_error!("opc-fs-verity-sys supports Unix targets only");

/// The number of bytes in the fixed SHA-256 fs-verity digest.
pub const DIGEST_BYTES: usize = 32;

/// Maximum number of bytes accepted for a persistent Linux file handle.
///
/// Linux documents `MAX_HANDLE_SZ` as 128 bytes.  Keeping this bound in the
/// safe wrapper means callers never need to allocate based on an untrusted
/// kernel-provided length.
pub const PERSISTENT_FILE_HANDLE_MAX_BYTES: usize = 128;

/// A filesystem-stable identifier for one inode.
///
/// This pairs the externally assigned filesystem UUID with the opaque handle
/// returned by `name_to_handle_at(2)` using `AT_EMPTY_PATH | AT_HANDLE_FID`.
/// It deliberately excludes the Linux mount-instance ID: a remount changes
/// that ID without changing the file.  The handle is comparison-only; this
/// crate never calls `open_by_handle_at`.
///
/// This is a Linux-only durable recovery capability, not a best-effort inode
/// fingerprint.  It requires a kernel exposing `FS_IOC_GETFSUUID` (Linux 6.9
/// or newer; `AT_HANDLE_FID` itself arrived in Linux 6.5) and a filesystem
/// which exports both that UUID and a bounded `AT_HANDLE_FID` handle.  Callers
/// must fail closed when either operation is unsupported; device numbers,
/// mount IDs and timestamps are not substitutes across remount or crash
/// recovery.
#[derive(Clone, PartialEq, Eq)]
pub struct PersistentFileIdentity {
    filesystem_uuid: [u8; 16],
    handle_type: i32,
    handle: Box<[u8]>,
}

impl fmt::Debug for PersistentFileIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistentFileIdentity")
            .field("handle_type", &self.handle_type)
            .field("handle_length", &self.handle.len())
            .finish_non_exhaustive()
    }
}

impl PersistentFileIdentity {
    /// The filesystem UUID returned by `FS_IOC_GETFSUUID`.
    pub const fn filesystem_uuid(&self) -> &[u8; 16] {
        &self.filesystem_uuid
    }

    /// The opaque Linux file-handle type.
    pub const fn handle_type(&self) -> i32 {
        self.handle_type
    }

    /// The opaque Linux file-handle bytes.
    pub fn handle_bytes(&self) -> &[u8] {
        &self.handle
    }
}

/// Error returned by a fixed fs-verity operation.
///
/// The [`Self::Enable`], [`Self::Measure`], and [`Self::ReadMetadata`]
/// variants retain the original [`io::Error`], including its platform errno.
/// No variant contains a path or a file's contents.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The kernel rejected the fixed-profile enable operation.
    Enable(io::Error),
    /// The kernel rejected the digest measurement operation.
    Measure(io::Error),
    /// The kernel rejected a metadata read needed to verify the full profile.
    ReadMetadata(io::Error),
    /// The kernel returned a digest that is not the fixed SHA-256 profile.
    UnsupportedProfile {
        /// Digest algorithm returned by the kernel.
        algorithm: u16,
        /// Digest size returned by the kernel.
        digest_size: u16,
    },
    /// The fs-verity descriptor selected a profile other than the fixed one.
    UnsupportedDescriptorProfile {
        /// Descriptor format version returned by the kernel.
        version: u8,
        /// Merkle-tree hash algorithm returned by the kernel.
        hash_algorithm: u8,
        /// Base-two logarithm of the Merkle-tree block size returned by the kernel.
        log_blocksize: u8,
        /// Salt length returned by the kernel.
        salt_size: u8,
    },
    /// The fs-verity descriptor was not in the canonical UAPI form.
    MalformedDescriptor,
    /// The metadata ioctl returned a length other than the requested shape.
    UnexpectedMetadataLength {
        /// Number of bytes requested from the metadata item.
        expected: usize,
        /// Number of bytes the kernel reported as read.
        actual: usize,
    },
    /// The fs-verity descriptor has a built-in signature.
    BuiltInSignature,
    /// A pointer or length cannot be represented by the Linux UAPI.
    AbiValueOutOfRange,
    /// The kernel rejected the filesystem UUID query.
    ReadFilesystemUuid(io::Error),
    /// The kernel rejected the persistent file-handle query.
    ReadFileHandle(io::Error),
    /// The filesystem returned an invalid or absent externally assigned UUID.
    InvalidFilesystemUuid,
    /// The filesystem returned an invalid opaque file handle.
    InvalidFileHandle,
    /// The filesystem requested a file handle beyond the bounded safe API.
    FileHandleTooLarge {
        /// Number of bytes requested by the kernel.
        requested: usize,
    },
    /// fs-verity is unavailable on this target platform.
    Unsupported,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Enable(_) => formatter.write_str("fs-verity enable failed"),
            Self::Measure(_) => formatter.write_str("fs-verity measurement failed"),
            Self::ReadMetadata(_) => formatter.write_str("fs-verity metadata read failed"),
            Self::UnsupportedProfile {
                algorithm,
                digest_size,
            } => write!(
                formatter,
                "unsupported fs-verity digest profile: algorithm {algorithm}, size {digest_size}"
            ),
            Self::UnsupportedDescriptorProfile {
                version,
                hash_algorithm,
                log_blocksize,
                salt_size,
            } => write!(
                formatter,
                "unsupported fs-verity descriptor profile: version {version}, algorithm {hash_algorithm}, log block size {log_blocksize}, salt size {salt_size}"
            ),
            Self::MalformedDescriptor => formatter.write_str("malformed fs-verity descriptor"),
            Self::UnexpectedMetadataLength { expected, actual } => write!(
                formatter,
                "unexpected fs-verity metadata length: expected {expected}, got {actual}"
            ),
            Self::BuiltInSignature => {
                formatter.write_str("fs-verity built-in signature is not permitted")
            }
            Self::AbiValueOutOfRange => {
                formatter.write_str("fs-verity UAPI argument is out of range")
            }
            Self::ReadFilesystemUuid(_) => formatter.write_str("filesystem UUID query failed"),
            Self::ReadFileHandle(_) => formatter.write_str("persistent file-handle query failed"),
            Self::InvalidFilesystemUuid => formatter.write_str("filesystem UUID is invalid"),
            Self::InvalidFileHandle => formatter.write_str("persistent file handle is invalid"),
            Self::FileHandleTooLarge { requested } => {
                write!(
                    formatter,
                    "persistent file handle is too large: {requested} bytes"
                )
            }
            Self::Unsupported => formatter.write_str("fs-verity is unsupported on this platform"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Enable(error)
            | Self::Measure(error)
            | Self::ReadMetadata(error)
            | Self::ReadFilesystemUuid(error)
            | Self::ReadFileHandle(error) => Some(error),
            Self::UnsupportedProfile { .. }
            | Self::UnsupportedDescriptorProfile { .. }
            | Self::MalformedDescriptor
            | Self::UnexpectedMetadataLength { .. }
            | Self::BuiltInSignature
            | Self::AbiValueOutOfRange
            | Self::InvalidFilesystemUuid
            | Self::InvalidFileHandle
            | Self::FileHandleTooLarge { .. }
            | Self::Unsupported => None,
        }
    }
}

/// Enable the fixed fs-verity profile and return its SHA-256 digest.
///
/// `fd` **must** be opened `O_RDONLY`, and the caller must close every writer
/// for the same inode before calling this function.  Those are kernel
/// requirements for enabling fs-verity; this descriptor-only boundary cannot
/// prove either condition.  On success, the file is sealed and this function
/// immediately verifies the resulting descriptor and measures the exact
/// fixed-profile digest.  On kernels that do not support
/// `FS_IOC_READ_VERITY_METADATA`, this fails closed with
/// [`Error::ReadMetadata`] after the kernel has sealed the file.
#[cfg(unix)]
pub fn enable_fixed_profile(fd: BorrowedFd<'_>) -> Result<[u8; DIGEST_BYTES], Error> {
    platform::enable_fixed_profile(fd)
}

/// Measure the SHA-256 fs-verity digest of an already sealed file.
///
/// The descriptor need not be writable.  This only establishes the digest's
/// SHA-256 shape; it does not establish the full enable profile.  Use
/// [`measure_exact_profile`] when the caller must require the fixed profile.
/// Measurement fails with
/// [`Error::Measure`] when the file is not sealed or the kernel rejects the
/// ioctl, and fails closed with [`Error::UnsupportedProfile`] if the kernel
/// returns any algorithm or digest size other than SHA-256/32 bytes.
#[cfg(unix)]
pub fn measure(fd: BorrowedFd<'_>) -> Result<[u8; DIGEST_BYTES], Error> {
    platform::measure(fd)
}

/// Verify that a sealed file uses the complete fixed fs-verity profile.
///
/// This reads metadata through `fd` only.  It requires descriptor version 1,
/// SHA-256, 4096-byte blocks, no salt, a zeroed unused SHA-256 root-hash tail,
/// canonical zeroed reserved fields, and no built-in signature.  Metadata
/// errors, short reads, malformed fields, alternate profiles, and signature
/// presence all fail closed.
#[cfg(unix)]
pub fn verify_exact_profile(fd: BorrowedFd<'_>) -> Result<(), Error> {
    platform::verify_exact_profile(fd)
}

/// Verify the complete fixed fs-verity profile and return its SHA-256 digest.
///
/// This is the descriptor-only operation intended for accepting a sealed
/// snapshot or recovery artifact.  It combines [`verify_exact_profile`] with
/// [`measure`] and never reopens a pathname.
#[cfg(unix)]
pub fn measure_exact_profile(fd: BorrowedFd<'_>) -> Result<[u8; DIGEST_BYTES], Error> {
    platform::measure_exact_profile(fd)
}

/// Read a stable, comparison-only identity for an already-open regular file.
///
/// The returned value combines `FS_IOC_GETFSUUID` with
/// `name_to_handle_at(fd, "", ..., AT_EMPTY_PATH | AT_HANDLE_FID)`.  It does
/// not require `CAP_DAC_READ_SEARCH` because it never reopens by handle.  A
/// missing UUID or unsupported handle fails closed; callers must not replace
/// this identity with mount IDs, timestamps, or device/inode numbers across a
/// crash boundary.
#[cfg(unix)]
pub fn persistent_file_identity(fd: BorrowedFd<'_>) -> Result<PersistentFileIdentity, Error> {
    platform::persistent_file_identity(fd)
}

#[cfg(target_os = "linux")]
mod platform {
    use super::{Error, PersistentFileIdentity, DIGEST_BYTES, PERSISTENT_FILE_HANDLE_MAX_BYTES};
    use std::mem::size_of;
    use std::os::fd::{AsRawFd, BorrowedFd};

    const FS_VERITY_VERSION: u32 = 1;
    const FS_VERITY_DESCRIPTOR_VERSION: u8 = 1;
    const FS_VERITY_HASH_ALG_SHA256: u32 = 1;
    const FS_VERITY_BLOCK_SIZE: u32 = 4096;
    const FS_VERITY_DIGEST_ALG_SHA256: u16 = 1;
    const FS_VERITY_DESCRIPTOR_HASH_ALG_SHA256: u8 = 1;
    const FS_VERITY_LOG_BLOCK_SIZE: u8 = 12;
    const FS_VERITY_METADATA_TYPE_DESCRIPTOR: u64 = 2;
    const FS_VERITY_METADATA_TYPE_SIGNATURE: u64 = 3;
    const DESCRIPTOR_BYTES: usize = 256;
    const DIGEST_BYTES_U16: u16 = 32;
    const FILESYSTEM_UUID_BYTES: usize = 16;
    const AT_EMPTY_PATH: libc::c_int = 0x1000;
    const AT_HANDLE_FID: libc::c_int = 0x0200;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct FilesystemUuid {
        length: u8,
        uuid: [u8; FILESYSTEM_UUID_BYTES],
    }

    // `FS_IOC_GETFSUUID` is `_IOR(0x15, 0, struct fsuuid2)`.  Do not embed
    // the x86/asm-generic number: Linux's MIPS, PowerPC, and SPARC UAPI uses
    // a 13-bit size field and therefore encodes a distinct request value.
    // libc's target-aware `_IOR` implementation is the Rust equivalent of
    // the UAPI macro and keeps this wrapper correct for every Linux target
    // libc supports.  linux-raw-sys exposes `fsuuid2` but, at the workspace
    // header baseline, not this new ioctl number on every target.
    const FS_IOC_GETFSUUID: libc::Ioctl = libc::_IOR::<FilesystemUuid>(0x15, 0);

    impl FilesystemUuid {
        const fn requested() -> Self {
            Self {
                length: FILESYSTEM_UUID_BYTES as u8,
                uuid: [0; FILESYSTEM_UUID_BYTES],
            }
        }
    }

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
                digest_size: DIGEST_BYTES_U16,
                digest: [0; DIGEST_BYTES],
            }
        }
    }

    // This is `struct fsverity_descriptor`, represented as its fixed UAPI byte
    // layout.  Every field is byte-addressable, so this avoids architecture-
    // dependent integer decoding for fields this crate does not consume.
    #[repr(transparent)]
    #[derive(Clone, Copy)]
    struct Descriptor([u8; DESCRIPTOR_BYTES]);

    impl Descriptor {
        const VERSION: usize = 0;
        const HASH_ALGORITHM: usize = 1;
        const LOG_BLOCKSIZE: usize = 2;
        const SALT_SIZE: usize = 3;
        const RESERVED_0X04: std::ops::Range<usize> = 4..8;
        #[cfg(test)]
        const ROOT_HASH_SHA256: std::ops::Range<usize> = 16..48;
        const ROOT_HASH_UNUSED: std::ops::Range<usize> = 48..80;
        const SALT: std::ops::Range<usize> = 80..112;
        const RESERVED: std::ops::Range<usize> = 112..256;

        const fn zeroed() -> Self {
            Self([0; DESCRIPTOR_BYTES])
        }

        fn version(&self) -> u8 {
            self.0[Self::VERSION]
        }

        fn hash_algorithm(&self) -> u8 {
            self.0[Self::HASH_ALGORITHM]
        }

        fn log_blocksize(&self) -> u8 {
            self.0[Self::LOG_BLOCKSIZE]
        }

        fn salt_size(&self) -> u8 {
            self.0[Self::SALT_SIZE]
        }

        fn has_canonical_zeroed_fields(&self) -> bool {
            self.0[Self::RESERVED_0X04]
                .iter()
                // The kernel constructs descriptors with `kzalloc()` and
                // fills only the active digest width.  SHA-256 therefore has
                // a canonical zeroed 32-byte tail in `root_hash[64]`.
                .chain(self.0[Self::ROOT_HASH_UNUSED].iter())
                .chain(self.0[Self::SALT].iter())
                .chain(self.0[Self::RESERVED].iter())
                .all(|byte| *byte == 0)
        }

        fn as_mut_bytes(&mut self) -> &mut [u8] {
            &mut self.0
        }
    }

    // This is `struct fsverity_read_metadata_arg`.  It must stay `repr(C)`:
    // the ioctl command number encodes its 40-byte UAPI size on both i686 and
    // x86_64, while the fields themselves are always 64-bit quantities.
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct ReadMetadataArg {
        metadata_type: u64,
        offset: u64,
        length: u64,
        buf_ptr: u64,
        reserved: u64,
    }

    impl ReadMetadataArg {
        fn for_buffer(metadata_type: u64, buffer: &mut [u8]) -> Result<Self, Error> {
            Ok(Self {
                metadata_type,
                offset: 0,
                length: u64::try_from(buffer.len()).map_err(|_| Error::AbiValueOutOfRange)?,
                buf_ptr: uapi_pointer(buffer.as_mut_ptr())?,
                reserved: 0,
            })
        }
    }

    fn uapi_pointer<T>(pointer: *const T) -> Result<u64, Error> {
        // Linux currently exposes this ioctl only on ABIs whose userspace
        // pointers fit the UAPI's u64 field.  Keep that assumption explicit
        // rather than silently truncating a future wider pointer ABI.
        if size_of::<usize>() > size_of::<u64>() {
            return Err(Error::AbiValueOutOfRange);
        }
        let address = pointer as usize;
        u64::try_from(address).map_err(|_| Error::AbiValueOutOfRange)
    }

    pub(super) fn enable_fixed_profile(fd: BorrowedFd<'_>) -> Result<[u8; DIGEST_BYTES], Error> {
        let enable = EnableArg::fixed_profile();
        enable_verity(fd, &enable).map_err(Error::Enable)?;
        measure_exact_profile(fd)
    }

    fn enable_verity(fd: BorrowedFd<'_>, enable: &EnableArg) -> std::io::Result<()> {
        // SAFETY: `enable` is a correctly laid out, fully initialized copy of
        // `struct fsverity_enable_arg`; `fd` remains valid for this call.
        let result = unsafe {
            libc::ioctl(
                fd.as_raw_fd(),
                linux_raw_sys::ioctl::FS_IOC_ENABLE_VERITY as libc::Ioctl,
                std::ptr::from_ref(enable),
            )
        };
        if result == -1 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    pub(super) fn measure(fd: BorrowedFd<'_>) -> Result<[u8; DIGEST_BYTES], Error> {
        let mut digest = DigestBuffer::requested_sha256();
        // SAFETY: `digest` is a correctly laid out writable buffer for
        // `struct fsverity_digest` plus exactly 32 digest bytes; `fd` remains
        // valid for this call.
        let result = unsafe {
            libc::ioctl(
                fd.as_raw_fd(),
                linux_raw_sys::ioctl::FS_IOC_MEASURE_VERITY as libc::Ioctl,
                std::ptr::addr_of_mut!(digest),
            )
        };
        if result == -1 {
            return Err(Error::Measure(std::io::Error::last_os_error()));
        }
        digest_from_kernel(digest)
    }

    pub(super) fn verify_exact_profile(fd: BorrowedFd<'_>) -> Result<(), Error> {
        let mut descriptor = Descriptor::zeroed();
        let descriptor_length = read_metadata(
            fd,
            FS_VERITY_METADATA_TYPE_DESCRIPTOR,
            descriptor.as_mut_bytes(),
        )?;
        require_exact_metadata_length(DESCRIPTOR_BYTES, descriptor_length)?;
        verify_descriptor(descriptor)?;

        let mut signature_probe = [0_u8; 1];
        // Linux returns ENODATA specifically when signature metadata was
        // requested for a descriptor whose built-in signature size is zero.
        match read_metadata(fd, FS_VERITY_METADATA_TYPE_SIGNATURE, &mut signature_probe) {
            Err(Error::ReadMetadata(error)) if error.raw_os_error() == Some(libc::ENODATA) => {
                Ok(())
            }
            Err(error) => Err(error),
            Ok(length) => verify_no_builtin_signature(length, &signature_probe),
        }
    }

    pub(super) fn measure_exact_profile(fd: BorrowedFd<'_>) -> Result<[u8; DIGEST_BYTES], Error> {
        verify_exact_profile(fd)?;
        measure(fd)
    }

    pub(super) fn persistent_file_identity(
        fd: BorrowedFd<'_>,
    ) -> Result<PersistentFileIdentity, Error> {
        let filesystem_uuid = filesystem_uuid(fd)?;
        let (handle_type, handle) = file_handle(fd)?;
        Ok(PersistentFileIdentity {
            filesystem_uuid,
            handle_type,
            handle: handle.into_boxed_slice(),
        })
    }

    fn filesystem_uuid(fd: BorrowedFd<'_>) -> Result<[u8; FILESYSTEM_UUID_BYTES], Error> {
        let mut uuid = FilesystemUuid::requested();
        // SAFETY: `uuid` has the exact `struct fsuuid2` representation and
        // remains writable for the ioctl. `fd` is borrowed for this call.
        let result = unsafe {
            libc::ioctl(
                fd.as_raw_fd(),
                FS_IOC_GETFSUUID,
                std::ptr::addr_of_mut!(uuid),
            )
        };
        if result == -1 {
            return Err(Error::ReadFilesystemUuid(std::io::Error::last_os_error()));
        }
        if uuid.length != FILESYSTEM_UUID_BYTES as u8 || uuid.uuid.iter().all(|byte| *byte == 0) {
            return Err(Error::InvalidFilesystemUuid);
        }
        Ok(uuid.uuid)
    }

    #[repr(C)]
    struct FileHandleBuffer {
        handle_bytes: libc::c_uint,
        handle_type: libc::c_int,
        handle: [u8; PERSISTENT_FILE_HANDLE_MAX_BYTES],
    }

    const _: () = {
        assert!(
            std::mem::offset_of!(FileHandleBuffer, handle)
                == std::mem::size_of::<libc::file_handle>()
        );
        assert!(
            std::mem::size_of::<FileHandleBuffer>()
                == std::mem::size_of::<libc::file_handle>() + PERSISTENT_FILE_HANDLE_MAX_BYTES
        );
    };

    fn file_handle(fd: BorrowedFd<'_>) -> Result<(i32, Vec<u8>), Error> {
        let empty_path = c"";
        let mut capacity = 32_usize.min(PERSISTENT_FILE_HANDLE_MAX_BYTES);
        // The kernel may report `EOVERFLOW` with the required byte count. A
        // single bounded retry handles filesystems whose handles are smaller
        // than our initial capacity without permitting attacker-sized growth.
        for attempt in 0..2 {
            let mut buffer = FileHandleBuffer {
                handle_bytes: libc::c_uint::try_from(capacity)
                    .map_err(|_| Error::AbiValueOutOfRange)?,
                handle_type: 0,
                handle: [0; PERSISTENT_FILE_HANDLE_MAX_BYTES],
            };
            // SAFETY: `FileHandleBuffer` is `repr(C)`, has the exact aligned
            // `struct file_handle` header at offset zero, and reserves the
            // bounded trailing handle storage.  The pointer is used only for
            // this syscall while `buffer` remains live.
            let handle = std::ptr::addr_of_mut!(buffer).cast::<libc::file_handle>();
            let mut ignored_mount_id = 0_i32;
            // SAFETY: the empty C pathname is NUL-terminated; `handle` and
            // `ignored_mount_id` point to live writable storage for the full
            // call. `AT_HANDLE_FID` requests a comparison-only handle and we
            // never call `open_by_handle_at`.
            let result = unsafe {
                libc::name_to_handle_at(
                    fd.as_raw_fd(),
                    empty_path.as_ptr(),
                    handle,
                    std::ptr::addr_of_mut!(ignored_mount_id),
                    AT_EMPTY_PATH | AT_HANDLE_FID,
                )
            };
            let reported_bytes =
                usize::try_from(buffer.handle_bytes).map_err(|_| Error::AbiValueOutOfRange)?;
            let handle_type = buffer.handle_type;
            if result == 0 {
                if reported_bytes == 0 || reported_bytes > capacity {
                    return Err(Error::InvalidFileHandle);
                }
                return Ok((handle_type, buffer.handle[..reported_bytes].to_vec()));
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EOVERFLOW)
                && attempt == 0
                && reported_bytes > capacity
                && reported_bytes <= PERSISTENT_FILE_HANDLE_MAX_BYTES
            {
                capacity = reported_bytes;
                continue;
            }
            if error.raw_os_error() == Some(libc::EOVERFLOW)
                && reported_bytes > PERSISTENT_FILE_HANDLE_MAX_BYTES
            {
                return Err(Error::FileHandleTooLarge {
                    requested: reported_bytes,
                });
            }
            return Err(Error::ReadFileHandle(error));
        }
        Err(Error::InvalidFileHandle)
    }

    fn read_metadata(
        fd: BorrowedFd<'_>,
        metadata_type: u64,
        buffer: &mut [u8],
    ) -> Result<usize, Error> {
        let mut argument = ReadMetadataArg::for_buffer(metadata_type, buffer)?;
        // SAFETY: `argument` is a fully initialized `struct
        // fsverity_read_metadata_arg`; its UAPI buffer pointer names the live,
        // writable `buffer` allocation for exactly `argument.length` bytes;
        // and `fd` remains valid for this call.
        let result = unsafe {
            libc::ioctl(
                fd.as_raw_fd(),
                linux_raw_sys::ioctl::FS_IOC_READ_VERITY_METADATA as libc::Ioctl,
                std::ptr::addr_of_mut!(argument),
            )
        };
        if result == -1 {
            return Err(Error::ReadMetadata(std::io::Error::last_os_error()));
        }
        usize::try_from(result).map_err(|_| Error::AbiValueOutOfRange)
    }

    fn require_exact_metadata_length(expected: usize, actual: usize) -> Result<(), Error> {
        if actual != expected {
            return Err(Error::UnexpectedMetadataLength { expected, actual });
        }
        Ok(())
    }

    fn verify_descriptor(descriptor: Descriptor) -> Result<(), Error> {
        if descriptor.version() != FS_VERITY_DESCRIPTOR_VERSION
            || descriptor.hash_algorithm() != FS_VERITY_DESCRIPTOR_HASH_ALG_SHA256
            || descriptor.log_blocksize() != FS_VERITY_LOG_BLOCK_SIZE
            || descriptor.salt_size() != 0
        {
            return Err(Error::UnsupportedDescriptorProfile {
                version: descriptor.version(),
                hash_algorithm: descriptor.hash_algorithm(),
                log_blocksize: descriptor.log_blocksize(),
                salt_size: descriptor.salt_size(),
            });
        }
        if !descriptor.has_canonical_zeroed_fields() {
            return Err(Error::MalformedDescriptor);
        }
        Ok(())
    }

    fn verify_no_builtin_signature(length: usize, probe: &[u8]) -> Result<(), Error> {
        require_exact_metadata_length(probe.len(), length)?;
        // The content is intentionally not parsed: any readable byte proves a
        // built-in signature exists, which this profile rejects.
        Err(Error::BuiltInSignature)
    }

    fn digest_from_kernel(digest: DigestBuffer) -> Result<[u8; DIGEST_BYTES], Error> {
        if digest.algorithm != FS_VERITY_DIGEST_ALG_SHA256 || digest.digest_size != DIGEST_BYTES_U16
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
        use std::os::unix::fs::MetadataExt as _;
        use std::path::PathBuf;
        use std::process::Command;

        #[test]
        fn fixed_enable_argument_layout_and_profile_are_deterministic() {
            let argument = EnableArg::fixed_profile();

            // The Linux UAPI reads this structure by its C field offsets and
            // total byte size.  A 32-bit C ABI may align `u64` to four bytes,
            // while 64-bit ABIs normally align it to eight; both layouts have
            // the same UAPI offsets and 128-byte extent.
            assert_eq!(size_of::<EnableArg>(), 128);
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
        fn filesystem_uuid_ioctl_uses_the_target_uapi_encoding() {
            assert_eq!(size_of::<FilesystemUuid>(), 17);
            assert_eq!(
                FS_IOC_GETFSUUID,
                libc::_IOR::<FilesystemUuid>(0x15, 0),
                "the request must be derived from the target's _IOR ABI"
            );
            #[cfg(any(
                target_arch = "mips",
                target_arch = "mips64",
                target_arch = "powerpc",
                target_arch = "powerpc64",
                target_arch = "sparc",
                target_arch = "sparc64"
            ))]
            assert_eq!(FS_IOC_GETFSUUID, 0x4011_1500);
            #[cfg(not(any(
                target_arch = "mips",
                target_arch = "mips64",
                target_arch = "powerpc",
                target_arch = "powerpc64",
                target_arch = "sparc",
                target_arch = "sparc64"
            )))]
            assert_eq!(FS_IOC_GETFSUUID, 0x8011_1500_u32 as libc::Ioctl);
        }

        #[test]
        fn descriptor_and_read_metadata_uapi_layouts_match_x86_64_and_i686() {
            // `struct fsverity_descriptor` consists solely of bytes.  Keep
            // each UAPI field range explicit so the parser cannot drift from
            // its 256-byte on-wire layout on either supported x86 ABI.
            assert_eq!(size_of::<Descriptor>(), DESCRIPTOR_BYTES);
            assert_eq!(align_of::<Descriptor>(), 1);
            assert_eq!(Descriptor::VERSION, 0);
            assert_eq!(Descriptor::HASH_ALGORITHM, 1);
            assert_eq!(Descriptor::LOG_BLOCKSIZE, 2);
            assert_eq!(Descriptor::SALT_SIZE, 3);
            assert_eq!(Descriptor::RESERVED_0X04, 4..8);
            assert_eq!(Descriptor::ROOT_HASH_SHA256, 16..48);
            assert_eq!(Descriptor::ROOT_HASH_UNUSED, 48..80);
            assert_eq!(Descriptor::SALT, 80..112);
            assert_eq!(Descriptor::RESERVED, 112..256);

            // `struct fsverity_read_metadata_arg` is five UAPI u64 fields.
            assert_eq!(size_of::<ReadMetadataArg>(), 40);
            assert_eq!(align_of::<ReadMetadataArg>(), align_of::<u64>());
            assert_eq!(offset_of!(ReadMetadataArg, metadata_type), 0);
            assert_eq!(offset_of!(ReadMetadataArg, offset), 8);
            assert_eq!(offset_of!(ReadMetadataArg, length), 16);
            assert_eq!(offset_of!(ReadMetadataArg, buf_ptr), 24);
            assert_eq!(offset_of!(ReadMetadataArg, reserved), 32);
            assert_eq!(
                linux_raw_sys::ioctl::FS_IOC_READ_VERITY_METADATA,
                3_223_873_159
            );
        }

        #[test]
        fn descriptor_and_signature_metadata_arguments_are_exact() {
            let mut descriptor = Descriptor::zeroed();
            let descriptor_pointer = uapi_pointer(descriptor.as_mut_bytes().as_mut_ptr()).unwrap();
            let descriptor_argument = ReadMetadataArg::for_buffer(
                FS_VERITY_METADATA_TYPE_DESCRIPTOR,
                descriptor.as_mut_bytes(),
            )
            .unwrap();
            assert_eq!(
                descriptor_argument.metadata_type,
                FS_VERITY_METADATA_TYPE_DESCRIPTOR
            );
            assert_eq!(descriptor_argument.offset, 0);
            assert_eq!(
                descriptor_argument.length,
                u64::try_from(DESCRIPTOR_BYTES).unwrap()
            );
            assert_eq!(descriptor_argument.buf_ptr, descriptor_pointer);
            assert_eq!(descriptor_argument.reserved, 0);

            let mut signature_probe = [0_u8; 1];
            let signature_argument = ReadMetadataArg::for_buffer(
                FS_VERITY_METADATA_TYPE_SIGNATURE,
                &mut signature_probe,
            )
            .unwrap();
            assert_eq!(
                signature_argument.metadata_type,
                FS_VERITY_METADATA_TYPE_SIGNATURE
            );
            assert_eq!(signature_argument.offset, 0);
            assert_eq!(signature_argument.length, 1);
            assert_ne!(signature_argument.buf_ptr, 0);
            assert_eq!(signature_argument.reserved, 0);
        }

        #[test]
        fn descriptor_parser_accepts_only_the_complete_fixed_profile() {
            let mut accepted = Descriptor::zeroed();
            accepted.0[Descriptor::VERSION] = FS_VERITY_DESCRIPTOR_VERSION;
            accepted.0[Descriptor::HASH_ALGORITHM] = FS_VERITY_DESCRIPTOR_HASH_ALG_SHA256;
            accepted.0[Descriptor::LOG_BLOCKSIZE] = FS_VERITY_LOG_BLOCK_SIZE;
            accepted.0[8..16].copy_from_slice(&42_u64.to_le_bytes());
            accepted.0[Descriptor::ROOT_HASH_SHA256].fill(0x5a);
            assert!(verify_descriptor(accepted).is_ok());

            for (field, value) in [
                (Descriptor::VERSION, 2),
                (Descriptor::HASH_ALGORITHM, 2),
                (Descriptor::LOG_BLOCKSIZE, 10),
                (Descriptor::SALT_SIZE, 1),
            ] {
                let mut rejected = accepted;
                rejected.0[field] = value;
                assert!(matches!(
                    verify_descriptor(rejected),
                    Err(Error::UnsupportedDescriptorProfile { .. })
                ));
            }

            for byte in [
                Descriptor::RESERVED_0X04.start,
                Descriptor::ROOT_HASH_UNUSED.start,
                Descriptor::SALT.start,
                Descriptor::RESERVED.start,
            ] {
                let mut malformed = accepted;
                malformed.0[byte] = 1;
                assert!(matches!(
                    verify_descriptor(malformed),
                    Err(Error::MalformedDescriptor)
                ));
            }

            assert!(matches!(
                require_exact_metadata_length(DESCRIPTOR_BYTES, DESCRIPTOR_BYTES - 1),
                Err(Error::UnexpectedMetadataLength {
                    expected: DESCRIPTOR_BYTES,
                    actual,
                }) if actual == DESCRIPTOR_BYTES - 1
            ));
        }

        #[test]
        fn signature_probe_rejects_any_nonempty_hostile_metadata() {
            // Creating a real built-in signature requires a configured
            // `.fs-verity` keyring and a valid detached PKCS#7 signature.  The
            // production check intentionally does not parse that hostile
            // format: one readable byte proves a signature exists and fails.
            for hostile_signature_byte in [0x00, 0x30, 0xff] {
                assert!(matches!(
                    verify_no_builtin_signature(1, &[hostile_signature_byte]),
                    Err(Error::BuiltInSignature)
                ));
            }
            assert!(matches!(
                verify_no_builtin_signature(0, &[0]),
                Err(Error::UnexpectedMetadataLength {
                    expected: 1,
                    actual: 0,
                })
            ));
            assert!(matches!(
                verify_no_builtin_signature(2, &[0]),
                Err(Error::UnexpectedMetadataLength {
                    expected: 1,
                    actual: 2,
                })
            ));
        }

        #[test]
        fn digest_parser_accepts_only_the_fixed_sha256_shape() {
            let mut accepted = DigestBuffer::requested_sha256();
            accepted.algorithm = FS_VERITY_DIGEST_ALG_SHA256;
            accepted.digest = [0x5a; DIGEST_BYTES];
            assert_eq!(digest_from_kernel(accepted).unwrap(), [0x5a; DIGEST_BYTES]);

            for (algorithm, digest_size) in [
                (0, DIGEST_BYTES_U16),
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
        fn persistent_file_identity_is_stable_and_rejects_forced_inode_reuse_when_supported() {
            let directory = tempfile::tempdir().expect("create identity qualification directory");
            let path = directory.path().join("persistent-file-identity");
            std::fs::write(&path, b"persistent file identity A")
                .expect("write identity qualification file");
            let original = File::open(&path).expect("open original identity file");
            let first = match persistent_file_identity(original.as_fd()) {
                Ok(identity) => identity,
                Err(Error::ReadFilesystemUuid(error) | Error::ReadFileHandle(error))
                    if is_persistent_identity_unsupported(&error) =>
                {
                    skip_or_fail_unsupported("persistent file identity", &error);
                    return;
                }
                Err(error) => panic!("read persistent file identity: {error}"),
            };
            assert_ne!(first.filesystem_uuid(), &[0; FILESYSTEM_UUID_BYTES]);
            assert!(!first.handle_bytes().is_empty());
            assert!(first.handle_bytes().len() <= PERSISTENT_FILE_HANDLE_MAX_BYTES);
            assert_eq!(
                first,
                persistent_file_identity(original.as_fd()).expect("repeat identity for held file")
            );

            let original_inode = original
                .metadata()
                .expect("read original identity metadata")
                .ino();
            // A comparison-only handle must distinguish a recreated object
            // even if this filesystem recycles its inode number. The hosted
            // qualification requires an actual reuse, rather than treating a
            // merely different inode as evidence for this crash boundary.
            drop(original);
            std::fs::remove_file(&path).expect("remove original identity file");
            let replacement = (0..4_096).find_map(|_| {
                std::fs::write(&path, b"persistent file identity A")
                    .expect("recreate byte-identical identity file");
                let candidate = File::open(&path).expect("open replacement identity file");
                if candidate
                    .metadata()
                    .expect("read replacement identity metadata")
                    .ino()
                    == original_inode
                {
                    Some(candidate)
                } else {
                    drop(candidate);
                    std::fs::remove_file(&path).expect("remove non-reused candidate");
                    None
                }
            });
            let Some(replacement) = replacement else {
                if qualification_required() {
                    panic!(
                        "persistent identity qualification filesystem did not recycle an inode within the bounded test"
                    );
                }
                eprintln!(
                    "persistent identity inode-reuse qualification unavailable on this filesystem"
                );
                return;
            };
            assert_eq!(
                replacement
                    .metadata()
                    .expect("read reused replacement identity metadata")
                    .ino(),
                original_inode,
                "the qualification must exercise an actual reused inode number"
            );
            let replacement = persistent_file_identity(replacement.as_fd())
                .expect("read replacement persistent identity");
            assert_ne!(
                first, replacement,
                "recreated inode retained a prior durable file handle"
            );
        }

        #[test]
        fn persistent_file_identity_survives_a_separate_bind_mount_when_supported() {
            let directory = tempfile::tempdir().expect("create remount qualification directory");
            let source = directory.path().join("source");
            let mounted = directory.path().join("mounted");
            std::fs::create_dir(&source).expect("create bind source directory");
            std::fs::create_dir(&mounted).expect("create bind target directory");
            let file_name = "persistent-file-identity";
            let source_file = source.join(file_name);
            std::fs::write(
                &source_file,
                b"persistent file identity mount qualification",
            )
            .expect("write bind source file");
            let source_descriptor = File::open(&source_file).expect("open bind source file");
            let source_identity = match persistent_file_identity(source_descriptor.as_fd()) {
                Ok(identity) => identity,
                Err(Error::ReadFilesystemUuid(error) | Error::ReadFileHandle(error))
                    if is_persistent_identity_unsupported(&error) =>
                {
                    skip_or_fail_unsupported("persistent file identity", &error);
                    return;
                }
                Err(error) => panic!("read bind-source persistent identity: {error}"),
            };

            let direct_output = Command::new("mount")
                .arg("--bind")
                .arg(&source)
                .arg(&mounted)
                .output()
                .expect("execute bind mount qualification");
            let mounted_with_sudo = if direct_output.status.success() {
                false
            } else {
                match Command::new("sudo")
                    .args(["-n", "mount", "--bind"])
                    .arg(&source)
                    .arg(&mounted)
                    .output()
                {
                    Ok(output) if output.status.success() => true,
                    Ok(output) => {
                        if qualification_required() {
                            panic!(
                                "persistent identity bind-mount qualification requires CAP_SYS_ADMIN or passwordless sudo (direct mount {}, sudo mount {})",
                                direct_output.status, output.status,
                            );
                        }
                        eprintln!(
                            "persistent identity bind-mount qualification unavailable (direct mount {}, sudo mount {})",
                            direct_output.status, output.status,
                        );
                        return;
                    }
                    Err(error) => {
                        if qualification_required() {
                            panic!(
                                "persistent identity bind-mount qualification requires CAP_SYS_ADMIN or passwordless sudo after direct mount {}: {error}",
                                direct_output.status,
                            );
                        }
                        eprintln!(
                            "persistent identity bind-mount qualification unavailable (direct mount {}, sudo unavailable: {error})",
                            direct_output.status,
                        );
                        return;
                    }
                }
            };
            let mut mount = ScopedBindMount {
                target: mounted.clone(),
                mounted: true,
                mounted_with_sudo,
            };
            let mounted_descriptor =
                File::open(mounted.join(file_name)).expect("open bind-mounted source file");
            assert_eq!(
                source_identity,
                persistent_file_identity(mounted_descriptor.as_fd())
                    .expect("read bind-mounted persistent identity"),
                "a new mount instance for the same file must retain the durable UUID + handle"
            );
            assert_eq!(
                source_descriptor
                    .metadata()
                    .expect("read source metadata")
                    .ino(),
                mounted_descriptor
                    .metadata()
                    .expect("read bind-mounted metadata")
                    .ino(),
                "the bind mount must expose the same source inode"
            );
            // The descriptor obtained through the bind mount pins that mount
            // instance. Release it before the guaranteed unmount cleanup.
            drop(mounted_descriptor);
            mount.unmount().expect("unmount bind qualification");
        }

        struct ScopedBindMount {
            target: PathBuf,
            mounted: bool,
            mounted_with_sudo: bool,
        }

        impl ScopedBindMount {
            fn run_umount(&self, with_sudo: bool) -> std::io::Result<std::process::Output> {
                if with_sudo {
                    Command::new("sudo")
                        .args(["-n", "umount"])
                        .arg(&self.target)
                        .output()
                } else {
                    Command::new("umount").arg(&self.target).output()
                }
            }

            fn umount(&self) -> std::io::Result<()> {
                let preferred = self.run_umount(self.mounted_with_sudo)?;
                if preferred.status.success() {
                    return Ok(());
                }
                let fallback = self.run_umount(!self.mounted_with_sudo)?;
                if fallback.status.success() {
                    return Ok(());
                }
                Err(std::io::Error::other(format!(
                    "persistent identity bind-mount qualification unmount failed (preferred {}: {}; fallback {}: {})",
                    preferred.status,
                    String::from_utf8_lossy(&preferred.stderr).trim(),
                    fallback.status,
                    String::from_utf8_lossy(&fallback.stderr).trim(),
                )))
            }

            fn unmount(&mut self) -> std::io::Result<()> {
                if !self.mounted {
                    return Ok(());
                }
                self.umount()?;
                self.mounted = false;
                Ok(())
            }
        }

        impl Drop for ScopedBindMount {
            fn drop(&mut self) {
                if self.mounted {
                    let _ = self.umount();
                }
            }
        }

        #[test]
        fn persistent_file_identity_survives_a_separate_loop_image_remount() {
            // This qualification deliberately uses a wholly test-owned image
            // and mountpoint.  In particular it never mounts, unmounts, or
            // otherwise mutates the harness's prepared fs-verity filesystem.
            let directory = tempfile::tempdir().expect("create loop qualification directory");
            let image = directory.path().join("persistent-identity.ext4");
            let mountpoint = directory.path().join("mounted");
            std::fs::create_dir(&mountpoint).expect("create loop mountpoint");
            let image_file = File::create(&image).expect("create loop image");
            image_file
                .set_len(64 * 1024 * 1024)
                .expect("size loop image");
            drop(image_file);

            let format = Command::new("mkfs.ext4")
                .args(["-q", "-F", "-O", "verity"])
                .arg(&image)
                .output();
            let format = match format {
                Ok(output) if output.status.success() => output,
                Ok(output) => {
                    if qualification_required() {
                        panic!(
                            "persistent identity loop-remount qualification could not format its test image ({})",
                            output.status
                        );
                    }
                    eprintln!(
                        "persistent identity loop-remount qualification unavailable: mkfs.ext4 {}",
                        output.status
                    );
                    return;
                }
                Err(error) => {
                    if qualification_required() {
                        panic!(
                            "persistent identity loop-remount qualification requires mkfs.ext4: {error}"
                        );
                    }
                    eprintln!(
                        "persistent identity loop-remount qualification unavailable: mkfs.ext4: {error}"
                    );
                    return;
                }
            };
            drop(format);

            let mut mount = match ScopedLoopMount::mount(&image, &mountpoint) {
                Ok(mount) => mount,
                Err(error) => {
                    if qualification_required() {
                        panic!(
                            "persistent identity loop-remount qualification requires passwordless sudo loop mounting: {error}"
                        );
                    }
                    eprintln!(
                        "persistent identity loop-remount qualification unavailable: {error}"
                    );
                    return;
                }
            };
            let file_name = "persistent-file-identity";
            let path = mountpoint.join(file_name);
            std::fs::write(
                &path,
                b"persistent file identity loop remount qualification",
            )
            .expect("write loop-qualified file");
            let source = File::open(&path).expect("open loop-qualified file");
            let identity = match persistent_file_identity(source.as_fd()) {
                Ok(identity) => identity,
                Err(Error::ReadFilesystemUuid(error) | Error::ReadFileHandle(error))
                    if is_persistent_identity_unsupported(&error) =>
                {
                    skip_or_fail_unsupported("persistent file identity", &error);
                    return;
                }
                Err(error) => panic!("read loop-qualified persistent identity: {error}"),
            };
            // The image is formatted with ext4's `verity` feature, but this
            // qualification concerns the separate durable UUID+handle
            // contract. Fixed-profile sealing is exercised on the prepared
            // fs-verity mount by `linux_ioctl_qualification_requires_ci_filesystem_to_seal`.
            // Keeping the checks separate ensures a hosted image policy which
            // rejects new verity enables cannot mask a remount identity bug.
            // The proof must survive after all original descriptors are gone,
            // not merely while one held file keeps the old mount live.
            drop(source);
            mount.unmount().expect("unmount test-owned loop image");
            mount
                .remount(&image)
                .expect("remount test-owned loop image");

            let reopened = File::open(mountpoint.join(file_name))
                .expect("reopen remounted loop-qualified file");
            assert_eq!(
                identity,
                persistent_file_identity(reopened.as_fd())
                    .expect("read remounted persistent identity"),
                "a remount of the same ext4 image retains its filesystem UUID and opaque handle"
            );
            drop(reopened);
            mount
                .unmount()
                .expect("final unmount of test-owned loop image");
        }

        struct ScopedLoopMount {
            target: PathBuf,
            mounted: bool,
        }

        impl ScopedLoopMount {
            fn mount(image: &std::path::Path, target: &std::path::Path) -> std::io::Result<Self> {
                let output = Command::new("sudo")
                    .args(["-n", "mount", "-o", "loop"])
                    .arg(image)
                    .arg(target)
                    .output()?;
                if !output.status.success() {
                    return Err(std::io::Error::other(format!(
                        "test-owned loop mount failed ({})",
                        output.status
                    )));
                }
                let mount = Self {
                    target: target.to_path_buf(),
                    mounted: true,
                };
                mount.make_test_directory_writable()?;
                Ok(mount)
            }

            fn remount(&mut self, image: &std::path::Path) -> std::io::Result<()> {
                if self.mounted {
                    return Err(std::io::Error::other(
                        "test-owned loop mount is already active",
                    ));
                }
                let output = Command::new("sudo")
                    .args(["-n", "mount", "-o", "loop"])
                    .arg(image)
                    .arg(&self.target)
                    .output()?;
                if !output.status.success() {
                    return Err(std::io::Error::other(format!(
                        "test-owned loop remount failed ({})",
                        output.status
                    )));
                }
                self.mounted = true;
                self.make_test_directory_writable()?;
                Ok(())
            }

            fn make_test_directory_writable(&self) -> std::io::Result<()> {
                let output = Command::new("sudo")
                    .args(["-n", "chmod", "0777"])
                    .arg(&self.target)
                    .output()?;
                if !output.status.success() {
                    return Err(std::io::Error::other(format!(
                        "test-owned loop mount permissions setup failed ({})",
                        output.status
                    )));
                }
                Ok(())
            }

            fn unmount(&mut self) -> std::io::Result<()> {
                if !self.mounted {
                    return Ok(());
                }
                let output = Command::new("sudo")
                    .args(["-n", "umount"])
                    .arg(&self.target)
                    .output()?;
                if !output.status.success() {
                    return Err(std::io::Error::other(format!(
                        "test-owned loop unmount failed ({})",
                        output.status
                    )));
                }
                self.mounted = false;
                Ok(())
            }
        }

        impl Drop for ScopedLoopMount {
            fn drop(&mut self) {
                let _ = self.unmount();
            }
        }

        #[test]
        fn persistent_identity_ignores_mount_instance_and_rejects_reused_inode_fixture() {
            // `name_to_handle_at` reports a mount ID as an out parameter, but
            // it is deliberately not persisted: remounting the same
            // filesystem changes that transient ID. This deterministic seam
            // models that remount while preserving the UUID + opaque handle,
            // then models inode-number reuse with a changed handle
            // generation. The durable comparison must accept only the first.
            #[derive(Clone)]
            struct LiveObservation {
                mount_instance_id: i32,
                inode: u64,
                durable: PersistentFileIdentity,
            }

            let original = LiveObservation {
                mount_instance_id: 17,
                inode: 91,
                durable: PersistentFileIdentity {
                    filesystem_uuid: [0x51; FILESYSTEM_UUID_BYTES],
                    handle_type: 1,
                    handle: vec![0xa1, 0xb2, 0xc3].into_boxed_slice(),
                },
            };
            let remounted_same_object = LiveObservation {
                mount_instance_id: 18,
                inode: original.inode,
                durable: original.durable.clone(),
            };
            let recreated_with_reused_inode = LiveObservation {
                mount_instance_id: remounted_same_object.mount_instance_id,
                inode: original.inode,
                durable: PersistentFileIdentity {
                    filesystem_uuid: [0x51; FILESYSTEM_UUID_BYTES],
                    handle_type: 1,
                    handle: vec![0xa1, 0xb2, 0xc4].into_boxed_slice(),
                },
            };

            assert_ne!(
                original.mount_instance_id, remounted_same_object.mount_instance_id,
                "fixture models a new mount instance"
            );
            assert_eq!(original.inode, remounted_same_object.inode);
            assert_eq!(
                original.durable, remounted_same_object.durable,
                "a remount of the same file retains its durable identity"
            );
            assert_eq!(original.inode, recreated_with_reused_inode.inode);
            assert_ne!(
                original.durable, recreated_with_reused_inode.durable,
                "a new generation cannot inherit a recycled inode number"
            );
        }

        #[test]
        fn linux_ioctl_qualification_requires_ci_filesystem_to_seal() {
            let mut temporary = fs_verity_qualification_file();
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
                    skip_or_fail_unsupported("measure", &error);
                    return;
                }
                result => {
                    panic!("expected pre-seal ENODATA or unsupported filesystem, got {result:?}")
                }
            }

            let digest = match enable_fixed_profile(reader.as_fd()) {
                Ok(digest) => digest,
                Err(Error::Enable(error)) if is_unsupported(&error) => {
                    skip_or_fail_unsupported("enable", &error);
                    return;
                }
                Err(Error::ReadMetadata(error)) if is_unsupported(&error) => {
                    skip_or_fail_unsupported("read metadata", &error);
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
            verify_exact_profile(reader.as_fd()).expect("verify exact sealed profile");
            assert_eq!(
                measure_exact_profile(reader.as_fd()).expect("measure exact sealed profile"),
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

        #[test]
        fn linux_ioctl_qualification_rejects_nonstandard_profiles() {
            let salt = [0xa5_u8];
            let mut salted = EnableArg::fixed_profile();
            salted.salt_size = u32::try_from(salt.len()).expect("one-byte salt fits UAPI");
            salted.salt_ptr = uapi_pointer(salt.as_ptr()).expect("salt pointer fits UAPI");
            assert_nonstandard_profile_is_rejected("salt", &salted);

            let mut alternate_block_size = EnableArg::fixed_profile();
            alternate_block_size.block_size = 1024;
            assert_nonstandard_profile_is_rejected("1024-byte block", &alternate_block_size);
        }

        fn assert_nonstandard_profile_is_rejected(profile: &str, enable: &EnableArg) {
            let mut temporary = fs_verity_qualification_file();
            temporary
                .write_all(b"nonstandard fs-verity qualification payload")
                .expect("write qualification file");
            temporary
                .as_file()
                .sync_all()
                .expect("sync qualification file");
            let path = temporary.into_temp_path();
            let reader = File::open(&path).expect("open qualification reader");

            match enable_verity(reader.as_fd(), enable) {
                Ok(()) => {}
                Err(error) if is_unsupported(&error) => {
                    skip_or_fail_unsupported(profile, &error);
                    return;
                }
                Err(error) if custom_profile_is_unavailable(&error) => {
                    skip_or_fail_custom_profile(profile, &error);
                    return;
                }
                Err(error) => panic!("enable {profile} fs-verity profile: {error}"),
            }

            // This confirms the old SHA-256-only measurement would have
            // accepted the file, while the exact-profile API rejects it.
            measure(reader.as_fd()).expect("measure nonstandard SHA-256 profile");
            assert!(matches!(
                verify_exact_profile(reader.as_fd()),
                Err(Error::UnsupportedDescriptorProfile { .. })
            ));
            assert!(matches!(
                measure_exact_profile(reader.as_fd()),
                Err(Error::UnsupportedDescriptorProfile { .. })
            ));
        }

        fn is_unsupported(error: &std::io::Error) -> bool {
            matches!(
                error.raw_os_error(),
                Some(libc::ENOTTY | libc::EOPNOTSUPP | libc::ENOSYS)
            )
        }

        fn is_persistent_identity_unsupported(error: &std::io::Error) -> bool {
            matches!(
                error.raw_os_error(),
                Some(libc::ENOTTY | libc::EOPNOTSUPP | libc::ENOSYS | libc::EINVAL | libc::EPERM)
            )
        }

        fn qualification_required() -> bool {
            std::env::var_os("OPC_FS_VERITY_QUALIFICATION").as_deref()
                == Some(std::ffi::OsStr::new("required"))
        }

        /// Creates only kernel-seal qualification artifacts on CI's prepared
        /// fs-verity mount. General temporary I/O remains on the runner's
        /// native filesystem.
        fn fs_verity_qualification_file() -> tempfile::NamedTempFile {
            const SNAPSHOT_ROOT_ENV: &str = "OPC_FS_VERITY_SNAPSHOT_ROOT";

            match std::env::var_os(SNAPSHOT_ROOT_ENV) {
                Some(root) => {
                    let root = PathBuf::from(root);
                    assert!(
                        root.is_absolute(),
                        "{SNAPSHOT_ROOT_ENV} must be an absolute fs-verity qualification root"
                    );
                    tempfile::NamedTempFile::new_in(root)
                        .expect("create fs-verity qualification file")
                }
                None if qualification_required() => {
                    panic!("required fs-verity qualification requires {SNAPSHOT_ROOT_ENV}")
                }
                None => tempfile::NamedTempFile::new().expect("create local qualification file"),
            }
        }

        fn custom_profile_is_unavailable(error: &std::io::Error) -> bool {
            matches!(error.raw_os_error(), Some(libc::EINVAL | libc::ENOPKG))
        }

        fn skip_or_fail_unsupported(operation: &str, error: &std::io::Error) {
            if qualification_required() {
                panic!(
                    "CI prepared an fs-verity filesystem, but {operation} was unsupported: {error}"
                );
            }
            eprintln!("fs-verity {operation} unsupported on this filesystem: {error}");
        }

        fn skip_or_fail_custom_profile(profile: &str, error: &std::io::Error) {
            if qualification_required() {
                panic!(
                    "CI prepared an fs-verity filesystem, but the {profile} negative qualification could not be created: {error}"
                );
            }
            eprintln!(
                "fs-verity {profile} negative qualification unavailable on this kernel/filesystem: {error}"
            );
        }
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
mod platform {
    use super::{Error, PersistentFileIdentity, DIGEST_BYTES};
    use std::os::fd::BorrowedFd;

    pub(super) fn enable_fixed_profile(_fd: BorrowedFd<'_>) -> Result<[u8; DIGEST_BYTES], Error> {
        Err(Error::Unsupported)
    }

    pub(super) fn measure(_fd: BorrowedFd<'_>) -> Result<[u8; DIGEST_BYTES], Error> {
        Err(Error::Unsupported)
    }

    pub(super) fn verify_exact_profile(_fd: BorrowedFd<'_>) -> Result<(), Error> {
        Err(Error::Unsupported)
    }

    pub(super) fn measure_exact_profile(_fd: BorrowedFd<'_>) -> Result<[u8; DIGEST_BYTES], Error> {
        Err(Error::Unsupported)
    }

    pub(super) fn persistent_file_identity(
        _fd: BorrowedFd<'_>,
    ) -> Result<PersistentFileIdentity, Error> {
        Err(Error::Unsupported)
    }
}
