//! Explicit logical namespace and directory capability for snapshot admission.

use std::fs::File;
use std::io;
use std::path::PathBuf;

/// A snapshot namespace selected by pathname or by an explicitly pinned directory.
///
/// The configured absolute name owns cross-process exclusion and pending-cleanup
/// custody. It is not an I/O capability. A pinned directory separately owns the
/// filesystem object used by every snapshot operation after admission.
///
/// This handoff does not acquire a lease or qualify snapshot integrity. Those
/// checks remain part of opening the consensus store.
pub struct SnapshotDirectory(pub(crate) SnapshotDirectorySource);

pub(crate) enum SnapshotDirectorySource {
    Path(PathBuf),
    #[cfg(target_os = "linux")]
    Pinned {
        configured_path: PathBuf,
        canonical_directory: PathBuf,
        directory: File,
    },
}

impl std::fmt::Debug for SnapshotDirectory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SnapshotDirectory")
            .finish_non_exhaustive()
    }
}

impl SnapshotDirectory {
    /// Defer ordinary pathname admission until the consensus store is opened.
    ///
    /// This retains the existing pathname opener's creation, permission and
    /// symlink rules. Relative names are resolved during store admission.
    pub fn from_path(path: impl Into<PathBuf>) -> Self {
        Self(SnapshotDirectorySource::Path(path.into()))
    }

    /// Bind an existing configured namespace name to an owned directory on Linux.
    ///
    /// The name is made absolute now and must identify this exact directory at
    /// construction. Supply the original configured filesystem name, never a
    /// process-relative descriptor locator such as `/proc/self/fd/N/`. Neither a
    /// descriptor number nor the canonical target replaces that logical key.
    /// Linux `O_NOFOLLOW` applies to the terminal pathname lookup. Intermediate
    /// symlinks may be traversed, including a link followed by a trailing slash;
    /// this is not a spelling-independent symlink rejection policy. The resolved
    /// directory must match the supplied descriptor, be owned by the effective
    /// UID and not be group/world writable.
    ///
    /// An independent open-file description is acquired relative to `directory`.
    /// This prevents lease acquisition or failed admission from unlocking a flock
    /// held through the caller's original descriptor or one of its duplicates.
    /// After construction, renaming or replacing the configured path cannot
    /// redirect this handoff. Store admission rechecks the retained object's
    /// permission policy and acquires the ordinary directory/database leases.
    /// Pending cleanup retains the same configured key until its real owners
    /// retire. Construction fails closed if name/descriptor correspondence cannot
    /// be established, and returns `Unsupported` on other platforms.
    pub fn from_pinned(configured_path: impl Into<PathBuf>, directory: File) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt as _;
            use std::path::{absolute, Path};

            let configured_path = absolute(configured_path.into())?;
            let flags = nix::fcntl::OFlag::O_RDONLY
                | nix::fcntl::OFlag::O_DIRECTORY
                | nix::fcntl::OFlag::O_NOFOLLOW
                | nix::fcntl::OFlag::O_CLOEXEC
                | nix::fcntl::OFlag::O_NONBLOCK;
            let named = nix::fcntl::open(&configured_path, flags, nix::sys::stat::Mode::empty())
                .map(File::from)
                .map_err(io::Error::from)?;
            let supplied = directory.metadata()?;
            let named_metadata = named.metadata()?;
            if !supplied.is_dir()
                || supplied.uid() != nix::unistd::geteuid().as_raw()
                || supplied.mode() & 0o022 != 0
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "snapshot directory must be owned by the effective uid and not group/world writable",
                ));
            }
            let canonical_directory = std::fs::canonicalize(&configured_path)?;
            let canonical = std::fs::metadata(&canonical_directory)?;
            if (supplied.dev(), supplied.ino()) != (named_metadata.dev(), named_metadata.ino())
                || (supplied.dev(), supplied.ino()) != (canonical.dev(), canonical.ino())
            {
                return Err(io::Error::other(
                    "snapshot configured name does not identify the supplied directory",
                ));
            }
            // openat(".") creates a new open-file description. dup/try_clone
            // would share the caller's flock and can unlock it on rejection.
            let independent = nix::fcntl::openat(
                &directory,
                Path::new("."),
                flags,
                nix::sys::stat::Mode::empty(),
            )
            .map(File::from)
            .map_err(io::Error::from)?;
            let retained = independent.metadata()?;
            if (supplied.dev(), supplied.ino()) != (retained.dev(), retained.ino()) {
                return Err(io::Error::other("snapshot directory changed while pinning"));
            }
            Ok(Self(SnapshotDirectorySource::Pinned {
                configured_path,
                canonical_directory,
                directory: independent,
            }))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (configured_path, directory);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "pinned snapshot directory admission requires Linux",
            ))
        }
    }
}
