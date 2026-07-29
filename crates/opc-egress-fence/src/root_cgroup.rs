//! Exact descriptor proof for the host's default cgroup-v2 hierarchy root.

use std::{
    fmt, io,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    path::Path,
};

use rustix::fs::{fstat, fstatfs, open, FileType, Mode, OFlags};

const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;
const DEFAULT_HIERARCHY_ROOT_INODE: u64 = 1;

/// Owned descriptor for the true root of the host's default cgroup-v2
/// hierarchy.
///
/// Construction proves the opened object is a directory on a cgroup-v2
/// superblock and has the root cgroup's fixed inode/cgroup identifier `1`.
/// A container-visible delegated subtree, cgroup namespace root, regular
/// directory, symlink at the final component, or cgroup-v1 hierarchy is
/// rejected. The validated descriptor, rather than its path, is used for all
/// subsequent BPF query and attach operations.
pub struct HostCgroupV2Root {
    descriptor: OwnedFd,
}

impl HostCgroupV2Root {
    /// Open and prove one operator-mounted host cgroup-v2 root.
    ///
    /// `path` must be absolute. The final path component may not be a symlink.
    ///
    /// # Errors
    ///
    /// Returns a value-free operating-system error when opening or metadata
    /// reads fail, or `InvalidData` unless the descriptor is exactly the
    /// cgroup-v2 default-hierarchy root with inode/cgroup identifier `1`.
    pub fn open(path: &Path) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(root_error(io::ErrorKind::InvalidInput));
        }
        let descriptor = open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io::Error::from)?;
        let filesystem = fstatfs(&descriptor).map_err(io::Error::from)?;
        let metadata = fstat(&descriptor).map_err(io::Error::from)?;
        validate_root_metadata(
            filesystem.f_type as u64,
            metadata.st_ino,
            FileType::from_raw_mode(metadata.st_mode).is_dir(),
        )?;
        Ok(Self { descriptor })
    }

    /// Borrow the exact validated cgroup directory descriptor.
    #[must_use]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.descriptor.as_fd()
    }
}

impl fmt::Debug for HostCgroupV2Root {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HostCgroupV2Root(<redacted>)")
    }
}

fn validate_root_metadata(filesystem_type: u64, inode: u64, is_directory: bool) -> io::Result<()> {
    if filesystem_type != CGROUP2_SUPER_MAGIC
        || inode != DEFAULT_HIERARCHY_ROOT_INODE
        || !is_directory
    {
        return Err(root_error(io::ErrorKind::InvalidData));
    }
    Ok(())
}

fn root_error(kind: io::ErrorKind) -> io::Error {
    io::Error::new(kind, "egress_fence_cgroup_root")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::fd::AsRawFd, path::PathBuf};

    #[test]
    fn exact_cgroup2_root_metadata_is_required() {
        assert!(validate_root_metadata(CGROUP2_SUPER_MAGIC, 1, true).is_ok());

        for (filesystem_type, inode, is_directory) in [
            (0, 1, true),
            (CGROUP2_SUPER_MAGIC, 2, true),
            (CGROUP2_SUPER_MAGIC, 1, false),
        ] {
            let error = validate_root_metadata(filesystem_type, inode, is_directory)
                .expect_err("non-root metadata must fail closed");
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(error.to_string(), "egress_fence_cgroup_root");
        }
    }

    #[test]
    fn relative_path_is_rejected_before_open() {
        let error =
            HostCgroupV2Root::open(Path::new("sys/fs/cgroup")).expect_err("relative cgroup path");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(error.to_string(), "egress_fence_cgroup_root");
    }

    #[test]
    fn ordinary_directory_cannot_be_used_as_cgroup_root() {
        let temporary = tempfile_directory();
        let error =
            HostCgroupV2Root::open(&temporary).expect_err("ordinary filesystem must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        std::fs::remove_dir(&temporary).expect("remove empty test directory");
    }

    #[test]
    fn live_default_hierarchy_is_accepted_when_host_visible() {
        let path = Path::new("/sys/fs/cgroup");
        if !path.exists() {
            return;
        }
        match HostCgroupV2Root::open(path) {
            Ok(root) => {
                assert!(root.as_fd().as_fd().as_raw_fd() >= 0);
                assert_eq!(format!("{root:?}"), "HostCgroupV2Root(<redacted>)");
            }
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                // A delegated/container cgroup namespace is deliberately not
                // production-authoritative. Pure metadata tests above retain
                // the exact detector on generic SDK build hosts.
            }
            Err(error) => panic!("unexpected cgroup-root probe failure: {error}"),
        }
    }

    fn tempfile_directory() -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "opc-egress-fence-cgroup-root-{}",
            std::process::id()
        ));
        match std::fs::create_dir(&path) {
            Ok(()) => path,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                std::fs::remove_dir(&path).expect("remove stale empty test directory");
                std::fs::create_dir(&path).expect("create replacement test directory");
                path
            }
            Err(error) => panic!("create test directory: {error}"),
        }
    }
}
