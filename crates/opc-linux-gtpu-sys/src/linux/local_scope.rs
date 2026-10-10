use std::ffi::CString;
use std::fs::File;
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::tc::ScopeError;

mod pins;
pub use pins::{LocalPin, LocalPinDirectory};

const BPF_FS_MAGIC: i64 = 0xcafe4a11;
const NSFS_MAGIC: i64 = 0x6e736673;
const NS_GET_NSTYPE: libc::Ioctl = 0xb703;
const AT_STATX_DONT_SYNC: libc::c_int = linux_raw_sys::general::AT_STATX_DONT_SYNC as libc::c_int;
const REQUIRED_STAT: u32 = linux_raw_sys::general::STATX_TYPE
    | linux_raw_sys::general::STATX_MODE
    | linux_raw_sys::general::STATX_NLINK
    | linux_raw_sys::general::STATX_UID
    | linux_raw_sys::general::STATX_INO
    | linux_raw_sys::general::STATX_MNT_ID;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity {
    major: u32,
    minor: u32,
    inode: u64,
    mount: u64,
    mode: u16,
    uid: u32,
    links: u32,
}

impl Identity {
    fn same_object(self, other: Self) -> bool {
        (
            self.major, self.minor, self.inode, self.mount, self.mode, self.uid,
        ) == (
            other.major,
            other.minor,
            other.inode,
            other.mount,
            other.mode,
            other.uid,
        )
    }
    fn private_directory(self) -> bool {
        // SAFETY: geteuid has no pointer arguments or side effects.
        self.uid == unsafe { libc::geteuid() }
            && u32::from(self.mode) & !libc::S_ISVTX == libc::S_IFDIR | 0o700
    }
    fn private_lock(self) -> bool {
        // SAFETY: geteuid has no pointer arguments or side effects.
        self.uid == unsafe { libc::geteuid() }
            && u32::from(self.mode) == libc::S_IFREG | 0o600
            && self.links == 1
    }
}

pub struct LocalScopeHandles {
    namespace: File,
    root: File,
    parent: File,
    lock: File,
    root_path: PathBuf,
    lock_path: PathBuf,
    root_identity: Identity,
    parent_identity: Identity,
    lock_identity: Identity,
}

impl LocalScopeHandles {
    pub fn open(root: &Path, lock: &Path) -> Result<Self, ScopeError> {
        Self::open_checked(root, lock, BPF_FS_MAGIC)
    }

    fn open_checked(
        root_path: &Path,
        lock_path: &Path,
        required_root_fs: i64,
    ) -> Result<Self, ScopeError> {
        if !root_path.is_absolute() || !lock_path.is_absolute() || lock_path.starts_with(root_path)
        {
            return Err(ScopeError::InvalidSpec);
        }
        let namespace = current_namespace()?;
        let root = open_path(root_path, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        let root_identity = identity(&root)?;
        if !root_identity.private_directory() || fs_magic(&root)? != required_root_fs {
            return Err(ScopeError::InvalidSpec);
        }
        let parent = open_path(
            lock_path.parent().ok_or(ScopeError::InvalidSpec)?,
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?;
        let parent_identity = identity(&parent)?;
        if !parent_identity.private_directory() || fs_magic(&parent)? == BPF_FS_MAGIC {
            return Err(ScopeError::InvalidSpec);
        }
        let lock = open_path(lock_path, libc::O_RDWR | libc::O_CREAT, 0o600)?;
        let lock_identity = identity(&lock)?;
        if !lock_identity.private_lock() || fs_magic(&lock)? == BPF_FS_MAGIC {
            return Err(ScopeError::InvalidSpec);
        }
        // SAFETY: lock owns a live descriptor. Nonblocking exclusive flock has
        // no pointers and never replaces, truncates, or unlinks the inode.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(ScopeError::from(io::Error::last_os_error()));
        }
        let held = Self {
            namespace,
            root,
            parent,
            lock,
            root_path: root_path.to_owned(),
            lock_path: lock_path.to_owned(),
            root_identity,
            parent_identity,
            lock_identity,
        };
        held.verify()?;
        Ok(held)
    }

    pub fn verify(&self) -> Result<(), ScopeError> {
        let current = current_namespace().map_err(|_| ScopeError::NamespaceChanged)?;
        if !identity(&self.namespace)?.same_object(identity(&current)?) {
            return Err(ScopeError::NamespaceChanged);
        }
        let parent = open_path(
            self.lock_path.parent().ok_or(ScopeError::LockChanged)?,
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )
        .map_err(|_| ScopeError::LockChanged)?;
        let lock =
            open_path(&self.lock_path, libc::O_RDWR, 0).map_err(|_| ScopeError::LockChanged)?;
        let current_lock = identity(&lock)?;
        if !self.parent_identity.same_object(identity(&parent)?)
            || !self.parent_identity.same_object(identity(&self.parent)?)
            || !self.lock_identity.same_object(current_lock)
            || !current_lock.private_lock()
            || identity(&self.lock)?.links != 1
        {
            return Err(ScopeError::LockChanged);
        }
        let root = open_path(&self.root_path, libc::O_RDONLY | libc::O_DIRECTORY, 0)
            .map_err(|_| ScopeError::RootChanged)?;
        if !self.root_identity.same_object(identity(&root)?)
            || !self.root_identity.same_object(identity(&self.root)?)
        {
            return Err(ScopeError::RootChanged);
        }
        Ok(())
    }
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

fn open_path(path: &Path, flags: i32, mode: u64) -> Result<File, ScopeError> {
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| ScopeError::InvalidSpec)?;
    let how = OpenHow {
        flags: (flags | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
        mode,
        resolve: 0x02 | 0x04,
    };
    // SAFETY: path is NUL terminated, how matches Linux open_how and both live
    // across this synchronous call. All path components reject symlinks.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            path.as_ptr(),
            &how as *const OpenHow,
            mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        let error = io::Error::last_os_error();
        return Err(
            if matches!(error.raw_os_error(), Some(libc::ENOSYS | libc::EOPNOTSUPP)) {
                ScopeError::Unsupported
            } else {
                ScopeError::from(error)
            },
        );
    }
    // SAFETY: openat2 returned this fresh descriptor; no other owner exists.
    Ok(unsafe { File::from_raw_fd(fd as i32) })
}

fn identity(file: &File) -> Result<Identity, ScopeError> {
    // SAFETY: zero is a valid initialized representation of Linux statx.
    let mut output: linux_raw_sys::general::statx = unsafe { mem::zeroed() };
    // SAFETY: file is held, the empty C string is valid with AT_EMPTY_PATH,
    // and output is writable for the complete Linux UAPI statx structure.
    // Use the syscall directly: musl's libc bindings do not expose statx.
    let result = unsafe {
        libc::syscall(
            libc::SYS_statx,
            file.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH | AT_STATX_DONT_SYNC,
            REQUIRED_STAT,
            &mut output as *mut linux_raw_sys::general::statx,
        )
    };
    if result != 0 {
        return Err(ScopeError::from(io::Error::last_os_error()));
    }
    if output.stx_mask & REQUIRED_STAT != REQUIRED_STAT || output.stx_mnt_id == 0 {
        return Err(ScopeError::Unsupported);
    }
    Ok(Identity {
        major: output.stx_dev_major,
        minor: output.stx_dev_minor,
        inode: output.stx_ino,
        mount: output.stx_mnt_id,
        mode: output.stx_mode,
        uid: output.stx_uid,
        links: output.stx_nlink,
    })
}

fn fs_magic(file: &File) -> Result<i64, ScopeError> {
    // SAFETY: zero initializes statfs, which is a plain C output structure.
    let mut output: libc::statfs = unsafe { mem::zeroed() };
    // SAFETY: file is held and output has the required writable extent.
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut output) } != 0 {
        return Err(ScopeError::from(io::Error::last_os_error()));
    }
    Ok(output.f_type as i64)
}

fn current_namespace() -> Result<File, ScopeError> {
    let namespace = File::open("/proc/thread-self/ns/net").map_err(ScopeError::from)?;
    if fs_magic(&namespace)? != NSFS_MAGIC {
        return Err(ScopeError::Unsupported);
    }
    // SAFETY: NS_GET_NSTYPE is a no-argument ioctl on this held nsfs descriptor.
    if unsafe { libc::ioctl(namespace.as_raw_fd(), NS_GET_NSTYPE) } != libc::CLONE_NEWNET {
        return Err(ScopeError::Unsupported);
    }
    Ok(namespace)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "opc-local-scope-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            let root = path.join("pins");
            std::fs::create_dir(&root).unwrap();
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
        fn open(&self) -> Result<LocalScopeHandles, ScopeError> {
            LocalScopeHandles::open_checked(
                &self.0.join("pins"),
                &self.0.join("lock"),
                fs_magic(&File::open(&self.0).unwrap()).unwrap(),
            )
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn busy_lock_never_steals_or_unlinks_the_inode() {
        let fixture = Fixture::new();
        let first = fixture.open().unwrap();
        assert!(matches!(fixture.open(), Err(ScopeError::Busy)));
        first.verify().unwrap();
        drop(first);
        fixture.open().unwrap().verify().unwrap();
        assert!(fixture.0.join("lock").is_file());
    }

    #[test]
    fn descriptor_identity_matches_metadata_and_keeps_mount_identity() {
        use std::os::unix::fs::MetadataExt;
        let fixture = Fixture::new();
        let handles = fixture.open().unwrap();
        let metadata = handles.lock.metadata().unwrap();
        let observed = identity(&handles.lock).unwrap();
        assert_eq!(observed.inode, metadata.ino());
        assert_eq!(observed.uid, metadata.uid());
        assert_eq!(u32::from(observed.mode), metadata.mode());
        assert_eq!(u64::from(observed.links), metadata.nlink());
        assert_eq!(observed.major, libc::major(metadata.dev()));
        assert_eq!(observed.minor, libc::minor(metadata.dev()));
        assert_ne!(observed.mount, 0);
        assert_eq!(observed.mount, identity(&handles.parent).unwrap().mount);
        assert_eq!(observed, handles.lock_identity);
    }
    #[test]
    fn rebuild_directory_is_private_descriptor_bound_and_rejects_replacement() {
        let fixture = Fixture::new();
        let handles = std::sync::Arc::new(fixture.open().unwrap());
        let directory = LocalPinDirectory::create(handles, Path::new("gtpu/lo")).unwrap();
        assert!(directory.entries().unwrap().is_empty());
        for relative in ["gtpu", "gtpu/lo"] {
            assert_eq!(
                std::fs::metadata(fixture.0.join("pins").join(relative))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
        std::fs::write(directory.descriptor_path().unwrap().join("held"), b"bound").unwrap();
        assert_eq!(directory.entries().unwrap(), vec!["held"]);
        std::fs::rename(fixture.0.join("pins/gtpu"), fixture.0.join("pins/retained")).unwrap();
        std::fs::create_dir(fixture.0.join("pins/gtpu")).unwrap();
        std::fs::set_permissions(
            fixture.0.join("pins/gtpu"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::create_dir(fixture.0.join("pins/gtpu/lo")).unwrap();
        std::fs::set_permissions(
            fixture.0.join("pins/gtpu/lo"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        assert!(directory.verify().is_err());
        assert!(directory.descriptor_path().is_err());
        assert_eq!(
            std::fs::read(fixture.0.join("pins/retained/lo/held")).unwrap(),
            b"bound"
        );
    }
    #[test]
    fn rebuild_directory_never_repairs_shared_or_symlink_ancestors() {
        let fixture = Fixture::new();
        let handles = std::sync::Arc::new(fixture.open().unwrap());
        std::fs::create_dir(fixture.0.join("pins/shared")).unwrap();
        std::fs::set_permissions(
            fixture.0.join("pins/shared"),
            std::fs::Permissions::from_mode(0o750),
        )
        .unwrap();
        symlink(fixture.0.join("pins/shared"), fixture.0.join("pins/alias")).unwrap();
        for relative in [
            "../outside",
            "shared/leaf",
            "alias/leaf",
            "/absolute",
            "a/./b",
        ] {
            assert!(LocalPinDirectory::create(handles.clone(), Path::new(relative)).is_err());
        }
        assert!(!fixture.0.join("pins/shared/leaf").exists());
        assert_eq!(
            std::fs::metadata(fixture.0.join("pins/shared"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o750
        );
    }

    #[test]
    fn private_bpffs_sticky_bit_does_not_grant_group_or_other_access() {
        let fixture = Fixture::new();
        std::fs::set_permissions(
            fixture.0.join("pins"),
            std::fs::Permissions::from_mode(0o1700),
        )
        .unwrap();
        fixture.open().unwrap().verify().unwrap();
        std::fs::set_permissions(
            fixture.0.join("pins"),
            std::fs::Permissions::from_mode(0o1750),
        )
        .unwrap();
        assert!(fixture.open().is_err());
    }

    #[test]
    fn replaced_lock_and_root_cannot_revalidate_old_scope() {
        for replace_root in [false, true] {
            let fixture = Fixture::new();
            let held = fixture.open().unwrap();
            let name = if replace_root { "pins" } else { "lock" };
            std::fs::rename(fixture.0.join(name), fixture.0.join("old")).unwrap();
            if replace_root {
                std::fs::create_dir(fixture.0.join(name)).unwrap();
            } else {
                File::create(fixture.0.join(name)).unwrap();
            }
            assert_eq!(
                held.verify(),
                Err(if replace_root {
                    ScopeError::RootChanged
                } else {
                    ScopeError::LockChanged
                })
            );
        }
    }

    #[test]
    fn symlinked_lock_and_root_are_refused_before_locking() {
        for root in [false, true] {
            let fixture = Fixture::new();
            if root {
                std::fs::rename(fixture.0.join("pins"), fixture.0.join("old")).unwrap();
                symlink(fixture.0.join("old"), fixture.0.join("pins")).unwrap();
            } else {
                File::create(fixture.0.join("old")).unwrap();
                symlink(fixture.0.join("old"), fixture.0.join("lock")).unwrap();
            }
            assert!(fixture.open().is_err());
        }
    }
}
