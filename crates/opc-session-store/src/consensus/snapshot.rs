//! File-backed snapshot transport owned by the session consensus adapter.
//!
//! Keeping the path beside the Tokio file handle lets the SQLite state
//! machine atomically promote a fully received snapshot without buffering it
//! in process memory. Diagnostics deliberately do not expose the path.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::io::{Read as _, Seek as _};
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

#[cfg(target_os = "linux")]
use rustix::fs::{renameat_with, RenameFlags};
use sha2::Digest as _;
#[cfg(target_os = "linux")]
use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd, RawFd};
#[cfg(target_os = "linux")]
use std::os::linux::fs::MetadataExt as _;
use tokio::io::{AsyncRead, AsyncSeek, AsyncSeekExt as _, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::fenced_mutation_roster::PROTECTED_ROSTER_LOGICAL_BUDGET_BYTES;

#[cfg(target_os = "linux")]
pub(crate) type RetainedSnapshotDatabaseFlock = Arc<nix::fcntl::Flock<std::fs::File>>;

#[cfg(target_os = "linux")]
pub(crate) type RetainedSnapshotNamespaceSocket = Arc<OwnedFd>;

#[cfg(target_os = "linux")]
type RetainedSnapshotRecoveryFence = (
    RetainedSnapshotDatabaseFlock,
    RetainedSnapshotNamespaceSocket,
);

/// A capability for one admitted snapshot directory.
///
/// Snapshot namespace operations must use this descriptor, not the configured
/// pathname. The canonical spelling is retained only as a stable logical
/// identity for diagnostics and terminal handoff matching; the immutable
/// configured absolute spelling is separately retained as the
/// cleanup-failure latch key. In
/// particular, a rename of the configured directory after admission cannot
/// redirect an `openat`, `renameat2`, `unlinkat`, scan, or directory fsync
/// issued through this object.
///
/// Admission requires an effective-UID-owned directory with no group/world
/// write bits (`mode & 0o022 == 0`); SDK-created leaves are `0700`, while an
/// existing `0755` directory is also admitted.  This is a dedicated
/// SDK-only namespace: cooperating SDK instances under that effective UID
/// serialize through the namespace lease.  Root/capability holders and
/// noncooperating same-UID processes (including one holding a writable alias)
/// are outside this integrity model. Unix offers no unlink-by-descriptor
/// primitive, so a dirfd alone cannot close a malicious child replacement by
/// an excluded actor between an identity check and `unlinkat`.
#[derive(Debug)]
pub(crate) struct RetainedSnapshotDirectory {
    logical_directory: PathBuf,
    cleanup_latch_identity: PathBuf,
    #[cfg(target_os = "linux")]
    // This is captured from the same descriptor that owns `directory`; it is
    // never sampled again through a pathname.  A queued cleanup failure can
    // safely share this authority with a subsequent recovery attempt only
    // when the newly admitted descriptor names this exact directory inode.
    directory_identity: (u64, u64),
    #[cfg(target_os = "linux")]
    // A retained directory flock must not make the namespace permanently
    // unrecoverable after a failed cleanup, but it also must not become a
    // general reentrant lock.  Bind the one durable SQLite main-file identity
    // that is allowed to reuse this queued authority during recovery.
    trusted_database_identity: std::sync::Mutex<Option<(u64, u64)>>,
    #[cfg(target_os = "linux")]
    // This is the actual cross-process fence for the durable SQLite owner.
    // It shares one open-file-description lock with the lease, and remains
    // live while a queued D1 cleanup authority exists.  A same-key D1->D2
    // recovery may borrow this exact Arc; any other process still sees the
    // kernel flock rather than a process-local cleanup registry.
    trusted_database_lock: std::sync::Mutex<Option<RetainedSnapshotDatabaseFlock>>,
    #[cfg(target_os = "linux")]
    // The abstract configured-key socket is the second half of the lease
    // fence. Retaining it with D1 blocks a fresh process from changing only
    // the configured namespace while D1 cleanup remains outstanding.
    trusted_namespace_socket: std::sync::Mutex<Option<RetainedSnapshotNamespaceSocket>>,
    #[cfg(unix)]
    // `Flock` is deliberately owned by the retained namespace capability.
    // A queued cleanup failure retains this `Arc`, so a cooperative opener of
    // a detached D1 cannot obtain its directory lease while validation is
    // still responsible for D1's exact cleanup and durability boundary.
    directory: Arc<nix::fcntl::Flock<std::fs::File>>,
}

/// Rename a child within one retained directory without replacing an existing
/// destination. Linux's `renameat2` is required because `renameat` cannot
/// preserve the no-replace invariant against a concurrent creator.
#[cfg(target_os = "linux")]
pub(crate) fn rename_noreplace_in_directory(
    directory: &std::fs::File,
    from: &OsStr,
    to: &OsStr,
) -> io::Result<()> {
    rename_in_directory(directory, from, to, RenameFlags::NOREPLACE)
}

/// Exchange two children within one retained directory.
#[cfg(target_os = "linux")]
pub(crate) fn rename_exchange_in_directory(
    directory: &std::fs::File,
    from: &OsStr,
    to: &OsStr,
) -> io::Result<()> {
    rename_in_directory(directory, from, to, RenameFlags::EXCHANGE)
}

#[cfg(target_os = "linux")]
fn rename_in_directory(
    directory: &std::fs::File,
    from: &OsStr,
    to: &OsStr,
    flags: RenameFlags,
) -> io::Result<()> {
    renameat_with(directory, from, directory, to, flags).map_err(io::Error::from)
}

#[cfg(test)]
#[derive(Default)]
struct RetainedNamespaceSyncTestHooks {
    fail: bool,
    #[cfg(target_os = "linux")]
    observer: Option<RetainedNamespaceSyncObserver>,
}

#[cfg(all(test, target_os = "linux"))]
struct RetainedNamespaceSyncObserver {
    observed: Vec<(u64, u64)>,
}

#[cfg(test)]
fn retained_namespace_sync_test_hooks(
) -> &'static std::sync::Mutex<BTreeMap<PathBuf, RetainedNamespaceSyncTestHooks>> {
    static HOOKS: std::sync::OnceLock<
        std::sync::Mutex<BTreeMap<PathBuf, RetainedNamespaceSyncTestHooks>>,
    > = std::sync::OnceLock::new();
    HOOKS.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()))
}

/// Fail one retained-dirfd fsync after any namespace mutation. This is scoped
/// to tests so cleanup-latch admission can prove that an empty directory does
/// not erase evidence of an earlier unflushed unlink.
#[cfg(test)]
pub(crate) fn fail_retained_namespace_sync_for_test(namespace: &RetainedSnapshotDirectory) {
    retained_namespace_sync_test_hooks()
        .lock()
        .expect("retained namespace sync hooks")
        .entry(namespace.cleanup_latch_identity().to_path_buf())
        .or_default()
        .fail = true;
}

/// Clear the test-only exact-directory fsync trace.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn clear_retained_namespace_sync_observer_for_test(
    namespace: &RetainedSnapshotDirectory,
) {
    retained_namespace_sync_test_hooks()
        .lock()
        .expect("retained namespace sync hooks")
        .entry(namespace.cleanup_latch_identity().to_path_buf())
        .or_default()
        .observer = Some(RetainedNamespaceSyncObserver {
        observed: Vec::new(),
    });
}

/// Return `(st_dev, st_ino)` for every retained directory fsync issued after
/// the last clear. This proves cleanup recovery syncs the exact detached D1,
/// not a replacement D2 at the same logical configured path.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn retained_namespace_sync_observer_for_test(
    cleanup_latch_identity: &Path,
) -> Vec<(u64, u64)> {
    retained_namespace_sync_test_hooks()
        .lock()
        .expect("retained namespace sync hooks")
        .get(cleanup_latch_identity)
        .and_then(|hooks| hooks.observer.as_ref())
        .map_or_else(Vec::new, |observer| observer.observed.clone())
}

impl RetainedSnapshotDirectory {
    /// Bind a verified directory descriptor to its stable logical spelling.
    #[cfg(unix)]
    pub(crate) fn from_directory_file(
        logical_directory: PathBuf,
        cleanup_latch_identity: PathBuf,
        directory: std::fs::File,
    ) -> io::Result<Self> {
        let metadata = directory.metadata()?;
        if !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snapshot namespace descriptor is not a directory",
            ));
        }
        #[cfg(target_os = "linux")]
        let directory_identity = (metadata.st_dev(), metadata.st_ino());
        let directory =
            nix::fcntl::Flock::lock(directory, nix::fcntl::FlockArg::LockExclusiveNonblock)
                .map_err(|(_, error)| io::Error::from(error))?;
        Ok(Self {
            logical_directory,
            cleanup_latch_identity,
            #[cfg(target_os = "linux")]
            directory_identity,
            #[cfg(target_os = "linux")]
            trusted_database_identity: std::sync::Mutex::new(None),
            #[cfg(target_os = "linux")]
            trusted_database_lock: std::sync::Mutex::new(None),
            #[cfg(target_os = "linux")]
            trusted_namespace_socket: std::sync::Mutex::new(None),
            directory: Arc::new(directory),
        })
    }

    #[cfg(not(unix))]
    pub(crate) fn from_directory_file(
        _logical_directory: PathBuf,
        _cleanup_latch_identity: PathBuf,
        _directory: std::fs::File,
    ) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "snapshot namespace descriptor requires Unix",
        ))
    }

    /// Return the sole accepted representation of a child name.
    pub(crate) fn basename<'a>(&self, name: &'a OsStr) -> io::Result<&'a OsStr> {
        let mut components = Path::new(name).components();
        match (components.next(), components.next()) {
            (Some(Component::Normal(component)), None) if component == name => Ok(name),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snapshot namespace child must be one basename",
            )),
        }
    }

    /// A stable logical child spelling; never use this for namespace I/O.
    pub(crate) fn logical_child(&self, name: &OsStr) -> io::Result<PathBuf> {
        Ok(self.logical_directory.join(self.basename(name)?))
    }

    /// Immutable normalized configured spelling used solely to find pending
    /// cleanup failures across a parent-symlink retarget. Unlike the logical
    /// canonical path, this remains identical when `/x/link` moves from D1's
    /// parent to D2's parent between process incarnations.
    pub(crate) fn cleanup_latch_identity(&self) -> &Path {
        &self.cleanup_latch_identity
    }

    /// Return the directory identity captured from the retained descriptor.
    /// This is only used to make a queued cleanup authority reentrant for its
    /// exact original namespace, never as a pathname replacement check.
    #[cfg(target_os = "linux")]
    pub(crate) fn directory_identity(&self) -> (u64, u64) {
        self.directory_identity
    }

    /// Bind the sole durable SQLite backend that may reenter a queued cleanup
    /// authority for this directory. A different backend must still contend
    /// on the retained directory flock rather than borrowing it.
    #[cfg(target_os = "linux")]
    pub(crate) fn bind_trusted_database_identity(&self, identity: (u64, u64)) -> io::Result<()> {
        let mut trusted = self
            .trusted_database_identity
            .lock()
            .map_err(|_| io::Error::other("snapshot namespace owner lock poisoned"))?;
        match *trusted {
            Some(existing) if existing != identity => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "snapshot namespace cleanup authority belongs to another database",
            )),
            Some(_) => Ok(()),
            None => {
                *trusted = Some(identity);
                Ok(())
            }
        }
    }

    /// Attach the kernel-owned database flock to this namespace capability.
    /// The lease and queued cleanup generation share this one `Arc`, so the
    /// database remains fenced across processes until the exact cleanup is
    /// acknowledged.
    #[cfg(target_os = "linux")]
    pub(crate) fn install_trusted_database_lock(
        &self,
        identity: (u64, u64),
        lock: RetainedSnapshotDatabaseFlock,
    ) -> io::Result<()> {
        self.bind_trusted_database_identity(identity)?;
        let mut trusted_lock = self
            .trusted_database_lock
            .lock()
            .map_err(|_| io::Error::other("snapshot namespace database lock poisoned"))?;
        match trusted_lock.as_ref() {
            Some(existing) if Arc::ptr_eq(existing, &lock) => Ok(()),
            Some(_) => Err(io::Error::other(
                "snapshot namespace already has another database flock",
            )),
            None => {
                *trusted_lock = Some(lock);
                Ok(())
            }
        }
    }

    /// Attach the immutable configured-key socket to the retained capability.
    /// Same-process recovery shares this Arc; a fresh process can only
    /// observe the already-bound kernel socket.
    #[cfg(target_os = "linux")]
    pub(crate) fn install_trusted_namespace_socket(
        &self,
        socket: RetainedSnapshotNamespaceSocket,
    ) -> io::Result<()> {
        let mut trusted_socket = self
            .trusted_namespace_socket
            .lock()
            .map_err(|_| io::Error::other("snapshot namespace socket lock poisoned"))?;
        match trusted_socket.as_ref() {
            Some(existing) if Arc::ptr_eq(existing, &socket) => Ok(()),
            Some(_) => Err(io::Error::other(
                "snapshot namespace already has another configured-key socket",
            )),
            None => {
                *trusted_socket = Some(socket);
                Ok(())
            }
        }
    }

    /// Clone the pre-existing database fence only when it belongs to the
    /// durable owner whose descriptor was just admitted. This is deliberately
    /// an in-process sharing operation; other processes cannot obtain this
    /// Arc and continue to contend on the kernel flock.
    #[cfg(target_os = "linux")]
    pub(crate) fn trusted_database_lock_for_identity(
        &self,
        identity: (u64, u64),
    ) -> io::Result<Option<RetainedSnapshotDatabaseFlock>> {
        if !self.has_trusted_database_identity(identity)? {
            return Ok(None);
        }
        self.trusted_database_lock
            .lock()
            .map_err(|_| io::Error::other("snapshot namespace database lock poisoned"))
            .map(|trusted_lock| trusted_lock.clone())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn trusted_namespace_socket_for_identity(
        &self,
        identity: (u64, u64),
    ) -> io::Result<Option<RetainedSnapshotNamespaceSocket>> {
        if !self.has_trusted_database_identity(identity)? {
            return Ok(None);
        }
        self.trusted_namespace_socket
            .lock()
            .map_err(|_| io::Error::other("snapshot namespace socket lock poisoned"))
            .map(|trusted_socket| trusted_socket.clone())
    }

    #[cfg(target_os = "linux")]
    fn trusted_recovery_fence_for_identity(
        &self,
        identity: (u64, u64),
    ) -> io::Result<Option<RetainedSnapshotRecoveryFence>> {
        let Some(database_lock) = self.trusted_database_lock_for_identity(identity)? else {
            return Ok(None);
        };
        let socket = self
            .trusted_namespace_socket_for_identity(identity)?
            .ok_or_else(|| io::Error::other("queued snapshot cleanup authority lost its socket"))?;
        Ok(Some((database_lock, socket)))
    }

    #[cfg(target_os = "linux")]
    fn matches_trusted_recovery_owner(
        &self,
        directory_identity: (u64, u64),
        database_identity: (u64, u64),
    ) -> io::Result<bool> {
        Ok(self.directory_identity() == directory_identity
            && self.has_trusted_database_identity(database_identity)?)
    }

    #[cfg(target_os = "linux")]
    fn has_trusted_database_identity(&self, database_identity: (u64, u64)) -> io::Result<bool> {
        let trusted = self
            .trusted_database_identity
            .lock()
            .map_err(|_| io::Error::other("snapshot namespace owner lock poisoned"))?;
        Ok(*trusted == Some(database_identity))
    }

    /// A verified descriptor-anchored spelling for pathname-only SQLite APIs.
    ///
    /// No durable value may retain this spelling: it includes a process-local
    /// fd number. General namespace I/O should use the fd-relative methods
    /// below instead.
    #[cfg(unix)]
    pub(crate) fn sqlite_child_path(&self, name: &OsStr) -> io::Result<PathBuf> {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::MetadataExt as _;

        let name = self.basename(name)?;
        let proc_directory =
            PathBuf::from("/proc/self/fd").join((**self.directory).as_raw_fd().to_string());
        let held = (**self.directory).metadata()?;
        let resolved = std::fs::metadata(&proc_directory)?;
        if !resolved.is_dir() || held.dev() != resolved.dev() || held.ino() != resolved.ino() {
            return Err(io::Error::other(
                "snapshot namespace proc descriptor does not resolve to retained directory",
            ));
        }
        Ok(proc_directory.join(name))
    }

    #[cfg(not(unix))]
    pub(crate) fn sqlite_child_path(&self, _name: &OsStr) -> io::Result<PathBuf> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "snapshot namespace descriptor requires Unix",
        ))
    }

    fn open_child_with(
        &self,
        name: &OsStr,
        flags: nix::fcntl::OFlag,
        mode: nix::sys::stat::Mode,
    ) -> io::Result<std::fs::File> {
        use nix::fcntl::openat;

        let name = self.basename(name)?;
        // `basename` accepts exactly one normal component. With no slash,
        // dot, dot-dot, or magic-link component available, openat relative
        // to the retained dirfd is already RESOLVE_BENEATH-equivalent while
        // retaining compatibility with pre-openat2 Linux kernels.
        openat(
            &**self.directory,
            Path::new(name),
            flags
                | nix::fcntl::OFlag::O_NOFOLLOW
                | nix::fcntl::OFlag::O_CLOEXEC
                | nix::fcntl::OFlag::O_NONBLOCK,
            mode,
        )
        .map(std::fs::File::from)
        .map_err(io::Error::from)
    }

    /// Open an existing regular candidate without following a link or waiting
    /// on a hostile special-file replacement.
    pub(crate) fn open_read(&self, name: &OsStr) -> io::Result<std::fs::File> {
        self.open_child_with(
            name,
            nix::fcntl::OFlag::O_RDONLY,
            nix::sys::stat::Mode::empty(),
        )
    }

    /// Create a brand-new private regular child through the retained dirfd.
    pub(crate) fn create_new(&self, name: &OsStr, _read: bool) -> io::Result<std::fs::File> {
        self.open_child_with(
            name,
            nix::fcntl::OFlag::O_CREAT | nix::fcntl::OFlag::O_EXCL | nix::fcntl::OFlag::O_RDWR,
            nix::sys::stat::Mode::from_bits_truncate(0o600),
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn rename_noreplace(&self, from: &OsStr, to: &OsStr) -> io::Result<()> {
        let from = self.basename(from)?;
        let to = self.basename(to)?;
        rename_noreplace_in_directory(&self.directory, from, to)
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    pub(crate) fn rename_noreplace(&self, _from: &OsStr, _to: &OsStr) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "identity-bound snapshot rename requires Linux renameat2",
        ))
    }

    #[cfg(unix)]
    pub(crate) fn unlink(&self, name: &OsStr) -> io::Result<()> {
        let name = self.basename(name)?;
        nix::unistd::unlinkat(
            &**self.directory,
            name,
            nix::unistd::UnlinkatFlags::NoRemoveDir,
        )
        .map_err(io::Error::from)
    }

    #[cfg(unix)]
    pub(crate) fn sync(&self) -> io::Result<()> {
        #[cfg(all(test, target_os = "linux"))]
        {
            use std::os::unix::fs::MetadataExt as _;

            let metadata = (**self.directory).metadata()?;
            let identity = (metadata.dev(), metadata.ino());
            let mut hooks = retained_namespace_sync_test_hooks()
                .lock()
                .expect("retained namespace sync hooks");
            let Some(hooks) = hooks.get_mut(self.cleanup_latch_identity()) else {
                return (**self.directory).sync_all();
            };
            if let Some(observer) = &mut hooks.observer {
                observer.observed.push(identity);
            }
            if std::mem::take(&mut hooks.fail) {
                return Err(io::Error::other(
                    "injected retained snapshot namespace sync failure",
                ));
            }
        }
        #[cfg(all(test, not(target_os = "linux")))]
        {
            let mut hooks = retained_namespace_sync_test_hooks()
                .lock()
                .expect("retained namespace sync hooks");
            if hooks
                .get_mut(self.cleanup_latch_identity())
                .is_some_and(|hooks| std::mem::take(&mut hooks.fail))
            {
                return Err(io::Error::other(
                    "injected retained snapshot namespace sync failure",
                ));
            }
        }
        (**self.directory).sync_all()
    }

    /// Enumerate at most `limit + 1` child basenames through a duplicate of
    /// the retained fd.  The extra entry lets callers reject over-capacity
    /// namespaces without allowing an untrusted pre-existing directory to
    /// force an unbounded allocation or scan.
    #[cfg(unix)]
    pub(crate) fn entries(&self, limit: usize) -> io::Result<Vec<OsString>> {
        use std::os::unix::ffi::OsStringExt as _;

        let duplicate = (**self.directory).try_clone()?;
        let directory = rustix::fs::Dir::read_from(duplicate).map_err(io::Error::from)?;
        let mut entries = Vec::with_capacity(limit.saturating_add(1));
        for entry in directory {
            let entry = entry.map_err(io::Error::from)?;
            let name = OsString::from_vec(entry.file_name().to_bytes().to_vec());
            if name == "." || name == ".." {
                continue;
            }
            entries.push(name);
            if entries.len() > limit {
                break;
            }
        }
        Ok(entries)
    }
}

/// SQLite backup reports page counts as a signed 32-bit integer, while SQLite
/// accepts a 512-byte page.  This is the one physical database payload ceiling
/// enforced by every SDK writer through `max_page_count`, and independently
/// checked by snapshot, transport, and recovery readers.  It bounds the whole
/// SQLite image--roster blobs, authoritative session rows, schema, indexes,
/// freelist, WAL-derived backup, and arbitrary non-roster rows--rather than
/// treating the roster's logical charge budget as a file-size quota.  The
/// final 512 bytes make the minimum-page representation fit the backup API's
/// `i32::MAX` page-count limit exactly.
const SNAPSHOT_MIN_PAGE_BYTES: u64 = 512;
const SNAPSHOT_MAX_BACKUP_PAGES: u64 = i32::MAX as u64;
pub(crate) const SNAPSHOT_DATABASE_MAX_BYTES: u64 =
    SNAPSHOT_MAX_BACKUP_PAGES * SNAPSHOT_MIN_PAGE_BYTES;
/// Maximum payload bytes admitted in one consensus snapshot envelope.
pub(crate) const SNAPSHOT_MAX_BYTES: u64 = SNAPSHOT_DATABASE_MAX_BYTES;
/// Fixed authenticated footer appended after an otherwise complete SQLite
/// payload.  The envelope has its own bound because it is a different file
/// from the database image.
pub(crate) const SNAPSHOT_ENVELOPE_FOOTER_BYTES: u64 = 8 + 8 + 32;
/// Maximum complete snapshot file accepted by transport and offline recovery.
pub(crate) const SNAPSHOT_ENVELOPE_MAX_BYTES: u64 =
    SNAPSHOT_DATABASE_MAX_BYTES + SNAPSHOT_ENVELOPE_FOOTER_BYTES;
const _: () =
    assert!(SNAPSHOT_DATABASE_MAX_BYTES == SNAPSHOT_MAX_BACKUP_PAGES * SNAPSHOT_MIN_PAGE_BYTES);
const _: () = assert!(
    SNAPSHOT_DATABASE_MAX_BYTES
        == PROTECTED_ROSTER_LOGICAL_BUDGET_BYTES * 4 - SNAPSHOT_MIN_PAGE_BYTES
);
/// Maximum bytes retained while checking an idempotent receiver replay.
const SNAPSHOT_REPLAY_VERIFY_BYTES: usize = 64 * 1024;

/// Test-only coordination around a snapshot artifact lifecycle boundary.
#[cfg(test)]
pub(crate) struct SnapshotArtifactGate {
    armed: AtomicBool,
    started: AtomicBool,
    started_notify: tokio::sync::Notify,
    released: AtomicBool,
    released_notify: tokio::sync::Notify,
    blocking_release_lock: std::sync::Mutex<()>,
    blocking_release: std::sync::Condvar,
}

#[cfg(test)]
impl SnapshotArtifactGate {
    pub(crate) fn new() -> Self {
        Self {
            armed: AtomicBool::new(false),
            started: AtomicBool::new(false),
            started_notify: tokio::sync::Notify::new(),
            released: AtomicBool::new(false),
            released_notify: tokio::sync::Notify::new(),
            blocking_release_lock: std::sync::Mutex::new(()),
            blocking_release: std::sync::Condvar::new(),
        }
    }

    pub(crate) fn arm(&self) {
        let _release = self
            .blocking_release_lock
            .lock()
            .expect("arm snapshot artifact gate");
        self.started.store(false, Ordering::Release);
        self.released.store(false, Ordering::Release);
        self.armed.store(true, Ordering::Release);
    }

    pub(crate) async fn wait_started(&self) {
        while !self.started.load(Ordering::Acquire) {
            let notified = self.started_notify.notified();
            if self.started.load(Ordering::Acquire) {
                break;
            }
            notified.await;
        }
    }

    pub(crate) fn release(&self) {
        let _release = self
            .blocking_release_lock
            .lock()
            .expect("release snapshot artifact gate");
        self.released.store(true, Ordering::Release);
        self.blocking_release.notify_all();
        self.released_notify.notify_waiters();
    }

    pub(crate) async fn block_if_armed(&self) {
        if !self.armed.load(Ordering::Acquire) {
            return;
        }
        self.started.store(true, Ordering::Release);
        self.started_notify.notify_waiters();
        while !self.released.load(Ordering::Acquire) {
            let notified = self.released_notify.notified();
            if self.released.load(Ordering::Acquire) {
                break;
            }
            notified.await;
        }
        self.armed.store(false, Ordering::Release);
    }

    /// Hold a synchronous descriptor-scan boundary. This is test-only so
    /// production retains no gate or registry.
    pub(crate) fn block_if_armed_blocking(&self) {
        if !self.armed.load(Ordering::Acquire) {
            return;
        }
        self.started.store(true, Ordering::Release);
        self.started_notify.notify_waiters();
        let mut release = self
            .blocking_release_lock
            .lock()
            .expect("wait for snapshot artifact gate release");
        while !self.released.load(Ordering::Acquire) {
            release = self
                .blocking_release
                .wait(release)
                .expect("wait for snapshot artifact gate release");
        }
        self.armed.store(false, Ordering::Release);
    }
}

/// Immutable identity taken from an already-open SQLite file descriptor.
///
/// On Linux this is deliberately based on the descriptor rather than its
/// pathname, which makes it stable when a snapshot name is atomically
/// replaced. Other platforms retain this internal handle shape for cfg
/// completeness, but public dynamic and fixed consensus initialization both
/// fail closed before snapshot state is created.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FileIdentity;

/// A regular SQLite file pinned to an existing OS handle.
///
/// `path` is diagnostic and cleanup information only. It must never be used
/// as authorization that an operation still targets this handle.
#[allow(dead_code)]
pub(crate) struct PinnedSqliteFile {
    file: std::fs::File,
    /// Descriptor namespace/name used for every post-admission identity
    /// re-open. `path` remains a SQLite-only spelling where an API cannot
    /// accept an fd.
    namespace: Option<(Arc<RetainedSnapshotDirectory>, OsString)>,
    path: PathBuf,
    identity: FileIdentity,
    immutable_generation: Option<ImmutableFileGeneration>,
    cleanup: Option<UnpublishedSnapshotArtifact>,
}

/// Kernel-enforced content, length, and Linux inode-generation authority
/// bound to a fixed snapshot artifact. This is kept separate from the live
/// SQLite descriptor identity: SQLite legitimately changes a live database
/// through another descriptor while a published or install artifact must
/// never change after it is verified.
///
/// This is deliberately not a userspace hash claim: `digest` is the
/// fixed-profile fs-verity measurement of the read-only descriptor.  A live
/// SQLite descriptor must never carry this state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ImmutableFileGeneration {
    length: u64,
    digest: [u8; 32],
    /// Linux `ctime` is owned by the kernel and changes when the inode is
    /// modified. It closes the post-scan/pre-publication window without a
    /// second content scan.
    #[cfg(target_os = "linux")]
    change_time: LinuxFileChangeTime,
}

/// Kernel-owned inode change time used as a constant-time generation fence.
///
/// This is intentionally separate from [`FileIdentity`]: device/inode proves
/// that a handle still names the same object, while `ctime` detects a
/// same-inode, same-length write through another descriptor.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LinuxFileChangeTime {
    seconds: i64,
    nanoseconds: i64,
}

/// The result of binding an immutable generation while validating a sealed
/// snapshot envelope through one descriptor-owned sequential read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ImmutableSnapshotEnvelope {
    pub(crate) payload_length: u64,
    pub(crate) total_length: u64,
}

#[cfg(test)]
#[derive(Default)]
struct FixedPrepublicationScanObservation {
    active_boundaries: usize,
    count: u64,
    bytes: u64,
}

/// Test-only, directory-scoped observation of fixed prepublication scans.
///
/// The registry is deliberately held only by an RAII test owner. A scan is
/// recorded only while the builder enters its precise post-seal/pre-metadata
/// boundary, so later postpublication verification and unrelated directories
/// cannot affect the observation.
#[cfg(test)]
pub(crate) struct FixedPrepublicationScanObserver {
    snapshot_directory: PathBuf,
    observation: Arc<std::sync::Mutex<FixedPrepublicationScanObservation>>,
}

#[cfg(test)]
impl FixedPrepublicationScanObserver {
    pub(crate) fn install(snapshot_directory: PathBuf) -> Self {
        let observation = Arc::new(std::sync::Mutex::new(
            FixedPrepublicationScanObservation::default(),
        ));
        fixed_prepublication_scan_observers()
            .lock()
            .expect("install fixed prepublication scan observer")
            .insert(snapshot_directory.clone(), Arc::clone(&observation));
        Self {
            snapshot_directory,
            observation,
        }
    }

    pub(crate) fn snapshot(&self) -> (u64, u64) {
        let observation = self
            .observation
            .lock()
            .expect("read fixed prepublication scan observer");
        (observation.count, observation.bytes)
    }
}

#[cfg(test)]
impl Drop for FixedPrepublicationScanObserver {
    fn drop(&mut self) {
        let mut observers = fixed_prepublication_scan_observers()
            .lock()
            .expect("remove fixed prepublication scan observer");
        if observers
            .get(&self.snapshot_directory)
            .is_some_and(|installed| Arc::ptr_eq(installed, &self.observation))
        {
            observers.remove(&self.snapshot_directory);
        }
    }
}

#[cfg(test)]
pub(crate) struct FixedPrepublicationScanBoundary {
    observation: Arc<std::sync::Mutex<FixedPrepublicationScanObservation>>,
}

#[cfg(test)]
impl Drop for FixedPrepublicationScanBoundary {
    fn drop(&mut self) {
        let mut observation = self
            .observation
            .lock()
            .expect("leave fixed prepublication scan boundary");
        observation.active_boundaries = observation.active_boundaries.saturating_sub(1);
    }
}

#[cfg(test)]
fn fixed_prepublication_scan_observers() -> &'static std::sync::Mutex<
    BTreeMap<PathBuf, Arc<std::sync::Mutex<FixedPrepublicationScanObservation>>>,
> {
    static OBSERVERS: std::sync::OnceLock<
        std::sync::Mutex<
            BTreeMap<PathBuf, Arc<std::sync::Mutex<FixedPrepublicationScanObservation>>>,
        >,
    > = std::sync::OnceLock::new();
    OBSERVERS.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()))
}

#[cfg(test)]
pub(crate) fn fixed_prepublication_scan_boundary(
    path: &Path,
) -> Option<FixedPrepublicationScanBoundary> {
    let snapshot_directory = path.parent()?;
    let observation = fixed_prepublication_scan_observers()
        .lock()
        .ok()
        .and_then(|observers| observers.get(snapshot_directory).cloned())?;
    observation
        .lock()
        .expect("enter fixed prepublication scan boundary")
        .active_boundaries += 1;
    Some(FixedPrepublicationScanBoundary { observation })
}

#[cfg(test)]
pub(crate) fn record_fixed_prepublication_scan(path: &Path, bytes: u64) {
    let Some(snapshot_directory) = path.parent() else {
        return;
    };
    let observation = fixed_prepublication_scan_observers()
        .lock()
        .ok()
        .and_then(|observers| observers.get(snapshot_directory).cloned());
    if let Some(observation) = observation {
        let mut observation = observation
            .lock()
            .expect("record fixed prepublication scan");
        if observation.active_boundaries != 0 {
            observation.count = observation.count.saturating_add(1);
            observation.bytes = observation.bytes.saturating_add(bytes);
        }
    }
}

/// Test-only, directory-scoped gate at the exact fixed prepublication
/// descriptor-scan boundary. The RAII owner always releases an in-flight scan
/// before removing its scoped registration.
#[cfg(test)]
pub(crate) struct FixedPrepublicationScanGateGuard {
    snapshot_directory: PathBuf,
    gate: Arc<SnapshotArtifactGate>,
}

#[cfg(test)]
impl FixedPrepublicationScanGateGuard {
    pub(crate) fn install(snapshot_directory: PathBuf, gate: Arc<SnapshotArtifactGate>) -> Self {
        fixed_prepublication_scan_gates()
            .lock()
            .expect("install fixed prepublication scan gate")
            .insert(snapshot_directory.clone(), Arc::clone(&gate));
        Self {
            snapshot_directory,
            gate,
        }
    }
}

#[cfg(test)]
impl Drop for FixedPrepublicationScanGateGuard {
    fn drop(&mut self) {
        self.gate.release();
        let mut gates = fixed_prepublication_scan_gates()
            .lock()
            .expect("remove fixed prepublication scan gate");
        if gates
            .get(&self.snapshot_directory)
            .is_some_and(|installed| Arc::ptr_eq(installed, &self.gate))
        {
            gates.remove(&self.snapshot_directory);
        }
    }
}

#[cfg(test)]
fn fixed_prepublication_scan_gates(
) -> &'static std::sync::Mutex<BTreeMap<PathBuf, Arc<SnapshotArtifactGate>>> {
    static GATES: std::sync::OnceLock<
        std::sync::Mutex<BTreeMap<PathBuf, Arc<SnapshotArtifactGate>>>,
    > = std::sync::OnceLock::new();
    GATES.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()))
}

#[cfg(test)]
fn block_fixed_prepublication_scan(path: &Path) {
    let Some(snapshot_directory) = path.parent() else {
        return;
    };
    let gate = fixed_prepublication_scan_gates()
        .lock()
        .ok()
        .and_then(|gates| gates.get(snapshot_directory).cloned());
    if let Some(gate) = gate {
        gate.block_if_armed_blocking();
    }
}

/// Exact ownership of an SDK-created snapshot artifact which is not yet
/// published. Cleanup authenticates the object by its open-descriptor identity
/// before unlinking the SDK-controlled name, so a same-name replacement is
/// never removed.
pub(crate) struct UnpublishedSnapshotArtifact {
    path: PathBuf,
    cleanup: SnapshotCleanupState,
    identity: FileIdentity,
    sqlite_sidecars: bool,
    sidecars: Vec<(SnapshotCleanupState, FileIdentity)>,
    armed: bool,
}

impl UnpublishedSnapshotArtifact {
    pub(crate) fn from_file(
        file: &std::fs::File,
        path: PathBuf,
        sqlite_sidecars: bool,
    ) -> io::Result<Self> {
        Self::from_metadata(path, &file.metadata()?, sqlite_sidecars)
    }

    pub(crate) fn from_metadata(
        path: PathBuf,
        metadata: &std::fs::Metadata,
        sqlite_sidecars: bool,
    ) -> io::Result<Self> {
        Ok(Self {
            cleanup: SnapshotCleanupState::new(path.clone()),
            path,
            identity: file_identity(metadata)?,
            sqlite_sidecars,
            sidecars: Vec::new(),
            armed: true,
        })
    }

    /// Bind an SDK-created child to the retained snapshot directory. The
    /// operational path is only for pathname-only SQLite calls; Drop cleanup
    /// stays fd-relative through `cleanup`.
    pub(crate) fn from_file_in_namespace(
        file: &std::fs::File,
        namespace: Arc<RetainedSnapshotDirectory>,
        name: &OsStr,
        sqlite_sidecars: bool,
    ) -> io::Result<Self> {
        let path = namespace.logical_child(name)?;
        Ok(Self {
            cleanup: SnapshotCleanupState::in_namespace(namespace, name)?,
            path,
            identity: file_identity(&file.metadata()?)?,
            sqlite_sidecars,
            sidecars: Vec::new(),
            armed: true,
        })
    }

    /// Reconstruct an interrupted tombstone using the retained directory
    /// descriptor. Recovery keeps the durable/latch spelling logical while
    /// every retry stays in the original namespace.
    #[cfg(target_os = "linux")]
    pub(crate) fn from_existing_tombstone_in_namespace(
        namespace: Arc<RetainedSnapshotDirectory>,
        tombstone_name: &OsStr,
        original_name: &OsStr,
        metadata: &std::fs::Metadata,
        sqlite_sidecars: bool,
    ) -> io::Result<Self> {
        let tombstone = namespace.logical_child(tombstone_name)?;
        let mut cleanup =
            SnapshotCleanupState::in_namespace(Arc::clone(&namespace), original_name)?;
        cleanup.location = SnapshotCleanupLocation::Tombstone(tombstone.clone());
        Ok(Self {
            path: tombstone,
            cleanup,
            identity: file_identity(metadata)?,
            sqlite_sidecars,
            sidecars: Vec::new(),
            armed: true,
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn from_existing_tombstone_in_namespace(
        namespace: Arc<RetainedSnapshotDirectory>,
        tombstone_name: &OsStr,
        original_name: &OsStr,
        metadata: &std::fs::Metadata,
        sqlite_sidecars: bool,
    ) -> io::Result<Self> {
        let _ = (
            namespace,
            tombstone_name,
            original_name,
            metadata,
            sqlite_sidecars,
        );
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "snapshot identity-bound cleanup requires Linux",
        ))
    }

    /// Reconstruct a durable final-unlink guard after a process stopped after
    /// its guard rename but before `unlinkat`.  The guard basename carries the
    /// admitted inode identity, so a syntactically similar foreign name cannot
    /// be promoted into a deletion target during restart recovery.
    #[cfg(target_os = "linux")]
    pub(crate) fn from_existing_unlink_guard_in_namespace(
        namespace: Arc<RetainedSnapshotDirectory>,
        guard_name: &OsStr,
        tombstone_name: &OsStr,
        original_name: &OsStr,
        metadata: &std::fs::Metadata,
        sqlite_sidecars: bool,
    ) -> io::Result<Self> {
        let identity = file_identity(metadata)?;
        if !snapshot_cleanup_unlink_guard_name_authenticates(guard_name, identity) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "snapshot unlink guard identity does not match its inode",
            ));
        }
        let guard = namespace.logical_child(guard_name)?;
        let tombstone = namespace.logical_child(tombstone_name)?;
        let mut cleanup =
            SnapshotCleanupState::in_namespace(Arc::clone(&namespace), original_name)?;
        cleanup.location = SnapshotCleanupLocation::UnlinkGuard { guard, tombstone };
        Ok(Self {
            path: cleanup
                .active_path()
                .expect("unlink guard is an active cleanup location")
                .to_path_buf(),
            cleanup,
            identity,
            sqlite_sidecars,
            sidecars: Vec::new(),
            armed: true,
        })
    }

    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }

    #[cfg(test)]
    pub(crate) fn rebind_path(&mut self, path: PathBuf) {
        self.path = path.clone();
        self.cleanup.rebind(path);
    }

    pub(crate) fn rebind_in_namespace(
        &mut self,
        namespace: Arc<RetainedSnapshotDirectory>,
        name: &OsStr,
    ) -> io::Result<()> {
        self.path = namespace.logical_child(name)?;
        self.cleanup = SnapshotCleanupState::in_namespace(namespace, name)?;
        Ok(())
    }

    fn capture_sidecars(&mut self) {
        if !self.sqlite_sidecars {
            return;
        }
        self.sidecars.clear();
        for suffix in ["-journal", "-wal", "-shm"] {
            let mut sidecar = self.path.as_os_str().to_os_string();
            sidecar.push(suffix);
            let sidecar = PathBuf::from(sidecar);
            let (metadata, cleanup) = match &self.cleanup.namespace {
                Some(namespace) => {
                    let Some(name) = sidecar.file_name() else {
                        continue;
                    };
                    let Ok(file) = namespace.open_read(name) else {
                        continue;
                    };
                    let Ok(metadata) = file.metadata() else {
                        continue;
                    };
                    let Ok(cleanup) =
                        SnapshotCleanupState::in_namespace(Arc::clone(namespace), name)
                    else {
                        continue;
                    };
                    (metadata, cleanup)
                }
                None => {
                    let Ok(metadata) = std::fs::symlink_metadata(&sidecar) else {
                        continue;
                    };
                    (metadata, SnapshotCleanupState::new(sidecar.clone()))
                }
            };
            if !metadata.is_file() {
                continue;
            }
            if let Ok(identity) = file_identity(&metadata) {
                self.sidecars.push((cleanup, identity));
            }
        }
    }

    fn remove_if_owned(
        cleanup: &mut SnapshotCleanupState,
        identity: FileIdentity,
    ) -> io::Result<bool> {
        remove_snapshot_cleanup_if_owned(cleanup, identity)
    }
}

/// One failed retained-directory durability boundary. The `Arc` is the
/// authority that actually performed the unlink/rename; retaining it keeps a
/// parent-path replacement from making a later validator acknowledge D1 after
/// fsyncing an attacker/operator-provided D2 at the same logical path.
#[derive(Clone)]
pub(crate) struct RetainedSnapshotCleanupFailure {
    generation: u64,
    namespace: Arc<RetainedSnapshotDirectory>,
}

impl RetainedSnapshotCleanupFailure {
    pub(crate) fn namespace(&self) -> &Arc<RetainedSnapshotDirectory> {
        &self.namespace
    }
}

#[derive(Default)]
struct SnapshotCleanupFailureGenerations {
    next_generation: u64,
    pending: Vec<RetainedSnapshotCleanupFailure>,
}

fn unpublished_snapshot_cleanup_failures(
) -> &'static std::sync::Mutex<BTreeMap<PathBuf, SnapshotCleanupFailureGenerations>> {
    static FAILURES: std::sync::OnceLock<
        std::sync::Mutex<BTreeMap<PathBuf, SnapshotCleanupFailureGenerations>>,
    > = std::sync::OnceLock::new();
    FAILURES.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()))
}

/// Issue a durable-cleanup failure generation for the exact admitted
/// directory capability that performed the mutation. A validator snapshots
/// these capabilities before fsync and acknowledges only the individual
/// generation whose retained fd it actually synced.
pub(crate) fn record_unpublished_snapshot_cleanup_failure_in_namespace(
    namespace: Arc<RetainedSnapshotDirectory>,
) {
    if let Ok(mut failures) = unpublished_snapshot_cleanup_failures().lock() {
        let latch_identity = namespace.cleanup_latch_identity().to_path_buf();
        let state = failures.entry(latch_identity).or_default();
        state.next_generation = state.next_generation.saturating_add(1);
        state.pending.push(RetainedSnapshotCleanupFailure {
            generation: state.next_generation,
            namespace,
        });
    }
}

fn record_unpublished_snapshot_cleanup_failure_for_state(state: &SnapshotCleanupState) {
    // Every production snapshot artifact is namespace-bound. Legacy path-only
    // helpers are test-only compatibility paths and cannot safely establish a
    // retained-dirfd durability authority, so they intentionally do not
    // publish a global latch under a pathname that a parent replacement could
    // later redirect.
    if let Some(namespace) = &state.namespace {
        record_unpublished_snapshot_cleanup_failure_in_namespace(Arc::clone(namespace));
    }
}

/// Immediate ownership of a just-created retained-namespace child.
///
/// This deliberately has no fallible setup after `O_EXCL` has succeeded: a
/// metadata query, descriptor clone, cleanup-state construction, or worker
/// cancellation may all fail under descriptor pressure.  Until the
/// identity-pinned cleanup owner is fully installed, Drop removes this exact
/// basename through the retained directory fd and makes the cleanup latch
/// durable if either unlink or its directory fsync fails.
struct NewNamespaceChildGuard {
    namespace: Arc<RetainedSnapshotDirectory>,
    name: OsString,
    cleanup_failed: Option<Arc<AtomicBool>>,
    armed: bool,
}

impl NewNamespaceChildGuard {
    fn new(
        namespace: Arc<RetainedSnapshotDirectory>,
        name: &OsStr,
        cleanup_failed: Option<Arc<AtomicBool>>,
    ) -> Self {
        Self {
            namespace,
            name: name.to_os_string(),
            cleanup_failed,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }

    fn record_failure(&self) {
        // `create_new` already validated this single basename.  Keep the
        // generation bound to its retained D1 descriptor, never merely to a
        // logical path or process-local `/proc/self/fd` spelling. Issue it
        // before the legacy boolean hint so validation cannot observe/clear
        // the latter before it has a concrete fsync generation to
        // acknowledge.
        record_unpublished_snapshot_cleanup_failure_in_namespace(Arc::clone(&self.namespace));
        if let Some(cleanup_failed) = &self.cleanup_failed {
            cleanup_failed.store(true, Ordering::Release);
        }
    }
}

impl Drop for NewNamespaceChildGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        match self.namespace.unlink(&self.name) {
            Ok(()) => {
                if self.namespace.sync().is_err() {
                    self.record_failure();
                }
            }
            // No entry remains to consume capacity. This can only happen if
            // an excluded actor mutated the private namespace, or a later
            // owner took over after this guard was disarmed.
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => self.record_failure(),
        }
    }
}

/// Snapshot each unacknowledged cleanup failure for one immutable configured
/// latch identity. The caller must fsync every returned retained fd before
/// acknowledging it.
pub(crate) fn pending_unpublished_snapshot_cleanup_failures(
    directory: &Path,
) -> io::Result<Vec<RetainedSnapshotCleanupFailure>> {
    let failures = unpublished_snapshot_cleanup_failures()
        .lock()
        .map_err(|_| io::Error::other("snapshot cleanup failure registry poisoned"))?;
    Ok(failures
        .get(directory)
        .map_or_else(Vec::new, |state| state.pending.clone()))
}

/// The outcome of looking up a queued cleanup authority during lease
/// admission. A database with any outstanding cleanup must not silently move
/// to another configured directory: only its exact original directory can
/// reenter and drain the retained authority.
#[cfg(target_os = "linux")]
pub(crate) enum PendingSnapshotNamespaceRecoveryAuthority {
    Exact(Arc<RetainedSnapshotDirectory>),
    /// The immutable configured key still names the caller's namespace, but
    /// the directory inode was replaced after D1's cleanup failed. Admit a
    /// fresh D2 dirfd and share D1's database fence so validation can reclaim
    /// and fsync D1 without letting another process take the same database.
    ReplacementAtSameConfiguredKey {
        database_lock: RetainedSnapshotDatabaseFlock,
        namespace_socket: RetainedSnapshotNamespaceSocket,
    },
    OtherPendingDirectory,
    None,
}

/// Reuse a queued cleanup authority only for the exact directory inode and
/// durable SQLite owner that originally issued it.  This gives a restarted
/// owner a way to drain its own retained directory flock after an interrupted
/// cleanup, while a different directory incarnation or database remains
/// excluded by that flock.
#[cfg(target_os = "linux")]
pub(crate) fn pending_snapshot_namespace_recovery_authority(
    cleanup_latch_identity: &Path,
    directory_identity: (u64, u64),
    database_identity: (u64, u64),
) -> io::Result<PendingSnapshotNamespaceRecoveryAuthority> {
    let failures = unpublished_snapshot_cleanup_failures()
        .lock()
        .map_err(|_| io::Error::other("snapshot cleanup failure registry poisoned"))?;
    if let Some(state) = failures.get(cleanup_latch_identity) {
        for failure in &state.pending {
            if failure
                .namespace
                .matches_trusted_recovery_owner(directory_identity, database_identity)?
            {
                return Ok(PendingSnapshotNamespaceRecoveryAuthority::Exact(
                    Arc::clone(&failure.namespace),
                ));
            }
        }
        for failure in &state.pending {
            if failure
                .namespace
                .has_trusted_database_identity(database_identity)?
            {
                let (database_lock, namespace_socket) = failure
                    .namespace
                    .trusted_recovery_fence_for_identity(database_identity)?
                    .ok_or_else(|| {
                        io::Error::other("queued snapshot cleanup authority lost its lease fence")
                    })?;
                return Ok(
                    PendingSnapshotNamespaceRecoveryAuthority::ReplacementAtSameConfiguredKey {
                        database_lock,
                        namespace_socket,
                    },
                );
            }
        }
        if !state.pending.is_empty() {
            // Another durable owner has unacknowledged cleanup for this
            // immutable configured key. Do not make a fresh namespace
            // authority out of that owner's outstanding evidence.
            return Ok(PendingSnapshotNamespaceRecoveryAuthority::OtherPendingDirectory);
        }
    }
    for state in failures.values() {
        for failure in &state.pending {
            if failure
                .namespace
                .has_trusted_database_identity(database_identity)?
            {
                return Ok(PendingSnapshotNamespaceRecoveryAuthority::OtherPendingDirectory);
            }
        }
    }
    Ok(PendingSnapshotNamespaceRecoveryAuthority::None)
}

/// Acknowledge exactly the generation whose retained directory fd the caller
/// fsynced. A concurrent later failure, or one associated with another D1
/// incarnation at the same logical path, cannot be consumed by this call.
pub(crate) fn acknowledge_unpublished_snapshot_cleanup_failure(
    directory: &Path,
    failure: &RetainedSnapshotCleanupFailure,
) -> bool {
    unpublished_snapshot_cleanup_failures()
        .lock()
        .map(|mut failures| {
            let Some(state) = failures.get_mut(directory) else {
                return false;
            };
            let Some(position) = state.pending.iter().position(|pending| {
                pending.generation == failure.generation
                    && Arc::ptr_eq(&pending.namespace, &failure.namespace)
            }) else {
                return false;
            };
            state.pending.remove(position);
            let remove_directory = state.pending.is_empty();
            if remove_directory {
                failures.remove(directory);
            }
            true
        })
        .unwrap_or(false)
}

/// Observe a dropped-artifact cleanup failure without consuming its one-shot
/// recovery latch.  Admission must not erase evidence before current-snapshot
/// and directory validation have completed successfully.
pub(crate) fn has_unpublished_snapshot_cleanup_failure(directory: &Path) -> bool {
    pending_unpublished_snapshot_cleanup_failures(directory)
        .map(|failures| !failures.is_empty())
        .unwrap_or(true)
}

#[cfg(test)]
pub(crate) fn latch_unpublished_snapshot_cleanup_failure_for_test(
    namespace: Arc<RetainedSnapshotDirectory>,
) {
    record_unpublished_snapshot_cleanup_failure_in_namespace(namespace);
}

#[cfg(test)]
pub(crate) fn fail_snapshot_cleanup_post_rename_sync_for_test(original: &Path) {
    snapshot_cleanup_test_hooks()
        .lock()
        .expect("snapshot cleanup test hooks")
        .entry(original.to_path_buf())
        .or_default()
        .fail_post_rename_sync = true;
}

impl Drop for UnpublishedSnapshotArtifact {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut removed = match Self::remove_if_owned(&mut self.cleanup, self.identity) {
            Ok(removed) => removed,
            Err(_) => {
                record_unpublished_snapshot_cleanup_failure_for_state(&self.cleanup);
                false
            }
        };
        for (sidecar, identity) in &mut self.sidecars {
            // Sidecars have no long-lived guard after this Drop.  Their
            // state still follows the same rename-to-tombstone protocol so a
            // post-rename failure is never redirected to a replacement.
            match Self::remove_if_owned(sidecar, *identity) {
                Ok(sidecar_removed) => removed |= sidecar_removed,
                Err(_) => record_unpublished_snapshot_cleanup_failure_for_state(sidecar),
            }
        }
        if removed && self.cleanup.sync_parent().is_err() {
            record_unpublished_snapshot_cleanup_failure_for_state(&self.cleanup);
        }
    }
}

/// Create a fresh unnamed-output artifact with cleanup ownership transferred
/// atomically from the immediate post-`O_EXCL` guard to the identity-pinned
/// unpublished-artifact guard.  Callers must use this instead of creating a
/// namespace child and then doing fallible setup themselves.
pub(crate) fn create_unpublished_snapshot_file_in_namespace(
    namespace: Arc<RetainedSnapshotDirectory>,
    name: &OsStr,
    read: bool,
    sqlite_sidecars: bool,
) -> io::Result<(std::fs::File, UnpublishedSnapshotArtifact)> {
    let file = namespace.create_new(name, read)?;
    let mut emergency = NewNamespaceChildGuard::new(Arc::clone(&namespace), name, None);
    let cleanup = UnpublishedSnapshotArtifact::from_file_in_namespace(
        &file,
        namespace,
        name,
        sqlite_sidecars,
    )?;
    emergency.disarm();
    Ok((file, cleanup))
}

#[allow(dead_code)]
impl PinnedSqliteFile {
    /// Pin an already-open regular SQLite file to its current handle identity.
    pub(crate) fn from_file(file: std::fs::File, path: PathBuf) -> io::Result<Self> {
        let metadata = file.metadata()?;
        ensure_regular_file(&metadata)?;
        let identity = file_identity(&metadata)?;
        Ok(Self {
            file,
            namespace: None,
            path,
            identity,
            immutable_generation: None,
            cleanup: None,
        })
    }

    /// Pin a newly-created SDK snapshot database and arm exact cleanup until
    /// the caller has durably published its enclosing snapshot.
    pub(crate) fn from_new_file(file: std::fs::File, path: PathBuf) -> io::Result<Self> {
        let mut pinned = Self::from_file(file, path)?;
        pinned.cleanup = Some(UnpublishedSnapshotArtifact::from_file(
            &pinned.file,
            pinned.path.clone(),
            true,
        )?);
        Ok(pinned)
    }

    /// Create and pin a new retained-namespace database.  An infallible
    /// emergency cleanup owner is installed immediately after O_EXCL before
    /// this constructor performs metadata/proc-path work.
    pub(crate) fn create_new_in_namespace(
        namespace: Arc<RetainedSnapshotDirectory>,
        name: &OsStr,
    ) -> io::Result<Self> {
        let file = namespace.create_new(name, true)?;
        let mut emergency = NewNamespaceChildGuard::new(Arc::clone(&namespace), name, None);
        #[cfg(test)]
        if take_namespace_pinned_post_create_setup_failure(&namespace)
            || take_namespace_vacuum_raw_pinned_post_create_setup_failure(&namespace, name)
        {
            return Err(io::Error::other(
                "injected retained-namespace pinned post-create setup failure",
            ));
        }
        let pinned = Self::from_new_file_in_namespace(file, namespace, name)?;
        emergency.disarm();
        Ok(pinned)
    }

    /// Retained-dirfd constructor used only while
    /// [`Self::create_new_in_namespace`] holds the immediate cleanup guard.
    fn from_new_file_in_namespace(
        file: std::fs::File,
        namespace: Arc<RetainedSnapshotDirectory>,
        name: &OsStr,
    ) -> io::Result<Self> {
        let path = namespace.sqlite_child_path(name)?;
        let mut pinned = Self::from_file(file, path)?;
        pinned.namespace = Some((Arc::clone(&namespace), name.to_os_string()));
        pinned.cleanup = Some(UnpublishedSnapshotArtifact::from_file_in_namespace(
            &pinned.file,
            namespace,
            name,
            true,
        )?);
        Ok(pinned)
    }

    /// The SDK-controlled diagnostic path associated with this handle.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// The identity captured from the open handle when it was pinned.
    pub(crate) fn identity(&self) -> FileIdentity {
        self.identity
    }

    /// Borrow the pinned handle without resolving its pathname again.
    pub(crate) fn file(&self) -> &std::fs::File {
        &self.file
    }

    /// Clone the pinned OS handle without reopening its pathname.
    pub(crate) fn try_clone(&self) -> io::Result<Self> {
        self.verify_identity()?;
        let file = self.file.try_clone()?;
        if file_identity(&file.metadata()?)? != self.identity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "cloned SQLite file handle identity changed",
            ));
        }
        Ok(Self {
            file,
            namespace: self.namespace.clone(),
            path: self.path.clone(),
            identity: self.identity,
            immutable_generation: self.immutable_generation,
            cleanup: None,
        })
    }

    /// Consume the wrapper and return the already-open OS handle.
    pub(crate) fn into_file(mut self) -> std::fs::File {
        self.cleanup = None;
        self.file
    }

    /// Transfer cleanup ownership alongside the descriptor for an
    /// unpublished SDK-created artifact.
    pub(crate) fn into_file_with_cleanup(
        mut self,
    ) -> (std::fs::File, Option<UnpublishedSnapshotArtifact>) {
        let cleanup = self.cleanup.take();
        (self.file, cleanup)
    }

    /// Mark the SDK-created database as intentionally retained by its caller.
    pub(crate) fn disarm_cleanup(&mut self) {
        if let Some(cleanup) = self.cleanup.as_mut() {
            cleanup.disarm();
        }
    }

    /// Move an already-created artifact's exact cleanup state onto the
    /// retained namespace after a pathname-only SQLite API created it through
    /// `/proc/self/fd/<dirfd>/<basename>`.
    pub(crate) fn bind_cleanup_to_namespace(
        &mut self,
        namespace: Arc<RetainedSnapshotDirectory>,
        name: &OsStr,
    ) -> io::Result<()> {
        let cleanup = self
            .cleanup
            .as_mut()
            .ok_or_else(|| invalid_data("snapshot artifact has no cleanup authority to bind"))?;
        cleanup.rebind_in_namespace(namespace, name)
    }

    /// Refresh the expected content identity after SQLite has written through
    /// this same descriptor. Cleanup ownership remains attached to the inode.
    pub(crate) fn refresh_identity(mut self) -> io::Result<Self> {
        self.identity = file_identity(&self.file.metadata()?)?;
        Ok(self)
    }

    /// Open a read-only, no-follow descriptor for this exact writer inode
    /// before the writer is closed.  The pathname is used only to acquire the
    /// new descriptor; the identity comparison is the authority for the
    /// handoff.
    #[cfg(target_os = "linux")]
    pub(crate) fn pin_readonly_from_writer(&self) -> io::Result<Self> {
        self.verify_identity()?;
        let file = match &self.namespace {
            Some((namespace, name)) => namespace.open_read(name)?,
            None => readonly_nofollow(&self.path)?,
        };
        let mut pinned = Self::from_file(file, self.path.clone())?;
        pinned.namespace = self.namespace.clone();
        if pinned.identity != self.identity {
            return Err(invalid_data(
                "fixed snapshot changed while acquiring its read-only pin",
            ));
        }
        pinned.verify_linked_identity()?;
        if !pinned.path_matches_identity(&self.path)? {
            return Err(invalid_data(
                "fixed snapshot path changed while acquiring its read-only pin",
            ));
        }
        Ok(pinned)
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn pin_readonly_from_writer(&self) -> io::Result<Self> {
        let _ = self;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "fixed snapshot sealing is unavailable",
        ))
    }

    /// Update the diagnostic pathname after an atomic rename. The held
    /// descriptor identity remains the authorization primitive.
    pub(crate) fn rebind_path(&mut self, path: PathBuf) {
        self.path = path;
    }

    /// Update both the SQLite-only path spelling and retained namespace name
    /// after an fd-relative atomic rename.
    pub(crate) fn rebind_in_namespace(
        &mut self,
        namespace: Arc<RetainedSnapshotDirectory>,
        name: &OsStr,
    ) -> io::Result<()> {
        self.path = namespace.sqlite_child_path(name)?;
        self.namespace = Some((namespace, name.to_os_string()));
        Ok(())
    }

    /// Durably sync the parent namespace after SQLite has populated this
    /// pinned artifact. Namespace-created files must never reopen a logical
    /// parent path here: the retained directory descriptor remains the only
    /// operational authority after admission.
    pub(crate) fn sync_parent_directory(&self) -> io::Result<()> {
        match &self.namespace {
            Some((namespace, _)) => namespace.sync(),
            None => sync_snapshot_parent_directory(&self.path),
        }
    }

    /// Record the exact identities of any SQLite sidecars created for this
    /// unique raw artifact, so later cleanup cannot remove replacements.
    pub(crate) fn capture_created_sidecars(&mut self) {
        if let Some(cleanup) = self.cleanup.as_mut() {
            cleanup.capture_sidecars();
        }
    }

    /// Sum SQLite sidecars without re-resolving an admitted namespace through
    /// its process-local `/proc` spelling. Existing sidecars are regular
    /// files opened with the retained dirfd; absent sidecars contribute zero.
    /// The legacy path-only branch remains for isolated non-namespace tests.
    pub(crate) fn sidecar_bytes(&self) -> io::Result<u64> {
        let mut total = 0_u64;
        match &self.namespace {
            Some((namespace, name)) => {
                for suffix in ["-journal", "-wal", "-shm"] {
                    let mut sidecar = name.clone();
                    sidecar.push(suffix);
                    let file = match namespace.open_read(&sidecar) {
                        Ok(file) => file,
                        Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                        Err(error) => return Err(error),
                    };
                    let metadata = file.metadata()?;
                    ensure_regular_file(&metadata)?;
                    total = total.checked_add(metadata.len()).ok_or_else(|| {
                        invalid_data("session consensus SQLite sidecar length overflow")
                    })?;
                }
            }
            None => {
                for suffix in ["-journal", "-wal", "-shm"] {
                    let mut sidecar = self.path.as_os_str().to_os_string();
                    sidecar.push(suffix);
                    let metadata = match std::fs::symlink_metadata(&sidecar) {
                        Ok(metadata) => metadata,
                        Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                        Err(error) => return Err(error),
                    };
                    ensure_regular_file(&metadata)?;
                    total = total.checked_add(metadata.len()).ok_or_else(|| {
                        invalid_data("session consensus SQLite sidecar length overflow")
                    })?;
                }
            }
        }
        Ok(total)
    }

    /// Revalidate that the held handle itself has not changed identity.
    pub(crate) fn verify_identity(&self) -> io::Result<()> {
        let current = file_identity(&self.file.metadata()?)?;
        if current == self.identity {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "pinned SQLite file handle identity changed",
            ))
        }
    }

    /// Reopen a final artifact read-only with `O_NOFOLLOW`, authenticate the
    /// pathname to the new descriptor, and enable the fixed fs-verity profile.
    /// Every writable alias held by this process must have been dropped before
    /// this call. The kernel rejects a concurrent writer, which is the point
    /// of sealing rather than merely observing a hash.
    #[cfg(target_os = "linux")]
    pub(crate) fn reopen_and_seal_fixed(path: &Path) -> io::Result<Self> {
        let file = readonly_nofollow(path)?;
        let mut pinned = Self::from_file(file, path.to_path_buf())?;
        pinned.verify_linked_identity()?;
        if !pinned.path_matches_identity(path)? {
            return Err(invalid_data("fixed snapshot path changed before sealing"));
        }
        pinned.seal_fixed()?;
        Ok(pinned)
    }

    /// Enable the fixed profile on this already-open, identity-checked
    /// descriptor. Callers that hand off from a writer must use this instead
    /// of reopening the pathname after closing that writer.
    #[cfg(target_os = "linux")]
    pub(crate) fn seal_fixed(&mut self) -> io::Result<()> {
        let digest = opc_fs_verity_sys::enable_fixed_profile(self.file.as_fd())
            .map_err(fs_verity_enable_error)?;
        let metadata = self.file.metadata()?;
        self.immutable_generation = Some(ImmutableFileGeneration {
            length: metadata.len(),
            digest,
            change_time: linux_file_change_time(&metadata),
        });
        self.verify_immutable_generation()
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn seal_fixed(&mut self) -> io::Result<()> {
        let _ = self;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "fixed snapshot sealing is unavailable",
        ))
    }

    /// Reopen a final fixed artifact and require an existing fixed fs-verity
    /// seal. This is used after restart and for received fixed snapshots;
    /// unsealed byte-identical replacements fail closed.
    #[cfg(target_os = "linux")]
    pub(crate) fn reopen_and_measure_fixed(path: &Path) -> io::Result<Self> {
        let file = readonly_nofollow(path)?;
        let mut pinned = Self::from_file(file, path.to_path_buf())?;
        pinned.verify_linked_identity()?;
        if !pinned.path_matches_identity(path)? {
            return Err(invalid_data(
                "fixed snapshot path changed before measurement",
            ));
        }
        let digest = opc_fs_verity_sys::measure_exact_profile(pinned.file.as_fd())
            .map_err(fs_verity_measure_error)?;
        let metadata = pinned.file.metadata()?;
        pinned.immutable_generation = Some(ImmutableFileGeneration {
            length: metadata.len(),
            digest,
            change_time: linux_file_change_time(&metadata),
        });
        pinned.verify_immutable_generation()?;
        Ok(pinned)
    }

    /// Bind an already-authoritative recovery descriptor to the exact fixed
    /// fs-verity generation without reopening its pathname.  Terminal
    /// recovery uses this for the descriptor it authenticated before normal
    /// snapshot startup is allowed to observe the public name.
    #[cfg(target_os = "linux")]
    pub(crate) fn from_file_and_measure_fixed(
        file: std::fs::File,
        path: PathBuf,
    ) -> io::Result<Self> {
        let mut pinned = Self::from_file(file, path)?;
        pinned.verify_linked_identity()?;
        let digest = opc_fs_verity_sys::measure_exact_profile(pinned.file.as_fd())
            .map_err(fs_verity_measure_error)?;
        let metadata = pinned.file.metadata()?;
        pinned.immutable_generation = Some(ImmutableFileGeneration {
            length: metadata.len(),
            digest,
            change_time: linux_file_change_time(&metadata),
        });
        pinned.verify_immutable_generation()?;
        Ok(pinned)
    }

    /// Retained-namespace variant of [`Self::from_file_and_measure_fixed`].
    /// The supplied descriptor and all later identity fences remain relative
    /// to `namespace`; `/proc/self/fd` is retained only as a path spelling for
    /// SQLite APIs and diagnostics.
    #[cfg(target_os = "linux")]
    pub(crate) fn from_file_and_measure_fixed_in_namespace(
        file: std::fs::File,
        namespace: Arc<RetainedSnapshotDirectory>,
        name: &OsStr,
    ) -> io::Result<Self> {
        let path = namespace.sqlite_child_path(name)?;
        let mut pinned = Self::from_file(file, path)?;
        pinned.namespace = Some((namespace, name.to_os_string()));
        pinned.verify_linked_identity()?;
        let digest = opc_fs_verity_sys::measure_exact_profile(pinned.file.as_fd())
            .map_err(fs_verity_measure_error)?;
        let metadata = pinned.file.metadata()?;
        pinned.immutable_generation = Some(ImmutableFileGeneration {
            length: metadata.len(),
            digest,
            change_time: linux_file_change_time(&metadata),
        });
        pinned.verify_immutable_generation()?;
        Ok(pinned)
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn reopen_and_seal_fixed(_path: &Path) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "fixed snapshot sealing is unavailable",
        ))
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn reopen_and_measure_fixed(_path: &Path) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "fixed snapshot sealing is unavailable",
        ))
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn from_file_and_measure_fixed(
        _file: std::fs::File,
        _path: PathBuf,
    ) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "fixed snapshot sealing is unavailable",
        ))
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn from_file_and_measure_fixed_in_namespace(
        _file: std::fs::File,
        _namespace: Arc<RetainedSnapshotDirectory>,
        _name: &OsStr,
    ) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "fixed snapshot sealing is unavailable",
        ))
    }

    /// Recheck the previously bound immutable content generation.
    pub(crate) fn verify_immutable_generation(&self) -> io::Result<()> {
        self.verify_linked_identity()?;
        let expected = self.immutable_generation.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "pinned SQLite file immutable generation is absent",
            )
        })?;
        self.verify_bound_immutable_metadata(expected)?;
        let digest = fixed_verity_measurement(&self.file)?;
        if digest == expected.digest {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "pinned SQLite file immutable generation changed",
            ))
        }
    }

    /// Validate a snapshot envelope through exactly one bounded, sequential
    /// descriptor scan. Fixed callers must seal and measure this descriptor
    /// before entering this method; the envelope scan itself never claims
    /// userspace hashing makes a mutable file immutable.
    ///
    /// The trailing footer is retained in a fixed-size buffer while the
    /// preceding bytes feed the payload digest. Fixed-profile generation
    /// authority comes from the kernel measurement, never this userspace
    /// validation digest.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn verify_snapshot_envelope_and_bind_immutable_generation(
        &mut self,
        path: &Path,
        footer_magic: &[u8; 8],
        footer_bytes: u64,
        maximum_payload_bytes: u64,
        expected_payload_checksum: [u8; 32],
        expected_total_length: u64,
    ) -> io::Result<ImmutableSnapshotEnvelope> {
        self.verify_linked_identity()?;
        if !self.path_matches_identity(path)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "pinned SQLite file path was replaced",
            ));
        }
        if footer_bytes != 48 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snapshot footer size is invalid",
            ));
        }
        let initial_metadata = self.file.metadata()?;
        let total_length = initial_metadata.len();
        #[cfg(target_os = "linux")]
        let initial_change_time = linux_file_change_time(&initial_metadata);
        if total_length != expected_total_length
            || total_length <= footer_bytes
            || total_length > maximum_payload_bytes.saturating_add(footer_bytes)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "session consensus snapshot size is invalid",
            ));
        }

        let footer_len = usize::try_from(footer_bytes).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "snapshot footer size is invalid",
            )
        })?;
        #[cfg(test)]
        block_fixed_prepublication_scan(&self.path);
        let mut reader = self.file.try_clone()?;
        reader.seek(io::SeekFrom::Start(0))?;
        let mut payload_hasher = sha2::Sha256::new();
        let mut trailing = [0_u8; 48];
        let mut trailing_len = 0_usize;
        let mut buffer = [0_u8; 64 * 1024];
        let mut scanned = 0_u64;
        while scanned < total_length {
            let remaining = total_length.checked_sub(scanned).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "snapshot length overflow")
            })?;
            let bounded = usize::try_from(remaining)
                .unwrap_or(usize::MAX)
                .min(buffer.len());
            let read = reader.read(&mut buffer[..bounded])?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "session consensus snapshot changed during verification",
                ));
            }
            scanned = scanned
                .checked_add(u64::try_from(read).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "snapshot length overflow")
                })?)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "snapshot length overflow")
                })?;
            if trailing_len + read <= footer_len {
                trailing[trailing_len..trailing_len + read].copy_from_slice(&buffer[..read]);
                trailing_len = trailing_len.checked_add(read).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "snapshot footer size is invalid",
                    )
                })?;
            } else if trailing_len == footer_len {
                if read < footer_len {
                    payload_hasher.update(&trailing[..read]);
                    trailing.copy_within(read..footer_len, 0);
                    trailing[footer_len - read..footer_len].copy_from_slice(&buffer[..read]);
                } else {
                    payload_hasher.update(trailing);
                    let payload_from_buffer = read - footer_len;
                    payload_hasher.update(&buffer[..payload_from_buffer]);
                    trailing.copy_from_slice(&buffer[payload_from_buffer..read]);
                }
            } else {
                let payload_bytes = trailing_len.checked_add(read).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "snapshot footer size is invalid",
                    )
                })? - footer_len;
                if payload_bytes < trailing_len {
                    payload_hasher.update(&trailing[..payload_bytes]);
                    let retained_from_trailing = trailing_len - payload_bytes;
                    trailing.copy_within(payload_bytes..trailing_len, 0);
                    trailing[retained_from_trailing..footer_len].copy_from_slice(&buffer[..read]);
                } else {
                    payload_hasher.update(&trailing[..trailing_len]);
                    let payload_from_buffer = payload_bytes - trailing_len;
                    payload_hasher.update(&buffer[..payload_from_buffer]);
                    trailing.copy_from_slice(&buffer[payload_from_buffer..read]);
                }
                trailing_len = footer_len;
            }
        }
        #[cfg(test)]
        {
            record_fixed_prepublication_scan(&self.path, scanned);
        }
        let scanned_metadata = self.file.metadata()?;
        if trailing_len != footer_len || scanned_metadata.len() != total_length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "session consensus snapshot changed during verification",
            ));
        }
        #[cfg(target_os = "linux")]
        if linux_file_change_time(&scanned_metadata) != initial_change_time {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "session consensus snapshot changed during verification",
            ));
        }

        let (magic, footer) = trailing.split_at(8);
        if magic != footer_magic {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "session consensus snapshot magic is invalid",
            ));
        }
        let encoded_length: [u8; 8] = footer[..8].try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "snapshot footer length is invalid",
            )
        })?;
        let payload_length = u64::from_be_bytes(encoded_length);
        if payload_length == 0
            || payload_length > maximum_payload_bytes
            || payload_length.checked_add(footer_bytes) != Some(total_length)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "session consensus snapshot length is invalid",
            ));
        }
        let footer_checksum: [u8; 32] = footer[8..].try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "snapshot footer checksum is invalid",
            )
        })?;
        let payload_checksum: [u8; 32] = payload_hasher.finalize().into();
        if footer_checksum != expected_payload_checksum || payload_checksum != footer_checksum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "session consensus snapshot checksum mismatch",
            ));
        }

        self.verify_linked_identity()?;
        if !self.path_matches_identity(path)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "pinned SQLite file path was replaced",
            ));
        }
        let bound_metadata = self.file.metadata()?;
        #[cfg(target_os = "linux")]
        let bound_change_time = linux_file_change_time(&bound_metadata);
        if bound_metadata.len() != total_length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "session consensus snapshot changed during verification",
            ));
        }
        #[cfg(target_os = "linux")]
        if bound_change_time != initial_change_time {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "session consensus snapshot changed during verification",
            ));
        }
        // The envelope hash is validation only. If this descriptor already
        // carries a fixed-profile seal, bind the post-scan generation to that
        // same kernel digest. This deliberately permits the authorized rename
        // between sealing the staging name and scanning the published name to
        // advance `ctime`, while rejecting a different seal, length, inode, or
        // pathname. Dynamic callers retain userspace corruption detection and
        // never acquire immutable authority here.
        if let Some(sealed_generation) = self.immutable_generation {
            if sealed_generation.length != total_length {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "session consensus snapshot immutable length is inconsistent",
                ));
            }
            let rebound_digest = fixed_verity_measurement(&self.file)?;
            if rebound_digest != sealed_generation.digest {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "pinned SQLite file immutable generation changed",
                ));
            }
            let rebound_metadata = self.file.metadata()?;
            if rebound_metadata.len() != total_length {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "session consensus snapshot changed during verification",
                ));
            }
            #[cfg(target_os = "linux")]
            if linux_file_change_time(&rebound_metadata) != bound_change_time {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "session consensus snapshot changed during verification",
                ));
            }
            self.verify_linked_identity()?;
            if !self.path_matches_identity(path)? {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "pinned SQLite file path was replaced",
                ));
            }
            self.immutable_generation = Some(ImmutableFileGeneration {
                length: total_length,
                digest: rebound_digest,
                #[cfg(target_os = "linux")]
                change_time: bound_change_time,
            });
        }
        Ok(ImmutableSnapshotEnvelope {
            payload_length,
            total_length,
        })
    }

    /// Read the self-describing footer from this already-sealed descriptor so
    /// a receiver can establish its expected checksum and length without
    /// consulting a second, mutable source descriptor.  This is intentionally
    /// only the small footer read: callers must immediately perform the full
    /// bounded validation with
    /// [`Self::verify_snapshot_envelope_and_bind_immutable_generation`].
    pub(crate) fn snapshot_envelope_footer_from_pinned_descriptor(
        &self,
        path: &Path,
        footer_magic: &[u8; 8],
        footer_bytes: u64,
        maximum_payload_bytes: u64,
    ) -> io::Result<([u8; 32], u64)> {
        self.verify_immutable_generation()?;
        if !self.path_matches_identity(path)? {
            return Err(invalid_data("pinned SQLite file path was replaced"));
        }
        if footer_bytes != 48 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snapshot footer size is invalid",
            ));
        }
        let total_length = self.file.metadata()?.len();
        if total_length <= footer_bytes
            || total_length > maximum_payload_bytes.saturating_add(footer_bytes)
        {
            return Err(invalid_data("session consensus snapshot size is invalid"));
        }
        let mut reader = self.file.try_clone()?;
        reader.seek(io::SeekFrom::End(-i64::try_from(footer_bytes).map_err(
            |_| invalid_data("session consensus snapshot footer size is invalid"),
        )?))?;
        let mut footer = [0_u8; 48];
        reader.read_exact(&mut footer)?;
        if &footer[..8] != footer_magic {
            return Err(invalid_data("session consensus snapshot magic is invalid"));
        }
        let encoded_length: [u8; 8] = footer[8..16]
            .try_into()
            .map_err(|_| invalid_data("snapshot footer length is invalid"))?;
        let payload_length = u64::from_be_bytes(encoded_length);
        if payload_length == 0
            || payload_length > maximum_payload_bytes
            || payload_length.checked_add(footer_bytes) != Some(total_length)
        {
            return Err(invalid_data("session consensus snapshot length is invalid"));
        }
        let checksum: [u8; 32] = footer[16..]
            .try_into()
            .map_err(|_| invalid_data("snapshot footer checksum is invalid"))?;
        self.verify_immutable_generation()?;
        if !self.path_matches_identity(path)? {
            return Err(invalid_data("pinned SQLite file path was replaced"));
        }
        Ok((checksum, total_length))
    }

    /// Recheck the constant-time authority needed between a completed
    /// immutable descriptor scan and durable metadata publication.
    ///
    /// The bounded scan above remains the sole content authority. This method
    /// deliberately performs only descriptor identity/link, pathname identity,
    /// fs-verity measurement, length, and Linux kernel change-time generation
    /// checks so SQLite's mutex need not cover a second full-file hash.
    pub(crate) fn verify_bound_immutable_snapshot_envelope(
        &self,
        path: &Path,
        expected_total_length: u64,
    ) -> io::Result<()> {
        let immutable_generation = self.immutable_generation.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "pinned SQLite file immutable generation is absent",
            )
        })?;
        if immutable_generation.length != expected_total_length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "session consensus snapshot immutable length is inconsistent",
            ));
        }

        self.verify_immutable_generation()?;
        if !self.path_matches_identity(path)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "pinned SQLite file path was replaced",
            ));
        }

        // Recheck after resolving the pathname so a replacement or unlink
        // racing that lookup cannot authorize the metadata write.
        self.verify_immutable_generation()?;
        if !self.path_matches_identity(path)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "pinned SQLite file path was replaced",
            ));
        }
        Ok(())
    }

    /// Check the descriptor metadata bound at the end of the sole content
    /// scan. This has no content read: it is the constant-time fence used by
    /// the metadata publication critical section.
    fn verify_bound_immutable_metadata(
        &self,
        immutable_generation: ImmutableFileGeneration,
    ) -> io::Result<()> {
        let metadata = self.file.metadata()?;
        if metadata.len() != immutable_generation.length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "session consensus snapshot length changed after verification",
            ));
        }
        #[cfg(target_os = "linux")]
        if linux_file_change_time(&metadata) != immutable_generation.change_time {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "session consensus snapshot generation changed after verification",
            ));
        }
        Ok(())
    }

    /// Whether this descriptor was explicitly promoted to an immutable
    /// artifact pin rather than a mutable live SQLite source pin.
    pub(crate) fn has_immutable_generation(&self) -> bool {
        self.immutable_generation.is_some()
    }

    /// Verify this descriptor still names a linked regular file.
    ///
    /// Snapshot readers use this for their WAL descriptor. An unlinked WAL
    /// could otherwise retain bytes after a replacement while pathname
    /// metadata reports zero or a different file.
    #[cfg(target_os = "linux")]
    pub(crate) fn verify_linked_identity(&self) -> io::Result<()> {
        use std::os::linux::fs::MetadataExt as _;

        self.verify_identity()?;
        if self.file.metadata()?.st_nlink() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "pinned SQLite file is no longer singly linked",
            ));
        }
        Ok(())
    }

    /// Reject link-count authorization on platforms where the descriptor
    /// identity and link count cannot be established by this adapter.
    #[cfg(not(target_os = "linux"))]
    pub(crate) fn verify_linked_identity(&self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "linked SQLite file identity requires Linux",
        ))
    }

    /// Compare a pathname with the pinned identity through a fresh
    /// `O_NOFOLLOW | O_NONBLOCK` descriptor.
    ///
    /// The re-open makes this suitable for final authorization checks: a
    /// symlink cannot be substituted for a same-inode path while the identity
    /// comparison is in progress.
    pub(crate) fn path_matches_identity(&self, path: &Path) -> io::Result<bool> {
        if let Some((namespace, name)) = &self.namespace {
            if path.file_name() != Some(name.as_os_str()) {
                return Ok(false);
            }
            let metadata = namespace.open_read(name)?.metadata()?;
            if !metadata.is_file() {
                return Ok(false);
            }
            return Ok(file_identity(&metadata)? == self.identity);
        }
        #[cfg(target_os = "linux")]
        let metadata = readonly_nofollow(path)?.metadata()?;
        #[cfg(not(target_os = "linux"))]
        let metadata = std::fs::metadata(path)?;
        if !metadata.is_file() {
            return Ok(false);
        }
        Ok(file_identity(&metadata)? == self.identity)
    }

    /// Return the descriptor for descriptor-based SQLite binding on Linux.
    #[cfg(target_os = "linux")]
    pub(crate) fn raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn readonly_nofollow(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    options.open(path)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn readonly_nofollow(path: &Path) -> io::Result<std::fs::File> {
    std::fs::File::open(path)
}

#[cfg(target_os = "linux")]
fn fixed_verity_measurement(file: &std::fs::File) -> io::Result<[u8; 32]> {
    opc_fs_verity_sys::measure_exact_profile(file.as_fd()).map_err(fs_verity_measure_error)
}

/// Classify the one kernel result emitted by an old fixed snapshot that
/// predates fs-verity.  This probes descriptor metadata only: it does not
/// read, hash, parse, or otherwise grant authority to the snapshot payload.
/// Every other fs-verity error remains fail-closed.
#[cfg(target_os = "linux")]
pub(crate) fn fixed_verity_is_exactly_unsealed(file: &std::fs::File) -> io::Result<bool> {
    match opc_fs_verity_sys::measure(file.as_fd()) {
        // `FS_IOC_MEASURE_VERITY` is the only kernel operation whose ENODATA
        // has the narrow legacy meaning required here.  A measured artifact
        // must still satisfy the complete fixed profile; a partially sealed
        // or differently profiled file is not an upgrade candidate.
        Ok(_) => opc_fs_verity_sys::measure_exact_profile(file.as_fd())
            .map(|_| false)
            .map_err(fs_verity_measure_error),
        Err(opc_fs_verity_sys::Error::Measure(error))
            if error.raw_os_error() == Some(libc::ENODATA) =>
        {
            Ok(true)
        }
        Err(error) => Err(fs_verity_measure_error(error)),
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn fixed_verity_is_exactly_unsealed(_file: &std::fs::File) -> io::Result<bool> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "fixed snapshot sealing is unavailable",
    ))
}

#[cfg(not(target_os = "linux"))]
fn fixed_verity_measurement(_file: &std::fs::File) -> io::Result<[u8; 32]> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "fixed snapshot sealing is unavailable",
    ))
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(target_os = "linux")]
fn fs_verity_enable_error(error: opc_fs_verity_sys::Error) -> io::Error {
    // Preserve only the kernel errno for operator qualification.  The
    // descriptor-only fs-verity API never contains a pathname or contents,
    // while collapsing this to a generic Unsupported error made a valid
    // qualification mount indistinguishable from a descriptor-lifetime bug.
    let diagnostic = match &error {
        opc_fs_verity_sys::Error::Enable(error) => {
            format!("enable errno={:?}", error.raw_os_error())
        }
        opc_fs_verity_sys::Error::Measure(error) => {
            format!("post-enable measurement errno={:?}", error.raw_os_error())
        }
        other => format!("{other}"),
    };
    let kind = match &error {
        opc_fs_verity_sys::Error::Unsupported
        | opc_fs_verity_sys::Error::UnsupportedProfile { .. } => io::ErrorKind::Unsupported,
        opc_fs_verity_sys::Error::Enable(error) => {
            if matches!(
                error.raw_os_error(),
                Some(libc::ENOTTY) | Some(libc::EOPNOTSUPP) | Some(libc::ENOSYS)
            ) {
                io::ErrorKind::Unsupported
            } else {
                io::ErrorKind::InvalidData
            }
        }
        // An enable operation that cannot immediately measure the requested
        // fixed profile is not an artifact authorization success.
        opc_fs_verity_sys::Error::Measure(_) => io::ErrorKind::InvalidData,
        _ => io::ErrorKind::InvalidData,
    };
    io::Error::new(
        kind,
        format!("fixed snapshot sealing is unavailable ({diagnostic})"),
    )
}

#[cfg(target_os = "linux")]
fn fs_verity_measure_error(_error: opc_fs_verity_sys::Error) -> io::Error {
    // A fixed artifact without a readable fixed-profile measurement is corrupt
    // (or unavailable), but never a pathname-bearing diagnostic.
    io::Error::new(io::ErrorKind::InvalidData, "fixed snapshot seal is invalid")
}

impl fmt::Debug for PinnedSqliteFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PinnedSqliteFile(<redacted>)")
    }
}

/// A seekable, chunkable snapshot file and its SDK-controlled staging path.
pub(crate) struct SessionSnapshotFile {
    file: tokio::fs::File,
    path: PathBuf,
    cleanup: Option<SnapshotCleanupGuard>,
    received_bytes: u64,
    received_maximum: u64,
    cursor: u64,
    extent: u64,
    receiving: bool,
    receive_limit_exceeded: bool,
    // Kept by a receiving artifact so cloned state-machine handles cannot
    // retain more than one unvalidated snapshot stream for one core.
    _receive_admission: Option<tokio::sync::OwnedSemaphorePermit>,
    // The snapshot namespace authority outlives state-machine/log wrappers
    // while a receiver is still writable.  It is intentionally opaque here:
    // transport owns no policy, it merely retains the admission capability.
    _namespace_lease: Option<Arc<dyn Send + Sync>>,
    seek_in_flight: bool,
    replay: Option<SnapshotReplayRead>,
    io_poisoned: bool,
}

/// An owned block read while proving a sender retry matches accepted bytes.
///
/// Tokio may return `Pending` after accepting the read request. The buffer is
/// therefore owned by the snapshot rather than borrowed from `poll_write`.
struct SnapshotReplayRead {
    start: u64,
    expected: Vec<u8>,
}

struct SnapshotCleanupGuard {
    state: Arc<std::sync::Mutex<SnapshotCleanupState>>,
    identity: FileIdentity,
    // Keeps the authenticated inode alive even after SessionSnapshotFile's
    // Tokio descriptor is dropped before this field's Drop runs.
    _pin: std::fs::File,
    armed: bool,
    cleanup_failed: Option<Arc<AtomicBool>>,
}

// The retained-dirfd receiver creates the inode on a blocking worker. Keep
// causal fault points both before cleanup-owner setup and after it is armed:
// descriptor pressure must not strand an O_EXCL-created incoming artifact.
#[cfg(test)]
#[derive(Default)]
struct NamespacePostCreateTestFailures {
    receiver_setup: bool,
    pinned_setup: bool,
    vacuum_raw_pinned_setup: bool,
    receiver_sync: bool,
}

#[cfg(test)]
fn namespace_post_create_test_failures(
) -> &'static std::sync::Mutex<BTreeMap<PathBuf, NamespacePostCreateTestFailures>> {
    static FAILURES: std::sync::OnceLock<
        std::sync::Mutex<BTreeMap<PathBuf, NamespacePostCreateTestFailures>>,
    > = std::sync::OnceLock::new();
    FAILURES.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()))
}

#[cfg(test)]
pub(crate) fn fail_namespace_receiver_post_create_setup_for_test(
    namespace: &RetainedSnapshotDirectory,
) {
    namespace_post_create_test_failures()
        .lock()
        .expect("namespace post-create test failures")
        .entry(namespace.cleanup_latch_identity().to_path_buf())
        .or_default()
        .receiver_setup = true;
}

#[cfg(test)]
fn take_namespace_receiver_post_create_setup_failure(
    namespace: &RetainedSnapshotDirectory,
) -> bool {
    namespace_post_create_test_failures()
        .lock()
        .expect("namespace post-create test failures")
        .get_mut(namespace.cleanup_latch_identity())
        .is_some_and(|failures| std::mem::take(&mut failures.receiver_setup))
}

// Pinned SQLite creation has the same O_EXCL-before-metadata boundary as the
// receiver. Build/VACUUM tests use this distinct point to prove both the
// final and intermediate SQLite children cannot leak under descriptor
// pressure before their identity-pinned cleanup owner exists.
#[cfg(test)]
pub(crate) fn fail_namespace_pinned_post_create_setup_for_test(
    namespace: &RetainedSnapshotDirectory,
) {
    namespace_post_create_test_failures()
        .lock()
        .expect("namespace post-create test failures")
        .entry(namespace.cleanup_latch_identity().to_path_buf())
        .or_default()
        .pinned_setup = true;
}

#[cfg(test)]
fn take_namespace_pinned_post_create_setup_failure(namespace: &RetainedSnapshotDirectory) -> bool {
    namespace_post_create_test_failures()
        .lock()
        .expect("namespace post-create test failures")
        .get_mut(namespace.cleanup_latch_identity())
        .is_some_and(|failures| std::mem::take(&mut failures.pinned_setup))
}

/// Target the fallback builder's strict `vacuum-raw-*` intermediate after its
/// final `build-*` pin was successfully armed.
#[cfg(test)]
pub(crate) fn fail_namespace_vacuum_raw_pinned_post_create_setup_for_test(
    namespace: &RetainedSnapshotDirectory,
) {
    namespace_post_create_test_failures()
        .lock()
        .expect("namespace post-create test failures")
        .entry(namespace.cleanup_latch_identity().to_path_buf())
        .or_default()
        .vacuum_raw_pinned_setup = true;
}

#[cfg(test)]
fn take_namespace_vacuum_raw_pinned_post_create_setup_failure(
    namespace: &RetainedSnapshotDirectory,
    name: &OsStr,
) -> bool {
    name.to_str()
        .is_some_and(|name| name.starts_with("vacuum-raw-"))
        && namespace_post_create_test_failures()
            .lock()
            .expect("namespace post-create test failures")
            .get_mut(namespace.cleanup_latch_identity())
            .is_some_and(|failures| std::mem::take(&mut failures.vacuum_raw_pinned_setup))
}

#[cfg(test)]
pub(crate) fn fail_namespace_receiver_post_create_sync_for_test(
    namespace: &RetainedSnapshotDirectory,
) {
    namespace_post_create_test_failures()
        .lock()
        .expect("namespace post-create test failures")
        .entry(namespace.cleanup_latch_identity().to_path_buf())
        .or_default()
        .receiver_sync = true;
}

#[cfg(test)]
fn take_namespace_receiver_post_create_sync_failure(namespace: &RetainedSnapshotDirectory) -> bool {
    namespace_post_create_test_failures()
        .lock()
        .expect("namespace post-create test failures")
        .get_mut(namespace.cleanup_latch_identity())
        .is_some_and(|failures| std::mem::take(&mut failures.receiver_sync))
}

impl SnapshotCleanupGuard {
    fn record_failure(&self) {
        // Publish the monotonic directory generation before the legacy
        // atomic hint. Validation snapshots/acknowledges generations, so a
        // failure concurrent with its fsync cannot be erased by a bool swap.
        if let Ok(state) = self.state.lock() {
            record_unpublished_snapshot_cleanup_failure_for_state(&state);
        }
        if let Some(cleanup_failed) = &self.cleanup_failed {
            cleanup_failed.store(true, Ordering::Release);
        }
    }

    async fn remove(&mut self) -> io::Result<()> {
        if !self.armed {
            return Ok(());
        }
        match tokio::task::spawn_blocking({
            let state = Arc::clone(&self.state);
            let identity = self.identity;
            move || {
                let mut state = state
                    .lock()
                    .map_err(|_| io::Error::other("snapshot cleanup state lock poisoned"))?;
                remove_snapshot_cleanup_if_owned(&mut state, identity)
            }
        })
        .await
        .map_err(|_| io::Error::other("snapshot cleanup worker failed"))?
        {
            Ok(true) | Ok(false) => {
                self.armed = false;
                Ok(())
            }
            Err(error) => {
                self.record_failure();
                Err(error)
            }
        }
    }
}

impl Drop for SnapshotCleanupGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let result = self
            .state
            .lock()
            .map_err(|_| io::Error::other("snapshot cleanup state lock poisoned"))
            .and_then(|mut state| remove_snapshot_cleanup_if_owned(&mut state, self.identity));
        if result.is_err() {
            self.record_failure();
        }
    }
}

fn sync_snapshot_parent_directory(path: &Path) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "snapshot artifact has no parent directory",
        )
    })?;
    std::fs::File::open(parent)?.sync_all()
}

/// The pathname presently owned by cleanup.  A successful rename changes
/// this state before any fallible durability or identity step, which keeps
/// every retry and Drop attempt pinned to the exact tombstone rather than the
/// now-vacant public name.
#[cfg(target_os = "linux")]
enum SnapshotCleanupLocation {
    Original,
    Tombstone(PathBuf),
    // The exact tombstone has been moved to this private basename after a
    // descriptor identity check.  Retain both spellings so a failed guard
    // authentication can restore only into the now-vacant tombstone name.
    UnlinkGuard { guard: PathBuf, tombstone: PathBuf },
    Unlinked,
}

struct SnapshotCleanupState {
    original: PathBuf,
    namespace: Option<Arc<RetainedSnapshotDirectory>>,
    #[cfg(target_os = "linux")]
    location: SnapshotCleanupLocation,
}

impl SnapshotCleanupState {
    fn new(path: PathBuf) -> Self {
        Self {
            original: path,
            namespace: None,
            #[cfg(target_os = "linux")]
            location: SnapshotCleanupLocation::Original,
        }
    }

    fn in_namespace(namespace: Arc<RetainedSnapshotDirectory>, name: &OsStr) -> io::Result<Self> {
        Ok(Self {
            original: namespace.logical_child(name)?,
            namespace: Some(namespace),
            #[cfg(target_os = "linux")]
            location: SnapshotCleanupLocation::Original,
        })
    }

    #[cfg(test)]
    fn rebind(&mut self, path: PathBuf) {
        self.original = path;
        self.namespace = None;
        #[cfg(target_os = "linux")]
        {
            self.location = SnapshotCleanupLocation::Original;
        }
    }

    #[cfg(target_os = "linux")]
    fn active_path(&self) -> Option<&Path> {
        match &self.location {
            SnapshotCleanupLocation::Original => Some(&self.original),
            SnapshotCleanupLocation::Tombstone(path) => Some(path),
            SnapshotCleanupLocation::UnlinkGuard { guard, .. } => Some(guard),
            SnapshotCleanupLocation::Unlinked => None,
        }
    }

    #[cfg(target_os = "linux")]
    fn tombstone_path(&self) -> Option<&Path> {
        match &self.location {
            SnapshotCleanupLocation::Tombstone(path) => Some(path),
            SnapshotCleanupLocation::UnlinkGuard { tombstone, .. } => Some(tombstone),
            SnapshotCleanupLocation::Original | SnapshotCleanupLocation::Unlinked => None,
        }
    }

    #[cfg(target_os = "linux")]
    fn active_name(&self) -> io::Result<&OsStr> {
        self.active_path()
            .and_then(Path::file_name)
            .ok_or_else(|| invalid_data("snapshot cleanup artifact has no basename"))
    }

    fn sync_parent(&self) -> io::Result<()> {
        match &self.namespace {
            Some(namespace) => namespace.sync(),
            None => sync_snapshot_parent_directory(&self.original),
        }
    }

    #[cfg(target_os = "linux")]
    fn open_active(&self) -> io::Result<std::fs::File> {
        match &self.namespace {
            Some(namespace) => namespace.open_read(self.active_name()?),
            None => readonly_nofollow(
                self.active_path()
                    .ok_or_else(|| invalid_data("snapshot cleanup artifact is unlinked"))?,
            ),
        }
    }

    #[cfg(target_os = "linux")]
    fn rename_noreplace(&self, from: &OsStr, to: &OsStr) -> io::Result<()> {
        match &self.namespace {
            Some(namespace) => namespace.rename_noreplace(from, to),
            None => {
                let parent = self
                    .original
                    .parent()
                    .ok_or_else(|| invalid_data("snapshot artifact has no parent"))?;
                let directory = std::fs::File::open(parent)?;
                rename_noreplace_in_directory(&directory, from, to)
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn unlink_active(&self) -> io::Result<()> {
        match &self.namespace {
            Some(namespace) => namespace.unlink(self.active_name()?),
            None => std::fs::remove_file(
                self.active_path()
                    .ok_or_else(|| invalid_data("snapshot cleanup artifact is unlinked"))?,
            ),
        }
    }
}

// The cleanup race is deliberately testable at the two causal boundaries.
// Production has no callback between identity authentication and rename, or
// between the durable rename state transition and its directory sync.
#[cfg(test)]
type SnapshotCleanupTestHook = Box<dyn FnOnce(&Path, &Path) + Send>;

#[cfg(test)]
#[derive(Default)]
struct SnapshotCleanupTestHooks {
    before_rename: Option<SnapshotCleanupTestHook>,
    #[cfg(target_os = "linux")]
    after_rename: Option<SnapshotCleanupTestHook>,
    #[cfg(target_os = "linux")]
    post_final_identity_before_unlink: Option<SnapshotCleanupTestHook>,
    fail_post_rename_sync: bool,
    #[cfg(target_os = "linux")]
    fail_post_unlink_guard_sync: bool,
}

#[cfg(test)]
fn snapshot_cleanup_test_hooks(
) -> &'static std::sync::Mutex<BTreeMap<PathBuf, SnapshotCleanupTestHooks>> {
    static HOOKS: std::sync::OnceLock<
        std::sync::Mutex<BTreeMap<PathBuf, SnapshotCleanupTestHooks>>,
    > = std::sync::OnceLock::new();
    HOOKS.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()))
}

#[cfg(test)]
pub(crate) fn snapshot_cleanup_test_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

#[cfg(all(test, target_os = "linux"))]
fn take_snapshot_cleanup_hook(
    original: &Path,
    after_rename: bool,
) -> (Option<SnapshotCleanupTestHook>, bool) {
    let mut hooks = snapshot_cleanup_test_hooks()
        .lock()
        .expect("snapshot cleanup test hooks");
    let Some(hooks) = hooks.get_mut(original) else {
        return (None, false);
    };
    let hook = if after_rename {
        hooks.after_rename.take()
    } else {
        hooks.before_rename.take()
    };
    let fail_sync = after_rename && std::mem::take(&mut hooks.fail_post_rename_sync);
    (hook, fail_sync)
}

#[cfg(target_os = "linux")]
fn snapshot_cleanup_before_rename(original: &Path, tombstone: &Path) {
    #[cfg(test)]
    if let (Some(hook), _) = take_snapshot_cleanup_hook(original, false) {
        hook(original, tombstone);
    }
    #[cfg(not(test))]
    let _ = (original, tombstone);
}

#[cfg(target_os = "linux")]
fn sync_snapshot_cleanup_after_rename(
    state: &SnapshotCleanupState,
    original: &Path,
    tombstone: &Path,
) -> io::Result<()> {
    #[cfg(test)]
    {
        let (hook, fail_sync) = take_snapshot_cleanup_hook(original, true);
        if let Some(hook) = hook {
            hook(original, tombstone);
        }
        if fail_sync {
            return Err(io::Error::other(
                "injected post-rename directory sync failure",
            ));
        }
    }
    #[cfg(not(test))]
    let _ = (original, tombstone);
    state.sync_parent()
}

/// The final identity check is intentionally exposed only in tests.  The
/// callback runs before the authenticated tombstone is captured under its
/// private guard name, making the historical check-to-unlink race causal and
/// deterministic without exposing a production interleaving point.
#[cfg(target_os = "linux")]
fn snapshot_cleanup_after_final_identity_before_unlink(
    original: &Path,
    tombstone: &Path,
    guard: &Path,
) {
    #[cfg(test)]
    if let Some(hook) = snapshot_cleanup_test_hooks()
        .lock()
        .expect("snapshot cleanup test hooks")
        .get_mut(original)
        .and_then(|hooks| hooks.post_final_identity_before_unlink.take())
    {
        hook(tombstone, guard);
    }
    #[cfg(not(test))]
    let _ = (original, tombstone, guard);
}

/// Persist a successful final guard rename before unlinking.  A retry after a
/// crash or a returned error therefore targets this exact bounded guard name,
/// never the original public or tombstone spelling.
#[cfg(target_os = "linux")]
fn sync_snapshot_cleanup_after_unlink_guard_rename(state: &SnapshotCleanupState) -> io::Result<()> {
    state.sync_parent()?;
    #[cfg(test)]
    if snapshot_cleanup_test_hooks()
        .lock()
        .expect("snapshot cleanup test hooks")
        .get_mut(&state.original)
        .is_some_and(|hooks| std::mem::take(&mut hooks.fail_post_unlink_guard_sync))
    {
        return Err(io::Error::other(
            "injected post-unlink-guard directory sync failure",
        ));
    }
    Ok(())
}

/// Build the one bounded final-unlink guard basename.  The source tombstone
/// already has the canonical operation UUID; the fixed-width `(st_dev,
/// st_ino)` suffix binds this second state transition to the exact admitted
/// regular file without adding another retry-generated artifact name.
#[cfg(target_os = "linux")]
fn snapshot_cleanup_unlink_guard_path(
    tombstone: &Path,
    identity: FileIdentity,
) -> io::Result<PathBuf> {
    let parent = tombstone
        .parent()
        .ok_or_else(|| invalid_data("snapshot tombstone has no parent"))?;
    let name = tombstone
        .file_name()
        .ok_or_else(|| invalid_data("snapshot tombstone has no name"))?;
    let mut guard_name = name.to_os_string();
    guard_name.push(format!(
        ".opc-unlink-guard-{:016x}-{:016x}",
        identity.device, identity.inode
    ));
    Ok(parent.join(guard_name))
}

/// Return whether an unlink guard's fixed-width identity suffix authenticates
/// the exact inode currently named by it.  The storage restart scanner first
/// applies its stricter production-name grammar, then calls this helper.
#[cfg(target_os = "linux")]
pub(crate) fn snapshot_cleanup_unlink_guard_name_authenticates_metadata(
    guard_name: &OsStr,
    metadata: &std::fs::Metadata,
) -> io::Result<bool> {
    Ok(metadata.is_file()
        && snapshot_cleanup_unlink_guard_name_authenticates(guard_name, file_identity(metadata)?))
}

#[cfg(target_os = "linux")]
fn snapshot_cleanup_unlink_guard_name_authenticates(
    guard_name: &OsStr,
    identity: FileIdentity,
) -> bool {
    let Some(guard_name) = guard_name.to_str() else {
        return false;
    };
    let Some((_tombstone, encoded_identity)) = guard_name.rsplit_once(".opc-unlink-guard-") else {
        return false;
    };
    let Some((device, inode)) = encoded_identity.split_once('-') else {
        return false;
    };
    parse_fixed_lower_hex_u64(device) == Some(identity.device)
        && parse_fixed_lower_hex_u64(inode) == Some(identity.inode)
}

#[cfg(target_os = "linux")]
fn parse_fixed_lower_hex_u64(token: &str) -> Option<u64> {
    (token.len() == 16
        && token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then(|| u64::from_str_radix(token, 16).ok())
    .flatten()
}

/// Restore a post-rename artifact only into a vacant original name.  This is
/// intentionally `RENAME_NOREPLACE`: an occupant at the original name is
/// foreign, even if it looks like one of our staging names.
#[cfg(target_os = "linux")]
fn restore_snapshot_tombstone(
    state: &mut SnapshotCleanupState,
    tombstone: &Path,
) -> io::Result<()> {
    match state.rename_noreplace(
        tombstone
            .file_name()
            .ok_or_else(|| invalid_data("snapshot tombstone has no name"))?,
        state
            .original
            .file_name()
            .ok_or_else(|| invalid_data("snapshot artifact has no name"))?,
    ) {
        Ok(()) => {
            state.location = SnapshotCleanupLocation::Original;
            state.sync_parent()
        }
        Err(error) => Err(error),
    }
}

/// Restore a rejected final guard only into its exact vacant tombstone name.
/// `RENAME_NOREPLACE` preserves both foreign names if another writer occupied
/// the tombstone while the guard was being authenticated.
#[cfg(target_os = "linux")]
fn restore_snapshot_unlink_guard(
    state: &mut SnapshotCleanupState,
    guard: &Path,
    tombstone: &Path,
) -> io::Result<()> {
    state.rename_noreplace(
        guard
            .file_name()
            .ok_or_else(|| invalid_data("snapshot unlink guard has no name"))?,
        tombstone
            .file_name()
            .ok_or_else(|| invalid_data("snapshot tombstone has no name"))?,
    )?;
    state.location = SnapshotCleanupLocation::Tombstone(tombstone.to_path_buf());
    state.sync_parent()
}

/// Descriptor-authenticated cleanup state machine.  It deliberately holds a
/// tombstone state across directory-sync, reopen, identity and unlink errors;
/// retries can therefore never act on a same-name replacement at `original`.
#[cfg(target_os = "linux")]
fn remove_snapshot_cleanup_if_owned(
    state: &mut SnapshotCleanupState,
    expected: FileIdentity,
) -> io::Result<bool> {
    if matches!(state.location, SnapshotCleanupLocation::Unlinked) {
        state.sync_parent()?;
        return Ok(false);
    }
    let file = match state.open_active() {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // A tombstone can have been removed by a prior successful unlink
            // whose directory sync failed.  Retrying that sync is the only
            // safe recovery action.
            if matches!(
                state.location,
                SnapshotCleanupLocation::Tombstone(_) | SnapshotCleanupLocation::UnlinkGuard { .. }
            ) {
                state.location = SnapshotCleanupLocation::Unlinked;
                state.sync_parent()?;
            }
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || !same_file_object(file_identity(&metadata)?, expected) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "snapshot cleanup path was replaced",
        ));
    }
    let name = state
        .original
        .file_name()
        .ok_or_else(|| invalid_data("snapshot artifact has no name"))?;
    if matches!(state.location, SnapshotCleanupLocation::Original) {
        let parent = state
            .original
            .parent()
            .ok_or_else(|| invalid_data("snapshot artifact has no parent"))?;
        let tombstone = parent.join(format!(
            ".{}.opc-cleanup-{}",
            name.to_string_lossy(),
            uuid::Uuid::new_v4()
        ));
        snapshot_cleanup_before_rename(&state.original, &tombstone);
        state.rename_noreplace(
            name,
            tombstone
                .file_name()
                .ok_or_else(|| invalid_data("snapshot tombstone has no name"))?,
        )?;
        // This assignment is deliberately immediately after rename.  Do not
        // put a fallible operation between them.
        state.location = SnapshotCleanupLocation::Tombstone(tombstone);
    }
    if !matches!(state.location, SnapshotCleanupLocation::UnlinkGuard { .. }) {
        let tombstone = state
            .tombstone_path()
            .expect("rename establishes a tombstone")
            .to_path_buf();
        sync_snapshot_cleanup_after_rename(state, &state.original, &tombstone)?;
        let tombstone_file = state.open_active()?;
        let tombstone_metadata = tombstone_file.metadata()?;
        if !tombstone_metadata.is_file()
            || !same_file_object(file_identity(&tombstone_metadata)?, expected)
        {
            drop(tombstone_file);
            // The precheck-to-rename race may have moved a foreign replacement.
            // Put it back only if the public name remains vacant; otherwise both
            // foreign inodes survive and the guard remains on the tombstone.
            let _ = restore_snapshot_tombstone(state, &tombstone);
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "snapshot cleanup artifact changed during rename",
            ));
        }
        drop(tombstone_file);

        let guard = snapshot_cleanup_unlink_guard_path(&tombstone, expected)?;
        snapshot_cleanup_after_final_identity_before_unlink(&state.original, &tombstone, &guard);
        state.rename_noreplace(
            tombstone
                .file_name()
                .ok_or_else(|| invalid_data("snapshot tombstone has no name"))?,
            guard
                .file_name()
                .ok_or_else(|| invalid_data("snapshot unlink guard has no name"))?,
        )?;
        // No fallible operation may occur between the guard rename and this
        // assignment: replay must never reopen the public/tombstone spelling.
        state.location = SnapshotCleanupLocation::UnlinkGuard {
            guard: guard.clone(),
            tombstone,
        };
        sync_snapshot_cleanup_after_unlink_guard_rename(state)?;

        let guard_file = state.open_active()?;
        let guard_metadata = guard_file.metadata()?;
        if !guard_metadata.is_file() || !same_file_object(file_identity(&guard_metadata)?, expected)
        {
            drop(guard_file);
            let (guard, tombstone) = match &state.location {
                SnapshotCleanupLocation::UnlinkGuard { guard, tombstone } => {
                    (guard.clone(), tombstone.clone())
                }
                _ => unreachable!("guard rename established unlink guard state"),
            };
            let _ = restore_snapshot_unlink_guard(state, &guard, &tombstone);
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "snapshot cleanup artifact changed during final unlink guard rename",
            ));
        }
        drop(guard_file);
    } else {
        // A previous guard rename may have succeeded before its directory sync
        // or unlink.  Do not generate a nested guard; make this exact retained
        // guard durable and replay it in place.
        sync_snapshot_cleanup_after_unlink_guard_rename(state)?;
    }
    drop(file);
    state.unlink_active()?;
    state.location = SnapshotCleanupLocation::Unlinked;
    state.sync_parent()?;
    Ok(true)
}

#[cfg(not(target_os = "linux"))]
fn remove_snapshot_cleanup_if_owned(
    _state: &mut SnapshotCleanupState,
    _expected: FileIdentity,
) -> io::Result<bool> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "snapshot identity-bound cleanup requires Linux",
    ))
}

#[allow(dead_code)]
impl SessionSnapshotFile {
    /// Create a new receiving file. Existing data is never reused.
    pub(crate) async fn create(path: PathBuf) -> io::Result<Self> {
        Self::create_with_cleanup(path, None).await
    }

    /// Create a receiving file whose staging name is removed on every exit.
    ///
    /// A synchronous `Drop` fallback protects cancellation. Its error is
    /// recorded in `cleanup_failed` so the next gated snapshot operation
    /// surfaces it instead of treating artifact cleanup as best effort.
    pub(crate) async fn create_with_cleanup(
        path: PathBuf,
        cleanup_failed: Option<Arc<AtomicBool>>,
    ) -> io::Result<Self> {
        Self::create_with_cleanup_bounded(path, cleanup_failed, u64::MAX, None).await
    }

    /// Create a receiving file with a fixed stream budget and optional
    /// state-machine admission. The budget counts bytes accepted by writes,
    /// before envelope validation is attempted.
    pub(crate) async fn create_with_cleanup_bounded(
        path: PathBuf,
        cleanup_failed: Option<Arc<AtomicBool>>,
        received_maximum: u64,
        receive_admission: Option<tokio::sync::OwnedSemaphorePermit>,
    ) -> io::Result<Self> {
        #[cfg(test)]
        {
            return Self::create_with_cleanup_bounded_inner(
                path,
                cleanup_failed,
                received_maximum,
                receive_admission,
                None,
            )
            .await;
        }
        #[cfg(not(test))]
        {
            Self::create_with_cleanup_bounded_inner(
                path,
                cleanup_failed,
                received_maximum,
                receive_admission,
            )
            .await
        }
    }

    /// Create a receiver staging file through the retained snapshot dirfd.
    /// `path()` remains a descriptor-anchored SQLite/path diagnostic spelling,
    /// while cancellation cleanup uses the namespace capability directly.
    pub(crate) async fn create_with_cleanup_bounded_in_namespace(
        namespace: Arc<RetainedSnapshotDirectory>,
        name: OsString,
        cleanup_failed: Option<Arc<AtomicBool>>,
        received_maximum: u64,
        receive_admission: Option<tokio::sync::OwnedSemaphorePermit>,
    ) -> io::Result<Self> {
        let create_namespace = Arc::clone(&namespace);
        let create_name = name.clone();
        let (file, path, cleanup) = tokio::task::spawn_blocking(move || {
            let file = create_namespace.create_new(&create_name, true)?;
            // This guard is intentionally first after O_EXCL. Metadata,
            // try_clone and cleanup-state setup can all fail with EMFILE.
            let mut emergency = NewNamespaceChildGuard::new(
                Arc::clone(&create_namespace),
                &create_name,
                cleanup_failed.clone(),
            );
            #[cfg(test)]
            if take_namespace_receiver_post_create_setup_failure(&create_namespace) {
                return Err(io::Error::other(
                    "injected retained-namespace receiver post-create setup failure",
                ));
            }
            let identity = file_identity(&file.metadata()?)?;
            let cleanup_pin = file.try_clone()?;
            let cleanup = SnapshotCleanupGuard {
                state: Arc::new(std::sync::Mutex::new(SnapshotCleanupState::in_namespace(
                    Arc::clone(&create_namespace),
                    &create_name,
                )?)),
                identity,
                _pin: cleanup_pin,
                armed: true,
                cleanup_failed: cleanup_failed.clone(),
            };
            // From this point the identity-pinned cleanup guard owns the
            // name through all later sync/proc-path failures.
            emergency.disarm();
            #[cfg(test)]
            if take_namespace_receiver_post_create_sync_failure(&create_namespace) {
                return Err(io::Error::other(
                    "injected retained-namespace receiver post-create sync failure",
                ));
            }
            create_namespace.sync()?;
            let path = create_namespace.sqlite_child_path(&create_name)?;
            Ok::<_, io::Error>((file, path, cleanup))
        })
        .await
        .map_err(|_| io::Error::other("snapshot receiver create worker failed"))??;
        let mut snapshot = Self::from_file(tokio::fs::File::from_std(file), path).await?;
        snapshot.cleanup = Some(cleanup);
        snapshot.received_maximum = received_maximum;
        snapshot._receive_admission = receive_admission;
        snapshot.receiving = true;
        Ok(snapshot)
    }

    async fn create_with_cleanup_bounded_inner(
        path: PathBuf,
        cleanup_failed: Option<Arc<AtomicBool>>,
        received_maximum: u64,
        receive_admission: Option<tokio::sync::OwnedSemaphorePermit>,
        #[cfg(test)] after_create: Option<&SnapshotArtifactGate>,
    ) -> io::Result<Self> {
        reject_symlink(&path).await?;
        let (file, mut cleanup) = create_new_snapshot_file(&path)?;
        sync_snapshot_parent_directory(&path)?;
        #[cfg(test)]
        if let Some(after_create) = after_create {
            after_create.block_if_armed().await;
        }
        let identity = file_identity(&file.metadata()?)?;
        let cleanup_pin = file.try_clone()?;
        let mut snapshot = Self::from_file(tokio::fs::File::from_std(file), path).await?;
        cleanup.disarm();
        snapshot.cleanup = Some(SnapshotCleanupGuard {
            state: Arc::new(std::sync::Mutex::new(SnapshotCleanupState::new(
                snapshot.path.clone(),
            ))),
            identity,
            _pin: cleanup_pin,
            armed: true,
            cleanup_failed,
        });
        snapshot.received_maximum = received_maximum;
        snapshot._receive_admission = receive_admission;
        snapshot.receiving = true;
        Ok(snapshot)
    }

    /// Open an immutable current snapshot for transfer.
    pub(crate) async fn open(path: PathBuf) -> io::Result<Self> {
        reject_symlink(&path).await?;
        let file = snapshot_open_options(false, true, false)
            .open(&path)
            .await?;
        Self::from_file(file, path).await
    }

    /// Attach a diagnostic path to an already-open regular snapshot handle.
    pub(crate) async fn from_file(file: tokio::fs::File, path: PathBuf) -> io::Result<Self> {
        let metadata = file.metadata().await?;
        ensure_regular_file(&metadata)?;
        Ok(Self {
            file,
            path,
            cleanup: None,
            received_bytes: 0,
            received_maximum: u64::MAX,
            cursor: 0,
            extent: metadata.len(),
            receiving: false,
            receive_limit_exceeded: false,
            _receive_admission: None,
            _namespace_lease: None,
            seek_in_flight: false,
            replay: None,
            io_poisoned: false,
        })
    }

    /// Convert an already-open standard file without resolving its path again.
    pub(crate) async fn from_std(file: std::fs::File, path: PathBuf) -> io::Result<Self> {
        Self::from_file(tokio::fs::File::from_std(file), path).await
    }

    /// SDK-controlled path associated with this handle.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Keep a caller-owned namespace admission alive for the lifetime of a
    /// mutable receiving descriptor.  This must be attached only after the
    /// descriptor was created successfully, so a failed create has no guard
    /// to clean up or latch.
    pub(crate) fn retain_namespace_lease<T>(&mut self, lease: Arc<T>)
    where
        T: Send + Sync + 'static,
    {
        self._namespace_lease = Some(lease);
    }

    /// Borrow the held Tokio file without reopening its path.
    pub(crate) fn file(&self) -> io::Result<&tokio::fs::File> {
        self.receiving_file_access().map(|()| &self.file)
    }

    /// Mutably borrow the held Tokio file without reopening its path.
    pub(crate) fn file_mut(&mut self) -> io::Result<&mut tokio::fs::File> {
        self.receiving_file_access().map(|()| &mut self.file)
    }

    /// Clone the held file handle without resolving its path again.
    pub(crate) async fn try_clone(&self) -> io::Result<Self> {
        if self._receive_admission.is_some() || self.receiving {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "snapshot receiver cannot be cloned",
            ));
        }
        let mut cloned = Self::from_file(self.file.try_clone().await?, self.path.clone()).await?;
        cloned.received_bytes = self.received_bytes;
        cloned.received_maximum = self.received_maximum;
        cloned.cursor = self.cursor;
        cloned.extent = self.extent;
        cloned.receiving = self.receiving;
        cloned.receive_limit_exceeded = self.receive_limit_exceeded;
        Ok(cloned)
    }

    /// Close a receiving file and synchronously observe removal of its
    /// staging name. Immutable published snapshots never opt into removal.
    pub(crate) async fn close_and_cleanup(mut self) -> io::Result<()> {
        match self.cleanup.as_mut() {
            Some(cleanup) => cleanup.remove().await,
            None => Ok(()),
        }
    }

    /// Consume the wrapper and return the already-open Tokio file.
    pub(crate) fn into_file(self) -> io::Result<tokio::fs::File> {
        self.receiving_file_access()?;
        Ok(self.file)
    }

    /// Consume the wrapper and return the already-open standard file.
    pub(crate) async fn into_std(self) -> io::Result<std::fs::File> {
        self.receiving_file_access()?;
        Ok(self.file.into_std().await)
    }

    /// Read metadata from the held handle rather than resolving its path.
    pub(crate) async fn metadata(&self) -> io::Result<std::fs::Metadata> {
        self.file.metadata().await
    }

    /// Seek the held file back to its first byte.
    pub(crate) async fn rewind(&mut self) -> io::Result<()> {
        self.seek(io::SeekFrom::Start(0)).await.map(|_| ())
    }

    /// Flush both file content and metadata before promotion.
    pub(crate) async fn sync_all(&mut self) -> io::Result<()> {
        self.flush().await?;
        match self.file.sync_all().await {
            Ok(()) => Ok(()),
            Err(error) => {
                self.poison();
                Err(error)
            }
        }
    }

    fn receiving_file_access(&self) -> io::Result<()> {
        if self._receive_admission.is_some() {
            Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "snapshot receiver is private",
            ))
        } else {
            Ok(())
        }
    }

    fn receive_limit_error(&mut self, message: &'static str) -> io::Error {
        self.receive_limit_exceeded = true;
        io::Error::new(io::ErrorKind::InvalidData, message)
    }

    fn poisoned_error(&self) -> io::Error {
        io::Error::other("snapshot receiver I/O state is uncertain")
    }

    fn poison(&mut self) {
        self.io_poisoned = true;
    }

    fn begin_seek_correction(&mut self, position: u64) -> io::Result<()> {
        if self.seek_in_flight {
            return Err(io::Error::other(
                "snapshot seek correction is already in progress",
            ));
        }
        Pin::new(&mut self.file).start_seek(io::SeekFrom::Start(position))?;
        self.seek_in_flight = true;
        Ok(())
    }

    /// Drain a pending replay read without accepting its caller-owned input,
    /// then restore the file cursor to the unverified replay start.
    fn poll_cancel_replay(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(mut replay) = self.as_mut().get_mut().replay.take() else {
            return Poll::Ready(Ok(()));
        };
        let start = replay.start;
        let mut read_buf = ReadBuf::new(&mut replay.expected);
        match Pin::new(&mut self.as_mut().get_mut().file).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                if let Err(error) = self.as_mut().get_mut().begin_seek_correction(start) {
                    self.as_mut().get_mut().poison();
                    return Poll::Ready(Err(error));
                }
                self.poll_complete_submitted_seek(cx)
            }
            Poll::Ready(Err(error)) => {
                self.as_mut().get_mut().poison();
                Poll::Ready(Err(error))
            }
            Poll::Pending => {
                self.as_mut().get_mut().replay = Some(replay);
                Poll::Pending
            }
        }
    }

    /// Reconcile a cancelled replay and any submitted seek before an action
    /// that does not itself continue the receiver write.
    fn poll_reconcile_before_other_action(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if self.as_ref().get_ref().io_poisoned {
            return Poll::Ready(Err(self.as_ref().get_ref().poisoned_error()));
        }
        match self.as_mut().poll_cancel_replay(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        self.poll_complete_submitted_seek(cx)
    }

    /// Compare one bounded overlap block with already accepted receiver data.
    /// A successful comparison is reported as a short successful write, so a
    /// caller such as `write_all` naturally continues with the missing suffix.
    fn poll_verify_replay(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.as_ref().get_ref().io_poisoned {
            return Poll::Ready(Err(self.as_ref().get_ref().poisoned_error()));
        }
        if self.as_ref().get_ref().replay.is_none() {
            let this = self.as_mut().get_mut();
            let overlap = this.extent.saturating_sub(this.cursor);
            let block = overlap
                .min(u64::try_from(buf.len()).unwrap_or(u64::MAX))
                .min(SNAPSHOT_REPLAY_VERIFY_BYTES as u64) as usize;
            if block == 0 {
                this.poison();
                return Poll::Ready(Err(io::Error::other(
                    "snapshot receiver replay block is empty",
                )));
            }
            this.replay = Some(SnapshotReplayRead {
                start: this.cursor,
                expected: vec![0; block],
            });
        }

        let Some(mut replay) = self.as_mut().get_mut().replay.take() else {
            self.as_mut().get_mut().poison();
            return Poll::Ready(Err(io::Error::other(
                "snapshot receiver replay state is absent",
            )));
        };
        let start = replay.start;
        let mut read_buf = ReadBuf::new(&mut replay.expected);
        match Pin::new(&mut self.as_mut().get_mut().file).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let read = read_buf.filled().len();
                if read == 0 {
                    self.as_mut().get_mut().poison();
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "snapshot receiver replay reached an unexpected end of file",
                    )));
                }
                if buf.len() < read {
                    if let Err(error) = self.as_mut().get_mut().begin_seek_correction(start) {
                        self.as_mut().get_mut().poison();
                        return Poll::Ready(Err(error));
                    }
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "snapshot receiver replay buffer changed while pending",
                    )));
                }
                if replay.expected[..read] != buf[..read] {
                    if let Err(error) = self.as_mut().get_mut().begin_seek_correction(start) {
                        self.as_mut().get_mut().poison();
                        return Poll::Ready(Err(error));
                    }
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "snapshot receiver replay does not match accepted bytes",
                    )));
                }
                self.as_mut().get_mut().cursor = start.saturating_add(read as u64);
                Poll::Ready(Ok(read))
            }
            Poll::Ready(Err(error)) => {
                self.as_mut().get_mut().poison();
                Poll::Ready(Err(error))
            }
            Poll::Pending => {
                self.as_mut().get_mut().replay = Some(replay);
                Poll::Pending
            }
        }
    }

    fn poll_complete_submitted_seek(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.seek_in_flight {
            return Poll::Ready(Ok(()));
        }
        match self.as_mut().poll_complete(cx) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) => {
                self.as_mut().get_mut().poison();
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

fn ensure_regular_file(metadata: &std::fs::Metadata) -> io::Result<()> {
    if metadata.is_file() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "snapshot file must be a regular file",
        ))
    }
}

#[cfg(target_os = "linux")]
fn linux_file_change_time(metadata: &std::fs::Metadata) -> LinuxFileChangeTime {
    LinuxFileChangeTime {
        seconds: metadata.st_ctime(),
        nanoseconds: metadata.st_ctime_nsec(),
    }
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
fn file_identity(metadata: &std::fs::Metadata) -> io::Result<FileIdentity> {
    Ok(FileIdentity {
        device: metadata.st_dev(),
        inode: metadata.st_ino(),
    })
}

#[cfg(target_os = "linux")]
fn same_file_object(left: FileIdentity, right: FileIdentity) -> bool {
    left.device == right.device && left.inode == right.inode
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
fn file_identity(_metadata: &std::fs::Metadata) -> io::Result<FileIdentity> {
    Ok(FileIdentity)
}

fn snapshot_open_options(create_new: bool, read: bool, write: bool) -> tokio::fs::OpenOptions {
    let mut options = tokio::fs::OpenOptions::new();
    options.create_new(create_new).read(read).write(write);
    #[cfg(unix)]
    {
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    options
}

fn create_new_snapshot_file(
    path: &Path,
) -> io::Result<(std::fs::File, UnpublishedSnapshotArtifact)> {
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let cleanup = UnpublishedSnapshotArtifact::from_file(&file, path.to_path_buf(), false)?;
    Ok((file, cleanup))
}

async fn reject_symlink(path: &Path) -> io::Result<()> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "snapshot path must not be a symbolic link",
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

impl fmt::Debug for SessionSnapshotFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionSnapshotFile(<redacted>)")
    }
}

impl AsyncRead for SessionSnapshotFile {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.as_mut().poll_reconcile_before_other_action(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        if self.as_ref().get_ref().receiving {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "snapshot receiver is not sealed for reading",
            )));
        }
        Pin::new(&mut self.file).poll_read(cx, buf)
    }
}

impl AsyncWrite for SessionSnapshotFile {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match self.as_mut().poll_complete_submitted_seek(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        if self.as_ref().get_ref().io_poisoned {
            return Poll::Ready(Err(self.as_ref().get_ref().poisoned_error()));
        }
        if !self.as_ref().get_ref().receiving {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snapshot file is not receiving",
            )));
        }
        if self.receive_limit_exceeded {
            return Poll::Ready(Err(self.receive_limit_error(
                "snapshot receiver size limit was previously exceeded",
            )));
        }
        let requested = match u64::try_from(buf.len()) {
            Ok(requested) => requested,
            Err(_) => {
                return Poll::Ready(Err(
                    self.receive_limit_error("snapshot write length is invalid")
                ));
            }
        };
        let Some(end) = self.cursor.checked_add(requested) else {
            return Poll::Ready(Err(
                self.receive_limit_error("snapshot stream exceeds size limit")
            ));
        };
        if end > self.received_maximum {
            return Poll::Ready(Err(
                self.receive_limit_error("snapshot stream exceeds size limit")
            ));
        }
        if self.cursor > self.extent {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snapshot receiver cannot write a sparse range",
            )));
        }
        if !buf.is_empty() && self.cursor < self.extent {
            return self.as_mut().poll_verify_replay(cx, buf);
        }
        match Pin::new(&mut self.file).poll_write(cx, buf) {
            Poll::Ready(Ok(written)) => {
                self.received_bytes = self.received_bytes.saturating_add(written as u64);
                self.cursor = self.cursor.saturating_add(written as u64);
                self.extent = self.extent.max(self.cursor);
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(error)) => {
                self.poison();
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match self.as_mut().poll_reconcile_before_other_action(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        match Pin::new(&mut self.file).poll_flush(cx) {
            Poll::Ready(Err(error)) => {
                self.as_mut().get_mut().poison();
                Poll::Ready(Err(error))
            }
            outcome => outcome,
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        match self.as_mut().poll_reconcile_before_other_action(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        match Pin::new(&mut self.file).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => {
                self.as_mut().get_mut().receiving = false;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                self.as_mut().get_mut().poison();
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncSeek for SessionSnapshotFile {
    fn start_seek(mut self: Pin<&mut Self>, position: io::SeekFrom) -> io::Result<()> {
        if self.seek_in_flight {
            return Err(io::Error::other("snapshot seek is already in progress"));
        }
        if self.replay.is_some() {
            return Err(io::Error::other(
                "snapshot replay must complete before another seek",
            ));
        }
        if self.io_poisoned {
            return Err(self.poisoned_error());
        }
        if self.receive_limit_exceeded {
            return Err(
                self.receive_limit_error("snapshot receiver size limit was previously exceeded")
            );
        }
        let target = match position {
            io::SeekFrom::Start(offset) => Some(offset),
            io::SeekFrom::Current(offset) => self.cursor.checked_add_signed(offset),
            io::SeekFrom::End(offset) => self.extent.checked_add_signed(offset),
        }
        .ok_or_else(|| self.receive_limit_error("snapshot seek is invalid"))?;
        if self.receiving && target > self.extent {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snapshot receiver cannot seek beyond accepted bytes",
            ));
        }
        if target > self.received_maximum {
            return Err(self.receive_limit_error("snapshot seek exceeds size limit"));
        }
        Pin::new(&mut self.file).start_seek(io::SeekFrom::Start(target))?;
        self.seek_in_flight = true;
        Ok(())
    }

    fn poll_complete(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        match Pin::new(&mut self.file).poll_complete(cx) {
            Poll::Ready(Ok(position)) if position <= self.received_maximum => {
                self.cursor = position;
                self.seek_in_flight = false;
                Poll::Ready(Ok(position))
            }
            Poll::Ready(Ok(_)) => {
                self.seek_in_flight = false;
                Poll::Ready(Err(
                    self.receive_limit_error("snapshot seek exceeds size limit")
                ))
            }
            Poll::Ready(Err(error)) => {
                self.seek_in_flight = false;
                self.poison();
                Poll::Ready(Err(error))
            }
            pending => pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    #[cfg(target_os = "linux")]
    use std::io::{Read as _, Write as _};
    use std::pin::Pin;
    use std::sync::Arc;

    #[cfg(not(target_os = "linux"))]
    use super::PinnedSqliteFile;
    #[cfg(target_os = "linux")]
    use super::{fs_verity_enable_error, PinnedSqliteFile, UnpublishedSnapshotArtifact};
    use super::{
        snapshot_cleanup_test_hooks, SessionSnapshotFile, SnapshotArtifactGate,
        SnapshotCleanupTestHooks, SnapshotReplayRead, SNAPSHOT_DATABASE_MAX_BYTES,
        SNAPSHOT_ENVELOPE_FOOTER_BYTES, SNAPSHOT_ENVELOPE_MAX_BYTES, SNAPSHOT_MAX_BACKUP_PAGES,
        SNAPSHOT_MAX_BYTES, SNAPSHOT_MIN_PAGE_BYTES,
    };
    use crate::fenced_mutation_roster::{
        MAX_ADMISSION_CODEC_BYTES, MAX_BUSINESS_SESSION_HEADER_BYTES, MAX_CHECKPOINT_BYTES,
        MAX_COMMITTED_TERMINAL_CODEC_BYTES, MAX_EXECUTOR_PROOF_BUNDLE_BYTES, MAX_LIVE_ROSTERS,
        MAX_RESERVED_AND_RETAINED, MAX_ROSTER_COMPACT_ADMISSION_PROVENANCE_BYTES,
        MAX_ROSTER_COMPACT_TERMINAL_EVIDENCE_BYTES, MAX_ROSTER_INGRESS_ATTESTATION_BYTES,
        MAX_TOMBSTONE_CODEC_BYTES, PROTECTED_ROSTER_LOGICAL_BUDGET_BYTES,
    };
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt as _, AsyncSeek as _, AsyncSeekExt as _, AsyncWriteExt as _};

    #[test]
    fn physical_snapshot_ceiling_covers_the_frozen_roster_ledger_without_overflow() {
        // One canonical row contains the bounded admission (including plan
        // and member descriptors), terminal/result, tombstone, provenance,
        // proof/evidence, ingress, and reserved authoritative business body.
        // The SQL primary-key/index values are small next to this body and the
        // common page cap below remains the final authority for all SQLite
        // pages, including arbitrary non-roster tables.
        let maximum_canonical_row = u64::try_from(
            MAX_ADMISSION_CODEC_BYTES
                + MAX_COMMITTED_TERMINAL_CODEC_BYTES
                + MAX_TOMBSTONE_CODEC_BYTES
                + MAX_ROSTER_COMPACT_ADMISSION_PROVENANCE_BYTES
                + MAX_ROSTER_COMPACT_TERMINAL_EVIDENCE_BYTES
                + MAX_EXECUTOR_PROOF_BUNDLE_BYTES
                + 2 * MAX_ROSTER_INGRESS_ATTESTATION_BYTES
                + MAX_CHECKPOINT_BYTES
                + MAX_BUSINESS_SESSION_HEADER_BYTES
                + 512,
        )
        .expect("frozen canonical-row bound fits u64");
        let maximum_canonical_ledger = maximum_canonical_row
            .checked_mul(MAX_RESERVED_AND_RETAINED as u64)
            .expect("frozen canonical ledger fits u64");
        let maximum_live_business_rows =
            u64::try_from(MAX_CHECKPOINT_BYTES + MAX_BUSINESS_SESSION_HEADER_BYTES)
                .expect("frozen business-row bound fits u64")
                .checked_mul(MAX_LIVE_ROSTERS as u64)
                .expect("frozen business rows fit u64");
        let roster_row_values = 120_u64 + 64 + 16;
        let history_floor_values = 64_u64 + 128;
        let retirement_cursor_values = 64_u64 + 256;
        let admission_values = 120_u64 + 32 + 16 + 16 + 128 + 30 + 30 + 4 * 8;
        let roster_side_values = (roster_row_values
            + history_floor_values
            + retirement_cursor_values
            + admission_values)
            .checked_mul(MAX_RESERVED_AND_RETAINED as u64)
            .and_then(|values| values.checked_add(maximum_live_business_rows))
            .and_then(|values| values.checked_add(1_024))
            .expect("frozen roster side values fit u64");
        assert_eq!(
            SNAPSHOT_DATABASE_MAX_BYTES,
            PROTECTED_ROSTER_LOGICAL_BUDGET_BYTES * 4 - SNAPSHOT_MIN_PAGE_BYTES
        );
        assert_eq!(
            SNAPSHOT_DATABASE_MAX_BYTES,
            SNAPSHOT_MAX_BACKUP_PAGES * SNAPSHOT_MIN_PAGE_BYTES
        );
        assert_eq!(SNAPSHOT_MAX_BYTES, SNAPSHOT_DATABASE_MAX_BYTES);
        assert_eq!(
            SNAPSHOT_ENVELOPE_MAX_BYTES,
            SNAPSHOT_DATABASE_MAX_BYTES + SNAPSHOT_ENVELOPE_FOOTER_BYTES
        );
        let maximum_roster_sqlite_content = maximum_canonical_ledger
            .checked_add(roster_side_values)
            .expect("frozen roster SQLite content fits u64");
        let sqlite_page_index_and_freelist_slack = SNAPSHOT_DATABASE_MAX_BYTES
            .checked_sub(maximum_roster_sqlite_content)
            .expect("the full frozen roster field envelope fits the physical page cap");
        // The field envelope above intentionally permits every row to take
        // every individual maximum even where the authenticated 256 GiB
        // logical witness would reject that combination. The remaining
        // physical slack is therefore available for SQLite pages, table and
        // index cells, schema, freelist, and any bounded non-roster contents
        // that share this database under the same max-page policy.
        assert!(
            sqlite_page_index_and_freelist_slack >= PROTECTED_ROSTER_LOGICAL_BUDGET_BYTES,
            "the physical cap leaves an additional logical-ledger-sized SQLite-layout slack"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unpublished_sqlite_cleanup_removes_only_its_created_identity(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("build.sqlite");
        let created = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)?;
        let owned = PinnedSqliteFile::from_new_file(created, path.clone())?;
        drop(owned);
        assert!(!path.exists());

        let created = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)?;
        let owned = PinnedSqliteFile::from_new_file(created, path.clone())?;
        let replacement = directory.path().join("replacement.sqlite");
        std::fs::write(&replacement, b"replacement")?;
        std::fs::rename(&replacement, &path)?;
        drop(owned);
        assert_eq!(std::fs::read(&path)?, b"replacement");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unpublished_sqlite_cleanup_fences_each_created_sidecar_identity(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("build.sqlite");
        let created = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)?;
        let mut owned = PinnedSqliteFile::from_new_file(created, path.clone())?;
        let wal = directory.path().join("build.sqlite-wal");
        let shm = directory.path().join("build.sqlite-shm");
        std::fs::write(&wal, b"owned wal")?;
        std::fs::write(&shm, b"owned shm")?;
        owned.capture_created_sidecars();

        let replacement = directory.path().join("replacement-wal");
        std::fs::write(&replacement, b"foreign replacement")?;
        std::fs::rename(&replacement, &wal)?;
        drop(owned);

        assert!(!path.exists());
        assert!(!shm.exists());
        assert_eq!(std::fs::read(wal)?, b"foreign replacement");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unpublished_snapshot_cleanup_tracks_atomic_promotion_and_publication(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let temporary = directory.path().join("seal.part");
        let published = directory.path().join("snapshot.opc");
        let created = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&temporary)?;
        let mut cleanup =
            UnpublishedSnapshotArtifact::from_file(&created, temporary.clone(), false)?;
        std::fs::rename(&temporary, &published)?;
        cleanup.rebind_path(published.clone());
        drop(cleanup);
        assert!(!published.exists());

        let created = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&temporary)?;
        let mut cleanup =
            UnpublishedSnapshotArtifact::from_file(&created, temporary.clone(), false)?;
        std::fs::rename(&temporary, &published)?;
        cleanup.rebind_path(published.clone());
        cleanup.disarm();
        drop(cleanup);
        assert!(published.exists());
        Ok(())
    }

    #[tokio::test]
    async fn create_new_rejects_an_existing_file() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("snapshot");
        let _snapshot = SessionSnapshotFile::create(path.clone()).await?;

        let error = SessionSnapshotFile::create(path)
            .await
            .err()
            .ok_or("create succeeded")?;
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        Ok(())
    }

    #[tokio::test]
    async fn receiving_snapshot_rewind_rejects_changed_overlapping_bytes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("incoming.part");
        let original = b"original snapshot";
        let mut snapshot = SessionSnapshotFile::create(path.clone()).await?;
        snapshot.write_all(original).await?;
        snapshot.sync_all().await?;
        snapshot.rewind().await?;

        let error = snapshot
            .write_all(b"overwritten bytes")
            .await
            .err()
            .ok_or("rewound receive accepted an overwrite")?;
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        snapshot.sync_all().await?;
        assert_eq!(snapshot.metadata().await?.len(), original.len() as u64);
        assert_eq!(std::fs::read(path)?, original);
        Ok(())
    }

    #[tokio::test]
    async fn receiving_snapshot_cancelled_seek_rejects_changed_overlapping_bytes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("incoming.part");
        let original = b"original snapshot";
        let mut snapshot = SessionSnapshotFile::create(path.clone()).await?;
        snapshot.write_all(original).await?;
        snapshot.sync_all().await?;
        Pin::new(&mut snapshot).start_seek(io::SeekFrom::Start(0))?;

        let error = snapshot
            .write_all(b"overwritten bytes")
            .await
            .err()
            .ok_or("cancelled receive seek accepted an overwrite")?;
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        snapshot.sync_all().await?;
        assert_eq!(snapshot.metadata().await?.len(), original.len() as u64);
        assert_eq!(std::fs::read(path)?, original);
        Ok(())
    }

    #[tokio::test]
    async fn receiving_snapshot_exact_rewind_retry_keeps_bytes_and_length(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("incoming.part");
        let original = b"exact snapshot retry";
        let mut snapshot = SessionSnapshotFile::create_with_cleanup_bounded(
            path.clone(),
            None,
            original.len() as u64,
            None,
        )
        .await?;
        snapshot.write_all(original).await?;
        snapshot.sync_all().await?;
        snapshot.rewind().await?;

        snapshot.write_all(original).await?;
        snapshot.sync_all().await?;

        assert_eq!(snapshot.received_bytes, original.len() as u64);
        assert_eq!(snapshot.metadata().await?.len(), original.len() as u64);
        assert_eq!(std::fs::read(path)?, original);
        Ok(())
    }

    #[tokio::test]
    async fn receiving_snapshot_partial_exact_overlap_appends_only_missing_suffix(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("incoming.part");
        let mut snapshot = SessionSnapshotFile::create(path.clone()).await?;
        snapshot.write_all(b"abcdef").await?;
        snapshot.seek(io::SeekFrom::Start(3)).await?;

        snapshot.write_all(b"defghi").await?;
        snapshot.sync_all().await?;

        assert_eq!(snapshot.metadata().await?.len(), 9);
        assert_eq!(std::fs::read(path)?, b"abcdefghi");
        Ok(())
    }

    #[tokio::test]
    async fn receiving_snapshot_is_readable_only_after_exact_shutdown(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("incoming.part");
        let original = b"authenticated snapshot stream";
        let mut snapshot = SessionSnapshotFile::create(path).await?;
        snapshot.write_all(original).await?;
        snapshot.rewind().await?;

        let mut observed = Vec::new();
        let error = snapshot
            .read_to_end(&mut observed)
            .await
            .err()
            .ok_or("active receiver allowed a read")?;
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        snapshot.shutdown().await?;
        snapshot.rewind().await?;
        snapshot.read_to_end(&mut observed).await?;
        assert_eq!(observed, original);
        Ok(())
    }

    #[tokio::test]
    async fn cancelled_replay_and_submitted_seek_preserve_receiver_exactness(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("incoming.part");
        let original = b"abcdef";
        let mut snapshot = SessionSnapshotFile::create(path.clone()).await?;
        snapshot.write_all(original).await?;
        snapshot.sync_all().await?;
        snapshot.rewind().await?;

        snapshot.replay = Some(SnapshotReplayRead {
            start: 0,
            expected: vec![0; original.len()],
        });
        snapshot.flush().await?;
        Pin::new(&mut snapshot).start_seek(io::SeekFrom::Start(0))?;
        snapshot.write_all(original).await?;
        snapshot.sync_all().await?;

        assert_eq!(snapshot.metadata().await?.len(), original.len() as u64);
        assert_eq!(std::fs::read(path)?, original);
        Ok(())
    }

    #[tokio::test]
    async fn cancellation_immediately_after_receive_create_cleans_the_exact_artifact(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("incoming-cancelled.part");
        let gate = Arc::new(SnapshotArtifactGate::new());
        gate.arm();
        let task_path = path.clone();
        let task_gate = Arc::clone(&gate);
        let task = tokio::spawn(async move {
            let _snapshot = SessionSnapshotFile::create_with_cleanup_bounded_inner(
                task_path,
                None,
                u64::MAX,
                None,
                Some(task_gate.as_ref()),
            )
            .await?;
            Ok::<(), io::Error>(())
        });

        gate.wait_started().await;
        assert!(path.is_file(), "the created receive artifact is observable");
        task.abort();
        assert!(task
            .await
            .expect_err("receive task is cancelled")
            .is_cancelled());
        assert!(
            !path.exists(),
            "cancellation after create must clean the exact receive artifact"
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn abandoned_receive_cleanup_never_unlinks_a_same_name_replacement(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("incoming.part");
        let receiving = SessionSnapshotFile::create(path.clone()).await?;
        let replacement = directory.path().join("replacement.part");
        std::fs::write(&replacement, b"replacement")?;
        std::fs::rename(&replacement, &path)?;
        drop(receiving);
        assert_eq!(std::fs::read(path)?, b"replacement");
        Ok(())
    }

    #[tokio::test]
    async fn explicit_snapshot_cleanup_retries_its_exact_tombstone_after_sync_failure(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let _hook_lock = super::snapshot_cleanup_test_lock().lock().await;
        let directory = tempdir()?;
        let path = directory.path().join("incoming.part");
        let mut snapshot = SessionSnapshotFile::create(path.clone()).await?;
        {
            let mut hooks = snapshot_cleanup_test_hooks()
                .lock()
                .expect("install cleanup hook");
            hooks.insert(
                path.clone(),
                SnapshotCleanupTestHooks {
                    fail_post_rename_sync: true,
                    ..SnapshotCleanupTestHooks::default()
                },
            );
        }
        let cleanup = snapshot.cleanup.as_mut().expect("cleanup guard");
        assert!(
            cleanup.remove().await.is_err(),
            "injected sync failure surfaces"
        );
        assert!(!path.exists(), "public path remains vacant after rename");
        let tombstone = std::fs::read_dir(directory.path())?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .next()
            .expect("exact tombstone retained");
        assert!(tombstone
            .file_name()
            .is_some_and(|name| name.to_string_lossy().contains(".opc-cleanup-")));
        cleanup.remove().await?;
        assert!(std::fs::read_dir(directory.path())?.next().is_none());
        drop(snapshot);
        Ok(())
    }

    #[tokio::test]
    async fn dropped_snapshot_cleanup_retries_tombstone_without_touching_public_replacement(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let _hook_lock = super::snapshot_cleanup_test_lock().lock().await;
        let directory = tempdir()?;
        let path = directory.path().join("incoming.part");
        let mut snapshot = SessionSnapshotFile::create(path.clone()).await?;
        {
            let mut hooks = snapshot_cleanup_test_hooks()
                .lock()
                .expect("install cleanup hook");
            hooks.insert(
                path.clone(),
                SnapshotCleanupTestHooks {
                    fail_post_rename_sync: true,
                    ..SnapshotCleanupTestHooks::default()
                },
            );
        }

        assert!(
            snapshot
                .cleanup
                .as_mut()
                .expect("cleanup guard")
                .remove()
                .await
                .is_err(),
            "the injected post-rename durability failure leaves the guard armed"
        );
        assert!(!path.exists(), "rename leaves the public name vacant");
        std::fs::write(&path, b"foreign-public-replacement")?;

        // `Drop` is the retry path reached after a cancelled caller. It must
        // continue from the exact tombstone state rather than reopening this
        // now-occupied public spelling.
        drop(snapshot);
        assert_eq!(std::fs::read(&path)?, b"foreign-public-replacement");
        assert_eq!(
            1,
            std::fs::read_dir(directory.path())?.count(),
            "only the foreign public replacement survives the tombstone retry"
        );
        Ok(())
    }

    #[tokio::test]
    async fn dropped_snapshot_cleanup_restores_pre_rename_foreign_replacement(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let _hook_lock = super::snapshot_cleanup_test_lock().lock().await;
        let directory = tempdir()?;
        let path = directory.path().join("incoming.part");
        let snapshot = SessionSnapshotFile::create(path.clone()).await?;
        snapshot_cleanup_test_hooks()
            .lock()
            .expect("install cleanup hook")
            .entry(path.clone())
            .or_default()
            .before_rename = Some(Box::new(|original, _tombstone| {
            let replacement = original.with_extension("foreign");
            std::fs::write(&replacement, b"foreign-before-rename").expect("foreign bytes");
            std::fs::rename(&replacement, original).expect("replace original");
        }));
        drop(snapshot);
        assert_eq!(std::fs::read(&path)?, b"foreign-before-rename");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn final_identity_unlink_seam_preserves_replacement_and_unrelated_child(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let _hook_lock = super::snapshot_cleanup_test_lock().lock().await;
        let directory = tempdir()?;
        let path = directory.path().join("incoming.part");
        let unrelated = directory.path().join("unrelated-survivor");
        std::fs::write(&unrelated, b"unrelated")?;
        let mut snapshot = SessionSnapshotFile::create(path.clone()).await?;
        snapshot_cleanup_test_hooks()
            .lock()
            .expect("install final identity seam hook")
            .entry(path.clone())
            .or_default()
            .post_final_identity_before_unlink = Some(Box::new(|tombstone, _guard| {
            std::fs::remove_file(tombstone).expect("remove authenticated tombstone");
            std::fs::write(tombstone, b"foreign-final-seam")
                .expect("replace tombstone at final identity seam");
        }));

        assert!(
            snapshot
                .cleanup
                .as_mut()
                .expect("cleanup guard")
                .remove()
                .await
                .is_err(),
            "a replacement after final identity must fail closed"
        );
        assert!(
            !path.exists(),
            "the public name remains vacant after cleanup rename"
        );
        let foreign = std::fs::read_dir(directory.path())?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|entry| entry != &unrelated)
            .expect("foreign replacement survives under its tombstone name");
        assert_eq!(std::fs::read(&foreign)?, b"foreign-final-seam");
        assert_eq!(std::fs::read(&unrelated)?, b"unrelated");

        // Drop replays the retained tombstone state but cannot re-authorize
        // either foreign inode.
        drop(snapshot);
        assert_eq!(std::fs::read(&foreign)?, b"foreign-final-seam");
        assert_eq!(std::fs::read(&unrelated)?, b"unrelated");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn post_unlink_guard_failure_replays_the_exact_guard_without_nesting(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let _hook_lock = super::snapshot_cleanup_test_lock().lock().await;
        let directory = tempdir()?;
        let path = directory.path().join("incoming.part");
        let mut snapshot = SessionSnapshotFile::create(path.clone()).await?;
        snapshot_cleanup_test_hooks()
            .lock()
            .expect("install final guard failure")
            .entry(path.clone())
            .or_default()
            .fail_post_unlink_guard_sync = true;

        let cleanup = snapshot.cleanup.as_mut().expect("cleanup guard");
        assert!(
            cleanup.remove().await.is_err(),
            "a failure after durable guard rename remains replayable"
        );
        let guards = std::fs::read_dir(directory.path())?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|entry| {
                entry
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().contains(".opc-unlink-guard-"))
            })
            .collect::<Vec<_>>();
        assert_eq!(guards.len(), 1, "one exact final guard is retained");
        assert_eq!(
            guards[0]
                .file_name()
                .expect("guard basename")
                .to_string_lossy()
                .matches(".opc-unlink-guard-")
                .count(),
            1,
            "replay never nests final guards"
        );

        cleanup.remove().await?;
        assert!(std::fs::read_dir(directory.path())?.next().is_none());
        drop(snapshot);
        Ok(())
    }

    #[tokio::test]
    async fn rejects_non_regular_files() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("directory");
        std::fs::create_dir(&path)?;

        let error = SessionSnapshotFile::open(path)
            .await
            .err()
            .ok_or("directory was accepted as a snapshot")?;
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_symbolic_link_paths() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let directory = tempdir()?;
        let target = directory.path().join("target");
        let link = directory.path().join("link");
        std::fs::write(&target, b"snapshot")?;
        symlink(&target, &link)?;

        let error = SessionSnapshotFile::open(link)
            .await
            .err()
            .ok_or("symbolic link was accepted as a snapshot")?;
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn open_handle_survives_atomic_path_replacement() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempdir()?;
        let path = directory.path().join("snapshot");
        std::fs::write(&path, b"original")?;
        let snapshot = SessionSnapshotFile::open(path.clone()).await?;
        let pinned = PinnedSqliteFile::from_file(snapshot.into_std().await?, path.clone())?;
        let identity = pinned.identity();

        let replacement = directory.path().join("replacement");
        std::fs::write(&replacement, b"replacement")?;
        std::fs::rename(&replacement, &path)?;

        pinned.verify_identity()?;
        assert_eq!(pinned.identity(), identity);
        assert!(!pinned.path_matches_identity(&path)?);
        let mut bytes = Vec::new();
        pinned.file().try_clone()?.read_to_end(&mut bytes)?;
        assert_eq!(bytes, b"original");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn revalidation_detects_mutation_of_held_file() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("snapshot");
        std::fs::write(&path, b"original")?;
        let pinned = match PinnedSqliteFile::reopen_and_seal_fixed(&path) {
            Ok(pinned) => pinned,
            Err(error) if error.kind() == std::io::ErrorKind::Unsupported => return Ok(()),
            Err(error) => return Err(error.into()),
        };

        match std::fs::OpenOptions::new().append(true).open(path) {
            Err(_) => {}
            Ok(mut writer) => assert!(writer.write_all(b" changed").is_err()),
        }
        pinned
            .verify_immutable_generation()
            .expect("sealed descriptor retains its fixed measurement");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fixed_seal_rejects_a_preexisting_writer() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("snapshot");
        std::fs::write(&path, b"fixed snapshot")?;
        let writer = std::fs::OpenOptions::new().append(true).open(&path)?;
        match PinnedSqliteFile::reopen_and_seal_fixed(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::Unsupported => return Ok(()),
            Err(_) => {}
            Ok(_) => return Err("fixed seal accepted a preexisting writer".into()),
        }
        drop(writer);
        match PinnedSqliteFile::reopen_and_seal_fixed(&path) {
            Ok(_) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::Unsupported => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn readonly_nofollow_rejects_fifo_without_blocking() -> Result<(), Box<dyn std::error::Error>> {
        use std::process::Command;
        use std::time::{Duration, Instant};

        let directory = tempdir()?;
        let path = directory.path().join("snapshot-fifo");
        assert!(Command::new("mkfifo")
            .arg("-m")
            .arg("600")
            .arg(&path)
            .status()?
            .success());

        let started = Instant::now();
        let file = super::readonly_nofollow(&path)?;
        let error = match PinnedSqliteFile::from_file(file, path) {
            Ok(_) => return Err("FIFO was pinned as a snapshot".into()),
            Err(error) => error,
        };
        assert_eq!(io::ErrorKind::InvalidInput, error.kind());
        assert!(started.elapsed() < Duration::from_secs(1));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fixed_enable_errno_classification_preserves_unsupported_admission() {
        for errno in [libc::ENOTTY, libc::EOPNOTSUPP, libc::ENOSYS] {
            assert_eq!(
                io::ErrorKind::Unsupported,
                fs_verity_enable_error(opc_fs_verity_sys::Error::Enable(
                    io::Error::from_raw_os_error(errno,)
                ))
                .kind()
            );
        }
        assert_eq!(
            io::ErrorKind::InvalidData,
            fs_verity_enable_error(opc_fs_verity_sys::Error::Enable(
                io::Error::from_raw_os_error(libc::EBUSY,)
            ))
            .kind()
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn linked_identity_fails_closed_without_linux_descriptor_authority(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("snapshot");
        std::fs::write(&path, b"snapshot")?;
        let pinned = PinnedSqliteFile::from_file(std::fs::File::open(&path)?, path)?;

        let error = pinned
            .verify_linked_identity()
            .expect_err("non-Linux platforms must not synthesize linked-descriptor authority");
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
        Ok(())
    }

    #[tokio::test]
    async fn debug_redacts_paths() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("secret-snapshot-name");
        let snapshot = SessionSnapshotFile::create(path.clone()).await?;
        assert!(!format!("{snapshot:?}").contains("secret-snapshot-name"));

        #[cfg(target_os = "linux")]
        {
            let pinned = PinnedSqliteFile::from_file(snapshot.into_std().await?, path)?;
            assert!(!format!("{pinned:?}").contains("secret-snapshot-name"));
        }
        Ok(())
    }

    #[tokio::test]
    async fn bounded_receiver_rejects_writes_before_file_growth(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("incoming");
        let admission = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let permit = std::sync::Arc::clone(&admission).try_acquire_owned()?;
        let mut snapshot =
            SessionSnapshotFile::create_with_cleanup_bounded(path.clone(), None, 3, Some(permit))
                .await?;
        let error = snapshot
            .write_all(b"four")
            .await
            .err()
            .ok_or("write succeeded")?;
        assert_eq!(std::io::ErrorKind::InvalidData, error.kind());
        assert_eq!(0, snapshot.metadata().await?.len());
        assert!(admission.try_acquire().is_err());
        snapshot.close_and_cleanup().await?;
        assert!(admission.try_acquire().is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn receiving_handle_cannot_bypass_the_stream_ceiling(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("incoming");
        let permit = std::sync::Arc::new(tokio::sync::Semaphore::new(1)).try_acquire_owned()?;
        let mut snapshot =
            SessionSnapshotFile::create_with_cleanup_bounded(path.clone(), None, 3, Some(permit))
                .await?;
        let seek = snapshot.seek(std::io::SeekFrom::Start(4)).await;
        assert!(seek.is_err(), "seek beyond a receiving ceiling must fail");
        assert!(
            snapshot.file().is_err(),
            "raw receiving file escapes the ceiling"
        );
        assert!(
            snapshot.file_mut().is_err(),
            "raw mutable receiving file escapes the ceiling"
        );
        assert!(snapshot.try_clone().await.is_err());
        assert_eq!(0, snapshot.metadata().await?.len());
        snapshot.close_and_cleanup().await?;
        Ok(())
    }
}
