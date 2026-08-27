//! File-backed snapshot transport owned by the session consensus adapter.
//!
//! Keeping the path beside the Tokio file handle lets the SQLite state
//! machine atomically promote a fully received snapshot without buffering it
//! in process memory. Diagnostics deliberately do not expose the path.

use std::fmt;
use std::io;
use std::io::{Read as _, Seek as _};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use sha2::Digest as _;
#[cfg(test)]
use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use std::os::fd::{AsFd as _, AsRawFd as _, RawFd};
#[cfg(target_os = "linux")]
use std::os::linux::fs::MetadataExt as _;
use tokio::io::{AsyncRead, AsyncSeek, AsyncSeekExt as _, AsyncWrite, AsyncWriteExt, ReadBuf};

/// Maximum payload bytes admitted in one consensus snapshot envelope.
pub(crate) const SNAPSHOT_MAX_BYTES: u64 = 64 * 1024 * 1024 * 1024;
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
    identity: FileIdentity,
    sqlite_sidecars: bool,
    sidecars: Vec<(PathBuf, FileIdentity)>,
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
            path,
            identity: file_identity(metadata)?,
            sqlite_sidecars,
            sidecars: Vec::new(),
            armed: true,
        })
    }

    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }

    pub(crate) fn rebind_path(&mut self, path: PathBuf) {
        self.path = path;
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
            let Ok(metadata) = std::fs::symlink_metadata(&sidecar) else {
                continue;
            };
            if !metadata.is_file() {
                continue;
            }
            if let Ok(identity) = file_identity(&metadata) {
                self.sidecars.push((sidecar, identity));
            }
        }
    }

    fn remove_if_owned(&self, path: &Path, identity: FileIdentity) {
        let Ok(metadata) = std::fs::symlink_metadata(path) else {
            return;
        };
        if !metadata.is_file() {
            return;
        }
        let Ok(observed) = file_identity(&metadata) else {
            return;
        };
        if same_file_object(observed, identity) {
            let _ = std::fs::remove_file(path);
        }
    }
}

impl Drop for UnpublishedSnapshotArtifact {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.remove_if_owned(&self.path, self.identity);
        for (sidecar, identity) in &self.sidecars {
            self.remove_if_owned(sidecar, *identity);
        }
    }
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

    /// Refresh the expected content identity after SQLite has written through
    /// this same descriptor. Cleanup ownership remains attached to the inode.
    pub(crate) fn refresh_identity(mut self) -> io::Result<Self> {
        self.identity = file_identity(&self.file.metadata()?)?;
        Ok(self)
    }

    /// Record the exact identities of any SQLite sidecars created for this
    /// unique raw artifact, so later cleanup cannot remove replacements.
    pub(crate) fn capture_created_sidecars(&mut self) {
        if let Some(cleanup) = self.cleanup.as_mut() {
            cleanup.capture_sidecars();
        }
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
        let digest = opc_fs_verity_sys::enable_fixed_profile(pinned.file.as_fd())
            .map_err(fs_verity_enable_error)?;
        let metadata = pinned.file.metadata()?;
        pinned.immutable_generation = Some(ImmutableFileGeneration {
            length: metadata.len(),
            digest,
            change_time: linux_file_change_time(&metadata),
        });
        pinned.verify_immutable_generation()?;
        Ok(pinned)
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
        let digest =
            opc_fs_verity_sys::measure(pinned.file.as_fd()).map_err(fs_verity_measure_error)?;
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
        // The envelope hash is validation only. Fixed callers bind and
        // remeasure the kernel fs-verity generation separately; this method
        // remains a bounded envelope validator for Dynamic corruption checks.
        Ok(ImmutableSnapshotEnvelope {
            payload_length,
            total_length,
        })
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

    /// Compare a pathname with the pinned identity for diagnostics or cleanup.
    ///
    /// This follows the path at the time of comparison and is intentionally
    /// not an authorization primitive.
    pub(crate) fn path_matches_identity(&self, path: &Path) -> io::Result<bool> {
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
fn readonly_nofollow(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options.open(path)
}

#[cfg(target_os = "linux")]
fn fixed_verity_measurement(file: &std::fs::File) -> io::Result<[u8; 32]> {
    opc_fs_verity_sys::measure(file.as_fd()).map_err(fs_verity_measure_error)
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

fn fs_verity_enable_error(error: opc_fs_verity_sys::Error) -> io::Error {
    let kind = match error {
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
    io::Error::new(kind, "fixed snapshot sealing is unavailable")
}

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
    path: PathBuf,
    identity: FileIdentity,
    armed: bool,
    cleanup_failed: Option<Arc<AtomicBool>>,
}

impl SnapshotCleanupGuard {
    async fn remove(&mut self) -> io::Result<()> {
        if !self.armed {
            return Ok(());
        }
        let metadata = match tokio::fs::symlink_metadata(&self.path).await {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.armed = false;
                return Ok(());
            }
            Err(error) => {
                if let Some(cleanup_failed) = &self.cleanup_failed {
                    cleanup_failed.store(true, Ordering::Release);
                }
                return Err(error);
            }
        };
        let identity = match file_identity(&metadata) {
            Ok(identity) => identity,
            Err(error) => {
                if let Some(cleanup_failed) = &self.cleanup_failed {
                    cleanup_failed.store(true, Ordering::Release);
                }
                return Err(error);
            }
        };
        if !metadata.is_file() || !same_file_object(identity, self.identity) {
            self.armed = false;
            return Ok(());
        }
        match tokio::fs::remove_file(&self.path).await {
            Ok(()) => {
                self.armed = false;
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.armed = false;
                Ok(())
            }
            Err(error) => {
                if let Some(cleanup_failed) = &self.cleanup_failed {
                    cleanup_failed.store(true, Ordering::Release);
                }
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
        let metadata = match std::fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return,
            Err(_) => {
                if let Some(cleanup_failed) = &self.cleanup_failed {
                    cleanup_failed.store(true, Ordering::Release);
                }
                return;
            }
        };
        let identity = match file_identity(&metadata) {
            Ok(identity) => identity,
            Err(_) => {
                if let Some(cleanup_failed) = &self.cleanup_failed {
                    cleanup_failed.store(true, Ordering::Release);
                }
                return;
            }
        };
        if !metadata.is_file() || !same_file_object(identity, self.identity) {
            return;
        }
        match std::fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => {
                if let Some(cleanup_failed) = &self.cleanup_failed {
                    cleanup_failed.store(true, Ordering::Release);
                }
            }
        }
    }
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

    async fn create_with_cleanup_bounded_inner(
        path: PathBuf,
        cleanup_failed: Option<Arc<AtomicBool>>,
        received_maximum: u64,
        receive_admission: Option<tokio::sync::OwnedSemaphorePermit>,
        #[cfg(test)] after_create: Option<&SnapshotArtifactGate>,
    ) -> io::Result<Self> {
        reject_symlink(&path).await?;
        let (file, mut cleanup) = create_new_snapshot_file(&path)?;
        #[cfg(test)]
        if let Some(after_create) = after_create {
            after_create.block_if_armed().await;
        }
        let identity = file_identity(&file.metadata()?)?;
        let mut snapshot = Self::from_file(tokio::fs::File::from_std(file), path).await?;
        cleanup.disarm();
        snapshot.cleanup = Some(SnapshotCleanupGuard {
            path: snapshot.path.clone(),
            identity,
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

#[cfg(not(target_os = "linux"))]
fn same_file_object(_left: FileIdentity, _right: FileIdentity) -> bool {
    false
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
    use super::{SessionSnapshotFile, SnapshotArtifactGate, SnapshotReplayRead};
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt as _, AsyncSeek as _, AsyncSeekExt as _, AsyncWriteExt as _};

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
