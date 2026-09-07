//! Openraft storage adapters backed by the session SQLite database.
//!
//! Openraft exclusively owns election, commit, and membership decisions. This
//! adapter only provides serialized durable I/O and deterministic application
//! of entries Openraft has already committed.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::ops::{Bound, RangeBounds};
use std::path::{absolute, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use opc_consensus::engine::storage::{LogFlushed, RaftLogStorage, RaftStateMachine};
use opc_consensus::engine::{
    Entry, EntryPayload, ErrorSubject, ErrorVerb, LogId, LogState, RaftLogReader,
    RaftSnapshotBuilder, Snapshot, SnapshotMeta, StorageError, StoredMembership, Vote,
};
use opc_consensus::DURABLE_OPENRAFT_MAX_PAYLOAD_ENTRIES;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use super::raft_adapter::{SessionRaftAdapterError, SessionRaftPeerDirectory};
#[cfg(target_os = "linux")]
use super::snapshot::rename_noreplace_in_directory;
#[cfg(target_os = "linux")]
use super::snapshot::snapshot_cleanup_unlink_guard_name_authenticates_metadata;
use super::snapshot::{
    acknowledge_unpublished_snapshot_cleanup_failure,
    create_unpublished_snapshot_file_in_namespace, fixed_verity_is_exactly_unsealed,
    has_unpublished_snapshot_cleanup_failure, pending_unpublished_snapshot_cleanup_failures,
    readonly_nofollow, record_unpublished_snapshot_cleanup_failure_in_namespace, PinnedSqliteFile,
    RetainedSnapshotDirectory, SessionSnapshotFile, UnpublishedSnapshotArtifact,
    SNAPSHOT_ENVELOPE_FOOTER_BYTES, SNAPSHOT_ENVELOPE_MAX_BYTES, SNAPSHOT_MAX_BYTES,
};
#[cfg(test)]
use super::snapshot::{
    fixed_prepublication_scan_boundary, FixedPrepublicationScanGateGuard, SnapshotArtifactGate,
};
#[cfg(target_os = "linux")]
use super::snapshot::{
    pending_snapshot_namespace_recovery_authority, PendingSnapshotNamespaceRecoveryAuthority,
};
use super::{
    SessionConsensusIdentity, SessionConsensusNodeId, SessionRaftTypeConfig,
    SessionTopologyMemberBinding, SnapshotIntegrityPolicy,
};
use crate::backend::ReplicationEntry;
use crate::fenced_mutation_roster::RosterAttestationTrustRootV1;
use crate::readiness::PlacementResiliencePolicy;
use crate::sqlite::consensus::{self, SqliteConsensusCore};
use crate::sqlite::SqliteSessionBackend;

const SNAPSHOT_FOOTER_MAGIC: &[u8; 8] = b"OPCSNP01";
const SNAPSHOT_FOOTER_BYTES: u64 = SNAPSHOT_ENVELOPE_FOOTER_BYTES;
// At most one published image and a bounded set of interrupted-attempt
// artifacts may coexist under the one snapshot gate.
const SNAPSHOT_DIRECTORY_MAX_ENTRIES: usize = 32;
// A receiving stream itself is its durable one-entry reservation. A SQLite
// staging database may have each of its three journal sidecars, even though
// the normal snapshot writer disables them. Build can retain a source and a
// compacted database at once; install can retain the validated envelope and
// one extracted database at once.
const SNAPSHOT_SQLITE_ARTIFACT_MAX_ENTRIES: usize = 4;
const SNAPSHOT_RECEIVE_RESERVATION_ENTRIES: usize = 1;
const SNAPSHOT_DYNAMIC_INSTALL_RESERVATION_ENTRIES: usize =
    SNAPSHOT_SQLITE_ARTIFACT_MAX_ENTRIES + 1;
const SNAPSHOT_FIXED_INSTALL_RESERVATION_ENTRIES: usize = SNAPSHOT_SQLITE_ARTIFACT_MAX_ENTRIES;
// The compacted database is renamed in place to its published envelope, so it
// never occupies a ninth namespace entry alongside that envelope.
const SNAPSHOT_BUILD_RESERVATION_ENTRIES: usize = SNAPSHOT_SQLITE_ARTIFACT_MAX_ENTRIES * 2;
const SNAPSHOT_APPLY_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Test-only witness for the expensive live-terminal branch. The production
/// fast probe cannot reach `reconcile_with_gate`, so a focused test can prove
/// that clear/active calls neither select nor open a current snapshot.
#[cfg(all(test, target_os = "linux"))]
struct LiveTerminalRecoveryFullReconciliationObserver {
    full_reconciliations: Arc<AtomicUsize>,
}

#[cfg(test)]
fn live_terminal_recovery_full_reconciliation_observer(
) -> &'static std::sync::Mutex<Option<Arc<AtomicUsize>>> {
    static OBSERVER: std::sync::OnceLock<std::sync::Mutex<Option<Arc<AtomicUsize>>>> =
        std::sync::OnceLock::new();
    OBSERVER.get_or_init(|| std::sync::Mutex::new(None))
}

#[cfg(all(test, target_os = "linux"))]
impl LiveTerminalRecoveryFullReconciliationObserver {
    fn install() -> Self {
        let full_reconciliations = Arc::new(AtomicUsize::new(0));
        let mut installed = live_terminal_recovery_full_reconciliation_observer()
            .lock()
            .expect("live terminal recovery full reconciliation observer");
        assert!(
            installed.is_none(),
            "live terminal recovery full reconciliation observer already installed"
        );
        *installed = Some(Arc::clone(&full_reconciliations));
        Self {
            full_reconciliations,
        }
    }

    fn full_reconciliations(&self) -> usize {
        self.full_reconciliations.load(Ordering::Acquire)
    }
}

#[cfg(all(test, target_os = "linux"))]
impl Drop for LiveTerminalRecoveryFullReconciliationObserver {
    fn drop(&mut self) {
        let mut installed = live_terminal_recovery_full_reconciliation_observer()
            .lock()
            .expect("live terminal recovery full reconciliation observer");
        assert!(
            installed
                .as_ref()
                .is_some_and(|observer| Arc::ptr_eq(observer, &self.full_reconciliations)),
            "live terminal recovery full reconciliation observer changed"
        );
        *installed = None;
    }
}

#[cfg(test)]
fn observe_live_terminal_recovery_full_reconciliation() {
    if let Some(observer) = live_terminal_recovery_full_reconciliation_observer()
        .lock()
        .expect("live terminal recovery full reconciliation observer")
        .as_ref()
    {
        observer.fetch_add(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SnapshotDirectoryValidationFailure {
    Current,
    ReadDirectory,
    SyncDirectory,
}

#[cfg(test)]
fn snapshot_directory_validation_failures(
) -> &'static std::sync::Mutex<BTreeMap<PathBuf, SnapshotDirectoryValidationFailure>> {
    static FAILURES: std::sync::OnceLock<
        std::sync::Mutex<BTreeMap<PathBuf, SnapshotDirectoryValidationFailure>>,
    > = std::sync::OnceLock::new();
    FAILURES.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()))
}

#[cfg(test)]
fn inject_snapshot_directory_validation_failure(
    snapshot_directory: PathBuf,
    failure: SnapshotDirectoryValidationFailure,
) {
    snapshot_directory_validation_failures()
        .lock()
        .expect("snapshot directory validation hook")
        .insert(snapshot_directory, failure);
}

#[cfg(test)]
fn take_snapshot_directory_validation_failure(
    snapshot_directory: &Path,
    expected: SnapshotDirectoryValidationFailure,
) -> bool {
    let mut failures = snapshot_directory_validation_failures()
        .lock()
        .expect("snapshot directory validation hook");
    if failures.get(snapshot_directory) == Some(&expected) {
        failures.remove(snapshot_directory);
        true
    } else {
        false
    }
}

// Model only the crash boundary after an SDK-owned successor has been renamed
// and its directory fsynced, but before its metadata transaction.  The test
// leaves the exact journal-reserved candidate in place for next-open preflight
// reclamation; production has no hook at this boundary.
#[cfg(test)]
fn legacy_fixed_snapshot_reseed_candidate_process_losses(
) -> &'static std::sync::Mutex<BTreeSet<PathBuf>> {
    static LOSSES: std::sync::OnceLock<std::sync::Mutex<BTreeSet<PathBuf>>> =
        std::sync::OnceLock::new();
    LOSSES.get_or_init(|| std::sync::Mutex::new(BTreeSet::new()))
}

#[cfg(all(test, target_os = "linux"))]
fn inject_legacy_fixed_snapshot_reseed_candidate_process_loss(snapshot_directory: PathBuf) {
    legacy_fixed_snapshot_reseed_candidate_process_losses()
        .lock()
        .expect("legacy reseed candidate process-loss hook")
        .insert(snapshot_directory);
}

#[cfg(test)]
fn take_legacy_fixed_snapshot_reseed_candidate_process_loss(snapshot_directory: &Path) -> bool {
    legacy_fixed_snapshot_reseed_candidate_process_losses()
        .lock()
        .expect("legacy reseed candidate process-loss hook")
        .remove(snapshot_directory)
}

// The path-to-core handoff is a separate causal boundary from ordinary
// retained-dirfd child I/O.  Production does nothing here; the test hook
// replaces the configured parent entry after FD admission but before core
// initialization, proving core receives the already-admitted logical key
// rather than recanonicalizing a replacement namespace.
#[cfg(test)]
type SnapshotDirectoryAdmissionTestHook = Box<dyn FnOnce(&Path) + Send>;

#[cfg(test)]
fn snapshot_directory_admission_test_hooks(
) -> &'static std::sync::Mutex<BTreeMap<PathBuf, SnapshotDirectoryAdmissionTestHook>> {
    static HOOKS: std::sync::OnceLock<
        std::sync::Mutex<BTreeMap<PathBuf, SnapshotDirectoryAdmissionTestHook>>,
    > = std::sync::OnceLock::new();
    HOOKS.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()))
}

#[cfg(all(test, target_os = "linux"))]
fn install_snapshot_directory_admission_test_hook(
    logical_directory: PathBuf,
    hook: SnapshotDirectoryAdmissionTestHook,
) {
    snapshot_directory_admission_test_hooks()
        .lock()
        .expect("install snapshot directory admission hook")
        .insert(logical_directory, hook);
}

fn run_snapshot_directory_admission_test_hook(logical_directory: &Path) {
    #[cfg(test)]
    if let Some(hook) = snapshot_directory_admission_test_hooks()
        .lock()
        .expect("take snapshot directory admission hook")
        .remove(logical_directory)
    {
        hook(logical_directory);
    }
    #[cfg(not(test))]
    let _ = logical_directory;
}

// Generation acknowledgement is deliberately a distinct causal boundary from
// the retained-dirfd fsync. A test gate here proves a cleanup failure issued
// after that fsync remains pending rather than being erased by the older
// validation pass's acknowledgement.
#[cfg(test)]
fn snapshot_cleanup_generation_ack_gates(
) -> &'static std::sync::Mutex<BTreeMap<PathBuf, Arc<SnapshotArtifactGate>>> {
    static GATES: std::sync::OnceLock<
        std::sync::Mutex<BTreeMap<PathBuf, Arc<SnapshotArtifactGate>>>,
    > = std::sync::OnceLock::new();
    GATES.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()))
}

#[cfg(test)]
struct SnapshotCleanupGenerationAckGateGuard {
    directory: PathBuf,
    gate: Arc<SnapshotArtifactGate>,
}

#[cfg(test)]
impl SnapshotCleanupGenerationAckGateGuard {
    fn install(directory: PathBuf, gate: Arc<SnapshotArtifactGate>) -> Self {
        snapshot_cleanup_generation_ack_gates()
            .lock()
            .expect("install cleanup generation acknowledgement gate")
            .insert(directory.clone(), Arc::clone(&gate));
        Self { directory, gate }
    }
}

#[cfg(test)]
impl Drop for SnapshotCleanupGenerationAckGateGuard {
    fn drop(&mut self) {
        self.gate.release();
        let mut gates = snapshot_cleanup_generation_ack_gates()
            .lock()
            .expect("remove cleanup generation acknowledgement gate");
        if gates
            .get(&self.directory)
            .is_some_and(|installed| Arc::ptr_eq(installed, &self.gate))
        {
            gates.remove(&self.directory);
        }
    }
}

#[cfg(test)]
async fn wait_after_snapshot_cleanup_failure_sync_before_ack(directory: &Path) {
    let gate = snapshot_cleanup_generation_ack_gates()
        .lock()
        .ok()
        .and_then(|gates| gates.get(directory).cloned());
    if let Some(gate) = gate {
        gate.block_if_armed().await;
    }
}

// OpenRaft dispatches snapshot installation to its state-machine worker, then
// may issue the matching log purge on the core worker without awaiting that
// task.  This test seam holds only after the replacement transaction has
// committed and the in-memory applied frontier has been published, proving a
// concurrent purge does not depend on later diagnostics or cleanup.
#[cfg(test)]
fn snapshot_install_applied_progress_gates(
) -> &'static std::sync::Mutex<BTreeMap<PathBuf, Arc<SnapshotArtifactGate>>> {
    static GATES: std::sync::OnceLock<
        std::sync::Mutex<BTreeMap<PathBuf, Arc<SnapshotArtifactGate>>>,
    > = std::sync::OnceLock::new();
    GATES.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()))
}

#[cfg(test)]
struct SnapshotInstallAppliedProgressGateGuard {
    directory: PathBuf,
    gate: Arc<SnapshotArtifactGate>,
}

#[cfg(test)]
impl SnapshotInstallAppliedProgressGateGuard {
    fn install(directory: PathBuf, gate: Arc<SnapshotArtifactGate>) -> Self {
        snapshot_install_applied_progress_gates()
            .lock()
            .expect("install snapshot applied-progress gate")
            .insert(directory.clone(), Arc::clone(&gate));
        Self { directory, gate }
    }
}

#[cfg(test)]
impl Drop for SnapshotInstallAppliedProgressGateGuard {
    fn drop(&mut self) {
        self.gate.release();
        let mut gates = snapshot_install_applied_progress_gates()
            .lock()
            .expect("remove snapshot applied-progress gate");
        if gates
            .get(&self.directory)
            .is_some_and(|installed| Arc::ptr_eq(installed, &self.gate))
        {
            gates.remove(&self.directory);
        }
    }
}

#[cfg(test)]
async fn wait_after_snapshot_install_applied_progress(directory: &Path) {
    let gate = snapshot_install_applied_progress_gates()
        .lock()
        .ok()
        .and_then(|gates| gates.get(directory).cloned());
    if let Some(gate) = gate {
        gate.block_if_armed().await;
    }
}

/// One advisory process-wide lease for a snapshot namespace. A kernel-owned
/// abstract Unix socket names the immutable configured absolute spelling, so
/// it cannot be replaced by mutating filesystem lock entries or a parent
/// symlink retarget. The directory FD is retained as the identity anchor for
/// subsequent namespace operations and carries the cooperating lease flock.
struct SnapshotDirectoryLease {
    canonical_directory: PathBuf,
    /// The sole operational authority for snapshot namespace children. The
    /// configured path remains a logical key only; it is never dereferenced
    /// by receive/install/build/cleanup after this descriptor is admitted.
    namespace: Arc<RetainedSnapshotDirectory>,
    // A database may select exactly one snapshot namespace in this process.
    // `flock` deliberately follows an open-file description, so a duplicate
    // from the same backend would otherwise make a second directory look
    // available.  Keep a process-local identity registry in addition to the
    // cross-process descriptor lock.
    #[cfg(target_os = "linux")]
    database_identity: Option<SnapshotDatabaseIdentity>,
    #[cfg(unix)]
    _namespace_socket: Arc<std::os::fd::OwnedFd>,
    #[cfg(unix)]
    _database_lock: Option<Arc<nix::fcntl::Flock<std::fs::File>>>,
}

/// Stable identity of the durable SQLite main file while a lease is held.
///
/// This is not a claim that an unrelated same-UID actor cannot replace a
/// database inode. Operators must retain a stable database-path anchor for
/// that threat model; this registry closes the same-backend/OFD bypass only.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SnapshotDatabaseIdentity {
    device: u64,
    inode: u64,
}

fn snapshot_directory_leases(
) -> &'static std::sync::Mutex<BTreeMap<PathBuf, std::sync::Weak<SnapshotDirectoryLease>>> {
    static LEASES: std::sync::OnceLock<
        std::sync::Mutex<BTreeMap<PathBuf, std::sync::Weak<SnapshotDirectoryLease>>>,
    > = std::sync::OnceLock::new();
    LEASES.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()))
}

#[cfg(target_os = "linux")]
fn snapshot_database_leases() -> &'static std::sync::Mutex<
    BTreeMap<SnapshotDatabaseIdentity, std::sync::Weak<SnapshotDirectoryLease>>,
> {
    static LEASES: std::sync::OnceLock<
        std::sync::Mutex<
            BTreeMap<SnapshotDatabaseIdentity, std::sync::Weak<SnapshotDirectoryLease>>,
        >,
    > = std::sync::OnceLock::new();
    LEASES.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()))
}

// Force the otherwise tiny same-OFD admission interval in a regression test.
// The production registry never relies on timing; this only makes the former
// check/unlock/insert race deterministic.
#[cfg(test)]
fn snapshot_database_lease_admission_barrier(
) -> &'static std::sync::Mutex<Option<Arc<tokio::sync::Barrier>>> {
    static BARRIER: std::sync::OnceLock<std::sync::Mutex<Option<Arc<tokio::sync::Barrier>>>> =
        std::sync::OnceLock::new();
    BARRIER.get_or_init(|| std::sync::Mutex::new(None))
}

#[cfg(test)]
async fn wait_snapshot_database_lease_admission_barrier() {
    let barrier = snapshot_database_lease_admission_barrier()
        .lock()
        .expect("snapshot database admission barrier")
        .clone();
    if let Some(barrier) = barrier {
        barrier.wait().await;
    }
}

/// Bind the immutable configured namespace key. The resulting descriptor is
/// shared with queued cleanup authority, so a detached D1 continues to block
/// a fresh process from publishing D2 under either the same key or the same
/// durable database before D1 is acknowledged.
#[cfg(target_os = "linux")]
fn bind_snapshot_directory_socket(configured_path: &Path) -> io::Result<Arc<std::os::fd::OwnedFd>> {
    use nix::sys::socket::{bind, socket, AddressFamily, SockFlag, SockType, UnixAddr};
    use std::os::fd::AsRawFd as _;

    let digest = Sha256::digest(configured_path.as_os_str().as_encoded_bytes());
    let mut name = b"opc-session-snapshot-".to_vec();
    for byte in digest {
        name.extend_from_slice(format!("{byte:02x}").as_bytes());
    }
    let socket = socket(
        AddressFamily::Unix,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC,
        None,
    )
    .map_err(io::Error::from)?;
    let address = UnixAddr::new_abstract(&name).map_err(io::Error::from)?;
    bind(socket.as_raw_fd(), &address).map_err(io::Error::from)?;
    Ok(Arc::new(socket))
}

#[cfg(all(unix, not(target_os = "linux")))]
fn bind_snapshot_directory_socket(
    _configured_path: &Path,
) -> io::Result<Arc<std::os::fd::OwnedFd>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "session consensus snapshot directory lease requires Linux abstract Unix sockets",
    ))
}

async fn acquire_snapshot_directory_lease(
    backend: &SqliteSessionBackend,
    path: &Path,
) -> io::Result<Arc<SnapshotDirectoryLease>> {
    let configured_path = absolute(path)?;
    let directory_preexisted = path.exists();
    if !directory_preexisted {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;

            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true).mode(0o700);
            builder.create(path)?;
        }
        #[cfg(not(unix))]
        std::fs::create_dir_all(path)?;
    }
    // Capture the durable owner before creating a directory flock.  A queued
    // cleanup retains the exact old directory flock until it is durably
    // reclaimed; only this same database identity may reenter that authority
    // instead of attempting a self-conflicting second flock.
    #[cfg(target_os = "linux")]
    let database_file = backend
        .duplicate_main_file_descriptor_for_snapshot_lease()
        .await?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "session consensus snapshot storage requires a file-backed SQLite backend",
            )
        })?;
    #[cfg(target_os = "linux")]
    let database_identity = {
        use std::os::linux::fs::MetadataExt as _;

        let metadata = database_file.metadata()?;
        SnapshotDatabaseIdentity {
            device: metadata.st_dev(),
            inode: metadata.st_ino(),
        }
    };
    #[cfg(unix)]
    let (namespace_socket, namespace, canonical_directory) = {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        // The retained FD is opened before any identity policy is evaluated.
        // Never turn the configured path into a capability after this point:
        // its parent may be renamed by an operator while the lease survives.
        let directory = nix::fcntl::open(
            &configured_path,
            nix::fcntl::OFlag::O_RDONLY
                | nix::fcntl::OFlag::O_DIRECTORY
                | nix::fcntl::OFlag::O_NOFOLLOW
                | nix::fcntl::OFlag::O_CLOEXEC
                | nix::fcntl::OFlag::O_NONBLOCK,
            nix::sys::stat::Mode::empty(),
        )
        .map(std::fs::File::from)
        .map_err(io::Error::from)?;
        let metadata = directory.metadata()?;
        let owner = metadata.uid();
        let mode = metadata.mode();
        let effective_uid = nix::unistd::geteuid().as_raw();
        if !metadata.is_dir() || owner != effective_uid || mode & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "snapshot directory must be owned by the effective uid and not group/world writable",
            ));
        }
        // `DirBuilder` is umask-sensitive. An SDK-created leaf is explicitly
        // made private before the descriptor is shared with any operation.
        if !directory_preexisted && mode & 0o777 != 0o700 {
            directory.set_permissions(std::fs::Permissions::from_mode(0o700))?;
        }
        // Canonical spelling is a logical/latch key only. Verify it still
        // names the exact retained descriptor before recording it; otherwise
        // a parent rename raced admission and we fail closed.
        let canonical_directory = std::fs::canonicalize(&configured_path)?;
        let canonical_metadata = std::fs::metadata(&canonical_directory)?;
        if canonical_metadata.dev() != metadata.dev() || canonical_metadata.ino() != metadata.ino()
        {
            return Err(io::Error::other(
                "snapshot directory changed while establishing retained descriptor",
            ));
        }
        #[cfg(target_os = "linux")]
        let (namespace_socket, namespace) = match pending_snapshot_namespace_recovery_authority(
            &configured_path,
            (metadata.dev(), metadata.ino()),
            (database_identity.device, database_identity.inode),
        )? {
            PendingSnapshotNamespaceRecoveryAuthority::Exact(namespace) => {
                // The new descriptor served only to prove this configured
                // path still names D1. The queued namespace already owns
                // D1's flock; reuse that exact capability so same-owner
                // restart can drain it.
                drop(directory);
                let namespace_socket = namespace
                    .trusted_namespace_socket_for_identity((
                        database_identity.device,
                        database_identity.inode,
                    ))?
                    .ok_or_else(|| {
                        io::Error::other("queued snapshot cleanup authority lost its socket")
                    })?;
                (namespace_socket, namespace)
            }
            PendingSnapshotNamespaceRecoveryAuthority::ReplacementAtSameConfiguredKey {
                database_lock,
                namespace_socket,
            } => {
                // A parent replacement detached queued D1 and installed D2
                // at the same immutable configured key. D2 needs its own
                // directory flock, but it must share D1's still-held SQLite
                // flock while validation reclaims and fsyncs D1.
                let namespace = Arc::new(RetainedSnapshotDirectory::from_directory_file(
                    canonical_directory.clone(),
                    configured_path.clone(),
                    directory,
                )?);
                namespace.install_trusted_database_lock(
                    (database_identity.device, database_identity.inode),
                    database_lock,
                )?;
                namespace.install_trusted_namespace_socket(Arc::clone(&namespace_socket))?;
                (namespace_socket, namespace)
            }
            PendingSnapshotNamespaceRecoveryAuthority::OtherPendingDirectory => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "session consensus database has pending snapshot cleanup in another namespace",
                ));
            }
            PendingSnapshotNamespaceRecoveryAuthority::None => {
                // Bind before constructing the fresh directory flock. A
                // competing process can win this immutable configured key,
                // but it cannot observe a half-admitted namespace without
                // making its own socket ownership explicit first.
                let namespace_socket = bind_snapshot_directory_socket(&configured_path)?;
                let namespace = Arc::new(RetainedSnapshotDirectory::from_directory_file(
                    canonical_directory.clone(),
                    configured_path.clone(),
                    directory,
                )?);
                namespace.bind_trusted_database_identity((
                    database_identity.device,
                    database_identity.inode,
                ))?;
                namespace.install_trusted_namespace_socket(Arc::clone(&namespace_socket))?;
                (namespace_socket, namespace)
            }
        };
        #[cfg(not(target_os = "linux"))]
        let (namespace_socket, namespace) = {
            let namespace_socket = bind_snapshot_directory_socket(&configured_path)?;
            let namespace = Arc::new(RetainedSnapshotDirectory::from_directory_file(
                canonical_directory.clone(),
                configured_path.clone(),
                directory,
            )?);
            (namespace_socket, namespace)
        };
        (namespace_socket, namespace, canonical_directory)
    };
    #[cfg(not(unix))]
    return Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "session consensus snapshot directory lease requires Unix",
    ));
    {
        let mut leases = snapshot_directory_leases()
            .lock()
            .map_err(|_| io::Error::other("snapshot directory lease lock poisoned"))?;
        if leases
            .get(&canonical_directory)
            .and_then(std::sync::Weak::upgrade)
            .is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "session consensus snapshot directory is already owned",
            ));
        }
        leases.remove(&canonical_directory);
    }
    // A duplicate of one SQLite backend shares an open-file description with
    // its owner. Checking the registry *before* creating a redundant Flock
    // is essential: dropping a rejected duplicate Flock would LOCK_UN the
    // still-live first lease. The registry check, Flock acquisition, and
    // weak insertion remain one synchronous critical section.
    #[cfg(test)]
    wait_snapshot_database_lease_admission_barrier().await;

    #[cfg(target_os = "linux")]
    let mut lease = Arc::new(SnapshotDirectoryLease {
        canonical_directory: canonical_directory.clone(),
        namespace,
        database_identity: Some(database_identity),
        _namespace_socket: namespace_socket,
        _database_lock: None,
    });
    #[cfg(target_os = "linux")]
    let mut database_leases = snapshot_database_leases()
        .lock()
        .map_err(|_| io::Error::other("snapshot database lease lock poisoned"))?;
    #[cfg(target_os = "linux")]
    {
        if database_leases
            .get(&database_identity)
            .and_then(std::sync::Weak::upgrade)
            .is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "session consensus database already owns a snapshot namespace",
            ));
        }
        let lock = match lease.namespace.trusted_database_lock_for_identity((
            database_identity.device,
            database_identity.inode,
        ))? {
            Some(lock) => lock,
            None => {
                let lock = Arc::new(
                    nix::fcntl::Flock::lock(
                        database_file,
                        nix::fcntl::FlockArg::LockExclusiveNonblock,
                    )
                    .map_err(|(_, error)| io::Error::from(error))?,
                );
                lease.namespace.install_trusted_database_lock(
                    (database_identity.device, database_identity.inode),
                    Arc::clone(&lock),
                )?;
                lock
            }
        };
        Arc::get_mut(&mut lease)
            .expect("database lease is unshared before registry insertion")
            ._database_lock = Some(lock);
        database_leases.insert(database_identity, Arc::downgrade(&lease));
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    let lease = {
        let database_file = backend
            .duplicate_main_file_descriptor_for_snapshot_lease()
            .await?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "session consensus snapshot storage requires a file-backed SQLite backend",
                )
            })?;
        let database_lock =
            nix::fcntl::Flock::lock(database_file, nix::fcntl::FlockArg::LockExclusiveNonblock)
                .map_err(|(_, error)| io::Error::from(error))?;
        Arc::new(SnapshotDirectoryLease {
            canonical_directory: canonical_directory.clone(),
            namespace,
            _namespace_socket: namespace_socket,
            _database_lock: Some(Arc::new(database_lock)),
        })
    };
    snapshot_directory_leases()
        .lock()
        .map_err(|_| io::Error::other("snapshot directory lease lock poisoned"))?
        .insert(canonical_directory, Arc::downgrade(&lease));
    Ok(lease)
}

impl Drop for SnapshotDirectoryLease {
    fn drop(&mut self) {
        if let Ok(mut leases) = snapshot_directory_leases().lock() {
            if leases
                .get(&self.canonical_directory)
                .and_then(std::sync::Weak::upgrade)
                .is_some_and(|owner| std::ptr::eq(Arc::as_ptr(&owner), self))
            {
                leases.remove(&self.canonical_directory);
            }
        }
        #[cfg(target_os = "linux")]
        if let Some(identity) = self.database_identity {
            if let Ok(mut leases) = snapshot_database_leases().lock() {
                if leases
                    .get(&identity)
                    .and_then(std::sync::Weak::upgrade)
                    .is_some_and(|owner| std::ptr::eq(Arc::as_ptr(&owner), self))
                {
                    leases.remove(&identity);
                }
            }
        }
    }
}

/// One UUID-named staging artifact owned through asynchronous failure and
/// cancellation. The last owner attempts a synchronous removal, latching an
/// error for the next operation under the single snapshot gate.
#[derive(Clone)]
struct SnapshotArtifact {
    state: Arc<SnapshotArtifactState>,
}

/// Holds the current published image while a successor is being prepared.
/// Until replacement metadata is known committed, dropping this holder must
/// preserve the authoritative predecessor rather than treating it as a failed
/// attempt's disposable artifact.
struct RetainedCurrentSnapshotArtifact {
    artifact: Option<SnapshotArtifact>,
}

impl RetainedCurrentSnapshotArtifact {
    fn new(artifact: SnapshotArtifact) -> Self {
        Self {
            artifact: Some(artifact),
        }
    }

    fn into_cleanup_artifact(mut self) -> SnapshotArtifact {
        self.artifact
            .take()
            .expect("retained current snapshot artifact is present")
    }
}

impl Drop for RetainedCurrentSnapshotArtifact {
    fn drop(&mut self) {
        if let Some(artifact) = &self.artifact {
            artifact.disarm();
        }
    }
}

struct SnapshotArtifactState {
    // `path` is the stable diagnostic/original name. Cleanup itself advances
    // through `cleanup` after a successful rename.
    path: PathBuf,
    // Present for production snapshot artifacts. Unit fixtures retain the
    // legacy path-only constructor, but all consensus namespace artifacts
    // receive this descriptor capability at creation.
    namespace: Option<Arc<RetainedSnapshotDirectory>>,
    cleanup: std::sync::Mutex<SnapshotArtifactCleanupState>,
    identity: std::sync::Mutex<Option<SnapshotArtifactIdentity>>,
    // A prior published artifact remains descriptor-pinned from admission
    // through replacement metadata publication; cleanup never re-authorizes
    // it by taking ownership from a later pathname lookup.
    pin: std::sync::Mutex<Option<std::fs::File>>,
    // A cancellation-safe cleanup worker may outlive its builder wrapper.
    // Retain the namespace lease with the artifact until identity-bound
    // cleanup has completed.
    namespace_lease: std::sync::Mutex<Option<Arc<dyn Send + Sync>>>,
    armed: AtomicBool,
    cleanup_failed: Arc<AtomicBool>,
}

fn record_snapshot_artifact_cleanup_failure(state: &SnapshotArtifactState) {
    // Namespace artifacts must latch under their configured logical key, not
    // under their `/proc/self/fd/<n>` SQLite-only spelling. Publish the
    // monotonic generation before the legacy atomic hint so validation can
    // never clear a failure whose directory fsync it did not perform.
    if let Some(namespace) = &state.namespace {
        record_unpublished_snapshot_cleanup_failure_in_namespace(Arc::clone(namespace));
    }
    // The remaining path-only constructor is test compatibility only. It has
    // no retained directory authority, so it must not publish a path-keyed
    // global acknowledgement that a replacement directory could satisfy. The
    // local atomic below still makes its caller fail closed.
    state.cleanup_failed.store(true, Ordering::Release);
}

/// Linux inode identity captured while an artifact is known to be ours.
/// Path names are deliberately never treated as ownership evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SnapshotArtifactIdentity {
    #[cfg(target_os = "linux")]
    device: u64,
    #[cfg(target_os = "linux")]
    inode: u64,
}

#[cfg(target_os = "linux")]
enum SnapshotArtifactCleanupLocation {
    Original,
    Tombstone(PathBuf),
    // The final private guard records both its own bounded basename and the
    // preceding tombstone spelling so a failed authentication can restore
    // only with `RENAME_NOREPLACE`.
    UnlinkGuard { guard: PathBuf, tombstone: PathBuf },
    Unlinked,
}

struct SnapshotArtifactCleanupState {
    #[cfg(target_os = "linux")]
    original: PathBuf,
    #[cfg(target_os = "linux")]
    location: SnapshotArtifactCleanupLocation,
}

impl SnapshotArtifactCleanupState {
    fn new(path: PathBuf) -> Self {
        #[cfg(not(target_os = "linux"))]
        let _ = path;
        Self {
            #[cfg(target_os = "linux")]
            original: path,
            #[cfg(target_os = "linux")]
            location: SnapshotArtifactCleanupLocation::Original,
        }
    }

    #[cfg(target_os = "linux")]
    fn active_path(&self) -> Option<&Path> {
        match &self.location {
            SnapshotArtifactCleanupLocation::Original => Some(&self.original),
            SnapshotArtifactCleanupLocation::Tombstone(path) => Some(path),
            SnapshotArtifactCleanupLocation::UnlinkGuard { guard, .. } => Some(guard),
            SnapshotArtifactCleanupLocation::Unlinked => None,
        }
    }

    #[cfg(target_os = "linux")]
    fn tombstone_path(&self) -> Option<&Path> {
        match &self.location {
            SnapshotArtifactCleanupLocation::Tombstone(path) => Some(path),
            SnapshotArtifactCleanupLocation::UnlinkGuard { tombstone, .. } => Some(tombstone),
            SnapshotArtifactCleanupLocation::Original
            | SnapshotArtifactCleanupLocation::Unlinked => None,
        }
    }
}

#[cfg(test)]
type SnapshotArtifactCleanupTestHook = Box<dyn FnOnce(&Path, &Path) + Send>;

/// Deterministic process-loss seams for the predecessor of a newly published
/// snapshot.  Each point is after successor metadata is durable, so tests can
/// exercise restart recovery without pretending that a pathname fixture was a
/// real publication.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)] // Each point names the crash boundary after durable work.
enum SnapshotPublicationCleanupCrashPoint {
    AfterMetadataBeforeOldRename,
    AfterOldTombstoneSync,
    AfterOldUnlinkGuardSync,
}

#[cfg(test)]
#[derive(Default)]
struct SnapshotArtifactCleanupTestHooks {
    before_rename: Option<SnapshotArtifactCleanupTestHook>,
    after_rename: Option<SnapshotArtifactCleanupTestHook>,
    #[cfg(target_os = "linux")]
    post_final_identity_before_unlink: Option<SnapshotArtifactCleanupTestHook>,
    #[cfg(target_os = "linux")]
    fail_before_rename: bool,
    fail_post_rename_sync: bool,
    #[cfg(target_os = "linux")]
    fail_post_unlink_guard_sync: bool,
    publication_process_loss: Option<SnapshotPublicationCleanupCrashPoint>,
}

#[cfg(test)]
fn snapshot_artifact_cleanup_test_hooks(
) -> &'static std::sync::Mutex<BTreeMap<PathBuf, SnapshotArtifactCleanupTestHooks>> {
    static HOOKS: std::sync::OnceLock<
        std::sync::Mutex<BTreeMap<PathBuf, SnapshotArtifactCleanupTestHooks>>,
    > = std::sync::OnceLock::new();
    HOOKS.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()))
}

#[cfg(test)]
fn take_snapshot_publication_cleanup_process_loss(
    original: &Path,
    point: SnapshotPublicationCleanupCrashPoint,
) -> bool {
    let mut hooks = snapshot_artifact_cleanup_test_hooks()
        .lock()
        .expect("snapshot artifact cleanup test hooks");
    let Some(hooks) = hooks.get_mut(original) else {
        return false;
    };
    if hooks.publication_process_loss == Some(point) {
        hooks.publication_process_loss = None;
        true
    } else {
        false
    }
}

#[cfg(all(test, target_os = "linux"))]
fn simulated_snapshot_publication_process_loss(
    original: &Path,
    point: SnapshotPublicationCleanupCrashPoint,
) -> io::Result<()> {
    if take_snapshot_publication_cleanup_process_loss(original, point) {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "injected snapshot publication process loss",
        ))
    } else {
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
fn take_snapshot_artifact_cleanup_hook(
    original: &Path,
    after_rename: bool,
) -> (Option<SnapshotArtifactCleanupTestHook>, bool, bool) {
    let mut hooks = snapshot_artifact_cleanup_test_hooks()
        .lock()
        .expect("snapshot artifact cleanup test hooks");
    let Some(hooks) = hooks.get_mut(original) else {
        return (None, false, false);
    };
    let hook = if after_rename {
        hooks.after_rename.take()
    } else {
        hooks.before_rename.take()
    };
    let fail_before_rename = !after_rename && std::mem::take(&mut hooks.fail_before_rename);
    let fail_post_rename_sync = after_rename && std::mem::take(&mut hooks.fail_post_rename_sync);
    (hook, fail_before_rename, fail_post_rename_sync)
}

#[cfg(target_os = "linux")]
fn snapshot_artifact_cleanup_before_rename(original: &Path, tombstone: &Path) -> io::Result<()> {
    #[cfg(test)]
    {
        let (hook, fail_before_rename, _) = take_snapshot_artifact_cleanup_hook(original, false);
        if let Some(hook) = hook {
            hook(original, tombstone);
        }
        if fail_before_rename {
            return Err(io::Error::other(
                "injected pre-rename snapshot artifact cleanup failure",
            ));
        }
    }
    #[cfg(not(test))]
    let _ = (original, tombstone);
    Ok(())
}

#[cfg(target_os = "linux")]
fn sync_snapshot_artifact_cleanup_after_rename(
    original: &Path,
    tombstone: &Path,
    namespace: Option<&RetainedSnapshotDirectory>,
) -> io::Result<()> {
    #[cfg(test)]
    {
        let (hook, _, fail_sync) = take_snapshot_artifact_cleanup_hook(original, true);
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
    let _ = original;
    match namespace {
        Some(namespace) => namespace.sync(),
        None => {
            let parent = tombstone.parent().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "session consensus snapshot artifact has no parent",
                )
            })?;
            sync_directory(parent)
        }
    }
}

/// Test-only seam at the former final-identity-check-to-unlink race.  The
/// production transition immediately moves the authenticated tombstone to a
/// private guard afterward; a replacement introduced here is reauthenticated
/// under that guard and must fail closed.
#[cfg(target_os = "linux")]
fn snapshot_artifact_cleanup_after_final_identity_before_unlink(
    original: &Path,
    tombstone: &Path,
    guard: &Path,
) {
    #[cfg(test)]
    if let Some(hook) = snapshot_artifact_cleanup_test_hooks()
        .lock()
        .expect("snapshot artifact cleanup test hooks")
        .get_mut(original)
        .and_then(|hooks| hooks.post_final_identity_before_unlink.take())
    {
        hook(tombstone, guard);
    }
    #[cfg(not(test))]
    let _ = (original, tombstone, guard);
}

/// A successful final guard rename is durable before unlink.  A crash/failure
/// at this point can replay only the exact guard instead of generating nested
/// tombstones or returning to a public artifact spelling.
#[cfg(target_os = "linux")]
fn sync_snapshot_artifact_cleanup_after_unlink_guard_rename(
    cleanup: &SnapshotArtifactCleanupState,
    namespace: Option<&RetainedSnapshotDirectory>,
) -> io::Result<()> {
    match namespace {
        Some(namespace) => namespace.sync()?,
        None => cleanup
            .original
            .parent()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "session consensus snapshot artifact has no parent",
                )
            })
            .and_then(sync_directory)?,
    }
    #[cfg(test)]
    if snapshot_artifact_cleanup_test_hooks()
        .lock()
        .expect("snapshot artifact cleanup test hooks")
        .get_mut(&cleanup.original)
        .is_some_and(|hooks| std::mem::take(&mut hooks.fail_post_unlink_guard_sync))
    {
        return Err(io::Error::other(
            "injected post-unlink-guard directory sync failure",
        ));
    }
    Ok(())
}

/// The guard is derived only from the already UUID-bounded tombstone and the
/// exact inode authenticated for cleanup.  It therefore has one deterministic
/// retry spelling rather than an unbounded sequence of post-check artifacts.
#[cfg(target_os = "linux")]
fn snapshot_artifact_unlink_guard_path(
    tombstone: &Path,
    identity: SnapshotArtifactIdentity,
) -> io::Result<PathBuf> {
    let parent = tombstone.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "session consensus snapshot tombstone has no parent",
        )
    })?;
    let name = tombstone.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "session consensus snapshot tombstone has no file name",
        )
    })?;
    let mut guard_name = name.to_os_string();
    guard_name.push(format!(
        ".opc-unlink-guard-{:016x}-{:016x}",
        identity.device, identity.inode
    ));
    Ok(parent.join(guard_name))
}

fn snapshot_artifact_identity(
    metadata: &std::fs::Metadata,
) -> io::Result<SnapshotArtifactIdentity> {
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "session consensus snapshot artifact is not a regular file",
        ));
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::linux::fs::MetadataExt;

        Ok(SnapshotArtifactIdentity {
            device: metadata.st_dev(),
            inode: metadata.st_ino(),
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = metadata;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "session consensus snapshot cleanup requires Linux inode identity",
        ))
    }
}

impl SnapshotArtifact {
    #[cfg(test)]
    fn new(path: PathBuf, cleanup_failed: Arc<AtomicBool>) -> Self {
        Self::new_with_namespace(path, None, cleanup_failed)
    }

    fn new_in_namespace(
        namespace: Arc<RetainedSnapshotDirectory>,
        name: &std::ffi::OsStr,
        cleanup_failed: Arc<AtomicBool>,
    ) -> io::Result<Self> {
        let path = namespace.sqlite_child_path(name)?;
        Ok(Self::new_with_namespace(
            path,
            Some(namespace),
            cleanup_failed,
        ))
    }

    fn new_with_namespace(
        path: PathBuf,
        namespace: Option<Arc<RetainedSnapshotDirectory>>,
        cleanup_failed: Arc<AtomicBool>,
    ) -> Self {
        Self {
            state: Arc::new(SnapshotArtifactState {
                cleanup: std::sync::Mutex::new(SnapshotArtifactCleanupState::new(path.clone())),
                path,
                namespace,
                identity: std::sync::Mutex::new(None),
                pin: std::sync::Mutex::new(None),
                namespace_lease: std::sync::Mutex::new(None),
                // Construction alone proves no ownership.  Arm only after an
                // already-held descriptor has supplied a regular-file
                // identity; failed create_new must not poison later
                // admission with an unbound Drop cleanup attempt.
                armed: AtomicBool::new(false),
                cleanup_failed,
            }),
        }
    }

    fn path(&self) -> &Path {
        &self.state.path
    }

    fn disarm(&self) {
        self.state.armed.store(false, Ordering::Release);
    }

    fn retain_namespace_lease<T>(&self, lease: Arc<T>) -> io::Result<()>
    where
        T: Send + Sync + 'static,
    {
        *self
            .state
            .namespace_lease
            .lock()
            .map_err(|_| io::Error::other("snapshot artifact namespace lease lock poisoned"))? =
            Some(lease);
        Ok(())
    }

    /// Bind cleanup to the regular no-follow object currently named by this
    /// artifact.  Call this only while an already-held descriptor proves the
    /// path still names the object created by this operation.
    fn record_identity_from_file(&self, file: &std::fs::File) -> io::Result<()> {
        let identity = snapshot_artifact_identity(&file.metadata()?)?;
        let mut recorded = self
            .state
            .identity
            .lock()
            .map_err(|_| io::Error::other("snapshot artifact identity lock poisoned"))?;
        match *recorded {
            Some(previous) if previous != identity => Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "session consensus snapshot artifact identity changed",
            )),
            Some(_) => Ok(()),
            None => {
                // Do not duplicate the writer's open-file description.  A
                // cleanup pin survives asynchronous publication, and a
                // duplicated writable description makes Linux reject
                // FS_IOC_ENABLE_VERITY with EBUSY even after the original
                // SQLite writer is dropped.  The no-follow read pin is opened
                // while `file` still authenticates the pathname, then its
                // inode is compared before it becomes the cleanup authority.
                let pin = match &self.state.namespace {
                    Some(namespace) => {
                        namespace.open_read(self.state.path.file_name().ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "snapshot artifact has no file name",
                            )
                        })?)?
                    }
                    None => readonly_nofollow(&self.state.path)?,
                };
                if snapshot_artifact_identity(&pin.metadata()?)? != identity {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "session consensus snapshot artifact path changed while pinning cleanup",
                    ));
                }
                *recorded = Some(identity);
                *self
                    .state
                    .pin
                    .lock()
                    .map_err(|_| io::Error::other("snapshot artifact pin lock poisoned"))? =
                    Some(pin);
                self.state.armed.store(true, Ordering::Release);
                Ok(())
            }
        }
    }

    fn remove_owned_blocking(&self) -> io::Result<()> {
        let expected = *self
            .state
            .identity
            .lock()
            .map_err(|_| io::Error::other("snapshot artifact identity lock poisoned"))?;
        let mut cleanup = self
            .state
            .cleanup
            .lock()
            .map_err(|_| io::Error::other("snapshot artifact cleanup lock poisoned"))?;
        remove_identity_bound_snapshot_artifact(
            &mut cleanup,
            expected,
            self.state.namespace.as_deref(),
        )
    }

    /// Model an abrupt process stop in a publication recovery test.  Dropping
    /// the local test owner must not run its in-process cleanup fallback: the
    /// next opener is the actor that recovers the durable namespace state.
    #[cfg(test)]
    fn abandon_for_simulated_process_loss(&self) {
        self.state.armed.store(false, Ordering::Release);
    }

    /// Do not disarm before unlink completes: cancellation otherwise loses
    /// the only cleanup owner between admission and filesystem result.
    async fn remove(&self) -> io::Result<()> {
        if !self.state.armed.load(Ordering::Acquire) {
            return Ok(());
        }
        match tokio::task::spawn_blocking({
            let artifact = self.clone();
            move || artifact.remove_owned_blocking()
        })
        .await
        .map_err(|_| io::Error::other("snapshot artifact cleanup worker failed"))?
        {
            Ok(()) => {
                let synced = match &self.state.namespace {
                    Some(namespace) => namespace.sync(),
                    None => self
                        .state
                        .path
                        .parent()
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "session consensus snapshot artifact has no parent",
                            )
                        })
                        .and_then(sync_directory),
                };
                if let Err(error) = synced {
                    record_snapshot_artifact_cleanup_failure(&self.state);
                    return Err(error);
                }
                self.state.armed.store(false, Ordering::Release);
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.state.armed.store(false, Ordering::Release);
                Ok(())
            }
            Err(error) => {
                #[cfg(test)]
                if error.kind() == io::ErrorKind::Interrupted {
                    self.abandon_for_simulated_process_loss();
                    return Err(error);
                }
                record_snapshot_artifact_cleanup_failure(&self.state);
                Err(error)
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn remove_identity_bound_snapshot_artifact(
    cleanup: &mut SnapshotArtifactCleanupState,
    expected: Option<SnapshotArtifactIdentity>,
    namespace: Option<&RetainedSnapshotDirectory>,
) -> io::Result<()> {
    let Some(expected) = expected else {
        return Err(io::Error::other(
            "session consensus snapshot artifact exists without an identity binding",
        ));
    };
    let sync_parent = || match namespace {
        Some(namespace) => namespace.sync(),
        None => cleanup
            .original
            .parent()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "session consensus snapshot artifact has no parent",
                )
            })
            .and_then(sync_directory),
    };
    if matches!(cleanup.location, SnapshotArtifactCleanupLocation::Unlinked) {
        return sync_parent();
    }
    let active = cleanup
        .active_path()
        .expect("unlinked state handled above")
        .to_path_buf();
    let opened = match namespace {
        Some(namespace) => namespace.open_read(active.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "session consensus snapshot artifact has no file name",
            )
        })?),
        None => open_snapshot_nofollow_read(&active),
    };
    let file = match opened {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if matches!(
                cleanup.location,
                SnapshotArtifactCleanupLocation::Tombstone(_)
                    | SnapshotArtifactCleanupLocation::UnlinkGuard { .. }
            ) {
                cleanup.location = SnapshotArtifactCleanupLocation::Unlinked;
                sync_parent()?;
            }
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    if snapshot_artifact_identity(&file.metadata()?)? != expected {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "session consensus snapshot artifact path was replaced",
        ));
    }
    let file_name = cleanup.original.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "session consensus snapshot artifact has no file name",
        )
    })?;
    if matches!(cleanup.location, SnapshotArtifactCleanupLocation::Original) {
        let parent = cleanup.original.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "session consensus snapshot artifact has no parent",
            )
        })?;
        let tombstone = parent.join(format!(
            ".{0}.opc-cleanup-{1}",
            file_name.to_string_lossy(),
            uuid::Uuid::new_v4()
        ));
        snapshot_artifact_cleanup_before_rename(&cleanup.original, &tombstone)?;
        #[cfg(target_os = "linux")]
        {
            if let Some(namespace) = namespace {
                namespace.rename_noreplace(
                    file_name,
                    tombstone.file_name().ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "snapshot tombstone has no name",
                        )
                    })?,
                )?;
            } else {
                let directory = std::fs::File::open(parent)?;
                rename_noreplace_in_directory(
                    &directory,
                    file_name,
                    tombstone.file_name().ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "snapshot tombstone has no name",
                        )
                    })?,
                )?;
            }
            // No fallible operation may occur between rename and this
            // transition: retries and Drop must target the exact tombstone.
            cleanup.location = SnapshotArtifactCleanupLocation::Tombstone(tombstone);
        }
        #[cfg(not(target_os = "linux"))]
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "identity-bound snapshot cleanup requires Linux renameat2",
        ));
    }
    if !matches!(
        cleanup.location,
        SnapshotArtifactCleanupLocation::UnlinkGuard { .. }
    ) {
        let tombstone = cleanup
            .tombstone_path()
            .expect("rename establishes tombstone state")
            .to_path_buf();
        sync_snapshot_artifact_cleanup_after_rename(&cleanup.original, &tombstone, namespace)?;
        #[cfg(all(test, target_os = "linux"))]
        simulated_snapshot_publication_process_loss(
            &cleanup.original,
            SnapshotPublicationCleanupCrashPoint::AfterOldTombstoneSync,
        )?;
        let tombstone_file = match namespace {
            Some(namespace) => namespace.open_read(tombstone.file_name().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "snapshot tombstone has no name",
                )
            })?)?,
            None => open_snapshot_nofollow_read(&tombstone)?,
        };
        if snapshot_artifact_identity(&tombstone_file.metadata()?)? != expected {
            drop(tombstone_file);
            #[cfg(target_os = "linux")]
            {
                let restored = match namespace {
                    Some(namespace) => namespace
                        .rename_noreplace(
                            tombstone.file_name().ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::InvalidInput,
                                    "snapshot tombstone has no name",
                                )
                            })?,
                            file_name,
                        )
                        .is_ok(),
                    None => {
                        let parent = cleanup.original.parent().ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "session consensus snapshot artifact has no parent",
                            )
                        })?;
                        let directory = std::fs::File::open(parent)?;
                        rename_noreplace_in_directory(
                            &directory,
                            tombstone.file_name().ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::InvalidInput,
                                    "snapshot tombstone has no name",
                                )
                            })?,
                            file_name,
                        )
                        .is_ok()
                    }
                };
                if restored {
                    cleanup.location = SnapshotArtifactCleanupLocation::Original;
                    sync_parent()?;
                }
            }
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "session consensus snapshot artifact changed during cleanup",
            ));
        }
        drop(tombstone_file);

        #[cfg(target_os = "linux")]
        {
            let guard = snapshot_artifact_unlink_guard_path(&tombstone, expected)?;
            snapshot_artifact_cleanup_after_final_identity_before_unlink(
                &cleanup.original,
                &tombstone,
                &guard,
            );
            #[cfg(unix)]
            {
                match namespace {
                    Some(namespace) => namespace.rename_noreplace(
                        tombstone.file_name().ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "snapshot tombstone has no name",
                            )
                        })?,
                        guard.file_name().ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "snapshot unlink guard has no name",
                            )
                        })?,
                    )?,
                    None => {
                        let parent = cleanup.original.parent().ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "session consensus snapshot artifact has no parent",
                            )
                        })?;
                        let directory = std::fs::File::open(parent)?;
                        rename_noreplace_in_directory(
                            &directory,
                            tombstone.file_name().ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::InvalidInput,
                                    "snapshot tombstone has no name",
                                )
                            })?,
                            guard.file_name().ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::InvalidInput,
                                    "snapshot unlink guard has no name",
                                )
                            })?,
                        )?;
                    }
                }
            }
            #[cfg(not(unix))]
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "identity-bound snapshot cleanup requires Unix",
            ));
            // Assign immediately after rename so a crash/retry can only replay
            // this exact private guard spelling.
            cleanup.location = SnapshotArtifactCleanupLocation::UnlinkGuard {
                guard: guard.clone(),
                tombstone,
            };
            sync_snapshot_artifact_cleanup_after_unlink_guard_rename(cleanup, namespace)?;
            #[cfg(all(test, target_os = "linux"))]
            simulated_snapshot_publication_process_loss(
                &cleanup.original,
                SnapshotPublicationCleanupCrashPoint::AfterOldUnlinkGuardSync,
            )?;

            let guard_file = match namespace {
                Some(namespace) => namespace.open_read(guard.file_name().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "snapshot unlink guard has no name",
                    )
                })?)?,
                None => open_snapshot_nofollow_read(&guard)?,
            };
            if snapshot_artifact_identity(&guard_file.metadata()?)? != expected {
                drop(guard_file);
                let (guard, tombstone) = match &cleanup.location {
                    SnapshotArtifactCleanupLocation::UnlinkGuard { guard, tombstone } => {
                        (guard.clone(), tombstone.clone())
                    }
                    _ => unreachable!("guard rename established unlink guard state"),
                };
                #[cfg(unix)]
                {
                    let restored = match namespace {
                        Some(namespace) => namespace.rename_noreplace(
                            guard.file_name().ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::InvalidInput,
                                    "snapshot unlink guard has no name",
                                )
                            })?,
                            tombstone.file_name().ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::InvalidInput,
                                    "snapshot tombstone has no name",
                                )
                            })?,
                        ),
                        None => {
                            let parent = cleanup.original.parent().ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::InvalidInput,
                                    "session consensus snapshot artifact has no parent",
                                )
                            })?;
                            let directory = std::fs::File::open(parent)?;
                            rename_noreplace_in_directory(
                                &directory,
                                guard.file_name().ok_or_else(|| {
                                    io::Error::new(
                                        io::ErrorKind::InvalidInput,
                                        "snapshot unlink guard has no name",
                                    )
                                })?,
                                tombstone.file_name().ok_or_else(|| {
                                    io::Error::new(
                                        io::ErrorKind::InvalidInput,
                                        "snapshot tombstone has no name",
                                    )
                                })?,
                            )
                        }
                    };
                    if restored.is_ok() {
                        cleanup.location = SnapshotArtifactCleanupLocation::Tombstone(tombstone);
                        sync_parent()?;
                    }
                }
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "session consensus snapshot artifact changed during final unlink guard rename",
                ));
            }
            drop(guard_file);
        }
        #[cfg(not(target_os = "linux"))]
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "identity-bound snapshot cleanup requires Linux",
        ));
    } else {
        // A previous guard rename succeeded but its sync/unlink did not. Keep
        // replay on this exact basename; never manufacture a nested guard.
        sync_snapshot_artifact_cleanup_after_unlink_guard_rename(cleanup, namespace)?;
    }
    drop(file);
    let unlink_path = cleanup
        .active_path()
        .expect("final unlink guard is an active cleanup location")
        .to_path_buf();
    match namespace {
        Some(namespace) => namespace.unlink(unlink_path.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "snapshot final unlink guard has no name",
            )
        })?)?,
        None => std::fs::remove_file(&unlink_path)?,
    }
    cleanup.location = SnapshotArtifactCleanupLocation::Unlinked;
    sync_parent()
}

#[cfg(not(target_os = "linux"))]
fn remove_identity_bound_snapshot_artifact(
    _cleanup: &mut SnapshotArtifactCleanupState,
    _expected: Option<SnapshotArtifactIdentity>,
    _namespace: Option<&RetainedSnapshotDirectory>,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "identity-bound snapshot cleanup requires Linux",
    ))
}

impl Drop for SnapshotArtifactState {
    fn drop(&mut self) {
        if !self.armed.load(Ordering::Acquire) {
            return;
        }
        let identity = self.identity.lock().ok().and_then(|identity| *identity);
        let result = self
            .cleanup
            .lock()
            .map_err(|_| io::Error::other("snapshot artifact cleanup lock poisoned"))
            .and_then(|mut cleanup| {
                remove_identity_bound_snapshot_artifact(
                    &mut cleanup,
                    identity,
                    self.namespace.as_deref(),
                )
            });
        match result {
            Ok(()) => {
                let synced = match &self.namespace {
                    Some(namespace) => namespace.sync(),
                    None => self
                        .path
                        .parent()
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "session consensus snapshot artifact has no parent",
                            )
                        })
                        .and_then(sync_directory),
                };
                if synced.is_err() {
                    record_snapshot_artifact_cleanup_failure(self);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => record_snapshot_artifact_cleanup_failure(self),
        }
    }
}

#[cfg(test)]
fn promoted_verify_gates(
) -> &'static std::sync::Mutex<BTreeMap<PathBuf, std::sync::Arc<SnapshotArtifactGate>>> {
    static GATES: std::sync::OnceLock<
        std::sync::Mutex<BTreeMap<PathBuf, std::sync::Arc<SnapshotArtifactGate>>>,
    > = std::sync::OnceLock::new();
    GATES.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()))
}

#[cfg(test)]
struct PromotedVerifyGateGuard {
    snapshot_directory: PathBuf,
    gate: std::sync::Arc<SnapshotArtifactGate>,
}

#[cfg(test)]
impl PromotedVerifyGateGuard {
    fn install(snapshot_directory: PathBuf, gate: std::sync::Arc<SnapshotArtifactGate>) -> Self {
        promoted_verify_gates()
            .lock()
            .expect("set promoted verify gate")
            .insert(snapshot_directory.clone(), Arc::clone(&gate));
        Self {
            snapshot_directory,
            gate,
        }
    }
}

#[cfg(test)]
impl Drop for PromotedVerifyGateGuard {
    fn drop(&mut self) {
        self.gate.release();
        let mut gates = promoted_verify_gates()
            .lock()
            .expect("clear promoted verify gate");
        if gates
            .get(&self.snapshot_directory)
            .is_some_and(|installed| Arc::ptr_eq(installed, &self.gate))
        {
            gates.remove(&self.snapshot_directory);
        }
    }
}

#[cfg(test)]
async fn wait_before_promoted_verify(final_path: &Path) {
    let Some(snapshot_directory) = final_path.parent() else {
        return;
    };
    let gate = promoted_verify_gates()
        .lock()
        .ok()
        .and_then(|gates| gates.get(snapshot_directory).cloned());
    if let Some(gate) = gate {
        gate.block_if_armed().await;
    }
}

/// Test-only source boundary for fixed installation. It is immediately after
/// the one permitted complete read of a receiver-owned mutable envelope, so a
/// pre-opened writer can prove no later source read participates in either
/// database extraction or publication.
#[cfg(test)]
fn fixed_install_source_copy_gates(
) -> &'static std::sync::Mutex<BTreeMap<PathBuf, std::sync::Arc<SnapshotArtifactGate>>> {
    static GATES: std::sync::OnceLock<
        std::sync::Mutex<BTreeMap<PathBuf, std::sync::Arc<SnapshotArtifactGate>>>,
    > = std::sync::OnceLock::new();
    GATES.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()))
}

#[cfg(all(test, target_os = "linux"))]
struct FixedInstallSourceCopyGateGuard {
    snapshot_directory: PathBuf,
    gate: std::sync::Arc<SnapshotArtifactGate>,
}

#[cfg(all(test, target_os = "linux"))]
impl FixedInstallSourceCopyGateGuard {
    fn install(snapshot_directory: PathBuf, gate: std::sync::Arc<SnapshotArtifactGate>) -> Self {
        fixed_install_source_copy_gates()
            .lock()
            .expect("set fixed install source-copy gate")
            .insert(snapshot_directory.clone(), Arc::clone(&gate));
        Self {
            snapshot_directory,
            gate,
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
impl Drop for FixedInstallSourceCopyGateGuard {
    fn drop(&mut self) {
        self.gate.release();
        let mut gates = fixed_install_source_copy_gates()
            .lock()
            .expect("clear fixed install source-copy gate");
        if gates
            .get(&self.snapshot_directory)
            .is_some_and(|installed| Arc::ptr_eq(installed, &self.gate))
        {
            gates.remove(&self.snapshot_directory);
        }
    }
}

#[cfg(test)]
async fn wait_before_fixed_install_source_copy(final_path: &Path) {
    let Some(snapshot_directory) = final_path.parent() else {
        return;
    };
    let gate = fixed_install_source_copy_gates()
        .lock()
        .ok()
        .and_then(|gates| gates.get(snapshot_directory).cloned());
    if let Some(gate) = gate {
        gate.block_if_armed().await;
    }
}

#[cfg(test)]
fn seal_in_place_gate() -> &'static std::sync::Mutex<Option<std::sync::Arc<SnapshotArtifactGate>>> {
    static GATE: std::sync::OnceLock<
        std::sync::Mutex<Option<std::sync::Arc<SnapshotArtifactGate>>>,
    > = std::sync::OnceLock::new();
    GATE.get_or_init(|| std::sync::Mutex::new(None))
}

#[cfg(test)]
async fn wait_after_in_place_seal_cleanup_is_armed() {
    let gate = seal_in_place_gate()
        .lock()
        .map(|gate| gate.clone())
        .unwrap_or(None);
    if let Some(gate) = gate {
        gate.block_if_armed().await;
    }
}

#[cfg(test)]
fn in_place_seal_test_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

#[cfg(test)]
fn fixed_prepublication_verify_gates(
) -> &'static std::sync::Mutex<BTreeMap<PathBuf, std::sync::Arc<SnapshotArtifactGate>>> {
    static GATES: std::sync::OnceLock<
        std::sync::Mutex<BTreeMap<PathBuf, std::sync::Arc<SnapshotArtifactGate>>>,
    > = std::sync::OnceLock::new();
    GATES.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()))
}

#[cfg(test)]
struct FixedPrepublicationVerifyGateGuard {
    snapshot_directory: PathBuf,
    gate: std::sync::Arc<SnapshotArtifactGate>,
}

#[cfg(test)]
impl FixedPrepublicationVerifyGateGuard {
    fn install(snapshot_directory: PathBuf, gate: std::sync::Arc<SnapshotArtifactGate>) -> Self {
        fixed_prepublication_verify_gates()
            .lock()
            .expect("set fixed prepublication verify gate")
            .insert(snapshot_directory.clone(), Arc::clone(&gate));
        Self {
            snapshot_directory,
            gate,
        }
    }
}

#[cfg(test)]
impl Drop for FixedPrepublicationVerifyGateGuard {
    fn drop(&mut self) {
        self.gate.release();
        let mut gates = fixed_prepublication_verify_gates()
            .lock()
            .expect("clear fixed prepublication verify gate");
        if gates
            .get(&self.snapshot_directory)
            .is_some_and(|installed| Arc::ptr_eq(installed, &self.gate))
        {
            gates.remove(&self.snapshot_directory);
        }
    }
}

#[cfg(test)]
async fn wait_before_fixed_prepublication_verify(final_path: &Path) {
    let Some(snapshot_directory) = final_path.parent() else {
        return;
    };
    let gate = fixed_prepublication_verify_gates()
        .lock()
        .ok()
        .and_then(|gates| gates.get(snapshot_directory).cloned());
    if let Some(gate) = gate {
        gate.block_if_armed().await;
    }
}

/// Test-only pause immediately before the retained-descriptor recovery fence
/// that precedes durable current-snapshot publication. It lets a causal test
/// terminalize an already Active remote recovery latch after the builder has
/// selected S1 but before it could publish S2.
#[cfg(test)]
fn recovery_publication_fence_gates(
) -> &'static std::sync::Mutex<BTreeMap<PathBuf, std::sync::Arc<SnapshotArtifactGate>>> {
    static GATES: std::sync::OnceLock<
        std::sync::Mutex<BTreeMap<PathBuf, std::sync::Arc<SnapshotArtifactGate>>>,
    > = std::sync::OnceLock::new();
    GATES.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()))
}

#[cfg(all(test, target_os = "linux"))]
struct RecoveryPublicationFenceGateGuard {
    snapshot_directory: PathBuf,
    gate: std::sync::Arc<SnapshotArtifactGate>,
}

#[cfg(all(test, target_os = "linux"))]
impl RecoveryPublicationFenceGateGuard {
    fn install(snapshot_directory: PathBuf, gate: std::sync::Arc<SnapshotArtifactGate>) -> Self {
        recovery_publication_fence_gates()
            .lock()
            .expect("set recovery publication fence gate")
            .insert(snapshot_directory.clone(), Arc::clone(&gate));
        Self {
            snapshot_directory,
            gate,
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
impl Drop for RecoveryPublicationFenceGateGuard {
    fn drop(&mut self) {
        self.gate.release();
        let mut gates = recovery_publication_fence_gates()
            .lock()
            .expect("clear recovery publication fence gate");
        if gates
            .get(&self.snapshot_directory)
            .is_some_and(|installed| Arc::ptr_eq(installed, &self.gate))
        {
            gates.remove(&self.snapshot_directory);
        }
    }
}

#[cfg(test)]
async fn wait_before_recovery_publication_fence(snapshot_directory: &Path) {
    let gate = recovery_publication_fence_gates()
        .lock()
        .ok()
        .and_then(|gates| gates.get(snapshot_directory).cloned());
    if let Some(gate) = gate {
        gate.block_if_armed().await;
    }
}

#[cfg(test)]
fn fixed_snapshot_return_gates(
) -> &'static std::sync::Mutex<BTreeMap<PathBuf, std::sync::Arc<SnapshotArtifactGate>>> {
    static GATES: std::sync::OnceLock<
        std::sync::Mutex<BTreeMap<PathBuf, std::sync::Arc<SnapshotArtifactGate>>>,
    > = std::sync::OnceLock::new();
    GATES.get_or_init(|| std::sync::Mutex::new(BTreeMap::new()))
}

#[cfg(all(test, target_os = "linux"))]
struct FixedSnapshotReturnGateGuard {
    snapshot_directory: PathBuf,
    gate: std::sync::Arc<SnapshotArtifactGate>,
}

#[cfg(all(test, target_os = "linux"))]
impl FixedSnapshotReturnGateGuard {
    fn install(snapshot_directory: PathBuf, gate: std::sync::Arc<SnapshotArtifactGate>) -> Self {
        fixed_snapshot_return_gates()
            .lock()
            .expect("set fixed snapshot return gate")
            .insert(snapshot_directory.clone(), Arc::clone(&gate));
        Self {
            snapshot_directory,
            gate,
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
impl Drop for FixedSnapshotReturnGateGuard {
    fn drop(&mut self) {
        self.gate.release();
        let mut gates = fixed_snapshot_return_gates()
            .lock()
            .expect("clear fixed snapshot return gate");
        if gates
            .get(&self.snapshot_directory)
            .is_some_and(|installed| Arc::ptr_eq(installed, &self.gate))
        {
            gates.remove(&self.snapshot_directory);
        }
    }
}

#[cfg(test)]
async fn wait_before_fixed_snapshot_return(final_path: &Path) {
    let Some(snapshot_directory) = final_path.parent() else {
        return;
    };
    let gate = fixed_snapshot_return_gates()
        .lock()
        .ok()
        .and_then(|gates| gates.get(snapshot_directory).cloned());
    if let Some(gate) = gate {
        gate.block_if_armed().await;
    }
}

/// Fail-closed errors emitted while binding an existing SQLite database to a
/// durable consensus identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum SessionConsensusStorageError {
    /// The explicitly required snapshot integrity capability is unavailable.
    #[error("required session consensus snapshot integrity is unavailable")]
    SnapshotIntegrityUnavailable,
    /// Durable consensus initialization is unsupported on this platform.
    #[error("session consensus storage is unsupported on this platform")]
    UnsupportedPlatform,
    /// Legacy session authority exists without a durable consensus identity.
    #[error("session consensus recovery is required before this database can join a cluster")]
    RecoveryRequired,
    /// The persisted cluster/configuration/epoch differs from the requested scope.
    #[error("session consensus storage identity does not match this configuration")]
    IdentityMismatch,
    /// The database was created by another consensus storage schema.
    #[error("unsupported session consensus storage schema")]
    SchemaVersionMismatch,
    /// A required row, constraint, or typed high-water mark is invalid.
    #[error("session consensus durable state is corrupt")]
    CorruptState,
    /// The supplied identity could not be represented by the durable schema.
    #[error("invalid session consensus storage identity")]
    InvalidIdentity,
    /// SQLite or snapshot storage could not be initialized.
    #[error("session consensus storage is unavailable")]
    BackendUnavailable,
}

/// Immutable authority model bound to one durable consensus database.
///
/// Dynamic authority permits the existing staged membership-transition model.
/// Fixed authority is set only when a pristine database is first admitted and
/// requires the original storage identity on every later open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConsensusAuthorityProfile {
    /// The durable store uses the normal dynamic-membership authority model.
    Dynamic,
    /// The durable store is permanently bound to one exact fixed quorum.
    FixedImmutable,
}

const fn snapshot_install_reservation_entries(profile: ConsensusAuthorityProfile) -> usize {
    match profile {
        // Dynamic installation retains the received envelope while extracting
        // one SQLite group. Fixed installation promotes that envelope in
        // place, so only the extracted group can increase the entry count.
        ConsensusAuthorityProfile::Dynamic => SNAPSHOT_DYNAMIC_INSTALL_RESERVATION_ENTRIES,
        ConsensusAuthorityProfile::FixedImmutable => SNAPSHOT_FIXED_INSTALL_RESERVATION_ENTRIES,
    }
}

/// Serialized Openraft vote/log persistence.
pub(crate) struct SqliteConsensusLogStore {
    core: SqliteConsensusCore,
    _snapshot_directory_lease: Arc<SnapshotDirectoryLease>,
    // Last-drop notification follows release of the log reader's SQLite core.
    shutdown_guard: ConsensusStorageShutdownGuard,
}

/// The retained authority through which a live consensus store consumes a
/// terminal recovery handoff published after its SQLite core was opened.
///
/// This intentionally retains the same core and admitted namespace lease as
/// the log store.  In particular, it never reopens `core.snapshot_dir`: the
/// selected current snapshot is opened only relative to the original D1
/// descriptor, then that exact descriptor is supplied to the connection-aware
/// terminal classifier and the existing descriptor-bound validation/consume
/// path.
pub(crate) struct LiveTerminalRecoveryHandoffConsumer {
    core: SqliteConsensusCore,
    snapshot_directory_lease: Arc<SnapshotDirectoryLease>,
}

/// The durable recovery state observed by a live handoff probe.
///
/// `Active` deliberately remains closed without being treated as a malformed
/// terminal record. `Clear` covers only an absent sidecar; callers which
/// first observed a pending backend gate must recheck that gate before
/// granting readiness. `Consumed` proves either that this live core completed
/// the descriptor-bound terminal path or that it reclassified the exact,
/// database-incarnation-bound consumed tombstone on an idempotent retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LiveTerminalRecoveryHandoffState {
    Active,
    Clear,
    Consumed,
}

/// Recovery-finalization ownership of one live core's snapshot transaction.
///
/// Recovery acquires this before pinning S1 and retains it through terminal
/// publication and descriptor-bound consumption.  The embedded gate identity
/// makes a token from another core fail closed rather than serializing the
/// wrong namespace.
#[derive(Clone)]
pub(crate) struct LiveTerminalRecoveryHandoffGate {
    snapshot_gate: Arc<tokio::sync::Mutex<()>>,
    _guard: Arc<tokio::sync::OwnedMutexGuard<()>>,
}

/// A cancelled integrity worker must keep the single snapshot transaction
/// and namespace lease until its last descriptor read has completed.
#[derive(Clone)]
struct SnapshotIntegrityWork {
    _gate: LiveTerminalRecoveryHandoffGate,
    _lease: Arc<SnapshotDirectoryLease>,
}

async fn seal_snapshot_pin(
    mut pinned: PinnedSqliteFile,
    policy: SnapshotIntegrityPolicy,
    expected_payload_checksum: Option<[u8; 32]>,
    retention: Option<SnapshotIntegrityWork>,
) -> io::Result<PinnedSqliteFile> {
    tokio::task::spawn_blocking(move || {
        let _retention = retention;
        pinned.seal_with_integrity(policy)?;
        if let Some(checksum) = expected_payload_checksum {
            pinned.verify_payload_checksum(checksum)?;
        }
        Ok(pinned)
    })
    .await
    .map_err(|_| io::Error::other("snapshot integrity worker unavailable"))?
}

async fn verify_received_snapshot(
    mut pinned: PinnedSqliteFile,
    path: PathBuf,
    retention: SnapshotIntegrityWork,
) -> io::Result<(
    PinnedSqliteFile,
    [u8; 32],
    super::snapshot::ImmutableSnapshotEnvelope,
)> {
    tokio::task::spawn_blocking(move || {
        let _retention = retention;
        let (checksum, length) = pinned.snapshot_envelope_footer_from_pinned_descriptor(
            &path,
            SNAPSHOT_FOOTER_MAGIC,
            SNAPSHOT_FOOTER_BYTES,
            SNAPSHOT_MAX_BYTES,
        )?;
        let envelope = pinned.verify_snapshot_envelope_and_bind_immutable_generation(
            &path,
            SNAPSHOT_FOOTER_MAGIC,
            SNAPSHOT_FOOTER_BYTES,
            SNAPSHOT_MAX_BYTES,
            checksum,
            length,
        )?;
        Ok((pinned, checksum, envelope))
    })
    .await
    .map_err(|_| io::Error::other("snapshot integrity worker unavailable"))?
}

/// Capture a restart/transfer proof and authenticate it against the durable
/// metadata on a blocking worker, never under the live SQLite connection.
async fn verify_admitted_snapshot(
    file: std::fs::File,
    lease: Arc<SnapshotDirectoryLease>,
    name: std::ffi::OsString,
    policy: SnapshotIntegrityPolicy,
    checksum: [u8; 32],
    length: u64,
) -> io::Result<PinnedSqliteFile> {
    tokio::task::spawn_blocking(move || {
        let path = lease.namespace.sqlite_child_path(&name)?;
        let mut pinned = PinnedSqliteFile::from_file_and_verify_in_namespace(
            file,
            Arc::clone(&lease.namespace),
            &name,
            policy,
        )?;
        let verified = pinned.verify_snapshot_envelope_and_bind_immutable_generation(
            &path,
            SNAPSHOT_FOOTER_MAGIC,
            SNAPSHOT_FOOTER_BYTES,
            SNAPSHOT_MAX_BYTES,
            checksum,
            length,
        )?;
        pinned.verify_bound_immutable_snapshot_envelope(&path, verified.total_length)?;
        Ok(pinned)
    })
    .await
    .map_err(|_| io::Error::other("snapshot integrity worker unavailable"))?
}

impl LiveTerminalRecoveryHandoffConsumer {
    pub(crate) fn snapshot_integrity_policy(&self) -> SnapshotIntegrityPolicy {
        self.core.snapshot_integrity
    }

    fn from_live_snapshot_owner(
        core: &SqliteConsensusCore,
        snapshot_directory_lease: &Arc<SnapshotDirectoryLease>,
    ) -> Self {
        Self {
            core: core.clone(),
            snapshot_directory_lease: Arc::clone(snapshot_directory_lease),
        }
    }

    /// Acquire the exact live core's snapshot transaction gate for an
    /// operator-recovery finalization transaction.
    pub(crate) async fn acquire_gate(
        &self,
    ) -> Result<LiveTerminalRecoveryHandoffGate, SessionConsensusStorageError> {
        let snapshot_gate = Arc::clone(&self.core.snapshot_gate);
        let guard = Arc::clone(&snapshot_gate).lock_owned().await;
        Ok(LiveTerminalRecoveryHandoffGate {
            snapshot_gate,
            _guard: Arc::new(guard),
        })
    }

    /// Reconcile the recovery sidecar observed by this already-open core.
    ///
    /// Clear and Active observations re-prove the SQLite descriptor/path
    /// binding and sidecar state without contending on snapshot work. Any
    /// terminal evidence, and a pending slot left by a cancelled or failed
    /// prior attempt, enters the existing gate-held validation path without
    /// replacing retained classifier evidence. A valid Active sidecar remains
    /// closed; malformed terminal evidence remains `CorruptState`.
    pub(crate) async fn reconcile(
        &self,
    ) -> Result<LiveTerminalRecoveryHandoffState, SessionConsensusStorageError> {
        if !self.core.terminal_recovery_handoff_pending()? {
            match self.probe_live_recovery_handoff().await? {
                consensus::LiveTerminalRecoveryHandoffProbe::Clear => {
                    return Ok(LiveTerminalRecoveryHandoffState::Clear);
                }
                consensus::LiveTerminalRecoveryHandoffProbe::Active => {
                    return Ok(LiveTerminalRecoveryHandoffState::Active);
                }
                consensus::LiveTerminalRecoveryHandoffProbe::TerminalNeedsSnapshot => {}
            }
        }
        let gate = self.acquire_gate().await?;
        #[cfg(test)]
        observe_live_terminal_recovery_full_reconciliation();
        self.reconcile_with_gate(&gate).await
    }

    /// Observe a nonterminal recovery state without selecting a snapshot.
    /// The SQLite helper repeats the VFS-descriptor/public-path binding and
    /// final sidecar absence fence on every Clear result; callers therefore
    /// never reuse a cached readiness decision.
    async fn probe_live_recovery_handoff(
        &self,
    ) -> Result<consensus::LiveTerminalRecoveryHandoffProbe, SessionConsensusStorageError> {
        let database = self
            .core
            .database_file
            .as_ref()
            .map(|file| file.path())
            .ok_or(SessionConsensusStorageError::CorruptState)?;
        let conn = self.core.conn.lock().await;
        consensus::probe_live_terminal_recovery_handoff_with_connection_sync(database, &conn)
            .map_err(|_| SessionConsensusStorageError::CorruptState)
    }

    /// Reconcile while the caller retains this core's snapshot transaction
    /// gate across a larger recovery finalization transaction.
    pub(crate) async fn reconcile_with_gate(
        &self,
        gate: &LiveTerminalRecoveryHandoffGate,
    ) -> Result<LiveTerminalRecoveryHandoffState, SessionConsensusStorageError> {
        if !Arc::ptr_eq(&self.core.snapshot_gate, &gate.snapshot_gate) {
            return Err(SessionConsensusStorageError::CorruptState);
        }
        // Current-snapshot selection, descriptor admission, terminal
        // classification, and the later validation/consume pass must observe
        // one serialized snapshot namespace state.  In particular, do not
        // permit a concurrent receive/install/build to change the durable
        // current record between the descriptor-bound classifier and the
        // descriptor-bound consumer.
        if self.core.terminal_recovery_handoff_pending()? {
            validate_and_clean_snapshot_directory(&self.core, Some(&self.snapshot_directory_lease))
                .await?;
            return Ok(LiveTerminalRecoveryHandoffState::Consumed);
        }

        let current = {
            let conn = self.core.conn.lock().await;
            consensus::read_current_snapshot_sync(&conn, self.core.storage_identity)
                .map_err(|_| SessionConsensusStorageError::CorruptState)?
        };
        let admitted_current_file = match current.as_ref() {
            Some((_, file_name, _, _)) => Some(
                open_snapshot_child_in_namespace(
                    Arc::clone(&self.snapshot_directory_lease.namespace),
                    std::ffi::OsString::from(file_name),
                )
                .await
                .map_err(|_| SessionConsensusStorageError::CorruptState)?,
            ),
            None => None,
        };

        match self
            .core
            .install_live_terminal_recovery_handoff_from_admitted_snapshot(
                current
                    .as_ref()
                    .map(|(_, file_name, _, _)| file_name.as_str()),
                admitted_current_file.as_ref(),
            )
            .await?
        {
            consensus::LiveTerminalRecoveryHandoffInstallOutcome::Active => {
                return Ok(LiveTerminalRecoveryHandoffState::Active);
            }
            consensus::LiveTerminalRecoveryHandoffInstallOutcome::Clear => {
                return Ok(LiveTerminalRecoveryHandoffState::Clear);
            }
            // This is not the ordinary Clear path: consensus just held and
            // revalidated the consumed terminal sidecar against this core's
            // SQLite descriptor.  A recovery-manager retry may therefore
            // complete idempotently after its first local consumption.
            consensus::LiveTerminalRecoveryHandoffInstallOutcome::AlreadyConsumed => {
                return Ok(LiveTerminalRecoveryHandoffState::Consumed);
            }
            consensus::LiveTerminalRecoveryHandoffInstallOutcome::Installed => {}
        }

        validate_and_clean_snapshot_directory(&self.core, Some(&self.snapshot_directory_lease))
            .await?;
        Ok(LiveTerminalRecoveryHandoffState::Consumed)
    }

    /// Acquire the SQLite connection which will publish current metadata,
    /// then select and open its current snapshot on the bounded blocking
    /// pool before classifying the recovery latch with that *same*
    /// connection. The returned guard stays held through the caller's
    /// irreversible write, so terminalization cannot slip between selection,
    /// D1 descriptor admission, classification, and publication.
    async fn acquire_publication_connection(
        &self,
        gate: &LiveTerminalRecoveryHandoffGate,
    ) -> Result<tokio::sync::OwnedMutexGuard<rusqlite::Connection>, SessionConsensusStorageError>
    {
        if !Arc::ptr_eq(&self.core.snapshot_gate, &gate.snapshot_gate) {
            return Err(SessionConsensusStorageError::CorruptState);
        }
        let core = self.core.clone();
        let namespace = Arc::clone(&self.snapshot_directory_lease.namespace);
        let conn = Arc::clone(&core.conn).lock_owned().await;
        tokio::task::spawn_blocking(move || {
            if core.terminal_recovery_handoff_pending()? {
                return Err(SessionConsensusStorageError::BackendUnavailable);
            }
            let current = consensus::read_current_snapshot_sync(&conn, core.storage_identity)
                .map_err(|_| SessionConsensusStorageError::CorruptState)?;
            let (selected_name, admitted_snapshot_file) = match current {
                Some((_, file_name, _, _)) => {
                    let file = namespace
                        .open_read(std::ffi::OsStr::new(&file_name))
                        .map_err(|_| SessionConsensusStorageError::CorruptState)?;
                    (Some(file_name), Some(file))
                }
                None => (None, None),
            };
            match core
                .install_live_terminal_recovery_handoff_from_admitted_snapshot_with_connection(
                    &conn,
                    selected_name.as_deref(),
                    admitted_snapshot_file.as_ref(),
                )? {
                consensus::LiveTerminalRecoveryHandoffInstallOutcome::Clear
                | consensus::LiveTerminalRecoveryHandoffInstallOutcome::AlreadyConsumed => Ok(conn),
                consensus::LiveTerminalRecoveryHandoffInstallOutcome::Active
                | consensus::LiveTerminalRecoveryHandoffInstallOutcome::Installed => {
                    Err(SessionConsensusStorageError::BackendUnavailable)
                }
            }
        })
        .await
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?
    }

    /// Strict recovery-manager entry point.  A manager invokes this only
    /// after publishing Terminal(PendingHandoff), so an Active/Clear result
    /// is a fail-closed corruption rather than a readiness observation.
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) async fn consume(&self) -> Result<(), SessionConsensusStorageError> {
        let gate = self.acquire_gate().await?;
        self.consume_with_gate(&gate).await
    }

    /// Strict terminal-manager consumption under an already-held finalization
    /// gate.  Active/Clear evidence at this boundary is corruption: the
    /// manager is required to call it only after Terminal(PendingHandoff).
    pub(crate) async fn consume_with_gate(
        &self,
        gate: &LiveTerminalRecoveryHandoffGate,
    ) -> Result<(), SessionConsensusStorageError> {
        match self.reconcile_with_gate(gate).await? {
            LiveTerminalRecoveryHandoffState::Consumed => Ok(()),
            LiveTerminalRecoveryHandoffState::Active | LiveTerminalRecoveryHandoffState::Clear => {
                Err(SessionConsensusStorageError::CorruptState)
            }
        }
    }
}

impl SqliteConsensusLogStore {
    /// Retain a recovery-only terminal consumer before Openraft takes this log
    /// store.  The consumer is independent of Openraft reader clones but owns
    /// the same D1 namespace authority for its entire store lifetime.
    pub(crate) fn live_terminal_recovery_handoff_consumer(
        &self,
    ) -> LiveTerminalRecoveryHandoffConsumer {
        LiveTerminalRecoveryHandoffConsumer::from_live_snapshot_owner(
            &self.core,
            &self._snapshot_directory_lease,
        )
    }

    fn tracked_reader(&self) -> Self {
        Self {
            core: self.core.clone(),
            _snapshot_directory_lease: Arc::clone(&self._snapshot_directory_lease),
            shutdown_guard: self.shutdown_guard.child(),
        }
    }
}

struct ConsensusStorageShutdownCompletion {
    active_owners: AtomicUsize,
    notify: tokio::sync::Notify,
}

/// Observation that every Openraft-owned SQLite storage handle has exited.
#[derive(Clone)]
pub(crate) struct ConsensusStorageShutdownObserver(Arc<ConsensusStorageShutdownCompletion>);

impl ConsensusStorageShutdownObserver {
    pub(crate) async fn wait(&self) {
        loop {
            if self.0.active_owners.load(Ordering::Acquire) == 0 {
                return;
            }
            let notified = self.0.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.0.active_owners.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }
}

struct ConsensusStorageShutdownGuard(Option<Arc<ConsensusStorageShutdownCompletion>>);

impl ConsensusStorageShutdownGuard {
    fn tracked() -> Self {
        Self(Some(Arc::new(ConsensusStorageShutdownCompletion {
            active_owners: AtomicUsize::new(1),
            notify: tokio::sync::Notify::new(),
        })))
    }

    const fn detached() -> Self {
        Self(None)
    }

    fn observer(&self) -> Option<ConsensusStorageShutdownObserver> {
        self.0
            .as_ref()
            .map(|completion| ConsensusStorageShutdownObserver(Arc::clone(completion)))
    }

    fn child(&self) -> Self {
        let Some(completion) = self.0.as_ref() else {
            return Self::detached();
        };
        let incremented =
            completion
                .active_owners
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    current.checked_add(1)
                });
        assert!(
            incremented.is_ok(),
            "bounded consensus storage ownership cannot overflow"
        );
        Self(Some(Arc::clone(completion)))
    }
}

impl Drop for ConsensusStorageShutdownGuard {
    fn drop(&mut self) {
        let Some(completion) = self.0.take() else {
            return;
        };
        if completion.active_owners.fetch_sub(1, Ordering::AcqRel) == 1 {
            completion.notify.notify_waiters();
        }
    }
}

impl SqliteConsensusLogStore {
    /// The one checkpoint lane attached to this exact consensus core.
    pub(crate) fn proactive_checkpoint_lane(
        &self,
    ) -> Option<Arc<consensus::ProactiveCheckpointLane>> {
        self.core.proactive_checkpoint_lane()
    }

    pub(crate) fn consensus_log_prune_lane(&self) -> Option<Arc<consensus::ConsensusLogPruneLane>> {
        self.core.consensus_log_prune_lane()
    }
}

/// Persistent session state machine and snapshot owner.
pub(crate) struct SqliteConsensusStateMachine {
    core: SqliteConsensusCore,
    _snapshot_directory_lease: Arc<SnapshotDirectoryLease>,
    membership_admission: Option<SessionRaftPeerDirectory>,
    #[cfg(test)]
    membership_observations: Arc<AtomicUsize>,
    #[cfg(test)]
    membership_observation_readback_witness: Option<Arc<AtomicBool>>,
    #[cfg(test)]
    membership_observations_before_readback: Arc<AtomicUsize>,
    // This field must remain last: its Drop is the completion edge after the
    // worker has released the SQLite core and membership admission fields.
    shutdown_guard: ConsensusStorageShutdownGuard,
}

#[cfg(test)]
impl Clone for SqliteConsensusStateMachine {
    fn clone(&self) -> Self {
        Self {
            core: self.core.clone(),
            _snapshot_directory_lease: Arc::clone(&self._snapshot_directory_lease),
            membership_admission: self.membership_admission.clone(),
            membership_observations: Arc::clone(&self.membership_observations),
            membership_observation_readback_witness: self
                .membership_observation_readback_witness
                .clone(),
            membership_observations_before_readback: Arc::clone(
                &self.membership_observations_before_readback,
            ),
            // Test-only direct state-machine clones are not worker owners and
            // must never satisfy the store's shutdown barrier.
            shutdown_guard: ConsensusStorageShutdownGuard::detached(),
        }
    }
}

impl SqliteConsensusStateMachine {
    pub(crate) fn shutdown_observer(&self) -> Option<ConsensusStorageShutdownObserver> {
        self.shutdown_guard.observer()
    }

    async fn begin_membership_apply(&self) -> Option<tokio::sync::OwnedRwLockWriteGuard<()>> {
        match self.membership_admission.as_ref() {
            Some(admission) => Some(admission.begin_membership_apply().await),
            None => None,
        }
    }

    fn observe_applied_membership(
        &self,
        membership: &StoredMembership<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>,
    ) -> Result<(), SessionRaftAdapterError> {
        let Some(admission) = self.membership_admission.as_ref() else {
            return Ok(());
        };
        admission.observe_applied_membership(membership)?;
        #[cfg(test)]
        {
            if self
                .membership_observation_readback_witness
                .as_ref()
                .is_some_and(|witness| !witness.load(Ordering::SeqCst))
            {
                self.membership_observations_before_readback
                    .fetch_add(1, Ordering::SeqCst);
            }
            self.membership_observations.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    }

    #[cfg(test)]
    fn membership_observations_for_test(&self) -> usize {
        self.membership_observations.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    fn require_membership_observation_after_readback_for_test(
        &mut self,
        readback_witness: Arc<AtomicBool>,
    ) {
        assert!(
            self.membership_observation_readback_witness.is_none(),
            "membership observation readback witness is already armed"
        );
        self.membership_observation_readback_witness = Some(readback_witness);
    }

    #[cfg(test)]
    fn membership_observations_before_readback_for_test(&self) -> usize {
        self.membership_observations_before_readback
            .load(Ordering::SeqCst)
    }

    /// Read the durable application chain head for storage qualification.
    #[cfg(test)]
    pub(crate) async fn proposal_state(
        &self,
    ) -> Result<
        (
            u64,
            super::SessionConsensusEntryDigest,
            Option<opc_types::Timestamp>,
        ),
        SessionConsensusStorageError,
    > {
        let conn = self.core.conn.lock().await;
        consensus::proposal_state_sync(&conn, self.core.storage_identity)
            .map_err(|_| SessionConsensusStorageError::CorruptState)
    }
}

/// Snapshot builder holding a point-in-time SQLite backup, not an in-memory
/// serialization of the session database.
pub(crate) struct SqliteConsensusSnapshotBuilder {
    core: SqliteConsensusCore,
    _snapshot_directory_lease: Arc<SnapshotDirectoryLease>,
    // Last-drop notification follows release of the builder's SQLite core.
    _shutdown_guard: ConsensusStorageShutdownGuard,
}

/// Detached blocking snapshot capture and its exact SQLite-owner lifetime.
///
/// Field order is intentional: Rust drops `reader` before `_shutdown_guard`,
/// so the shutdown observer cannot complete while the WAL-pinning connection
/// remains live after cancellation of the async snapshot caller.
struct SnapshotCaptureWorker {
    reader: consensus::SnapshotReadConnection,
    _snapshot_directory_lease: Arc<SnapshotDirectoryLease>,
    _shutdown_guard: ConsensusStorageShutdownGuard,
}

#[cfg(test)]
pub(crate) async fn open_with_member_bindings(
    backend: &SqliteSessionBackend,
    snapshot_dir: impl Into<PathBuf>,
    identity: SessionConsensusIdentity,
    expected_members: BTreeSet<SessionConsensusNodeId>,
    expected_bindings: BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    membership_admission: SessionRaftPeerDirectory,
) -> Result<
    (
        SqliteConsensusLogStore,
        SqliteConsensusStateMachine,
        SessionConsensusIdentity,
    ),
    SessionConsensusStorageError,
> {
    open_with_member_bindings_for_profile(
        backend,
        snapshot_dir,
        identity,
        expected_members,
        expected_bindings,
        membership_admission,
        ConsensusAuthorityProfile::Dynamic,
        None,
        None,
        SnapshotIntegrityPolicy::FsVerity,
    )
    .await
}

/// Open dynamic consensus with the immutable topology-provisioned roster
/// attestation root. Passing `None` preserves ordinary non-roster operation;
/// roster mutations then fail closed in deterministic apply.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn open_with_member_bindings_and_roster_attestation_root(
    backend: &SqliteSessionBackend,
    snapshot_dir: impl Into<PathBuf>,
    identity: SessionConsensusIdentity,
    expected_members: BTreeSet<SessionConsensusNodeId>,
    expected_bindings: BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    membership_admission: SessionRaftPeerDirectory,
    roster_attestation_trust_root: Option<RosterAttestationTrustRootV1>,
) -> Result<
    (
        SqliteConsensusLogStore,
        SqliteConsensusStateMachine,
        SessionConsensusIdentity,
    ),
    SessionConsensusStorageError,
> {
    open_with_member_bindings_for_profile(
        backend,
        snapshot_dir,
        identity,
        expected_members,
        expected_bindings,
        membership_admission,
        ConsensusAuthorityProfile::Dynamic,
        None,
        roster_attestation_trust_root,
        SnapshotIntegrityPolicy::FsVerity,
    )
    .await
}

/// Fixed-quorum counterpart that persists the immutable roster root.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn open_fixed_with_member_bindings_and_roster_attestation_root(
    backend: &SqliteSessionBackend,
    snapshot_dir: impl Into<PathBuf>,
    identity: SessionConsensusIdentity,
    expected_members: BTreeSet<SessionConsensusNodeId>,
    expected_bindings: BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    membership_admission: SessionRaftPeerDirectory,
    placement_policy: PlacementResiliencePolicy,
    roster_attestation_trust_root: Option<RosterAttestationTrustRootV1>,
    snapshot_integrity: SnapshotIntegrityPolicy,
) -> Result<
    (
        SqliteConsensusLogStore,
        SqliteConsensusStateMachine,
        SessionConsensusIdentity,
    ),
    SessionConsensusStorageError,
> {
    open_with_member_bindings_for_profile(
        backend,
        snapshot_dir,
        identity,
        expected_members,
        expected_bindings,
        membership_admission,
        ConsensusAuthorityProfile::FixedImmutable,
        Some(placement_policy),
        roster_attestation_trust_root,
        snapshot_integrity,
    )
    .await
}

/// Qualify the exact admitted filesystem before initializing consensus state.
/// The probe is an ordinary recoverable SDK staging child, not a permanent
/// capability marker: storage may change between process incarnations.
async fn preflight_fs_verity(
    lease: Arc<SnapshotDirectoryLease>,
) -> Result<(), SessionConsensusStorageError> {
    tokio::task::spawn_blocking(move || {
        use std::io::Write as _;
        let name = std::ffi::OsString::from(format!("build-{}.sqlite", uuid::Uuid::new_v4()));
        let (mut writer, mut cleanup) = create_unpublished_snapshot_file_in_namespace(
            Arc::clone(&lease.namespace),
            &name,
            true,
            false,
        )?;
        writer.write_all(b"OPC snapshot integrity preflight\n")?;
        writer.sync_all()?;
        let mut pinned =
            PinnedSqliteFile::from_file(writer, lease.namespace.sqlite_child_path(&name)?)?;
        pinned.rebind_in_namespace(Arc::clone(&lease.namespace), &name)?;
        let mut reader = pinned.pin_readonly_from_writer()?;
        drop(pinned);
        let result = reader.seal_fixed();
        // Observe cleanup even when qualification fails. Drop retains its
        // usual failure latch if exact cleanup itself cannot complete.
        cleanup.remove_owned()?;
        result
    })
    .await
    .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?
    .map_err(|_| SessionConsensusStorageError::SnapshotIntegrityUnavailable)
}

#[allow(clippy::too_many_arguments)]
async fn open_with_member_bindings_for_profile(
    backend: &SqliteSessionBackend,
    snapshot_dir: impl Into<PathBuf>,
    identity: SessionConsensusIdentity,
    expected_members: BTreeSet<SessionConsensusNodeId>,
    expected_bindings: BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    membership_admission: SessionRaftPeerDirectory,
    authority_profile: ConsensusAuthorityProfile,
    fixed_placement_policy: Option<PlacementResiliencePolicy>,
    roster_attestation_trust_root: Option<RosterAttestationTrustRootV1>,
    snapshot_integrity: SnapshotIntegrityPolicy,
) -> Result<
    (
        SqliteConsensusLogStore,
        SqliteConsensusStateMachine,
        SessionConsensusIdentity,
    ),
    SessionConsensusStorageError,
> {
    let snapshot_dir = snapshot_dir.into();
    let snapshot_directory_lease = acquire_snapshot_directory_lease(backend, &snapshot_dir)
        .await
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
    if authority_profile == ConsensusAuthorityProfile::FixedImmutable
        && snapshot_integrity == SnapshotIntegrityPolicy::FsVerity
    {
        preflight_fs_verity(Arc::clone(&snapshot_directory_lease)).await?;
    }
    run_snapshot_directory_admission_test_hook(&snapshot_directory_lease.canonical_directory);
    let mut core = SqliteConsensusCore::initialize_with_roster_attestation_root_with_admitted_snapshot_directory(
        backend,
        snapshot_directory_lease.canonical_directory.clone(),
        identity,
        expected_members,
        expected_bindings,
        authority_profile,
        fixed_placement_policy,
        roster_attestation_trust_root,
    )
    .await?;
    core.snapshot_integrity = snapshot_integrity;
    // Validate the selected legacy descriptor before constructing a successor.
    // The compatibility branch accepts only the journal-bound `measure(2)`
    // ENODATA result and never reads the old payload.  Running this after a
    // build would let a marker alone authorize a replacement.
    validate_and_clean_snapshot_directory(&core, Some(&snapshot_directory_lease)).await?;
    if reseed_legacy_fixed_snapshot_from_authoritative_database(
        &core,
        Arc::clone(&snapshot_directory_lease),
    )
    .await?
    {
        // Metadata publication atomically clears the journal. Only then may
        // ordinary scavenging reclaim the unsealed predecessor by its old
        // namespace identity; it is never read or used as unlink authority.
        validate_and_clean_snapshot_directory(&core, Some(&snapshot_directory_lease)).await?;
    }
    let storage_identity = core.storage_identity;
    let shutdown_guard = ConsensusStorageShutdownGuard::tracked();
    let state_machine_shutdown_guard = shutdown_guard.child();
    Ok((
        SqliteConsensusLogStore {
            core: core.clone(),
            _snapshot_directory_lease: Arc::clone(&snapshot_directory_lease),
            shutdown_guard,
        },
        SqliteConsensusStateMachine {
            core,
            _snapshot_directory_lease: snapshot_directory_lease,
            membership_admission: Some(membership_admission),
            #[cfg(test)]
            membership_observations: Arc::new(AtomicUsize::new(0)),
            #[cfg(test)]
            membership_observation_readback_witness: None,
            #[cfg(test)]
            membership_observations_before_readback: Arc::new(AtomicUsize::new(0)),
            shutdown_guard: state_machine_shutdown_guard,
        },
        storage_identity,
    ))
}

/// Replace the one exact old selected fixed artifact with a newly built,
/// sealed snapshot. The current old file is never opened for contents: its
/// only compatibility classification happens under the builder's namespace
/// lease as a typed fs-verity `ENODATA` probe.
async fn reseed_legacy_fixed_snapshot_from_authoritative_database(
    core: &SqliteConsensusCore,
    snapshot_directory_lease: Arc<SnapshotDirectoryLease>,
) -> Result<bool, SessionConsensusStorageError> {
    if core.authority_profile != ConsensusAuthorityProfile::FixedImmutable {
        return Ok(false);
    }
    let should_reseed = {
        let conn = core.conn.lock().await;
        let current = consensus::read_current_snapshot_sync(&conn, core.storage_identity)
            .map_err(|_| SessionConsensusStorageError::CorruptState)?;
        let reseed =
            consensus::read_legacy_fixed_snapshot_reseed_sync(&conn, core.storage_identity)
                .map_err(|_| SessionConsensusStorageError::CorruptState)?;
        match (reseed.as_ref(), current.as_ref()) {
            (Some(reseed), Some(current)) => reseed
                .matches_current(core.storage_identity, current)
                .map_err(|_| SessionConsensusStorageError::CorruptState)?,
            (Some(_), None) => return Err(SessionConsensusStorageError::CorruptState),
            (None, _) => false,
        }
    };
    if !should_reseed {
        return Ok(false);
    }
    let mut builder = SqliteConsensusSnapshotBuilder {
        core: core.clone(),
        _snapshot_directory_lease: snapshot_directory_lease,
        _shutdown_guard: ConsensusStorageShutdownGuard::tracked(),
    };
    builder
        .build_snapshot()
        .await
        .map(|_| true)
        .map_err(|_| SessionConsensusStorageError::CorruptState)
}

#[cfg(test)]
async fn open(
    backend: &SqliteSessionBackend,
    snapshot_dir: impl Into<PathBuf>,
    identity: SessionConsensusIdentity,
    expected_members: BTreeSet<SessionConsensusNodeId>,
) -> Result<(SqliteConsensusLogStore, SqliteConsensusStateMachine), SessionConsensusStorageError> {
    let bindings = expected_members
        .iter()
        .copied()
        .map(|node| {
            let mut descriptor = [0x11; 32];
            descriptor[..8].copy_from_slice(&node.get().to_be_bytes());
            let mut endpoint = [0x22; 32];
            endpoint[..8].copy_from_slice(&node.get().to_be_bytes());
            let mut tls = [0x33; 32];
            tls[..8].copy_from_slice(&node.get().to_be_bytes());
            let mut backing = [0x44; 32];
            backing[..8].copy_from_slice(&node.get().to_be_bytes());
            (
                node,
                SessionTopologyMemberBinding::new(descriptor, endpoint, tls, backing),
            )
        })
        .collect();
    let snapshot_dir = snapshot_dir.into();
    let snapshot_directory_lease = acquire_snapshot_directory_lease(backend, &snapshot_dir)
        .await
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
    run_snapshot_directory_admission_test_hook(&snapshot_directory_lease.canonical_directory);
    let core = SqliteConsensusCore::initialize_with_admitted_snapshot_directory(
        backend,
        snapshot_directory_lease.canonical_directory.clone(),
        identity,
        expected_members,
        bindings,
        ConsensusAuthorityProfile::Dynamic,
        None,
    )
    .await?;
    validate_and_clean_snapshot_directory(&core, Some(&snapshot_directory_lease)).await?;
    let shutdown_guard = ConsensusStorageShutdownGuard::tracked();
    let state_machine_shutdown_guard = shutdown_guard.child();
    Ok((
        SqliteConsensusLogStore {
            core: core.clone(),
            _snapshot_directory_lease: Arc::clone(&snapshot_directory_lease),
            shutdown_guard,
        },
        SqliteConsensusStateMachine {
            core,
            _snapshot_directory_lease: snapshot_directory_lease,
            membership_admission: None,
            membership_observations: Arc::new(AtomicUsize::new(0)),
            membership_observation_readback_witness: None,
            membership_observations_before_readback: Arc::new(AtomicUsize::new(0)),
            shutdown_guard: state_machine_shutdown_guard,
        },
    ))
}

/// Root-aware pending-membership open that preserves the current immutable
/// roster root while durably staging one successor scope.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn open_with_pending_membership_and_roster_attestation_root(
    backend: &SqliteSessionBackend,
    snapshot_dir: impl Into<PathBuf>,
    storage_identity: SessionConsensusIdentity,
    current_identity: SessionConsensusIdentity,
    current_members: BTreeSet<SessionConsensusNodeId>,
    current_bindings: BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    local_candidate_node_id: SessionConsensusNodeId,
    transition_id: [u8; 16],
    transition_digest: [u8; 32],
    desired_identity: SessionConsensusIdentity,
    desired_members: &BTreeSet<SessionConsensusNodeId>,
    desired_bindings: &BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    membership_admission: SessionRaftPeerDirectory,
    roster_attestation_trust_root: Option<RosterAttestationTrustRootV1>,
) -> Result<
    (
        SqliteConsensusLogStore,
        SqliteConsensusStateMachine,
        SessionConsensusIdentity,
    ),
    SessionConsensusStorageError,
> {
    let snapshot_dir = snapshot_dir.into();
    let snapshot_directory_lease = acquire_snapshot_directory_lease(backend, &snapshot_dir)
        .await
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
    run_snapshot_directory_admission_test_hook(&snapshot_directory_lease.canonical_directory);
    let core = SqliteConsensusCore::initialize_with_pending_and_roster_attestation_root_with_admitted_snapshot_directory(
        backend,
        snapshot_directory_lease.canonical_directory.clone(),
        storage_identity,
        current_identity,
        current_members,
        current_bindings,
        consensus::PendingMembershipBootstrap {
            local_candidate_node_id: Some(local_candidate_node_id),
            transition_id,
            transition_digest,
            desired_identity,
            desired_members,
            desired_bindings,
        },
        ConsensusAuthorityProfile::Dynamic,
        None,
        roster_attestation_trust_root,
    )
    .await?;
    validate_and_clean_snapshot_directory(&core, Some(&snapshot_directory_lease)).await?;
    let storage_identity = core.storage_identity;
    let shutdown_guard = ConsensusStorageShutdownGuard::tracked();
    let state_machine_shutdown_guard = shutdown_guard.child();
    Ok((
        SqliteConsensusLogStore {
            core: core.clone(),
            _snapshot_directory_lease: Arc::clone(&snapshot_directory_lease),
            shutdown_guard,
        },
        SqliteConsensusStateMachine {
            core,
            _snapshot_directory_lease: snapshot_directory_lease,
            membership_admission: Some(membership_admission),
            #[cfg(test)]
            membership_observations: Arc::new(AtomicUsize::new(0)),
            #[cfg(test)]
            membership_observation_readback_witness: None,
            #[cfg(test)]
            membership_observations_before_readback: Arc::new(AtomicUsize::new(0)),
            shutdown_guard: state_machine_shutdown_guard,
        },
        storage_identity,
    ))
}

/// Reclaim SDK-owned interrupted staging artifacts from a detached failed
/// namespace. This is deliberately separate from the current lease scan: a
/// queued cleanup failure can belong to D1 after a parent replacement has
/// admitted D2 at the same logical path. Syncing D1 without first retrying
/// its bounded cleanup would acknowledge a recoverable orphan.
async fn reclaim_detached_failed_snapshot_namespace(
    namespace: Arc<RetainedSnapshotDirectory>,
) -> Result<(), SessionConsensusStorageError> {
    let entries_namespace = Arc::clone(&namespace);
    let entries = tokio::task::spawn_blocking(move || {
        entries_namespace.entries(SNAPSHOT_DIRECTORY_MAX_ENTRIES)
    })
    .await
    .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?
    .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
    if entries.len() > SNAPSHOT_DIRECTORY_MAX_ENTRIES {
        return Err(SessionConsensusStorageError::CorruptState);
    }

    let mut removed = false;
    for entry_name in entries {
        let Some(file_name) = entry_name.to_str().map(str::to_owned) else {
            continue;
        };
        // The retained namespace capability owns the cooperative directory
        // flock until this queued generation is acknowledged. A cooperative
        // SDK receiver therefore cannot be live in detached D1 here. Only
        // exact SDK staging/tombstone grammar is reclaimable; every other
        // entry is intentionally preserved, even when it consumes bounded
        // capacity.
        if !is_sdk_snapshot_staging_name(&file_name) {
            continue;
        }
        let open_namespace = Arc::clone(&namespace);
        let open_name = entry_name.clone();
        let file = tokio::task::spawn_blocking(move || open_namespace.open_read(&open_name))
            .await
            .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?
            .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
        let metadata = file
            .metadata()
            .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
        if !metadata.is_file() {
            return Err(SessionConsensusStorageError::CorruptState);
        }
        let cleanup = match sdk_snapshot_unlink_guard_parts(&file_name) {
            Some((tombstone, original)) => {
                #[cfg(target_os = "linux")]
                {
                    if !snapshot_cleanup_unlink_guard_name_authenticates_metadata(
                        &entry_name,
                        &metadata,
                    )
                    .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?
                    {
                        // A syntactically similar guard with a mismatched
                        // identity is foreign. Retain it exactly as found;
                        // never convert it into a cleanup target.
                        continue;
                    }
                    UnpublishedSnapshotArtifact::from_existing_unlink_guard_in_namespace(
                        Arc::clone(&namespace),
                        &entry_name,
                        std::ffi::OsStr::new(tombstone),
                        std::ffi::OsStr::new(original),
                        &metadata,
                        false,
                    )
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = (tombstone, original);
                    return Err(SessionConsensusStorageError::CorruptState);
                }
            }
            None => match sdk_snapshot_tombstone_original_name(&file_name) {
                Some(original) => {
                    UnpublishedSnapshotArtifact::from_existing_tombstone_in_namespace(
                        Arc::clone(&namespace),
                        &entry_name,
                        std::ffi::OsStr::new(&original),
                        &metadata,
                        false,
                    )
                }
                None => UnpublishedSnapshotArtifact::from_file_in_namespace(
                    &file,
                    Arc::clone(&namespace),
                    &entry_name,
                    false,
                ),
            },
        }
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
        drop(cleanup);
        drop(file);
        let verify_namespace = Arc::clone(&namespace);
        let verify_name = entry_name.clone();
        match tokio::task::spawn_blocking(move || verify_namespace.open_read(&verify_name)).await {
            Ok(Err(error)) if error.kind() == io::ErrorKind::NotFound => {}
            Ok(_) | Err(_) => return Err(SessionConsensusStorageError::BackendUnavailable),
        }
        removed = true;
    }
    if removed {
        let sync_namespace = Arc::clone(&namespace);
        tokio::task::spawn_blocking(move || sync_namespace.sync())
            .await
            .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?
            .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
    }
    Ok(())
}

async fn validate_and_clean_snapshot_directory(
    core: &SqliteConsensusCore,
    lease: Option<&Arc<SnapshotDirectoryLease>>,
) -> Result<usize, SessionConsensusStorageError> {
    // `core.snapshot_dir` remains the durable/logical key.  Every operation
    // on its children is instead issued through the retained descriptor. A
    // parent-directory rename must not make this owner inspect a replacement
    // namespace at the same configured spelling.
    let lease = lease.ok_or(SessionConsensusStorageError::CorruptState)?;
    // A `Drop` fallback cannot return its I/O error to a cancelled caller.
    // Do not consume its one-shot latch yet: every fallible validation and
    // scan below must leave recovery evidence pending.  Only a completed
    // current-snapshot + directory pass gets to report and clear it.
    // Legacy in-process cleanup owners still expose an atomic flag. Fold any
    // observed flag into the per-directory generation registry *before* this
    // pass snapshots its target. Production owners issue the generation
    // first, so a concurrent failure can never be cleared by a later bool
    // swap after this pass has fsynced.
    // Keep the legacy hint set until this complete validation pass has
    // fsynced and acknowledged its namespace generation.  Clearing it here
    // would let an early current/read-directory/sync failure consume the
    // only local evidence before the recovery boundary completed.
    if core.snapshot_cleanup_failed.load(Ordering::Acquire) {
        record_unpublished_snapshot_cleanup_failure_in_namespace(Arc::clone(&lease.namespace));
    }
    let cleanup_latch_identity = lease.namespace.cleanup_latch_identity();
    let cleanup_failures = pending_unpublished_snapshot_cleanup_failures(cleanup_latch_identity)
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
    let cleanup_failure_pending = !cleanup_failures.is_empty();
    // A failure from a detached D1 may have happened before unlink, leaving a
    // canonical staging child or tombstone behind. Reclaim that exact
    // descriptor namespace before the normal D2 validation path can observe
    // or acknowledge the failure. Same-Arc failures are handled by the
    // current-lease loop below, which also respects a live receiver permit.
    for failure in &cleanup_failures {
        if !Arc::ptr_eq(failure.namespace(), &lease.namespace) {
            reclaim_detached_failed_snapshot_namespace(Arc::clone(failure.namespace())).await?;
        }
    }
    let (current, legacy_fixed_snapshot_reseed) = {
        let conn = core.conn.lock().await;
        (
            consensus::read_current_snapshot_sync(&conn, core.storage_identity)
                .map_err(|_| SessionConsensusStorageError::CorruptState)?,
            consensus::read_legacy_fixed_snapshot_reseed_sync(&conn, core.storage_identity)
                .map_err(|_| SessionConsensusStorageError::CorruptState)?,
        )
    };
    let legacy_reseed_matches_current =
        match (legacy_fixed_snapshot_reseed.as_ref(), current.as_ref()) {
            (Some(reseed), Some(current)) => reseed
                .matches_current(core.storage_identity, current)
                .map_err(|_| SessionConsensusStorageError::CorruptState)?,
            (Some(_), None) => return Err(SessionConsensusStorageError::CorruptState),
            (None, _) => false,
        };
    if legacy_reseed_matches_current && core.snapshot_integrity != SnapshotIntegrityPolicy::FsVerity
    {
        // The released reseed journal authorizes only a strict sealed
        // successor. Complete that exact migration before changing policy;
        // portable admission must not reinterpret its deletion authority.
        return Err(SessionConsensusStorageError::RecoveryRequired);
    }
    if let (Some(current), Some(candidate_file_name)) = (
        current.as_ref(),
        legacy_fixed_snapshot_reseed
            .as_ref()
            .filter(|_| legacy_reseed_matches_current)
            .and_then(|reseed| reseed.candidate_file_name.as_deref()),
    ) {
        reclaim_legacy_fixed_snapshot_reseed_candidate(
            core,
            &lease.namespace,
            current,
            candidate_file_name,
        )
        .await?;
    }
    #[cfg(test)]
    if take_snapshot_directory_validation_failure(
        &core.snapshot_dir,
        SnapshotDirectoryValidationFailure::Current,
    ) {
        return Err(SessionConsensusStorageError::BackendUnavailable);
    }
    // Open the current candidate through the retained namespace before any
    // terminal-handoff fence.  Keep this exact descriptor alive through the
    // final consume call: terminal recovery must not reopen core.snapshot_dir
    // after a parent replacement has detached the admitted namespace.
    let admitted_current_file = match current.as_ref() {
        Some((_, file_name, _, _)) => Some(
            open_snapshot_child_in_namespace(
                Arc::clone(&lease.namespace),
                std::ffi::OsString::from(file_name),
            )
            .await
            .map_err(|_| SessionConsensusStorageError::CorruptState)?,
        ),
        None => None,
    };
    // Recovery may have retained the terminal descriptor which classified the
    // current snapshot. Validate that descriptor itself against the admitted
    // descriptor; do not replace either with a pathname reopen before the
    // terminal latch is consumed.
    let mut terminal_handoff_file = if legacy_reseed_matches_current {
        // The one-time reseed intentionally does not consume a terminal
        // handoff against an artifact it will never read. A pending handoff
        // requires ordinary sealed recovery instead.
        if core.terminal_recovery_handoff_pending()? {
            return Err(SessionConsensusStorageError::CorruptState);
        }
        None
    } else {
        core.terminal_recovery_snapshot_handoff_file(
            current
                .as_ref()
                .map(|(_, file_name, _, _)| file_name.as_str()),
            admitted_current_file.as_ref(),
        )
        .map_err(|_| SessionConsensusStorageError::CorruptState)?
    };
    if let Some((_, file_name, expected_checksum, expected_length)) = &current {
        let path = lease
            .namespace
            .sqlite_child_path(std::ffi::OsStr::new(file_name))
            .map_err(|_| SessionConsensusStorageError::CorruptState)?;
        let (checksum, length) =
            if core.authority_profile == ConsensusAuthorityProfile::FixedImmutable {
                if legacy_reseed_matches_current {
                    // Probe only the kernel fs-verity state of the admitted
                    // descriptor. No old envelope byte is read or parsed:
                    // the ensuing replacement is reconstructed solely from
                    // the separately validated DB/log state.
                    let file = admitted_current_file
                        .as_ref()
                        .ok_or(SessionConsensusStorageError::CorruptState)?;
                    // `measure(2)` is meaningful only for a regular inode.
                    // Keep special files (including FIFOs opened with
                    // O_NONBLOCK) outside the compatibility classifier.
                    if !file
                        .metadata()
                        .map_err(|_| SessionConsensusStorageError::CorruptState)?
                        .is_file()
                    {
                        return Err(SessionConsensusStorageError::CorruptState);
                    }
                    if !fixed_verity_is_exactly_unsealed(file)
                        .map_err(|_| SessionConsensusStorageError::CorruptState)?
                    {
                        return Err(SessionConsensusStorageError::CorruptState);
                    }
                    (*expected_checksum, *expected_length)
                } else {
                    // Capture/validate the selected policy on this exact
                    // admitted descriptor. The strict policy requires an
                    // existing seal; portable readers retain a verified image
                    // authenticated against the durable checksum. Neither
                    // path repairs or substitutes the admitted object.
                    let file = match terminal_handoff_file.take() {
                        Some(file) => Ok(file),
                        None => admitted_current_file
                            .as_ref()
                            .ok_or_else(|| io::Error::other("missing admitted current snapshot"))
                            .and_then(std::fs::File::try_clone),
                    };
                    verify_admitted_snapshot(
                        file.map_err(|_| SessionConsensusStorageError::CorruptState)?,
                        Arc::clone(lease),
                        std::ffi::OsString::from(file_name),
                        core.snapshot_integrity,
                        *expected_checksum,
                        *expected_length,
                    )
                    .await
                    .map_err(|_| SessionConsensusStorageError::CorruptState)?;
                    (*expected_checksum, *expected_length)
                }
            } else {
                let file = match terminal_handoff_file.take() {
                    Some(file) => Ok(file),
                    None => admitted_current_file
                        .as_ref()
                        .ok_or_else(|| io::Error::other("missing admitted current snapshot"))
                        .and_then(std::fs::File::try_clone),
                }
                .map_err(|_| SessionConsensusStorageError::CorruptState)?;
                let mut snapshot = SessionSnapshotFile::from_std(file, path.clone())
                    .await
                    .map_err(|_| SessionConsensusStorageError::CorruptState)?;
                let (_, checksum, length) = verify_snapshot_envelope_reader(&mut snapshot)
                    .await
                    .map_err(|_| SessionConsensusStorageError::CorruptState)?;
                (checksum, length)
            };
        if checksum != *expected_checksum || length != *expected_length {
            return Err(SessionConsensusStorageError::CorruptState);
        }
    }

    // Keep enumeration bounded, but classify and reclaim admitted stale names
    // before enforcing the survivor capacity.  A run of interrupted
    // publication cleanups must not permanently wedge reopening merely by
    // reaching the one-entry-over-capacity proof returned by `entries`.
    #[cfg(test)]
    if take_snapshot_directory_validation_failure(
        &core.snapshot_dir,
        SnapshotDirectoryValidationFailure::ReadDirectory,
    ) {
        return Err(SessionConsensusStorageError::BackendUnavailable);
    }
    let namespace = Arc::clone(&lease.namespace);
    let entries =
        tokio::task::spawn_blocking(move || namespace.entries(SNAPSHOT_DIRECTORY_MAX_ENTRIES))
            .await
            .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?
            .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
    let mut durable_survivors = 0_usize;
    let mut removed = false;
    // `begin_receiving_snapshot` intentionally releases the mutation mutex
    // while its one permitted receiver owns an incoming descriptor. A build
    // or install recovery pass must count that live namespace entry but may
    // never reclaim it. The semaphore is per core, so this relies on the
    // existing one-writer-per-snapshot-directory construction contract.
    let live_receiver = core.snapshot_receive_admission.available_permits() == 0;
    for entry_name in entries {
        let Some(file_name) = entry_name.to_str().map(str::to_owned) else {
            durable_survivors = durable_survivors
                .checked_add(1)
                .ok_or(SessionConsensusStorageError::CorruptState)?;
            if durable_survivors > SNAPSHOT_DIRECTORY_MAX_ENTRIES {
                return Err(SessionConsensusStorageError::CorruptState);
            }
            continue;
        };
        // A candidate name is not ownership.  Staging names are emitted only
        // by this module. A canonical published name becomes reclaimable only
        // when it is not the exact current durable metadata name: successor
        // metadata publication makes its predecessor an admitted SDK orphan.
        // Tombstones and final guards inherit that same original-name rule.
        let cleanup_original = sdk_snapshot_restart_cleanup_original_name(&file_name);
        let reclaimable = cleanup_original.is_some_and(|original| {
            !(is_sdk_published_snapshot_name(original)
                && current
                    .as_ref()
                    .is_some_and(|(_, current_name, _, _)| current_name == original))
        });
        if !reclaimable || (live_receiver && is_sdk_snapshot_incoming_name(&file_name)) {
            durable_survivors = durable_survivors
                .checked_add(1)
                .ok_or(SessionConsensusStorageError::CorruptState)?;
            if durable_survivors > SNAPSHOT_DIRECTORY_MAX_ENTRIES {
                return Err(SessionConsensusStorageError::CorruptState);
            }
            continue;
        }
        // Never follow a special file. The bounded recovery pass may only
        // unlink an exact SDK namespace regular file after capturing its
        // no-follow identity for the cleanup guard.
        let namespace = Arc::clone(&lease.namespace);
        let name = entry_name.clone();
        let file = tokio::task::spawn_blocking(move || {
            let file = namespace.open_read(&name)?;
            Ok::<_, io::Error>(file)
        })
        .await
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
        let metadata = file
            .metadata()
            .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
        if !metadata.is_file() {
            return Err(SessionConsensusStorageError::CorruptState);
        }
        let cleanup = match sdk_snapshot_unlink_guard_parts(&file_name) {
            Some((tombstone, original)) => {
                #[cfg(target_os = "linux")]
                {
                    if !snapshot_cleanup_unlink_guard_name_authenticates_metadata(
                        &entry_name,
                        &metadata,
                    )
                    .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?
                    {
                        // A name is not authority: a guard whose encoded
                        // inode does not authenticate this descriptor remains
                        // a durable capacity survivor.
                        durable_survivors = durable_survivors
                            .checked_add(1)
                            .ok_or(SessionConsensusStorageError::CorruptState)?;
                        if durable_survivors > SNAPSHOT_DIRECTORY_MAX_ENTRIES {
                            return Err(SessionConsensusStorageError::CorruptState);
                        }
                        continue;
                    }
                    UnpublishedSnapshotArtifact::from_existing_unlink_guard_in_namespace(
                        Arc::clone(&lease.namespace),
                        &entry_name,
                        std::ffi::OsStr::new(tombstone),
                        std::ffi::OsStr::new(original),
                        &metadata,
                        false,
                    )
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = (tombstone, original);
                    durable_survivors = durable_survivors
                        .checked_add(1)
                        .ok_or(SessionConsensusStorageError::CorruptState)?;
                    continue;
                }
            }
            None => match sdk_snapshot_tombstone_original_name(&file_name) {
                Some(original) => {
                    UnpublishedSnapshotArtifact::from_existing_tombstone_in_namespace(
                        Arc::clone(&lease.namespace),
                        &entry_name,
                        std::ffi::OsStr::new(&original),
                        &metadata,
                        false,
                    )
                }
                None => UnpublishedSnapshotArtifact::from_file_in_namespace(
                    &file,
                    Arc::clone(&lease.namespace),
                    &entry_name,
                    false,
                ),
            },
        }
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
        drop(cleanup);
        drop(file);
        let namespace = Arc::clone(&lease.namespace);
        let name = entry_name.clone();
        match tokio::task::spawn_blocking(move || namespace.open_read(&name)).await {
            Ok(Err(error)) if error.kind() == io::ErrorKind::NotFound => {}
            Ok(_) | Err(_) => return Err(SessionConsensusStorageError::BackendUnavailable),
        }
        removed = true;
    }
    // A dropped cleanup can unlink its final child and fail only the parent
    // fsync. Its next validation pass may therefore see an empty namespace,
    // but must still retry that durable boundary before consuming the latch or
    // allowing terminal recovery handoff to advance.
    if removed || cleanup_failure_pending {
        #[cfg(test)]
        if take_snapshot_directory_validation_failure(
            &core.snapshot_dir,
            SnapshotDirectoryValidationFailure::SyncDirectory,
        ) {
            return Err(SessionConsensusStorageError::BackendUnavailable);
        }
    }
    if removed {
        let namespace = Arc::clone(&lease.namespace);
        tokio::task::spawn_blocking(move || namespace.sync())
            .await
            .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?
            .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
    }
    // A failure belongs to the directory descriptor that actually performed
    // the unlink/rename. Do not substitute the present lease namespace here:
    // after D1 is detached and D2 appears at the same logical path, only a
    // D1 fsync makes D1's cleanup durable. Retaining the failure `Arc` also
    // keeps that exact descriptor alive until this acknowledgement.
    for failure in &cleanup_failures {
        let namespace = Arc::clone(failure.namespace());
        tokio::task::spawn_blocking(move || namespace.sync())
            .await
            .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?
            .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
    }
    if cleanup_failure_pending {
        #[cfg(test)]
        wait_after_snapshot_cleanup_failure_sync_before_ack(cleanup_latch_identity).await;
    }
    if cleanup_failure_pending {
        // Acknowledge only failures whose own retained descriptor has been
        // fsynced. A later generation, or another detached incarnation at
        // this logical path, remains pending for its own durable retry.
        let mut acknowledged = false;
        for failure in &cleanup_failures {
            acknowledged |=
                acknowledge_unpublished_snapshot_cleanup_failure(cleanup_latch_identity, failure);
        }
        if acknowledged {
            // Namespace failures publish their generation before this legacy
            // hint, so clearing the hint after its own generation was
            // acknowledged cannot erase a concurrent cleanup failure.
            core.snapshot_cleanup_failed.store(false, Ordering::Release);
            return Err(SessionConsensusStorageError::BackendUnavailable);
        }
    }
    if core.snapshot_cleanup_failed.load(Ordering::Acquire)
        || has_unpublished_snapshot_cleanup_failure(cleanup_latch_identity)
    {
        // A failure arrived after the completed-pass exchange. Preserve it
        // for the next gated operation rather than consuming it speculatively.
        return Err(SessionConsensusStorageError::BackendUnavailable);
    }
    if !legacy_reseed_matches_current {
        core.consume_terminal_recovery_handoff_after_snapshot_validation(
            current
                .as_ref()
                .map(|(_, file_name, _, _)| file_name.as_str()),
            admitted_current_file.as_ref(),
        )
        .await?;
    }
    Ok(durable_survivors)
}

/// Reclaim the one sealed candidate that an exact local reseed journal
/// reserved before an interrupted pre-metadata publication.  The candidate is
/// not selected state and is never opened for payload bytes: its private
/// journal name plus an exact immutable fs-verity descriptor are the complete
/// deletion authority.  Any other object/type/profile remains fail-closed.
async fn reclaim_legacy_fixed_snapshot_reseed_candidate(
    core: &SqliteConsensusCore,
    namespace: &Arc<RetainedSnapshotDirectory>,
    current: &consensus::CurrentSnapshot,
    candidate_file_name: &str,
) -> Result<(), SessionConsensusStorageError> {
    let candidate = std::ffi::OsString::from(candidate_file_name);
    match open_snapshot_child_in_namespace(Arc::clone(namespace), candidate.clone()).await {
        Ok(file) => {
            if !file
                .metadata()
                .map_err(|_| SessionConsensusStorageError::CorruptState)?
                .is_file()
                || fixed_verity_is_exactly_unsealed(&file)
                    .map_err(|_| SessionConsensusStorageError::CorruptState)?
            {
                return Err(SessionConsensusStorageError::CorruptState);
            }
            namespace
                .unlink(std::ffi::OsStr::new(candidate_file_name))
                .map_err(|_| SessionConsensusStorageError::CorruptState)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(SessionConsensusStorageError::CorruptState),
    }
    // Even an ENOENT is a recovery result that may follow a crash or a
    // previously interrupted unlink.  Establish the retained namespace's
    // durability boundary before clearing the only database reservation; a
    // failed sync must retain the marker so the next open cannot confuse an
    // undurable namespace with a completed reclamation.
    namespace
        .sync()
        .map_err(|_| SessionConsensusStorageError::CorruptState)?;
    let conn = core.conn.lock().await;
    consensus::clear_legacy_fixed_snapshot_reseed_candidate_sync(
        &conn,
        core.storage_identity,
        current,
        candidate_file_name,
    )
    .map_err(|_| SessionConsensusStorageError::CorruptState)
}

fn is_canonical_snapshot_uuid(token: &str) -> bool {
    uuid::Uuid::parse_str(token)
        .map(|parsed| {
            parsed.get_version() == Some(uuid::Version::Random)
                && parsed.get_variant() == uuid::Variant::RFC4122
                && parsed.hyphenated().to_string() == token
        })
        .unwrap_or(false)
}

fn is_sdk_snapshot_staging_name(file_name: &str) -> bool {
    if let Some((_, original)) = sdk_snapshot_unlink_guard_parts(file_name) {
        return is_sdk_snapshot_staging_name_without_tombstone(original);
    }
    if let Some(original) = sdk_snapshot_tombstone_original_name(file_name) {
        return is_sdk_snapshot_staging_name_without_tombstone(original);
    }
    is_sdk_snapshot_staging_name_without_tombstone(file_name)
}

/// A published envelope uses one canonical UUIDv4 basename. Restart cleanup
/// may consider it only after comparing it with current snapshot metadata.
fn is_sdk_published_snapshot_name(file_name: &str) -> bool {
    file_name
        .strip_prefix("snapshot-")
        .and_then(|remainder| remainder.strip_suffix(".opc"))
        .is_some_and(is_canonical_snapshot_uuid)
}

/// Return the original SDK artifact named by a bounded restart candidate.
/// Published originals intentionally share the strict tombstone/guard grammar
/// with staging artifacts, but callers must separately exclude the exact
/// current metadata snapshot before reclaiming them.
fn sdk_snapshot_restart_cleanup_original_name(file_name: &str) -> Option<&str> {
    if let Some((_, original)) = sdk_snapshot_unlink_guard_parts(file_name) {
        return Some(original);
    }
    if let Some(original) = sdk_snapshot_tombstone_original_name(file_name) {
        return Some(original);
    }
    (is_sdk_snapshot_staging_name_without_tombstone(file_name)
        || is_sdk_published_snapshot_name(file_name))
    .then_some(file_name)
}

fn is_sdk_snapshot_cleanup_original_name(file_name: &str) -> bool {
    is_sdk_snapshot_staging_name_without_tombstone(file_name)
        || is_sdk_published_snapshot_name(file_name)
}

fn is_sdk_snapshot_staging_name_without_tombstone(file_name: &str) -> bool {
    let part = ["incoming-", "promote-"].iter().any(|prefix| {
        file_name
            .strip_prefix(prefix)
            .and_then(|remainder| remainder.strip_suffix(".part"))
            .is_some_and(is_canonical_snapshot_uuid)
    });
    part || ["install-", "build-", "vacuum-"].iter().any(|prefix| {
        [".sqlite", ".sqlite-journal", ".sqlite-wal", ".sqlite-shm"]
            .iter()
            .any(|suffix| {
                file_name
                    .strip_prefix(prefix)
                    .and_then(|remainder| remainder.strip_suffix(suffix))
                    .is_some_and(is_canonical_snapshot_uuid)
            })
    }) || is_sdk_snapshot_vacuum_raw_name(file_name)
}

fn sdk_snapshot_unlink_guard_parts(file_name: &str) -> Option<(&str, &str)> {
    let (tombstone, encoded_identity) = file_name.rsplit_once(".opc-unlink-guard-")?;
    let (device, inode) = encoded_identity.split_once('-')?;
    (is_fixed_lower_hex_u64(device) && is_fixed_lower_hex_u64(inode))
        .then(|| {
            sdk_snapshot_tombstone_original_name(tombstone).map(|original| (tombstone, original))
        })
        .flatten()
}

fn is_fixed_lower_hex_u64(token: &str) -> bool {
    token.len() == 16
        && token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Parse a strict cleanup tombstone wrapping one canonical SDK staging or
/// published basename. The restart scanner separately refuses a published
/// original that is still the exact current metadata snapshot.
fn sdk_snapshot_tombstone_original_name(file_name: &str) -> Option<&str> {
    let remainder = file_name.strip_prefix('.')?;
    let (original, token) = remainder.rsplit_once(".opc-cleanup-")?;
    (is_canonical_snapshot_uuid(token)
        && !original.starts_with('.')
        && is_sdk_snapshot_cleanup_original_name(original))
    .then_some(original)
}

fn is_sdk_snapshot_incoming_name(file_name: &str) -> bool {
    file_name
        .strip_prefix("incoming-")
        .and_then(|remainder| remainder.strip_suffix(".part"))
        .is_some_and(is_canonical_snapshot_uuid)
}

fn is_sdk_snapshot_vacuum_raw_name(file_name: &str) -> bool {
    [".sqlite", ".sqlite-journal", ".sqlite-wal", ".sqlite-shm"]
        .iter()
        .any(|suffix| {
            let Some(token) = file_name
                .strip_prefix("vacuum-raw-")
                .and_then(|remainder| remainder.strip_suffix(suffix))
            else {
                return false;
            };
            let Some((pid, sequence)) = token.split_once('-') else {
                return false;
            };
            pid.parse::<u32>()
                .map(|parsed| parsed > 0 && parsed.to_string() == pid)
                .unwrap_or(false)
                && sequence
                    .parse::<u64>()
                    .map(|parsed| parsed.to_string() == sequence)
                    .unwrap_or(false)
        })
}

/// Reserve a bounded directory footprint while the snapshot mutation gate is
/// held. For a receiver, the just-created `incoming-*.part` remains the
/// reservation for its full lifetime. For build/install, the gate itself is
/// retained through every temporary SQLite, sidecar, promotion, and cleanup
/// transition, so no concurrent path can consume the same slots.
fn reserve_snapshot_directory_entries(
    durable_survivors: usize,
    requested_entries: usize,
) -> Result<(), SessionConsensusStorageError> {
    let reserved = durable_survivors
        .checked_add(requested_entries)
        .ok_or(SessionConsensusStorageError::CorruptState)?;
    if reserved > SNAPSHOT_DIRECTORY_MAX_ENTRIES {
        return Err(SessionConsensusStorageError::BackendUnavailable);
    }
    Ok(())
}

fn storage_error(
    subject: ErrorSubject<SessionConsensusNodeId>,
    verb: ErrorVerb,
    error: io::Error,
) -> StorageError<SessionConsensusNodeId> {
    StorageError::from_io_error(subject, verb, error)
}

fn membership_admission_storage_error(
    _error: SessionRaftAdapterError,
) -> StorageError<SessionConsensusNodeId> {
    storage_error(
        ErrorSubject::StateMachine,
        ErrorVerb::Write,
        io::Error::other("session consensus membership admission is unavailable"),
    )
}

fn range_to_half_open<R: RangeBounds<u64>>(range: &R) -> io::Result<(u64, Option<u64>)> {
    let start = match range.start_bound() {
        Bound::Included(value) => *value,
        Bound::Excluded(value) => value
            .checked_add(1)
            .ok_or_else(|| consensus::invalid_data("session consensus log range overflow"))?,
        Bound::Unbounded => 0,
    };
    let end = match range.end_bound() {
        Bound::Included(value) => Some(
            value
                .checked_add(1)
                .ok_or_else(|| consensus::invalid_data("session consensus log range overflow"))?,
        ),
        Bound::Excluded(value) => Some(*value),
        Bound::Unbounded => None,
    };
    Ok((start, end))
}

impl RaftLogReader<SessionRaftTypeConfig> for SqliteConsensusLogStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + std::fmt::Debug + Send>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<SessionRaftTypeConfig>>, StorageError<SessionConsensusNodeId>> {
        let (start, end) = range_to_half_open(&range)
            .map_err(|error| storage_error(ErrorSubject::Logs, ErrorVerb::Read, error))?;
        let conn = self.core.conn.lock().await;
        consensus::with_durable_authority_raw_read_sync(
            &conn,
            self.core.storage_identity,
            self.core.authority_profile,
            &self.core.expected_members,
            &self.core.expected_bindings,
            self.core.fixed_placement_policy,
            |conn| {
                if end.is_some_and(|end| start >= end) {
                    return Ok(Vec::new());
                }
                consensus::read_log_range_sync(conn, self.core.storage_identity, start, end, None)
            },
        )
        .map_err(|error| storage_error(ErrorSubject::Logs, ErrorVerb::Read, error))
    }

    async fn limited_get_log_entries(
        &mut self,
        start: u64,
        end: u64,
    ) -> Result<Vec<Entry<SessionRaftTypeConfig>>, StorageError<SessionConsensusNodeId>> {
        let conn = self.core.conn.lock().await;
        let entries = consensus::with_durable_authority_raw_read_sync(
            &conn,
            self.core.storage_identity,
            self.core.authority_profile,
            &self.core.expected_members,
            &self.core.expected_bindings,
            self.core.fixed_placement_policy,
            |conn| {
                if start >= end {
                    return Ok(Vec::new());
                }
                consensus::read_limited_log_range_sync(
                    conn,
                    self.core.storage_identity,
                    start,
                    end,
                    DURABLE_OPENRAFT_MAX_PAYLOAD_ENTRIES,
                )
            },
        )
        .map_err(|error| storage_error(ErrorSubject::Logs, ErrorVerb::Read, error))?;
        if start >= end {
            return Ok(entries);
        }
        if entries.is_empty() {
            return Err(storage_error(
                ErrorSubject::Logs,
                ErrorVerb::Read,
                consensus::invalid_data(
                    "session consensus limited nonempty log range returned no entry",
                ),
            ));
        }
        Ok(entries)
    }
}

impl RaftLogStorage<SessionRaftTypeConfig> for SqliteConsensusLogStore {
    type LogReader = Self;

    async fn get_log_state(
        &mut self,
    ) -> Result<LogState<SessionRaftTypeConfig>, StorageError<SessionConsensusNodeId>> {
        let conn = self.core.conn.lock().await;
        let (last_purged_log_id, last_log_id) = consensus::with_durable_authority_raw_read_sync(
            &conn,
            self.core.storage_identity,
            self.core.authority_profile,
            &self.core.expected_members,
            &self.core.expected_bindings,
            self.core.fixed_placement_policy,
            |conn| {
                Ok((
                    consensus::read_purged_sync(conn, self.core.storage_identity)?,
                    consensus::last_log_sync(conn, self.core.storage_identity)?,
                ))
            },
        )
        .map_err(|error| storage_error(ErrorSubject::Logs, ErrorVerb::Read, error))?;
        Ok(LogState {
            last_purged_log_id,
            last_log_id,
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.tracked_reader()
    }

    async fn save_vote(
        &mut self,
        vote: &Vote<SessionConsensusNodeId>,
    ) -> Result<(), StorageError<SessionConsensusNodeId>> {
        let _prune_preemption = self.core.request_consensus_log_prune_preemption().await;
        let result = {
            let conn = self.core.conn.lock().await;
            consensus::save_vote_with_authority_sync(
                &conn,
                self.core.storage_identity,
                self.core.authority_profile,
                &self.core.expected_members,
                &self.core.expected_bindings,
                self.core.fixed_placement_policy,
                vote,
            )
        }
        .map_err(|error| storage_error(ErrorSubject::Vote, ErrorVerb::Write, error));
        if result.is_ok() {
            self.core.signal_proactive_checkpoint();
        }
        result
    }

    async fn read_vote(
        &mut self,
    ) -> Result<Option<Vote<SessionConsensusNodeId>>, StorageError<SessionConsensusNodeId>> {
        let conn = self.core.conn.lock().await;
        consensus::with_durable_authority_raw_read_sync(
            &conn,
            self.core.storage_identity,
            self.core.authority_profile,
            &self.core.expected_members,
            &self.core.expected_bindings,
            self.core.fixed_placement_policy,
            |conn| consensus::read_vote_sync(conn, self.core.storage_identity),
        )
        .map_err(|error| storage_error(ErrorSubject::Vote, ErrorVerb::Read, error))
    }

    async fn save_committed(
        &mut self,
        committed: Option<LogId<SessionConsensusNodeId>>,
    ) -> Result<(), StorageError<SessionConsensusNodeId>> {
        let _prune_preemption = self.core.request_consensus_log_prune_preemption().await;
        let result = {
            let conn = self.core.conn.lock().await;
            consensus::save_committed_with_authority_sync(
                &conn,
                self.core.storage_identity,
                self.core.authority_profile,
                &self.core.expected_members,
                &self.core.expected_bindings,
                self.core.fixed_placement_policy,
                committed,
            )
        }
        .map_err(|error| storage_error(ErrorSubject::Logs, ErrorVerb::Write, error));
        if result.is_ok() {
            self.core.signal_proactive_checkpoint();
        }
        result
    }

    async fn read_committed(
        &mut self,
    ) -> Result<Option<LogId<SessionConsensusNodeId>>, StorageError<SessionConsensusNodeId>> {
        let conn = self.core.conn.lock().await;
        consensus::with_durable_authority_raw_read_sync(
            &conn,
            self.core.storage_identity,
            self.core.authority_profile,
            &self.core.expected_members,
            &self.core.expected_bindings,
            self.core.fixed_placement_policy,
            |conn| consensus::read_committed_sync(conn, self.core.storage_identity),
        )
        .map_err(|error| storage_error(ErrorSubject::Logs, ErrorVerb::Read, error))
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<SessionRaftTypeConfig>,
    ) -> Result<(), StorageError<SessionConsensusNodeId>>
    where
        I: IntoIterator<Item = Entry<SessionRaftTypeConfig>> + Send,
        I::IntoIter: Send,
    {
        let entries: Vec<_> = entries.into_iter().collect();
        let has_entries = !entries.is_empty();
        let _prune_preemption = self.core.request_consensus_log_prune_preemption().await;
        let result = {
            let conn = self.core.conn.lock().await;
            consensus::append_logs_with_authority_and_diagnostics_sync(
                &conn,
                self.core.storage_identity,
                self.core.authority_profile,
                &self.core.expected_members,
                &self.core.expected_bindings,
                self.core.fixed_placement_policy,
                &entries,
                self.core.diagnostics.as_deref(),
            )
        };
        match result {
            Ok(()) => {
                callback.log_io_completed(Ok(()));
                if has_entries {
                    self.core.signal_proactive_checkpoint();
                }
                Ok(())
            }
            Err(error) => {
                callback
                    .log_io_completed(Err(io::Error::other("session consensus log append failed")));
                Err(storage_error(ErrorSubject::Logs, ErrorVerb::Write, error))
            }
        }
    }

    async fn truncate(
        &mut self,
        log_id: LogId<SessionConsensusNodeId>,
    ) -> Result<(), StorageError<SessionConsensusNodeId>> {
        let _prune_preemption = self.core.request_consensus_log_prune_preemption().await;
        let result = {
            let conn = self.core.conn.lock().await;
            (|| -> io::Result<()> {
                ensure_recovery_terminal_allows_log_compaction(&self.core, &conn)
                    .map_err(|_| io::Error::other("operator recovery blocks log truncation"))?;
                consensus::truncate_logs_with_authority_sync(
                    &conn,
                    self.core.storage_identity,
                    self.core.authority_profile,
                    &self.core.expected_members,
                    &self.core.expected_bindings,
                    self.core.fixed_placement_policy,
                    &log_id,
                )
            })()
        }
        .map_err(|error| storage_error(ErrorSubject::Log(log_id), ErrorVerb::Delete, error));
        if result.is_ok() {
            self.core.signal_proactive_checkpoint();
        }
        result
    }

    async fn purge(
        &mut self,
        log_id: LogId<SessionConsensusNodeId>,
    ) -> Result<(), StorageError<SessionConsensusNodeId>> {
        wait_until_applied(&self.core, &log_id)
            .await
            .map_err(|error| storage_error(ErrorSubject::Log(log_id), ErrorVerb::Delete, error))?;
        let _prune_preemption = self.core.request_consensus_log_prune_preemption().await;
        let result = {
            let conn = self.core.conn.lock().await;
            (|| -> io::Result<()> {
                ensure_recovery_terminal_allows_log_compaction(&self.core, &conn)
                    .map_err(|_| io::Error::other("operator recovery blocks log purge"))?;
                if self.core.authority_profile == ConsensusAuthorityProfile::FixedImmutable
                    && self.core.consensus_log_prune_lane().is_none()
                {
                    consensus::purge_logs_without_prune_lane_with_authority_sync(
                        &conn,
                        self.core.storage_identity,
                        self.core.authority_profile,
                        &self.core.expected_members,
                        &self.core.expected_bindings,
                        self.core.fixed_placement_policy,
                        &log_id,
                    )
                } else {
                    consensus::purge_logs_with_authority_sync(
                        &conn,
                        self.core.storage_identity,
                        self.core.authority_profile,
                        &self.core.expected_members,
                        &self.core.expected_bindings,
                        self.core.fixed_placement_policy,
                        &log_id,
                    )
                }
            })()
        }
        .map_err(|error| storage_error(ErrorSubject::Log(log_id), ErrorVerb::Delete, error));
        if result.is_ok() {
            self.core.signal_proactive_checkpoint();
            if let Some(lane) = self.core.consensus_log_prune_lane() {
                lane.signal();
            }
        }
        result
    }
}

/// A recovery V2 marker must remain physically available to every
/// Active/Pending sidecar proof. OpenRaft's log-store contract permits purge
/// after apply even when no snapshot covers the prefix, so enforce the
/// recovery publication boundary here rather than relying on scheduler
/// behavior. An exact consumed tombstone is permitted: its authenticated
/// workflow proof supplies the later historical/snapshot path on retry.
fn ensure_recovery_terminal_allows_log_compaction(
    core: &SqliteConsensusCore,
    conn: &rusqlite::Connection,
) -> Result<(), SessionConsensusStorageError> {
    let Some(database_file) = core.database_file.as_ref() else {
        return Ok(());
    };
    let classification = consensus::classify_operator_recovery_latch_with_connection_sync(
        database_file.path(),
        conn,
    )
    .map_err(|_| SessionConsensusStorageError::CorruptState)?;
    if classification.latch().is_some() {
        return Err(SessionConsensusStorageError::BackendUnavailable);
    }
    // An exact consumed terminal remains distinguishable from a missing
    // sidecar in this classifier. Both ordinary pristine databases and the
    // post-consumed state may compact; Active/Pending never may.
    let _already_consumed = classification.has_consumed_terminal();
    Ok(())
}

impl RaftStateMachine<SessionRaftTypeConfig> for SqliteConsensusStateMachine {
    type SnapshotBuilder = SqliteConsensusSnapshotBuilder;

    async fn applied_state(
        &mut self,
    ) -> Result<
        (
            Option<LogId<SessionConsensusNodeId>>,
            StoredMembership<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>,
        ),
        StorageError<SessionConsensusNodeId>,
    > {
        let (applied, membership) = {
            let _membership_apply = self.begin_membership_apply().await;
            let conn = self.core.conn.lock().await;
            let (applied, membership) = consensus::with_durable_authority_raw_read_sync(
                &conn,
                self.core.storage_identity,
                self.core.authority_profile,
                &self.core.expected_members,
                &self.core.expected_bindings,
                self.core.fixed_placement_policy,
                |conn| {
                    Ok((
                        consensus::read_applied_sync(conn, self.core.storage_identity)?,
                        consensus::read_membership_sync(conn, self.core.storage_identity)?,
                    ))
                },
            )
            .map_err(|error| storage_error(ErrorSubject::StateMachine, ErrorVerb::Read, error))?;
            self.observe_applied_membership(&membership)
                .map_err(membership_admission_storage_error)?;
            (applied, membership)
        };
        Ok((applied, membership))
    }

    async fn apply<I>(
        &mut self,
        entries: I,
    ) -> Result<Vec<super::SessionConsensusResponse>, StorageError<SessionConsensusNodeId>>
    where
        I: IntoIterator<Item = Entry<SessionRaftTypeConfig>> + Send,
        I::IntoIter: Send,
    {
        #[cfg(test)]
        let _apply_permit = self.core.apply_gate.acquire().await.map_err(|_| {
            storage_error(
                ErrorSubject::StateMachine,
                ErrorVerb::Write,
                io::Error::other("session consensus test apply gate closed"),
            )
        })?;
        let entries: Vec<_> = entries.into_iter().collect();
        let has_entries = !entries.is_empty();
        let applies_membership = entries
            .iter()
            .any(|entry| matches!(&entry.payload, EntryPayload::Membership(_)));
        let applies_uniform_cutover = self.membership_admission.as_ref().is_some_and(|admission| {
            entries.iter().any(|entry| {
                let EntryPayload::Membership(membership) = &entry.payload else {
                    return false;
                };
                admission.requires_uniform_membership_fence(membership)
            })
        });
        let last_applied = entries.last().map(|entry| entry.log_id);
        let applied = {
            let _membership_apply = if applies_uniform_cutover {
                self.begin_membership_apply().await
            } else {
                None
            };
            let _prune_preemption = self.core.request_consensus_log_prune_preemption().await;
            let conn = self.core.conn.lock().await;
            let applied = consensus::apply_entries_with_authority_and_diagnostics_sync(
                &conn,
                self.core.storage_identity,
                &self.core.caps,
                self.core.authority_profile,
                &self.core.expected_members,
                &self.core.expected_bindings,
                self.core.fixed_placement_policy,
                entries,
                self.core.diagnostics.as_deref(),
            )
            .map_err(|error| storage_error(ErrorSubject::StateMachine, ErrorVerb::Write, error))?;
            if applies_membership {
                let membership = consensus::read_membership_sync(&conn, self.core.storage_identity)
                    .map_err(|error| {
                        storage_error(ErrorSubject::StateMachine, ErrorVerb::Read, error)
                    })?;
                self.observe_applied_membership(&membership)
                    .map_err(membership_admission_storage_error)?;
            }
            applied
        };
        // This follows the successful durable state-machine commit and only
        // enqueues fixed-capacity best-effort work. It never awaits a
        // checkpoint before Openraft can publish the accepted response.
        if has_entries {
            self.core.signal_proactive_checkpoint();
        }
        if let Some(last_applied) = last_applied {
            self.core.applied_progress.send_replace(Some(last_applied));
        }
        notify_watchers(&self.core, &applied.notifications).await;
        Ok(applied.responses)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        SqliteConsensusSnapshotBuilder {
            core: self.core.clone(),
            _snapshot_directory_lease: Arc::clone(&self._snapshot_directory_lease),
            _shutdown_guard: self.shutdown_guard.child(),
        }
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<SessionSnapshotFile>, StorageError<SessionConsensusNodeId>> {
        // Serialize receive creation with build/install admission. The file
        // returned below remains its durable reservation after this guard is
        // released, while `snapshot_receive_admission` prevents a second
        // receiver from taking another slot for this core.
        let _snapshot_guard = self.core.snapshot_gate.lock().await;
        let receive_admission = Arc::clone(&self.core.snapshot_receive_admission)
            .try_acquire_owned()
            .map_err(|_| {
                storage_error(
                    ErrorSubject::Snapshot(None),
                    ErrorVerb::Write,
                    io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "session consensus snapshot receiver is already active",
                    ),
                )
            })?;
        let durable_survivors = validate_and_clean_snapshot_directory(
            &self.core,
            Some(&self._snapshot_directory_lease),
        )
        .await
        .map_err(|_| {
            storage_error(
                ErrorSubject::Snapshot(None),
                ErrorVerb::Write,
                io::Error::other("session consensus snapshot staging cleanup failed"),
            )
        })?;
        reserve_snapshot_directory_entries(durable_survivors, SNAPSHOT_RECEIVE_RESERVATION_ENTRIES)
            .map_err(|_| {
                storage_error(
                    ErrorSubject::Snapshot(None),
                    ErrorVerb::Write,
                    io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "session consensus snapshot directory capacity is exhausted",
                    ),
                )
            })?;
        let name = std::ffi::OsString::from(format!("incoming-{}.part", uuid::Uuid::new_v4()));
        let namespace_lease = Arc::clone(&self._snapshot_directory_lease);
        SessionSnapshotFile::create_with_cleanup_bounded_in_namespace(
            Arc::clone(&self._snapshot_directory_lease.namespace),
            name,
            Some(Arc::clone(&self.core.snapshot_cleanup_failed)),
            SNAPSHOT_ENVELOPE_MAX_BYTES,
            Some(receive_admission),
        )
        .await
        .map(move |mut snapshot| {
            snapshot.retain_namespace_lease(Arc::clone(&namespace_lease));
            Box::new(snapshot)
        })
        .map_err(|error| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, error))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>,
        snapshot: Box<SessionSnapshotFile>,
    ) -> Result<(), StorageError<SessionConsensusNodeId>> {
        let live_terminal_consumer = LiveTerminalRecoveryHandoffConsumer::from_live_snapshot_owner(
            &self.core,
            &self._snapshot_directory_lease,
        );
        let snapshot_gate = live_terminal_consumer
            .acquire_gate()
            .await
            .map_err(|error| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Write,
                    io::Error::other(error),
                )
            })?;
        let integrity_work = SnapshotIntegrityWork {
            _gate: snapshot_gate.clone(),
            _lease: Arc::clone(&self._snapshot_directory_lease),
        };
        reject_indeterminate_snapshot_publication(&self.core).map_err(|error| {
            storage_error(
                ErrorSubject::Snapshot(Some(meta.signature())),
                ErrorVerb::Write,
                error,
            )
        })?;
        // Installation is also a recovery admission. A predecessor left by a
        // transient delete failure must be reclaimed before another incoming
        // image consumes bounded directory capacity.
        let durable_survivors = validate_and_clean_snapshot_directory(
            &self.core,
            Some(&self._snapshot_directory_lease),
        )
        .await
        .map_err(|_| {
            storage_error(
                ErrorSubject::Snapshot(Some(meta.signature())),
                ErrorVerb::Write,
                io::Error::other("session consensus snapshot staging cleanup failed"),
            )
        })?;
        reserve_snapshot_directory_entries(
            durable_survivors,
            snapshot_install_reservation_entries(self.core.authority_profile),
        )
        .map_err(|_| {
            storage_error(
                ErrorSubject::Snapshot(Some(meta.signature())),
                ErrorVerb::Write,
                io::Error::other("session consensus snapshot directory capacity is exhausted"),
            )
        })?;
        let mut snapshot = *snapshot;
        snapshot.shutdown().await.map_err(|error| {
            storage_error(
                ErrorSubject::Snapshot(Some(meta.signature())),
                ErrorVerb::Write,
                error,
            )
        })?;
        snapshot.sync_all().await.map_err(|error| {
            storage_error(
                ErrorSubject::Snapshot(Some(meta.signature())),
                ErrorVerb::Write,
                error,
            )
        })?;
        let raw_name = std::ffi::OsString::from(format!("install-{}.sqlite", uuid::Uuid::new_v4()));
        let raw_path = self
            ._snapshot_directory_lease
            .namespace
            .sqlite_child_path(&raw_name)
            .map_err(|error| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Write,
                    error,
                )
            })?;
        let raw_artifact = SnapshotArtifact::new_in_namespace(
            Arc::clone(&self._snapshot_directory_lease.namespace),
            &raw_name,
            Arc::clone(&self.core.snapshot_cleanup_failed),
        )
        .map_err(|error| {
            storage_error(
                ErrorSubject::Snapshot(Some(meta.signature())),
                ErrorVerb::Write,
                error,
            )
        })?;
        raw_artifact
            .retain_namespace_lease(Arc::clone(&self._snapshot_directory_lease))
            .map_err(|error| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Write,
                    error,
                )
            })?;
        let file_name = format!("snapshot-{}.opc", uuid::Uuid::new_v4());
        let final_path = self
            ._snapshot_directory_lease
            .namespace
            .sqlite_child_path(std::ffi::OsStr::new(&file_name))
            .map_err(|error| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Write,
                    error,
                )
            })?;
        let promoted_name =
            std::ffi::OsString::from(format!("promote-{}.part", uuid::Uuid::new_v4()));
        let (
            raw_snapshot,
            _raw_snapshot_cleanup,
            mut promoted_cleanup,
            promoted_pin,
            checksum,
            total_length,
        ) = if self.core.authority_profile == ConsensusAuthorityProfile::FixedImmutable {
            // The received stream is mutable until it is copied.  Consume it
            // exactly once into a fresh SDK-owned envelope, keep the output's
            // O_NOFOLLOW read pin continuously, then seal and validate that
            // pin.  The raw SQLite image is derived only from a clone of this
            // validated sealed descriptor; no later operation reads the
            // received pathname or descriptor as content authority.
            let received_length = snapshot
                .metadata()
                .await
                .map_err(|error| {
                    storage_error(
                        ErrorSubject::Snapshot(Some(meta.signature())),
                        ErrorVerb::Read,
                        error,
                    )
                })?
                .len();
            let (promoted_cleanup, promoted_pin) = copy_and_promote_from_reader_fixed_in_namespace(
                &mut snapshot,
                Arc::clone(&self._snapshot_directory_lease.namespace),
                &promoted_name,
                std::ffi::OsStr::new(&file_name),
                received_length,
                self.core.snapshot_integrity,
                integrity_work.clone(),
            )
            .await
            .map_err(|error| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Write,
                    error,
                )
            })?;
            snapshot.close_and_cleanup().await.map_err(|error| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Write,
                    error,
                )
            })?;
            #[cfg(test)]
            wait_before_promoted_verify(&final_path).await;
            let (promoted_pin, checksum, verified) =
                verify_received_snapshot(promoted_pin, final_path.clone(), integrity_work.clone())
                    .await
                    .map_err(|error| {
                        storage_error(
                            ErrorSubject::Snapshot(Some(meta.signature())),
                            ErrorVerb::Read,
                            error,
                        )
                    })?;
            let total_length = verified.total_length;
            let mut sealed_source = SessionSnapshotFile::from_pinned(
                promoted_pin.try_clone().map_err(|error| {
                    storage_error(
                        ErrorSubject::Snapshot(Some(meta.signature())),
                        ErrorVerb::Read,
                        error,
                    )
                })?,
                final_path.clone(),
            )
            .await
            .map_err(|error| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Read,
                    error,
                )
            })?;
            let raw_snapshot = extract_snapshot_database_from_reader_in_namespace(
                &mut sealed_source,
                Arc::clone(&self._snapshot_directory_lease.namespace),
                &raw_name,
                verified.payload_length,
                checksum,
            )
            .await
            .map_err(|error| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Write,
                    error,
                )
            })?;
            if !raw_snapshot
                .path_matches_identity(&raw_path)
                .map_err(|error| {
                    storage_error(
                        ErrorSubject::Snapshot(Some(meta.signature())),
                        ErrorVerb::Write,
                        error,
                    )
                })?
            {
                return Err(storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Write,
                    consensus::invalid_data(
                        "session consensus extracted snapshot path was replaced",
                    ),
                ));
            }
            raw_artifact
                .record_identity_from_file(raw_snapshot.file())
                .map_err(|error| {
                    storage_error(
                        ErrorSubject::Snapshot(Some(meta.signature())),
                        ErrorVerb::Write,
                        error,
                    )
                })?;
            drop(sealed_source);

            // The raw image is a private derivative of the validated envelope.
            // Pin and seal it before SQLite attaches it so a writable alias can
            // never change the database after its bound extraction hash.
            let raw_pin = raw_snapshot.pin_readonly_from_writer().map_err(|error| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Write,
                    error,
                )
            })?;
            let (raw_file, raw_snapshot_cleanup) = raw_snapshot.into_file_with_cleanup();
            raw_file.sync_all().map_err(|error| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Write,
                    error,
                )
            })?;
            drop(raw_file);
            let raw_pin = seal_snapshot_pin(
                raw_pin,
                self.core.snapshot_integrity,
                Some(checksum),
                Some(integrity_work.clone()),
            )
            .await
            .map_err(|error| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Write,
                    error,
                )
            })?;
            (
                raw_pin,
                raw_snapshot_cleanup,
                promoted_cleanup,
                Some(promoted_pin),
                checksum,
                total_length,
            )
        } else {
            let (payload_length, checksum, total_length) =
                verify_snapshot_envelope_reader(&mut snapshot)
                    .await
                    .map_err(|error| {
                        storage_error(
                            ErrorSubject::Snapshot(Some(meta.signature())),
                            ErrorVerb::Read,
                            error,
                        )
                    })?;
            let raw_snapshot = extract_snapshot_database_from_reader_in_namespace(
                &mut snapshot,
                Arc::clone(&self._snapshot_directory_lease.namespace),
                &raw_name,
                payload_length,
                checksum,
            )
            .await
            .map_err(|error| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Write,
                    error,
                )
            })?;
            if !raw_snapshot
                .path_matches_identity(&raw_path)
                .map_err(|error| {
                    storage_error(
                        ErrorSubject::Snapshot(Some(meta.signature())),
                        ErrorVerb::Write,
                        error,
                    )
                })?
            {
                return Err(storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Write,
                    consensus::invalid_data(
                        "session consensus extracted snapshot path was replaced",
                    ),
                ));
            }
            raw_artifact
                .record_identity_from_file(raw_snapshot.file())
                .map_err(|error| {
                    storage_error(
                        ErrorSubject::Snapshot(Some(meta.signature())),
                        ErrorVerb::Write,
                        error,
                    )
                })?;
            let promoted_cleanup = copy_and_promote_from_reader_in_namespace(
                &mut snapshot,
                Arc::clone(&self._snapshot_directory_lease.namespace),
                &promoted_name,
                std::ffi::OsStr::new(&file_name),
                total_length,
            )
            .await
            .map_err(|error| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Write,
                    error,
                )
            })?;
            snapshot.close_and_cleanup().await.map_err(|error| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Write,
                    error,
                )
            })?;
            #[cfg(test)]
            wait_before_promoted_verify(&final_path).await;
            let promoted_file = open_snapshot_child_in_namespace(
                Arc::clone(&self._snapshot_directory_lease.namespace),
                std::ffi::OsString::from(&file_name),
            )
            .await
            .map_err(|error| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Read,
                    error,
                )
            })?;
            let mut promoted_snapshot =
                SessionSnapshotFile::from_std(promoted_file, final_path.clone())
                    .await
                    .map_err(|error| {
                        storage_error(
                            ErrorSubject::Snapshot(Some(meta.signature())),
                            ErrorVerb::Read,
                            error,
                        )
                    })?;
            let (_, promoted_checksum, promoted_length) =
                verify_snapshot_envelope_reader(&mut promoted_snapshot)
                    .await
                    .map_err(|error| {
                        storage_error(
                            ErrorSubject::Snapshot(Some(meta.signature())),
                            ErrorVerb::Read,
                            error,
                        )
                    })?;
            if promoted_checksum != checksum || promoted_length != total_length {
                return Err(storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Read,
                    consensus::invalid_data("session consensus promoted snapshot is inconsistent"),
                ));
            }
            (
                raw_snapshot,
                None,
                promoted_cleanup,
                None,
                checksum,
                total_length,
            )
        };

        let installs_uniform_cutover =
            self.membership_admission.as_ref().is_some_and(|admission| {
                admission.requires_uniform_membership_fence(meta.last_membership.membership())
            });
        // Authenticate and retain the predecessor before entering the
        // replacement transaction. Fixed-profile predecessor verification is
        // a bounded full scan; snapshot ownership already excludes another
        // publisher, so it does not need either primary writer guard.
        let (previous, legacy_reseed_predecessor) = {
            let conn = self.core.conn.lock().await;
            let previous = consensus::read_current_snapshot_sync(&conn, self.core.storage_identity)
                .map_err(|error| {
                    storage_error(
                        ErrorSubject::Snapshot(Some(meta.signature())),
                        ErrorVerb::Read,
                        error,
                    )
                })?;
            let legacy_reseed_predecessor =
                if self.core.authority_profile == ConsensusAuthorityProfile::FixedImmutable {
                    let reseed = consensus::read_legacy_fixed_snapshot_reseed_sync(
                        &conn,
                        self.core.storage_identity,
                    )
                    .map_err(|error| {
                        storage_error(
                            ErrorSubject::Snapshot(Some(meta.signature())),
                            ErrorVerb::Read,
                            error,
                        )
                    })?;
                    match (reseed.as_ref(), previous.as_ref()) {
                        (Some(reseed), Some(previous)) => reseed
                            .matches_current(self.core.storage_identity, previous)
                            .map_err(|error| {
                                storage_error(
                                    ErrorSubject::Snapshot(Some(meta.signature())),
                                    ErrorVerb::Read,
                                    error,
                                )
                            })?,
                        (Some(_), None) => {
                            return Err(storage_error(
                                ErrorSubject::Snapshot(Some(meta.signature())),
                                ErrorVerb::Read,
                                consensus::invalid_data(
                                    "legacy fixed snapshot reseed has no current snapshot",
                                ),
                            ));
                        }
                        (None, _) => false,
                    }
                } else {
                    false
                };
            (previous, legacy_reseed_predecessor)
        };
        let previous_artifact = if legacy_reseed_predecessor {
            // The legacy image has no immutable payload pin. Do not open it
            // for a scan or use it as an unlink authority; normal restart
            // cleanup may reclaim it only after successor metadata commits.
            None
        } else {
            track_previous_snapshot_artifact(
                &previous,
                Arc::clone(&self.core.snapshot_cleanup_failed),
                self.core.authority_profile,
                self.core.snapshot_integrity,
                Arc::clone(&self._snapshot_directory_lease),
            )
            .await
            .map_err(|error| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Read,
                    error,
                )
            })?
        };
        #[cfg(test)]
        wait_before_recovery_publication_fence(self.core.snapshot_dir.as_ref()).await;
        let _membership_apply = if installs_uniform_cutover {
            self.begin_membership_apply().await
        } else {
            None
        };
        let mut prune_preemption = Some(self.core.request_consensus_log_prune_preemption().await);
        let conn = live_terminal_consumer
            .acquire_publication_connection(&snapshot_gate)
            .await
            .map_err(|error| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Write,
                    io::Error::other(error),
                )
            })?;
        let install_result = {
            let observed_previous =
                consensus::read_current_snapshot_sync(&conn, self.core.storage_identity).map_err(
                    |error| {
                        storage_error(
                            ErrorSubject::Snapshot(Some(meta.signature())),
                            ErrorVerb::Read,
                            error,
                        )
                    },
                )?;
            if observed_previous != previous {
                return Err(storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Write,
                    consensus::invalid_data(
                        "session consensus current snapshot changed under the publication owner",
                    ),
                ));
            }
            if let Some(promoted_pin) = &promoted_pin {
                promoted_pin
                    .verify_bound_immutable_snapshot_envelope(&final_path, total_length)
                    .map_err(|error| {
                        storage_error(
                            ErrorSubject::Snapshot(Some(meta.signature())),
                            ErrorVerb::Read,
                            error,
                        )
                    })?;
            }
            match publish_snapshot_metadata_with_readback(
                &conn,
                self.core.storage_identity,
                meta,
                &file_name,
                checksum,
                total_length,
                &mut promoted_cleanup,
                self.core.snapshot_publication_indeterminate.as_ref(),
                || {
                    consensus::install_snapshot_database_from_pinned_with_authority_sync(
                        &conn,
                        self.core.storage_identity,
                        self.core.authority_profile,
                        Some(&self.core.expected_members),
                        Some(&self.core.expected_bindings),
                        self.core.fixed_placement_policy,
                        raw_snapshot,
                        promoted_pin.as_ref().map(|pin| (pin, final_path.as_path())),
                        meta,
                        &file_name,
                        checksum,
                        total_length,
                    )
                },
            ) {
                Err(error) => Err(storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Write,
                    error,
                )),
                Ok(()) => {
                    self.observe_applied_membership(&meta.last_membership)
                        .map_err(membership_admission_storage_error)?;
                    Ok((previous, previous_artifact))
                }
            }
        };
        // `acquire_publication_connection()` intentionally holds this guard
        // through the irreversible replacement transaction.  That boundary
        // is complete now; retaining the named guard through post-commit
        // diagnostics would self-deadlock on the diagnostic re-lock below,
        // and would also strand OpenRaft's concurrently dispatched PurgeLog.
        drop(conn);
        let (previous, previous_artifact) = match install_result {
            Ok(previous) => previous,
            Err(error) => return Err(error),
        };
        // OpenRaft may enqueue PurgeLog immediately after dispatching this
        // install to its independent state-machine worker.  The replacement
        // transaction has now committed both the installed applied frontier
        // and the snapshot's exact logical purge floor, so it is safe to
        // release that waiter before best-effort diagnostics or artifact
        // reclamation.  Those follow-up steps cannot revoke the committed
        // coverage contract.
        self.core.applied_progress.send_replace(meta.last_log_id);
        // The fixed-profile prune lane permit protects the replacement
        // transaction itself, not post-commit diagnostics or staging-file
        // cleanup.  OpenRaft may already be awaiting the matching PurgeLog on
        // its core worker; retaining this non-reentrant permit after the
        // durable applied/snapshot/purge frontiers are committed would make
        // that purge wait on this install's return path.
        drop(prune_preemption.take());
        #[cfg(test)]
        wait_after_snapshot_install_applied_progress(self.core.snapshot_dir.as_ref()).await;
        if let Some(diagnostics) = &self.core.diagnostics {
            let conn = self.core.conn.lock().await;
            match consensus::protected_roster_diagnostic_occupancy_sync(
                &conn,
                self.core.storage_identity,
            ) {
                Ok(occupancy) => diagnostics.set_protected_roster_occupancy(occupancy),
                Err(_) => diagnostics.invalidate_protected_roster_occupancy(),
            }
        }
        self.core.signal_proactive_checkpoint();
        raw_artifact.remove().await.map_err(|error| {
            storage_error(
                ErrorSubject::Snapshot(Some(meta.signature())),
                ErrorVerb::Write,
                error,
            )
        })?;
        if !legacy_reseed_predecessor {
            remove_old_snapshot(
                previous,
                &file_name,
                previous_artifact.map(RetainedCurrentSnapshotArtifact::into_cleanup_artifact),
            )
            .await
            .map_err(|error| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Write,
                    error,
                )
            })?;
        }
        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<SessionRaftTypeConfig>>, StorageError<SessionConsensusNodeId>> {
        let current = {
            let conn = self.core.conn.lock().await;
            consensus::with_durable_authority_raw_read_sync(
                &conn,
                self.core.storage_identity,
                self.core.authority_profile,
                &self.core.expected_members,
                &self.core.expected_bindings,
                self.core.fixed_placement_policy,
                |conn| consensus::read_current_snapshot_sync(conn, self.core.storage_identity),
            )
            .map_err(|error| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Read, error))?
        };
        let Some((meta, file_name, expected_checksum, expected_length)) = current else {
            return Ok(None);
        };
        let path = self
            ._snapshot_directory_lease
            .namespace
            .sqlite_child_path(std::ffi::OsStr::new(&file_name))
            .map_err(|error| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Read,
                    error,
                )
            })?;
        let (mut snapshot, checksum, length) =
            if self.core.authority_profile == ConsensusAuthorityProfile::FixedImmutable {
                // Validate and return the measured descriptor itself. A pathname
                // reopen after measurement could substitute an unsealed inode.
                let file = open_snapshot_child_in_namespace(
                    Arc::clone(&self._snapshot_directory_lease.namespace),
                    std::ffi::OsString::from(&file_name),
                )
                .await
                .map_err(|error| {
                    storage_error(
                        ErrorSubject::Snapshot(Some(meta.signature())),
                        ErrorVerb::Read,
                        error,
                    )
                })?;
                let pinned = verify_admitted_snapshot(
                    file,
                    Arc::clone(&self._snapshot_directory_lease),
                    std::ffi::OsString::from(&file_name),
                    self.core.snapshot_integrity,
                    expected_checksum,
                    expected_length,
                )
                .await
                .map_err(|error| {
                    storage_error(
                        ErrorSubject::Snapshot(Some(meta.signature())),
                        ErrorVerb::Read,
                        error,
                    )
                })?;
                let snapshot = SessionSnapshotFile::from_pinned(pinned, path.clone())
                    .await
                    .map_err(|error| {
                        storage_error(
                            ErrorSubject::Snapshot(Some(meta.signature())),
                            ErrorVerb::Read,
                            error,
                        )
                    })?;
                (snapshot, expected_checksum, expected_length)
            } else {
                let file = open_snapshot_child_in_namespace(
                    Arc::clone(&self._snapshot_directory_lease.namespace),
                    std::ffi::OsString::from(&file_name),
                )
                .await
                .map_err(|error| {
                    storage_error(
                        ErrorSubject::Snapshot(Some(meta.signature())),
                        ErrorVerb::Read,
                        error,
                    )
                })?;
                let mut snapshot = SessionSnapshotFile::from_std(file, path.clone())
                    .await
                    .map_err(|error| {
                        storage_error(
                            ErrorSubject::Snapshot(Some(meta.signature())),
                            ErrorVerb::Read,
                            error,
                        )
                    })?;
                let (_, checksum, length) = verify_snapshot_envelope_reader(&mut snapshot)
                    .await
                    .map_err(|error| {
                        storage_error(
                            ErrorSubject::Snapshot(Some(meta.signature())),
                            ErrorVerb::Read,
                            error,
                        )
                    })?;
                (snapshot, checksum, length)
            };
        if checksum != expected_checksum || length != expected_length {
            return Err(storage_error(
                ErrorSubject::Snapshot(Some(meta.signature())),
                ErrorVerb::Read,
                consensus::invalid_data("session consensus snapshot metadata is inconsistent"),
            ));
        }
        snapshot.rewind().await.map_err(|error| {
            storage_error(
                ErrorSubject::Snapshot(Some(meta.signature())),
                ErrorVerb::Read,
                error,
            )
        })?;
        {
            let conn = self.core.conn.lock().await;
            consensus::with_durable_authority_raw_read_sync(
                &conn,
                self.core.storage_identity,
                self.core.authority_profile,
                &self.core.expected_members,
                &self.core.expected_bindings,
                self.core.fixed_placement_policy,
                |_| Ok(()),
            )
            .map_err(|error| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Read,
                    error,
                )
            })?;
        }
        Ok(Some(Snapshot {
            meta,
            snapshot: Box::new(snapshot),
        }))
    }
}

async fn wait_until_applied(
    core: &SqliteConsensusCore,
    through: &LogId<SessionConsensusNodeId>,
) -> io::Result<()> {
    let deadline = tokio::time::Instant::now()
        .checked_add(SNAPSHOT_APPLY_WAIT)
        .ok_or_else(|| consensus::invalid_data("session consensus apply wait is invalid"))?;
    let mut applied_progress = core.applied_progress.subscribe();
    loop {
        let applied = *applied_progress.borrow_and_update();
        if let Some(applied) = applied {
            if applied.index > through.index || &applied == through {
                return Ok(());
            }
            if applied.index == through.index {
                return Err(consensus::invalid_data(
                    "session consensus applied log conflicts with purge",
                ));
            }
        }
        tokio::time::timeout_at(deadline, applied_progress.changed())
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "session consensus apply wait timed out",
                )
            })?
            .map_err(|_| {
                consensus::invalid_data("session consensus apply progress channel closed")
            })?;
    }
}

/// Create the fallback copier's raw VACUUM source with the same strict name
/// grammar accepted by restart scavenging. `O_EXCL` remains authoritative;
/// the bounded sequence only gives a crashed predecessor a distinct retry
/// name without ever turning an unrecognized foreign child into ours.
fn create_vacuum_raw_snapshot_intermediate(
    namespace: Arc<RetainedSnapshotDirectory>,
) -> io::Result<PinnedSqliteFile> {
    for _ in 0..SNAPSHOT_DIRECTORY_MAX_ENTRIES {
        let name = consensus::next_snapshot_database_intermediate_name();
        match PinnedSqliteFile::create_new_in_namespace(Arc::clone(&namespace), &name) {
            Ok(snapshot) => return Ok(snapshot),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "session consensus snapshot intermediate name is unavailable",
    ))
}

/// Build a file-backed snapshot from one independently owned WAL reader. The
/// live consensus connection is held only long enough to admit and compare the
/// exact applied/membership cut; backup and offline finalization never retain
/// that mutex.
#[allow(clippy::result_large_err)]
async fn build_file_backed_snapshot_database(
    core: &SqliteConsensusCore,
    snapshot_directory_lease: Arc<SnapshotDirectoryLease>,
    raw_snapshot: PinnedSqliteFile,
    vacuum_snapshot: PinnedSqliteFile,
    snapshot_guard: LiveTerminalRecoveryHandoffGate,
    worker_shutdown_guard: ConsensusStorageShutdownGuard,
) -> Result<
    (
        LiveTerminalRecoveryHandoffGate,
        Option<(
            (
                Option<LogId<SessionConsensusNodeId>>,
                StoredMembership<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>,
            ),
            PinnedSqliteFile,
            u64,
        )>,
    ),
    StorageError<SessionConsensusNodeId>,
> {
    let Some(database_file) = &core.database_file else {
        // The caller normally avoids this branch, but retaining it makes an
        // accidental in-memory call fail closed without stranding either
        // already-created namespace child: both pins own exact cleanup.
        return Ok((snapshot_guard, None));
    };
    let worker = SnapshotCaptureWorker {
        reader: consensus::open_snapshot_read_connection(database_file)
            .map_err(|error| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Read, error))?,
        _snapshot_directory_lease: snapshot_directory_lease,
        _shutdown_guard: worker_shutdown_guard,
    };
    let source_cut = {
        let conn = core.conn.lock().await;
        match consensus::begin_snapshot_read_sync(&worker.reader, core.storage_identity) {
            Ok(source_cut) => {
                let live_file = opc_sqlite_file_control_sys::main_file_descriptor(&conn)
                    .map_err(|_| {
                        consensus::invalid_data(
                            "session consensus live source descriptor is unavailable",
                        )
                    })
                    .and_then(|file| {
                        PinnedSqliteFile::from_file(file, database_file.path().to_path_buf())
                    });
                match live_file {
                    Ok(live_file) if live_file.identity() != database_file.identity() => Err(
                        consensus::invalid_data("session consensus live source descriptor changed"),
                    ),
                    Err(error) => Err(error),
                    Ok(_) => consensus::with_durable_authority_raw_read_sync(
                        &conn,
                        core.storage_identity,
                        core.authority_profile,
                        &core.expected_members,
                        &core.expected_bindings,
                        core.fixed_placement_policy,
                        |conn| {
                            consensus::snapshot_applied_membership_sync(conn, core.storage_identity)
                        },
                    )
                    .and_then(|live_cut| {
                        if live_cut == source_cut {
                            Ok(source_cut)
                        } else {
                            Err(consensus::invalid_data(
                                "session consensus snapshot reader does not match the live cut",
                            ))
                        }
                    }),
                }
            }
            Err(error) => Err(error),
        }
    };
    let source_cut = match source_cut {
        Ok(source_cut) => source_cut,
        Err(error) => {
            let error = match consensus::release_snapshot_read_sync(&worker.reader) {
                Ok(()) => error,
                Err(release_error) => release_error,
            };
            return Err(storage_error(
                ErrorSubject::Snapshot(None),
                ErrorVerb::Read,
                error,
            ));
        }
    };

    let storage_identity = core.storage_identity;
    let authority_profile = core.authority_profile;
    let expected_members = core.expected_members.clone();
    let expected_bindings = core.expected_bindings.clone();
    let fixed_placement_policy = core.fixed_placement_policy;
    let snapshot_foreground_pacer = core.snapshot_foreground_pacer();
    #[cfg(test)]
    let snapshot_capture_gate = Arc::clone(&core.snapshot_capture_gate);
    // The owned gate guard moves into the worker and comes back with its
    // result. Cancellation of the async caller therefore cannot detach a
    // second snapshot worker or a second WAL-pinning reader for this core.
    let (captured, snapshot_guard) = tokio::task::spawn_blocking(move || {
        #[cfg(test)]
        snapshot_capture_gate.block_after_capture();
        let captured = consensus::capture_snapshot_database_from_reader_into_sync(
            &worker.reader,
            storage_identity,
            authority_profile,
            &expected_members,
            &expected_bindings,
            fixed_placement_policy,
            &source_cut,
            raw_snapshot,
            &snapshot_foreground_pacer,
        );
        // The source transaction is retained only through `Backup`; all
        // cleanup, VACUUM, validation, hashing, and sealing follow release.
        let released = consensus::release_snapshot_read_sync(&worker.reader);
        let captured = match (captured, released) {
            (Ok(captured), Ok(())) => (|| {
                let (captured_cut, raw_snapshot, wal_bytes) = captured;
                let raw_snapshot = consensus::finalize_captured_snapshot_database_into_sync(
                    storage_identity,
                    authority_profile,
                    &expected_members,
                    &expected_bindings,
                    fixed_placement_policy,
                    &captured_cut,
                    raw_snapshot,
                    vacuum_snapshot,
                    &snapshot_foreground_pacer,
                )?;
                // The raw source pin is consumed by finalization and removes
                // its exact namespace child.  The returned compacted pin is
                // the sole cleanup authority that proceeds to sealing.
                Ok((captured_cut, raw_snapshot, wal_bytes))
            })(),
            (Err(_), Err(release_error)) | (Ok(_), Err(release_error)) => Err(release_error),
            (Err(error), Ok(())) => Err(error),
        };
        // Keep cleanup-bearing capture state before the guard in drop order.
        // If the async caller is cancelled, Tokio drops this detached worker
        // output in field order, so every unpublished artifact is removed
        // before another snapshot builder can acquire sole-worker ownership.
        // Force Rust 2021 to retain the complete wrapper: field-disjoint
        // closure capture must not detach its reader from the shutdown guard
        // that bounds the WAL-pinning SQLite owner's lifetime.
        drop(worker);
        (captured, snapshot_guard)
    })
    .await
    .map_err(|_| {
        storage_error(
            ErrorSubject::Snapshot(None),
            ErrorVerb::Write,
            io::Error::other("session consensus snapshot worker is unavailable"),
        )
    })?;
    let (captured_cut, raw_snapshot, wal_bytes) = captured
        .map_err(|error| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, error))?;
    Ok((
        snapshot_guard,
        Some((captured_cut, raw_snapshot, wal_bytes)),
    ))
}

impl RaftSnapshotBuilder<SessionRaftTypeConfig> for SqliteConsensusSnapshotBuilder {
    async fn build_snapshot(
        &mut self,
    ) -> Result<Snapshot<SessionRaftTypeConfig>, StorageError<SessionConsensusNodeId>> {
        let live_terminal_consumer = LiveTerminalRecoveryHandoffConsumer::from_live_snapshot_owner(
            &self.core,
            &self._snapshot_directory_lease,
        );
        let snapshot_guard = live_terminal_consumer
            .acquire_gate()
            .await
            .map_err(|error| {
                storage_error(
                    ErrorSubject::Snapshot(None),
                    ErrorVerb::Write,
                    io::Error::other(error),
                )
            })?;
        let integrity_work = SnapshotIntegrityWork {
            _gate: snapshot_guard.clone(),
            _lease: Arc::clone(&self._snapshot_directory_lease),
        };
        reject_indeterminate_snapshot_publication(&self.core).map_err(|error| {
            storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, error)
        })?;
        // Queue wait is contention, not snapshot work. The duration exposed
        // to status starts at the single snapshot-gate acquisition and
        // includes this attempt's bounded staging recovery.
        let snapshot_started = std::time::Instant::now();
        // This bounded scavenger runs under the same single-worker gate as
        // capture. It can reclaim interrupted UUID artifacts but never the
        // current validated snapshot named by durable metadata.
        let durable_survivors = validate_and_clean_snapshot_directory(
            &self.core,
            Some(&self._snapshot_directory_lease),
        )
        .await
        .map_err(|_| {
            storage_error(
                ErrorSubject::Snapshot(None),
                ErrorVerb::Write,
                io::Error::other("session consensus snapshot staging cleanup failed"),
            )
        })?;
        reserve_snapshot_directory_entries(durable_survivors, SNAPSHOT_BUILD_RESERVATION_ENTRIES)
            .map_err(|_| {
            storage_error(
                ErrorSubject::Snapshot(None),
                ErrorVerb::Write,
                io::Error::other("session consensus snapshot directory capacity is exhausted"),
            )
        })?;
        let raw_name = std::ffi::OsString::from(format!("build-{}.sqlite", uuid::Uuid::new_v4()));
        let raw_path = self
            ._snapshot_directory_lease
            .namespace
            .sqlite_child_path(&raw_name)
            .map_err(|error| {
                storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, error)
            })?;
        let vacuum_name =
            std::ffi::OsString::from(format!("vacuum-{}.sqlite", uuid::Uuid::new_v4()));
        let vacuum_path = self
            ._snapshot_directory_lease
            .namespace
            .sqlite_child_path(&vacuum_name)
            .map_err(|error| {
                storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, error)
            })?;
        let file_name = format!("snapshot-{}.opc", uuid::Uuid::new_v4());
        // Persist the sole candidate name before its first durable rename.
        // If the process stops after rename/fsync and before metadata commit,
        // preflight can reclaim only this exact sealed namespace child before
        // reserving another successor. Ordinary snapshots do not create or
        // broaden this compatibility state.
        let legacy_reseed_candidate = if self.core.authority_profile
            == ConsensusAuthorityProfile::FixedImmutable
        {
            let conn = self.core.conn.lock().await;
            consensus::reserve_legacy_fixed_snapshot_reseed_candidate_sync(
                &conn,
                self.core.storage_identity,
                &file_name,
            )
            .map_err(|error| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, error))?
        } else {
            false
        };
        #[cfg(not(test))]
        let _ = legacy_reseed_candidate;
        let final_path = self
            ._snapshot_directory_lease
            .namespace
            .sqlite_child_path(std::ffi::OsStr::new(&file_name))
            .map_err(|error| {
                storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, error)
            })?;
        let (snapshot_guard, file_backed) = if self.core.database_file.is_some() {
            // Both namespace children are created and cleanup-armed before
            // the capture worker reaches any fallible SQLite setup.  Passing
            // their exact descriptors into SQLite avoids its legacy
            // pathname/O_EXCL helper and keeps post-create failure from
            // consuming bounded namespace capacity.
            let raw_snapshot = PinnedSqliteFile::create_new_in_namespace(
                Arc::clone(&self._snapshot_directory_lease.namespace),
                &raw_name,
            )
            .map_err(|error| {
                storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, error)
            })?;
            let vacuum_snapshot = PinnedSqliteFile::create_new_in_namespace(
                Arc::clone(&self._snapshot_directory_lease.namespace),
                &vacuum_name,
            )
            .map_err(|error| {
                storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, error)
            })?;
            build_file_backed_snapshot_database(
                &self.core,
                Arc::clone(&self._snapshot_directory_lease),
                raw_snapshot,
                vacuum_snapshot,
                snapshot_guard,
                self._shutdown_guard.child(),
            )
            .await?
        } else {
            (snapshot_guard, None)
        };
        let (
            (last_log_id, last_membership),
            (mut snapshot, mut sealed_pin, checksum, byte_length, mut published_cleanup),
            publication_path,
            captured_wal_bytes,
        ) = if let Some((membership, raw_snapshot, wal_bytes)) = file_backed {
            // `raw_snapshot` is the independently validated, descriptor-pinned
            // compacted inode. Seal that exact inode in place: copying it
            // into a third full-payload artifact would multiply peak snapshot
            // storage and leave a second publication boundary to defend.
            let sealed = seal_snapshot_database_in_place_in_namespace(
                raw_snapshot,
                Arc::clone(&self._snapshot_directory_lease.namespace),
                &vacuum_name,
                std::ffi::OsStr::new(&file_name),
                self.core.authority_profile == ConsensusAuthorityProfile::FixedImmutable,
                self.core.snapshot_integrity,
                integrity_work.clone(),
            )
            .await
            .map_err(|error| {
                storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, error)
            })?;
            (membership, sealed, vacuum_path.clone(), Some(wal_bytes))
        } else {
            // The fallback copier has the same two-file lifecycle as the
            // reader-backed path.  In particular its `vacuum-raw-*` source
            // is created and guarded before SQLite receives either
            // descriptor, so a metadata/cleanup-setup failure cannot strand
            // a recognizable staging child.
            let raw_snapshot = PinnedSqliteFile::create_new_in_namespace(
                Arc::clone(&self._snapshot_directory_lease.namespace),
                &raw_name,
            )
            .map_err(|error| {
                storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, error)
            })?;
            let intermediate_snapshot = create_vacuum_raw_snapshot_intermediate(Arc::clone(
                &self._snapshot_directory_lease.namespace,
            ))
            .map_err(|error| {
                storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, error)
            })?;
            let (membership, raw_snapshot) = {
                let conn = self.core.conn.lock().await;
                consensus::build_snapshot_database_pinned_with_authority_into_sync(
                    &conn,
                    consensus::SnapshotBuildAuthority {
                        identity: self.core.storage_identity,
                        profile: self.core.authority_profile,
                        expected_members: &self.core.expected_members,
                        expected_bindings: &self.core.expected_bindings,
                        fixed_placement_policy: self.core.fixed_placement_policy,
                    },
                    raw_snapshot,
                    intermediate_snapshot,
                )
            }
            .map_err(|error| {
                storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, error)
            })?;
            let sealed = seal_snapshot_database_in_place_in_namespace(
                raw_snapshot,
                Arc::clone(&self._snapshot_directory_lease.namespace),
                &raw_name,
                std::ffi::OsStr::new(&file_name),
                self.core.authority_profile == ConsensusAuthorityProfile::FixedImmutable,
                self.core.snapshot_integrity,
                integrity_work.clone(),
            )
            .await
            .map_err(|error| {
                storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, error)
            })?;
            (membership, sealed, raw_path.clone(), None)
        };
        // Promotion and guard rebinding form one cancellation-free local
        // filesystem step. If promotion fails the still-armed guard removes
        // only the exact temporary inode; once it succeeds the same guard owns
        // the exact final name until durable metadata publishes it.
        let publication_name = publication_path.file_name().ok_or_else(|| {
            storage_error(
                ErrorSubject::Snapshot(None),
                ErrorVerb::Write,
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "snapshot publication has no basename",
                ),
            )
        })?;
        self._snapshot_directory_lease
            .namespace
            .rename_noreplace(publication_name, std::ffi::OsStr::new(&file_name))
            .map_err(|error| {
                storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, error)
            })?;
        published_cleanup
            .rebind_in_namespace(
                Arc::clone(&self._snapshot_directory_lease.namespace),
                std::ffi::OsStr::new(&file_name),
            )
            .map_err(|error| {
                storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, error)
            })?;
        if let Some(pin) = &mut sealed_pin {
            pin.rebind_in_namespace(
                Arc::clone(&self._snapshot_directory_lease.namespace),
                std::ffi::OsStr::new(&file_name),
            )
            .map_err(|error| {
                storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, error)
            })?;
        }
        self._snapshot_directory_lease
            .namespace
            .sync()
            .map_err(|error| {
                storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, error)
            })?;
        #[cfg(test)]
        if legacy_reseed_candidate
            && take_legacy_fixed_snapshot_reseed_candidate_process_loss(
                self.core.snapshot_dir.as_ref(),
            )
        {
            // The renamed, fsync'd descriptor survives exactly as it would
            // after process loss. The next open consults the journal-bound
            // name before it retries the DB-authoritative successor build.
            published_cleanup.disarm();
            return Err(storage_error(
                ErrorSubject::Snapshot(None),
                ErrorVerb::Write,
                io::Error::new(
                    io::ErrorKind::Interrupted,
                    "injected legacy fixed snapshot reseed candidate process loss",
                ),
            ));
        }
        #[cfg(test)]
        let fixed_prepublication_scan_boundary = (self.core.authority_profile
            == ConsensusAuthorityProfile::FixedImmutable)
            .then(|| fixed_prepublication_scan_boundary(&final_path))
            .flatten();
        // Dynamic authority retains its bounded corruption-detection scan.
        // Fixed authority closes the final writable handle, seals an
        // O_RDONLY|O_NOFOLLOW descriptor, and performs its one full scan in a
        // blocking worker before the metadata mutex is acquired.
        let (published_pin, snapshot_guard) = if self.core.authority_profile
            == ConsensusAuthorityProfile::FixedImmutable
        {
            drop(snapshot);
            let published_pin = sealed_pin.take().ok_or_else(|| {
                storage_error(
                    ErrorSubject::Snapshot(None),
                    ErrorVerb::Write,
                    io::Error::other("fixed snapshot publication lost its writer-to-pin handoff"),
                )
            })?;
            let scan_path = final_path.clone();
            let namespace_lease = Arc::clone(&self._snapshot_directory_lease);
            // The worker owns the sole snapshot gate while the caller
            // awaits it. Cancellation therefore cannot admit another
            // builder until the descriptor pass and exact cleanup finish.
            let (scan_result, published_pin, snapshot_guard) =
                tokio::task::spawn_blocking(move || {
                    // The builder future may be cancelled while this scan is
                    // still holding the snapshot gate and exact descriptor.
                    // Keep namespace ownership until both are returned.
                    let _namespace_lease = namespace_lease;
                    let mut published_pin = published_pin;
                    let scan_result = published_pin
                        .verify_snapshot_envelope_and_bind_immutable_generation(
                            &scan_path,
                            SNAPSHOT_FOOTER_MAGIC,
                            SNAPSHOT_FOOTER_BYTES,
                            SNAPSHOT_MAX_BYTES,
                            checksum,
                            byte_length,
                        );
                    (scan_result, published_pin, snapshot_guard)
                })
                .await
                .map_err(|_| {
                    storage_error(
                        ErrorSubject::Snapshot(None),
                        ErrorVerb::Read,
                        io::Error::other(
                            "session consensus snapshot verification worker is unavailable",
                        ),
                    )
                })?;
            scan_result.map_err(|error| {
                storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Read, error)
            })?;
            (Some(published_pin), snapshot_guard)
        } else {
            let (_, observed_checksum, observed_length) =
                verify_snapshot_envelope_reader(&mut snapshot)
                    .await
                    .map_err(|error| {
                        storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Read, error)
                    })?;
            if observed_checksum != checksum || observed_length != byte_length {
                return Err(storage_error(
                    ErrorSubject::Snapshot(None),
                    ErrorVerb::Read,
                    consensus::invalid_data("session consensus sealed snapshot is inconsistent"),
                ));
            }
            snapshot.rewind().await.map_err(|error| {
                storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Read, error)
            })?;
            (None, snapshot_guard)
        };
        #[cfg(test)]
        if self.core.authority_profile == ConsensusAuthorityProfile::FixedImmutable {
            // The test gate is intentionally after the sealed bounded scan and
            // before core.conn metadata linearization. It proves an immutable
            // candidate cannot be modified while unrelated primary work is
            // still able to acquire the SQLite mutex.
            wait_before_fixed_prepublication_verify(&final_path).await;
        }
        let snapshot_id = format!("session-{}", uuid::Uuid::new_v4());
        let meta = SnapshotMeta {
            last_log_id,
            last_membership,
            snapshot_id,
        };
        // Pin and authenticate the predecessor while the snapshot owner still
        // serializes every publisher, but before taking either primary SQLite
        // writer guard. Fixed-profile authentication performs a bounded full
        // envelope scan and must not stall unrelated Raft work.
        let (previous, legacy_reseed_predecessor) = {
            let conn = self.core.conn.lock().await;
            let previous = consensus::read_current_snapshot_sync(&conn, self.core.storage_identity)
                .map_err(|error| {
                    storage_error(
                        ErrorSubject::Snapshot(Some(meta.signature())),
                        ErrorVerb::Read,
                        error,
                    )
                })?;
            let legacy_reseed_predecessor =
                if self.core.authority_profile == ConsensusAuthorityProfile::FixedImmutable {
                    let reseed = consensus::read_legacy_fixed_snapshot_reseed_sync(
                        &conn,
                        self.core.storage_identity,
                    )
                    .map_err(|error| {
                        storage_error(
                            ErrorSubject::Snapshot(Some(meta.signature())),
                            ErrorVerb::Read,
                            error,
                        )
                    })?;
                    match (reseed.as_ref(), previous.as_ref()) {
                        (Some(reseed), Some(previous)) => reseed
                            .matches_current(self.core.storage_identity, previous)
                            .map_err(|error| {
                                storage_error(
                                    ErrorSubject::Snapshot(Some(meta.signature())),
                                    ErrorVerb::Read,
                                    error,
                                )
                            })?,
                        (Some(_), None) => {
                            return Err(storage_error(
                                ErrorSubject::Snapshot(Some(meta.signature())),
                                ErrorVerb::Read,
                                consensus::invalid_data(
                                    "legacy fixed snapshot reseed has no current snapshot",
                                ),
                            ));
                        }
                        (None, _) => false,
                    }
                } else {
                    false
                };
            (previous, legacy_reseed_predecessor)
        };
        let previous_artifact = if legacy_reseed_predecessor {
            // The legacy image has no immutable payload pin.  Its pathname is
            // retained until the successor's metadata and journal-clear commit;
            // never read, measure, or use it as unlink authority here.
            None
        } else {
            track_previous_snapshot_artifact(
                &previous,
                Arc::clone(&self.core.snapshot_cleanup_failed),
                self.core.authority_profile,
                self.core.snapshot_integrity,
                Arc::clone(&self._snapshot_directory_lease),
            )
            .await
            .map_err(|error| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Read,
                    error,
                )
            })?
        };
        #[cfg(test)]
        wait_before_recovery_publication_fence(self.core.snapshot_dir.as_ref()).await;
        let prune_preemption = self.core.request_consensus_log_prune_preemption().await;
        let conn = live_terminal_consumer
            .acquire_publication_connection(&snapshot_guard)
            .await
            .map_err(|error| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Write,
                    io::Error::other(error),
                )
            })?;
        let observed_previous =
            consensus::read_current_snapshot_sync(&conn, self.core.storage_identity).map_err(
                |error| {
                    storage_error(
                        ErrorSubject::Snapshot(Some(meta.signature())),
                        ErrorVerb::Read,
                        error,
                    )
                },
            )?;
        if observed_previous != previous {
            return Err(storage_error(
                ErrorSubject::Snapshot(Some(meta.signature())),
                ErrorVerb::Write,
                consensus::invalid_data(
                    "session consensus current snapshot changed under the publication owner",
                ),
            ));
        }
        if let Some(published_pin) = &published_pin {
            published_pin
                .verify_bound_immutable_snapshot_envelope(&final_path, byte_length)
                .map_err(|error| {
                    storage_error(
                        ErrorSubject::Snapshot(Some(meta.signature())),
                        ErrorVerb::Read,
                        error,
                    )
                })?;
        }
        publish_snapshot_metadata_with_readback(
            &conn,
            self.core.storage_identity,
            &meta,
            &file_name,
            checksum,
            byte_length,
            &mut published_cleanup,
            self.core.snapshot_publication_indeterminate.as_ref(),
            || {
                consensus::save_current_snapshot_with_authority_sync(
                    &conn,
                    self.core.storage_identity,
                    self.core.authority_profile,
                    &self.core.expected_members,
                    &self.core.expected_bindings,
                    self.core.fixed_placement_policy,
                    &meta,
                    &file_name,
                    checksum,
                    byte_length,
                )
                .map(|_| consensus::SnapshotInstallPublicationOutcome::Clean)
            },
        )
        .map_err(|error| {
            storage_error(
                ErrorSubject::Snapshot(Some(meta.signature())),
                ErrorVerb::Write,
                error,
            )
        })?;
        // The same-connection readback above is the end of the irreversible
        // publication boundary. Predecessor cleanup and descriptor return are
        // already serialized by `snapshot_guard`; retaining either primary
        // writer guard across their asynchronous work would stall Raft.
        drop(conn);
        drop(prune_preemption);
        #[cfg(test)]
        drop(fixed_prepublication_scan_boundary);
        // Every raw/vacuum staging pin either dropped during SQLite
        // finalization or transferred its exact cleanup guard to
        // `published_cleanup`; no separate pathname artifact may race it.
        if !legacy_reseed_predecessor {
            remove_old_snapshot(
                previous,
                &file_name,
                previous_artifact.map(RetainedCurrentSnapshotArtifact::into_cleanup_artifact),
            )
            .await
            .map_err(|error| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Write,
                    error,
                )
            })?;
        }
        let snapshot = if self.core.authority_profile == ConsensusAuthorityProfile::FixedImmutable {
            // The descriptor was sealed, measured, scanned, and bound before
            // metadata publication. Return that exact descriptor: reopening
            // `final_path` here could substitute a byte-identical, unsealed
            // inode after the final authority check.
            #[cfg(test)]
            wait_before_fixed_snapshot_return(&final_path).await;
            let published_pin = published_pin.ok_or_else(|| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Read,
                    io::Error::other("fixed snapshot publication lost its pinned descriptor"),
                )
            })?;
            let mut snapshot = SessionSnapshotFile::from_pinned(published_pin, final_path.clone())
                .await
                .map_err(|error| {
                    storage_error(
                        ErrorSubject::Snapshot(Some(meta.signature())),
                        ErrorVerb::Read,
                        error,
                    )
                })?;
            // `PinnedSqliteFile` verifies through a cloned descriptor. Unix
            // descriptor clones share their file offset, so transfer remains
            // exact-handle but may arrive at EOF after the bounded scan.
            // Rewind the same sealed descriptor before OpenRaft consumes it.
            snapshot.rewind().await.map_err(|error| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Read,
                    error,
                )
            })?;
            snapshot
        } else {
            let file = open_snapshot_child_in_namespace(
                Arc::clone(&self._snapshot_directory_lease.namespace),
                std::ffi::OsString::from(&file_name),
            )
            .await
            .map_err(|error| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Read,
                    error,
                )
            })?;
            let mut snapshot = SessionSnapshotFile::from_std(file, final_path.clone())
                .await
                .map_err(|error| {
                    storage_error(
                        ErrorSubject::Snapshot(Some(meta.signature())),
                        ErrorVerb::Read,
                        error,
                    )
                })?;
            let (_, observed_checksum, observed_length) =
                verify_snapshot_envelope_reader(&mut snapshot)
                    .await
                    .map_err(|error| {
                        storage_error(
                            ErrorSubject::Snapshot(Some(meta.signature())),
                            ErrorVerb::Read,
                            error,
                        )
                    })?;
            if observed_checksum != checksum || observed_length != byte_length {
                return Err(storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Read,
                    consensus::invalid_data("session consensus sealed snapshot is inconsistent"),
                ));
            }
            snapshot.rewind().await.map_err(|error| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Read,
                    error,
                )
            })?;
            snapshot
        };
        self.core
            .snapshot_observation
            .record_published(captured_wal_bytes.unwrap_or(0), snapshot_started.elapsed());
        Ok(Snapshot {
            meta,
            snapshot: Box::new(snapshot),
        })
    }
}

async fn notify_watchers(core: &SqliteConsensusCore, notifications: &[ReplicationEntry]) {
    if notifications.is_empty() {
        return;
    }
    let mut watchers = core.watchers.lock().await;
    for notification in notifications {
        watchers.retain_mut(|watcher| watcher.notify(notification));
    }
}

fn secure_snapshot_create_file(path: &Path) -> io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    options.open(path)
}

#[cfg(any(target_os = "linux", test))]
fn open_snapshot_nofollow_read(path: &Path) -> io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        // A hostile special-file replacement must never make admission or
        // identity-bound cleanup wait for a writer.  Metadata validation will
        // reject it immediately after this nonblocking open.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    options.open(path)
}

#[cfg(test)]
fn create_unpublished_snapshot_output(
    path: &Path,
    read: bool,
) -> io::Result<(tokio::fs::File, UnpublishedSnapshotArtifact)> {
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).read(read).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let output = options.open(path)?;
    let cleanup = UnpublishedSnapshotArtifact::from_file(&output, path.to_path_buf(), false)?;
    Ok((tokio::fs::File::from_std(output), cleanup))
}

fn create_unpublished_snapshot_output_in_namespace(
    namespace: Arc<RetainedSnapshotDirectory>,
    name: &std::ffi::OsStr,
    read: bool,
) -> io::Result<(tokio::fs::File, UnpublishedSnapshotArtifact)> {
    let (output, cleanup) =
        create_unpublished_snapshot_file_in_namespace(namespace, name, read, false)?;
    Ok((tokio::fs::File::from_std(output), cleanup))
}

async fn seal_snapshot_database_in_place(
    raw_snapshot: PinnedSqliteFile,
    final_path: &Path,
    fixed_profile: bool,
    snapshot_integrity: SnapshotIntegrityPolicy,
    integrity_work: Option<SnapshotIntegrityWork>,
) -> io::Result<(
    SessionSnapshotFile,
    Option<PinnedSqliteFile>,
    [u8; 32],
    u64,
    UnpublishedSnapshotArtifact,
)> {
    raw_snapshot.verify_identity()?;
    let payload_length = raw_snapshot.file().metadata()?.len();
    if payload_length == 0 || payload_length > SNAPSHOT_MAX_BYTES {
        return Err(consensus::invalid_data(
            "session consensus snapshot size is invalid",
        ));
    }
    // Take the no-follow read pin before releasing the writer. In fixed mode
    // this is the only descriptor that is sealed and measured; a later path
    // reopen could otherwise select a byte-identical replacement inode.
    let fixed_pin = if fixed_profile {
        Some(raw_snapshot.pin_readonly_from_writer()?)
    } else {
        None
    };
    let (raw_file, output_cleanup) = raw_snapshot.into_file_with_cleanup();
    // This is the cleanup owner for the already-created, descriptor-pinned
    // compaction inode. It must remain armed through every async hash, footer,
    // sync, and later atomic rename; otherwise cancellation could retain an
    // unverified full snapshot payload.
    let output_cleanup = output_cleanup.ok_or_else(|| {
        consensus::invalid_data("session consensus snapshot publication cleanup is absent")
    })?;
    let mut output = tokio::fs::File::from_std(raw_file);
    #[cfg(test)]
    wait_after_in_place_seal_cleanup_is_armed().await;
    if output.metadata().await?.len() != payload_length {
        return Err(consensus::invalid_data(
            "session consensus snapshot changed before sealing",
        ));
    }
    output.seek(io::SeekFrom::Start(0)).await?;
    let mut hasher = Sha256::new();
    let mut copied = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let remaining = payload_length
            .checked_sub(copied)
            .ok_or_else(|| consensus::invalid_data("session consensus snapshot length overflow"))?;
        if remaining == 0 {
            break;
        }
        let bounded = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        let read = output.read(&mut buffer[..bounded]).await?;
        if read == 0 {
            return Err(consensus::invalid_data(
                "session consensus snapshot changed while sealing",
            ));
        }
        copied = copied
            .checked_add(u64::try_from(read).map_err(|_| {
                consensus::invalid_data("session consensus snapshot length overflow")
            })?)
            .ok_or_else(|| consensus::invalid_data("session consensus snapshot length overflow"))?;
        if copied > SNAPSHOT_MAX_BYTES {
            return Err(consensus::invalid_data(
                "session consensus snapshot exceeds size limit",
            ));
        }
        hasher.update(&buffer[..read]);
    }
    if copied != payload_length {
        return Err(consensus::invalid_data(
            "session consensus snapshot changed while sealing",
        ));
    }
    let checksum: [u8; 32] = hasher.finalize().into();
    if output.seek(io::SeekFrom::End(0)).await? != payload_length {
        return Err(consensus::invalid_data(
            "session consensus snapshot changed while sealing",
        ));
    }
    output.write_all(SNAPSHOT_FOOTER_MAGIC).await?;
    output.write_all(&payload_length.to_be_bytes()).await?;
    output.write_all(&checksum).await?;
    output.flush().await?;
    output.sync_all().await?;
    let (snapshot, fixed_pin) = if let Some(fixed_pin) = fixed_pin {
        drop(output);
        let fixed_pin =
            seal_snapshot_pin(fixed_pin, snapshot_integrity, None, integrity_work).await?;
        // Keep the original immutable pin for the caller's verification and
        // publication. The snapshot transport handle is only an exact-descriptor
        // clone used for the existing return contract.
        let snapshot =
            SessionSnapshotFile::from_pinned(fixed_pin.try_clone()?, final_path.to_path_buf())
                .await?;
        (snapshot, Some(fixed_pin))
    } else {
        (
            SessionSnapshotFile::from_file(output, final_path.to_path_buf()).await?,
            None,
        )
    };
    let total = payload_length
        .checked_add(SNAPSHOT_FOOTER_BYTES)
        .ok_or_else(|| consensus::invalid_data("session consensus snapshot length overflow"))?;
    Ok((snapshot, fixed_pin, checksum, total, output_cleanup))
}

async fn seal_snapshot_database_in_place_in_namespace(
    mut raw_snapshot: PinnedSqliteFile,
    namespace: Arc<RetainedSnapshotDirectory>,
    raw_name: &std::ffi::OsStr,
    final_name: &std::ffi::OsStr,
    fixed_profile: bool,
    snapshot_integrity: SnapshotIntegrityPolicy,
    integrity_work: SnapshotIntegrityWork,
) -> io::Result<(
    SessionSnapshotFile,
    Option<PinnedSqliteFile>,
    [u8; 32],
    u64,
    UnpublishedSnapshotArtifact,
)> {
    raw_snapshot.bind_cleanup_to_namespace(Arc::clone(&namespace), raw_name)?;
    let final_path = namespace.sqlite_child_path(final_name)?;
    seal_snapshot_database_in_place(
        raw_snapshot,
        &final_path,
        fixed_profile,
        snapshot_integrity,
        Some(integrity_work),
    )
    .await
}

#[cfg(test)]
async fn snapshot_handle_identity_pin(
    snapshot: &SessionSnapshotFile,
    path: &Path,
) -> io::Result<PinnedSqliteFile> {
    let cloned = snapshot.try_clone().await?;
    PinnedSqliteFile::from_file(cloned.into_std().await?, path.to_path_buf())
}

async fn verify_snapshot_envelope_reader(
    file: &mut SessionSnapshotFile,
) -> io::Result<(u64, [u8; 32], u64)> {
    let total_length = file.seek(io::SeekFrom::End(0)).await?;
    if total_length <= SNAPSHOT_FOOTER_BYTES || total_length > SNAPSHOT_ENVELOPE_MAX_BYTES {
        return Err(consensus::invalid_data(
            "session consensus snapshot size is invalid",
        ));
    }
    file.seek(io::SeekFrom::End(
        -i64::try_from(SNAPSHOT_FOOTER_BYTES).map_err(|_| {
            consensus::invalid_data("session consensus snapshot footer size is invalid")
        })?,
    ))
    .await?;
    let mut magic = [0_u8; 8];
    let mut encoded_length = [0_u8; 8];
    let mut expected_checksum = [0_u8; 32];
    file.read_exact(&mut magic).await?;
    file.read_exact(&mut encoded_length).await?;
    file.read_exact(&mut expected_checksum).await?;
    if &magic != SNAPSHOT_FOOTER_MAGIC {
        return Err(consensus::invalid_data(
            "session consensus snapshot magic is invalid",
        ));
    }
    let payload_length = u64::from_be_bytes(encoded_length);
    if payload_length == 0
        || payload_length > SNAPSHOT_MAX_BYTES
        || payload_length.checked_add(SNAPSHOT_FOOTER_BYTES) != Some(total_length)
    {
        return Err(consensus::invalid_data(
            "session consensus snapshot length is invalid",
        ));
    }
    file.seek(io::SeekFrom::Start(0)).await?;
    let mut limited = file.take(payload_length);
    let mut hasher = Sha256::new();
    let mut observed = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = limited.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        observed = observed
            .checked_add(u64::try_from(read).map_err(|_| {
                consensus::invalid_data("session consensus snapshot length overflow")
            })?)
            .ok_or_else(|| consensus::invalid_data("session consensus snapshot length overflow"))?;
        hasher.update(&buffer[..read]);
    }
    let actual_checksum: [u8; 32] = hasher.finalize().into();
    #[cfg(test)]
    super::snapshot::record_fixed_prepublication_scan(file.path(), observed);
    if observed != payload_length || actual_checksum != expected_checksum {
        return Err(consensus::invalid_data(
            "session consensus snapshot checksum mismatch",
        ));
    }
    Ok((payload_length, actual_checksum, total_length))
}

#[cfg(test)]
async fn extract_snapshot_database_from_reader<R>(
    source: &mut R,
    destination: &Path,
    length: u64,
    expected_checksum: [u8; 32],
) -> io::Result<PinnedSqliteFile>
where
    R: tokio::io::AsyncRead + tokio::io::AsyncSeek + Unpin,
{
    extract_snapshot_database_from_reader_inner(
        source,
        destination,
        length,
        expected_checksum,
        None,
    )
    .await
}

async fn extract_snapshot_database_from_reader_in_namespace<R>(
    source: &mut R,
    namespace: Arc<RetainedSnapshotDirectory>,
    name: &std::ffi::OsStr,
    length: u64,
    expected_checksum: [u8; 32],
) -> io::Result<PinnedSqliteFile>
where
    R: tokio::io::AsyncRead + tokio::io::AsyncSeek + Unpin,
{
    let destination = namespace.sqlite_child_path(name)?;
    extract_snapshot_database_from_reader_inner(
        source,
        &destination,
        length,
        expected_checksum,
        Some((namespace, name.to_os_string())),
    )
    .await
}

async fn extract_snapshot_database_from_reader_inner<R>(
    source: &mut R,
    destination: &Path,
    length: u64,
    expected_checksum: [u8; 32],
    namespace: Option<(Arc<RetainedSnapshotDirectory>, std::ffi::OsString)>,
) -> io::Result<PinnedSqliteFile>
where
    R: tokio::io::AsyncRead + tokio::io::AsyncSeek + Unpin,
{
    source.seek(io::SeekFrom::Start(0)).await?;
    let mut source = source.take(length);
    let destination_path = destination.to_path_buf();
    // `PinnedSqliteFile` owns the new descriptor before the first await, so a
    // cancelled extraction can clean only this exact artifact while later
    // verification retains descriptor identity.
    let mut raw_snapshot = match namespace {
        Some((namespace, name)) => PinnedSqliteFile::create_new_in_namespace(namespace, &name)?,
        None => PinnedSqliteFile::from_new_file(
            secure_snapshot_create_file(destination)?,
            destination_path,
        )?,
    };
    let mut destination = tokio::fs::File::from_std(raw_snapshot.file().try_clone()?);
    let mut copied = 0_u64;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = source.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        copied = copied
            .checked_add(u64::try_from(read).map_err(|_| {
                consensus::invalid_data("session consensus snapshot extraction length overflow")
            })?)
            .ok_or_else(|| {
                consensus::invalid_data("session consensus snapshot extraction length overflow")
            })?;
        if copied > length {
            return Err(consensus::invalid_data(
                "session consensus snapshot extraction exceeded its validated length",
            ));
        }
        hasher.update(&buffer[..read]);
        destination.write_all(&buffer[..read]).await?;
    }
    if copied != length {
        return Err(consensus::invalid_data(
            "session consensus snapshot extraction was incomplete",
        ));
    }
    let copied_checksum: [u8; 32] = hasher.finalize().into();
    if copied_checksum != expected_checksum {
        return Err(consensus::invalid_data(
            "session consensus snapshot extraction differs from its validated envelope",
        ));
    }
    destination.flush().await?;
    destination.sync_all().await?;
    drop(destination);
    raw_snapshot = raw_snapshot.refresh_identity()?;
    raw_snapshot.capture_created_sidecars();
    Ok(raw_snapshot)
}

#[cfg(test)]
#[allow(dead_code)]
async fn copy_and_promote_from_reader<R>(
    source: &mut R,
    temporary: &Path,
    final_path: &Path,
    expected_length: u64,
) -> io::Result<UnpublishedSnapshotArtifact>
where
    R: tokio::io::AsyncRead + tokio::io::AsyncSeek + Unpin,
{
    #[cfg(test)]
    {
        return copy_and_promote_from_reader_inner(
            source,
            temporary,
            final_path,
            expected_length,
            None,
        )
        .await;
    }
    #[cfg(not(test))]
    {
        copy_and_promote_from_reader_inner(source, temporary, final_path, expected_length).await
    }
}

/// Fixed-profile promotion keeps one read-only descriptor continuously from
/// before the staging writer is closed through rename, seal, validation, and
/// metadata installation.  The staged pathname is never reopened as
/// authority after its writer closes.
#[cfg(test)]
#[allow(dead_code)]
async fn copy_and_promote_from_reader_fixed<R>(
    source: &mut R,
    temporary: &Path,
    final_path: &Path,
    expected_length: u64,
) -> io::Result<(UnpublishedSnapshotArtifact, PinnedSqliteFile)>
where
    R: tokio::io::AsyncRead + tokio::io::AsyncSeek + Unpin,
{
    source.seek(io::SeekFrom::Start(0)).await?;
    let (mut output, mut cleanup) = create_unpublished_snapshot_output(temporary, true)?;
    // The cloned writer handle establishes the identity to which the
    // O_RDONLY|O_NOFOLLOW pin must bind before either writer descriptor is
    // closed. It carries no cleanup ownership.
    let writer = PinnedSqliteFile::from_file(
        output.try_clone().await?.into_std().await,
        temporary.to_path_buf(),
    )?;
    let mut pin = writer.pin_readonly_from_writer()?;
    let copied = tokio::io::copy(source, &mut output).await?;
    if copied != expected_length {
        return Err(consensus::invalid_data(
            "session consensus promoted snapshot length changed",
        ));
    }
    #[cfg(test)]
    wait_before_fixed_install_source_copy(final_path).await;
    output.flush().await?;
    output.sync_all().await?;
    drop(output);
    drop(writer);
    std::fs::rename(temporary, final_path)?;
    cleanup.rebind_path(final_path.to_path_buf());
    pin.rebind_path(final_path.to_path_buf());
    pin.seal_fixed()?;
    let parent = final_path
        .parent()
        .ok_or_else(|| consensus::invalid_data("session consensus snapshot has no parent"))?;
    sync_directory(parent)?;
    Ok((cleanup, pin))
}

async fn copy_and_promote_from_reader_fixed_in_namespace<R>(
    source: &mut R,
    namespace: Arc<RetainedSnapshotDirectory>,
    temporary_name: &std::ffi::OsStr,
    final_name: &std::ffi::OsStr,
    expected_length: u64,
    snapshot_integrity: SnapshotIntegrityPolicy,
    integrity_work: SnapshotIntegrityWork,
) -> io::Result<(UnpublishedSnapshotArtifact, PinnedSqliteFile)>
where
    R: tokio::io::AsyncRead + tokio::io::AsyncSeek + Unpin,
{
    source.seek(io::SeekFrom::Start(0)).await?;
    let (mut output, mut cleanup) = create_unpublished_snapshot_output_in_namespace(
        Arc::clone(&namespace),
        temporary_name,
        true,
    )?;
    let temporary_path = namespace.sqlite_child_path(temporary_name)?;
    #[cfg(test)]
    let final_path = namespace.sqlite_child_path(final_name)?;
    let mut writer =
        PinnedSqliteFile::from_file(output.try_clone().await?.into_std().await, temporary_path)?;
    writer.rebind_in_namespace(Arc::clone(&namespace), temporary_name)?;
    let mut pin = writer.pin_readonly_from_writer()?;
    let copied = tokio::io::copy(source, &mut output).await?;
    if copied != expected_length {
        return Err(consensus::invalid_data(
            "session consensus promoted snapshot length changed",
        ));
    }
    #[cfg(test)]
    wait_before_fixed_install_source_copy(&final_path).await;
    output.flush().await?;
    output.sync_all().await?;
    drop(output);
    drop(writer);
    namespace.rename_noreplace(temporary_name, final_name)?;
    cleanup.rebind_in_namespace(Arc::clone(&namespace), final_name)?;
    pin.rebind_in_namespace(Arc::clone(&namespace), final_name)?;
    let pin = seal_snapshot_pin(pin, snapshot_integrity, None, Some(integrity_work)).await?;
    namespace.sync()?;
    Ok((cleanup, pin))
}

#[cfg(test)]
async fn copy_and_promote_from_reader_inner<R>(
    source: &mut R,
    temporary: &Path,
    final_path: &Path,
    expected_length: u64,
    #[cfg(test)] after_rename: Option<&SnapshotArtifactGate>,
) -> io::Result<UnpublishedSnapshotArtifact>
where
    R: tokio::io::AsyncRead + tokio::io::AsyncSeek + Unpin,
{
    source.seek(io::SeekFrom::Start(0)).await?;
    let (mut output, mut cleanup) = create_unpublished_snapshot_output(temporary, false)?;
    let copied = tokio::io::copy(source, &mut output).await?;
    if copied != expected_length {
        return Err(consensus::invalid_data(
            "session consensus promoted snapshot length changed",
        ));
    }
    output.flush().await?;
    output.sync_all().await?;
    drop(output);
    std::fs::rename(temporary, final_path)?;
    cleanup.rebind_path(final_path.to_path_buf());
    #[cfg(test)]
    if let Some(after_rename) = after_rename {
        after_rename.block_if_armed().await;
    }
    let parent = final_path
        .parent()
        .ok_or_else(|| consensus::invalid_data("session consensus snapshot has no parent"))?;
    sync_directory(parent)?;
    Ok(cleanup)
}

async fn copy_and_promote_from_reader_in_namespace<R>(
    source: &mut R,
    namespace: Arc<RetainedSnapshotDirectory>,
    temporary_name: &std::ffi::OsStr,
    final_name: &std::ffi::OsStr,
    expected_length: u64,
) -> io::Result<UnpublishedSnapshotArtifact>
where
    R: tokio::io::AsyncRead + tokio::io::AsyncSeek + Unpin,
{
    source.seek(io::SeekFrom::Start(0)).await?;
    let (mut output, mut cleanup) = create_unpublished_snapshot_output_in_namespace(
        Arc::clone(&namespace),
        temporary_name,
        false,
    )?;
    let copied = tokio::io::copy(source, &mut output).await?;
    if copied != expected_length {
        return Err(consensus::invalid_data(
            "session consensus promoted snapshot length changed",
        ));
    }
    output.flush().await?;
    output.sync_all().await?;
    drop(output);
    namespace.rename_noreplace(temporary_name, final_name)?;
    cleanup.rebind_in_namespace(Arc::clone(&namespace), final_name)?;
    namespace.sync()?;
    Ok(cleanup)
}

fn sync_directory(path: &Path) -> io::Result<()> {
    std::fs::File::open(path)?.sync_all()
}

/// Open one validated snapshot basename through the retained namespace on the
/// blocking pool.  The descriptor uses `O_NOFOLLOW | O_NONBLOCK`; callers
/// attach their logical or SQLite-only diagnostic spelling afterwards.
async fn open_snapshot_child_in_namespace(
    namespace: Arc<RetainedSnapshotDirectory>,
    name: std::ffi::OsString,
) -> io::Result<std::fs::File> {
    tokio::task::spawn_blocking(move || namespace.open_read(&name))
        .await
        .map_err(|_| io::Error::other("snapshot namespace open worker failed"))?
}

async fn remove_old_snapshot(
    previous: Option<consensus::CurrentSnapshot>,
    current_file_name: &str,
    previous_artifact: Option<SnapshotArtifact>,
) -> io::Result<()> {
    if let Some((_, file_name, _, _)) = previous {
        if file_name != current_file_name {
            let artifact = previous_artifact.ok_or_else(|| {
                io::Error::other("session consensus previous snapshot has no identity pin")
            })?;
            if artifact.path().file_name() != Some(std::ffi::OsStr::new(&file_name)) {
                return Err(io::Error::other(
                    "session consensus previous snapshot identity pin has wrong path",
                ));
            }
            #[cfg(test)]
            if take_snapshot_publication_cleanup_process_loss(
                artifact.path(),
                SnapshotPublicationCleanupCrashPoint::AfterMetadataBeforeOldRename,
            ) {
                artifact.abandon_for_simulated_process_loss();
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "injected snapshot publication process loss",
                ));
            }
            artifact.remove().await?;
        }
    }
    Ok(())
}

async fn track_previous_snapshot_artifact(
    previous: &Option<consensus::CurrentSnapshot>,
    cleanup_failed: Arc<AtomicBool>,
    authority_profile: ConsensusAuthorityProfile,
    snapshot_integrity: SnapshotIntegrityPolicy,
    namespace_lease: Arc<SnapshotDirectoryLease>,
) -> io::Result<Option<RetainedCurrentSnapshotArtifact>> {
    let Some((_, file_name, expected_checksum, expected_length)) = previous.as_ref() else {
        return Ok(None);
    };
    let path = namespace_lease
        .namespace
        .sqlite_child_path(std::ffi::OsStr::new(file_name))?;
    // The cleanup pin is derived from the descriptor that authenticated the
    // row, never a later pathname reopen.  A replacement after this point
    // fails the identity-bound unlink and is preserved rather than adopted.
    let file = if authority_profile == ConsensusAuthorityProfile::FixedImmutable {
        let file = open_snapshot_child_in_namespace(
            Arc::clone(&namespace_lease.namespace),
            std::ffi::OsString::from(file_name),
        )
        .await?;
        let pinned = verify_admitted_snapshot(
            file,
            Arc::clone(&namespace_lease),
            std::ffi::OsString::from(file_name),
            snapshot_integrity,
            *expected_checksum,
            *expected_length,
        )
        .await?;
        pinned.into_file()
    } else {
        let file = open_snapshot_child_in_namespace(
            Arc::clone(&namespace_lease.namespace),
            std::ffi::OsString::from(file_name),
        )
        .await?;
        let mut snapshot = SessionSnapshotFile::from_std(file, path.clone()).await?;
        let (_, checksum, length) = verify_snapshot_envelope_reader(&mut snapshot).await?;
        if checksum != *expected_checksum || length != *expected_length {
            return Err(consensus::invalid_data(
                "previous snapshot differs from durable row",
            ));
        }
        snapshot.into_std().await?
    };
    let artifact = SnapshotArtifact::new_in_namespace(
        Arc::clone(&namespace_lease.namespace),
        std::ffi::OsStr::new(file_name),
        cleanup_failed,
    )?;
    artifact.record_identity_from_file(&file)?;
    artifact.retain_namespace_lease(namespace_lease)?;
    // `record_identity_from_file` owns an exact duplicate, retaining it
    // through successor metadata publication and identity-bound cleanup.
    Ok(Some(RetainedCurrentSnapshotArtifact::new(artifact)))
}

/// Publish one already-durable snapshot file without deleting it after an
/// ambiguous SQLite commit result.
///
/// SQLite may durably commit a transaction and then report an I/O/finalization
/// error. The same locked connection therefore reads the singleton back before
/// an armed error-path guard is allowed to unlink the candidate. An exact
/// candidate or an unavailable readback is preserved. Every indeterminate
/// readback branch disarms this attempt's cleanup guard because the candidate
/// remains needed for reopen resolution; it latches the core instead of
/// returning an ordinary replayable publication error. An exact durable
/// readback is a committed success, even when SQLite reported an error after
/// committing.
#[allow(clippy::too_many_arguments)]
fn publish_snapshot_metadata_with_readback<F>(
    conn: &rusqlite::Connection,
    identity: SessionConsensusIdentity,
    meta: &SnapshotMeta<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>,
    file_name: &str,
    checksum: [u8; 32],
    byte_length: u64,
    cleanup: &mut UnpublishedSnapshotArtifact,
    indeterminate: &AtomicBool,
    publish: F,
) -> io::Result<()>
where
    F: FnOnce() -> io::Result<consensus::SnapshotInstallPublicationOutcome>,
{
    match publish() {
        Ok(consensus::SnapshotInstallPublicationOutcome::Clean) => {
            cleanup.disarm();
            Ok(())
        }
        Ok(consensus::SnapshotInstallPublicationOutcome::CommittedDetachPending) => {
            // The replacement transaction is known committed, but its two
            // in-transaction cleanup attempts left the incoming schema
            // attached. First prove the exact singleton, then require one
            // successful detach before this live connection is declared
            // reusable. A persistent cleanup failure is an explicit reopen
            // requirement, never a replayable ordinary publish error.
            match consensus::read_current_snapshot_sync(conn, identity) {
                Ok(Some((
                    observed_meta,
                    observed_file_name,
                    observed_checksum,
                    observed_length,
                ))) if observed_meta == *meta
                    && observed_file_name == file_name
                    && observed_checksum == checksum
                    && observed_length == byte_length =>
                {
                    match consensus::detach_attached_snapshot_database_sync(conn) {
                        Ok(()) => {
                            cleanup.disarm();
                            Ok(())
                        }
                        Err(detach_error) => {
                            cleanup.disarm();
                            indeterminate.store(true, Ordering::Release);
                            Err(io::Error::other(format!(
                                "session consensus snapshot metadata publication committed exactly but incoming cleanup is unresolved; reopen required (detach: {detach_error})"
                            )))
                        }
                    }
                }
                Ok(Some(_)) => {
                    cleanup.disarm();
                    indeterminate.store(true, Ordering::Release);
                    Err(io::Error::other(
                        "session consensus snapshot metadata publication is indeterminate; reopen required (post-commit cleanup: different durable metadata)",
                    ))
                }
                Ok(None) => {
                    cleanup.disarm();
                    indeterminate.store(true, Ordering::Release);
                    Err(io::Error::other(
                        "session consensus snapshot metadata publication is indeterminate; reopen required (post-commit cleanup: metadata absent)",
                    ))
                }
                Err(readback_error) => {
                    cleanup.disarm();
                    indeterminate.store(true, Ordering::Release);
                    Err(io::Error::other(format!(
                        "session consensus snapshot metadata publication is indeterminate; reopen required (post-commit cleanup readback: {readback_error})"
                    )))
                }
            }
        }
        Err(error) => {
            match consensus::read_current_snapshot_sync(conn, identity) {
                Ok(Some((
                    observed_meta,
                    observed_file_name,
                    observed_checksum,
                    observed_length,
                ))) => {
                    let exact = observed_meta == *meta
                        && observed_file_name == file_name
                        && observed_checksum == checksum
                        && observed_length == byte_length;
                    if exact {
                        // A generic SQLite error can still originate after an
                        // attached snapshot-install transaction committed.
                        // Exact metadata proves the commit, not that this
                        // live connection is reusable: leave no attached
                        // alias behind before returning the normal success
                        // path. Ordinary save-current callers have no alias
                        // and keep the exact-readback success behavior.
                        match consensus::attached_snapshot_database_is_attached_sync(conn) {
                            Ok(false) => {
                                cleanup.disarm();
                                return Ok(());
                            }
                            Ok(true) => {
                                match consensus::detach_attached_snapshot_database_sync(conn) {
                                    Ok(()) => {
                                        cleanup.disarm();
                                        return Ok(());
                                    }
                                    Err(detach_error) => {
                                        cleanup.disarm();
                                        indeterminate.store(true, Ordering::Release);
                                        return Err(io::Error::other(format!(
                                        "session consensus snapshot metadata publication committed exactly but incoming cleanup is unresolved; reopen required (publish: {error}; detach: {detach_error})"
                                    )));
                                    }
                                }
                            }
                            Err(alias_error) => {
                                cleanup.disarm();
                                indeterminate.store(true, Ordering::Release);
                                return Err(io::Error::other(format!(
                                    "session consensus snapshot metadata publication committed exactly but incoming cleanup is indeterminate; reopen required (publish: {error}; attachment check: {alias_error})"
                                )));
                            }
                        }
                    }
                    cleanup.disarm();
                    indeterminate.store(true, Ordering::Release);
                    Err(io::Error::other(format!(
                        "session consensus snapshot metadata publication is indeterminate; reopen required (publish: {error}; readback: different durable metadata)"
                    )))
                }
                Ok(None) => {
                    cleanup.disarm();
                    indeterminate.store(true, Ordering::Release);
                    Err(io::Error::other(format!(
                        "session consensus snapshot metadata publication is indeterminate; reopen required (publish: {error}; readback: metadata absent)"
                    )))
                }
                Err(readback_error) => {
                    // Do not unlink a candidate whose commit status cannot
                    // be resolved.  This error is deliberately distinct
                    // from a retryable publish failure: the caller must
                    // reopen/recover the durable singleton before deciding
                    // whether publication may be attempted again.
                    cleanup.disarm();
                    indeterminate.store(true, Ordering::Release);
                    Err(io::Error::other(format!(
                        "session consensus snapshot metadata publication is indeterminate; reopen required (publish: {error}; readback: {readback_error})"
                    )))
                }
            }
        }
    }
}

fn reject_indeterminate_snapshot_publication(core: &SqliteConsensusCore) -> io::Result<()> {
    if core
        .snapshot_publication_indeterminate
        .load(Ordering::Acquire)
    {
        return Err(io::Error::other(
            "session consensus snapshot metadata publication is indeterminate; reopen required",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::Duration;

    use bytes::Bytes;
    use opc_consensus::engine::network::RaftNetworkFactory;
    use opc_consensus::engine::storage::RaftLogStorageExt;
    use opc_consensus::engine::storage::{RaftLogStorage, RaftStateMachine};
    use opc_consensus::engine::{CommittedLeaderId, EmptyNode, EntryPayload, RaftSnapshotBuilder};
    use opc_crypto::CryptoEnvelopeV1;
    use opc_key::{
        serialize_bound_aad, AeadAlgorithm, EnvelopeAad, KeyId, SessionAad, AEAD_TAG_LEN,
        AES_256_GCM_SIV_NONCE_LEN,
    };
    use opc_types::{NetworkFunctionKind, TenantId, Timestamp};
    use sha2::Sha256;
    use tokio::io::{AsyncSeekExt, AsyncWriteExt};

    use super::super::raft_adapter::SessionRaftNetworkFactory;
    #[cfg(target_os = "linux")]
    use super::super::snapshot::{
        clear_retained_namespace_sync_observer_for_test, retained_namespace_sync_observer_for_test,
    };
    use super::super::snapshot::{
        fail_namespace_pinned_post_create_setup_for_test,
        fail_namespace_receiver_post_create_setup_for_test,
        fail_namespace_receiver_post_create_sync_for_test,
        fail_namespace_vacuum_raw_pinned_post_create_setup_for_test,
        fail_retained_namespace_sync_for_test, fail_snapshot_cleanup_post_rename_sync_for_test,
        latch_unpublished_snapshot_cleanup_failure_for_test, snapshot_cleanup_test_lock,
        FixedPrepublicationScanObserver,
    };
    use super::*;
    use crate::backend::CompareAndSet;
    use crate::consensus::{
        store::ConsensusStoreDiagnosticCounters, SessionConsensusClusterId,
        SessionConsensusCommand, SessionConsensusConfigurationEpoch,
        SessionConsensusConfigurationId, SessionConsensusEntryDigest, SessionConsensusPeer,
        SessionConsensusPeerError, SessionConsensusRequestId, SessionConsensusWireRequest,
        SessionConsensusWireResponse, SessionMutationIntent, SessionMutationOutcome,
        SESSION_CONSENSUS_SCHEMA_VERSION,
    };
    use crate::lease::SessionLeaseManager;
    use crate::model::{Generation, OwnerId, SessionKey, SessionKeyType, StateClass, StateType};
    use crate::record::{EncryptedSessionPayload, StoredSessionRecord};

    const PLAINTEXT_CANARY: &[u8] = b"never-persist-this-plaintext-canary";

    #[derive(Debug)]
    struct MembershipObservationProbePeer {
        node_id: SessionConsensusNodeId,
    }

    #[async_trait::async_trait]
    impl SessionConsensusPeer for MembershipObservationProbePeer {
        fn node_id(&self) -> SessionConsensusNodeId {
            self.node_id
        }

        async fn call(
            &self,
            _request: SessionConsensusWireRequest,
        ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
            Err(SessionConsensusPeerError::Protocol)
        }
    }
    fn snapshot_artifact_cleanup_test_lock() -> &'static tokio::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    async fn assert_published_predecessor_restart_recovery(
        backend: &SqliteSessionBackend,
        snapshot_directory: &Path,
        predecessor_name: &str,
        current_name: &str,
        foreign: &Path,
        malformed: &Path,
    ) {
        for attempt in 0..2 {
            let (log_store, mut state_machine) = open(
                backend,
                snapshot_directory.to_path_buf(),
                identity(1),
                expected_members(),
            )
            .await
            .expect("restart keeps the successor snapshot valid");
            let current = state_machine
                .get_current_snapshot()
                .await
                .expect("read recovered successor")
                .expect("successor remains current");
            assert_eq!(
                current.snapshot.path().file_name(),
                Some(std::ffi::OsStr::new(current_name)),
                "restart {attempt} never reclaims the exact current metadata file"
            );
            drop(current);
            drop(log_store);
            drop(state_machine);

            assert!(
                !std::fs::read_dir(snapshot_directory)
                    .expect("read recovered snapshot namespace")
                    .filter_map(Result::ok)
                    .any(|entry| entry
                        .file_name()
                        .to_string_lossy()
                        .contains(predecessor_name)),
                "restart {attempt} reclaims exactly the superseded published artifact"
            );
            assert!(
                snapshot_directory.join(current_name).is_file(),
                "restart {attempt} preserves the successor's current file"
            );
            assert_eq!(
                std::fs::read(foreign).expect("foreign survivor"),
                b"foreign-published-lookalike",
                "restart {attempt} preserves unrelated files"
            );
            assert_eq!(
                std::fs::read(malformed).expect("malformed survivor"),
                b"malformed-published-lookalike",
                "restart {attempt} preserves malformed lookalikes"
            );
        }
    }

    fn assert_expected_published_process_loss_residue(
        snapshot_directory: &Path,
        predecessor_name: &str,
        point: SnapshotPublicationCleanupCrashPoint,
    ) {
        let names = std::fs::read_dir(snapshot_directory)
            .expect("read process-loss snapshot namespace")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        match point {
            SnapshotPublicationCleanupCrashPoint::AfterMetadataBeforeOldRename => assert!(
                names.iter().any(|name| name == predecessor_name),
                "metadata commit precedes predecessor rename"
            ),
            SnapshotPublicationCleanupCrashPoint::AfterOldTombstoneSync => assert!(
                names.iter().any(|name| {
                    name.starts_with(&format!(".{predecessor_name}.opc-cleanup-"))
                        && !name.contains(".opc-unlink-guard-")
                }),
                "tombstone is durable before the simulated stop"
            ),
            SnapshotPublicationCleanupCrashPoint::AfterOldUnlinkGuardSync => assert!(
                names.iter().any(|name| {
                    name.starts_with(&format!(".{predecessor_name}.opc-cleanup-"))
                        && name.contains(".opc-unlink-guard-")
                }),
                "identity-authenticated final guard is durable before the simulated stop"
            ),
        }
    }

    #[cfg(target_os = "linux")]
    async fn pending_terminal_backend_fixture() -> (tempfile::TempDir, SqliteSessionBackend, PathBuf)
    {
        let directory = tempfile::tempdir().expect("terminal handoff directory");
        let database = directory.path().join("sessions.sqlite");
        let snapshots = directory.path().join("snapshots");
        let initial_backend = SqliteSessionBackend::open(&database).expect("initial backend");
        let (initial_log, initial_state) = open(
            &initial_backend,
            snapshots.clone(),
            identity(1),
            expected_members(),
        )
        .await
        .expect("initialize terminal handoff database");
        {
            let conn = initial_state.core.conn.lock().await;
            conn.execute(
                "UPDATE consensus_operator_recovery SET recovery_epoch = 1, last_plan_digest = ?1, pending_epoch = NULL, pending_plan_digest = NULL WHERE singleton = 1",
                rusqlite::params![[0xA5_u8; 32].as_slice()],
            )
            .expect("advance terminal recovery fixture state");
        }
        drop(initial_log);
        drop(initial_state);
        drop(initial_backend);

        let latch = consensus::OperatorRecoveryLatch {
            identity: identity(1),
            recovery_epoch: 1,
            plan_digest: [0xA5; 32],
            audit_pending: false,
        };
        let database_file = std::fs::File::open(&database).expect("open terminal database");
        consensus::ensure_operator_recovery_latch_sync(&database, latch)
            .expect("write active terminal latch");
        consensus::terminalize_operator_recovery_latch_sync(&database, latch, &database_file, None)
            .expect("write pending terminal handoff");
        drop(database_file);

        (
            directory,
            SqliteSessionBackend::open(&database).expect("classify terminal handoff"),
            snapshots,
        )
    }

    #[test]
    fn snapshot_recovery_provenance_accepts_only_canonical_production_names() {
        let published = "snapshot-00000000-0000-4000-8000-000000000007.opc";
        for file_name in [
            "incoming-00000000-0000-4000-8000-000000000001.part",
            "promote-00000000-0000-4000-8000-000000000002.part",
            "install-00000000-0000-4000-8000-000000000003.sqlite-wal",
            "build-00000000-0000-4000-8000-000000000004.sqlite",
            "vacuum-00000000-0000-4000-8000-000000000005.sqlite-shm",
            "vacuum-raw-4242-7.sqlite",
            "vacuum-raw-4242-7.sqlite-journal",
            "vacuum-raw-4242-7.sqlite-wal",
            "vacuum-raw-4242-7.sqlite-shm",
            ".incoming-00000000-0000-4000-8000-000000000001.part.opc-cleanup-00000000-0000-4000-8000-000000000008",
            ".incoming-00000000-0000-4000-8000-000000000001.part.opc-cleanup-00000000-0000-4000-8000-000000000008.opc-unlink-guard-0000000000000001-0000000000000002",
        ] {
            assert!(is_sdk_snapshot_staging_name(file_name), "{file_name}");
        }
        assert!(
            sdk_snapshot_restart_cleanup_original_name(published).is_some(),
            "a noncurrent canonical published original is a restart candidate"
        );
        assert!(
            sdk_snapshot_restart_cleanup_original_name(&format!(
                ".{published}.opc-cleanup-00000000-0000-4000-8000-000000000008"
            ))
            .is_some(),
            "a canonical published tombstone retains its original identity"
        );
        assert!(
            sdk_snapshot_restart_cleanup_original_name(&format!(
                ".{published}.opc-cleanup-00000000-0000-4000-8000-000000000008.opc-unlink-guard-0000000000000001-0000000000000002"
            ))
            .is_some(),
            "a canonical published final guard retains its original identity"
        );
        for file_name in [
            "incoming-anything.part",
            "incoming-00000000-0000-1000-8000-000000000001.part",
            "install-00000000-0000-4000-8000-000000000003.sqlite.bak",
            "vacuum-raw-4242-not-a-sequence.sqlite",
            "vacuum-raw-04242-7.sqlite",
            "vacuum-raw-4242-007.sqlite",
            "vacuum-raw-+4242-7.sqlite",
            "vacuum-raw-0-7.sqlite",
            // Version four alone is not enough: RFC 4122's variant bits are
            // part of the production namespace grammar.
            "incoming-00000000-0000-4000-c000-000000000001.part",
            "incoming-00000000-0000-4000-e000-000000000001.part",
            "seal-00000000-0000-4000-8000-000000000006.part",
            published,
            ".foreign.opc-cleanup-00000000-0000-4000-8000-000000000008",
            ".incoming-00000000-0000-4000-8000-000000000001.part.opc-cleanup-00000000-0000-4000-8000-000000000008.opc-unlink-guard-0000000000000001-000000000000000G",
            ".incoming-00000000-0000-4000-8000-000000000001.part.opc-cleanup-00000000-0000-4000-8000-000000000008.opc-unlink-guard-0000000000000001-0000000000000002-extra",
        ] {
            assert!(
                !is_sdk_snapshot_staging_name(file_name),
                "unproven candidate must remain a capacity-consuming survivor: {file_name}"
            );
        }
        for file_name in [
            "snapshot-00000000-0000-1000-8000-000000000007.opc",
            ".snapshot-00000000-0000-1000-8000-000000000007.opc-cleanup-00000000-0000-4000-8000-000000000008",
            ".snapshot-00000000-0000-4000-8000-000000000007.opc-cleanup-00000000-0000-4000-8000-000000000008.opc-unlink-guard-0000000000000001-000000000000000G",
        ] {
            assert!(
                sdk_snapshot_restart_cleanup_original_name(file_name).is_none(),
                "malformed published lookalike remains foreign: {file_name}"
            );
        }
    }

    #[tokio::test]
    async fn real_build_publication_process_loss_matrix_reclaims_superseded_published_snapshot() {
        let _hook_lock = snapshot_artifact_cleanup_test_lock().lock().await;
        for (index, point) in [
            SnapshotPublicationCleanupCrashPoint::AfterMetadataBeforeOldRename,
            SnapshotPublicationCleanupCrashPoint::AfterOldTombstoneSync,
            SnapshotPublicationCleanupCrashPoint::AfterOldUnlinkGuardSync,
        ]
        .into_iter()
        .enumerate()
        {
            let directory = tempfile::tempdir().expect("build publication crash directory");
            let snapshot_directory = directory.path().join("snapshots");
            let backend = SqliteSessionBackend::open(directory.path().join("sessions.sqlite"))
                .expect("build publication crash backend");
            let (mut log_store, mut state_machine) = open(
                &backend,
                snapshot_directory.clone(),
                identity(1),
                expected_members(),
            )
            .await
            .expect("create build publication storage");
            append_commit_and_apply(
                &mut log_store,
                &mut state_machine,
                [initial_membership_entry()],
                "seed first published snapshot",
            )
            .await;
            let first = state_machine
                .get_snapshot_builder()
                .await
                .build_snapshot()
                .await
                .expect("build predecessor snapshot");
            let predecessor_name = first
                .snapshot
                .path()
                .file_name()
                .expect("predecessor basename")
                .to_string_lossy()
                .into_owned();
            let predecessor_path = first.snapshot.path().to_path_buf();
            drop(first);
            append_commit_and_apply(
                &mut log_store,
                &mut state_machine,
                [normal_entry(
                    1,
                    acquire_command(
                        identity(1),
                        SessionConsensusRequestId::from_bytes([(index + 1) as u8; 16]),
                    ),
                )],
                "advance successor snapshot state",
            )
            .await;

            snapshot_artifact_cleanup_test_hooks()
                .lock()
                .expect("install build process-loss seam")
                .entry(predecessor_path)
                .or_default()
                .publication_process_loss = Some(point);
            assert!(
                state_machine
                    .get_snapshot_builder()
                    .await
                    .build_snapshot()
                    .await
                    .is_err(),
                "the simulated process stop interrupts predecessor cleanup"
            );
            let current_name = {
                let conn = state_machine.core.conn.lock().await;
                consensus::read_current_snapshot_sync(&conn, identity(1))
                    .expect("read committed successor metadata")
                    .expect("successor metadata exists")
                    .1
            };
            assert_ne!(predecessor_name, current_name);
            assert_expected_published_process_loss_residue(
                &snapshot_directory,
                &predecessor_name,
                point,
            );
            let foreign = snapshot_directory.join("foreign-published-survivor");
            let malformed =
                snapshot_directory.join("snapshot-00000000-0000-1000-8000-000000000007.opc");
            std::fs::write(&foreign, b"foreign-published-lookalike")
                .expect("write unrelated survivor");
            std::fs::write(&malformed, b"malformed-published-lookalike")
                .expect("write malformed published lookalike");
            sync_directory(&snapshot_directory).expect("sync process-loss namespace fixtures");
            drop(log_store);
            drop(state_machine);

            assert_published_predecessor_restart_recovery(
                &backend,
                &snapshot_directory,
                &predecessor_name,
                &current_name,
                &foreign,
                &malformed,
            )
            .await;
        }
    }

    #[tokio::test]
    async fn real_install_publication_process_loss_matrix_reclaims_superseded_published_snapshot() {
        let _hook_lock = snapshot_artifact_cleanup_test_lock().lock().await;
        for (index, point) in [
            SnapshotPublicationCleanupCrashPoint::AfterMetadataBeforeOldRename,
            SnapshotPublicationCleanupCrashPoint::AfterOldTombstoneSync,
            SnapshotPublicationCleanupCrashPoint::AfterOldUnlinkGuardSync,
        ]
        .into_iter()
        .enumerate()
        {
            let source_directory =
                tempfile::tempdir().expect("install publication source directory");
            let source_backend =
                SqliteSessionBackend::open(source_directory.path().join("sessions.sqlite"))
                    .expect("install publication source backend");
            let (mut source_log, mut source) = open(
                &source_backend,
                source_directory.path().join("snapshots"),
                identity(1),
                expected_members(),
            )
            .await
            .expect("create install publication source");
            let source_predecessor_entries = [
                initial_membership_entry(),
                normal_entry(
                    1,
                    acquire_command(
                        identity(1),
                        SessionConsensusRequestId::from_bytes([0x41 + index as u8; 16]),
                    ),
                ),
            ];
            append_commit_and_apply(
                &mut source_log,
                &mut source,
                source_predecessor_entries.clone(),
                "seed install source predecessor",
            )
            .await;
            let mut source_predecessor = source
                .get_snapshot_builder()
                .await
                .build_snapshot()
                .await
                .expect("build install source predecessor");
            let source_successor_entry = normal_entry(
                2,
                acquire_command(
                    identity(1),
                    SessionConsensusRequestId::from_bytes([0x51 + index as u8; 16]),
                ),
            );
            append_commit_and_apply(
                &mut source_log,
                &mut source,
                [source_successor_entry.clone()],
                "advance install source successor",
            )
            .await;
            let mut source_successor = source
                .get_snapshot_builder()
                .await
                .build_snapshot()
                .await
                .expect("build install source successor");

            let target_directory =
                tempfile::tempdir().expect("install publication target directory");
            let snapshot_directory = target_directory.path().join("snapshots");
            let target_backend =
                SqliteSessionBackend::open(target_directory.path().join("sessions.sqlite"))
                    .expect("install publication target backend");
            let (mut target_log, mut target) = open(
                &target_backend,
                snapshot_directory.clone(),
                identity(1),
                expected_members(),
            )
            .await
            .expect("create install publication target");
            append_and_commit(
                &mut target_log,
                source_predecessor_entries,
                "replicate install source predecessor",
            )
            .await;

            let mut receiving = target
                .begin_receiving_snapshot()
                .await
                .expect("receive predecessor snapshot");
            source_predecessor
                .snapshot
                .rewind()
                .await
                .expect("rewind predecessor source snapshot");
            tokio::io::copy(&mut source_predecessor.snapshot, &mut receiving)
                .await
                .expect("copy predecessor source snapshot");
            target
                .install_snapshot(&source_predecessor.meta, receiving)
                .await
                .expect("install predecessor snapshot");
            let predecessor_name = {
                let conn = target.core.conn.lock().await;
                consensus::read_current_snapshot_sync(&conn, identity(1))
                    .expect("read installed predecessor metadata")
                    .expect("installed predecessor metadata exists")
                    .1
            };
            let predecessor_path = target
                ._snapshot_directory_lease
                .namespace
                .sqlite_child_path(std::ffi::OsStr::new(&predecessor_name))
                .expect("predecessor artifact path");
            append_and_commit(
                &mut target_log,
                [source_successor_entry],
                "replicate install source successor",
            )
            .await;

            let mut receiving = target
                .begin_receiving_snapshot()
                .await
                .expect("receive successor snapshot");
            source_successor
                .snapshot
                .rewind()
                .await
                .expect("rewind successor source snapshot");
            tokio::io::copy(&mut source_successor.snapshot, &mut receiving)
                .await
                .expect("copy successor source snapshot");
            snapshot_artifact_cleanup_test_hooks()
                .lock()
                .expect("install install process-loss seam")
                .entry(predecessor_path)
                .or_default()
                .publication_process_loss = Some(point);
            assert!(
                target
                    .install_snapshot(&source_successor.meta, receiving)
                    .await
                    .is_err(),
                "the simulated process stop interrupts installed predecessor cleanup"
            );
            let current_name = {
                let conn = target.core.conn.lock().await;
                consensus::read_current_snapshot_sync(&conn, identity(1))
                    .expect("read committed installed successor metadata")
                    .expect("installed successor metadata exists")
                    .1
            };
            assert_ne!(predecessor_name, current_name);
            assert_expected_published_process_loss_residue(
                &snapshot_directory,
                &predecessor_name,
                point,
            );
            let foreign = snapshot_directory.join("foreign-published-survivor");
            let malformed =
                snapshot_directory.join("snapshot-00000000-0000-1000-8000-000000000007.opc");
            std::fs::write(&foreign, b"foreign-published-lookalike")
                .expect("write unrelated survivor");
            std::fs::write(&malformed, b"malformed-published-lookalike")
                .expect("write malformed published lookalike");
            sync_directory(&snapshot_directory)
                .expect("sync installed process-loss namespace fixtures");
            drop(target_log);
            drop(target);

            assert_published_predecessor_restart_recovery(
                &target_backend,
                &snapshot_directory,
                &predecessor_name,
                &current_name,
                &foreign,
                &malformed,
            )
            .await;
        }
    }

    #[tokio::test]
    async fn restart_cleanup_retries_the_exact_canonical_tombstone_without_nesting() {
        let _hook_lock = snapshot_cleanup_test_lock().lock().await;
        let directory = tempfile::tempdir().expect("tombstone restart directory");
        let database = directory.path().join("sessions.sqlite");
        let snapshots = directory.path().join("snapshots");
        let backend = SqliteSessionBackend::open(&database).expect("tombstone restart backend");
        let (log, state) = open(&backend, snapshots.clone(), identity(1), expected_members())
            .await
            .expect("initialize tombstone restart storage");
        drop(log);
        drop(state);

        let original = format!("incoming-{}.part", uuid::Uuid::new_v4().hyphenated());
        let tombstone_name = format!(
            ".{original}.opc-cleanup-{}",
            uuid::Uuid::new_v4().hyphenated()
        );
        let tombstone = snapshots.join(&tombstone_name);
        std::fs::write(&tombstone, b"crash-after-rename")
            .expect("write canonical retained tombstone");
        sync_directory(&snapshots).expect("sync retained tombstone");
        fail_snapshot_cleanup_post_rename_sync_for_test(&snapshots.join(&original));

        assert!(matches!(
            open(&backend, snapshots.clone(), identity(1), expected_members()).await,
            Err(SessionConsensusStorageError::BackendUnavailable)
        ));
        let names = std::fs::read_dir(&snapshots)
            .expect("read retained tombstone")
            .map(|entry| {
                entry
                    .expect("directory entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        assert_eq!(names, vec![tombstone_name]);
        assert!(
            names[0].matches(".opc-cleanup-").count() == 1,
            "retry never constructs a nested cleanup tombstone"
        );

        #[cfg(target_os = "linux")]
        let migrated_snapshots = directory.path().join("migrated-snapshots");
        // The same durable database cannot use a queued D1 cleanup failure
        // as an excuse to migrate to a fresh D2. Only the same configured
        // key may recover a replacement directory; another namespace fails
        // closed until the original owner drains its retained tombstone.
        #[cfg(target_os = "linux")]
        assert!(matches!(
            open(
                &backend,
                migrated_snapshots.clone(),
                identity(1),
                expected_members(),
            )
            .await,
            Err(SessionConsensusStorageError::BackendUnavailable)
        ));
        assert!(tombstone.exists(), "migration never bypasses D1 cleanup");

        // The queued D1 flock is reentrant only for the durable SQLite
        // backend that issued the cleanup generation. A different database
        // cannot borrow that authority during sequential recovery; its fresh
        // directory flock remains blocked until the original owner drains
        // the exact retained tombstone.
        #[cfg(target_os = "linux")]
        {
            let foreign_backend = SqliteSessionBackend::open(directory.path().join("other.sqlite"))
                .expect("open independent backend");
            assert!(matches!(
                open(
                    &foreign_backend,
                    snapshots.clone(),
                    identity(1),
                    expected_members(),
                )
                .await,
                Err(SessionConsensusStorageError::BackendUnavailable)
            ));

            // The in-process registry is deliberately not the only fence.
            // A fresh process has no queued-generation map to consult, so it
            // must still be blocked by the retained D1 lease fence even when
            // it asks for a different configured D2 namespace.
            const CHILD_MODE: &str = "OPC_SESSION_STORE_SNAPSHOT_LEASE_CHILD_MODE";
            const CHILD_DATABASE: &str = "OPC_SESSION_STORE_SNAPSHOT_LEASE_CHILD_DATABASE";
            const CHILD_SNAPSHOTS: &str = "OPC_SESSION_STORE_SNAPSHOT_LEASE_CHILD_SNAPSHOTS";
            const CHILD_TEST: &str = "consensus::storage::tests::receiver_lease_excludes_a_separate_process_until_receiver_drop";
            let blocked =
                std::process::Command::new(std::env::current_exe().expect("test executable"))
                    .arg(CHILD_TEST)
                    .arg("--exact")
                    .arg("--nocapture")
                    .env(CHILD_MODE, "blocked")
                    .env(CHILD_DATABASE, &database)
                    .env(CHILD_SNAPSHOTS, &migrated_snapshots)
                    .output()
                    .expect("run independent queued-cleanup child");
            assert!(
                blocked.status.success(),
                "fresh process bypassed the queued D1 lease fence: {}",
                String::from_utf8_lossy(&blocked.stderr)
            );
        }

        // A second crash at the retained-tombstone sync boundary must still
        // target that same name; it must not manufacture a nested tombstone.
        fail_snapshot_cleanup_post_rename_sync_for_test(&snapshots.join(&original));
        assert!(matches!(
            open(&backend, snapshots.clone(), identity(1), expected_members()).await,
            Err(SessionConsensusStorageError::BackendUnavailable)
        ));
        let names = std::fs::read_dir(&snapshots)
            .expect("read twice-retained tombstone")
            .map(|entry| {
                entry
                    .expect("directory entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        assert_eq!(names.len(), 1);
        assert_eq!(names[0].matches(".opc-cleanup-").count(), 1);

        // The next retry removes the exact tombstone. Its synchronous cleanup
        // failure is then reported once, before the following clean restart.
        assert!(matches!(
            open(&backend, snapshots.clone(), identity(1), expected_members()).await,
            Err(SessionConsensusStorageError::BackendUnavailable)
        ));
        assert!(std::fs::read_dir(&snapshots)
            .expect("read emptied tombstone directory")
            .next()
            .is_none());
        let (final_log, final_state) = open(&backend, snapshots, identity(1), expected_members())
            .await
            .expect("clean restart after exact tombstone retry");
        drop(final_log);
        drop(final_state);

        #[cfg(target_os = "linux")]
        {
            // Once the original D1 generation is reclaimed, acknowledged,
            // and its final owner has dropped, a fresh process can select a
            // different configured namespace for the durable database.
            const CHILD_MODE: &str = "OPC_SESSION_STORE_SNAPSHOT_LEASE_CHILD_MODE";
            const CHILD_DATABASE: &str = "OPC_SESSION_STORE_SNAPSHOT_LEASE_CHILD_DATABASE";
            const CHILD_SNAPSHOTS: &str = "OPC_SESSION_STORE_SNAPSHOT_LEASE_CHILD_SNAPSHOTS";
            const CHILD_TEST: &str = "consensus::storage::tests::receiver_lease_excludes_a_separate_process_until_receiver_drop";
            let admitted =
                std::process::Command::new(std::env::current_exe().expect("test executable"))
                    .arg(CHILD_TEST)
                    .arg("--exact")
                    .arg("--nocapture")
                    .env(CHILD_MODE, "admitted")
                    .env(CHILD_DATABASE, &database)
                    .env(CHILD_SNAPSHOTS, &migrated_snapshots)
                    .output()
                    .expect("run post-ack child");
            assert!(
                admitted.status.success(),
                "fresh process remained fenced after D1 acknowledgement: {}",
                String::from_utf8_lossy(&admitted.stderr)
            );
        }
    }

    #[tokio::test]
    async fn snapshot_artifact_cleanup_preserves_a_same_name_replacement() {
        let directory = tempfile::tempdir().expect("snapshot artifact directory");
        let path = directory.path().join("install-identity.sqlite");
        std::fs::write(&path, b"original").expect("create owned artifact");
        let cleanup_failed = Arc::new(AtomicBool::new(false));
        let artifact = SnapshotArtifact::new(path.clone(), Arc::clone(&cleanup_failed));
        let created_descriptor = open_snapshot_nofollow_read(&path)
            .expect("hold descriptor for freshly created artifact");
        artifact
            .record_identity_from_file(&created_descriptor)
            .expect("bind identity from created descriptor");
        let replacement = directory.path().join("replacement.sqlite");
        std::fs::write(&replacement, b"replacement").expect("write replacement");
        std::fs::rename(&replacement, &path).expect("replace artifact path");

        assert!(
            artifact.remove().await.is_err(),
            "replacement must fail closed"
        );
        assert!(cleanup_failed.load(Ordering::Acquire));
        assert_eq!(
            std::fs::read(&path).expect("read replacement"),
            b"replacement"
        );
        drop(artifact);
        assert_eq!(
            std::fs::read(&path).expect("replacement survives drop"),
            b"replacement"
        );
    }

    #[tokio::test]
    async fn snapshot_artifact_cleanup_restores_pre_rename_replacement_without_clobbering() {
        let _hook_lock = snapshot_artifact_cleanup_test_lock().lock().await;
        let directory = tempfile::tempdir().expect("snapshot artifact directory");
        let path = directory.path().join("install-identity.sqlite");
        std::fs::write(&path, b"owned").expect("create owned artifact");
        let cleanup_failed = Arc::new(AtomicBool::new(false));
        let artifact = SnapshotArtifact::new(path.clone(), Arc::clone(&cleanup_failed));
        let descriptor = open_snapshot_nofollow_read(&path).expect("owned descriptor");
        artifact
            .record_identity_from_file(&descriptor)
            .expect("bind owned descriptor");
        {
            let mut hooks = snapshot_artifact_cleanup_test_hooks()
                .lock()
                .expect("install cleanup hook");
            hooks.entry(path.clone()).or_default().before_rename =
                Some(Box::new(|original, _tombstone| {
                    let replacement = original.with_extension("replacement");
                    std::fs::write(&replacement, b"foreign-before-rename").expect("foreign bytes");
                    std::fs::rename(&replacement, original).expect("replace before rename");
                }));
        }

        assert!(artifact.remove().await.is_err());
        assert_eq!(
            std::fs::read(&path).expect("restored foreign occupant"),
            b"foreign-before-rename"
        );
        drop(artifact);
        assert_eq!(
            std::fs::read(&path).expect("drop cannot clobber foreign"),
            b"foreign-before-rename"
        );
        assert!(cleanup_failed.load(Ordering::Acquire));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn snapshot_artifact_cleanup_pre_rename_fifo_fails_without_blocking() {
        let _hook_lock = snapshot_artifact_cleanup_test_lock().lock().await;
        let directory = tempfile::tempdir().expect("snapshot artifact directory");
        let path = directory.path().join("install-identity.sqlite");
        std::fs::write(&path, b"owned").expect("create owned artifact");
        let cleanup_failed = Arc::new(AtomicBool::new(false));
        let artifact = SnapshotArtifact::new(path.clone(), Arc::clone(&cleanup_failed));
        let descriptor = open_snapshot_nofollow_read(&path).expect("owned descriptor");
        artifact
            .record_identity_from_file(&descriptor)
            .expect("bind owned descriptor");
        snapshot_artifact_cleanup_test_hooks()
            .lock()
            .expect("install cleanup hook")
            .entry(path.clone())
            .or_default()
            .before_rename = Some(Box::new(|original, _| {
            std::fs::remove_file(original).expect("remove original before FIFO replacement");
            assert!(std::process::Command::new("mkfifo")
                .arg("-m")
                .arg("600")
                .arg(original)
                .status()
                .expect("run mkfifo")
                .success());
        }));

        assert!(
            tokio::time::timeout(Duration::from_secs(1), artifact.remove())
                .await
                .expect("FIFO cleanup open must not block")
                .is_err()
        );
        assert!(cleanup_failed.load(Ordering::Acquire));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn snapshot_artifact_cleanup_post_rename_fifo_fails_without_blocking() {
        let _hook_lock = snapshot_artifact_cleanup_test_lock().lock().await;
        let directory = tempfile::tempdir().expect("snapshot artifact directory");
        let path = directory.path().join("install-identity.sqlite");
        std::fs::write(&path, b"owned").expect("create owned artifact");
        let cleanup_failed = Arc::new(AtomicBool::new(false));
        let artifact = SnapshotArtifact::new(path.clone(), Arc::clone(&cleanup_failed));
        let descriptor = open_snapshot_nofollow_read(&path).expect("owned descriptor");
        artifact
            .record_identity_from_file(&descriptor)
            .expect("bind owned descriptor");
        snapshot_artifact_cleanup_test_hooks()
            .lock()
            .expect("install cleanup hook")
            .entry(path.clone())
            .or_default()
            .after_rename = Some(Box::new(|_, tombstone| {
            std::fs::remove_file(tombstone)
                .expect("remove owned tombstone before FIFO replacement");
            assert!(std::process::Command::new("mkfifo")
                .arg("-m")
                .arg("600")
                .arg(tombstone)
                .status()
                .expect("run mkfifo")
                .success());
        }));

        assert!(
            tokio::time::timeout(Duration::from_secs(1), artifact.remove())
                .await
                .expect("FIFO cleanup open must not block")
                .is_err()
        );
        assert!(cleanup_failed.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn snapshot_artifact_cleanup_never_replaces_a_precreated_tombstone_collision() {
        let _hook_lock = snapshot_artifact_cleanup_test_lock().lock().await;
        let directory = tempfile::tempdir().expect("snapshot artifact directory");
        let path = directory.path().join("install-identity.sqlite");
        std::fs::write(&path, b"owned").expect("create owned artifact");
        let cleanup_failed = Arc::new(AtomicBool::new(false));
        let artifact = SnapshotArtifact::new(path.clone(), Arc::clone(&cleanup_failed));
        let descriptor = open_snapshot_nofollow_read(&path).expect("owned descriptor");
        artifact
            .record_identity_from_file(&descriptor)
            .expect("bind owned descriptor");
        let collision = Arc::new(std::sync::Mutex::new(None));
        {
            let collision = Arc::clone(&collision);
            let mut hooks = snapshot_artifact_cleanup_test_hooks()
                .lock()
                .expect("install cleanup hook");
            hooks.entry(path.clone()).or_default().before_rename =
                Some(Box::new(move |_original, tombstone| {
                    std::fs::write(tombstone, b"foreign-tombstone-collision")
                        .expect("collision bytes");
                    *collision.lock().expect("collision path") = Some(tombstone.to_path_buf());
                }));
        }

        assert!(
            artifact.remove().await.is_err(),
            "RENAME_NOREPLACE rejects collision"
        );
        assert_eq!(
            std::fs::read(&path).expect("owned source remains"),
            b"owned"
        );
        let collision = collision
            .lock()
            .expect("collision path")
            .clone()
            .expect("hook selected tombstone");
        assert_eq!(
            std::fs::read(&collision).expect("foreign collision survives"),
            b"foreign-tombstone-collision"
        );
        drop(artifact);
        assert_eq!(
            std::fs::read(&collision).expect("drop cannot clobber collision"),
            b"foreign-tombstone-collision"
        );
        assert!(cleanup_failed.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn snapshot_artifact_cleanup_retries_exact_tombstone_after_post_rename_sync_failure() {
        let _hook_lock = snapshot_artifact_cleanup_test_lock().lock().await;
        let directory = tempfile::tempdir().expect("snapshot artifact directory");
        let path = directory.path().join("install-identity.sqlite");
        std::fs::write(&path, b"owned").expect("create owned artifact");
        let cleanup_failed = Arc::new(AtomicBool::new(false));
        let artifact = SnapshotArtifact::new(path.clone(), Arc::clone(&cleanup_failed));
        let descriptor = open_snapshot_nofollow_read(&path).expect("owned descriptor");
        artifact
            .record_identity_from_file(&descriptor)
            .expect("bind owned descriptor");
        snapshot_artifact_cleanup_test_hooks()
            .lock()
            .expect("install cleanup hook")
            .entry(path.clone())
            .or_default()
            .fail_post_rename_sync = true;

        assert!(
            artifact.remove().await.is_err(),
            "injected sync failure surfaces"
        );
        assert!(!path.exists(), "original name stays vacant after rename");
        let tombstones = std::fs::read_dir(directory.path())
            .expect("read tombstones")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|entry| {
                entry
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().contains(".opc-cleanup-"))
            })
            .collect::<Vec<_>>();
        assert_eq!(tombstones.len(), 1, "one exact tombstone is retained");
        artifact.remove().await.expect("retry exact tombstone");
        assert!(std::fs::read_dir(directory.path())
            .expect("empty directory")
            .next()
            .is_none());
        assert!(
            cleanup_failed.load(Ordering::Acquire),
            "first failure stays observable"
        );
    }

    #[tokio::test]
    async fn snapshot_artifact_cleanup_post_rename_mismatch_preserves_occupied_original_and_tombstone(
    ) {
        let _hook_lock = snapshot_artifact_cleanup_test_lock().lock().await;
        let directory = tempfile::tempdir().expect("snapshot artifact directory");
        let path = directory.path().join("install-identity.sqlite");
        std::fs::write(&path, b"owned").expect("create owned artifact");
        let cleanup_failed = Arc::new(AtomicBool::new(false));
        let artifact = SnapshotArtifact::new(path.clone(), Arc::clone(&cleanup_failed));
        let descriptor = open_snapshot_nofollow_read(&path).expect("owned descriptor");
        artifact
            .record_identity_from_file(&descriptor)
            .expect("bind owned descriptor");
        {
            let mut hooks = snapshot_artifact_cleanup_test_hooks()
                .lock()
                .expect("install cleanup hook");
            hooks.entry(path.clone()).or_default().after_rename =
                Some(Box::new(|original, tombstone| {
                    let foreign_tombstone = tombstone.with_extension("foreign");
                    std::fs::write(&foreign_tombstone, b"foreign-tombstone")
                        .expect("foreign tombstone");
                    std::fs::rename(&foreign_tombstone, tombstone).expect("replace tombstone");
                    std::fs::write(original, b"foreign-original").expect("occupy original");
                }));
        }

        assert!(artifact.remove().await.is_err());
        assert_eq!(
            std::fs::read(&path).expect("foreign original"),
            b"foreign-original"
        );
        let tombstone = std::fs::read_dir(directory.path())
            .expect("read tombstone")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|entry| entry != &path)
            .expect("foreign tombstone survives");
        assert_eq!(
            std::fs::read(&tombstone).expect("foreign tombstone bytes"),
            b"foreign-tombstone"
        );
        drop(artifact);
        assert_eq!(
            std::fs::read(&path).expect("drop preserves original"),
            b"foreign-original"
        );
        assert_eq!(
            std::fs::read(&tombstone).expect("drop preserves tombstone"),
            b"foreign-tombstone"
        );
        assert!(cleanup_failed.load(Ordering::Acquire));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn snapshot_artifact_final_identity_unlink_seam_preserves_replacement_and_unrelated_child(
    ) {
        let _hook_lock = snapshot_artifact_cleanup_test_lock().lock().await;
        let directory = tempfile::tempdir().expect("snapshot artifact directory");
        let path = directory.path().join("install-identity.sqlite");
        let unrelated = directory.path().join("unrelated-survivor");
        std::fs::write(&path, b"owned").expect("create owned artifact");
        std::fs::write(&unrelated, b"unrelated").expect("create unrelated survivor");
        let cleanup_failed = Arc::new(AtomicBool::new(false));
        let artifact = SnapshotArtifact::new(path.clone(), Arc::clone(&cleanup_failed));
        let descriptor = open_snapshot_nofollow_read(&path).expect("owned descriptor");
        artifact
            .record_identity_from_file(&descriptor)
            .expect("bind owned descriptor");
        snapshot_artifact_cleanup_test_hooks()
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
            artifact.remove().await.is_err(),
            "a replacement after final identity must fail closed"
        );
        assert!(!path.exists(), "public artifact name remains vacant");
        let foreign = std::fs::read_dir(directory.path())
            .expect("read cleanup directory")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|entry| entry != &unrelated)
            .expect("foreign replacement survives under tombstone name");
        assert_eq!(
            std::fs::read(&foreign).expect("foreign replacement bytes"),
            b"foreign-final-seam"
        );
        assert_eq!(
            std::fs::read(&unrelated).expect("unrelated survivor bytes"),
            b"unrelated"
        );

        drop(artifact);
        assert_eq!(
            std::fs::read(&foreign).expect("drop preserves foreign replacement"),
            b"foreign-final-seam"
        );
        assert_eq!(
            std::fs::read(&unrelated).expect("drop preserves unrelated survivor"),
            b"unrelated"
        );
        assert!(cleanup_failed.load(Ordering::Acquire));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn snapshot_artifact_post_unlink_guard_failure_replays_the_exact_guard_without_nesting() {
        let _hook_lock = snapshot_artifact_cleanup_test_lock().lock().await;
        let directory = tempfile::tempdir().expect("snapshot artifact directory");
        let path = directory.path().join("install-identity.sqlite");
        std::fs::write(&path, b"owned").expect("create owned artifact");
        let cleanup_failed = Arc::new(AtomicBool::new(false));
        let artifact = SnapshotArtifact::new(path.clone(), Arc::clone(&cleanup_failed));
        let descriptor = open_snapshot_nofollow_read(&path).expect("owned descriptor");
        artifact
            .record_identity_from_file(&descriptor)
            .expect("bind owned descriptor");
        snapshot_artifact_cleanup_test_hooks()
            .lock()
            .expect("inject post-final-guard failure")
            .entry(path.clone())
            .or_default()
            .fail_post_unlink_guard_sync = true;

        assert!(
            artifact.remove().await.is_err(),
            "the durable final guard remains for replay"
        );
        let guards = std::fs::read_dir(directory.path())
            .expect("read cleanup directory")
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

        artifact.remove().await.expect("replay exact final guard");
        assert!(std::fs::read_dir(directory.path())
            .expect("read replayed directory")
            .next()
            .is_none());
        assert!(cleanup_failed.load(Ordering::Acquire));
    }

    #[test]
    fn snapshot_build_capacity_reserves_exactly_two_sqlite_artifact_groups() {
        assert_eq!(8, SNAPSHOT_BUILD_RESERVATION_ENTRIES);
        assert!(reserve_snapshot_directory_entries(24, SNAPSHOT_BUILD_RESERVATION_ENTRIES).is_ok());
        assert!(
            reserve_snapshot_directory_entries(25, SNAPSHOT_BUILD_RESERVATION_ENTRIES).is_err()
        );
    }

    #[tokio::test]
    async fn build_snapshot_admits_24_survivors_and_rejects_25_before_creation() {
        async fn fixture(survivors: usize) -> (tempfile::TempDir, SqliteConsensusStateMachine) {
            let directory = tempfile::tempdir().expect("near-cap build directory");
            let snapshot_directory = directory.path().join("snapshots");
            let backend = SqliteSessionBackend::open(directory.path().join("sessions.sqlite"))
                .expect("near-cap build backend");
            let (_, mut state_machine) = open(
                &backend,
                snapshot_directory.clone(),
                identity(1),
                expected_members(),
            )
            .await
            .expect("near-cap build storage");
            state_machine
                .apply([initial_membership_entry()])
                .await
                .expect("near-cap membership");
            for index in 0..survivors {
                std::fs::write(
                    snapshot_directory.join(format!("survivor-{index}")),
                    b"foreign",
                )
                .expect("write survivor");
            }
            sync_directory(&snapshot_directory).expect("sync near-cap fixture");
            (directory, state_machine)
        }

        let (_directory, mut accepted) = fixture(24).await;
        accepted
            .get_snapshot_builder()
            .await
            .build_snapshot()
            .await
            .expect("24 survivors retain the physical eight-entry build reservation");

        let (_directory, mut rejected) = fixture(25).await;
        assert!(rejected
            .get_snapshot_builder()
            .await
            .build_snapshot()
            .await
            .is_err());
    }

    #[test]
    fn snapshot_install_capacity_reservation_is_profile_specific() {
        assert_eq!(
            5,
            snapshot_install_reservation_entries(ConsensusAuthorityProfile::Dynamic)
        );
        assert_eq!(
            4,
            snapshot_install_reservation_entries(ConsensusAuthorityProfile::FixedImmutable)
        );
        // The incoming envelope is already a counted survivor.  Fixed
        // promotion is in-place, so 28 occupied entries plus its four-entry
        // SQLite group is the exact accepted peak; 29 cannot reserve it.
        assert!(reserve_snapshot_directory_entries(
            28,
            snapshot_install_reservation_entries(ConsensusAuthorityProfile::FixedImmutable)
        )
        .is_ok());
        assert!(reserve_snapshot_directory_entries(
            29,
            snapshot_install_reservation_entries(ConsensusAuthorityProfile::FixedImmutable)
        )
        .is_err());
    }

    #[tokio::test]
    async fn shutdown_observer_waits_for_all_tracked_sqlite_owners() {
        let root = ConsensusStorageShutdownGuard::tracked();
        let observer = root.observer().expect("tracked root has an observer");
        let state_machine = root.child();
        let replication_reader = root.child();
        let snapshot_builder = state_machine.child();
        assert_eq!(observer.0.active_owners.load(Ordering::Acquire), 4);

        drop(root);
        assert_eq!(
            observer.0.active_owners.load(Ordering::Acquire),
            3,
            "the log root cannot complete while other engine tasks own SQLite"
        );
        drop(state_machine);
        drop(replication_reader);
        assert_eq!(observer.0.active_owners.load(Ordering::Acquire), 1);
        drop(snapshot_builder);
        assert_eq!(observer.0.active_owners.load(Ordering::Acquire), 0);
        tokio::time::timeout(Duration::from_secs(1), observer.wait())
            .await
            .expect("the final tracked SQLite owner releases the shutdown barrier");
    }

    #[tokio::test]
    async fn shutdown_observer_tracks_real_openraft_storage_wrappers() {
        let directory = tempfile::tempdir().expect("storage ownership directory");
        let backend = SqliteSessionBackend::open(directory.path().join("sessions.sqlite"))
            .expect("storage ownership backend");
        let (mut log_store, mut state_machine) = open(
            &backend,
            directory.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("storage ownership wrappers");
        let observer = state_machine
            .shutdown_observer()
            .expect("production wrappers share a shutdown observer");
        let replication_reader = log_store.get_log_reader().await;
        let snapshot_builder = state_machine.get_snapshot_builder().await;
        assert_eq!(observer.0.active_owners.load(Ordering::Acquire), 4);

        let first_waiter = tokio::spawn({
            let observer = observer.clone();
            async move { observer.wait().await }
        });
        let second_waiter = tokio::spawn({
            let observer = observer.clone();
            async move { observer.wait().await }
        });
        tokio::task::yield_now().await;

        drop(log_store);
        drop(state_machine);
        assert_eq!(observer.0.active_owners.load(Ordering::Acquire), 2);
        assert!(!first_waiter.is_finished());
        assert!(!second_waiter.is_finished());

        drop(replication_reader);
        assert_eq!(observer.0.active_owners.load(Ordering::Acquire), 1);
        assert!(!first_waiter.is_finished());
        assert!(!second_waiter.is_finished());

        drop(snapshot_builder);
        tokio::time::timeout(Duration::from_secs(1), async {
            first_waiter.await.expect("first shutdown observer");
            second_waiter.await.expect("second shutdown observer");
        })
        .await
        .expect("all waiters observe final wrapper release");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn publication_identity_check_rejects_atomic_pathname_replacement() {
        let directory = tempfile::tempdir().expect("snapshot directory");
        let published = directory.path().join("snapshot.opc");
        tokio::fs::write(&published, b"verified envelope A")
            .await
            .expect("write first envelope");
        let snapshot = SessionSnapshotFile::open(published.clone())
            .await
            .expect("open first envelope");
        let pinned = snapshot_handle_identity_pin(&snapshot, &published)
            .await
            .expect("pin first envelope");

        let replacement = directory.path().join("replacement.opc");
        tokio::fs::write(&replacement, b"different valid envelope B")
            .await
            .expect("write replacement envelope");
        tokio::fs::rename(&replacement, &published)
            .await
            .expect("replace published name");

        assert!(
            !pinned
                .path_matches_identity(&published)
                .expect("compare published inode"),
            "a verified handle must not authorize a replacement published name"
        );
    }

    #[tokio::test]
    async fn publication_error_after_durable_metadata_is_committed_success_without_retry() {
        let directory = tempfile::tempdir().expect("snapshot publication directory");
        let backend = SqliteSessionBackend::open(directory.path().join("sessions.sqlite"))
            .expect("snapshot publication backend");
        let (_, mut state_machine) = open(
            &backend,
            directory.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("snapshot publication storage");
        state_machine
            .apply([initial_membership_entry()])
            .await
            .expect("snapshot publication membership");
        let (last_log_id, last_membership) = state_machine
            .applied_state()
            .await
            .expect("snapshot publication applied state");
        let meta = SnapshotMeta {
            last_log_id,
            last_membership,
            snapshot_id: "publication-error-after-commit".to_owned(),
        };
        let file_name = "snapshot-00000000-0000-4000-8000-000000000019.opc";
        let candidate_path = directory.path().join("snapshots").join(file_name);
        std::fs::write(&candidate_path, b"durable sealed snapshot fixture")
            .expect("write snapshot publication candidate");
        let candidate =
            std::fs::File::open(&candidate_path).expect("open snapshot publication candidate");
        let mut cleanup =
            UnpublishedSnapshotArtifact::from_file(&candidate, candidate_path.clone(), false)
                .expect("arm snapshot publication cleanup");
        let checksum = [0x5a; 32];
        let byte_length = candidate.metadata().expect("candidate metadata").len();
        let publication_attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed_publication_attempts = Arc::clone(&publication_attempts);

        let conn = state_machine.core.conn.lock().await;
        let publication = publish_snapshot_metadata_with_readback(
            &conn,
            state_machine.core.storage_identity,
            &meta,
            file_name,
            checksum,
            byte_length,
            &mut cleanup,
            state_machine
                .core
                .snapshot_publication_indeterminate
                .as_ref(),
            || {
                observed_publication_attempts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                consensus::save_current_snapshot_sync(
                    &conn,
                    state_machine.core.storage_identity,
                    &meta,
                    file_name,
                    checksum,
                    byte_length,
                )?;
                Err(io::Error::other(
                    "injected snapshot publication error after durable metadata",
                ))
            },
        );
        assert!(
            publication.is_ok(),
            "an exact durable metadata readback resolves the commit as success"
        );
        assert_eq!(
            publication_attempts.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "the resolved publication is not replayed"
        );
        let observed =
            consensus::read_current_snapshot_sync(&conn, state_machine.core.storage_identity)
                .expect("read committed snapshot metadata")
                .expect("snapshot metadata was durably committed");
        assert_eq!(meta, observed.0);
        assert_eq!(file_name, observed.1);
        assert_eq!(checksum, observed.2);
        assert_eq!(byte_length, observed.3);
        drop(conn);

        drop(cleanup);
        assert!(
            candidate_path.is_file(),
            "an error-path guard must preserve the exact durably published snapshot"
        );
    }

    #[tokio::test]
    async fn publication_error_with_attached_alias_latches_until_reopen() {
        use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

        let directory = tempfile::tempdir().expect("attached generic publication directory");
        let backend = SqliteSessionBackend::open(directory.path().join("sessions.sqlite"))
            .expect("attached generic publication backend");
        let (_, mut state_machine) = open(
            &backend,
            directory.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("attached generic publication storage");
        state_machine
            .apply([initial_membership_entry()])
            .await
            .expect("attached generic publication membership");
        let (last_log_id, last_membership) = state_machine
            .applied_state()
            .await
            .expect("attached generic publication applied state");
        let meta = SnapshotMeta {
            last_log_id,
            last_membership,
            snapshot_id: "attached-generic-publication".to_owned(),
        };
        let file_name = "snapshot-00000000-0000-4000-8000-00000000001a.opc";
        let candidate_path = directory.path().join("snapshots").join(file_name);
        std::fs::write(&candidate_path, b"sealed generic attached candidate")
            .expect("write attached generic candidate");
        let candidate = std::fs::File::open(&candidate_path).expect("open attached candidate");
        let mut cleanup =
            UnpublishedSnapshotArtifact::from_file(&candidate, candidate_path.clone(), false)
                .expect("arm attached generic candidate cleanup");
        let checksum = [0x6a; 32];
        let byte_length = candidate.metadata().expect("candidate metadata").len();
        let detach_attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed_detach_attempts = Arc::clone(&detach_attempts);
        let conn = state_machine.core.conn.lock().await;
        conn.authorizer(Some(move |context: AuthContext<'_>| {
            if matches!(context.action, AuthAction::Detach { .. }) {
                observed_detach_attempts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Authorization::Deny
            } else {
                Authorization::Allow
            }
        }));
        let publication = publish_snapshot_metadata_with_readback(
            &conn,
            state_machine.core.storage_identity,
            &meta,
            file_name,
            checksum,
            byte_length,
            &mut cleanup,
            state_machine
                .core
                .snapshot_publication_indeterminate
                .as_ref(),
            || {
                consensus::save_current_snapshot_sync(
                    &conn,
                    state_machine.core.storage_identity,
                    &meta,
                    file_name,
                    checksum,
                    byte_length,
                )?;
                conn.execute("ATTACH DATABASE ':memory:' AS consensus_incoming", [])
                    .map_err(|error| io::Error::other(error.to_string()))?;
                Err(io::Error::other(
                    "injected error after attached publication commit",
                ))
            },
        );
        assert!(
            publication.is_err(),
            "unresolved attached alias is fail-stop"
        );
        assert!(
            state_machine
                .core
                .snapshot_publication_indeterminate
                .load(std::sync::atomic::Ordering::Acquire),
            "generic exact-readback success cannot declare an attached connection reusable"
        );
        assert_eq!(
            detach_attempts.load(std::sync::atomic::Ordering::Relaxed),
            2,
            "generic error path exhausts the bounded final detach before latching"
        );
        assert!(
            consensus::attached_snapshot_database_is_attached_sync(&conn)
                .expect("inspect unresolved attached alias"),
            "failed cleanup leaves the connection explicitly non-reusable"
        );
        drop(conn);
        drop(cleanup);
        assert!(
            candidate_path.is_file(),
            "committed candidate remains preserved"
        );
    }

    #[tokio::test]
    async fn indeterminate_publication_readback_latches_until_a_fresh_core_validates() {
        use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
        use rusqlite::OptionalExtension;

        for case in ["mismatch", "absent", "readback-error"] {
            let directory = tempfile::tempdir().expect("indeterminate publication directory");
            let snapshot_directory = directory.path().join("snapshots");
            let database_path = directory.path().join("sessions.sqlite");
            let backend = SqliteSessionBackend::open(&database_path)
                .expect("indeterminate publication backend");
            let (mut log_store, mut state_machine) = open(
                &backend,
                snapshot_directory.clone(),
                identity(1),
                expected_members(),
            )
            .await
            .expect("indeterminate publication storage");
            append_commit_and_apply(
                &mut log_store,
                &mut state_machine,
                [initial_membership_entry()],
                "indeterminate publication membership",
            )
            .await;
            let mut built = state_machine
                .get_snapshot_builder()
                .await
                .build_snapshot()
                .await
                .expect("build durable publication candidate");
            let mut second_install = state_machine
                .begin_receiving_snapshot()
                .await
                .expect("stage second-install candidate before latch");
            built
                .snapshot
                .rewind()
                .await
                .expect("rewind second-install candidate");
            tokio::io::copy(&mut built.snapshot, &mut second_install)
                .await
                .expect("copy second-install candidate before latch");

            let membership_before = state_machine
                .applied_state()
                .await
                .expect("read membership before indeterminate publication")
                .1;
            let readback_denied = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let observed_readback_denied = Arc::clone(&readback_denied);
            let conn = state_machine.core.conn.lock().await;
            if case == "readback-error" {
                conn.authorizer(Some(move |context: AuthContext<'_>| {
                    if observed_readback_denied.load(std::sync::atomic::Ordering::Acquire)
                        && matches!(
                            context.action,
                            AuthAction::Read {
                                table_name: "consensus_snapshot",
                                ..
                            }
                        )
                    {
                        Authorization::Deny
                    } else {
                        Authorization::Allow
                    }
                }));
            }
            let (meta, file_name, checksum, byte_length) =
                consensus::read_current_snapshot_sync(&conn, state_machine.core.storage_identity)
                    .expect("read baseline durable candidate")
                    .expect("baseline candidate metadata");
            let candidate_path = snapshot_directory.join(&file_name);
            let candidate =
                std::fs::File::open(&candidate_path).expect("open durable publication candidate");
            let mut cleanup =
                UnpublishedSnapshotArtifact::from_file(&candidate, candidate_path.clone(), false)
                    .expect("arm exact candidate cleanup");
            let publication_attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let observed_publication_attempts = Arc::clone(&publication_attempts);
            let alternate_meta = SnapshotMeta {
                last_log_id: meta.last_log_id,
                last_membership: meta.last_membership.clone(),
                snapshot_id: format!("indeterminate-{case}-alternate"),
            };
            let publication = publish_snapshot_metadata_with_readback(
                &conn,
                state_machine.core.storage_identity,
                &meta,
                &file_name,
                checksum,
                byte_length,
                &mut cleanup,
                state_machine
                    .core
                    .snapshot_publication_indeterminate
                    .as_ref(),
                || {
                    observed_publication_attempts
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    match case {
                        "mismatch" => consensus::save_current_snapshot_sync(
                            &conn,
                            state_machine.core.storage_identity,
                            &alternate_meta,
                            &file_name,
                            checksum,
                            byte_length,
                        )?,
                        "absent" => {
                            conn.execute("DELETE FROM consensus_snapshot", [])
                                .map_err(|error| io::Error::other(error.to_string()))?;
                        }
                        "readback-error" => {
                            // Arm only after the write so the publication
                            // reaches the readback boundary rather than
                            // manufacturing an earlier write failure.
                            readback_denied.store(true, std::sync::atomic::Ordering::Release);
                        }
                        _ => unreachable!("fixed indeterminate case"),
                    }
                    Err(io::Error::other(format!(
                        "injected {case} after publication boundary"
                    )))
                },
            );
            assert!(publication.is_err(), "{case} is fail-stop indeterminate");
            assert_eq!(
                publication_attempts.load(std::sync::atomic::Ordering::Relaxed),
                1,
                "{case} never replays a possibly committed publication"
            );
            assert!(
                state_machine
                    .core
                    .snapshot_publication_indeterminate
                    .load(std::sync::atomic::Ordering::Acquire),
                "{case} latches this core before a second publication"
            );
            readback_denied.store(false, std::sync::atomic::Ordering::Release);
            let snapshot_rows_before_second_build: i64 = conn
                .query_row("SELECT COUNT(*) FROM consensus_snapshot", [], |row| {
                    row.get(0)
                })
                .expect("count publication rows before blocked retry");
            drop(conn);
            drop(cleanup);
            assert!(
                candidate_path.is_file(),
                "{case} preserves the candidate for fresh-core resolution"
            );
            assert_eq!(
                state_machine
                    .applied_state()
                    .await
                    .expect("read membership after indeterminate publication")
                    .1,
                membership_before,
                "{case} does not observe a membership change"
            );
            assert!(
                state_machine
                    .get_snapshot_builder()
                    .await
                    .build_snapshot()
                    .await
                    .is_err(),
                "{case} rejects a second build before it can publish"
            );
            let candidate_bytes_before_second_install =
                std::fs::read(&candidate_path).expect("read candidate before blocked install");
            let metadata_before_second_install: Option<(Vec<u8>, String, Vec<u8>, i64)> = {
                let conn = state_machine.core.conn.lock().await;
                conn.query_row(
                    "SELECT meta_json, file_name, checksum, byte_length FROM consensus_snapshot WHERE singleton = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()
                .expect("read metadata before blocked install")
            };
            assert!(
                state_machine
                    .install_snapshot(&built.meta, second_install)
                    .await
                    .is_err(),
                "{case} rejects a second install before it can publish"
            );
            let conn = state_machine.core.conn.lock().await;
            assert_eq!(
                conn.query_row("SELECT COUNT(*) FROM consensus_snapshot", [], |row| row
                    .get::<_, i64>(0))
                    .expect("count publication rows after blocked retry"),
                snapshot_rows_before_second_build,
                "{case} blocked retry performs no metadata publication"
            );
            drop(conn);
            assert_eq!(
                std::fs::read(&candidate_path).expect("read candidate after blocked install"),
                candidate_bytes_before_second_install,
                "{case} blocked install leaves the current candidate byte-identical"
            );
            {
                let conn = state_machine.core.conn.lock().await;
                assert_eq!(
                    conn.query_row(
                        "SELECT meta_json, file_name, checksum, byte_length FROM consensus_snapshot WHERE singleton = 1",
                        [],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                    )
                    .optional()
                    .expect("read metadata after blocked install"),
                    metadata_before_second_install,
                    "{case} blocked install leaves durable metadata byte-identical"
                );
            }
            drop(built);
            drop(candidate);
            drop(log_store);
            drop(state_machine);
            drop(backend);

            let fresh_backend = SqliteSessionBackend::open(&database_path)
                .expect("reopen backend with a new SQLite connection");
            let fresh = open(
                &fresh_backend,
                snapshot_directory,
                identity(1),
                expected_members(),
            )
            .await;
            match case {
                "readback-error" => {
                    let (fresh_log, mut fresh_state_machine) =
                        fresh.expect("a new backend validates the exact durable candidate");
                    assert_eq!(
                        fresh_state_machine
                            .applied_state()
                            .await
                            .expect("read fresh durable membership")
                            .1,
                        membership_before,
                        "transient readback denial preserves exact durable membership"
                    );
                    assert!(
                        candidate_path.is_file(),
                        "transient readback denial retains the exact current candidate"
                    );
                    assert!(
                        !fresh_state_machine
                            .core
                            .snapshot_publication_indeterminate
                            .load(std::sync::atomic::Ordering::Acquire),
                        "only the new core starts without the old one-way latch"
                    );
                    fresh_state_machine
                        .get_snapshot_builder()
                        .await
                        .build_snapshot()
                        .await
                        .expect("fresh core can publish after exact validation");
                    drop(fresh_log);
                    drop(fresh_state_machine);
                }
                "mismatch" => {
                    let (fresh_log, fresh_state_machine) = fresh
                        .expect("fresh validation adopts the authoritative mismatched singleton");
                    let conn = fresh_state_machine.core.conn.lock().await;
                    assert_eq!(
                        consensus::read_current_snapshot_sync(
                            &conn,
                            fresh_state_machine.core.storage_identity,
                        )
                        .expect("read recovered mismatched singleton")
                        .expect("recovered mismatched singleton")
                        .0,
                        alternate_meta,
                        "reopen resolves to the exact durable alternate metadata rather than replaying the candidate"
                    );
                    drop(conn);
                    assert!(
                        candidate_path.is_file(),
                        "the exact durable candidate remains current"
                    );
                    drop(fresh_log);
                    drop(fresh_state_machine);
                }
                "absent" => {
                    let (fresh_log, mut fresh_state_machine) =
                        fresh.expect("fresh validation returns a new core for absent metadata");
                    assert!(
                        fresh_state_machine
                            .get_current_snapshot()
                            .await
                            .expect("read recovered absent singleton")
                            .is_none(),
                        "reopen accepts the durable absence rather than replaying the candidate"
                    );
                    assert!(
                        !candidate_path.exists(),
                        "fresh validation removes the unreferenced absent candidate"
                    );
                    drop(fresh_log);
                    drop(fresh_state_machine);
                }
                _ => unreachable!("fixed indeterminate case"),
            }
        }
    }

    #[tokio::test]
    async fn receiving_snapshot_rejects_sparse_or_oversized_offsets_and_cleans_abandoned_artifacts()
    {
        let directory = tempfile::tempdir().expect("receiving snapshot directory");
        let backend = SqliteSessionBackend::open(directory.path().join("sessions.sqlite"))
            .expect("receiving snapshot backend");
        let (_, mut state_machine) = open(
            &backend,
            directory.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("receiving snapshot storage");

        for _ in 0..2 {
            let receiving = state_machine
                .begin_receiving_snapshot()
                .await
                .expect("fresh receiving snapshot");
            let path = receiving.path().to_path_buf();
            assert!(path.is_file(), "fresh receive artifact exists while owned");
            drop(receiving);
            assert!(
                !path.exists(),
                "a later fresh snapshot must not retain an abandoned receive artifact"
            );
        }

        let mut receiving = state_machine
            .begin_receiving_snapshot()
            .await
            .expect("bounded receiving snapshot");
        let path = receiving.path().to_path_buf();
        assert!(
            receiving
                .seek(io::SeekFrom::Start(
                    SNAPSHOT_MAX_BYTES + SNAPSHOT_FOOTER_BYTES + 1
                ))
                .await
                .is_err(),
            "a receive cursor beyond the snapshot envelope must fail before writing"
        );
        assert_eq!(
            0,
            receiving.metadata().await.expect("receive metadata").len(),
            "an oversized receive cursor must not grow the artifact"
        );
        drop(receiving);
        assert!(
            !path.exists(),
            "an oversized receive artifact is cleaned on drop"
        );

        let mut receiving = state_machine
            .begin_receiving_snapshot()
            .await
            .expect("fresh sparse receiving snapshot");
        let path = receiving.path().to_path_buf();
        assert!(
            receiving.seek(io::SeekFrom::Start(1)).await.is_err(),
            "a sparse receive cursor must fail before writing"
        );
        assert_eq!(
            0,
            receiving.metadata().await.expect("receive metadata").len(),
            "a rejected sparse cursor must not grow the artifact"
        );
        drop(receiving);
        assert!(
            !path.exists(),
            "bounded receive artifact is cleaned on drop"
        );
    }

    #[tokio::test]
    async fn snapshot_install_detach_error_preserves_durably_current_candidate() {
        use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

        let source_directory = tempfile::tempdir().expect("snapshot source directory");
        let source_backend =
            SqliteSessionBackend::open(source_directory.path().join("sessions.sqlite"))
                .expect("snapshot source backend");
        let (mut source_log, mut source) = open(
            &source_backend,
            source_directory.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("snapshot source storage");
        let source_membership = initial_membership_entry();
        // The snapshot applies the one-member successor topology. The target
        // peer directory starts in the distinct two-member predecessor
        // topology so `observe_applied_membership` must suspend its old engine
        // route; merely returning `Ok(())` from that delegation is observable.
        let source_snapshot_membership = Entry {
            log_id: log_id(1),
            payload: EntryPayload::Membership(opc_consensus::engine::Membership::new(
                vec![expected_members()],
                expected_members(),
            )),
        };
        append_commit_and_apply(
            &mut source_log,
            &mut source,
            [
                source_membership.clone(),
                source_snapshot_membership.clone(),
            ],
            "snapshot source membership",
        )
        .await;
        let mut builder = source.get_snapshot_builder().await;
        let mut built = builder
            .build_snapshot()
            .await
            .expect("build source snapshot");

        let target_directory = tempfile::tempdir().expect("snapshot target directory");
        let target_backend =
            SqliteSessionBackend::open(target_directory.path().join("sessions.sqlite"))
                .expect("snapshot target backend");
        let predecessor_admission_members = BTreeSet::from([
            node_id(),
            SessionConsensusNodeId::new(8).expect("predecessor peer node"),
        ]);
        let predecessor_peer = SessionConsensusNodeId::new(8).expect("predecessor peer node");
        let mut target_network_factory = SessionRaftNetworkFactory::try_new(
            identity(1),
            node_id(),
            predecessor_admission_members,
            BTreeMap::from([(
                predecessor_peer,
                Arc::new(MembershipObservationProbePeer {
                    node_id: predecessor_peer,
                }) as Arc<dyn SessionConsensusPeer>,
            )]),
        )
        .expect("construct real target membership admission");
        let target_network = RaftNetworkFactory::new_client(
            &mut target_network_factory,
            predecessor_peer,
            &EmptyNode {},
        )
        .await;
        assert!(
            format!("{target_network:?}").contains("peer_configured: true"),
            "the predecessor topology begins with an admitted engine peer"
        );
        let target_admission = target_network_factory.peer_directory();
        let (mut target_log, mut target, _) = open_with_member_bindings(
            &target_backend,
            target_directory.path().join("snapshots"),
            identity(1),
            expected_members(),
            expected_member_bindings(),
            target_admission,
        )
        .await
        .expect("snapshot target storage");
        let exact_readback_completed = Arc::new(AtomicBool::new(false));
        target.require_membership_observation_after_readback_for_test(Arc::clone(
            &exact_readback_completed,
        ));
        append_and_commit(
            &mut target_log,
            [source_membership, source_snapshot_membership],
            "replicate distinguishable snapshot membership history",
        )
        .await;
        let mut receiving = target
            .begin_receiving_snapshot()
            .await
            .expect("target receive snapshot");
        built
            .snapshot
            .rewind()
            .await
            .expect("rewind source snapshot");
        tokio::io::copy(&mut built.snapshot, &mut receiving)
            .await
            .expect("copy source snapshot");

        let detach_attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed_detach_attempts = Arc::clone(&detach_attempts);
        let observed_detach_state = Arc::clone(&detach_attempts);
        let post_commit_readbacks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed_post_commit_readbacks = Arc::clone(&post_commit_readbacks);
        let observed_exact_readback_completed = Arc::clone(&exact_readback_completed);
        {
            let conn = target.core.conn.lock().await;
            conn.authorizer(Some(move |context: AuthContext<'_>| {
                if matches!(context.action, AuthAction::Detach { .. }) {
                    // The install primitive exhausts its two local cleanup
                    // attempts. The publication layer must then prove the
                    // singleton exactly before this third attempt makes the
                    // connection reusable.
                    if observed_detach_attempts.fetch_add(1, Ordering::Relaxed) < 2 {
                        Authorization::Deny
                    } else {
                        Authorization::Allow
                    }
                } else {
                    if matches!(
                        context.action,
                        AuthAction::Read {
                            table_name: "consensus_snapshot",
                            ..
                        }
                    ) && observed_detach_state.load(Ordering::Relaxed) >= 2
                    {
                        observed_post_commit_readbacks.fetch_add(1, Ordering::Relaxed);
                        observed_exact_readback_completed.store(true, Ordering::SeqCst);
                    }
                    Authorization::Allow
                }
            }));
        }
        target
            .install_snapshot(&built.meta, receiving)
            .await
            .expect("exact durable readback resolves a post-commit DETACH denial as success");
        let publication_readbacks_before_any_followup_read =
            post_commit_readbacks.load(Ordering::Relaxed);
        assert_eq!(
            target.membership_observations_for_test(),
            1,
            "the admitted state machine observes the distinguishable installed membership exactly once"
        );
        assert_eq!(
            target.membership_observations_before_readback_for_test(),
            0,
            "the membership admission cannot run before exact durable publication readback"
        );
        assert!(
            format!("{target_network:?}").contains("peer_configured: false"),
            "the real directory applied the one-member successor and suspended the predecessor engine route"
        );
        {
            let conn = target.core.conn.lock().await;
            conn.authorizer(Some(|_: AuthContext<'_>| Authorization::Allow));
            let (observed_meta, file_name, _, _) =
                consensus::read_current_snapshot_sync(&conn, target.core.storage_identity)
                    .expect("read durably installed snapshot metadata")
                    .expect("post-commit installation remains current");
            assert_eq!(
                observed_meta, built.meta,
                "exact durable readback preserves the installed membership and snapshot cut"
            );
            assert!(
                target_directory
                    .path()
                    .join("snapshots")
                    .join(&file_name)
                    .is_file(),
                "a current snapshot candidate survives a post-commit DETACH error"
            );
            let artifacts = std::fs::read_dir(target_directory.path().join("snapshots"))
                .expect("read target snapshot directory")
                .map(|entry| entry.expect("snapshot directory entry").file_name())
                .collect::<Vec<_>>();
            assert_eq!(
                vec![std::ffi::OsString::from(file_name)],
                artifacts,
                "a post-commit error leaves no incoming, raw, or promotion artifact"
            );
        }
        assert!(
            detach_attempts.load(Ordering::Relaxed) >= 3,
            "two injected cleanup denials reach publication's reusable-connection detach"
        );
        assert!(
            publication_readbacks_before_any_followup_read > 0,
            "the only membership observation follows exact durable publication readback columns"
        );
        assert!(
            target
                .get_current_snapshot()
                .await
                .expect("the reusable connection resolves the committed current candidate")
                .is_some(),
            "a post-commit DETACH denial leaves the same connection in an explicit safe reusable state"
        );
        let expected_meta = built.meta.clone();
        let target_database = target_directory.path().join("sessions.sqlite");
        drop(built);
        drop(builder);
        drop(source);
        drop(source_log);
        drop(source_backend);
        drop(target);
        drop(target_log);
        drop(target_backend);
        let reopened_backend = SqliteSessionBackend::open(&target_database)
            .expect("open genuinely fresh target backend");
        let (_, mut restarted) = open(
            &reopened_backend,
            target_directory.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("restart preserves the current installed snapshot");
        let restarted_current = restarted
            .get_current_snapshot()
            .await
            .expect("read current snapshot from genuinely fresh connection")
            .expect("fresh connection resolves the durable candidate");
        assert_eq!(
            restarted_current.meta, expected_meta,
            "fresh validation retains the exact admitted membership and candidate metadata"
        );
    }

    #[tokio::test]
    async fn raw_snapshot_copy_failure_cleans_the_exact_created_artifact() {
        let directory = tempfile::tempdir().expect("raw snapshot cleanup directory");
        let source_path = directory.path().join("source.opc");
        tokio::fs::write(&source_path, [])
            .await
            .expect("write empty source");
        let mut source = SessionSnapshotFile::open(source_path)
            .await
            .expect("open empty source");
        let raw_path = directory.path().join("install-copy-failure.sqlite");

        assert!(
            extract_snapshot_database_from_reader(&mut source, &raw_path, 1, [0_u8; 32])
                .await
                .is_err(),
            "incomplete raw copy must fail"
        );
        assert!(
            !raw_path.exists(),
            "a raw artifact created before a copy failure must be cleaned"
        );
    }

    #[tokio::test]
    async fn cancellation_immediately_after_promotion_keeps_no_final_artifact() {
        let directory = tempfile::tempdir().expect("promotion cancellation directory");
        let source_path = directory.path().join("source.opc");
        tokio::fs::write(&source_path, b"snapshot envelope")
            .await
            .expect("write source envelope");
        let temporary = directory.path().join("promote.part");
        let final_path = directory.path().join("snapshot.opc");
        let gate = Arc::new(SnapshotArtifactGate::new());
        gate.arm();
        let task_gate = Arc::clone(&gate);
        let task_final_path = final_path.clone();
        let task = tokio::spawn(async move {
            let mut source = SessionSnapshotFile::open(source_path)
                .await
                .expect("open source envelope");
            copy_and_promote_from_reader_inner(
                &mut source,
                &temporary,
                &task_final_path,
                b"snapshot envelope".len() as u64,
                Some(task_gate.as_ref()),
            )
            .await
        });

        gate.wait_started().await;
        assert!(
            final_path.is_file(),
            "the promoted name is visible at the cancellation boundary"
        );
        task.abort();
        assert!(match task.await {
            Err(error) => error.is_cancelled(),
            Ok(_) => false,
        });
        assert!(
            !final_path.exists(),
            "cancellation after rename must clean the exact promoted artifact"
        );
    }

    #[tokio::test]
    async fn promoted_verify_gate_guard_releases_and_clears_on_drop_and_panic() {
        let directory = tempfile::tempdir().expect("promoted verify gate directory");
        let snapshot_directory = directory.path().join("snapshots");
        let gate = Arc::new(SnapshotArtifactGate::new());
        gate.arm();
        {
            let _guard =
                PromotedVerifyGateGuard::install(snapshot_directory.clone(), Arc::clone(&gate));
            assert!(
                promoted_verify_gates()
                    .lock()
                    .expect("read promoted verify gate")
                    .contains_key(&snapshot_directory),
                "installed gate is visible before its successful scope exits"
            );
        }
        assert!(
            !promoted_verify_gates()
                .lock()
                .expect("read cleared promoted verify gate")
                .contains_key(&snapshot_directory),
            "successful scope exit clears its exact promoted verify gate"
        );
        gate.block_if_armed().await;

        gate.arm();
        let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard =
                PromotedVerifyGateGuard::install(snapshot_directory.clone(), Arc::clone(&gate));
            panic!("exercise promoted verify gate guard unwinding");
        }));
        assert!(panic_result.is_err(), "the guarded scope must unwind");
        assert!(
            !promoted_verify_gates()
                .lock()
                .expect("read unwound promoted verify gate")
                .contains_key(&snapshot_directory),
            "unwinding clears its exact promoted verify gate"
        );
        gate.block_if_armed().await;
    }

    #[tokio::test]
    async fn promoted_mismatch_never_unlinks_a_same_name_replacement() {
        let source_directory = tempfile::tempdir().expect("mismatch source directory");
        let source_backend =
            SqliteSessionBackend::open(source_directory.path().join("sessions.sqlite"))
                .expect("mismatch source backend");
        let (_, mut source) = open(
            &source_backend,
            source_directory.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("mismatch source storage");
        source
            .apply([initial_membership_entry()])
            .await
            .expect("mismatch source membership");
        let mut first_builder = source.get_snapshot_builder().await;
        let mut first = first_builder
            .build_snapshot()
            .await
            .expect("build first snapshot");
        source
            .apply([normal_entry(1, advance_time_command(identity(1), 1, 1))])
            .await
            .expect("advance mismatch source");
        let mut second_builder = source.get_snapshot_builder().await;
        let second = second_builder
            .build_snapshot()
            .await
            .expect("build replacement snapshot");
        let replacement_bytes = tokio::fs::read(second.snapshot.path())
            .await
            .expect("read replacement bytes");
        let replacement_path = second.snapshot.path().to_path_buf();

        let target_directory = tempfile::tempdir().expect("mismatch target directory");
        let target_snapshot_directory = target_directory.path().join("snapshots");
        let target_backend =
            SqliteSessionBackend::open(target_directory.path().join("sessions.sqlite"))
                .expect("mismatch target backend");
        let (_, mut target) = open(
            &target_backend,
            target_snapshot_directory.clone(),
            identity(1),
            expected_members(),
        )
        .await
        .expect("mismatch target storage");
        let mut receiving = target
            .begin_receiving_snapshot()
            .await
            .expect("mismatch receiving snapshot");
        first
            .snapshot
            .rewind()
            .await
            .expect("rewind first snapshot");
        tokio::io::copy(&mut first.snapshot, &mut receiving)
            .await
            .expect("copy first snapshot");

        let unrelated_directory = tempfile::tempdir().expect("unrelated target directory");
        let unrelated_snapshot_directory = unrelated_directory.path().join("snapshots");
        let unrelated_backend =
            SqliteSessionBackend::open(unrelated_directory.path().join("sessions.sqlite"))
                .expect("unrelated target backend");
        let (_, mut unrelated_target) = open(
            &unrelated_backend,
            unrelated_snapshot_directory,
            identity(1),
            expected_members(),
        )
        .await
        .expect("unrelated target storage");
        let mut unrelated_receiving = unrelated_target
            .begin_receiving_snapshot()
            .await
            .expect("unrelated receiving snapshot");
        first
            .snapshot
            .rewind()
            .await
            .expect("rewind unrelated snapshot");
        tokio::io::copy(&mut first.snapshot, &mut unrelated_receiving)
            .await
            .expect("copy unrelated snapshot");

        let gate = Arc::new(SnapshotArtifactGate::new());
        gate.arm();
        let hook_directory =
            snapshot_namespace_test_hook_directory(&target._snapshot_directory_lease);
        let _gate_guard = PromotedVerifyGateGuard::install(hook_directory, Arc::clone(&gate));
        assert!(
            tokio::time::timeout(
                Duration::from_secs(1),
                unrelated_target.install_snapshot(&first.meta, unrelated_receiving),
            )
            .await
            .expect("unrelated install must not inherit the promoted verify gate")
            .is_ok(),
            "unrelated snapshot install succeeds while the intended target is gated"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), gate.wait_started())
                .await
                .is_err(),
            "unrelated snapshot install must not signal the intended gate"
        );
        let meta = first.meta.clone();
        let install = tokio::spawn(async move { target.install_snapshot(&meta, receiving).await });
        tokio::time::timeout(Duration::from_secs(1), gate.wait_started())
            .await
            .expect("intended snapshot install must signal the targeted gate");
        let final_path = std::fs::read_dir(&target_snapshot_directory)
            .expect("read promoted snapshot directory")
            .map(|entry| entry.expect("promoted snapshot entry").path())
            .find(|path| path.extension().is_some_and(|extension| extension == "opc"))
            .expect("locate promoted snapshot");
        std::fs::rename(&replacement_path, &final_path).expect("replace promoted snapshot name");
        gate.release();
        assert!(
            install
                .await
                .expect("join mismatched snapshot install")
                .is_err(),
            "the replacement must fail promoted-content verification"
        );
        assert_eq!(
            replacement_bytes,
            tokio::fs::read(&final_path)
                .await
                .expect("same-name replacement survives mismatch cleanup"),
            "mismatch cleanup must not unlink a replacement inode"
        );
    }

    #[tokio::test]
    async fn cancelled_seal_output_removes_its_exact_unpublished_inode() {
        let directory = tempfile::tempdir().expect("snapshot seal cancellation directory");
        let output_path = directory.path().join("seal-cancelled.part");
        let task_path = output_path.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let (output, cleanup) = create_unpublished_snapshot_output(&task_path, true)
                .expect("create guarded seal output");
            started_tx.send(()).expect("signal guarded output");
            std::future::pending::<()>().await;
            drop((output, cleanup));
        });

        started_rx.await.expect("guarded output is armed");
        assert!(output_path.exists());
        task.abort();
        assert!(task
            .await
            .expect_err("seal output task is cancelled")
            .is_cancelled());
        assert!(!output_path.exists());
    }

    #[tokio::test]
    async fn in_place_seal_appends_footer_to_the_compacted_pinned_inode() {
        let _serial = in_place_seal_test_lock().lock().await;
        let directory = tempfile::tempdir().expect("in-place seal directory");
        let compacted_path = directory.path().join("vacuum.sqlite");
        let final_path = directory.path().join("snapshot.opc");
        let payload = b"validated compacted snapshot";
        let mut compacted = PinnedSqliteFile::from_new_file(
            secure_snapshot_create_file(&compacted_path).expect("create compacted inode"),
            compacted_path.clone(),
        )
        .expect("pin compacted inode");
        {
            let mut file = compacted.file().try_clone().expect("clone compacted inode");
            std::io::Write::write_all(&mut file, payload).expect("write compacted payload");
            file.sync_all().expect("sync compacted payload");
        }
        compacted = compacted
            .refresh_identity()
            .expect("refresh compacted identity");
        let inode = compacted.identity();

        let (mut snapshot, _fixed_pin, checksum, length, cleanup) =
            seal_snapshot_database_in_place(
                compacted,
                &final_path,
                false,
                SnapshotIntegrityPolicy::FsVerity,
                None,
            )
            .await
            .expect("seal compacted inode in place");
        let held = snapshot_handle_identity_pin(&snapshot, &compacted_path)
            .await
            .expect("pin sealed inode");
        assert_eq!(inode, held.identity());
        assert!(
            held.path_matches_identity(&compacted_path)
                .expect("compare sealed inode and compacted name"),
            "the seal must retain the compacted inode rather than copy it"
        );
        assert_eq!(
            u64::try_from(payload.len()).expect("payload length") + SNAPSHOT_FOOTER_BYTES,
            length
        );
        let (payload_length, observed_checksum, observed_length) =
            verify_snapshot_envelope_reader(&mut snapshot)
                .await
                .expect("verify sealed in-place envelope");
        assert_eq!(
            u64::try_from(payload.len()).expect("payload length"),
            payload_length
        );
        assert_eq!(checksum, observed_checksum);
        assert_eq!(length, observed_length);
        drop((snapshot, cleanup));
        assert!(
            !compacted_path.exists(),
            "the still-unpublished compacted inode is cleaned after the test"
        );
    }

    #[tokio::test]
    async fn cancelled_in_place_seal_removes_the_compacted_inode() {
        let _serial = in_place_seal_test_lock().lock().await;
        let directory = tempfile::tempdir().expect("in-place seal cancellation directory");
        let compacted_path = directory.path().join("vacuum.sqlite");
        let final_path = directory.path().join("snapshot.opc");
        let mut compacted = PinnedSqliteFile::from_new_file(
            secure_snapshot_create_file(&compacted_path).expect("create compacted inode"),
            compacted_path.clone(),
        )
        .expect("pin compacted inode");
        {
            let mut file = compacted.file().try_clone().expect("clone compacted inode");
            std::io::Write::write_all(&mut file, b"validated compacted snapshot")
                .expect("write compacted payload");
            file.sync_all().expect("sync compacted payload");
        }
        compacted = compacted
            .refresh_identity()
            .expect("refresh compacted identity");

        let gate = Arc::new(SnapshotArtifactGate::new());
        gate.arm();
        *seal_in_place_gate().lock().expect("set in-place seal gate") = Some(Arc::clone(&gate));
        let seal = tokio::spawn(async move {
            seal_snapshot_database_in_place(
                compacted,
                &final_path,
                false,
                SnapshotIntegrityPolicy::FsVerity,
                None,
            )
            .await
        });
        gate.wait_started().await;
        seal.abort();
        assert!(matches!(seal.await, Err(error) if error.is_cancelled()));
        *seal_in_place_gate()
            .lock()
            .expect("clear in-place seal gate") = None;
        assert!(
            !compacted_path.exists(),
            "cancellation after cleanup arming must unlink the compacted inode"
        );
    }

    fn identity(configuration_byte: u8) -> SessionConsensusIdentity {
        SessionConsensusIdentity::new(
            SessionConsensusClusterId::new("storage-tests").expect("cluster identity"),
            SessionConsensusConfigurationId::from_bytes([configuration_byte; 32]),
            SessionConsensusConfigurationEpoch::new(1).expect("configuration epoch"),
        )
    }

    fn node_id() -> SessionConsensusNodeId {
        SessionConsensusNodeId::new(7).expect("node ID")
    }

    fn expected_members() -> BTreeSet<SessionConsensusNodeId> {
        BTreeSet::from([node_id()])
    }

    fn expected_member_bindings() -> BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>
    {
        expected_members()
            .into_iter()
            .map(|node| {
                let mut descriptor = [0x11; 32];
                descriptor[..8].copy_from_slice(&node.get().to_be_bytes());
                let mut endpoint = [0x22; 32];
                endpoint[..8].copy_from_slice(&node.get().to_be_bytes());
                let mut tls = [0x33; 32];
                tls[..8].copy_from_slice(&node.get().to_be_bytes());
                let mut backing = [0x44; 32];
                backing[..8].copy_from_slice(&node.get().to_be_bytes());
                (
                    node,
                    SessionTopologyMemberBinding::new(descriptor, endpoint, tls, backing),
                )
            })
            .collect()
    }

    fn fixed_raw_read_members() -> BTreeSet<SessionConsensusNodeId> {
        BTreeSet::from([
            SessionConsensusNodeId::new(7).expect("fixed node ID"),
            SessionConsensusNodeId::new(8).expect("fixed node ID"),
            SessionConsensusNodeId::new(9).expect("fixed node ID"),
        ])
    }

    fn fixed_raw_read_bindings(
        members: &BTreeSet<SessionConsensusNodeId>,
    ) -> BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding> {
        members
            .iter()
            .copied()
            .map(|node| {
                let mut descriptor = [0x11; 32];
                descriptor[..8].copy_from_slice(&node.get().to_be_bytes());
                let mut endpoint = [0x22; 32];
                endpoint[..8].copy_from_slice(&node.get().to_be_bytes());
                let mut tls = [0x33; 32];
                tls[..8].copy_from_slice(&node.get().to_be_bytes());
                let mut backing = [0x44; 32];
                backing[..8].copy_from_slice(&node.get().to_be_bytes());
                (
                    node,
                    SessionTopologyMemberBinding::new(descriptor, endpoint, tls, backing),
                )
            })
            .collect()
    }

    /// Test hooks follow the retained directory descriptor rather than the
    /// configured spelling. Fixed publication derives every child through
    /// this namespace, so its `/proc/self/fd` parent is the hook key.
    fn snapshot_namespace_test_hook_directory(lease: &SnapshotDirectoryLease) -> PathBuf {
        lease
            .namespace
            .sqlite_child_path(std::ffi::OsStr::new("snapshot-test-hook"))
            .expect("derive retained snapshot namespace test-hook path")
            .parent()
            .expect("retained snapshot namespace test-hook path has a parent")
            .to_path_buf()
    }

    /// Owns the separate native SQLite and fs-verity snapshot roots used by
    /// every fixed-profile raw-store fixture. The two roots must outlive the
    /// store together so cancellation and panic still clean both namespaces.
    struct FixedRawReadStoreFixture {
        database: tempfile::TempDir,
        snapshots: tempfile::TempDir,
    }

    impl FixedRawReadStoreFixture {
        fn new() -> Self {
            Self {
                database: tempfile::Builder::new()
                    .prefix("fixed-raw-read-database-")
                    .tempdir()
                    .expect("create fixed raw-read database directory"),
                snapshots: fs_verity_snapshot_tempdir("fixed-raw-read-snapshots-"),
            }
        }

        fn snapshot_path(&self) -> &Path {
            self.snapshots.path()
        }
    }

    impl std::ops::Deref for FixedRawReadStoreFixture {
        type Target = tempfile::TempDir;

        fn deref(&self) -> &Self::Target {
            &self.database
        }
    }

    fn fs_verity_snapshot_tempdir(prefix: &str) -> tempfile::TempDir {
        const QUALIFICATION_ENV: &str = "OPC_FS_VERITY_QUALIFICATION";
        const SNAPSHOT_ROOT_ENV: &str = "OPC_FS_VERITY_SNAPSHOT_ROOT";

        let qualification_required = std::env::var_os(QUALIFICATION_ENV).as_deref()
            == Some(std::ffi::OsStr::new("required"));
        match std::env::var_os(SNAPSHOT_ROOT_ENV) {
            Some(root) => {
                let root = PathBuf::from(root);
                assert!(
                    root.is_absolute(),
                    "{SNAPSHOT_ROOT_ENV} must be an absolute fs-verity snapshot root"
                );
                tempfile::Builder::new()
                    .prefix(prefix)
                    .tempdir_in(root)
                    .expect("create fs-verity snapshot fixture directory")
            }
            None if qualification_required => {
                panic!("required fs-verity qualification requires {SNAPSHOT_ROOT_ENV}")
            }
            None => tempfile::Builder::new()
                .prefix(prefix)
                .tempdir()
                .expect("create local snapshot fixture directory"),
        }
    }

    async fn open_fixed_raw_read_store(
        directory: &FixedRawReadStoreFixture,
    ) -> (
        SqliteConsensusLogStore,
        SqliteConsensusStateMachine,
        PathBuf,
    ) {
        open_fixed_raw_read_store_with_diagnostics(directory, None).await
    }

    async fn open_fixed_raw_read_store_with_diagnostics(
        directory: &FixedRawReadStoreFixture,
        diagnostics: Option<Arc<ConsensusStoreDiagnosticCounters>>,
    ) -> (
        SqliteConsensusLogStore,
        SqliteConsensusStateMachine,
        PathBuf,
    ) {
        open_fixed_raw_read_store_with_integrity(
            directory,
            diagnostics,
            SnapshotIntegrityPolicy::FsVerity,
        )
        .await
    }

    async fn open_fixed_raw_read_store_with_integrity(
        directory: &FixedRawReadStoreFixture,
        diagnostics: Option<Arc<ConsensusStoreDiagnosticCounters>>,
        snapshot_integrity: SnapshotIntegrityPolicy,
    ) -> (
        SqliteConsensusLogStore,
        SqliteConsensusStateMachine,
        PathBuf,
    ) {
        let database = directory.path().join("fixed-raw-read.sqlite");
        let backend = SqliteSessionBackend::open(&database).expect("fixed raw-read backend");
        let backend = match diagnostics {
            Some(diagnostics) => backend.with_consensus_diagnostics(diagnostics),
            None => backend,
        };
        let members = fixed_raw_read_members();
        let mut core = SqliteConsensusCore::initialize(
            &backend,
            directory.snapshot_path().join("fixed-raw-read-snapshots"),
            identity(1),
            members.clone(),
            fixed_raw_read_bindings(&members),
            ConsensusAuthorityProfile::FixedImmutable,
            Some(PlacementResiliencePolicy::AllowReducedResilience),
        )
        .await
        .expect("open exact fixed raw-read store");
        core.snapshot_integrity = snapshot_integrity;
        let snapshot_directory_lease =
            acquire_snapshot_directory_lease(&backend, core.snapshot_dir.as_ref())
                .await
                .expect("acquire fixed raw-read snapshot directory lease");
        (
            SqliteConsensusLogStore {
                core: core.clone(),
                _snapshot_directory_lease: Arc::clone(&snapshot_directory_lease),
                shutdown_guard: ConsensusStorageShutdownGuard::detached(),
            },
            SqliteConsensusStateMachine {
                core,
                _snapshot_directory_lease: snapshot_directory_lease,
                membership_admission: None,
                membership_observations: Arc::new(AtomicUsize::new(0)),
                membership_observation_readback_witness: None,
                membership_observations_before_readback: Arc::new(AtomicUsize::new(0)),
                shutdown_guard: ConsensusStorageShutdownGuard::detached(),
            },
            database,
        )
    }

    #[cfg(target_os = "linux")]
    async fn append_apply_fixed_prune_backlog(
        log_store: &mut SqliteConsensusLogStore,
        state_machine: &mut SqliteConsensusStateMachine,
    ) {
        let mut entries = Vec::with_capacity(130);
        entries.push(fixed_initial_membership_entry());
        entries.extend((1..=129).map(blank_entry));
        log_store
            .blocking_append(entries.clone())
            .await
            .expect("append fixed prune backlog through the storage adapter");
        log_store
            .save_committed(Some(log_id(129)))
            .await
            .expect("commit fixed prune backlog through the storage adapter");
        state_machine
            .apply(entries)
            .await
            .expect("apply fixed prune backlog through the storage adapter");
    }

    #[cfg(target_os = "linux")]
    async fn prepare_fixed_prune_backlog(
        log_store: &mut SqliteConsensusLogStore,
        state_machine: &mut SqliteConsensusStateMachine,
    ) {
        append_apply_fixed_prune_backlog(log_store, state_machine).await;
        log_store
            .purge(log_id(129))
            .await
            .expect("durably record the fixed logical purge floor");
    }

    #[cfg(target_os = "linux")]
    async fn prepare_dormant_fixed_prune_backlog(directory: &FixedRawReadStoreFixture) {
        let (mut log_store, mut state_machine, _) = open_fixed_raw_read_store(directory).await;
        let lane = state_machine
            .core
            .consensus_log_prune_lane()
            .expect("fixed store installs one physical prune lane");
        append_apply_fixed_prune_backlog(&mut log_store, &mut state_machine).await;
        lane.shutdown().await;
        log_store
            .purge(log_id(129))
            .await
            .expect("durably record a dormant fixed logical purge floor");
        let mut snapshot_builder = state_machine.get_snapshot_builder().await;
        let snapshot = snapshot_builder
            .build_snapshot()
            .await
            .expect("build fixed snapshot coverage after dormant logical purge");
        drop(snapshot);
    }

    #[cfg(target_os = "linux")]
    async fn prepare_dormant_fixed_prune_backlog_with_next_log(
        directory: &FixedRawReadStoreFixture,
    ) {
        let (mut log_store, mut state_machine, _) = open_fixed_raw_read_store(directory).await;
        let lane = state_machine
            .core
            .consensus_log_prune_lane()
            .expect("fixed store installs one physical prune lane");
        append_apply_fixed_prune_backlog(&mut log_store, &mut state_machine).await;
        lane.shutdown().await;
        log_store
            .purge(log_id(129))
            .await
            .expect("durably record a dormant fixed logical purge floor");
        let mut snapshot_builder = state_machine.get_snapshot_builder().await;
        let snapshot = snapshot_builder
            .build_snapshot()
            .await
            .expect("build fixed snapshot coverage after dormant logical purge");
        drop(snapshot);
        log_store
            .blocking_append([blank_entry(130)])
            .await
            .expect("durably append the next unapplied fixed log");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pristine_fixed_store_prune_recovery_never_takes_sqlite_writer() {
        let directory = FixedRawReadStoreFixture::new();
        let gate = consensus::ConsensusLogPruneTurnGateForTest::install_after_writer_acquired(
            directory.path(),
        );
        let diagnostics = Arc::new(ConsensusStoreDiagnosticCounters::default());
        let (mut log_store, state_machine, _) =
            open_fixed_raw_read_store_with_diagnostics(&directory, Some(Arc::clone(&diagnostics)))
                .await;
        let lane = state_machine
            .core
            .consensus_log_prune_lane()
            .expect("fixed store installs one physical prune lane");

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if diagnostics.snapshot().consensus_log_prune_completed_turns == 1 {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("startup prune recovery completes its read-only preflight");
        let snapshot = diagnostics.snapshot();
        assert_eq!(snapshot.consensus_log_prune_attempts, 1);
        assert_eq!(snapshot.consensus_log_prune_busy_retries, 0);
        assert!(
            !gate.wait_until_entered(Duration::from_millis(10)),
            "a pristine startup prune preflight must not take SQLite's writer transaction"
        );

        log_store
            .blocking_append([fixed_initial_membership_entry()])
            .await
            .expect("the first fixed-store append succeeds after read-only prune recovery");
        assert!(
            !gate.wait_until_entered(Duration::from_millis(10)),
            "the first append cannot race a needless startup prune writer"
        );
        lane.shutdown().await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fixed_prune_yields_writer_to_later_adapter_append_and_resumes() {
        let directory = FixedRawReadStoreFixture::new();
        prepare_dormant_fixed_prune_backlog(&directory).await;
        // The gate is captured when the reopened lane starts. Its startup turn
        // now has eligible physical work, so this one-shot gate cannot be
        // consumed by an earlier empty turn.
        let gate = consensus::ConsensusLogPruneTurnGateForTest::install_after_writer_acquired(
            directory.path(),
        );
        let diagnostics = Arc::new(ConsensusStoreDiagnosticCounters::default());
        let (mut log_store, state_machine, _) =
            open_fixed_raw_read_store_with_diagnostics(&directory, Some(Arc::clone(&diagnostics)))
                .await;
        let lane = state_machine
            .core
            .consensus_log_prune_lane()
            .expect("fixed store installs one physical prune lane");
        assert!(
            gate.wait_until_entered(Duration::from_secs(1)),
            "the prune turn owns SQLite's writer before the primary adapter append arrives"
        );

        let append =
            tokio::spawn(async move { log_store.blocking_append([blank_entry(130)]).await });
        tokio::time::timeout(Duration::from_secs(1), async {
            while !gate.preemption_requested() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("later primary append publishes deterministic prune preemption");
        tokio::time::timeout(Duration::from_secs(1), append)
            .await
            .expect("preempted prune returns its local writer turn")
            .expect("join later primary adapter append")
            .expect("later primary adapter append succeeds without SQLITE_BUSY");

        if tokio::time::timeout(Duration::from_secs(1), gate.wait_until_completed())
            .await
            .is_err()
        {
            panic!(
                "preempted prune did not resume and complete its durable logical backlog; diagnostics={:?}",
                diagnostics.snapshot()
            );
        }
        let conn = state_machine.core.conn.lock().await;
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM consensus_log WHERE log_index <= 129",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("count fixed prune backlog"),
            0,
            "the completed physical prune drains the durable logical backlog"
        );
        drop(conn);
        lane.shutdown().await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fixed_prune_preempts_for_state_machine_apply_without_applied_lag() {
        let directory = FixedRawReadStoreFixture::new();
        prepare_dormant_fixed_prune_backlog_with_next_log(&directory).await;
        let gate = consensus::ConsensusLogPruneTurnGateForTest::install_after_writer_acquired(
            directory.path(),
        );
        let diagnostics = Arc::new(ConsensusStoreDiagnosticCounters::default());
        let (mut log_store, mut state_machine, _) =
            open_fixed_raw_read_store_with_diagnostics(&directory, Some(Arc::clone(&diagnostics)))
                .await;
        let lane = state_machine
            .core
            .consensus_log_prune_lane()
            .expect("fixed store installs one physical prune lane");
        let checkpoint_lane = state_machine
            .core
            .proactive_checkpoint_lane()
            .expect("file-backed store installs one proactive checkpoint lane");
        assert!(
            gate.wait_until_entered(Duration::from_secs(1)),
            "the prune turn owns SQLite's writer before the state-machine apply arrives"
        );
        let reader = consensus::open_snapshot_read_connection(
            state_machine
                .core
                .database_file
                .as_deref()
                .expect("file-backed store retains its snapshot source"),
        )
        .expect("open deferred snapshot reader");
        let reader_cut =
            consensus::begin_snapshot_read_sync(&reader, state_machine.core.storage_identity)
                .expect("pin snapshot reader before the next state-machine apply");
        assert_eq!(
            reader_cut.0,
            Some(log_id(129)),
            "the pinned reader observes the durable applied cut before the next log"
        );
        assert_eq!(
            state_machine
                .applied_state()
                .await
                .expect("read durable applied state before the apply")
                .0,
            Some(log_id(129)),
            "the next durable log is intentionally one ahead of applied"
        );

        let apply = tokio::spawn(async move {
            let result = state_machine.apply([blank_entry(130)]).await;
            (state_machine, result)
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while !gate.preemption_requested() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("state-machine apply publishes deterministic prune preemption");
        assert!(
            gate.preemption_requested(),
            "the active physical prune observes the state-machine writer's preemption"
        );
        let (mut state_machine, responses) = tokio::time::timeout(Duration::from_secs(1), apply)
            .await
            .expect("preempted prune returns its writer turn to the state-machine apply")
            .expect("join state-machine apply");
        responses.expect("state-machine apply succeeds without SQLITE_BUSY");
        assert_eq!(
            state_machine
                .applied_state()
                .await
                .expect("read durable applied state after the apply")
                .0,
            Some(log_id(130)),
            "the real state-machine apply advances durable applied exactly once"
        );
        assert_eq!(
            log_store
                .get_log_state()
                .await
                .expect("storage remains usable after the preempted apply")
                .last_log_id,
            Some(log_id(130)),
            "the durable log and applied state converge at the next entry"
        );

        // The state-machine apply accounts for the first durable-write signal;
        // the remaining fixed cadence signals schedule one observed PASSIVE
        // checkpoint while the reader still pins its pre-apply WAL cut.
        for _ in 1..64 {
            checkpoint_lane.signal();
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if diagnostics.snapshot().proactive_checkpoint_busy == 1 {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("reader-pinned PASSIVE checkpoint reports incomplete progress");
        consensus::release_snapshot_read_sync(&reader).expect("release deferred snapshot reader");
        for _ in 0..64 {
            checkpoint_lane.signal();
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if diagnostics.snapshot().proactive_checkpoint_completed == 1 {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("PASSIVE checkpoint drains after the deferred reader releases");

        gate.release();
        tokio::time::timeout(Duration::from_secs(1), gate.wait_until_completed())
            .await
            .expect("preempted prune resumes and drains after the state-machine apply");
        let conn = state_machine.core.conn.lock().await;
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM consensus_log WHERE log_index <= 129",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("count resumed fixed prune backlog"),
            0,
            "the resumed physical prune drains the durable logical backlog"
        );
        drop(conn);
        lane.shutdown().await;
        checkpoint_lane.shutdown().await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fixed_prune_defers_for_primary_priority_claimed_before_active_turn() {
        let directory = FixedRawReadStoreFixture::new();
        let gate = consensus::ConsensusLogPruneTurnGateForTest::install_before_active_interrupt(
            directory.path(),
        );
        let (mut log_store, mut state_machine, _) = open_fixed_raw_read_store(&directory).await;
        let lane = state_machine
            .core
            .consensus_log_prune_lane()
            .expect("fixed store installs one physical prune lane");
        prepare_fixed_prune_backlog(&mut log_store, &mut state_machine).await;
        assert!(
            gate.wait_until_entered(Duration::from_secs(1)),
            "the dequeued prune turn reaches its pre-active boundary"
        );

        let mut primary_priority = Some(
            state_machine
                .core
                .request_consensus_log_prune_preemption()
                .await,
        );
        gate.release();
        let conn = state_machine.core.conn.lock().await;
        consensus::append_logs_with_authority_and_diagnostics_sync(
            &conn,
            state_machine.core.storage_identity,
            state_machine.core.authority_profile,
            &state_machine.core.expected_members,
            &state_machine.core.expected_bindings,
            state_machine.core.fixed_placement_policy,
            &[blank_entry(130)],
            state_machine.core.diagnostics.as_deref(),
        )
        .expect("pre-active primary writer succeeds without SQLITE_BUSY");
        drop(conn);
        drop(primary_priority.take());

        tokio::time::timeout(Duration::from_secs(1), gate.wait_until_completed())
            .await
            .expect("deferred prune resumes and completes after the primary write");
        let conn = state_machine.core.conn.lock().await;
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM consensus_log WHERE log_index <= 129",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("count deferred fixed prune backlog"),
            0,
            "the logical purge remains durable while a pre-active priority claim defers pruning"
        );
        drop(conn);
        lane.shutdown().await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_primary_waiting_for_prune_turn_releases_priority() {
        let directory = FixedRawReadStoreFixture::new();
        prepare_dormant_fixed_prune_backlog(&directory).await;
        let gate = consensus::ConsensusLogPruneTurnGateForTest::install_before_authority_read(
            directory.path(),
        );
        let (_log_store, state_machine, _) = open_fixed_raw_read_store(&directory).await;
        let lane = state_machine
            .core
            .consensus_log_prune_lane()
            .expect("fixed store installs one physical prune lane");
        assert!(
            gate.wait_until_entered(Duration::from_secs(1)),
            "the gated prune turn owns its transaction permit before primary admission"
        );

        let waiting_lane = Arc::clone(&lane);
        let waiting_primary = tokio::spawn(async move {
            let _preemption = waiting_lane.request_primary_preemption().await;
            std::future::pending::<()>().await;
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if lane.primary_writers_for_test() == 1 {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("waiting primary publishes priority before cancellation");
        waiting_primary.abort();
        assert!(matches!(waiting_primary.await, Err(error) if error.is_cancelled()));
        assert_eq!(
            lane.primary_writers_for_test(),
            0,
            "cancelling while awaiting the prune permit releases primary priority"
        );

        gate.release();
        tokio::time::timeout(Duration::from_secs(1), gate.wait_until_completed())
            .await
            .expect("prune resumes after the cancelled primary releases priority");
        lane.shutdown().await;
    }

    async fn assert_fixed_raw_reads_fail_closed(
        log_store: &mut SqliteConsensusLogStore,
        state_machine: &mut SqliteConsensusStateMachine,
    ) {
        assert!(log_store.try_get_log_entries(0..0).await.is_err());
        assert!(log_store.limited_get_log_entries(0, 0).await.is_err());
        assert!(log_store.get_log_state().await.is_err());
        assert!(log_store.read_vote().await.is_err());
        assert!(log_store.read_committed().await.is_err());
        assert!(state_machine.applied_state().await.is_err());
        assert!(state_machine.get_current_snapshot().await.is_err());
    }

    fn log_id(index: u64) -> LogId<SessionConsensusNodeId> {
        log_id_with_term(1, index)
    }

    fn log_id_with_term(term: u64, index: u64) -> LogId<SessionConsensusNodeId> {
        LogId::new(CommittedLeaderId::new(term, node_id()), index)
    }

    fn timestamp(second: u8) -> Timestamp {
        Timestamp::from_str(&format!("2026-07-12T00:00:{second:02}Z")).expect("timestamp")
    }

    fn key() -> SessionKey {
        SessionKey {
            tenant: TenantId::from_static("storage-test"),
            nf_kind: NetworkFunctionKind::from_static("smf"),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"opaque-stable-id")
                .try_into()
                .expect("valid stable ID"),
        }
    }

    fn test_envelope(record: &StoredSessionRecord, opaque: &[u8]) -> Vec<u8> {
        let key_id = KeyId::new("storage-test-key").expect("key ID");
        let aad = EnvelopeAad::session(
            record.key.tenant.clone(),
            1,
            SessionAad::new(
                record.key.nf_kind.as_str(),
                "opaque-test-keyed-session-digest",
                record.state_type.as_str(),
                record.generation.get(),
                record.fence.get(),
                "storage-test-backend",
            )
            .expect("session AAD"),
        );
        let mut ciphertext_and_tag = opaque.to_vec();
        ciphertext_and_tag.extend_from_slice(&[0xA5; AEAD_TAG_LEN]);
        CryptoEnvelopeV1 {
            algorithm: AeadAlgorithm::Aes256GcmSiv,
            key_id: key_id.clone(),
            nonce: vec![0x42; AES_256_GCM_SIV_NONCE_LEN],
            aad: serialize_bound_aad(&aad, &key_id).expect("bound AAD"),
            ciphertext_and_tag,
        }
        .encode()
        .expect("test envelope")
    }

    fn acquire_command(
        identity: SessionConsensusIdentity,
        request_id: SessionConsensusRequestId,
    ) -> SessionConsensusCommand {
        SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity,
            request_id,
            logical_time: timestamp(1),
            intent: SessionMutationIntent::AcquireLease {
                key: key(),
                owner: OwnerId::new("replica-a").expect("owner"),
                ttl: Duration::from_secs(300),
            },
        }
    }

    fn normal_entry(index: u64, command: SessionConsensusCommand) -> Entry<SessionRaftTypeConfig> {
        normal_entry_with_term(1, index, command)
    }

    fn normal_entry_with_term(
        term: u64,
        index: u64,
        command: SessionConsensusCommand,
    ) -> Entry<SessionRaftTypeConfig> {
        Entry {
            log_id: log_id_with_term(term, index),
            payload: EntryPayload::Normal(command),
        }
    }

    fn sealed_cas_entry(
        index: u64,
        request_byte: u8,
        payload_bytes: usize,
    ) -> Entry<SessionRaftTypeConfig> {
        let key = key();
        let owner = OwnerId::new("replica-a").expect("owner");
        let fence = crate::model::FenceToken::new(1);
        let lease = crate::lease::LeaseGuard::new(
            key.clone(),
            owner.clone(),
            fence,
            timestamp(1),
            timestamp(59),
            1,
        );
        let mut record = StoredSessionRecord {
            key: key.clone(),
            generation: Generation::new(index),
            owner,
            fence,
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::new("bounded-log-read").expect("state type"),
            expires_at: None,
            payload: EncryptedSessionPayload::new([]),
        };
        let envelope_overhead = test_envelope(&record, &[]).len();
        let opaque_bytes = payload_bytes
            .checked_sub(envelope_overhead)
            .expect("payload length exceeds envelope overhead");
        let sealed = test_envelope(&record, &vec![request_byte; opaque_bytes]);
        assert_eq!(sealed.len(), payload_bytes);
        record.payload =
            EncryptedSessionPayload::try_envelope(sealed).expect("structurally valid envelope");
        normal_entry(
            index,
            SessionConsensusCommand {
                schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
                identity: identity(1),
                request_id: SessionConsensusRequestId::from_bytes([request_byte; 16]),
                logical_time: timestamp(request_byte),
                intent: SessionMutationIntent::CompareAndSet(Arc::new(CompareAndSet {
                    key,
                    lease,
                    expected_generation: None,
                    new_record: record,
                })),
            },
        )
    }

    fn advance_time_command(
        identity: SessionConsensusIdentity,
        request_byte: u8,
        second: u8,
    ) -> SessionConsensusCommand {
        SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity,
            request_id: SessionConsensusRequestId::from_bytes([request_byte; 16]),
            logical_time: timestamp(second),
            intent: SessionMutationIntent::AdvanceLogicalTime,
        }
    }

    fn initial_membership_entry() -> Entry<SessionRaftTypeConfig> {
        Entry {
            log_id: log_id(0),
            payload: EntryPayload::Membership(opc_consensus::engine::Membership::new(
                vec![expected_members()],
                expected_members(),
            )),
        }
    }

    async fn append_commit_and_apply<I>(
        log_store: &mut SqliteConsensusLogStore,
        state_machine: &mut SqliteConsensusStateMachine,
        entries: I,
        context: &str,
    ) where
        I: IntoIterator<Item = Entry<SessionRaftTypeConfig>>,
    {
        let entries = entries.into_iter().collect::<Vec<_>>();
        append_and_commit(log_store, entries.clone(), context).await;
        state_machine
            .apply(entries)
            .await
            .unwrap_or_else(|error| panic!("apply {context}: {error}"));
    }

    async fn append_and_commit<I>(
        log_store: &mut SqliteConsensusLogStore,
        entries: I,
        context: &str,
    ) where
        I: IntoIterator<Item = Entry<SessionRaftTypeConfig>>,
    {
        let entries = entries.into_iter().collect::<Vec<_>>();
        let committed = entries
            .last()
            .expect("honest fixture requires at least one entry")
            .log_id;
        log_store
            .blocking_append(entries)
            .await
            .unwrap_or_else(|error| panic!("append {context}: {error}"));
        log_store
            .save_committed(Some(committed))
            .await
            .unwrap_or_else(|error| panic!("commit {context}: {error}"));
    }

    fn fixed_initial_membership_entry() -> Entry<SessionRaftTypeConfig> {
        let members = fixed_raw_read_members();
        Entry {
            log_id: log_id(0),
            payload: EntryPayload::Membership(opc_consensus::engine::Membership::new(
                vec![members.clone()],
                members,
            )),
        }
    }

    #[cfg(target_os = "linux")]
    fn blank_entry(index: u64) -> Entry<SessionRaftTypeConfig> {
        Entry {
            log_id: log_id(index),
            payload: EntryPayload::Blank,
        }
    }

    fn write_sealed_snapshot_fixture(
        path: &Path,
        payload: &[u8],
        magic: &[u8; 8],
        encoded_length: u64,
        footer_checksum: [u8; 32],
    ) {
        let mut file = std::fs::File::create(path).expect("create sealed snapshot fixture");
        std::io::Write::write_all(&mut file, payload).expect("write fixture payload");
        std::io::Write::write_all(&mut file, magic).expect("write fixture magic");
        std::io::Write::write_all(&mut file, &encoded_length.to_be_bytes())
            .expect("write fixture length");
        std::io::Write::write_all(&mut file, &footer_checksum).expect("write fixture checksum");
        file.sync_all().expect("sync sealed snapshot fixture");
    }

    fn fixture_checksum(payload: &[u8]) -> [u8; 32] {
        Sha256::digest(payload).into()
    }

    fn verify_fixed_prepublication_fixture(
        path: &Path,
        expected_checksum: [u8; 32],
        expected_length: u64,
        maximum_payload: u64,
    ) -> io::Result<()> {
        let file = std::fs::File::open(path)?;
        let mut pinned = PinnedSqliteFile::from_file(file, path.to_path_buf())?;
        pinned
            .verify_snapshot_envelope_and_bind_immutable_generation(
                path,
                SNAPSHOT_FOOTER_MAGIC,
                SNAPSHOT_FOOTER_BYTES,
                maximum_payload,
                expected_checksum,
                expected_length,
            )
            .map(|_| ())
    }

    #[test]
    fn fixed_prepublication_descriptor_scan_accepts_one_valid_bounded_envelope_and_rejects_tampering(
    ) {
        let directory = fs_verity_snapshot_tempdir("fixed-prepublication-fixture-");
        let payload = b"fixed prepublication envelope";
        let checksum = fixture_checksum(payload);
        let length =
            u64::try_from(payload.len()).expect("fixture payload length") + SNAPSHOT_FOOTER_BYTES;
        let path = directory.path().join("valid.opc");
        write_sealed_snapshot_fixture(
            &path,
            payload,
            SNAPSHOT_FOOTER_MAGIC,
            u64::try_from(payload.len()).expect("fixture payload length"),
            checksum,
        );
        verify_fixed_prepublication_fixture(&path, checksum, length, 1024)
            .expect("valid descriptor-pinned envelope");

        let chunked_payload = vec![0x5a; 64 * 1024 + 19];
        let chunked_checksum = fixture_checksum(&chunked_payload);
        let chunked_length = u64::try_from(chunked_payload.len()).expect("chunked payload length")
            + SNAPSHOT_FOOTER_BYTES;
        let chunked = directory.path().join("chunked.opc");
        write_sealed_snapshot_fixture(
            &chunked,
            &chunked_payload,
            SNAPSHOT_FOOTER_MAGIC,
            u64::try_from(chunked_payload.len()).expect("chunked payload length"),
            chunked_checksum,
        );
        verify_fixed_prepublication_fixture(&chunked, chunked_checksum, chunked_length, 128 * 1024)
            .expect("chunked descriptor-pinned envelope");

        let truncated = directory.path().join("truncated.opc");
        std::fs::write(&truncated, payload).expect("write truncated fixture");
        assert!(verify_fixed_prepublication_fixture(&truncated, checksum, length, 1024).is_err());

        let oversized = directory.path().join("oversized.opc");
        write_sealed_snapshot_fixture(
            &oversized,
            payload,
            SNAPSHOT_FOOTER_MAGIC,
            u64::try_from(payload.len()).expect("fixture payload length"),
            checksum,
        );
        assert!(verify_fixed_prepublication_fixture(&oversized, checksum, length, 1).is_err());

        let bad_magic = directory.path().join("bad-magic.opc");
        write_sealed_snapshot_fixture(
            &bad_magic,
            payload,
            b"OPCBAD01",
            u64::try_from(payload.len()).expect("fixture payload length"),
            checksum,
        );
        assert!(verify_fixed_prepublication_fixture(&bad_magic, checksum, length, 1024).is_err());

        let wrong_length = directory.path().join("wrong-length.opc");
        write_sealed_snapshot_fixture(
            &wrong_length,
            payload,
            SNAPSHOT_FOOTER_MAGIC,
            u64::try_from(payload.len()).expect("fixture payload length") + 1,
            checksum,
        );
        assert!(
            verify_fixed_prepublication_fixture(&wrong_length, checksum, length, 1024).is_err()
        );

        let wrong_checksum = directory.path().join("wrong-checksum.opc");
        write_sealed_snapshot_fixture(
            &wrong_checksum,
            payload,
            SNAPSHOT_FOOTER_MAGIC,
            u64::try_from(payload.len()).expect("fixture payload length"),
            [0_u8; 32],
        );
        assert!(
            verify_fixed_prepublication_fixture(&wrong_checksum, checksum, length, 1024).is_err()
        );

        let same_inode_mutation = directory.path().join("same-inode-mutation.opc");
        write_sealed_snapshot_fixture(
            &same_inode_mutation,
            payload,
            SNAPSHOT_FOOTER_MAGIC,
            u64::try_from(payload.len()).expect("fixture payload length"),
            checksum,
        );
        {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .open(&same_inode_mutation)
                .expect("open same-inode fixture");
            std::io::Write::write_all(&mut file, b"X").expect("mutate same inode");
            file.sync_all().expect("sync same-inode mutation");
        }
        assert!(
            verify_fixed_prepublication_fixture(&same_inode_mutation, checksum, length, 1024,)
                .is_err()
        );

        let pathname_replacement = directory.path().join("pathname-replacement.opc");
        write_sealed_snapshot_fixture(
            &pathname_replacement,
            payload,
            SNAPSHOT_FOOTER_MAGIC,
            u64::try_from(payload.len()).expect("fixture payload length"),
            checksum,
        );
        let file =
            std::fs::File::open(&pathname_replacement).expect("open original pathname fixture");
        let mut pinned = PinnedSqliteFile::from_file(file, pathname_replacement.clone())
            .expect("pin pathname fixture");
        let replacement = directory.path().join("pathname-replacement-next.opc");
        write_sealed_snapshot_fixture(
            &replacement,
            payload,
            SNAPSHOT_FOOTER_MAGIC,
            u64::try_from(payload.len()).expect("fixture payload length"),
            checksum,
        );
        std::fs::rename(&replacement, &pathname_replacement).expect("replace pinned pathname");
        assert!(pinned
            .verify_snapshot_envelope_and_bind_immutable_generation(
                &pathname_replacement,
                SNAPSHOT_FOOTER_MAGIC,
                SNAPSHOT_FOOTER_BYTES,
                1024,
                checksum,
                length,
            )
            .is_err());

        let post_scan_replacement = directory.path().join("post-scan-replacement.opc");
        write_sealed_snapshot_fixture(
            &post_scan_replacement,
            payload,
            SNAPSHOT_FOOTER_MAGIC,
            u64::try_from(payload.len()).expect("fixture payload length"),
            checksum,
        );
        let mut pinned = match PinnedSqliteFile::reopen_and_seal_fixed(&post_scan_replacement) {
            Ok(pinned) => pinned,
            Err(error) if error.kind() == io::ErrorKind::Unsupported => return,
            Err(error) => panic!("seal post-scan replacement fixture: {error}"),
        };
        pinned
            .verify_snapshot_envelope_and_bind_immutable_generation(
                &post_scan_replacement,
                SNAPSHOT_FOOTER_MAGIC,
                SNAPSHOT_FOOTER_BYTES,
                1024,
                checksum,
                length,
            )
            .expect("scan sealed post-scan replacement fixture");
        let replacement = directory.path().join("post-scan-replacement-next.opc");
        write_sealed_snapshot_fixture(
            &replacement,
            payload,
            SNAPSHOT_FOOTER_MAGIC,
            u64::try_from(payload.len()).expect("fixture payload length"),
            checksum,
        );
        std::fs::rename(&replacement, &post_scan_replacement)
            .expect("replace bound post-scan pathname");
        assert!(pinned
            .verify_bound_immutable_snapshot_envelope(&post_scan_replacement, length)
            .is_err());

        let post_scan_length_change = directory.path().join("post-scan-length-change.opc");
        write_sealed_snapshot_fixture(
            &post_scan_length_change,
            payload,
            SNAPSHOT_FOOTER_MAGIC,
            u64::try_from(payload.len()).expect("fixture payload length"),
            checksum,
        );
        let mut pinned = PinnedSqliteFile::reopen_and_seal_fixed(&post_scan_length_change)
            .expect("seal post-scan length fixture");
        pinned
            .verify_snapshot_envelope_and_bind_immutable_generation(
                &post_scan_length_change,
                SNAPSHOT_FOOTER_MAGIC,
                SNAPSHOT_FOOTER_BYTES,
                1024,
                checksum,
                length,
            )
            .expect("scan sealed post-scan length fixture");
        match std::fs::OpenOptions::new()
            .write(true)
            .open(&post_scan_length_change)
        {
            Err(error) => assert_eq!(
                io::ErrorKind::PermissionDenied,
                error.kind(),
                "fs-verity rejects the writable open itself"
            ),
            Ok(file) => {
                let error = file
                    .set_len(length + 1)
                    .expect_err("sealed fixture accepted a truncate");
                assert_eq!(
                    io::ErrorKind::PermissionDenied,
                    error.kind(),
                    "fs-verity rejects truncation through an admitted writable descriptor"
                );
            }
        }
        pinned
            .verify_bound_immutable_snapshot_envelope(&post_scan_length_change, length)
            .expect("sealed fixed generation remains valid after rejected truncate");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn portable_fixed_quorum_builds_and_reads_snapshot_without_fs_verity() {
        // tmpfs deliberately has no fs-verity support, independently of the
        // separate ext4 scratch root used by strict fs-verity qualification.
        let directory = FixedRawReadStoreFixture {
            database: tempfile::Builder::new()
                .prefix("portable-fixed-database-")
                .tempdir_in("/dev/shm")
                .expect("create portable fixed database directory"),
            snapshots: tempfile::Builder::new()
                .prefix("portable-fixed-snapshots-")
                .tempdir_in("/dev/shm")
                .expect("create portable fixed snapshot directory"),
        };
        let (_, mut state_machine, _) = open_fixed_raw_read_store_with_integrity(
            &directory,
            None,
            SnapshotIntegrityPolicy::PortableVerified,
        )
        .await;
        state_machine
            .apply([fixed_initial_membership_entry()])
            .await
            .expect("apply unchanged fixed membership");
        let mut snapshot = state_machine
            .get_snapshot_builder()
            .await
            .build_snapshot()
            .await
            .expect("portable fixed quorum snapshots without filesystem sealing");
        let bytes = tokio::io::copy(&mut snapshot.snapshot, &mut tokio::io::sink())
            .await
            .expect("read verified portable snapshot");
        assert!(bytes > SNAPSHOT_FOOTER_BYTES);
        assert_eq!(
            ConsensusAuthorityProfile::FixedImmutable,
            state_machine.core.authority_profile,
            "portable snapshot verification must preserve fixed membership authority"
        );
        let current = state_machine
            .get_current_snapshot()
            .await
            .expect("reopen published portable snapshot")
            .expect("portable snapshot was durably published");
        assert_eq!(snapshot.meta, current.meta);
    }

    #[cfg(target_os = "linux")]
    fn portable_fixed_fixture() -> FixedRawReadStoreFixture {
        portable_fixed_fixture_in(std::env::temp_dir())
    }

    #[cfg(target_os = "linux")]
    fn portable_fixed_fixture_in(root: impl AsRef<Path>) -> FixedRawReadStoreFixture {
        FixedRawReadStoreFixture {
            database: tempfile::Builder::new()
                .prefix("portable-database-")
                .tempdir_in(root.as_ref())
                .expect("portable database directory"),
            snapshots: tempfile::Builder::new()
                .prefix("portable-snapshots-")
                .tempdir_in(root.as_ref())
                .expect("portable snapshot directory"),
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn portable_fixed_snapshot_installs_restarts_and_rejects_changed_generation() {
        use std::os::unix::fs::FileExt as _;
        let source_directory = portable_fixed_fixture();
        let (mut source_log, mut source, _) = open_fixed_raw_read_store_with_integrity(
            &source_directory,
            None,
            SnapshotIntegrityPolicy::PortableVerified,
        )
        .await;
        append_commit_and_apply(
            &mut source_log,
            &mut source,
            [fixed_initial_membership_entry(), blank_entry(1)],
            "portable source cut",
        )
        .await;
        let mut built = source
            .get_snapshot_builder()
            .await
            .build_snapshot()
            .await
            .expect("build portable source");
        let target_directory = portable_fixed_fixture();
        let (mut target_log, mut target, _) = open_fixed_raw_read_store_with_integrity(
            &target_directory,
            None,
            SnapshotIntegrityPolicy::PortableVerified,
        )
        .await;
        append_commit_and_apply(
            &mut target_log,
            &mut target,
            [fixed_initial_membership_entry()],
            "portable target membership",
        )
        .await;
        let mut receiver = target
            .begin_receiving_snapshot()
            .await
            .expect("portable receiver");
        tokio::io::copy(&mut built.snapshot, &mut receiver)
            .await
            .expect("verified transfer");
        target
            .install_snapshot(&built.meta, receiver)
            .await
            .expect("verified SQLite install");
        assert_eq!(
            Some(log_id(1)),
            target.applied_state().await.expect("installed cut").0
        );
        let mut current = target
            .get_current_snapshot()
            .await
            .expect("installed snapshot")
            .expect("current");
        assert_eq!(built.meta, current.meta);
        let mut expected = Vec::new();
        current
            .snapshot
            .read_to_end(&mut expected)
            .await
            .expect("installed verified bytes");
        assert!(
            current.snapshot.file().is_err(),
            "no unchecked descriptor read escape"
        );
        drop(current);
        drop(target_log);
        drop(target);
        let (_reopened_log, mut reopened, _) = open_fixed_raw_read_store_with_integrity(
            &target_directory,
            None,
            SnapshotIntegrityPolicy::PortableVerified,
        )
        .await;
        validate_and_clean_snapshot_directory(
            &reopened.core,
            Some(&reopened._snapshot_directory_lease),
        )
        .await
        .expect("portable startup validation");
        let mut restored = reopened
            .get_current_snapshot()
            .await
            .expect("restart current")
            .expect("restart snapshot");
        let mut observed = Vec::new();
        restored
            .snapshot
            .read_to_end(&mut observed)
            .await
            .expect("restart verified bytes");
        assert_eq!(expected, observed);
        assert_eq!(
            ConsensusAuthorityProfile::FixedImmutable,
            reopened.core.authority_profile
        );
        let file_name = {
            let conn = reopened.core.conn.lock().await;
            consensus::read_current_snapshot_sync(&conn, reopened.core.storage_identity)
                .expect("durable snapshot row")
                .expect("snapshot row")
                .1
        };
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .open(reopened.core.snapshot_dir.join(file_name))
            .expect("ordinary filesystem remains writable");
        writer
            .write_all_at(b"corrupt", 128)
            .expect("same-inode corruption");
        writer.sync_all().expect("sync corruption");
        restored
            .snapshot
            .rewind()
            .await
            .expect("rewind logical snapshot");
        assert!(
            tokio::io::copy(&mut restored.snapshot, &mut tokio::io::sink())
                .await
                .is_err()
        );
        assert!(
            validate_and_clean_snapshot_directory(
                &reopened.core,
                Some(&reopened._snapshot_directory_lease)
            )
            .await
            .is_err(),
            "restart cannot accept corrupt bytes against the durable checksum"
        );
        assert_eq!(
            Some(log_id(1)),
            reopened
                .applied_state()
                .await
                .expect("live state unchanged")
                .0
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn explicit_fs_verity_preflight_rejects_tmpfs_and_cleans_probe() {
        let directory = portable_fixed_fixture_in("/dev/shm");
        let backend = SqliteSessionBackend::open(directory.path().join("strict-preflight.sqlite"))
            .expect("strict probe backend");
        let lease = acquire_snapshot_directory_lease(&backend, directory.snapshot_path())
            .await
            .expect("strict probe namespace");
        assert_eq!(
            SessionConsensusStorageError::SnapshotIntegrityUnavailable,
            preflight_fs_verity(Arc::clone(&lease))
                .await
                .expect_err("tmpfs cannot seal")
        );
        assert!(
            lease
                .namespace
                .entries(32)
                .expect("read probe namespace")
                .is_empty(),
            "preflight must leave no staging artifact or permanent marker"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fixed_prepublication_seal_rejects_writes_without_blocking_primary_connection() {
        let directory = FixedRawReadStoreFixture::new();
        let (_, mut state_machine, _) = open_fixed_raw_read_store(&directory).await;
        state_machine
            .apply([fixed_initial_membership_entry()])
            .await
            .expect("apply fixed membership");

        let gate = Arc::new(SnapshotArtifactGate::new());
        gate.arm();
        let hook_directory =
            snapshot_namespace_test_hook_directory(&state_machine._snapshot_directory_lease);
        let _gate_guard =
            FixedPrepublicationVerifyGateGuard::install(hook_directory.clone(), Arc::clone(&gate));
        let observer = FixedPrepublicationScanObserver::install(hook_directory);
        let mut builder = state_machine.get_snapshot_builder().await;
        let build = tokio::spawn(async move { builder.build_snapshot().await });
        tokio::time::timeout(Duration::from_secs(5), gate.wait_started())
            .await
            .expect("fixed build reaches prepublication verification");
        let final_path = std::fs::read_dir(state_machine.core.snapshot_dir.as_ref())
            .expect("read fixed snapshot directory")
            .map(|entry| entry.expect("fixed snapshot entry").path())
            .find(|path| path.extension().is_some_and(|extension| extension == "opc"))
            .expect("find promoted fixed snapshot");
        match std::fs::OpenOptions::new().write(true).open(&final_path) {
            Err(_) => {}
            Ok(mut file) => assert!(std::io::Write::write_all(&mut file, b"X").is_err()),
        }
        let mut unrelated_primary = state_machine.clone();
        tokio::time::timeout(Duration::from_secs(5), unrelated_primary.applied_state())
            .await
            .expect("sealed prepublication gate must not hold core.conn")
            .expect("unrelated primary operation completes while publication is paused");
        gate.release();
        build
            .await
            .expect("join fixed sealed build")
            .expect("sealed fixed build publishes metadata");
        let (scan_count, scan_bytes) = observer.snapshot();
        assert_eq!(
            1, scan_count,
            "the fixed build performs exactly one prepublication descriptor scan"
        );
        assert!(
            scan_bytes > 0 && scan_bytes <= SNAPSHOT_MAX_BYTES + SNAPSHOT_FOOTER_BYTES,
            "the fixed prepublication scan remains bounded by one snapshot envelope"
        );
        let conn = state_machine.core.conn.lock().await;
        assert!(
            consensus::read_current_snapshot_sync(&conn, state_machine.core.storage_identity)
                .expect("read fixed current metadata")
                .is_some(),
            "sealed snapshot metadata publishes after the prepublication pause"
        );
        drop(conn);
        assert!(
            std::fs::read_dir(state_machine.core.snapshot_dir.as_ref())
                .expect("read cleaned fixed snapshot directory")
                .next()
                .is_some(),
            "successful fixed publication retains its sealed current artifact"
        );
    }

    #[tokio::test]
    async fn fixed_restart_rejects_a_byte_identical_unsealed_snapshot_replacement() {
        let directory = FixedRawReadStoreFixture::new();
        let (_, mut state_machine, database) = open_fixed_raw_read_store(&directory).await;
        state_machine
            .apply([fixed_initial_membership_entry()])
            .await
            .expect("apply fixed membership");
        let mut builder = state_machine.get_snapshot_builder().await;
        let built = builder
            .build_snapshot()
            .await
            .expect("build sealed fixed snapshot");
        let file_name = {
            let conn = state_machine.core.conn.lock().await;
            consensus::read_current_snapshot_sync(&conn, state_machine.core.storage_identity)
                .expect("read fixed current snapshot")
                .expect("fixed current snapshot")
                .1
        };
        let path = state_machine.core.snapshot_dir.join(file_name);
        let bytes = std::fs::read(&path).expect("read sealed snapshot bytes");
        drop(built);
        drop(builder);
        drop(state_machine);
        std::fs::remove_file(&path).expect("remove sealed snapshot");
        std::fs::write(&path, bytes).expect("replace with byte-identical unsealed snapshot");
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsFd as _;

            let unsealed = std::fs::File::open(&path).expect("open unsealed replacement");
            assert!(
                opc_fs_verity_sys::measure(unsealed.as_fd()).is_err(),
                "the simulated pre-feature snapshot must not carry fs-verity evidence"
            );
        }

        let members = fixed_raw_read_members();
        let backend = SqliteSessionBackend::open(&database).expect("reopen fixed backend");
        let reopened = match SqliteConsensusCore::initialize(
            &backend,
            directory.snapshot_path().join("fixed-raw-read-snapshots"),
            identity(1),
            members.clone(),
            fixed_raw_read_bindings(&members),
            ConsensusAuthorityProfile::FixedImmutable,
            Some(PlacementResiliencePolicy::AllowReducedResilience),
        )
        .await
        {
            Ok(core) => core,
            // Startup may reject the unsealed replacement while recovery
            // classification is still constructing the core.  That is the
            // same required fail-closed outcome as the later directory pass.
            Err(SessionConsensusStorageError::CorruptState) => return,
            Err(error) => panic!("unexpected fixed restart error: {error:?}"),
        };
        assert!(
            validate_and_clean_snapshot_directory(&reopened, None)
                .await
                .is_err(),
            "fixed restart accepts an unsealed replacement"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn legacy_fixed_reseed_reclaims_renamed_fsynced_candidate_before_retry() {
        use std::os::fd::AsFd as _;

        let directory = FixedRawReadStoreFixture::new();
        let probe_path = directory.snapshot_path().join("probe");
        let probe = std::fs::File::create(&probe_path).expect("create fs-verity probe");
        match opc_fs_verity_sys::measure(probe.as_fd()) {
            Err(opc_fs_verity_sys::Error::Measure(error))
                if error.raw_os_error() == Some(libc::ENODATA) => {}
            Err(opc_fs_verity_sys::Error::Measure(error))
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ENOTTY) | Some(libc::EOPNOTSUPP) | Some(libc::ENOSYS)
                ) =>
            {
                assert!(
                    std::env::var_os("OPC_FS_VERITY_QUALIFICATION").as_deref()
                        != Some(std::ffi::OsStr::new("required")),
                    "required fs-verity qualification is unsupported at the prepared snapshot root: {error:?}"
                );
                return;
            }
            other => panic!("unexpected fs-verity capability result: {other:?}"),
        }
        drop(probe);

        let (mut log_store, mut state_machine, database) =
            open_fixed_raw_read_store(&directory).await;
        append_commit_and_apply(
            &mut log_store,
            &mut state_machine,
            [fixed_initial_membership_entry()],
            "persist fixed membership before legacy reseed snapshot",
        )
        .await;
        let mut initial_builder = state_machine.get_snapshot_builder().await;
        let initial = initial_builder
            .build_snapshot()
            .await
            .expect("build sealed fixed predecessor");
        let old_file_name = {
            let conn = state_machine.core.conn.lock().await;
            consensus::read_current_snapshot_sync(&conn, state_machine.core.storage_identity)
                .expect("read fixed predecessor metadata")
                .expect("fixed predecessor metadata")
                .1
        };
        let snapshot_directory = state_machine.core.snapshot_dir.as_ref().clone();
        let old_path = snapshot_directory.join(&old_file_name);
        let old_bytes = std::fs::read(&old_path).expect("read sealed fixed predecessor");
        drop(initial);
        drop(initial_builder);
        drop(log_store);
        drop(state_machine);

        std::fs::remove_file(&old_path).expect("remove sealed fixed predecessor");
        std::fs::write(&old_path, b"untrusted old fixed snapshot")
            .expect("write corrupt unsealed fixed predecessor");
        assert!(matches!(
            opc_fs_verity_sys::measure(
                std::fs::File::open(&old_path)
                    .expect("open unsealed fixed predecessor")
                    .as_fd()
            ),
            Err(opc_fs_verity_sys::Error::Measure(error))
                if error.raw_os_error() == Some(libc::ENODATA)
        ));

        let connection = rusqlite::Connection::open(&database).expect("open old fixed database");
        connection
            .execute_batch(
                "CREATE TEMP TABLE legacy_recovery AS \
                 SELECT singleton, configuration_epoch, recovery_epoch, last_plan_digest, \
                        pending_epoch, pending_plan_digest, watch_cursor_invalidation_floor \
                 FROM consensus_operator_recovery; \
                 DROP TABLE consensus_operator_recovery; \
                 CREATE TABLE consensus_operator_recovery ( \
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1), \
                    configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0), \
                    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0), \
                    last_plan_digest BLOB NOT NULL CHECK (length(last_plan_digest) = 32), \
                    pending_epoch INTEGER CHECK (pending_epoch > recovery_epoch), \
                    pending_plan_digest BLOB CHECK ( \
                        pending_plan_digest IS NULL OR length(pending_plan_digest) = 32 \
                    ), \
                    watch_cursor_invalidation_floor INTEGER NOT NULL CHECK (watch_cursor_invalidation_floor >= 0), \
                    CHECK ( \
                        (pending_epoch IS NULL AND pending_plan_digest IS NULL) \
                        OR (pending_epoch IS NOT NULL AND pending_plan_digest IS NOT NULL) \
                    ), \
                    FOREIGN KEY(configuration_epoch) REFERENCES consensus_identity(configuration_epoch) \
                 ); \
                 INSERT INTO consensus_operator_recovery \
                    (singleton, configuration_epoch, recovery_epoch, last_plan_digest, \
                     pending_epoch, pending_plan_digest, watch_cursor_invalidation_floor) \
                 SELECT singleton, configuration_epoch, recovery_epoch, last_plan_digest, \
                        pending_epoch, pending_plan_digest, watch_cursor_invalidation_floor \
                 FROM legacy_recovery; \
                 DROP TABLE legacy_recovery;",
            )
            .expect("install exact released cursor-only recovery schema");
        drop(connection);

        let members = fixed_raw_read_members();
        let backend = SqliteSessionBackend::open(&database).expect("open legacy fixed backend");
        let core = SqliteConsensusCore::initialize(
            &backend,
            snapshot_directory.clone(),
            identity(1),
            members.clone(),
            fixed_raw_read_bindings(&members),
            ConsensusAuthorityProfile::FixedImmutable,
            Some(PlacementResiliencePolicy::AllowReducedResilience),
        )
        .await
        .expect("initialize exact legacy fixed source");
        let lease = acquire_snapshot_directory_lease(&backend, &snapshot_directory)
            .await
            .expect("acquire legacy fixed snapshot lease");
        let mut portable_attempt = core.clone();
        portable_attempt.snapshot_integrity = SnapshotIntegrityPolicy::PortableVerified;
        assert_eq!(
            SessionConsensusStorageError::RecoveryRequired,
            validate_and_clean_snapshot_directory(&portable_attempt, Some(&lease))
                .await
                .expect_err("finish strict reseed before changing integrity policy")
        );
        assert_eq!(
            b"untrusted old fixed snapshot",
            std::fs::read(&old_path)
                .expect("refused policy change preserves predecessor")
                .as_slice()
        );
        validate_and_clean_snapshot_directory(&core, Some(&lease))
            .await
            .expect("validate exact unsealed legacy selection");
        inject_legacy_fixed_snapshot_reseed_candidate_process_loss(
            core.snapshot_dir.as_ref().clone(),
        );
        assert!(
            reseed_legacy_fixed_snapshot_from_authoritative_database(&core, Arc::clone(&lease))
                .await
                .is_err(),
            "simulated stop interrupts after candidate rename and directory fsync"
        );
        let candidate_file_name = {
            let conn = core.conn.lock().await;
            consensus::read_legacy_fixed_snapshot_reseed_sync(&conn, core.storage_identity)
                .expect("read reseed journal after simulated stop")
                .expect("reseed journal remains after simulated stop")
                .candidate_file_name
                .expect("journal retains exact renamed candidate name")
        };
        let candidate_path = snapshot_directory.join(&candidate_file_name);
        assert!(
            candidate_path.is_file(),
            "renamed candidate survives simulated stop"
        );
        opc_fs_verity_sys::measure_exact_profile(
            std::fs::File::open(&candidate_path)
                .expect("open renamed candidate")
                .as_fd(),
        )
        .expect("renamed candidate is sealed before its metadata commit");
        drop(core);
        drop(lease);
        drop(backend);

        let backend = SqliteSessionBackend::open(&database).expect("reopen crashed fixed backend");
        let reopened = SqliteConsensusCore::initialize(
            &backend,
            snapshot_directory.clone(),
            identity(1),
            members.clone(),
            fixed_raw_read_bindings(&members),
            ConsensusAuthorityProfile::FixedImmutable,
            Some(PlacementResiliencePolicy::AllowReducedResilience),
        )
        .await
        .expect("reopen exact legacy source after candidate crash");
        let lease = acquire_snapshot_directory_lease(&backend, &snapshot_directory)
            .await
            .expect("reacquire fixed snapshot lease after candidate crash");
        validate_and_clean_snapshot_directory(&reopened, Some(&lease))
            .await
            .expect("preflight reclaims the journal-bound sealed orphan candidate");
        assert!(
            !candidate_path.exists(),
            "successful preflight reclaims the found sealed candidate"
        );
        {
            let conn = reopened.conn.lock().await;
            assert!(
                consensus::read_legacy_fixed_snapshot_reseed_sync(&conn, reopened.storage_identity)
                    .expect("read retained reseed journal after found candidate reclaim")
                    .expect("old selected source remains eligible for one retry")
                    .candidate_file_name
                    .is_none(),
                "found candidate reclaim clears only its exact reservation"
            );
        }

        // Model the other crash-recovery outcome: a previously renamed
        // candidate is already absent when a retry opens the retained
        // namespace. Reserve that exact missing name, then prove the marker
        // survives a failed directory sync before a later retry clears it.
        let absent_candidate_file_name = "snapshot-00000000-0000-4000-8000-0000000000b2.opc";
        {
            let conn = reopened.conn.lock().await;
            assert!(
                consensus::reserve_legacy_fixed_snapshot_reseed_candidate_sync(
                    &conn,
                    reopened.storage_identity,
                    absent_candidate_file_name,
                )
                .expect("reserve exact missing candidate"),
                "the completed found-candidate reclaim leaves the one-time marker retryable"
            );
        }
        fail_retained_namespace_sync_for_test(&lease.namespace);
        assert!(matches!(
            validate_and_clean_snapshot_directory(&reopened, Some(&lease)).await,
            Err(SessionConsensusStorageError::CorruptState)
        ));
        {
            let conn = reopened.conn.lock().await;
            assert_eq!(
                consensus::read_legacy_fixed_snapshot_reseed_sync(&conn, reopened.storage_identity)
                    .expect("read retained reseed journal after failed namespace sync")
                    .expect("sync failure retains exact candidate reservation")
                    .candidate_file_name
                    .as_deref(),
                Some(absent_candidate_file_name),
                "an ENOENT candidate cannot clear its reservation before directory fsync"
            );
        }
        validate_and_clean_snapshot_directory(&reopened, Some(&lease))
            .await
            .expect("preflight acknowledges absent candidate only after a durable directory sync");
        {
            let conn = reopened.conn.lock().await;
            assert!(
                consensus::read_legacy_fixed_snapshot_reseed_sync(&conn, reopened.storage_identity)
                    .expect("read retained reseed journal")
                    .expect("old selected source remains eligible for one retry")
                    .candidate_file_name
                    .is_none(),
                "preflight clears only the consumed candidate reservation"
            );
        }
        assert!(
            reseed_legacy_fixed_snapshot_from_authoritative_database(&reopened, Arc::clone(&lease))
                .await
                .expect("reseed retry succeeds"),
            "retry rebuilds the successor solely from durable DB/log state"
        );
        validate_and_clean_snapshot_directory(&reopened, Some(&lease))
            .await
            .expect("validate rebuilt sealed successor");
        let successor_name = {
            let conn = reopened.conn.lock().await;
            let current = consensus::read_current_snapshot_sync(&conn, reopened.storage_identity)
                .expect("read reseeded current snapshot")
                .expect("reseeded current snapshot");
            assert!(
                consensus::read_legacy_fixed_snapshot_reseed_sync(&conn, reopened.storage_identity)
                    .expect("read cleared reseed journal")
                    .is_none(),
                "successor metadata switch atomically drops the reseed journal"
            );
            current.1
        };
        assert_ne!(
            old_file_name, successor_name,
            "retry selects a new sealed successor"
        );
        assert!(
            !old_path.exists(),
            "old unsealed source is reclaimed after success"
        );
        assert!(
            snapshot_directory.join(successor_name).is_file(),
            "reseed retry publishes a sealed successor"
        );
        assert!(
            !old_bytes.is_empty(),
            "fixture started from a real sealed selected snapshot"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fixed_snapshot_builder_returns_the_sealed_descriptor_after_pathname_replacement() {
        use std::os::fd::AsFd as _;

        let directory = FixedRawReadStoreFixture::new();
        let (_, mut state_machine, _) = open_fixed_raw_read_store(&directory).await;
        state_machine
            .apply([fixed_initial_membership_entry()])
            .await
            .expect("apply fixed membership");

        let gate = Arc::new(SnapshotArtifactGate::new());
        gate.arm();
        let hook_directory =
            snapshot_namespace_test_hook_directory(&state_machine._snapshot_directory_lease);
        let _gate_guard = FixedSnapshotReturnGateGuard::install(hook_directory, Arc::clone(&gate));
        let mut builder = state_machine.get_snapshot_builder().await;
        let build = tokio::spawn(async move { builder.build_snapshot().await });
        tokio::time::timeout(Duration::from_secs(5), gate.wait_started())
            .await
            .expect("fixed build reaches the post-publication return gate");

        let published = std::fs::read_dir(state_machine.core.snapshot_dir.as_ref())
            .expect("read fixed snapshot directory")
            .map(|entry| entry.expect("fixed snapshot entry").path())
            .find(|path| path.extension().is_some_and(|extension| extension == "opc"))
            .expect("locate sealed fixed snapshot");
        let sealed_bytes = std::fs::read(&published).expect("read sealed fixed snapshot");
        let replacement = published.with_extension("replacement");
        std::fs::write(&replacement, &sealed_bytes)
            .expect("write byte-identical unsealed replacement");
        std::fs::rename(&replacement, &published).expect("replace published pathname");

        gate.release();
        let mut built = build
            .await
            .expect("join fixed snapshot build")
            .expect("fixed snapshot returns its sealed descriptor");

        let returned_file = built
            .snapshot
            .file()
            .expect("access returned fixed snapshot descriptor");
        assert!(
            opc_fs_verity_sys::measure(returned_file.as_fd()).is_ok(),
            "the returned snapshot must retain the measured fs-verity descriptor"
        );
        let replacement_file = std::fs::File::open(&published).expect("open pathname replacement");
        assert!(
            opc_fs_verity_sys::measure(replacement_file.as_fd()).is_err(),
            "the published pathname now names the byte-identical but unsealed replacement"
        );

        let mut returned_bytes = Vec::new();
        built
            .snapshot
            .read_to_end(&mut returned_bytes)
            .await
            .expect("read returned pinned snapshot descriptor");
        assert_eq!(
            sealed_bytes, returned_bytes,
            "the returned descriptor remains the pre-replacement sealed inode"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fixed_postpublication_return_does_not_hold_primary_connection() {
        let directory = FixedRawReadStoreFixture::new();
        let (_, mut state_machine, _) = open_fixed_raw_read_store(&directory).await;
        state_machine
            .apply([fixed_initial_membership_entry()])
            .await
            .expect("apply fixed membership");

        let gate = Arc::new(SnapshotArtifactGate::new());
        gate.arm();
        let hook_directory =
            snapshot_namespace_test_hook_directory(&state_machine._snapshot_directory_lease);
        let _gate_guard = FixedSnapshotReturnGateGuard::install(hook_directory, Arc::clone(&gate));
        let mut builder = state_machine.get_snapshot_builder().await;
        let build = tokio::spawn(async move { builder.build_snapshot().await });
        tokio::time::timeout(Duration::from_secs(5), gate.wait_started())
            .await
            .expect("fixed build reaches the post-publication return gate");

        let applied_while_held = tokio::time::timeout(
            SNAPSHOT_APPLY_WAIT,
            state_machine.apply([normal_entry(1, advance_time_command(identity(1), 1, 1))]),
        )
        .await;
        let observed_while_held = if applied_while_held.is_ok() {
            Some(tokio::time::timeout(SNAPSHOT_APPLY_WAIT, state_machine.applied_state()).await)
        } else {
            None
        };
        assert!(
            !build.is_finished(),
            "the fixed build remains held after durable metadata publication"
        );

        gate.release();
        let built = build
            .await
            .expect("join fixed post-publication build")
            .expect("fixed post-publication build succeeds after release");
        let applied = applied_while_held
            .expect("consensus write completes while fixed snapshot return is held")
            .expect("consensus write succeeds while fixed snapshot return is held");
        assert_eq!(
            1,
            applied.len(),
            "the concurrent consensus write is applied"
        );
        let (last_applied, _) = observed_while_held
            .expect("consensus read starts after the concurrent write")
            .expect("consensus read completes while fixed snapshot return is held")
            .expect("consensus read succeeds while fixed snapshot return is held");
        assert_eq!(
            Some(log_id(1)),
            last_applied,
            "the concurrent consensus read observes the completed write"
        );
        assert_eq!(
            Some(log_id(0)),
            built.meta.last_log_id,
            "post-publication primary work cannot alter the already captured snapshot cut"
        );
    }

    #[tokio::test]
    async fn fixed_snapshot_install_seals_the_extracted_database_and_envelope() {
        let source_directory = FixedRawReadStoreFixture::new();
        let (mut source_log, mut source, _) = open_fixed_raw_read_store(&source_directory).await;
        append_commit_and_apply(
            &mut source_log,
            &mut source,
            [fixed_initial_membership_entry()],
            "fixed source membership",
        )
        .await;
        let mut builder = source.get_snapshot_builder().await;
        let mut built = builder
            .build_snapshot()
            .await
            .expect("build fixed source snapshot");

        let target_directory = FixedRawReadStoreFixture::new();
        let (mut target_log, mut target, _) = open_fixed_raw_read_store(&target_directory).await;
        append_commit_and_apply(
            &mut target_log,
            &mut target,
            [fixed_initial_membership_entry()],
            "fixed target membership",
        )
        .await;
        let mut receiving = target
            .begin_receiving_snapshot()
            .await
            .expect("create fixed receiver");
        built
            .snapshot
            .seek(io::SeekFrom::Start(0))
            .await
            .expect("rewind fixed source snapshot");
        tokio::io::copy(&mut built.snapshot, &mut receiving)
            .await
            .expect("copy fixed snapshot");
        target
            .install_snapshot(&built.meta, receiving)
            .await
            .expect("install fixed sealed snapshot");
        assert!(target
            .get_current_snapshot()
            .await
            .expect("read installed fixed snapshot")
            .is_some());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn fixed_install_admits_28_physical_entries_and_rejects_29() {
        use std::os::fd::AsFd as _;

        // CI runners without fs-verity support cannot exercise the immutable
        // profile at all. Production qualification runs this exact test on a
        // verity-capable filesystem; a capability absence is not a storage
        // capacity result.
        let probe_directory = fs_verity_snapshot_tempdir("fixed-capacity-verity-probe-");
        let probe_path = probe_directory.path().join("probe");
        let probe = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&probe_path)
            .expect("create fixed capacity verity probe");
        probe.sync_all().expect("sync fixed capacity verity probe");
        drop(probe);
        // The qualification probe must model the production seal boundary:
        // fs-verity rightly rejects a live writable description with EBUSY.
        let probe = std::fs::File::open(&probe_path).expect("reopen fixed capacity probe readonly");
        if let Err(error) = opc_fs_verity_sys::enable_fixed_profile(probe.as_fd()) {
            if std::env::var_os("OPC_FS_VERITY_QUALIFICATION").as_deref()
                == Some(std::ffi::OsStr::new("required"))
            {
                panic!("required fixed capacity qualification cannot seal: {error:?}");
            }
            return;
        }

        async fn run(foreign_entries: usize) -> bool {
            let source_dir = FixedRawReadStoreFixture::new();
            let (mut source_log, mut source, _) = open_fixed_raw_read_store(&source_dir).await;
            append_commit_and_apply(
                &mut source_log,
                &mut source,
                [fixed_initial_membership_entry()],
                "fixed capacity source membership",
            )
            .await;
            let mut builder = source.get_snapshot_builder().await;
            let mut built = builder
                .build_snapshot()
                .await
                .expect("fixed capacity source snapshot");

            let target_dir = FixedRawReadStoreFixture::new();
            let (mut target_log, mut target, _) = open_fixed_raw_read_store(&target_dir).await;
            append_commit_and_apply(
                &mut target_log,
                &mut target,
                [fixed_initial_membership_entry()],
                "fixed capacity target membership",
            )
            .await;
            for index in 0..foreign_entries {
                std::fs::write(
                    target.core.snapshot_dir.join(format!("foreign-{index}")),
                    b"foreign",
                )
                .expect("fixed capacity foreign survivor");
            }
            let mut receiving = target
                .begin_receiving_snapshot()
                .await
                .expect("fixed capacity receiver");
            assert_eq!(
                foreign_entries + 1,
                std::fs::read_dir(target.core.snapshot_dir.as_ref())
                    .expect("count fixed physical entries")
                    .count()
            );
            built.snapshot.rewind().await.expect("rewind fixed source");
            tokio::io::copy(&mut built.snapshot, &mut receiving)
                .await
                .expect("stream fixed source");
            target
                .install_snapshot(&built.meta, receiving)
                .await
                .is_ok()
        }

        assert!(
            run(27).await,
            "27 survivors plus receiver is the 28-entry accepted peak"
        );
        assert!(
            !run(28).await,
            "28 survivors plus receiver exhausts fixed installation"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fixed_install_uses_one_sealed_envelope_for_publication_and_database_extraction() {
        use std::io::{Seek as _, Write as _};

        let source_directory = FixedRawReadStoreFixture::new();
        let (mut source_log, mut source, _) = open_fixed_raw_read_store(&source_directory).await;
        append_commit_and_apply(
            &mut source_log,
            &mut source,
            [fixed_initial_membership_entry()],
            "fixed source membership A",
        )
        .await;
        let mut first_builder = source.get_snapshot_builder().await;
        let mut first = first_builder
            .build_snapshot()
            .await
            .expect("build fixed source snapshot A");
        first
            .snapshot
            .rewind()
            .await
            .expect("rewind fixed source snapshot A");
        let mut envelope_a = Vec::new();
        first
            .snapshot
            .read_to_end(&mut envelope_a)
            .await
            .expect("read fixed source snapshot A");

        append_commit_and_apply(
            &mut source_log,
            &mut source,
            [blank_entry(1)],
            "fixed source snapshot B",
        )
        .await;
        let mut second_builder = source.get_snapshot_builder().await;
        let mut second = second_builder
            .build_snapshot()
            .await
            .expect("build fixed source snapshot B");
        second
            .snapshot
            .rewind()
            .await
            .expect("rewind fixed source snapshot B");
        let mut envelope_b = Vec::new();
        second
            .snapshot
            .read_to_end(&mut envelope_b)
            .await
            .expect("read fixed source snapshot B");
        assert_eq!(
            envelope_a.len(),
            envelope_b.len(),
            "the hostile writer must be able to alternate valid same-length envelopes"
        );

        let target_directory = FixedRawReadStoreFixture::new();
        let (mut target_log, mut target, _) = open_fixed_raw_read_store(&target_directory).await;
        append_commit_and_apply(
            &mut target_log,
            &mut target,
            [fixed_initial_membership_entry()],
            "fixed target membership",
        )
        .await;
        let mut receiving = target
            .begin_receiving_snapshot()
            .await
            .expect("create fixed receiver");
        receiving
            .write_all(&envelope_a)
            .await
            .expect("write valid envelope A");
        receiving.flush().await.expect("flush valid envelope A");
        let incoming_path = receiving.path().to_path_buf();
        let mut preopened_writer = std::fs::OpenOptions::new()
            .write(true)
            .open(&incoming_path)
            .expect("pre-open writable received-envelope alias");

        let gate = Arc::new(SnapshotArtifactGate::new());
        gate.arm();
        let hook_directory =
            snapshot_namespace_test_hook_directory(&target._snapshot_directory_lease);
        let _gate_guard =
            FixedInstallSourceCopyGateGuard::install(hook_directory, Arc::clone(&gate));
        let meta = first.meta.clone();
        let mut installer = target.clone();
        let install =
            tokio::spawn(async move { installer.install_snapshot(&meta, receiving).await });
        gate.wait_started().await;

        // No sleep is involved: the gate fires after the authoritative source
        // pass has completed. Replacing A with valid same-length B here makes
        // any hypothetical second source pass select B; success and the
        // assertions below therefore prove extraction and publication retain
        // the descriptor-backed A artifact from the one completed pass.
        preopened_writer
            .seek(io::SeekFrom::Start(0))
            .expect("seek pre-opened writer to B");
        preopened_writer
            .write_all(&envelope_b)
            .expect("write valid envelope B through pre-opened alias");
        preopened_writer
            .sync_all()
            .expect("sync valid envelope B through pre-opened alias");
        gate.release();
        install
            .await
            .expect("join fixed A/B install")
            .expect("one sealed A envelope installs and publishes atomically");

        let (published_meta, file_name, _, _) = {
            let conn = target.core.conn.lock().await;
            consensus::read_current_snapshot_sync(&conn, target.core.storage_identity)
                .expect("read installed fixed metadata")
                .expect("fixed install publishes a current snapshot")
        };
        assert_eq!(
            first.meta.last_log_id, published_meta.last_log_id,
            "the installed SQLite image must be the A image selected by the first sealed pass"
        );
        assert_eq!(
            envelope_a,
            std::fs::read(target.core.snapshot_dir.join(file_name))
                .expect("read published fixed A envelope"),
            "publication must retain exactly the sealed source that raw extraction used"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fixed_prepublication_descriptor_scan_does_not_block_consensus_reads_or_writes() {
        prepublication_scan_preserves_consensus_progress(SnapshotIntegrityPolicy::FsVerity).await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn portable_prepublication_descriptor_scan_does_not_block_consensus_reads_or_writes() {
        prepublication_scan_preserves_consensus_progress(SnapshotIntegrityPolicy::PortableVerified)
            .await;
    }

    async fn prepublication_scan_preserves_consensus_progress(policy: SnapshotIntegrityPolicy) {
        let directory = FixedRawReadStoreFixture::new();
        let (_, mut state_machine, _) =
            open_fixed_raw_read_store_with_integrity(&directory, None, policy).await;
        state_machine
            .apply([fixed_initial_membership_entry()])
            .await
            .expect("apply fixed membership");

        let gate = Arc::new(SnapshotArtifactGate::new());
        gate.arm();
        let hook_directory =
            snapshot_namespace_test_hook_directory(&state_machine._snapshot_directory_lease);
        let _gate_guard =
            FixedPrepublicationScanGateGuard::install(hook_directory.clone(), Arc::clone(&gate));
        let observer = FixedPrepublicationScanObserver::install(hook_directory);
        let mut builder = state_machine.get_snapshot_builder().await;
        let build = tokio::spawn(async move { builder.build_snapshot().await });
        tokio::time::timeout(Duration::from_secs(5), gate.wait_started())
            .await
            .expect("fixed build reaches its descriptor-scan gate");

        let applied = tokio::time::timeout(
            SNAPSHOT_APPLY_WAIT,
            state_machine.apply([normal_entry(1, advance_time_command(identity(1), 1, 1))]),
        )
        .await
        .expect("consensus write completes while the descriptor scan is held")
        .expect("consensus write succeeds while the descriptor scan is held");
        assert_eq!(
            1,
            applied.len(),
            "the concurrent consensus write is applied"
        );

        let (last_applied, _) =
            tokio::time::timeout(SNAPSHOT_APPLY_WAIT, state_machine.applied_state())
                .await
                .expect("consensus read completes while the descriptor scan is held")
                .expect("consensus read succeeds while the descriptor scan is held");
        assert_eq!(
            Some(log_id(1)),
            last_applied,
            "the concurrent consensus read observes the completed write"
        );
        assert!(
            !build.is_finished(),
            "publication cannot pass the deliberately held descriptor scan"
        );

        gate.release();
        let published_snapshot = build
            .await
            .expect("join fixed descriptor-scan build")
            .expect("fixed publication succeeds after the descriptor scan is released");
        let published_length = tokio::fs::metadata(published_snapshot.snapshot.path())
            .await
            .expect("read published snapshot length")
            .len();
        assert_eq!(
            (1, published_length),
            observer.snapshot(),
            "successful publication performs exactly one bounded descriptor scan"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_fixed_prepublication_scan_retains_snapshot_worker_ownership() {
        cancelled_prepublication_scan_retains_snapshot_worker(SnapshotIntegrityPolicy::FsVerity)
            .await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_portable_prepublication_scan_retains_snapshot_worker_ownership() {
        cancelled_prepublication_scan_retains_snapshot_worker(
            SnapshotIntegrityPolicy::PortableVerified,
        )
        .await;
    }

    async fn cancelled_prepublication_scan_retains_snapshot_worker(
        policy: SnapshotIntegrityPolicy,
    ) {
        let directory = FixedRawReadStoreFixture::new();
        let (_, mut state_machine, _) =
            open_fixed_raw_read_store_with_integrity(&directory, None, policy).await;
        state_machine
            .apply([fixed_initial_membership_entry()])
            .await
            .expect("apply fixed membership");

        let core = state_machine.core.clone();
        let gate = Arc::new(SnapshotArtifactGate::new());
        gate.arm();
        let hook_directory =
            snapshot_namespace_test_hook_directory(&state_machine._snapshot_directory_lease);
        let _gate_guard =
            FixedPrepublicationScanGateGuard::install(hook_directory, Arc::clone(&gate));
        let mut builder = state_machine.get_snapshot_builder().await;
        let build = tokio::spawn(async move { builder.build_snapshot().await });
        tokio::time::timeout(Duration::from_secs(5), gate.wait_started())
            .await
            .expect("fixed build reaches its descriptor-scan gate");

        build.abort();
        assert!(
            build
                .await
                .expect_err("fixed snapshot caller is cancelled")
                .is_cancelled(),
            "the fixture must cancel only the asynchronous snapshot caller"
        );
        assert!(
            Arc::clone(&core.snapshot_gate).try_lock_owned().is_err(),
            "the detached descriptor scan retains the sole snapshot owner"
        );

        gate.release();
        let worker_released = tokio::time::timeout(
            Duration::from_secs(5),
            Arc::clone(&core.snapshot_gate).lock_owned(),
        )
        .await
        .expect("cancelled descriptor scan exits within the existing bounded test window");
        drop(worker_released);
        assert!(
            std::fs::read_dir(core.snapshot_dir.as_ref())
                .expect("read cancelled fixed snapshot directory")
                .next()
                .is_none(),
            "a cancelled descriptor scan leaves no unpublished snapshot artifact"
        );
        let conn = core.conn.lock().await;
        assert!(
            consensus::read_current_snapshot_sync(&conn, core.storage_identity)
                .expect("read current snapshot after cancellation")
                .is_none(),
            "a cancelled descriptor scan cannot publish snapshot metadata"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fixed_prepublication_observer_is_directory_scoped_and_counts_one_successful_build() {
        let observed_directory = FixedRawReadStoreFixture::new();
        let (_, mut observed_state_machine, _) =
            open_fixed_raw_read_store(&observed_directory).await;
        observed_state_machine
            .apply([fixed_initial_membership_entry()])
            .await
            .expect("apply observed fixed membership");

        let unrelated_directory = FixedRawReadStoreFixture::new();
        let (_, mut unrelated_state_machine, _) =
            open_fixed_raw_read_store(&unrelated_directory).await;
        unrelated_state_machine
            .apply([fixed_initial_membership_entry()])
            .await
            .expect("apply unrelated fixed membership");

        let gate = Arc::new(SnapshotArtifactGate::new());
        gate.arm();
        let hook_directory = snapshot_namespace_test_hook_directory(
            &observed_state_machine._snapshot_directory_lease,
        );
        let _gate_guard =
            FixedPrepublicationVerifyGateGuard::install(hook_directory.clone(), Arc::clone(&gate));
        let observer = FixedPrepublicationScanObserver::install(hook_directory);
        let mut observed_builder = observed_state_machine.get_snapshot_builder().await;
        let observed_build = tokio::spawn(async move { observed_builder.build_snapshot().await });
        tokio::time::timeout(Duration::from_secs(5), gate.wait_started())
            .await
            .expect("observed build reaches its prepublication gate");

        let mut unrelated_builder = unrelated_state_machine.get_snapshot_builder().await;
        let unrelated_snapshot = unrelated_builder
            .build_snapshot()
            .await
            .expect("unrelated fixed build succeeds while observed build is gated");
        drop(unrelated_snapshot);
        let observed_length_before_publish =
            std::fs::read_dir(observed_state_machine.core.snapshot_dir.as_ref())
                .expect("read observed prepublication directory")
                .map(|entry| entry.expect("observed prepublication entry").metadata())
                .find_map(Result::ok)
                .expect("sealed observed candidate")
                .len();
        assert_eq!(
            (1, observed_length_before_publish),
            observer.snapshot(),
            "the observed sealed scan is complete before the gate; another directory is not observed"
        );

        gate.release();
        let observed_snapshot = observed_build
            .await
            .expect("join observed fixed build")
            .expect("observed fixed build succeeds");
        let observed_length = tokio::fs::metadata(observed_snapshot.snapshot.path())
            .await
            .expect("read observed fixed snapshot length")
            .len();
        assert_eq!(
            (1, observed_length),
            observer.snapshot(),
            "one successful fixed build has exactly one bounded prepublication scan"
        );
    }

    #[tokio::test]
    async fn limited_log_reads_are_nonempty_gap_free_and_byte_bounded() {
        let temp = tempfile::tempdir().expect("tempdir");
        let backend =
            SqliteSessionBackend::open(temp.path().join("sessions.sqlite")).expect("backend");
        let (mut log_store, _) = open(
            &backend,
            temp.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("consensus storage");
        let entries = [
            initial_membership_entry(),
            sealed_cas_entry(1, 11, 600 * 1024),
            sealed_cas_entry(2, 12, 600 * 1024),
            sealed_cas_entry(3, 13, crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES),
        ];
        {
            let conn = log_store.core.conn.lock().await;
            consensus::append_logs_sync(&conn, identity(1), &entries)
                .expect("append bounded-read fixtures");
        }

        let full = log_store
            .try_get_log_entries(1..4)
            .await
            .expect("full read remains unbounded by replication budget");
        assert_eq!(
            full.iter()
                .map(|entry| entry.log_id.index)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        for (start, expected) in [(1, 1), (2, 2), (3, 3)] {
            let page = log_store
                .limited_get_log_entries(start, 4)
                .await
                .expect("nonempty limited page");
            assert_eq!(
                page.iter()
                    .map(|entry| entry.log_id.index)
                    .collect::<Vec<_>>(),
                vec![expected]
            );
        }
        assert!(log_store.limited_get_log_entries(4, 5).await.is_err());
    }

    #[tokio::test]
    async fn fixed_raw_reads_reject_persisted_profile_policy_and_scope_drift() {
        for drift in [
            "UPDATE consensus_identity SET authority_profile = 1 WHERE singleton = 1",
            "UPDATE consensus_identity SET fixed_placement_policy = 1 WHERE singleton = 1",
            "UPDATE consensus_membership_scope SET application_authority_epoch = application_authority_epoch + 1 WHERE singleton = 1",
        ] {
            let directory = FixedRawReadStoreFixture::new();
            let (mut log_store, mut state_machine, database) =
                open_fixed_raw_read_store(&directory).await;
            let connection = rusqlite::Connection::open(database).expect("open fixed raw-read db");
            connection
                .execute(drift, [])
                .expect("persist fixed raw-read drift");
            drop(connection);

            assert_fixed_raw_reads_fail_closed(&mut log_store, &mut state_machine).await;
        }
    }

    #[tokio::test]
    async fn dynamic_raw_reads_do_not_require_fixed_authority() {
        let directory = tempfile::tempdir().expect("dynamic raw-read directory");
        let backend = SqliteSessionBackend::open(directory.path().join("dynamic-raw-read.sqlite"))
            .expect("dynamic raw-read backend");
        let (mut log_store, mut state_machine) = open(
            &backend,
            directory.path().join("dynamic-raw-read-snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("open dynamic raw-read store");

        assert!(log_store.try_get_log_entries(0..0).await.is_ok());
        assert!(log_store.limited_get_log_entries(0, 0).await.is_ok());
        assert!(log_store.get_log_state().await.is_ok());
        assert!(log_store.read_vote().await.is_ok());
        assert!(log_store.read_committed().await.is_ok());
        assert!(state_machine.applied_state().await.is_ok());
        assert!(state_machine.get_current_snapshot().await.is_ok());
    }

    #[tokio::test]
    async fn empty_migration_is_idempotent_and_identity_bound() {
        let temp = tempfile::tempdir().expect("tempdir");
        let database = temp.path().join("sessions.sqlite");
        let snapshots = temp.path().join("snapshots");
        let backend = SqliteSessionBackend::open(&database).expect("backend");

        let _ = open(&backend, &snapshots, identity(1), expected_members())
            .await
            .expect("first initialization");
        let cancelled_receive =
            snapshots.join("incoming-00000000-0000-4000-8000-000000000001.part");
        let interrupted_build = snapshots.join("build-00000000-0000-4000-8000-000000000002.sqlite");
        let interrupted_install_wal =
            snapshots.join("install-00000000-0000-4000-8000-000000000003.sqlite-wal");
        let interrupted_vacuum =
            snapshots.join("vacuum-00000000-0000-4000-8000-000000000004.sqlite");
        let interrupted_vacuum_wal =
            snapshots.join("vacuum-00000000-0000-4000-8000-000000000005.sqlite-wal");
        // Model process loss after the dynamic/in-memory builder has created
        // its descriptor-pinned raw sibling but before its RAII owner can
        // drop. The sibling and every SQLite sidecar deliberately use the
        // same exact UUID `vacuum-*.sqlite` staging namespace.
        let interrupted_dynamic_raw =
            snapshots.join("vacuum-00000000-0000-4000-8000-000000000006.sqlite");
        let interrupted_dynamic_raw_journal =
            snapshots.join("vacuum-00000000-0000-4000-8000-000000000007.sqlite-journal");
        let interrupted_dynamic_raw_wal =
            snapshots.join("vacuum-00000000-0000-4000-8000-000000000008.sqlite-wal");
        let interrupted_dynamic_raw_shm =
            snapshots.join("vacuum-00000000-0000-4000-8000-000000000009.sqlite-shm");
        let orphan_promoted = snapshots.join("snapshot-orphan.opc");
        tokio::fs::write(&cancelled_receive, b"partial authenticated stream")
            .await
            .expect("write cancelled receive artifact");
        tokio::fs::write(&interrupted_build, b"partial SQLite snapshot")
            .await
            .expect("write interrupted build artifact");
        tokio::fs::write(&interrupted_install_wal, b"partial SQLite WAL")
            .await
            .expect("write interrupted install WAL artifact");
        tokio::fs::write(&interrupted_vacuum, b"partial compacted SQLite snapshot")
            .await
            .expect("write interrupted vacuum artifact");
        tokio::fs::write(&interrupted_vacuum_wal, b"partial compacted SQLite WAL")
            .await
            .expect("write interrupted vacuum WAL artifact");
        tokio::fs::write(
            &interrupted_dynamic_raw,
            b"interrupted dynamic raw SQLite snapshot",
        )
        .await
        .expect("write interrupted dynamic raw artifact");
        tokio::fs::write(
            &interrupted_dynamic_raw_journal,
            b"interrupted dynamic raw SQLite journal",
        )
        .await
        .expect("write interrupted dynamic raw journal artifact");
        tokio::fs::write(
            &interrupted_dynamic_raw_wal,
            b"interrupted dynamic raw SQLite WAL",
        )
        .await
        .expect("write interrupted dynamic raw WAL artifact");
        tokio::fs::write(
            &interrupted_dynamic_raw_shm,
            b"interrupted dynamic raw SQLite SHM",
        )
        .await
        .expect("write interrupted dynamic raw SHM artifact");
        tokio::fs::write(&orphan_promoted, b"promoted before metadata commit")
            .await
            .expect("write orphan promoted artifact");
        let _ = open(&backend, &snapshots, identity(1), expected_members())
            .await
            .expect("idempotent initialization cleans interrupted staging");
        assert!(!cancelled_receive.exists());
        assert!(!interrupted_build.exists());
        assert!(!interrupted_install_wal.exists());
        assert!(!interrupted_vacuum.exists());
        assert!(!interrupted_vacuum_wal.exists());
        assert!(!interrupted_dynamic_raw.exists());
        assert!(!interrupted_dynamic_raw_journal.exists());
        assert!(!interrupted_dynamic_raw_wal.exists());
        assert!(!interrupted_dynamic_raw_shm.exists());
        assert!(
            orphan_promoted.exists(),
            "pathname-only snapshot candidates survive recovery"
        );
        let error = match open(&backend, &snapshots, identity(2), expected_members()).await {
            Ok(_) => panic!("different configuration must fail"),
            Err(error) => error,
        };
        assert_eq!(SessionConsensusStorageError::IdentityMismatch, error);
    }

    #[tokio::test]
    async fn nonempty_legacy_authority_requires_explicit_recovery() {
        let temp = tempfile::tempdir().expect("tempdir");
        let backend =
            SqliteSessionBackend::open(temp.path().join("sessions.sqlite")).expect("backend");
        backend
            .acquire(
                &key(),
                OwnerId::new("legacy-owner").expect("owner"),
                Duration::from_secs(60),
            )
            .await
            .expect("legacy lease");

        let error = match open(
            &backend,
            temp.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        {
            Ok(_) => panic!("legacy authority must not be silently adopted"),
            Err(error) => error,
        };
        assert_eq!(SessionConsensusStorageError::RecoveryRequired, error);
    }

    #[tokio::test(start_paused = true)]
    async fn covered_log_purge_wait_is_bounded_when_apply_never_arrives() {
        let temp = tempfile::tempdir().expect("tempdir");
        let backend =
            SqliteSessionBackend::open(temp.path().join("sessions.sqlite")).expect("backend");
        let (mut log_store, _) = open(
            &backend,
            temp.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("consensus storage");

        assert!(log_store.purge(log_id(1)).await.is_err());
        let conn = log_store.core.conn.lock().await;
        assert_eq!(
            None,
            consensus::read_purged_sync(&conn, identity(1)).expect("purged pointer")
        );
    }

    #[tokio::test]
    async fn covered_log_purge_waits_for_asynchronous_snapshot_apply() {
        let temp = tempfile::tempdir().expect("tempdir");
        let backend =
            SqliteSessionBackend::open(temp.path().join("sessions.sqlite")).expect("backend");
        let (mut log_store, mut state_machine) = open(
            &backend,
            temp.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("consensus storage");
        let membership = initial_membership_entry();
        let command = normal_entry(1, advance_time_command(identity(1), 16, 1));
        {
            let conn = state_machine.core.conn.lock().await;
            consensus::append_logs_sync(&conn, identity(1), &[membership.clone(), command.clone()])
                .expect("append snapshot-covered logs");
        }

        let purge = tokio::spawn(async move { log_store.purge(log_id(1)).await });
        tokio::task::yield_now().await;
        state_machine
            .apply([membership, command])
            .await
            .expect("asynchronous snapshot apply");
        purge
            .await
            .expect("purge task")
            .expect("purge succeeds after applied notification");

        let conn = state_machine.core.conn.lock().await;
        assert_eq!(
            Some(log_id(1)),
            consensus::read_purged_sync(&conn, identity(1)).expect("purged pointer")
        );
        assert_eq!(
            0_i64,
            conn.query_row("SELECT COUNT(*) FROM consensus_log", [], |row| {
                row.get::<_, i64>(0)
            })
            .expect("covered log count")
        );
    }

    #[tokio::test]
    async fn snapshot_install_publishes_applied_frontier_before_concurrent_purge() {
        let source_dir = tempfile::tempdir().expect("snapshot source directory");
        let source_backend = SqliteSessionBackend::open(source_dir.path().join("sessions.sqlite"))
            .expect("snapshot source backend");
        let (_, mut source) = open(
            &source_backend,
            source_dir.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("snapshot source storage");
        let membership = initial_membership_entry();
        let command = normal_entry(1, advance_time_command(identity(1), 16, 1));
        source
            .apply([membership.clone(), command.clone()])
            .await
            .expect("apply source snapshot cut");
        let mut built = source
            .get_snapshot_builder()
            .await
            .build_snapshot()
            .await
            .expect("build source snapshot");

        let target_dir = tempfile::tempdir().expect("snapshot target directory");
        let target_backend = SqliteSessionBackend::open(target_dir.path().join("sessions.sqlite"))
            .expect("snapshot target backend");
        let target_snapshot_dir = target_dir.path().join("snapshots");
        let (mut log_store, mut target) = open(
            &target_backend,
            target_snapshot_dir,
            identity(1),
            expected_members(),
        )
        .await
        .expect("snapshot target storage");
        {
            let conn = target.core.conn.lock().await;
            consensus::append_logs_sync(&conn, identity(1), &[membership, command])
                .expect("append target snapshot-covered logs");
        }
        let mut receiving = target
            .begin_receiving_snapshot()
            .await
            .expect("begin target snapshot receive");
        built
            .snapshot
            .rewind()
            .await
            .expect("rewind source snapshot");
        tokio::io::copy(&mut built.snapshot, &mut receiving)
            .await
            .expect("stream source snapshot");
        receiving.flush().await.expect("flush target snapshot");

        // Model OpenRaft's command ordering: its core invokes PurgeLog while
        // InstallFullSnapshot is still executing on the independent
        // state-machine worker.
        let purge = tokio::spawn(async move { log_store.purge(log_id(1)).await });
        tokio::time::timeout(Duration::from_secs(1), async {
            while target.core.applied_progress.receiver_count() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("concurrent purge subscribes before snapshot publication");
        let gate = Arc::new(SnapshotArtifactGate::new());
        gate.arm();
        let _gate_guard = SnapshotInstallAppliedProgressGateGuard::install(
            target.core.snapshot_dir.as_ref().clone(),
            Arc::clone(&gate),
        );
        let meta = built.meta.clone();
        let mut installer = target.clone();
        let install =
            tokio::spawn(async move { installer.install_snapshot(&meta, receiving).await });
        tokio::time::timeout(Duration::from_secs(5), gate.wait_started())
            .await
            .expect("snapshot install commits and publishes its applied frontier");
        assert_eq!(
            Some(log_id(1)),
            *target.core.applied_progress.borrow(),
            "the gate is reached only after the durable installed frontier is published"
        );
        let post_commit_connection =
            tokio::time::timeout(Duration::from_secs(1), target.core.conn.lock())
                .await
                .expect("post-commit snapshot work releases the publication connection");
        drop(post_commit_connection);
        gate.release();
        install
            .await
            .expect("snapshot install task")
            .expect("snapshot install succeeds");
        purge
            .await
            .expect("purge task")
            .expect("purge succeeds once the installed frontier is durable");

        let conn = target.core.conn.lock().await;
        assert_eq!(
            Some(log_id(1)),
            consensus::read_applied_sync(&conn, identity(1)).expect("installed applied frontier")
        );
        assert_eq!(
            Some(log_id(1)),
            consensus::read_purged_sync(&conn, identity(1)).expect("installed purge floor")
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn fixed_snapshot_install_publishes_applied_frontier_before_concurrent_purge() {
        let source_directory = FixedRawReadStoreFixture::new();
        let (mut source_log, mut source, _) = open_fixed_raw_read_store(&source_directory).await;
        let membership = fixed_initial_membership_entry();
        let command = blank_entry(1);
        append_commit_and_apply(
            &mut source_log,
            &mut source,
            [membership.clone(), command.clone()],
            "fixed source snapshot cut",
        )
        .await;
        let mut built = source
            .get_snapshot_builder()
            .await
            .build_snapshot()
            .await
            .expect("build fixed source snapshot");

        let target_directory = FixedRawReadStoreFixture::new();
        let (mut log_store, mut target, _) = open_fixed_raw_read_store(&target_directory).await;
        append_commit_and_apply(
            &mut log_store,
            &mut target,
            [membership],
            "fixed target predecessor",
        )
        .await;
        let mut receiving = target
            .begin_receiving_snapshot()
            .await
            .expect("begin fixed target snapshot receive");
        built
            .snapshot
            .seek(io::SeekFrom::Start(0))
            .await
            .expect("rewind fixed source snapshot");
        tokio::io::copy(&mut built.snapshot, &mut receiving)
            .await
            .expect("stream fixed source snapshot");
        receiving
            .flush()
            .await
            .expect("flush fixed target snapshot");

        // This is the OpenRaft interleaving from the production failure: its
        // core is already awaiting PurgeLog(1) while the independent
        // state-machine worker installs the snapshot that establishes applied
        // coverage for that exact LogId.
        let purge = tokio::spawn(async move { log_store.purge(log_id(1)).await });
        tokio::time::timeout(Duration::from_secs(1), async {
            while target.core.applied_progress.receiver_count() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("fixed concurrent purge subscribes before snapshot publication");
        let gate = Arc::new(SnapshotArtifactGate::new());
        gate.arm();
        let _gate_guard = SnapshotInstallAppliedProgressGateGuard::install(
            target.core.snapshot_dir.as_ref().clone(),
            Arc::clone(&gate),
        );
        let meta = built.meta.clone();
        let mut installer = target.clone();
        let install =
            tokio::spawn(async move { installer.install_snapshot(&meta, receiving).await });
        tokio::time::timeout(Duration::from_secs(5), gate.wait_started())
            .await
            .expect("fixed snapshot install commits and publishes its applied frontier");
        assert_eq!(
            Some(log_id(1)),
            *target.core.applied_progress.borrow(),
            "the fixed gate is reached only after the durable installed frontier is published"
        );
        let post_commit_connection =
            tokio::time::timeout(Duration::from_secs(1), target.core.conn.lock())
                .await
                .expect("fixed post-commit snapshot work releases the publication connection");
        drop(post_commit_connection);
        gate.release();
        tokio::time::timeout(Duration::from_secs(5), install)
            .await
            .expect("fixed snapshot install completes after the test gate")
            .expect("fixed snapshot install task")
            .expect("fixed snapshot install succeeds");
        tokio::time::timeout(Duration::from_secs(5), purge)
            .await
            .expect("fixed purge completes after the installed frontier is durable")
            .expect("fixed purge task")
            .expect("fixed purge succeeds once the installed frontier is durable");

        let conn = target.core.conn.lock().await;
        assert_eq!(
            Some(log_id(1)),
            consensus::read_applied_sync(&conn, identity(1))
                .expect("fixed installed applied frontier")
        );
        assert_eq!(
            Some(log_id(1)),
            consensus::read_purged_sync(&conn, identity(1)).expect("fixed installed purge floor")
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn recovery_sidecar_blocks_apply_only_log_purge_until_exactly_consumed() {
        // OpenRaft may call purge immediately after apply, before snapshot
        // publication. Exercise that real log-store entry point through all
        // sidecar phases: neither Active nor Pending may erase the V2 marker,
        // while an exact consumed tombstone permits the normal path again.
        let temp = tempfile::tempdir().expect("tempdir");
        let database = temp.path().join("sessions.sqlite");
        let snapshots = temp.path().join("snapshots");
        let backend = SqliteSessionBackend::open(&database).expect("backend");
        let (mut log_store, mut state_machine) =
            open(&backend, snapshots, identity(1), expected_members())
                .await
                .expect("consensus storage");
        let membership = initial_membership_entry();
        let command = normal_entry(1, advance_time_command(identity(1), 16, 1));
        {
            let conn = state_machine.core.conn.lock().await;
            consensus::append_logs_sync(&conn, identity(1), &[membership.clone(), command.clone()])
                .expect("append apply-only purge fixture");
        }
        state_machine
            .apply([membership, command])
            .await
            .expect("apply purge fixture");

        let latch = consensus::OperatorRecoveryLatch {
            identity: identity(1),
            recovery_epoch: 1,
            plan_digest: [0xA8; 32],
            audit_pending: false,
        };
        consensus::ensure_operator_recovery_latch_sync(&database, latch)
            .expect("publish active recovery sidecar");
        assert!(
            log_store.purge(log_id(1)).await.is_err(),
            "Active sidecar must block OpenRaft apply-only purge"
        );
        {
            let conn = state_machine.core.conn.lock().await;
            assert_eq!(
                None,
                consensus::read_purged_sync(&conn, identity(1)).expect("active purge floor")
            );
            consensus::mark_operator_recovery_pending_sync(&conn, identity(1), 1, [0xA8; 32])
                .expect("mark pending terminal recovery");
            assert_eq!(
                consensus::OperatorRecoveryApply::Applied,
                consensus::finalize_operator_recovery_sync(
                    &conn,
                    identity(1),
                    1,
                    [0xA8; 32],
                    consensus::observed_fence_high_water_sync(&conn)
                        .expect("terminal fence high-water"),
                    consensus::observed_credential_high_water_sync(&conn)
                        .expect("terminal credential high-water"),
                )
                .expect("finalize terminal recovery state")
            );
        }
        let database_file = std::fs::File::open(&database).expect("open terminal database");
        consensus::terminalize_operator_recovery_latch_sync(&database, latch, &database_file, None)
            .expect("publish pending terminal sidecar");
        drop(database_file);
        assert!(
            log_store.purge(log_id(1)).await.is_err(),
            "PendingHandoff sidecar must block OpenRaft apply-only purge"
        );

        let consumer = log_store.live_terminal_recovery_handoff_consumer();
        consumer
            .consume()
            .await
            .expect("consume exact terminal sidecar");
        log_store
            .purge(log_id(1))
            .await
            .expect("exact consumed tombstone permits apply-only purge");
        let conn = state_machine.core.conn.lock().await;
        assert_eq!(
            Some(log_id(1)),
            consensus::read_purged_sync(&conn, identity(1)).expect("consumed purge floor")
        );
    }

    #[tokio::test]
    async fn log_is_gap_free_and_rejects_unsealed_payloads_before_persistence() {
        let temp = tempfile::tempdir().expect("tempdir");
        let backend =
            SqliteSessionBackend::open(temp.path().join("sessions.sqlite")).expect("backend");
        let (store, _) = open(
            &backend,
            temp.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("consensus storage");
        let acquire = acquire_command(identity(1), SessionConsensusRequestId::from_bytes([1; 16]));
        {
            let conn = store.core.conn.lock().await;
            consensus::append_logs_sync(
                &conn,
                identity(1),
                &[initial_membership_entry(), normal_entry(1, acquire.clone())],
            )
            .expect("initial and first application logs");
            let gap = consensus::append_logs_sync(
                &conn,
                identity(1),
                &[normal_entry(3, acquire.clone())],
            );
            assert!(gap.is_err());

            let guard = crate::lease::LeaseGuard::new(
                key(),
                OwnerId::new("replica-a").expect("owner"),
                crate::model::FenceToken::new(1),
                timestamp(1),
                timestamp(59),
                1,
            );
            let unsealed = SessionConsensusCommand {
                request_id: SessionConsensusRequestId::from_bytes([2; 16]),
                logical_time: timestamp(2),
                intent: SessionMutationIntent::CompareAndSet(Arc::new(CompareAndSet {
                    key: key(),
                    lease: guard.clone(),
                    expected_generation: None,
                    new_record: StoredSessionRecord {
                        key: key(),
                        generation: Generation::new(1),
                        owner: guard.owner().clone(),
                        fence: guard.fence(),
                        state_class: StateClass::AuthoritativeSession,
                        state_type: StateType::new("sealed-canary").expect("state type"),
                        expires_at: None,
                        payload: EncryptedSessionPayload::new(PLAINTEXT_CANARY),
                    },
                })),
                ..acquire
            };
            let rejected =
                consensus::append_logs_sync(&conn, identity(1), &[normal_entry(2, unsealed)]);
            assert!(rejected.is_err());
            assert_eq!(
                2_i64,
                conn.query_row("SELECT COUNT(*) FROM consensus_log", [], |row| row
                    .get::<_, i64>(0))
                    .expect("log count")
            );
        }
    }

    #[tokio::test]
    async fn committed_application_replays_outcome_and_persists_only_sealed_bytes() {
        let temp = tempfile::tempdir().expect("tempdir");
        let database = temp.path().join("sessions.sqlite");
        let backend = SqliteSessionBackend::open(&database).expect("backend");
        let (_, mut state_machine) = open(
            &backend,
            temp.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("consensus storage");
        let acquire = acquire_command(identity(1), SessionConsensusRequestId::from_bytes([3; 16]));
        state_machine
            .apply([initial_membership_entry()])
            .await
            .expect("apply initial entry");
        let response = state_machine
            .apply([normal_entry(1, acquire.clone())])
            .await
            .expect("apply acquire")
            .remove(0);
        let SessionMutationOutcome::Lease(guard) = response.result.expect("lease outcome") else {
            panic!("expected lease outcome");
        };
        let first_digest = acquire
            .calculate_applied_digest(1, SessionConsensusEntryDigest::GENESIS, timestamp(1))
            .expect("digest");
        assert_eq!(
            (1, first_digest, Some(timestamp(1))),
            state_machine
                .proposal_state()
                .await
                .expect("proposal state")
        );

        let opaque = b"opaque-envelope-with-key-id-preserved-byte-for-byte";
        let record_template = StoredSessionRecord {
            key: key(),
            generation: Generation::new(1),
            owner: guard.owner().clone(),
            fence: guard.fence(),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::new("sealed-canary").expect("state type"),
            expires_at: None,
            payload: EncryptedSessionPayload::new([]),
        };
        let sealed_bytes = test_envelope(&record_template, opaque);
        let cas = SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: identity(1),
            request_id: SessionConsensusRequestId::from_bytes([4; 16]),
            logical_time: timestamp(2),
            intent: SessionMutationIntent::CompareAndSet(Arc::new(CompareAndSet {
                key: key(),
                lease: guard.clone(),
                expected_generation: None,
                new_record: StoredSessionRecord {
                    payload: EncryptedSessionPayload::try_envelope(&sealed_bytes)
                        .expect("valid envelope"),
                    ..record_template
                },
            })),
        };
        let first = state_machine
            .apply([normal_entry(2, cas.clone())])
            .await
            .expect("apply CAS")
            .remove(0);
        let replay_command = SessionConsensusCommand {
            logical_time: timestamp(3),
            ..cas
        };
        let replay = state_machine
            .apply([normal_entry(3, replay_command)])
            .await
            .expect("replay CAS after response loss and leader change")
            .remove(0);
        assert_eq!(first, replay);

        let stored = backend
            .consensus_get_at(&key(), timestamp(3))
            .await
            .expect("read")
            .expect("stored record");
        assert_eq!(sealed_bytes.as_slice(), stored.payload.as_bytes());
        let conn = state_machine.core.conn.lock().await;
        assert_eq!(
            2_i64,
            conn.query_row("SELECT COUNT(*) FROM session_replication_log", [], |row| {
                row.get::<_, i64>(0)
            })
            .expect("replication count")
        );
        for table_and_column in [
            ("consensus_request_outcomes", "response_json"),
            ("session_replication_log", "entry_json"),
        ] {
            let sql = format!(
                "SELECT CAST({1} AS BLOB) FROM {0}",
                table_and_column.0, table_and_column.1
            );
            let mut statement = conn.prepare(&sql).expect("statement");
            let rows = statement
                .query_map([], |row| row.get::<_, Vec<u8>>(0))
                .expect("rows");
            for row in rows {
                let bytes = row.expect("row");
                assert!(!bytes
                    .windows(PLAINTEXT_CANARY.len())
                    .any(|window| window == PLAINTEXT_CANARY));
            }
        }
    }

    #[tokio::test]
    async fn divergent_uncommitted_tails_are_replaceable_but_committed_prefix_is_immutable() {
        let temp = tempfile::tempdir().expect("tempdir");
        let backend =
            SqliteSessionBackend::open(temp.path().join("sessions.sqlite")).expect("backend");
        let (_, mut state_machine) = open(
            &backend,
            temp.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("consensus storage");

        let membership = initial_membership_entry();
        let committed_command = advance_time_command(identity(1), 11, 1);
        let committed_digest = committed_command
            .calculate_applied_digest(1, SessionConsensusEntryDigest::GENESIS, timestamp(1))
            .expect("committed digest");
        let committed = normal_entry(1, committed_command);
        let first_tail = normal_entry(2, advance_time_command(identity(1), 12, 2));
        {
            let conn = state_machine.core.conn.lock().await;
            consensus::append_logs_sync(
                &conn,
                identity(1),
                &[membership.clone(), committed.clone(), first_tail],
            )
            .expect("append committed prefix and first uncommitted tail");
        }
        state_machine
            .apply([membership, committed.clone()])
            .await
            .expect("apply proven committed prefix");
        {
            let conn = state_machine.core.conn.lock().await;
            consensus::save_committed_sync(&conn, identity(1), Some(committed.log_id))
                .expect("persist committed proof");

            assert!(consensus::truncate_logs_sync(&conn, identity(1), &committed.log_id).is_err());
            assert_eq!(
                3_i64,
                conn.query_row("SELECT COUNT(*) FROM consensus_log", [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("log count after rejected committed truncation")
            );

            consensus::truncate_logs_sync(&conn, identity(1), &log_id(2))
                .expect("truncate only the uncommitted tail");
            let second_tail =
                normal_entry_with_term(2, 2, advance_time_command(identity(1), 13, 3));
            consensus::append_logs_sync(&conn, identity(1), std::slice::from_ref(&second_tail))
                .expect("append second branch at the same index");

            consensus::truncate_logs_sync(&conn, identity(1), &second_tail.log_id)
                .expect("replace a second uncommitted branch");
            let third_tail = normal_entry_with_term(3, 2, advance_time_command(identity(1), 14, 4));
            consensus::append_logs_sync(&conn, identity(1), std::slice::from_ref(&third_tail))
                .expect("append authoritative replacement tail");

            assert_eq!(
                Some(committed.log_id),
                consensus::read_committed_sync(&conn, identity(1)).expect("committed pointer")
            );
            assert_eq!(
                Some(committed.log_id),
                consensus::read_applied_sync(&conn, identity(1)).expect("applied pointer")
            );
            let logs = consensus::read_log_range_sync(&conn, identity(1), 0, Some(3), None)
                .expect("read repaired log");
            assert_eq!(3, logs.len());
            assert_eq!(committed.log_id, logs[1].log_id);
            assert_eq!(third_tail.log_id, logs[2].log_id);
        }

        assert_eq!(
            (1, committed_digest, Some(timestamp(1))),
            state_machine
                .proposal_state()
                .await
                .expect("state-machine head")
        );
        drop(state_machine);

        let (_, reopened_state_machine) = open(
            &backend,
            temp.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("restart storage after divergent-tail replacement");
        assert_eq!(
            (1, committed_digest, Some(timestamp(1))),
            reopened_state_machine
                .proposal_state()
                .await
                .expect("restarted state-machine head")
        );
        let conn = reopened_state_machine.core.conn.lock().await;
        assert_eq!(
            Some(committed.log_id),
            consensus::read_committed_sync(&conn, identity(1)).expect("restarted commit proof")
        );
        let restarted_logs = consensus::read_log_range_sync(&conn, identity(1), 0, Some(3), None)
            .expect("restarted repaired log");
        assert_eq!(log_id_with_term(3, 2), restarted_logs[2].log_id);
    }

    #[tokio::test]
    async fn committed_apply_allocates_sequence_and_time_for_inflight_proposals() {
        let temp = tempfile::tempdir().expect("tempdir");
        let backend =
            SqliteSessionBackend::open(temp.path().join("sessions.sqlite")).expect("backend");
        let (_, mut state_machine) = open(
            &backend,
            temp.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("consensus storage");
        let mut first =
            acquire_command(identity(1), SessionConsensusRequestId::from_bytes([9; 16]));
        first.logical_time = timestamp(5);
        let second = SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: identity(1),
            request_id: SessionConsensusRequestId::from_bytes([10; 16]),
            // Simulate a later proposal built before the first command applied
            // and after the proposing clock moved backwards.
            logical_time: timestamp(1),
            intent: SessionMutationIntent::AdvanceLogicalTime,
        };

        let responses = state_machine
            .apply([
                initial_membership_entry(),
                normal_entry(1, first.clone()),
                normal_entry(2, second.clone()),
            ])
            .await
            .expect("apply concurrently prepared commands");
        assert_eq!(responses[1].sequence, 1);
        assert_eq!(responses[1].logical_time, Some(timestamp(5)));
        assert_eq!(responses[2].sequence, 2);
        assert_eq!(responses[2].logical_time, Some(timestamp(5)));

        let first_digest = first
            .calculate_applied_digest(1, SessionConsensusEntryDigest::GENESIS, timestamp(5))
            .expect("first digest");
        let second_digest = second
            .calculate_applied_digest(2, first_digest, timestamp(5))
            .expect("second digest");
        assert_eq!(
            (2, second_digest, Some(timestamp(5))),
            state_machine.proposal_state().await.expect("applied state")
        );
    }

    #[tokio::test]
    async fn snapshot_is_file_backed_checksummed_and_installs_atomically() {
        let source_dir = tempfile::tempdir().expect("source tempdir");
        let source_backend =
            SqliteSessionBackend::open(source_dir.path().join("sessions.sqlite")).expect("backend");
        let (_, mut source_sm) = open(
            &source_backend,
            source_dir.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("source storage");
        let command = acquire_command(identity(1), SessionConsensusRequestId::from_bytes([5; 16]));
        source_sm
            .apply([initial_membership_entry()])
            .await
            .expect("apply initial entry");
        source_sm
            .apply([normal_entry(1, command)])
            .await
            .expect("apply");
        let mut builder = source_sm.get_snapshot_builder().await;
        let mut snapshot = builder.build_snapshot().await.expect("build snapshot");
        let snapshot_bytes = tokio::fs::read(snapshot.snapshot.path())
            .await
            .expect("snapshot bytes");
        assert!(!snapshot_bytes
            .windows(PLAINTEXT_CANARY.len())
            .any(|window| window == PLAINTEXT_CANARY));

        let target_dir = tempfile::tempdir().expect("target tempdir");
        let target_backend =
            SqliteSessionBackend::open(target_dir.path().join("sessions.sqlite")).expect("backend");
        let (_, mut target_sm) = open(
            &target_backend,
            target_dir.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("target storage");
        let mut receiving = target_sm
            .begin_receiving_snapshot()
            .await
            .expect("receiving file");
        snapshot
            .snapshot
            .seek(io::SeekFrom::Start(0))
            .await
            .expect("rewind snapshot");
        tokio::io::copy(&mut snapshot.snapshot, &mut receiving)
            .await
            .expect("stream snapshot");
        receiving.flush().await.expect("flush receiving");
        target_sm
            .install_snapshot(&snapshot.meta, receiving)
            .await
            .expect("install snapshot");
        assert_eq!(
            source_sm.proposal_state().await.expect("source state"),
            target_sm.proposal_state().await.expect("target state")
        );
        {
            let conn = target_sm.core.conn.lock().await;
            assert_eq!(
                1_i64,
                conn.query_row("SELECT MAX(fence) FROM key_fences", [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("restored fence high-water mark")
            );
            assert_eq!(
                1_i64,
                conn.query_row("SELECT MAX(credential_id) FROM leases", [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("restored credential high-water mark")
            );
        }
        let current = target_sm
            .get_current_snapshot()
            .await
            .expect("current snapshot")
            .expect("snapshot exists");
        assert_eq!(snapshot.meta, current.meta);

        let advanced = advance_time_command(identity(1), 15, 2);
        let advanced_digest = advanced
            .calculate_applied_digest(
                2,
                source_sm
                    .proposal_state()
                    .await
                    .expect("source proposal state")
                    .1,
                timestamp(2),
            )
            .expect("advanced digest");
        let advanced_entry = normal_entry(2, advanced);
        let advanced_log_id = advanced_entry.log_id;
        {
            let conn = target_sm.core.conn.lock().await;
            consensus::append_logs_sync(&conn, identity(1), std::slice::from_ref(&advanced_entry))
                .expect("persist exact advanced log before committed floor");
        }
        target_sm
            .apply([advanced_entry])
            .await
            .expect("advance target beyond snapshot");
        {
            let conn = target_sm.core.conn.lock().await;
            consensus::save_committed_sync(&conn, identity(1), Some(advanced_log_id))
                .expect("persist newer committed floor");
        }
        let mut stale_receiving = target_sm
            .begin_receiving_snapshot()
            .await
            .expect("stale receiving file");
        snapshot
            .snapshot
            .seek(io::SeekFrom::Start(0))
            .await
            .expect("rewind stale snapshot");
        tokio::io::copy(&mut snapshot.snapshot, &mut stale_receiving)
            .await
            .expect("stream stale snapshot");
        stale_receiving.flush().await.expect("flush stale snapshot");
        assert!(target_sm
            .install_snapshot(&snapshot.meta, stale_receiving)
            .await
            .is_err());
        assert_eq!(
            (2, advanced_digest, Some(timestamp(2))),
            target_sm
                .proposal_state()
                .await
                .expect("newer target state survives stale snapshot")
        );

        let wrong_identity_dir = tempfile::tempdir().expect("wrong identity tempdir");
        let wrong_identity_backend =
            SqliteSessionBackend::open(wrong_identity_dir.path().join("sessions.sqlite"))
                .expect("wrong identity backend");
        let (_, mut wrong_identity_sm) = open(
            &wrong_identity_backend,
            wrong_identity_dir.path().join("snapshots"),
            identity(2),
            expected_members(),
        )
        .await
        .expect("wrong identity target storage");
        let mut wrong_identity_receiving = wrong_identity_sm
            .begin_receiving_snapshot()
            .await
            .expect("wrong identity receiving file");
        snapshot
            .snapshot
            .seek(io::SeekFrom::Start(0))
            .await
            .expect("rewind cross-identity snapshot");
        tokio::io::copy(&mut snapshot.snapshot, &mut wrong_identity_receiving)
            .await
            .expect("stream cross-identity snapshot");
        wrong_identity_receiving
            .flush()
            .await
            .expect("flush cross-identity snapshot");
        assert!(wrong_identity_sm
            .install_snapshot(&snapshot.meta, wrong_identity_receiving)
            .await
            .is_err());
        assert_eq!(
            (0, SessionConsensusEntryDigest::GENESIS, None),
            wrong_identity_sm
                .proposal_state()
                .await
                .expect("wrong-identity target remains pristine")
        );

        let corrupt_dir = tempfile::tempdir().expect("corrupt target tempdir");
        let corrupt_backend =
            SqliteSessionBackend::open(corrupt_dir.path().join("sessions.sqlite"))
                .expect("corrupt target backend");
        let (_, mut corrupt_target_sm) = open(
            &corrupt_backend,
            corrupt_dir.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("corrupt target storage");
        let mut corrupt_receiving = corrupt_target_sm
            .begin_receiving_snapshot()
            .await
            .expect("corrupt receiving file");
        let mut corrupted_snapshot = snapshot_bytes.clone();
        corrupted_snapshot[64] ^= 0xff;
        corrupt_receiving
            .write_all(&corrupted_snapshot)
            .await
            .expect("write corrupt snapshot");
        corrupt_receiving
            .flush()
            .await
            .expect("flush corrupt snapshot");
        assert!(corrupt_target_sm
            .install_snapshot(&snapshot.meta, corrupt_receiving)
            .await
            .is_err());
        assert_eq!(
            (0, SessionConsensusEntryDigest::GENESIS, None),
            corrupt_target_sm
                .proposal_state()
                .await
                .expect("corrupt target remains pristine")
        );

        let path = current.snapshot.path().to_path_buf();
        drop(current);
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .await
            .expect("open current snapshot");
        file.seek(io::SeekFrom::Start(64)).await.expect("seek");
        file.write_all(b"corrupt").await.expect("corrupt snapshot");
        file.sync_all().await.expect("sync corruption");
        assert!(target_sm.get_current_snapshot().await.is_err());
        drop(file);
        drop(target_sm);
        let reopen_error = match open(
            &target_backend,
            target_dir.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        {
            Ok(_) => panic!("restart must reject a corrupt current snapshot"),
            Err(error) => error,
        };
        assert_eq!(SessionConsensusStorageError::CorruptState, reopen_error);
    }

    #[tokio::test]
    async fn dynamic_install_admits_27_physical_entries_and_rejects_28() {
        async fn run(foreign_entries: usize) -> bool {
            let source_dir = tempfile::tempdir().expect("dynamic capacity source");
            let source_backend =
                SqliteSessionBackend::open(source_dir.path().join("sessions.sqlite"))
                    .expect("dynamic capacity source backend");
            let (_, mut source) = open(
                &source_backend,
                source_dir.path().join("snapshots"),
                identity(1),
                expected_members(),
            )
            .await
            .expect("dynamic capacity source store");
            source
                .apply([initial_membership_entry()])
                .await
                .expect("dynamic capacity source membership");
            let mut builder = source.get_snapshot_builder().await;
            let mut built = builder
                .build_snapshot()
                .await
                .expect("dynamic capacity source snapshot");

            let target_dir = tempfile::tempdir().expect("dynamic capacity target");
            let target_backend =
                SqliteSessionBackend::open(target_dir.path().join("sessions.sqlite"))
                    .expect("dynamic capacity target backend");
            let snapshot_dir = target_dir.path().join("snapshots");
            let (_, mut target) = open(
                &target_backend,
                snapshot_dir.clone(),
                identity(1),
                expected_members(),
            )
            .await
            .expect("dynamic capacity target store");
            for index in 0..foreign_entries {
                std::fs::write(snapshot_dir.join(format!("foreign-{index}")), b"foreign")
                    .expect("dynamic capacity foreign survivor");
            }
            let mut receiving = target
                .begin_receiving_snapshot()
                .await
                .expect("dynamic capacity receiver");
            assert_eq!(
                foreign_entries + 1,
                std::fs::read_dir(&snapshot_dir)
                    .expect("count dynamic physical entries")
                    .count()
            );
            built
                .snapshot
                .rewind()
                .await
                .expect("rewind dynamic source");
            tokio::io::copy(&mut built.snapshot, &mut receiving)
                .await
                .expect("stream dynamic source");
            target
                .install_snapshot(&built.meta, receiving)
                .await
                .is_ok()
        }

        assert!(
            run(26).await,
            "26 survivors plus receiver is the 27-entry accepted peak"
        );
        assert!(
            !run(27).await,
            "27 survivors plus receiver exhausts dynamic installation"
        );
    }

    #[tokio::test]
    async fn only_one_incoming_snapshot_receiver_is_admitted_per_core() {
        let directory = tempfile::tempdir().expect("receiver admission directory");
        let backend = SqliteSessionBackend::open(directory.path().join("sessions.sqlite"))
            .expect("receiver admission backend");
        let (_, mut state_machine) = open(
            &backend,
            directory.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("receiver admission storage");
        let receiver = state_machine
            .begin_receiving_snapshot()
            .await
            .expect("first receiver");
        assert!(state_machine.begin_receiving_snapshot().await.is_err());
        drop(receiver);
        assert!(state_machine.begin_receiving_snapshot().await.is_ok());
    }

    #[tokio::test]
    async fn snapshot_directory_capacity_rejects_a_33rd_receiver_artifact() {
        let directory = tempfile::tempdir().expect("snapshot capacity directory");
        let snapshot_directory = directory.path().join("snapshots");
        let backend = SqliteSessionBackend::open(directory.path().join("sessions.sqlite"))
            .expect("snapshot capacity backend");
        let (_, mut state_machine) = open(
            &backend,
            snapshot_directory.clone(),
            identity(1),
            expected_members(),
        )
        .await
        .expect("snapshot capacity storage");

        for index in 0..SNAPSHOT_DIRECTORY_MAX_ENTRIES {
            std::fs::write(
                snapshot_directory.join(format!("foreign-survivor-{index}")),
                b"unreclaimable survivor",
            )
            .expect("write unreclaimable snapshot survivor");
        }
        sync_directory(&snapshot_directory).expect("sync full snapshot directory");
        assert_eq!(
            SNAPSHOT_DIRECTORY_MAX_ENTRIES,
            std::fs::read_dir(&snapshot_directory)
                .expect("read full snapshot directory")
                .count(),
            "fixture begins at the configured durable survivor bound"
        );

        assert!(
            state_machine.begin_receiving_snapshot().await.is_err(),
            "a receive admission must reserve its incoming artifact before creating it"
        );
        let entries: Vec<_> = std::fs::read_dir(&snapshot_directory)
            .expect("read rejected snapshot directory")
            .map(|entry| entry.expect("read snapshot entry").file_name())
            .collect();
        assert_eq!(SNAPSHOT_DIRECTORY_MAX_ENTRIES, entries.len());
        assert!(
            entries
                .iter()
                .all(|name| !name.to_string_lossy().starts_with("incoming-")),
            "rejected admission must leave no thirty-third incoming artifact"
        );
    }

    #[tokio::test]
    async fn retained_namespace_receiver_post_create_error_cleans_exact_artifact() {
        let directory = tempfile::tempdir().expect("retained receiver create cleanup directory");
        let snapshot_directory = directory.path().join("snapshots");
        let backend = SqliteSessionBackend::open(directory.path().join("sessions.sqlite"))
            .expect("retained receiver create cleanup backend");
        let (_log, mut state_machine) = open(
            &backend,
            snapshot_directory.clone(),
            identity(1),
            expected_members(),
        )
        .await
        .expect("retained receiver create cleanup storage");
        fail_namespace_receiver_post_create_sync_for_test(
            &state_machine._snapshot_directory_lease.namespace,
        );
        assert!(
            state_machine.begin_receiving_snapshot().await.is_err(),
            "the injected post-create sync error reaches the receiver caller"
        );
        assert_eq!(
            0,
            std::fs::read_dir(&snapshot_directory)
                .expect("read retained receiver namespace")
                .count(),
            "the armed cleanup guard removes the just-created incoming artifact"
        );
        assert!(
            state_machine.begin_receiving_snapshot().await.is_ok(),
            "no stranded incoming entry or stale cleanup latch consumes capacity"
        );
    }

    #[tokio::test]
    async fn retained_namespace_receiver_preclone_failures_never_consume_capacity() {
        let directory = tempfile::tempdir().expect("retained receiver setup cleanup directory");
        let snapshot_directory = directory.path().join("snapshots");
        let backend = SqliteSessionBackend::open(directory.path().join("sessions.sqlite"))
            .expect("retained receiver setup cleanup backend");
        let (_log, mut state_machine) = open(
            &backend,
            snapshot_directory.clone(),
            identity(1),
            expected_members(),
        )
        .await
        .expect("retained receiver setup cleanup storage");

        // This is deliberately one more than the namespace admission limit.
        // The injected error fires after O_EXCL but before metadata/try_clone,
        // reproducing the descriptor-pressure boundary that previously could
        // strand `incoming-*.part` entries until the thirty-third attempt.
        for attempt in 0..=SNAPSHOT_DIRECTORY_MAX_ENTRIES {
            fail_namespace_receiver_post_create_setup_for_test(
                &state_machine._snapshot_directory_lease.namespace,
            );
            assert!(
                state_machine.begin_receiving_snapshot().await.is_err(),
                "pre-clone failure {attempt} reaches the receiver caller"
            );
            assert_eq!(
                0,
                std::fs::read_dir(&snapshot_directory)
                    .expect("read retained receiver namespace")
                    .count(),
                "pre-clone failure {attempt} leaves no stranded incoming artifact"
            );
        }
        assert!(
            state_machine.begin_receiving_snapshot().await.is_ok(),
            "repeated pre-clone failures cannot exhaust the bounded namespace"
        );
    }

    #[tokio::test]
    async fn retained_namespace_build_pre_pin_failures_never_consume_capacity() {
        let directory = tempfile::tempdir().expect("retained build setup cleanup directory");
        let snapshot_directory = directory.path().join("snapshots");
        let backend = SqliteSessionBackend::open(directory.path().join("sessions.sqlite"))
            .expect("retained build setup cleanup backend");
        let (_log, mut state_machine) = open(
            &backend,
            snapshot_directory.clone(),
            identity(1),
            expected_members(),
        )
        .await
        .expect("retained build setup cleanup storage");
        state_machine
            .apply([initial_membership_entry()])
            .await
            .expect("seed build authority");

        // The injection fires immediately after retained-dirfd O_EXCL on the
        // file-backed capture's final `build-*` child, before Pinned metadata
        // or its identity cleanup owner. Repeating beyond the capacity bound
        // proves the emergency guard owns every failed child.
        for attempt in 0..=SNAPSHOT_DIRECTORY_MAX_ENTRIES {
            fail_namespace_pinned_post_create_setup_for_test(
                &state_machine._snapshot_directory_lease.namespace,
            );
            assert!(
                state_machine
                    .get_snapshot_builder()
                    .await
                    .build_snapshot()
                    .await
                    .is_err(),
                "pre-pin build failure {attempt} reaches the caller"
            );
            assert!(
                std::fs::read_dir(&snapshot_directory)
                    .expect("read failed-build namespace")
                    .next()
                    .is_none(),
                "failed build {attempt} leaves no retained namespace child"
            );
        }
        state_machine
            .get_snapshot_builder()
            .await
            .build_snapshot()
            .await
            .expect("capacity remains available after repeated final-pin failures");
    }

    #[tokio::test]
    async fn retained_namespace_fallback_intermediate_pre_pin_failures_never_consume_capacity() {
        let directory = tempfile::tempdir().expect("fallback intermediate cleanup directory");
        let snapshot_directory = directory.path().join("snapshots");
        let backend = SqliteSessionBackend::open(directory.path().join("sessions.sqlite"))
            .expect("fallback intermediate cleanup backend");
        let (_log, state_machine) = open(
            &backend,
            snapshot_directory.clone(),
            identity(1),
            expected_members(),
        )
        .await
        .expect("fallback intermediate cleanup storage");
        let namespace = Arc::clone(&state_machine._snapshot_directory_lease.namespace);

        // This is the exact fallback precreation order: the final build pin
        // has already become identity-cleanup authority when the strict
        // `vacuum-raw-pid-sequence` intermediate fails immediately after
        // O_EXCL. Dropping the final pin then removes it too.
        for attempt in 0..=SNAPSHOT_DIRECTORY_MAX_ENTRIES {
            let final_name =
                std::ffi::OsString::from(format!("build-{}.sqlite", uuid::Uuid::new_v4()));
            let final_pin =
                PinnedSqliteFile::create_new_in_namespace(Arc::clone(&namespace), &final_name)
                    .expect("create fallback final pin");
            fail_namespace_vacuum_raw_pinned_post_create_setup_for_test(&namespace);
            assert!(
                create_vacuum_raw_snapshot_intermediate(Arc::clone(&namespace)).is_err(),
                "fallback intermediate pre-pin failure {attempt} reaches its caller"
            );
            drop(final_pin);
            assert!(
                namespace
                    .entries(SNAPSHOT_DIRECTORY_MAX_ENTRIES)
                    .expect("read failed-fallback namespace")
                    .is_empty(),
                "failed fallback intermediate {attempt} leaves no child group"
            );
        }
        let final_pin = PinnedSqliteFile::create_new_in_namespace(
            Arc::clone(&namespace),
            std::ffi::OsStr::new("build-00000000-0000-4000-8000-000000000001.sqlite"),
        )
        .expect("capacity remains for fallback final pin");
        let intermediate = create_vacuum_raw_snapshot_intermediate(Arc::clone(&namespace))
            .expect("capacity remains for strict fallback intermediate");
        drop(intermediate);
        drop(final_pin);
    }

    #[tokio::test]
    async fn snapshot_directory_recovery_rejects_33_unreclaimable_survivors() {
        let directory = tempfile::tempdir().expect("snapshot recovery capacity directory");
        let snapshot_directory = directory.path().join("snapshots");
        let database = directory.path().join("sessions.sqlite");
        let backend = SqliteSessionBackend::open(&database).expect("snapshot recovery backend");
        let (log_store, state_machine) = open(
            &backend,
            snapshot_directory.clone(),
            identity(1),
            expected_members(),
        )
        .await
        .expect("create snapshot recovery storage");
        drop(log_store);
        drop(state_machine);

        for index in 0..=SNAPSHOT_DIRECTORY_MAX_ENTRIES {
            std::fs::write(
                snapshot_directory.join(format!("foreign-survivor-{index}")),
                b"unreclaimable survivor",
            )
            .expect("write unreclaimable recovery survivor");
        }
        sync_directory(&snapshot_directory).expect("sync overflowing snapshot directory");

        let error = match open(
            &backend,
            snapshot_directory,
            identity(1),
            expected_members(),
        )
        .await
        {
            Ok(_) => panic!("restart must reject more durable snapshot survivors than capacity"),
            Err(error) => error,
        };
        assert_eq!(SessionConsensusStorageError::CorruptState, error);
    }

    #[tokio::test]
    async fn snapshot_directory_over_capacity_scan_stops_at_thirty_third_entry() {
        let directory = tempfile::tempdir().expect("bounded snapshot scan directory");
        let snapshot_directory = directory.path().join("snapshots");
        let backend = SqliteSessionBackend::open(directory.path().join("sessions.sqlite"))
            .expect("bounded snapshot scan backend");
        let (_log, mut state_machine) = open(
            &backend,
            snapshot_directory.clone(),
            identity(1),
            expected_members(),
        )
        .await
        .expect("bounded snapshot scan storage");
        for index in 0..(SNAPSHOT_DIRECTORY_MAX_ENTRIES + 64) {
            std::fs::write(
                snapshot_directory.join(format!("foreign-survivor-{index}")),
                b"unreclaimable survivor",
            )
            .expect("write overflowing snapshot survivors");
        }
        let namespace = Arc::clone(&state_machine._snapshot_directory_lease.namespace);
        let observed =
            tokio::task::spawn_blocking(move || namespace.entries(SNAPSHOT_DIRECTORY_MAX_ENTRIES))
                .await
                .expect("bounded namespace scan worker")
                .expect("bounded namespace scan");
        assert_eq!(
            SNAPSHOT_DIRECTORY_MAX_ENTRIES + 1,
            observed.len(),
            "descriptor enumeration stops immediately after the capacity proof entry"
        );
        assert!(
            state_machine.begin_receiving_snapshot().await.is_err(),
            "the same bounded pass rejects capacity before it creates an incoming artifact"
        );
    }

    #[tokio::test]
    async fn restart_reclaims_a_durably_renamed_canonical_cleanup_tombstone() {
        let directory = tempfile::tempdir().expect("crash recovery directory");
        let snapshot_directory = directory.path().join("snapshots");
        let database = directory.path().join("sessions.sqlite");
        let backend = SqliteSessionBackend::open(&database).expect("snapshot recovery backend");
        let (log_store, state_machine) = open(
            &backend,
            snapshot_directory.clone(),
            identity(1),
            expected_members(),
        )
        .await
        .expect("create snapshot storage");
        drop(log_store);
        drop(state_machine);

        // Faithful crash point: rename is already durable, but unlink has not
        // happened. The restart scanner may reclaim only this canonical name.
        let tombstone = snapshot_directory.join(
            ".incoming-00000000-0000-4000-8000-000000000001.part.opc-cleanup-00000000-0000-4000-8000-000000000002",
        );
        std::fs::write(&tombstone, b"durably renamed before simulated crash")
            .expect("write durable tombstone");
        sync_directory(&snapshot_directory).expect("durable tombstone rename");
        assert!(tombstone.exists());

        let (log_store, state_machine) = open(
            &backend,
            snapshot_directory.clone(),
            identity(1),
            expected_members(),
        )
        .await
        .expect("restart reclaims canonical tombstone");
        drop(log_store);
        drop(state_machine);
        assert!(!tombstone.exists());
        assert_eq!(
            0,
            std::fs::read_dir(&snapshot_directory)
                .expect("reclaimed directory")
                .count(),
            "reclaim restores capacity"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn restart_replays_only_an_authenticated_final_unlink_guard() {
        use std::os::linux::fs::MetadataExt as _;

        let directory = tempfile::tempdir().expect("final guard recovery directory");
        let snapshot_directory = directory.path().join("snapshots");
        let database = directory.path().join("sessions.sqlite");
        let backend = SqliteSessionBackend::open(&database).expect("final guard recovery backend");
        let (log_store, state_machine) = open(
            &backend,
            snapshot_directory.clone(),
            identity(1),
            expected_members(),
        )
        .await
        .expect("create snapshot storage");
        drop(log_store);
        drop(state_machine);

        let original = "incoming-00000000-0000-4000-8000-000000000001.part";
        let tombstone = snapshot_directory.join(format!(
            ".{original}.opc-cleanup-00000000-0000-4000-8000-000000000002"
        ));
        std::fs::write(&tombstone, b"admitted-before-final-unlink")
            .expect("write admitted tombstone");
        let metadata = std::fs::metadata(&tombstone).expect("stat admitted tombstone");
        let guard = snapshot_directory.join(format!(
            "{}.opc-unlink-guard-{:016x}-{:016x}",
            tombstone
                .file_name()
                .expect("tombstone basename")
                .to_string_lossy(),
            metadata.st_dev(),
            metadata.st_ino(),
        ));
        std::fs::rename(&tombstone, &guard).expect("simulate final guard rename");

        // This name is strict syntactically but does not authenticate the
        // inode it names. Recovery must retain it as unrelated capacity rather
        // than deleting it beside the admitted guard.
        let foreign_guard = snapshot_directory.join(format!(
            ".{original}.opc-cleanup-00000000-0000-4000-8000-000000000003.opc-unlink-guard-0000000000000000-0000000000000000"
        ));
        std::fs::write(&foreign_guard, b"foreign-unmatched-guard")
            .expect("write foreign guard lookalike");
        sync_directory(&snapshot_directory).expect("durable simulated guard state");

        let (log_store, state_machine) = open(
            &backend,
            snapshot_directory.clone(),
            identity(1),
            expected_members(),
        )
        .await
        .expect("restart replays admitted final guard");
        drop(log_store);
        drop(state_machine);
        assert!(
            !guard.exists(),
            "restart replays the one admitted final guard to completion"
        );
        assert_eq!(
            std::fs::read(&foreign_guard).expect("foreign guard survives"),
            b"foreign-unmatched-guard"
        );
    }

    #[tokio::test]
    async fn restart_reclaims_an_actual_generated_vacuum_raw_sqlite_group() {
        let directory = tempfile::tempdir().expect("vacuum raw restart directory");
        let snapshot_directory = directory.path().join("snapshots");
        let database = directory.path().join("sessions.sqlite");
        let backend = SqliteSessionBackend::open(&database).expect("vacuum raw backend");
        let (log_store, state_machine) = open(
            &backend,
            snapshot_directory.clone(),
            identity(1),
            expected_members(),
        )
        .await
        .expect("initial vacuum raw storage");
        drop(log_store);
        drop(state_machine);

        let raw = snapshot_directory.join(format!("vacuum-raw-{}-1.sqlite", std::process::id()));
        {
            let connection = rusqlite::Connection::open(&raw).expect("create real raw sqlite");
            connection
                .execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE raw_fixture (id INTEGER);")
                .expect("write real raw sqlite schema");
            connection
                .execute("INSERT INTO raw_fixture VALUES (1)", [])
                .expect("write real raw sqlite row");
        }
        assert!(raw.is_file(), "fixture is a generated SQLite main file");
        sync_directory(&snapshot_directory).expect("sync raw sqlite fixture");

        let (log_store, state_machine) = open(
            &backend,
            snapshot_directory.clone(),
            identity(1),
            expected_members(),
        )
        .await
        .expect("restart reclaims raw sqlite group");
        drop(log_store);
        drop(state_machine);
        for suffix in ["", "-journal", "-wal", "-shm"] {
            assert!(
                !snapshot_directory
                    .join(format!(
                        "vacuum-raw-{}-1.sqlite{suffix}",
                        std::process::id()
                    ))
                    .exists(),
                "restart removes exact generated raw artifact {suffix}"
            );
        }
    }

    #[tokio::test]
    async fn restart_preserves_foreign_cleanup_tombstone_lookalike_and_counts_it() {
        let directory = tempfile::tempdir().expect("lookalike recovery directory");
        let snapshot_directory = directory.path().join("snapshots");
        let database = directory.path().join("sessions.sqlite");
        let backend = SqliteSessionBackend::open(&database).expect("snapshot recovery backend");
        let (log_store, state_machine) = open(
            &backend,
            snapshot_directory.clone(),
            identity(1),
            expected_members(),
        )
        .await
        .expect("create snapshot storage");
        drop(log_store);
        drop(state_machine);

        let lookalike =
            snapshot_directory.join(".foreign.opc-cleanup-00000000-0000-4000-8000-000000000002");
        std::fs::write(&lookalike, b"foreign lookalike bytes").expect("write lookalike");
        sync_directory(&snapshot_directory).expect("durable foreign lookalike");
        let (log_store, state_machine) = open(
            &backend,
            snapshot_directory.clone(),
            identity(1),
            expected_members(),
        )
        .await
        .expect("restart counts foreign lookalike without deleting it");
        drop(log_store);
        drop(state_machine);
        assert_eq!(
            std::fs::read(&lookalike).expect("lookalike survives"),
            b"foreign lookalike bytes"
        );
        assert_eq!(
            1,
            std::fs::read_dir(&snapshot_directory)
                .expect("surviving foreign entry")
                .count(),
            "foreign lookalike remains a capacity survivor"
        );
    }

    #[tokio::test]
    async fn snapshot_directory_recovery_reclaims_33_known_staging_artifacts_before_capacity_rejection(
    ) {
        let directory = tempfile::tempdir().expect("snapshot staging recovery directory");
        let snapshot_directory = directory.path().join("snapshots");
        let database = directory.path().join("sessions.sqlite");
        let backend = SqliteSessionBackend::open(&database).expect("snapshot staging backend");
        let (log_store, state_machine) = open(
            &backend,
            snapshot_directory.clone(),
            identity(1),
            expected_members(),
        )
        .await
        .expect("create snapshot staging storage");
        drop(log_store);
        drop(state_machine);

        for index in 0..=SNAPSHOT_DIRECTORY_MAX_ENTRIES {
            std::fs::write(
                snapshot_directory
                    .join(format!("incoming-00000000-0000-4000-8000-{index:012}.part")),
                b"interrupted receiver artifact",
            )
            .expect("write stale receiver artifact");
        }
        sync_directory(&snapshot_directory).expect("sync stale receiver artifacts");

        let (log_store, state_machine) = open(
            &backend,
            snapshot_directory.clone(),
            identity(1),
            expected_members(),
        )
        .await
        .expect("restart reclaims admitted staging remnants before capacity enforcement");
        drop(log_store);
        drop(state_machine);
        assert_eq!(
            0,
            std::fs::read_dir(snapshot_directory)
                .expect("read reclaimed staging directory")
                .count(),
            "bounded recovery reclaims its capacity proof entries first"
        );
    }

    #[tokio::test]
    async fn restart_reclaims_a_capacity_full_set_of_noncurrent_published_snapshot_orphans() {
        let directory = tempfile::tempdir().expect("published orphan capacity directory");
        let snapshot_directory = directory.path().join("snapshots");
        let backend = SqliteSessionBackend::open(directory.path().join("sessions.sqlite"))
            .expect("published orphan capacity backend");
        let (mut log_store, mut state_machine) = open(
            &backend,
            snapshot_directory.clone(),
            identity(1),
            expected_members(),
        )
        .await
        .expect("create published orphan capacity storage");
        append_commit_and_apply(
            &mut log_store,
            &mut state_machine,
            [initial_membership_entry()],
            "seed current published snapshot",
        )
        .await;
        let current = state_machine
            .get_snapshot_builder()
            .await
            .build_snapshot()
            .await
            .expect("build current published snapshot");
        let current_name = current
            .snapshot
            .path()
            .file_name()
            .expect("current published basename")
            .to_string_lossy()
            .into_owned();
        drop(current);
        drop(log_store);
        drop(state_machine);

        // One durable current image plus this full predecessor set reaches the
        // thirty-third capacity-proof entry. Every orphan has the canonical
        // publication basename but is not the exact metadata current name.
        for index in 0..SNAPSHOT_DIRECTORY_MAX_ENTRIES {
            std::fs::write(
                snapshot_directory
                    .join(format!("snapshot-00000000-0000-4000-8000-{index:012}.opc")),
                b"interrupted published predecessor",
            )
            .expect("write canonical published predecessor orphan");
        }
        sync_directory(&snapshot_directory).expect("sync published predecessor orphans");

        let (log_store, state_machine) = open(
            &backend,
            snapshot_directory.clone(),
            identity(1),
            expected_members(),
        )
        .await
        .expect("restart reclaims published predecessor capacity proof entries");
        drop(log_store);
        drop(state_machine);
        let names = std::fs::read_dir(&snapshot_directory)
            .expect("read reclaimed published namespace")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(names, vec![current_name]);
    }

    #[tokio::test]
    async fn cleanup_failure_latch_survives_each_early_validation_error_then_reports_once() {
        let _hook_lock = snapshot_artifact_cleanup_test_lock().lock().await;

        for failure in [
            SnapshotDirectoryValidationFailure::Current,
            SnapshotDirectoryValidationFailure::ReadDirectory,
            SnapshotDirectoryValidationFailure::SyncDirectory,
        ] {
            let directory = tempfile::tempdir().expect("cleanup latch directory");
            let snapshot_directory = directory.path().join("snapshots");
            let backend = SqliteSessionBackend::open(directory.path().join("sessions.sqlite"))
                .expect("cleanup latch backend");
            let (_log, state_machine) = open(
                &backend,
                snapshot_directory.clone(),
                identity(1),
                expected_members(),
            )
            .await
            .expect("cleanup latch storage");
            if failure == SnapshotDirectoryValidationFailure::SyncDirectory {
                std::fs::write(
                    snapshot_directory.join("incoming-00000000-0000-4000-8000-000000000001.part"),
                    b"interrupted receive",
                )
                .expect("write reclaimable artifact");
            }
            state_machine
                .core
                .snapshot_cleanup_failed
                .store(true, Ordering::Release);
            inject_snapshot_directory_validation_failure(snapshot_directory.clone(), failure);
            assert!(validate_and_clean_snapshot_directory(
                &state_machine.core,
                Some(&state_machine._snapshot_directory_lease),
            )
            .await
            .is_err());
            assert!(
                state_machine
                    .core
                    .snapshot_cleanup_failed
                    .load(Ordering::Acquire),
                "early {failure:?} error must not consume dropped-cleanup evidence"
            );
            assert_eq!(
                Err(SessionConsensusStorageError::BackendUnavailable),
                validate_and_clean_snapshot_directory(
                    &state_machine.core,
                    Some(&state_machine._snapshot_directory_lease),
                )
                .await,
                "first clean pass reports the retained latch"
            );
            assert!(
                validate_and_clean_snapshot_directory(
                    &state_machine.core,
                    Some(&state_machine._snapshot_directory_lease),
                )
                .await
                .is_ok(),
                "the latch is one-shot after a completed pass"
            );
        }
    }

    #[tokio::test]
    async fn empty_namespace_cleanup_latch_retries_dirfd_sync_before_consumption() {
        let _hook_lock = snapshot_artifact_cleanup_test_lock().lock().await;
        let directory = tempfile::tempdir().expect("empty cleanup latch directory");
        let backend = SqliteSessionBackend::open(directory.path().join("sessions.sqlite"))
            .expect("empty cleanup latch backend");
        let (_log, state_machine) = open(
            &backend,
            directory.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("empty cleanup latch storage");
        let namespace = Arc::clone(&state_machine._snapshot_directory_lease.namespace);

        // The emergency O_EXCL owner unlinks the child, then its only
        // directory fsync fails. This leaves no entry to trigger ordinary
        // cleanup on the next admission, but must leave durable evidence.
        fail_namespace_pinned_post_create_setup_for_test(&namespace);
        fail_retained_namespace_sync_for_test(&namespace);
        assert!(PinnedSqliteFile::create_new_in_namespace(
            Arc::clone(&namespace),
            std::ffi::OsStr::new("build-00000000-0000-4000-8000-000000000001.sqlite"),
        )
        .is_err());
        assert!(
            namespace
                .entries(SNAPSHOT_DIRECTORY_MAX_ENTRIES)
                .expect("read empty namespace")
                .is_empty(),
            "the post-O_EXCL guard removed the only child before its fsync failed"
        );
        assert!(has_unpublished_snapshot_cleanup_failure(
            state_machine
                ._snapshot_directory_lease
                .namespace
                .cleanup_latch_identity()
        ));

        // This is an empty-directory validation, so only the pending latch
        // can make the retained descriptor sync mandatory. A failure here
        // must preserve the latch and block terminal handoff.
        inject_snapshot_directory_validation_failure(
            state_machine.core.snapshot_dir.as_ref().clone(),
            SnapshotDirectoryValidationFailure::SyncDirectory,
        );
        assert_eq!(
            Err(SessionConsensusStorageError::BackendUnavailable),
            validate_and_clean_snapshot_directory(
                &state_machine.core,
                Some(&state_machine._snapshot_directory_lease),
            )
            .await
        );
        assert!(has_unpublished_snapshot_cleanup_failure(
            state_machine
                ._snapshot_directory_lease
                .namespace
                .cleanup_latch_identity()
        ));

        // The completed retry reaches dirfd fsync, reports the one-shot
        // cleanup evidence, and only the following clean pass can proceed.
        assert_eq!(
            Err(SessionConsensusStorageError::BackendUnavailable),
            validate_and_clean_snapshot_directory(
                &state_machine.core,
                Some(&state_machine._snapshot_directory_lease),
            )
            .await
        );
        assert!(
            !has_unpublished_snapshot_cleanup_failure(
                state_machine
                    ._snapshot_directory_lease
                    .namespace
                    .cleanup_latch_identity()
            ),
            "latch is consumed only after the retained descriptor sync succeeds"
        );
        validate_and_clean_snapshot_directory(
            &state_machine.core,
            Some(&state_machine._snapshot_directory_lease),
        )
        .await
        .expect("clean retry after durable empty-directory sync");
    }

    #[tokio::test]
    async fn cleanup_generation_issued_after_fsync_is_not_acknowledged_by_older_pass() {
        let directory = tempfile::tempdir().expect("cleanup generation race directory");
        let backend = SqliteSessionBackend::open(directory.path().join("sessions.sqlite"))
            .expect("cleanup generation race backend");
        let (_log, state_machine) = open(
            &backend,
            directory.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("cleanup generation race storage");
        let latch_identity = state_machine
            ._snapshot_directory_lease
            .namespace
            .cleanup_latch_identity()
            .to_path_buf();
        latch_unpublished_snapshot_cleanup_failure_for_test(Arc::clone(
            &state_machine._snapshot_directory_lease.namespace,
        ));

        let gate = Arc::new(SnapshotArtifactGate::new());
        gate.arm();
        let _gate_guard = SnapshotCleanupGenerationAckGateGuard::install(
            latch_identity.clone(),
            Arc::clone(&gate),
        );
        let core = state_machine.core.clone();
        let lease = Arc::clone(&state_machine._snapshot_directory_lease);
        let older = tokio::spawn(async move {
            validate_and_clean_snapshot_directory(&core, Some(&lease)).await
        });
        gate.wait_started().await;

        // This models another cleanup owner unlinking an artifact and then
        // reporting its failed fsync after the older validator's retained
        // directory fsync, but before that validator can acknowledge. It is
        // a distinct generation and must survive the older acknowledgement.
        latch_unpublished_snapshot_cleanup_failure_for_test(Arc::clone(
            &state_machine._snapshot_directory_lease.namespace,
        ));
        gate.release();
        assert_eq!(
            Err(SessionConsensusStorageError::BackendUnavailable),
            older.await.expect("older generation validation task")
        );
        assert!(has_unpublished_snapshot_cleanup_failure(&latch_identity));

        assert_eq!(
            Err(SessionConsensusStorageError::BackendUnavailable),
            validate_and_clean_snapshot_directory(
                &state_machine.core,
                Some(&state_machine._snapshot_directory_lease),
            )
            .await,
            "the later generation receives its own fsync and one-shot report"
        );
        assert!(
            !has_unpublished_snapshot_cleanup_failure(&latch_identity),
            "second pass acknowledges only the later generation after its fsync"
        );
        validate_and_clean_snapshot_directory(
            &state_machine.core,
            Some(&state_machine._snapshot_directory_lease),
        )
        .await
        .expect("only the third clean pass may continue");
    }

    #[tokio::test]
    async fn simultaneous_atomic_and_dropped_cleanup_latches_report_once_together() {
        let directory = tempfile::tempdir().expect("combined cleanup latch directory");
        let backend = SqliteSessionBackend::open(directory.path().join("sessions.sqlite"))
            .expect("combined cleanup latch backend");
        let (_log, state_machine) = open(
            &backend,
            directory.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("combined cleanup latch storage");
        state_machine
            .core
            .snapshot_cleanup_failed
            .store(true, Ordering::Release);
        latch_unpublished_snapshot_cleanup_failure_for_test(Arc::clone(
            &state_machine._snapshot_directory_lease.namespace,
        ));

        assert_eq!(
            Err(SessionConsensusStorageError::BackendUnavailable),
            validate_and_clean_snapshot_directory(
                &state_machine.core,
                Some(&state_machine._snapshot_directory_lease),
            )
            .await,
            "both independent latches are consumed by the same completed pass"
        );
        assert!(validate_and_clean_snapshot_directory(
            &state_machine.core,
            Some(&state_machine._snapshot_directory_lease),
        )
        .await
        .is_ok());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn pending_terminal_handoff_survives_cleanup_validation_failures_until_one_clean_pass() {
        async fn pending_terminal_core() -> (
            tempfile::TempDir,
            SqliteSessionBackend,
            SqliteConsensusCore,
            Arc<SnapshotDirectoryLease>,
        ) {
            let directory = tempfile::tempdir().expect("terminal handoff directory");
            let database = directory.path().join("sessions.sqlite");
            let snapshots = directory.path().join("snapshots");
            let initial_backend = SqliteSessionBackend::open(&database).expect("initial backend");
            let (initial_log, initial_state) = open(
                &initial_backend,
                snapshots.clone(),
                identity(1),
                expected_members(),
            )
            .await
            .expect("initialize terminal handoff database");
            {
                let conn = initial_state.core.conn.lock().await;
                conn.execute(
                    "UPDATE consensus_operator_recovery SET recovery_epoch = 1, last_plan_digest = ?1, pending_epoch = NULL, pending_plan_digest = NULL WHERE singleton = 1",
                    rusqlite::params![[0xA5_u8; 32].as_slice()],
                )
                .expect("advance terminal recovery fixture state");
            }
            drop(initial_log);
            drop(initial_state);
            drop(initial_backend);

            let latch = consensus::OperatorRecoveryLatch {
                identity: identity(1),
                recovery_epoch: 1,
                plan_digest: [0xA5; 32],
                audit_pending: false,
            };
            let database_file = std::fs::File::open(&database).expect("open terminal database");
            consensus::ensure_operator_recovery_latch_sync(&database, latch)
                .expect("write active terminal latch");
            consensus::terminalize_operator_recovery_latch_sync(
                &database,
                latch,
                &database_file,
                None,
            )
            .expect("write pending terminal handoff");
            drop(database_file);

            let backend = SqliteSessionBackend::open(&database).expect("classify terminal handoff");
            let lease = acquire_snapshot_directory_lease(&backend, &snapshots)
                .await
                .expect("acquire terminal handoff lease");
            let members = expected_members();
            let bindings = members
                .iter()
                .copied()
                .map(|node| {
                    let mut descriptor = [0x11; 32];
                    descriptor[..8].copy_from_slice(&node.get().to_be_bytes());
                    let mut endpoint = [0x22; 32];
                    endpoint[..8].copy_from_slice(&node.get().to_be_bytes());
                    let mut tls = [0x33; 32];
                    tls[..8].copy_from_slice(&node.get().to_be_bytes());
                    let mut backing = [0x44; 32];
                    backing[..8].copy_from_slice(&node.get().to_be_bytes());
                    (
                        node,
                        SessionTopologyMemberBinding::new(descriptor, endpoint, tls, backing),
                    )
                })
                .collect();
            let core = SqliteConsensusCore::initialize(
                &backend,
                snapshots,
                identity(1),
                members,
                bindings,
                ConsensusAuthorityProfile::Dynamic,
                None,
            )
            .await
            .expect("initialize core holding pending terminal handoff");
            assert!(
                core.terminal_recovery_handoff_pending_for_test(),
                "core receives the pending terminal handoff before storage validation"
            );
            (directory, backend, core, lease)
        }

        let _hook_lock = snapshot_artifact_cleanup_test_lock().lock().await;
        for failure in [
            SnapshotDirectoryValidationFailure::Current,
            SnapshotDirectoryValidationFailure::ReadDirectory,
            SnapshotDirectoryValidationFailure::SyncDirectory,
        ] {
            let (_directory, backend, core, lease) = pending_terminal_core().await;
            // The directory-sync injection is reached only after reclaiming
            // an owned staging name.  Keep that branch causally equivalent
            // to Current/ReadDirectory: none may consume terminal recovery.
            let stale = core.snapshot_dir.join(format!(
                "incoming-{}.part",
                uuid::Uuid::new_v4().hyphenated()
            ));
            std::fs::write(stale, b"terminal-handoff-cleanup-fixture")
                .expect("write reclaimable staging fixture");
            core.snapshot_cleanup_failed.store(true, Ordering::Release);
            inject_snapshot_directory_validation_failure(
                core.snapshot_dir.as_ref().clone(),
                failure,
            );
            assert_eq!(
                Err(SessionConsensusStorageError::BackendUnavailable),
                validate_and_clean_snapshot_directory(&core, Some(&lease)).await,
                "injected {failure:?} failure"
            );
            assert!(
                core.terminal_recovery_handoff_pending_for_test(),
                "{failure:?} failure must not consume the terminal handoff"
            );

            assert_eq!(
                Err(SessionConsensusStorageError::BackendUnavailable),
                validate_and_clean_snapshot_directory(&core, Some(&lease)).await,
                "the deferred cleanup latch reports before terminal consumption"
            );
            assert!(core.terminal_recovery_handoff_pending_for_test());

            // A duplicate admission fails at the lease before it can take a
            // handoff from its backend. This is the same ordering boundary as
            // a concurrent process/namespace owner.
            let duplicate = open(
                &backend,
                core.snapshot_dir.as_ref().clone(),
                identity(1),
                expected_members(),
            )
            .await;
            assert!(matches!(
                duplicate,
                Err(SessionConsensusStorageError::BackendUnavailable)
            ));
            assert!(
                core.terminal_recovery_handoff_pending_for_test(),
                "duplicate lease loss must not consume the terminal handoff"
            );

            validate_and_clean_snapshot_directory(&core, Some(&lease))
                .await
                .expect("a fully clean validation consumes the handoff");
            assert!(
                !core.terminal_recovery_handoff_pending_for_test(),
                "only the successful complete pass consumes the terminal handoff"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn failed_public_open_restores_terminal_handoff_for_same_backend_retry() {
        let (_directory, backend, snapshots) = pending_terminal_backend_fixture().await;
        let _hook_lock = snapshot_artifact_cleanup_test_lock().lock().await;
        inject_snapshot_directory_validation_failure(
            snapshots.clone(),
            SnapshotDirectoryValidationFailure::Current,
        );
        assert!(matches!(
            open(&backend, snapshots.clone(), identity(1), expected_members()).await,
            Err(SessionConsensusStorageError::BackendUnavailable)
        ));

        // The failed public open drops its core.  The exact terminal
        // descriptor handoff must return to this backend rather than leaving
        // a durable PendingHandoff record with an empty in-process slot.
        let (_log, state_machine) = open(&backend, snapshots, identity(1), expected_members())
            .await
            .expect("same backend retries pending terminal handoff");
        assert!(
            !state_machine
                .core
                .terminal_recovery_handoff_pending_for_test(),
            "successful full public admission consumes the restored handoff"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn strict_live_terminal_consume_rejects_an_absent_sidecar() {
        let directory = tempfile::tempdir().expect("absent terminal directory");
        let database = directory.path().join("sessions.sqlite");
        let snapshots = directory.path().join("snapshots");
        let backend = SqliteSessionBackend::open(&database).expect("open absent terminal backend");
        let (log_store, state_machine) = open(&backend, snapshots, identity(1), expected_members())
            .await
            .expect("open clean terminal core");
        let consumer = log_store.live_terminal_recovery_handoff_consumer();
        assert_eq!(
            Err(SessionConsensusStorageError::CorruptState),
            consumer.consume().await,
            "strict manager consumption never treats absence as an idempotent terminal"
        );
        assert!(
            !state_machine
                .core
                .terminal_recovery_handoff_pending_for_test(),
            "an absent sidecar must not fabricate a terminal slot"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn live_terminal_reconciliation_skips_snapshot_selection_until_terminal_evidence() {
        let directory = tempfile::tempdir().expect("live terminal probe directory");
        let database = directory.path().join("sessions.sqlite");
        let snapshots = directory.path().join("snapshots");
        let backend = SqliteSessionBackend::open(&database).expect("open live terminal backend");
        let (log_store, mut state_machine) =
            open(&backend, snapshots.clone(), identity(1), expected_members())
                .await
                .expect("open live terminal storage");
        state_machine
            .apply([initial_membership_entry()])
            .await
            .expect("apply membership before snapshot");
        let mut snapshot_builder = state_machine.get_snapshot_builder().await;
        let built_snapshot = snapshot_builder
            .build_snapshot()
            .await
            .expect("build current snapshot for terminal fixture");
        drop(built_snapshot);
        drop(snapshot_builder);

        let terminal_snapshot = {
            let conn = state_machine.core.conn.lock().await;
            let (_, file_name, _, _) =
                consensus::read_current_snapshot_sync(&conn, state_machine.core.storage_identity)
                    .expect("read current terminal fixture snapshot")
                    .expect("current terminal fixture snapshot");
            let path = snapshots.join(file_name);
            let file = std::fs::File::open(&path).expect("open current terminal fixture snapshot");
            consensus::operator_recovery_terminal_snapshot(&path, &file, false)
                .expect("bind current terminal fixture snapshot")
        };
        let consumer = log_store.live_terminal_recovery_handoff_consumer();
        let observer = LiveTerminalRecoveryFullReconciliationObserver::install();

        assert_eq!(
            LiveTerminalRecoveryHandoffState::Clear,
            consumer
                .reconcile()
                .await
                .expect("clear probe revalidates application authority"),
            "clear steady state does not enter snapshot reconciliation"
        );
        assert_eq!(
            0,
            observer.full_reconciliations(),
            "clear steady state must not select, open, or classify the current snapshot"
        );

        let latch = consensus::OperatorRecoveryLatch {
            identity: identity(1),
            recovery_epoch: 1,
            plan_digest: [0xA9; 32],
            audit_pending: false,
        };
        {
            let conn = state_machine.core.conn.lock().await;
            consensus::mark_operator_recovery_pending_sync(&conn, identity(1), 1, [0xA9; 32])
                .expect("mark terminal fixture recovery pending");
        }
        consensus::ensure_operator_recovery_latch_sync(&database, latch)
            .expect("publish active terminal fixture latch");
        assert_eq!(
            LiveTerminalRecoveryHandoffState::Active,
            consumer
                .reconcile()
                .await
                .expect("active probe remains closed without snapshot work")
        );
        assert_eq!(
            0,
            observer.full_reconciliations(),
            "an active sidecar remains closed without current snapshot selection"
        );

        {
            let conn = state_machine.core.conn.lock().await;
            assert_eq!(
                consensus::OperatorRecoveryApply::Applied,
                consensus::finalize_operator_recovery_sync(
                    &conn,
                    identity(1),
                    1,
                    [0xA9; 32],
                    consensus::observed_fence_high_water_sync(&conn)
                        .expect("read terminal fixture fence high-water"),
                    consensus::observed_credential_high_water_sync(&conn)
                        .expect("read terminal fixture credential high-water"),
                )
                .expect("finalize terminal fixture recovery")
            );
        }
        let database_file = std::fs::File::open(&database).expect("open terminal fixture database");
        consensus::terminalize_operator_recovery_latch_sync(
            &database,
            latch,
            &database_file,
            Some(terminal_snapshot),
        )
        .expect("publish pending terminal fixture handoff");
        drop(database_file);

        assert_eq!(
            LiveTerminalRecoveryHandoffState::Consumed,
            consumer
                .reconcile()
                .await
                .expect("terminal evidence enters full snapshot reconciliation")
        );
        assert_eq!(
            1,
            observer.full_reconciliations(),
            "terminal evidence must select/open/classify the retained current snapshot"
        );
        assert!(
            !state_machine
                .core
                .terminal_recovery_handoff_pending_for_test(),
            "the terminal path completes descriptor-bound handoff consumption"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn live_terminal_handoff_consumer_retains_d1_after_active_terminalization() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("live terminal handoff directory");
        let database = directory.path().join("sessions.sqlite");
        let snapshots = directory.path().join("snapshots");
        let initial_backend =
            SqliteSessionBackend::open(&database).expect("initialize live terminal database");
        let (initial_log, initial_state) = open(
            &initial_backend,
            snapshots.clone(),
            identity(1),
            expected_members(),
        )
        .await
        .expect("initialize live terminal storage");
        drop(initial_log);
        drop(initial_state);
        drop(initial_backend);

        let latch = consensus::OperatorRecoveryLatch {
            identity: identity(1),
            recovery_epoch: 1,
            plan_digest: [0xA7; 32],
            audit_pending: false,
        };
        {
            let conn = rusqlite::Connection::open(&database)
                .expect("open recovery-state fixture connection");
            consensus::mark_operator_recovery_pending_sync(&conn, identity(1), 1, [0xA7; 32])
                .expect("mark live recovery pending");
        }
        let database_file = std::fs::File::open(&database).expect("open active terminal database");
        consensus::ensure_operator_recovery_latch_sync(&database, latch)
            .expect("publish active terminal latch");
        drop(database_file);

        // The core opens while recovery is Active, so it holds no terminal
        // handoff. Ordinary readiness remains recovery-pending until the
        // later terminal publication is explicitly consumed through this
        // same retained lease.
        let backend = SqliteSessionBackend::open(&database).expect("open active live backend");
        let (log_store, state_machine) =
            open(&backend, snapshots.clone(), identity(1), expected_members())
                .await
                .expect("open core while recovery latch is active");
        let consumer = log_store.live_terminal_recovery_handoff_consumer();
        assert!(
            !state_machine
                .core
                .terminal_recovery_handoff_pending_for_test(),
            "an active latch does not fabricate a pending terminal descriptor"
        );
        assert!(backend
            .consensus_operator_recovery_pending(identity(1))
            .await
            .expect("active recovery remains pending"));
        assert!(matches!(
            consumer.consume().await,
            Err(SessionConsensusStorageError::CorruptState)
        ));
        assert!(
            !state_machine
                .core
                .terminal_recovery_handoff_pending_for_test(),
            "active classification failure must not populate the terminal slot"
        );

        {
            let conn = state_machine.core.conn.lock().await;
            assert_eq!(
                consensus::OperatorRecoveryApply::Applied,
                consensus::finalize_operator_recovery_sync(
                    &conn,
                    identity(1),
                    1,
                    [0xA7; 32],
                    consensus::observed_fence_high_water_sync(&conn)
                        .expect("read live terminal fence high-water"),
                    consensus::observed_credential_high_water_sync(&conn)
                        .expect("read live terminal credential high-water"),
                )
                .expect("finalize live terminal recovery state")
            );
        }
        let database_file = std::fs::File::open(&database).expect("open terminal database");
        consensus::terminalize_operator_recovery_latch_sync(&database, latch, &database_file, None)
            .expect("publish pending terminal handoff");
        drop(database_file);
        assert!(backend
            .consensus_operator_recovery_pending(identity(1))
            .await
            .expect("published terminal remains pending before live consume"));

        // D1 has an exact owned cleanup candidate, then an operator replaces
        // the configured spelling with D2.  A second store cannot acquire D2
        // while the live D1 lease remains held, and the retained consumer
        // reclaims/syncs D1 without touching D2.
        let stale_name = format!("incoming-{}.part", uuid::Uuid::new_v4().hyphenated());
        std::fs::write(snapshots.join(&stale_name), b"live-terminal-d1-staging")
            .expect("write D1 cleanup candidate");
        sync_directory(&snapshots).expect("sync D1 cleanup candidate");
        let detached_d1 = directory.path().join("snapshots-d1");
        std::fs::rename(&snapshots, &detached_d1).expect("detach D1 after live core admission");
        std::fs::create_dir(&snapshots).expect("create replacement D2");
        std::fs::set_permissions(&snapshots, std::fs::Permissions::from_mode(0o700))
            .expect("restrict replacement D2");
        assert!(matches!(
            open(&backend, snapshots.clone(), identity(1), expected_members(),).await,
            Err(SessionConsensusStorageError::BackendUnavailable)
        ));

        // The live handoff takes the same snapshot transaction gate as
        // receive/install/build.  It cannot select/classify a snapshot while
        // another snapshot mutation owns that gate, and proceeds once that
        // owner releases it.
        let held_snapshot_gate = Arc::clone(&state_machine.core.snapshot_gate)
            .lock_owned()
            .await;
        let waiting_consumer = log_store.live_terminal_recovery_handoff_consumer();
        let wait_for_gate = tokio::spawn(async move { waiting_consumer.acquire_gate().await });
        tokio::task::yield_now().await;
        assert!(
            !wait_for_gate.is_finished(),
            "live terminal handoff waits for the snapshot transaction gate"
        );
        drop(held_snapshot_gate);
        let released_gate = wait_for_gate
            .await
            .expect("join gate-serialized live terminal gate waiter")
            .expect("acquire released live terminal gate");
        drop(released_gate);

        let finalization_gate = consumer
            .acquire_gate()
            .await
            .expect("acquire retained finalization gate");
        consumer
            .consume_with_gate(&finalization_gate)
            .await
            .expect("retained D1 consumer validates and consumes terminal handoff");
        drop(finalization_gate);
        assert!(
            !detached_d1.join(&stale_name).exists(),
            "the live consumer reclaims only its detached D1 staging child"
        );
        assert_eq!(
            0,
            std::fs::read_dir(&snapshots)
                .expect("read untouched D2")
                .count(),
            "terminal validation never creates, scans, or removes in replacement D2"
        );
        assert!(
            !state_machine
                .core
                .terminal_recovery_handoff_pending_for_test(),
            "only the retained descriptor validation consumes the live handoff"
        );
        // The terminal slot is now empty, but the durable consumed tombstone
        // still names this exact database. A recovery-manager retry must be
        // idempotent through that descriptor-bound evidence, not fail as a
        // generic Clear/absent sidecar.
        let retry_gate = consumer
            .acquire_gate()
            .await
            .expect("acquire retry terminal gate");
        consumer
            .consume_with_gate(&retry_gate)
            .await
            .expect("exact consumed terminal retry is accepted");
        drop(retry_gate);
        assert!(!backend
            .consensus_operator_recovery_pending(identity(1))
            .await
            .expect("live terminal consumption clears recovery pending"));
        drop(log_store);
        drop(state_machine);
    }

    /// A remote core can already be constructing S2 when recovery has pinned
    /// S1.  Its local snapshot gate cannot serialize with the finalizer's
    /// different-core gate, so the last current-record write itself must see
    /// the newly terminal sidecar through the retained namespace descriptor
    /// and reject S2.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn terminal_recovery_fence_aborts_remote_snapshot_publication_after_s1_pin() {
        let directory = tempfile::tempdir().expect("remote publication fence directory");
        let database = directory.path().join("sessions.sqlite");
        let snapshots = directory.path().join("snapshots");
        let initial_backend = SqliteSessionBackend::open(&database).expect("initial backend");
        let (mut initial_log, mut initial_state_machine) = open(
            &initial_backend,
            snapshots.clone(),
            identity(1),
            expected_members(),
        )
        .await
        .expect("initialize S1 source");
        let membership = initial_membership_entry();
        initial_log
            .blocking_append([membership.clone()])
            .await
            .expect("append S1 membership");
        initial_log
            .save_committed(Some(membership.log_id))
            .await
            .expect("commit S1 membership");
        initial_state_machine
            .apply([membership])
            .await
            .expect("apply S1 membership");
        let mut initial_builder = initial_state_machine.get_snapshot_builder().await;
        let initial_snapshot = initial_builder
            .build_snapshot()
            .await
            .expect("publish S1 before recovery becomes active");
        let (s1_name, s1_checksum, s1_length) = {
            let conn = initial_state_machine.core.conn.lock().await;
            let (_, name, checksum, length) = consensus::read_current_snapshot_sync(
                &conn,
                initial_state_machine.core.storage_identity,
            )
            .expect("read durable S1")
            .expect("S1 current row");
            (name, checksum, length)
        };
        drop(initial_snapshot);
        drop(initial_builder);
        drop(initial_log);
        drop(initial_state_machine);
        drop(initial_backend);

        let latch = consensus::OperatorRecoveryLatch {
            identity: identity(1),
            recovery_epoch: 1,
            plan_digest: [0xB4; 32],
            audit_pending: false,
        };
        {
            let conn = rusqlite::Connection::open(&database)
                .expect("open Active recovery-state connection");
            consensus::mark_operator_recovery_pending_sync(&conn, identity(1), 1, [0xB4; 32])
                .expect("mark S1 recovery pending");
        }
        consensus::ensure_operator_recovery_latch_sync(&database, latch)
            .expect("publish Active recovery latch before remote builder starts");

        // This is the remote live core: it opens under Active and therefore
        // has no terminal descriptor yet. Its build is deliberately paused
        // after preparing S2 but before its connection-held publication
        // fence.
        let backend = SqliteSessionBackend::open(&database).expect("open remote backend");
        let (log_store, mut state_machine) =
            open(&backend, snapshots.clone(), identity(1), expected_members())
                .await
                .expect("open remote core under Active recovery");
        assert!(
            !state_machine
                .core
                .terminal_recovery_handoff_pending_for_test(),
            "Active recovery does not create a terminal descriptor before S1 is pinned"
        );
        let publication_gate = Arc::new(SnapshotArtifactGate::new());
        publication_gate.arm();
        let publication_fence = RecoveryPublicationFenceGateGuard::install(
            state_machine.core.snapshot_dir.as_ref().clone(),
            Arc::clone(&publication_gate),
        );
        let mut builder = state_machine.get_snapshot_builder().await;
        let remote_build = tokio::spawn(async move { builder.build_snapshot().await });
        tokio::time::timeout(Duration::from_secs(5), publication_gate.wait_started())
            .await
            .expect("remote builder reaches the recovery publication fence");

        // Model finalization on another live core: it publishes a terminal
        // handoff bound to S1 while this remote S2 candidate is paused. The
        // terminal descriptor is opened only through the remote core's
        // retained D1 namespace authority.
        {
            let conn = state_machine.core.conn.lock().await;
            assert_eq!(
                consensus::OperatorRecoveryApply::Applied,
                consensus::finalize_operator_recovery_sync(
                    &conn,
                    identity(1),
                    1,
                    [0xB4; 32],
                    consensus::observed_fence_high_water_sync(&conn)
                        .expect("read S1 recovery fence high-water"),
                    consensus::observed_credential_high_water_sync(&conn)
                        .expect("read S1 recovery credential high-water"),
                )
                .expect("finalize S1 recovery state")
            );
        }
        let s1_file = state_machine
            ._snapshot_directory_lease
            .namespace
            .open_read(std::ffi::OsStr::new(&s1_name))
            .expect("open S1 through the retained D1 namespace");
        let s1_path = state_machine.core.snapshot_dir.join(&s1_name);
        let terminal_snapshot =
            consensus::operator_recovery_terminal_snapshot(&s1_path, &s1_file, false)
                .expect("bind terminal recovery to S1 descriptor");
        let database_file = std::fs::File::open(&database).expect("open terminal database");
        consensus::terminalize_operator_recovery_latch_sync(
            &database,
            latch,
            &database_file,
            Some(terminal_snapshot),
        )
        .expect("publish pending S1 handoff");
        drop(database_file);
        drop(s1_file);

        drop(publication_fence);
        let build_result = remote_build
            .await
            .expect("join remote builder after terminal publication");
        assert!(
            build_result.is_err(),
            "the S2 candidate must abort rather than publish across a terminal S1 handoff"
        );

        let after = {
            let conn = state_machine.core.conn.lock().await;
            consensus::read_current_snapshot_sync(&conn, state_machine.core.storage_identity)
                .expect("read current after rejected S2")
                .expect("S1 remains current after rejected S2")
        };
        assert_eq!(s1_name, after.1, "rejected S2 cannot replace S1");
        assert_eq!(s1_checksum, after.2, "rejected S2 cannot alter S1 checksum");
        assert_eq!(s1_length, after.3, "rejected S2 cannot alter S1 length");
        assert!(
            state_machine
                .core
                .terminal_recovery_handoff_pending_for_test(),
            "the fence retains the exact S1 terminal handoff for descriptor-bound consumption"
        );

        log_store
            .live_terminal_recovery_handoff_consumer()
            .consume()
            .await
            .expect("consume the retained S1 handoff after rejecting S2");
        assert!(
            !state_machine
                .core
                .terminal_recovery_handoff_pending_for_test(),
            "descriptor-bound S1 consumption clears the retained terminal handoff"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn fixed_terminal_snapshot_handoff_measures_the_retained_descriptor_then_consumes() {
        let directory = FixedRawReadStoreFixture::new();
        let (mut log, mut state_machine, database) = open_fixed_raw_read_store(&directory).await;
        let membership = fixed_initial_membership_entry();
        let membership_log_id = membership.log_id;
        log.blocking_append([membership.clone()])
            .await
            .expect("append fixed terminal fixture membership");
        log.save_committed(Some(membership_log_id))
            .await
            .expect("commit fixed terminal fixture membership");
        state_machine
            .apply([membership])
            .await
            .expect("apply fixed terminal fixture membership");
        let mut builder = state_machine.get_snapshot_builder().await;
        let built = builder
            .build_snapshot()
            .await
            .expect("build sealed fixed terminal snapshot");
        let (file_name, checksum, length) = {
            let conn = state_machine.core.conn.lock().await;
            consensus::mark_operator_recovery_pending_sync(&conn, identity(1), 1, [0xA6; 32])
                .expect("mark fixed terminal recovery pending");
            assert_eq!(
                consensus::OperatorRecoveryApply::Applied,
                consensus::finalize_operator_recovery_sync(
                    &conn,
                    identity(1),
                    1,
                    [0xA6; 32],
                    consensus::observed_fence_high_water_sync(&conn)
                        .expect("read fixed terminal fence high-water"),
                    consensus::observed_credential_high_water_sync(&conn)
                        .expect("read fixed terminal credential high-water"),
                )
                .expect("finalize fixed terminal recovery state")
            );
            let (_, file_name, checksum, length) =
                consensus::read_current_snapshot_sync(&conn, state_machine.core.storage_identity)
                    .expect("read fixed terminal snapshot row")
                    .expect("fixed terminal snapshot row");
            (file_name, checksum, length)
        };
        let snapshot_path = state_machine.core.snapshot_dir.join(&file_name);
        let snapshot_file =
            std::fs::File::open(&snapshot_path).expect("open sealed terminal snapshot");
        let snapshot =
            consensus::operator_recovery_terminal_snapshot(&snapshot_path, &snapshot_file, true)
                .expect("bind sealed terminal snapshot incarnation");
        let latch = consensus::OperatorRecoveryLatch {
            identity: identity(1),
            recovery_epoch: 1,
            plan_digest: [0xA6; 32],
            audit_pending: false,
        };
        let database_file = std::fs::File::open(&database).expect("open fixed terminal database");
        consensus::ensure_operator_recovery_latch_sync(&database, latch)
            .expect("write fixed terminal latch");
        consensus::terminalize_operator_recovery_latch_sync(
            &database,
            latch,
            &database_file,
            Some(snapshot),
        )
        .expect("terminalize fixed snapshot handoff");
        drop(database_file);
        drop(snapshot_file);
        drop(built);
        drop(builder);
        drop(log);
        drop(state_machine);

        let members = fixed_raw_read_members();
        let backend =
            SqliteSessionBackend::open(&database).expect("classify fixed terminal handoff");
        let configured_snapshot_directory =
            directory.snapshot_path().join("fixed-raw-read-snapshots");
        let lease = acquire_snapshot_directory_lease(&backend, &configured_snapshot_directory)
            .await
            .expect("acquire fixed terminal retained namespace lease");
        let detached_snapshot_directory = directory
            .snapshot_path()
            .join("fixed-raw-read-snapshots-old");
        std::fs::rename(&configured_snapshot_directory, &detached_snapshot_directory)
            .expect("detach terminal snapshot namespace after lease admission");
        std::fs::create_dir(&configured_snapshot_directory)
            .expect("create terminal replacement namespace");
        let core_result = SqliteConsensusCore::initialize_with_admitted_snapshot_directory(
            &backend,
            lease.canonical_directory.clone(),
            identity(1),
            members.clone(),
            fixed_raw_read_bindings(&members),
            ConsensusAuthorityProfile::FixedImmutable,
            Some(PlacementResiliencePolicy::AllowReducedResilience),
        )
        .await;
        let core = core_result.expect("initialize fixed terminal core");
        assert!(core.terminal_recovery_handoff_pending_for_test());
        assert_eq!(
            1,
            validate_and_clean_snapshot_directory(&core, Some(&lease))
                .await
                .expect("validate fixed terminal descriptor"),
            "the sealed current artifact is the sole durable survivor"
        );
        assert!(
            !core.terminal_recovery_handoff_pending_for_test(),
            "only successful retained-descriptor fixed validation consumes the handoff"
        );
        let current = {
            let conn = core.conn.lock().await;
            consensus::read_current_snapshot_sync(&conn, core.storage_identity)
                .expect("read consumed fixed terminal row")
                .expect("current fixed terminal row")
        };
        assert_eq!(current.1, file_name);
        assert_eq!(current.2, checksum);
        assert_eq!(current.3, length);
        assert!(
            detached_snapshot_directory.join(&file_name).exists(),
            "terminal validation reads the detached retained namespace"
        );
        assert_eq!(
            0,
            std::fs::read_dir(&configured_snapshot_directory)
                .expect("read terminal replacement namespace")
                .count(),
            "terminal handoff validation and consume never inspect the replacement namespace"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn snapshot_receive_admission_waits_for_build_capacity_reservation() {
        let directory = tempfile::tempdir().expect("snapshot admission serialization directory");
        let backend = SqliteSessionBackend::open(directory.path().join("sessions.sqlite"))
            .expect("snapshot admission serialization backend");
        let (_, mut state_machine) = open(
            &backend,
            directory.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("snapshot admission serialization storage");
        state_machine
            .apply([initial_membership_entry()])
            .await
            .expect("apply membership before snapshot build");

        let capture_gate = backend.snapshot_capture_gate();
        capture_gate.arm();
        let mut builder = state_machine.get_snapshot_builder().await;
        let build = tokio::spawn(async move { builder.build_snapshot().await });
        capture_gate.wait_started().await;

        let (receive_started, receive_started_waiter) = tokio::sync::oneshot::channel();
        let mut receiver_state_machine = state_machine.clone();
        let receive = tokio::spawn(async move {
            let _ = receive_started.send(());
            receiver_state_machine.begin_receiving_snapshot().await
        });
        receive_started_waiter
            .await
            .expect("receiver task starts while build owns capacity reservation");
        tokio::task::yield_now().await;
        assert!(
            !receive.is_finished(),
            "receive cannot create an incoming reservation while build holds the snapshot gate"
        );
        assert!(
            Arc::clone(&state_machine.core.snapshot_gate)
                .try_lock_owned()
                .is_err(),
            "the build retains capacity admission until its artifacts are durable"
        );

        capture_gate.release();
        build
            .await
            .expect("join serialized snapshot build")
            .expect("snapshot build succeeds");
        let receiver = receive
            .await
            .expect("join serialized receiver")
            .expect("receiver admits after build releases its reservation");
        drop(receiver);
    }

    #[tokio::test]
    async fn snapshot_build_never_scavenges_a_live_receiver_reservation() {
        let directory = tempfile::tempdir().expect("live receiver directory");
        let backend = SqliteSessionBackend::open(directory.path().join("sessions.sqlite"))
            .expect("live receiver backend");
        let (_, mut state_machine) = open(
            &backend,
            directory.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("live receiver storage");
        state_machine
            .apply([initial_membership_entry()])
            .await
            .expect("live receiver membership");

        let receiver = state_machine
            .begin_receiving_snapshot()
            .await
            .expect("create active receiver");
        let receiver_path = receiver.path().to_path_buf();
        let mut builder = state_machine.get_snapshot_builder().await;
        builder
            .build_snapshot()
            .await
            .expect("build alongside receiver");
        assert!(
            receiver_path.is_file(),
            "build recovery counts but never unlinks an active receiver artifact"
        );
        drop(receiver);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn duplicate_core_open_cannot_scavenge_a_live_receiver() {
        use std::os::linux::fs::MetadataExt;

        let directory = tempfile::tempdir().expect("shared receiver directory");
        let snapshot_directory = directory.path().join("snapshots");
        let database = directory.path().join("sessions.sqlite");
        let backend = SqliteSessionBackend::open(&database).expect("shared receiver backend");
        let (_, mut core_a) = open(
            &backend,
            snapshot_directory.clone(),
            identity(1),
            expected_members(),
        )
        .await
        .expect("open owner core");
        let mut receiver = core_a
            .begin_receiving_snapshot()
            .await
            .expect("create owner receiver");
        receiver
            .write_all(b"receiver bytes that must survive a second core")
            .await
            .expect("write receiver bytes");
        receiver.flush().await.expect("flush receiver bytes");
        let receiver_path = receiver.path().to_path_buf();
        let receiver_inode = std::fs::metadata(&receiver_path)
            .expect("stat receiver before duplicate open")
            .st_ino();

        let duplicate = open(
            &backend,
            snapshot_directory,
            identity(1),
            expected_members(),
        )
        .await;
        assert!(
            matches!(
                duplicate,
                Err(SessionConsensusStorageError::BackendUnavailable)
            ),
            "a second in-process core must be rejected before snapshot recovery"
        );
        assert_eq!(
            b"receiver bytes that must survive a second core".as_slice(),
            std::fs::read(&receiver_path).expect("read preserved receiver")
        );
        assert_eq!(
            receiver_inode,
            std::fs::metadata(&receiver_path)
                .expect("stat preserved receiver")
                .st_ino(),
            "duplicate admission must not replace the live receiver inode"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn one_durable_database_cannot_own_two_snapshot_namespaces() {
        let directory = tempfile::tempdir().expect("database namespace directory");
        let backend = SqliteSessionBackend::open(directory.path().join("sessions.sqlite"))
            .expect("database namespace backend");
        let (_first_log, _first_state) = open(
            &backend,
            directory.path().join("first-snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("first snapshot namespace");

        let second = open(
            &backend,
            directory.path().join("second-snapshots"),
            identity(1),
            expected_members(),
        )
        .await;
        assert!(matches!(
            second,
            Err(SessionConsensusStorageError::BackendUnavailable)
        ));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_same_backend_different_directories_admit_exactly_one_lease() {
        let directory = tempfile::tempdir().expect("database namespace race directory");
        let backend = SqliteSessionBackend::open(directory.path().join("sessions.sqlite"))
            .expect("database namespace race backend");
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        *snapshot_database_lease_admission_barrier()
            .lock()
            .expect("install database namespace race barrier") = Some(Arc::clone(&barrier));

        let first_path = directory.path().join("first-snapshots");
        let second_path = directory.path().join("second-snapshots");
        let (first, second) = tokio::join!(
            acquire_snapshot_directory_lease(&backend, &first_path),
            acquire_snapshot_directory_lease(&backend, &second_path),
        );
        *snapshot_database_lease_admission_barrier()
            .lock()
            .expect("clear database namespace race barrier") = None;

        assert_eq!(
            usize::from(first.is_ok()) + usize::from(second.is_ok()),
            1,
            "one durable SQLite identity may reserve only one snapshot namespace"
        );
        drop(first);
        drop(second);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn rejected_same_backend_lease_never_unlocks_the_original_database_flock() {
        const CHILD_MODE: &str = "OPC_SESSION_STORE_SNAPSHOT_LEASE_CHILD_MODE";
        const CHILD_DATABASE: &str = "OPC_SESSION_STORE_SNAPSHOT_LEASE_CHILD_DATABASE";
        const CHILD_SNAPSHOTS: &str = "OPC_SESSION_STORE_SNAPSHOT_LEASE_CHILD_SNAPSHOTS";
        const CHILD_TEST: &str = "consensus::storage::tests::receiver_lease_excludes_a_separate_process_until_receiver_drop";

        let directory = tempfile::tempdir().expect("same-OFD unlock regression directory");
        let database = directory.path().join("sessions.sqlite");
        let backend = SqliteSessionBackend::open(&database).expect("same-OFD unlock backend");
        let original_directory = directory.path().join("original-snapshots");
        let rejected_directory = directory.path().join("rejected-snapshots");
        let child_directory = directory.path().join("child-snapshots");
        let original = acquire_snapshot_directory_lease(&backend, &original_directory)
            .await
            .expect("original backend lease");

        assert!(
            acquire_snapshot_directory_lease(&backend, &rejected_directory)
                .await
                .is_err(),
            "the same backend cannot reserve a second namespace"
        );

        let run_child = |mode: &str| {
            std::process::Command::new(std::env::current_exe().expect("test executable"))
                .arg(CHILD_TEST)
                .arg("--exact")
                .arg("--nocapture")
                .env(CHILD_MODE, mode)
                .env(CHILD_DATABASE, &database)
                .env(CHILD_SNAPSHOTS, &child_directory)
                .output()
                .expect("run independent database-lock child")
        };

        let blocked = run_child("blocked");
        assert!(
            blocked.status.success(),
            "rejected same-OFD lease unlocked original flock: {}",
            String::from_utf8_lossy(&blocked.stderr)
        );
        drop(original);
        let admitted = run_child("admitted");
        assert!(
            admitted.status.success(),
            "independent flock child remained blocked after original lease drop: {}",
            String::from_utf8_lossy(&admitted.stderr)
        );
    }

    #[tokio::test]
    async fn public_consensus_storage_rejects_cloned_in_memory_backends() {
        let directory = tempfile::tempdir().expect("in-memory consensus lease directory");
        let backend = SqliteSessionBackend::in_memory().expect("in-memory consensus backend");
        let clone = backend.clone();
        for (backend, path) in [
            (&backend, directory.path().join("first-snapshots")),
            (&clone, directory.path().join("second-snapshots")),
        ] {
            assert!(
                matches!(
                    open(backend, path, identity(1), expected_members()).await,
                    Err(SessionConsensusStorageError::BackendUnavailable)
                ),
                "public durable consensus storage must not admit an unleaseable in-memory backend"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn snapshot_directory_lease_enforces_private_directory_admission_policy() {
        use std::os::unix::fs::PermissionsExt as _;

        const UMASK_CHILD: &str = "OPC_SESSION_STORE_SNAPSHOT_UMASK_CHILD";
        const UMASK_ROOT: &str = "OPC_SESSION_STORE_SNAPSHOT_UMASK_ROOT";
        const TEST_NAME: &str = "consensus::storage::tests::snapshot_directory_lease_enforces_private_directory_admission_policy";

        if std::env::var_os(UMASK_CHILD).is_some() {
            let root = PathBuf::from(std::env::var_os(UMASK_ROOT).expect("umask child root"));
            let backend = SqliteSessionBackend::open(root.join("umask-child.sqlite"))
                .expect("umask child backend");
            let created = root.join("created-under-umask-0077");
            let previous = nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o077));
            let lease = acquire_snapshot_directory_lease(&backend, &created).await;
            nix::sys::stat::umask(previous);
            let lease = lease.expect("create snapshot leaf under restrictive umask");
            assert_eq!(
                0o700,
                std::fs::metadata(&created)
                    .expect("created snapshot directory metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                "a restrictive child-process umask cannot weaken the explicit 0700 leaf"
            );
            drop(lease);
            return;
        }

        let directory = tempfile::tempdir().expect("snapshot directory policy directory");
        let backend = SqliteSessionBackend::open(directory.path().join("sessions.sqlite"))
            .expect("snapshot directory policy backend");
        for (mode, accepted) in [
            (0o700, true),
            (0o755, true),
            (0o770, false),
            (0o702, false),
            (0o777, false),
        ] {
            let path = directory.path().join(format!("snapshots-{mode:o}"));
            std::fs::create_dir(&path).expect("create pre-existing snapshot directory");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
                .expect("set snapshot directory mode");
            let lease = acquire_snapshot_directory_lease(&backend, &path).await;
            assert_eq!(
                accepted,
                lease.is_ok(),
                "mode {mode:o} admission must match the cooperative-namespace policy"
            );
            drop(lease);
        }

        let created = directory.path().join("created-private");
        let lease = acquire_snapshot_directory_lease(&backend, &created)
            .await
            .expect("create private snapshot directory");
        assert_eq!(
            0o700,
            std::fs::metadata(&created)
                .expect("created snapshot directory metadata")
                .permissions()
                .mode()
                & 0o777,
            "SDK-created snapshot leaf is explicitly private"
        );
        drop(lease);

        let status =
            std::process::Command::new(std::env::current_exe().expect("current test executable"))
                .args(["--exact", TEST_NAME, "--nocapture"])
                .env(UMASK_CHILD, "1")
                .env(UMASK_ROOT, directory.path())
                .status()
                .expect("run restrictive-umask child");
        assert!(status.success(), "restrictive-umask child passes");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn snapshot_directory_lease_rejects_final_symlink_and_fifo_without_waiting() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("snapshot special-entry directory");
        let backend = SqliteSessionBackend::open(directory.path().join("sessions.sqlite"))
            .expect("snapshot special-entry backend");
        let target = directory.path().join("target");
        std::fs::create_dir(&target).expect("create symlink target");
        let symlink_path = directory.path().join("snapshot-symlink");
        symlink(&target, &symlink_path).expect("create snapshot symlink");
        assert!(
            acquire_snapshot_directory_lease(&backend, &symlink_path)
                .await
                .is_err(),
            "the configured final path is opened O_NOFOLLOW before canonicalization"
        );

        let fifo_path = directory.path().join("snapshot-fifo");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo_path)
            .status()
            .expect("run mkfifo");
        assert!(status.success(), "mkfifo fixture succeeds");
        let started = std::time::Instant::now();
        assert!(
            acquire_snapshot_directory_lease(&backend, &fifo_path)
                .await
                .is_err(),
            "non-directory FIFO is rejected by the nonblocking directory open"
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "FIFO admission is nonblocking"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn snapshot_directory_lease_admits_a_procfd_pinned_directory() {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::PermissionsExt as _;

        let workspace = tempfile::tempdir().expect("create procfd snapshot workspace");
        let snapshots = workspace.path().join("snapshots");
        std::fs::create_dir(&snapshots).expect("create procfd snapshot leaf");
        std::fs::set_permissions(&snapshots, std::fs::Permissions::from_mode(0o700))
            .expect("make procfd snapshot leaf private");
        let snapshot_fd = nix::fcntl::open(
            &snapshots,
            nix::fcntl::OFlag::O_RDONLY
                | nix::fcntl::OFlag::O_DIRECTORY
                | nix::fcntl::OFlag::O_NOFOLLOW
                | nix::fcntl::OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::empty(),
        )
        .expect("open pinned procfd snapshot leaf");
        let procfd_path = PathBuf::from(format!("/proc/self/fd/{}/", snapshot_fd.as_raw_fd()));
        let backend = SqliteSessionBackend::open(workspace.path().join("sessions.sqlite"))
            .expect("open procfd snapshot backend");
        acquire_snapshot_directory_lease(&backend, &procfd_path)
            .await
            .expect("admit inherited procfd snapshot leaf through the complete lease path");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn retained_namespace_owner_receives_and_builds_in_detached_directory_after_replacement()
    {
        let directory = tempfile::tempdir().expect("replaced namespace directory");
        let snapshots = directory.path().join("snapshots");
        let retired = directory.path().join("retired-snapshots");
        let backend = SqliteSessionBackend::open(directory.path().join("sessions.sqlite"))
            .expect("replaced namespace backend");
        let (_log, mut state_machine) =
            open(&backend, snapshots.clone(), identity(1), expected_members())
                .await
                .expect("open original namespace owner");
        state_machine
            .apply([initial_membership_entry()])
            .await
            .expect("seed dynamic snapshot build");
        std::fs::rename(&snapshots, &retired).expect("rename leased namespace away");
        std::fs::create_dir(&snapshots).expect("replace configured namespace directory");

        let receiver = state_machine
            .begin_receiving_snapshot()
            .await
            .expect("receive stays in retained directory");
        let incoming_name = receiver
            .path()
            .file_name()
            .expect("incoming basename")
            .to_owned();
        assert!(retired.join(&incoming_name).exists());
        assert!(
            !snapshots.join(&incoming_name).exists(),
            "replacement directory must not receive an incoming artifact"
        );
        drop(receiver);
        let mut builder = state_machine.get_snapshot_builder().await;
        let built = builder
            .build_snapshot()
            .await
            .expect("build stays in retained directory");
        let published_name = built
            .snapshot
            .path()
            .file_name()
            .expect("published basename")
            .to_owned();
        assert!(retired.join(&published_name).exists());
        assert!(
            !snapshots.join(&published_name).exists(),
            "replacement directory must not receive a published artifact"
        );
        assert_eq!(
            0,
            std::fs::read_dir(&snapshots)
                .expect("read replacement namespace")
                .count(),
            "the replacement namespace stays untouched"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn detached_cleanup_failure_syncs_its_original_directory_before_acknowledgement() {
        use std::os::unix::fs::MetadataExt as _;

        let _hook_lock = snapshot_artifact_cleanup_test_lock().lock().await;
        let directory = tempfile::tempdir().expect("detached cleanup generation directory");
        let snapshots = directory.path().join("snapshots");
        let retired = directory.path().join("retired-snapshots");
        let backend = SqliteSessionBackend::open(directory.path().join("sessions.sqlite"))
            .expect("detached cleanup generation backend");
        let (log, state_machine) =
            open(&backend, snapshots.clone(), identity(1), expected_members())
                .await
                .expect("open original cleanup namespace");
        let namespace = Arc::clone(&state_machine._snapshot_directory_lease.namespace);

        // O_EXCL succeeds, the emergency owner unlinks the exact child, and
        // only D1's parent fsync fails. The global latch must retain this D1
        // capability even after every ordinary owner is dropped.
        fail_namespace_pinned_post_create_setup_for_test(&namespace);
        fail_retained_namespace_sync_for_test(&namespace);
        assert!(PinnedSqliteFile::create_new_in_namespace(
            Arc::clone(&namespace),
            std::ffi::OsStr::new("build-00000000-0000-4000-8000-000000000001.sqlite"),
        )
        .is_err());
        clear_retained_namespace_sync_observer_for_test(&namespace);
        drop(namespace);
        drop(log);
        drop(state_machine);

        std::fs::rename(&snapshots, &retired).expect("detach failed-cleanup D1");
        std::fs::create_dir(&snapshots).expect("install admissible D2");
        let d1 = std::fs::metadata(&retired).expect("D1 metadata");
        let d2 = std::fs::metadata(&snapshots).expect("D2 metadata");
        assert_ne!(
            (d1.dev(), d1.ino()),
            (d2.dev(), d2.ino()),
            "replacement must be a distinct directory incarnation"
        );

        assert!(
            matches!(
                open(&backend, snapshots.clone(), identity(1), expected_members()).await,
                Err(SessionConsensusStorageError::BackendUnavailable)
            ),
            "the first D2 admission reports the D1 cleanup failure only after syncing D1"
        );
        assert_eq!(
            vec![(d1.dev(), d1.ino())],
            retained_namespace_sync_observer_for_test(&snapshots),
            "acknowledgement fsync targets the detached original directory, never D2"
        );
        assert_eq!(
            0,
            std::fs::read_dir(&snapshots)
                .expect("read replacement namespace")
                .count(),
            "D2 receives no cleanup mutation while D1 durability is retried"
        );
        assert!(
            !has_unpublished_snapshot_cleanup_failure(&snapshots),
            "the D1 failure is acknowledged only after its exact descriptor sync"
        );

        open(&backend, snapshots, identity(1), expected_members())
            .await
            .expect("clean D2 admission after D1 durability was reported");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn detached_preunlink_cleanup_is_reclaimed_by_configured_latch_key_after_parent_symlink_retarget(
    ) {
        use std::os::unix::fs::symlink;
        use std::os::unix::fs::MetadataExt as _;

        let _hook_lock = snapshot_artifact_cleanup_test_lock().lock().await;
        let directory = tempfile::tempdir().expect("symlink retarget cleanup directory");
        let first_parent = directory.path().join("first-parent");
        let second_parent = directory.path().join("second-parent");
        std::fs::create_dir(&first_parent).expect("create first symlink parent");
        std::fs::create_dir(&second_parent).expect("create second symlink parent");
        let configured_parent = directory.path().join("configured-parent");
        symlink(&first_parent, &configured_parent).expect("point configured parent at D1");
        let snapshots = configured_parent.join("snapshots");
        let first_snapshots = first_parent.join("snapshots");
        let second_snapshots = second_parent.join("snapshots");
        let database = directory.path().join("sessions.sqlite");
        let backend = SqliteSessionBackend::open(&database).expect("D1 cleanup backend");
        let (log, state_machine) =
            open(&backend, snapshots.clone(), identity(1), expected_members())
                .await
                .expect("open D1 through configured parent symlink");
        let namespace = Arc::clone(&state_machine._snapshot_directory_lease.namespace);
        let name = std::ffi::OsStr::new("build-00000000-0000-4000-8000-000000000001.sqlite");
        let file = namespace
            .create_new(name, true)
            .expect("create D1 pre-unlink artifact");
        let artifact = SnapshotArtifact::new_in_namespace(
            Arc::clone(&namespace),
            name,
            Arc::new(AtomicBool::new(false)),
        )
        .expect("bind D1 artifact namespace");
        artifact
            .record_identity_from_file(&file)
            .expect("bind D1 artifact identity");
        drop(file);
        snapshot_artifact_cleanup_test_hooks()
            .lock()
            .expect("inject pre-unlink failure")
            .entry(artifact.path().to_path_buf())
            .or_default()
            .fail_before_rename = true;
        assert!(
            artifact.remove().await.is_err(),
            "the deterministic pre-rename failure leaves the owned staging child in D1"
        );
        assert!(
            first_snapshots.join(name).is_file(),
            "D1 retains the exact staging child for descriptor-bound retry"
        );

        // Drop the original owner. The queued cleanup generation and this
        // still-armed artifact retain D1's namespace fd; the raw `flock(2)`
        // lock tied to that OFD must therefore prevent a cooperating SDK
        // instance from acquiring the retired directory while D2 validates
        // and reclaims it.
        drop(log);
        drop(state_machine);
        let retired_backend = SqliteSessionBackend::open(directory.path().join("retired.sqlite"))
            .expect("open independent retired-directory backend");
        assert!(
            acquire_snapshot_directory_lease(&retired_backend, &first_snapshots)
                .await
                .is_err(),
            "a queued D1 cleanup authority retains the directory lease against a cooperating opener"
        );

        std::fs::remove_file(&configured_parent).expect("remove D1 configured parent symlink");
        symlink(&second_parent, &configured_parent).expect("retarget configured parent at D2");
        let d1 = std::fs::metadata(&first_snapshots).expect("D1 metadata");
        assert!(
            !second_snapshots.exists(),
            "D2 does not exist before its new admission creates it"
        );

        clear_retained_namespace_sync_observer_for_test(&namespace);
        assert!(
            matches!(
                open(&backend, snapshots.clone(), identity(1), expected_members()).await,
                Err(SessionConsensusStorageError::BackendUnavailable)
            ),
            "D2 finds the D1 failure through the immutable configured latch key and reports only after exact reclamation"
        );
        assert!(
            std::fs::read_dir(&first_snapshots)
                .expect("read reclaimed D1")
                .next()
                .is_none(),
            "the original D1 staging child is reclaimed through its retained descriptor before acknowledgement"
        );
        assert_eq!(
            0,
            std::fs::read_dir(&second_snapshots)
                .expect("read untouched D2")
                .count(),
            "D2 is never scanned, created in, or deleted from by D1 cleanup"
        );
        let synced = retained_namespace_sync_observer_for_test(&snapshots);
        assert!(
            !synced.is_empty()
                && synced
                    .iter()
                    .all(|identity| *identity == (d1.dev(), d1.ino())),
            "all cleanup durability barriers target D1, never the symlink-retargeted D2"
        );

        // The retained artifact now observes its original name absent and
        // cannot issue a second destructive cleanup. The next D2 admission
        // is clean, proving the exact configured-key generation was drained.
        drop(artifact);
        // This fixture kept an explicit D1 namespace Arc solely to create
        // its staging child. In production the final artifact owner is the
        // last retained D1 fence owner; release the fixture Arc before
        // asserting a clean D2 can bind the now-acknowledged key/database.
        drop(namespace);
        open(&backend, snapshots, identity(1), expected_members())
            .await
            .expect("clean D2 admission after D1 reclaim and acknowledgement");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn admitted_core_handoff_never_canonicalizes_parent_replacement() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("admitted core handoff directory");
        let snapshots = directory.path().join("snapshots");
        let retired = directory.path().join("retired-snapshots");
        let replacement_target = directory.path().join("replacement-target");
        std::fs::create_dir(&snapshots).expect("create initial namespace");
        let logical = std::fs::canonicalize(&snapshots).expect("canonical initial namespace");
        let hook_retired = retired.clone();
        let hook_replacement_target = replacement_target.clone();
        install_snapshot_directory_admission_test_hook(
            logical.clone(),
            Box::new(move |admitted| {
                std::fs::rename(admitted, &hook_retired).expect("detach admitted namespace");
                std::fs::create_dir(&hook_replacement_target).expect("create replacement target");
                symlink(&hook_replacement_target, admitted)
                    .expect("replace configured path with a symlink");
            }),
        );
        let backend = SqliteSessionBackend::open(directory.path().join("sessions.sqlite"))
            .expect("admitted core handoff backend");
        let (_log, mut state_machine) =
            open(&backend, snapshots.clone(), identity(1), expected_members())
                .await
                .expect("core uses the already-admitted logical key without resolving replacement");
        assert_eq!(
            logical.as_path(),
            state_machine.core.snapshot_dir.as_ref(),
            "core retains the lease-captured logical key instead of canonicalizing the replacement symlink"
        );
        let receiver = state_machine
            .begin_receiving_snapshot()
            .await
            .expect("receive remains on detached retained namespace");
        let name = receiver
            .path()
            .file_name()
            .expect("incoming basename")
            .to_owned();
        assert!(retired.join(&name).exists());
        let replacement_target =
            std::fs::read_link(&snapshots).expect("configured replacement remains a symlink");
        assert_eq!(
            0,
            std::fs::read_dir(replacement_target)
                .expect("read replacement target")
                .count(),
            "core handoff and receiver never touch the replacement namespace"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn independently_opened_backend_for_same_database_cannot_bypass_lease() {
        let directory = tempfile::tempdir().expect("independent database lease directory");
        let database = directory.path().join("sessions.sqlite");
        let first_backend = SqliteSessionBackend::open(&database).expect("first backend");
        let second_backend = SqliteSessionBackend::open(&database).expect("second backend");
        let (_first_log, _first_state) = open(
            &first_backend,
            directory.path().join("first-snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("first database owner");
        let second = open(
            &second_backend,
            directory.path().join("second-snapshots"),
            identity(1),
            expected_members(),
        )
        .await;
        assert!(matches!(
            second,
            Err(SessionConsensusStorageError::BackendUnavailable)
        ));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn receiver_retains_namespace_lease_after_storage_wrappers_drop() {
        let directory = tempfile::tempdir().expect("receiver lease lifetime directory");
        let snapshot_directory = directory.path().join("snapshots");
        let backend = SqliteSessionBackend::open(directory.path().join("sessions.sqlite"))
            .expect("receiver lease lifetime backend");
        let (log_store, mut state_machine) = open(
            &backend,
            snapshot_directory.clone(),
            identity(1),
            expected_members(),
        )
        .await
        .expect("receiver lease lifetime storage");
        let receiver = state_machine
            .begin_receiving_snapshot()
            .await
            .expect("receiver retains lease");
        drop(log_store);
        drop(state_machine);
        assert!(matches!(
            open(
                &backend,
                snapshot_directory,
                identity(1),
                expected_members(),
            )
            .await,
            Err(SessionConsensusStorageError::BackendUnavailable)
        ));
        drop(receiver);
    }

    /// Exercise the real test binary as a second process.  The abstract
    /// directory socket is namespace-local, whereas the SQLite-main-file
    /// `flock` is the durable cross-process fence.  This test deliberately
    /// uses a newly opened backend in the child, so it cannot accidentally
    /// inherit the parent's in-process identity registry or open-file
    /// description.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn receiver_lease_excludes_a_separate_process_until_receiver_drop() {
        const CHILD_MODE: &str = "OPC_SESSION_STORE_SNAPSHOT_LEASE_CHILD_MODE";
        const CHILD_DATABASE: &str = "OPC_SESSION_STORE_SNAPSHOT_LEASE_CHILD_DATABASE";
        const CHILD_SNAPSHOTS: &str = "OPC_SESSION_STORE_SNAPSHOT_LEASE_CHILD_SNAPSHOTS";
        const TEST_NAME: &str = "consensus::storage::tests::receiver_lease_excludes_a_separate_process_until_receiver_drop";

        if let Ok(mode) = std::env::var(CHILD_MODE) {
            let database = std::path::PathBuf::from(
                std::env::var(CHILD_DATABASE).expect("child database path"),
            );
            let snapshots = std::path::PathBuf::from(
                std::env::var(CHILD_SNAPSHOTS).expect("child snapshot path"),
            );
            let backend = SqliteSessionBackend::open(database).expect("child opens fresh backend");
            let admitted = open(&backend, snapshots, identity(1), expected_members())
                .await
                .is_ok();
            match mode.as_str() {
                "blocked" => assert!(
                    !admitted,
                    "the child's distinct SQLite open must observe the held parent lease"
                ),
                "admitted" => assert!(
                    admitted,
                    "the child may acquire only after the receiver releases the final lease"
                ),
                unexpected => panic!("unexpected snapshot lease child mode: {unexpected}"),
            }
            return;
        }

        let directory = tempfile::tempdir().expect("cross-process lease directory");
        let database = directory.path().join("sessions.sqlite");
        let snapshots = directory.path().join("snapshots");
        let backend = SqliteSessionBackend::open(&database).expect("parent backend");
        let (log_store, mut state_machine) =
            open(&backend, snapshots.clone(), identity(1), expected_members())
                .await
                .expect("parent opens snapshot namespace");
        let receiver = state_machine
            .begin_receiving_snapshot()
            .await
            .expect("receiver keeps namespace lease alive");
        drop(log_store);
        drop(state_machine);

        let run_child = |mode: &str| {
            std::process::Command::new(std::env::current_exe().expect("test executable"))
                .arg(TEST_NAME)
                .arg("--exact")
                .arg("--nocapture")
                .env(CHILD_MODE, mode)
                .env(CHILD_DATABASE, &database)
                .env(CHILD_SNAPSHOTS, &snapshots)
                .output()
                .expect("run separate-process lease child")
        };

        let blocked = run_child("blocked");
        assert!(
            blocked.status.success(),
            "fresh child backend bypassed a live receiver lease: {}",
            String::from_utf8_lossy(&blocked.stderr)
        );
        drop(receiver);
        let admitted = run_child("admitted");
        assert!(
            admitted.status.success(),
            "fresh child backend remained excluded after receiver release: {}",
            String::from_utf8_lossy(&admitted.stderr)
        );
    }

    #[tokio::test]
    async fn replaced_configured_snapshot_directory_cannot_admit_a_second_owner() {
        let directory = tempfile::tempdir().expect("lease replacement directory");
        let snapshot_directory = directory.path().join("snapshots");
        let backend = SqliteSessionBackend::open(directory.path().join("sessions.sqlite"))
            .expect("lease replacement backend");
        let (_log, _owner) = open(
            &backend,
            snapshot_directory.clone(),
            identity(1),
            expected_members(),
        )
        .await
        .expect("open original owner");

        std::fs::rename(
            &snapshot_directory,
            directory.path().join("snapshots-renamed"),
        )
        .expect("rename owned directory");
        std::fs::create_dir(&snapshot_directory).expect("create configured-path replacement");
        let second = open(
            &backend,
            snapshot_directory,
            identity(1),
            expected_members(),
        )
        .await;
        assert!(
            matches!(
                second,
                Err(SessionConsensusStorageError::BackendUnavailable)
            ),
            "the parent-scoped admission lock rejects a replacement directory"
        );
    }

    #[tokio::test]
    async fn distinct_snapshot_directories_under_one_parent_admit_independently() {
        let directory = tempfile::tempdir().expect("sibling namespace parent");
        let first_backend = SqliteSessionBackend::open(directory.path().join("first.sqlite"))
            .expect("first sibling backend");
        let second_backend = SqliteSessionBackend::open(directory.path().join("second.sqlite"))
            .expect("second sibling backend");
        let (_first_log, _first_state) = open(
            &first_backend,
            directory.path().join("first-snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("first sibling namespace");
        let (_second_log, _second_state) = open(
            &second_backend,
            directory.path().join("second-snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("second sibling namespace");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_snapshot_build_retains_its_single_worker_ownership() {
        let directory = tempfile::tempdir().expect("snapshot cancellation directory");
        let backend = SqliteSessionBackend::open(directory.path().join("sessions.sqlite"))
            .expect("snapshot cancellation backend");
        let (log_store, mut state_machine) = open(
            &backend,
            directory.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("snapshot cancellation storage");
        let shutdown_observer = state_machine
            .shutdown_observer()
            .expect("snapshot wrappers share a shutdown observer");
        state_machine
            .apply([initial_membership_entry()])
            .await
            .expect("snapshot cancellation membership");

        let capture_gate = backend.snapshot_capture_gate();
        let core = state_machine.core.clone();
        for _ in 0..3 {
            capture_gate.arm();
            let mut builder = state_machine.get_snapshot_builder().await;
            let build = tokio::spawn(async move { builder.build_snapshot().await });
            tokio::time::timeout(Duration::from_secs(5), capture_gate.wait_started())
                .await
                .expect("snapshot worker reaches its fixed source cut");

            build.abort();
            assert!(
                build
                    .await
                    .expect_err("snapshot future is cancelled")
                    .is_cancelled(),
                "the fixture must cancel only the async snapshot caller"
            );
            assert!(
                Arc::clone(&core.snapshot_gate).try_lock_owned().is_err(),
                "the detached blocking capture must retain the sole snapshot owner"
            );

            capture_gate.release();
            let worker_released = tokio::time::timeout(
                Duration::from_secs(5),
                Arc::clone(&core.snapshot_gate).lock_owned(),
            )
            .await
            .expect("cancelled snapshot worker exits within the existing bounded test window");
            drop(worker_released);
        }
        assert_eq!(
            0,
            core.snapshot_observation.snapshot().3,
            "a cancelled caller must not publish successful snapshot status"
        );
        let mut entries = tokio::fs::read_dir(core.snapshot_dir.as_ref())
            .await
            .expect("read bounded snapshot artifacts");
        assert!(
            entries
                .next_entry()
                .await
                .expect("read artifact entry")
                .is_none(),
            "repeated cancelled workers leave no staged artifact after their RAII owners exit"
        );

        let mut successful_builder = state_machine.get_snapshot_builder().await;
        let successful = successful_builder
            .build_snapshot()
            .await
            .expect("subsequent snapshot succeeds after cancellation");
        drop(successful);
        drop(successful_builder);
        assert_eq!(
            1,
            core.snapshot_observation.snapshot().3,
            "only the returned, durable snapshot advances completion status"
        );

        capture_gate.arm();
        let mut cancelled_builder = state_machine.get_snapshot_builder().await;
        let cancelled = tokio::spawn(async move { cancelled_builder.build_snapshot().await });
        tokio::time::timeout(Duration::from_secs(5), async {
            while !capture_gate.started() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("final snapshot worker reaches its fixed source cut");
        cancelled.abort();
        assert!(cancelled
            .await
            .expect_err("final snapshot future is cancelled")
            .is_cancelled());

        let shutdown_waiter = tokio::spawn({
            let observer = shutdown_observer.clone();
            async move { observer.wait().await }
        });
        tokio::task::yield_now().await;
        drop(log_store);
        drop(state_machine);
        assert_eq!(
            shutdown_observer.0.active_owners.load(Ordering::Acquire),
            1,
            "the detached WAL reader remains the final SQLite owner"
        );
        assert!(
            !shutdown_waiter.is_finished(),
            "shutdown must remain pending while detached capture owns SQLite"
        );

        capture_gate.release();
        let worker_released = tokio::time::timeout(
            Duration::from_secs(5),
            Arc::clone(&core.snapshot_gate).lock_owned(),
        )
        .await
        .expect("final cancelled snapshot worker exits within the bounded window");
        drop(worker_released);
        tokio::time::timeout(Duration::from_secs(1), shutdown_waiter)
            .await
            .expect("shutdown observes detached snapshot worker exit")
            .expect("shutdown observer task remains available");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn detached_capture_worker_retains_namespace_lease_after_wrappers_drop() {
        let directory = tempfile::tempdir().expect("detached worker lease directory");
        let snapshot_directory = directory.path().join("snapshots");
        let backend = SqliteSessionBackend::open(directory.path().join("sessions.sqlite"))
            .expect("detached worker lease backend");
        let (log_store, mut state_machine) = open(
            &backend,
            snapshot_directory.clone(),
            identity(1),
            expected_members(),
        )
        .await
        .expect("detached worker lease storage");
        state_machine
            .apply([initial_membership_entry()])
            .await
            .expect("detached worker membership");
        let gate = backend.snapshot_capture_gate();
        gate.arm();
        let mut builder = state_machine.get_snapshot_builder().await;
        let build = tokio::spawn(async move { builder.build_snapshot().await });
        gate.wait_started().await;
        build.abort();
        assert!(build.await.expect_err("cancelled builder").is_cancelled());
        drop(log_store);
        drop(state_machine);
        assert!(matches!(
            open(
                &backend,
                snapshot_directory,
                identity(1),
                expected_members(),
            )
            .await,
            Err(SessionConsensusStorageError::BackendUnavailable)
        ));
        gate.release();
    }
}
