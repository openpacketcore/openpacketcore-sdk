//! Durable SQLite implementation of the storage and lease APIs.
//!
//! Intended for single-node and edge/single-replica profiles: it provides
//! transactional fenced CAS, monotonic per-key fences, server-side lease
//! expiry, and per-key TTL on one local database file (WAL mode, full sync).
//! Application-journal replay and watch remain for standalone compatibility.
//! Once the durable consensus identity claims a database, every public raw
//! backend operation fails closed; Openraft's internal state-machine adapter
//! is the only mutation and read-authority path.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
#[cfg(feature = "test-vfs")]
use std::sync::Condvar;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use async_trait::async_trait;
use rusqlite::{
    params, Connection, InterruptHandle, OptionalExtension, Transaction, TransactionBehavior,
};

use crate::consensus::store::ConsensusStoreDiagnosticCounters;
use crate::{
    backend::{
        validate_replication_log_page_owned, validate_replication_prefix_owned,
        validate_session_ops_at, BackendInstanceIdentity, CompareAndSet, CompareAndSetResult,
        ReplicationEntry, ReplicationLogRange, ReplicationWatchCursor, SessionBackend, SessionOp,
        SessionOpResult, REPLICATION_TX_ID_MAX_BYTES, REPLICATION_TX_ID_MIN_BYTES,
    },
    capability::BackendCapabilities,
    clock::Clock,
    error::{LeaseError, StoreError},
    lease::{LeaseGuard, SessionLeaseManager},
    model::{OwnerId, SessionKey},
    record::{SessionPayloadEncoding, StoredSessionRecord},
    replication_watch::{
        prepare_watch_registration, watch_backlog_query_limit, ReplicationWatcher,
    },
    restore::{RestoreScanPage, RestoreScanRequest},
    ttl::{checked_session_deadline, validate_session_ttl, validate_stored_record_expiry_at},
};

pub mod audit;
pub(crate) mod consensus;

/// Non-production consensus timing hooks for deterministic integration tests.
#[cfg(feature = "test-control")]
#[doc(hidden)]
pub mod test_support {
    pub use super::consensus::{
        protected_roster_terminal_apply_timing_test_guard,
        protected_roster_terminal_apply_timings_for_test,
        reset_protected_roster_terminal_apply_timings_for_test,
        ProtectedRosterTerminalApplyTimings,
    };
}

pub(crate) mod lease;
pub(crate) mod ops;
pub(crate) mod replication;

#[cfg(all(test, target_os = "linux"))]
std::thread_local! {
    static REGULAR_READ_OPEN_ATTEMPTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) fn reset_regular_read_open_attempts_for_test() {
    REGULAR_READ_OPEN_ATTEMPTS.with(|attempts| attempts.set(0));
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) fn regular_read_open_attempts_for_test() -> usize {
    REGULAR_READ_OPEN_ATTEMPTS.with(std::cell::Cell::get)
}

/// Open a regular file through a descriptor-stable nofollow gate.
///
/// Linux first opens `path` as `O_PATH|O_NOFOLLOW`, rejects non-regular
/// objects with fstat, then opens `/proc/self/fd/<pin>` for read and compares
/// the resulting descriptor to that held object.  This prevents a FIFO,
/// device, socket, or pathname replacement from gaining a readable-open
/// authority before the regular-file check has happened.
pub(crate) fn open_regular_read_nofollow(path: &Path) -> std::io::Result<File> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

        let mut path_options = OpenOptions::new();
        path_options.read(true);
        path_options.custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let path_pin = path_options.open(path)?;
        let pinned_metadata = path_pin.metadata()?;
        if !pinned_metadata.is_file() {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
        }

        let descriptor_path = PathBuf::from(format!("/proc/self/fd/{}", path_pin.as_raw_fd()));
        let mut read_options = OpenOptions::new();
        read_options.read(true);
        // This procfs magic link is the held O_PATH descriptor, rather than
        // an untrusted name. O_NOFOLLOW would reject the magic link itself;
        // the fstat comparison below proves the returned reader is exact.
        read_options.custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK);
        #[cfg(test)]
        REGULAR_READ_OPEN_ATTEMPTS.with(|attempts| attempts.set(attempts.get() + 1));
        let file = read_options.open(descriptor_path)?;
        let observed = file.metadata()?;
        if !observed.is_file()
            || observed.dev() != pinned_metadata.dev()
            || observed.ino() != pinned_metadata.ino()
        {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
        }
        Ok(file)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
        }
        let file = options.open(path)?;
        if !file.metadata()?.is_file() {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
        }
        Ok(file)
    }
}

const SQLITE_SESSION_MAX_VALUE_BYTES: usize = 4 * 1024 * 1024 + 64 * 1024;
// Consensus retains its existing value profile until #683 raises the shared
// command/RPC and consumer-response ceilings together. Advertising the raw
// SQLite limit through that adapter would accept values its 2 MiB transport
// cannot propose and would disable every record-bearing consumer batch.
pub(crate) const SQLITE_CONSENSUS_MAX_VALUE_BYTES: usize = 1_048_576;
const CONSENSUS_AUTHORITY_REQUIRED: &str = "consensus_authority_required";
const RESTORE_SCAN_BLOCKING_WORKERS: usize = 1;
const SQLITE_OPERATION_BLOCKING_WORKERS: usize = 1;
// Fixed at the store scope, rather than at a consumer or subscriber scope.
// Three lanes let two independent exact acceptance snapshots progress while a
// third has a bounded in-flight SQLite operation.
const SQLITE_CONSENSUS_ACCEPTANCE_READ_WORKERS: usize = 3;
const SQLITE_OPERATION_MAX_WORK: Duration = Duration::from_secs(2);
const SQLITE_BUSY_TIMEOUT_MILLIS: u64 = 100;
const SQLITE_OPERATION_PROGRESS_INTERVAL: i32 = 1_000;
// Keep the file-backed writer's automatic WAL checkpoint threshold explicit.
// This is SQLite's default, but the writer owns checkpoint policy rather than
// acceptance readers, whose return path must remain a pure health check.
const SQLITE_WRITER_WAL_AUTOCHECKPOINT_PAGES: i32 = 1_000;

#[cfg(feature = "test-vfs")]
#[derive(Default)]
struct ProactiveCheckpointIdleWaitState {
    armed: bool,
    entered: bool,
    released: bool,
}

/// Feature-gated deterministic seam for the checkpoint worker's idle receive.
///
/// It is only available to the real-file test VFS qualification. The guard
/// pauses the worker after its durable-work cancellation check and before it
/// registers its next receive, which makes retained shutdown state testable.
#[cfg(feature = "test-vfs")]
#[doc(hidden)]
pub struct ProactiveCheckpointIdleWaitForTest {
    hook: Arc<ProactiveCheckpointIdleWaitHook>,
}

#[cfg(feature = "test-vfs")]
struct ProactiveCheckpointIdleWaitHook {
    state: StdMutex<ProactiveCheckpointIdleWaitState>,
    entered: Condvar,
    released: Condvar,
}

#[cfg(feature = "test-vfs")]
impl Default for ProactiveCheckpointIdleWaitHook {
    fn default() -> Self {
        Self {
            state: StdMutex::new(ProactiveCheckpointIdleWaitState::default()),
            entered: Condvar::new(),
            released: Condvar::new(),
        }
    }
}

#[cfg(feature = "test-vfs")]
impl ProactiveCheckpointIdleWaitHook {
    fn arm(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.armed = true;
        state.entered = false;
        state.released = false;
    }

    fn wait_before_receive(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state.armed {
            return;
        }
        state.entered = true;
        self.entered.notify_all();
        while !state.released {
            state = self
                .released
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        state.armed = false;
    }

    fn release(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.released = true;
        self.released.notify_all();
    }
}

#[cfg(feature = "test-vfs")]
impl ProactiveCheckpointIdleWaitForTest {
    /// Wait until the selected lane has reached the exact idle-receive seam.
    pub fn wait_until_entered(&self, timeout: Duration) -> bool {
        let state = self
            .hook
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (state, _) = self
            .hook
            .entered
            .wait_timeout_while(state, timeout, |state| !state.entered)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.entered
    }

    /// Release the idle-receive seam.
    pub fn release(&self) {
        self.hook.release();
    }
}

#[cfg(feature = "test-vfs")]
impl Drop for ProactiveCheckpointIdleWaitForTest {
    fn drop(&mut self) {
        self.release();
    }
}

#[cfg(feature = "test-vfs")]
#[derive(Default)]
struct ProactiveCheckpointShutdownJoinState {
    armed: bool,
    entered: bool,
}

#[cfg(feature = "test-vfs")]
struct ProactiveCheckpointShutdownJoinHook {
    state: StdMutex<ProactiveCheckpointShutdownJoinState>,
    entered: Condvar,
}

#[cfg(feature = "test-vfs")]
impl Default for ProactiveCheckpointShutdownJoinHook {
    fn default() -> Self {
        Self {
            state: StdMutex::new(ProactiveCheckpointShutdownJoinState::default()),
            entered: Condvar::new(),
        }
    }
}

#[cfg(feature = "test-vfs")]
impl ProactiveCheckpointShutdownJoinHook {
    fn arm(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.armed = true;
        state.entered = false;
    }

    fn observe(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.armed {
            state.entered = true;
            self.entered.notify_all();
        }
    }
}

/// Feature-gated observation of the checkpoint-worker join boundary.
///
/// This test-only seam marks the point after a shutdown owns the shared join
/// slot and immediately before it awaits the worker. It does not pause or
/// alter the worker.
#[cfg(feature = "test-vfs")]
#[doc(hidden)]
pub struct ProactiveCheckpointShutdownJoinForTest {
    hook: Arc<ProactiveCheckpointShutdownJoinHook>,
}

#[cfg(feature = "test-vfs")]
impl ProactiveCheckpointShutdownJoinForTest {
    /// Wait until shutdown begins awaiting the retained worker join handle.
    pub fn wait_until_entered(&self, timeout: Duration) -> bool {
        let state = self
            .hook
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (state, _) = self
            .hook
            .entered
            .wait_timeout_while(state, timeout, |state| !state.entered)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.entered
    }
}

#[cfg(feature = "test-vfs")]
struct ProactiveCheckpointWorkerObservation {
    active_workers: AtomicUsize,
    sender: tokio::sync::watch::Sender<usize>,
}

#[cfg(feature = "test-vfs")]
impl ProactiveCheckpointWorkerObservation {
    fn new() -> Self {
        let (sender, _) = tokio::sync::watch::channel(0);
        Self {
            active_workers: AtomicUsize::new(0),
            sender,
        }
    }

    fn begin(self: &Arc<Self>) -> ProactiveCheckpointWorkerObservationGuard {
        let active = self
            .active_workers
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1);
        self.sender.send_replace(active);
        ProactiveCheckpointWorkerObservationGuard {
            observation: Arc::clone(self),
        }
    }

    fn end(&self) {
        let active = self
            .active_workers
            .fetch_sub(1, Ordering::AcqRel)
            .saturating_sub(1);
        self.sender.send_replace(active);
    }

    fn subscribe(&self) -> tokio::sync::watch::Receiver<usize> {
        self.sender.subscribe()
    }
}

#[cfg(feature = "test-vfs")]
struct ProactiveCheckpointWorkerObservationGuard {
    observation: Arc<ProactiveCheckpointWorkerObservation>,
}

#[cfg(feature = "test-vfs")]
impl Drop for ProactiveCheckpointWorkerObservationGuard {
    fn drop(&mut self) {
        self.observation.end();
    }
}

/// Feature-gated, redaction-free worker-liveness observation for a test.
///
/// A lane has exactly one task, so this only exposes the bounded `0` or `1`
/// lifecycle count; it carries no database identity, path, or error value.
#[cfg(feature = "test-vfs")]
#[doc(hidden)]
pub struct ProactiveCheckpointWorkerObservationForTest {
    receiver: tokio::sync::watch::Receiver<usize>,
}

#[cfg(feature = "test-vfs")]
impl ProactiveCheckpointWorkerObservationForTest {
    /// Wait for this store's fixed checkpoint worker count.
    pub async fn wait_for_worker_count(&mut self, expected: usize) -> bool {
        loop {
            if *self.receiver.borrow() == expected {
                return true;
            }
            if self.receiver.changed().await.is_err() {
                return false;
            }
        }
    }
}

pub(crate) fn validate_consensus_record(record: &StoredSessionRecord) -> Result<(), StoreError> {
    let actual = record.payload.len();
    if actual > SQLITE_CONSENSUS_MAX_VALUE_BYTES {
        return Err(StoreError::PayloadTooLarge {
            actual,
            max: SQLITE_CONSENSUS_MAX_VALUE_BYTES,
        });
    }
    if record.payload.encoding() != SessionPayloadEncoding::EnvelopeV1 {
        return Err(StoreError::Crypto(
            "session consensus requires a sealed payload".into(),
        ));
    }
    record.payload.validate_envelope_for_record(record)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RestoreScanValidationProfile {
    Standalone,
    Consensus,
}

/// Result of the fixed-quorum V2 status acceptance read.
///
/// `Unactivated` is deliberately distinct from an unavailable authority: the
/// caller may obtain the one-shot unanimous V2 proof and repeat the same
/// atomic authority/status read.  A normal status is never returned until the
/// immutable authority, recovery state, and (when requested) exact activation
/// certificate have all been observed in one SQLite transaction.
#[derive(Debug)]
#[allow(dead_code)] // Retained singleton adapter for internal generic callers.
pub(crate) enum FixedQuorumFencedTransitionV2StatusRead {
    Activated(crate::FencedTransitionV2Status),
    Unactivated,
}

/// Result of one atomic fixed-quorum V2 status cohort acceptance read.
///
/// The vector preserves the caller's admitted order.  It is never retained
/// after the one SQLite snapshot has been fanned back to that cohort.
#[derive(Debug)]
pub(crate) enum FixedQuorumFencedTransitionV2StatusBatchRead {
    Activated(Vec<crate::FencedTransitionV2Status>),
    Unactivated,
}

/// Atomic fixed-quorum admission facts for a raw V2 mutation proposal.
///
/// `Activated` carries the durable state machine's currently applied logical
/// time. The leader must derive its command time from this fresh snapshot; it
/// must not reuse a logical-time read made before the exact authority and V2
/// activation checks. `Unactivated` is a normal result that lets the caller
/// take the existing one-shot unanimous activation path. It never means that
/// authority, recovery, or a mismatched V2 profile was accepted.
#[derive(Debug)]
pub(crate) enum FixedQuorumActivatedV2MutationSnapshot {
    Activated {
        /// Last logical time applied by the durable consensus state machine.
        applied_logical_time: Option<opc_types::Timestamp>,
    },
    Unactivated,
}

/// Immutable inputs revalidated together before a raw V2 mutation proposal.
///
/// This is an owned caller snapshot only; the durable authority, recovery
/// state, V2 activation certificate, and logical time are always read again
/// in one SQLite transaction.
pub(crate) struct FixedQuorumActivatedV2MutationSnapshotRequest {
    pub(crate) storage_identity: crate::consensus::SessionConsensusIdentity,
    pub(crate) scope_identity: crate::consensus::SessionConsensusIdentity,
    pub(crate) voters: std::collections::BTreeSet<crate::consensus::SessionConsensusNodeId>,
    pub(crate) expected_members:
        std::collections::BTreeSet<crate::consensus::SessionConsensusNodeId>,
    pub(crate) expected_bindings: std::collections::BTreeMap<
        crate::consensus::SessionConsensusNodeId,
        crate::consensus::SessionTopologyMemberBinding,
    >,
    pub(crate) expected_placement_policy: crate::readiness::PlacementResiliencePolicy,
    pub(crate) profile_digest: [u8; 32],
}

/// Fixed inputs that must be revalidated with a consumer V2 status result.
///
/// This is intentionally an owned snapshot from the caller: every invocation
/// still re-reads durable authority and recovery state; none of these values
/// cache that decision across calls.
pub(crate) struct FixedQuorumFencedTransitionV2StatusReadRequest {
    pub(crate) storage_identity: crate::consensus::SessionConsensusIdentity,
    pub(crate) scope_identity: crate::consensus::SessionConsensusIdentity,
    pub(crate) voters: std::collections::BTreeSet<crate::consensus::SessionConsensusNodeId>,
    pub(crate) expected_members:
        std::collections::BTreeSet<crate::consensus::SessionConsensusNodeId>,
    pub(crate) expected_bindings: std::collections::BTreeMap<
        crate::consensus::SessionConsensusNodeId,
        crate::consensus::SessionTopologyMemberBinding,
    >,
    pub(crate) expected_placement_policy: crate::readiness::PlacementResiliencePolicy,
    pub(crate) profile_digest: [u8; 32],
    pub(crate) require_activation: bool,
}

impl RestoreScanValidationProfile {
    const fn is_standalone(self) -> bool {
        matches!(self, Self::Standalone)
    }

    const fn max_payload_bytes(self) -> usize {
        match self {
            Self::Standalone => crate::RESTORE_SCAN_MAX_LOCAL_PAGE_PAYLOAD_BYTES,
            Self::Consensus => SQLITE_CONSENSUS_MAX_VALUE_BYTES,
        }
    }

    fn validate_record(self, record: &StoredSessionRecord) -> Result<(), StoreError> {
        match self {
            Self::Standalone => Ok(()),
            Self::Consensus => validate_consensus_record(record),
        }
    }
}

/// Begin one standalone operation while holding SQLite's write reservation.
///
/// The immediate transaction is the hand-off fence between the standalone
/// backend and consensus admission, including when another process opens the
/// same database through a distinct `Connection`. If consensus admission wins
/// first, the durable identity marker is visible and this operation fails. If
/// this operation wins first, admission waits and then either observes an
/// empty compatible database or rejects its newly written legacy authority.
fn standalone_transaction(conn: &Connection) -> Result<Transaction<'_>, StoreError> {
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)
        .map_err(|_| StoreError::BackendUnavailable("session store operation failed".into()))?;
    let consensus_owned = consensus_identity_exists(&tx)?;
    if consensus_owned || operator_recovery_latch_exists(&tx)? {
        return Err(StoreError::CapabilityNotSupported(
            CONSENSUS_AUTHORITY_REQUIRED.into(),
        ));
    }
    Ok(tx)
}

fn operator_recovery_latch_exists(conn: &Connection) -> Result<bool, StoreError> {
    let database_path: String = conn
        .query_row(
            "SELECT file FROM pragma_database_list WHERE name = 'main'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| StoreError::BackendUnavailable("session store operation failed".into()))?;
    if database_path.is_empty() {
        return Ok(false);
    }
    consensus::classify_operator_recovery_latch_with_connection_sync(
        Path::new(&database_path),
        conn,
    )
    .map(|classification| classification.latch().is_some())
    .map_err(|_| StoreError::BackendUnavailable("session store operation failed".into()))
}

fn consensus_identity_exists(conn: &Connection) -> Result<bool, StoreError> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'consensus_identity')",
        [],
        |row| row.get(0),
    )
    .map_err(|_| StoreError::BackendUnavailable("session store operation failed".into()))
}

/// SQLite-backed durable session backend and lease manager.
///
/// This backend is intended for single-node and edge/single-replica profiles. It
/// provides durable CAS, fencing, leases, TTL refresh, and sequential batch
/// operations, but it does not provide a backend watch stream or ordered
/// replication log.
#[derive(Clone)]
#[allow(clippy::type_complexity)]
pub struct SqliteSessionBackend {
    conn: Arc<tokio::sync::Mutex<Connection>>,
    // A recovered terminal snapshot stays pinned from the connection-aware
    // latch classifier through the first consensus-core initialization.  That
    // core alone consumes the pending terminal record after using this exact
    // descriptor; clones share the one-shot handoff rather than reopening the
    // selected pathname.
    terminal_recovery_handoff: Arc<StdMutex<Option<consensus::OperatorRecoveryTerminalHandoff>>>,
    // File-backed consensus acceptance reads use fixed WAL reader lanes instead
    // of waiting behind Raft log/state-machine writes on `conn`. This is a
    // store-level resource shared by every clone, never a caller or subscriber
    // allocation. In-memory stores retain their single-connection behavior.
    consensus_acceptance_reader_pool: Option<Arc<ConsensusAcceptanceReaderPool>>,
    database_path: Option<Arc<PathBuf>>,
    // The selected VFS is normally SQLite's default. The feature-gated RED
    // fixture supplies its explicit test VFS here so the store-scoped
    // checkpoint lane observes the same real-file durability boundary as the
    // primary writer. This is not user configuration and is never populated
    // by production construction.
    checkpoint_vfs_name: Option<Arc<str>>,
    #[cfg(feature = "test-vfs")]
    proactive_checkpoint_idle_wait_hook: Arc<ProactiveCheckpointIdleWaitHook>,
    #[cfg(feature = "test-vfs")]
    proactive_checkpoint_worker_observation: Arc<ProactiveCheckpointWorkerObservation>,
    #[cfg(feature = "test-vfs")]
    proactive_checkpoint_shutdown_join_hook: Arc<ProactiveCheckpointShutdownJoinHook>,
    consensus_snapshot_observation: Arc<consensus::SnapshotBuildObservation>,
    caps: BackendCapabilities,
    clock: Arc<dyn Clock>,
    restore_scan_workers: Arc<tokio::sync::Semaphore>,
    operation_workers: Arc<tokio::sync::Semaphore>,
    consensus_diagnostics: Option<Arc<ConsensusStoreDiagnosticCounters>>,
    #[cfg(test)]
    pub(crate) consensus_apply_gate: Arc<tokio::sync::Semaphore>,
    #[cfg(test)]
    consensus_snapshot_capture_gate: Arc<consensus::SnapshotCaptureGate>,
    #[cfg(test)]
    consensus_operator_recovery_failure: Arc<AtomicBool>,
    #[cfg(test)]
    fixed_quorum_v2_mutation_snapshot_cut: Arc<AtomicBool>,
    #[cfg(test)]
    pub(crate) fixed_quorum_durable_check_count: Arc<AtomicUsize>,
    watchers: Arc<tokio::sync::Mutex<Vec<ReplicationWatcher>>>,
    #[cfg(test)]
    pub(crate) watch_registration_gate: Arc<tokio::sync::Semaphore>,
    #[cfg(test)]
    pub(crate) watch_backlog_captured: Arc<AtomicBool>,
}

struct RestoreScanCancellation {
    cancellation: Arc<AtomicBool>,
    abort: tokio::task::AbortHandle,
    cancel_queued: Option<Box<dyn FnOnce() + Send>>,
    armed: bool,
}

impl RestoreScanCancellation {
    fn disarm(&mut self) {
        self.armed = false;
        self.cancel_queued = None;
    }
}

impl Drop for RestoreScanCancellation {
    fn drop(&mut self) {
        if self.armed {
            self.cancellation.store(true, Ordering::Release);
            if let Some(cancel_queued) = self.cancel_queued.take() {
                cancel_queued();
            }
            self.abort.abort();
        }
    }
}

struct SqliteOperationCancellation {
    cancellation: Arc<AtomicBool>,
    interrupt: InterruptHandle,
    abort: tokio::task::AbortHandle,
    cancel_queued: Option<Box<dyn FnOnce() + Send>>,
    armed: bool,
}

impl SqliteOperationCancellation {
    fn disarm(&mut self) {
        self.armed = false;
        self.cancel_queued = None;
    }
}

impl Drop for SqliteOperationCancellation {
    fn drop(&mut self) {
        if self.armed {
            self.cancellation.store(true, Ordering::Release);
            self.interrupt.interrupt();
            if let Some(cancel_queued) = self.cancel_queued.take() {
                cancel_queued();
            }
            // A running blocking job ignores abort and remains bounded by its
            // SQLite interrupt/progress handler.
            self.abort.abort();
        }
    }
}

struct SqliteOperationProgressGuard<'a>(&'a Connection);

impl Drop for SqliteOperationProgressGuard<'_> {
    fn drop(&mut self) {
        self.0.progress_handler(0, None::<fn() -> bool>);
    }
}

/// Fixed, process-scoped WAL readers for exact consensus acceptance snapshots.
///
/// A checked-out connection is owned by exactly one blocking task. Returning
/// it through the bounded channel makes reuse exclusive without holding a
/// process-wide execution lock. A failed reset retires the lane; a replacement
/// is admitted only after its WAL profile has been installed successfully.
struct ConsensusAcceptanceReaderPool {
    sender: tokio::sync::mpsc::Sender<Connection>,
    receiver: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Connection>>,
    workers: Arc<tokio::sync::Semaphore>,
    database_path: Arc<PathBuf>,
    usable_lanes: AtomicUsize,
    #[cfg(test)]
    retire_next_reader: AtomicBool,
    #[cfg(test)]
    fail_replenishment: AtomicBool,
}

impl ConsensusAcceptanceReaderPool {
    fn new(database_path: Arc<PathBuf>) -> Result<Arc<Self>, StoreError> {
        let (sender, receiver) =
            tokio::sync::mpsc::channel(SQLITE_CONSENSUS_ACCEPTANCE_READ_WORKERS);
        for _ in 0..SQLITE_CONSENSUS_ACCEPTANCE_READ_WORKERS {
            let reader = Connection::open(database_path.as_ref())
                .map_err(|error| StoreError::BackendUnavailable(error.to_string()))?;
            apply_pragma_profile(&reader, false, false)?;
            sender.try_send(reader).map_err(|_| {
                StoreError::BackendUnavailable("session acceptance reader pool unavailable".into())
            })?;
        }
        Ok(Arc::new(Self {
            sender,
            receiver: tokio::sync::Mutex::new(receiver),
            workers: Arc::new(tokio::sync::Semaphore::new(
                SQLITE_CONSENSUS_ACCEPTANCE_READ_WORKERS,
            )),
            database_path,
            usable_lanes: AtomicUsize::new(SQLITE_CONSENSUS_ACCEPTANCE_READ_WORKERS),
            #[cfg(test)]
            retire_next_reader: AtomicBool::new(false),
            #[cfg(test)]
            fail_replenishment: AtomicBool::new(false),
        }))
    }

    async fn checkout(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<Connection, SqliteWorkerFailure> {
        let mut receiver = tokio::time::timeout_at(deadline, self.receiver.lock())
            .await
            .map_err(|_| SqliteWorkerFailure::Admission)?;
        tokio::time::timeout_at(deadline, receiver.recv())
            .await
            .map_err(|_| SqliteWorkerFailure::Admission)?
            .ok_or(SqliteWorkerFailure::Admission)
    }

    fn connection_is_usable(&self, conn: &Connection) -> bool {
        #[cfg(test)]
        if self.retire_next_reader.swap(false, Ordering::AcqRel) {
            return false;
        }
        conn.is_autocommit()
            && conn
                .query_row("SELECT 1", [], |row| row.get::<_, i64>(0))
                .is_ok()
    }

    fn replenish(&self) -> Option<Connection> {
        #[cfg(test)]
        if self.fail_replenishment.load(Ordering::Acquire) {
            return None;
        }
        let reader = Connection::open(self.database_path.as_ref()).ok()?;
        apply_pragma_profile(&reader, false, false).ok()?;
        Some(reader)
    }

    fn return_or_retire(
        &self,
        reader: Connection,
        worker_permit: tokio::sync::OwnedSemaphorePermit,
    ) {
        if self.connection_is_usable(&reader) && self.sender.try_send(reader).is_ok() {
            return;
        }
        if let Some(replacement) = self.replenish() {
            if self.sender.try_send(replacement).is_ok() {
                return;
            }
        }
        self.usable_lanes.fetch_sub(1, Ordering::AcqRel);
        // A lane that cannot be safely replenished must not leave a phantom
        // permit that could admit work without a usable reader.
        worker_permit.forget();
    }

    #[cfg(test)]
    fn usable_lanes(&self) -> usize {
        self.usable_lanes.load(Ordering::Acquire)
    }
}

/// Owns one checked-out reader and its matching admission permit. Dropping a
/// lease is deliberately fail-closed: panics, task cancellation, and join
/// failure all return a healthy lane or retire the lane and its permit.
struct ConsensusAcceptanceReaderLease {
    pool: Arc<ConsensusAcceptanceReaderPool>,
    reader: Option<Connection>,
    worker_permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl ConsensusAcceptanceReaderLease {
    fn new(
        pool: Arc<ConsensusAcceptanceReaderPool>,
        reader: Connection,
        worker_permit: tokio::sync::OwnedSemaphorePermit,
    ) -> Self {
        Self {
            pool,
            reader: Some(reader),
            worker_permit: Some(worker_permit),
        }
    }

    fn connection(&self) -> Option<&Connection> {
        self.reader.as_ref()
    }

    fn complete(mut self) {
        self.return_or_retire();
    }

    fn return_or_retire(&mut self) {
        if let (Some(reader), Some(worker_permit)) = (self.reader.take(), self.worker_permit.take())
        {
            self.pool.return_or_retire(reader, worker_permit);
        }
    }
}

impl Drop for ConsensusAcceptanceReaderLease {
    fn drop(&mut self) {
        self.return_or_retire();
    }
}

#[derive(Clone, Copy)]
enum SqliteStoreWorkKind {
    Read,
    CompareAndSet,
    Mutation,
}

#[derive(Clone, Copy)]
enum SqliteWorkerFailure {
    Admission,
    OutcomeUnavailable,
}

fn install_sqlite_operation_progress_handler(
    conn: &Connection,
    cancellation: Arc<AtomicBool>,
    deadline: std::time::Instant,
) -> SqliteOperationProgressGuard<'_> {
    conn.progress_handler(
        SQLITE_OPERATION_PROGRESS_INTERVAL,
        Some(move || cancellation.load(Ordering::Acquire) || std::time::Instant::now() >= deadline),
    );
    SqliteOperationProgressGuard(conn)
}

impl SqliteSessionBackend {
    /// Open (or create) a SQLite database at the given path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref();
        let conn = Connection::open(path)
            .map_err(|error| StoreError::BackendUnavailable(error.to_string()))?;
        Self::finish_file_open(path, conn)
    }

    /// Open a test database through an explicitly selected SQLite test VFS.
    ///
    /// This exists only for the `test-vfs` feature's real-file durability
    /// qualification. Apart from selecting the VFS for `Connection::open`, it
    /// takes the identical file-open path as [`Self::open`], including the
    /// recovery latch check and the primary writer pragma profile.
    #[cfg(feature = "test-vfs")]
    #[doc(hidden)]
    pub fn open_with_vfs_for_test(
        path: impl AsRef<Path>,
        vfs_name: &str,
    ) -> Result<Self, StoreError> {
        let path = path.as_ref();
        let conn =
            Connection::open_with_flags_and_vfs(path, rusqlite::OpenFlags::default(), vfs_name)
                .map_err(|error| StoreError::BackendUnavailable(error.to_string()))?;
        let mut backend = Self::finish_file_open(path, conn)?;
        backend.checkpoint_vfs_name = Some(Arc::from(vfs_name));
        Ok(backend)
    }

    fn finish_file_open(path: &Path, conn: Connection) -> Result<Self, StoreError> {
        let database_path = std::fs::canonicalize(path)
            .map_err(|error| StoreError::BackendUnavailable(error.to_string()))?;
        let database_bytes = std::fs::metadata(&database_path)
            .map_err(|error| StoreError::BackendUnavailable(error.to_string()))?
            .len();
        if database_bytes > crate::consensus::snapshot::SNAPSHOT_DATABASE_MAX_BYTES {
            return Err(StoreError::BackendUnavailable(
                "SQLite database exceeds the fixed snapshot extent".into(),
            ));
        }
        // Install before the auxiliary latch reader opens the file. An
        // existing image that cannot accept the common writer guard is never
        // examined as a normal SDK database.
        install_consensus_snapshot_extent_guard(&conn)?;
        let classification =
            consensus::classify_operator_recovery_latch_with_connection_sync(&database_path, &conn)
                .map_err(|_| {
                    StoreError::BackendUnavailable(
                        "session operator recovery latch is unavailable".into(),
                    )
                })?;
        if let Some(latch) = classification.latch() {
            opc_redaction::metrics::METRICS
                .session_operator_recovery_required
                .store(1, std::sync::atomic::Ordering::Relaxed);
            opc_redaction::metrics::METRICS
                .session_operator_recovery_epoch
                .fetch_max(latch.recovery_epoch, std::sync::atomic::Ordering::Relaxed);
            opc_redaction::metrics::METRICS
                .session_operator_recovery_audit_pending
                .store(
                    i64::from(latch.audit_pending),
                    std::sync::atomic::Ordering::Relaxed,
                );
        }
        let backend = Self::new_with_conn(conn, false, Some(database_path))?;
        if let Some(handoff) = classification.into_terminal_handoff() {
            backend
                .terminal_recovery_handoff
                .lock()
                .map_err(|_| {
                    StoreError::BackendUnavailable(
                        "session operator recovery handoff is unavailable".into(),
                    )
                })?
                .replace(handoff);
        }
        Ok(backend)
    }

    /// Read the primary writer's fixed automatic-checkpoint fallback in a test.
    ///
    /// The proactive lane never changes this value. Keeping the assertion at
    /// the normal writer profile guards against a test accidentally proving a
    /// threshold-retuned configuration instead of the production boundary.
    #[cfg(feature = "test-vfs")]
    #[doc(hidden)]
    pub async fn wal_autocheckpoint_for_test(&self) -> Result<i32, StoreError> {
        if self.database_path.is_none() {
            return Err(StoreError::BackendUnavailable(
                "SQLite checkpoint profile is unavailable for an in-memory backend".into(),
            ));
        }
        let conn = self.conn.lock().await;
        conn.query_row("PRAGMA wal_autocheckpoint", [], |row| row.get(0))
            .map_err(|error| StoreError::BackendUnavailable(error.to_string()))
    }

    /// Pause the one checkpoint worker before its next idle receive in a test.
    ///
    /// The returned guard releases the worker on drop, including a failing
    /// test. This is only a retained-cancellation regression seam; it cannot
    /// be enabled by production construction.
    #[cfg(feature = "test-vfs")]
    #[doc(hidden)]
    pub fn hold_proactive_checkpoint_before_idle_receive_for_test(
        &self,
    ) -> ProactiveCheckpointIdleWaitForTest {
        self.proactive_checkpoint_idle_wait_hook.arm();
        ProactiveCheckpointIdleWaitForTest {
            hook: Arc::clone(&self.proactive_checkpoint_idle_wait_hook),
        }
    }

    /// Observe the one store-scoped checkpoint worker's bounded lifecycle.
    #[cfg(feature = "test-vfs")]
    #[doc(hidden)]
    pub fn proactive_checkpoint_worker_observation_for_test(
        &self,
    ) -> ProactiveCheckpointWorkerObservationForTest {
        ProactiveCheckpointWorkerObservationForTest {
            receiver: self.proactive_checkpoint_worker_observation.subscribe(),
        }
    }

    /// Mark the next checkpoint-worker join boundary for a cancellation test.
    #[cfg(feature = "test-vfs")]
    #[doc(hidden)]
    pub fn observe_proactive_checkpoint_shutdown_join_for_test(
        &self,
    ) -> ProactiveCheckpointShutdownJoinForTest {
        self.proactive_checkpoint_shutdown_join_hook.arm();
        ProactiveCheckpointShutdownJoinForTest {
            hook: Arc::clone(&self.proactive_checkpoint_shutdown_join_hook),
        }
    }

    /// Open an ephemeral in-memory SQLite database.
    pub fn in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
        Self::new_with_conn(conn, true, None)
    }

    fn new_with_conn(
        conn: Connection,
        in_memory: bool,
        database_path: Option<PathBuf>,
    ) -> Result<Self, StoreError> {
        apply_pragma_profile(&conn, in_memory, true)?;

        // Create table for storing session records
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS session_records (
                tenant TEXT NOT NULL,
                nf_kind TEXT NOT NULL,
                key_type TEXT NOT NULL,
                stable_id BLOB NOT NULL CHECK (
                    typeof(stable_id) = 'blob' AND length(stable_id) BETWEEN 1 AND 64
                ),
                generation INTEGER NOT NULL,
                owner TEXT NOT NULL,
                fence INTEGER NOT NULL,
                state_class TEXT NOT NULL,
                state_type TEXT NOT NULL,
                expires_at TEXT,
                payload BLOB NOT NULL,
                encoding INTEGER NOT NULL,
                PRIMARY KEY (tenant, nf_kind, key_type, stable_id)
            );
            "#,
            [],
        )
        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;

        // Local, non-authoritative metadata for opaque bounded restore
        // cursors. The epoch distinguishes database incarnations while the
        // revision invalidates pagination whenever visible record state
        // changes. Neither value allocates session mutation authority.
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS restore_scan_state (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                epoch BLOB NOT NULL CHECK (length(epoch) = 16),
                revision INTEGER NOT NULL CHECK (revision >= 0),
                cursor_key BLOB NOT NULL CHECK (length(cursor_key) = 32)
            );
            "#,
            [],
        )
        .map_err(|_| StoreError::BackendUnavailable("session restore metadata failed".into()))?;
        ops::initialize_restore_scan_metadata_sync(&conn)?;

        // Create table for storing lease entries
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS leases (
                tenant TEXT NOT NULL,
                nf_kind TEXT NOT NULL,
                key_type TEXT NOT NULL,
                stable_id BLOB NOT NULL CHECK (
                    typeof(stable_id) = 'blob' AND length(stable_id) BETWEEN 1 AND 64
                ),
                active INTEGER NOT NULL,
                credential_id INTEGER NOT NULL,
                owner TEXT NOT NULL,
                fence INTEGER NOT NULL,
                expires_at_unix_ms INTEGER NOT NULL,
                guard_expires_at TEXT NOT NULL,
                acquired_at TEXT,
                PRIMARY KEY (tenant, nf_kind, key_type, stable_id)
            );
            "#,
            [],
        )
        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
        migrate_lease_acquired_at_schema(&conn)?;

        // Create table for key fences
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS key_fences (
                tenant TEXT NOT NULL,
                nf_kind TEXT NOT NULL,
                key_type TEXT NOT NULL,
                stable_id BLOB NOT NULL CHECK (
                    typeof(stable_id) = 'blob' AND length(stable_id) BETWEEN 1 AND 64
                ),
                fence INTEGER NOT NULL,
                PRIMARY KEY (tenant, nf_kind, key_type, stable_id)
            );
            "#,
            [],
        )
        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;

        // Create table for lease globals (credential ID, global fence sequence)
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS lease_globals (
                key TEXT PRIMARY KEY,
                val INTEGER NOT NULL
            );
            "#,
            [],
        )
        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;

        conn.execute(
            "INSERT OR IGNORE INTO lease_globals (key, val) VALUES ('next_fence', 1);",
            [],
        )
        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;

        conn.execute(
            "INSERT OR IGNORE INTO lease_globals (key, val) VALUES ('next_credential_id', 1);",
            [],
        )
        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;

        // Create table for replication logs
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS session_replication_log (
                sequence INTEGER PRIMARY KEY CHECK (sequence > 0),
                tx_id TEXT NOT NULL CHECK (
                    typeof(tx_id) = 'text'
                    AND length(CAST(tx_id AS BLOB)) BETWEEN 1 AND 128
                ),
                entry_json TEXT NOT NULL,
                timestamp TEXT NOT NULL
            );
            "#,
            [],
        )
        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;

        let consensus_acceptance_reader_pool = database_path
            .as_ref()
            .map(|path| ConsensusAcceptanceReaderPool::new(Arc::new(path.clone())))
            .transpose()?;

        Ok(Self {
            conn: Arc::new(tokio::sync::Mutex::new(conn)),
            terminal_recovery_handoff: Arc::new(StdMutex::new(None)),
            consensus_acceptance_reader_pool,
            database_path: database_path.map(Arc::new),
            checkpoint_vfs_name: None,
            #[cfg(feature = "test-vfs")]
            proactive_checkpoint_idle_wait_hook: Arc::new(
                ProactiveCheckpointIdleWaitHook::default(),
            ),
            #[cfg(feature = "test-vfs")]
            proactive_checkpoint_worker_observation: Arc::new(
                ProactiveCheckpointWorkerObservation::new(),
            ),
            #[cfg(feature = "test-vfs")]
            proactive_checkpoint_shutdown_join_hook: Arc::new(
                ProactiveCheckpointShutdownJoinHook::default(),
            ),
            consensus_snapshot_observation: Arc::new(consensus::SnapshotBuildObservation::default()),
            caps: sqlite_capabilities(),
            clock: Arc::new(crate::clock::SystemClock),
            restore_scan_workers: Arc::new(tokio::sync::Semaphore::new(
                RESTORE_SCAN_BLOCKING_WORKERS,
            )),
            operation_workers: Arc::new(tokio::sync::Semaphore::new(
                SQLITE_OPERATION_BLOCKING_WORKERS,
            )),
            consensus_diagnostics: None,
            #[cfg(test)]
            consensus_apply_gate: Arc::new(tokio::sync::Semaphore::new(1)),
            #[cfg(test)]
            consensus_snapshot_capture_gate: Arc::new(consensus::SnapshotCaptureGate::new()),
            #[cfg(test)]
            consensus_operator_recovery_failure: Arc::new(AtomicBool::new(false)),
            #[cfg(test)]
            fixed_quorum_v2_mutation_snapshot_cut: Arc::new(AtomicBool::new(false)),
            #[cfg(test)]
            fixed_quorum_durable_check_count: Arc::new(AtomicUsize::new(0)),
            watchers: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            #[cfg(test)]
            watch_registration_gate: Arc::new(tokio::sync::Semaphore::new(1)),
            #[cfg(test)]
            watch_backlog_captured: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Build the exact standalone schema used by the production constructor
    /// and return its connection to internal schema validators.
    ///
    /// Keeping this behind the adapter prevents recovery code from maintaining
    /// a second, potentially weaker copy of the session-table definitions.
    pub(crate) fn canonical_schema_connection() -> Result<Connection, StoreError> {
        let Self { conn, .. } = Self::in_memory()?;
        Arc::try_unwrap(conn)
            .map(tokio::sync::Mutex::into_inner)
            .map_err(|_| {
                StoreError::BackendUnavailable(
                    "canonical session schema connection is unexpectedly shared".into(),
                )
            })
    }

    #[cfg(test)]
    pub(crate) async fn lock_connection_for_test(&self) -> tokio::sync::MutexGuard<'_, Connection> {
        self.conn.lock().await
    }

    /// Replace the default `SystemClock`.
    ///
    /// The clock drives record TTL expiry and server-side lease expiry
    /// checks; substituting a virtual clock makes expiry behavior testable
    /// without real waiting. Has no effect on rows already written — only on
    /// how their deadlines are evaluated.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    pub(crate) fn with_consensus_diagnostics(
        mut self,
        diagnostics: Arc<ConsensusStoreDiagnosticCounters>,
    ) -> Self {
        self.consensus_diagnostics = Some(diagnostics);
        self
    }

    async fn run_sqlite_task<T, E, F>(
        &self,
        operation: F,
    ) -> Result<Result<T, E>, SqliteWorkerFailure>
    where
        T: Send + 'static,
        E: Send + 'static,
        F: FnOnce(&Connection) -> Result<T, E> + Send + 'static,
    {
        self.run_sqlite_task_on(
            Arc::clone(&self.conn),
            Arc::clone(&self.operation_workers),
            operation,
        )
        .await
    }

    async fn run_sqlite_task_on<T, E, F>(
        &self,
        conn: Arc<tokio::sync::Mutex<Connection>>,
        workers: Arc<tokio::sync::Semaphore>,
        operation: F,
    ) -> Result<Result<T, E>, SqliteWorkerFailure>
    where
        T: Send + 'static,
        E: Send + 'static,
        F: FnOnce(&Connection) -> Result<T, E> + Send + 'static,
    {
        let deadline = tokio::time::Instant::now()
            .checked_add(SQLITE_OPERATION_MAX_WORK)
            .ok_or(SqliteWorkerFailure::Admission)?;
        let worker_permit = tokio::time::timeout_at(deadline, workers.acquire_owned())
            .await
            .map_err(|_| {
                if let Some(diagnostics) = &self.consensus_diagnostics {
                    diagnostics.increment_sqlite_worker_permit_deadline();
                }
                SqliteWorkerFailure::Admission
            })?
            .map_err(|_| SqliteWorkerFailure::Admission)?;
        // The async connection lock is acquired before `spawn_blocking`, so a
        // blocked database cannot accumulate detached blocking jobs. Once the
        // job starts, both the connection and worker permit stay in its
        // closure even if the caller disconnects or its future is cancelled.
        let conn = tokio::time::timeout_at(deadline, conn.lock_owned())
            .await
            .map_err(|_| {
                if let Some(diagnostics) = &self.consensus_diagnostics {
                    diagnostics.increment_sqlite_connection_lock_deadline();
                }
                SqliteWorkerFailure::Admission
            })?;
        let cancellation = Arc::new(AtomicBool::new(false));
        let interrupt = conn.get_interrupt_handle();
        let operation_deadline = deadline.into_std();
        let task_cancellation = Arc::clone(&cancellation);
        let queued_job = Arc::new(StdMutex::new(Some((conn, worker_permit, operation))));
        let task_job = Arc::clone(&queued_job);
        let task = tokio::task::spawn_blocking(move || {
            let (conn, worker_permit, operation) = task_job
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()?;
            let result = {
                let _progress = install_sqlite_operation_progress_handler(
                    &conn,
                    Arc::clone(&task_cancellation),
                    operation_deadline,
                );
                if task_cancellation.load(Ordering::Acquire) {
                    Err(SqliteWorkerFailure::OutcomeUnavailable)
                } else {
                    Ok(operation(&conn))
                }
            };
            // Return both guards with the result. The async wrapper disarms
            // its interrupt before dropping them, so completion cannot issue
            // a stale interrupt against a successor operation. If the wrapper
            // was dropped, this output is discarded only after the worker
            // exits, retaining bounded admission for the full lifetime.
            Some((result, conn, worker_permit))
        });
        let cancel_job = Arc::clone(&queued_job);
        let mut cancel_on_drop = SqliteOperationCancellation {
            cancellation: Arc::clone(&cancellation),
            interrupt,
            abort: task.abort_handle(),
            cancel_queued: Some(Box::new(move || {
                drop(
                    cancel_job
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .take(),
                );
            })),
            armed: true,
        };
        match tokio::time::timeout_at(deadline, task).await {
            Err(_) => {
                if let Some(diagnostics) = &self.consensus_diagnostics {
                    diagnostics.increment_sqlite_execution_deadline();
                }
                Err(SqliteWorkerFailure::OutcomeUnavailable)
            }
            Ok(Err(_)) => {
                cancel_on_drop.disarm();
                Err(SqliteWorkerFailure::OutcomeUnavailable)
            }
            Ok(Ok(Some((result, conn, worker_permit)))) => {
                cancel_on_drop.disarm();
                drop(conn);
                drop(worker_permit);
                result
            }
            Ok(Ok(None)) => {
                cancel_on_drop.disarm();
                Err(SqliteWorkerFailure::OutcomeUnavailable)
            }
        }
    }

    async fn run_store_sqlite_task<T, F>(
        &self,
        kind: SqliteStoreWorkKind,
        operation: F,
    ) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> Result<T, StoreError> + Send + 'static,
    {
        match self.run_sqlite_task(operation).await {
            Ok(Ok(value)) => Ok(value),
            Err(SqliteWorkerFailure::OutcomeUnavailable) => {
                Err(sqlite_store_outcome_unavailable(kind))
            }
            Ok(Err(error)) => Err(error),
            Err(SqliteWorkerFailure::Admission) => Err(StoreError::BackendUnavailable(
                "session SQLite worker admission deadline exceeded".into(),
            )),
        }
    }

    async fn run_sqlite_task_on_consensus_acceptance_reader<T, E, F>(
        &self,
        pool: Arc<ConsensusAcceptanceReaderPool>,
        operation: F,
    ) -> Result<Result<T, E>, SqliteWorkerFailure>
    where
        T: Send + 'static,
        E: Send + 'static,
        F: FnOnce(&Connection) -> Result<T, E> + Send + 'static,
    {
        let deadline = tokio::time::Instant::now()
            .checked_add(SQLITE_OPERATION_MAX_WORK)
            .ok_or(SqliteWorkerFailure::Admission)?;
        let worker_permit =
            tokio::time::timeout_at(deadline, Arc::clone(&pool.workers).acquire_owned())
                .await
                .map_err(|_| {
                    if let Some(diagnostics) = &self.consensus_diagnostics {
                        diagnostics.increment_sqlite_worker_permit_deadline();
                    }
                    SqliteWorkerFailure::Admission
                })?
                .map_err(|_| SqliteWorkerFailure::Admission)?;
        let conn = pool.checkout(deadline).await?;
        let cancellation = Arc::new(AtomicBool::new(false));
        let interrupt = conn.get_interrupt_handle();
        let operation_deadline = deadline.into_std();
        let task_cancellation = Arc::clone(&cancellation);
        let queued_job = Arc::new(StdMutex::new(Some((
            ConsensusAcceptanceReaderLease::new(Arc::clone(&pool), conn, worker_permit),
            operation,
        ))));
        let task_job = Arc::clone(&queued_job);
        let task = tokio::task::spawn_blocking(move || {
            let (lease, operation) = task_job
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()?;
            let result = {
                if let Some(conn) = lease.connection() {
                    let _progress = install_sqlite_operation_progress_handler(
                        conn,
                        Arc::clone(&task_cancellation),
                        operation_deadline,
                    );
                    if task_cancellation.load(Ordering::Acquire) || !conn.is_autocommit() {
                        Err(SqliteWorkerFailure::OutcomeUnavailable)
                    } else {
                        Ok(operation(conn))
                    }
                } else {
                    Err(SqliteWorkerFailure::OutcomeUnavailable)
                }
            };
            lease.complete();
            Some(result)
        });
        let cancel_job = Arc::clone(&queued_job);
        let mut cancel_on_drop = SqliteOperationCancellation {
            cancellation: Arc::clone(&cancellation),
            interrupt,
            abort: task.abort_handle(),
            cancel_queued: Some(Box::new(move || {
                if let Some((lease, _)) = cancel_job
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take()
                {
                    drop(lease);
                }
            })),
            armed: true,
        };
        match tokio::time::timeout_at(deadline, task).await {
            Err(_) => {
                if let Some(diagnostics) = &self.consensus_diagnostics {
                    diagnostics.increment_sqlite_execution_deadline();
                }
                Err(SqliteWorkerFailure::OutcomeUnavailable)
            }
            Ok(Err(_)) => {
                cancel_on_drop.disarm();
                Err(SqliteWorkerFailure::OutcomeUnavailable)
            }
            Ok(Ok(Some(result))) => {
                cancel_on_drop.disarm();
                result
            }
            Ok(Ok(None)) => {
                cancel_on_drop.disarm();
                Err(SqliteWorkerFailure::OutcomeUnavailable)
            }
        }
    }

    /// Run one exact fixed-quorum acceptance snapshot on a fixed file-backed
    /// WAL reader lane. Every lane is process-scoped and exclusive, so Raft
    /// log/state-machine writes cannot create head-of-line lock waits. The
    /// supplied closure must establish its own fresh SQLite transaction as the
    /// visibility and authority boundary.
    async fn run_consensus_acceptance_read_task<T, F>(&self, operation: F) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> Result<T, StoreError> + Send + 'static,
    {
        let result = match &self.consensus_acceptance_reader_pool {
            Some(pool) => {
                self.run_sqlite_task_on_consensus_acceptance_reader(Arc::clone(pool), operation)
                    .await
            }
            None => self.run_sqlite_task(operation).await,
        };
        match result {
            Ok(Ok(value)) => Ok(value),
            Err(SqliteWorkerFailure::OutcomeUnavailable) => {
                Err(sqlite_store_outcome_unavailable(SqliteStoreWorkKind::Read))
            }
            Ok(Err(error)) => Err(error),
            Err(SqliteWorkerFailure::Admission) => Err(StoreError::BackendUnavailable(
                "session SQLite worker admission deadline exceeded".into(),
            )),
        }
    }

    async fn run_lease_sqlite_task<T, F>(&self, operation: F) -> Result<T, LeaseError>
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> Result<T, LeaseError> + Send + 'static,
    {
        match self.run_sqlite_task(operation).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(error),
            Err(SqliteWorkerFailure::OutcomeUnavailable) => {
                Err(LeaseError::OperationOutcomeUnavailable)
            }
            Err(SqliteWorkerFailure::Admission) => Err(LeaseError::Backend(
                "session SQLite worker admission deadline exceeded".into(),
            )),
        }
    }

    /// Capabilities consumed by the consensus adapter that owns this backend.
    pub(crate) const fn consensus_capabilities(&self) -> BackendCapabilities {
        let mut capabilities = self.caps;
        capabilities.max_value_bytes = SQLITE_CONSENSUS_MAX_VALUE_BYTES;
        capabilities
    }

    /// Maximum encoded durable consensus-log entry accepted by this SQLite
    /// build. V2 capability admission binds this concrete limit into the
    /// advertised protocol profile before any command is proposed.
    pub(crate) const fn consensus_log_entry_max_bytes(&self) -> usize {
        consensus::SQLITE_CONSENSUS_LOG_ENTRY_MAX_BYTES
    }

    /// Whether consensus state is backed by a filesystem database.
    ///
    /// Fixed durable quorums reject ephemeral in-memory stores. This is a
    /// durability-shape check, not a claim about physical failure domains or
    /// concrete volume identity.
    pub(crate) const fn is_file_backed(&self) -> bool {
        self.database_path.is_some()
    }

    /// Duplicate the exact SQLite main-database descriptor for a snapshot
    /// lease acquired before consensus-core construction.
    ///
    /// The returned descriptor is tied to SQLite's live VFS object, not a
    /// fresh pathname open.  File-backed stores fail closed if SQLite reports
    /// a moved main file or if the canonical name no longer resolves to that
    /// same object. In-memory stores have no descriptor and return `None`.
    pub(crate) async fn duplicate_main_file_descriptor_for_snapshot_lease(
        &self,
    ) -> std::io::Result<Option<File>> {
        let Some(database_path) = self.database_path.as_ref() else {
            return Ok(None);
        };
        let connection = self.conn.lock().await;

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;

            let unavailable = || {
                std::io::Error::other(
                    "SQLite main file descriptor is unavailable for snapshot lease",
                )
            };
            if opc_sqlite_file_control_sys::main_file_has_moved(&connection)
                .map_err(|_| unavailable())?
            {
                return Err(unavailable());
            }
            let descriptor = opc_sqlite_file_control_sys::main_file_descriptor(&connection)
                .map_err(|_| unavailable())?;
            let path_pin = open_regular_read_nofollow(database_path.as_ref())?;
            let path_metadata = path_pin.metadata()?;
            let descriptor_metadata = descriptor.metadata()?;
            if path_metadata.dev() != descriptor_metadata.dev()
                || path_metadata.ino() != descriptor_metadata.ino()
                || opc_sqlite_file_control_sys::main_file_has_moved(&connection)
                    .map_err(|_| unavailable())?
            {
                return Err(unavailable());
            }
            Ok(Some(descriptor))
        }

        #[cfg(not(unix))]
        {
            let _ = connection;
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "SQLite main file descriptor is unavailable for snapshot lease",
            ))
        }
    }

    /// Fixed-dimension observation shared by the consensus snapshot builder.
    pub(crate) fn snapshot_observation(&self) -> Arc<consensus::SnapshotBuildObservation> {
        Arc::clone(&self.consensus_snapshot_observation)
    }

    /// Transfer the exact terminal recovery descriptor handoff to the first
    /// consensus-core initialization.  A poisoned handoff is fail-closed: it
    /// leaves the durable pending terminal sidecar in place for a later
    /// process rather than admitting normal traffic.
    pub(crate) fn take_terminal_recovery_handoff(
        &self,
    ) -> Result<Option<consensus::OperatorRecoveryTerminalHandoff>, StoreError> {
        self.terminal_recovery_handoff
            .lock()
            .map_err(|_| {
                StoreError::BackendUnavailable(
                    "session operator recovery handoff is unavailable".into(),
                )
            })
            .map(|mut handoff| handoff.take())
    }

    /// Restore a terminal handoff after consensus-core initialization aborts
    /// before storage has validated and consumed it.  The handoff owns the
    /// same pinned descriptors and sidecar incarnation captured at backend
    /// open; putting it back is therefore a retry, never a pathname reopen.
    ///
    /// A populated slot is an internal lifecycle violation.  Callers must
    /// fail closed rather than replacing a concurrent handoff.
    pub(crate) fn restore_terminal_recovery_handoff(
        &self,
        handoff: consensus::OperatorRecoveryTerminalHandoff,
    ) -> Result<(), StoreError> {
        let mut slot = self.terminal_recovery_handoff.lock().map_err(|_| {
            StoreError::BackendUnavailable(
                "session operator recovery handoff is unavailable".into(),
            )
        })?;
        if slot.is_some() {
            return Err(StoreError::BackendUnavailable(
                "session operator recovery handoff restore is unavailable".into(),
            ));
        }
        *slot = Some(handoff);
        Ok(())
    }

    /// Shared one-shot handoff slot retained by a constructed consensus core
    /// until storage has consumed the pending terminal record.  It is not a
    /// way to inspect or manufacture a handoff: the core uses it solely to
    /// restore its still-owned exact descriptor evidence if a later storage
    /// initialization stage aborts.
    pub(crate) fn terminal_recovery_handoff_restore_slot(
        &self,
    ) -> Arc<StdMutex<Option<consensus::OperatorRecoveryTerminalHandoff>>> {
        Arc::clone(&self.terminal_recovery_handoff)
    }

    #[cfg(test)]
    pub(crate) fn snapshot_capture_gate(&self) -> Arc<consensus::SnapshotCaptureGate> {
        Arc::clone(&self.consensus_snapshot_capture_gate)
    }

    /// Synchronously test a fixed-quorum authority record without waiting for
    /// a concurrent SQLite operation. Callers must treat lock contention or a
    /// malformed durable record as revoked authority.
    pub(crate) fn fixed_quorum_authority_is_exact_now(
        &self,
        identity: crate::consensus::SessionConsensusIdentity,
        expected_members: &std::collections::BTreeSet<crate::consensus::SessionConsensusNodeId>,
        expected_bindings: &std::collections::BTreeMap<
            crate::consensus::SessionConsensusNodeId,
            crate::consensus::SessionTopologyMemberBinding,
        >,
        expected_placement_policy: crate::readiness::PlacementResiliencePolicy,
    ) -> bool {
        self.conn.try_lock().is_ok_and(|conn| {
            consensus::fixed_quorum_authority_is_exact_sync(
                &conn,
                identity,
                expected_members,
                expected_bindings,
                expected_placement_policy,
                false,
            )
            .unwrap_or(false)
        })
    }

    /// Read the immutable fixed-quorum authority record under the backend
    /// lock. Storage failure is intentionally indistinguishable from a
    /// revoked authority to inbound engine traffic.
    pub(crate) async fn fixed_quorum_authority_record_is_exact(
        &self,
        identity: crate::consensus::SessionConsensusIdentity,
        expected_members: &std::collections::BTreeSet<crate::consensus::SessionConsensusNodeId>,
        expected_bindings: &std::collections::BTreeMap<
            crate::consensus::SessionConsensusNodeId,
            crate::consensus::SessionTopologyMemberBinding,
        >,
        expected_placement_policy: crate::readiness::PlacementResiliencePolicy,
        allow_pristine_membership: bool,
    ) -> bool {
        #[cfg(test)]
        self.fixed_quorum_durable_check_count
            .fetch_add(1, Ordering::SeqCst);
        let conn = self.conn.lock().await;
        consensus::fixed_quorum_authority_is_exact_sync(
            &conn,
            identity,
            expected_members,
            expected_bindings,
            expected_placement_policy,
            allow_pristine_membership,
        )
        .unwrap_or(false)
    }

    /// Atomically revalidate the immutable fixed-quorum authority and operator
    /// recovery state needed before ordinary application traffic is admitted.
    ///
    /// A malformed or unavailable durable record remains distinguishable to
    /// callers as storage unavailability; callers must fail closed in either
    /// case. The recovery sidecar is deliberately read for every invocation,
    /// rather than being cached with the immutable authority record.
    pub(crate) async fn fixed_quorum_application_traffic_authority_is_exact(
        &self,
        identity: crate::consensus::SessionConsensusIdentity,
        expected_members: std::collections::BTreeSet<crate::consensus::SessionConsensusNodeId>,
        expected_bindings: std::collections::BTreeMap<
            crate::consensus::SessionConsensusNodeId,
            crate::consensus::SessionTopologyMemberBinding,
        >,
        expected_placement_policy: crate::readiness::PlacementResiliencePolicy,
    ) -> Result<bool, StoreError> {
        #[cfg(test)]
        if self
            .consensus_operator_recovery_failure
            .load(Ordering::Acquire)
        {
            return Err(StoreError::BackendUnavailable(
                "injected session operator recovery check failure".into(),
            ));
        }
        let database_path = self.database_path.clone();
        self.run_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
            let database_latch = database_path
                .as_deref()
                .map(|path| {
                    consensus::classify_operator_recovery_latch_with_connection_sync(path, conn)
                        .map(|classification| classification.latch())
                })
                .transpose()
                .map_err(|_| {
                    StoreError::BackendUnavailable(
                        "session operator recovery latch is unavailable".into(),
                    )
                })?
                .flatten();
            if let Some(latch) = database_latch {
                if latch.identity != identity {
                    return Err(StoreError::BackendUnavailable(
                        "session operator recovery latch identity does not match".into(),
                    ));
                }
                opc_redaction::metrics::METRICS
                    .session_operator_recovery_required
                    .store(1, std::sync::atomic::Ordering::Relaxed);
                opc_redaction::metrics::METRICS
                    .session_operator_recovery_epoch
                    .fetch_max(latch.recovery_epoch, std::sync::atomic::Ordering::Relaxed);
                if latch.audit_pending {
                    opc_redaction::metrics::METRICS
                        .session_operator_recovery_audit_pending
                        .store(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
            let fixed_authority_is_exact = consensus::fixed_quorum_authority_is_exact_sync(
                conn,
                identity,
                &expected_members,
                &expected_bindings,
                expected_placement_policy,
                false,
            )
            .map_err(|_| {
                StoreError::BackendUnavailable(
                    "session fixed-quorum authority is unavailable".into(),
                )
            })?;
            let recovery_pending = consensus::read_operator_recovery_sync(conn, identity)
                .map(|state| state.pending_epoch.is_some())
                .map_err(|_| {
                    StoreError::BackendUnavailable(
                        "session operator recovery state is unavailable".into(),
                    )
                })?;
            Ok(fixed_authority_is_exact && !recovery_pending && database_latch.is_none())
        })
        .await
    }

    /// Atomically snapshot all durable facts required to propose a raw V2
    /// mutation through an immutable fixed quorum.
    ///
    /// The filesystem recovery latch is re-read on every call in the same
    /// bounded SQLite worker closure. The database-resident checks -- exact
    /// fixed authority and scope, pending recovery, exact active V2 profile,
    /// and the currently applied logical time -- share one read transaction.
    /// Any malformed, changed, or unavailable durable state is a safe
    /// pre-proposal failure and no result is cached across invocations.
    pub(crate) async fn fixed_quorum_activated_v2_mutation_snapshot(
        &self,
        acceptance: FixedQuorumActivatedV2MutationSnapshotRequest,
    ) -> Result<FixedQuorumActivatedV2MutationSnapshot, StoreError> {
        let FixedQuorumActivatedV2MutationSnapshotRequest {
            storage_identity,
            scope_identity,
            voters,
            expected_members,
            expected_bindings,
            expected_placement_policy,
            profile_digest,
        } = acceptance;
        #[cfg(test)]
        if self
            .consensus_operator_recovery_failure
            .load(Ordering::Acquire)
        {
            return Err(StoreError::BackendUnavailable(
                "injected session operator recovery check failure".into(),
            ));
        }
        let database_path = self.database_path.clone();
        #[cfg(test)]
        let snapshot_cut = Arc::clone(&self.fixed_quorum_v2_mutation_snapshot_cut);
        self.run_consensus_acceptance_read_task(move |conn| {
            let database_latch = database_path
                .as_deref()
                .map(|path| {
                    consensus::classify_operator_recovery_latch_with_connection_sync(path, conn)
                        .map(|classification| classification.latch())
                })
                .transpose()
                .map_err(|_| {
                    StoreError::BackendUnavailable(
                        "session operator recovery latch is unavailable".into(),
                    )
                })?
                .flatten();
            if let Some(latch) = database_latch {
                if latch.identity != storage_identity {
                    return Err(StoreError::BackendUnavailable(
                        "session operator recovery latch identity does not match".into(),
                    ));
                }
                opc_redaction::metrics::METRICS
                    .session_operator_recovery_required
                    .store(1, std::sync::atomic::Ordering::Relaxed);
                opc_redaction::metrics::METRICS
                    .session_operator_recovery_epoch
                    .fetch_max(latch.recovery_epoch, std::sync::atomic::Ordering::Relaxed);
                if latch.audit_pending {
                    opc_redaction::metrics::METRICS
                        .session_operator_recovery_audit_pending
                        .store(1, std::sync::atomic::Ordering::Relaxed);
                }
                return Err(StoreError::BackendUnavailable(
                    "session application traffic authority is unavailable".into(),
                ));
            }

            let tx = conn
                .unchecked_transaction()
                .map_err(|_| StoreError::BackendUnavailable("session store read failed".into()))?;
            if scope_identity != storage_identity || voters != expected_members {
                return Err(StoreError::BackendUnavailable(
                    "session fixed-quorum authority is unavailable".into(),
                ));
            }
            let fixed_authority_is_exact = consensus::fixed_quorum_authority_is_exact_sync(
                &tx,
                storage_identity,
                &expected_members,
                &expected_bindings,
                expected_placement_policy,
                false,
            )
            .map_err(|_| {
                StoreError::BackendUnavailable(
                    "session fixed-quorum authority is unavailable".into(),
                )
            })?;
            let recovery_pending = consensus::read_operator_recovery_sync(&tx, storage_identity)
                .map(|state| state.pending_epoch.is_some())
                .map_err(|_| {
                    StoreError::BackendUnavailable(
                        "session operator recovery state is unavailable".into(),
                    )
                })?;
            if !fixed_authority_is_exact || recovery_pending {
                return Err(StoreError::BackendUnavailable(
                    "session application traffic authority is unavailable".into(),
                ));
            }
            let activated = consensus::fenced_transition_v2_activation_matches_scope_sync(
                &tx,
                storage_identity,
                scope_identity,
                &voters,
                profile_digest,
            )
            .map_err(|_| {
                StoreError::BackendUnavailable(
                    "fenced transition V2 activation is unavailable".into(),
                )
            })?;
            #[cfg(test)]
            if snapshot_cut.load(Ordering::Acquire) {
                return Err(StoreError::BackendUnavailable(
                    "injected fixed-quorum V2 mutation snapshot cut".into(),
                ));
            }
            let result = if activated {
                FixedQuorumActivatedV2MutationSnapshot::Activated {
                    applied_logical_time: consensus::logical_time_sync(&tx, storage_identity)
                        .map_err(|_| {
                            StoreError::BackendUnavailable(
                                "session consensus logical time is unavailable".into(),
                            )
                        })?,
                }
            } else {
                FixedQuorumActivatedV2MutationSnapshot::Unactivated
            };
            tx.commit()
                .map_err(|_| StoreError::BackendUnavailable("session store read failed".into()))?;
            Ok(result)
        })
        .await
    }

    /// Atomically accept one fixed-quorum V2 status read at an exact consumer
    /// scope.
    ///
    /// The recovery sidecar is necessarily checked outside SQLite, but is read
    /// anew for every invocation.  All database-resident acceptance facts --
    /// fixed authority, recovery state, exact V2 activation, and the receipt
    /// status itself -- share the one read transaction.  `require_activation`
    /// is false only after the caller has just obtained a fresh unanimous V2
    /// capability proof at the preceding committed logical-time fence.
    #[allow(dead_code)] // Retained singleton adapter for internal generic callers.
    pub(crate) async fn fixed_quorum_fenced_transition_v2_status_at_scope(
        &self,
        acceptance: FixedQuorumFencedTransitionV2StatusReadRequest,
        request: &crate::FencedTransitionV2Request,
    ) -> Result<FixedQuorumFencedTransitionV2StatusRead, StoreError> {
        match self
            .fixed_quorum_fenced_transition_v2_status_batch_at_scope(
                acceptance,
                vec![request.clone()],
            )
            .await?
        {
            FixedQuorumFencedTransitionV2StatusBatchRead::Activated(mut statuses) => statuses
                .pop()
                .map(FixedQuorumFencedTransitionV2StatusRead::Activated)
                .ok_or_else(|| {
                    StoreError::BackendUnavailable("session status cohort was empty".into())
                }),
            FixedQuorumFencedTransitionV2StatusBatchRead::Unactivated => {
                Ok(FixedQuorumFencedTransitionV2StatusRead::Unactivated)
            }
        }
    }

    /// Atomically accept an ordered bounded cohort of V2 status reads at one
    /// exact fixed-quorum consumer scope.
    ///
    /// The recovery sidecar and all durable authority facts are evaluated once
    /// for this one local cohort, then every receipt lookup runs in the same
    /// SQLite snapshot.  No answer survives the fanout to its original callers.
    pub(crate) async fn fixed_quorum_fenced_transition_v2_status_batch_at_scope(
        &self,
        acceptance: FixedQuorumFencedTransitionV2StatusReadRequest,
        requests: Vec<crate::FencedTransitionV2Request>,
    ) -> Result<FixedQuorumFencedTransitionV2StatusBatchRead, StoreError> {
        if requests.is_empty() {
            return Err(StoreError::BackendUnavailable(
                "session status cohort was empty".into(),
            ));
        }
        let FixedQuorumFencedTransitionV2StatusReadRequest {
            storage_identity,
            scope_identity,
            voters,
            expected_members,
            expected_bindings,
            expected_placement_policy,
            profile_digest,
            require_activation,
        } = acceptance;
        #[cfg(test)]
        if self
            .consensus_operator_recovery_failure
            .load(Ordering::Acquire)
        {
            return Err(StoreError::BackendUnavailable(
                "injected session operator recovery check failure".into(),
            ));
        }
        let database_path = self.database_path.clone();
        self.run_consensus_acceptance_read_task(move |conn| {
            let database_latch = database_path
                .as_deref()
                .map(|path| {
                    consensus::classify_operator_recovery_latch_with_connection_sync(path, conn)
                        .map(|classification| classification.latch())
                })
                .transpose()
                .map_err(|_| {
                    StoreError::BackendUnavailable(
                        "session operator recovery latch is unavailable".into(),
                    )
                })?
                .flatten();
            if let Some(latch) = database_latch {
                if latch.identity != storage_identity {
                    return Err(StoreError::BackendUnavailable(
                        "session operator recovery latch identity does not match".into(),
                    ));
                }
                opc_redaction::metrics::METRICS
                    .session_operator_recovery_required
                    .store(1, std::sync::atomic::Ordering::Relaxed);
                opc_redaction::metrics::METRICS
                    .session_operator_recovery_epoch
                    .fetch_max(latch.recovery_epoch, std::sync::atomic::Ordering::Relaxed);
                if latch.audit_pending {
                    opc_redaction::metrics::METRICS
                        .session_operator_recovery_audit_pending
                        .store(1, std::sync::atomic::Ordering::Relaxed);
                }
                return Err(StoreError::BackendUnavailable(
                    "session application traffic authority is unavailable".into(),
                ));
            }

            let tx = conn
                .unchecked_transaction()
                .map_err(|_| StoreError::BackendUnavailable("session store read failed".into()))?;
            if scope_identity != storage_identity || voters != expected_members {
                return Err(StoreError::BackendUnavailable(
                    "session fixed-quorum authority is unavailable".into(),
                ));
            }
            let fixed_authority_is_exact = consensus::fixed_quorum_authority_is_exact_sync(
                &tx,
                storage_identity,
                &expected_members,
                &expected_bindings,
                expected_placement_policy,
                false,
            )
            .map_err(|_| {
                StoreError::BackendUnavailable(
                    "session fixed-quorum authority is unavailable".into(),
                )
            })?;
            let recovery_pending = consensus::read_operator_recovery_sync(&tx, storage_identity)
                .map(|state| state.pending_epoch.is_some())
                .map_err(|_| {
                    StoreError::BackendUnavailable(
                        "session operator recovery state is unavailable".into(),
                    )
                })?;
            if !fixed_authority_is_exact || recovery_pending {
                return Err(StoreError::BackendUnavailable(
                    "session application traffic authority is unavailable".into(),
                ));
            }
            let activated = consensus::fenced_transition_v2_activation_matches_scope_sync(
                &tx,
                storage_identity,
                scope_identity,
                &voters,
                profile_digest,
            )
            .map_err(|_| {
                StoreError::BackendUnavailable(
                    "fenced transition V2 activation is unavailable".into(),
                )
            })?;
            if require_activation && !activated {
                tx.commit().map_err(|_| {
                    StoreError::BackendUnavailable("session store read failed".into())
                })?;
                return Ok(FixedQuorumFencedTransitionV2StatusBatchRead::Unactivated);
            }
            let statuses = requests
                .iter()
                .map(|request| {
                    consensus::read_fenced_transition_v2_status_sync(
                        &tx,
                        storage_identity,
                        scope_identity,
                        request,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            tx.commit()
                .map_err(|_| StoreError::BackendUnavailable("session store read failed".into()))?;
            Ok(FixedQuorumFencedTransitionV2StatusBatchRead::Activated(
                statuses,
            ))
        })
        .await
    }

    /// Read the last committed state-machine logical time after a caller-owned
    /// Openraft linearizable barrier. This path is read-only and allocates no
    /// sequencing authority.
    pub(crate) async fn consensus_logical_time(
        &self,
        identity: crate::consensus::SessionConsensusIdentity,
    ) -> Result<Option<opc_types::Timestamp>, StoreError> {
        self.run_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
            consensus::logical_time_sync(conn, identity).map_err(|_| {
                StoreError::BackendUnavailable(
                    "session consensus logical time is unavailable".into(),
                )
            })
        })
        .await
    }

    /// Read one exact immutable protected-roster admission and the effective
    /// authority time under one backend lock after a caller-owned linearizable
    /// barrier. The current authority may be the original live lease or a
    /// strictly higher-fence successor; this path never allocates a consensus
    /// request or advances logical time.
    pub(crate) async fn consensus_protected_roster_admission_status(
        &self,
        identity: crate::consensus::SessionConsensusIdentity,
        admission: crate::fenced_mutation_roster::Admission,
        current_authority: crate::fenced_mutation_roster_executor::AuthorityBinding,
        wall_time_floor: opc_types::Timestamp,
    ) -> Result<(consensus::ProtectedRosterReadResult, opc_types::Timestamp), StoreError> {
        self.run_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
            let logical_time = consensus::logical_time_sync(conn, identity)
                .map_err(|_| {
                    StoreError::BackendUnavailable(
                        "session consensus logical time is unavailable".into(),
                    )
                })?
                .map_or(wall_time_floor, |time| time.max(wall_time_floor));
            let read = consensus::read_protected_roster_admission_status_sync(
                conn,
                identity,
                &admission,
                &current_authority,
                logical_time,
            )?;
            Ok((read, logical_time))
        })
        .await
    }

    /// Recover one exact protected roster under a valid strictly newer fence,
    /// with effective authority time and state selected under one backend
    /// lock after a caller-owned linearizable barrier. Missing remains
    /// ambiguous.
    pub(crate) async fn consensus_protected_roster_recovery(
        &self,
        identity: crate::consensus::SessionConsensusIdentity,
        recovery: crate::fenced_mutation_roster_executor::RecoveryRequest,
        wall_time_floor: opc_types::Timestamp,
    ) -> Result<(consensus::ProtectedRosterReadResult, opc_types::Timestamp), StoreError> {
        self.run_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
            let logical_time = consensus::logical_time_sync(conn, identity)
                .map_err(|_| {
                    StoreError::BackendUnavailable(
                        "session consensus logical time is unavailable".into(),
                    )
                })?
                .map_or(wall_time_floor, |time| time.max(wall_time_floor));
            let read = consensus::read_protected_roster_recovery_sync(
                conn,
                identity,
                &recovery,
                logical_time,
            )?;
            Ok((read, logical_time))
        })
        .await
    }

    /// Read one exact terminal body and effective authority time under one
    /// backend lock after a caller-owned linearizable barrier. No status read
    /// can select a new terminal phase or body.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn consensus_protected_roster_terminal_status(
        &self,
        identity: crate::consensus::SessionConsensusIdentity,
        binding: crate::fenced_mutation_roster::RequestBindingKey,
        registration_parts: ([u8; 32], crate::fenced_mutation_roster::RequestId, [u8; 32]),
        current_authority: crate::fenced_mutation_roster_executor::AuthorityBinding,
        terminal_body_commitment: [u8; 32],
        terminal_evidence: crate::fenced_mutation_roster::RosterCompactTerminalEvidenceV2,
        wall_time_floor: opc_types::Timestamp,
    ) -> Result<(consensus::ProtectedRosterReadResult, opc_types::Timestamp), StoreError> {
        self.run_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
            let logical_time = consensus::logical_time_sync(conn, identity)
                .map_err(|_| {
                    StoreError::BackendUnavailable(
                        "session consensus logical time is unavailable".into(),
                    )
                })?
                .map_or(wall_time_floor, |time| time.max(wall_time_floor));
            let read = consensus::read_protected_roster_terminal_status_sync(
                conn,
                identity,
                binding,
                consensus::ProtectedRosterTerminalStatusRequest {
                    registration_parts,
                    current_authority: &current_authority,
                    terminal_body_commitment,
                    terminal_evidence: &terminal_evidence,
                    logical_time,
                },
            )?;
            Ok((read, logical_time))
        })
        .await
    }

    /// Resolve one complete Established publication identity and current
    /// authority under one SQLite read task after the caller's linearizable
    /// barrier.  This is intentionally read-only: it neither proposes nor
    /// retains a consumer receipt.
    pub(crate) async fn consensus_protected_roster_current_publication_authority(
        &self,
        identity: crate::consensus::SessionConsensusIdentity,
        request: crate::consumer::SessionConsumerRosterCurrentPublicationAuthorityCapsule,
        wall_time_floor: opc_types::Timestamp,
    ) -> Result<opc_types::Timestamp, StoreError> {
        self.run_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
            let logical_time = consensus::logical_time_sync(conn, identity)
                .map_err(|_| {
                    StoreError::BackendUnavailable(
                        "session consensus logical time is unavailable".into(),
                    )
                })?
                .map_or(wall_time_floor, |time| time.max(wall_time_floor));
            consensus::read_protected_roster_current_publication_authority_sync(
                conn,
                identity,
                &request,
                logical_time,
            )?;
            Ok(logical_time)
        })
        .await
    }

    /// Check the bounded V1 activation certificate after a caller-owned
    /// consensus barrier.  A missing or stale certificate is a normal
    /// unsupported state; storage failure remains unavailable.
    pub(crate) async fn consensus_fenced_transition_activation_matches_scope(
        &self,
        storage_identity: crate::consensus::SessionConsensusIdentity,
        scope_identity: crate::consensus::SessionConsensusIdentity,
        voters: std::collections::BTreeSet<crate::consensus::SessionConsensusNodeId>,
    ) -> Result<bool, StoreError> {
        self.run_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
            consensus::fenced_transition_activation_matches_scope_sync(
                conn,
                storage_identity,
                scope_identity,
                &voters,
            )
            .map_err(|_| {
                StoreError::BackendUnavailable("fenced transition activation is unavailable".into())
            })
        })
        .await
    }

    /// Check the exact immutable protected-roster profile certificate after a
    /// caller-owned consensus barrier. A generic V1 certificate is not
    /// sufficient for this capability.
    pub(crate) async fn consensus_protected_roster_profile_activation_matches_scope(
        &self,
        storage_identity: crate::consensus::SessionConsensusIdentity,
        scope_identity: crate::consensus::SessionConsensusIdentity,
        voters: std::collections::BTreeSet<crate::consensus::SessionConsensusNodeId>,
    ) -> Result<bool, StoreError> {
        self.run_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
            consensus::protected_roster_profile_activation_matches_scope_sync(
                conn,
                storage_identity,
                scope_identity,
                &voters,
            )
            .map_err(|_| {
                StoreError::BackendUnavailable(
                    "protected roster profile activation is unavailable".into(),
                )
            })
        })
        .await
    }

    /// Check the exact V2 profile certificate after a caller-owned consensus
    /// barrier. A missing or stale certificate is a normal unsupported state;
    /// storage failure remains unavailable.
    pub(crate) async fn consensus_fenced_transition_v2_activation_matches_scope(
        &self,
        storage_identity: crate::consensus::SessionConsensusIdentity,
        scope_identity: crate::consensus::SessionConsensusIdentity,
        voters: std::collections::BTreeSet<crate::consensus::SessionConsensusNodeId>,
        profile_digest: [u8; 32],
    ) -> Result<bool, StoreError> {
        self.run_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
            consensus::fenced_transition_v2_activation_matches_scope_sync(
                conn,
                storage_identity,
                scope_identity,
                &voters,
                profile_digest,
            )
            .map_err(|_| {
                StoreError::BackendUnavailable(
                    "fenced transition V2 activation is unavailable".into(),
                )
            })
        })
        .await
    }

    /// Read at a logical timestamp already committed by the consensus state
    /// machine. This path is read-only: expiry affects visibility but never
    /// prunes physical rows outside a committed command.
    pub(crate) async fn consensus_get_at(
        &self,
        key: &SessionKey,
        logical_time: opc_types::Timestamp,
    ) -> Result<Option<StoredSessionRecord>, StoreError> {
        let key = key.clone();
        self.run_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
            let tx = conn
                .unchecked_transaction()
                .map_err(|_| StoreError::BackendUnavailable("session store read failed".into()))?;
            let result = ops::get_sync(&tx, &key, logical_time)?;
            if let Some(record) = result.as_ref() {
                validate_consensus_record(record)?;
            }
            tx.commit()
                .map_err(|_| StoreError::BackendUnavailable("session store read failed".into()))?;
            Ok(result)
        })
        .await
    }

    /// Read one live record and its durable per-key fence floor together.
    ///
    /// The caller owns the preceding consensus barrier. This local read is a
    /// single SQLite transaction and never allocates a fence or prunes expiry.
    pub(crate) async fn consensus_observe_fenced_transition_at(
        &self,
        key: &SessionKey,
        logical_time: opc_types::Timestamp,
    ) -> Result<crate::FencedTransitionObservation, StoreError> {
        let key = key.clone();
        self.run_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
            let tx = conn
                .unchecked_transaction()
                .map_err(|_| StoreError::BackendUnavailable("session store read failed".into()))?;
            let record = ops::get_sync(&tx, &key, logical_time)?;
            if let Some(record) = record.as_ref() {
                validate_consensus_record(record)?;
                if record.key != key {
                    return Err(StoreError::Serialization(
                        "fenced_transition_observation_invalid".into(),
                    ));
                }
            }
            let current_fence = crate::FenceToken::new(ops::current_fence_sync(&tx, &key)?);
            let observation = crate::FencedTransitionObservation::new(record, current_fence)?;
            tx.commit()
                .map_err(|_| StoreError::BackendUnavailable("session store read failed".into()))?;
            Ok(observation)
        })
        .await
        // This observation is returned to fenced-transition callers. Persisted
        // rows and SQLite diagnostics can contain session data or local schema
        // details, so its entire failure surface is intentionally one fixed,
        // SDK-controlled availability error.
        .map_err(|_| {
            StoreError::BackendUnavailable("fenced transition observation is unavailable".into())
        })
    }

    /// Read one exact fenced-transition receipt after a caller-owned barrier.
    ///
    /// The complete request is required so a reused identity can be reported
    /// as a body conflict. This operation never mutates or compacts the ledger.
    pub(crate) async fn consensus_fenced_transition_status(
        &self,
        storage_identity: crate::consensus::SessionConsensusIdentity,
        _authority_identity: crate::consensus::SessionConsensusIdentity,
        request: &crate::FencedTransitionRequest,
    ) -> Result<crate::FencedTransitionStatus, StoreError> {
        let request = request.clone();
        self.run_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
            let tx = conn
                .unchecked_transaction()
                .map_err(|_| StoreError::BackendUnavailable("session store read failed".into()))?;
            let status = consensus::read_fenced_transition_status_sync(
                &tx,
                storage_identity,
                storage_identity,
                &request,
            )?;
            tx.commit()
                .map_err(|_| StoreError::BackendUnavailable("session store read failed".into()))?;
            Ok(status)
        })
        .await
    }

    /// Read one ordinary consumer lease-mutation receipt after the caller has
    /// completed its leader-linearizable barrier.  This opens a SQLite read
    /// transaction only; it does not advance logical time or submit a
    /// consensus command.
    pub(crate) async fn consensus_consumer_lease_mutation_status(
        &self,
        storage_identity: crate::consensus::SessionConsensusIdentity,
        authority_identity: crate::consensus::SessionConsensusIdentity,
        binding_request_id: crate::consensus::SessionConsensusRequestId,
        operation_request_id: crate::consensus::SessionConsensusRequestId,
        request: &crate::consumer::SessionConsumerRequest,
    ) -> Result<crate::consumer::SessionConsumerLeaseMutationStatus, StoreError> {
        let request = request.clone();
        self.run_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
            let tx = conn
                .unchecked_transaction()
                .map_err(|_| StoreError::BackendUnavailable("session store read failed".into()))?;
            let status = consensus::read_consumer_lease_mutation_status_sync(
                &tx,
                storage_identity,
                authority_identity,
                binding_request_id,
                operation_request_id,
                &request,
            )?;
            tx.commit()
                .map_err(|_| StoreError::BackendUnavailable("session store read failed".into()))?;
            Ok(status)
        })
        .await
    }

    /// Read one prepared consumer compare-and-set receipt after a
    /// caller-owned leader-linearizable barrier. This is a read-only query of
    /// the existing consensus outcome ledger; it opens no prepared-CAS
    /// journal and performs no schema or migration work.
    pub(crate) async fn consensus_consumer_compare_and_set_status(
        &self,
        storage_identity: crate::consensus::SessionConsensusIdentity,
        lookup: consensus::ConsumerCompareAndSetReceiptLookup,
    ) -> Result<crate::consumer::SessionConsumerCompareAndSetStatus, StoreError> {
        self.run_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
            let tx = conn
                .unchecked_transaction()
                .map_err(|_| StoreError::BackendUnavailable("session store read failed".into()))?;
            let status = consensus::read_consumer_compare_and_set_status_sync(
                &tx,
                storage_identity,
                lookup,
            )?;
            tx.commit()
                .map_err(|_| StoreError::BackendUnavailable("session store read failed".into()))?;
            Ok(status)
        })
        .await
    }

    /// Check one exact consumer binding before the leader decides whether a
    /// marker proposal is necessary. This is a point read of the outcome
    /// ledger, not a receipt barrier, mutation, or consensus proposal.
    pub(crate) async fn consensus_consumer_request_binding_lookup(
        &self,
        storage_identity: crate::consensus::SessionConsensusIdentity,
        authority_identity: crate::consensus::SessionConsensusIdentity,
        binding_request_id: crate::consensus::SessionConsensusRequestId,
        request_commitment: [u8; 32],
    ) -> Result<consensus::ConsumerRequestBindingLookup, StoreError> {
        self.run_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
            let tx = conn
                .unchecked_transaction()
                .map_err(|_| StoreError::BackendUnavailable("session store read failed".into()))?;
            let lookup = consensus::read_consumer_request_binding_sync(
                &tx,
                storage_identity,
                authority_identity,
                binding_request_id,
                request_commitment,
            )?;
            tx.commit()
                .map_err(|_| StoreError::BackendUnavailable("session store read failed".into()))?;
            Ok(lookup)
        })
        .await
    }

    /// Read one exact V2 receipt after a caller-owned barrier.
    pub(crate) async fn consensus_fenced_transition_v2_status(
        &self,
        storage_identity: crate::consensus::SessionConsensusIdentity,
        authority_identity: crate::consensus::SessionConsensusIdentity,
        request: &crate::FencedTransitionV2Request,
    ) -> Result<crate::FencedTransitionV2Status, StoreError> {
        let request = request.clone();
        self.run_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
            let tx = conn
                .unchecked_transaction()
                .map_err(|_| StoreError::BackendUnavailable("session store read failed".into()))?;
            let status = consensus::read_fenced_transition_v2_status_sync(
                &tx,
                storage_identity,
                authority_identity,
                &request,
            )?;
            tx.commit()
                .map_err(|_| StoreError::BackendUnavailable("session store read failed".into()))?;
            Ok(status)
        })
        .await
    }

    /// Report whether the durable V2 ledger layout has already been activated.
    ///
    /// This survives replication-authority changes even though the exact-scope
    /// activation certificate is cleared at cutover. Callers use it to keep
    /// prospective voters fail-closed once V2 history semantics are durable.
    pub(crate) async fn consensus_fenced_transition_v2_history_is_activated(
        &self,
        storage_identity: crate::consensus::SessionConsensusIdentity,
    ) -> Result<bool, StoreError> {
        self.run_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
            let persisted_identity = consensus::read_storage_identity_sync(conn).map_err(|_| {
                StoreError::BackendUnavailable("fenced transition V2 history is unavailable".into())
            })?;
            if persisted_identity != storage_identity {
                return Err(StoreError::BackendUnavailable(
                    "fenced transition V2 history is unavailable".into(),
                ));
            }
            consensus::fenced_transition_v2_ledger_layout_sync(conn)
                .map(|layout| layout == consensus::FencedTransitionV2LedgerLayout::Activated)
                .map_err(|_| {
                    StoreError::BackendUnavailable(
                        "fenced transition V2 history is unavailable".into(),
                    )
                })
        })
        .await
    }

    /// Read the durable V2 history lifecycle after a caller-owned barrier.
    pub(crate) async fn consensus_fenced_transition_v2_history_state(
        &self,
        storage_identity: crate::consensus::SessionConsensusIdentity,
        _authority_identity: crate::consensus::SessionConsensusIdentity,
    ) -> Result<crate::FencedTransitionV2HistoryState, StoreError> {
        self.run_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
            consensus::read_fenced_transition_v2_history_state_sync(conn, storage_identity).map_err(
                |_| {
                    StoreError::BackendUnavailable(
                        "fenced transition V2 history is unavailable".into(),
                    )
                },
            )
        })
        .await
    }

    /// Restore scan at one persisted consensus logical timestamp.
    pub(crate) async fn consensus_scan_restore_records_at(
        &self,
        request: RestoreScanRequest,
        logical_time: opc_types::Timestamp,
        deadline: tokio::time::Instant,
    ) -> Result<RestoreScanPage, StoreError> {
        self.run_restore_scan(
            request,
            logical_time,
            deadline,
            RestoreScanValidationProfile::Consensus,
        )
        .await
    }

    async fn run_restore_scan(
        &self,
        request: RestoreScanRequest,
        logical_time: opc_types::Timestamp,
        deadline: tokio::time::Instant,
        profile: RestoreScanValidationProfile,
    ) -> Result<RestoreScanPage, StoreError> {
        let cancellation = Arc::new(AtomicBool::new(false));
        // Admission happens before `spawn_blocking` and the owned permit stays
        // with the blocking closure. A timed-out caller therefore cannot
        // detach another worker behind the one SQLite connection; later calls
        // wait asynchronously and disappear cleanly when their futures drop.
        let worker_permit = tokio::time::timeout_at(
            deadline,
            Arc::clone(&self.restore_scan_workers).acquire_owned(),
        )
        .await
        .map_err(|_| StoreError::RestoreScanWorkBudgetExceeded)?
        .map_err(|_| StoreError::BackendUnavailable("session restore scan unavailable".into()))?;
        // Acquire the async connection guard before entering the blocking
        // pool so a busy connection is part of the same absolute operation
        // deadline and never strands a blocking thread waiting on a mutex.
        let conn = tokio::time::timeout_at(deadline, Arc::clone(&self.conn).lock_owned())
            .await
            .map_err(|_| StoreError::RestoreScanWorkBudgetExceeded)?;
        let operation_deadline = deadline.into_std();
        let task_cancellation = Arc::clone(&cancellation);
        let queued_job = Arc::new(StdMutex::new(Some((conn, worker_permit, request))));
        let task_job = Arc::clone(&queued_job);
        let task = tokio::task::spawn_blocking(move || {
            let (conn, worker_permit, request) = task_job
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()?;
            let _worker_permit = worker_permit;
            if task_cancellation.load(Ordering::Acquire) {
                return Some(Err(StoreError::RestoreScanWorkBudgetExceeded));
            }
            let tx = if profile.is_standalone() {
                match standalone_transaction(&conn) {
                    Ok(tx) => tx,
                    Err(error) => return Some(Err(error)),
                }
            } else {
                match conn
                    .unchecked_transaction()
                    .map_err(|_| StoreError::BackendUnavailable("session store scan failed".into()))
                {
                    Ok(tx) => tx,
                    Err(error) => return Some(Err(error)),
                }
            };
            let result = match ops::scan_restore_records_sync(
                &tx,
                request,
                logical_time,
                Arc::clone(&task_cancellation),
                operation_deadline,
                profile,
            ) {
                Ok(result) => result,
                Err(error) => return Some(Err(error)),
            };
            if task_cancellation.load(Ordering::Acquire) {
                return Some(Err(StoreError::RestoreScanWorkBudgetExceeded));
            }
            if tx.commit().is_err() {
                return Some(Err(StoreError::BackendUnavailable(
                    "session store scan failed".into(),
                )));
            }
            Some(Ok(result))
        });
        let cancel_job = Arc::clone(&queued_job);
        let mut cancel_on_drop = RestoreScanCancellation {
            cancellation: Arc::clone(&cancellation),
            abort: task.abort_handle(),
            cancel_queued: Some(Box::new(move || {
                drop(
                    cancel_job
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .take(),
                );
            })),
            armed: true,
        };
        match tokio::time::timeout_at(deadline, task).await {
            Err(_) => Err(StoreError::RestoreScanWorkBudgetExceeded),
            Ok(Err(_)) => {
                cancel_on_drop.disarm();
                Err(StoreError::BackendUnavailable(
                    "session restore scan task failed".into(),
                ))
            }
            Ok(Ok(Some(result))) => {
                cancel_on_drop.disarm();
                result
            }
            Ok(Ok(None)) => {
                cancel_on_drop.disarm();
                Err(StoreError::RestoreScanWorkBudgetExceeded)
            }
        }
    }

    /// Read the committed application-journal head after the caller has
    /// completed its Openraft linearizable barrier and local apply wait.
    pub(crate) async fn consensus_max_replication_sequence(&self) -> Result<u64, StoreError> {
        self.run_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
            let seq: i64 = conn
                .query_row(
                    "SELECT MAX(machine.watch_sequence, recovery.watch_cursor_invalidation_floor)
                     FROM consensus_machine AS machine
                     JOIN consensus_operator_recovery AS recovery ON recovery.singleton = machine.singleton
                     WHERE machine.singleton = 1",
                    [],
                    |row| row.get(0),
                )
                .map_err(|_| StoreError::BackendUnavailable("session store read failed".into()))?;
            consensus::checked_u64(seq)
                .map_err(|_| StoreError::BackendUnavailable("session store read failed".into()))
        })
        .await
    }

    /// Whether an offline operator reset is awaiting its Openraft-committed
    /// recovery epoch. A pending replica may exchange Raft traffic and rejoin,
    /// but must not admit ordinary session operations or advertise readiness.
    #[cfg(test)]
    pub(crate) async fn consensus_operator_recovery_pending(
        &self,
        identity: crate::consensus::SessionConsensusIdentity,
    ) -> Result<bool, StoreError> {
        #[cfg(test)]
        if self
            .consensus_operator_recovery_failure
            .load(Ordering::Acquire)
        {
            return Err(StoreError::BackendUnavailable(
                "injected session operator recovery check failure".into(),
            ));
        }
        let database_path = self.database_path.clone();
        self.run_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
            let database_latch = database_path
                .as_deref()
                .map(|path| {
                    consensus::classify_operator_recovery_latch_with_connection_sync(path, conn)
                        .map(|classification| classification.latch())
                })
                .transpose()
                .map_err(|_| {
                    StoreError::BackendUnavailable(
                        "session operator recovery latch is unavailable".into(),
                    )
                })?
                .flatten();
            if let Some(latch) = database_latch {
                if latch.identity != identity {
                    return Err(StoreError::BackendUnavailable(
                        "session operator recovery latch identity does not match".into(),
                    ));
                }
                opc_redaction::metrics::METRICS
                    .session_operator_recovery_required
                    .store(1, std::sync::atomic::Ordering::Relaxed);
                opc_redaction::metrics::METRICS
                    .session_operator_recovery_epoch
                    .fetch_max(latch.recovery_epoch, std::sync::atomic::Ordering::Relaxed);
                if latch.audit_pending {
                    opc_redaction::metrics::METRICS
                        .session_operator_recovery_audit_pending
                        .store(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
            consensus::read_operator_recovery_sync(conn, identity)
                .map(|state| state.pending_epoch.is_some() || database_latch.is_some())
                .map_err(|_| {
                    StoreError::BackendUnavailable(
                        "session operator recovery state is unavailable".into(),
                    )
                })
        })
        .await
    }

    #[cfg(test)]
    pub(crate) fn inject_consensus_operator_recovery_failure(&self, enabled: bool) {
        self.consensus_operator_recovery_failure
            .store(enabled, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn inject_fixed_quorum_v2_mutation_snapshot_cut(&self, enabled: bool) {
        self.fixed_quorum_v2_mutation_snapshot_cut
            .store(enabled, Ordering::Release);
    }

    pub(crate) async fn consensus_operator_recovery_committed(
        &self,
        identity: crate::consensus::SessionConsensusIdentity,
        recovery_epoch: u64,
        plan_digest: [u8; 32],
    ) -> Result<bool, StoreError> {
        self.run_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
            consensus::read_operator_recovery_sync(conn, identity)
                .map(|state| {
                    state.pending_epoch.is_none()
                        && state.recovery_epoch == recovery_epoch
                        && state.last_plan_digest == plan_digest
                })
                .map_err(|_| {
                    StoreError::BackendUnavailable(
                        "session operator recovery state is unavailable".into(),
                    )
                })
        })
        .await
    }

    /// Read committed application-journal entries after the caller's Openraft
    /// barrier. This internal path cannot allocate sequencing authority.
    pub(crate) async fn consensus_get_replication_log(
        &self,
        start: u64,
        limit: usize,
    ) -> Result<Vec<ReplicationEntry>, StoreError> {
        let range = ReplicationLogRange::try_new(start, limit)?;
        if range.is_empty() {
            return Ok(Vec::new());
        }
        let Ok(sqlite_start) = i64::try_from(range.first_sequence()) else {
            return Ok(Vec::new());
        };
        let sqlite_limit =
            i64::try_from(range.limit()).map_err(|_| StoreError::InvalidReplicationLogRange)?;
        self.run_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
            let invalidation_floor = consensus::read_watch_cursor_invalidation_floor_sync(conn)
                .map_err(|_| StoreError::BackendUnavailable("session store read failed".into()))?;
            range.ensure_not_compacted(invalidation_floor)?;
            let mut stmt = conn
                .prepare(
                    r#"
                SELECT sequence,
                       CASE
                           WHEN typeof(tx_id) = 'text'
                            AND length(CAST(tx_id AS BLOB)) BETWEEN ?3 AND ?4
                           THEN tx_id
                       END,
                       entry_json
                FROM session_replication_log
                WHERE sequence >= ?1
                ORDER BY sequence ASC
                LIMIT ?2
                "#,
                )
                .map_err(|_| StoreError::BackendUnavailable("session store read failed".into()))?;
            let entries = stmt
                .query_map(
                    params![
                        sqlite_start,
                        sqlite_limit,
                        REPLICATION_TX_ID_MIN_BYTES,
                        REPLICATION_TX_ID_MAX_BYTES
                    ],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, Option<String>>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    },
                )
                .map_err(|_| StoreError::BackendUnavailable("session store read failed".into()))?;
            let mut result = Vec::new();
            for item in entries {
                let (stored_sequence, stored_tx_id, json) = item.map_err(|_| {
                    StoreError::BackendUnavailable("session store read failed".into())
                })?;
                let entry =
                    replication::hydrate_replication_entry(stored_sequence, stored_tx_id, &json)?;
                consensus::validate_sealed_replication_op(&entry.op).map_err(|_| {
                    StoreError::BackendUnavailable("session store read failed".into())
                })?;
                result.push(entry);
            }
            validate_replication_log_page_owned(start, limit, result)
        })
        .await
    }

    /// Subscribe to the committed application journal. The caller must first
    /// complete an Openraft barrier; this function only reads already-applied
    /// state and registers for later state-machine notifications.
    pub(crate) async fn consensus_watch(
        &self,
        start_sequence: u64,
    ) -> Result<
        futures_util::stream::BoxStream<'static, Result<ReplicationEntry, StoreError>>,
        StoreError,
    > {
        let cursor = ReplicationWatchCursor::new(start_sequence);
        let mut watchers = self.watchers.lock().await;
        let existing = self
            .consensus_get_replication_log(
                cursor.first_sequence(),
                watch_backlog_query_limit(cursor),
            )
            .await?;
        #[cfg(test)]
        self.pause_after_watch_backlog_capture().await?;
        let (stream, watcher) = prepare_watch_registration(cursor, existing)?;
        watchers.retain(|watcher| !watcher.is_closed());
        if let Some(watcher) = watcher {
            watchers.push(watcher);
        }
        use futures_util::StreamExt;
        Ok(stream.boxed())
    }

    #[cfg(test)]
    async fn pause_after_watch_backlog_capture(&self) -> Result<(), StoreError> {
        self.watch_backlog_captured.store(true, Ordering::SeqCst);
        let permit = Arc::clone(&self.watch_registration_gate)
            .acquire_owned()
            .await
            .map_err(|_| StoreError::BackendUnavailable("watch registration unavailable".into()))?;
        drop(permit);
        Ok(())
    }
}

fn sqlite_capabilities() -> BackendCapabilities {
    BackendCapabilities {
        atomic_compare_and_set: true,
        monotonic_fencing_token: true,
        per_key_ttl: true,
        server_side_lease_expiry: true,
        ordered_replication_log: false,
        batch_write: true,
        watch: false,
        restore_scan: true,
        max_value_bytes: SQLITE_SESSION_MAX_VALUE_BYTES,
    }
}

#[cfg(test)]
#[test]
fn consensus_value_cap_stays_below_unexpanded_transport_contract() {
    let backend = SqliteSessionBackend::in_memory().expect("in-memory SQLite backend");
    assert_eq!(
        backend.consensus_capabilities().max_value_bytes,
        SQLITE_CONSENSUS_MAX_VALUE_BYTES
    );
    assert!(backend.consensus_capabilities().max_value_bytes < SQLITE_SESSION_MAX_VALUE_BYTES);
}

#[cfg(test)]
#[test]
fn snapshot_page_guard_uses_the_actual_sparse_sqlite_page_size() {
    let conn = Connection::open_in_memory().expect("open SQLite fixture");
    install_consensus_snapshot_extent_guard(&conn).expect("install physical snapshot guard");
    let page_size: u64 = conn
        .query_row("PRAGMA page_size", [], |row| row.get::<_, i64>(0))
        .expect("read SQLite page size")
        .try_into()
        .expect("positive SQLite page size");
    let maximum_pages: i64 = conn
        .query_row("PRAGMA max_page_count", [], |row| row.get(0))
        .expect("read SQLite page bound");
    assert_eq!(
        u64::try_from(maximum_pages).expect("positive SQLite page bound") * page_size,
        crate::consensus::snapshot::SNAPSHOT_DATABASE_MAX_BYTES / page_size * page_size
    );
}

#[cfg(test)]
#[test]
fn file_backed_snapshot_guard_reopens_and_read_only_validation_preserves_identity() {
    let directory = tempfile::tempdir().expect("create SQLite fixture directory");
    let path = directory.path().join("session.sqlite");
    let backend = SqliteSessionBackend::open(&path).expect("create file-backed SQLite backend");
    drop(backend);

    // Exercise the production file-backed reopen path before inspecting the
    // independently observable SQLite setting below.
    let reopened_backend =
        SqliteSessionBackend::open(&path).expect("reopen file-backed SQLite backend");
    drop(reopened_backend);

    // Every normal file-backed reopen reinstalls the writer guard at the
    // actual SQLite page size. The query-only handle uses the independent
    // extent validation instead, which cannot mutate the database identity.
    let reopened = Connection::open(&path).expect("reopen SQLite fixture");
    install_consensus_snapshot_extent_guard(&reopened).expect("reinstall physical guard");
    let page_size: u64 = reopened
        .query_row("PRAGMA page_size", [], |row| row.get::<_, i64>(0))
        .expect("read SQLite page size")
        .try_into()
        .expect("positive SQLite page size");
    let maximum_pages: i64 = reopened
        .query_row("PRAGMA max_page_count", [], |row| row.get(0))
        .expect("read SQLite page bound");
    assert_eq!(
        u64::try_from(maximum_pages).expect("positive SQLite page bound") * page_size,
        crate::consensus::snapshot::SNAPSHOT_DATABASE_MAX_BYTES / page_size * page_size
    );
    drop(reopened);

    let before = std::fs::metadata(&path).expect("read fixture identity");
    let read_only = Connection::open_with_flags(
        &path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("open query-only SQLite fixture");
    consensus::snapshot_database_extent_sync(&read_only)
        .expect("query-only fixture is within the shared physical extent");
    drop(read_only);
    let after = std::fs::metadata(&path).expect("re-read fixture identity");
    assert_eq!(before.len(), after.len());
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
    }
}

#[cfg(test)]
#[test]
fn file_backed_open_rejects_a_sparse_file_beyond_the_common_extent() {
    let directory = tempfile::tempdir().expect("create SQLite fixture directory");
    let path = directory.path().join("oversized.sqlite");
    let backend = SqliteSessionBackend::open(&path).expect("create file-backed SQLite backend");
    drop(backend);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("open sparse SQLite fixture");
    file.set_len(crate::consensus::snapshot::SNAPSHOT_DATABASE_MAX_BYTES + 1)
        .expect("extend sparse SQLite fixture without allocating it");
    drop(file);
    assert!(SqliteSessionBackend::open(&path).is_err());
}

#[cfg(test)]
mod fenced_transition_observation_redaction_tests {
    use super::*;
    use crate::model::SessionKeyType;
    use bytes::Bytes;
    use opc_types::{NetworkFunctionKind, TenantId, Timestamp};

    const FIXED_MESSAGE: &str = "fenced transition observation is unavailable";

    fn key() -> SessionKey {
        SessionKey {
            tenant: TenantId::new("sqlite-observe-tenant").expect("tenant"),
            nf_kind: NetworkFunctionKind::from_static("smf"),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"key-canary")
                .try_into()
                .expect("stable ID"),
        }
    }

    fn assert_fixed_redacted_error(error: StoreError) {
        let display = error.to_string();
        let debug = format!("{error:?}");
        assert_eq!(
            error,
            StoreError::BackendUnavailable(FIXED_MESSAGE.into()),
            "observation errors use one fixed SDK category"
        );
        assert_eq!(
            display,
            format!("backend unavailable: {FIXED_MESSAGE}"),
            "observation display is fixed"
        );
        assert_eq!(
            debug,
            format!("BackendUnavailable(\"{FIXED_MESSAGE}\")"),
            "observation debug is fixed"
        );
        for forbidden in [
            "key-canary",
            "owner-canary",
            "request-canary",
            "state-class-canary",
            "timestamp-canary",
            "session_records",
            "key_fences",
            "state_class",
            "no such table",
            "SQLite",
            "/",
        ] {
            assert!(
                !display.contains(forbidden) && !debug.contains(forbidden),
                "observation error leaked {forbidden:?}"
            );
        }
    }

    #[tokio::test]
    async fn corrupt_persisted_record_is_redacted_from_fenced_transition_observation() {
        let backend = SqliteSessionBackend::in_memory().expect("in-memory SQLite backend");
        let key = key();
        {
            let conn = backend.conn.lock().await;
            conn.execute(
                "INSERT INTO session_records (tenant, nf_kind, key_type, stable_id, generation, owner, fence, state_class, state_type, expires_at, payload, encoding) VALUES (?1, ?2, ?3, ?4, 1, ?5, 1, ?6, ?7, ?8, X'00', 2)",
                rusqlite::params![
                    key.tenant.as_str(),
                    key.nf_kind.as_str(),
                    key.key_type.to_string(),
                    key.stable_id.as_ref(),
                    "owner-canary",
                    "state-class-canary",
                    "request-canary",
                    "timestamp-canary",
                ],
            )
            .expect("insert corrupt persisted record");
        }

        let error = backend
            .consensus_observe_fenced_transition_at(&key, Timestamp::now_utc())
            .await
            .expect_err("corrupt persisted record must fail observation");
        assert_fixed_redacted_error(error);
    }

    #[tokio::test]
    async fn schema_failure_is_redacted_from_fenced_transition_observation() {
        let backend = SqliteSessionBackend::in_memory().expect("in-memory SQLite backend");
        let key = key();
        {
            let conn = backend.conn.lock().await;
            conn.execute_batch("DROP TABLE session_records")
                .expect("remove observation table");
        }

        let error = backend
            .consensus_observe_fenced_transition_at(&key, Timestamp::now_utc())
            .await
            .expect_err("missing table must fail observation");
        assert_fixed_redacted_error(error);
    }
}

fn sqlite_store_outcome_unavailable(kind: SqliteStoreWorkKind) -> StoreError {
    match kind {
        SqliteStoreWorkKind::Read => {
            StoreError::BackendUnavailable("session SQLite operation did not complete".into())
        }
        SqliteStoreWorkKind::CompareAndSet => StoreError::CasIdempotencyOutcomeUnavailable,
        SqliteStoreWorkKind::Mutation => StoreError::BackendOperationOutcomeUnavailable,
    }
}

fn session_op_result_has_backend_unavailable(result: &SessionOpResult) -> bool {
    let error = match result {
        SessionOpResult::Get(Err(error))
        | SessionOpResult::CompareAndSet(Err(error))
        | SessionOpResult::DeleteFenced(Err(error))
        | SessionOpResult::RefreshTtl(Err(error)) => Some(error),
        SessionOpResult::Get(Ok(_))
        | SessionOpResult::CompareAndSet(Ok(_))
        | SessionOpResult::DeleteFenced(Ok(()))
        | SessionOpResult::RefreshTtl(Ok(())) => None,
    };
    matches!(error, Some(StoreError::BackendUnavailable(_)))
}

/// Add the durable lease-acquisition binding without minting history for
/// already-issued credentials.
///
/// A pre-column row has no authoritative acquisition timestamp: lease TTLs
/// record only an expiry, so deriving an acquisition instant from it would
/// make caller-supplied guard metadata authoritative. SQLite fills the
/// nullable column with `NULL` for those rows. The lease authority checks
/// treat that value as a legacy, non-renewable/non-mutable marker while the
/// existing expiry continues to bound its lifetime. New acquisitions always
/// write a normalized timestamp.
fn migrate_lease_acquired_at_schema(conn: &Connection) -> Result<(), StoreError> {
    let mut statement = conn.prepare("PRAGMA table_info(leases)").map_err(|_| {
        StoreError::BackendUnavailable("session lease schema is unavailable".into())
    })?;
    let columns = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })
        .map_err(|_| StoreError::BackendUnavailable("session lease schema is unavailable".into()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            StoreError::BackendUnavailable("session lease schema is unavailable".into())
        })?;

    let acquired_at = columns
        .iter()
        .filter(|(name, ..)| name == "acquired_at")
        .collect::<Vec<_>>();
    match acquired_at.as_slice() {
        [] => conn
            .execute("ALTER TABLE leases ADD COLUMN acquired_at TEXT", [])
            .map(|_| ())
            .map_err(|_| {
                StoreError::BackendUnavailable("session lease schema migration failed".into())
            }),
        [(_, column_type, not_null, default, primary_key)]
            if column_type.eq_ignore_ascii_case("TEXT")
                && *not_null == 0
                && default.is_none()
                && *primary_key == 0 =>
        {
            Ok(())
        }
        _ => Err(StoreError::BackendUnavailable(
            "session lease authority schema is invalid".into(),
        )),
    }
}

fn apply_pragma_profile(
    conn: &Connection,
    in_memory: bool,
    primary_write_connection: bool,
) -> Result<(), StoreError> {
    if in_memory {
        conn.execute_batch(
            r#"
            PRAGMA synchronous = EXTRA;
            PRAGMA foreign_keys = ON;
            PRAGMA locking_mode = NORMAL;
            PRAGMA temp_store = MEMORY;
            "#,
        )
    } else {
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = EXTRA;
            PRAGMA foreign_keys = ON;
            PRAGMA locking_mode = NORMAL;
            PRAGMA temp_store = MEMORY;
            "#,
        )
    }
    .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
    conn.busy_timeout(Duration::from_millis(SQLITE_BUSY_TIMEOUT_MILLIS))
        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;

    // This writer guard caps the shared physical SQLite image. Protected
    // roster HistoryFull/RetentionExhausted remains protocol/logical
    // accounting; arbitrary non-roster rows are governed only by this common
    // extent. Read-only snapshot and recovery opens verify the same actual
    // extent because they cannot safely install a write-like pragma.
    if !in_memory {
        install_consensus_snapshot_extent_guard(conn)?;
    }

    if !in_memory && primary_write_connection {
        conn.pragma_update(
            None,
            "wal_autocheckpoint",
            SQLITE_WRITER_WAL_AUTOCHECKPOINT_PAGES,
        )
        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
        let wal_autocheckpoint: i32 = conn
            .query_row("PRAGMA wal_autocheckpoint", [], |row| row.get(0))
            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
        if wal_autocheckpoint != SQLITE_WRITER_WAL_AUTOCHECKPOINT_PAGES {
            return Err(StoreError::BackendUnavailable(
                "failed to set SQLite WAL autocheckpoint threshold".into(),
            ));
        }
    }

    let foreign_keys: i32 = conn
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
    if foreign_keys != 1 {
        return Err(StoreError::BackendUnavailable(
            "failed to enable SQLite foreign key enforcement".into(),
        ));
    }

    if !in_memory {
        let journal_mode: String = conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(StoreError::BackendUnavailable(format!(
                "failed to enable SQLite WAL journal mode: {journal_mode}"
            )));
        }
    }

    Ok(())
}

fn install_consensus_snapshot_extent_guard(conn: &Connection) -> Result<(), StoreError> {
    consensus::install_snapshot_database_extent_guard_sync(conn)
        .map_err(|error| StoreError::BackendUnavailable(error.to_string()))
}

// ─────────────────────────────────────────────────────────────────────────────
// SessionBackend Implementation
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait]
impl SessionBackend for SqliteSessionBackend {
    fn restore_scan_cursor_profile(&self) -> Option<crate::RestoreScanCursorProfile> {
        Some(crate::RestoreScanCursorProfile::DurableOpaqueV1)
    }

    fn backend_instance_identity(&self) -> Option<BackendInstanceIdentity> {
        Some(BackendInstanceIdentity::for_shared(&self.conn))
    }

    async fn capabilities(&self) -> BackendCapabilities {
        let caps = self.caps;
        self.run_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
            Ok(
                match (
                    consensus_identity_exists(conn),
                    operator_recovery_latch_exists(conn),
                ) {
                    (Ok(false), Ok(false)) => caps,
                    _ => BackendCapabilities::minimal(),
                },
            )
        })
        .await
        .unwrap_or_else(|_| BackendCapabilities::minimal())
    }

    fn record_expiry_reference(&self) -> Option<opc_types::Timestamp> {
        Some(self.clock.now_utc())
    }

    async fn get(&self, key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
        let key = key.clone();
        let now = self.clock.now_utc();
        self.run_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
            let tx = standalone_transaction(conn)?;
            let result = ops::get_sync(&tx, &key, now)?;
            // Standalone SQLite owns its local monotonic clock and may
            // physically prune on reads. Consensus reads never mutate outside
            // an Openraft-applied command.
            ops::prune_sync(&tx, now)?;
            tx.commit()
                .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
            Ok(result)
        })
        .await
    }

    async fn compare_and_set(&self, op: CompareAndSet) -> Result<CompareAndSetResult, StoreError> {
        let now = self.clock.now_utc();
        validate_stored_record_expiry_at(&op.new_record, now)?;
        let caps = self.caps;
        self.run_store_sqlite_task(SqliteStoreWorkKind::CompareAndSet, move |conn| {
            let tx = standalone_transaction(conn)?;
            let result = ops::compare_and_set_sync(&tx, &op, &caps, now)?;
            tx.commit()
                .map_err(|_| StoreError::CasIdempotencyOutcomeUnavailable)?;
            Ok(result)
        })
        .await
    }

    async fn delete_fenced(&self, lease: &LeaseGuard) -> Result<(), StoreError> {
        let lease = lease.clone();
        let now = self.clock.now_utc();
        let caps = self.caps;
        self.run_store_sqlite_task(SqliteStoreWorkKind::Mutation, move |conn| {
            let tx = standalone_transaction(conn)?;
            ops::delete_fenced_sync(&tx, &lease, &caps, now)?;
            tx.commit()
                .map_err(|_| StoreError::BackendOperationOutcomeUnavailable)?;
            Ok(())
        })
        .await
    }

    async fn refresh_ttl(&self, lease: &LeaseGuard, ttl: Duration) -> Result<(), StoreError> {
        validate_session_ttl(ttl)?;
        let now = self.clock.now_utc();
        checked_session_deadline(now, ttl)?;
        let lease = lease.clone();
        let caps = self.caps;
        self.run_store_sqlite_task(SqliteStoreWorkKind::Mutation, move |conn| {
            let tx = standalone_transaction(conn)?;
            ops::refresh_ttl_sync(&tx, &lease, ttl, &caps, now)?;
            tx.commit()
                .map_err(|_| StoreError::BackendOperationOutcomeUnavailable)?;
            Ok(())
        })
        .await
    }

    async fn batch(&self, ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
        let now = self.clock.now_utc();
        validate_session_ops_at(&ops, now)?;
        for op in &ops {
            if let SessionOp::RefreshTtl { ttl, .. } = op {
                checked_session_deadline(now, *ttl)?;
            }
        }
        if !self.caps.batch_write {
            return Err(StoreError::CapabilityNotSupported("batch_write".into()));
        }
        let contains_mutation = ops.iter().any(|op| !matches!(op, SessionOp::Get { .. }));
        let kind = if contains_mutation {
            SqliteStoreWorkKind::Mutation
        } else {
            SqliteStoreWorkKind::Read
        };
        let caps = self.caps;
        self.run_store_sqlite_task(kind, move |conn| {
            let mut results = Vec::with_capacity(ops.len());
            let mut effect_may_have_committed = false;
            for op in ops {
                let mutation_slot = !matches!(&op, SessionOp::Get { .. });
                let result = match op {
                    SessionOp::Get { key } => {
                        let run_get = || {
                            let tx = standalone_transaction(conn)?;
                            let result = ops::get_sync(&tx, &key, now)?;
                            tx.commit()
                                .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
                            Ok(result)
                        };
                        SessionOpResult::Get(run_get())
                    }
                    SessionOp::CompareAndSet(cas) => {
                        let run_cas = || {
                            let tx = standalone_transaction(conn)?;
                            let result = ops::compare_and_set_sync(&tx, &cas, &caps, now)?;
                            tx.commit()
                                .map_err(|_| StoreError::CasIdempotencyOutcomeUnavailable)?;
                            Ok(result)
                        };
                        SessionOpResult::CompareAndSet(run_cas())
                    }
                    SessionOp::DeleteFenced { lease } => {
                        let run_delete = || {
                            let tx = standalone_transaction(conn)?;
                            ops::delete_fenced_sync(&tx, &lease, &caps, now)?;
                            tx.commit()
                                .map_err(|_| StoreError::BackendOperationOutcomeUnavailable)?;
                            Ok(())
                        };
                        SessionOpResult::DeleteFenced(run_delete())
                    }
                    SessionOp::RefreshTtl { lease, ttl } => {
                        let run_refresh = || {
                            let tx = standalone_transaction(conn)?;
                            ops::refresh_ttl_sync(&tx, &lease, ttl, &caps, now)?;
                            tx.commit()
                                .map_err(|_| StoreError::BackendOperationOutcomeUnavailable)?;
                            Ok(())
                        };
                        SessionOpResult::RefreshTtl(run_refresh())
                    }
                };
                if session_op_result_has_backend_unavailable(&result) {
                    return Err(if effect_may_have_committed {
                        StoreError::BackendOperationOutcomeUnavailable
                    } else {
                        StoreError::BackendUnavailable(
                            "session SQLite batch outcome is unavailable".into(),
                        )
                    });
                }
                if mutation_slot {
                    // A non-generic result proves the slot crossed its SQLite
                    // admission/transaction setup. From this point onward a
                    // later generic backend error cannot prove that no prior
                    // batch effect committed.
                    effect_may_have_committed = true;
                }
                results.push(result);
            }
            Ok(results)
        })
        .await
    }

    async fn scan_restore_records(
        &self,
        request: RestoreScanRequest,
    ) -> Result<RestoreScanPage, StoreError> {
        let now = self.clock.now_utc();
        let deadline = tokio::time::Instant::now()
            .checked_add(Duration::from_millis(
                crate::RESTORE_SCAN_MAX_SQLITE_WORK_MILLIS,
            ))
            .ok_or(StoreError::RestoreScanWorkBudgetExceeded)?;
        self.run_restore_scan(
            request,
            now,
            deadline,
            RestoreScanValidationProfile::Standalone,
        )
        .await
    }

    async fn max_replication_sequence(&self) -> Result<u64, StoreError> {
        self.run_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
            let tx = standalone_transaction(conn)?;
            let seq: Option<Option<i64>> = tx
                .query_row(
                    "SELECT MAX(sequence) FROM session_replication_log",
                    [],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
            let sequence = seq
                .flatten()
                .map(replication::stored_replication_sequence)
                .transpose()
                .map(|sequence| sequence.unwrap_or(0))?;
            tx.commit().map_err(|_| {
                StoreError::BackendUnavailable("session store operation failed".into())
            })?;
            Ok(sequence)
        })
        .await
    }

    async fn get_replication_log(
        &self,
        start: u64,
        limit: usize,
    ) -> Result<Vec<ReplicationEntry>, StoreError> {
        let range = ReplicationLogRange::try_new(start, limit)?;
        if range.is_empty() {
            return Ok(Vec::new());
        }
        let Ok(sqlite_start) = i64::try_from(range.first_sequence()) else {
            return Ok(Vec::new());
        };
        let sqlite_limit =
            i64::try_from(range.limit()).map_err(|_| StoreError::InvalidReplicationLogRange)?;
        self.run_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
            let tx = standalone_transaction(conn)?;
            let result = {
                let mut stmt = tx
                    .prepare(
                        r#"
                SELECT sequence,
                       CASE
                           WHEN typeof(tx_id) = 'text'
                            AND length(CAST(tx_id AS BLOB)) BETWEEN ?3 AND ?4
                           THEN tx_id
                       END,
                       entry_json
                FROM session_replication_log
                WHERE sequence >= ?1
                ORDER BY sequence ASC
                LIMIT ?2
                "#,
                    )
                    .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
                let entries = stmt
                    .query_map(
                        params![
                            sqlite_start,
                            sqlite_limit,
                            REPLICATION_TX_ID_MIN_BYTES,
                            REPLICATION_TX_ID_MAX_BYTES
                        ],
                        |row| {
                            Ok((
                                row.get::<_, i64>(0)?,
                                row.get::<_, Option<String>>(1)?,
                                row.get::<_, String>(2)?,
                            ))
                        },
                    )
                    .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;

                let mut result = Vec::new();
                for item in entries {
                    let (stored_sequence, stored_tx_id, json) =
                        item.map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
                    result.push(replication::hydrate_replication_entry(
                        stored_sequence,
                        stored_tx_id,
                        &json,
                    )?);
                }
                validate_replication_log_page_owned(start, limit, result)?
            };
            tx.commit().map_err(|_| {
                StoreError::BackendUnavailable("session store operation failed".into())
            })?;
            Ok(result)
        })
        .await
    }

    async fn replicate_entry(&self, entry: ReplicationEntry) -> Result<(), StoreError> {
        let entry = entry.into_validated()?;
        replication::validate_replication_payloads(&entry.op, self.caps.max_value_bytes)?;
        let worker_entry = entry.clone();
        let now = self.clock.now_utc();
        let caps = self.caps;
        let should_notify = self
            .run_store_sqlite_task(SqliteStoreWorkKind::Mutation, move |conn| {
                replication::replicate_entry_sync(conn, &worker_entry, &caps, now)
            })
            .await?;

        if should_notify {
            let mut watchers = self.watchers.lock().await;
            watchers.retain_mut(|watcher| watcher.notify(&entry));
        }

        Ok(())
    }

    async fn rebuild_replication_state(
        &self,
        entries: Vec<ReplicationEntry>,
    ) -> Result<(), StoreError> {
        let entries = validate_replication_prefix_owned(entries)?;
        for entry in &entries {
            replication::validate_replication_payloads(&entry.op, self.caps.max_value_bytes)?;
        }
        let caps = self.caps;
        self.run_store_sqlite_task(SqliteStoreWorkKind::Mutation, move |conn| {
            replication::rebuild_replication_state_sync(conn, &entries, &caps)
        })
        .await
    }

    async fn watch(
        &self,
        start_sequence: u64,
    ) -> Result<
        futures_util::stream::BoxStream<'static, Result<ReplicationEntry, StoreError>>,
        StoreError,
    > {
        let cursor = ReplicationWatchCursor::new(start_sequence);
        let mut watchers = self.watchers.lock().await;
        let existing = self
            .get_replication_log(cursor.first_sequence(), watch_backlog_query_limit(cursor))
            .await?;
        #[cfg(test)]
        self.pause_after_watch_backlog_capture().await?;
        let (stream, watcher) = prepare_watch_registration(cursor, existing)?;
        watchers.retain(|watcher| !watcher.is_closed());
        if let Some(watcher) = watcher {
            watchers.push(watcher);
        }

        use futures_util::StreamExt;
        Ok(stream.boxed())
    }

    async fn next_lease_info(&self) -> Result<(u64, u64), StoreError> {
        self.run_store_sqlite_task(SqliteStoreWorkKind::Read, move |conn| {
            let tx = standalone_transaction(conn)?;
            let (next_fence, next_credential_id) = {
                let mut global_stmt = tx
                    .prepare("SELECT val FROM lease_globals WHERE key = ?1")
                    .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
                let next_fence: i64 = global_stmt
                    .query_row(["next_fence"], |row| row.get(0))
                    .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
                let next_credential_id: i64 = global_stmt
                    .query_row(["next_credential_id"], |row| row.get(0))
                    .map_err(|e| StoreError::BackendUnavailable(e.to_string()))?;
                (next_fence, next_credential_id)
            };
            let result = (
                ops::persisted_u64(next_fence)?,
                ops::persisted_u64(next_credential_id)?,
            );
            tx.commit().map_err(|_| {
                StoreError::BackendUnavailable("session store operation failed".into())
            })?;
            Ok(result)
        })
        .await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SessionLeaseManager Implementation
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait]
impl SessionLeaseManager for SqliteSessionBackend {
    async fn acquire(
        &self,
        key: &SessionKey,
        owner: OwnerId,
        ttl: Duration,
    ) -> Result<LeaseGuard, LeaseError> {
        validate_session_ttl(ttl).map_err(LeaseError::from)?;
        let now = self.clock.now_utc();
        checked_session_deadline(now, ttl).map_err(LeaseError::from)?;
        let key = key.clone();
        self.run_lease_sqlite_task(move |conn| {
            let tx = standalone_transaction(conn).map_err(LeaseError::from)?;
            let result = lease::acquire_sync(&tx, &key, owner, ttl, now)?;
            tx.commit()
                .map_err(|_| LeaseError::OperationOutcomeUnavailable)?;
            Ok(result)
        })
        .await
    }

    async fn renew(&self, lease: &LeaseGuard, ttl: Duration) -> Result<LeaseGuard, LeaseError> {
        validate_session_ttl(ttl).map_err(LeaseError::from)?;
        let now = self.clock.now_utc();
        checked_session_deadline(now, ttl).map_err(LeaseError::from)?;
        let lease = lease.clone();
        self.run_lease_sqlite_task(move |conn| {
            let tx = standalone_transaction(conn).map_err(LeaseError::from)?;
            let result = lease::renew_sync(&tx, &lease, ttl, now)?;
            tx.commit()
                .map_err(|_| LeaseError::OperationOutcomeUnavailable)?;
            Ok(result)
        })
        .await
    }

    async fn release(&self, lease: LeaseGuard) -> Result<(), LeaseError> {
        let now = self.clock.now_utc();
        self.run_lease_sqlite_task(move |conn| {
            let tx = standalone_transaction(conn).map_err(LeaseError::from)?;
            lease::release_sync(&tx, lease, now)?;
            tx.commit()
                .map_err(|_| LeaseError::OperationOutcomeUnavailable)?;
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod operation_lifetime_tests {
    use super::*;
    use crate::{
        backend::ReplicationOp,
        model::{FenceToken, Generation, SessionKeyType, StateClass, StateType},
        record::EncryptedSessionPayload,
    };
    use bytes::Bytes;
    use opc_types::{NetworkFunctionKind, TenantId, Timestamp};
    use rusqlite::hooks::{AuthAction, Authorization};

    fn key(stable_id: &'static [u8]) -> SessionKey {
        SessionKey {
            tenant: TenantId::new("sqlite-lifetime").expect("tenant"),
            nf_kind: NetworkFunctionKind::from_static("smf"),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(stable_id).try_into().expect("stable ID"),
        }
    }

    fn record(key: SessionKey, lease: &LeaseGuard) -> StoredSessionRecord {
        StoredSessionRecord {
            key,
            generation: Generation::new(1),
            owner: lease.owner().clone(),
            fence: FenceToken::new(lease.fence().get()),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::new("sqlite-lifetime").expect("state type"),
            expires_at: None,
            payload: EncryptedSessionPayload::new(vec![0x5a]),
        }
    }

    fn replication_entry(key: SessionKey, lease: &LeaseGuard) -> ReplicationEntry {
        let timestamp = Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH);
        let expires_at = Timestamp::from_offset_datetime(
            time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(60),
        );
        ReplicationEntry {
            sequence: 1,
            tx_id: "sqlite-lifetime-replication"
                .try_into()
                .expect("transaction ID"),
            op: ReplicationOp::RefreshTtl {
                key,
                owner: lease.owner().clone(),
                fence: FenceToken::new(lease.fence().get()),
                ttl: Duration::from_secs(60),
                expires_at,
            },
            timestamp,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_sqlite_lock_contention_is_bounded_and_known_preeffect_failures_remain_retryable()
    {
        let directory = tempfile::tempdir().expect("SQLite lifetime directory");
        let path = directory.path().join("store.sqlite");
        let backend = SqliteSessionBackend::open(&path).expect("SQLite backend");
        let key = key(b"blocked-operation");
        let lease = backend
            .acquire(
                &key,
                OwnerId::new("sqlite-lifetime-owner").expect("owner"),
                Duration::from_secs(60),
            )
            .await
            .expect("prepare lease");
        let compare_and_set = CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: record(key.clone(), &lease),
        };
        let entry = replication_entry(key.clone(), &lease);

        let blocker = Connection::open(&path).expect("blocking SQLite connection");
        blocker
            .execute_batch("BEGIN IMMEDIATE")
            .expect("hold SQLite write reservation");

        assert!(matches!(
            backend.get(&key).await,
            Err(StoreError::BackendUnavailable(_))
        ));
        assert!(matches!(
            backend.compare_and_set(compare_and_set).await,
            Err(StoreError::BackendUnavailable(_))
        ));
        assert!(matches!(
            backend.delete_fenced(&lease).await,
            Err(StoreError::BackendUnavailable(_))
        ));
        assert!(matches!(
            backend.replicate_entry(entry.clone()).await,
            Err(StoreError::BackendUnavailable(_))
        ));
        assert!(matches!(
            backend.rebuild_replication_state(vec![entry]).await,
            Err(StoreError::BackendUnavailable(_))
        ));
        assert!(matches!(
            backend.renew(&lease, Duration::from_secs(60)).await,
            Err(LeaseError::Backend(_))
        ));
        assert_eq!(
            backend.operation_workers.available_permits(),
            SQLITE_OPERATION_BLOCKING_WORKERS
        );

        blocker.execute_batch("ROLLBACK").expect("release blocker");
        assert_eq!(backend.get(&key).await.expect("read after unblock"), None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn file_backed_consensus_acceptance_reader_pool_admits_unrelated_probes_and_uses_fresh_snapshots(
    ) {
        let directory = tempfile::tempdir().expect("SQLite acceptance-reader directory");
        let path = directory.path().join("store.sqlite");
        let backend = SqliteSessionBackend::open(&path).expect("SQLite backend");
        let clone = backend.clone();
        let pool = backend
            .consensus_acceptance_reader_pool
            .as_ref()
            .expect("file-backed stores have acceptance readers");
        assert!(Arc::ptr_eq(
            pool,
            clone
                .consensus_acceptance_reader_pool
                .as_ref()
                .expect("backend clones share the acceptance reader pool"),
        ));
        assert!(Arc::ptr_eq(
            &pool.workers,
            &clone
                .consensus_acceptance_reader_pool
                .as_ref()
                .expect("backend clones share the acceptance reader pool")
                .workers,
        ));
        assert_eq!(
            pool.usable_lanes(),
            SQLITE_CONSENSUS_ACCEPTANCE_READ_WORKERS,
            "acceptance reads have a fixed process-local reader width",
        );

        // Remove one lane and hold the primary writer mutex. The two remaining
        // lanes must both enter their independent acceptance probes; a single
        // mutex-protected reader would leave the second probe behind the first.
        let held_reader = {
            let mut receiver = pool.receiver.lock().await;
            receiver.recv().await.expect("reader pool lane")
        };
        let held_primary = backend.conn.lock().await;
        let entered = Arc::new(std::sync::Barrier::new(3));
        let first_backend = clone.clone();
        let first_entered = Arc::clone(&entered);
        let first = tokio::spawn(async move {
            first_backend
                .run_consensus_acceptance_read_task(move |conn| {
                    let tx = conn.unchecked_transaction().map_err(|_| {
                        StoreError::BackendUnavailable("session store read failed".into())
                    })?;
                    let count = tx
                        .query_row("SELECT COUNT(*) FROM session_records", [], |row| {
                            row.get::<_, i64>(0)
                        })
                        .map_err(|_| {
                            StoreError::BackendUnavailable("session store read failed".into())
                        })?;
                    first_entered.wait();
                    tx.commit().map_err(|_| {
                        StoreError::BackendUnavailable("session store read failed".into())
                    })?;
                    Ok(count)
                })
                .await
        });
        let second_backend = clone.clone();
        let second_entered = Arc::clone(&entered);
        let second = tokio::spawn(async move {
            second_backend
                .run_consensus_acceptance_read_task(move |conn| {
                    let tx = conn.unchecked_transaction().map_err(|_| {
                        StoreError::BackendUnavailable("session store read failed".into())
                    })?;
                    let count = tx
                        .query_row("SELECT COUNT(*) FROM session_records", [], |row| {
                            row.get::<_, i64>(0)
                        })
                        .map_err(|_| {
                            StoreError::BackendUnavailable("session store read failed".into())
                        })?;
                    second_entered.wait();
                    tx.commit().map_err(|_| {
                        StoreError::BackendUnavailable("session store read failed".into())
                    })?;
                    Ok(count)
                })
                .await
        });
        let observer = Arc::clone(&entered);
        tokio::task::spawn_blocking(move || observer.wait())
            .await
            .expect("acceptance probes enter distinct reader lanes");
        assert_eq!(
            first.await.expect("first probe task").expect("first probe"),
            0
        );
        assert_eq!(
            second
                .await
                .expect("second probe task")
                .expect("second probe"),
            0
        );
        drop(held_primary);
        pool.sender
            .send(held_reader)
            .await
            .expect("return held reader lane");

        // Each checkout starts a new transaction rather than reusing a stale
        // snapshot retained by a previous borrower.
        backend
            .conn
            .lock()
            .await
            .execute_batch(
                "CREATE TABLE acceptance_reader_visibility (value INTEGER NOT NULL);
                 INSERT INTO acceptance_reader_visibility (value) VALUES (1);",
            )
            .expect("writer commits a new row");
        let visible_rows = clone
            .run_consensus_acceptance_read_task(|conn| {
                let tx = conn.unchecked_transaction().map_err(|_| {
                    StoreError::BackendUnavailable("session store read failed".into())
                })?;
                let count = tx
                    .query_row(
                        "SELECT COUNT(*) FROM acceptance_reader_visibility",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .map_err(|_| {
                        StoreError::BackendUnavailable("session store read failed".into())
                    })?;
                tx.commit().map_err(|_| {
                    StoreError::BackendUnavailable("session store read failed".into())
                })?;
                Ok(count)
            })
            .await
            .expect("fresh reader transaction sees committed writer state");
        assert_eq!(visible_rows, 1);

        let callers = (0..32)
            .map(|_| {
                let backend = clone.clone();
                tokio::spawn(async move {
                    backend
                        .run_consensus_acceptance_read_task(|conn| {
                            conn.query_row("SELECT 1", [], |row| row.get::<_, i64>(0))
                                .map_err(|_| {
                                    StoreError::BackendUnavailable(
                                        "session store read failed".into(),
                                    )
                                })
                        })
                        .await
                })
            })
            .collect::<Vec<_>>();
        for caller in callers {
            assert_eq!(caller.await.expect("caller task").expect("caller probe"), 1);
        }
        assert_eq!(
            pool.usable_lanes(),
            SQLITE_CONSENSUS_ACCEPTANCE_READ_WORKERS
        );
        assert_eq!(
            pool.workers.available_permits(),
            SQLITE_CONSENSUS_ACCEPTANCE_READ_WORKERS
        );
    }

    #[tokio::test]
    async fn file_backed_writer_sets_exact_wal_autocheckpoint_ceiling() {
        let directory = tempfile::tempdir().expect("SQLite writer-profile directory");
        let path = directory.path().join("store.sqlite");
        let backend = SqliteSessionBackend::open(&path).expect("SQLite backend");
        let writer = backend.conn.lock().await;
        let wal_autocheckpoint: i32 = writer
            .query_row("PRAGMA wal_autocheckpoint", [], |row| row.get(0))
            .expect("writer WAL autocheckpoint threshold");

        assert_eq!(
            wal_autocheckpoint, SQLITE_WRITER_WAL_AUTOCHECKPOINT_PAGES,
            "the primary writer owns the fixed WAL autocheckpoint threshold",
        );
    }

    #[tokio::test]
    async fn acceptance_reader_return_skips_checkpoint_and_next_transaction_sees_fresh_commit() {
        let directory = tempfile::tempdir().expect("SQLite acceptance-reader directory");
        let path = directory.path().join("store.sqlite");
        let backend = SqliteSessionBackend::open(&path).expect("SQLite backend");
        let pool = backend
            .consensus_acceptance_reader_pool
            .as_ref()
            .expect("file-backed stores have acceptance readers");
        {
            let writer = backend.conn.lock().await;
            writer
                .execute_batch(
                    "CREATE TABLE acceptance_reader_return_visibility (value INTEGER NOT NULL);",
                )
                .expect("create visibility table");
        }

        // Empty the channel so the returned reader is the next borrower. The
        // two unreturned lanes are deliberately held only within this test.
        let mut readers = {
            let mut receiver = pool.receiver.lock().await;
            let mut readers = Vec::with_capacity(SQLITE_CONSENSUS_ACCEPTANCE_READ_WORKERS);
            for _ in 0..SQLITE_CONSENSUS_ACCEPTANCE_READ_WORKERS {
                readers.push(receiver.recv().await.expect("reader pool lane"));
            }
            readers
        };
        let reader = readers.pop().expect("reader to return");
        let checkpoint_attempts = Arc::new(AtomicUsize::new(0));
        reader.authorizer(Some({
            let checkpoint_attempts = Arc::clone(&checkpoint_attempts);
            move |context: rusqlite::hooks::AuthContext<'_>| match context.action {
                AuthAction::Pragma { pragma_name, .. }
                    if pragma_name.eq_ignore_ascii_case("wal_checkpoint") =>
                {
                    checkpoint_attempts.fetch_add(1, Ordering::AcqRel);
                    Authorization::Deny
                }
                _ => Authorization::Allow,
            }
        }));

        let first = reader
            .unchecked_transaction()
            .expect("first reader transaction");
        let first_visible: i64 = first
            .query_row(
                "SELECT COUNT(*) FROM acceptance_reader_return_visibility",
                [],
                |row| row.get(0),
            )
            .expect("first reader snapshot");
        first.commit().expect("close first reader transaction");
        assert_eq!(first_visible, 0);
        {
            let writer = backend.conn.lock().await;
            writer
                .execute(
                    "INSERT INTO acceptance_reader_return_visibility (value) VALUES (1)",
                    [],
                )
                .expect("writer commits fresh state");
        }

        let permit = pool
            .workers
            .clone()
            .try_acquire_owned()
            .expect("reader worker permit");
        pool.return_or_retire(reader, permit);
        assert_eq!(
            checkpoint_attempts.load(Ordering::Acquire),
            0,
            "returning a reader never attempts a manual WAL checkpoint",
        );

        let returned = {
            let mut receiver = pool.receiver.lock().await;
            receiver.recv().await.expect("returned reader lane")
        };
        let next = returned
            .unchecked_transaction()
            .expect("next reader transaction");
        let next_visible: i64 = next
            .query_row(
                "SELECT COUNT(*) FROM acceptance_reader_return_visibility",
                [],
                |row| row.get(0),
            )
            .expect("next reader snapshot");
        next.commit().expect("close next reader transaction");
        assert_eq!(
            next_visible, 1,
            "the next transaction sees the fresh commit"
        );
    }

    #[tokio::test]
    async fn repeated_acceptance_snapshots_skip_manual_checkpoints_and_observe_commits() {
        let directory = tempfile::tempdir().expect("SQLite acceptance-reader directory");
        let path = directory.path().join("store.sqlite");
        let backend = SqliteSessionBackend::open(&path).expect("SQLite backend");
        let pool = backend
            .consensus_acceptance_reader_pool
            .as_ref()
            .expect("file-backed stores have acceptance readers");
        let checkpoint_attempts = Arc::new(AtomicUsize::new(0));

        // Instrument every fixed reader lane before returning it to the pool.
        // A denied checkpoint makes the historical per-return path observable
        // without permitting it to alter the connection's state.
        let readers = {
            let mut receiver = pool.receiver.lock().await;
            let mut readers = Vec::with_capacity(SQLITE_CONSENSUS_ACCEPTANCE_READ_WORKERS);
            for _ in 0..SQLITE_CONSENSUS_ACCEPTANCE_READ_WORKERS {
                readers.push(receiver.recv().await.expect("reader pool lane"));
            }
            readers
        };
        for reader in readers {
            reader.authorizer(Some({
                let checkpoint_attempts = Arc::clone(&checkpoint_attempts);
                move |context: rusqlite::hooks::AuthContext<'_>| match context.action {
                    AuthAction::Pragma { pragma_name, .. }
                        if pragma_name.eq_ignore_ascii_case("wal_checkpoint") =>
                    {
                        checkpoint_attempts.fetch_add(1, Ordering::AcqRel);
                        Authorization::Deny
                    }
                    _ => Authorization::Allow,
                }
            }));
            pool.sender
                .try_send(reader)
                .expect("return instrumented reader lane");
        }
        {
            let writer = backend.conn.lock().await;
            writer
                .execute_batch(
                    "CREATE TABLE repeated_acceptance_reader_visibility (value INTEGER NOT NULL);",
                )
                .expect("create visibility table");
        }

        // Cycle through every fixed lane twice. Each closure establishes and
        // commits its own transaction, which is the acceptance visibility cut.
        for expected_rows in 1..=(SQLITE_CONSENSUS_ACCEPTANCE_READ_WORKERS as i64 * 2) {
            {
                let writer = backend.conn.lock().await;
                writer
                    .execute(
                        "INSERT INTO repeated_acceptance_reader_visibility (value) VALUES (1)",
                        [],
                    )
                    .expect("writer commits fresh state");
            }
            let visible_rows = backend
                .run_consensus_acceptance_read_task(|conn| {
                    let tx = conn.unchecked_transaction().map_err(|_| {
                        StoreError::BackendUnavailable("session store read failed".into())
                    })?;
                    let rows = tx
                        .query_row(
                            "SELECT COUNT(*) FROM repeated_acceptance_reader_visibility",
                            [],
                            |row| row.get::<_, i64>(0),
                        )
                        .map_err(|_| {
                            StoreError::BackendUnavailable("session store read failed".into())
                        })?;
                    tx.commit().map_err(|_| {
                        StoreError::BackendUnavailable("session store read failed".into())
                    })?;
                    Ok(rows)
                })
                .await
                .expect("acceptance snapshot succeeds");
            assert_eq!(
                visible_rows, expected_rows,
                "each fresh acceptance transaction sees the current committed state",
            );
        }

        assert_eq!(
            checkpoint_attempts.load(Ordering::Acquire),
            0,
            "no acceptance snapshot return attempts a manual WAL checkpoint",
        );
        assert_eq!(
            pool.usable_lanes(),
            SQLITE_CONSENSUS_ACCEPTANCE_READ_WORKERS,
            "all bounded reader lanes remain usable",
        );
        assert_eq!(
            pool.workers.available_permits(),
            SQLITE_CONSENSUS_ACCEPTANCE_READ_WORKERS,
            "all bounded reader permits are returned",
        );
    }

    #[tokio::test]
    async fn acceptance_reader_health_requires_autocommit_and_select() {
        let directory = tempfile::tempdir().expect("SQLite acceptance-reader directory");
        let path = directory.path().join("store.sqlite");
        let backend = SqliteSessionBackend::open(&path).expect("SQLite backend");
        let pool = backend
            .consensus_acceptance_reader_pool
            .as_ref()
            .expect("file-backed stores have acceptance readers");
        let reader = {
            let mut receiver = pool.receiver.lock().await;
            receiver.recv().await.expect("reader pool lane")
        };

        assert!(pool.connection_is_usable(&reader));
        reader
            .execute_batch("BEGIN")
            .expect("open reader transaction");
        assert!(
            !pool.connection_is_usable(&reader),
            "a reader with an active transaction is not reusable",
        );
        reader
            .execute_batch("ROLLBACK")
            .expect("close reader transaction");
        reader.authorizer(Some(
            |context: rusqlite::hooks::AuthContext<'_>| match context.action {
                AuthAction::Select => Authorization::Deny,
                _ => Authorization::Allow,
            },
        ));
        assert!(
            !pool.connection_is_usable(&reader),
            "a reader that cannot run its SELECT 1 health probe is retired",
        );
    }

    #[tokio::test]
    async fn acceptance_reader_retirement_never_counts_an_unreplenished_lane_as_ready() {
        let directory = tempfile::tempdir().expect("SQLite acceptance-reader directory");
        let path = directory.path().join("store.sqlite");
        let backend = SqliteSessionBackend::open(&path).expect("SQLite backend");
        let pool = backend
            .consensus_acceptance_reader_pool
            .as_ref()
            .expect("file-backed stores have acceptance readers");
        pool.retire_next_reader.store(true, Ordering::Release);
        pool.fail_replenishment.store(true, Ordering::Release);

        assert_eq!(
            backend
                .run_consensus_acceptance_read_task(|conn| {
                    conn.query_row("SELECT 1", [], |row| row.get::<_, i64>(0))
                        .map_err(|_| {
                            StoreError::BackendUnavailable("session store read failed".into())
                        })
                })
                .await
                .expect("completed probe remains sound before reader retirement"),
            1
        );
        assert_eq!(
            pool.usable_lanes(),
            SQLITE_CONSENSUS_ACCEPTANCE_READ_WORKERS - 1,
            "a dead lane is retired from usable reader capacity",
        );
        assert_eq!(
            pool.workers.available_permits(),
            SQLITE_CONSENSUS_ACCEPTANCE_READ_WORKERS - 1,
            "the retired lane leaves no phantom admission permit",
        );
    }

    #[tokio::test]
    async fn acceptance_reader_task_panic_returns_its_lane_once() {
        let directory = tempfile::tempdir().expect("SQLite acceptance-reader directory");
        let path = directory.path().join("store.sqlite");
        let backend = SqliteSessionBackend::open(&path).expect("SQLite backend");
        let pool = backend
            .consensus_acceptance_reader_pool
            .as_ref()
            .expect("file-backed stores have acceptance readers");

        let outcome = backend
            .run_consensus_acceptance_read_task(|_| -> Result<(), StoreError> {
                panic!("injected acceptance reader task panic")
            })
            .await;
        assert_eq!(
            outcome,
            Err(sqlite_store_outcome_unavailable(SqliteStoreWorkKind::Read)),
        );
        assert_eq!(
            pool.usable_lanes(),
            SQLITE_CONSENSUS_ACCEPTANCE_READ_WORKERS,
            "the dropped lease returns the reader before join-error handling",
        );
        assert_eq!(
            pool.workers.available_permits(),
            SQLITE_CONSENSUS_ACCEPTANCE_READ_WORKERS,
            "the panic path returns exactly one matching worker permit",
        );
    }

    #[tokio::test]
    async fn batch_backend_failure_after_an_earlier_commit_is_typed_ambiguous() {
        let backend = SqliteSessionBackend::in_memory().expect("in-memory SQLite");
        let key = key(b"partially-committed-batch");
        let lease = backend
            .acquire(
                &key,
                OwnerId::new("partial-batch-owner").expect("owner"),
                Duration::from_secs(60),
            )
            .await
            .expect("prepare batch lease");
        backend
            .conn
            .lock()
            .await
            .execute_batch(
                "CREATE TRIGGER fail_test_refresh
                 BEFORE UPDATE OF expires_at ON session_records
                 BEGIN SELECT RAISE(ABORT, 'forced refresh failure'); END;",
            )
            .expect("install deterministic second-slot failure");

        let error = backend
            .batch(vec![
                SessionOp::CompareAndSet(CompareAndSet {
                    key: key.clone(),
                    lease: lease.clone(),
                    expected_generation: None,
                    new_record: record(key.clone(), &lease),
                }),
                SessionOp::RefreshTtl {
                    lease,
                    ttl: Duration::from_secs(30),
                },
            ])
            .await
            .expect_err("later backend failure makes the whole batch outcome unknown");
        assert_eq!(error, StoreError::BackendOperationOutcomeUnavailable);
        assert!(
            backend
                .get(&key)
                .await
                .expect("read committed first slot")
                .is_some(),
            "the first slot committed before the second slot failed"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_sqlite_mutation_retains_its_worker_until_blocking_work_stops() {
        let directory = tempfile::tempdir().expect("SQLite cancellation directory");
        let path = directory.path().join("store.sqlite");
        let backend = SqliteSessionBackend::open(&path).expect("SQLite backend");
        let key = key(b"cancelled-operation");
        let lease = backend
            .acquire(
                &key,
                OwnerId::new("sqlite-cancel-owner").expect("owner"),
                Duration::from_secs(60),
            )
            .await
            .expect("prepare lease");
        let operation = CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: record(key.clone(), &lease),
        };
        let blocker = Connection::open(&path).expect("blocking SQLite connection");
        blocker
            .execute_batch("BEGIN IMMEDIATE")
            .expect("hold SQLite write reservation");

        let worker_backend = backend.clone();
        let task = tokio::spawn(async move { worker_backend.compare_and_set(operation).await });
        tokio::time::timeout(Duration::from_secs(1), async {
            while backend.operation_workers.available_permits() == SQLITE_OPERATION_BLOCKING_WORKERS
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("blocking worker starts");
        assert_eq!(
            backend.operation_workers.available_permits(),
            0,
            "the live blocking job retains its admission permit"
        );
        task.abort();
        assert!(task.await.expect_err("cancel task").is_cancelled());
        tokio::time::timeout(Duration::from_secs(1), async {
            while backend.operation_workers.available_permits() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("interrupted blocking worker exits within the SQLite busy bound");

        blocker.execute_batch("ROLLBACK").expect("release blocker");
        assert_eq!(backend.get(&key).await.expect("read after unblock"), None);
    }

    #[test]
    fn cancelling_queued_blocking_tasks_releases_captured_sqlite_admission() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .expect("single blocking-thread runtime");

        let (
            ordinary_released,
            ordinary_connection_released,
            restore_released,
            restore_connection_released,
        ) = runtime.block_on(async {
            let (started_tx, started_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let saturator = tokio::task::spawn_blocking(move || {
                let _ = started_tx.send(());
                let _ = release_rx.recv();
            });
            started_rx.await.expect("blocking pool saturator starts");

            let backend = SqliteSessionBackend::in_memory().expect("in-memory SQLite");
            let ordinary_backend = backend.clone();
            let ordinary = tokio::spawn(async move {
                ordinary_backend
                    .run_sqlite_task(|_| Ok::<(), StoreError>(()))
                    .await
            });
            tokio::time::timeout(Duration::from_secs(1), async {
                while backend.operation_workers.available_permits()
                    == SQLITE_OPERATION_BLOCKING_WORKERS
                {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("ordinary SQLite job queues behind saturated pool");
            ordinary.abort();
            let _ = ordinary.await;
            let ordinary_released = tokio::time::timeout(Duration::from_secs(1), async {
                while backend.operation_workers.available_permits() == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .is_ok();
            let ordinary_connection_released = backend.conn.try_lock().is_ok();

            let restore_backend = backend.clone();
            let restore = tokio::spawn(async move {
                let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
                restore_backend
                    .run_restore_scan(
                        RestoreScanRequest::all(1),
                        restore_backend.clock.now_utc(),
                        deadline,
                        RestoreScanValidationProfile::Standalone,
                    )
                    .await
            });
            tokio::time::timeout(Duration::from_secs(1), async {
                while backend.restore_scan_workers.available_permits()
                    == RESTORE_SCAN_BLOCKING_WORKERS
                {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("restore SQLite job queues behind saturated pool");
            restore.abort();
            let _ = restore.await;
            let restore_released = tokio::time::timeout(Duration::from_secs(1), async {
                while backend.restore_scan_workers.available_permits() == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .is_ok();
            let restore_connection_released = backend.conn.try_lock().is_ok();

            let _ = release_tx.send(());
            saturator.await.expect("blocking pool saturator exits");
            (
                ordinary_released,
                ordinary_connection_released,
                restore_released,
                restore_connection_released,
            )
        });

        assert!(ordinary_released, "queued ordinary job retained its permit");
        assert!(
            ordinary_connection_released,
            "queued ordinary job retained its connection guard"
        );
        assert!(restore_released, "queued restore job retained its permit");
        assert!(
            restore_connection_released,
            "queued restore job retained its connection guard"
        );
    }
}

#[cfg(test)]
mod consensus_readiness_deadline_tests {
    use std::collections::BTreeMap;

    use opc_consensus::{
        derive_configuration_id, ConsensusClusterId, ConsensusConfigurationEpoch, ConsensusIdentity,
    };

    use super::*;
    use crate::{
        consensus::ConsensusSessionStore,
        readiness::DurableReadinessState,
        topology::{
            QuorumReplicaDescriptor, ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain,
            ReplicaId, ReplicaTlsIdentity, ValidatedQuorumTopology,
        },
    };

    const OPERATION_TIMEOUT: Duration = Duration::from_secs(1);
    const RECOVERY_PREFLIGHT_HOLD: Duration = Duration::from_millis(600);
    const PROBE_ASSERTION_SLACK: Duration = Duration::from_millis(250);

    fn singleton_topology() -> ValidatedQuorumTopology {
        let replica_id = ReplicaId::new("readiness-deadline-singleton").expect("replica ID");
        let descriptor = QuorumReplicaDescriptor::new(
            replica_id.clone(),
            ReplicaEndpoint::new("readiness-deadline.invalid", 7443).expect("endpoint"),
            ReplicaTlsIdentity::new("spiffe://test/session/readiness-deadline")
                .expect("TLS identity"),
            ReplicaFailureDomain::new("readiness-deadline-zone").expect("failure domain"),
            ReplicaBackingIdentity::new("readiness-deadline-disk").expect("backing identity"),
        );
        let cluster_id =
            ConsensusClusterId::new("session-readiness-deadline-tests").expect("cluster ID");
        let epoch = ConsensusConfigurationEpoch::new(1).expect("configuration epoch");
        let configuration_id =
            derive_configuration_id(cluster_id, epoch, &[descriptor.configuration_fingerprint()]);
        ValidatedQuorumTopology::try_new_consensus_lab_singleton(
            replica_id,
            vec![descriptor],
            ConsensusIdentity::new(cluster_id, configuration_id, epoch),
        )
        .expect("singleton topology")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn readiness_recovery_and_barrier_share_one_complete_operation_deadline() {
        let _timing_permit = crate::acquire_consensus_timing_test_permit().await;
        let snapshots = tempfile::tempdir().expect("snapshot directory");
        let backend = SqliteSessionBackend::open(snapshots.path().join("sessions.sqlite"))
            .expect("file-backed SQLite backend");
        let apply_gate = Arc::clone(&backend.consensus_apply_gate);
        let store = ConsensusSessionStore::open_with_operation_timeout(
            singleton_topology(),
            backend.clone(),
            snapshots.path(),
            BTreeMap::new(),
            OPERATION_TIMEOUT,
        )
        .await
        .expect("open consensus singleton");
        store
            .initialize_cluster()
            .await
            .expect("initialize consensus singleton");
        assert!(store.probe_durable_readiness().await.is_ready());

        let held_apply = apply_gate
            .acquire_owned()
            .await
            .expect("hold state-machine apply");
        let status_before = store.status();
        let mutation_store = store.clone();
        let mutation = tokio::spawn(async move { mutation_store.max_replication_sequence().await });
        tokio::time::timeout(OPERATION_TIMEOUT, async {
            loop {
                let status = store.status();
                if status.last_log_index.is_some_and(|last| {
                    last > status_before.last_log_index.unwrap_or_default()
                        && status.applied_index.is_none_or(|applied| applied < last)
                }) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("mutation reaches the log while apply is held");

        let held_connection = backend.conn.lock().await;
        let probe_store = store.clone();
        let probe_started = tokio::time::Instant::now();
        let mut probe = tokio::spawn(async move { probe_store.probe_durable_readiness().await });
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut probe)
                .await
                .is_err(),
            "readiness recovery preflight remains blocked on the held live consensus connection"
        );
        tokio::time::sleep_until(probe_started + RECOVERY_PREFLIGHT_HOLD).await;
        drop(held_connection);

        let report = tokio::time::timeout_at(
            probe_started + OPERATION_TIMEOUT + PROBE_ASSERTION_SLACK,
            &mut probe,
        )
        .await
        .expect("readiness probe must not receive a second operation budget")
        .expect("readiness probe task");
        assert_eq!(report.state(), DurableReadinessState::NoQuorum);
        assert!(probe_started.elapsed() >= RECOVERY_PREFLIGHT_HOLD);

        drop(held_apply);
        let _ = tokio::time::timeout(Duration::from_secs(2), mutation)
            .await
            .expect("mutation task settles after apply resumes")
            .expect("mutation task");
        store
            .shutdown()
            .await
            .expect("shutdown consensus singleton");
    }
}

#[cfg(test)]
mod restore_cancellation_tests {
    use super::*;

    #[tokio::test]
    async fn queued_worker_admission_uses_the_restore_operation_deadline() {
        let backend = SqliteSessionBackend::in_memory().expect("in-memory SQLite");
        let held_permit = Arc::clone(&backend.restore_scan_workers)
            .acquire_owned()
            .await
            .expect("hold restore worker admission");

        for _ in 0..4 {
            let deadline = tokio::time::Instant::now() + Duration::from_millis(25);
            let error = backend
                .run_restore_scan(
                    RestoreScanRequest::all(1),
                    backend.clock.now_utc(),
                    deadline,
                    RestoreScanValidationProfile::Standalone,
                )
                .await
                .expect_err("queued scan must stop at its absolute deadline");
            assert_eq!(error, StoreError::RestoreScanWorkBudgetExceeded);
        }
        drop(held_permit);

        let page = backend
            .scan_restore_records(RestoreScanRequest::all(1))
            .await
            .expect("worker admission recovers after repeated timeouts");
        assert!(page.complete);
    }

    #[tokio::test]
    async fn held_connection_admission_is_async_bounded_and_recovers() {
        let backend = SqliteSessionBackend::in_memory().expect("in-memory SQLite");
        let held_connection = backend.conn.lock().await;
        let deadline = tokio::time::Instant::now() + Duration::from_millis(25);
        let error = backend
            .run_restore_scan(
                RestoreScanRequest::all(1),
                backend.clock.now_utc(),
                deadline,
                RestoreScanValidationProfile::Standalone,
            )
            .await
            .expect_err("connection admission must stop at the operation deadline");
        assert_eq!(error, StoreError::RestoreScanWorkBudgetExceeded);
        assert_eq!(
            backend.restore_scan_workers.available_permits(),
            RESTORE_SCAN_BLOCKING_WORKERS,
            "a connection timeout cannot detach a blocking worker"
        );
        drop(held_connection);

        let page = backend
            .scan_restore_records(RestoreScanRequest::all(1))
            .await
            .expect("connection admission recovers after timeout");
        assert!(page.complete);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn repeated_cancelled_restore_scans_admit_only_one_blocking_worker() {
        let backend = SqliteSessionBackend::in_memory().expect("in-memory SQLite");
        let held_connection = backend.conn.lock().await;
        let first_backend = backend.clone();
        let mut scans = vec![tokio::spawn(async move {
            first_backend
                .scan_restore_records(RestoreScanRequest::all(1))
                .await
        })];
        tokio::time::timeout(Duration::from_secs(1), async {
            while backend.restore_scan_workers.available_permits()
                != RESTORE_SCAN_BLOCKING_WORKERS - 1
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first restore worker acquires the sole admission permit");

        for _ in 0..64 {
            let cancelled_backend = backend.clone();
            scans.push(tokio::spawn(async move {
                cancelled_backend
                    .scan_restore_records(RestoreScanRequest::all(1))
                    .await
            }));
        }
        tokio::task::yield_now().await;
        assert_eq!(
            backend.restore_scan_workers.available_permits(),
            0,
            "queued callers cannot admit another blocking worker"
        );

        for scan in &scans {
            scan.abort();
        }
        for scan in scans {
            let cancelled = scan.await.expect_err("scan task is cancelled");
            assert!(cancelled.is_cancelled());
        }
        assert_eq!(
            backend.restore_scan_workers.available_permits(),
            RESTORE_SCAN_BLOCKING_WORKERS,
            "cancelling async connection admission cannot detach a worker"
        );
        drop(held_connection);

        let page = tokio::time::timeout(
            Duration::from_secs(1),
            backend.scan_restore_records(RestoreScanRequest::all(1)),
        )
        .await
        .expect("cancelled blocking task releases the connection promptly")
        .expect("fresh restore scan succeeds");
        assert!(page.complete);
    }
}

#[cfg(test)]
mod watcher_lifetime_tests {
    use super::*;
    use crate::ReplicationOp;
    use futures_util::StreamExt;
    use opc_types::Timestamp;

    fn watch_entry(sequence: u64) -> ReplicationEntry {
        ReplicationEntry {
            sequence,
            tx_id: format!("sqlite-watch-{sequence}")
                .try_into()
                .expect("transaction ID"),
            op: ReplicationOp::Batch { ops: Vec::new() },
            timestamp: Timestamp::now_utc(),
        }
    }

    #[tokio::test]
    async fn repeated_idle_watch_disconnects_are_pruned_before_registration() {
        let backend = SqliteSessionBackend::in_memory().expect("in-memory SQLite");
        for _ in 0..128 {
            let stream = backend.watch(1).await.expect("register idle watch");
            drop(stream);
        }

        let live = backend.watch(1).await.expect("register live watch");
        assert_eq!(
            backend.watchers.lock().await.len(),
            1,
            "closed idle watchers cannot accumulate without a later mutation"
        );
        drop(live);
    }

    #[tokio::test]
    async fn append_between_backlog_capture_and_registration_is_delivered_once() {
        let backend = SqliteSessionBackend::in_memory().expect("in-memory SQLite");
        backend
            .replicate_entry(watch_entry(1))
            .await
            .expect("seed backlog");

        let held_registration = Arc::clone(&backend.watch_registration_gate)
            .acquire_owned()
            .await
            .expect("hold registration failpoint");
        let watch_backend = backend.clone();
        let watch = tokio::spawn(async move { watch_backend.watch(1).await });
        tokio::time::timeout(Duration::from_secs(1), async {
            while !backend.watch_backlog_captured.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("watch captures backlog before registration");

        let append_backend = backend.clone();
        let append =
            tokio::spawn(async move { append_backend.replicate_entry(watch_entry(2)).await });
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if backend
                    .max_replication_sequence()
                    .await
                    .expect("read committed standalone head")
                    == 2
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("append commits while notification waits on registration");

        drop(held_registration);
        let mut stream = watch
            .await
            .expect("watch task")
            .expect("atomic watch registration");
        append
            .await
            .expect("append task")
            .expect("append notification");
        assert_eq!(
            stream
                .next()
                .await
                .expect("backlog entry")
                .expect("valid")
                .sequence,
            1
        );
        assert_eq!(
            stream
                .next()
                .await
                .expect("live entry")
                .expect("valid")
                .sequence,
            2
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(25), stream.next())
                .await
                .is_err(),
            "handoff must not duplicate the append"
        );
    }

    #[tokio::test]
    async fn slow_sqlite_watch_receiver_is_evicted_at_the_live_bound() {
        let backend = SqliteSessionBackend::in_memory().expect("in-memory SQLite");
        let mut stream = backend.watch(1).await.expect("register slow watcher");
        for sequence in 1..=u64::try_from(crate::backend::WATCH_CHANNEL_CAPACITY + 1)
            .expect("bounded fixture width")
        {
            backend
                .replicate_entry(watch_entry(sequence))
                .await
                .expect("append live watch fixture");
        }

        for expected in 1..=u64::try_from(crate::backend::WATCH_CHANNEL_CAPACITY)
            .expect("bounded fixture width")
        {
            assert_eq!(
                stream
                    .next()
                    .await
                    .expect("buffered live item")
                    .expect("valid live item")
                    .sequence,
                expected
            );
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(100), stream.next())
                .await
                .expect("closed slow watcher deadline")
                .is_none(),
            "slow watcher must close rather than retain more live state"
        );
    }
}
