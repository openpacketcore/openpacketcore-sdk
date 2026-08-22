//! Bounded `/5` mTLS transport for server-owned managed provider jobs.
//!
//! This module deliberately has a closed, two-operation wire protocol.  In
//! particular it does not serialize provider input, verifier material, worker
//! identity, private evidence, receipts, or a caller supplied job identity.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::io;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
#[cfg(test)]
use std::sync::Condvar;
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::FutureExt;
use opc_session_store::fenced_mutation_roster::FencedMutationRosterOrdinal;
use opc_session_store::{
    derive_fenced_mutation_roster_scope, FencedMutationRosterAdmission, ManagedProviderJobError,
    ManagedProviderJobMemberPhase, ManagedProviderJobMode, ManagedProviderJobStatus,
    SessionConsumerScope,
};
use opc_types::SpiffeId;
use rustls_pki_types::ServerName;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(test)]
use tokio::io::AsyncWriteExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Notify, OwnedSemaphorePermit, Semaphore};
use tokio::task::{JoinHandle, JoinSet};

use crate::consensus::RemoteAddrResolver;
use crate::error::classify_tls_io_error;
use crate::protocol::{
    write_frame_bounded_until_classified, FrameWriteError as ProtocolFrameWriteError,
};

/// The dedicated managed-provider ALPN. No predecessor ALPN is offered.
pub const MANAGED_PROVIDER_JOB_ALPN: &[u8] = b"opc-session-consumer/5";
/// Fixed transport revision for the managed-provider lane.
pub const MANAGED_PROVIDER_JOB_TRANSPORT_REVISION: u16 = 7;
/// Fixed semantic revision for the managed-provider wire DTO family.
pub const MANAGED_PROVIDER_JOB_SEMANTIC_REVISION: u16 = 5;
/// The immutable voter cardinality for this client family.
pub const MANAGED_PROVIDER_JOB_VOTERS: usize = 3;
/// The default fixed connection width per voter.
pub const DEFAULT_MANAGED_PROVIDER_POOL_LANES: usize = 4;
/// Hard cap for lanes per voter; this is a resource bound, not a tuning knob.
pub const MAX_MANAGED_PROVIDER_POOL_LANES: usize = 16;
/// Aggregate queued plus in-flight work bound.
pub const MANAGED_PROVIDER_POOL_QUEUE_CAPACITY: usize = 1024;
/// Maximum retained encoded request bytes across the pool.
pub const DEFAULT_MANAGED_PROVIDER_POOL_REQUEST_BYTES: usize = 8_588_477;
/// Maximum bounded public response bytes.
pub const DEFAULT_MANAGED_PROVIDER_POOL_RESPONSE_BYTES: usize = 1024;
/// No managed-provider listener may allocate more permits than Tokio accepts.
pub const MAX_MANAGED_PROVIDER_SERVER_CONNECTIONS: usize = Semaphore::MAX_PERMITS;

// This is the exact JSON frame length for simultaneously maximal legal V5
// fields: 8 members × 4096-byte descriptors, 128 NUL-byte owner (JSON's
// longest legal string escaping), 1 MiB plan,
// 16 KiB terminal result, and a second 1 MiB checkpoint, including each
// closed-envelope byte. The maximum-legal-frame test derives this value from
// those source profile maxima. Peers prove it in Hello instead of silently
// accepting a caller-selected frame size.
pub const MANAGED_PROVIDER_V5_REQUEST_FRAME_BYTES: usize = 8_588_477;
/// Fixed public result profile; status and every typed domain error fit here.
pub const MANAGED_PROVIDER_V5_RESPONSE_FRAME_BYTES: usize = 1024;
/// One absolute setup budget spans resolver, TCP, TLS, Hello, and HelloAck.
pub const MANAGED_PROVIDER_SETUP_TIMEOUT: Duration = Duration::from_secs(2);
/// Each authenticated application frame has one non-renewing budget.
pub const MANAGED_PROVIDER_FRAME_TIMEOUT: Duration = Duration::from_millis(250);
/// A facade call cannot retain an admitted server connection indefinitely.
pub const MANAGED_PROVIDER_FACADE_TIMEOUT: Duration = Duration::from_secs(2);
/// Largest supported caller-to-scheduler queue budget. It is exactly one
/// bounded application-frame interval, so queued work cannot outlive the
/// transport protocol's own fixed application deadline.
pub const MAX_MANAGED_PROVIDER_POOL_QUEUE_TIMEOUT: Duration = MANAGED_PROVIDER_FRAME_TIMEOUT;
/// Largest supported lane setup budget. Resolver, TCP, TLS, Hello, and Ack
/// share the protocol's one fixed setup transaction budget.
pub const MAX_MANAGED_PROVIDER_POOL_SETUP_TIMEOUT: Duration = MANAGED_PROVIDER_SETUP_TIMEOUT;
/// Largest supported graceful drain. It covers the existing setup and facade
/// budgets plus four bounded application-frame intervals, rounded to the
/// established five-second managed-provider shutdown policy.
pub const MAX_MANAGED_PROVIDER_POOL_SHUTDOWN_DRAIN: Duration = Duration::from_secs(5);

const PROFILE_DOMAIN: &[u8] = b"opc-session-net/managed-provider/5/profile\0";
// The server identity is authenticated by the TLS peer certificate and bound
// to the endpoint before Hello is sent.  Echoing it in HelloAck was redundant
// and made a legal 2048-byte canonical SPIFFE identity exceed the fixed public
// response profile.
const PROFILE_ACK_OMITS_VOTER_IDENTITY: u8 = 1;
// Kept equal to `opc_identity::MAX_SPIFFE_ID_URI_LEN`; this crate does not
// depend on identity reload machinery at runtime solely for its profile bound.
const PROFILE_MAX_SPIFFE_ID_BYTES: usize = 2_048;

fn profile_digest() -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(PROFILE_DOMAIN);
    hash.update(MANAGED_PROVIDER_JOB_TRANSPORT_REVISION.to_be_bytes());
    hash.update(MANAGED_PROVIDER_JOB_SEMANTIC_REVISION.to_be_bytes());
    hash.update((MANAGED_PROVIDER_V5_REQUEST_FRAME_BYTES as u64).to_be_bytes());
    hash.update((MANAGED_PROVIDER_V5_RESPONSE_FRAME_BYTES as u64).to_be_bytes());
    hash.update([PROFILE_ACK_OMITS_VOTER_IDENTITY]);
    hash.update((PROFILE_MAX_SPIFFE_ID_BYTES as u64).to_be_bytes());
    hash.finalize().into()
}

/// Redaction-safe construction failure for the `/5` pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid managed provider pool configuration")]
pub struct ManagedProviderPoolConfigError;

/// Fixed resource limits for one composite, three-voter client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManagedProviderPoolConfig {
    lanes_per_voter: usize,
    queued_and_inflight: usize,
    request_bytes: usize,
    response_bytes: usize,
    queue_deadline: Duration,
    setup_timeout: Duration,
    shutdown_drain: Duration,
}

impl Default for ManagedProviderPoolConfig {
    fn default() -> Self {
        Self {
            lanes_per_voter: DEFAULT_MANAGED_PROVIDER_POOL_LANES,
            queued_and_inflight: MANAGED_PROVIDER_POOL_QUEUE_CAPACITY,
            request_bytes: MANAGED_PROVIDER_V5_REQUEST_FRAME_BYTES,
            response_bytes: MANAGED_PROVIDER_V5_RESPONSE_FRAME_BYTES,
            queue_deadline: MAX_MANAGED_PROVIDER_POOL_QUEUE_TIMEOUT,
            setup_timeout: MAX_MANAGED_PROVIDER_POOL_SETUP_TIMEOUT,
            shutdown_drain: MAX_MANAGED_PROVIDER_POOL_SHUTDOWN_DRAIN,
        }
    }
}

impl ManagedProviderPoolConfig {
    /// Construct a complete bounded policy. The aggregate queue is intentionally
    /// fixed at 1024 so a deployment cannot accidentally turn load into memory.
    pub fn try_new(
        lanes_per_voter: usize,
        request_bytes: usize,
        response_bytes: usize,
        queue_deadline: Duration,
        setup_timeout: Duration,
        shutdown_drain: Duration,
    ) -> Result<Self, ManagedProviderPoolConfigError> {
        let value = Self {
            lanes_per_voter,
            queued_and_inflight: MANAGED_PROVIDER_POOL_QUEUE_CAPACITY,
            request_bytes,
            response_bytes,
            queue_deadline,
            setup_timeout,
            shutdown_drain,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), ManagedProviderPoolConfigError> {
        if !(1..=MAX_MANAGED_PROVIDER_POOL_LANES).contains(&self.lanes_per_voter)
            || self.queued_and_inflight != MANAGED_PROVIDER_POOL_QUEUE_CAPACITY
            || self.request_bytes == 0
            || self.response_bytes == 0
            || self.request_bytes != MANAGED_PROVIDER_V5_REQUEST_FRAME_BYTES
            || self.response_bytes != MANAGED_PROVIDER_V5_RESPONSE_FRAME_BYTES
            || self.request_bytes > u32::MAX as usize
            || self.response_bytes > u32::MAX as usize
            || self.request_bytes > Semaphore::MAX_PERMITS
            || self.queued_and_inflight > Semaphore::MAX_PERMITS
            || self.queue_deadline.is_zero()
            || self.queue_deadline > MAX_MANAGED_PROVIDER_POOL_QUEUE_TIMEOUT
            || self.setup_timeout.is_zero()
            || self.setup_timeout > MAX_MANAGED_PROVIDER_POOL_SETUP_TIMEOUT
            || self.shutdown_drain.is_zero()
            || self.shutdown_drain > MAX_MANAGED_PROVIDER_POOL_SHUTDOWN_DRAIN
        {
            return Err(ManagedProviderPoolConfigError);
        }
        Ok(())
    }
    pub const fn lanes_per_voter(self) -> usize {
        self.lanes_per_voter
    }
    pub const fn total_lanes(self) -> usize {
        MANAGED_PROVIDER_JOB_VOTERS * self.lanes_per_voter
    }
    pub const fn queued_and_inflight(self) -> usize {
        self.queued_and_inflight
    }
    pub const fn request_bytes(self) -> usize {
        self.request_bytes
    }
    pub const fn response_bytes(self) -> usize {
        self.response_bytes
    }
    pub const fn queue_deadline(self) -> Duration {
        self.queue_deadline
    }
}

/// Construction-time authenticated authority. It binds every call to one
/// configured consensus scope and local mTLS material; calls cannot select a
/// tenant, provider, verifier, worker, endpoint, or raw job ID.
#[derive(Clone)]
pub struct ManagedProviderClientAuthority {
    scope: SessionConsumerScope,
    tls: opc_tls::AuthenticatedClientConfig,
}

impl ManagedProviderClientAuthority {
    /// Construct authority in the authenticated client composition root.
    pub fn new(
        scope: SessionConsumerScope,
        tls: opc_tls::AuthenticatedClientConfig,
    ) -> Result<Self, ManagedProviderPoolConfigError> {
        if tls.local_spiffe_identity_commitment().is_none() {
            return Err(ManagedProviderPoolConfigError);
        }
        Ok(Self { scope, tls })
    }
}

impl fmt::Debug for ManagedProviderClientAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ManagedProviderClientAuthority(<authenticated>)")
    }
}

/// One configured distinct voter target. Resolution is retained only by the
/// fixed lane for this voter and is never performed by an admitted caller.
#[derive(Clone)]
pub struct ManagedVoterEndpoint {
    resolve: RemoteAddrResolver,
    server_name: ServerName<'static>,
    identity: SpiffeId,
}

impl ManagedVoterEndpoint {
    pub fn new(
        resolve: RemoteAddrResolver,
        server_name: ServerName<'static>,
        identity: SpiffeId,
    ) -> Self {
        Self {
            resolve,
            server_name,
            identity,
        }
    }
}

impl fmt::Debug for ManagedVoterEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ManagedVoterEndpoint(<redacted>)")
    }
}

/// Narrow server-side adapter boundary.
///
/// The store's concrete least-authority facade implements this boundary. It
/// deliberately accepts only validated transport values and exposes neither a
/// store handle nor an authority token. This temporary boundary is kept small
/// so replacing the private adapter with that concrete facade is mechanical.
#[async_trait]
pub trait ManagedProviderJobNetworkFacade: Send + Sync {
    async fn run_member(
        &self,
        admission: FencedMutationRosterAdmission,
        protected_checkpoint: Box<[u8]>,
        ordinal: FencedMutationRosterOrdinal,
    ) -> Result<ManagedProviderJobStatus, ManagedProviderJobError>;
    async fn job_status(
        &self,
        admission: FencedMutationRosterAdmission,
        ordinal: FencedMutationRosterOrdinal,
    ) -> Result<ManagedProviderJobStatus, ManagedProviderJobError>;
}

#[derive(Clone)]
struct ManagedProviderJobServiceAdapter(Arc<dyn ManagedProviderJobNetworkFacade>);
impl ManagedProviderJobServiceAdapter {
    #[cfg(test)]
    fn for_test(service: Arc<dyn ManagedProviderJobNetworkFacade>) -> Self {
        Self(service)
    }
}
impl fmt::Debug for ManagedProviderJobServiceAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ManagedProviderJobServiceAdapter(<closed>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagedProviderReadiness {
    Ready,
    Degraded,
    Unready,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ManagedProviderPoolDiagnostics {
    pub connections: u64,
    pub connection_high_water: u64,
    pub queued: u64,
    pub queue_high_water: u64,
    pub inflight: u64,
    pub inflight_high_water: u64,
    pub response_cells: u64,
    pub response_high_water: u64,
    pub request_bytes: u64,
    pub request_bytes_high_water: u64,
    pub overload: u64,
    pub outcome_unknown: u64,
}

/// Aggregate listener state. `connection_tasks` counts live task futures;
/// their retained completed outputs still hold the same bounded listener
/// permits until the registry reaps them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ManagedProviderServerDiagnostics {
    pub connections: u64,
    pub connection_high_water: u64,
    pub connection_tasks: u64,
    pub task_high_water: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ManagedProviderShutdownReport {
    pub drained: u64,
    pub forced: u64,
    pub remaining_connections: u64,
    pub remaining_tasks: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ManagedProviderClientError {
    #[error("managed provider request was not transmitted")]
    Unavailable,
    #[error("managed provider authentication failed")]
    Authentication,
    #[error("managed provider protocol failed")]
    Protocol,
    #[error("managed provider is overloaded")]
    Overloaded,
    #[error("managed provider is shutting down")]
    ShuttingDown,
    #[error("managed provider request outcome is unknown")]
    OutcomeUnknown,
    #[error("managed provider service is unavailable")]
    ServiceUnavailable,
    #[error("managed provider job is closed by a frozen terminal receipt")]
    FrozenV4Terminal,
    #[error("managed provider job requires reconciliation")]
    ReconciliationRequired,
    #[error("managed provider job requires fresh admission")]
    FreshAdmissionRequired,
    #[error("managed provider job attestation was rejected")]
    AttestationRejected,
    #[error("managed provider job member is invalid")]
    InvalidMember,
}

#[derive(Default)]
struct Counters {
    connections: AtomicU64,
    connection_high_water: AtomicU64,
    queued: AtomicU64,
    queue_high_water: AtomicU64,
    inflight: AtomicU64,
    inflight_high_water: AtomicU64,
    response_cells: AtomicU64,
    response_high_water: AtomicU64,
    request_bytes: AtomicU64,
    request_bytes_high_water: AtomicU64,
    overload: AtomicU64,
    outcome_unknown: AtomicU64,
    shutdown_drained: AtomicU64,
    shutdown_forced: AtomicU64,
}

struct ConnectionCounterGuard(Arc<Counters>);

impl Drop for ConnectionCounterGuard {
    fn drop(&mut self) {
        self.0.connections.fetch_sub(1, Ordering::Relaxed);
    }
}

fn high(value: &AtomicU64, current: u64) {
    let mut old = value.load(Ordering::Relaxed);
    while current > old {
        match value.compare_exchange_weak(old, current, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(next) => old = next,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Running,
    Draining,
    Forced,
    Stopped,
}

/// A composite, fixed-width `/5` client. Construction validates exactly three
/// distinct voter identities; subscriber cardinality does not create sockets,
/// tasks, response cells, or queues.
#[derive(Clone)]
pub struct PersistentManagedProviderJobClient {
    pool: Arc<Pool>,
    // Public-client ownership is intentionally separate from task ownership.
    // The last clone synchronously aborts the bounded registry even when it is
    // dropped outside a Tokio runtime.
    _owner: Arc<ClientOwner>,
}

struct ClientOwner {
    pool: Weak<Pool>,
}

impl Drop for ClientOwner {
    fn drop(&mut self) {
        if let Some(pool) = self.pool.upgrade() {
            pool.close_from_last_client();
        }
    }
}

struct Pool {
    authority: ManagedProviderClientAuthority,
    endpoints: [ManagedVoterEndpoint; MANAGED_PROVIDER_JOB_VOTERS],
    config: ManagedProviderPoolConfig,
    readiness: AtomicU8,
    warm: [AtomicUsize; MANAGED_PROVIDER_JOB_VOTERS],
    pending: Arc<Semaphore>,
    bytes: Arc<Semaphore>,
    cells: Arc<Semaphore>,
    counters: Arc<Counters>,
    lifecycle: StdMutex<LifecycleState>,
    startup_changed: Notify,
    shutdown_report: StdMutex<Option<ManagedProviderShutdownReport>>,
    shutdown_complete: Notify,
    readiness_changed: Notify,
    admissions_changed: Notify,
    #[cfg(test)]
    test_hooks: ManagedProviderTestHooks,
}

/// The only mutable lifecycle authority for a managed-provider pool.
///
/// A caller either receives an admission guard while this record says
/// `Running`, or shutdown changes that same record to `Draining` first. The
/// task registry and scheduler publication use the same critical section, so
/// shutdown can only take a complete set of owned handles.
struct LifecycleState {
    phase: Phase,
    started: bool,
    starting: bool,
    shutdown_driver_started: bool,
    active_admissions: usize,
    scheduler: Option<mpsc::Sender<Command>>,
    tasks: Vec<JoinHandle<()>>,
}

struct AdmissionGuard {
    pool: Arc<Pool>,
}
impl Drop for AdmissionGuard {
    fn drop(&mut self) {
        let mut lifecycle = self.pool.lifecycle();
        lifecycle.active_admissions = lifecycle.active_admissions.saturating_sub(1);
        drop(lifecycle);
        self.pool.admissions_changed.notify_waiters();
    }
}

/// Keeps the startup claim cancellable. A cancelled prewarm must release
/// callers waiting to observe either the complete registry or the next
/// startup attempt; it may never strand `starting` at true.
struct StartupGuard {
    pool: Arc<Pool>,
    active: bool,
}

impl StartupGuard {
    fn complete(&mut self) {
        if !self.active {
            return;
        }
        let mut lifecycle = self.pool.lifecycle();
        lifecycle.starting = false;
        drop(lifecycle);
        self.active = false;
        self.pool.startup_changed.notify_waiters();
    }
}

impl Drop for StartupGuard {
    fn drop(&mut self) {
        self.complete();
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ManagedProviderTestPause {
    AdmissionBeforePermits,
    AdmissionAfterPermits,
    AdmissionAfterAccounting,
    AdmissionBeforeSend,
    #[cfg(test)]
    WorkerAfterInflight,
    StartupBeforeRegistry,
    StartupAfterRegistry,
}

#[cfg(test)]
struct ManagedProviderTestPauseHook {
    armed: AtomicBool,
    entered: AtomicUsize,
    entered_changed: Notify,
    released: Notify,
}

#[cfg(test)]
impl ManagedProviderTestPauseHook {
    fn new() -> Self {
        Self {
            armed: AtomicBool::new(false),
            entered: AtomicUsize::new(0),
            entered_changed: Notify::new(),
            released: Notify::new(),
        }
    }

    fn arm(&self) {
        self.entered.store(0, Ordering::Release);
        self.armed.store(true, Ordering::Release);
    }

    async fn pause(&self) {
        if !self.armed.load(Ordering::Acquire) {
            return;
        }
        self.entered.fetch_add(1, Ordering::AcqRel);
        self.entered_changed.notify_waiters();
        loop {
            let released = self.released.notified();
            tokio::pin!(released);
            released.as_mut().enable();
            if !self.armed.load(Ordering::Acquire) {
                return;
            }
            released.await;
        }
    }

    async fn entered(&self) {
        loop {
            let changed = self.entered_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.entered.load(Ordering::Acquire) != 0 {
                return;
            }
            changed.await;
        }
    }

    fn release(&self) {
        self.armed.store(false, Ordering::Release);
        self.released.notify_waiters();
    }
}

#[cfg(test)]
struct ManagedProviderTestHooks {
    admission_before_permits: ManagedProviderTestPauseHook,
    admission_after_permits: ManagedProviderTestPauseHook,
    admission_after_accounting: ManagedProviderTestPauseHook,
    admission_before_send: ManagedProviderTestPauseHook,
    worker_after_inflight: ManagedProviderTestPauseHook,
    startup_before_registry: ManagedProviderTestPauseHook,
    startup_after_registry: ManagedProviderTestPauseHook,
}

#[cfg(test)]
impl ManagedProviderTestHooks {
    fn new() -> Self {
        Self {
            admission_before_permits: ManagedProviderTestPauseHook::new(),
            admission_after_permits: ManagedProviderTestPauseHook::new(),
            admission_after_accounting: ManagedProviderTestPauseHook::new(),
            admission_before_send: ManagedProviderTestPauseHook::new(),
            worker_after_inflight: ManagedProviderTestPauseHook::new(),
            startup_before_registry: ManagedProviderTestPauseHook::new(),
            startup_after_registry: ManagedProviderTestPauseHook::new(),
        }
    }

    async fn pause(&self, point: ManagedProviderTestPause) {
        match point {
            ManagedProviderTestPause::AdmissionBeforePermits => {
                self.admission_before_permits.pause().await
            }
            ManagedProviderTestPause::AdmissionAfterPermits => {
                self.admission_after_permits.pause().await
            }
            ManagedProviderTestPause::AdmissionAfterAccounting => {
                self.admission_after_accounting.pause().await
            }
            ManagedProviderTestPause::AdmissionBeforeSend => {
                self.admission_before_send.pause().await
            }
            ManagedProviderTestPause::WorkerAfterInflight => {
                self.worker_after_inflight.pause().await
            }
            ManagedProviderTestPause::StartupBeforeRegistry => {
                self.startup_before_registry.pause().await
            }
            ManagedProviderTestPause::StartupAfterRegistry => {
                self.startup_after_registry.pause().await
            }
        }
    }

    fn hook(&self, point: ManagedProviderTestPause) -> &ManagedProviderTestPauseHook {
        match point {
            ManagedProviderTestPause::AdmissionBeforePermits => &self.admission_before_permits,
            ManagedProviderTestPause::AdmissionAfterPermits => &self.admission_after_permits,
            ManagedProviderTestPause::AdmissionAfterAccounting => &self.admission_after_accounting,
            ManagedProviderTestPause::AdmissionBeforeSend => &self.admission_before_send,
            ManagedProviderTestPause::WorkerAfterInflight => &self.worker_after_inflight,
            ManagedProviderTestPause::StartupBeforeRegistry => &self.startup_before_registry,
            ManagedProviderTestPause::StartupAfterRegistry => &self.startup_after_registry,
        }
    }
}

impl PersistentManagedProviderJobClient {
    pub fn new(
        authority: ManagedProviderClientAuthority,
        endpoints: [ManagedVoterEndpoint; MANAGED_PROVIDER_JOB_VOTERS],
        config: ManagedProviderPoolConfig,
    ) -> Result<Self, ManagedProviderPoolConfigError> {
        config.validate()?;
        if endpoints.iter().enumerate().any(|(i, endpoint)| {
            endpoints
                .iter()
                .take(i)
                .any(|prior| prior.identity == endpoint.identity)
        }) {
            return Err(ManagedProviderPoolConfigError);
        }
        if endpoints
            .iter()
            .any(|endpoint| endpoint.identity.as_str().len() > PROFILE_MAX_SPIFFE_ID_BYTES)
        {
            return Err(ManagedProviderPoolConfigError);
        }
        let pool = Arc::new(Pool {
            authority,
            endpoints,
            config,
            readiness: AtomicU8::new(0),
            warm: std::array::from_fn(|_| AtomicUsize::new(0)),
            pending: Arc::new(Semaphore::new(config.queued_and_inflight)),
            bytes: Arc::new(Semaphore::new(config.request_bytes)),
            cells: Arc::new(Semaphore::new(config.queued_and_inflight)),
            counters: Arc::new(Counters::default()),
            lifecycle: StdMutex::new(LifecycleState {
                phase: Phase::Running,
                started: false,
                starting: false,
                shutdown_driver_started: false,
                active_admissions: 0,
                scheduler: None,
                tasks: Vec::new(),
            }),
            startup_changed: Notify::new(),
            shutdown_report: StdMutex::new(None),
            shutdown_complete: Notify::new(),
            readiness_changed: Notify::new(),
            admissions_changed: Notify::new(),
            #[cfg(test)]
            test_hooks: ManagedProviderTestHooks::new(),
        });
        Ok(Self {
            _owner: Arc::new(ClientOwner {
                pool: Arc::downgrade(&pool),
            }),
            pool,
        })
    }
    pub fn config(&self) -> ManagedProviderPoolConfig {
        self.pool.config
    }
    pub fn readiness(&self) -> ManagedProviderReadiness {
        match self.pool.readiness.load(Ordering::Acquire) {
            2 => ManagedProviderReadiness::Ready,
            1 => ManagedProviderReadiness::Degraded,
            _ => ManagedProviderReadiness::Unready,
        }
    }
    pub fn diagnostics(&self) -> ManagedProviderPoolDiagnostics {
        let c = &self.pool.counters;
        ManagedProviderPoolDiagnostics {
            connections: c.connections.load(Ordering::Relaxed),
            connection_high_water: c.connection_high_water.load(Ordering::Relaxed),
            queued: c.queued.load(Ordering::Relaxed),
            queue_high_water: c.queue_high_water.load(Ordering::Relaxed),
            inflight: c.inflight.load(Ordering::Relaxed),
            inflight_high_water: c.inflight_high_water.load(Ordering::Relaxed),
            response_cells: c.response_cells.load(Ordering::Relaxed),
            response_high_water: c.response_high_water.load(Ordering::Relaxed),
            request_bytes: c.request_bytes.load(Ordering::Relaxed),
            request_bytes_high_water: c.request_bytes_high_water.load(Ordering::Relaxed),
            overload: c.overload.load(Ordering::Relaxed),
            outcome_unknown: c.outcome_unknown.load(Ordering::Relaxed),
        }
    }
    pub async fn prewarm(&self) -> Result<ManagedProviderReadiness, ManagedProviderClientError> {
        self.pool.start().await?;
        let deadline = tokio::time::Instant::now()
            .checked_add(self.pool.config.setup_timeout)
            .ok_or(ManagedProviderClientError::Unavailable)?;
        loop {
            // Register before observing state so a readiness transition cannot
            // notify in the check-to-wait gap.
            let notified = self.pool.readiness_changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.pool.phase() != Phase::Running {
                return Err(ManagedProviderClientError::ShuttingDown);
            }
            if self.readiness() == ManagedProviderReadiness::Ready {
                return Ok(ManagedProviderReadiness::Ready);
            }
            if tokio::time::timeout_at(deadline, &mut notified)
                .await
                .is_err()
            {
                return Err(ManagedProviderClientError::Unavailable);
            }
        }
    }
    pub async fn run_member(
        &self,
        admission: FencedMutationRosterAdmission,
        protected_checkpoint: Box<[u8]>,
        ordinal: FencedMutationRosterOrdinal,
    ) -> Result<ManagedProviderJobStatus, ManagedProviderClientError> {
        self.call(WireOperation::Run {
            admission,
            protected_checkpoint,
            ordinal: ordinal.get(),
        })
        .await
    }
    pub async fn job_status(
        &self,
        admission: FencedMutationRosterAdmission,
        ordinal: FencedMutationRosterOrdinal,
    ) -> Result<ManagedProviderJobStatus, ManagedProviderClientError> {
        self.call(WireOperation::Status {
            admission,
            ordinal: ordinal.get(),
        })
        .await
    }
    async fn call(
        &self,
        operation: WireOperation,
    ) -> Result<ManagedProviderJobStatus, ManagedProviderClientError> {
        let admission_guard = self.pool.enter_admission()?;
        self.pool
            .pause(ManagedProviderTestPause::AdmissionBeforePermits)
            .await;
        if self.readiness() == ManagedProviderReadiness::Unready {
            return Err(ManagedProviderClientError::Unavailable);
        }
        if !operation_matches_authority(&operation, &self.pool.authority) {
            return Err(ManagedProviderClientError::Protocol);
        }
        // Callers can construct the public DTO without transport constructors;
        // reject malformed or oversized nested values before allocating a
        // frame, acquiring queue permits, or writing any network byte.
        if !wire_operation_is_valid(&operation) {
            return Err(ManagedProviderClientError::Protocol);
        }
        let pending = Arc::clone(&self.pool.pending)
            .try_acquire_owned()
            .map_err(|_| {
                self.pool.counters.overload.fetch_add(1, Ordering::Relaxed);
                ManagedProviderClientError::Overloaded
            })?;
        let cells = Arc::clone(&self.pool.cells)
            .try_acquire_owned()
            .map_err(|_| {
                self.pool.counters.overload.fetch_add(1, Ordering::Relaxed);
                ManagedProviderClientError::Overloaded
            })?;
        let frame = WireRequest::Call { operation };
        // Count against the configured allocation bound before retaining an
        // encoded request. The second serializer pass fills exact capacity;
        // no queued or in-flight request can allocate past the byte semaphore.
        let frame_bytes = bounded_json_len(&frame, self.pool.config.request_bytes)?;
        let byte_count =
            u32::try_from(frame_bytes).map_err(|_| ManagedProviderClientError::Overloaded)?;
        let bytes = Arc::clone(&self.pool.bytes)
            .try_acquire_many_owned(byte_count)
            .map_err(|_| {
                self.pool.counters.overload.fetch_add(1, Ordering::Relaxed);
                ManagedProviderClientError::Overloaded
            })?;
        self.pool
            .pause(ManagedProviderTestPause::AdmissionAfterPermits)
            .await;
        let (reply_tx, reply_rx) = oneshot::channel();
        let key = job_key(&frame);
        let job = Job {
            key,
            frame,
            frame_bytes,
            deadline: tokio::time::Instant::now()
                .checked_add(self.pool.config.queue_deadline)
                .ok_or(ManagedProviderClientError::Overloaded)?,
            inflight: false,
            accepted: false,
            shutdown: JobShutdownOutcome::Unclassified,
            pool: Arc::downgrade(&self.pool),
            counters: Arc::clone(&self.pool.counters),
            reply: Some(reply_tx),
            _pending: pending,
            _bytes: bytes,
            _cell: cells,
        };
        self.pool.track_enqueue(job.frame_bytes);
        self.pool
            .pause(ManagedProviderTestPause::AdmissionAfterAccounting)
            .await;
        let tx = self
            .pool
            .lifecycle()
            .scheduler
            .clone()
            .ok_or(ManagedProviderClientError::Unavailable)?;
        self.pool
            .pause(ManagedProviderTestPause::AdmissionBeforeSend)
            .await;
        let mut job = Box::new(job);
        // Set before publication so a scheduler on another executor cannot
        // complete the Job before it has a shutdown classification. A failed
        // publication returns ownership and explicitly revokes acceptance.
        job.accepted = true;
        match tx.try_send(Command::Submit(job)) {
            Ok(()) => {}
            Err(error) => {
                if let Command::Submit(mut job) = error.into_inner() {
                    job.accepted = false;
                }
                self.pool.counters.overload.fetch_add(1, Ordering::Relaxed);
                return Err(ManagedProviderClientError::Overloaded);
            }
        }
        drop(admission_guard);
        match reply_rx.await {
            Ok(reply) => reply,
            Err(_) => Err(ManagedProviderClientError::ShuttingDown),
        }
    }
    pub async fn shutdown(&self) -> ManagedProviderShutdownReport {
        self.pool.request_shutdown();
        self.pool.wait_shutdown().await
    }
}

fn bounded_json_len<T: Serialize>(
    value: &T,
    maximum: usize,
) -> Result<usize, ManagedProviderClientError> {
    struct Counter {
        len: usize,
        maximum: usize,
        exceeded: bool,
    }
    impl io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let Some(next) = self.len.checked_add(bytes.len()) else {
                self.exceeded = true;
                return Err(io::Error::other("managed provider frame overflow"));
            };
            if next > self.maximum {
                self.exceeded = true;
                return Err(io::Error::other("managed provider frame exceeds bound"));
            }
            self.len = next;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter {
        len: 0,
        maximum,
        exceeded: false,
    };
    serde_json::to_writer(&mut counter, value).map_err(|_| {
        if counter.exceeded {
            ManagedProviderClientError::Overloaded
        } else {
            ManagedProviderClientError::Protocol
        }
    })?;
    Ok(counter.len)
}

fn operation_matches_authority(
    operation: &WireOperation,
    authority: &ManagedProviderClientAuthority,
) -> bool {
    let admission = match operation {
        WireOperation::Run { admission, .. } | WireOperation::Status { admission, .. } => admission,
    };
    let Some(commitment) = authority.tls.local_spiffe_identity_commitment() else {
        return false;
    };
    admission.validate().is_ok()
        && admission.scope() == derive_fenced_mutation_roster_scope(commitment, authority.scope)
}

impl Pool {
    fn lifecycle(&self) -> std::sync::MutexGuard<'_, LifecycleState> {
        self.lifecycle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn phase(&self) -> Phase {
        self.lifecycle().phase
    }

    /// Abort every owned background resource without requiring a Tokio
    /// runtime. This is called by the last public client owner and is also the
    /// drop backstop for a partially started pool.
    fn close_from_last_client(&self) {
        let (scheduler, handles) = {
            let mut lifecycle = self.lifecycle();
            if lifecycle.phase == Phase::Stopped {
                return;
            }
            lifecycle.phase = Phase::Forced;
            lifecycle.started = false;
            (
                lifecycle.scheduler.take(),
                std::mem::take(&mut lifecycle.tasks),
            )
        };
        self.readiness.store(0, Ordering::Release);
        self.readiness_changed.notify_waiters();
        drop(scheduler);
        for handle in handles {
            handle.abort();
        }
    }

    fn running_and_started(&self) -> bool {
        let lifecycle = self.lifecycle();
        lifecycle.phase == Phase::Running && lifecycle.started
    }

    async fn pause(&self, point: ManagedProviderTestPause) {
        #[cfg(test)]
        self.test_hooks.pause(point).await;
        #[cfg(not(test))]
        let _ = point;
    }

    fn enter_admission(self: &Arc<Self>) -> Result<AdmissionGuard, ManagedProviderClientError> {
        let mut lifecycle = self.lifecycle();
        if lifecycle.phase != Phase::Running {
            return Err(ManagedProviderClientError::ShuttingDown);
        }
        lifecycle.active_admissions = lifecycle.active_admissions.saturating_add(1);
        Ok(AdmissionGuard {
            pool: Arc::clone(self),
        })
    }

    async fn wait_admissions_closed(&self) {
        loop {
            let notified = self.admissions_changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.lifecycle().active_admissions == 0 {
                return;
            }
            notified.await;
        }
    }

    async fn start(self: &Arc<Self>) -> Result<(), ManagedProviderClientError> {
        loop {
            let notified = self.startup_changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let claimed_startup = {
                let mut lifecycle = self.lifecycle();
                if lifecycle.phase != Phase::Running {
                    return Err(ManagedProviderClientError::ShuttingDown);
                }
                if lifecycle.started {
                    return Ok(());
                }
                if lifecycle.starting {
                    false
                } else {
                    lifecycle.starting = true;
                    true
                }
            };
            if claimed_startup {
                break;
            }
            notified.await;
        }
        let mut startup_guard = StartupGuard {
            pool: Arc::clone(self),
            active: true,
        };
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(ManagedProviderClientError::Unavailable);
        }

        self.pause(ManagedProviderTestPause::StartupBeforeRegistry)
            .await;

        // Reclaim the same lifecycle gate before spawning. Shutdown either
        // closes this gate first, in which case no worker exists, or observes
        // the complete scheduler and handle registry published below.
        {
            let mut lifecycle = self.lifecycle();
            if lifecycle.phase != Phase::Running {
                return Err(ManagedProviderClientError::ShuttingDown);
            }
            let (tx, rx) = mpsc::channel(self.config.queued_and_inflight);
            let (event_tx, event_rx) = mpsc::channel(self.config.total_lanes() * 2);
            let mut worker_txs = Vec::with_capacity(self.config.total_lanes());
            let mut handles = Vec::with_capacity(self.config.total_lanes() + 1);
            for voter in 0..MANAGED_PROVIDER_JOB_VOTERS {
                for lane in 0..self.config.lanes_per_voter {
                    let (worker_tx, worker_rx) = mpsc::channel(1);
                    worker_txs.push(worker_tx);
                    handles.push(tokio::spawn(lane_worker(
                        Arc::downgrade(self),
                        LaneConnectConfig {
                            authority: self.authority.clone(),
                            endpoint: self.endpoints[voter].clone(),
                            config: self.config,
                            counters: Arc::clone(&self.counters),
                        },
                        voter,
                        lane,
                        worker_rx,
                        event_tx.clone(),
                    )));
                }
            }
            handles.push(tokio::spawn(scheduler(
                Arc::downgrade(self),
                rx,
                event_rx,
                worker_txs,
            )));
            lifecycle.scheduler = Some(tx);
            lifecycle.tasks = handles;
            lifecycle.started = true;
        }
        startup_guard.complete();
        self.pause(ManagedProviderTestPause::StartupAfterRegistry)
            .await;
        Ok(())
    }
    fn track_enqueue(&self, bytes: usize) {
        let q = self.counters.queued.fetch_add(1, Ordering::Relaxed) + 1;
        high(&self.counters.queue_high_water, q);
        let b = self
            .counters
            .request_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed)
            + bytes as u64;
        high(&self.counters.request_bytes_high_water, b);
        let r = self.counters.response_cells.fetch_add(1, Ordering::Relaxed) + 1;
        high(&self.counters.response_high_water, r);
    }
    fn mark_inflight(&self) {
        self.counters.queued.fetch_sub(1, Ordering::Relaxed);
        let now = self.counters.inflight.fetch_add(1, Ordering::Relaxed) + 1;
        high(&self.counters.inflight_high_water, now);
    }

    /// Queue-to-inflight transition shares the lifecycle gate with force.
    /// A job either changes accounting before force, or observes force before
    /// it can leave the queue; there is no sampled counter race.
    fn begin_inflight(&self, job: &mut Job) -> Phase {
        let lifecycle = self.lifecycle();
        let phase = lifecycle.phase;
        if !matches!(phase, Phase::Forced | Phase::Stopped) {
            self.mark_inflight();
            job.inflight = true;
        }
        phase
    }

    /// Completion is ordered against the force transition by the same gate.
    fn classify_completion(&self, job: &mut Job) {
        let lifecycle = self.lifecycle();
        job.classify(lifecycle.phase);
    }
    fn update_readiness(&self) {
        if !self.running_and_started() {
            self.readiness.store(0, Ordering::Release);
            self.readiness_changed.notify_waiters();
            return;
        }
        let voters = self
            .warm
            .iter()
            .filter(|n| n.load(Ordering::Acquire) > 0)
            .count();
        let all = self
            .warm
            .iter()
            .all(|n| n.load(Ordering::Acquire) == self.config.lanes_per_voter);
        let next = if all {
            2
        } else if voters >= 2 {
            1
        } else {
            0
        };
        self.readiness.store(next, Ordering::Release);
        self.readiness_changed.notify_waiters();
    }
    fn request_shutdown(self: &Arc<Self>) {
        let start_driver = {
            let mut lifecycle = self.lifecycle();
            if lifecycle.shutdown_driver_started {
                false
            } else {
                lifecycle.phase = Phase::Draining;
                lifecycle.shutdown_driver_started = true;
                true
            }
        };
        if !start_driver {
            return;
        }
        self.readiness.store(0, Ordering::Release);
        self.readiness_changed.notify_waiters();
        let pool = Arc::clone(self);
        tokio::spawn(async move {
            pool.wait_admissions_closed().await;
            let scheduler = pool.lifecycle().scheduler.clone();
            if let Some(deadline) =
                tokio::time::Instant::now().checked_add(pool.config.shutdown_drain)
            {
                if let Some(tx) = scheduler {
                    let _ = tokio::time::timeout_at(deadline, tx.send(Command::Drain)).await;
                    tokio::time::sleep_until(deadline).await;
                }
            }
            let (scheduler, handles) = {
                let mut lifecycle = pool.lifecycle();
                lifecycle.phase = Phase::Forced;
                (
                    lifecycle.scheduler.take(),
                    std::mem::take(&mut lifecycle.tasks),
                )
            };
            if let Some(tx) = scheduler {
                let _ = tx.try_send(Command::Force);
            }
            // A hung TLS peer or service cannot hold a retained supervisor
            // beyond its drain deadline. Abort only after the bounded drain.
            for handle in &handles {
                handle.abort();
            }
            for mut handle in handles {
                let _ = (&mut handle).await;
            }
            // Every queued or in-flight Job owns its accounting. Joining all
            // supervisors above runs its Drop exactly once, including abort
            // and panic paths; never blind-zero racing gauges here.
            debug_assert_eq!(pool.counters.queued.load(Ordering::Relaxed), 0);
            debug_assert_eq!(pool.counters.inflight.load(Ordering::Relaxed), 0);
            debug_assert_eq!(pool.counters.request_bytes.load(Ordering::Relaxed), 0);
            debug_assert_eq!(pool.counters.response_cells.load(Ordering::Relaxed), 0);
            {
                let mut lifecycle = pool.lifecycle();
                lifecycle.phase = Phase::Stopped;
            }
            let report = ManagedProviderShutdownReport {
                drained: pool.counters.shutdown_drained.load(Ordering::Relaxed),
                forced: pool.counters.shutdown_forced.load(Ordering::Relaxed),
                remaining_connections: pool.counters.connections.load(Ordering::Relaxed),
                remaining_tasks: 0,
            };
            *pool
                .shutdown_report
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(report);
            pool.shutdown_complete.notify_waiters();
        });
    }
    async fn wait_shutdown(&self) -> ManagedProviderShutdownReport {
        loop {
            // Register before the report check for the same lost-wakeup
            // protection as prewarm.
            let notified = self.shutdown_complete.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(report) = *self
                .shutdown_report
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
            {
                return report;
            }
            notified.await;
        }
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        let lifecycle = self
            .lifecycle
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        lifecycle.phase = Phase::Forced;
        lifecycle.scheduler.take();
        let handles = std::mem::take(&mut lifecycle.tasks);
        for handle in handles {
            handle.abort();
        }
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
struct FairKey([u8; 56], u8);
fn job_key(request: &WireRequest) -> FairKey {
    match request {
        WireRequest::Call { operation } => match operation {
            WireOperation::Run {
                admission, ordinal, ..
            }
            | WireOperation::Status { admission, ordinal } => {
                FairKey(admission.request_id().to_bytes(), *ordinal)
            }
        },
        WireRequest::Hello(_) => FairKey([0; 56], 0),
    }
}
struct Job {
    key: FairKey,
    frame: WireRequest,
    frame_bytes: usize,
    deadline: tokio::time::Instant,
    inflight: bool,
    accepted: bool,
    shutdown: JobShutdownOutcome,
    pool: Weak<Pool>,
    counters: Arc<Counters>,
    reply: Option<oneshot::Sender<Result<ManagedProviderJobStatus, ManagedProviderClientError>>>,
    _pending: OwnedSemaphorePermit,
    _bytes: OwnedSemaphorePermit,
    _cell: OwnedSemaphorePermit,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum JobShutdownOutcome {
    Unclassified,
    Drained,
    Forced,
}

impl Job {
    fn classify(&mut self, phase: Phase) {
        if !self.accepted || self.shutdown != JobShutdownOutcome::Unclassified {
            return;
        }
        match phase {
            Phase::Running => {}
            Phase::Draining => {
                self.shutdown = JobShutdownOutcome::Drained;
                self.counters
                    .shutdown_drained
                    .fetch_add(1, Ordering::Relaxed);
            }
            Phase::Forced | Phase::Stopped => self.force(),
        }
    }

    fn force(&mut self) {
        if !self.accepted || self.shutdown != JobShutdownOutcome::Unclassified {
            return;
        }
        self.shutdown = JobShutdownOutcome::Forced;
        self.counters
            .shutdown_forced
            .fetch_add(1, Ordering::Relaxed);
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        if self.shutdown == JobShutdownOutcome::Unclassified {
            if let Some(pool) = self.pool.upgrade() {
                self.classify(pool.phase());
            }
        }
        if self.inflight {
            self.counters.inflight.fetch_sub(1, Ordering::Relaxed);
        } else {
            self.counters.queued.fetch_sub(1, Ordering::Relaxed);
        }
        self.counters
            .request_bytes
            .fetch_sub(self.frame_bytes as u64, Ordering::Relaxed);
        self.counters.response_cells.fetch_sub(1, Ordering::Relaxed);
    }
}
enum Command {
    Submit(Box<Job>),
    Drain,
    Force,
}
enum Event {
    Ready(usize, u64),
    Lost(usize, u64, Option<FairKey>),
    Idle(usize, u64, FairKey),
}

async fn scheduler(
    pool: Weak<Pool>,
    mut commands: mpsc::Receiver<Command>,
    mut events: mpsc::Receiver<Event>,
    workers: Vec<mpsc::Sender<Job>>,
) {
    let mut queues: BTreeMap<FairKey, VecDeque<Job>> = BTreeMap::new();
    let mut rr: VecDeque<FairKey> = VecDeque::new();
    let mut idle: VecDeque<usize> = VecDeque::new();
    let mut live = vec![false; workers.len()];
    let mut generation = vec![0_u64; workers.len()];
    let mut active = BTreeSet::new();
    let mut expiry = tokio::time::interval(Duration::from_millis(10));
    expiry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let Some(p) = pool.upgrade() else { return };
        while let Some(lane) = idle.pop_front() {
            let Some(key) = rr.pop_front() else {
                idle.push_front(lane);
                break;
            };
            let (mut job, empty) = match queues.get_mut(&key) {
                Some(queue) => match queue.pop_front() {
                    Some(job) => (job, queue.is_empty()),
                    None => continue,
                },
                None => continue,
            };
            if job.deadline <= tokio::time::Instant::now() {
                if empty {
                    queues.remove(&key);
                } else {
                    rr.push_back(key);
                }
                p.classify_completion(&mut job);
                complete(job, Err(ManagedProviderClientError::Overloaded));
                continue;
            }
            if empty {
                queues.remove(&key);
            } else {
                rr.push_back(key)
            }
            match workers[lane].try_send(job) {
                Ok(()) => {
                    active.insert(key);
                }
                Err(mpsc::error::TrySendError::Full(job)) => {
                    queues.entry(job.key).or_default().push_front(job);
                    rr.push_front(key);
                    idle.push_front(lane);
                    break;
                }
                Err(mpsc::error::TrySendError::Closed(mut job)) => {
                    p.classify_completion(&mut job);
                    complete(job, Err(ManagedProviderClientError::Unavailable))
                }
            }
        }
        drop(p);
        tokio::select! {
            command = commands.recv() => match command {
                Some(Command::Submit(job)) => {
                    let job = *job;
                    let Some(p) = pool.upgrade() else { return };
                    if p.phase() != Phase::Running {
                        let mut job = job;
                        job.force();
                        complete(job, Err(ManagedProviderClientError::ShuttingDown));
                    } else if active.contains(&job.key) || queues.contains_key(&job.key) {
                        let mut job = job;
                        p.classify_completion(&mut job);
                        complete(job, Err(ManagedProviderClientError::Overloaded));
                    } else {
                        let key = job.key;
                        queues.entry(key).or_default().push_back(job);
                        rr.push_back(key);
                    }
                }
                Some(Command::Drain) => {}
                Some(Command::Force) | None => {
                    if pool.upgrade().is_some() {
                        for (_, queue) in queues {
                            for mut job in queue {
                                job.force();
                                complete(job, Err(ManagedProviderClientError::ShuttingDown));
                            }
                        }
                    }
                    return;
                }
            },
            event = events.recv() => match event {
                Some(Event::Ready(lane, next_generation)) => {
                    if next_generation >= generation[lane] {
                        generation[lane] = next_generation;
                        if !live[lane] {
                            live[lane] = true;
                            idle.push_back(lane);
                            if let Some(p) = pool.upgrade() {
                                let voter = lane / p.config.lanes_per_voter;
                                p.warm[voter].fetch_add(1, Ordering::AcqRel);
                                p.update_readiness();
                            }
                        }
                    }
                }
                Some(Event::Lost(lane, lost_generation, key)) => {
                    if lost_generation == generation[lane] {
                        idle.retain(|idle_lane| *idle_lane != lane);
                        if let Some(key) = key {
                            active.remove(&key);
                        }
                        if live[lane] {
                            live[lane] = false;
                            if let Some(p) = pool.upgrade() {
                                let voter = lane / p.config.lanes_per_voter;
                                p.warm[voter].fetch_sub(1, Ordering::AcqRel);
                                p.update_readiness();
                            }
                        }
                    }
                }
                Some(Event::Idle(lane, idle_generation, key)) => {
                    if idle_generation == generation[lane] {
                        active.remove(&key);
                        if live[lane] && !idle.contains(&lane) {
                            idle.push_back(lane);
                        }
                    }
                }
                None => return,
            },
            _ = expiry.tick() => {
                let Some(p) = pool.upgrade() else { return };
                let now = tokio::time::Instant::now();
                let mut expired = Vec::new();
                for queue in queues.values_mut() {
                    while queue.front().is_some_and(|job| job.deadline <= now) {
                        if let Some(job) = queue.pop_front() {
                            expired.push(job);
                        }
                    }
                }
                queues.retain(|_, queue| !queue.is_empty());
                rr.retain(|key| queues.contains_key(key));
                for mut job in expired {
                    p.classify_completion(&mut job);
                    complete(job, Err(ManagedProviderClientError::Overloaded));
                }
            }
        }
    }
}
fn complete(mut job: Job, result: Result<ManagedProviderJobStatus, ManagedProviderClientError>) {
    if let Some(reply) = job.reply.take() {
        let _ = reply.send(result);
    }
}

#[derive(Clone)]
struct LaneConnectConfig {
    authority: ManagedProviderClientAuthority,
    endpoint: ManagedVoterEndpoint,
    config: ManagedProviderPoolConfig,
    counters: Arc<Counters>,
}

fn worker_phase(pool: &Weak<Pool>) -> Phase {
    pool.upgrade().map_or(Phase::Stopped, |pool| pool.phase())
}

async fn lane_worker(
    pool: Weak<Pool>,
    connect: LaneConnectConfig,
    voter: usize,
    lane: usize,
    mut jobs: mpsc::Receiver<Job>,
    events: mpsc::Sender<Event>,
) {
    let index = voter * connect.config.lanes_per_voter + lane;
    let mut generation = 0_u64;
    let mut reconnect_attempt = 0_u8;
    loop {
        if worker_phase(&pool) != Phase::Running {
            return;
        }
        let connection = connect_lane(&connect).await;
        let mut connection = match connection {
            Ok(c) => {
                if worker_phase(&pool) != Phase::Running {
                    // Shutdown may have started while the absolute setup
                    // transaction was in progress; never publish a late lane.
                    return;
                }
                generation = generation.wrapping_add(1);
                reconnect_attempt = 0;
                connect.counters.connections.fetch_add(1, Ordering::Relaxed);
                let connection_counter = ConnectionCounterGuard(Arc::clone(&connect.counters));
                high(
                    &connect.counters.connection_high_water,
                    connect.counters.connections.load(Ordering::Relaxed),
                );
                if events.send(Event::Ready(index, generation)).await.is_err() {
                    return;
                };
                (c, connection_counter)
            }
            Err(_) => {
                // Capped lane-local jitter prevents a failed voter from
                // synchronising all of its replacements into one reconnect
                // burst. No subscriber creates a retry task.
                reconnect_attempt = reconnect_attempt.saturating_add(1).min(6);
                let base = 5_u64 << reconnect_attempt;
                let jitter = ((index as u64 * 17) + generation) % 11;
                tokio::time::sleep(Duration::from_millis((base + jitter).min(250))).await;
                continue;
            }
        };
        while let Some(mut job) = jobs.recv().await {
            let phase = worker_phase(&pool);
            if matches!(phase, Phase::Forced | Phase::Stopped) {
                job.force();
                complete(job, Err(ManagedProviderClientError::ShuttingDown));
                continue;
            }
            if job.deadline <= tokio::time::Instant::now() {
                let key = job.key;
                if let Some(pool) = pool.upgrade() {
                    pool.classify_completion(&mut job);
                } else {
                    job.force();
                }
                complete(job, Err(ManagedProviderClientError::Overloaded));
                let _ = events.send(Event::Idle(index, generation, key)).await;
                continue;
            }
            let Some(pool_for_transition) = pool.upgrade() else {
                job.force();
                complete(job, Err(ManagedProviderClientError::ShuttingDown));
                return;
            };
            if matches!(
                pool_for_transition.begin_inflight(&mut job),
                Phase::Forced | Phase::Stopped
            ) {
                drop(pool_for_transition);
                job.force();
                complete(job, Err(ManagedProviderClientError::ShuttingDown));
                continue;
            }
            drop(pool_for_transition);
            #[cfg(test)]
            if let Some(pool) = pool.upgrade() {
                pool.pause(ManagedProviderTestPause::WorkerAfterInflight)
                    .await;
            }
            let key = job.key;
            let result = call_on_lane(
                &mut connection.0,
                &job.frame,
                connect.config.request_bytes,
                connect.config.response_bytes,
                job.deadline,
            )
            .await;
            match result {
                Ok(value) => {
                    if let Some(pool) = pool.upgrade() {
                        pool.classify_completion(&mut job);
                    } else {
                        job.force();
                    }
                    complete(job, value);
                    let _ = events.send(Event::Idle(index, generation, key)).await;
                }
                Err(error) => {
                    if error == ManagedProviderClientError::OutcomeUnknown {
                        connect
                            .counters
                            .outcome_unknown
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    if let Some(pool) = pool.upgrade() {
                        pool.classify_completion(&mut job);
                    } else {
                        job.force();
                    }
                    complete(job, Err(error));
                    // A failed lane must never advertise itself as idle. The
                    // generation-bound Lost event purges a stale idle slot.
                    let _ = events.send(Event::Lost(index, generation, Some(key))).await;
                    break;
                }
            }
        }
        drop(connection.1);
        let _ = events.send(Event::Lost(index, generation, None)).await;
    }
}

type ClientLane = tokio_rustls::client::TlsStream<TcpStream>;
async fn connect_lane(
    connect: &LaneConnectConfig,
) -> Result<ClientLane, ManagedProviderClientError> {
    let endpoint = &connect.endpoint;
    // This deadline is deliberately created once.  Resolver, TCP, TLS, Hello,
    // and Ack are one setup transaction; no successful phase renews it.
    let deadline = tokio::time::Instant::now()
        .checked_add(connect.config.setup_timeout)
        .ok_or(ManagedProviderClientError::Unavailable)?;
    let address = tokio::time::timeout_at(deadline, (endpoint.resolve)())
        .await
        .map_err(|_| ManagedProviderClientError::Unavailable)?
        .map_err(|_| ManagedProviderClientError::Unavailable)?;
    let stream = tokio::time::timeout_at(deadline, TcpStream::connect(address))
        .await
        .map_err(|_| ManagedProviderClientError::Unavailable)?
        .map_err(|_| ManagedProviderClientError::Unavailable)?;
    stream
        .set_nodelay(true)
        .map_err(|_| ManagedProviderClientError::Unavailable)?;
    let handshake = connect
        .authority
        .tls
        .begin_handshake()
        .map_err(|_| ManagedProviderClientError::Authentication)?;
    let mut config = handshake.rustls_config().as_ref().clone();
    config.alpn_protocols = vec![MANAGED_PROVIDER_JOB_ALPN.to_vec()];
    config.resumption = tokio_rustls::rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    let mut tls = tokio::time::timeout_at(
        deadline,
        tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(endpoint.server_name.clone(), stream),
    )
    .await
    .map_err(|_| ManagedProviderClientError::Unavailable)?
    .map_err(classify_tls_io_error)
    .map_err(|e| {
        if matches!(e, crate::ProtocolError::Authentication) {
            ManagedProviderClientError::Authentication
        } else {
            ManagedProviderClientError::Unavailable
        }
    })?;
    if tls.get_ref().1.alpn_protocol() != Some(MANAGED_PROVIDER_JOB_ALPN) {
        return Err(ManagedProviderClientError::Protocol);
    }
    let peer = opc_tls::peer_tls_identity_from_client_connection(tls.get_ref().1)
        .map_err(|_| ManagedProviderClientError::Authentication)?;
    if peer.spiffe_id() != &endpoint.identity {
        return Err(ManagedProviderClientError::Authentication);
    }
    let hello = WireRequest::Hello(WireHello {
        transport_revision: MANAGED_PROVIDER_JOB_TRANSPORT_REVISION,
        semantic_revision: MANAGED_PROVIDER_JOB_SEMANTIC_REVISION,
        scope: connect.authority.scope,
        profile_digest: profile_digest(),
        request_frame_size: connect.config.request_bytes as u32,
        response_frame_size: connect.config.response_bytes as u32,
        expected_voter: endpoint.identity.as_str().to_owned(),
    });
    write_json_until(&mut tls, &hello, connect.config.request_bytes, deadline).await?;
    let ack: WireResponse =
        read_json_until(&mut tls, connect.config.response_bytes, deadline).await?;
    match ack {
        WireResponse::HelloAck(ack)
            if ack.transport_revision == MANAGED_PROVIDER_JOB_TRANSPORT_REVISION
                && ack.semantic_revision == MANAGED_PROVIDER_JOB_SEMANTIC_REVISION
                && ack.scope == connect.authority.scope
                && ack.profile_digest == profile_digest()
                && ack.request_frame_size == MANAGED_PROVIDER_V5_REQUEST_FRAME_BYTES as u32
                && ack.response_frame_size == MANAGED_PROVIDER_V5_RESPONSE_FRAME_BYTES as u32 =>
        {
            handshake
                .admit()
                .map_err(|_| ManagedProviderClientError::Authentication)?;
            Ok(tls)
        }
        _ => Err(ManagedProviderClientError::Protocol),
    }
}
async fn call_on_lane(
    connection: &mut ClientLane,
    request: &WireRequest,
    request_bound: usize,
    response_bound: usize,
    deadline: tokio::time::Instant,
) -> Result<Result<ManagedProviderJobStatus, ManagedProviderClientError>, ManagedProviderClientError>
{
    match write_frame_bounded_until_classified(connection, request, request_bound, deadline).await {
        Ok(()) => {}
        Err(ProtocolFrameWriteError::BeforeWrite(_)) => {
            return Err(ManagedProviderClientError::Unavailable);
        }
        Err(ProtocolFrameWriteError::MayHaveWritten(_)) => {
            return Err(ManagedProviderClientError::OutcomeUnknown);
        }
    }
    let response: WireResponse = read_json_until(connection, response_bound, deadline)
        .await
        .map_err(|_| ManagedProviderClientError::OutcomeUnknown)?;
    match response {
        WireResponse::Call(result) => match result.into_result() {
            Ok(status) => Ok(Ok(status)),
            Err(ManagedProviderClientError::Protocol) => {
                Err(ManagedProviderClientError::OutcomeUnknown)
            }
            Err(error) => Ok(Err(error)),
        },
        // The request crossed the transport boundary.  A wrong response is
        // indistinguishable from an effect whose reply was lost or corrupted.
        _ => Err(ManagedProviderClientError::OutcomeUnknown),
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FrameWriteError {
    NotTransmitted,
    OutcomeUnknown,
}

#[cfg(test)]
async fn write_raw<W: AsyncWrite + Unpin>(
    writer: &mut W,
    bytes: &[u8],
) -> Result<(), FrameWriteError> {
    let length = u32::try_from(bytes.len()).map_err(|_| FrameWriteError::NotTransmitted)?;
    let mut frame = Vec::with_capacity(4 + bytes.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(bytes);
    let mut offset = 0;
    while offset < frame.len() {
        match writer.write(&frame[offset..]).await {
            Ok(0) => {
                return Err(if offset == 0 {
                    FrameWriteError::NotTransmitted
                } else {
                    FrameWriteError::OutcomeUnknown
                });
            }
            Err(_) => {
                return Err(if offset == 0 {
                    FrameWriteError::NotTransmitted
                } else {
                    FrameWriteError::OutcomeUnknown
                });
            }
            Ok(written) => offset = offset.saturating_add(written),
        }
    }
    writer
        .flush()
        .await
        .map_err(|_| FrameWriteError::OutcomeUnknown)
}
async fn write_json_until<W: AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    value: &T,
    bound: usize,
    deadline: tokio::time::Instant,
) -> Result<(), ManagedProviderClientError> {
    write_frame_bounded_until_classified(writer, value, bound, deadline)
        .await
        .map_err(|error| match error {
            ProtocolFrameWriteError::BeforeWrite(_) => ManagedProviderClientError::Unavailable,
            ProtocolFrameWriteError::MayHaveWritten(_) => {
                ManagedProviderClientError::OutcomeUnknown
            }
        })
}
async fn read_json<R: AsyncRead + Unpin, T: for<'a> Deserialize<'a>>(
    reader: &mut R,
    bound: usize,
) -> Result<T, ManagedProviderClientError> {
    let length = reader
        .read_u32()
        .await
        .map_err(|_| ManagedProviderClientError::Unavailable)? as usize;
    if length > bound {
        return Err(ManagedProviderClientError::Protocol);
    }
    let mut bytes = vec![0; length];
    reader
        .read_exact(&mut bytes)
        .await
        .map_err(|_| ManagedProviderClientError::Unavailable)?;
    let mut unknown = false;
    let mut decoder = serde_json::Deserializer::from_slice(&bytes);
    let value = serde_ignored::deserialize(&mut decoder, |_| unknown = true)
        .map_err(|_| ManagedProviderClientError::Protocol)?;
    // `deserialize` accepts one valid JSON value and deliberately leaves a
    // suffix unread. The closed wire format admits exactly one value.
    if unknown || decoder.end().is_err() {
        return Err(ManagedProviderClientError::Protocol);
    }
    Ok(value)
}
async fn read_json_until<R: AsyncRead + Unpin, T: for<'a> Deserialize<'a>>(
    reader: &mut R,
    bound: usize,
    deadline: tokio::time::Instant,
) -> Result<T, ManagedProviderClientError> {
    match tokio::time::timeout_at(deadline, read_json(reader, bound)).await {
        Ok(result) if tokio::time::Instant::now() < deadline => result,
        Ok(_) | Err(_) => Err(ManagedProviderClientError::Unavailable),
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", content = "value")]
enum WireRequest {
    Hello(WireHello),
    Call { operation: WireOperation },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireHello {
    transport_revision: u16,
    semantic_revision: u16,
    scope: SessionConsumerScope,
    profile_digest: [u8; 32],
    request_frame_size: u32,
    response_frame_size: u32,
    expected_voter: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "operation", content = "value")]
enum WireOperation {
    Run {
        admission: FencedMutationRosterAdmission,
        protected_checkpoint: Box<[u8]>,
        ordinal: u8,
    },
    Status {
        admission: FencedMutationRosterAdmission,
        ordinal: u8,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "kind", content = "value")]
enum WireResponse {
    HelloAck(WireAck),
    Reject,
    Call(WireCallResult),
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireAck {
    transport_revision: u16,
    semantic_revision: u16,
    scope: SessionConsumerScope,
    profile_digest: [u8; 32],
    request_frame_size: u32,
    response_frame_size: u32,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireCallResult {
    status: Option<WireStatus>,
    error: Option<WireError>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireStatus {
    mode: u8,
    phase: u8,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum WireError {
    Frozen,
    Reconciliation,
    FreshAdmission,
    Attestation,
    Unavailable,
    InvalidMember,
}
impl WireCallResult {
    fn into_result(self) -> Result<ManagedProviderJobStatus, ManagedProviderClientError> {
        match (self.status, self.error) {
            (Some(status), None) => status
                .into_status()
                .ok_or(ManagedProviderClientError::Protocol),
            // A returned application response proves transmission. It is not
            // interchangeable with a pre-write transport failure and must not
            // be treated as automatically replay-safe by a caller.
            (None, Some(WireError::Frozen)) => Err(ManagedProviderClientError::FrozenV4Terminal),
            (None, Some(WireError::Reconciliation)) => {
                Err(ManagedProviderClientError::ReconciliationRequired)
            }
            (None, Some(WireError::FreshAdmission)) => {
                Err(ManagedProviderClientError::FreshAdmissionRequired)
            }
            (None, Some(WireError::Attestation)) => {
                Err(ManagedProviderClientError::AttestationRejected)
            }
            (None, Some(WireError::Unavailable)) => {
                Err(ManagedProviderClientError::ServiceUnavailable)
            }
            (None, Some(WireError::InvalidMember)) => {
                Err(ManagedProviderClientError::InvalidMember)
            }
            _ => Err(ManagedProviderClientError::Protocol),
        }
    }
}
impl WireStatus {
    fn from_status(status: ManagedProviderJobStatus) -> Self {
        Self {
            mode: match status.mode() {
                ManagedProviderJobMode::Unselected => 0,
                ManagedProviderJobMode::ManagedV5 => 1,
                ManagedProviderJobMode::FrozenV4Terminal => 2,
            },
            phase: match status.phase() {
                ManagedProviderJobMemberPhase::Ready => 0,
                ManagedProviderJobMemberPhase::EffectStarted => 1,
                ManagedProviderJobMemberPhase::Verified => 2,
                ManagedProviderJobMemberPhase::ReconciliationRequired => 3,
                ManagedProviderJobMemberPhase::Established => 4,
                ManagedProviderJobMemberPhase::Aborted => 5,
            },
        }
    }
    fn into_status(self) -> Option<ManagedProviderJobStatus> {
        let mode = match self.mode {
            0 => ManagedProviderJobMode::Unselected,
            1 => ManagedProviderJobMode::ManagedV5,
            2 => ManagedProviderJobMode::FrozenV4Terminal,
            _ => return None,
        };
        let phase = match self.phase {
            0 => ManagedProviderJobMemberPhase::Ready,
            1 => ManagedProviderJobMemberPhase::EffectStarted,
            2 => ManagedProviderJobMemberPhase::Verified,
            3 => ManagedProviderJobMemberPhase::ReconciliationRequired,
            4 => ManagedProviderJobMemberPhase::Established,
            5 => ManagedProviderJobMemberPhase::Aborted,
            _ => return None,
        };
        Some(ManagedProviderJobStatus::new(mode, phase))
    }
}

/// Closed `/5` mTLS listener. It admits only an exact Hello and the two public
/// operations; unknown fields are rejected before the closed service port runs.
pub struct ManagedProviderJobServer {
    service: ManagedProviderJobServiceAdapter,
    tls: opc_tls::AuthenticatedServerConfig,
    scope: SessionConsumerScope,
    voter: SpiffeId,
    client: SpiffeId,
    max_connections: usize,
    #[cfg(test)]
    test_hooks: Arc<ManagedProviderServerTestHooks>,
}
#[derive(Default)]
struct ServerCounters {
    connections: AtomicU64,
    connection_high_water: AtomicU64,
    tasks: AtomicU64,
    task_high_water: AtomicU64,
}

struct ServerConnectionGuard(Arc<ServerCounters>);
impl Drop for ServerConnectionGuard {
    fn drop(&mut self) {
        self.0.connections.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Counts exactly one published task from registration until its future is
/// removed or dropped. It is moved into the future before `JoinSet::spawn`, so
/// an abort before first poll still releases the count.
struct ServerTaskGuard(Arc<ServerCounters>);
impl Drop for ServerTaskGuard {
    fn drop(&mut self) {
        self.0.tasks.fetch_sub(1, Ordering::Relaxed);
    }
}

/// The shutdown barrier and the complete retained task set have one mutex.
/// An accept path either publishes while this state remains open, or observes
/// the closed barrier and drops its socket/permit without creating a task.
struct ServerTaskRegistry {
    closed: bool,
    tasks: JoinSet<OwnedSemaphorePermit>,
}

impl ServerTaskRegistry {
    fn new() -> Self {
        Self {
            closed: false,
            tasks: JoinSet::new(),
        }
    }
}

#[cfg(test)]
struct ManagedProviderServerPublicationBarrier {
    armed: AtomicBool,
    entered: AtomicBool,
    state: StdMutex<()>,
    changed: Condvar,
}

#[cfg(test)]
impl ManagedProviderServerPublicationBarrier {
    fn new() -> Self {
        Self {
            armed: AtomicBool::new(false),
            entered: AtomicBool::new(false),
            state: StdMutex::new(()),
            changed: Condvar::new(),
        }
    }

    fn arm(&self) {
        let _state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.entered.store(false, Ordering::Release);
        self.armed.store(true, Ordering::Release);
    }

    /// This deliberately blocks a listener executor thread rather than await
    /// cancellation. It creates a real accept-to-publication interleaving: a
    /// concurrent Drop can close the registry before this path resumes.
    fn pause(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !self.armed.load(Ordering::Acquire) {
            return;
        }
        self.entered.store(true, Ordering::Release);
        self.changed.notify_all();
        while self.armed.load(Ordering::Acquire) {
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    fn wait_entered(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while !self.entered.load(Ordering::Acquire) {
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    fn release(&self) {
        let _state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.armed.store(false, Ordering::Release);
        self.changed.notify_all();
    }
}

#[cfg(test)]
struct ManagedProviderServerClosedObservation {
    armed: AtomicBool,
    observed: AtomicBool,
    state: StdMutex<()>,
    changed: Condvar,
}

#[cfg(test)]
impl ManagedProviderServerClosedObservation {
    fn new() -> Self {
        Self {
            armed: AtomicBool::new(false),
            observed: AtomicBool::new(false),
            state: StdMutex::new(()),
            changed: Condvar::new(),
        }
    }

    fn arm(&self) {
        let _state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.observed.store(false, Ordering::Release);
        self.armed.store(true, Ordering::Release);
    }

    /// Acknowledges the exact accept-path recheck under the registry lock.
    /// It is deliberately separate from the publication barrier: tests must
    /// not infer that a released accept path actually observed closure.
    fn observe_closed(&self) {
        let _state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.armed.load(Ordering::Acquire) {
            self.observed.store(true, Ordering::Release);
            self.changed.notify_all();
        }
    }

    fn wait_observed(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while !self.observed.load(Ordering::Acquire) {
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
}

#[cfg(test)]
struct ManagedProviderServerTestHooks {
    after_accept_before_publication: ManagedProviderServerPublicationBarrier,
    after_spawn_before_first_poll: ManagedProviderServerPublicationBarrier,
    closed_registry_observed: ManagedProviderServerClosedObservation,
    connection_task_first_polls: AtomicUsize,
}

#[cfg(test)]
impl ManagedProviderServerTestHooks {
    fn new() -> Self {
        Self {
            after_accept_before_publication: ManagedProviderServerPublicationBarrier::new(),
            after_spawn_before_first_poll: ManagedProviderServerPublicationBarrier::new(),
            closed_registry_observed: ManagedProviderServerClosedObservation::new(),
            connection_task_first_polls: AtomicUsize::new(0),
        }
    }
}

impl ManagedProviderJobServer {
    // This is deliberately private until opc-session-store exposes its
    // concrete least-authority facade. Production must not accept an arbitrary
    // trait object at a public network constructor.
    #[cfg(test)]
    fn new(
        service: ManagedProviderJobServiceAdapter,
        tls: opc_tls::AuthenticatedServerConfig,
        scope: SessionConsumerScope,
        voter: SpiffeId,
        client: SpiffeId,
    ) -> Self {
        Self {
            service,
            tls,
            scope,
            voter,
            client,
            max_connections: 64,
            test_hooks: Arc::new(ManagedProviderServerTestHooks::new()),
        }
    }
    pub fn with_max_connections(mut self, max_connections: usize) -> Self {
        self.max_connections = max_connections;
        self
    }
    #[cfg(test)]
    fn for_test(
        service: Arc<dyn ManagedProviderJobNetworkFacade>,
        tls: opc_tls::AuthenticatedServerConfig,
        scope: SessionConsumerScope,
        voter: SpiffeId,
        client: SpiffeId,
    ) -> Self {
        Self::new(
            ManagedProviderJobServiceAdapter::for_test(service),
            tls,
            scope,
            voter,
            client,
        )
    }
    pub async fn listen(
        self,
        bind: std::net::SocketAddr,
    ) -> io::Result<(ManagedProviderJobServerHandle, std::net::SocketAddr)> {
        if self.max_connections == 0
            || self.max_connections > MAX_MANAGED_PROVIDER_SERVER_CONNECTIONS
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid managed provider listener",
            ));
        }
        let listener = TcpListener::bind(bind).await?;
        let address = listener.local_addr()?;
        let cancelled = Arc::new(AtomicBool::new(false));
        // The task output retains its connection permit. A replacement cannot
        // be accepted until reaping consumes that output; caught panics follow
        // the same path, so retained entries stay structurally bounded.
        let tasks = Arc::new(StdMutex::new(ServerTaskRegistry::new()));
        let counters = Arc::new(ServerCounters::default());
        let permit = Arc::new(Semaphore::new(self.max_connections));
        let cancel = Arc::clone(&cancelled);
        let accept_tasks = Arc::clone(&tasks);
        let accept_counters = Arc::clone(&counters);
        #[cfg(test)]
        let accept_test_hooks = Arc::clone(&self.test_hooks);
        let handle = tokio::spawn(async move {
            let mut reap = tokio::time::interval(Duration::from_millis(10));
            reap.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            while !cancel.load(Ordering::Acquire) {
                tokio::select! {
                    _ = reap.tick() => {
                        let mut registry = accept_tasks
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        while registry.tasks.try_join_next().is_some() {}
                    }
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { continue };
                        let Ok(slot) = permit.clone().try_acquire_owned() else { continue };
                        #[cfg(test)]
                        accept_test_hooks.after_accept_before_publication.pause();
                        let service = self.service.clone();
                        let tls = self.tls.clone();
                        let scope = self.scope;
                        let voter = self.voter.clone();
                        let client = self.client.clone();
                        let counters = Arc::clone(&accept_counters);
                        // The cancellation flag is only a wakeup aid for the
                        // accept loop. `registry.closed`, checked below under
                        // this same mutex as spawn, is the publication truth.
                        let mut registry = accept_tasks
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if registry.closed || cancel.load(Ordering::Acquire) {
                            #[cfg(test)]
                            if registry.closed {
                                accept_test_hooks.closed_registry_observed.observe_closed();
                            }
                            continue;
                        }
                        let current = counters.connections.fetch_add(1, Ordering::Relaxed) + 1;
                        high(&counters.connection_high_water, current);
                        let tasks_current = counters.tasks.fetch_add(1, Ordering::Relaxed) + 1;
                        high(&counters.task_high_water, tasks_current);
                        let connection_guard = ServerConnectionGuard(Arc::clone(&counters));
                        let task_guard = ServerTaskGuard(counters);
                        #[cfg(test)]
                        let connection_test_hooks = Arc::clone(&accept_test_hooks);
                        registry.tasks.spawn(async move {
                            #[cfg(test)]
                            connection_test_hooks
                                .connection_task_first_polls
                                .fetch_add(1, Ordering::Relaxed);
                            let _task = task_guard;
                            let _connection = connection_guard;
                            let _ = AssertUnwindSafe(serve_connection(
                                stream, service, tls, scope, voter, client,
                            ))
                            .catch_unwind()
                            .await;
                            slot
                        });
                        #[cfg(test)]
                        {
                            // Keep this listener task synchronous after spawn
                            // so a different thread can abort the retained
                            // JoinSet entry before the connection future gets
                            // its first poll.
                            drop(registry);
                            accept_test_hooks.after_spawn_before_first_poll.pause();
                        }
                    }
                }
            }
        });
        Ok((
            ManagedProviderJobServerHandle {
                handle,
                cancelled,
                tasks,
                counters,
                #[cfg(test)]
                test_hooks: self.test_hooks,
            },
            address,
        ))
    }
}
pub struct ManagedProviderJobServerHandle {
    handle: JoinHandle<()>,
    cancelled: Arc<AtomicBool>,
    tasks: Arc<StdMutex<ServerTaskRegistry>>,
    counters: Arc<ServerCounters>,
    #[cfg(test)]
    test_hooks: Arc<ManagedProviderServerTestHooks>,
}
impl ManagedProviderJobServerHandle {
    /// Cancellation and task abort are synchronous so ordinary Drop has the
    /// same resource-closure guarantee as explicit shutdown, including when
    /// the last server owner is dropped outside a Tokio runtime.
    fn abort_now(&self) {
        self.handle.abort();
        let mut registry = self
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.cancelled.store(true, Ordering::Release);
        registry.closed = true;
        registry.tasks.abort_all();
    }

    /// Return redaction-safe aggregate listener counters.
    pub fn diagnostics(&self) -> ManagedProviderServerDiagnostics {
        ManagedProviderServerDiagnostics {
            connections: self.counters.connections.load(Ordering::Relaxed),
            connection_high_water: self.counters.connection_high_water.load(Ordering::Relaxed),
            connection_tasks: self.counters.tasks.load(Ordering::Relaxed),
            task_high_water: self.counters.task_high_water.load(Ordering::Relaxed),
        }
    }
    pub async fn shutdown(mut self) {
        self.abort_now();
        let _ = (&mut self.handle).await;
        let mut tasks = {
            let mut retained = self
                .tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::replace(&mut retained.tasks, JoinSet::new())
        };
        tasks.shutdown().await;
    }
}

impl Drop for ManagedProviderJobServerHandle {
    fn drop(&mut self) {
        self.abort_now();
    }
}
async fn serve_connection(
    stream: TcpStream,
    service: ManagedProviderJobServiceAdapter,
    tls: opc_tls::AuthenticatedServerConfig,
    scope: SessionConsumerScope,
    voter: SpiffeId,
    client: SpiffeId,
) -> Result<(), ManagedProviderClientError> {
    let setup_deadline = tokio::time::Instant::now()
        .checked_add(MANAGED_PROVIDER_SETUP_TIMEOUT)
        .ok_or(ManagedProviderClientError::Unavailable)?;
    let handshake = tls
        .begin_handshake()
        .map_err(|_| ManagedProviderClientError::Authentication)?;
    let mut config = handshake.rustls_config().as_ref().clone();
    config.alpn_protocols = vec![MANAGED_PROVIDER_JOB_ALPN.to_vec()];
    let mut stream = tokio::time::timeout_at(
        setup_deadline,
        tokio_rustls::TlsAcceptor::from(Arc::new(config)).accept(stream),
    )
    .await
    .map_err(|_| ManagedProviderClientError::Authentication)?
    .map_err(classify_tls_io_error)
    .map_err(|_| ManagedProviderClientError::Authentication)?;
    if stream.get_ref().1.alpn_protocol() != Some(MANAGED_PROVIDER_JOB_ALPN) {
        return Err(ManagedProviderClientError::Protocol);
    }
    let peer = opc_tls::peer_tls_identity_from_server_connection(stream.get_ref().1)
        .map_err(|_| ManagedProviderClientError::Authentication)?;
    if peer.spiffe_id() != &client {
        return Err(ManagedProviderClientError::Authentication);
    }
    let hello: WireRequest = read_json_until(
        &mut stream,
        MANAGED_PROVIDER_V5_REQUEST_FRAME_BYTES,
        setup_deadline,
    )
    .await?;
    let WireRequest::Hello(hello) = hello else {
        return Err(ManagedProviderClientError::Protocol);
    };
    if hello.transport_revision != MANAGED_PROVIDER_JOB_TRANSPORT_REVISION
        || hello.semantic_revision != MANAGED_PROVIDER_JOB_SEMANTIC_REVISION
        || hello.scope != scope
        || hello.profile_digest != profile_digest()
        || !wire_voter_identity_is_valid(&hello.expected_voter)
        || hello.expected_voter != voter.as_str()
        || hello.request_frame_size != MANAGED_PROVIDER_V5_REQUEST_FRAME_BYTES as u32
        || hello.response_frame_size != MANAGED_PROVIDER_V5_RESPONSE_FRAME_BYTES as u32
    {
        let _ = write_json_until(
            &mut stream,
            &WireResponse::Reject,
            MANAGED_PROVIDER_V5_RESPONSE_FRAME_BYTES,
            setup_deadline,
        )
        .await;
        return Err(ManagedProviderClientError::Protocol);
    }
    handshake
        .admit()
        .map_err(|_| ManagedProviderClientError::Authentication)?;
    write_json_until(
        &mut stream,
        &WireResponse::HelloAck(WireAck {
            transport_revision: MANAGED_PROVIDER_JOB_TRANSPORT_REVISION,
            semantic_revision: MANAGED_PROVIDER_JOB_SEMANTIC_REVISION,
            scope,
            profile_digest: profile_digest(),
            request_frame_size: MANAGED_PROVIDER_V5_REQUEST_FRAME_BYTES as u32,
            response_frame_size: MANAGED_PROVIDER_V5_RESPONSE_FRAME_BYTES as u32,
        }),
        MANAGED_PROVIDER_V5_RESPONSE_FRAME_BYTES,
        setup_deadline,
    )
    .await?;
    loop {
        let frame_deadline = tokio::time::Instant::now()
            .checked_add(MANAGED_PROVIDER_FRAME_TIMEOUT)
            .ok_or(ManagedProviderClientError::Unavailable)?;
        let request: WireRequest = read_json_until(
            &mut stream,
            MANAGED_PROVIDER_V5_REQUEST_FRAME_BYTES,
            frame_deadline,
        )
        .await?;
        let WireRequest::Call { operation } = request else {
            return Err(ManagedProviderClientError::Protocol);
        };
        // Serde derives bypass constructors for nested store DTOs. Reapply the
        // closed profile's invariant checks before the least-authority facade
        // can observe any decoded value.
        if !wire_operation_is_valid(&operation) {
            return Err(ManagedProviderClientError::Protocol);
        }
        let response = match operation {
            WireOperation::Run {
                admission,
                protected_checkpoint,
                ordinal,
            } => match validated_admission(admission, scope, &client) {
                Ok(admission) => match FencedMutationRosterOrdinal::new(ordinal) {
                    Ok(ordinal) => result_to_wire(
                        tokio::time::timeout(
                            MANAGED_PROVIDER_FACADE_TIMEOUT,
                            service
                                .0
                                .run_member(admission, protected_checkpoint, ordinal),
                        )
                        .await
                        .map_err(|_| ManagedProviderClientError::OutcomeUnknown)?,
                    ),
                    Err(_) => WireCallResult {
                        status: None,
                        error: Some(WireError::InvalidMember),
                    },
                },
                Err(_) => WireCallResult {
                    status: None,
                    error: Some(WireError::InvalidMember),
                },
            },
            WireOperation::Status { admission, ordinal } => {
                match validated_admission(admission, scope, &client) {
                    Ok(admission) => match FencedMutationRosterOrdinal::new(ordinal) {
                        Ok(ordinal) => result_to_wire(
                            tokio::time::timeout(
                                MANAGED_PROVIDER_FACADE_TIMEOUT,
                                service.0.job_status(admission, ordinal),
                            )
                            .await
                            .map_err(|_| ManagedProviderClientError::OutcomeUnknown)?,
                        ),
                        Err(_) => WireCallResult {
                            status: None,
                            error: Some(WireError::InvalidMember),
                        },
                    },
                    Err(_) => WireCallResult {
                        status: None,
                        error: Some(WireError::InvalidMember),
                    },
                }
            }
        };
        // A completed facade call never renews the read budget. Its response
        // gets its own fixed write budget, so a slow-but-in-budget facade is
        // not converted into a late frame write.
        let response_deadline = tokio::time::Instant::now()
            .checked_add(MANAGED_PROVIDER_FRAME_TIMEOUT)
            .ok_or(ManagedProviderClientError::Unavailable)?;
        write_json_until(
            &mut stream,
            &WireResponse::Call(response),
            MANAGED_PROVIDER_V5_RESPONSE_FRAME_BYTES,
            response_deadline,
        )
        .await?;
    }
}
fn wire_voter_identity_is_valid(identity: &str) -> bool {
    identity.len() <= PROFILE_MAX_SPIFFE_ID_BYTES && SpiffeId::new(identity.to_owned()).is_ok()
}
fn wire_operation_is_valid(operation: &WireOperation) -> bool {
    use opc_session_store::fenced_mutation_roster::{
        MAX_DESCRIPTOR_BYTES, MAX_PLAN_BYTES, MAX_RESULT_BYTES,
    };

    let (admission, checkpoint) = match operation {
        WireOperation::Run {
            admission,
            protected_checkpoint,
            ..
        } => (admission, Some(protected_checkpoint.as_ref())),
        WireOperation::Status { admission, .. } => (admission, None),
    };
    if admission.validate().is_err()
        || admission.protected_plan().len() > MAX_PLAN_BYTES
        || admission.terminal_result().as_bytes().len() > MAX_RESULT_BYTES
        || checkpoint.is_some_and(|bytes| bytes.len() > MAX_PLAN_BYTES)
        || admission.members().as_slice().iter().any(|member| {
            member.caller_id().iter().all(|byte| *byte == 0)
                || member.descriptor().as_bytes().len() > MAX_DESCRIPTOR_BYTES
        })
    {
        return false;
    }
    !admission
        .request_id()
        .operation_id()
        .as_bytes()
        .iter()
        .all(|byte| *byte == 0)
}
fn validated_admission(
    admission: FencedMutationRosterAdmission,
    scope: SessionConsumerScope,
    client: &SpiffeId,
) -> Result<FencedMutationRosterAdmission, ()> {
    admission.validate().map_err(|_| ())?;
    let mut identity = Sha256::new();
    identity.update(b"openpacketcore/tls/local-spiffe-identity-commitment/v1\0");
    identity.update(
        u16::try_from(client.as_str().len())
            .map_err(|_| ())?
            .to_be_bytes(),
    );
    identity.update(client.as_str().as_bytes());
    let expected = derive_fenced_mutation_roster_scope(identity.finalize().into(), scope);
    if admission.scope() != expected {
        return Err(());
    }
    Ok(admission)
}
fn result_to_wire(
    result: Result<ManagedProviderJobStatus, ManagedProviderJobError>,
) -> WireCallResult {
    match result {
        Ok(status) => WireCallResult {
            status: Some(WireStatus::from_status(status)),
            error: None,
        },
        Err(error) => WireCallResult {
            status: None,
            error: Some(match error {
                ManagedProviderJobError::FrozenV4Terminal => WireError::Frozen,
                ManagedProviderJobError::ReconciliationRequired => WireError::Reconciliation,
                ManagedProviderJobError::FreshAdmissionRequired => WireError::FreshAdmission,
                ManagedProviderJobError::AttestationRejected => WireError::Attestation,
                ManagedProviderJobError::Unavailable => WireError::Unavailable,
                ManagedProviderJobError::InvalidMember => WireError::InvalidMember,
            }),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::task::{Context, Poll};

    use futures_util::future::BoxFuture;
    use opc_consensus::{derive_configuration_id, ConsensusClusterId, ConsensusConfigurationEpoch};
    use opc_identity::{build_identity_state, parse_certs_pem, parse_key_pem, TrustBundle};
    use opc_session_store::SessionConsensusIdentity;
    use opc_tls::TlsConfigBuilder;

    struct FaultWriter {
        limits: VecDeque<usize>,
        flush_fails: bool,
    }

    struct TestPki {
        ca: rcgen::CertifiedIssuer<'static, rcgen::KeyPair>,
    }

    impl TestPki {
        fn new() -> Self {
            let key = rcgen::KeyPair::generate().expect("test CA key");
            let mut parameters = rcgen::CertificateParams::default();
            parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            parameters
                .distinguished_name
                .push(rcgen::DnType::CommonName, "managed provider test CA");
            Self {
                ca: rcgen::CertifiedIssuer::self_signed(parameters, key)
                    .expect("test CA certificate"),
            }
        }

        fn client_config(&self, identity: &str) -> opc_tls::AuthenticatedClientConfig {
            let (_source, receiver) = tokio::sync::watch::channel(Some(self.identity(identity)));
            TlsConfigBuilder::new(receiver)
                .allow_any_trusted_peer()
                .build_authenticated_client_config()
                .expect("test client mTLS configuration")
        }

        fn server_config(&self, identity: &str) -> opc_tls::AuthenticatedServerConfig {
            let (_source, receiver) = tokio::sync::watch::channel(Some(self.identity(identity)));
            TlsConfigBuilder::new(receiver)
                .allow_any_trusted_peer()
                .build_authenticated_server_config()
                .expect("test server mTLS configuration")
        }

        fn identity(&self, identity: &str) -> opc_identity::IdentityState {
            let mut parameters = rcgen::CertificateParams::default();
            parameters
                .distinguished_name
                .push(rcgen::DnType::CommonName, "managed provider test leaf");
            parameters.subject_alt_names.push(rcgen::SanType::URI(
                rcgen::string::Ia5String::try_from(identity).expect("test SPIFFE URI"),
            ));
            let now = time::OffsetDateTime::now_utc();
            parameters.not_before = now - time::Duration::days(1);
            parameters.not_after = now + time::Duration::days(1);
            let key = rcgen::KeyPair::generate().expect("test leaf key");
            let certificate = parameters
                .signed_by(&key, &self.ca)
                .expect("test leaf certificate");
            let certificates = parse_certs_pem(&(certificate.pem() + &self.ca.pem()))
                .expect("test certificate chain");
            let private_key = parse_key_pem(&key.serialize_pem()).expect("test private key");
            let mut bundles = opc_identity::TrustBundleSet::new();
            bundles.insert(TrustBundle {
                trust_domain: opc_identity::TrustDomain::new("test.example")
                    .expect("test trust domain"),
                certificates: parse_certs_pem(&self.ca.pem()).expect("test trust bundle"),
            });
            build_identity_state(certificates, private_key, bundles).expect("test identity state")
        }
    }

    fn test_scope() -> SessionConsumerScope {
        let cluster = ConsensusClusterId::new("managed-provider-network-test")
            .expect("test cluster identity");
        let epoch = ConsensusConfigurationEpoch::new(1).expect("test epoch");
        SessionConsumerScope::new(SessionConsensusIdentity::new(
            cluster,
            derive_configuration_id(cluster, epoch, &[]),
            epoch,
        ))
    }

    fn lifecycle_test_client(
        resolver_calls: Arc<AtomicUsize>,
    ) -> PersistentManagedProviderJobClient {
        let pki = TestPki::new();
        let client_identity =
            "spiffe://test.example/tenant/test/ns/default/sa/session/nf/consumer/instance/lifecycle-client";
        let endpoint_identities = [
            "spiffe://test.example/tenant/test/ns/default/sa/session/nf/consumer/instance/lifecycle-voter-0",
            "spiffe://test.example/tenant/test/ns/default/sa/session/nf/consumer/instance/lifecycle-voter-1",
            "spiffe://test.example/tenant/test/ns/default/sa/session/nf/consumer/instance/lifecycle-voter-2",
        ];
        let endpoints = endpoint_identities.map(|identity| {
            let resolver_calls = Arc::clone(&resolver_calls);
            let resolver: RemoteAddrResolver = Arc::new(move || {
                resolver_calls.fetch_add(1, AtomicOrdering::Relaxed);
                Box::pin(std::future::pending()) as BoxFuture<'static, io::Result<_>>
            });
            ManagedVoterEndpoint::new(
                resolver,
                ServerName::IpAddress(std::net::Ipv4Addr::LOCALHOST.into()),
                SpiffeId::new(identity).expect("test voter SPIFFE identity"),
            )
        });
        PersistentManagedProviderJobClient::new(
            ManagedProviderClientAuthority::new(test_scope(), pki.client_config(client_identity))
                .expect("test authority"),
            endpoints,
            ManagedProviderPoolConfig::try_new(
                1,
                MANAGED_PROVIDER_V5_REQUEST_FRAME_BYTES,
                MANAGED_PROVIDER_V5_RESPONSE_FRAME_BYTES,
                Duration::from_millis(10),
                Duration::from_millis(10),
                Duration::from_millis(1),
            )
            .expect("short lifecycle configuration"),
        )
        .expect("test client")
    }

    fn lifecycle_test_operation() -> WireOperation {
        use opc_session_store::fenced_mutation_roster as roster;
        use opc_session_store::{FenceToken, Generation, OwnerId};

        let client_identity =
            "spiffe://test.example/tenant/test/ns/default/sa/session/nf/consumer/instance/lifecycle-client";
        let mut commitment = Sha256::new();
        commitment.update(b"openpacketcore/tls/local-spiffe-identity-commitment/v1\0");
        commitment.update(
            u16::try_from(client_identity.len())
                .expect("test identity length")
                .to_be_bytes(),
        );
        commitment.update(client_identity.as_bytes());
        let members: [roster::FencedMutationRosterMember; roster::MAX_MEMBERS] =
            std::array::from_fn(|index| {
                roster::FencedMutationRosterMember::new(
                    roster::FencedMutationRosterOrdinal::new(index as u8).expect("test ordinal"),
                    [u8::try_from(index + 1).expect("test member ID"); roster::MEMBER_ID_BYTES],
                    roster::FencedMutationRosterDescriptor::new(vec![1]).expect("test descriptor"),
                    1,
                    1,
                    roster::FencedMutationMemberDisposition::Indeterminate,
                    roster::FencedMutationMemberAdoption::Unreconciled,
                )
                .expect("test member")
            });
        let admission = FencedMutationRosterAdmission::new(
            1,
            roster::FencedMutationRosterOperationId::new([1; roster::MEMBER_ID_BYTES])
                .expect("test operation ID"),
            derive_fenced_mutation_roster_scope(commitment.finalize().into(), test_scope()),
            roster::FencedMutationRosterFenceIntent::new(
                OwnerId::new("owner").expect("test owner"),
                FenceToken::new(1),
            ),
            Generation::new(1),
            roster::FencedMutationRosterMembers::new(members).expect("test members"),
            roster::FencedMutationRosterProtectedPlan::new(vec![1].into_boxed_slice())
                .expect("test plan"),
        )
        .expect("test admission");
        WireOperation::Run {
            admission,
            protected_checkpoint: vec![1].into_boxed_slice(),
            ordinal: 0,
        }
    }

    fn lifecycle_test_operation_for(ordinal: u8) -> WireOperation {
        match lifecycle_test_operation() {
            WireOperation::Run {
                admission,
                protected_checkpoint,
                ..
            } => WireOperation::Run {
                admission,
                protected_checkpoint,
                ordinal,
            },
            WireOperation::Status { .. } => unreachable!("test operation is Run"),
        }
    }

    fn assert_zero_lifecycle_resources(client: &PersistentManagedProviderJobClient) {
        let diagnostics = client.diagnostics();
        assert_eq!(diagnostics.queued, 0);
        assert_eq!(diagnostics.inflight, 0);
        assert_eq!(diagnostics.request_bytes, 0);
        assert_eq!(diagnostics.response_cells, 0);
        assert_eq!(
            client.pool.pending.available_permits(),
            client.pool.config.queued_and_inflight
        );
        assert_eq!(
            client.pool.bytes.available_permits(),
            client.pool.config.request_bytes
        );
        assert_eq!(
            client.pool.cells.available_permits(),
            client.pool.config.queued_and_inflight
        );
    }

    fn canonical_spiffe_with_len(length: usize) -> String {
        let prefix = "spiffe://test.example/tenant/t/ns/";
        let suffix = "/sa/s/nf/consumer/instance/i";
        let namespace_len = length
            .checked_sub(prefix.len() + suffix.len())
            .expect("test SPIFFE length is large enough");
        let identity = format!("{prefix}{}{suffix}", "n".repeat(namespace_len));
        assert_eq!(identity.len(), length);
        assert!(SpiffeId::new(identity.clone()).is_ok());
        identity
    }

    async fn wait_for_server_drop(counters: &ServerCounters) {
        for _ in 0..128 {
            if counters.connections.load(AtomicOrdering::Relaxed) == 0
                && counters.tasks.load(AtomicOrdering::Relaxed) == 0
            {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("server drop did not cancel every connection task");
    }

    struct NoopNetworkFacade;

    #[async_trait]
    impl ManagedProviderJobNetworkFacade for NoopNetworkFacade {
        async fn run_member(
            &self,
            _: FencedMutationRosterAdmission,
            _: Box<[u8]>,
            _: FencedMutationRosterOrdinal,
        ) -> Result<ManagedProviderJobStatus, ManagedProviderJobError> {
            Ok(ManagedProviderJobStatus::new(
                ManagedProviderJobMode::ManagedV5,
                ManagedProviderJobMemberPhase::Established,
            ))
        }

        async fn job_status(
            &self,
            _: FencedMutationRosterAdmission,
            _: FencedMutationRosterOrdinal,
        ) -> Result<ManagedProviderJobStatus, ManagedProviderJobError> {
            Ok(ManagedProviderJobStatus::new(
                ManagedProviderJobMode::ManagedV5,
                ManagedProviderJobMemberPhase::Established,
            ))
        }
    }

    #[derive(Default)]
    struct CountingNetworkFacade {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl ManagedProviderJobNetworkFacade for CountingNetworkFacade {
        async fn run_member(
            &self,
            _: FencedMutationRosterAdmission,
            _: Box<[u8]>,
            _: FencedMutationRosterOrdinal,
        ) -> Result<ManagedProviderJobStatus, ManagedProviderJobError> {
            self.calls.fetch_add(1, AtomicOrdering::Relaxed);
            Err(ManagedProviderJobError::Unavailable)
        }

        async fn job_status(
            &self,
            _: FencedMutationRosterAdmission,
            _: FencedMutationRosterOrdinal,
        ) -> Result<ManagedProviderJobStatus, ManagedProviderJobError> {
            self.calls.fetch_add(1, AtomicOrdering::Relaxed);
            Err(ManagedProviderJobError::Unavailable)
        }
    }

    impl AsyncWrite for FaultWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            match self.limits.pop_front().unwrap_or(bytes.len()) {
                0 => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "test close"))),
                limit => Poll::Ready(Ok(limit.min(bytes.len()))),
            }
        }

        fn poll_flush(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.flush_fails {
                self.flush_fails = false;
                Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "test close")))
            } else {
                Poll::Ready(Ok(()))
            }
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn pool_config_keeps_the_aggregate_queue_immutable() {
        let config = ManagedProviderPoolConfig::default();
        assert_eq!(
            config.queued_and_inflight(),
            MANAGED_PROVIDER_POOL_QUEUE_CAPACITY
        );
        assert_eq!(
            config.total_lanes(),
            MANAGED_PROVIDER_JOB_VOTERS * DEFAULT_MANAGED_PROVIDER_POOL_LANES
        );
        assert!(ManagedProviderPoolConfig::try_new(
            0,
            DEFAULT_MANAGED_PROVIDER_POOL_REQUEST_BYTES,
            DEFAULT_MANAGED_PROVIDER_POOL_RESPONSE_BYTES,
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::from_millis(1),
        )
        .is_err());
        assert!(ManagedProviderPoolConfig::try_new(
            DEFAULT_MANAGED_PROVIDER_POOL_LANES,
            MANAGED_PROVIDER_V5_REQUEST_FRAME_BYTES,
            MANAGED_PROVIDER_V5_RESPONSE_FRAME_BYTES,
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::from_millis(1),
        )
        .is_ok());
        for (queue, setup, drain) in [
            (
                Duration::MAX,
                Duration::from_millis(1),
                Duration::from_millis(1),
            ),
            (
                Duration::from_millis(1),
                Duration::MAX,
                Duration::from_millis(1),
            ),
            (
                Duration::from_millis(1),
                Duration::from_millis(1),
                Duration::MAX,
            ),
        ] {
            assert!(ManagedProviderPoolConfig::try_new(
                DEFAULT_MANAGED_PROVIDER_POOL_LANES,
                MANAGED_PROVIDER_V5_REQUEST_FRAME_BYTES,
                MANAGED_PROVIDER_V5_RESPONSE_FRAME_BYTES,
                queue,
                setup,
                drain,
            )
            .is_err());
        }
    }

    #[test]
    fn pool_config_accepts_exact_operational_maxima_and_rejects_every_larger_duration() {
        let config = |queue_deadline, setup_timeout, shutdown_drain| {
            ManagedProviderPoolConfig::try_new(
                DEFAULT_MANAGED_PROVIDER_POOL_LANES,
                MANAGED_PROVIDER_V5_REQUEST_FRAME_BYTES,
                MANAGED_PROVIDER_V5_RESPONSE_FRAME_BYTES,
                queue_deadline,
                setup_timeout,
                shutdown_drain,
            )
        };
        assert!(config(
            MAX_MANAGED_PROVIDER_POOL_QUEUE_TIMEOUT,
            MAX_MANAGED_PROVIDER_POOL_SETUP_TIMEOUT,
            MAX_MANAGED_PROVIDER_POOL_SHUTDOWN_DRAIN,
        )
        .is_ok());
        for (queue_deadline, setup_timeout, shutdown_drain) in [
            (
                MAX_MANAGED_PROVIDER_POOL_QUEUE_TIMEOUT + Duration::from_nanos(1),
                MAX_MANAGED_PROVIDER_POOL_SETUP_TIMEOUT,
                MAX_MANAGED_PROVIDER_POOL_SHUTDOWN_DRAIN,
            ),
            (
                MAX_MANAGED_PROVIDER_POOL_QUEUE_TIMEOUT,
                MAX_MANAGED_PROVIDER_POOL_SETUP_TIMEOUT + Duration::from_nanos(1),
                MAX_MANAGED_PROVIDER_POOL_SHUTDOWN_DRAIN,
            ),
            (
                MAX_MANAGED_PROVIDER_POOL_QUEUE_TIMEOUT,
                MAX_MANAGED_PROVIDER_POOL_SETUP_TIMEOUT,
                MAX_MANAGED_PROVIDER_POOL_SHUTDOWN_DRAIN + Duration::from_nanos(1),
            ),
            (
                Duration::MAX - Duration::from_nanos(1),
                MAX_MANAGED_PROVIDER_POOL_SETUP_TIMEOUT,
                MAX_MANAGED_PROVIDER_POOL_SHUTDOWN_DRAIN,
            ),
            (
                MAX_MANAGED_PROVIDER_POOL_QUEUE_TIMEOUT,
                Duration::MAX - Duration::from_nanos(1),
                MAX_MANAGED_PROVIDER_POOL_SHUTDOWN_DRAIN,
            ),
            (
                MAX_MANAGED_PROVIDER_POOL_QUEUE_TIMEOUT,
                MAX_MANAGED_PROVIDER_POOL_SETUP_TIMEOUT,
                Duration::MAX - Duration::from_nanos(1),
            ),
        ] {
            assert!(config(queue_deadline, setup_timeout, shutdown_drain).is_err());
        }
    }

    #[tokio::test]
    async fn shutdown_waits_for_each_admission_pause_and_cancellation_releases_every_resource() {
        for point in [
            ManagedProviderTestPause::AdmissionBeforePermits,
            ManagedProviderTestPause::AdmissionAfterPermits,
            ManagedProviderTestPause::AdmissionAfterAccounting,
            ManagedProviderTestPause::AdmissionBeforeSend,
        ] {
            let client = lifecycle_test_client(Arc::new(AtomicUsize::new(0)));
            client.pool.readiness.store(2, Ordering::Release);
            if point == ManagedProviderTestPause::AdmissionBeforeSend {
                let (scheduler, _receiver) = mpsc::channel(1);
                client.pool.lifecycle().scheduler = Some(scheduler);
            }
            let hook = client.pool.test_hooks.hook(point);
            hook.arm();
            let caller = tokio::spawn({
                let client = client.clone();
                async move { client.call(lifecycle_test_operation()).await }
            });
            hook.entered().await;
            let shutdown = tokio::spawn({
                let client = client.clone();
                async move { client.shutdown().await }
            });
            tokio::task::yield_now().await;
            assert!(
                !shutdown.is_finished(),
                "shutdown must wait for the caller-local admission guard"
            );
            caller.abort();
            let _ = caller.await;
            let report = tokio::time::timeout(Duration::from_millis(250), shutdown)
                .await
                .expect("bounded shutdown after cancelled caller")
                .expect("shutdown task joins");
            assert_eq!(report.remaining_connections, 0);
            assert_eq!(report.remaining_tasks, 0);
            assert_zero_lifecycle_resources(&client);
            assert_eq!(client.pool.phase(), Phase::Stopped);
        }
    }

    #[tokio::test]
    async fn panicking_admission_guard_releases_shutdown_and_repeated_waiters_share_one_report() {
        let client = lifecycle_test_client(Arc::new(AtomicUsize::new(0)));
        let panicking = tokio::spawn({
            let pool = Arc::clone(&client.pool);
            async move {
                let _guard = pool.enter_admission().expect("test admission");
                panic!("test caller panic")
            }
        });
        assert!(panicking.await.is_err(), "test task panics");
        let first = tokio::spawn({
            let client = client.clone();
            async move { client.shutdown().await }
        });
        let second = tokio::spawn({
            let client = client.clone();
            async move { client.shutdown().await }
        });
        let report = client.shutdown().await;
        assert_eq!(first.await.expect("first waiter joins"), report);
        assert_eq!(second.await.expect("second waiter joins"), report);
        assert_zero_lifecycle_resources(&client);
        assert_eq!(client.pool.phase(), Phase::Stopped);
    }

    #[tokio::test]
    async fn shutdown_before_start_prevents_registry_publication_and_network_work() {
        let resolver_calls = Arc::new(AtomicUsize::new(0));
        let client = lifecycle_test_client(Arc::clone(&resolver_calls));
        let hook = client
            .pool
            .test_hooks
            .hook(ManagedProviderTestPause::StartupBeforeRegistry);
        hook.arm();
        let prewarm = tokio::spawn({
            let client = client.clone();
            async move { client.prewarm().await }
        });
        hook.entered().await;
        let shutdown = tokio::spawn({
            let client = client.clone();
            async move { client.shutdown().await }
        });
        tokio::task::yield_now().await;
        hook.release();
        assert_eq!(
            prewarm.await.expect("prewarm task joins"),
            Err(ManagedProviderClientError::ShuttingDown)
        );
        let report = shutdown.await.expect("shutdown task joins");
        assert_eq!(report.remaining_tasks, 0);
        assert_eq!(resolver_calls.load(AtomicOrdering::Relaxed), 0);
        assert_eq!(
            client.prewarm().await,
            Err(ManagedProviderClientError::ShuttingDown)
        );
        assert_eq!(resolver_calls.load(AtomicOrdering::Relaxed), 0);
        let lifecycle = client.pool.lifecycle();
        assert!(!lifecycle.started);
        assert!(lifecycle.tasks.is_empty());
    }

    #[tokio::test]
    async fn cancelled_prewarm_releases_the_startup_claim_for_the_next_caller() {
        let client = lifecycle_test_client(Arc::new(AtomicUsize::new(0)));
        let hook = client
            .pool
            .test_hooks
            .hook(ManagedProviderTestPause::StartupBeforeRegistry);
        hook.arm();
        let cancelled = tokio::spawn({
            let client = client.clone();
            async move { client.prewarm().await }
        });
        hook.entered().await;
        cancelled.abort();
        let _ = cancelled.await;
        hook.release();
        assert_eq!(
            client.prewarm().await,
            Err(ManagedProviderClientError::Unavailable)
        );
        let report = client.shutdown().await;
        assert_eq!(report.remaining_connections, 0);
        assert_eq!(report.remaining_tasks, 0);
    }

    #[tokio::test]
    async fn complete_start_is_registered_once_and_shutdown_joins_every_worker() {
        let resolver_calls = Arc::new(AtomicUsize::new(0));
        let client = lifecycle_test_client(Arc::clone(&resolver_calls));
        let hook = client
            .pool
            .test_hooks
            .hook(ManagedProviderTestPause::StartupAfterRegistry);
        hook.arm();
        let first = tokio::spawn({
            let client = client.clone();
            async move { client.prewarm().await }
        });
        hook.entered().await;
        let second = tokio::spawn({
            let client = client.clone();
            async move { client.prewarm().await }
        });
        tokio::task::yield_now().await;
        {
            let lifecycle = client.pool.lifecycle();
            assert!(lifecycle.started);
            assert_eq!(lifecycle.tasks.len(), MANAGED_PROVIDER_JOB_VOTERS + 1);
            assert!(lifecycle.scheduler.is_some());
        }
        let shutdown = tokio::spawn({
            let client = client.clone();
            async move { client.shutdown().await }
        });
        hook.release();
        assert_eq!(
            first.await.expect("first prewarm task joins"),
            Err(ManagedProviderClientError::ShuttingDown)
        );
        assert_eq!(
            second.await.expect("second prewarm task joins"),
            Err(ManagedProviderClientError::ShuttingDown)
        );
        let report = shutdown.await.expect("shutdown task joins");
        assert_eq!(report.remaining_connections, 0);
        assert_eq!(report.remaining_tasks, 0);
        let after_shutdown = resolver_calls.load(AtomicOrdering::Relaxed);
        tokio::task::yield_now().await;
        assert_eq!(resolver_calls.load(AtomicOrdering::Relaxed), after_shutdown);
        assert_zero_lifecycle_resources(&client);
        let lifecycle = client.pool.lifecycle();
        assert!(lifecycle.tasks.is_empty());
        assert!(lifecycle.scheduler.is_none());
        assert_eq!(lifecycle.phase, Phase::Stopped);
    }

    #[tokio::test]
    async fn last_public_client_drop_aborts_the_registry_without_early_clone_closure() {
        let resolver_calls = Arc::new(AtomicUsize::new(0));
        let client = lifecycle_test_client(Arc::clone(&resolver_calls));
        client.pool.start().await.expect("test pool starts");
        tokio::task::yield_now().await;
        let weak = Arc::downgrade(&client.pool);
        let counters = Arc::clone(&client.pool.counters);
        let pending = Arc::clone(&client.pool.pending);
        let bytes = Arc::clone(&client.pool.bytes);
        let cells = Arc::clone(&client.pool.cells);
        let queue_capacity = client.pool.config.queued_and_inflight;
        let request_bytes = client.pool.config.request_bytes;
        let shared = client.clone();
        drop(client);
        let retained = weak.upgrade().expect("a shared client retains the pool");
        assert_eq!(
            retained.lifecycle().tasks.len(),
            MANAGED_PROVIDER_JOB_VOTERS + 1
        );
        drop(retained);
        drop(shared);
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        assert!(
            weak.upgrade().is_none(),
            "no task may keep a pool self-cycle"
        );
        assert_eq!(counters.connections.load(AtomicOrdering::Relaxed), 0);
        assert_eq!(counters.queued.load(AtomicOrdering::Relaxed), 0);
        assert_eq!(counters.inflight.load(AtomicOrdering::Relaxed), 0);
        assert_eq!(pending.available_permits(), queue_capacity);
        assert_eq!(bytes.available_permits(), request_bytes);
        assert_eq!(cells.available_permits(), queue_capacity);
        let calls_after_drop = resolver_calls.load(AtomicOrdering::Relaxed);
        tokio::task::yield_now().await;
        assert_eq!(
            resolver_calls.load(AtomicOrdering::Relaxed),
            calls_after_drop
        );
    }

    #[tokio::test]
    async fn last_public_client_drop_off_runtime_aborts_the_registry() {
        let resolver_calls = Arc::new(AtomicUsize::new(0));
        let client = lifecycle_test_client(Arc::clone(&resolver_calls));
        client.pool.start().await.expect("test pool starts");
        tokio::task::yield_now().await;
        let weak = Arc::downgrade(&client.pool);
        let counters = Arc::clone(&client.pool.counters);
        let pending = Arc::clone(&client.pool.pending);
        let bytes = Arc::clone(&client.pool.bytes);
        let cells = Arc::clone(&client.pool.cells);
        let queue_capacity = client.pool.config.queued_and_inflight;
        let request_bytes = client.pool.config.request_bytes;
        let last_owner = client.clone();
        drop(client);
        std::thread::spawn(move || drop(last_owner))
            .join()
            .expect("off-runtime client drop joins");
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        assert!(
            weak.upgrade().is_none(),
            "off-runtime drop breaks every task edge"
        );
        assert_eq!(counters.connections.load(AtomicOrdering::Relaxed), 0);
        assert_eq!(counters.queued.load(AtomicOrdering::Relaxed), 0);
        assert_eq!(counters.inflight.load(AtomicOrdering::Relaxed), 0);
        assert_eq!(pending.available_permits(), queue_capacity);
        assert_eq!(bytes.available_permits(), request_bytes);
        assert_eq!(cells.available_permits(), queue_capacity);
        let calls_after_drop = resolver_calls.load(AtomicOrdering::Relaxed);
        tokio::task::yield_now().await;
        assert_eq!(
            resolver_calls.load(AtomicOrdering::Relaxed),
            calls_after_drop
        );
    }

    #[tokio::test]
    async fn force_shutdown_reports_each_queued_and_inflight_production_job_once() {
        let client = lifecycle_test_client(Arc::new(AtomicUsize::new(0)));
        client.pool.readiness.store(2, Ordering::Release);
        client.pool.warm[1].store(1, Ordering::Release);
        client.pool.warm[2].store(1, Ordering::Release);
        let (scheduler_tx, scheduler_rx) = mpsc::channel(client.pool.config.queued_and_inflight);
        let (event_tx, event_rx) = mpsc::channel(2);
        let (worker_tx, mut worker_rx) = mpsc::channel(1);
        let worker_pool = Arc::downgrade(&client.pool);
        let worker = tokio::spawn(async move {
            let mut job = worker_rx
                .recv()
                .await
                .expect("scheduler dispatches first job");
            let pool = worker_pool.upgrade().expect("pool remains live for worker");
            assert_eq!(pool.begin_inflight(&mut job), Phase::Running);
            pool.pause(ManagedProviderTestPause::WorkerAfterInflight)
                .await;
            let _job = job;
            std::future::pending::<()>().await;
        });
        let scheduler = tokio::spawn(scheduler(
            Arc::downgrade(&client.pool),
            scheduler_rx,
            event_rx,
            vec![worker_tx],
        ));
        {
            let mut lifecycle = client.pool.lifecycle();
            lifecycle.scheduler = Some(scheduler_tx);
            lifecycle.tasks = vec![worker, scheduler];
            lifecycle.started = true;
        }
        event_tx
            .send(Event::Ready(0, 1))
            .await
            .expect("scheduler event channel is open");
        let hook = client
            .pool
            .test_hooks
            .hook(ManagedProviderTestPause::WorkerAfterInflight);
        hook.arm();
        let first = tokio::spawn({
            let client = client.clone();
            async move { client.call(lifecycle_test_operation_for(0)).await }
        });
        for _ in 0..128 {
            if hook.entered.load(Ordering::Acquire) != 0 || first.is_finished() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            !first.is_finished(),
            "first caller must remain owned by the production worker"
        );
        assert_ne!(
            hook.entered.load(Ordering::Acquire),
            0,
            "production worker reaches the post-inflight pause"
        );
        let second = tokio::spawn({
            let client = client.clone();
            async move { client.call(lifecycle_test_operation_for(1)).await }
        });
        for _ in 0..32 {
            if client.diagnostics().queued == 1 && client.diagnostics().inflight == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(client.diagnostics().queued, 1);
        assert_eq!(client.diagnostics().inflight, 1);
        let report = client.shutdown().await;
        hook.release();
        assert_eq!(report.drained, 0);
        assert_eq!(report.forced, 2);
        assert_eq!(report.remaining_connections, 0);
        assert_eq!(report.remaining_tasks, 0);
        assert_eq!(
            first.await.expect("first caller joins"),
            Err(ManagedProviderClientError::ShuttingDown)
        );
        assert_eq!(
            second.await.expect("second caller joins"),
            Err(ManagedProviderClientError::ShuttingDown)
        );
        assert_zero_lifecycle_resources(&client);
    }

    #[test]
    fn profile_is_pinned_to_the_exact_v5_revisions() {
        assert_eq!(MANAGED_PROVIDER_JOB_ALPN, b"opc-session-consumer/5");
        assert_eq!(MANAGED_PROVIDER_JOB_TRANSPORT_REVISION, 7);
        assert_eq!(MANAGED_PROVIDER_JOB_SEMANTIC_REVISION, 5);
        assert_eq!(
            PROFILE_MAX_SPIFFE_ID_BYTES,
            opc_identity::MAX_SPIFFE_ID_URI_LEN
        );
        assert_ne!(profile_digest(), [0; 32]);
    }

    #[test]
    fn hello_and_ack_profile_accept_exact_maximum_spiffe_identity_without_an_ack_echo() {
        let scope = test_scope();
        for (length, accepted) in [
            (PROFILE_MAX_SPIFFE_ID_BYTES - 1, true),
            (PROFILE_MAX_SPIFFE_ID_BYTES, true),
            (PROFILE_MAX_SPIFFE_ID_BYTES + 1, false),
        ] {
            let hello = WireHello {
                transport_revision: MANAGED_PROVIDER_JOB_TRANSPORT_REVISION,
                semantic_revision: MANAGED_PROVIDER_JOB_SEMANTIC_REVISION,
                scope,
                profile_digest: profile_digest(),
                request_frame_size: MANAGED_PROVIDER_V5_REQUEST_FRAME_BYTES as u32,
                response_frame_size: MANAGED_PROVIDER_V5_RESPONSE_FRAME_BYTES as u32,
                expected_voter: canonical_spiffe_with_len(length),
            };
            assert_eq!(
                wire_voter_identity_is_valid(&hello.expected_voter),
                accepted
            );
            if accepted {
                assert!(bounded_json_len(
                    &WireRequest::Hello(hello),
                    MANAGED_PROVIDER_V5_REQUEST_FRAME_BYTES
                )
                .is_ok());
            }
        }
        let ack = WireResponse::HelloAck(WireAck {
            transport_revision: MANAGED_PROVIDER_JOB_TRANSPORT_REVISION,
            semantic_revision: MANAGED_PROVIDER_JOB_SEMANTIC_REVISION,
            scope,
            profile_digest: profile_digest(),
            request_frame_size: MANAGED_PROVIDER_V5_REQUEST_FRAME_BYTES as u32,
            response_frame_size: MANAGED_PROVIDER_V5_RESPONSE_FRAME_BYTES as u32,
        });
        let exact = serde_json::to_vec(&ack).expect("test Ack encoding").len();
        assert!(exact <= MANAGED_PROVIDER_V5_RESPONSE_FRAME_BYTES);
        assert_eq!(bounded_json_len(&ack, exact), Ok(exact));
        assert_eq!(
            bounded_json_len(&ack, exact - 1),
            Err(ManagedProviderClientError::Overloaded)
        );
        assert!(bounded_json_len(&ack, MANAGED_PROVIDER_V5_RESPONSE_FRAME_BYTES).is_ok());
        let encoded = serde_json::to_string(&ack).expect("test Ack JSON");
        assert!(!encoded.contains("voter_identity"));
    }

    #[test]
    fn injectable_server_path_is_test_only() {
        let _ = ManagedProviderJobServiceAdapter::for_test;
        let _ = ManagedProviderJobServer::for_test;
    }

    #[test]
    fn unknown_public_response_fields_are_rejected() {
        assert!(serde_json::from_str::<WireResponse>(r#"{"kind":"Reject","extra":true}"#).is_err());
        assert!(serde_json::from_str::<WireCallResult>(
            r#"{"status":null,"error":null,"receipt":"forbidden"}"#
        )
        .is_err());
    }

    #[tokio::test]
    async fn closed_decoder_rejects_a_valid_value_with_trailing_bytes() {
        let bytes = br#"{"kind":"Reject"}x"#;
        let (mut writer, mut reader) = tokio::io::duplex(128);
        writer
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .await
            .expect("test length");
        writer.write_all(bytes).await.expect("test body");
        assert!(matches!(
            read_json::<_, WireResponse>(&mut reader, 128).await,
            Err(ManagedProviderClientError::Protocol)
        ));
    }

    #[test]
    fn returned_service_unavailable_is_not_a_prewrite_failure() {
        assert_eq!(
            WireCallResult {
                status: None,
                error: Some(WireError::Unavailable),
            }
            .into_result(),
            Err(ManagedProviderClientError::ServiceUnavailable)
        );
    }

    #[test]
    fn every_typed_v5_domain_error_survives_the_wire() {
        for (wire, expected) in [
            (
                WireError::Frozen,
                ManagedProviderClientError::FrozenV4Terminal,
            ),
            (
                WireError::Reconciliation,
                ManagedProviderClientError::ReconciliationRequired,
            ),
            (
                WireError::FreshAdmission,
                ManagedProviderClientError::FreshAdmissionRequired,
            ),
            (
                WireError::Attestation,
                ManagedProviderClientError::AttestationRejected,
            ),
            (
                WireError::Unavailable,
                ManagedProviderClientError::ServiceUnavailable,
            ),
            (
                WireError::InvalidMember,
                ManagedProviderClientError::InvalidMember,
            ),
        ] {
            assert_eq!(
                WireCallResult {
                    status: None,
                    error: Some(wire),
                }
                .into_result(),
                Err(expected)
            );
        }
    }

    #[test]
    fn encoded_frame_length_is_checked_before_retention() {
        assert_eq!(
            bounded_json_len(&WireResponse::Reject, 1),
            Err(ManagedProviderClientError::Overloaded)
        );
        assert!(bounded_json_len(&WireResponse::Reject, 64).is_ok());
    }

    #[test]
    fn maximum_legal_v5_plan_and_checkpoint_fit_the_pinned_profile() {
        use opc_session_store::fenced_mutation_roster as roster;
        use opc_session_store::{FenceToken, Generation, OwnerId};

        let members: [roster::FencedMutationRosterMember; roster::MAX_MEMBERS] =
            std::array::from_fn(|ordinal| {
                let caller_id = [248 + ordinal as u8; roster::MEMBER_ID_BYTES];
                roster::FencedMutationRosterMember::new(
                    roster::FencedMutationRosterOrdinal::new(ordinal as u8).expect("test ordinal"),
                    caller_id,
                    roster::FencedMutationRosterDescriptor::new(vec![
                        255;
                        roster::MAX_DESCRIPTOR_BYTES
                    ])
                    .expect("test descriptor"),
                    u64::MAX,
                    u64::MAX,
                    roster::FencedMutationMemberDisposition::Indeterminate,
                    roster::FencedMutationMemberAdoption::Unreconciled,
                )
                .expect("test member")
            });
        let admission = FencedMutationRosterAdmission::new(
            u64::MAX,
            roster::FencedMutationRosterOperationId::new([255; roster::MEMBER_ID_BYTES])
                .expect("test operation ID"),
            roster::FencedMutationRosterScope::from_digest([255; 32]),
            roster::FencedMutationRosterFenceIntent::new(
                OwnerId::new("\0".repeat(OwnerId::MAX_BYTES)).expect("test owner"),
                FenceToken::new(u64::MAX),
            ),
            Generation::new(u64::MAX),
            roster::FencedMutationRosterMembers::new(members).expect("test members"),
            roster::FencedMutationRosterProtectedPlan::new(
                vec![255; roster::MAX_PLAN_BYTES].into_boxed_slice(),
            )
            .expect("test plan"),
        )
        .expect("test admission")
        .with_terminal_result(
            roster::FencedMutationRosterProtectedResult::new(
                vec![255; roster::MAX_RESULT_BYTES].into_boxed_slice(),
            )
            .expect("test result"),
        )
        .expect("test result-bound admission");
        let frame = WireRequest::Call {
            operation: WireOperation::Run {
                admission,
                protected_checkpoint: vec![255; roster::MAX_PLAN_BYTES].into_boxed_slice(),
                ordinal: 0,
            },
        };
        let length = bounded_json_len(&frame, usize::MAX).expect("maximum legal encoding");
        assert_eq!(length, MANAGED_PROVIDER_V5_REQUEST_FRAME_BYTES);
        assert_eq!(
            bounded_json_len(&frame, 8_588_476),
            Err(ManagedProviderClientError::Overloaded)
        );
    }

    #[tokio::test]
    async fn frame_writer_marks_only_prewrite_close_not_transmitted() {
        for (limits, flush_fails, expected) in [
            (vec![0], false, FrameWriteError::NotTransmitted),
            (vec![1, 0], false, FrameWriteError::OutcomeUnknown),
            (vec![4, 0], false, FrameWriteError::OutcomeUnknown),
            (vec![usize::MAX], true, FrameWriteError::OutcomeUnknown),
        ] {
            let mut writer = FaultWriter {
                limits: limits.into(),
                flush_fails,
            };
            assert_eq!(write_raw(&mut writer, b"body").await, Err(expected));
        }
    }

    #[tokio::test]
    async fn prefinal_real_tcp_rustls_exact_three_voter_prewarm_is_fixed_width() {
        // This is deliberately a short host-local behavioral proof, not the
        // deferred 960k production scale-qualification acceptance run.
        let pki = TestPki::new();
        let client_identity =
            "spiffe://test.example/tenant/test/ns/default/sa/session/nf/consumer/instance/client";
        let voter_identities = [
            "spiffe://test.example/tenant/test/ns/default/sa/session/nf/consumer/instance/voter-0",
            "spiffe://test.example/tenant/test/ns/default/sa/session/nf/consumer/instance/voter-1",
            "spiffe://test.example/tenant/test/ns/default/sa/session/nf/consumer/instance/voter-2",
        ];
        let scope = test_scope();
        let facade = Arc::new(NoopNetworkFacade);
        let client_spiffe = SpiffeId::new(client_identity).expect("client SPIFFE identity");
        let mut handles = Vec::new();
        let mut endpoints = Vec::new();
        for identity in voter_identities {
            let voter = SpiffeId::new(identity).expect("voter SPIFFE identity");
            let (handle, address) = ManagedProviderJobServer::for_test(
                facade.clone(),
                pki.server_config(identity),
                scope,
                voter.clone(),
                client_spiffe.clone(),
            )
            .with_max_connections(DEFAULT_MANAGED_PROVIDER_POOL_LANES * 2)
            .listen("127.0.0.1:0".parse().expect("loopback address"))
            .await
            .expect("real host-local listener");
            let resolver: RemoteAddrResolver = Arc::new(move || {
                Box::pin(async move { Ok(address) }) as BoxFuture<'static, io::Result<_>>
            });
            endpoints.push(ManagedVoterEndpoint::new(
                resolver,
                ServerName::IpAddress(address.ip().into()),
                voter,
            ));
            handles.push(handle);
        }
        let endpoints: [ManagedVoterEndpoint; MANAGED_PROVIDER_JOB_VOTERS] =
            endpoints.try_into().expect("exactly three voter endpoints");
        let client = PersistentManagedProviderJobClient::new(
            ManagedProviderClientAuthority::new(scope, pki.client_config(client_identity))
                .expect("authenticated client authority"),
            endpoints,
            ManagedProviderPoolConfig::try_new(
                DEFAULT_MANAGED_PROVIDER_POOL_LANES,
                DEFAULT_MANAGED_PROVIDER_POOL_REQUEST_BYTES,
                DEFAULT_MANAGED_PROVIDER_POOL_RESPONSE_BYTES,
                Duration::from_millis(250),
                Duration::from_secs(2),
                Duration::from_millis(1),
            )
            .expect("short test shutdown drain"),
        )
        .expect("bounded client pool");

        assert_eq!(client.prewarm().await, Ok(ManagedProviderReadiness::Ready));
        let diagnostics = client.diagnostics();
        assert_eq!(
            diagnostics.connections,
            DEFAULT_MANAGED_PROVIDER_POOL_LANES as u64 * 3
        );
        assert_eq!(
            diagnostics.connection_high_water,
            DEFAULT_MANAGED_PROVIDER_POOL_LANES as u64 * 3
        );
        let cancelled_waiter = tokio::spawn({
            let client = client.clone();
            async move { client.shutdown().await }
        });
        tokio::task::yield_now().await;
        cancelled_waiter.abort();
        let shared_waiter = tokio::spawn({
            let client = client.clone();
            async move { client.shutdown().await }
        });
        let report = client.shutdown().await;
        assert_eq!(shared_waiter.await.expect("shared shutdown waiter"), report);
        assert_eq!(report.remaining_connections, 0);
        assert_eq!(report.remaining_tasks, 0);
        for handle in handles {
            handle.shutdown().await;
        }
    }

    #[tokio::test]
    async fn malformed_authenticated_frame_makes_zero_service_calls() {
        let pki = TestPki::new();
        let scope = test_scope();
        let client_identity =
            "spiffe://test.example/tenant/test/ns/default/sa/session/nf/consumer/instance/client";
        let voter_identity =
            "spiffe://test.example/tenant/test/ns/default/sa/session/nf/consumer/instance/voter";
        let service = Arc::new(CountingNetworkFacade::default());
        let (handle, address) = ManagedProviderJobServer::for_test(
            service.clone(),
            pki.server_config(voter_identity),
            scope,
            SpiffeId::new(voter_identity).expect("voter SPIFFE identity"),
            SpiffeId::new(client_identity).expect("client SPIFFE identity"),
        )
        .listen("127.0.0.1:0".parse().expect("loopback address"))
        .await
        .expect("real host-local listener");
        let client = pki.client_config(client_identity);
        let mut config = client.rustls_config().as_ref().clone();
        config.alpn_protocols = vec![MANAGED_PROVIDER_JOB_ALPN.to_vec()];
        let stream = TcpStream::connect(address).await.expect("loopback connect");
        let mut tls = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(ServerName::IpAddress(address.ip().into()), stream)
            .await
            .expect("real rustls mTLS handshake");
        write_raw(
            &mut tls,
            br#"{"kind":"unexpected","nested":{"forbidden":true}}"#,
        )
        .await
        .expect("malformed frame written");
        let _ = tokio::time::timeout(Duration::from_millis(100), tls.read_u8()).await;
        assert_eq!(service.calls.load(AtomicOrdering::Relaxed), 0);
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn profile_mismatch_is_rejected_before_any_service_call() {
        let pki = TestPki::new();
        let scope = test_scope();
        let client_identity =
            "spiffe://test.example/tenant/test/ns/default/sa/session/nf/consumer/instance/client";
        let voter_identity =
            "spiffe://test.example/tenant/test/ns/default/sa/session/nf/consumer/instance/voter";
        let service = Arc::new(CountingNetworkFacade::default());
        let (handle, address) = ManagedProviderJobServer::for_test(
            service.clone(),
            pki.server_config(voter_identity),
            scope,
            SpiffeId::new(voter_identity).expect("voter SPIFFE identity"),
            SpiffeId::new(client_identity).expect("client SPIFFE identity"),
        )
        .listen("127.0.0.1:0".parse().expect("loopback address"))
        .await
        .expect("real host-local listener");
        let client = pki.client_config(client_identity);
        let mut config = client.rustls_config().as_ref().clone();
        config.alpn_protocols = vec![MANAGED_PROVIDER_JOB_ALPN.to_vec()];
        let stream = TcpStream::connect(address).await.expect("loopback connect");
        let mut tls = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(ServerName::IpAddress(address.ip().into()), stream)
            .await
            .expect("real rustls mTLS handshake");
        let mismatch = WireRequest::Hello(WireHello {
            transport_revision: MANAGED_PROVIDER_JOB_TRANSPORT_REVISION,
            semantic_revision: MANAGED_PROVIDER_JOB_SEMANTIC_REVISION,
            scope,
            profile_digest: profile_digest(),
            request_frame_size: (MANAGED_PROVIDER_V5_REQUEST_FRAME_BYTES - 1) as u32,
            response_frame_size: MANAGED_PROVIDER_V5_RESPONSE_FRAME_BYTES as u32,
            expected_voter: voter_identity.to_owned(),
        });
        let bytes = serde_json::to_vec(&mismatch).expect("test hello encoding");
        write_raw(&mut tls, &bytes).await.expect("mismatch written");
        let _ = tokio::time::timeout(Duration::from_millis(100), tls.read_u8()).await;
        assert_eq!(service.calls.load(AtomicOrdering::Relaxed), 0);
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn listener_rejects_an_unrepresentable_permit_count() {
        let pki = TestPki::new();
        let scope = test_scope();
        let client_identity =
            "spiffe://test.example/tenant/test/ns/default/sa/session/nf/consumer/instance/client";
        let voter_identity =
            "spiffe://test.example/tenant/test/ns/default/sa/session/nf/consumer/instance/voter";
        let server = ManagedProviderJobServer::for_test(
            Arc::new(NoopNetworkFacade),
            pki.server_config(voter_identity),
            scope,
            SpiffeId::new(voter_identity).expect("voter SPIFFE identity"),
            SpiffeId::new(client_identity).expect("client SPIFFE identity"),
        )
        .with_max_connections(MAX_MANAGED_PROVIDER_SERVER_CONNECTIONS.saturating_add(1));
        assert!(server
            .listen("127.0.0.1:0".parse().expect("loopback address"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn dropping_server_handle_cancels_listener_and_connection_tasks() {
        let pki = TestPki::new();
        let scope = test_scope();
        let client_identity =
            "spiffe://test.example/tenant/test/ns/default/sa/session/nf/consumer/instance/client";
        let voter_identity =
            "spiffe://test.example/tenant/test/ns/default/sa/session/nf/consumer/instance/voter";
        let (handle, address) = ManagedProviderJobServer::for_test(
            Arc::new(NoopNetworkFacade),
            pki.server_config(voter_identity),
            scope,
            SpiffeId::new(voter_identity).expect("voter SPIFFE identity"),
            SpiffeId::new(client_identity).expect("client SPIFFE identity"),
        )
        .listen("127.0.0.1:0".parse().expect("loopback address"))
        .await
        .expect("real host-local listener");
        let counters = Arc::clone(&handle.counters);
        let stream = TcpStream::connect(address).await.expect("loopback connect");
        for _ in 0..128 {
            if counters.connections.load(AtomicOrdering::Relaxed) == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(counters.connections.load(AtomicOrdering::Relaxed), 1);
        drop(handle);
        wait_for_server_drop(&counters).await;
        drop(stream);
    }

    #[test]
    fn dropping_server_handle_inside_runtime_closes_the_accept_publication_barrier() {
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let listener = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("test listener runtime");
            runtime.block_on(async move {
                let pki = TestPki::new();
                let scope = test_scope();
                let client_identity = "spiffe://test.example/tenant/test/ns/default/sa/session/nf/consumer/instance/client";
                let voter_identity = "spiffe://test.example/tenant/test/ns/default/sa/session/nf/consumer/instance/voter";
                let (handle, address) = ManagedProviderJobServer::for_test(
                    Arc::new(NoopNetworkFacade),
                    pki.server_config(voter_identity),
                    scope,
                    SpiffeId::new(voter_identity).expect("voter SPIFFE identity"),
                    SpiffeId::new(client_identity).expect("client SPIFFE identity"),
                )
                .listen("127.0.0.1:0".parse().expect("loopback address"))
                .await
                .expect("real host-local listener");
                let (stop_tx, stop_rx) = oneshot::channel();
                ready_tx
                    .send((handle, address, stop_tx))
                    .expect("test listener receiver remains live");
                let _ = stop_rx.await;
            });
        });
        let (handle, address, stop_tx) = ready_rx.recv().expect("test listener is ready");
        let hook = Arc::clone(&handle.test_hooks);
        let counters = Arc::clone(&handle.counters);
        hook.after_accept_before_publication.arm();
        hook.closed_registry_observed.arm();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test client runtime");
        runtime.block_on(async move {
            let stream = TcpStream::connect(address).await.expect("loopback connect");
            hook.after_accept_before_publication.wait_entered();
            // This Drop runs inside Tokio while the listener executor is
            // synchronously held between accept and registry publication.
            drop(handle);
            hook.after_accept_before_publication.release();
            hook.closed_registry_observed.wait_observed();
            wait_for_server_drop(&counters).await;
            assert_eq!(
                counters.connection_high_water.load(AtomicOrdering::Relaxed),
                0
            );
            assert_eq!(counters.task_high_water.load(AtomicOrdering::Relaxed), 0);
            drop(stream);
        });
        let _ = stop_tx.send(());
        listener.join().expect("test listener thread joins");
    }

    #[tokio::test]
    async fn dropping_server_handle_off_runtime_closes_the_accept_publication_barrier() {
        let pki = TestPki::new();
        let scope = test_scope();
        let client_identity =
            "spiffe://test.example/tenant/test/ns/default/sa/session/nf/consumer/instance/client";
        let voter_identity =
            "spiffe://test.example/tenant/test/ns/default/sa/session/nf/consumer/instance/voter";
        let (handle, address) = ManagedProviderJobServer::for_test(
            Arc::new(NoopNetworkFacade),
            pki.server_config(voter_identity),
            scope,
            SpiffeId::new(voter_identity).expect("voter SPIFFE identity"),
            SpiffeId::new(client_identity).expect("client SPIFFE identity"),
        )
        .listen("127.0.0.1:0".parse().expect("loopback address"))
        .await
        .expect("real host-local listener");
        let counters = Arc::clone(&handle.counters);
        let hook = Arc::clone(&handle.test_hooks);
        hook.after_accept_before_publication.arm();
        hook.closed_registry_observed.arm();
        let drop_hook = Arc::clone(&hook);
        let dropper = std::thread::spawn(move || {
            drop_hook.after_accept_before_publication.wait_entered();
            drop(handle);
            drop_hook.after_accept_before_publication.release();
        });
        let stream = TcpStream::connect(address).await.expect("loopback connect");
        // The listener task blocks synchronously at the hook. The off-runtime
        // drop closes the registry, then releases it to recheck that barrier.
        for _ in 0..128 {
            if hook
                .after_accept_before_publication
                .entered
                .load(Ordering::Acquire)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            hook.after_accept_before_publication
                .entered
                .load(Ordering::Acquire),
            "listener reached the accept-to-publication barrier"
        );
        dropper.join().expect("off-runtime server drop joins");
        hook.closed_registry_observed.wait_observed();
        wait_for_server_drop(&counters).await;
        assert_eq!(
            counters.connection_high_water.load(AtomicOrdering::Relaxed),
            0
        );
        assert_eq!(counters.task_high_water.load(AtomicOrdering::Relaxed), 0);
        drop(stream);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dropping_server_handle_aborts_an_unpolled_published_task() {
        let pki = TestPki::new();
        let scope = test_scope();
        let client_identity =
            "spiffe://test.example/tenant/test/ns/default/sa/session/nf/consumer/instance/client";
        let voter_identity =
            "spiffe://test.example/tenant/test/ns/default/sa/session/nf/consumer/instance/voter";
        let (handle, address) = ManagedProviderJobServer::for_test(
            Arc::new(NoopNetworkFacade),
            pki.server_config(voter_identity),
            scope,
            SpiffeId::new(voter_identity).expect("voter SPIFFE identity"),
            SpiffeId::new(client_identity).expect("client SPIFFE identity"),
        )
        .listen("127.0.0.1:0".parse().expect("loopback address"))
        .await
        .expect("real host-local listener");
        let counters = Arc::clone(&handle.counters);
        let hook = Arc::clone(&handle.test_hooks);
        hook.after_spawn_before_first_poll.arm();
        let drop_hook = Arc::clone(&hook);
        let dropper = std::thread::spawn(move || {
            drop_hook.after_spawn_before_first_poll.wait_entered();
            // The listener has released the registry mutex after publication,
            // but cannot yield to the new task until this barrier releases.
            // Drop therefore aborts the retained, never-polled future.
            drop(handle);
            drop_hook.after_spawn_before_first_poll.release();
        });
        let stream = TcpStream::connect(address).await.expect("loopback connect");
        for _ in 0..128 {
            if hook
                .after_spawn_before_first_poll
                .entered
                .load(Ordering::Acquire)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            hook.after_spawn_before_first_poll
                .entered
                .load(Ordering::Acquire),
            "listener published the connection task before it could first poll"
        );
        dropper.join().expect("unpolled task abort joins");
        wait_for_server_drop(&counters).await;
        assert_eq!(
            hook.connection_task_first_polls
                .load(AtomicOrdering::Relaxed),
            0,
            "the aborted task never reached its first poll"
        );
        assert_eq!(
            counters.connection_high_water.load(AtomicOrdering::Relaxed),
            1
        );
        assert_eq!(counters.task_high_water.load(AtomicOrdering::Relaxed), 1);
        assert_eq!(counters.connections.load(AtomicOrdering::Relaxed), 0);
        assert_eq!(counters.tasks.load(AtomicOrdering::Relaxed), 0);
        drop(stream);
    }

    #[tokio::test]
    async fn completed_server_entries_retain_permits_until_reaped() {
        let pki = TestPki::new();
        let scope = test_scope();
        let client_identity =
            "spiffe://test.example/tenant/test/ns/default/sa/session/nf/consumer/instance/client";
        let voter_identity =
            "spiffe://test.example/tenant/test/ns/default/sa/session/nf/consumer/instance/voter";
        let (handle, address) = ManagedProviderJobServer::for_test(
            Arc::new(NoopNetworkFacade),
            pki.server_config(voter_identity),
            scope,
            SpiffeId::new(voter_identity).expect("voter SPIFFE identity"),
            SpiffeId::new(client_identity).expect("client SPIFFE identity"),
        )
        .with_max_connections(1)
        .listen("127.0.0.1:0".parse().expect("loopback address"))
        .await
        .expect("real host-local listener");
        for _ in 0..32 {
            let stream = TcpStream::connect(address).await.expect("loopback connect");
            drop(stream);
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        let diagnostics = handle.diagnostics();
        assert!(diagnostics.connection_tasks <= 1);
        assert_eq!(diagnostics.task_high_water, 1);
        assert!(diagnostics.connections <= 1);
        assert_eq!(diagnostics.connection_high_water, 1);
        handle.shutdown().await;
    }
}
