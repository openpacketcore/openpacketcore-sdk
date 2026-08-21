//! Bounded `/5` mTLS transport for server-owned managed provider jobs.
//!
//! This module deliberately has a closed, two-operation wire protocol.  In
//! particular it does not serialize provider input, verifier material, worker
//! identity, private evidence, receipts, or a caller supplied job identity.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::Duration;

use async_trait::async_trait;
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
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Mutex, Notify, OwnedSemaphorePermit, Semaphore};
use tokio::task::{JoinHandle, JoinSet};

use crate::consensus::RemoteAddrResolver;
use crate::error::classify_tls_io_error;

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
pub const DEFAULT_MANAGED_PROVIDER_POOL_REQUEST_BYTES: usize = 1_048_576;
/// Maximum bounded public response bytes.
pub const DEFAULT_MANAGED_PROVIDER_POOL_RESPONSE_BYTES: usize = 1024;

const PROFILE_DOMAIN: &[u8] = b"opc-session-net/managed-provider/5/profile\0";

fn profile_digest() -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(PROFILE_DOMAIN);
    hash.update(MANAGED_PROVIDER_JOB_TRANSPORT_REVISION.to_be_bytes());
    hash.update(MANAGED_PROVIDER_JOB_SEMANTIC_REVISION.to_be_bytes());
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
            request_bytes: DEFAULT_MANAGED_PROVIDER_POOL_REQUEST_BYTES,
            response_bytes: DEFAULT_MANAGED_PROVIDER_POOL_RESPONSE_BYTES,
            queue_deadline: Duration::from_millis(250),
            setup_timeout: Duration::from_secs(2),
            shutdown_drain: Duration::from_secs(5),
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
            || self.response_bytes > 4096
            || self.request_bytes > u32::MAX as usize
            || self.response_bytes > u32::MAX as usize
            || self.request_bytes > Semaphore::MAX_PERMITS
            || self.queued_and_inflight > Semaphore::MAX_PERMITS
            || self.queue_deadline.is_zero()
            || self.setup_timeout.is_zero()
            || self.shutdown_drain.is_zero()
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
fn high(value: &AtomicU64, current: u64) {
    let mut old = value.load(Ordering::Relaxed);
    while current > old {
        match value.compare_exchange_weak(old, current, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(next) => old = next,
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Running,
    Draining,
    Forced,
    Stopped,
}
impl Phase {
    fn load(value: &AtomicU8) -> Self {
        match value.load(Ordering::Acquire) {
            1 => Self::Draining,
            2 => Self::Forced,
            3 => Self::Stopped,
            _ => Self::Running,
        }
    }
}

/// A composite, fixed-width `/5` client. Construction validates exactly three
/// distinct voter identities; subscriber cardinality does not create sockets,
/// tasks, response cells, or queues.
#[derive(Clone)]
pub struct PersistentManagedProviderJobClient {
    pool: Arc<Pool>,
}

struct Pool {
    authority: ManagedProviderClientAuthority,
    endpoints: [ManagedVoterEndpoint; MANAGED_PROVIDER_JOB_VOTERS],
    config: ManagedProviderPoolConfig,
    phase: AtomicU8,
    started: AtomicBool,
    readiness: AtomicU8,
    warm: [AtomicUsize; MANAGED_PROVIDER_JOB_VOTERS],
    pending: Arc<Semaphore>,
    bytes: Arc<Semaphore>,
    cells: Arc<Semaphore>,
    counters: Counters,
    scheduler: StdMutex<Option<mpsc::Sender<Command>>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    shutdown_started: AtomicBool,
    shutdown_report: StdMutex<Option<ManagedProviderShutdownReport>>,
    shutdown_complete: Notify,
    readiness_changed: Notify,
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
        Ok(Self {
            pool: Arc::new(Pool {
                authority,
                endpoints,
                config,
                phase: AtomicU8::new(Phase::Running as u8),
                started: AtomicBool::new(false),
                readiness: AtomicU8::new(0),
                warm: std::array::from_fn(|_| AtomicUsize::new(0)),
                pending: Arc::new(Semaphore::new(config.queued_and_inflight)),
                bytes: Arc::new(Semaphore::new(config.request_bytes)),
                cells: Arc::new(Semaphore::new(config.queued_and_inflight)),
                counters: Counters::default(),
                scheduler: StdMutex::new(None),
                tasks: Mutex::new(Vec::new()),
                shutdown_started: AtomicBool::new(false),
                shutdown_report: StdMutex::new(None),
                shutdown_complete: Notify::new(),
                readiness_changed: Notify::new(),
            }),
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
        self.pool.start()?;
        let deadline = tokio::time::Instant::now() + self.pool.config.setup_timeout;
        loop {
            if self.readiness() == ManagedProviderReadiness::Ready {
                return Ok(ManagedProviderReadiness::Ready);
            }
            if Phase::load(&self.pool.phase) != Phase::Running {
                return Err(ManagedProviderClientError::ShuttingDown);
            }
            let notified = self.pool.readiness_changed.notified();
            tokio::pin!(notified);
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
        if Phase::load(&self.pool.phase) != Phase::Running {
            return Err(ManagedProviderClientError::ShuttingDown);
        }
        if self.readiness() == ManagedProviderReadiness::Unready {
            return Err(ManagedProviderClientError::Unavailable);
        }
        if !operation_matches_authority(&operation, &self.pool.authority) {
            return Err(ManagedProviderClientError::Protocol);
        }
        let frame = WireRequest::Call { operation };
        let encoded =
            serde_json::to_vec(&frame).map_err(|_| ManagedProviderClientError::Protocol)?;
        if encoded.len() > self.pool.config.request_bytes {
            self.pool.counters.overload.fetch_add(1, Ordering::Relaxed);
            return Err(ManagedProviderClientError::Overloaded);
        }
        let pending = Arc::clone(&self.pool.pending)
            .try_acquire_owned()
            .map_err(|_| {
                self.pool.counters.overload.fetch_add(1, Ordering::Relaxed);
                ManagedProviderClientError::Overloaded
            })?;
        let frame_bytes = encoded.len();
        let byte_count =
            u32::try_from(frame_bytes).map_err(|_| ManagedProviderClientError::Overloaded)?;
        let bytes = Arc::clone(&self.pool.bytes)
            .try_acquire_many_owned(byte_count)
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
        let (reply_tx, reply_rx) = oneshot::channel();
        let key = job_key(&frame);
        let job = Job {
            key,
            encoded: Arc::<[u8]>::from(encoded),
            deadline: tokio::time::Instant::now() + self.pool.config.queue_deadline,
            reply: reply_tx,
            _pending: pending,
            _bytes: bytes,
            _cell: cells,
        };
        self.pool.track_enqueue(job.encoded.len());
        let tx = self
            .pool
            .scheduler
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .ok_or(ManagedProviderClientError::Unavailable)?;
        if tx.try_send(Command::Submit(job)).is_err() {
            self.pool.release_enqueue(frame_bytes);
            self.pool.counters.overload.fetch_add(1, Ordering::Relaxed);
            return Err(ManagedProviderClientError::Overloaded);
        }
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
    fn start(self: &Arc<Self>) -> Result<(), ManagedProviderClientError> {
        if self.started.load(Ordering::Acquire) {
            return Ok(());
        }
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(ManagedProviderClientError::Unavailable);
        }
        if self.started.swap(true, Ordering::AcqRel) {
            return Ok(());
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
                    Arc::clone(self),
                    voter,
                    lane,
                    worker_rx,
                    event_tx.clone(),
                )));
            }
        }
        *self
            .scheduler
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(tx);
        handles.push(tokio::spawn(scheduler(
            Arc::downgrade(self),
            rx,
            event_rx,
            worker_txs,
        )));
        *self
            .tasks
            .try_lock()
            .map_err(|_| ManagedProviderClientError::Unavailable)? = handles;
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
    fn release_enqueue(&self, bytes: usize) {
        self.counters.queued.fetch_sub(1, Ordering::Relaxed);
        self.counters
            .request_bytes
            .fetch_sub(bytes as u64, Ordering::Relaxed);
        self.counters.response_cells.fetch_sub(1, Ordering::Relaxed);
    }
    fn update_readiness(&self) {
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
        if self.shutdown_started.swap(true, Ordering::AcqRel) {
            return;
        }
        self.phase.store(Phase::Draining as u8, Ordering::Release);
        let scheduler = self
            .scheduler
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let pool = Arc::clone(self);
        tokio::spawn(async move {
            if let Some(tx) = scheduler {
                let _ = tx.send(Command::Drain).await;
                tokio::time::sleep(pool.config.shutdown_drain).await;
                pool.phase.store(Phase::Forced as u8, Ordering::Release);
                let _ = tx.send(Command::Force).await;
            }
            let handles = std::mem::take(&mut *pool.tasks.lock().await);
            // A hung TLS peer or service cannot hold a retained supervisor
            // beyond its drain deadline. Abort only after the bounded drain.
            pool.counters.shutdown_forced.fetch_add(
                pool.counters.inflight.load(Ordering::Relaxed),
                Ordering::Relaxed,
            );
            for handle in &handles {
                handle.abort();
            }
            for mut handle in handles {
                let _ = (&mut handle).await;
            }
            pool.phase.store(Phase::Stopped as u8, Ordering::Release);
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
            if let Some(report) = *self
                .shutdown_report
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
            {
                return report;
            }
            self.shutdown_complete.notified().await;
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
    encoded: Arc<[u8]>,
    deadline: tokio::time::Instant,
    reply: oneshot::Sender<Result<ManagedProviderJobStatus, ManagedProviderClientError>>,
    _pending: OwnedSemaphorePermit,
    _bytes: OwnedSemaphorePermit,
    _cell: OwnedSemaphorePermit,
}
enum Command {
    Submit(Job),
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
            let (job, empty) = match queues.get_mut(&key) {
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
                complete(&p, job, Err(ManagedProviderClientError::Overloaded));
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
                Err(mpsc::error::TrySendError::Closed(job)) => {
                    complete(&p, job, Err(ManagedProviderClientError::Unavailable))
                }
            }
        }
        drop(p);
        tokio::select! {
            command = commands.recv() => match command {
                Some(Command::Submit(job)) => {
                    let Some(p) = pool.upgrade() else { return };
                    if Phase::load(&p.phase) != Phase::Running {
                        complete(&p, job, Err(ManagedProviderClientError::ShuttingDown));
                    } else if active.contains(&job.key) || queues.contains_key(&job.key) {
                        complete(&p, job, Err(ManagedProviderClientError::Overloaded));
                    } else {
                        let key = job.key;
                        queues.entry(key).or_default().push_back(job);
                        rr.push_back(key);
                    }
                }
                Some(Command::Drain) => {}
                Some(Command::Force) | None => {
                    if let Some(p) = pool.upgrade() {
                        for (_, queue) in queues {
                            for job in queue {
                                p.counters.shutdown_forced.fetch_add(1, Ordering::Relaxed);
                                complete(&p, job, Err(ManagedProviderClientError::ShuttingDown));
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
                for job in expired {
                    complete(&p, job, Err(ManagedProviderClientError::Overloaded));
                }
            }
        }
    }
}
fn complete(
    pool: &Pool,
    job: Job,
    result: Result<ManagedProviderJobStatus, ManagedProviderClientError>,
) {
    pool.release_enqueue(job.encoded.len());
    let _ = job.reply.send(result);
}

async fn lane_worker(
    pool: Arc<Pool>,
    voter: usize,
    _lane: usize,
    mut jobs: mpsc::Receiver<Job>,
    events: mpsc::Sender<Event>,
) {
    let index = voter * pool.config.lanes_per_voter + _lane;
    let mut generation = 0_u64;
    let mut reconnect_attempt = 0_u8;
    loop {
        if matches!(Phase::load(&pool.phase), Phase::Forced | Phase::Stopped) {
            return;
        }
        let connection = connect_lane(&pool, voter).await;
        let mut connection = match connection {
            Ok(c) => {
                generation = generation.wrapping_add(1);
                reconnect_attempt = 0;
                pool.counters.connections.fetch_add(1, Ordering::Relaxed);
                high(
                    &pool.counters.connection_high_water,
                    pool.counters.connections.load(Ordering::Relaxed),
                );
                if events.send(Event::Ready(index, generation)).await.is_err() {
                    return;
                };
                c
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
        while let Some(job) = jobs.recv().await {
            if matches!(Phase::load(&pool.phase), Phase::Forced | Phase::Stopped) {
                pool.counters
                    .shutdown_forced
                    .fetch_add(1, Ordering::Relaxed);
                complete(&pool, job, Err(ManagedProviderClientError::ShuttingDown));
                continue;
            }
            if job.deadline <= tokio::time::Instant::now() {
                let key = job.key;
                complete(&pool, job, Err(ManagedProviderClientError::Overloaded));
                let _ = events.send(Event::Idle(index, generation, key)).await;
                continue;
            }
            let now = pool.counters.inflight.fetch_add(1, Ordering::Relaxed) + 1;
            high(&pool.counters.inflight_high_water, now);
            let key = job.key;
            let result =
                call_on_lane(&mut connection, &job.encoded, pool.config.response_bytes).await;
            pool.counters.inflight.fetch_sub(1, Ordering::Relaxed);
            match result {
                Ok(value) => {
                    if Phase::load(&pool.phase) == Phase::Draining {
                        pool.counters
                            .shutdown_drained
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    complete(&pool, job, value);
                    let _ = events.send(Event::Idle(index, generation, key)).await;
                }
                Err(error) => {
                    if error == ManagedProviderClientError::OutcomeUnknown {
                        pool.counters
                            .outcome_unknown
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    complete(&pool, job, Err(error));
                    // A failed lane must never advertise itself as idle. The
                    // generation-bound Lost event purges a stale idle slot.
                    let _ = events.send(Event::Lost(index, generation, Some(key))).await;
                    break;
                }
            }
        }
        pool.counters.connections.fetch_sub(1, Ordering::Relaxed);
        let _ = events.send(Event::Lost(index, generation, None)).await;
    }
}

type ClientLane = tokio_rustls::client::TlsStream<TcpStream>;
async fn connect_lane(pool: &Pool, voter: usize) -> Result<ClientLane, ManagedProviderClientError> {
    let endpoint = &pool.endpoints[voter];
    let address = tokio::time::timeout(pool.config.setup_timeout, (endpoint.resolve)())
        .await
        .map_err(|_| ManagedProviderClientError::Unavailable)?
        .map_err(|_| ManagedProviderClientError::Unavailable)?;
    let stream = tokio::time::timeout(pool.config.setup_timeout, TcpStream::connect(address))
        .await
        .map_err(|_| ManagedProviderClientError::Unavailable)?
        .map_err(|_| ManagedProviderClientError::Unavailable)?;
    stream
        .set_nodelay(true)
        .map_err(|_| ManagedProviderClientError::Unavailable)?;
    let handshake = pool
        .authority
        .tls
        .begin_handshake()
        .map_err(|_| ManagedProviderClientError::Authentication)?;
    let mut config = handshake.rustls_config().as_ref().clone();
    config.alpn_protocols = vec![MANAGED_PROVIDER_JOB_ALPN.to_vec()];
    config.resumption = tokio_rustls::rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(endpoint.server_name.clone(), stream)
        .await
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
        scope: pool.authority.scope,
        profile_digest: profile_digest(),
        request_frame_size: pool.config.request_bytes as u32,
        response_frame_size: pool.config.response_bytes as u32,
        expected_voter: endpoint.identity.as_str().to_owned(),
    });
    write_json(&mut tls, &hello, pool.config.request_bytes).await?;
    let ack: WireResponse = read_json(&mut tls, pool.config.response_bytes).await?;
    match ack {
        WireResponse::HelloAck(ack)
            if ack.transport_revision == MANAGED_PROVIDER_JOB_TRANSPORT_REVISION
                && ack.semantic_revision == MANAGED_PROVIDER_JOB_SEMANTIC_REVISION
                && ack.scope == pool.authority.scope
                && ack.profile_digest == profile_digest()
                && ack.voter_identity == endpoint.identity.as_str() =>
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
    encoded: &[u8],
    response_bound: usize,
) -> Result<Result<ManagedProviderJobStatus, ManagedProviderClientError>, ManagedProviderClientError>
{
    write_raw(connection, encoded)
        .await
        .map_err(FrameWriteError::client_error)?;
    let response: WireResponse = read_json(connection, response_bound)
        .await
        .map_err(|_| ManagedProviderClientError::OutcomeUnknown)?;
    match response {
        WireResponse::Call(result) => Ok(result.into_result()),
        _ => Err(ManagedProviderClientError::Protocol),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FrameWriteError {
    NotTransmitted,
    OutcomeUnknown,
}
impl FrameWriteError {
    const fn client_error(self) -> ManagedProviderClientError {
        match self {
            Self::NotTransmitted => ManagedProviderClientError::Unavailable,
            Self::OutcomeUnknown => ManagedProviderClientError::OutcomeUnknown,
        }
    }
}

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
async fn write_json<W: AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    value: &T,
    bound: usize,
) -> Result<(), ManagedProviderClientError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ManagedProviderClientError::Protocol)?;
    if bytes.len() > bound {
        return Err(ManagedProviderClientError::Protocol);
    }
    write_raw(writer, &bytes)
        .await
        .map_err(FrameWriteError::client_error)
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
    if unknown {
        return Err(ManagedProviderClientError::Protocol);
    }
    Ok(value)
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
    voter_identity: String,
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
            (None, Some(WireError::Unavailable)) => {
                Err(ManagedProviderClientError::ServiceUnavailable)
            }
            (None, Some(_)) => Err(ManagedProviderClientError::Protocol),
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
        if self.max_connections == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid managed provider listener",
            ));
        }
        let listener = TcpListener::bind(bind).await?;
        let address = listener.local_addr()?;
        let cancelled = Arc::new(AtomicBool::new(false));
        let tasks = Arc::new(Mutex::new(JoinSet::new()));
        let permit = Arc::new(Semaphore::new(self.max_connections));
        let cancel = Arc::clone(&cancelled);
        let accept_tasks = Arc::clone(&tasks);
        let handle = tokio::spawn(async move {
            while !cancel.load(Ordering::Acquire) {
                let Ok(slot) = permit.clone().acquire_owned().await else {
                    return;
                };
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                let service = self.service.clone();
                let tls = self.tls.clone();
                let scope = self.scope;
                let voter = self.voter.clone();
                let client = self.client.clone();
                accept_tasks.lock().await.spawn(async move {
                    let _slot = slot;
                    let _ = serve_connection(stream, service, tls, scope, voter, client).await;
                });
            }
        });
        Ok((
            ManagedProviderJobServerHandle {
                handle,
                cancelled,
                tasks,
            },
            address,
        ))
    }
}
pub struct ManagedProviderJobServerHandle {
    handle: JoinHandle<()>,
    cancelled: Arc<AtomicBool>,
    tasks: Arc<Mutex<JoinSet<()>>>,
}
impl ManagedProviderJobServerHandle {
    pub async fn shutdown(mut self) {
        self.cancelled.store(true, Ordering::Release);
        self.handle.abort();
        let _ = (&mut self.handle).await;
        self.tasks.lock().await.shutdown().await;
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
    let handshake = tls
        .begin_handshake()
        .map_err(|_| ManagedProviderClientError::Authentication)?;
    let mut config = handshake.rustls_config().as_ref().clone();
    config.alpn_protocols = vec![MANAGED_PROVIDER_JOB_ALPN.to_vec()];
    let mut stream = tokio_rustls::TlsAcceptor::from(Arc::new(config))
        .accept(stream)
        .await
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
    let hello: WireRequest =
        read_json(&mut stream, DEFAULT_MANAGED_PROVIDER_POOL_REQUEST_BYTES).await?;
    let WireRequest::Hello(hello) = hello else {
        return Err(ManagedProviderClientError::Protocol);
    };
    if hello.transport_revision != MANAGED_PROVIDER_JOB_TRANSPORT_REVISION
        || hello.semantic_revision != MANAGED_PROVIDER_JOB_SEMANTIC_REVISION
        || hello.scope != scope
        || hello.profile_digest != profile_digest()
        || hello.expected_voter != voter.as_str()
    {
        let _ = write_json(
            &mut stream,
            &WireResponse::Reject,
            DEFAULT_MANAGED_PROVIDER_POOL_RESPONSE_BYTES,
        )
        .await;
        return Err(ManagedProviderClientError::Protocol);
    }
    handshake
        .admit()
        .map_err(|_| ManagedProviderClientError::Authentication)?;
    write_json(
        &mut stream,
        &WireResponse::HelloAck(WireAck {
            transport_revision: MANAGED_PROVIDER_JOB_TRANSPORT_REVISION,
            semantic_revision: MANAGED_PROVIDER_JOB_SEMANTIC_REVISION,
            scope,
            profile_digest: profile_digest(),
            voter_identity: voter.as_str().to_owned(),
        }),
        DEFAULT_MANAGED_PROVIDER_POOL_RESPONSE_BYTES,
    )
    .await?;
    loop {
        let request: WireRequest =
            read_json(&mut stream, DEFAULT_MANAGED_PROVIDER_POOL_REQUEST_BYTES).await?;
        let WireRequest::Call { operation } = request else {
            return Err(ManagedProviderClientError::Protocol);
        };
        let response = match operation {
            WireOperation::Run {
                admission,
                protected_checkpoint,
                ordinal,
            } => match validated_admission(admission, scope, &client) {
                Ok(admission) => match FencedMutationRosterOrdinal::new(ordinal) {
                    Ok(ordinal) => result_to_wire(
                        service
                            .0
                            .run_member(admission, protected_checkpoint, ordinal)
                            .await,
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
                        Ok(ordinal) => {
                            result_to_wire(service.0.job_status(admission, ordinal).await)
                        }
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
        write_json(
            &mut stream,
            &WireResponse::Call(response),
            DEFAULT_MANAGED_PROVIDER_POOL_RESPONSE_BYTES,
        )
        .await?;
    }
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
    use std::task::{Context, Poll};

    struct FaultWriter {
        limits: VecDeque<usize>,
        flush_fails: bool,
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
    }

    #[test]
    fn profile_is_pinned_to_the_exact_v5_revisions() {
        assert_eq!(MANAGED_PROVIDER_JOB_ALPN, b"opc-session-consumer/5");
        assert_eq!(MANAGED_PROVIDER_JOB_TRANSPORT_REVISION, 7);
        assert_eq!(MANAGED_PROVIDER_JOB_SEMANTIC_REVISION, 5);
        assert_ne!(profile_digest(), [0; 32]);
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
}
