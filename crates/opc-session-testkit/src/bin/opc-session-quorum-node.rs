//! Private child-process node for experimental session-HA qualification.

use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use futures_util::stream::BoxStream;
use futures_util::StreamExt;
use opc_identity::ProjectedSvidSource;
use opc_key::{KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing, AES_256_GCM_SIV_KEY_LEN};
use opc_redaction::metrics::{SecurityMetricsReader, METRICS};
use opc_session_net::{
    ConnectionLifecyclePolicy, LocalReplicaBinding, RemoteAddrResolver, RemoteSessionConsensusPeer,
    SessionClusterId, SessionConfigurationEpoch, SessionConfigurationGeneration,
    SessionConsensusServer, SessionConsensusServerHandle, SessionReauthenticationControl,
    SessionReplicationManifest,
};
use opc_session_store::{
    CompareAndSet, CompareAndSetResult, ConsensusSessionStore, EncryptedSessionPayload,
    EncryptingSessionBackend, FenceToken, Generation, LeaseError, LeaseGuard, OwnerId,
    QuorumReplicaDescriptor, QuorumTopologyConfig, ReplicaBackingIdentity, ReplicaEndpoint,
    ReplicaFailureDomain, ReplicaId, ReplicaTlsIdentity, ReplicationEntry, ReplicationOp,
    RestoreScanCursorProfile, RestoreScanRequest, SessionBackend, SessionConsensusIdentity,
    SessionConsensusNodeId, SessionConsensusPeer, SessionConsensusPeerError,
    SessionConsensusRpcFamily, SessionConsensusRpcHandler, SessionConsensusWireRequest,
    SessionConsensusWireResponse, SessionKey, SessionKeyType, SessionLeaseManager,
    SqliteSessionBackend, StateClass, StateType, StoreError, StoredSessionRecord,
    ValidatedQuorumTopology,
};
use opc_session_testkit::qualification::{
    qualification_owner_sha256, qualification_traffic_schedule_sha256, qualification_traffic_seed,
    qualification_traffic_value, qualification_value_sha256, read_bounded_json_line,
    write_json_line, QualificationConnectionLifecycleMetrics,
    QualificationConsensusRpcAvailability, QualificationNodeCommand, QualificationNodeConfig,
    QualificationNodeErrorCode, QualificationNodeReply, QualificationPeerRouting,
    QualificationProjectedSvidStatus, QualificationReadinessCode,
    QualificationSecurityMetricsSnapshot, QualificationTlsMaterialStatus,
    QualificationTrafficErrorClass, QualificationTrafficFailureCode,
    QualificationTrafficFailureStage, QualificationTrafficState, QualificationTrafficStatus,
    QualificationTransportConfig, QUALIFICATION_FAULT_MUTATION_SHUTDOWN_LEAD_MILLIS,
    QUALIFICATION_INBOUND_CONNECTION_SLOTS, QUALIFICATION_MAX_CONFIG_BYTES,
    QUALIFICATION_MAX_LEASE_HANDLES,
    QUALIFICATION_TRAFFIC_AVAILABILITY_INTERRUPTION_BUDGET_PER_NODE,
    QUALIFICATION_TRAFFIC_AVAILABILITY_RECOVERY_MILLIS,
    QUALIFICATION_TRAFFIC_AVAILABILITY_RETRY_MILLIS,
    QUALIFICATION_TRAFFIC_MUTATION_DELAY_MIN_MILLIS,
    QUALIFICATION_TRAFFIC_MUTATION_DELAY_SPAN_MILLIS, QUALIFICATION_TRAFFIC_RESTORE_LIMIT,
    QUALIFICATION_TRAFFIC_TTL_MILLIS, QUALIFICATION_TRAFFIC_WATCH_RECONCILIATION_MAX_ENTRIES,
    QUALIFICATION_TRAFFIC_WATCH_RECONCILIATION_MILLIS,
    QUALIFICATION_TRAFFIC_WATCH_RECONCILIATION_PAGE_ENTRIES,
};
use opc_tls::{
    AuthenticatedClientConfig, AuthenticatedServerConfig, TlsConfigBuilder, TlsMaterialController,
};
use opc_types::{NetworkFunctionKind, SpiffeId, TenantId};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

const QUALIFICATION_TENANT: &str = "session-ha-qualification";
const QUALIFICATION_KEY_ID: &str = "session-ha-qualification-key-v1";
const QUALIFICATION_STATE_TYPE: &str = "session-ha-qualification-state";
const QUALIFICATION_TRAFFIC_STATE_TYPE: &str = "session-ha-qualification-traffic-state";
const QUALIFICATION_TRAFFIC_TTL: Duration = Duration::from_millis(QUALIFICATION_TRAFFIC_TTL_MILLIS);
const QUALIFICATION_KEY_BYTES: [u8; AES_256_GCM_SIV_KEY_LEN] = [0x5a; AES_256_GCM_SIV_KEY_LEN];

type ProtectedStore = EncryptingSessionBackend<ConsensusSessionStore, MemoryKeyProvider>;

struct QualificationLease {
    guard: LeaseGuard,
    released: bool,
}

#[derive(Debug, thiserror::Error)]
#[error("qualification node failed")]
struct NodeFailure;

#[derive(Debug, Clone, Copy)]
enum QualificationNodeOpenStage {
    Transport,
    Sqlite,
    Consensus,
    Listener,
}

fn node_open_failure(stage: QualificationNodeOpenStage) -> NodeFailure {
    let stage = match stage {
        QualificationNodeOpenStage::Transport => "transport",
        QualificationNodeOpenStage::Sqlite => "sqlite",
        QualificationNodeOpenStage::Consensus => "consensus",
        QualificationNodeOpenStage::Listener => "listener",
    };
    eprintln!("qualification node open failed: {stage}");
    NodeFailure
}

#[derive(Clone)]
struct QualificationConsensusRpcGate {
    available: Arc<AtomicBool>,
}

impl QualificationConsensusRpcGate {
    fn available() -> Self {
        Self {
            available: Arc::new(AtomicBool::new(true)),
        }
    }

    fn set(&self, availability: QualificationConsensusRpcAvailability) {
        self.available.store(
            matches!(
                availability,
                QualificationConsensusRpcAvailability::Available
            ),
            Ordering::SeqCst,
        );
    }

    fn availability(&self) -> QualificationConsensusRpcAvailability {
        if self.available.load(Ordering::SeqCst) {
            QualificationConsensusRpcAvailability::Available
        } else {
            QualificationConsensusRpcAvailability::Unavailable
        }
    }

    fn permits_rpc(&self) -> bool {
        matches!(
            self.availability(),
            QualificationConsensusRpcAvailability::Available
        )
    }
}

impl std::fmt::Debug for QualificationConsensusRpcGate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QualificationConsensusRpcGate")
            .field("availability", &self.availability())
            .finish()
    }
}

#[derive(Clone)]
struct QualificationGatedConsensusPeer {
    inner: Arc<dyn SessionConsensusPeer>,
    gate: QualificationConsensusRpcGate,
}

impl QualificationGatedConsensusPeer {
    fn new(inner: Arc<dyn SessionConsensusPeer>, gate: QualificationConsensusRpcGate) -> Self {
        Self { inner, gate }
    }
}

impl std::fmt::Debug for QualificationGatedConsensusPeer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QualificationGatedConsensusPeer")
            .field("availability", &self.gate.availability())
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl SessionConsensusPeer for QualificationGatedConsensusPeer {
    fn node_id(&self) -> SessionConsensusNodeId {
        self.inner.node_id()
    }

    async fn call(
        &self,
        request: SessionConsensusWireRequest,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        if !self.gate.permits_rpc() {
            return Err(SessionConsensusPeerError::Unavailable);
        }
        self.inner.call(request).await
    }

    async fn call_with_timeout(
        &self,
        request: SessionConsensusWireRequest,
        timeout: Duration,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        if !self.gate.permits_rpc() {
            return Err(SessionConsensusPeerError::Unavailable);
        }
        self.inner.call_with_timeout(request, timeout).await
    }
}

struct QualificationGatedConsensusRpcHandler {
    inner: Arc<dyn SessionConsensusRpcHandler>,
    gate: QualificationConsensusRpcGate,
}

impl std::fmt::Debug for QualificationGatedConsensusRpcHandler {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QualificationGatedConsensusRpcHandler")
            .field("availability", &self.gate.availability())
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl SessionConsensusRpcHandler for QualificationGatedConsensusRpcHandler {
    async fn handle(
        &self,
        authenticated_sender: SessionConsensusNodeId,
        request: SessionConsensusWireRequest,
    ) -> SessionConsensusWireResponse {
        if !self.gate.permits_rpc() {
            return SessionConsensusWireResponse {
                result: Err(SessionConsensusPeerError::Unavailable),
            };
        }
        self.inner.handle(authenticated_sender, request).await
    }
}

#[derive(Debug)]
struct QualificationProbeDispatchCountingHandler {
    inner: Arc<dyn SessionConsensusRpcHandler>,
    empty_vote_dispatches: Arc<AtomicU64>,
}

#[async_trait::async_trait]
impl SessionConsensusRpcHandler for QualificationProbeDispatchCountingHandler {
    async fn handle(
        &self,
        authenticated_sender: SessionConsensusNodeId,
        request: SessionConsensusWireRequest,
    ) -> SessionConsensusWireResponse {
        if request.family == SessionConsensusRpcFamily::Vote && request.payload.is_empty() {
            self.empty_vote_dispatches.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.handle(authenticated_sender, request).await
    }
}

struct QualificationNode {
    store: Arc<ConsensusSessionStore>,
    protected: ProtectedStore,
    server: Option<SessionConsensusServerHandle>,
    transport: QualificationTransportRuntime,
    leases: HashMap<String, QualificationLease>,
    node_index: usize,
    member_count: usize,
    traffic_schedule_bound: bool,
    traffic: Option<QualificationTrafficRuntime>,
    empty_vote_dispatches: Arc<AtomicU64>,
    rpc_gate: QualificationConsensusRpcGate,
}

struct QualificationTrafficRuntime {
    seed: u64,
    observation: Arc<QualificationTrafficObservation>,
    mutation_started: bool,
    mutation_cancel: Option<oneshot::Sender<tokio::time::Instant>>,
    mutation_task: Option<JoinHandle<Result<(), QualificationTrafficFailure>>>,
    watch_cancel: Option<oneshot::Sender<()>>,
    watch_task: Option<JoinHandle<Result<(), QualificationTrafficFailure>>>,
}

struct QualificationTrafficObservation {
    failure: OnceLock<QualificationTrafficFailure>,
    mutation_cycles: AtomicU64,
    linearizable_reads: AtomicU64,
    lease_renewals: AtomicU64,
    lease_reacquisitions: AtomicU64,
    availability_interruptions: AtomicU64,
    availability_recoveries: AtomicU64,
    max_consecutive_availability_interruptions: AtomicU64,
    synthetic_release_response_loss_pending: AtomicBool,
    complete_restore_scans: AtomicU64,
    durable_readiness_probes: AtomicU64,
    mutation_resume_generation: AtomicU64,
    mutation_resume_record_fence: AtomicU64,
    last_generation: AtomicU64,
    last_record_fence: AtomicU64,
    watch_entries: AtomicU64,
    watch_applied_records: AtomicU64,
    watch_sequence: AtomicU64,
    last_authoritative_replication_head: AtomicU64,
    watch_reconciliations: AtomicU64,
    watch_reconciled_sequence: AtomicU64,
    watch_traffic_generations: Vec<AtomicU64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct QualificationTrafficFailure {
    code: QualificationTrafficFailureCode,
    stage: QualificationTrafficFailureStage,
    error_class: QualificationTrafficErrorClass,
    recovery_elapsed_millis: Option<u64>,
}

impl QualificationTrafficFailure {
    const fn fixed(
        code: QualificationTrafficFailureCode,
        stage: QualificationTrafficFailureStage,
    ) -> Self {
        Self {
            code,
            stage,
            error_class: QualificationTrafficErrorClass::Other,
            recovery_elapsed_millis: None,
        }
    }

    fn store(
        code: QualificationTrafficFailureCode,
        stage: QualificationTrafficFailureStage,
        error: &StoreError,
    ) -> Self {
        Self {
            code,
            stage,
            error_class: qualification_store_error_class(error),
            recovery_elapsed_millis: None,
        }
    }

    fn lease(
        code: QualificationTrafficFailureCode,
        stage: QualificationTrafficFailureStage,
        error: &LeaseError,
    ) -> Self {
        Self {
            code,
            stage,
            error_class: qualification_lease_error_class(error),
            recovery_elapsed_millis: None,
        }
    }

    const fn backend_unavailable(
        code: QualificationTrafficFailureCode,
        stage: QualificationTrafficFailureStage,
    ) -> Self {
        Self {
            code,
            stage,
            error_class: QualificationTrafficErrorClass::BackendUnavailable,
            recovery_elapsed_millis: None,
        }
    }

    fn recovery_deadline_exceeded(
        stage: QualificationTrafficFailureStage,
        recovery_started_at: tokio::time::Instant,
    ) -> Self {
        Self::recovery_deadline_exceeded_at(stage, recovery_started_at, tokio::time::Instant::now())
    }

    fn recovery_deadline_exceeded_at(
        stage: QualificationTrafficFailureStage,
        recovery_started_at: tokio::time::Instant,
        observed_at: tokio::time::Instant,
    ) -> Self {
        let elapsed_millis = u64::try_from(
            observed_at
                .saturating_duration_since(recovery_started_at)
                .as_millis(),
        )
        .unwrap_or(u64::MAX);
        Self {
            code: QualificationTrafficFailureCode::AvailabilityRecoveryDeadlineExceeded,
            stage,
            error_class: QualificationTrafficErrorClass::BackendUnavailable,
            recovery_elapsed_millis: Some(elapsed_millis),
        }
    }
}

impl QualificationTrafficObservation {
    fn new(initial_watch_sequence: u64, member_count: usize) -> Self {
        Self {
            failure: OnceLock::new(),
            mutation_cycles: AtomicU64::new(0),
            linearizable_reads: AtomicU64::new(0),
            lease_renewals: AtomicU64::new(0),
            lease_reacquisitions: AtomicU64::new(0),
            availability_interruptions: AtomicU64::new(0),
            availability_recoveries: AtomicU64::new(0),
            max_consecutive_availability_interruptions: AtomicU64::new(0),
            synthetic_release_response_loss_pending: AtomicBool::new(true),
            complete_restore_scans: AtomicU64::new(0),
            durable_readiness_probes: AtomicU64::new(0),
            mutation_resume_generation: AtomicU64::new(0),
            mutation_resume_record_fence: AtomicU64::new(0),
            last_generation: AtomicU64::new(0),
            last_record_fence: AtomicU64::new(0),
            watch_entries: AtomicU64::new(0),
            watch_applied_records: AtomicU64::new(0),
            watch_sequence: AtomicU64::new(initial_watch_sequence),
            last_authoritative_replication_head: AtomicU64::new(initial_watch_sequence),
            watch_reconciliations: AtomicU64::new(0),
            watch_reconciled_sequence: AtomicU64::new(0),
            watch_traffic_generations: (0..member_count).map(|_| AtomicU64::new(0)).collect(),
        }
    }

    fn record_failure(&self, failure: QualificationTrafficFailure) {
        let _ = self.failure.set(failure);
    }

    fn failure(&self) -> Option<QualificationTrafficFailure> {
        self.failure.get().copied()
    }

    fn record_authoritative_replication_head(&self, head: u64) {
        self.last_authoritative_replication_head
            .store(head, Ordering::Release);
    }

    fn record_mutation_resume(&self, generation: u64, record_fence: u64) {
        self.mutation_resume_generation
            .store(generation, Ordering::Release);
        self.mutation_resume_record_fence
            .store(record_fence, Ordering::Release);
        self.last_generation.store(generation, Ordering::Release);
        self.last_record_fence
            .store(record_fence, Ordering::Release);
        if generation != 0 {
            self.synthetic_release_response_loss_pending
                .store(false, Ordering::Release);
        }
    }

    fn authoritative_replication_head(&self) -> u64 {
        self.last_authoritative_replication_head
            .load(Ordering::Acquire)
    }

    fn record_availability_interruption(&self, consecutive: &mut u64) -> bool {
        if self
            .availability_interruptions
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1).filter(|next| {
                    *next <= QUALIFICATION_TRAFFIC_AVAILABILITY_INTERRUPTION_BUDGET_PER_NODE
                })
            })
            .is_err()
        {
            return false;
        }
        *consecutive = consecutive.saturating_add(1);
        let _ = self
            .max_consecutive_availability_interruptions
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                Some(current.max(*consecutive))
            });
        true
    }

    fn record_availability_recovery(&self, consecutive: &mut u64) {
        let recovered = *consecutive;
        let _ = self.availability_recoveries.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |value| Some(value.saturating_add(recovered)),
        );
        *consecutive = 0;
    }
}

fn traffic_failure_is_recoverable(failure: QualificationTrafficFailure) -> bool {
    failure.code != QualificationTrafficFailureCode::AvailabilityRecoveryDeadlineExceeded
        && matches!(
            failure.error_class,
            QualificationTrafficErrorClass::BackendUnavailable
                | QualificationTrafficErrorClass::CasIdempotencyOutcomeUnavailable
                | QualificationTrafficErrorClass::BackendOperationOutcomeUnavailable
        )
}

// These checkpoints occur only after renew and CAS have returned terminal
// success. Their availability outcome cannot make lease or record authority
// ambiguous, so recovery must not mint a replacement fence unnecessarily.
fn traffic_failure_retains_known_authority(failure: QualificationTrafficFailure) -> bool {
    traffic_failure_is_recoverable(failure)
        && matches!(
            failure.stage,
            QualificationTrafficFailureStage::Get
                | QualificationTrafficFailureStage::RestoreScan
                | QualificationTrafficFailureStage::ReadinessProbe
        )
}

fn qualification_store_error_class(error: &StoreError) -> QualificationTrafficErrorClass {
    match error {
        StoreError::BackendUnavailable(_) => QualificationTrafficErrorClass::BackendUnavailable,
        StoreError::CasIdempotencyOutcomeUnavailable => {
            QualificationTrafficErrorClass::CasIdempotencyOutcomeUnavailable
        }
        StoreError::BackendOperationOutcomeUnavailable => {
            QualificationTrafficErrorClass::BackendOperationOutcomeUnavailable
        }
        StoreError::NotFound
        | StoreError::StaleFence
        | StoreError::InvalidKey(_)
        | StoreError::InvalidSessionTtl
        | StoreError::LeaseHeld
        | StoreError::LeaseExpired => QualificationTrafficErrorClass::LeaseLostOrInvalid,
        _ => QualificationTrafficErrorClass::Other,
    }
}

fn qualification_lease_error_class(error: &LeaseError) -> QualificationTrafficErrorClass {
    match error {
        LeaseError::OperationOutcomeUnavailable => {
            QualificationTrafficErrorClass::BackendOperationOutcomeUnavailable
        }
        LeaseError::Backend(_) => QualificationTrafficErrorClass::BackendUnavailable,
        LeaseError::AlreadyHeld
        | LeaseError::Expired
        | LeaseError::StaleFence
        | LeaseError::NotFound
        | LeaseError::InvalidSessionTtl => QualificationTrafficErrorClass::LeaseLostOrInvalid,
    }
}

fn increment(counter: &AtomicU64) {
    let _ = counter.fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
        Some(value.saturating_add(1))
    });
}

enum QualificationTransportRuntime {
    #[cfg_attr(not(feature = "foundation-insecure"), allow(dead_code))]
    FoundationPlaintext,
    ProjectedMtls(Box<QualificationProjectedMtlsRuntime>),
}

struct QualificationProjectedMtlsRuntime {
    source: ProjectedSvidSource,
    client_config: AuthenticatedClientConfig,
    reauthentication: SessionReauthenticationControl,
    directed_peers: BTreeMap<usize, QualificationDirectedPeer>,
    consensus_identity: SessionConsensusIdentity,
    local_node_id: SessionConsensusNodeId,
}

struct QualificationDirectedPeer {
    peer: QualificationGatedConsensusPeer,
    resolver_evidence: QualificationResolverEvidence,
    required_resolution: Option<QualificationRequiredResolution>,
}

#[derive(Clone)]
struct QualificationResolverEvidence {
    calls: Arc<AtomicU64>,
    last_reauthentication_generation: Arc<AtomicU64>,
}

#[derive(Clone, Copy)]
struct QualificationRequiredResolution {
    calls_before_request: u64,
    reauthentication_generation: u64,
}

impl QualificationResolverEvidence {
    fn new() -> Self {
        Self {
            calls: Arc::new(AtomicU64::new(0)),
            last_reauthentication_generation: Arc::new(AtomicU64::new(0)),
        }
    }

    fn record_resolution(&self, reauthentication_generation: u64) {
        self.last_reauthentication_generation
            .store(reauthentication_generation, Ordering::SeqCst);
        let _ = self
            .calls
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |calls| {
                Some(calls.saturating_add(1))
            });
    }

    fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }

    fn proves(&self, required: QualificationRequiredResolution) -> bool {
        self.calls() > required.calls_before_request
            && self.last_reauthentication_generation.load(Ordering::SeqCst)
                >= required.reauthentication_generation
    }
}

enum QualificationServerTransport {
    #[cfg(feature = "foundation-insecure")]
    FoundationPlaintext,
    ProjectedMtls(Box<QualificationProjectedMtlsServerTransport>),
}

struct QualificationProjectedMtlsServerTransport {
    server_config: AuthenticatedServerConfig,
    lifecycle: ConnectionLifecyclePolicy,
    reauthentication: SessionReauthenticationControl,
}

impl QualificationNode {
    async fn open(
        config: &QualificationNodeConfig,
        listener: TcpListener,
    ) -> Result<Self, NodeFailure> {
        secure_qualification_paths(config)?;
        config
            .validate_bind_addr(listener.local_addr().map_err(|_| NodeFailure)?)
            .map_err(|_| NodeFailure)?;
        let descriptors = config
            .members
            .iter()
            .map(|member| {
                Ok(QuorumReplicaDescriptor::new(
                    ReplicaId::new(member.replica_id.clone()).map_err(|_| NodeFailure)?,
                    ReplicaEndpoint::new(member.endpoint_host.clone(), member.endpoint_port)
                        .map_err(|_| NodeFailure)?,
                    ReplicaTlsIdentity::new(member.tls_identity.clone())
                        .map_err(|_| NodeFailure)?,
                    ReplicaFailureDomain::new(member.failure_domain.clone())
                        .map_err(|_| NodeFailure)?,
                    ReplicaBackingIdentity::new(member.backing_identity.clone())
                        .map_err(|_| NodeFailure)?,
                ))
            })
            .collect::<Result<Vec<_>, NodeFailure>>()?;
        let manifest = Arc::new(
            SessionReplicationManifest::try_new_with_epoch(
                SessionClusterId::new(config.cluster_id.clone()).map_err(|_| NodeFailure)?,
                SessionConfigurationGeneration::new(config.configuration_generation.clone())
                    .map_err(|_| NodeFailure)?,
                SessionConfigurationEpoch::new(config.configuration_epoch)
                    .map_err(|_| NodeFailure)?,
                descriptors.clone(),
            )
            .map_err(|_| NodeFailure)?,
        );
        let local_replica = ReplicaId::new(config.members[config.node_index].replica_id.clone())
            .map_err(|_| NodeFailure)?;
        let local_binding = manifest
            .bind_local(local_replica.clone())
            .map_err(|_| NodeFailure)?;
        let topology = ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new_consensus(
            local_replica,
            descriptors,
            manifest.consensus_identity(),
        ))
        .map_err(|_| NodeFailure)?;
        let rpc_gate = QualificationConsensusRpcGate::available();
        let (peers, server_transport, transport) = prepare_transport(
            config,
            &local_binding,
            manifest.consensus_identity(),
            rpc_gate.clone(),
        )
        .await
        .map_err(|_| node_open_failure(QualificationNodeOpenStage::Transport))?;

        let backend = SqliteSessionBackend::open(&config.database_path)
            .map_err(|_| node_open_failure(QualificationNodeOpenStage::Sqlite))?;
        let store = Arc::new(
            ConsensusSessionStore::open_with_operation_timeout(
                topology,
                backend,
                &config.snapshot_directory,
                peers,
                Duration::from_millis(config.operation_timeout_millis),
            )
            .await
            .map_err(|_| node_open_failure(QualificationNodeOpenStage::Consensus))?,
        );
        let empty_vote_dispatches = Arc::new(AtomicU64::new(0));
        let counting_handler: Arc<dyn SessionConsensusRpcHandler> =
            Arc::new(QualificationProbeDispatchCountingHandler {
                inner: store.rpc_handler(),
                empty_vote_dispatches: Arc::clone(&empty_vote_dispatches),
            });
        let handler: Arc<dyn SessionConsensusRpcHandler> =
            Arc::new(QualificationGatedConsensusRpcHandler {
                inner: counting_handler,
                gate: rpc_gate.clone(),
            });
        let server = match server_transport {
            #[cfg(feature = "foundation-insecure")]
            QualificationServerTransport::FoundationPlaintext => {
                SessionConsensusServer::new_insecure(handler, local_binding)
            }
            QualificationServerTransport::ProjectedMtls(transport) => {
                SessionConsensusServer::new(handler, transport.server_config, local_binding)
                    .with_connection_lifecycle(transport.lifecycle)
                    .with_reauthentication_control(transport.reauthentication)
            }
        }
        .with_max_connections(QUALIFICATION_INBOUND_CONNECTION_SLOTS);
        let (server, actual_addr) = server
            .listen_on(listener)
            .await
            .map_err(|_| node_open_failure(QualificationNodeOpenStage::Listener))?;
        if config.validate_bind_addr(actual_addr).is_err() {
            server.abort_and_wait().await;
            return Err(NodeFailure);
        }

        let provider = Arc::new(MemoryKeyProvider::new());
        provider
            .insert_active_key(
                KeyId::new(QUALIFICATION_KEY_ID).map_err(|_| NodeFailure)?,
                KeyPurpose::Session,
                TenantId::new(QUALIFICATION_TENANT).map_err(|_| NodeFailure)?,
                Zeroizing::new(QUALIFICATION_KEY_BYTES),
            )
            .map_err(|_| NodeFailure)?;
        let protected = EncryptingSessionBackend::new(
            Arc::clone(&store),
            provider,
            config.backend_namespace.clone(),
        );
        Ok(Self {
            store,
            protected,
            server: Some(server),
            transport,
            leases: HashMap::new(),
            node_index: config.node_index,
            member_count: config.members.len(),
            traffic_schedule_bound: qualification_traffic_schedule_sha256(config.members.len())
                .is_some_and(|digest| digest == config.workload_schedule_sha256),
            traffic: None,
            empty_vote_dispatches,
            rpc_gate,
        })
    }

    async fn handle(&mut self, command: QualificationNodeCommand) -> QualificationNodeReply {
        match command {
            QualificationNodeCommand::Configure => QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::InvalidRequest,
            },
            QualificationNodeCommand::Initialize => match self.store.initialize_cluster().await {
                Ok(()) => QualificationNodeReply::Initialized,
                Err(_) => QualificationNodeReply::Error {
                    code: QualificationNodeErrorCode::InitializationUnavailable,
                },
            },
            QualificationNodeCommand::Probe => self.probe().await,
            QualificationNodeCommand::ProjectedSourceStatus => self.projected_source_status(),
            QualificationNodeCommand::MaterialStatus => self.material_status(),
            QualificationNodeCommand::ReauthenticationGeneration => {
                self.reauthentication_generation()
            }
            QualificationNodeCommand::RequestReauthentication => self.request_reauthentication(),
            QualificationNodeCommand::DirectedHandshake { remote_node_index } => {
                self.directed_handshake(remote_node_index).await
            }
            QualificationNodeCommand::LifecycleMetrics => {
                QualificationNodeReply::LifecycleMetrics {
                    metrics: lifecycle_metrics(self.empty_vote_dispatches.load(Ordering::SeqCst)),
                }
            }
            QualificationNodeCommand::SetConsensusRpcAvailability { availability } => {
                self.rpc_gate.set(availability);
                QualificationNodeReply::ConsensusRpcAvailability {
                    availability: self.rpc_gate.availability(),
                }
            }
            QualificationNodeCommand::SecurityMetrics => QualificationNodeReply::SecurityMetrics {
                metrics: QualificationSecurityMetricsSnapshot::from(
                    SecurityMetricsReader::global().snapshot(),
                ),
            },
            QualificationNodeCommand::StartTrafficWatch => self.start_traffic_watch().await,
            QualificationNodeCommand::ReconcileTrafficWatch => self.reconcile_traffic_watch().await,
            QualificationNodeCommand::StartTrafficMutation => self.start_traffic_mutation().await,
            QualificationNodeCommand::StopTrafficMutation => self.stop_traffic_mutation().await,
            QualificationNodeCommand::StopTrafficWatch => self.stop_traffic_watch().await,
            QualificationNodeCommand::TrafficStatus => self.traffic_status().await,
            QualificationNodeCommand::TrafficStatusSnapshot => self.traffic_status_snapshot(),
            QualificationNodeCommand::Acquire {
                lease_handle,
                stable_id,
                owner,
                ttl_millis,
            } => {
                if let Err(code) = validate_new_lease_handle(&self.leases, &lease_handle) {
                    return QualificationNodeReply::Error { code };
                }
                let key = match qualification_key(&stable_id) {
                    Ok(key) => key,
                    Err(()) => {
                        return QualificationNodeReply::Error {
                            code: QualificationNodeErrorCode::InvalidRequest,
                        }
                    }
                };
                let owner = match OwnerId::new(owner) {
                    Ok(owner) => owner,
                    Err(_) => {
                        return QualificationNodeReply::Error {
                            code: QualificationNodeErrorCode::InvalidRequest,
                        }
                    }
                };
                match self
                    .protected
                    .acquire(&key, owner, Duration::from_millis(ttl_millis))
                    .await
                {
                    Ok(lease) => {
                        let fence = lease.fence().get();
                        self.leases.insert(
                            lease_handle,
                            QualificationLease {
                                guard: lease,
                                released: false,
                            },
                        );
                        QualificationNodeReply::LeaseAcquired { fence }
                    }
                    Err(error) => QualificationNodeReply::Error {
                        code: map_lease_error(&error),
                    },
                }
            }
            QualificationNodeCommand::CompareAndSet {
                lease_handle,
                stable_id,
                expected_generation,
                new_generation,
                value,
            } => {
                let Some(lease) = self
                    .leases
                    .get(&lease_handle)
                    .map(|lease| lease.guard.clone())
                else {
                    return QualificationNodeReply::Error {
                        code: QualificationNodeErrorCode::LeaseHandleMissing,
                    };
                };
                let key = match qualification_key(&stable_id) {
                    Ok(key) => key,
                    Err(()) => {
                        return QualificationNodeReply::Error {
                            code: QualificationNodeErrorCode::InvalidRequest,
                        }
                    }
                };
                let record = StoredSessionRecord {
                    key: key.clone(),
                    generation: Generation::new(new_generation),
                    owner: lease.owner().clone(),
                    fence: lease.fence(),
                    state_class: StateClass::AuthoritativeSession,
                    state_type: StateType::from_static(QUALIFICATION_STATE_TYPE),
                    expires_at: None,
                    payload: EncryptedSessionPayload::new(value.as_bytes()),
                };
                match self
                    .protected
                    .compare_and_set(CompareAndSet {
                        key,
                        lease,
                        expected_generation: expected_generation.map(Generation::new),
                        new_record: record,
                    })
                    .await
                {
                    Ok(CompareAndSetResult::Success) => QualificationNodeReply::CompareAndSet {
                        applied: true,
                        current_generation: Some(new_generation),
                    },
                    Ok(CompareAndSetResult::Conflict { current }) => {
                        QualificationNodeReply::CompareAndSet {
                            applied: false,
                            current_generation: current.map(|record| record.generation.get()),
                        }
                    }
                    Err(error) => QualificationNodeReply::Error {
                        code: map_store_error(&error),
                    },
                }
            }
            QualificationNodeCommand::Get { stable_id } => {
                let key = match qualification_key(&stable_id) {
                    Ok(key) => key,
                    Err(()) => {
                        return QualificationNodeReply::Error {
                            code: QualificationNodeErrorCode::InvalidRequest,
                        }
                    }
                };
                match self.protected.get(&key).await {
                    Ok(Some(record)) => QualificationNodeReply::Record {
                        present: true,
                        generation: Some(record.generation.get()),
                        owner_sha256: Some(qualification_owner_sha256(record.owner.as_str())),
                        fence: Some(record.fence.get()),
                        value_sha256: Some(qualification_value_sha256(record.payload.as_bytes())),
                    },
                    Ok(None) => QualificationNodeReply::Record {
                        present: false,
                        generation: None,
                        owner_sha256: None,
                        fence: None,
                        value_sha256: None,
                    },
                    Err(_) => QualificationNodeReply::Error {
                        code: QualificationNodeErrorCode::BackendUnavailable,
                    },
                }
            }
            QualificationNodeCommand::Release { lease_handle } => {
                let Some(lease) = self
                    .leases
                    .get(&lease_handle)
                    .filter(|lease| !lease.released)
                    .map(|lease| lease.guard.clone())
                else {
                    return QualificationNodeReply::Error {
                        code: QualificationNodeErrorCode::LeaseHandleMissing,
                    };
                };
                match self.protected.release(lease).await {
                    Ok(()) => {
                        if let Some(lease) = self.leases.get_mut(&lease_handle) {
                            mark_released_lease(&mut lease.released, true);
                        }
                        QualificationNodeReply::Released
                    }
                    Err(error) => QualificationNodeReply::Error {
                        code: map_lease_error(&error),
                    },
                }
            }
            QualificationNodeCommand::Shutdown => QualificationNodeReply::ShuttingDown,
        }
    }

    async fn start_traffic_watch(&mut self) -> QualificationNodeReply {
        if self.traffic.is_some() || !self.traffic_schedule_bound {
            return QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::TrafficUnavailable,
            };
        }
        let Some(seed) = qualification_traffic_seed(self.member_count) else {
            return QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::TrafficUnavailable,
            };
        };
        let initial_head = match self.protected.max_replication_sequence().await {
            Ok(head) => head,
            Err(_) => {
                return QualificationNodeReply::Error {
                    code: QualificationNodeErrorCode::TrafficUnavailable,
                }
            }
        };
        let Some(watch_start) = initial_head.checked_add(1) else {
            return QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::TrafficUnavailable,
            };
        };
        let stream = match self.protected.watch(watch_start).await {
            Ok(stream) => stream,
            Err(_) => {
                return QualificationNodeReply::Error {
                    code: QualificationNodeErrorCode::TrafficUnavailable,
                };
            }
        };

        let observation = Arc::new(QualificationTrafficObservation::new(
            initial_head,
            self.member_count,
        ));
        let (watch_cancel, watch_cancel_rx) = oneshot::channel();
        let watch_task = tokio::spawn(run_traffic_watch_task(
            stream,
            watch_start,
            self.member_count,
            watch_cancel_rx,
            Arc::clone(&observation),
        ));
        self.traffic = Some(QualificationTrafficRuntime {
            seed,
            observation,
            mutation_started: false,
            mutation_cancel: None,
            mutation_task: None,
            watch_cancel: Some(watch_cancel),
            watch_task: Some(watch_task),
        });
        self.traffic_status().await
    }

    async fn reconcile_traffic_watch(&mut self) -> QualificationNodeReply {
        if !self.traffic_schedule_bound
            || self.traffic.as_ref().is_some_and(|traffic| {
                traffic.mutation_cancel.is_some()
                    || traffic.mutation_task.is_some()
                    || traffic.watch_cancel.is_some()
                    || traffic.watch_task.is_some()
                    || traffic.observation.failure().is_some()
            })
        {
            return QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::TrafficUnavailable,
            };
        }
        let Some(seed) = qualification_traffic_seed(self.member_count) else {
            return QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::TrafficUnavailable,
            };
        };
        let traffic_keys = match (0..self.member_count)
            .map(qualification_traffic_key)
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(keys) => keys,
            Err(()) => {
                return QualificationNodeReply::Error {
                    code: QualificationNodeErrorCode::TrafficUnavailable,
                }
            }
        };
        let existing_observation = self
            .traffic
            .as_ref()
            .map(|traffic| Arc::clone(&traffic.observation));
        let process_restart = existing_observation.is_none();
        let mut reconciled_sequence = existing_observation.as_ref().map_or(0, |observation| {
            observation.watch_sequence.load(Ordering::Acquire)
        });
        let mut reconciled_generations = existing_observation.as_ref().map_or_else(
            || vec![0; self.member_count],
            |observation| {
                observation
                    .watch_traffic_generations
                    .iter()
                    .map(|generation| generation.load(Ordering::Acquire))
                    .collect()
            },
        );
        let mut reconciled_record_fences = vec![0; self.member_count];
        if let Some(observation) = &existing_observation {
            reconciled_record_fences[self.node_index] =
                observation.last_record_fence.load(Ordering::Acquire);
        }
        let deadline = tokio::time::Instant::now()
            + Duration::from_millis(QUALIFICATION_TRAFFIC_WATCH_RECONCILIATION_MILLIS);
        let mut reconciled_entries = 0_u64;
        let (stream, watch_start, reconciled_head) = loop {
            if tokio::time::Instant::now() >= deadline {
                return QualificationNodeReply::Error {
                    code: QualificationNodeErrorCode::TrafficUnavailable,
                };
            }
            let head =
                match tokio::time::timeout_at(deadline, self.protected.max_replication_sequence())
                    .await
                {
                    Ok(Ok(head)) if head >= reconciled_sequence => head,
                    Ok(Ok(_)) | Ok(Err(_)) | Err(_) => {
                        return QualificationNodeReply::Error {
                            code: QualificationNodeErrorCode::TrafficUnavailable,
                        }
                    }
                };
            while reconciled_sequence < head {
                let Ok(Some((start, limit))) =
                    traffic_reconciliation_page_plan(reconciled_sequence, head, reconciled_entries)
                else {
                    return QualificationNodeReply::Error {
                        code: QualificationNodeErrorCode::TrafficUnavailable,
                    };
                };
                let entries = match tokio::time::timeout_at(
                    deadline,
                    self.protected.get_replication_log(start, limit),
                )
                .await
                {
                    Ok(Ok(entries)) if entries.len() == limit => entries,
                    Ok(Ok(_)) | Ok(Err(_)) | Err(_) => {
                        return QualificationNodeReply::Error {
                            code: QualificationNodeErrorCode::TrafficUnavailable,
                        }
                    }
                };
                for entry in entries {
                    let Some(expected_sequence) = reconciled_sequence.checked_add(1) else {
                        return QualificationNodeReply::Error {
                            code: QualificationNodeErrorCode::TrafficUnavailable,
                        };
                    };
                    if entry.sequence != expected_sequence
                        || reconcile_applied_traffic_records(
                            &entry.op,
                            &traffic_keys,
                            &mut reconciled_generations,
                            &mut reconciled_record_fences,
                            seed,
                            self.member_count,
                        )
                        .is_err()
                    {
                        return QualificationNodeReply::Error {
                            code: QualificationNodeErrorCode::TrafficUnavailable,
                        };
                    }
                    reconciled_sequence = entry.sequence;
                    reconciled_entries = reconciled_entries.saturating_add(1);
                }
            }
            let Some(watch_start) = head.checked_add(1) else {
                return QualificationNodeReply::Error {
                    code: QualificationNodeErrorCode::TrafficUnavailable,
                };
            };
            match tokio::time::timeout_at(deadline, self.protected.watch(watch_start)).await {
                Ok(Ok(stream)) => break (stream, watch_start, head),
                Ok(Err(StoreError::ReplicationWatchCatchUpRequired)) => continue,
                Ok(Err(_)) | Err(_) => {
                    return QualificationNodeReply::Error {
                        code: QualificationNodeErrorCode::TrafficUnavailable,
                    }
                }
            }
        };

        let resumed_generation = reconciled_generations[self.node_index];
        let resumed_record_fence = reconciled_record_fences[self.node_index];
        if process_restart
            && !restart_traffic_record_is_exact(
                &self.protected,
                &traffic_keys[self.node_index],
                seed,
                self.member_count,
                self.node_index,
                resumed_generation,
                resumed_record_fence,
                deadline,
            )
            .await
        {
            return QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::TrafficUnavailable,
            };
        }

        let observation = existing_observation.unwrap_or_else(|| {
            Arc::new(QualificationTrafficObservation::new(
                reconciled_head,
                self.member_count,
            ))
        });
        if process_restart {
            observation.record_mutation_resume(resumed_generation, resumed_record_fence);
        }
        for (generation, reconciled) in observation
            .watch_traffic_generations
            .iter()
            .zip(reconciled_generations)
        {
            generation.store(reconciled, Ordering::Release);
        }
        observation
            .watch_sequence
            .store(reconciled_head, Ordering::Release);
        observation.record_authoritative_replication_head(reconciled_head);
        observation
            .watch_reconciled_sequence
            .store(reconciled_head, Ordering::Release);
        increment(&observation.watch_reconciliations);

        let (watch_cancel, watch_cancel_rx) = oneshot::channel();
        let watch_task = tokio::spawn(run_traffic_watch_task(
            stream,
            watch_start,
            self.member_count,
            watch_cancel_rx,
            Arc::clone(&observation),
        ));
        if let Some(traffic) = &mut self.traffic {
            traffic.watch_cancel = Some(watch_cancel);
            traffic.watch_task = Some(watch_task);
        } else {
            self.traffic = Some(QualificationTrafficRuntime {
                seed,
                observation,
                mutation_started: false,
                mutation_cancel: None,
                mutation_task: None,
                watch_cancel: Some(watch_cancel),
                watch_task: Some(watch_task),
            });
        }
        self.traffic_status_snapshot()
    }

    async fn start_traffic_mutation(&mut self) -> QualificationNodeReply {
        let Some(traffic) = &self.traffic else {
            return QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::TrafficUnavailable,
            };
        };
        if traffic.mutation_started
            || traffic.mutation_task.is_some()
            || traffic.observation.failure().is_some()
            || traffic
                .watch_task
                .as_ref()
                .is_none_or(tokio::task::JoinHandle::is_finished)
        {
            return QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::TrafficUnavailable,
            };
        }
        let resume_generation = traffic
            .observation
            .mutation_resume_generation
            .load(Ordering::Acquire);
        let resume_record_fence = traffic
            .observation
            .mutation_resume_record_fence
            .load(Ordering::Acquire);
        if (resume_generation == 0) != (resume_record_fence == 0) {
            traffic
                .observation
                .record_failure(QualificationTrafficFailure::fixed(
                    QualificationTrafficFailureCode::InvariantViolation,
                    QualificationTrafficFailureStage::LeaseAcquire,
                ));
            return QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::TrafficUnavailable,
            };
        }
        let key = match qualification_traffic_key(self.node_index) {
            Ok(key) => key,
            Err(()) => {
                return QualificationNodeReply::Error {
                    code: QualificationNodeErrorCode::TrafficUnavailable,
                }
            }
        };
        let owner = match OwnerId::new(format!("rotation-traffic-owner-{}", self.node_index)) {
            Ok(owner) => owner,
            Err(_) => {
                traffic
                    .observation
                    .record_failure(QualificationTrafficFailure::fixed(
                        QualificationTrafficFailureCode::LeaseRejected,
                        QualificationTrafficFailureStage::LeaseAcquire,
                    ));
                return QualificationNodeReply::Error {
                    code: QualificationNodeErrorCode::TrafficUnavailable,
                };
            }
        };
        let lease = match self
            .protected
            .acquire(&key, owner.clone(), QUALIFICATION_TRAFFIC_TTL)
            .await
        {
            Ok(lease) => lease,
            Err(error) => {
                traffic
                    .observation
                    .record_failure(QualificationTrafficFailure::lease(
                        QualificationTrafficFailureCode::LeaseRejected,
                        QualificationTrafficFailureStage::LeaseAcquire,
                        &error,
                    ));
                return QualificationNodeReply::Error {
                    code: QualificationNodeErrorCode::TrafficUnavailable,
                };
            }
        };
        if resume_record_fence != 0
            && !lease_authority_is_advanced(
                &key,
                &owner,
                resume_record_fence,
                lease.key(),
                lease.owner(),
                lease.fence().get(),
            )
        {
            let _ = self.protected.release(lease).await;
            traffic
                .observation
                .record_failure(QualificationTrafficFailure::fixed(
                    QualificationTrafficFailureCode::InvariantViolation,
                    QualificationTrafficFailureStage::LeaseAcquire,
                ));
            return QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::TrafficUnavailable,
            };
        }
        let Some(traffic) = self.traffic.as_mut() else {
            let _ = self.protected.release(lease).await;
            return QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::TrafficUnavailable,
            };
        };
        let (mutation_cancel, mutation_cancel_rx) = oneshot::channel();
        let mutation_task = tokio::spawn(run_traffic_mutation_task(
            self.protected.clone(),
            Arc::clone(&self.store),
            key,
            owner,
            lease,
            traffic.seed,
            self.member_count,
            self.node_index,
            mutation_cancel_rx,
            Arc::clone(&traffic.observation),
        ));
        traffic.mutation_started = true;
        traffic.mutation_cancel = Some(mutation_cancel);
        traffic.mutation_task = Some(mutation_task);
        self.traffic_status().await
    }

    async fn stop_traffic_mutation(&mut self) -> QualificationNodeReply {
        let Some(traffic) = &mut self.traffic else {
            return QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::TrafficUnavailable,
            };
        };
        let (cancel, task, observation) = (
            traffic.mutation_cancel.take(),
            traffic.mutation_task.take(),
            Arc::clone(&traffic.observation),
        );
        let (Some(cancel), Some(task)) = (cancel, task) else {
            return QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::TrafficUnavailable,
            };
        };
        let shutdown_deadline = tokio::time::Instant::now()
            + Duration::from_millis(QUALIFICATION_FAULT_MUTATION_SHUTDOWN_LEAD_MILLIS);
        let _ = cancel.send(shutdown_deadline);
        match task.await {
            Ok(Ok(())) => {}
            Ok(Err(failure)) => observation.record_failure(failure),
            Err(_) => observation.record_failure(QualificationTrafficFailure::fixed(
                QualificationTrafficFailureCode::TaskJoinUnavailable,
                QualificationTrafficFailureStage::TaskJoin,
            )),
        }
        self.traffic_status_snapshot()
    }

    async fn stop_traffic_watch(&mut self) -> QualificationNodeReply {
        let Some(traffic) = &mut self.traffic else {
            return QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::TrafficUnavailable,
            };
        };
        if traffic.mutation_task.is_some() {
            return QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::TrafficUnavailable,
            };
        }
        let (cancel, task, observation) = (
            traffic.watch_cancel.take(),
            traffic.watch_task.take(),
            Arc::clone(&traffic.observation),
        );
        let (Some(cancel), Some(task)) = (cancel, task) else {
            return QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::TrafficUnavailable,
            };
        };
        let _ = cancel.send(());
        match task.await {
            Ok(Ok(())) => {}
            Ok(Err(failure)) => observation.record_failure(failure),
            Err(_) => observation.record_failure(QualificationTrafficFailure::fixed(
                QualificationTrafficFailureCode::TaskJoinUnavailable,
                QualificationTrafficFailureStage::TaskJoin,
            )),
        }
        self.traffic_status_snapshot()
    }

    async fn traffic_status(&self) -> QualificationNodeReply {
        let Some(traffic) = &self.traffic else {
            return QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::TrafficUnavailable,
            };
        };
        let replication_head = match self.protected.max_replication_sequence().await {
            Ok(head) => {
                traffic
                    .observation
                    .record_authoritative_replication_head(head);
                head
            }
            Err(error) => {
                traffic
                    .observation
                    .record_failure(QualificationTrafficFailure::store(
                        QualificationTrafficFailureCode::BackendUnavailable,
                        QualificationTrafficFailureStage::Watch,
                        &error,
                    ));
                traffic.observation.authoritative_replication_head()
            }
        };
        self.traffic_status_with_replication_head(replication_head)
    }

    fn traffic_status_snapshot(&self) -> QualificationNodeReply {
        let Some(traffic) = &self.traffic else {
            return QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::TrafficUnavailable,
            };
        };
        let replication_head = traffic.observation.authoritative_replication_head();
        self.traffic_status_with_replication_head(replication_head)
    }

    fn traffic_status_with_replication_head(
        &self,
        replication_head: u64,
    ) -> QualificationNodeReply {
        let Some(traffic) = &self.traffic else {
            return QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::TrafficUnavailable,
            };
        };
        let mutation_running = traffic
            .mutation_task
            .as_ref()
            .is_some_and(|task| !task.is_finished());
        let watch_running = traffic
            .watch_task
            .as_ref()
            .is_some_and(|task| !task.is_finished());
        let failure = traffic.observation.failure();
        let state = if failure.is_some() {
            QualificationTrafficState::Failed
        } else if mutation_running {
            QualificationTrafficState::Running
        } else if watch_running {
            if traffic.mutation_started {
                QualificationTrafficState::MutationStopped
            } else {
                QualificationTrafficState::WatchReady
            }
        } else {
            QualificationTrafficState::Stopped
        };
        QualificationNodeReply::TrafficStatus {
            status: QualificationTrafficStatus {
                state,
                failure: failure.map(|failure| failure.code),
                failure_stage: failure.map(|failure| failure.stage),
                failure_error_class: failure.map(|failure| failure.error_class),
                failure_recovery_elapsed_millis: failure
                    .and_then(|failure| failure.recovery_elapsed_millis),
                seed: traffic.seed,
                owned_async_tasks: u8::from(mutation_running) + u8::from(watch_running),
                mutation_cycles: traffic.observation.mutation_cycles.load(Ordering::Acquire),
                linearizable_reads: traffic
                    .observation
                    .linearizable_reads
                    .load(Ordering::Acquire),
                lease_renewals: traffic.observation.lease_renewals.load(Ordering::Acquire),
                lease_reacquisitions: traffic
                    .observation
                    .lease_reacquisitions
                    .load(Ordering::Acquire),
                availability_interruptions: traffic
                    .observation
                    .availability_interruptions
                    .load(Ordering::Acquire),
                availability_recoveries: traffic
                    .observation
                    .availability_recoveries
                    .load(Ordering::Acquire),
                max_consecutive_availability_interruptions: traffic
                    .observation
                    .max_consecutive_availability_interruptions
                    .load(Ordering::Acquire),
                complete_restore_scans: traffic
                    .observation
                    .complete_restore_scans
                    .load(Ordering::Acquire),
                durable_readiness_probes: traffic
                    .observation
                    .durable_readiness_probes
                    .load(Ordering::Acquire),
                mutation_resume_generation: traffic
                    .observation
                    .mutation_resume_generation
                    .load(Ordering::Acquire),
                mutation_resume_record_fence: traffic
                    .observation
                    .mutation_resume_record_fence
                    .load(Ordering::Acquire),
                last_generation: traffic.observation.last_generation.load(Ordering::Acquire),
                last_record_fence: traffic
                    .observation
                    .last_record_fence
                    .load(Ordering::Acquire),
                watch_entries: traffic.observation.watch_entries.load(Ordering::Acquire),
                watch_applied_records: traffic
                    .observation
                    .watch_applied_records
                    .load(Ordering::Acquire),
                watch_sequence: traffic.observation.watch_sequence.load(Ordering::Acquire),
                watch_reconciliations: traffic
                    .observation
                    .watch_reconciliations
                    .load(Ordering::Acquire),
                watch_reconciled_sequence: traffic
                    .observation
                    .watch_reconciled_sequence
                    .load(Ordering::Acquire),
                watch_traffic_generations: traffic
                    .observation
                    .watch_traffic_generations
                    .iter()
                    .map(|generation| generation.load(Ordering::Acquire))
                    .collect(),
                replication_head,
            },
        }
    }

    fn material_status(&self) -> QualificationNodeReply {
        let QualificationTransportRuntime::ProjectedMtls(transport) = &self.transport else {
            return QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::TransportUnavailable,
            };
        };
        QualificationNodeReply::MaterialStatus {
            status: QualificationTlsMaterialStatus::from(transport.client_config.material_status()),
        }
    }

    fn projected_source_status(&self) -> QualificationNodeReply {
        let QualificationTransportRuntime::ProjectedMtls(transport) = &self.transport else {
            return QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::TransportUnavailable,
            };
        };
        QualificationNodeReply::ProjectedSourceStatus {
            status: QualificationProjectedSvidStatus::from(transport.source.status()),
        }
    }

    fn request_reauthentication(&mut self) -> QualificationNodeReply {
        let QualificationTransportRuntime::ProjectedMtls(transport) = &mut self.transport else {
            return QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::TransportUnavailable,
            };
        };
        let resolution_baselines = transport
            .directed_peers
            .iter()
            .map(|(node_index, directed)| (*node_index, directed.resolver_evidence.calls()))
            .collect::<BTreeMap<_, _>>();
        match transport.reauthentication.request_reauthentication() {
            Ok(generation) => {
                for (node_index, directed) in &mut transport.directed_peers {
                    let Some(calls_before_request) = resolution_baselines.get(node_index) else {
                        return QualificationNodeReply::Error {
                            code: QualificationNodeErrorCode::TransportUnavailable,
                        };
                    };
                    directed.required_resolution = Some(QualificationRequiredResolution {
                        calls_before_request: *calls_before_request,
                        reauthentication_generation: generation,
                    });
                }
                QualificationNodeReply::ReauthenticationRequested { generation }
            }
            Err(_) => QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::TransportUnavailable,
            },
        }
    }

    fn reauthentication_generation(&self) -> QualificationNodeReply {
        let QualificationTransportRuntime::ProjectedMtls(transport) = &self.transport else {
            return QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::TransportUnavailable,
            };
        };
        QualificationNodeReply::ReauthenticationGeneration {
            generation: transport.reauthentication.generation(),
        }
    }

    async fn directed_handshake(&self, remote_node_index: usize) -> QualificationNodeReply {
        let QualificationTransportRuntime::ProjectedMtls(transport) = &self.transport else {
            return QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::TransportUnavailable,
            };
        };
        let Some(directed) = transport.directed_peers.get(&remote_node_index) else {
            return QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::InvalidRequest,
            };
        };
        let Some(required_resolution) = directed.required_resolution else {
            return QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::DirectedHandshakeUnavailable,
            };
        };
        if !matches!(
            transport.client_config.material_status().availability(),
            opc_tls::TlsMaterialAvailability::Ready
                | opc_tls::TlsMaterialAvailability::RetainingLastGood
        ) {
            return QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::MaterialUnavailable,
            };
        }
        // The empty bounded ReadBarrier payload currently matches the store's
        // private unit request. An exact Protocol result is also accepted: it
        // proves authenticated TLS plus exact manifest-bound bootstrap reached
        // the remote service, but does not claim valid ReadBarrier handling.
        let request = match SessionConsensusWireRequest::try_new(
            transport.consensus_identity,
            transport.local_node_id,
            SessionConsensusRpcFamily::ReadBarrier,
            Vec::new(),
        ) {
            Ok(request) => request,
            Err(_) => {
                return QualificationNodeReply::Error {
                    code: QualificationNodeErrorCode::DirectedHandshakeUnavailable,
                }
            }
        };
        let succeeded = match directed.peer.call(request).await {
            Ok(response) if response.validate().is_ok() => {
                response.result.is_ok()
                    || matches!(response.result, Err(SessionConsensusPeerError::Protocol))
            }
            _ => false,
        };
        if succeeded && directed.resolver_evidence.proves(required_resolution) {
            QualificationNodeReply::DirectedHandshake {
                remote_node_index,
                reauthentication_generation: required_resolution.reauthentication_generation,
            }
        } else {
            QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::DirectedHandshakeUnavailable,
            }
        }
    }

    async fn probe(&self) -> QualificationNodeReply {
        let report = self.store.probe_durable_readiness().await;
        let reason_code = match report.state() {
            opc_session_store::DurableReadinessState::Ready => QualificationReadinessCode::Ready,
            opc_session_store::DurableReadinessState::NoQuorum => {
                QualificationReadinessCode::NoQuorum
            }
            opc_session_store::DurableReadinessState::TopologyInvalid => {
                QualificationReadinessCode::TopologyInvalid
            }
            opc_session_store::DurableReadinessState::RecoveryRequired => {
                QualificationReadinessCode::RecoveryRequired
            }
            _ => QualificationReadinessCode::RecoveryRequired,
        };
        let progress = report.recovery_progress();
        let status = self.store.status();
        QualificationNodeReply::Readiness {
            ready: report.is_ready(),
            reason_code,
            node_id: status.node_id.get(),
            term: status.term,
            leader_id: status.leader_id.map(|node_id| node_id.get()),
            configured_voters: report.configured_voters(),
            fresh_reachable_voters: report.fresh_reachable_voters(),
            agreeing_voters: report.agreeing_voters(),
            required_quorum: report.required_quorum(),
            committed_index: report.committed_barrier_index(),
            applied_index: progress.local_applied_index(),
        }
    }

    async fn stop_server(&mut self) {
        if self
            .traffic
            .as_ref()
            .and_then(|traffic| traffic.mutation_task.as_ref())
            .is_some()
        {
            let _ = self.stop_traffic_mutation().await;
        }
        if self
            .traffic
            .as_ref()
            .and_then(|traffic| traffic.watch_task.as_ref())
            .is_some()
        {
            let _ = self.stop_traffic_watch().await;
        }
        if let Some(server) = self.server.take() {
            server.abort_and_wait().await;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_traffic_mutation_task(
    protected: ProtectedStore,
    store: Arc<ConsensusSessionStore>,
    key: SessionKey,
    owner: OwnerId,
    lease: LeaseGuard,
    seed: u64,
    member_count: usize,
    node_index: usize,
    mut cancellation: oneshot::Receiver<tokio::time::Instant>,
    observation: Arc<QualificationTrafficObservation>,
) -> Result<(), QualificationTrafficFailure> {
    // The option is the task's single source of truth for lease ownership. An
    // explicit release takes the guard before awaiting the backend, so neither
    // cancellation nor an error path can attempt to release the same guard a
    // second time.
    let mut lease = Some(lease);
    let mut consecutive_availability_interruptions = 0_u64;
    let mut shutdown_deadline = None;
    let terminal_failure = loop {
        match run_traffic_mutation_task_inner(
            &protected,
            &store,
            &key,
            &owner,
            &mut lease,
            seed,
            member_count,
            node_index,
            &mut cancellation,
            &mut shutdown_deadline,
            &observation,
        )
        .await
        {
            Ok(()) => break None,
            Err(failure) if traffic_failure_is_recoverable(failure) => {
                if !observation
                    .record_availability_interruption(&mut consecutive_availability_interruptions)
                {
                    break Some(failure);
                }
                let recovery_started_at = tokio::time::Instant::now();
                let deadline = traffic_recovery_deadline(recovery_started_at, shutdown_deadline);
                match reconcile_traffic_mutation_checkpoint(
                    &protected,
                    &key,
                    &owner,
                    &mut lease,
                    seed,
                    member_count,
                    node_index,
                    failure,
                    recovery_started_at,
                    deadline,
                    &mut consecutive_availability_interruptions,
                    &observation,
                )
                .await
                {
                    Ok(()) => {
                        observation.record_availability_recovery(
                            &mut consecutive_availability_interruptions,
                        );
                        if traffic_cancellation_requested(&mut cancellation, &mut shutdown_deadline)
                        {
                            break None;
                        }
                    }
                    Err(recovery_failure) => break Some(recovery_failure),
                }
            }
            Err(failure) => break Some(failure),
        }
    };

    if let Some(failure) = terminal_failure {
        observation.record_failure(failure);
        if shutdown_deadline.is_none_or(|deadline| tokio::time::Instant::now() < deadline) {
            if let Some(lease) = lease.take() {
                let _ = protected.release(lease).await;
            }
        }
        return Err(failure);
    }

    // A clean stop also preserves the same no-unknown-outcome rule. If the
    // release response is typed as ambiguous, reacquire the same-owner
    // authority, reconcile the record, and retry release within the identical
    // fixed budget. No accepted lease operation is cancelled mid-flight.
    loop {
        if traffic_shutdown_deadline_reached(shutdown_deadline, tokio::time::Instant::now()) {
            let failure = QualificationTrafficFailure::backend_unavailable(
                QualificationTrafficFailureCode::LeaseRejected,
                QualificationTrafficFailureStage::LeaseRelease,
            );
            observation.record_failure(failure);
            return Err(failure);
        }
        let Some(lease_to_release) = lease.take() else {
            return Ok(());
        };
        match protected.release(lease_to_release).await {
            Ok(()) => {
                if traffic_shutdown_deadline_reached(shutdown_deadline, tokio::time::Instant::now())
                {
                    let failure = QualificationTrafficFailure::backend_unavailable(
                        QualificationTrafficFailureCode::LeaseRejected,
                        QualificationTrafficFailureStage::LeaseRelease,
                    );
                    observation.record_failure(failure);
                    return Err(failure);
                }
                return Ok(());
            }
            Err(error) => {
                let failure = QualificationTrafficFailure::lease(
                    QualificationTrafficFailureCode::LeaseRejected,
                    QualificationTrafficFailureStage::LeaseRelease,
                    &error,
                );
                if !traffic_failure_is_recoverable(failure)
                    || !observation.record_availability_interruption(
                        &mut consecutive_availability_interruptions,
                    )
                {
                    observation.record_failure(failure);
                    return Err(failure);
                }
                let recovery_started_at = tokio::time::Instant::now();
                let deadline = traffic_recovery_deadline(recovery_started_at, shutdown_deadline);
                match reconcile_traffic_mutation_authority(
                    &protected,
                    &key,
                    &owner,
                    &mut lease,
                    seed,
                    member_count,
                    node_index,
                    failure,
                    recovery_started_at,
                    deadline,
                    &mut consecutive_availability_interruptions,
                    &observation,
                )
                .await
                {
                    Ok(()) => observation
                        .record_availability_recovery(&mut consecutive_availability_interruptions),
                    Err(recovery_failure) => {
                        observation.record_failure(recovery_failure);
                        if shutdown_deadline
                            .is_none_or(|deadline| tokio::time::Instant::now() < deadline)
                        {
                            if let Some(lease) = lease.take() {
                                let _ = protected.release(lease).await;
                            }
                        }
                        return Err(recovery_failure);
                    }
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn reconcile_traffic_mutation_checkpoint(
    protected: &ProtectedStore,
    key: &SessionKey,
    owner: &OwnerId,
    lease: &mut Option<LeaseGuard>,
    seed: u64,
    member_count: usize,
    node_index: usize,
    initial_failure: QualificationTrafficFailure,
    recovery_started_at: tokio::time::Instant,
    deadline: tokio::time::Instant,
    consecutive_availability_interruptions: &mut u64,
    observation: &QualificationTrafficObservation,
) -> Result<(), QualificationTrafficFailure> {
    if traffic_failure_retains_known_authority(initial_failure) {
        return reconcile_traffic_known_authority(
            protected,
            key,
            owner,
            lease.as_ref(),
            seed,
            member_count,
            node_index,
            initial_failure,
            recovery_started_at,
            deadline,
            consecutive_availability_interruptions,
            observation,
        )
        .await;
    }
    reconcile_traffic_mutation_authority(
        protected,
        key,
        owner,
        lease,
        seed,
        member_count,
        node_index,
        initial_failure,
        recovery_started_at,
        deadline,
        consecutive_availability_interruptions,
        observation,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn reconcile_traffic_known_authority(
    protected: &ProtectedStore,
    key: &SessionKey,
    owner: &OwnerId,
    lease: Option<&LeaseGuard>,
    seed: u64,
    member_count: usize,
    node_index: usize,
    initial_failure: QualificationTrafficFailure,
    recovery_started_at: tokio::time::Instant,
    deadline: tokio::time::Instant,
    consecutive_availability_interruptions: &mut u64,
    observation: &QualificationTrafficObservation,
) -> Result<(), QualificationTrafficFailure> {
    let Some(current_lease) = lease else {
        return Err(QualificationTrafficFailure::fixed(
            QualificationTrafficFailureCode::InvariantViolation,
            QualificationTrafficFailureStage::LeaseAcquire,
        ));
    };
    let observed_generation = observation.last_generation.load(Ordering::Acquire);
    let observed_record_fence = observation.last_record_fence.load(Ordering::Acquire);
    if observed_generation == 0
        || observed_record_fence == 0
        || !lease_authority_is_preserved(
            key,
            owner,
            observed_record_fence,
            current_lease.key(),
            current_lease.owner(),
            current_lease.fence().get(),
        )
    {
        return Err(QualificationTrafficFailure::fixed(
            QualificationTrafficFailureCode::InvariantViolation,
            QualificationTrafficFailureStage::Get,
        ));
    }

    let stored = loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(QualificationTrafficFailure::recovery_deadline_exceeded(
                QualificationTrafficFailureStage::Get,
                recovery_started_at,
            ));
        }
        match protected.get(key).await {
            Ok(Some(stored)) => break stored,
            Ok(None) => {
                return Err(QualificationTrafficFailure::fixed(
                    QualificationTrafficFailureCode::InvariantViolation,
                    QualificationTrafficFailureStage::Get,
                ));
            }
            Err(error) => {
                let failure = QualificationTrafficFailure::store(
                    QualificationTrafficFailureCode::BackendUnavailable,
                    QualificationTrafficFailureStage::Get,
                    &error,
                );
                if !traffic_failure_is_recoverable(failure)
                    || !observation
                        .record_availability_interruption(consecutive_availability_interruptions)
                {
                    return Err(failure);
                }
                if !wait_for_traffic_recovery_retry(deadline).await {
                    return Err(QualificationTrafficFailure::recovery_deadline_exceeded(
                        QualificationTrafficFailureStage::Get,
                        recovery_started_at,
                    ));
                }
            }
        }
    };
    if tokio::time::Instant::now() >= deadline {
        return Err(QualificationTrafficFailure::recovery_deadline_exceeded(
            QualificationTrafficFailureStage::Get,
            recovery_started_at,
        ));
    }
    let Some((generation, record_fence)) = reconciled_traffic_record_identity(
        &stored,
        key,
        owner,
        seed,
        member_count,
        node_index,
        observed_generation,
        observed_record_fence,
        None,
        initial_failure.stage,
    ) else {
        return Err(QualificationTrafficFailure::fixed(
            QualificationTrafficFailureCode::InvariantViolation,
            QualificationTrafficFailureStage::Get,
        ));
    };
    if generation != observed_generation
        || record_fence != observed_record_fence
        || !lease_authority_is_preserved(
            key,
            owner,
            record_fence,
            current_lease.key(),
            current_lease.owner(),
            current_lease.fence().get(),
        )
    {
        return Err(QualificationTrafficFailure::fixed(
            QualificationTrafficFailureCode::InvariantViolation,
            QualificationTrafficFailureStage::Get,
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn reconcile_traffic_mutation_authority(
    protected: &ProtectedStore,
    key: &SessionKey,
    owner: &OwnerId,
    lease: &mut Option<LeaseGuard>,
    seed: u64,
    member_count: usize,
    node_index: usize,
    initial_failure: QualificationTrafficFailure,
    recovery_started_at: tokio::time::Instant,
    deadline: tokio::time::Instant,
    consecutive_availability_interruptions: &mut u64,
    observation: &QualificationTrafficObservation,
) -> Result<(), QualificationTrafficFailure> {
    let ambiguous_lease_fence = lease.as_ref().map(|guard| guard.fence().get());
    let observed_generation = observation.last_generation.load(Ordering::Acquire);
    let observed_record_fence = observation.last_record_fence.load(Ordering::Acquire);
    let previous_authority_fence = ambiguous_lease_fence
        .unwrap_or(observed_record_fence)
        .max(observed_record_fence);
    // The prior guard is no longer usable after a typed ambiguous mutation
    // outcome. Same-owner acquire is the only operation that establishes a
    // fresh, strictly higher fencing authority for deterministic recovery.
    *lease = None;

    let recovered_lease = loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(QualificationTrafficFailure::recovery_deadline_exceeded(
                QualificationTrafficFailureStage::LeaseAcquire,
                recovery_started_at,
            ));
        }
        match protected
            .acquire(key, owner.clone(), QUALIFICATION_TRAFFIC_TTL)
            .await
        {
            Ok(recovered) => break recovered,
            Err(error) => {
                let failure = QualificationTrafficFailure::lease(
                    QualificationTrafficFailureCode::LeaseRejected,
                    QualificationTrafficFailureStage::LeaseAcquire,
                    &error,
                );
                if !traffic_failure_is_recoverable(failure)
                    || !observation
                        .record_availability_interruption(consecutive_availability_interruptions)
                {
                    return Err(failure);
                }
                if !wait_for_traffic_recovery_retry(deadline).await {
                    return Err(QualificationTrafficFailure::recovery_deadline_exceeded(
                        QualificationTrafficFailureStage::LeaseAcquire,
                        recovery_started_at,
                    ));
                }
            }
        }
    };
    if !lease_authority_is_advanced(
        key,
        owner,
        previous_authority_fence,
        recovered_lease.key(),
        recovered_lease.owner(),
        recovered_lease.fence().get(),
    ) {
        return Err(QualificationTrafficFailure::fixed(
            QualificationTrafficFailureCode::InvariantViolation,
            QualificationTrafficFailureStage::LeaseAcquire,
        ));
    }
    let recovered_lease_fence = recovered_lease.fence().get();
    *lease = Some(recovered_lease);
    if tokio::time::Instant::now() >= deadline {
        return Err(QualificationTrafficFailure::recovery_deadline_exceeded(
            QualificationTrafficFailureStage::LeaseAcquire,
            recovery_started_at,
        ));
    }

    let stored = loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(QualificationTrafficFailure::recovery_deadline_exceeded(
                QualificationTrafficFailureStage::Get,
                recovery_started_at,
            ));
        }
        match protected.get(key).await {
            Ok(stored) => break stored,
            Err(error) => {
                let failure = QualificationTrafficFailure::store(
                    QualificationTrafficFailureCode::BackendUnavailable,
                    QualificationTrafficFailureStage::Get,
                    &error,
                );
                if !traffic_failure_is_recoverable(failure)
                    || !observation
                        .record_availability_interruption(consecutive_availability_interruptions)
                {
                    return Err(failure);
                }
                if !wait_for_traffic_recovery_retry(deadline).await {
                    return Err(QualificationTrafficFailure::recovery_deadline_exceeded(
                        QualificationTrafficFailureStage::Get,
                        recovery_started_at,
                    ));
                }
            }
        }
    };
    if tokio::time::Instant::now() >= deadline {
        return Err(QualificationTrafficFailure::recovery_deadline_exceeded(
            QualificationTrafficFailureStage::Get,
            recovery_started_at,
        ));
    }

    match stored {
        None if observed_generation == 0
            && matches!(
                initial_failure.stage,
                QualificationTrafficFailureStage::LeaseRenew
                    | QualificationTrafficFailureStage::CompareAndSet
            ) => {}
        None => {
            return Err(QualificationTrafficFailure::fixed(
                QualificationTrafficFailureCode::InvariantViolation,
                QualificationTrafficFailureStage::Get,
            ));
        }
        Some(stored) => {
            let Some((generation, record_fence)) = reconciled_traffic_record_identity(
                &stored,
                key,
                owner,
                seed,
                member_count,
                node_index,
                observed_generation,
                observed_record_fence,
                ambiguous_lease_fence,
                initial_failure.stage,
            ) else {
                return Err(QualificationTrafficFailure::fixed(
                    QualificationTrafficFailureCode::InvariantViolation,
                    QualificationTrafficFailureStage::Get,
                ));
            };
            if recovered_lease_fence <= record_fence {
                return Err(QualificationTrafficFailure::fixed(
                    QualificationTrafficFailureCode::InvariantViolation,
                    QualificationTrafficFailureStage::LeaseAcquire,
                ));
            }
            observation
                .last_record_fence
                .store(record_fence, Ordering::Release);
            observation
                .last_generation
                .store(generation, Ordering::Release);
        }
    }
    Ok(())
}

async fn wait_for_traffic_recovery_retry(deadline: tokio::time::Instant) -> bool {
    let now = tokio::time::Instant::now();
    if now >= deadline {
        return false;
    }
    let delay = Duration::from_millis(QUALIFICATION_TRAFFIC_AVAILABILITY_RETRY_MILLIS)
        .min(deadline.saturating_duration_since(now));
    tokio::time::sleep(delay).await;
    tokio::time::Instant::now() < deadline
}

fn traffic_recovery_deadline(
    recovery_started_at: tokio::time::Instant,
    shutdown_deadline: Option<tokio::time::Instant>,
) -> tokio::time::Instant {
    let episode_deadline = recovery_started_at
        + Duration::from_millis(QUALIFICATION_TRAFFIC_AVAILABILITY_RECOVERY_MILLIS);
    shutdown_deadline.map_or(episode_deadline, |deadline| deadline.min(episode_deadline))
}

#[allow(clippy::too_many_arguments)]
fn reconciled_traffic_record_identity(
    stored: &StoredSessionRecord,
    key: &SessionKey,
    owner: &OwnerId,
    seed: u64,
    member_count: usize,
    node_index: usize,
    observed_generation: u64,
    observed_record_fence: u64,
    ambiguous_lease_fence: Option<u64>,
    failure_stage: QualificationTrafficFailureStage,
) -> Option<(u64, u64)> {
    let generation = stored.generation.get();
    let record_fence = if generation == observed_generation && generation != 0 {
        observed_record_fence
    } else if matches!(
        failure_stage,
        QualificationTrafficFailureStage::CompareAndSet
    ) && observed_generation.checked_add(1) == Some(generation)
    {
        ambiguous_lease_fence?
    } else {
        return None;
    };
    let expected = StoredSessionRecord {
        key: key.clone(),
        generation: Generation::new(generation),
        owner: owner.clone(),
        fence: FenceToken::new(record_fence),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static(QUALIFICATION_TRAFFIC_STATE_TYPE),
        expires_at: None,
        payload: EncryptedSessionPayload::new(
            qualification_traffic_value(seed, member_count, node_index, generation).as_bytes(),
        ),
    };
    traffic_record_is_exact(&expected, stored).then_some((generation, record_fence))
}

#[allow(clippy::too_many_arguments)]
async fn run_traffic_mutation_task_inner(
    protected: &ProtectedStore,
    store: &ConsensusSessionStore,
    key: &SessionKey,
    owner: &OwnerId,
    lease: &mut Option<LeaseGuard>,
    seed: u64,
    member_count: usize,
    node_index: usize,
    cancellation: &mut oneshot::Receiver<tokio::time::Instant>,
    shutdown_deadline: &mut Option<tokio::time::Instant>,
    observation: &QualificationTrafficObservation,
) -> Result<(), QualificationTrafficFailure> {
    let mut schedule_state = seed ^ (u64::try_from(node_index).unwrap_or(u64::MAX) << 32);
    loop {
        if traffic_cancellation_requested(cancellation, shutdown_deadline) {
            return Ok(());
        }

        let Some(current_lease) = lease.as_ref() else {
            return Err(QualificationTrafficFailure::fixed(
                QualificationTrafficFailureCode::InvariantViolation,
                QualificationTrafficFailureStage::LeaseRenew,
            ));
        };
        let previous_fence = current_lease.fence().get();
        let renewed = protected
            .renew(current_lease, QUALIFICATION_TRAFFIC_TTL)
            .await
            .map_err(|error| {
                QualificationTrafficFailure::lease(
                    QualificationTrafficFailureCode::LeaseRejected,
                    QualificationTrafficFailureStage::LeaseRenew,
                    &error,
                )
            })?;
        *lease = Some(renewed);
        let Some(renewed) = lease.as_ref() else {
            return Err(QualificationTrafficFailure::fixed(
                QualificationTrafficFailureCode::InvariantViolation,
                QualificationTrafficFailureStage::LeaseRenew,
            ));
        };
        if !lease_authority_is_preserved(
            key,
            owner,
            previous_fence,
            renewed.key(),
            renewed.owner(),
            renewed.fence().get(),
        ) {
            return Err(QualificationTrafficFailure::fixed(
                QualificationTrafficFailureCode::InvariantViolation,
                QualificationTrafficFailureStage::LeaseRenew,
            ));
        }
        increment(&observation.lease_renewals);
        // Every cancellation checkpoint follows a completed operation. The
        // task never selects cancellation against a polled store future, whose
        // outcome would become unknown if dropped.
        if traffic_cancellation_requested(cancellation, shutdown_deadline) {
            return Ok(());
        }

        let generation = observation
            .last_generation
            .load(Ordering::Acquire)
            .checked_add(1)
            .ok_or_else(|| {
                QualificationTrafficFailure::fixed(
                    QualificationTrafficFailureCode::InvariantViolation,
                    QualificationTrafficFailureStage::CompareAndSet,
                )
            })?;
        let value = qualification_traffic_value(seed, member_count, node_index, generation);
        let Some(current_lease) = lease.as_ref() else {
            return Err(QualificationTrafficFailure::fixed(
                QualificationTrafficFailureCode::InvariantViolation,
                QualificationTrafficFailureStage::CompareAndSet,
            ));
        };
        let record_fence = current_lease.fence().get();
        let expected_record = StoredSessionRecord {
            key: key.clone(),
            generation: Generation::new(generation),
            owner: current_lease.owner().clone(),
            fence: current_lease.fence(),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static(QUALIFICATION_TRAFFIC_STATE_TYPE),
            expires_at: None,
            payload: EncryptedSessionPayload::new(value.as_bytes()),
        };
        let expected_generation = generation.checked_sub(1).filter(|value| *value != 0);
        match protected
            .compare_and_set(CompareAndSet {
                key: key.clone(),
                lease: current_lease.clone(),
                expected_generation: expected_generation.map(Generation::new),
                new_record: expected_record.clone(),
            })
            .await
            .map_err(|error| {
                QualificationTrafficFailure::store(
                    QualificationTrafficFailureCode::BackendUnavailable,
                    QualificationTrafficFailureStage::CompareAndSet,
                    &error,
                )
            })? {
            CompareAndSetResult::Success => {}
            CompareAndSetResult::Conflict { .. } => {
                return Err(QualificationTrafficFailure::fixed(
                    QualificationTrafficFailureCode::InvariantViolation,
                    QualificationTrafficFailureStage::CompareAndSet,
                ))
            }
        }
        // Publish the committed record identity immediately. A clean stop or
        // later-stage failure must not hide a CAS that already succeeded.
        observation
            .last_record_fence
            .store(record_fence, Ordering::Release);
        observation
            .last_generation
            .store(generation, Ordering::Release);
        if traffic_cancellation_requested(cancellation, shutdown_deadline) {
            return Ok(());
        }

        let stored = protected
            .get(key)
            .await
            .map_err(|error| {
                QualificationTrafficFailure::store(
                    QualificationTrafficFailureCode::BackendUnavailable,
                    QualificationTrafficFailureStage::Get,
                    &error,
                )
            })?
            .ok_or_else(|| {
                QualificationTrafficFailure::fixed(
                    QualificationTrafficFailureCode::InvariantViolation,
                    QualificationTrafficFailureStage::Get,
                )
            })?;
        if !traffic_record_is_exact(&expected_record, &stored) {
            return Err(QualificationTrafficFailure::fixed(
                QualificationTrafficFailureCode::InvariantViolation,
                QualificationTrafficFailureStage::Get,
            ));
        }
        increment(&observation.linearizable_reads);
        if traffic_cancellation_requested(cancellation, shutdown_deadline) {
            return Ok(());
        }

        let page = protected
            .scan_restore_records(RestoreScanRequest::all(QUALIFICATION_TRAFFIC_RESTORE_LIMIT))
            .await
            .map_err(|error| {
                QualificationTrafficFailure::store(
                    QualificationTrafficFailureCode::RestoreScanRejected,
                    QualificationTrafficFailureStage::RestoreScan,
                    &error,
                )
            })?;
        if !page.complete
            || page.next_cursor.is_some()
            || page.cursor_profile != RestoreScanCursorProfile::DurableOpaqueV1
            || page.loaded_count != page.records.len()
            || page.loaded_count > QUALIFICATION_TRAFFIC_RESTORE_LIMIT
            || !page
                .records
                .iter()
                .any(|candidate| traffic_record_is_exact(&expected_record, candidate))
        {
            return Err(QualificationTrafficFailure::fixed(
                QualificationTrafficFailureCode::RestoreScanRejected,
                QualificationTrafficFailureStage::RestoreScan,
            ));
        }
        increment(&observation.complete_restore_scans);
        if traffic_cancellation_requested(cancellation, shutdown_deadline) {
            return Ok(());
        }

        let readiness = store.probe_durable_readiness().await;
        if !readiness.is_ready() {
            return Err(QualificationTrafficFailure::backend_unavailable(
                QualificationTrafficFailureCode::ReadinessUnavailable,
                QualificationTrafficFailureStage::ReadinessProbe,
            ));
        }
        increment(&observation.durable_readiness_probes);
        if traffic_cancellation_requested(cancellation, shutdown_deadline) {
            return Ok(());
        }

        let Some(lease_to_release) = lease.take() else {
            return Err(QualificationTrafficFailure::fixed(
                QualificationTrafficFailureCode::InvariantViolation,
                QualificationTrafficFailureStage::LeaseRelease,
            ));
        };
        protected.release(lease_to_release).await.map_err(|error| {
            QualificationTrafficFailure::lease(
                QualificationTrafficFailureCode::LeaseRejected,
                QualificationTrafficFailureStage::LeaseRelease,
                &error,
            )
        })?;
        // The private qualification schedule deterministically drops exactly
        // one otherwise successful release response per mutation task. This
        // exercises the same no-guess recovery path as a real typed ambiguous
        // outcome without changing Openraft, the store, or production APIs.
        if observation
            .synthetic_release_response_loss_pending
            .swap(false, Ordering::AcqRel)
        {
            return Err(QualificationTrafficFailure {
                code: QualificationTrafficFailureCode::LeaseRejected,
                stage: QualificationTrafficFailureStage::LeaseRelease,
                error_class: QualificationTrafficErrorClass::BackendOperationOutcomeUnavailable,
                recovery_elapsed_millis: None,
            });
        }
        if traffic_cancellation_requested(cancellation, shutdown_deadline) {
            return Ok(());
        }
        let reacquired = protected
            .acquire(key, owner.clone(), QUALIFICATION_TRAFFIC_TTL)
            .await
            .map_err(|error| {
                QualificationTrafficFailure::lease(
                    QualificationTrafficFailureCode::LeaseRejected,
                    QualificationTrafficFailureStage::LeaseAcquire,
                    &error,
                )
            })?;
        *lease = Some(reacquired);
        let Some(reacquired) = lease.as_ref() else {
            return Err(QualificationTrafficFailure::fixed(
                QualificationTrafficFailureCode::InvariantViolation,
                QualificationTrafficFailureStage::LeaseAcquire,
            ));
        };
        if !lease_authority_is_advanced(
            key,
            owner,
            record_fence,
            reacquired.key(),
            reacquired.owner(),
            reacquired.fence().get(),
        ) {
            return Err(QualificationTrafficFailure::fixed(
                QualificationTrafficFailureCode::InvariantViolation,
                QualificationTrafficFailureStage::LeaseAcquire,
            ));
        }
        increment(&observation.lease_reacquisitions);
        increment(&observation.mutation_cycles);

        schedule_state = schedule_state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let delay = QUALIFICATION_TRAFFIC_MUTATION_DELAY_MIN_MILLIS
            + schedule_state % QUALIFICATION_TRAFFIC_MUTATION_DELAY_SPAN_MILLIS;
        tokio::select! {
            cancellation = &mut *cancellation => {
                let deadline = cancellation.unwrap_or_else(|_| {
                    tokio::time::Instant::now()
                        + Duration::from_millis(
                            QUALIFICATION_FAULT_MUTATION_SHUTDOWN_LEAD_MILLIS,
                        )
                });
                record_traffic_shutdown_deadline(shutdown_deadline, deadline);
                return Ok(());
            },
            _ = tokio::time::sleep(Duration::from_millis(delay)) => {}
        }
    }
}

fn traffic_cancellation_requested(
    cancellation: &mut oneshot::Receiver<tokio::time::Instant>,
    shutdown_deadline: &mut Option<tokio::time::Instant>,
) -> bool {
    match cancellation.try_recv() {
        Ok(deadline) => {
            record_traffic_shutdown_deadline(shutdown_deadline, deadline);
            true
        }
        Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
            let deadline = tokio::time::Instant::now()
                + Duration::from_millis(QUALIFICATION_FAULT_MUTATION_SHUTDOWN_LEAD_MILLIS);
            record_traffic_shutdown_deadline(shutdown_deadline, deadline);
            true
        }
        Err(tokio::sync::oneshot::error::TryRecvError::Empty) => false,
    }
}

fn record_traffic_shutdown_deadline(
    shutdown_deadline: &mut Option<tokio::time::Instant>,
    deadline: tokio::time::Instant,
) {
    *shutdown_deadline = Some(shutdown_deadline.map_or(deadline, |current| current.min(deadline)));
}

fn traffic_shutdown_deadline_reached(
    shutdown_deadline: Option<tokio::time::Instant>,
    now: tokio::time::Instant,
) -> bool {
    shutdown_deadline.is_some_and(|deadline| now >= deadline)
}

fn lease_authority_is_preserved(
    expected_key: &SessionKey,
    expected_owner: &OwnerId,
    expected_fence: u64,
    actual_key: &SessionKey,
    actual_owner: &OwnerId,
    actual_fence: u64,
) -> bool {
    actual_key == expected_key && actual_owner == expected_owner && actual_fence == expected_fence
}

fn lease_authority_is_advanced(
    expected_key: &SessionKey,
    expected_owner: &OwnerId,
    previous_fence: u64,
    actual_key: &SessionKey,
    actual_owner: &OwnerId,
    actual_fence: u64,
) -> bool {
    actual_key == expected_key && actual_owner == expected_owner && actual_fence > previous_fence
}

fn traffic_record_is_exact(expected: &StoredSessionRecord, actual: &StoredSessionRecord) -> bool {
    actual == expected
}

fn traffic_reconciliation_page_plan(
    reconciled_sequence: u64,
    authoritative_head: u64,
    reconciled_entries: u64,
) -> Result<Option<(u64, usize)>, ()> {
    let remaining = authoritative_head
        .checked_sub(reconciled_sequence)
        .ok_or(())?;
    if remaining == 0 {
        return Ok(None);
    }
    if reconciled_entries
        .checked_add(remaining)
        .is_none_or(|total| total > QUALIFICATION_TRAFFIC_WATCH_RECONCILIATION_MAX_ENTRIES)
    {
        return Err(());
    }
    let start = reconciled_sequence.checked_add(1).ok_or(())?;
    let limit = usize::try_from(remaining)
        .unwrap_or(usize::MAX)
        .min(QUALIFICATION_TRAFFIC_WATCH_RECONCILIATION_PAGE_ENTRIES);
    Ok(Some((start, limit)))
}

async fn run_traffic_watch_task(
    mut stream: BoxStream<'static, Result<ReplicationEntry, StoreError>>,
    mut expected_sequence: u64,
    member_count: usize,
    mut cancellation: oneshot::Receiver<()>,
    observation: Arc<QualificationTrafficObservation>,
) -> Result<(), QualificationTrafficFailure> {
    let traffic_keys = match (0..member_count)
        .map(qualification_traffic_key)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(keys) => keys,
        Err(()) => {
            let failure = QualificationTrafficFailure::fixed(
                QualificationTrafficFailureCode::InvariantViolation,
                QualificationTrafficFailureStage::Watch,
            );
            observation.record_failure(failure);
            return Err(failure);
        }
    };
    loop {
        tokio::select! {
            biased;
            _ = &mut cancellation => return Ok(()),
            entry = stream.next() => {
                let Some(entry) = entry else {
                    let failure = QualificationTrafficFailure::fixed(
                        QualificationTrafficFailureCode::WatchUnavailable,
                        QualificationTrafficFailureStage::Watch,
                    );
                    observation.record_failure(failure);
                    return Err(failure);
                };
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(error) => {
                        let failure = QualificationTrafficFailure::store(
                            QualificationTrafficFailureCode::WatchUnavailable,
                            QualificationTrafficFailureStage::Watch,
                            &error,
                        );
                        observation.record_failure(failure);
                        return Err(failure);
                    }
                };
                if entry.sequence != expected_sequence {
                    let failure = QualificationTrafficFailure::fixed(
                        QualificationTrafficFailureCode::InvariantViolation,
                        QualificationTrafficFailureStage::Watch,
                    );
                    observation.record_failure(failure);
                    return Err(failure);
                }
                let applied_records = match observe_applied_records(
                    &entry.op,
                    &traffic_keys,
                    &observation.watch_traffic_generations,
                ) {
                    Ok(applied_records) => applied_records,
                    Err(_) => {
                        let failure = QualificationTrafficFailure::fixed(
                            QualificationTrafficFailureCode::InvariantViolation,
                            QualificationTrafficFailureStage::Watch,
                        );
                        observation.record_failure(failure);
                        return Err(failure);
                    }
                };
                observation.watch_sequence.store(entry.sequence, Ordering::Release);
                increment(&observation.watch_entries);
                if applied_records != 0 {
                    let _ = observation.watch_applied_records.fetch_update(
                        Ordering::AcqRel,
                        Ordering::Acquire,
                        |value| Some(value.saturating_add(applied_records)),
                    );
                }
                let Some(next_sequence) = expected_sequence.checked_add(1) else {
                    let failure = QualificationTrafficFailure::fixed(
                        QualificationTrafficFailureCode::InvariantViolation,
                        QualificationTrafficFailureStage::Watch,
                    );
                    observation.record_failure(failure);
                    return Err(failure);
                };
                expected_sequence = next_sequence;
            }
        }
    }
}

fn observe_applied_records(
    operation: &ReplicationOp,
    traffic_keys: &[SessionKey],
    watch_traffic_generations: &[AtomicU64],
) -> Result<u64, QualificationTrafficFailureCode> {
    if traffic_keys.len() != watch_traffic_generations.len() {
        return Err(QualificationTrafficFailureCode::InvariantViolation);
    }
    let mut count = 0_u64;
    let mut pending = vec![operation];
    while let Some(operation) = pending.pop() {
        match operation {
            ReplicationOp::CompareAndSet {
                key, new_record, ..
            } => {
                count = count.saturating_add(1);
                if let Some(node_index) = traffic_keys.iter().position(|candidate| candidate == key)
                {
                    if new_record.key != *key {
                        return Err(QualificationTrafficFailureCode::InvariantViolation);
                    }
                    let generation = new_record.generation.get();
                    let previous = watch_traffic_generations[node_index].load(Ordering::Acquire);
                    if previous.checked_add(1) != Some(generation) {
                        return Err(QualificationTrafficFailureCode::InvariantViolation);
                    }
                    watch_traffic_generations[node_index].store(generation, Ordering::Release);
                }
            }
            ReplicationOp::Batch { ops } => pending.extend(ops.iter().rev()),
            ReplicationOp::DeleteFenced { .. }
            | ReplicationOp::RefreshTtl { .. }
            | ReplicationOp::AcquireLease { .. }
            | ReplicationOp::RenewLease { .. }
            | ReplicationOp::ReleaseLease { .. } => {}
        }
    }
    Ok(count)
}

fn reconcile_applied_traffic_records(
    operation: &ReplicationOp,
    traffic_keys: &[SessionKey],
    traffic_generations: &mut [u64],
    traffic_record_fences: &mut [u64],
    seed: u64,
    member_count: usize,
) -> Result<(), QualificationTrafficFailureCode> {
    if traffic_keys.len() != member_count
        || traffic_generations.len() != member_count
        || traffic_record_fences.len() != member_count
    {
        return Err(QualificationTrafficFailureCode::InvariantViolation);
    }
    let mut pending = vec![operation];
    while let Some(operation) = pending.pop() {
        match operation {
            ReplicationOp::CompareAndSet {
                key, new_record, ..
            } => {
                let Some(node_index) = traffic_keys.iter().position(|candidate| candidate == key)
                else {
                    continue;
                };
                let generation = new_record.generation.get();
                let expected_record = expected_traffic_record(
                    key,
                    seed,
                    member_count,
                    node_index,
                    generation,
                    new_record.fence.get(),
                )?;
                if new_record.fence.get() == 0
                    || !traffic_record_is_exact(&expected_record, new_record)
                    || traffic_generations[node_index].checked_add(1) != Some(generation)
                {
                    return Err(QualificationTrafficFailureCode::InvariantViolation);
                }
                traffic_generations[node_index] = generation;
                traffic_record_fences[node_index] = new_record.fence.get();
            }
            ReplicationOp::Batch { ops } => pending.extend(ops.iter().rev()),
            ReplicationOp::DeleteFenced { .. }
            | ReplicationOp::RefreshTtl { .. }
            | ReplicationOp::AcquireLease { .. }
            | ReplicationOp::RenewLease { .. }
            | ReplicationOp::ReleaseLease { .. } => {}
        }
    }
    Ok(())
}

fn expected_traffic_record(
    key: &SessionKey,
    seed: u64,
    member_count: usize,
    node_index: usize,
    generation: u64,
    record_fence: u64,
) -> Result<StoredSessionRecord, QualificationTrafficFailureCode> {
    if generation == 0 || record_fence == 0 {
        return Err(QualificationTrafficFailureCode::InvariantViolation);
    }
    let owner = OwnerId::new(format!("rotation-traffic-owner-{node_index}"))
        .map_err(|_| QualificationTrafficFailureCode::InvariantViolation)?;
    Ok(StoredSessionRecord {
        key: key.clone(),
        generation: Generation::new(generation),
        owner,
        fence: FenceToken::new(record_fence),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static(QUALIFICATION_TRAFFIC_STATE_TYPE),
        expires_at: None,
        payload: EncryptedSessionPayload::new(
            qualification_traffic_value(seed, member_count, node_index, generation).as_bytes(),
        ),
    })
}

#[allow(clippy::too_many_arguments)]
async fn restart_traffic_record_is_exact(
    protected: &ProtectedStore,
    key: &SessionKey,
    seed: u64,
    member_count: usize,
    node_index: usize,
    generation: u64,
    record_fence: u64,
    deadline: tokio::time::Instant,
) -> bool {
    let record = match tokio::time::timeout_at(deadline, protected.get(key)).await {
        Ok(Ok(record)) => record,
        Ok(Err(_)) | Err(_) => return false,
    };
    if generation == 0 {
        return record_fence == 0 && record.is_none();
    }
    let Ok(expected) = expected_traffic_record(
        key,
        seed,
        member_count,
        node_index,
        generation,
        record_fence,
    ) else {
        return false;
    };
    record.is_some_and(|record| traffic_record_is_exact(&expected, &record))
}

fn qualification_traffic_key(node_index: usize) -> Result<SessionKey, ()> {
    qualification_key(&format!("rotation-traffic-{node_index}"))
}

fn lifecycle_metrics(empty_vote_dispatches: u64) -> QualificationConnectionLifecycleMetrics {
    QualificationConnectionLifecycleMetrics {
        retirement_maximum_age: METRICS
            .session_net_lifecycle_retirement_maximum_age
            .load(Ordering::Relaxed),
        retirement_local_leaf_expiry: METRICS
            .session_net_lifecycle_retirement_local_leaf_expiry
            .load(Ordering::Relaxed),
        retirement_peer_leaf_expiry: METRICS
            .session_net_lifecycle_retirement_peer_leaf_expiry
            .load(Ordering::Relaxed),
        retirement_local_certificate_chain_expiry: METRICS
            .session_net_lifecycle_retirement_local_certificate_chain_expiry
            .load(Ordering::Relaxed),
        retirement_peer_certificate_chain_expiry: METRICS
            .session_net_lifecycle_retirement_peer_certificate_chain_expiry
            .load(Ordering::Relaxed),
        retirement_material_epoch: METRICS
            .session_net_lifecycle_retirement_material_epoch
            .load(Ordering::Relaxed),
        retirement_explicit: METRICS
            .session_net_lifecycle_retirement_explicit
            .load(Ordering::Relaxed),
        retirement_idle_timeout: METRICS
            .session_net_lifecycle_retirement_idle_timeout
            .load(Ordering::Relaxed),
        active_connections: METRICS
            .session_net_lifecycle_active_connections
            .load(Ordering::Relaxed),
        draining_connections: METRICS
            .session_net_lifecycle_draining_connections
            .load(Ordering::Relaxed),
        drain_started: METRICS
            .session_net_lifecycle_drain_started
            .load(Ordering::Relaxed),
        drain_completed: METRICS
            .session_net_lifecycle_drain_completed
            .load(Ordering::Relaxed),
        drain_overruns: METRICS
            .session_net_lifecycle_drain_overruns
            .load(Ordering::Relaxed),
        connection_attempts: METRICS
            .session_net_connection_attempts
            .load(Ordering::Relaxed),
        connection_successes: METRICS
            .session_net_connection_successes
            .load(Ordering::Relaxed),
        connection_failure_transport: METRICS
            .session_net_connection_failure_transport
            .load(Ordering::Relaxed),
        connection_failure_authentication: METRICS
            .session_net_connection_failure_authentication
            .load(Ordering::Relaxed),
        connection_failure_timeout: METRICS
            .session_net_connection_failure_timeout
            .load(Ordering::Relaxed),
        connection_superseded: METRICS
            .session_net_connection_superseded
            .load(Ordering::Relaxed),
        connection_abandoned: METRICS
            .session_net_connection_abandoned
            .load(Ordering::Relaxed),
        connection_failure_protocol: METRICS
            .session_net_connection_failure_protocol
            .load(Ordering::Relaxed),
        connection_failure_backend: METRICS
            .session_net_connection_failure_backend
            .load(Ordering::Relaxed),
        reconnect_attempts: METRICS
            .session_net_reconnect_attempts
            .load(Ordering::Relaxed),
        reconnect_failures: METRICS
            .session_net_reconnect_failures
            .load(Ordering::Relaxed),
        empty_vote_dispatches,
    }
}

const QUALIFICATION_MAX_ENDPOINT_ADDRESSES: usize = 16;

async fn resolve_canonical_endpoint(
    endpoint_host: String,
    endpoint_port: u16,
) -> io::Result<SocketAddr> {
    let mut addresses = tokio::net::lookup_host((endpoint_host.as_str(), endpoint_port)).await?;
    addresses
        .by_ref()
        .take(QUALIFICATION_MAX_ENDPOINT_ADDRESSES)
        .find(|address| is_admissible_peer_address(*address))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "peer endpoint unavailable"))
}

fn is_admissible_peer_address(address: SocketAddr) -> bool {
    if address.port() == 0 || address.ip().is_unspecified() {
        return false;
    }
    let ip = address.ip();
    if ip.is_loopback() || ip.is_multicast() {
        return false;
    }
    !matches!(ip, IpAddr::V4(value) if value == Ipv4Addr::BROADCAST)
}

async fn prepare_transport(
    config: &QualificationNodeConfig,
    local_binding: &LocalReplicaBinding,
    consensus_identity: SessionConsensusIdentity,
    rpc_gate: QualificationConsensusRpcGate,
) -> Result<
    (
        BTreeMap<SessionConsensusNodeId, Arc<dyn SessionConsensusPeer>>,
        QualificationServerTransport,
        QualificationTransportRuntime,
    ),
    NodeFailure,
> {
    match &config.transport {
        QualificationTransportConfig::LoopbackPlaintextTestOnly => {
            #[cfg(feature = "foundation-insecure")]
            {
                let mut peers = BTreeMap::new();
                for member in &config.members {
                    if member.node_index == config.node_index {
                        continue;
                    }
                    let binding = local_binding
                        .bind_remote(
                            ReplicaId::new(member.replica_id.clone()).map_err(|_| NodeFailure)?,
                        )
                        .map_err(|_| NodeFailure)?;
                    let node_id = binding.remote_consensus_node_id();
                    let dial_addr = member.dial_addr.ok_or(NodeFailure)?;
                    let peer: Arc<dyn SessionConsensusPeer> = Arc::new(
                        RemoteSessionConsensusPeer::new_insecure(binding, dial_addr, None),
                    );
                    peers.insert(
                        node_id,
                        Arc::new(QualificationGatedConsensusPeer::new(peer, rpc_gate.clone()))
                            as Arc<dyn SessionConsensusPeer>,
                    );
                }
                Ok((
                    peers,
                    QualificationServerTransport::FoundationPlaintext,
                    QualificationTransportRuntime::FoundationPlaintext,
                ))
            }
            #[cfg(not(feature = "foundation-insecure"))]
            {
                Err(NodeFailure)
            }
        }
        QualificationTransportConfig::ProjectedMtls(projected) => {
            let lifecycle = projected.lifecycle.to_policy().map_err(|_| NodeFailure)?;
            let source = ProjectedSvidSource::new_authoritative(
                &projected.projected_volume_root,
                &projected.certificate_file,
                &projected.private_key_file,
                projected.trust_bundle_files.clone(),
                Some(Duration::from_millis(projected.poll_interval_millis)),
            )
            .map_err(|_| NodeFailure)?;
            source
                .wait_for_initial_identity(Duration::from_millis(config.operation_timeout_millis))
                .await
                .map_err(|_| NodeFailure)?;

            let local_spiffe_id =
                SpiffeId::new(config.members[config.node_index].tls_identity.clone())
                    .map_err(|_| NodeFailure)?;
            let controller =
                TlsMaterialController::new_pinned_from_projected_source(&source, local_spiffe_id)
                    .map_err(|_| NodeFailure)?;
            let client_config = TlsConfigBuilder::from_material_controller(controller.clone())
                .allow_any_trusted_peer()
                .build_authenticated_client_config()
                .map_err(|_| NodeFailure)?;
            let server_config = TlsConfigBuilder::from_material_controller(controller)
                .allow_any_trusted_peer()
                .build_authenticated_server_config()
                .map_err(|_| NodeFailure)?;
            if !matches!(
                client_config.material_status().availability(),
                opc_tls::TlsMaterialAvailability::Ready
            ) {
                return Err(NodeFailure);
            }

            let reauthentication = SessionReauthenticationControl::new();
            let mut peers = BTreeMap::new();
            let mut directed_peers = BTreeMap::new();
            for member in &config.members {
                if member.node_index == config.node_index {
                    continue;
                }
                let binding = local_binding
                    .bind_remote(
                        ReplicaId::new(member.replica_id.clone()).map_err(|_| NodeFailure)?,
                    )
                    .map_err(|_| NodeFailure)?;
                let node_id = binding.remote_consensus_node_id();
                let resolver_evidence = QualificationResolverEvidence::new();
                let resolver_evidence_for_call = resolver_evidence.clone();
                let reauthentication_for_resolver = reauthentication.clone();
                let resolver: RemoteAddrResolver = match projected.peer_routing {
                    QualificationPeerRouting::PinnedLoopbackTestOnly => {
                        let dial_addr = member.dial_addr.ok_or(NodeFailure)?;
                        Arc::new(move || {
                            let resolver_evidence = resolver_evidence_for_call.clone();
                            let reauthentication = reauthentication_for_resolver.clone();
                            Box::pin(async move {
                                resolver_evidence.record_resolution(reauthentication.generation());
                                Ok(dial_addr)
                            })
                        })
                    }
                    QualificationPeerRouting::CanonicalEndpointDns => {
                        let endpoint_host = member.endpoint_host.clone();
                        let endpoint_port = member.endpoint_port;
                        Arc::new(move || {
                            let resolver_evidence = resolver_evidence_for_call.clone();
                            let reauthentication = reauthentication_for_resolver.clone();
                            let endpoint_host = endpoint_host.clone();
                            Box::pin(async move {
                                let address =
                                    resolve_canonical_endpoint(endpoint_host, endpoint_port)
                                        .await?;
                                resolver_evidence.record_resolution(reauthentication.generation());
                                Ok(address)
                            })
                        })
                    }
                };
                let remote_peer = RemoteSessionConsensusPeer::new_profiled_with_resolver(
                    binding,
                    resolver,
                    client_config.clone(),
                )
                .with_connection_lifecycle(lifecycle)
                .with_reauthentication_control(reauthentication.clone());
                let peer =
                    QualificationGatedConsensusPeer::new(Arc::new(remote_peer), rpc_gate.clone());
                directed_peers.insert(
                    member.node_index,
                    QualificationDirectedPeer {
                        peer: peer.clone(),
                        resolver_evidence,
                        required_resolution: None,
                    },
                );
                peers.insert(node_id, Arc::new(peer) as Arc<dyn SessionConsensusPeer>);
            }

            Ok((
                peers,
                QualificationServerTransport::ProjectedMtls(Box::new(
                    QualificationProjectedMtlsServerTransport {
                        server_config,
                        lifecycle,
                        reauthentication: reauthentication.clone(),
                    },
                )),
                QualificationTransportRuntime::ProjectedMtls(Box::new(
                    QualificationProjectedMtlsRuntime {
                        source,
                        client_config,
                        reauthentication,
                        directed_peers,
                        consensus_identity,
                        local_node_id: local_binding.local_consensus_node_id(),
                    },
                )),
            ))
        }
    }
}

fn validate_new_lease_handle<T>(
    leases: &HashMap<String, T>,
    lease_handle: &str,
) -> Result<(), QualificationNodeErrorCode> {
    if leases.contains_key(lease_handle) {
        Err(QualificationNodeErrorCode::LeaseHandleDuplicate)
    } else if leases.len() >= QUALIFICATION_MAX_LEASE_HANDLES {
        Err(QualificationNodeErrorCode::InvalidRequest)
    } else {
        Ok(())
    }
}

fn mark_released_lease(released: &mut bool, release_succeeded: bool) {
    if release_succeeded {
        *released = true;
    }
}

fn qualification_key(stable_id: &str) -> Result<SessionKey, ()> {
    Ok(SessionKey {
        tenant: TenantId::new(QUALIFICATION_TENANT).map_err(|_| ())?,
        nf_kind: NetworkFunctionKind::new("smf").map_err(|_| ())?,
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::copy_from_slice(stable_id.as_bytes())
            .try_into()
            .map_err(|_| ())?,
    })
}

fn map_lease_error(error: &LeaseError) -> QualificationNodeErrorCode {
    match error {
        LeaseError::AlreadyHeld
        | LeaseError::Expired
        | LeaseError::StaleFence
        | LeaseError::NotFound => QualificationNodeErrorCode::LeaseRejected,
        LeaseError::InvalidSessionTtl => QualificationNodeErrorCode::InvalidRequest,
        LeaseError::OperationOutcomeUnavailable | LeaseError::Backend(_) => {
            QualificationNodeErrorCode::BackendUnavailable
        }
    }
}

fn map_store_error(error: &StoreError) -> QualificationNodeErrorCode {
    match error {
        StoreError::BackendUnavailable(_)
        | StoreError::BackendOperationOutcomeUnavailable
        | StoreError::CasIdempotencyOutcomeUnavailable
        | StoreError::Crypto(_)
        | StoreError::Serialization(_) => QualificationNodeErrorCode::BackendUnavailable,
        _ => QualificationNodeErrorCode::MutationRejected,
    }
}

fn load_config(path: &Path) -> Result<QualificationNodeConfig, NodeFailure> {
    let file = File::open(path).map_err(|_| NodeFailure)?;
    let mut bounded = file.take(QUALIFICATION_MAX_CONFIG_BYTES + 1);
    let mut encoded = Vec::new();
    bounded.read_to_end(&mut encoded).map_err(|_| NodeFailure)?;
    if encoded.is_empty() || encoded.len() as u64 > QUALIFICATION_MAX_CONFIG_BYTES {
        return Err(NodeFailure);
    }
    let config: QualificationNodeConfig =
        serde_json::from_slice(&encoded).map_err(|_| NodeFailure)?;
    config.validate().map_err(|_| NodeFailure)?;
    Ok(config)
}

fn secure_qualification_paths(config: &QualificationNodeConfig) -> Result<(), NodeFailure> {
    let workspace = fs::canonicalize(&config.workspace_directory).map_err(|_| NodeFailure)?;
    if workspace.parent().is_none() {
        return Err(NodeFailure);
    }
    let database_parent = config.database_path.parent().ok_or(NodeFailure)?;
    let database_parent = fs::canonicalize(database_parent).map_err(|_| NodeFailure)?;
    if !database_parent.starts_with(&workspace) {
        return Err(NodeFailure);
    }
    if let Ok(metadata) = fs::symlink_metadata(&config.database_path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(NodeFailure);
        }
        let database = fs::canonicalize(&config.database_path).map_err(|_| NodeFailure)?;
        if !database.starts_with(&workspace) {
            return Err(NodeFailure);
        }
    }
    fs::create_dir_all(&config.snapshot_directory).map_err(|_| NodeFailure)?;
    let snapshots = fs::canonicalize(&config.snapshot_directory).map_err(|_| NodeFailure)?;
    if !snapshots.starts_with(&workspace) {
        return Err(NodeFailure);
    }
    if let QualificationTransportConfig::ProjectedMtls(projected) = &config.transport {
        let metadata =
            fs::symlink_metadata(&projected.projected_volume_root).map_err(|_| NodeFailure)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(NodeFailure);
        }
        let projected_root =
            fs::canonicalize(&projected.projected_volume_root).map_err(|_| NodeFailure)?;
        if !projected_root.starts_with(&workspace) || projected_root == workspace {
            return Err(NodeFailure);
        }
    }
    Ok(())
}

struct NodeArguments {
    config_path: PathBuf,
    node_index: usize,
    bind_addr: SocketAddr,
}

fn arguments() -> Result<NodeArguments, NodeFailure> {
    let mut args = env::args_os();
    let _program = args.next().ok_or(NodeFailure)?;
    if args.next().as_deref() != Some(std::ffi::OsStr::new("--config")) {
        return Err(NodeFailure);
    }
    let config_path = PathBuf::from(args.next().ok_or(NodeFailure)?);
    if args.next().as_deref() != Some(std::ffi::OsStr::new("--node-index")) {
        return Err(NodeFailure);
    }
    let node_index = args
        .next()
        .and_then(|value| value.into_string().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value < 5)
        .ok_or(NodeFailure)?;
    if args.next().as_deref() != Some(std::ffi::OsStr::new("--bind-addr")) {
        return Err(NodeFailure);
    }
    let bind_addr = args
        .next()
        .and_then(|value| value.into_string().ok())
        .and_then(|value| value.parse::<SocketAddr>().ok())
        .ok_or(NodeFailure)?;
    if args.next().is_some() || !config_path.is_absolute() {
        return Err(NodeFailure);
    }
    Ok(NodeArguments {
        config_path,
        node_index,
        bind_addr,
    })
}

fn run() -> Result<(), NodeFailure> {
    let arguments = arguments()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .map_err(|_| NodeFailure)?;
    let listener = runtime
        .block_on(TcpListener::bind(arguments.bind_addr))
        .map_err(|_| NodeFailure)?;
    let bind_addr = listener.local_addr().map_err(|_| NodeFailure)?;
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = BufWriter::new(stdout.lock());
    write_json_line(
        &mut writer,
        &QualificationNodeReply::Bound {
            node_index: arguments.node_index,
            bind_addr,
        },
    )
    .map_err(|_| NodeFailure)?;

    let configure = read_bounded_json_line::<_, QualificationNodeCommand>(&mut reader)
        .map_err(|_| NodeFailure)?
        .ok_or(NodeFailure)?;
    if !matches!(configure, QualificationNodeCommand::Configure) {
        return Err(NodeFailure);
    }
    let config = load_config(&arguments.config_path)?;
    if config.node_index != arguments.node_index || config.validate_bind_addr(bind_addr).is_err() {
        return Err(NodeFailure);
    }
    let mut node = runtime.block_on(QualificationNode::open(&config, listener))?;
    write_json_line(
        &mut writer,
        &QualificationNodeReply::Started {
            node_index: config.node_index,
        },
    )
    .map_err(|_| NodeFailure)?;

    loop {
        let command = match read_bounded_json_line::<_, QualificationNodeCommand>(&mut reader) {
            Ok(Some(command)) => command,
            Ok(None) => break,
            Err(_) => {
                write_json_line(
                    &mut writer,
                    &QualificationNodeReply::Error {
                        code: QualificationNodeErrorCode::InvalidRequest,
                    },
                )
                .map_err(|_| NodeFailure)?;
                continue;
            }
        };
        if command.validate().is_err() {
            write_json_line(
                &mut writer,
                &QualificationNodeReply::Error {
                    code: QualificationNodeErrorCode::InvalidRequest,
                },
            )
            .map_err(|_| NodeFailure)?;
            continue;
        }
        let shutdown = matches!(command, QualificationNodeCommand::Shutdown);
        let reply = runtime.block_on(node.handle(command));
        write_json_line(&mut writer, &reply).map_err(|_| NodeFailure)?;
        if shutdown {
            break;
        }
    }
    runtime.block_on(node.stop_server());
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            eprintln!("qualification node failed");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_dns_resolution_rejects_local_or_non_routable_results() {
        for address in [
            "127.0.0.1:7443",
            "[::1]:7443",
            "0.0.0.0:7443",
            "[::]:7443",
            "224.0.0.1:7443",
            "255.255.255.255:7443",
            "192.0.2.10:0",
        ] {
            assert!(!is_admissible_peer_address(
                address.parse().expect("test socket address")
            ));
        }
        assert!(is_admissible_peer_address(
            "192.0.2.10:7443".parse().expect("test peer address")
        ));
        assert!(is_admissible_peer_address(
            "[2001:db8::10]:7443"
                .parse()
                .expect("test IPv6 peer address")
        ));
    }

    #[test]
    fn traffic_cancellation_checkpoint_distinguishes_open_sent_and_closed_channels() {
        let (sender, mut cancellation) = oneshot::channel();
        let mut shutdown_deadline = None;
        assert!(!traffic_cancellation_requested(
            &mut cancellation,
            &mut shutdown_deadline
        ));
        let expected_deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        sender
            .send(expected_deadline)
            .expect("traffic cancellation receiver open");
        assert!(traffic_cancellation_requested(
            &mut cancellation,
            &mut shutdown_deadline
        ));
        assert_eq!(shutdown_deadline, Some(expected_deadline));

        let (sender, mut cancellation) = oneshot::channel::<tokio::time::Instant>();
        drop(sender);
        let mut shutdown_deadline = None;
        assert!(traffic_cancellation_requested(
            &mut cancellation,
            &mut shutdown_deadline
        ));
        assert!(shutdown_deadline.is_some());
    }

    #[test]
    fn traffic_shutdown_deadline_is_inclusive() {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        assert!(!traffic_shutdown_deadline_reached(
            Some(deadline),
            deadline - Duration::from_nanos(1)
        ));
        assert!(traffic_shutdown_deadline_reached(Some(deadline), deadline));
        assert!(traffic_shutdown_deadline_reached(
            Some(deadline),
            deadline + Duration::from_nanos(1)
        ));
        assert!(!traffic_shutdown_deadline_reached(None, deadline));
    }

    #[test]
    fn traffic_observation_retains_only_the_last_proven_authoritative_head() {
        let observation = QualificationTrafficObservation::new(41, 3);
        assert_eq!(observation.authoritative_replication_head(), 41);
        observation.record_authoritative_replication_head(44);
        assert_eq!(observation.authoritative_replication_head(), 44);
        assert_eq!(observation.watch_sequence.load(Ordering::Acquire), 41);
        observation.record_mutation_resume(7, 11);
        assert_eq!(
            observation
                .mutation_resume_generation
                .load(Ordering::Acquire),
            7
        );
        assert_eq!(
            observation
                .mutation_resume_record_fence
                .load(Ordering::Acquire),
            11
        );
        assert_eq!(observation.last_generation.load(Ordering::Acquire), 7);
        assert_eq!(observation.last_record_fence.load(Ordering::Acquire), 11);
        assert!(!observation
            .synthetic_release_response_loss_pending
            .load(Ordering::Acquire));
    }

    #[test]
    fn traffic_failure_diagnostic_is_atomic_closed_and_redacted() {
        let observation = QualificationTrafficObservation::new(0, 3);
        let first = QualificationTrafficFailure::store(
            QualificationTrafficFailureCode::BackendUnavailable,
            QualificationTrafficFailureStage::CompareAndSet,
            &StoreError::CasIdempotencyOutcomeUnavailable,
        );
        observation.record_failure(first);
        observation.record_failure(QualificationTrafficFailure::lease(
            QualificationTrafficFailureCode::LeaseRejected,
            QualificationTrafficFailureStage::LeaseRenew,
            &LeaseError::Expired,
        ));
        assert_eq!(observation.failure(), Some(first));

        assert_eq!(
            qualification_store_error_class(&StoreError::BackendUnavailable(
                "must-not-cross-control-boundary".to_owned()
            )),
            QualificationTrafficErrorClass::BackendUnavailable
        );
        assert_eq!(
            qualification_store_error_class(&StoreError::BackendOperationOutcomeUnavailable),
            QualificationTrafficErrorClass::BackendOperationOutcomeUnavailable
        );
        assert_eq!(
            qualification_store_error_class(&StoreError::StaleFence),
            QualificationTrafficErrorClass::LeaseLostOrInvalid
        );
        assert_eq!(
            qualification_store_error_class(&StoreError::Crypto(
                "must-not-cross-control-boundary".to_owned()
            )),
            QualificationTrafficErrorClass::Other
        );
        assert_eq!(
            qualification_lease_error_class(&LeaseError::OperationOutcomeUnavailable),
            QualificationTrafficErrorClass::BackendOperationOutcomeUnavailable
        );
        assert_eq!(
            qualification_lease_error_class(&LeaseError::Backend(
                "must-not-cross-control-boundary".to_owned()
            )),
            QualificationTrafficErrorClass::BackendUnavailable
        );

        assert!(traffic_failure_is_recoverable(first));
        assert!(traffic_failure_is_recoverable(
            QualificationTrafficFailure::lease(
                QualificationTrafficFailureCode::LeaseRejected,
                QualificationTrafficFailureStage::LeaseRelease,
                &LeaseError::OperationOutcomeUnavailable,
            )
        ));
        assert!(!traffic_failure_is_recoverable(
            QualificationTrafficFailure::lease(
                QualificationTrafficFailureCode::LeaseRejected,
                QualificationTrafficFailureStage::LeaseRenew,
                &LeaseError::Expired,
            )
        ));
        assert!(!traffic_failure_is_recoverable(
            QualificationTrafficFailure::fixed(
                QualificationTrafficFailureCode::InvariantViolation,
                QualificationTrafficFailureStage::Get,
            )
        ));

        let recovery_started_at = tokio::time::Instant::now();
        let recovery_elapsed_millis = QUALIFICATION_TRAFFIC_AVAILABILITY_RECOVERY_MILLIS + 123;
        let observed_at = recovery_started_at + Duration::from_millis(recovery_elapsed_millis);
        let deadline_failure = QualificationTrafficFailure::recovery_deadline_exceeded_at(
            QualificationTrafficFailureStage::LeaseAcquire,
            recovery_started_at,
            observed_at,
        );
        assert_eq!(
            deadline_failure,
            QualificationTrafficFailure {
                code: QualificationTrafficFailureCode::AvailabilityRecoveryDeadlineExceeded,
                stage: QualificationTrafficFailureStage::LeaseAcquire,
                error_class: QualificationTrafficErrorClass::BackendUnavailable,
                recovery_elapsed_millis: Some(recovery_elapsed_millis),
            }
        );
        assert!(!traffic_failure_is_recoverable(deadline_failure));
    }

    #[test]
    fn traffic_recovery_retains_authority_only_for_known_outcome_checkpoints() {
        for stage in [
            QualificationTrafficFailureStage::Get,
            QualificationTrafficFailureStage::RestoreScan,
            QualificationTrafficFailureStage::ReadinessProbe,
        ] {
            assert!(traffic_failure_retains_known_authority(
                QualificationTrafficFailure::backend_unavailable(
                    QualificationTrafficFailureCode::BackendUnavailable,
                    stage,
                )
            ));
        }
        for stage in [
            QualificationTrafficFailureStage::LeaseRenew,
            QualificationTrafficFailureStage::CompareAndSet,
            QualificationTrafficFailureStage::LeaseRelease,
            QualificationTrafficFailureStage::LeaseAcquire,
            QualificationTrafficFailureStage::Watch,
            QualificationTrafficFailureStage::TaskJoin,
        ] {
            assert!(!traffic_failure_retains_known_authority(
                QualificationTrafficFailure::backend_unavailable(
                    QualificationTrafficFailureCode::BackendUnavailable,
                    stage,
                )
            ));
        }
        assert!(!traffic_failure_retains_known_authority(
            QualificationTrafficFailure::fixed(
                QualificationTrafficFailureCode::InvariantViolation,
                QualificationTrafficFailureStage::Get,
            )
        ));
    }

    #[test]
    fn traffic_availability_interruption_budget_is_exact_and_resets_consecutive_count() {
        let observation = QualificationTrafficObservation::new(0, 3);
        let mut consecutive = 0;
        for expected in 1..=QUALIFICATION_TRAFFIC_AVAILABILITY_INTERRUPTION_BUDGET_PER_NODE {
            assert!(observation.record_availability_interruption(&mut consecutive));
            assert_eq!(consecutive, expected);
        }
        assert!(!observation.record_availability_interruption(&mut consecutive));
        assert_eq!(
            observation
                .availability_interruptions
                .load(Ordering::Acquire),
            QUALIFICATION_TRAFFIC_AVAILABILITY_INTERRUPTION_BUDGET_PER_NODE
        );
        assert_eq!(
            observation
                .max_consecutive_availability_interruptions
                .load(Ordering::Acquire),
            QUALIFICATION_TRAFFIC_AVAILABILITY_INTERRUPTION_BUDGET_PER_NODE
        );
        observation.record_availability_recovery(&mut consecutive);
        assert_eq!(consecutive, 0);
        assert_eq!(
            observation.availability_recoveries.load(Ordering::Acquire),
            QUALIFICATION_TRAFFIC_AVAILABILITY_INTERRUPTION_BUDGET_PER_NODE
        );
    }

    #[derive(Debug)]
    struct CountingPeer {
        node_id: SessionConsensusNodeId,
        calls: Arc<AtomicU64>,
        timeout_millis: Arc<AtomicU64>,
    }

    #[async_trait::async_trait]
    impl SessionConsensusPeer for CountingPeer {
        fn node_id(&self) -> SessionConsensusNodeId {
            self.node_id
        }

        async fn call(
            &self,
            _request: SessionConsensusWireRequest,
        ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(SessionConsensusWireResponse {
                result: Ok(Vec::new()),
            })
        }

        async fn call_with_timeout(
            &self,
            request: SessionConsensusWireRequest,
            timeout: Duration,
        ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
            self.timeout_millis.store(
                u64::try_from(timeout.as_millis()).expect("bounded test timeout"),
                Ordering::SeqCst,
            );
            self.call(request).await
        }
    }

    #[derive(Debug)]
    struct CountingHandler {
        calls: Arc<AtomicU64>,
    }

    #[async_trait::async_trait]
    impl SessionConsensusRpcHandler for CountingHandler {
        async fn handle(
            &self,
            _authenticated_sender: SessionConsensusNodeId,
            _request: SessionConsensusWireRequest,
        ) -> SessionConsensusWireResponse {
            self.calls.fetch_add(1, Ordering::SeqCst);
            SessionConsensusWireResponse {
                result: Ok(Vec::new()),
            }
        }
    }

    fn gate_test_request(sender: SessionConsensusNodeId) -> SessionConsensusWireRequest {
        let identity = SessionConsensusIdentity::new(
            opc_session_store::SessionConsensusClusterId::new("qualification-rpc-gate-test")
                .expect("cluster identity"),
            opc_session_store::SessionConsensusConfigurationId::from_bytes([0x64; 32]),
            opc_session_store::SessionConsensusConfigurationEpoch::new(1)
                .expect("configuration epoch"),
        );
        SessionConsensusWireRequest::try_new(
            identity,
            sender,
            SessionConsensusRpcFamily::Vote,
            Vec::new(),
        )
        .expect("bounded request")
    }

    #[tokio::test]
    async fn rpc_gate_fails_closed_before_outbound_or_inbound_dispatch() {
        let sender = SessionConsensusNodeId::new(1).expect("sender node ID");
        let target = SessionConsensusNodeId::new(2).expect("target node ID");
        let gate = QualificationConsensusRpcGate::available();
        gate.set(QualificationConsensusRpcAvailability::Unavailable);

        let outbound_calls = Arc::new(AtomicU64::new(0));
        let outbound_timeout_millis = Arc::new(AtomicU64::new(0));
        let peer = QualificationGatedConsensusPeer::new(
            Arc::new(CountingPeer {
                node_id: target,
                calls: Arc::clone(&outbound_calls),
                timeout_millis: Arc::clone(&outbound_timeout_millis),
            }),
            gate.clone(),
        );
        assert_eq!(
            peer.call(gate_test_request(sender)).await,
            Err(SessionConsensusPeerError::Unavailable)
        );
        assert_eq!(outbound_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            peer.call_with_timeout(gate_test_request(sender), Duration::from_millis(137))
                .await,
            Err(SessionConsensusPeerError::Unavailable)
        );
        assert_eq!(outbound_calls.load(Ordering::SeqCst), 0);
        assert_eq!(outbound_timeout_millis.load(Ordering::SeqCst), 0);

        let inbound_calls = Arc::new(AtomicU64::new(0));
        let handler = QualificationGatedConsensusRpcHandler {
            inner: Arc::new(CountingHandler {
                calls: Arc::clone(&inbound_calls),
            }),
            gate: gate.clone(),
        };
        assert_eq!(
            handler.handle(sender, gate_test_request(sender)).await,
            SessionConsensusWireResponse {
                result: Err(SessionConsensusPeerError::Unavailable),
            }
        );
        assert_eq!(inbound_calls.load(Ordering::SeqCst), 0);

        gate.set(QualificationConsensusRpcAvailability::Available);
        assert!(peer.call(gate_test_request(sender)).await.is_ok());
        assert_eq!(outbound_calls.load(Ordering::SeqCst), 1);
        assert!(peer
            .call_with_timeout(gate_test_request(sender), Duration::from_millis(137))
            .await
            .is_ok());
        assert_eq!(outbound_calls.load(Ordering::SeqCst), 2);
        assert_eq!(outbound_timeout_millis.load(Ordering::SeqCst), 137);
        assert!(handler
            .handle(sender, gate_test_request(sender))
            .await
            .result
            .is_ok());
        assert_eq!(inbound_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn directed_proof_requires_resolution_after_the_requested_generation() {
        let evidence = QualificationResolverEvidence::new();
        let first = QualificationRequiredResolution {
            calls_before_request: evidence.calls(),
            reauthentication_generation: 1,
        };
        assert!(!evidence.proves(first));

        evidence.record_resolution(0);
        assert!(!evidence.proves(first));
        evidence.record_resolution(1);
        assert!(evidence.proves(first));

        let second = QualificationRequiredResolution {
            calls_before_request: evidence.calls(),
            reauthentication_generation: 2,
        };
        evidence.record_resolution(1);
        assert!(!evidence.proves(second));
        evidence.record_resolution(2);
        assert!(evidence.proves(second));
    }

    #[test]
    fn duplicate_and_bounded_lease_handles_fail_before_backend_work() {
        let mut leases = HashMap::new();
        leases.insert("existing".to_owned(), ());
        assert_eq!(
            validate_new_lease_handle(&leases, "existing"),
            Err(QualificationNodeErrorCode::LeaseHandleDuplicate)
        );
        for index in 1..QUALIFICATION_MAX_LEASE_HANDLES {
            leases.insert(format!("lease-{index}"), ());
        }
        assert_eq!(
            validate_new_lease_handle(&leases, "new"),
            Err(QualificationNodeErrorCode::InvalidRequest)
        );
    }

    #[test]
    fn release_retains_a_bounded_handle_for_stale_fence_probes() {
        let mut released = false;
        mark_released_lease(&mut released, false);
        assert!(!released);
        mark_released_lease(&mut released, true);
        assert!(released);

        let leases = HashMap::from([("lease".to_owned(), ())]);
        assert_eq!(
            validate_new_lease_handle(&leases, "lease"),
            Err(QualificationNodeErrorCode::LeaseHandleDuplicate)
        );
    }

    #[test]
    fn traffic_lease_contract_requires_preserved_renewal_and_advanced_reacquisition() {
        let key = qualification_key("traffic-lease-contract").expect("traffic key");
        let other_key = qualification_key("other-traffic-lease").expect("other traffic key");
        let owner = OwnerId::new("traffic-owner").expect("traffic owner");
        let other_owner = OwnerId::new("other-traffic-owner").expect("other traffic owner");

        assert!(lease_authority_is_preserved(
            &key, &owner, 7, &key, &owner, 7
        ));
        assert!(!lease_authority_is_preserved(
            &key, &owner, 7, &key, &owner, 8
        ));
        assert!(!lease_authority_is_preserved(
            &key, &owner, 7, &other_key, &owner, 7
        ));
        assert!(!lease_authority_is_preserved(
            &key,
            &owner,
            7,
            &key,
            &other_owner,
            7
        ));

        assert!(lease_authority_is_advanced(
            &key, &owner, 7, &key, &owner, 8
        ));
        assert!(!lease_authority_is_advanced(
            &key, &owner, 7, &key, &owner, 7
        ));
        assert!(!lease_authority_is_advanced(
            &key, &owner, 7, &key, &owner, 6
        ));
        assert!(!lease_authority_is_advanced(
            &key,
            &owner,
            7,
            &key,
            &other_owner,
            8
        ));
    }

    #[test]
    fn traffic_record_equality_rejects_every_metadata_substitution() {
        let expected = StoredSessionRecord {
            key: qualification_key("traffic-record-contract").expect("traffic key"),
            generation: Generation::new(9),
            owner: OwnerId::new("traffic-record-owner").expect("traffic owner"),
            fence: opc_session_store::FenceToken::new(11),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static(QUALIFICATION_TRAFFIC_STATE_TYPE),
            expires_at: None,
            payload: EncryptedSessionPayload::new(b"traffic-record-value"),
        };
        assert!(traffic_record_is_exact(&expected, &expected.clone()));

        let mut substitutions = Vec::new();
        let mut substituted = expected.clone();
        substituted.key = qualification_key("other-traffic-record").expect("other traffic key");
        substitutions.push(substituted);
        let mut substituted = expected.clone();
        substituted.generation = Generation::new(expected.generation.get() + 1);
        substitutions.push(substituted);
        let mut substituted = expected.clone();
        substituted.owner = OwnerId::new("other-traffic-record-owner").expect("other owner");
        substitutions.push(substituted);
        let mut substituted = expected.clone();
        substituted.fence = FenceToken::new(expected.fence.get() + 1);
        substitutions.push(substituted);
        let mut substituted = expected.clone();
        substituted.state_class = StateClass::ReplicatedDr;
        substitutions.push(substituted);
        let mut substituted = expected.clone();
        substituted.state_type = StateType::from_static("other-traffic-state");
        substitutions.push(substituted);
        let mut substituted = expected.clone();
        substituted.expires_at = Some(opc_types::Timestamp::now_utc());
        substitutions.push(substituted);
        let mut substituted = expected.clone();
        substituted.payload = EncryptedSessionPayload::new(b"other-traffic-record-value");
        substitutions.push(substituted);

        for substituted in substitutions {
            assert!(!traffic_record_is_exact(&expected, &substituted));
        }
    }

    #[test]
    fn traffic_record_reconciliation_accepts_only_the_exact_current_or_ambiguous_cas_result() {
        let member_count = 3;
        let node_index = 0;
        let seed = qualification_traffic_seed(member_count).expect("traffic seed");
        let key = qualification_traffic_key(node_index).expect("traffic key");
        let owner = OwnerId::new("rotation-traffic-owner-0").expect("traffic owner");
        let record = StoredSessionRecord {
            key: key.clone(),
            generation: Generation::new(8),
            owner: owner.clone(),
            fence: FenceToken::new(11),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static(QUALIFICATION_TRAFFIC_STATE_TYPE),
            expires_at: None,
            payload: EncryptedSessionPayload::new(
                qualification_traffic_value(seed, member_count, node_index, 8).as_bytes(),
            ),
        };
        assert_eq!(
            reconciled_traffic_record_identity(
                &record,
                &key,
                &owner,
                seed,
                member_count,
                node_index,
                7,
                9,
                Some(11),
                QualificationTrafficFailureStage::CompareAndSet,
            ),
            Some((8, 11))
        );
        assert!(reconciled_traffic_record_identity(
            &record,
            &key,
            &owner,
            seed,
            member_count,
            node_index,
            7,
            9,
            Some(11),
            QualificationTrafficFailureStage::Get,
        )
        .is_none());

        let mut substituted = record.clone();
        substituted.payload = EncryptedSessionPayload::new(b"untrusted-recovery-payload");
        assert!(reconciled_traffic_record_identity(
            &substituted,
            &key,
            &owner,
            seed,
            member_count,
            node_index,
            7,
            9,
            Some(11),
            QualificationTrafficFailureStage::CompareAndSet,
        )
        .is_none());

        let current = StoredSessionRecord {
            generation: Generation::new(7),
            fence: FenceToken::new(9),
            payload: EncryptedSessionPayload::new(
                qualification_traffic_value(seed, member_count, node_index, 7).as_bytes(),
            ),
            ..record
        };
        assert_eq!(
            reconciled_traffic_record_identity(
                &current,
                &key,
                &owner,
                seed,
                member_count,
                node_index,
                7,
                9,
                None,
                QualificationTrafficFailureStage::LeaseRelease,
            ),
            Some((7, 9))
        );
    }

    #[test]
    fn traffic_reconciliation_page_plan_enforces_total_and_page_boundaries() {
        assert_eq!(traffic_reconciliation_page_plan(7, 7, 0), Ok(None));
        assert_eq!(traffic_reconciliation_page_plan(8, 7, 0), Err(()));
        assert_eq!(
            traffic_reconciliation_page_plan(
                0,
                QUALIFICATION_TRAFFIC_WATCH_RECONCILIATION_MAX_ENTRIES,
                0,
            ),
            Ok(Some((
                1,
                QUALIFICATION_TRAFFIC_WATCH_RECONCILIATION_PAGE_ENTRIES,
            )))
        );
        assert_eq!(
            traffic_reconciliation_page_plan(
                0,
                QUALIFICATION_TRAFFIC_WATCH_RECONCILIATION_MAX_ENTRIES + 1,
                0,
            ),
            Err(())
        );
        assert_eq!(
            traffic_reconciliation_page_plan(
                10,
                11,
                QUALIFICATION_TRAFFIC_WATCH_RECONCILIATION_MAX_ENTRIES - 1,
            ),
            Ok(Some((11, 1)))
        );
        assert_eq!(
            traffic_reconciliation_page_plan(
                10,
                12,
                QUALIFICATION_TRAFFIC_WATCH_RECONCILIATION_MAX_ENTRIES - 1,
            ),
            Err(())
        );
    }

    fn reconciliation_cas(node_index: usize, generation: u64) -> ReplicationOp {
        let key = qualification_traffic_key(node_index).expect("traffic key");
        ReplicationOp::CompareAndSet {
            key: key.clone(),
            expected_generation: generation
                .checked_sub(1)
                .filter(|value| *value != 0)
                .map(Generation::new),
            credential_id: 1,
            guard_expires_at: opc_types::Timestamp::now_utc(),
            new_record: StoredSessionRecord {
                key,
                generation: Generation::new(generation),
                owner: OwnerId::new(format!("rotation-traffic-owner-{node_index}"))
                    .expect("traffic owner"),
                fence: opc_session_store::FenceToken::new(generation.saturating_add(1)),
                state_class: StateClass::AuthoritativeSession,
                state_type: StateType::from_static(QUALIFICATION_TRAFFIC_STATE_TYPE),
                expires_at: None,
                payload: EncryptedSessionPayload::new(
                    qualification_traffic_value(
                        qualification_traffic_seed(3).expect("traffic seed"),
                        3,
                        node_index,
                        generation,
                    )
                    .as_bytes(),
                ),
            },
        }
    }

    #[test]
    fn traffic_reconciliation_requires_strict_generations_and_exact_records() {
        let keys = (0..3)
            .map(qualification_traffic_key)
            .collect::<Result<Vec<_>, _>>()
            .expect("traffic keys");
        let seed = qualification_traffic_seed(3).expect("traffic seed");
        let mut generations = vec![0; 3];
        let mut fences = vec![0; 3];
        assert!(reconcile_applied_traffic_records(
            &reconciliation_cas(0, 1),
            &keys,
            &mut generations,
            &mut fences,
            seed,
            3,
        )
        .is_ok());
        assert_eq!(generations, vec![1, 0, 0]);
        assert_eq!(fences, vec![2, 0, 0]);
        assert!(reconcile_applied_traffic_records(
            &reconciliation_cas(0, 2),
            &keys,
            &mut generations,
            &mut fences,
            seed,
            3,
        )
        .is_ok());

        for (previous, generation) in [(0, 17), (2, 2), (2, 4), (u64::MAX, 1)] {
            let mut candidate = vec![previous, 0, 0];
            let mut candidate_fences = vec![0; 3];
            assert!(reconcile_applied_traffic_records(
                &reconciliation_cas(0, generation),
                &keys,
                &mut candidate,
                &mut candidate_fences,
                seed,
                3,
            )
            .is_err());
        }

        let mut malformed = reconciliation_cas(1, 1);
        let ReplicationOp::CompareAndSet { new_record, .. } = &mut malformed else {
            unreachable!()
        };
        new_record.payload = EncryptedSessionPayload::new(b"wrong-reconciled-value");
        assert!(reconcile_applied_traffic_records(
            &malformed,
            &keys,
            &mut [0; 3],
            &mut [0; 3],
            seed,
            3,
        )
        .is_err());
    }

    #[test]
    fn traffic_reconciliation_preserves_batch_operation_order() {
        let keys = (0..3)
            .map(qualification_traffic_key)
            .collect::<Result<Vec<_>, _>>()
            .expect("traffic keys");
        let seed = qualification_traffic_seed(3).expect("traffic seed");
        let mut generations = vec![0; 3];
        let mut fences = vec![0; 3];
        let batch = ReplicationOp::Batch {
            ops: vec![reconciliation_cas(1, 1), reconciliation_cas(1, 2)],
        };
        assert!(reconcile_applied_traffic_records(
            &batch,
            &keys,
            &mut generations,
            &mut fences,
            seed,
            3,
        )
        .is_ok());
        assert_eq!(generations, vec![0, 2, 0]);
        assert_eq!(fences, vec![0, 3, 0]);
    }
}
