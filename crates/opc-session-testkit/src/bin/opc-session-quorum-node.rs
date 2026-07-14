//! Private child-process node for experimental session-HA qualification.

use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
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
    EncryptingSessionBackend, Generation, LeaseError, LeaseGuard, OwnerId, QuorumReplicaDescriptor,
    QuorumTopologyConfig, ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain, ReplicaId,
    ReplicaTlsIdentity, ReplicationEntry, ReplicationOp, RestoreScanCursorProfile,
    RestoreScanRequest, SessionBackend, SessionConsensusIdentity, SessionConsensusNodeId,
    SessionConsensusPeer, SessionConsensusPeerError, SessionConsensusRpcFamily,
    SessionConsensusRpcHandler, SessionConsensusWireRequest, SessionConsensusWireResponse,
    SessionKey, SessionKeyType, SessionLeaseManager, SqliteSessionBackend, StateClass, StateType,
    StoreError, StoredSessionRecord, ValidatedQuorumTopology,
};
use opc_session_testkit::qualification::{
    qualification_owner_sha256, qualification_traffic_schedule_sha256, qualification_traffic_seed,
    qualification_traffic_value, qualification_value_sha256, read_bounded_json_line,
    write_json_line, QualificationConnectionLifecycleMetrics,
    QualificationConsensusRpcAvailability, QualificationNodeCommand, QualificationNodeConfig,
    QualificationNodeErrorCode, QualificationNodeReply, QualificationProjectedSvidStatus,
    QualificationReadinessCode, QualificationSecurityMetricsSnapshot,
    QualificationTlsMaterialStatus, QualificationTrafficFailureCode, QualificationTrafficState,
    QualificationTrafficStatus, QualificationTransportConfig,
    QUALIFICATION_INBOUND_CONNECTION_SLOTS, QUALIFICATION_MAX_CONFIG_BYTES,
    QUALIFICATION_MAX_LEASE_HANDLES, QUALIFICATION_TRAFFIC_MUTATION_DELAY_MIN_MILLIS,
    QUALIFICATION_TRAFFIC_MUTATION_DELAY_SPAN_MILLIS, QUALIFICATION_TRAFFIC_RESTORE_LIMIT,
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
const QUALIFICATION_TRAFFIC_TTL: Duration = Duration::from_secs(60 * 60);
const QUALIFICATION_KEY_BYTES: [u8; AES_256_GCM_SIV_KEY_LEN] = [0x5a; AES_256_GCM_SIV_KEY_LEN];

type ProtectedStore = EncryptingSessionBackend<ConsensusSessionStore, MemoryKeyProvider>;

struct QualificationLease {
    guard: LeaseGuard,
    released: bool,
}

#[derive(Debug, thiserror::Error)]
#[error("qualification node failed")]
struct NodeFailure;

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
    mutation_cancel: Option<oneshot::Sender<()>>,
    mutation_task: Option<JoinHandle<Result<(), QualificationTrafficFailureCode>>>,
    watch_cancel: Option<oneshot::Sender<()>>,
    watch_task: Option<JoinHandle<Result<(), QualificationTrafficFailureCode>>>,
}

struct QualificationTrafficObservation {
    failure: AtomicU8,
    mutation_cycles: AtomicU64,
    linearizable_reads: AtomicU64,
    lease_renewals: AtomicU64,
    lease_reacquisitions: AtomicU64,
    complete_restore_scans: AtomicU64,
    durable_readiness_probes: AtomicU64,
    last_generation: AtomicU64,
    last_record_fence: AtomicU64,
    watch_entries: AtomicU64,
    watch_applied_records: AtomicU64,
    watch_sequence: AtomicU64,
    watch_traffic_generations: Vec<AtomicU64>,
}

impl QualificationTrafficObservation {
    fn new(initial_watch_sequence: u64, member_count: usize) -> Self {
        Self {
            failure: AtomicU8::new(0),
            mutation_cycles: AtomicU64::new(0),
            linearizable_reads: AtomicU64::new(0),
            lease_renewals: AtomicU64::new(0),
            lease_reacquisitions: AtomicU64::new(0),
            complete_restore_scans: AtomicU64::new(0),
            durable_readiness_probes: AtomicU64::new(0),
            last_generation: AtomicU64::new(0),
            last_record_fence: AtomicU64::new(0),
            watch_entries: AtomicU64::new(0),
            watch_applied_records: AtomicU64::new(0),
            watch_sequence: AtomicU64::new(initial_watch_sequence),
            watch_traffic_generations: (0..member_count).map(|_| AtomicU64::new(0)).collect(),
        }
    }

    fn record_failure(&self, failure: QualificationTrafficFailureCode) {
        let _ = self.failure.compare_exchange(
            0,
            traffic_failure_code(failure),
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    fn failure(&self) -> Option<QualificationTrafficFailureCode> {
        match self.failure.load(Ordering::Acquire) {
            0 => None,
            1 => Some(QualificationTrafficFailureCode::BackendUnavailable),
            2 => Some(QualificationTrafficFailureCode::LeaseRejected),
            3 => Some(QualificationTrafficFailureCode::WatchUnavailable),
            4 => Some(QualificationTrafficFailureCode::RestoreScanRejected),
            5 => Some(QualificationTrafficFailureCode::ReadinessUnavailable),
            6 => Some(QualificationTrafficFailureCode::InvariantViolation),
            _ => Some(QualificationTrafficFailureCode::TaskJoinUnavailable),
        }
    }
}

const fn traffic_failure_code(failure: QualificationTrafficFailureCode) -> u8 {
    match failure {
        QualificationTrafficFailureCode::BackendUnavailable => 1,
        QualificationTrafficFailureCode::LeaseRejected => 2,
        QualificationTrafficFailureCode::WatchUnavailable => 3,
        QualificationTrafficFailureCode::RestoreScanRejected => 4,
        QualificationTrafficFailureCode::ReadinessUnavailable => 5,
        QualificationTrafficFailureCode::InvariantViolation => 6,
        QualificationTrafficFailureCode::TaskJoinUnavailable => 7,
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
        let expected_addr = config.members[config.node_index].dial_addr;
        if listener.local_addr().map_err(|_| NodeFailure)? != expected_addr {
            return Err(NodeFailure);
        }
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
        .await?;

        let backend = SqliteSessionBackend::open(&config.database_path).map_err(|_| NodeFailure)?;
        let store = Arc::new(
            ConsensusSessionStore::open_with_operation_timeout(
                topology,
                backend,
                &config.snapshot_directory,
                peers,
                Duration::from_millis(config.operation_timeout_millis),
            )
            .await
            .map_err(|_| NodeFailure)?,
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
        let (server, actual_addr) = server.listen_on(listener).await.map_err(|_| NodeFailure)?;
        if actual_addr != expected_addr {
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
            QualificationNodeCommand::StartTrafficMutation => self.start_traffic_mutation().await,
            QualificationNodeCommand::StopTrafficMutation => self.stop_traffic_mutation().await,
            QualificationNodeCommand::StopTrafficWatch => self.stop_traffic_watch().await,
            QualificationNodeCommand::TrafficStatus => self.traffic_status().await,
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

    async fn start_traffic_mutation(&mut self) -> QualificationNodeReply {
        let Some(traffic) = &self.traffic else {
            return QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::TrafficUnavailable,
            };
        };
        if traffic.mutation_started
            || traffic.mutation_task.is_some()
            || traffic
                .watch_task
                .as_ref()
                .is_none_or(tokio::task::JoinHandle::is_finished)
        {
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
                return QualificationNodeReply::Error {
                    code: QualificationNodeErrorCode::TrafficUnavailable,
                }
            }
        };
        let lease = match self
            .protected
            .acquire(&key, owner.clone(), QUALIFICATION_TRAFFIC_TTL)
            .await
        {
            Ok(lease) => lease,
            Err(_) => {
                return QualificationNodeReply::Error {
                    code: QualificationNodeErrorCode::TrafficUnavailable,
                }
            }
        };
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
        let _ = cancel.send(());
        match task.await {
            Ok(Ok(())) => {}
            Ok(Err(failure)) => observation.record_failure(failure),
            Err(_) => {
                observation.record_failure(QualificationTrafficFailureCode::TaskJoinUnavailable)
            }
        }
        self.traffic_status().await
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
            Err(_) => {
                observation.record_failure(QualificationTrafficFailureCode::TaskJoinUnavailable)
            }
        }
        self.traffic_status().await
    }

    async fn traffic_status(&self) -> QualificationNodeReply {
        let Some(traffic) = &self.traffic else {
            return QualificationNodeReply::Error {
                code: QualificationNodeErrorCode::TrafficUnavailable,
            };
        };
        let replication_head = match self.protected.max_replication_sequence().await {
            Ok(head) => head,
            Err(_) => {
                traffic
                    .observation
                    .record_failure(QualificationTrafficFailureCode::BackendUnavailable);
                traffic.observation.watch_sequence.load(Ordering::Acquire)
            }
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
                failure,
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
                complete_restore_scans: traffic
                    .observation
                    .complete_restore_scans
                    .load(Ordering::Acquire),
                durable_readiness_probes: traffic
                    .observation
                    .durable_readiness_probes
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
    mut lease: LeaseGuard,
    seed: u64,
    member_count: usize,
    node_index: usize,
    mut cancellation: oneshot::Receiver<()>,
    observation: Arc<QualificationTrafficObservation>,
) -> Result<(), QualificationTrafficFailureCode> {
    let result = run_traffic_mutation_task_inner(
        &protected,
        &store,
        &key,
        &owner,
        &mut lease,
        seed,
        member_count,
        node_index,
        &mut cancellation,
        &observation,
    )
    .await;
    match result {
        Ok(()) => match protected.release(lease).await {
            Ok(()) => Ok(()),
            Err(_) => {
                observation.record_failure(QualificationTrafficFailureCode::LeaseRejected);
                Err(QualificationTrafficFailureCode::LeaseRejected)
            }
        },
        Err(failure) => {
            observation.record_failure(failure);
            let _ = protected.release(lease).await;
            Err(failure)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_traffic_mutation_task_inner(
    protected: &ProtectedStore,
    store: &ConsensusSessionStore,
    key: &SessionKey,
    owner: &OwnerId,
    lease: &mut LeaseGuard,
    seed: u64,
    member_count: usize,
    node_index: usize,
    cancellation: &mut oneshot::Receiver<()>,
    observation: &QualificationTrafficObservation,
) -> Result<(), QualificationTrafficFailureCode> {
    let mut schedule_state = seed ^ (u64::try_from(node_index).unwrap_or(u64::MAX) << 32);
    loop {
        match cancellation.try_recv() {
            Ok(()) | Err(tokio::sync::oneshot::error::TryRecvError::Closed) => return Ok(()),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {}
        }

        let renewed = protected
            .renew(lease, QUALIFICATION_TRAFFIC_TTL)
            .await
            .map_err(|_| QualificationTrafficFailureCode::LeaseRejected)?;
        if !lease_authority_is_preserved(
            key,
            owner,
            lease.fence().get(),
            renewed.key(),
            renewed.owner(),
            renewed.fence().get(),
        ) {
            return Err(QualificationTrafficFailureCode::InvariantViolation);
        }
        *lease = renewed;
        increment(&observation.lease_renewals);

        let generation = observation
            .last_generation
            .load(Ordering::Acquire)
            .checked_add(1)
            .ok_or(QualificationTrafficFailureCode::InvariantViolation)?;
        let value = qualification_traffic_value(seed, member_count, node_index, generation);
        let expected_record = StoredSessionRecord {
            key: key.clone(),
            generation: Generation::new(generation),
            owner: lease.owner().clone(),
            fence: lease.fence(),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static(QUALIFICATION_TRAFFIC_STATE_TYPE),
            expires_at: None,
            payload: EncryptedSessionPayload::new(value.as_bytes()),
        };
        let expected_generation = generation.checked_sub(1).filter(|value| *value != 0);
        match protected
            .compare_and_set(CompareAndSet {
                key: key.clone(),
                lease: lease.clone(),
                expected_generation: expected_generation.map(Generation::new),
                new_record: expected_record.clone(),
            })
            .await
            .map_err(|_| QualificationTrafficFailureCode::BackendUnavailable)?
        {
            CompareAndSetResult::Success => {}
            CompareAndSetResult::Conflict { .. } => {
                return Err(QualificationTrafficFailureCode::InvariantViolation)
            }
        }

        let stored = protected
            .get(key)
            .await
            .map_err(|_| QualificationTrafficFailureCode::BackendUnavailable)?
            .ok_or(QualificationTrafficFailureCode::InvariantViolation)?;
        if !traffic_record_is_exact(&expected_record, &stored) {
            return Err(QualificationTrafficFailureCode::InvariantViolation);
        }
        increment(&observation.linearizable_reads);

        let page = protected
            .scan_restore_records(RestoreScanRequest::all(QUALIFICATION_TRAFFIC_RESTORE_LIMIT))
            .await
            .map_err(|_| QualificationTrafficFailureCode::RestoreScanRejected)?;
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
            return Err(QualificationTrafficFailureCode::RestoreScanRejected);
        }
        increment(&observation.complete_restore_scans);

        let readiness = store.probe_durable_readiness().await;
        if !readiness.is_ready() {
            return Err(QualificationTrafficFailureCode::ReadinessUnavailable);
        }
        increment(&observation.durable_readiness_probes);

        let record_fence = lease.fence().get();
        protected
            .release(lease.clone())
            .await
            .map_err(|_| QualificationTrafficFailureCode::LeaseRejected)?;
        let reacquired = protected
            .acquire(key, owner.clone(), QUALIFICATION_TRAFFIC_TTL)
            .await
            .map_err(|_| QualificationTrafficFailureCode::LeaseRejected)?;
        if !lease_authority_is_advanced(
            key,
            owner,
            record_fence,
            reacquired.key(),
            reacquired.owner(),
            reacquired.fence().get(),
        ) {
            return Err(QualificationTrafficFailureCode::InvariantViolation);
        }
        *lease = reacquired;
        increment(&observation.lease_reacquisitions);
        observation
            .last_record_fence
            .store(record_fence, Ordering::Release);
        observation
            .last_generation
            .store(generation, Ordering::Release);
        increment(&observation.mutation_cycles);

        schedule_state = schedule_state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let delay = QUALIFICATION_TRAFFIC_MUTATION_DELAY_MIN_MILLIS
            + schedule_state % QUALIFICATION_TRAFFIC_MUTATION_DELAY_SPAN_MILLIS;
        tokio::select! {
            _ = &mut *cancellation => return Ok(()),
            _ = tokio::time::sleep(Duration::from_millis(delay)) => {}
        }
    }
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

async fn run_traffic_watch_task(
    mut stream: BoxStream<'static, Result<ReplicationEntry, StoreError>>,
    mut expected_sequence: u64,
    member_count: usize,
    mut cancellation: oneshot::Receiver<()>,
    observation: Arc<QualificationTrafficObservation>,
) -> Result<(), QualificationTrafficFailureCode> {
    let traffic_keys = (0..member_count)
        .map(qualification_traffic_key)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|()| QualificationTrafficFailureCode::InvariantViolation)?;
    loop {
        tokio::select! {
            biased;
            _ = &mut cancellation => return Ok(()),
            entry = stream.next() => {
                let Some(entry) = entry else {
                    observation.record_failure(QualificationTrafficFailureCode::WatchUnavailable);
                    return Err(QualificationTrafficFailureCode::WatchUnavailable);
                };
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(_) => {
                        observation.record_failure(QualificationTrafficFailureCode::WatchUnavailable);
                        return Err(QualificationTrafficFailureCode::WatchUnavailable);
                    }
                };
                if entry.sequence != expected_sequence {
                    observation.record_failure(QualificationTrafficFailureCode::InvariantViolation);
                    return Err(QualificationTrafficFailureCode::InvariantViolation);
                }
                let applied_records = observe_applied_records(
                    &entry.op,
                    &traffic_keys,
                    &observation.watch_traffic_generations,
                )?;
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
                    observation.record_failure(QualificationTrafficFailureCode::InvariantViolation);
                    return Err(QualificationTrafficFailureCode::InvariantViolation);
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
            ReplicationOp::Batch { ops } => pending.extend(ops.iter()),
            ReplicationOp::DeleteFenced { .. }
            | ReplicationOp::RefreshTtl { .. }
            | ReplicationOp::AcquireLease { .. }
            | ReplicationOp::RenewLease { .. }
            | ReplicationOp::ReleaseLease { .. } => {}
        }
    }
    Ok(count)
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
                    let peer: Arc<dyn SessionConsensusPeer> = Arc::new(
                        RemoteSessionConsensusPeer::new_insecure(binding, member.dial_addr, None),
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
                let dial_addr = member.dial_addr;
                let resolver_evidence = QualificationResolverEvidence::new();
                let resolver_evidence_for_call = resolver_evidence.clone();
                let reauthentication_for_resolver = reauthentication.clone();
                let resolver: RemoteAddrResolver = Arc::new(move || {
                    let resolver_evidence = resolver_evidence_for_call.clone();
                    let reauthentication = reauthentication_for_resolver.clone();
                    Box::pin(async move {
                        resolver_evidence.record_resolution(reauthentication.generation());
                        Ok(dial_addr)
                    })
                });
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
        .filter(|value| value.ip().is_loopback())
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
    if config.node_index != arguments.node_index
        || config.members[config.node_index].dial_addr != bind_addr
    {
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

    #[derive(Debug)]
    struct CountingPeer {
        node_id: SessionConsensusNodeId,
        calls: Arc<AtomicU64>,
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
        let peer = QualificationGatedConsensusPeer::new(
            Arc::new(CountingPeer {
                node_id: target,
                calls: Arc::clone(&outbound_calls),
            }),
            gate.clone(),
        );
        assert_eq!(
            peer.call(gate_test_request(sender)).await,
            Err(SessionConsensusPeerError::Unavailable)
        );
        assert_eq!(outbound_calls.load(Ordering::SeqCst), 0);

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
}
