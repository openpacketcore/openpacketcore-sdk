//! Private child-process node for experimental session-HA qualification.

use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use opc_identity::ProjectedSvidSource;
use opc_key::{KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing, AES_256_GCM_SIV_KEY_LEN};
use opc_redaction::metrics::METRICS;
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
    ReplicaTlsIdentity, SessionBackend, SessionConsensusIdentity, SessionConsensusNodeId,
    SessionConsensusPeer, SessionConsensusPeerError, SessionConsensusRpcFamily,
    SessionConsensusWireRequest, SessionKey, SessionKeyType, SessionLeaseManager,
    SqliteSessionBackend, StateClass, StateType, StoreError, StoredSessionRecord,
    ValidatedQuorumTopology,
};
use opc_session_testkit::qualification::{
    qualification_owner_sha256, qualification_value_sha256, read_bounded_json_line,
    write_json_line, QualificationConnectionLifecycleMetrics, QualificationNodeCommand,
    QualificationNodeConfig, QualificationNodeErrorCode, QualificationNodeReply,
    QualificationReadinessCode, QualificationTlsMaterialStatus, QualificationTransportConfig,
    QUALIFICATION_MAX_CONFIG_BYTES, QUALIFICATION_MAX_LEASE_HANDLES,
};
use opc_tls::{
    AuthenticatedClientConfig, AuthenticatedServerConfig, TlsConfigBuilder, TlsMaterialController,
};
use opc_types::{NetworkFunctionKind, SpiffeId, TenantId};
use tokio::net::TcpListener;

const QUALIFICATION_TENANT: &str = "session-ha-qualification";
const QUALIFICATION_KEY_ID: &str = "session-ha-qualification-key-v1";
const QUALIFICATION_STATE_TYPE: &str = "session-ha-qualification-state";
const QUALIFICATION_KEY_BYTES: [u8; AES_256_GCM_SIV_KEY_LEN] = [0x5a; AES_256_GCM_SIV_KEY_LEN];

type ProtectedStore = EncryptingSessionBackend<ConsensusSessionStore, MemoryKeyProvider>;

struct QualificationLease {
    guard: LeaseGuard,
    released: bool,
}

#[derive(Debug, thiserror::Error)]
#[error("qualification node failed")]
struct NodeFailure;

struct QualificationNode {
    store: Arc<ConsensusSessionStore>,
    protected: ProtectedStore,
    server: Option<SessionConsensusServerHandle>,
    transport: QualificationTransportRuntime,
    leases: HashMap<String, QualificationLease>,
}

enum QualificationTransportRuntime {
    #[cfg_attr(not(feature = "foundation-insecure"), allow(dead_code))]
    FoundationPlaintext,
    ProjectedMtls(Box<QualificationProjectedMtlsRuntime>),
}

struct QualificationProjectedMtlsRuntime {
    _source: ProjectedSvidSource,
    client_config: AuthenticatedClientConfig,
    reauthentication: SessionReauthenticationControl,
    directed_peers: BTreeMap<usize, QualificationDirectedPeer>,
    consensus_identity: SessionConsensusIdentity,
    local_node_id: SessionConsensusNodeId,
}

struct QualificationDirectedPeer {
    peer: RemoteSessionConsensusPeer,
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
        let (peers, server_transport, transport) =
            prepare_transport(config, &local_binding, manifest.consensus_identity()).await?;

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
        let server = match server_transport {
            #[cfg(feature = "foundation-insecure")]
            QualificationServerTransport::FoundationPlaintext => {
                SessionConsensusServer::new_insecure(store.rpc_handler(), local_binding)
            }
            QualificationServerTransport::ProjectedMtls(transport) => SessionConsensusServer::new(
                store.rpc_handler(),
                transport.server_config,
                local_binding,
            )
            .with_connection_lifecycle(transport.lifecycle)
            .with_reauthentication_control(transport.reauthentication),
        };
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
            QualificationNodeCommand::MaterialStatus => self.material_status(),
            QualificationNodeCommand::RequestReauthentication => self.request_reauthentication(),
            QualificationNodeCommand::DirectedHandshake { remote_node_index } => {
                self.directed_handshake(remote_node_index).await
            }
            QualificationNodeCommand::LifecycleMetrics => {
                QualificationNodeReply::LifecycleMetrics {
                    metrics: lifecycle_metrics(),
                }
            }
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
            required_quorum: report.required_quorum(),
            committed_index: report.committed_barrier_index(),
            applied_index: progress.local_applied_index(),
        }
    }

    async fn stop_server(&mut self) {
        if let Some(server) = self.server.take() {
            server.abort_and_wait().await;
        }
    }
}

fn lifecycle_metrics() -> QualificationConnectionLifecycleMetrics {
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
    }
}

async fn prepare_transport(
    config: &QualificationNodeConfig,
    local_binding: &LocalReplicaBinding,
    consensus_identity: SessionConsensusIdentity,
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
                    peers.insert(
                        node_id,
                        Arc::new(RemoteSessionConsensusPeer::new_insecure(
                            binding,
                            member.dial_addr,
                            None,
                        )) as Arc<dyn SessionConsensusPeer>,
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
            let source = ProjectedSvidSource::new(
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
            let controller = TlsMaterialController::new_pinned(source.subscribe(), local_spiffe_id);
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
                let peer = RemoteSessionConsensusPeer::new_profiled_with_resolver(
                    binding,
                    resolver,
                    client_config.clone(),
                )
                .with_connection_lifecycle(lifecycle)
                .with_reauthentication_control(reauthentication.clone());
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
                        _source: source,
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
}
