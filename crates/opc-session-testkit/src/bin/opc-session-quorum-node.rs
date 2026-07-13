//! Private child-process node for experimental session-HA qualification.

use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use opc_key::{KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing, AES_256_GCM_SIV_KEY_LEN};
use opc_session_net::{
    RemoteSessionConsensusPeer, SessionClusterId, SessionConfigurationEpoch,
    SessionConfigurationGeneration, SessionConsensusServer, SessionConsensusServerHandle,
    SessionReplicationManifest,
};
use opc_session_store::{
    CompareAndSet, CompareAndSetResult, ConsensusSessionStore, EncryptedSessionPayload,
    EncryptingSessionBackend, Generation, LeaseError, LeaseGuard, OwnerId, QuorumReplicaDescriptor,
    QuorumTopologyConfig, ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain, ReplicaId,
    ReplicaTlsIdentity, SessionBackend, SessionConsensusPeer, SessionKey, SessionKeyType,
    SessionLeaseManager, SqliteSessionBackend, StateClass, StateType, StoreError,
    StoredSessionRecord, ValidatedQuorumTopology,
};
use opc_session_testkit::qualification::{
    qualification_owner_sha256, qualification_value_sha256, read_bounded_json_line,
    write_json_line, QualificationNodeCommand, QualificationNodeConfig, QualificationNodeErrorCode,
    QualificationNodeReply, QualificationReadinessCode, QUALIFICATION_MAX_CONFIG_BYTES,
    QUALIFICATION_MAX_LEASE_HANDLES,
};
use opc_types::{NetworkFunctionKind, TenantId};

const QUALIFICATION_TENANT: &str = "session-ha-qualification";
const QUALIFICATION_KEY_ID: &str = "session-ha-qualification-key-v1";
const QUALIFICATION_STATE_TYPE: &str = "session-ha-qualification-state";
const QUALIFICATION_KEY_BYTES: [u8; AES_256_GCM_SIV_KEY_LEN] = [0x5a; AES_256_GCM_SIV_KEY_LEN];

type ProtectedStore = EncryptingSessionBackend<ConsensusSessionStore, MemoryKeyProvider>;

#[derive(Debug, thiserror::Error)]
#[error("qualification node failed")]
struct NodeFailure;

struct QualificationNode {
    store: Arc<ConsensusSessionStore>,
    protected: ProtectedStore,
    server: Option<SessionConsensusServerHandle>,
    leases: HashMap<String, LeaseGuard>,
}

impl QualificationNode {
    async fn open(config: &QualificationNodeConfig) -> Result<Self, NodeFailure> {
        secure_qualification_paths(config)?;
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
        let mut peers = BTreeMap::new();
        for member in &config.members {
            if member.node_index == config.node_index {
                continue;
            }
            let binding = local_binding
                .bind_remote(ReplicaId::new(member.replica_id.clone()).map_err(|_| NodeFailure)?)
                .map_err(|_| NodeFailure)?;
            let node_id = binding.remote_consensus_node_id();
            let peer: Arc<dyn SessionConsensusPeer> =
                Arc::new(RemoteSessionConsensusPeer::new_insecure(
                    binding,
                    member.dial_addr,
                    Some(Duration::from_millis(config.operation_timeout_millis)),
                ));
            peers.insert(node_id, peer);
        }

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
        let expected_addr = config.members[config.node_index].dial_addr;
        let (server, actual_addr) =
            SessionConsensusServer::new_insecure(store.rpc_handler(), local_binding)
                .listen(expected_addr)
                .await
                .map_err(|_| NodeFailure)?;
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
            leases: HashMap::new(),
        })
    }

    async fn handle(&mut self, command: QualificationNodeCommand) -> QualificationNodeReply {
        match command {
            QualificationNodeCommand::Initialize => match self.store.initialize_cluster().await {
                Ok(()) => QualificationNodeReply::Initialized,
                Err(_) => QualificationNodeReply::Error {
                    code: QualificationNodeErrorCode::InitializationUnavailable,
                },
            },
            QualificationNodeCommand::Probe => self.probe().await,
            QualificationNodeCommand::Acquire {
                lease_handle,
                stable_id,
                owner,
                ttl_millis,
            } => {
                if self.leases.len() >= QUALIFICATION_MAX_LEASE_HANDLES
                    && !self.leases.contains_key(&lease_handle)
                {
                    return QualificationNodeReply::Error {
                        code: QualificationNodeErrorCode::InvalidRequest,
                    };
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
                        self.leases.insert(lease_handle, lease);
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
                let Some(lease) = self.leases.get(&lease_handle).cloned() else {
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
                let Some(lease) = self.leases.get(&lease_handle).cloned() else {
                    return QualificationNodeReply::Error {
                        code: QualificationNodeErrorCode::LeaseHandleMissing,
                    };
                };
                match self.protected.release(lease).await {
                    Ok(()) => QualificationNodeReply::Released,
                    Err(error) => QualificationNodeReply::Error {
                        code: map_lease_error(&error),
                    },
                }
            }
            QualificationNodeCommand::Shutdown => QualificationNodeReply::ShuttingDown,
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
        QualificationNodeReply::Readiness {
            ready: report.is_ready(),
            reason_code,
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
    Ok(())
}

fn config_path_from_args() -> Result<PathBuf, NodeFailure> {
    let mut args = env::args_os();
    let _program = args.next().ok_or(NodeFailure)?;
    if args.next().as_deref() != Some(std::ffi::OsStr::new("--config")) {
        return Err(NodeFailure);
    }
    let path = PathBuf::from(args.next().ok_or(NodeFailure)?);
    if args.next().is_some() || !path.is_absolute() {
        return Err(NodeFailure);
    }
    Ok(path)
}

fn run() -> Result<(), NodeFailure> {
    let config = load_config(&config_path_from_args()?)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .map_err(|_| NodeFailure)?;
    let mut node = runtime.block_on(QualificationNode::open(&config))?;
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = BufWriter::new(stdout.lock());
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
