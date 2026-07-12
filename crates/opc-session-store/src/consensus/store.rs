//! Production session store coordinated exclusively by Openraft.
//!
//! Session payload sealing remains an outer adapter concern. Commands admitted
//! here contain only already-enveloped records; the consensus engine, network,
//! log store, snapshots, and state machine never receive an HKMS provider,
//! plaintext key, or plaintext session payload.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::stream::{BoxStream, StreamExt};
use opc_consensus::engine::error::{ClientWriteError, InitializeError, RaftError};
use opc_consensus::engine::{Config, EmptyNode, LogId, SnapshotPolicy, StoredMembership};
use opc_consensus::{decode_bounded, encode_bounded};
use opc_types::Timestamp;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::raft_adapter::{
    SessionRaftAdapterError, SessionRaftNetworkFactory, SessionRaftRpcHandler,
};
use super::storage::{self, SessionConsensusStorageError};
use super::{
    SessionConsensusIdentity, SessionConsensusNodeId, SessionConsensusPeer,
    SessionConsensusPeerError, SessionConsensusRequestId, SessionConsensusResponse,
    SessionConsensusRpcFamily, SessionConsensusRpcHandler, SessionConsensusWireRequest,
    SessionConsensusWireResponse, SessionMutationIntent, SessionMutationOutcome, SessionRaft,
    SESSION_CONSENSUS_SCHEMA_VERSION,
};
use crate::backend::{
    validate_replication_prefix_owned, BackendInstanceIdentity, CompareAndSet, CompareAndSetResult,
    ReplicationEntry, SessionBackend, SessionOp, SessionOpResult,
};
use crate::capability::{BackendCapabilities, SessionStorePlatformProfile};
use crate::clock::{Clock, SystemClock};
use crate::error::{LeaseError, StoreError};
use crate::lease::{LeaseGuard, SessionLeaseManager};
use crate::model::{OwnerId, SessionKey};
use crate::readiness::{
    DurableReadinessReport, DurableReadinessState, DurableRecoveryProgress, DurableRecoveryState,
    ReplicaReadinessObservation, ReplicaReadinessOutcome,
};
use crate::record::SessionPayloadEncoding;
use crate::record::StoredSessionRecord;
use crate::restore::{RestoreScanPage, RestoreScanRequest};
use crate::sqlite::SqliteSessionBackend;
use crate::topology::{QuorumTopologyMode, QuorumTopologySummary, ValidatedQuorumTopology};
use crate::ttl::{checked_session_deadline, validate_session_ttl};

/// Default complete client-operation deadline, including leader discovery,
/// forwarding, quorum confirmation, commit, and local apply.
pub const DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT: Duration = Duration::from_secs(10);

const SESSION_CONSENSUS_HEARTBEAT_MILLIS: u64 = 250;
const SESSION_CONSENSUS_ELECTION_MIN_MILLIS: u64 = 1_000;
const SESSION_CONSENSUS_ELECTION_MAX_MILLIS: u64 = 2_000;
const SESSION_CONSENSUS_ROUTE_RETRY_BACKOFF: Duration = Duration::from_millis(50);
const SESSION_CONSENSUS_SNAPSHOT_CHUNK_BYTES: u64 = 1024 * 1024;
const SESSION_CONSENSUS_LOGS_PER_SNAPSHOT: u64 = 4_096;
const SESSION_CONSENSUS_RETAINED_LOGS: u64 = 1_024;

/// Fail-closed construction or cluster-formation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ConsensusSessionStoreOpenError {
    /// The topology was not a consensus-scoped HA or consensus singleton.
    #[error("session consensus topology is invalid")]
    InvalidTopology,
    /// The exact remote consensus peer set did not match admitted membership.
    #[error("session consensus peer set does not match topology")]
    PeerSetMismatch,
    /// Legacy or corrupt durable authority requires an explicit recovery
    /// workflow before this member may join.
    #[error("session consensus durable recovery is required")]
    RecoveryRequired,
    /// Persisted identity/schema does not match this deployment.
    #[error("session consensus durable identity does not match configuration")]
    DurableIdentityMismatch,
    /// Durable storage could not be opened or validated.
    #[error("session consensus durable storage is unavailable")]
    StorageUnavailable,
    /// The fixed SDK Openraft runtime profile was invalid.
    #[error("session consensus runtime configuration is invalid")]
    InvalidRuntimeConfiguration,
    /// Openraft could not start or stopped fatally.
    #[error("session consensus engine is unavailable")]
    EngineUnavailable,
    /// Cluster formation or exact live voter admission did not converge.
    #[error("session consensus cluster formation or membership admission was rejected")]
    ClusterFormationRejected,
}

impl From<SessionConsensusStorageError> for ConsensusSessionStoreOpenError {
    fn from(error: SessionConsensusStorageError) -> Self {
        match error {
            SessionConsensusStorageError::RecoveryRequired
            | SessionConsensusStorageError::CorruptState => Self::RecoveryRequired,
            SessionConsensusStorageError::IdentityMismatch
            | SessionConsensusStorageError::SchemaVersionMismatch
            | SessionConsensusStorageError::InvalidIdentity => Self::DurableIdentityMismatch,
            SessionConsensusStorageError::BackendUnavailable => Self::StorageUnavailable,
        }
    }
}

impl From<SessionRaftAdapterError> for ConsensusSessionStoreOpenError {
    fn from(_: SessionRaftAdapterError) -> Self {
        Self::PeerSetMismatch
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ForwardMutationRequest {
    request_id: SessionConsensusRequestId,
    intent: SessionMutationIntent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum ForwardMutationReply {
    Applied(Box<SessionConsensusResponse>),
    NotLeader {
        leader: Option<SessionConsensusNodeId>,
    },
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct ReadBarrierRequest;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum ReadBarrierReply {
    Ready(Option<LogId<SessionConsensusNodeId>>),
    NotLeader {
        leader: Option<SessionConsensusNodeId>,
    },
    Unavailable,
}

struct ConsensusSessionStoreInner {
    raft: SessionRaft,
    raft_handler: SessionRaftRpcHandler,
    backend: SqliteSessionBackend,
    identity: SessionConsensusIdentity,
    local_node_id: SessionConsensusNodeId,
    peers: BTreeMap<SessionConsensusNodeId, Arc<dyn SessionConsensusPeer>>,
    members: BTreeSet<SessionConsensusNodeId>,
    topology: QuorumTopologySummary,
    clock: Arc<dyn Clock>,
    operation_timeout: Duration,
    admitted: AtomicBool,
    proposal_gate: tokio::sync::Mutex<()>,
}

/// SQLite session state coordinated by the SDK's single Openraft engine.
///
/// Call [`Self::open`] first, start the consensus-only network listener using
/// [`Self::rpc_handler`], then call [`Self::initialize_cluster`]. Calling
/// initialization concurrently on every pristine member with the same
/// admitted membership is safe; restart of an initialized member is also
/// idempotent.
#[derive(Clone)]
pub struct ConsensusSessionStore {
    inner: Arc<ConsensusSessionStoreInner>,
}

impl fmt::Debug for ConsensusSessionStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConsensusSessionStore")
            .field("identity", &self.inner.identity)
            .field("local_node_id", &self.inner.local_node_id)
            .field("configured_members", &self.inner.members.len())
            .finish_non_exhaustive()
    }
}

impl ConsensusSessionStore {
    /// Start one durable Openraft node without yet forming pristine membership.
    ///
    /// `topology` contains only immutable member descriptors. `backend` is this
    /// node's sole local state-machine database; every remote member must be
    /// represented by exactly one consensus-only peer instead of a backend
    /// adapter.
    pub async fn open(
        topology: ValidatedQuorumTopology,
        backend: SqliteSessionBackend,
        snapshot_dir: impl Into<PathBuf>,
        peers: BTreeMap<SessionConsensusNodeId, Arc<dyn SessionConsensusPeer>>,
    ) -> Result<Self, ConsensusSessionStoreOpenError> {
        Self::open_with_clock(
            topology,
            backend,
            snapshot_dir,
            peers,
            Arc::new(SystemClock),
            DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
        )
        .await
    }

    /// Start one durable Openraft node with a bounded complete operation
    /// deadline.
    ///
    /// The deadline covers leader discovery/forwarding, quorum confirmation,
    /// commit, and local apply for writes and linearizable readiness/reads.
    pub async fn open_with_operation_timeout(
        topology: ValidatedQuorumTopology,
        backend: SqliteSessionBackend,
        snapshot_dir: impl Into<PathBuf>,
        peers: BTreeMap<SessionConsensusNodeId, Arc<dyn SessionConsensusPeer>>,
        operation_timeout: Duration,
    ) -> Result<Self, ConsensusSessionStoreOpenError> {
        Self::open_with_clock(
            topology,
            backend,
            snapshot_dir,
            peers,
            Arc::new(SystemClock),
            operation_timeout,
        )
        .await
    }

    /// Start a node with an injected logical-clock source and bounded complete
    /// operation deadline. Primarily useful for deterministic qualification.
    pub async fn open_with_clock(
        topology: ValidatedQuorumTopology,
        backend: SqliteSessionBackend,
        snapshot_dir: impl Into<PathBuf>,
        peers: BTreeMap<SessionConsensusNodeId, Arc<dyn SessionConsensusPeer>>,
        clock: Arc<dyn Clock>,
        operation_timeout: Duration,
    ) -> Result<Self, ConsensusSessionStoreOpenError> {
        if operation_timeout.is_zero() || operation_timeout > Duration::from_secs(60) {
            return Err(ConsensusSessionStoreOpenError::InvalidRuntimeConfiguration);
        }
        if !matches!(
            topology.summary().mode(),
            QuorumTopologyMode::ValidatedHa | QuorumTopologyMode::LabSingleton
        ) {
            return Err(ConsensusSessionStoreOpenError::InvalidTopology);
        }
        let identity = topology
            .consensus_identity()
            .ok_or(ConsensusSessionStoreOpenError::InvalidTopology)?;
        let local_node_id = topology
            .local_consensus_node_id()
            .ok_or(ConsensusSessionStoreOpenError::InvalidTopology)?;
        let members = topology
            .members()
            .iter()
            .map(|descriptor| {
                topology
                    .consensus_node_id(descriptor.replica_id())
                    .ok_or(ConsensusSessionStoreOpenError::InvalidTopology)
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        if members.len() != topology.summary().configured_members()
            || !members.contains(&local_node_id)
        {
            return Err(ConsensusSessionStoreOpenError::InvalidTopology);
        }
        let expected_peers = members
            .iter()
            .copied()
            .filter(|node_id| *node_id != local_node_id)
            .collect::<BTreeSet<_>>();
        if peers.keys().copied().collect::<BTreeSet<_>>() != expected_peers {
            return Err(ConsensusSessionStoreOpenError::PeerSetMismatch);
        }

        let network = SessionRaftNetworkFactory::try_new(identity, local_node_id, peers.clone())?;
        let (log_store, state_machine) =
            storage::open(&backend, snapshot_dir, identity, members.clone()).await?;
        let config = Arc::new(session_raft_config()?);
        let raft = SessionRaft::new(local_node_id, config, network, log_store, state_machine)
            .await
            .map_err(|_| ConsensusSessionStoreOpenError::EngineUnavailable)?;
        let raft_handler = SessionRaftRpcHandler::new(raft.clone(), identity, local_node_id);
        let topology_summary = topology.summary().clone();

        Ok(Self {
            inner: Arc::new(ConsensusSessionStoreInner {
                raft,
                raft_handler,
                backend,
                identity,
                local_node_id,
                peers,
                members,
                topology: topology_summary,
                clock,
                operation_timeout,
                admitted: AtomicBool::new(false),
                proposal_gate: tokio::sync::Mutex::new(()),
            }),
        })
    }

    /// Consensus-only handler to install on the authenticated session-net
    /// listener before cluster formation begins.
    pub fn rpc_handler(&self) -> Arc<dyn SessionConsensusRpcHandler> {
        Arc::new(SessionConsensusService {
            store: self.clone(),
        })
    }

    /// Initialize pristine members with the exact admitted voting set.
    pub async fn initialize_cluster(&self) -> Result<(), ConsensusSessionStoreOpenError> {
        self.inner.admitted.store(false, Ordering::Release);
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or(ConsensusSessionStoreOpenError::ClusterFormationRejected)?;
        let initialize = tokio::time::timeout_at(
            deadline,
            self.inner.raft.initialize(self.inner.members.clone()),
        )
        .await
        .map_err(|_| ConsensusSessionStoreOpenError::ClusterFormationRejected)?;
        match initialize {
            Ok(()) | Err(RaftError::APIError(InitializeError::NotAllowed(_))) => {}
            Err(RaftError::APIError(InitializeError::NotInMembers(_))) => {
                return Err(ConsensusSessionStoreOpenError::ClusterFormationRejected);
            }
            Err(RaftError::Fatal(_)) => {
                return Err(ConsensusSessionStoreOpenError::EngineUnavailable);
            }
        }
        self.wait_for_exact_membership(deadline).await?;
        self.inner.admitted.store(true, Ordering::Release);
        if !self.exact_membership_is_admitted() {
            return Err(ConsensusSessionStoreOpenError::ClusterFormationRejected);
        }
        Ok(())
    }

    /// Redaction-safe immutable topology shape.
    pub fn topology(&self) -> &QuorumTopologySummary {
        &self.inner.topology
    }

    /// This adapter is the only store allowed to claim the quorum profile.
    pub fn platform_profile(&self) -> SessionStorePlatformProfile {
        self.inner.topology.mode().platform_profile()
    }

    async fn wait_for_exact_membership(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<(), ConsensusSessionStoreOpenError> {
        let mut metrics = self.inner.raft.metrics();
        loop {
            {
                let current = metrics.borrow();
                if current.running_state.is_err() {
                    return Err(ConsensusSessionStoreOpenError::EngineUnavailable);
                }
                if exact_uniform_voter_membership(
                    current.membership_config.as_ref(),
                    &self.inner.members,
                ) {
                    return Ok(());
                }
            }
            match tokio::time::timeout_at(deadline, metrics.changed()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => {
                    return Err(ConsensusSessionStoreOpenError::EngineUnavailable);
                }
                Err(_) => {
                    return Err(ConsensusSessionStoreOpenError::ClusterFormationRejected);
                }
            }
        }
    }

    fn live_membership_is_exact(&self) -> bool {
        let metrics = self.inner.raft.metrics();
        let current = metrics.borrow();
        current.running_state.is_ok()
            && exact_uniform_voter_membership(
                current.membership_config.as_ref(),
                &self.inner.members,
            )
    }

    fn exact_membership_is_admitted(&self) -> bool {
        if !self.inner.admitted.load(Ordering::Acquire) {
            return false;
        }
        if self.live_membership_is_exact() {
            true
        } else {
            self.inner.admitted.store(false, Ordering::Release);
            false
        }
    }

    fn require_exact_membership_admission(&self) -> Result<(), StoreError> {
        if self.exact_membership_is_admitted() {
            Ok(())
        } else {
            Err(consensus_unavailable())
        }
    }

    /// Fresh readiness proof using the same Openraft quorum/read-index path as
    /// authoritative operations.
    pub async fn probe_durable_readiness(&self) -> DurableReadinessReport {
        let configured = self.inner.members.len();
        let quorum = (configured / 2) + 1;
        let report_without_barrier = |state, recovery_progress| {
            DurableReadinessReport::new(state, configured, 0, 0, quorum, None, Vec::new())
                .with_recovery_progress(recovery_progress)
        };
        let progress = || {
            let metrics = self.inner.raft.metrics();
            let metrics = metrics.borrow();
            let state = if metrics.running_state.is_err() {
                DurableRecoveryState::RecoveryRequired
            } else if metrics.last_log_index
                > metrics.last_applied.as_ref().map(|log_id| log_id.index)
            {
                DurableRecoveryState::CatchingUp
            } else {
                DurableRecoveryState::AwaitingQuorum
            };
            DurableRecoveryProgress::new(
                state,
                metrics.last_log_index,
                metrics.last_applied.as_ref().map(|log_id| log_id.index),
                metrics.snapshot.as_ref().map(|log_id| log_id.index),
                metrics.purged.as_ref().map(|log_id| log_id.index),
            )
        };
        if !self.exact_membership_is_admitted() {
            let progress = progress();
            let state = if progress.state() == DurableRecoveryState::RecoveryRequired {
                DurableReadinessState::RecoveryRequired
            } else {
                DurableReadinessState::NoQuorum
            };
            return report_without_barrier(state, progress);
        }
        match self.linearizable_barrier().await {
            Ok(log_id) => {
                let metrics = self.inner.raft.metrics();
                let metrics = metrics.borrow();
                let recovery_progress = DurableRecoveryProgress::new(
                    DurableRecoveryState::Synchronized,
                    metrics.last_log_index,
                    metrics.last_applied.as_ref().map(|log_id| log_id.index),
                    metrics.snapshot.as_ref().map(|log_id| log_id.index),
                    metrics.purged.as_ref().map(|log_id| log_id.index),
                );
                let observations = self
                    .inner
                    .topology
                    .local_replica_id()
                    .cloned()
                    .map(|replica_id| {
                        ReplicaReadinessObservation::new(
                            replica_id,
                            log_id.map(|log_id| log_id.index),
                            ReplicaReadinessOutcome::Fresh,
                        )
                    })
                    .into_iter()
                    .collect();
                DurableReadinessReport::new(
                    DurableReadinessState::Ready,
                    configured,
                    quorum,
                    quorum,
                    quorum,
                    log_id.map(|log_id| log_id.index),
                    observations,
                )
                .with_recovery_progress(recovery_progress)
            }
            Err(_) => {
                let progress = progress();
                let state = if progress.state() == DurableRecoveryState::RecoveryRequired {
                    DurableReadinessState::RecoveryRequired
                } else {
                    DurableReadinessState::NoQuorum
                };
                report_without_barrier(state, progress)
            }
        }
    }

    async fn submit_intent(
        &self,
        intent: SessionMutationIntent,
    ) -> Result<SessionConsensusResponse, StoreError> {
        self.submit_request(SessionConsensusRequestId::new(), intent)
            .await
    }

    async fn submit_request(
        &self,
        request_id: SessionConsensusRequestId,
        intent: SessionMutationIntent,
    ) -> Result<SessionConsensusResponse, StoreError> {
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        self.submit_request_before(request_id, intent, deadline)
            .await
    }

    async fn submit_request_before(
        &self,
        request_id: SessionConsensusRequestId,
        intent: SessionMutationIntent,
        deadline: tokio::time::Instant,
    ) -> Result<SessionConsensusResponse, StoreError> {
        self.require_exact_membership_admission()?;
        validate_consensus_intent(&intent)?;
        let request = ForwardMutationRequest { request_id, intent };
        let mut preferred = None;

        loop {
            let leader = match preferred.take() {
                Some(leader) => leader,
                None => self.wait_for_known_leader(deadline).await?,
            };
            let reply = if leader == self.inner.local_node_id {
                self.apply_on_local_leader(request.clone(), deadline).await
            } else {
                match self
                    .call_peer::<_, ForwardMutationReply>(
                        leader,
                        SessionConsensusRpcFamily::ForwardMutation,
                        &request,
                        deadline,
                    )
                    .await
                {
                    Ok(reply) => reply,
                    Err(_) => {
                        self.wait_for_route_refresh(leader, deadline).await?;
                        continue;
                    }
                }
            };
            match reply {
                ForwardMutationReply::Applied(response) => {
                    self.require_exact_membership_admission()?;
                    return Ok(*response);
                }
                ForwardMutationReply::NotLeader {
                    leader: next_leader,
                } => {
                    preferred = next_leader.filter(|candidate| {
                        *candidate != leader && self.inner.members.contains(candidate)
                    });
                    if preferred.is_none() {
                        self.wait_for_route_refresh(leader, deadline).await?;
                    }
                }
                ForwardMutationReply::Unavailable => {
                    self.wait_for_route_refresh(leader, deadline).await?;
                }
            }
        }
    }

    async fn apply_on_local_leader(
        &self,
        request: ForwardMutationRequest,
        deadline: tokio::time::Instant,
    ) -> ForwardMutationReply {
        if self.require_exact_membership_admission().is_err() {
            return ForwardMutationReply::Unavailable;
        }
        if let Err(error) = validate_consensus_intent(&request.intent) {
            return ForwardMutationReply::Applied(Box::new(SessionConsensusResponse::rejected(
                error,
            )));
        }
        let _proposal_guard =
            match tokio::time::timeout_at(deadline, self.inner.proposal_gate.lock()).await {
                Ok(guard) => guard,
                Err(_) => return ForwardMutationReply::Unavailable,
            };

        match tokio::time::timeout_at(deadline, self.inner.raft.ensure_linearizable()).await {
            Err(_) => return ForwardMutationReply::Unavailable,
            Ok(Ok(_)) => {
                if self.require_exact_membership_admission().is_err() {
                    return ForwardMutationReply::Unavailable;
                }
            }
            Ok(Err(error)) => {
                return ForwardMutationReply::NotLeader {
                    leader: error
                        .forward_to_leader()
                        .and_then(|forward| forward.leader_id),
                };
            }
        }

        let command = super::SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: self.inner.identity,
            request_id: request.request_id,
            logical_time: self.inner.clock.now_utc(),
            intent: request.intent,
        };
        if encode_bounded(&command).is_err() {
            let max = self.inner.backend.capabilities().await.max_value_bytes;
            return ForwardMutationReply::Applied(Box::new(SessionConsensusResponse::rejected(
                StoreError::PayloadTooLarge {
                    actual: max.saturating_add(1),
                    max,
                },
            )));
        }

        match tokio::time::timeout_at(
            deadline,
            self.inner
                .raft
                .client_write::<tokio::sync::oneshot::error::RecvError>(command),
        )
        .await
        {
            Err(_) => ForwardMutationReply::Unavailable,
            Ok(Ok(response)) if self.exact_membership_is_admitted() => {
                ForwardMutationReply::Applied(Box::new(response.data))
            }
            Ok(Ok(_)) => ForwardMutationReply::Unavailable,
            Ok(Err(error)) => ForwardMutationReply::NotLeader {
                leader: client_write_leader(&error),
            },
        }
    }

    async fn wait_for_known_leader(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<SessionConsensusNodeId, StoreError> {
        let mut metrics = self.inner.raft.metrics();
        loop {
            if let Some(leader) = metrics.borrow().current_leader {
                return Ok(leader);
            }
            match tokio::time::timeout_at(deadline, metrics.changed()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) | Err(_) => return Err(consensus_unavailable()),
            }
        }
    }

    async fn wait_for_route_refresh(
        &self,
        attempted_leader: SessionConsensusNodeId,
        deadline: tokio::time::Instant,
    ) -> Result<(), StoreError> {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(consensus_unavailable());
        }
        let retry_deadline = now
            .checked_add(SESSION_CONSENSUS_ROUTE_RETRY_BACKOFF)
            .map_or(deadline, |candidate| candidate.min(deadline));
        let mut metrics = self.inner.raft.metrics();
        loop {
            if metrics.borrow().current_leader != Some(attempted_leader) {
                return Ok(());
            }
            match tokio::time::timeout_at(retry_deadline, metrics.changed()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => return Err(consensus_unavailable()),
                Err(_) if retry_deadline < deadline => return Ok(()),
                Err(_) => return Err(consensus_unavailable()),
            }
        }
    }

    async fn call_peer<Req, Resp>(
        &self,
        target: SessionConsensusNodeId,
        family: SessionConsensusRpcFamily,
        request: &Req,
        deadline: tokio::time::Instant,
    ) -> Result<Resp, StoreError>
    where
        Req: Serialize + ?Sized,
        Resp: serde::de::DeserializeOwned,
    {
        let peer = self
            .inner
            .peers
            .get(&target)
            .filter(|peer| peer.node_id() == target)
            .ok_or_else(consensus_unavailable)?;
        let payload = encode_bounded(request).map_err(|_| consensus_unavailable())?;
        let wire = SessionConsensusWireRequest::try_new(
            self.inner.identity,
            self.inner.local_node_id,
            family,
            payload,
        )
        .map_err(|_| consensus_unavailable())?;
        let response = tokio::time::timeout_at(deadline, peer.call(wire))
            .await
            .map_err(|_| consensus_unavailable())?
            .map_err(|_| consensus_unavailable())?;
        response.validate().map_err(|_| consensus_unavailable())?;
        let payload = response.result.map_err(|_| consensus_unavailable())?;
        decode_bounded(&payload).map_err(|_| consensus_unavailable())
    }

    async fn local_read_barrier(&self, deadline: tokio::time::Instant) -> ReadBarrierReply {
        if self.require_exact_membership_admission().is_err() {
            return ReadBarrierReply::Unavailable;
        }
        match tokio::time::timeout_at(deadline, self.inner.raft.ensure_linearizable()).await {
            Err(_) => ReadBarrierReply::Unavailable,
            Ok(Ok(log_id)) if self.exact_membership_is_admitted() => {
                ReadBarrierReply::Ready(log_id)
            }
            Ok(Ok(_)) => ReadBarrierReply::Unavailable,
            Ok(Err(error)) => ReadBarrierReply::NotLeader {
                leader: error
                    .forward_to_leader()
                    .and_then(|forward| forward.leader_id),
            },
        }
    }

    async fn linearizable_barrier(
        &self,
    ) -> Result<Option<LogId<SessionConsensusNodeId>>, StoreError> {
        self.require_exact_membership_admission()?;
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        let mut preferred = None;
        loop {
            let leader = match preferred.take() {
                Some(leader) => leader,
                None => self.wait_for_known_leader(deadline).await?,
            };
            let reply = if leader == self.inner.local_node_id {
                self.local_read_barrier(deadline).await
            } else {
                match self
                    .call_peer::<_, ReadBarrierReply>(
                        leader,
                        SessionConsensusRpcFamily::ReadBarrier,
                        &ReadBarrierRequest,
                        deadline,
                    )
                    .await
                {
                    Ok(reply) => reply,
                    Err(_) => {
                        self.wait_for_route_refresh(leader, deadline).await?;
                        continue;
                    }
                }
            };
            match reply {
                ReadBarrierReply::Ready(log_id) => {
                    if let Some(log_id) = log_id {
                        self.wait_for_local_apply(log_id.index, deadline).await?;
                    }
                    self.require_exact_membership_admission()?;
                    return Ok(log_id);
                }
                ReadBarrierReply::NotLeader {
                    leader: next_leader,
                } => {
                    preferred = next_leader.filter(|candidate| {
                        *candidate != leader && self.inner.members.contains(candidate)
                    });
                    if preferred.is_none() {
                        self.wait_for_route_refresh(leader, deadline).await?;
                    }
                }
                ReadBarrierReply::Unavailable => {
                    self.wait_for_route_refresh(leader, deadline).await?;
                }
            }
        }
    }

    async fn wait_for_local_apply(
        &self,
        index: u64,
        deadline: tokio::time::Instant,
    ) -> Result<(), StoreError> {
        let mut metrics = self.inner.raft.metrics();
        loop {
            if metrics
                .borrow()
                .last_applied
                .as_ref()
                .is_some_and(|applied| applied.index >= index)
            {
                return Ok(());
            }
            match tokio::time::timeout_at(deadline, metrics.changed()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) | Err(_) => return Err(consensus_unavailable()),
            }
        }
    }

    async fn logical_read_time_before(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<Timestamp, StoreError> {
        let response = self
            .submit_request_before(
                SessionConsensusRequestId::new(),
                SessionMutationIntent::AdvanceLogicalTime,
                deadline,
            )
            .await?;
        response.result?;
        if response.raft_log_index == 0 {
            return Err(consensus_unavailable());
        }
        self.wait_for_local_apply(response.raft_log_index, deadline)
            .await?;
        response.logical_time.ok_or_else(consensus_unavailable)
    }

    async fn logical_read_time(&self) -> Result<Timestamp, StoreError> {
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        self.logical_read_time_before(deadline).await
    }
}

fn session_raft_config() -> Result<Config, ConsensusSessionStoreOpenError> {
    Config {
        cluster_name: "opc-session-store".into(),
        heartbeat_interval: SESSION_CONSENSUS_HEARTBEAT_MILLIS,
        election_timeout_min: SESSION_CONSENSUS_ELECTION_MIN_MILLIS,
        election_timeout_max: SESSION_CONSENSUS_ELECTION_MAX_MILLIS,
        install_snapshot_timeout: 10_000,
        max_payload_entries: 1,
        replication_lag_threshold: SESSION_CONSENSUS_LOGS_PER_SNAPSHOT,
        snapshot_policy: SnapshotPolicy::LogsSinceLast(SESSION_CONSENSUS_LOGS_PER_SNAPSHOT),
        snapshot_max_chunk_size: SESSION_CONSENSUS_SNAPSHOT_CHUNK_BYTES,
        max_in_snapshot_log_to_keep: SESSION_CONSENSUS_RETAINED_LOGS,
        ..Config::default()
    }
    .validate()
    .map_err(|_| ConsensusSessionStoreOpenError::InvalidRuntimeConfiguration)
}

fn client_write_leader(
    error: &RaftError<SessionConsensusNodeId, ClientWriteError<SessionConsensusNodeId, EmptyNode>>,
) -> Option<SessionConsensusNodeId> {
    error
        .forward_to_leader()
        .and_then(|forward| forward.leader_id)
}

fn consensus_unavailable() -> StoreError {
    StoreError::BackendUnavailable("session consensus quorum is unavailable".into())
}

fn exact_uniform_voter_membership(
    stored: &StoredMembership<SessionConsensusNodeId, EmptyNode>,
    configured: &BTreeSet<SessionConsensusNodeId>,
) -> bool {
    let membership = stored.membership();
    let configs = membership.get_joint_config();
    let nodes = membership
        .nodes()
        .map(|(node_id, _)| *node_id)
        .collect::<BTreeSet<_>>();
    stored.log_id().is_some()
        && configs.len() == 1
        && configs.first() == Some(configured)
        && membership.learner_ids().next().is_none()
        && nodes == *configured
}

fn validate_consensus_intent(intent: &SessionMutationIntent) -> Result<(), StoreError> {
    if let SessionMutationIntent::CompareAndSet(op) = intent {
        validate_sealed_payload(op)?;
    }
    Ok(())
}

fn validate_consensus_batch(ops: &[SessionOp]) -> Result<(), StoreError> {
    for op in ops {
        if let SessionOp::CompareAndSet(op) = op {
            validate_sealed_payload(op)?;
        }
    }
    Ok(())
}

fn validate_sealed_payload(op: &CompareAndSet) -> Result<(), StoreError> {
    if op.new_record.payload.encoding() != SessionPayloadEncoding::EnvelopeV1 {
        return Err(StoreError::Crypto(
            "session consensus requires a sealed payload".into(),
        ));
    }
    op.new_record
        .payload
        .validate_envelope_for_record(&op.new_record)
}

#[derive(Clone)]
struct SessionConsensusService {
    store: ConsensusSessionStore,
}

impl fmt::Debug for SessionConsensusService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionConsensusService(<redacted>)")
    }
}

#[async_trait]
impl SessionConsensusRpcHandler for SessionConsensusService {
    async fn handle(
        &self,
        authenticated_sender: SessionConsensusNodeId,
        request: SessionConsensusWireRequest,
    ) -> SessionConsensusWireResponse {
        if request.validate().is_err()
            || request.schema_version != SESSION_CONSENSUS_SCHEMA_VERSION
            || request.identity != self.store.inner.identity
            || request.sender != authenticated_sender
            || !self.store.inner.members.contains(&authenticated_sender)
        {
            return SessionConsensusWireResponse {
                result: Err(SessionConsensusPeerError::ScopeMismatch),
            };
        }

        match request.family {
            SessionConsensusRpcFamily::Vote
            | SessionConsensusRpcFamily::AppendEntries
            | SessionConsensusRpcFamily::InstallSnapshot => {
                self.store
                    .inner
                    .raft_handler
                    .handle(authenticated_sender, request)
                    .await
            }
            SessionConsensusRpcFamily::ForwardMutation => {
                let forwarded: ForwardMutationRequest = match decode_bounded(&request.payload) {
                    Ok(forwarded) => forwarded,
                    Err(_) => return protocol_rejection(),
                };
                let deadline = tokio::time::Instant::now()
                    .checked_add(self.store.inner.operation_timeout)
                    .unwrap_or_else(tokio::time::Instant::now);
                encode_service_reply(&self.store.apply_on_local_leader(forwarded, deadline).await)
            }
            SessionConsensusRpcFamily::ReadBarrier => {
                if decode_bounded::<ReadBarrierRequest>(&request.payload).is_err() {
                    return protocol_rejection();
                }
                let deadline = tokio::time::Instant::now()
                    .checked_add(self.store.inner.operation_timeout)
                    .unwrap_or_else(tokio::time::Instant::now);
                encode_service_reply(&self.store.local_read_barrier(deadline).await)
            }
            _ => protocol_rejection(),
        }
    }
}

fn encode_service_reply<T: Serialize>(reply: &T) -> SessionConsensusWireResponse {
    match encode_bounded(reply) {
        Ok(payload) => SessionConsensusWireResponse {
            result: Ok(payload),
        },
        Err(_) => protocol_rejection(),
    }
}

fn protocol_rejection() -> SessionConsensusWireResponse {
    SessionConsensusWireResponse {
        result: Err(SessionConsensusPeerError::Protocol),
    }
}

#[async_trait]
impl SessionBackend for ConsensusSessionStore {
    fn restore_scan_cursor_profile(&self) -> Option<crate::RestoreScanCursorProfile> {
        Some(crate::RestoreScanCursorProfile::DurableOpaqueV1)
    }

    fn backend_instance_identity(&self) -> Option<BackendInstanceIdentity> {
        Some(BackendInstanceIdentity::for_shared(&self.inner))
    }

    async fn capabilities(&self) -> BackendCapabilities {
        let mut capabilities = self.inner.backend.consensus_capabilities();
        capabilities.ordered_replication_log = true;
        capabilities.watch = true;
        capabilities.restore_scan = true;
        capabilities
    }

    async fn get(&self, key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
        let logical_time = self.logical_read_time().await?;
        self.inner.backend.consensus_get_at(key, logical_time).await
    }

    async fn compare_and_set(&self, op: CompareAndSet) -> Result<CompareAndSetResult, StoreError> {
        let response = self
            .submit_intent(SessionMutationIntent::CompareAndSet(Box::new(op)))
            .await?;
        match response.result? {
            SessionMutationOutcome::CompareAndSet(result) => Ok(result),
            _ => Err(consensus_unavailable()),
        }
    }

    async fn delete_fenced(&self, lease: &LeaseGuard) -> Result<(), StoreError> {
        let response = self
            .submit_intent(SessionMutationIntent::DeleteFenced(lease.clone()))
            .await?;
        match response.result? {
            SessionMutationOutcome::Unit => Ok(()),
            _ => Err(consensus_unavailable()),
        }
    }

    async fn refresh_ttl(&self, lease: &LeaseGuard, ttl: Duration) -> Result<(), StoreError> {
        validate_session_ttl(ttl)?;
        checked_session_deadline(self.inner.clock.now_utc(), ttl)?;
        let response = self
            .submit_intent(SessionMutationIntent::RefreshTtl {
                lease: lease.clone(),
                ttl,
            })
            .await?;
        match response.result? {
            SessionMutationOutcome::Unit => Ok(()),
            _ => Err(consensus_unavailable()),
        }
    }

    async fn batch(&self, ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
        self.require_exact_membership_admission()?;
        crate::backend::validate_session_ops_ttls(&ops)?;
        validate_consensus_batch(&ops)?;
        let mut results = Vec::with_capacity(ops.len());
        for op in ops {
            results.push(match op {
                SessionOp::Get { key } => SessionOpResult::Get(self.get(&key).await),
                SessionOp::CompareAndSet(op) => {
                    SessionOpResult::CompareAndSet(self.compare_and_set(op).await)
                }
                SessionOp::DeleteFenced { lease } => {
                    SessionOpResult::DeleteFenced(self.delete_fenced(&lease).await)
                }
                SessionOp::RefreshTtl { lease, ttl } => {
                    SessionOpResult::RefreshTtl(self.refresh_ttl(&lease, ttl).await)
                }
            });
        }
        Ok(results)
    }

    async fn scan_restore_records(
        &self,
        request: RestoreScanRequest,
    ) -> Result<RestoreScanPage, StoreError> {
        request.validate()?;
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or(StoreError::RestoreScanWorkBudgetExceeded)?;
        let logical_time =
            tokio::time::timeout_at(deadline, self.logical_read_time_before(deadline))
                .await
                .map_err(|_| StoreError::RestoreScanWorkBudgetExceeded)??;
        self.inner
            .backend
            .consensus_scan_restore_records_at(request, logical_time, deadline)
            .await
    }

    async fn max_replication_sequence(&self) -> Result<u64, StoreError> {
        self.logical_read_time().await?;
        self.inner
            .backend
            .consensus_max_replication_sequence()
            .await
    }

    async fn get_replication_log(
        &self,
        start: u64,
        limit: usize,
    ) -> Result<Vec<ReplicationEntry>, StoreError> {
        self.logical_read_time().await?;
        self.inner
            .backend
            .consensus_get_replication_log(start, limit)
            .await
    }

    async fn replicate_entry(&self, entry: ReplicationEntry) -> Result<(), StoreError> {
        let _ = entry.into_validated()?;
        Err(StoreError::CapabilityNotSupported(
            "direct_replication_authority".into(),
        ))
    }

    async fn rebuild_replication_state(
        &self,
        entries: Vec<ReplicationEntry>,
    ) -> Result<(), StoreError> {
        let _ = validate_replication_prefix_owned(entries)?;
        Err(StoreError::CapabilityNotSupported(
            "direct_rebuild_authority".into(),
        ))
    }

    async fn watch(
        &self,
        start_sequence: u64,
    ) -> Result<BoxStream<'static, Result<ReplicationEntry, StoreError>>, StoreError> {
        self.logical_read_time().await?;
        let stream = self.inner.backend.consensus_watch(start_sequence).await?;
        let store = self.clone();
        Ok(stream
            .map(move |entry| {
                store.require_exact_membership_admission()?;
                entry
            })
            .boxed())
    }

    async fn next_lease_info(&self) -> Result<(u64, u64), StoreError> {
        Err(StoreError::CapabilityNotSupported(
            "external_lease_sequencing".into(),
        ))
    }
}

#[async_trait]
impl SessionLeaseManager for ConsensusSessionStore {
    async fn acquire(
        &self,
        key: &SessionKey,
        owner: OwnerId,
        ttl: Duration,
    ) -> Result<LeaseGuard, LeaseError> {
        validate_session_ttl(ttl).map_err(LeaseError::from)?;
        checked_session_deadline(self.inner.clock.now_utc(), ttl).map_err(LeaseError::from)?;
        let response = self
            .submit_intent(SessionMutationIntent::AcquireLease {
                key: key.clone(),
                owner,
                ttl,
            })
            .await
            .map_err(LeaseError::from)?;
        match response.result.map_err(LeaseError::from)? {
            SessionMutationOutcome::Lease(guard) => Ok(guard),
            _ => Err(LeaseError::Backend(
                "session consensus outcome mismatch".into(),
            )),
        }
    }

    async fn renew(&self, lease: &LeaseGuard, ttl: Duration) -> Result<LeaseGuard, LeaseError> {
        validate_session_ttl(ttl).map_err(LeaseError::from)?;
        checked_session_deadline(self.inner.clock.now_utc(), ttl).map_err(LeaseError::from)?;
        let response = self
            .submit_intent(SessionMutationIntent::RenewLease {
                lease: lease.clone(),
                ttl,
            })
            .await
            .map_err(LeaseError::from)?;
        match response.result.map_err(LeaseError::from)? {
            SessionMutationOutcome::Lease(guard) => Ok(guard),
            _ => Err(LeaseError::Backend(
                "session consensus outcome mismatch".into(),
            )),
        }
    }

    async fn release(&self, lease: LeaseGuard) -> Result<(), LeaseError> {
        let response = self
            .submit_intent(SessionMutationIntent::ReleaseLease(lease))
            .await
            .map_err(LeaseError::from)?;
        match response.result.map_err(LeaseError::from)? {
            SessionMutationOutcome::Unit => Ok(()),
            _ => Err(LeaseError::Backend(
                "session consensus outcome mismatch".into(),
            )),
        }
    }
}

#[cfg(test)]
mod membership_tests {
    use opc_consensus::engine::{CommittedLeaderId, Membership};
    use opc_consensus::{
        derive_configuration_id, ConsensusClusterId, ConsensusConfigurationEpoch, ConsensusIdentity,
    };

    use super::*;
    use crate::topology::{
        QuorumReplicaDescriptor, ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain,
        ReplicaId, ReplicaTlsIdentity,
    };

    fn node(value: u64) -> SessionConsensusNodeId {
        SessionConsensusNodeId::new(value).expect("valid test consensus node ID")
    }

    fn stored_membership(
        configs: Vec<BTreeSet<SessionConsensusNodeId>>,
        nodes: BTreeSet<SessionConsensusNodeId>,
    ) -> StoredMembership<SessionConsensusNodeId, EmptyNode> {
        let membership: Membership<SessionConsensusNodeId, EmptyNode> =
            Membership::new(configs, nodes);
        StoredMembership::new(
            Some(LogId::new(CommittedLeaderId::new(1, node(1)), 0)),
            membership,
        )
    }

    fn singleton_topology() -> ValidatedQuorumTopology {
        let replica_id = ReplicaId::new("membership-admission-singleton").expect("replica ID");
        let descriptor = QuorumReplicaDescriptor::new(
            replica_id.clone(),
            ReplicaEndpoint::new("membership-admission.invalid", 7443).expect("endpoint"),
            ReplicaTlsIdentity::new("spiffe://test/session/membership-admission")
                .expect("TLS identity"),
            ReplicaFailureDomain::new("membership-admission-zone").expect("failure domain"),
            ReplicaBackingIdentity::new("membership-admission-disk").expect("backing identity"),
        );
        let cluster_id =
            ConsensusClusterId::new("session-membership-admission-tests").expect("cluster ID");
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

    #[test]
    fn exact_membership_requires_one_uniform_config_and_no_learners() {
        let configured = [node(1), node(2), node(3)]
            .into_iter()
            .collect::<BTreeSet<_>>();
        let exact = stored_membership(vec![configured.clone()], configured.clone());
        assert!(exact_uniform_voter_membership(&exact, &configured));

        let subset = [node(1), node(2)].into_iter().collect::<BTreeSet<_>>();
        let subset_membership = stored_membership(vec![subset.clone()], subset);
        assert!(!exact_uniform_voter_membership(
            &subset_membership,
            &configured
        ));

        let joint_left = [node(1), node(2)].into_iter().collect::<BTreeSet<_>>();
        let joint_right = [node(2), node(3)].into_iter().collect::<BTreeSet<_>>();
        let joint = stored_membership(vec![joint_left, joint_right], configured.clone());
        assert!(!exact_uniform_voter_membership(&joint, &configured));

        let mut voter_and_learner_nodes = configured.clone();
        voter_and_learner_nodes.insert(node(4));
        let learner = stored_membership(vec![configured.clone()], voter_and_learner_nodes);
        assert!(!exact_uniform_voter_membership(&learner, &configured));

        let without_durable_log = StoredMembership::new(
            None,
            Membership::<SessionConsensusNodeId, EmptyNode>::new(
                vec![configured.clone()],
                configured.clone(),
            ),
        );
        assert!(!exact_uniform_voter_membership(
            &without_durable_log,
            &configured
        ));
    }

    #[test]
    fn corrupt_durable_state_is_typed_as_recovery_required() {
        assert_eq!(
            ConsensusSessionStoreOpenError::RecoveryRequired,
            ConsensusSessionStoreOpenError::from(SessionConsensusStorageError::CorruptState)
        );
    }

    #[tokio::test]
    async fn store_and_forwarded_services_fail_closed_before_exact_admission() {
        let directory = tempfile::tempdir().expect("membership admission directory");
        let backend = SqliteSessionBackend::open(directory.path().join("store.sqlite"))
            .expect("membership admission SQLite backend");
        let store = ConsensusSessionStore::open(
            singleton_topology(),
            backend,
            directory.path().join("snapshots"),
            BTreeMap::new(),
        )
        .await
        .expect("open uninitialized consensus store");

        let uninitialized = store.probe_durable_readiness().await;
        assert_eq!(uninitialized.state(), DurableReadinessState::NoQuorum);
        assert_eq!(
            uninitialized.recovery_progress().state(),
            DurableRecoveryState::AwaitingQuorum
        );
        assert!(matches!(
            store
                .submit_intent(SessionMutationIntent::AdvanceLogicalTime)
                .await,
            Err(StoreError::BackendUnavailable(_))
        ));

        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let forwarded = store
            .apply_on_local_leader(
                ForwardMutationRequest {
                    request_id: SessionConsensusRequestId::new(),
                    intent: SessionMutationIntent::AdvanceLogicalTime,
                },
                deadline,
            )
            .await;
        assert_eq!(forwarded, ForwardMutationReply::Unavailable);
        assert_eq!(
            store.local_read_barrier(deadline).await,
            ReadBarrierReply::Unavailable
        );

        store
            .initialize_cluster()
            .await
            .expect("admit exact singleton membership");
        assert!(store.exact_membership_is_admitted());
        let initialized = store.probe_durable_readiness().await;
        assert!(initialized.is_ready());
        assert_eq!(
            initialized.recovery_progress().state(),
            DurableRecoveryState::Synchronized
        );
    }
}

#[cfg(test)]
mod encryption_tests;
