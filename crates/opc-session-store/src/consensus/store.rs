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
    validate_replication_log_page_owned, validate_replication_prefix_owned,
    BackendInstanceIdentity, CompareAndSet, CompareAndSetResult, ReplicationEntry,
    ReplicationLogRange, SessionBackend, SessionOp, SessionOpResult,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OperatorRecoveryCommitError {
    NotLocalLeader,
    Rejected,
    Unavailable,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConsensusPeerCallFailure {
    BeforeTransmission,
    AfterTransmission,
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
    proposal_gate: Arc<tokio::sync::Mutex<()>>,
}

/// SQLite session state coordinated by the SDK's single Openraft engine.
///
/// Call [`Self::open`] first, start the consensus-only network listener using
/// [`Self::rpc_handler`], then call [`Self::initialize_cluster`] on every
/// member. On clean first formation the method lets only the canonical lowest
/// node initialize Openraft while the other pristine nodes wait for replicated
/// membership. Restarted members with durable Openraft state skip bootstrap.
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
                proposal_gate: Arc::new(tokio::sync::Mutex::new(())),
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
    ///
    /// Concurrent calls are expected, but only the canonical lowest pristine
    /// member invokes Openraft initialization. Other pristine members wait for
    /// replicated membership, avoiding fixed-timeout split-vote lockstep.
    /// Clean first formation fails closed if the canonical member is absent.
    pub async fn initialize_cluster(&self) -> Result<(), ConsensusSessionStoreOpenError> {
        self.inner.admitted.store(false, Ordering::Release);
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or(ConsensusSessionStoreOpenError::ClusterFormationRejected)?;
        let initialized = tokio::time::timeout_at(deadline, self.inner.raft.is_initialized())
            .await
            .map_err(|_| ConsensusSessionStoreOpenError::ClusterFormationRejected)?
            .map_err(|_| ConsensusSessionStoreOpenError::EngineUnavailable)?;
        let canonical_bootstrap = self.inner.members.first().copied();
        if !initialized && canonical_bootstrap == Some(self.inner.local_node_id) {
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

    pub(crate) fn recovery_identity(&self) -> SessionConsensusIdentity {
        self.inner.identity
    }

    pub(crate) fn recovery_members(&self) -> &BTreeSet<SessionConsensusNodeId> {
        &self.inner.members
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
        let recovery_deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .unwrap_or_else(tokio::time::Instant::now);
        let recovery_pending = tokio::time::timeout_at(
            recovery_deadline,
            self.inner
                .backend
                .consensus_operator_recovery_pending(self.inner.identity),
        )
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or(true);
        if recovery_pending {
            let metrics = self.inner.raft.metrics();
            let metrics = metrics.borrow();
            let recovery_progress = DurableRecoveryProgress::new(
                DurableRecoveryState::RecoveryRequired,
                metrics.last_log_index,
                metrics.last_applied.as_ref().map(|log_id| log_id.index),
                metrics.snapshot.as_ref().map(|log_id| log_id.index),
                metrics.purged.as_ref().map(|log_id| log_id.index),
            );
            return report_without_barrier(
                DurableReadinessState::RecoveryRequired,
                recovery_progress,
            );
        }
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
        let recovery_pending = tokio::time::timeout_at(
            deadline,
            self.inner
                .backend
                .consensus_operator_recovery_pending(self.inner.identity),
        )
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or(true);
        if recovery_pending {
            return Err(consensus_unavailable());
        }
        validate_consensus_intent(&intent)?;
        let request = ForwardMutationRequest { request_id, intent };
        let mut preferred = None;
        let mut outcome_may_be_unavailable = false;

        loop {
            let leader = match preferred.take() {
                Some(leader) => leader,
                None => match self.wait_for_known_leader(deadline).await {
                    Ok(leader) => leader,
                    Err(_) if outcome_may_be_unavailable => {
                        return Err(consensus_outcome_unavailable(&request.intent));
                    }
                    Err(error) => return Err(error),
                },
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
                    Err(ConsensusPeerCallFailure::AfterTransmission) => {
                        // The peer abstraction cannot prove that a failed call
                        // stopped before delivery. Retrying this same durable
                        // request ID is safe; returning a generic unavailable
                        // error after this point is not.
                        outcome_may_be_unavailable = true;
                        if self.wait_for_route_refresh(leader, deadline).await.is_err() {
                            return Err(consensus_outcome_unavailable(&request.intent));
                        }
                        continue;
                    }
                    Err(ConsensusPeerCallFailure::BeforeTransmission) => {
                        if let Err(error) = self.wait_for_route_refresh(leader, deadline).await {
                            return if outcome_may_be_unavailable {
                                Err(consensus_outcome_unavailable(&request.intent))
                            } else {
                                Err(error)
                            };
                        }
                        continue;
                    }
                }
            };
            match reply {
                ForwardMutationReply::Applied(response) => {
                    if committed_response_matches_intent(&request.intent, &response) {
                        return Ok(*response);
                    }
                    if !outcome_may_be_unavailable
                        && rejected_response_matches_intent(&request.intent, &response)
                    {
                        return match response.result {
                            Err(error) => Err(error),
                            Ok(_) => Err(consensus_outcome_unavailable(&request.intent)),
                        };
                    }
                    return Err(consensus_outcome_unavailable(&request.intent));
                }
                ForwardMutationReply::NotLeader {
                    leader: next_leader,
                } => {
                    preferred = next_leader.filter(|candidate| {
                        *candidate != leader && self.inner.members.contains(candidate)
                    });
                    if preferred.is_none() {
                        if let Err(error) = self.wait_for_route_refresh(leader, deadline).await {
                            return if outcome_may_be_unavailable {
                                Err(consensus_outcome_unavailable(&request.intent))
                            } else {
                                Err(error)
                            };
                        }
                    }
                }
                ForwardMutationReply::Unavailable => {
                    if let Err(error) = self.wait_for_route_refresh(leader, deadline).await {
                        return if outcome_may_be_unavailable {
                            Err(consensus_outcome_unavailable(&request.intent))
                        } else {
                            Err(error)
                        };
                    }
                }
            }
        }
    }

    async fn apply_on_local_leader(
        &self,
        request: ForwardMutationRequest,
        deadline: tokio::time::Instant,
    ) -> ForwardMutationReply {
        self.apply_on_local_leader_inner(request, deadline, false)
            .await
    }

    async fn apply_on_local_leader_inner(
        &self,
        request: ForwardMutationRequest,
        deadline: tokio::time::Instant,
        allow_operator_recovery: bool,
    ) -> ForwardMutationReply {
        if self.require_exact_membership_admission().is_err() {
            return ForwardMutationReply::Unavailable;
        }
        if !allow_operator_recovery {
            let recovery_pending = match tokio::time::timeout_at(
                deadline,
                self.inner
                    .backend
                    .consensus_operator_recovery_pending(self.inner.identity),
            )
            .await
            {
                Ok(Ok(pending)) => pending,
                Ok(Err(_)) | Err(_) => return ForwardMutationReply::Unavailable,
            };
            if recovery_pending {
                return ForwardMutationReply::Unavailable;
            }
        }
        if let Err(error) =
            validate_consensus_intent_with_recovery(&request.intent, allow_operator_recovery)
        {
            return ForwardMutationReply::Applied(Box::new(SessionConsensusResponse::rejected(
                error,
            )));
        }
        let proposal_guard = match tokio::time::timeout_at(
            deadline,
            Arc::clone(&self.inner.proposal_gate).lock_owned(),
        )
        .await
        {
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

        let outcome_unavailable = consensus_outcome_unavailable(&request.intent);
        let command = super::SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: self.inner.identity,
            request_id: request.request_id,
            logical_time: self.inner.clock.now_utc(),
            intent: request.intent,
        };
        if encode_bounded(&command).is_err() {
            let max = self.inner.backend.consensus_capabilities().max_value_bytes;
            return ForwardMutationReply::Applied(Box::new(SessionConsensusResponse::rejected(
                StoreError::PayloadTooLarge {
                    actual: max.saturating_add(1),
                    max,
                },
            )));
        }

        // Split Openraft's enqueue and result phases explicitly. Once
        // `client_write_ff` returns a receiver, the proposal was accepted by
        // the local Raft core. Losing the receiver or crossing the deadline
        // after that point is an unknown committed outcome, never a safe
        // retryable availability failure.
        let response =
            match tokio::time::timeout_at(deadline, self.inner.raft.client_write_ff(command)).await
            {
                Err(_) => return ForwardMutationReply::Unavailable,
                Ok(Err(_)) => return ForwardMutationReply::Unavailable,
                Ok(Ok(response)) => response,
            };
        // Once Openraft returns the receiver, the proposal is accepted by its
        // core. A detached supervisor owns the proposal permit until Openraft
        // resolves the receiver, so caller cancellation, peer EOF, or a
        // response deadline cannot admit an unbounded queue of detached
        // mutations behind the still-running command.
        let (completion_tx, completion_rx) = tokio::sync::oneshot::channel();
        let timeout_outcome_unavailable = outcome_unavailable.clone();
        tokio::spawn(async move {
            let reply = match response.await {
                Err(_) => ForwardMutationReply::Applied(Box::new(
                    SessionConsensusResponse::rejected(outcome_unavailable.clone()),
                )),
                Ok(Ok(response)) => ForwardMutationReply::Applied(Box::new(response.data)),
                Ok(Err(ClientWriteError::ForwardToLeader(forward))) => {
                    ForwardMutationReply::NotLeader {
                        leader: forward.leader_id,
                    }
                }
                Ok(Err(ClientWriteError::ChangeMembershipError(_))) => {
                    ForwardMutationReply::Applied(Box::new(SessionConsensusResponse::rejected(
                        outcome_unavailable,
                    )))
                }
            };
            let _ = completion_tx.send(reply);
            drop(proposal_guard);
        });
        match tokio::time::timeout_at(deadline, completion_rx).await {
            Err(_) | Ok(Err(_)) => ForwardMutationReply::Applied(Box::new(
                SessionConsensusResponse::rejected(timeout_outcome_unavailable),
            )),
            Ok(Ok(reply)) => reply,
        }
    }

    pub(crate) async fn commit_operator_recovery(
        &self,
        request_id: SessionConsensusRequestId,
        recovery_epoch: u64,
        plan_digest: [u8; 32],
        fence_high_water: u64,
        credential_high_water: u64,
    ) -> Result<(), OperatorRecoveryCommitError> {
        self.require_exact_membership_admission()
            .map_err(|_| OperatorRecoveryCommitError::Unavailable)?;
        if recovery_epoch == 0 {
            return Err(OperatorRecoveryCommitError::Rejected);
        }
        let metrics = self.inner.raft.metrics();
        if metrics.borrow().current_leader != Some(self.inner.local_node_id) {
            return Err(OperatorRecoveryCommitError::NotLocalLeader);
        }
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or(OperatorRecoveryCommitError::Unavailable)?;
        let reply = self
            .apply_on_local_leader_inner(
                ForwardMutationRequest {
                    request_id,
                    intent: SessionMutationIntent::FinalizeOperatorRecovery {
                        recovery_epoch,
                        plan_digest,
                        fence_high_water,
                        credential_high_water,
                    },
                },
                deadline,
                true,
            )
            .await;
        match reply {
            ForwardMutationReply::Applied(response) => match response.result {
                Ok(SessionMutationOutcome::Unit) => Ok(()),
                Err(StoreError::InvalidKey(reason))
                    if reason == "operator_recovery_epoch_rejected" =>
                {
                    Err(OperatorRecoveryCommitError::Rejected)
                }
                _ => Err(OperatorRecoveryCommitError::Unavailable),
            },
            ForwardMutationReply::NotLeader { .. } => {
                Err(OperatorRecoveryCommitError::NotLocalLeader)
            }
            ForwardMutationReply::Unavailable => Err(OperatorRecoveryCommitError::Unavailable),
        }
    }

    pub(crate) async fn probe_operator_recovery_rejoin(
        &self,
        recovery_epoch: u64,
        plan_digest: [u8; 32],
    ) -> bool {
        if self.require_exact_membership_admission().is_err() {
            return false;
        }
        let deadline = match tokio::time::Instant::now().checked_add(self.inner.operation_timeout) {
            Some(deadline) => deadline,
            None => return false,
        };
        if !matches!(
            tokio::time::timeout_at(deadline, self.inner.raft.ensure_linearizable()).await,
            Ok(Ok(_))
        ) {
            return false;
        }
        self.exact_membership_is_admitted()
            && tokio::time::timeout_at(
                deadline,
                self.inner.backend.consensus_operator_recovery_committed(
                    self.inner.identity,
                    recovery_epoch,
                    plan_digest,
                ),
            )
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or(false)
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
    ) -> Result<Resp, ConsensusPeerCallFailure>
    where
        Req: Serialize + ?Sized,
        Resp: serde::de::DeserializeOwned,
    {
        let peer = self
            .inner
            .peers
            .get(&target)
            .filter(|peer| peer.node_id() == target)
            .ok_or(ConsensusPeerCallFailure::BeforeTransmission)?;
        let payload =
            encode_bounded(request).map_err(|_| ConsensusPeerCallFailure::BeforeTransmission)?;
        let wire = SessionConsensusWireRequest::try_new(
            self.inner.identity,
            self.inner.local_node_id,
            family,
            payload,
        )
        .map_err(|_| ConsensusPeerCallFailure::BeforeTransmission)?;
        let response = tokio::time::timeout_at(deadline, peer.call(wire))
            .await
            .map_err(|_| ConsensusPeerCallFailure::AfterTransmission)?
            .map_err(|_| ConsensusPeerCallFailure::AfterTransmission)?;
        response
            .validate()
            .map_err(|_| ConsensusPeerCallFailure::AfterTransmission)?;
        let payload = response
            .result
            .map_err(|_| ConsensusPeerCallFailure::AfterTransmission)?;
        decode_bounded(&payload).map_err(|_| ConsensusPeerCallFailure::AfterTransmission)
    }

    async fn local_read_barrier(&self, deadline: tokio::time::Instant) -> ReadBarrierReply {
        if self.require_exact_membership_admission().is_err() {
            return ReadBarrierReply::Unavailable;
        }
        let recovery_pending = tokio::time::timeout_at(
            deadline,
            self.inner
                .backend
                .consensus_operator_recovery_pending(self.inner.identity),
        )
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or(true);
        if recovery_pending {
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
            .await
            .map_err(|error| match error {
                // Advancing logical time is an idempotent implementation
                // detail of a read barrier. A lost result may have advanced
                // time, but repeating it cannot duplicate a user mutation.
                StoreError::BackendOperationOutcomeUnavailable => consensus_unavailable(),
                error => error,
            })?;
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

fn consensus_unavailable() -> StoreError {
    StoreError::BackendUnavailable("session consensus quorum is unavailable".into())
}

fn consensus_outcome_unavailable(intent: &SessionMutationIntent) -> StoreError {
    if matches!(intent, SessionMutationIntent::CompareAndSet(_)) {
        StoreError::CasIdempotencyOutcomeUnavailable
    } else {
        StoreError::BackendOperationOutcomeUnavailable
    }
}

fn committed_response_matches_intent(
    intent: &SessionMutationIntent,
    response: &SessionConsensusResponse,
) -> bool {
    if response.sequence == 0
        || response.digest.is_none()
        || response.logical_time.is_none()
        || response.raft_log_index == 0
    {
        return false;
    }
    let Some(logical_time) = response.logical_time else {
        return false;
    };
    match (&response.result, intent) {
        (Err(error), intent) => committed_error_matches_intent(intent, error),
        (Ok(SessionMutationOutcome::Unit), SessionMutationIntent::AdvanceLogicalTime)
        | (Ok(SessionMutationOutcome::Unit), SessionMutationIntent::DeleteFenced(_))
        | (Ok(SessionMutationOutcome::Unit), SessionMutationIntent::RefreshTtl { .. })
        | (Ok(SessionMutationOutcome::Unit), SessionMutationIntent::ReleaseLease(_))
        | (
            Ok(SessionMutationOutcome::Unit),
            SessionMutationIntent::FinalizeOperatorRecovery { .. },
        ) => true,
        (
            Ok(SessionMutationOutcome::CompareAndSet(CompareAndSetResult::Success)),
            SessionMutationIntent::CompareAndSet(_),
        )
        | (
            Ok(SessionMutationOutcome::CompareAndSet(CompareAndSetResult::Conflict {
                current: None,
            })),
            SessionMutationIntent::CompareAndSet(_),
        ) => true,
        (
            Ok(SessionMutationOutcome::CompareAndSet(CompareAndSetResult::Conflict {
                current: Some(current),
            })),
            SessionMutationIntent::CompareAndSet(operation),
        ) => current.key == operation.key,
        (
            Ok(SessionMutationOutcome::Lease(guard)),
            SessionMutationIntent::AcquireLease {
                key, owner, ttl, ..
            },
        ) => {
            guard.key() == key
                && guard.owner() == owner
                && guard.fence().get() != 0
                && guard.credential_id() != 0
                && guard.acquired_at() == logical_time
                && checked_session_deadline(logical_time, *ttl)
                    .is_ok_and(|expires_at| guard.expires_at() == expires_at)
        }
        (
            Ok(SessionMutationOutcome::Lease(renewed)),
            SessionMutationIntent::RenewLease { lease, ttl },
        ) => {
            renewed.key() == lease.key()
                && renewed.owner() == lease.owner()
                && renewed.fence() == lease.fence()
                && renewed.credential_id() == lease.credential_id()
                && renewed.acquired_at() == lease.acquired_at()
                && checked_session_deadline(logical_time, *ttl)
                    .is_ok_and(|expires_at| renewed.expires_at() == expires_at)
        }
        _ => false,
    }
}

fn rejected_response_matches_intent(
    intent: &SessionMutationIntent,
    response: &SessionConsensusResponse,
) -> bool {
    // The original private forwarding wire shape does not echo the request ID.
    // Keep the existing private wire discriminants stable, but accept a rejection as
    // preproposal only when it carries the sentinel non-committed metadata and
    // the error is one this exact intent can encounter before submission.
    response.sequence == 0
        && response.digest.is_none()
        && response.logical_time.is_none()
        && response.raft_log_index == 0
        && matches!(
            &response.result,
            Err(error) if rejected_error_matches_intent(intent, error)
        )
}

fn rejected_error_matches_intent(_: &SessionMutationIntent, error: &StoreError) -> bool {
    // Normal callers validate intent before routing. The only remaining
    // preproposal rejection is the fixed bounded-command encoding limit.
    matches!(error, StoreError::PayloadTooLarge { .. })
}

fn committed_error_matches_intent(intent: &SessionMutationIntent, error: &StoreError) -> bool {
    match intent {
        SessionMutationIntent::AdvanceLogicalTime => false,
        SessionMutationIntent::CompareAndSet(_) => matches!(
            error,
            StoreError::NotFound
                | StoreError::StaleFence
                | StoreError::InvalidKey(_)
                | StoreError::LeaseExpired
                | StoreError::PayloadTooLarge { .. }
        ),
        SessionMutationIntent::DeleteFenced(_) => matches!(
            error,
            StoreError::NotFound | StoreError::StaleFence | StoreError::LeaseExpired
        ),
        SessionMutationIntent::RefreshTtl { .. } => matches!(
            error,
            StoreError::NotFound
                | StoreError::StaleFence
                | StoreError::InvalidSessionTtl
                | StoreError::LeaseExpired
        ),
        SessionMutationIntent::AcquireLease { .. } => {
            matches!(error, StoreError::InvalidSessionTtl | StoreError::LeaseHeld)
        }
        SessionMutationIntent::RenewLease { .. } => matches!(
            error,
            StoreError::NotFound
                | StoreError::StaleFence
                | StoreError::InvalidSessionTtl
                | StoreError::LeaseHeld
                | StoreError::LeaseExpired
        ),
        SessionMutationIntent::ReleaseLease(_) => matches!(
            error,
            StoreError::NotFound | StoreError::StaleFence | StoreError::LeaseHeld
        ),
        SessionMutationIntent::FinalizeOperatorRecovery { .. } => {
            matches!(error, StoreError::InvalidKey(reason) if reason == "operator_recovery_epoch_rejected")
        }
    }
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
    validate_consensus_intent_with_recovery(intent, false)
}

fn validate_consensus_intent_with_recovery(
    intent: &SessionMutationIntent,
    allow_operator_recovery: bool,
) -> Result<(), StoreError> {
    if matches!(
        intent,
        SessionMutationIntent::FinalizeOperatorRecovery { .. }
    ) && !allow_operator_recovery
    {
        return Err(StoreError::CapabilityNotSupported(
            "operator_recovery_requires_local_admin_authority".into(),
        ));
    }
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
            _ => Err(StoreError::CasIdempotencyOutcomeUnavailable),
        }
    }

    async fn delete_fenced(&self, lease: &LeaseGuard) -> Result<(), StoreError> {
        let response = self
            .submit_intent(SessionMutationIntent::DeleteFenced(lease.clone()))
            .await?;
        match response.result? {
            SessionMutationOutcome::Unit => Ok(()),
            _ => Err(StoreError::BackendOperationOutcomeUnavailable),
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
            _ => Err(StoreError::BackendOperationOutcomeUnavailable),
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
        let range = ReplicationLogRange::try_new(start, limit)?;
        if range.is_empty() {
            return Ok(Vec::new());
        }
        self.logical_read_time().await?;
        validate_replication_log_page_owned(
            start,
            limit,
            self.inner
                .backend
                .consensus_get_replication_log(start, limit)
                .await?,
        )
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
            _ => Err(LeaseError::OperationOutcomeUnavailable),
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
            _ => Err(LeaseError::OperationOutcomeUnavailable),
        }
    }

    async fn release(&self, lease: LeaseGuard) -> Result<(), LeaseError> {
        let response = self
            .submit_intent(SessionMutationIntent::ReleaseLease(lease))
            .await
            .map_err(LeaseError::from)?;
        match response.result.map_err(LeaseError::from)? {
            SessionMutationOutcome::Unit => Ok(()),
            _ => Err(LeaseError::OperationOutcomeUnavailable),
        }
    }
}

#[cfg(test)]
mod membership_tests {
    use bytes::Bytes;
    use opc_consensus::engine::{CommittedLeaderId, Membership};
    use opc_consensus::{
        derive_configuration_id, ConsensusClusterId, ConsensusConfigurationEpoch, ConsensusIdentity,
    };

    use super::*;
    use crate::model::{FenceToken, Generation, SessionKeyType, StateClass, StateType};
    use crate::record::EncryptedSessionPayload;
    use crate::topology::{
        QuorumReplicaDescriptor, ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain,
        ReplicaId, ReplicaTlsIdentity,
    };
    use opc_types::{NetworkFunctionKind, TenantId};

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

    #[test]
    fn forwarded_mutation_responses_are_bound_to_the_exact_intent() {
        let key = |stable_id: &'static [u8]| SessionKey {
            tenant: TenantId::new("forward-response-binding").expect("tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(stable_id).try_into().expect("stable ID"),
        };
        let key_a = key(b"key-a");
        let key_b = key(b"key-b");
        let owner_a = OwnerId::new("owner-a").expect("owner");
        let owner_b = OwnerId::new("owner-b").expect("owner");
        let logical_time = Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH);
        let ttl = Duration::from_secs(60);
        let expires_at = checked_session_deadline(logical_time, ttl).expect("lease deadline");
        let lease_a = LeaseGuard::new(
            key_a.clone(),
            owner_a.clone(),
            FenceToken::new(7),
            logical_time,
            expires_at,
            9,
        );
        let record = |key: SessionKey| StoredSessionRecord {
            key,
            generation: Generation::new(1),
            owner: owner_a.clone(),
            fence: lease_a.fence(),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::new("forward-response-binding").expect("state type"),
            expires_at: None,
            payload: EncryptedSessionPayload::new(Bytes::from_static(b"payload")),
        };
        let cas = CompareAndSet {
            key: key_a.clone(),
            lease: lease_a.clone(),
            expected_generation: None,
            new_record: record(key_a.clone()),
        };
        let committed = |result| SessionConsensusResponse {
            result,
            sequence: 1,
            digest: Some(crate::consensus::SessionConsensusEntryDigest::from_bytes(
                [0x5a; 32],
            )),
            logical_time: Some(logical_time),
            raft_log_index: 1,
        };

        let rejected =
            SessionConsensusResponse::rejected(StoreError::PayloadTooLarge { actual: 2, max: 1 });
        assert!(rejected_response_matches_intent(
            &SessionMutationIntent::AdvanceLogicalTime,
            &rejected
        ));
        assert!(!committed_response_matches_intent(
            &SessionMutationIntent::AdvanceLogicalTime,
            &rejected
        ));
        assert!(!rejected_response_matches_intent(
            &SessionMutationIntent::AdvanceLogicalTime,
            &SessionConsensusResponse::rejected(StoreError::BackendOperationOutcomeUnavailable)
        ));

        let cas_intent = SessionMutationIntent::CompareAndSet(Box::new(cas));
        assert!(!committed_response_matches_intent(
            &cas_intent,
            &committed(Ok(SessionMutationOutcome::Unit))
        ));
        assert!(!committed_response_matches_intent(
            &cas_intent,
            &committed(Err(StoreError::CasConflict))
        ));
        assert!(!committed_response_matches_intent(
            &cas_intent,
            &committed(Ok(SessionMutationOutcome::CompareAndSet(
                CompareAndSetResult::Conflict {
                    current: Some(record(key_b)),
                },
            )))
        ));
        assert!(committed_response_matches_intent(
            &cas_intent,
            &committed(Ok(SessionMutationOutcome::CompareAndSet(
                CompareAndSetResult::Conflict {
                    current: Some(record(key_a.clone())),
                },
            )))
        ));

        assert!(!committed_response_matches_intent(
            &SessionMutationIntent::ReleaseLease(lease_a.clone()),
            &committed(Err(StoreError::LeaseExpired))
        ));

        let acquire = SessionMutationIntent::AcquireLease {
            key: key_a.clone(),
            owner: owner_a.clone(),
            ttl,
        };
        assert!(committed_response_matches_intent(
            &acquire,
            &committed(Ok(SessionMutationOutcome::Lease(lease_a.clone())))
        ));
        let forged_acquire = LeaseGuard::new(
            key_a.clone(),
            owner_b,
            lease_a.fence(),
            logical_time,
            expires_at,
            lease_a.credential_id(),
        );
        assert!(!committed_response_matches_intent(
            &acquire,
            &committed(Ok(SessionMutationOutcome::Lease(forged_acquire)))
        ));

        let renew = SessionMutationIntent::RenewLease {
            lease: lease_a.clone(),
            ttl,
        };
        assert!(committed_response_matches_intent(
            &renew,
            &committed(Ok(SessionMutationOutcome::Lease(lease_a.clone())))
        ));
        let forged_renew = LeaseGuard::new(
            key_a,
            owner_a,
            lease_a.fence(),
            lease_a.acquired_at(),
            expires_at,
            lease_a.credential_id() + 1,
        );
        assert!(!committed_response_matches_intent(
            &renew,
            &committed(Ok(SessionMutationOutcome::Lease(forged_renew)))
        ));
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

    #[tokio::test]
    async fn accepted_local_proposals_remain_supervised_after_timeout_and_cancellation() {
        let directory = tempfile::tempdir().expect("proposal supervision directory");
        let backend = SqliteSessionBackend::open(directory.path().join("store.sqlite"))
            .expect("proposal supervision SQLite backend");
        let apply_gate = Arc::clone(&backend.consensus_apply_gate);
        let store = ConsensusSessionStore::open_with_clock(
            singleton_topology(),
            backend,
            directory.path().join("snapshots"),
            BTreeMap::new(),
            Arc::new(SystemClock),
            Duration::from_millis(150),
        )
        .await
        .expect("open proposal supervision store");
        store
            .initialize_cluster()
            .await
            .expect("initialize proposal supervision store");

        let wait_for_submission = |store: ConsensusSessionStore, before: u64| async move {
            tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    if store.inner.raft.metrics().borrow().last_log_index > Some(before) {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("proposal reaches the real Openraft log");
        };
        let wait_for_supervisor = |store: ConsensusSessionStore| async move {
            let guard = tokio::time::timeout(
                Duration::from_secs(1),
                Arc::clone(&store.inner.proposal_gate).lock_owned(),
            )
            .await
            .expect("proposal supervisor releases admission after apply");
            drop(guard);
        };

        // Dropping the original caller after Openraft accepted its proposal
        // must not release admission or permit a disconnect flood to enqueue
        // more detached commands.
        let held_apply = Arc::clone(&apply_gate)
            .acquire_owned()
            .await
            .expect("hold state-machine apply");
        let before = store
            .inner
            .raft
            .metrics()
            .borrow()
            .last_log_index
            .unwrap_or(0);
        let cancelled_store = store.clone();
        let cancelled = tokio::spawn(async move {
            cancelled_store
                .submit_intent(SessionMutationIntent::AdvanceLogicalTime)
                .await
        });
        wait_for_submission(store.clone(), before).await;
        cancelled.abort();
        let _ = cancelled.await;
        assert!(
            Arc::clone(&store.inner.proposal_gate)
                .try_lock_owned()
                .is_err(),
            "accepted proposal admission must outlive its cancelled caller"
        );
        let flood = (0..16)
            .map(|_| {
                let store = store.clone();
                tokio::spawn(async move {
                    store
                        .submit_intent(SessionMutationIntent::AdvanceLogicalTime)
                        .await
                })
            })
            .collect::<Vec<_>>();
        for attempt in flood {
            assert!(matches!(
                attempt.await.expect("queued flood task"),
                Err(StoreError::BackendUnavailable(_))
            ));
        }
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            Some(before + 1),
            "cancelled callers cannot build an unbounded Openraft queue"
        );
        drop(held_apply);
        wait_for_supervisor(store.clone()).await;

        // A live non-CAS caller that crosses the same post-submit boundary
        // receives typed ambiguity while the supervisor continues to own
        // admission until the delayed state-machine result arrives.
        let held_apply = Arc::clone(&apply_gate)
            .acquire_owned()
            .await
            .expect("hold state-machine apply for non-CAS");
        let before = store
            .inner
            .raft
            .metrics()
            .borrow()
            .last_log_index
            .unwrap_or(0);
        let mutation_store = store.clone();
        let mutation = tokio::spawn(async move {
            mutation_store
                .submit_intent(SessionMutationIntent::AdvanceLogicalTime)
                .await
        });
        wait_for_submission(store.clone(), before).await;
        assert_eq!(
            mutation.await.expect("non-CAS task"),
            Err(StoreError::BackendOperationOutcomeUnavailable)
        );
        assert!(Arc::clone(&store.inner.proposal_gate)
            .try_lock_owned()
            .is_err());
        drop(held_apply);
        wait_for_supervisor(store.clone()).await;

        // Lease APIs must translate that same committed-unknown boundary to
        // their lease-specific non-retryable outcome.
        let held_apply = Arc::clone(&apply_gate)
            .acquire_owned()
            .await
            .expect("hold state-machine apply for lease");
        let before = store
            .inner
            .raft
            .metrics()
            .borrow()
            .last_log_index
            .unwrap_or(0);
        let key = SessionKey {
            tenant: TenantId::new("proposal-supervision").expect("tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"lease-timeout")
                .try_into()
                .expect("stable ID"),
        };
        let lease_store = store.clone();
        let lease = tokio::spawn(async move {
            lease_store
                .acquire(
                    &key,
                    OwnerId::new("proposal-supervision-owner").expect("owner"),
                    Duration::from_secs(30),
                )
                .await
        });
        wait_for_submission(store.clone(), before).await;
        assert_eq!(
            lease.await.expect("lease task"),
            Err(LeaseError::OperationOutcomeUnavailable)
        );
        assert!(Arc::clone(&store.inner.proposal_gate)
            .try_lock_owned()
            .is_err());
        drop(held_apply);
        wait_for_supervisor(store).await;
    }
}

#[cfg(test)]
mod encryption_tests;
