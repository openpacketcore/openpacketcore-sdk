//! ConfigStore implementation coordinated exclusively by Openraft.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use opc_consensus::engine::error::{ClientWriteError, InitializeError, RaftError};
use opc_consensus::engine::{Config, EmptyNode, LogId, SnapshotPolicy, StoredMembership};
use opc_consensus::{
    encode_bounded, ConsensusNodeId, ConsensusPeer, ConsensusPeerError, ConsensusRpcFamily,
    ConsensusRpcHandler, ConsensusWireRequest, ConsensusWireResponse,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::raft_adapter::{ConfigRaftAdapterError, ConfigRaftNetworkFactory, ConfigRaftRpcHandler};
use super::storage::{self, ConfigConsensusStorageError};
use super::types::{
    bind_audit_identity, decode_config_wire, encode_config_wire, ValidatedRollbackLabel,
};
use super::{
    ApprovedLegacyConfigRecovery, ConfigConsensusClock, ConfigConsensusResponse,
    ConfigConsensusTopology, ConfigMutationIntent, ConfigRaft, PreparedConfigCommit,
    SystemConfigConsensusClock,
};
use crate::backend::SqliteBackend;
use crate::error::PersistError;
use crate::preflight::PersistCapabilities;
use crate::types::{
    AttestedConfigCommit, AuditRecord, CommitRecord, ConfigStore, RollbackTarget, StoredConfig,
};

/// Complete client-operation deadline including routing, quorum, commit, and apply.
pub const DEFAULT_CONFIG_CONSENSUS_OPERATION_TIMEOUT: Duration = Duration::from_secs(10);

const HEARTBEAT_MILLIS: u64 = 250;
const ELECTION_MIN_MILLIS: u64 = 1_000;
const ELECTION_MAX_MILLIS: u64 = 2_000;
const ROUTE_RETRY_BACKOFF: Duration = Duration::from_millis(50);
const SNAPSHOT_CHUNK_BYTES: u64 = 1024 * 1024;
const LOGS_PER_SNAPSHOT: u64 = 4_096;
const RETAINED_LOGS: u64 = 1_024;
const MAX_FORWARDED_BUDGET: Duration = Duration::from_secs(60);
const REQUEST_ID_DOMAIN: &[u8] = b"openpacketcore/config-consensus/request-id/v1\0";

/// Fail-closed construction or cluster-formation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ConfigConsensusOpenError {
    /// Peer routes did not exactly cover every remote configured voter.
    #[error("config consensus peer set does not match topology")]
    PeerSetMismatch,
    /// Legacy authority requires an explicit approved recovery snapshot.
    #[error("config consensus legacy recovery is required")]
    RecoveryRequired,
    /// Persisted identity or schema differs from this deployment.
    #[error("config consensus durable identity does not match configuration")]
    DurableIdentityMismatch,
    /// Durable SQLite or snapshot storage could not be opened.
    #[error("config consensus durable storage is unavailable")]
    StorageUnavailable,
    /// Fixed Openraft runtime profile or deadline was invalid.
    #[error("config consensus runtime configuration is invalid")]
    InvalidRuntimeConfiguration,
    /// Openraft could not start or stopped fatally.
    #[error("config consensus engine is unavailable")]
    EngineUnavailable,
    /// Exact voter formation did not converge before the deadline.
    #[error("config consensus cluster formation was rejected")]
    ClusterFormationRejected,
}

impl From<ConfigConsensusStorageError> for ConfigConsensusOpenError {
    fn from(error: ConfigConsensusStorageError) -> Self {
        match error {
            ConfigConsensusStorageError::RecoveryRequired => Self::RecoveryRequired,
            ConfigConsensusStorageError::IdentityMismatch
            | ConfigConsensusStorageError::SchemaVersionMismatch
            | ConfigConsensusStorageError::CorruptState
            | ConfigConsensusStorageError::InvalidIdentity => Self::DurableIdentityMismatch,
            ConfigConsensusStorageError::BackendUnavailable => Self::StorageUnavailable,
        }
    }
}

impl From<ConfigRaftAdapterError> for ConfigConsensusOpenError {
    fn from(_: ConfigRaftAdapterError) -> Self {
        Self::PeerSetMismatch
    }
}

/// Redaction-safe current engine observation for readiness and telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ConfigConsensusStatus {
    /// Local canonical node ID.
    pub node_id: ConsensusNodeId,
    /// Current Openraft term.
    pub term: u64,
    /// Current leader, when known.
    pub leader_id: Option<ConsensusNodeId>,
    /// Highest locally applied log index.
    pub applied_index: Option<u64>,
    /// Highest locally committed log index.
    pub committed_index: Option<u64>,
    /// Non-secret audit-key rotation epoch admitted by this node.
    pub audit_key_epoch: u64,
    /// Non-secret, purpose-separated fingerprint used for fleet compatibility.
    pub audit_key_fingerprint: [u8; 32],
    /// Whether exact configured membership has been admitted and remains live.
    pub admitted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ForwardedBudget {
    remaining_nanos: u64,
}

impl ForwardedBudget {
    fn from_deadline(deadline: tokio::time::Instant) -> Result<Self, PersistError> {
        let remaining = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .filter(|remaining| !remaining.is_zero() && *remaining <= MAX_FORWARDED_BUDGET)
            .ok_or_else(consensus_unavailable)?;
        let remaining_nanos =
            u64::try_from(remaining.as_nanos()).map_err(|_| consensus_unavailable())?;
        Ok(Self { remaining_nanos })
    }

    fn inbound_deadline(self, local_timeout: Duration) -> Option<tokio::time::Instant> {
        if self.remaining_nanos == 0 {
            return None;
        }
        let remaining = Duration::from_nanos(self.remaining_nanos);
        if remaining > MAX_FORWARDED_BUDGET || local_timeout.is_zero() {
            return None;
        }
        tokio::time::Instant::now().checked_add(remaining.min(local_timeout))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ForwardMutationRequest {
    request_id: opc_consensus::ConsensusRequestId,
    intent: ConfigMutationIntent,
    budget: ForwardedBudget,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
enum ForwardMutationReply {
    Applied(Box<ConfigConsensusResponse>),
    NotLeader { leader: Option<ConsensusNodeId> },
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadBarrierRequest {
    budget: ForwardedBudget,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum ReadBarrierReply {
    Ready(Option<LogId<ConsensusNodeId>>),
    NotLeader { leader: Option<ConsensusNodeId> },
    Unavailable,
}

struct ConsensusConfigStoreInner {
    raft: ConfigRaft,
    raft_handler: ConfigRaftRpcHandler,
    backend: SqliteBackend,
    identity: opc_consensus::ConsensusIdentity,
    local_node_id: ConsensusNodeId,
    peers: BTreeMap<ConsensusNodeId, Arc<dyn ConsensusPeer>>,
    members: BTreeSet<ConsensusNodeId>,
    clock: Arc<dyn ConfigConsensusClock>,
    operation_timeout: Duration,
    admitted: AtomicBool,
    proposal_gate: tokio::sync::Mutex<()>,
    metric_leader: std::sync::Mutex<Option<ConsensusNodeId>>,
    durable_progress: Arc<storage::ConfigDurableProgress>,
}

/// SQLite config state coordinated by the SDK's shared Openraft engine.
#[derive(Clone)]
pub struct ConsensusConfigStore {
    inner: Arc<ConsensusConfigStoreInner>,
}

impl fmt::Debug for ConsensusConfigStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConsensusConfigStore")
            .field("identity", &self.inner.identity)
            .field("local_node_id", &self.inner.local_node_id)
            .field("configured_members", &self.inner.members.len())
            .finish_non_exhaustive()
    }
}

impl ConsensusConfigStore {
    /// Start a durable node. Install [`Self::rpc_handler`] on an authenticated
    /// shared consensus listener before calling [`Self::initialize_cluster`].
    pub async fn open(
        topology: ConfigConsensusTopology,
        backend: SqliteBackend,
        snapshot_dir: impl Into<PathBuf>,
        peers: BTreeMap<ConsensusNodeId, Arc<dyn ConsensusPeer>>,
    ) -> Result<Self, ConfigConsensusOpenError> {
        Self::open_with_clock(
            topology,
            backend,
            snapshot_dir,
            peers,
            Arc::new(SystemConfigConsensusClock),
            DEFAULT_CONFIG_CONSENSUS_OPERATION_TIMEOUT,
        )
        .await
    }

    /// Start with an explicit complete operation timeout.
    pub async fn open_with_operation_timeout(
        topology: ConfigConsensusTopology,
        backend: SqliteBackend,
        snapshot_dir: impl Into<PathBuf>,
        peers: BTreeMap<ConsensusNodeId, Arc<dyn ConsensusPeer>>,
        operation_timeout: Duration,
    ) -> Result<Self, ConfigConsensusOpenError> {
        Self::open_with_clock(
            topology,
            backend,
            snapshot_dir,
            peers,
            Arc::new(SystemConfigConsensusClock),
            operation_timeout,
        )
        .await
    }

    // Kept private so a production caller cannot inject a blocking or
    // non-monotonic clock into the proposal path. Unit tests in this module
    // may still exercise deterministic logical time.
    async fn open_with_clock(
        topology: ConfigConsensusTopology,
        backend: SqliteBackend,
        snapshot_dir: impl Into<PathBuf>,
        peers: BTreeMap<ConsensusNodeId, Arc<dyn ConsensusPeer>>,
        clock: Arc<dyn ConfigConsensusClock>,
        operation_timeout: Duration,
    ) -> Result<Self, ConfigConsensusOpenError> {
        Self::open_internal(
            topology,
            backend,
            snapshot_dir.into(),
            peers,
            clock,
            operation_timeout,
            None,
        )
        .await
    }

    /// Atomically replace nonempty legacy authority with one exact
    /// operator-approved applied snapshot and claim Openraft authority.
    pub async fn open_with_legacy_recovery(
        topology: ConfigConsensusTopology,
        backend: SqliteBackend,
        snapshot_dir: impl Into<PathBuf>,
        peers: BTreeMap<ConsensusNodeId, Arc<dyn ConsensusPeer>>,
        approval: ApprovedLegacyConfigRecovery,
    ) -> Result<Self, ConfigConsensusOpenError> {
        Self::open_internal(
            topology,
            backend,
            snapshot_dir.into(),
            peers,
            Arc::new(SystemConfigConsensusClock),
            DEFAULT_CONFIG_CONSENSUS_OPERATION_TIMEOUT,
            Some(approval),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn open_internal(
        topology: ConfigConsensusTopology,
        backend: SqliteBackend,
        snapshot_dir: PathBuf,
        peers: BTreeMap<ConsensusNodeId, Arc<dyn ConsensusPeer>>,
        clock: Arc<dyn ConfigConsensusClock>,
        operation_timeout: Duration,
        recovery: Option<ApprovedLegacyConfigRecovery>,
    ) -> Result<Self, ConfigConsensusOpenError> {
        if operation_timeout.is_zero() || operation_timeout > Duration::from_secs(60) {
            return Err(ConfigConsensusOpenError::InvalidRuntimeConfiguration);
        }
        let identity = bind_audit_identity(topology.identity(), backend.audit_key());
        let local_node_id = topology.local_node_id();
        let members = topology.members().clone();
        let expected_peers = members
            .iter()
            .copied()
            .filter(|node_id| *node_id != local_node_id)
            .collect::<BTreeSet<_>>();
        if peers.keys().copied().collect::<BTreeSet<_>>() != expected_peers {
            return Err(ConfigConsensusOpenError::PeerSetMismatch);
        }
        let network = ConfigRaftNetworkFactory::try_new(identity, local_node_id, peers.clone())?;
        let (log_store, state_machine, durable_progress) = if let Some(recovery) = recovery {
            storage::open_with_recovery(
                &backend,
                snapshot_dir,
                identity,
                members.clone(),
                Some(recovery),
            )
            .await?
        } else {
            storage::open(&backend, snapshot_dir, identity, members.clone()).await?
        };
        let raft = ConfigRaft::new(
            local_node_id,
            Arc::new(config_raft_config()?),
            network,
            log_store,
            state_machine,
        )
        .await
        .map_err(|_| ConfigConsensusOpenError::EngineUnavailable)?;
        let raft_handler = ConfigRaftRpcHandler::new(raft.clone(), identity, local_node_id);
        Ok(Self {
            inner: Arc::new(ConsensusConfigStoreInner {
                raft,
                raft_handler,
                backend,
                identity,
                local_node_id,
                peers,
                members,
                clock,
                operation_timeout,
                admitted: AtomicBool::new(false),
                proposal_gate: tokio::sync::Mutex::new(()),
                metric_leader: std::sync::Mutex::new(None),
                durable_progress,
            }),
        })
    }

    /// Shared authenticated consensus-only handler.
    pub fn rpc_handler(&self) -> Arc<dyn ConsensusRpcHandler> {
        Arc::new(ConfigConsensusService {
            store: self.clone(),
        })
    }

    /// Initialize a pristine cluster or re-admit an already initialized node.
    pub async fn initialize_cluster(&self) -> Result<(), ConfigConsensusOpenError> {
        self.inner.admitted.store(false, Ordering::Release);
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or(ConfigConsensusOpenError::ClusterFormationRejected)?;
        let initialize = tokio::time::timeout_at(
            deadline,
            self.inner.raft.initialize(self.inner.members.clone()),
        )
        .await
        .map_err(|_| ConfigConsensusOpenError::ClusterFormationRejected)?;
        match initialize {
            Ok(()) | Err(RaftError::APIError(InitializeError::NotAllowed(_))) => {}
            Err(RaftError::APIError(InitializeError::NotInMembers(_))) => {
                return Err(ConfigConsensusOpenError::ClusterFormationRejected)
            }
            Err(RaftError::Fatal(_)) => return Err(ConfigConsensusOpenError::EngineUnavailable),
        }
        self.wait_for_admissible_membership(deadline).await?;
        self.inner.admitted.store(true, Ordering::Release);
        if !self.exact_membership_is_admitted() {
            return Err(ConfigConsensusOpenError::ClusterFormationRejected);
        }
        self.publish_global_metrics();
        Ok(())
    }

    /// Fresh status sourced from Openraft metrics, never from a second state machine.
    pub fn status(&self) -> ConfigConsensusStatus {
        self.publish_global_metrics();
        let metrics = self.inner.raft.metrics();
        let metrics = metrics.borrow();
        ConfigConsensusStatus {
            node_id: self.inner.local_node_id,
            term: metrics.current_term,
            leader_id: metrics.current_leader,
            applied_index: metrics.last_applied.as_ref().map(|log_id| log_id.index),
            // Openraft metrics expose applied but not committed. The storage
            // adapter publishes the separately persisted committed pointer.
            committed_index: self.inner.durable_progress.committed_index(),
            audit_key_epoch: self.inner.backend.audit_key().epoch(),
            audit_key_fingerprint: self.inner.backend.audit_key().fingerprint(),
            admitted: self.exact_membership_is_admitted(),
        }
    }

    /// Prove quorum through the same read-index path used by authoritative reads.
    pub async fn probe_durable_readiness(&self) -> Result<(), PersistError> {
        self.linearizable_barrier().await.map(|_| ())
    }

    /// Ask Openraft to build and compact a state-machine snapshot.
    ///
    /// This is a maintenance trigger only; Openraft remains the sole snapshot
    /// and compaction authority.
    pub async fn trigger_snapshot(&self) -> Result<(), PersistError> {
        self.require_admission()?;
        let result = tokio::time::timeout(
            self.inner.operation_timeout,
            self.inner.raft.trigger().snapshot(),
        )
        .await
        .map_err(|_| consensus_unavailable())?
        .map_err(|_| consensus_unavailable());
        self.publish_global_metrics();
        result
    }

    /// Stop this Openraft node and all of its engine tasks.
    pub async fn shutdown(&self) -> Result<(), PersistError> {
        self.inner
            .raft
            .shutdown()
            .await
            .map_err(|_| consensus_unavailable())
    }

    /// Append with a caller-retained durable request ID so a timed-out caller
    /// can recover the original committed outcome after restart or failover.
    pub async fn append_commit_idempotent(
        &self,
        request_id: opc_consensus::ConsensusRequestId,
        commit: AttestedConfigCommit,
    ) -> Result<(), PersistError> {
        let (record, audit) = commit.into_parts();
        let prepared =
            PreparedConfigCommit::prepare(record, audit, self.inner.backend.audit_key())?;
        self.submit_request(
            request_id,
            ConfigMutationIntent::AppendCommit(Box::new(prepared)),
        )
        .await?
        .into_result()
    }

    /// Confirm with a caller-retained durable request ID.
    pub async fn mark_confirmed_idempotent(
        &self,
        request_id: opc_consensus::ConsensusRequestId,
        tx_id: opc_types::TxId,
    ) -> Result<(), PersistError> {
        self.submit_request(request_id, ConfigMutationIntent::MarkConfirmed { tx_id })
            .await?
            .into_result()
    }

    /// Create a rollback point with a caller-retained durable request ID.
    pub async fn create_rollback_point_idempotent(
        &self,
        request_id: opc_consensus::ConsensusRequestId,
        tx_id: opc_types::TxId,
        label: Option<String>,
    ) -> Result<(), PersistError> {
        let label = label.map(ValidatedRollbackLabel::try_new).transpose()?;
        self.submit_request(
            request_id,
            ConfigMutationIntent::CreateRollbackPoint { tx_id, label },
        )
        .await?
        .into_result()
    }

    /// Re-assert the immutable configured voter set.
    ///
    /// Config consensus does not expose a second membership policy. Changing
    /// membership requires a new, explicitly coordinated topology epoch; a
    /// subset cannot be admitted under the current durable identity.
    pub async fn change_membership(
        &self,
        new_voters: BTreeSet<ConsensusNodeId>,
    ) -> Result<(), PersistError> {
        if new_voters != self.inner.members {
            return Err(PersistError::inconsistent_state(
                "config consensus voter set is immutable within an epoch",
            ));
        }
        self.probe_durable_readiness().await
    }

    async fn wait_for_admissible_membership(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<(), ConfigConsensusOpenError> {
        let mut metrics = self.inner.raft.metrics();
        loop {
            {
                let current = metrics.borrow();
                if current.running_state.is_err() {
                    return Err(ConfigConsensusOpenError::EngineUnavailable);
                }
                let membership = current.membership_config.as_ref();
                if exact_uniform_voter_membership(membership, &self.inner.members) {
                    return Ok(());
                }
            }
            match tokio::time::timeout_at(deadline, metrics.changed()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => return Err(ConfigConsensusOpenError::EngineUnavailable),
                Err(_) => return Err(ConfigConsensusOpenError::ClusterFormationRejected),
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

    fn require_admission(&self) -> Result<(), PersistError> {
        if self.exact_membership_is_admitted() {
            Ok(())
        } else {
            Err(consensus_unavailable())
        }
    }

    fn is_live_voter(&self, node_id: ConsensusNodeId) -> bool {
        self.inner
            .raft
            .metrics()
            .borrow()
            .membership_config
            .membership()
            .voter_ids()
            .any(|voter| voter == node_id)
    }

    async fn submit_request(
        &self,
        request_id: opc_consensus::ConsensusRequestId,
        intent: ConfigMutationIntent,
    ) -> Result<ConfigConsensusResponse, PersistError> {
        let result = self.submit_request_inner(request_id, intent).await;
        let metric = if result.is_ok() {
            &opc_redaction::metrics::METRICS.persist_quorum_write_success
        } else {
            &opc_redaction::metrics::METRICS.persist_quorum_write_failure
        };
        metric.fetch_add(1, Ordering::Relaxed);
        self.publish_global_metrics();
        result
    }

    async fn submit_request_inner(
        &self,
        request_id: opc_consensus::ConsensusRequestId,
        intent: ConfigMutationIntent,
    ) -> Result<ConfigConsensusResponse, PersistError> {
        self.require_admission()?;
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        let mut preferred = None;
        loop {
            let leader = match preferred.take() {
                Some(leader) => leader,
                None => self.wait_for_known_leader(deadline).await?,
            };
            let request = ForwardMutationRequest {
                request_id,
                intent: intent.clone(),
                budget: ForwardedBudget::from_deadline(deadline)?,
            };
            let reply = if leader == self.inner.local_node_id {
                self.apply_on_local_leader(request.clone(), deadline).await
            } else {
                match self
                    .call_peer::<_, ForwardMutationReply>(
                        leader,
                        ConsensusRpcFamily::ForwardMutation,
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
                    self.require_admission()?;
                    return Ok(*response);
                }
                ForwardMutationReply::NotLeader { leader: next } => {
                    opc_redaction::metrics::METRICS
                        .persist_stale_leader_rejections
                        .fetch_add(1, Ordering::Relaxed);
                    preferred = next.filter(|candidate| {
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
        if self.require_admission().is_err() {
            return ForwardMutationReply::Unavailable;
        }
        let _guard = match tokio::time::timeout_at(deadline, self.inner.proposal_gate.lock()).await
        {
            Ok(guard) => guard,
            Err(_) => return ForwardMutationReply::Unavailable,
        };
        match tokio::time::timeout_at(deadline, self.inner.raft.ensure_linearizable()).await {
            Err(_) => return ForwardMutationReply::Unavailable,
            Ok(Ok(_)) if self.require_admission().is_ok() => {}
            Ok(Ok(_)) => return ForwardMutationReply::Unavailable,
            Ok(Err(error)) => {
                return ForwardMutationReply::NotLeader {
                    leader: error
                        .forward_to_leader()
                        .and_then(|forward| forward.leader_id),
                }
            }
        }
        let command = super::ConfigConsensusCommand {
            schema_version: super::CONFIG_CONSENSUS_COMMAND_VERSION,
            identity: self.inner.identity,
            request_id: request.request_id,
            logical_time: self.inner.clock.now_utc(),
            intent: request.intent,
        };
        if command.validate(self.inner.identity).is_err() || encode_bounded(&command).is_err() {
            return ForwardMutationReply::Unavailable;
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
    ) -> Result<ConsensusNodeId, PersistError> {
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
        attempted_leader: ConsensusNodeId,
        deadline: tokio::time::Instant,
    ) -> Result<(), PersistError> {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(consensus_unavailable());
        }
        let retry_deadline = now
            .checked_add(ROUTE_RETRY_BACKOFF)
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
        target: ConsensusNodeId,
        family: ConsensusRpcFamily,
        request: &Req,
        deadline: tokio::time::Instant,
    ) -> Result<Resp, PersistError>
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
        let payload = encode_config_wire(request).map_err(|_| consensus_unavailable())?;
        let wire = ConsensusWireRequest::try_new(
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
        decode_config_wire(&response.result.map_err(|_| consensus_unavailable())?)
            .map_err(|_| consensus_unavailable())
    }

    async fn local_read_barrier(&self, deadline: tokio::time::Instant) -> ReadBarrierReply {
        if self.require_admission().is_err() {
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

    async fn linearizable_barrier(&self) -> Result<Option<LogId<ConsensusNodeId>>, PersistError> {
        let result = self.linearizable_barrier_inner().await;
        let metric = if result.is_ok() {
            &opc_redaction::metrics::METRICS.persist_quorum_read_success
        } else {
            &opc_redaction::metrics::METRICS.persist_quorum_read_failure
        };
        metric.fetch_add(1, Ordering::Relaxed);
        self.publish_global_metrics();
        result
    }

    async fn linearizable_barrier_inner(
        &self,
    ) -> Result<Option<LogId<ConsensusNodeId>>, PersistError> {
        self.require_admission()?;
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
                        ConsensusRpcFamily::ReadBarrier,
                        &ReadBarrierRequest {
                            budget: ForwardedBudget::from_deadline(deadline)?,
                        },
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
                    self.require_admission()?;
                    return Ok(log_id);
                }
                ReadBarrierReply::NotLeader { leader: next } => {
                    opc_redaction::metrics::METRICS
                        .persist_stale_leader_rejections
                        .fetch_add(1, Ordering::Relaxed);
                    preferred = next.filter(|candidate| {
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
    ) -> Result<(), PersistError> {
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

    fn publish_global_metrics(&self) {
        let metrics = self.inner.raft.metrics();
        let metrics = metrics.borrow();
        let global = &opc_redaction::metrics::METRICS;
        global
            .persist_leader_term
            .store(metrics.current_term, Ordering::Relaxed);
        let applied = metrics
            .last_applied
            .as_ref()
            .map_or(0, |log_id| log_id.index);
        global.persist_commit_index.store(
            self.inner.durable_progress.committed_index().unwrap_or(0),
            Ordering::Relaxed,
        );
        global
            .persist_applied_index
            .store(applied, Ordering::Relaxed);
        global.persist_snapshot_index.store(
            metrics.snapshot.as_ref().map_or(0, |log_id| log_id.index),
            Ordering::Relaxed,
        );
        if let Ok(mut observed) = self.inner.metric_leader.lock() {
            if metrics.current_leader.is_some() && *observed != metrics.current_leader {
                if observed.is_some() {
                    global
                        .persist_leader_changes
                        .fetch_add(1, Ordering::Relaxed);
                }
                *observed = metrics.current_leader;
            }
        }
        if let Ok(mut lag) = global.persist_peer_replication_lag.lock() {
            lag.clear();
            if let Some(replication) = &metrics.replication {
                let last = metrics.last_log_index.unwrap_or(0);
                for (node_id, matched) in replication {
                    if let Ok(node_id) = usize::try_from(node_id.get()) {
                        let matched = matched.as_ref().map_or(0, |log_id| log_id.index);
                        lag.insert(node_id, last.saturating_sub(matched));
                    }
                }
            }
        }
    }
}

fn config_raft_config() -> Result<Config, ConfigConsensusOpenError> {
    Config {
        cluster_name: "opc-config-store".into(),
        heartbeat_interval: HEARTBEAT_MILLIS,
        election_timeout_min: ELECTION_MIN_MILLIS,
        election_timeout_max: ELECTION_MAX_MILLIS,
        install_snapshot_timeout: 10_000,
        max_payload_entries: 1,
        replication_lag_threshold: LOGS_PER_SNAPSHOT,
        snapshot_policy: SnapshotPolicy::LogsSinceLast(LOGS_PER_SNAPSHOT),
        snapshot_max_chunk_size: SNAPSHOT_CHUNK_BYTES,
        max_in_snapshot_log_to_keep: RETAINED_LOGS,
        ..Config::default()
    }
    .validate()
    .map_err(|_| ConfigConsensusOpenError::InvalidRuntimeConfiguration)
}

fn client_write_leader(
    error: &RaftError<ConsensusNodeId, ClientWriteError<ConsensusNodeId, EmptyNode>>,
) -> Option<ConsensusNodeId> {
    error
        .forward_to_leader()
        .and_then(|forward| forward.leader_id)
}

fn consensus_unavailable() -> PersistError {
    PersistError::io("config consensus quorum is unavailable")
}

fn derive_durable_request_id(
    identity: opc_consensus::ConsensusIdentity,
    operation: &[u8],
    durable_operation_identity: &[u8],
) -> opc_consensus::ConsensusRequestId {
    let mut hasher = Sha256::new();
    hasher.update(REQUEST_ID_DOMAIN);
    hasher.update(identity.cluster_id().as_bytes());
    hasher.update(identity.configuration_id().as_bytes());
    hasher.update(identity.configuration_epoch().get().to_be_bytes());
    hasher.update((operation.len() as u32).to_be_bytes());
    hasher.update(operation);
    hasher.update((durable_operation_identity.len() as u32).to_be_bytes());
    hasher.update(durable_operation_identity);
    let digest = hasher.finalize();
    let mut request_id = [0_u8; 16];
    request_id.copy_from_slice(&digest[..16]);
    opc_consensus::ConsensusRequestId::from_bytes(request_id)
}

fn exact_uniform_voter_membership(
    stored: &StoredMembership<ConsensusNodeId, EmptyNode>,
    configured: &BTreeSet<ConsensusNodeId>,
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

#[derive(Clone)]
struct ConfigConsensusService {
    store: ConsensusConfigStore,
}

impl fmt::Debug for ConfigConsensusService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConfigConsensusService(<redacted>)")
    }
}

#[async_trait]
impl ConsensusRpcHandler for ConfigConsensusService {
    async fn handle(
        &self,
        authenticated_sender: ConsensusNodeId,
        request: ConsensusWireRequest,
    ) -> ConsensusWireResponse {
        if request.validate().is_err()
            || request.identity != self.store.inner.identity
            || request.sender != authenticated_sender
            || !self.store.inner.members.contains(&authenticated_sender)
        {
            return ConsensusWireResponse {
                result: Err(ConsensusPeerError::ScopeMismatch),
            };
        }
        match request.family {
            ConsensusRpcFamily::Vote
            | ConsensusRpcFamily::AppendEntries
            | ConsensusRpcFamily::InstallSnapshot => {
                self.store
                    .inner
                    .raft_handler
                    .handle(authenticated_sender, request)
                    .await
            }
            ConsensusRpcFamily::ForwardMutation => {
                if !self.store.is_live_voter(authenticated_sender) {
                    return ConsensusWireResponse {
                        result: Err(ConsensusPeerError::ScopeMismatch),
                    };
                }
                let forwarded: ForwardMutationRequest = match decode_config_wire(&request.payload) {
                    Ok(forwarded) => forwarded,
                    Err(_) => return protocol_rejection(),
                };
                let Some(deadline) = forwarded
                    .budget
                    .inbound_deadline(self.store.inner.operation_timeout)
                else {
                    return protocol_rejection();
                };
                encode_service_reply(&self.store.apply_on_local_leader(forwarded, deadline).await)
            }
            ConsensusRpcFamily::ReadBarrier => {
                if !self.store.is_live_voter(authenticated_sender) {
                    return ConsensusWireResponse {
                        result: Err(ConsensusPeerError::ScopeMismatch),
                    };
                }
                let read: ReadBarrierRequest = match decode_config_wire(&request.payload) {
                    Ok(read) => read,
                    Err(_) => return protocol_rejection(),
                };
                let Some(deadline) = read
                    .budget
                    .inbound_deadline(self.store.inner.operation_timeout)
                else {
                    return protocol_rejection();
                };
                encode_service_reply(&self.store.local_read_barrier(deadline).await)
            }
            _ => protocol_rejection(),
        }
    }
}

fn encode_service_reply<T: Serialize>(reply: &T) -> ConsensusWireResponse {
    match encode_config_wire(reply) {
        Ok(payload) => ConsensusWireResponse {
            result: Ok(payload),
        },
        Err(_) => protocol_rejection(),
    }
}

fn protocol_rejection() -> ConsensusWireResponse {
    ConsensusWireResponse {
        result: Err(ConsensusPeerError::Protocol),
    }
}

#[async_trait]
impl ConfigStore for ConsensusConfigStore {
    async fn load_latest(&self) -> Result<Option<StoredConfig>, PersistError> {
        self.linearizable_barrier().await?;
        self.inner.backend.load_latest().await
    }

    async fn load_rollback(&self, target: RollbackTarget) -> Result<StoredConfig, PersistError> {
        self.linearizable_barrier().await?;
        self.inner.backend.load_rollback(target).await
    }

    async fn append_commit(
        &self,
        _record: CommitRecord,
        _audit: Vec<AuditRecord>,
    ) -> Result<(), PersistError> {
        Err(PersistError::constraint_violation(
            "config consensus requires a fresh authenticated encryption proposal",
        ))
    }

    async fn append_attested_commit(
        &self,
        commit: AttestedConfigCommit,
    ) -> Result<(), PersistError> {
        let record = commit.record();
        let request_id = derive_durable_request_id(
            self.inner.identity,
            b"append",
            record.tx_id.as_uuid().as_bytes(),
        );
        self.append_commit_idempotent(request_id, commit).await
    }

    async fn mark_confirmed(&self, tx_id: opc_types::TxId) -> Result<(), PersistError> {
        let request_id =
            derive_durable_request_id(self.inner.identity, b"confirm", tx_id.as_uuid().as_bytes());
        self.mark_confirmed_idempotent(request_id, tx_id).await
    }

    async fn create_rollback_point(
        &self,
        tx_id: opc_types::TxId,
        label: Option<String>,
    ) -> Result<(), PersistError> {
        let mut operation_identity = tx_id.as_uuid().as_bytes().to_vec();
        if let Some(label) = &label {
            operation_identity.extend_from_slice(&(label.len() as u32).to_be_bytes());
            operation_identity.extend_from_slice(label.as_bytes());
        } else {
            operation_identity.extend_from_slice(&0_u32.to_be_bytes());
        }
        let request_id =
            derive_durable_request_id(self.inner.identity, b"rollback-point", &operation_identity);
        self.create_rollback_point_idempotent(request_id, tx_id, label)
            .await
    }

    async fn preflight(&self) -> Result<PersistCapabilities, PersistError> {
        self.inner.backend.preflight().await
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        ConfigConsensusClusterId, ConfigConsensusConfigurationEpoch, ConfigConsensusConfigurationId,
    };
    use super::*;

    fn topology() -> ConfigConsensusTopology {
        let node = ConsensusNodeId::new(1).expect("node ID");
        let identity = opc_consensus::ConsensusIdentity::new(
            ConfigConsensusClusterId::new("config-forward-budget-tests").expect("cluster ID"),
            ConfigConsensusConfigurationId::from_bytes([0xB1; 32]),
            ConfigConsensusConfigurationEpoch::new(1).expect("epoch"),
        );
        ConfigConsensusTopology::try_new(identity, node, BTreeSet::from([node])).expect("topology")
    }

    async fn singleton_store() -> (ConsensusConfigStore, tempfile::TempDir) {
        let topology = topology();
        let backend = SqliteBackend::in_memory_for_test()
            .await
            .expect("config backend");
        let snapshots = tempfile::tempdir().expect("snapshot directory");
        let store = ConsensusConfigStore::open_with_operation_timeout(
            topology,
            backend,
            snapshots.path().join("snapshots"),
            BTreeMap::new(),
            Duration::from_secs(3),
        )
        .await
        .expect("config store");
        store
            .initialize_cluster()
            .await
            .expect("initialize cluster");
        (store, snapshots)
    }

    fn forwarded_mutation(budget: ForwardedBudget) -> ForwardMutationRequest {
        ForwardMutationRequest {
            request_id: opc_consensus::ConsensusRequestId::from_bytes([0xC2; 16]),
            intent: ConfigMutationIntent::MarkConfirmed {
                tx_id: opc_types::TxId::new(),
            },
            budget,
        }
    }

    async fn service_call(
        store: &ConsensusConfigStore,
        family: ConsensusRpcFamily,
        payload: Vec<u8>,
    ) -> ConsensusWireResponse {
        let sender = store.inner.local_node_id;
        let wire = ConsensusWireRequest::try_new(store.inner.identity, sender, family, payload)
            .expect("wire request");
        store.rpc_handler().handle(sender, wire).await
    }

    #[test]
    fn forwarded_budget_rejects_zero_and_overflow() {
        assert!(ForwardedBudget { remaining_nanos: 0 }
            .inbound_deadline(Duration::from_secs(10))
            .is_none());
        assert!(ForwardedBudget {
            remaining_nanos: u64::try_from(MAX_FORWARDED_BUDGET.as_nanos())
                .expect("maximum budget")
                + 1,
        }
        .inbound_deadline(Duration::from_secs(10))
        .is_none());
    }

    #[tokio::test]
    async fn inbound_forward_uses_remaining_budget_instead_of_fresh_local_timeout() {
        let (store, _snapshots) = singleton_store().await;
        let _gate = store.inner.proposal_gate.lock().await;
        let request = forwarded_mutation(ForwardedBudget {
            remaining_nanos: 50_000_000,
        });
        let started = tokio::time::Instant::now();
        let response = service_call(
            &store,
            ConsensusRpcFamily::ForwardMutation,
            encode_config_wire(&request).expect("forwarded request"),
        )
        .await;
        let elapsed = started.elapsed();
        let reply: ForwardMutationReply = decode_config_wire(
            &response
                .result
                .expect("bounded budget returns an application reply"),
        )
        .expect("forwarded reply");
        assert_eq!(ForwardMutationReply::Unavailable, reply);
        assert!(elapsed >= Duration::from_millis(40), "elapsed {elapsed:?}");
        assert!(elapsed < Duration::from_millis(250), "elapsed {elapsed:?}");
        store.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn malformed_zero_and_overflow_forward_budgets_fail_before_work() {
        let (store, _snapshots) = singleton_store().await;
        let _gate = store.inner.proposal_gate.lock().await;
        for budget in [
            ForwardedBudget { remaining_nanos: 0 },
            ForwardedBudget {
                remaining_nanos: u64::try_from(MAX_FORWARDED_BUDGET.as_nanos())
                    .expect("maximum budget")
                    + 1,
            },
        ] {
            let started = tokio::time::Instant::now();
            let response = service_call(
                &store,
                ConsensusRpcFamily::ForwardMutation,
                encode_config_wire(&forwarded_mutation(budget)).expect("invalid budget request"),
            )
            .await;
            assert_eq!(Err(ConsensusPeerError::Protocol), response.result);
            assert!(started.elapsed() < Duration::from_millis(100));
        }

        let mut malformed = encode_config_wire(&forwarded_mutation(ForwardedBudget {
            remaining_nanos: 50_000_000,
        }))
        .expect("valid request");
        malformed.push(0);
        let response = service_call(&store, ConsensusRpcFamily::ForwardMutation, malformed).await;
        assert_eq!(Err(ConsensusPeerError::Protocol), response.result);

        let read = ReadBarrierRequest {
            budget: ForwardedBudget { remaining_nanos: 0 },
        };
        let response = service_call(
            &store,
            ConsensusRpcFamily::ReadBarrier,
            encode_config_wire(&read).expect("zero read budget"),
        )
        .await;
        assert_eq!(Err(ConsensusPeerError::Protocol), response.result);
        store.shutdown().await.expect("shutdown");
    }
}
