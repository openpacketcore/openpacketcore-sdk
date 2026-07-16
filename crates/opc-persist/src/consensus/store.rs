//! ConfigStore implementation coordinated exclusively by Openraft.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use opc_consensus::engine::error::{ClientWriteError, InitializeError, RaftError};
use opc_consensus::engine::{EmptyNode, LogId, StoredMembership};
use opc_consensus::{
    durable_openraft_config, encode_bounded, ConsensusNodeId, ConsensusPeer, ConsensusPeerError,
    ConsensusRpcFamily, ConsensusRpcHandler, ConsensusWireRequest, ConsensusWireResponse,
    DurableOpenraftDomain, EnsureLinearizableOutcome, EnsureLinearizableSupervisor,
    DURABLE_CONSENSUS_OPERATION_TIMEOUT, DURABLE_OPENRAFT_APPEND_ENTRIES_TARGET_BYTES,
    DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::raft_adapter::{ConfigRaftAdapterError, ConfigRaftNetworkFactory, ConfigRaftRpcHandler};
use super::storage::{self, ConfigConsensusStorageError};
use super::types::{decode_config_wire, encode_config_wire, ValidatedRollbackLabel};
use super::{
    ApprovedLegacyConfigRecovery, ConfigConsensusClock, ConfigConsensusResponse,
    ConfigConsensusTopology, ConfigMutationIntent, ConfigRaft, ConfigRaftTypeConfig,
    PreparedConfigCommit, SystemConfigConsensusClock,
};
use crate::backend::SqliteBackend;
use crate::error::PersistError;
use crate::preflight::PersistCapabilities;
use crate::types::{
    AttestedConfigCommit, AuditRecord, CommitRecord, ConfigStore, RollbackTarget, StoredConfig,
};

/// Complete client-operation deadline including routing, quorum, commit, and apply.
pub const DEFAULT_CONFIG_CONSENSUS_OPERATION_TIMEOUT: Duration =
    DURABLE_CONSENSUS_OPERATION_TIMEOUT;

const ROUTE_RETRY_BACKOFF: Duration = Duration::from_millis(50);
const MAX_FORWARDED_BUDGET: Duration = Duration::from_secs(60);
const REQUEST_ID_DOMAIN: &[u8] = b"openpacketcore/config-consensus/request-id/v1\0";

fn map_watch_snapshot<T, R: 'static>(
    receiver: &tokio::sync::watch::Receiver<T>,
    map: impl FnOnce(&T) -> R,
) -> R {
    let current = receiver.borrow();
    map(&current)
}

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
    compatibility: ConfigPeerCompatibility,
    budget: ForwardedBudget,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
enum ForwardMutationReply {
    Applied(Box<ConfigConsensusResponse>),
    NotLeader { leader: Option<ConsensusNodeId> },
    Unavailable,
    Rejected(ForwardMutationRejection),
    // Keep additive variants after the original discriminants so their
    // postcard shapes remain stable inside the current exact-revision payload.
    OutcomeUnknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum ForwardMutationRejection {
    CommandTooLarge,
    InvalidCommand,
}

impl ForwardMutationRejection {
    fn into_persist_error(self) -> PersistError {
        match self {
            Self::CommandTooLarge => PersistError::constraint_violation(
                "config consensus command exceeds durable replication limit",
            ),
            Self::InvalidCommand => PersistError::corrupt_blob(),
        }
    }
}

#[derive(Serialize)]
struct ConfigConsensusCommandSizeProbe<'a> {
    schema_version: u16,
    identity: opc_consensus::ConsensusIdentity,
    request_id: opc_consensus::ConsensusRequestId,
    logical_time: opc_types::Timestamp,
    intent: &'a ConfigMutationIntent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadBarrierRequest {
    compatibility: ConfigPeerCompatibility,
    compatibility_probe: bool,
    budget: ForwardedBudget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigPeerCompatibility {
    wire_version: u16,
    command_version: u16,
    audit_key_epoch: u64,
    audit_key_fingerprint: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum ReadBarrierReply {
    Compatible,
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
    linearizability: EnsureLinearizableSupervisor<ConfigRaftTypeConfig>,
    proposal_admission: Arc<tokio::sync::Semaphore>,
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
        let identity = topology.identity();
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
        let linearizability = EnsureLinearizableSupervisor::new(raft.clone());
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
                linearizability,
                proposal_admission: Arc::new(tokio::sync::Semaphore::new(
                    DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS,
                )),
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
    ///
    /// Every member may call this concurrently. On clean first formation only
    /// the canonical lowest node asks Openraft to initialize; other pristine
    /// members wait for that exact membership to replicate. Restarted members
    /// with durable Openraft state skip bootstrap and re-admit normally. Clean
    /// first formation fails closed if the canonical member is absent.
    pub async fn initialize_cluster(&self) -> Result<(), ConfigConsensusOpenError> {
        self.inner.admitted.store(false, Ordering::Release);
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or(ConfigConsensusOpenError::ClusterFormationRejected)?;
        let initialized = tokio::time::timeout_at(deadline, self.inner.raft.is_initialized())
            .await
            .map_err(|_| ConfigConsensusOpenError::ClusterFormationRejected)?
            .map_err(|_| ConfigConsensusOpenError::EngineUnavailable)?;
        let canonical_bootstrap = self.inner.members.first().copied();
        if !initialized && canonical_bootstrap == Some(self.inner.local_node_id) {
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
                Err(RaftError::Fatal(_)) => {
                    return Err(ConfigConsensusOpenError::EngineUnavailable)
                }
            }
        }
        self.wait_for_admissible_membership(deadline).await?;
        self.verify_fleet_compatibility(deadline).await?;
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
        // Snapshot every value derived from the watch payload while holding
        // one read guard. Re-borrowing the watch lock before the first guard
        // is dropped can deadlock when its underlying lock gives a queued
        // Openraft metrics writer priority: the writer waits for the first
        // guard, while the nested read waits for the writer.
        let (term, leader_id, applied_index, live_membership_is_exact) =
            map_watch_snapshot(&metrics, |metrics| {
                (
                    metrics.current_term,
                    metrics.current_leader,
                    metrics.last_applied.as_ref().map(|log_id| log_id.index),
                    metrics.running_state.is_ok()
                        && exact_uniform_voter_membership(
                            metrics.membership_config.as_ref(),
                            &self.inner.members,
                        ),
                )
            });
        let admitted = self.apply_live_membership_admission(live_membership_is_exact);

        ConfigConsensusStatus {
            node_id: self.inner.local_node_id,
            term,
            leader_id,
            applied_index,
            // Openraft metrics expose applied but not committed. The storage
            // adapter publishes the separately persisted committed pointer.
            committed_index: self.inner.durable_progress.committed_index(),
            audit_key_epoch: self.inner.backend.audit_key().epoch(),
            audit_key_fingerprint: self.inner.backend.audit_key().fingerprint(),
            admitted,
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
        let (record, audit, resolution) = commit.into_parts();
        let prepared =
            PreparedConfigCommit::prepare(record, audit, self.inner.backend.audit_key())?;
        let intent = match resolution {
            Some(resolution) => ConfigMutationIntent::ResolveConfirmedAndAppend {
                commit: Box::new(prepared),
                resolution,
            },
            None => ConfigMutationIntent::AppendCommit(Box::new(prepared)),
        };
        self.submit_request(request_id, intent).await?.into_result()
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

    /// Clear a config-bus recovery marker with a caller-retained durable
    /// request ID.
    pub async fn clear_recovery_required_idempotent(
        &self,
        request_id: opc_consensus::ConsensusRequestId,
        tx_id: opc_types::TxId,
    ) -> Result<(), PersistError> {
        self.submit_request(
            request_id,
            ConfigMutationIntent::ClearRecoveryRequired { tx_id },
        )
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
        map_watch_snapshot(&metrics, |current| {
            current.running_state.is_ok()
                && exact_uniform_voter_membership(
                    current.membership_config.as_ref(),
                    &self.inner.members,
                )
        })
    }

    fn exact_membership_is_admitted(&self) -> bool {
        if !self.inner.admitted.load(Ordering::Acquire) {
            return false;
        }
        self.apply_live_membership_admission(self.live_membership_is_exact())
    }

    fn apply_live_membership_admission(&self, live_membership_is_exact: bool) -> bool {
        if !self.inner.admitted.load(Ordering::Acquire) {
            return false;
        }
        if live_membership_is_exact {
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

    fn peer_compatibility(&self) -> ConfigPeerCompatibility {
        ConfigPeerCompatibility {
            wire_version: super::CONFIG_CONSENSUS_WIRE_VERSION,
            command_version: super::CONFIG_CONSENSUS_COMMAND_VERSION,
            audit_key_epoch: self.inner.backend.audit_key().epoch(),
            audit_key_fingerprint: self.inner.backend.audit_key().fingerprint(),
        }
    }

    async fn verify_fleet_compatibility(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<(), ConfigConsensusOpenError> {
        for target in self.inner.peers.keys().copied() {
            let reply = self
                .call_peer::<_, ReadBarrierReply>(
                    target,
                    ConsensusRpcFamily::ReadBarrier,
                    &ReadBarrierRequest {
                        compatibility: self.peer_compatibility(),
                        compatibility_probe: true,
                        budget: ForwardedBudget::from_deadline(deadline)
                            .map_err(|_| ConfigConsensusOpenError::ClusterFormationRejected)?,
                    },
                    deadline,
                )
                .await
                .map_err(|_| ConfigConsensusOpenError::ClusterFormationRejected)?;
            if reply != ReadBarrierReply::Compatible {
                return Err(ConfigConsensusOpenError::ClusterFormationRejected);
            }
        }
        Ok(())
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
        preflight_config_command_replication_budget(self.inner.identity, request_id, &intent)
            .map_err(ForwardMutationRejection::into_persist_error)?;
        self.require_admission()?;
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        let mut preferred = None;
        let mut ambiguity_seen = false;
        loop {
            let leader = match preferred.take() {
                Some(leader) => leader,
                None => match self.wait_for_known_leader(deadline).await {
                    Ok(leader) => leader,
                    Err(error) if ambiguity_seen => {
                        drop(error);
                        return Err(PersistError::outcome_unknown());
                    }
                    Err(error) => return Err(error),
                },
            };
            let budget = match ForwardedBudget::from_deadline(deadline) {
                Ok(budget) => budget,
                Err(error) if ambiguity_seen => {
                    drop(error);
                    return Err(PersistError::outcome_unknown());
                }
                Err(error) => return Err(error),
            };
            let request = ForwardMutationRequest {
                request_id,
                intent: intent.clone(),
                compatibility: self.peer_compatibility(),
                budget,
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
                        ambiguity_seen = true;
                        if let Err(error) = self.wait_for_route_refresh(leader, deadline).await {
                            drop(error);
                            return Err(PersistError::outcome_unknown());
                        }
                        continue;
                    }
                }
            };
            match reply {
                ForwardMutationReply::Applied(response) => {
                    return Ok(*response);
                }
                ForwardMutationReply::Rejected(rejection) => {
                    return Err(rejection.into_persist_error());
                }
                ForwardMutationReply::NotLeader { leader: next } => {
                    opc_redaction::metrics::METRICS
                        .persist_stale_leader_rejections
                        .fetch_add(1, Ordering::Relaxed);
                    preferred = next.filter(|candidate| {
                        *candidate != leader && self.inner.members.contains(candidate)
                    });
                    if preferred.is_none() {
                        if let Err(error) = self.wait_for_route_refresh(leader, deadline).await {
                            if ambiguity_seen {
                                drop(error);
                                return Err(PersistError::outcome_unknown());
                            }
                            return Err(error);
                        }
                    }
                }
                ForwardMutationReply::Unavailable => {
                    if let Err(error) = self.wait_for_route_refresh(leader, deadline).await {
                        if ambiguity_seen {
                            drop(error);
                            return Err(PersistError::outcome_unknown());
                        }
                        return Err(error);
                    }
                }
                ForwardMutationReply::OutcomeUnknown => {
                    ambiguity_seen = true;
                    if let Err(error) = self.wait_for_route_refresh(leader, deadline).await {
                        drop(error);
                        return Err(PersistError::outcome_unknown());
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
        if let Err(rejection) = preflight_config_command_replication_budget(
            self.inner.identity,
            request.request_id,
            &request.intent,
        ) {
            return ForwardMutationReply::Rejected(rejection);
        }
        if self.require_admission().is_err() {
            return ForwardMutationReply::Unavailable;
        }
        let proposal_permit = match tokio::time::timeout_at(
            deadline,
            Arc::clone(&self.inner.proposal_admission).acquire_owned(),
        )
        .await
        {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) | Err(_) => return ForwardMutationReply::Unavailable,
        };
        match self
            .inner
            .linearizability
            .ensure_linearizable(deadline)
            .await
        {
            EnsureLinearizableOutcome::Ready { .. } if self.require_admission().is_ok() => {}
            EnsureLinearizableOutcome::Ready { .. } | EnsureLinearizableOutcome::Unavailable => {
                return ForwardMutationReply::Unavailable;
            }
            EnsureLinearizableOutcome::Retry { leader_hint } => {
                return ForwardMutationReply::NotLeader {
                    leader: leader_hint,
                }
            }
            _ => return ForwardMutationReply::Unavailable,
        }
        let command = super::ConfigConsensusCommand {
            schema_version: super::CONFIG_CONSENSUS_COMMAND_VERSION,
            identity: self.inner.identity,
            request_id: request.request_id,
            logical_time: self.inner.clock.now_utc(),
            intent: request.intent,
        };
        if command.validate(self.inner.identity).is_err() {
            return ForwardMutationReply::Rejected(ForwardMutationRejection::InvalidCommand);
        }
        if !config_command_fits_replication_budget(&command) {
            return ForwardMutationReply::Rejected(ForwardMutationRejection::CommandTooLarge);
        }
        let response =
            match tokio::time::timeout_at(deadline, self.inner.raft.client_write_ff(command)).await
            {
                Err(_) => return ForwardMutationReply::OutcomeUnknown,
                Ok(Err(_)) => return ForwardMutationReply::Unavailable,
                Ok(Ok(response)) => response,
            };
        // The returned receiver proves that Openraft accepted this durable
        // request ID. Supervision, not the originating RPC/client future,
        // owns admission until that exact accepted proposal resolves.
        let (completion_tx, completion_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let reply = match response.await {
                Err(_) => ForwardMutationReply::OutcomeUnknown,
                Ok(Ok(response)) => ForwardMutationReply::Applied(Box::new(response.data)),
                Ok(Err(ClientWriteError::ForwardToLeader(forward))) => {
                    ForwardMutationReply::NotLeader {
                        leader: forward.leader_id,
                    }
                }
                Ok(Err(ClientWriteError::ChangeMembershipError(_))) => {
                    ForwardMutationReply::Unavailable
                }
            };
            let _ = completion_tx.send(reply);
            drop(proposal_permit);
        });
        match tokio::time::timeout_at(deadline, completion_rx).await {
            Err(_) | Ok(Err(_)) => ForwardMutationReply::OutcomeUnknown,
            Ok(Ok(ForwardMutationReply::Applied(response))) => {
                ForwardMutationReply::Applied(response)
            }
            Ok(Ok(reply)) => reply,
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
        match self
            .inner
            .linearizability
            .ensure_linearizable(deadline)
            .await
        {
            EnsureLinearizableOutcome::Ready { read_log_id }
                if self.exact_membership_is_admitted() =>
            {
                ReadBarrierReply::Ready(read_log_id)
            }
            EnsureLinearizableOutcome::Ready { .. } | EnsureLinearizableOutcome::Unavailable => {
                ReadBarrierReply::Unavailable
            }
            EnsureLinearizableOutcome::Retry { leader_hint } => ReadBarrierReply::NotLeader {
                leader: leader_hint,
            },
            _ => ReadBarrierReply::Unavailable,
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
                            compatibility: self.peer_compatibility(),
                            compatibility_probe: false,
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
                ReadBarrierReply::Compatible => return Err(consensus_unavailable()),
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

fn config_raft_config() -> Result<opc_consensus::engine::Config, ConfigConsensusOpenError> {
    durable_openraft_config(DurableOpenraftDomain::ConfigurationState)
        .map_err(|_| ConfigConsensusOpenError::InvalidRuntimeConfiguration)
}

fn config_command_fits_replication_budget(command: &super::ConfigConsensusCommand) -> bool {
    // The 1 MiB command ceiling leaves more than 1 MiB for the fixed config
    // revision and singleton Openraft metadata under the 2 MiB hard RPC
    // ceiling. It also aligns every admitted command with the shared
    // AppendEntries soft target, so no accepted singleton can wedge the log.
    encode_bounded(command)
        .is_ok_and(|encoded| encoded.len() <= DURABLE_OPENRAFT_APPEND_ENTRIES_TARGET_BYTES)
}

fn preflight_config_command_replication_budget(
    identity: opc_consensus::ConsensusIdentity,
    request_id: opc_consensus::ConsensusRequestId,
    intent: &ConfigMutationIntent,
) -> Result<(), ForwardMutationRejection> {
    // The maximum UTC RFC 3339 timestamp has the longest representation that
    // the leader-selected logical time can add to the postcard command. This
    // makes admission independent of the current clock value while retaining
    // the exact command shape and field order.
    let probe = ConfigConsensusCommandSizeProbe {
        schema_version: super::CONFIG_CONSENSUS_COMMAND_VERSION,
        identity,
        request_id,
        logical_time: maximum_encoded_config_timestamp()
            .ok_or(ForwardMutationRejection::InvalidCommand)?,
        intent,
    };
    match encode_bounded(&probe) {
        Ok(encoded) if encoded.len() <= DURABLE_OPENRAFT_APPEND_ENTRIES_TARGET_BYTES => Ok(()),
        Ok(_) | Err(opc_consensus::ConsensusCodecError::TooLarge) => {
            Err(ForwardMutationRejection::CommandTooLarge)
        }
        Err(_) => Err(ForwardMutationRejection::InvalidCommand),
    }
}

fn maximum_encoded_config_timestamp() -> Option<opc_types::Timestamp> {
    let date = time::Date::from_calendar_date(9999, time::Month::December, 31).ok()?;
    let clock_time = time::Time::from_hms_nano(23, 59, 59, 999_999_999).ok()?;
    Some(opc_types::Timestamp::from_offset_datetime(
        time::PrimitiveDateTime::new(date, clock_time).assume_utc(),
    ))
}

fn consensus_unavailable() -> PersistError {
    PersistError::unavailable()
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
                if forwarded.compatibility != self.store.peer_compatibility() {
                    return ConsensusWireResponse {
                        result: Err(ConsensusPeerError::ScopeMismatch),
                    };
                }
                let Some(deadline) = forwarded
                    .budget
                    .inbound_deadline(self.store.inner.operation_timeout)
                else {
                    return protocol_rejection();
                };
                encode_service_reply(&self.store.apply_on_local_leader(forwarded, deadline).await)
            }
            ConsensusRpcFamily::ReadBarrier => {
                let read: ReadBarrierRequest = match decode_config_wire(&request.payload) {
                    Ok(read) => read,
                    Err(_) => return protocol_rejection(),
                };
                if read.compatibility != self.store.peer_compatibility() {
                    return ConsensusWireResponse {
                        result: Err(ConsensusPeerError::ScopeMismatch),
                    };
                }
                if read.compatibility_probe {
                    return encode_service_reply(&ReadBarrierReply::Compatible);
                }
                if !self.store.is_live_voter(authenticated_sender) {
                    return ConsensusWireResponse {
                        result: Err(ConsensusPeerError::ScopeMismatch),
                    };
                }
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

    async fn load_by_replay_lookup_digest(
        &self,
        digest: &str,
    ) -> Result<Option<StoredConfig>, PersistError> {
        self.linearizable_barrier().await?;
        self.inner
            .backend
            .load_by_replay_lookup_digest(digest)
            .await
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

    async fn clear_recovery_required(&self, tx_id: opc_types::TxId) -> Result<(), PersistError> {
        let request_id = derive_durable_request_id(
            self.inner.identity,
            b"clear-recovery",
            tx_id.as_uuid().as_bytes(),
        );
        self.clear_recovery_required_idempotent(request_id, tx_id)
            .await
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

    #[allow(dead_code)]
    #[derive(Serialize)]
    enum LegacyForwardMutationReply {
        Applied(Box<ConfigConsensusResponse>),
        NotLeader { leader: Option<ConsensusNodeId> },
        Unavailable,
        Rejected(ForwardMutationRejection),
    }

    #[test]
    fn legacy_forward_rejection_discriminant_retains_its_wire_shape() {
        let rejection = ForwardMutationRejection::CommandTooLarge;
        let legacy = encode_config_wire(&LegacyForwardMutationReply::Rejected(rejection))
            .expect("legacy forwarded rejection fixture");
        let current = encode_config_wire(&ForwardMutationReply::Rejected(rejection))
            .expect("current forwarded rejection fixture");
        assert_eq!(legacy, current);
    }

    fn size_test_timestamp() -> opc_types::Timestamp {
        opc_types::Timestamp::from_offset_datetime(
            time::OffsetDateTime::from_unix_timestamp(1_900_000_000)
                .expect("fixed size-test timestamp"),
        )
    }

    fn sized_append_intent(
        store: &ConsensusConfigStore,
        ciphertext_and_tag_bytes: usize,
    ) -> ConfigMutationIntent {
        let tx_id = opc_types::TxId::new();
        let committed_at = size_test_timestamp();
        let principal =
            "spiffe://qualification.invalid/tenant/test/ns/test/sa/config/nf/test/instance/0"
                .to_owned();
        let schema_digest = opc_types::SchemaDigest::from_bytes([0xA7; 32]);
        let key_id =
            opc_key::KeyId::new("config-size-preflight-key".to_owned()).expect("bounded key ID");
        let aad = opc_key::EnvelopeAad::config(
            opc_types::TenantId::from_static("test"),
            1,
            opc_key::ConfigAad::new(
                tx_id,
                None,
                committed_at,
                &principal,
                schema_digest,
                "running",
            )
            .expect("bounded config AAD"),
        );
        let encrypted_blob = opc_crypto::CryptoEnvelopeV1 {
            algorithm: opc_key::AeadAlgorithm::Aes256GcmSiv,
            key_id: key_id.clone(),
            nonce: vec![0xA8; opc_key::AES_256_GCM_SIV_NONCE_LEN],
            aad: opc_key::serialize_bound_aad(&aad, &key_id).expect("bound config AAD"),
            ciphertext_and_tag: vec![0xA9; ciphertext_and_tag_bytes],
        }
        .encode()
        .expect("encoded size-test envelope");
        let record = CommitRecord {
            tx_id,
            parent_tx_id: None,
            version: opc_types::ConfigVersion::new(1),
            committed_at,
            principal,
            source: crate::types::CommitSource::Gnmi,
            schema_digest,
            plaintext_digest: vec![0xAA; 32],
            encrypted_blob,
            rollback_point: false,
            confirmed_deadline: None,
        };
        let prepared =
            PreparedConfigCommit::prepare(record, Vec::new(), store.inner.backend.audit_key())
                .expect("structurally valid encrypted size-test commit");
        ConfigMutationIntent::AppendCommit(Box::new(prepared))
    }

    fn sized_forwarded_mutation(
        store: &ConsensusConfigStore,
        ciphertext_and_tag_bytes: usize,
    ) -> ForwardMutationRequest {
        ForwardMutationRequest {
            request_id: opc_consensus::ConsensusRequestId::from_bytes([0xAB; 16]),
            intent: sized_append_intent(store, ciphertext_and_tag_bytes),
            compatibility: store.peer_compatibility(),
            budget: ForwardedBudget {
                remaining_nanos: 2_000_000_000,
            },
        }
    }

    fn sized_attested_commit(plaintext_bytes: usize) -> AttestedConfigCommit {
        let tx_id = opc_types::TxId::new();
        let committed_at = size_test_timestamp();
        let principal =
            "spiffe://qualification.invalid/tenant/test/ns/test/sa/config/nf/test/instance/0"
                .to_owned();
        let schema_digest = opc_types::SchemaDigest::from_bytes([0xB7; 32]);
        let key_id =
            opc_key::KeyId::new("config-size-public-key".to_owned()).expect("bounded key ID");
        let aad = opc_key::EnvelopeAad::config(
            opc_types::TenantId::from_static("test"),
            1,
            opc_key::ConfigAad::new(
                tx_id,
                None,
                committed_at,
                &principal,
                schema_digest,
                "running",
            )
            .expect("bounded config AAD"),
        );
        let handle = opc_key::KeyHandle::new(
            key_id,
            opc_key::KeyPurpose::Config,
            opc_types::TenantId::from_static("test"),
            opc_key::Zeroizing::new([0xB8; opc_key::AES_256_GCM_SIV_KEY_LEN]),
        );
        let plaintext = vec![0xB9; plaintext_bytes];
        let envelope = opc_crypto::encrypt_attested_envelope_with_handle_and_nonce(
            &handle,
            &aad,
            &plaintext,
            [0xBA; opc_key::AES_256_GCM_SIV_NONCE_LEN],
        )
        .expect("attested size-test envelope");
        let record = CommitRecord {
            tx_id,
            parent_tx_id: None,
            version: opc_types::ConfigVersion::new(1),
            committed_at,
            principal,
            source: crate::types::CommitSource::Gnmi,
            schema_digest,
            plaintext_digest: Sha256::digest(&plaintext).to_vec(),
            encrypted_blob: envelope.encoded().to_vec(),
            rollback_point: false,
            confirmed_deadline: None,
        };
        AttestedConfigCommit::try_new(
            record,
            Vec::new(),
            envelope.claim().expect("fresh size-test encryption claim"),
        )
        .expect("attested size-test commit")
    }

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
        singleton_store_with_timeout(Duration::from_secs(3)).await
    }

    async fn singleton_store_with_timeout(
        operation_timeout: Duration,
    ) -> (ConsensusConfigStore, tempfile::TempDir) {
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
            operation_timeout,
        )
        .await
        .expect("config store");
        store
            .initialize_cluster()
            .await
            .expect("initialize cluster");
        (store, snapshots)
    }

    fn forwarded_mutation(
        store: &ConsensusConfigStore,
        budget: ForwardedBudget,
    ) -> ForwardMutationRequest {
        ForwardMutationRequest {
            request_id: opc_consensus::ConsensusRequestId::from_bytes([0xC2; 16]),
            intent: ConfigMutationIntent::MarkConfirmed {
                tx_id: opc_types::TxId::new(),
            },
            compatibility: store.peer_compatibility(),
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
    async fn config_command_budget_rejects_before_openraft_and_preserves_the_log() {
        use opc_consensus::engine::raft::AppendEntriesRequest;
        use opc_consensus::engine::{CommittedLeaderId, Entry, EntryPayload, Vote};

        let (store, _snapshots) = singleton_store().await;
        let command_for = |request: &ForwardMutationRequest| super::super::ConfigConsensusCommand {
            schema_version: super::super::CONFIG_CONSENSUS_COMMAND_VERSION,
            identity: store.inner.identity,
            request_id: request.request_id,
            logical_time: size_test_timestamp(),
            intent: request.intent.clone(),
        };

        let shape_request = sized_forwarded_mutation(&store, opc_key::AEAD_TAG_LEN);
        let max_time_command = super::super::ConfigConsensusCommand {
            schema_version: super::super::CONFIG_CONSENSUS_COMMAND_VERSION,
            identity: store.inner.identity,
            request_id: shape_request.request_id,
            logical_time: maximum_encoded_config_timestamp()
                .expect("maximum RFC 3339 timestamp is representable"),
            intent: shape_request.intent.clone(),
        };
        let max_time_probe = ConfigConsensusCommandSizeProbe {
            schema_version: super::super::CONFIG_CONSENSUS_COMMAND_VERSION,
            identity: store.inner.identity,
            request_id: shape_request.request_id,
            logical_time: maximum_encoded_config_timestamp()
                .expect("maximum RFC 3339 timestamp is representable"),
            intent: &shape_request.intent,
        };
        assert_eq!(
            encode_bounded(&max_time_command)
                .expect("maximum-time command encoding")
                .len(),
            encode_bounded(&max_time_probe)
                .expect("maximum-time size probe encoding")
                .len(),
            "the borrow-based size probe must retain the exact command wire shape"
        );

        let mut admitted = opc_key::AEAD_TAG_LEN;
        let mut rejected = DURABLE_OPENRAFT_APPEND_ENTRIES_TARGET_BYTES + 1;
        while admitted + 1 < rejected {
            let candidate = admitted + ((rejected - admitted) / 2);
            let request = sized_forwarded_mutation(&store, candidate);
            if config_command_fits_replication_budget(&command_for(&request)) {
                admitted = candidate;
            } else {
                rejected = candidate;
            }
        }

        let admitted_request = sized_forwarded_mutation(&store, admitted);
        let admitted_command = command_for(&admitted_request);
        let admitted_command_bytes = encode_bounded(&admitted_command).expect("admitted command");
        assert!(admitted_command_bytes.len() <= DURABLE_OPENRAFT_APPEND_ENTRIES_TARGET_BYTES);
        assert!(config_command_fits_replication_budget(&admitted_command));

        let max_node = ConsensusNodeId::new(opc_consensus::CONSENSUS_NODE_ID_MAX)
            .expect("largest bounded consensus node ID");
        let max_log = LogId::new(CommittedLeaderId::new(u64::MAX, max_node), u64::MAX);
        let append = AppendEntriesRequest::<super::super::ConfigRaftTypeConfig> {
            vote: Vote::new_committed(u64::MAX, max_node),
            prev_log_id: Some(max_log),
            entries: vec![Entry {
                log_id: max_log,
                payload: EntryPayload::Normal(admitted_command),
            }],
            leader_commit: Some(max_log),
        };
        let append_bytes = encode_config_wire(&append).expect("bounded singleton append");
        assert!(append_bytes.len() <= opc_consensus::CONSENSUS_MAX_RPC_PAYLOAD_BYTES);
        assert!(encode_config_wire(&admitted_request).is_ok());

        let oversized_request = sized_forwarded_mutation(&store, rejected);
        assert!(!config_command_fits_replication_budget(&command_for(
            &oversized_request
        )));
        assert_eq!(
            preflight_config_command_replication_budget(
                store.inner.identity,
                oversized_request.request_id,
                &oversized_request.intent,
            ),
            Err(ForwardMutationRejection::CommandTooLarge)
        );
        let before = store.inner.raft.metrics().borrow().last_log_index;
        let held_admission = Arc::clone(&store.inner.proposal_admission)
            .acquire_many_owned(
                u32::try_from(DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS)
                    .expect("proposal slot count fits u32"),
            )
            .await
            .expect("hold every proposal slot");
        let local_reply = tokio::time::timeout(
            Duration::from_secs(1),
            store.apply_on_local_leader(
                oversized_request.clone(),
                tokio::time::Instant::now() + Duration::from_secs(2),
            ),
        )
        .await
        .expect("local oversize rejection precedes proposal admission");
        assert_eq!(
            local_reply,
            ForwardMutationReply::Rejected(ForwardMutationRejection::CommandTooLarge)
        );
        assert_eq!(store.inner.raft.metrics().borrow().last_log_index, before);

        let response = tokio::time::timeout(
            Duration::from_secs(1),
            service_call(
                &store,
                ConsensusRpcFamily::ForwardMutation,
                encode_config_wire(&oversized_request)
                    .expect("bounded forwarded oversized command"),
            ),
        )
        .await
        .expect("forwarded oversize rejection precedes proposal admission");
        let forwarded_reply: ForwardMutationReply = decode_config_wire(
            &response
                .result
                .expect("oversized command returns an application reply"),
        )
        .expect("bounded forwarded reply");
        assert_eq!(
            forwarded_reply,
            ForwardMutationReply::Rejected(ForwardMutationRejection::CommandTooLarge)
        );
        assert_eq!(store.inner.raft.metrics().borrow().last_log_index, before);
        assert_eq!(store.inner.proposal_admission.available_permits(), 0);

        let public_request_id = opc_consensus::ConsensusRequestId::from_bytes([0xBC; 16]);
        let public_error = tokio::time::timeout(
            Duration::from_secs(1),
            store.append_commit_idempotent(
                public_request_id,
                sized_attested_commit(DURABLE_OPENRAFT_APPEND_ENTRIES_TARGET_BYTES),
            ),
        )
        .await
        .expect("public oversize rejection does not enter the routing retry loop")
        .expect_err("oversized public command must be terminally rejected");
        assert!(matches!(
            public_error.kind(),
            crate::PersistErrorKind::ConstraintViolation(message)
                if message == "config consensus command exceeds durable replication limit"
        ));
        assert_eq!(store.inner.raft.metrics().borrow().last_log_index, before);
        assert_eq!(store.inner.proposal_admission.available_permits(), 0);

        drop(held_admission);
        store.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn inbound_forward_uses_remaining_budget_instead_of_fresh_local_timeout() {
        let (store, _snapshots) = singleton_store().await;
        let _admission = Arc::clone(&store.inner.proposal_admission)
            .acquire_many_owned(
                u32::try_from(DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS)
                    .expect("proposal slot count fits u32"),
            )
            .await
            .expect("hold proposal admission");
        let request = forwarded_mutation(
            &store,
            ForwardedBudget {
                remaining_nanos: 50_000_000,
            },
        );
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
        let _admission = Arc::clone(&store.inner.proposal_admission)
            .acquire_many_owned(
                u32::try_from(DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS)
                    .expect("proposal slot count fits u32"),
            )
            .await
            .expect("hold proposal admission");
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
                encode_config_wire(&forwarded_mutation(&store, budget))
                    .expect("invalid budget request"),
            )
            .await;
            assert_eq!(Err(ConsensusPeerError::Protocol), response.result);
            assert!(started.elapsed() < Duration::from_millis(100));
        }

        let mut malformed = encode_config_wire(&forwarded_mutation(
            &store,
            ForwardedBudget {
                remaining_nanos: 50_000_000,
            },
        ))
        .expect("valid request");
        malformed.push(0);
        let response = service_call(&store, ConsensusRpcFamily::ForwardMutation, malformed).await;
        assert_eq!(Err(ConsensusPeerError::Protocol), response.result);

        let read = ReadBarrierRequest {
            compatibility: store.peer_compatibility(),
            compatibility_probe: false,
            budget: ForwardedBudget { remaining_nanos: 0 },
        };
        let response = service_call(
            &store,
            ConsensusRpcFamily::ReadBarrier,
            encode_config_wire(&read).expect("zero read budget"),
        )
        .await;
        assert_eq!(Err(ConsensusPeerError::Protocol), response.result);

        let incompatible = ReadBarrierRequest {
            compatibility: ConfigPeerCompatibility {
                audit_key_fingerprint: [0; 32],
                ..store.peer_compatibility()
            },
            compatibility_probe: false,
            budget: ForwardedBudget {
                remaining_nanos: 50_000_000,
            },
        };
        let response = service_call(
            &store,
            ConsensusRpcFamily::ReadBarrier,
            encode_config_wire(&incompatible).expect("incompatible read request"),
        )
        .await;
        assert_eq!(Err(ConsensusPeerError::ScopeMismatch), response.result);
        store.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn formation_probe_rejects_mixed_wire_and_command_revisions_before_admission() {
        #[derive(Serialize)]
        struct ExplicitWirePayload<'a, T: ?Sized> {
            revision: u16,
            value: &'a T,
        }

        let (store, _snapshots) = singleton_store().await;
        let before_log = store.inner.raft.metrics().borrow().last_log_index;
        let current_probe = ReadBarrierRequest {
            compatibility: store.peer_compatibility(),
            compatibility_probe: true,
            budget: ForwardedBudget {
                remaining_nanos: 50_000_000,
            },
        };
        let current_response = service_call(
            &store,
            ConsensusRpcFamily::ReadBarrier,
            encode_config_wire(&current_probe).expect("current formation probe"),
        )
        .await;
        let current_reply: ReadBarrierReply = decode_config_wire(
            &current_response
                .result
                .expect("uniform revision formation probe reply"),
        )
        .expect("decode uniform revision formation reply");
        assert_eq!(ReadBarrierReply::Compatible, current_reply);

        store.inner.admitted.store(false, Ordering::Release);
        let legacy_wire = opc_consensus::encode_bounded(&ExplicitWirePayload {
            revision: super::super::CONFIG_CONSENSUS_WIRE_VERSION - 1,
            value: &current_probe,
        })
        .expect("legacy wire formation probe");
        let response = service_call(&store, ConsensusRpcFamily::ReadBarrier, legacy_wire).await;
        assert_eq!(Err(ConsensusPeerError::Protocol), response.result);

        for compatibility in [
            ConfigPeerCompatibility {
                wire_version: super::super::CONFIG_CONSENSUS_WIRE_VERSION - 1,
                ..store.peer_compatibility()
            },
            ConfigPeerCompatibility {
                command_version: super::super::CONFIG_CONSENSUS_COMMAND_VERSION - 1,
                ..store.peer_compatibility()
            },
        ] {
            let mixed_probe = ReadBarrierRequest {
                compatibility,
                ..current_probe
            };
            let response = service_call(
                &store,
                ConsensusRpcFamily::ReadBarrier,
                encode_config_wire(&mixed_probe).expect("mixed revision formation probe"),
            )
            .await;
            assert_eq!(Err(ConsensusPeerError::ScopeMismatch), response.result);
        }
        assert!(!store.status().admitted);
        assert_eq!(
            before_log,
            store.inner.raft.metrics().borrow().last_log_index
        );
        assert_eq!(
            DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS,
            store.inner.proposal_admission.available_permits()
        );
        store.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn accepted_config_proposals_are_bounded_and_same_id_replays_the_outcome() {
        let (store, _snapshots) = singleton_store_with_timeout(Duration::from_millis(150)).await;
        let apply_gate = Arc::clone(&store.inner.backend.consensus_apply_gate);
        let held_apply = apply_gate
            .acquire_owned()
            .await
            .expect("hold config state-machine apply");
        let target_tx = "00000000-0000-0000-0000-000000000164"
            .parse::<opc_types::TxId>()
            .expect("fixed transaction ID");
        let cancelled_request_id = opc_consensus::ConsensusRequestId::from_bytes([0x41; 16]);
        let cancelled_intent = ConfigMutationIntent::MarkConfirmed { tx_id: target_tx };
        let before = store
            .inner
            .raft
            .metrics()
            .borrow()
            .last_log_index
            .unwrap_or(0);

        let wait_for_log = |store: ConsensusConfigStore, minimum: u64| async move {
            tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    if store
                        .inner
                        .raft
                        .metrics()
                        .borrow()
                        .last_log_index
                        .is_some_and(|index| index >= minimum)
                    {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("accepted proposal reaches the real Openraft log");
        };
        let wait_for_available = |store: ConsensusConfigStore,
                                  expected: usize,
                                  context: &'static str| async move {
            tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    if store.inner.proposal_admission.available_permits() == expected {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap_or_else(|_| panic!("proposal admission did not reach {expected}: {context}"));
        };

        let cancelled_store = store.clone();
        let cancelled_intent_for_task = cancelled_intent.clone();
        let cancelled = tokio::spawn(async move {
            cancelled_store
                .submit_request_inner(cancelled_request_id, cancelled_intent_for_task)
                .await
        });
        wait_for_log(store.clone(), before + 1).await;
        wait_for_available(
            store.clone(),
            DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS - 1,
            "first accepted config proposal",
        )
        .await;
        cancelled.abort();
        let _ = cancelled.await;
        tokio::task::yield_now().await;
        assert_eq!(
            store.inner.proposal_admission.available_permits(),
            DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS - 1,
            "accepted config proposal admission must outlive its cancelled caller"
        );

        let held_saturation = Arc::clone(&store.inner.proposal_admission)
            .acquire_many_owned(
                u32::try_from(DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS - 1)
                    .expect("remaining proposal slots fit u32"),
            )
            .await
            .expect("saturate remaining config proposal admission");
        assert_eq!(store.inner.proposal_admission.available_permits(), 0);

        let rejected_overflow = (0..16)
            .map(|slot| {
                let store = store.clone();
                let request_id = opc_consensus::ConsensusRequestId::from_bytes(
                    [0x80_u8.saturating_add(slot); 16],
                );
                let intent = cancelled_intent.clone();
                tokio::spawn(async move { store.submit_request_inner(request_id, intent).await })
            })
            .collect::<Vec<_>>();
        for attempt in rejected_overflow {
            let error = attempt
                .await
                .expect("bounded config overflow task")
                .expect_err("overflow must fail before acceptance");
            assert!(matches!(error.kind(), crate::PersistErrorKind::Unavailable));
        }
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            Some(before + 1),
            "saturated config admission cannot append another Openraft proposal"
        );
        drop(held_saturation);
        assert_eq!(
            store.inner.proposal_admission.available_permits(),
            DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS - 1,
            "the cancelled accepted config proposal still owns its slot"
        );

        drop(held_apply);
        let all_permits = tokio::time::timeout(
            Duration::from_secs(1),
            Arc::clone(&store.inner.proposal_admission).acquire_many_owned(
                u32::try_from(DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS)
                    .expect("proposal slots fit u32"),
            ),
        )
        .await
        .expect("config proposal supervisors finish after apply")
        .expect("config proposal admission remains open");
        drop(all_permits);

        let replayed = store
            .submit_request_inner(cancelled_request_id, cancelled_intent.clone())
            .await
            .expect("same durable request ID recovers the cancelled outcome");
        let replayed_again = store
            .submit_request_inner(cancelled_request_id, cancelled_intent)
            .await
            .expect("same durable request ID remains replayable");
        assert_eq!(replayed, replayed_again);
        assert_eq!(
            replayed.result,
            Err(super::super::ConfigMutationFailure::NotFound)
        );
        assert!(replayed.raft_log_index > before);

        store.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn precomputed_membership_snapshot_latches_admission() {
        let (store, _snapshots) = singleton_store().await;

        assert!(store.status().admitted);
        assert!(store.apply_live_membership_admission(true));
        assert!(store.inner.admitted.load(Ordering::Acquire));

        assert!(!store.apply_live_membership_admission(false));
        assert!(!store.inner.admitted.load(Ordering::Acquire));
        assert!(!store.apply_live_membership_admission(true));

        store.shutdown().await.expect("shutdown");
    }

    #[test]
    fn owned_watch_snapshot_releases_read_guard_before_downstream_work() {
        let (sender, receiver) = tokio::sync::watch::channel(7_u64);
        let _receiver_keepalive = receiver.clone();
        let (guard_held_tx, guard_held_rx) = std::sync::mpsc::channel();
        let (release_guard_tx, release_guard_rx) = std::sync::mpsc::channel();
        let snapshot_thread = std::thread::spawn(move || {
            map_watch_snapshot(&receiver, |value| {
                guard_held_tx.send(()).expect("signal held read guard");
                release_guard_rx.recv().expect("release held read guard");
                *value
            })
        });
        guard_held_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("snapshot mapper acquires watch read guard");

        let (writer_started_tx, writer_started_rx) = std::sync::mpsc::channel();
        let (writer_done_tx, writer_done_rx) = std::sync::mpsc::channel();
        let writer_thread = std::thread::spawn(move || {
            writer_started_tx
                .send(())
                .expect("signal watch writer start");
            sender.send(8).expect("publish replacement watch value");
            writer_done_tx.send(()).expect("signal completed writer");
        });
        writer_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("watch writer starts");
        assert_eq!(
            Err(std::sync::mpsc::RecvTimeoutError::Timeout),
            writer_done_rx.recv_timeout(Duration::from_millis(50)),
            "watch writer must wait while the snapshot mapper holds its read guard"
        );

        release_guard_tx.send(()).expect("release snapshot mapper");
        assert_eq!(7, snapshot_thread.join().expect("join snapshot mapper"));
        writer_done_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("writer proceeds after owned snapshot returns");
        writer_thread.join().expect("join watch writer");
    }
}
