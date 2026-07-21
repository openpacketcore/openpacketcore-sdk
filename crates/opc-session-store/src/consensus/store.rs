//! Production session store coordinated exclusively by Openraft.
//!
//! Session payload sealing remains an outer adapter concern. Commands admitted
//! here contain only already-enveloped records; the consensus engine, network,
//! log store, snapshots, and state machine never receive an HKMS provider,
//! plaintext key, or plaintext session payload.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::stream::{BoxStream, StreamExt};
use opc_consensus::engine::error::{ClientWriteError, InitializeError, RaftError};
use opc_consensus::engine::{EmptyNode, LogId, StoredMembership};
use opc_consensus::{
    decode_bounded, durable_openraft_config, encode_bounded, DurableOpenraftDomain,
    EnsureLinearizableOutcome, EnsureLinearizableSupervisor, LinearizableReadBarrier,
    LinearizableReadBarrierError, LinearizableReadLease, DURABLE_CONSENSUS_OPERATION_TIMEOUT,
    DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS,
};
use opc_types::Timestamp;
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::raft_adapter::{
    SessionRaftAdapterError, SessionRaftNetworkFactory, SessionRaftPeerDirectory,
    SessionRaftRpcHandler,
};
use super::storage::{self, SessionConsensusStorageError};
use super::{
    SessionConsensusCommand, SessionConsensusConfigurationEpoch, SessionConsensusIdentity,
    SessionConsensusNodeId, SessionConsensusPeer, SessionConsensusPeerError,
    SessionConsensusRequestId, SessionConsensusResponse, SessionConsensusRpcFamily,
    SessionConsensusRpcHandler, SessionConsensusWireRequest, SessionConsensusWireResponse,
    SessionMutationIntent, SessionMutationOutcome, SessionRaft, SessionRaftTypeConfig,
    SessionTopologyMemberBinding, SESSION_CONSENSUS_SCHEMA_VERSION,
};
use crate::backend::{
    record_expiry_preflights, validate_record_expiry_preflights_at,
    validate_record_expiry_preflights_profile, validate_replication_log_page_owned,
    validate_replication_prefix_owned, BackendInstanceIdentity, CompareAndSet, CompareAndSetResult,
    RecordExpiryPreflight, ReplicationEntry, ReplicationLogRange, SessionBackend, SessionOp,
    SessionOpResult, MAX_RECORD_EXPIRY_PREFLIGHTS,
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
use crate::topology_attestation::{
    TopologyAttestationSummary, TopologyAttestationTime, VerifiedQuorumTopologyAttestation,
};
use crate::ttl::{
    checked_session_deadline, validate_session_ttl, validate_stored_record_expiry_at,
};

mod membership;

use membership::SessionTopologyCoordinatorState;
pub use membership::{
    SessionConsensusStorageAnchor, SessionTopologyCandidateBootstrap,
    SessionTopologyTransitionPeers, SessionTopologyTransportAdmission,
    SessionTopologyTransportAdmissionError,
};

/// Default complete client-operation deadline, including leader discovery,
/// forwarding, quorum confirmation, commit, and local apply.
pub const DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT: Duration =
    DURABLE_CONSENSUS_OPERATION_TIMEOUT;

const SESSION_CONSENSUS_ROUTE_RETRY_BACKOFF: Duration = Duration::from_millis(50);
const TOPOLOGY_ENDPOINT_BINDING_DOMAIN: &[u8] =
    b"openpacketcore/session-store/topology-endpoint-binding/v1\0";
const TOPOLOGY_TLS_BINDING_DOMAIN: &[u8] =
    b"openpacketcore/session-store/topology-tls-binding/v1\0";
const TOPOLOGY_BACKING_BINDING_DOMAIN: &[u8] =
    b"openpacketcore/session-store/topology-backing-binding/v1\0";

fn topology_node_bindings(
    topology: &ValidatedQuorumTopology,
) -> BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding> {
    topology
        .members()
        .iter()
        .filter_map(|descriptor| {
            let node_id = topology.consensus_node_id(descriptor.replica_id())?;
            let mut endpoint = Sha256::new();
            endpoint.update(TOPOLOGY_ENDPOINT_BINDING_DOMAIN);
            endpoint.update(Sha256::digest(descriptor.endpoint().host().as_bytes()));
            endpoint.update(descriptor.endpoint().port().to_be_bytes());
            let mut tls = Sha256::new();
            tls.update(TOPOLOGY_TLS_BINDING_DOMAIN);
            tls.update(Sha256::digest(
                descriptor.tls_identity().as_str().as_bytes(),
            ));
            let mut backing = Sha256::new();
            backing.update(TOPOLOGY_BACKING_BINDING_DOMAIN);
            backing.update(descriptor.backing_identity().fingerprint());
            Some((
                node_id,
                SessionTopologyMemberBinding::new(
                    descriptor.configuration_fingerprint(),
                    endpoint.finalize().into(),
                    tls.finalize().into(),
                    backing.finalize().into(),
                ),
            ))
        })
        .collect()
}

fn attestation_deadline_from_verification_start(
    verification_started_at: tokio::time::Instant,
    valid_for: Duration,
) -> Option<tokio::time::Instant> {
    verification_started_at.checked_add(valid_for)
}

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
    /// This exact joining-candidate transition was durably cancelled.
    #[error("session consensus candidate transition was cancelled")]
    CandidateTransitionCancelled,
}

/// Redaction-safe current Openraft observation for readiness and operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SessionConsensusStatus {
    /// Local canonical node ID.
    pub node_id: SessionConsensusNodeId,
    /// Current Openraft term.
    pub term: u64,
    /// Current leader, when known.
    pub leader_id: Option<SessionConsensusNodeId>,
    /// Highest local log index, whether committed or not.
    pub last_log_index: Option<u64>,
    /// Highest locally applied log index.
    pub applied_index: Option<u64>,
    /// Whether exact configured membership has been admitted and remains live.
    pub admitted: bool,
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
enum ForwardRequest {
    Mutation(ForwardMutationRequest),
    RecordExpiryPreflight {
        preflights: BoundedRecordExpiryPreflights,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
struct BoundedRecordExpiryPreflights(Vec<RecordExpiryPreflight>);

impl BoundedRecordExpiryPreflights {
    fn try_from_slice(preflights: &[RecordExpiryPreflight]) -> Result<Self, StoreError> {
        validate_record_expiry_preflights_profile(preflights)?;
        Ok(Self(preflights.to_vec()))
    }

    fn into_inner(self) -> Vec<RecordExpiryPreflight> {
        self.0
    }
}

struct BoundedRecordExpiryPreflightsVisitor;

impl<'de> Visitor<'de> for BoundedRecordExpiryPreflightsVisitor {
    type Value = BoundedRecordExpiryPreflights;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "at most {MAX_RECORD_EXPIRY_PREFLIGHTS} record-expiry descriptors"
        )
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        if sequence
            .size_hint()
            .is_some_and(|size| size > MAX_RECORD_EXPIRY_PREFLIGHTS)
        {
            return Err(serde::de::Error::custom(
                "record-expiry preflight exceeds the operation limit",
            ));
        }
        let mut preflights = Vec::with_capacity(
            sequence
                .size_hint()
                .unwrap_or(0)
                .min(MAX_RECORD_EXPIRY_PREFLIGHTS),
        );
        while let Some(preflight) = sequence.next_element()? {
            if preflights.len() == MAX_RECORD_EXPIRY_PREFLIGHTS {
                return Err(serde::de::Error::custom(
                    "record-expiry preflight exceeds the operation limit",
                ));
            }
            preflights.push(preflight);
        }
        Ok(BoundedRecordExpiryPreflights(preflights))
    }
}

impl<'de> Deserialize<'de> for BoundedRecordExpiryPreflights {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(BoundedRecordExpiryPreflightsVisitor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum ForwardMutationReply {
    Applied(Box<SessionConsensusResponse>),
    RecordExpiryPreflight(Result<(), StoreError>),
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

#[derive(Clone, Copy)]
struct LocalProposalAuthority {
    origin: SessionConsensusNodeId,
    allows_operator_recovery: bool,
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
    storage_identity: SessionConsensusIdentity,
    local_node_id: SessionConsensusNodeId,
    peer_directory: SessionRaftPeerDirectory,
    topology_coordinator: Arc<SessionTopologyCoordinatorState>,
    bootstrap_members: BTreeSet<SessionConsensusNodeId>,
    topology: QuorumTopologySummary,
    clock: Arc<dyn Clock>,
    operation_timeout: Duration,
    admitted: AtomicBool,
    topology_attestation_time_high_water: AtomicU64,
    linearizability: EnsureLinearizableSupervisor<SessionRaftTypeConfig>,
    read_barrier: LinearizableReadBarrier<SessionRaftTypeConfig>,
    proposal_admission: Arc<tokio::sync::Semaphore>,
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
            .field("storage_identity", &self.inner.storage_identity)
            .field("local_node_id", &self.inner.local_node_id)
            .field("bootstrap_members", &self.inner.bootstrap_members.len())
            .field("peer_directory", &self.inner.peer_directory)
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
            QuorumTopologyMode::ValidatedHa
                | QuorumTopologyMode::AttestedHa
                | QuorumTopologyMode::LabSingleton
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
        let topology_coordinator = Arc::new(SessionTopologyCoordinatorState::try_from_topology(
            &topology,
        )?);

        let network = SessionRaftNetworkFactory::try_new(
            identity,
            local_node_id,
            members.clone(),
            peers.clone(),
        )?;
        let peer_directory = network.peer_directory();
        let bindings = topology_node_bindings(&topology);
        let (log_store, state_machine, storage_identity) = storage::open_with_member_bindings(
            &backend,
            snapshot_dir,
            identity,
            members.clone(),
            bindings,
            peer_directory.clone(),
        )
        .await?;
        let (membership_scope, _) = backend
            .consensus_membership_scope_snapshot(storage_identity)
            .await
            .map_err(|_| ConsensusSessionStoreOpenError::StorageUnavailable)?;
        topology_coordinator
            .load_retained_transitions(&membership_scope)
            .map_err(|_| ConsensusSessionStoreOpenError::StorageUnavailable)?;
        let config = Arc::new(session_raft_config()?);
        let raft = SessionRaft::new(local_node_id, config, network, log_store, state_machine)
            .await
            .map_err(|_| ConsensusSessionStoreOpenError::EngineUnavailable)?;
        let raft_handler =
            SessionRaftRpcHandler::new(raft.clone(), peer_directory.clone(), local_node_id);
        let linearizability = EnsureLinearizableSupervisor::new(raft.clone());
        let read_barrier = LinearizableReadBarrier::new(
            local_node_id,
            linearizability.clone(),
            raft.metrics(),
            LinearizableReadLease::Disabled,
        );
        let topology_summary = topology.summary().clone();
        let topology_attestation_time_high_water = topology_summary
            .attestation_admission()
            .production_verified_at()
            .map(TopologyAttestationTime::unix_seconds)
            .unwrap_or(0);

        Ok(Self {
            inner: Arc::new(ConsensusSessionStoreInner {
                raft,
                raft_handler,
                backend,
                storage_identity,
                local_node_id,
                peer_directory,
                topology_coordinator,
                bootstrap_members: members,
                topology: topology_summary,
                clock,
                operation_timeout,
                admitted: AtomicBool::new(false),
                topology_attestation_time_high_water: AtomicU64::new(
                    topology_attestation_time_high_water,
                ),
                linearizability,
                read_barrier,
                proposal_admission: Arc::new(tokio::sync::Semaphore::new(
                    DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS,
                )),
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
        let canonical_bootstrap = self.inner.bootstrap_members.first().copied();
        if !initialized && canonical_bootstrap == Some(self.inner.local_node_id) {
            let initialize = tokio::time::timeout_at(
                deadline,
                self.inner
                    .raft
                    .initialize(self.inner.bootstrap_members.clone()),
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

    /// Snapshot redaction-safe status directly from the one Openraft engine.
    pub fn status(&self) -> SessionConsensusStatus {
        let current_members = self
            .current_scope()
            .map(|(_, members)| members)
            .unwrap_or_default();
        let metrics = self.inner.raft.metrics();
        let (term, leader_id, last_log_index, applied_index, engine_running) = {
            let current = metrics.borrow();
            (
                current.current_term,
                current.current_leader,
                current.last_log_index,
                current.last_applied.as_ref().map(|log_id| log_id.index),
                current.running_state.is_ok(),
            )
        };
        // `membership_config` is Openraft's effective proposal state, not the
        // applied membership authority. It may remain joint or otherwise lead
        // the state machine after a completed change, so it must neither grant
        // nor veto application authority. The latch is set only after the
        // exact durable applied scope is proven; engine failure and local
        // removal remain live vetoes.
        let admitted = self.inner.admitted.load(Ordering::Acquire)
            && engine_running
            && current_members.contains(&self.inner.local_node_id);
        SessionConsensusStatus {
            node_id: self.inner.local_node_id,
            term,
            leader_id,
            last_log_index,
            applied_index,
            admitted,
        }
    }

    pub(crate) fn recovery_identity(&self) -> SessionConsensusIdentity {
        self.inner.storage_identity
    }

    pub(crate) fn recovery_members(&self) -> &BTreeSet<SessionConsensusNodeId> {
        &self.inner.bootstrap_members
    }

    /// Static, fail-closed engine profile admitted from descriptor shape.
    ///
    /// Time-bound HA evidence cannot safely produce a static quorum claim, so
    /// HA topologies return [`SessionStorePlatformProfile::Unknown`]. Production
    /// callers must use [`Self::production_platform_profile_at`] and
    /// [`Self::probe_production_durable_readiness`].
    pub fn platform_profile(&self) -> SessionStorePlatformProfile {
        self.inner.topology.mode().platform_profile()
    }

    /// Redaction-safe topology evidence provenance and freshness at `now`.
    ///
    /// The summary contains only provenance class, configuration epoch,
    /// freshness durations, and result. It never exposes member identities,
    /// endpoints, TLS identities, placement, backing identities, collectors,
    /// proof bytes, or canonical digests. This wall-clock summary is diagnostic
    /// only; it does not apply the store's monotonic expiry or clock high-water
    /// and cannot authorize traffic.
    pub fn topology_attestation_summary_at(
        &self,
        now: TopologyAttestationTime,
    ) -> TopologyAttestationSummary {
        self.inner.topology.attestation_at(now)
    }

    /// Platform profile after requiring fresh production-eligible topology
    /// evidence at `now`.
    ///
    /// Descriptor-only HA returns [`SessionStorePlatformProfile::Unknown`]
    /// rather than presenting configuration strings as observed proof. Calls
    /// share a nondecreasing per-store time authority; a backward `now` fails
    /// closed and cannot revive evidence after a forward/expired evaluation.
    pub fn production_platform_profile_at(
        &self,
        now: TopologyAttestationTime,
    ) -> SessionStorePlatformProfile {
        match self.inner.topology.mode() {
            QuorumTopologyMode::LabSingleton => SessionStorePlatformProfile::SingleReplica,
            QuorumTopologyMode::AttestedHa
                if self
                    .initial_production_attestation_valid_for_at(now)
                    .is_some() =>
            {
                SessionStorePlatformProfile::Quorum
            }
            QuorumTopologyMode::ValidatedHa | QuorumTopologyMode::AttestedHa => {
                SessionStorePlatformProfile::Unknown
            }
        }
    }

    /// Platform profile gated by a separately refreshed attestation for this
    /// exact immutable topology. Identity and production provenance are checked
    /// before the supplied nondecreasing time can advance the store high-water.
    pub fn production_platform_profile_with_attestation_at(
        &self,
        attestation: &VerifiedQuorumTopologyAttestation,
        now: TopologyAttestationTime,
    ) -> SessionStorePlatformProfile {
        if self.inner.topology.mode() != QuorumTopologyMode::AttestedHa {
            return SessionStorePlatformProfile::Unknown;
        }
        if self
            .refreshed_production_attestation_valid_for_at(attestation, now)
            .is_some()
        {
            SessionStorePlatformProfile::Quorum
        } else {
            SessionStorePlatformProfile::Unknown
        }
    }

    async fn wait_for_exact_membership(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<(), ConsensusSessionStoreOpenError> {
        let mut metrics = self.inner.raft.metrics();
        loop {
            let effective_membership_is_exact = {
                let current = metrics.borrow();
                if current.running_state.is_err() {
                    return Err(ConsensusSessionStoreOpenError::EngineUnavailable);
                }
                exact_uniform_voter_membership(
                    current.membership_config.as_ref(),
                    &self.inner.bootstrap_members,
                )
            };
            if effective_membership_is_exact && self.durable_uniform_scope_is_admitted().await? {
                return Ok(());
            }
            tokio::select! {
                changed = metrics.changed() => {
                    if changed.is_err() {
                        return Err(ConsensusSessionStoreOpenError::EngineUnavailable);
                    }
                }
                () = tokio::time::sleep(Duration::from_millis(25)) => {}
                () = tokio::time::sleep_until(deadline) => {
                    return Err(ConsensusSessionStoreOpenError::ClusterFormationRejected);
                }
            }
        }
    }

    async fn durable_uniform_scope_is_admitted(
        &self,
    ) -> Result<bool, ConsensusSessionStoreOpenError> {
        let (scope, applied_membership) = self
            .inner
            .backend
            .consensus_membership_scope_snapshot(self.inner.storage_identity)
            .await
            .map_err(|_| ConsensusSessionStoreOpenError::StorageUnavailable)?;
        let (current_identity, current_members) = self
            .inner
            .peer_directory
            .current_scope()
            .map_err(|_| ConsensusSessionStoreOpenError::ClusterFormationRejected)?;
        Ok(scope.current_identity == current_identity
            && scope.current_members == current_members
            && scope.application_authority_epoch == current_identity.configuration_epoch()
            && scope.application_authority_members == current_members
            && scope.pending.is_none()
            && current_members.contains(&self.inner.local_node_id)
            && exact_uniform_voter_membership(&applied_membership, &current_members))
    }

    fn engine_is_running_in_local_scope(&self) -> bool {
        let Ok((_, current_members)) = self.current_scope() else {
            return false;
        };
        if !current_members.contains(&self.inner.local_node_id) {
            return false;
        }
        let metrics = self.inner.raft.metrics();
        let current = metrics.borrow();
        current.running_state.is_ok()
    }

    fn exact_membership_is_admitted(&self) -> bool {
        self.inner.admitted.load(Ordering::Acquire) && self.engine_is_running_in_local_scope()
    }

    fn current_application_scope_matches(
        &self,
        sender: SessionConsensusNodeId,
        identity: SessionConsensusIdentity,
    ) -> bool {
        self.current_scope()
            .is_ok_and(|(current_identity, current_members)| {
                current_identity == identity
                    && current_members.contains(&self.inner.local_node_id)
                    && current_members.contains(&sender)
            })
    }

    fn current_scope(
        &self,
    ) -> Result<(SessionConsensusIdentity, BTreeSet<SessionConsensusNodeId>), StoreError> {
        self.inner
            .peer_directory
            .current_scope()
            .map_err(|_| consensus_unavailable())
    }

    fn current_member_count(&self) -> Option<usize> {
        self.current_scope().ok().map(|(_, members)| members.len())
    }

    fn is_current_member(&self, node_id: SessionConsensusNodeId) -> bool {
        self.current_scope()
            .is_ok_and(|(_, members)| members.contains(&node_id))
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
    ///
    /// This is an engine/lab/conformance probe and does not evaluate platform
    /// topology evidence. Its `Ready` result MUST NOT authorize production
    /// traffic; use [`Self::probe_production_durable_readiness`] for that gate.
    ///
    /// The recovery-latch check and linearizable barrier share one complete
    /// operation deadline. A delayed recovery check therefore cannot silently
    /// grant the barrier a second operation budget.
    pub async fn probe_durable_readiness(&self) -> DurableReadinessReport {
        let start = tokio::time::Instant::now();
        let deadline = self.operation_deadline_from(start);
        self.probe_durable_readiness_before(deadline).await
    }

    fn operation_deadline_from(&self, start: tokio::time::Instant) -> tokio::time::Instant {
        start
            .checked_add(self.inner.operation_timeout)
            .unwrap_or(start)
    }

    async fn probe_durable_readiness_before(
        &self,
        deadline: tokio::time::Instant,
    ) -> DurableReadinessReport {
        let configured = self.current_member_count().unwrap_or(0);
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
        let recovery_pending = tokio::time::timeout_at(
            deadline,
            self.inner
                .backend
                .consensus_operator_recovery_pending(self.inner.storage_identity),
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
        match self.linearizable_barrier_before(deadline).await {
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

    /// Fresh Openraft readiness gated by currently valid, production-eligible
    /// platform topology evidence.
    ///
    /// Unlike [`Self::probe_durable_readiness`], this is the production traffic
    /// gate. Descriptor-only, deterministic-conformance, expired, or
    /// not-yet-valid evidence returns [`DurableReadinessState::TopologyInvalid`]
    /// without attempting to turn a successful quorum barrier into readiness.
    pub async fn probe_production_durable_readiness(&self) -> DurableReadinessReport {
        let Ok(now) = TopologyAttestationTime::now() else {
            return self.topology_invalid_readiness_report();
        };
        let report = self.probe_production_durable_readiness_at(now).await;
        let Ok(finished_at) = TopologyAttestationTime::now() else {
            return self.topology_invalid_readiness_report();
        };
        if self
            .initial_production_attestation_valid_for_at(finished_at)
            .is_none()
        {
            return self.topology_invalid_readiness_report();
        }
        report
    }

    /// Deterministic-time form of [`Self::probe_production_durable_readiness`]
    /// for conformance harnesses and platform clocks.
    ///
    /// `now` is the wall-clock evaluation origin. Monotonic elapsed time during
    /// the asynchronous probe still consumes the evidence's remaining validity.
    /// Every call on one store must come from one nondecreasing trusted clock;
    /// a backward value fails closed. The no-argument production method uses
    /// the platform system clock directly.
    pub async fn probe_production_durable_readiness_at(
        &self,
        now: TopologyAttestationTime,
    ) -> DurableReadinessReport {
        self.probe_durable_readiness_with_production_attestation(
            self.inner.topology.attestation_admission(),
            now,
        )
        .await
    }

    /// Fresh Openraft readiness gated by a separately refreshed attestation
    /// and the current platform wall clock.
    ///
    /// The proof is bound to the exact immutable store topology. The probe also
    /// uses a monotonic deadline and rechecks wall-clock freshness after the
    /// asynchronous barrier, so evidence expiring during the operation cannot
    /// produce a ready result.
    pub async fn probe_production_durable_readiness_with_attestation(
        &self,
        attestation: &VerifiedQuorumTopologyAttestation,
    ) -> DurableReadinessReport {
        let Ok(now) = TopologyAttestationTime::now() else {
            return self.topology_invalid_readiness_report();
        };
        let report = self
            .probe_production_durable_readiness_with_attestation_at(attestation, now)
            .await;
        let Ok(finished_at) = TopologyAttestationTime::now() else {
            return self.topology_invalid_readiness_report();
        };
        if self
            .refreshed_production_attestation_valid_for_at(attestation, finished_at)
            .is_none()
        {
            return self.topology_invalid_readiness_report();
        }
        report
    }

    /// Fresh Openraft readiness gated by a separately refreshed attestation
    /// for this exact immutable topology.
    ///
    /// This is the long-running form of the production gate: consumers may
    /// periodically authenticate replacement evidence through
    /// [`ValidatedQuorumTopology::verify_attestation_evidence`] and pass the
    /// resulting opaque value here. The token cannot change membership and a
    /// token for another cluster/configuration/epoch fails closed. Monotonic
    /// elapsed time during the probe consumes the token's remaining validity.
    /// Every explicit `now` on one store must come from the same nondecreasing
    /// trusted clock authority. A process restart must authenticate evidence
    /// again against current time; the in-process clock high-water and verified
    /// token are intentionally not persisted. The attestor's proof/replay policy
    /// decides whether a still-unexpired underlying proof may be re-presented.
    pub async fn probe_production_durable_readiness_with_attestation_at(
        &self,
        attestation: &VerifiedQuorumTopologyAttestation,
        now: TopologyAttestationTime,
    ) -> DurableReadinessReport {
        let current_identity = self.current_scope().ok().map(|(identity, _)| identity);
        if self.inner.topology.mode() != QuorumTopologyMode::AttestedHa
            || current_identity != Some(attestation.consensus_identity())
        {
            return self.topology_invalid_readiness_report();
        }
        self.probe_durable_readiness_with_production_attestation(attestation.admission(), now)
            .await
    }

    async fn probe_durable_readiness_with_production_attestation(
        &self,
        admission: &crate::topology_attestation::TopologyAttestationAdmission,
        now: TopologyAttestationTime,
    ) -> DurableReadinessReport {
        // Capture the operation origin before evaluating freshness. Any time
        // consumed by wall/monotonic verification must reduce, never extend,
        // the asynchronous barrier budget.
        let start = tokio::time::Instant::now();
        let Some(valid_for) = self.production_attestation_valid_for_at(admission, now) else {
            return self.topology_invalid_readiness_report();
        };
        let Some(attestation_deadline) =
            attestation_deadline_from_verification_start(start, valid_for)
        else {
            return self.topology_invalid_readiness_report();
        };
        let deadline = self
            .operation_deadline_from(start)
            .min(attestation_deadline);
        let report = self
            .probe_durable_readiness_before(deadline)
            .await
            .with_production_topology_attestation();
        if tokio::time::Instant::now() >= attestation_deadline
            || self
                .production_attestation_valid_for_at(admission, now)
                .is_none()
        {
            self.topology_invalid_readiness_report()
        } else {
            report
        }
    }

    fn initial_production_attestation_valid_for_at(
        &self,
        now: TopologyAttestationTime,
    ) -> Option<Duration> {
        (self.inner.topology.mode() == QuorumTopologyMode::AttestedHa).then_some(())?;
        self.current_scope()
            .ok()
            .filter(|(identity, _)| *identity == self.inner.storage_identity)?;
        self.production_attestation_valid_for_at(self.inner.topology.attestation_admission(), now)
    }

    fn refreshed_production_attestation_valid_for_at(
        &self,
        attestation: &VerifiedQuorumTopologyAttestation,
        now: TopologyAttestationTime,
    ) -> Option<Duration> {
        (self.inner.topology.mode() == QuorumTopologyMode::AttestedHa).then_some(())?;
        self.current_scope()
            .ok()
            .filter(|(identity, _)| *identity == attestation.consensus_identity())?;
        self.production_attestation_valid_for_at(attestation.admission(), now)
    }

    fn production_attestation_valid_for_at(
        &self,
        admission: &crate::topology_attestation::TopologyAttestationAdmission,
        now: TopologyAttestationTime,
    ) -> Option<Duration> {
        (self.inner.topology.mode() == QuorumTopologyMode::AttestedHa).then_some(())?;
        let verified_at = admission.production_verified_at()?;
        if self.current_member_count()? < 3
            || now < verified_at
            || !self.advance_topology_attestation_time(now)
        {
            return None;
        }
        let valid_for = admission.production_valid_for_at(now, std::time::Instant::now())?;
        (self
            .inner
            .topology_attestation_time_high_water
            .load(Ordering::Acquire)
            == now.unix_seconds())
        .then_some(valid_for)
    }

    fn advance_topology_attestation_time(&self, now: TopologyAttestationTime) -> bool {
        let candidate = now.unix_seconds();
        let high_water = &self.inner.topology_attestation_time_high_water;
        let mut current = high_water.load(Ordering::Acquire);
        loop {
            if candidate < current {
                return false;
            }
            if candidate == current {
                return true;
            }
            match high_water.compare_exchange_weak(
                current,
                candidate,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }

    fn topology_invalid_readiness_report(&self) -> DurableReadinessReport {
        let configured = self.current_member_count().unwrap_or(0);
        let quorum = (configured / 2) + 1;
        DurableReadinessReport::new(
            DurableReadinessState::TopologyInvalid,
            configured,
            0,
            0,
            quorum,
            None,
            Vec::new(),
        )
        .with_production_topology_attestation()
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
                .consensus_operator_recovery_pending(self.inner.storage_identity),
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
                self.apply_on_local_leader(request.clone(), self.inner.local_node_id, deadline)
                    .await
            } else {
                match self
                    .call_peer::<_, ForwardMutationReply>(
                        leader,
                        SessionConsensusRpcFamily::ForwardMutation,
                        &ForwardRequest::Mutation(request.clone()),
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
                        *candidate != leader && self.is_current_member(*candidate)
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
                ForwardMutationReply::RecordExpiryPreflight(_) => {
                    return Err(consensus_outcome_unavailable(&request.intent));
                }
            }
        }
    }

    async fn preflight_record_expiry_before(
        &self,
        preflights: &[RecordExpiryPreflight],
        deadline: tokio::time::Instant,
    ) -> Result<(), StoreError> {
        validate_record_expiry_preflights_profile(preflights)?;
        self.require_exact_membership_admission()?;
        let request = ForwardRequest::RecordExpiryPreflight {
            preflights: BoundedRecordExpiryPreflights::try_from_slice(preflights)?,
        };
        let mut preferred = None;
        loop {
            let leader = match preferred.take() {
                Some(leader) => leader,
                None => self.wait_for_known_leader(deadline).await?,
            };
            let reply = if leader == self.inner.local_node_id {
                let ForwardRequest::RecordExpiryPreflight { preflights } = request.clone() else {
                    unreachable!("fixed expiry-preflight request")
                };
                self.preflight_record_expiry_on_local_leader(
                    preflights.into_inner(),
                    self.inner.local_node_id,
                    deadline,
                )
                .await
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
                        // A valid preflight may have committed only its logical
                        // time floor. Never run provider work without a
                        // definitive acknowledgement; an outer retry is safe.
                        return Err(consensus_unavailable());
                    }
                    Err(ConsensusPeerCallFailure::BeforeTransmission) => {
                        self.wait_for_route_refresh(leader, deadline).await?;
                        continue;
                    }
                }
            };
            match reply {
                ForwardMutationReply::RecordExpiryPreflight(result) => return result,
                ForwardMutationReply::NotLeader {
                    leader: next_leader,
                } => {
                    preferred = next_leader.filter(|candidate| {
                        *candidate != leader && self.is_current_member(*candidate)
                    });
                    if preferred.is_none() {
                        self.wait_for_route_refresh(leader, deadline).await?;
                    }
                }
                ForwardMutationReply::Unavailable => {
                    self.wait_for_route_refresh(leader, deadline).await?;
                }
                ForwardMutationReply::Applied(_) => {
                    return Err(consensus_unavailable());
                }
            }
        }
    }

    async fn apply_on_local_leader(
        &self,
        request: ForwardMutationRequest,
        origin: SessionConsensusNodeId,
        deadline: tokio::time::Instant,
    ) -> ForwardMutationReply {
        self.apply_on_local_leader_inner(request, origin, deadline, false)
            .await
    }

    async fn apply_on_local_leader_inner(
        &self,
        request: ForwardMutationRequest,
        origin: SessionConsensusNodeId,
        deadline: tokio::time::Instant,
        allow_operator_recovery: bool,
    ) -> ForwardMutationReply {
        // Membership changes take the exclusive side of this gate. Holding a
        // shared guard through the definitive proposal result lets the
        // transition driver drain every already-admitted application write
        // before it commits learner-ready/fencing evidence.
        let operation_gate = self.inner.topology_coordinator.operation_gate();
        let operation_guard =
            match tokio::time::timeout_at(deadline, operation_gate.read_owned()).await {
                Ok(guard) => guard,
                Err(_) => return ForwardMutationReply::Unavailable,
            };
        if self.require_exact_membership_admission().is_err() {
            return ForwardMutationReply::Unavailable;
        }
        if !allow_operator_recovery {
            let recovery_pending = match tokio::time::timeout_at(
                deadline,
                self.inner
                    .backend
                    .consensus_operator_recovery_pending(self.inner.storage_identity),
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
            EnsureLinearizableOutcome::Ready { .. } => {
                if self.require_exact_membership_admission().is_err() {
                    return ForwardMutationReply::Unavailable;
                }
            }
            EnsureLinearizableOutcome::Retry { leader_hint } => {
                return ForwardMutationReply::NotLeader {
                    leader: leader_hint,
                };
            }
            EnsureLinearizableOutcome::Unavailable => {
                return ForwardMutationReply::Unavailable;
            }
            _ => return ForwardMutationReply::Unavailable,
        }

        let logical_time = match tokio::time::timeout_at(
            deadline,
            self.inner
                .backend
                .consensus_logical_time(self.inner.storage_identity),
        )
        .await
        {
            Ok(Ok(persisted)) => persisted.map_or_else(
                || self.inner.clock.now_utc(),
                |persisted| persisted.max(self.inner.clock.now_utc()),
            ),
            Ok(Err(_)) | Err(_) => return ForwardMutationReply::Unavailable,
        };
        self.propose_on_local_leader(
            request,
            LocalProposalAuthority {
                origin,
                allows_operator_recovery: allow_operator_recovery,
            },
            logical_time,
            proposal_permit,
            operation_guard,
            deadline,
        )
        .await
    }

    async fn propose_on_local_leader(
        &self,
        request: ForwardMutationRequest,
        authority: LocalProposalAuthority,
        logical_time: Timestamp,
        proposal_permit: tokio::sync::OwnedSemaphorePermit,
        operation_guard: tokio::sync::OwnedRwLockReadGuard<()>,
        deadline: tokio::time::Instant,
    ) -> ForwardMutationReply {
        let outcome_unavailable = consensus_outcome_unavailable(&request.intent);
        let Ok((identity, _)) = self.current_scope() else {
            return ForwardMutationReply::Unavailable;
        };
        let intent = match request.intent {
            intent @ SessionMutationIntent::FinalizeOperatorRecovery { .. }
                if authority.allows_operator_recovery =>
            {
                intent
            }
            mutation => SessionMutationIntent::Authorized {
                origin: authority.origin,
                authority_identity: identity,
                mutation: Box::new(mutation),
            },
        };
        let command = super::SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: self.inner.storage_identity,
            request_id: request.request_id,
            logical_time,
            intent,
        };
        if let Err(error) = validate_consensus_command_preproposal(&command) {
            return ForwardMutationReply::Applied(Box::new(SessionConsensusResponse::rejected(
                error,
            )));
        }
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
            drop(proposal_permit);
            drop(operation_guard);
        });
        match tokio::time::timeout_at(deadline, completion_rx).await {
            Err(_) | Ok(Err(_)) => ForwardMutationReply::Applied(Box::new(
                SessionConsensusResponse::rejected(timeout_outcome_unavailable),
            )),
            Ok(Ok(reply)) => reply,
        }
    }

    async fn preflight_record_expiry_on_local_leader(
        &self,
        preflights: Vec<RecordExpiryPreflight>,
        origin: SessionConsensusNodeId,
        deadline: tokio::time::Instant,
    ) -> ForwardMutationReply {
        if let Err(error) = validate_record_expiry_preflights_profile(&preflights) {
            return ForwardMutationReply::RecordExpiryPreflight(Err(error));
        }
        let operation_gate = self.inner.topology_coordinator.operation_gate();
        let operation_guard =
            match tokio::time::timeout_at(deadline, operation_gate.read_owned()).await {
                Ok(guard) => guard,
                Err(_) => return ForwardMutationReply::Unavailable,
            };
        if self.require_exact_membership_admission().is_err() {
            return ForwardMutationReply::Unavailable;
        }
        let recovery_pending = match tokio::time::timeout_at(
            deadline,
            self.inner
                .backend
                .consensus_operator_recovery_pending(self.inner.storage_identity),
        )
        .await
        {
            Ok(Ok(pending)) => pending,
            Ok(Err(_)) | Err(_) => return ForwardMutationReply::Unavailable,
        };
        if recovery_pending {
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
            EnsureLinearizableOutcome::Ready { .. } => {
                if self.require_exact_membership_admission().is_err() {
                    return ForwardMutationReply::Unavailable;
                }
            }
            EnsureLinearizableOutcome::Retry { leader_hint } => {
                return ForwardMutationReply::NotLeader {
                    leader: leader_hint,
                };
            }
            EnsureLinearizableOutcome::Unavailable => {
                return ForwardMutationReply::Unavailable;
            }
            _ => return ForwardMutationReply::Unavailable,
        }
        let persisted = match tokio::time::timeout_at(
            deadline,
            self.inner
                .backend
                .consensus_logical_time(self.inner.storage_identity),
        )
        .await
        {
            Ok(Ok(persisted)) => persisted,
            Ok(Err(_)) | Err(_) => return ForwardMutationReply::Unavailable,
        };
        if persisted.is_some_and(|persisted| {
            validate_record_expiry_preflights_at(&preflights, persisted).is_ok()
        }) {
            return ForwardMutationReply::RecordExpiryPreflight(Ok(()));
        }
        let authority_time = persisted.map_or_else(
            || self.inner.clock.now_utc(),
            |persisted| persisted.max(self.inner.clock.now_utc()),
        );
        if let Err(error) = validate_record_expiry_preflights_at(&preflights, authority_time) {
            return ForwardMutationReply::RecordExpiryPreflight(Err(error));
        }
        if !preflights
            .iter()
            .copied()
            .any(RecordExpiryPreflight::is_finite)
        {
            return ForwardMutationReply::RecordExpiryPreflight(Ok(()));
        }

        let intent = SessionMutationIntent::AdvanceLogicalTime;
        let reply = self
            .propose_on_local_leader(
                ForwardMutationRequest {
                    request_id: SessionConsensusRequestId::new(),
                    intent: intent.clone(),
                },
                LocalProposalAuthority {
                    origin,
                    allows_operator_recovery: false,
                },
                authority_time,
                proposal_permit,
                operation_guard,
                deadline,
            )
            .await;
        match reply {
            ForwardMutationReply::Applied(response) => ForwardMutationReply::RecordExpiryPreflight(
                validate_committed_record_expiry_preflight(&preflights, &intent, &response),
            ),
            other => other,
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
                self.inner.local_node_id,
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
            ForwardMutationReply::Unavailable | ForwardMutationReply::RecordExpiryPreflight(_) => {
                Err(OperatorRecoveryCommitError::Unavailable)
            }
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
            self.inner
                .linearizability
                .ensure_linearizable(deadline)
                .await,
            EnsureLinearizableOutcome::Ready { .. }
        ) {
            return false;
        }
        self.exact_membership_is_admitted()
            && tokio::time::timeout_at(
                deadline,
                self.inner.backend.consensus_operator_recovery_committed(
                    self.inner.storage_identity,
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
        let (identity, peer) = self
            .inner
            .peer_directory
            .resolve_application(target)
            .map_err(|_| ConsensusPeerCallFailure::BeforeTransmission)?;
        let payload =
            encode_bounded(request).map_err(|_| ConsensusPeerCallFailure::BeforeTransmission)?;
        let wire = SessionConsensusWireRequest::try_new(
            identity,
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
                .consensus_operator_recovery_pending(self.inner.storage_identity),
        )
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or(true);
        if recovery_pending {
            return ReadBarrierReply::Unavailable;
        }
        match self.inner.read_barrier.admit(deadline).await {
            Ok(admit) if self.exact_membership_is_admitted() => {
                ReadBarrierReply::Ready(admit.read_log_id())
            }
            Ok(_) | Err(LinearizableReadBarrierError::Unavailable) => ReadBarrierReply::Unavailable,
            Err(LinearizableReadBarrierError::NotLeader { leader }) => {
                ReadBarrierReply::NotLeader { leader }
            }
            _ => ReadBarrierReply::Unavailable,
        }
    }

    async fn linearizable_barrier_before(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<Option<LogId<SessionConsensusNodeId>>, StoreError> {
        self.require_exact_membership_admission()?;
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
                    if let Some(log_id) = &log_id {
                        self.inner
                            .read_barrier
                            .wait_for_applied_index(log_id.index, deadline)
                            .await
                            .map_err(|_| consensus_unavailable())?;
                    }
                    self.require_exact_membership_admission()?;
                    return Ok(log_id);
                }
                ReadBarrierReply::NotLeader {
                    leader: next_leader,
                } => {
                    preferred = next_leader.filter(|candidate| {
                        *candidate != leader && self.is_current_member(*candidate)
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
        self.inner
            .read_barrier
            .wait_for_applied_index(response.raft_log_index, deadline)
            .await
            .map_err(|_| consensus_unavailable())?;
        response.logical_time.ok_or_else(consensus_unavailable)
    }

    async fn logical_read_time(&self) -> Result<Timestamp, StoreError> {
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        self.logical_read_time_before(deadline).await
    }
}

fn session_raft_config() -> Result<opc_consensus::engine::Config, ConsensusSessionStoreOpenError> {
    durable_openraft_config(DurableOpenraftDomain::SessionState)
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

fn validate_committed_record_expiry_preflight(
    preflights: &[RecordExpiryPreflight],
    intent: &SessionMutationIntent,
    response: &SessionConsensusResponse,
) -> Result<(), StoreError> {
    if !committed_response_matches_intent(intent, response)
        || !matches!(&response.result, Ok(SessionMutationOutcome::Unit))
    {
        return Err(consensus_unavailable());
    }
    let committed_logical_time = response.logical_time.ok_or_else(consensus_unavailable)?;
    validate_record_expiry_preflights_at(preflights, committed_logical_time)
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

fn rejected_error_matches_intent(intent: &SessionMutationIntent, error: &StoreError) -> bool {
    // Normal callers validate intent before routing. The only remaining
    // preproposal rejection is the fixed bounded-command encoding limit.
    matches!(error, StoreError::PayloadTooLarge { .. })
        || matches!(
            (intent, error),
            (
                SessionMutationIntent::CompareAndSet(_),
                StoreError::InvalidRecordExpiry
            )
        )
}

fn committed_error_matches_intent(intent: &SessionMutationIntent, error: &StoreError) -> bool {
    // Application-authority revocation is a deterministic committed outcome
    // for every user mutation. The response is matched against the original
    // unwrapped intent, not the state-machine-only `Authorized` envelope.
    if matches!(error, StoreError::TopologyAuthorityRevoked) {
        return matches!(
            intent,
            SessionMutationIntent::CompareAndSet(_)
                | SessionMutationIntent::DeleteFenced(_)
                | SessionMutationIntent::RefreshTtl { .. }
                | SessionMutationIntent::AcquireLease { .. }
                | SessionMutationIntent::RenewLease { .. }
                | SessionMutationIntent::ReleaseLease(_)
        );
    }
    match intent {
        SessionMutationIntent::AdvanceLogicalTime => false,
        SessionMutationIntent::CompareAndSet(_) => matches!(
            error,
            StoreError::NotFound
                | StoreError::StaleFence
                | StoreError::InvalidKey(_)
                | StoreError::LeaseExpired
                | StoreError::InvalidRecordExpiry
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
        SessionMutationIntent::PrepareTopologyTransition { .. }
        | SessionMutationIntent::MarkTopologyLearnersReady { .. }
        | SessionMutationIntent::FenceTopologyAuthority { .. }
        | SessionMutationIntent::AbortTopologyTransition { .. }
        | SessionMutationIntent::FinalizeTopologyTransition { .. }
        | SessionMutationIntent::Authorized { .. } => false,
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

fn validate_consensus_command_preproposal(
    command: &super::SessionConsensusCommand,
) -> Result<(), StoreError> {
    let intent = match &command.intent {
        SessionMutationIntent::Authorized { mutation, .. } => mutation.as_ref(),
        intent => intent,
    };
    if let SessionMutationIntent::CompareAndSet(op) = intent {
        validate_stored_record_expiry_at(&op.new_record, command.logical_time)?;
    }
    Ok(())
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
    if matches!(
        intent,
        SessionMutationIntent::PrepareTopologyTransition { .. }
            | SessionMutationIntent::MarkTopologyLearnersReady { .. }
            | SessionMutationIntent::FenceTopologyAuthority { .. }
            | SessionMutationIntent::AbortTopologyTransition { .. }
            | SessionMutationIntent::FinalizeTopologyTransition { .. }
            | SessionMutationIntent::Authorized { .. }
    ) {
        return Err(StoreError::CapabilityNotSupported(
            "topology_transition_requires_local_coordinator_authority".into(),
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
            || request.sender != authenticated_sender
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
                if !self
                    .store
                    .current_application_scope_matches(authenticated_sender, request.identity)
                {
                    return SessionConsensusWireResponse {
                        result: Err(SessionConsensusPeerError::ScopeMismatch),
                    };
                }
                let forwarded: ForwardRequest = match decode_bounded(&request.payload) {
                    Ok(forwarded) => forwarded,
                    Err(_) => return protocol_rejection(),
                };
                let deadline = tokio::time::Instant::now()
                    .checked_add(self.store.inner.operation_timeout)
                    .unwrap_or_else(tokio::time::Instant::now);
                let reply = match forwarded {
                    ForwardRequest::Mutation(request) => {
                        self.store
                            .apply_on_local_leader(request, authenticated_sender, deadline)
                            .await
                    }
                    ForwardRequest::RecordExpiryPreflight { preflights } => {
                        self.store
                            .preflight_record_expiry_on_local_leader(
                                preflights.into_inner(),
                                authenticated_sender,
                                deadline,
                            )
                            .await
                    }
                };
                encode_service_reply(&reply)
            }
            SessionConsensusRpcFamily::ReadBarrier => {
                if !self
                    .store
                    .current_application_scope_matches(authenticated_sender, request.identity)
                {
                    return SessionConsensusWireResponse {
                        result: Err(SessionConsensusPeerError::ScopeMismatch),
                    };
                }
                if decode_bounded::<ReadBarrierRequest>(&request.payload).is_err() {
                    return protocol_rejection();
                }
                let deadline = tokio::time::Instant::now()
                    .checked_add(self.store.inner.operation_timeout)
                    .unwrap_or_else(tokio::time::Instant::now);
                encode_service_reply(&self.store.local_read_barrier(deadline).await)
            }
            SessionConsensusRpcFamily::TopologyAdmissionBarrier => {
                let barrier = match decode_bounded(&request.payload) {
                    Ok(barrier) => barrier,
                    Err(_) => return protocol_rejection(),
                };
                let reply = self
                    .store
                    .handle_topology_admission_barrier(
                        authenticated_sender,
                        request.identity,
                        barrier,
                    )
                    .await;
                encode_service_reply(&reply)
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

    async fn preflight_record_expiry(
        &self,
        preflights: &[RecordExpiryPreflight],
    ) -> Result<(), StoreError> {
        validate_record_expiry_preflights_profile(preflights)?;
        if !preflights
            .iter()
            .copied()
            .any(RecordExpiryPreflight::is_finite)
        {
            return Ok(());
        }
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        self.preflight_record_expiry_before(preflights, deadline)
            .await
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
        let preflights = record_expiry_preflights(&ops)?;
        validate_consensus_batch(&ops)?;
        self.preflight_record_expiry(&preflights).await?;
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
    use std::sync::Mutex;

    use bytes::Bytes;
    use opc_consensus::engine::{CommittedLeaderId, Membership};
    use opc_consensus::{
        derive_configuration_id, ConsensusClusterId, ConsensusConfigurationEpoch, ConsensusIdentity,
    };

    use super::*;
    use crate::backend::ReplicationOp;
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

    #[derive(Debug)]
    struct MutableClock(Mutex<Timestamp>);

    impl MutableClock {
        fn new(now: Timestamp) -> Self {
            Self(Mutex::new(now))
        }

        fn set(&self, now: Timestamp) {
            *self.0.lock().expect("clock lock") = now;
        }
    }

    impl Clock for MutableClock {
        fn now_utc(&self) -> Timestamp {
            *self.0.lock().expect("clock lock")
        }
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

    fn forged_operator_recovery_intent(seed: u8) -> SessionMutationIntent {
        SessionMutationIntent::FinalizeOperatorRecovery {
            recovery_epoch: 1,
            plan_digest: [seed; 32],
            fence_high_water: 7,
            credential_high_water: 9,
        }
    }

    fn durable_recovery_epoch(
        database: &std::path::Path,
        identity: SessionConsensusIdentity,
    ) -> u64 {
        let connection = rusqlite::Connection::open(database).expect("open recovery state");
        crate::sqlite::consensus::read_operator_recovery_sync(&connection, identity)
            .expect("read recovery state")
            .recovery_epoch
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

    #[tokio::test(start_paused = true)]
    async fn attestation_deadline_is_anchored_before_verification_work() {
        let verification_started_at = tokio::time::Instant::now();
        tokio::time::advance(Duration::from_millis(400)).await;

        let deadline = attestation_deadline_from_verification_start(
            verification_started_at,
            Duration::from_secs(1),
        )
        .expect("representable attestation deadline");

        assert_eq!(
            deadline.saturating_duration_since(tokio::time::Instant::now()),
            Duration::from_millis(600),
            "verification work must consume the original validity budget"
        );
    }

    #[test]
    fn corrupt_durable_state_is_typed_as_recovery_required() {
        assert_eq!(
            ConsensusSessionStoreOpenError::RecoveryRequired,
            ConsensusSessionStoreOpenError::from(SessionConsensusStorageError::CorruptState)
        );
    }

    #[test]
    fn forwarded_expiry_preflight_is_bounded_during_deserialization() {
        let key = SessionKey {
            tenant: TenantId::new("preflight-bound").expect("tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"preflight-bound")
                .try_into()
                .expect("stable ID"),
        };
        let descriptor = RecordExpiryPreflight::from_record(&StoredSessionRecord {
            key,
            generation: Generation::new(1),
            owner: OwnerId::new("preflight-bound-owner").expect("owner"),
            fence: FenceToken::new(1),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("preflight-bound"),
            expires_at: None,
            payload: EncryptedSessionPayload::new(b"must-not-cross-preflight"),
        });
        let exact = ForwardRequest::RecordExpiryPreflight {
            preflights: BoundedRecordExpiryPreflights::try_from_slice(&vec![
                descriptor;
                MAX_RECORD_EXPIRY_PREFLIGHTS
            ])
            .expect("exact bound"),
        };
        let mut encoded = serde_json::to_value(exact).expect("encode exact preflight");
        let decoded: ForwardRequest =
            serde_json::from_value(encoded.clone()).expect("decode exact preflight");
        assert!(matches!(
            decoded,
            ForwardRequest::RecordExpiryPreflight { preflights }
                if preflights.0.len() == MAX_RECORD_EXPIRY_PREFLIGHTS
        ));
        let rendered = encoded.to_string();
        for forbidden in ["stable_id", "payload", "owner", "generation", "fence"] {
            assert!(!rendered.contains(forbidden));
        }

        let values = encoded["RecordExpiryPreflight"]["preflights"]
            .as_array_mut()
            .expect("preflight array");
        values.push(values[0].clone());
        assert!(serde_json::from_value::<ForwardRequest>(encoded).is_err());
    }

    #[test]
    fn expiry_preflight_uses_committed_logical_time_and_fails_closed_when_absent() {
        let proposed_time = Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH);
        let expires_at = checked_session_deadline(proposed_time, crate::MAX_SESSION_TTL)
            .expect("maximum expiry");
        let record = StoredSessionRecord {
            key: SessionKey {
                tenant: TenantId::new("concurrent-expiry-floor").expect("tenant"),
                nf_kind: NetworkFunctionKind::smf(),
                key_type: SessionKeyType::PduSession,
                stable_id: Bytes::from_static(b"concurrent-expiry-floor")
                    .try_into()
                    .expect("stable ID"),
            },
            generation: Generation::new(1),
            owner: OwnerId::new("concurrent-expiry-owner").expect("owner"),
            fence: FenceToken::new(1),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("concurrent-expiry-floor"),
            expires_at: Some(expires_at),
            payload: EncryptedSessionPayload::new(b"payload-free-preflight"),
        };
        let preflights = [RecordExpiryPreflight::from_record(&record)];
        let intent = SessionMutationIntent::AdvanceLogicalTime;
        let response = |logical_time| SessionConsensusResponse {
            result: Ok(SessionMutationOutcome::Unit),
            sequence: 1,
            digest: Some(crate::consensus::SessionConsensusEntryDigest::from_bytes(
                [0x4d; 32],
            )),
            logical_time: Some(logical_time),
            raft_log_index: 1,
        };

        validate_committed_record_expiry_preflight(&preflights, &intent, &response(proposed_time))
            .expect("proposal-time verdict remains valid at the same committed time");

        let concurrently_advanced = Timestamp::from_offset_datetime(
            proposed_time
                .as_offset_datetime()
                .checked_add(time::Duration::nanoseconds(1))
                .expect("one nanosecond later"),
        );
        validate_committed_record_expiry_preflight(
            &preflights,
            &intent,
            &response(concurrently_advanced),
        )
        .expect("a newer committed floor preserves the maximum-TTL upper bound");

        let mut missing_authority = response(concurrently_advanced);
        missing_authority.logical_time = None;
        assert!(matches!(
            validate_committed_record_expiry_preflight(&preflights, &intent, &missing_authority,),
            Err(StoreError::BackendUnavailable(_))
        ));
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
        assert!(rejected_response_matches_intent(
            &cas_intent,
            &SessionConsensusResponse::rejected(StoreError::InvalidRecordExpiry)
        ));
        assert!(!rejected_response_matches_intent(
            &SessionMutationIntent::DeleteFenced(lease_a.clone()),
            &SessionConsensusResponse::rejected(StoreError::InvalidRecordExpiry)
        ));
        assert!(!committed_response_matches_intent(
            &cas_intent,
            &committed(Ok(SessionMutationOutcome::Unit))
        ));

        let SessionMutationIntent::CompareAndSet(cas) = &cas_intent else {
            unreachable!("CAS intent changed variant")
        };
        let mut invalid_cas = cas.as_ref().clone();
        invalid_cas.new_record.expires_at = Some(Timestamp::from_offset_datetime(
            checked_session_deadline(logical_time, crate::MAX_SESSION_TTL)
                .expect("maximum record expiry")
                .as_offset_datetime()
                .checked_add(time::Duration::nanoseconds(1))
                .expect("maximum plus one"),
        ));
        let invalid_command = crate::consensus::SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: singleton_topology()
                .consensus_identity()
                .expect("consensus topology identity"),
            request_id: SessionConsensusRequestId::new(),
            logical_time,
            intent: SessionMutationIntent::CompareAndSet(Box::new(invalid_cas)),
        };
        assert_eq!(
            validate_consensus_command_preproposal(&invalid_command),
            Err(StoreError::InvalidRecordExpiry)
        );
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
        for revoked_intent in [
            cas_intent.clone(),
            SessionMutationIntent::DeleteFenced(lease_a.clone()),
            SessionMutationIntent::RefreshTtl {
                lease: lease_a.clone(),
                ttl,
            },
            acquire.clone(),
            renew.clone(),
            SessionMutationIntent::ReleaseLease(lease_a.clone()),
        ] {
            assert!(committed_response_matches_intent(
                &revoked_intent,
                &committed(Err(StoreError::TopologyAuthorityRevoked)),
            ));
        }
        assert!(!committed_response_matches_intent(
            &SessionMutationIntent::AdvanceLogicalTime,
            &committed(Err(StoreError::TopologyAuthorityRevoked)),
        ));
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
        let production = store
            .probe_production_durable_readiness_at(TopologyAttestationTime::from_unix_seconds(
                1_000,
            ))
            .await;
        assert_eq!(production.state(), DurableReadinessState::TopologyInvalid);
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
                store.inner.local_node_id,
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
        let production = store
            .probe_production_durable_readiness_at(TopologyAttestationTime::from_unix_seconds(
                1_000,
            ))
            .await;
        assert_eq!(production.state(), DurableReadinessState::TopologyInvalid);
        assert_eq!(
            initialized.recovery_progress().state(),
            DurableRecoveryState::Synchronized
        );
    }

    #[tokio::test]
    async fn local_raw_operator_recovery_intent_cannot_bypass_admin_authority() {
        let directory = tempfile::tempdir().expect("operator recovery spoof directory");
        let database = directory.path().join("local.sqlite");
        let backend =
            SqliteSessionBackend::open(&database).expect("operator recovery spoof backend");
        let store = ConsensusSessionStore::open(
            singleton_topology(),
            backend,
            directory.path().join("local-snapshots"),
            BTreeMap::new(),
        )
        .await
        .expect("open operator recovery spoof store");
        store
            .initialize_cluster()
            .await
            .expect("initialize operator recovery spoof store");

        let before_log = store.inner.raft.metrics().borrow().last_log_index;
        assert_eq!(
            durable_recovery_epoch(&database, store.inner.storage_identity),
            0
        );
        let result = store
            .submit_intent(forged_operator_recovery_intent(0xA1))
            .await;
        assert!(matches!(
            result,
            Err(StoreError::CapabilityNotSupported(reason))
                if reason == "operator_recovery_requires_local_admin_authority"
        ));
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            before_log,
            "rejected local recovery forgery reached the Raft log"
        );
        assert_eq!(
            durable_recovery_epoch(&database, store.inner.storage_identity),
            0,
            "rejected local recovery forgery advanced the durable epoch"
        );
    }

    #[tokio::test]
    async fn forwarded_raw_operator_recovery_intent_cannot_spoof_admin_authority() {
        let directory = tempfile::tempdir().expect("forwarded recovery spoof directory");
        let database = directory.path().join("forwarded.sqlite");
        let backend =
            SqliteSessionBackend::open(&database).expect("forwarded recovery spoof backend");
        let store = ConsensusSessionStore::open(
            singleton_topology(),
            backend,
            directory.path().join("forwarded-snapshots"),
            BTreeMap::new(),
        )
        .await
        .expect("open forwarded recovery spoof store");
        store
            .initialize_cluster()
            .await
            .expect("initialize forwarded recovery spoof store");

        let before_log = store.inner.raft.metrics().borrow().last_log_index;
        assert_eq!(
            durable_recovery_epoch(&database, store.inner.storage_identity),
            0
        );
        let payload = encode_bounded(&ForwardRequest::Mutation(ForwardMutationRequest {
            request_id: SessionConsensusRequestId::new(),
            intent: forged_operator_recovery_intent(0xB2),
        }))
        .expect("encode forged forwarded recovery request");
        let request = SessionConsensusWireRequest::try_new(
            store.inner.storage_identity,
            store.inner.local_node_id,
            SessionConsensusRpcFamily::ForwardMutation,
            payload,
        )
        .expect("bind forged request to an authenticated current member");
        let response = store
            .rpc_handler()
            .handle(store.inner.local_node_id, request)
            .await;
        response.validate().expect("valid rejection response");
        let payload = response.result.expect("encoded forwarded rejection");
        let reply: ForwardMutationReply =
            decode_bounded(&payload).expect("decode forwarded rejection");
        assert!(matches!(
            reply,
            ForwardMutationReply::Applied(response)
                if matches!(
                    &response.result,
                    Err(StoreError::CapabilityNotSupported(reason))
                        if reason == "operator_recovery_requires_local_admin_authority"
                )
                    && response.sequence == 0
                    && response.digest.is_none()
                    && response.logical_time.is_none()
                    && response.raft_log_index == 0
        ));
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            before_log,
            "rejected forwarded recovery forgery reached the Raft log"
        );
        assert_eq!(
            durable_recovery_epoch(&database, store.inner.storage_identity),
            0,
            "rejected forwarded recovery forgery advanced the durable epoch"
        );
    }

    #[tokio::test]
    async fn committed_expiry_floor_is_idempotent_and_survives_leader_clock_rollback() {
        let directory = tempfile::tempdir().expect("expiry floor directory");
        let backend = SqliteSessionBackend::open(directory.path().join("store.sqlite"))
            .expect("expiry floor SQLite backend");
        let start = Timestamp::from_offset_datetime(
            time::OffsetDateTime::from_unix_timestamp(1_900_000_000).expect("test timestamp"),
        );
        let clock = Arc::new(MutableClock::new(start));
        let store = ConsensusSessionStore::open_with_clock(
            singleton_topology(),
            backend,
            directory.path().join("snapshots"),
            BTreeMap::new(),
            clock.clone(),
            Duration::from_secs(1),
        )
        .await
        .expect("open expiry floor store");
        store
            .initialize_cluster()
            .await
            .expect("initialize expiry floor store");
        let key = SessionKey {
            tenant: TenantId::new("expiry-floor").expect("tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"expiry-floor")
                .try_into()
                .expect("stable ID"),
        };
        let maximum =
            checked_session_deadline(start, crate::MAX_SESSION_TTL).expect("maximum expiry");
        let mut record = StoredSessionRecord {
            key,
            generation: Generation::new(1),
            owner: OwnerId::new("expiry-floor-owner").expect("owner"),
            fence: FenceToken::new(1),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("expiry-floor"),
            expires_at: Some(maximum),
            payload: EncryptedSessionPayload::new(b"payload-free-preflight"),
        };
        let descriptor = RecordExpiryPreflight::from_record(&record);

        store
            .preflight_record_expiry(&[descriptor])
            .await
            .expect("commit first authority floor");
        let first_log = store.inner.raft.metrics().borrow().last_log_index;
        clock.set(Timestamp::from_offset_datetime(
            start
                .as_offset_datetime()
                .checked_sub(time::Duration::days(1))
                .expect("clock rollback"),
        ));
        store
            .preflight_record_expiry(&[descriptor])
            .await
            .expect("persisted floor covers repeated preflight");
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            first_log,
            "nested wrapper preflights must not append another floor"
        );

        record.expires_at = Some(Timestamp::from_offset_datetime(
            maximum
                .as_offset_datetime()
                .checked_add(time::Duration::nanoseconds(1))
                .expect("maximum plus one"),
        ));
        let invalid = RecordExpiryPreflight::from_record(&record);
        assert_eq!(
            store.preflight_record_expiry(&[invalid]).await,
            Err(StoreError::InvalidRecordExpiry)
        );
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            first_log
        );

        let response = store
            .submit_intent(SessionMutationIntent::AdvanceLogicalTime)
            .await
            .expect("command after clock rollback");
        assert_eq!(response.logical_time, Some(start));
    }

    #[tokio::test]
    async fn watch_exposes_only_state_machine_applied_application_entries() {
        let directory = tempfile::tempdir().expect("watch commit gate directory");
        let backend = SqliteSessionBackend::open(directory.path().join("store.sqlite"))
            .expect("watch commit gate SQLite backend");
        let apply_gate = Arc::clone(&backend.consensus_apply_gate);
        let store = ConsensusSessionStore::open_with_clock(
            singleton_topology(),
            backend,
            directory.path().join("snapshots"),
            BTreeMap::new(),
            Arc::new(SystemClock),
            Duration::from_secs(1),
        )
        .await
        .expect("open watch commit gate store");
        store
            .initialize_cluster()
            .await
            .expect("initialize watch commit gate store");
        let mut watch = store.watch(1).await.expect("register applied watch");

        let held_apply = apply_gate
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
        let key = SessionKey {
            tenant: TenantId::new("watch-commit-gate").expect("tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"watch-commit-gate")
                .try_into()
                .expect("stable ID"),
        };
        let mutation_store = store.clone();
        let mutation = tokio::spawn(async move {
            mutation_store
                .acquire(
                    &key,
                    OwnerId::new("watch-commit-owner").expect("owner"),
                    Duration::from_secs(30),
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if store.inner.raft.metrics().borrow().last_log_index > Some(before) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("proposal reaches Openraft log");
        assert!(
            tokio::time::timeout(Duration::from_millis(40), watch.next())
                .await
                .is_err(),
            "log-only entries must not be visible before state-machine apply"
        );

        drop(held_apply);
        mutation
            .await
            .expect("acquire task")
            .expect("committed acquire");
        let applied = tokio::time::timeout(Duration::from_secs(1), watch.next())
            .await
            .expect("applied watch deadline")
            .expect("applied watch item")
            .expect("valid applied entry");
        assert_eq!(applied.sequence, 1);
        assert!(matches!(applied.op, ReplicationOp::AcquireLease { .. }));
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
        let wait_for_available = |store: ConsensusSessionStore,
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
        let wait_for_all_supervisors = |store: ConsensusSessionStore| async move {
            let permits = tokio::time::timeout(
                Duration::from_secs(1),
                Arc::clone(&store.inner.proposal_admission).acquire_many_owned(
                    u32::try_from(DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS)
                        .expect("proposal slot count fits u32"),
                ),
            )
            .await
            .expect("proposal supervisors release admission after apply")
            .expect("proposal admission remains open");
            drop(permits);
        };

        // Dropping the original caller after Openraft accepted its proposal
        // must not release its slot. Saturating the other seven slots proves a
        // disconnect flood cannot enqueue behind that supervised proposal.
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
        wait_for_available(
            store.clone(),
            DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS - 1,
            "first accepted proposal",
        )
        .await;
        cancelled.abort();
        let _ = cancelled.await;
        tokio::task::yield_now().await;
        assert_eq!(
            store.inner.proposal_admission.available_permits(),
            DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS - 1,
            "accepted proposal admission must outlive its cancelled caller"
        );

        let held_saturation = Arc::clone(&store.inner.proposal_admission)
            .acquire_many_owned(
                u32::try_from(DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS - 1)
                    .expect("remaining proposal slots fit u32"),
            )
            .await
            .expect("saturate remaining proposal admission");
        assert_eq!(store.inner.proposal_admission.available_permits(), 0);

        let rejected_overflow = (0..16)
            .map(|_| {
                let store = store.clone();
                tokio::spawn(async move {
                    store
                        .submit_intent(SessionMutationIntent::AdvanceLogicalTime)
                        .await
                })
            })
            .collect::<Vec<_>>();
        for attempt in rejected_overflow {
            assert!(matches!(
                attempt.await.expect("bounded overflow task"),
                Err(StoreError::BackendUnavailable(_))
            ));
        }
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            Some(before + 1),
            "saturated admission cannot append another Openraft proposal"
        );
        drop(held_saturation);
        assert_eq!(
            store.inner.proposal_admission.available_permits(),
            DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS - 1,
            "the cancelled accepted proposal still owns its slot"
        );
        drop(held_apply);
        wait_for_all_supervisors(store.clone()).await;

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
        assert_eq!(
            store.inner.proposal_admission.available_permits(),
            DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS - 1
        );
        drop(held_apply);
        wait_for_all_supervisors(store.clone()).await;

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
        assert_eq!(
            store.inner.proposal_admission.available_permits(),
            DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS - 1
        );
        drop(held_apply);
        wait_for_all_supervisors(store).await;
    }
}

#[cfg(test)]
mod encryption_tests;
