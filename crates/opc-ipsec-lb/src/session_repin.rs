//! Durable, forward-converging session-level re-pin coordination.
//!
//! A packet-core session resumes one IKE SA, one default-bearer ESP SA, and
//! optionally more dedicated-bearer ESP SAs. [`RePinCoordinator`] deliberately
//! coordinates one SA at a time. This module adds the durable ordered saga that
//! binds those exact requests into one operation and exposes success only after
//! every SA has crossed the ownership fence and completed steering.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;
use std::num::NonZeroU128;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use opc_session_store::{
    decode_json_payload, encode_json_payload, BackendCapabilities, CompareAndSet,
    CompareAndSetResult, EncryptedSessionPayload, Generation, LeaseError, LeaseGuard, OwnerId,
    SessionBackend, SessionKey, SessionKeyType, SessionLeaseManager, SessionPayloadEncoding,
    SessionPayloadFormat, SessionPayloadVersion, StableId, StateClass, StateType, StoreError,
    StoredSessionRecord,
};
use opc_types::{NetworkFunctionKind, TenantId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::IpsecLbError;
use crate::failover::{AntiReplayResume, SendIvCounterMode, SendIvForwardJump};
use crate::model::{ClusterNode, SaId, ShardId, SteerKey, SteeringRule};
use crate::ports::{OwnershipFencer, OwnershipSource, RePinAuditSink, SteeringBackend};
use crate::repin::{
    validate_request, IkeRandomIvAttestation, OwnershipFence, OwnershipTransitionId,
    RePinCoordinator, RePinError, RePinRequest, ResumeKeySource, SameSpiOutboundIvResume,
    SameSpiResume,
};

/// Minimum canonical session batch: one IKE SA plus one default ESP SA.
pub const MIN_SESSION_REPIN_SAS: usize = 2;

/// Maximum number of SAs admitted into one session re-pin saga.
///
/// The first entry is IKE, the second is the default ESP SA, and the remaining
/// 62 entries are available for dedicated-bearer ESP SAs. This fixed bound
/// limits validation, hashing, persistence decoding, and recovery work.
pub const MAX_SESSION_REPIN_SAS: usize = 64;

const SESSION_REPIN_KEY_TYPE: &str = "ipsec-lb-session-repin";
const SESSION_REPIN_PAYLOAD_FORMAT: &str = "openpacketcore/ipsec-lb/session-repin";
const SESSION_REPIN_PAYLOAD_VERSION: u16 = 1;
/// Maximum encoded durable checkpoint size admitted by the session saga.
///
/// This includes the SDK session-payload envelope as well as the complete exact
/// request set. Backends may advertise a smaller limit, which is enforced too.
pub const SESSION_REPIN_JOURNAL_MAX_BYTES: usize = 256 * 1024;
const SESSION_REPIN_LEASE_TTL: Duration = Duration::from_secs(10);
const SESSION_REPIN_RELEASE_TIMEOUT: Duration = Duration::from_secs(1);
const SESSION_REPIN_MAX_CAS_ATTEMPTS: usize = 16;

/// Privacy-preserving identity of the session whose complete SA set is moving.
///
/// Construct the underlying [`StableId`] with a tenant-specific keyed digest;
/// do not supply a raw subscriber identity. Formatting never reveals its bytes.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionRePinSessionId(StableId);

impl SessionRePinSessionId {
    /// Bind a session re-pin to an already validated privacy-preserving stable ID.
    #[must_use]
    pub const fn from_stable_id(value: StableId) -> Self {
        Self(value)
    }

    /// Borrow the stable ID for session-store key construction.
    #[must_use]
    pub const fn as_stable_id(&self) -> &StableId {
        &self.0
    }
}

impl fmt::Debug for SessionRePinSessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionRePinSessionId([redacted])")
    }
}

/// Deployment-unique identity of one complete session re-pin operation.
///
/// Replaying the same operation retains this value. A later failover, including
/// an ABA return to an earlier owner, uses a fresh value.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionRePinOperationId(NonZeroU128);

impl SessionRePinOperationId {
    /// Validate and construct a non-zero operation identity.
    pub fn new(value: u128) -> Result<Self, IpsecLbError> {
        NonZeroU128::new(value).map(Self).ok_or_else(|| {
            IpsecLbError::invalid_config(
                "session_repin.operation_id",
                "session re-pin operation ID must be non-zero",
            )
        })
    }

    /// Return the numeric value for durable encoding and explicit correlation.
    #[must_use]
    pub const fn get(self) -> u128 {
        self.0.get()
    }
}

impl fmt::Debug for SessionRePinOperationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionRePinOperationId([redacted])")
    }
}

/// Collision-resistant binding of a session operation to its ordered requests.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionRePinPlanFingerprint([u8; 32]);

impl SessionRePinPlanFingerprint {
    /// Restore an opaque fingerprint retained by a durable caller.
    ///
    /// This does not confer journal authority: successor, resume, and status
    /// still compare it with the exact retained checkpoint.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return the fingerprint bytes for durable adapters.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for SessionRePinPlanFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionRePinPlanFingerprint([redacted])")
    }
}

/// Exact, redaction-safe correlation identity for one durable session saga.
///
/// An operation ID by itself is not sufficient after a successor replaces a
/// terminal checkpoint. This token also binds the complete ordered plan
/// fingerprint, so stale resume and status callers fail closed even if an
/// operation ID is accidentally reused. Formatting never reveals either
/// component.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionRePinIdentity {
    operation_id: SessionRePinOperationId,
    fingerprint: SessionRePinPlanFingerprint,
}

impl SessionRePinIdentity {
    /// Build an exact identity from previously retained typed components.
    #[must_use]
    pub const fn new(
        operation_id: SessionRePinOperationId,
        fingerprint: SessionRePinPlanFingerprint,
    ) -> Self {
        Self {
            operation_id,
            fingerprint,
        }
    }

    /// Return the operation ID retained across retries of this exact plan.
    #[must_use]
    pub const fn operation_id(self) -> SessionRePinOperationId {
        self.operation_id
    }

    /// Return the whole-plan fingerprint retained across exact retries.
    #[must_use]
    pub const fn fingerprint(self) -> SessionRePinPlanFingerprint {
        self.fingerprint
    }
}

impl fmt::Debug for SessionRePinIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionRePinIdentity([redacted])")
    }
}

/// Complete, canonical, ordered SA set for one session-level re-pin.
///
/// Entry zero is the IKE SA. Entry one is the default-bearer ESP SA. Remaining
/// entries are dedicated-bearer ESP SAs in caller-selected stable order. Every
/// request must name the same previous owner, new owner, source shard, and
/// destination shard; SAs and per-SA transition IDs must be unique. The first
/// operation has no predecessor; every later operation names the exact
/// fingerprint of the prior terminal plan so stale completions cannot replace
/// newer restart authority.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionRePinPlan {
    session_id: SessionRePinSessionId,
    operation_id: SessionRePinOperationId,
    predecessor: Option<SessionRePinPlanFingerprint>,
    requests: Vec<RePinRequest>,
    fingerprint: SessionRePinPlanFingerprint,
}

impl SessionRePinPlan {
    /// Validate and bind the first complete ordered session transition.
    ///
    /// Later operations for the same session must use [`Self::new_successor`]
    /// with the prior terminal fingerprint.
    pub fn new(
        session_id: SessionRePinSessionId,
        operation_id: SessionRePinOperationId,
        requests: Vec<RePinRequest>,
    ) -> Result<Self, IpsecLbError> {
        Self::build(session_id, operation_id, None, requests)
    }

    /// Validate and bind a later operation to its exact terminal predecessor.
    ///
    /// The predecessor is the fingerprint returned by the previous terminal
    /// plan for this session. This proof prevents a stale completed operation
    /// from replacing a newer terminal checkpoint.
    pub fn new_successor(
        session_id: SessionRePinSessionId,
        operation_id: SessionRePinOperationId,
        predecessor: SessionRePinPlanFingerprint,
        requests: Vec<RePinRequest>,
    ) -> Result<Self, IpsecLbError> {
        Self::build(session_id, operation_id, Some(predecessor), requests)
    }

    fn build(
        session_id: SessionRePinSessionId,
        operation_id: SessionRePinOperationId,
        predecessor: Option<SessionRePinPlanFingerprint>,
        requests: Vec<RePinRequest>,
    ) -> Result<Self, IpsecLbError> {
        validate_plan_requests(&requests)?;
        let fingerprint = fingerprint_plan(&session_id, operation_id, predecessor, &requests);
        Ok(Self {
            session_id,
            operation_id,
            predecessor,
            requests,
            fingerprint,
        })
    }

    /// Return the privacy-preserving session identity.
    #[must_use]
    pub const fn session_id(&self) -> &SessionRePinSessionId {
        &self.session_id
    }

    /// Return the operation identity retained across every retry.
    #[must_use]
    pub const fn operation_id(&self) -> SessionRePinOperationId {
        self.operation_id
    }

    /// Return the exact terminal plan this later operation must succeed.
    ///
    /// Initial operations return `None`.
    #[must_use]
    pub const fn predecessor(&self) -> Option<SessionRePinPlanFingerprint> {
        self.predecessor
    }

    /// Return the complete canonical plan fingerprint.
    #[must_use]
    pub const fn fingerprint(&self) -> SessionRePinPlanFingerprint {
        self.fingerprint
    }

    /// Return the exact token required for restart resume and status reads.
    #[must_use]
    pub const fn identity(&self) -> SessionRePinIdentity {
        SessionRePinIdentity::new(self.operation_id, self.fingerprint)
    }

    /// Borrow every exact request in canonical recovery order.
    #[must_use]
    pub fn requests(&self) -> &[RePinRequest] {
        &self.requests
    }

    /// Return the number of SAs bound into this operation.
    #[must_use]
    pub fn len(&self) -> usize {
        self.requests.len()
    }

    /// Return whether the plan contains no SAs.
    ///
    /// Constructed plans are never empty; this method accompanies [`Self::len`]
    /// for conventional collection-like inspection.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    fn new_owner(&self) -> &ClusterNode {
        &self.requests[0].new_owner
    }
}

impl fmt::Debug for SessionRePinPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionRePinPlan")
            .field("session_id", &"[redacted]")
            .field("operation_id", &"[redacted]")
            .field("fingerprint", &"[redacted]")
            .field("sa_count", &self.requests.len())
            .finish()
    }
}

fn validate_plan_requests(requests: &[RePinRequest]) -> Result<(), IpsecLbError> {
    if !(MIN_SESSION_REPIN_SAS..=MAX_SESSION_REPIN_SAS).contains(&requests.len()) {
        return Err(IpsecLbError::invalid_config(
            "session_repin.requests",
            "session re-pin requires 2 to 64 ordered SAs",
        ));
    }
    if !matches!(requests[0].sa, SaId::Ike { .. }) {
        return Err(IpsecLbError::invalid_config(
            "session_repin.requests",
            "the first session re-pin request must be the IKE SA",
        ));
    }
    if requests[1..]
        .iter()
        .any(|request| !matches!(request.sa, SaId::Esp { .. }))
    {
        return Err(IpsecLbError::invalid_config(
            "session_repin.requests",
            "the default and dedicated bearer requests must be ESP SAs",
        ));
    }

    let first = &requests[0];
    validate_owner(&first.previous_owner)?;
    validate_owner(&first.new_owner)?;
    let mut sas = BTreeSet::new();
    let mut transitions = BTreeSet::new();
    for request in requests {
        validate_request(request)?;
        request.resume.validate_for_repin(request.sa)?;
        validate_owner(&request.previous_owner)?;
        validate_owner(&request.new_owner)?;
        if request.previous_owner != first.previous_owner
            || request.new_owner != first.new_owner
            || request.rule.shard != first.rule.shard
            || request.rule.owner != first.rule.owner
        {
            return Err(IpsecLbError::invalid_config(
                "session_repin.requests",
                "every request must bind the same owners and steering shards",
            ));
        }
        if !sas.insert(request.sa) {
            return Err(IpsecLbError::invalid_config(
                "session_repin.requests",
                "session re-pin contains a duplicate SA",
            ));
        }
        if !transitions.insert(request.transition_id) {
            return Err(IpsecLbError::invalid_config(
                "session_repin.requests",
                "session re-pin contains a duplicate SA transition ID",
            ));
        }
    }
    Ok(())
}

fn validate_owner(owner: &ClusterNode) -> Result<(), IpsecLbError> {
    OwnerId::new(owner.as_str()).map(|_| ()).map_err(|_| {
        IpsecLbError::invalid_config(
            "session_repin.owner",
            "session re-pin owner must be a bounded non-empty identity",
        )
    })
}

fn fingerprint_plan(
    session_id: &SessionRePinSessionId,
    operation_id: SessionRePinOperationId,
    predecessor: Option<SessionRePinPlanFingerprint>,
    requests: &[RePinRequest],
) -> SessionRePinPlanFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(b"opc-ipsec-lb/session-repin-plan/v1");
    hash_len_prefixed(&mut hasher, session_id.as_stable_id().as_bytes());
    hasher.update(operation_id.get().to_be_bytes());
    match predecessor {
        Some(fingerprint) => {
            hasher.update([1]);
            hasher.update(fingerprint.as_bytes());
        }
        None => hasher.update([0]),
    }
    hasher.update((requests.len() as u64).to_be_bytes());
    for request in requests {
        hasher.update(request.ownership_fingerprint().as_bytes());
    }
    SessionRePinPlanFingerprint(hasher.finalize().into())
}

fn hash_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

/// Durable per-SA progress for one exact session re-pin plan.
///
/// Completed fences form an ordered prefix. `current_fence` means the next SA
/// crossed its ownership fence but its steering/audit completion is not yet
/// durably recorded. The complete request set remains retained in `plan` for
/// exact replay after restart.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionRePinCheckpoint {
    plan: SessionRePinPlan,
    completed_fences: Vec<OwnershipFence>,
    current_fence: Option<OwnershipFence>,
}

impl SessionRePinCheckpoint {
    fn from_progress(
        plan: SessionRePinPlan,
        completed_fences: Vec<OwnershipFence>,
        current_fence: Option<OwnershipFence>,
    ) -> Result<Self, IpsecLbError> {
        if completed_fences.len() > plan.len()
            || (completed_fences.len() == plan.len() && current_fence.is_some())
        {
            return Err(IpsecLbError::invalid_config(
                "session_repin.checkpoint",
                "session re-pin checkpoint progress is inconsistent",
            ));
        }
        Ok(Self {
            plan,
            completed_fences,
            current_fence,
        })
    }

    /// Borrow the exact retained plan.
    #[must_use]
    pub const fn plan(&self) -> &SessionRePinPlan {
        &self.plan
    }

    /// Return how many SAs have durably completed ownership and steering.
    #[must_use]
    pub fn completed_sa_count(&self) -> usize {
        self.completed_fences.len()
    }

    /// Return the durable completed fence at one ordered position.
    #[must_use]
    pub fn completed_fence(&self, index: usize) -> Option<OwnershipFence> {
        self.completed_fences.get(index).copied()
    }

    /// Return the retained fence for the current forward-convergence position.
    #[must_use]
    pub const fn current_fence(&self) -> Option<OwnershipFence> {
        self.current_fence
    }

    /// Return a redaction-safe progress projection.
    #[must_use]
    pub fn status(&self) -> SessionRePinStatus {
        SessionRePinStatus::new(
            self.plan.len(),
            self.completed_fences.len(),
            self.current_fence.is_some(),
        )
    }

    fn is_complete(&self) -> bool {
        self.completed_fences.len() == self.plan.len()
    }

    fn with_ownership_commit(
        &self,
        index: usize,
        fence: OwnershipFence,
    ) -> Result<Self, IpsecLbError> {
        if index < self.completed_fences.len() {
            return if self.completed_fences[index] == fence {
                Ok(self.clone())
            } else {
                Err(progress_conflict())
            };
        }
        if index != self.completed_fences.len() || self.is_complete() {
            return Err(progress_conflict());
        }
        if let Some(current) = self.current_fence {
            return if current == fence {
                Ok(self.clone())
            } else {
                Err(progress_conflict())
            };
        }
        Self::from_progress(
            self.plan.clone(),
            self.completed_fences.clone(),
            Some(fence),
        )
    }

    fn with_sa_complete(&self, index: usize, fence: OwnershipFence) -> Result<Self, IpsecLbError> {
        if index < self.completed_fences.len() {
            return if self.completed_fences[index] == fence {
                Ok(self.clone())
            } else {
                Err(progress_conflict())
            };
        }
        if index != self.completed_fences.len() || self.current_fence != Some(fence) {
            return Err(progress_conflict());
        }
        let mut completed_fences = self.completed_fences.clone();
        completed_fences.push(fence);
        Self::from_progress(self.plan.clone(), completed_fences, None)
    }
}

impl fmt::Debug for SessionRePinCheckpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionRePinCheckpoint")
            .field("status", &self.status())
            .finish()
    }
}

fn progress_conflict() -> IpsecLbError {
    IpsecLbError::ownership_conflict(
        "session re-pin journal progress conflicts with this operation",
    )
}

fn validate_plan_succession(
    existing: Option<&SessionRePinCheckpoint>,
    next: &SessionRePinPlan,
) -> Result<(), IpsecLbError> {
    match existing {
        Some(checkpoint)
            if checkpoint.is_complete()
                && next.predecessor() == Some(checkpoint.plan().fingerprint()) =>
        {
            validate_successor_freshness(checkpoint.plan(), next)
        }
        None if next.predecessor().is_none() => Ok(()),
        Some(_) | None => Err(progress_conflict()),
    }
}

fn validate_successor_freshness(
    predecessor: &SessionRePinPlan,
    successor: &SessionRePinPlan,
) -> Result<(), IpsecLbError> {
    if predecessor.operation_id() == successor.operation_id() {
        return Err(progress_conflict());
    }
    let predecessor_transitions = predecessor
        .requests()
        .iter()
        .map(|request| request.transition_id)
        .collect::<BTreeSet<_>>();
    if successor
        .requests()
        .iter()
        .any(|request| predecessor_transitions.contains(&request.transition_id))
    {
        return Err(progress_conflict());
    }
    Ok(())
}

/// Redaction-safe phase of a session-level re-pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionRePinPhase {
    /// The exact plan is durable but no SA ownership commit is retained.
    Prepared,
    /// At least one SA committed, so recovery must converge forward.
    ConvergingForward,
    /// Every SA durably completed ownership fencing and steering.
    Complete,
}

/// Redaction-safe session saga status.
///
/// It intentionally contains counts and a phase only. It never carries session
/// IDs, owners, SAs, SPIs, counters, fences, rules, keys, or peer addresses.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionRePinStatus {
    phase: SessionRePinPhase,
    total_sa_count: usize,
    completed_sa_count: usize,
    current_ownership_committed: bool,
}

impl SessionRePinStatus {
    const fn new(
        total_sa_count: usize,
        completed_sa_count: usize,
        current_ownership_committed: bool,
    ) -> Self {
        let phase = if completed_sa_count == total_sa_count {
            SessionRePinPhase::Complete
        } else if completed_sa_count > 0 || current_ownership_committed {
            SessionRePinPhase::ConvergingForward
        } else {
            SessionRePinPhase::Prepared
        };
        Self {
            phase,
            total_sa_count,
            completed_sa_count,
            current_ownership_committed,
        }
    }

    /// Return the current fail-closed phase.
    #[must_use]
    pub const fn phase(self) -> SessionRePinPhase {
        self.phase
    }

    /// Return the fixed number of SAs in the retained plan.
    #[must_use]
    pub const fn total_sa_count(self) -> usize {
        self.total_sa_count
    }

    /// Return how many ordered SAs durably completed.
    #[must_use]
    pub const fn completed_sa_count(self) -> usize {
        self.completed_sa_count
    }

    /// Whether the current incomplete SA has a retained ownership commit.
    #[must_use]
    pub const fn current_ownership_committed(self) -> bool {
        self.current_ownership_committed
    }
}

impl fmt::Debug for SessionRePinStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionRePinStatus")
            .field("phase", &self.phase)
            .field("total_sa_count", &self.total_sa_count)
            .field("completed_sa_count", &self.completed_sa_count)
            .field(
                "current_ownership_committed",
                &self.current_ownership_committed,
            )
            .finish()
    }
}

/// Durable journal port for session-level re-pin progress.
///
/// Checkpoint construction is SDK-private: external code may wrap/delegate an
/// SDK journal, but cannot mint completed progress and bypass fencing or
/// steering. The production implementation is [`SessionStoreRePinJournal`]
/// and deterministic tests can use [`MockSessionRePinJournal`].
///
/// Implementations must linearize one active plan per session identity. An
/// identical call is idempotent. A different plan may replace a completed plan,
/// only when [`SessionRePinPlan::predecessor`] names that exact terminal plan;
/// its operation ID and all transition IDs must be fresh relative to that
/// predecessor. Rejection must preserve the terminal checkpoint. It must
/// conflict with a prepared, forward-converging, unbound, or stale plan.
/// Progress can advance only in order and may never discard a retained
/// ownership commit.
#[async_trait]
pub trait SessionRePinJournal: Send + Sync + fmt::Debug {
    /// Create the exact plan or load its existing durable progress.
    async fn begin(&self, plan: &SessionRePinPlan) -> Result<SessionRePinCheckpoint, IpsecLbError>;

    /// Load the active or most recently completed plan for a session.
    async fn load(
        &self,
        session_id: &SessionRePinSessionId,
    ) -> Result<Option<SessionRePinCheckpoint>, IpsecLbError>;

    /// Retain the authoritative fence before reporting a post-commit failure.
    async fn record_ownership_committed(
        &self,
        plan: &SessionRePinPlan,
        index: usize,
        fence: OwnershipFence,
    ) -> Result<SessionRePinCheckpoint, IpsecLbError>;

    /// Record that steering and its final audit completed for one SA.
    async fn record_sa_complete(
        &self,
        plan: &SessionRePinPlan,
        index: usize,
        fence: OwnershipFence,
    ) -> Result<SessionRePinCheckpoint, IpsecLbError>;
}

/// Deterministic in-memory journal for unit tests and non-durable examples.
#[derive(Clone, Default)]
pub struct MockSessionRePinJournal {
    state: Arc<Mutex<MockJournalState>>,
}

#[derive(Default)]
struct MockJournalState {
    checkpoints: BTreeMap<SessionRePinSessionId, SessionRePinCheckpoint>,
    failure: Option<IpsecLbError>,
}

impl fmt::Debug for MockSessionRePinJournal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MockSessionRePinJournal")
            .finish_non_exhaustive()
    }
}

impl MockSessionRePinJournal {
    /// Inject a redaction-safe journal failure.
    pub fn set_failure(&self, failure: IpsecLbError) {
        let mut state = lock_unpoisoned(&self.state);
        state.failure = Some(failure);
    }

    /// Clear an injected journal failure.
    pub fn clear_failure(&self) {
        let mut state = lock_unpoisoned(&self.state);
        state.failure = None;
    }

    fn mutate(
        &self,
        plan: &SessionRePinPlan,
        mutate: impl FnOnce(&SessionRePinCheckpoint) -> Result<SessionRePinCheckpoint, IpsecLbError>,
    ) -> Result<SessionRePinCheckpoint, IpsecLbError> {
        let mut state = lock_unpoisoned(&self.state);
        if let Some(error) = &state.failure {
            return Err(error.clone());
        }
        let checkpoint = state
            .checkpoints
            .get(plan.session_id())
            .ok_or(IpsecLbError::NotFound)?;
        if checkpoint.plan() != plan {
            return Err(progress_conflict());
        }
        let next = mutate(checkpoint)?;
        state
            .checkpoints
            .insert(plan.session_id().clone(), next.clone());
        Ok(next)
    }
}

#[async_trait]
impl SessionRePinJournal for MockSessionRePinJournal {
    async fn begin(&self, plan: &SessionRePinPlan) -> Result<SessionRePinCheckpoint, IpsecLbError> {
        let mut state = lock_unpoisoned(&self.state);
        if let Some(error) = &state.failure {
            return Err(error.clone());
        }
        if let Some(existing) = state.checkpoints.get(plan.session_id()) {
            if existing.plan() == plan {
                return Ok(existing.clone());
            }
        }
        validate_plan_succession(state.checkpoints.get(plan.session_id()), plan)?;
        let checkpoint = SessionRePinCheckpoint::from_progress(plan.clone(), Vec::new(), None)?;
        state
            .checkpoints
            .insert(plan.session_id().clone(), checkpoint.clone());
        Ok(checkpoint)
    }

    async fn load(
        &self,
        session_id: &SessionRePinSessionId,
    ) -> Result<Option<SessionRePinCheckpoint>, IpsecLbError> {
        let state = lock_unpoisoned(&self.state);
        if let Some(error) = &state.failure {
            return Err(error.clone());
        }
        Ok(state.checkpoints.get(session_id).cloned())
    }

    async fn record_ownership_committed(
        &self,
        plan: &SessionRePinPlan,
        index: usize,
        fence: OwnershipFence,
    ) -> Result<SessionRePinCheckpoint, IpsecLbError> {
        self.mutate(plan, |checkpoint| {
            checkpoint.with_ownership_commit(index, fence)
        })
    }

    async fn record_sa_complete(
        &self,
        plan: &SessionRePinPlan,
        index: usize,
        fence: OwnershipFence,
    ) -> Result<SessionRePinCheckpoint, IpsecLbError> {
        self.mutate(plan, |checkpoint| checkpoint.with_sa_complete(index, fence))
    }
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Successful session transition with one proven all-SAs convergence point.
///
/// Success proves that the completed prefix passed phase-two validation at one
/// linearization point during this `start` or `resume` invocation. It is not an
/// ownership or steering lease and does not guarantee that the state remains
/// current when the future returns or afterward. A later supported transition
/// may advance a validated fence. Consumers must serialize subsequent
/// transitions and use current fenced authority at the action boundary.
pub struct SessionRePinOutcome {
    checkpoint: SessionRePinCheckpoint,
}

impl SessionRePinOutcome {
    /// Return the redaction-safe terminal durable-journal status.
    ///
    /// This reports retained journal progress, not current live convergence.
    #[must_use]
    pub fn status(&self) -> SessionRePinStatus {
        self.checkpoint.status()
    }

    /// Borrow the exact plan that reached terminal success.
    #[must_use]
    pub const fn plan(&self) -> &SessionRePinPlan {
        self.checkpoint.plan()
    }

    /// Return the exact token for a later status read or idempotent resume.
    #[must_use]
    pub const fn identity(&self) -> SessionRePinIdentity {
        self.checkpoint.plan().identity()
    }

    /// Return the committed fence for an ordered SA position.
    #[must_use]
    pub fn fence(&self, index: usize) -> Option<OwnershipFence> {
        self.checkpoint.completed_fence(index)
    }
}

impl fmt::Debug for SessionRePinOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionRePinOutcome")
            .field("status", &self.status())
            .finish()
    }
}

/// Failure returned by session-level re-pin coordination.
#[derive(Debug, thiserror::Error)]
pub enum SessionRePinError {
    /// The durable journal could not establish or load an exact plan.
    #[error("session re-pin journal is unavailable or conflicting")]
    Journal(#[source] IpsecLbError),
    /// No SA ownership commit is retained; the session remains quarantined.
    #[error("session re-pin is quarantined before any ownership commit")]
    Quarantined {
        /// Redaction-safe progress at failure.
        status: SessionRePinStatus,
        /// Underlying redaction-safe port failure.
        #[source]
        cause: IpsecLbError,
    },
    /// At least one SA may have committed; only exact forward recovery is safe.
    #[error("session re-pin requires forward convergence")]
    ForwardConvergenceRequired {
        /// Redaction-safe progress at failure.
        status: SessionRePinStatus,
        /// Underlying redaction-safe port or journal failure.
        #[source]
        cause: IpsecLbError,
    },
}

impl SessionRePinError {
    /// Return a stable redaction-safe machine-readable failure code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Journal(_) => "session_repin_journal",
            Self::Quarantined { .. } => "session_repin_quarantined_before_commit",
            Self::ForwardConvergenceRequired { .. } => "session_repin_forward_convergence_required",
        }
    }

    /// Return the underlying redaction-safe failure.
    #[must_use]
    pub const fn cause(&self) -> &IpsecLbError {
        match self {
            Self::Journal(cause)
            | Self::Quarantined { cause, .. }
            | Self::ForwardConvergenceRequired { cause, .. } => cause,
        }
    }

    /// Return progress when the exact plan was durably established.
    #[must_use]
    pub const fn status(&self) -> Option<SessionRePinStatus> {
        match self {
            Self::Journal(_) => None,
            Self::Quarantined { status, .. } | Self::ForwardConvergenceRequired { status, .. } => {
                Some(*status)
            }
        }
    }
}

/// Coordinates a durable ordered session saga over the existing single-SA
/// [`RePinCoordinator`].
#[derive(Debug, Clone)]
pub struct SessionRePinCoordinator<B, F, O, A, J> {
    repin: RePinCoordinator<B, F, O, A>,
    journal: J,
}

impl<B, F, O, A, J> SessionRePinCoordinator<B, F, O, A, J>
where
    B: SteeringBackend,
    F: OwnershipFencer,
    O: OwnershipSource,
    A: RePinAuditSink,
    J: SessionRePinJournal,
{
    /// Compose a single-SA coordinator with one durable journal authority.
    #[must_use]
    pub const fn new(repin: RePinCoordinator<B, F, O, A>, journal: J) -> Self {
        Self { repin, journal }
    }

    /// Persist a complete plan, or recover its existing progress, then advance it.
    pub async fn start(
        &self,
        plan: SessionRePinPlan,
    ) -> Result<SessionRePinOutcome, SessionRePinError> {
        let checkpoint = self
            .journal
            .begin(&plan)
            .await
            .map_err(SessionRePinError::Journal)?;
        validate_exact_checkpoint(&checkpoint, &plan).map_err(SessionRePinError::Journal)?;
        self.drive(checkpoint).await
    }

    /// Resume the exact durable plan after consumer or process restart.
    ///
    /// The identity must match both the retained operation ID and complete
    /// plan fingerprint. An operation ID alone is deliberately insufficient.
    pub async fn resume(
        &self,
        session_id: &SessionRePinSessionId,
        identity: SessionRePinIdentity,
    ) -> Result<SessionRePinOutcome, SessionRePinError> {
        let checkpoint = self
            .journal
            .load(session_id)
            .await
            .map_err(SessionRePinError::Journal)?
            .ok_or(SessionRePinError::Journal(IpsecLbError::NotFound))?;
        if checkpoint.plan().identity() != identity {
            return Err(SessionRePinError::Journal(progress_conflict()));
        }
        self.drive(checkpoint).await
    }

    /// Read redaction-safe durable journal progress without performing a mutation.
    ///
    /// The identity must match both the retained operation ID and complete
    /// plan fingerprint. A stale predecessor cannot observe its successor.
    /// This read does not rerun convergence validation and is not live
    /// ownership or steering authority.
    pub async fn status(
        &self,
        session_id: &SessionRePinSessionId,
        identity: SessionRePinIdentity,
    ) -> Result<Option<SessionRePinStatus>, SessionRePinError> {
        let checkpoint = self
            .journal
            .load(session_id)
            .await
            .map_err(SessionRePinError::Journal)?;
        match checkpoint {
            Some(value) if value.plan().identity() == identity => Ok(Some(value.status())),
            Some(_) => Err(SessionRePinError::Journal(progress_conflict())),
            None => Ok(None),
        }
    }

    async fn drive(
        &self,
        mut checkpoint: SessionRePinCheckpoint,
    ) -> Result<SessionRePinOutcome, SessionRePinError> {
        let plan = checkpoint.plan().clone();
        validate_exact_checkpoint(&checkpoint, &plan).map_err(SessionRePinError::Journal)?;
        loop {
            self.reconcile_completed_prefix(&plan, &checkpoint).await?;
            if checkpoint.is_complete() {
                return Ok(SessionRePinOutcome { checkpoint });
            }
            let index = checkpoint.completed_sa_count();
            let request = plan.requests()[index].clone();
            match self.repin.repin(request).await {
                Ok(outcome) => {
                    let fence = outcome.fence();
                    if checkpoint
                        .current_fence()
                        .is_some_and(|current| current != fence)
                    {
                        return Err(SessionRePinError::ForwardConvergenceRequired {
                            status: checkpoint.status(),
                            cause: progress_conflict(),
                        });
                    }
                    checkpoint = match self
                        .journal
                        .record_ownership_committed(&plan, index, fence)
                        .await
                    {
                        Ok(updated) => updated,
                        Err(cause) => {
                            return Err(SessionRePinError::ForwardConvergenceRequired {
                                status: known_committed_status(&checkpoint),
                                cause,
                            });
                        }
                    };
                    validate_exact_checkpoint(&checkpoint, &plan).map_err(|cause| {
                        SessionRePinError::ForwardConvergenceRequired {
                            status: known_committed_status(&checkpoint),
                            cause,
                        }
                    })?;
                    checkpoint = match self.journal.record_sa_complete(&plan, index, fence).await {
                        Ok(updated) => updated,
                        Err(cause) => {
                            return Err(SessionRePinError::ForwardConvergenceRequired {
                                status: checkpoint.status(),
                                cause,
                            });
                        }
                    };
                    validate_exact_checkpoint(&checkpoint, &plan).map_err(|cause| {
                        SessionRePinError::ForwardConvergenceRequired {
                            status: checkpoint.status(),
                            cause,
                        }
                    })?;
                }
                Err(RePinError::BeforeOwnershipCommit(cause)) => {
                    return if checkpoint.completed_sa_count() == 0
                        && checkpoint.current_fence().is_none()
                    {
                        Err(SessionRePinError::Quarantined {
                            status: checkpoint.status(),
                            cause,
                        })
                    } else {
                        Err(SessionRePinError::ForwardConvergenceRequired {
                            status: checkpoint.status(),
                            cause,
                        })
                    };
                }
                Err(RePinError::AfterOwnershipCommit(partial)) => {
                    let fence = partial.fence();
                    if checkpoint
                        .current_fence()
                        .is_some_and(|current| current != fence)
                    {
                        return Err(SessionRePinError::ForwardConvergenceRequired {
                            status: checkpoint.status(),
                            cause: progress_conflict(),
                        });
                    }
                    let interruption = partial.cause().clone();
                    checkpoint = match self
                        .journal
                        .record_ownership_committed(&plan, index, fence)
                        .await
                    {
                        Ok(updated) => updated,
                        Err(cause) => {
                            return Err(SessionRePinError::ForwardConvergenceRequired {
                                status: known_committed_status(&checkpoint),
                                cause,
                            });
                        }
                    };
                    validate_exact_checkpoint(&checkpoint, &plan).map_err(|cause| {
                        SessionRePinError::ForwardConvergenceRequired {
                            status: checkpoint.status(),
                            cause,
                        }
                    })?;
                    return Err(SessionRePinError::ForwardConvergenceRequired {
                        status: checkpoint.status(),
                        cause: interruption,
                    });
                }
            }
        }
    }

    async fn reconcile_completed_prefix(
        &self,
        plan: &SessionRePinPlan,
        checkpoint: &SessionRePinCheckpoint,
    ) -> Result<(), SessionRePinError> {
        // Phase one repairs every exact steering rule. Do not mix validation
        // and repair per entry: a supported direct per-SA transition can
        // advance an earlier monotonic fence while a later repair is awaited.
        for (index, request) in plan
            .requests()
            .iter()
            .take(checkpoint.completed_sa_count())
            .enumerate()
        {
            let fence = checkpoint.completed_fence(index).ok_or_else(|| {
                SessionRePinError::ForwardConvergenceRequired {
                    status: checkpoint.status(),
                    cause: progress_conflict(),
                }
            })?;
            self.repin
                .reconcile_committed(request, fence)
                .await
                .map_err(|cause| SessionRePinError::ForwardConvergenceRequired {
                    status: checkpoint.status(),
                    cause,
                })?;
        }

        // Phase two is a global mutation-free sweep that begins only after all
        // phase-one repairs complete. Because ownership fences advance
        // monotonically and cannot ABA back to the retained value, successful
        // exact reads across the whole prefix establish a valid linearization
        // point. No later SA mutation or terminal result escapes without it.
        for (index, request) in plan
            .requests()
            .iter()
            .take(checkpoint.completed_sa_count())
            .enumerate()
        {
            let fence = checkpoint.completed_fence(index).ok_or_else(|| {
                SessionRePinError::ForwardConvergenceRequired {
                    status: checkpoint.status(),
                    cause: progress_conflict(),
                }
            })?;
            self.repin
                .validate_committed(request, fence)
                .await
                .map_err(|cause| SessionRePinError::ForwardConvergenceRequired {
                    status: checkpoint.status(),
                    cause,
                })?;
        }
        Ok(())
    }
}

fn validate_exact_checkpoint(
    checkpoint: &SessionRePinCheckpoint,
    plan: &SessionRePinPlan,
) -> Result<(), IpsecLbError> {
    if checkpoint.plan() != plan
        || checkpoint.plan().fingerprint()
            != fingerprint_plan(
                plan.session_id(),
                plan.operation_id(),
                plan.predecessor(),
                plan.requests(),
            )
    {
        return Err(progress_conflict());
    }
    Ok(())
}

fn known_committed_status(checkpoint: &SessionRePinCheckpoint) -> SessionRePinStatus {
    SessionRePinStatus::new(
        checkpoint.plan().len(),
        checkpoint.completed_sa_count(),
        true,
    )
}

/// Durable session re-pin journal backed by fenced session-store CAS.
///
/// The record key is tenant/NF scoped and uses the plan's privacy-preserving
/// session ID. Production HA wiring must provide a majority-committed
/// `QuorumSessionStore` (or equivalent) wrapped by `EncryptingSessionBackend`;
/// the journal payload contains exact recovery inputs, including public SA and
/// counter metadata, but never key material. The encrypting wrapper seals those
/// inputs before persistence and returns plaintext only at this caller-facing
/// boundary.
#[derive(Clone)]
pub struct SessionStoreRePinJournal<B> {
    backend: Arc<B>,
    tenant: TenantId,
    nf_kind: NetworkFunctionKind,
    lease_ttl: Duration,
}

impl<B> fmt::Debug for SessionStoreRePinJournal<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionStoreRePinJournal")
            .field("lease_ttl", &self.lease_ttl)
            .finish_non_exhaustive()
    }
}

impl<B> SessionStoreRePinJournal<B>
where
    B: SessionBackend + SessionLeaseManager + 'static,
{
    /// Build a journal in one tenant and network-function namespace.
    #[must_use]
    pub fn new(backend: B, tenant: TenantId, nf_kind: NetworkFunctionKind) -> Self {
        Self {
            backend: Arc::new(backend),
            tenant,
            nf_kind,
            lease_ttl: SESSION_REPIN_LEASE_TTL,
        }
    }

    /// Fail closed unless the backend can retain the complete authority record.
    ///
    /// Consumers should call this during startup validation. Every journal
    /// read and write also repeats the check so a capability downgrade cannot
    /// turn a stale terminal record into a whole-session success result.
    pub async fn validate_authority(&self) -> Result<(), IpsecLbError> {
        let capabilities = self.backend.capabilities().await;
        if session_repin_authority_supported(capabilities) {
            Ok(())
        } else {
            Err(IpsecLbError::Unsupported)
        }
    }

    fn key(&self, session_id: &SessionRePinSessionId) -> Result<SessionKey, IpsecLbError> {
        let key_type = SessionKeyType::other(SESSION_REPIN_KEY_TYPE).map_err(|_| {
            IpsecLbError::invalid_config(
                "session_repin.key_type",
                "session re-pin key type is invalid",
            )
        })?;
        Ok(SessionKey {
            tenant: self.tenant.clone(),
            nf_kind: self.nf_kind.clone(),
            key_type,
            stable_id: session_id.as_stable_id().clone(),
        })
    }

    async fn read(
        &self,
        session_id: &SessionRePinSessionId,
    ) -> Result<Option<(StoredSessionRecord, SessionRePinCheckpoint)>, IpsecLbError> {
        self.validate_authority().await?;
        let key = self.key(session_id)?;
        let Some(record) = self.backend.get(&key).await.map_err(map_store_error)? else {
            return Ok(None);
        };
        let checkpoint = decode_journal_record(&record, &key, session_id)?;
        Ok(Some((record, checkpoint)))
    }

    async fn begin_inner(
        &self,
        plan: &SessionRePinPlan,
    ) -> Result<SessionRePinCheckpoint, IpsecLbError> {
        for _ in 0..SESSION_REPIN_MAX_CAS_ATTEMPTS {
            let current = self.read(plan.session_id()).await?;
            if let Some((_, checkpoint)) = &current {
                if checkpoint.plan() == plan {
                    return Ok(checkpoint.clone());
                }
            }
            validate_plan_succession(current.as_ref().map(|value| &value.1), plan)?;
            let desired = SessionRePinCheckpoint::from_progress(plan.clone(), Vec::new(), None)?;
            match self
                .write_checkpoint(current.as_ref().map(|value| &value.0), &desired)
                .await?
            {
                JournalWrite::Committed(checkpoint) => return Ok(checkpoint),
                JournalWrite::Conflict => continue,
            }
        }
        Err(IpsecLbError::ownership_conflict(
            "session re-pin journal CAS attempts exhausted",
        ))
    }

    async fn mutate(
        &self,
        plan: &SessionRePinPlan,
        mutation: JournalMutation,
    ) -> Result<SessionRePinCheckpoint, IpsecLbError> {
        for _ in 0..SESSION_REPIN_MAX_CAS_ATTEMPTS {
            let Some((record, current)) = self.read(plan.session_id()).await? else {
                return Err(IpsecLbError::NotFound);
            };
            if current.plan() != plan {
                return Err(progress_conflict());
            }
            let desired = match mutation {
                JournalMutation::OwnershipCommitted { index, fence } => {
                    current.with_ownership_commit(index, fence)?
                }
                JournalMutation::SaComplete { index, fence } => {
                    current.with_sa_complete(index, fence)?
                }
            };
            if desired == current {
                return Ok(current);
            }
            match self.write_checkpoint(Some(&record), &desired).await? {
                JournalWrite::Committed(checkpoint) => return Ok(checkpoint),
                JournalWrite::Conflict => continue,
            }
        }
        Err(IpsecLbError::ownership_conflict(
            "session re-pin journal CAS attempts exhausted",
        ))
    }

    async fn write_checkpoint(
        &self,
        current: Option<&StoredSessionRecord>,
        desired: &SessionRePinCheckpoint,
    ) -> Result<JournalWrite, IpsecLbError> {
        let key = self.key(desired.plan().session_id())?;
        if current.is_some_and(|record| record.key != key) {
            return Err(progress_conflict());
        }
        let generation = match current {
            Some(record) => record.generation.next().ok_or_else(|| {
                IpsecLbError::invalid_config(
                    "session_repin.generation",
                    "session re-pin journal generation exhausted",
                )
            })?,
            None => Generation::new(1),
        };
        let owner = OwnerId::new(desired.plan().new_owner().as_str()).map_err(|_| {
            IpsecLbError::invalid_config("session_repin.owner", "session re-pin owner is invalid")
        })?;
        let payload = encode_checkpoint(desired)?;
        let capabilities = self.backend.capabilities().await;
        if !session_repin_authority_supported(capabilities) {
            return Err(IpsecLbError::Unsupported);
        }
        if payload.len() > capabilities.max_value_bytes {
            return Err(IpsecLbError::invalid_config(
                "session_repin.payload",
                "session re-pin journal exceeds the backend value limit",
            ));
        }
        let state_type = StateType::new(SESSION_REPIN_KEY_TYPE).map_err(|_| {
            IpsecLbError::invalid_config(
                "session_repin.state_type",
                "session re-pin state type is invalid",
            )
        })?;
        let lease = acquire_journal_lease(
            Arc::clone(&self.backend),
            key.clone(),
            owner.clone(),
            self.lease_ttl,
        )
        .await?;
        let guard = lease.guard().cloned().ok_or_else(|| {
            IpsecLbError::invalid_config(
                "session_repin.lease",
                "session re-pin lease cleanup guard is unavailable",
            )
        })?;
        let record = StoredSessionRecord {
            key: key.clone(),
            generation,
            owner,
            fence: guard.fence(),
            state_class: StateClass::AuthoritativeSession,
            state_type,
            expires_at: None,
            payload,
        };
        let expected_generation = current.map(|value| value.generation);
        let write = tokio::time::timeout(
            self.lease_ttl,
            self.backend.compare_and_set(CompareAndSet {
                key: key.clone(),
                lease: guard,
                expected_generation,
                new_record: record,
            }),
        )
        .await;

        match write {
            Ok(Ok(CompareAndSetResult::Success)) => Ok(JournalWrite::Committed(desired.clone())),
            Ok(Ok(CompareAndSetResult::Conflict { current })) => {
                if let Some(record) = current {
                    let observed =
                        decode_journal_record(&record, &key, desired.plan().session_id())?;
                    if observed == *desired {
                        return Ok(JournalWrite::Committed(observed));
                    }
                }
                Ok(JournalWrite::Conflict)
            }
            Ok(Err(error)) => {
                if let Some(observed) = self
                    .read_back_desired(&key, desired)
                    .await
                    .map_err(|_| map_store_error(error.clone()))?
                {
                    return Ok(JournalWrite::Committed(observed));
                }
                Err(map_store_error(error))
            }
            Err(_) => {
                if let Some(observed) = self.read_back_desired(&key, desired).await? {
                    return Ok(JournalWrite::Committed(observed));
                }
                Err(IpsecLbError::io(
                    "session_repin_journal_cas",
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "session re-pin journal commit acknowledgement timed out",
                    ),
                ))
            }
        }
    }

    async fn read_back_desired(
        &self,
        key: &SessionKey,
        desired: &SessionRePinCheckpoint,
    ) -> Result<Option<SessionRePinCheckpoint>, IpsecLbError> {
        let Some(record) = self.backend.get(key).await.map_err(map_store_error)? else {
            return Ok(None);
        };
        let observed = decode_journal_record(&record, key, desired.plan().session_id())?;
        Ok((observed == *desired).then_some(observed))
    }
}

const fn session_repin_authority_supported(capabilities: BackendCapabilities) -> bool {
    capabilities.atomic_compare_and_set
        && capabilities.monotonic_fencing_token
        && capabilities.per_key_ttl
        && capabilities.server_side_lease_expiry
        && capabilities.max_value_bytes >= SESSION_REPIN_JOURNAL_MAX_BYTES
}

#[async_trait]
impl<B> SessionRePinJournal for SessionStoreRePinJournal<B>
where
    B: SessionBackend + SessionLeaseManager + 'static,
{
    async fn begin(&self, plan: &SessionRePinPlan) -> Result<SessionRePinCheckpoint, IpsecLbError> {
        self.begin_inner(plan).await
    }

    async fn load(
        &self,
        session_id: &SessionRePinSessionId,
    ) -> Result<Option<SessionRePinCheckpoint>, IpsecLbError> {
        self.read(session_id)
            .await
            .map(|record| record.map(|value| value.1))
    }

    async fn record_ownership_committed(
        &self,
        plan: &SessionRePinPlan,
        index: usize,
        fence: OwnershipFence,
    ) -> Result<SessionRePinCheckpoint, IpsecLbError> {
        self.mutate(plan, JournalMutation::OwnershipCommitted { index, fence })
            .await
    }

    async fn record_sa_complete(
        &self,
        plan: &SessionRePinPlan,
        index: usize,
        fence: OwnershipFence,
    ) -> Result<SessionRePinCheckpoint, IpsecLbError> {
        self.mutate(plan, JournalMutation::SaComplete { index, fence })
            .await
    }
}

#[derive(Clone, Copy)]
enum JournalMutation {
    OwnershipCommitted { index: usize, fence: OwnershipFence },
    SaComplete { index: usize, fence: OwnershipFence },
}

enum JournalWrite {
    Committed(SessionRePinCheckpoint),
    Conflict,
}

struct JournalLeaseCleanup<B>
where
    B: SessionLeaseManager + 'static,
{
    backend: Arc<B>,
    lease: Option<LeaseGuard>,
}

impl<B> JournalLeaseCleanup<B>
where
    B: SessionLeaseManager + 'static,
{
    fn new(backend: Arc<B>, lease: LeaseGuard) -> Self {
        Self {
            backend,
            lease: Some(lease),
        }
    }

    fn guard(&self) -> Option<&LeaseGuard> {
        self.lease.as_ref()
    }
}

impl<B> Drop for JournalLeaseCleanup<B>
where
    B: SessionLeaseManager + 'static,
{
    fn drop(&mut self) {
        let Some(lease) = self.lease.take() else {
            return;
        };
        let backend = Arc::clone(&self.backend);
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            drop(runtime.spawn(async move {
                let _release =
                    tokio::time::timeout(SESSION_REPIN_RELEASE_TIMEOUT, backend.release(lease))
                        .await;
            }));
        }
    }
}

async fn acquire_journal_lease<B>(
    backend: Arc<B>,
    key: SessionKey,
    owner: OwnerId,
    ttl: Duration,
) -> Result<JournalLeaseCleanup<B>, IpsecLbError>
where
    B: SessionLeaseManager + 'static,
{
    let runtime = tokio::runtime::Handle::try_current().map_err(|_| {
        IpsecLbError::invalid_config(
            "session_repin.runtime",
            "session re-pin journaling requires a Tokio runtime",
        )
    })?;
    let acquisition_backend = Arc::clone(&backend);
    runtime
        .spawn(async move {
            let lease = tokio::time::timeout(ttl, acquisition_backend.acquire(&key, owner, ttl))
                .await
                .map_err(|_| {
                    IpsecLbError::io(
                        "session_repin_journal_lease",
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            "session re-pin journal lease acquisition timed out",
                        ),
                    )
                })?
                .map_err(map_lease_error)?;
            Ok(JournalLeaseCleanup::new(acquisition_backend, lease))
        })
        .await
        .map_err(|_| {
            IpsecLbError::io(
                "session_repin_journal_lease",
                io::Error::other("session re-pin journal lease task failed"),
            )
        })?
}

fn journal_payload_format() -> Result<SessionPayloadFormat, IpsecLbError> {
    SessionPayloadFormat::new(SESSION_REPIN_PAYLOAD_FORMAT).map_err(|_| {
        IpsecLbError::invalid_config(
            "session_repin.payload_format",
            "session re-pin payload format is invalid",
        )
    })
}

fn encode_checkpoint(
    checkpoint: &SessionRePinCheckpoint,
) -> Result<EncryptedSessionPayload, IpsecLbError> {
    let wire = JournalWire::from_checkpoint(checkpoint);
    encode_json_payload(
        &journal_payload_format()?,
        SessionPayloadVersion::new(SESSION_REPIN_PAYLOAD_VERSION),
        &wire,
        Some(SESSION_REPIN_JOURNAL_MAX_BYTES),
    )
    .map_err(|_| {
        IpsecLbError::invalid_config(
            "session_repin.payload",
            "session re-pin checkpoint encoding failed",
        )
    })
}

fn decode_journal_record(
    record: &StoredSessionRecord,
    expected_key: &SessionKey,
    expected_session_id: &SessionRePinSessionId,
) -> Result<SessionRePinCheckpoint, IpsecLbError> {
    if &record.key != expected_key
        || record.key.key_type.as_str() != SESSION_REPIN_KEY_TYPE
        || record.state_type.as_str() != SESSION_REPIN_KEY_TYPE
        || record.state_class != StateClass::AuthoritativeSession
        || record.generation.get() == 0
        || record.fence.get() == 0
        || record.expires_at.is_some()
        || record.payload.encoding() != SessionPayloadEncoding::Plaintext
    {
        return Err(IpsecLbError::invalid_config(
            "session_repin.record",
            "session re-pin journal metadata is invalid",
        ));
    }
    let wire: JournalWire = decode_json_payload(
        &record.payload,
        &journal_payload_format()?,
        SessionPayloadVersion::new(SESSION_REPIN_PAYLOAD_VERSION),
        Some(SESSION_REPIN_JOURNAL_MAX_BYTES),
    )
    .map_err(|_| {
        IpsecLbError::invalid_config(
            "session_repin.payload",
            "session re-pin checkpoint is unreadable",
        )
    })?;
    let checkpoint = wire.into_checkpoint()?;
    if checkpoint.plan().session_id() != expected_session_id
        || record.owner.as_str() != checkpoint.plan().new_owner().as_str()
    {
        return Err(progress_conflict());
    }
    Ok(checkpoint)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalWire {
    session_id: Vec<u8>,
    operation_id: u128,
    predecessor: Option<[u8; 32]>,
    fingerprint: [u8; 32],
    requests: Vec<RequestWire>,
    completed_fences: Vec<u64>,
    current_fence: Option<u64>,
}

impl JournalWire {
    fn from_checkpoint(checkpoint: &SessionRePinCheckpoint) -> Self {
        Self {
            session_id: checkpoint
                .plan()
                .session_id()
                .as_stable_id()
                .as_bytes()
                .to_vec(),
            operation_id: checkpoint.plan().operation_id().get(),
            predecessor: checkpoint
                .plan()
                .predecessor()
                .map(SessionRePinPlanFingerprint::as_bytes),
            fingerprint: checkpoint.plan().fingerprint().as_bytes(),
            requests: checkpoint
                .plan()
                .requests()
                .iter()
                .map(RequestWire::from_request)
                .collect(),
            completed_fences: checkpoint
                .completed_fences
                .iter()
                .map(|fence| fence.get())
                .collect(),
            current_fence: checkpoint.current_fence().map(OwnershipFence::get),
        }
    }

    fn into_checkpoint(self) -> Result<SessionRePinCheckpoint, IpsecLbError> {
        let stable_id = StableId::new(Bytes::from(self.session_id)).map_err(|_| {
            IpsecLbError::invalid_config(
                "session_repin.session_id",
                "session re-pin session identity is invalid",
            )
        })?;
        let operation_id = SessionRePinOperationId::new(self.operation_id)?;
        if self.requests.len() > MAX_SESSION_REPIN_SAS {
            return Err(IpsecLbError::invalid_config(
                "session_repin.requests",
                "session re-pin request count exceeds its bound",
            ));
        }
        let requests = self
            .requests
            .into_iter()
            .map(RequestWire::into_request)
            .collect::<Result<Vec<_>, _>>()?;
        let session_id = SessionRePinSessionId::from_stable_id(stable_id);
        let plan = match self.predecessor {
            Some(predecessor) => SessionRePinPlan::new_successor(
                session_id,
                operation_id,
                SessionRePinPlanFingerprint(predecessor),
                requests,
            )?,
            None => SessionRePinPlan::new(session_id, operation_id, requests)?,
        };
        if plan.fingerprint().as_bytes() != self.fingerprint {
            return Err(progress_conflict());
        }
        if self.completed_fences.len() > plan.len() {
            return Err(progress_conflict());
        }
        let completed_fences = self
            .completed_fences
            .into_iter()
            .map(OwnershipFence::new)
            .collect::<Result<Vec<_>, _>>()?;
        let current_fence = self.current_fence.map(OwnershipFence::new).transpose()?;
        SessionRePinCheckpoint::from_progress(plan, completed_fences, current_fence)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestWire {
    sa: SaWire,
    transition_id: u128,
    previous_fence: u64,
    previous_owner: String,
    new_owner: String,
    rule: RuleWire,
    resume: ResumeWire,
}

impl RequestWire {
    fn from_request(request: &RePinRequest) -> Self {
        Self {
            sa: SaWire::from_sa(request.sa),
            transition_id: request.transition_id.get(),
            previous_fence: request.previous_fence.get(),
            previous_owner: request.previous_owner.as_str().to_owned(),
            new_owner: request.new_owner.as_str().to_owned(),
            rule: RuleWire::from_rule(request.rule),
            resume: ResumeWire::from_resume(request.resume),
        }
    }

    fn into_request(self) -> Result<RePinRequest, IpsecLbError> {
        Ok(RePinRequest {
            sa: self.sa.into_sa()?,
            transition_id: OwnershipTransitionId::new(self.transition_id)?,
            previous_fence: OwnershipFence::new(self.previous_fence)?,
            previous_owner: ClusterNode::new(self.previous_owner),
            new_owner: ClusterNode::new(self.new_owner),
            rule: self.rule.into_rule()?,
            resume: self.resume.into_resume()?,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SaWire {
    kind: u8,
    value: u64,
}

impl SaWire {
    const fn from_sa(sa: SaId) -> Self {
        match sa {
            SaId::Ike { responder_spi } => Self {
                kind: 1,
                value: responder_spi,
            },
            SaId::Esp { spi } => Self {
                kind: 2,
                value: spi as u64,
            },
        }
    }

    fn into_sa(self) -> Result<SaId, IpsecLbError> {
        match self.kind {
            1 if self.value != 0 => Ok(SaId::Ike {
                responder_spi: self.value,
            }),
            2 => u32::try_from(self.value)
                .ok()
                .filter(|value| *value != 0)
                .map(|spi| SaId::Esp { spi })
                .ok_or_else(invalid_wire),
            _ => Err(invalid_wire()),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleWire {
    shard: u16,
    owner: u16,
    key_kind: u8,
    key_value: u64,
}

impl RuleWire {
    const fn from_rule(rule: SteeringRule) -> Self {
        match rule.key {
            SteerKey::IkeResponderSpi(value) => Self {
                shard: rule.shard.get(),
                owner: rule.owner.get(),
                key_kind: 1,
                key_value: value,
            },
            SteerKey::EspSpi(value) => Self {
                shard: rule.shard.get(),
                owner: rule.owner.get(),
                key_kind: 2,
                key_value: value as u64,
            },
            SteerKey::IkeInit { .. } => Self {
                shard: rule.shard.get(),
                owner: rule.owner.get(),
                key_kind: 0,
                key_value: 0,
            },
        }
    }

    fn into_rule(self) -> Result<SteeringRule, IpsecLbError> {
        let key = match self.key_kind {
            1 if self.key_value != 0 => SteerKey::IkeResponderSpi(self.key_value),
            2 => {
                let value = u32::try_from(self.key_value)
                    .ok()
                    .filter(|value| *value != 0)
                    .ok_or_else(invalid_wire)?;
                SteerKey::EspSpi(value)
            }
            _ => return Err(invalid_wire()),
        };
        Ok(SteeringRule {
            shard: ShardId::new(self.shard),
            owner: ShardId::new(self.owner),
            key,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResumeWire {
    previous_sa: SaWire,
    resumed_sa: SaWire,
    outbound_iv: OutboundIvWire,
    anti_replay: AntiReplayWire,
    key_source: u8,
}

impl ResumeWire {
    fn from_resume(resume: SameSpiResume) -> Self {
        Self {
            previous_sa: SaWire::from_sa(resume.previous_sa),
            resumed_sa: SaWire::from_sa(resume.resumed_sa),
            outbound_iv: OutboundIvWire::from_outbound(resume.outbound_iv),
            anti_replay: AntiReplayWire::from_anti_replay(resume.anti_replay),
            key_source: match resume.key_source {
                ResumeKeySource::LiveMirrored => 1,
                ResumeKeySource::RekeyOrReattachFallback => 2,
                ResumeKeySource::PersistedKeyMaterial => 3,
            },
        }
    }

    fn into_resume(self) -> Result<SameSpiResume, IpsecLbError> {
        let key_source = match self.key_source {
            1 => ResumeKeySource::LiveMirrored,
            2 => ResumeKeySource::RekeyOrReattachFallback,
            3 => ResumeKeySource::PersistedKeyMaterial,
            _ => return Err(invalid_wire()),
        };
        Ok(SameSpiResume {
            previous_sa: self.previous_sa.into_sa()?,
            resumed_sa: self.resumed_sa.into_sa()?,
            outbound_iv: self.outbound_iv.into_outbound()?,
            anti_replay: self.anti_replay.into_anti_replay()?,
            key_source,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OutboundIvWire {
    kind: u8,
    checkpointed_send_iv_next: Option<u64>,
    restored_send_iv_next: Option<u64>,
    forward_jump: Option<ForwardJumpWire>,
}

impl OutboundIvWire {
    fn from_outbound(outbound: SameSpiOutboundIvResume) -> Self {
        match outbound {
            SameSpiOutboundIvResume::Unspecified => Self {
                kind: 0,
                checkpointed_send_iv_next: None,
                restored_send_iv_next: None,
                forward_jump: None,
            },
            SameSpiOutboundIvResume::CounterBased {
                checkpointed_send_iv_next,
                restored_send_iv_next,
                forward_jump,
            } => Self {
                kind: 1,
                checkpointed_send_iv_next: Some(checkpointed_send_iv_next),
                restored_send_iv_next: Some(restored_send_iv_next),
                forward_jump: forward_jump.map(ForwardJumpWire::from_jump),
            },
            SameSpiOutboundIvResume::IkeRandomIv { .. } => Self {
                kind: 2,
                checkpointed_send_iv_next: None,
                restored_send_iv_next: None,
                forward_jump: None,
            },
        }
    }

    fn into_outbound(self) -> Result<SameSpiOutboundIvResume, IpsecLbError> {
        match self.kind {
            0 if self.checkpointed_send_iv_next.is_none()
                && self.restored_send_iv_next.is_none()
                && self.forward_jump.is_none() =>
            {
                Ok(SameSpiOutboundIvResume::Unspecified)
            }
            1 => Ok(SameSpiOutboundIvResume::CounterBased {
                checkpointed_send_iv_next: self
                    .checkpointed_send_iv_next
                    .ok_or_else(invalid_wire)?,
                restored_send_iv_next: self.restored_send_iv_next.ok_or_else(invalid_wire)?,
                forward_jump: self
                    .forward_jump
                    .map(ForwardJumpWire::into_jump)
                    .transpose()?,
            }),
            2 if self.checkpointed_send_iv_next.is_none()
                && self.restored_send_iv_next.is_none()
                && self.forward_jump.is_none() =>
            {
                Ok(SameSpiOutboundIvResume::IkeRandomIv {
                    attestation: IkeRandomIvAttestation::FreshIndependentCsprngIvPerMessage,
                })
            }
            _ => Err(invalid_wire()),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ForwardJumpWire {
    forward_jump: u64,
    counter_mode: u8,
    max_peer_sequence_lag: Option<u64>,
}

impl ForwardJumpWire {
    const fn from_jump(jump: SendIvForwardJump) -> Self {
        match jump.counter_mode {
            SendIvCounterMode::EspExtendedSequenceNumbers {
                max_peer_sequence_lag,
            } => Self {
                forward_jump: jump.forward_jump,
                counter_mode: 1,
                max_peer_sequence_lag: Some(max_peer_sequence_lag),
            },
            SendIvCounterMode::IkeAeadExplicitIv64 => Self {
                forward_jump: jump.forward_jump,
                counter_mode: 2,
                max_peer_sequence_lag: None,
            },
        }
    }

    fn into_jump(self) -> Result<SendIvForwardJump, IpsecLbError> {
        let counter_mode = match (self.counter_mode, self.max_peer_sequence_lag) {
            (1, Some(max_peer_sequence_lag)) => SendIvCounterMode::EspExtendedSequenceNumbers {
                max_peer_sequence_lag,
            },
            (2, None) => SendIvCounterMode::IkeAeadExplicitIv64,
            _ => return Err(invalid_wire()),
        };
        Ok(SendIvForwardJump {
            forward_jump: self.forward_jump,
            counter_mode,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AntiReplayWire {
    kind: u8,
    checkpoint_highest_accepted: u64,
    restored_highest_accepted: u64,
    max_reopened_packets: Option<u64>,
}

impl AntiReplayWire {
    const fn from_anti_replay(value: AntiReplayResume) -> Self {
        match value {
            AntiReplayResume::ExactWindowRestore {
                checkpoint_highest_accepted,
                restored_highest_accepted,
            } => Self {
                kind: 1,
                checkpoint_highest_accepted,
                restored_highest_accepted,
                max_reopened_packets: None,
            },
            AntiReplayResume::BoundedReopening {
                checkpoint_highest_accepted,
                restored_highest_accepted,
                max_reopened_packets,
            } => Self {
                kind: 2,
                checkpoint_highest_accepted,
                restored_highest_accepted,
                max_reopened_packets: Some(max_reopened_packets),
            },
        }
    }

    fn into_anti_replay(self) -> Result<AntiReplayResume, IpsecLbError> {
        match (self.kind, self.max_reopened_packets) {
            (1, None) => Ok(AntiReplayResume::ExactWindowRestore {
                checkpoint_highest_accepted: self.checkpoint_highest_accepted,
                restored_highest_accepted: self.restored_highest_accepted,
            }),
            (2, Some(max_reopened_packets)) => Ok(AntiReplayResume::BoundedReopening {
                checkpoint_highest_accepted: self.checkpoint_highest_accepted,
                restored_highest_accepted: self.restored_highest_accepted,
                max_reopened_packets,
            }),
            _ => Err(invalid_wire()),
        }
    }
}

fn invalid_wire() -> IpsecLbError {
    IpsecLbError::invalid_config(
        "session_repin.payload",
        "session re-pin checkpoint value is invalid",
    )
}

fn map_lease_error(error: LeaseError) -> IpsecLbError {
    match error {
        LeaseError::AlreadyHeld | LeaseError::Expired | LeaseError::StaleFence => {
            IpsecLbError::ownership_conflict("session re-pin journal lease is contended")
        }
        LeaseError::InvalidSessionTtl => IpsecLbError::invalid_config(
            "session_repin.ttl",
            "session re-pin journal TTL is outside the supported range",
        ),
        LeaseError::OperationOutcomeUnavailable => IpsecLbError::io(
            "session_repin_journal_lease",
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "session re-pin journal lease outcome is unavailable",
            ),
        ),
        LeaseError::NotFound | LeaseError::Backend(_) => IpsecLbError::io(
            "session_repin_journal_lease",
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "session store unavailable",
            ),
        ),
    }
}

fn map_store_error(error: StoreError) -> IpsecLbError {
    match error {
        StoreError::NotFound => IpsecLbError::NotFound,
        StoreError::StaleFence
        | StoreError::LeaseHeld
        | StoreError::LeaseExpired
        | StoreError::CasConflict => {
            IpsecLbError::ownership_conflict("session re-pin journal write is contended")
        }
        StoreError::InvalidKey(_) => IpsecLbError::invalid_config(
            "session_repin.key",
            "session re-pin journal key was rejected",
        ),
        StoreError::CasIdempotencyConflict => IpsecLbError::invalid_config(
            "session_repin.idempotency",
            "session re-pin journal mutation identity was reused",
        ),
        StoreError::CasIdempotencyOutcomeUnavailable
        | StoreError::BackendOperationOutcomeUnavailable => IpsecLbError::io(
            "session_repin_journal_cas",
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "session re-pin journal mutation outcome is unavailable",
            ),
        ),
        StoreError::InvalidSessionTtl => IpsecLbError::invalid_config(
            "session_repin.ttl",
            "session re-pin journal TTL is invalid",
        ),
        StoreError::InvalidRecordExpiry => IpsecLbError::invalid_config(
            "session_repin.expiry",
            "session re-pin journal expiry is invalid",
        ),
        StoreError::CapabilityNotSupported(_) => IpsecLbError::Unsupported,
        StoreError::BackendUnavailable(_) | StoreError::ReplicationWatchCatchUpRequired => {
            IpsecLbError::io(
                "session_repin_journal",
                io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "session store unavailable",
                ),
            )
        }
        StoreError::PayloadTooLarge { .. } => IpsecLbError::invalid_config(
            "session_repin.payload",
            "session re-pin journal payload exceeds the backend limit",
        ),
        StoreError::Crypto(_) | StoreError::Serialization(_) => IpsecLbError::invalid_config(
            "session_repin.record",
            "session re-pin journal record is unreadable",
        ),
        StoreError::InvalidReplicationSequence
        | StoreError::InvalidReplicationLogRange
        | StoreError::ReplicationLogPageTooLarge { .. }
        | StoreError::ReplicationLogCursorCompacted { .. }
        | StoreError::ReplicationOperationLimitExceeded
        | StoreError::RecordExpiryPreflightLimitExceeded
        | StoreError::InvalidRestoreScanRequest(_)
        | StoreError::InvalidRestoreScanResponse(_)
        | StoreError::RestoreScanPageTooLarge { .. }
        | StoreError::RestoreScanResponseTooLarge { .. }
        | StoreError::RestoreScanCursorStale
        | StoreError::RestoreScanWorkBudgetExceeded => IpsecLbError::invalid_config(
            "session_repin.record",
            "session re-pin journal backend rejected the operation",
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use tokio::sync::Notify;

    use opc_key::{KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing};
    use opc_session_store::{
        BackendCapabilities, EncryptingSessionBackend, FakeSessionBackend, SessionOp,
        SessionOpResult, SessionPayloadEncoding, SessionStore,
    };

    use super::*;
    use crate::failover::MIN_SEND_IV_FORWARD_JUMP;
    use crate::mock::{
        MockOwnershipFencer, MockOwnershipSource, MockRePinAuditSink, MockSteeringBackend,
        MockSteeringOperation,
    };
    use crate::repin::{
        OwnershipFenceGrant, OwnershipFenceRequest, OwnershipRetryProof, OwnershipSnapshot,
        OwnershipTransitionFingerprint,
    };

    const SESSION_SA_COUNT: usize = 4;

    fn tenant() -> TenantId {
        TenantId::new("tenant-a").unwrap()
    }

    fn nf_kind() -> NetworkFunctionKind {
        NetworkFunctionKind::new("epdg").unwrap()
    }

    fn session_id(seed: u8) -> SessionRePinSessionId {
        SessionRePinSessionId::from_stable_id(StableId::from([seed; 32]))
    }

    fn operation_id(value: u128) -> SessionRePinOperationId {
        SessionRePinOperationId::new(value).unwrap()
    }

    fn sa_for(index: usize) -> SaId {
        if index == 0 {
            SaId::Ike {
                responder_spi: 0x8877_6655_4433_2200,
            }
        } else {
            SaId::Esp {
                spi: 0x1122_3300 + u32::try_from(index).unwrap(),
            }
        }
    }

    fn request(index: usize, transition_offset: u128) -> RePinRequest {
        let sa = sa_for(index);
        let outbound_iv = match sa {
            SaId::Ike { .. } => SameSpiOutboundIvResume::IkeRandomIv {
                attestation: IkeRandomIvAttestation::FreshIndependentCsprngIvPerMessage,
            },
            SaId::Esp { .. } => SameSpiOutboundIvResume::CounterBased {
                checkpointed_send_iv_next: 100 + index as u64,
                restored_send_iv_next: 100 + index as u64 + MIN_SEND_IV_FORWARD_JUMP,
                forward_jump: Some(SendIvForwardJump {
                    forward_jump: MIN_SEND_IV_FORWARD_JUMP,
                    counter_mode: SendIvCounterMode::EspExtendedSequenceNumbers {
                        max_peer_sequence_lag: 0,
                    },
                }),
            },
        };
        RePinRequest {
            sa,
            transition_id: OwnershipTransitionId::new(transition_offset + index as u128).unwrap(),
            previous_fence: OwnershipFence::new(1).unwrap(),
            previous_owner: ClusterNode::new("worker-source-sensitive"),
            new_owner: ClusterNode::new("worker-target-sensitive"),
            rule: SteeringRule {
                shard: ShardId::new(7),
                owner: ShardId::new(9),
                key: match sa {
                    SaId::Ike { responder_spi } => SteerKey::IkeResponderSpi(responder_spi),
                    SaId::Esp { spi } => SteerKey::EspSpi(spi),
                },
            },
            resume: SameSpiResume {
                previous_sa: sa,
                resumed_sa: sa,
                outbound_iv,
                anti_replay: AntiReplayResume::ExactWindowRestore {
                    checkpoint_highest_accepted: 40 + index as u64,
                    restored_highest_accepted: 40 + index as u64,
                },
                key_source: ResumeKeySource::LiveMirrored,
            },
        }
    }

    fn plan_with(
        seed: u8,
        operation: u128,
        transition_offset: u128,
        count: usize,
    ) -> SessionRePinPlan {
        SessionRePinPlan::new(
            session_id(seed),
            operation_id(operation),
            (0..count)
                .map(|index| request(index, transition_offset))
                .collect(),
        )
        .unwrap()
    }

    fn successor_of(
        predecessor: &SessionRePinPlan,
        operation: u128,
        transition_offset: u128,
    ) -> SessionRePinPlan {
        SessionRePinPlan::new_successor(
            predecessor.session_id().clone(),
            operation_id(operation),
            predecessor.fingerprint(),
            (0..predecessor.len())
                .map(|index| request(index, transition_offset))
                .collect(),
        )
        .unwrap()
    }

    async fn complete_journal_plan<J>(journal: &J, plan: &SessionRePinPlan, fence_value: u64)
    where
        J: SessionRePinJournal,
    {
        journal.begin(plan).await.unwrap();
        let fence = OwnershipFence::new(fence_value).unwrap();
        for index in 0..plan.len() {
            journal
                .record_ownership_committed(plan, index, fence)
                .await
                .unwrap();
            journal
                .record_sa_complete(plan, index, fence)
                .await
                .unwrap();
        }
    }

    #[derive(Debug, Clone)]
    struct InjectedFencer {
        inner: MockOwnershipFencer,
        fence_calls: Arc<AtomicUsize>,
        validate_calls: Arc<AtomicUsize>,
        fail_fence_at: Arc<Mutex<Option<usize>>>,
        fail_validate_at: Arc<Mutex<Option<usize>>>,
    }

    impl InjectedFencer {
        fn new(inner: MockOwnershipFencer) -> Self {
            Self {
                inner,
                fence_calls: Arc::new(AtomicUsize::new(0)),
                validate_calls: Arc::new(AtomicUsize::new(0)),
                fail_fence_at: Arc::new(Mutex::new(None)),
                fail_validate_at: Arc::new(Mutex::new(None)),
            }
        }

        fn fail_fence_once(&self, call: usize) {
            *lock_unpoisoned(&self.fail_fence_at) = Some(call);
        }

        fn fail_validate_once(&self, call: usize) {
            *lock_unpoisoned(&self.fail_validate_at) = Some(call);
        }

        fn should_fail(target: &Mutex<Option<usize>>, call: usize) -> bool {
            let mut target = lock_unpoisoned(target);
            if *target == Some(call) {
                *target = None;
                true
            } else {
                false
            }
        }
    }

    #[async_trait]
    impl OwnershipFencer for InjectedFencer {
        async fn recover_fence_grant(
            &self,
            request: &OwnershipFenceRequest,
        ) -> Result<Option<OwnershipFenceGrant>, IpsecLbError> {
            self.inner.recover_fence_grant(request).await
        }

        async fn fence_sa_owner(
            &self,
            request: OwnershipFenceRequest,
        ) -> Result<OwnershipFenceGrant, IpsecLbError> {
            let call = self.fence_calls.fetch_add(1, Ordering::SeqCst) + 1;
            if Self::should_fail(&self.fail_fence_at, call) {
                return Err(IpsecLbError::Unsupported);
            }
            self.inner.fence_sa_owner(request).await
        }

        async fn validate_retry_proof(
            &self,
            proof: &OwnershipRetryProof,
        ) -> Result<(), IpsecLbError> {
            let call = self.validate_calls.fetch_add(1, Ordering::SeqCst) + 1;
            if Self::should_fail(&self.fail_validate_at, call) {
                return Err(IpsecLbError::Unsupported);
            }
            self.inner.validate_retry_proof(proof).await
        }
    }

    #[derive(Debug, Clone, Copy)]
    enum CompletedAuthorityDivergence {
        Owner,
        Fence,
        Transition,
        Fingerprint,
    }

    #[derive(Debug, Clone)]
    struct DivergentCompletedFencer {
        inner: InjectedFencer,
        sa: SaId,
        divergence: CompletedAuthorityDivergence,
    }

    #[async_trait]
    impl OwnershipFencer for DivergentCompletedFencer {
        async fn recover_fence_grant(
            &self,
            request: &OwnershipFenceRequest,
        ) -> Result<Option<OwnershipFenceGrant>, IpsecLbError> {
            let mut grant = self.inner.recover_fence_grant(request).await?;
            if request.sa != self.sa {
                return Ok(grant);
            }
            if let Some(value) = &mut grant {
                match self.divergence {
                    CompletedAuthorityDivergence::Owner => {
                        value.owner = ClusterNode::new("foreign-authoritative-owner")
                    }
                    CompletedAuthorityDivergence::Fence => {
                        value.fence = OwnershipFence::new(value.fence.get() + 1_000).unwrap()
                    }
                    CompletedAuthorityDivergence::Transition => {
                        value.transition_id = OwnershipTransitionId::new(u128::MAX - 1).unwrap()
                    }
                    CompletedAuthorityDivergence::Fingerprint => {
                        let mut bytes = value.fingerprint.as_bytes();
                        bytes[0] ^= 0x80;
                        value.fingerprint = OwnershipTransitionFingerprint::from_bytes(bytes);
                    }
                }
            }
            Ok(grant)
        }

        async fn fence_sa_owner(
            &self,
            request: OwnershipFenceRequest,
        ) -> Result<OwnershipFenceGrant, IpsecLbError> {
            self.inner.fence_sa_owner(request).await
        }

        async fn validate_retry_proof(
            &self,
            proof: &OwnershipRetryProof,
        ) -> Result<(), IpsecLbError> {
            self.inner.validate_retry_proof(proof).await
        }
    }

    #[derive(Clone)]
    struct Harness {
        plan: SessionRePinPlan,
        journal: MockSessionRePinJournal,
        steering: MockSteeringBackend,
        fencer: InjectedFencer,
        ownership: MockOwnershipSource,
        audit: MockRePinAuditSink,
    }

    #[derive(Debug, Clone)]
    struct BlockingSteering {
        inner: MockSteeringBackend,
        block: Arc<AtomicBool>,
        entered: Arc<AtomicBool>,
        release: Arc<Notify>,
    }

    impl BlockingSteering {
        fn new(inner: MockSteeringBackend) -> Self {
            Self {
                inner,
                block: Arc::new(AtomicBool::new(true)),
                entered: Arc::new(AtomicBool::new(false)),
                release: Arc::new(Notify::new()),
            }
        }

        fn unblock(&self) {
            self.block.store(false, Ordering::SeqCst);
            self.release.notify_waiters();
        }
    }

    #[async_trait]
    impl SteeringBackend for BlockingSteering {
        async fn install_rule(&self, rule: SteeringRule) -> Result<(), IpsecLbError> {
            if self.block.load(Ordering::SeqCst) {
                self.entered.store(true, Ordering::SeqCst);
                self.release.notified().await;
            }
            self.inner.install_rule(rule).await
        }

        async fn remove_rule(&self, rule: SteeringRule) -> Result<(), IpsecLbError> {
            self.inner.remove_rule(rule).await
        }

        async fn probe(&self) -> Result<crate::model::SteeringProbe, IpsecLbError> {
            self.inner.probe().await
        }
    }

    #[derive(Debug, Clone)]
    struct SelectiveInstallBarrier {
        inner: MockSteeringBackend,
        rule: SteeringRule,
        armed: Arc<AtomicBool>,
        entered: Arc<AtomicBool>,
        release: Arc<Notify>,
    }

    impl SelectiveInstallBarrier {
        fn new(inner: MockSteeringBackend, rule: SteeringRule) -> Self {
            Self {
                inner,
                rule,
                armed: Arc::new(AtomicBool::new(true)),
                entered: Arc::new(AtomicBool::new(false)),
                release: Arc::new(Notify::new()),
            }
        }

        fn release(&self) {
            self.release.notify_one();
        }
    }

    #[async_trait]
    impl SteeringBackend for SelectiveInstallBarrier {
        async fn install_rule(&self, rule: SteeringRule) -> Result<(), IpsecLbError> {
            if rule == self.rule && self.armed.swap(false, Ordering::SeqCst) {
                self.entered.store(true, Ordering::SeqCst);
                self.release.notified().await;
            }
            self.inner.install_rule(rule).await
        }

        async fn remove_rule(&self, rule: SteeringRule) -> Result<(), IpsecLbError> {
            self.inner.remove_rule(rule).await
        }

        async fn probe(&self) -> Result<crate::model::SteeringProbe, IpsecLbError> {
            self.inner.probe().await
        }
    }

    #[derive(Debug, Clone)]
    struct BlockingJournal {
        inner: MockSessionRePinJournal,
        block_stage: Arc<AtomicUsize>,
        entered: Arc<AtomicBool>,
        release: Arc<Notify>,
    }

    impl BlockingJournal {
        fn new(inner: MockSessionRePinJournal, block_stage: usize) -> Self {
            Self {
                inner,
                block_stage: Arc::new(AtomicUsize::new(block_stage)),
                entered: Arc::new(AtomicBool::new(false)),
                release: Arc::new(Notify::new()),
            }
        }

        async fn block_if_selected(&self, stage: usize) {
            if self.block_stage.load(Ordering::SeqCst) == stage {
                self.entered.store(true, Ordering::SeqCst);
                self.release.notified().await;
            }
        }

        fn unblock(&self) {
            self.block_stage.store(0, Ordering::SeqCst);
            self.release.notify_waiters();
        }
    }

    #[async_trait]
    impl SessionRePinJournal for BlockingJournal {
        async fn begin(
            &self,
            plan: &SessionRePinPlan,
        ) -> Result<SessionRePinCheckpoint, IpsecLbError> {
            self.inner.begin(plan).await
        }

        async fn load(
            &self,
            session_id: &SessionRePinSessionId,
        ) -> Result<Option<SessionRePinCheckpoint>, IpsecLbError> {
            self.inner.load(session_id).await
        }

        async fn record_ownership_committed(
            &self,
            plan: &SessionRePinPlan,
            index: usize,
            fence: OwnershipFence,
        ) -> Result<SessionRePinCheckpoint, IpsecLbError> {
            self.block_if_selected(1).await;
            self.inner
                .record_ownership_committed(plan, index, fence)
                .await
        }

        async fn record_sa_complete(
            &self,
            plan: &SessionRePinPlan,
            index: usize,
            fence: OwnershipFence,
        ) -> Result<SessionRePinCheckpoint, IpsecLbError> {
            self.block_if_selected(2).await;
            self.inner.record_sa_complete(plan, index, fence).await
        }
    }

    async fn wait_until_entered(entered: &AtomicBool) {
        for _ in 0..1_000 {
            if entered.load(Ordering::SeqCst) {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("test operation did not reach its cancellation point");
    }

    impl Harness {
        fn new() -> Self {
            let plan = plan_with(0x44, 700, 900, SESSION_SA_COUNT);
            let steering = MockSteeringBackend::new();
            let inner_fencer = MockOwnershipFencer::new();
            for request in plan.requests() {
                inner_fencer.set_owner(request.sa, request.previous_owner.clone());
            }
            let fencer = InjectedFencer::new(inner_fencer);
            let ownership = MockOwnershipSource::default();
            ownership.set_shard_owner(
                plan.requests()[0].rule.owner,
                plan.requests()[0].new_owner.clone(),
            );
            for request in plan.requests() {
                ownership.set_sa_ownership(
                    request.sa,
                    OwnershipSnapshot::new(request.previous_owner.clone(), request.previous_fence),
                );
            }
            Self {
                plan,
                journal: MockSessionRePinJournal::default(),
                steering,
                fencer,
                ownership,
                audit: MockRePinAuditSink::new(),
            }
        }

        fn coordinator(
            &self,
        ) -> SessionRePinCoordinator<
            MockSteeringBackend,
            InjectedFencer,
            MockOwnershipSource,
            MockRePinAuditSink,
            MockSessionRePinJournal,
        > {
            SessionRePinCoordinator::new(
                RePinCoordinator::new(
                    self.steering.clone(),
                    self.fencer.clone(),
                    self.ownership.clone(),
                    self.audit.clone(),
                ),
                self.journal.clone(),
            )
        }

        fn assert_terminal(&self, outcome: &SessionRePinOutcome) {
            assert_eq!(outcome.status().phase(), SessionRePinPhase::Complete);
            assert_eq!(
                outcome.status().completed_sa_count(),
                self.plan.requests().len()
            );
            assert_eq!(
                self.fencer.inner.operations().len(),
                self.plan.requests().len(),
                "each ownership transition must commit once"
            );
            assert_eq!(
                self.steering
                    .operations()
                    .iter()
                    .filter(|operation| matches!(operation, MockSteeringOperation::Install(_)))
                    .count(),
                self.plan.requests().len(),
                "idempotent recovery must leave one installed rule per SA"
            );
        }
    }

    async fn leave_completed_prefix(completed: usize) -> Harness {
        let harness = Harness::new();
        seed_completed_prefix(&harness, &harness.journal, completed).await;
        harness
    }

    async fn seed_completed_prefix<J>(harness: &Harness, journal: &J, completed: usize)
    where
        J: SessionRePinJournal + Clone,
    {
        assert!((1..=harness.plan.len()).contains(&completed));
        let coordinator = SessionRePinCoordinator::new(
            RePinCoordinator::new(
                harness.steering.clone(),
                harness.fencer.clone(),
                harness.ownership.clone(),
                harness.audit.clone(),
            ),
            journal.clone(),
        );
        if completed < harness.plan.len() {
            harness.fencer.fail_fence_once(completed + 1);
            assert!(matches!(
                coordinator.start(harness.plan.clone()).await,
                Err(SessionRePinError::ForwardConvergenceRequired { .. })
            ));
        } else {
            coordinator.start(harness.plan.clone()).await.unwrap();
        }
        let checkpoint = journal
            .load(harness.plan.session_id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(checkpoint.completed_sa_count(), completed);
    }

    async fn assert_phase_two_detects_supported_interleaving<J>(
        journal: J,
        completed: usize,
        displaced_index: usize,
        barrier_index: usize,
    ) where
        J: SessionRePinJournal + Clone + 'static,
    {
        assert!(displaced_index < barrier_index);
        assert!(barrier_index < completed);
        let harness = Harness::new();
        seed_completed_prefix(&harness, &journal, completed).await;

        let barrier_rule = harness.plan.requests()[barrier_index].rule;
        let original_barrier_installs = harness
            .steering
            .operations()
            .iter()
            .filter(|operation| {
                matches!(operation, MockSteeringOperation::Install(rule) if *rule == barrier_rule)
            })
            .count();
        harness.steering.remove_rule(barrier_rule).await.unwrap();
        let barrier = SelectiveInstallBarrier::new(harness.steering.clone(), barrier_rule);
        let coordinator = SessionRePinCoordinator::new(
            RePinCoordinator::new(
                barrier.clone(),
                harness.fencer.clone(),
                harness.ownership.clone(),
                harness.audit.clone(),
            ),
            journal.clone(),
        );
        let session_id = harness.plan.session_id().clone();
        let identity = harness.plan.identity();
        let resume = tokio::spawn(async move { coordinator.resume(&session_id, identity).await });
        wait_until_entered(&barrier.entered).await;

        let checkpoint = journal
            .load(harness.plan.session_id())
            .await
            .unwrap()
            .unwrap();
        let displaced = &harness.plan.requests()[displaced_index];
        let foreign_owner = ClusterNode::new("foreign-authoritative-owner");
        let mut foreign_rule = displaced.rule;
        foreign_rule.owner = ShardId::new(displaced.rule.owner.get() + 100);
        harness
            .ownership
            .set_shard_owner(foreign_rule.owner, foreign_owner.clone());
        let foreign_transition = OwnershipTransitionId::new(
            70_000
                + u128::try_from(completed).unwrap() * 100
                + u128::try_from(displaced_index).unwrap() * 10
                + u128::try_from(barrier_index).unwrap(),
        )
        .unwrap();
        let direct_per_sa = RePinCoordinator::new(
            harness.steering.clone(),
            harness.fencer.clone(),
            harness.ownership.clone(),
            harness.audit.clone(),
        );
        assert!(matches!(
            direct_per_sa
                .repin(RePinRequest {
                    sa: displaced.sa,
                    transition_id: foreign_transition,
                    previous_fence: checkpoint.completed_fence(displaced_index).unwrap(),
                    previous_owner: displaced.new_owner.clone(),
                    new_owner: foreign_owner,
                    rule: foreign_rule,
                    resume: displaced.resume,
                })
                .await,
            Err(RePinError::AfterOwnershipCommit(_))
        ));
        let operations_after_foreign_commit = harness.fencer.inner.operations().len();

        barrier.release();
        assert!(matches!(
            resume.await.unwrap(),
            Err(SessionRePinError::ForwardConvergenceRequired { .. })
        ));
        assert_eq!(
            harness.fencer.inner.operations().len(),
            operations_after_foreign_commit,
            "phase two must fail before fencing a later SA"
        );
        assert_eq!(
            harness
                .steering
                .operations()
                .iter()
                .filter(|operation| {
                    matches!(operation, MockSteeringOperation::Install(rule) if *rule == barrier_rule)
                })
                .count(),
            original_barrier_installs + 1,
            "phase one must finish every steering repair before phase two"
        );
        if completed < harness.plan.len() {
            assert!(!harness.fencer.inner.operations().iter().any(|operation| {
                operation.transition_id == harness.plan.requests()[completed].transition_id
            }));
        }
        assert_eq!(
            journal
                .load(harness.plan.session_id())
                .await
                .unwrap()
                .unwrap()
                .completed_sa_count(),
            completed
        );
    }

    #[test]
    fn plan_requires_canonical_complete_order_and_unique_exact_requests() {
        let valid = plan_with(1, 1, 10, 3);
        assert!(matches!(valid.requests()[0].sa, SaId::Ike { .. }));
        assert!(valid.requests()[1..]
            .iter()
            .all(|request| matches!(request.sa, SaId::Esp { .. })));

        for invalid in [Vec::new(), vec![request(0, 10)]] {
            assert!(SessionRePinPlan::new(session_id(1), operation_id(1), invalid).is_err());
        }

        let mut wrong_order = valid.requests().to_vec();
        wrong_order.swap(0, 1);
        assert!(SessionRePinPlan::new(session_id(1), operation_id(2), wrong_order).is_err());

        let mut duplicate_sa = valid.requests().to_vec();
        duplicate_sa.push(duplicate_sa[2].clone());
        duplicate_sa[3].transition_id = OwnershipTransitionId::new(99).unwrap();
        assert!(SessionRePinPlan::new(session_id(1), operation_id(3), duplicate_sa).is_err());

        let mut different_owner = valid.requests().to_vec();
        different_owner[2].new_owner = ClusterNode::new("another-owner");
        assert!(SessionRePinPlan::new(session_id(1), operation_id(4), different_owner).is_err());

        let too_many = (0..=MAX_SESSION_REPIN_SAS)
            .map(|index| request(index, 1000))
            .collect();
        assert!(SessionRePinPlan::new(session_id(1), operation_id(5), too_many).is_err());
    }

    #[test]
    fn maximum_plan_round_trips_within_the_fixed_journal_budget() {
        let mut requests = plan_with(1, 1, 100, MAX_SESSION_REPIN_SAS)
            .requests()
            .to_vec();
        for request in &mut requests {
            request.previous_owner = ClusterNode::new("p".repeat(OwnerId::MAX_BYTES));
            request.new_owner = ClusterNode::new("n".repeat(OwnerId::MAX_BYTES));
        }
        let plan = SessionRePinPlan::new(
            SessionRePinSessionId::from_stable_id(
                StableId::new(Bytes::from(vec![0x5a; StableId::MAX_BYTES])).unwrap(),
            ),
            operation_id(1),
            requests,
        )
        .unwrap();
        let checkpoint =
            SessionRePinCheckpoint::from_progress(plan.clone(), Vec::new(), None).unwrap();
        let payload = encode_checkpoint(&checkpoint).unwrap();
        assert!(payload.len() <= SESSION_REPIN_JOURNAL_MAX_BYTES);
        let decoded: JournalWire = decode_json_payload(
            &payload,
            &journal_payload_format().unwrap(),
            SessionPayloadVersion::new(SESSION_REPIN_PAYLOAD_VERSION),
            Some(SESSION_REPIN_JOURNAL_MAX_BYTES),
        )
        .unwrap();
        assert_eq!(decoded.into_checkpoint().unwrap(), checkpoint);
    }

    #[test]
    fn plan_fingerprint_binds_session_operation_order_and_every_request() {
        let base = plan_with(1, 1, 100, 3);
        let different_session =
            SessionRePinPlan::new(session_id(2), base.operation_id(), base.requests().to_vec())
                .unwrap();
        let different_operation = SessionRePinPlan::new(
            base.session_id().clone(),
            operation_id(2),
            base.requests().to_vec(),
        )
        .unwrap();
        let mut changed_request = base.requests().to_vec();
        changed_request[2].resume.anti_replay = AntiReplayResume::ExactWindowRestore {
            checkpoint_highest_accepted: 99,
            restored_highest_accepted: 99,
        };
        let changed_request = SessionRePinPlan::new(
            base.session_id().clone(),
            base.operation_id(),
            changed_request,
        )
        .unwrap();
        let predecessor_bound = SessionRePinPlan::new_successor(
            base.session_id().clone(),
            base.operation_id(),
            base.fingerprint(),
            base.requests().to_vec(),
        )
        .unwrap();

        assert_ne!(base.fingerprint(), different_session.fingerprint());
        assert_ne!(base.fingerprint(), different_operation.fingerprint());
        assert_ne!(base.fingerprint(), changed_request.fingerprint());
        assert_ne!(base.fingerprint(), predecessor_bound.fingerprint());
        assert_eq!(
            SessionRePinIdentity::new(
                base.operation_id(),
                SessionRePinPlanFingerprint::from_bytes(base.fingerprint().as_bytes()),
            ),
            base.identity()
        );
    }

    #[tokio::test]
    async fn happy_path_exposes_success_only_after_every_sa_is_durable() {
        let harness = Harness::new();
        let outcome = harness
            .coordinator()
            .start(harness.plan.clone())
            .await
            .unwrap();
        harness.assert_terminal(&outcome);
        let checkpoint = harness
            .journal
            .load(harness.plan.session_id())
            .await
            .unwrap()
            .unwrap();
        assert!(checkpoint.is_complete());
        for index in 0..harness.plan.len() {
            assert_eq!(outcome.fence(index), checkpoint.completed_fence(index));
        }
    }

    #[tokio::test]
    async fn terminal_replay_reproves_every_completed_entry_without_refencing() {
        let harness = Harness::new();
        harness
            .coordinator()
            .start(harness.plan.clone())
            .await
            .unwrap();
        let fence_operations = harness.fencer.inner.operations().len();
        let proof_reads = harness.fencer.validate_calls.load(Ordering::SeqCst);
        let steering_attempts = harness.steering.install_attempts();

        let replayed = harness
            .coordinator()
            .resume(harness.plan.session_id(), harness.plan.identity())
            .await
            .unwrap();
        harness.assert_terminal(&replayed);
        assert_eq!(harness.fencer.inner.operations().len(), fence_operations);
        assert_eq!(
            harness.fencer.validate_calls.load(Ordering::SeqCst) - proof_reads,
            harness.plan.len() * 2
        );
        assert_eq!(
            harness.steering.install_attempts() - steering_attempts,
            harness.plan.len()
        );
    }

    #[tokio::test]
    async fn committed_validation_is_strictly_mutation_free() {
        let harness = Harness::new();
        let outcome = harness
            .coordinator()
            .start(harness.plan.clone())
            .await
            .unwrap();
        let fence_operations = harness.fencer.inner.operations().len();
        let steering_attempts = harness.steering.install_attempts();
        let audit_attempts = harness.audit.record_attempts();
        let repin = RePinCoordinator::new(
            harness.steering.clone(),
            harness.fencer.clone(),
            harness.ownership.clone(),
            harness.audit.clone(),
        );

        let validated = repin
            .validate_committed(&harness.plan.requests()[0], outcome.fence(0).unwrap())
            .await
            .unwrap();
        assert_eq!(validated.fence(), outcome.fence(0).unwrap());
        assert_eq!(harness.fencer.inner.operations().len(), fence_operations);
        assert_eq!(harness.steering.install_attempts(), steering_attempts);
        assert_eq!(harness.audit.record_attempts(), audit_attempts);
    }

    #[tokio::test]
    async fn emitted_repin_audit_debug_redacts_session_identifiers_and_fences() {
        let harness = Harness::new();
        let outcome = harness
            .coordinator()
            .start(harness.plan.clone())
            .await
            .unwrap();
        let rendered = format!("{:?}", harness.audit.events());
        assert!(rendered.contains("[redacted]"));
        for request in harness.plan.requests() {
            for forbidden in [
                format!("{:?}", request.sa),
                format!("{:?}", request.transition_id),
                request.previous_owner.as_str().to_owned(),
                request.new_owner.as_str().to_owned(),
            ] {
                assert!(!rendered.contains(&forbidden), "leaked {forbidden}");
            }
        }
        for index in 0..harness.plan.len() {
            let fence = outcome.fence(index).unwrap();
            let forbidden = format!("{fence:?}");
            assert!(!rendered.contains(&forbidden), "leaked {forbidden}");
        }
    }

    #[tokio::test]
    async fn precommit_failure_at_every_position_quarantines_only_before_first_commit() {
        for index in 0..SESSION_SA_COUNT {
            let harness = Harness::new();
            harness.fencer.fail_fence_once(index + 1);
            let error = harness
                .coordinator()
                .start(harness.plan.clone())
                .await
                .unwrap_err();
            if index == 0 {
                assert!(matches!(error, SessionRePinError::Quarantined { .. }));
                assert_eq!(error.status().unwrap().phase(), SessionRePinPhase::Prepared);
            } else {
                assert!(matches!(
                    error,
                    SessionRePinError::ForwardConvergenceRequired { .. }
                ));
                assert_eq!(
                    error.status().unwrap().completed_sa_count(),
                    index,
                    "completed prefix must remain durable"
                );
            }
            let restarted = harness
                .coordinator()
                .resume(harness.plan.session_id(), harness.plan.identity())
                .await
                .unwrap();
            harness.assert_terminal(&restarted);
        }
    }

    #[tokio::test]
    async fn postcommit_validation_failure_at_every_position_recovers_forward() {
        for index in 0..SESSION_SA_COUNT {
            let harness = Harness::new();
            let completed_prefix_validations = index * (index + 1);
            harness
                .fencer
                .fail_validate_once(index * 2 + completed_prefix_validations + 1);
            let error = harness
                .coordinator()
                .start(harness.plan.clone())
                .await
                .unwrap_err();
            assert!(matches!(
                error,
                SessionRePinError::ForwardConvergenceRequired { .. }
            ));
            assert!(error.status().unwrap().current_ownership_committed());

            let restarted = harness
                .coordinator()
                .resume(harness.plan.session_id(), harness.plan.identity())
                .await
                .unwrap();
            harness.assert_terminal(&restarted);
        }
    }

    #[tokio::test]
    async fn steering_failure_at_every_position_recovers_exact_requests() {
        for index in 0..SESSION_SA_COUNT {
            let harness = Harness::new();
            let completed_prefix_installs = index * (index + 1) / 2;
            harness
                .steering
                .fail_install_on_call(
                    index + completed_prefix_installs + 1,
                    IpsecLbError::Unsupported,
                )
                .unwrap();
            let error = harness
                .coordinator()
                .start(harness.plan.clone())
                .await
                .unwrap_err();
            assert!(matches!(
                error,
                SessionRePinError::ForwardConvergenceRequired { .. }
            ));
            let restarted = harness
                .coordinator()
                .resume(harness.plan.session_id(), harness.plan.identity())
                .await
                .unwrap();
            harness.assert_terminal(&restarted);
        }
    }

    #[tokio::test]
    async fn every_audit_stage_at_every_position_recovers_without_refencing() {
        for event_offset in 1..=3 {
            for index in 0..SESSION_SA_COUNT {
                let harness = Harness::new();
                harness
                    .audit
                    .fail_on_call(index * 3 + event_offset, IpsecLbError::Unsupported)
                    .unwrap();
                let error = harness
                    .coordinator()
                    .start(harness.plan.clone())
                    .await
                    .unwrap_err();
                if index == 0 && event_offset == 1 {
                    assert!(matches!(error, SessionRePinError::Quarantined { .. }));
                } else {
                    assert!(matches!(
                        error,
                        SessionRePinError::ForwardConvergenceRequired { .. }
                    ));
                }
                let restarted = harness
                    .coordinator()
                    .resume(harness.plan.session_id(), harness.plan.identity())
                    .await
                    .unwrap();
                harness.assert_terminal(&restarted);
            }
        }
    }

    #[tokio::test]
    async fn restart_from_prepared_current_commit_prefix_and_complete_is_idempotent() {
        let prepared = Harness::new();
        prepared.journal.begin(&prepared.plan).await.unwrap();
        let outcome = prepared
            .coordinator()
            .resume(prepared.plan.session_id(), prepared.plan.identity())
            .await
            .unwrap();
        prepared.assert_terminal(&outcome);
        let operations = prepared.fencer.inner.operations().len();
        let replayed = prepared
            .coordinator()
            .resume(prepared.plan.session_id(), prepared.plan.identity())
            .await
            .unwrap();
        prepared.assert_terminal(&replayed);
        assert_eq!(prepared.fencer.inner.operations().len(), operations);

        for restart_index in 0..SESSION_SA_COUNT {
            let harness = Harness::new();
            harness.fencer.fail_fence_once(restart_index + 1);
            let _ = harness
                .coordinator()
                .start(harness.plan.clone())
                .await
                .unwrap_err();
            let checkpoint = harness
                .journal
                .load(harness.plan.session_id())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(checkpoint.completed_sa_count(), restart_index);
            let outcome = harness
                .coordinator()
                .resume(harness.plan.session_id(), harness.plan.identity())
                .await
                .unwrap();
            harness.assert_terminal(&outcome);
        }
    }

    #[tokio::test]
    async fn cancellation_after_fence_before_repin_returns_recovers_from_prepared_plan() {
        let harness = Harness::new();
        let blocking = BlockingSteering::new(harness.steering.clone());
        let coordinator = SessionRePinCoordinator::new(
            RePinCoordinator::new(
                blocking.clone(),
                harness.fencer.clone(),
                harness.ownership.clone(),
                harness.audit.clone(),
            ),
            harness.journal.clone(),
        );
        let plan = harness.plan.clone();
        let task = tokio::spawn(async move { coordinator.start(plan).await });
        wait_until_entered(&blocking.entered).await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());

        let checkpoint = harness
            .journal
            .load(harness.plan.session_id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(checkpoint.status().phase(), SessionRePinPhase::Prepared);
        assert_eq!(harness.fencer.inner.operations().len(), 1);

        blocking.unblock();
        let recovered = harness
            .coordinator()
            .resume(harness.plan.session_id(), harness.plan.identity())
            .await
            .unwrap();
        harness.assert_terminal(&recovered);
    }

    #[tokio::test]
    async fn cancellation_around_each_journal_progress_write_recovers_exactly() {
        for stage in [1, 2] {
            let harness = Harness::new();
            let blocking = BlockingJournal::new(harness.journal.clone(), stage);
            let coordinator = SessionRePinCoordinator::new(
                RePinCoordinator::new(
                    harness.steering.clone(),
                    harness.fencer.clone(),
                    harness.ownership.clone(),
                    harness.audit.clone(),
                ),
                blocking.clone(),
            );
            let plan = harness.plan.clone();
            let task = tokio::spawn(async move { coordinator.start(plan).await });
            wait_until_entered(&blocking.entered).await;
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());

            let checkpoint = harness
                .journal
                .load(harness.plan.session_id())
                .await
                .unwrap()
                .unwrap();
            if stage == 1 {
                assert_eq!(checkpoint.status().phase(), SessionRePinPhase::Prepared);
            } else {
                assert_eq!(
                    checkpoint.status().phase(),
                    SessionRePinPhase::ConvergingForward
                );
                assert!(checkpoint.current_fence().is_some());
            }
            assert_eq!(harness.fencer.inner.operations().len(), 1);

            blocking.unblock();
            let recovered = harness
                .coordinator()
                .resume(harness.plan.session_id(), harness.plan.identity())
                .await
                .unwrap();
            harness.assert_terminal(&recovered);
        }
    }

    #[tokio::test]
    async fn competing_plan_cannot_displace_an_active_saga_or_overwrite_predecessors() {
        let harness = Harness::new();
        harness.journal.begin(&harness.plan).await.unwrap();
        let competitor = plan_with(
            0x44,
            harness.plan.operation_id().get() + 1,
            5_000,
            SESSION_SA_COUNT,
        );
        let error = harness.coordinator().start(competitor).await.unwrap_err();
        assert!(matches!(error, SessionRePinError::Journal(_)));
        assert!(harness.fencer.inner.operations().is_empty());
        for request in harness.plan.requests() {
            assert_eq!(
                harness.fencer.inner.owner(request.sa),
                Some(request.previous_owner.clone())
            );
        }

        let outcome = harness
            .coordinator()
            .resume(harness.plan.session_id(), harness.plan.identity())
            .await
            .unwrap();
        harness.assert_terminal(&outcome);
    }

    #[tokio::test]
    async fn mock_journal_requires_exact_terminal_succession_and_rejects_stale_completion() {
        let journal = MockSessionRePinJournal::default();
        let first = plan_with(1, 1, 100, 3);
        complete_journal_plan(&journal, &first, 2).await;
        let first_terminal = journal.load(first.session_id()).await.unwrap().unwrap();

        let unbound = plan_with(1, 2, 500, 3);
        assert!(journal.begin(&unbound).await.is_err());

        let reused_operation = SessionRePinPlan::new_successor(
            first.session_id().clone(),
            first.operation_id(),
            first.fingerprint(),
            (0..first.len()).map(|index| request(index, 500)).collect(),
        )
        .unwrap();
        assert!(journal.begin(&reused_operation).await.is_err());
        assert_eq!(
            journal.load(first.session_id()).await.unwrap().unwrap(),
            first_terminal
        );

        let mut one_reused_transition = (0..first.len())
            .map(|index| request(index, 500))
            .collect::<Vec<_>>();
        one_reused_transition[1].transition_id = first.requests()[1].transition_id;
        let one_reused_transition = SessionRePinPlan::new_successor(
            first.session_id().clone(),
            operation_id(2),
            first.fingerprint(),
            one_reused_transition,
        )
        .unwrap();
        assert!(journal.begin(&one_reused_transition).await.is_err());
        assert!(journal
            .begin(
                &SessionRePinPlan::new_successor(
                    first.session_id().clone(),
                    operation_id(3),
                    first.fingerprint(),
                    first.requests().to_vec(),
                )
                .unwrap(),
            )
            .await
            .is_err());
        assert_eq!(
            journal.load(first.session_id()).await.unwrap().unwrap(),
            first_terminal
        );

        let second = successor_of(&first, 4, 500);
        complete_journal_plan(&journal, &second, 3).await;
        let third = successor_of(&second, 5, 900);
        complete_journal_plan(&journal, &third, 4).await;
        assert!(journal.begin(&first).await.is_err());
        assert!(journal.begin(&second).await.is_err());
        assert_eq!(
            journal
                .load(first.session_id())
                .await
                .unwrap()
                .unwrap()
                .plan(),
            &third
        );
    }

    #[tokio::test]
    async fn restart_requires_the_exact_retained_operation_identity() {
        let harness = Harness::new();
        harness.journal.begin(&harness.plan).await.unwrap();
        let wrong_operation = operation_id(harness.plan.operation_id().get() + 1);
        let wrong_identity = SessionRePinIdentity::new(wrong_operation, harness.plan.fingerprint());
        let changed_plan = plan_with(
            0x44,
            harness.plan.operation_id().get(),
            5_000,
            SESSION_SA_COUNT,
        );
        let wrong_fingerprint =
            SessionRePinIdentity::new(harness.plan.operation_id(), changed_plan.fingerprint());
        for identity in [wrong_identity, wrong_fingerprint] {
            let error = harness
                .coordinator()
                .resume(harness.plan.session_id(), identity)
                .await
                .unwrap_err();
            assert!(matches!(error, SessionRePinError::Journal(_)));
            assert!(harness
                .coordinator()
                .status(harness.plan.session_id(), identity)
                .await
                .is_err());
        }
        assert!(harness.fencer.inner.operations().is_empty());
    }

    #[tokio::test]
    async fn stale_terminal_identity_cannot_observe_or_drive_its_successor() {
        let harness = Harness::new();
        complete_journal_plan(&harness.journal, &harness.plan, 2).await;
        let successor = successor_of(&harness.plan, 701, 5_000);
        harness.journal.begin(&successor).await.unwrap();

        for identity in [
            harness.plan.identity(),
            SessionRePinIdentity::new(successor.operation_id(), harness.plan.fingerprint()),
        ] {
            assert!(harness
                .coordinator()
                .status(harness.plan.session_id(), identity)
                .await
                .is_err());
            assert!(matches!(
                harness
                    .coordinator()
                    .resume(harness.plan.session_id(), identity)
                    .await,
                Err(SessionRePinError::Journal(_))
            ));
        }
        assert_eq!(
            harness
                .coordinator()
                .status(successor.session_id(), successor.identity())
                .await
                .unwrap()
                .unwrap()
                .phase(),
            SessionRePinPhase::Prepared
        );
        assert!(harness.fencer.inner.operations().is_empty());
    }

    #[tokio::test]
    async fn every_completed_prefix_conflict_fails_closed_before_a_later_transition() {
        for divergence in [
            CompletedAuthorityDivergence::Owner,
            CompletedAuthorityDivergence::Fence,
            CompletedAuthorityDivergence::Transition,
            CompletedAuthorityDivergence::Fingerprint,
        ] {
            for completed in 1..=SESSION_SA_COUNT {
                let harness = leave_completed_prefix(completed).await;
                let operation_count = harness.fencer.inner.operations().len();
                let target = harness.plan.requests()[completed - 1].sa;
                let coordinator = SessionRePinCoordinator::new(
                    RePinCoordinator::new(
                        harness.steering.clone(),
                        DivergentCompletedFencer {
                            inner: harness.fencer.clone(),
                            sa: target,
                            divergence,
                        },
                        harness.ownership.clone(),
                        harness.audit.clone(),
                    ),
                    harness.journal.clone(),
                );

                assert!(matches!(
                    coordinator
                        .resume(harness.plan.session_id(), harness.plan.identity())
                        .await,
                    Err(SessionRePinError::ForwardConvergenceRequired { .. })
                ));
                assert_eq!(harness.fencer.inner.operations().len(), operation_count);
                let retained = harness
                    .journal
                    .load(harness.plan.session_id())
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(retained.completed_sa_count(), completed);
            }
        }
    }

    #[tokio::test]
    async fn direct_single_sa_bypass_of_each_prefix_blocks_session_resume() {
        for completed in 1..=SESSION_SA_COUNT {
            let harness = leave_completed_prefix(completed).await;
            let target_index = completed - 1;
            let request = &harness.plan.requests()[target_index];
            let checkpoint = harness
                .journal
                .load(harness.plan.session_id())
                .await
                .unwrap()
                .unwrap();
            let foreign_transition =
                OwnershipTransitionId::new(50_000 + u128::try_from(completed).unwrap()).unwrap();
            let foreign_owner = ClusterNode::new("foreign-authoritative-owner");
            let mut foreign_rule = request.rule;
            foreign_rule.owner = ShardId::new(request.rule.owner.get() + 100);
            harness
                .ownership
                .set_shard_owner(foreign_rule.owner, foreign_owner.clone());
            let foreign_request = RePinRequest {
                sa: request.sa,
                transition_id: foreign_transition,
                previous_fence: checkpoint.completed_fence(target_index).unwrap(),
                previous_owner: request.new_owner.clone(),
                new_owner: foreign_owner,
                rule: foreign_rule,
                resume: request.resume,
            };
            let direct_per_sa = RePinCoordinator::new(
                harness.steering.clone(),
                harness.fencer.clone(),
                harness.ownership.clone(),
                harness.audit.clone(),
            );
            assert!(matches!(
                direct_per_sa.repin(foreign_request).await,
                Err(RePinError::AfterOwnershipCommit(_))
            ));
            let operation_count = harness.fencer.inner.operations().len();

            assert!(matches!(
                harness
                    .coordinator()
                    .resume(harness.plan.session_id(), harness.plan.identity())
                    .await,
                Err(SessionRePinError::ForwardConvergenceRequired { .. })
            ));
            assert_eq!(harness.fencer.inner.operations().len(), operation_count);
            if completed < harness.plan.len() {
                assert!(!harness.fencer.inner.operations().iter().any(|operation| {
                    operation.transition_id == harness.plan.requests()[completed].transition_id
                }));
            }
        }
    }

    #[tokio::test]
    async fn mock_global_phase_two_detects_every_earlier_later_interleaving() {
        for completed in 2..=SESSION_SA_COUNT {
            for displaced_index in 0..completed - 1 {
                for barrier_index in displaced_index + 1..completed {
                    assert_phase_two_detects_supported_interleaving(
                        MockSessionRePinJournal::default(),
                        completed,
                        displaced_index,
                        barrier_index,
                    )
                    .await;
                }
            }
        }
    }

    #[tokio::test]
    async fn session_store_global_phase_two_detects_every_earlier_later_interleaving() {
        for completed in 2..=SESSION_SA_COUNT {
            for displaced_index in 0..completed - 1 {
                for barrier_index in displaced_index + 1..completed {
                    let journal = SessionStoreRePinJournal::new(
                        SessionStore::new(FakeSessionBackend::new()),
                        tenant(),
                        nf_kind(),
                    );
                    assert_phase_two_detects_supported_interleaving(
                        journal,
                        completed,
                        displaced_index,
                        barrier_index,
                    )
                    .await;
                }
            }
        }
    }

    #[tokio::test]
    async fn every_completed_prefix_steering_conflict_blocks_later_mutation_and_success() {
        for completed in 1..=SESSION_SA_COUNT {
            let harness = leave_completed_prefix(completed).await;
            let operation_count = harness.fencer.inner.operations().len();
            let exact = harness.plan.requests()[completed - 1].rule;
            harness.steering.remove_rule(exact).await.unwrap();
            let mut conflicting = exact;
            conflicting.owner = ShardId::new(exact.owner.get() + 100);
            harness.steering.install_rule(conflicting).await.unwrap();

            assert!(matches!(
                harness
                    .coordinator()
                    .resume(harness.plan.session_id(), harness.plan.identity())
                    .await,
                Err(SessionRePinError::ForwardConvergenceRequired { .. })
            ));
            assert_eq!(harness.fencer.inner.operations().len(), operation_count);
            let retained = harness
                .journal
                .load(harness.plan.session_id())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(retained.completed_sa_count(), completed);
        }
    }

    #[tokio::test]
    async fn two_helpers_for_the_same_exact_saga_commit_each_transition_once() {
        let harness = Harness::new();
        let left = harness.coordinator();
        let right = harness.coordinator();
        let (left, right) = tokio::join!(
            left.start(harness.plan.clone()),
            right.start(harness.plan.clone())
        );
        let left = left.unwrap();
        let right = right.unwrap();
        harness.assert_terminal(&left);
        harness.assert_terminal(&right);
    }

    #[tokio::test]
    async fn mock_journal_rejects_skips_fence_changes_and_foreign_plans() {
        let journal = MockSessionRePinJournal::default();
        let plan = plan_with(1, 1, 100, 3);
        let fence = OwnershipFence::new(2).unwrap();
        journal.begin(&plan).await.unwrap();
        assert!(journal
            .record_ownership_committed(&plan, 1, fence)
            .await
            .is_err());
        journal
            .record_ownership_committed(&plan, 0, fence)
            .await
            .unwrap();
        assert!(journal
            .record_ownership_committed(&plan, 0, OwnershipFence::new(3).unwrap())
            .await
            .is_err());
        assert!(journal
            .record_sa_complete(&plan, 0, OwnershipFence::new(3).unwrap())
            .await
            .is_err());

        let foreign = plan_with(1, 2, 500, 3);
        assert!(journal.begin(&foreign).await.is_err());
    }

    #[tokio::test]
    async fn session_store_journal_round_trips_exact_requests_and_progress() {
        let store = SessionStore::new(FakeSessionBackend::new());
        let journal = SessionStoreRePinJournal::new(store.clone(), tenant(), nf_kind());
        let plan = plan_with(1, 1, 100, 3);
        let initial = journal.begin(&plan).await.unwrap();
        assert_eq!(initial.plan(), &plan);
        let fence = OwnershipFence::new(7).unwrap();
        journal
            .record_ownership_committed(&plan, 0, fence)
            .await
            .unwrap();
        journal.record_sa_complete(&plan, 0, fence).await.unwrap();

        let restarted = SessionStoreRePinJournal::new(store, tenant(), nf_kind());
        let loaded = restarted.load(plan.session_id()).await.unwrap().unwrap();
        assert_eq!(loaded.plan(), &plan);
        assert_eq!(loaded.completed_fence(0), Some(fence));
        assert_eq!(loaded.current_fence(), None);
    }

    #[tokio::test]
    async fn session_store_journal_rejects_non_authoritative_backend_capabilities() {
        let backend = FakeSessionBackend::with_capabilities(BackendCapabilities::minimal());
        let journal =
            SessionStoreRePinJournal::new(SessionStore::new(backend), tenant(), nf_kind());
        let error = journal.begin(&plan_with(1, 1, 100, 3)).await.unwrap_err();
        assert_eq!(error, IpsecLbError::Unsupported);
    }

    fn encryption_provider() -> Arc<MemoryKeyProvider> {
        let provider = Arc::new(MemoryKeyProvider::new());
        provider
            .insert_active_key(
                KeyId::new("session-repin-test-key").unwrap(),
                KeyPurpose::Session,
                tenant(),
                Zeroizing::new([0x5a; 32]),
            )
            .unwrap();
        provider
    }

    #[derive(Debug, Clone)]
    struct CapabilityOverrideBackend<B> {
        inner: B,
        capabilities: BackendCapabilities,
    }

    #[async_trait]
    impl<B> SessionBackend for CapabilityOverrideBackend<B>
    where
        B: SessionBackend,
    {
        async fn capabilities(&self) -> BackendCapabilities {
            self.capabilities
        }

        async fn get(&self, key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
            self.inner.get(key).await
        }

        async fn compare_and_set(
            &self,
            op: CompareAndSet,
        ) -> Result<CompareAndSetResult, StoreError> {
            self.inner.compare_and_set(op).await
        }

        async fn delete_fenced(&self, lease: &LeaseGuard) -> Result<(), StoreError> {
            self.inner.delete_fenced(lease).await
        }

        async fn refresh_ttl(&self, lease: &LeaseGuard, ttl: Duration) -> Result<(), StoreError> {
            self.inner.refresh_ttl(lease, ttl).await
        }

        async fn batch(&self, ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
            self.inner.batch(ops).await
        }
    }

    #[async_trait]
    impl<B> SessionLeaseManager for CapabilityOverrideBackend<B>
    where
        B: SessionLeaseManager,
    {
        async fn acquire(
            &self,
            key: &SessionKey,
            owner: OwnerId,
            ttl: Duration,
        ) -> Result<LeaseGuard, LeaseError> {
            self.inner.acquire(key, owner, ttl).await
        }

        async fn renew(&self, lease: &LeaseGuard, ttl: Duration) -> Result<LeaseGuard, LeaseError> {
            self.inner.renew(lease, ttl).await
        }

        async fn release(&self, lease: LeaseGuard) -> Result<(), LeaseError> {
            self.inner.release(lease).await
        }
    }

    #[derive(Debug, Clone)]
    struct CommitThenErrorBackend<B> {
        inner: B,
        inject: Arc<AtomicBool>,
        cas_calls: Arc<AtomicUsize>,
    }

    impl<B> CommitThenErrorBackend<B> {
        fn new(inner: B) -> Self {
            Self {
                inner,
                inject: Arc::new(AtomicBool::new(true)),
                cas_calls: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    #[async_trait]
    impl<B> SessionBackend for CommitThenErrorBackend<B>
    where
        B: SessionBackend,
    {
        async fn capabilities(&self) -> BackendCapabilities {
            self.inner.capabilities().await
        }

        async fn get(&self, key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
            self.inner.get(key).await
        }

        async fn compare_and_set(
            &self,
            op: CompareAndSet,
        ) -> Result<CompareAndSetResult, StoreError> {
            self.cas_calls.fetch_add(1, Ordering::SeqCst);
            let result = self.inner.compare_and_set(op).await?;
            if self.inject.swap(false, Ordering::SeqCst) {
                assert_eq!(result, CompareAndSetResult::Success);
                Err(StoreError::BackendUnavailable(
                    "injected lost acknowledgement".to_owned(),
                ))
            } else {
                Ok(result)
            }
        }

        async fn delete_fenced(&self, lease: &LeaseGuard) -> Result<(), StoreError> {
            self.inner.delete_fenced(lease).await
        }

        async fn refresh_ttl(&self, lease: &LeaseGuard, ttl: Duration) -> Result<(), StoreError> {
            self.inner.refresh_ttl(lease, ttl).await
        }

        async fn batch(&self, ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
            self.inner.batch(ops).await
        }
    }

    #[async_trait]
    impl<B> SessionLeaseManager for CommitThenErrorBackend<B>
    where
        B: SessionLeaseManager,
    {
        async fn acquire(
            &self,
            key: &SessionKey,
            owner: OwnerId,
            ttl: Duration,
        ) -> Result<LeaseGuard, LeaseError> {
            self.inner.acquire(key, owner, ttl).await
        }

        async fn renew(&self, lease: &LeaseGuard, ttl: Duration) -> Result<LeaseGuard, LeaseError> {
            self.inner.renew(lease, ttl).await
        }

        async fn release(&self, lease: LeaseGuard) -> Result<(), LeaseError> {
            self.inner.release(lease).await
        }
    }

    #[tokio::test]
    async fn journal_recovers_a_committed_write_after_lost_acknowledgement() {
        let backend = CommitThenErrorBackend::new(SessionStore::new(FakeSessionBackend::new()));
        let journal = SessionStoreRePinJournal::new(backend.clone(), tenant(), nf_kind());
        let plan = plan_with(1, 1, 100, 3);
        let checkpoint = journal.begin(&plan).await.unwrap();
        assert_eq!(checkpoint.plan(), &plan);
        assert_eq!(backend.cas_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            journal.load(plan.session_id()).await.unwrap().unwrap(),
            checkpoint
        );
    }

    #[tokio::test]
    async fn capability_downgrade_cannot_read_or_resume_a_terminal_checkpoint() {
        let store = SessionStore::new(FakeSessionBackend::new());
        let authoritative = SessionStoreRePinJournal::new(store.clone(), tenant(), nf_kind());
        let plan = plan_with(1, 1, 100, 3);
        complete_journal_plan(&authoritative, &plan, 2).await;

        let degraded = SessionStoreRePinJournal::new(
            CapabilityOverrideBackend {
                inner: store.clone(),
                capabilities: BackendCapabilities::minimal(),
            },
            tenant(),
            nf_kind(),
        );
        assert_eq!(
            degraded.validate_authority().await,
            Err(IpsecLbError::Unsupported)
        );
        assert_eq!(
            degraded.load(plan.session_id()).await,
            Err(IpsecLbError::Unsupported)
        );
        assert_eq!(degraded.begin(&plan).await, Err(IpsecLbError::Unsupported));
        let ports = Harness::new();
        let coordinator = SessionRePinCoordinator::new(
            RePinCoordinator::new(ports.steering, ports.fencer, ports.ownership, ports.audit),
            degraded,
        );
        assert!(matches!(
            coordinator.resume(plan.session_id(), plan.identity()).await,
            Err(SessionRePinError::Journal(IpsecLbError::Unsupported))
        ));

        let mut too_small = BackendCapabilities::all_enabled();
        too_small.max_value_bytes = SESSION_REPIN_JOURNAL_MAX_BYTES - 1;
        let too_small = SessionStoreRePinJournal::new(
            CapabilityOverrideBackend {
                inner: store,
                capabilities: too_small,
            },
            tenant(),
            nf_kind(),
        );
        assert_eq!(
            too_small.validate_authority().await,
            Err(IpsecLbError::Unsupported)
        );
        assert_eq!(
            too_small.load(plan.session_id()).await,
            Err(IpsecLbError::Unsupported)
        );
    }

    #[tokio::test]
    async fn session_store_cas_admits_exactly_one_competing_active_plan() {
        let store = SessionStore::new(FakeSessionBackend::new());
        let left = SessionStoreRePinJournal::new(store.clone(), tenant(), nf_kind());
        let right = SessionStoreRePinJournal::new(store, tenant(), nf_kind());
        let left_plan = plan_with(1, 1, 100, 3);
        let right_plan = plan_with(1, 2, 500, 3);
        let (left_result, right_result) =
            tokio::join!(left.begin(&left_plan), right.begin(&right_plan));
        assert_ne!(left_result.is_ok(), right_result.is_ok());
        let winner = left.load(left_plan.session_id()).await.unwrap().unwrap();
        assert!(winner.plan() == &left_plan || winner.plan() == &right_plan);
    }

    #[tokio::test]
    async fn session_store_journal_rejects_unbound_and_stale_terminal_replacements() {
        let journal = SessionStoreRePinJournal::new(
            SessionStore::new(FakeSessionBackend::new()),
            tenant(),
            nf_kind(),
        );
        let first = plan_with(1, 1, 100, 3);
        complete_journal_plan(&journal, &first, 2).await;
        let first_terminal = journal.load(first.session_id()).await.unwrap().unwrap();

        assert!(journal.begin(&plan_with(1, 2, 500, 3)).await.is_err());

        let reused_operation = SessionRePinPlan::new_successor(
            first.session_id().clone(),
            first.operation_id(),
            first.fingerprint(),
            (0..first.len()).map(|index| request(index, 500)).collect(),
        )
        .unwrap();
        assert!(journal.begin(&reused_operation).await.is_err());
        let mut one_reused_transition = (0..first.len())
            .map(|index| request(index, 500))
            .collect::<Vec<_>>();
        one_reused_transition[1].transition_id = first.requests()[1].transition_id;
        let one_reused_transition = SessionRePinPlan::new_successor(
            first.session_id().clone(),
            operation_id(2),
            first.fingerprint(),
            one_reused_transition,
        )
        .unwrap();
        assert!(journal.begin(&one_reused_transition).await.is_err());
        assert!(journal
            .begin(
                &SessionRePinPlan::new_successor(
                    first.session_id().clone(),
                    operation_id(3),
                    first.fingerprint(),
                    first.requests().to_vec(),
                )
                .unwrap(),
            )
            .await
            .is_err());
        assert_eq!(
            journal.load(first.session_id()).await.unwrap().unwrap(),
            first_terminal
        );

        let second = successor_of(&first, 4, 500);
        complete_journal_plan(&journal, &second, 3).await;
        let third = successor_of(&second, 5, 900);
        complete_journal_plan(&journal, &third, 4).await;
        assert!(journal.begin(&first).await.is_err());
        assert!(journal.begin(&second).await.is_err());
        assert_eq!(
            journal
                .load(first.session_id())
                .await
                .unwrap()
                .unwrap()
                .plan(),
            &third
        );
    }

    #[tokio::test]
    async fn session_store_successor_hides_predecessor_from_stale_exact_callers() {
        let journal = SessionStoreRePinJournal::new(
            SessionStore::new(FakeSessionBackend::new()),
            tenant(),
            nf_kind(),
        );
        let first = plan_with(1, 1, 100, 3);
        complete_journal_plan(&journal, &first, 2).await;
        let second = successor_of(&first, 2, 500);
        journal.begin(&second).await.unwrap();
        let ports = Harness::new();
        let coordinator = SessionRePinCoordinator::new(
            RePinCoordinator::new(ports.steering, ports.fencer, ports.ownership, ports.audit),
            journal,
        );

        for identity in [
            first.identity(),
            SessionRePinIdentity::new(second.operation_id(), first.fingerprint()),
        ] {
            assert!(coordinator
                .status(first.session_id(), identity)
                .await
                .is_err());
            assert!(matches!(
                coordinator.resume(first.session_id(), identity).await,
                Err(SessionRePinError::Journal(_))
            ));
        }
        assert_eq!(
            coordinator
                .status(second.session_id(), second.identity())
                .await
                .unwrap()
                .unwrap()
                .phase(),
            SessionRePinPhase::Prepared
        );
    }

    #[tokio::test]
    async fn session_store_cas_admits_only_one_exactly_bound_successor() {
        let store = SessionStore::new(FakeSessionBackend::new());
        let journal = SessionStoreRePinJournal::new(store.clone(), tenant(), nf_kind());
        let first = plan_with(1, 1, 100, 3);
        complete_journal_plan(&journal, &first, 2).await;

        let left = SessionStoreRePinJournal::new(store.clone(), tenant(), nf_kind());
        let right = SessionStoreRePinJournal::new(store, tenant(), nf_kind());
        let left_plan = successor_of(&first, 2, 500);
        let right_plan = successor_of(&first, 3, 900);
        let (left_result, right_result) =
            tokio::join!(left.begin(&left_plan), right.begin(&right_plan));
        assert_ne!(left_result.is_ok(), right_result.is_ok());
        let winner = journal.load(first.session_id()).await.unwrap().unwrap();
        assert!(winner.plan() == &left_plan || winner.plan() == &right_plan);
    }

    #[tokio::test]
    async fn production_encryption_wrapper_keeps_exact_journal_inputs_out_of_raw_storage() {
        let raw = SessionStore::new(FakeSessionBackend::new());
        let encrypted = EncryptingSessionBackend::new(
            Arc::new(raw.clone()),
            encryption_provider(),
            "session-repin-test",
        );
        let journal = SessionStoreRePinJournal::new(encrypted, tenant(), nf_kind());
        let plan = plan_with(0x77, 99, 700, 3);
        journal.begin(&plan).await.unwrap();

        let key = journal.key(plan.session_id()).unwrap();
        let stored = raw.get(&key).await.unwrap().unwrap();
        assert_eq!(
            stored.payload.encoding(),
            SessionPayloadEncoding::EnvelopeV1
        );
        let raw_payload = stored.payload.as_bytes();
        for forbidden in [
            b"worker-source-sensitive".as_slice(),
            b"worker-target-sensitive".as_slice(),
            b"8877665544332200".as_slice(),
        ] {
            assert!(!raw_payload
                .windows(forbidden.len())
                .any(|window| window == forbidden));
        }

        let loaded = journal.load(plan.session_id()).await.unwrap().unwrap();
        assert_eq!(loaded.plan(), &plan);
    }

    #[test]
    fn wire_decode_rejects_fingerprint_tampering_invalid_progress_and_trailing_shape() {
        let plan = plan_with(1, 1, 100, 3);
        let checkpoint = SessionRePinCheckpoint::from_progress(plan, Vec::new(), None).unwrap();
        let mut wire = JournalWire::from_checkpoint(&checkpoint);
        wire.fingerprint[0] ^= 1;
        assert!(wire.into_checkpoint().is_err());

        let mut wire = JournalWire::from_checkpoint(&checkpoint);
        wire.completed_fences = vec![2, 3, 4, 5];
        assert!(wire.into_checkpoint().is_err());

        let mut wire = JournalWire::from_checkpoint(&checkpoint);
        wire.current_fence = Some(0);
        assert!(wire.into_checkpoint().is_err());
    }

    #[test]
    fn status_plan_outcome_and_errors_are_redaction_safe() {
        let plan = plan_with(0x44, 123_456_789, 987_654_321, 3);
        let checkpoint = SessionRePinCheckpoint::from_progress(
            plan.clone(),
            vec![OwnershipFence::new(555_666_777).unwrap()],
            Some(OwnershipFence::new(777_888_999).unwrap()),
        )
        .unwrap();
        let status = checkpoint.status();
        let outcome = SessionRePinOutcome {
            checkpoint: SessionRePinCheckpoint::from_progress(
                plan.clone(),
                vec![
                    OwnershipFence::new(2).unwrap(),
                    OwnershipFence::new(3).unwrap(),
                    OwnershipFence::new(4).unwrap(),
                ],
                None,
            )
            .unwrap(),
        };
        let error = SessionRePinError::ForwardConvergenceRequired {
            status,
            cause: IpsecLbError::ownership_conflict("redaction-safe-static-code"),
        };
        let identity = plan.identity();
        let rendered = format!(
            "{plan:?} {identity:?} {checkpoint:?} {status:?} {outcome:?} {error:?} {error}"
        );
        for forbidden in [
            "worker-source-sensitive",
            "worker-target-sensitive",
            "8877665544332200",
            "9833440827789222417",
            "11223301",
            "287453953",
            "555666777",
            "777888999",
            "123456789",
            "987654321",
            "[68, 68, 68",
        ] {
            assert!(!rendered.contains(forbidden), "leaked {forbidden}");
        }
    }

    #[test]
    fn saga_does_not_relabel_caller_counter_arithmetic_as_applied_state_proof() {
        let plan = plan_with(1, 1, 100, 3);
        let rendered = format!("{plan:?}");
        assert!(!rendered.contains("applied"));
        assert!(plan.requests()[1]
            .resume
            .validate_for_repin(plan.requests()[1].sa)
            .is_ok());
        // The session layer only retains the exact request. It introduces no
        // receipt, applied-state flag, or kernel read-back claim for #333.
        assert_eq!(plan.requests()[1], plan.requests()[1].clone());
    }
}
