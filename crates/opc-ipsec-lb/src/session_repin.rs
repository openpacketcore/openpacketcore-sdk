//! Durable, forward-converging session-level re-pin coordination.
//!
//! A packet-core session resumes one IKE SA, one default-bearer ESP SA, and
//! optionally more dedicated-bearer ESP SAs. [`RePinCoordinator`] deliberately
//! coordinates one SA at a time. This module adds the durable ordered saga that
//! binds those exact requests into one operation and exposes success only after
//! every SA has crossed the ownership fence and completed steering. An
//! authoritative teardown can then retire only that exact terminal identity;
//! a bounded encrypted tombstone rejects stale recreation during the declared
//! retry horizon without retaining complete SA recovery inputs indefinitely.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;
use std::num::NonZeroU128;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use opc_ipsec_xfrm::OutboundSaBindingId;
use opc_session_store::{
    decode_json_payload, decode_session_payload_envelope, encode_json_payload,
    ttl::checked_session_deadline, BackendCapabilities, Clock, CompareAndSet, CompareAndSetResult,
    EncryptedSessionPayload, Generation, LeaseError, LeaseGuard, OwnerId, SessionBackend,
    SessionKey, SessionKeyType, SessionLeaseManager, SessionPayloadEncoding, SessionPayloadFormat,
    SessionPayloadVersion, StableId, StateClass, StateType, StoreError, StoredSessionRecord,
    SystemClock, Timestamp, SESSION_PAYLOAD_JSON_CONTENT_TYPE,
};
use opc_types::{NetworkFunctionKind, TenantId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::IpsecLbError;
use crate::failover::{AntiReplayResume, SendIvCounterMode, SendIvForwardJump};
use crate::model::{ClusterNode, SaId, ShardId, SteerKey, SteeringRule};
use crate::ownership::SessionOwnershipKey;
use crate::ports::{
    OwnershipFencer, OwnershipRetirementAuthority, OwnershipSource, RePinAuditSink,
    RePinSteeringBackend, RePinSteeringRetirementBackend,
};
use crate::repin::{
    validate_request, IkeRandomIvAttestation, OwnershipCleanupCompleteProof, OwnershipFence,
    OwnershipRetirementFinalizedProof, OwnershipRetirementGrant, OwnershipRetirementRequest,
    OwnershipRetirementStep, OwnershipRetirementSupersededProof, OwnershipTransitionId,
    PendingOwnershipRetirement, RePinCoordinator, RePinError, RePinRequest, ResumeKeySource,
    SameSpiOutboundIvResume, SameSpiResume,
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
const SESSION_REPIN_CHECKPOINT_PAYLOAD_VERSION: u16 = 3;
const SESSION_REPIN_RETIREMENT_PAYLOAD_VERSION: u16 = 2;
const SESSION_REPIN_RETIRING_PAYLOAD_VERSION: u16 = 4;
/// Maximum encoded durable checkpoint size admitted by the session saga.
///
/// This includes the SDK session-payload envelope as well as the complete exact
/// request set. Backends may advertise a smaller limit, which is enforced too.
pub const SESSION_REPIN_JOURNAL_MAX_BYTES: usize = 256 * 1024;
/// Fixed horizon for a retired session re-pin identity tombstone.
///
/// The tombstone prevents a delayed exact `begin`, resume, or successor call
/// from recreating a torn-down session. It is deliberately not refreshed by
/// retries, so storage is bounded by the deployment's retirement rate over
/// seven days. After this horizon the backend may garbage-collect the record;
/// callers must use non-reused privacy-preserving session IDs and keep every
/// retry horizon shorter than this duration.
pub const SESSION_REPIN_RETIREMENT_RETENTION: Duration = Duration::from_secs(7 * 24 * 60 * 60);
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
    let mut ownership_keys = BTreeSet::new();
    let mut outbound_sa_bindings = BTreeSet::new();
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
        if !ownership_keys.insert(request.ownership_key) {
            return Err(IpsecLbError::invalid_config(
                "session_repin.requests",
                "session re-pin contains a duplicate destination-scoped SA",
            ));
        }
        if let Some(id) = request.outbound_sa_binding_id {
            if !outbound_sa_bindings.insert(id.to_bytes()) {
                return Err(IpsecLbError::invalid_config(
                    "session_repin.requests",
                    "session re-pin contains a duplicate outbound SA binding ID",
                ));
            }
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

/// Durable result of one exact terminal-journal retirement attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionRePinRetirementDisposition {
    /// This mutation attempt established or confirmed the retirement tombstone.
    Retired,
    /// The same exact retirement was already durably committed.
    AlreadyRetired,
}

/// Redaction-safe result of retiring one terminal session re-pin journal.
///
/// The deadline is returned so a consumer can bound its teardown retry queue.
/// Formatting deliberately omits the exact timestamp as well as every session,
/// operation, SA, fence, and counter input.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionRePinRetirementOutcome {
    disposition: SessionRePinRetirementDisposition,
    retained_until: Timestamp,
}

impl SessionRePinRetirementOutcome {
    fn new(disposition: SessionRePinRetirementDisposition, retained_until: Timestamp) -> Self {
        Self {
            disposition,
            retained_until,
        }
    }

    /// Whether this call committed the tombstone or observed an exact retry.
    #[must_use]
    pub const fn disposition(self) -> SessionRePinRetirementDisposition {
        self.disposition
    }

    /// Return the fixed deadline through which stale recreation is rejected.
    ///
    /// Retrying retirement does not extend this deadline. Once it passes, the
    /// session ID must remain unused; the SDK cannot distinguish an ancient
    /// request from a new initial plan after bounded tombstone cleanup.
    #[must_use]
    pub const fn retained_until(self) -> Timestamp {
        self.retained_until
    }
}

impl fmt::Debug for SessionRePinRetirementOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionRePinRetirementOutcome")
            .field("disposition", &self.disposition)
            .field("retained_until", &"[redacted]")
            .finish()
    }
}

/// Redaction-safe durable progress of authoritative Host steering retirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionRePinRetirementStatus {
    total_sa_count: usize,
    cleanup_complete_count: usize,
    ownership_finalized_count: usize,
}

impl SessionRePinRetirementStatus {
    /// Return the fixed number of SAs in the terminal plan.
    #[must_use]
    pub const fn total_sa_count(self) -> usize {
        self.total_sa_count
    }

    /// Return how many ordered Host cleanups are durably marked complete.
    #[must_use]
    pub const fn cleanup_complete_count(self) -> usize {
        self.cleanup_complete_count
    }

    /// Return how many ordered ownership records are finalized.
    #[must_use]
    pub const fn ownership_finalized_count(self) -> usize {
        self.ownership_finalized_count
    }
}

/// Durable, non-expiring retirement work retained until every SA is clean.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionRePinRetirementProgress {
    checkpoint: SessionRePinCheckpoint,
    retirement_markers: Vec<OwnershipRetirementMarker>,
    ownership_finalized_count: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OwnershipRetirementMarker {
    CleanupComplete(OwnershipFence),
    Superseded(OwnershipFence),
}

impl SessionRePinRetirementProgress {
    fn from_terminal(checkpoint: SessionRePinCheckpoint) -> Result<Self, IpsecLbError> {
        let progress = Self {
            checkpoint,
            retirement_markers: Vec::new(),
            ownership_finalized_count: 0,
        };
        progress.validate()?;
        Ok(progress)
    }

    fn from_progress(
        checkpoint: SessionRePinCheckpoint,
        retirement_markers: Vec<OwnershipRetirementMarker>,
        ownership_finalized_count: usize,
    ) -> Result<Self, IpsecLbError> {
        let progress = Self {
            checkpoint,
            retirement_markers,
            ownership_finalized_count,
        };
        progress.validate()?;
        Ok(progress)
    }

    fn validate(&self) -> Result<(), IpsecLbError> {
        if !self.checkpoint.is_complete()
            || self.retirement_markers.len() > self.checkpoint.plan().len()
            || self.ownership_finalized_count > self.retirement_markers.len()
            || self.retirement_markers.len() - self.ownership_finalized_count > 1
        {
            return Err(progress_conflict());
        }
        if self.retirement_markers.len() > self.ownership_finalized_count
            && !matches!(
                self.retirement_markers.last(),
                Some(OwnershipRetirementMarker::CleanupComplete(_))
            )
        {
            return Err(progress_conflict());
        }
        for (index, marker) in self.retirement_markers.iter().enumerate() {
            let active_fence = self
                .checkpoint
                .completed_fence(index)
                .ok_or_else(progress_conflict)?;
            let authoritative_fence = match marker {
                OwnershipRetirementMarker::CleanupComplete(fence)
                | OwnershipRetirementMarker::Superseded(fence) => *fence,
            };
            if authoritative_fence <= active_fence {
                return Err(progress_conflict());
            }
        }
        Ok(())
    }

    fn exact_identity(
        &self,
        session_id: &SessionRePinSessionId,
        identity: SessionRePinIdentity,
    ) -> bool {
        self.checkpoint.plan().session_id() == session_id
            && self.checkpoint.plan().identity() == identity
    }

    fn grant(&self, index: usize) -> Result<OwnershipRetirementGrant, IpsecLbError> {
        let request = self
            .checkpoint
            .plan()
            .requests()
            .get(index)
            .ok_or_else(progress_conflict)?;
        let active_fence = self
            .checkpoint
            .completed_fence(index)
            .ok_or_else(progress_conflict)?;
        let retirement_fence = self
            .retirement_markers
            .get(index)
            .and_then(|marker| match marker {
                OwnershipRetirementMarker::CleanupComplete(fence) => Some(*fence),
                OwnershipRetirementMarker::Superseded(_) => None,
            })
            .ok_or_else(progress_conflict)?;
        Ok(OwnershipRetirementGrant::new(
            OwnershipRetirementRequest::from_committed(request, active_fence),
            retirement_fence,
        ))
    }

    fn with_cleanup_complete(
        &self,
        pending: &PendingOwnershipRetirement,
    ) -> Result<Self, IpsecLbError> {
        let index = self.retirement_markers.len();
        if index != self.ownership_finalized_count || index >= self.checkpoint.plan().len() {
            return Err(progress_conflict());
        }
        let request = &self.checkpoint.plan().requests()[index];
        let active_fence = self
            .checkpoint
            .completed_fence(index)
            .ok_or_else(progress_conflict)?;
        let expected = OwnershipRetirementRequest::from_committed(request, active_fence);
        if pending.grant().request() != &expected
            || pending.grant().retirement_fence() <= active_fence
        {
            return Err(progress_conflict());
        }
        let mut markers = self.retirement_markers.clone();
        markers.push(OwnershipRetirementMarker::CleanupComplete(
            pending.grant().retirement_fence(),
        ));
        Self::from_progress(
            self.checkpoint.clone(),
            markers,
            self.ownership_finalized_count,
        )
    }

    fn with_superseded(
        &self,
        proof: &OwnershipRetirementSupersededProof,
    ) -> Result<Self, IpsecLbError> {
        let index = self.ownership_finalized_count;
        if self.retirement_markers.len() != index || index >= self.checkpoint.plan().len() {
            return Err(progress_conflict());
        }
        let request = &self.checkpoint.plan().requests()[index];
        let active_fence = self
            .checkpoint
            .completed_fence(index)
            .ok_or_else(progress_conflict)?;
        let expected = OwnershipRetirementRequest::from_committed(request, active_fence);
        if proof.request() != &expected || proof.authoritative_fence() <= active_fence {
            return Err(progress_conflict());
        }
        let mut markers = self.retirement_markers.clone();
        markers.push(OwnershipRetirementMarker::Superseded(
            proof.authoritative_fence(),
        ));
        Self::from_progress(self.checkpoint.clone(), markers, index + 1)
    }

    fn with_ownership_finalized(
        &self,
        finalized: &OwnershipRetirementFinalizedProof,
    ) -> Result<Self, IpsecLbError> {
        let index = self.ownership_finalized_count;
        if index >= self.retirement_markers.len()
            || self.grant(index)? != *finalized.cleanup().grant()
        {
            return Err(progress_conflict());
        }
        Self::from_progress(
            self.checkpoint.clone(),
            self.retirement_markers.clone(),
            index + 1,
        )
    }

    fn is_complete(&self) -> bool {
        self.ownership_finalized_count == self.checkpoint.plan().len()
    }

    fn strictly_advances(&self, previous: &Self) -> bool {
        self.validate().is_ok()
            && previous.validate().is_ok()
            && self.checkpoint == previous.checkpoint
            && self
                .retirement_markers
                .starts_with(&previous.retirement_markers)
            && self.ownership_finalized_count >= previous.ownership_finalized_count
            && (self.retirement_markers.len() > previous.retirement_markers.len()
                || self.ownership_finalized_count > previous.ownership_finalized_count)
    }

    /// Return the exact retained terminal session identity.
    #[must_use]
    pub const fn identity(&self) -> SessionRePinIdentity {
        self.checkpoint.plan().identity()
    }

    /// Return redaction-safe ordered cleanup progress.
    #[must_use]
    pub fn status(&self) -> SessionRePinRetirementStatus {
        SessionRePinRetirementStatus {
            total_sa_count: self.checkpoint.plan().len(),
            cleanup_complete_count: self
                .retirement_markers
                .iter()
                .filter(|marker| matches!(marker, OwnershipRetirementMarker::CleanupComplete(_)))
                .count(),
            ownership_finalized_count: self.ownership_finalized_count,
        }
    }
}

impl fmt::Debug for SessionRePinRetirementProgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionRePinRetirementProgress")
            .field("status", &self.status())
            .finish()
    }
}

/// Exact result of beginning or recovering durable session retirement.
#[derive(Clone, PartialEq, Eq)]
pub enum SessionRePinRetirementResume {
    /// Cleanup remains in progress and ordinary session resume is revoked.
    InProgress(SessionRePinRetirementProgress),
    /// The exact bounded session tombstone was already committed.
    Retired(SessionRePinRetirementOutcome),
}

impl fmt::Debug for SessionRePinRetirementResume {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InProgress(progress) => f
                .debug_tuple("SessionRePinRetirementResume::InProgress")
                .field(&progress.status())
                .finish(),
            Self::Retired(outcome) => f
                .debug_tuple("SessionRePinRetirementResume::Retired")
                .field(outcome)
                .finish(),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct SessionRePinRetirementTombstone {
    session_id: SessionRePinSessionId,
    identity: SessionRePinIdentity,
    owner: OwnerId,
    retired_at: Timestamp,
    retained_until: Timestamp,
    fingerprint: [u8; 32],
}

impl SessionRePinRetirementTombstone {
    fn from_terminal(
        checkpoint: &SessionRePinCheckpoint,
        owner: OwnerId,
        retired_at: Timestamp,
        retained_until: Timestamp,
    ) -> Result<Self, IpsecLbError> {
        if !checkpoint.is_complete() {
            return Err(progress_conflict());
        }
        let session_id = checkpoint.plan().session_id().clone();
        let identity = checkpoint.plan().identity();
        let fingerprint =
            fingerprint_retirement(&session_id, identity, &owner, retired_at, retained_until);
        Ok(Self {
            session_id,
            identity,
            owner,
            retired_at,
            retained_until,
            fingerprint,
        })
    }

    fn validate(&self) -> Result<(), IpsecLbError> {
        let expected = fingerprint_retirement(
            &self.session_id,
            self.identity,
            &self.owner,
            self.retired_at,
            self.retained_until,
        );
        let expected_deadline =
            checked_session_deadline(self.retired_at, SESSION_REPIN_RETIREMENT_RETENTION)
                .map_err(map_store_error)?;
        if self.fingerprint == expected && self.retained_until == expected_deadline {
            Ok(())
        } else {
            Err(progress_conflict())
        }
    }

    fn exact_identity(
        &self,
        session_id: &SessionRePinSessionId,
        identity: SessionRePinIdentity,
    ) -> bool {
        self.session_id == *session_id && self.identity == identity
    }

    fn outcome(
        &self,
        disposition: SessionRePinRetirementDisposition,
    ) -> SessionRePinRetirementOutcome {
        SessionRePinRetirementOutcome::new(disposition, self.retained_until)
    }
}

impl fmt::Debug for SessionRePinRetirementTombstone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionRePinRetirementTombstone")
            .field("session_id", &"[redacted]")
            .field("identity", &"[redacted]")
            .field("owner", &"[redacted]")
            .field("retired_at", &"[redacted]")
            .field("retained_until", &"[redacted]")
            .finish()
    }
}

fn fingerprint_retirement(
    session_id: &SessionRePinSessionId,
    identity: SessionRePinIdentity,
    owner: &OwnerId,
    retired_at: Timestamp,
    retained_until: Timestamp,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"opc-ipsec-lb/session-repin-retirement/v1");
    hash_len_prefixed(&mut hasher, session_id.as_stable_id().as_bytes());
    hasher.update(identity.operation_id().get().to_be_bytes());
    hasher.update(identity.fingerprint().as_bytes());
    hash_len_prefixed(&mut hasher, owner.as_str().as_bytes());
    let retired = retired_at.as_offset_datetime();
    hasher.update(retired.unix_timestamp().to_be_bytes());
    hasher.update(retired.nanosecond().to_be_bytes());
    let deadline = retained_until.as_offset_datetime();
    hasher.update(deadline.unix_timestamp().to_be_bytes());
    hasher.update(deadline.nanosecond().to_be_bytes());
    hasher.finalize().into()
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
/// ownership commit. This low-level port exposes proof-gated retirement
/// recovery primitives, but no direct Active-to-retired-tombstone completion:
/// callers must use [`SessionRePinCoordinator::retire`] so Host cleanup and
/// ownership finalization precede the retained tombstone.
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

    /// Atomically revoke ordinary resume for one exact complete session.
    async fn begin_steering_retirement(
        &self,
        _session_id: &SessionRePinSessionId,
        _identity: SessionRePinIdentity,
    ) -> Result<SessionRePinRetirementResume, IpsecLbError> {
        Err(IpsecLbError::Unsupported)
    }

    /// Persist ordered Host cleanup before ownership may be deleted.
    async fn record_cleanup_complete(
        &self,
        _progress: &SessionRePinRetirementProgress,
        _pending: &PendingOwnershipRetirement,
    ) -> Result<
        (
            SessionRePinRetirementProgress,
            OwnershipCleanupCompleteProof,
        ),
        IpsecLbError,
    > {
        Err(IpsecLbError::Unsupported)
    }

    /// Persist that a strictly newer authoritative owner superseded this old
    /// key before Host cleanup. Implementations must append and finalize this
    /// ordered disposition atomically; it never authorizes a Host mutation.
    async fn record_ownership_superseded(
        &self,
        _progress: &SessionRePinRetirementProgress,
        _proof: &OwnershipRetirementSupersededProof,
    ) -> Result<SessionRePinRetirementProgress, IpsecLbError> {
        Err(IpsecLbError::Unsupported)
    }

    /// Persist that cleanup-complete ownership was deleted or superseded.
    async fn record_ownership_finalized(
        &self,
        _progress: &SessionRePinRetirementProgress,
        _finalized: &OwnershipRetirementFinalizedProof,
    ) -> Result<SessionRePinRetirementProgress, IpsecLbError> {
        Err(IpsecLbError::Unsupported)
    }

    /// Convert fully finalized progress into the bounded session tombstone.
    async fn finish_steering_retirement(
        &self,
        _progress: &SessionRePinRetirementProgress,
    ) -> Result<SessionRePinRetirementOutcome, IpsecLbError> {
        Err(IpsecLbError::Unsupported)
    }
}

/// Deterministic in-memory journal for unit tests and non-durable examples.
#[derive(Clone)]
pub struct MockSessionRePinJournal {
    state: Arc<Mutex<MockJournalState>>,
    clock: Arc<dyn Clock>,
}

#[derive(Default)]
struct MockJournalState {
    entries: BTreeMap<SessionRePinSessionId, MockJournalEntry>,
    failure: Option<IpsecLbError>,
}

enum MockJournalEntry {
    Active(SessionRePinCheckpoint),
    Retiring(SessionRePinRetirementProgress),
    Retired(SessionRePinRetirementTombstone),
}

impl Default for MockSessionRePinJournal {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(MockJournalState::default())),
            clock: Arc::new(SystemClock),
        }
    }
}

impl fmt::Debug for MockSessionRePinJournal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MockSessionRePinJournal")
            .finish_non_exhaustive()
    }
}

impl MockSessionRePinJournal {
    /// Build deterministic test support with an injected session-store clock.
    ///
    /// Share this clock with a fake backend when testing the fixed tombstone
    /// expiry boundary. Production code should use [`SessionStoreRePinJournal`].
    #[must_use]
    pub fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self {
            state: Arc::new(Mutex::new(MockJournalState::default())),
            clock,
        }
    }

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
        prune_mock_retirement(&mut state, plan.session_id(), self.clock.now_utc());
        let checkpoint = match state
            .entries
            .get(plan.session_id())
            .ok_or(IpsecLbError::NotFound)?
        {
            MockJournalEntry::Active(checkpoint) => checkpoint,
            MockJournalEntry::Retiring(_) => return Err(progress_conflict()),
            MockJournalEntry::Retired(_) => return Err(progress_conflict()),
        };
        if checkpoint.plan() != plan {
            return Err(progress_conflict());
        }
        let next = mutate(checkpoint)?;
        state.entries.insert(
            plan.session_id().clone(),
            MockJournalEntry::Active(next.clone()),
        );
        Ok(next)
    }

    #[cfg(test)]
    async fn retire(
        &self,
        session_id: &SessionRePinSessionId,
        identity: SessionRePinIdentity,
    ) -> Result<SessionRePinRetirementOutcome, IpsecLbError> {
        let mut state = lock_unpoisoned(&self.state);
        if let Some(error) = &state.failure {
            return Err(error.clone());
        }
        let retired_at = self.clock.now_utc();
        prune_mock_retirement(&mut state, session_id, retired_at);
        match state.entries.get(session_id) {
            Some(MockJournalEntry::Active(checkpoint)) => {
                if checkpoint.plan().identity() != identity || !checkpoint.is_complete() {
                    return Err(progress_conflict());
                }
                let retained_until =
                    checked_session_deadline(retired_at, SESSION_REPIN_RETIREMENT_RETENTION)
                        .map_err(map_store_error)?;
                let owner = OwnerId::new(checkpoint.plan().new_owner().as_str()).map_err(|_| {
                    IpsecLbError::invalid_config(
                        "session_repin.owner",
                        "session re-pin owner is invalid",
                    )
                })?;
                let tombstone = SessionRePinRetirementTombstone::from_terminal(
                    checkpoint,
                    owner,
                    retired_at,
                    retained_until,
                )?;
                let outcome = tombstone.outcome(SessionRePinRetirementDisposition::Retired);
                state
                    .entries
                    .insert(session_id.clone(), MockJournalEntry::Retired(tombstone));
                Ok(outcome)
            }
            Some(MockJournalEntry::Retired(tombstone))
                if tombstone.exact_identity(session_id, identity) =>
            {
                tombstone.validate()?;
                Ok(tombstone.outcome(SessionRePinRetirementDisposition::AlreadyRetired))
            }
            Some(MockJournalEntry::Retired(_)) => Err(progress_conflict()),
            Some(MockJournalEntry::Retiring(_)) => Err(progress_conflict()),
            None => Err(IpsecLbError::NotFound),
        }
    }
}

fn prune_mock_retirement(
    state: &mut MockJournalState,
    session_id: &SessionRePinSessionId,
    now: Timestamp,
) {
    let expired = matches!(
        state.entries.get(session_id),
        Some(MockJournalEntry::Retired(tombstone)) if tombstone.retained_until <= now
    );
    if expired {
        state.entries.remove(session_id);
    }
}

#[async_trait]
impl SessionRePinJournal for MockSessionRePinJournal {
    async fn begin(&self, plan: &SessionRePinPlan) -> Result<SessionRePinCheckpoint, IpsecLbError> {
        let mut state = lock_unpoisoned(&self.state);
        if let Some(error) = &state.failure {
            return Err(error.clone());
        }
        prune_mock_retirement(&mut state, plan.session_id(), self.clock.now_utc());
        if let Some(existing) = state.entries.get(plan.session_id()) {
            match existing {
                MockJournalEntry::Active(checkpoint) if checkpoint.plan() == plan => {
                    return Ok(checkpoint.clone());
                }
                MockJournalEntry::Active(_) | MockJournalEntry::Retired(_) => {}
                MockJournalEntry::Retiring(_) => {}
            }
        }
        let existing = match state.entries.get(plan.session_id()) {
            Some(MockJournalEntry::Active(checkpoint)) => Some(checkpoint),
            Some(MockJournalEntry::Retiring(_)) => return Err(progress_conflict()),
            Some(MockJournalEntry::Retired(_)) => return Err(progress_conflict()),
            None => None,
        };
        validate_plan_succession(existing, plan)?;
        let checkpoint = SessionRePinCheckpoint::from_progress(plan.clone(), Vec::new(), None)?;
        state.entries.insert(
            plan.session_id().clone(),
            MockJournalEntry::Active(checkpoint.clone()),
        );
        Ok(checkpoint)
    }

    async fn load(
        &self,
        session_id: &SessionRePinSessionId,
    ) -> Result<Option<SessionRePinCheckpoint>, IpsecLbError> {
        let mut state = lock_unpoisoned(&self.state);
        if let Some(error) = &state.failure {
            return Err(error.clone());
        }
        prune_mock_retirement(&mut state, session_id, self.clock.now_utc());
        Ok(match state.entries.get(session_id) {
            Some(MockJournalEntry::Active(checkpoint)) => Some(checkpoint.clone()),
            Some(MockJournalEntry::Retiring(_) | MockJournalEntry::Retired(_)) | None => None,
        })
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

    async fn begin_steering_retirement(
        &self,
        session_id: &SessionRePinSessionId,
        identity: SessionRePinIdentity,
    ) -> Result<SessionRePinRetirementResume, IpsecLbError> {
        let mut state = lock_unpoisoned(&self.state);
        if let Some(error) = &state.failure {
            return Err(error.clone());
        }
        let now = self.clock.now_utc();
        prune_mock_retirement(&mut state, session_id, now);
        match state.entries.get(session_id) {
            Some(MockJournalEntry::Active(checkpoint))
                if checkpoint.plan().identity() == identity && checkpoint.is_complete() =>
            {
                let progress = SessionRePinRetirementProgress::from_terminal(checkpoint.clone())?;
                state.entries.insert(
                    session_id.clone(),
                    MockJournalEntry::Retiring(progress.clone()),
                );
                Ok(SessionRePinRetirementResume::InProgress(progress))
            }
            Some(MockJournalEntry::Retiring(progress))
                if progress.exact_identity(session_id, identity) =>
            {
                progress.validate()?;
                Ok(SessionRePinRetirementResume::InProgress(progress.clone()))
            }
            Some(MockJournalEntry::Retired(tombstone))
                if tombstone.exact_identity(session_id, identity) =>
            {
                tombstone.validate()?;
                Ok(SessionRePinRetirementResume::Retired(tombstone.outcome(
                    SessionRePinRetirementDisposition::AlreadyRetired,
                )))
            }
            Some(_) => Err(progress_conflict()),
            None => Err(IpsecLbError::NotFound),
        }
    }

    async fn record_cleanup_complete(
        &self,
        progress: &SessionRePinRetirementProgress,
        pending: &PendingOwnershipRetirement,
    ) -> Result<
        (
            SessionRePinRetirementProgress,
            OwnershipCleanupCompleteProof,
        ),
        IpsecLbError,
    > {
        let mut state = lock_unpoisoned(&self.state);
        if let Some(error) = &state.failure {
            return Err(error.clone());
        }
        let session_id = progress.checkpoint.plan().session_id();
        let Some(MockJournalEntry::Retiring(current)) = state.entries.get(session_id) else {
            return Err(progress_conflict());
        };
        if current != progress {
            return Err(progress_conflict());
        }
        let desired = current.with_cleanup_complete(pending)?;
        let proof = OwnershipCleanupCompleteProof::new(pending.grant().clone());
        state.entries.insert(
            session_id.clone(),
            MockJournalEntry::Retiring(desired.clone()),
        );
        Ok((desired, proof))
    }

    async fn record_ownership_superseded(
        &self,
        progress: &SessionRePinRetirementProgress,
        proof: &OwnershipRetirementSupersededProof,
    ) -> Result<SessionRePinRetirementProgress, IpsecLbError> {
        let mut state = lock_unpoisoned(&self.state);
        if let Some(error) = &state.failure {
            return Err(error.clone());
        }
        let session_id = progress.checkpoint.plan().session_id();
        let Some(MockJournalEntry::Retiring(current)) = state.entries.get(session_id) else {
            return Err(progress_conflict());
        };
        if current != progress {
            return Err(progress_conflict());
        }
        let desired = current.with_superseded(proof)?;
        state.entries.insert(
            session_id.clone(),
            MockJournalEntry::Retiring(desired.clone()),
        );
        Ok(desired)
    }

    async fn record_ownership_finalized(
        &self,
        progress: &SessionRePinRetirementProgress,
        finalized: &OwnershipRetirementFinalizedProof,
    ) -> Result<SessionRePinRetirementProgress, IpsecLbError> {
        let mut state = lock_unpoisoned(&self.state);
        if let Some(error) = &state.failure {
            return Err(error.clone());
        }
        let session_id = progress.checkpoint.plan().session_id();
        let Some(MockJournalEntry::Retiring(current)) = state.entries.get(session_id) else {
            return Err(progress_conflict());
        };
        let desired = progress.with_ownership_finalized(finalized)?;
        if current == &desired {
            return Ok(current.clone());
        }
        if current != progress {
            return Err(progress_conflict());
        }
        state.entries.insert(
            session_id.clone(),
            MockJournalEntry::Retiring(desired.clone()),
        );
        Ok(desired)
    }

    async fn finish_steering_retirement(
        &self,
        progress: &SessionRePinRetirementProgress,
    ) -> Result<SessionRePinRetirementOutcome, IpsecLbError> {
        let mut state = lock_unpoisoned(&self.state);
        if let Some(error) = &state.failure {
            return Err(error.clone());
        }
        let session_id = progress.checkpoint.plan().session_id();
        match state.entries.get(session_id) {
            Some(MockJournalEntry::Retiring(current)) if current == progress => {
                if !current.is_complete() {
                    return Err(progress_conflict());
                }
                let retired_at = self.clock.now_utc();
                let retained_until =
                    checked_session_deadline(retired_at, SESSION_REPIN_RETIREMENT_RETENTION)
                        .map_err(map_store_error)?;
                let owner =
                    OwnerId::new(current.checkpoint.plan().new_owner().as_str()).map_err(|_| {
                        IpsecLbError::invalid_config(
                            "session_repin.owner",
                            "session re-pin owner is invalid",
                        )
                    })?;
                let tombstone = SessionRePinRetirementTombstone::from_terminal(
                    &current.checkpoint,
                    owner,
                    retired_at,
                    retained_until,
                )?;
                let outcome = tombstone.outcome(SessionRePinRetirementDisposition::Retired);
                state
                    .entries
                    .insert(session_id.clone(), MockJournalEntry::Retired(tombstone));
                Ok(outcome)
            }
            Some(MockJournalEntry::Retired(tombstone))
                if tombstone.exact_identity(session_id, progress.identity()) =>
            {
                Ok(tombstone.outcome(SessionRePinRetirementDisposition::AlreadyRetired))
            }
            Some(_) => Err(progress_conflict()),
            None => Err(IpsecLbError::NotFound),
        }
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
    /// Durable retirement began and must converge before activation can resume.
    #[error("session re-pin retirement requires forward convergence")]
    RetirementConvergenceRequired {
        /// Redaction-safe ordered retirement progress.
        status: SessionRePinRetirementStatus,
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
            Self::RetirementConvergenceRequired { .. } => {
                "session_repin_retirement_convergence_required"
            }
        }
    }

    /// Return the underlying redaction-safe failure.
    #[must_use]
    pub const fn cause(&self) -> &IpsecLbError {
        match self {
            Self::Journal(cause)
            | Self::Quarantined { cause, .. }
            | Self::ForwardConvergenceRequired { cause, .. }
            | Self::RetirementConvergenceRequired { cause, .. } => cause,
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
            Self::RetirementConvergenceRequired { .. } => None,
        }
    }

    /// Return durable retirement progress, when retirement already began.
    #[must_use]
    pub const fn retirement_status(&self) -> Option<SessionRePinRetirementStatus> {
        match self {
            Self::RetirementConvergenceRequired { status, .. } => Some(*status),
            Self::Journal(_)
            | Self::Quarantined { .. }
            | Self::ForwardConvergenceRequired { .. } => None,
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
    B: RePinSteeringBackend,
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

impl<B, F, O, A, J> SessionRePinCoordinator<B, F, O, A, J>
where
    B: RePinSteeringRetirementBackend + Clone + 'static,
    F: OwnershipFencer + OwnershipRetirementAuthority + Clone + 'static,
    O: OwnershipSource + Clone + 'static,
    A: RePinAuditSink + Clone + 'static,
    J: SessionRePinJournal + Clone + 'static,
{
    /// Durably retire every exact destination-scoped owner in this session.
    ///
    /// The entire operation runs in an owned supervised task. Dropping the
    /// observer future does not cancel an admitted ownership CAS, Host cleanup,
    /// or `CleanupComplete` write. Exact retries resume the non-expiring
    /// `Retiring` journal and never touch Host maps again for an already-marked
    /// key. The bounded session tombstone is written only after all ownership
    /// records are deleted or proven strictly superseded.
    pub async fn retire(
        &self,
        session_id: &SessionRePinSessionId,
        identity: SessionRePinIdentity,
    ) -> Result<SessionRePinRetirementOutcome, SessionRePinError> {
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| {
            SessionRePinError::Journal(IpsecLbError::invalid_config(
                "session_repin.runtime",
                "session re-pin retirement requires a Tokio runtime",
            ))
        })?;
        let worker = Self {
            repin: self.repin.clone(),
            journal: self.journal.clone(),
        };
        let session_id = session_id.clone();
        runtime
            .spawn(async move { worker.retire_owned(session_id, identity).await })
            .await
            .map_err(|_| {
                SessionRePinError::Journal(IpsecLbError::io(
                    "session_repin_retirement_worker",
                    io::Error::new(
                        io::ErrorKind::Interrupted,
                        "session re-pin retirement worker failed",
                    ),
                ))
            })?
    }

    async fn adopt_concurrent_retirement_progress(
        &self,
        session_id: &SessionRePinSessionId,
        identity: SessionRePinIdentity,
        previous: &SessionRePinRetirementProgress,
        cause: IpsecLbError,
    ) -> Result<SessionRePinRetirementResume, SessionRePinError> {
        match self
            .journal
            .begin_steering_retirement(session_id, identity)
            .await
        {
            Ok(SessionRePinRetirementResume::InProgress(current))
                if current.strictly_advances(previous) =>
            {
                Ok(SessionRePinRetirementResume::InProgress(current))
            }
            Ok(SessionRePinRetirementResume::Retired(outcome)) => {
                Ok(SessionRePinRetirementResume::Retired(outcome))
            }
            Ok(SessionRePinRetirementResume::InProgress(_)) | Err(_) => {
                Err(SessionRePinError::RetirementConvergenceRequired {
                    status: previous.status(),
                    cause,
                })
            }
        }
    }

    async fn retire_owned(
        &self,
        session_id: SessionRePinSessionId,
        identity: SessionRePinIdentity,
    ) -> Result<SessionRePinRetirementOutcome, SessionRePinError> {
        let mut permits = Vec::new();
        // Admission happens while the session is still Active. Once the
        // journal reaches Retiring, recovery must not depend on the old shard
        // owner because legitimate teardown/failover may already have moved it.
        if let Some(checkpoint) = self
            .journal
            .load(&session_id)
            .await
            .map_err(SessionRePinError::Journal)?
        {
            if checkpoint.plan().identity() != identity || !checkpoint.is_complete() {
                return Err(SessionRePinError::Journal(progress_conflict()));
            }
            let acquired = self
                .repin
                .acquire_retirement_permits(checkpoint.plan().requests())
                .await
                .map_err(SessionRePinError::Journal)?;
            if let Some(rechecked) = self
                .journal
                .load(&session_id)
                .await
                .map_err(SessionRePinError::Journal)?
            {
                if rechecked != checkpoint {
                    return Err(SessionRePinError::Journal(progress_conflict()));
                }
                for (index, (request, permit)) in rechecked
                    .plan()
                    .requests()
                    .iter()
                    .zip(&acquired)
                    .enumerate()
                {
                    let fence = rechecked
                        .completed_fence(index)
                        .ok_or_else(|| SessionRePinError::Journal(progress_conflict()))?;
                    self.repin
                        .validate_retirement_admission(request, fence, permit)
                        .await
                        .map_err(SessionRePinError::Journal)?;
                }
            }
            permits = acquired.into_iter().map(Some).collect();
        }

        let mut progress = match self
            .journal
            .begin_steering_retirement(&session_id, identity)
            .await
            .map_err(SessionRePinError::Journal)?
        {
            SessionRePinRetirementResume::InProgress(progress) => progress,
            SessionRePinRetirementResume::Retired(outcome) => return Ok(outcome),
        };

        loop {
            progress.validate().map_err(|cause| {
                SessionRePinError::RetirementConvergenceRequired {
                    status: progress.status(),
                    cause,
                }
            })?;
            if progress.is_complete() {
                return match self.journal.finish_steering_retirement(&progress).await {
                    Ok(outcome) => Ok(outcome),
                    Err(cause) => match self
                        .adopt_concurrent_retirement_progress(
                            &session_id,
                            identity,
                            &progress,
                            cause,
                        )
                        .await?
                    {
                        SessionRePinRetirementResume::Retired(outcome) => Ok(outcome),
                        SessionRePinRetirementResume::InProgress(_) => {
                            Err(SessionRePinError::RetirementConvergenceRequired {
                                status: progress.status(),
                                cause: progress_conflict(),
                            })
                        }
                    },
                };
            }

            let index = progress.ownership_finalized_count;
            if progress.retirement_markers.len() > index {
                let cleanup =
                    OwnershipCleanupCompleteProof::new(progress.grant(index).map_err(|cause| {
                        SessionRePinError::RetirementConvergenceRequired {
                            status: progress.status(),
                            cause,
                        }
                    })?);
                let finalized = self
                    .repin
                    .finalize_retirement_cleanup(cleanup)
                    .await
                    .map_err(|cause| SessionRePinError::RetirementConvergenceRequired {
                        status: progress.status(),
                        cause,
                    })?;
                progress = match self
                    .journal
                    .record_ownership_finalized(&progress, &finalized)
                    .await
                {
                    Ok(next) => next,
                    Err(cause) => match self
                        .adopt_concurrent_retirement_progress(
                            &session_id,
                            identity,
                            &progress,
                            cause,
                        )
                        .await?
                    {
                        SessionRePinRetirementResume::InProgress(next) => next,
                        SessionRePinRetirementResume::Retired(outcome) => return Ok(outcome),
                    },
                };
                continue;
            }

            if permits.is_empty() {
                let suffix = &progress.checkpoint.plan().requests()[index..];
                let acquired = self
                    .repin
                    .acquire_retirement_permits(suffix)
                    .await
                    .map_err(|cause| SessionRePinError::RetirementConvergenceRequired {
                        status: progress.status(),
                        cause,
                    })?;
                let refreshed = match self
                    .journal
                    .begin_steering_retirement(&session_id, identity)
                    .await
                    .map_err(|cause| SessionRePinError::RetirementConvergenceRequired {
                        status: progress.status(),
                        cause,
                    })? {
                    SessionRePinRetirementResume::InProgress(progress) => progress,
                    SessionRePinRetirementResume::Retired(outcome) => return Ok(outcome),
                };
                if refreshed != progress {
                    progress = refreshed;
                    drop(acquired);
                    continue;
                }
                permits = std::iter::repeat_with(|| None)
                    .take(index)
                    .chain(acquired.into_iter().map(Some))
                    .collect();
            }

            let request = progress.checkpoint.plan().requests()[index].clone();
            let active_fence = progress.checkpoint.completed_fence(index).ok_or_else(|| {
                SessionRePinError::RetirementConvergenceRequired {
                    status: progress.status(),
                    cause: progress_conflict(),
                }
            })?;
            let permit = permits
                .get_mut(index)
                .and_then(Option::take)
                .ok_or_else(|| SessionRePinError::RetirementConvergenceRequired {
                    status: progress.status(),
                    cause: IpsecLbError::adapter_contract_violation(
                        "session_repin_retirement_permit_missing",
                    ),
                })?;
            let step = self
                .repin
                .cleanup_committed_for_retirement(&request, active_fence, permit)
                .await
                .map_err(|cause| SessionRePinError::RetirementConvergenceRequired {
                    status: progress.status(),
                    cause,
                })?;
            match step {
                OwnershipRetirementStep::CleanupPending(pending) => {
                    let (cleanup_progress, cleanup) = match self
                        .journal
                        .record_cleanup_complete(&progress, &pending)
                        .await
                    {
                        Ok(value) => value,
                        Err(cause) => {
                            let resume = self
                                .adopt_concurrent_retirement_progress(
                                    &session_id,
                                    identity,
                                    &progress,
                                    cause,
                                )
                                .await?;
                            drop(pending);
                            match resume {
                                SessionRePinRetirementResume::InProgress(next) => {
                                    progress = next;
                                    continue;
                                }
                                SessionRePinRetirementResume::Retired(outcome) => {
                                    return Ok(outcome);
                                }
                            }
                        }
                    };
                    let finalized = match self.repin.finalize_retirement_cleanup(cleanup).await {
                        Ok(finalized) => finalized,
                        Err(cause) => {
                            let resume = self
                                .adopt_concurrent_retirement_progress(
                                    &session_id,
                                    identity,
                                    &cleanup_progress,
                                    cause,
                                )
                                .await?;
                            drop(pending);
                            match resume {
                                SessionRePinRetirementResume::InProgress(next) => {
                                    progress = next;
                                    continue;
                                }
                                SessionRePinRetirementResume::Retired(outcome) => {
                                    return Ok(outcome);
                                }
                            }
                        }
                    };
                    progress = match self
                        .journal
                        .record_ownership_finalized(&cleanup_progress, &finalized)
                        .await
                    {
                        Ok(next) => next,
                        Err(cause) => match self
                            .adopt_concurrent_retirement_progress(
                                &session_id,
                                identity,
                                &cleanup_progress,
                                cause,
                            )
                            .await?
                        {
                            SessionRePinRetirementResume::InProgress(next) => next,
                            SessionRePinRetirementResume::Retired(outcome) => {
                                drop(pending);
                                return Ok(outcome);
                            }
                        },
                    };
                    drop(pending);
                }
                OwnershipRetirementStep::Superseded(proof) => {
                    progress = match self
                        .journal
                        .record_ownership_superseded(&progress, &proof)
                        .await
                    {
                        Ok(next) => next,
                        Err(cause) => match self
                            .adopt_concurrent_retirement_progress(
                                &session_id,
                                identity,
                                &progress,
                                cause,
                            )
                            .await?
                        {
                            SessionRePinRetirementResume::InProgress(next) => next,
                            SessionRePinRetirementResume::Retired(outcome) => return Ok(outcome),
                        },
                    };
                }
            }
        }
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

#[derive(Clone, PartialEq, Eq)]
enum SessionRePinJournalEntry {
    Active(SessionRePinCheckpoint),
    Retiring(SessionRePinRetirementProgress),
    Retired(SessionRePinRetirementTombstone),
}

impl SessionRePinJournalEntry {
    fn session_id(&self) -> &SessionRePinSessionId {
        match self {
            Self::Active(checkpoint) => checkpoint.plan().session_id(),
            Self::Retiring(progress) => progress.checkpoint.plan().session_id(),
            Self::Retired(tombstone) => &tombstone.session_id,
        }
    }

    fn owner(&self) -> Result<OwnerId, IpsecLbError> {
        match self {
            Self::Active(checkpoint) => OwnerId::new(checkpoint.plan().new_owner().as_str())
                .map_err(|_| {
                    IpsecLbError::invalid_config(
                        "session_repin.owner",
                        "session re-pin owner is invalid",
                    )
                }),
            Self::Retiring(progress) => {
                OwnerId::new(progress.checkpoint.plan().new_owner().as_str()).map_err(|_| {
                    IpsecLbError::invalid_config(
                        "session_repin.owner",
                        "session re-pin owner is invalid",
                    )
                })
            }
            Self::Retired(tombstone) => Ok(tombstone.owner.clone()),
        }
    }

    const fn expires_at(&self) -> Option<Timestamp> {
        match self {
            Self::Active(_) => None,
            Self::Retiring(_) => None,
            Self::Retired(tombstone) => Some(tombstone.retained_until),
        }
    }
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
    clock: Arc<dyn Clock>,
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
            clock: Arc::new(SystemClock),
        }
    }

    /// Use one injected clock for the fixed retirement tombstone deadline.
    ///
    /// Production callers normally use the monotonic [`SystemClock`] selected
    /// by [`Self::new`]. Tests should share this clock with their fake backend
    /// so retirement expiry is deterministic.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
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

    async fn read_entry(
        &self,
        session_id: &SessionRePinSessionId,
    ) -> Result<Option<(StoredSessionRecord, SessionRePinJournalEntry)>, IpsecLbError> {
        self.validate_authority().await?;
        let key = self.key(session_id)?;
        let Some(record) = self.backend.get(&key).await.map_err(map_store_error)? else {
            return Ok(None);
        };
        let entry = decode_journal_record(&record, &key, session_id)?;
        Ok(Some((record, entry)))
    }

    async fn begin_inner(
        &self,
        plan: &SessionRePinPlan,
    ) -> Result<SessionRePinCheckpoint, IpsecLbError> {
        for _ in 0..SESSION_REPIN_MAX_CAS_ATTEMPTS {
            let current = self.read_entry(plan.session_id()).await?;
            if let Some((_, entry)) = &current {
                match entry {
                    SessionRePinJournalEntry::Active(checkpoint) if checkpoint.plan() == plan => {
                        return Ok(checkpoint.clone());
                    }
                    SessionRePinJournalEntry::Retired(_) => return Err(progress_conflict()),
                    SessionRePinJournalEntry::Retiring(_) => return Err(progress_conflict()),
                    SessionRePinJournalEntry::Active(_) => {}
                }
            }
            let existing = current.as_ref().and_then(|value| match &value.1 {
                SessionRePinJournalEntry::Active(checkpoint) => Some(checkpoint),
                SessionRePinJournalEntry::Retiring(_) | SessionRePinJournalEntry::Retired(_) => {
                    None
                }
            });
            validate_plan_succession(existing, plan)?;
            let desired = SessionRePinCheckpoint::from_progress(plan.clone(), Vec::new(), None)?;
            match self
                .write_entry(
                    current.as_ref().map(|value| &value.0),
                    &SessionRePinJournalEntry::Active(desired),
                )
                .await?
            {
                JournalWrite::Committed(SessionRePinJournalEntry::Active(checkpoint)) => {
                    return Ok(checkpoint);
                }
                JournalWrite::Committed(SessionRePinJournalEntry::Retired(_)) => {
                    return Err(progress_conflict());
                }
                JournalWrite::Committed(SessionRePinJournalEntry::Retiring(_)) => {
                    return Err(progress_conflict());
                }
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
            let Some((record, entry)) = self.read_entry(plan.session_id()).await? else {
                return Err(IpsecLbError::NotFound);
            };
            let SessionRePinJournalEntry::Active(current) = entry else {
                return Err(progress_conflict());
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
            match self
                .write_entry(Some(&record), &SessionRePinJournalEntry::Active(desired))
                .await?
            {
                JournalWrite::Committed(SessionRePinJournalEntry::Active(checkpoint)) => {
                    return Ok(checkpoint);
                }
                JournalWrite::Committed(SessionRePinJournalEntry::Retired(_)) => {
                    return Err(progress_conflict());
                }
                JournalWrite::Committed(SessionRePinJournalEntry::Retiring(_)) => {
                    return Err(progress_conflict());
                }
                JournalWrite::Conflict => continue,
            }
        }
        Err(IpsecLbError::ownership_conflict(
            "session re-pin journal CAS attempts exhausted",
        ))
    }

    async fn begin_steering_retirement_inner(
        &self,
        session_id: &SessionRePinSessionId,
        identity: SessionRePinIdentity,
    ) -> Result<SessionRePinRetirementResume, IpsecLbError> {
        for _ in 0..SESSION_REPIN_MAX_CAS_ATTEMPTS {
            let Some((record, entry)) = self.read_entry(session_id).await? else {
                return Err(IpsecLbError::NotFound);
            };
            let progress = match entry {
                SessionRePinJournalEntry::Active(checkpoint) => {
                    if checkpoint.plan().identity() != identity || !checkpoint.is_complete() {
                        return Err(progress_conflict());
                    }
                    SessionRePinRetirementProgress::from_terminal(checkpoint)?
                }
                SessionRePinJournalEntry::Retiring(progress) => {
                    if !progress.exact_identity(session_id, identity) {
                        return Err(progress_conflict());
                    }
                    progress.validate()?;
                    return Ok(SessionRePinRetirementResume::InProgress(progress));
                }
                SessionRePinJournalEntry::Retired(tombstone) => {
                    if !tombstone.exact_identity(session_id, identity) {
                        return Err(progress_conflict());
                    }
                    tombstone.validate()?;
                    return Ok(SessionRePinRetirementResume::Retired(
                        tombstone.outcome(SessionRePinRetirementDisposition::AlreadyRetired),
                    ));
                }
            };
            match self
                .write_entry(Some(&record), &SessionRePinJournalEntry::Retiring(progress))
                .await?
            {
                JournalWrite::Committed(SessionRePinJournalEntry::Retiring(progress)) => {
                    return Ok(SessionRePinRetirementResume::InProgress(progress));
                }
                JournalWrite::Committed(_) => return Err(progress_conflict()),
                JournalWrite::Conflict => continue,
            }
        }
        Err(IpsecLbError::ownership_conflict(
            "session re-pin retirement journal CAS attempts exhausted",
        ))
    }

    async fn record_cleanup_complete_inner(
        &self,
        expected: &SessionRePinRetirementProgress,
        pending: &PendingOwnershipRetirement,
    ) -> Result<SessionRePinRetirementProgress, IpsecLbError> {
        for _ in 0..SESSION_REPIN_MAX_CAS_ATTEMPTS {
            let session_id = expected.checkpoint.plan().session_id();
            let Some((record, entry)) = self.read_entry(session_id).await? else {
                return Err(IpsecLbError::NotFound);
            };
            let SessionRePinJournalEntry::Retiring(current) = entry else {
                return Err(progress_conflict());
            };
            if current != *expected {
                return Err(progress_conflict());
            }
            let desired = current.with_cleanup_complete(pending)?;
            match self
                .write_entry(Some(&record), &SessionRePinJournalEntry::Retiring(desired))
                .await?
            {
                JournalWrite::Committed(SessionRePinJournalEntry::Retiring(progress)) => {
                    return Ok(progress);
                }
                JournalWrite::Committed(_) => return Err(progress_conflict()),
                JournalWrite::Conflict => continue,
            }
        }
        Err(IpsecLbError::ownership_conflict(
            "session re-pin retirement journal CAS attempts exhausted",
        ))
    }

    async fn record_ownership_finalized_inner(
        &self,
        expected: &SessionRePinRetirementProgress,
        finalized: &OwnershipRetirementFinalizedProof,
    ) -> Result<SessionRePinRetirementProgress, IpsecLbError> {
        let desired = expected.with_ownership_finalized(finalized)?;
        for _ in 0..SESSION_REPIN_MAX_CAS_ATTEMPTS {
            let session_id = expected.checkpoint.plan().session_id();
            let Some((record, entry)) = self.read_entry(session_id).await? else {
                return Err(IpsecLbError::NotFound);
            };
            let SessionRePinJournalEntry::Retiring(current) = entry else {
                return Err(progress_conflict());
            };
            if current == desired {
                return Ok(current);
            }
            if current != *expected {
                return Err(progress_conflict());
            }
            match self
                .write_entry(
                    Some(&record),
                    &SessionRePinJournalEntry::Retiring(desired.clone()),
                )
                .await?
            {
                JournalWrite::Committed(SessionRePinJournalEntry::Retiring(progress)) => {
                    return Ok(progress);
                }
                JournalWrite::Committed(_) => return Err(progress_conflict()),
                JournalWrite::Conflict => continue,
            }
        }
        Err(IpsecLbError::ownership_conflict(
            "session re-pin retirement journal CAS attempts exhausted",
        ))
    }

    async fn record_ownership_superseded_inner(
        &self,
        expected: &SessionRePinRetirementProgress,
        proof: &OwnershipRetirementSupersededProof,
    ) -> Result<SessionRePinRetirementProgress, IpsecLbError> {
        for _ in 0..SESSION_REPIN_MAX_CAS_ATTEMPTS {
            let session_id = expected.checkpoint.plan().session_id();
            let Some((record, entry)) = self.read_entry(session_id).await? else {
                return Err(IpsecLbError::NotFound);
            };
            let SessionRePinJournalEntry::Retiring(current) = entry else {
                return Err(progress_conflict());
            };
            if current != *expected {
                return Err(progress_conflict());
            }
            let desired = current.with_superseded(proof)?;
            match self
                .write_entry(Some(&record), &SessionRePinJournalEntry::Retiring(desired))
                .await?
            {
                JournalWrite::Committed(SessionRePinJournalEntry::Retiring(progress)) => {
                    return Ok(progress);
                }
                JournalWrite::Committed(_) => return Err(progress_conflict()),
                JournalWrite::Conflict => continue,
            }
        }
        Err(IpsecLbError::ownership_conflict(
            "session re-pin retirement journal CAS attempts exhausted",
        ))
    }

    async fn finish_steering_retirement_inner(
        &self,
        expected: &SessionRePinRetirementProgress,
    ) -> Result<SessionRePinRetirementOutcome, IpsecLbError> {
        expected.validate()?;
        if !expected.is_complete() {
            return Err(progress_conflict());
        }
        for _ in 0..SESSION_REPIN_MAX_CAS_ATTEMPTS {
            let session_id = expected.checkpoint.plan().session_id();
            let Some((record, entry)) = self.read_entry(session_id).await? else {
                return Err(IpsecLbError::NotFound);
            };
            match entry {
                SessionRePinJournalEntry::Retired(tombstone)
                    if tombstone.exact_identity(session_id, expected.identity()) =>
                {
                    tombstone.validate()?;
                    return Ok(tombstone.outcome(SessionRePinRetirementDisposition::AlreadyRetired));
                }
                SessionRePinJournalEntry::Retiring(current) if current == *expected => {}
                SessionRePinJournalEntry::Active(_)
                | SessionRePinJournalEntry::Retiring(_)
                | SessionRePinJournalEntry::Retired(_) => return Err(progress_conflict()),
            }
            let retired_at = self.clock.now_utc();
            let retained_until =
                checked_session_deadline(retired_at, SESSION_REPIN_RETIREMENT_RETENTION)
                    .map_err(map_store_error)?;
            let tombstone = SessionRePinRetirementTombstone::from_terminal(
                &expected.checkpoint,
                record.owner.clone(),
                retired_at,
                retained_until,
            )?;
            match self
                .write_entry(Some(&record), &SessionRePinJournalEntry::Retired(tombstone))
                .await?
            {
                JournalWrite::Committed(SessionRePinJournalEntry::Retired(tombstone)) => {
                    return Ok(tombstone.outcome(SessionRePinRetirementDisposition::Retired));
                }
                JournalWrite::Committed(_) => return Err(progress_conflict()),
                JournalWrite::Conflict => continue,
            }
        }
        Err(IpsecLbError::ownership_conflict(
            "session re-pin retirement journal CAS attempts exhausted",
        ))
    }

    #[cfg(test)]
    async fn retire(
        &self,
        session_id: &SessionRePinSessionId,
        identity: SessionRePinIdentity,
    ) -> Result<SessionRePinRetirementOutcome, IpsecLbError> {
        for _ in 0..SESSION_REPIN_MAX_CAS_ATTEMPTS {
            let Some((record, entry)) = self.read_entry(session_id).await? else {
                return Err(IpsecLbError::NotFound);
            };
            let checkpoint = match entry {
                SessionRePinJournalEntry::Active(checkpoint) => checkpoint,
                SessionRePinJournalEntry::Retiring(_) => return Err(progress_conflict()),
                SessionRePinJournalEntry::Retired(tombstone) => {
                    if tombstone.exact_identity(session_id, identity) {
                        tombstone.validate()?;
                        return Ok(
                            tombstone.outcome(SessionRePinRetirementDisposition::AlreadyRetired)
                        );
                    }
                    return Err(progress_conflict());
                }
            };
            if checkpoint.plan().identity() != identity || !checkpoint.is_complete() {
                return Err(progress_conflict());
            }

            let retired_at = self.clock.now_utc();
            let retained_until =
                checked_session_deadline(retired_at, SESSION_REPIN_RETIREMENT_RETENTION)
                    .map_err(map_store_error)?;
            let tombstone = SessionRePinRetirementTombstone::from_terminal(
                &checkpoint,
                record.owner.clone(),
                retired_at,
                retained_until,
            )?;
            let desired = SessionRePinJournalEntry::Retired(tombstone);
            match self.write_entry(Some(&record), &desired).await? {
                JournalWrite::Committed(SessionRePinJournalEntry::Retired(tombstone)) => {
                    return Ok(tombstone.outcome(SessionRePinRetirementDisposition::Retired));
                }
                JournalWrite::Committed(SessionRePinJournalEntry::Active(_)) => {
                    return Err(progress_conflict());
                }
                JournalWrite::Committed(SessionRePinJournalEntry::Retiring(_)) => {
                    return Err(progress_conflict());
                }
                JournalWrite::Conflict => continue,
            }
        }
        Err(IpsecLbError::ownership_conflict(
            "session re-pin journal CAS attempts exhausted",
        ))
    }

    async fn write_entry(
        &self,
        current: Option<&StoredSessionRecord>,
        desired: &SessionRePinJournalEntry,
    ) -> Result<JournalWrite, IpsecLbError> {
        let key = self.key(desired.session_id())?;
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
        let owner = desired.owner()?;
        let payload = match desired {
            SessionRePinJournalEntry::Active(checkpoint) => encode_checkpoint(checkpoint)?,
            SessionRePinJournalEntry::Retiring(progress) => encode_retiring(progress)?,
            SessionRePinJournalEntry::Retired(tombstone) => encode_retirement(tombstone)?,
        };
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
            expires_at: desired.expires_at(),
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
                    let observed = decode_journal_record(&record, &key, desired.session_id())?;
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
        desired: &SessionRePinJournalEntry,
    ) -> Result<Option<SessionRePinJournalEntry>, IpsecLbError> {
        let Some(record) = self.backend.get(key).await.map_err(map_store_error)? else {
            return Ok(None);
        };
        let observed = decode_journal_record(&record, key, desired.session_id())?;
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
        self.read_entry(session_id).await.map(|record| {
            record.and_then(|value| match value.1 {
                SessionRePinJournalEntry::Active(checkpoint) => Some(checkpoint),
                SessionRePinJournalEntry::Retiring(_) | SessionRePinJournalEntry::Retired(_) => {
                    None
                }
            })
        })
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

    async fn begin_steering_retirement(
        &self,
        session_id: &SessionRePinSessionId,
        identity: SessionRePinIdentity,
    ) -> Result<SessionRePinRetirementResume, IpsecLbError> {
        self.begin_steering_retirement_inner(session_id, identity)
            .await
    }

    async fn record_cleanup_complete(
        &self,
        progress: &SessionRePinRetirementProgress,
        pending: &PendingOwnershipRetirement,
    ) -> Result<
        (
            SessionRePinRetirementProgress,
            OwnershipCleanupCompleteProof,
        ),
        IpsecLbError,
    > {
        let updated = self
            .record_cleanup_complete_inner(progress, pending)
            .await?;
        Ok((
            updated,
            OwnershipCleanupCompleteProof::new(pending.grant().clone()),
        ))
    }

    async fn record_ownership_finalized(
        &self,
        progress: &SessionRePinRetirementProgress,
        finalized: &OwnershipRetirementFinalizedProof,
    ) -> Result<SessionRePinRetirementProgress, IpsecLbError> {
        self.record_ownership_finalized_inner(progress, finalized)
            .await
    }

    async fn record_ownership_superseded(
        &self,
        progress: &SessionRePinRetirementProgress,
        proof: &OwnershipRetirementSupersededProof,
    ) -> Result<SessionRePinRetirementProgress, IpsecLbError> {
        self.record_ownership_superseded_inner(progress, proof)
            .await
    }

    async fn finish_steering_retirement(
        &self,
        progress: &SessionRePinRetirementProgress,
    ) -> Result<SessionRePinRetirementOutcome, IpsecLbError> {
        self.finish_steering_retirement_inner(progress).await
    }
}

#[derive(Clone, Copy)]
enum JournalMutation {
    OwnershipCommitted { index: usize, fence: OwnershipFence },
    SaComplete { index: usize, fence: OwnershipFence },
}

// Writes normally commit an entry, so retain it inline instead of allocating on
// every journal transition merely to shrink the uncommon conflict variant.
#[allow(clippy::large_enum_variant)]
enum JournalWrite {
    Committed(SessionRePinJournalEntry),
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
        SessionPayloadVersion::new(SESSION_REPIN_CHECKPOINT_PAYLOAD_VERSION),
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

fn encode_retirement(
    tombstone: &SessionRePinRetirementTombstone,
) -> Result<EncryptedSessionPayload, IpsecLbError> {
    tombstone.validate()?;
    let wire = RetirementWire::from_tombstone(tombstone);
    encode_json_payload(
        &journal_payload_format()?,
        SessionPayloadVersion::new(SESSION_REPIN_RETIREMENT_PAYLOAD_VERSION),
        &wire,
        Some(SESSION_REPIN_JOURNAL_MAX_BYTES),
    )
    .map_err(|_| {
        IpsecLbError::invalid_config(
            "session_repin.payload",
            "session re-pin retirement encoding failed",
        )
    })
}

fn encode_retiring(
    progress: &SessionRePinRetirementProgress,
) -> Result<EncryptedSessionPayload, IpsecLbError> {
    progress.validate()?;
    let wire = RetiringWire::from_progress(progress);
    encode_json_payload(
        &journal_payload_format()?,
        SessionPayloadVersion::new(SESSION_REPIN_RETIRING_PAYLOAD_VERSION),
        &wire,
        Some(SESSION_REPIN_JOURNAL_MAX_BYTES),
    )
    .map_err(|_| {
        IpsecLbError::invalid_config(
            "session_repin.payload",
            "session re-pin retiring progress encoding failed",
        )
    })
}

fn decode_journal_record(
    record: &StoredSessionRecord,
    expected_key: &SessionKey,
    expected_session_id: &SessionRePinSessionId,
) -> Result<SessionRePinJournalEntry, IpsecLbError> {
    if &record.key != expected_key
        || record.key.key_type.as_str() != SESSION_REPIN_KEY_TYPE
        || record.state_type.as_str() != SESSION_REPIN_KEY_TYPE
        || record.state_class != StateClass::AuthoritativeSession
        || record.generation.get() == 0
        || record.fence.get() == 0
        || record.payload.encoding() != SessionPayloadEncoding::Plaintext
    {
        return Err(IpsecLbError::invalid_config(
            "session_repin.record",
            "session re-pin journal metadata is invalid",
        ));
    }
    let format = journal_payload_format()?;
    let envelope =
        decode_session_payload_envelope(&record.payload, Some(SESSION_REPIN_JOURNAL_MAX_BYTES))
            .map_err(|_| unreadable_journal_payload())?;
    if envelope.format() != &format
        || envelope.content_type() != Some(SESSION_PAYLOAD_JSON_CONTENT_TYPE)
    {
        return Err(unreadable_journal_payload());
    }

    match envelope.version().get() {
        SESSION_REPIN_CHECKPOINT_PAYLOAD_VERSION => {
            if record.expires_at.is_some() {
                return Err(invalid_journal_metadata());
            }
            let wire: JournalWire = decode_json_payload(
                &record.payload,
                &format,
                SessionPayloadVersion::new(SESSION_REPIN_CHECKPOINT_PAYLOAD_VERSION),
                Some(SESSION_REPIN_JOURNAL_MAX_BYTES),
            )
            .map_err(|_| unreadable_journal_payload())?;
            let checkpoint = wire.into_checkpoint()?;
            if checkpoint.plan().session_id() != expected_session_id
                || record.owner.as_str() != checkpoint.plan().new_owner().as_str()
            {
                return Err(progress_conflict());
            }
            Ok(SessionRePinJournalEntry::Active(checkpoint))
        }
        SESSION_REPIN_RETIRING_PAYLOAD_VERSION => {
            if record.expires_at.is_some() {
                return Err(invalid_journal_metadata());
            }
            let wire: RetiringWire = decode_json_payload(
                &record.payload,
                &format,
                SessionPayloadVersion::new(SESSION_REPIN_RETIRING_PAYLOAD_VERSION),
                Some(SESSION_REPIN_JOURNAL_MAX_BYTES),
            )
            .map_err(|_| unreadable_journal_payload())?;
            let progress = wire.into_progress()?;
            if progress.checkpoint.plan().session_id() != expected_session_id
                || record.owner.as_str() != progress.checkpoint.plan().new_owner().as_str()
            {
                return Err(progress_conflict());
            }
            Ok(SessionRePinJournalEntry::Retiring(progress))
        }
        SESSION_REPIN_RETIREMENT_PAYLOAD_VERSION => {
            let wire: RetirementWire = decode_json_payload(
                &record.payload,
                &format,
                SessionPayloadVersion::new(SESSION_REPIN_RETIREMENT_PAYLOAD_VERSION),
                Some(SESSION_REPIN_JOURNAL_MAX_BYTES),
            )
            .map_err(|_| unreadable_journal_payload())?;
            let tombstone = wire.into_tombstone()?;
            tombstone.validate()?;
            if &tombstone.session_id != expected_session_id
                || record.owner != tombstone.owner
                || record.expires_at != Some(tombstone.retained_until)
            {
                return Err(progress_conflict());
            }
            Ok(SessionRePinJournalEntry::Retired(tombstone))
        }
        _ => Err(unreadable_journal_payload()),
    }
}

fn invalid_journal_metadata() -> IpsecLbError {
    IpsecLbError::invalid_config(
        "session_repin.record",
        "session re-pin journal metadata is invalid",
    )
}

fn unreadable_journal_payload() -> IpsecLbError {
    IpsecLbError::invalid_config(
        "session_repin.payload",
        "session re-pin journal payload is unreadable",
    )
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

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetiringWire {
    checkpoint: JournalWire,
    retirement_markers: Vec<RetirementMarkerWire>,
    ownership_finalized_count: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "disposition", rename_all = "snake_case", deny_unknown_fields)]
enum RetirementMarkerWire {
    CleanupComplete { authoritative_fence: u64 },
    Superseded { authoritative_fence: u64 },
}

impl RetiringWire {
    fn from_progress(progress: &SessionRePinRetirementProgress) -> Self {
        Self {
            checkpoint: JournalWire::from_checkpoint(&progress.checkpoint),
            retirement_markers: progress
                .retirement_markers
                .iter()
                .map(|marker| match marker {
                    OwnershipRetirementMarker::CleanupComplete(fence) => {
                        RetirementMarkerWire::CleanupComplete {
                            authoritative_fence: fence.get(),
                        }
                    }
                    OwnershipRetirementMarker::Superseded(fence) => {
                        RetirementMarkerWire::Superseded {
                            authoritative_fence: fence.get(),
                        }
                    }
                })
                .collect(),
            ownership_finalized_count: progress.ownership_finalized_count,
        }
    }

    fn into_progress(self) -> Result<SessionRePinRetirementProgress, IpsecLbError> {
        if self.retirement_markers.len() > MAX_SESSION_REPIN_SAS {
            return Err(progress_conflict());
        }
        let checkpoint = self.checkpoint.into_checkpoint()?;
        let markers = self
            .retirement_markers
            .into_iter()
            .map(|marker| match marker {
                RetirementMarkerWire::CleanupComplete {
                    authoritative_fence,
                } => OwnershipFence::new(authoritative_fence)
                    .map(OwnershipRetirementMarker::CleanupComplete),
                RetirementMarkerWire::Superseded {
                    authoritative_fence,
                } => OwnershipFence::new(authoritative_fence)
                    .map(OwnershipRetirementMarker::Superseded),
            })
            .collect::<Result<Vec<_>, _>>()?;
        SessionRePinRetirementProgress::from_progress(
            checkpoint,
            markers,
            self.ownership_finalized_count,
        )
    }
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
struct RetirementWire {
    session_id: Vec<u8>,
    operation_id: u128,
    plan_fingerprint: [u8; 32],
    owner: String,
    retired_at: Timestamp,
    expires_at: Timestamp,
    retirement_fingerprint: [u8; 32],
}

impl RetirementWire {
    fn from_tombstone(tombstone: &SessionRePinRetirementTombstone) -> Self {
        Self {
            session_id: tombstone.session_id.as_stable_id().as_bytes().to_vec(),
            operation_id: tombstone.identity.operation_id().get(),
            plan_fingerprint: tombstone.identity.fingerprint().as_bytes(),
            owner: tombstone.owner.as_str().to_owned(),
            retired_at: tombstone.retired_at,
            expires_at: tombstone.retained_until,
            retirement_fingerprint: tombstone.fingerprint,
        }
    }

    fn into_tombstone(self) -> Result<SessionRePinRetirementTombstone, IpsecLbError> {
        let stable_id = StableId::new(Bytes::from(self.session_id)).map_err(|_| {
            IpsecLbError::invalid_config(
                "session_repin.session_id",
                "session re-pin session identity is invalid",
            )
        })?;
        let operation_id = SessionRePinOperationId::new(self.operation_id)?;
        let owner = OwnerId::new(self.owner).map_err(|_| {
            IpsecLbError::invalid_config("session_repin.owner", "session re-pin owner is invalid")
        })?;
        let tombstone = SessionRePinRetirementTombstone {
            session_id: SessionRePinSessionId::from_stable_id(stable_id),
            identity: SessionRePinIdentity::new(
                operation_id,
                SessionRePinPlanFingerprint::from_bytes(self.plan_fingerprint),
            ),
            owner,
            retired_at: self.retired_at,
            retained_until: self.expires_at,
            fingerprint: self.retirement_fingerprint,
        };
        tombstone.validate()?;
        Ok(tombstone)
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
    ownership_key: Vec<u8>,
    outbound_sa_binding_id: Option<[u8; 32]>,
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
            ownership_key: request.ownership_key.to_canonical_bytes(),
            outbound_sa_binding_id: request
                .outbound_sa_binding_id
                .map(OutboundSaBindingId::to_bytes),
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
            ownership_key: SessionOwnershipKey::from_canonical_bytes(&self.ownership_key)
                .map_err(|_| invalid_wire())?,
            outbound_sa_binding_id: self
                .outbound_sa_binding_id
                .map(OutboundSaBindingId::from_bytes),
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
        StoreError::TopologyAuthorityRevoked => IpsecLbError::ownership_conflict(
            "session re-pin journal topology authority was revoked",
        ),
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
        SessionOpResult, SessionPayloadEncoding, SessionStore, SqliteSessionBackend,
    };

    use super::*;
    use crate::failover::MIN_SEND_IV_FORWARD_JUMP;
    use crate::mock::{
        MockOwnershipFencer, MockOwnershipSource, MockRePinAuditSink, MockSteeringBackend,
        MockSteeringOperation,
    };
    use crate::ownership::{
        DestinationContext, EspEncapsulationKind, EspOwnershipKey, EspSpi,
        EstablishedIkeOwnershipKey, IkeSpi, RoutingDomainTag,
    };
    use crate::ports::SteeringBackend;

    use crate::repin::{
        OwnershipFenceGrant, OwnershipFenceRequest, OwnershipRetryProof, OwnershipSnapshot,
        OwnershipTransitionFingerprint,
    };
    macro_rules! test_repin {
        ($steering:expr, $fencer:expr, $ownership:expr, $audit:expr $(,)?) => {
            RePinCoordinator::new($steering, $fencer, $ownership, $audit)
                .with_test_applied_esp_counter_proof()
        };
    }

    #[test]
    fn topology_authority_revocation_maps_to_ownership_conflict() {
        assert!(matches!(
            map_store_error(StoreError::TopologyAuthorityRevoked),
            IpsecLbError::OwnershipConflict { .. }
        ));
    }

    const SESSION_SA_COUNT: usize = 4;
    static NEXT_TEST_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

    #[derive(Debug)]
    struct TestDirectory(std::path::PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let base = std::env::temp_dir();
            for _ in 0..100 {
                let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let path = base.join(format!(
                    "opc-ipsec-lb-{label}-{}-{sequence}",
                    std::process::id()
                ));
                match std::fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("failed to create test directory: {error}"),
                }
            }
            panic!("failed to allocate a unique test directory");
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

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

    fn ownership_key(sa: SaId) -> SessionOwnershipKey {
        let destination = DestinationContext::new(
            crate::IpAddress::V4([192, 0, 2, 30]),
            RoutingDomainTag::new(7),
        );
        match sa {
            SaId::Esp { spi } => SessionOwnershipKey::Esp(EspOwnershipKey::new(
                destination,
                EspEncapsulationKind::UdpEncapsulated,
                EspSpi::new(spi).unwrap(),
            )),
            SaId::Ike { responder_spi } => {
                SessionOwnershipKey::EstablishedIke(EstablishedIkeOwnershipKey::new(
                    destination,
                    IkeSpi::new(21).unwrap(),
                    IkeSpi::new(responder_spi).unwrap(),
                ))
            }
        }
    }

    fn outbound_sa_binding_id(sa: SaId) -> Option<OutboundSaBindingId> {
        match sa {
            SaId::Esp { spi } => {
                let mut bytes = [0x44; 32];
                bytes[..4].copy_from_slice(&spi.to_be_bytes());
                Some(OutboundSaBindingId::from_bytes(bytes))
            }
            SaId::Ike { .. } => None,
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
            ownership_key: ownership_key(sa),
            outbound_sa_binding_id: outbound_sa_binding_id(sa),
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
    impl RePinSteeringBackend for BlockingSteering {
        async fn apply_fenced_repin(
            &self,
            update: crate::RePinSteeringUpdate,
            permit: crate::RePinSteeringOperationPermit,
        ) -> Result<crate::RePinSteeringOperationPermit, IpsecLbError> {
            if self.block.load(Ordering::SeqCst) {
                self.entered.store(true, Ordering::SeqCst);
                self.release.notified().await;
            }
            self.inner.apply_fenced_repin(update, permit).await
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
    impl RePinSteeringBackend for SelectiveInstallBarrier {
        async fn apply_fenced_repin(
            &self,
            update: crate::RePinSteeringUpdate,
            permit: crate::RePinSteeringOperationPermit,
        ) -> Result<crate::RePinSteeringOperationPermit, IpsecLbError> {
            let rule = update.rule();
            if rule == self.rule && self.armed.swap(false, Ordering::SeqCst) {
                self.entered.store(true, Ordering::SeqCst);
                self.release.notified().await;
            }
            self.inner.apply_fenced_repin(update, permit).await
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
            let loaded = self.inner.load(session_id).await;
            self.block_if_selected(3).await;
            loaded
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

    #[derive(Debug, Clone)]
    struct RetirementTestAuthority {
        states: Arc<Mutex<BTreeMap<SessionOwnershipKey, RetirementAuthorityState>>>,
        begin_calls: Arc<AtomicUsize>,
        finalize_calls: Arc<AtomicUsize>,
        fence_calls: Arc<AtomicUsize>,
        fail_begin_on_call: Arc<Mutex<Option<usize>>>,
        fail_finalize_on_call: Arc<Mutex<Option<usize>>>,
    }

    #[derive(Debug, Clone)]
    enum RetirementAuthorityState {
        Active(OwnershipFenceGrant),
        Retiring(OwnershipRetirementGrant),
        Deleted,
    }

    impl RetirementTestAuthority {
        fn from_plan(plan: &SessionRePinPlan, fence: OwnershipFence) -> Self {
            let states = plan
                .requests()
                .iter()
                .map(|request| {
                    (
                        request.ownership_key,
                        RetirementAuthorityState::Active(OwnershipFenceGrant {
                            sa: request.sa,
                            ownership_key: request.ownership_key,
                            transition_id: request.transition_id,
                            fingerprint: request.ownership_fingerprint(),
                            owner: request.new_owner.clone(),
                            fence,
                        }),
                    )
                })
                .collect();
            Self {
                states: Arc::new(Mutex::new(states)),
                begin_calls: Arc::new(AtomicUsize::new(0)),
                finalize_calls: Arc::new(AtomicUsize::new(0)),
                fence_calls: Arc::new(AtomicUsize::new(0)),
                fail_begin_on_call: Arc::new(Mutex::new(None)),
                fail_finalize_on_call: Arc::new(Mutex::new(None)),
            }
        }

        fn fail_begin_on_call(&self, call: usize) {
            *lock_unpoisoned(&self.fail_begin_on_call) = Some(call);
        }

        fn fail_finalize_on_call(&self, call: usize) {
            *lock_unpoisoned(&self.fail_finalize_on_call) = Some(call);
        }

        fn install_successor(&self, request: &RePinRequest, fence: OwnershipFence) {
            let mut fingerprint = request.ownership_fingerprint().as_bytes();
            fingerprint[0] ^= 0x80;
            lock_unpoisoned(&self.states).insert(
                request.ownership_key,
                RetirementAuthorityState::Active(OwnershipFenceGrant {
                    sa: request.sa,
                    ownership_key: request.ownership_key,
                    transition_id: OwnershipTransitionId::new(request.transition_id.get() + 10_000)
                        .expect("nonzero"),
                    fingerprint: OwnershipTransitionFingerprint::from_bytes(fingerprint),
                    owner: ClusterNode::new("newer-owner"),
                    fence,
                }),
            );
        }

        fn grant_matches_request(
            grant: &OwnershipFenceGrant,
            request: &OwnershipFenceRequest,
        ) -> bool {
            grant.sa == request.sa
                && grant.ownership_key == request.ownership_key
                && grant.transition_id == request.transition_id
                && grant.fingerprint == request.fingerprint
                && grant.owner == request.new_owner
        }
    }

    #[async_trait]
    impl OwnershipFencer for RetirementTestAuthority {
        async fn recover_fence_grant(
            &self,
            request: &OwnershipFenceRequest,
        ) -> Result<Option<OwnershipFenceGrant>, IpsecLbError> {
            match lock_unpoisoned(&self.states).get(&request.ownership_key) {
                Some(RetirementAuthorityState::Active(grant))
                    if Self::grant_matches_request(grant, request) =>
                {
                    Ok(Some(grant.clone()))
                }
                Some(RetirementAuthorityState::Active(_)) => Err(IpsecLbError::ownership_conflict(
                    "test authority contains a different active lineage",
                )),
                Some(RetirementAuthorityState::Retiring(_)) => Err(
                    IpsecLbError::ownership_conflict("test authority is retiring"),
                ),
                Some(RetirementAuthorityState::Deleted) | None => Err(IpsecLbError::NotFound),
            }
        }

        async fn fence_sa_owner(
            &self,
            request: OwnershipFenceRequest,
        ) -> Result<OwnershipFenceGrant, IpsecLbError> {
            self.fence_calls.fetch_add(1, Ordering::SeqCst);
            let mut states = lock_unpoisoned(&self.states);
            let Some(RetirementAuthorityState::Active(current)) =
                states.get(&request.ownership_key)
            else {
                return Err(IpsecLbError::NotFound);
            };
            if current.owner != request.previous_owner || current.fence != request.previous_fence {
                return Err(IpsecLbError::ownership_conflict(
                    "test activation predecessor changed",
                ));
            }
            let grant = OwnershipFenceGrant {
                sa: request.sa,
                ownership_key: request.ownership_key,
                transition_id: request.transition_id,
                fingerprint: request.fingerprint,
                owner: request.new_owner,
                fence: OwnershipFence::new(current.fence.get() + 1)?,
            };
            states.insert(
                request.ownership_key,
                RetirementAuthorityState::Active(grant.clone()),
            );
            Ok(grant)
        }

        async fn validate_retry_proof(
            &self,
            proof: &OwnershipRetryProof,
        ) -> Result<(), IpsecLbError> {
            match lock_unpoisoned(&self.states).get(&proof.ownership_key()) {
                Some(RetirementAuthorityState::Active(grant))
                    if grant.sa == proof.sa()
                        && grant.ownership_key == proof.ownership_key()
                        && grant.transition_id == proof.transition_id()
                        && grant.fingerprint == proof.fingerprint()
                        && grant.owner == *proof.owner()
                        && grant.fence == proof.fence() =>
                {
                    Ok(())
                }
                _ => Err(IpsecLbError::ownership_conflict(
                    "test retry proof is no longer active",
                )),
            }
        }
    }

    #[async_trait]
    impl OwnershipRetirementAuthority for RetirementTestAuthority {
        async fn begin_ownership_retirement(
            &self,
            request: OwnershipRetirementRequest,
        ) -> Result<crate::OwnershipRetirementAdmission, IpsecLbError> {
            let call = self.begin_calls.fetch_add(1, Ordering::SeqCst) + 1;
            if *lock_unpoisoned(&self.fail_begin_on_call) == Some(call) {
                *lock_unpoisoned(&self.fail_begin_on_call) = None;
                return Err(IpsecLbError::Unsupported);
            }
            let mut states = lock_unpoisoned(&self.states);
            match states.get(&request.ownership_key()).cloned() {
                Some(RetirementAuthorityState::Active(grant))
                    if grant.sa == request.sa()
                        && grant.transition_id == request.transition_id()
                        && grant.fingerprint == request.fingerprint()
                        && grant.owner == *request.owner()
                        && grant.fence == request.active_fence() =>
                {
                    let retired = OwnershipRetirementGrant::new(
                        request.clone(),
                        OwnershipFence::new(request.active_fence().get() + 1)?,
                    );
                    states.insert(
                        request.ownership_key(),
                        RetirementAuthorityState::Retiring(retired.clone()),
                    );
                    Ok(crate::OwnershipRetirementAdmission::Granted(retired))
                }
                Some(RetirementAuthorityState::Retiring(grant)) if grant.request() == &request => {
                    Ok(crate::OwnershipRetirementAdmission::Granted(grant))
                }
                Some(RetirementAuthorityState::Active(grant))
                    if grant.fence > request.active_fence()
                        && (grant.transition_id != request.transition_id()
                            || grant.fingerprint != request.fingerprint()) =>
                {
                    Ok(crate::OwnershipRetirementAdmission::Superseded(
                        OwnershipRetirementSupersededProof::new(request, grant.fence),
                    ))
                }
                Some(RetirementAuthorityState::Deleted) | None => Err(IpsecLbError::NotFound),
                _ => Err(IpsecLbError::ownership_conflict(
                    "test retirement request does not match authority",
                )),
            }
        }

        async fn finalize_ownership_retirement(
            &self,
            cleanup: &OwnershipCleanupCompleteProof,
        ) -> Result<crate::OwnershipRetirementFinalization, IpsecLbError> {
            let call = self.finalize_calls.fetch_add(1, Ordering::SeqCst) + 1;
            if *lock_unpoisoned(&self.fail_finalize_on_call) == Some(call) {
                *lock_unpoisoned(&self.fail_finalize_on_call) = None;
                return Err(IpsecLbError::Unsupported);
            }
            let key = cleanup.grant().request().ownership_key();
            let mut states = lock_unpoisoned(&self.states);
            match states.get(&key) {
                Some(RetirementAuthorityState::Retiring(grant)) if grant == cleanup.grant() => {
                    states.insert(key, RetirementAuthorityState::Deleted);
                    Ok(crate::OwnershipRetirementFinalization::Deleted)
                }
                Some(RetirementAuthorityState::Deleted) | None => {
                    Ok(crate::OwnershipRetirementFinalization::AlreadyDeleted)
                }
                Some(RetirementAuthorityState::Active(grant))
                    if grant.fence > cleanup.grant().retirement_fence() =>
                {
                    Ok(crate::OwnershipRetirementFinalization::Superseded)
                }
                _ => Err(IpsecLbError::ownership_conflict(
                    "test cleanup proof does not match authority",
                )),
            }
        }
    }

    struct RetirementTestGuard {
        _guard: tokio::sync::OwnedMutexGuard<()>,
    }

    #[derive(Debug, Clone)]
    struct RetirementTestSteering {
        gate: Arc<tokio::sync::Mutex<()>>,
        batch_acquires: Arc<AtomicUsize>,
        host_calls: Arc<AtomicUsize>,
        fail_acquire: Arc<AtomicBool>,
        block_host: Arc<AtomicBool>,
        host_entered: Arc<AtomicBool>,
        host_release: Arc<Notify>,
    }

    impl RetirementTestSteering {
        fn new() -> Self {
            Self {
                gate: Arc::new(tokio::sync::Mutex::new(())),
                batch_acquires: Arc::new(AtomicUsize::new(0)),
                host_calls: Arc::new(AtomicUsize::new(0)),
                fail_acquire: Arc::new(AtomicBool::new(false)),
                block_host: Arc::new(AtomicBool::new(false)),
                host_entered: Arc::new(AtomicBool::new(false)),
                host_release: Arc::new(Notify::new()),
            }
        }

        fn block_host(&self) {
            self.block_host.store(true, Ordering::SeqCst);
        }

        fn release_host(&self) {
            self.block_host.store(false, Ordering::SeqCst);
            self.host_release.notify_waiters();
        }
    }

    #[async_trait]
    impl RePinSteeringBackend for RetirementTestSteering {
        async fn acquire_repin_permit(
            &self,
            key: SessionOwnershipKey,
        ) -> Result<crate::RePinSteeringOperationPermit, IpsecLbError> {
            if self.fail_acquire.load(Ordering::SeqCst) {
                return Err(IpsecLbError::Unsupported);
            }
            let guard = Arc::clone(&self.gate).lock_owned().await;
            Ok(crate::RePinSteeringOperationPermit::guarded(
                key,
                RetirementTestGuard { _guard: guard },
            ))
        }

        async fn apply_fenced_repin(
            &self,
            update: crate::RePinSteeringUpdate,
            permit: crate::RePinSteeringOperationPermit,
        ) -> Result<crate::RePinSteeringOperationPermit, IpsecLbError> {
            if permit.ownership_key() != update.ownership_key() {
                return Err(IpsecLbError::adapter_contract_violation(
                    "test permit key mismatch",
                ));
            }
            Ok(permit)
        }
    }

    #[async_trait]
    impl RePinSteeringRetirementBackend for RetirementTestSteering {
        async fn acquire_repin_retirement_permits(
            &self,
            keys: Vec<SessionOwnershipKey>,
        ) -> Result<Vec<crate::RePinSteeringOperationPermit>, IpsecLbError> {
            if self.fail_acquire.load(Ordering::SeqCst) || keys.is_empty() {
                return Err(IpsecLbError::Unsupported);
            }
            self.batch_acquires.fetch_add(1, Ordering::SeqCst);
            let guard = Arc::new(RetirementTestGuard {
                _guard: Arc::clone(&self.gate).lock_owned().await,
            });
            Ok(keys
                .into_iter()
                .map(|key| crate::RePinSteeringOperationPermit::guarded(key, Arc::clone(&guard)))
                .collect())
        }

        fn arm_repin_retirement_permit(
            &self,
            permit: crate::RePinSteeringOperationPermit,
        ) -> Result<crate::RePinSteeringOperationPermit, IpsecLbError> {
            Ok(permit)
        }

        fn release_classified_repin_retirement_permit(
            &self,
            _permit: crate::RePinSteeringOperationPermit,
        ) -> Result<(), IpsecLbError> {
            Ok(())
        }

        async fn retire_fenced_repin(
            &self,
            grant: &OwnershipRetirementGrant,
            permit: crate::RePinSteeringOperationPermit,
        ) -> Result<crate::RePinSteeringOperationPermit, IpsecLbError> {
            if permit.ownership_key() != grant.request().ownership_key() {
                return Err(IpsecLbError::adapter_contract_violation(
                    "test retirement permit key mismatch",
                ));
            }
            self.host_calls.fetch_add(1, Ordering::SeqCst);
            if self.block_host.load(Ordering::SeqCst) {
                self.host_entered.store(true, Ordering::SeqCst);
                self.host_release.notified().await;
            }
            Ok(permit)
        }
    }

    #[derive(Debug, Clone)]
    struct RetirementBlockingJournal {
        inner: MockSessionRePinJournal,
        block_stage: Arc<AtomicUsize>,
        entered: Arc<AtomicBool>,
        release: Arc<Notify>,
    }

    impl RetirementBlockingJournal {
        fn new(inner: MockSessionRePinJournal, stage: usize) -> Self {
            Self {
                inner,
                block_stage: Arc::new(AtomicUsize::new(stage)),
                entered: Arc::new(AtomicBool::new(false)),
                release: Arc::new(Notify::new()),
            }
        }

        async fn maybe_block(&self, stage: usize) {
            if self
                .block_stage
                .compare_exchange(stage, 0, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                self.entered.store(true, Ordering::SeqCst);
                self.release.notified().await;
            }
        }

        fn unblock(&self) {
            self.release.notify_waiters();
        }
    }

    #[async_trait]
    impl SessionRePinJournal for RetirementBlockingJournal {
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
            self.inner.record_sa_complete(plan, index, fence).await
        }

        async fn begin_steering_retirement(
            &self,
            session_id: &SessionRePinSessionId,
            identity: SessionRePinIdentity,
        ) -> Result<SessionRePinRetirementResume, IpsecLbError> {
            self.maybe_block(1).await;
            self.inner
                .begin_steering_retirement(session_id, identity)
                .await
        }

        async fn record_cleanup_complete(
            &self,
            progress: &SessionRePinRetirementProgress,
            pending: &PendingOwnershipRetirement,
        ) -> Result<
            (
                SessionRePinRetirementProgress,
                OwnershipCleanupCompleteProof,
            ),
            IpsecLbError,
        > {
            self.maybe_block(2).await;
            self.inner.record_cleanup_complete(progress, pending).await
        }

        async fn record_ownership_superseded(
            &self,
            progress: &SessionRePinRetirementProgress,
            proof: &OwnershipRetirementSupersededProof,
        ) -> Result<SessionRePinRetirementProgress, IpsecLbError> {
            self.inner
                .record_ownership_superseded(progress, proof)
                .await
        }

        async fn record_ownership_finalized(
            &self,
            progress: &SessionRePinRetirementProgress,
            finalized: &OwnershipRetirementFinalizedProof,
        ) -> Result<SessionRePinRetirementProgress, IpsecLbError> {
            self.inner
                .record_ownership_finalized(progress, finalized)
                .await
        }

        async fn finish_steering_retirement(
            &self,
            progress: &SessionRePinRetirementProgress,
        ) -> Result<SessionRePinRetirementOutcome, IpsecLbError> {
            self.inner.finish_steering_retirement(progress).await
        }
    }

    async fn retirement_test_components() -> (
        SessionRePinPlan,
        MockSessionRePinJournal,
        RetirementTestAuthority,
        RetirementTestSteering,
        MockOwnershipSource,
        MockRePinAuditSink,
    ) {
        let plan = plan_with(91, 91, 9_100, MIN_SESSION_REPIN_SAS);
        let journal = MockSessionRePinJournal::default();
        complete_journal_plan(&journal, &plan, 10).await;
        let authority =
            RetirementTestAuthority::from_plan(&plan, OwnershipFence::new(10).expect("nonzero"));
        let steering = RetirementTestSteering::new();
        let ownership = MockOwnershipSource::default();
        ownership.set_shard_owner(plan.requests()[0].rule.owner, plan.new_owner().clone());
        (
            plan,
            journal,
            authority,
            steering,
            ownership,
            MockRePinAuditSink::new(),
        )
    }

    fn retirement_test_coordinator<J>(
        journal: J,
        authority: RetirementTestAuthority,
        steering: RetirementTestSteering,
        ownership: MockOwnershipSource,
        audit: MockRePinAuditSink,
    ) -> SessionRePinCoordinator<
        RetirementTestSteering,
        RetirementTestAuthority,
        MockOwnershipSource,
        MockRePinAuditSink,
        J,
    >
    where
        J: SessionRePinJournal,
    {
        SessionRePinCoordinator::new(test_repin!(steering, authority, ownership, audit), journal)
    }

    fn assert_one_retired_one_already(
        left: &SessionRePinRetirementOutcome,
        right: &SessionRePinRetirementOutcome,
    ) {
        assert!(matches!(
            (left.disposition(), right.disposition()),
            (
                SessionRePinRetirementDisposition::Retired,
                SessionRePinRetirementDisposition::AlreadyRetired
            ) | (
                SessionRePinRetirementDisposition::AlreadyRetired,
                SessionRePinRetirementDisposition::Retired
            )
        ));
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
                inner_fencer.set_owner(request.ownership_key, request.previous_owner.clone());
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
                test_repin!(
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
            test_repin!(
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
            test_repin!(
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
        let direct_per_sa = test_repin!(
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
                    ownership_key: displaced.ownership_key,
                    outbound_sa_binding_id: displaced.outbound_sa_binding_id,
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

        let mut same_spi_in_distinct_scopes = valid.requests().to_vec();
        let shared_sa = same_spi_in_distinct_scopes[1].sa;
        same_spi_in_distinct_scopes[2].sa = shared_sa;
        same_spi_in_distinct_scopes[2].rule.key = same_spi_in_distinct_scopes[1].rule.key;
        same_spi_in_distinct_scopes[2].resume.previous_sa = shared_sa;
        same_spi_in_distinct_scopes[2].resume.resumed_sa = shared_sa;
        let SaId::Esp { spi } = shared_sa else {
            panic!("second request is an ESP SA")
        };
        same_spi_in_distinct_scopes[2].ownership_key =
            SessionOwnershipKey::Esp(EspOwnershipKey::new(
                DestinationContext::new(
                    crate::IpAddress::V4([198, 51, 100, 30]),
                    RoutingDomainTag::new(8),
                ),
                EspEncapsulationKind::UdpEncapsulated,
                EspSpi::new(spi).unwrap(),
            ));
        assert!(SessionRePinPlan::new(
            session_id(1),
            operation_id(30),
            same_spi_in_distinct_scopes,
        )
        .is_ok());

        let mut duplicate_outbound_binding = valid.requests().to_vec();
        duplicate_outbound_binding[2].outbound_sa_binding_id =
            duplicate_outbound_binding[1].outbound_sa_binding_id;
        assert!(
            SessionRePinPlan::new(session_id(1), operation_id(31), duplicate_outbound_binding,)
                .is_err()
        );

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
            SessionPayloadVersion::new(SESSION_REPIN_CHECKPOINT_PAYLOAD_VERSION),
            Some(SESSION_REPIN_JOURNAL_MAX_BYTES),
        )
        .unwrap();
        assert_eq!(decoded.into_checkpoint().unwrap(), checkpoint);
    }

    #[test]
    fn checkpoint_v3_wire_is_canonical_with_destination_scoped_fingerprints() {
        // The first-public journal wire version remains v3. IKE transitions
        // retain the v4 domain while ESP counter transitions carry the v5
        // outbound-binding domain. Keep this synthetic encoding immutable so
        // a wire DTO change cannot self-agree.
        const V3_DESTINATION_SCOPED_SHA256: [u8; 32] = [
            82, 135, 104, 142, 148, 122, 195, 215, 254, 196, 164, 242, 104, 44, 54, 189, 158, 71,
            148, 83, 104, 56, 192, 36, 122, 118, 228, 237, 97, 148, 191, 106,
        ];
        let plan = plan_with(1, 1, 100, 3);
        let checkpoint =
            SessionRePinCheckpoint::from_progress(plan.clone(), Vec::new(), None).unwrap();
        let encoded_v3 = encode_checkpoint(&checkpoint).unwrap();
        let encoded_hash: [u8; 32] = Sha256::digest(encoded_v3.as_bytes()).into();
        assert_eq!(encoded_hash, V3_DESTINATION_SCOPED_SHA256);

        let key = SessionKey {
            tenant: tenant(),
            nf_kind: nf_kind(),
            key_type: SessionKeyType::other(SESSION_REPIN_KEY_TYPE).unwrap(),
            stable_id: plan.session_id().as_stable_id().clone(),
        };
        let record = StoredSessionRecord {
            key: key.clone(),
            generation: Generation::new(1),
            owner: OwnerId::new(plan.new_owner().as_str()).unwrap(),
            fence: opc_session_store::FenceToken::new(1),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::new(SESSION_REPIN_KEY_TYPE).unwrap(),
            expires_at: None,
            payload: encoded_v3,
        };
        let SessionRePinJournalEntry::Active(decoded) =
            decode_journal_record(&record, &key, plan.session_id()).unwrap()
        else {
            panic!("expected v3 checkpoint");
        };
        assert_eq!(decoded, checkpoint);
        assert_eq!(encode_checkpoint(&decoded).unwrap(), record.payload);
    }

    #[test]
    fn legacy_active_v1_envelope_is_explicitly_unreadable() {
        let plan = plan_with(1, 1, 100, 3);
        let checkpoint =
            SessionRePinCheckpoint::from_progress(plan.clone(), Vec::new(), None).unwrap();
        let payload = encode_json_payload(
            &journal_payload_format().unwrap(),
            SessionPayloadVersion::new(1),
            &JournalWire::from_checkpoint(&checkpoint),
            Some(SESSION_REPIN_JOURNAL_MAX_BYTES),
        )
        .unwrap();
        let key = SessionKey {
            tenant: tenant(),
            nf_kind: nf_kind(),
            key_type: SessionKeyType::other(SESSION_REPIN_KEY_TYPE).unwrap(),
            stable_id: plan.session_id().as_stable_id().clone(),
        };
        let record = StoredSessionRecord {
            key: key.clone(),
            generation: Generation::new(1),
            owner: OwnerId::new(plan.new_owner().as_str()).unwrap(),
            fence: opc_session_store::FenceToken::new(1),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::new(SESSION_REPIN_KEY_TYPE).unwrap(),
            expires_at: None,
            payload,
        };

        assert!(decode_journal_record(&record, &key, plan.session_id()).is_err());
    }

    #[tokio::test]
    async fn retirement_v2_tombstone_remains_readable() {
        let store = SessionStore::new(FakeSessionBackend::new());
        let journal = SessionStoreRePinJournal::new(store.clone(), tenant(), nf_kind());
        let plan = plan_with(1, 1, 100, 3);
        complete_journal_plan(&journal, &plan, 2).await;
        journal
            .retire(plan.session_id(), plan.identity())
            .await
            .unwrap();
        let key = journal.key(plan.session_id()).unwrap();
        let record = store.get(&key).await.unwrap().unwrap();
        let envelope =
            decode_session_payload_envelope(&record.payload, Some(SESSION_REPIN_JOURNAL_MAX_BYTES))
                .unwrap();
        assert_eq!(
            envelope.version().get(),
            SESSION_REPIN_RETIREMENT_PAYLOAD_VERSION
        );
        assert!(matches!(
            decode_journal_record(&record, &key, plan.session_id()).unwrap(),
            SessionRePinJournalEntry::Retired(_)
        ));
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

    #[test]
    fn retiring_v4_marker_wire_rejects_unknown_fields_and_nonadvancing_authority() {
        let plan = plan_with(7, 7, 700, MIN_SESSION_REPIN_SAS);
        let active_fence = OwnershipFence::new(10).expect("nonzero");
        let checkpoint = SessionRePinCheckpoint::from_progress(
            plan.clone(),
            vec![active_fence; plan.len()],
            None,
        )
        .expect("terminal checkpoint");
        let progress =
            SessionRePinRetirementProgress::from_terminal(checkpoint).expect("retirement progress");
        let proof = OwnershipRetirementSupersededProof::new(
            OwnershipRetirementRequest::from_committed(&plan.requests()[0], active_fence),
            OwnershipFence::new(11).expect("nonzero"),
        );
        let progress = progress.with_superseded(&proof).expect("superseded marker");
        let wire = RetiringWire::from_progress(&progress);

        let mut unknown = serde_json::to_value(&wire).expect("serialize wire");
        unknown["retirement_markers"][0]["contradictory_fence"] = serde_json::json!(u64::MAX);
        assert!(serde_json::from_value::<RetiringWire>(unknown).is_err());

        let mut nonadvancing = serde_json::to_value(&wire).expect("serialize wire");
        nonadvancing["retirement_markers"][0]["authoritative_fence"] =
            serde_json::json!(active_fence.get());
        let decoded =
            serde_json::from_value::<RetiringWire>(nonadvancing).expect("structurally valid wire");
        assert!(decoded.into_progress().is_err());
    }

    #[tokio::test]
    async fn production_retiring_v4_max_plan_roundtrips_and_rejects_tampering() {
        let store = SessionStore::new(FakeSessionBackend::new());
        let journal = SessionStoreRePinJournal::new(store.clone(), tenant(), nf_kind());
        let plan = plan_with(8, 8, 800, MAX_SESSION_REPIN_SAS);
        complete_journal_plan(&journal, &plan, 10).await;

        let SessionRePinRetirementResume::InProgress(mut progress) = journal
            .begin_steering_retirement(plan.session_id(), plan.identity())
            .await
            .expect("terminal checkpoint enters durable retirement")
        else {
            panic!("fresh terminal checkpoint cannot already be retired");
        };

        let active_fence = progress
            .checkpoint
            .completed_fence(0)
            .expect("terminal plan retains the first active fence");
        let first_grant = OwnershipRetirementGrant::new(
            OwnershipRetirementRequest::from_committed(&plan.requests()[0], active_fence),
            OwnershipFence::new(active_fence.get() + 1).expect("advanced fence"),
        );
        let pending = PendingOwnershipRetirement::for_test(
            first_grant.clone(),
            crate::RePinSteeringOperationPermit::unguarded(plan.requests()[0].ownership_key),
        );
        let (cleanup_progress, _original_cleanup_proof) = journal
            .record_cleanup_complete(&progress, &pending)
            .await
            .expect("CleanupComplete marker is durable");
        drop(pending);

        let restarted = SessionStoreRePinJournal::new(store.clone(), tenant(), nf_kind());
        let SessionRePinRetirementResume::InProgress(recovered_cleanup) = restarted
            .begin_steering_retirement(plan.session_id(), plan.identity())
            .await
            .expect("restart recovers CleanupComplete")
        else {
            panic!("CleanupComplete must remain in non-expiring v4 progress");
        };
        assert_eq!(recovered_cleanup, cleanup_progress);
        assert_eq!(
            recovered_cleanup.grant(0).expect("grant reconstructs"),
            first_grant
        );
        let reconstructed_cleanup = OwnershipCleanupCompleteProof::new(
            recovered_cleanup.grant(0).expect("grant reconstructs"),
        );
        let finalized = OwnershipRetirementFinalizedProof::for_test(
            reconstructed_cleanup,
            crate::OwnershipRetirementFinalization::AlreadyDeleted,
        );
        progress = restarted
            .record_ownership_finalized(&recovered_cleanup, &finalized)
            .await
            .expect("reconstructed cleanup proof finalizes after restart");

        for index in 1..plan.len() {
            let active_fence = progress
                .checkpoint
                .completed_fence(index)
                .expect("terminal plan retains every active fence");
            let proof = OwnershipRetirementSupersededProof::new(
                OwnershipRetirementRequest::from_committed(&plan.requests()[index], active_fence),
                OwnershipFence::new(active_fence.get() + 1).expect("advanced fence"),
            );
            progress = restarted
                .record_ownership_superseded(&progress, &proof)
                .await
                .expect("ordered superseded marker is durable");
        }
        assert_eq!(
            progress.status().ownership_finalized_count(),
            MAX_SESSION_REPIN_SAS
        );

        let key = journal.key(plan.session_id()).expect("journal key");
        let record = store
            .get(&key)
            .await
            .expect("read succeeds")
            .expect("Retiring record exists");
        assert_eq!(record.expires_at, None);
        let envelope =
            decode_session_payload_envelope(&record.payload, Some(SESSION_REPIN_JOURNAL_MAX_BYTES))
                .expect("v4 envelope decodes");
        assert_eq!(
            envelope.version().get(),
            SESSION_REPIN_RETIRING_PAYLOAD_VERSION
        );
        assert!(record.payload.as_bytes().len() <= SESSION_REPIN_JOURNAL_MAX_BYTES);

        let final_restart = SessionStoreRePinJournal::new(store, tenant(), nf_kind());
        let SessionRePinRetirementResume::InProgress(recovered) = final_restart
            .begin_steering_retirement(plan.session_id(), plan.identity())
            .await
            .expect("restart recovers exact v4 progress")
        else {
            panic!("non-expiring Retiring progress must survive restart");
        };
        assert_eq!(recovered, progress);

        let wire: RetiringWire = decode_json_payload(
            &record.payload,
            &journal_payload_format().expect("static payload format"),
            SessionPayloadVersion::new(SESSION_REPIN_RETIRING_PAYLOAD_VERSION),
            Some(SESSION_REPIN_JOURNAL_MAX_BYTES),
        )
        .expect("stored v4 payload decodes");
        let base = serde_json::to_value(wire).expect("v4 wire serializes");
        let assert_rejected = |value: serde_json::Value| {
            let mut tampered = record.clone();
            tampered.payload = encode_json_payload(
                &journal_payload_format().expect("static payload format"),
                SessionPayloadVersion::new(SESSION_REPIN_RETIRING_PAYLOAD_VERSION),
                &value,
                Some(SESSION_REPIN_JOURNAL_MAX_BYTES),
            )
            .expect("tampered fixture remains a valid envelope");
            assert!(decode_journal_record(&tampered, &key, plan.session_id()).is_err());
        };

        let mut unknown = base.clone();
        unknown["unexpected_retirement_authority"] = serde_json::json!(true);
        assert_rejected(unknown);

        let mut nonadvancing = base.clone();
        nonadvancing["retirement_markers"][0]["authoritative_fence"] = serde_json::json!(10);
        assert_rejected(nonadvancing);

        let mut impossible_finalized_count = base;
        impossible_finalized_count["ownership_finalized_count"] =
            serde_json::json!(MAX_SESSION_REPIN_SAS + 1);
        assert_rejected(impossible_finalized_count);

        let retired = final_restart
            .finish_steering_retirement(&recovered)
            .await
            .expect("fully finalized v4 progress becomes a v2 tombstone");
        assert_eq!(
            retired.disposition(),
            SessionRePinRetirementDisposition::Retired
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
    async fn safe_retirement_is_idempotent_for_concurrent_active_and_retiring_callers() {
        let (plan, journal, authority, steering, ownership, audit) =
            retirement_test_components().await;
        let coordinator = retirement_test_coordinator(
            journal.clone(),
            authority.clone(),
            steering.clone(),
            ownership,
            audit,
        );
        let (left, right) = tokio::join!(
            coordinator.retire(plan.session_id(), plan.identity()),
            coordinator.retire(plan.session_id(), plan.identity()),
        );
        let left = left.expect("first concurrent retirement converges");
        let right = right.expect("second concurrent retirement converges");
        assert_one_retired_one_already(&left, &right);
        assert_eq!(steering.host_calls.load(Ordering::SeqCst), plan.len());

        let (plan, journal, authority, steering, ownership, audit) =
            retirement_test_components().await;
        authority.fail_begin_on_call(1);
        let coordinator =
            retirement_test_coordinator(journal, authority, steering, ownership, audit);
        assert!(coordinator
            .retire(plan.session_id(), plan.identity())
            .await
            .is_err());
        let (left, right) = tokio::join!(
            coordinator.retire(plan.session_id(), plan.identity()),
            coordinator.retire(plan.session_id(), plan.identity()),
        );
        let left = left.expect("first Retiring caller converges");
        let right = right.expect("second Retiring caller converges");
        assert_one_retired_one_already(&left, &right);
    }

    #[tokio::test]
    async fn cleanup_marker_resume_needs_no_host_for_the_marked_terminal_key() {
        let (plan, journal, authority, steering, ownership, audit) =
            retirement_test_components().await;
        authority.fail_finalize_on_call(plan.len());
        let coordinator =
            retirement_test_coordinator(journal, authority, steering.clone(), ownership, audit);
        assert!(coordinator
            .retire(plan.session_id(), plan.identity())
            .await
            .is_err());
        let acquired_before = steering.batch_acquires.load(Ordering::SeqCst);
        let host_before = steering.host_calls.load(Ordering::SeqCst);
        assert_eq!(host_before, plan.len());
        steering.fail_acquire.store(true, Ordering::SeqCst);

        let outcome = coordinator
            .retire(plan.session_id(), plan.identity())
            .await
            .expect("durable terminal cleanup marker finalizes without Host");
        assert_eq!(
            outcome.disposition(),
            SessionRePinRetirementDisposition::Retired
        );
        assert_eq!(
            steering.batch_acquires.load(Ordering::SeqCst),
            acquired_before
        );
        assert_eq!(steering.host_calls.load(Ordering::SeqCst), host_before);
    }

    #[tokio::test]
    async fn concurrent_callers_converge_from_the_same_cleanup_marker() {
        let (plan, journal, authority, steering, ownership, audit) =
            retirement_test_components().await;
        authority.fail_finalize_on_call(1);
        let coordinator =
            retirement_test_coordinator(journal, authority, steering, ownership, audit);
        assert!(coordinator
            .retire(plan.session_id(), plan.identity())
            .await
            .is_err());
        let (left, right) = tokio::join!(
            coordinator.retire(plan.session_id(), plan.identity()),
            coordinator.retire(plan.session_id(), plan.identity()),
        );
        let left = left.expect("first cleanup-marker caller converges");
        let right = right.expect("second cleanup-marker caller converges");
        assert_one_retired_one_already(&left, &right);
    }

    #[tokio::test]
    async fn crash_before_later_key_begin_preserves_a_newer_lineage_without_host_cleanup() {
        let (plan, journal, authority, steering, ownership, audit) =
            retirement_test_components().await;
        authority.fail_begin_on_call(1);
        let coordinator = retirement_test_coordinator(
            journal,
            authority.clone(),
            steering.clone(),
            ownership,
            audit,
        );
        assert!(coordinator
            .retire(plan.session_id(), plan.identity())
            .await
            .is_err());
        authority.install_successor(
            &plan.requests()[1],
            OwnershipFence::new(20).expect("nonzero"),
        );

        let outcome = coordinator
            .retire(plan.session_id(), plan.identity())
            .await
            .expect("strictly newer lineage is durably superseded");
        assert_eq!(
            outcome.disposition(),
            SessionRePinRetirementDisposition::Retired
        );
        assert_eq!(steering.host_calls.load(Ordering::SeqCst), 1);
        assert!(matches!(
            lock_unpoisoned(&authority.states).get(&plan.requests()[1].ownership_key),
            Some(RetirementAuthorityState::Active(grant)) if grant.fence.get() == 20
        ));
    }

    #[tokio::test]
    async fn dropping_retirement_observer_never_cancels_session_host_or_marker_work() {
        for stage in 1..=3 {
            let (plan, journal, authority, steering, ownership, audit) =
                retirement_test_components().await;
            let blocking_journal = RetirementBlockingJournal::new(
                journal,
                if stage == 1 {
                    1
                } else if stage == 3 {
                    2
                } else {
                    0
                },
            );
            if stage == 2 {
                steering.block_host();
            }
            let coordinator = retirement_test_coordinator(
                blocking_journal.clone(),
                authority,
                steering.clone(),
                ownership,
                audit,
            );
            let worker = coordinator.clone();
            let session_id = plan.session_id().clone();
            let identity = plan.identity();
            let observer = tokio::spawn(async move { worker.retire(&session_id, identity).await });
            if stage == 2 {
                wait_until_entered(&steering.host_entered).await;
            } else {
                wait_until_entered(&blocking_journal.entered).await;
            }
            observer.abort();
            let _ = observer.await;
            if stage == 2 {
                steering.release_host();
            } else {
                blocking_journal.unblock();
            }
            let outcome = tokio::time::timeout(
                Duration::from_secs(3),
                coordinator.retire(plan.session_id(), plan.identity()),
            )
            .await
            .expect("detached retirement worker remains bounded")
            .expect("observer retry converges");
            assert!(matches!(
                outcome.disposition(),
                SessionRePinRetirementDisposition::Retired
                    | SessionRePinRetirementDisposition::AlreadyRetired
            ));
        }
    }

    #[tokio::test]
    async fn retirement_batch_prevents_activation_ownership_commit_crossing_the_cut() {
        let (plan, journal, authority, steering, ownership, audit) =
            retirement_test_components().await;
        let blocking_journal = RetirementBlockingJournal::new(journal, 1);
        let retirement = retirement_test_coordinator(
            blocking_journal.clone(),
            authority.clone(),
            steering.clone(),
            ownership.clone(),
            audit.clone(),
        );
        let retirement_worker = retirement.clone();
        let session_id = plan.session_id().clone();
        let identity = plan.identity();
        let retirement_task =
            tokio::spawn(async move { retirement_worker.retire(&session_id, identity).await });
        wait_until_entered(&blocking_journal.entered).await;

        let mut activation = plan.requests()[0].clone();
        activation.previous_owner = activation.new_owner.clone();
        activation.previous_fence = OwnershipFence::new(10).expect("nonzero");
        activation.new_owner = ClusterNode::new("newer-owner");
        activation.transition_id = OwnershipTransitionId::new(99_999).expect("nonzero");
        activation.rule.owner = ShardId::new(10);
        ownership.set_shard_owner(activation.rule.owner, activation.new_owner.clone());
        let activation_coordinator = test_repin!(steering, authority.clone(), ownership, audit);
        let activation_task =
            tokio::spawn(async move { activation_coordinator.repin(activation).await });
        tokio::task::yield_now().await;
        assert_eq!(authority.fence_calls.load(Ordering::SeqCst), 0);

        blocking_journal.unblock();
        retirement_task
            .await
            .expect("retirement task joins")
            .expect("retirement converges");
        assert!(activation_task
            .await
            .expect("activation task joins")
            .is_err());
        assert_eq!(authority.fence_calls.load(Ordering::SeqCst), 0);
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
        let repin = test_repin!(
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
            test_repin!(
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
                test_repin!(
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
                harness.fencer.inner.owner(request.ownership_key),
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
    async fn mock_terminal_retirement_is_exact_idempotent_and_blocks_stale_recreation() {
        let journal = MockSessionRePinJournal::default();
        let plan = plan_with(1, 1, 100, 3);
        complete_journal_plan(&journal, &plan, 2).await;

        let retired = journal
            .retire(plan.session_id(), plan.identity())
            .await
            .unwrap();
        assert_eq!(
            retired.disposition(),
            SessionRePinRetirementDisposition::Retired
        );
        let replayed = journal
            .retire(plan.session_id(), plan.identity())
            .await
            .unwrap();
        assert_eq!(
            replayed.disposition(),
            SessionRePinRetirementDisposition::AlreadyRetired
        );
        assert_eq!(replayed.retained_until(), retired.retained_until());
        assert_eq!(journal.load(plan.session_id()).await.unwrap(), None);

        assert!(journal.begin(&plan).await.is_err());
        assert!(journal.begin(&successor_of(&plan, 2, 500)).await.is_err());
        let stale_fence = OwnershipFence::new(2).unwrap();
        assert!(journal
            .record_ownership_committed(&plan, 0, stale_fence)
            .await
            .is_err());
        assert!(journal
            .record_sa_complete(&plan, 0, stale_fence)
            .await
            .is_err());
        let stale = SessionRePinIdentity::new(operation_id(2), plan.fingerprint());
        assert!(journal.retire(plan.session_id(), stale).await.is_err());

        let rendered = format!("{retired:?} {replayed:?}");
        assert!(rendered.contains("[redacted]"));
        for forbidden in ["worker-target-sensitive", "8877665544332200", "100"] {
            assert!(!rendered.contains(forbidden), "leaked {forbidden}");
        }
    }

    #[tokio::test]
    async fn mock_retirement_rejects_nonterminal_and_stale_successor_identities() {
        let journal = MockSessionRePinJournal::default();
        let first = plan_with(1, 1, 100, 3);
        journal.begin(&first).await.unwrap();
        assert!(journal
            .retire(first.session_id(), first.identity())
            .await
            .is_err());
        let fence = OwnershipFence::new(2).unwrap();
        journal
            .record_ownership_committed(&first, 0, fence)
            .await
            .unwrap();
        assert!(journal
            .retire(first.session_id(), first.identity())
            .await
            .is_err());
        assert!(journal
            .load(first.session_id())
            .await
            .unwrap()
            .unwrap()
            .current_fence()
            .is_some());

        journal.record_sa_complete(&first, 0, fence).await.unwrap();
        for index in 1..first.len() {
            journal
                .record_ownership_committed(&first, index, fence)
                .await
                .unwrap();
            journal
                .record_sa_complete(&first, index, fence)
                .await
                .unwrap();
        }
        let successor = successor_of(&first, 2, 500);
        journal.begin(&successor).await.unwrap();
        assert!(journal
            .retire(first.session_id(), first.identity())
            .await
            .is_err());
        assert!(journal
            .retire(successor.session_id(), successor.identity())
            .await
            .is_err());
        complete_journal_plan(&journal, &successor, 3).await;
        assert!(journal
            .retire(first.session_id(), first.identity())
            .await
            .is_err());
        assert_eq!(
            journal
                .retire(successor.session_id(), successor.identity())
                .await
                .unwrap()
                .disposition(),
            SessionRePinRetirementDisposition::Retired
        );
    }

    #[tokio::test(start_paused = true)]
    async fn mock_tombstone_has_an_exact_bounded_cleanup_horizon() {
        let clock = Arc::new(opc_session_store::TokioVirtualClock::new());
        let journal = MockSessionRePinJournal::with_clock(clock);
        let plan = plan_with(1, 1, 100, 3);
        complete_journal_plan(&journal, &plan, 2).await;
        let retired = journal
            .retire(plan.session_id(), plan.identity())
            .await
            .unwrap();

        tokio::time::advance(SESSION_REPIN_RETIREMENT_RETENTION - Duration::from_nanos(1)).await;
        assert!(journal.begin(&plan).await.is_err());
        assert_eq!(
            journal
                .retire(plan.session_id(), plan.identity())
                .await
                .unwrap()
                .retained_until(),
            retired.retained_until()
        );

        tokio::time::advance(Duration::from_nanos(1)).await;
        assert_eq!(journal.load(plan.session_id()).await.unwrap(), None);
        // Cleanup ends the bounded stale-retry guarantee. Production callers
        // must never reuse this privacy-safe per-session ID after teardown.
        assert!(journal.begin(&plan).await.is_ok());
    }

    #[tokio::test]
    async fn mock_retire_and_successor_begin_linearize_without_mixed_state() {
        let journal = MockSessionRePinJournal::default();
        let first = plan_with(1, 1, 100, 3);
        complete_journal_plan(&journal, &first, 2).await;
        let successor = successor_of(&first, 2, 500);

        let (retired, started) = tokio::join!(
            journal.retire(first.session_id(), first.identity()),
            journal.begin(&successor)
        );
        assert_ne!(retired.is_ok(), started.is_ok());
        match journal.load(first.session_id()).await.unwrap() {
            Some(checkpoint) => assert_eq!(checkpoint.plan(), &successor),
            None => assert!(retired.is_ok()),
        }
    }

    #[tokio::test]
    async fn mock_final_progress_and_retirement_race_never_loses_a_known_commit() {
        let journal = MockSessionRePinJournal::default();
        let plan = plan_with(1, 1, 100, 3);
        journal.begin(&plan).await.unwrap();
        let fence = OwnershipFence::new(2).unwrap();
        for index in 0..plan.len() - 1 {
            journal
                .record_ownership_committed(&plan, index, fence)
                .await
                .unwrap();
            journal
                .record_sa_complete(&plan, index, fence)
                .await
                .unwrap();
        }
        let last = plan.len() - 1;
        journal
            .record_ownership_committed(&plan, last, fence)
            .await
            .unwrap();

        let (completed, retired) = tokio::join!(
            journal.record_sa_complete(&plan, last, fence),
            journal.retire(plan.session_id(), plan.identity())
        );
        assert!(completed.is_ok());
        if retired.is_err() {
            assert_eq!(
                journal
                    .load(plan.session_id())
                    .await
                    .unwrap()
                    .unwrap()
                    .status()
                    .phase(),
                SessionRePinPhase::Complete
            );
            journal
                .retire(plan.session_id(), plan.identity())
                .await
                .unwrap();
        }
        assert_eq!(journal.load(plan.session_id()).await.unwrap(), None);
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
                    test_repin!(
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
                ownership_key: request.ownership_key,
                outbound_sa_binding_id: request.outbound_sa_binding_id,
                resume: request.resume,
            };
            let direct_per_sa = test_repin!(
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
    async fn session_store_terminal_retirement_is_fenced_versioned_and_restart_idempotent() {
        let store = SessionStore::new(FakeSessionBackend::new());
        let journal = SessionStoreRePinJournal::new(store.clone(), tenant(), nf_kind());
        let plan = plan_with(1, 1, 100, 3);
        complete_journal_plan(&journal, &plan, 2).await;
        let key = journal.key(plan.session_id()).unwrap();
        let active_record = store.get(&key).await.unwrap().unwrap();
        let active_envelope = decode_session_payload_envelope(
            &active_record.payload,
            Some(SESSION_REPIN_JOURNAL_MAX_BYTES),
        )
        .unwrap();
        assert_eq!(
            active_envelope.version().get(),
            SESSION_REPIN_CHECKPOINT_PAYLOAD_VERSION
        );
        assert_eq!(active_record.expires_at, None);

        let retired = journal
            .retire(plan.session_id(), plan.identity())
            .await
            .unwrap();
        assert_eq!(
            retired.disposition(),
            SessionRePinRetirementDisposition::Retired
        );
        assert_eq!(journal.load(plan.session_id()).await.unwrap(), None);
        let retired_record = store.get(&key).await.unwrap().unwrap();
        assert!(retired_record.generation > active_record.generation);
        assert!(retired_record.fence > active_record.fence);
        assert_eq!(retired_record.expires_at, Some(retired.retained_until()));
        let retired_envelope = decode_session_payload_envelope(
            &retired_record.payload,
            Some(SESSION_REPIN_JOURNAL_MAX_BYTES),
        )
        .unwrap();
        assert_eq!(
            retired_envelope.version().get(),
            SESSION_REPIN_RETIREMENT_PAYLOAD_VERSION
        );
        let SessionRePinJournalEntry::Retired(tombstone) =
            decode_journal_record(&retired_record, &key, plan.session_id()).unwrap()
        else {
            panic!("expected retirement tombstone");
        };
        assert_eq!(tombstone.retained_until, retired.retained_until());
        assert_eq!(
            checked_session_deadline(tombstone.retired_at, SESSION_REPIN_RETIREMENT_RETENTION)
                .unwrap(),
            tombstone.retained_until
        );

        let restarted = SessionStoreRePinJournal::new(store, tenant(), nf_kind());
        let replayed = restarted
            .retire(plan.session_id(), plan.identity())
            .await
            .unwrap();
        assert_eq!(
            replayed.disposition(),
            SessionRePinRetirementDisposition::AlreadyRetired
        );
        assert_eq!(replayed.retained_until(), retired.retained_until());
        assert!(restarted.begin(&plan).await.is_err());
        assert!(restarted.begin(&successor_of(&plan, 2, 500)).await.is_err());
        let stale_fence = OwnershipFence::new(2).unwrap();
        assert!(restarted
            .record_ownership_committed(&plan, 0, stale_fence)
            .await
            .is_err());
        assert!(restarted
            .record_sa_complete(&plan, 0, stale_fence)
            .await
            .is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn session_store_retirement_expiry_matches_the_documented_retry_horizon() {
        let clock = Arc::new(opc_session_store::TokioVirtualClock::new());
        let backend = FakeSessionBackend::new().with_clock(clock.clone());
        let store = SessionStore::new(backend);
        let journal =
            SessionStoreRePinJournal::new(store.clone(), tenant(), nf_kind()).with_clock(clock);
        let plan = plan_with(1, 1, 100, 3);
        complete_journal_plan(&journal, &plan, 2).await;
        let retired = journal
            .retire(plan.session_id(), plan.identity())
            .await
            .unwrap();

        tokio::time::advance(SESSION_REPIN_RETIREMENT_RETENTION - Duration::from_nanos(1)).await;
        assert!(journal.begin(&plan).await.is_err());
        assert_eq!(
            journal
                .retire(plan.session_id(), plan.identity())
                .await
                .unwrap()
                .retained_until(),
            retired.retained_until()
        );

        tokio::time::advance(Duration::from_nanos(1)).await;
        assert_eq!(journal.load(plan.session_id()).await.unwrap(), None);
        // As documented, ancient requests are indistinguishable after bounded
        // cleanup; callers must never reuse a retired session stable ID.
        assert!(journal.begin(&plan).await.is_ok());
    }

    #[tokio::test]
    async fn session_store_retirement_rejects_nonterminal_and_stale_identity() {
        let journal = SessionStoreRePinJournal::new(
            SessionStore::new(FakeSessionBackend::new()),
            tenant(),
            nf_kind(),
        );
        let plan = plan_with(1, 1, 100, 3);
        journal.begin(&plan).await.unwrap();
        assert!(journal
            .retire(plan.session_id(), plan.identity())
            .await
            .is_err());
        let stale = SessionRePinIdentity::new(operation_id(99), plan.fingerprint());
        assert!(journal.retire(plan.session_id(), stale).await.is_err());
        assert_eq!(
            journal
                .load(plan.session_id())
                .await
                .unwrap()
                .unwrap()
                .status()
                .phase(),
            SessionRePinPhase::Prepared
        );
    }

    #[tokio::test]
    async fn session_store_retire_and_successor_begin_linearize_at_one_generation() {
        let store = SessionStore::new(FakeSessionBackend::new());
        let journal = SessionStoreRePinJournal::new(store.clone(), tenant(), nf_kind());
        let first = plan_with(1, 1, 100, 3);
        complete_journal_plan(&journal, &first, 2).await;
        let successor = successor_of(&first, 2, 500);
        let retiring = SessionStoreRePinJournal::new(store.clone(), tenant(), nf_kind());
        let starting = SessionStoreRePinJournal::new(store, tenant(), nf_kind());

        let (retired, started) = tokio::join!(
            retiring.retire(first.session_id(), first.identity()),
            starting.begin(&successor)
        );
        assert_ne!(retired.is_ok(), started.is_ok());
        match journal.load(first.session_id()).await.unwrap() {
            Some(checkpoint) => assert_eq!(checkpoint.plan(), &successor),
            None => assert!(retired.is_ok()),
        }
    }

    #[tokio::test]
    async fn session_store_final_progress_and_retire_race_preserves_terminal_state() {
        let journal = SessionStoreRePinJournal::new(
            SessionStore::new(FakeSessionBackend::new()),
            tenant(),
            nf_kind(),
        );
        let plan = plan_with(1, 1, 100, 3);
        journal.begin(&plan).await.unwrap();
        let fence = OwnershipFence::new(2).unwrap();
        for index in 0..plan.len() - 1 {
            journal
                .record_ownership_committed(&plan, index, fence)
                .await
                .unwrap();
            journal
                .record_sa_complete(&plan, index, fence)
                .await
                .unwrap();
        }
        let last = plan.len() - 1;
        journal
            .record_ownership_committed(&plan, last, fence)
            .await
            .unwrap();

        let (completed, retired) = tokio::join!(
            journal.record_sa_complete(&plan, last, fence),
            journal.retire(plan.session_id(), plan.identity())
        );
        assert!(completed.is_ok());
        if retired.is_err() {
            assert_eq!(
                journal
                    .load(plan.session_id())
                    .await
                    .unwrap()
                    .unwrap()
                    .status()
                    .phase(),
                SessionRePinPhase::Complete
            );
            journal
                .retire(plan.session_id(), plan.identity())
                .await
                .unwrap();
        }
        assert_eq!(journal.load(plan.session_id()).await.unwrap(), None);
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
        fail_readback_after_injected_cas: Arc<AtomicBool>,
        fail_next_get: Arc<AtomicBool>,
        cas_calls: Arc<AtomicUsize>,
    }

    impl<B> CommitThenErrorBackend<B> {
        fn new(inner: B) -> Self {
            Self {
                inner,
                inject: Arc::new(AtomicBool::new(true)),
                fail_readback_after_injected_cas: Arc::new(AtomicBool::new(false)),
                fail_next_get: Arc::new(AtomicBool::new(false)),
                cas_calls: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn arm_lost_ack_and_failed_readback(&self) {
            self.fail_readback_after_injected_cas
                .store(true, Ordering::SeqCst);
            self.inject.store(true, Ordering::SeqCst);
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
            if self.fail_next_get.swap(false, Ordering::SeqCst) {
                return Err(StoreError::BackendUnavailable(
                    "injected read-back failure".to_owned(),
                ));
            }
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
                if self
                    .fail_readback_after_injected_cas
                    .swap(false, Ordering::SeqCst)
                {
                    self.fail_next_get.store(true, Ordering::SeqCst);
                }
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
    async fn retirement_restart_recovers_after_ambiguous_commit_and_failed_readback() {
        let backend = CommitThenErrorBackend::new(SessionStore::new(FakeSessionBackend::new()));
        let journal = SessionStoreRePinJournal::new(backend.clone(), tenant(), nf_kind());
        let plan = plan_with(1, 1, 100, 3);
        complete_journal_plan(&journal, &plan, 2).await;
        backend.arm_lost_ack_and_failed_readback();

        assert!(journal
            .retire(plan.session_id(), plan.identity())
            .await
            .is_err());
        let restarted = SessionStoreRePinJournal::new(backend, tenant(), nf_kind());
        let recovered = restarted
            .retire(plan.session_id(), plan.identity())
            .await
            .unwrap();
        assert_eq!(
            recovered.disposition(),
            SessionRePinRetirementDisposition::AlreadyRetired
        );
        assert_eq!(restarted.load(plan.session_id()).await.unwrap(), None);
        assert!(restarted.begin(&plan).await.is_err());
    }

    #[tokio::test]
    async fn contended_session_store_retirement_converges_on_one_tombstone() {
        let store = SessionStore::new(FakeSessionBackend::new());
        let setup = SessionStoreRePinJournal::new(store.clone(), tenant(), nf_kind());
        let plan = plan_with(1, 1, 100, 3);
        complete_journal_plan(&setup, &plan, 2).await;
        let left = SessionStoreRePinJournal::new(store.clone(), tenant(), nf_kind());
        let right = SessionStoreRePinJournal::new(store, tenant(), nf_kind());

        let (left_result, right_result) = tokio::join!(
            left.retire(plan.session_id(), plan.identity()),
            right.retire(plan.session_id(), plan.identity())
        );
        assert!(left_result.is_ok() || right_result.is_ok());
        let retry = if left_result.is_err() { &left } else { &right };
        assert_eq!(
            retry
                .retire(plan.session_id(), plan.identity())
                .await
                .unwrap()
                .disposition(),
            SessionRePinRetirementDisposition::AlreadyRetired
        );
        assert_eq!(setup.load(plan.session_id()).await.unwrap(), None);
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
        assert_eq!(
            degraded.retire(plan.session_id(), plan.identity()).await,
            Err(IpsecLbError::Unsupported)
        );
        let ports = Harness::new();
        let coordinator = SessionRePinCoordinator::new(
            test_repin!(ports.steering, ports.fencer, ports.ownership, ports.audit),
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
            test_repin!(ports.steering, ports.fencer, ports.ownership, ports.audit),
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
        let fingerprint_json = serde_json::to_vec(&plan.fingerprint().as_bytes()).unwrap();
        for forbidden in [
            b"worker-source-sensitive".as_slice(),
            b"worker-target-sensitive".as_slice(),
            b"8877665544332200".as_slice(),
            b"\"operation_id\":99".as_slice(),
            fingerprint_json.as_slice(),
        ] {
            assert!(!raw_payload
                .windows(forbidden.len())
                .any(|window| window == forbidden));
        }

        let loaded = journal.load(plan.session_id()).await.unwrap().unwrap();
        assert_eq!(loaded.plan(), &plan);

        complete_journal_plan(&journal, &plan, 2).await;
        journal
            .retire(plan.session_id(), plan.identity())
            .await
            .unwrap();
        let retired = raw.get(&key).await.unwrap().unwrap();
        assert_eq!(
            retired.payload.encoding(),
            SessionPayloadEncoding::EnvelopeV1
        );
        for forbidden in [
            b"worker-source-sensitive".as_slice(),
            b"worker-target-sensitive".as_slice(),
            b"8877665544332200".as_slice(),
            b"\"operation_id\":99".as_slice(),
            fingerprint_json.as_slice(),
            b"\"plan_fingerprint\"".as_slice(),
            b"\"retired_at\"".as_slice(),
        ] {
            assert!(!retired
                .payload
                .as_bytes()
                .windows(forbidden.len())
                .any(|window| window == forbidden));
        }
        assert_eq!(journal.load(plan.session_id()).await.unwrap(), None);
    }

    #[tokio::test]
    async fn encrypted_sqlite_retirement_survives_adapter_restart() {
        let directory = TestDirectory::new("encrypted-retirement-restart");
        let database_path = directory.path().join("session-store.sqlite");
        let provider = encryption_provider();
        let encrypted = EncryptingSessionBackend::new(
            Arc::new(SqliteSessionBackend::open(&database_path).unwrap()),
            Arc::clone(&provider),
            "session-repin-retirement-sqlite",
        );
        let journal = SessionStoreRePinJournal::new(encrypted, tenant(), nf_kind());
        let plan = plan_with(0x33, 77, 900, 3);
        complete_journal_plan(&journal, &plan, 2).await;
        let retired = journal
            .retire(plan.session_id(), plan.identity())
            .await
            .unwrap();
        drop(journal);

        let restarted = SessionStoreRePinJournal::new(
            EncryptingSessionBackend::new(
                Arc::new(SqliteSessionBackend::open(&database_path).unwrap()),
                provider,
                "session-repin-retirement-sqlite",
            ),
            tenant(),
            nf_kind(),
        );
        let replayed = restarted
            .retire(plan.session_id(), plan.identity())
            .await
            .unwrap();
        assert_eq!(
            replayed.disposition(),
            SessionRePinRetirementDisposition::AlreadyRetired
        );
        assert_eq!(replayed.retained_until(), retired.retained_until());
        assert_eq!(restarted.load(plan.session_id()).await.unwrap(), None);
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

    #[tokio::test]
    async fn retirement_decode_rejects_expiry_fingerprint_and_version_tampering() {
        let store = SessionStore::new(FakeSessionBackend::new());
        let journal = SessionStoreRePinJournal::new(store.clone(), tenant(), nf_kind());
        let plan = plan_with(1, 1, 100, 3);
        complete_journal_plan(&journal, &plan, 2).await;
        journal
            .retire(plan.session_id(), plan.identity())
            .await
            .unwrap();
        let key = journal.key(plan.session_id()).unwrap();
        let record = store.get(&key).await.unwrap().unwrap();
        let SessionRePinJournalEntry::Retired(tombstone) =
            decode_journal_record(&record, &key, plan.session_id()).unwrap()
        else {
            panic!("expected retirement tombstone");
        };

        let mut wrong_expiry = record.clone();
        wrong_expiry.expires_at = Some(tombstone.retired_at);
        assert!(decode_journal_record(&wrong_expiry, &key, plan.session_id()).is_err());

        let mut tampered_wire = RetirementWire::from_tombstone(&tombstone);
        tampered_wire.retirement_fingerprint[0] ^= 1;
        let mut tampered = record.clone();
        tampered.payload = encode_json_payload(
            &journal_payload_format().unwrap(),
            SessionPayloadVersion::new(SESSION_REPIN_RETIREMENT_PAYLOAD_VERSION),
            &tampered_wire,
            Some(SESSION_REPIN_JOURNAL_MAX_BYTES),
        )
        .unwrap();
        assert!(decode_journal_record(&tampered, &key, plan.session_id()).is_err());

        let malformed_envelope = opc_session_store::SessionPayloadEnvelope::new(
            journal_payload_format().unwrap(),
            SessionPayloadVersion::new(SESSION_REPIN_RETIREMENT_PAYLOAD_VERSION),
            b"{\"session_id\":".to_vec(),
        )
        .with_content_type(SESSION_PAYLOAD_JSON_CONTENT_TYPE)
        .unwrap();
        let mut malformed = record.clone();
        malformed.payload = opc_session_store::encode_session_payload_envelope(
            &malformed_envelope,
            Some(SESSION_REPIN_JOURNAL_MAX_BYTES),
        )
        .unwrap();
        assert!(decode_journal_record(&malformed, &key, plan.session_id()).is_err());

        let mut unknown_version = record;
        unknown_version.payload = encode_json_payload(
            &journal_payload_format().unwrap(),
            SessionPayloadVersion::new(99),
            &RetirementWire::from_tombstone(&tombstone),
            Some(SESSION_REPIN_JOURNAL_MAX_BYTES),
        )
        .unwrap();
        assert!(decode_journal_record(&unknown_version, &key, plan.session_id()).is_err());
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
