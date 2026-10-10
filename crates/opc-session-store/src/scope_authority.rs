//! Untimed, strictly durable authority for one stable scope.
//!
//! An admitted process keeps authority until an exact committed transition
//! closes or supersedes it. Time never transfers ownership. Every child write
//! compares the current incarnation and complete execution at replicated apply.

use std::fmt;

use bytes::Bytes;
use opc_types::{NetworkFunctionKind, TenantId};
use serde::{Deserialize, Serialize};

use crate::{
    SessionConsensusClusterId, SessionConsensusIdentity, SessionConsumerIdentity, SessionKey,
    SessionKeyType, StableId,
};

pub(crate) mod service;
mod state;

pub(crate) use service::is_scope_authority_key;
pub use service::{
    ScopeAuthorityAction, ScopeAuthorityAdmission, ScopeAuthorityRole, ScopeAuthorityStore,
};

const RECORD_TYPE: &str = "opc-scope-authority";
const RECORD_MAGIC: &[u8; 5] = b"OPSA\x04";
/// Maximum plaintext size of the fixed scope authority checkpoint.
pub const MAX_SCOPE_AUTHORITY_RECORD_BYTES: usize = 4096;
const COUNTER_MAX: u64 = i64::MAX as u64;

/// Stable, value-free refusal reason. Refusals allocate no authority receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[non_exhaustive]
pub enum ScopeAuthorityError {
    /// A field is empty, out of bounds, or inconsistent.
    #[error("scope_authority_invalid_request")]
    InvalidRequest,
    /// The independently authenticated peer or verified boot is not authorized.
    #[error("scope_authority_unauthorized")]
    Unauthorized,
    /// The exact expected authority revision no longer matches.
    #[error("scope_authority_conflict")]
    Conflict,
    /// A retained request ID was reused with different content.
    #[error("scope_authority_idempotency_conflict")]
    IdempotencyConflict,
    /// The complete execution stamp is no longer active and current.
    #[error("scope_authority_stale_authority")]
    StaleAuthority,
    /// A retired incarnation can never regain writes.
    #[error("scope_authority_retired")]
    Retired,
    /// A generation or boot has already been consumed or superseded.
    #[error("scope_authority_superseded")]
    Superseded,
    /// Positive, exact predecessor closure has not been established.
    #[error("scope_authority_closure_required")]
    ClosureRequired,
    /// Stored data is malformed or contradicts the retained floors.
    #[error("scope_authority_format_mismatch")]
    FormatMismatch,
    /// An earlier scope format requires a new installation, never migration.
    #[error("scope_authority_fresh_installation_required")]
    FreshInstallationRequired,
    /// Scope authority requires strictly durable consensus persistence.
    #[error("scope_authority_durable_consensus_required")]
    DurableConsensusRequired,
    /// The request may have committed; resolve its exact outcome before advancing.
    #[error("scope_authority_outcome_unknown")]
    OutcomeUnknown,
    /// Quorum or current configuration authority is temporarily unavailable.
    #[error("scope_authority_unavailable")]
    Unavailable,
    /// The current exact voter set has not activated scope profile 4.
    #[error("scope_authority_profile_not_activated")]
    ProfileNotActivated,
}

/// Stable cluster, tenant, network function and opaque slot.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeId {
    store: SessionConsensusClusterId,
    tenant: TenantId,
    nf_kind: NetworkFunctionKind,
    slot: [u8; 32],
}

impl ScopeId {
    /// Bind the configured consensus cluster and an opaque nonzero slot.
    ///
    /// The replication manifest derives the cluster from its configured name
    /// with [`opc_consensus::ConsensusClusterId::new`]. Obtain this identity from
    /// the immutable topology, without a live authority probe. Membership epochs
    /// are deliberately excluded; reusing a cluster name reuses its identity.
    pub fn new(
        store: SessionConsensusIdentity,
        tenant: TenantId,
        nf_kind: NetworkFunctionKind,
        slot: [u8; 32],
    ) -> Result<Self, ScopeAuthorityError> {
        if slot == [0; 32] {
            return Err(ScopeAuthorityError::InvalidRequest);
        }
        Ok(Self {
            store: store.cluster_id(),
            tenant,
            nf_kind,
            slot,
        })
    }
    /// Cluster identity, independent of membership epochs.
    pub const fn store(&self) -> SessionConsensusClusterId {
        self.store
    }
    /// Tenant admitted by the service.
    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }
    /// Network-function namespace admitted by the service.
    pub const fn nf_kind(&self) -> &NetworkFunctionKind {
        &self.nf_kind
    }
    /// Opaque stable slot.
    pub const fn slot(&self) -> &[u8; 32] {
        &self.slot
    }
    pub(crate) fn key(&self) -> Result<SessionKey, ScopeAuthorityError> {
        Ok(SessionKey {
            tenant: self.tenant.clone(),
            nf_kind: self.nf_kind.clone(),
            key_type: SessionKeyType::other(RECORD_TYPE)
                .map_err(|_| ScopeAuthorityError::InvalidRequest)?,
            stable_id: StableId::new(Bytes::copy_from_slice(&self.slot))
                .map_err(|_| ScopeAuthorityError::InvalidRequest)?,
        })
    }
}

/// Ordered worker-cohort identity, distinct from a voter incarnation or boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ScopeIncarnation(u64);
impl ScopeIncarnation {
    /// Construct a positive incarnation within the durable signed counter range.
    pub fn new(value: u64) -> Result<Self, ScopeAuthorityError> {
        if !(1..=COUNTER_MAX).contains(&value) {
            return Err(ScopeAuthorityError::InvalidRequest);
        }
        Ok(Self(value))
    }
    /// Positive, monotonically increasing cohort ordinal.
    pub const fn get(self) -> u64 {
        self.0
    }
}
impl<'de> Deserialize<'de> for ScopeIncarnation {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(u64::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Exact child/claim namespace. Stable counters and birth floors exclude this ordinal.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeNamespace {
    scope: ScopeId,
    incarnation: ScopeIncarnation,
}
impl ScopeNamespace {
    /// Bind an explicit cohort; handles never follow replacement implicitly.
    pub fn new(scope: ScopeId, incarnation: ScopeIncarnation) -> Result<Self, ScopeAuthorityError> {
        if scope.slot == [0; 32] {
            return Err(ScopeAuthorityError::InvalidRequest);
        }
        Ok(Self { scope, incarnation })
    }
    /// Stable scope whose protected counters and birth floor are shared.
    pub const fn scope(&self) -> &ScopeId {
        &self.scope
    }
    /// Exact worker cohort.
    pub const fn incarnation(&self) -> ScopeIncarnation {
        self.incarnation
    }
}

/// Complete admitted boot binding, with no duplicate workload-incarnation UUID.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeExecution {
    #[serde(with = "identity_claim")]
    identity: SessionConsumerIdentity,
    admission_generation: u64,
    workload: [u8; 16],
    process: [u8; 16],
    boot_key: [u8; 32],
}
mod identity_claim {
    use super::*;
    pub fn serialize<S: serde::Serializer>(
        value: &SessionConsumerIdentity,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(value.as_str())
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<SessionConsumerIdentity, D::Error> {
        SessionConsumerIdentity::new(String::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)
    }
}
impl ScopeExecution {
    /// Describe a boot for independent verification against the authenticated
    /// channel. `boot_key` is the verifier's public-key commitment, not a secret
    /// or a self-authenticating claim. Each supported restart needs a fresh
    /// nonce/key and a higher independently issued admission generation.
    pub fn new(
        identity: SessionConsumerIdentity,
        admission_generation: u64,
        workload: [u8; 16],
        process: [u8; 16],
        boot_key: [u8; 32],
    ) -> Result<Self, ScopeAuthorityError> {
        let value = Self {
            identity,
            admission_generation,
            workload,
            process,
            boot_key,
        };
        value.validate()?;
        Ok(value)
    }
    /// Independently authenticated logical consumer.
    pub const fn identity(&self) -> &SessionConsumerIdentity {
        &self.identity
    }
    /// Verified scope-wide admission generation; it never resets at retirement.
    pub const fn admission_generation(&self) -> u64 {
        self.admission_generation
    }
    /// Exact platform-authenticated workload identity.
    pub const fn workload(&self) -> &[u8; 16] {
        &self.workload
    }
    /// Nonce unique to this process, never reused after restart.
    pub const fn process(&self) -> &[u8; 16] {
        &self.process
    }
    /// Public boot-key commitment retained atomically with admission.
    pub const fn boot_key(&self) -> &[u8; 32] {
        &self.boot_key
    }
    fn validate(&self) -> Result<(), ScopeAuthorityError> {
        if !(1..=COUNTER_MAX).contains(&self.admission_generation)
            || self.workload == [0; 16]
            || self.process == [0; 16]
            || self.boot_key == [0; 32]
        {
            return Err(ScopeAuthorityError::InvalidRequest);
        }
        Ok(())
    }
}

/// Serializable claims naming exact authority. Decoding these never grants effects.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeAuthorityStamp {
    namespace: ScopeNamespace,
    revision: u64,
    execution: ScopeExecution,
}
impl ScopeAuthorityStamp {
    /// Stable scope binding.
    pub const fn scope(&self) -> &ScopeId {
        self.namespace.scope()
    }
    /// Exact child/claim namespace.
    pub const fn namespace(&self) -> &ScopeNamespace {
        &self.namespace
    }
    /// Worker cohort which must exceed the committed retirement floor.
    pub const fn incarnation(&self) -> ScopeIncarnation {
        self.namespace.incarnation
    }
    /// Authority revision; child/lane mutations do not advance it.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    /// Complete boot binding, including generation and public-key commitment.
    pub const fn execution(&self) -> &ScopeExecution {
        &self.execution
    }
    pub(crate) fn validate(&self) -> Result<(), ScopeAuthorityError> {
        self.execution.validate()?;
        if self.scope().slot == [0; 32] || !(1..=COUNTER_MAX).contains(&self.revision) {
            return Err(ScopeAuthorityError::InvalidRequest);
        }
        Ok(())
    }
}

/// Authenticated committed authority for a local effect adapter.
///
/// Only the authority service constructs this token after an admission or exact
/// recovery for the current boot. Installed forwarding is not time limited by
/// this capability. The adapter still enforces its exact local boot/generation.
///
/// ```compile_fail
/// use opc_session_store::scope_authority::CommittedScopeAuthority;
/// let forged: CommittedScopeAuthority = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct CommittedScopeAuthority {
    stamp: ScopeAuthorityStamp,
    closed_predecessor: Option<ScopeAuthorityStamp>,
}
impl CommittedScopeAuthority {
    /// Immutable committed comparison facts, not a transferable capability.
    pub const fn stamp(&self) -> &ScopeAuthorityStamp {
        &self.stamp
    }
    /// Exact positively closed predecessor of this committed same-cohort
    /// succession. Initial admission has no handoff provenance.
    pub const fn closed_predecessor(&self) -> Option<&ScopeAuthorityStamp> {
        self.closed_predecessor.as_ref()
    }
    /// Refuse a copied token at a different local boot or generation.
    pub fn check_execution(&self, current: &ScopeExecution) -> Result<(), ScopeAuthorityError> {
        if &self.stamp.execution != current {
            return Err(ScopeAuthorityError::StaleAuthority);
        }
        Ok(())
    }
}

/// Evidence kind; validity is established by a configured trusted verifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScopeClosureKind {
    /// The current boot has irreversibly closed mutation/peer-control paths.
    /// This can justify self-Close, never a successor by itself.
    LocalQuiescence,
    /// Independent final termination evidence for the exact predecessor boot.
    FinalTermination,
    /// An exact retained Closed authority checkpoint.
    CommittedClose,
}
/// Bounded serializable reference to evidence, not a verified closure token.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeClosureEvidence {
    kind: ScopeClosureKind,
    digest: [u8; 32],
}
impl ScopeClosureEvidence {
    /// Name immutable evidence for independent verification. The verifier must
    /// establish these exact bytes and their predecessor, not trust the caller.
    pub fn new(kind: ScopeClosureKind, digest: [u8; 32]) -> Result<Self, ScopeAuthorityError> {
        if digest == [0; 32] {
            return Err(ScopeAuthorityError::InvalidRequest);
        }
        Ok(Self { kind, digest })
    }
    /// Declared evidence kind, checked before proposal and again at apply.
    pub const fn kind(&self) -> ScopeClosureKind {
        self.kind
    }
    /// Immutable digest included in the complete authority request digest.
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

/// Opaque result of trusted closure verification, never a wire claim.
///
/// There is no public constructor. The service creates this only after its
/// configured verifier or an exact committed Close has established that the
/// predecessor cannot write or submit peer-control effects. Installed kernel
/// forwarding is explicitly excluded from closure.
///
/// ```compile_fail
/// use opc_session_store::scope_authority::VerifiedScopeClosure;
/// let forged: VerifiedScopeClosure = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedScopeClosure {
    predecessor: ScopeAuthorityStamp,
    evidence: ScopeClosureEvidence,
}
impl VerifiedScopeClosure {
    /// Digest of the immutable evidence which this token verifies.
    pub const fn digest(&self) -> &[u8; 32] {
        &self.evidence.digest
    }
}

/// One exact authority transition. No timer or unchecked retirement operation exists.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ScopeAuthorityOperation {
    /// Admit a verified boot only into a domain with no retained rows or floors.
    AdmitInitial {
        /// Exact independently verified boot and generation.
        execution: ScopeExecution,
    },
    /// Supersede a positively closed predecessor within the same cohort.
    SucceedClosed {
        /// Exact current predecessor, including its authority revision.
        predecessor: ScopeAuthorityStamp,
        /// Fresh verified boot, key and strictly higher generation.
        execution: ScopeExecution,
        /// Immutable final-termination or committed-Close evidence reference.
        evidence: ScopeClosureEvidence,
    },
    /// Irreversibly close the current execution after verified local quiescence.
    Close {
        /// Exact current active stamp.
        current: ScopeAuthorityStamp,
        /// Verified local mutation and peer-control closure, excluding forwarding.
        evidence: ScopeClosureEvidence,
    },
}
impl ScopeAuthorityOperation {
    /// Boot being admitted or closed; controllers do not inherit its identity.
    pub fn execution(&self) -> &ScopeExecution {
        match self {
            Self::AdmitInitial { execution } | Self::SucceedClosed { execution, .. } => execution,
            Self::Close { current, .. } => &current.execution,
        }
    }
    pub(crate) fn closure(&self) -> Option<(&ScopeAuthorityStamp, &ScopeClosureEvidence)> {
        match self {
            Self::AdmitInitial { .. } => None,
            Self::SucceedClosed {
                predecessor,
                evidence,
                ..
            } => Some((predecessor, evidence)),
            Self::Close { current, evidence } => Some((current, evidence)),
        }
    }
}

/// Exact immutable request; retain it until its outcome is resolved.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeAuthorityRequest {
    scope: ScopeId,
    request_id: [u8; 16],
    expected_revision: u64,
    operation: ScopeAuthorityOperation,
}
impl ScopeAuthorityRequest {
    /// Construct one bounded request. Configuration admission stays outside its
    /// digest; closure evidence and the entire candidate boot stay inside it.
    pub fn new(
        scope: ScopeId,
        request_id: [u8; 16],
        expected_revision: u64,
        operation: ScopeAuthorityOperation,
    ) -> Result<Self, ScopeAuthorityError> {
        let value = Self {
            scope,
            request_id,
            expected_revision,
            operation,
        };
        value.validate()?;
        Ok(value)
    }
    /// Stable scope of the request.
    pub const fn scope(&self) -> &ScopeId {
        &self.scope
    }
    /// Caller-retained request identity.
    pub const fn request_id(&self) -> &[u8; 16] {
        &self.request_id
    }
    /// Exact authority revision compared at apply.
    pub const fn expected_revision(&self) -> u64 {
        self.expected_revision
    }
    /// Complete operation, including immutable evidence references.
    pub const fn operation(&self) -> &ScopeAuthorityOperation {
        &self.operation
    }
}

/// Current authority claims. A read never issues an effect capability.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeAuthorityView {
    scope: ScopeId,
    revision: u64,
    retired_through: u64,
    admission_generation_floor: u64,
    stamp: Option<ScopeAuthorityStamp>,
    active: bool,
    closed_digest: Option<[u8; 32]>,
}
impl ScopeAuthorityView {
    /// Stable scope observed.
    pub const fn scope(&self) -> &ScopeId {
        &self.scope
    }
    /// Revision for an authority compare-and-set.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    /// Highest permanently retired cohort.
    pub const fn retired_through(&self) -> u64 {
        self.retired_through
    }
    /// Highest committed admission generation, retained even after Close.
    pub const fn admission_generation_floor(&self) -> u64 {
        self.admission_generation_floor
    }
    /// Current cohort, including when its last execution is Closed.
    pub fn current_incarnation(&self) -> Option<ScopeIncarnation> {
        self.stamp.as_ref().map(ScopeAuthorityStamp::incarnation)
    }
    /// Retained current boot and revision; inspect `is_active` before mutation.
    pub const fn stamp(&self) -> Option<&ScopeAuthorityStamp> {
        self.stamp.as_ref()
    }
    /// Whether the exact retained stamp can still authorize new mutations.
    pub const fn is_active(&self) -> bool {
        self.active
    }
    /// Claims for the exact committed Close, checked against durable state at
    /// succession. This does not construct a verified token or effect capability.
    pub fn closed_evidence(&self) -> Option<ScopeClosureEvidence> {
        self.closed_digest.map(|digest| ScopeClosureEvidence {
            kind: ScopeClosureKind::CommittedClose,
            digest,
        })
    }
}

macro_rules! redacted_debug {
    ($($ty:ty),+ $(,)?) => { $(impl fmt::Debug for $ty {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(concat!(stringify!($ty), "(<redacted>)")) }
    })+ };
}
redacted_debug!(
    ScopeId,
    ScopeNamespace,
    ScopeExecution,
    ScopeAuthorityStamp,
    CommittedScopeAuthority,
    ScopeClosureEvidence,
    VerifiedScopeClosure,
    ScopeAuthorityOperation,
    ScopeAuthorityRequest,
    ScopeAuthorityView,
    ScopeState
);

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScopeState {
    pub(crate) view: ScopeAuthorityView,
    last_request_id: [u8; 16],
    last_digest: [u8; 32],
}

mod command;
mod profile;
pub(crate) use command::checkpoint_state;
#[cfg(target_os = "linux")]
pub(crate) use command::ScopeCheckpointFacts;
pub use command::{ScopeAuthorityCheckpoint, ScopeAuthorityCommand};
pub(crate) use profile::scope_profile_digest;
pub use profile::{ScopeProfileActivation, ScopeProfileContinuation};
#[cfg(test)]
mod service_tests;
#[cfg(test)]
pub(crate) mod tests;

mod transport;
mod transport_codec;
pub use transport::{ScopeAuthorityOutcome, ScopeAuthorityRemote, ScopeAuthorityResponseVerifier};
#[cfg(test)]
mod transport_tests;
