//! Store-side authority and terminal records for the protected roster port.
//!
//! The durable backend owns the two quorum mutations and their authority
//! validation. Provider execution, ambiguity tracking, scheduling, and local
//! terminal preparation live in `opc-session-net`; this module contains only
//! the bounded authenticated values that cross into consensus and the exact
//! committed receipt codecs returned from it. It deliberately exposes no
//! provider, queue, task, connection, or raw consensus capability.

use crate::{
    fenced_mutation_roster::{
        decode_frame, encode_frame, Admission, Phase, RequestId, Scope, TerminalRecord,
        TerminalSlotId, COMMITTED_TERMINAL_FRAME_DOMAIN, COMMITTED_TERMINAL_FRAME_MAGIC,
        MAX_COMMITTED_TERMINAL_CODEC_BYTES, MAX_PLAN_BYTES, TERMINAL_COMMITTING_GUARD_DOMAIN,
        TERMINAL_RECEIPT_COMMITMENT_DOMAIN, TERMINAL_RECORD_COMMITMENT_DOMAIN,
    },
    model::{FenceToken, Generation, OwnerId, SessionKey},
};
use opc_types::Timestamp;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fmt, sync::Arc};

/// Fixed, redaction-safe executor failure classification.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub(crate) enum ExecutorError {
    /// Registration input is malformed or contradicts its immutable admission.
    InvalidRegistration,
    /// The backend rejected scope, tenant, key, owner, fence, credential, or generation.
    AuthorityRejected,
    /// The local attempt has crossed an ambiguity boundary and must not execute again.
    RecoveryRequired,
    /// A different terminal body conflicts with the same durable registration.
    TerminalConflict,
    /// The terminal phase, complete proof set, or checkpoint is invalid.
    InvalidTerminal,
    /// Admission's required present session record was not available.
    AdmissionRecordMissing,
    /// Admission's required present session generation differed.
    AdmissionGenerationConflict,
    /// Admission rejected a Put whose successor generation would overflow.
    AdmissionGenerationExhausted,
    /// Another live admission already reserves this protected business key.
    AdmissionBusinessKeyReserved,
    /// Admission rejected an invalid exact protected checkpoint.
    AdmissionInvalidProtectedCheckpoint,
    /// Admission could not reserve deterministic aggregate terminal storage.
    AdmissionAggregateBytesFull,
    /// Admission could not reserve a bounded live roster slot.
    AdmissionLiveFull,
    /// Admission could not reserve a bounded retained-history slot.
    AdmissionHistoryFull,
}

impl fmt::Display for ExecutorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRegistration => "invalid roster executor registration",
            Self::AuthorityRejected => "roster executor authority rejected",
            Self::RecoveryRequired => "roster executor recovery required",
            Self::TerminalConflict => "roster executor terminal conflict",
            Self::InvalidTerminal => "invalid roster executor terminal",
            Self::AdmissionRecordMissing => "roster admission record missing",
            Self::AdmissionGenerationConflict => "roster admission generation conflict",
            Self::AdmissionGenerationExhausted => "roster admission generation exhausted",
            Self::AdmissionBusinessKeyReserved => "roster admission business key reserved",
            Self::AdmissionInvalidProtectedCheckpoint => {
                "roster admission protected checkpoint rejected"
            }
            Self::AdmissionAggregateBytesFull => "roster admission aggregate capacity full",
            Self::AdmissionLiveFull => "roster admission live capacity full",
            Self::AdmissionHistoryFull => "roster admission history capacity full",
        })
    }
}

impl std::error::Error for ExecutorError {}

/// Authenticated lease values that travel together with one authority binding.
///
/// Keeping this exact tuple together prevents constructors from accidentally
/// pairing a credential or generation with another lease's time window.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthorityLeaseMetadata {
    credential_id: u64,
    generation: Generation,
    acquired_at: Timestamp,
    expires_at: Timestamp,
}

impl AuthorityLeaseMetadata {
    pub(crate) const fn new(
        credential_id: u64,
        generation: Generation,
        acquired_at: Timestamp,
        expires_at: Timestamp,
    ) -> Self {
        Self {
            credential_id,
            generation,
            acquired_at,
            expires_at,
        }
    }
}

/// Authenticated authority metadata bound to a registration by the backend.
///
/// The tenant is derived from `key` rather than accepted as a second
/// caller-supplied string. The admission/recovery and terminal quorum
/// mutations receive this complete binding and MUST compare it exactly with
/// durable state. Provider-local work uses the startup-owned permit derived
/// from this binding instead of making a quorum read.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct AuthorityBinding {
    scope: Scope,
    key: SessionKey,
    owner: OwnerId,
    fence: FenceToken,
    credential_id: u64,
    generation: Generation,
    // These are authenticated lease-manager values. Backends compare them to
    // their own logical clock/lease row. The executor's injected clock uses
    // them only as a conservative process-local expiry/revocation gate; it is
    // never a source of distributed authority.
    acquired_at: Timestamp,
    expires_at: Timestamp,
}

impl AuthorityBinding {
    /// Build the binding for an immutable admission and one lease credential.
    pub(crate) fn for_admission(
        admission: &Admission,
        owner: OwnerId,
        fence: FenceToken,
        lease: AuthorityLeaseMetadata,
    ) -> Result<Self, ExecutorError> {
        if lease.credential_id == 0
            || fence.get() == 0
            || &owner != admission.logical_owner()
            || fence != admission.admission_fence()
            || lease.generation != admission.expected_generation()
            || lease.expires_at <= lease.acquired_at
        {
            return Err(ExecutorError::InvalidRegistration);
        }
        Ok(Self {
            scope: admission.scope(),
            key: admission.key().clone(),
            owner,
            fence,
            credential_id: lease.credential_id,
            generation: lease.generation,
            acquired_at: lease.acquired_at,
            expires_at: lease.expires_at,
        })
    }

    /// Build current authority for a recovery lookup before the backend has
    /// returned its consensus-retained immutable admission.
    fn for_recovery(
        scope: Scope,
        key: SessionKey,
        owner: OwnerId,
        fence: FenceToken,
        lease: AuthorityLeaseMetadata,
    ) -> Result<Self, ExecutorError> {
        if lease.credential_id == 0 || fence.get() == 0 || lease.expires_at <= lease.acquired_at {
            return Err(ExecutorError::InvalidRegistration);
        }
        Ok(Self {
            scope,
            key,
            owner,
            fence,
            credential_id: lease.credential_id,
            generation: lease.generation,
            acquired_at: lease.acquired_at,
            expires_at: lease.expires_at,
        })
    }

    /// Rehydrate an authenticated authority carried by a bounded consensus
    /// command or read capsule. The caller must still compare it with the
    /// durable current lease and backend-owned logical time.
    pub(crate) fn from_consensus_parts(
        scope_digest: [u8; 32],
        key: SessionKey,
        owner: OwnerId,
        fence: FenceToken,
        lease: AuthorityLeaseMetadata,
    ) -> Result<Self, ExecutorError> {
        Self::for_recovery(Scope::from_digest(scope_digest), key, owner, fence, lease)
    }

    /// Authenticated least-authority scope commitment.
    pub(crate) const fn scope(&self) -> Scope {
        self.scope
    }

    /// Exact protected session key, including tenant.
    pub(crate) fn key(&self) -> &SessionKey {
        &self.key
    }

    /// Exact authenticated owner.
    pub(crate) fn owner(&self) -> &OwnerId {
        &self.owner
    }

    /// Exact authenticated fence token.
    pub(crate) const fn fence(&self) -> FenceToken {
        self.fence
    }

    /// Exact authenticated lease credential sequence.
    pub(crate) const fn credential_id(&self) -> u64 {
        self.credential_id
    }

    /// Exact authoritative generation.
    pub(crate) const fn generation(&self) -> Generation {
        self.generation
    }

    /// Lease issuance metadata to compare with backend-owned logical time.
    pub(crate) const fn acquired_at(&self) -> Timestamp {
        self.acquired_at
    }

    /// Lease expiry metadata to compare with backend-owned logical time.
    pub(crate) const fn expires_at(&self) -> Timestamp {
        self.expires_at
    }
}

impl fmt::Debug for AuthorityBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorityBinding(<redacted>)")
    }
}

/// Registration input for the startup-owned executor.
#[derive(Clone)]
pub(crate) struct RegistrationRequest {
    admission: Arc<Admission>,
    authority: AuthorityBinding,
}

impl RegistrationRequest {
    /// Bind immutable admission bytes to the complete lease credential.
    pub(crate) fn new_with_lease_metadata(
        admission: Admission,
        owner: OwnerId,
        fence: FenceToken,
        credential_id: u64,
        generation: Generation,
        acquired_at: Timestamp,
        expires_at: Timestamp,
    ) -> Result<Self, ExecutorError> {
        let admission = Arc::new(admission);
        let authority = AuthorityBinding::for_admission(
            &admission,
            owner,
            fence,
            AuthorityLeaseMetadata::new(credential_id, generation, acquired_at, expires_at),
        )?;
        Ok(Self {
            admission,
            authority,
        })
    }

    /// Exact immutable admission that must be persisted atomically by registration.
    pub(crate) fn admission(&self) -> &Admission {
        &self.admission
    }

    /// Exact authorization values which the durable backend must bind.
    pub(crate) fn authority(&self) -> &AuthorityBinding {
        &self.authority
    }
}

impl fmt::Debug for RegistrationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RegistrationRequest(<redacted>)")
    }
}

/// Stable durable lookup key for recovery of one exact immutable admission.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct RecoveryLookup {
    scope: Scope,
    roster_id: crate::fenced_mutation_roster::RosterId,
}

impl RecoveryLookup {
    fn new(scope: Scope, roster_id: crate::fenced_mutation_roster::RosterId) -> Self {
        Self { scope, roster_id }
    }

    /// Exact least-authority scope for the durable lookup.
    pub(crate) const fn scope(&self) -> Scope {
        self.scope
    }

    /// Stable caller-owned roster identity.
    pub(crate) const fn roster_id(&self) -> crate::fenced_mutation_roster::RosterId {
        self.roster_id
    }
}

impl fmt::Debug for RecoveryLookup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveryLookup(<redacted>)")
    }
}

/// Successor-takeover input which retains one already-admitted exact body.
#[derive(Clone)]
pub(crate) struct RecoveryRequest {
    lookup: RecoveryLookup,
    authority: AuthorityBinding,
}

impl RecoveryRequest {
    pub(crate) fn new_with_lease_metadata(
        scope: Scope,
        roster_id: crate::fenced_mutation_roster::RosterId,
        key: SessionKey,
        owner: OwnerId,
        fence: FenceToken,
        lease: AuthorityLeaseMetadata,
    ) -> Result<Self, ExecutorError> {
        Ok(Self {
            lookup: RecoveryLookup::new(scope, roster_id),
            authority: AuthorityBinding::for_recovery(scope, key, owner, fence, lease)?,
        })
    }

    /// Stable durable lookup key; no prior in-memory capability is required.
    pub(crate) const fn lookup(&self) -> RecoveryLookup {
        self.lookup
    }

    /// Current successor authority the backend must validate exactly.
    pub(crate) fn authority(&self) -> &AuthorityBinding {
        &self.authority
    }
}

impl fmt::Debug for RecoveryRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveryRequest(<redacted>)")
    }
}

/// Backend-issued opaque registration handle.
///
/// Its crate-private constructor is intentionally available only to the
/// durable server/backend side of this crate.  It is never caller-minted and
/// its bytes are never rendered in diagnostics.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct BackendRegistration {
    handle: [u8; 32],
    request_id: RequestId,
    terminal_slot_id: TerminalSlotId,
}

impl BackendRegistration {
    /// Issue a nonzero opaque registration handle after durable admission.
    pub(crate) fn issue(
        bytes: [u8; 32],
        request_id: RequestId,
        admission: &Admission,
    ) -> Result<Self, ExecutorError> {
        if bytes == [0; 32]
            || admission.profile().validate().is_err()
            || admission.protected_plan().len() > MAX_PLAN_BYTES
        {
            return Err(ExecutorError::InvalidRegistration);
        }
        request_id
            .validate_for(admission)
            .map_err(|_| ExecutorError::InvalidRegistration)?;
        let terminal_slot_id = request_id
            .terminal_slot_id(admission)
            .map_err(|_| ExecutorError::InvalidRegistration)?;
        Ok(Self {
            handle: bytes,
            request_id,
            terminal_slot_id,
        })
    }

    /// Rehydrate an opaque registration retained in consensus state.
    pub(crate) fn from_consensus_parts(
        handle: [u8; 32],
        request_id: RequestId,
        admission: &Admission,
    ) -> Result<Self, ExecutorError> {
        Self::issue(handle, request_id, admission)
    }

    /// Return the exact opaque handle, request identity, and terminal slot for
    /// bounded consensus encoding. These values never enter diagnostics.
    pub(crate) const fn consensus_parts(self) -> ([u8; 32], RequestId, TerminalSlotId) {
        (self.handle, self.request_id, self.terminal_slot_id)
    }

    fn request_id(self) -> RequestId {
        self.request_id
    }

    fn terminal_slot_id(self) -> TerminalSlotId {
        self.terminal_slot_id
    }

    fn validate_for(self, admission: &Admission) -> Result<(), ExecutorError> {
        self.request_id
            .validate_for(admission)
            .map_err(|_| ExecutorError::InvalidRegistration)?;
        if self.terminal_slot_id
            != self
                .request_id
                .terminal_slot_id(admission)
                .map_err(|_| ExecutorError::InvalidRegistration)?
        {
            return Err(ExecutorError::InvalidRegistration);
        }
        Ok(())
    }
}

impl fmt::Debug for BackendRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BackendRegistration(<redacted>)")
    }
}

/// Durable backend rejection without provider, tenant, or credential detail.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum BackendRejection {
    /// Any exact authority binding component was stale or cross-scoped.
    Authority,
    /// Another execution would be a blind replay.
    RecoveryRequired,
    /// A different terminal body conflicts with the persisted lock.
    TerminalConflict,
    /// Admission found no exact present protected business record.
    RecordMissing,
    /// Admission found a different protected business generation.
    GenerationConflict,
    /// Admission cannot produce a checked successor generation for Put.
    GenerationExhausted,
    /// A live admission already reserves the exact protected business key.
    BusinessKeyReserved,
    /// The proposed protected checkpoint cannot become the authoritative record.
    InvalidProtectedCheckpoint,
    /// Aggregate reservation for admission plus retained terminal data is full.
    AggregateBytesFull,
    /// The bounded live-roster reservation is full.
    LiveFull,
    /// The bounded retained-history reservation is full.
    HistoryFull,
}

impl From<BackendRejection> for ExecutorError {
    fn from(value: BackendRejection) -> Self {
        match value {
            BackendRejection::Authority => Self::AuthorityRejected,
            BackendRejection::RecoveryRequired => Self::RecoveryRequired,
            BackendRejection::TerminalConflict => Self::TerminalConflict,
            BackendRejection::RecordMissing => Self::AdmissionRecordMissing,
            BackendRejection::GenerationConflict => Self::AdmissionGenerationConflict,
            BackendRejection::GenerationExhausted => Self::AdmissionGenerationExhausted,
            BackendRejection::BusinessKeyReserved => Self::AdmissionBusinessKeyReserved,
            BackendRejection::InvalidProtectedCheckpoint => {
                Self::AdmissionInvalidProtectedCheckpoint
            }
            BackendRejection::AggregateBytesFull => Self::AdmissionAggregateBytesFull,
            BackendRejection::LiveFull => Self::AdmissionLiveFull,
            BackendRejection::HistoryFull => Self::AdmissionHistoryFull,
        }
    }
}

/// Exact process-local prepared terminal body whose bytes feed terminalization.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct TerminalBody {
    record: TerminalRecord,
    phase: Phase,
}

impl TerminalBody {
    /// Rehydrate a canonical terminal body retained by a durable backend.
    pub(crate) fn from_record(
        record: TerminalRecord,
        admission: &Admission,
    ) -> Result<Self, ExecutorError> {
        record
            .validate_for(admission)
            .map_err(|_| ExecutorError::InvalidTerminal)?;
        let phase = record.phase().map_err(|_| ExecutorError::InvalidTerminal)?;
        Ok(Self { record, phase })
    }

    /// Chosen terminal phase.
    pub(crate) const fn phase(&self) -> Phase {
        self.phase
    }

    /// Canonical domain terminal record persisted by the backend.
    pub(crate) fn record(&self) -> &TerminalRecord {
        &self.record
    }
}

impl fmt::Debug for TerminalBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TerminalBody(<redacted>)")
    }
}

/// Canonical business materialization coupled to one committed terminal.
///
/// This is intentionally separate from [`TerminalBody`]. A body proves the
/// provider outcome to be terminal; this value proves what the same atomic
/// backend transaction did to the protected session state.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum TerminalMaterialization {
    /// An established roster atomically materialized its admitted mutation.
    Established(EstablishedMaterialization),
    /// An aborted roster atomically wrote only its terminal receipt.
    Aborted,
}

impl TerminalMaterialization {
    fn for_body(admission: &Admission, body: &TerminalBody) -> Result<Self, ExecutorError> {
        match body.phase() {
            Phase::Established => Ok(Self::Established(
                EstablishedMaterialization::for_admission(admission)?,
            )),
            Phase::Aborted => Ok(Self::Aborted),
        }
    }

    fn validate_for(
        &self,
        admission: &Admission,
        body: &TerminalBody,
    ) -> Result<(), ExecutorError> {
        if *self != Self::for_body(admission, body)? {
            return Err(ExecutorError::InvalidTerminal);
        }
        Ok(())
    }

    fn update_receipt_commitment(&self, hasher: &mut Sha256) {
        match self {
            Self::Established(materialization) => {
                hasher.update([1]);
                materialization.update_receipt_commitment(hasher);
            }
            Self::Aborted => hasher.update([2]),
        }
    }
}

impl fmt::Debug for TerminalMaterialization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TerminalMaterialization(<redacted>)")
    }
}

/// Exact session mutation written by an established terminal transaction.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum EstablishedMaterialization {
    /// The admitted checkpoint became the authoritative session record.
    Updated {
        /// Exact expected generation reserved by admission.
        from: Generation,
        /// Checked successor generation written by the transaction.
        to: Generation,
        /// Commitment to the immutable authoritative record header and bytes.
        record_commitment: [u8; 32],
    },
    /// The admitted present-generation record was deleted.
    Deleted {
        /// Exact generation deleted by the transaction.
        generation: Generation,
    },
    /// The transaction retained the admitted present-generation record.
    NoOp {
        /// Exact generation retained by the transaction.
        generation: Generation,
    },
}

impl EstablishedMaterialization {
    fn for_admission(admission: &Admission) -> Result<Self, ExecutorError> {
        let mutation = admission.established_mutation();
        if mutation == &crate::fenced_mutation_roster::EstablishedMutation::delete() {
            return Ok(Self::Deleted {
                generation: admission.expected_generation(),
            });
        }
        if mutation == &crate::fenced_mutation_roster::EstablishedMutation::no_op() {
            return Ok(Self::NoOp {
                generation: admission.expected_generation(),
            });
        }

        let state_type = mutation
            .state_type()
            .ok_or(ExecutorError::InvalidTerminal)?;
        let from = admission.expected_generation();
        let to = from.next().ok_or(ExecutorError::InvalidTerminal)?;
        Ok(Self::Updated {
            from,
            to,
            record_commitment: terminal_record_commitment(admission, to, state_type.as_str()),
        })
    }

    fn update_receipt_commitment(&self, hasher: &mut Sha256) {
        match self {
            Self::Updated {
                from,
                to,
                record_commitment,
            } => {
                hasher.update([1]);
                hasher.update(from.get().to_be_bytes());
                hasher.update(to.get().to_be_bytes());
                hasher.update(record_commitment);
            }
            Self::Deleted { generation } => {
                hasher.update([2]);
                hasher.update(generation.get().to_be_bytes());
            }
            Self::NoOp { generation } => {
                hasher.update([3]);
                hasher.update(generation.get().to_be_bytes());
            }
        }
    }
}

impl fmt::Debug for EstablishedMaterialization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EstablishedMaterialization(<redacted>)")
    }
}

#[derive(Clone, Copy, Serialize, Deserialize)]
enum TerminalMaterializationWire {
    Updated {
        from: Generation,
        to: Generation,
        record_commitment: [u8; 32],
    },
    Deleted {
        generation: Generation,
    },
    NoOp {
        generation: Generation,
    },
    Aborted,
}

impl From<&TerminalMaterialization> for TerminalMaterializationWire {
    fn from(materialization: &TerminalMaterialization) -> Self {
        match materialization {
            TerminalMaterialization::Established(EstablishedMaterialization::Updated {
                from,
                to,
                record_commitment,
            }) => Self::Updated {
                from: *from,
                to: *to,
                record_commitment: *record_commitment,
            },
            TerminalMaterialization::Established(EstablishedMaterialization::Deleted {
                generation,
            }) => Self::Deleted {
                generation: *generation,
            },
            TerminalMaterialization::Established(EstablishedMaterialization::NoOp {
                generation,
            }) => Self::NoOp {
                generation: *generation,
            },
            TerminalMaterialization::Aborted => Self::Aborted,
        }
    }
}

impl From<TerminalMaterializationWire> for TerminalMaterialization {
    fn from(materialization: TerminalMaterializationWire) -> Self {
        match materialization {
            TerminalMaterializationWire::Updated {
                from,
                to,
                record_commitment,
            } => Self::Established(EstablishedMaterialization::Updated {
                from,
                to,
                record_commitment,
            }),
            TerminalMaterializationWire::Deleted { generation } => {
                Self::Established(EstablishedMaterialization::Deleted { generation })
            }
            TerminalMaterializationWire::NoOp { generation } => {
                Self::Established(EstablishedMaterialization::NoOp { generation })
            }
            TerminalMaterializationWire::Aborted => Self::Aborted,
        }
    }
}

/// Consensus-derived coordinates for the terminal linearization point.
///
/// The production adapter mints this value only from an applied quorum
/// response. Keeping construction crate-private prevents an SDK consumer from
/// choosing the retention clock, while embedding it in the committed terminal
/// frame makes restart, snapshot, and follower replay validate one exact
/// terminal timestamp rather than a separate mutable column.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConsensusCommitMetadata {
    sequence: u64,
    raft_log_index: u64,
    committed_at: Timestamp,
}

impl ConsensusCommitMetadata {
    pub(crate) fn issue(
        sequence: u64,
        raft_log_index: u64,
        committed_at: Timestamp,
    ) -> Result<Self, ExecutorError> {
        let value = Self {
            sequence,
            raft_log_index,
            committed_at,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(self) -> Result<(), ExecutorError> {
        if self.sequence == 0
            || self.raft_log_index == 0
            || self.committed_at.as_offset_datetime().unix_timestamp() < 0
        {
            return Err(ExecutorError::InvalidTerminal);
        }
        Ok(())
    }

    /// Validate that the consensus linearization occurred while the exact
    /// committing lease was live. A self-consistent old timestamp must never
    /// make a terminal immediately reclaimable or authenticate a stale guard.
    fn validate_for_authority(self, authority: &AuthorityBinding) -> Result<(), ExecutorError> {
        self.validate()?;
        if self.committed_at < authority.acquired_at()
            || self.committed_at >= authority.expires_at()
        {
            return Err(ExecutorError::InvalidTerminal);
        }
        Ok(())
    }

    pub(crate) const fn committed_at(self) -> Timestamp {
        self.committed_at
    }

    fn update_commitment(self, hasher: &mut Sha256) {
        hasher.update(self.sequence.to_be_bytes());
        hasher.update(self.raft_log_index.to_be_bytes());
        hasher.update(
            self.committed_at
                .as_offset_datetime()
                .unix_timestamp_nanos()
                .to_be_bytes(),
        );
    }
}

impl fmt::Debug for ConsensusCommitMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConsensusCommitMetadata(<redacted>)")
    }
}

#[derive(Serialize)]
struct CommittedTerminalWireRef<'a> {
    record: &'a TerminalRecord,
    commit_metadata: ConsensusCommitMetadata,
    committing_registration_handle: [u8; 32],
    committing_registration_request_id: RequestId,
    committing_registration_terminal_slot_id: [u8; 32],
    committing_authority_scope: [u8; 32],
    committing_authority_key: &'a SessionKey,
    committing_authority_owner: &'a OwnerId,
    committing_authority_fence: FenceToken,
    committing_authority_credential_id: u64,
    committing_authority_generation: Generation,
    committing_authority_acquired_at: Timestamp,
    committing_authority_expires_at: Timestamp,
    committing_guard_commitment: [u8; 32],
    materialization: TerminalMaterializationWire,
    receipt_commitment: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct CommittedTerminalWire {
    record: TerminalRecord,
    commit_metadata: ConsensusCommitMetadata,
    committing_registration_handle: [u8; 32],
    committing_registration_request_id: RequestId,
    committing_registration_terminal_slot_id: [u8; 32],
    committing_authority_scope: [u8; 32],
    committing_authority_key: SessionKey,
    committing_authority_owner: OwnerId,
    committing_authority_fence: FenceToken,
    committing_authority_credential_id: u64,
    committing_authority_generation: Generation,
    committing_authority_acquired_at: Timestamp,
    committing_authority_expires_at: Timestamp,
    committing_guard_commitment: [u8; 32],
    materialization: TerminalMaterializationWire,
    receipt_commitment: [u8; 32],
}

/// Backend-issued result of the one atomic terminal transaction.
///
/// It binds the canonical terminal record, the guard that committed it, and
/// the business materialization into one receipt. The executor never mints
/// publication authority from a prepared body; it first validates this exact
/// stored composite against the current request.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CommittedTerminal {
    record: TerminalRecord,
    commit_metadata: ConsensusCommitMetadata,
    committing_registration: BackendRegistration,
    committing_authority: AuthorityBinding,
    committing_guard_commitment: [u8; 32],
    materialization: TerminalMaterialization,
    receipt_commitment: [u8; 32],
}

impl CommittedTerminal {
    /// Build the exact durable composite while the backend holds its terminal
    /// transaction lock. This is crate-private so production adapters can use
    /// the same contract without exposing a caller-side proof constructor.
    pub(crate) fn issue(
        registration: BackendRegistration,
        admission: &Admission,
        authority: &AuthorityBinding,
        body: &TerminalBody,
        commit_metadata: ConsensusCommitMetadata,
    ) -> Result<Self, ExecutorError> {
        validate_terminal_request_shape(registration, admission, authority, body)?;
        commit_metadata.validate_for_authority(authority)?;
        let materialization = TerminalMaterialization::for_body(admission, body)?;
        let committing_guard_commitment =
            terminal_committing_guard_commitment(registration, admission, authority);
        let record = body.record().clone();
        let receipt_commitment = terminal_receipt_commitment(
            registration,
            admission,
            &record,
            authority.fence(),
            committing_guard_commitment,
            &materialization,
            commit_metadata,
        );
        Ok(Self {
            record,
            commit_metadata,
            committing_registration: registration,
            committing_authority: authority.clone(),
            committing_guard_commitment,
            materialization,
            receipt_commitment,
        })
    }

    /// Build the same validated composite from a canonical retained record.
    /// This seam exists for consensus storage and its production transaction
    /// tests; it does not expose a caller-side terminal proof constructor.
    pub(crate) fn issue_from_record(
        registration: BackendRegistration,
        admission: &Admission,
        authority: &AuthorityBinding,
        record: TerminalRecord,
        commit_metadata: ConsensusCommitMetadata,
    ) -> Result<Self, ExecutorError> {
        let body = TerminalBody::from_record(record, admission)?;
        Self::issue(registration, admission, authority, &body, commit_metadata)
    }

    /// Encode the exact historical terminal composite for consensus storage,
    /// snapshots, and cross-node replay. Protected bytes are copied verbatim
    /// from the committed terminal record; this path never reseals them.
    pub(crate) fn to_canonical_bytes(
        &self,
        admission: &Admission,
    ) -> Result<Vec<u8>, ExecutorError> {
        let body = TerminalBody::from_record(self.record.clone(), admission)?;
        self.validate_for_terminal_commit(
            self.committing_registration,
            admission,
            &self.committing_authority,
            &body,
        )?;
        let wire = CommittedTerminalWireRef {
            record: &self.record,
            commit_metadata: self.commit_metadata,
            committing_registration_handle: self.committing_registration.handle,
            committing_registration_request_id: self.committing_registration.request_id(),
            committing_registration_terminal_slot_id: *self
                .committing_registration
                .terminal_slot_id()
                .as_bytes(),
            committing_authority_scope: self.committing_authority.scope().digest(),
            committing_authority_key: self.committing_authority.key(),
            committing_authority_owner: self.committing_authority.owner(),
            committing_authority_fence: self.committing_authority.fence(),
            committing_authority_credential_id: self.committing_authority.credential_id(),
            committing_authority_generation: self.committing_authority.generation(),
            committing_authority_acquired_at: self.committing_authority.acquired_at(),
            committing_authority_expires_at: self.committing_authority.expires_at(),
            committing_guard_commitment: self.committing_guard_commitment,
            materialization: TerminalMaterializationWire::from(&self.materialization),
            receipt_commitment: self.receipt_commitment,
        };
        encode_frame(
            COMMITTED_TERMINAL_FRAME_MAGIC,
            COMMITTED_TERMINAL_FRAME_DOMAIN,
            &wire,
            MAX_COMMITTED_TERMINAL_CODEC_BYTES,
        )
        .map_err(|_| ExecutorError::InvalidTerminal)
    }

    /// Rehydrate and fully revalidate one exact consensus-retained terminal
    /// composite. The original committing guard remains historical provenance;
    /// a successor's current higher guard is validated separately on read.
    pub(crate) fn from_canonical_bytes(
        bytes: &[u8],
        admission: &Admission,
    ) -> Result<Self, ExecutorError> {
        let wire: CommittedTerminalWire = decode_frame(
            bytes,
            COMMITTED_TERMINAL_FRAME_MAGIC,
            COMMITTED_TERMINAL_FRAME_DOMAIN,
            MAX_COMMITTED_TERMINAL_CODEC_BYTES,
        )
        .map_err(|_| ExecutorError::InvalidTerminal)?;
        let committing_registration = BackendRegistration::issue(
            wire.committing_registration_handle,
            wire.committing_registration_request_id,
            admission,
        )?;
        wire.commit_metadata.validate()?;
        if wire.committing_registration_terminal_slot_id
            != *committing_registration.terminal_slot_id().as_bytes()
        {
            return Err(ExecutorError::InvalidTerminal);
        }
        let committing_authority = AuthorityBinding::for_recovery(
            Scope::from_digest(wire.committing_authority_scope),
            wire.committing_authority_key,
            wire.committing_authority_owner,
            wire.committing_authority_fence,
            AuthorityLeaseMetadata::new(
                wire.committing_authority_credential_id,
                wire.committing_authority_generation,
                wire.committing_authority_acquired_at,
                wire.committing_authority_expires_at,
            ),
        )?;
        let value = Self {
            record: wire.record,
            commit_metadata: wire.commit_metadata,
            committing_registration,
            committing_authority,
            committing_guard_commitment: wire.committing_guard_commitment,
            materialization: wire.materialization.into(),
            receipt_commitment: wire.receipt_commitment,
        };
        let body = TerminalBody::from_record(value.record.clone(), admission)?;
        value.validate_for_terminal_commit(
            value.committing_registration,
            admission,
            &value.committing_authority,
            &body,
        )?;
        if value.to_canonical_bytes(admission)? != bytes {
            return Err(ExecutorError::InvalidTerminal);
        }
        Ok(value)
    }

    /// Validate the self-contained commitment shape of retained terminal bytes.
    ///
    /// This does not grant publication authority: callers must still use
    /// [`Self::from_canonical_bytes`] with the exact recovered admission. It is
    /// used at the consensus response boundary to reject a response capsule
    /// whose embedded terminal body differs from the submitted command.
    pub(crate) fn canonical_terminal_body_commitment(
        bytes: &[u8],
    ) -> Result<[u8; 32], ExecutorError> {
        let wire: CommittedTerminalWire = decode_frame(
            bytes,
            COMMITTED_TERMINAL_FRAME_MAGIC,
            COMMITTED_TERMINAL_FRAME_DOMAIN,
            MAX_COMMITTED_TERMINAL_CODEC_BYTES,
        )
        .map_err(|_| ExecutorError::InvalidTerminal)?;
        wire.record
            .validate_self_contained()
            .map_err(|_| ExecutorError::InvalidTerminal)?;
        wire.commit_metadata.validate()?;
        AuthorityBinding::for_recovery(
            Scope::from_digest(wire.committing_authority_scope),
            wire.committing_authority_key.clone(),
            wire.committing_authority_owner.clone(),
            wire.committing_authority_fence,
            AuthorityLeaseMetadata::new(
                wire.committing_authority_credential_id,
                wire.committing_authority_generation,
                wire.committing_authority_acquired_at,
                wire.committing_authority_expires_at,
            ),
        )?;
        let phase_matches_materialization = matches!(
            (wire.record.phase(), &wire.materialization),
            (
                Ok(Phase::Established),
                TerminalMaterializationWire::Updated { .. }
                    | TerminalMaterializationWire::Deleted { .. }
                    | TerminalMaterializationWire::NoOp { .. }
            ) | (Ok(Phase::Aborted), TerminalMaterializationWire::Aborted)
        );
        if wire.committing_registration_handle == [0; 32]
            || wire.committing_registration_terminal_slot_id == [0; 32]
            || wire.committing_registration_request_id != wire.record.request_id()
            || wire.committing_guard_commitment == [0; 32]
            || wire.receipt_commitment == [0; 32]
            || !phase_matches_materialization
            || encode_frame(
                COMMITTED_TERMINAL_FRAME_MAGIC,
                COMMITTED_TERMINAL_FRAME_DOMAIN,
                &wire,
                MAX_COMMITTED_TERMINAL_CODEC_BYTES,
            )
            .map_err(|_| ExecutorError::InvalidTerminal)?
                != bytes
        {
            return Err(ExecutorError::InvalidTerminal);
        }
        Ok(wire.record.body_commitment())
    }

    fn validate_common(
        &self,
        registration: BackendRegistration,
        admission: &Admission,
        authority: &AuthorityBinding,
        body: &TerminalBody,
    ) -> Result<(), ExecutorError> {
        validate_terminal_request_shape(registration, admission, authority, body)?;
        self.commit_metadata
            .validate_for_authority(&self.committing_authority)?;
        let committed_body = TerminalBody::from_record(self.record.clone(), admission)?;
        validate_terminal_request_shape(
            self.committing_registration,
            admission,
            &self.committing_authority,
            &committed_body,
        )?;
        if committed_body != *body
            || self.record.request_id() != registration.request_id()
            || self.committing_guard_commitment == [0; 32]
            || self.committing_guard_commitment
                != terminal_committing_guard_commitment(
                    self.committing_registration,
                    admission,
                    &self.committing_authority,
                )
            || self
                .materialization
                .validate_for(admission, &committed_body)
                .is_err()
            || self.receipt_commitment
                != terminal_receipt_commitment(
                    registration,
                    admission,
                    &self.record,
                    self.committing_authority.fence(),
                    self.committing_guard_commitment,
                    &self.materialization,
                    self.commit_metadata,
                )
        {
            return Err(ExecutorError::InvalidTerminal);
        }
        Ok(())
    }

    /// Validate a freshly committed decision: its historical guard must be
    /// exactly the authority that submitted this irreversible transaction.
    fn validate_for_terminal_commit(
        &self,
        registration: BackendRegistration,
        admission: &Admission,
        authority: &AuthorityBinding,
        body: &TerminalBody,
    ) -> Result<(), ExecutorError> {
        self.validate_common(registration, admission, authority, body)?;
        if self.committing_registration != registration || self.committing_authority != *authority {
            return Err(ExecutorError::InvalidTerminal);
        }
        Ok(())
    }

    pub(crate) fn record(&self) -> &TerminalRecord {
        &self.record
    }

    /// Exact registration that bound the historical terminal proof set.
    ///
    /// Storage uses this only to re-verify retained terminal evidence after a
    /// restart or snapshot install. It is deliberately crate-private so a
    /// caller cannot manufacture a terminal publication capability from it.
    pub(crate) const fn committing_registration(&self) -> BackendRegistration {
        self.committing_registration
    }

    /// Exact authority that committed the historical terminal proof set.
    ///
    /// This is provenance, not a current-leader authority grant. A later
    /// same-body replay may carry proofs issued for a newer authority.
    pub(crate) fn committing_authority(&self) -> &AuthorityBinding {
        &self.committing_authority
    }

    pub(crate) const fn commit_metadata(&self) -> ConsensusCommitMetadata {
        self.commit_metadata
    }

    /// Exact business materialization committed in the same terminal
    /// transaction. Storage adapters use this read-only descriptor to derive
    /// their typed business-row CAS; callers can never substitute opaque
    /// replacement bytes.
    pub(crate) const fn materialization(&self) -> &TerminalMaterialization {
        &self.materialization
    }
}

impl fmt::Debug for CommittedTerminal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CommittedTerminal(<redacted>)")
    }
}

fn validate_terminal_request_shape(
    registration: BackendRegistration,
    admission: &Admission,
    authority: &AuthorityBinding,
    body: &TerminalBody,
) -> Result<(), ExecutorError> {
    registration.validate_for(admission)?;
    body.record()
        .validate_for(admission)
        .map_err(|_| ExecutorError::InvalidTerminal)?;
    if body.record().request_id() != registration.request_id()
        || body
            .record()
            .request_id()
            .terminal_slot_id(admission)
            .map_err(|_| ExecutorError::InvalidTerminal)?
            != registration.terminal_slot_id()
        || authority.scope() != admission.scope()
        || authority.key() != admission.key()
        || authority.generation() != admission.expected_generation()
        || authority.credential_id() == 0
        || authority.fence().get() == 0
        || authority.expires_at() <= authority.acquired_at()
        || (authority.fence() == admission.admission_fence()
            && authority.owner() != admission.logical_owner())
        || authority.fence() < admission.admission_fence()
    {
        return Err(ExecutorError::InvalidTerminal);
    }
    Ok(())
}

fn terminal_committing_guard_commitment(
    registration: BackendRegistration,
    admission: &Admission,
    authority: &AuthorityBinding,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(TERMINAL_COMMITTING_GUARD_DOMAIN);
    hasher.update(admission.profile().schema().to_be_bytes());
    hasher.update(admission.profile().consumer_revision().to_be_bytes());
    hasher.update(admission.profile().digest());
    hasher.update(registration.handle);
    hasher.update(registration.request_id().to_bytes());
    hasher.update(registration.terminal_slot_id().as_bytes());
    hasher.update(admission.body_commitment());
    hasher.update(authority.scope().digest());
    update_terminal_commitment_bytes(&mut hasher, &authority.key().canonical_digest_input());
    update_terminal_commitment_bytes(&mut hasher, authority.owner().as_str().as_bytes());
    hasher.update(authority.fence().get().to_be_bytes());
    hasher.update(authority.credential_id().to_be_bytes());
    hasher.update(authority.generation().get().to_be_bytes());
    hasher.update(
        authority
            .acquired_at()
            .as_offset_datetime()
            .unix_timestamp_nanos()
            .to_be_bytes(),
    );
    hasher.update(
        authority
            .expires_at()
            .as_offset_datetime()
            .unix_timestamp_nanos()
            .to_be_bytes(),
    );
    hasher.finalize().into()
}

fn terminal_record_commitment(
    admission: &Admission,
    generation: Generation,
    state_type: &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(TERMINAL_RECORD_COMMITMENT_DOMAIN);
    hasher.update(admission.profile().schema().to_be_bytes());
    hasher.update(admission.profile().consumer_revision().to_be_bytes());
    hasher.update(admission.profile().digest());
    hasher.update(admission.body_commitment());
    hasher.update(admission.scope().digest());
    update_terminal_commitment_bytes(&mut hasher, &admission.key().canonical_digest_input());
    update_terminal_commitment_bytes(&mut hasher, admission.logical_owner().as_str().as_bytes());
    hasher.update(admission.admission_fence().get().to_be_bytes());
    hasher.update(generation.get().to_be_bytes());
    update_terminal_commitment_bytes(&mut hasher, b"authoritative-session");
    update_terminal_commitment_bytes(&mut hasher, state_type.as_bytes());
    hasher.update([0]); // no expiry is part of the immutable V1 record header
    update_terminal_commitment_bytes(&mut hasher, admission.terminal_checkpoint());
    hasher.finalize().into()
}

fn terminal_receipt_commitment(
    registration: BackendRegistration,
    admission: &Admission,
    record: &TerminalRecord,
    committing_fence: FenceToken,
    committing_guard_commitment: [u8; 32],
    materialization: &TerminalMaterialization,
    commit_metadata: ConsensusCommitMetadata,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(TERMINAL_RECEIPT_COMMITMENT_DOMAIN);
    hasher.update(admission.profile().schema().to_be_bytes());
    hasher.update(admission.profile().consumer_revision().to_be_bytes());
    hasher.update(admission.profile().digest());
    hasher.update(registration.request_id().to_bytes());
    hasher.update(registration.terminal_slot_id().as_bytes());
    hasher.update(admission.body_commitment());
    hasher.update(record.body_commitment());
    hasher.update(match record.phase() {
        Ok(Phase::Established) => [1],
        Ok(Phase::Aborted) => [2],
        Err(_) => [0],
    });
    hasher.update(committing_fence.get().to_be_bytes());
    hasher.update(committing_guard_commitment);
    commit_metadata.update_commitment(&mut hasher);
    materialization.update_receipt_commitment(&mut hasher);
    hasher.finalize().into()
}

fn update_terminal_commitment_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}
