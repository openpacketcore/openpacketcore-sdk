//! Generic, bounded roster profile for fenced multi-member mutations.
//!
//! This module deliberately contains no backend implementation.  It defines
//! the stable identities, canonical wire values, and validation shared by a
//! store adapter and its callers.  In particular, no value in this module
//! identifies a transport, a peer address, or a concrete member kind.

use std::{error::Error, fmt};

use crate::model::{FenceToken, Generation, OwnerId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The frozen wire-schema revision for this roster profile.
pub const SCHEMA_V1: u16 = 1;
/// Maximum members in one roster plan.
pub const MAX_MEMBERS: usize = 8;
/// Maximum protected plan or terminal checkpoint bytes accepted by this profile.
pub const MAX_PLAN_BYTES: usize = 1_048_576;
/// Maximum protected terminal result bytes accepted by this profile.
pub const MAX_RESULT_BYTES: usize = 16_384;
/// Maximum nonterminal admissions retained by an implementation.
pub const MAX_LIVE_NONTERMINAL: usize = 1_024;
/// Maximum terminal results retained by an implementation.
pub const MAX_RETAINED_RESULTS: usize = 131_072;
/// Maximum receipts reclaimed in one bounded implementation batch.
pub const RECLAIM_BATCH: usize = 1_024;
/// Required terminal-result retention period, in seconds.
pub const RETENTION_SECS: u64 = 86_400;
/// Fixed width of a caller-selected member identity.
pub const MEMBER_ID_BYTES: usize = 16;
/// Maximum canonical descriptor bytes for one member.
pub const MAX_DESCRIPTOR_BYTES: usize = 4_096;
/// Maximum canonical status bytes for one member outcome.
pub const MAX_STATUS_BYTES: usize = 4_096;
/// Maximum opaque owner binding bytes.
pub const MAX_OWNER_BYTES: usize = 1_024;
/// Maximum opaque fence binding bytes.
pub const MAX_FENCE_BYTES: usize = 1_024;
/// Compatibility name for the frozen roster schema revision.
pub const FENCED_MUTATION_ROSTER_SCHEMA_V1: u16 = SCHEMA_V1;
/// Compatibility name for the fixed operation-ID width.
pub const FENCED_MUTATION_ROSTER_OPERATION_ID_BYTES: usize = MEMBER_ID_BYTES;
/// Exact encoded request-ID width.
pub const FENCED_MUTATION_ROSTER_REQUEST_ID_BYTES: usize = 56;
/// Fixed scope commitment width.
pub const FENCED_MUTATION_ROSTER_SCOPE_BYTES: usize = 32;
/// Minimum roster members accepted by the generic profile.
pub const FENCED_MUTATION_ROSTER_MIN_MEMBERS: usize = 0;
/// Compatibility name for the member bound.
pub const FENCED_MUTATION_ROSTER_MAX_MEMBERS: usize = MAX_MEMBERS;
/// Maximum protected plan or checkpoint bytes.
pub const FENCED_MUTATION_ROSTER_MAX_PLAN_OR_CHECKPOINT_BYTES: usize = MAX_PLAN_BYTES;
/// Maximum exact protected result bytes.
pub const FENCED_MUTATION_ROSTER_MAX_EXACT_RESULT_BYTES: usize = MAX_RESULT_BYTES;
/// Compatibility name for the live roster bound.
pub const FENCED_MUTATION_ROSTER_MAX_LIVE: usize = MAX_LIVE_NONTERMINAL;
/// Operational target below permanent retained-result capacity.
pub const FENCED_MUTATION_ROSTER_OPERATIONAL_TARGET: usize = 100_000;
/// Compatibility name for retained-result capacity.
pub const FENCED_MUTATION_ROSTER_RETAINED_RESULT_CAPACITY: usize = MAX_RETAINED_RESULTS;
/// Compatibility name for reclamation batch size.
pub const FENCED_MUTATION_ROSTER_RECLAIM_BATCH: usize = RECLAIM_BATCH;
/// Compatibility name for retention duration.
pub const FENCED_MUTATION_ROSTER_RETENTION_SECONDS: u64 = RETENTION_SECS;
/// Conservative admission codec bound for every simultaneously legal field maximum.
pub const FENCED_MUTATION_ROSTER_ADMISSION_CODEC_MAX_BYTES: usize =
    POSTCARD_ADMISSION_FIXED_MAX_BYTES
        + POSTCARD_MEMBER_MANIFEST_CODEC_MAX_BYTES
        + POSTCARD_LENGTH_PREFIX_MAX_BYTES
        + MAX_PLAN_BYTES
        + POSTCARD_LENGTH_PREFIX_MAX_BYTES
        + MAX_RESULT_BYTES;
/// Conservative terminal codec bound for every simultaneously legal field maximum.
pub const FENCED_MUTATION_ROSTER_TERMINAL_CODEC_MAX_BYTES: usize = TERMINAL_CODEC_FIXED_BYTES
    + (MAX_MEMBERS * TERMINAL_MEMBER_OUTCOME_CODEC_MAX_BYTES)
    + CANONICAL_LENGTH_PREFIX_BYTES
    + MAX_PLAN_BYTES
    + CANONICAL_LENGTH_PREFIX_BYTES
    + MAX_RESULT_BYTES;
/// Conservative identity codec bound.
pub const FENCED_MUTATION_ROSTER_IDENTITY_CODEC_MAX_BYTES: usize = 128;
/// Conservative member manifest codec bound.
pub const FENCED_MUTATION_ROSTER_MEMBER_MANIFEST_CODEC_MAX_BYTES: usize =
    POSTCARD_MEMBER_MANIFEST_CODEC_MAX_BYTES;
/// Frozen profile digest for static metadata consumers.
pub const FENCED_MUTATION_ROSTER_PROFILE_DIGEST: [u8; 32] = [
    0xa1, 0x84, 0x36, 0xce, 0xf6, 0x65, 0xf2, 0xdb, 0x3f, 0x25, 0x65, 0xf3, 0x4f, 0x36, 0x55, 0x7b,
    0x20, 0xa1, 0x30, 0x66, 0x1d, 0x6a, 0xad, 0x6c, 0xef, 0x84, 0xf3, 0x92, 0x91, 0x1f, 0x42, 0xda,
];

const PLAN_MAGIC: &[u8; 8] = b"OPCFMRP1";
const TERMINAL_MAGIC: &[u8; 8] = b"OPCFMRT1";
const BODY_DOMAIN: &[u8] = b"opc-session-store/fenced-mutation-roster/body/v1";
const REQUEST_DOMAIN: &[u8] = b"opc-session-store/fenced-mutation-roster/request/v1";
const PROFILE_DOMAIN: &[u8] = b"opc-session-store/fenced-mutation-roster/profile/v1";

// Postcard encodes all integers and collection lengths as varints. These
// bounds deliberately use the largest portable varint, rather than relying on
// the smaller encodings of the current profile maxima.
const POSTCARD_U64_MAX_BYTES: usize = 10;
const POSTCARD_LENGTH_PREFIX_MAX_BYTES: usize = 10;
const POSTCARD_MEMBER_CODEC_MAX_BYTES: usize = 1
    + MEMBER_ID_BYTES
    + POSTCARD_LENGTH_PREFIX_MAX_BYTES
    + MAX_DESCRIPTOR_BYTES
    + (2 * POSTCARD_U64_MAX_BYTES)
    + 2;
const POSTCARD_MEMBER_MANIFEST_CODEC_MAX_BYTES: usize =
    POSTCARD_LENGTH_PREFIX_MAX_BYTES + (MAX_MEMBERS * POSTCARD_MEMBER_CODEC_MAX_BYTES);
const POSTCARD_ADMISSION_FIXED_MAX_BYTES: usize = POSTCARD_U64_MAX_BYTES
    + MEMBER_ID_BYTES
    + FENCED_MUTATION_ROSTER_SCOPE_BYTES
    + POSTCARD_LENGTH_PREFIX_MAX_BYTES
    + OwnerId::MAX_BYTES
    + (2 * POSTCARD_U64_MAX_BYTES);

const CANONICAL_LENGTH_PREFIX_BYTES: usize = 4;
const TERMINAL_MEMBER_OUTCOME_CODEC_MAX_BYTES: usize =
    1 + MEMBER_ID_BYTES + 2 + CANONICAL_LENGTH_PREFIX_BYTES + MAX_STATUS_BYTES;
const TERMINAL_CODEC_FIXED_BYTES: usize = TERMINAL_MAGIC.len() + 2 + 32 + 1;

/// One fixed canonical ordinal in the generic six-member roster.
///
/// Ordinals have no product semantics in this SDK.  An adapter may document
/// its own role mapping, but canonical plans always retain their ordinal
/// ordering and never encode a product-specific role name.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FencedMutationRosterOrdinal(u8);

impl FencedMutationRosterOrdinal {
    /// Construct one canonical ordinal within the profile member bound.
    pub fn new(value: u8) -> Result<Self, FencedMutationRosterError> {
        if (value as usize) < MAX_MEMBERS {
            Ok(Self(value))
        } else {
            Err(FencedMutationRosterError::MemberLimitExceeded)
        }
    }
    /// Return the canonical ordinal value.
    pub fn get(self) -> u8 {
        self.0
    }
}

impl fmt::Debug for FencedMutationRosterOrdinal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FencedMutationRosterOrdinal(<redacted>)")
    }
}

/// Stable, caller-retained nonzero operation identity.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FencedMutationRosterOperationId([u8; MEMBER_ID_BYTES]);

impl FencedMutationRosterOperationId {
    /// Construct a nonzero operation identity.
    pub fn new(bytes: [u8; MEMBER_ID_BYTES]) -> Result<Self, FencedMutationRosterError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(FencedMutationRosterError::LifecycleConflict);
        }
        Ok(Self(bytes))
    }

    /// Borrow the fixed-width identity for a trusted transport implementation.
    pub fn as_bytes(&self) -> &[u8; MEMBER_ID_BYTES] {
        &self.0
    }
}

impl fmt::Debug for FencedMutationRosterOperationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FencedMutationRosterOperationId(<redacted>)")
    }
}

/// Full idempotency identity for one exact canonical roster body.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FencedMutationRosterRequestId {
    epoch: u64,
    operation_id: FencedMutationRosterOperationId,
    body_commitment: [u8; 32],
}

impl FencedMutationRosterRequestId {
    /// Construct an identity after checking that its operation component is nonzero.
    pub fn new(
        epoch: u64,
        operation_id: FencedMutationRosterOperationId,
        body_commitment: [u8; 32],
    ) -> Self {
        Self {
            epoch,
            operation_id,
            body_commitment,
        }
    }

    /// Derive an identity that commits to `plan`'s exact canonical body.
    pub fn for_plan(
        epoch: u64,
        operation_id: FencedMutationRosterOperationId,
        plan: &FencedMutationRosterPlan,
    ) -> Self {
        Self::new(epoch, operation_id, plan.body_commitment())
    }

    /// Return the durable history epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    /// Return the caller operation component.
    pub fn operation_id(&self) -> FencedMutationRosterOperationId {
        self.operation_id
    }
    /// Return the body commitment component.
    pub fn body_commitment(&self) -> [u8; 32] {
        self.body_commitment
    }

    /// Compute a domain-separated commitment to the complete request identity.
    pub fn request_commitment(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(REQUEST_DOMAIN);
        hash.update([0]);
        hash.update(self.epoch.to_be_bytes());
        hash.update(self.operation_id.0);
        hash.update(self.body_commitment);
        hash.finalize().into()
    }
    /// Encode the complete fixed-width identity.
    pub fn to_bytes(&self) -> [u8; FENCED_MUTATION_ROSTER_REQUEST_ID_BYTES] {
        encode_fenced_mutation_roster_identity(*self)
    }
}

impl fmt::Debug for FencedMutationRosterRequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FencedMutationRosterRequestId(<redacted>)")
    }
}

/// Durable phase of a roster request receipt.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[repr(u8)]
pub enum FencedMutationRosterPhase {
    /// No receipt is durably known.
    Absent = 0,
    /// Admission is recorded but member effects are not terminal.
    PollAdmitted = 1,
    /// A complete terminal receipt is durably known.
    Established = 2,
    /// Admission was durably aborted before establishment.
    Aborted = 3,
}

/// Valid receipt-history transition requested from an adapter.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[repr(u8)]
pub enum FencedMutationRosterTransition {
    /// Bind a previously absent request identity to its canonical plan.
    Admit = 1,
    /// Store the one terminal outcome for an admitted request identity.
    Terminalize = 2,
}

/// Durable disposition of one member's requested change.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[repr(u8)]
pub enum FencedMutationRosterDisposition {
    /// A member effect remains pending.
    Pending = 0,
    /// The member effect was applied.
    Applied = 1,
    /// The member effect was compensated.
    Compensated = 2,
    /// The member effect cannot be determined from durable evidence.
    Indeterminate = 3,
    /// The member effect was conclusively not applied.
    NotApplied = 4,
}

/// Adoption state of one member's requested change.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[repr(u8)]
pub enum FencedMutationRosterAdoption {
    /// No conclusive reconciliation evidence is retained.
    Unreconciled = 0,
    /// The requested effect was executed under the admitted fence.
    Executed = 1,
    /// The intended member state was adopted.
    Adopted = 2,
    /// The member state was reconciled with durable evidence.
    Reconciled = 3,
}

/// Canonically bounded opaque member descriptor bytes.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FencedMutationRosterDescriptor(Vec<u8>);

impl FencedMutationRosterDescriptor {
    /// Validate and retain canonical descriptor bytes.
    pub fn new(bytes: Vec<u8>) -> Result<Self, FencedMutationRosterError> {
        checked_len(
            bytes.len(),
            MAX_DESCRIPTOR_BYTES,
            FencedMutationRosterError::DescriptorTooLarge,
        )?;
        Ok(Self(bytes))
    }
    /// Borrow the descriptor bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for FencedMutationRosterDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "FencedMutationRosterDescriptor(len={})",
            self.0.len()
        )
    }
}

/// Canonically bounded opaque member status bytes.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FencedMutationRosterStatusBytes(Vec<u8>);

impl FencedMutationRosterStatusBytes {
    /// Validate and retain canonical status bytes.
    pub fn new(bytes: Vec<u8>) -> Result<Self, FencedMutationRosterError> {
        checked_len(
            bytes.len(),
            MAX_STATUS_BYTES,
            FencedMutationRosterError::StatusTooLarge,
        )?;
        Ok(Self(bytes))
    }
    /// Borrow the status bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for FencedMutationRosterStatusBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "FencedMutationRosterStatusBytes(len={})",
            self.0.len()
        )
    }
}

/// One ordered member guarded by a stable caller identity and expected state.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FencedMutationRosterMember {
    ordinal: FencedMutationRosterOrdinal,
    caller_id: [u8; MEMBER_ID_BYTES],
    descriptor: FencedMutationRosterDescriptor,
    expected_generation: u64,
    expected_version: u64,
    disposition: FencedMutationRosterDisposition,
    adoption: FencedMutationRosterAdoption,
}

impl FencedMutationRosterMember {
    /// Construct one member.  Member IDs must be nonzero.
    pub fn new(
        ordinal: FencedMutationRosterOrdinal,
        caller_id: [u8; MEMBER_ID_BYTES],
        descriptor: FencedMutationRosterDescriptor,
        expected_generation: u64,
        expected_version: u64,
        disposition: FencedMutationRosterDisposition,
        adoption: FencedMutationRosterAdoption,
    ) -> Result<Self, FencedMutationRosterError> {
        if caller_id.iter().all(|byte| *byte == 0) {
            return Err(FencedMutationRosterError::LifecycleConflict);
        }
        Ok(Self {
            ordinal,
            caller_id,
            descriptor,
            expected_generation,
            expected_version,
            disposition,
            adoption,
        })
    }

    /// Return the fixed canonical role ordinal.
    pub fn ordinal(&self) -> FencedMutationRosterOrdinal {
        self.ordinal
    }
    /// Return the stable caller-selected member ID.
    pub fn caller_id(&self) -> &[u8; MEMBER_ID_BYTES] {
        &self.caller_id
    }
    /// Return the canonical descriptor.
    pub fn descriptor(&self) -> &FencedMutationRosterDescriptor {
        &self.descriptor
    }
    /// Return the expected member record generation.
    pub fn expected_generation(&self) -> u64 {
        self.expected_generation
    }
    /// Return the expected member version.
    pub fn expected_version(&self) -> u64 {
        self.expected_version
    }
    /// Return the requested disposition.
    pub fn disposition(&self) -> FencedMutationRosterDisposition {
        self.disposition
    }
    /// Return the requested adoption state.
    pub fn adoption(&self) -> FencedMutationRosterAdoption {
        self.adoption
    }
}

impl fmt::Debug for FencedMutationRosterMember {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FencedMutationRosterMember(<redacted>)")
    }
}

/// Immutable, fenced plan admitted before member effects can become terminal.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FencedMutationRosterPlan {
    profile_commitment: [u8; 32],
    scope_commitment: [u8; 32],
    owner: Vec<u8>,
    fence: Vec<u8>,
    expected_record_generation: u64,
    members: Vec<FencedMutationRosterMember>,
    protected_plan: Vec<u8>,
    terminal_checkpoint: Vec<u8>,
}

impl FencedMutationRosterPlan {
    /// Construct and validate an immutable roster plan.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        profile_commitment: [u8; 32],
        scope_commitment: [u8; 32],
        owner: Vec<u8>,
        fence: Vec<u8>,
        expected_record_generation: u64,
        members: Vec<FencedMutationRosterMember>,
        protected_plan: Vec<u8>,
        terminal_checkpoint: Vec<u8>,
    ) -> Result<Self, FencedMutationRosterError> {
        checked_nonempty_len(
            owner.len(),
            MAX_OWNER_BYTES,
            FencedMutationRosterError::StaleOwnerFence,
        )?;
        checked_nonempty_len(
            fence.len(),
            MAX_FENCE_BYTES,
            FencedMutationRosterError::StaleOwnerFence,
        )?;
        checked_len(
            protected_plan.len(),
            MAX_PLAN_BYTES,
            FencedMutationRosterError::PlanTooLarge,
        )?;
        checked_len(
            terminal_checkpoint.len(),
            MAX_PLAN_BYTES,
            FencedMutationRosterError::ResultTooLarge,
        )?;
        validate_members(&members)?;
        Ok(Self {
            profile_commitment,
            scope_commitment,
            owner,
            fence,
            expected_record_generation,
            members,
            protected_plan,
            terminal_checkpoint,
        })
    }
    /// Return the immutable profile commitment.
    pub fn profile_commitment(&self) -> [u8; 32] {
        self.profile_commitment
    }
    /// Return the immutable scope commitment.
    pub fn scope_commitment(&self) -> [u8; 32] {
        self.scope_commitment
    }
    /// Return the expected record generation.
    pub fn expected_record_generation(&self) -> u64 {
        self.expected_record_generation
    }
    /// Return the ordered member list.
    pub fn members(&self) -> &[FencedMutationRosterMember] {
        &self.members
    }
    /// Borrow the protected plan bytes.
    pub fn protected_plan(&self) -> &[u8] {
        &self.protected_plan
    }
    /// Borrow the predeclared terminal checkpoint bytes.
    pub fn terminal_checkpoint(&self) -> &[u8] {
        &self.terminal_checkpoint
    }
    /// Return whether a current owner, fence, and generation still bind this exact plan.
    pub fn binds(&self, owner: &[u8], fence: &[u8], generation: u64) -> bool {
        self.owner.as_slice() == owner
            && self.fence.as_slice() == fence
            && self.expected_record_generation == generation
    }
    /// Produce the exact canonical plan bytes.
    pub fn encode_canonical(&self) -> Vec<u8> {
        encode_plan(self)
    }
    /// Decode an exact canonical plan, rejecting malformed and trailing bytes.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, FencedMutationRosterError> {
        let plan = decode_plan(bytes)?;
        if plan.encode_canonical() != bytes {
            return Err(FencedMutationRosterError::LifecycleConflict);
        }
        Ok(plan)
    }
    /// Compute a domain-separated commitment to the exact canonical plan.
    pub fn body_commitment(&self) -> [u8; 32] {
        roster_body_commitment(&self.encode_canonical())
    }
    /// Compute the immutable admission commitment used by a terminal receipt.
    pub fn admission_commitment(&self) -> [u8; 32] {
        self.body_commitment()
    }
}

impl fmt::Debug for FencedMutationRosterPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "FencedMutationRosterPlan(members={})",
            self.members.len()
        )
    }
}

/// One terminal member outcome, including opaque bounded status.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FencedMutationRosterMemberOutcome {
    ordinal: FencedMutationRosterOrdinal,
    caller_id: [u8; MEMBER_ID_BYTES],
    disposition: FencedMutationRosterDisposition,
    adoption: FencedMutationRosterAdoption,
    status: FencedMutationRosterStatusBytes,
}

impl FencedMutationRosterMemberOutcome {
    /// Construct one terminal member outcome with a nonzero caller ID.
    pub fn new(
        ordinal: FencedMutationRosterOrdinal,
        caller_id: [u8; MEMBER_ID_BYTES],
        disposition: FencedMutationRosterDisposition,
        adoption: FencedMutationRosterAdoption,
        status: FencedMutationRosterStatusBytes,
    ) -> Result<Self, FencedMutationRosterError> {
        if caller_id.iter().all(|byte| *byte == 0) {
            return Err(FencedMutationRosterError::LifecycleConflict);
        }
        Ok(Self {
            ordinal,
            caller_id,
            disposition,
            adoption,
            status,
        })
    }
    /// Return the fixed canonical role ordinal.
    pub fn ordinal(&self) -> FencedMutationRosterOrdinal {
        self.ordinal
    }
    /// Return the stable member ID.
    pub fn caller_id(&self) -> &[u8; MEMBER_ID_BYTES] {
        &self.caller_id
    }
    /// Return the terminal disposition.
    pub fn disposition(&self) -> FencedMutationRosterDisposition {
        self.disposition
    }
    /// Return the terminal adoption state.
    pub fn adoption(&self) -> FencedMutationRosterAdoption {
        self.adoption
    }
    /// Return the bounded opaque status bytes.
    pub fn status(&self) -> &FencedMutationRosterStatusBytes {
        &self.status
    }
}

impl fmt::Debug for FencedMutationRosterMemberOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FencedMutationRosterMemberOutcome(<redacted>)")
    }
}

/// Complete terminal receipt for one admitted roster request.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FencedMutationRosterTerminal {
    admission_commitment: [u8; 32],
    members: Vec<FencedMutationRosterMemberOutcome>,
    protected_checkpoint: Vec<u8>,
    protected_result: Vec<u8>,
}

impl FencedMutationRosterTerminal {
    /// Construct a complete terminal result with bounded protected bytes.
    pub(crate) fn new(
        admission_commitment: [u8; 32],
        members: Vec<FencedMutationRosterMemberOutcome>,
        protected_checkpoint: Vec<u8>,
        protected_result: Vec<u8>,
    ) -> Result<Self, FencedMutationRosterError> {
        checked_len(
            protected_checkpoint.len(),
            MAX_PLAN_BYTES,
            FencedMutationRosterError::ResultTooLarge,
        )?;
        checked_len(
            protected_result.len(),
            MAX_RESULT_BYTES,
            FencedMutationRosterError::ResultTooLarge,
        )?;
        validate_outcomes(&members)?;
        Ok(Self {
            admission_commitment,
            members,
            protected_checkpoint,
            protected_result,
        })
    }

    /// Build a terminal receipt only from SDK-issued conclusive member proofs.
    pub fn from_member_proofs(
        admission: &FencedMutationRosterAdmission,
        proofs: &[FencedMutationRosterMemberProof],
        current_fence: FenceToken,
        protected_checkpoint: Vec<u8>,
        protected_result: Vec<u8>,
    ) -> Result<Self, FencedMutationRosterError> {
        if proofs.len() != admission.members().len() {
            return Err(FencedMutationRosterError::LifecycleConflict);
        }
        let mut outcomes = Vec::with_capacity(proofs.len());
        for proof in proofs {
            proof.validate_for(admission, current_fence)?;
            let (disposition, adoption) = match proof.outcome {
                FencedMutationRosterProviderOutcome::AppliedExecuted => (
                    FencedMutationRosterDisposition::Applied,
                    FencedMutationRosterAdoption::Executed,
                ),
                FencedMutationRosterProviderOutcome::AppliedAdopted => (
                    FencedMutationRosterDisposition::Applied,
                    FencedMutationRosterAdoption::Adopted,
                ),
                FencedMutationRosterProviderOutcome::NotAppliedReconciled => (
                    FencedMutationRosterDisposition::NotApplied,
                    FencedMutationRosterAdoption::Reconciled,
                ),
                FencedMutationRosterProviderOutcome::CompensatedReconciled => (
                    FencedMutationRosterDisposition::Compensated,
                    FencedMutationRosterAdoption::Reconciled,
                ),
            };
            outcomes.push(FencedMutationRosterMemberOutcome::new(
                proof.ordinal,
                proof.member_operation_id,
                disposition,
                adoption,
                FencedMutationRosterStatusBytes::new(Vec::new())?,
            )?);
        }
        Self::new(
            admission.request_id().body_commitment(),
            outcomes,
            protected_checkpoint,
            protected_result,
        )
    }
    /// Return the admission commitment that this receipt terminalizes.
    pub fn admission_commitment(&self) -> [u8; 32] {
        self.admission_commitment
    }
    /// Return the full ordered terminal outcomes.
    pub fn members(&self) -> &[FencedMutationRosterMemberOutcome] {
        &self.members
    }
    /// Borrow protected checkpoint bytes.
    pub fn protected_checkpoint(&self) -> &[u8] {
        &self.protected_checkpoint
    }
    /// Borrow protected result bytes.
    pub fn protected_result(&self) -> &[u8] {
        &self.protected_result
    }
    /// Return true only if this terminal exactly belongs to `plan` and its member order.
    pub fn belongs_to(&self, plan: &FencedMutationRosterPlan) -> bool {
        self.admission_commitment == plan.admission_commitment()
            && self.members.len() == plan.members.len()
            && self
                .members
                .iter()
                .zip(&plan.members)
                .all(|(outcome, member)| {
                    outcome.ordinal == member.ordinal && outcome.caller_id == member.caller_id
                })
            && self.protected_result == plan.terminal_checkpoint
    }
    /// Produce exact canonical terminal bytes.
    pub fn encode_canonical(&self) -> Vec<u8> {
        encode_terminal(self)
    }
    /// Decode exact canonical terminal bytes, rejecting malformed and trailing input.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, FencedMutationRosterError> {
        let terminal = decode_terminal(bytes)?;
        if terminal.encode_canonical() != bytes {
            return Err(FencedMutationRosterError::LifecycleConflict);
        }
        Ok(terminal)
    }
    /// Return the terminal phase inferred from the conclusive member matrix.
    pub fn phase(&self) -> FencedMutationRosterPhase {
        if self.members.iter().all(|member| {
            member.disposition == FencedMutationRosterDisposition::Applied
                && matches!(
                    member.adoption,
                    FencedMutationRosterAdoption::Executed | FencedMutationRosterAdoption::Adopted
                )
        }) {
            FencedMutationRosterPhase::Established
        } else {
            FencedMutationRosterPhase::Aborted
        }
    }
    /// Validate the exact admission commitment, member identity/order, and terminal matrix.
    pub fn validate_for_admission(
        &self,
        admission: &FencedMutationRosterAdmission,
    ) -> Result<(), FencedMutationRosterError> {
        if !self.belongs_to(&FencedMutationRosterPlan::new(
            fenced_mutation_roster_profile_digest(),
            admission.scope().digest(),
            admission
                .fence_intent()
                .owner()
                .as_str()
                .as_bytes()
                .to_vec(),
            admission
                .fence_intent()
                .fence()
                .get()
                .to_be_bytes()
                .to_vec(),
            admission.expected_generation().get(),
            admission.members().as_slice().to_vec(),
            admission.protected_plan().as_bytes().to_vec(),
            self.protected_result.clone(),
        )?) {
            return Err(FencedMutationRosterError::RequestConflict);
        }
        let established = self.members.iter().all(|member| {
            member.disposition == FencedMutationRosterDisposition::Applied
                && matches!(
                    member.adoption,
                    FencedMutationRosterAdoption::Executed | FencedMutationRosterAdoption::Adopted
                )
        });
        let aborted = self.members.iter().all(|member| {
            matches!(
                member.disposition,
                FencedMutationRosterDisposition::NotApplied
                    | FencedMutationRosterDisposition::Compensated
            ) && member.adoption == FencedMutationRosterAdoption::Reconciled
        });
        if established || aborted {
            Ok(())
        } else {
            Err(FencedMutationRosterError::Indeterminate)
        }
    }
}

impl fmt::Debug for FencedMutationRosterTerminal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "FencedMutationRosterTerminal(members={})",
            self.members.len()
        )
    }
}

/// Durable status returned by a roster adapter.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FencedMutationRosterStatus {
    phase: FencedMutationRosterPhase,
    request_id: FencedMutationRosterRequestId,
    terminal: Option<FencedMutationRosterTerminal>,
}

impl FencedMutationRosterStatus {
    /// Construct a status; terminal data is legal only for `Established`.
    pub fn new(
        phase: FencedMutationRosterPhase,
        request_id: FencedMutationRosterRequestId,
        terminal: Option<FencedMutationRosterTerminal>,
    ) -> Result<Self, FencedMutationRosterError> {
        match (phase, terminal.is_some()) {
            (FencedMutationRosterPhase::Established, true)
            | (
                FencedMutationRosterPhase::Absent
                | FencedMutationRosterPhase::PollAdmitted
                | FencedMutationRosterPhase::Aborted,
                false,
            ) => Ok(Self {
                phase,
                request_id,
                terminal,
            }),
            _ => Err(FencedMutationRosterError::LifecycleConflict),
        }
    }
    /// Return the receipt phase.
    pub fn phase(&self) -> FencedMutationRosterPhase {
        self.phase
    }
    /// Return the stable request identity.
    pub fn request_id(&self) -> FencedMutationRosterRequestId {
        self.request_id
    }
    /// Return the terminal receipt when established.
    pub fn terminal(&self) -> Option<&FencedMutationRosterTerminal> {
        self.terminal.as_ref()
    }
}

impl fmt::Debug for FencedMutationRosterStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "FencedMutationRosterStatus(phase={:?}, request_id=<redacted>)",
            self.phase
        )
    }
}

/// Successful execution result.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FencedMutationRosterResult {
    /// Admission is durable but not yet terminal.
    Pending(FencedMutationRosterStatus),
    /// The complete terminal result is durable.
    Terminal(FencedMutationRosterTerminal),
}

impl fmt::Debug for FencedMutationRosterResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending(_) => {
                formatter.write_str("FencedMutationRosterResult::Pending(<redacted>)")
            }
            Self::Terminal(_) => {
                formatter.write_str("FencedMutationRosterResult::Terminal(<redacted>)")
            }
        }
    }
}

/// Failure to execute or observe a roster request.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FencedMutationRosterExecuteError {
    /// The adapter proves no request was transmitted; retry may reuse its identity.
    NotTransmitted,
    /// Transmission may have occurred, so the caller must poll this identity before retrying.
    OutcomeUnknown {
        /// Stable identity that may have been admitted.
        request_id: FencedMutationRosterRequestId,
    },
    /// The adapter rejected the operation before it could produce a result.
    Rejected(FencedMutationRosterError),
}

impl FencedMutationRosterExecuteError {
    /// Return the identity requiring reconciliation when the outcome is ambiguous.
    pub fn request_id(&self) -> Option<FencedMutationRosterRequestId> {
        match self {
            Self::OutcomeUnknown { request_id } => Some(*request_id),
            Self::NotTransmitted | Self::Rejected(_) => None,
        }
    }
}

impl fmt::Debug for FencedMutationRosterExecuteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotTransmitted => formatter.write_str("NotTransmitted"),
            Self::OutcomeUnknown { .. } => {
                formatter.write_str("OutcomeUnknown { request_id: <redacted> }")
            }
            Self::Rejected(error) => write!(formatter, "Rejected({error:?})"),
        }
    }
}

impl fmt::Display for FencedMutationRosterExecuteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotTransmitted => "roster request was not transmitted",
            Self::OutcomeUnknown { .. } => "roster request outcome is unknown",
            Self::Rejected(error) => return error.fmt(formatter),
        })
    }
}
impl Error for FencedMutationRosterExecuteError {}

/// Validation, admission, and lifecycle errors for this profile.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FencedMutationRosterError {
    /// The same operation identity is already bound to a different body.
    RequestConflict,
    /// The selected backend lacks this profile's required capability.
    CapabilityNotSupported,
    /// The admitted owner or fence no longer matches.
    StaleOwnerFence,
    /// A record or member generation differs from its expected value.
    GenerationConflict,
    /// The owner lease is no longer valid.
    LeaseLost,
    /// The requested receipt phase transition is invalid.
    LifecycleConflict,
    /// The roster has more than `MAX_MEMBERS` members.
    MemberLimitExceeded,
    /// A member descriptor exceeds `MAX_DESCRIPTOR_BYTES`.
    DescriptorTooLarge,
    /// A member status exceeds `MAX_STATUS_BYTES`.
    StatusTooLarge,
    /// Protected plan bytes exceed `MAX_PLAN_BYTES`.
    PlanTooLarge,
    /// Protected result or checkpoint bytes exceed `MAX_RESULT_BYTES`.
    ResultTooLarge,
    /// Nonterminal admission capacity is exhausted.
    LiveLimitReached,
    /// Retained terminal history capacity is exhausted.
    HistoryFull,
    /// The requested history epoch was retired.
    Retired,
    /// Durable evidence cannot determine a member or request outcome.
    Indeterminate,
}

impl fmt::Debug for FencedMutationRosterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}
impl fmt::Display for FencedMutationRosterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}
impl Error for FencedMutationRosterError {}
impl FencedMutationRosterError {
    fn name(&self) -> &'static str {
        match self {
            Self::RequestConflict => "RequestConflict",
            Self::CapabilityNotSupported => "CapabilityNotSupported",
            Self::StaleOwnerFence => "StaleOwnerFence",
            Self::GenerationConflict => "GenerationConflict",
            Self::LeaseLost => "LeaseLost",
            Self::LifecycleConflict => "LifecycleConflict",
            Self::MemberLimitExceeded => "MemberLimitExceeded",
            Self::DescriptorTooLarge => "DescriptorTooLarge",
            Self::StatusTooLarge => "StatusTooLarge",
            Self::PlanTooLarge => "PlanTooLarge",
            Self::ResultTooLarge => "ResultTooLarge",
            Self::LiveLimitReached => "LiveLimitReached",
            Self::HistoryFull => "HistoryFull",
            Self::Retired => "Retired",
            Self::Indeterminate => "Indeterminate",
        }
    }
    fn message(&self) -> &'static str {
        match self {
            Self::RequestConflict => "roster request conflicts with its existing binding",
            Self::CapabilityNotSupported => "roster capability is not supported",
            Self::StaleOwnerFence => "roster owner or fence is stale",
            Self::GenerationConflict => "roster generation conflicts",
            Self::LeaseLost => "roster lease was lost",
            Self::LifecycleConflict => "roster lifecycle conflict",
            Self::MemberLimitExceeded => "roster member limit exceeded",
            Self::DescriptorTooLarge => "roster descriptor is too large",
            Self::StatusTooLarge => "roster status is too large",
            Self::PlanTooLarge => "roster plan is too large",
            Self::ResultTooLarge => "roster result is too large",
            Self::LiveLimitReached => "roster live admission limit reached",
            Self::HistoryFull => "roster retained history is full",
            Self::Retired => "roster history is retired",
            Self::Indeterminate => "roster outcome is indeterminate",
        }
    }
}

/// Return the fixed digest of this profile's complete validation contract.
pub fn fenced_mutation_roster_profile_digest() -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(PROFILE_DOMAIN);
    hash.update([0]);
    for value in [
        SCHEMA_V1 as u64,
        MAX_MEMBERS as u64,
        MAX_PLAN_BYTES as u64,
        MAX_RESULT_BYTES as u64,
        MAX_LIVE_NONTERMINAL as u64,
        MAX_RETAINED_RESULTS as u64,
        RECLAIM_BATCH as u64,
        RETENTION_SECS,
        MEMBER_ID_BYTES as u64,
        MAX_DESCRIPTOR_BYTES as u64,
        MAX_STATUS_BYTES as u64,
        MAX_OWNER_BYTES as u64,
        MAX_FENCE_BYTES as u64,
    ] {
        hash.update(value.to_be_bytes());
    }
    hash.finalize().into()
}

/// Compute the domain-separated body commitment for exact canonical plan bytes.
pub fn roster_body_commitment(canonical_plan: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(BODY_DOMAIN);
    hash.update([0]);
    hash.update((canonical_plan.len() as u64).to_be_bytes());
    hash.update(canonical_plan);
    hash.finalize().into()
}

/// Alias for the terminal member disposition vocabulary.
pub type FencedMutationMemberDisposition = FencedMutationRosterDisposition;
/// Alias for the terminal member adoption vocabulary.
pub type FencedMutationMemberAdoption = FencedMutationRosterAdoption;

/// Stable nonzero member identity in a roster manifest.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FencedMutationMemberOperationId([u8; MEMBER_ID_BYTES]);
impl FencedMutationMemberOperationId {
    /// Construct a nonzero stable member identity.
    pub fn new(bytes: [u8; MEMBER_ID_BYTES]) -> Result<Self, FencedMutationRosterError> {
        if bytes.iter().all(|byte| *byte == 0) {
            Err(FencedMutationRosterError::LifecycleConflict)
        } else {
            Ok(Self(bytes))
        }
    }
    /// Borrow the fixed-width member identity.
    pub fn as_bytes(&self) -> &[u8; MEMBER_ID_BYTES] {
        &self.0
    }
}
impl fmt::Debug for FencedMutationMemberOperationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FencedMutationMemberOperationId(<redacted>)")
    }
}

/// Immutable scope binding retained as a digest only.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FencedMutationRosterScope([u8; FENCED_MUTATION_ROSTER_SCOPE_BYTES]);
impl FencedMutationRosterScope {
    /// Construct a scope from a caller-authenticated digest.
    pub const fn from_digest(digest: [u8; FENCED_MUTATION_ROSTER_SCOPE_BYTES]) -> Self {
        Self(digest)
    }
    /// Return the fixed-width scope digest.
    pub const fn digest(self) -> [u8; FENCED_MUTATION_ROSTER_SCOPE_BYTES] {
        self.0
    }
}
impl fmt::Debug for FencedMutationRosterScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FencedMutationRosterScope(<redacted>)")
    }
}

/// Logical owner plus the admission fence, distinct from any successor execution fence.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FencedMutationRosterFenceIntent {
    owner: OwnerId,
    fence: FenceToken,
}
impl FencedMutationRosterFenceIntent {
    /// Bind a logical owner and nonzero admission fence.
    pub fn new(owner: OwnerId, fence: FenceToken) -> Self {
        Self { owner, fence }
    }
    /// Borrow the logical owner.
    pub fn owner(&self) -> &OwnerId {
        &self.owner
    }
    /// Return the fence captured at admission.
    pub fn fence(&self) -> FenceToken {
        self.fence
    }
}
impl fmt::Debug for FencedMutationRosterFenceIntent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FencedMutationRosterFenceIntent(<redacted>)")
    }
}

/// Bounded, caller-protected plan or checkpoint bytes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FencedMutationRosterProtectedPlan(Box<[u8]>);
impl FencedMutationRosterProtectedPlan {
    /// Retain bytes only when they meet the exact protected-plan bound.
    pub fn new(bytes: Box<[u8]>) -> Result<Self, FencedMutationRosterError> {
        checked_len(
            bytes.len(),
            MAX_PLAN_BYTES,
            FencedMutationRosterError::PlanTooLarge,
        )?;
        Ok(Self(bytes))
    }
    /// Borrow the exact protected bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    /// Return the exact protected byte length.
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// Return whether the protected body is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
impl fmt::Debug for FencedMutationRosterProtectedPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FencedMutationRosterProtectedPlan(len={})", self.0.len())
    }
}

/// Bounded, caller-protected exact terminal response bytes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FencedMutationRosterProtectedResult(Box<[u8]>);
impl FencedMutationRosterProtectedResult {
    /// Retain bytes only when they meet the exact protected-result bound.
    pub fn new(bytes: Box<[u8]>) -> Result<Self, FencedMutationRosterError> {
        checked_len(
            bytes.len(),
            MAX_RESULT_BYTES,
            FencedMutationRosterError::ResultTooLarge,
        )?;
        Ok(Self(bytes))
    }
    /// Borrow the exact protected bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
impl fmt::Debug for FencedMutationRosterProtectedResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FencedMutationRosterProtectedResult(len={})",
            self.0.len()
        )
    }
}

/// A bounded ordered roster manifest.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FencedMutationRosterMembers(Vec<FencedMutationRosterMember>);
impl FencedMutationRosterMembers {
    /// Construct an ordered member manifest.
    pub fn new<const N: usize>(
        members: [FencedMutationRosterMember; N],
    ) -> Result<Self, FencedMutationRosterError> {
        let members = Vec::from(members);
        validate_members(&members)?;
        Ok(Self(members))
    }
    /// Borrow ordered members.
    pub fn as_slice(&self) -> &[FencedMutationRosterMember] {
        &self.0
    }
    /// Return the manifest length.
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// Return whether the manifest is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
impl fmt::Debug for FencedMutationRosterMembers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FencedMutationRosterMembers(len={})", self.0.len())
    }
}

/// Complete immutable admission body for all roster phases.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FencedMutationRosterAdmission {
    history_epoch: u64,
    operation_id: FencedMutationRosterOperationId,
    scope: FencedMutationRosterScope,
    fence_intent: FencedMutationRosterFenceIntent,
    expected_generation: Generation,
    members: FencedMutationRosterMembers,
    protected_plan: FencedMutationRosterProtectedPlan,
    #[serde(default)]
    terminal_result: FencedMutationRosterProtectedResult,
}
impl FencedMutationRosterAdmission {
    /// Construct one exact immutable admission binding.
    pub fn new(
        history_epoch: u64,
        operation_id: FencedMutationRosterOperationId,
        scope: FencedMutationRosterScope,
        fence_intent: FencedMutationRosterFenceIntent,
        expected_generation: Generation,
        members: FencedMutationRosterMembers,
        protected_plan: FencedMutationRosterProtectedPlan,
    ) -> Result<Self, FencedMutationRosterError> {
        let value = Self {
            history_epoch,
            operation_id,
            scope,
            fence_intent,
            expected_generation,
            members,
            protected_plan,
            terminal_result: FencedMutationRosterProtectedResult::new(Box::new([]))?,
        };
        value.validate()?;
        Ok(value)
    }
    /// Return the stable self-authenticating request identity.
    pub fn request_id(&self) -> FencedMutationRosterRequestId {
        FencedMutationRosterRequestId::new(
            self.history_epoch,
            self.operation_id,
            roster_body_commitment(&self.canonical_body()),
        )
    }
    /// Validate all immutable bindings and bounded members.
    pub fn validate(&self) -> Result<(), FencedMutationRosterError> {
        validate_members(self.members.as_slice())
    }
    /// Return the immutable scope commitment.
    pub fn scope(&self) -> FencedMutationRosterScope {
        self.scope
    }
    /// Return the logical owner/fence binding.
    pub fn fence_intent(&self) -> &FencedMutationRosterFenceIntent {
        &self.fence_intent
    }
    /// Return the expected record generation.
    pub fn expected_generation(&self) -> Generation {
        self.expected_generation
    }
    /// Return the ordered immutable member manifest.
    pub fn members(&self) -> &FencedMutationRosterMembers {
        &self.members
    }
    /// Borrow exact protected plan bytes.
    pub fn protected_plan(&self) -> &FencedMutationRosterProtectedPlan {
        &self.protected_plan
    }
    /// Bind the prebuilt exact terminal result before admission.
    pub fn with_terminal_result(
        mut self,
        result: FencedMutationRosterProtectedResult,
    ) -> Result<Self, FencedMutationRosterError> {
        self.terminal_result = result;
        self.validate()?;
        Ok(self)
    }
    /// Borrow the prebuilt exact terminal result bound into the request ID.
    pub fn terminal_result(&self) -> &FencedMutationRosterProtectedResult {
        &self.terminal_result
    }
    fn canonical_body(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.history_epoch.to_be_bytes());
        out.extend_from_slice(self.operation_id.as_bytes());
        out.extend_from_slice(&self.scope.0);
        put_bytes(&mut out, self.fence_intent.owner.as_str().as_bytes());
        out.extend_from_slice(&self.fence_intent.fence.get().to_be_bytes());
        out.extend_from_slice(&self.expected_generation.get().to_be_bytes());
        put_u32(&mut out, self.members.len());
        for member in self.members.as_slice() {
            put_member(&mut out, member);
        }
        put_bytes(&mut out, self.protected_plan.as_bytes());
        put_bytes(&mut out, self.terminal_result.as_bytes());
        out
    }
}
impl fmt::Debug for FencedMutationRosterAdmission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FencedMutationRosterAdmission(<redacted>)")
    }
}

/// One member's conclusive terminal status.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FencedMutationMemberTerminalStatus {
    disposition: FencedMutationRosterDisposition,
    adoption: FencedMutationRosterAdoption,
}
impl FencedMutationMemberTerminalStatus {
    /// Construct one terminal status.
    pub const fn new(
        disposition: FencedMutationRosterDisposition,
        adoption: FencedMutationRosterAdoption,
    ) -> Self {
        Self {
            disposition,
            adoption,
        }
    }
    /// Return terminal disposition.
    pub const fn disposition(self) -> FencedMutationRosterDisposition {
        self.disposition
    }
    /// Return terminal adoption.
    pub const fn adoption(self) -> FencedMutationRosterAdoption {
        self.adoption
    }
}
impl fmt::Debug for FencedMutationMemberTerminalStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FencedMutationMemberTerminalStatus(<redacted>)")
    }
}

/// Capability proof emitted by a roster-capable implementation.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub enum FencedMutationRosterCapability {
    /// Version-one bounded roster capability.
    V1,
}
/// Public immutable profile proof.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FencedMutationRosterProfile {
    /// Schema revision.
    pub schema: u16,
    /// Domain profile digest.
    pub digest: [u8; 32],
}
impl FencedMutationRosterProfile {
    /// Return the sole version-one profile.
    pub fn v1() -> Self {
        Self {
            schema: SCHEMA_V1,
            digest: fenced_mutation_roster_profile_digest(),
        }
    }
}
impl fmt::Debug for FencedMutationRosterProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FencedMutationRosterProfile(<redacted>)")
    }
}
/// Bounded retained history counters.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct FencedMutationRosterHistoryState {
    /// Active history epoch.
    pub active_epoch: u64,
    /// Highest retired epoch.
    pub retired_through: u64,
    /// Lifecycle generation.
    pub generation: u64,
    /// Bound admissions.
    pub bound: u64,
    /// Live admissions.
    pub live: u64,
}
/// Public phase result from an admission or terminalization attempt.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FencedMutationRosterOutcome {
    /// Current status.
    pub status: FencedMutationRosterStatus,
}
impl fmt::Debug for FencedMutationRosterOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FencedMutationRosterOutcome(<redacted>)")
    }
}
/// Redaction-safe, durable roster error status.
pub type FencedMutationRosterErrorStatus = FencedMutationRosterError;
/// A prepared immutable roster admission; all phases reuse this one identity.
pub type FencedMutationRosterPrepared = FencedMutationRosterAdmission;
/// Generic phase API implemented by a roster-capable store profile.
pub trait FencedMutationRosterProfileApi {
    /// Prepare an exact immutable admission before any member effect is permitted.
    fn prepare_roster(
        &self,
        admission: FencedMutationRosterAdmission,
    ) -> Result<FencedMutationRosterPrepared, FencedMutationRosterError>;
    /// Durably admit a prepared roster and reserve its eventual retained-result slot.
    fn admit_roster(
        &self,
        prepared: &FencedMutationRosterPrepared,
    ) -> Result<FencedMutationRosterOutcome, FencedMutationRosterError>;
    /// Read exact authenticated status without transmitting member work.
    fn roster_status(
        &self,
        prepared: &FencedMutationRosterPrepared,
        phase: FencedMutationRosterPhase,
    ) -> Result<FencedMutationRosterStatus, FencedMutationRosterError>;
    /// Read exact authenticated adoption evidence without transmitting member work.
    fn roster_adoption(
        &self,
        prepared: &FencedMutationRosterPrepared,
    ) -> Result<FencedMutationRosterStatus, FencedMutationRosterError>;
    /// Prepare one conclusive terminal body for the same prepared roster ID.
    fn prepare_terminal(
        &self,
        prepared: &FencedMutationRosterPrepared,
        terminal: FencedMutationRosterTerminal,
    ) -> Result<FencedMutationRosterTerminal, FencedMutationRosterError>;
    /// Atomically move an admitted roster from live to retained terminal history.
    fn terminalize_roster(
        &self,
        prepared: &FencedMutationRosterPrepared,
        terminal: &FencedMutationRosterTerminal,
    ) -> Result<FencedMutationRosterOutcome, FencedMutationRosterError>;
}

/// Conclusive provider result used to issue a member proof.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub enum FencedMutationRosterProviderOutcome {
    /// Provider conclusively executed the effect.
    AppliedExecuted,
    /// Provider conclusively adopted the effect.
    AppliedAdopted,
    /// Provider conclusively proved the effect was not applied.
    NotAppliedReconciled,
    /// Provider conclusively compensated and reconciled the effect.
    CompensatedReconciled,
}

/// Opaque SDK-issued evidence for one member operation.  Fields are private
/// so a consumer cannot manufacture `Applied` or `NotApplied` terminal state.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FencedMutationRosterMemberProof {
    roster_id: FencedMutationRosterRequestId,
    phase_commitment: [u8; 32],
    ordinal: FencedMutationRosterOrdinal,
    member_operation_id: [u8; MEMBER_ID_BYTES],
    descriptor_commitment: [u8; 32],
    expected_version: u64,
    execution_fence: FenceToken,
    outcome: FencedMutationRosterProviderOutcome,
}

impl fmt::Debug for FencedMutationRosterMemberProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FencedMutationRosterMemberProof(<redacted>)")
    }
}

impl FencedMutationRosterMemberProof {
    pub(crate) fn issue(
        admission: &FencedMutationRosterAdmission,
        member: &FencedMutationRosterMember,
        current_fence: FenceToken,
        outcome: FencedMutationRosterProviderOutcome,
    ) -> Self {
        Self {
            roster_id: admission.request_id(),
            phase_commitment: roster_body_commitment(&admission.canonical_body()),
            ordinal: member.ordinal(),
            member_operation_id: *member.caller_id(),
            descriptor_commitment: roster_body_commitment(member.descriptor().as_bytes()),
            expected_version: member.expected_version(),
            execution_fence: current_fence,
            outcome,
        }
    }
    /// Validate that this proof belongs to the exact immutable roster member.
    pub fn validate_for(
        &self,
        admission: &FencedMutationRosterAdmission,
        current_fence: FenceToken,
    ) -> Result<(), FencedMutationRosterError> {
        if self.roster_id != admission.request_id()
            || self.execution_fence != current_fence
            || self.phase_commitment != roster_body_commitment(&admission.canonical_body())
        {
            return Err(FencedMutationRosterError::RequestConflict);
        }
        let member = admission
            .members()
            .as_slice()
            .iter()
            .find(|member| member.ordinal() == self.ordinal)
            .ok_or(FencedMutationRosterError::LifecycleConflict)?;
        if member.caller_id() != &self.member_operation_id
            || roster_body_commitment(member.descriptor().as_bytes()) != self.descriptor_commitment
            || member.expected_version() != self.expected_version
        {
            return Err(FencedMutationRosterError::RequestConflict);
        }
        Ok(())
    }
    /// Return the conclusive provider outcome.
    pub fn outcome(&self) -> FencedMutationRosterProviderOutcome {
        self.outcome
    }
}

/// Generic opaque member provider.  The SDK owns proof issuance and all
/// ambiguity handling; providers never assert terminal dispositions directly.
pub trait FencedMutationRosterMemberProvider {
    /// Provider error returned without creating a terminal proof.
    type Error;
    /// Execute one member under the current guard.
    fn execute_member(
        &self,
        recovered: &FencedMutationRosterAdmission,
        ordinal: FencedMutationRosterOrdinal,
        current_fence: FenceToken,
    ) -> Result<FencedMutationRosterMemberProof, Self::Error>;
    /// Read exact durable status for one member.
    fn member_status(
        &self,
        recovered: &FencedMutationRosterAdmission,
        ordinal: FencedMutationRosterOrdinal,
        current_fence: FenceToken,
    ) -> Result<FencedMutationRosterMemberProof, Self::Error>;
    /// Adopt or reconcile one ambiguous member using durable evidence.
    fn adopt_member(
        &self,
        recovered: &FencedMutationRosterAdmission,
        ordinal: FencedMutationRosterOrdinal,
        current_fence: FenceToken,
    ) -> Result<FencedMutationRosterMemberProof, Self::Error>;
}
/// Compatibility alias for callers using the profile digest spelling.
pub fn compute_fenced_mutation_roster_profile_digest() -> [u8; 32] {
    fenced_mutation_roster_profile_digest()
}

/// Encode an admission with a bounded deterministic binary codec.
pub fn encode_fenced_mutation_roster_admission(
    admission: &FencedMutationRosterAdmission,
) -> Result<Vec<u8>, FencedMutationRosterError> {
    admission.validate()?;
    let bytes = postcard::to_allocvec(admission)
        .map_err(|_| FencedMutationRosterError::LifecycleConflict)?;
    checked_len(
        bytes.len(),
        FENCED_MUTATION_ROSTER_ADMISSION_CODEC_MAX_BYTES,
        FencedMutationRosterError::PlanTooLarge,
    )?;
    Ok(bytes)
}
/// Decode an exact admission codec frame, rejecting trailing bytes.
pub fn decode_fenced_mutation_roster_admission(
    bytes: &[u8],
) -> Result<FencedMutationRosterAdmission, FencedMutationRosterError> {
    checked_len(
        bytes.len(),
        FENCED_MUTATION_ROSTER_ADMISSION_CODEC_MAX_BYTES,
        FencedMutationRosterError::PlanTooLarge,
    )?;
    let (value, remainder): (FencedMutationRosterAdmission, &[u8]) =
        postcard::take_from_bytes(bytes)
            .map_err(|_| FencedMutationRosterError::LifecycleConflict)?;
    if !remainder.is_empty() {
        return Err(FencedMutationRosterError::LifecycleConflict);
    }
    value.validate()?;
    if encode_fenced_mutation_roster_admission(&value)? != bytes {
        return Err(FencedMutationRosterError::LifecycleConflict);
    }
    Ok(value)
}
/// Encode an exact terminal codec frame.
pub fn encode_fenced_mutation_roster_terminal(
    terminal: &FencedMutationRosterTerminal,
) -> Result<Vec<u8>, FencedMutationRosterError> {
    let bytes = terminal.encode_canonical();
    checked_len(
        bytes.len(),
        FENCED_MUTATION_ROSTER_TERMINAL_CODEC_MAX_BYTES,
        FencedMutationRosterError::ResultTooLarge,
    )?;
    Ok(bytes)
}
/// Decode an exact terminal codec frame, rejecting trailing bytes.
pub fn decode_fenced_mutation_roster_terminal(
    bytes: &[u8],
) -> Result<FencedMutationRosterTerminal, FencedMutationRosterError> {
    checked_len(
        bytes.len(),
        FENCED_MUTATION_ROSTER_TERMINAL_CODEC_MAX_BYTES,
        FencedMutationRosterError::ResultTooLarge,
    )?;
    FencedMutationRosterTerminal::decode_canonical(bytes)
}
/// Encode the fixed-width request identity.
pub fn encode_fenced_mutation_roster_identity(
    identity: FencedMutationRosterRequestId,
) -> [u8; FENCED_MUTATION_ROSTER_REQUEST_ID_BYTES] {
    let mut bytes = [0; FENCED_MUTATION_ROSTER_REQUEST_ID_BYTES];
    bytes[..8].copy_from_slice(&identity.epoch.to_be_bytes());
    bytes[8..24].copy_from_slice(identity.operation_id.as_bytes());
    bytes[24..].copy_from_slice(&identity.body_commitment);
    bytes
}
/// Decode the exact fixed-width request identity.
pub fn decode_fenced_mutation_roster_identity(
    bytes: &[u8],
) -> Result<FencedMutationRosterRequestId, FencedMutationRosterError> {
    let array: [u8; FENCED_MUTATION_ROSTER_REQUEST_ID_BYTES] = bytes
        .try_into()
        .map_err(|_| FencedMutationRosterError::LifecycleConflict)?;
    let epoch = u64::from_be_bytes(
        array[..8]
            .try_into()
            .map_err(|_| FencedMutationRosterError::LifecycleConflict)?,
    );
    let operation_id = FencedMutationRosterOperationId::new(
        array[8..24]
            .try_into()
            .map_err(|_| FencedMutationRosterError::LifecycleConflict)?,
    )?;
    Ok(FencedMutationRosterRequestId::new(
        epoch,
        operation_id,
        array[24..]
            .try_into()
            .map_err(|_| FencedMutationRosterError::LifecycleConflict)?,
    ))
}
/// Encode a bounded member manifest.
pub fn encode_fenced_mutation_roster_member_manifest(
    members: &FencedMutationRosterMembers,
) -> Result<Vec<u8>, FencedMutationRosterError> {
    let bytes =
        postcard::to_allocvec(members).map_err(|_| FencedMutationRosterError::LifecycleConflict)?;
    checked_len(
        bytes.len(),
        FENCED_MUTATION_ROSTER_MEMBER_MANIFEST_CODEC_MAX_BYTES,
        FencedMutationRosterError::MemberLimitExceeded,
    )?;
    Ok(bytes)
}
/// Decode an exact member manifest.
pub fn decode_fenced_mutation_roster_member_manifest(
    bytes: &[u8],
) -> Result<FencedMutationRosterMembers, FencedMutationRosterError> {
    checked_len(
        bytes.len(),
        FENCED_MUTATION_ROSTER_MEMBER_MANIFEST_CODEC_MAX_BYTES,
        FencedMutationRosterError::MemberLimitExceeded,
    )?;
    let (members, trailing): (FencedMutationRosterMembers, &[u8]) =
        postcard::take_from_bytes(bytes)
            .map_err(|_| FencedMutationRosterError::LifecycleConflict)?;
    if !trailing.is_empty() {
        return Err(FencedMutationRosterError::LifecycleConflict);
    }
    validate_members(members.as_slice())?;
    Ok(members)
}

fn checked_len(
    length: usize,
    maximum: usize,
    error: FencedMutationRosterError,
) -> Result<(), FencedMutationRosterError> {
    if length > maximum {
        Err(error)
    } else {
        Ok(())
    }
}
fn checked_nonempty_len(
    length: usize,
    maximum: usize,
    error: FencedMutationRosterError,
) -> Result<(), FencedMutationRosterError> {
    if length == 0 || length > maximum {
        Err(error)
    } else {
        Ok(())
    }
}
fn validate_members(
    members: &[FencedMutationRosterMember],
) -> Result<(), FencedMutationRosterError> {
    if members.len() > MAX_MEMBERS {
        return Err(FencedMutationRosterError::MemberLimitExceeded);
    }
    if members
        .iter()
        .enumerate()
        .any(|(index, member)| member.ordinal.get() as usize != index)
        || members
            .windows(2)
            .any(|window| window[0].caller_id >= window[1].caller_id)
    {
        return Err(FencedMutationRosterError::LifecycleConflict);
    }
    Ok(())
}
fn validate_outcomes(
    members: &[FencedMutationRosterMemberOutcome],
) -> Result<(), FencedMutationRosterError> {
    if members.len() > MAX_MEMBERS {
        return Err(FencedMutationRosterError::MemberLimitExceeded);
    }
    if members
        .iter()
        .enumerate()
        .any(|(index, member)| member.ordinal.get() as usize != index)
        || members
            .windows(2)
            .any(|window| window[0].caller_id >= window[1].caller_id)
    {
        return Err(FencedMutationRosterError::LifecycleConflict);
    }
    Ok(())
}
fn put_u32(out: &mut Vec<u8>, value: usize) {
    out.extend_from_slice(&(value as u32).to_be_bytes());
}
fn put_bytes(out: &mut Vec<u8>, value: &[u8]) {
    put_u32(out, value.len());
    out.extend_from_slice(value);
}
fn put_member(out: &mut Vec<u8>, member: &FencedMutationRosterMember) {
    out.push(member.ordinal.get());
    out.extend_from_slice(&member.caller_id);
    put_bytes(out, member.descriptor.as_bytes());
    out.extend_from_slice(&member.expected_generation.to_be_bytes());
    out.extend_from_slice(&member.expected_version.to_be_bytes());
    out.push(member.disposition as u8);
    out.push(member.adoption as u8);
}
fn encode_plan(plan: &FencedMutationRosterPlan) -> Vec<u8> {
    let mut out = Vec::with_capacity(128 + plan.protected_plan.len());
    out.extend_from_slice(PLAN_MAGIC);
    out.extend_from_slice(&SCHEMA_V1.to_be_bytes());
    out.extend_from_slice(&plan.profile_commitment);
    out.extend_from_slice(&plan.scope_commitment);
    put_bytes(&mut out, &plan.owner);
    put_bytes(&mut out, &plan.fence);
    out.extend_from_slice(&plan.expected_record_generation.to_be_bytes());
    out.push(plan.members.len() as u8);
    for member in &plan.members {
        put_member(&mut out, member);
    }
    put_bytes(&mut out, &plan.protected_plan);
    put_bytes(&mut out, &plan.terminal_checkpoint);
    out
}
fn encode_terminal(terminal: &FencedMutationRosterTerminal) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + terminal.protected_result.len());
    out.extend_from_slice(TERMINAL_MAGIC);
    out.extend_from_slice(&SCHEMA_V1.to_be_bytes());
    out.extend_from_slice(&terminal.admission_commitment);
    out.push(terminal.members.len() as u8);
    for member in &terminal.members {
        out.push(member.ordinal.get());
        out.extend_from_slice(&member.caller_id);
        out.push(member.disposition as u8);
        out.push(member.adoption as u8);
        put_bytes(&mut out, member.status.as_bytes());
    }
    put_bytes(&mut out, &terminal.protected_checkpoint);
    put_bytes(&mut out, &terminal.protected_result);
    out
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], FencedMutationRosterError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(FencedMutationRosterError::LifecycleConflict)?;
        let result = self
            .bytes
            .get(self.offset..end)
            .ok_or(FencedMutationRosterError::LifecycleConflict)?;
        self.offset = end;
        Ok(result)
    }
    fn u8(&mut self) -> Result<u8, FencedMutationRosterError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, FencedMutationRosterError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().map_err(
            |_| FencedMutationRosterError::LifecycleConflict,
        )?))
    }
    fn u32(&mut self) -> Result<usize, FencedMutationRosterError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| FencedMutationRosterError::LifecycleConflict)?,
        ) as usize)
    }
    fn u64(&mut self) -> Result<u64, FencedMutationRosterError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().map_err(
            |_| FencedMutationRosterError::LifecycleConflict,
        )?))
    }
    fn bytes(&mut self) -> Result<Vec<u8>, FencedMutationRosterError> {
        let length = self.u32()?;
        Ok(self.take(length)?.to_vec())
    }
    fn array16(&mut self) -> Result<[u8; 16], FencedMutationRosterError> {
        self.take(16)?
            .try_into()
            .map_err(|_| FencedMutationRosterError::LifecycleConflict)
    }
    fn array32(&mut self) -> Result<[u8; 32], FencedMutationRosterError> {
        self.take(32)?
            .try_into()
            .map_err(|_| FencedMutationRosterError::LifecycleConflict)
    }
    fn done(&self) -> bool {
        self.offset == self.bytes.len()
    }
}
fn disposition(tag: u8) -> Result<FencedMutationRosterDisposition, FencedMutationRosterError> {
    match tag {
        0 => Ok(FencedMutationRosterDisposition::Pending),
        1 => Ok(FencedMutationRosterDisposition::Applied),
        2 => Ok(FencedMutationRosterDisposition::Compensated),
        3 => Ok(FencedMutationRosterDisposition::Indeterminate),
        4 => Ok(FencedMutationRosterDisposition::NotApplied),
        _ => Err(FencedMutationRosterError::LifecycleConflict),
    }
}
fn adoption(tag: u8) -> Result<FencedMutationRosterAdoption, FencedMutationRosterError> {
    match tag {
        0 => Ok(FencedMutationRosterAdoption::Unreconciled),
        1 => Ok(FencedMutationRosterAdoption::Executed),
        2 => Ok(FencedMutationRosterAdoption::Adopted),
        3 => Ok(FencedMutationRosterAdoption::Reconciled),
        _ => Err(FencedMutationRosterError::LifecycleConflict),
    }
}
fn decode_plan(bytes: &[u8]) -> Result<FencedMutationRosterPlan, FencedMutationRosterError> {
    let mut reader = Reader::new(bytes);
    if reader.take(8)? != PLAN_MAGIC || reader.u16()? != SCHEMA_V1 {
        return Err(FencedMutationRosterError::LifecycleConflict);
    }
    let profile_commitment = reader.array32()?;
    let scope_commitment = reader.array32()?;
    let owner = reader.bytes()?;
    let fence = reader.bytes()?;
    let expected_record_generation = reader.u64()?;
    let count = reader.u8()? as usize;
    if count > MAX_MEMBERS {
        return Err(FencedMutationRosterError::MemberLimitExceeded);
    }
    let mut members = Vec::with_capacity(count);
    for _ in 0..count {
        let ordinal = FencedMutationRosterOrdinal::new(reader.u8()?)?;
        let caller_id = reader.array16()?;
        let descriptor = FencedMutationRosterDescriptor::new(reader.bytes()?)?;
        let expected_generation = reader.u64()?;
        let expected_version = reader.u64()?;
        let member = FencedMutationRosterMember::new(
            ordinal,
            caller_id,
            descriptor,
            expected_generation,
            expected_version,
            disposition(reader.u8()?)?,
            adoption(reader.u8()?)?,
        )?;
        members.push(member);
    }
    let protected_plan = reader.bytes()?;
    let terminal_checkpoint = reader.bytes()?;
    if !reader.done() {
        return Err(FencedMutationRosterError::LifecycleConflict);
    }
    FencedMutationRosterPlan::new(
        profile_commitment,
        scope_commitment,
        owner,
        fence,
        expected_record_generation,
        members,
        protected_plan,
        terminal_checkpoint,
    )
}
fn decode_terminal(
    bytes: &[u8],
) -> Result<FencedMutationRosterTerminal, FencedMutationRosterError> {
    let mut reader = Reader::new(bytes);
    if reader.take(8)? != TERMINAL_MAGIC || reader.u16()? != SCHEMA_V1 {
        return Err(FencedMutationRosterError::LifecycleConflict);
    }
    let admission_commitment = reader.array32()?;
    let count = reader.u8()? as usize;
    if count > MAX_MEMBERS {
        return Err(FencedMutationRosterError::MemberLimitExceeded);
    }
    let mut members = Vec::with_capacity(count);
    for _ in 0..count {
        let ordinal = FencedMutationRosterOrdinal::new(reader.u8()?)?;
        let caller_id = reader.array16()?;
        let disposition = disposition(reader.u8()?)?;
        let adoption = adoption(reader.u8()?)?;
        let status = FencedMutationRosterStatusBytes::new(reader.bytes()?)?;
        members.push(FencedMutationRosterMemberOutcome::new(
            ordinal,
            caller_id,
            disposition,
            adoption,
            status,
        )?);
    }
    let checkpoint = reader.bytes()?;
    let result = reader.bytes()?;
    if !reader.done() {
        return Err(FencedMutationRosterError::LifecycleConflict);
    }
    FencedMutationRosterTerminal::new(admission_commitment, members, checkpoint, result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::OwnerId;

    fn id(value: u8) -> [u8; 16] {
        [value; 16]
    }
    fn member(ordinal: u8) -> FencedMutationRosterMember {
        FencedMutationRosterMember::new(
            FencedMutationRosterOrdinal::new(ordinal).unwrap(),
            id(ordinal + 1),
            FencedMutationRosterDescriptor::new(vec![ordinal]).unwrap(),
            2,
            3,
            FencedMutationRosterDisposition::Pending,
            FencedMutationRosterAdoption::Unreconciled,
        )
        .unwrap()
    }
    fn plan(
        members: Vec<FencedMutationRosterMember>,
        protected: Vec<u8>,
    ) -> FencedMutationRosterPlan {
        FencedMutationRosterPlan::new(
            fenced_mutation_roster_profile_digest(),
            [7; 32],
            b"owner".to_vec(),
            b"fence".to_vec(),
            9,
            members,
            protected,
            vec![],
        )
        .unwrap()
    }

    fn admission_member(
        ordinal: u8,
        descriptor: Vec<u8>,
        expected_generation: u64,
        expected_version: u64,
        disposition: FencedMutationRosterDisposition,
        adoption: FencedMutationRosterAdoption,
    ) -> FencedMutationRosterMember {
        FencedMutationRosterMember::new(
            FencedMutationRosterOrdinal::new(ordinal).unwrap(),
            id(ordinal + 1),
            FencedMutationRosterDescriptor::new(descriptor).unwrap(),
            expected_generation,
            expected_version,
            disposition,
            adoption,
        )
        .unwrap()
    }

    fn admission_with_member(member: FencedMutationRosterMember) -> FencedMutationRosterAdmission {
        FencedMutationRosterAdmission::new(
            7,
            FencedMutationRosterOperationId::new(id(9)).unwrap(),
            FencedMutationRosterScope::from_digest([4; 32]),
            FencedMutationRosterFenceIntent::new(
                OwnerId::new("roster-owner").unwrap(),
                FenceToken::new(8),
            ),
            Generation::new(9),
            FencedMutationRosterMembers::new([member]).unwrap(),
            FencedMutationRosterProtectedPlan::new(vec![3].into_boxed_slice()).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn admission_request_id_commits_to_every_frozen_member_field() {
        let baseline = admission_with_member(admission_member(
            0,
            vec![1],
            2,
            3,
            FencedMutationRosterDisposition::Pending,
            FencedMutationRosterAdoption::Unreconciled,
        ));
        let baseline_id = baseline.request_id();
        assert_eq!(baseline_id, baseline.clone().request_id());

        let mut ordinal_changed = baseline.clone();
        ordinal_changed.members.0[0].ordinal = FencedMutationRosterOrdinal::new(1).unwrap();
        let mut caller_id_changed = baseline.clone();
        caller_id_changed.members.0[0].caller_id = id(2);
        let mut descriptor_changed = baseline.clone();
        descriptor_changed.members.0[0].descriptor =
            FencedMutationRosterDescriptor::new(vec![2]).unwrap();
        let mut expected_generation_changed = baseline.clone();
        expected_generation_changed.members.0[0].expected_generation = 4;
        let mut expected_version_changed = baseline.clone();
        expected_version_changed.members.0[0].expected_version = 5;
        let mut disposition_changed = baseline.clone();
        disposition_changed.members.0[0].disposition = FencedMutationRosterDisposition::Applied;
        let mut adoption_changed = baseline.clone();
        adoption_changed.members.0[0].adoption = FencedMutationRosterAdoption::Executed;

        for changed in [
            ordinal_changed,
            caller_id_changed,
            descriptor_changed,
            expected_generation_changed,
            expected_version_changed,
            disposition_changed,
            adoption_changed,
        ] {
            assert_ne!(baseline_id, changed.request_id());
        }
    }

    fn maximum_member(ordinal: u8) -> FencedMutationRosterMember {
        admission_member(
            ordinal,
            vec![ordinal; MAX_DESCRIPTOR_BYTES],
            u64::MAX,
            u64::MAX,
            FencedMutationRosterDisposition::NotApplied,
            FencedMutationRosterAdoption::Reconciled,
        )
    }

    fn maximum_members<const N: usize>() -> FencedMutationRosterMembers {
        let members: [FencedMutationRosterMember; N] =
            std::array::from_fn(|ordinal| maximum_member(ordinal as u8));
        FencedMutationRosterMembers::new(members).unwrap()
    }

    fn maximum_admission<const N: usize>() -> FencedMutationRosterAdmission {
        FencedMutationRosterAdmission::new(
            u64::MAX,
            FencedMutationRosterOperationId::new(id(1)).unwrap(),
            FencedMutationRosterScope::from_digest([2; 32]),
            FencedMutationRosterFenceIntent::new(
                OwnerId::new("o".repeat(OwnerId::MAX_BYTES)).unwrap(),
                FenceToken::new(u64::MAX),
            ),
            Generation::new(u64::MAX),
            maximum_members::<N>(),
            FencedMutationRosterProtectedPlan::new(vec![3; MAX_PLAN_BYTES].into_boxed_slice())
                .unwrap(),
        )
        .unwrap()
        .with_terminal_result(
            FencedMutationRosterProtectedResult::new(vec![4; MAX_RESULT_BYTES].into_boxed_slice())
                .unwrap(),
        )
        .unwrap()
    }

    fn maximum_terminal<const N: usize>() -> FencedMutationRosterTerminal {
        let outcomes = (0..N)
            .map(|ordinal| {
                FencedMutationRosterMemberOutcome::new(
                    FencedMutationRosterOrdinal::new(ordinal as u8).unwrap(),
                    id(ordinal as u8 + 1),
                    FencedMutationRosterDisposition::NotApplied,
                    FencedMutationRosterAdoption::Reconciled,
                    FencedMutationRosterStatusBytes::new(vec![ordinal as u8; MAX_STATUS_BYTES])
                        .unwrap(),
                )
                .unwrap()
            })
            .collect();
        FencedMutationRosterTerminal::new(
            [5; 32],
            outcomes,
            vec![6; MAX_PLAN_BYTES],
            vec![7; MAX_RESULT_BYTES],
        )
        .unwrap()
    }

    fn assert_maximum_codec_round_trip<const N: usize>() {
        let manifest = maximum_members::<N>();
        let encoded_manifest = encode_fenced_mutation_roster_member_manifest(&manifest).unwrap();
        assert!(encoded_manifest.len() <= FENCED_MUTATION_ROSTER_MEMBER_MANIFEST_CODEC_MAX_BYTES);
        assert_eq!(
            decode_fenced_mutation_roster_member_manifest(&encoded_manifest).unwrap(),
            manifest
        );

        let admission = maximum_admission::<N>();
        let encoded_admission = encode_fenced_mutation_roster_admission(&admission).unwrap();
        assert!(encoded_admission.len() <= FENCED_MUTATION_ROSTER_ADMISSION_CODEC_MAX_BYTES);
        assert_eq!(
            decode_fenced_mutation_roster_admission(&encoded_admission).unwrap(),
            admission
        );

        let terminal = maximum_terminal::<N>();
        let encoded_terminal = encode_fenced_mutation_roster_terminal(&terminal).unwrap();
        assert!(encoded_terminal.len() <= FENCED_MUTATION_ROSTER_TERMINAL_CODEC_MAX_BYTES);
        assert_eq!(
            decode_fenced_mutation_roster_terminal(&encoded_terminal).unwrap(),
            terminal
        );
    }

    #[test]
    fn exact_maximum_codec_frames_round_trip_for_one_and_eight_members() {
        assert_maximum_codec_round_trip::<1>();
        assert_maximum_codec_round_trip::<MAX_MEMBERS>();
    }

    #[test]
    fn codec_and_domain_bounds_reject_one_over() {
        assert_eq!(
            FencedMutationRosterProtectedPlan::new(vec![0; MAX_PLAN_BYTES + 1].into_boxed_slice()),
            Err(FencedMutationRosterError::PlanTooLarge)
        );
        assert_eq!(
            FencedMutationRosterProtectedResult::new(
                vec![0; MAX_RESULT_BYTES + 1].into_boxed_slice()
            ),
            Err(FencedMutationRosterError::ResultTooLarge)
        );
        assert_eq!(
            FencedMutationRosterTerminal::new([0; 32], vec![], vec![0; MAX_PLAN_BYTES + 1], vec![]),
            Err(FencedMutationRosterError::ResultTooLarge)
        );
        assert_eq!(
            decode_fenced_mutation_roster_member_manifest(&vec![
                0;
                FENCED_MUTATION_ROSTER_MEMBER_MANIFEST_CODEC_MAX_BYTES
                    + 1
            ]),
            Err(FencedMutationRosterError::MemberLimitExceeded)
        );
        assert_eq!(
            decode_fenced_mutation_roster_admission(&vec![
                0;
                FENCED_MUTATION_ROSTER_ADMISSION_CODEC_MAX_BYTES
                    + 1
            ]),
            Err(FencedMutationRosterError::PlanTooLarge)
        );
        assert_eq!(
            decode_fenced_mutation_roster_terminal(&vec![
                0;
                FENCED_MUTATION_ROSTER_TERMINAL_CODEC_MAX_BYTES
                    + 1
            ]),
            Err(FencedMutationRosterError::ResultTooLarge)
        );
    }
    #[test]
    fn accepted_member_arities_are_bounded() {
        for arity in [0_usize, 1, 6, 8] {
            assert_eq!(
                plan(
                    (0..arity).map(|value| member(value as u8)).collect(),
                    vec![]
                )
                .members()
                .len(),
                arity
            );
        }
        let too_many: Vec<_> = (0..9)
            .map(|value| {
                FencedMutationRosterMember::new(
                    FencedMutationRosterOrdinal(value.min(7)),
                    id(value + 1),
                    FencedMutationRosterDescriptor::new(vec![value]).unwrap(),
                    0,
                    0,
                    FencedMutationRosterDisposition::Pending,
                    FencedMutationRosterAdoption::Unreconciled,
                )
                .unwrap()
            })
            .collect();
        assert_eq!(
            FencedMutationRosterPlan::new(
                [0; 32],
                [1; 32],
                vec![1],
                vec![2],
                0,
                too_many,
                vec![],
                vec![]
            ),
            Err(FencedMutationRosterError::MemberLimitExceeded)
        );
    }
    #[test]
    fn duplicate_and_noncanonical_member_order_are_rejected() {
        assert_eq!(
            FencedMutationRosterPlan::new(
                [0; 32],
                [1; 32],
                vec![1],
                vec![2],
                0,
                vec![member(0), member(0)],
                vec![],
                vec![]
            ),
            Err(FencedMutationRosterError::LifecycleConflict)
        );
        assert_eq!(
            FencedMutationRosterPlan::new(
                [0; 32],
                [1; 32],
                vec![1],
                vec![2],
                0,
                vec![member(1), member(0)],
                vec![],
                vec![]
            ),
            Err(FencedMutationRosterError::LifecycleConflict)
        );
    }
    #[test]
    fn exact_and_over_limits_are_enforced() {
        assert!(FencedMutationRosterDescriptor::new(vec![0; MAX_DESCRIPTOR_BYTES]).is_ok());
        assert_eq!(
            FencedMutationRosterDescriptor::new(vec![0; MAX_DESCRIPTOR_BYTES + 1]),
            Err(FencedMutationRosterError::DescriptorTooLarge)
        );
        assert!(FencedMutationRosterStatusBytes::new(vec![0; MAX_STATUS_BYTES]).is_ok());
        assert_eq!(
            FencedMutationRosterStatusBytes::new(vec![0; MAX_STATUS_BYTES + 1]),
            Err(FencedMutationRosterError::StatusTooLarge)
        );
        assert_eq!(
            plan(vec![], vec![0; MAX_PLAN_BYTES]).protected_plan().len(),
            MAX_PLAN_BYTES
        );
        assert_eq!(
            FencedMutationRosterPlan::new(
                [0; 32],
                [1; 32],
                vec![1],
                vec![2],
                0,
                vec![],
                vec![0; MAX_PLAN_BYTES + 1],
                vec![]
            ),
            Err(FencedMutationRosterError::PlanTooLarge)
        );
        let terminal =
            FencedMutationRosterTerminal::new([0; 32], vec![], vec![], vec![0; MAX_RESULT_BYTES]);
        assert!(terminal.is_ok());
        assert_eq!(
            FencedMutationRosterTerminal::new(
                [0; 32],
                vec![],
                vec![],
                vec![0; MAX_RESULT_BYTES + 1]
            ),
            Err(FencedMutationRosterError::ResultTooLarge)
        );
    }
    #[test]
    fn canonical_replay_and_conflict_are_distinct() {
        let roster_plan = plan(vec![member(0)], vec![4, 5]);
        let encoded = roster_plan.encode_canonical();
        assert_eq!(
            FencedMutationRosterPlan::decode_canonical(&encoded).unwrap(),
            roster_plan
        );
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            FencedMutationRosterPlan::decode_canonical(&trailing),
            Err(FencedMutationRosterError::LifecycleConflict)
        );
        let operation = FencedMutationRosterOperationId::new(id(9)).unwrap();
        let request = FencedMutationRosterRequestId::for_plan(4, operation, &roster_plan);
        let other = plan(vec![member(0)], vec![4, 6]);
        assert_ne!(
            request.body_commitment(),
            FencedMutationRosterRequestId::for_plan(4, operation, &other).body_commitment()
        );
    }
    #[test]
    fn profile_digest_is_fixed_and_domain_separated() {
        assert_eq!(
            fenced_mutation_roster_profile_digest(),
            fenced_mutation_roster_profile_digest()
        );
        assert_ne!(
            fenced_mutation_roster_profile_digest(),
            roster_body_commitment(&[])
        );
    }
    #[test]
    fn ambiguity_carries_identity_but_not_nontransmission() {
        let request = FencedMutationRosterRequestId::new(
            1,
            FencedMutationRosterOperationId::new(id(1)).unwrap(),
            [2; 32],
        );
        assert_eq!(
            FencedMutationRosterExecuteError::NotTransmitted.request_id(),
            None
        );
        assert_eq!(
            FencedMutationRosterExecuteError::OutcomeUnknown {
                request_id: request
            }
            .request_id(),
            Some(request)
        );
    }
    #[test]
    fn diagnostics_are_redacted() {
        let request = FencedMutationRosterRequestId::new(
            77,
            FencedMutationRosterOperationId::new(id(7)).unwrap(),
            [9; 32],
        );
        let secret = format!(
            "{request:?} {:?} {:?}",
            FencedMutationRosterExecuteError::OutcomeUnknown {
                request_id: request
            },
            FencedMutationRosterDescriptor::new(b"secret-descriptor".to_vec()).unwrap()
        );
        assert!(!secret.contains("secret-descriptor"));
        assert!(!secret.contains("77"));
        assert!(!secret.contains("0909"));
    }
}
