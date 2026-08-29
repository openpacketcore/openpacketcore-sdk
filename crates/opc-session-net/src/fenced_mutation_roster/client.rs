//! Public, least-authority client for protected fenced-mutation rosters.
//!
//! The client owns neither a consensus backend nor a provider selected by an
//! individual caller.  Its crate-private constructor receives the one
//! startup-owned executor; every public operation consequently uses the same
//! bounded provider and durable authority adapter.  This module exposes only
//! opaque capabilities and redaction-safe outcomes.  In particular, callers
//! cannot construct an applied proof, a member terminal state, or a terminal
//! record.

use super::{
    canonical::{
        AbsentAdmissionProposal, Admission, AdmissionProposal, Error as RosterError,
        EstablishedPublicationCall, Member, Phase, Profile, RosterId, Scope, INITIAL_GENERATION,
        MAX_MEMBERS,
    },
    diagnostics::{Counter, FencedMutationRosterDiagnostics, RosterDiagnostics},
    runtime::{
        AppliedProof, CallResult, ExecutorError, LeaseMetadata, PreparedTerminal,
        PublicationAuthority, RecoveryLeaseAuthority, RecoveryLookup, RecoveryRequest,
        RecoveryResult, Registration, RegistrationRequest, RosterExecutor, RosterExecutorBackend,
        TerminalCommitReceipt, TerminalStatusResult,
    },
};
use async_trait::async_trait;
use opc_session_store::{FenceToken, Generation, LeaseGuard, OwnerId};
use serde::{Deserialize, Deserializer, Serialize};
use std::{fmt, sync::Arc};

/// Fixed, redaction-safe rejection from the protected-roster client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClientError {
    /// A public input was malformed, out of bounds, or profile-incompatible.
    InvalidInput,
    /// The current lease or scope did not authorize the requested operation.
    AuthorityRejected,
    /// Admission found no authoritative session record at the expected key.
    AdmissionRecordMissing,
    /// Admission required exact row absence but an authoritative row exists.
    AdmissionRecordAlreadyExists,
    /// Admission's expected generation did not match the authoritative record.
    AdmissionGenerationConflict,
    /// Admission could not reserve the checked successor generation.
    AdmissionGenerationExhausted,
    /// Another live roster already reserves this exact business key.
    AdmissionBusinessKeyReserved,
    /// The admitted protected checkpoint was not a valid authoritative envelope.
    AdmissionInvalidProtectedCheckpoint,
    /// Admission could not reserve its deterministic aggregate storage peak.
    AdmissionAggregateCapacityFull,
    /// Admission could not reserve one of the bounded live-roster slots.
    AdmissionLiveCapacityFull,
    /// Admission could not reserve its eventual retained terminal slot.
    AdmissionHistoryCapacityFull,
    /// The operation is only legal after an ambiguity recovery step.
    RecoveryRequired,
    /// The exact terminal body conflicts with the durable terminal body.
    TerminalConflict,
    /// The operation cannot proceed from the current opaque capability state.
    InvalidState,
    /// The startup-owned executor or durable adapter is temporarily unavailable.
    Unavailable,
}

impl fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput => "invalid protected roster input",
            Self::AuthorityRejected => "protected roster authority rejected",
            Self::AdmissionRecordMissing => "protected roster admission record missing",
            Self::AdmissionRecordAlreadyExists => {
                "protected roster admission record already exists"
            }
            Self::AdmissionGenerationConflict => "protected roster admission generation conflict",
            Self::AdmissionGenerationExhausted => "protected roster admission generation exhausted",
            Self::AdmissionBusinessKeyReserved => {
                "protected roster admission business key reserved"
            }
            Self::AdmissionInvalidProtectedCheckpoint => {
                "protected roster admission checkpoint rejected"
            }
            Self::AdmissionAggregateCapacityFull => {
                "protected roster admission aggregate capacity full"
            }
            Self::AdmissionLiveCapacityFull => "protected roster admission live capacity full",
            Self::AdmissionHistoryCapacityFull => {
                "protected roster admission history capacity full"
            }
            Self::RecoveryRequired => "protected roster recovery required",
            Self::TerminalConflict => "protected roster terminal conflict",
            Self::InvalidState => "invalid protected roster state",
            Self::Unavailable => "protected roster unavailable",
        })
    }
}

impl std::error::Error for ClientError {}

impl From<RosterError> for ClientError {
    fn from(_: RosterError) -> Self {
        Self::InvalidInput
    }
}

impl From<ExecutorError> for ClientError {
    fn from(error: ExecutorError) -> Self {
        match error {
            ExecutorError::AuthorityRejected => Self::AuthorityRejected,
            ExecutorError::RecoveryRequired => Self::RecoveryRequired,
            ExecutorError::TerminalConflict => Self::TerminalConflict,
            ExecutorError::ExecutorUnavailable
            | ExecutorError::ExecutorBusy
            | ExecutorError::AttestationUnavailable
            | ExecutorError::BackendUnavailable => Self::Unavailable,
            ExecutorError::AdmissionRecordMissing => Self::AdmissionRecordMissing,
            ExecutorError::AdmissionRecordAlreadyExists => Self::AdmissionRecordAlreadyExists,
            ExecutorError::AdmissionGenerationConflict => Self::AdmissionGenerationConflict,
            ExecutorError::AdmissionGenerationExhausted => Self::AdmissionGenerationExhausted,
            ExecutorError::AdmissionBusinessKeyReserved => Self::AdmissionBusinessKeyReserved,
            ExecutorError::AdmissionInvalidProtectedCheckpoint => {
                Self::AdmissionInvalidProtectedCheckpoint
            }
            ExecutorError::AdmissionAggregateBytesFull => Self::AdmissionAggregateCapacityFull,
            ExecutorError::AdmissionLiveFull => Self::AdmissionLiveCapacityFull,
            ExecutorError::AdmissionHistoryFull => Self::AdmissionHistoryCapacityFull,
            ExecutorError::InvalidRegistration
            | ExecutorError::InvalidMember
            | ExecutorError::InvalidProviderResponse
            | ExecutorError::InvalidTerminal => Self::InvalidInput,
            ExecutorError::TerminalLocked
            | ExecutorError::OutcomeUnknown
            | ExecutorError::AdmissionNotTransmitted
            | ExecutorError::AdmissionOutcomeUnknown
            | ExecutorError::TerminalizeOutcomeUnknown
            | ExecutorError::TerminalizeNotTransmitted
            | ExecutorError::TerminalPayloadCompacted => Self::InvalidState,
        }
    }
}

/// A bounded member ordinal accepted by generic provider operations.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct MemberOrdinal(u8);

impl MemberOrdinal {
    /// Construct an ordinal in the frozen protected-roster range.
    pub fn new(ordinal: u8) -> Result<Self, ClientError> {
        if usize::from(ordinal) < MAX_MEMBERS {
            Ok(Self(ordinal))
        } else {
            Err(ClientError::InvalidInput)
        }
    }

    /// Return the profile-bounded ordinal.
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl fmt::Debug for MemberOrdinal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MemberOrdinal(<redacted>)")
    }
}

impl<'de> Deserialize<'de> for MemberOrdinal {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(u8::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Immutable fresh-admission input paired with SDK-authenticated lease data.
///
/// Scope is intentionally absent.  The client receives its scope from the
/// startup-owned `SessionBackend` composition, rather than accepting a raw
/// caller-controlled scope commitment.
///
/// This handle is deliberately not serializable or cloneable. Once an admit
/// call may have transmitted, its process-local state is permanently
/// recovery-only; deserialization must never recreate execute authority.
pub struct AdmissionInput {
    lease: LeaseGuard,
    expected_generation: Generation,
    proposal: AdmissionProposal,
    state: AdmissionInputState,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum AdmissionInputState {
    #[default]
    Fresh,
    /// The exact retained admission was directly proven not transmitted.
    RetryReady,
    RecoveryOnly,
}

impl AdmissionInputState {
    fn begin_attempt(&mut self) -> Result<bool, ClientError> {
        let is_resubmit = match self {
            Self::Fresh => false,
            Self::RetryReady => true,
            Self::RecoveryOnly => return Err(ClientError::RecoveryRequired),
        };
        *self = Self::RecoveryOnly;
        Ok(is_resubmit)
    }

    fn restore_after_not_transmitted(&mut self) {
        *self = Self::RetryReady;
    }
}

impl AdmissionInput {
    /// Construct one generic bounded admission request.
    pub fn new(
        lease: LeaseGuard,
        expected_generation: Generation,
        proposal: AdmissionProposal,
    ) -> Result<Self, ClientError> {
        if proposal.profile() != Profile::v1()
            || !proposal
                .established_mutation()
                .requires_present_predecessor()
        {
            return Err(ClientError::InvalidInput);
        }
        Self::new_for_profile(lease, expected_generation, proposal)
    }

    /// Construct an absent-predecessor admission with the SDK-fixed initial
    /// generation. Callers cannot select a different creation generation.
    fn new_absent(lease: LeaseGuard, proposal: AdmissionProposal) -> Result<Self, ClientError> {
        if proposal.profile() != Profile::v2()
            || !proposal
                .established_mutation()
                .requires_absent_predecessor()
        {
            return Err(ClientError::InvalidInput);
        }
        Self::new_for_profile(lease, INITIAL_GENERATION, proposal)
    }

    fn new_for_profile(
        lease: LeaseGuard,
        expected_generation: Generation,
        proposal: AdmissionProposal,
    ) -> Result<Self, ClientError> {
        if !lease_has_valid_profile(&lease) {
            return Err(ClientError::InvalidInput);
        }
        Ok(Self {
            lease,
            expected_generation,
            proposal,
            state: AdmissionInputState::Fresh,
        })
    }

    /// Return the stable roster identity retained across every phase.
    pub const fn roster_id(&self) -> RosterId {
        self.proposal.roster_id()
    }

    /// Return the immutable public proposal.
    pub const fn proposal(&self) -> &AdmissionProposal {
        &self.proposal
    }

    /// Build a read-only recovery request for this same stable identity.
    ///
    /// This remains available when an admission future is cancelled after it
    /// may have transmitted; the input itself cannot be admitted again until a
    /// conclusive `NotTransmitted` restores its ready state.
    pub fn recovery(
        &self,
        lease: LeaseGuard,
        expected_generation: Generation,
    ) -> Result<RecoveryInput, ClientError> {
        if self.proposal.profile() != Profile::v1() {
            return Err(ClientError::InvalidInput);
        }
        RecoveryInput::new(
            self.roster_id(),
            self.lease.owner().clone(),
            self.lease.fence(),
            lease,
            expected_generation,
        )
    }

    /// Build read-only successor recovery for an absent-predecessor admission.
    pub fn recovery_absent(&self, lease: LeaseGuard) -> Result<AbsentRecoveryInput, ClientError> {
        if self.proposal.profile() != Profile::v2() {
            return Err(ClientError::InvalidInput);
        }
        AbsentRecoveryInput::new(
            self.roster_id(),
            self.lease.owner().clone(),
            self.lease.fence(),
            lease,
        )
    }

    fn registration_request(&self, scope: Scope) -> Result<RegistrationRequest, ClientError> {
        let admission = Admission::authenticate(
            self.proposal.clone(),
            self.lease.key().clone(),
            scope,
            self.lease.owner().clone(),
            self.lease.fence(),
            self.expected_generation,
        )?;
        RegistrationRequest::new_with_lease_metadata(
            admission,
            self.lease.owner().clone(),
            self.lease.fence(),
            self.lease.credential_id(),
            self.expected_generation,
            self.lease.acquired_at(),
            self.lease.expires_at(),
        )
        .map_err(Into::into)
    }
}

impl fmt::Debug for AdmissionInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdmissionInput(<redacted>)")
    }
}

/// Read-only cross-node recovery input for one stable roster identity.
///
/// The current guard is authenticated by the durable backend.  The immutable
/// admission body is deliberately not accepted here: recovery reads its exact
/// retained canonical form only after qualifying the client-fixed scope,
/// roster ID, original owner, and original admission fence.
#[derive(Serialize)]
pub struct RecoveryInput {
    #[serde(skip_serializing)]
    profile: Profile,
    roster_id: RosterId,
    // These values are immutable provenance from the original admission. They
    // are deliberately distinct from the replaceable current lease below.
    original_owner: OwnerId,
    original_admission_fence: FenceToken,
    lease: LeaseGuard,
    expected_generation: Generation,
}

impl RecoveryInput {
    /// Construct a recovery request under a current, higher lease guard.
    pub fn new(
        roster_id: RosterId,
        original_owner: OwnerId,
        original_admission_fence: FenceToken,
        lease: LeaseGuard,
        expected_generation: Generation,
    ) -> Result<Self, ClientError> {
        validate_recovery_authority(original_admission_fence, &lease)?;
        Ok(Self {
            profile: Profile::v1(),
            roster_id,
            original_owner,
            original_admission_fence,
            lease,
            expected_generation,
        })
    }

    /// Return the stable roster identity used by recovery.
    pub const fn roster_id(&self) -> RosterId {
        self.roster_id
    }

    fn request(&self, scope: Scope) -> Result<RecoveryRequest, ClientError> {
        RecoveryRequest::new_with_lease_metadata(
            RecoveryLookup::new(scope, self.roster_id),
            self.original_owner.clone(),
            self.original_admission_fence,
            RecoveryLeaseAuthority::new(
                self.lease.key().clone(),
                self.lease.owner().clone(),
                self.lease.fence(),
                self.lease.credential_id(),
                self.expected_generation,
                LeaseMetadata::new(self.lease.acquired_at(), self.lease.expires_at()),
            ),
        )
        .map_err(Into::into)
    }
}

impl fmt::Debug for RecoveryInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveryInput(<redacted>)")
    }
}

fn lease_has_valid_profile(lease: &LeaseGuard) -> bool {
    lease.fence().get() != 0
        && lease.credential_id() != 0
        && lease.expires_at() >= lease.acquired_at()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryInputWire {
    roster_id: RosterId,
    original_owner: OwnerId,
    original_admission_fence: FenceToken,
    lease: LeaseGuard,
    expected_generation: Generation,
}

impl<'de> Deserialize<'de> for RecoveryInput {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = RecoveryInputWire::deserialize(deserializer)?;
        Self::new(
            wire.roster_id,
            wire.original_owner,
            wire.original_admission_fence,
            wire.lease,
            wire.expected_generation,
        )
        .map_err(serde::de::Error::custom)
    }
}

/// Read-only cross-node recovery input for an absent-predecessor roster.
///
/// This profile-specific capability has a disjoint serialized form that
/// carries the exact V2 profile and fixes recovery at generation one. It can
/// neither be decoded as the frozen V1 [`RecoveryInput`] nor supplied to the
/// V1 recovery method.
#[derive(Serialize)]
pub struct AbsentRecoveryInput {
    profile: Profile,
    roster_id: RosterId,
    original_owner: OwnerId,
    original_admission_fence: FenceToken,
    lease: LeaseGuard,
}

impl AbsentRecoveryInput {
    /// Construct recovery for an absent-predecessor admission under a current,
    /// higher lease guard.
    pub fn new(
        roster_id: RosterId,
        original_owner: OwnerId,
        original_admission_fence: FenceToken,
        lease: LeaseGuard,
    ) -> Result<Self, ClientError> {
        validate_recovery_authority(original_admission_fence, &lease)?;
        Ok(Self {
            profile: Profile::v2(),
            roster_id,
            original_owner,
            original_admission_fence,
            lease,
        })
    }

    /// Return the stable roster identity used by recovery.
    pub const fn roster_id(&self) -> RosterId {
        self.roster_id
    }

    fn request(&self, scope: Scope) -> Result<RecoveryRequest, ClientError> {
        RecoveryRequest::new_with_lease_metadata(
            RecoveryLookup::new(scope, self.roster_id),
            self.original_owner.clone(),
            self.original_admission_fence,
            RecoveryLeaseAuthority::new(
                self.lease.key().clone(),
                self.lease.owner().clone(),
                self.lease.fence(),
                self.lease.credential_id(),
                INITIAL_GENERATION,
                LeaseMetadata::new(self.lease.acquired_at(), self.lease.expires_at()),
            ),
        )
        .map_err(Into::into)
    }
}

impl fmt::Debug for AbsentRecoveryInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AbsentRecoveryInput(<redacted>)")
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AbsentRecoveryInputWire {
    profile: Profile,
    roster_id: RosterId,
    original_owner: OwnerId,
    original_admission_fence: FenceToken,
    lease: LeaseGuard,
}

impl<'de> Deserialize<'de> for AbsentRecoveryInput {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = AbsentRecoveryInputWire::deserialize(deserializer)?;
        if wire.profile != Profile::v2() {
            return Err(serde::de::Error::custom(ClientError::InvalidInput));
        }
        Self::new(
            wire.roster_id,
            wire.original_owner,
            wire.original_admission_fence,
            wire.lease,
        )
        .map_err(serde::de::Error::custom)
    }
}

fn validate_recovery_authority(
    original_admission_fence: FenceToken,
    lease: &LeaseGuard,
) -> Result<(), ClientError> {
    if !lease_has_valid_profile(lease) || original_admission_fence.get() == 0 {
        return Err(ClientError::InvalidInput);
    }
    if lease.fence() <= original_admission_fence {
        return Err(ClientError::AuthorityRejected);
    }
    Ok(())
}

/// Outcome of the single admission mutation.
pub enum AdmissionOutcome {
    /// The immutable admission is durable and may execute its members.
    Admitted(ActiveRoster),
    /// No admission byte crossed transport; retry only the same borrowed input.
    NotTransmitted,
    /// Admission may have committed; recover later using this stable roster ID.
    OutcomeUnknown(AdmissionUnknown),
}

impl fmt::Debug for AdmissionOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdmissionOutcome(<redacted>)")
    }
}

/// Admission ambiguity represented by its stable identity and sealed original
/// admission provenance; it never retains protected admission payload bytes.
pub struct AdmissionUnknown {
    profile: Profile,
    roster_id: RosterId,
    original_owner: OwnerId,
    original_admission_fence: FenceToken,
}

impl AdmissionUnknown {
    /// Return the stable roster identity required for later recovery.
    pub const fn roster_id(&self) -> RosterId {
        self.roster_id
    }

    /// Pair this identity with the then-current lease guard for recovery.
    pub fn recover(
        self,
        lease: LeaseGuard,
        expected_generation: Generation,
    ) -> Result<RecoveryInput, ClientError> {
        if self.profile != Profile::v1() {
            return Err(ClientError::InvalidInput);
        }
        RecoveryInput::new(
            self.roster_id,
            self.original_owner,
            self.original_admission_fence,
            lease,
            expected_generation,
        )
    }

    /// Recover an ambiguous absent-predecessor admission without permitting
    /// the caller to choose a creation generation.
    pub fn recover_absent(self, lease: LeaseGuard) -> Result<AbsentRecoveryInput, ClientError> {
        if self.profile != Profile::v2() {
            return Err(ClientError::InvalidInput);
        }
        AbsentRecoveryInput::new(
            self.roster_id,
            self.original_owner,
            self.original_admission_fence,
            lease,
        )
    }
}

impl fmt::Debug for AdmissionUnknown {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdmissionUnknown(<redacted>)")
    }
}

/// Opaque active roster capability issued only after fresh durable admission.
pub struct ActiveRoster {
    registration: Arc<Registration>,
    roster_id: RosterId,
    issued_members: u8,
}

impl ActiveRoster {
    fn from_registration(registration: Registration) -> Self {
        let roster_id = registration.admission().roster_id();
        Self {
            registration: Arc::new(registration),
            roster_id,
            issued_members: 0,
        }
    }

    /// Return the stable identity shared by admission, recovery, and terminalization.
    pub const fn roster_id(&self) -> RosterId {
        self.roster_id
    }

    /// Return the exact ordered stable IDs and opaque descriptors admitted by consensus.
    pub fn members(&self) -> &[Member] {
        self.registration.admission().members()
    }

    /// Return the exact protected plan retained by the immutable admission.
    pub fn protected_plan(&self) -> &[u8] {
        self.registration.admission().protected_plan()
    }

    /// Return a member in the initial provider-prepare state.
    ///
    /// A recovered roster must use [`RecoveredRoster::member`] instead; it
    /// regains a prepare or execute stage only from a provider's strong durable
    /// status observation.
    pub fn member(&mut self, ordinal: MemberOrdinal) -> Result<ReadyMember, ClientError> {
        validate_member_ordinal(ordinal, self.registration.admission().members().len())?;
        mark_member_issued(&mut self.issued_members, ordinal)?;
        Ok(ReadyMember {
            registration: Arc::clone(&self.registration),
            roster_id: self.roster_id,
            ordinal,
            state: ReadyMemberState::PrepareReady,
        })
    }

    /// Borrow this active roster for terminal preparation or resumption.
    pub const fn for_terminal(&self) -> TerminalRoster<'_> {
        TerminalRoster::Active(self)
    }
}

impl fmt::Debug for ActiveRoster {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ActiveRoster(<redacted>)")
    }
}

/// Opaque recovered roster whose members are limited to recovery operations.
pub struct RecoveredRoster {
    registration: Arc<Registration>,
    roster_id: RosterId,
    issued_members: u8,
}

impl RecoveredRoster {
    fn from_registration(registration: Registration) -> Self {
        let roster_id = registration.admission().roster_id();
        Self {
            registration: Arc::new(registration),
            roster_id,
            issued_members: 0,
        }
    }

    /// Return the stable roster identity.
    pub const fn roster_id(&self) -> RosterId {
        self.roster_id
    }

    /// Return the consensus-recovered ordered stable IDs and opaque descriptors.
    pub fn members(&self) -> &[Member] {
        self.registration.admission().members()
    }

    /// Return the byte-exact protected plan recovered from consensus.
    pub fn protected_plan(&self) -> &[u8] {
        self.registration.admission().protected_plan()
    }

    /// Return a member restricted to status and adoption recovery.
    pub fn member(&mut self, ordinal: MemberOrdinal) -> Result<RecoverableMember, ClientError> {
        validate_member_ordinal(ordinal, self.registration.admission().members().len())?;
        mark_member_issued(&mut self.issued_members, ordinal)?;
        Ok(RecoverableMember {
            registration: Arc::clone(&self.registration),
            roster_id: self.roster_id,
            ordinal,
            state: RecoverableMemberState::RecoveryOnly,
        })
    }

    /// Borrow this recovered roster for terminal preparation or resumption.
    pub const fn for_terminal(&self) -> TerminalRoster<'_> {
        TerminalRoster::Recovered(self)
    }
}

impl fmt::Debug for RecoveredRoster {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveredRoster(<redacted>)")
    }
}

fn validate_member_ordinal(ordinal: MemberOrdinal, member_count: usize) -> Result<(), ClientError> {
    if usize::from(ordinal.get()) < member_count {
        Ok(())
    } else {
        Err(ClientError::InvalidInput)
    }
}

fn mark_member_issued(issued_members: &mut u8, ordinal: MemberOrdinal) -> Result<(), ClientError> {
    let member_bit = 1_u8
        .checked_shl(u32::from(ordinal.get()))
        .ok_or(ClientError::InvalidInput)?;
    if *issued_members & member_bit != 0 {
        return Err(ClientError::InvalidState);
    }
    *issued_members |= member_bit;
    Ok(())
}

/// Borrowed active or recovered roster capability accepted by terminal operations.
pub enum TerminalRoster<'a> {
    /// A roster originally admitted by this process.
    Active(&'a ActiveRoster),
    /// A roster recovered under a current higher-fence guard.
    Recovered(&'a RecoveredRoster),
}

impl TerminalRoster<'_> {
    fn registration(&self) -> &Arc<Registration> {
        match self {
            Self::Active(roster) => &roster.registration,
            Self::Recovered(roster) => &roster.registration,
        }
    }
}

impl fmt::Debug for TerminalRoster<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TerminalRoster(<redacted>)")
    }
}

/// A member carrying exactly one provider-local prepare or execute stage.
pub struct ReadyMember {
    registration: Arc<Registration>,
    roster_id: RosterId,
    ordinal: MemberOrdinal,
    state: ReadyMemberState,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReadyMemberState {
    PrepareReady,
    ExecuteReady,
    RecoveryOnly,
}

impl ReadyMember {
    /// Return the stable identity of the roster containing this member.
    pub const fn roster_id(&self) -> RosterId {
        self.roster_id
    }

    /// Return the exact member ordinal.
    pub const fn ordinal(&self) -> MemberOrdinal {
        self.ordinal
    }

    /// Convert a member whose direct call became ambiguous into recovery-only
    /// authority.
    ///
    /// `execute` makes this conversion mandatory before its first await and
    /// restores readiness only after a conclusive `NotTransmitted`. Therefore
    /// cancellation and provider errors cannot accidentally enable replay.
    pub fn into_recoverable(self) -> Result<RecoverableMember, ClientError> {
        if self.state != ReadyMemberState::RecoveryOnly {
            return Err(ClientError::RecoveryRequired);
        }
        Ok(RecoverableMember {
            registration: self.registration,
            roster_id: self.roster_id,
            ordinal: self.ordinal,
            state: RecoverableMemberState::RecoveryOnly,
        })
    }
}

impl fmt::Debug for ReadyMember {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReadyMember(<redacted>)")
    }
}

/// A member whose possible prior effect restricts it to recovery operations.
pub struct RecoverableMember {
    registration: Arc<Registration>,
    roster_id: RosterId,
    ordinal: MemberOrdinal,
    state: RecoverableMemberState,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RecoverableMemberState {
    /// This capability exists only after a direct ambiguity or successor
    /// recovery. Both status and adopt retain recovery-only authority.
    RecoveryOnly,
}

impl RecoverableMember {
    /// Return the stable identity of the roster containing this member.
    pub const fn roster_id(&self) -> RosterId {
        self.roster_id
    }

    /// Return the exact member ordinal.
    pub const fn ordinal(&self) -> MemberOrdinal {
        self.ordinal
    }
}

impl fmt::Debug for RecoverableMember {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoverableMember(<redacted>)")
    }
}

/// Bounded, redaction-safe classification of an unresolved member call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberRecoveryStatus {
    /// The provider call may have crossed its effect boundary.
    OutcomeUnknown,
    /// Provider absence does not exclude a prior effect.
    NotFound,
    /// The provider state is not yet conclusive.
    Pending,
}

/// Result of executing one exact member.
pub enum ExecuteOutcome {
    /// The SDK issued a conclusive, nonconstructible proof.
    Conclusive(Box<MemberProof>),
    /// No execute byte crossed transport; retry the same retained ready member.
    NotTransmitted,
    /// The retained member is now recovery-only.
    Ambiguous(MemberRecoveryStatus),
}

/// Result of durably preparing one exact provider-local member request.
///
/// This is the public prepare row of the fixed provider matrix: a preparation
/// is either retained pre-effect, proven not transmitted, or recovery-only.
/// It never returns a terminal proof; a prior effect must be re-observed by
/// [`FencedMutationRosterClient::status`] or
/// [`FencedMutationRosterClient::adopt`].
pub enum MemberPrepareOutcome {
    /// The provider retained the exact request and proved execution has not run.
    Prepared,
    /// No prepare byte crossed transport; retry the same retained prepare stage.
    NotTransmitted,
    /// The retained member is now recovery-only.
    Ambiguous(MemberRecoveryStatus),
}

impl fmt::Debug for MemberPrepareOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MemberPrepareOutcome(<redacted>)")
    }
}

impl fmt::Debug for ExecuteOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExecuteOutcome(<redacted>)")
    }
}

/// Result of a status, adoption, reconciliation, or compensation operation.
///
/// The `Conclusive` variant is an SDK-issued proof only. Status or adoption
/// can yield applied, reconciled non-applied, or final compensated evidence;
/// reconciliation can yield reconciled non-applied or compensated evidence;
/// direct compensation can yield final compensated evidence only. `NotFound`
/// remains `Ambiguous` and never authorizes an execution retry or Aborted
/// terminal on its own.
pub enum MemberRecoveryOutcome {
    /// The SDK issued a conclusive, nonconstructible proof.
    Conclusive(Box<MemberProof>),
    /// No provider byte crossed transport; the same retained call may retry.
    NotTransmitted,
    /// Status observed an exclusionary pre-prepare state.
    ///
    /// This remains recovery-only: an earlier ambiguous provider call cannot
    /// regain prepare or execute authority from a read response.
    ReadyToPrepare,
    /// Status observed the exact request prepared but not run.
    ///
    /// This remains recovery-only: a retransmission is authorized only by the
    /// exact `NotTransmitted` result of the same prepare or execute call.
    PreparedNotRun,
    /// The retained member remains recovery-only and can never execute.
    Ambiguous(MemberRecoveryStatus),
}

impl fmt::Debug for MemberRecoveryOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MemberRecoveryOutcome(<redacted>)")
    }
}

/// Move-only SDK-issued proof for one conclusive member terminal state.
///
/// Callers can retain and move a proof returned by this client, but cannot
/// construct one from product-authored disposition/adoption values:
///
/// ```compile_fail
/// use opc_session_net::FencedMutationRosterMemberProof;
///
/// let _forged = FencedMutationRosterMemberProof(());
/// ```
pub struct MemberProof(AppliedProof);

impl fmt::Debug for MemberProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MemberProof(<redacted>)")
    }
}

/// Complete ordered proof set accepted by terminal preparation.
pub struct CompleteProofSet(Vec<MemberProof>);

impl CompleteProofSet {
    /// Collect a nonempty bounded proof set without exposing its contents.
    /// Exact ordinal coverage is checked against the admitted roster during
    /// terminal preparation.
    pub fn new(proofs: Vec<MemberProof>) -> Result<Self, ClientError> {
        if !proofs.is_empty() && proofs.len() <= MAX_MEMBERS {
            Ok(Self(proofs))
        } else {
            Err(ClientError::InvalidState)
        }
    }

    /// Return the number of move-only proofs in this set.
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Report whether this proof set is empty.
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn raw_cloned(&self) -> Vec<AppliedProof> {
        self.0.iter().map(|proof| proof.0.clone()).collect()
    }
}

impl fmt::Debug for CompleteProofSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CompleteProofSet(<redacted>)")
    }
}

/// Opaque, exact terminal body prepared from SDK-issued proofs.
pub struct PreparedRosterTerminal {
    registration: Arc<Registration>,
    roster_id: RosterId,
    prepared: PreparedTerminal,
    state: PreparedTerminalState,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PreparedTerminalState {
    Fresh,
    /// The exact retained terminal body was directly proven not transmitted.
    RetryReady,
    StatusOnly,
}

impl PreparedTerminalState {
    fn begin_attempt(&mut self) -> Result<bool, ClientError> {
        let is_resubmit = match self {
            Self::Fresh => false,
            Self::RetryReady => true,
            Self::StatusOnly => return Err(ClientError::RecoveryRequired),
        };
        *self = Self::StatusOnly;
        Ok(is_resubmit)
    }

    fn restore_after_not_transmitted(&mut self) {
        *self = Self::RetryReady;
    }
}

impl PreparedRosterTerminal {
    fn new(
        registration: Arc<Registration>,
        roster_id: RosterId,
        prepared: PreparedTerminal,
    ) -> Self {
        Self {
            registration,
            roster_id,
            prepared,
            state: PreparedTerminalState::Fresh,
        }
    }

    /// Return the stable roster identity bound to this terminal body.
    pub const fn roster_id(&self) -> RosterId {
        self.roster_id
    }
}

impl fmt::Debug for PreparedRosterTerminal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedRosterTerminal(<redacted>)")
    }
}

/// Result of terminalization for one exact prepared body.
pub enum TerminalizationOutcome {
    /// The terminal committed and exposes its phase-specific retained receipt.
    Committed(TerminalReceipt),
    /// No terminalization byte crossed transport; retry the retained exact body.
    NotTransmitted,
    /// Terminalization may have committed; status only the retained exact body.
    OutcomeUnknown,
}

impl fmt::Debug for TerminalizationOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TerminalizationOutcome(<redacted>)")
    }
}

/// Durable exact terminal receipt separated by irreversible phase.
pub enum TerminalReceipt {
    /// Established terminal with the only publication authority.
    Established(EstablishedTerminal),
    /// Aborted terminal retaining bytes but never publication authority.
    Aborted(AbortedTerminal),
}

impl fmt::Debug for TerminalReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TerminalReceipt(<redacted>)")
    }
}

/// Exact protected bytes and the sole move-only publication authority.
///
/// This capsule is deliberately not cloneable and never separates an
/// authority token from its protected bytes. Public consumers may inspect and
/// consume the exact terminal only into the opaque capsule accepted by a
/// startup-fixed publication adapter through [`Self::into_publication`].
///
/// ```compile_fail
/// use opc_session_net::FencedMutationRosterEstablishedTerminal;
/// let forged = FencedMutationRosterEstablishedTerminal {};
/// ```
pub struct EstablishedTerminal {
    receipt: Box<TerminalCommitReceipt>,
}

impl EstablishedTerminal {
    /// Return the byte-exact protected checkpoint bound to this publication capsule.
    pub fn protected_checkpoint(&self) -> &[u8] {
        self.receipt.protected_checkpoint()
    }

    /// Return the byte-exact protected result bound to this publication capsule.
    pub fn protected_result(&self) -> &[u8] {
        self.receipt.protected_result()
    }

    /// Consume this terminal into the only publication capsule accepted by a
    /// startup-fixed roster provider adapter.
    ///
    /// The resulting capsule is opaque, non-cloneable, and retains the exact
    /// terminal body and its retry state. It neither exposes nor separates a
    /// publication authority token from the established receipt.
    pub fn into_publication(self) -> EstablishedPublication {
        EstablishedPublication {
            receipt: *self.receipt,
            state: PublicationState::Unclassified,
        }
    }
}

impl fmt::Debug for EstablishedTerminal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EstablishedTerminal(<redacted>)")
    }
}

/// Exact protected recovery evidence for an aborted terminal.
///
/// These bytes remain durable and byte-identical across status, restart, and
/// successor recovery.  Unlike [`EstablishedTerminal`], this type has no
/// publication conversion: an aborted terminal can prove recovery state but
/// can never authorize a local or on-wire publication.
///
/// ```compile_fail
/// use opc_session_net::FencedMutationRosterAbortedTerminal;
/// fn publish(aborted: FencedMutationRosterAbortedTerminal) {
///     let _ = aborted.into_publication();
/// }
/// ```
pub struct AbortedTerminal {
    receipt: Box<TerminalCommitReceipt>,
}

impl AbortedTerminal {
    /// Return the byte-exact protected checkpoint retained for recovery.
    pub fn protected_checkpoint(&self) -> &[u8] {
        self.receipt.protected_checkpoint()
    }

    /// Return the byte-exact protected result retained for recovery.
    pub fn protected_result(&self) -> &[u8] {
        self.receipt.protected_result()
    }
}

impl fmt::Debug for AbortedTerminal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AbortedTerminal(<redacted>)")
    }
}

/// Opaque publication capsule obtained only by consuming an SDK-issued
/// [`EstablishedTerminal`].
///
/// A startup-fixed [`super::FencedMutationRosterProviderAdapter`]
/// is the only public consumer. The capsule owns the exact established bytes
/// and tracks whether its inert provider intent is unclassified, retryable
/// after a direct begin non-transmission proof, or status/adopt-only after
/// ambiguity.
pub struct EstablishedPublication {
    receipt: TerminalCommitReceipt,
    state: PublicationState,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PublicationState {
    Unclassified,
    DirectBeginRetry,
    StatusAdoptOnly,
}

impl EstablishedPublication {
    /// Return the exact checkpoint bound to this consumed publication capsule.
    pub(crate) fn protected_checkpoint(&self) -> &[u8] {
        self.receipt.protected_checkpoint()
    }

    /// Return the exact result bound to this consumed publication capsule.
    pub(crate) fn protected_result(&self) -> &[u8] {
        self.receipt.protected_result()
    }

    /// Exact move-only identity and current guard to revalidate around every
    /// provider-local intent or adoption operation.
    pub(crate) fn authority(&self) -> Result<&PublicationAuthority, RosterError> {
        self.receipt
            .publication_authority()
            .ok_or(RosterError::InvalidAuthority)
    }

    pub(crate) const fn state(&self) -> PublicationState {
        self.state
    }

    pub(crate) fn set_state(&mut self, state: PublicationState) {
        self.state = state;
    }
}

impl<'a> EstablishedPublicationCall<'a> {
    /// Construct the provider view only from a consumed, SDK-issued
    /// Established receipt. No public constructor can attach arbitrary bytes
    /// or caller-authored authority to a publication call.
    pub(crate) fn from_established(
        publication: &'a EstablishedPublication,
    ) -> Result<Self, RosterError> {
        Self::from_executor(
            publication.authority()?,
            publication.protected_checkpoint(),
            publication.protected_result(),
        )
    }
}

impl fmt::Debug for EstablishedPublication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EstablishedPublication(<redacted>)")
    }
}

/// Result of an exact read-only terminal status operation.
pub enum TerminalStatus {
    /// The exact prepared body remains admitted at the read barrier.
    Admitted,
    /// The exact body is committed with a phase-specific retained receipt.
    Committed(TerminalReceipt),
    /// Retention compaction removed protected bytes and publication authority.
    Compacted,
}

impl fmt::Debug for TerminalStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TerminalStatus(<redacted>)")
    }
}

/// Read-only recovery outcome for a stable roster ID and current higher guard.
pub enum RecoveryOutcome {
    /// The roster remains admitted; members require recovery-only operations.
    Admitted(RecoveredRoster),
    /// A retained terminal has committed.
    Terminal(TerminalReceipt),
    /// Only nonpublishing compacted status remains.
    Compacted,
}

impl fmt::Debug for RecoveryOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveryOutcome(<redacted>)")
    }
}

#[async_trait]
trait ExecutorClient: Send + Sync {
    async fn register(&self, request: RegistrationRequest) -> Result<Registration, ExecutorError>;
    async fn admission_status(
        &self,
        request: RegistrationRequest,
    ) -> Result<RecoveryResult, ExecutorError>;
    async fn recover(&self, request: RecoveryRequest) -> Result<RecoveryResult, ExecutorError>;
    async fn prepare(
        &self,
        registration: &Registration,
        ordinal: u8,
    ) -> Result<CallResult, ExecutorError>;
    async fn execute(
        &self,
        registration: &Registration,
        ordinal: u8,
    ) -> Result<CallResult, ExecutorError>;
    async fn status(
        &self,
        registration: &Registration,
        ordinal: u8,
    ) -> Result<CallResult, ExecutorError>;
    async fn adopt(
        &self,
        registration: &Registration,
        ordinal: u8,
    ) -> Result<CallResult, ExecutorError>;
    async fn reconcile_member(
        &self,
        registration: &Registration,
        ordinal: u8,
    ) -> Result<CallResult, ExecutorError>;
    async fn compensate_member(
        &self,
        registration: &Registration,
        ordinal: u8,
    ) -> Result<CallResult, ExecutorError>;
    async fn prepare_terminal(
        &self,
        registration: &Registration,
        proofs: Vec<AppliedProof>,
    ) -> Result<PreparedTerminal, ExecutorError>;
    async fn terminalize(
        &self,
        registration: &Registration,
        prepared: &PreparedTerminal,
    ) -> Result<TerminalCommitReceipt, ExecutorError>;
    async fn terminal_status(
        &self,
        registration: &Registration,
        prepared: &PreparedTerminal,
    ) -> Result<TerminalStatusResult, ExecutorError>;
}

struct ExecutorClientAdapter<P, B> {
    executor: RosterExecutor<P, B>,
}

#[async_trait]
impl<P, B> ExecutorClient for ExecutorClientAdapter<P, B>
where
    P: super::canonical::MemberProvider,
    B: RosterExecutorBackend + 'static,
{
    async fn register(&self, request: RegistrationRequest) -> Result<Registration, ExecutorError> {
        self.executor.register(request).await
    }

    async fn admission_status(
        &self,
        request: RegistrationRequest,
    ) -> Result<RecoveryResult, ExecutorError> {
        self.executor.admission_status(request).await
    }

    async fn recover(&self, request: RecoveryRequest) -> Result<RecoveryResult, ExecutorError> {
        self.executor.recover(request).await
    }

    async fn prepare(
        &self,
        registration: &Registration,
        ordinal: u8,
    ) -> Result<CallResult, ExecutorError> {
        self.executor.prepare(registration, ordinal).await
    }

    async fn execute(
        &self,
        registration: &Registration,
        ordinal: u8,
    ) -> Result<CallResult, ExecutorError> {
        self.executor.execute(registration, ordinal).await
    }

    async fn status(
        &self,
        registration: &Registration,
        ordinal: u8,
    ) -> Result<CallResult, ExecutorError> {
        self.executor.status(registration, ordinal).await
    }

    async fn adopt(
        &self,
        registration: &Registration,
        ordinal: u8,
    ) -> Result<CallResult, ExecutorError> {
        self.executor.adopt(registration, ordinal).await
    }

    async fn reconcile_member(
        &self,
        registration: &Registration,
        ordinal: u8,
    ) -> Result<CallResult, ExecutorError> {
        self.executor.reconcile_member(registration, ordinal).await
    }

    async fn compensate_member(
        &self,
        registration: &Registration,
        ordinal: u8,
    ) -> Result<CallResult, ExecutorError> {
        self.executor.compensate_member(registration, ordinal).await
    }

    async fn prepare_terminal(
        &self,
        registration: &Registration,
        proofs: Vec<AppliedProof>,
    ) -> Result<PreparedTerminal, ExecutorError> {
        self.executor.prepare_terminal(registration, proofs).await
    }

    async fn terminalize(
        &self,
        registration: &Registration,
        prepared: &PreparedTerminal,
    ) -> Result<TerminalCommitReceipt, ExecutorError> {
        self.executor.terminalize(registration, prepared).await
    }

    async fn terminal_status(
        &self,
        registration: &Registration,
        prepared: &PreparedTerminal,
    ) -> Result<TerminalStatusResult, ExecutorError> {
        self.executor.terminal_status(registration, prepared).await
    }
}

/// Public client bound to one startup-owned provider, backend, and scope.
#[derive(Clone)]
pub struct FencedMutationRosterClient {
    scope: Scope,
    profile: Profile,
    executor: Arc<dyn ExecutorClient>,
    diagnostics: RosterDiagnostics,
}

impl FencedMutationRosterClient {
    /// Compose the client inside the crate from the startup-owned executor.
    ///
    /// The startup-owned persistent `/3` provider-adapter composition is the
    /// only intended caller. There is no public constructor and no
    /// per-operation provider or backend argument, preventing substitution of
    /// consensus/admin authority.
    pub(crate) fn new<P, B>(executor: RosterExecutor<P, B>, scope: Scope) -> Self
    where
        P: super::canonical::MemberProvider,
        B: RosterExecutorBackend + 'static,
    {
        let diagnostics = executor.diagnostics();
        Self {
            scope,
            profile: Profile::v1(),
            executor: Arc::new(ExecutorClientAdapter { executor }),
            diagnostics,
        }
    }

    /// Compose the additive V2 client from the startup-owned `/4` executor.
    pub(crate) fn new_v2<P, B>(executor: RosterExecutor<P, B>, scope: Scope) -> Self
    where
        P: super::canonical::MemberProvider,
        B: RosterExecutorBackend + 'static,
    {
        let diagnostics = executor.diagnostics();
        Self {
            scope,
            profile: Profile::v2(),
            executor: Arc::new(ExecutorClientAdapter { executor }),
            diagnostics,
        }
    }

    /// Return the capability profile fixed for this client.
    pub fn profile(&self) -> Profile {
        self.profile
    }

    /// Return the shared numeric diagnostics for this startup-owned roster adapter.
    pub fn diagnostics(&self) -> FencedMutationRosterDiagnostics {
        self.diagnostics.snapshot()
    }

    pub(crate) fn diagnostics_handle(&self) -> RosterDiagnostics {
        self.diagnostics.clone()
    }

    /// Prepare and validate one exact fresh roster without crossing a remote
    /// mutation boundary.
    ///
    /// The returned move-only input retains the same lease, stable roster ID,
    /// ordered members, and protected bytes used by [`Self::admit`].
    pub fn prepare(
        &self,
        lease: LeaseGuard,
        expected_generation: Generation,
        proposal: AdmissionProposal,
    ) -> Result<AdmissionInput, ClientError> {
        if self.profile != Profile::v1() || proposal.profile() != self.profile {
            return Err(ClientError::InvalidInput);
        }
        let input = AdmissionInput::new(lease, expected_generation, proposal)?;
        input.registration_request(self.scope)?;
        Ok(input)
    }

    /// Prepare a V2 exact-absence admission at the fixed generation-one
    /// creation point without exposing a caller-selected generation.
    pub fn prepare_absent(
        &self,
        lease: LeaseGuard,
        proposal: AbsentAdmissionProposal,
    ) -> Result<AdmissionInput, ClientError> {
        if self.profile != Profile::v2() {
            return Err(ClientError::InvalidInput);
        }
        let input = AdmissionInput::new_absent(lease, proposal.into_proposal())?;
        input.registration_request(self.scope)?;
        Ok(input)
    }

    /// Perform the one immutable admission mutation.
    /// The input becomes recovery-only before this method awaits. Only a
    /// conclusive `NotTransmitted` permits the identical admission to retry;
    /// cancellation and every ambiguous result require profile-specific
    /// [`Self::recover`] or [`Self::recover_absent`] readback. A retry is
    /// counted only for that direct, transport-proven transition.
    pub async fn admit(&self, input: &mut AdmissionInput) -> Result<AdmissionOutcome, ClientError> {
        if input.proposal.profile() != self.profile {
            return Err(ClientError::InvalidInput);
        }
        let is_resubmit = input.state.begin_attempt()?;
        let request = input.registration_request(self.scope)?;
        record_resubmit(&self.diagnostics, Counter::AdmissionResubmits, is_resubmit);
        match self.executor.register(request).await {
            Ok(registration) => Ok(AdmissionOutcome::Admitted(ActiveRoster::from_registration(
                registration,
            ))),
            Err(ExecutorError::AdmissionNotTransmitted) => {
                input.state.restore_after_not_transmitted();
                Ok(AdmissionOutcome::NotTransmitted)
            }
            Err(ExecutorError::AdmissionOutcomeUnknown) => {
                Ok(AdmissionOutcome::OutcomeUnknown(AdmissionUnknown {
                    profile: input.proposal.profile(),
                    roster_id: input.roster_id(),
                    original_owner: input.lease.owner().clone(),
                    original_admission_fence: input.lease.fence(),
                }))
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Read the exact durable roster under the current higher-fence guard.
    pub async fn recover(&self, input: &RecoveryInput) -> Result<RecoveryOutcome, ClientError> {
        if self.profile != Profile::v1() || input.profile != Profile::v1() {
            return Err(ClientError::InvalidInput);
        }
        match self.executor.recover(input.request(self.scope)?).await? {
            RecoveryResult::PollAdmitted(recovered) => {
                let roster = RecoveredRoster::from_registration(recovered.registration);
                Ok(RecoveryOutcome::Admitted(roster))
            }
            RecoveryResult::Established(receipt) | RecoveryResult::Aborted(receipt) => {
                Ok(RecoveryOutcome::Terminal(receipt_from_executor(receipt)?))
            }
            RecoveryResult::Compacted => Ok(RecoveryOutcome::Compacted),
        }
    }

    /// Read the exact durable absent-predecessor roster under the current
    /// higher-fence guard.
    pub async fn recover_absent(
        &self,
        input: &AbsentRecoveryInput,
    ) -> Result<RecoveryOutcome, ClientError> {
        if self.profile != Profile::v2() || input.profile != Profile::v2() {
            return Err(ClientError::InvalidInput);
        }
        match self.executor.recover(input.request(self.scope)?).await? {
            RecoveryResult::PollAdmitted(recovered) => Ok(RecoveryOutcome::Admitted(
                RecoveredRoster::from_registration(recovered.registration),
            )),
            RecoveryResult::Established(receipt) | RecoveryResult::Aborted(receipt) => {
                Ok(RecoveryOutcome::Terminal(receipt_from_executor(receipt)?))
            }
            RecoveryResult::Compacted => Ok(RecoveryOutcome::Compacted),
        }
    }

    /// Read back the exact original admission after an ambiguous admission
    /// reply, without retransmitting `register`.
    ///
    /// The supplied input retains the canonical original admission plus its
    /// original authority provenance; a successor `RecoveryInput` cannot be
    /// substituted at this ambiguity boundary.
    pub async fn admission_status(
        &self,
        input: &AdmissionInput,
    ) -> Result<RecoveryOutcome, ClientError> {
        if input.proposal.profile() != self.profile {
            return Err(ClientError::InvalidInput);
        }
        if input.state != AdmissionInputState::RecoveryOnly {
            return Err(ClientError::RecoveryRequired);
        }
        match self
            .executor
            .admission_status(input.registration_request(self.scope)?)
            .await?
        {
            RecoveryResult::PollAdmitted(recovered) => Ok(RecoveryOutcome::Admitted(
                RecoveredRoster::from_registration(recovered.registration),
            )),
            RecoveryResult::Established(receipt) | RecoveryResult::Aborted(receipt) => {
                Ok(RecoveryOutcome::Terminal(receipt_from_executor(receipt)?))
            }
            RecoveryResult::Compacted => Ok(RecoveryOutcome::Compacted),
        }
    }

    /// Durably prepare one exact member in the startup-fixed provider journal.
    ///
    /// Preparation stays outside roster consensus. The handle becomes
    /// recovery-only before the first await; only a direct `NotTransmitted`
    /// restores the exact prepare stage, while `Prepared` advances the same
    /// handle to its execute stage.
    pub async fn prepare_member(
        &self,
        member: &mut ReadyMember,
    ) -> Result<MemberPrepareOutcome, ClientError> {
        if member.state != ReadyMemberState::PrepareReady {
            return Err(ClientError::RecoveryRequired);
        }
        member.state = ReadyMemberState::RecoveryOnly;
        let result = self
            .executor
            .prepare(member.registration.as_ref(), member.ordinal.get())
            .await;
        match result {
            Ok(CallResult::PreparedNotRun) => {
                member.state = ReadyMemberState::ExecuteReady;
                Ok(MemberPrepareOutcome::Prepared)
            }
            Ok(CallResult::Conclusive(_)) => Err(ClientError::InvalidState),
            Ok(CallResult::NotTransmitted) => {
                member.state = ReadyMemberState::PrepareReady;
                Ok(MemberPrepareOutcome::NotTransmitted)
            }
            Ok(CallResult::OutcomeUnknown)
            | Err(ExecutorError::OutcomeUnknown | ExecutorError::InvalidProviderResponse) => Ok(
                MemberPrepareOutcome::Ambiguous(MemberRecoveryStatus::OutcomeUnknown),
            ),
            Ok(CallResult::NotFound) => Ok(MemberPrepareOutcome::Ambiguous(
                MemberRecoveryStatus::NotFound,
            )),
            Ok(CallResult::Pending) => Ok(MemberPrepareOutcome::Ambiguous(
                MemberRecoveryStatus::Pending,
            )),
            Ok(CallResult::ReadyToPrepare) => Err(ClientError::InvalidState),
            Err(ExecutorError::ExecutorBusy) => {
                member.state = ReadyMemberState::PrepareReady;
                Err(ClientError::Unavailable)
            }
            Err(ExecutorError::ExecutorUnavailable) => Err(ClientError::Unavailable),
            Err(error) => Err(error.into()),
        }
    }

    /// Execute one exact prepared member through the startup-fixed generic provider.
    /// The member becomes recovery-only before this method first awaits. A
    /// conclusive `NotTransmitted` restores the same execute stage; every
    /// ambiguity, provider error, or cancellation leaves it recovery-only.
    pub async fn execute(&self, member: &mut ReadyMember) -> Result<ExecuteOutcome, ClientError> {
        if member.state != ReadyMemberState::ExecuteReady {
            return Err(ClientError::RecoveryRequired);
        }
        member.state = ReadyMemberState::RecoveryOnly;
        let result = self
            .executor
            .execute(member.registration.as_ref(), member.ordinal.get())
            .await;
        match result {
            Ok(CallResult::NotTransmitted) => {
                member.state = ReadyMemberState::ExecuteReady;
                Ok(ExecuteOutcome::NotTransmitted)
            }
            Ok(result) => execute_outcome(result),
            Err(ExecutorError::OutcomeUnknown | ExecutorError::InvalidProviderResponse) => Ok(
                ExecuteOutcome::Ambiguous(MemberRecoveryStatus::OutcomeUnknown),
            ),
            // `ExecutorBusy` is emitted only before the shared scheduler or
            // per-member gate admits provider I/O, so the exact retained
            // execute remains safe to try later.  A generic unavailable
            // result is not transport evidence and must stay recovery-only.
            Err(ExecutorError::ExecutorBusy) => {
                member.state = ReadyMemberState::ExecuteReady;
                Err(ClientError::Unavailable)
            }
            Err(ExecutorError::ExecutorUnavailable) => Err(ClientError::Unavailable),
            Err(error) => Err(error.into()),
        }
    }

    /// Observe one ambiguous member through the startup-fixed generic provider.
    pub async fn status(
        &self,
        member: &mut RecoverableMember,
    ) -> Result<MemberRecoveryOutcome, ClientError> {
        let result = self
            .executor
            .status(member.registration.as_ref(), member.ordinal.get())
            .await;
        recovery_member_outcome(result)
    }

    /// Adopt one ambiguous member through the startup-fixed generic provider.
    pub async fn adopt(
        &self,
        member: &mut RecoverableMember,
    ) -> Result<MemberRecoveryOutcome, ClientError> {
        begin_recovery_effect(member)?;
        let result = self
            .executor
            .adopt(member.registration.as_ref(), member.ordinal.get())
            .await;
        recovery_member_outcome(result)
    }

    /// Reconcile one ambiguous member under the same stable identity and
    /// current guard without replaying its external effect.
    ///
    /// Only a provider-signed conclusive reconciliation receipt can produce
    /// a terminal proof. `NotFound`, pending, and ambiguous observations stay
    /// non-exclusionary and cannot authorize Aborted.
    pub async fn reconcile(
        &self,
        member: &mut RecoverableMember,
    ) -> Result<MemberRecoveryOutcome, ClientError> {
        let result = self
            .executor
            .reconcile_member(member.registration.as_ref(), member.ordinal.get())
            .await;
        recovery_member_outcome(result)
    }

    /// Compensate an SDK-proven applied member using the same exact retained
    /// identity/body.
    ///
    /// The SDK permits this only after every member has a conclusive provider
    /// observation and at least one member has conclusively locked the roster
    /// into its aborting direction. Otherwise this returns recovery-required
    /// without provider I/O. The member becomes status/adopt-only before any
    /// permitted provider call.
    pub async fn compensate_member(
        &self,
        member: &mut RecoverableMember,
    ) -> Result<MemberRecoveryOutcome, ClientError> {
        begin_recovery_effect(member)?;
        let result = self
            .executor
            .compensate_member(member.registration.as_ref(), member.ordinal.get())
            .await;
        recovery_member_outcome(result)
    }

    /// Bind complete SDK-issued proofs into one exact durable terminal body.
    pub async fn prepare_terminal(
        &self,
        roster: TerminalRoster<'_>,
        proofs: &CompleteProofSet,
    ) -> Result<PreparedRosterTerminal, ClientError> {
        let registration = roster.registration();
        let roster_id = registration.admission().roster_id();
        let prepared = self
            .executor
            .prepare_terminal(registration.as_ref(), proofs.raw_cloned())
            .await
            .map_err(ClientError::from)?;
        Ok(PreparedRosterTerminal::new(
            Arc::clone(registration),
            roster_id,
            prepared,
        ))
    }

    /// Perform the sole atomic terminal mutation for one exact prepared body.
    pub async fn terminalize(
        &self,
        prepared: &mut PreparedRosterTerminal,
    ) -> Result<TerminalizationOutcome, ClientError> {
        let is_resubmit = prepared.state.begin_attempt()?;
        record_resubmit(
            &self.diagnostics,
            Counter::TerminalizeResubmits,
            is_resubmit,
        );
        match self
            .executor
            .terminalize(prepared.registration.as_ref(), &prepared.prepared)
            .await
        {
            Ok(receipt) => Ok(TerminalizationOutcome::Committed(receipt_from_executor(
                receipt,
            )?)),
            Err(ExecutorError::TerminalizeNotTransmitted) => {
                prepared.state.restore_after_not_transmitted();
                Ok(TerminalizationOutcome::NotTransmitted)
            }
            Err(
                ExecutorError::TerminalizeOutcomeUnknown | ExecutorError::TerminalPayloadCompacted,
            ) => Ok(TerminalizationOutcome::OutcomeUnknown),
            Err(error) => Err(error.into()),
        }
    }

    /// Read status of one exact prepared terminal body without a roster mutation.
    pub async fn terminal_status(
        &self,
        prepared: &mut PreparedRosterTerminal,
    ) -> Result<TerminalStatus, ClientError> {
        if prepared.state != PreparedTerminalState::StatusOnly {
            return Err(ClientError::RecoveryRequired);
        }
        match self
            .executor
            .terminal_status(prepared.registration.as_ref(), &prepared.prepared)
            .await?
        {
            // A read barrier cannot prove that the earlier terminal request
            // was not transmitted.  Keep a previously ambiguous handle
            // status-only; only the direct NotTransmitted reply restores
            // `Ready` in `terminalize`.
            TerminalStatusResult::Admitted => Ok(TerminalStatus::Admitted),
            TerminalStatusResult::Recorded(receipt) => {
                Ok(TerminalStatus::Committed(receipt_from_executor(*receipt)?))
            }
            TerminalStatusResult::Compacted => Ok(TerminalStatus::Compacted),
        }
    }
}

impl fmt::Debug for FencedMutationRosterClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FencedMutationRosterClient(<redacted>)")
    }
}

fn record_resubmit(diagnostics: &RosterDiagnostics, counter: Counter, is_resubmit: bool) {
    if is_resubmit {
        diagnostics.increment(counter);
    }
}

fn execute_outcome(result: CallResult) -> Result<ExecuteOutcome, ClientError> {
    match result {
        CallResult::Conclusive(proof) => {
            Ok(ExecuteOutcome::Conclusive(Box::new(MemberProof(*proof))))
        }
        CallResult::NotTransmitted => Err(ClientError::InvalidState),
        CallResult::OutcomeUnknown => Ok(ExecuteOutcome::Ambiguous(
            MemberRecoveryStatus::OutcomeUnknown,
        )),
        CallResult::NotFound => Ok(ExecuteOutcome::Ambiguous(MemberRecoveryStatus::NotFound)),
        CallResult::Pending => Ok(ExecuteOutcome::Ambiguous(MemberRecoveryStatus::Pending)),
        CallResult::ReadyToPrepare | CallResult::PreparedNotRun => Err(ClientError::InvalidState),
    }
}

fn begin_recovery_effect(member: &mut RecoverableMember) -> Result<(), ClientError> {
    if member.state != RecoverableMemberState::RecoveryOnly {
        return Err(ClientError::RecoveryRequired);
    }
    Ok(())
}

fn recovery_member_outcome(
    result: Result<CallResult, ExecutorError>,
) -> Result<MemberRecoveryOutcome, ClientError> {
    match result {
        Ok(CallResult::Conclusive(proof)) => Ok(MemberRecoveryOutcome::Conclusive(Box::new(
            MemberProof(*proof),
        ))),
        Ok(CallResult::NotTransmitted) => Ok(MemberRecoveryOutcome::NotTransmitted),
        Ok(CallResult::ReadyToPrepare) => Ok(MemberRecoveryOutcome::ReadyToPrepare),
        Ok(CallResult::PreparedNotRun) => Ok(MemberRecoveryOutcome::PreparedNotRun),
        Ok(CallResult::OutcomeUnknown)
        | Err(ExecutorError::OutcomeUnknown | ExecutorError::InvalidProviderResponse) => Ok(
            MemberRecoveryOutcome::Ambiguous(MemberRecoveryStatus::OutcomeUnknown),
        ),
        Ok(CallResult::NotFound) => Ok(MemberRecoveryOutcome::Ambiguous(
            MemberRecoveryStatus::NotFound,
        )),
        Ok(CallResult::Pending) => Ok(MemberRecoveryOutcome::Ambiguous(
            MemberRecoveryStatus::Pending,
        )),
        Err(error) => Err(error.into()),
    }
}

fn receipt_from_executor(receipt: TerminalCommitReceipt) -> Result<TerminalReceipt, ClientError> {
    match receipt.phase() {
        Phase::Established if receipt.publication_authority().is_some() => {
            Ok(TerminalReceipt::Established(EstablishedTerminal {
                receipt: Box::new(receipt),
            }))
        }
        Phase::Aborted if receipt.publication_authority().is_none() => {
            Ok(TerminalReceipt::Aborted(AbortedTerminal {
                receipt: Box::new(receipt),
            }))
        }
        Phase::Established | Phase::Aborted => Err(ClientError::InvalidState),
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        canonical::{
            AbsentAdmissionProposal, AdmissionProposal, EstablishedMutation, Member,
            MemberOperationId, Profile, RosterId, Scope,
        },
        diagnostics::RosterDiagnosticsInner,
        runtime::{
            AppliedProof, CallResult, ExecutorError, PreparedTerminal, RecoveryRequest,
            RecoveryResult, Registration, RegistrationRequest, TerminalCommitReceipt,
            TerminalStatusResult,
        },
    };
    use super::{
        record_resubmit, AbsentRecoveryInput, AdmissionInput, AdmissionInputState,
        AdmissionUnknown, ClientError, Counter, ExecutorClient, FencedMutationRosterClient,
        PreparedTerminalState, RecoveryInput,
    };
    use async_trait::async_trait;
    use opc_session_store::{FenceToken, Generation, LeaseGuard, OwnerId};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    struct RejectingExecutor {
        calls: AtomicUsize,
    }

    impl RejectingExecutor {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
            }
        }

        fn unavailable<T>(&self) -> Result<T, ExecutorError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(ExecutorError::BackendUnavailable)
        }
    }

    #[async_trait]
    impl ExecutorClient for RejectingExecutor {
        async fn register(&self, _: RegistrationRequest) -> Result<Registration, ExecutorError> {
            self.unavailable()
        }

        async fn admission_status(
            &self,
            _: RegistrationRequest,
        ) -> Result<RecoveryResult, ExecutorError> {
            self.unavailable()
        }

        async fn recover(&self, _: RecoveryRequest) -> Result<RecoveryResult, ExecutorError> {
            self.unavailable()
        }

        async fn prepare(&self, _: &Registration, _: u8) -> Result<CallResult, ExecutorError> {
            self.unavailable()
        }

        async fn execute(&self, _: &Registration, _: u8) -> Result<CallResult, ExecutorError> {
            self.unavailable()
        }

        async fn status(&self, _: &Registration, _: u8) -> Result<CallResult, ExecutorError> {
            self.unavailable()
        }

        async fn adopt(&self, _: &Registration, _: u8) -> Result<CallResult, ExecutorError> {
            self.unavailable()
        }

        async fn reconcile_member(
            &self,
            _: &Registration,
            _: u8,
        ) -> Result<CallResult, ExecutorError> {
            self.unavailable()
        }

        async fn compensate_member(
            &self,
            _: &Registration,
            _: u8,
        ) -> Result<CallResult, ExecutorError> {
            self.unavailable()
        }

        async fn prepare_terminal(
            &self,
            _: &Registration,
            _: Vec<AppliedProof>,
        ) -> Result<PreparedTerminal, ExecutorError> {
            self.unavailable()
        }

        async fn terminalize(
            &self,
            _: &Registration,
            _: &PreparedTerminal,
        ) -> Result<TerminalCommitReceipt, ExecutorError> {
            self.unavailable()
        }

        async fn terminal_status(
            &self,
            _: &Registration,
            _: &PreparedTerminal,
        ) -> Result<TerminalStatusResult, ExecutorError> {
            self.unavailable()
        }
    }

    fn lease() -> LeaseGuard {
        serde_json::from_value(serde_json::json!({
            "key": {
                "tenant": "test-tenant",
                "nf_kind": "smf",
                "key_type": "pdu-session",
                "stable_id": [1]
            },
            "owner": "test-owner",
            "fence": 2,
            "acquired_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-01-01T00:01:00Z",
            "credential_id": 1
        }))
        .expect("valid public lease guard")
    }

    fn v2_proposal() -> AdmissionProposal {
        let create = EstablishedMutation::create_checkpoint(
            opc_session_store::StateType::from_static("created"),
        );
        assert_eq!(
            postcard::to_allocvec(&create).expect("serialize V2 create mutation")[0],
            4,
            "V2 create mutation uses the frozen tag 4"
        );
        let proposal = AdmissionProposal::new(
            Profile::v2(),
            RosterId::from_bytes([0x41; 16]).expect("nonzero roster ID"),
            vec![Member::new(
                0,
                MemberOperationId::from_bytes([0x42; 16]).expect("nonzero member ID"),
                vec![0x43],
                1,
            )
            .expect("valid member")],
            create,
            vec![0x44],
            vec![0x45],
            vec![0x46],
        )
        .expect("valid V2 creation proposal");
        let bytes = postcard::to_allocvec(&proposal).expect("serialize V2 tag-4 proposal");
        postcard::from_bytes(&bytes).expect("deserialize V2 tag-4 proposal")
    }

    fn client(profile: Profile, executor: Arc<RejectingExecutor>) -> FencedMutationRosterClient {
        FencedMutationRosterClient {
            scope: Scope::from_digest([0x51; 32]),
            profile,
            executor,
            diagnostics: RosterDiagnosticsInner::new(),
        }
    }

    #[tokio::test]
    async fn deserialized_v2_tag_four_cannot_cross_generic_public_boundaries() {
        let proposal = v2_proposal();
        assert!(matches!(
            AdmissionInput::new(lease(), Generation::new(9), proposal.clone()),
            Err(ClientError::InvalidInput)
        ));

        let absent = AbsentAdmissionProposal::new(
            Profile::v2(),
            proposal.roster_id(),
            proposal.members().to_vec(),
            opc_session_store::StateType::from_static("created"),
            proposal.protected_plan().to_vec(),
            proposal.terminal_checkpoint().to_vec(),
            proposal.terminal_result().to_vec(),
        )
        .expect("typed V2 absent proposal");
        let executor = Arc::new(RejectingExecutor::new());
        let v1 = client(Profile::v1(), Arc::clone(&executor));
        let mut admission = AdmissionInput::new_absent(lease(), absent.into_proposal())
            .expect("official V2 admission input");

        assert!(matches!(
            admission.recovery(lease(), Generation::new(9)),
            Err(ClientError::InvalidInput)
        ));

        assert!(matches!(
            v1.admit(&mut admission).await,
            Err(ClientError::InvalidInput)
        ));
        admission.state = AdmissionInputState::RecoveryOnly;
        assert!(matches!(
            v1.admission_status(&admission).await,
            Err(ClientError::InvalidInput)
        ));
        let recovery = AbsentRecoveryInput::new(
            admission.roster_id(),
            lease().owner().clone(),
            FenceToken::new(1),
            lease(),
        )
        .expect("official V2 recovery input");
        assert!(matches!(
            v1.recover_absent(&recovery).await,
            Err(ClientError::InvalidInput)
        ));
        let unknown = AdmissionUnknown {
            profile: Profile::v2(),
            roster_id: admission.roster_id(),
            original_owner: lease().owner().clone(),
            original_admission_fence: FenceToken::new(1),
        };
        assert!(matches!(
            unknown.recover(lease(), Generation::new(9)),
            Err(ClientError::InvalidInput)
        ));
        assert_eq!(executor.calls.load(Ordering::SeqCst), 0);

        let v2 = client(Profile::v2(), Arc::clone(&executor));
        let v1_recovery = RecoveryInput::new(
            admission.roster_id(),
            lease().owner().clone(),
            FenceToken::new(1),
            lease(),
            Generation::new(7),
        )
        .expect("official V1 recovery input");
        assert!(matches!(
            v2.recover(&v1_recovery).await,
            Err(ClientError::InvalidInput)
        ));
        assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
        let absent = AbsentAdmissionProposal::new(
            Profile::v2(),
            proposal.roster_id(),
            proposal.members().to_vec(),
            opc_session_store::StateType::from_static("created"),
            proposal.protected_plan().to_vec(),
            proposal.terminal_checkpoint().to_vec(),
            proposal.terminal_result().to_vec(),
        )
        .expect("typed V2 absent proposal");
        assert!(v2.prepare_absent(lease(), absent).is_ok());
    }

    #[test]
    fn v1_recovery_wire_remains_profile_free_and_byte_stable() {
        #[derive(serde::Serialize)]
        struct V1Wire<'a> {
            roster_id: RosterId,
            original_owner: &'a OwnerId,
            original_admission_fence: FenceToken,
            lease: &'a LeaseGuard,
            expected_generation: Generation,
        }

        let input = RecoveryInput::new(
            RosterId::from_bytes([0x61; 16]).expect("nonzero roster ID"),
            lease().owner().clone(),
            FenceToken::new(1),
            lease(),
            Generation::new(7),
        )
        .expect("V1 recovery input");
        assert_eq!(
            postcard::to_allocvec(&input).expect("serialize V1 recovery input"),
            postcard::to_allocvec(&V1Wire {
                roster_id: input.roster_id,
                original_owner: &input.original_owner,
                original_admission_fence: input.original_admission_fence,
                lease: &input.lease,
                expected_generation: input.expected_generation,
            })
            .expect("serialize frozen V1 recovery wire")
        );
    }

    #[test]
    fn absent_recovery_wire_round_trips_v2_and_rejects_cross_profile_decode() {
        let absent = AbsentRecoveryInput::new(
            RosterId::from_bytes([0x71; 16]).expect("nonzero absent roster ID"),
            lease().owner().clone(),
            FenceToken::new(1),
            lease(),
        )
        .expect("V2 absent recovery input");
        let absent_bytes = postcard::to_allocvec(&absent).expect("serialize V2 recovery input");
        let recovered: AbsentRecoveryInput =
            postcard::from_bytes(&absent_bytes).expect("deserialize V2 recovery input");
        assert_eq!(recovered.profile, Profile::v2());
        assert_eq!(recovered.roster_id(), absent.roster_id());
        assert_eq!(
            postcard::to_allocvec(&recovered).expect("reserialize V2 recovery input"),
            absent_bytes
        );
        assert!(postcard::from_bytes::<RecoveryInput>(&absent_bytes).is_err());

        let v1 = RecoveryInput::new(
            RosterId::from_bytes([0x72; 16]).expect("nonzero V1 roster ID"),
            lease().owner().clone(),
            FenceToken::new(1),
            lease(),
            Generation::new(7),
        )
        .expect("V1 recovery input");
        let v1_bytes = postcard::to_allocvec(&v1).expect("serialize V1 recovery input");
        assert!(postcard::from_bytes::<AbsentRecoveryInput>(&v1_bytes).is_err());

        let absent_json = serde_json::to_value(&absent).expect("serialize V2 recovery JSON");
        let mut absent_with_v1_generation = absent_json.clone();
        absent_with_v1_generation["expected_generation"] = serde_json::json!(7);
        assert!(serde_json::from_value::<RecoveryInput>(absent_with_v1_generation).is_err());
        let mut wrong_profile = absent_json;
        wrong_profile["profile"] =
            serde_json::to_value(Profile::v1()).expect("serialize V1 profile");
        assert!(serde_json::from_value::<AbsentRecoveryInput>(wrong_profile).is_err());
        assert!(serde_json::from_value::<AbsentRecoveryInput>(
            serde_json::to_value(v1).expect("serialize V1 recovery JSON")
        )
        .is_err());
    }

    #[test]
    fn admission_resubmit_state_requires_direct_not_transmitted() {
        let diagnostics = RosterDiagnosticsInner::new();
        let mut state = AdmissionInputState::Fresh;
        record_resubmit(
            &diagnostics,
            Counter::AdmissionResubmits,
            state.begin_attempt().unwrap(),
        );
        assert_eq!(diagnostics.snapshot().admission_resubmits, 0);

        // OutcomeUnknown leaves this state recovery-only, so status-only
        // recovery cannot create a count or retry authority.
        assert_eq!(state.begin_attempt(), Err(ClientError::RecoveryRequired));
        assert_eq!(diagnostics.snapshot().admission_resubmits, 0);

        state.restore_after_not_transmitted();
        record_resubmit(
            &diagnostics,
            Counter::AdmissionResubmits,
            state.begin_attempt().unwrap(),
        );
        assert_eq!(diagnostics.snapshot().admission_resubmits, 1);
        assert_eq!(state.begin_attempt(), Err(ClientError::RecoveryRequired));
    }

    #[test]
    fn terminalize_resubmit_state_requires_direct_not_transmitted() {
        let diagnostics = RosterDiagnosticsInner::new();
        let mut state = PreparedTerminalState::Fresh;
        record_resubmit(
            &diagnostics,
            Counter::TerminalizeResubmits,
            state.begin_attempt().unwrap(),
        );
        assert_eq!(diagnostics.snapshot().terminalize_resubmits, 0);

        // OutcomeUnknown leaves this state status-only, so terminal-status
        // reads cannot create a count or retry authority.
        assert_eq!(state.begin_attempt(), Err(ClientError::RecoveryRequired));
        assert_eq!(diagnostics.snapshot().terminalize_resubmits, 0);

        state.restore_after_not_transmitted();
        record_resubmit(
            &diagnostics,
            Counter::TerminalizeResubmits,
            state.begin_attempt().unwrap(),
        );
        assert_eq!(diagnostics.snapshot().terminalize_resubmits, 1);
        assert_eq!(state.begin_attempt(), Err(ClientError::RecoveryRequired));
    }
}
