//! Namespace-serialized durable grouped XFRM object roster protocol.
//!
//! One IKEv2 Child SA needs several dependency-ordered XFRM objects. This
//! module applies that whole ordered group under ONE durable admission, ONE
//! writer-epoch burn, and ONE crash-recovery verdict, on top of the record
//! store in [`crate::durable_roster`].
//!
//! The protocol is all-or-nothing. Members are applied in the caller-declared
//! order and compensated in strict reverse order, so a partially applied
//! Child SA is never reported as success: RFC 7296 has no wire representation
//! for half an installed Child SA, and RFC 4301 treats the SPD and SAD entries
//! of one protected flow as a single consistent unit.
//!
//! # Named deletion invariant
//!
//! **A member slot in `NoMutation` is never an argument to any delete, at any
//! phase, regardless of proof codes.** Deletion authority for a member
//! additionally requires that member's ADJACENT proof to be `Absent`: the
//! group-wide sweep proof alone never authorizes a deletion, because it is
//! witnessed before the group's epoch burn and therefore cannot order an
//! observation against this roster's own effect window.

// The namespace actor binds this protocol in a later slice. Until then nothing
// outside the module calls the crate-internal flow functions, which fires the
// unused-item lint across an otherwise complete and tested module. Remove this
// once the roster actor wiring lands.
#![allow(dead_code)]

use std::{error::Error, fmt, num::NonZeroU64};

use crate::durable_install::{install, readback_object_present, remove};
use crate::durable_roster::{
    DurableRosterMemberSlot, DurableRosterRecord, XfrmObjectRosterAdjacentProof,
    XfrmObjectRosterDurableError, XfrmObjectRosterDurablePhase, XfrmObjectRosterGroupId,
    XfrmObjectRosterMemberId, XfrmObjectRosterMemberMaterial, XfrmObjectRosterMemberPhase,
    XfrmObjectRosterMemberTransition, XfrmObjectRosterOperationGeneration,
    XfrmObjectRosterRecoveryHandle, XfrmObjectRosterRecoveryStore, XfrmObjectRosterSweepProof,
    XfrmObjectRosterTransition, XFRM_OBJECT_ROSTER_MAX_MEMBERS,
};
use crate::model::validate_exact_lookup_mark;
use crate::{
    IpAddress, XfrmBackend, XfrmDirection, XfrmError, XfrmObjectInstallRequest, XfrmSelector,
};

/// One member of a durable roster, in caller-declared apply order.
///
/// Ordinal zero is applied first and compensated last. The SDK derives the
/// member's durable identity from the group identity, generation, and ordinal
/// unless the consumer supplies its own correlation through
/// [`Self::with_identity`].
#[derive(Clone)]
pub struct XfrmObjectRosterMemberRequest {
    request: XfrmObjectInstallRequest,
    identity: Option<([u8; 16], XfrmObjectRosterOperationGeneration)>,
}

impl XfrmObjectRosterMemberRequest {
    /// Declare one roster member from its complete install request.
    #[must_use]
    pub fn new(request: XfrmObjectInstallRequest) -> Self {
        Self {
            request,
            identity: None,
        }
    }

    /// Override the durable identity the SDK would otherwise derive.
    ///
    /// The identity is bound into the durable record and the roster digest
    /// either way; overriding it only lets a consumer reuse its own
    /// correlation values. The reserved all-zero identity is rejected by
    /// [`XfrmObjectRosterRequest::new`].
    #[must_use]
    pub fn with_identity(
        mut self,
        member_id: [u8; 16],
        generation: XfrmObjectRosterOperationGeneration,
    ) -> Self {
        self.identity = Some((member_id, generation));
        self
    }

    /// Borrow the complete install request this member applies.
    #[must_use]
    pub const fn request(&self) -> &XfrmObjectInstallRequest {
        &self.request
    }
}

impl fmt::Debug for XfrmObjectRosterMemberRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XfrmObjectRosterMemberRequest")
            .field("object", &self.request.object().as_str())
            .finish_non_exhaustive()
    }
}

/// Value-free rejection of an inadmissible roster request.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XfrmObjectRosterRequestError {
    /// The roster declared no members.
    EmptyRoster,
    /// The roster declared more than [`XFRM_OBJECT_ROSTER_MAX_MEMBERS`]
    /// members.
    TooManyMembers,
    /// A member cannot produce an exact unconditional removal identity, so
    /// compensation could remove an object this roster never installed.
    NonExactRemovalIdentity,
    /// Two members share one exact deletion identity, which would make reverse
    /// compensation ambiguous.
    DuplicateDeletionIdentity,
    /// Two members are distinct requests that the kernel's own selection
    /// relation cannot tell apart.
    ///
    /// Linux matches a stored SA's mark mask against the incoming lookup value,
    /// so an unmarked SA is selected for every lookup value sharing its
    /// destination, protocol, and SPI. Two such members would collide in the
    /// kernel even though their keyed fingerprints differ.
    AmbiguousKernelSelection,
    /// A member supplied the reserved all-zero durable identity.
    MalformedMemberIdentity,
}

impl XfrmObjectRosterRequestError {
    /// Stable machine-readable, value-free error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EmptyRoster => "xfrm_object_roster_request_empty",
            Self::TooManyMembers => "xfrm_object_roster_request_too_many_members",
            Self::NonExactRemovalIdentity => {
                "xfrm_object_roster_request_non_exact_removal_identity"
            }
            Self::DuplicateDeletionIdentity => {
                "xfrm_object_roster_request_duplicate_deletion_identity"
            }
            Self::AmbiguousKernelSelection => {
                "xfrm_object_roster_request_ambiguous_kernel_selection"
            }
            Self::MalformedMemberIdentity => "xfrm_object_roster_request_malformed_member_identity",
        }
    }
}

impl fmt::Display for XfrmObjectRosterRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Error for XfrmObjectRosterRequestError {}

/// The coarse identity Linux itself selects on, used to reject members the
/// kernel could not tell apart.
#[derive(Clone, PartialEq, Eq)]
enum KernelSelectionKey {
    Sa {
        destination: IpAddress,
        protocol: u8,
        spi: u32,
    },
    Policy {
        selector: XfrmSelector,
        direction: XfrmDirection,
        if_id: Option<u32>,
    },
}

fn kernel_selection_key(request: &XfrmObjectInstallRequest) -> KernelSelectionKey {
    match request {
        XfrmObjectInstallRequest::Sa(request) => KernelSelectionKey::Sa {
            destination: request.parameters.id.destination,
            protocol: request.parameters.id.protocol,
            spi: request.parameters.id.spi,
        },
        XfrmObjectInstallRequest::Policy(policy) => KernelSelectionKey::Policy {
            selector: policy.parameters.selector.clone(),
            direction: policy.parameters.direction,
            if_id: request.policy_if_id(),
        },
    }
}

/// A validated, ordered roster of XFRM objects applied as one transaction.
///
/// Construction is the only place member admissibility is decided, so every
/// later durable step operates on a member set that is exact, uniquely
/// removable, and unambiguous in the kernel's own selection relation.
pub struct XfrmObjectRosterRequest {
    members: Vec<XfrmObjectRosterMemberRequest>,
}

impl XfrmObjectRosterRequest {
    /// Validate a caller-declared apply order into one roster transaction.
    ///
    /// Ordinal zero is applied first and compensated last. Every member must
    /// select exactly one kernel object for removal, no two members may share
    /// an exact deletion identity, and no two members may collide in the
    /// kernel's coarse selection relation.
    ///
    /// # Errors
    ///
    /// Returns [`XfrmObjectRosterRequestError`] naming the first violated rule.
    /// Nothing is persisted and no backend is contacted.
    pub fn new(
        members: Vec<XfrmObjectRosterMemberRequest>,
    ) -> Result<Self, XfrmObjectRosterRequestError> {
        if members.is_empty() {
            return Err(XfrmObjectRosterRequestError::EmptyRoster);
        }
        if members.len() > XFRM_OBJECT_ROSTER_MAX_MEMBERS {
            return Err(XfrmObjectRosterRequestError::TooManyMembers);
        }
        for member in &members {
            if let Some((identity, _)) = member.identity {
                if identity.iter().all(|byte| *byte == 0) {
                    return Err(XfrmObjectRosterRequestError::MalformedMemberIdentity);
                }
            }
            // Identical to the single-object prepare admission: a narrow lookup
            // mark can never produce the exact unconditional removal identity
            // that compensation re-selects on.
            let removal = member.request.removal();
            validate_exact_lookup_mark(removal.lookup_mark(), "durable_roster.member.mark")
                .map_err(|_| XfrmObjectRosterRequestError::NonExactRemovalIdentity)?;
        }
        let deletion_identities = members
            .iter()
            .map(|member| (member.request.removal(), member.request.policy_if_id()))
            .collect::<Vec<_>>();
        for (index, left) in deletion_identities.iter().enumerate() {
            if deletion_identities[index + 1..]
                .iter()
                .any(|right| right == left)
            {
                return Err(XfrmObjectRosterRequestError::DuplicateDeletionIdentity);
            }
        }
        let selection_keys = members
            .iter()
            .map(|member| kernel_selection_key(&member.request))
            .collect::<Vec<_>>();
        for (index, left) in selection_keys.iter().enumerate() {
            if selection_keys[index + 1..]
                .iter()
                .any(|right| right == left)
            {
                return Err(XfrmObjectRosterRequestError::AmbiguousKernelSelection);
            }
        }
        Ok(Self { members })
    }

    /// Number of declared members.
    #[must_use]
    pub fn arity(&self) -> usize {
        self.members.len()
    }

    /// Borrow one declared member by ordinal.
    #[must_use]
    pub fn member(&self, ordinal: usize) -> Option<&XfrmObjectRosterMemberRequest> {
        self.members.get(ordinal)
    }

    fn members(&self) -> &[XfrmObjectRosterMemberRequest] {
        &self.members
    }

    fn request(
        &self,
        ordinal: usize,
    ) -> Result<&XfrmObjectInstallRequest, XfrmObjectRosterDurableError> {
        self.members
            .get(ordinal)
            .map(XfrmObjectRosterMemberRequest::request)
            .ok_or(XfrmObjectRosterDurableError::Malformed)
    }
}

impl fmt::Debug for XfrmObjectRosterRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XfrmObjectRosterRequest")
            .field("arity", &self.members.len())
            .finish_non_exhaustive()
    }
}

/// Value-free durable disposition of one roster member slot.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct XfrmObjectRosterMemberDisposition {
    ordinal: usize,
    phase: &'static str,
    sweep_proof: Option<&'static str>,
    adjacent_proof: Option<&'static str>,
}

impl XfrmObjectRosterMemberDisposition {
    /// Position of this member in the caller-declared apply order.
    #[must_use]
    pub const fn ordinal(self) -> usize {
        self.ordinal
    }

    /// Stable, value-free durable phase label of this member slot.
    #[must_use]
    pub const fn phase(self) -> &'static str {
        self.phase
    }

    /// Stable label of the group-wide pre-effect sweep proof, when witnessed.
    #[must_use]
    pub const fn sweep_proof(self) -> Option<&'static str> {
        self.sweep_proof
    }

    /// Stable label of the adjacent proof witnessed immediately before this
    /// member's own effect window, when witnessed.
    ///
    /// This is the only proof that can authorize deleting this member.
    #[must_use]
    pub const fn adjacent_proof(self) -> Option<&'static str> {
        self.adjacent_proof
    }

    /// Whether this member witnessed a conflicting object it must never
    /// delete.
    #[must_use]
    pub fn is_conflicting(self) -> bool {
        self.sweep_proof == Some(XfrmObjectRosterSweepProof::Conflict.as_str())
            || matches!(
                self.adjacent_proof,
                Some(label)
                    if label == XfrmObjectRosterAdjacentProof::Conflict.as_str()
                        || label
                            == XfrmObjectRosterAdjacentProof::AbsentThenAlreadyExists.as_str()
            )
    }
}

impl fmt::Debug for XfrmObjectRosterMemberDisposition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XfrmObjectRosterMemberDisposition")
            .field("ordinal", &self.ordinal)
            .field("phase", &self.phase)
            .field("sweep_proof", &self.sweep_proof)
            .field("adjacent_proof", &self.adjacent_proof)
            .finish()
    }
}

/// Value-free per-member disposition of one authenticated roster record.
///
/// Every outcome variant of both roster outcome enums carries this, so a
/// consumer always learns which ordinals conflicted, which are owned, and
/// which never entered an effect window, without any identity value.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct XfrmObjectRosterMemberDispositions {
    entries: [Option<XfrmObjectRosterMemberDisposition>; XFRM_OBJECT_ROSTER_MAX_MEMBERS],
}

impl XfrmObjectRosterMemberDispositions {
    /// Number of populated member slots.
    #[must_use]
    pub fn arity(&self) -> usize {
        self.entries.iter().flatten().count()
    }

    /// Borrow one member disposition by ordinal.
    #[must_use]
    pub fn member(&self, ordinal: usize) -> Option<XfrmObjectRosterMemberDisposition> {
        self.entries.get(ordinal).copied().flatten()
    }

    /// Iterate the populated member dispositions in apply order.
    pub fn iter(&self) -> impl Iterator<Item = XfrmObjectRosterMemberDisposition> + '_ {
        self.entries.iter().flatten().copied()
    }

    /// Whether any member witnessed a conflicting object.
    #[must_use]
    pub fn has_conflict(&self) -> bool {
        self.iter()
            .any(XfrmObjectRosterMemberDisposition::is_conflicting)
    }

    const fn empty() -> Self {
        Self {
            entries: [None; XFRM_OBJECT_ROSTER_MAX_MEMBERS],
        }
    }
}

impl fmt::Debug for XfrmObjectRosterMemberDispositions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XfrmObjectRosterMemberDispositions")
            .field("arity", &self.arity())
            .finish_non_exhaustive()
    }
}

/// Durable terminal result of one grouped roster transaction.
///
/// Every variant carries an authenticated opaque handle and the complete
/// per-member disposition. The handle is only correlation data until the same
/// bound store authenticates its current record; its `Debug` and `Display`
/// forms never expose identity material.
#[non_exhaustive]
pub enum XfrmObjectRosterDurableOutcome {
    /// Every member was acknowledged in the declared order and the group is
    /// durably `Applied`, awaiting the consumer's adoption decision.
    Applied {
        /// Authenticated correlation handle for the applied record.
        handle: XfrmObjectRosterRecoveryHandle,
        /// Per-member durable disposition.
        members: XfrmObjectRosterMemberDispositions,
    },
    /// A conflict was proved before any member effect was admitted, so the
    /// whole group made no mutation. The dispositions name the conflicting
    /// ordinals.
    NoMutation {
        /// Authenticated correlation handle for the terminal record.
        handle: XfrmObjectRosterRecoveryHandle,
        /// Per-member durable disposition.
        members: XfrmObjectRosterMemberDispositions,
    },
    /// A member failed or conflicted after at least one member was acquired.
    /// The acquired prefix was reverse-compensated and the group left no
    /// acquired member behind.
    RolledBack {
        /// Authenticated correlation handle for the terminal record.
        handle: XfrmObjectRosterRecoveryHandle,
        /// Ordinal of the member whose result diverted the group.
        failed_member: usize,
        /// Per-member durable disposition.
        members: XfrmObjectRosterMemberDispositions,
        /// Redaction-safe backend failure, when one was observed. A witnessed
        /// adjacent conflict diverts the group without any backend error.
        source: Option<XfrmError>,
    },
    /// The group cannot prove its own residue and the record stays unresolved
    /// so restart recovery can reconcile it under the writer gate. No later
    /// member ran and no unproved deletion was attempted.
    Indeterminate {
        /// Authenticated correlation handle for the retained record.
        handle: XfrmObjectRosterRecoveryHandle,
        /// Per-member durable disposition.
        members: XfrmObjectRosterMemberDispositions,
        /// Redaction-safe backend failure observed by the current process.
        source: Option<XfrmError>,
    },
}

impl XfrmObjectRosterDurableOutcome {
    /// Stable, value-free outcome label.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Applied { .. } => "applied",
            Self::NoMutation { .. } => "no_mutation",
            Self::RolledBack { .. } => "rolled_back",
            Self::Indeterminate { .. } => "indeterminate",
        }
    }

    /// Authenticated opaque correlation handle.
    #[must_use]
    pub const fn handle(&self) -> &XfrmObjectRosterRecoveryHandle {
        match self {
            Self::Applied { handle, .. }
            | Self::NoMutation { handle, .. }
            | Self::RolledBack { handle, .. }
            | Self::Indeterminate { handle, .. } => handle,
        }
    }

    /// Per-member durable disposition of the record this outcome published.
    #[must_use]
    pub const fn members(&self) -> &XfrmObjectRosterMemberDispositions {
        match self {
            Self::Applied { members, .. }
            | Self::NoMutation { members, .. }
            | Self::RolledBack { members, .. }
            | Self::Indeterminate { members, .. } => members,
        }
    }

    /// Ordinal of the member that diverted the group, when one did.
    #[must_use]
    pub const fn failed_member(&self) -> Option<usize> {
        match self {
            Self::RolledBack { failed_member, .. } => Some(*failed_member),
            _ => None,
        }
    }

    /// Redaction-safe backend failure observed by the current process.
    #[must_use]
    pub const fn source(&self) -> Option<&XfrmError> {
        match self {
            Self::RolledBack { source, .. } | Self::Indeterminate { source, .. } => source.as_ref(),
            Self::Applied { .. } | Self::NoMutation { .. } => None,
        }
    }
}

impl fmt::Debug for XfrmObjectRosterDurableOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XfrmObjectRosterDurableOutcome")
            .field("outcome", &self.as_str())
            .field("members", self.members())
            .finish_non_exhaustive()
    }
}

/// Deterministic disposition of a durable roster record after process loss.
///
/// Every variant carries the per-member disposition of the record that
/// produced the verdict, read back through the store's own authentication. For
/// a terminal verdict those slots are the retired history; for a retained
/// record they are the exact state the operator must repair or retry against.
#[non_exhaustive]
pub enum XfrmObjectRosterRestartOutcome {
    /// A prepared or explicit no-mutation roster was retired without any
    /// backend removal.
    NoMutation {
        /// Per-member durable disposition.
        members: XfrmObjectRosterMemberDispositions,
    },
    /// Compensation completed and the roster left no acquired member behind.
    RolledBack {
        /// Per-member durable disposition.
        members: XfrmObjectRosterMemberDispositions,
    },
    /// An unfinalized applied roster was owned residue; every member was
    /// removed in reverse order and the record was retired.
    OwnedResidueRetired {
        /// Per-member durable disposition.
        members: XfrmObjectRosterMemberDispositions,
    },
    /// Every acquired member read back present, so the applied roster was
    /// committed additively without any deletion.
    Adopted {
        /// Per-member durable disposition.
        members: XfrmObjectRosterMemberDispositions,
    },
    /// Adoption could not prove every acquired member present. Nothing was
    /// published and nothing was deleted; the record stays `Applied` and the
    /// consumer may still recover it.
    AdoptionRefused {
        /// Per-member durable disposition.
        members: XfrmObjectRosterMemberDispositions,
    },
    /// A member's exact readback could not be trusted, so its ownership stays
    /// unproved. No deletion was attempted and the record stays unresolved.
    Indeterminate {
        /// Per-member durable disposition.
        members: XfrmObjectRosterMemberDispositions,
    },
    /// Product ownership was already committed; cleanup is forbidden.
    Committed {
        /// Per-member durable disposition.
        members: XfrmObjectRosterMemberDispositions,
    },
    /// Cleanup had already completed.
    Retired {
        /// Per-member durable disposition.
        members: XfrmObjectRosterMemberDispositions,
    },
    /// An exact removal failed after `RemovalAdmitted` was made durable. The
    /// record remains retryable and blocks a cooperating replacement.
    RemovalPending {
        /// Per-member durable disposition.
        members: XfrmObjectRosterMemberDispositions,
        /// Redaction-safe backend failure.
        source: XfrmError,
    },
    /// A member witnessed a conflicting object before its effect window, so no
    /// effect was admitted for it and the foreign state was left exactly as it
    /// was found.
    ForeignUntouched {
        /// Per-member durable disposition.
        members: XfrmObjectRosterMemberDispositions,
    },
    /// The durable record is inconsistent in a way this boundary cannot safely
    /// repair, such as a stale writer epoch under an unresolved roster. The
    /// record is retained, nothing was deleted, and it continues to gate
    /// cooperating writers until product repair.
    RepairRequired {
        /// Per-member durable disposition.
        members: XfrmObjectRosterMemberDispositions,
    },
}

impl XfrmObjectRosterRestartOutcome {
    /// Stable, value-free recovery label.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NoMutation { .. } => "no_mutation",
            Self::RolledBack { .. } => "rolled_back",
            Self::OwnedResidueRetired { .. } => "owned_residue_retired",
            Self::Adopted { .. } => "adopted",
            Self::AdoptionRefused { .. } => "adoption_refused",
            Self::Indeterminate { .. } => "indeterminate",
            Self::Committed { .. } => "committed",
            Self::Retired { .. } => "retired",
            Self::RemovalPending { .. } => "removal_pending",
            Self::ForeignUntouched { .. } => "foreign_untouched",
            Self::RepairRequired { .. } => "repair_required",
        }
    }

    /// Per-member durable disposition of the record that produced this verdict.
    #[must_use]
    pub const fn members(&self) -> &XfrmObjectRosterMemberDispositions {
        match self {
            Self::NoMutation { members }
            | Self::RolledBack { members }
            | Self::OwnedResidueRetired { members }
            | Self::Adopted { members }
            | Self::AdoptionRefused { members }
            | Self::Indeterminate { members }
            | Self::Committed { members }
            | Self::Retired { members }
            | Self::RemovalPending { members, .. }
            | Self::ForeignUntouched { members }
            | Self::RepairRequired { members } => members,
        }
    }

    /// Redaction-safe backend removal failure, when retry remains required.
    #[must_use]
    pub const fn source(&self) -> Option<&XfrmError> {
        match self {
            Self::RemovalPending { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl fmt::Debug for XfrmObjectRosterRestartOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XfrmObjectRosterRestartOutcome")
            .field("outcome", &self.as_str())
            .field("members", self.members())
            .finish_non_exhaustive()
    }
}

/// Deterministic rejection while issuing one admitted roster.
///
/// The pre-effect variant is the proved-clean rejection: no durable state
/// changed and no backend effect was admitted, so the actor may return the
/// caller's admission authority for an exact retry.
pub(crate) enum XfrmObjectRosterIssueError {
    /// A durable store operation failed. Whatever the record already published
    /// stands and recovery reconciles it.
    Durable(XfrmObjectRosterDurableError),
    /// A pre-effect readback could not be trusted, so the group's
    /// all-or-nothing conflict gate cannot be decided. Durable state is
    /// untouched and no effect was admitted.
    PreEffectReadbackFailed(XfrmError),
}

impl XfrmObjectRosterIssueError {
    /// Stable machine-readable, value-free error code.
    pub(crate) const fn as_str(&self) -> &'static str {
        match self {
            Self::Durable(_) => "xfrm_object_roster_issue_durable",
            Self::PreEffectReadbackFailed(_) => "xfrm_object_roster_issue_pre_effect_readback",
        }
    }

    /// Whether this rejection proved that no backend effect was admitted and
    /// no durable state changed.
    pub(crate) const fn is_proved_clean(&self) -> bool {
        matches!(self, Self::PreEffectReadbackFailed(_))
    }
}

impl From<XfrmObjectRosterDurableError> for XfrmObjectRosterIssueError {
    fn from(error: XfrmObjectRosterDurableError) -> Self {
        Self::Durable(error)
    }
}

impl fmt::Debug for XfrmObjectRosterIssueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XfrmObjectRosterIssueError")
            .field("error", &self.as_str())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for XfrmObjectRosterIssueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl XfrmObjectRosterRecoveryStore {
    /// Re-authenticate a retained handle and yield the record's per-member
    /// disposition.
    ///
    /// This is the precise recovery descriptor: it never returns state that the
    /// store has not just authenticated against this exact lease, group
    /// identity, generation, and member set, so a stale or forged handle can
    /// never be mistaken for current truth. It publishes nothing and never
    /// authorizes a deletion.
    ///
    /// # Errors
    ///
    /// Returns [`XfrmObjectRosterDurableError::Stale`] for a superseded handle,
    /// [`XfrmObjectRosterDurableError::AuthenticationFailed`] for a forged one,
    /// and [`XfrmObjectRosterDurableError::WrongBinding`] when the handle does
    /// not belong to this group, generation, or member set.
    pub fn inspect_dispositions(
        &self,
        handle: &XfrmObjectRosterRecoveryHandle,
        group_id: XfrmObjectRosterGroupId,
        generation: XfrmObjectRosterOperationGeneration,
        roster: &XfrmObjectRosterRequest,
    ) -> Result<XfrmObjectRosterMemberDispositions, XfrmObjectRosterDurableError> {
        let fingerprint = roster_digest(self, group_id, generation, roster)?;
        let record = self.restore_handle(handle, fingerprint)?;
        if record.group_id != group_id || record.group_generation != generation {
            return Err(XfrmObjectRosterDurableError::WrongBinding);
        }
        Ok(dispositions_for(&record))
    }
}

/// Derive the complete durable material for every declared member.
fn roster_member_material(
    store: &XfrmObjectRosterRecoveryStore,
    group_id: XfrmObjectRosterGroupId,
    generation: XfrmObjectRosterOperationGeneration,
    roster: &XfrmObjectRosterRequest,
) -> Result<Vec<XfrmObjectRosterMemberMaterial>, XfrmObjectRosterDurableError> {
    let mut material = Vec::with_capacity(roster.arity());
    for (ordinal, member) in roster.members().iter().enumerate() {
        let fingerprints = store.fingerprints_for_request(member.request())?;
        let (member_id, member_generation) = match member.identity {
            Some((bytes, generation)) => (
                XfrmObjectRosterMemberId::from_bytes(bytes)?,
                NonZeroU64::new(generation.get()).ok_or(XfrmObjectRosterDurableError::Malformed)?,
            ),
            None => (
                store.derive_member_identity(group_id, generation, ordinal)?,
                NonZeroU64::new(generation.get()).ok_or(XfrmObjectRosterDurableError::Malformed)?,
            ),
        };
        material.push(XfrmObjectRosterMemberMaterial {
            object: member.request().object(),
            member_id,
            member_generation,
            fingerprints,
        });
    }
    Ok(material)
}

/// Compute the keyed digest that binds this exact ordered member set.
fn roster_digest(
    store: &XfrmObjectRosterRecoveryStore,
    group_id: XfrmObjectRosterGroupId,
    generation: XfrmObjectRosterOperationGeneration,
    roster: &XfrmObjectRosterRequest,
) -> Result<[u8; 32], XfrmObjectRosterDurableError> {
    let material = roster_member_material(store, group_id, generation, roster)?;
    store.roster_fingerprint_for(&material)
}

fn dispositions_for(record: &DurableRosterRecord) -> XfrmObjectRosterMemberDispositions {
    let mut dispositions = XfrmObjectRosterMemberDispositions::empty();
    for (ordinal, entry) in dispositions.entries.iter_mut().enumerate() {
        let Some(slot) = record.member(ordinal) else {
            continue;
        };
        *entry = Some(XfrmObjectRosterMemberDisposition {
            ordinal,
            phase: slot.phase.as_str(),
            sweep_proof: slot.sweep_proof.map(XfrmObjectRosterSweepProof::as_str),
            adjacent_proof: slot
                .adjacent_proof
                .map(XfrmObjectRosterAdjacentProof::as_str),
        });
    }
    dispositions
}

/// Restate one slot's persisted proofs while advancing only its phase.
fn advance_slot(
    slot: &DurableRosterMemberSlot,
    phase: XfrmObjectRosterMemberPhase,
) -> XfrmObjectRosterMemberTransition {
    XfrmObjectRosterMemberTransition {
        phase,
        sweep_proof: slot.sweep_proof,
        adjacent_proof: slot.adjacent_proof,
    }
}

/// Publish one transition from the record's own authenticated current phase.
fn publish(
    store: &XfrmObjectRosterRecoveryStore,
    record: &DurableRosterRecord,
    next: XfrmObjectRosterTransition,
) -> Result<DurableRosterRecord, XfrmObjectRosterDurableError> {
    store.transition(&store.handle_for_record(record)?, record.phase, next)
}

fn cursor_of(ordinal: usize) -> Result<u8, XfrmObjectRosterDurableError> {
    u8::try_from(ordinal).map_err(|_| XfrmObjectRosterDurableError::Malformed)
}

pub(crate) fn prepare_object_roster(
    store: &XfrmObjectRosterRecoveryStore,
    group_id: XfrmObjectRosterGroupId,
    generation: XfrmObjectRosterOperationGeneration,
    roster: &XfrmObjectRosterRequest,
) -> Result<XfrmObjectRosterRecoveryHandle, XfrmObjectRosterDurableError> {
    let material = roster_member_material(store, group_id, generation, roster)?;
    store.prepare(group_id, generation, &material)
}

pub(crate) fn validate_object_roster_admission(
    store: &XfrmObjectRosterRecoveryStore,
    prepared: &XfrmObjectRosterRecoveryHandle,
    group_id: XfrmObjectRosterGroupId,
    generation: XfrmObjectRosterOperationGeneration,
    roster: &XfrmObjectRosterRequest,
) -> Result<(), XfrmObjectRosterDurableError> {
    let fingerprint = roster_digest(store, group_id, generation, roster)?;
    let record = store.restore_handle(prepared, fingerprint)?;
    if record.group_id != group_id
        || record.group_generation != generation
        || record.phase != XfrmObjectRosterDurablePhase::Prepared
    {
        return Err(XfrmObjectRosterDurableError::WrongBinding);
    }
    Ok(())
}

/// Where an issue run must stop short of its terminal publication.
#[derive(Clone, Copy)]
struct IssuingCut {
    ordinal: usize,
    admit_backend_effect: bool,
}

/// Result of driving one admitted roster.
// Both variants are dominated by the same 944-byte durable handle, so boxing
// would only add an allocation to a value that is constructed once and
// immediately destructured by its two callers.
#[allow(clippy::large_enum_variant)]
enum Issued {
    Terminal(XfrmObjectRosterDurableOutcome),
    Cut(XfrmObjectRosterRecoveryHandle),
}

/// Apply one admitted roster in declared order, compensating in reverse.
///
/// The protocol is the spec's run protocol verbatim: sweep every member, burn
/// the group's single writer epoch on `Prepared -> Issuing`, publish each
/// member's adjacent absence proof BEFORE its effect, and divert the whole
/// group on any member result other than a clean acquisition.
///
/// # Contract
///
/// `AlreadyExists` from a member install under an `Absent` adjacent proof
/// records that member as `NoMutation` with the `AbsentThenAlreadyExists`
/// proof and FAILS the roster, deliberately diverging from the single-object
/// family's `AlreadyExists -> NoMutation` success semantics. For a
/// dependency-ordered Child SA roster, "one leg is a foreign object of unknown
/// parameters" must not be reported as protocol success: RFC 7296 sections 1.3
/// and 2.8 give partial Child SA installation no wire representation, and
/// RFC 4301 section 4.4 treats the SPD and SAD entries of one protected flow as
/// a single consistent unit. The foreign object is never deleted.
///
/// # Errors
///
/// Returns [`XfrmObjectRosterIssueError::PreEffectReadbackFailed`] when a
/// pre-effect readback cannot be trusted, in which case durable state is
/// untouched and no effect was admitted, or
/// [`XfrmObjectRosterIssueError::Durable`] for a store failure.
#[allow(clippy::too_many_arguments)]
async fn issue_roster<B>(
    store: &XfrmObjectRosterRecoveryStore,
    prepared: &XfrmObjectRosterRecoveryHandle,
    group_id: XfrmObjectRosterGroupId,
    generation: XfrmObjectRosterOperationGeneration,
    roster: &XfrmObjectRosterRequest,
    backend: &B,
    cut: Option<IssuingCut>,
) -> Result<Issued, XfrmObjectRosterIssueError>
where
    B: XfrmBackend + ?Sized,
{
    validate_object_roster_admission(store, prepared, group_id, generation, roster)?;
    let arity = roster.arity();

    // Step 3: sweep witness of every member. This is the all-or-nothing
    // conflict gate and the early abort; it is read-only and precedes the
    // epoch burn, so it can never authorize a deletion on its own.
    let mut sweeps = Vec::with_capacity(arity);
    for member in roster.members() {
        let present = readback_object_present(backend, member.request())
            .await
            .map_err(XfrmObjectRosterIssueError::PreEffectReadbackFailed)?;
        sweeps.push(if present {
            XfrmObjectRosterSweepProof::Conflict
        } else {
            XfrmObjectRosterSweepProof::Absent
        });
    }
    let swept_clean = sweeps
        .iter()
        .all(|proof| *proof == XfrmObjectRosterSweepProof::Absent);

    // Member zero's adjacent witness rides the Prepared -> Issuing publication,
    // so its effect window is opened by the same durable record that burns the
    // epoch. It is taken only when the sweep already admitted the group.
    let member_zero_present = if swept_clean {
        Some(
            readback_object_present(backend, roster.request(0)?)
                .await
                .map_err(XfrmObjectRosterIssueError::PreEffectReadbackFailed)?,
        )
    } else {
        None
    };

    // Step 5: the group's single writer-epoch burn.
    let mut issuing = XfrmObjectRosterTransition::new(XfrmObjectRosterDurablePhase::Issuing, 0);
    for (ordinal, sweep) in sweeps.iter().enumerate() {
        let adjacent = if ordinal == 0 && member_zero_present == Some(false) {
            Some(XfrmObjectRosterAdjacentProof::Absent)
        } else {
            None
        };
        issuing = issuing.with_member(
            ordinal,
            XfrmObjectRosterMemberTransition {
                phase: XfrmObjectRosterMemberPhase::Pending,
                sweep_proof: Some(*sweep),
                adjacent_proof: adjacent,
            },
        );
    }
    let mut record = store.transition(prepared, XfrmObjectRosterDurablePhase::Prepared, issuing)?;

    // Step 6: any sweep conflict is terminal with zero backend calls.
    if !swept_clean {
        let record = publish(
            store,
            &record,
            XfrmObjectRosterTransition::new(XfrmObjectRosterDurablePhase::NoMutation, 0),
        )?;
        return Ok(Issued::Terminal(
            XfrmObjectRosterDurableOutcome::NoMutation {
                handle: store.handle_for_record(&record)?,
                members: dispositions_for(&record),
            },
        ));
    }

    // Member zero conflicted between the sweep and its own effect window: the
    // group is terminal no-mutation before any effect was admitted.
    if member_zero_present == Some(true) {
        let slot = record
            .member(0)
            .ok_or(XfrmObjectRosterDurableError::Malformed)?;
        let conflicted = XfrmObjectRosterMemberTransition {
            phase: XfrmObjectRosterMemberPhase::NoMutation,
            sweep_proof: slot.sweep_proof,
            adjacent_proof: Some(XfrmObjectRosterAdjacentProof::Conflict),
        };
        let record = publish(
            store,
            &record,
            XfrmObjectRosterTransition::new(XfrmObjectRosterDurablePhase::NoMutation, 0)
                .with_member(0, conflicted),
        )?;
        return Ok(Issued::Terminal(
            XfrmObjectRosterDurableOutcome::NoMutation {
                handle: store.handle_for_record(&record)?,
                members: dispositions_for(&record),
            },
        ));
    }

    // Step 7: ordered apply. The loop invariant is that member k's slot carries
    // an `Absent` adjacent proof published strictly before member k's effect.
    let mut failed_member = None;
    let mut failure_source = None;
    let mut ordinal = 0;
    while ordinal < arity {
        if ordinal > 0 {
            // Publish the previous member's acquisition together with this
            // member's freshly witnessed adjacent proof.
            let previous = record
                .member(ordinal - 1)
                .ok_or(XfrmObjectRosterDurableError::Malformed)?;
            let acquired = advance_slot(previous, XfrmObjectRosterMemberPhase::Acquired);
            match readback_object_present(backend, roster.request(ordinal)?).await {
                Ok(false) => {
                    let slot = record
                        .member(ordinal)
                        .ok_or(XfrmObjectRosterDurableError::Malformed)?;
                    record = publish(
                        store,
                        &record,
                        XfrmObjectRosterTransition::new(
                            XfrmObjectRosterDurablePhase::Issuing,
                            cursor_of(ordinal)?,
                        )
                        .with_member(ordinal - 1, acquired)
                        .with_member(
                            ordinal,
                            XfrmObjectRosterMemberTransition {
                                adjacent_proof: Some(XfrmObjectRosterAdjacentProof::Absent),
                                ..advance_slot(slot, XfrmObjectRosterMemberPhase::Pending)
                            },
                        ),
                    )?;
                }
                Ok(true) => {
                    // A conflicting object appeared inside the group's own
                    // epoch. No effect is admitted for this member and the
                    // acquired prefix is compensated.
                    let slot = record
                        .member(ordinal)
                        .ok_or(XfrmObjectRosterDurableError::Malformed)?;
                    record = publish(
                        store,
                        &record,
                        XfrmObjectRosterTransition::new(
                            XfrmObjectRosterDurablePhase::Compensating,
                            cursor_of(ordinal - 1)?,
                        )
                        .with_member(ordinal - 1, acquired)
                        .with_member(
                            ordinal,
                            XfrmObjectRosterMemberTransition {
                                adjacent_proof: Some(XfrmObjectRosterAdjacentProof::Conflict),
                                ..advance_slot(slot, XfrmObjectRosterMemberPhase::NoMutation)
                            },
                        ),
                    )?;
                    failed_member = Some(ordinal);
                    break;
                }
                Err(source) => {
                    // The adjacent proof is the only thing that could authorize
                    // deleting this member later, so an untrustworthy readback
                    // must never be followed by its effect.
                    record = publish(
                        store,
                        &record,
                        XfrmObjectRosterTransition::new(
                            XfrmObjectRosterDurablePhase::Compensating,
                            cursor_of(ordinal - 1)?,
                        )
                        .with_member(ordinal - 1, acquired),
                    )?;
                    failed_member = Some(ordinal);
                    failure_source = Some(source);
                    break;
                }
            }
        }

        if let Some(cut) = cut {
            if cut.ordinal == ordinal {
                if cut.admit_backend_effect {
                    // The epoch is already burned and the adjacent proof is
                    // already durable, so this is the production effect
                    // admission with its terminal publication deliberately
                    // omitted.
                    let _ = install(backend, roster.request(ordinal)?).await;
                }
                return Ok(Issued::Cut(store.handle_for_record(&record)?));
            }
        }

        match install(backend, roster.request(ordinal)?).await {
            Ok(()) => {
                if ordinal + 1 == arity {
                    let slot = record
                        .member(ordinal)
                        .ok_or(XfrmObjectRosterDurableError::Malformed)?;
                    let acquired = advance_slot(slot, XfrmObjectRosterMemberPhase::Acquired);
                    let record = publish(
                        store,
                        &record,
                        XfrmObjectRosterTransition::new(
                            XfrmObjectRosterDurablePhase::Applied,
                            cursor_of(arity)?,
                        )
                        .with_member(ordinal, acquired),
                    )?;
                    return Ok(Issued::Terminal(XfrmObjectRosterDurableOutcome::Applied {
                        handle: store.handle_for_record(&record)?,
                        members: dispositions_for(&record),
                    }));
                }
                ordinal += 1;
            }
            Err(XfrmError::AlreadyExists) => {
                let slot = record
                    .member(ordinal)
                    .ok_or(XfrmObjectRosterDurableError::Malformed)?;
                record = publish(
                    store,
                    &record,
                    XfrmObjectRosterTransition::new(
                        XfrmObjectRosterDurablePhase::Compensating,
                        cursor_of(ordinal)?,
                    )
                    .with_member(
                        ordinal,
                        XfrmObjectRosterMemberTransition {
                            adjacent_proof: Some(
                                XfrmObjectRosterAdjacentProof::AbsentThenAlreadyExists,
                            ),
                            ..advance_slot(slot, XfrmObjectRosterMemberPhase::NoMutation)
                        },
                    ),
                )?;
                failed_member = Some(ordinal);
                failure_source = Some(XfrmError::AlreadyExists);
                break;
            }
            Err(source) => {
                let slot = record
                    .member(ordinal)
                    .ok_or(XfrmObjectRosterDurableError::Malformed)?;
                record = publish(
                    store,
                    &record,
                    XfrmObjectRosterTransition::new(
                        XfrmObjectRosterDurablePhase::Compensating,
                        cursor_of(ordinal)?,
                    )
                    .with_member(
                        ordinal,
                        advance_slot(slot, XfrmObjectRosterMemberPhase::Indeterminate),
                    ),
                )?;
                // Step 8: the identical reconcile recovery uses. Never descend
                // past a member whose own residue is still unproved.
                match reconcile_unresolved_member(store, record, ordinal, roster, backend).await? {
                    MemberReconcile::Resolved(next) | MemberReconcile::Foreign(next) => {
                        record = next;
                    }
                    MemberReconcile::Unreadable(next)
                    | MemberReconcile::RepairRequired(next)
                    | MemberReconcile::RemovalPending { record: next, .. } => {
                        return Ok(Issued::Terminal(
                            XfrmObjectRosterDurableOutcome::Indeterminate {
                                handle: store.handle_for_record(&next)?,
                                members: dispositions_for(&next),
                                source: Some(source),
                            },
                        ));
                    }
                }
                failed_member = Some(ordinal);
                failure_source = Some(source);
                break;
            }
        }
    }

    let failed_member = failed_member.ok_or(XfrmObjectRosterDurableError::InvalidTransition)?;

    // Step 9: strict reverse compensation of the acquired prefix.
    match compensate_acquired_slots(store, record, roster, backend, None).await? {
        Compensation::RolledBack(record) => Ok(Issued::Terminal(
            XfrmObjectRosterDurableOutcome::RolledBack {
                handle: store.handle_for_record(&record)?,
                failed_member,
                members: dispositions_for(&record),
                source: failure_source,
            },
        )),
        Compensation::RemovalPending { record, source } => Ok(Issued::Terminal(
            XfrmObjectRosterDurableOutcome::Indeterminate {
                handle: store.handle_for_record(&record)?,
                members: dispositions_for(&record),
                source: Some(source),
            },
        )),
        Compensation::RepairRequired(record) | Compensation::Cut(record) => Ok(Issued::Terminal(
            XfrmObjectRosterDurableOutcome::Indeterminate {
                handle: store.handle_for_record(&record)?,
                members: dispositions_for(&record),
                source: failure_source,
            },
        )),
    }
}

/// Apply one admitted roster as a single durable transaction.
///
/// See [`issue_roster`] for the protocol, the `AlreadyExists` contract, and the
/// named deletion invariant.
///
/// # Errors
///
/// Returns [`XfrmObjectRosterIssueError`]; the pre-effect variant proves that
/// nothing was admitted and the caller's authority may be returned for retry.
pub(crate) async fn issue_durable_object_roster<B>(
    store: &XfrmObjectRosterRecoveryStore,
    prepared: &XfrmObjectRosterRecoveryHandle,
    group_id: XfrmObjectRosterGroupId,
    generation: XfrmObjectRosterOperationGeneration,
    roster: &XfrmObjectRosterRequest,
    backend: &B,
) -> Result<XfrmObjectRosterDurableOutcome, XfrmObjectRosterIssueError>
where
    B: XfrmBackend + ?Sized,
{
    match issue_roster(store, prepared, group_id, generation, roster, backend, None).await? {
        Issued::Terminal(outcome) => Ok(outcome),
        Issued::Cut(_) => Err(XfrmObjectRosterIssueError::Durable(
            XfrmObjectRosterDurableError::InvalidTransition,
        )),
    }
}

/// Outcome of one member reconciliation.
enum MemberReconcile {
    /// The member is durably resolved and compensation may descend past it.
    Resolved(DurableRosterRecord),
    /// The member witnessed a conflicting object it must never delete. The
    /// slot is resolved and the foreign state was left untouched.
    Foreign(DurableRosterRecord),
    /// The member's exact readback could not be trusted; nothing was published.
    Unreadable(DurableRosterRecord),
    /// The exact removal failed after `RemovalAdmitted` was made durable.
    RemovalPending {
        record: DurableRosterRecord,
        source: XfrmError,
    },
    /// The record cannot be safely repaired at this boundary.
    RepairRequired(DurableRosterRecord),
}

/// Reconcile one unresolved member from its ADJACENT proof plus a fresh exact
/// readback.
///
/// This is the single implementation shared by the live run and by restart
/// recovery, so the live and post-crash verdicts for the same durable state
/// cannot drift apart. The classification is:
///
/// - no adjacent proof recorded: the member never entered its effect window,
///   so it provably made no mutation and nothing is deleted.
/// - `Absent` + absent: the effect provably never landed; no deletion.
/// - `Absent` + present: the object appeared inside this member's own effect
///   window under the group's burned epoch, so it can only be this roster's
///   residue; admit and remove it.
/// - `Conflict` or `AbsentThenAlreadyExists`: no effect was admitted for this
///   member, so the object is foreign and is never deleted.
///
/// A stale writer epoch removes the ordering guarantee the `Absent` proof
/// depends on, so it is classified for repair with nothing deleted.
async fn reconcile_unresolved_member<B>(
    store: &XfrmObjectRosterRecoveryStore,
    record: DurableRosterRecord,
    ordinal: usize,
    roster: &XfrmObjectRosterRequest,
    backend: &B,
) -> Result<MemberReconcile, XfrmObjectRosterDurableError>
where
    B: XfrmBackend + ?Sized,
{
    let slot = *record
        .member(ordinal)
        .ok_or(XfrmObjectRosterDurableError::Malformed)?;
    let cursor = cursor_of(ordinal)?;
    let resolve = |store: &XfrmObjectRosterRecoveryStore,
                   record: &DurableRosterRecord,
                   phase: XfrmObjectRosterMemberPhase| {
        publish(
            store,
            record,
            XfrmObjectRosterTransition::new(XfrmObjectRosterDurablePhase::Compensating, cursor)
                .with_member(ordinal, advance_slot(&slot, phase)),
        )
    };

    match slot.adjacent_proof {
        None => Ok(MemberReconcile::Resolved(resolve(
            store,
            &record,
            XfrmObjectRosterMemberPhase::NoMutation,
        )?)),
        Some(XfrmObjectRosterAdjacentProof::Conflict)
        | Some(XfrmObjectRosterAdjacentProof::AbsentThenAlreadyExists) => {
            if slot.phase == XfrmObjectRosterMemberPhase::NoMutation {
                return Ok(MemberReconcile::Foreign(record));
            }
            Ok(MemberReconcile::Foreign(resolve(
                store,
                &record,
                XfrmObjectRosterMemberPhase::NoMutation,
            )?))
        }
        Some(XfrmObjectRosterAdjacentProof::Absent) => {
            // Named invariant, enforced here as well as by the store's own slot
            // edges: a member that already published a terminal no-mutation or
            // retired verdict is never an argument to a delete, whatever its
            // proofs say.
            if matches!(
                slot.phase,
                XfrmObjectRosterMemberPhase::NoMutation | XfrmObjectRosterMemberPhase::Retired
            ) {
                return Ok(MemberReconcile::Resolved(record));
            }
            if !store.record_writer_epoch_is_current(&record)? {
                return Ok(MemberReconcile::RepairRequired(record));
            }
            let present = match readback_object_present(backend, roster.request(ordinal)?).await {
                Ok(present) => present,
                Err(_) => return Ok(MemberReconcile::Unreadable(record)),
            };
            if !present {
                return Ok(MemberReconcile::Resolved(resolve(
                    store,
                    &record,
                    XfrmObjectRosterMemberPhase::NoMutation,
                )?));
            }
            // A slot that never left `Pending` has no durable statement that
            // its own effect may have landed, and the store's slot edges refuse
            // to jump straight to removal authority. Publish the unresolved
            // step the live run would have published, then admit the removal.
            let unresolved = if slot.phase == XfrmObjectRosterMemberPhase::Pending {
                resolve(store, &record, XfrmObjectRosterMemberPhase::Indeterminate)?
            } else {
                record
            };
            let admitted = resolve(
                store,
                &unresolved,
                XfrmObjectRosterMemberPhase::RemovalAdmitted,
            )?;
            let request = roster.request(ordinal)?;
            match remove(backend, &request.removal(), request.policy_if_id()).await {
                Ok(()) | Err(XfrmError::NotFound) => Ok(MemberReconcile::Resolved(resolve(
                    store,
                    &admitted,
                    XfrmObjectRosterMemberPhase::Retired,
                )?)),
                Err(source) => Ok(MemberReconcile::RemovalPending {
                    record: admitted,
                    source,
                }),
            }
        }
    }
}

/// Outcome of one reverse-compensation sweep.
enum Compensation {
    RolledBack(DurableRosterRecord),
    RemovalPending {
        record: DurableRosterRecord,
        source: XfrmError,
    },
    RepairRequired(DurableRosterRecord),
    Cut(DurableRosterRecord),
}

/// Reverse-compensate every acquired member, highest ordinal first.
///
/// Each member is durably `RemovalAdmitted` before its delete is issued and
/// only becomes `Retired` once the delete returned success or proved the object
/// absent, so a crash at any point leaves retryable authority rather than an
/// unproved deletion. A member slot in `NoMutation` is never an argument to a
/// delete here or anywhere else.
async fn compensate_acquired_slots<B>(
    store: &XfrmObjectRosterRecoveryStore,
    record: DurableRosterRecord,
    roster: &XfrmObjectRosterRequest,
    backend: &B,
    cut: Option<(usize, bool)>,
) -> Result<Compensation, XfrmObjectRosterDurableError>
where
    B: XfrmBackend + ?Sized,
{
    let mut record = record;
    if !store.record_writer_epoch_is_current(&record)? {
        return Ok(Compensation::RepairRequired(record));
    }
    let arity = record.arity()?;
    loop {
        let target = (0..arity).rev().find(|ordinal| {
            record.member(*ordinal).is_some_and(|slot| {
                matches!(
                    slot.phase,
                    XfrmObjectRosterMemberPhase::Acquired
                        | XfrmObjectRosterMemberPhase::RemovalAdmitted
                )
            })
        });
        let Some(ordinal) = target else {
            break;
        };
        let cursor = cursor_of(ordinal)?;
        let slot = *record
            .member(ordinal)
            .ok_or(XfrmObjectRosterDurableError::Malformed)?;
        if slot.phase == XfrmObjectRosterMemberPhase::Acquired {
            record = publish(
                store,
                &record,
                XfrmObjectRosterTransition::new(XfrmObjectRosterDurablePhase::Compensating, cursor)
                    .with_member(
                        ordinal,
                        advance_slot(&slot, XfrmObjectRosterMemberPhase::RemovalAdmitted),
                    ),
            )?;
        }
        let request = roster.request(ordinal)?;
        if let Some((cut_ordinal, admit_backend_effect)) = cut {
            if cut_ordinal == ordinal {
                if admit_backend_effect {
                    // Deliberately omit the terminal publication regardless of
                    // the reply: recovery must safely retry an exact delete or
                    // observe absence while the durable removal authority is
                    // intact.
                    let _ = remove(backend, &request.removal(), request.policy_if_id()).await;
                }
                return Ok(Compensation::Cut(record));
            }
        }
        match remove(backend, &request.removal(), request.policy_if_id()).await {
            Ok(()) | Err(XfrmError::NotFound) => {
                let slot = *record
                    .member(ordinal)
                    .ok_or(XfrmObjectRosterDurableError::Malformed)?;
                record = publish(
                    store,
                    &record,
                    XfrmObjectRosterTransition::new(
                        XfrmObjectRosterDurablePhase::Compensating,
                        cursor,
                    )
                    .with_member(
                        ordinal,
                        advance_slot(&slot, XfrmObjectRosterMemberPhase::Retired),
                    ),
                )?;
            }
            Err(source) => return Ok(Compensation::RemovalPending { record, source }),
        }
    }
    let record = publish(
        store,
        &record,
        XfrmObjectRosterTransition::new(XfrmObjectRosterDurablePhase::RolledBack, 0),
    )?;
    Ok(Compensation::RolledBack(record))
}

/// Surrender the roster's cleanup authority after the consumer's adoption
/// decision is durable.
///
/// `Applied` becomes `Committed` with every member slot preserved as
/// `Acquired`: per-member ownership survives finalize so a crash immediately
/// afterwards still classifies each object exactly. A terminal no-mutation or
/// rolled-back roster is retired so its record and deletion identities are
/// pruned at the next prepare or epoch advance.
///
/// # Errors
///
/// Returns [`XfrmObjectRosterDurableError::InvalidTransition`] when the roster
/// is still unresolved, and any authentication or storage failure.
pub(crate) fn finalize_durable_object_roster(
    store: &XfrmObjectRosterRecoveryStore,
    group_id: XfrmObjectRosterGroupId,
    generation: XfrmObjectRosterOperationGeneration,
    roster: &XfrmObjectRosterRequest,
) -> Result<XfrmObjectRosterDurablePhase, XfrmObjectRosterDurableError> {
    let fingerprint = roster_digest(store, group_id, generation, roster)?;
    let record = store.restore(group_id, generation, fingerprint)?;
    match record.phase {
        XfrmObjectRosterDurablePhase::Applied => publish(
            store,
            &record,
            XfrmObjectRosterTransition::new(XfrmObjectRosterDurablePhase::Committed, record.cursor),
        )
        .map(|record| record.phase),
        XfrmObjectRosterDurablePhase::NoMutation | XfrmObjectRosterDurablePhase::RolledBack => {
            publish(
                store,
                &record,
                XfrmObjectRosterTransition::new(XfrmObjectRosterDurablePhase::Retired, 0),
            )
            .map(|record| record.phase)
        }
        XfrmObjectRosterDurablePhase::Committed | XfrmObjectRosterDurablePhase::Retired => {
            Ok(record.phase)
        }
        _ => Err(XfrmObjectRosterDurableError::InvalidTransition),
    }
}

/// Adopt an unfinalized applied roster after process loss, without deleting
/// anything.
///
/// # Contract
///
/// Call this (or [`recover_durable_object_roster`]) BEFORE any other namespace
/// mutation after process start. An intervening ordinary mutation burns the
/// writer epoch and forces `RepairRequired`.
///
/// Adoption is legal only from `Applied` and is purely additive: it
/// re-authenticates the binding, incarnations, member digest, and epoch
/// currency, reads every member back exactly, and commits only when every
/// acquired member is present. Otherwise it publishes nothing, leaves the
/// record `Applied` with the writer gate closed, and returns `AdoptionRefused`
/// so the consumer can still choose recovery.
///
/// Adopt against recover: adopt keeps a converged roster whose consumer
/// deadline expired, recover destroys it. Use adopt when the consumer's
/// bookkeeping can still accept the group; use recover when it cannot.
///
/// # Errors
///
/// Returns any authentication, binding, or storage failure from the store.
pub(crate) async fn adopt_durable_object_roster<B>(
    store: &XfrmObjectRosterRecoveryStore,
    group_id: XfrmObjectRosterGroupId,
    generation: XfrmObjectRosterOperationGeneration,
    roster: &XfrmObjectRosterRequest,
    backend: &B,
) -> Result<XfrmObjectRosterRestartOutcome, XfrmObjectRosterDurableError>
where
    B: XfrmBackend + ?Sized,
{
    let fingerprint = roster_digest(store, group_id, generation, roster)?;
    let record = store.restore(group_id, generation, fingerprint)?;
    let members = dispositions_for(&record);
    match record.phase {
        XfrmObjectRosterDurablePhase::Committed => {
            return Ok(XfrmObjectRosterRestartOutcome::Committed { members })
        }
        XfrmObjectRosterDurablePhase::Retired => {
            return Ok(XfrmObjectRosterRestartOutcome::Retired { members })
        }
        XfrmObjectRosterDurablePhase::Applied => {}
        _ => return Ok(XfrmObjectRosterRestartOutcome::AdoptionRefused { members }),
    }
    if !store.record_writer_epoch_is_current(&record)? {
        return Ok(XfrmObjectRosterRestartOutcome::RepairRequired { members });
    }
    let arity = record.arity()?;
    for ordinal in 0..arity {
        let slot = record
            .member(ordinal)
            .ok_or(XfrmObjectRosterDurableError::Malformed)?;
        if slot.phase != XfrmObjectRosterMemberPhase::Acquired {
            return Ok(XfrmObjectRosterRestartOutcome::AdoptionRefused { members });
        }
        match readback_object_present(backend, roster.request(ordinal)?).await {
            Ok(true) => {}
            // An absent member or an untrustworthy readback both fail to prove
            // the group converged. Nothing is published and nothing is deleted.
            Ok(false) | Err(_) => {
                return Ok(XfrmObjectRosterRestartOutcome::AdoptionRefused { members })
            }
        }
    }
    let record = publish(
        store,
        &record,
        XfrmObjectRosterTransition::new(XfrmObjectRosterDurablePhase::Committed, record.cursor),
    )?;
    Ok(XfrmObjectRosterRestartOutcome::Adopted {
        members: dispositions_for(&record),
    })
}

/// Reconstruct the deterministic verdict for one durable roster after process
/// loss.
///
/// # Contract
///
/// Call this (or [`adopt_durable_object_roster`]) BEFORE any other namespace
/// mutation after process start. An intervening ordinary mutation burns the
/// writer epoch, which removes the ordering guarantee every adjacent absence
/// proof depends on, and recovery then reports `RepairRequired` with the record
/// retained and nothing deleted.
///
/// There is no conflict shortcut: every unresolved member is classified from
/// its own adjacent proof plus a fresh exact readback, and an acquired prefix
/// is always reverse-compensated. A member slot in `NoMutation` is never an
/// argument to a delete.
///
/// # Errors
///
/// Returns any authentication, binding, or storage failure from the store.
pub(crate) async fn recover_durable_object_roster<B>(
    store: &XfrmObjectRosterRecoveryStore,
    group_id: XfrmObjectRosterGroupId,
    generation: XfrmObjectRosterOperationGeneration,
    roster: &XfrmObjectRosterRequest,
    backend: &B,
) -> Result<XfrmObjectRosterRestartOutcome, XfrmObjectRosterDurableError>
where
    B: XfrmBackend + ?Sized,
{
    let fingerprint = roster_digest(store, group_id, generation, roster)?;
    let record = store.restore(group_id, generation, fingerprint)?;
    let members = dispositions_for(&record);
    match record.phase {
        XfrmObjectRosterDurablePhase::Prepared => {
            let record = publish(
                store,
                &record,
                XfrmObjectRosterTransition::new(XfrmObjectRosterDurablePhase::Retired, 0),
            )?;
            Ok(XfrmObjectRosterRestartOutcome::NoMutation {
                members: dispositions_for(&record),
            })
        }
        XfrmObjectRosterDurablePhase::NoMutation => {
            let conflicted = members.has_conflict();
            let record = publish(
                store,
                &record,
                XfrmObjectRosterTransition::new(XfrmObjectRosterDurablePhase::Retired, 0),
            )?;
            let members = dispositions_for(&record);
            if conflicted {
                // The group admitted no effect precisely because it witnessed a
                // conflicting object, and that object was never touched.
                Ok(XfrmObjectRosterRestartOutcome::ForeignUntouched { members })
            } else {
                Ok(XfrmObjectRosterRestartOutcome::NoMutation { members })
            }
        }
        XfrmObjectRosterDurablePhase::RolledBack => {
            let record = publish(
                store,
                &record,
                XfrmObjectRosterTransition::new(XfrmObjectRosterDurablePhase::Retired, 0),
            )?;
            Ok(XfrmObjectRosterRestartOutcome::RolledBack {
                members: dispositions_for(&record),
            })
        }
        XfrmObjectRosterDurablePhase::Committed => {
            Ok(XfrmObjectRosterRestartOutcome::Committed { members })
        }
        XfrmObjectRosterDurablePhase::Retired => {
            Ok(XfrmObjectRosterRestartOutcome::Retired { members })
        }
        XfrmObjectRosterDurablePhase::Issuing
        | XfrmObjectRosterDurablePhase::Applied
        | XfrmObjectRosterDurablePhase::Compensating => {
            if !store.record_writer_epoch_is_current(&record)? {
                return Ok(XfrmObjectRosterRestartOutcome::RepairRequired { members });
            }
            recover_unresolved_roster(store, record, roster, backend).await
        }
    }
}

async fn recover_unresolved_roster<B>(
    store: &XfrmObjectRosterRecoveryStore,
    record: DurableRosterRecord,
    roster: &XfrmObjectRosterRequest,
    backend: &B,
) -> Result<XfrmObjectRosterRestartOutcome, XfrmObjectRosterDurableError>
where
    B: XfrmBackend + ?Sized,
{
    let mut record = record;
    let arity = record.arity()?;
    let mut foreign = false;
    let from_applied = record.phase == XfrmObjectRosterDurablePhase::Applied;

    if record.phase == XfrmObjectRosterDurablePhase::Issuing {
        let swept_conflict = (0..arity).any(|ordinal| {
            record
                .member(ordinal)
                .is_some_and(|slot| slot.sweep_proof == Some(XfrmObjectRosterSweepProof::Conflict))
        });
        if swept_conflict {
            // The sweep aborted the group before any member entered an effect
            // window, so the terminal verdict is the zero-effect one and the
            // conflicting object is left exactly as it was found.
            let record = publish(
                store,
                &record,
                XfrmObjectRosterTransition::new(XfrmObjectRosterDurablePhase::NoMutation, 0),
            )?;
            let record = publish(
                store,
                &record,
                XfrmObjectRosterTransition::new(XfrmObjectRosterDurablePhase::Retired, 0),
            )?;
            return Ok(XfrmObjectRosterRestartOutcome::ForeignUntouched {
                members: dispositions_for(&record),
            });
        }
    }

    // Never descend past a member whose own residue is still unproved.
    let unresolved = match record.phase {
        XfrmObjectRosterDurablePhase::Issuing => Some(usize::from(record.cursor)),
        XfrmObjectRosterDurablePhase::Compensating => (0..arity).find(|ordinal| {
            record
                .member(*ordinal)
                .is_some_and(|slot| slot.phase == XfrmObjectRosterMemberPhase::Indeterminate)
        }),
        _ => None,
    };
    if let Some(ordinal) = unresolved {
        match reconcile_unresolved_member(store, record, ordinal, roster, backend).await? {
            MemberReconcile::Resolved(next) => record = next,
            MemberReconcile::Foreign(next) => {
                record = next;
                foreign = true;
            }
            MemberReconcile::Unreadable(next) => {
                return Ok(XfrmObjectRosterRestartOutcome::Indeterminate {
                    members: dispositions_for(&next),
                })
            }
            MemberReconcile::RepairRequired(next) => {
                return Ok(XfrmObjectRosterRestartOutcome::RepairRequired {
                    members: dispositions_for(&next),
                })
            }
            MemberReconcile::RemovalPending {
                record: next,
                source,
            } => {
                return Ok(XfrmObjectRosterRestartOutcome::RemovalPending {
                    members: dispositions_for(&next),
                    source,
                })
            }
        }
    }

    match compensate_acquired_slots(store, record, roster, backend, None).await? {
        Compensation::RolledBack(record) => {
            let record = publish(
                store,
                &record,
                XfrmObjectRosterTransition::new(XfrmObjectRosterDurablePhase::Retired, 0),
            )?;
            let members = dispositions_for(&record);
            if foreign {
                Ok(XfrmObjectRosterRestartOutcome::ForeignUntouched { members })
            } else if from_applied {
                Ok(XfrmObjectRosterRestartOutcome::OwnedResidueRetired { members })
            } else {
                Ok(XfrmObjectRosterRestartOutcome::RolledBack { members })
            }
        }
        Compensation::RemovalPending { record, source } => {
            Ok(XfrmObjectRosterRestartOutcome::RemovalPending {
                members: dispositions_for(&record),
                source,
            })
        }
        Compensation::RepairRequired(record) => {
            Ok(XfrmObjectRosterRestartOutcome::RepairRequired {
                members: dispositions_for(&record),
            })
        }
        Compensation::Cut(record) => Ok(XfrmObjectRosterRestartOutcome::Indeterminate {
            members: dispositions_for(&record),
        }),
    }
}

/// Process-loss detector seam: drive an admitted roster to a durable `Issuing`
/// record at member `ordinal` and stop before that member's terminal
/// publication.
///
/// This reproduces the exact crash window [`issue_durable_object_roster`] would
/// leave if the process died between the cursor-`ordinal` publication and the
/// terminal record for that member. Members below `ordinal` are applied for
/// real, so the durable prefix is genuine acquisition authority. When
/// `admit_backend_effect` is true the member's install is invoked exactly as
/// the real effect admission does (the epoch is already burned and the adjacent
/// proof already durable), so the kernel object exists while the record stays
/// `Issuing`; when false the backend is never asked to mutate that member. No
/// terminal phase is published, so the record stays unresolved and recoverable.
/// This is only used by crash detectors and never grants deletion authority.
///
/// # Errors
///
/// Returns [`XfrmObjectRosterIssueError`]. A roster that diverts before
/// reaching `ordinal` reports [`XfrmObjectRosterDurableError::InvalidTransition`].
#[allow(clippy::too_many_arguments)]
pub(crate) async fn cut_durable_object_roster_at_issuing_member<B>(
    store: &XfrmObjectRosterRecoveryStore,
    prepared: &XfrmObjectRosterRecoveryHandle,
    group_id: XfrmObjectRosterGroupId,
    generation: XfrmObjectRosterOperationGeneration,
    roster: &XfrmObjectRosterRequest,
    backend: &B,
    ordinal: usize,
    admit_backend_effect: bool,
) -> Result<XfrmObjectRosterRecoveryHandle, XfrmObjectRosterIssueError>
where
    B: XfrmBackend + ?Sized,
{
    if ordinal >= roster.arity() {
        return Err(XfrmObjectRosterIssueError::Durable(
            XfrmObjectRosterDurableError::Malformed,
        ));
    }
    match issue_roster(
        store,
        prepared,
        group_id,
        generation,
        roster,
        backend,
        Some(IssuingCut {
            ordinal,
            admit_backend_effect,
        }),
    )
    .await?
    {
        Issued::Cut(handle) => Ok(handle),
        Issued::Terminal(_) => Err(XfrmObjectRosterIssueError::Durable(
            XfrmObjectRosterDurableError::InvalidTransition,
        )),
    }
}

/// Process-loss detector seam: apply an admitted roster and stop at the
/// unfinalized `Applied` record.
///
/// This is the production run path with the consumer's finalize deliberately
/// omitted, which is the window in which both `adopt` and `recover` are legal.
///
/// # Errors
///
/// Returns [`XfrmObjectRosterIssueError`]. A roster that does not reach
/// `Applied` reports [`XfrmObjectRosterDurableError::InvalidTransition`].
pub(crate) async fn cut_durable_object_roster_at_applied<B>(
    store: &XfrmObjectRosterRecoveryStore,
    prepared: &XfrmObjectRosterRecoveryHandle,
    group_id: XfrmObjectRosterGroupId,
    generation: XfrmObjectRosterOperationGeneration,
    roster: &XfrmObjectRosterRequest,
    backend: &B,
) -> Result<XfrmObjectRosterRecoveryHandle, XfrmObjectRosterIssueError>
where
    B: XfrmBackend + ?Sized,
{
    match issue_durable_object_roster(store, prepared, group_id, generation, roster, backend)
        .await?
    {
        XfrmObjectRosterDurableOutcome::Applied { handle, .. } => Ok(handle),
        _ => Err(XfrmObjectRosterIssueError::Durable(
            XfrmObjectRosterDurableError::InvalidTransition,
        )),
    }
}

/// Process-loss detector seam: reverse-compensate an applied roster down to
/// member `ordinal`, durably admit that member's removal, optionally issue the
/// deletion, and stop before publishing its `Retired` slot.
///
/// Before any delete this runs the identical validation chain
/// [`recover_durable_object_roster`] runs: an authenticated restore of the
/// exact group identity, generation, and member set, the group phase legality
/// check, and writer-epoch currency. The namespace actor wraps this call with
/// its store-instance and admission-gate checks exactly as it wraps recovery.
/// Leaving the member at `RemovalAdmitted` models a crash after the deletion
/// was admitted, including after the kernel effect but before its
/// acknowledgement became durable.
///
/// # Errors
///
/// Returns any authentication, binding, or storage failure, and
/// [`XfrmObjectRosterDurableError::InvalidTransition`] when compensation never
/// reaches `ordinal`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn cut_durable_object_roster_at_compensating_member<B>(
    store: &XfrmObjectRosterRecoveryStore,
    group_id: XfrmObjectRosterGroupId,
    generation: XfrmObjectRosterOperationGeneration,
    roster: &XfrmObjectRosterRequest,
    backend: &B,
    ordinal: usize,
    admit_backend_effect: bool,
) -> Result<XfrmObjectRosterRecoveryHandle, XfrmObjectRosterDurableError>
where
    B: XfrmBackend + ?Sized,
{
    let fingerprint = roster_digest(store, group_id, generation, roster)?;
    let record = store.restore(group_id, generation, fingerprint)?;
    if !matches!(
        record.phase,
        XfrmObjectRosterDurablePhase::Applied | XfrmObjectRosterDurablePhase::Compensating
    ) {
        return Err(XfrmObjectRosterDurableError::InvalidTransition);
    }
    match compensate_acquired_slots(
        store,
        record,
        roster,
        backend,
        Some((ordinal, admit_backend_effect)),
    )
    .await?
    {
        Compensation::Cut(record) => store.handle_for_record(&record),
        _ => Err(XfrmObjectRosterDurableError::InvalidTransition),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        fs::{self, DirBuilder},
        io,
        os::unix::fs::DirBuilderExt,
        path::{Path, PathBuf},
        sync::{Mutex, MutexGuard},
    };

    use async_trait::async_trait;

    use super::*;
    use crate::durable_install::{
        finalize_durable_object_install, issue_durable_object_install,
        prepare_durable_object_install,
    };
    use crate::durable_object::{
        XfrmObjectInstallDurablePhase, XfrmObjectInstallOperationGeneration,
        XfrmObjectInstallOperationId, XfrmObjectInstallPreEffectProof,
        XfrmObjectInstallRecoveryStore, XfrmObjectRecoveryProofKey,
    };
    use crate::durable_roster::{
        XfrmObjectRosterPublicationClass, XfrmObjectRosterRecoveryProofKey,
    };
    use crate::model::{
        AllocateSpiRequest, ExactRemovePolicyRequest, InstallPolicyRequest, InstallSaRequest,
        PolicyParameters, QueryPolicyRequest, QuerySaRequest, RekeyPolicyRequest, RekeySaRequest,
        RemovePolicyRequest, RemoveSaRequest, SaParameters, SaState, SpiAllocation, XfrmAction,
        XfrmId, XfrmLookupMark, XfrmMode, XfrmProbe, XfrmTemplate,
    };
    use crate::MockXfrmBackend;

    const NAMESPACE_BINDING: [u8; 40] = [0x5c; 40];
    const PROOF_KEY_BYTE: u8 = 0x71;
    /// Synthetic cost charged at each consumer-visible durable boundary.
    const BARRIER_COST: usize = 7;
    /// The dependency-ordered Child SA roster: inbound SA, inbound policy,
    /// inbound forward policy, outbound SA, outbound policy.
    const CHILD_SA_ROSTER: [Kind; 5] =
        [Kind::Sa, Kind::Policy, Kind::Policy, Kind::Sa, Kind::Policy];

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            for _ in 0..8 {
                let identity = XfrmObjectRosterGroupId::generate().unwrap();
                let name = identity
                    .to_bytes()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                let path = std::env::temp_dir().join(format!("opc-xfrm-roster-flow-test-{name}"));
                assert!(path.is_absolute());
                match DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("failed to create secure test root: {error}"),
                }
            }
            panic!("failed to allocate a unique secure test root");
        }

        fn path(&self) -> &Path {
            &self.0
        }

        /// Number of durable roster record files, excluding the control record
        /// and the epoch witnesses.
        fn record_files(&self) -> usize {
            fs::read_dir(&self.0)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .filter(|name| name != "control" && !name.starts_with("epoch-"))
                .count()
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            if self.0.is_dir() {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
    }

    fn open_store(root: &TestRoot) -> XfrmObjectRosterRecoveryStore {
        XfrmObjectRosterRecoveryStore::open_bound(
            root.path(),
            XfrmObjectRosterRecoveryProofKey::new([PROOF_KEY_BYTE; 32]).unwrap(),
            NAMESPACE_BINDING,
        )
        .unwrap()
    }

    fn open_object_store(root: &TestRoot) -> XfrmObjectInstallRecoveryStore {
        XfrmObjectInstallRecoveryStore::open_bound(
            root.path(),
            XfrmObjectRecoveryProofKey::new([PROOF_KEY_BYTE; 32]).unwrap(),
            NAMESPACE_BINDING,
        )
        .unwrap()
    }

    fn group(byte: u8) -> XfrmObjectRosterGroupId {
        XfrmObjectRosterGroupId::from_bytes([byte; 16]).unwrap()
    }

    fn generation(value: u64) -> XfrmObjectRosterOperationGeneration {
        XfrmObjectRosterOperationGeneration::new(value).unwrap()
    }

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddress {
        IpAddress::Ipv4([a, b, c, d])
    }

    fn octet(index: usize) -> u8 {
        u8::try_from(index).unwrap()
    }

    fn selector(index: usize) -> XfrmSelector {
        XfrmSelector::new(
            ipv4(10, 67, 0, 1 + octet(index)),
            ipv4(198, 51, 100, 19),
            50,
        )
    }

    fn identity(index: usize) -> XfrmId {
        XfrmId {
            destination: ipv4(198, 51, 100, 20 + octet(index)),
            spi: 0x6160_0001 + u32::try_from(index).unwrap(),
            protocol: 50,
        }
    }

    fn sa_request(index: usize) -> XfrmObjectInstallRequest {
        XfrmObjectInstallRequest::Sa(InstallSaRequest {
            parameters: SaParameters {
                selector: selector(index),
                id: identity(index),
                source_address: ipv4(10, 67, 0, 1),
                request_id: None,
                auth: None,
                crypt: None,
                aead: None,
                mode: XfrmMode::Tunnel,
                lifetime: Default::default(),
                replay_window: 32,
                replay_state: None,
                encap: None,
                mark: None,
                output_mark: None,
                if_id: None,
                egress_dscp: None,
            },
        })
    }

    fn policy_request(index: usize) -> XfrmObjectInstallRequest {
        XfrmObjectInstallRequest::Policy(InstallPolicyRequest {
            parameters: PolicyParameters {
                selector: selector(index),
                direction: XfrmDirection::Out,
                action: XfrmAction::Allow,
                priority: 616,
                templates: vec![XfrmTemplate {
                    id: identity(index),
                    source_address: ipv4(10, 67, 0, 1),
                    request_id: None,
                    mode: XfrmMode::Tunnel,
                }],
                mark: None,
                if_id: Some(600 + u32::try_from(index).unwrap()),
            },
        })
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Kind {
        Sa,
        Policy,
    }

    fn request_for(kind: Kind, index: usize) -> XfrmObjectInstallRequest {
        match kind {
            Kind::Sa => sa_request(index),
            Kind::Policy => policy_request(index),
        }
    }

    fn roster_of(kinds: &[Kind]) -> XfrmObjectRosterRequest {
        XfrmObjectRosterRequest::new(
            kinds
                .iter()
                .enumerate()
                .map(|(index, kind)| XfrmObjectRosterMemberRequest::new(request_for(*kind, index)))
                .collect(),
        )
        .unwrap()
    }

    fn canonical_if_id(if_id: Option<u32>) -> Option<u32> {
        if_id.filter(|if_id| *if_id != 0)
    }

    /// The exact kernel identity one scripted operation addressed.
    #[derive(Clone, PartialEq, Eq)]
    enum ObjectKey {
        Sa {
            destination: IpAddress,
            protocol: u8,
            spi: u32,
            mark: Option<XfrmLookupMark>,
        },
        Policy {
            selector: XfrmSelector,
            direction: XfrmDirection,
            mark: Option<XfrmLookupMark>,
            if_id: Option<u32>,
        },
    }

    fn object_key(request: &XfrmObjectInstallRequest) -> ObjectKey {
        match request {
            XfrmObjectInstallRequest::Sa(sa) => ObjectKey::Sa {
                destination: sa.parameters.id.destination,
                protocol: sa.parameters.id.protocol,
                spi: sa.parameters.id.spi,
                mark: sa.parameters.mark,
            },
            XfrmObjectInstallRequest::Policy(policy) => ObjectKey::Policy {
                selector: policy.parameters.selector.clone(),
                direction: policy.parameters.direction,
                mark: policy.parameters.mark,
                if_id: request.policy_if_id(),
            },
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum OpKind {
        Query,
        Install,
        Remove,
    }

    /// One value-free scripted-backend observation.
    ///
    /// The ordinal is resolved by the rig from the roster's declared member
    /// set, so order assertions never mention an address, SPI, or selector.
    /// The interface identifier is retained deliberately: `MockOperation`
    /// drops it, so only this rig can prove that policy compensation used the
    /// exact interface-scoped deletion identity.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    struct ScriptedOp {
        kind: OpKind,
        ordinal: Option<usize>,
        if_id: Option<u32>,
    }

    struct Fault {
        kind: OpKind,
        ordinal: usize,
        occurrence: usize,
        error: XfrmError,
    }

    struct Script {
        keys: Vec<ObjectKey>,
        log: Vec<ScriptedOp>,
        faults: Vec<Fault>,
    }

    /// Per-call-index fault backend that records every operation in order.
    ///
    /// State semantics are delegated to [`MockXfrmBackend`] so create-exclusive
    /// `AlreadyExists`, exact `NotFound`, and interface-scoped policy identity
    /// stay exactly as the shared mock defines them.
    struct ScriptedBackend {
        inner: MockXfrmBackend,
        script: Mutex<Script>,
    }

    impl fmt::Debug for ScriptedBackend {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("ScriptedBackend(<redacted>)")
        }
    }

    impl ScriptedBackend {
        fn for_roster(roster: &XfrmObjectRosterRequest) -> Self {
            let keys = (0..roster.arity())
                .map(|ordinal| object_key(roster.member(ordinal).unwrap().request()))
                .collect();
            Self {
                inner: MockXfrmBackend::new(),
                script: Mutex::new(Script {
                    keys,
                    log: Vec::new(),
                    faults: Vec::new(),
                }),
            }
        }

        fn script(&self) -> MutexGuard<'_, Script> {
            self.script
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        }

        fn fail(&self, kind: OpKind, ordinal: usize, occurrence: usize, error: XfrmError) {
            self.script().faults.push(Fault {
                kind,
                ordinal,
                occurrence,
                error,
            });
        }

        fn fail_install(&self, ordinal: usize, error: XfrmError) {
            self.fail(OpKind::Install, ordinal, 0, error);
        }

        fn fail_remove(&self, ordinal: usize, error: XfrmError) {
            self.fail(OpKind::Remove, ordinal, 0, error);
        }

        fn fail_query(&self, ordinal: usize, occurrence: usize, error: XfrmError) {
            self.fail(OpKind::Query, ordinal, occurrence, error);
        }

        fn clear_faults(&self) {
            self.script().faults.clear();
        }

        fn clear_log(&self) {
            self.script().log.clear();
        }

        fn log(&self) -> Vec<ScriptedOp> {
            self.script().log.clone()
        }

        fn ordinals(&self, kind: OpKind) -> Vec<usize> {
            self.log()
                .iter()
                .filter(|op| op.kind == kind)
                .filter_map(|op| op.ordinal)
                .collect()
        }

        fn scopes(&self, kind: OpKind) -> Vec<Option<u32>> {
            self.log()
                .iter()
                .filter(|op| op.kind == kind)
                .map(|op| op.if_id)
                .collect()
        }

        fn effects(&self) -> usize {
            self.log()
                .iter()
                .filter(|op| op.kind != OpKind::Query)
                .count()
        }

        /// Record one operation and yield the fault scripted for this exact
        /// occurrence, if any.
        fn record(&self, kind: OpKind, key: &ObjectKey, if_id: Option<u32>) -> Option<XfrmError> {
            let mut script = self.script();
            let ordinal = script.keys.iter().position(|candidate| candidate == key);
            let occurrence = script
                .log
                .iter()
                .filter(|op| op.kind == kind && op.ordinal == ordinal)
                .count();
            script.log.push(ScriptedOp {
                kind,
                ordinal,
                if_id,
            });
            let ordinal = ordinal?;
            script
                .faults
                .iter()
                .find(|fault| {
                    fault.kind == kind && fault.ordinal == ordinal && fault.occurrence == occurrence
                })
                .map(|fault| fault.error.clone())
        }

        /// Observe kernel state without logging or scripting, so assertions
        /// never perturb the order detectors.
        async fn is_present(&self, request: &XfrmObjectInstallRequest) -> bool {
            readback_object_present(&self.inner, request).await.unwrap()
        }

        /// Plant a foreign object at a member's exact identity.
        async fn plant(&self, request: &XfrmObjectInstallRequest) {
            install(&self.inner, request).await.unwrap();
        }

        /// Remove an object out of band, without logging or scripting.
        async fn retire(&self, request: &XfrmObjectInstallRequest) {
            remove(&self.inner, &request.removal(), request.policy_if_id())
                .await
                .unwrap();
        }
    }

    #[async_trait]
    impl XfrmBackend for ScriptedBackend {
        async fn allocate_spi(
            &self,
            request: AllocateSpiRequest,
        ) -> Result<SpiAllocation, XfrmError> {
            self.inner.allocate_spi(request).await
        }

        async fn install_sa(&self, request: InstallSaRequest) -> Result<(), XfrmError> {
            let key = ObjectKey::Sa {
                destination: request.parameters.id.destination,
                protocol: request.parameters.id.protocol,
                spi: request.parameters.id.spi,
                mark: request.parameters.mark,
            };
            match self.record(OpKind::Install, &key, None) {
                Some(error) => Err(error),
                None => self.inner.install_sa(request).await,
            }
        }

        async fn query_sa(&self, request: QuerySaRequest) -> Result<SaState, XfrmError> {
            let key = ObjectKey::Sa {
                destination: request.destination,
                protocol: request.protocol,
                spi: request.spi,
                mark: request.mark,
            };
            match self.record(OpKind::Query, &key, None) {
                Some(error) => Err(error),
                None => self.inner.query_sa(request).await,
            }
        }

        async fn query_policy(
            &self,
            request: QueryPolicyRequest,
        ) -> Result<PolicyParameters, XfrmError> {
            let if_id = canonical_if_id(request.if_id());
            let key = ObjectKey::Policy {
                selector: request.selector().clone(),
                direction: request.direction(),
                mark: request.mark(),
                if_id,
            };
            match self.record(OpKind::Query, &key, if_id) {
                Some(error) => Err(error),
                None => self.inner.query_policy(request).await,
            }
        }

        async fn rekey_sa(&self, request: RekeySaRequest) -> Result<(), XfrmError> {
            self.inner.rekey_sa(request).await
        }

        async fn remove_sa(&self, request: RemoveSaRequest) -> Result<(), XfrmError> {
            let key = ObjectKey::Sa {
                destination: request.destination,
                protocol: request.protocol,
                spi: request.spi,
                mark: request.mark,
            };
            match self.record(OpKind::Remove, &key, None) {
                Some(error) => Err(error),
                None => self.inner.remove_sa(request).await,
            }
        }

        async fn install_policy(&self, request: InstallPolicyRequest) -> Result<(), XfrmError> {
            let if_id = canonical_if_id(request.parameters.if_id);
            let key = ObjectKey::Policy {
                selector: request.parameters.selector.clone(),
                direction: request.parameters.direction,
                mark: request.parameters.mark,
                if_id,
            };
            match self.record(OpKind::Install, &key, if_id) {
                Some(error) => Err(error),
                None => self.inner.install_policy(request).await,
            }
        }

        async fn rekey_policy(&self, request: RekeyPolicyRequest) -> Result<(), XfrmError> {
            self.inner.rekey_policy(request).await
        }

        async fn remove_policy(&self, request: RemovePolicyRequest) -> Result<(), XfrmError> {
            let key = ObjectKey::Policy {
                selector: request.selector.clone(),
                direction: request.direction,
                mark: request.mark,
                if_id: None,
            };
            match self.record(OpKind::Remove, &key, None) {
                Some(error) => Err(error),
                None => self.inner.remove_policy(request).await,
            }
        }

        async fn remove_policy_exact(
            &self,
            request: ExactRemovePolicyRequest,
        ) -> Result<(), XfrmError> {
            let if_id = canonical_if_id(request.if_id());
            let key = ObjectKey::Policy {
                selector: request.request().selector.clone(),
                direction: request.request().direction,
                mark: request.request().mark,
                if_id,
            };
            match self.record(OpKind::Remove, &key, if_id) {
                Some(error) => Err(error),
                None => self.inner.remove_policy_exact(request).await,
            }
        }

        async fn probe(&self) -> Result<XfrmProbe, XfrmError> {
            self.inner.probe().await
        }
    }

    async fn run_roster<B>(
        store: &XfrmObjectRosterRecoveryStore,
        group_id: XfrmObjectRosterGroupId,
        generation: XfrmObjectRosterOperationGeneration,
        roster: &XfrmObjectRosterRequest,
        backend: &B,
    ) -> Result<XfrmObjectRosterDurableOutcome, XfrmObjectRosterIssueError>
    where
        B: XfrmBackend + ?Sized,
    {
        let prepared = prepare_object_roster(store, group_id, generation, roster)?;
        issue_durable_object_roster(store, &prepared, group_id, generation, roster, backend).await
    }

    fn phase_ledger(store: &XfrmObjectRosterRecoveryStore) -> Vec<XfrmObjectRosterDurablePhase> {
        store
            .publication_ledger()
            .unwrap()
            .iter()
            .map(|publication| publication.phase)
            .collect()
    }

    fn class_count(
        store: &XfrmObjectRosterRecoveryStore,
        class: XfrmObjectRosterPublicationClass,
    ) -> usize {
        store
            .publication_ledger()
            .unwrap()
            .iter()
            .filter(|publication| publication.class == class)
            .count()
    }

    fn member_phase(outcome: &XfrmObjectRosterDurableOutcome, ordinal: usize) -> &'static str {
        outcome.members().member(ordinal).unwrap().phase()
    }

    fn descending(from: usize) -> Vec<usize> {
        (0..from).rev().collect()
    }

    #[test]
    fn roster_request_rejects_every_inadmissible_member_set() {
        assert_eq!(
            XfrmObjectRosterRequest::new(Vec::new()).unwrap_err(),
            XfrmObjectRosterRequestError::EmptyRoster
        );

        let too_many = (0..=XFRM_OBJECT_ROSTER_MAX_MEMBERS)
            .map(|index| XfrmObjectRosterMemberRequest::new(sa_request(index)))
            .collect::<Vec<_>>();
        assert_eq!(
            XfrmObjectRosterRequest::new(too_many).unwrap_err(),
            XfrmObjectRosterRequestError::TooManyMembers
        );

        // A narrow lookup mark cannot produce the exact unconditional removal
        // identity reverse compensation re-selects on.
        let mut narrow = sa_request(0);
        let XfrmObjectInstallRequest::Sa(request) = &mut narrow else {
            unreachable!();
        };
        request.parameters.mark = Some(XfrmLookupMark::new(0x10, 0xf0).unwrap());
        assert_eq!(
            XfrmObjectRosterRequest::new(vec![XfrmObjectRosterMemberRequest::new(narrow)])
                .unwrap_err(),
            XfrmObjectRosterRequestError::NonExactRemovalIdentity
        );

        assert_eq!(
            XfrmObjectRosterRequest::new(vec![
                XfrmObjectRosterMemberRequest::new(sa_request(0)),
                XfrmObjectRosterMemberRequest::new(sa_request(0)),
            ])
            .unwrap_err(),
            XfrmObjectRosterRequestError::DuplicateDeletionIdentity
        );

        // Fingerprint-distinct but kernel-colliding: Linux applies the STORED
        // SA's mark mask to the incoming lookup value, so the unmarked SA is
        // selected for every lookup value sharing its destination, protocol,
        // and SPI.
        let mut marked = sa_request(0);
        let XfrmObjectInstallRequest::Sa(request) = &mut marked else {
            unreachable!();
        };
        request.parameters.mark = Some(XfrmLookupMark::full(0x2a));
        assert_ne!(sa_request(0).removal(), marked.removal());
        assert_eq!(
            XfrmObjectRosterRequest::new(vec![
                XfrmObjectRosterMemberRequest::new(sa_request(0)),
                XfrmObjectRosterMemberRequest::new(marked),
            ])
            .unwrap_err(),
            XfrmObjectRosterRequestError::AmbiguousKernelSelection
        );

        let mut marked_policy = policy_request(0);
        let XfrmObjectInstallRequest::Policy(request) = &mut marked_policy else {
            unreachable!();
        };
        request.parameters.mark = Some(XfrmLookupMark::full(0x2b));
        assert_eq!(
            XfrmObjectRosterRequest::new(vec![
                XfrmObjectRosterMemberRequest::new(policy_request(0)),
                XfrmObjectRosterMemberRequest::new(marked_policy),
            ])
            .unwrap_err(),
            XfrmObjectRosterRequestError::AmbiguousKernelSelection
        );

        assert_eq!(
            XfrmObjectRosterRequest::new(vec![XfrmObjectRosterMemberRequest::new(sa_request(0))
                .with_identity([0; 16], generation(1))])
            .unwrap_err(),
            XfrmObjectRosterRequestError::MalformedMemberIdentity
        );

        assert_eq!(roster_of(&[Kind::Sa]).arity(), 1);
        assert_eq!(
            roster_of(&[Kind::Sa; XFRM_OBJECT_ROSTER_MAX_MEMBERS]).arity(),
            8
        );
    }

    #[tokio::test]
    async fn applied_roster_follows_the_declared_member_order() {
        let root = TestRoot::new();
        let roster = roster_of(&CHILD_SA_ROSTER);
        let backend = ScriptedBackend::for_roster(&roster);
        let store = open_store(&root);

        let outcome = run_roster(&store, group(0x11), generation(1), &roster, &backend)
            .await
            .unwrap();
        assert_eq!(outcome.as_str(), "applied");
        // Observed apply order equals the caller-declared order; the SDK
        // publishes no order constant of its own.
        assert_eq!(backend.ordinals(OpKind::Install), vec![0, 1, 2, 3, 4]);
        assert!(backend.ordinals(OpKind::Remove).is_empty());
        // Sweep witness of every member, then one adjacent witness per member.
        assert_eq!(
            backend.ordinals(OpKind::Query),
            vec![0, 1, 2, 3, 4, 0, 1, 2, 3, 4]
        );
        for ordinal in 0..5 {
            let disposition = outcome.members().member(ordinal).unwrap();
            assert_eq!(disposition.ordinal(), ordinal);
            assert_eq!(disposition.phase(), "acquired");
            assert_eq!(disposition.sweep_proof(), Some("absent"));
            assert_eq!(disposition.adjacent_proof(), Some("absent"));
            assert!(!disposition.is_conflicting());
        }
        assert!(!outcome.members().has_conflict());
        assert_eq!(outcome.members().arity(), 5);

        // The authenticated re-read agrees with the outcome it accompanied.
        let dispositions = store
            .inspect_dispositions(outcome.handle(), group(0x11), generation(1), &roster)
            .unwrap();
        assert_eq!(dispositions, *outcome.members());
        assert_eq!(
            store.inspect(outcome.handle()).unwrap(),
            XfrmObjectRosterDurablePhase::Applied
        );

        assert_eq!(
            finalize_durable_object_roster(&store, group(0x11), generation(1), &roster).unwrap(),
            XfrmObjectRosterDurablePhase::Committed
        );
        // A stale handle is never authority, and the committed record still
        // carries per-member ownership.
        assert!(store.inspect(outcome.handle()).is_err());
    }

    #[tokio::test]
    async fn install_failure_at_every_member_reverse_compensates_the_prefix() {
        for failed in 0..CHILD_SA_ROSTER.len() {
            let root = TestRoot::new();
            let roster = roster_of(&CHILD_SA_ROSTER);
            let backend = ScriptedBackend::for_roster(&roster);
            backend.fail_install(failed, XfrmError::Unavailable);
            let store = open_store(&root);

            let outcome = run_roster(&store, group(0x21), generation(1), &roster, &backend)
                .await
                .unwrap();
            assert_eq!(outcome.as_str(), "rolled_back");
            assert_eq!(outcome.failed_member(), Some(failed));
            assert!(matches!(outcome.source(), Some(XfrmError::Unavailable)));

            // Members are applied in order up to and including the failure and
            // no later member ever runs.
            assert_eq!(
                backend.ordinals(OpKind::Install),
                (0..=failed).collect::<Vec<_>>()
            );
            // The acquired prefix is compensated in strict reverse order.
            assert_eq!(backend.ordinals(OpKind::Remove), descending(failed));
            for ordinal in 0..failed {
                assert_eq!(member_phase(&outcome, ordinal), "retired");
                assert!(
                    !backend
                        .is_present(roster.member(ordinal).unwrap().request())
                        .await
                );
            }
            assert_eq!(member_phase(&outcome, failed), "no_mutation");
            for ordinal in failed + 1..CHILD_SA_ROSTER.len() {
                assert_eq!(member_phase(&outcome, ordinal), "pending");
            }
            assert_eq!(
                store.inspect(outcome.handle()).unwrap(),
                XfrmObjectRosterDurablePhase::RolledBack
            );
        }
    }

    #[tokio::test]
    async fn policy_compensation_uses_the_exact_interface_scoped_identity() {
        // MockOperation drops XFRMA_IF_ID, so the scoped deletion identity is
        // only observable through this rig.
        let root = TestRoot::new();
        let roster = roster_of(&[Kind::Policy, Kind::Policy, Kind::Sa]);
        let backend = ScriptedBackend::for_roster(&roster);
        backend.fail_install(2, XfrmError::Unavailable);
        let store = open_store(&root);

        let outcome = run_roster(&store, group(0x22), generation(1), &roster, &backend)
            .await
            .unwrap();
        assert_eq!(outcome.as_str(), "rolled_back");
        assert_eq!(backend.ordinals(OpKind::Remove), vec![1, 0]);
        assert_eq!(backend.scopes(OpKind::Remove), vec![Some(601), Some(600)]);
    }

    #[tokio::test]
    async fn durable_phase_sequence_records_every_compensation_boundary() {
        let root = TestRoot::new();
        let roster = roster_of(&[Kind::Sa, Kind::Policy, Kind::Sa]);
        let backend = ScriptedBackend::for_roster(&roster);
        backend.fail_install(2, XfrmError::Unavailable);
        let store = open_store(&root);

        run_roster(&store, group(0x23), generation(1), &roster, &backend)
            .await
            .unwrap();
        use XfrmObjectRosterDurablePhase::{Compensating, Issuing, Prepared, RolledBack};
        assert_eq!(
            phase_ledger(&store),
            vec![
                Prepared,
                Issuing,
                Issuing,
                Issuing,
                // The failed member is durably unresolved, then reconciled,
                // before compensation descends past it.
                Compensating,
                Compensating,
                Compensating,
                Compensating,
                Compensating,
                Compensating,
                RolledBack,
            ]
        );
    }

    #[tokio::test]
    async fn already_exists_mid_roster_fails_the_group_without_deleting_the_foreign_object() {
        let root = TestRoot::new();
        let roster = roster_of(&[Kind::Sa, Kind::Policy, Kind::Sa]);
        let backend = ScriptedBackend::for_roster(&roster);
        // A foreign object exists at member one's identity but both pre-effect
        // readbacks report it absent, so the install itself is what discovers
        // the collision.
        backend.plant(roster.member(1).unwrap().request()).await;
        backend.fail_query(1, 0, XfrmError::NotFound);
        backend.fail_query(1, 1, XfrmError::NotFound);
        let store = open_store(&root);

        let outcome = run_roster(&store, group(0x24), generation(1), &roster, &backend)
            .await
            .unwrap();
        assert_eq!(outcome.as_str(), "rolled_back");
        assert_eq!(outcome.failed_member(), Some(1));
        assert!(matches!(outcome.source(), Some(XfrmError::AlreadyExists)));
        assert_eq!(member_phase(&outcome, 1), "no_mutation");
        assert_eq!(
            outcome.members().member(1).unwrap().adjacent_proof(),
            Some("absent_then_already_exists")
        );
        assert!(outcome.members().member(1).unwrap().is_conflicting());
        // The foreign object is never an argument to a delete.
        assert_eq!(backend.ordinals(OpKind::Remove), vec![0]);
        assert!(
            backend
                .is_present(roster.member(1).unwrap().request())
                .await
        );
        assert!(
            !backend
                .is_present(roster.member(0).unwrap().request())
                .await
        );
    }

    #[tokio::test]
    async fn member_zero_conflict_before_any_effect_is_terminal_no_mutation() {
        let root = TestRoot::new();
        let roster = roster_of(&[Kind::Sa, Kind::Policy, Kind::Sa]);
        let backend = ScriptedBackend::for_roster(&roster);
        // The object appears between the group sweep and member zero's own
        // adjacent witness.
        backend.plant(roster.member(0).unwrap().request()).await;
        backend.fail_query(0, 0, XfrmError::NotFound);
        let store = open_store(&root);

        let outcome = run_roster(&store, group(0x25), generation(1), &roster, &backend)
            .await
            .unwrap();
        assert_eq!(outcome.as_str(), "no_mutation");
        assert_eq!(backend.effects(), 0);
        assert_eq!(member_phase(&outcome, 0), "no_mutation");
        assert_eq!(
            outcome.members().member(0).unwrap().adjacent_proof(),
            Some("conflict")
        );
        assert!(outcome.members().has_conflict());
        assert_eq!(
            store.inspect(outcome.handle()).unwrap(),
            XfrmObjectRosterDurablePhase::NoMutation
        );
        assert!(
            backend
                .is_present(roster.member(0).unwrap().request())
                .await
        );
    }

    #[tokio::test]
    async fn any_sweep_conflict_aborts_the_group_with_zero_backend_effects() {
        for conflicted in [0, 3, 4] {
            let root = TestRoot::new();
            let roster = roster_of(&CHILD_SA_ROSTER);
            let backend = ScriptedBackend::for_roster(&roster);
            backend
                .plant(roster.member(conflicted).unwrap().request())
                .await;
            backend.clear_log();
            let store = open_store(&root);

            let outcome = run_roster(&store, group(0x26), generation(1), &roster, &backend)
                .await
                .unwrap();
            assert_eq!(outcome.as_str(), "no_mutation");
            // The sweep is read-only and the group never reaches an effect.
            assert_eq!(backend.effects(), 0);
            assert_eq!(backend.ordinals(OpKind::Query), vec![0, 1, 2, 3, 4]);
            for ordinal in 0..CHILD_SA_ROSTER.len() {
                let disposition = outcome.members().member(ordinal).unwrap();
                assert_eq!(disposition.phase(), "pending");
                assert_eq!(disposition.adjacent_proof(), None);
                if ordinal == conflicted {
                    assert_eq!(disposition.sweep_proof(), Some("conflict"));
                    assert!(disposition.is_conflicting());
                } else {
                    assert_eq!(disposition.sweep_proof(), Some("absent"));
                    assert!(!disposition.is_conflicting());
                }
            }

            // After restart the conflicting object is still left untouched.
            drop(store);
            backend.clear_log();
            let reopened = open_store(&root);
            let recovered = recover_durable_object_roster(
                &reopened,
                group(0x26),
                generation(1),
                &roster,
                &backend,
            )
            .await
            .unwrap();
            assert_eq!(recovered.as_str(), "foreign_untouched");
            assert_eq!(backend.effects(), 0);
            assert!(
                backend
                    .is_present(roster.member(conflicted).unwrap().request())
                    .await
            );
        }
    }

    #[tokio::test]
    async fn pre_effect_readback_failure_rejects_before_any_durable_change() {
        let root = TestRoot::new();
        let roster = roster_of(&CHILD_SA_ROSTER);
        let backend = ScriptedBackend::for_roster(&roster);
        backend.fail_query(2, 0, XfrmError::Unavailable);
        let store = open_store(&root);

        let error = run_roster(&store, group(0x27), generation(1), &roster, &backend)
            .await
            .unwrap_err();
        assert!(error.is_proved_clean());
        assert_eq!(
            error.as_str(),
            "xfrm_object_roster_issue_pre_effect_readback"
        );
        assert_eq!(backend.effects(), 0);
        // The prepared record is untouched, so the authority can be retried.
        assert!(!store.has_unresolved_writer_authority().unwrap());
    }

    #[tokio::test]
    async fn compensation_delete_failure_retains_authority_and_recovers() {
        for failed in 1..CHILD_SA_ROSTER.len() {
            let root = TestRoot::new();
            let roster = roster_of(&CHILD_SA_ROSTER);
            let backend = ScriptedBackend::for_roster(&roster);
            backend.fail_install(failed, XfrmError::Unavailable);
            backend.fail_remove(failed - 1, XfrmError::Unavailable);
            let store = open_store(&root);

            let outcome = run_roster(&store, group(0x31), generation(1), &roster, &backend)
                .await
                .unwrap();
            assert_eq!(outcome.as_str(), "indeterminate");
            assert!(matches!(outcome.source(), Some(XfrmError::Unavailable)));
            assert_eq!(member_phase(&outcome, failed - 1), "removal_admitted");
            // Durable removal authority is retained and keeps the gate closed.
            assert_eq!(
                store.advance_writer_epoch(),
                Err(XfrmObjectRosterDurableError::InvalidTransition)
            );
            drop(store);

            backend.clear_faults();
            backend.clear_log();
            let reopened = open_store(&root);
            let recovered = recover_durable_object_roster(
                &reopened,
                group(0x31),
                generation(1),
                &roster,
                &backend,
            )
            .await
            .unwrap();
            assert_eq!(recovered.as_str(), "rolled_back");
            assert_eq!(backend.ordinals(OpKind::Remove), descending(failed));
            for ordinal in 0..CHILD_SA_ROSTER.len() {
                assert!(
                    !backend
                        .is_present(roster.member(ordinal).unwrap().request())
                        .await
                );
            }
            assert!(reopened.advance_writer_epoch().is_ok());
        }
    }

    #[tokio::test]
    async fn reconcile_readback_failure_never_descends_past_the_unresolved_member() {
        for failed in 0..CHILD_SA_ROSTER.len() {
            let root = TestRoot::new();
            let roster = roster_of(&CHILD_SA_ROSTER);
            let backend = ScriptedBackend::for_roster(&roster);
            backend.fail_install(failed, XfrmError::Unavailable);
            // The sweep and adjacent witnesses succeed; the reconcile readback
            // that follows the failed install does not.
            backend.fail_query(failed, 2, XfrmError::Unavailable);
            let store = open_store(&root);

            let outcome = run_roster(&store, group(0x32), generation(1), &roster, &backend)
                .await
                .unwrap();
            assert_eq!(outcome.as_str(), "indeterminate");
            assert_eq!(member_phase(&outcome, failed), "indeterminate");
            // Compensation never descends past an unresolved member.
            assert!(backend.ordinals(OpKind::Remove).is_empty());
            assert_eq!(
                store.advance_writer_epoch(),
                Err(XfrmObjectRosterDurableError::InvalidTransition)
            );
            drop(store);

            backend.clear_faults();
            backend.clear_log();
            let reopened = open_store(&root);
            let recovered = recover_durable_object_roster(
                &reopened,
                group(0x32),
                generation(1),
                &roster,
                &backend,
            )
            .await
            .unwrap();
            assert_eq!(recovered.as_str(), "rolled_back");
            assert_eq!(backend.ordinals(OpKind::Remove), descending(failed));
            assert!(reopened.advance_writer_epoch().is_ok());
        }
    }

    #[tokio::test]
    async fn restart_verdict_matrix_for_issuing_cuts() {
        // Section 8 Issuing row x member index x object kind, with the member's
        // effect both admitted and denied.
        for kinds in [
            [Kind::Sa; 3],
            [Kind::Policy; 3],
            [Kind::Sa, Kind::Policy, Kind::Sa],
        ] {
            for ordinal in 0..3 {
                for admit in [false, true] {
                    let root = TestRoot::new();
                    let roster = roster_of(&kinds);
                    let backend = ScriptedBackend::for_roster(&roster);
                    let store = open_store(&root);
                    let prepared =
                        prepare_object_roster(&store, group(0x41), generation(1), &roster).unwrap();
                    cut_durable_object_roster_at_issuing_member(
                        &store,
                        &prepared,
                        group(0x41),
                        generation(1),
                        &roster,
                        &backend,
                        ordinal,
                        admit,
                    )
                    .await
                    .unwrap();
                    drop(store);

                    backend.clear_log();
                    let reopened = open_store(&root);
                    let recovered = recover_durable_object_roster(
                        &reopened,
                        group(0x41),
                        generation(1),
                        &roster,
                        &backend,
                    )
                    .await
                    .unwrap_or_else(|error| {
                        panic!("kinds {kinds:?} ordinal {ordinal} admit {admit}: {error:?}")
                    });
                    assert_eq!(
                        recovered.as_str(),
                        "rolled_back",
                        "kinds {kinds:?} ordinal {ordinal} admit {admit}"
                    );
                    let expected = if admit {
                        (0..=ordinal).rev().collect::<Vec<_>>()
                    } else {
                        descending(ordinal)
                    };
                    assert_eq!(backend.ordinals(OpKind::Remove), expected);
                    for member in 0..3 {
                        assert!(
                            !backend
                                .is_present(roster.member(member).unwrap().request())
                                .await
                        );
                    }
                    // Recovery is idempotent and the gate reopens.
                    assert_eq!(
                        recover_durable_object_roster(
                            &reopened,
                            group(0x41),
                            generation(1),
                            &roster,
                            &backend,
                        )
                        .await
                        .unwrap()
                        .as_str(),
                        "retired"
                    );
                    assert!(reopened.advance_writer_epoch().is_ok());
                }
            }
        }
    }

    #[tokio::test]
    async fn applied_roster_recovers_as_owned_residue_and_adopts_when_converged() {
        for adopt in [false, true] {
            let root = TestRoot::new();
            let roster = roster_of(&CHILD_SA_ROSTER);
            let backend = ScriptedBackend::for_roster(&roster);
            let store = open_store(&root);
            let prepared =
                prepare_object_roster(&store, group(0x51), generation(1), &roster).unwrap();
            cut_durable_object_roster_at_applied(
                &store,
                &prepared,
                group(0x51),
                generation(1),
                &roster,
                &backend,
            )
            .await
            .unwrap();
            drop(store);

            backend.clear_log();
            let reopened = open_store(&root);
            if adopt {
                let adopted = adopt_durable_object_roster(
                    &reopened,
                    group(0x51),
                    generation(1),
                    &roster,
                    &backend,
                )
                .await
                .unwrap();
                assert_eq!(adopted.as_str(), "adopted");
                assert!(backend.ordinals(OpKind::Remove).is_empty());
                for ordinal in 0..CHILD_SA_ROSTER.len() {
                    assert_eq!(
                        adopted.members().member(ordinal).unwrap().phase(),
                        "acquired"
                    );
                    assert!(
                        backend
                            .is_present(roster.member(ordinal).unwrap().request())
                            .await
                    );
                }
                // Cleanup authority is surrendered: recovery must never delete.
                assert_eq!(
                    recover_durable_object_roster(
                        &reopened,
                        group(0x51),
                        generation(1),
                        &roster,
                        &backend,
                    )
                    .await
                    .unwrap()
                    .as_str(),
                    "committed"
                );
                assert!(backend.ordinals(OpKind::Remove).is_empty());
            } else {
                let recovered = recover_durable_object_roster(
                    &reopened,
                    group(0x51),
                    generation(1),
                    &roster,
                    &backend,
                )
                .await
                .unwrap();
                assert_eq!(recovered.as_str(), "owned_residue_retired");
                assert_eq!(backend.ordinals(OpKind::Remove), descending(5));
                for ordinal in 0..CHILD_SA_ROSTER.len() {
                    assert!(
                        !backend
                            .is_present(roster.member(ordinal).unwrap().request())
                            .await
                    );
                }
                assert_eq!(
                    recover_durable_object_roster(
                        &reopened,
                        group(0x51),
                        generation(1),
                        &roster,
                        &backend,
                    )
                    .await
                    .unwrap()
                    .as_str(),
                    "retired"
                );
            }
        }
    }

    #[tokio::test]
    async fn adoption_is_refused_when_a_member_is_no_longer_present() {
        for absent in [0, 2, 4] {
            let root = TestRoot::new();
            let roster = roster_of(&CHILD_SA_ROSTER);
            let backend = ScriptedBackend::for_roster(&roster);
            let store = open_store(&root);
            let prepared =
                prepare_object_roster(&store, group(0x52), generation(1), &roster).unwrap();
            cut_durable_object_roster_at_applied(
                &store,
                &prepared,
                group(0x52),
                generation(1),
                &roster,
                &backend,
            )
            .await
            .unwrap();
            drop(store);

            // The group no longer converges: one leg vanished out of band.
            backend
                .retire(roster.member(absent).unwrap().request())
                .await;
            backend.clear_log();
            let reopened = open_store(&root);
            let refused = adopt_durable_object_roster(
                &reopened,
                group(0x52),
                generation(1),
                &roster,
                &backend,
            )
            .await
            .unwrap();
            assert_eq!(refused.as_str(), "adoption_refused");
            // Nothing destructive was published and the record stays applied.
            assert!(backend.ordinals(OpKind::Remove).is_empty());
            assert!(reopened.has_unresolved_writer_authority().unwrap());

            // The consumer may still choose recovery.
            let recovered = recover_durable_object_roster(
                &reopened,
                group(0x52),
                generation(1),
                &roster,
                &backend,
            )
            .await
            .unwrap();
            assert_eq!(recovered.as_str(), "owned_residue_retired");
            assert!(reopened.advance_writer_epoch().is_ok());
        }
    }

    #[tokio::test]
    async fn compensating_cut_resumes_strict_descending_compensation() {
        for admit in [false, true] {
            for cut_at in [0, 2, 4] {
                let root = TestRoot::new();
                let roster = roster_of(&CHILD_SA_ROSTER);
                let backend = ScriptedBackend::for_roster(&roster);
                let store = open_store(&root);
                let prepared =
                    prepare_object_roster(&store, group(0x53), generation(1), &roster).unwrap();
                cut_durable_object_roster_at_applied(
                    &store,
                    &prepared,
                    group(0x53),
                    generation(1),
                    &roster,
                    &backend,
                )
                .await
                .unwrap();
                backend.clear_log();
                cut_durable_object_roster_at_compensating_member(
                    &store,
                    group(0x53),
                    generation(1),
                    &roster,
                    &backend,
                    cut_at,
                    admit,
                )
                .await
                .unwrap();
                let removed_before = backend.ordinals(OpKind::Remove);
                let expected_before = if admit {
                    (cut_at..5).rev().collect::<Vec<_>>()
                } else {
                    (cut_at + 1..5).rev().collect::<Vec<_>>()
                };
                assert_eq!(removed_before, expected_before);
                drop(store);

                backend.clear_log();
                let reopened = open_store(&root);
                let recovered = recover_durable_object_roster(
                    &reopened,
                    group(0x53),
                    generation(1),
                    &roster,
                    &backend,
                )
                .await
                .unwrap();
                assert_eq!(recovered.as_str(), "rolled_back");
                assert_eq!(
                    backend.ordinals(OpKind::Remove),
                    (0..=cut_at).rev().collect::<Vec<_>>()
                );
                for ordinal in 0..CHILD_SA_ROSTER.len() {
                    assert!(
                        !backend
                            .is_present(roster.member(ordinal).unwrap().request())
                            .await
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn a_stale_epoch_under_an_unresolved_roster_requires_repair() {
        let root = TestRoot::new();
        let roster = roster_of(&[Kind::Sa, Kind::Policy, Kind::Sa]);
        let backend = ScriptedBackend::for_roster(&roster);
        let store = open_store(&root);
        let prepared = prepare_object_roster(&store, group(0x61), generation(1), &roster).unwrap();
        cut_durable_object_roster_at_issuing_member(
            &store,
            &prepared,
            group(0x61),
            generation(1),
            &roster,
            &backend,
            1,
            true,
        )
        .await
        .unwrap();

        // An out-of-band mutation burns the writer epoch underneath the
        // unresolved roster, which is exactly what recovering after an
        // intervening namespace mutation looks like.
        store.tests_force_advance_writer_epoch().unwrap();
        backend.clear_log();
        let recovered =
            recover_durable_object_roster(&store, group(0x61), generation(1), &roster, &backend)
                .await
                .unwrap();
        assert_eq!(recovered.as_str(), "repair_required");
        // Nothing was deleted, the record is retained, and the gate stays shut.
        assert!(backend.ordinals(OpKind::Remove).is_empty());
        assert!(
            backend
                .is_present(roster.member(0).unwrap().request())
                .await
        );
        assert!(
            backend
                .is_present(roster.member(1).unwrap().request())
                .await
        );
        assert!(store.has_unresolved_writer_authority().unwrap());
        assert_eq!(
            store.advance_writer_epoch(),
            Err(XfrmObjectRosterDurableError::InvalidTransition)
        );
    }

    #[tokio::test]
    async fn homogeneous_and_mixed_rosters_apply_and_compensate_alike() {
        for kinds in [[Kind::Sa; 5], [Kind::Policy; 5], CHILD_SA_ROSTER] {
            let root = TestRoot::new();
            let roster = roster_of(&kinds);
            let backend = ScriptedBackend::for_roster(&roster);
            let store = open_store(&root);

            let outcome = run_roster(&store, group(0x71), generation(1), &roster, &backend)
                .await
                .unwrap();
            assert_eq!(outcome.as_str(), "applied");
            assert_eq!(backend.ordinals(OpKind::Install), vec![0, 1, 2, 3, 4]);
            assert_eq!(
                finalize_durable_object_roster(&store, group(0x71), generation(1), &roster)
                    .unwrap(),
                XfrmObjectRosterDurablePhase::Committed
            );

            // The same declared order compensates in reverse after a failure.
            let second = roster_of(&kinds);
            let backend = ScriptedBackend::for_roster(&second);
            backend.fail_install(3, XfrmError::Unavailable);
            let outcome = run_roster(&store, group(0x72), generation(1), &second, &backend)
                .await
                .unwrap();
            assert_eq!(outcome.as_str(), "rolled_back");
            assert_eq!(backend.ordinals(OpKind::Remove), vec![2, 1, 0]);
        }
    }

    #[tokio::test]
    async fn a_successful_roster_retains_no_durable_entries() {
        let root = TestRoot::new();
        let roster = roster_of(&CHILD_SA_ROSTER);
        let backend = ScriptedBackend::for_roster(&roster);
        let store = open_store(&root);

        let outcome = run_roster(&store, group(0x81), generation(1), &roster, &backend)
            .await
            .unwrap();
        assert_eq!(outcome.as_str(), "applied");
        assert_eq!(
            finalize_durable_object_roster(&store, group(0x81), generation(1), &roster).unwrap(),
            XfrmObjectRosterDurablePhase::Committed
        );
        assert_eq!(root.record_files(), 1);
        // The committed record is pruned at the next epoch advance.
        assert!(store.advance_writer_epoch().is_ok());
        assert_eq!(root.record_files(), 0);

        // A partial roster retains exactly one group record until it resolves.
        let partial = roster_of(&CHILD_SA_ROSTER);
        let backend = ScriptedBackend::for_roster(&partial);
        backend.fail_install(2, XfrmError::Unavailable);
        backend.fail_remove(1, XfrmError::Unavailable);
        assert_eq!(
            run_roster(&store, group(0x82), generation(1), &partial, &backend)
                .await
                .unwrap()
                .as_str(),
            "indeterminate"
        );
        assert_eq!(root.record_files(), 1);
        backend.clear_faults();
        assert_eq!(
            recover_durable_object_roster(&store, group(0x82), generation(1), &partial, &backend)
                .await
                .unwrap()
                .as_str(),
            "rolled_back"
        );
        assert!(store.advance_writer_epoch().is_ok());
        assert_eq!(root.record_files(), 0);
    }

    /// Synthetic barrier charged once per consumer-visible durable boundary.
    struct BarrierMeter {
        charged: Cell<usize>,
    }

    impl BarrierMeter {
        fn new() -> Self {
            Self {
                charged: Cell::new(0),
            }
        }

        fn boundary(&self) {
            self.charged.set(self.charged.get() + BARRIER_COST);
        }

        fn total(&self) -> usize {
            self.charged.get()
        }
    }

    #[tokio::test]
    async fn one_roster_lifecycle_replaces_the_serial_single_object_baseline() {
        for arity in [1, 2, 5, 8] {
            let kinds = vec![Kind::Sa; arity];

            // Roster: three consumer-visible durable boundaries and one epoch
            // burn, independent of arity.
            let roster_root = TestRoot::new();
            let roster = roster_of(&kinds);
            let backend = ScriptedBackend::for_roster(&roster);
            let store = open_store(&roster_root);
            let meter = BarrierMeter::new();
            let before = store.advance_writer_epoch().unwrap().get();
            meter.boundary();
            let prepared =
                prepare_object_roster(&store, group(0x91), generation(1), &roster).unwrap();
            meter.boundary();
            let outcome = issue_durable_object_roster(
                &store,
                &prepared,
                group(0x91),
                generation(1),
                &roster,
                &backend,
            )
            .await
            .unwrap();
            assert_eq!(outcome.as_str(), "applied");
            meter.boundary();
            assert_eq!(
                finalize_durable_object_roster(&store, group(0x91), generation(1), &roster)
                    .unwrap(),
                XfrmObjectRosterDurablePhase::Committed
            );
            let after = store.advance_writer_epoch().unwrap().get();
            let roster_boundaries = meter.total();
            let roster_burns = after - before - 1;
            // One prepare-class and one finalize-class publication regardless
            // of how many members the group carries.
            assert_eq!(
                class_count(&store, XfrmObjectRosterPublicationClass::Prepare),
                1
            );
            assert_eq!(
                class_count(&store, XfrmObjectRosterPublicationClass::Finalize),
                1
            );
            assert_eq!(roster_boundaries, 3 * BARRIER_COST);
            assert_eq!(roster_burns, 1);

            // Baseline: the same objects through the serial single-object
            // durable API, driven for real in the same test.
            let object_root = TestRoot::new();
            let object_store = open_object_store(&object_root);
            let object_backend = MockXfrmBackend::new();
            let baseline = BarrierMeter::new();
            let before = object_store.advance_writer_epoch().unwrap().get();
            for index in 0..arity {
                let request = sa_request(index);
                let operation =
                    XfrmObjectInstallOperationId::from_bytes([octet(index) + 1; 16]).unwrap();
                let object_generation = XfrmObjectInstallOperationGeneration::new(1).unwrap();
                baseline.boundary();
                let prepared = prepare_durable_object_install(
                    &object_store,
                    operation,
                    object_generation,
                    &request,
                )
                .unwrap();
                let proof = if readback_object_present(&object_backend, &request)
                    .await
                    .unwrap()
                {
                    XfrmObjectInstallPreEffectProof::Conflict
                } else {
                    XfrmObjectInstallPreEffectProof::Absent
                };
                baseline.boundary();
                assert_eq!(
                    issue_durable_object_install(
                        &object_store,
                        &prepared,
                        operation,
                        object_generation,
                        &request,
                        &object_backend,
                        proof,
                    )
                    .await
                    .unwrap()
                    .as_str(),
                    "acquired"
                );
                baseline.boundary();
                assert_eq!(
                    finalize_durable_object_install(
                        &object_store,
                        operation,
                        object_generation,
                        &request,
                    )
                    .unwrap(),
                    XfrmObjectInstallDurablePhase::Committed
                );
            }
            let after = object_store.advance_writer_epoch().unwrap().get();
            let baseline_boundaries = baseline.total();
            let baseline_burns = after - before - 1;

            assert_eq!(baseline_boundaries, 3 * arity * BARRIER_COST);
            assert_eq!(baseline_burns, u64::try_from(arity).unwrap());
            if arity == 5 {
                assert_eq!(roster_boundaries, 3 * BARRIER_COST);
                assert_eq!(baseline_boundaries, 15 * BARRIER_COST);
            }
        }
    }

    #[tokio::test]
    async fn mock_backend_runs_a_complete_roster_lifecycle() {
        let root = TestRoot::new();
        let roster = roster_of(&CHILD_SA_ROSTER);
        let backend = MockXfrmBackend::new();
        let store = open_store(&root);

        let outcome = run_roster(&store, group(0xa1), generation(1), &roster, &backend)
            .await
            .unwrap();
        assert_eq!(outcome.as_str(), "applied");
        for ordinal in 0..CHILD_SA_ROSTER.len() {
            assert!(matches!(
                install(&backend, roster.member(ordinal).unwrap().request()).await,
                Err(XfrmError::AlreadyExists)
            ));
        }
        assert_eq!(
            finalize_durable_object_roster(&store, group(0xa1), generation(1), &roster).unwrap(),
            XfrmObjectRosterDurablePhase::Committed
        );
        assert_eq!(
            recover_durable_object_roster(&store, group(0xa1), generation(1), &roster, &backend)
                .await
                .unwrap()
                .as_str(),
            "committed"
        );
    }

    #[tokio::test]
    async fn roster_diagnostics_are_value_free() {
        let root = TestRoot::new();
        let roster = roster_of(&CHILD_SA_ROSTER);
        let backend = ScriptedBackend::for_roster(&roster);
        backend.fail_install(2, XfrmError::Unavailable);
        let store = open_store(&root);
        let outcome = run_roster(&store, group(0xb1), generation(1), &roster, &backend)
            .await
            .unwrap();
        let recovered =
            recover_durable_object_roster(&store, group(0xb1), generation(1), &roster, &backend)
                .await
                .unwrap();
        let issue_error = XfrmObjectRosterIssueError::PreEffectReadbackFailed(XfrmError::NotFound);
        let member = XfrmObjectRosterMemberRequest::new(sa_request(0));

        let mut rendered = vec![
            format!("{outcome:?}"),
            format!("{recovered:?}"),
            format!("{issue_error:?}"),
            format!("{issue_error}"),
            format!("{roster:?}"),
            format!("{member:?}"),
            format!("{:?}", outcome.members()),
            format!("{:?}", outcome.members().member(0).unwrap()),
        ];
        for error in [
            XfrmObjectRosterRequestError::EmptyRoster,
            XfrmObjectRosterRequestError::TooManyMembers,
            XfrmObjectRosterRequestError::NonExactRemovalIdentity,
            XfrmObjectRosterRequestError::DuplicateDeletionIdentity,
            XfrmObjectRosterRequestError::AmbiguousKernelSelection,
            XfrmObjectRosterRequestError::MalformedMemberIdentity,
        ] {
            rendered.push(format!("{error:?}"));
            rendered.push(format!("{error}"));
            assert!(!error.as_str().is_empty());
        }

        for text in rendered {
            for forbidden in [
                "198",
                "10.67",
                "6160",
                "1633058817",
                "600",
                "616",
                "Ipv4",
                "Tunnel",
                "selector",
                "KeyMaterial",
            ] {
                assert!(
                    !text.contains(forbidden),
                    "diagnostic leaked {forbidden}: {text}"
                );
            }
        }
    }
}
