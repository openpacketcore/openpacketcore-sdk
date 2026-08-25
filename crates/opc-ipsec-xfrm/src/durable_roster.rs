//! Durable, authenticated authority records for grouped XFRM object rosters.
//!
//! A consumer that installs one IKEv2 Child SA must apply several
//! dependency-ordered XFRM objects. This module persists that whole ordered
//! group as ONE fixed-size authenticated record so the group has a single
//! durable admission, a single writer-epoch burn, and a single crash-recovery
//! verdict.
//!
//! Like the single-object and SA-relocation families, this module stores only
//! opaque correlation values and keyed fingerprints. It never serializes an
//! XFRM request, key material, packet mark, SPI, selector, or address. A
//! decoded record is correlation data, not cleanup authority: callers must
//! validate it through [`XfrmObjectRosterRecoveryStore`] while holding that
//! store's permanent cross-process lease.
//!
//! The family is deliberately self-contained: its own store root, proof-key
//! newtype, record/control/epoch magics, and HMAC domains. The domain
//! divergence from the single-object family is load-bearing, not cosmetic. A
//! deployment may configure the same 32 secret bytes for every family, and the
//! domain separator is then the only thing preventing cross-family fingerprint
//! confusion. The canonical request encoders themselves are shared with
//! [`crate::durable_object`] so both families pin the same bytes-on-the-wire
//! definition of "the same request".

#[cfg(target_os = "linux")]
use std::io::Write;
use std::{
    collections::BTreeMap,
    error::Error,
    ffi::OsStr,
    fmt,
    io::{self, Read, Seek, SeekFrom},
    num::NonZeroU64,
    os::{
        fd::{AsFd, OwnedFd},
        unix::{ffi::OsStrExt, fs::DirBuilderExt},
    },
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard, TryLockError},
};

use rand::{rngs::SysRng, TryRng};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use rustix::fs::{
    flock, fstat, fsync, open, openat, unlinkat, AtFlags, Dir, FileType, FlockOperation, Mode,
    OFlags,
};
#[cfg(target_os = "linux")]
use rustix::fs::{renameat_with, RenameFlags};

use crate::durable_object::{
    authenticate_deletion_identity, authenticate_domain, authenticate_install_request, mac_bytes,
    mac_u64, mac_u8, verify_authentication_domain, CanonicalEncodeError, CanonicalMacKey,
};
use crate::model::validate_exact_lookup_mark;
use crate::{XfrmInstallObject, XfrmObjectInstallRequest};

/// Largest number of members one durable roster may carry.
///
/// This is a WIRE-FORMAT bound, not a tuning knob. The durable record reserves
/// exactly this many fixed-size member slots, so raising it changes
/// [`XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES`] and is a format break with no
/// compatibility path.
pub const XFRM_OBJECT_ROSTER_MAX_MEMBERS: usize = 8;

/// Exact byte length of a persisted roster recovery handle and durable record.
///
/// One roster handle is smaller than the five single-object handles it
/// replaces for a Child-SA install (944 against 5 x 208 = 1040).
pub const XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES: usize = 944;

const AUTH_TAG_BYTES: usize = 32;
const MEMBER_SLOT_BYTES: usize = 96;
const MEMBER_SLOTS_OFFSET: usize = 144;
const RECORD_BODY_BYTES: usize =
    MEMBER_SLOTS_OFFSET + XFRM_OBJECT_ROSTER_MAX_MEMBERS * MEMBER_SLOT_BYTES;
const RECORD_MAGIC: [u8; 8] = *b"OPCXROS1";
const RECORD_VERSION: u16 = 1;
const RECORD_AUTH_DOMAIN: &[u8] = b"opc-xfrm-roster-record-v1\0";
const MEMBERS_AUTH_DOMAIN: &[u8] = b"opc-xfrm-roster-members-v1\0";
const MEMBER_ID_AUTH_DOMAIN: &[u8] = b"opc-xfrm-roster-member-id-v1\0";
const INSTALL_REQUEST_AUTH_DOMAIN: &[u8] = b"opc-xfrm-roster-install-request-v1\0";
const DELETION_IDENTITY_AUTH_DOMAIN: &[u8] = b"opc-xfrm-roster-deletion-identity-v1\0";
const NAMESPACE_AUTH_DOMAIN: &[u8] = b"opc-xfrm-roster-namespace-v1\0";
const CONTROL_BYTES: usize = 128;
const CONTROL_BODY_BYTES: usize = CONTROL_BYTES - AUTH_TAG_BYTES;
// Family-distinct control/epoch magics: an open against another durable
// family's root must fail control-record validation, never adopt it.
const CONTROL_MAGIC: [u8; 8] = *b"OPCXRSC1";
const CONTROL_AUTH_DOMAIN: &[u8] = b"opc-xfrm-roster-control-v1\0";
const CONTROL_NAME: &str = "control";
// Fresh roster stores retain the logically ordered state-machine records in
// one descriptor-anchored append journal.  One frame is still authenticated
// and complete on its own; the journal only removes the directory-sync and
// predecessor-unlink barriers from every state transition.
const JOURNAL_NAME: &str = "journal";
const MAX_JOURNAL_FRAMES: usize = 256;
const JOURNAL_HEADER_BYTES: usize = EPOCH_BYTES;
const MAX_JOURNAL_BYTES: usize =
    JOURNAL_HEADER_BYTES + MAX_JOURNAL_FRAMES * XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES;
const TEMPORARY_PREFIX: &str = ".opc-xfrm-roster-pending-";
const EPOCH_BYTES: usize = 80;
const EPOCH_BODY_BYTES: usize = EPOCH_BYTES - AUTH_TAG_BYTES;
const EPOCH_MAGIC: [u8; 8] = *b"OPCXRSE1";
const EPOCH_AUTH_DOMAIN: &[u8] = b"opc-xfrm-roster-epoch-v1\0";
const MAX_STORE_ENTRIES: usize = 64;
// One control record plus at most two consecutive epoch witnesses are reserved,
// and one roster occupies at most two files inside its publication window, so
// the active-record bound is half the remaining entry budget.
const MAX_ACTIVE_RECORDS: usize = (MAX_STORE_ENTRIES - 3) / 2;
const MAX_STORE_PATH_BYTES: usize = 4096;
const FILE_MODE: u32 = 0o600;
const DIRECTORY_MODE: u32 = 0o700;
const CREATE_ATTEMPTS: usize = 8;

/// Secret proof key used to authenticate durable roster recovery state.
///
/// The key is supplied by the product's durable secret configuration and must
/// remain stable across a process restart. `Debug` and `Display` are redacted,
/// and the bytes are zeroized when the value is dropped.
pub struct XfrmObjectRosterRecoveryProofKey([u8; AUTH_TAG_BYTES]);

impl XfrmObjectRosterRecoveryProofKey {
    /// Construct a proof key from exactly 256 bits of secret material.
    ///
    /// An all-zero key is rejected so an omitted secret cannot silently create
    /// forgeable recovery authority.
    ///
    /// # Errors
    ///
    /// Returns [`XfrmObjectRosterDurableError::InvalidProofKey`] for the
    /// reserved all-zero value.
    pub fn new(bytes: [u8; AUTH_TAG_BYTES]) -> Result<Self, XfrmObjectRosterDurableError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(XfrmObjectRosterDurableError::InvalidProofKey);
        }
        Ok(Self(bytes))
    }

    /// Borrow this key for the shared canonical encoders.
    pub(crate) const fn canonical_mac_key(&self) -> CanonicalMacKey<'_> {
        CanonicalMacKey::new(&self.0)
    }
}

impl Clone for XfrmObjectRosterRecoveryProofKey {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl Drop for XfrmObjectRosterRecoveryProofKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for XfrmObjectRosterRecoveryProofKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("XfrmObjectRosterRecoveryProofKey(<redacted>)")
    }
}

impl fmt::Display for XfrmObjectRosterRecoveryProofKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

/// Opaque, randomly generated identity of one durable roster transaction.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct XfrmObjectRosterGroupId([u8; 16]);

impl XfrmObjectRosterGroupId {
    /// Generate a nonzero group identity using the operating system RNG.
    ///
    /// # Errors
    ///
    /// Returns [`XfrmObjectRosterDurableError::EntropyUnavailable`] when the
    /// operating-system random source is unavailable.
    pub fn generate() -> Result<Self, XfrmObjectRosterDurableError> {
        let mut bytes = [0_u8; 16];
        SysRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| XfrmObjectRosterDurableError::EntropyUnavailable)?;
        Self::from_bytes(bytes)
    }

    /// Decode an opaque group identity, rejecting the reserved zero value.
    ///
    /// # Errors
    ///
    /// Returns [`XfrmObjectRosterDurableError::Malformed`] for the reserved
    /// all-zero value.
    pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, XfrmObjectRosterDurableError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(XfrmObjectRosterDurableError::Malformed);
        }
        Ok(Self(bytes))
    }

    /// Return the opaque correlation bytes for durable application storage.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0
    }
}

impl fmt::Debug for XfrmObjectRosterGroupId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("XfrmObjectRosterGroupId(<redacted>)")
    }
}

impl fmt::Display for XfrmObjectRosterGroupId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

/// Nonzero product generation for one durable roster transaction.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct XfrmObjectRosterOperationGeneration(NonZeroU64);

impl XfrmObjectRosterOperationGeneration {
    /// Construct a nonzero roster generation.
    #[must_use]
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Return the generation value for durable correlation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Borrow the nonzero value the newtype already guarantees.
    pub(crate) const fn nonzero(self) -> NonZeroU64 {
        self.0
    }
}

impl fmt::Debug for XfrmObjectRosterOperationGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("XfrmObjectRosterOperationGeneration(<redacted>)")
    }
}

impl fmt::Display for XfrmObjectRosterOperationGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

/// Durable state of one grouped roster transaction.
///
/// The group carries no `Indeterminate` phase. Individual member slots do: an
/// unresolved member is a property of that member, and lifting it to the group
/// would make the publication successor relation cyclic.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XfrmObjectRosterDurablePhase {
    /// Intent is durable and no backend mutation has been admitted.
    ///
    /// A prepared roster has zero effects and recovers as authoritative
    /// no-mutation, so unlike an SA relocation it does not fence cooperating
    /// writers.
    Prepared,
    /// The writer epoch was advanced and members are being applied in order.
    Issuing,
    /// Every member was acknowledged and the group awaits the consumer's
    /// adoption decision.
    Applied,
    /// A member failed after at least one member was acquired, and the acquired
    /// prefix is being reverse-compensated.
    Compensating,
    /// A pre-effect conflict proved that the group made no mutation at all.
    NoMutation,
    /// Compensation completed and the group left no acquired member behind.
    RolledBack,
    /// The product adopted the group and cleanup authority was surrendered.
    Committed,
    /// Recovery completed and no cleanup authority remains.
    Retired,
}

impl XfrmObjectRosterDurablePhase {
    /// Stable, value-free phase label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Issuing => "issuing",
            Self::Applied => "applied",
            Self::Compensating => "compensating",
            Self::NoMutation => "no_mutation",
            Self::RolledBack => "rolled_back",
            Self::Committed => "committed",
            Self::Retired => "retired",
        }
    }

    const fn code(self) -> u8 {
        match self {
            Self::Prepared => 1,
            Self::Issuing => 2,
            Self::Applied => 3,
            Self::Compensating => 4,
            Self::NoMutation => 5,
            Self::RolledBack => 6,
            Self::Committed => 7,
            Self::Retired => 8,
        }
    }

    fn from_code(code: u8) -> Result<Self, XfrmObjectRosterDurableError> {
        match code {
            1 => Ok(Self::Prepared),
            2 => Ok(Self::Issuing),
            3 => Ok(Self::Applied),
            4 => Ok(Self::Compensating),
            5 => Ok(Self::NoMutation),
            6 => Ok(Self::RolledBack),
            7 => Ok(Self::Committed),
            8 => Ok(Self::Retired),
            _ => Err(XfrmObjectRosterDurableError::Malformed),
        }
    }

    /// Whether this phase may be followed by `next`.
    ///
    /// The relation is a strict DAG apart from the two intra-phase progress
    /// self-edges. Ordering inside a phase is carried by the record's
    /// publication sequence, never by the phase alone.
    ///
    /// `Committed -> Retired` has no writer today: `finalize` reports a
    /// committed roster idempotently and terminal pruning unlinks its record
    /// outright. The edge is kept because retiring a committed roster is the
    /// one direction that can never lose authority — it surrenders cleanup
    /// rights that were already surrendered — so admitting it costs nothing
    /// and refusing it would make a future explicit retire an unpublishable
    /// state rather than a no-op.
    pub(crate) const fn permits(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Prepared, Self::Issuing)
                | (Self::Prepared, Self::Retired)
                | (Self::Issuing, Self::Issuing)
                | (Self::Issuing, Self::Applied)
                | (Self::Issuing, Self::NoMutation)
                | (Self::Issuing, Self::Compensating)
                | (Self::Applied, Self::Committed)
                | (Self::Applied, Self::Compensating)
                | (Self::Compensating, Self::Compensating)
                | (Self::Compensating, Self::RolledBack)
                | (Self::NoMutation, Self::Retired)
                | (Self::RolledBack, Self::Retired)
                | (Self::Committed, Self::Retired)
        )
    }

    /// Whether this phase keeps the namespace-wide writer gate closed.
    ///
    /// `Prepared` is deliberately excluded, matching the single-object family
    /// and diverging from SA relocation: a relocation that reached `Prepared`
    /// has committed to moving live state, whereas a prepared roster has zero
    /// effects and recovers as no-mutation.
    pub(crate) const fn is_unresolved_writer_authority(self) -> bool {
        matches!(self, Self::Issuing | Self::Applied | Self::Compensating)
    }

    const fn is_terminal(self) -> bool {
        matches!(self, Self::Retired | Self::Committed)
    }
}

/// Durable state of one member slot inside a roster record.
///
/// This is the per-member half of a roster verdict: the group phase says what
/// the transaction did, and this says what each declared member ended up
/// owning. It is value-free — no address, selector, SPI, mark, or interface
/// identifier is representable here.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum XfrmObjectRosterMemberPhase {
    /// The member has not been issued.
    Pending,
    /// Linux acknowledged that this roster acquired the member's object.
    Acquired,
    /// The member provably made no mutation.
    NoMutation,
    /// The member's backend result cannot prove ownership or absence.
    Indeterminate,
    /// Recovery authority was validated and fenced before deleting the member.
    RemovalAdmitted,
    /// The member's object was removed and no cleanup authority remains.
    Retired,
}

impl XfrmObjectRosterMemberPhase {
    /// Stable, value-free member phase label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Acquired => "acquired",
            Self::NoMutation => "no_mutation",
            Self::Indeterminate => "indeterminate",
            Self::RemovalAdmitted => "removal_admitted",
            Self::Retired => "retired",
        }
    }

    const fn code(self) -> u8 {
        match self {
            Self::Pending => 1,
            Self::Acquired => 2,
            Self::NoMutation => 3,
            Self::Indeterminate => 4,
            Self::RemovalAdmitted => 5,
            Self::Retired => 6,
        }
    }

    fn from_code(code: u8) -> Result<Self, XfrmObjectRosterDurableError> {
        match code {
            1 => Ok(Self::Pending),
            2 => Ok(Self::Acquired),
            3 => Ok(Self::NoMutation),
            4 => Ok(Self::Indeterminate),
            5 => Ok(Self::RemovalAdmitted),
            6 => Ok(Self::Retired),
            _ => Err(XfrmObjectRosterDurableError::Malformed),
        }
    }

    /// Whether one member slot may advance from this state to `next`.
    const fn permits(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Pending, Self::Acquired)
                | (Self::Pending, Self::NoMutation)
                | (Self::Pending, Self::Indeterminate)
                | (Self::Indeterminate, Self::NoMutation)
                | (Self::Indeterminate, Self::RemovalAdmitted)
                | (Self::Acquired, Self::RemovalAdmitted)
                | (Self::RemovalAdmitted, Self::Retired)
        ) || matches!(
            (self, next),
            (Self::Pending, Self::Pending)
                | (Self::Acquired, Self::Acquired)
                | (Self::NoMutation, Self::NoMutation)
                | (Self::Indeterminate, Self::Indeterminate)
                | (Self::RemovalAdmitted, Self::RemovalAdmitted)
                | (Self::Retired, Self::Retired)
        )
    }
}

impl fmt::Debug for XfrmObjectRosterMemberPhase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("XfrmObjectRosterMemberPhase")
            .field(&self.as_str())
            .finish()
    }
}

/// Durable pre-effect proof witnessed for every member before any effect.
///
/// The sweep runs across all members before the group leaves `Prepared`. Its
/// only job is the all-or-nothing conflict gate. It never authorizes a
/// deletion on its own.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum XfrmObjectRosterSweepProof {
    /// The member's exact deletion identity was absent during the sweep.
    Absent,
    /// The member's exact deletion identity was already present, so the whole
    /// group admits no effect.
    Conflict,
}

impl XfrmObjectRosterSweepProof {
    /// Stable, value-free proof label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Conflict => "conflict",
        }
    }

    const fn code(self) -> u8 {
        match self {
            Self::Absent => 1,
            Self::Conflict => 2,
        }
    }

    fn from_code(code: u8) -> Result<Self, XfrmObjectRosterDurableError> {
        match code {
            1 => Ok(Self::Absent),
            2 => Ok(Self::Conflict),
            _ => Err(XfrmObjectRosterDurableError::Malformed),
        }
    }
}

impl fmt::Debug for XfrmObjectRosterSweepProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("XfrmObjectRosterSweepProof")
            .field(&self.as_str())
            .finish()
    }
}

/// Durable adjacent proof witnessed immediately before one member's effect.
///
/// This is the only proof that can authorize deleting a member: it is
/// published before the member's install is issued, so a fresh readback that
/// finds the object present proves the object is this roster's residue.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum XfrmObjectRosterAdjacentProof {
    /// The member's exact deletion identity was absent immediately before its
    /// effect window opened.
    Absent,
    /// The member's exact deletion identity was already present, so no effect
    /// was admitted for this member.
    Conflict,
    /// The member's install was issued under an absence proof and Linux still
    /// reported that the object exists.
    AbsentThenAlreadyExists,
}

impl XfrmObjectRosterAdjacentProof {
    /// Stable, value-free proof label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Conflict => "conflict",
            Self::AbsentThenAlreadyExists => "absent_then_already_exists",
        }
    }

    const fn code(self) -> u8 {
        match self {
            Self::Absent => 1,
            Self::Conflict => 2,
            Self::AbsentThenAlreadyExists => 3,
        }
    }

    fn from_code(code: u8) -> Result<Self, XfrmObjectRosterDurableError> {
        match code {
            1 => Ok(Self::Absent),
            2 => Ok(Self::Conflict),
            3 => Ok(Self::AbsentThenAlreadyExists),
            _ => Err(XfrmObjectRosterDurableError::Malformed),
        }
    }
}

impl fmt::Debug for XfrmObjectRosterAdjacentProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("XfrmObjectRosterAdjacentProof")
            .field(&self.as_str())
            .finish()
    }
}

/// Opaque identity of one member inside a roster.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct XfrmObjectRosterMemberId([u8; 16]);

impl XfrmObjectRosterMemberId {
    /// Decode an opaque member identity, rejecting the reserved zero value.
    ///
    /// # Errors
    ///
    /// Returns [`XfrmObjectRosterDurableError::Malformed`] for the reserved
    /// all-zero value.
    pub(crate) fn from_bytes(bytes: [u8; 16]) -> Result<Self, XfrmObjectRosterDurableError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(XfrmObjectRosterDurableError::Malformed);
        }
        Ok(Self(bytes))
    }
}

impl fmt::Debug for XfrmObjectRosterMemberId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("XfrmObjectRosterMemberId(<redacted>)")
    }
}

impl fmt::Display for XfrmObjectRosterMemberId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

/// Independent keyed fingerprints of one member's kernel identity and request.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct XfrmObjectRosterMemberFingerprints {
    pub(crate) deletion_identity: [u8; 32],
    pub(crate) install_request: [u8; 32],
}

impl XfrmObjectRosterMemberFingerprints {
    #[cfg(test)]
    pub(crate) fn repeated(byte: u8) -> Self {
        Self {
            deletion_identity: [byte; 32],
            install_request: [byte.wrapping_add(1); 32],
        }
    }
}

impl fmt::Debug for XfrmObjectRosterMemberFingerprints {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("XfrmObjectRosterMemberFingerprints(<redacted>)")
    }
}

/// Complete durable material for one prepared roster member.
///
/// The flow layer builds this from its validated roster request. The store
/// deliberately never sees a request: it stores keyed fingerprints only.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct XfrmObjectRosterMemberMaterial {
    pub(crate) object: XfrmInstallObject,
    pub(crate) member_id: XfrmObjectRosterMemberId,
    pub(crate) member_generation: NonZeroU64,
    pub(crate) fingerprints: XfrmObjectRosterMemberFingerprints,
}

impl fmt::Debug for XfrmObjectRosterMemberMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XfrmObjectRosterMemberMaterial")
            .field("object", &self.object.as_str())
            .finish_non_exhaustive()
    }
}

/// One authenticated member slot inside a durable roster record.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct DurableRosterMemberSlot {
    pub(crate) object: XfrmInstallObject,
    pub(crate) phase: XfrmObjectRosterMemberPhase,
    pub(crate) sweep_proof: Option<XfrmObjectRosterSweepProof>,
    pub(crate) adjacent_proof: Option<XfrmObjectRosterAdjacentProof>,
    pub(crate) member_id: XfrmObjectRosterMemberId,
    pub(crate) member_generation: NonZeroU64,
    pub(crate) deletion_identity_fingerprint: [u8; 32],
    pub(crate) install_request_fingerprint: [u8; 32],
}

impl DurableRosterMemberSlot {
    fn from_material(material: XfrmObjectRosterMemberMaterial) -> Self {
        Self {
            object: material.object,
            phase: XfrmObjectRosterMemberPhase::Pending,
            sweep_proof: None,
            adjacent_proof: None,
            member_id: material.member_id,
            member_generation: material.member_generation,
            deletion_identity_fingerprint: material.fingerprints.deletion_identity,
            install_request_fingerprint: material.fingerprints.install_request,
        }
    }

    /// Whether this slot's durable identity equals another slot's.
    fn same_identity(&self, other: &Self) -> bool {
        self.object == other.object
            && self.member_id == other.member_id
            && self.member_generation == other.member_generation
            && fingerprints_equal(
                &self.deletion_identity_fingerprint,
                &other.deletion_identity_fingerprint,
            )
            && fingerprints_equal(
                &self.install_request_fingerprint,
                &other.install_request_fingerprint,
            )
    }
}

impl fmt::Debug for DurableRosterMemberSlot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableRosterMemberSlot")
            .field("object", &self.object.as_str())
            .field("phase", &self.phase.as_str())
            .field(
                "sweep_proof",
                &self.sweep_proof.map(XfrmObjectRosterSweepProof::as_str),
            )
            .field(
                "adjacent_proof",
                &self
                    .adjacent_proof
                    .map(XfrmObjectRosterAdjacentProof::as_str),
            )
            .finish_non_exhaustive()
    }
}

/// Requested next state of one member slot in a roster transition.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct XfrmObjectRosterMemberTransition {
    pub(crate) phase: XfrmObjectRosterMemberPhase,
    pub(crate) sweep_proof: Option<XfrmObjectRosterSweepProof>,
    pub(crate) adjacent_proof: Option<XfrmObjectRosterAdjacentProof>,
}

impl fmt::Debug for XfrmObjectRosterMemberTransition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XfrmObjectRosterMemberTransition")
            .field("phase", &self.phase.as_str())
            .field(
                "sweep_proof",
                &self.sweep_proof.map(XfrmObjectRosterSweepProof::as_str),
            )
            .field(
                "adjacent_proof",
                &self
                    .adjacent_proof
                    .map(XfrmObjectRosterAdjacentProof::as_str),
            )
            .finish()
    }
}

/// One complete publication of a roster's next durable state.
///
/// A `None` member entry leaves that slot exactly as published, so the flow
/// layer describes only the slots it actually advances. Slots at or beyond the
/// roster's arity must stay `None`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct XfrmObjectRosterTransition {
    phase: XfrmObjectRosterDurablePhase,
    cursor: u8,
    members: [Option<XfrmObjectRosterMemberTransition>; XFRM_OBJECT_ROSTER_MAX_MEMBERS],
    out_of_range: bool,
}

impl XfrmObjectRosterTransition {
    /// Describe a publication that moves the group to `phase` at `cursor`.
    #[must_use]
    pub(crate) const fn new(phase: XfrmObjectRosterDurablePhase, cursor: u8) -> Self {
        Self {
            phase,
            cursor,
            members: [None; XFRM_OBJECT_ROSTER_MAX_MEMBERS],
            out_of_range: false,
        }
    }

    /// Advance one member slot as part of this publication.
    ///
    /// An ordinal beyond the fixed slot array is recorded and rejected by the
    /// store, so a caller can never silently drop a member update.
    #[must_use]
    pub(crate) fn with_member(
        mut self,
        ordinal: usize,
        member: XfrmObjectRosterMemberTransition,
    ) -> Self {
        match self.members.get_mut(ordinal) {
            Some(slot) => *slot = Some(member),
            None => self.out_of_range = true,
        }
        self
    }
}

impl fmt::Debug for XfrmObjectRosterTransition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XfrmObjectRosterTransition")
            .field("phase", &self.phase.as_str())
            .finish_non_exhaustive()
    }
}

/// Fixed-size authenticated correlation handle safe to persist.
///
/// Possessing or decoding this value does not authorize deletion. The store
/// must authenticate it, find exactly one matching current record, and validate
/// namespace, incarnation, generation, epoch, publication sequence, and phase.
#[derive(Clone, PartialEq, Eq)]
pub struct XfrmObjectRosterRecoveryHandle([u8; XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES]);

impl XfrmObjectRosterRecoveryHandle {
    /// Decode fixed-size opaque bytes without treating them as authority.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES]) -> Self {
        Self(bytes)
    }

    /// Return fixed-size opaque bytes for durable application storage.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES] {
        self.0
    }
}

impl fmt::Debug for XfrmObjectRosterRecoveryHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("XfrmObjectRosterRecoveryHandle(<redacted>)")
    }
}

impl fmt::Display for XfrmObjectRosterRecoveryHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

/// Value-free durable roster recovery failure.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XfrmObjectRosterDurableError {
    /// The proof key is the reserved all-zero value.
    InvalidProofKey,
    /// The operating-system random source was unavailable.
    EntropyUnavailable,
    /// The trusted store root is invalid or was replaced.
    InvalidStoreRoot,
    /// Another process owns the permanent store lease.
    StoreBusy,
    /// A durable filesystem operation failed.
    Storage,
    /// A record or handle is malformed, unbounded, or has unknown fields.
    Malformed,
    /// Authentication failed.
    AuthenticationFailed,
    /// More than one candidate exists for a roster or control record.
    Duplicate,
    /// Store or namespace binding does not match.
    WrongBinding,
    /// Actor incarnation does not match the authorized incarnation.
    WrongIncarnation,
    /// The roster generation, publication sequence, or writer epoch is stale.
    Stale,
    /// The requested durable phase transition is not permitted.
    InvalidTransition,
    /// A member request cannot produce an exact unconditional removal identity.
    NonExactRemovalIdentity,
    /// The exact roster record is absent.
    NotFound,
    /// The bounded store has no safe publication slot remaining.
    CapacityExceeded,
}

impl XfrmObjectRosterDurableError {
    /// Stable machine-readable, value-free error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidProofKey => "xfrm_object_roster_recovery_invalid_proof_key",
            Self::EntropyUnavailable => "xfrm_object_roster_recovery_entropy_unavailable",
            Self::InvalidStoreRoot => "xfrm_object_roster_recovery_invalid_store_root",
            Self::StoreBusy => "xfrm_object_roster_recovery_store_busy",
            Self::Storage => "xfrm_object_roster_recovery_storage",
            Self::Malformed => "xfrm_object_roster_recovery_malformed",
            Self::AuthenticationFailed => "xfrm_object_roster_recovery_authentication_failed",
            Self::Duplicate => "xfrm_object_roster_recovery_duplicate",
            Self::WrongBinding => "xfrm_object_roster_recovery_wrong_binding",
            Self::WrongIncarnation => "xfrm_object_roster_recovery_wrong_incarnation",
            Self::Stale => "xfrm_object_roster_recovery_stale",
            Self::InvalidTransition => "xfrm_object_roster_recovery_invalid_transition",
            Self::NonExactRemovalIdentity => {
                "xfrm_object_roster_recovery_non_exact_removal_identity"
            }
            Self::NotFound => "xfrm_object_roster_recovery_not_found",
            Self::CapacityExceeded => "xfrm_object_roster_recovery_capacity_exceeded",
        }
    }
}

impl fmt::Display for XfrmObjectRosterDurableError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Error for XfrmObjectRosterDurableError {}

fn map_canonical_encode_error(error: CanonicalEncodeError) -> XfrmObjectRosterDurableError {
    match error {
        CanonicalEncodeError::CapacityExceeded => XfrmObjectRosterDurableError::CapacityExceeded,
        CanonicalEncodeError::Malformed => XfrmObjectRosterDurableError::Malformed,
    }
}

/// One authenticated durable roster record.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct DurableRosterRecord {
    pub(crate) phase: XfrmObjectRosterDurablePhase,
    pub(crate) cursor: u8,
    pub(crate) publication_sequence: u16,
    pub(crate) store_incarnation: [u8; 16],
    pub(crate) namespace_seal: [u8; 32],
    pub(crate) actor_incarnation: [u8; 16],
    pub(crate) group_id: XfrmObjectRosterGroupId,
    pub(crate) group_generation: XfrmObjectRosterOperationGeneration,
    pub(crate) writer_epoch: NonZeroU64,
    pub(crate) roster_fingerprint: [u8; 32],
    pub(crate) members: [Option<DurableRosterMemberSlot>; XFRM_OBJECT_ROSTER_MAX_MEMBERS],
}

impl fmt::Debug for DurableRosterRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableRosterRecord")
            .field("phase", &self.phase.as_str())
            .finish_non_exhaustive()
    }
}

impl DurableRosterRecord {
    /// Number of populated member slots.
    ///
    /// # Errors
    ///
    /// Returns [`XfrmObjectRosterDurableError::Malformed`] when the populated
    /// slots are not a nonempty prefix of the fixed slot array.
    pub(crate) fn arity(&self) -> Result<usize, XfrmObjectRosterDurableError> {
        let leading = self
            .members
            .iter()
            .take_while(|slot| slot.is_some())
            .count();
        let populated = self.members.iter().flatten().count();
        if leading == 0 || leading != populated {
            return Err(XfrmObjectRosterDurableError::Malformed);
        }
        Ok(leading)
    }

    fn active(&self) -> Vec<&DurableRosterMemberSlot> {
        self.members.iter().flatten().collect()
    }

    /// Borrow one member slot by ordinal.
    pub(crate) fn member(&self, ordinal: usize) -> Option<&DurableRosterMemberSlot> {
        self.members.get(ordinal).and_then(Option::as_ref)
    }

    pub(crate) fn encode(
        &self,
        key: &XfrmObjectRosterRecoveryProofKey,
    ) -> Result<[u8; XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES], XfrmObjectRosterDurableError> {
        let arity = validate_roster_record(self)?;
        if !fingerprints_equal(
            &self.roster_fingerprint,
            &roster_fingerprint(key.canonical_mac_key(), &self.active())?,
        ) {
            return Err(XfrmObjectRosterDurableError::Malformed);
        }
        let mut encoded = [0_u8; XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES];
        encoded[0..8].copy_from_slice(&RECORD_MAGIC);
        encoded[8..10].copy_from_slice(&RECORD_VERSION.to_be_bytes());
        encoded[10] = self.phase.code();
        encoded[11] = self.cursor;
        encoded[12] = u8::try_from(arity).map_err(|_| XfrmObjectRosterDurableError::Malformed)?;
        encoded[13..15].copy_from_slice(&self.publication_sequence.to_be_bytes());
        encoded[16..32].copy_from_slice(&self.store_incarnation);
        encoded[32..64].copy_from_slice(&self.namespace_seal);
        encoded[64..80].copy_from_slice(&self.actor_incarnation);
        encoded[80..96].copy_from_slice(&self.group_id.0);
        encoded[96..104].copy_from_slice(&self.group_generation.get().to_be_bytes());
        encoded[104..112].copy_from_slice(&self.writer_epoch.get().to_be_bytes());
        encoded[112..144].copy_from_slice(&self.roster_fingerprint);
        for (index, slot) in self.members.iter().enumerate() {
            let Some(slot) = slot else {
                continue;
            };
            let base = MEMBER_SLOTS_OFFSET + index * MEMBER_SLOT_BYTES;
            encoded[base] = match slot.object {
                XfrmInstallObject::Sa => 1,
                XfrmInstallObject::Policy => 2,
            };
            encoded[base + 1] = slot.phase.code();
            encoded[base + 2] = slot.sweep_proof.map_or(0, XfrmObjectRosterSweepProof::code);
            encoded[base + 3] = slot
                .adjacent_proof
                .map_or(0, XfrmObjectRosterAdjacentProof::code);
            encoded[base + 8..base + 24].copy_from_slice(&slot.member_id.0);
            encoded[base + 24..base + 32]
                .copy_from_slice(&slot.member_generation.get().to_be_bytes());
            encoded[base + 32..base + 64].copy_from_slice(&slot.deletion_identity_fingerprint);
            encoded[base + 64..base + 96].copy_from_slice(&slot.install_request_fingerprint);
        }
        let tag = authenticate_domain(
            key.canonical_mac_key(),
            RECORD_AUTH_DOMAIN,
            &encoded[..RECORD_BODY_BYTES],
        );
        encoded[RECORD_BODY_BYTES..].copy_from_slice(&tag);
        Ok(encoded)
    }

    pub(crate) fn decode(
        encoded: &[u8; XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES],
        key: &XfrmObjectRosterRecoveryProofKey,
    ) -> Result<Self, XfrmObjectRosterDurableError> {
        if encoded[0..8] != RECORD_MAGIC
            || encoded[8..10] != RECORD_VERSION.to_be_bytes()
            || encoded[15] != 0
        {
            return Err(XfrmObjectRosterDurableError::Malformed);
        }
        if !verify_authentication_domain(
            key.canonical_mac_key(),
            RECORD_AUTH_DOMAIN,
            &encoded[..RECORD_BODY_BYTES],
            &encoded[RECORD_BODY_BYTES..],
        ) {
            return Err(XfrmObjectRosterDurableError::AuthenticationFailed);
        }
        let arity = usize::from(encoded[12]);
        if arity == 0 || arity > XFRM_OBJECT_ROSTER_MAX_MEMBERS {
            return Err(XfrmObjectRosterDurableError::Malformed);
        }
        let mut members: [Option<DurableRosterMemberSlot>; XFRM_OBJECT_ROSTER_MAX_MEMBERS] =
            [None; XFRM_OBJECT_ROSTER_MAX_MEMBERS];
        for (index, member) in members.iter_mut().enumerate() {
            let base = MEMBER_SLOTS_OFFSET + index * MEMBER_SLOT_BYTES;
            let raw = &encoded[base..base + MEMBER_SLOT_BYTES];
            if index >= arity {
                if raw.iter().any(|byte| *byte != 0) {
                    return Err(XfrmObjectRosterDurableError::Malformed);
                }
                continue;
            }
            if raw[4..8].iter().any(|byte| *byte != 0) {
                return Err(XfrmObjectRosterDurableError::Malformed);
            }
            let object = match raw[0] {
                1 => XfrmInstallObject::Sa,
                2 => XfrmInstallObject::Policy,
                _ => return Err(XfrmObjectRosterDurableError::Malformed),
            };
            *member = Some(DurableRosterMemberSlot {
                object,
                phase: XfrmObjectRosterMemberPhase::from_code(raw[1])?,
                sweep_proof: match raw[2] {
                    0 => None,
                    code => Some(XfrmObjectRosterSweepProof::from_code(code)?),
                },
                adjacent_proof: match raw[3] {
                    0 => None,
                    code => Some(XfrmObjectRosterAdjacentProof::from_code(code)?),
                },
                member_id: XfrmObjectRosterMemberId::from_bytes(array_at(raw, 8))?,
                member_generation: NonZeroU64::new(u64_at(raw, 24))
                    .ok_or(XfrmObjectRosterDurableError::Malformed)?,
                deletion_identity_fingerprint: array_at(raw, 32),
                install_request_fingerprint: array_at(raw, 64),
            });
        }
        let record = Self {
            phase: XfrmObjectRosterDurablePhase::from_code(encoded[10])?,
            cursor: encoded[11],
            publication_sequence: u16::from_be_bytes(array_at(encoded, 13)),
            store_incarnation: array_at(encoded, 16),
            namespace_seal: array_at(encoded, 32),
            actor_incarnation: array_at(encoded, 64),
            group_id: XfrmObjectRosterGroupId::from_bytes(array_at(encoded, 80))?,
            group_generation: XfrmObjectRosterOperationGeneration::new(u64_at(encoded, 96))
                .ok_or(XfrmObjectRosterDurableError::Malformed)?,
            writer_epoch: NonZeroU64::new(u64_at(encoded, 104))
                .ok_or(XfrmObjectRosterDurableError::Malformed)?,
            roster_fingerprint: array_at(encoded, 112),
            members,
        };
        validate_roster_record(&record)?;
        // The roster digest is authenticated by the record tag, but a writer
        // bug could still publish a MAC-valid record whose digest disagrees
        // with its own slots. Recomputing it here makes the record internally
        // self-consistent or malformed, never silently wrong.
        if !fingerprints_equal(
            &record.roster_fingerprint,
            &roster_fingerprint(key.canonical_mac_key(), &record.active())?,
        ) {
            return Err(XfrmObjectRosterDurableError::Malformed);
        }
        Ok(record)
    }

    pub(crate) fn handle(
        &self,
        key: &XfrmObjectRosterRecoveryProofKey,
    ) -> Result<XfrmObjectRosterRecoveryHandle, XfrmObjectRosterDurableError> {
        Ok(XfrmObjectRosterRecoveryHandle(self.encode(key)?))
    }
}

/// Compute the keyed digest that binds one ordered member set to a roster.
fn roster_fingerprint(
    key: CanonicalMacKey<'_>,
    members: &[&DurableRosterMemberSlot],
) -> Result<[u8; AUTH_TAG_BYTES], XfrmObjectRosterDurableError> {
    let mut mac = key.begin(MEMBERS_AUTH_DOMAIN);
    mac_u64(
        &mut mac,
        u64::try_from(members.len()).map_err(|_| XfrmObjectRosterDurableError::CapacityExceeded)?,
    );
    for (ordinal, slot) in members.iter().enumerate() {
        mac_u8(
            &mut mac,
            u8::try_from(ordinal).map_err(|_| XfrmObjectRosterDurableError::CapacityExceeded)?,
        );
        mac_u8(
            &mut mac,
            match slot.object {
                XfrmInstallObject::Sa => 1,
                XfrmInstallObject::Policy => 2,
            },
        );
        mac_bytes(&mut mac, &slot.deletion_identity_fingerprint)
            .map_err(map_canonical_encode_error)?;
        mac_bytes(&mut mac, &slot.install_request_fingerprint)
            .map_err(map_canonical_encode_error)?;
        mac_bytes(&mut mac, &slot.member_id.0).map_err(map_canonical_encode_error)?;
        mac_u64(&mut mac, slot.member_generation.get());
    }
    Ok(*mac.finalize())
}

/// Validate every durable invariant of one roster record and return its arity.
///
/// This is the executable form of the per-phase legality table. It runs on
/// both encode and decode, so a MAC-valid record published by a buggy writer
/// is rejected exactly like a forged one.
///
/// # Errors
///
/// Returns [`XfrmObjectRosterDurableError::Malformed`] for any violation.
fn validate_roster_record(
    record: &DurableRosterRecord,
) -> Result<usize, XfrmObjectRosterDurableError> {
    let arity = record.arity()?;
    if record.publication_sequence == 0
        || record.store_incarnation.iter().all(|byte| *byte == 0)
        || record.namespace_seal.iter().all(|byte| *byte == 0)
        || record.actor_incarnation.iter().all(|byte| *byte == 0)
        || record.roster_fingerprint.iter().all(|byte| *byte == 0)
    {
        return Err(XfrmObjectRosterDurableError::Malformed);
    }
    let active = record.active();
    for slot in &active {
        if slot.deletion_identity_fingerprint.iter().all(|b| *b == 0)
            || slot.install_request_fingerprint.iter().all(|b| *b == 0)
        {
            return Err(XfrmObjectRosterDurableError::Malformed);
        }
        // A member slot never carries deletion authority without a clean
        // adjacent absence proof, at any phase and regardless of the sweep.
        let adjacent_ok = match slot.phase {
            XfrmObjectRosterMemberPhase::Pending => !matches!(
                slot.adjacent_proof,
                Some(XfrmObjectRosterAdjacentProof::Conflict)
                    | Some(XfrmObjectRosterAdjacentProof::AbsentThenAlreadyExists)
            ),
            XfrmObjectRosterMemberPhase::Acquired
            | XfrmObjectRosterMemberPhase::Indeterminate
            | XfrmObjectRosterMemberPhase::RemovalAdmitted
            | XfrmObjectRosterMemberPhase::Retired => {
                slot.adjacent_proof == Some(XfrmObjectRosterAdjacentProof::Absent)
            }
            XfrmObjectRosterMemberPhase::NoMutation => true,
        };
        if !adjacent_ok {
            return Err(XfrmObjectRosterDurableError::Malformed);
        }
        if slot.phase == XfrmObjectRosterMemberPhase::Acquired
            && slot.sweep_proof != Some(XfrmObjectRosterSweepProof::Absent)
        {
            return Err(XfrmObjectRosterDurableError::Malformed);
        }
    }
    // Two members of one roster may never share a durable identity: a shared
    // deletion identity would make compensation ambiguous.
    for (index, left) in active.iter().enumerate() {
        if active[index + 1..].iter().any(|right| {
            left.member_id == right.member_id
                || fingerprints_equal(
                    &left.deletion_identity_fingerprint,
                    &right.deletion_identity_fingerprint,
                )
        }) {
            return Err(XfrmObjectRosterDurableError::Malformed);
        }
    }
    if usize::from(record.cursor) > arity {
        return Err(XfrmObjectRosterDurableError::Malformed);
    }
    let legal = match record.phase {
        XfrmObjectRosterDurablePhase::Prepared => prepared_body_is_legal(record, &active),
        XfrmObjectRosterDurablePhase::Issuing => issuing_body_is_legal(record, &active),
        XfrmObjectRosterDurablePhase::Applied | XfrmObjectRosterDurablePhase::Committed => {
            settled_body_is_legal(record, &active, arity)
        }
        XfrmObjectRosterDurablePhase::Compensating => {
            compensating_body_is_legal(record, &active, arity)
        }
        XfrmObjectRosterDurablePhase::NoMutation => no_mutation_body_is_legal(record, &active),
        XfrmObjectRosterDurablePhase::RolledBack => rolled_back_body_is_legal(record, &active),
        // A retired roster preserves the body of whichever terminal state it
        // retired from, so it is legal exactly when one of those bodies is.
        XfrmObjectRosterDurablePhase::Retired => {
            prepared_body_is_legal(record, &active)
                || no_mutation_body_is_legal(record, &active)
                || rolled_back_body_is_legal(record, &active)
                || settled_body_is_legal(record, &active, arity)
        }
    };
    if legal {
        Ok(arity)
    } else {
        Err(XfrmObjectRosterDurableError::Malformed)
    }
}

fn prepared_body_is_legal(
    record: &DurableRosterRecord,
    active: &[&DurableRosterMemberSlot],
) -> bool {
    record.cursor == 0
        && active.iter().all(|slot| {
            slot.phase == XfrmObjectRosterMemberPhase::Pending
                && slot.sweep_proof.is_none()
                && slot.adjacent_proof.is_none()
        })
}

fn issuing_body_is_legal(
    record: &DurableRosterRecord,
    active: &[&DurableRosterMemberSlot],
) -> bool {
    let cursor = usize::from(record.cursor);
    if cursor >= active.len() || active.iter().any(|slot| slot.sweep_proof.is_none()) {
        return false;
    }
    if active
        .iter()
        .any(|slot| slot.sweep_proof == Some(XfrmObjectRosterSweepProof::Conflict))
    {
        // A sweep conflict aborts before any member enters its effect window,
        // so the cursor never left member zero and no adjacent proof exists.
        return cursor == 0
            && active.iter().all(|slot| {
                slot.phase == XfrmObjectRosterMemberPhase::Pending && slot.adjacent_proof.is_none()
            });
    }
    active.iter().enumerate().all(|(index, slot)| {
        if index < cursor {
            slot.phase == XfrmObjectRosterMemberPhase::Acquired
        } else if index == cursor {
            slot.phase == XfrmObjectRosterMemberPhase::Pending
                && matches!(
                    slot.adjacent_proof,
                    None | Some(XfrmObjectRosterAdjacentProof::Absent)
                )
        } else {
            slot.phase == XfrmObjectRosterMemberPhase::Pending && slot.adjacent_proof.is_none()
        }
    })
}

fn settled_body_is_legal(
    record: &DurableRosterRecord,
    active: &[&DurableRosterMemberSlot],
    arity: usize,
) -> bool {
    usize::from(record.cursor) == arity
        && active
            .iter()
            .all(|slot| slot.phase == XfrmObjectRosterMemberPhase::Acquired)
}

fn compensating_body_is_legal(
    record: &DurableRosterRecord,
    active: &[&DurableRosterMemberSlot],
    arity: usize,
) -> bool {
    let cursor = usize::from(record.cursor);
    if cursor >= arity
        || active
            .iter()
            .any(|slot| slot.sweep_proof != Some(XfrmObjectRosterSweepProof::Absent))
    {
        return false;
    }
    // The highest member that left `Pending` is the deepest member this roster
    // ever entered. Compensation walks strictly downward from the cursor and
    // never descends past an unresolved member.
    let Some(deepest) = active
        .iter()
        .rposition(|slot| slot.phase != XfrmObjectRosterMemberPhase::Pending)
    else {
        return false;
    };
    if cursor > deepest {
        return false;
    }
    if active
        .iter()
        .filter(|slot| {
            matches!(
                slot.phase,
                XfrmObjectRosterMemberPhase::Indeterminate
                    | XfrmObjectRosterMemberPhase::RemovalAdmitted
            )
        })
        .count()
        > 1
    {
        return false;
    }
    active.iter().enumerate().all(|(index, slot)| {
        if index == deepest {
            !matches!(slot.phase, XfrmObjectRosterMemberPhase::Pending)
        } else if index < cursor {
            slot.phase == XfrmObjectRosterMemberPhase::Acquired
        } else if index == cursor {
            matches!(
                slot.phase,
                XfrmObjectRosterMemberPhase::Acquired
                    | XfrmObjectRosterMemberPhase::RemovalAdmitted
                    | XfrmObjectRosterMemberPhase::Retired
            )
        } else if index < deepest {
            slot.phase == XfrmObjectRosterMemberPhase::Retired
        } else {
            slot.phase == XfrmObjectRosterMemberPhase::Pending && slot.adjacent_proof.is_none()
        }
    })
}

fn no_mutation_body_is_legal(
    record: &DurableRosterRecord,
    active: &[&DurableRosterMemberSlot],
) -> bool {
    if record.cursor != 0 || active.iter().any(|slot| slot.sweep_proof.is_none()) {
        return false;
    }
    if active
        .iter()
        .any(|slot| slot.sweep_proof == Some(XfrmObjectRosterSweepProof::Conflict))
    {
        // The sweep found a conflicting object, so the group published its
        // terminal verdict without issuing anything at all.
        return active.iter().all(|slot| {
            slot.phase == XfrmObjectRosterMemberPhase::Pending && slot.adjacent_proof.is_none()
        });
    }
    // Otherwise member zero's own adjacent witness found a conflict before any
    // member was acquired, which is the only other zero-effect verdict.
    active.iter().enumerate().all(|(index, slot)| {
        if index == 0 {
            slot.phase == XfrmObjectRosterMemberPhase::NoMutation
                && slot.adjacent_proof == Some(XfrmObjectRosterAdjacentProof::Conflict)
        } else {
            slot.phase == XfrmObjectRosterMemberPhase::Pending && slot.adjacent_proof.is_none()
        }
    })
}

fn rolled_back_body_is_legal(
    record: &DurableRosterRecord,
    active: &[&DurableRosterMemberSlot],
) -> bool {
    record.cursor == 0
        && active
            .iter()
            .all(|slot| slot.sweep_proof == Some(XfrmObjectRosterSweepProof::Absent))
        && !active.iter().any(|slot| {
            matches!(
                slot.phase,
                XfrmObjectRosterMemberPhase::Acquired
                    | XfrmObjectRosterMemberPhase::RemovalAdmitted
                    | XfrmObjectRosterMemberPhase::Indeterminate
            )
        })
}

fn fingerprints_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    bool::from(left.ct_eq(right))
}

fn array_at<const N: usize>(bytes: &[u8], start: usize) -> [u8; N] {
    let mut result = [0_u8; N];
    result.copy_from_slice(&bytes[start..start + N]);
    result
}

fn u64_at(bytes: &[u8], start: usize) -> u64 {
    u64::from_be_bytes(array_at(bytes, start))
}

/// Descriptor-anchored, permanently leased roster recovery store.
///
/// The store owns an exclusive `flock` on the originally opened root directory
/// for its entire lifetime. Every operation reopens the visible path with
/// `O_NOFOLLOW`, verifies the root device/inode, and scans a bounded inventory.
/// Unknown, malformed, conflicting duplicate, wrong-owner, wrong-device, or
/// wrong-mode entries poison the operation without deleting anything. The sole
/// duplicate exception is an authenticated pair of consecutive publications of
/// the same roster (or consecutive epoch witnesses) that this implementation
/// can leave after the new entry's directory fsync but before unlinking its
/// predecessor; the bounded scan deterministically keeps the successor and
/// syncs predecessor removal.
///
/// The control record's actor incarnation is durable writer authority. A fresh
/// process that reopens the same root, namespace, and proof key adopts that
/// incarnation; it is not regenerated on every open. A live authority from a
/// different root/store incarnation cannot validate against this lease.
#[derive(Clone)]
pub struct XfrmObjectRosterRecoveryStore {
    inner: Arc<StoreInner>,
}

struct StoreInner {
    visible_path: PathBuf,
    descriptor: OwnedFd,
    root_device: u64,
    root_inode: u64,
    root_owner: u32,
    owner_process_id: u32,
    proof_key: XfrmObjectRosterRecoveryProofKey,
    control: ControlRecord,
    journal_enabled: bool,
    process_lock: Mutex<()>,
    #[cfg(test)]
    ledger: Mutex<Vec<XfrmObjectRosterPublication>>,
    #[cfg(test)]
    physical_barriers: Mutex<usize>,
}

impl Drop for StoreInner {
    fn drop(&mut self) {
        if self.owner_process_id == std::process::id() {
            let _ = flock(&self.descriptor, FlockOperation::Unlock);
        }
    }
}

/// Test-only record of one durable roster publication.
///
/// The latency and crash-ordering detectors count consumer-visible durable
/// boundaries, so they need the publication history without a clock or a delay
/// hook in production code.
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct XfrmObjectRosterPublication {
    pub(crate) sequence: u16,
    pub(crate) phase: XfrmObjectRosterDurablePhase,
    pub(crate) class: XfrmObjectRosterPublicationClass,
}

/// Test-only classification of one durable roster publication.
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum XfrmObjectRosterPublicationClass {
    /// The roster's first publication.
    Prepare,
    /// An intermediate state-machine publication.
    Transition,
    /// The publication that surrenders cleanup authority to the product.
    Finalize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ControlRecord {
    store_incarnation: [u8; 16],
    namespace_seal: [u8; 32],
    actor_incarnation: [u8; 16],
    root_device: u64,
    root_inode: u64,
}

impl ControlRecord {
    fn encode(
        self,
        key: &XfrmObjectRosterRecoveryProofKey,
    ) -> Result<[u8; CONTROL_BYTES], XfrmObjectRosterDurableError> {
        if self.store_incarnation.iter().all(|byte| *byte == 0)
            || self.namespace_seal.iter().all(|byte| *byte == 0)
            || self.actor_incarnation.iter().all(|byte| *byte == 0)
            || self.root_device == 0
            || self.root_inode == 0
        {
            return Err(XfrmObjectRosterDurableError::Malformed);
        }
        let mut encoded = [0_u8; CONTROL_BYTES];
        encoded[0..8].copy_from_slice(&CONTROL_MAGIC);
        encoded[8..10].copy_from_slice(&RECORD_VERSION.to_be_bytes());
        encoded[16..32].copy_from_slice(&self.store_incarnation);
        encoded[32..64].copy_from_slice(&self.namespace_seal);
        encoded[64..80].copy_from_slice(&self.actor_incarnation);
        encoded[80..88].copy_from_slice(&self.root_device.to_be_bytes());
        encoded[88..96].copy_from_slice(&self.root_inode.to_be_bytes());
        let tag = authenticate_domain(
            key.canonical_mac_key(),
            CONTROL_AUTH_DOMAIN,
            &encoded[..CONTROL_BODY_BYTES],
        );
        encoded[CONTROL_BODY_BYTES..].copy_from_slice(&tag);
        Ok(encoded)
    }

    fn decode(
        encoded: &[u8; CONTROL_BYTES],
        key: &XfrmObjectRosterRecoveryProofKey,
    ) -> Result<Self, XfrmObjectRosterDurableError> {
        if encoded[0..8] != CONTROL_MAGIC
            || encoded[8..10] != RECORD_VERSION.to_be_bytes()
            || encoded[10..16] != [0_u8; 6]
        {
            return Err(XfrmObjectRosterDurableError::Malformed);
        }
        if !verify_authentication_domain(
            key.canonical_mac_key(),
            CONTROL_AUTH_DOMAIN,
            &encoded[..CONTROL_BODY_BYTES],
            &encoded[CONTROL_BODY_BYTES..],
        ) {
            return Err(XfrmObjectRosterDurableError::AuthenticationFailed);
        }
        let control = Self {
            store_incarnation: array_at(encoded, 16),
            namespace_seal: array_at(encoded, 32),
            actor_incarnation: array_at(encoded, 64),
            root_device: u64_at(encoded, 80),
            root_inode: u64_at(encoded, 88),
        };
        if control.store_incarnation.iter().all(|byte| *byte == 0)
            || control.namespace_seal.iter().all(|byte| *byte == 0)
            || control.actor_incarnation.iter().all(|byte| *byte == 0)
            || control.root_device == 0
            || control.root_inode == 0
        {
            return Err(XfrmObjectRosterDurableError::Malformed);
        }
        Ok(control)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct EpochRecord {
    store_incarnation: [u8; 16],
    epoch: NonZeroU64,
}

impl EpochRecord {
    fn encode(
        self,
        key: &XfrmObjectRosterRecoveryProofKey,
    ) -> Result<[u8; EPOCH_BYTES], XfrmObjectRosterDurableError> {
        let mut encoded = [0_u8; EPOCH_BYTES];
        encoded[0..8].copy_from_slice(&EPOCH_MAGIC);
        encoded[8..10].copy_from_slice(&RECORD_VERSION.to_be_bytes());
        encoded[16..32].copy_from_slice(&self.store_incarnation);
        encoded[32..40].copy_from_slice(&self.epoch.get().to_be_bytes());
        let tag = authenticate_domain(
            key.canonical_mac_key(),
            EPOCH_AUTH_DOMAIN,
            &encoded[..EPOCH_BODY_BYTES],
        );
        encoded[EPOCH_BODY_BYTES..].copy_from_slice(&tag);
        Ok(encoded)
    }

    fn decode(
        encoded: &[u8; EPOCH_BYTES],
        key: &XfrmObjectRosterRecoveryProofKey,
    ) -> Result<Self, XfrmObjectRosterDurableError> {
        if encoded[0..8] != EPOCH_MAGIC
            || encoded[8..10] != RECORD_VERSION.to_be_bytes()
            || encoded[10..16] != [0_u8; 6]
            || encoded[40..EPOCH_BODY_BYTES].iter().any(|byte| *byte != 0)
        {
            return Err(XfrmObjectRosterDurableError::Malformed);
        }
        if !verify_authentication_domain(
            key.canonical_mac_key(),
            EPOCH_AUTH_DOMAIN,
            &encoded[..EPOCH_BODY_BYTES],
            &encoded[EPOCH_BODY_BYTES..],
        ) {
            return Err(XfrmObjectRosterDurableError::AuthenticationFailed);
        }
        let store_incarnation = array_at(encoded, 16);
        let epoch =
            NonZeroU64::new(u64_at(encoded, 32)).ok_or(XfrmObjectRosterDurableError::Malformed)?;
        if store_incarnation.iter().all(|byte| *byte == 0) {
            return Err(XfrmObjectRosterDurableError::Malformed);
        }
        Ok(Self {
            store_incarnation,
            epoch,
        })
    }
}

struct StoreLease<'a> {
    store: &'a StoreInner,
    _process_guard: MutexGuard<'a, ()>,
}

struct Inventory {
    records: Vec<NamedRosterRecord>,
    epoch_name: String,
    epoch: NonZeroU64,
    journal: bool,
}

type NamedRosterRecord = (String, DurableRosterRecord);
type ReconciledRosterRecords = (Vec<NamedRosterRecord>, Vec<String>);

impl Inventory {
    fn has_unresolved_writer_authority(&self) -> bool {
        self.records
            .iter()
            .any(|(_, record)| record.phase.is_unresolved_writer_authority())
    }

    fn current_for(
        &self,
        group_id: XfrmObjectRosterGroupId,
        generation: XfrmObjectRosterOperationGeneration,
    ) -> Result<(&str, &DurableRosterRecord), XfrmObjectRosterDurableError> {
        let mut matches = self.records.iter().filter(|(_, record)| {
            record.group_id == group_id && record.group_generation == generation
        });
        let Some((name, record)) = matches.next() else {
            return Err(XfrmObjectRosterDurableError::NotFound);
        };
        if matches.next().is_some() {
            return Err(XfrmObjectRosterDurableError::Duplicate);
        }
        Ok((name, record))
    }
}

impl XfrmObjectRosterRecoveryStore {
    /// Open or initialize a roster store through a namespace-bound backend.
    ///
    /// The root path must be absolute and must never be shared with another
    /// durable family. If absent, it is created with mode `0700`; its parent is
    /// part of the caller's trusted configuration. An existing root must be
    /// owned by the effective user, be exactly `0700`, and contain either no
    /// entries or one valid control record plus valid roster records.
    /// `namespace_binding` is the canonical private nsfs device/inode,
    /// `SO_NETNS_COOKIE`, and boot identity material supplied by the sealed
    /// namespace actor.
    ///
    /// # Errors
    ///
    /// Returns [`XfrmObjectRosterDurableError::InvalidStoreRoot`] for an
    /// untrusted root, [`XfrmObjectRosterDurableError::StoreBusy`] when another
    /// process holds the lease, and [`XfrmObjectRosterDurableError::Malformed`]
    /// or [`XfrmObjectRosterDurableError::WrongBinding`] when the root belongs
    /// to another family, namespace, or proof key.
    pub(crate) fn open_bound(
        path: &Path,
        proof_key: XfrmObjectRosterRecoveryProofKey,
        namespace_binding: [u8; 40],
    ) -> Result<Self, XfrmObjectRosterDurableError> {
        if !valid_store_path(path) {
            return Err(XfrmObjectRosterDurableError::InvalidStoreRoot);
        }
        create_root_if_absent(path)?;
        let descriptor = open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(map_root_open_error)?;
        let metadata = fstat(&descriptor).map_err(|_| XfrmObjectRosterDurableError::Storage)?;
        validate_root_metadata(&metadata)?;
        let root_device = stat_device(&metadata)?;
        let root_inode = stat_inode(&metadata)?;
        flock(&descriptor, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
            if error == rustix::io::Errno::WOULDBLOCK {
                XfrmObjectRosterDurableError::StoreBusy
            } else {
                XfrmObjectRosterDurableError::Storage
            }
        })?;
        // Synchronize the containing directory even on reopen. This both
        // publishes a newly created root and repairs the safe case where a
        // prior process died after mkdir but before its parent fsync.
        sync_store_root_parent(path, &descriptor)?;

        let namespace_seal = namespace_seal(&proof_key, namespace_binding);
        let owner_process_id = std::process::id();
        let mut inner = StoreInner {
            visible_path: path.to_path_buf(),
            descriptor,
            root_device,
            root_inode,
            root_owner: metadata.st_uid,
            owner_process_id,
            proof_key,
            control: ControlRecord {
                store_incarnation: [1; 16],
                namespace_seal,
                actor_incarnation: [1; 16],
                root_device,
                root_inode,
            },
            journal_enabled: false,
            process_lock: Mutex::new(()),
            #[cfg(test)]
            ledger: Mutex::new(Vec::new()),
            #[cfg(test)]
            physical_barriers: Mutex::new(0),
        };
        inner.control = initialize_or_load_control(&inner, namespace_seal)?;
        inner.journal_enabled = initialize_journal_mode(&inner)?;
        let store = Self {
            inner: Arc::new(inner),
        };
        store.lease()?.inventory()?;
        Ok(store)
    }

    /// Persist a prepared roster before any backend mutation is admitted.
    ///
    /// `members` is the caller-declared apply order: ordinal zero is applied
    /// first and compensated last. Every member contributes independent opaque,
    /// proof-keyed digests of its exact kernel deletion identity and complete
    /// install request; the store derives the roster digest from that ordered
    /// set and never sees a request. A duplicate active deletion identity is
    /// rejected globally, and any unresolved roster blocks preparation so
    /// consumer bookkeeping and recovery stay ordered before every later
    /// cooperating writer.
    ///
    /// # Errors
    ///
    /// Returns [`XfrmObjectRosterDurableError::Malformed`] for an empty or
    /// oversized member list, [`XfrmObjectRosterDurableError::Duplicate`] for a
    /// repeated `(group_id, generation)` or deletion identity,
    /// [`XfrmObjectRosterDurableError::InvalidTransition`] while a roster is
    /// unresolved, and [`XfrmObjectRosterDurableError::CapacityExceeded`] when
    /// the bounded store is full.
    pub(crate) fn prepare(
        &self,
        group_id: XfrmObjectRosterGroupId,
        generation: XfrmObjectRosterOperationGeneration,
        members: &[XfrmObjectRosterMemberMaterial],
    ) -> Result<XfrmObjectRosterRecoveryHandle, XfrmObjectRosterDurableError> {
        if members.is_empty() || members.len() > XFRM_OBJECT_ROSTER_MAX_MEMBERS {
            return Err(XfrmObjectRosterDurableError::Malformed);
        }
        let lease = self.lease()?;
        let mut inventory = lease.inventory()?;
        if lease.prune_terminal_records(&inventory)? {
            inventory = lease.inventory()?;
        }
        if inventory.has_unresolved_writer_authority() {
            return Err(XfrmObjectRosterDurableError::InvalidTransition);
        }
        if inventory.records.len() >= MAX_ACTIVE_RECORDS {
            return Err(XfrmObjectRosterDurableError::CapacityExceeded);
        }
        if inventory
            .records
            .iter()
            .any(|(_, record)| record.group_id == group_id && record.group_generation == generation)
        {
            return Err(XfrmObjectRosterDurableError::Duplicate);
        }
        if members.iter().any(|member| {
            inventory.records.iter().any(|(_, record)| {
                !record.phase.is_terminal()
                    && record.members.iter().flatten().any(|slot| {
                        fingerprints_equal(
                            &slot.deletion_identity_fingerprint,
                            &member.fingerprints.deletion_identity,
                        )
                    })
            })
        }) {
            return Err(XfrmObjectRosterDurableError::Duplicate);
        }
        let mut slots: [Option<DurableRosterMemberSlot>; XFRM_OBJECT_ROSTER_MAX_MEMBERS] =
            [None; XFRM_OBJECT_ROSTER_MAX_MEMBERS];
        for (slot, material) in slots.iter_mut().zip(members.iter()) {
            *slot = Some(DurableRosterMemberSlot::from_material(*material));
        }
        let epoch = lease.current_epoch(&inventory)?;
        let mut record = DurableRosterRecord {
            phase: XfrmObjectRosterDurablePhase::Prepared,
            cursor: 0,
            publication_sequence: 1,
            store_incarnation: lease.store.control.store_incarnation,
            namespace_seal: lease.store.control.namespace_seal,
            actor_incarnation: lease.store.control.actor_incarnation,
            group_id,
            group_generation: generation,
            writer_epoch: epoch,
            roster_fingerprint: [0; 32],
            members: slots,
        };
        record.roster_fingerprint =
            roster_fingerprint(lease.store.proof_key.canonical_mac_key(), &record.active())?;
        lease.publish_record(&record, PublicationClass::Prepare)?;
        record.handle(&lease.store.proof_key)
    }

    /// Publish one exact roster transition with atomic file and parent
    /// directory synchronization.
    ///
    /// The publication sequence is the sole ordering authority: every
    /// transition increments it by exactly one, so the two intra-phase progress
    /// self-edges are totally ordered without relying on phase antisymmetry.
    /// `Prepared -> Issuing` is the roster's single writer-epoch burn; every
    /// later edge inherits that epoch.
    ///
    /// A member's `Conflict` or `AbsentThenAlreadyExists` adjacent proof is
    /// published by the same transition that moves the group out of `Issuing`,
    /// never while the group is still `Issuing`: a conflicted member is not
    /// `Pending` any more, and the `Issuing` body admits only pending or
    /// acquired members.
    ///
    /// # Errors
    ///
    /// Returns [`XfrmObjectRosterDurableError::InvalidTransition`] for an
    /// illegal edge or while another roster is unresolved,
    /// [`XfrmObjectRosterDurableError::Stale`] when the handle or the record's
    /// writer epoch is not current, [`XfrmObjectRosterDurableError::Malformed`]
    /// when the resulting body violates the per-phase legality table, and
    /// [`XfrmObjectRosterDurableError::CapacityExceeded`] when the publication
    /// sequence would overflow.
    pub(crate) fn transition(
        &self,
        handle: &XfrmObjectRosterRecoveryHandle,
        expected: XfrmObjectRosterDurablePhase,
        next: XfrmObjectRosterTransition,
    ) -> Result<DurableRosterRecord, XfrmObjectRosterDurableError> {
        if next.out_of_range {
            return Err(XfrmObjectRosterDurableError::Malformed);
        }
        if !expected.permits(next.phase) {
            return Err(XfrmObjectRosterDurableError::InvalidTransition);
        }
        let lease = self.lease()?;
        let inventory = lease.inventory()?;
        let (old_name, current) = lease.current_from_handle(&inventory, handle)?;
        if current.phase != expected {
            return Err(XfrmObjectRosterDurableError::InvalidTransition);
        }
        let entering_issuing = expected == XfrmObjectRosterDurablePhase::Prepared
            && next.phase == XfrmObjectRosterDurablePhase::Issuing;
        if entering_issuing && inventory.has_unresolved_writer_authority() {
            return Err(XfrmObjectRosterDurableError::InvalidTransition);
        }
        let current_epoch = lease.current_epoch(&inventory)?;
        // A stale epoch under an unresolved roster means another writer burned
        // the epoch underneath it. Reading such a record stays legal so
        // recovery can classify it for repair, but publishing any further
        // state from it, including one that would authorize a delete, does not.
        if current.phase.is_unresolved_writer_authority() && current.writer_epoch != current_epoch {
            return Err(XfrmObjectRosterDurableError::Stale);
        }
        let publication_sequence = current
            .publication_sequence
            .checked_add(1)
            .ok_or(XfrmObjectRosterDurableError::CapacityExceeded)?;
        let mut members = current.members;
        for (slot, requested) in members.iter_mut().zip(next.members.iter()) {
            let (Some(slot), Some(requested)) = (slot.as_mut(), requested) else {
                if slot.is_none() && requested.is_some() {
                    return Err(XfrmObjectRosterDurableError::Malformed);
                }
                continue;
            };
            slot.phase = requested.phase;
            slot.sweep_proof = requested.sweep_proof;
            slot.adjacent_proof = requested.adjacent_proof;
        }
        // Project the post-transition epoch without burning it yet. Every
        // rejection below must consume nothing: a failed transition may not
        // leave a burned epoch behind that fences cooperating writers.
        let projected_epoch = if entering_issuing {
            current_epoch
                .get()
                .checked_add(1)
                .and_then(NonZeroU64::new)
                .ok_or(XfrmObjectRosterDurableError::Stale)?
        } else {
            current.writer_epoch
        };
        let next_record = DurableRosterRecord {
            phase: next.phase,
            cursor: next.cursor,
            publication_sequence,
            writer_epoch: projected_epoch,
            members,
            ..current.clone()
        };
        if !is_exact_roster_publication_successor(current, &next_record, projected_epoch) {
            return Err(XfrmObjectRosterDurableError::InvalidTransition);
        }
        validate_roster_record(&next_record)?;
        if entering_issuing
            && !inventory.journal
            && lease.advance_epoch(&inventory)? != projected_epoch
        {
            return Err(XfrmObjectRosterDurableError::Stale);
        }
        let class = if next.phase == XfrmObjectRosterDurablePhase::Committed {
            PublicationClass::Finalize
        } else {
            PublicationClass::Transition
        };
        lease.publish_record(&next_record, class)?;
        if !inventory.journal {
            lease.remove_record(old_name)?;
        }
        Ok(next_record)
    }

    /// Inspect the authenticated current group phase for a retained handle.
    ///
    /// The result is diagnostic state only and never cleanup authority.
    ///
    /// # Errors
    ///
    /// Returns [`XfrmObjectRosterDurableError::NotFound`] when no record
    /// matches, [`XfrmObjectRosterDurableError::Stale`] when the handle is not
    /// the current publication, and
    /// [`XfrmObjectRosterDurableError::AuthenticationFailed`] for a forged or
    /// tampered handle.
    pub fn inspect(
        &self,
        handle: &XfrmObjectRosterRecoveryHandle,
    ) -> Result<XfrmObjectRosterDurablePhase, XfrmObjectRosterDurableError> {
        let lease = self.lease()?;
        let inventory = lease.inventory()?;
        Ok(lease.current_from_handle(&inventory, handle)?.1.phase)
    }

    /// Restore one exact authenticated roster record from durable correlation
    /// data.
    ///
    /// Unlike the single-object family, a stale writer epoch is NOT rejected
    /// here. Epoch currency is a per-delete precondition inside recovery, so a
    /// stale-epoch roster must remain readable and classifiable for repair
    /// instead of becoming a permanent dead end.
    ///
    /// # Errors
    ///
    /// Returns [`XfrmObjectRosterDurableError::NotFound`] when no record
    /// matches and [`XfrmObjectRosterDurableError::WrongBinding`] when the
    /// roster digest does not match the caller's member set.
    pub(crate) fn restore(
        &self,
        group_id: XfrmObjectRosterGroupId,
        generation: XfrmObjectRosterOperationGeneration,
        roster_fingerprint: [u8; 32],
    ) -> Result<DurableRosterRecord, XfrmObjectRosterDurableError> {
        let lease = self.lease()?;
        let inventory = lease.inventory()?;
        let (_, record) = inventory.current_for(group_id, generation)?;
        lease.validate_record_binding(record)?;
        if !fingerprints_equal(&record.roster_fingerprint, &roster_fingerprint) {
            return Err(XfrmObjectRosterDurableError::WrongBinding);
        }
        Ok(record.clone())
    }

    /// Authenticate an exact current handle for actor-bound recovery.
    ///
    /// Unlike group-ID restoration, this requires every encoded phase, cursor,
    /// publication sequence, member state, and epoch field to equal the current
    /// record. A handle retained across any transition is stale and cannot
    /// drive another transition.
    ///
    /// # Errors
    ///
    /// Returns [`XfrmObjectRosterDurableError::Stale`] for a superseded handle
    /// and [`XfrmObjectRosterDurableError::WrongBinding`] when the roster
    /// digest does not match the caller's member set.
    pub(crate) fn restore_handle(
        &self,
        handle: &XfrmObjectRosterRecoveryHandle,
        roster_fingerprint: [u8; 32],
    ) -> Result<DurableRosterRecord, XfrmObjectRosterDurableError> {
        let lease = self.lease()?;
        let inventory = lease.inventory()?;
        let (_, record) = lease.current_from_handle(&inventory, handle)?;
        if !fingerprints_equal(&record.roster_fingerprint, &roster_fingerprint) {
            return Err(XfrmObjectRosterDurableError::WrongBinding);
        }
        Ok(record.clone())
    }

    /// Encode a live actor-validated record as an authenticated current handle.
    ///
    /// # Errors
    ///
    /// Returns [`XfrmObjectRosterDurableError::WrongBinding`] or
    /// [`XfrmObjectRosterDurableError::WrongIncarnation`] when the record does
    /// not belong to this exact store lease.
    pub(crate) fn handle_for_record(
        &self,
        record: &DurableRosterRecord,
    ) -> Result<XfrmObjectRosterRecoveryHandle, XfrmObjectRosterDurableError> {
        let lease = self.lease()?;
        lease.validate_record_binding(record)?;
        record.handle(&lease.store.proof_key)
    }

    /// Report whether any roster keeps the writer gate closed, without
    /// mutating the store.
    ///
    /// # Errors
    ///
    /// Returns any inventory failure; an unreadable store never reports "no
    /// authority".
    pub(crate) fn has_unresolved_writer_authority(
        &self,
    ) -> Result<bool, XfrmObjectRosterDurableError> {
        let lease = self.lease()?;
        let inventory = lease.inventory()?;
        Ok(inventory.has_unresolved_writer_authority())
    }

    /// Burn a fresh global epoch before an independently issued XFRM mutation.
    ///
    /// The call is rejected while any roster is unresolved, so no cooperating
    /// replacement can race consumer bookkeeping or cleanup.
    ///
    /// # Errors
    ///
    /// Returns [`XfrmObjectRosterDurableError::InvalidTransition`] while a
    /// roster is unresolved and [`XfrmObjectRosterDurableError::Stale`] when
    /// the epoch counter would overflow.
    pub(crate) fn advance_writer_epoch(&self) -> Result<NonZeroU64, XfrmObjectRosterDurableError> {
        let lease = self.lease()?;
        let mut inventory = lease.inventory()?;
        if lease.prune_terminal_records(&inventory)? {
            inventory = lease.inventory()?;
        }
        if inventory.has_unresolved_writer_authority() {
            return Err(XfrmObjectRosterDurableError::InvalidTransition);
        }
        lease.advance_epoch(&inventory)
    }

    /// True only for clones sharing this exact open store lease.
    pub(crate) fn is_same_instance(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    /// Report whether a restored record's writer epoch equals the store's
    /// current epoch without exposing the epoch value.
    ///
    /// Recovery uses this as the per-delete freshness precondition: a stale
    /// epoch under an unresolved roster removes the proof's ordering guarantee
    /// and must be classified for repair, never deletion.
    ///
    /// # Errors
    ///
    /// Returns [`XfrmObjectRosterDurableError::WrongBinding`] when the record
    /// does not belong to this store lease.
    pub(crate) fn record_writer_epoch_is_current(
        &self,
        record: &DurableRosterRecord,
    ) -> Result<bool, XfrmObjectRosterDurableError> {
        let lease = self.lease()?;
        let inventory = lease.inventory()?;
        lease.validate_record_binding(record)?;
        Ok(record.writer_epoch == lease.current_epoch(&inventory)?)
    }

    /// Compute independent keyed fingerprints of one member's exact removal
    /// identity and complete install request without persisting either
    /// plaintext.
    ///
    /// # Errors
    ///
    /// Returns [`XfrmObjectRosterDurableError::NonExactRemovalIdentity`] when
    /// the request cannot select exactly one kernel object for removal.
    pub(crate) fn fingerprints_for_request(
        &self,
        request: &XfrmObjectInstallRequest,
    ) -> Result<XfrmObjectRosterMemberFingerprints, XfrmObjectRosterDurableError> {
        let removal = request.removal();
        validate_exact_lookup_mark(removal.lookup_mark(), "durable_roster.member.mark")
            .map_err(|_| XfrmObjectRosterDurableError::NonExactRemovalIdentity)?;
        let lease = self.lease()?;
        let key = lease.store.proof_key.canonical_mac_key();
        let deletion_identity = authenticate_deletion_identity(
            key,
            DELETION_IDENTITY_AUTH_DOMAIN,
            &removal,
            request.policy_if_id(),
        )
        .map_err(map_canonical_encode_error)?;
        let install_request =
            authenticate_install_request(key, INSTALL_REQUEST_AUTH_DOMAIN, request)
                .map_err(map_canonical_encode_error)?;
        Ok(XfrmObjectRosterMemberFingerprints {
            deletion_identity,
            install_request,
        })
    }

    /// Derive the default durable identity of one roster member.
    ///
    /// The identity is a keyed function of the group identity, generation, and
    /// ordinal, so it is stable across a restart without the consumer storing
    /// anything extra. A consumer that wants its own correlation supplies an
    /// explicit identity instead.
    ///
    /// # Errors
    ///
    /// Returns [`XfrmObjectRosterDurableError::Malformed`] when the ordinal
    /// exceeds [`XFRM_OBJECT_ROSTER_MAX_MEMBERS`] or the derivation lands on
    /// the reserved all-zero identity.
    pub(crate) fn derive_member_identity(
        &self,
        group_id: XfrmObjectRosterGroupId,
        generation: XfrmObjectRosterOperationGeneration,
        ordinal: usize,
    ) -> Result<XfrmObjectRosterMemberId, XfrmObjectRosterDurableError> {
        if ordinal >= XFRM_OBJECT_ROSTER_MAX_MEMBERS {
            return Err(XfrmObjectRosterDurableError::Malformed);
        }
        let lease = self.lease()?;
        let mut mac = lease
            .store
            .proof_key
            .canonical_mac_key()
            .begin(MEMBER_ID_AUTH_DOMAIN);
        mac_bytes(&mut mac, &group_id.0).map_err(map_canonical_encode_error)?;
        mac_u64(&mut mac, generation.get());
        mac_u8(
            &mut mac,
            u8::try_from(ordinal).map_err(|_| XfrmObjectRosterDurableError::Malformed)?,
        );
        let derived = mac.finalize();
        XfrmObjectRosterMemberId::from_bytes(array_at(derived.as_slice(), 0))
    }

    /// Compute the keyed digest that binds one ordered member set to a roster.
    ///
    /// The flow layer passes this back to [`Self::restore`] and
    /// [`Self::restore_handle`] as the exact-member-set binding check.
    ///
    /// # Errors
    ///
    /// Returns [`XfrmObjectRosterDurableError::Malformed`] for an empty or
    /// oversized member list.
    pub(crate) fn roster_fingerprint_for(
        &self,
        members: &[XfrmObjectRosterMemberMaterial],
    ) -> Result<[u8; 32], XfrmObjectRosterDurableError> {
        if members.is_empty() || members.len() > XFRM_OBJECT_ROSTER_MAX_MEMBERS {
            return Err(XfrmObjectRosterDurableError::Malformed);
        }
        let lease = self.lease()?;
        let slots = members
            .iter()
            .map(|material| DurableRosterMemberSlot::from_material(*material))
            .collect::<Vec<_>>();
        roster_fingerprint(
            lease.store.proof_key.canonical_mac_key(),
            &slots.iter().collect::<Vec<_>>(),
        )
    }

    /// Return the test-only publication ledger for this store lease.
    #[cfg(test)]
    pub(crate) fn publication_ledger(
        &self,
    ) -> Result<Vec<XfrmObjectRosterPublication>, XfrmObjectRosterDurableError> {
        self.inner
            .ledger
            .lock()
            .map(|ledger| ledger.clone())
            .map_err(|_| XfrmObjectRosterDurableError::Storage)
    }

    /// Test-only physical durability counter.
    ///
    /// Unlike [`Self::publication_ledger`], this counts successful filesystem
    /// synchronization barriers on the roster store itself.  The hot-path
    /// detector deliberately resets it after opening the store, so initial
    /// control-record construction is not mistaken for an admission barrier.
    #[cfg(test)]
    pub(crate) fn tests_reset_physical_barriers(&self) -> Result<(), XfrmObjectRosterDurableError> {
        let mut barriers = self
            .inner
            .physical_barriers
            .lock()
            .map_err(|_| XfrmObjectRosterDurableError::Storage)?;
        *barriers = 0;
        Ok(())
    }

    /// Return the test-only successful filesystem synchronization count.
    #[cfg(test)]
    pub(crate) fn tests_physical_barriers(&self) -> Result<usize, XfrmObjectRosterDurableError> {
        self.inner
            .physical_barriers
            .lock()
            .map(|barriers| *barriers)
            .map_err(|_| XfrmObjectRosterDurableError::Storage)
    }

    /// Test-only durable anomaly: burn the writer epoch underneath an
    /// unresolved roster.
    ///
    /// [`Self::advance_writer_epoch`] refuses this by design, and the store's
    /// lease is private, so the recovery detectors in the flow module cannot
    /// otherwise reproduce a storage rollback or an out-of-band epoch burn.
    /// Recovery must classify the resulting record for repair rather than let
    /// a stale proof authorize a deletion.
    #[cfg(test)]
    pub(crate) fn tests_force_advance_writer_epoch(
        &self,
    ) -> Result<NonZeroU64, XfrmObjectRosterDurableError> {
        let lease = self.lease()?;
        let inventory = lease.inventory()?;
        lease.advance_epoch(&inventory)
    }

    fn lease(&self) -> Result<StoreLease<'_>, XfrmObjectRosterDurableError> {
        if self.inner.owner_process_id == 0 || self.inner.owner_process_id != std::process::id() {
            return Err(XfrmObjectRosterDurableError::WrongIncarnation);
        }
        let process_guard = self
            .inner
            .process_lock
            .try_lock()
            .map_err(|error| match error {
                TryLockError::WouldBlock => XfrmObjectRosterDurableError::StoreBusy,
                TryLockError::Poisoned(_) => XfrmObjectRosterDurableError::Storage,
            })?;
        verify_visible_identity(&self.inner)?;
        Ok(StoreLease {
            store: &self.inner,
            _process_guard: process_guard,
        })
    }
}

impl fmt::Debug for XfrmObjectRosterRecoveryStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("XfrmObjectRosterRecoveryStore(<redacted>)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PublicationClass {
    Prepare,
    Transition,
    Finalize,
}

impl StoreLease<'_> {
    fn inventory(&self) -> Result<Inventory, XfrmObjectRosterDurableError> {
        verify_visible_identity(self.store)?;
        let mut control_count = 0_usize;
        let mut epochs = Vec::new();
        let mut records = Vec::new();
        let mut journal = None;
        let mut seen_names = BTreeMap::<String, ()>::new();
        let directory = Dir::read_from(&self.store.descriptor)
            .map_err(|_| XfrmObjectRosterDurableError::Storage)?;
        for entry in directory {
            let entry = entry.map_err(|_| XfrmObjectRosterDurableError::Storage)?;
            let raw_name = entry.file_name().to_bytes();
            if raw_name == b"." || raw_name == b".." {
                continue;
            }
            if seen_names.len() >= MAX_STORE_ENTRIES {
                return Err(XfrmObjectRosterDurableError::Malformed);
            }
            let name = std::str::from_utf8(raw_name)
                .map_err(|_| XfrmObjectRosterDurableError::Malformed)?
                .to_owned();
            if seen_names.insert(name.clone(), ()).is_some() {
                return Err(XfrmObjectRosterDurableError::Duplicate);
            }
            if name == CONTROL_NAME {
                control_count += 1;
                let encoded = read_fixed_file::<CONTROL_BYTES>(self.store, &name)?;
                let control = ControlRecord::decode(&encoded, &self.store.proof_key)?;
                if control != self.store.control {
                    return Err(XfrmObjectRosterDurableError::WrongBinding);
                }
                continue;
            }
            if name.starts_with("epoch-") {
                let expected_epoch =
                    parse_epoch_name(&name).ok_or(XfrmObjectRosterDurableError::Malformed)?;
                let encoded = read_fixed_file::<EPOCH_BYTES>(self.store, &name)?;
                let decoded = EpochRecord::decode(&encoded, &self.store.proof_key)?;
                if decoded.store_incarnation != self.store.control.store_incarnation {
                    return Err(XfrmObjectRosterDurableError::WrongBinding);
                }
                if decoded.epoch != expected_epoch || name != epoch_name(decoded.epoch) {
                    return Err(XfrmObjectRosterDurableError::Malformed);
                }
                epochs.push((name, decoded));
                continue;
            }
            if name == JOURNAL_NAME {
                if !self.store.journal_enabled || journal.is_some() {
                    return Err(XfrmObjectRosterDurableError::Malformed);
                }
                let (journal_epoch, decoded) = read_journal_records(self.store)?;
                for record in &decoded {
                    self.validate_record_binding(record)?;
                }
                journal = Some((journal_epoch, decoded));
                continue;
            }
            let parsed = parse_record_name(OsStr::from_bytes(raw_name))
                .ok_or(XfrmObjectRosterDurableError::Malformed)?;
            let encoded =
                read_fixed_file::<XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES>(self.store, &name)?;
            let record = DurableRosterRecord::decode(&encoded, &self.store.proof_key)?;
            if parsed
                != (
                    record.phase,
                    record.group_id,
                    record.group_generation,
                    record.publication_sequence,
                )
                || name != record_name(&record)
            {
                return Err(XfrmObjectRosterDurableError::Malformed);
            }
            self.validate_record_binding(&record)?;
            records.push((name, record));
        }
        if control_count != 1 {
            return Err(if control_count > 1 {
                XfrmObjectRosterDurableError::Duplicate
            } else {
                XfrmObjectRosterDurableError::Malformed
            });
        }
        // Decide every recovery action before removing any entry. Arbitrary
        // duplicates remain fail-closed; only the exact adjacent publications
        // that this module itself can leave between fsync and unlink are
        // completed deterministically.
        let (epoch_name, legacy_epoch, obsolete_epoch) = classify_epoch_records(epochs)?;
        let journal_enabled = journal.is_some();
        if journal_enabled != self.store.journal_enabled || (journal_enabled && !records.is_empty())
        {
            return Err(XfrmObjectRosterDurableError::Malformed);
        }
        let (journal_epoch, records, obsolete_records) = match journal {
            Some((epoch, records)) => {
                (epoch, classify_journal_roster_records(records)?, Vec::new())
            }
            None => {
                let (records, obsolete) = classify_roster_records(records, legacy_epoch)?;
                (legacy_epoch, records, obsolete)
            }
        };
        // Journal frames carry their own writer epoch.  The durable current
        // epoch is therefore the greater of the legacy bootstrap/explicit
        // witness and every authenticated current roster record.
        let epoch = records
            .iter()
            .map(|(_, record)| record.writer_epoch)
            .max()
            .map_or(journal_epoch.max(legacy_epoch), |record_epoch| {
                record_epoch.max(journal_epoch).max(legacy_epoch)
            });
        validate_unique_active_deletion_identities(&records)?;
        validate_single_cleanup_authority(&records)?;
        if let Some(name) = obsolete_epoch {
            self.remove_epoch(&name)?;
        }
        for name in obsolete_records {
            self.remove_record(&name)?;
        }
        Ok(Inventory {
            records,
            epoch_name,
            epoch,
            journal: journal_enabled,
        })
    }

    fn validate_record_binding(
        &self,
        record: &DurableRosterRecord,
    ) -> Result<(), XfrmObjectRosterDurableError> {
        if record.store_incarnation != self.store.control.store_incarnation
            || record.namespace_seal != self.store.control.namespace_seal
        {
            return Err(XfrmObjectRosterDurableError::WrongBinding);
        }
        if record.actor_incarnation != self.store.control.actor_incarnation {
            return Err(XfrmObjectRosterDurableError::WrongIncarnation);
        }
        Ok(())
    }

    fn current_from_handle<'a>(
        &self,
        inventory: &'a Inventory,
        handle: &XfrmObjectRosterRecoveryHandle,
    ) -> Result<(&'a str, &'a DurableRosterRecord), XfrmObjectRosterDurableError> {
        let correlation = DurableRosterRecord::decode(&handle.0, &self.store.proof_key)?;
        self.validate_record_binding(&correlation)?;
        let (name, current) =
            inventory.current_for(correlation.group_id, correlation.group_generation)?;
        if current.store_incarnation != correlation.store_incarnation
            || current.namespace_seal != correlation.namespace_seal
            || current.actor_incarnation != correlation.actor_incarnation
            || !fingerprints_equal(&current.roster_fingerprint, &correlation.roster_fingerprint)
            || !members_share_identity(current, &correlation)
        {
            return Err(XfrmObjectRosterDurableError::WrongBinding);
        }
        if current.phase != correlation.phase
            || current.cursor != correlation.cursor
            || current.publication_sequence != correlation.publication_sequence
            || current.writer_epoch != correlation.writer_epoch
            || !members_share_state(current, &correlation)
        {
            return Err(XfrmObjectRosterDurableError::Stale);
        }
        Ok((name, current))
    }

    fn current_epoch(
        &self,
        inventory: &Inventory,
    ) -> Result<NonZeroU64, XfrmObjectRosterDurableError> {
        Ok(inventory.epoch)
    }

    fn publish_record(
        &self,
        record: &DurableRosterRecord,
        class: PublicationClass,
    ) -> Result<(), XfrmObjectRosterDurableError> {
        self.validate_record_binding(record)?;
        let bytes = record.encode(&self.store.proof_key)?;
        if self.store.journal_enabled {
            append_journal_record(self.store, &bytes, record.writer_epoch)?;
        } else {
            let name = record_name(record);
            publish_new_file(self.store, &name, &bytes)?;
        }
        #[cfg(test)]
        {
            let mut ledger = self
                .store
                .ledger
                .lock()
                .map_err(|_| XfrmObjectRosterDurableError::Storage)?;
            ledger.push(XfrmObjectRosterPublication {
                sequence: record.publication_sequence,
                phase: record.phase,
                class: match class {
                    PublicationClass::Prepare => XfrmObjectRosterPublicationClass::Prepare,
                    PublicationClass::Transition => XfrmObjectRosterPublicationClass::Transition,
                    PublicationClass::Finalize => XfrmObjectRosterPublicationClass::Finalize,
                },
            });
        }
        #[cfg(not(test))]
        let _ = class;
        Ok(())
    }

    fn advance_epoch(
        &self,
        inventory: &Inventory,
    ) -> Result<NonZeroU64, XfrmObjectRosterDurableError> {
        let epoch = inventory
            .epoch
            .get()
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .ok_or(XfrmObjectRosterDurableError::Stale)?;
        let record = EpochRecord {
            store_incarnation: self.store.control.store_incarnation,
            epoch,
        };
        let next_name = epoch_name(epoch);
        publish_new_file(
            self.store,
            &next_name,
            &record.encode(&self.store.proof_key)?,
        )?;
        self.remove_epoch(&inventory.epoch_name)?;
        Ok(epoch)
    }

    fn prune_terminal_records(
        &self,
        inventory: &Inventory,
    ) -> Result<bool, XfrmObjectRosterDurableError> {
        let names = inventory
            .records
            .iter()
            .filter(|(_, record)| record.phase.is_terminal())
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        if inventory.journal {
            if !names.is_empty() {
                compact_journal(
                    self.store,
                    &inventory
                        .records
                        .iter()
                        .filter(|(_, record)| !record.phase.is_terminal())
                        .map(|(_, record)| record.clone())
                        .collect::<Vec<_>>(),
                    inventory.epoch,
                )?;
            }
        } else {
            for name in &names {
                self.remove_record(name)?;
            }
        }
        Ok(!names.is_empty())
    }

    fn remove_epoch(&self, name: &str) -> Result<(), XfrmObjectRosterDurableError> {
        parse_epoch_name(name).ok_or(XfrmObjectRosterDurableError::Malformed)?;
        unlinkat(self.store.descriptor.as_fd(), name, AtFlags::empty())
            .map_err(|_| XfrmObjectRosterDurableError::Storage)?;
        fsync(&self.store.descriptor).map_err(|_| XfrmObjectRosterDurableError::Storage)?;
        #[cfg(test)]
        record_physical_barrier(self.store)?;
        Ok(())
    }

    fn remove_record(&self, name: &str) -> Result<(), XfrmObjectRosterDurableError> {
        validate_record_name(OsStr::new(name))?;
        unlinkat(self.store.descriptor.as_fd(), name, AtFlags::empty())
            .map_err(|_| XfrmObjectRosterDurableError::Storage)?;
        fsync(&self.store.descriptor).map_err(|_| XfrmObjectRosterDurableError::Storage)?;
        #[cfg(test)]
        record_physical_barrier(self.store)?;
        Ok(())
    }
}

#[cfg(test)]
fn record_physical_barrier(store: &StoreInner) -> Result<(), XfrmObjectRosterDurableError> {
    let mut barriers = store
        .physical_barriers
        .lock()
        .map_err(|_| XfrmObjectRosterDurableError::Storage)?;
    *barriers = barriers
        .checked_add(1)
        .ok_or(XfrmObjectRosterDurableError::Storage)?;
    Ok(())
}

fn members_share_identity(left: &DurableRosterRecord, right: &DurableRosterRecord) -> bool {
    left.members
        .iter()
        .zip(right.members.iter())
        .all(|(left, right)| match (left, right) {
            (None, None) => true,
            (Some(left), Some(right)) => left.same_identity(right),
            _ => false,
        })
}

fn members_share_state(left: &DurableRosterRecord, right: &DurableRosterRecord) -> bool {
    left.members
        .iter()
        .zip(right.members.iter())
        .all(|(left, right)| match (left, right) {
            (None, None) => true,
            (Some(left), Some(right)) => {
                left.phase == right.phase
                    && left.sweep_proof == right.sweep_proof
                    && left.adjacent_proof == right.adjacent_proof
            }
            _ => false,
        })
}

fn classify_epoch_records(
    mut epochs: Vec<(String, EpochRecord)>,
) -> Result<(String, NonZeroU64, Option<String>), XfrmObjectRosterDurableError> {
    match epochs.len() {
        0 => Err(XfrmObjectRosterDurableError::Malformed),
        1 => {
            let (name, record) = epochs
                .pop()
                .ok_or(XfrmObjectRosterDurableError::Malformed)?;
            Ok((name, record.epoch, None))
        }
        // Epoch advancement publishes the successor before unlinking its
        // predecessor, so exactly two consecutive witnesses of one store
        // incarnation are the only duplicate this module can leave behind.
        2 => {
            epochs.sort_by_key(|(_, record)| record.epoch);
            let (lower_name, lower) = epochs.remove(0);
            let (upper_name, upper) = epochs.remove(0);
            if lower.store_incarnation != upper.store_incarnation
                || lower.epoch.get().checked_add(1) != Some(upper.epoch.get())
            {
                return Err(XfrmObjectRosterDurableError::Duplicate);
            }
            Ok((upper_name, upper.epoch, Some(lower_name)))
        }
        _ => Err(XfrmObjectRosterDurableError::Duplicate),
    }
}

fn classify_roster_records(
    records: Vec<NamedRosterRecord>,
    current_epoch: NonZeroU64,
) -> Result<ReconciledRosterRecords, XfrmObjectRosterDurableError> {
    let mut groups = BTreeMap::<([u8; 16], u64), Vec<NamedRosterRecord>>::new();
    for entry in records {
        groups
            .entry((entry.1.group_id.0, entry.1.group_generation.get()))
            .or_default()
            .push(entry);
    }
    let mut current = Vec::new();
    let mut obsolete = Vec::new();
    for mut group in groups.into_values() {
        match group.len() {
            1 => current.push(group.pop().ok_or(XfrmObjectRosterDurableError::Malformed)?),
            2 => {
                let right = group.pop().ok_or(XfrmObjectRosterDurableError::Duplicate)?;
                let left = group.pop().ok_or(XfrmObjectRosterDurableError::Duplicate)?;
                let (old, next) =
                    if is_exact_roster_publication_successor(&left.1, &right.1, current_epoch) {
                        (left, right)
                    } else if is_exact_roster_publication_successor(
                        &right.1,
                        &left.1,
                        current_epoch,
                    ) {
                        (right, left)
                    } else {
                        return Err(XfrmObjectRosterDurableError::Duplicate);
                    };
                obsolete.push(old.0);
                current.push(next);
            }
            _ => return Err(XfrmObjectRosterDurableError::Duplicate),
        }
    }
    Ok((current, obsolete))
}

/// Collapse append-journal history to one current record per group.
///
/// Every retained frame is an independently authenticated durable record.  A
/// journal may therefore contain more than the two adjacent files accepted by
/// the legacy publish-then-unlink layout, but it accepts only a complete
/// sequence beginning at `Prepared` and linked by the existing exact
/// successor validator.  This makes a crash after any logical transition
/// recoverable from that transition without ever treating an arbitrary older
/// record as current cleanup authority.
fn classify_journal_roster_records(
    records: Vec<DurableRosterRecord>,
) -> Result<Vec<NamedRosterRecord>, XfrmObjectRosterDurableError> {
    let mut groups = BTreeMap::<([u8; 16], u64), Vec<DurableRosterRecord>>::new();
    for record in records {
        groups
            .entry((record.group_id.0, record.group_generation.get()))
            .or_default()
            .push(record);
    }
    let mut current = Vec::with_capacity(groups.len());
    for mut history in groups.into_values() {
        history.sort_by_key(|record| record.publication_sequence);
        let first = history
            .first()
            .ok_or(XfrmObjectRosterDurableError::Malformed)?;
        if first.publication_sequence != 1
            || first.phase != XfrmObjectRosterDurablePhase::Prepared
            || first.cursor != 0
        {
            return Err(XfrmObjectRosterDurableError::Duplicate);
        }
        validate_roster_record(first)?;
        for pair in history.windows(2) {
            let [old, next] = pair else {
                return Err(XfrmObjectRosterDurableError::Malformed);
            };
            if !is_exact_roster_publication_successor(old, next, next.writer_epoch) {
                return Err(XfrmObjectRosterDurableError::Duplicate);
            }
            validate_roster_record(next)?;
        }
        let record = history
            .pop()
            .ok_or(XfrmObjectRosterDurableError::Malformed)?;
        current.push((record_name(&record), record));
    }
    Ok(current)
}

fn validate_unique_active_deletion_identities(
    records: &[NamedRosterRecord],
) -> Result<(), XfrmObjectRosterDurableError> {
    for (index, (_, left)) in records.iter().enumerate() {
        if left.phase.is_terminal() {
            continue;
        }
        for slot in left.members.iter().flatten() {
            if records[index + 1..].iter().any(|(_, right)| {
                !right.phase.is_terminal()
                    && right.members.iter().flatten().any(|other| {
                        fingerprints_equal(
                            &slot.deletion_identity_fingerprint,
                            &other.deletion_identity_fingerprint,
                        )
                    })
            }) {
                return Err(XfrmObjectRosterDurableError::Duplicate);
            }
        }
    }
    Ok(())
}

fn validate_single_cleanup_authority(
    records: &[NamedRosterRecord],
) -> Result<(), XfrmObjectRosterDurableError> {
    if records
        .iter()
        .filter(|(_, record)| record.phase.is_unresolved_writer_authority())
        .take(2)
        .count()
        > 1
    {
        return Err(XfrmObjectRosterDurableError::Duplicate);
    }
    Ok(())
}

/// Whether `next` is the exact publication that follows `old`.
///
/// The checks run in a fixed order and every one of them must hold:
///
/// 1. identical store, namespace, actor, group, generation, arity, roster
///    digest, and per-member durable identity;
/// 2. `next.publication_sequence == old.publication_sequence + 1`, which is the
///    total order and the sole ordering authority;
/// 3. `old.phase.permits(next.phase)`;
/// 4. per-slot edge legality for phase and both proofs;
/// 5. cursor monotonicity, non-decreasing while issuing and non-increasing
///    while compensating;
/// 6. epoch, which advances exactly once on `Prepared -> Issuing` and is
///    preserved by every other edge.
fn is_exact_roster_publication_successor(
    old: &DurableRosterRecord,
    next: &DurableRosterRecord,
    current_epoch: NonZeroU64,
) -> bool {
    if old.store_incarnation != next.store_incarnation
        || old.namespace_seal != next.namespace_seal
        || old.actor_incarnation != next.actor_incarnation
        || old.group_id != next.group_id
        || old.group_generation != next.group_generation
        || !fingerprints_equal(&old.roster_fingerprint, &next.roster_fingerprint)
        || !members_share_identity(old, next)
    {
        return false;
    }
    if old.publication_sequence.checked_add(1) != Some(next.publication_sequence) {
        return false;
    }
    if !old.phase.permits(next.phase) {
        return false;
    }
    let slots_advance = old
        .members
        .iter()
        .zip(next.members.iter())
        .all(|(old, next)| match (old, next) {
            (None, None) => true,
            (Some(old), Some(next)) => {
                old.phase.permits(next.phase)
                    && sweep_proof_permits(old.sweep_proof, next.sweep_proof)
                    && adjacent_proof_permits(old.adjacent_proof, next.adjacent_proof)
            }
            _ => false,
        });
    if !slots_advance {
        return false;
    }
    let cursor_ok = match (old.phase, next.phase) {
        (XfrmObjectRosterDurablePhase::Prepared, XfrmObjectRosterDurablePhase::Issuing) => {
            next.cursor == 0
        }
        (XfrmObjectRosterDurablePhase::Issuing, XfrmObjectRosterDurablePhase::Issuing) => {
            old.cursor.checked_add(1) == Some(next.cursor)
        }
        (_, XfrmObjectRosterDurablePhase::Compensating) => next.cursor <= old.cursor,
        (_, XfrmObjectRosterDurablePhase::Retired) => next.cursor == old.cursor,
        _ => true,
    };
    if !cursor_ok {
        return false;
    }
    if next.phase == XfrmObjectRosterDurablePhase::Issuing
        && old.phase == XfrmObjectRosterDurablePhase::Prepared
    {
        next.writer_epoch == current_epoch && next.writer_epoch > old.writer_epoch
    } else {
        next.writer_epoch == old.writer_epoch
    }
}

fn sweep_proof_permits(
    old: Option<XfrmObjectRosterSweepProof>,
    next: Option<XfrmObjectRosterSweepProof>,
) -> bool {
    match (old, next) {
        (None, _) => true,
        (Some(old), Some(next)) => old == next,
        (Some(_), None) => false,
    }
}

fn adjacent_proof_permits(
    old: Option<XfrmObjectRosterAdjacentProof>,
    next: Option<XfrmObjectRosterAdjacentProof>,
) -> bool {
    match (old, next) {
        (None, _) => true,
        // A member issued under an absence proof may still be told the object
        // exists; every other recorded proof is immutable.
        (
            Some(XfrmObjectRosterAdjacentProof::Absent),
            Some(XfrmObjectRosterAdjacentProof::AbsentThenAlreadyExists),
        ) => true,
        (Some(old), Some(next)) => old == next,
        (Some(_), None) => false,
    }
}

fn create_root_if_absent(path: &Path) -> Result<(), XfrmObjectRosterDurableError> {
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(DIRECTORY_MODE);
    match builder.create(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(_) => Err(XfrmObjectRosterDurableError::Storage),
    }
}

fn valid_store_path(path: &Path) -> bool {
    let bytes = path.as_os_str().as_bytes();
    path.is_absolute()
        && path.file_name().is_some()
        && !bytes.is_empty()
        && bytes.len() <= MAX_STORE_PATH_BYTES
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

fn sync_store_root_parent(path: &Path, root: &OwnedFd) -> Result<(), XfrmObjectRosterDurableError> {
    let parent = path
        .parent()
        .ok_or(XfrmObjectRosterDurableError::InvalidStoreRoot)?;
    let child_name = path
        .file_name()
        .ok_or(XfrmObjectRosterDurableError::InvalidStoreRoot)?;
    let parent_descriptor = open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(map_root_open_error)?;
    let parent_metadata =
        fstat(&parent_descriptor).map_err(|_| XfrmObjectRosterDurableError::Storage)?;
    let parent_is_untrusted_writable =
        parent_metadata.st_mode & 0o022 != 0 && parent_metadata.st_mode & 0o1000 == 0;
    if !FileType::from_raw_mode(parent_metadata.st_mode).is_dir()
        || parent_metadata.st_nlink == 0
        || parent_is_untrusted_writable
    {
        return Err(XfrmObjectRosterDurableError::InvalidStoreRoot);
    }

    let reopened = openat(
        parent_descriptor.as_fd(),
        child_name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(map_root_open_error)?;
    let expected = fstat(root).map_err(|_| XfrmObjectRosterDurableError::Storage)?;
    let observed = fstat(&reopened).map_err(|_| XfrmObjectRosterDurableError::Storage)?;
    validate_root_metadata(&observed)?;
    if expected.st_dev != observed.st_dev || expected.st_ino != observed.st_ino {
        return Err(XfrmObjectRosterDurableError::InvalidStoreRoot);
    }
    fsync(&parent_descriptor).map_err(|_| XfrmObjectRosterDurableError::Storage)
}

fn validate_root_metadata(metadata: &rustix::fs::Stat) -> Result<(), XfrmObjectRosterDurableError> {
    if !FileType::from_raw_mode(metadata.st_mode).is_dir()
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_mode.store_permissions() != DIRECTORY_MODE
        || metadata.st_nlink == 0
    {
        return Err(XfrmObjectRosterDurableError::InvalidStoreRoot);
    }
    Ok(())
}

fn stat_device(metadata: &rustix::fs::Stat) -> Result<u64, XfrmObjectRosterDurableError> {
    metadata
        .st_dev
        .store_identity()
        .ok_or(XfrmObjectRosterDurableError::InvalidStoreRoot)
}

fn stat_inode(metadata: &rustix::fs::Stat) -> Result<u64, XfrmObjectRosterDurableError> {
    metadata
        .st_ino
        .store_identity()
        .ok_or(XfrmObjectRosterDurableError::InvalidStoreRoot)
}

trait StoreIdentityValue {
    fn store_identity(self) -> Option<u64>;
}

impl StoreIdentityValue for u64 {
    fn store_identity(self) -> Option<u64> {
        Some(self)
    }
}

impl StoreIdentityValue for u32 {
    fn store_identity(self) -> Option<u64> {
        Some(u64::from(self))
    }
}

impl StoreIdentityValue for i64 {
    fn store_identity(self) -> Option<u64> {
        u64::try_from(self).ok()
    }
}

impl StoreIdentityValue for i32 {
    fn store_identity(self) -> Option<u64> {
        u64::try_from(self).ok()
    }
}

trait StoreModeValue {
    fn store_permissions(self) -> u32;
}

impl StoreModeValue for u32 {
    fn store_permissions(self) -> u32 {
        self & 0o7777
    }
}

impl StoreModeValue for u16 {
    fn store_permissions(self) -> u32 {
        u32::from(self & 0o7777)
    }
}

fn map_root_open_error(error: rustix::io::Errno) -> XfrmObjectRosterDurableError {
    if matches!(error, rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) {
        XfrmObjectRosterDurableError::InvalidStoreRoot
    } else {
        XfrmObjectRosterDurableError::Storage
    }
}

fn verify_visible_identity(store: &StoreInner) -> Result<(), XfrmObjectRosterDurableError> {
    if store.owner_process_id != std::process::id() {
        return Err(XfrmObjectRosterDurableError::WrongIncarnation);
    }
    let visible = open(
        &store.visible_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(map_root_open_error)?;
    let metadata = fstat(&visible).map_err(|_| XfrmObjectRosterDurableError::Storage)?;
    validate_root_metadata(&metadata)?;
    if stat_device(&metadata)? != store.root_device
        || stat_inode(&metadata)? != store.root_inode
        || metadata.st_uid != store.root_owner
    {
        return Err(XfrmObjectRosterDurableError::InvalidStoreRoot);
    }
    Ok(())
}

fn initialize_or_load_control(
    store: &StoreInner,
    namespace_seal: [u8; 32],
) -> Result<ControlRecord, XfrmObjectRosterDurableError> {
    verify_visible_identity(store)?;
    cleanup_interrupted_publications(store)?;
    let names = scan_raw_names(store)?;
    if names.is_empty() {
        let control = ControlRecord {
            store_incarnation: random_nonzero_16()?,
            namespace_seal,
            actor_incarnation: random_nonzero_16()?,
            root_device: store.root_device,
            root_inode: store.root_inode,
        };
        publish_new_file(store, CONTROL_NAME, &control.encode(&store.proof_key)?)?;
        let epoch = EpochRecord {
            store_incarnation: control.store_incarnation,
            epoch: NonZeroU64::new(1).ok_or(XfrmObjectRosterDurableError::Malformed)?,
        };
        publish_new_file(
            store,
            &epoch_name(epoch.epoch),
            &epoch.encode(&store.proof_key)?,
        )?;
        return Ok(control);
    }
    if !names.iter().any(|name| name == CONTROL_NAME) {
        return Err(XfrmObjectRosterDurableError::Malformed);
    }
    let encoded = read_fixed_file::<CONTROL_BYTES>(store, CONTROL_NAME)?;
    let control = ControlRecord::decode(&encoded, &store.proof_key)?;
    if control.namespace_seal != namespace_seal
        || control.root_device != store.root_device
        || control.root_inode != store.root_inode
    {
        return Err(XfrmObjectRosterDurableError::WrongBinding);
    }
    // First initialization publishes `control` before epoch 1. A process loss
    // between those two fsyncs leaves this one exact, authenticated safe
    // residue. No mutation can have been admitted yet, so completing epoch 1
    // is deterministic. Any additional or different entry remains fail-closed
    // in the bounded inventory scan.
    if names.len() == 1
        || (names.len() == 2
            && names.iter().any(|name| name == JOURNAL_NAME)
            && names.iter().any(|name| name == CONTROL_NAME))
    {
        let epoch = EpochRecord {
            store_incarnation: control.store_incarnation,
            epoch: NonZeroU64::new(1).ok_or(XfrmObjectRosterDurableError::Malformed)?,
        };
        publish_new_file(
            store,
            &epoch_name(epoch.epoch),
            &epoch.encode(&store.proof_key)?,
        )?;
    }
    Ok(control)
}

/// Enable the grouped publication path only for a fresh roster root.
///
/// Existing roots with named roster records keep their established
/// publish-successor recovery format.  This avoids a format migration during
/// recovery: a fresh root gets the journal before its first `Prepared`
/// publication, while an old root remains wholly on the legacy path.
fn initialize_journal_mode(store: &StoreInner) -> Result<bool, XfrmObjectRosterDurableError> {
    let names = scan_raw_names(store)?;
    if names.iter().any(|name| name == JOURNAL_NAME) {
        return Ok(true);
    }
    if names
        .iter()
        .all(|name| name == CONTROL_NAME || name.starts_with("epoch-"))
    {
        let header = EpochRecord {
            store_incarnation: store.control.store_incarnation,
            epoch: NonZeroU64::new(1).ok_or(XfrmObjectRosterDurableError::Malformed)?,
        };
        publish_new_file(store, JOURNAL_NAME, &header.encode(&store.proof_key)?)?;
        return Ok(true);
    }
    Ok(false)
}

fn scan_raw_names(store: &StoreInner) -> Result<Vec<String>, XfrmObjectRosterDurableError> {
    let directory =
        Dir::read_from(&store.descriptor).map_err(|_| XfrmObjectRosterDurableError::Storage)?;
    let mut names = Vec::new();
    for entry in directory {
        let entry = entry.map_err(|_| XfrmObjectRosterDurableError::Storage)?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        if names.len() >= MAX_STORE_ENTRIES {
            return Err(XfrmObjectRosterDurableError::Malformed);
        }
        names.push(
            std::str::from_utf8(name)
                .map_err(|_| XfrmObjectRosterDurableError::Malformed)?
                .to_owned(),
        );
    }
    Ok(names)
}

/// Remove only SDK-owned named staging files left by process death before
/// their atomic rename. Unknown entries and unsafe lookalikes remain
/// fail-closed; the store root is a trusted, permanently leased directory.
fn cleanup_interrupted_publications(
    store: &StoreInner,
) -> Result<(), XfrmObjectRosterDurableError> {
    let names = scan_raw_names(store)?;
    let mut removed = false;
    for name in names {
        if !is_temporary_name(&name) {
            continue;
        }
        let descriptor = openat(
            store.descriptor.as_fd(),
            name.as_str(),
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| XfrmObjectRosterDurableError::Malformed)?;
        let metadata = fstat(&descriptor).map_err(|_| XfrmObjectRosterDurableError::Storage)?;
        if !FileType::from_raw_mode(metadata.st_mode).is_file()
            || stat_device(&metadata)? != store.root_device
            || metadata.st_uid != store.root_owner
            || metadata.st_mode.store_permissions() != FILE_MODE
            || metadata.st_nlink != 1
            || metadata.st_size < 0
            || metadata.st_size > MAX_JOURNAL_BYTES as i64
        {
            return Err(XfrmObjectRosterDurableError::Malformed);
        }
        unlinkat(store.descriptor.as_fd(), name.as_str(), AtFlags::empty())
            .map_err(|_| XfrmObjectRosterDurableError::Storage)?;
        removed = true;
    }
    if removed {
        fsync(&store.descriptor).map_err(|_| XfrmObjectRosterDurableError::Storage)?;
    }
    Ok(())
}

fn read_fixed_file<const N: usize>(
    store: &StoreInner,
    name: &str,
) -> Result<[u8; N], XfrmObjectRosterDurableError> {
    // `O_NONBLOCK` so that a FIFO planted in the leased root under a
    // well-formed entry name cannot park the whole namespace actor inside
    // `open`. `validate_file_metadata` below still rejects everything that is
    // not a regular file, but it only runs once the open returns, and every
    // actor command is serialized behind this scan.
    let descriptor = openat(
        store.descriptor.as_fd(),
        name,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| XfrmObjectRosterDurableError::Malformed)?;
    validate_file_metadata(store, &descriptor, N)?;
    let mut file = std::fs::File::from(descriptor);
    let mut bytes = [0_u8; N];
    file.read_exact(&mut bytes)
        .map_err(|_| XfrmObjectRosterDurableError::Malformed)?;
    let mut trailing = [0_u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|_| XfrmObjectRosterDurableError::Storage)?
        != 0
    {
        return Err(XfrmObjectRosterDurableError::Malformed);
    }
    Ok(bytes)
}

fn journal_frame_count<F: AsFd>(
    store: &StoreInner,
    descriptor: F,
) -> Result<usize, XfrmObjectRosterDurableError> {
    let (frames, trailing_bytes) = journal_frame_layout(store, descriptor)?;
    if trailing_bytes != 0 {
        return Err(XfrmObjectRosterDurableError::Malformed);
    }
    Ok(frames)
}

/// Return the authenticated-frame prefix and any incomplete trailing bytes.
///
/// A process loss during an append may leave a torn final write even though
/// the preceding frame was already synchronized.  A non-frame tail has never
/// been an acknowledged logical publication, so recovery may discard exactly
/// that tail and resume from the preceding complete record.  A full frame
/// with a bad tag is deliberately *not* treated this way: it could be
/// corruption of an acknowledged transition and must remain fail-closed.
fn journal_frame_layout<F: AsFd>(
    store: &StoreInner,
    descriptor: F,
) -> Result<(usize, usize), XfrmObjectRosterDurableError> {
    let metadata = fstat(descriptor).map_err(|_| XfrmObjectRosterDurableError::Storage)?;
    if !FileType::from_raw_mode(metadata.st_mode).is_file()
        || stat_device(&metadata)? != store.root_device
        || metadata.st_uid != store.root_owner
        || metadata.st_mode.store_permissions() != FILE_MODE
        || metadata.st_nlink != 1
        || metadata.st_size < 0
        || metadata.st_size > MAX_JOURNAL_BYTES as i64
        || metadata.st_size < JOURNAL_HEADER_BYTES as i64
    {
        return Err(XfrmObjectRosterDurableError::Malformed);
    }
    let payload = usize::try_from(metadata.st_size - JOURNAL_HEADER_BYTES as i64)
        .map_err(|_| XfrmObjectRosterDurableError::Malformed)?;
    Ok((
        payload / XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES,
        payload % XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES,
    ))
}

fn read_journal_records(
    store: &StoreInner,
) -> Result<(NonZeroU64, Vec<DurableRosterRecord>), XfrmObjectRosterDurableError> {
    let descriptor = openat(
        store.descriptor.as_fd(),
        JOURNAL_NAME,
        OFlags::RDWR | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| XfrmObjectRosterDurableError::Malformed)?;
    let (frames, trailing_bytes) = journal_frame_layout(store, &descriptor)?;
    let mut file = std::fs::File::from(descriptor);
    if trailing_bytes != 0 {
        let length = JOURNAL_HEADER_BYTES
            .checked_add(
                frames
                    .checked_mul(XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES)
                    .ok_or(XfrmObjectRosterDurableError::Malformed)?,
            )
            .ok_or(XfrmObjectRosterDurableError::Malformed)?;
        file.set_len(u64::try_from(length).map_err(|_| XfrmObjectRosterDurableError::Malformed)?)
            .map_err(|_| XfrmObjectRosterDurableError::Storage)?;
        file.sync_all()
            .map_err(|_| XfrmObjectRosterDurableError::Storage)?;
        #[cfg(test)]
        record_physical_barrier(store)?;
    }
    let mut header = [0_u8; JOURNAL_HEADER_BYTES];
    file.read_exact(&mut header)
        .map_err(|_| XfrmObjectRosterDurableError::Malformed)?;
    let header = EpochRecord::decode(&header, &store.proof_key)?;
    if header.store_incarnation != store.control.store_incarnation {
        return Err(XfrmObjectRosterDurableError::WrongBinding);
    }
    let mut bytes = vec![0_u8; frames * XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES];
    file.read_exact(&mut bytes)
        .map_err(|_| XfrmObjectRosterDurableError::Malformed)?;
    let (encoded_records, remainder) =
        bytes.as_chunks::<XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES>();
    if !remainder.is_empty() {
        return Err(XfrmObjectRosterDurableError::Malformed);
    }
    let records = encoded_records
        .iter()
        .map(|encoded| DurableRosterRecord::decode(encoded, &store.proof_key))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((header.epoch, records))
}

/// Append one complete, authenticated logical publication and synchronize the
/// already-created journal descriptor.  The record itself remains the
/// recovery handle's exact fixed-size byte format; only its physical container
/// changes, so every logical transition remains individually crash-visible.
fn append_journal_record(
    store: &StoreInner,
    bytes: &[u8; XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES],
    writer_epoch: NonZeroU64,
) -> Result<(), XfrmObjectRosterDurableError> {
    verify_visible_identity(store)?;
    let descriptor = openat(
        store.descriptor.as_fd(),
        JOURNAL_NAME,
        OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| XfrmObjectRosterDurableError::Storage)?;
    let frames = journal_frame_count(store, &descriptor)?;
    if frames >= MAX_JOURNAL_FRAMES {
        return Err(XfrmObjectRosterDurableError::CapacityExceeded);
    }
    let mut file = std::fs::File::from(descriptor);
    let mut header = [0_u8; JOURNAL_HEADER_BYTES];
    file.read_exact(&mut header)
        .map_err(|_| XfrmObjectRosterDurableError::Storage)?;
    let header = EpochRecord::decode(&header, &store.proof_key)?;
    if header.store_incarnation != store.control.store_incarnation || writer_epoch < header.epoch {
        return Err(XfrmObjectRosterDurableError::Stale);
    }
    // The header is a compaction checkpoint, not a second mutable epoch
    // witness.  Updating it before the frame would let a failed append leave
    // a newer epoch visible without the exact transition to which that epoch
    // belongs.  Every live frame already carries and authenticates its writer
    // epoch, so append only the frame and advance the header when a later
    // fully-synchronized compaction snapshots the surviving records.
    file.seek(SeekFrom::End(0))
        .map_err(|_| XfrmObjectRosterDurableError::Storage)?;
    if file.write_all(bytes).is_err() || file.sync_all().is_err() {
        return Err(XfrmObjectRosterDurableError::Storage);
    }
    #[cfg(test)]
    record_physical_barrier(store)?;
    let frames = journal_frame_count(store, &file)?;
    if frames == 0 || frames > MAX_JOURNAL_FRAMES {
        return Err(XfrmObjectRosterDurableError::Storage);
    }
    Ok(())
}

/// Compact terminal and superseded journal history only at a later
/// cooperating write.  The new file is fully synchronized before the atomic
/// replacement, so a crash can expose either the complete old journal or the
/// complete snapshot; both retain every unresolved cleanup authority.
fn compact_journal(
    store: &StoreInner,
    records: &[DurableRosterRecord],
    epoch: NonZeroU64,
) -> Result<(), XfrmObjectRosterDurableError> {
    if records.len() > MAX_JOURNAL_FRAMES {
        return Err(XfrmObjectRosterDurableError::CapacityExceeded);
    }
    verify_visible_identity(store)?;
    let temporary = temporary_name()?;
    let descriptor = openat(
        store.descriptor.as_fd(),
        temporary.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(FILE_MODE),
    )
    .map_err(|_| XfrmObjectRosterDurableError::Storage)?;
    let mut file = std::fs::File::from(descriptor);
    file.write_all(
        &EpochRecord {
            store_incarnation: store.control.store_incarnation,
            epoch,
        }
        .encode(&store.proof_key)?,
    )
    .map_err(|_| XfrmObjectRosterDurableError::Storage)?;
    for record in records {
        file.write_all(&record.encode(&store.proof_key)?)
            .map_err(|_| XfrmObjectRosterDurableError::Storage)?;
    }
    if file.sync_all().is_err() {
        let _ = unlinkat(
            store.descriptor.as_fd(),
            temporary.as_str(),
            AtFlags::empty(),
        );
        return Err(XfrmObjectRosterDurableError::Storage);
    }
    #[cfg(test)]
    record_physical_barrier(store)?;
    renameat_with(
        store.descriptor.as_fd(),
        temporary.as_str(),
        store.descriptor.as_fd(),
        JOURNAL_NAME,
        RenameFlags::empty(),
    )
    .map_err(|_| XfrmObjectRosterDurableError::Storage)?;
    fsync(&store.descriptor).map_err(|_| XfrmObjectRosterDurableError::Storage)?;
    #[cfg(test)]
    record_physical_barrier(store)?;
    Ok(())
}

fn validate_file_metadata(
    store: &StoreInner,
    descriptor: &OwnedFd,
    expected_size: usize,
) -> Result<(), XfrmObjectRosterDurableError> {
    let metadata = fstat(descriptor).map_err(|_| XfrmObjectRosterDurableError::Storage)?;
    if !FileType::from_raw_mode(metadata.st_mode).is_file()
        || stat_device(&metadata)? != store.root_device
        || metadata.st_uid != store.root_owner
        || metadata.st_mode.store_permissions() != FILE_MODE
        || metadata.st_nlink != 1
        || metadata.st_size != expected_size as i64
    {
        return Err(XfrmObjectRosterDurableError::Malformed);
    }
    Ok(())
}

fn publish_new_file(
    store: &StoreInner,
    target: &str,
    bytes: &[u8],
) -> Result<(), XfrmObjectRosterDurableError> {
    #[cfg(not(target_os = "linux"))]
    {
        // The public atomic constructor is unavailable before this point on a
        // non-Linux host. Keep the crate's established portable model and
        // unsupported backend buildable without pretending that another OS
        // provides Linux renameat2(RENAME_NOREPLACE) crash semantics.
        let _ = (store, target, bytes);
        Err(XfrmObjectRosterDurableError::Storage)
    }

    #[cfg(target_os = "linux")]
    {
        verify_visible_identity(store)?;
        for _ in 0..CREATE_ATTEMPTS {
            let temporary = temporary_name()?;
            let descriptor = match openat(
                store.descriptor.as_fd(),
                temporary.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(FILE_MODE),
            ) {
                Ok(descriptor) => descriptor,
                Err(error) if error == rustix::io::Errno::EXIST => continue,
                Err(_) => return Err(XfrmObjectRosterDurableError::Storage),
            };
            let mut file = std::fs::File::from(descriptor);
            if file.write_all(bytes).is_err() || file.sync_all().is_err() {
                let _ = unlinkat(
                    store.descriptor.as_fd(),
                    temporary.as_str(),
                    AtFlags::empty(),
                );
                return Err(XfrmObjectRosterDurableError::Storage);
            }
            #[cfg(test)]
            record_physical_barrier(store)?;
            let staged_metadata =
                fstat(&file).map_err(|_| XfrmObjectRosterDurableError::Storage)?;
            if !FileType::from_raw_mode(staged_metadata.st_mode).is_file()
                || staged_metadata.st_dev != store.root_device
                || staged_metadata.st_uid != store.root_owner
                || staged_metadata.st_mode.store_permissions() != FILE_MODE
                || staged_metadata.st_nlink != 1
                || staged_metadata.st_size != bytes.len() as i64
            {
                let _ = unlinkat(
                    store.descriptor.as_fd(),
                    temporary.as_str(),
                    AtFlags::empty(),
                );
                return Err(XfrmObjectRosterDurableError::Storage);
            }
            match renameat_with(
                store.descriptor.as_fd(),
                temporary.as_str(),
                store.descriptor.as_fd(),
                target,
                RenameFlags::NOREPLACE,
            ) {
                Ok(()) => {
                    fsync(&store.descriptor).map_err(|_| XfrmObjectRosterDurableError::Storage)?;
                    #[cfg(test)]
                    record_physical_barrier(store)?;
                    let reopened = openat(
                        store.descriptor.as_fd(),
                        target,
                        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(|_| XfrmObjectRosterDurableError::Storage)?;
                    validate_file_metadata(store, &reopened, bytes.len())?;
                    let published_metadata =
                        fstat(&reopened).map_err(|_| XfrmObjectRosterDurableError::Storage)?;
                    if published_metadata.st_dev != staged_metadata.st_dev
                        || published_metadata.st_ino != staged_metadata.st_ino
                    {
                        return Err(XfrmObjectRosterDurableError::Storage);
                    }
                    return Ok(());
                }
                Err(error) => {
                    let _ = unlinkat(
                        store.descriptor.as_fd(),
                        temporary.as_str(),
                        AtFlags::empty(),
                    );
                    let _ = fsync(&store.descriptor);
                    return Err(if error == rustix::io::Errno::EXIST {
                        XfrmObjectRosterDurableError::Duplicate
                    } else {
                        XfrmObjectRosterDurableError::Storage
                    });
                }
            }
        }
        Err(XfrmObjectRosterDurableError::EntropyUnavailable)
    }
}

fn random_nonzero_16() -> Result<[u8; 16], XfrmObjectRosterDurableError> {
    for _ in 0..CREATE_ATTEMPTS {
        let mut bytes = [0_u8; 16];
        SysRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| XfrmObjectRosterDurableError::EntropyUnavailable)?;
        if bytes.iter().any(|byte| *byte != 0) {
            return Ok(bytes);
        }
    }
    Err(XfrmObjectRosterDurableError::EntropyUnavailable)
}

#[cfg(target_os = "linux")]
fn temporary_name() -> Result<String, XfrmObjectRosterDurableError> {
    Ok(format!(
        "{TEMPORARY_PREFIX}{}",
        encode_hex(&random_nonzero_16()?)
    ))
}

fn is_temporary_name(name: &str) -> bool {
    let Some(encoded) = name.strip_prefix(TEMPORARY_PREFIX) else {
        return false;
    };
    encoded.len() == 32
        && encoded
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        && encoded.bytes().any(|byte| byte != b'0')
}

fn epoch_name(epoch: NonZeroU64) -> String {
    format!("epoch-{:016x}", epoch.get())
}

fn parse_epoch_name(name: &str) -> Option<NonZeroU64> {
    let encoded = name.strip_prefix("epoch-")?;
    if encoded.len() != 16 {
        return None;
    }
    NonZeroU64::new(u64::from_str_radix(encoded, 16).ok()?)
}

fn namespace_seal(key: &XfrmObjectRosterRecoveryProofKey, binding: [u8; 40]) -> [u8; 32] {
    authenticate_domain(key.canonical_mac_key(), NAMESPACE_AUTH_DOMAIN, &binding)
}

/// Name one roster record file.
///
/// The publication sequence is part of the name. Publication is
/// `renameat2(RENAME_NOREPLACE)` and the roster is the first family with
/// intra-phase progress, so without the sequence the second same-phase publish
/// would fail with `EEXIST` and the crash-window discipline would collapse.
fn record_name(record: &DurableRosterRecord) -> String {
    format!(
        "{}-{}-{:016x}-{:04x}",
        record.phase.as_str(),
        encode_hex(&record.group_id.0),
        record.group_generation.get(),
        record.publication_sequence
    )
}

fn validate_record_name(name: &OsStr) -> Result<(), XfrmObjectRosterDurableError> {
    parse_record_name(name)
        .map(|_| ())
        .ok_or(XfrmObjectRosterDurableError::Malformed)
}

fn parse_record_name(
    name: &OsStr,
) -> Option<(
    XfrmObjectRosterDurablePhase,
    XfrmObjectRosterGroupId,
    XfrmObjectRosterOperationGeneration,
    u16,
)> {
    let text = name.to_str()?;
    let mut components = text.rsplitn(4, '-');
    let sequence_text = components.next()?;
    if sequence_text.len() != 4 {
        return None;
    }
    let sequence = u16::from_str_radix(sequence_text, 16).ok()?;
    if sequence == 0 {
        return None;
    }
    let generation_text = components.next()?;
    if generation_text.len() != 16 {
        return None;
    }
    let generation = u64::from_str_radix(generation_text, 16).ok()?;
    let group = decode_hex_16(components.next()?)?;
    let phase = match components.next()? {
        "prepared" => XfrmObjectRosterDurablePhase::Prepared,
        "issuing" => XfrmObjectRosterDurablePhase::Issuing,
        "applied" => XfrmObjectRosterDurablePhase::Applied,
        "compensating" => XfrmObjectRosterDurablePhase::Compensating,
        "no_mutation" => XfrmObjectRosterDurablePhase::NoMutation,
        "rolled_back" => XfrmObjectRosterDurablePhase::RolledBack,
        "committed" => XfrmObjectRosterDurablePhase::Committed,
        "retired" => XfrmObjectRosterDurablePhase::Retired,
        _ => return None,
    };
    Some((
        phase,
        XfrmObjectRosterGroupId::from_bytes(group).ok()?,
        XfrmObjectRosterOperationGeneration::new(generation)?,
        sequence,
    ))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_hex_16(text: &str) -> Option<[u8; 16]> {
    let encoded = text.as_bytes();
    if encoded.len() != 32 {
        return None;
    }
    let mut decoded = [0_u8; 16];
    for (output, pair) in decoded.iter_mut().zip(encoded.as_chunks::<2>().0.iter()) {
        *output = decode_hex_nibble(pair[0])?
            .checked_mul(16)?
            .checked_add(decode_hex_nibble(pair[1])?)?;
    }
    Some(decoded)
}

fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, DirBuilder};
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use crate::model::{
        Algorithm, AuthAlgorithm, InstallSaRequest, IpAddress, KeyMaterial, LifetimeConfig,
        SaParameters, XfrmId, XfrmSelector,
    };

    const NAMESPACE_BINDING: [u8; 40] = [0x42; 40];
    const ARITY: usize = 3;

    type SlotSpec = (
        XfrmObjectRosterMemberPhase,
        Option<XfrmObjectRosterSweepProof>,
        Option<XfrmObjectRosterAdjacentProof>,
    );

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            for _ in 0..8 {
                let identity = XfrmObjectRosterGroupId::generate().unwrap();
                let path = std::env::temp_dir().join(format!(
                    "opc-xfrm-durable-roster-test-{}",
                    encode_hex(&identity.to_bytes())
                ));
                assert!(path.is_absolute());
                match DirBuilder::new().mode(DIRECTORY_MODE).create(&path) {
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
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            if self.0.is_dir() {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
    }

    fn key(byte: u8) -> XfrmObjectRosterRecoveryProofKey {
        XfrmObjectRosterRecoveryProofKey::new([byte; 32]).unwrap()
    }

    fn store(root: &TestRoot) -> XfrmObjectRosterRecoveryStore {
        XfrmObjectRosterRecoveryStore::open_bound(root.path(), key(9), NAMESPACE_BINDING).unwrap()
    }

    fn group(byte: u8) -> XfrmObjectRosterGroupId {
        XfrmObjectRosterGroupId::from_bytes([byte; 16]).unwrap()
    }

    fn generation(value: u64) -> XfrmObjectRosterOperationGeneration {
        XfrmObjectRosterOperationGeneration::new(value).unwrap()
    }

    fn material(index: usize) -> XfrmObjectRosterMemberMaterial {
        let byte = 0x11 * u8::try_from(index + 1).unwrap();
        XfrmObjectRosterMemberMaterial {
            object: if index.is_multiple_of(2) {
                XfrmInstallObject::Sa
            } else {
                XfrmInstallObject::Policy
            },
            member_id: XfrmObjectRosterMemberId::from_bytes([byte; 16]).unwrap(),
            member_generation: NonZeroU64::new(u64::from(byte)).unwrap(),
            fingerprints: XfrmObjectRosterMemberFingerprints {
                deletion_identity: [byte; 32],
                install_request: [byte ^ 0x0f; 32],
            },
        }
    }

    fn members(count: usize) -> Vec<XfrmObjectRosterMemberMaterial> {
        (0..count).map(material).collect()
    }

    fn roster_record(
        phase: XfrmObjectRosterDurablePhase,
        cursor: u8,
        slots: &[SlotSpec],
    ) -> DurableRosterRecord {
        let mut record = DurableRosterRecord {
            phase,
            cursor,
            publication_sequence: 1,
            store_incarnation: [1; 16],
            namespace_seal: [2; 32],
            actor_incarnation: [3; 16],
            group_id: group(4),
            group_generation: generation(5),
            writer_epoch: NonZeroU64::new(6).unwrap(),
            roster_fingerprint: [0; 32],
            members: [None; XFRM_OBJECT_ROSTER_MAX_MEMBERS],
        };
        for (index, (member_phase, sweep, adjacent)) in slots.iter().enumerate() {
            let mut slot = DurableRosterMemberSlot::from_material(material(index));
            slot.phase = *member_phase;
            slot.sweep_proof = *sweep;
            slot.adjacent_proof = *adjacent;
            record.members[index] = Some(slot);
        }
        record.roster_fingerprint =
            roster_fingerprint(key(9).canonical_mac_key(), &record.active()).unwrap();
        record
    }

    fn acquired() -> SlotSpec {
        (
            XfrmObjectRosterMemberPhase::Acquired,
            Some(XfrmObjectRosterSweepProof::Absent),
            Some(XfrmObjectRosterAdjacentProof::Absent),
        )
    }

    fn pending_swept() -> SlotSpec {
        (
            XfrmObjectRosterMemberPhase::Pending,
            Some(XfrmObjectRosterSweepProof::Absent),
            None,
        )
    }

    fn pending_witnessed() -> SlotSpec {
        (
            XfrmObjectRosterMemberPhase::Pending,
            Some(XfrmObjectRosterSweepProof::Absent),
            Some(XfrmObjectRosterAdjacentProof::Absent),
        )
    }

    fn prepared_record() -> DurableRosterRecord {
        roster_record(
            XfrmObjectRosterDurablePhase::Prepared,
            0,
            &[(XfrmObjectRosterMemberPhase::Pending, None, None); ARITY],
        )
    }

    fn issuing_record(cursor: usize) -> DurableRosterRecord {
        let slots = (0..ARITY)
            .map(|index| match index.cmp(&cursor) {
                std::cmp::Ordering::Less => acquired(),
                std::cmp::Ordering::Equal => pending_witnessed(),
                std::cmp::Ordering::Greater => pending_swept(),
            })
            .collect::<Vec<_>>();
        roster_record(
            XfrmObjectRosterDurablePhase::Issuing,
            u8::try_from(cursor).unwrap(),
            &slots,
        )
    }

    fn issuing_sweep_conflict_record() -> DurableRosterRecord {
        let mut slots = vec![pending_swept(); ARITY];
        slots[1].1 = Some(XfrmObjectRosterSweepProof::Conflict);
        roster_record(XfrmObjectRosterDurablePhase::Issuing, 0, &slots)
    }

    fn applied_record() -> DurableRosterRecord {
        roster_record(
            XfrmObjectRosterDurablePhase::Applied,
            u8::try_from(ARITY).unwrap(),
            &[acquired(); ARITY],
        )
    }

    fn committed_record() -> DurableRosterRecord {
        roster_record(
            XfrmObjectRosterDurablePhase::Committed,
            u8::try_from(ARITY).unwrap(),
            &[acquired(); ARITY],
        )
    }

    fn compensating_record() -> DurableRosterRecord {
        roster_record(
            XfrmObjectRosterDurablePhase::Compensating,
            1,
            &[
                acquired(),
                acquired(),
                (
                    XfrmObjectRosterMemberPhase::Indeterminate,
                    Some(XfrmObjectRosterSweepProof::Absent),
                    Some(XfrmObjectRosterAdjacentProof::Absent),
                ),
            ],
        )
    }

    fn no_mutation_sweep_record() -> DurableRosterRecord {
        let mut slots = vec![pending_swept(); ARITY];
        slots[2].1 = Some(XfrmObjectRosterSweepProof::Conflict);
        roster_record(XfrmObjectRosterDurablePhase::NoMutation, 0, &slots)
    }

    fn no_mutation_adjacent_record() -> DurableRosterRecord {
        let mut slots = vec![pending_swept(); ARITY];
        slots[0] = (
            XfrmObjectRosterMemberPhase::NoMutation,
            Some(XfrmObjectRosterSweepProof::Absent),
            Some(XfrmObjectRosterAdjacentProof::Conflict),
        );
        roster_record(XfrmObjectRosterDurablePhase::NoMutation, 0, &slots)
    }

    fn rolled_back_record() -> DurableRosterRecord {
        roster_record(
            XfrmObjectRosterDurablePhase::RolledBack,
            0,
            &[
                (
                    XfrmObjectRosterMemberPhase::Retired,
                    Some(XfrmObjectRosterSweepProof::Absent),
                    Some(XfrmObjectRosterAdjacentProof::Absent),
                ),
                (
                    XfrmObjectRosterMemberPhase::Retired,
                    Some(XfrmObjectRosterSweepProof::Absent),
                    Some(XfrmObjectRosterAdjacentProof::Absent),
                ),
                (
                    XfrmObjectRosterMemberPhase::NoMutation,
                    Some(XfrmObjectRosterSweepProof::Absent),
                    Some(XfrmObjectRosterAdjacentProof::AbsentThenAlreadyExists),
                ),
            ],
        )
    }

    fn valid_records() -> Vec<(&'static str, DurableRosterRecord)> {
        vec![
            ("prepared", prepared_record()),
            ("issuing_0", issuing_record(0)),
            ("issuing_1", issuing_record(1)),
            ("issuing_2", issuing_record(2)),
            ("issuing_sweep_conflict", issuing_sweep_conflict_record()),
            ("applied", applied_record()),
            ("committed", committed_record()),
            ("compensating", compensating_record()),
            ("no_mutation_sweep", no_mutation_sweep_record()),
            ("no_mutation_adjacent", no_mutation_adjacent_record()),
            ("rolled_back", rolled_back_record()),
        ]
    }

    fn slot_byte(index: usize, field: usize) -> usize {
        MEMBER_SLOTS_OFFSET + index * MEMBER_SLOT_BYTES + field
    }

    fn reseal(
        mut encoded: [u8; XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES],
    ) -> [u8; XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES] {
        let tag = authenticate_domain(
            key(9).canonical_mac_key(),
            RECORD_AUTH_DOMAIN,
            &encoded[..RECORD_BODY_BYTES],
        );
        encoded[RECORD_BODY_BYTES..].copy_from_slice(&tag);
        encoded
    }

    fn patched(
        record: &DurableRosterRecord,
        edits: &[(usize, u8)],
    ) -> [u8; XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES] {
        let mut encoded = record.encode(&key(9)).unwrap();
        for (offset, value) in edits {
            encoded[*offset] = *value;
        }
        reseal(encoded)
    }

    fn advance(
        store: &XfrmObjectRosterRecoveryStore,
        handle: &XfrmObjectRosterRecoveryHandle,
        expected: XfrmObjectRosterDurablePhase,
        transition: XfrmObjectRosterTransition,
    ) -> XfrmObjectRosterRecoveryHandle {
        store
            .transition(handle, expected, transition)
            .unwrap()
            .handle(&store.inner.proof_key)
            .unwrap()
    }

    fn enter_issuing(count: usize) -> XfrmObjectRosterTransition {
        let mut transition =
            XfrmObjectRosterTransition::new(XfrmObjectRosterDurablePhase::Issuing, 0);
        for index in 0..count {
            transition = transition.with_member(
                index,
                XfrmObjectRosterMemberTransition {
                    phase: XfrmObjectRosterMemberPhase::Pending,
                    sweep_proof: Some(XfrmObjectRosterSweepProof::Absent),
                    adjacent_proof: if index == 0 {
                        Some(XfrmObjectRosterAdjacentProof::Absent)
                    } else {
                        None
                    },
                },
            );
        }
        transition
    }

    fn acquire_member(count: usize, index: usize) -> XfrmObjectRosterTransition {
        let last = index + 1 == count;
        let next_phase = if last {
            XfrmObjectRosterDurablePhase::Applied
        } else {
            XfrmObjectRosterDurablePhase::Issuing
        };
        let mut transition =
            XfrmObjectRosterTransition::new(next_phase, u8::try_from(index + 1).unwrap())
                .with_member(
                    index,
                    XfrmObjectRosterMemberTransition {
                        phase: XfrmObjectRosterMemberPhase::Acquired,
                        sweep_proof: Some(XfrmObjectRosterSweepProof::Absent),
                        adjacent_proof: Some(XfrmObjectRosterAdjacentProof::Absent),
                    },
                );
        if !last {
            transition = transition.with_member(
                index + 1,
                XfrmObjectRosterMemberTransition {
                    phase: XfrmObjectRosterMemberPhase::Pending,
                    sweep_proof: Some(XfrmObjectRosterSweepProof::Absent),
                    adjacent_proof: Some(XfrmObjectRosterAdjacentProof::Absent),
                },
            );
        }
        transition
    }

    fn run_to_applied(
        store: &XfrmObjectRosterRecoveryStore,
        prepared: &XfrmObjectRosterRecoveryHandle,
        count: usize,
    ) -> XfrmObjectRosterRecoveryHandle {
        let mut handle = advance(
            store,
            prepared,
            XfrmObjectRosterDurablePhase::Prepared,
            enter_issuing(count),
        );
        for index in 0..count {
            handle = advance(
                store,
                &handle,
                XfrmObjectRosterDurablePhase::Issuing,
                acquire_member(count, index),
            );
        }
        handle
    }

    fn record_file_names(root: &TestRoot) -> Vec<String> {
        let mut names = fs::read_dir(root.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| {
                name != CONTROL_NAME && name != JOURNAL_NAME && !name.starts_with("epoch-")
            })
            .collect::<Vec<_>>();
        names.sort();
        names
    }

    fn sample_install_request() -> XfrmObjectInstallRequest {
        XfrmObjectInstallRequest::Sa(InstallSaRequest {
            parameters: SaParameters {
                selector: XfrmSelector::new(
                    IpAddress::Ipv4([10, 0, 0, 1]),
                    IpAddress::Ipv4([10, 0, 0, 2]),
                    50,
                ),
                id: XfrmId {
                    destination: IpAddress::Ipv4([10, 0, 0, 2]),
                    spi: 0x1234_5678,
                    protocol: 50,
                },
                source_address: IpAddress::Ipv4([10, 0, 0, 1]),
                request_id: None,
                auth: Some((
                    AuthAlgorithm::hmac_sha256(96),
                    KeyMaterial::new(vec![0xab; 32]),
                )),
                crypt: Some((Algorithm::cbc_aes(), KeyMaterial::new(vec![0xcd; 32]))),
                aead: None,
                mode: crate::XfrmMode::Tunnel,
                lifetime: LifetimeConfig::default(),
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

    #[test]
    fn record_layout_is_frozen_at_the_documented_size() {
        assert_eq!(XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES, 944);
        assert_eq!(RECORD_BODY_BYTES, 912);
        assert_eq!(MEMBER_SLOTS_OFFSET, 144);
        assert_eq!(MEMBER_SLOT_BYTES, 96);
        assert_eq!(XFRM_OBJECT_ROSTER_MAX_MEMBERS, 8);
        // One roster handle is smaller than the five single-object handles it
        // replaces for a Child-SA install.
        const {
            assert!(
                XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES
                    < 5 * crate::XFRM_OBJECT_INSTALL_RECOVERY_HANDLE_BYTES
            );
        }
    }

    #[test]
    fn record_codec_round_trips_every_legal_phase_body() {
        for (label, expected) in valid_records() {
            let encoded = expected.encode(&key(9)).unwrap();
            assert_eq!(
                encoded.len(),
                XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES,
                "{label}"
            );
            assert_eq!(
                DurableRosterRecord::decode(&encoded, &key(9)).unwrap(),
                expected,
                "{label}"
            );
            let handle = XfrmObjectRosterRecoveryHandle::from_bytes(encoded);
            assert_eq!(handle.to_bytes(), encoded, "{label}");
        }
    }

    #[test]
    fn record_codec_round_trips_every_arity() {
        for arity in 1..=XFRM_OBJECT_ROSTER_MAX_MEMBERS {
            let slots = vec![(XfrmObjectRosterMemberPhase::Pending, None, None); arity];
            let expected = roster_record(XfrmObjectRosterDurablePhase::Prepared, 0, &slots);
            let encoded = expected.encode(&key(9)).unwrap();
            assert_eq!(usize::from(encoded[12]), arity);
            assert_eq!(
                DurableRosterRecord::decode(&encoded, &key(9)).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn golden_vectors_pin_the_record_and_roster_digest_encoding() {
        let record = prepared_record();
        assert_eq!(
            record.roster_fingerprint,
            [
                0x33, 0x50, 0x67, 0xd5, 0xfc, 0x7d, 0x00, 0x06, 0x58, 0x1c, 0xf5, 0x01, 0xa7, 0x29,
                0xda, 0x3a, 0xee, 0x42, 0xae, 0x96, 0xe4, 0x41, 0xb3, 0x22, 0xaa, 0x16, 0x7c, 0x63,
                0x94, 0x47, 0x37, 0x8a,
            ],
            "roster digest encoding changed"
        );
        let encoded = record.encode(&key(9)).unwrap();
        assert_eq!(
            encoded[RECORD_BODY_BYTES..],
            [
                0x3f, 0xe3, 0x96, 0x76, 0x5f, 0x4d, 0x48, 0x54, 0xeb, 0x9f, 0xa5, 0x18, 0xa9, 0x28,
                0x63, 0xa9, 0xca, 0xcd, 0x44, 0x26, 0x64, 0xbd, 0xd4, 0x24, 0x5a, 0xba, 0xff, 0x49,
                0xed, 0x6a, 0x40, 0xb2,
            ],
            "record tag encoding changed"
        );
    }

    #[test]
    fn golden_vector_pins_the_member_fingerprint_encoding() {
        let root = TestRoot::new();
        let store = store(&root);
        let fingerprints = store
            .fingerprints_for_request(&sample_install_request())
            .unwrap();
        assert_eq!(
            fingerprints.deletion_identity,
            [
                0x34, 0x6a, 0xf1, 0xa8, 0xa9, 0x39, 0xd6, 0x1e, 0xde, 0xb3, 0x0c, 0xbe, 0x03, 0xb6,
                0xf0, 0x57, 0x32, 0x7e, 0xd2, 0x54, 0x8d, 0xcc, 0x03, 0xf3, 0x3e, 0xea, 0x73, 0xb9,
                0x57, 0xc1, 0xb1, 0x92,
            ],
            "member deletion-identity fingerprint encoding changed"
        );
        assert_eq!(
            fingerprints.install_request,
            [
                0x47, 0x02, 0xee, 0x59, 0x55, 0xc8, 0x98, 0x26, 0x45, 0x0c, 0xbf, 0xb8, 0x48, 0x1d,
                0xcd, 0x8f, 0x14, 0xab, 0x92, 0xea, 0x65, 0x56, 0x8f, 0xd8, 0xdb, 0x4e, 0x63, 0xe5,
                0x92, 0xac, 0x20, 0xdd,
            ],
            "member install-request fingerprint encoding changed"
        );
    }

    #[test]
    fn every_family_domain_separates_an_otherwise_identical_key() {
        // A deployment may configure the same 32 secret bytes for every
        // durable family, so the domain separator is the only thing keeping
        // their fingerprints apart. Unifying the domains would silently make
        // two families' correlation values interchangeable.
        let proof_key = key(9);
        let borrowed = proof_key.canonical_mac_key();
        let request = sample_install_request();
        let removal = request.removal();
        let roster_install =
            authenticate_install_request(borrowed, INSTALL_REQUEST_AUTH_DOMAIN, &request).unwrap();
        let object_install = authenticate_install_request(
            borrowed,
            b"opc-xfrm-object-install-request-v1\0",
            &request,
        )
        .unwrap();
        assert_ne!(roster_install, object_install);

        let roster_deletion =
            authenticate_deletion_identity(borrowed, DELETION_IDENTITY_AUTH_DOMAIN, &removal, None)
                .unwrap();
        let object_deletion = authenticate_deletion_identity(
            borrowed,
            b"opc-xfrm-object-deletion-identity-v1\0",
            &removal,
            None,
        )
        .unwrap();
        assert_ne!(roster_deletion, object_deletion);

        let roster_seal = namespace_seal(&proof_key, NAMESPACE_BINDING);
        let object_seal = authenticate_domain(
            borrowed,
            b"opc-xfrm-object-namespace-v1\0",
            &NAMESPACE_BINDING,
        );
        assert_ne!(roster_seal, object_seal);
    }

    #[test]
    fn roster_record_decode_rejects_each_invariant_violation() {
        let cases: Vec<(&str, [u8; XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES])> = vec![
            ("prepared_cursor", patched(&prepared_record(), &[(11, 1)])),
            (
                "prepared_sweep_set",
                patched(&prepared_record(), &[(slot_byte(0, 2), 1)]),
            ),
            (
                "prepared_adjacent_set",
                patched(&prepared_record(), &[(slot_byte(0, 3), 1)]),
            ),
            (
                "prepared_member_acquired",
                patched(&prepared_record(), &[(slot_byte(0, 1), 2)]),
            ),
            (
                "issuing_missing_sweep",
                patched(&issuing_record(0), &[(slot_byte(1, 2), 0)]),
            ),
            (
                "issuing_cursor_at_arity",
                patched(&issuing_record(2), &[(11, 3)]),
            ),
            (
                "issuing_prefix_not_acquired",
                patched(&issuing_record(1), &[(slot_byte(0, 1), 1)]),
            ),
            (
                "issuing_cursor_member_already_acquired",
                patched(&issuing_record(1), &[(slot_byte(1, 1), 2)]),
            ),
            (
                "issuing_lookahead_adjacent_proof",
                patched(&issuing_record(0), &[(slot_byte(1, 3), 1)]),
            ),
            (
                "issuing_sweep_conflict_with_cursor",
                patched(&issuing_sweep_conflict_record(), &[(11, 1)]),
            ),
            (
                "issuing_sweep_conflict_with_acquired_member",
                patched(&issuing_sweep_conflict_record(), &[(slot_byte(0, 1), 2)]),
            ),
            ("applied_cursor", patched(&applied_record(), &[(11, 2)])),
            (
                "applied_member_pending",
                patched(&applied_record(), &[(slot_byte(1, 1), 1)]),
            ),
            (
                "applied_member_without_adjacent_proof",
                patched(&applied_record(), &[(slot_byte(1, 3), 0)]),
            ),
            (
                "applied_member_without_sweep_proof",
                patched(&applied_record(), &[(slot_byte(1, 2), 0)]),
            ),
            ("committed_cursor", patched(&committed_record(), &[(11, 0)])),
            (
                "compensating_cursor_at_arity",
                patched(&compensating_record(), &[(11, 3)]),
            ),
            (
                "compensating_without_a_deepest_member",
                patched(
                    &compensating_record(),
                    &[
                        (slot_byte(0, 1), 1),
                        (slot_byte(0, 3), 0),
                        (slot_byte(1, 1), 1),
                        (slot_byte(1, 3), 0),
                        (slot_byte(2, 1), 1),
                        (slot_byte(2, 3), 0),
                        (11, 0),
                    ],
                ),
            ),
            (
                "compensating_two_unresolved_members",
                patched(&compensating_record(), &[(slot_byte(1, 1), 5)]),
            ),
            (
                "compensating_prefix_not_acquired",
                patched(&compensating_record(), &[(slot_byte(0, 1), 6)]),
            ),
            (
                "compensating_gap_not_retired",
                patched(
                    &roster_record(
                        XfrmObjectRosterDurablePhase::Compensating,
                        0,
                        &[
                            acquired(),
                            (
                                XfrmObjectRosterMemberPhase::Retired,
                                Some(XfrmObjectRosterSweepProof::Absent),
                                Some(XfrmObjectRosterAdjacentProof::Absent),
                            ),
                            (
                                XfrmObjectRosterMemberPhase::NoMutation,
                                Some(XfrmObjectRosterSweepProof::Absent),
                                Some(XfrmObjectRosterAdjacentProof::AbsentThenAlreadyExists),
                            ),
                        ],
                    ),
                    &[(slot_byte(1, 1), 3)],
                ),
            ),
            (
                "compensating_sweep_conflict",
                patched(&compensating_record(), &[(slot_byte(2, 2), 2)]),
            ),
            (
                "no_mutation_cursor",
                patched(&no_mutation_sweep_record(), &[(11, 1)]),
            ),
            (
                "no_mutation_missing_verdict",
                patched(&no_mutation_adjacent_record(), &[(slot_byte(0, 1), 1)]),
            ),
            (
                "no_mutation_absent_adjacent_verdict",
                patched(&no_mutation_adjacent_record(), &[(slot_byte(0, 3), 1)]),
            ),
            (
                "no_mutation_verdict_off_member_zero",
                patched(
                    &no_mutation_adjacent_record(),
                    &[
                        (slot_byte(0, 1), 1),
                        (slot_byte(0, 3), 0),
                        (slot_byte(1, 1), 3),
                        (slot_byte(1, 3), 2),
                    ],
                ),
            ),
            (
                "rolled_back_with_acquired_member",
                patched(&rolled_back_record(), &[(slot_byte(0, 1), 2)]),
            ),
            (
                "rolled_back_cursor",
                patched(&rolled_back_record(), &[(11, 1)]),
            ),
            (
                "removal_admitted_without_absence_proof",
                patched(
                    &compensating_record(),
                    &[(slot_byte(2, 1), 5), (slot_byte(2, 3), 2)],
                ),
            ),
            (
                "retired_body_matches_no_terminal_state",
                patched(&issuing_record(1), &[(10, 8)]),
            ),
            (
                "pending_member_with_conflict_adjacent_proof",
                patched(&issuing_record(0), &[(slot_byte(0, 3), 2)]),
            ),
            ("arity_zero", patched(&prepared_record(), &[(12, 0)])),
            ("arity_above_bound", patched(&prepared_record(), &[(12, 9)])),
            (
                "arity_shrunk_leaves_a_populated_tail_slot",
                patched(&prepared_record(), &[(12, 2)]),
            ),
            (
                "slot_reserved_bytes_nonzero",
                patched(&prepared_record(), &[(slot_byte(0, 4), 1)]),
            ),
            (
                "publication_sequence_zero",
                patched(&prepared_record(), &[(13, 0), (14, 0)]),
            ),
            (
                "unknown_member_object_kind",
                patched(&prepared_record(), &[(slot_byte(0, 0), 3)]),
            ),
            (
                "unknown_member_phase_code",
                patched(&prepared_record(), &[(slot_byte(0, 1), 7)]),
            ),
            (
                "unknown_sweep_proof_code",
                patched(&issuing_record(0), &[(slot_byte(0, 2), 3)]),
            ),
            (
                "unknown_adjacent_proof_code",
                patched(&issuing_record(0), &[(slot_byte(0, 3), 4)]),
            ),
            (
                "unknown_group_phase_code",
                patched(&prepared_record(), &[(10, 9)]),
            ),
        ];
        for (label, encoded) in cases {
            assert_eq!(
                DurableRosterRecord::decode(&encoded, &key(9)),
                Err(XfrmObjectRosterDurableError::Malformed),
                "{label} decoded as a legal record"
            );
        }
    }

    #[test]
    fn self_inconsistent_roster_digest_fails_closed() {
        // A MAC-valid record whose digest disagrees with its own slots is a
        // writer bug, not a forgery, and must still fail closed.
        let mut encoded = prepared_record().encode(&key(9)).unwrap();
        encoded[112] ^= 0x80;
        assert_eq!(
            DurableRosterRecord::decode(&reseal(encoded), &key(9)),
            Err(XfrmObjectRosterDurableError::Malformed)
        );
    }

    #[test]
    fn tampering_and_wrong_key_fail_authentication() {
        let encoded = applied_record().encode(&key(9)).unwrap();
        assert_eq!(
            DurableRosterRecord::decode(&encoded, &key(8)),
            Err(XfrmObjectRosterDurableError::AuthenticationFailed)
        );
        for index in [10, 11, 12, 16, 47, 80, 103, 111, 143, 200, 500, 911] {
            let mut tampered = encoded;
            tampered[index] ^= 0x80;
            assert_eq!(
                DurableRosterRecord::decode(&tampered, &key(9)),
                Err(XfrmObjectRosterDurableError::AuthenticationFailed),
                "byte {index}"
            );
        }
        let mut tag = encoded;
        tag[RECORD_BODY_BYTES] ^= 0x01;
        assert_eq!(
            DurableRosterRecord::decode(&tag, &key(9)),
            Err(XfrmObjectRosterDurableError::AuthenticationFailed)
        );
    }

    #[test]
    fn reserved_and_version_fields_fail_closed_before_authentication() {
        assert!(matches!(
            XfrmObjectRosterRecoveryProofKey::new([0; 32]),
            Err(XfrmObjectRosterDurableError::InvalidProofKey)
        ));
        let valid = prepared_record().encode(&key(9)).unwrap();
        for (label, index, value) in [
            ("version_low", 9_usize, 2_u8),
            ("version_high", 8, 1),
            ("reserved", 15, 1),
            ("magic", 0, b'X'),
        ] {
            let mut invalid = valid;
            invalid[index] = value;
            assert_eq!(
                DurableRosterRecord::decode(&invalid, &key(9)),
                Err(XfrmObjectRosterDurableError::Malformed),
                "{label}"
            );
        }
        let mut zeroed = prepared_record();
        zeroed.store_incarnation = [0; 16];
        assert_eq!(
            zeroed.encode(&key(9)),
            Err(XfrmObjectRosterDurableError::Malformed)
        );
    }

    #[test]
    fn state_machine_rejects_unsafe_group_edges() {
        use XfrmObjectRosterDurablePhase as Phase;
        assert!(Phase::Prepared.permits(Phase::Issuing));
        assert!(Phase::Prepared.permits(Phase::Retired));
        assert!(Phase::Issuing.permits(Phase::Issuing));
        assert!(Phase::Issuing.permits(Phase::Compensating));
        assert!(Phase::Applied.permits(Phase::Compensating));
        assert!(Phase::Compensating.permits(Phase::Compensating));
        // A roster never retires without a terminal verdict, never revives a
        // terminal verdict, and never re-enters an earlier working phase.
        assert!(!Phase::Issuing.permits(Phase::Retired));
        assert!(!Phase::Issuing.permits(Phase::Prepared));
        assert!(!Phase::Compensating.permits(Phase::Retired));
        assert!(!Phase::Compensating.permits(Phase::Issuing));
        assert!(!Phase::Applied.permits(Phase::Applied));
        assert!(!Phase::NoMutation.permits(Phase::Issuing));
        assert!(!Phase::Retired.permits(Phase::Retired));
        assert!(!Phase::Committed.permits(Phase::Compensating));
        for phase in [Phase::Issuing, Phase::Applied, Phase::Compensating] {
            assert!(phase.is_unresolved_writer_authority(), "{}", phase.as_str());
        }
        for phase in [
            Phase::Prepared,
            Phase::NoMutation,
            Phase::RolledBack,
            Phase::Committed,
            Phase::Retired,
        ] {
            assert!(
                !phase.is_unresolved_writer_authority(),
                "{}",
                phase.as_str()
            );
        }
    }

    #[test]
    fn member_slot_edges_are_monotone() {
        use XfrmObjectRosterMemberPhase as Member;
        assert!(Member::Pending.permits(Member::Acquired));
        assert!(Member::Pending.permits(Member::NoMutation));
        assert!(Member::Indeterminate.permits(Member::RemovalAdmitted));
        assert!(Member::Acquired.permits(Member::RemovalAdmitted));
        assert!(Member::RemovalAdmitted.permits(Member::Retired));
        assert!(Member::Retired.permits(Member::Retired));
        assert!(!Member::Acquired.permits(Member::Pending));
        assert!(!Member::Acquired.permits(Member::Retired));
        assert!(!Member::NoMutation.permits(Member::RemovalAdmitted));
        assert!(!Member::NoMutation.permits(Member::Retired));
        assert!(!Member::Retired.permits(Member::RemovalAdmitted));
        assert!(!adjacent_proof_permits(
            Some(XfrmObjectRosterAdjacentProof::Conflict),
            Some(XfrmObjectRosterAdjacentProof::Absent)
        ));
        assert!(adjacent_proof_permits(
            Some(XfrmObjectRosterAdjacentProof::Absent),
            Some(XfrmObjectRosterAdjacentProof::AbsentThenAlreadyExists)
        ));
        assert!(!adjacent_proof_permits(
            Some(XfrmObjectRosterAdjacentProof::Absent),
            None
        ));
        assert!(!sweep_proof_permits(
            Some(XfrmObjectRosterSweepProof::Absent),
            Some(XfrmObjectRosterSweepProof::Conflict)
        ));
    }

    #[test]
    fn publication_successor_survives_either_scan_order() {
        let mut old = prepared_record();
        old.publication_sequence = 1;
        let mut next = issuing_record(0);
        next.publication_sequence = 2;
        next.writer_epoch = NonZeroU64::new(7).unwrap();
        let epoch = NonZeroU64::new(7).unwrap();
        assert!(is_exact_roster_publication_successor(&old, &next, epoch));
        assert!(!is_exact_roster_publication_successor(&next, &old, epoch));

        for order in [[0_usize, 1_usize], [1, 0]] {
            let planted = order
                .iter()
                .map(|index| {
                    if *index == 0 {
                        ("old".to_owned(), old.clone())
                    } else {
                        ("next".to_owned(), next.clone())
                    }
                })
                .collect::<Vec<_>>();
            let (current, obsolete) = classify_roster_records(planted, epoch).unwrap();
            assert_eq!(current.len(), 1);
            assert_eq!(current[0].0, "next");
            assert_eq!(obsolete, vec!["old".to_owned()]);
        }
    }

    #[test]
    fn publication_sequence_gaps_and_reuse_fail_closed() {
        let epoch = NonZeroU64::new(7).unwrap();
        let old = prepared_record();
        let mut gapped = issuing_record(0);
        gapped.publication_sequence = 3;
        gapped.writer_epoch = epoch;
        assert!(!is_exact_roster_publication_successor(&old, &gapped, epoch));
        let mut repeated = issuing_record(0);
        repeated.publication_sequence = 1;
        repeated.writer_epoch = epoch;
        assert!(!is_exact_roster_publication_successor(
            &old, &repeated, epoch
        ));
        assert_eq!(
            classify_roster_records(
                vec![("old".to_owned(), old), ("gapped".to_owned(), gapped)],
                epoch,
            ),
            Err(XfrmObjectRosterDurableError::Duplicate)
        );
    }

    #[test]
    fn publication_successor_requires_a_fresh_epoch_only_when_issuing_begins() {
        let old = prepared_record();
        let mut next = issuing_record(0);
        next.publication_sequence = 2;
        next.writer_epoch = old.writer_epoch;
        // Entering `Issuing` without burning the epoch is not a successor.
        assert!(!is_exact_roster_publication_successor(
            &old,
            &next,
            old.writer_epoch
        ));
        let mut applied = applied_record();
        applied.publication_sequence = 2;
        let issuing = issuing_record(2);
        assert!(is_exact_roster_publication_successor(
            &issuing,
            &applied,
            issuing.writer_epoch
        ));
        let mut drifted = applied;
        drifted.writer_epoch = NonZeroU64::new(9).unwrap();
        assert!(!is_exact_roster_publication_successor(
            &issuing,
            &drifted,
            issuing.writer_epoch
        ));
    }

    #[test]
    fn publication_successor_requires_stable_member_identity_and_digest() {
        let epoch = NonZeroU64::new(7).unwrap();
        let old = prepared_record();
        let mut next = issuing_record(0);
        next.publication_sequence = 2;
        next.writer_epoch = epoch;
        assert!(is_exact_roster_publication_successor(&old, &next, epoch));

        let mut substituted = next.clone();
        if let Some(slot) = substituted.members[1].as_mut() {
            slot.deletion_identity_fingerprint = [0x7e; 32];
        }
        assert!(!is_exact_roster_publication_successor(
            &old,
            &substituted,
            epoch
        ));

        let mut redigested = next.clone();
        redigested.roster_fingerprint = [0x5a; 32];
        assert!(!is_exact_roster_publication_successor(
            &old,
            &redigested,
            epoch
        ));

        let mut regrouped = next;
        regrouped.group_id = group(0x77);
        assert!(!is_exact_roster_publication_successor(
            &old, &regrouped, epoch
        ));
    }

    #[test]
    fn publication_successor_pins_cursor_monotonicity() {
        let epoch = NonZeroU64::new(6).unwrap();
        let mut next = issuing_record(2);
        next.publication_sequence = 2;
        // An issuing self-edge advances the cursor by exactly one.
        assert!(is_exact_roster_publication_successor(
            &issuing_record(1),
            &next,
            epoch
        ));
        assert!(!is_exact_roster_publication_successor(
            &issuing_record(0),
            &next,
            epoch
        ));
        // Compensation never re-descends into a deeper member.
        let mut deeper = compensating_record();
        deeper.publication_sequence = 2;
        deeper.cursor = 2;
        assert!(!is_exact_roster_publication_successor(
            &issuing_record(1),
            &deeper,
            epoch
        ));
    }

    #[test]
    fn store_persists_control_and_reopens_the_same_incarnation() {
        let root = TestRoot::new();
        let first = store(&root);
        let incarnation = first.inner.control.actor_incarnation;
        let handle = first
            .prepare(group(0x21), generation(1), &members(3))
            .unwrap();
        let digest = first.roster_fingerprint_for(&members(3)).unwrap();
        assert_eq!(
            first.inspect(&handle),
            Ok(XfrmObjectRosterDurablePhase::Prepared)
        );
        drop(first);

        let reopened = store(&root);
        assert_eq!(reopened.inner.control.actor_incarnation, incarnation);
        assert_eq!(
            reopened.inspect(&handle),
            Ok(XfrmObjectRosterDurablePhase::Prepared)
        );
        let restored = reopened
            .restore(group(0x21), generation(1), digest)
            .unwrap();
        assert_eq!(restored.phase, XfrmObjectRosterDurablePhase::Prepared);
        assert_eq!(restored.arity().unwrap(), 3);
        assert_eq!(
            reopened.restore(group(0x21), generation(2), digest),
            Err(XfrmObjectRosterDurableError::NotFound)
        );
        assert_eq!(
            reopened
                .restore(group(0x21), generation(1), [0x5a; 32])
                .unwrap_err(),
            XfrmObjectRosterDurableError::WrongBinding
        );
    }

    #[test]
    fn permanent_root_lease_rejects_a_second_open() {
        let root = TestRoot::new();
        let first = store(&root);
        assert_eq!(
            XfrmObjectRosterRecoveryStore::open_bound(root.path(), key(9), NAMESPACE_BINDING)
                .unwrap_err(),
            XfrmObjectRosterDurableError::StoreBusy
        );
        drop(first);
        assert!(
            XfrmObjectRosterRecoveryStore::open_bound(root.path(), key(9), NAMESPACE_BINDING)
                .is_ok()
        );
    }

    #[test]
    fn prepare_rejects_illegal_arity_and_duplicate_identity() {
        let root = TestRoot::new();
        let store = store(&root);
        assert_eq!(
            store.prepare(group(0x21), generation(1), &[]),
            Err(XfrmObjectRosterDurableError::Malformed)
        );
        assert_eq!(
            store.prepare(group(0x21), generation(1), &members(9)),
            Err(XfrmObjectRosterDurableError::Malformed)
        );
        store
            .prepare(group(0x21), generation(1), &members(3))
            .unwrap();
        assert_eq!(
            store.prepare(group(0x21), generation(1), &members(2)),
            Err(XfrmObjectRosterDurableError::Duplicate)
        );
        // A different roster may not claim a kernel object an active roster
        // already owns.
        assert_eq!(
            store.prepare(group(0x22), generation(1), &members(1)),
            Err(XfrmObjectRosterDurableError::Duplicate)
        );
        assert!(store
            .prepare(group(0x22), generation(1), &[material(5), material(6)])
            .is_ok());
    }

    #[test]
    fn prepare_rejects_a_roster_whose_members_share_an_identity() {
        let root = TestRoot::new();
        let store = store(&root);
        assert_eq!(
            store.prepare(group(0x21), generation(1), &[material(0), material(0)]),
            Err(XfrmObjectRosterDurableError::Malformed)
        );
    }

    #[test]
    fn wrong_namespace_binding_and_wrong_key_fail_closed_on_reopen() {
        let root = TestRoot::new();
        let first = store(&root);
        drop(first);
        assert_eq!(
            XfrmObjectRosterRecoveryStore::open_bound(root.path(), key(9), [0x11; 40]).unwrap_err(),
            XfrmObjectRosterDurableError::WrongBinding
        );
        assert_eq!(
            XfrmObjectRosterRecoveryStore::open_bound(root.path(), key(8), NAMESPACE_BINDING)
                .unwrap_err(),
            XfrmObjectRosterDurableError::AuthenticationFailed
        );
    }

    #[test]
    fn foreign_store_and_actor_incarnations_fail_closed() {
        let root = TestRoot::new();
        let store = store(&root);
        let handle = store
            .prepare(group(0x21), generation(1), &members(2))
            .unwrap();
        let current = DurableRosterRecord::decode(&handle.0, &store.inner.proof_key).unwrap();

        let mut foreign_store = current.clone();
        foreign_store.store_incarnation = [0x5a; 16];
        assert_eq!(
            store.inspect(&foreign_store.handle(&store.inner.proof_key).unwrap()),
            Err(XfrmObjectRosterDurableError::WrongBinding)
        );

        let mut foreign_namespace = current.clone();
        foreign_namespace.namespace_seal = [0x5a; 32];
        assert_eq!(
            store.inspect(&foreign_namespace.handle(&store.inner.proof_key).unwrap()),
            Err(XfrmObjectRosterDurableError::WrongBinding)
        );

        let mut foreign_actor = current;
        foreign_actor.actor_incarnation = [0x5a; 16];
        assert_eq!(
            store.inspect(&foreign_actor.handle(&store.inner.proof_key).unwrap()),
            Err(XfrmObjectRosterDurableError::WrongIncarnation)
        );
    }

    #[test]
    fn superseded_handles_are_stale_and_cannot_drive_another_transition() {
        let root = TestRoot::new();
        let store = store(&root);
        let prepared = store
            .prepare(group(0x21), generation(1), &members(2))
            .unwrap();
        let issuing = advance(
            &store,
            &prepared,
            XfrmObjectRosterDurablePhase::Prepared,
            enter_issuing(2),
        );
        assert_eq!(
            store.inspect(&issuing),
            Ok(XfrmObjectRosterDurablePhase::Issuing)
        );
        assert_eq!(
            store.inspect(&prepared),
            Err(XfrmObjectRosterDurableError::Stale)
        );
        assert_eq!(
            store.transition(
                &prepared,
                XfrmObjectRosterDurablePhase::Prepared,
                enter_issuing(2)
            ),
            Err(XfrmObjectRosterDurableError::Stale)
        );
    }

    #[test]
    fn a_full_roster_lifecycle_publishes_one_epoch_burn_and_one_finalize() {
        let root = TestRoot::new();
        let store = store(&root);
        let before = store.lease().unwrap().inventory().unwrap().epoch;
        let prepared = store
            .prepare(group(0x21), generation(1), &members(5))
            .unwrap();
        let applied = run_to_applied(&store, &prepared, 5);
        assert_eq!(
            store.inspect(&applied),
            Ok(XfrmObjectRosterDurablePhase::Applied)
        );
        let committed = advance(
            &store,
            &applied,
            XfrmObjectRosterDurablePhase::Applied,
            XfrmObjectRosterTransition::new(
                XfrmObjectRosterDurablePhase::Committed,
                u8::try_from(5_usize).unwrap(),
            ),
        );
        assert_eq!(
            store.inspect(&committed),
            Ok(XfrmObjectRosterDurablePhase::Committed)
        );
        let after = store.lease().unwrap().inventory().unwrap().epoch;
        assert_eq!(after.get(), before.get() + 1, "exactly one epoch burn");

        let ledger = store.publication_ledger().unwrap();
        assert_eq!(
            ledger
                .iter()
                .filter(|entry| entry.class == XfrmObjectRosterPublicationClass::Prepare)
                .count(),
            1
        );
        assert_eq!(
            ledger
                .iter()
                .filter(|entry| entry.class == XfrmObjectRosterPublicationClass::Finalize)
                .count(),
            1
        );
        let sequences = ledger
            .iter()
            .map(|entry| entry.sequence)
            .collect::<Vec<_>>();
        assert_eq!(sequences, (1..=8).collect::<Vec<u16>>());
    }

    #[test]
    fn unresolved_rosters_gate_preparation_and_epoch_advancement() {
        let root = TestRoot::new();
        let store = store(&root);
        let prepared = store
            .prepare(group(0x21), generation(1), &members(2))
            .unwrap();
        // A prepared roster has no effects, so it gates nothing.
        assert!(store
            .prepare(group(0x22), generation(1), &[material(4)])
            .is_ok());
        assert!(store.advance_writer_epoch().is_ok());
        assert!(!store.has_unresolved_writer_authority().unwrap());

        let restored = store
            .restore_handle(
                &prepared,
                store.roster_fingerprint_for(&members(2)).unwrap(),
            )
            .unwrap();
        assert_eq!(restored.phase, XfrmObjectRosterDurablePhase::Prepared);
        assert_eq!(
            store.restore_handle(&prepared, [0x5a; 32]),
            Err(XfrmObjectRosterDurableError::WrongBinding)
        );
        let issuing = advance(
            &store,
            &prepared,
            XfrmObjectRosterDurablePhase::Prepared,
            enter_issuing(2),
        );
        assert!(store.has_unresolved_writer_authority().unwrap());
        assert_eq!(
            store.prepare(group(0x23), generation(1), &[material(6)]),
            Err(XfrmObjectRosterDurableError::InvalidTransition)
        );
        assert_eq!(
            store.advance_writer_epoch(),
            Err(XfrmObjectRosterDurableError::InvalidTransition)
        );
        assert_eq!(
            store.inspect(&issuing),
            Ok(XfrmObjectRosterDurablePhase::Issuing)
        );
    }

    #[test]
    fn a_stale_epoch_blocks_publication_but_never_blocks_restoration() {
        let root = TestRoot::new();
        let store = store(&root);
        let prepared = store
            .prepare(group(0x21), generation(1), &members(2))
            .unwrap();
        let applied = run_to_applied(&store, &prepared, 2);
        let digest = store.roster_fingerprint_for(&members(2)).unwrap();

        // Burn the epoch underneath the unresolved roster the way an ordinary
        // namespace mutation would.
        let lease = store.lease().unwrap();
        let inventory = lease.inventory().unwrap();
        lease.advance_epoch(&inventory).unwrap();
        drop(lease);

        let restored = store.restore(group(0x21), generation(1), digest).unwrap();
        assert_eq!(restored.phase, XfrmObjectRosterDurablePhase::Applied);
        assert!(!store.record_writer_epoch_is_current(&restored).unwrap());
        assert_eq!(
            store.transition(
                &applied,
                XfrmObjectRosterDurablePhase::Applied,
                XfrmObjectRosterTransition::new(
                    XfrmObjectRosterDurablePhase::Committed,
                    u8::try_from(2_usize).unwrap()
                ),
            ),
            Err(XfrmObjectRosterDurableError::Stale)
        );
    }

    #[test]
    fn a_prepared_roster_retires_at_a_stale_epoch() {
        let root = TestRoot::new();
        let store = store(&root);
        let prepared = store
            .prepare(group(0x21), generation(1), &members(2))
            .unwrap();
        store.advance_writer_epoch().unwrap();
        let retired = store
            .transition(
                &prepared,
                XfrmObjectRosterDurablePhase::Prepared,
                XfrmObjectRosterTransition::new(XfrmObjectRosterDurablePhase::Retired, 0),
            )
            .unwrap();
        assert_eq!(retired.phase, XfrmObjectRosterDurablePhase::Retired);
    }

    #[test]
    fn malformed_journal_sequence_overflow_fails_closed() {
        let root = TestRoot::new();
        let store = store(&root);
        let seed = store
            .prepare(group(0x21), generation(1), &members(2))
            .unwrap();
        let mut saturated = DurableRosterRecord::decode(&seed.0, &store.inner.proof_key).unwrap();
        saturated.group_id = group(0x31);
        saturated.publication_sequence = u16::MAX;
        for (index, slot) in saturated.members.iter_mut().flatten().enumerate() {
            let byte = 0xb0 + u8::try_from(index).unwrap();
            slot.member_id = XfrmObjectRosterMemberId::from_bytes([byte; 16]).unwrap();
            slot.deletion_identity_fingerprint = [byte; 32];
            slot.install_request_fingerprint = [byte ^ 0x0f; 32];
        }
        saturated.roster_fingerprint = roster_fingerprint(
            store.inner.proof_key.canonical_mac_key(),
            &saturated.active(),
        )
        .unwrap();
        let lease = store.lease().unwrap();
        lease
            .publish_record(&saturated, PublicationClass::Transition)
            .unwrap();
        drop(lease);
        let handle = saturated.handle(&store.inner.proof_key).unwrap();
        assert_eq!(
            store.transition(
                &handle,
                XfrmObjectRosterDurablePhase::Prepared,
                enter_issuing(2)
            ),
            Err(XfrmObjectRosterDurableError::Duplicate)
        );
    }

    #[test]
    fn journal_retains_the_exact_successor_history_without_a_predecessor_unlink_window() {
        let root = TestRoot::new();
        let store = store(&root);
        let prepared = store
            .prepare(group(0x21), generation(1), &members(2))
            .unwrap();
        let issuing = advance(
            &store,
            &prepared,
            XfrmObjectRosterDurablePhase::Prepared,
            enter_issuing(2),
        );
        // The journal contains both complete logical states in one permanent
        // file. There is no predecessor unlink barrier to crash between.
        let (_, history) = read_journal_records(&store.inner).unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(
            store.inspect(&issuing),
            Ok(XfrmObjectRosterDurablePhase::Issuing)
        );
    }

    #[test]
    fn journal_reopens_every_happy_path_logical_transition() {
        let root = TestRoot::new();
        let mut recovered_store = store(&root);
        let mut handle = recovered_store
            .prepare(group(0x43), generation(1), &members(5))
            .unwrap();
        let mut expected_sequence = 1_usize;

        // Each point is a process-loss boundary: only the authenticated
        // journal frame(s) survive the old store instance. Reopening must
        // recover exactly the current handle rather than a predecessor or an
        // uncommitted aggregate.
        for transition in std::iter::once((
            XfrmObjectRosterDurablePhase::Prepared,
            enter_issuing(5),
            XfrmObjectRosterDurablePhase::Issuing,
        ))
        .chain((0..5).map(|ordinal| {
            (
                XfrmObjectRosterDurablePhase::Issuing,
                acquire_member(5, ordinal),
                if ordinal == 4 {
                    XfrmObjectRosterDurablePhase::Applied
                } else {
                    XfrmObjectRosterDurablePhase::Issuing
                },
            )
        })) {
            handle = advance(&recovered_store, &handle, transition.0, transition.1);
            expected_sequence += 1;
            drop(recovered_store);
            recovered_store = store(&root);
            assert_eq!(recovered_store.inspect(&handle), Ok(transition.2));
            let (_, history) = read_journal_records(&recovered_store.inner).unwrap();
            assert_eq!(history.len(), expected_sequence);
        }

        handle = advance(
            &recovered_store,
            &handle,
            XfrmObjectRosterDurablePhase::Applied,
            XfrmObjectRosterTransition::new(XfrmObjectRosterDurablePhase::Committed, 5),
        );
        drop(recovered_store);
        let store = store(&root);
        assert_eq!(
            store.inspect(&handle),
            Ok(XfrmObjectRosterDurablePhase::Committed)
        );
    }

    #[test]
    fn journal_repairs_only_an_incomplete_unacknowledged_tail() {
        let root = TestRoot::new();
        let opened = store(&root);
        let prepared = opened
            .prepare(group(0x44), generation(1), &members(2))
            .unwrap();
        let journal = root.path().join(JOURNAL_NAME);
        let complete_length = fs::metadata(&journal).unwrap().len();
        drop(opened);

        // This models a power loss during the append, before `sync_all`
        // could acknowledge another logical publication.  The previous whole
        // frame is still the exact pre-effect recovery authority.
        let mut file = fs::OpenOptions::new().append(true).open(&journal).unwrap();
        file.write_all(&[0x5a; 17]).unwrap();
        file.sync_all().unwrap();
        drop(file);

        let reopened = store(&root);
        assert_eq!(
            reopened.inspect(&prepared),
            Ok(XfrmObjectRosterDurablePhase::Prepared)
        );
        assert_eq!(fs::metadata(&journal).unwrap().len(), complete_length);
    }

    #[test]
    fn journal_rejects_a_corrupted_complete_tail_frame() {
        let root = TestRoot::new();
        let store = store(&root);
        store
            .prepare(group(0x45), generation(1), &members(2))
            .unwrap();
        let journal = root.path().join(JOURNAL_NAME);
        drop(store);

        // A whole frame could have been an acknowledged transition.  Its bad
        // authenticator therefore remains a fail-closed corruption, rather
        // than being mistaken for a torn, unacknowledged append.
        let mut file = fs::OpenOptions::new().append(true).open(&journal).unwrap();
        file.write_all(&[0x5a; XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES])
            .unwrap();
        file.sync_all().unwrap();
        drop(file);

        assert_eq!(
            XfrmObjectRosterRecoveryStore::open_bound(root.path(), key(9), NAMESPACE_BINDING)
                .unwrap_err(),
            XfrmObjectRosterDurableError::Malformed
        );
    }

    #[test]
    fn journal_compacts_terminal_history_only_before_a_later_prepare() {
        let root = TestRoot::new();
        let store = store(&root);

        // Repeated completed groups never make the descriptor grow with
        // process lifetime.  Compaction is intentionally paid by the next
        // prepare/maintenance operation, never by the current run path.
        for index in 0..12_u8 {
            let prepared = store
                .prepare(group(0x50 + index), generation(1), &members(1))
                .unwrap();
            let applied = run_to_applied(&store, &prepared, 1);
            advance(
                &store,
                &applied,
                XfrmObjectRosterDurablePhase::Applied,
                XfrmObjectRosterTransition::new(XfrmObjectRosterDurablePhase::Committed, 1),
            );
            let (_, history) = read_journal_records(&store.inner).unwrap();
            assert_eq!(history.len(), 4);
        }

        store.tests_reset_physical_barriers().unwrap();
        store
            .prepare(group(0x61), generation(1), &members(1))
            .unwrap();
        let (_, history) = read_journal_records(&store.inner).unwrap();
        assert_eq!(history.len(), 1);
        // One fully synchronized compaction replacement plus the newly
        // prepared frame.  This maintenance cost is outside the five-member
        // run-path barrier detector above.
        assert_eq!(store.tests_physical_barriers().unwrap(), 3);
    }

    #[test]
    fn journal_reopens_disjoint_concurrent_prepared_group_identities() {
        let root = TestRoot::new();
        let opened = store(&root);
        let first = opened
            .prepare(group(0x62), generation(1), &members(2))
            .unwrap();
        let second_members = vec![material(5)];
        let second = opened
            .prepare(group(0x63), generation(1), &second_members)
            .unwrap();
        drop(opened);

        let reopened = store(&root);
        assert_eq!(
            reopened.inspect(&first),
            Ok(XfrmObjectRosterDurablePhase::Prepared)
        );
        assert_eq!(
            reopened.inspect(&second),
            Ok(XfrmObjectRosterDurablePhase::Prepared)
        );
    }

    #[test]
    fn journal_rejects_unsafe_entry_kinds_and_permissions() {
        let restrictive = TestRoot::new();
        drop(store(&restrictive));
        let journal = restrictive.path().join(JOURNAL_NAME);
        fs::set_permissions(&journal, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            XfrmObjectRosterRecoveryStore::open_bound(
                restrictive.path(),
                key(9),
                NAMESPACE_BINDING
            )
            .unwrap_err(),
            XfrmObjectRosterDurableError::Malformed
        );

        let symlinked = TestRoot::new();
        drop(store(&symlinked));
        let journal = symlinked.path().join(JOURNAL_NAME);
        fs::remove_file(&journal).unwrap();
        std::os::unix::fs::symlink("control", &journal).unwrap();
        assert_eq!(
            XfrmObjectRosterRecoveryStore::open_bound(symlinked.path(), key(9), NAMESPACE_BINDING)
                .unwrap_err(),
            XfrmObjectRosterDurableError::Malformed
        );

        let non_regular = TestRoot::new();
        drop(store(&non_regular));
        let journal = non_regular.path().join(JOURNAL_NAME);
        fs::remove_file(&journal).unwrap();
        fs::create_dir(&journal).unwrap();
        assert_eq!(
            XfrmObjectRosterRecoveryStore::open_bound(
                non_regular.path(),
                key(9),
                NAMESPACE_BINDING
            )
            .unwrap_err(),
            XfrmObjectRosterDurableError::Malformed
        );
    }

    #[test]
    fn existing_per_file_roster_roots_remain_on_the_legacy_format() {
        let root = TestRoot::new();
        let journal_store = store(&root);
        let prepared = journal_store
            .prepare(group(0x64), generation(1), &members(2))
            .unwrap();
        let record =
            DurableRosterRecord::decode(&prepared.0, &journal_store.inner.proof_key).unwrap();
        drop(journal_store);

        // Simulate a root written by the predecessor format: it has the same
        // authenticated record and epoch/control witnesses, but no journal.
        let journal = root.path().join(JOURNAL_NAME);
        fs::remove_file(&journal).unwrap();
        let legacy = root.path().join(record_name(&record));
        fs::write(&legacy, record.encode(&key(9)).unwrap()).unwrap();
        fs::set_permissions(&legacy, fs::Permissions::from_mode(FILE_MODE)).unwrap();

        let reopened = store(&root);
        assert!(!reopened.inner.journal_enabled);
        assert_eq!(
            reopened.inspect(&prepared),
            Ok(XfrmObjectRosterDurablePhase::Prepared)
        );
        assert!(!root.path().join(JOURNAL_NAME).exists());
    }

    #[test]
    fn terminal_rosters_are_pruned_at_the_next_prepare_or_epoch_advance() {
        let root = TestRoot::new();
        let store = store(&root);
        let prepared = store
            .prepare(group(0x21), generation(1), &members(2))
            .unwrap();
        let applied = run_to_applied(&store, &prepared, 2);
        advance(
            &store,
            &applied,
            XfrmObjectRosterDurablePhase::Applied,
            XfrmObjectRosterTransition::new(
                XfrmObjectRosterDurablePhase::Committed,
                u8::try_from(2_usize).unwrap(),
            ),
        );
        assert!(record_file_names(&root).is_empty());
        store.advance_writer_epoch().unwrap();
        assert!(record_file_names(&root).is_empty());

        let prepared = store
            .prepare(group(0x31), generation(1), &members(2))
            .unwrap();
        advance(
            &store,
            &prepared,
            XfrmObjectRosterDurablePhase::Prepared,
            XfrmObjectRosterTransition::new(XfrmObjectRosterDurablePhase::Retired, 0),
        );
        assert!(record_file_names(&root).is_empty());
        store
            .prepare(group(0x41), generation(1), &members(2))
            .unwrap();
        assert!(record_file_names(&root).is_empty());
    }

    #[test]
    fn filenames_cross_check_the_record_body_including_the_sequence() {
        let root = TestRoot::new();
        let store = store(&root);
        let handle = store
            .prepare(group(0x21), generation(7), &members(2))
            .unwrap();
        let record = DurableRosterRecord::decode(&handle.0, &store.inner.proof_key).unwrap();
        let name = record_name(&record);
        assert_eq!(
            name,
            format!("prepared-{}-0000000000000007-0001", encode_hex(&[0x21; 16]))
        );
        assert_eq!(
            parse_record_name(OsStr::new(&name)),
            Some((
                XfrmObjectRosterDurablePhase::Prepared,
                group(0x21),
                generation(7),
                1
            ))
        );
        assert!(record_file_names(&root).is_empty());

        // The journal removes the record filename from the trusted surface;
        // a changed logical frame still poisons the authenticated scan.
        let journal = root.path().join(JOURNAL_NAME);
        let mut bytes = fs::read(&journal).unwrap();
        let offset = JOURNAL_HEADER_BYTES + XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES - 1;
        bytes[offset] ^= 0x01;
        fs::write(&journal, bytes).unwrap();
        assert_eq!(
            store.advance_writer_epoch(),
            Err(XfrmObjectRosterDurableError::AuthenticationFailed)
        );
    }

    #[test]
    fn malformed_filenames_are_rejected_without_panicking() {
        let root = TestRoot::new();
        let store = store(&root);
        for name in [
            format!("prepared-{}-0000000000000001", encode_hex(&[0x21; 16])),
            format!("prepared-{}-0000000000000001-0000", encode_hex(&[0x21; 16])),
            format!("prepared-{}-0000000000000001-1", encode_hex(&[0x21; 16])),
            format!("issued-{}-0000000000000001-0001", encode_hex(&[0x21; 16])),
            format!("prepared-aé{}-0000000000000001-0001", "a".repeat(29)),
        ] {
            let path = root.path().join(&name);
            fs::write(&path, [0_u8; XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES]).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(FILE_MODE)).unwrap();
            assert_eq!(
                store.advance_writer_epoch(),
                Err(XfrmObjectRosterDurableError::Malformed),
                "{name}"
            );
            fs::remove_file(&path).unwrap();
        }
    }

    #[test]
    fn a_second_unresolved_roster_fails_the_inventory_closed() {
        let root = TestRoot::new();
        let store = store(&root);
        let prepared = store
            .prepare(group(0x21), generation(1), &members(2))
            .unwrap();
        let applied = run_to_applied(&store, &prepared, 2);
        let current = DurableRosterRecord::decode(&applied.0, &store.inner.proof_key).unwrap();
        let mut second = current;
        second.group_id = group(0x31);
        for (index, slot) in second.members.iter_mut().flatten().enumerate() {
            slot.deletion_identity_fingerprint = [0x90 + u8::try_from(index).unwrap(); 32];
            slot.install_request_fingerprint = [0xa0 + u8::try_from(index).unwrap(); 32];
        }
        second.roster_fingerprint =
            roster_fingerprint(store.inner.proof_key.canonical_mac_key(), &second.active())
                .unwrap();
        let lease = store.lease().unwrap();
        lease
            .publish_record(&second, PublicationClass::Transition)
            .unwrap();
        drop(lease);

        assert_eq!(
            store.inspect(&applied),
            Err(XfrmObjectRosterDurableError::Duplicate)
        );
    }

    #[test]
    fn duplicate_active_deletion_identities_across_rosters_fail_closed() {
        let root = TestRoot::new();
        let store = store(&root);
        let handle = store
            .prepare(group(0x21), generation(1), &members(2))
            .unwrap();
        let current = DurableRosterRecord::decode(&handle.0, &store.inner.proof_key).unwrap();
        let mut duplicate = current;
        duplicate.group_id = group(0x31);
        let lease = store.lease().unwrap();
        lease
            .publish_record(&duplicate, PublicationClass::Transition)
            .unwrap();
        drop(lease);

        assert_eq!(
            store.advance_writer_epoch(),
            Err(XfrmObjectRosterDurableError::Duplicate)
        );
    }

    #[test]
    fn cross_family_store_roots_are_rejected_in_every_direction() {
        let object_key =
            || crate::durable_object::XfrmObjectRecoveryProofKey::new([9; 32]).unwrap();
        let relocation_key =
            || crate::durable_relocation::XfrmSaRelocationRecoveryProofKey::new([9; 32]).unwrap();

        let object_root = TestRoot::new();
        drop(
            crate::durable_object::XfrmObjectInstallRecoveryStore::open_bound(
                object_root.path(),
                object_key(),
                NAMESPACE_BINDING,
            )
            .unwrap(),
        );
        let relocation_root = TestRoot::new();
        drop(
            crate::durable_relocation::XfrmSaRelocationRecoveryStore::open_bound(
                relocation_root.path(),
                relocation_key(),
                NAMESPACE_BINDING,
            )
            .unwrap(),
        );
        let roster_root = TestRoot::new();
        drop(store(&roster_root));

        assert!(XfrmObjectRosterRecoveryStore::open_bound(
            object_root.path(),
            key(9),
            NAMESPACE_BINDING
        )
        .is_err());
        assert!(XfrmObjectRosterRecoveryStore::open_bound(
            relocation_root.path(),
            key(9),
            NAMESPACE_BINDING
        )
        .is_err());
        assert!(
            crate::durable_object::XfrmObjectInstallRecoveryStore::open_bound(
                roster_root.path(),
                object_key(),
                NAMESPACE_BINDING
            )
            .is_err()
        );
        assert!(
            crate::durable_object::XfrmObjectInstallRecoveryStore::open_bound(
                relocation_root.path(),
                object_key(),
                NAMESPACE_BINDING
            )
            .is_err()
        );
        assert!(
            crate::durable_relocation::XfrmSaRelocationRecoveryStore::open_bound(
                roster_root.path(),
                relocation_key(),
                NAMESPACE_BINDING
            )
            .is_err()
        );
        assert!(
            crate::durable_relocation::XfrmSaRelocationRecoveryStore::open_bound(
                object_root.path(),
                relocation_key(),
                NAMESPACE_BINDING
            )
            .is_err()
        );
    }

    #[test]
    fn a_roster_sized_file_in_an_object_root_fails_the_exact_size_check() {
        // Both families name records `{phase}-{id}-{generation}`-first, so a
        // roster-sized file can be dropped into an object root under a name
        // that parses. The exact-size read is what keeps it fail-closed.
        let object_root = TestRoot::new();
        let object_store = crate::durable_object::XfrmObjectInstallRecoveryStore::open_bound(
            object_root.path(),
            crate::durable_object::XfrmObjectRecoveryProofKey::new([9; 32]).unwrap(),
            NAMESPACE_BINDING,
        )
        .unwrap();
        let path = object_root.path().join(format!(
            "prepared-{}-0000000000000001",
            encode_hex(&[0x21; 16])
        ));
        fs::write(&path, [0_u8; XFRM_OBJECT_ROSTER_RECOVERY_HANDLE_BYTES]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(FILE_MODE)).unwrap();
        assert_eq!(
            object_store.advance_writer_epoch(),
            Err(crate::XfrmObjectInstallDurableError::Malformed)
        );
    }

    #[test]
    fn authenticated_control_only_initialization_residue_repairs_epoch_one() {
        let root = TestRoot::new();
        let initial = store(&root);
        let epoch = epoch_name(NonZeroU64::new(1).unwrap());
        drop(initial);
        fs::remove_file(root.path().join(epoch)).unwrap();
        std::fs::File::open(root.path())
            .unwrap()
            .sync_all()
            .unwrap();

        let reopened = store(&root);
        let inventory = reopened.lease().unwrap().inventory().unwrap();
        assert_eq!(inventory.epoch, NonZeroU64::new(1).unwrap());
        assert!(inventory.records.is_empty());
    }

    #[test]
    fn process_loss_staging_residue_is_removed_before_reopen() {
        let root = TestRoot::new();
        drop(store(&root));
        let pending = root
            .path()
            .join(".opc-xfrm-roster-pending-1234567890abcdef1234567890abcdef");
        fs::write(&pending, [0xa5; 17]).unwrap();
        fs::set_permissions(&pending, fs::Permissions::from_mode(FILE_MODE)).unwrap();
        std::fs::File::open(&pending).unwrap().sync_all().unwrap();
        std::fs::File::open(root.path())
            .unwrap()
            .sync_all()
            .unwrap();

        let reopened = store(&root);
        assert!(!pending.exists());
        assert!(reopened.lease().unwrap().inventory().is_ok());
    }

    #[test]
    fn first_publication_staging_residue_is_removed_before_initialization() {
        let root = TestRoot::new();
        let pending = root
            .path()
            .join(".opc-xfrm-roster-pending-abcdef1234567890abcdef1234567890");
        fs::write(&pending, [0x5a; 9]).unwrap();
        fs::set_permissions(&pending, fs::Permissions::from_mode(FILE_MODE)).unwrap();
        std::fs::File::open(&pending).unwrap().sync_all().unwrap();
        std::fs::File::open(root.path())
            .unwrap()
            .sync_all()
            .unwrap();

        let initialized = store(&root);
        assert!(!pending.exists());
        let inventory = initialized.lease().unwrap().inventory().unwrap();
        assert_eq!(inventory.epoch, NonZeroU64::new(1).unwrap());
        assert!(inventory.records.is_empty());
    }

    #[test]
    fn oversized_staging_residue_remains_fail_closed() {
        let root = TestRoot::new();
        drop(store(&root));
        let pending = root
            .path()
            .join(".opc-xfrm-roster-pending-fedcba0987654321fedcba0987654321");
        fs::write(&pending, [0x5a; MAX_JOURNAL_BYTES + 1]).unwrap();
        fs::set_permissions(&pending, fs::Permissions::from_mode(FILE_MODE)).unwrap();
        assert_eq!(
            XfrmObjectRosterRecoveryStore::open_bound(root.path(), key(9), NAMESPACE_BINDING)
                .unwrap_err(),
            XfrmObjectRosterDurableError::Malformed
        );
        assert!(pending.symlink_metadata().is_ok());
    }

    #[test]
    fn two_consecutive_epoch_witnesses_reconcile_to_the_successor() {
        let root = TestRoot::new();
        let store = store(&root);
        let lease = store.lease().unwrap();
        let inventory = lease.inventory().unwrap();
        let next = EpochRecord {
            store_incarnation: lease.store.control.store_incarnation,
            epoch: NonZeroU64::new(inventory.epoch.get() + 1).unwrap(),
        };
        publish_new_file(
            lease.store,
            &epoch_name(next.epoch),
            &next.encode(&lease.store.proof_key).unwrap(),
        )
        .unwrap();
        drop(lease);

        let reconciled = store.lease().unwrap().inventory().unwrap();
        assert_eq!(reconciled.epoch, next.epoch);
        assert!(!root
            .path()
            .join(epoch_name(NonZeroU64::new(1).unwrap()))
            .exists());
    }

    #[test]
    fn non_consecutive_epoch_witnesses_fail_closed() {
        let root = TestRoot::new();
        let store = store(&root);
        let lease = store.lease().unwrap();
        let skipped = EpochRecord {
            store_incarnation: lease.store.control.store_incarnation,
            epoch: NonZeroU64::new(9).unwrap(),
        };
        publish_new_file(
            lease.store,
            &epoch_name(skipped.epoch),
            &skipped.encode(&lease.store.proof_key).unwrap(),
        )
        .unwrap();
        drop(lease);

        assert!(matches!(
            store.lease().unwrap().inventory(),
            Err(XfrmObjectRosterDurableError::Duplicate)
        ));
    }

    #[test]
    fn derived_member_identities_are_stable_and_ordinal_separated() {
        let root = TestRoot::new();
        let store = store(&root);
        let first = store
            .derive_member_identity(group(0x21), generation(1), 0)
            .unwrap();
        assert_eq!(
            store
                .derive_member_identity(group(0x21), generation(1), 0)
                .unwrap(),
            first
        );
        for (label, other) in [
            (
                "ordinal",
                store
                    .derive_member_identity(group(0x21), generation(1), 1)
                    .unwrap(),
            ),
            (
                "generation",
                store
                    .derive_member_identity(group(0x21), generation(2), 0)
                    .unwrap(),
            ),
            (
                "group",
                store
                    .derive_member_identity(group(0x22), generation(1), 0)
                    .unwrap(),
            ),
        ] {
            assert_ne!(first, other, "{label} did not separate the identity");
        }
        assert_eq!(
            store.derive_member_identity(
                group(0x21),
                generation(1),
                XFRM_OBJECT_ROSTER_MAX_MEMBERS
            ),
            Err(XfrmObjectRosterDurableError::Malformed)
        );
    }

    #[test]
    fn non_exact_removal_marks_are_rejected_before_any_fingerprint() {
        let root = TestRoot::new();
        let store = store(&root);
        let XfrmObjectInstallRequest::Sa(mut request) = sample_install_request() else {
            panic!("expected an SA request");
        };
        request.parameters.mark = Some(crate::XfrmLookupMark::new(0x10, 0xf0).unwrap());
        assert_eq!(
            store.fingerprints_for_request(&XfrmObjectInstallRequest::Sa(request)),
            Err(XfrmObjectRosterDurableError::NonExactRemovalIdentity)
        );
    }

    #[test]
    fn transitions_reject_member_updates_outside_the_roster_arity() {
        let root = TestRoot::new();
        let store = store(&root);
        let prepared = store
            .prepare(group(0x21), generation(1), &members(2))
            .unwrap();
        let transition = enter_issuing(2).with_member(
            5,
            XfrmObjectRosterMemberTransition {
                phase: XfrmObjectRosterMemberPhase::Acquired,
                sweep_proof: Some(XfrmObjectRosterSweepProof::Absent),
                adjacent_proof: Some(XfrmObjectRosterAdjacentProof::Absent),
            },
        );
        assert_eq!(
            store.transition(
                &prepared,
                XfrmObjectRosterDurablePhase::Prepared,
                transition
            ),
            Err(XfrmObjectRosterDurableError::Malformed)
        );
        let beyond = enter_issuing(2).with_member(
            XFRM_OBJECT_ROSTER_MAX_MEMBERS,
            XfrmObjectRosterMemberTransition {
                phase: XfrmObjectRosterMemberPhase::Acquired,
                sweep_proof: Some(XfrmObjectRosterSweepProof::Absent),
                adjacent_proof: Some(XfrmObjectRosterAdjacentProof::Absent),
            },
        );
        assert_eq!(
            store.transition(&prepared, XfrmObjectRosterDurablePhase::Prepared, beyond),
            Err(XfrmObjectRosterDurableError::Malformed)
        );
    }

    #[test]
    fn illegal_group_edges_are_rejected_before_any_publication() {
        let root = TestRoot::new();
        let store = store(&root);
        let prepared = store
            .prepare(group(0x21), generation(1), &members(2))
            .unwrap();
        assert_eq!(
            store.transition(
                &prepared,
                XfrmObjectRosterDurablePhase::Prepared,
                XfrmObjectRosterTransition::new(XfrmObjectRosterDurablePhase::Applied, 2),
            ),
            Err(XfrmObjectRosterDurableError::InvalidTransition)
        );
        assert_eq!(
            store.transition(
                &prepared,
                XfrmObjectRosterDurablePhase::Issuing,
                enter_issuing(2),
            ),
            Err(XfrmObjectRosterDurableError::InvalidTransition)
        );
        assert_eq!(
            store.inspect(&prepared),
            Ok(XfrmObjectRosterDurablePhase::Prepared)
        );
    }

    #[test]
    fn a_compensation_walk_publishes_one_removal_at_a_time() {
        let root = TestRoot::new();
        let store = store(&root);
        let prepared = store
            .prepare(group(0x21), generation(1), &members(3))
            .unwrap();
        let mut handle = advance(
            &store,
            &prepared,
            XfrmObjectRosterDurablePhase::Prepared,
            enter_issuing(3),
        );
        handle = advance(
            &store,
            &handle,
            XfrmObjectRosterDurablePhase::Issuing,
            acquire_member(3, 0),
        );
        handle = advance(
            &store,
            &handle,
            XfrmObjectRosterDurablePhase::Issuing,
            acquire_member(3, 1),
        );
        // Member two fails after two members were acquired.
        handle = advance(
            &store,
            &handle,
            XfrmObjectRosterDurablePhase::Issuing,
            XfrmObjectRosterTransition::new(XfrmObjectRosterDurablePhase::Compensating, 1)
                .with_member(
                    2,
                    XfrmObjectRosterMemberTransition {
                        phase: XfrmObjectRosterMemberPhase::Indeterminate,
                        sweep_proof: Some(XfrmObjectRosterSweepProof::Absent),
                        adjacent_proof: Some(XfrmObjectRosterAdjacentProof::Absent),
                    },
                ),
        );
        // Reconcile the failed member first, then descend.
        for (ordinal, cursor, phase) in [
            (2_usize, 1_u8, XfrmObjectRosterMemberPhase::RemovalAdmitted),
            (2, 1, XfrmObjectRosterMemberPhase::Retired),
            (1, 1, XfrmObjectRosterMemberPhase::RemovalAdmitted),
            (1, 0, XfrmObjectRosterMemberPhase::Retired),
            (0, 0, XfrmObjectRosterMemberPhase::RemovalAdmitted),
            (0, 0, XfrmObjectRosterMemberPhase::Retired),
        ] {
            handle = advance(
                &store,
                &handle,
                XfrmObjectRosterDurablePhase::Compensating,
                XfrmObjectRosterTransition::new(XfrmObjectRosterDurablePhase::Compensating, cursor)
                    .with_member(
                        ordinal,
                        XfrmObjectRosterMemberTransition {
                            phase,
                            sweep_proof: Some(XfrmObjectRosterSweepProof::Absent),
                            adjacent_proof: Some(XfrmObjectRosterAdjacentProof::Absent),
                        },
                    ),
            );
        }
        let rolled_back = advance(
            &store,
            &handle,
            XfrmObjectRosterDurablePhase::Compensating,
            XfrmObjectRosterTransition::new(XfrmObjectRosterDurablePhase::RolledBack, 0),
        );
        assert_eq!(
            store.inspect(&rolled_back),
            Ok(XfrmObjectRosterDurablePhase::RolledBack)
        );
        assert!(!store.has_unresolved_writer_authority().unwrap());
    }

    #[test]
    fn compensation_never_descends_past_an_unresolved_member() {
        let root = TestRoot::new();
        let store = store(&root);
        let prepared = store
            .prepare(group(0x21), generation(1), &members(3))
            .unwrap();
        let mut handle = advance(
            &store,
            &prepared,
            XfrmObjectRosterDurablePhase::Prepared,
            enter_issuing(3),
        );
        handle = advance(
            &store,
            &handle,
            XfrmObjectRosterDurablePhase::Issuing,
            acquire_member(3, 0),
        );
        handle = advance(
            &store,
            &handle,
            XfrmObjectRosterDurablePhase::Issuing,
            acquire_member(3, 1),
        );
        handle = advance(
            &store,
            &handle,
            XfrmObjectRosterDurablePhase::Issuing,
            XfrmObjectRosterTransition::new(XfrmObjectRosterDurablePhase::Compensating, 1)
                .with_member(
                    2,
                    XfrmObjectRosterMemberTransition {
                        phase: XfrmObjectRosterMemberPhase::Indeterminate,
                        sweep_proof: Some(XfrmObjectRosterSweepProof::Absent),
                        adjacent_proof: Some(XfrmObjectRosterAdjacentProof::Absent),
                    },
                ),
        );
        // Admitting a second removal while member two is unresolved would put
        // two members in flight at once.
        assert_eq!(
            store.transition(
                &handle,
                XfrmObjectRosterDurablePhase::Compensating,
                XfrmObjectRosterTransition::new(XfrmObjectRosterDurablePhase::Compensating, 1)
                    .with_member(
                        1,
                        XfrmObjectRosterMemberTransition {
                            phase: XfrmObjectRosterMemberPhase::RemovalAdmitted,
                            sweep_proof: Some(XfrmObjectRosterSweepProof::Absent),
                            adjacent_proof: Some(XfrmObjectRosterAdjacentProof::Absent),
                        },
                    ),
            ),
            Err(XfrmObjectRosterDurableError::Malformed)
        );
    }

    #[test]
    fn a_sweep_conflict_publishes_a_zero_effect_terminal_verdict() {
        let root = TestRoot::new();
        let store = store(&root);
        let prepared = store
            .prepare(group(0x21), generation(1), &members(3))
            .unwrap();
        let mut conflicted =
            XfrmObjectRosterTransition::new(XfrmObjectRosterDurablePhase::Issuing, 0);
        for index in 0..3 {
            conflicted = conflicted.with_member(
                index,
                XfrmObjectRosterMemberTransition {
                    phase: XfrmObjectRosterMemberPhase::Pending,
                    sweep_proof: Some(if index == 1 {
                        XfrmObjectRosterSweepProof::Conflict
                    } else {
                        XfrmObjectRosterSweepProof::Absent
                    }),
                    adjacent_proof: None,
                },
            );
        }
        let issuing = advance(
            &store,
            &prepared,
            XfrmObjectRosterDurablePhase::Prepared,
            conflicted,
        );
        let no_mutation = advance(
            &store,
            &issuing,
            XfrmObjectRosterDurablePhase::Issuing,
            XfrmObjectRosterTransition::new(XfrmObjectRosterDurablePhase::NoMutation, 0),
        );
        assert_eq!(
            store.inspect(&no_mutation),
            Ok(XfrmObjectRosterDurablePhase::NoMutation)
        );
        let retired = advance(
            &store,
            &no_mutation,
            XfrmObjectRosterDurablePhase::NoMutation,
            XfrmObjectRosterTransition::new(XfrmObjectRosterDurablePhase::Retired, 0),
        );
        assert_eq!(
            store.inspect(&retired),
            Ok(XfrmObjectRosterDurablePhase::Retired)
        );
    }

    #[test]
    fn capacity_is_bounded_well_below_the_scan_limit() {
        assert_eq!(MAX_ACTIVE_RECORDS, 30);
        const {
            assert!(MAX_ACTIVE_RECORDS * 2 + 3 <= MAX_STORE_ENTRIES);
        }
    }

    #[test]
    fn all_new_diagnostics_are_value_free() {
        let group_id = XfrmObjectRosterGroupId::from_bytes([0xab; 16]).unwrap();
        let member_id = XfrmObjectRosterMemberId::from_bytes([0xab; 16]).unwrap();
        let roster_generation = XfrmObjectRosterOperationGeneration::new(0xfeed_beef).unwrap();
        let record = roster_record(
            XfrmObjectRosterDurablePhase::Applied,
            u8::try_from(ARITY).unwrap(),
            &[acquired(); ARITY],
        );
        let handle = record.handle(&key(9)).unwrap();
        let slot = record.member(0).copied().unwrap();
        let fingerprints = XfrmObjectRosterMemberFingerprints::repeated(0xab);
        let material = material(0);
        let transition = XfrmObjectRosterTransition::new(XfrmObjectRosterDurablePhase::Issuing, 0)
            .with_member(
                0,
                XfrmObjectRosterMemberTransition {
                    phase: XfrmObjectRosterMemberPhase::Acquired,
                    sweep_proof: Some(XfrmObjectRosterSweepProof::Absent),
                    adjacent_proof: Some(XfrmObjectRosterAdjacentProof::AbsentThenAlreadyExists),
                },
            );
        let member_transition = XfrmObjectRosterMemberTransition {
            phase: XfrmObjectRosterMemberPhase::RemovalAdmitted,
            sweep_proof: Some(XfrmObjectRosterSweepProof::Conflict),
            adjacent_proof: Some(XfrmObjectRosterAdjacentProof::Conflict),
        };
        let root = TestRoot::new();
        let opened = store(&root);
        let mac_key = key(0xab);
        let borrowed = mac_key.canonical_mac_key();
        for rendered in [
            format!("{group_id:?} {group_id}"),
            format!("{member_id:?} {member_id}"),
            format!("{roster_generation:?} {roster_generation}"),
            format!("{handle:?} {handle}"),
            format!("{:?} {}", key(0xab), key(0xab)),
            format!("{record:?}"),
            format!("{slot:?}"),
            format!("{fingerprints:?}"),
            format!("{material:?}"),
            format!("{transition:?}"),
            format!("{member_transition:?}"),
            format!("{opened:?}"),
            format!("{borrowed:?}"),
            format!("{:?}", XfrmObjectRosterMemberPhase::Acquired),
            format!("{:?}", XfrmObjectRosterSweepProof::Conflict),
            format!(
                "{:?}",
                XfrmObjectRosterAdjacentProof::AbsentThenAlreadyExists
            ),
        ] {
            // Both renderings of every fixture are forbidden. Rust's derived
            // `Debug` prints `[u8; N]` in DECIMAL and a `u64` generation in
            // decimal too, so a hex-only predicate would let a `#[derive(Debug)]`
            // regression on any of these types pass silently.
            for forbidden in [
                // group id / member id / first fingerprint 0xab bytes
                "abab",
                "171, 171",
                // second fingerprint 0xac bytes
                "acac",
                "172, 172",
                // generation 0xfeed_beef
                "feed",
                "4276993775",
                // member identity fill 0x11 bytes
                "1111",
                "17, 17",
            ] {
                assert!(
                    !rendered.contains(forbidden),
                    "leaked {forbidden}: {rendered}"
                );
            }
        }
        for error in [
            XfrmObjectRosterDurableError::InvalidProofKey,
            XfrmObjectRosterDurableError::EntropyUnavailable,
            XfrmObjectRosterDurableError::InvalidStoreRoot,
            XfrmObjectRosterDurableError::StoreBusy,
            XfrmObjectRosterDurableError::Storage,
            XfrmObjectRosterDurableError::Malformed,
            XfrmObjectRosterDurableError::AuthenticationFailed,
            XfrmObjectRosterDurableError::Duplicate,
            XfrmObjectRosterDurableError::WrongBinding,
            XfrmObjectRosterDurableError::WrongIncarnation,
            XfrmObjectRosterDurableError::Stale,
            XfrmObjectRosterDurableError::InvalidTransition,
            XfrmObjectRosterDurableError::NonExactRemovalIdentity,
            XfrmObjectRosterDurableError::NotFound,
            XfrmObjectRosterDurableError::CapacityExceeded,
        ] {
            assert_eq!(error.to_string(), error.as_str());
            assert!(error.as_str().starts_with("xfrm_object_roster_recovery_"));
        }
        for phase in [
            XfrmObjectRosterDurablePhase::Prepared,
            XfrmObjectRosterDurablePhase::Issuing,
            XfrmObjectRosterDurablePhase::Applied,
            XfrmObjectRosterDurablePhase::Compensating,
            XfrmObjectRosterDurablePhase::NoMutation,
            XfrmObjectRosterDurablePhase::RolledBack,
            XfrmObjectRosterDurablePhase::Committed,
            XfrmObjectRosterDurablePhase::Retired,
        ] {
            assert!(!phase.as_str().is_empty());
            assert!(!phase.as_str().contains('-'));
        }
    }
}
