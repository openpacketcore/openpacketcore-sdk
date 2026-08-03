//! Durable, authenticated authority records for SA relocation recovery.
//!
//! This module deliberately stores only opaque correlation values and keyed
//! fingerprints. It never serializes an XFRM request, key material, packet
//! mark, SPI, selector, or address. A decoded record is correlation data, not
//! cleanup authority: callers must validate it through
//! [`XfrmSaRelocationRecoveryStore`] while holding that store's permanent
//! cross-process lease.

#[cfg(target_os = "linux")]
use std::io::Write;
use std::{
    collections::BTreeMap,
    error::Error,
    ffi::OsStr,
    fmt,
    io::{self, Read},
    num::NonZeroU64,
    os::{
        fd::{AsFd, OwnedFd},
        unix::{ffi::OsStrExt, fs::DirBuilderExt},
    },
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard, TryLockError},
};

use rand::{rngs::SysRng, TryRng};
use sha2_zeroize::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use rustix::fs::{
    flock, fstat, fsync, open, openat, unlinkat, AtFlags, Dir, FileType, FlockOperation, Mode,
    OFlags,
};
#[cfg(target_os = "linux")]
use rustix::fs::{renameat_with, RenameFlags};

use crate::model::{
    validate_exact_lookup_mark, RelocateSaRequest, SaRelocationDirection, SaRelocationEncap,
    SaRelocationSelector,
};
use crate::{IpAddress, UdpEncap, XfrmId, XfrmLookupMark, XfrmMark, XfrmMode, XfrmRequestId};

/// Exact byte length of a persisted relocation recovery handle and durable
/// record.
pub const XFRM_SA_RELOCATION_RECOVERY_HANDLE_BYTES: usize = 208;

const RECORD_BODY_BYTES: usize = 176;
const AUTH_TAG_BYTES: usize = 32;
const RECORD_MAGIC: [u8; 8] = *b"OPCXRLC1";
const RECORD_VERSION: u16 = 1;
const RECORD_AUTH_DOMAIN: &[u8] = b"opc-xfrm-relocation-record-v1\0";
const RELOCATION_REQUEST_AUTH_DOMAIN: &[u8] = b"opc-xfrm-relocation-request-v1\0";
const DELETION_IDENTITY_AUTH_DOMAIN: &[u8] = b"opc-xfrm-relocation-deletion-identity-v1\0";
const NAMESPACE_AUTH_DOMAIN: &[u8] = b"opc-xfrm-relocation-namespace-v1\0";
const CONTROL_BYTES: usize = 128;
const CONTROL_BODY_BYTES: usize = CONTROL_BYTES - AUTH_TAG_BYTES;
const CONTROL_MAGIC: [u8; 8] = *b"OPCXCTL1";
const CONTROL_AUTH_DOMAIN: &[u8] = b"opc-xfrm-relocation-control-v1\0";
const CONTROL_NAME: &str = "control";
const EPOCH_BYTES: usize = 80;
const EPOCH_BODY_BYTES: usize = EPOCH_BYTES - AUTH_TAG_BYTES;
const EPOCH_MAGIC: [u8; 8] = *b"OPCXEPC1";
const EPOCH_AUTH_DOMAIN: &[u8] = b"opc-xfrm-relocation-epoch-v1\0";
const MAX_STORE_ENTRIES: usize = 64;
const MAX_ACTIVE_RECORDS: usize = MAX_STORE_ENTRIES - 3;
const MAX_STORE_PATH_BYTES: usize = 4096;
const FILE_MODE: u32 = 0o600;
const DIRECTORY_MODE: u32 = 0o700;
const CREATE_ATTEMPTS: usize = 8;

type HmacSha256 = ZeroizingHmacSha256;

struct ZeroizingHmacSha256 {
    inner: Sha256,
    outer_pad: Zeroizing<[u8; 64]>,
}

impl ZeroizingHmacSha256 {
    fn new(key: &[u8; AUTH_TAG_BYTES]) -> Self {
        let mut inner_pad = Zeroizing::new([0x36_u8; 64]);
        let mut outer_pad = Zeroizing::new([0x5c_u8; 64]);
        for ((inner, outer), key_byte) in inner_pad
            .iter_mut()
            .zip(outer_pad.iter_mut())
            .zip(key.iter())
        {
            *inner ^= key_byte;
            *outer ^= key_byte;
        }
        let mut inner = Sha256::new();
        inner.update(inner_pad.as_slice());
        Self { inner, outer_pad }
    }

    fn update(&mut self, bytes: &[u8]) {
        self.inner.update(bytes);
    }

    fn finalize(self) -> Zeroizing<[u8; AUTH_TAG_BYTES]> {
        let mut inner_digest = self.inner.finalize();
        let mut outer = Sha256::new();
        outer.update(self.outer_pad.as_slice());
        outer.update(inner_digest.as_slice());
        inner_digest.as_mut_slice().zeroize();
        let mut digest = outer.finalize();
        let mut output = Zeroizing::new([0_u8; AUTH_TAG_BYTES]);
        output.copy_from_slice(digest.as_slice());
        digest.as_mut_slice().zeroize();
        output
    }
}

/// Secret proof key used to authenticate SA relocation recovery state.
///
/// The key is supplied by the product's durable secret configuration and must
/// remain stable across a process restart. `Debug` and `Display` are redacted,
/// and the bytes are zeroized when the value is dropped.
pub struct XfrmSaRelocationRecoveryProofKey([u8; AUTH_TAG_BYTES]);

impl XfrmSaRelocationRecoveryProofKey {
    /// Construct a proof key from exactly 256 bits of secret material.
    ///
    /// An all-zero key is rejected so an omitted secret cannot silently create
    /// forgeable recovery authority.
    pub fn new(bytes: [u8; AUTH_TAG_BYTES]) -> Result<Self, XfrmSaRelocationDurableError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(XfrmSaRelocationDurableError::InvalidProofKey);
        }
        Ok(Self(bytes))
    }

    fn bytes(&self) -> &[u8; AUTH_TAG_BYTES] {
        &self.0
    }
}

impl Clone for XfrmSaRelocationRecoveryProofKey {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl Drop for XfrmSaRelocationRecoveryProofKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for XfrmSaRelocationRecoveryProofKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("XfrmSaRelocationRecoveryProofKey(<redacted>)")
    }
}

impl fmt::Display for XfrmSaRelocationRecoveryProofKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

/// Opaque, randomly generated identity of one durable SA relocation operation.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct XfrmSaRelocationOperationId([u8; 16]);

impl XfrmSaRelocationOperationId {
    /// Generate a nonzero operation identity using the operating system RNG.
    pub fn generate() -> Result<Self, XfrmSaRelocationDurableError> {
        let mut bytes = [0_u8; 16];
        SysRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| XfrmSaRelocationDurableError::EntropyUnavailable)?;
        Self::from_bytes(bytes)
    }

    /// Decode an opaque operation identity, rejecting the reserved zero value.
    pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, XfrmSaRelocationDurableError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(XfrmSaRelocationDurableError::Malformed);
        }
        Ok(Self(bytes))
    }

    /// Return the opaque correlation bytes for durable application storage.
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0
    }
}

impl fmt::Debug for XfrmSaRelocationOperationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("XfrmSaRelocationOperationId(<redacted>)")
    }
}

impl fmt::Display for XfrmSaRelocationOperationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

/// Nonzero product generation for one durable SA relocation operation.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct XfrmSaRelocationOperationGeneration(NonZeroU64);

impl XfrmSaRelocationOperationGeneration {
    /// Construct a nonzero operation generation.
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Return the generation value for durable correlation.
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl fmt::Debug for XfrmSaRelocationOperationGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("XfrmSaRelocationOperationGeneration(<redacted>)")
    }
}

impl fmt::Display for XfrmSaRelocationOperationGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

/// Durable state of one exact SA relocation.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XfrmSaRelocationDurablePhase {
    /// Intent is durable and no backend mutation has been admitted.
    ///
    /// Unlike the staged-object install boundary, a prepared relocation
    /// reserves the namespace-wide writer gate until it is recovered or
    /// admitted: an unreconciled MOBIKE-style transaction fences cooperating
    /// writers.
    Prepared,
    /// The writer epoch was advanced before issuing the relocation.
    Issuing,
    /// The relocation completed and durable terminal proof was published.
    Relocated,
    /// The relocation provably made no mutation.
    NoMutation,
    /// The backend result cannot safely prove relocation or absence.
    Indeterminate,
    /// Recovery authority was validated and fenced before deletion.
    RemovalAdmitted,
    /// Recovery completed and no cleanup authority remains.
    Retired,
}

impl XfrmSaRelocationDurablePhase {
    /// Stable, value-free phase label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Issuing => "issuing",
            Self::Relocated => "relocated",
            Self::NoMutation => "no_mutation",
            Self::Indeterminate => "indeterminate",
            Self::RemovalAdmitted => "removal_admitted",
            Self::Retired => "retired",
        }
    }

    const fn code(self) -> u8 {
        match self {
            Self::Prepared => 1,
            Self::Issuing => 2,
            Self::Relocated => 3,
            Self::NoMutation => 4,
            Self::Indeterminate => 5,
            Self::RemovalAdmitted => 6,
            Self::Retired => 7,
        }
    }

    fn from_code(code: u8) -> Result<Self, XfrmSaRelocationDurableError> {
        match code {
            1 => Ok(Self::Prepared),
            2 => Ok(Self::Issuing),
            3 => Ok(Self::Relocated),
            4 => Ok(Self::NoMutation),
            5 => Ok(Self::Indeterminate),
            6 => Ok(Self::RemovalAdmitted),
            7 => Ok(Self::Retired),
            _ => Err(XfrmSaRelocationDurableError::Malformed),
        }
    }

    pub(crate) const fn permits(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Prepared, Self::Issuing)
                | (Self::Prepared, Self::Retired)
                | (Self::Issuing, Self::Relocated)
                | (Self::Issuing, Self::NoMutation)
                | (Self::Issuing, Self::Indeterminate)
                | (Self::Issuing, Self::RemovalAdmitted)
                | (Self::Indeterminate, Self::NoMutation)
                | (Self::Indeterminate, Self::RemovalAdmitted)
                | (Self::Relocated, Self::Retired)
                | (Self::NoMutation, Self::Retired)
                | (Self::RemovalAdmitted, Self::Retired)
        )
    }

    /// Whether this phase keeps the namespace-wide writer gate closed.
    ///
    /// Every unresolved relocation phase gates cooperating writers, including
    /// `Prepared`: a prepared-but-unrecovered relocation reserves the
    /// namespace until it is reconciled.
    pub(crate) const fn is_unresolved_writer_authority(self) -> bool {
        matches!(
            self,
            Self::Prepared | Self::Issuing | Self::Indeterminate | Self::RemovalAdmitted
        )
    }
}

/// Durable pre-effect proof witnessed before a relocation effect is admitted.
///
/// Immediately before the `Prepared -> Issuing` transition, the namespace
/// actor performs exact readbacks of the current and target SA identities and
/// embeds the witnessed target disposition in the record. After process loss,
/// combining this proof with fresh exact readbacks classifies old/new kernel
/// state without relying on retained intent alone.
///
/// This type is crate-internal: it never appears in a public signature and is
/// only observable through the recovery outcome it authorizes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum XfrmSaRelocationPreEffectProof {
    /// The relocated target identity differs from the current identity and
    /// was absent when the effect was admitted.
    TargetAbsent = 1,
    /// The relocated target identity equals the current identity (an
    /// encapsulation and/or source-only change), and that exact identity was
    /// present when the effect was admitted.
    SameIdentityWitnessed = 2,
}

impl XfrmSaRelocationPreEffectProof {
    /// Stable, value-free proof label.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::TargetAbsent => "target_absent",
            Self::SameIdentityWitnessed => "same_identity_witnessed",
        }
    }

    const fn code(self) -> u8 {
        match self {
            Self::TargetAbsent => 1,
            Self::SameIdentityWitnessed => 2,
        }
    }

    fn from_code(code: u8) -> Result<Self, XfrmSaRelocationDurableError> {
        match code {
            1 => Ok(Self::TargetAbsent),
            2 => Ok(Self::SameIdentityWitnessed),
            _ => Err(XfrmSaRelocationDurableError::Malformed),
        }
    }
}

impl fmt::Debug for XfrmSaRelocationPreEffectProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("XfrmSaRelocationPreEffectProof")
            .field(&self.as_str())
            .finish()
    }
}

/// Fixed-size authenticated correlation handle safe to persist.
///
/// Possessing or decoding this value does not authorize deletion. The store
/// must authenticate it, find exactly one matching current record, and validate
/// namespace, incarnation, generation, epoch, and phase.
#[derive(Clone, PartialEq, Eq)]
pub struct XfrmSaRelocationRecoveryHandle([u8; XFRM_SA_RELOCATION_RECOVERY_HANDLE_BYTES]);

impl XfrmSaRelocationRecoveryHandle {
    /// Decode fixed-size opaque bytes without treating them as authority.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; XFRM_SA_RELOCATION_RECOVERY_HANDLE_BYTES]) -> Self {
        Self(bytes)
    }

    /// Return fixed-size opaque bytes for durable application storage.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; XFRM_SA_RELOCATION_RECOVERY_HANDLE_BYTES] {
        self.0
    }
}

impl fmt::Debug for XfrmSaRelocationRecoveryHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("XfrmSaRelocationRecoveryHandle(<redacted>)")
    }
}

impl fmt::Display for XfrmSaRelocationRecoveryHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

/// Value-free durable relocation recovery failure.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XfrmSaRelocationDurableError {
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
    /// More than one candidate exists for an operation or control record.
    Duplicate,
    /// Store or namespace binding does not match.
    WrongBinding,
    /// Actor incarnation does not match the authorized incarnation.
    WrongIncarnation,
    /// The operation generation or writer epoch is stale.
    Stale,
    /// The requested durable phase transition is not permitted.
    InvalidTransition,
    /// The request cannot produce an exact unconditional removal identity.
    NonExactRemovalIdentity,
    /// The exact operation record is absent.
    NotFound,
    /// The bounded store has no safe publication slot remaining.
    CapacityExceeded,
}

impl XfrmSaRelocationDurableError {
    /// Stable machine-readable, value-free error code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidProofKey => "xfrm_sa_relocation_recovery_invalid_proof_key",
            Self::EntropyUnavailable => "xfrm_sa_relocation_recovery_entropy_unavailable",
            Self::InvalidStoreRoot => "xfrm_sa_relocation_recovery_invalid_store_root",
            Self::StoreBusy => "xfrm_sa_relocation_recovery_store_busy",
            Self::Storage => "xfrm_sa_relocation_recovery_storage",
            Self::Malformed => "xfrm_sa_relocation_recovery_malformed",
            Self::AuthenticationFailed => "xfrm_sa_relocation_recovery_authentication_failed",
            Self::Duplicate => "xfrm_sa_relocation_recovery_duplicate",
            Self::WrongBinding => "xfrm_sa_relocation_recovery_wrong_binding",
            Self::WrongIncarnation => "xfrm_sa_relocation_recovery_wrong_incarnation",
            Self::Stale => "xfrm_sa_relocation_recovery_stale",
            Self::InvalidTransition => "xfrm_sa_relocation_recovery_invalid_transition",
            Self::NonExactRemovalIdentity => {
                "xfrm_sa_relocation_recovery_non_exact_removal_identity"
            }
            Self::NotFound => "xfrm_sa_relocation_recovery_not_found",
            Self::CapacityExceeded => "xfrm_sa_relocation_recovery_capacity_exceeded",
        }
    }
}

impl fmt::Display for XfrmSaRelocationDurableError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Error for XfrmSaRelocationDurableError {}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct DurableRelocationRecord {
    pub(crate) phase: XfrmSaRelocationDurablePhase,
    pub(crate) pre_effect_proof: Option<XfrmSaRelocationPreEffectProof>,
    pub(crate) store_incarnation: [u8; 16],
    pub(crate) namespace_seal: [u8; 32],
    pub(crate) actor_incarnation: [u8; 16],
    pub(crate) operation_id: XfrmSaRelocationOperationId,
    pub(crate) operation_generation: XfrmSaRelocationOperationGeneration,
    pub(crate) writer_epoch: NonZeroU64,
    pub(crate) deletion_identity_fingerprint: [u8; 32],
    pub(crate) relocation_request_fingerprint: [u8; 32],
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct DurableRelocationFingerprints {
    pub(crate) deletion_identity: [u8; 32],
    pub(crate) relocation_request: [u8; 32],
}

impl fmt::Debug for DurableRelocationRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableRelocationRecord")
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}

impl DurableRelocationRecord {
    pub(crate) fn encode(
        &self,
        key: &XfrmSaRelocationRecoveryProofKey,
    ) -> Result<[u8; XFRM_SA_RELOCATION_RECOVERY_HANDLE_BYTES], XfrmSaRelocationDurableError> {
        validate_record(self)?;
        let mut encoded = [0_u8; XFRM_SA_RELOCATION_RECOVERY_HANDLE_BYTES];
        encoded[0..8].copy_from_slice(&RECORD_MAGIC);
        encoded[8..10].copy_from_slice(&RECORD_VERSION.to_be_bytes());
        encoded[10] = self.phase.code();
        encoded[12] = self.pre_effect_proof.map_or(0, |proof| proof.code());
        encoded[16..32].copy_from_slice(&self.store_incarnation);
        encoded[32..64].copy_from_slice(&self.namespace_seal);
        encoded[64..80].copy_from_slice(&self.actor_incarnation);
        encoded[80..96].copy_from_slice(&self.operation_id.0);
        encoded[96..104].copy_from_slice(&self.operation_generation.get().to_be_bytes());
        encoded[104..112].copy_from_slice(&self.writer_epoch.get().to_be_bytes());
        encoded[112..144].copy_from_slice(&self.deletion_identity_fingerprint);
        encoded[144..176].copy_from_slice(&self.relocation_request_fingerprint);
        let tag = authenticate(key, &encoded[..RECORD_BODY_BYTES])?;
        encoded[RECORD_BODY_BYTES..].copy_from_slice(&tag);
        Ok(encoded)
    }

    pub(crate) fn decode(
        encoded: &[u8; XFRM_SA_RELOCATION_RECOVERY_HANDLE_BYTES],
        key: &XfrmSaRelocationRecoveryProofKey,
    ) -> Result<Self, XfrmSaRelocationDurableError> {
        if encoded[0..8] != RECORD_MAGIC
            || encoded[8..10] != RECORD_VERSION.to_be_bytes()
            || encoded[11] != 0
            || encoded[13..16] != [0_u8; 3]
        {
            return Err(XfrmSaRelocationDurableError::Malformed);
        }
        let pre_effect_proof = match encoded[12] {
            0 => None,
            code => Some(XfrmSaRelocationPreEffectProof::from_code(code)?),
        };
        verify_authentication(
            key,
            &encoded[..RECORD_BODY_BYTES],
            &encoded[RECORD_BODY_BYTES..],
        )?;
        let record = Self {
            phase: XfrmSaRelocationDurablePhase::from_code(encoded[10])?,
            pre_effect_proof,
            store_incarnation: array_at(encoded, 16),
            namespace_seal: array_at(encoded, 32),
            actor_incarnation: array_at(encoded, 64),
            operation_id: XfrmSaRelocationOperationId::from_bytes(array_at(encoded, 80))?,
            operation_generation: XfrmSaRelocationOperationGeneration::new(u64_at(encoded, 96))
                .ok_or(XfrmSaRelocationDurableError::Malformed)?,
            writer_epoch: NonZeroU64::new(u64_at(encoded, 104))
                .ok_or(XfrmSaRelocationDurableError::Malformed)?,
            deletion_identity_fingerprint: array_at(encoded, 112),
            relocation_request_fingerprint: array_at(encoded, 144),
        };
        validate_record(&record)?;
        Ok(record)
    }

    pub(crate) fn handle(
        &self,
        key: &XfrmSaRelocationRecoveryProofKey,
    ) -> Result<XfrmSaRelocationRecoveryHandle, XfrmSaRelocationDurableError> {
        Ok(XfrmSaRelocationRecoveryHandle(self.encode(key)?))
    }
}

fn validate_record(record: &DurableRelocationRecord) -> Result<(), XfrmSaRelocationDurableError> {
    if record.store_incarnation.iter().all(|byte| *byte == 0)
        || record.namespace_seal.iter().all(|byte| *byte == 0)
        || record.actor_incarnation.iter().all(|byte| *byte == 0)
        || record
            .deletion_identity_fingerprint
            .iter()
            .all(|byte| *byte == 0)
        || record
            .relocation_request_fingerprint
            .iter()
            .all(|byte| *byte == 0)
    {
        return Err(XfrmSaRelocationDurableError::Malformed);
    }
    // The pre-effect proof is witnessed exactly at the `Prepared -> Issuing`
    // transition and preserved by every subsequent transition. A `Prepared`
    // record therefore never carries a proof, every effect-possible or
    // terminal-effect phase must carry one, and a `Retired` record may or may
    // not depending on whether it retired through an effect-possible phase.
    let proof_required = matches!(
        record.phase,
        XfrmSaRelocationDurablePhase::Issuing
            | XfrmSaRelocationDurablePhase::Relocated
            | XfrmSaRelocationDurablePhase::NoMutation
            | XfrmSaRelocationDurablePhase::Indeterminate
            | XfrmSaRelocationDurablePhase::RemovalAdmitted
    );
    let proof_forbidden = record.phase == XfrmSaRelocationDurablePhase::Prepared;
    if (proof_required && record.pre_effect_proof.is_none())
        || (proof_forbidden && record.pre_effect_proof.is_some())
    {
        return Err(XfrmSaRelocationDurableError::Malformed);
    }
    Ok(())
}

fn fingerprints_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    bool::from(left.ct_eq(right))
}

fn record_matches_fingerprints(
    record: &DurableRelocationRecord,
    fingerprints: DurableRelocationFingerprints,
) -> bool {
    bool::from(
        record
            .deletion_identity_fingerprint
            .ct_eq(&fingerprints.deletion_identity)
            & record
                .relocation_request_fingerprint
                .ct_eq(&fingerprints.relocation_request),
    )
}

fn authenticate(
    key: &XfrmSaRelocationRecoveryProofKey,
    body: &[u8],
) -> Result<[u8; AUTH_TAG_BYTES], XfrmSaRelocationDurableError> {
    authenticate_domain(key, RECORD_AUTH_DOMAIN, body)
}

fn authenticate_domain(
    key: &XfrmSaRelocationRecoveryProofKey,
    domain: &[u8],
    body: &[u8],
) -> Result<[u8; AUTH_TAG_BYTES], XfrmSaRelocationDurableError> {
    let mut mac = HmacSha256::new(key.bytes());
    mac.update(domain);
    mac.update(body);
    Ok(*mac.finalize())
}

fn verify_authentication(
    key: &XfrmSaRelocationRecoveryProofKey,
    body: &[u8],
    tag: &[u8],
) -> Result<(), XfrmSaRelocationDurableError> {
    verify_authentication_domain(key, RECORD_AUTH_DOMAIN, body, tag)
}

fn verify_authentication_domain(
    key: &XfrmSaRelocationRecoveryProofKey,
    domain: &[u8],
    body: &[u8],
    tag: &[u8],
) -> Result<(), XfrmSaRelocationDurableError> {
    let mut mac = HmacSha256::new(key.bytes());
    mac.update(domain);
    mac.update(body);
    if bool::from(mac.finalize().as_slice().ct_eq(tag)) {
        Ok(())
    } else {
        Err(XfrmSaRelocationDurableError::AuthenticationFailed)
    }
}

fn array_at<const N: usize>(bytes: &[u8], start: usize) -> [u8; N] {
    let mut result = [0_u8; N];
    result.copy_from_slice(&bytes[start..start + N]);
    result
}

fn u64_at(bytes: &[u8], start: usize) -> u64 {
    u64::from_be_bytes(array_at(bytes, start))
}

/// Descriptor-anchored, permanently leased relocation recovery store.
///
/// The store owns an exclusive `flock` on the originally opened root directory
/// for its entire lifetime. Every operation reopens the visible path with
/// `O_NOFOLLOW`, verifies the root device/inode, and scans a bounded inventory.
/// Unknown, malformed, conflicting duplicate, wrong-owner, wrong-device, or
/// wrong-mode entries poison the operation without deleting anything. The sole
/// duplicate exception is an authenticated pair of exact adjacent phases (or
/// consecutive epoch witnesses) that this implementation can leave after the
/// new entry's directory fsync but before unlinking its predecessor; bounded
/// scan deterministically keeps the successor and syncs predecessor removal.
///
/// The control record's actor incarnation is durable writer authority. A fresh
/// process that reopens the same root, namespace, and proof key adopts that
/// incarnation; it is not regenerated on every open. A live authority from a
/// different root/store incarnation cannot validate against this lease.
#[derive(Clone)]
pub struct XfrmSaRelocationRecoveryStore {
    inner: Arc<StoreInner>,
}

struct StoreInner {
    visible_path: PathBuf,
    descriptor: OwnedFd,
    root_device: u64,
    root_inode: u64,
    root_owner: u32,
    owner_process_id: u32,
    proof_key: XfrmSaRelocationRecoveryProofKey,
    control: ControlRecord,
    process_lock: Mutex<()>,
}

impl Drop for StoreInner {
    fn drop(&mut self) {
        if self.owner_process_id == std::process::id() {
            let _ = flock(&self.descriptor, FlockOperation::Unlock);
        }
    }
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
        key: &XfrmSaRelocationRecoveryProofKey,
    ) -> Result<[u8; CONTROL_BYTES], XfrmSaRelocationDurableError> {
        if self.store_incarnation.iter().all(|byte| *byte == 0)
            || self.namespace_seal.iter().all(|byte| *byte == 0)
            || self.actor_incarnation.iter().all(|byte| *byte == 0)
            || self.root_device == 0
            || self.root_inode == 0
        {
            return Err(XfrmSaRelocationDurableError::Malformed);
        }
        let mut encoded = [0_u8; CONTROL_BYTES];
        encoded[0..8].copy_from_slice(&CONTROL_MAGIC);
        encoded[8..10].copy_from_slice(&RECORD_VERSION.to_be_bytes());
        encoded[16..32].copy_from_slice(&self.store_incarnation);
        encoded[32..64].copy_from_slice(&self.namespace_seal);
        encoded[64..80].copy_from_slice(&self.actor_incarnation);
        encoded[80..88].copy_from_slice(&self.root_device.to_be_bytes());
        encoded[88..96].copy_from_slice(&self.root_inode.to_be_bytes());
        let tag = authenticate_domain(key, CONTROL_AUTH_DOMAIN, &encoded[..CONTROL_BODY_BYTES])?;
        encoded[CONTROL_BODY_BYTES..].copy_from_slice(&tag);
        Ok(encoded)
    }

    fn decode(
        encoded: &[u8; CONTROL_BYTES],
        key: &XfrmSaRelocationRecoveryProofKey,
    ) -> Result<Self, XfrmSaRelocationDurableError> {
        if encoded[0..8] != CONTROL_MAGIC
            || encoded[8..10] != RECORD_VERSION.to_be_bytes()
            || encoded[10..16] != [0_u8; 6]
            || encoded[96..CONTROL_BODY_BYTES]
                .iter()
                .any(|byte| *byte != 0)
        {
            return Err(XfrmSaRelocationDurableError::Malformed);
        }
        verify_authentication_domain(
            key,
            CONTROL_AUTH_DOMAIN,
            &encoded[..CONTROL_BODY_BYTES],
            &encoded[CONTROL_BODY_BYTES..],
        )?;
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
            return Err(XfrmSaRelocationDurableError::Malformed);
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
        key: &XfrmSaRelocationRecoveryProofKey,
    ) -> Result<[u8; EPOCH_BYTES], XfrmSaRelocationDurableError> {
        let mut encoded = [0_u8; EPOCH_BYTES];
        encoded[0..8].copy_from_slice(&EPOCH_MAGIC);
        encoded[8..10].copy_from_slice(&RECORD_VERSION.to_be_bytes());
        encoded[16..32].copy_from_slice(&self.store_incarnation);
        encoded[32..40].copy_from_slice(&self.epoch.get().to_be_bytes());
        let tag = authenticate_domain(key, EPOCH_AUTH_DOMAIN, &encoded[..EPOCH_BODY_BYTES])?;
        encoded[EPOCH_BODY_BYTES..].copy_from_slice(&tag);
        Ok(encoded)
    }

    fn decode(
        encoded: &[u8; EPOCH_BYTES],
        key: &XfrmSaRelocationRecoveryProofKey,
    ) -> Result<Self, XfrmSaRelocationDurableError> {
        if encoded[0..8] != EPOCH_MAGIC
            || encoded[8..10] != RECORD_VERSION.to_be_bytes()
            || encoded[10..16] != [0_u8; 6]
            || encoded[40..EPOCH_BODY_BYTES].iter().any(|byte| *byte != 0)
        {
            return Err(XfrmSaRelocationDurableError::Malformed);
        }
        verify_authentication_domain(
            key,
            EPOCH_AUTH_DOMAIN,
            &encoded[..EPOCH_BODY_BYTES],
            &encoded[EPOCH_BODY_BYTES..],
        )?;
        let store_incarnation = array_at(encoded, 16);
        let epoch =
            NonZeroU64::new(u64_at(encoded, 32)).ok_or(XfrmSaRelocationDurableError::Malformed)?;
        if store_incarnation.iter().all(|byte| *byte == 0) {
            return Err(XfrmSaRelocationDurableError::Malformed);
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
    records: Vec<NamedDurableRecord>,
    epoch_name: String,
    epoch: NonZeroU64,
}

type NamedDurableRecord = (String, DurableRelocationRecord);
type ReconciledOperationRecords = (Vec<NamedDurableRecord>, Vec<String>);

impl Inventory {
    fn has_unresolved_writer_authority(&self) -> bool {
        self.records
            .iter()
            .any(|(_, record)| record.phase.is_unresolved_writer_authority())
    }

    fn has_unresolved_writer_authority_excluding(&self, excluded_name: &str) -> bool {
        self.records.iter().any(|(name, record)| {
            name != excluded_name && record.phase.is_unresolved_writer_authority()
        })
    }

    fn current_for(
        &self,
        operation_id: XfrmSaRelocationOperationId,
        generation: XfrmSaRelocationOperationGeneration,
    ) -> Result<(&str, &DurableRelocationRecord), XfrmSaRelocationDurableError> {
        let mut matches = self.records.iter().filter(|(_, record)| {
            record.operation_id == operation_id && record.operation_generation == generation
        });
        let Some((name, record)) = matches.next() else {
            return Err(XfrmSaRelocationDurableError::NotFound);
        };
        if matches.next().is_some() {
            return Err(XfrmSaRelocationDurableError::Duplicate);
        }
        Ok((name, record))
    }
}

impl XfrmSaRelocationRecoveryStore {
    /// Open or initialize a store through a namespace-bound backend.
    ///
    /// The root path must be absolute. If absent, it is created with mode
    /// `0700`; its parent is part of the caller's trusted configuration. An
    /// existing root must be owned by the effective user, be exactly `0700`,
    /// and contain either no entries or one valid control record plus valid
    /// operation records. `namespace_binding` is the canonical private
    /// nsfs device/inode, `SO_NETNS_COOKIE`, and boot identity material
    /// supplied by the sealed namespace actor.
    pub(crate) fn open_bound(
        path: &Path,
        proof_key: XfrmSaRelocationRecoveryProofKey,
        namespace_binding: [u8; 40],
    ) -> Result<Self, XfrmSaRelocationDurableError> {
        if !valid_store_path(path) {
            return Err(XfrmSaRelocationDurableError::InvalidStoreRoot);
        }
        create_root_if_absent(path)?;
        let descriptor = open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(map_root_open_error)?;
        let metadata = fstat(&descriptor).map_err(|_| XfrmSaRelocationDurableError::Storage)?;
        validate_root_metadata(&metadata)?;
        let root_device = stat_device(&metadata)?;
        let root_inode = stat_inode(&metadata)?;
        flock(&descriptor, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
            if error == rustix::io::Errno::WOULDBLOCK {
                XfrmSaRelocationDurableError::StoreBusy
            } else {
                XfrmSaRelocationDurableError::Storage
            }
        })?;
        // Synchronize the containing directory even on reopen. This both
        // publishes a newly created root and repairs the safe case where a
        // prior process died after mkdir but before its parent fsync.
        sync_store_root_parent(path, &descriptor)?;

        let namespace_seal = namespace_seal(&proof_key, namespace_binding)?;
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
            process_lock: Mutex::new(()),
        };
        inner.control = initialize_or_load_control(&inner, namespace_seal)?;
        let store = Self {
            inner: Arc::new(inner),
        };
        store.lease()?.inventory()?;
        Ok(store)
    }

    /// Persist a prepared relocation before any backend mutation is admitted.
    ///
    /// The fingerprints must be independent opaque, proof-keyed digests of
    /// the exact kernel deletion identity and complete relocation request. A
    /// duplicate active deletion identity is rejected globally. Any unresolved
    /// `Prepared`, `Issuing`, `Indeterminate`, or `RemovalAdmitted` record
    /// blocks preparation so consumer bookkeeping/recovery remains ordered
    /// before every later cooperating writer.
    pub(crate) fn prepare(
        &self,
        operation_id: XfrmSaRelocationOperationId,
        operation_generation: XfrmSaRelocationOperationGeneration,
        fingerprints: DurableRelocationFingerprints,
    ) -> Result<XfrmSaRelocationRecoveryHandle, XfrmSaRelocationDurableError> {
        let lease = self.lease()?;
        let mut inventory = lease.inventory()?;
        if lease.prune_terminal_records(&inventory)? {
            inventory = lease.inventory()?;
        }
        if inventory.has_unresolved_writer_authority() {
            return Err(XfrmSaRelocationDurableError::InvalidTransition);
        }
        if inventory.records.len() >= MAX_ACTIVE_RECORDS {
            return Err(XfrmSaRelocationDurableError::CapacityExceeded);
        }
        if inventory.records.iter().any(|(_, record)| {
            record.operation_id == operation_id
                && record.operation_generation == operation_generation
        }) {
            return Err(XfrmSaRelocationDurableError::Duplicate);
        }
        if inventory.records.iter().any(|(_, record)| {
            fingerprints_equal(
                &record.deletion_identity_fingerprint,
                &fingerprints.deletion_identity,
            ) && !matches!(
                record.phase,
                XfrmSaRelocationDurablePhase::NoMutation
                    | XfrmSaRelocationDurablePhase::Relocated
                    | XfrmSaRelocationDurablePhase::Retired
            )
        }) {
            return Err(XfrmSaRelocationDurableError::Duplicate);
        }
        let epoch = lease.current_epoch(&inventory)?;
        let record = DurableRelocationRecord {
            phase: XfrmSaRelocationDurablePhase::Prepared,
            pre_effect_proof: None,
            store_incarnation: lease.store.control.store_incarnation,
            namespace_seal: lease.store.control.namespace_seal,
            actor_incarnation: lease.store.control.actor_incarnation,
            operation_id,
            operation_generation,
            writer_epoch: epoch,
            deletion_identity_fingerprint: fingerprints.deletion_identity,
            relocation_request_fingerprint: fingerprints.relocation_request,
        };
        lease.publish_record(&record)?;
        record.handle(&lease.store.proof_key)
    }

    /// Compute independent keyed fingerprints of the exact removal identity
    /// and complete relocation request without persisting either plaintext.
    pub(crate) fn fingerprints_for_request(
        &self,
        request: &RelocateSaRequest,
    ) -> Result<DurableRelocationFingerprints, XfrmSaRelocationDurableError> {
        validate_exact_lookup_mark(request.current.mark, "relocation.current.mark")
            .map_err(|_| XfrmSaRelocationDurableError::NonExactRemovalIdentity)?;
        let lease = self.lease()?;
        let mut canonical = Zeroizing::new([0_u8; 64]);
        let length = encode_deletion_identity(request, &mut canonical);
        let deletion_identity = authenticate_domain(
            &lease.store.proof_key,
            DELETION_IDENTITY_AUTH_DOMAIN,
            &canonical[..length],
        )?;
        let relocation_request = authenticate_relocation_request(&lease.store.proof_key, request)?;
        Ok(DurableRelocationFingerprints {
            deletion_identity,
            relocation_request,
        })
    }

    /// Inspect the authenticated current phase for a retained handle.
    ///
    /// The result is diagnostic state only and never cleanup authority.
    pub fn inspect(
        &self,
        handle: &XfrmSaRelocationRecoveryHandle,
    ) -> Result<XfrmSaRelocationDurablePhase, XfrmSaRelocationDurableError> {
        let lease = self.lease()?;
        let inventory = lease.inventory()?;
        Ok(lease.current_from_handle(&inventory, handle)?.1.phase)
    }

    /// Restore one exact authenticated record from durable correlation data.
    ///
    /// This does not mint public cleanup authority. The namespace actor uses
    /// the returned sealed record to bind a private live capability.
    pub(crate) fn restore(
        &self,
        operation_id: XfrmSaRelocationOperationId,
        operation_generation: XfrmSaRelocationOperationGeneration,
        fingerprints: DurableRelocationFingerprints,
    ) -> Result<DurableRelocationRecord, XfrmSaRelocationDurableError> {
        let lease = self.lease()?;
        let inventory = lease.inventory()?;
        let (_, record) = inventory.current_for(operation_id, operation_generation)?;
        lease.validate_record_binding(record)?;
        if !record_matches_fingerprints(record, fingerprints) {
            return Err(XfrmSaRelocationDurableError::WrongBinding);
        }
        if record.phase == XfrmSaRelocationDurablePhase::RemovalAdmitted
            && record.writer_epoch != lease.current_epoch(&inventory)?
        {
            return Err(XfrmSaRelocationDurableError::Stale);
        }
        Ok(record.clone())
    }

    /// Authenticate an exact current handle for actor-bound recovery.
    ///
    /// Unlike operation-ID restoration, this requires every encoded phase and
    /// epoch field to equal the current record. A handle retained across any
    /// transition is stale and cannot drive another transition.
    pub(crate) fn restore_handle(
        &self,
        handle: &XfrmSaRelocationRecoveryHandle,
        fingerprints: DurableRelocationFingerprints,
    ) -> Result<DurableRelocationRecord, XfrmSaRelocationDurableError> {
        let lease = self.lease()?;
        let inventory = lease.inventory()?;
        let (_, record) = lease.current_from_handle(&inventory, handle)?;
        if !record_matches_fingerprints(record, fingerprints) {
            return Err(XfrmSaRelocationDurableError::WrongBinding);
        }
        if record.phase == XfrmSaRelocationDurablePhase::RemovalAdmitted
            && record.writer_epoch != lease.current_epoch(&inventory)?
        {
            return Err(XfrmSaRelocationDurableError::Stale);
        }
        Ok(record.clone())
    }

    /// Encode a live actor-validated record as an authenticated current handle.
    pub(crate) fn handle_for_record(
        &self,
        record: &DurableRelocationRecord,
    ) -> Result<XfrmSaRelocationRecoveryHandle, XfrmSaRelocationDurableError> {
        let lease = self.lease()?;
        lease.validate_record_binding(record)?;
        record.handle(&lease.store.proof_key)
    }

    /// Publish one exact state-machine transition with atomic file and parent
    /// directory synchronization.
    ///
    /// Entering `Issuing` burns a fresh global writer epoch before the new
    /// phase is published, and it is the sole transition that consumes a
    /// pre-effect proof: `pre_effect_proof` must be `Some` exactly for
    /// `Prepared -> Issuing` and `None` for every other transition, which
    /// preserves the current record's proof. The entering-`Issuing` gate
    /// recheck excludes the transitioning record itself, so the sole
    /// unresolved `Prepared` record can advance; every other unresolved
    /// record still rejects the transition. `RemovalAdmitted` already holds
    /// the writer gate, so it is published at that same current epoch before
    /// deletion and has no ambiguous half-advanced epoch crash cut.
    pub(crate) fn transition(
        &self,
        handle: &XfrmSaRelocationRecoveryHandle,
        expected: XfrmSaRelocationDurablePhase,
        next: XfrmSaRelocationDurablePhase,
        pre_effect_proof: Option<XfrmSaRelocationPreEffectProof>,
    ) -> Result<DurableRelocationRecord, XfrmSaRelocationDurableError> {
        if !expected.permits(next) {
            return Err(XfrmSaRelocationDurableError::InvalidTransition);
        }
        let entering_issuing = expected == XfrmSaRelocationDurablePhase::Prepared
            && next == XfrmSaRelocationDurablePhase::Issuing;
        if entering_issuing != pre_effect_proof.is_some() {
            return Err(XfrmSaRelocationDurableError::InvalidTransition);
        }
        let lease = self.lease()?;
        let inventory = lease.inventory()?;
        let (old_name, current) = lease.current_from_handle(&inventory, handle)?;
        if current.phase != expected {
            return Err(XfrmSaRelocationDurableError::InvalidTransition);
        }
        if next == XfrmSaRelocationDurablePhase::Issuing
            && inventory.has_unresolved_writer_authority_excluding(old_name)
        {
            return Err(XfrmSaRelocationDurableError::InvalidTransition);
        }
        let current_epoch = lease.current_epoch(&inventory)?;
        if expected == XfrmSaRelocationDurablePhase::RemovalAdmitted
            && current.writer_epoch != current_epoch
        {
            return Err(XfrmSaRelocationDurableError::Stale);
        }
        let writer_epoch = if next == XfrmSaRelocationDurablePhase::Issuing {
            lease.advance_epoch(&inventory)?
        } else {
            current.writer_epoch
        };
        let next_record = DurableRelocationRecord {
            phase: next,
            writer_epoch,
            pre_effect_proof: if entering_issuing {
                pre_effect_proof
            } else {
                current.pre_effect_proof
            },
            ..current.clone()
        };
        lease.publish_record(&next_record)?;
        lease.remove_record(old_name)?;
        Ok(next_record)
    }

    /// Burn a fresh global epoch before an independently issued XFRM mutation.
    ///
    /// The actor calls this for every mutation outside the durable relocation
    /// flow; even a later backend failure burns its epoch. The call is
    /// rejected while any `Prepared`, `Issuing`, `Indeterminate`, or
    /// `RemovalAdmitted` record remains unresolved, so no cooperating
    /// replacement can race consumer bookkeeping or cleanup.
    pub(crate) fn advance_writer_epoch(&self) -> Result<NonZeroU64, XfrmSaRelocationDurableError> {
        let lease = self.lease()?;
        let mut inventory = lease.inventory()?;
        if lease.prune_terminal_records(&inventory)? {
            inventory = lease.inventory()?;
        }
        if inventory.has_unresolved_writer_authority() {
            return Err(XfrmSaRelocationDurableError::InvalidTransition);
        }
        lease.advance_epoch(&inventory)
    }

    /// Report whether any record keeps the writer gate closed, without
    /// mutating the store.
    ///
    /// The namespace actor uses this predicate for the cross-family
    /// cooperating-writer gate: an unresolved relocation record fences every
    /// cooperating install admission, and vice versa.
    pub(crate) fn has_unresolved_writer_authority(
        &self,
    ) -> Result<bool, XfrmSaRelocationDurableError> {
        let lease = self.lease()?;
        let inventory = lease.inventory()?;
        Ok(inventory.has_unresolved_writer_authority())
    }

    /// Report whether a restored record's writer epoch equals the store's
    /// current epoch without exposing the epoch value.
    ///
    /// Recovery uses this as a fail-closed freshness predicate for
    /// `Issuing`/`Indeterminate` records: a durable anomaly that advanced or
    /// rewound the epoch underneath an unresolved record removes the proof's
    /// ordering guarantee and must be classified for repair, never deletion.
    pub(crate) fn record_writer_epoch_is_current(
        &self,
        record: &DurableRelocationRecord,
    ) -> Result<bool, XfrmSaRelocationDurableError> {
        let lease = self.lease()?;
        let inventory = lease.inventory()?;
        lease.validate_record_binding(record)?;
        Ok(record.writer_epoch == lease.current_epoch(&inventory)?)
    }

    /// True only for clones sharing this exact open store lease.
    pub(crate) fn is_same_instance(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    fn lease(&self) -> Result<StoreLease<'_>, XfrmSaRelocationDurableError> {
        if self.inner.owner_process_id == 0 || self.inner.owner_process_id != std::process::id() {
            return Err(XfrmSaRelocationDurableError::WrongIncarnation);
        }
        let process_guard = self
            .inner
            .process_lock
            .try_lock()
            .map_err(|error| match error {
                TryLockError::WouldBlock => XfrmSaRelocationDurableError::StoreBusy,
                TryLockError::Poisoned(_) => XfrmSaRelocationDurableError::Storage,
            })?;
        verify_visible_identity(&self.inner)?;
        Ok(StoreLease {
            store: &self.inner,
            _process_guard: process_guard,
        })
    }
}

impl fmt::Debug for XfrmSaRelocationRecoveryStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("XfrmSaRelocationRecoveryStore(<redacted>)")
    }
}

impl StoreLease<'_> {
    fn inventory(&self) -> Result<Inventory, XfrmSaRelocationDurableError> {
        verify_visible_identity(self.store)?;
        let mut control_count = 0_usize;
        let mut epochs = Vec::new();
        let mut records = Vec::new();
        let mut seen_names = BTreeMap::<String, ()>::new();
        let directory = Dir::read_from(&self.store.descriptor)
            .map_err(|_| XfrmSaRelocationDurableError::Storage)?;
        for entry in directory {
            let entry = entry.map_err(|_| XfrmSaRelocationDurableError::Storage)?;
            let raw_name = entry.file_name().to_bytes();
            if raw_name == b"." || raw_name == b".." {
                continue;
            }
            if seen_names.len() >= MAX_STORE_ENTRIES {
                return Err(XfrmSaRelocationDurableError::Malformed);
            }
            let name = std::str::from_utf8(raw_name)
                .map_err(|_| XfrmSaRelocationDurableError::Malformed)?
                .to_owned();
            if seen_names.insert(name.clone(), ()).is_some() {
                return Err(XfrmSaRelocationDurableError::Duplicate);
            }
            if name == CONTROL_NAME {
                control_count += 1;
                let encoded = read_fixed_file::<CONTROL_BYTES>(self.store, &name)?;
                let control = ControlRecord::decode(&encoded, &self.store.proof_key)?;
                if control != self.store.control {
                    return Err(XfrmSaRelocationDurableError::WrongBinding);
                }
                continue;
            }
            if name.starts_with("epoch-") {
                let expected_epoch =
                    parse_epoch_name(&name).ok_or(XfrmSaRelocationDurableError::Malformed)?;
                let encoded = read_fixed_file::<EPOCH_BYTES>(self.store, &name)?;
                let decoded = EpochRecord::decode(&encoded, &self.store.proof_key)?;
                if decoded.store_incarnation != self.store.control.store_incarnation {
                    return Err(XfrmSaRelocationDurableError::WrongBinding);
                }
                if decoded.epoch != expected_epoch || name != epoch_name(decoded.epoch) {
                    return Err(XfrmSaRelocationDurableError::Malformed);
                }
                epochs.push((name, decoded));
                continue;
            }
            let parsed = parse_record_name(OsStr::from_bytes(raw_name))
                .ok_or(XfrmSaRelocationDurableError::Malformed)?;
            let encoded =
                read_fixed_file::<XFRM_SA_RELOCATION_RECOVERY_HANDLE_BYTES>(self.store, &name)?;
            let record = DurableRelocationRecord::decode(&encoded, &self.store.proof_key)?;
            if parsed
                != (
                    record.phase,
                    record.operation_id,
                    record.operation_generation,
                )
                || name != record_name(&record)
            {
                return Err(XfrmSaRelocationDurableError::Malformed);
            }
            self.validate_record_binding(&record)?;
            records.push((name, record));
        }
        if control_count != 1 {
            return Err(if control_count > 1 {
                XfrmSaRelocationDurableError::Duplicate
            } else {
                XfrmSaRelocationDurableError::Malformed
            });
        }
        // Decide every recovery action before removing any entry. Arbitrary
        // duplicates remain fail-closed; only the two exact adjacent states
        // that this module itself can leave between fsync and unlink are
        // completed deterministically.
        let (epoch_name, epoch, obsolete_epoch) = classify_epoch_records(epochs)?;
        let (records, obsolete_records) = classify_operation_records(records, epoch)?;
        validate_unique_active_deletion_identities(&records)?;
        validate_single_unresolved_authority(&records)?;
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
        })
    }

    fn validate_record_binding(
        &self,
        record: &DurableRelocationRecord,
    ) -> Result<(), XfrmSaRelocationDurableError> {
        if record.store_incarnation != self.store.control.store_incarnation
            || record.namespace_seal != self.store.control.namespace_seal
        {
            return Err(XfrmSaRelocationDurableError::WrongBinding);
        }
        if record.actor_incarnation != self.store.control.actor_incarnation {
            return Err(XfrmSaRelocationDurableError::WrongIncarnation);
        }
        Ok(())
    }

    fn current_from_handle<'a>(
        &self,
        inventory: &'a Inventory,
        handle: &XfrmSaRelocationRecoveryHandle,
    ) -> Result<(&'a str, &'a DurableRelocationRecord), XfrmSaRelocationDurableError> {
        let correlation = DurableRelocationRecord::decode(&handle.0, &self.store.proof_key)?;
        self.validate_record_binding(&correlation)?;
        let (name, current) =
            inventory.current_for(correlation.operation_id, correlation.operation_generation)?;
        if current.store_incarnation != correlation.store_incarnation
            || current.namespace_seal != correlation.namespace_seal
            || current.actor_incarnation != correlation.actor_incarnation
            || !fingerprints_equal(
                &current.deletion_identity_fingerprint,
                &correlation.deletion_identity_fingerprint,
            )
            || !fingerprints_equal(
                &current.relocation_request_fingerprint,
                &correlation.relocation_request_fingerprint,
            )
        {
            return Err(XfrmSaRelocationDurableError::WrongBinding);
        }
        if current.phase != correlation.phase || current.writer_epoch != correlation.writer_epoch {
            return Err(XfrmSaRelocationDurableError::Stale);
        }
        Ok((name, current))
    }

    fn current_epoch(
        &self,
        inventory: &Inventory,
    ) -> Result<NonZeroU64, XfrmSaRelocationDurableError> {
        Ok(inventory.epoch)
    }

    fn publish_record(
        &self,
        record: &DurableRelocationRecord,
    ) -> Result<(), XfrmSaRelocationDurableError> {
        self.validate_record_binding(record)?;
        let name = record_name(record);
        let bytes = record.encode(&self.store.proof_key)?;
        publish_new_file(self.store, &name, &bytes)
    }

    fn advance_epoch(
        &self,
        inventory: &Inventory,
    ) -> Result<NonZeroU64, XfrmSaRelocationDurableError> {
        let epoch = inventory
            .epoch
            .get()
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .ok_or(XfrmSaRelocationDurableError::Stale)?;
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
    ) -> Result<bool, XfrmSaRelocationDurableError> {
        let names = inventory
            .records
            .iter()
            .filter(|(_, record)| {
                matches!(
                    record.phase,
                    XfrmSaRelocationDurablePhase::NoMutation
                        | XfrmSaRelocationDurablePhase::Relocated
                        | XfrmSaRelocationDurablePhase::Retired
                )
            })
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        for name in &names {
            self.remove_record(name)?;
        }
        Ok(!names.is_empty())
    }

    fn remove_epoch(&self, name: &str) -> Result<(), XfrmSaRelocationDurableError> {
        parse_epoch_name(name).ok_or(XfrmSaRelocationDurableError::Malformed)?;
        unlinkat(self.store.descriptor.as_fd(), name, AtFlags::empty())
            .map_err(|_| XfrmSaRelocationDurableError::Storage)?;
        fsync(&self.store.descriptor).map_err(|_| XfrmSaRelocationDurableError::Storage)?;
        Ok(())
    }

    fn remove_record(&self, name: &str) -> Result<(), XfrmSaRelocationDurableError> {
        validate_record_name(OsStr::new(name))?;
        unlinkat(self.store.descriptor.as_fd(), name, AtFlags::empty())
            .map_err(|_| XfrmSaRelocationDurableError::Storage)?;
        fsync(&self.store.descriptor).map_err(|_| XfrmSaRelocationDurableError::Storage)?;
        Ok(())
    }
}

fn classify_epoch_records(
    mut epochs: Vec<(String, EpochRecord)>,
) -> Result<(String, NonZeroU64, Option<String>), XfrmSaRelocationDurableError> {
    match epochs.len() {
        0 => Err(XfrmSaRelocationDurableError::Malformed),
        1 => {
            let (name, record) = epochs
                .pop()
                .ok_or(XfrmSaRelocationDurableError::Malformed)?;
            Ok((name, record.epoch, None))
        }
        2 => {
            epochs.sort_by_key(|(_, record)| record.epoch);
            let (lower_name, lower) = epochs.remove(0);
            let (upper_name, upper) = epochs.remove(0);
            if lower.store_incarnation != upper.store_incarnation
                || lower.epoch.get().checked_add(1) != Some(upper.epoch.get())
            {
                return Err(XfrmSaRelocationDurableError::Duplicate);
            }
            Ok((upper_name, upper.epoch, Some(lower_name)))
        }
        _ => Err(XfrmSaRelocationDurableError::Duplicate),
    }
}

fn classify_operation_records(
    records: Vec<NamedDurableRecord>,
    current_epoch: NonZeroU64,
) -> Result<ReconciledOperationRecords, XfrmSaRelocationDurableError> {
    let mut groups = BTreeMap::<([u8; 16], u64), Vec<NamedDurableRecord>>::new();
    for entry in records {
        groups
            .entry((entry.1.operation_id.0, entry.1.operation_generation.get()))
            .or_default()
            .push(entry);
    }
    let mut current = Vec::new();
    let mut obsolete = Vec::new();
    for mut group in groups.into_values() {
        match group.len() {
            1 => current.push(group.pop().ok_or(XfrmSaRelocationDurableError::Malformed)?),
            2 => {
                let right = group.pop().ok_or(XfrmSaRelocationDurableError::Duplicate)?;
                let left = group.pop().ok_or(XfrmSaRelocationDurableError::Duplicate)?;
                let (old, next) =
                    if is_exact_publication_successor(&left.1, &right.1, current_epoch) {
                        (left, right)
                    } else if is_exact_publication_successor(&right.1, &left.1, current_epoch) {
                        (right, left)
                    } else {
                        return Err(XfrmSaRelocationDurableError::Duplicate);
                    };
                obsolete.push(old.0);
                current.push(next);
            }
            _ => return Err(XfrmSaRelocationDurableError::Duplicate),
        }
    }
    Ok((current, obsolete))
}

fn validate_unique_active_deletion_identities(
    records: &[NamedDurableRecord],
) -> Result<(), XfrmSaRelocationDurableError> {
    for (index, (_, left)) in records.iter().enumerate() {
        if matches!(
            left.phase,
            XfrmSaRelocationDurablePhase::NoMutation
                | XfrmSaRelocationDurablePhase::Relocated
                | XfrmSaRelocationDurablePhase::Retired
        ) {
            continue;
        }
        if records[index + 1..].iter().any(|(_, right)| {
            !matches!(
                right.phase,
                XfrmSaRelocationDurablePhase::NoMutation
                    | XfrmSaRelocationDurablePhase::Relocated
                    | XfrmSaRelocationDurablePhase::Retired
            ) && fingerprints_equal(
                &left.deletion_identity_fingerprint,
                &right.deletion_identity_fingerprint,
            )
        }) {
            return Err(XfrmSaRelocationDurableError::Duplicate);
        }
    }
    Ok(())
}

fn validate_single_unresolved_authority(
    records: &[NamedDurableRecord],
) -> Result<(), XfrmSaRelocationDurableError> {
    // Because preparation is rejected while any record is unresolved and the
    // entering-`Issuing` transition re-checks the gate, one store can
    // legitimately hold at most one unresolved relocation authority.
    if records
        .iter()
        .filter(|(_, record)| record.phase.is_unresolved_writer_authority())
        .take(2)
        .count()
        > 1
    {
        return Err(XfrmSaRelocationDurableError::Duplicate);
    }
    Ok(())
}

fn is_exact_publication_successor(
    old: &DurableRelocationRecord,
    next: &DurableRelocationRecord,
    current_epoch: NonZeroU64,
) -> bool {
    if !old.phase.permits(next.phase)
        || old.store_incarnation != next.store_incarnation
        || old.namespace_seal != next.namespace_seal
        || old.actor_incarnation != next.actor_incarnation
        || old.operation_id != next.operation_id
        || old.operation_generation != next.operation_generation
        || !fingerprints_equal(
            &old.deletion_identity_fingerprint,
            &next.deletion_identity_fingerprint,
        )
        || !fingerprints_equal(
            &old.relocation_request_fingerprint,
            &next.relocation_request_fingerprint,
        )
    {
        return false;
    }
    // Only `Prepared -> Issuing` witnesses the pre-effect proof; every other
    // transition preserves it. A successor that invents or drops a proof on
    // any other edge is not an exact publication of this state machine.
    let entering_issuing = old.phase == XfrmSaRelocationDurablePhase::Prepared
        && next.phase == XfrmSaRelocationDurablePhase::Issuing;
    let proof_ok = if entering_issuing {
        old.pre_effect_proof.is_none() && next.pre_effect_proof.is_some()
    } else {
        old.pre_effect_proof == next.pre_effect_proof
    };
    if !proof_ok {
        return false;
    }
    if next.phase == XfrmSaRelocationDurablePhase::Issuing {
        next.writer_epoch == current_epoch && next.writer_epoch > old.writer_epoch
    } else {
        next.writer_epoch == old.writer_epoch
    }
}

fn create_root_if_absent(path: &Path) -> Result<(), XfrmSaRelocationDurableError> {
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(DIRECTORY_MODE);
    match builder.create(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(_) => Err(XfrmSaRelocationDurableError::Storage),
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

fn sync_store_root_parent(path: &Path, root: &OwnedFd) -> Result<(), XfrmSaRelocationDurableError> {
    let parent = path
        .parent()
        .ok_or(XfrmSaRelocationDurableError::InvalidStoreRoot)?;
    let child_name = path
        .file_name()
        .ok_or(XfrmSaRelocationDurableError::InvalidStoreRoot)?;
    let parent_descriptor = open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(map_root_open_error)?;
    let parent_metadata =
        fstat(&parent_descriptor).map_err(|_| XfrmSaRelocationDurableError::Storage)?;
    let parent_is_untrusted_writable =
        parent_metadata.st_mode & 0o022 != 0 && parent_metadata.st_mode & 0o1000 == 0;
    if !FileType::from_raw_mode(parent_metadata.st_mode).is_dir()
        || parent_metadata.st_nlink == 0
        || parent_is_untrusted_writable
    {
        return Err(XfrmSaRelocationDurableError::InvalidStoreRoot);
    }

    let reopened = openat(
        parent_descriptor.as_fd(),
        child_name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(map_root_open_error)?;
    let expected = fstat(root).map_err(|_| XfrmSaRelocationDurableError::Storage)?;
    let observed = fstat(&reopened).map_err(|_| XfrmSaRelocationDurableError::Storage)?;
    validate_root_metadata(&observed)?;
    if expected.st_dev != observed.st_dev || expected.st_ino != observed.st_ino {
        return Err(XfrmSaRelocationDurableError::InvalidStoreRoot);
    }
    fsync(&parent_descriptor).map_err(|_| XfrmSaRelocationDurableError::Storage)
}

fn validate_root_metadata(metadata: &rustix::fs::Stat) -> Result<(), XfrmSaRelocationDurableError> {
    if !FileType::from_raw_mode(metadata.st_mode).is_dir()
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_mode.store_permissions() != DIRECTORY_MODE
        || metadata.st_nlink == 0
    {
        return Err(XfrmSaRelocationDurableError::InvalidStoreRoot);
    }
    Ok(())
}

fn stat_device(metadata: &rustix::fs::Stat) -> Result<u64, XfrmSaRelocationDurableError> {
    metadata
        .st_dev
        .store_identity()
        .ok_or(XfrmSaRelocationDurableError::InvalidStoreRoot)
}

fn stat_inode(metadata: &rustix::fs::Stat) -> Result<u64, XfrmSaRelocationDurableError> {
    metadata
        .st_ino
        .store_identity()
        .ok_or(XfrmSaRelocationDurableError::InvalidStoreRoot)
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

fn map_root_open_error(error: rustix::io::Errno) -> XfrmSaRelocationDurableError {
    if matches!(error, rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) {
        XfrmSaRelocationDurableError::InvalidStoreRoot
    } else {
        XfrmSaRelocationDurableError::Storage
    }
}

fn verify_visible_identity(store: &StoreInner) -> Result<(), XfrmSaRelocationDurableError> {
    if store.owner_process_id != std::process::id() {
        return Err(XfrmSaRelocationDurableError::WrongIncarnation);
    }
    let visible = open(
        &store.visible_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(map_root_open_error)?;
    let metadata = fstat(&visible).map_err(|_| XfrmSaRelocationDurableError::Storage)?;
    validate_root_metadata(&metadata)?;
    if stat_device(&metadata)? != store.root_device
        || stat_inode(&metadata)? != store.root_inode
        || metadata.st_uid != store.root_owner
    {
        return Err(XfrmSaRelocationDurableError::InvalidStoreRoot);
    }
    Ok(())
}

fn initialize_or_load_control(
    store: &StoreInner,
    namespace_seal: [u8; 32],
) -> Result<ControlRecord, XfrmSaRelocationDurableError> {
    verify_visible_identity(store)?;
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
            epoch: NonZeroU64::new(1).ok_or(XfrmSaRelocationDurableError::Malformed)?,
        };
        publish_new_file(
            store,
            &epoch_name(epoch.epoch),
            &epoch.encode(&store.proof_key)?,
        )?;
        return Ok(control);
    }
    if !names.iter().any(|name| name == CONTROL_NAME) {
        return Err(XfrmSaRelocationDurableError::Malformed);
    }
    let encoded = read_fixed_file::<CONTROL_BYTES>(store, CONTROL_NAME)?;
    let control = ControlRecord::decode(&encoded, &store.proof_key)?;
    if control.namespace_seal != namespace_seal
        || control.root_device != store.root_device
        || control.root_inode != store.root_inode
    {
        return Err(XfrmSaRelocationDurableError::WrongBinding);
    }
    // First initialization publishes `control` before epoch 1. A process loss
    // between those two fsyncs leaves this one exact, authenticated safe
    // residue. No mutation can have been admitted yet, so completing epoch 1
    // is deterministic. Any additional or different entry remains fail-closed
    // in the bounded inventory scan.
    if names.len() == 1 {
        let epoch = EpochRecord {
            store_incarnation: control.store_incarnation,
            epoch: NonZeroU64::new(1).ok_or(XfrmSaRelocationDurableError::Malformed)?,
        };
        publish_new_file(
            store,
            &epoch_name(epoch.epoch),
            &epoch.encode(&store.proof_key)?,
        )?;
    }
    Ok(control)
}

fn scan_raw_names(store: &StoreInner) -> Result<Vec<String>, XfrmSaRelocationDurableError> {
    let directory =
        Dir::read_from(&store.descriptor).map_err(|_| XfrmSaRelocationDurableError::Storage)?;
    let mut names = Vec::new();
    for entry in directory {
        let entry = entry.map_err(|_| XfrmSaRelocationDurableError::Storage)?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        if names.len() >= MAX_STORE_ENTRIES {
            return Err(XfrmSaRelocationDurableError::Malformed);
        }
        names.push(
            std::str::from_utf8(name)
                .map_err(|_| XfrmSaRelocationDurableError::Malformed)?
                .to_owned(),
        );
    }
    Ok(names)
}

fn read_fixed_file<const N: usize>(
    store: &StoreInner,
    name: &str,
) -> Result<[u8; N], XfrmSaRelocationDurableError> {
    let descriptor = openat(
        store.descriptor.as_fd(),
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| XfrmSaRelocationDurableError::Malformed)?;
    validate_file_metadata(store, &descriptor, N)?;
    let mut file = std::fs::File::from(descriptor);
    let mut bytes = [0_u8; N];
    file.read_exact(&mut bytes)
        .map_err(|_| XfrmSaRelocationDurableError::Malformed)?;
    let mut trailing = [0_u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|_| XfrmSaRelocationDurableError::Storage)?
        != 0
    {
        return Err(XfrmSaRelocationDurableError::Malformed);
    }
    Ok(bytes)
}

fn validate_file_metadata(
    store: &StoreInner,
    descriptor: &OwnedFd,
    expected_size: usize,
) -> Result<(), XfrmSaRelocationDurableError> {
    let metadata = fstat(descriptor).map_err(|_| XfrmSaRelocationDurableError::Storage)?;
    if !FileType::from_raw_mode(metadata.st_mode).is_file()
        || stat_device(&metadata)? != store.root_device
        || metadata.st_uid != store.root_owner
        || metadata.st_mode.store_permissions() != FILE_MODE
        || metadata.st_nlink != 1
        || metadata.st_size != expected_size as i64
    {
        return Err(XfrmSaRelocationDurableError::Malformed);
    }
    Ok(())
}

fn publish_new_file(
    store: &StoreInner,
    target: &str,
    bytes: &[u8],
) -> Result<(), XfrmSaRelocationDurableError> {
    #[cfg(not(target_os = "linux"))]
    {
        // The public atomic constructor is unavailable before this point on a
        // non-Linux host. Keep the crate's established portable model and
        // unsupported backend buildable without pretending that another OS
        // provides Linux renameat2(RENAME_NOREPLACE) crash semantics.
        let _ = (store, target, bytes);
        Err(XfrmSaRelocationDurableError::Storage)
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
                Err(_) => return Err(XfrmSaRelocationDurableError::Storage),
            };
            let mut file = std::fs::File::from(descriptor);
            if file.write_all(bytes).is_err() || file.sync_all().is_err() {
                let _ = unlinkat(
                    store.descriptor.as_fd(),
                    temporary.as_str(),
                    AtFlags::empty(),
                );
                return Err(XfrmSaRelocationDurableError::Storage);
            }
            let staged_metadata =
                fstat(&file).map_err(|_| XfrmSaRelocationDurableError::Storage)?;
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
                return Err(XfrmSaRelocationDurableError::Storage);
            }
            match renameat_with(
                store.descriptor.as_fd(),
                temporary.as_str(),
                store.descriptor.as_fd(),
                target,
                RenameFlags::NOREPLACE,
            ) {
                Ok(()) => {
                    fsync(&store.descriptor).map_err(|_| XfrmSaRelocationDurableError::Storage)?;
                    let reopened = openat(
                        store.descriptor.as_fd(),
                        target,
                        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(|_| XfrmSaRelocationDurableError::Storage)?;
                    validate_file_metadata(store, &reopened, bytes.len())?;
                    let published_metadata =
                        fstat(&reopened).map_err(|_| XfrmSaRelocationDurableError::Storage)?;
                    if published_metadata.st_dev != staged_metadata.st_dev
                        || published_metadata.st_ino != staged_metadata.st_ino
                    {
                        return Err(XfrmSaRelocationDurableError::Storage);
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
                        XfrmSaRelocationDurableError::Duplicate
                    } else {
                        XfrmSaRelocationDurableError::Storage
                    });
                }
            }
        }
        Err(XfrmSaRelocationDurableError::EntropyUnavailable)
    }
}

fn random_nonzero_16() -> Result<[u8; 16], XfrmSaRelocationDurableError> {
    for _ in 0..CREATE_ATTEMPTS {
        let mut bytes = [0_u8; 16];
        SysRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| XfrmSaRelocationDurableError::EntropyUnavailable)?;
        if bytes.iter().any(|byte| *byte != 0) {
            return Ok(bytes);
        }
    }
    Err(XfrmSaRelocationDurableError::EntropyUnavailable)
}

#[cfg(target_os = "linux")]
fn temporary_name() -> Result<String, XfrmSaRelocationDurableError> {
    Ok(format!(".pending-{}", encode_hex(&random_nonzero_16()?)))
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

fn namespace_seal(
    key: &XfrmSaRelocationRecoveryProofKey,
    binding: [u8; 40],
) -> Result<[u8; 32], XfrmSaRelocationDurableError> {
    authenticate_domain(key, NAMESPACE_AUTH_DOMAIN, &binding)
}

fn authenticate_relocation_request(
    key: &XfrmSaRelocationRecoveryProofKey,
    request: &RelocateSaRequest,
) -> Result<[u8; AUTH_TAG_BYTES], XfrmSaRelocationDurableError> {
    let mut mac = HmacSha256::new(key.bytes());
    mac.update(RELOCATION_REQUEST_AUTH_DOMAIN);
    let current = &request.current;
    mac_sa_relocation_selector(&mut mac, &current.selector);
    mac_id(&mut mac, current.id);
    mac_ip_address(&mut mac, current.source_address);
    mac_request_id(&mut mac, current.request_id);
    mac_mode(&mut mac, current.mode);
    mac_encap(&mut mac, current.encap);
    mac_lookup_mark(&mut mac, current.mark);
    mac_optional_u32(&mut mac, current.if_id);
    mac_output_mark(&mut mac, current.output_mark);
    mac_ip_address(&mut mac, request.new_source_address);
    mac_ip_address(&mut mac, request.new_destination);
    mac_relocation_encap_action(&mut mac, request.encap);
    mac_relocation_direction(&mut mac, request.direction);
    Ok(*mac.finalize())
}

fn mac_u8(mac: &mut HmacSha256, value: u8) {
    mac.update(&[value]);
}

fn mac_u16(mac: &mut HmacSha256, value: u16) {
    mac.update(&value.to_be_bytes());
}

fn mac_u32(mac: &mut HmacSha256, value: u32) {
    mac.update(&value.to_be_bytes());
}

fn mac_i32(mac: &mut HmacSha256, value: i32) {
    mac.update(&value.to_be_bytes());
}

fn mac_ip_address(mac: &mut HmacSha256, address: IpAddress) {
    match address {
        IpAddress::Ipv4(octets) => {
            mac_u8(mac, 4);
            mac.update(&octets);
        }
        IpAddress::Ipv6(octets) => {
            mac_u8(mac, 6);
            mac.update(&octets);
        }
    }
}

fn mac_sa_relocation_selector(mac: &mut HmacSha256, selector: &SaRelocationSelector) {
    mac_ip_address(mac, selector.source);
    mac_ip_address(mac, selector.destination);
    mac_u16(mac, selector.source_port);
    mac_u16(mac, selector.source_port_mask);
    mac_u16(mac, selector.destination_port);
    mac_u16(mac, selector.destination_port_mask);
    mac_u8(mac, selector.protocol);
    mac_u8(mac, selector.source_prefix_len);
    mac_u8(mac, selector.destination_prefix_len);
    mac_i32(mac, selector.ifindex);
    mac_u32(mac, selector.user_id);
}

fn mac_id(mac: &mut HmacSha256, id: XfrmId) {
    mac_ip_address(mac, id.destination);
    mac_u32(mac, id.spi);
    mac_u8(mac, id.protocol);
}

fn mac_request_id(mac: &mut HmacSha256, request_id: Option<XfrmRequestId>) {
    mac_optional_u32(mac, request_id.map(XfrmRequestId::get));
}

fn mac_optional_u32(mac: &mut HmacSha256, value: Option<u32>) {
    match value {
        Some(value) => {
            mac_u8(mac, 1);
            mac_u32(mac, value);
        }
        None => mac_u8(mac, 0),
    }
}

fn mac_mode(mac: &mut HmacSha256, mode: XfrmMode) {
    mac_u8(
        mac,
        match mode {
            XfrmMode::Transport => 1,
            XfrmMode::Tunnel => 2,
            XfrmMode::Beet => 3,
        },
    );
}

fn mac_encap(mac: &mut HmacSha256, encap: Option<UdpEncap>) {
    match encap {
        Some(encap) => {
            mac_u8(mac, 1);
            mac_u16(mac, encap.encap_type);
            mac_u16(mac, encap.source_port);
            mac_u16(mac, encap.destination_port);
        }
        None => mac_u8(mac, 0),
    }
}

fn mac_lookup_mark(mac: &mut HmacSha256, mark: Option<XfrmLookupMark>) {
    match mark {
        Some(mark) => {
            mac_u8(mac, 1);
            mac_u32(mac, mark.value());
            mac_u32(mac, mark.mask());
        }
        None => mac_u8(mac, 0),
    }
}

fn mac_output_mark(mac: &mut HmacSha256, mark: Option<XfrmMark>) {
    match mark {
        Some(mark) => {
            mac_u8(mac, 1);
            mac_u32(mac, mark.value);
            mac_u32(mac, mark.mask);
        }
        None => mac_u8(mac, 0),
    }
}

fn mac_relocation_encap_action(mac: &mut HmacSha256, encap: SaRelocationEncap) {
    match encap {
        SaRelocationEncap::Preserve => mac_u8(mac, 0),
        SaRelocationEncap::Set(encap) => {
            mac_u8(mac, 1);
            mac_u16(mac, encap.encap_type);
            mac_u16(mac, encap.source_port);
            mac_u16(mac, encap.destination_port);
        }
        SaRelocationEncap::Remove => mac_u8(mac, 2),
    }
}

fn mac_relocation_direction(mac: &mut HmacSha256, direction: SaRelocationDirection) {
    mac_u8(
        mac,
        match direction {
            SaRelocationDirection::Inbound => 1,
            SaRelocationDirection::OutboundBlockPolicyInstalled => 2,
        },
    );
}

/// Encode the exact unconditional deletion identity of one relocation: the
/// target SA destination, protocol, SPI, and lookup mark.
fn encode_deletion_identity(request: &RelocateSaRequest, output: &mut [u8; 64]) -> usize {
    let mut cursor = 0_usize;
    output[cursor] = 1;
    cursor += 1;
    encode_ip_address(request.new_destination, output, &mut cursor);
    output[cursor] = request.current.id.protocol;
    cursor += 1;
    push_bytes(output, &mut cursor, &request.current.id.spi.to_be_bytes());
    encode_mark(request.current.mark, output, &mut cursor);
    cursor
}

fn encode_ip_address(address: IpAddress, output: &mut [u8; 64], cursor: &mut usize) {
    match address {
        IpAddress::Ipv4(octets) => {
            output[*cursor] = 4;
            *cursor += 1;
            push_bytes(output, cursor, &octets);
            push_bytes(output, cursor, &[0; 12]);
        }
        IpAddress::Ipv6(octets) => {
            output[*cursor] = 6;
            *cursor += 1;
            push_bytes(output, cursor, &octets);
        }
    }
}

fn encode_mark(mark: Option<XfrmLookupMark>, output: &mut [u8; 64], cursor: &mut usize) {
    match mark {
        Some(mark) => {
            output[*cursor] = 1;
            *cursor += 1;
            push_bytes(output, cursor, &mark.value().to_be_bytes());
            push_bytes(output, cursor, &mark.mask().to_be_bytes());
        }
        None => {
            output[*cursor] = 0;
            *cursor += 1;
            push_bytes(output, cursor, &[0; 8]);
        }
    }
}

fn push_bytes(output: &mut [u8; 64], cursor: &mut usize, bytes: &[u8]) {
    let end = *cursor + bytes.len();
    output[*cursor..end].copy_from_slice(bytes);
    *cursor = end;
}

fn record_name(record: &DurableRelocationRecord) -> String {
    format!(
        "{}-{}-{:016x}",
        record.phase.as_str(),
        encode_hex(&record.operation_id.0),
        record.operation_generation.get()
    )
}

fn validate_record_name(name: &OsStr) -> Result<(), XfrmSaRelocationDurableError> {
    parse_record_name(name)
        .map(|_| ())
        .ok_or(XfrmSaRelocationDurableError::Malformed)
}

fn parse_record_name(
    name: &OsStr,
) -> Option<(
    XfrmSaRelocationDurablePhase,
    XfrmSaRelocationOperationId,
    XfrmSaRelocationOperationGeneration,
)> {
    let text = name.to_str()?;
    let mut components = text.rsplitn(3, '-');
    let generation = u64::from_str_radix(components.next()?, 16).ok()?;
    let operation = decode_hex_16(components.next()?)?;
    let phase = match components.next()? {
        "prepared" => XfrmSaRelocationDurablePhase::Prepared,
        "issuing" => XfrmSaRelocationDurablePhase::Issuing,
        "relocated" => XfrmSaRelocationDurablePhase::Relocated,
        "no_mutation" => XfrmSaRelocationDurablePhase::NoMutation,
        "indeterminate" => XfrmSaRelocationDurablePhase::Indeterminate,
        "removal_admitted" => XfrmSaRelocationDurablePhase::RemovalAdmitted,
        "retired" => XfrmSaRelocationDurablePhase::Retired,
        _ => return None,
    };
    Some((
        phase,
        XfrmSaRelocationOperationId::from_bytes(operation).ok()?,
        XfrmSaRelocationOperationGeneration::new(generation)?,
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
    for (output, pair) in decoded.iter_mut().zip(encoded.chunks_exact(2)) {
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
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};

    use crate::{
        IpAddress, SaRelocationIdentity, SaRelocationSelector, XfrmId, XfrmLookupMark, XfrmMark,
        XfrmMode, XfrmRequestId, XfrmSelector,
    };

    use super::*;

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let identity = XfrmSaRelocationOperationId::generate().unwrap();
            let path = std::env::temp_dir().join(format!(
                "opc-xfrm-durable-relocation-test-{}",
                encode_hex(&identity.to_bytes())
            ));
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            if self.0.is_dir() {
                fs::remove_dir_all(&self.0).unwrap();
            }
        }
    }

    fn key(byte: u8) -> XfrmSaRelocationRecoveryProofKey {
        XfrmSaRelocationRecoveryProofKey::new([byte; 32]).unwrap()
    }

    fn fingerprints(byte: u8) -> DurableRelocationFingerprints {
        DurableRelocationFingerprints {
            deletion_identity: [byte; 32],
            relocation_request: [byte.wrapping_add(1); 32],
        }
    }

    fn valid_proof_for(
        phase: XfrmSaRelocationDurablePhase,
    ) -> Option<XfrmSaRelocationPreEffectProof> {
        match phase {
            XfrmSaRelocationDurablePhase::Prepared | XfrmSaRelocationDurablePhase::Retired => None,
            _ => Some(XfrmSaRelocationPreEffectProof::TargetAbsent),
        }
    }

    fn record(phase: XfrmSaRelocationDurablePhase) -> DurableRelocationRecord {
        DurableRelocationRecord {
            phase,
            pre_effect_proof: valid_proof_for(phase),
            store_incarnation: [1; 16],
            namespace_seal: [2; 32],
            actor_incarnation: [3; 16],
            operation_id: XfrmSaRelocationOperationId::from_bytes([4; 16]).unwrap(),
            operation_generation: XfrmSaRelocationOperationGeneration::new(5).unwrap(),
            writer_epoch: NonZeroU64::new(6).unwrap(),
            deletion_identity_fingerprint: [7; 32],
            relocation_request_fingerprint: [8; 32],
        }
    }

    fn store(root: &TestRoot) -> XfrmSaRelocationRecoveryStore {
        XfrmSaRelocationRecoveryStore::open_bound(root.path(), key(9), [0x42; 40]).unwrap()
    }

    fn proof_for(
        expected: XfrmSaRelocationDurablePhase,
        next: XfrmSaRelocationDurablePhase,
    ) -> Option<XfrmSaRelocationPreEffectProof> {
        if expected == XfrmSaRelocationDurablePhase::Prepared
            && next == XfrmSaRelocationDurablePhase::Issuing
        {
            Some(XfrmSaRelocationPreEffectProof::TargetAbsent)
        } else {
            None
        }
    }

    fn next_handle(
        store: &XfrmSaRelocationRecoveryStore,
        current: &XfrmSaRelocationRecoveryHandle,
        expected: XfrmSaRelocationDurablePhase,
        next: XfrmSaRelocationDurablePhase,
    ) -> XfrmSaRelocationRecoveryHandle {
        store
            .transition(current, expected, next, proof_for(expected, next))
            .unwrap()
            .handle(&store.inner.proof_key)
            .unwrap()
    }

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddress {
        IpAddress::Ipv4([a, b, c, d])
    }

    fn current_identity(encap: Option<UdpEncap>) -> SaRelocationIdentity {
        SaRelocationIdentity {
            selector: SaRelocationSelector::from_selector(&XfrmSelector::new(
                ipv4(10, 62, 9, 1),
                ipv4(10, 62, 9, 2),
                17,
            )),
            id: XfrmId {
                destination: ipv4(192, 0, 2, 62),
                spi: 0x6290_0001,
                protocol: 50,
            },
            source_address: ipv4(192, 0, 2, 61),
            request_id: XfrmRequestId::new(629),
            mode: XfrmMode::Tunnel,
            encap,
            mark: Some(XfrmLookupMark::full(0x6290)),
            if_id: Some(6),
            output_mark: Some(XfrmMark {
                value: 0x0000_0629,
                mask: 0x0000_ffff,
            }),
        }
    }

    fn relocation_request() -> RelocateSaRequest {
        RelocateSaRequest {
            current: current_identity(Some(UdpEncap::esp_in_udp(4500, 4500))),
            new_source_address: ipv4(198, 51, 100, 10),
            new_destination: ipv4(198, 51, 100, 20),
            encap: SaRelocationEncap::Set(UdpEncap::esp_in_udp(4500, 62_000)),
            direction: SaRelocationDirection::Inbound,
        }
    }

    #[test]
    fn record_codec_round_trips_every_phase_and_proof() {
        for phase in [
            XfrmSaRelocationDurablePhase::Prepared,
            XfrmSaRelocationDurablePhase::Issuing,
            XfrmSaRelocationDurablePhase::Relocated,
            XfrmSaRelocationDurablePhase::NoMutation,
            XfrmSaRelocationDurablePhase::Indeterminate,
            XfrmSaRelocationDurablePhase::RemovalAdmitted,
            XfrmSaRelocationDurablePhase::Retired,
        ] {
            let mut expected = record(phase);
            expected.pre_effect_proof = valid_proof_for(phase);
            let encoded = expected.encode(&key(9)).unwrap();
            assert_eq!(encoded.len(), XFRM_SA_RELOCATION_RECOVERY_HANDLE_BYTES);
            assert_eq!(
                DurableRelocationRecord::decode(&encoded, &key(9)).unwrap(),
                expected
            );
            let handle = XfrmSaRelocationRecoveryHandle::from_bytes(encoded);
            assert_eq!(handle.to_bytes(), encoded);
        }
    }

    #[test]
    fn zeroizing_hmac_matches_independent_sha256_vector() {
        let mut key = [0_u8; 32];
        for (index, byte) in key.iter_mut().enumerate() {
            *byte = u8::try_from(index).unwrap();
        }
        let mut mac = ZeroizingHmacSha256::new(&key);
        mac.update(b"abc");
        assert_eq!(
            mac.finalize().as_slice(),
            [
                0xf0, 0x13, 0x37, 0x29, 0xc4, 0x16, 0x3d, 0xed, 0xe8, 0x1e, 0x21, 0xcd, 0x47, 0x83,
                0x92, 0x56, 0xda, 0x58, 0x17, 0x12, 0x38, 0xc8, 0xa0, 0xd8, 0x74, 0x39, 0x7c, 0x73,
                0xb1, 0x4e, 0x1e, 0x47,
            ]
        );
    }

    #[test]
    fn tampering_and_wrong_key_fail_authentication() {
        let encoded = record(XfrmSaRelocationDurablePhase::Issuing)
            .encode(&key(9))
            .unwrap();
        assert_eq!(
            DurableRelocationRecord::decode(&encoded, &key(8)),
            Err(XfrmSaRelocationDurableError::AuthenticationFailed)
        );
        for index in [10, 12, 16, 47, 80, 103, 111, 143, 175] {
            let mut tampered = encoded;
            tampered[index] ^= 0x80;
            assert!(DurableRelocationRecord::decode(&tampered, &key(9)).is_err());
        }
    }

    #[test]
    fn reserved_and_zero_fields_fail_closed() {
        assert!(matches!(
            XfrmSaRelocationRecoveryProofKey::new([0; 32]),
            Err(XfrmSaRelocationDurableError::InvalidProofKey)
        ));
        let valid = record(XfrmSaRelocationDurablePhase::Prepared)
            .encode(&key(9))
            .unwrap();
        // Bytes 11 and 13..16 remain reserved and must stay zero.
        for index in [11, 13, 14, 15] {
            let mut reserved = valid;
            reserved[index] = 1;
            assert_eq!(
                DurableRelocationRecord::decode(&reserved, &key(9)),
                Err(XfrmSaRelocationDurableError::Malformed)
            );
        }
        let mut invalid = record(XfrmSaRelocationDurablePhase::Prepared);
        invalid.store_incarnation = [0; 16];
        assert_eq!(
            invalid.encode(&key(9)),
            Err(XfrmSaRelocationDurableError::Malformed)
        );
    }

    #[test]
    fn all_public_diagnostics_are_value_free() {
        let operation = XfrmSaRelocationOperationId::from_bytes([0xab; 16]).unwrap();
        let generation = XfrmSaRelocationOperationGeneration::new(0xfeed_beef).unwrap();
        let handle = record(XfrmSaRelocationDurablePhase::Relocated)
            .handle(&key(9))
            .unwrap();
        for rendered in [
            format!("{operation:?} {operation}"),
            format!("{generation:?} {generation}"),
            format!("{handle:?} {handle}"),
            format!("{:?} {}", key(0xab), key(0xab)),
        ] {
            assert!(!rendered.contains("abab"));
            assert!(!rendered.contains("feed"));
        }
        for error in [
            XfrmSaRelocationDurableError::AuthenticationFailed,
            XfrmSaRelocationDurableError::Duplicate,
            XfrmSaRelocationDurableError::WrongBinding,
            XfrmSaRelocationDurableError::Stale,
        ] {
            assert!(error
                .to_string()
                .starts_with("xfrm_sa_relocation_recovery_"));
        }
    }

    #[test]
    fn state_machine_rejects_unsafe_edges() {
        assert!(
            XfrmSaRelocationDurablePhase::Prepared.permits(XfrmSaRelocationDurablePhase::Issuing)
        );
        assert!(XfrmSaRelocationDurablePhase::Issuing
            .permits(XfrmSaRelocationDurablePhase::RemovalAdmitted));
        assert!(XfrmSaRelocationDurablePhase::Indeterminate
            .permits(XfrmSaRelocationDurablePhase::RemovalAdmitted));
        assert!(XfrmSaRelocationDurablePhase::Indeterminate
            .permits(XfrmSaRelocationDurablePhase::NoMutation));
        assert!(
            XfrmSaRelocationDurablePhase::Relocated.permits(XfrmSaRelocationDurablePhase::Retired)
        );
        // An unresolved record may never retire directly without a verdict.
        assert!(
            !XfrmSaRelocationDurablePhase::Issuing.permits(XfrmSaRelocationDurablePhase::Retired)
        );
        assert!(!XfrmSaRelocationDurablePhase::Indeterminate
            .permits(XfrmSaRelocationDurablePhase::Retired));
        // Terminal proof never reopens deletion authority.
        assert!(!XfrmSaRelocationDurablePhase::Relocated
            .permits(XfrmSaRelocationDurablePhase::RemovalAdmitted));
        assert!(!XfrmSaRelocationDurablePhase::NoMutation
            .permits(XfrmSaRelocationDurablePhase::RemovalAdmitted));
        assert!(
            !XfrmSaRelocationDurablePhase::Retired.permits(XfrmSaRelocationDurablePhase::Prepared)
        );
    }

    #[test]
    fn store_persists_control_and_reopens_same_incarnation() {
        let root = TestRoot::new();
        let first = store(&root);
        let incarnation = first.inner.control.actor_incarnation;
        let operation = XfrmSaRelocationOperationId::generate().unwrap();
        let generation = XfrmSaRelocationOperationGeneration::new(1).unwrap();
        let handle = first
            .prepare(operation, generation, fingerprints(0x55))
            .unwrap();
        assert_eq!(
            first.inspect(&handle),
            Ok(XfrmSaRelocationDurablePhase::Prepared)
        );
        drop(first);

        let reopened = store(&root);
        assert_eq!(reopened.inner.control.actor_incarnation, incarnation);
        assert_eq!(
            reopened.inspect(&handle),
            Ok(XfrmSaRelocationDurablePhase::Prepared)
        );
        assert_eq!(
            reopened
                .restore(operation, generation, fingerprints(0x55))
                .unwrap()
                .phase,
            XfrmSaRelocationDurablePhase::Prepared
        );
        assert_eq!(
            reopened.restore(
                operation,
                XfrmSaRelocationOperationGeneration::new(2).unwrap(),
                fingerprints(0x55),
            ),
            Err(XfrmSaRelocationDurableError::NotFound)
        );
        assert_eq!(
            reopened.restore(operation, generation, fingerprints(0x56)),
            Err(XfrmSaRelocationDurableError::WrongBinding)
        );
        // A prepared relocation gates the store: a second preparation with a
        // distinct deletion identity is still rejected until recovery.
        assert_eq!(
            reopened.prepare(
                XfrmSaRelocationOperationId::generate().unwrap(),
                generation,
                fingerprints(0x57),
            ),
            Err(XfrmSaRelocationDurableError::InvalidTransition)
        );
        // Recovery retirement reopens the gate; the terminal record remains
        // inspectable until terminal compaction prunes it.
        let retired = reopened
            .transition(
                &handle,
                XfrmSaRelocationDurablePhase::Prepared,
                XfrmSaRelocationDurablePhase::Retired,
                None,
            )
            .unwrap();
        assert_eq!(
            reopened
                .restore(operation, generation, fingerprints(0x55))
                .unwrap()
                .phase,
            XfrmSaRelocationDurablePhase::Retired
        );
        let _ = retired;
        // Terminal compaction prunes the retired record during preparation.
        assert!(reopened
            .prepare(operation, generation, fingerprints(0x55))
            .is_ok());
    }

    #[test]
    fn permanent_root_lease_rejects_second_open() {
        let root = TestRoot::new();
        let first = store(&root);
        assert_eq!(
            XfrmSaRelocationRecoveryStore::open_bound(root.path(), key(9), [0x42; 40]).unwrap_err(),
            XfrmSaRelocationDurableError::StoreBusy
        );
        drop(first);
        assert!(XfrmSaRelocationRecoveryStore::open_bound(root.path(), key(9), [0x42; 40]).is_ok());
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
    fn multibyte_operation_filename_is_malformed_without_panicking() {
        let root = TestRoot::new();
        let store = store(&root);
        let operation = format!("aé{}", "a".repeat(29));
        assert_eq!(operation.len(), 32);
        let name = format!("prepared-{operation}-0000000000000001");
        fs::write(
            root.path().join(&name),
            [0_u8; XFRM_SA_RELOCATION_RECOVERY_HANDLE_BYTES],
        )
        .unwrap();
        fs::set_permissions(
            root.path().join(&name),
            fs::Permissions::from_mode(FILE_MODE),
        )
        .unwrap();

        assert_eq!(
            store.advance_writer_epoch(),
            Err(XfrmSaRelocationDurableError::Malformed)
        );
    }

    #[test]
    fn duplicate_active_deletion_identity_across_operations_fails_closed() {
        let root = TestRoot::new();
        let store = store(&root);
        let prepared = store
            .prepare(
                XfrmSaRelocationOperationId::from_bytes([0x41; 16]).unwrap(),
                XfrmSaRelocationOperationGeneration::new(1).unwrap(),
                fingerprints(0x71),
            )
            .unwrap();
        // Forge a second unresolved record that repeats the first operation's
        // deletion identity fingerprint under a distinct operation identity.
        let _ = prepared;
        let lease = store.lease().unwrap();
        let inventory = lease.inventory().unwrap();
        let (_, first) = inventory
            .current_for(
                XfrmSaRelocationOperationId::from_bytes([0x41; 16]).unwrap(),
                XfrmSaRelocationOperationGeneration::new(1).unwrap(),
            )
            .unwrap();
        let duplicate = DurableRelocationRecord {
            operation_id: XfrmSaRelocationOperationId::from_bytes([0x42; 16]).unwrap(),
            ..first.clone()
        };
        lease.publish_record(&duplicate).unwrap();
        drop(lease);

        assert_eq!(
            store.advance_writer_epoch(),
            Err(XfrmSaRelocationDurableError::Duplicate)
        );
    }

    #[test]
    fn multiple_unresolved_authorities_with_distinct_identities_fail_closed() {
        let root = TestRoot::new();
        let store = store(&root);
        let prepared = store
            .prepare(
                XfrmSaRelocationOperationId::from_bytes([0x51; 16]).unwrap(),
                XfrmSaRelocationOperationGeneration::new(1).unwrap(),
                fingerprints(0x81),
            )
            .unwrap();
        let issuing = next_handle(
            &store,
            &prepared,
            XfrmSaRelocationDurablePhase::Prepared,
            XfrmSaRelocationDurablePhase::Issuing,
        );
        let lease = store.lease().unwrap();
        let inventory = lease.inventory().unwrap();
        let (_, first) = lease.current_from_handle(&inventory, &issuing).unwrap();
        let second = DurableRelocationRecord {
            operation_id: XfrmSaRelocationOperationId::from_bytes([0x52; 16]).unwrap(),
            deletion_identity_fingerprint: [0x91; 32],
            relocation_request_fingerprint: [0x92; 32],
            ..first.clone()
        };
        lease.publish_record(&second).unwrap();
        drop(lease);

        assert_eq!(
            store.advance_writer_epoch(),
            Err(XfrmSaRelocationDurableError::Duplicate)
        );
    }

    #[test]
    fn exact_phase_handle_is_required_for_each_transition() {
        let root = TestRoot::new();
        let store = store(&root);
        let prepared = store
            .prepare(
                XfrmSaRelocationOperationId::generate().unwrap(),
                XfrmSaRelocationOperationGeneration::new(1).unwrap(),
                fingerprints(0x31),
            )
            .unwrap();
        let issuing = next_handle(
            &store,
            &prepared,
            XfrmSaRelocationDurablePhase::Prepared,
            XfrmSaRelocationDurablePhase::Issuing,
        );
        assert_eq!(
            store.transition(
                &prepared,
                XfrmSaRelocationDurablePhase::Prepared,
                XfrmSaRelocationDurablePhase::Issuing,
                proof_for(
                    XfrmSaRelocationDurablePhase::Prepared,
                    XfrmSaRelocationDurablePhase::Issuing
                ),
            ),
            Err(XfrmSaRelocationDurableError::Stale)
        );
        let relocated = next_handle(
            &store,
            &issuing,
            XfrmSaRelocationDurablePhase::Issuing,
            XfrmSaRelocationDurablePhase::Relocated,
        );
        assert_eq!(
            store.inspect(&relocated),
            Ok(XfrmSaRelocationDurablePhase::Relocated)
        );
        assert_eq!(
            store.inspect(&issuing),
            Err(XfrmSaRelocationDurableError::Stale)
        );
    }

    #[test]
    fn prepared_relocation_gates_every_writer_until_retired() {
        let root = TestRoot::new();
        let store = store(&root);
        let operation_a = XfrmSaRelocationOperationId::generate().unwrap();
        let generation = XfrmSaRelocationOperationGeneration::new(1).unwrap();
        let prepared_a = store
            .prepare(operation_a, generation, fingerprints(0xa1))
            .unwrap();
        // While A stays Prepared, no other operation may prepare, no writer
        // epoch may advance, and A's own admission remains the sole path.
        assert_eq!(
            store.prepare(
                XfrmSaRelocationOperationId::generate().unwrap(),
                generation,
                fingerprints(0xb2),
            ),
            Err(XfrmSaRelocationDurableError::InvalidTransition)
        );
        assert_eq!(
            store.advance_writer_epoch(),
            Err(XfrmSaRelocationDurableError::InvalidTransition)
        );
        assert!(store.has_unresolved_writer_authority().unwrap());
        // The sole prepared record can still advance to Issuing: the gate
        // recheck excludes the transitioning record itself.
        let issuing_a = next_handle(
            &store,
            &prepared_a,
            XfrmSaRelocationDurablePhase::Prepared,
            XfrmSaRelocationDurablePhase::Issuing,
        );
        assert_eq!(
            store.prepare(
                XfrmSaRelocationOperationId::generate().unwrap(),
                generation,
                fingerprints(0xb3),
            ),
            Err(XfrmSaRelocationDurableError::InvalidTransition)
        );
        // Retiring through the no-mutation verdict reopens the gate.
        let no_mutation = next_handle(
            &store,
            &issuing_a,
            XfrmSaRelocationDurablePhase::Issuing,
            XfrmSaRelocationDurablePhase::NoMutation,
        );
        let _retired = next_handle(
            &store,
            &no_mutation,
            XfrmSaRelocationDurablePhase::NoMutation,
            XfrmSaRelocationDurablePhase::Retired,
        );
        assert!(!store.has_unresolved_writer_authority().unwrap());
        assert!(store.advance_writer_epoch().is_ok());
        assert!(store
            .prepare(
                XfrmSaRelocationOperationId::generate().unwrap(),
                generation,
                fingerprints(0xb3),
            )
            .is_ok());
    }

    #[test]
    fn absent_root_is_published_through_a_nofollow_parent_descriptor() {
        let parent = TestRoot::new();
        fs::create_dir(parent.path()).unwrap();
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(DIRECTORY_MODE)).unwrap();
        let root = parent.path().join("store");
        let store = XfrmSaRelocationRecoveryStore::open_bound(&root, key(9), [0x42; 40]).unwrap();
        assert!(root.is_dir());
        drop(store);
        assert!(XfrmSaRelocationRecoveryStore::open_bound(&root, key(9), [0x42; 40]).is_ok());

        let actual_parent = parent.path().join("actual");
        fs::create_dir(&actual_parent).unwrap();
        fs::set_permissions(&actual_parent, fs::Permissions::from_mode(DIRECTORY_MODE)).unwrap();
        let linked_parent = parent.path().join("linked");
        symlink(&actual_parent, &linked_parent).unwrap();
        assert_eq!(
            XfrmSaRelocationRecoveryStore::open_bound(
                &linked_parent.join("store"),
                key(9),
                [0x42; 40],
            )
            .unwrap_err(),
            XfrmSaRelocationDurableError::InvalidStoreRoot
        );
    }

    #[test]
    fn noncanonical_hex_record_filename_is_malformed() {
        let root = TestRoot::new();
        let record_store = store(&root);
        let handle = record_store
            .prepare(
                XfrmSaRelocationOperationId::from_bytes([0xab; 16]).unwrap(),
                XfrmSaRelocationOperationGeneration::new(1).unwrap(),
                fingerprints(0x45),
            )
            .unwrap();
        let lease = record_store.lease().unwrap();
        let inventory = lease.inventory().unwrap();
        let (canonical, _) = lease.current_from_handle(&inventory, &handle).unwrap();
        let canonical = canonical.to_owned();
        drop(lease);
        let noncanonical = canonical.replacen("abab", "ABAB", 1);
        assert_ne!(canonical, noncanonical);
        fs::rename(root.path().join(canonical), root.path().join(noncanonical)).unwrap();
        assert_eq!(
            record_store.inspect(&handle),
            Err(XfrmSaRelocationDurableError::Malformed)
        );

        let epoch_root = TestRoot::new();
        let epoch_store = store(&epoch_root);
        for _ in 0..9 {
            epoch_store.advance_writer_epoch().unwrap();
        }
        let canonical_epoch = epoch_name(NonZeroU64::new(10).unwrap());
        let noncanonical_epoch = canonical_epoch.replace('a', "A");
        assert_ne!(canonical_epoch, noncanonical_epoch);
        fs::rename(
            epoch_root.path().join(canonical_epoch),
            epoch_root.path().join(noncanonical_epoch),
        )
        .unwrap();
        assert_eq!(
            epoch_store.advance_writer_epoch(),
            Err(XfrmSaRelocationDurableError::Malformed)
        );
    }

    #[test]
    fn forged_later_epoch_stales_removal_authority_fail_closed() {
        let root = TestRoot::new();
        let store = store(&root);
        let operation = XfrmSaRelocationOperationId::generate().unwrap();
        let generation = XfrmSaRelocationOperationGeneration::new(1).unwrap();
        let prepared = store
            .prepare(operation, generation, fingerprints(0xa4))
            .unwrap();
        let issuing = next_handle(
            &store,
            &prepared,
            XfrmSaRelocationDurablePhase::Prepared,
            XfrmSaRelocationDurablePhase::Issuing,
        );
        let issuing_record = store
            .restore(operation, generation, fingerprints(0xa4))
            .unwrap();
        let admitted = next_handle(
            &store,
            &issuing,
            XfrmSaRelocationDurablePhase::Issuing,
            XfrmSaRelocationDurablePhase::RemovalAdmitted,
        );
        let lease = store.lease().unwrap();
        let inventory = lease.inventory().unwrap();
        lease.advance_epoch(&inventory).unwrap();
        drop(lease);
        assert_eq!(
            store.restore(operation, generation, fingerprints(0xa4)),
            Err(XfrmSaRelocationDurableError::Stale)
        );
        assert_eq!(
            store.transition(
                &admitted,
                XfrmSaRelocationDurablePhase::RemovalAdmitted,
                XfrmSaRelocationDurablePhase::Retired,
                None,
            ),
            Err(XfrmSaRelocationDurableError::Stale)
        );
        assert!(!store
            .record_writer_epoch_is_current(&issuing_record)
            .unwrap());
    }

    #[test]
    fn removal_admitted_blocks_later_writer_until_retired() {
        let root = TestRoot::new();
        let store = store(&root);
        let operation = XfrmSaRelocationOperationId::generate().unwrap();
        let generation = XfrmSaRelocationOperationGeneration::new(1).unwrap();
        let prepared = store
            .prepare(operation, generation, fingerprints(0xc3))
            .unwrap();
        let issuing = next_handle(
            &store,
            &prepared,
            XfrmSaRelocationDurablePhase::Prepared,
            XfrmSaRelocationDurablePhase::Issuing,
        );
        let admitted = next_handle(
            &store,
            &issuing,
            XfrmSaRelocationDurablePhase::Issuing,
            XfrmSaRelocationDurablePhase::RemovalAdmitted,
        );
        assert_eq!(
            store.advance_writer_epoch(),
            Err(XfrmSaRelocationDurableError::InvalidTransition)
        );
        assert!(store
            .restore(operation, generation, fingerprints(0xc3))
            .is_ok());
        assert!(store
            .transition(
                &admitted,
                XfrmSaRelocationDurablePhase::RemovalAdmitted,
                XfrmSaRelocationDurablePhase::Retired,
                None,
            )
            .is_ok());
        assert!(store.advance_writer_epoch().is_ok());
    }

    #[test]
    fn terminal_compaction_keeps_more_than_twice_the_bound_live() {
        let root = TestRoot::new();
        let store = store(&root);
        for index in 1_u64..=(MAX_STORE_ENTRIES as u64 * 2 + 1) {
            let mut operation = [0_u8; 16];
            operation[8..].copy_from_slice(&index.to_be_bytes());
            let operation = XfrmSaRelocationOperationId::from_bytes(operation).unwrap();
            let generation = XfrmSaRelocationOperationGeneration::new(index).unwrap();
            let mut deletion_identity = [0_u8; 32];
            deletion_identity[24..].copy_from_slice(&index.to_be_bytes());
            let mut relocation_request = [0xff_u8; 32];
            relocation_request[24..].copy_from_slice(&index.to_be_bytes());
            let fingerprints = DurableRelocationFingerprints {
                deletion_identity,
                relocation_request,
            };
            let prepared = store.prepare(operation, generation, fingerprints).unwrap();
            let issuing = next_handle(
                &store,
                &prepared,
                XfrmSaRelocationDurablePhase::Prepared,
                XfrmSaRelocationDurablePhase::Issuing,
            );
            let no_mutation = next_handle(
                &store,
                &issuing,
                XfrmSaRelocationDurablePhase::Issuing,
                XfrmSaRelocationDurablePhase::NoMutation,
            );
            let _retired = next_handle(
                &store,
                &no_mutation,
                XfrmSaRelocationDurablePhase::NoMutation,
                XfrmSaRelocationDurablePhase::Retired,
            );
        }
        for _ in 0..(MAX_STORE_ENTRIES * 2 + 1) {
            store.advance_writer_epoch().unwrap();
        }
        assert!(store.lease().unwrap().inventory().unwrap().records.len() <= 1);
    }

    #[test]
    fn bounded_inventory_rejects_unbounded_publication() {
        // Every unresolved relocation phase gates preparation, so capacity is
        // enforced structurally by the bounded inventory scan rather than by
        // accumulating 61 live records through the API: 63 forged records
        // plus control and epoch exceed the 64-entry bound.
        let root = TestRoot::new();
        let store = store(&root);
        let lease = store.lease().unwrap();
        let epoch = lease.current_epoch(&lease.inventory().unwrap()).unwrap();
        for index in 1_u64..=63 {
            let mut operation = [0_u8; 16];
            operation[8..].copy_from_slice(&index.to_be_bytes());
            let mut deletion_identity = [0x10_u8; 32];
            deletion_identity[24..].copy_from_slice(&index.to_be_bytes());
            let mut relocation_request = [0x20_u8; 32];
            relocation_request[24..].copy_from_slice(&index.to_be_bytes());
            let record = DurableRelocationRecord {
                phase: XfrmSaRelocationDurablePhase::Prepared,
                pre_effect_proof: None,
                store_incarnation: store.inner.control.store_incarnation,
                namespace_seal: store.inner.control.namespace_seal,
                actor_incarnation: store.inner.control.actor_incarnation,
                operation_id: XfrmSaRelocationOperationId::from_bytes(operation).unwrap(),
                operation_generation: XfrmSaRelocationOperationGeneration::new(1).unwrap(),
                writer_epoch: epoch,
                deletion_identity_fingerprint: deletion_identity,
                relocation_request_fingerprint: relocation_request,
            };
            lease.publish_record(&record).unwrap();
        }
        drop(lease);
        assert_eq!(
            store.advance_writer_epoch(),
            Err(XfrmSaRelocationDurableError::Malformed)
        );
    }

    #[test]
    fn conflicting_adjacent_phase_residue_is_fail_closed() {
        let root = TestRoot::new();
        let store = store(&root);
        let prepared = store
            .prepare(
                XfrmSaRelocationOperationId::generate().unwrap(),
                XfrmSaRelocationOperationGeneration::new(1).unwrap(),
                fingerprints(0x77),
            )
            .unwrap();
        let lease = store.lease().unwrap();
        let inventory = lease.inventory().unwrap();
        let (_, current) = lease.current_from_handle(&inventory, &prepared).unwrap();
        let next = DurableRelocationRecord {
            phase: XfrmSaRelocationDurablePhase::Issuing,
            writer_epoch: NonZeroU64::new(inventory.epoch.get() + 1).unwrap(),
            pre_effect_proof: Some(XfrmSaRelocationPreEffectProof::TargetAbsent),
            ..current.clone()
        };
        lease.publish_record(&next).unwrap();
        drop(lease);
        assert_eq!(
            store.inspect(&prepared),
            Err(XfrmSaRelocationDurableError::Duplicate)
        );
        assert_eq!(
            store.transition(
                &prepared,
                XfrmSaRelocationDurablePhase::Prepared,
                XfrmSaRelocationDurablePhase::Issuing,
                proof_for(
                    XfrmSaRelocationDurablePhase::Prepared,
                    XfrmSaRelocationDurablePhase::Issuing
                ),
            ),
            Err(XfrmSaRelocationDurableError::Duplicate)
        );
    }

    #[test]
    fn every_exact_adjacent_phase_publication_residue_self_heals() {
        for (old_phase, next_phase) in [
            (
                XfrmSaRelocationDurablePhase::Prepared,
                XfrmSaRelocationDurablePhase::Issuing,
            ),
            (
                XfrmSaRelocationDurablePhase::Prepared,
                XfrmSaRelocationDurablePhase::Retired,
            ),
            (
                XfrmSaRelocationDurablePhase::Issuing,
                XfrmSaRelocationDurablePhase::Relocated,
            ),
            (
                XfrmSaRelocationDurablePhase::Issuing,
                XfrmSaRelocationDurablePhase::NoMutation,
            ),
            (
                XfrmSaRelocationDurablePhase::Issuing,
                XfrmSaRelocationDurablePhase::Indeterminate,
            ),
            (
                XfrmSaRelocationDurablePhase::Issuing,
                XfrmSaRelocationDurablePhase::RemovalAdmitted,
            ),
            (
                XfrmSaRelocationDurablePhase::Indeterminate,
                XfrmSaRelocationDurablePhase::NoMutation,
            ),
            (
                XfrmSaRelocationDurablePhase::Indeterminate,
                XfrmSaRelocationDurablePhase::RemovalAdmitted,
            ),
            (
                XfrmSaRelocationDurablePhase::Relocated,
                XfrmSaRelocationDurablePhase::Retired,
            ),
            (
                XfrmSaRelocationDurablePhase::NoMutation,
                XfrmSaRelocationDurablePhase::Retired,
            ),
            (
                XfrmSaRelocationDurablePhase::RemovalAdmitted,
                XfrmSaRelocationDurablePhase::Retired,
            ),
        ] {
            let root = TestRoot::new();
            let store = store(&root);
            let prepared = store
                .prepare(
                    XfrmSaRelocationOperationId::generate().unwrap(),
                    XfrmSaRelocationOperationGeneration::new(1).unwrap(),
                    fingerprints(0xd1),
                )
                .unwrap();
            let lease = store.lease().unwrap();
            let inventory = lease.inventory().unwrap();
            let (prepared_name, prepared_record) =
                lease.current_from_handle(&inventory, &prepared).unwrap();
            let prepared_name = prepared_name.to_owned();
            let mut old = prepared_record.clone();
            old.phase = old_phase;
            old.pre_effect_proof = valid_proof_for(old_phase);
            if old_phase != XfrmSaRelocationDurablePhase::Prepared {
                lease.remove_record(&prepared_name).unwrap();
                lease.publish_record(&old).unwrap();
            }
            let inventory = lease.inventory().unwrap();
            let old_name = record_name(&old);
            let entering_issuing = old_phase == XfrmSaRelocationDurablePhase::Prepared
                && next_phase == XfrmSaRelocationDurablePhase::Issuing;
            let next_proof = if entering_issuing {
                Some(XfrmSaRelocationPreEffectProof::TargetAbsent)
            } else {
                old.pre_effect_proof
            };
            let mut next = DurableRelocationRecord {
                phase: next_phase,
                pre_effect_proof: next_proof,
                ..old.clone()
            };
            if next_phase == XfrmSaRelocationDurablePhase::Issuing {
                next.writer_epoch = lease.advance_epoch(&inventory).unwrap();
            }
            lease.publish_record(&next).unwrap();
            drop(lease);

            let recovered = store.lease().unwrap().inventory().unwrap();
            assert_eq!(recovered.records.len(), 1);
            assert_eq!(recovered.records[0].1.phase, next_phase);
            assert!(!root.path().join(old_name).exists());
        }
    }

    #[test]
    fn exact_consecutive_epoch_publication_residue_selects_newer() {
        let root = TestRoot::new();
        let store = store(&root);
        let lease = store.lease().unwrap();
        let inventory = lease.inventory().unwrap();
        let next = NonZeroU64::new(inventory.epoch.get() + 1).unwrap();
        let record = EpochRecord {
            store_incarnation: store.inner.control.store_incarnation,
            epoch: next,
        };
        publish_new_file(
            &store.inner,
            &epoch_name(next),
            &record.encode(&store.inner.proof_key).unwrap(),
        )
        .unwrap();
        drop(lease);

        let recovered = store.lease().unwrap().inventory().unwrap();
        assert_eq!(recovered.epoch, next);
        assert!(!root
            .path()
            .join(epoch_name(NonZeroU64::new(1).unwrap()))
            .exists());
    }

    #[test]
    fn valid_record_with_wrong_actor_incarnation_is_rejected() {
        let root = TestRoot::new();
        let store = store(&root);
        let handle = store
            .prepare(
                XfrmSaRelocationOperationId::generate().unwrap(),
                XfrmSaRelocationOperationGeneration::new(1).unwrap(),
                fingerprints(0x88),
            )
            .unwrap();
        let lease = store.lease().unwrap();
        let inventory = lease.inventory().unwrap();
        let (name, current) = lease.current_from_handle(&inventory, &handle).unwrap();
        let name = name.to_owned();
        let mut wrong = current.clone();
        wrong.actor_incarnation = [0x99; 16];
        let bytes = wrong.encode(&store.inner.proof_key).unwrap();
        lease.remove_record(&name).unwrap();
        publish_new_file(&store.inner, &name, &bytes).unwrap();
        drop(lease);
        assert_eq!(
            store.inspect(&handle),
            Err(XfrmSaRelocationDurableError::WrongIncarnation)
        );
    }

    #[test]
    fn wrong_key_namespace_unknown_entry_and_root_copy_fail_closed() {
        let root = TestRoot::new();
        let initial_store = store(&root);
        drop(initial_store);
        assert_eq!(
            XfrmSaRelocationRecoveryStore::open_bound(root.path(), key(8), [0x42; 40]).unwrap_err(),
            XfrmSaRelocationDurableError::AuthenticationFailed
        );
        assert_eq!(
            XfrmSaRelocationRecoveryStore::open_bound(root.path(), key(9), [0x43; 40]).unwrap_err(),
            XfrmSaRelocationDurableError::WrongBinding
        );

        let copied = TestRoot::new();
        fs::create_dir(copied.path()).unwrap();
        fs::set_permissions(copied.path(), fs::Permissions::from_mode(DIRECTORY_MODE)).unwrap();
        for entry in fs::read_dir(root.path()).unwrap() {
            let entry = entry.unwrap();
            fs::copy(entry.path(), copied.path().join(entry.file_name())).unwrap();
        }
        assert_eq!(
            XfrmSaRelocationRecoveryStore::open_bound(copied.path(), key(9), [0x42; 40])
                .unwrap_err(),
            XfrmSaRelocationDurableError::WrongBinding
        );

        let reopened = store(&root);
        fs::write(root.path().join("unknown"), b"poison").unwrap();
        assert_eq!(
            reopened.advance_writer_epoch(),
            Err(XfrmSaRelocationDurableError::Malformed)
        );
    }

    #[test]
    fn deletion_fingerprint_covers_target_sa_identity() {
        let root = TestRoot::new();
        let store = store(&root);
        let base = relocation_request();
        let base_fingerprint = store.fingerprints_for_request(&base).unwrap();

        let mut changed_destination = base.clone();
        changed_destination.new_destination = ipv4(198, 51, 100, 21);
        assert_ne!(
            base_fingerprint.deletion_identity,
            store
                .fingerprints_for_request(&changed_destination)
                .unwrap()
                .deletion_identity
        );

        let mut changed_spi = base.clone();
        changed_spi.current.id.spi += 1;
        assert_ne!(
            base_fingerprint.deletion_identity,
            store
                .fingerprints_for_request(&changed_spi)
                .unwrap()
                .deletion_identity
        );

        let mut changed_mark = base.clone();
        changed_mark.current.mark = Some(XfrmLookupMark::full(0x6291));
        assert_ne!(
            base_fingerprint.deletion_identity,
            store
                .fingerprints_for_request(&changed_mark)
                .unwrap()
                .deletion_identity
        );

        // Every retained request field changes the request fingerprint.
        let mut changed_source = base.clone();
        changed_source.new_source_address = ipv4(198, 51, 100, 11);
        assert_ne!(
            base_fingerprint.relocation_request,
            store
                .fingerprints_for_request(&changed_source)
                .unwrap()
                .relocation_request
        );
        let mut changed_direction = base.clone();
        changed_direction.direction = SaRelocationDirection::OutboundBlockPolicyInstalled;
        assert_ne!(
            base_fingerprint.relocation_request,
            store
                .fingerprints_for_request(&changed_direction)
                .unwrap()
                .relocation_request
        );
        let mut changed_selector = base.clone();
        changed_selector.current.selector.user_id = 1;
        assert_ne!(
            base_fingerprint.relocation_request,
            store
                .fingerprints_for_request(&changed_selector)
                .unwrap()
                .relocation_request
        );

        // A narrow lookup mark cannot produce an exact removal identity.
        let mut narrow_mark = base.clone();
        narrow_mark.current.mark = Some(XfrmLookupMark::new(0x6290_0000, 0xffff_0000).unwrap());
        assert!(matches!(
            store.fingerprints_for_request(&narrow_mark),
            Err(XfrmSaRelocationDurableError::NonExactRemovalIdentity)
        ));
    }

    #[test]
    fn proof_encoding_rules_fail_closed() {
        // Unknown proof codes are malformed.
        let valid = record(XfrmSaRelocationDurablePhase::Issuing)
            .encode(&key(9))
            .unwrap();
        let mut bad_code = valid;
        bad_code[12] = 3;
        assert_eq!(
            DurableRelocationRecord::decode(&bad_code, &key(9)),
            Err(XfrmSaRelocationDurableError::Malformed)
        );
        // Prepared must not carry a proof.
        let mut prepared_with_proof = record(XfrmSaRelocationDurablePhase::Prepared);
        prepared_with_proof.pre_effect_proof = Some(XfrmSaRelocationPreEffectProof::TargetAbsent);
        assert_eq!(
            prepared_with_proof.encode(&key(9)),
            Err(XfrmSaRelocationDurableError::Malformed)
        );
        // An effect-possible record must carry a proof.
        let mut issuing_without_proof = record(XfrmSaRelocationDurablePhase::Issuing);
        issuing_without_proof.pre_effect_proof = None;
        assert_eq!(
            issuing_without_proof.encode(&key(9)),
            Err(XfrmSaRelocationDurableError::Malformed)
        );
    }

    #[test]
    fn proof_round_trips_both_witnesses() {
        for proof in [
            XfrmSaRelocationPreEffectProof::TargetAbsent,
            XfrmSaRelocationPreEffectProof::SameIdentityWitnessed,
        ] {
            let mut expected = record(XfrmSaRelocationDurablePhase::Issuing);
            expected.pre_effect_proof = Some(proof);
            let encoded = expected.encode(&key(9)).unwrap();
            assert_eq!(
                DurableRelocationRecord::decode(&encoded, &key(9)).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn transition_requires_proof_exactly_for_entering_issuing() {
        let root = TestRoot::new();
        let store = store(&root);
        let prepared = store
            .prepare(
                XfrmSaRelocationOperationId::generate().unwrap(),
                XfrmSaRelocationOperationGeneration::new(1).unwrap(),
                fingerprints(0x61),
            )
            .unwrap();
        // Missing proof for Prepared -> Issuing is rejected.
        assert_eq!(
            store.transition(
                &prepared,
                XfrmSaRelocationDurablePhase::Prepared,
                XfrmSaRelocationDurablePhase::Issuing,
                None,
            ),
            Err(XfrmSaRelocationDurableError::InvalidTransition)
        );
        let issuing = store
            .transition(
                &prepared,
                XfrmSaRelocationDurablePhase::Prepared,
                XfrmSaRelocationDurablePhase::Issuing,
                Some(XfrmSaRelocationPreEffectProof::TargetAbsent),
            )
            .unwrap();
        assert_eq!(
            issuing.pre_effect_proof,
            Some(XfrmSaRelocationPreEffectProof::TargetAbsent)
        );
        // A supplied proof on any non-issuing transition is rejected.
        let issuing_handle = issuing.handle(&store.inner.proof_key).unwrap();
        assert_eq!(
            store.transition(
                &issuing_handle,
                XfrmSaRelocationDurablePhase::Issuing,
                XfrmSaRelocationDurablePhase::Relocated,
                Some(XfrmSaRelocationPreEffectProof::SameIdentityWitnessed),
            ),
            Err(XfrmSaRelocationDurableError::InvalidTransition)
        );
        // The accepted transition preserves the witnessed proof.
        let relocated = store
            .transition(
                &issuing_handle,
                XfrmSaRelocationDurablePhase::Issuing,
                XfrmSaRelocationDurablePhase::Relocated,
                None,
            )
            .unwrap();
        assert_eq!(
            relocated.pre_effect_proof,
            Some(XfrmSaRelocationPreEffectProof::TargetAbsent)
        );
    }

    #[test]
    fn unresolved_phases_gate_prepare_and_writer_epoch_until_retired() {
        for unresolved_phase in [
            XfrmSaRelocationDurablePhase::Prepared,
            XfrmSaRelocationDurablePhase::Issuing,
            XfrmSaRelocationDurablePhase::Indeterminate,
            XfrmSaRelocationDurablePhase::RemovalAdmitted,
        ] {
            let root = TestRoot::new();
            let store = store(&root);
            let operation = XfrmSaRelocationOperationId::generate().unwrap();
            let generation = XfrmSaRelocationOperationGeneration::new(1).unwrap();
            let prepared = store
                .prepare(operation, generation, fingerprints(0x62))
                .unwrap();
            let unresolved_handle = if unresolved_phase == XfrmSaRelocationDurablePhase::Prepared {
                prepared.clone()
            } else {
                let issuing = next_handle(
                    &store,
                    &prepared,
                    XfrmSaRelocationDurablePhase::Prepared,
                    XfrmSaRelocationDurablePhase::Issuing,
                );
                if unresolved_phase == XfrmSaRelocationDurablePhase::Issuing {
                    issuing.clone()
                } else {
                    next_handle(
                        &store,
                        &issuing,
                        XfrmSaRelocationDurablePhase::Issuing,
                        unresolved_phase,
                    )
                }
            };
            assert!(store.has_unresolved_writer_authority().unwrap());
            assert_eq!(
                store.prepare(
                    XfrmSaRelocationOperationId::generate().unwrap(),
                    generation,
                    fingerprints(0x63),
                ),
                Err(XfrmSaRelocationDurableError::InvalidTransition)
            );
            assert_eq!(
                store.advance_writer_epoch(),
                Err(XfrmSaRelocationDurableError::InvalidTransition)
            );
            // Retire the unresolved record through a no-mutation or removal
            // verdict and confirm the gate reopens.
            let retired = match unresolved_phase {
                XfrmSaRelocationDurablePhase::Prepared => next_handle(
                    &store,
                    &unresolved_handle,
                    unresolved_phase,
                    XfrmSaRelocationDurablePhase::Retired,
                ),
                XfrmSaRelocationDurablePhase::RemovalAdmitted => next_handle(
                    &store,
                    &unresolved_handle,
                    unresolved_phase,
                    XfrmSaRelocationDurablePhase::Retired,
                ),
                _ => {
                    let no_mutation = next_handle(
                        &store,
                        &unresolved_handle,
                        unresolved_phase,
                        XfrmSaRelocationDurablePhase::NoMutation,
                    );
                    next_handle(
                        &store,
                        &no_mutation,
                        XfrmSaRelocationDurablePhase::NoMutation,
                        XfrmSaRelocationDurablePhase::Retired,
                    )
                }
            };
            let _ = retired;
            assert!(!store.has_unresolved_writer_authority().unwrap());
            assert!(store.advance_writer_epoch().is_ok());
            assert!(store
                .prepare(
                    XfrmSaRelocationOperationId::generate().unwrap(),
                    generation,
                    fingerprints(0x63),
                )
                .is_ok());
        }
    }

    #[test]
    fn epoch_currency_predicate_tracks_writer_epoch_advances() {
        let root = TestRoot::new();
        let store = store(&root);
        let operation = XfrmSaRelocationOperationId::generate().unwrap();
        let generation = XfrmSaRelocationOperationGeneration::new(1).unwrap();
        let prepared = store
            .prepare(operation, generation, fingerprints(0x69))
            .unwrap();
        let issuing = store
            .transition(
                &prepared,
                XfrmSaRelocationDurablePhase::Prepared,
                XfrmSaRelocationDurablePhase::Issuing,
                Some(XfrmSaRelocationPreEffectProof::TargetAbsent),
            )
            .unwrap();
        assert!(store.record_writer_epoch_is_current(&issuing).unwrap());
        // Forge a later epoch underneath the unresolved record; the predicate
        // must then report the record as no longer current.
        let lease = store.lease().unwrap();
        let inventory = lease.inventory().unwrap();
        lease.advance_epoch(&inventory).unwrap();
        drop(lease);
        assert!(!store.record_writer_epoch_is_current(&issuing).unwrap());
    }

    /// Build the flow-level test request used by the durable-anomaly recovery
    /// detectors below.
    fn flow_relocation_request() -> RelocateSaRequest {
        use crate::{SaRelocationIdentity, SaRelocationSelector, XfrmSelector};
        let current = SaRelocationIdentity {
            selector: SaRelocationSelector::from_selector(&XfrmSelector::new(
                IpAddress::Ipv4([10, 62, 9, 1]),
                IpAddress::Ipv4([10, 62, 9, 2]),
                17,
            )),
            id: XfrmId {
                destination: IpAddress::Ipv4([192, 0, 2, 62]),
                spi: 0x6290_0001,
                protocol: 50,
            },
            source_address: IpAddress::Ipv4([192, 0, 2, 61]),
            request_id: XfrmRequestId::new(629),
            mode: XfrmMode::Tunnel,
            encap: Some(UdpEncap::esp_in_udp(4500, 4500)),
            mark: Some(XfrmLookupMark::full(0x6290)),
            if_id: Some(9),
            output_mark: None,
        };
        RelocateSaRequest {
            current,
            new_source_address: IpAddress::Ipv4([198, 51, 100, 10]),
            new_destination: IpAddress::Ipv4([198, 51, 100, 20]),
            encap: SaRelocationEncap::Set(UdpEncap::esp_in_udp(4500, 62_000)),
            direction: SaRelocationDirection::Inbound,
        }
    }

    #[tokio::test]
    async fn stale_epoch_under_unresolved_record_recovers_repair_required() {
        // A durable anomaly that advances the epoch underneath an unresolved
        // record removes the proof's ordering guarantee. Recovery must refuse
        // to delete and classify the record for repair, keeping it gating.
        let root = TestRoot::new();
        let store = store(&root);
        let operation = XfrmSaRelocationOperationId::generate().unwrap();
        let generation = XfrmSaRelocationOperationGeneration::new(1).unwrap();
        let request = flow_relocation_request();
        let fingerprints = store.fingerprints_for_request(&request).unwrap();
        let prepared = store.prepare(operation, generation, fingerprints).unwrap();
        store
            .transition(
                &prepared,
                XfrmSaRelocationDurablePhase::Prepared,
                XfrmSaRelocationDurablePhase::Issuing,
                Some(XfrmSaRelocationPreEffectProof::TargetAbsent),
            )
            .unwrap();
        let lease = store.lease().unwrap();
        let inventory = lease.inventory().unwrap();
        lease.advance_epoch(&inventory).unwrap();
        drop(lease);

        let backend = crate::MockXfrmBackend::new();
        let outcome = crate::durable_relocation_flow::recover_durable_sa_relocation(
            &store, operation, generation, &request, &backend,
        )
        .await
        .unwrap();
        assert_eq!(outcome.as_str(), "repair_required");
        // The record remains unresolved and keeps gating writers.
        assert_eq!(
            store.advance_writer_epoch(),
            Err(XfrmSaRelocationDurableError::InvalidTransition)
        );
        assert!(backend.operations().is_empty());
    }

    #[tokio::test]
    async fn removed_proof_under_unresolved_record_fails_closed() {
        // Tampering that removes the pre-effect proof from an effect-possible
        // record is re-authenticated below so the detector reacts to the
        // missing proof itself, not to a broken tag. Record decode enforces
        // phase/proof consistency, so the store refuses to read the record at
        // all and recovery performs no deletion.
        let root = TestRoot::new();
        let store = store(&root);
        let operation = XfrmSaRelocationOperationId::generate().unwrap();
        let generation = XfrmSaRelocationOperationGeneration::new(1).unwrap();
        let request = flow_relocation_request();
        let fingerprints = store.fingerprints_for_request(&request).unwrap();
        let prepared = store.prepare(operation, generation, fingerprints).unwrap();
        let issuing = store
            .transition(
                &prepared,
                XfrmSaRelocationDurablePhase::Prepared,
                XfrmSaRelocationDurablePhase::Issuing,
                Some(XfrmSaRelocationPreEffectProof::TargetAbsent),
            )
            .unwrap();
        let record_file = root.path().join(record_name(&issuing));
        let _ = issuing;

        // Rewrite the durable record file with the proof byte zeroed and a
        // fresh authentication tag.
        let mut encoded = fs::read(&record_file).unwrap();
        encoded[12] = 0;
        let tag = authenticate_domain(&key(9), RECORD_AUTH_DOMAIN, &encoded[..RECORD_BODY_BYTES])
            .unwrap();
        encoded[RECORD_BODY_BYTES..].copy_from_slice(&tag);
        fs::write(&record_file, &encoded).unwrap();

        let backend = crate::MockXfrmBackend::new();
        assert!(matches!(
            crate::durable_relocation_flow::recover_durable_sa_relocation(
                &store, operation, generation, &request, &backend,
            )
            .await,
            Err(XfrmSaRelocationDurableError::Malformed)
        ));
        assert!(backend.operations().is_empty());
    }
}
