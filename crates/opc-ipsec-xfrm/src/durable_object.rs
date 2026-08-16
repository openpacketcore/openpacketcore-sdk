//! Durable, authenticated authority records for staged single-object recovery.
//!
//! This module deliberately stores only opaque correlation values and keyed
//! fingerprints. It never serializes an XFRM request, key material, packet
//! mark, SPI, selector, or address. A decoded record is correlation data, not
//! cleanup authority: callers must validate it through
//! [`XfrmObjectInstallRecoveryStore`] while holding that store's permanent
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

use crate::model::validate_exact_lookup_mark;
use crate::{
    IpAddress, LifetimeConfig, RemovePolicyRequest, RemoveSaRequest, SaReplayState, UdpEncap,
    XfrmAction, XfrmDirection, XfrmId, XfrmInstallObject, XfrmLookupMark, XfrmMark, XfrmMode,
    XfrmObjectInstallRequest, XfrmObjectRemovalRequest, XfrmRequestId, XfrmSelector, XfrmTemplate,
};

/// Exact byte length of a persisted recovery handle and durable record.
pub const XFRM_OBJECT_INSTALL_RECOVERY_HANDLE_BYTES: usize = 208;

const RECORD_BODY_BYTES: usize = 176;
const AUTH_TAG_BYTES: usize = 32;
const RECORD_MAGIC: [u8; 8] = *b"OPCXOBJ1";
const RECORD_VERSION: u16 = 2;
const RECORD_AUTH_DOMAIN: &[u8] = b"opc-xfrm-object-record-v1\0";
const INSTALL_REQUEST_AUTH_DOMAIN: &[u8] = b"opc-xfrm-object-install-request-v1\0";
const DELETION_IDENTITY_AUTH_DOMAIN: &[u8] = b"opc-xfrm-object-deletion-identity-v1\0";
const NAMESPACE_AUTH_DOMAIN: &[u8] = b"opc-xfrm-object-namespace-v1\0";
const CONTROL_BYTES: usize = 128;
const CONTROL_BODY_BYTES: usize = CONTROL_BYTES - AUTH_TAG_BYTES;
const CONTROL_MAGIC: [u8; 8] = *b"OPCXCTL1";
const CONTROL_AUTH_DOMAIN: &[u8] = b"opc-xfrm-object-control-v1\0";
const CONTROL_NAME: &str = "control";
const TEMPORARY_PREFIX: &str = ".opc-xfrm-object-pending-";
const EPOCH_BYTES: usize = 80;
const EPOCH_BODY_BYTES: usize = EPOCH_BYTES - AUTH_TAG_BYTES;
const EPOCH_MAGIC: [u8; 8] = *b"OPCXEPC1";
const EPOCH_AUTH_DOMAIN: &[u8] = b"opc-xfrm-object-epoch-v1\0";
const MAX_STORE_ENTRIES: usize = 64;
const MAX_ACTIVE_RECORDS: usize = MAX_STORE_ENTRIES - 3;
const MAX_STORE_PATH_BYTES: usize = 4096;
const FILE_MODE: u32 = 0o600;
const DIRECTORY_MODE: u32 = 0o700;
const CREATE_ATTEMPTS: usize = 8;

pub(crate) type HmacSha256 = ZeroizingHmacSha256;

pub(crate) struct ZeroizingHmacSha256 {
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

    pub(crate) fn update(&mut self, bytes: &[u8]) {
        self.inner.update(bytes);
    }

    pub(crate) fn finalize(self) -> Zeroizing<[u8; AUTH_TAG_BYTES]> {
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

/// Borrow-scoped view of one durable family's secret proof-key bytes.
///
/// Every durable record family owns a distinct zeroizing proof-key newtype.
/// The canonical encoders below are shared across those families, so they take
/// this borrow instead of a concrete key type. The borrow is the point: the
/// secret is never copied out of its owning newtype, so each family keeps its
/// own `Drop`-time zeroization discipline.
#[derive(Clone, Copy)]
pub(crate) struct CanonicalMacKey<'a>(&'a [u8; AUTH_TAG_BYTES]);

impl<'a> CanonicalMacKey<'a> {
    /// Borrow a proof-key newtype's secret bytes for canonical encoding.
    ///
    /// Call this only from a proof-key newtype's own accessor so the borrow
    /// cannot outlive the key it observes.
    pub(crate) const fn new(bytes: &'a [u8; AUTH_TAG_BYTES]) -> Self {
        Self(bytes)
    }

    /// Start a keyed MAC already bound to one family-specific domain.
    ///
    /// The domain separator is unconditionally absorbed first, so no caller can
    /// produce a domain-free tag by forgetting it.
    pub(crate) fn begin(self, domain: &[u8]) -> HmacSha256 {
        let mut mac = HmacSha256::new(self.0);
        mac.update(domain);
        mac
    }
}

impl fmt::Debug for CanonicalMacKey<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CanonicalMacKey(<redacted>)")
    }
}

/// Value-free failure of a shared canonical encoder.
///
/// Each durable family maps this into its own public error enum so no family
/// leaks another family's diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CanonicalEncodeError {
    /// A variable-length field exceeds the bounded canonical encoding.
    CapacityExceeded,
    /// The request cannot produce an exact canonical identity.
    Malformed,
}

/// Secret proof key used to authenticate staged-object recovery state.
///
/// The key is supplied by the product's durable secret configuration and must
/// remain stable across a process restart. `Debug` and `Display` are redacted,
/// and the bytes are zeroized when the value is dropped.
pub struct XfrmObjectRecoveryProofKey([u8; AUTH_TAG_BYTES]);

impl XfrmObjectRecoveryProofKey {
    /// Construct a proof key from exactly 256 bits of secret material.
    ///
    /// An all-zero key is rejected so an omitted secret cannot silently create
    /// forgeable recovery authority.
    pub fn new(bytes: [u8; AUTH_TAG_BYTES]) -> Result<Self, XfrmObjectInstallDurableError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(XfrmObjectInstallDurableError::InvalidProofKey);
        }
        Ok(Self(bytes))
    }

    /// Borrow this key for the shared canonical encoders.
    pub(crate) const fn canonical_mac_key(&self) -> CanonicalMacKey<'_> {
        CanonicalMacKey::new(&self.0)
    }
}

impl Clone for XfrmObjectRecoveryProofKey {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl Drop for XfrmObjectRecoveryProofKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for XfrmObjectRecoveryProofKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("XfrmObjectRecoveryProofKey(<redacted>)")
    }
}

impl fmt::Display for XfrmObjectRecoveryProofKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

/// Opaque, randomly generated identity of one staged install operation.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct XfrmObjectInstallOperationId([u8; 16]);

impl XfrmObjectInstallOperationId {
    /// Generate a nonzero operation identity using the operating system RNG.
    pub fn generate() -> Result<Self, XfrmObjectInstallDurableError> {
        let mut bytes = [0_u8; 16];
        SysRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| XfrmObjectInstallDurableError::EntropyUnavailable)?;
        Self::from_bytes(bytes)
    }

    /// Decode an opaque operation identity, rejecting the reserved zero value.
    pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, XfrmObjectInstallDurableError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(XfrmObjectInstallDurableError::Malformed);
        }
        Ok(Self(bytes))
    }

    /// Return the opaque correlation bytes for durable application storage.
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0
    }
}

impl fmt::Debug for XfrmObjectInstallOperationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("XfrmObjectInstallOperationId(<redacted>)")
    }
}

impl fmt::Display for XfrmObjectInstallOperationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

/// Nonzero product generation for one staged install operation.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct XfrmObjectInstallOperationGeneration(NonZeroU64);

impl XfrmObjectInstallOperationGeneration {
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

impl fmt::Debug for XfrmObjectInstallOperationGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("XfrmObjectInstallOperationGeneration(<redacted>)")
    }
}

impl fmt::Display for XfrmObjectInstallOperationGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

/// Durable state of a staged single-object install.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XfrmObjectInstallDurablePhase {
    /// Intent is durable and no backend mutation has been admitted.
    Prepared,
    /// The writer epoch was advanced before issuing the install.
    Issuing,
    /// Linux acknowledged that this operation acquired the object.
    Acquired,
    /// A pre-effect conflict or create-exclusive collision proved no mutation.
    NoMutation,
    /// The backend result cannot safely prove ownership or absence.
    Indeterminate,
    /// Recovery authority was validated and fenced before deletion.
    RemovalAdmitted,
    /// Recovery completed and no cleanup authority remains.
    Retired,
    /// The product adopted the object and cleanup authority was surrendered.
    Committed,
}

impl XfrmObjectInstallDurablePhase {
    /// Stable, value-free phase label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Issuing => "issuing",
            Self::Acquired => "acquired",
            Self::NoMutation => "no_mutation",
            Self::Indeterminate => "indeterminate",
            Self::RemovalAdmitted => "removal_admitted",
            Self::Retired => "retired",
            Self::Committed => "committed",
        }
    }

    const fn code(self) -> u8 {
        match self {
            Self::Prepared => 1,
            Self::Issuing => 2,
            Self::Acquired => 3,
            Self::NoMutation => 4,
            Self::Indeterminate => 5,
            Self::RemovalAdmitted => 6,
            Self::Retired => 7,
            Self::Committed => 8,
        }
    }

    fn from_code(code: u8) -> Result<Self, XfrmObjectInstallDurableError> {
        match code {
            1 => Ok(Self::Prepared),
            2 => Ok(Self::Issuing),
            3 => Ok(Self::Acquired),
            4 => Ok(Self::NoMutation),
            5 => Ok(Self::Indeterminate),
            6 => Ok(Self::RemovalAdmitted),
            7 => Ok(Self::Retired),
            8 => Ok(Self::Committed),
            _ => Err(XfrmObjectInstallDurableError::Malformed),
        }
    }

    pub(crate) const fn permits(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Prepared, Self::Issuing)
                | (Self::Prepared, Self::Retired)
                | (Self::Issuing, Self::Acquired)
                | (Self::Issuing, Self::NoMutation)
                | (Self::Issuing, Self::Indeterminate)
                | (Self::Issuing, Self::RemovalAdmitted)
                | (Self::Indeterminate, Self::NoMutation)
                | (Self::Indeterminate, Self::RemovalAdmitted)
                | (Self::Acquired, Self::RemovalAdmitted)
                | (Self::Acquired, Self::Committed)
                | (Self::NoMutation, Self::Retired)
                | (Self::RemovalAdmitted, Self::Retired)
        )
    }
}

/// Durable pre-effect proof witnessed before possible backend install
/// admission.
///
/// Immediately before the `Prepared -> Issuing` transition, the namespace
/// actor performs an exact readback of the deletion identity and embeds the
/// observed presence in the record. After process loss, combining this proof
/// with a fresh exact readback distinguishes a provably-owned residue from a
/// foreign or absent object without relying on retained intent alone.
///
/// This type is crate-internal: it never appears in a public signature and is
/// only observable through the recovery outcome it authorizes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum XfrmObjectInstallPreEffectProof {
    /// The exact deletion identity was absent immediately before possible
    /// effect admission.
    Absent = 1,
    /// The exact deletion identity was already present, so the install effect
    /// was not admitted.
    Conflict = 2,
}

impl XfrmObjectInstallPreEffectProof {
    /// Stable, value-free proof label.
    pub(crate) const fn as_str(self) -> &'static str {
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

    fn from_code(code: u8) -> Result<Self, XfrmObjectInstallDurableError> {
        match code {
            1 => Ok(Self::Absent),
            2 => Ok(Self::Conflict),
            _ => Err(XfrmObjectInstallDurableError::Malformed),
        }
    }
}

impl fmt::Debug for XfrmObjectInstallPreEffectProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("XfrmObjectInstallPreEffectProof")
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
pub struct XfrmObjectInstallRecoveryHandle([u8; XFRM_OBJECT_INSTALL_RECOVERY_HANDLE_BYTES]);

impl XfrmObjectInstallRecoveryHandle {
    /// Decode fixed-size opaque bytes without treating them as authority.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; XFRM_OBJECT_INSTALL_RECOVERY_HANDLE_BYTES]) -> Self {
        Self(bytes)
    }

    /// Return fixed-size opaque bytes for durable application storage.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; XFRM_OBJECT_INSTALL_RECOVERY_HANDLE_BYTES] {
        self.0
    }
}

impl fmt::Debug for XfrmObjectInstallRecoveryHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("XfrmObjectInstallRecoveryHandle(<redacted>)")
    }
}

impl fmt::Display for XfrmObjectInstallRecoveryHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

/// Value-free durable recovery failure.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XfrmObjectInstallDurableError {
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

impl XfrmObjectInstallDurableError {
    /// Stable machine-readable, value-free error code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidProofKey => "xfrm_object_recovery_invalid_proof_key",
            Self::EntropyUnavailable => "xfrm_object_recovery_entropy_unavailable",
            Self::InvalidStoreRoot => "xfrm_object_recovery_invalid_store_root",
            Self::StoreBusy => "xfrm_object_recovery_store_busy",
            Self::Storage => "xfrm_object_recovery_storage",
            Self::Malformed => "xfrm_object_recovery_malformed",
            Self::AuthenticationFailed => "xfrm_object_recovery_authentication_failed",
            Self::Duplicate => "xfrm_object_recovery_duplicate",
            Self::WrongBinding => "xfrm_object_recovery_wrong_binding",
            Self::WrongIncarnation => "xfrm_object_recovery_wrong_incarnation",
            Self::Stale => "xfrm_object_recovery_stale",
            Self::InvalidTransition => "xfrm_object_recovery_invalid_transition",
            Self::NonExactRemovalIdentity => "xfrm_object_recovery_non_exact_removal_identity",
            Self::NotFound => "xfrm_object_recovery_not_found",
            Self::CapacityExceeded => "xfrm_object_recovery_capacity_exceeded",
        }
    }
}

impl fmt::Display for XfrmObjectInstallDurableError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Error for XfrmObjectInstallDurableError {}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct DurableObjectRecord {
    pub(crate) phase: XfrmObjectInstallDurablePhase,
    pub(crate) object: XfrmInstallObject,
    pub(crate) pre_effect_proof: Option<XfrmObjectInstallPreEffectProof>,
    pub(crate) store_incarnation: [u8; 16],
    pub(crate) namespace_seal: [u8; 32],
    pub(crate) actor_incarnation: [u8; 16],
    pub(crate) operation_id: XfrmObjectInstallOperationId,
    pub(crate) operation_generation: XfrmObjectInstallOperationGeneration,
    pub(crate) writer_epoch: NonZeroU64,
    pub(crate) deletion_identity_fingerprint: [u8; 32],
    pub(crate) install_request_fingerprint: [u8; 32],
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct DurableObjectFingerprints {
    deletion_identity: [u8; 32],
    install_request: [u8; 32],
}

impl DurableObjectFingerprints {
    #[cfg(test)]
    pub(crate) fn repeated(byte: u8) -> Self {
        Self {
            deletion_identity: [byte; 32],
            install_request: [byte.wrapping_add(1); 32],
        }
    }
}

impl fmt::Debug for DurableObjectRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableObjectRecord")
            .field("phase", &self.phase)
            .field("object", &self.object.as_str())
            .finish_non_exhaustive()
    }
}

impl DurableObjectRecord {
    pub(crate) fn encode(
        &self,
        key: &XfrmObjectRecoveryProofKey,
    ) -> Result<[u8; XFRM_OBJECT_INSTALL_RECOVERY_HANDLE_BYTES], XfrmObjectInstallDurableError>
    {
        validate_record(self)?;
        let mut encoded = [0_u8; XFRM_OBJECT_INSTALL_RECOVERY_HANDLE_BYTES];
        encoded[0..8].copy_from_slice(&RECORD_MAGIC);
        encoded[8..10].copy_from_slice(&RECORD_VERSION.to_be_bytes());
        encoded[10] = self.phase.code();
        encoded[11] = match self.object {
            XfrmInstallObject::Sa => 1,
            XfrmInstallObject::Policy => 2,
        };
        encoded[12] = self.pre_effect_proof.map_or(0, |proof| proof.code());
        encoded[16..32].copy_from_slice(&self.store_incarnation);
        encoded[32..64].copy_from_slice(&self.namespace_seal);
        encoded[64..80].copy_from_slice(&self.actor_incarnation);
        encoded[80..96].copy_from_slice(&self.operation_id.0);
        encoded[96..104].copy_from_slice(&self.operation_generation.get().to_be_bytes());
        encoded[104..112].copy_from_slice(&self.writer_epoch.get().to_be_bytes());
        encoded[112..144].copy_from_slice(&self.deletion_identity_fingerprint);
        encoded[144..176].copy_from_slice(&self.install_request_fingerprint);
        let tag = authenticate(key, &encoded[..RECORD_BODY_BYTES]);
        encoded[RECORD_BODY_BYTES..].copy_from_slice(&tag);
        Ok(encoded)
    }

    pub(crate) fn decode(
        encoded: &[u8; XFRM_OBJECT_INSTALL_RECOVERY_HANDLE_BYTES],
        key: &XfrmObjectRecoveryProofKey,
    ) -> Result<Self, XfrmObjectInstallDurableError> {
        if encoded[0..8] != RECORD_MAGIC
            || encoded[8..10] != RECORD_VERSION.to_be_bytes()
            || encoded[13..16] != [0_u8; 3]
        {
            return Err(XfrmObjectInstallDurableError::Malformed);
        }
        let pre_effect_proof = match encoded[12] {
            0 => None,
            code => Some(XfrmObjectInstallPreEffectProof::from_code(code)?),
        };
        verify_authentication(
            key,
            &encoded[..RECORD_BODY_BYTES],
            &encoded[RECORD_BODY_BYTES..],
        )?;
        let object = match encoded[11] {
            1 => XfrmInstallObject::Sa,
            2 => XfrmInstallObject::Policy,
            _ => return Err(XfrmObjectInstallDurableError::Malformed),
        };
        let record = Self {
            phase: XfrmObjectInstallDurablePhase::from_code(encoded[10])?,
            object,
            pre_effect_proof,
            store_incarnation: array_at(encoded, 16),
            namespace_seal: array_at(encoded, 32),
            actor_incarnation: array_at(encoded, 64),
            operation_id: XfrmObjectInstallOperationId::from_bytes(array_at(encoded, 80))?,
            operation_generation: XfrmObjectInstallOperationGeneration::new(u64_at(encoded, 96))
                .ok_or(XfrmObjectInstallDurableError::Malformed)?,
            writer_epoch: NonZeroU64::new(u64_at(encoded, 104))
                .ok_or(XfrmObjectInstallDurableError::Malformed)?,
            deletion_identity_fingerprint: array_at(encoded, 112),
            install_request_fingerprint: array_at(encoded, 144),
        };
        validate_record(&record)?;
        Ok(record)
    }

    pub(crate) fn handle(
        &self,
        key: &XfrmObjectRecoveryProofKey,
    ) -> Result<XfrmObjectInstallRecoveryHandle, XfrmObjectInstallDurableError> {
        Ok(XfrmObjectInstallRecoveryHandle(self.encode(key)?))
    }
}

fn validate_record(record: &DurableObjectRecord) -> Result<(), XfrmObjectInstallDurableError> {
    if record.store_incarnation.iter().all(|byte| *byte == 0)
        || record.namespace_seal.iter().all(|byte| *byte == 0)
        || record.actor_incarnation.iter().all(|byte| *byte == 0)
        || record
            .deletion_identity_fingerprint
            .iter()
            .all(|byte| *byte == 0)
        || record
            .install_request_fingerprint
            .iter()
            .all(|byte| *byte == 0)
    {
        return Err(XfrmObjectInstallDurableError::Malformed);
    }
    // The pre-effect proof is witnessed exactly at the `Prepared -> Issuing`
    // transition and preserved by every subsequent transition. A `Prepared`
    // record therefore never carries a proof, every effect-possible or
    // terminal-effect phase must carry one, and a `Retired` record may or may
    // not depending on whether it retired through an effect-possible phase.
    let proof_required = matches!(
        record.phase,
        XfrmObjectInstallDurablePhase::Issuing
            | XfrmObjectInstallDurablePhase::Acquired
            | XfrmObjectInstallDurablePhase::NoMutation
            | XfrmObjectInstallDurablePhase::Indeterminate
            | XfrmObjectInstallDurablePhase::RemovalAdmitted
            | XfrmObjectInstallDurablePhase::Committed
    );
    let proof_forbidden = record.phase == XfrmObjectInstallDurablePhase::Prepared;
    if (proof_required && record.pre_effect_proof.is_none())
        || (proof_forbidden && record.pre_effect_proof.is_some())
    {
        return Err(XfrmObjectInstallDurableError::Malformed);
    }
    Ok(())
}

fn fingerprints_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    bool::from(left.ct_eq(right))
}

fn record_matches_fingerprints(
    record: &DurableObjectRecord,
    fingerprints: DurableObjectFingerprints,
) -> bool {
    bool::from(
        record
            .deletion_identity_fingerprint
            .ct_eq(&fingerprints.deletion_identity)
            & record
                .install_request_fingerprint
                .ct_eq(&fingerprints.install_request),
    )
}

fn authenticate(key: &XfrmObjectRecoveryProofKey, body: &[u8]) -> [u8; AUTH_TAG_BYTES] {
    authenticate_domain(key.canonical_mac_key(), RECORD_AUTH_DOMAIN, body)
}

/// Compute the domain-separated keyed tag over one canonical body.
pub(crate) fn authenticate_domain(
    key: CanonicalMacKey<'_>,
    domain: &[u8],
    body: &[u8],
) -> [u8; AUTH_TAG_BYTES] {
    let mut mac = key.begin(domain);
    mac.update(body);
    *mac.finalize()
}

fn verify_authentication(
    key: &XfrmObjectRecoveryProofKey,
    body: &[u8],
    tag: &[u8],
) -> Result<(), XfrmObjectInstallDurableError> {
    if verify_authentication_domain(key.canonical_mac_key(), RECORD_AUTH_DOMAIN, body, tag) {
        Ok(())
    } else {
        Err(XfrmObjectInstallDurableError::AuthenticationFailed)
    }
}

/// Report whether a tag matches the domain-separated keyed tag of one body.
///
/// The comparison is constant time. Callers map `false` into their own family's
/// authentication failure so no family leaks another family's diagnostics.
#[must_use]
pub(crate) fn verify_authentication_domain(
    key: CanonicalMacKey<'_>,
    domain: &[u8],
    body: &[u8],
    tag: &[u8],
) -> bool {
    let mut mac = key.begin(domain);
    mac.update(body);
    bool::from(mac.finalize().as_slice().ct_eq(tag))
}

fn array_at<const N: usize>(bytes: &[u8], start: usize) -> [u8; N] {
    let mut result = [0_u8; N];
    result.copy_from_slice(&bytes[start..start + N]);
    result
}

fn u64_at(bytes: &[u8], start: usize) -> u64 {
    u64::from_be_bytes(array_at(bytes, start))
}

/// Descriptor-anchored, permanently leased recovery store.
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
pub struct XfrmObjectInstallRecoveryStore {
    inner: Arc<StoreInner>,
}

struct StoreInner {
    visible_path: PathBuf,
    descriptor: OwnedFd,
    root_device: u64,
    root_inode: u64,
    root_owner: u32,
    owner_process_id: u32,
    proof_key: XfrmObjectRecoveryProofKey,
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
        key: &XfrmObjectRecoveryProofKey,
    ) -> Result<[u8; CONTROL_BYTES], XfrmObjectInstallDurableError> {
        if self.store_incarnation.iter().all(|byte| *byte == 0)
            || self.namespace_seal.iter().all(|byte| *byte == 0)
            || self.actor_incarnation.iter().all(|byte| *byte == 0)
            || self.root_device == 0
            || self.root_inode == 0
        {
            return Err(XfrmObjectInstallDurableError::Malformed);
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
        key: &XfrmObjectRecoveryProofKey,
    ) -> Result<Self, XfrmObjectInstallDurableError> {
        if encoded[0..8] != CONTROL_MAGIC
            || encoded[8..10] != RECORD_VERSION.to_be_bytes()
            || encoded[10..16] != [0_u8; 6]
        {
            return Err(XfrmObjectInstallDurableError::Malformed);
        }
        if !verify_authentication_domain(
            key.canonical_mac_key(),
            CONTROL_AUTH_DOMAIN,
            &encoded[..CONTROL_BODY_BYTES],
            &encoded[CONTROL_BODY_BYTES..],
        ) {
            return Err(XfrmObjectInstallDurableError::AuthenticationFailed);
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
            return Err(XfrmObjectInstallDurableError::Malformed);
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
        key: &XfrmObjectRecoveryProofKey,
    ) -> Result<[u8; EPOCH_BYTES], XfrmObjectInstallDurableError> {
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
        key: &XfrmObjectRecoveryProofKey,
    ) -> Result<Self, XfrmObjectInstallDurableError> {
        if encoded[0..8] != EPOCH_MAGIC
            || encoded[8..10] != RECORD_VERSION.to_be_bytes()
            || encoded[10..16] != [0_u8; 6]
            || encoded[40..EPOCH_BODY_BYTES].iter().any(|byte| *byte != 0)
        {
            return Err(XfrmObjectInstallDurableError::Malformed);
        }
        if !verify_authentication_domain(
            key.canonical_mac_key(),
            EPOCH_AUTH_DOMAIN,
            &encoded[..EPOCH_BODY_BYTES],
            &encoded[EPOCH_BODY_BYTES..],
        ) {
            return Err(XfrmObjectInstallDurableError::AuthenticationFailed);
        }
        let store_incarnation = array_at(encoded, 16);
        let epoch =
            NonZeroU64::new(u64_at(encoded, 32)).ok_or(XfrmObjectInstallDurableError::Malformed)?;
        if store_incarnation.iter().all(|byte| *byte == 0) {
            return Err(XfrmObjectInstallDurableError::Malformed);
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

type NamedDurableRecord = (String, DurableObjectRecord);
type ReconciledOperationRecords = (Vec<NamedDurableRecord>, Vec<String>);

impl Inventory {
    fn has_unresolved_writer_authority(&self) -> bool {
        self.records.iter().any(|(_, record)| {
            matches!(
                record.phase,
                XfrmObjectInstallDurablePhase::Issuing
                    | XfrmObjectInstallDurablePhase::Indeterminate
                    | XfrmObjectInstallDurablePhase::Acquired
                    | XfrmObjectInstallDurablePhase::RemovalAdmitted
            )
        })
    }

    fn current_for(
        &self,
        operation_id: XfrmObjectInstallOperationId,
        generation: XfrmObjectInstallOperationGeneration,
    ) -> Result<(&str, &DurableObjectRecord), XfrmObjectInstallDurableError> {
        let mut matches = self.records.iter().filter(|(_, record)| {
            record.operation_id == operation_id && record.operation_generation == generation
        });
        let Some((name, record)) = matches.next() else {
            return Err(XfrmObjectInstallDurableError::NotFound);
        };
        if matches.next().is_some() {
            return Err(XfrmObjectInstallDurableError::Duplicate);
        }
        Ok((name, record))
    }
}

impl XfrmObjectInstallRecoveryStore {
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
        proof_key: XfrmObjectRecoveryProofKey,
        namespace_binding: [u8; 40],
    ) -> Result<Self, XfrmObjectInstallDurableError> {
        if !valid_store_path(path) {
            return Err(XfrmObjectInstallDurableError::InvalidStoreRoot);
        }
        create_root_if_absent(path)?;
        let descriptor = open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(map_root_open_error)?;
        let metadata = fstat(&descriptor).map_err(|_| XfrmObjectInstallDurableError::Storage)?;
        validate_root_metadata(&metadata)?;
        let root_device = stat_device(&metadata)?;
        let root_inode = stat_inode(&metadata)?;
        flock(&descriptor, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
            if error == rustix::io::Errno::WOULDBLOCK {
                XfrmObjectInstallDurableError::StoreBusy
            } else {
                XfrmObjectInstallDurableError::Storage
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
            process_lock: Mutex::new(()),
        };
        inner.control = initialize_or_load_control(&inner, namespace_seal)?;
        let store = Self {
            inner: Arc::new(inner),
        };
        store.lease()?.inventory()?;
        Ok(store)
    }

    /// Persist a prepared operation before any backend mutation is admitted.
    ///
    /// The fingerprints must be independent opaque, proof-keyed digests of
    /// the exact kernel deletion identity and complete install request. A
    /// duplicate active deletion identity is rejected globally. Any unresolved
    /// `Issuing`, `Indeterminate`, `Acquired`, or `RemovalAdmitted` authority
    /// blocks preparation so consumer bookkeeping/recovery remains ordered
    /// before every later cooperating writer.
    pub(crate) fn prepare(
        &self,
        operation_id: XfrmObjectInstallOperationId,
        operation_generation: XfrmObjectInstallOperationGeneration,
        object: XfrmInstallObject,
        fingerprints: DurableObjectFingerprints,
    ) -> Result<XfrmObjectInstallRecoveryHandle, XfrmObjectInstallDurableError> {
        let lease = self.lease()?;
        let mut inventory = lease.inventory()?;
        if lease.prune_terminal_records(&inventory)? {
            inventory = lease.inventory()?;
        }
        if inventory.has_unresolved_writer_authority() {
            return Err(XfrmObjectInstallDurableError::InvalidTransition);
        }
        if inventory.records.len() >= MAX_ACTIVE_RECORDS {
            return Err(XfrmObjectInstallDurableError::CapacityExceeded);
        }
        if inventory.records.iter().any(|(_, record)| {
            record.operation_id == operation_id
                && record.operation_generation == operation_generation
        }) {
            return Err(XfrmObjectInstallDurableError::Duplicate);
        }
        if inventory.records.iter().any(|(_, record)| {
            fingerprints_equal(
                &record.deletion_identity_fingerprint,
                &fingerprints.deletion_identity,
            ) && !matches!(
                record.phase,
                XfrmObjectInstallDurablePhase::Retired | XfrmObjectInstallDurablePhase::Committed
            )
        }) {
            return Err(XfrmObjectInstallDurableError::Duplicate);
        }
        let epoch = lease.current_epoch(&inventory)?;
        let record = DurableObjectRecord {
            phase: XfrmObjectInstallDurablePhase::Prepared,
            object,
            pre_effect_proof: None,
            store_incarnation: lease.store.control.store_incarnation,
            namespace_seal: lease.store.control.namespace_seal,
            actor_incarnation: lease.store.control.actor_incarnation,
            operation_id,
            operation_generation,
            writer_epoch: epoch,
            deletion_identity_fingerprint: fingerprints.deletion_identity,
            install_request_fingerprint: fingerprints.install_request,
        };
        lease.publish_record(&record)?;
        record.handle(&lease.store.proof_key)
    }

    /// Compute independent keyed fingerprints of the exact removal identity
    /// and complete install request without persisting either plaintext.
    pub(crate) fn fingerprints_for_request(
        &self,
        request: &XfrmObjectInstallRequest,
    ) -> Result<DurableObjectFingerprints, XfrmObjectInstallDurableError> {
        let removal = request.removal();
        validate_exact_lookup_mark(removal.lookup_mark(), "durable_object.install.mark")
            .map_err(|_| XfrmObjectInstallDurableError::NonExactRemovalIdentity)?;
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
        Ok(DurableObjectFingerprints {
            deletion_identity,
            install_request,
        })
    }

    #[cfg(test)]
    fn deletion_identity_fingerprint_with_policy_if_id(
        &self,
        removal: &XfrmObjectRemovalRequest,
        policy_if_id: Option<u32>,
    ) -> Result<[u8; 32], XfrmObjectInstallDurableError> {
        validate_exact_lookup_mark(removal.lookup_mark(), "durable_object.install.mark")
            .map_err(|_| XfrmObjectInstallDurableError::NonExactRemovalIdentity)?;
        let lease = self.lease()?;
        authenticate_deletion_identity(
            lease.store.proof_key.canonical_mac_key(),
            DELETION_IDENTITY_AUTH_DOMAIN,
            removal,
            policy_if_id,
        )
        .map_err(map_canonical_encode_error)
    }

    /// Inspect the authenticated current phase for a retained handle.
    ///
    /// The result is diagnostic state only and never cleanup authority.
    pub fn inspect(
        &self,
        handle: &XfrmObjectInstallRecoveryHandle,
    ) -> Result<XfrmObjectInstallDurablePhase, XfrmObjectInstallDurableError> {
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
        operation_id: XfrmObjectInstallOperationId,
        operation_generation: XfrmObjectInstallOperationGeneration,
        object: XfrmInstallObject,
        fingerprints: DurableObjectFingerprints,
    ) -> Result<DurableObjectRecord, XfrmObjectInstallDurableError> {
        let lease = self.lease()?;
        let inventory = lease.inventory()?;
        let (_, record) = inventory.current_for(operation_id, operation_generation)?;
        lease.validate_record_binding(record)?;
        if record.object != object || !record_matches_fingerprints(record, fingerprints) {
            return Err(XfrmObjectInstallDurableError::WrongBinding);
        }
        if matches!(
            record.phase,
            XfrmObjectInstallDurablePhase::Acquired
                | XfrmObjectInstallDurablePhase::RemovalAdmitted
        ) && record.writer_epoch != lease.current_epoch(&inventory)?
        {
            return Err(XfrmObjectInstallDurableError::Stale);
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
        handle: &XfrmObjectInstallRecoveryHandle,
        object: XfrmInstallObject,
        fingerprints: DurableObjectFingerprints,
    ) -> Result<DurableObjectRecord, XfrmObjectInstallDurableError> {
        let lease = self.lease()?;
        let inventory = lease.inventory()?;
        let (_, record) = lease.current_from_handle(&inventory, handle)?;
        if record.object != object || !record_matches_fingerprints(record, fingerprints) {
            return Err(XfrmObjectInstallDurableError::WrongBinding);
        }
        if matches!(
            record.phase,
            XfrmObjectInstallDurablePhase::Acquired
                | XfrmObjectInstallDurablePhase::RemovalAdmitted
        ) && record.writer_epoch != lease.current_epoch(&inventory)?
        {
            return Err(XfrmObjectInstallDurableError::Stale);
        }
        Ok(record.clone())
    }

    /// Encode a live actor-validated record as an authenticated current handle.
    pub(crate) fn handle_for_record(
        &self,
        record: &DurableObjectRecord,
    ) -> Result<XfrmObjectInstallRecoveryHandle, XfrmObjectInstallDurableError> {
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
    /// preserves the current record's proof. `Acquired` already excludes every
    /// cooperating writer, so `RemovalAdmitted` is published at that same
    /// current epoch; this avoids an ambiguous half-advanced epoch crash cut
    /// before deletion.
    pub(crate) fn transition(
        &self,
        handle: &XfrmObjectInstallRecoveryHandle,
        expected: XfrmObjectInstallDurablePhase,
        next: XfrmObjectInstallDurablePhase,
        pre_effect_proof: Option<XfrmObjectInstallPreEffectProof>,
    ) -> Result<DurableObjectRecord, XfrmObjectInstallDurableError> {
        if !expected.permits(next) {
            return Err(XfrmObjectInstallDurableError::InvalidTransition);
        }
        let entering_issuing = expected == XfrmObjectInstallDurablePhase::Prepared
            && next == XfrmObjectInstallDurablePhase::Issuing;
        if entering_issuing != pre_effect_proof.is_some() {
            return Err(XfrmObjectInstallDurableError::InvalidTransition);
        }
        let lease = self.lease()?;
        let inventory = lease.inventory()?;
        let (old_name, current) = lease.current_from_handle(&inventory, handle)?;
        if current.phase != expected {
            return Err(XfrmObjectInstallDurableError::InvalidTransition);
        }
        if next == XfrmObjectInstallDurablePhase::Issuing
            && inventory.has_unresolved_writer_authority()
        {
            return Err(XfrmObjectInstallDurableError::InvalidTransition);
        }
        let current_epoch = lease.current_epoch(&inventory)?;
        if matches!(
            expected,
            XfrmObjectInstallDurablePhase::Acquired
                | XfrmObjectInstallDurablePhase::RemovalAdmitted
        ) && current.writer_epoch != current_epoch
        {
            return Err(XfrmObjectInstallDurableError::Stale);
        }
        let writer_epoch = if next == XfrmObjectInstallDurablePhase::Issuing {
            lease.advance_epoch(&inventory)?
        } else {
            current.writer_epoch
        };
        let next_record = DurableObjectRecord {
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

    /// Report whether any record keeps the writer gate closed, without
    /// mutating the store.
    ///
    /// The namespace actor uses this predicate for the cross-family
    /// cooperating-writer gate: an unresolved `Issuing`, `Indeterminate`,
    /// `Acquired`, or `RemovalAdmitted` record fences every cooperating SA
    /// relocation admission until it is finalized or recovered.
    pub(crate) fn has_unresolved_writer_authority(
        &self,
    ) -> Result<bool, XfrmObjectInstallDurableError> {
        let lease = self.lease()?;
        let inventory = lease.inventory()?;
        Ok(inventory.records.iter().any(|(_, record)| {
            matches!(
                record.phase,
                XfrmObjectInstallDurablePhase::Issuing
                    | XfrmObjectInstallDurablePhase::Indeterminate
                    | XfrmObjectInstallDurablePhase::Acquired
                    | XfrmObjectInstallDurablePhase::RemovalAdmitted
            )
        }))
    }

    /// Burn a fresh global epoch before an independently issued XFRM mutation.
    ///
    /// The actor calls this for every mutation outside the staged-object flow;
    /// even a later backend failure burns its epoch. The call is rejected while
    /// any `Issuing`, `Indeterminate`, `Acquired`, or `RemovalAdmitted`
    /// authority remains unresolved, so no cooperating replacement can race
    /// consumer bookkeeping or cleanup.
    pub(crate) fn advance_writer_epoch(&self) -> Result<NonZeroU64, XfrmObjectInstallDurableError> {
        let lease = self.lease()?;
        let mut inventory = lease.inventory()?;
        if lease.prune_terminal_records(&inventory)? {
            inventory = lease.inventory()?;
        }
        if inventory.has_unresolved_writer_authority() {
            return Err(XfrmObjectInstallDurableError::InvalidTransition);
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
    /// Recovery uses this as a fail-closed freshness predicate for
    /// `Issuing`/`Indeterminate` records: a durable anomaly that advanced or
    /// rewound the epoch underneath an unresolved record removes the proof's
    /// ordering guarantee and must be classified for repair, never deletion.
    pub(crate) fn record_writer_epoch_is_current(
        &self,
        record: &DurableObjectRecord,
    ) -> Result<bool, XfrmObjectInstallDurableError> {
        let lease = self.lease()?;
        let inventory = lease.inventory()?;
        lease.validate_record_binding(record)?;
        Ok(record.writer_epoch == lease.current_epoch(&inventory)?)
    }

    fn lease(&self) -> Result<StoreLease<'_>, XfrmObjectInstallDurableError> {
        if self.inner.owner_process_id == 0 || self.inner.owner_process_id != std::process::id() {
            return Err(XfrmObjectInstallDurableError::WrongIncarnation);
        }
        let process_guard = self
            .inner
            .process_lock
            .try_lock()
            .map_err(|error| match error {
                TryLockError::WouldBlock => XfrmObjectInstallDurableError::StoreBusy,
                TryLockError::Poisoned(_) => XfrmObjectInstallDurableError::Storage,
            })?;
        verify_visible_identity(&self.inner)?;
        Ok(StoreLease {
            store: &self.inner,
            _process_guard: process_guard,
        })
    }
}

impl fmt::Debug for XfrmObjectInstallRecoveryStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("XfrmObjectInstallRecoveryStore(<redacted>)")
    }
}

impl StoreLease<'_> {
    fn inventory(&self) -> Result<Inventory, XfrmObjectInstallDurableError> {
        verify_visible_identity(self.store)?;
        let mut control_count = 0_usize;
        let mut epochs = Vec::new();
        let mut records = Vec::new();
        let mut seen_names = BTreeMap::<String, ()>::new();
        let directory = Dir::read_from(&self.store.descriptor)
            .map_err(|_| XfrmObjectInstallDurableError::Storage)?;
        for entry in directory {
            let entry = entry.map_err(|_| XfrmObjectInstallDurableError::Storage)?;
            let raw_name = entry.file_name().to_bytes();
            if raw_name == b"." || raw_name == b".." {
                continue;
            }
            if seen_names.len() >= MAX_STORE_ENTRIES {
                return Err(XfrmObjectInstallDurableError::Malformed);
            }
            let name = std::str::from_utf8(raw_name)
                .map_err(|_| XfrmObjectInstallDurableError::Malformed)?
                .to_owned();
            if seen_names.insert(name.clone(), ()).is_some() {
                return Err(XfrmObjectInstallDurableError::Duplicate);
            }
            if name == CONTROL_NAME {
                control_count += 1;
                let encoded = read_fixed_file::<CONTROL_BYTES>(self.store, &name)?;
                let control = ControlRecord::decode(&encoded, &self.store.proof_key)?;
                if control != self.store.control {
                    return Err(XfrmObjectInstallDurableError::WrongBinding);
                }
                continue;
            }
            if name.starts_with("epoch-") {
                let expected_epoch =
                    parse_epoch_name(&name).ok_or(XfrmObjectInstallDurableError::Malformed)?;
                let encoded = read_fixed_file::<EPOCH_BYTES>(self.store, &name)?;
                let decoded = EpochRecord::decode(&encoded, &self.store.proof_key)?;
                if decoded.store_incarnation != self.store.control.store_incarnation {
                    return Err(XfrmObjectInstallDurableError::WrongBinding);
                }
                if decoded.epoch != expected_epoch || name != epoch_name(decoded.epoch) {
                    return Err(XfrmObjectInstallDurableError::Malformed);
                }
                epochs.push((name, decoded));
                continue;
            }
            let parsed = parse_record_name(OsStr::from_bytes(raw_name))
                .ok_or(XfrmObjectInstallDurableError::Malformed)?;
            let encoded =
                read_fixed_file::<XFRM_OBJECT_INSTALL_RECOVERY_HANDLE_BYTES>(self.store, &name)?;
            let record = DurableObjectRecord::decode(&encoded, &self.store.proof_key)?;
            if parsed
                != (
                    record.phase,
                    record.operation_id,
                    record.operation_generation,
                )
                || name != record_name(&record)
            {
                return Err(XfrmObjectInstallDurableError::Malformed);
            }
            self.validate_record_binding(&record)?;
            records.push((name, record));
        }
        if control_count != 1 {
            return Err(if control_count > 1 {
                XfrmObjectInstallDurableError::Duplicate
            } else {
                XfrmObjectInstallDurableError::Malformed
            });
        }
        // Decide every recovery action before removing any entry. Arbitrary
        // duplicates remain fail-closed; only the two exact adjacent states
        // that this module itself can leave between fsync and unlink are
        // completed deterministically.
        let (epoch_name, epoch, obsolete_epoch) = classify_epoch_records(epochs)?;
        let (records, obsolete_records) = classify_operation_records(records, epoch)?;
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
        })
    }

    fn validate_record_binding(
        &self,
        record: &DurableObjectRecord,
    ) -> Result<(), XfrmObjectInstallDurableError> {
        if record.store_incarnation != self.store.control.store_incarnation
            || record.namespace_seal != self.store.control.namespace_seal
        {
            return Err(XfrmObjectInstallDurableError::WrongBinding);
        }
        if record.actor_incarnation != self.store.control.actor_incarnation {
            return Err(XfrmObjectInstallDurableError::WrongIncarnation);
        }
        Ok(())
    }

    fn current_from_handle<'a>(
        &self,
        inventory: &'a Inventory,
        handle: &XfrmObjectInstallRecoveryHandle,
    ) -> Result<(&'a str, &'a DurableObjectRecord), XfrmObjectInstallDurableError> {
        let correlation = DurableObjectRecord::decode(&handle.0, &self.store.proof_key)?;
        self.validate_record_binding(&correlation)?;
        let (name, current) =
            inventory.current_for(correlation.operation_id, correlation.operation_generation)?;
        if current.object != correlation.object
            || current.store_incarnation != correlation.store_incarnation
            || current.namespace_seal != correlation.namespace_seal
            || current.actor_incarnation != correlation.actor_incarnation
            || !fingerprints_equal(
                &current.deletion_identity_fingerprint,
                &correlation.deletion_identity_fingerprint,
            )
            || !fingerprints_equal(
                &current.install_request_fingerprint,
                &correlation.install_request_fingerprint,
            )
        {
            return Err(XfrmObjectInstallDurableError::WrongBinding);
        }
        if current.phase != correlation.phase || current.writer_epoch != correlation.writer_epoch {
            return Err(XfrmObjectInstallDurableError::Stale);
        }
        Ok((name, current))
    }

    fn current_epoch(
        &self,
        inventory: &Inventory,
    ) -> Result<NonZeroU64, XfrmObjectInstallDurableError> {
        Ok(inventory.epoch)
    }

    fn publish_record(
        &self,
        record: &DurableObjectRecord,
    ) -> Result<(), XfrmObjectInstallDurableError> {
        self.validate_record_binding(record)?;
        let name = record_name(record);
        let bytes = record.encode(&self.store.proof_key)?;
        publish_new_file(self.store, &name, &bytes)
    }

    fn advance_epoch(
        &self,
        inventory: &Inventory,
    ) -> Result<NonZeroU64, XfrmObjectInstallDurableError> {
        let epoch = inventory
            .epoch
            .get()
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .ok_or(XfrmObjectInstallDurableError::Stale)?;
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
    ) -> Result<bool, XfrmObjectInstallDurableError> {
        let names = inventory
            .records
            .iter()
            .filter(|(_, record)| {
                matches!(
                    record.phase,
                    XfrmObjectInstallDurablePhase::Retired
                        | XfrmObjectInstallDurablePhase::Committed
                )
            })
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        for name in &names {
            self.remove_record(name)?;
        }
        Ok(!names.is_empty())
    }

    fn remove_epoch(&self, name: &str) -> Result<(), XfrmObjectInstallDurableError> {
        parse_epoch_name(name).ok_or(XfrmObjectInstallDurableError::Malformed)?;
        unlinkat(self.store.descriptor.as_fd(), name, AtFlags::empty())
            .map_err(|_| XfrmObjectInstallDurableError::Storage)?;
        fsync(&self.store.descriptor).map_err(|_| XfrmObjectInstallDurableError::Storage)?;
        Ok(())
    }

    fn remove_record(&self, name: &str) -> Result<(), XfrmObjectInstallDurableError> {
        validate_record_name(OsStr::new(name))?;
        unlinkat(self.store.descriptor.as_fd(), name, AtFlags::empty())
            .map_err(|_| XfrmObjectInstallDurableError::Storage)?;
        fsync(&self.store.descriptor).map_err(|_| XfrmObjectInstallDurableError::Storage)?;
        Ok(())
    }
}

fn classify_epoch_records(
    mut epochs: Vec<(String, EpochRecord)>,
) -> Result<(String, NonZeroU64, Option<String>), XfrmObjectInstallDurableError> {
    match epochs.len() {
        0 => Err(XfrmObjectInstallDurableError::Malformed),
        1 => {
            let (name, record) = epochs
                .pop()
                .ok_or(XfrmObjectInstallDurableError::Malformed)?;
            Ok((name, record.epoch, None))
        }
        2 => {
            epochs.sort_by_key(|(_, record)| record.epoch);
            let (lower_name, lower) = epochs.remove(0);
            let (upper_name, upper) = epochs.remove(0);
            if lower.store_incarnation != upper.store_incarnation
                || lower.epoch.get().checked_add(1) != Some(upper.epoch.get())
            {
                return Err(XfrmObjectInstallDurableError::Duplicate);
            }
            Ok((upper_name, upper.epoch, Some(lower_name)))
        }
        _ => Err(XfrmObjectInstallDurableError::Duplicate),
    }
}

fn classify_operation_records(
    records: Vec<NamedDurableRecord>,
    current_epoch: NonZeroU64,
) -> Result<ReconciledOperationRecords, XfrmObjectInstallDurableError> {
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
            1 => current.push(
                group
                    .pop()
                    .ok_or(XfrmObjectInstallDurableError::Malformed)?,
            ),
            2 => {
                let right = group
                    .pop()
                    .ok_or(XfrmObjectInstallDurableError::Duplicate)?;
                let left = group
                    .pop()
                    .ok_or(XfrmObjectInstallDurableError::Duplicate)?;
                let (old, next) =
                    if is_exact_publication_successor(&left.1, &right.1, current_epoch) {
                        (left, right)
                    } else if is_exact_publication_successor(&right.1, &left.1, current_epoch) {
                        (right, left)
                    } else {
                        return Err(XfrmObjectInstallDurableError::Duplicate);
                    };
                obsolete.push(old.0);
                current.push(next);
            }
            _ => return Err(XfrmObjectInstallDurableError::Duplicate),
        }
    }
    Ok((current, obsolete))
}

fn validate_unique_active_deletion_identities(
    records: &[NamedDurableRecord],
) -> Result<(), XfrmObjectInstallDurableError> {
    for (index, (_, left)) in records.iter().enumerate() {
        if matches!(
            left.phase,
            XfrmObjectInstallDurablePhase::Retired | XfrmObjectInstallDurablePhase::Committed
        ) {
            continue;
        }
        if records[index + 1..].iter().any(|(_, right)| {
            !matches!(
                right.phase,
                XfrmObjectInstallDurablePhase::Retired | XfrmObjectInstallDurablePhase::Committed
            ) && fingerprints_equal(
                &left.deletion_identity_fingerprint,
                &right.deletion_identity_fingerprint,
            )
        }) {
            return Err(XfrmObjectInstallDurableError::Duplicate);
        }
    }
    Ok(())
}

fn validate_single_cleanup_authority(
    records: &[NamedDurableRecord],
) -> Result<(), XfrmObjectInstallDurableError> {
    if records
        .iter()
        .filter(|(_, record)| {
            matches!(
                record.phase,
                XfrmObjectInstallDurablePhase::Issuing
                    | XfrmObjectInstallDurablePhase::Indeterminate
                    | XfrmObjectInstallDurablePhase::Acquired
                    | XfrmObjectInstallDurablePhase::RemovalAdmitted
            )
        })
        .take(2)
        .count()
        > 1
    {
        return Err(XfrmObjectInstallDurableError::Duplicate);
    }
    Ok(())
}

fn is_exact_publication_successor(
    old: &DurableObjectRecord,
    next: &DurableObjectRecord,
    current_epoch: NonZeroU64,
) -> bool {
    if !old.phase.permits(next.phase)
        || old.object != next.object
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
            &old.install_request_fingerprint,
            &next.install_request_fingerprint,
        )
    {
        return false;
    }
    // Only `Prepared -> Issuing` witnesses the pre-effect proof; every other
    // transition preserves it. A successor that invents or drops a proof on
    // any other edge is not an exact publication of this state machine.
    let entering_issuing = old.phase == XfrmObjectInstallDurablePhase::Prepared
        && next.phase == XfrmObjectInstallDurablePhase::Issuing;
    let proof_ok = if entering_issuing {
        old.pre_effect_proof.is_none() && next.pre_effect_proof.is_some()
    } else {
        old.pre_effect_proof == next.pre_effect_proof
    };
    if !proof_ok {
        return false;
    }
    if next.phase == XfrmObjectInstallDurablePhase::Issuing {
        next.writer_epoch == current_epoch && next.writer_epoch > old.writer_epoch
    } else {
        next.writer_epoch == old.writer_epoch
    }
}

fn create_root_if_absent(path: &Path) -> Result<(), XfrmObjectInstallDurableError> {
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(DIRECTORY_MODE);
    match builder.create(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(_) => Err(XfrmObjectInstallDurableError::Storage),
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

fn sync_store_root_parent(
    path: &Path,
    root: &OwnedFd,
) -> Result<(), XfrmObjectInstallDurableError> {
    let parent = path
        .parent()
        .ok_or(XfrmObjectInstallDurableError::InvalidStoreRoot)?;
    let child_name = path
        .file_name()
        .ok_or(XfrmObjectInstallDurableError::InvalidStoreRoot)?;
    let parent_descriptor = open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(map_root_open_error)?;
    let parent_metadata =
        fstat(&parent_descriptor).map_err(|_| XfrmObjectInstallDurableError::Storage)?;
    let parent_is_untrusted_writable =
        parent_metadata.st_mode & 0o022 != 0 && parent_metadata.st_mode & 0o1000 == 0;
    if !FileType::from_raw_mode(parent_metadata.st_mode).is_dir()
        || parent_metadata.st_nlink == 0
        || parent_is_untrusted_writable
    {
        return Err(XfrmObjectInstallDurableError::InvalidStoreRoot);
    }

    let reopened = openat(
        parent_descriptor.as_fd(),
        child_name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(map_root_open_error)?;
    let expected = fstat(root).map_err(|_| XfrmObjectInstallDurableError::Storage)?;
    let observed = fstat(&reopened).map_err(|_| XfrmObjectInstallDurableError::Storage)?;
    validate_root_metadata(&observed)?;
    if expected.st_dev != observed.st_dev || expected.st_ino != observed.st_ino {
        return Err(XfrmObjectInstallDurableError::InvalidStoreRoot);
    }
    fsync(&parent_descriptor).map_err(|_| XfrmObjectInstallDurableError::Storage)
}

fn validate_root_metadata(
    metadata: &rustix::fs::Stat,
) -> Result<(), XfrmObjectInstallDurableError> {
    if !FileType::from_raw_mode(metadata.st_mode).is_dir()
        || metadata.st_uid != rustix::process::geteuid().as_raw()
        || metadata.st_mode.store_permissions() != DIRECTORY_MODE
        || metadata.st_nlink == 0
    {
        return Err(XfrmObjectInstallDurableError::InvalidStoreRoot);
    }
    Ok(())
}

fn stat_device(metadata: &rustix::fs::Stat) -> Result<u64, XfrmObjectInstallDurableError> {
    metadata
        .st_dev
        .store_identity()
        .ok_or(XfrmObjectInstallDurableError::InvalidStoreRoot)
}

fn stat_inode(metadata: &rustix::fs::Stat) -> Result<u64, XfrmObjectInstallDurableError> {
    metadata
        .st_ino
        .store_identity()
        .ok_or(XfrmObjectInstallDurableError::InvalidStoreRoot)
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

fn map_root_open_error(error: rustix::io::Errno) -> XfrmObjectInstallDurableError {
    if matches!(error, rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) {
        XfrmObjectInstallDurableError::InvalidStoreRoot
    } else {
        XfrmObjectInstallDurableError::Storage
    }
}

fn verify_visible_identity(store: &StoreInner) -> Result<(), XfrmObjectInstallDurableError> {
    if store.owner_process_id != std::process::id() {
        return Err(XfrmObjectInstallDurableError::WrongIncarnation);
    }
    let visible = open(
        &store.visible_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(map_root_open_error)?;
    let metadata = fstat(&visible).map_err(|_| XfrmObjectInstallDurableError::Storage)?;
    validate_root_metadata(&metadata)?;
    if stat_device(&metadata)? != store.root_device
        || stat_inode(&metadata)? != store.root_inode
        || metadata.st_uid != store.root_owner
    {
        return Err(XfrmObjectInstallDurableError::InvalidStoreRoot);
    }
    Ok(())
}

fn initialize_or_load_control(
    store: &StoreInner,
    namespace_seal: [u8; 32],
) -> Result<ControlRecord, XfrmObjectInstallDurableError> {
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
            epoch: NonZeroU64::new(1).ok_or(XfrmObjectInstallDurableError::Malformed)?,
        };
        publish_new_file(
            store,
            &epoch_name(epoch.epoch),
            &epoch.encode(&store.proof_key)?,
        )?;
        return Ok(control);
    }
    if !names.iter().any(|name| name == CONTROL_NAME) {
        return Err(XfrmObjectInstallDurableError::Malformed);
    }
    let encoded = read_fixed_file::<CONTROL_BYTES>(store, CONTROL_NAME)?;
    let control = ControlRecord::decode(&encoded, &store.proof_key)?;
    if control.namespace_seal != namespace_seal
        || control.root_device != store.root_device
        || control.root_inode != store.root_inode
    {
        return Err(XfrmObjectInstallDurableError::WrongBinding);
    }
    // First initialization publishes `control` before epoch 1. A process loss
    // between those two fsyncs leaves this one exact, authenticated safe
    // residue. No mutation can have been admitted yet, so completing epoch 1
    // is deterministic. Any additional or different entry remains fail-closed
    // in the bounded inventory scan.
    if names.len() == 1 {
        let epoch = EpochRecord {
            store_incarnation: control.store_incarnation,
            epoch: NonZeroU64::new(1).ok_or(XfrmObjectInstallDurableError::Malformed)?,
        };
        publish_new_file(
            store,
            &epoch_name(epoch.epoch),
            &epoch.encode(&store.proof_key)?,
        )?;
    }
    Ok(control)
}

fn scan_raw_names(store: &StoreInner) -> Result<Vec<String>, XfrmObjectInstallDurableError> {
    let directory =
        Dir::read_from(&store.descriptor).map_err(|_| XfrmObjectInstallDurableError::Storage)?;
    let mut names = Vec::new();
    for entry in directory {
        let entry = entry.map_err(|_| XfrmObjectInstallDurableError::Storage)?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        if names.len() >= MAX_STORE_ENTRIES {
            return Err(XfrmObjectInstallDurableError::Malformed);
        }
        names.push(
            std::str::from_utf8(name)
                .map_err(|_| XfrmObjectInstallDurableError::Malformed)?
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
) -> Result<(), XfrmObjectInstallDurableError> {
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
        .map_err(|_| XfrmObjectInstallDurableError::Malformed)?;
        let metadata = fstat(&descriptor).map_err(|_| XfrmObjectInstallDurableError::Storage)?;
        if !FileType::from_raw_mode(metadata.st_mode).is_file()
            || stat_device(&metadata)? != store.root_device
            || metadata.st_uid != store.root_owner
            || metadata.st_mode.store_permissions() != FILE_MODE
            || metadata.st_nlink != 1
            || metadata.st_size < 0
            || metadata.st_size > XFRM_OBJECT_INSTALL_RECOVERY_HANDLE_BYTES as i64
        {
            return Err(XfrmObjectInstallDurableError::Malformed);
        }
        unlinkat(store.descriptor.as_fd(), name.as_str(), AtFlags::empty())
            .map_err(|_| XfrmObjectInstallDurableError::Storage)?;
        removed = true;
    }
    if removed {
        fsync(&store.descriptor).map_err(|_| XfrmObjectInstallDurableError::Storage)?;
    }
    Ok(())
}

fn read_fixed_file<const N: usize>(
    store: &StoreInner,
    name: &str,
) -> Result<[u8; N], XfrmObjectInstallDurableError> {
    let descriptor = openat(
        store.descriptor.as_fd(),
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| XfrmObjectInstallDurableError::Malformed)?;
    validate_file_metadata(store, &descriptor, N)?;
    let mut file = std::fs::File::from(descriptor);
    let mut bytes = [0_u8; N];
    file.read_exact(&mut bytes)
        .map_err(|_| XfrmObjectInstallDurableError::Malformed)?;
    let mut trailing = [0_u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|_| XfrmObjectInstallDurableError::Storage)?
        != 0
    {
        return Err(XfrmObjectInstallDurableError::Malformed);
    }
    Ok(bytes)
}

fn validate_file_metadata(
    store: &StoreInner,
    descriptor: &OwnedFd,
    expected_size: usize,
) -> Result<(), XfrmObjectInstallDurableError> {
    let metadata = fstat(descriptor).map_err(|_| XfrmObjectInstallDurableError::Storage)?;
    if !FileType::from_raw_mode(metadata.st_mode).is_file()
        || stat_device(&metadata)? != store.root_device
        || metadata.st_uid != store.root_owner
        || metadata.st_mode.store_permissions() != FILE_MODE
        || metadata.st_nlink != 1
        || metadata.st_size != expected_size as i64
    {
        return Err(XfrmObjectInstallDurableError::Malformed);
    }
    Ok(())
}

fn publish_new_file(
    store: &StoreInner,
    target: &str,
    bytes: &[u8],
) -> Result<(), XfrmObjectInstallDurableError> {
    #[cfg(not(target_os = "linux"))]
    {
        // The public atomic constructor is unavailable before this point on a
        // non-Linux host. Keep the crate's established portable model and
        // unsupported backend buildable without pretending that another OS
        // provides Linux renameat2(RENAME_NOREPLACE) crash semantics.
        let _ = (store, target, bytes);
        Err(XfrmObjectInstallDurableError::Storage)
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
                Err(_) => return Err(XfrmObjectInstallDurableError::Storage),
            };
            let mut file = std::fs::File::from(descriptor);
            if file.write_all(bytes).is_err() || file.sync_all().is_err() {
                let _ = unlinkat(
                    store.descriptor.as_fd(),
                    temporary.as_str(),
                    AtFlags::empty(),
                );
                return Err(XfrmObjectInstallDurableError::Storage);
            }
            let staged_metadata =
                fstat(&file).map_err(|_| XfrmObjectInstallDurableError::Storage)?;
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
                return Err(XfrmObjectInstallDurableError::Storage);
            }
            match renameat_with(
                store.descriptor.as_fd(),
                temporary.as_str(),
                store.descriptor.as_fd(),
                target,
                RenameFlags::NOREPLACE,
            ) {
                Ok(()) => {
                    fsync(&store.descriptor).map_err(|_| XfrmObjectInstallDurableError::Storage)?;
                    let reopened = openat(
                        store.descriptor.as_fd(),
                        target,
                        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(|_| XfrmObjectInstallDurableError::Storage)?;
                    validate_file_metadata(store, &reopened, bytes.len())?;
                    let published_metadata =
                        fstat(&reopened).map_err(|_| XfrmObjectInstallDurableError::Storage)?;
                    if published_metadata.st_dev != staged_metadata.st_dev
                        || published_metadata.st_ino != staged_metadata.st_ino
                    {
                        return Err(XfrmObjectInstallDurableError::Storage);
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
                        XfrmObjectInstallDurableError::Duplicate
                    } else {
                        XfrmObjectInstallDurableError::Storage
                    });
                }
            }
        }
        Err(XfrmObjectInstallDurableError::EntropyUnavailable)
    }
}

fn random_nonzero_16() -> Result<[u8; 16], XfrmObjectInstallDurableError> {
    for _ in 0..CREATE_ATTEMPTS {
        let mut bytes = [0_u8; 16];
        SysRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| XfrmObjectInstallDurableError::EntropyUnavailable)?;
        if bytes.iter().any(|byte| *byte != 0) {
            return Ok(bytes);
        }
    }
    Err(XfrmObjectInstallDurableError::EntropyUnavailable)
}

#[cfg(target_os = "linux")]
fn temporary_name() -> Result<String, XfrmObjectInstallDurableError> {
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

fn namespace_seal(key: &XfrmObjectRecoveryProofKey, binding: [u8; 40]) -> [u8; 32] {
    authenticate_domain(key.canonical_mac_key(), NAMESPACE_AUTH_DOMAIN, &binding)
}

fn map_canonical_encode_error(error: CanonicalEncodeError) -> XfrmObjectInstallDurableError {
    match error {
        CanonicalEncodeError::CapacityExceeded => XfrmObjectInstallDurableError::CapacityExceeded,
        CanonicalEncodeError::Malformed => XfrmObjectInstallDurableError::Malformed,
    }
}

/// Compute the domain-separated keyed fingerprint of one complete install
/// request.
///
/// The encoding is length-prefixed and covers every field the backend would
/// send, so two requests that differ anywhere produce different fingerprints.
/// The `domain` argument keeps sibling record families separate even when a
/// deployment configures the same key bytes for both.
///
/// # Errors
///
/// Returns [`CanonicalEncodeError::CapacityExceeded`] when a variable-length
/// field exceeds the bounded canonical encoding.
pub(crate) fn authenticate_install_request(
    key: CanonicalMacKey<'_>,
    domain: &[u8],
    request: &XfrmObjectInstallRequest,
) -> Result<[u8; AUTH_TAG_BYTES], CanonicalEncodeError> {
    let mut mac = key.begin(domain);
    match request {
        XfrmObjectInstallRequest::Sa(request) => {
            mac_u8(&mut mac, 1);
            let parameters = &request.parameters;
            mac_selector(&mut mac, &parameters.selector);
            mac_id(&mut mac, parameters.id);
            mac_ip_address(&mut mac, parameters.source_address);
            mac_request_id(&mut mac, parameters.request_id);
            match &parameters.auth {
                Some((algorithm, key)) => {
                    mac_u8(&mut mac, 1);
                    mac_bytes(&mut mac, algorithm.name.as_bytes())?;
                    mac_u32(&mut mac, algorithm.truncation_len_bits);
                    mac_bytes(&mut mac, key.as_bytes())?;
                }
                None => mac_u8(&mut mac, 0),
            }
            match &parameters.crypt {
                Some((algorithm, key)) => {
                    mac_u8(&mut mac, 1);
                    mac_bytes(&mut mac, algorithm.name.as_bytes())?;
                    mac_bytes(&mut mac, key.as_bytes())?;
                }
                None => mac_u8(&mut mac, 0),
            }
            match &parameters.aead {
                Some((algorithm, key)) => {
                    mac_u8(&mut mac, 1);
                    mac_bytes(&mut mac, algorithm.name.as_bytes())?;
                    mac_u32(&mut mac, algorithm.icv_len_bits);
                    mac_bytes(&mut mac, key.as_bytes())?;
                }
                None => mac_u8(&mut mac, 0),
            }
            mac_mode(&mut mac, parameters.mode);
            mac_lifetime(&mut mac, parameters.lifetime);
            mac_u32(&mut mac, parameters.replay_window);
            mac_replay_state(&mut mac, parameters.replay_state.as_ref())?;
            mac_encap(&mut mac, parameters.encap);
            mac_lookup_mark(&mut mac, parameters.mark);
            mac_output_mark(&mut mac, parameters.output_mark);
            mac_optional_u32(&mut mac, parameters.if_id);
            match parameters.egress_dscp {
                Some(dscp) => {
                    mac_u8(&mut mac, 1);
                    mac_u8(&mut mac, dscp.get());
                }
                None => mac_u8(&mut mac, 0),
            }
        }
        XfrmObjectInstallRequest::Policy(request) => {
            mac_u8(&mut mac, 2);
            let parameters = &request.parameters;
            mac_selector(&mut mac, &parameters.selector);
            mac_direction(&mut mac, parameters.direction);
            mac_action(&mut mac, parameters.action);
            mac_u32(&mut mac, parameters.priority);
            mac_u64(
                &mut mac,
                u64::try_from(parameters.templates.len())
                    .map_err(|_| CanonicalEncodeError::CapacityExceeded)?,
            );
            for template in &parameters.templates {
                mac_template(&mut mac, *template);
            }
            mac_lookup_mark(&mut mac, parameters.mark);
            mac_optional_u32(&mut mac, parameters.if_id);
        }
    }
    Ok(*mac.finalize())
}

/// Absorb one length-prefixed byte string.
///
/// # Errors
///
/// Returns [`CanonicalEncodeError::CapacityExceeded`] when the length cannot be
/// represented in the fixed-width prefix.
pub(crate) fn mac_bytes(mac: &mut HmacSha256, bytes: &[u8]) -> Result<(), CanonicalEncodeError> {
    mac_u64(
        mac,
        u64::try_from(bytes.len()).map_err(|_| CanonicalEncodeError::CapacityExceeded)?,
    );
    mac.update(bytes);
    Ok(())
}

/// Absorb one unsigned byte.
pub(crate) fn mac_u8(mac: &mut HmacSha256, value: u8) {
    mac.update(&[value]);
}

/// Absorb one big-endian 16-bit value.
pub(crate) fn mac_u16(mac: &mut HmacSha256, value: u16) {
    mac.update(&value.to_be_bytes());
}

/// Absorb one big-endian 32-bit value.
pub(crate) fn mac_u32(mac: &mut HmacSha256, value: u32) {
    mac.update(&value.to_be_bytes());
}

/// Absorb one big-endian 64-bit value.
pub(crate) fn mac_u64(mac: &mut HmacSha256, value: u64) {
    mac.update(&value.to_be_bytes());
}

/// Absorb one address with its family discriminant.
pub(crate) fn mac_ip_address(mac: &mut HmacSha256, address: IpAddress) {
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

/// Absorb one traffic selector.
pub(crate) fn mac_selector(mac: &mut HmacSha256, selector: &XfrmSelector) {
    mac_ip_address(mac, selector.source);
    mac_ip_address(mac, selector.destination);
    mac_u16(mac, selector.source_port);
    mac_u16(mac, selector.destination_port);
    mac_u8(mac, selector.protocol);
    mac_u8(mac, selector.source_prefix_len);
    mac_u8(mac, selector.destination_prefix_len);
}

/// Absorb one exact XFRM identity triple.
pub(crate) fn mac_id(mac: &mut HmacSha256, id: XfrmId) {
    mac_ip_address(mac, id.destination);
    mac_u32(mac, id.spi);
    mac_u8(mac, id.protocol);
}

/// Absorb one optional request identifier.
pub(crate) fn mac_request_id(mac: &mut HmacSha256, request_id: Option<XfrmRequestId>) {
    mac_optional_u32(mac, request_id.map(XfrmRequestId::get));
}

/// Absorb one optional 32-bit value with its presence discriminant.
pub(crate) fn mac_optional_u32(mac: &mut HmacSha256, value: Option<u32>) {
    match value {
        Some(value) => {
            mac_u8(mac, 1);
            mac_u32(mac, value);
        }
        None => mac_u8(mac, 0),
    }
}

/// Absorb one transform mode.
pub(crate) fn mac_mode(mac: &mut HmacSha256, mode: XfrmMode) {
    mac_u8(
        mac,
        match mode {
            XfrmMode::Transport => 1,
            XfrmMode::Tunnel => 2,
            XfrmMode::Beet => 3,
        },
    );
}

/// Absorb one policy direction.
pub(crate) fn mac_direction(mac: &mut HmacSha256, direction: XfrmDirection) {
    mac_u8(
        mac,
        match direction {
            XfrmDirection::In => 1,
            XfrmDirection::Out => 2,
            XfrmDirection::Forward => 3,
        },
    );
}

/// Absorb one policy action.
pub(crate) fn mac_action(mac: &mut HmacSha256, action: XfrmAction) {
    mac_u8(
        mac,
        match action {
            XfrmAction::Allow => 1,
            XfrmAction::Block => 2,
        },
    );
}

/// Absorb one complete lifetime configuration.
pub(crate) fn mac_lifetime(mac: &mut HmacSha256, lifetime: LifetimeConfig) {
    mac_u64(mac, lifetime.soft_byte_limit);
    mac_u64(mac, lifetime.hard_byte_limit);
    mac_u64(mac, lifetime.soft_packet_limit);
    mac_u64(mac, lifetime.hard_packet_limit);
    mac_u64(mac, lifetime.soft_add_expires_seconds);
    mac_u64(mac, lifetime.hard_add_expires_seconds);
}

/// Absorb one optional replay state including its bitmap.
///
/// # Errors
///
/// Returns [`CanonicalEncodeError::CapacityExceeded`] when the bitmap length
/// cannot be represented in the fixed-width prefix.
pub(crate) fn mac_replay_state(
    mac: &mut HmacSha256,
    state: Option<&SaReplayState>,
) -> Result<(), CanonicalEncodeError> {
    let Some(state) = state else {
        mac_u8(mac, 0);
        return Ok(());
    };
    mac_u8(mac, 1);
    mac_u8(mac, u8::from(state.esn));
    mac_u32(mac, state.outbound_sequence);
    mac_u32(mac, state.inbound_sequence);
    mac_u32(mac, state.outbound_sequence_hi);
    mac_u32(mac, state.inbound_sequence_hi);
    mac_u32(mac, state.replay_window);
    mac_u64(
        mac,
        u64::try_from(state.bitmap.len()).map_err(|_| CanonicalEncodeError::CapacityExceeded)?,
    );
    for word in &state.bitmap {
        mac_u32(mac, *word);
    }
    Ok(())
}

/// Absorb one optional UDP encapsulation descriptor.
pub(crate) fn mac_encap(mac: &mut HmacSha256, encap: Option<UdpEncap>) {
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

/// Absorb one optional lookup mark.
pub(crate) fn mac_lookup_mark(mac: &mut HmacSha256, mark: Option<XfrmLookupMark>) {
    match mark {
        Some(mark) => {
            mac_u8(mac, 1);
            mac_u32(mac, mark.value());
            mac_u32(mac, mark.mask());
        }
        None => mac_u8(mac, 0),
    }
}

/// Absorb one optional post-transform output mark.
pub(crate) fn mac_output_mark(mac: &mut HmacSha256, mark: Option<XfrmMark>) {
    match mark {
        Some(mark) => {
            mac_u8(mac, 1);
            mac_u32(mac, mark.value);
            mac_u32(mac, mark.mask);
        }
        None => mac_u8(mac, 0),
    }
}

/// Absorb one policy template.
pub(crate) fn mac_template(mac: &mut HmacSha256, template: XfrmTemplate) {
    mac_id(mac, template.id);
    mac_ip_address(mac, template.source_address);
    mac_request_id(mac, template.request_id);
    mac_mode(mac, template.mode);
}

/// Compute the domain-separated keyed fingerprint of one exact kernel deletion
/// identity.
///
/// The canonical plaintext exists only in a zeroizing buffer for the duration
/// of the call; the caller receives the tag alone. `policy_if_id` must already
/// be canonicalized, so an encoded zero arrives as `None`.
///
/// # Errors
///
/// Returns [`CanonicalEncodeError::Malformed`] when the removal request cannot
/// produce an exact canonical identity.
pub(crate) fn authenticate_deletion_identity(
    key: CanonicalMacKey<'_>,
    domain: &[u8],
    removal: &XfrmObjectRemovalRequest,
    policy_if_id: Option<u32>,
) -> Result<[u8; AUTH_TAG_BYTES], CanonicalEncodeError> {
    let mut canonical = Zeroizing::new([0_u8; 64]);
    let length = encode_deletion_identity(removal, policy_if_id, &mut canonical)?;
    Ok(authenticate_domain(key, domain, &canonical[..length]))
}

fn encode_deletion_identity(
    removal: &XfrmObjectRemovalRequest,
    policy_if_id: Option<u32>,
    output: &mut [u8; 64],
) -> Result<usize, CanonicalEncodeError> {
    let mut cursor = 0_usize;
    match removal {
        XfrmObjectRemovalRequest::Sa(request) => {
            if policy_if_id.is_some() {
                return Err(CanonicalEncodeError::Malformed);
            }
            output[cursor] = 1;
            cursor += 1;
            encode_sa_identity(request, output, &mut cursor);
        }
        XfrmObjectRemovalRequest::Policy(request) => {
            output[cursor] = 2;
            cursor += 1;
            encode_policy_identity(request, policy_if_id, output, &mut cursor)?;
        }
    }
    Ok(cursor)
}

fn encode_sa_identity(request: &RemoveSaRequest, output: &mut [u8; 64], cursor: &mut usize) {
    encode_ip_address(request.destination, output, cursor);
    output[*cursor] = request.protocol;
    *cursor += 1;
    push_bytes(output, cursor, &request.spi.to_be_bytes());
    encode_mark(request.mark, output, cursor);
}

fn encode_policy_identity(
    request: &RemovePolicyRequest,
    if_id: Option<u32>,
    output: &mut [u8; 64],
    cursor: &mut usize,
) -> Result<(), CanonicalEncodeError> {
    encode_selector(&request.selector, output, cursor);
    output[*cursor] = match request.direction {
        XfrmDirection::In => 1,
        XfrmDirection::Out => 2,
        XfrmDirection::Forward => 3,
    };
    *cursor += 1;
    encode_mark(request.mark, output, cursor);
    match if_id {
        Some(value) if value != 0 => {
            output[*cursor] = 1;
            *cursor += 1;
            push_bytes(output, cursor, &value.to_be_bytes());
        }
        Some(_) => return Err(CanonicalEncodeError::Malformed),
        None => {
            output[*cursor] = 0;
            *cursor += 1;
            push_bytes(output, cursor, &[0; 4]);
        }
    }
    Ok(())
}

fn encode_selector(selector: &XfrmSelector, output: &mut [u8; 64], cursor: &mut usize) {
    encode_ip_address(selector.source, output, cursor);
    encode_ip_address(selector.destination, output, cursor);
    push_bytes(output, cursor, &selector.source_port.to_be_bytes());
    push_bytes(output, cursor, &selector.destination_port.to_be_bytes());
    output[*cursor] = selector.protocol;
    *cursor += 1;
    output[*cursor] = selector.source_prefix_len;
    *cursor += 1;
    output[*cursor] = selector.destination_prefix_len;
    *cursor += 1;
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

fn encode_mark(mark: Option<crate::XfrmLookupMark>, output: &mut [u8; 64], cursor: &mut usize) {
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

fn record_name(record: &DurableObjectRecord) -> String {
    format!(
        "{}-{}-{:016x}",
        record.phase.as_str(),
        encode_hex(&record.operation_id.0),
        record.operation_generation.get()
    )
}

fn validate_record_name(name: &OsStr) -> Result<(), XfrmObjectInstallDurableError> {
    parse_record_name(name)
        .map(|_| ())
        .ok_or(XfrmObjectInstallDurableError::Malformed)
}

fn parse_record_name(
    name: &OsStr,
) -> Option<(
    XfrmObjectInstallDurablePhase,
    XfrmObjectInstallOperationId,
    XfrmObjectInstallOperationGeneration,
)> {
    let text = name.to_str()?;
    let mut components = text.rsplitn(3, '-');
    let generation = u64::from_str_radix(components.next()?, 16).ok()?;
    let operation = decode_hex_16(components.next()?)?;
    let phase = match components.next()? {
        "prepared" => XfrmObjectInstallDurablePhase::Prepared,
        "issuing" => XfrmObjectInstallDurablePhase::Issuing,
        "acquired" => XfrmObjectInstallDurablePhase::Acquired,
        "no_mutation" => XfrmObjectInstallDurablePhase::NoMutation,
        "indeterminate" => XfrmObjectInstallDurablePhase::Indeterminate,
        "removal_admitted" => XfrmObjectInstallDurablePhase::RemovalAdmitted,
        "retired" => XfrmObjectInstallDurablePhase::Retired,
        "committed" => XfrmObjectInstallDurablePhase::Committed,
        _ => return None,
    };
    Some((
        phase,
        XfrmObjectInstallOperationId::from_bytes(operation).ok()?,
        XfrmObjectInstallOperationGeneration::new(generation)?,
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

    use rustix::fs::{mkfifoat, CWD};

    use crate::{IpAddress, RemovePolicyRequest, RemoveSaRequest, XfrmLookupMark, XfrmSelector};

    use super::*;

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let identity = XfrmObjectInstallOperationId::generate().unwrap();
            let path = std::env::temp_dir().join(format!(
                "opc-xfrm-durable-object-test-{}",
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

    fn key(byte: u8) -> XfrmObjectRecoveryProofKey {
        XfrmObjectRecoveryProofKey::new([byte; 32]).unwrap()
    }

    fn record(phase: XfrmObjectInstallDurablePhase) -> DurableObjectRecord {
        DurableObjectRecord {
            phase,
            object: XfrmInstallObject::Policy,
            pre_effect_proof: valid_proof_for(phase),
            store_incarnation: [1; 16],
            namespace_seal: [2; 32],
            actor_incarnation: [3; 16],
            operation_id: XfrmObjectInstallOperationId::from_bytes([4; 16]).unwrap(),
            operation_generation: XfrmObjectInstallOperationGeneration::new(5).unwrap(),
            writer_epoch: NonZeroU64::new(6).unwrap(),
            deletion_identity_fingerprint: [7; 32],
            install_request_fingerprint: [8; 32],
        }
    }

    fn valid_proof_for(
        phase: XfrmObjectInstallDurablePhase,
    ) -> Option<XfrmObjectInstallPreEffectProof> {
        match phase {
            XfrmObjectInstallDurablePhase::Prepared => None,
            XfrmObjectInstallDurablePhase::Retired => None,
            _ => Some(XfrmObjectInstallPreEffectProof::Absent),
        }
    }

    fn store(root: &TestRoot) -> XfrmObjectInstallRecoveryStore {
        XfrmObjectInstallRecoveryStore::open_bound(root.path(), key(9), [0x42; 40]).unwrap()
    }

    fn proof_for(
        expected: XfrmObjectInstallDurablePhase,
        next: XfrmObjectInstallDurablePhase,
    ) -> Option<XfrmObjectInstallPreEffectProof> {
        if expected == XfrmObjectInstallDurablePhase::Prepared
            && next == XfrmObjectInstallDurablePhase::Issuing
        {
            Some(XfrmObjectInstallPreEffectProof::Absent)
        } else {
            None
        }
    }

    fn next_handle(
        store: &XfrmObjectInstallRecoveryStore,
        current: &XfrmObjectInstallRecoveryHandle,
        expected: XfrmObjectInstallDurablePhase,
        next: XfrmObjectInstallDurablePhase,
    ) -> XfrmObjectInstallRecoveryHandle {
        store
            .transition(current, expected, next, proof_for(expected, next))
            .unwrap()
            .handle(&store.inner.proof_key)
            .unwrap()
    }

    #[test]
    fn record_codec_round_trips_every_phase_and_object() {
        for phase in [
            XfrmObjectInstallDurablePhase::Prepared,
            XfrmObjectInstallDurablePhase::Issuing,
            XfrmObjectInstallDurablePhase::Acquired,
            XfrmObjectInstallDurablePhase::NoMutation,
            XfrmObjectInstallDurablePhase::Indeterminate,
            XfrmObjectInstallDurablePhase::RemovalAdmitted,
            XfrmObjectInstallDurablePhase::Retired,
            XfrmObjectInstallDurablePhase::Committed,
        ] {
            for object in [XfrmInstallObject::Sa, XfrmInstallObject::Policy] {
                let mut expected = record(phase);
                expected.object = object;
                let encoded = expected.encode(&key(9)).unwrap();
                assert_eq!(encoded.len(), XFRM_OBJECT_INSTALL_RECOVERY_HANDLE_BYTES);
                assert_eq!(
                    DurableObjectRecord::decode(&encoded, &key(9)).unwrap(),
                    expected
                );
                let handle = XfrmObjectInstallRecoveryHandle::from_bytes(encoded);
                assert_eq!(handle.to_bytes(), encoded);
            }
        }
    }

    /// Fixed SA install request for the object family's golden vectors.
    fn golden_sa_request() -> XfrmObjectInstallRequest {
        XfrmObjectInstallRequest::Sa(crate::InstallSaRequest {
            parameters: crate::SaParameters {
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
                    crate::AuthAlgorithm::hmac_sha256(96),
                    crate::KeyMaterial::new(vec![0xab; 32]),
                )),
                crypt: Some((
                    crate::Algorithm::cbc_aes(),
                    crate::KeyMaterial::new(vec![0xcd; 32]),
                )),
                aead: None,
                mode: XfrmMode::Tunnel,
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

    /// Fixed interface-scoped policy install request for the golden vectors.
    fn golden_policy_request() -> XfrmObjectInstallRequest {
        XfrmObjectInstallRequest::Policy(crate::InstallPolicyRequest {
            parameters: crate::PolicyParameters {
                selector: XfrmSelector::new(
                    IpAddress::Ipv4([10, 0, 0, 1]),
                    IpAddress::Ipv4([10, 0, 0, 2]),
                    50,
                ),
                direction: XfrmDirection::Out,
                action: XfrmAction::Allow,
                priority: 616,
                templates: vec![XfrmTemplate {
                    id: XfrmId {
                        destination: IpAddress::Ipv4([10, 0, 0, 2]),
                        spi: 0x1234_5678,
                        protocol: 50,
                    },
                    source_address: IpAddress::Ipv4([10, 0, 0, 1]),
                    request_id: None,
                    mode: XfrmMode::Tunnel,
                }],
                mark: None,
                if_id: Some(600),
            },
        })
    }

    /// Byte-pinned canonical encodings for the object family.
    ///
    /// The three encoders are now shared with the roster family and take their
    /// domain separator as a parameter, so nothing in a round-trip test can
    /// notice if the object family's domain is changed: both sides of every
    /// comparison would move together. These vectors are the only thing that
    /// does notice. A domain change silently invalidates every persisted
    /// `DurableObjectRecord`, which turns `recover_durable_object_install`
    /// into a permanent `WrongBinding` and leaves the writer gate closed
    /// forever, so this must fail loudly rather than pass quietly.
    #[test]
    fn golden_vectors_pin_the_object_install_request_and_deletion_identity_encoding() {
        let proof_key = key(9);
        let borrowed = proof_key.canonical_mac_key();
        let sa = golden_sa_request();
        let policy = golden_policy_request();

        assert_eq!(
            authenticate_install_request(borrowed, INSTALL_REQUEST_AUTH_DOMAIN, &sa).unwrap(),
            [
                0x25, 0x45, 0x12, 0x78, 0x88, 0x1a, 0xe4, 0xa7, 0x0c, 0x35, 0x75, 0xb6, 0xc5, 0x4c,
                0xbc, 0x46, 0xbc, 0x33, 0xe0, 0xc2, 0x6c, 0xc2, 0x77, 0xa4, 0xfb, 0x48, 0x3b, 0x64,
                0xb6, 0x9d, 0x02, 0x54,
            ],
            "object SA install-request fingerprint encoding changed"
        );
        assert_eq!(
            authenticate_install_request(borrowed, INSTALL_REQUEST_AUTH_DOMAIN, &policy).unwrap(),
            [
                0xc5, 0xc9, 0xb4, 0x1f, 0x1b, 0x7e, 0x3c, 0x34, 0x15, 0x62, 0x28, 0x7b, 0x00, 0xb7,
                0xa2, 0x4a, 0xa6, 0x88, 0x71, 0xda, 0x6c, 0x42, 0x94, 0x1e, 0x8d, 0x66, 0x2b, 0x53,
                0xf2, 0xa5, 0x6c, 0x2a,
            ],
            "object policy install-request fingerprint encoding changed"
        );
        assert_eq!(
            authenticate_deletion_identity(
                borrowed,
                DELETION_IDENTITY_AUTH_DOMAIN,
                &sa.removal(),
                sa.policy_if_id(),
            )
            .unwrap(),
            [
                0x02, 0x4d, 0x3a, 0x78, 0xe3, 0x53, 0xf9, 0x5b, 0x32, 0x63, 0x89, 0x19, 0xca, 0x2c,
                0x68, 0xdb, 0xb1, 0x85, 0xe6, 0x02, 0xc1, 0x2c, 0xe4, 0x2d, 0x3a, 0xfe, 0x72, 0x20,
                0xbd, 0xe6, 0xf5, 0x36,
            ],
            "object SA deletion-identity fingerprint encoding changed"
        );
        assert_eq!(
            authenticate_deletion_identity(
                borrowed,
                DELETION_IDENTITY_AUTH_DOMAIN,
                &policy.removal(),
                policy.policy_if_id(),
            )
            .unwrap(),
            [
                0x98, 0x42, 0xce, 0x31, 0xc7, 0xaa, 0x69, 0x82, 0x51, 0x08, 0x22, 0x72, 0x25, 0x14,
                0x36, 0x04, 0x86, 0xac, 0x14, 0x04, 0x0e, 0x3f, 0x57, 0xef, 0x2d, 0x33, 0xe2, 0x2e,
                0xcb, 0xc2, 0x9e, 0x44,
            ],
            "object scoped-policy deletion-identity fingerprint encoding changed"
        );
        assert_eq!(
            namespace_seal(&proof_key, [0x42; 40]),
            [
                0x26, 0xa8, 0x2e, 0x11, 0x15, 0xb3, 0x48, 0x52, 0x82, 0x39, 0x7c, 0x6c, 0x24, 0x54,
                0xd0, 0x5d, 0x64, 0x91, 0x54, 0x58, 0xf2, 0x97, 0x24, 0x16, 0x5b, 0xda, 0xc9, 0xf9,
                0x50, 0x44, 0x66, 0x31,
            ],
            "object namespace seal encoding changed"
        );
        assert_eq!(
            record(XfrmObjectInstallDurablePhase::Acquired)
                .encode(&proof_key)
                .unwrap()[RECORD_BODY_BYTES..],
            [
                0xb4, 0x48, 0x2b, 0xf7, 0xdc, 0x72, 0xad, 0x30, 0x56, 0xeb, 0x26, 0x45, 0x5f, 0xae,
                0xe6, 0x13, 0xc0, 0x91, 0x77, 0x6c, 0x9d, 0x04, 0x69, 0xf6, 0x87, 0x96, 0x07, 0x44,
                0x98, 0x5a, 0x14, 0x04,
            ],
            "object record tag encoding changed"
        );
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
        let encoded = record(XfrmObjectInstallDurablePhase::Acquired)
            .encode(&key(9))
            .unwrap();
        assert_eq!(
            DurableObjectRecord::decode(&encoded, &key(8)),
            Err(XfrmObjectInstallDurableError::AuthenticationFailed)
        );
        for index in [10, 16, 47, 80, 103, 111, 143, 175] {
            let mut tampered = encoded;
            tampered[index] ^= 0x80;
            assert!(DurableObjectRecord::decode(&tampered, &key(9)).is_err());
        }
    }

    #[test]
    fn reserved_and_zero_fields_fail_closed() {
        assert!(matches!(
            XfrmObjectRecoveryProofKey::new([0; 32]),
            Err(XfrmObjectInstallDurableError::InvalidProofKey)
        ));
        let valid = record(XfrmObjectInstallDurablePhase::Prepared)
            .encode(&key(9))
            .unwrap();
        // Bytes 13..16 remain reserved and must stay zero.
        let mut reserved = valid;
        reserved[13] = 1;
        assert_eq!(
            DurableObjectRecord::decode(&reserved, &key(9)),
            Err(XfrmObjectInstallDurableError::Malformed)
        );
        let mut invalid = record(XfrmObjectInstallDurablePhase::Prepared);
        invalid.store_incarnation = [0; 16];
        assert_eq!(
            invalid.encode(&key(9)),
            Err(XfrmObjectInstallDurableError::Malformed)
        );
    }

    #[test]
    fn all_public_diagnostics_are_value_free() {
        let operation = XfrmObjectInstallOperationId::from_bytes([0xab; 16]).unwrap();
        let generation = XfrmObjectInstallOperationGeneration::new(0xfeed_beef).unwrap();
        let handle = record(XfrmObjectInstallDurablePhase::Acquired)
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
            XfrmObjectInstallDurableError::AuthenticationFailed,
            XfrmObjectInstallDurableError::Duplicate,
            XfrmObjectInstallDurableError::WrongBinding,
            XfrmObjectInstallDurableError::Stale,
        ] {
            assert!(error.to_string().starts_with("xfrm_object_recovery_"));
        }
    }

    #[test]
    fn state_machine_rejects_unsafe_edges() {
        assert!(
            XfrmObjectInstallDurablePhase::Prepared.permits(XfrmObjectInstallDurablePhase::Issuing)
        );
        assert!(XfrmObjectInstallDurablePhase::Acquired
            .permits(XfrmObjectInstallDurablePhase::RemovalAdmitted));
        // Recovery edges that prove-and-retire an unresolved record.
        assert!(XfrmObjectInstallDurablePhase::Issuing
            .permits(XfrmObjectInstallDurablePhase::RemovalAdmitted));
        assert!(XfrmObjectInstallDurablePhase::Indeterminate
            .permits(XfrmObjectInstallDurablePhase::RemovalAdmitted));
        assert!(XfrmObjectInstallDurablePhase::Indeterminate
            .permits(XfrmObjectInstallDurablePhase::NoMutation));
        // An unresolved record may never retire directly without a verdict.
        assert!(
            !XfrmObjectInstallDurablePhase::Issuing.permits(XfrmObjectInstallDurablePhase::Retired)
        );
        assert!(!XfrmObjectInstallDurablePhase::Indeterminate
            .permits(XfrmObjectInstallDurablePhase::Retired));
        assert!(!XfrmObjectInstallDurablePhase::NoMutation
            .permits(XfrmObjectInstallDurablePhase::RemovalAdmitted));
    }

    #[test]
    fn store_persists_control_and_reopens_same_incarnation() {
        let root = TestRoot::new();
        let first = store(&root);
        let incarnation = first.inner.control.actor_incarnation;
        let operation = XfrmObjectInstallOperationId::generate().unwrap();
        let generation = XfrmObjectInstallOperationGeneration::new(1).unwrap();
        let handle = first
            .prepare(
                operation,
                generation,
                XfrmInstallObject::Sa,
                DurableObjectFingerprints::repeated(0x55),
            )
            .unwrap();
        assert_eq!(
            first.inspect(&handle),
            Ok(XfrmObjectInstallDurablePhase::Prepared)
        );
        drop(first);

        let reopened = store(&root);
        assert_eq!(reopened.inner.control.actor_incarnation, incarnation);
        assert_eq!(
            reopened.inspect(&handle),
            Ok(XfrmObjectInstallDurablePhase::Prepared)
        );
        assert_eq!(
            reopened.restore(
                operation,
                generation,
                XfrmInstallObject::Sa,
                DurableObjectFingerprints::repeated(0x55),
            ),
            Ok(reopened
                .lease()
                .unwrap()
                .inventory()
                .unwrap()
                .current_for(operation, generation)
                .unwrap()
                .1
                .clone())
        );
        assert_eq!(
            reopened.restore(
                operation,
                XfrmObjectInstallOperationGeneration::new(2).unwrap(),
                XfrmInstallObject::Sa,
                DurableObjectFingerprints::repeated(0x55),
            ),
            Err(XfrmObjectInstallDurableError::NotFound)
        );
        assert_eq!(
            reopened.restore(
                operation,
                generation,
                XfrmInstallObject::Sa,
                DurableObjectFingerprints::repeated(0x56),
            ),
            Err(XfrmObjectInstallDurableError::WrongBinding)
        );
        assert_eq!(
            reopened.prepare(
                XfrmObjectInstallOperationId::generate().unwrap(),
                generation,
                XfrmInstallObject::Sa,
                DurableObjectFingerprints::repeated(0x55),
            ),
            Err(XfrmObjectInstallDurableError::Duplicate)
        );
    }

    #[test]
    fn permanent_root_lease_rejects_second_open() {
        let root = TestRoot::new();
        let first = store(&root);
        assert_eq!(
            XfrmObjectInstallRecoveryStore::open_bound(root.path(), key(9), [0x42; 40])
                .unwrap_err(),
            XfrmObjectInstallDurableError::StoreBusy
        );
        drop(first);
        assert!(
            XfrmObjectInstallRecoveryStore::open_bound(root.path(), key(9), [0x42; 40]).is_ok()
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
        let initial = store(&root);
        drop(initial);
        let pending = root
            .path()
            .join(".opc-xfrm-object-pending-1234567890abcdef1234567890abcdef");
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
        fs::create_dir(root.path()).unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(DIRECTORY_MODE)).unwrap();
        let pending = root
            .path()
            .join(".opc-xfrm-object-pending-abcdef1234567890abcdef1234567890");
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
    fn unsafe_staging_lookalike_remains_fail_closed() {
        let root = TestRoot::new();
        let initial = store(&root);
        drop(initial);
        let pending = root
            .path()
            .join(".opc-xfrm-object-pending-fedcba0987654321fedcba0987654321");
        symlink(root.path().join(CONTROL_NAME), &pending).unwrap();

        assert!(matches!(
            XfrmObjectInstallRecoveryStore::open_bound(root.path(), key(9), [0x42; 40]),
            Err(XfrmObjectInstallDurableError::Malformed)
        ));
        assert!(pending.symlink_metadata().is_ok());
    }

    #[test]
    fn staging_fifo_is_rejected_without_blocking() {
        let root = TestRoot::new();
        let initial = store(&root);
        drop(initial);
        let pending = root
            .path()
            .join(".opc-xfrm-object-pending-0123456789abcdef0123456789abcdef");
        mkfifoat(CWD, &pending, Mode::from_raw_mode(FILE_MODE)).unwrap();

        assert!(matches!(
            XfrmObjectInstallRecoveryStore::open_bound(root.path(), key(9), [0x42; 40]),
            Err(XfrmObjectInstallDurableError::Malformed)
        ));
        assert!(pending.symlink_metadata().is_ok());
    }

    #[test]
    fn multibyte_operation_filename_is_malformed_without_panicking() {
        let root = TestRoot::new();
        let store = store(&root);
        let operation = format!("aé{}", "a".repeat(29));
        assert_eq!(operation.len(), 32);
        let name = format!("prepared-{operation}-0000000000000001");
        fs::write(
            root.path().join(name),
            [0_u8; XFRM_OBJECT_INSTALL_RECOVERY_HANDLE_BYTES],
        )
        .unwrap();
        fs::set_permissions(
            root.path()
                .join(format!("prepared-{operation}-0000000000000001")),
            fs::Permissions::from_mode(FILE_MODE),
        )
        .unwrap();

        assert_eq!(
            store.advance_writer_epoch(),
            Err(XfrmObjectInstallDurableError::Malformed)
        );
    }

    #[test]
    fn duplicate_active_deletion_identity_across_operations_fails_closed() {
        let root = TestRoot::new();
        let store = store(&root);
        let prepared = store
            .prepare(
                XfrmObjectInstallOperationId::from_bytes([0x41; 16]).unwrap(),
                XfrmObjectInstallOperationGeneration::new(1).unwrap(),
                XfrmInstallObject::Sa,
                DurableObjectFingerprints::repeated(0x71),
            )
            .unwrap();
        let lease = store.lease().unwrap();
        let inventory = lease.inventory().unwrap();
        let (_, first) = lease.current_from_handle(&inventory, &prepared).unwrap();
        let duplicate = DurableObjectRecord {
            operation_id: XfrmObjectInstallOperationId::from_bytes([0x42; 16]).unwrap(),
            ..first.clone()
        };
        lease.publish_record(&duplicate).unwrap();
        drop(lease);

        assert_eq!(
            store.advance_writer_epoch(),
            Err(XfrmObjectInstallDurableError::Duplicate)
        );
    }

    #[test]
    fn multiple_cleanup_authorities_with_distinct_identities_fail_closed() {
        let root = TestRoot::new();
        let store = store(&root);
        let prepared = store
            .prepare(
                XfrmObjectInstallOperationId::from_bytes([0x51; 16]).unwrap(),
                XfrmObjectInstallOperationGeneration::new(1).unwrap(),
                XfrmInstallObject::Sa,
                DurableObjectFingerprints::repeated(0x81),
            )
            .unwrap();
        let issuing = next_handle(
            &store,
            &prepared,
            XfrmObjectInstallDurablePhase::Prepared,
            XfrmObjectInstallDurablePhase::Issuing,
        );
        let acquired = next_handle(
            &store,
            &issuing,
            XfrmObjectInstallDurablePhase::Issuing,
            XfrmObjectInstallDurablePhase::Acquired,
        );
        let lease = store.lease().unwrap();
        let inventory = lease.inventory().unwrap();
        let (_, first) = lease.current_from_handle(&inventory, &acquired).unwrap();
        let second = DurableObjectRecord {
            operation_id: XfrmObjectInstallOperationId::from_bytes([0x52; 16]).unwrap(),
            deletion_identity_fingerprint: [0x91; 32],
            install_request_fingerprint: [0x92; 32],
            ..first.clone()
        };
        lease.publish_record(&second).unwrap();
        drop(lease);

        assert_eq!(
            store.advance_writer_epoch(),
            Err(XfrmObjectInstallDurableError::Duplicate)
        );
    }

    #[test]
    fn exact_phase_handle_is_required_for_each_transition() {
        let root = TestRoot::new();
        let store = store(&root);
        let prepared = store
            .prepare(
                XfrmObjectInstallOperationId::generate().unwrap(),
                XfrmObjectInstallOperationGeneration::new(1).unwrap(),
                XfrmInstallObject::Policy,
                DurableObjectFingerprints::repeated(0x31),
            )
            .unwrap();
        let issuing = next_handle(
            &store,
            &prepared,
            XfrmObjectInstallDurablePhase::Prepared,
            XfrmObjectInstallDurablePhase::Issuing,
        );
        assert_eq!(
            store.transition(
                &prepared,
                XfrmObjectInstallDurablePhase::Prepared,
                XfrmObjectInstallDurablePhase::Issuing,
                proof_for(
                    XfrmObjectInstallDurablePhase::Prepared,
                    XfrmObjectInstallDurablePhase::Issuing
                ),
            ),
            Err(XfrmObjectInstallDurableError::Stale)
        );
        let acquired = next_handle(
            &store,
            &issuing,
            XfrmObjectInstallDurablePhase::Issuing,
            XfrmObjectInstallDurablePhase::Acquired,
        );
        assert_eq!(
            store.inspect(&acquired),
            Ok(XfrmObjectInstallDurablePhase::Acquired)
        );
        assert_eq!(
            store.inspect(&issuing),
            Err(XfrmObjectInstallDurableError::Stale)
        );
    }

    #[test]
    fn acquired_authority_blocks_queued_and_new_writers_until_resolution() {
        let root = TestRoot::new();
        let store = store(&root);
        let operation_a = XfrmObjectInstallOperationId::generate().unwrap();
        let generation = XfrmObjectInstallOperationGeneration::new(1).unwrap();
        let prepared_a = store
            .prepare(
                operation_a,
                generation,
                XfrmInstallObject::Sa,
                DurableObjectFingerprints::repeated(0xa1),
            )
            .unwrap();
        // Prepare B before A becomes unresolved writer authority, so a queued
        // second operation exists to be gated once A advances.
        let operation_b = XfrmObjectInstallOperationId::generate().unwrap();
        let prepared_b = store
            .prepare(
                operation_b,
                generation,
                XfrmInstallObject::Policy,
                DurableObjectFingerprints::repeated(0xb2),
            )
            .unwrap();
        let issuing_a = next_handle(
            &store,
            &prepared_a,
            XfrmObjectInstallDurablePhase::Prepared,
            XfrmObjectInstallDurablePhase::Issuing,
        );
        // While A is Issuing, B is already prepared but may not be admitted.
        assert_eq!(
            store.transition(
                &prepared_b,
                XfrmObjectInstallDurablePhase::Prepared,
                XfrmObjectInstallDurablePhase::Issuing,
                proof_for(
                    XfrmObjectInstallDurablePhase::Prepared,
                    XfrmObjectInstallDurablePhase::Issuing
                ),
            ),
            Err(XfrmObjectInstallDurableError::InvalidTransition)
        );
        let acquired_a = next_handle(
            &store,
            &issuing_a,
            XfrmObjectInstallDurablePhase::Issuing,
            XfrmObjectInstallDurablePhase::Acquired,
        );
        assert_eq!(
            store.transition(
                &prepared_b,
                XfrmObjectInstallDurablePhase::Prepared,
                XfrmObjectInstallDurablePhase::Issuing,
                proof_for(
                    XfrmObjectInstallDurablePhase::Prepared,
                    XfrmObjectInstallDurablePhase::Issuing
                ),
            ),
            Err(XfrmObjectInstallDurableError::InvalidTransition)
        );
        assert_eq!(
            store.prepare(
                XfrmObjectInstallOperationId::generate().unwrap(),
                generation,
                XfrmInstallObject::Policy,
                DurableObjectFingerprints::repeated(0xb3),
            ),
            Err(XfrmObjectInstallDurableError::InvalidTransition)
        );
        assert_eq!(
            store.advance_writer_epoch(),
            Err(XfrmObjectInstallDurableError::InvalidTransition)
        );
        assert!(store
            .restore(
                operation_a,
                generation,
                XfrmInstallObject::Sa,
                DurableObjectFingerprints::repeated(0xa1),
            )
            .is_ok());
        assert!(store
            .transition(
                &acquired_a,
                XfrmObjectInstallDurablePhase::Acquired,
                XfrmObjectInstallDurablePhase::RemovalAdmitted,
                None,
            )
            .is_ok());
    }

    #[test]
    fn absent_root_is_published_through_a_nofollow_parent_descriptor() {
        let parent = TestRoot::new();
        fs::create_dir(parent.path()).unwrap();
        fs::set_permissions(parent.path(), fs::Permissions::from_mode(DIRECTORY_MODE)).unwrap();
        let root = parent.path().join("store");
        let store = XfrmObjectInstallRecoveryStore::open_bound(&root, key(9), [0x42; 40]).unwrap();
        assert!(root.is_dir());
        drop(store);
        assert!(XfrmObjectInstallRecoveryStore::open_bound(&root, key(9), [0x42; 40]).is_ok());

        let actual_parent = parent.path().join("actual");
        fs::create_dir(&actual_parent).unwrap();
        fs::set_permissions(&actual_parent, fs::Permissions::from_mode(DIRECTORY_MODE)).unwrap();
        let linked_parent = parent.path().join("linked");
        symlink(&actual_parent, &linked_parent).unwrap();
        assert_eq!(
            XfrmObjectInstallRecoveryStore::open_bound(
                &linked_parent.join("store"),
                key(9),
                [0x42; 40],
            )
            .unwrap_err(),
            XfrmObjectInstallDurableError::InvalidStoreRoot
        );
    }

    #[test]
    fn noncanonical_hex_record_filename_is_malformed() {
        let root = TestRoot::new();
        let record_store = store(&root);
        let handle = record_store
            .prepare(
                XfrmObjectInstallOperationId::from_bytes([0xab; 16]).unwrap(),
                XfrmObjectInstallOperationGeneration::new(1).unwrap(),
                XfrmInstallObject::Sa,
                DurableObjectFingerprints::repeated(0x45),
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
            Err(XfrmObjectInstallDurableError::Malformed)
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
            Err(XfrmObjectInstallDurableError::Malformed)
        );
    }

    #[test]
    fn forged_later_epoch_stales_acquired_authority_fail_closed() {
        let root = TestRoot::new();
        let store = store(&root);
        let operation = XfrmObjectInstallOperationId::generate().unwrap();
        let generation = XfrmObjectInstallOperationGeneration::new(1).unwrap();
        let prepared = store
            .prepare(
                operation,
                generation,
                XfrmInstallObject::Sa,
                DurableObjectFingerprints::repeated(0xa4),
            )
            .unwrap();
        let issuing = next_handle(
            &store,
            &prepared,
            XfrmObjectInstallDurablePhase::Prepared,
            XfrmObjectInstallDurablePhase::Issuing,
        );
        let acquired = next_handle(
            &store,
            &issuing,
            XfrmObjectInstallDurablePhase::Issuing,
            XfrmObjectInstallDurablePhase::Acquired,
        );
        let lease = store.lease().unwrap();
        let inventory = lease.inventory().unwrap();
        lease.advance_epoch(&inventory).unwrap();
        drop(lease);
        assert_eq!(
            store.restore(
                operation,
                generation,
                XfrmInstallObject::Sa,
                DurableObjectFingerprints::repeated(0xa4),
            ),
            Err(XfrmObjectInstallDurableError::Stale)
        );
        assert_eq!(
            store.transition(
                &acquired,
                XfrmObjectInstallDurablePhase::Acquired,
                XfrmObjectInstallDurablePhase::RemovalAdmitted,
                None,
            ),
            Err(XfrmObjectInstallDurableError::Stale)
        );
    }

    #[test]
    fn removal_admitted_blocks_later_writer_until_retired() {
        let root = TestRoot::new();
        let store = store(&root);
        let operation = XfrmObjectInstallOperationId::generate().unwrap();
        let generation = XfrmObjectInstallOperationGeneration::new(1).unwrap();
        let prepared = store
            .prepare(
                operation,
                generation,
                XfrmInstallObject::Sa,
                DurableObjectFingerprints::repeated(0xc3),
            )
            .unwrap();
        let issuing = next_handle(
            &store,
            &prepared,
            XfrmObjectInstallDurablePhase::Prepared,
            XfrmObjectInstallDurablePhase::Issuing,
        );
        let acquired = next_handle(
            &store,
            &issuing,
            XfrmObjectInstallDurablePhase::Issuing,
            XfrmObjectInstallDurablePhase::Acquired,
        );
        let admitted = next_handle(
            &store,
            &acquired,
            XfrmObjectInstallDurablePhase::Acquired,
            XfrmObjectInstallDurablePhase::RemovalAdmitted,
        );
        assert_eq!(
            store.advance_writer_epoch(),
            Err(XfrmObjectInstallDurableError::InvalidTransition)
        );
        assert!(store
            .restore(
                operation,
                generation,
                XfrmInstallObject::Sa,
                DurableObjectFingerprints::repeated(0xc3),
            )
            .is_ok());
        assert!(store
            .transition(
                &admitted,
                XfrmObjectInstallDurablePhase::RemovalAdmitted,
                XfrmObjectInstallDurablePhase::Retired,
                None,
            )
            .is_ok());
    }

    #[test]
    fn terminal_compaction_keeps_more_than_twice_the_bound_live() {
        let root = TestRoot::new();
        let store = store(&root);
        for index in 1_u64..=(MAX_STORE_ENTRIES as u64 * 2 + 1) {
            let mut operation = [0_u8; 16];
            operation[8..].copy_from_slice(&index.to_be_bytes());
            let operation = XfrmObjectInstallOperationId::from_bytes(operation).unwrap();
            let generation = XfrmObjectInstallOperationGeneration::new(index).unwrap();
            let mut deletion_identity = [0_u8; 32];
            deletion_identity[24..].copy_from_slice(&index.to_be_bytes());
            let mut install_request = [0xff_u8; 32];
            install_request[24..].copy_from_slice(&index.to_be_bytes());
            let fingerprints = DurableObjectFingerprints {
                deletion_identity,
                install_request,
            };
            let prepared = store
                .prepare(operation, generation, XfrmInstallObject::Sa, fingerprints)
                .unwrap();
            let issuing = next_handle(
                &store,
                &prepared,
                XfrmObjectInstallDurablePhase::Prepared,
                XfrmObjectInstallDurablePhase::Issuing,
            );
            let no_mutation = next_handle(
                &store,
                &issuing,
                XfrmObjectInstallDurablePhase::Issuing,
                XfrmObjectInstallDurablePhase::NoMutation,
            );
            let _retired = next_handle(
                &store,
                &no_mutation,
                XfrmObjectInstallDurablePhase::NoMutation,
                XfrmObjectInstallDurablePhase::Retired,
            );
        }
        for _ in 0..(MAX_STORE_ENTRIES * 2 + 1) {
            store.advance_writer_epoch().unwrap();
        }
        assert!(store.lease().unwrap().inventory().unwrap().records.len() <= 1);
    }

    #[test]
    fn conflicting_adjacent_phase_residue_is_fail_closed() {
        let root = TestRoot::new();
        let store = store(&root);
        let prepared = store
            .prepare(
                XfrmObjectInstallOperationId::generate().unwrap(),
                XfrmObjectInstallOperationGeneration::new(1).unwrap(),
                XfrmInstallObject::Sa,
                DurableObjectFingerprints::repeated(0x77),
            )
            .unwrap();
        let lease = store.lease().unwrap();
        let inventory = lease.inventory().unwrap();
        let (_, current) = lease.current_from_handle(&inventory, &prepared).unwrap();
        let next = DurableObjectRecord {
            phase: XfrmObjectInstallDurablePhase::Issuing,
            writer_epoch: NonZeroU64::new(inventory.epoch.get() + 1).unwrap(),
            pre_effect_proof: Some(XfrmObjectInstallPreEffectProof::Absent),
            ..current.clone()
        };
        lease.publish_record(&next).unwrap();
        drop(lease);
        assert_eq!(
            store.inspect(&prepared),
            Err(XfrmObjectInstallDurableError::Duplicate)
        );
        assert_eq!(
            store.transition(
                &prepared,
                XfrmObjectInstallDurablePhase::Prepared,
                XfrmObjectInstallDurablePhase::Issuing,
                proof_for(
                    XfrmObjectInstallDurablePhase::Prepared,
                    XfrmObjectInstallDurablePhase::Issuing
                ),
            ),
            Err(XfrmObjectInstallDurableError::Duplicate)
        );
    }

    #[test]
    fn every_exact_adjacent_phase_publication_residue_self_heals() {
        for (old_phase, next_phase) in [
            (
                XfrmObjectInstallDurablePhase::Prepared,
                XfrmObjectInstallDurablePhase::Issuing,
            ),
            (
                XfrmObjectInstallDurablePhase::Prepared,
                XfrmObjectInstallDurablePhase::Retired,
            ),
            (
                XfrmObjectInstallDurablePhase::Issuing,
                XfrmObjectInstallDurablePhase::Acquired,
            ),
            (
                XfrmObjectInstallDurablePhase::Issuing,
                XfrmObjectInstallDurablePhase::NoMutation,
            ),
            (
                XfrmObjectInstallDurablePhase::Issuing,
                XfrmObjectInstallDurablePhase::Indeterminate,
            ),
            (
                XfrmObjectInstallDurablePhase::Issuing,
                XfrmObjectInstallDurablePhase::RemovalAdmitted,
            ),
            (
                XfrmObjectInstallDurablePhase::Indeterminate,
                XfrmObjectInstallDurablePhase::NoMutation,
            ),
            (
                XfrmObjectInstallDurablePhase::Indeterminate,
                XfrmObjectInstallDurablePhase::RemovalAdmitted,
            ),
            (
                XfrmObjectInstallDurablePhase::Acquired,
                XfrmObjectInstallDurablePhase::RemovalAdmitted,
            ),
            (
                XfrmObjectInstallDurablePhase::Acquired,
                XfrmObjectInstallDurablePhase::Committed,
            ),
            (
                XfrmObjectInstallDurablePhase::NoMutation,
                XfrmObjectInstallDurablePhase::Retired,
            ),
            (
                XfrmObjectInstallDurablePhase::RemovalAdmitted,
                XfrmObjectInstallDurablePhase::Retired,
            ),
        ] {
            let root = TestRoot::new();
            let store = store(&root);
            let prepared = store
                .prepare(
                    XfrmObjectInstallOperationId::generate().unwrap(),
                    XfrmObjectInstallOperationGeneration::new(1).unwrap(),
                    XfrmInstallObject::Sa,
                    DurableObjectFingerprints::repeated(0xd1),
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
            if old_phase != XfrmObjectInstallDurablePhase::Prepared {
                lease.remove_record(&prepared_name).unwrap();
                lease.publish_record(&old).unwrap();
            }
            let inventory = lease.inventory().unwrap();
            let old_name = record_name(&old);
            let entering_issuing = old_phase == XfrmObjectInstallDurablePhase::Prepared
                && next_phase == XfrmObjectInstallDurablePhase::Issuing;
            let next_proof = if entering_issuing {
                Some(XfrmObjectInstallPreEffectProof::Absent)
            } else {
                old.pre_effect_proof
            };
            let mut next = DurableObjectRecord {
                phase: next_phase,
                pre_effect_proof: next_proof,
                ..old.clone()
            };
            if next_phase == XfrmObjectInstallDurablePhase::Issuing {
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
                XfrmObjectInstallOperationId::generate().unwrap(),
                XfrmObjectInstallOperationGeneration::new(1).unwrap(),
                XfrmInstallObject::Policy,
                DurableObjectFingerprints::repeated(0x88),
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
            Err(XfrmObjectInstallDurableError::WrongIncarnation)
        );
    }

    #[test]
    fn wrong_key_namespace_unknown_entry_and_root_copy_fail_closed() {
        let root = TestRoot::new();
        let initial_store = store(&root);
        drop(initial_store);
        assert_eq!(
            XfrmObjectInstallRecoveryStore::open_bound(root.path(), key(8), [0x42; 40])
                .unwrap_err(),
            XfrmObjectInstallDurableError::AuthenticationFailed
        );
        assert_eq!(
            XfrmObjectInstallRecoveryStore::open_bound(root.path(), key(9), [0x43; 40])
                .unwrap_err(),
            XfrmObjectInstallDurableError::WrongBinding
        );

        let copied = TestRoot::new();
        fs::create_dir(copied.path()).unwrap();
        fs::set_permissions(copied.path(), fs::Permissions::from_mode(DIRECTORY_MODE)).unwrap();
        for entry in fs::read_dir(root.path()).unwrap() {
            let entry = entry.unwrap();
            fs::copy(entry.path(), copied.path().join(entry.file_name())).unwrap();
        }
        assert_eq!(
            XfrmObjectInstallRecoveryStore::open_bound(copied.path(), key(9), [0x42; 40])
                .unwrap_err(),
            XfrmObjectInstallDurableError::WrongBinding
        );

        let reopened = store(&root);
        fs::write(root.path().join("unknown"), b"poison").unwrap();
        assert_eq!(
            reopened.advance_writer_epoch(),
            Err(XfrmObjectInstallDurableError::Malformed)
        );
    }

    #[test]
    fn relocation_family_store_root_rejects_install_open_fail_closed() {
        let root = TestRoot::new();
        let relocation_store =
            crate::durable_relocation::XfrmSaRelocationRecoveryStore::open_bound(
                root.path(),
                crate::durable_relocation::XfrmSaRelocationRecoveryProofKey::new([9; 32]).unwrap(),
                [0x42; 40],
            )
            .unwrap();
        drop(relocation_store);
        // The dropped relocation store's root passes ownership, mode, and
        // flock validation on reopen; the rejection must come from
        // control-record validation, where the relocation family's distinct
        // control magic fails `ControlRecord::decode` before authentication
        // is even attempted.
        assert_eq!(
            XfrmObjectInstallRecoveryStore::open_bound(root.path(), key(9), [0x42; 40])
                .unwrap_err(),
            XfrmObjectInstallDurableError::Malformed
        );
    }

    #[test]
    fn deletion_fingerprint_covers_sa_and_scoped_policy_identity() {
        let root = TestRoot::new();
        let store = store(&root);
        let sa = XfrmObjectRemovalRequest::Sa(RemoveSaRequest {
            destination: IpAddress::Ipv4([10, 0, 0, 1]),
            protocol: 50,
            spi: 7,
            mark: Some(XfrmLookupMark::full(11)),
        });
        let mut changed_sa = sa.clone();
        if let XfrmObjectRemovalRequest::Sa(request) = &mut changed_sa {
            request.spi += 1;
        }
        assert_ne!(
            store
                .deletion_identity_fingerprint_with_policy_if_id(&sa, None)
                .unwrap(),
            store
                .deletion_identity_fingerprint_with_policy_if_id(&changed_sa, None)
                .unwrap()
        );

        let policy = XfrmObjectRemovalRequest::Policy(RemovePolicyRequest {
            selector: XfrmSelector::new(IpAddress::Ipv6([1; 16]), IpAddress::Ipv6([2; 16]), 17),
            direction: XfrmDirection::Out,
            mark: Some(XfrmLookupMark::full(12)),
        });
        let unscoped = store
            .deletion_identity_fingerprint_with_policy_if_id(&policy, None)
            .unwrap();
        let scoped = store
            .deletion_identity_fingerprint_with_policy_if_id(&policy, Some(9))
            .unwrap();
        let other_scope = store
            .deletion_identity_fingerprint_with_policy_if_id(&policy, Some(10))
            .unwrap();
        assert_ne!(unscoped, scoped);
        assert_ne!(scoped, other_scope);
        assert_eq!(
            store.deletion_identity_fingerprint_with_policy_if_id(&sa, Some(9)),
            Err(XfrmObjectInstallDurableError::Malformed)
        );
    }

    #[test]
    fn record_version_one_fails_closed_after_format_bump() {
        let encoded = record(XfrmObjectInstallDurablePhase::Acquired)
            .encode(&key(9))
            .unwrap();
        let mut v1 = encoded;
        v1[8..10].copy_from_slice(&1_u16.to_be_bytes());
        assert_eq!(
            DurableObjectRecord::decode(&v1, &key(9)),
            Err(XfrmObjectInstallDurableError::Malformed)
        );
    }

    #[test]
    fn proof_encoding_rules_fail_closed() {
        // Unknown proof codes are malformed.
        let valid = record(XfrmObjectInstallDurablePhase::Issuing)
            .encode(&key(9))
            .unwrap();
        let mut bad_code = valid;
        bad_code[12] = 3;
        assert_eq!(
            DurableObjectRecord::decode(&bad_code, &key(9)),
            Err(XfrmObjectInstallDurableError::Malformed)
        );
        // A trailing reserved byte must stay zero.
        let mut bad_reserved = valid;
        bad_reserved[13] = 1;
        assert_eq!(
            DurableObjectRecord::decode(&bad_reserved, &key(9)),
            Err(XfrmObjectInstallDurableError::Malformed)
        );
        // Prepared must not carry a proof.
        let mut prepared_with_proof = record(XfrmObjectInstallDurablePhase::Prepared);
        prepared_with_proof.pre_effect_proof = Some(XfrmObjectInstallPreEffectProof::Absent);
        assert_eq!(
            prepared_with_proof.encode(&key(9)),
            Err(XfrmObjectInstallDurableError::Malformed)
        );
        // An effect-possible record must carry a proof.
        let mut issuing_without_proof = record(XfrmObjectInstallDurablePhase::Issuing);
        issuing_without_proof.pre_effect_proof = None;
        assert_eq!(
            issuing_without_proof.encode(&key(9)),
            Err(XfrmObjectInstallDurableError::Malformed)
        );
    }

    #[test]
    fn proof_round_trips_both_witnesses() {
        for proof in [
            XfrmObjectInstallPreEffectProof::Absent,
            XfrmObjectInstallPreEffectProof::Conflict,
        ] {
            let mut expected = record(XfrmObjectInstallDurablePhase::Issuing);
            expected.pre_effect_proof = Some(proof);
            let encoded = expected.encode(&key(9)).unwrap();
            assert_eq!(
                DurableObjectRecord::decode(&encoded, &key(9)).unwrap(),
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
                XfrmObjectInstallOperationId::generate().unwrap(),
                XfrmObjectInstallOperationGeneration::new(1).unwrap(),
                XfrmInstallObject::Sa,
                DurableObjectFingerprints::repeated(0x61),
            )
            .unwrap();
        // Missing proof for Prepared -> Issuing is rejected.
        assert_eq!(
            store.transition(
                &prepared,
                XfrmObjectInstallDurablePhase::Prepared,
                XfrmObjectInstallDurablePhase::Issuing,
                None,
            ),
            Err(XfrmObjectInstallDurableError::InvalidTransition)
        );
        let issuing = store
            .transition(
                &prepared,
                XfrmObjectInstallDurablePhase::Prepared,
                XfrmObjectInstallDurablePhase::Issuing,
                Some(XfrmObjectInstallPreEffectProof::Absent),
            )
            .unwrap();
        assert_eq!(
            issuing.pre_effect_proof,
            Some(XfrmObjectInstallPreEffectProof::Absent)
        );
        // A supplied proof on any non-issuing transition is rejected.
        let issuing_handle = issuing.handle(&store.inner.proof_key).unwrap();
        assert_eq!(
            store.transition(
                &issuing_handle,
                XfrmObjectInstallDurablePhase::Issuing,
                XfrmObjectInstallDurablePhase::Acquired,
                Some(XfrmObjectInstallPreEffectProof::Conflict),
            ),
            Err(XfrmObjectInstallDurableError::InvalidTransition)
        );
        // The accepted transition preserves the witnessed proof.
        let acquired = store
            .transition(
                &issuing_handle,
                XfrmObjectInstallDurablePhase::Issuing,
                XfrmObjectInstallDurablePhase::Acquired,
                None,
            )
            .unwrap();
        assert_eq!(
            acquired.pre_effect_proof,
            Some(XfrmObjectInstallPreEffectProof::Absent)
        );
    }

    #[test]
    fn unresolved_issuing_gates_prepare_and_writer_epoch_until_retired() {
        for unresolved_phase in [
            XfrmObjectInstallDurablePhase::Issuing,
            XfrmObjectInstallDurablePhase::Indeterminate,
        ] {
            let root = TestRoot::new();
            let store = store(&root);
            let operation = XfrmObjectInstallOperationId::generate().unwrap();
            let generation = XfrmObjectInstallOperationGeneration::new(1).unwrap();
            let prepared = store
                .prepare(
                    operation,
                    generation,
                    XfrmInstallObject::Sa,
                    DurableObjectFingerprints::repeated(0x62),
                )
                .unwrap();
            let issuing = next_handle(
                &store,
                &prepared,
                XfrmObjectInstallDurablePhase::Prepared,
                XfrmObjectInstallDurablePhase::Issuing,
            );
            let unresolved_handle = if unresolved_phase == XfrmObjectInstallDurablePhase::Issuing {
                issuing.clone()
            } else {
                next_handle(
                    &store,
                    &issuing,
                    XfrmObjectInstallDurablePhase::Issuing,
                    XfrmObjectInstallDurablePhase::Indeterminate,
                )
            };
            assert_eq!(
                store.prepare(
                    XfrmObjectInstallOperationId::generate().unwrap(),
                    generation,
                    XfrmInstallObject::Policy,
                    DurableObjectFingerprints::repeated(0x63),
                ),
                Err(XfrmObjectInstallDurableError::InvalidTransition)
            );
            assert_eq!(
                store.advance_writer_epoch(),
                Err(XfrmObjectInstallDurableError::InvalidTransition)
            );
            // Retire the unresolved record through a no-mutation verdict and
            // confirm the gate reopens.
            let no_mutation = next_handle(
                &store,
                &unresolved_handle,
                unresolved_phase,
                XfrmObjectInstallDurablePhase::NoMutation,
            );
            let _retired = next_handle(
                &store,
                &no_mutation,
                XfrmObjectInstallDurablePhase::NoMutation,
                XfrmObjectInstallDurablePhase::Retired,
            );
            assert!(store.advance_writer_epoch().is_ok());
            assert!(store
                .prepare(
                    XfrmObjectInstallOperationId::generate().unwrap(),
                    generation,
                    XfrmInstallObject::Policy,
                    DurableObjectFingerprints::repeated(0x63),
                )
                .is_ok());
        }
    }

    #[test]
    fn duplicate_issuing_authorities_fail_closed() {
        let root = TestRoot::new();
        let store = store(&root);
        let prepared = store
            .prepare(
                XfrmObjectInstallOperationId::from_bytes([0x64; 16]).unwrap(),
                XfrmObjectInstallOperationGeneration::new(1).unwrap(),
                XfrmInstallObject::Sa,
                DurableObjectFingerprints::repeated(0x65),
            )
            .unwrap();
        let issuing = next_handle(
            &store,
            &prepared,
            XfrmObjectInstallDurablePhase::Prepared,
            XfrmObjectInstallDurablePhase::Issuing,
        );
        let lease = store.lease().unwrap();
        let inventory = lease.inventory().unwrap();
        let (_, first) = lease.current_from_handle(&inventory, &issuing).unwrap();
        let second = DurableObjectRecord {
            operation_id: XfrmObjectInstallOperationId::from_bytes([0x66; 16]).unwrap(),
            deletion_identity_fingerprint: [0x67; 32],
            install_request_fingerprint: [0x68; 32],
            ..first.clone()
        };
        lease.publish_record(&second).unwrap();
        drop(lease);
        assert_eq!(
            store.advance_writer_epoch(),
            Err(XfrmObjectInstallDurableError::Duplicate)
        );
    }

    #[test]
    fn epoch_currency_predicate_tracks_writer_epoch_advances() {
        let root = TestRoot::new();
        let store = store(&root);
        let operation = XfrmObjectInstallOperationId::generate().unwrap();
        let generation = XfrmObjectInstallOperationGeneration::new(1).unwrap();
        let prepared = store
            .prepare(
                operation,
                generation,
                XfrmInstallObject::Sa,
                DurableObjectFingerprints::repeated(0x69),
            )
            .unwrap();
        let issuing = store
            .transition(
                &prepared,
                XfrmObjectInstallDurablePhase::Prepared,
                XfrmObjectInstallDurablePhase::Issuing,
                Some(XfrmObjectInstallPreEffectProof::Absent),
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

    #[tokio::test]
    async fn stale_epoch_under_unresolved_record_recovers_repair_required() {
        // A durable anomaly that advances the epoch underneath an unresolved
        // record removes the proof's ordering guarantee. Recovery must refuse
        // to delete and classify the record for repair, keeping it gating.
        let root = TestRoot::new();
        let store = store(&root);
        let operation = XfrmObjectInstallOperationId::generate().unwrap();
        let generation = XfrmObjectInstallOperationGeneration::new(1).unwrap();
        let request = crate::durable_install::tests_sa_request_for_repair();
        let fingerprints = store.fingerprints_for_request(&request).unwrap();
        let prepared = store
            .prepare(operation, generation, request.object(), fingerprints)
            .unwrap();
        store
            .transition(
                &prepared,
                XfrmObjectInstallDurablePhase::Prepared,
                XfrmObjectInstallDurablePhase::Issuing,
                Some(XfrmObjectInstallPreEffectProof::Absent),
            )
            .unwrap();
        let lease = store.lease().unwrap();
        let inventory = lease.inventory().unwrap();
        lease.advance_epoch(&inventory).unwrap();
        drop(lease);

        let backend = crate::MockXfrmBackend::new();
        let outcome = crate::durable_install::recover_durable_object_install(
            &store, operation, generation, &request, &backend,
        )
        .await
        .unwrap();
        assert_eq!(outcome.as_str(), "repair_required");
        // The record remains unresolved and keeps gating writers.
        assert_eq!(
            store.advance_writer_epoch(),
            Err(XfrmObjectInstallDurableError::InvalidTransition)
        );
    }
}
