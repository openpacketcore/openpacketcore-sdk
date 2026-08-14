//! Opaque, fail-closed admission for the grouped GTP-U selector namespace.
//!
//! The dataplane's bounded journals intentionally do not retain selector
//! history.  This module is the authority boundary for that history: callers
//! obtain one affine admission only after an atomic namespace claim, then move
//! it into a grouped reconcile request.  Selector bytes never leave this
//! module and all public diagnostics are summaries.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::Future;
use std::num::NonZeroU64;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use hmac::{Hmac, Mac};
use opc_gtpu_ebpf_common::{
    GtpuSessionDownlinkKey, GtpuSessionIpFamily, GtpuSessionPaa,
    GTPU_SESSION_SELECTOR_STAMP_VALUE_LEN,
};
use opc_session_store::{
    CompareAndSet, CompareAndSetResult, EncryptedSessionPayload, Generation, OwnerId,
    ProtectedSelectorLedgerBase, ProtectedSessionBackend, RestoreScanCursorProfile,
    SelectorLedgerStorageScope, SessionBackend, SessionKey, SessionKeyType, SessionLeaseManager,
    SessionStore, StableId, StateClass, StateType, StoredSessionRecord,
};
use rand::{rngs::SysRng, TryRng};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    GtpAddressFamily, GtpuDataplaneBackend, GtpuSessionDeviceId, GtpuSessionGroup,
    GtpuSessionGroupReconcileOutcome, GtpuSessionGroupReconcileRequest,
    GtpuSessionGroupRemovalOutcome,
};

// RFC 016 fixes these byte-for-byte.  The NUL terminator is part of the
// domain input; never reuse one commitment kind's codec for another.
const GROUP_DOMAIN: &[u8] = b"opc/gtpu-selector/group/v1\0";
const SET_DOMAIN: &[u8] = b"opc/gtpu-selector/set/v1\0";
const ATOM_DOMAIN: &[u8] = b"opc/gtpu-selector/atom/v1\0";
const DESIRED_DOMAIN: &[u8] = b"opc/gtpu-selector/desired/v1\0";
const STORAGE_DOMAIN: &[u8] = b"opc/gtpu-selector/storage/v1\0";
const STORAGE_KEY_DOMAIN: &[u8] = b"opc/gtpu-selector/storage-key/v1\0";
const STORAGE_SCOPE_DOMAIN: &[u8] = b"opc/gtpu-selector/storage-scope/v1\0";
const SELECTOR_SECRET_COMMITMENT_DOMAIN: &[u8] = b"opc/gtpu-selector/secret-commitment/v1\0";
const DECOMMISSION_FENCE_DOMAIN: &[u8] = b"opc/gtpu-selector/decommission-fence/v1\0";
const SELECTOR_LEDGER_KEY_TYPE: &str = "gtpu-selector-ledger-v1";
/// A conservative envelope reserve keeps plaintext ledgers below SQLite's
/// one-MiB record capability when an `EncryptingSessionBackend` seals them.
const MAX_RECORD_BYTES: usize = 512 * 1024;
const MAX_PERMANENT_GROUPS: usize = 1_024;
const MAX_LIVE_GROUPS: usize = 512;
const MAX_KNOWN_ATOMS: usize = 1_024;
// The permanent group history has a fixed aggregate atom-reference budget.
// One group can contribute up to six elementary atoms (two families, each
// with a TEID, PAA, and optional mark), but the aggregate must remain within
// RFC 016's 4,096-reference record profile.
const MAX_GROUP_ATOM_REFERENCES: usize = 4_096;
const MIN_BACKEND_RECORD_BYTES: usize = MAX_RECORD_BYTES + (64 * 1024);
/// Bounded conflict retries for one fenced durable selector mutation.
pub const SELECTOR_NAMESPACE_MAX_CAS_ATTEMPTS: usize = 4;
/// Maximum canonical selector atoms admitted for one exact backend readback.
pub const SELECTOR_NAMESPACE_MAX_READBACK_ATOMS: usize = 256;
/// Maximum concurrently retained userspace selector-operation stamps.
pub const SELECTOR_NAMESPACE_MAX_STAMP_SLOTS: usize = 1_024;
/// Maximum concurrent namespace supervisors per stable namespace.
pub const SELECTOR_NAMESPACE_MAX_SUPERVISORS_PER_NAMESPACE: usize = 64;
/// Maximum concurrent namespace supervisors in one process.
pub const SELECTOR_NAMESPACE_MAX_SUPERVISORS_PER_PROCESS: usize = 256;
/// Maximum immutable selector-binding markers accepted for one dataplane.
pub const SELECTOR_NAMESPACE_MAX_MARKER_ENTRIES: usize = 16;
/// Longest permitted durable worker lease for this authority.
pub const SELECTOR_NAMESPACE_MAX_LEASE_TTL: Duration = Duration::from_secs(30);
/// Lease renewal cadence used by long-running supervisors.
pub const SELECTOR_NAMESPACE_LEASE_RENEW_INTERVAL: Duration = Duration::from_secs(10);
/// One backend effect/readback step must complete within this bound.
pub const SELECTOR_NAMESPACE_MAX_EFFECT_DURATION: Duration = Duration::from_secs(5);
const MAX_CAS_RETRIES: usize = SELECTOR_NAMESPACE_MAX_CAS_ATTEMPTS;

/// Affine evidence that the eBPF backend has resolved one canonical grouped
/// pin namespace and currently holds its host-global ownership lease.
///
/// Product code can move this value only into the protected selector-ledger
/// provisioning/opening boundary.  Its pin commitment is deliberately not
/// observable or constructible outside the SDK: a stable device ID alone
/// cannot name the bpffs authority it is allowed to control.
#[must_use = "a selector namespace bootstrap must be consumed by protected provisioning or opening"]
pub struct GtpuSelectorNamespaceBootstrap {
    stable_device: GtpuSessionDeviceId,
    pin_commitment: [u8; 32],
}

impl GtpuSelectorNamespaceBootstrap {
    /// Mint only after the eBPF runtime has resolved the canonical pin
    /// namespace and qualified its held ownership lease.
    pub(crate) fn from_qualified_backend(
        stable_device: GtpuSessionDeviceId,
        pin_commitment: [u8; 32],
    ) -> Option<Self> {
        (pin_commitment != [0; 32]).then_some(Self {
            stable_device,
            pin_commitment,
        })
    }

    pub(crate) const fn stable_device(&self) -> GtpuSessionDeviceId {
        self.stable_device
    }

    pub(crate) const fn pin_commitment(&self) -> [u8; 32] {
        self.pin_commitment
    }
}

impl fmt::Debug for GtpuSelectorNamespaceBootstrap {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GtpuSelectorNamespaceBootstrap(<redacted>)")
    }
}

struct ProtectedSelectorLedgerDerivation {
    namespace_key: SessionKey,
    storage_scope_commitment: [u8; 32],
    stable_device: GtpuSessionDeviceId,
    pin_commitment: [u8; 32],
}

#[derive(Clone, Copy)]
struct NamespaceBackendScope {
    storage_scope_commitment: [u8; 32],
    stable_device: GtpuSessionDeviceId,
    pin_commitment: [u8; 32],
}

impl From<&ProtectedSelectorLedgerDerivation> for NamespaceBackendScope {
    fn from(derivation: &ProtectedSelectorLedgerDerivation) -> Self {
        Self {
            storage_scope_commitment: derivation.storage_scope_commitment,
            stable_device: derivation.stable_device,
            pin_commitment: derivation.pin_commitment,
        }
    }
}

/// Derive the durable selector ledger entirely inside the SDK from a sealed
/// store base and an affine backend-minted namespace bootstrap. The lookup
/// key deliberately omits the live pin commitment so an existing permanent
/// ledger remains discoverable after bpffs remount; the first pin commitment
/// is instead immutably retained in its protected record and binding.
fn derive_protected_selector_ledger(
    base: ProtectedSelectorLedgerBase,
    bootstrap: GtpuSelectorNamespaceBootstrap,
) -> Result<ProtectedSelectorLedgerDerivation, GtpuSessionSelectorNamespaceError> {
    let stable_device = bootstrap.stable_device();
    let pin_commitment = bootstrap.pin_commitment();
    let protected_scope_commitment = base.protected_payload_scope_commitment();
    if pin_commitment == [0; 32] || protected_scope_commitment == [0; 32] {
        return Err(GtpuSessionSelectorNamespaceError::UnsuitableStore);
    }

    let mut seed = Vec::new();
    seed.push(1);
    append_len_prefixed(&mut seed, base.tenant().as_str().as_bytes());
    append_len_prefixed(&mut seed, base.nf_kind().as_str().as_bytes());
    append_len_prefixed(&mut seed, SELECTOR_LEDGER_KEY_TYPE.as_bytes());
    seed.extend_from_slice(&protected_scope_commitment);
    seed.extend_from_slice(&stable_device.to_bytes());
    let stable_id: [u8; 32] = Sha256::digest([STORAGE_KEY_DOMAIN, seed.as_slice()].concat()).into();
    let stable_id = StableId::new(bytes::Bytes::copy_from_slice(&stable_id))
        .map_err(|_| GtpuSessionSelectorNamespaceError::UnsuitableStore)?;
    let key_type = SessionKeyType::other(SELECTOR_LEDGER_KEY_TYPE)
        .map_err(|_| GtpuSessionSelectorNamespaceError::UnsuitableStore)?;
    let namespace_key = SessionKey {
        tenant: base.tenant().clone(),
        nf_kind: base.nf_kind().clone(),
        key_type,
        stable_id,
    };

    let mut scope = Vec::new();
    scope.push(1);
    append_len_prefixed(&mut scope, base.tenant().as_str().as_bytes());
    append_len_prefixed(&mut scope, base.nf_kind().as_str().as_bytes());
    append_len_prefixed(&mut scope, SELECTOR_LEDGER_KEY_TYPE.as_bytes());
    scope.extend_from_slice(namespace_key.stable_id.as_bytes());
    scope.extend_from_slice(&protected_scope_commitment);
    let storage_scope_commitment: [u8; 32] =
        Sha256::digest([STORAGE_SCOPE_DOMAIN, scope.as_slice()].concat()).into();
    (storage_scope_commitment != [0; 32])
        .then_some(ProtectedSelectorLedgerDerivation {
            namespace_key,
            storage_scope_commitment,
            stable_device,
            pin_commitment,
        })
        .ok_or(GtpuSessionSelectorNamespaceError::UnsuitableStore)
}

fn append_len_prefixed(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

/// Opaque candidate for binding one durable selector ledger to a stable
/// dataplane namespace.  It contains no selector material or secret.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GtpuSessionSelectorBackendBinding {
    stable_device: GtpuSessionDeviceId,
    pin_commitment: [u8; 32],
    ledger_id: [u8; 16],
    backend_epoch: [u8; 16],
    storage_scope_commitment: [u8; 32],
    selector_key_commitment: [u8; 32],
}

impl GtpuSessionSelectorBackendBinding {
    /// Stable backend namespace that this binding may control.
    #[must_use]
    pub const fn stable_device(self) -> GtpuSessionDeviceId {
        self.stable_device
    }

    /// Compare a backend's independently qualified pin commitment without
    /// exposing the commitment retained by the selector authority.
    #[must_use]
    pub fn matches_qualified_pin_commitment(self, candidate: [u8; 32]) -> bool {
        bool::from(self.pin_commitment.ct_eq(&candidate))
    }

    /// Expected opaque commitment to the canonical pinned eBPF namespace.
    /// The backend compares it to its currently qualified ownership before it
    /// trusts a marker, journal, or recovery readback.
    pub(crate) const fn pin_commitment(self) -> [u8; 32] {
        self.pin_commitment
    }

    pub(crate) const fn ledger_id(self) -> [u8; 16] {
        self.ledger_id
    }

    /// Durable namespace epoch. An old operation stamp is recoverable only
    /// while this exact epoch remains in the immutable backend binding.
    pub(crate) const fn backend_epoch(self) -> [u8; 16] {
        self.backend_epoch
    }

    pub(crate) const fn storage_scope_commitment(self) -> [u8; 32] {
        self.storage_scope_commitment
    }

    pub(crate) const fn selector_key_commitment(self) -> [u8; 32] {
        self.selector_key_commitment
    }
}

impl fmt::Debug for GtpuSessionSelectorBackendBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GtpuSessionSelectorBackendBinding(<redacted>)")
    }
}

/// SDK-minted, nonzero generation of one selector namespace claim.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GtpuSessionSelectorAuthorityGeneration(NonZeroU64);

impl GtpuSessionSelectorAuthorityGeneration {
    /// Return the monotonically increasing authority generation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl fmt::Debug for GtpuSessionSelectorAuthorityGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GtpuSessionSelectorAuthorityGeneration(<redacted>)")
    }
}

/// Bounded, non-identifying classification of a namespace admission failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum GtpuSessionSelectorNamespaceError {
    /// The requested generation is not the current namespace generation.
    #[error("selector namespace generation is stale")]
    StaleGeneration,
    /// The group identity has already been bound by a prior claim.
    #[error("selector namespace group is already claimed")]
    GroupClaimed,
    /// At least one canonical selector atom is still active elsewhere.
    #[error("selector namespace selector is already active")]
    SelectorClaimed,
    /// The operation could not prove that the namespace state was complete.
    #[error("selector namespace state is indeterminate")]
    Indeterminate,
    /// The monotonic generation cannot advance further.
    #[error("selector namespace generation is exhausted")]
    GenerationExhausted,
    /// The durable namespace was initialized for another device or authority
    /// configuration.
    #[error("selector namespace configuration differs")]
    ConfigurationMismatch,
    /// A per-operation atom bound or a permanent durable-record bound was
    /// exceeded. The persisted operation bound is not a namespace-wide atom
    /// quota.
    #[error("selector namespace operation or durable capacity is exhausted")]
    CapacityExhausted,
    /// The selected store cannot provide the durable authority contract.
    #[error("selector namespace durable store is unsuitable")]
    UnsuitableStore,
    /// No permanent stopped-installation selector ledger exists for this
    /// protected scope and stable device. Normal runtime never treats this as
    /// a virgin namespace.
    #[error("selector namespace is not provisioned")]
    Unprovisioned,
}

/// Bounded result of an SDK-owned selector lifecycle operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum GtpuSessionSelectorCoordinatorError {
    /// The durable authority could not establish a safe lifecycle state.
    #[error("selector namespace lifecycle is indeterminate")]
    Namespace,
    /// The backend did not confirm the exact requested dataplane state.
    #[error("selector namespace backend operation was not confirmed")]
    Backend,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DecommissionAttempt {
    Retry,
    Complete,
}

/// Result of the one durable false-to-true backend-supervisor handoff.
///
/// A worker that observes `AlreadyStarted` after independently proving the
/// pre-effect state lost the handoff race. It may read final state, but must
/// not use that stale negative proof to enter the affine backend effect.
enum BackendStartHandoff {
    Transitioned(GtpuSessionSelectorAdmission),
    AlreadyStarted(GtpuSessionSelectorAdmission),
}

/// Affine capability emitted only after an exact Retiring→Retired completion.
///
/// It identifies one permanently retired source graph and preserves the
/// SDK-issued terminal stamp coordinate. It is not itself a reuse permission:
/// a backend must still attest the required drain or RCU barrier.
#[must_use = "a retired selector claim must be consumed by backend quiescence authorization"]
pub struct GtpuSessionSelectorRetiredClaim {
    group: GtpuSessionGroup,
    admission: GtpuSessionSelectorAdmission,
}

impl fmt::Debug for GtpuSessionSelectorRetiredClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GtpuSessionSelectorRetiredClaim(<redacted>)")
    }
}

/// Opaque backend request to attest quiescence for one exact retired source
/// before its selectors may be reused by one exact successor graph.
pub struct GtpuSessionSelectorReuseRequest {
    retired: GtpuSessionSelectorRetiredClaim,
    desired: GtpuSessionGroup,
}

impl GtpuSessionSelectorReuseRequest {
    /// Exact retired source graph whose terminal stamp must be verified.
    #[must_use]
    pub const fn retired_group(&self) -> &GtpuSessionGroup {
        &self.retired.group
    }

    /// Exact successor graph that this one authorization may permit.
    #[must_use]
    pub const fn desired_group(&self) -> &GtpuSessionGroup {
        &self.desired
    }

    /// Opaque backend binding lease for this exact retired source. Backends
    /// may inspect its stable device and validate a locally-qualified pin
    /// commitment, but never receive selector bytes or the selector key.
    #[must_use]
    pub const fn binding(&self) -> GtpuSessionSelectorBackendBinding {
        self.retired.admission.binding()
    }

    /// Verify a raw selector-stamp value as the exact terminal-retired stamp
    /// for this source coordinate. This is intentionally the only public
    /// stamp verifier: callers cannot request a pending or terminal stamp for
    /// another generation, source, or namespace.
    #[must_use]
    pub fn verifies_exact_terminal_retired_stamp(
        &self,
        stamp: &[u8; GTPU_SESSION_SELECTOR_STAMP_VALUE_LEN],
    ) -> bool {
        verifies_terminal_retired_stamp(&self.retired.admission, stamp)
    }

    /// Complete this one request after the backend has proved exact terminal
    /// retirement, authoritative absence, and a trusted drain/RCU barrier.
    /// The receipt cannot be constructed independently of this request.
    pub fn confirm_traffic_drained(self) -> GtpuSessionSelectorReuseReceipt {
        GtpuSessionSelectorReuseReceipt {
            retired: self.retired,
            desired: self.desired,
            evidence: crate::GtpuSessionSelectorReuseEvidence::TrafficDrained,
        }
    }

    /// Complete this one request after the backend has proved exact terminal
    /// retirement, authoritative absence, and a completed RCU grace period.
    pub fn confirm_rcu_grace_period(self) -> GtpuSessionSelectorReuseReceipt {
        GtpuSessionSelectorReuseReceipt {
            retired: self.retired,
            desired: self.desired,
            evidence: crate::GtpuSessionSelectorReuseEvidence::RcuGracePeriodElapsed,
        }
    }
}

impl fmt::Debug for GtpuSessionSelectorReuseRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GtpuSessionSelectorReuseRequest(<redacted>)")
    }
}

fn verifies_terminal_retired_stamp(
    admission: &GtpuSessionSelectorAdmission,
    stamp: &[u8; GTPU_SESSION_SELECTOR_STAMP_VALUE_LEN],
) -> bool {
    let dataplane_generation = u64::from_be_bytes(match stamp[192..200].try_into() {
        Ok(generation) if generation != [0; 8] => generation,
        _ => return false,
    });
    let binding = admission.binding();
    let mut expected = [0_u8; GTPU_SESSION_SELECTOR_STAMP_VALUE_LEN];
    expected[0] = 1;
    expected[1] = 4; // Retired
    expected[2] = 2; // Remove
    expected[3] = 3; // Absent
    expected[8..16].copy_from_slice(&admission.terminal_generation().get().to_be_bytes());
    expected[16..32].copy_from_slice(&admission.terminal_operation_nonce());
    expected[32..48].copy_from_slice(&binding.backend_epoch());
    expected[64..96].copy_from_slice(&binding.storage_scope_commitment());
    expected[96..128].copy_from_slice(&admission.group_fingerprint());
    expected[128..160].copy_from_slice(&admission.selector_set_fingerprint());
    expected[160..192].copy_from_slice(&admission.desired_fingerprint());
    expected[192..200].copy_from_slice(&dataplane_generation.to_be_bytes());
    bool::from(expected.ct_eq(stamp))
}

/// Opaque receipt minted only by consuming one SDK-issued quiescence request.
#[must_use = "a reuse receipt must be consumed by reconciliation"]
pub struct GtpuSessionSelectorReuseReceipt {
    retired: GtpuSessionSelectorRetiredClaim,
    desired: GtpuSessionGroup,
    evidence: crate::GtpuSessionSelectorReuseEvidence,
}

impl fmt::Debug for GtpuSessionSelectorReuseReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GtpuSessionSelectorReuseReceipt(<redacted>)")
    }
}

/// SDK-verified one-successor reuse authorization. This consumes the backend
/// receipt, so public callers cannot forge a selector reuse proof.
#[must_use = "a reuse authorization must be consumed by reconciliation"]
pub struct GtpuSessionSelectorReuseAuthorization {
    desired: GtpuSessionGroup,
    proof: crate::GtpuSessionSelectorReuseProof,
}

/// An opaque lease over one immutable selector namespace binding. It can be
/// consumed only by a backend to confirm the exact binding it acquired.
#[must_use = "a selector binding lease must be consumed by a backend receipt"]
pub struct GtpuSessionSelectorBindingLease {
    binding: GtpuSessionSelectorBackendBinding,
}

impl GtpuSessionSelectorBindingLease {
    /// Immutable backend namespace binding being leased.
    #[must_use]
    pub const fn binding(&self) -> GtpuSessionSelectorBackendBinding {
        self.binding
    }

    /// Mint a receipt only after the backend has acquired the exact binding.
    pub fn confirm(self) -> GtpuSessionSelectorBackendReceipt {
        GtpuSessionSelectorBackendReceipt::binding_confirmed()
    }
}

/// Opaque stopped-installation request for the exact immutable binding.
#[must_use = "a selector provisioning request must be consumed by a backend receipt"]
pub struct GtpuSessionSelectorProvisionRequest {
    binding: GtpuSessionSelectorBackendBinding,
}

impl GtpuSessionSelectorProvisionRequest {
    /// Immutable backend namespace binding being provisioned.
    #[must_use]
    pub const fn binding(&self) -> GtpuSessionSelectorBackendBinding {
        self.binding
    }

    /// Mint a receipt only after complete empty-inventory proof, marker write,
    /// and exact marker readback under the backend's exclusive effect lease.
    pub fn confirm(self) -> GtpuSessionSelectorBackendReceipt {
        GtpuSessionSelectorBackendReceipt::provisioned()
    }
}

/// Opaque install/reconcile request issued from one exact Installing
/// coordinate. Backends can inspect its complete semantic graph and binding,
/// but cannot construct an equivalent request or mint another coordinate.
#[must_use = "a selector effect request must be consumed by a backend receipt"]
pub struct GtpuSessionSelectorEffectRequest {
    request: GtpuSessionGroupReconcileRequest,
}

impl GtpuSessionSelectorEffectRequest {
    /// Complete semantic graph to converge.
    #[must_use]
    pub const fn desired_group(&self) -> &GtpuSessionGroup {
        self.request.desired()
    }

    /// Opaque immutable namespace binding for this effect.
    #[must_use]
    pub const fn binding(&self) -> GtpuSessionSelectorBackendBinding {
        self.request.selector_backend_binding()
    }

    /// Consume the exact request into the corresponding classified receipt.
    pub fn complete(
        self,
        outcome: GtpuSessionGroupReconcileOutcome,
    ) -> GtpuSessionSelectorBackendReceipt {
        GtpuSessionSelectorBackendReceipt::effect(outcome)
    }

    pub(crate) fn into_inner(self) -> GtpuSessionGroupReconcileRequest {
        self.request
    }
}

/// Opaque authorized readback request for one lifecycle coordinate.
#[must_use = "an authorized readback request must be consumed by a backend receipt"]
pub struct GtpuSessionSelectorReadbackRequest {
    expected: GtpuSessionGroup,
    admission: GtpuSessionSelectorAdmission,
}

impl GtpuSessionSelectorReadbackRequest {
    /// Semantic graph whose exact authorized state is requested.
    #[must_use]
    pub const fn expected_group(&self) -> &GtpuSessionGroup {
        &self.expected
    }

    /// Immutable backend namespace binding for this readback.
    #[must_use]
    pub const fn binding(&self) -> GtpuSessionSelectorBackendBinding {
        self.admission.binding()
    }

    /// Consume the request into the backend's exact classified readback.
    pub fn complete(
        self,
        readback: crate::GtpuSessionGroupReadback,
    ) -> GtpuSessionSelectorBackendReceipt {
        GtpuSessionSelectorBackendReceipt::readback(readback)
    }

    pub(crate) fn into_inner(self) -> (GtpuSessionGroup, GtpuSessionSelectorAdmission) {
        (self.expected, self.admission)
    }
}

/// Opaque authorized removal request for one exact Retiring coordinate.
#[must_use = "a selector removal request must be consumed by a backend receipt"]
pub struct GtpuSessionSelectorRemovalRequest {
    expected: GtpuSessionGroup,
    admission: GtpuSessionSelectorAdmission,
}

impl GtpuSessionSelectorRemovalRequest {
    /// Semantic graph whose exact removal is requested.
    #[must_use]
    pub const fn expected_group(&self) -> &GtpuSessionGroup {
        &self.expected
    }

    /// Immutable backend namespace binding for this removal.
    #[must_use]
    pub const fn binding(&self) -> GtpuSessionSelectorBackendBinding {
        self.admission.binding()
    }

    /// Consume the request into the backend's classified removal receipt.
    pub fn complete(
        self,
        outcome: GtpuSessionGroupRemovalOutcome,
    ) -> GtpuSessionSelectorBackendReceipt {
        GtpuSessionSelectorBackendReceipt::removal(outcome)
    }

    pub(crate) fn into_inner(self) -> (GtpuSessionGroup, GtpuSessionSelectorAdmission) {
        (self.expected, self.admission)
    }
}

/// Opaque terminal-fence inspection request.
///
/// Before the durable decommission precommit this requires the capsule to be
/// absent. Once a terminal coordinate is persisted it instead accepts only
/// that exact capsule. Any other retained capsule is an indeterminate
/// authority conflict, never a replacement coordinate.
#[must_use = "a selector terminal-fence inspection request must be consumed by a backend receipt"]
pub struct GtpuSessionSelectorDecommissionInspectRequest {
    binding: GtpuSessionSelectorBackendBinding,
    expected_fence: Option<DecommissionFence>,
}

impl GtpuSessionSelectorDecommissionInspectRequest {
    /// Immutable namespace binding whose terminal capsule is inspected.
    #[must_use]
    pub const fn binding(&self) -> GtpuSessionSelectorBackendBinding {
        self.binding
    }

    /// The exact persisted terminal capsule when recovery is in progress.
    /// `None` means this is the precommit absence check.
    #[must_use]
    pub fn expected_terminal_marker_payload(&self) -> Option<[u8; 57]> {
        self.expected_fence.map(DecommissionFence::marker_payload)
    }

    /// Consume this request after proving no terminal capsule exists.
    pub fn confirm_absent(self) -> GtpuSessionSelectorBackendReceipt {
        GtpuSessionSelectorBackendReceipt::decommission_fence_absent()
    }

    /// Consume this request after proving the persisted terminal capsule is
    /// byte-for-byte exact.
    pub fn confirm_exact(self) -> GtpuSessionSelectorBackendReceipt {
        GtpuSessionSelectorBackendReceipt::decommission_fence_exact()
    }
}

/// Opaque terminal namespace-decommission creation request.
///
/// The request is issued only after the durable ledger has precommitted a
/// nonzero terminal coordinate. A backend must preserve that exact coordinate
/// and its keyed marker commitment in any permanent decommission fence; a
/// binding-only marker cannot be used to recover or roll back this state.
#[must_use = "a selector decommission request must be consumed by a backend receipt"]
pub struct GtpuSessionSelectorDecommissionRequest {
    binding: GtpuSessionSelectorBackendBinding,
    fence: DecommissionFence,
}

impl GtpuSessionSelectorDecommissionRequest {
    /// Immutable namespace binding being permanently decommissioned.
    #[must_use]
    pub const fn binding(&self) -> GtpuSessionSelectorBackendBinding {
        self.binding
    }

    /// Verify a backend-observed terminal marker commitment without exposing
    /// the selector key or allowing a caller to mint another terminal fence.
    #[must_use]
    pub fn matches_terminal_marker_commitment(&self, candidate: [u8; 32]) -> bool {
        bool::from(self.fence.marker_commitment.ct_eq(&candidate))
    }

    /// Return the versioned, authenticated terminal marker payload that an
    /// external backend persists. It carries the exact precommitted terminal
    /// generation and nonce as well as their binding/keyed authentication;
    /// no selector bytes or selector secret are exposed.
    #[must_use]
    pub fn terminal_marker_payload(&self) -> [u8; 57] {
        self.fence.marker_payload()
    }

    /// Validate a backend-read terminal marker payload for this exact opaque
    /// decommission request.
    #[must_use]
    pub fn verifies_terminal_marker_payload(&self, payload: &[u8; 57]) -> bool {
        bool::from(self.terminal_marker_payload().ct_eq(payload))
    }

    /// Consume the request only after an exact terminal capsule containing the
    /// committed coordinate has been durably created and read back.
    pub fn confirm(self) -> GtpuSessionSelectorBackendReceipt {
        GtpuSessionSelectorBackendReceipt::decommission_fence_exact()
    }
}

/// Opaque exact terminal-fence readback request.
///
/// This is issued after a backend creates a terminal capsule and again when a
/// recovered terminal ledger is about to be accepted. It permits only the
/// exact durable coordinate already precommitted by the selector authority.
#[must_use = "a selector terminal-fence readback request must be consumed by a backend receipt"]
pub struct GtpuSessionSelectorDecommissionReadbackRequest {
    binding: GtpuSessionSelectorBackendBinding,
    fence: DecommissionFence,
}

impl GtpuSessionSelectorDecommissionReadbackRequest {
    /// Immutable namespace binding whose terminal capsule is read back.
    #[must_use]
    pub const fn binding(&self) -> GtpuSessionSelectorBackendBinding {
        self.binding
    }

    /// Expected versioned terminal capsule bytes.
    #[must_use]
    pub fn terminal_marker_payload(&self) -> [u8; 57] {
        self.fence.marker_payload()
    }

    /// Validate a backend-read terminal capsule for this exact request.
    #[must_use]
    pub fn verifies_terminal_marker_payload(&self, payload: &[u8; 57]) -> bool {
        bool::from(self.terminal_marker_payload().ct_eq(payload))
    }

    /// Consume the request after an exact durable capsule readback.
    pub fn confirm_exact(self) -> GtpuSessionSelectorBackendReceipt {
        GtpuSessionSelectorBackendReceipt::decommission_fence_exact()
    }
}

/// SDK-minted result of consuming one opaque selector backend request.
///
/// The classification is private: only consuming the matching affine request
/// (or an in-crate backend adapter that owns it) can mint a receipt. This
/// prevents a third-party backend from fabricating an `Activated`, `Absent`,
/// or binding confirmation without first receiving authority for that exact
/// operation.
#[must_use = "selector backend receipts must be verified by the SDK authority"]
pub struct GtpuSessionSelectorBackendReceipt {
    kind: SelectorBackendReceiptKind,
}

enum SelectorBackendReceiptKind {
    BindingConfirmed,
    Provisioned,
    DecommissionFenceAbsent,
    DecommissionFenceExact,
    Effect(GtpuSessionGroupReconcileOutcome),
    Readback(crate::GtpuSessionGroupReadback),
    Removal(GtpuSessionGroupRemovalOutcome),
}

impl GtpuSessionSelectorBackendReceipt {
    pub(crate) const fn binding_confirmed() -> Self {
        Self {
            kind: SelectorBackendReceiptKind::BindingConfirmed,
        }
    }

    pub(crate) const fn provisioned() -> Self {
        Self {
            kind: SelectorBackendReceiptKind::Provisioned,
        }
    }

    pub(crate) const fn decommission_fence_absent() -> Self {
        Self {
            kind: SelectorBackendReceiptKind::DecommissionFenceAbsent,
        }
    }

    pub(crate) const fn decommission_fence_exact() -> Self {
        Self {
            kind: SelectorBackendReceiptKind::DecommissionFenceExact,
        }
    }

    pub(crate) const fn effect(outcome: GtpuSessionGroupReconcileOutcome) -> Self {
        Self {
            kind: SelectorBackendReceiptKind::Effect(outcome),
        }
    }

    pub(crate) const fn readback(readback: crate::GtpuSessionGroupReadback) -> Self {
        Self {
            kind: SelectorBackendReceiptKind::Readback(readback),
        }
    }

    pub(crate) const fn removal(outcome: GtpuSessionGroupRemovalOutcome) -> Self {
        Self {
            kind: SelectorBackendReceiptKind::Removal(outcome),
        }
    }

    pub(crate) fn confirms_binding(&self) -> bool {
        matches!(self.kind, SelectorBackendReceiptKind::BindingConfirmed)
    }

    pub(crate) fn confirms_provisioning(&self) -> bool {
        matches!(self.kind, SelectorBackendReceiptKind::Provisioned)
    }

    pub(crate) fn confirms_decommission_fence_absent(&self) -> bool {
        matches!(
            self.kind,
            SelectorBackendReceiptKind::DecommissionFenceAbsent
        )
    }

    pub(crate) fn confirms_decommission_fence_exact(&self) -> bool {
        matches!(
            self.kind,
            SelectorBackendReceiptKind::DecommissionFenceExact
        )
    }

    pub(crate) fn into_effect(self) -> Option<GtpuSessionGroupReconcileOutcome> {
        match self.kind {
            SelectorBackendReceiptKind::Effect(outcome) => Some(outcome),
            _ => None,
        }
    }

    pub(crate) fn into_readback(self) -> Option<crate::GtpuSessionGroupReadback> {
        match self.kind {
            SelectorBackendReceiptKind::Readback(readback) => Some(readback),
            _ => None,
        }
    }

    pub(crate) fn into_removal(self) -> Option<GtpuSessionGroupRemovalOutcome> {
        match self.kind {
            SelectorBackendReceiptKind::Removal(outcome) => Some(outcome),
            _ => None,
        }
    }
}

impl fmt::Debug for GtpuSessionSelectorBackendReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GtpuSessionSelectorBackendReceipt(<redacted>)")
    }
}

impl fmt::Debug for GtpuSessionSelectorReuseAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GtpuSessionSelectorReuseAuthorization(<redacted>)")
    }
}

/// Result receiver for one SDK-owned selector namespace worker.
///
/// Dropping this value only stops observing the result. The worker retains its
/// store, backend handle, admission, and namespace permit until it reaches a
/// terminal result; it is never represented by a caller-owned join handle.
#[must_use = "dropping the receiver does not cancel the selector namespace worker"]
pub struct GtpuSessionSelectorOperation<T, E = GtpuSessionSelectorCoordinatorError> {
    receiver: tokio::sync::oneshot::Receiver<Result<T, E>>,
    closed_error: E,
}

impl<T, E> Unpin for GtpuSessionSelectorOperation<T, E> {}

impl<T, E> fmt::Debug for GtpuSessionSelectorOperation<T, E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GtpuSessionSelectorOperation(<detached>)")
    }
}

impl<T, E: Clone> Future for GtpuSessionSelectorOperation<T, E> {
    type Output = Result<T, E>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match Pin::new(&mut this.receiver).poll(context) {
            Poll::Ready(Ok(result)) => Poll::Ready(result),
            // A worker must send a result before it exits. A closed channel is
            // therefore an internal containment failure, not an invitation to
            // guess dataplane state.
            Poll::Ready(Err(_)) => Poll::Ready(Err(this.closed_error.clone())),
            Poll::Pending => Poll::Pending,
        }
    }
}

static SELECTOR_PROCESS_SUPERVISORS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
static SELECTOR_NAMESPACE_SUPERVISORS: OnceLock<
    Mutex<BTreeMap<[u8; 32], Weak<tokio::sync::Semaphore>>>,
> = OnceLock::new();

fn selector_process_supervisors() -> Arc<tokio::sync::Semaphore> {
    SELECTOR_PROCESS_SUPERVISORS
        .get_or_init(|| {
            Arc::new(tokio::sync::Semaphore::new(
                SELECTOR_NAMESPACE_MAX_SUPERVISORS_PER_PROCESS,
            ))
        })
        .clone()
}

fn selector_namespace_supervisors(
    storage_scope_commitment: [u8; 32],
) -> Arc<tokio::sync::Semaphore> {
    let registry = SELECTOR_NAMESPACE_SUPERVISORS.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut registry = registry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    registry.retain(|_, semaphore| semaphore.strong_count() != 0);
    if let Some(existing) = registry
        .get(&storage_scope_commitment)
        .and_then(Weak::upgrade)
    {
        return existing;
    }
    let semaphore = Arc::new(tokio::sync::Semaphore::new(
        SELECTOR_NAMESPACE_MAX_SUPERVISORS_PER_NAMESPACE,
    ));
    registry.insert(storage_scope_commitment, Arc::downgrade(&semaphore));
    semaphore
}

fn spawn_selector_operation<T, E, F>(
    storage_scope_commitment: [u8; 32],
    runtime_error: E,
    worker: F,
) -> GtpuSessionSelectorOperation<T, E>
where
    T: Send + 'static,
    E: Clone + Send + 'static,
    F: Future<Output = Result<T, E>> + Send + 'static,
{
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let process_permits = selector_process_supervisors();
    let namespace_permits = selector_namespace_supervisors(storage_scope_commitment);
    let closed_error = runtime_error.clone();
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            handle.spawn(async move {
                // Both permits are owned by the detached worker, rather than
                // the caller. Waiting for capacity therefore cannot be
                // cancelled by dropping the returned receiver.
                let process_permit = process_permits.acquire_owned().await;
                let namespace_permit = namespace_permits.acquire_owned().await;
                let result = match (process_permit, namespace_permit) {
                    (Ok(_), Ok(_)) => worker.await,
                    _ => Err(runtime_error),
                };
                let _ = sender.send(result);
            });
        }
        Err(_) => {
            let _ = sender.send(Err(runtime_error));
        }
    }
    GtpuSessionSelectorOperation {
        receiver,
        closed_error,
    }
}

/// An opaque, affine SDK admission for one exact grouped selector graph.
///
/// This value has no public constructor and deliberately does not implement
/// [`Clone`].  It binds the stable device namespace, group identity, complete
/// canonical selector set, and authority generation.  Move it into
/// [`crate::GtpuSessionGroupReconcileRequest`]; a stale or cross-boundary
/// admission is rejected before any dataplane mutation.
///
/// ```compile_fail
/// use opc_gtpu_dataplane::GtpuSessionSelectorAdmission;
///
/// fn forge() -> GtpuSessionSelectorAdmission {
///     GtpuSessionSelectorAdmission {}
/// }
/// ```
pub struct GtpuSessionSelectorAdmission {
    binding: GtpuSessionSelectorBackendBinding,
    // The authority derives commitments only while issuing or consuming this
    // affine permit.  It is deliberately private and zeroized when the
    // permit is consumed or dropped; callers and backend adapters receive
    // commitments, never raw selector material or this key.
    selector_digest_key: Zeroizing<[u8; 32]>,
    device_fingerprint: [u8; 32],
    group_fingerprint: [u8; 32],
    selector_set_fingerprint: [u8; 32],
    desired_fingerprint: [u8; 32],
    /// Coordinate of the pending backend mutation.  The terminal coordinate
    /// is minted in the same durable CAS but is intentionally distinct.
    generation: GtpuSessionSelectorAuthorityGeneration,
    operation_nonce: [u8; 16],
    terminal_generation: GtpuSessionSelectorAuthorityGeneration,
    terminal_operation_nonce: [u8; 16],
    previous_terminal: Option<SelectorAuthorityCoordinate>,
    phase: SelectorAdmissionPhase,
    retired_reissue: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SelectorAdmissionPhase {
    Installing,
    Active,
    Retiring,
    Retired,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct SelectorAuthorityCoordinate {
    generation: GtpuSessionSelectorAuthorityGeneration,
    nonce: [u8; 16],
}

/// Persisted terminal coordinate for one namespace-wide decommission.
///
/// `marker_commitment` authenticates the binding and exact coordinate with
/// the durable selector key. It is intentionally opaque outside this module.
#[derive(Clone, Copy, PartialEq, Eq)]
struct DecommissionFence {
    terminal: SelectorAuthorityCoordinate,
    marker_commitment: [u8; 32],
}

impl DecommissionFence {
    fn marker_payload(self) -> [u8; 57] {
        let mut payload = [0_u8; 57];
        payload[0] = 1;
        payload[1..9].copy_from_slice(&self.terminal.generation.get().to_be_bytes());
        payload[9..25].copy_from_slice(&self.terminal.nonce);
        payload[25..57].copy_from_slice(&self.marker_commitment);
        payload
    }
}

impl GtpuSessionSelectorAdmission {
    /// Return the SDK-minted authority generation without exposing selectors.
    #[must_use]
    pub const fn generation(&self) -> GtpuSessionSelectorAuthorityGeneration {
        self.generation
    }

    /// Internal only: the backend consumes this binding under its exclusive
    /// effect lease.  It never exposes selector material or the digest key.
    pub(crate) const fn binding(&self) -> GtpuSessionSelectorBackendBinding {
        self.binding
    }

    /// Exact opaque operation nonce consumed by the dataplane operation stamp.
    pub(crate) const fn operation_nonce(&self) -> [u8; 16] {
        self.operation_nonce
    }

    pub(crate) const fn terminal_generation(&self) -> GtpuSessionSelectorAuthorityGeneration {
        self.terminal_generation
    }

    pub(crate) const fn terminal_operation_nonce(&self) -> [u8; 16] {
        self.terminal_operation_nonce
    }

    pub(crate) const fn previous_terminal_generation(
        &self,
    ) -> Option<GtpuSessionSelectorAuthorityGeneration> {
        match self.previous_terminal {
            Some(coordinate) => Some(coordinate.generation),
            None => None,
        }
    }

    pub(crate) const fn previous_terminal_nonce(&self) -> Option<[u8; 16]> {
        match self.previous_terminal {
            Some(coordinate) => Some(coordinate.nonce),
            None => None,
        }
    }

    pub(crate) const fn group_fingerprint(&self) -> [u8; 32] {
        self.group_fingerprint
    }

    pub(crate) const fn selector_set_fingerprint(&self) -> [u8; 32] {
        self.selector_set_fingerprint
    }

    pub(crate) const fn desired_fingerprint(&self) -> [u8; 32] {
        self.desired_fingerprint
    }

    pub(crate) fn validates(&self, group: &GtpuSessionGroup) -> bool {
        let Some(canonical) = CanonicalClaim::from_group(group).with_key(&self.selector_digest_key)
        else {
            return false;
        };
        self.binding.stable_device() == group.device_id()
            && self.binding.pin_commitment() != [0; 32]
            && self.binding.ledger_id() != [0; 16]
            && self.binding.backend_epoch() != [0; 16]
            && self.binding.selector_key_commitment() != [0; 32]
            && self.device_fingerprint == canonical.device_fingerprint
            && self.group_fingerprint == canonical.group_fingerprint
            && self.selector_set_fingerprint == canonical.selector_set_fingerprint
            && self.desired_fingerprint == canonical.desired_fingerprint
    }

    pub(crate) const fn is_retired_reissue(&self) -> bool {
        self.retired_reissue
    }

    fn with_coordinates(
        &self,
        generation: GtpuSessionSelectorAuthorityGeneration,
        operation_nonce: [u8; 16],
        terminal: SelectorAuthorityCoordinate,
        previous_terminal: Option<SelectorAuthorityCoordinate>,
        phase: SelectorAdmissionPhase,
    ) -> Result<Self, GtpuSessionSelectorNamespaceError> {
        if operation_nonce == [0; 16] || terminal.nonce == [0; 16] {
            return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
        }
        let terminal_is_current =
            terminal.generation == generation && terminal.nonce == operation_nonce;
        match phase {
            SelectorAdmissionPhase::Installing => {
                if terminal.generation.get() <= generation.get() || previous_terminal.is_some() {
                    return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
                }
            }
            SelectorAdmissionPhase::Retiring => {
                if terminal.generation.get() <= generation.get()
                    || !previous_terminal.is_some_and(|prior| {
                        prior.generation.get() < generation.get() && prior.nonce != [0; 16]
                    })
                {
                    return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
                }
            }
            SelectorAdmissionPhase::Active | SelectorAdmissionPhase::Retired => {
                if !terminal_is_current || previous_terminal.is_some() {
                    return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
                }
            }
        }
        Ok(Self {
            binding: self.binding,
            selector_digest_key: Zeroizing::new(*self.selector_digest_key),
            device_fingerprint: self.device_fingerprint,
            group_fingerprint: self.group_fingerprint,
            selector_set_fingerprint: self.selector_set_fingerprint,
            desired_fingerprint: self.desired_fingerprint,
            generation,
            operation_nonce,
            terminal_generation: terminal.generation,
            terminal_operation_nonce: terminal.nonce,
            previous_terminal,
            phase,
            retired_reissue: self.retired_reissue,
        })
    }
}

impl fmt::Debug for GtpuSessionSelectorAdmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GtpuSessionSelectorAdmission")
            .field("generation", &"<redacted>")
            .field("phase", &self.phase)
            .field("bound_selector_count", &"<redacted>")
            .finish()
    }
}

/// An atomic selector namespace authority suitable for deterministic tests and
/// single-process adapters.
///
/// Production adapters must keep an equivalent complete state machine in one
/// durable compare-and-swap transaction.  In particular, the normal
/// `opc-session-store` sequential batch API is not sufficient: all atom
/// claims, group binding, tombstones, and the generation must commit together
/// or remain unchanged.  A process-loss recovery adapter must read back the
/// exact mutation fingerprint and leave ambiguous mutations poisoned rather
/// than guessing.
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct InMemoryGtpuSessionSelectorNamespace {
    state: Arc<Mutex<NamespaceState>>,
    key: [u8; 32],
}

#[cfg(test)]
impl Default for InMemoryGtpuSessionSelectorNamespace {
    fn default() -> Self {
        Self::new([0x53; 32])
    }
}

#[cfg(test)]
impl InMemoryGtpuSessionSelectorNamespace {
    /// Construct a deterministic atomic model with domain-separated keyed
    /// selector digests.  The key is authority material and is never exposed
    /// in diagnostics; production adapters obtain it from their secret store.
    #[must_use]
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            state: Arc::new(Mutex::new(NamespaceState::default())),
            key,
        }
    }

    /// Atomically claim every selector atom in `group`.
    ///
    /// A group can be claimed once only.  Every atom must be either
    /// never-published or already retired; active, retiring, poisoned, or
    /// partially known atoms fail closed.  `expected_generation`, when set,
    /// supplies CAS recovery and is never used to mint a generation.
    pub fn claim(
        &self,
        group: &GtpuSessionGroup,
        expected_generation: Option<GtpuSessionSelectorAuthorityGeneration>,
    ) -> Result<GtpuSessionSelectorAdmission, GtpuSessionSelectorNamespaceError> {
        let claim = CanonicalClaim::from_group(group)
            .with_key(&self.key)
            .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
        if let Some(expected) = expected_generation {
            if state.generation != expected.get() {
                return Err(GtpuSessionSelectorNamespaceError::StaleGeneration);
            }
        }
        if state.groups.contains_key(&claim.group_fingerprint) {
            return Err(GtpuSessionSelectorNamespaceError::GroupClaimed);
        }
        let atoms = claim
            .selector_atoms(&self.key)
            .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
        if atoms.iter().any(|atom| {
            state.selectors.contains_key(atom)
                || state.published_atoms.contains(atom)
                || state.tombstones.contains(atom)
        }) {
            return Err(GtpuSessionSelectorNamespaceError::SelectorClaimed);
        }
        state.bind_or_validate(
            group.device_id(),
            SELECTOR_NAMESPACE_MAX_READBACK_ATOMS,
            Some(self.key),
        )?;
        let generation = state.next_generation()?;
        let operation_nonce = test_nonzero_nonce(&self.key, claim.group_fingerprint, generation)?;
        let admission = state.issue_admission(
            test_storage_scope_commitment(&self.key),
            &claim,
            generation,
            operation_nonce,
            SelectorAdmissionPhase::Active,
            false,
        )?;
        for atom in &atoms {
            state.selectors.insert(
                *atom,
                SelectorState::Active {
                    group: claim.group_fingerprint,
                    generation,
                },
            );
            state.published_atoms.insert(*atom);
        }
        state.groups.insert(
            claim.group_fingerprint,
            GroupState::Active {
                device: claim.device_fingerprint,
                selectors: claim.selector_set_fingerprint,
                desired: claim.desired_fingerprint,
                atoms,
                generation,
                operation_nonce: admission.operation_nonce,
            },
        );
        Ok(admission)
    }

    /// Atomically admit the exact complete selector set of a permanently
    /// retired source group.  This is deliberately distinct from `claim`:
    /// ordinary fresh admission rejects every selector that has ever appeared.
    pub fn claim_reused(
        &self,
        desired: &GtpuSessionGroup,
        proof: &crate::GtpuSessionSelectorReuseProof,
    ) -> Result<GtpuSessionSelectorAdmission, GtpuSessionSelectorNamespaceError> {
        let claim = CanonicalClaim::from_group(desired)
            .with_key(&self.key)
            .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
        let source = CanonicalClaim::from_group(proof.retired_group())
            .with_key(&self.key)
            .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
        if desired.device_id() != proof.retired_group().device_id()
            || desired.id() == proof.retired_group().id()
            || claim.selector_set_fingerprint != source.selector_set_fingerprint
        {
            return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
        }
        let atoms = claim
            .selector_atoms(&self.key)
            .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
        if state.groups.contains_key(&claim.group_fingerprint)
            || !matches!(
                state.groups.get(&source.group_fingerprint),
                Some(GroupState::Retired { device, selectors, desired: source_desired, atoms: source_atoms, successor: None, .. })
                    if *device == source.device_fingerprint
                        && *selectors == source.selector_set_fingerprint
                        && *source_desired == source.desired_fingerprint
                        && *source_atoms == atoms
            )
            || !atoms
                .iter()
                .all(|atom| matches!(state.selectors.get(atom), Some(SelectorState::Retired)))
        {
            return Err(GtpuSessionSelectorNamespaceError::SelectorClaimed);
        }
        let Some(GroupState::Retired {
            device,
            selectors,
            desired: source_desired,
            atoms: source_atoms,
            generation: source_generation,
            operation_nonce: source_nonce,
            successor: None,
        }) = state.groups.get(&source.group_fingerprint).cloned()
        else {
            return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
        };
        let generation = state.next_generation()?;
        let operation_nonce = test_nonzero_nonce(&self.key, claim.group_fingerprint, generation)?;
        state.groups.insert(
            source.group_fingerprint,
            GroupState::Retired {
                device,
                selectors,
                desired: source_desired,
                atoms: source_atoms,
                generation: source_generation,
                operation_nonce: source_nonce,
                successor: Some(RetiredSuccessor {
                    group: claim.group_fingerprint,
                    generation,
                }),
            },
        );
        for atom in &atoms {
            state.selectors.insert(
                *atom,
                SelectorState::Active {
                    group: claim.group_fingerprint,
                    generation,
                },
            );
            state.published_atoms.insert(*atom);
        }
        state.groups.insert(
            claim.group_fingerprint,
            GroupState::Active {
                device: claim.device_fingerprint,
                selectors: claim.selector_set_fingerprint,
                desired: claim.desired_fingerprint,
                atoms,
                generation,
                operation_nonce,
            },
        );
        state.issue_admission(
            test_storage_scope_commitment(&self.key),
            &claim,
            generation,
            operation_nonce,
            SelectorAdmissionPhase::Active,
            true,
        )
    }

    /// Atomically record permanent retirement before dataplane removal.
    ///
    /// The returned admission is only a receipt for recovery diagnostics; it
    /// cannot authorize another reconcile.  Reissue requires a new claim and
    /// an external drain/RCU proof at the product boundary.
    pub fn begin_retire(
        &self,
        admission: GtpuSessionSelectorAdmission,
    ) -> Result<GtpuSessionSelectorRetiringAdmission, GtpuSessionSelectorNamespaceError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
        let Some(GroupState::Active {
            device,
            selectors,
            desired,
            atoms,
            generation,
            operation_nonce,
            ..
        }) = state.groups.get(&admission.group_fingerprint).cloned()
        else {
            return Err(GtpuSessionSelectorNamespaceError::GroupClaimed);
        };
        if device != admission.device_fingerprint
            || selectors != admission.selector_set_fingerprint
            || generation != admission.generation
            || operation_nonce != admission.operation_nonce
            || admission.terminal_generation != generation
            || admission.terminal_operation_nonce != operation_nonce
            || admission.previous_terminal.is_some()
        {
            return Err(GtpuSessionSelectorNamespaceError::StaleGeneration);
        }
        let pending_generation = state.next_generation()?;
        let pending_nonce =
            test_nonzero_nonce(&self.key, admission.group_fingerprint, pending_generation)?;
        let terminal_generation = state.next_generation()?;
        let terminal_operation_nonce =
            test_nonzero_nonce(&self.key, admission.group_fingerprint, terminal_generation)?;
        let previous_terminal = SelectorAuthorityCoordinate {
            generation,
            nonce: operation_nonce,
        };
        let retiring_admission = admission.with_coordinates(
            pending_generation,
            pending_nonce,
            SelectorAuthorityCoordinate {
                generation: terminal_generation,
                nonce: terminal_operation_nonce,
            },
            Some(previous_terminal),
            SelectorAdmissionPhase::Retiring,
        )?;
        for atom in &atoms {
            state.selectors.insert(
                *atom,
                SelectorState::Retiring {
                    group: admission.group_fingerprint,
                    generation: pending_generation,
                },
            );
        }
        state.groups.insert(
            admission.group_fingerprint,
            GroupState::Retiring {
                device,
                selectors,
                desired,
                atoms,
                generation: pending_generation,
                operation_nonce: pending_nonce,
                terminal_generation,
                terminal_operation_nonce,
                previous_terminal,
                backend_started: false,
            },
        );
        Ok(GtpuSessionSelectorRetiringAdmission(retiring_admission))
    }

    /// Commit permanent tombstones after the caller has proven exact absence.
    pub fn finish_retire(
        &self,
        retiring: GtpuSessionSelectorRetiringAdmission,
    ) -> Result<(), GtpuSessionSelectorNamespaceError> {
        let admission = retiring.0;
        let mut state = self
            .state
            .lock()
            .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
        let Some(GroupState::Retiring {
            device,
            selectors,
            desired,
            atoms,
            generation,
            operation_nonce,
            terminal_generation,
            terminal_operation_nonce,
            previous_terminal,
            ..
        }) = state.groups.get(&admission.group_fingerprint).cloned()
        else {
            return Err(GtpuSessionSelectorNamespaceError::StaleGeneration);
        };
        if device != admission.device_fingerprint
            || selectors != admission.selector_set_fingerprint
            || generation != admission.generation
            || operation_nonce != admission.operation_nonce
            || terminal_generation != admission.terminal_generation
            || terminal_operation_nonce != admission.terminal_operation_nonce
            || admission.previous_terminal != Some(previous_terminal)
        {
            return Err(GtpuSessionSelectorNamespaceError::StaleGeneration);
        }
        for selector in state.selectors.values_mut() {
            if matches!(selector, SelectorState::Retiring { group, generation } if *group == admission.group_fingerprint && *generation == admission.generation)
            {
                *selector = SelectorState::Retired;
            }
        }
        for atom in &atoms {
            state.tombstones.insert(*atom);
        }
        state.groups.insert(
            admission.group_fingerprint,
            GroupState::Retired {
                device,
                selectors,
                desired,
                atoms,
                generation: terminal_generation,
                operation_nonce: terminal_operation_nonce,
                successor: None,
            },
        );
        Ok(())
    }
}

#[cfg(test)]
impl fmt::Debug for InMemoryGtpuSessionSelectorNamespace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InMemoryGtpuSessionSelectorNamespace(<redacted>)")
    }
}

/// Opaque, versioned durable ledger bytes for one selector namespace.
///
/// A store persists this complete value as a single record. Its bytes contain
/// keyed selector digests and state only, never raw TEIDs, PAAs, marks, or
/// subscriber addresses.
#[cfg(test)]
#[derive(Clone, PartialEq, Eq)]
pub struct GtpuSessionSelectorNamespaceRecord(Vec<u8>);

#[cfg(test)]
impl GtpuSessionSelectorNamespaceRecord {
    /// Construct the empty version-one ledger record.
    #[must_use]
    pub fn empty() -> Self {
        Self(NamespaceState::default().encode())
    }

    /// Return opaque bytes for durable storage.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Rehydrate bytes that were previously returned by [`Self::as_bytes`].
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

#[cfg(test)]
impl fmt::Debug for GtpuSessionSelectorNamespaceRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GtpuSessionSelectorNamespaceRecord(<redacted>)")
    }
}

/// Complete ledger value and the store-issued revision observed atomically.
#[cfg(test)]
#[derive(Clone, Debug)]
pub struct GtpuSessionSelectorNamespaceSnapshot {
    revision: u64,
    record: GtpuSessionSelectorNamespaceRecord,
}

#[cfg(test)]
impl GtpuSessionSelectorNamespaceSnapshot {
    /// Construct one store read result.
    #[must_use]
    pub const fn new(revision: u64, record: GtpuSessionSelectorNamespaceRecord) -> Self {
        Self { revision, record }
    }

    /// Store-issued revision for the next CAS condition.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Opaque complete ledger record from this exact revision.
    #[must_use]
    pub const fn record(&self) -> &GtpuSessionSelectorNamespaceRecord {
        &self.record
    }
}

/// Result of atomically replacing one complete selector namespace record.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GtpuSessionSelectorNamespaceCas {
    /// The complete replacement was durably committed.
    Applied { revision: u64 },
    /// Another writer changed the record; read and retry the identical intent.
    Contended,
}

/// Bounded failure classification for the durable selector namespace store.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum GtpuSessionSelectorNamespaceStoreError {
    /// The store cannot establish a durable result.
    #[error("selector namespace durable store is unavailable")]
    Unavailable,
    /// The store reported malformed, lost, or contradictory durable state.
    #[error("selector namespace durable store state is indeterminate")]
    Indeterminate,
}

/// Backend-neutral port for a multiprocess-safe durable namespace ledger.
///
/// `compare_and_swap` must linearize across process loss and restart: it may
/// replace the *whole* record only when `expected_revision` remains current.
/// An acknowledgement lost after the durable effect point is `Indeterminate`,
/// never `Applied`; a coordinator reads back the exact record before recovery.
/// Sequential multi-key stores do not satisfy this contract.
#[cfg(test)]
pub(crate) trait GtpuSessionSelectorNamespaceStore: Send + Sync {
    /// Read one exact complete record and store-issued revision.
    fn read(
        &self,
    ) -> Result<GtpuSessionSelectorNamespaceSnapshot, GtpuSessionSelectorNamespaceStoreError>;

    /// Compare-and-swap one exact complete record.
    fn compare_and_swap(
        &self,
        expected_revision: u64,
        replacement: GtpuSessionSelectorNamespaceRecord,
    ) -> Result<GtpuSessionSelectorNamespaceCas, GtpuSessionSelectorNamespaceStoreError>;
}

/// Deterministic in-memory implementation of the durable CAS port for tests.
///
/// This is a conformance model only; it has no restart durability and must not
/// be used as a production selector authority.
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct InMemoryGtpuSessionSelectorNamespaceStore {
    state: Arc<Mutex<(u64, GtpuSessionSelectorNamespaceRecord)>>,
}

#[cfg(test)]
impl Default for InMemoryGtpuSessionSelectorNamespaceStore {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new((0, GtpuSessionSelectorNamespaceRecord::empty()))),
        }
    }
}

#[cfg(test)]
impl GtpuSessionSelectorNamespaceStore for InMemoryGtpuSessionSelectorNamespaceStore {
    fn read(
        &self,
    ) -> Result<GtpuSessionSelectorNamespaceSnapshot, GtpuSessionSelectorNamespaceStoreError> {
        let state = self
            .state
            .lock()
            .map_err(|_| GtpuSessionSelectorNamespaceStoreError::Indeterminate)?;
        Ok(GtpuSessionSelectorNamespaceSnapshot::new(
            state.0,
            state.1.clone(),
        ))
    }

    fn compare_and_swap(
        &self,
        expected_revision: u64,
        replacement: GtpuSessionSelectorNamespaceRecord,
    ) -> Result<GtpuSessionSelectorNamespaceCas, GtpuSessionSelectorNamespaceStoreError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| GtpuSessionSelectorNamespaceStoreError::Indeterminate)?;
        if state.0 != expected_revision {
            return Ok(GtpuSessionSelectorNamespaceCas::Contended);
        }
        state.0 = state
            .0
            .checked_add(1)
            .ok_or(GtpuSessionSelectorNamespaceStoreError::Indeterminate)?;
        state.1 = replacement;
        Ok(GtpuSessionSelectorNamespaceCas::Applied { revision: state.0 })
    }
}

#[cfg(test)]
impl fmt::Debug for InMemoryGtpuSessionSelectorNamespaceStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InMemoryGtpuSessionSelectorNamespaceStore(<redacted>)")
    }
}

/// SDK-owned selector namespace coordinator over one durable CAS store.
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct TestGtpuSessionSelectorNamespaceAuthority<S> {
    store: S,
    key: [u8; 32],
    maximum_operation_atoms: usize,
}

/// Opaque durable evidence that a group is Retiring before dataplane removal.
#[cfg(test)]
pub(crate) struct GtpuSessionSelectorRetiringAdmission(GtpuSessionSelectorAdmission);

#[cfg(test)]
impl GtpuSessionSelectorRetiringAdmission {
    pub(crate) fn into_inner(self) -> GtpuSessionSelectorAdmission {
        self.0
    }
}

/// Opaque, affine proof that one exact selector graph is durably Active.
///
/// This is intentionally distinct from an install admission: only an active
/// claim may start teardown, so a delayed install permit cannot race a
/// retirement into publication.
#[must_use = "dropping an active claim abandons the lifecycle operation"]
pub struct GtpuSessionSelectorActiveClaim(GtpuSessionSelectorAdmission);

impl fmt::Debug for GtpuSessionSelectorActiveClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GtpuSessionSelectorActiveClaim(<redacted>)")
    }
}

#[cfg(test)]
impl fmt::Debug for GtpuSessionSelectorRetiringAdmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GtpuSessionSelectorRetiringAdmission(<redacted>)")
    }
}

#[cfg(test)]
#[allow(dead_code)]
impl<S: GtpuSessionSelectorNamespaceStore> TestGtpuSessionSelectorNamespaceAuthority<S> {
    /// Bind the SDK coordinator to one qualified durable store.
    ///
    /// `maximum_operation_atoms` bounds one canonical group admission or
    /// readback; it does not cap the namespace's cumulative permanent atom
    /// history.
    #[must_use]
    pub fn new(store: S, key: [u8; 32], maximum_operation_atoms: usize) -> Self {
        Self {
            store,
            key,
            maximum_operation_atoms,
        }
    }

    /// Claim one complete canonical selector graph with a durable CAS.
    pub fn claim(
        &self,
        group: &GtpuSessionGroup,
        expected_generation: Option<GtpuSessionSelectorAuthorityGeneration>,
    ) -> Result<GtpuSessionSelectorAdmission, GtpuSessionSelectorNamespaceError> {
        let claim = CanonicalClaim::from_group(group)
            .with_key(&self.key)
            .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
        let atoms = claim
            .selector_atoms(&self.key)
            .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
        if atoms.len() > self.maximum_operation_atoms {
            return Err(GtpuSessionSelectorNamespaceError::CapacityExhausted);
        }
        for _ in 0..4 {
            let snapshot = self
                .store
                .read()
                .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
            let mut state = NamespaceState::decode(snapshot.record().as_bytes())
                .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
            state.bind_or_validate(
                group.device_id(),
                self.maximum_operation_atoms,
                Some(self.key),
            )?;
            if let Some(expected) = expected_generation {
                if state.generation != expected.get() {
                    return Err(GtpuSessionSelectorNamespaceError::StaleGeneration);
                }
            }
            if state.groups.contains_key(&claim.group_fingerprint) {
                return Err(GtpuSessionSelectorNamespaceError::GroupClaimed);
            }
            if atoms.iter().any(|atom| {
                state.selectors.contains_key(atom)
                    || state.published_atoms.contains(atom)
                    || state.tombstones.contains(atom)
            }) {
                return Err(GtpuSessionSelectorNamespaceError::SelectorClaimed);
            }
            state.preflight_fresh_claim(atoms.len())?;
            let generation = state.next_generation()?;
            let operation_nonce =
                test_nonzero_nonce(&self.key, claim.group_fingerprint, generation)?;
            let terminal_generation = state.next_generation()?;
            let terminal_operation_nonce =
                test_nonzero_nonce(&self.key, claim.group_fingerprint, terminal_generation)?;
            let admission = state.issue_admission_with_terminal(
                test_storage_scope_commitment(&self.key),
                &claim,
                generation,
                operation_nonce,
                SelectorAuthorityCoordinate {
                    generation: terminal_generation,
                    nonce: terminal_operation_nonce,
                },
                None,
                SelectorAdmissionPhase::Installing,
                false,
            )?;
            for atom in &atoms {
                state.selectors.insert(
                    *atom,
                    SelectorState::Installing {
                        group: claim.group_fingerprint,
                        generation,
                    },
                );
                state.published_atoms.insert(*atom);
            }
            state.groups.insert(
                claim.group_fingerprint,
                GroupState::Installing {
                    device: claim.device_fingerprint,
                    selectors: claim.selector_set_fingerprint,
                    desired: claim.desired_fingerprint,
                    atoms: atoms.clone(),
                    generation,
                    operation_nonce,
                    terminal_generation,
                    terminal_operation_nonce,
                    backend_started: false,
                },
            );
            let replacement = GtpuSessionSelectorNamespaceRecord(state.encode());
            match self
                .store
                .compare_and_swap(snapshot.revision(), replacement.clone())
            {
                Ok(GtpuSessionSelectorNamespaceCas::Applied { revision }) => {
                    let readback = self
                        .store
                        .read()
                        .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
                    if readback.revision() == revision && readback.record() == &replacement {
                        return Ok(admission);
                    }
                    return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
                }
                Ok(GtpuSessionSelectorNamespaceCas::Contended) => continue,
                Err(_) => {
                    let recovered = self
                        .store
                        .read()
                        .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
                    if recovered.record() == &replacement {
                        return Ok(admission);
                    }
                    return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
                }
            }
        }
        Err(GtpuSessionSelectorNamespaceError::Indeterminate)
    }

    /// Durably admit one exact whole-set reissue from one permanently retired
    /// predecessor.  This is not Fresh: the source group tombstone remains in
    /// the ledger forever, and the returned admission can only construct a
    /// request with that exact source's explicit drain/grace proof.
    pub fn claim_reused(
        &self,
        desired: &GtpuSessionGroup,
        proof: &crate::GtpuSessionSelectorReuseProof,
    ) -> Result<GtpuSessionSelectorAdmission, GtpuSessionSelectorNamespaceError> {
        let claim = CanonicalClaim::from_group(desired)
            .with_key(&self.key)
            .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
        let source = CanonicalClaim::from_group(proof.retired_group())
            .with_key(&self.key)
            .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
        if desired.device_id() != proof.retired_group().device_id()
            || desired.id() == proof.retired_group().id()
            || claim.selector_set_fingerprint != source.selector_set_fingerprint
        {
            return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
        }
        let atoms = claim
            .selector_atoms(&self.key)
            .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
        for _ in 0..4 {
            let snapshot = self
                .store
                .read()
                .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
            let mut state = NamespaceState::decode(snapshot.record().as_bytes())
                .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
            state.bind_or_validate(
                desired.device_id(),
                self.maximum_operation_atoms,
                Some(self.key),
            )?;
            if state.groups.contains_key(&claim.group_fingerprint)
                || !matches!(
                    state.groups.get(&source.group_fingerprint),
                    Some(GroupState::Retired { device, selectors, desired: source_desired, atoms: source_atoms, successor: None, .. })
                        if *device == source.device_fingerprint
                            && *selectors == source.selector_set_fingerprint
                            && *source_desired == source.desired_fingerprint
                            && *source_atoms == atoms
                )
                || !atoms.iter().all(|atom| {
                    matches!(state.selectors.get(atom), Some(SelectorState::Retired))
                        && state.tombstones.contains(atom)
                })
            {
                return Err(GtpuSessionSelectorNamespaceError::SelectorClaimed);
            }
            // Reissue consumes no additional selector-record capacity: each
            // tombstone is atomically replaced by its new live owner while
            // the predecessor group tombstone remains permanent.
            state.preflight_reissue(atoms.len())?;
            let generation = state.next_generation()?;
            let operation_nonce =
                test_nonzero_nonce(&self.key, claim.group_fingerprint, generation)?;
            let terminal_generation = state.next_generation()?;
            let terminal_operation_nonce =
                test_nonzero_nonce(&self.key, claim.group_fingerprint, terminal_generation)?;
            let Some(GroupState::Retired {
                device,
                selectors,
                desired: source_desired,
                atoms: source_atoms,
                generation: source_generation,
                operation_nonce: source_nonce,
                successor: None,
            }) = state.groups.get(&source.group_fingerprint).cloned()
            else {
                return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
            };
            state.groups.insert(
                source.group_fingerprint,
                GroupState::Retired {
                    device,
                    selectors,
                    desired: source_desired,
                    atoms: source_atoms,
                    generation: source_generation,
                    operation_nonce: source_nonce,
                    successor: Some(RetiredSuccessor {
                        group: claim.group_fingerprint,
                        generation,
                    }),
                },
            );
            for atom in &atoms {
                state.tombstones.insert(*atom);
                state.selectors.insert(
                    *atom,
                    SelectorState::Installing {
                        group: claim.group_fingerprint,
                        generation,
                    },
                );
                state.published_atoms.insert(*atom);
            }
            state.groups.insert(
                claim.group_fingerprint,
                GroupState::Installing {
                    device: claim.device_fingerprint,
                    selectors: claim.selector_set_fingerprint,
                    desired: claim.desired_fingerprint,
                    atoms: atoms.clone(),
                    generation,
                    operation_nonce,
                    terminal_generation,
                    terminal_operation_nonce,
                    backend_started: false,
                },
            );
            let replacement = GtpuSessionSelectorNamespaceRecord(state.encode());
            match self
                .store
                .compare_and_swap(snapshot.revision(), replacement.clone())
            {
                Ok(GtpuSessionSelectorNamespaceCas::Applied { revision }) => {
                    let readback = self
                        .store
                        .read()
                        .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
                    if readback.revision() == revision && readback.record() == &replacement {
                        return state.issue_admission_with_terminal(
                            test_storage_scope_commitment(&self.key),
                            &claim,
                            generation,
                            operation_nonce,
                            SelectorAuthorityCoordinate {
                                generation: terminal_generation,
                                nonce: terminal_operation_nonce,
                            },
                            None,
                            SelectorAdmissionPhase::Installing,
                            true,
                        );
                    }
                    return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
                }
                Ok(GtpuSessionSelectorNamespaceCas::Contended) => continue,
                Err(_) => {
                    let readback = self
                        .store
                        .read()
                        .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
                    if readback.record() == &replacement {
                        return state.issue_admission_with_terminal(
                            test_storage_scope_commitment(&self.key),
                            &claim,
                            generation,
                            operation_nonce,
                            SelectorAuthorityCoordinate {
                                generation: terminal_generation,
                                nonce: terminal_operation_nonce,
                            },
                            None,
                            SelectorAdmissionPhase::Installing,
                            true,
                        );
                    }
                    return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
                }
            }
        }
        Err(GtpuSessionSelectorNamespaceError::Indeterminate)
    }

    /// Perform a fresh admission and its grouped backend effect as one
    /// SDK-owned lifecycle operation.
    ///
    /// The durable `Installing` intent is committed before the backend call.
    /// No active teardown capability exists until that call reports an exact
    /// activation and the coordinator CASes the same intent to `Active`.
    /// Dropping this future therefore leaves only a recoverable, fail-closed
    /// install intent; it cannot leave a usable teardown capability.
    pub async fn reconcile_fresh<B>(
        &self,
        backend: &B,
        desired: GtpuSessionGroup,
    ) -> Result<GtpuSessionSelectorActiveClaim, GtpuSessionSelectorCoordinatorError>
    where
        B: GtpuDataplaneBackend + ?Sized,
    {
        let admission = self
            .claim(&desired, None)
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let request = GtpuSessionGroupReconcileRequest::new(desired.clone(), admission)
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        match backend
            .reconcile_pdp_context_group(request)
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Backend)?
        {
            GtpuSessionGroupReconcileOutcome::Activated => self
                .activate_for(&desired)
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace),
            _ => Err(GtpuSessionSelectorCoordinatorError::Backend),
        }
    }

    /// Perform one exact whole-set retired reissue through the existing
    /// backend provenance validation.  The durable authority proves the
    /// permanent predecessor tombstone; the backend still proves exact source
    /// absence and the caller-supplied drain/grace condition at effect time.
    pub async fn reconcile_reused<B>(
        &self,
        backend: &B,
        desired: GtpuSessionGroup,
        proof: crate::GtpuSessionSelectorReuseProof,
    ) -> Result<GtpuSessionSelectorActiveClaim, GtpuSessionSelectorCoordinatorError>
    where
        B: GtpuDataplaneBackend + ?Sized,
    {
        let admission = self
            .claim_reused(&desired, &proof)
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let request =
            GtpuSessionGroupReconcileRequest::new_reused(desired.clone(), admission, proof)
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        match backend
            .reconcile_pdp_context_group(request)
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Backend)?
        {
            GtpuSessionGroupReconcileOutcome::Activated => self
                .activate_for(&desired)
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace),
            _ => Err(GtpuSessionSelectorCoordinatorError::Backend),
        }
    }

    /// Recover a durable `Installing` intent only after exact backend
    /// readback.  This is the ACK-loss and cancellation recovery path.
    pub async fn recover_install<B>(
        &self,
        backend: &B,
        desired: &GtpuSessionGroup,
    ) -> Result<GtpuSessionSelectorActiveClaim, GtpuSessionSelectorCoordinatorError>
    where
        B: GtpuDataplaneBackend + ?Sized,
    {
        let readback = backend
            .read_pdp_context_group(crate::GtpuSessionGroupSelector::new(
                desired.id(),
                desired.device_id(),
            ))
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Backend)?;
        if !matches!(readback, crate::GtpuSessionGroupReadback::Active(ref active) if active == desired)
        {
            return Err(GtpuSessionSelectorCoordinatorError::Backend);
        }
        self.activate_for(desired)
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)
    }

    fn activate_for(
        &self,
        desired: &GtpuSessionGroup,
    ) -> Result<GtpuSessionSelectorActiveClaim, GtpuSessionSelectorNamespaceError> {
        let claim = CanonicalClaim::from_group(desired)
            .with_key(&self.key)
            .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
        let snapshot = self
            .store
            .read()
            .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
        let state = NamespaceState::decode(snapshot.record().as_bytes())
            .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
        let Some(GroupState::Installing {
            device,
            selectors,
            desired,
            generation,
            operation_nonce,
            terminal_generation,
            terminal_operation_nonce,
            ..
        }) = state.groups.get(&claim.group_fingerprint)
        else {
            return Err(GtpuSessionSelectorNamespaceError::StaleGeneration);
        };
        if *device != claim.device_fingerprint
            || *selectors != claim.selector_set_fingerprint
            || *desired != claim.desired_fingerprint
        {
            return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
        }
        self.activate(state.issue_admission_with_terminal(
            test_storage_scope_commitment(&self.key),
            &claim,
            *generation,
            *operation_nonce,
            SelectorAuthorityCoordinate {
                generation: *terminal_generation,
                nonce: *terminal_operation_nonce,
            },
            None,
            SelectorAdmissionPhase::Installing,
            false,
        )?)
    }

    /// Convert an installed exact admission into the sole teardown authority.
    ///
    /// Callers use this only after exact backend readback confirms the graph
    /// was published.  A store adapter that cannot establish this CAS result
    /// must leave the install intent for recovery rather than minting a claim.
    pub fn activate(
        &self,
        admission: GtpuSessionSelectorAdmission,
    ) -> Result<GtpuSessionSelectorActiveClaim, GtpuSessionSelectorNamespaceError> {
        for _ in 0..4 {
            let snapshot = self
                .store
                .read()
                .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
            let mut state = NamespaceState::decode(snapshot.record().as_bytes())
                .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
            let Some(GroupState::Installing {
                device,
                selectors,
                desired,
                atoms,
                generation,
                operation_nonce,
                terminal_generation,
                terminal_operation_nonce,
                ..
            }) = state.groups.get(&admission.group_fingerprint).cloned()
            else {
                return Err(GtpuSessionSelectorNamespaceError::StaleGeneration);
            };
            if device != admission.device_fingerprint
                || selectors != admission.selector_set_fingerprint
                || desired != admission.desired_fingerprint
                || generation != admission.generation
                || operation_nonce != admission.operation_nonce
                || terminal_generation != admission.terminal_generation
                || terminal_operation_nonce != admission.terminal_operation_nonce
                || admission.previous_terminal.is_some()
            {
                return Err(GtpuSessionSelectorNamespaceError::StaleGeneration);
            }
            let active_admission = admission.with_coordinates(
                terminal_generation,
                terminal_operation_nonce,
                SelectorAuthorityCoordinate {
                    generation: terminal_generation,
                    nonce: terminal_operation_nonce,
                },
                None,
                SelectorAdmissionPhase::Active,
            )?;
            for atom in &atoms {
                state.selectors.insert(
                    *atom,
                    SelectorState::Active {
                        group: admission.group_fingerprint,
                        generation: terminal_generation,
                    },
                );
                state.published_atoms.insert(*atom);
            }
            state.groups.insert(
                admission.group_fingerprint,
                GroupState::Active {
                    device,
                    selectors,
                    desired,
                    atoms,
                    generation: terminal_generation,
                    operation_nonce: terminal_operation_nonce,
                },
            );
            let replacement = GtpuSessionSelectorNamespaceRecord(state.encode());
            match self
                .store
                .compare_and_swap(snapshot.revision(), replacement.clone())
            {
                Ok(GtpuSessionSelectorNamespaceCas::Applied { revision }) => {
                    let readback = self
                        .store
                        .read()
                        .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
                    if readback.revision() == revision && readback.record() == &replacement {
                        return Ok(GtpuSessionSelectorActiveClaim(active_admission));
                    }
                    return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
                }
                Ok(GtpuSessionSelectorNamespaceCas::Contended) => continue,
                Err(_) => {
                    let recovered = self
                        .store
                        .read()
                        .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
                    if recovered.record() == &replacement {
                        return Ok(GtpuSessionSelectorActiveClaim(active_admission));
                    }
                    return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
                }
            }
        }
        Err(GtpuSessionSelectorNamespaceError::Indeterminate)
    }

    /// Commit `Retiring` before exact backend removal.
    pub fn begin_retire(
        &self,
        active: GtpuSessionSelectorActiveClaim,
    ) -> Result<GtpuSessionSelectorRetiringAdmission, GtpuSessionSelectorNamespaceError> {
        self.retire(active.0)
    }

    /// Permanently retire a previously admitted complete claim through CAS.
    ///
    /// Product teardown calls this before removing dataplane state. A durable
    /// adapter that loses an acknowledgement retains `Retiring` or `Poisoned`
    /// on its own recovery path; this coordinator returns indeterminate rather
    /// than guessing whether a selector can be reissued.
    pub fn retire(
        &self,
        admission: GtpuSessionSelectorAdmission,
    ) -> Result<GtpuSessionSelectorRetiringAdmission, GtpuSessionSelectorNamespaceError> {
        for _ in 0..4 {
            let snapshot = self
                .store
                .read()
                .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
            let mut state = NamespaceState::decode(snapshot.record().as_bytes())
                .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
            let Some(GroupState::Active {
                device,
                selectors,
                desired,
                atoms,
                generation,
                operation_nonce,
                ..
            }) = state.groups.get(&admission.group_fingerprint).cloned()
            else {
                return Err(GtpuSessionSelectorNamespaceError::GroupClaimed);
            };
            if device != admission.device_fingerprint
                || selectors != admission.selector_set_fingerprint
                || desired != admission.desired_fingerprint
                || generation != admission.generation
                || operation_nonce != admission.operation_nonce
                || admission.terminal_generation != generation
                || admission.terminal_operation_nonce != operation_nonce
                || admission.previous_terminal.is_some()
            {
                return Err(GtpuSessionSelectorNamespaceError::StaleGeneration);
            }
            let pending_generation = state.next_generation()?;
            let pending_nonce =
                test_nonzero_nonce(&self.key, admission.group_fingerprint, pending_generation)?;
            let terminal_generation = state.next_generation()?;
            let terminal_operation_nonce =
                test_nonzero_nonce(&self.key, admission.group_fingerprint, terminal_generation)?;
            let previous_terminal = SelectorAuthorityCoordinate {
                generation,
                nonce: operation_nonce,
            };
            let retiring_admission = admission.with_coordinates(
                pending_generation,
                pending_nonce,
                SelectorAuthorityCoordinate {
                    generation: terminal_generation,
                    nonce: terminal_operation_nonce,
                },
                Some(previous_terminal),
                SelectorAdmissionPhase::Retiring,
            )?;
            for atom in &atoms {
                state.selectors.insert(
                    *atom,
                    SelectorState::Retiring {
                        group: admission.group_fingerprint,
                        generation: pending_generation,
                    },
                );
            }
            state.groups.insert(
                admission.group_fingerprint,
                GroupState::Retiring {
                    device,
                    selectors,
                    desired,
                    atoms,
                    generation: pending_generation,
                    operation_nonce: pending_nonce,
                    terminal_generation,
                    terminal_operation_nonce,
                    previous_terminal,
                    backend_started: false,
                },
            );
            let replacement = GtpuSessionSelectorNamespaceRecord(state.encode());
            match self
                .store
                .compare_and_swap(snapshot.revision(), replacement.clone())
            {
                Ok(GtpuSessionSelectorNamespaceCas::Applied { revision }) => {
                    let readback = self
                        .store
                        .read()
                        .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
                    if readback.revision() == revision && readback.record() == &replacement {
                        return Ok(GtpuSessionSelectorRetiringAdmission(retiring_admission));
                    }
                    return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
                }
                Ok(GtpuSessionSelectorNamespaceCas::Contended) => continue,
                Err(_) => {
                    let recovered = self
                        .store
                        .read()
                        .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
                    if recovered.record() == &replacement {
                        return Ok(GtpuSessionSelectorRetiringAdmission(retiring_admission));
                    }
                    return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
                }
            }
        }
        Err(GtpuSessionSelectorNamespaceError::Indeterminate)
    }

    /// Permanently tombstone a Retiring claim after trusted exact absence.
    pub fn finish_retire(
        &self,
        retiring: GtpuSessionSelectorRetiringAdmission,
    ) -> Result<(), GtpuSessionSelectorNamespaceError> {
        let admission = retiring.0;
        for _ in 0..4 {
            let snapshot = self
                .store
                .read()
                .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
            let mut state = NamespaceState::decode(snapshot.record().as_bytes())
                .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
            let Some(GroupState::Retiring {
                device,
                selectors,
                desired,
                atoms,
                generation,
                operation_nonce,
                terminal_generation,
                terminal_operation_nonce,
                previous_terminal,
                ..
            }) = state.groups.get(&admission.group_fingerprint).cloned()
            else {
                return Err(GtpuSessionSelectorNamespaceError::StaleGeneration);
            };
            if device != admission.device_fingerprint
                || selectors != admission.selector_set_fingerprint
                || generation != admission.generation
                || operation_nonce != admission.operation_nonce
                || terminal_generation != admission.terminal_generation
                || terminal_operation_nonce != admission.terminal_operation_nonce
                || admission.previous_terminal != Some(previous_terminal)
            {
                return Err(GtpuSessionSelectorNamespaceError::StaleGeneration);
            }
            state.preflight_retirement(&atoms)?;
            for selector in state.selectors.values_mut() {
                if matches!(selector, SelectorState::Retiring { group, generation } if *group == admission.group_fingerprint && *generation == admission.generation)
                {
                    *selector = SelectorState::Retired;
                }
            }
            for atom in &atoms {
                state.tombstones.insert(*atom);
            }
            state.groups.insert(
                admission.group_fingerprint,
                GroupState::Retired {
                    device,
                    selectors,
                    desired,
                    atoms,
                    generation: terminal_generation,
                    operation_nonce: terminal_operation_nonce,
                    successor: None,
                },
            );
            let replacement = GtpuSessionSelectorNamespaceRecord(state.encode());
            match self
                .store
                .compare_and_swap(snapshot.revision(), replacement.clone())
            {
                Ok(GtpuSessionSelectorNamespaceCas::Applied { revision }) => {
                    let readback = self
                        .store
                        .read()
                        .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
                    if readback.revision() == revision && readback.record() == &replacement {
                        return Ok(());
                    }
                    return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
                }
                Ok(GtpuSessionSelectorNamespaceCas::Contended) => continue,
                Err(_) => {
                    let recovered = self
                        .store
                        .read()
                        .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
                    if recovered.record() == &replacement {
                        return Ok(());
                    }
                    return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
                }
            }
        }
        Err(GtpuSessionSelectorNamespaceError::Indeterminate)
    }
}

#[cfg(test)]
impl<S> fmt::Debug for TestGtpuSessionSelectorNamespaceAuthority<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TestGtpuSessionSelectorNamespaceAuthority(<redacted>)")
    }
}

/// Production selector-namespace authority.
///
/// Exactly one `AuthoritativeSession` record holds the complete ledger.  The
/// record never expires; a short server-side lease fences each individual CAS.
/// Production construction requires an SDK-owned protected session-store
/// wrapper. The durable key is derived from its authenticated payload boundary
/// and an affine eBPF bootstrap; product code never supplies a raw namespace,
/// pin commitment, or stable device coordinate. The selector secret is
/// provisioned durably before normal reconciliation and remains immutable.
pub struct GtpuSessionSelectorNamespaceAuthority<B>
where
    B: SessionBackend + SessionLeaseManager,
{
    store: SessionStore<B>,
    namespace_key: SessionKey,
    owner: OwnerId,
    lease_ttl: Duration,
    /// Immutable maximum canonical atoms accepted by one group operation or
    /// exact backend readback. This is not a namespace-history quota.
    maximum_operation_atoms: usize,
    storage_scope_commitment: [u8; 32],
    stable_device: GtpuSessionDeviceId,
    pin_commitment: [u8; 32],
    #[cfg(test)]
    allows_test_raw_open: bool,
}

impl<B> fmt::Debug for GtpuSessionSelectorNamespaceAuthority<B>
where
    B: SessionBackend + SessionLeaseManager,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GtpuSessionSelectorNamespaceAuthority(<redacted>)")
    }
}

impl<B> Clone for GtpuSessionSelectorNamespaceAuthority<B>
where
    B: SessionBackend + SessionLeaseManager,
{
    fn clone(&self) -> Self {
        Self {
            store: self.store.clone(),
            namespace_key: self.namespace_key.clone(),
            owner: self.owner.clone(),
            lease_ttl: self.lease_ttl,
            maximum_operation_atoms: self.maximum_operation_atoms,
            storage_scope_commitment: self.storage_scope_commitment,
            stable_device: self.stable_device,
            pin_commitment: self.pin_commitment,
            #[cfg(test)]
            allows_test_raw_open: self.allows_test_raw_open,
        }
    }
}

impl<B> GtpuSessionSelectorNamespaceAuthority<B>
where
    B: SessionBackend + SessionLeaseManager,
{
    /// Open a production selector authority over an adapter that proves
    /// authenticated payload protection. The durable key is SDK-derived from
    /// the protected boundary and stable device, never caller-selected.
    pub async fn open_protected(
        store: SessionStore<B>,
        scope: SelectorLedgerStorageScope,
        bootstrap: GtpuSelectorNamespaceBootstrap,
        owner: OwnerId,
        lease_ttl: Duration,
        maximum_atoms: usize,
    ) -> Result<Self, GtpuSessionSelectorNamespaceError>
    where
        B: ProtectedSessionBackend,
    {
        let base = store
            .protected_selector_ledger_base(&scope)
            .ok_or(GtpuSessionSelectorNamespaceError::UnsuitableStore)?;
        let derivation = derive_protected_selector_ledger(base, bootstrap)?;
        let scope = NamespaceBackendScope::from(&derivation);
        let authority = Self::open_with_backend_scope(
            store,
            derivation.namespace_key,
            owner,
            lease_ttl,
            maximum_atoms,
            scope,
        )
        .await?;
        authority.verify_open_bound().await?;
        Ok(authority)
    }

    /// Test-only raw-key constructor for deterministic conformance fixtures.
    ///
    /// Production callers must use [`Self::open_protected`], which derives the
    /// durable key inside an SDK-owned protected session-store wrapper.
    #[cfg(test)]
    pub(crate) async fn open(
        store: SessionStore<B>,
        namespace_key: SessionKey,
        owner: OwnerId,
        lease_ttl: Duration,
        maximum_atoms: usize,
    ) -> Result<Self, GtpuSessionSelectorNamespaceError> {
        let mut authority = Self::open_with_backend_scope(
            store,
            namespace_key.clone(),
            owner,
            lease_ttl,
            maximum_atoms,
            NamespaceBackendScope {
                storage_scope_commitment: namespace_key.digest(),
                stable_device: GtpuSessionDeviceId::new([1; 16])
                    .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?,
                pin_commitment: test_pin_commitment(&namespace_key.digest()),
            },
        )
        .await?;
        authority.allows_test_raw_open = true;
        Ok(authority)
    }

    async fn open_with_backend_scope(
        store: SessionStore<B>,
        namespace_key: SessionKey,
        owner: OwnerId,
        lease_ttl: Duration,
        maximum_atoms: usize,
        scope: NamespaceBackendScope,
    ) -> Result<Self, GtpuSessionSelectorNamespaceError> {
        if lease_ttl.is_zero()
            || lease_ttl > SELECTOR_NAMESPACE_MAX_LEASE_TTL
            || maximum_atoms == 0
            || maximum_atoms > SELECTOR_NAMESPACE_MAX_READBACK_ATOMS
        {
            return Err(GtpuSessionSelectorNamespaceError::UnsuitableStore);
        }
        let caps = store.capabilities().await;
        if !caps.atomic_compare_and_set
            || !caps.monotonic_fencing_token
            || !caps.per_key_ttl
            || !caps.server_side_lease_expiry
            || caps.max_value_bytes < MIN_BACKEND_RECORD_BYTES
            || store.restore_scan_cursor_profile()
                != Some(RestoreScanCursorProfile::DurableOpaqueV1)
        {
            return Err(GtpuSessionSelectorNamespaceError::UnsuitableStore);
        }
        Ok(Self {
            store,
            namespace_key,
            owner,
            lease_ttl,
            maximum_operation_atoms: maximum_atoms,
            storage_scope_commitment: scope.storage_scope_commitment,
            stable_device: scope.stable_device,
            pin_commitment: scope.pin_commitment,
            #[cfg(test)]
            allows_test_raw_open: false,
        })
    }

    /// Explicit stopped-installation provisioning for a previously absent
    /// protected selector namespace.  This consumes the backend-minted
    /// bootstrap, commits immutable material before any backend effect, and
    /// requires the backend's exact empty-inventory marker proof before the
    /// durable ledger becomes Bound.
    pub fn provision_protected<D>(
        store: SessionStore<B>,
        scope: SelectorLedgerStorageScope,
        bootstrap: GtpuSelectorNamespaceBootstrap,
        backend: Arc<D>,
        owner: OwnerId,
        lease_ttl: Duration,
        maximum_atoms: usize,
    ) -> GtpuSessionSelectorOperation<Self, GtpuSessionSelectorNamespaceError>
    where
        B: ProtectedSessionBackend + Send + Sync + 'static,
        D: GtpuDataplaneBackend + Send + Sync + 'static,
    {
        let Some(base) = store.protected_selector_ledger_base(&scope) else {
            return spawn_selector_operation(
                [0; 32],
                GtpuSessionSelectorNamespaceError::UnsuitableStore,
                async { Err(GtpuSessionSelectorNamespaceError::UnsuitableStore) },
            );
        };
        let derivation = match derive_protected_selector_ledger(base, bootstrap) {
            Ok(derivation) => derivation,
            Err(error) => {
                return spawn_selector_operation([0; 32], error, async move { Err(error) });
            }
        };
        let storage_scope_commitment = derivation.storage_scope_commitment;
        let backend_scope = NamespaceBackendScope::from(&derivation);
        spawn_selector_operation(
            storage_scope_commitment,
            GtpuSessionSelectorNamespaceError::Indeterminate,
            async move {
                let authority = Self::open_with_backend_scope(
                    store,
                    derivation.namespace_key,
                    owner,
                    lease_ttl,
                    maximum_atoms,
                    backend_scope,
                )
                .await?;
                authority.provision(backend.as_ref()).await?;
                Ok(authority)
            },
        )
    }

    /// Permanently decommission an empty selector namespace.
    ///
    /// This first commits an authenticated terminal coordinate in the durable
    /// ledger. The opaque backend request then writes and reads that exact
    /// terminal marker. If the caller disappears or the terminal CAS loses an
    /// acknowledgement, a later worker resumes the same precommitted fence;
    /// it never mints a replacement coordinate.
    pub fn decommission<D>(&self, backend: Arc<D>) -> GtpuSessionSelectorOperation<()>
    where
        B: Send + Sync + 'static,
        D: GtpuDataplaneBackend + Send + Sync + 'static,
    {
        let authority = self.clone();
        let scope = self.storage_scope_commitment;
        spawn_selector_operation(
            scope,
            GtpuSessionSelectorCoordinatorError::Backend,
            async move { authority.decommission_owned(backend.as_ref()).await },
        )
    }

    /// Claim a previously unpublished complete graph, effect it, prove exact
    /// Active readback, then durably acknowledge Active.  A failed or unknown
    /// effect poisons the intent where a fenced CAS can prove that transition;
    /// otherwise the persisted Installing state remains non-reissuable.
    pub fn reconcile_fresh<D>(
        &self,
        backend: Arc<D>,
        desired: GtpuSessionGroup,
    ) -> GtpuSessionSelectorOperation<GtpuSessionSelectorActiveClaim>
    where
        B: Send + Sync + 'static,
        D: GtpuDataplaneBackend + Send + Sync + 'static,
    {
        let authority = self.clone();
        let scope = self.storage_scope_commitment;
        spawn_selector_operation(
            scope,
            GtpuSessionSelectorCoordinatorError::Backend,
            async move {
                authority
                    .reconcile_fresh_owned(backend.as_ref(), desired)
                    .await
            },
        )
    }

    async fn reconcile_fresh_owned<D>(
        &self,
        backend: &D,
        desired: GtpuSessionGroup,
    ) -> Result<GtpuSessionSelectorActiveClaim, GtpuSessionSelectorCoordinatorError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        self.claim_fresh(backend, &desired)
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let handoff = self
            .mark_install_backend_started(&desired)
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let BackendStartHandoff::Transitioned(admission) = handoff else {
            return Err(GtpuSessionSelectorCoordinatorError::Namespace);
        };
        self.effect_and_activate(backend, desired, admission).await
    }

    /// Ask the backend to prove quiescence for an exact retired source before
    /// it may be reused by this exact successor. The backend consumes the
    /// retired capability and can return a receipt only by completing the
    /// opaque request after its terminal-stamp, absence, and barrier proof.
    pub fn authorize_reuse<D>(
        &self,
        backend: Arc<D>,
        desired: GtpuSessionGroup,
        retired: GtpuSessionSelectorRetiredClaim,
    ) -> GtpuSessionSelectorOperation<GtpuSessionSelectorReuseAuthorization>
    where
        B: Send + Sync + 'static,
        D: GtpuDataplaneBackend + Send + Sync + 'static,
    {
        let authority = self.clone();
        let scope = self.storage_scope_commitment;
        spawn_selector_operation(
            scope,
            GtpuSessionSelectorCoordinatorError::Backend,
            async move {
                authority
                    .authorize_reuse_owned(backend.as_ref(), desired, retired)
                    .await
            },
        )
    }

    async fn authorize_reuse_owned<D>(
        &self,
        backend: &D,
        desired: GtpuSessionGroup,
        retired: GtpuSessionSelectorRetiredClaim,
    ) -> Result<GtpuSessionSelectorReuseAuthorization, GtpuSessionSelectorCoordinatorError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        self.ensure_backend_namespace(backend)
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        if retired.admission.phase != SelectorAdmissionPhase::Retired
            || !retired.admission.validates(&retired.group)
            || retired.group.device_id() != desired.device_id()
            || retired.group.id() == desired.id()
        {
            return Err(GtpuSessionSelectorCoordinatorError::Namespace);
        }
        let receipt = tokio::time::timeout(
            SELECTOR_NAMESPACE_MAX_EFFECT_DURATION,
            backend.authorize_selector_reuse(GtpuSessionSelectorReuseRequest { retired, desired }),
        )
        .await
        .map_err(|_| GtpuSessionSelectorCoordinatorError::Backend)?
        .map_err(|_| GtpuSessionSelectorCoordinatorError::Backend)?;
        let GtpuSessionSelectorReuseReceipt {
            retired,
            desired,
            evidence,
        } = receipt;
        if retired.admission.phase != SelectorAdmissionPhase::Retired
            || !retired.admission.validates(&retired.group)
        {
            return Err(GtpuSessionSelectorCoordinatorError::Backend);
        }
        let proof = match evidence {
            crate::GtpuSessionSelectorReuseEvidence::TrafficDrained => {
                crate::GtpuSessionSelectorReuseProof::after_traffic_drain(retired.group)
            }
            crate::GtpuSessionSelectorReuseEvidence::RcuGracePeriodElapsed => {
                crate::GtpuSessionSelectorReuseProof::after_rcu_grace_period(retired.group)
            }
        };
        Ok(GtpuSessionSelectorReuseAuthorization { desired, proof })
    }

    /// Claim an exact full-set reissue from one backend-authorized retired
    /// predecessor. Mixed selector transfers and same-group updates remain
    /// unsupported.
    pub fn reconcile_reused<D>(
        &self,
        backend: Arc<D>,
        authorization: GtpuSessionSelectorReuseAuthorization,
    ) -> GtpuSessionSelectorOperation<GtpuSessionSelectorActiveClaim>
    where
        B: Send + Sync + 'static,
        D: GtpuDataplaneBackend + Send + Sync + 'static,
    {
        let authority = self.clone();
        let scope = self.storage_scope_commitment;
        spawn_selector_operation(
            scope,
            GtpuSessionSelectorCoordinatorError::Backend,
            async move {
                authority
                    .reconcile_reused_owned(backend.as_ref(), authorization)
                    .await
            },
        )
    }

    async fn reconcile_reused_owned<D>(
        &self,
        backend: &D,
        authorization: GtpuSessionSelectorReuseAuthorization,
    ) -> Result<GtpuSessionSelectorActiveClaim, GtpuSessionSelectorCoordinatorError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        let GtpuSessionSelectorReuseAuthorization { desired, proof } = authorization;
        self.claim_reused(backend, &desired, &proof)
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let handoff = self
            .mark_install_backend_started(&desired)
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let BackendStartHandoff::Transitioned(admission) = handoff else {
            return Err(GtpuSessionSelectorCoordinatorError::Namespace);
        };
        let request =
            GtpuSessionGroupReconcileRequest::new_reused(desired.clone(), admission, proof)
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        self.complete_effect(backend, desired, request).await
    }

    /// Recover an Installing intent only after exact dataplane Active
    /// readback. A separately authenticated no-effect inspection is the sole
    /// other terminal branch; it poisons the durable intent rather than
    /// treating an absent stamp as a new/virgin namespace.
    pub fn recover_install<D>(
        &self,
        backend: Arc<D>,
        desired: GtpuSessionGroup,
    ) -> GtpuSessionSelectorOperation<GtpuSessionSelectorActiveClaim>
    where
        B: Send + Sync + 'static,
        D: GtpuDataplaneBackend + Send + Sync + 'static,
    {
        let authority = self.clone();
        let scope = self.storage_scope_commitment;
        spawn_selector_operation(
            scope,
            GtpuSessionSelectorCoordinatorError::Backend,
            async move {
                authority
                    .recover_install_owned(backend.as_ref(), desired)
                    .await
            },
        )
    }

    async fn recover_install_owned<D>(
        &self,
        backend: &D,
        desired: GtpuSessionGroup,
    ) -> Result<GtpuSessionSelectorActiveClaim, GtpuSessionSelectorCoordinatorError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        self.ensure_backend_namespace(backend)
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        // `Installing(false)` is a durable pre-effect reservation, not a
        // retry permit.  Only independently authenticated complete absence
        // may advance it; a pending, terminal, partial, or malformed backend
        // observation remains fail-closed rather than being reinterpreted as
        // a request to replay the effect.
        if let Ok(admission) = self.installing_admission(&desired, Some(false)).await {
            let no_effect = tokio::time::timeout(
                SELECTOR_NAMESPACE_MAX_EFFECT_DURATION,
                backend.inspect_installing_selector_no_effect(&desired, &admission),
            )
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Backend)?
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Backend)?;
            if !matches!(
                no_effect,
                crate::GtpuSessionSelectorInstallRecovery::NoEffect
            ) {
                return Err(GtpuSessionSelectorCoordinatorError::Backend);
            }
            let handoff = self
                .mark_install_backend_started(&desired)
                .await
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
            return match handoff {
                BackendStartHandoff::Transitioned(admission) => {
                    self.effect_and_activate(backend, desired, admission).await
                }
                BackendStartHandoff::AlreadyStarted(admission) => {
                    self.recover_install_after_competing_start(backend, desired, admission)
                        .await
                }
            };
        }

        let admission = self
            .installing_admission(&desired, Some(true))
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let readback = Self::authorized_readback(backend, desired.clone(), admission).await?;
        match readback {
            crate::GtpuSessionGroupReadback::Active(ref active) if active == &desired => self
                .activate_claim(&desired)
                .await
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace),
            // A detached supervisor has durably claimed the effect coordinate.
            // It may rejoin the exact pending stamp/journal only after the
            // started bit is readable as true; eBPF independently verifies
            // that exact stamp before the executor can mutate anything.
            _ => self.recover_install_started(backend, desired).await,
        }
    }

    /// Observe only final state after losing the false-to-true Installing
    /// handoff. The caller's no-effect proof predates another supervisor's
    /// durable CAS, so it is never a permit to invoke the backend effect.
    async fn recover_install_after_competing_start<D>(
        &self,
        backend: &D,
        desired: GtpuSessionGroup,
        admission: GtpuSessionSelectorAdmission,
    ) -> Result<GtpuSessionSelectorActiveClaim, GtpuSessionSelectorCoordinatorError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        match Self::authorized_readback(backend, desired.clone(), admission).await? {
            crate::GtpuSessionGroupReadback::Active(active) if active == desired => self
                .activate_claim(&desired)
                .await
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace),
            _ => Err(GtpuSessionSelectorCoordinatorError::Backend),
        }
    }

    /// Resume a previously started Installing supervisor only after a
    /// backend-held inventory proof binds the current state to this exact
    /// pending coordinate. This excludes partial, malformed, and unstamped
    /// state before an effect request can reach the eBPF executor.
    async fn recover_install_started<D>(
        &self,
        backend: &D,
        desired: GtpuSessionGroup,
    ) -> Result<GtpuSessionSelectorActiveClaim, GtpuSessionSelectorCoordinatorError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        let admission = self
            .installing_admission(&desired, Some(true))
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let resume = tokio::time::timeout(
            SELECTOR_NAMESPACE_MAX_EFFECT_DURATION,
            backend.inspect_installing_selector_resume(&desired, &admission),
        )
        .await
        .map_err(|_| GtpuSessionSelectorCoordinatorError::Backend)?
        .map_err(|_| GtpuSessionSelectorCoordinatorError::Backend)?;
        if !matches!(
            resume,
            crate::GtpuSessionSelectorInstallResume::NoEffect
                | crate::GtpuSessionSelectorInstallResume::ExactPendingInstall
        ) {
            return Err(GtpuSessionSelectorCoordinatorError::Backend);
        }
        self.effect_and_activate(backend, desired, admission).await
    }

    /// Re-mint the affine Active capability after a caller lost the response
    /// to the final Installing→Active CAS. The final ledger row persists the
    /// complete private issuance descriptor (canonical fingerprints, atoms,
    /// generation, and operation nonce), so this is recovery rather than a
    /// second claim and cannot consume or reissue selectors.
    pub fn recover_active<D>(
        &self,
        backend: Arc<D>,
        desired: GtpuSessionGroup,
    ) -> GtpuSessionSelectorOperation<GtpuSessionSelectorActiveClaim>
    where
        B: Send + Sync + 'static,
        D: GtpuDataplaneBackend + Send + Sync + 'static,
    {
        let authority = self.clone();
        let scope = self.storage_scope_commitment;
        spawn_selector_operation(
            scope,
            GtpuSessionSelectorCoordinatorError::Backend,
            async move {
                authority
                    .recover_active_owned(backend.as_ref(), desired)
                    .await
            },
        )
    }

    async fn recover_active_owned<D>(
        &self,
        backend: &D,
        desired: GtpuSessionGroup,
    ) -> Result<GtpuSessionSelectorActiveClaim, GtpuSessionSelectorCoordinatorError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        self.ensure_backend_namespace(backend)
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let admission = self
            .active_admission(&desired)
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        self.require_exact_active(backend, desired.clone(), admission)
            .await?;
        let admission = self
            .active_admission(&desired)
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        Ok(GtpuSessionSelectorActiveClaim(admission))
    }

    /// Recover the opaque retired capability after a lost
    /// Retiring→Retired response. The capability still requires backend
    /// quiescence authorization before any reuse.
    pub fn recover_retired<D>(
        &self,
        backend: Arc<D>,
        expected: GtpuSessionGroup,
    ) -> GtpuSessionSelectorOperation<GtpuSessionSelectorRetiredClaim>
    where
        B: Send + Sync + 'static,
        D: GtpuDataplaneBackend + Send + Sync + 'static,
    {
        let authority = self.clone();
        let scope = self.storage_scope_commitment;
        spawn_selector_operation(
            scope,
            GtpuSessionSelectorCoordinatorError::Backend,
            async move {
                authority
                    .recover_retired_owned(backend.as_ref(), expected)
                    .await
            },
        )
    }

    async fn recover_retired_owned<D>(
        &self,
        backend: &D,
        expected: GtpuSessionGroup,
    ) -> Result<GtpuSessionSelectorRetiredClaim, GtpuSessionSelectorCoordinatorError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        self.ensure_backend_namespace(backend)
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let admission = self
            .retired_admission(&expected)
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let readback = Self::authorized_readback(backend, expected.clone(), admission).await?;
        let admission = self
            .retired_admission(&expected)
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        matches!(readback, crate::GtpuSessionGroupReadback::Absent)
            .then_some(GtpuSessionSelectorRetiredClaim {
                group: expected,
                admission,
            })
            .ok_or(GtpuSessionSelectorCoordinatorError::Backend)
    }

    /// Retire an Active claim in the only permitted order: durable Retiring,
    /// exact backend removal, exact stable absence, durable Retired.
    pub fn retire<D>(
        &self,
        backend: Arc<D>,
        active: GtpuSessionSelectorActiveClaim,
        expected: GtpuSessionGroup,
    ) -> GtpuSessionSelectorOperation<GtpuSessionSelectorRetiredClaim>
    where
        B: Send + Sync + 'static,
        D: GtpuDataplaneBackend + Send + Sync + 'static,
    {
        let authority = self.clone();
        let scope = self.storage_scope_commitment;
        spawn_selector_operation(
            scope,
            GtpuSessionSelectorCoordinatorError::Backend,
            async move {
                authority
                    .retire_owned(backend.as_ref(), active, expected)
                    .await
            },
        )
    }

    async fn retire_owned<D>(
        &self,
        backend: &D,
        active: GtpuSessionSelectorActiveClaim,
        expected: GtpuSessionGroup,
    ) -> Result<GtpuSessionSelectorRetiredClaim, GtpuSessionSelectorCoordinatorError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        self.ensure_backend_namespace(backend)
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        if !active.0.validates(&expected) {
            return Err(GtpuSessionSelectorCoordinatorError::Namespace);
        }
        let admission = active.0;
        self.transition_retiring(&admission)
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let handoff = self
            .mark_retirement_backend_started(&expected)
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let BackendStartHandoff::Transitioned(admission) = handoff else {
            return Err(GtpuSessionSelectorCoordinatorError::Namespace);
        };
        self.complete_retirement(backend, expected, admission).await
    }

    /// Recover a crash after durable Retiring.  Only exact absence can finish
    /// retirement; partial or ambiguous dataplane state remains Retiring.
    pub fn recover_retiring<D>(
        &self,
        backend: Arc<D>,
        expected: GtpuSessionGroup,
    ) -> GtpuSessionSelectorOperation<GtpuSessionSelectorRetiredClaim>
    where
        B: Send + Sync + 'static,
        D: GtpuDataplaneBackend + Send + Sync + 'static,
    {
        let authority = self.clone();
        let scope = self.storage_scope_commitment;
        spawn_selector_operation(
            scope,
            GtpuSessionSelectorCoordinatorError::Backend,
            async move {
                authority
                    .recover_retiring_owned(backend.as_ref(), expected)
                    .await
            },
        )
    }

    async fn recover_retiring_owned<D>(
        &self,
        backend: &D,
        expected: GtpuSessionGroup,
    ) -> Result<GtpuSessionSelectorRetiredClaim, GtpuSessionSelectorCoordinatorError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        self.ensure_backend_namespace(backend)
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        // The Retiring(false) coordinate still represents the exact prior
        // Active graph. A generic structural Active readback cannot prove no
        // remove effect occurred: only the opaque backend inspection below
        // binds that negative fact to the previous terminal stamp.
        if let Ok(admission) = self.retiring_admission(&expected, Some(false)).await {
            let no_effect = tokio::time::timeout(
                SELECTOR_NAMESPACE_MAX_EFFECT_DURATION,
                backend.inspect_retiring_selector_no_effect(&expected, &admission),
            )
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Backend)?
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Backend)?;
            if !matches!(
                no_effect,
                crate::GtpuSessionSelectorRetiringRecovery::ExactPreviousActive
            ) {
                return Err(GtpuSessionSelectorCoordinatorError::Backend);
            }
            let handoff = self
                .mark_retirement_backend_started(&expected)
                .await
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
            return match handoff {
                BackendStartHandoff::Transitioned(admission) => {
                    self.complete_retirement(backend, expected, admission).await
                }
                BackendStartHandoff::AlreadyStarted(admission) => {
                    self.recover_retiring_after_competing_start(backend, expected, admission)
                        .await
                }
            };
        }

        let admission = self
            .retiring_admission(&expected, Some(true))
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let readback = Self::authorized_readback(backend, expected.clone(), admission).await?;
        if matches!(readback, crate::GtpuSessionGroupReadback::Absent) {
            let admission = self
                .retiring_admission(&expected, Some(true))
                .await
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
            let admission = self
                .transition_retired(&admission)
                .await
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
            return Ok(GtpuSessionSelectorRetiredClaim {
                group: expected,
                admission,
            });
        }
        self.recover_retiring_started(backend, expected).await
    }

    /// Observe only final state after losing the false-to-true Retiring
    /// handoff. It deliberately cannot replay a removal based on a stale
    /// prior-Active proof while the winning supervisor owns that coordinate.
    async fn recover_retiring_after_competing_start<D>(
        &self,
        backend: &D,
        expected: GtpuSessionGroup,
        admission: GtpuSessionSelectorAdmission,
    ) -> Result<GtpuSessionSelectorRetiredClaim, GtpuSessionSelectorCoordinatorError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        if !matches!(
            Self::authorized_readback(backend, expected.clone(), admission).await?,
            crate::GtpuSessionGroupReadback::Absent
        ) {
            return Err(GtpuSessionSelectorCoordinatorError::Backend);
        }
        let admission = self
            .retiring_admission(&expected, Some(true))
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let admission = self
            .transition_retired(&admission)
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        Ok(GtpuSessionSelectorRetiredClaim {
            group: expected,
            admission,
        })
    }

    /// Resume a previously started Retiring supervisor only after an exact
    /// no-effect predecessor proof or exact pending-remove journal/stamp.
    async fn recover_retiring_started<D>(
        &self,
        backend: &D,
        expected: GtpuSessionGroup,
    ) -> Result<GtpuSessionSelectorRetiredClaim, GtpuSessionSelectorCoordinatorError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        let admission = self
            .retiring_admission(&expected, Some(true))
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let resume = tokio::time::timeout(
            SELECTOR_NAMESPACE_MAX_EFFECT_DURATION,
            backend.inspect_retiring_selector_resume(&expected, &admission),
        )
        .await
        .map_err(|_| GtpuSessionSelectorCoordinatorError::Backend)?
        .map_err(|_| GtpuSessionSelectorCoordinatorError::Backend)?;
        if !matches!(
            resume,
            crate::GtpuSessionSelectorRetiringResume::NoEffect
                | crate::GtpuSessionSelectorRetiringResume::ExactPendingRemove
        ) {
            return Err(GtpuSessionSelectorCoordinatorError::Backend);
        }
        self.complete_retirement(backend, expected, admission).await
    }

    async fn effect_and_activate<D>(
        &self,
        backend: &D,
        desired: GtpuSessionGroup,
        admission: GtpuSessionSelectorAdmission,
    ) -> Result<GtpuSessionSelectorActiveClaim, GtpuSessionSelectorCoordinatorError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        let request = GtpuSessionGroupReconcileRequest::new(desired.clone(), admission)
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        self.complete_effect(backend, desired, request).await
    }

    async fn complete_effect<D>(
        &self,
        backend: &D,
        desired: GtpuSessionGroup,
        request: GtpuSessionGroupReconcileRequest,
    ) -> Result<GtpuSessionSelectorActiveClaim, GtpuSessionSelectorCoordinatorError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        let receipt = tokio::time::timeout(
            SELECTOR_NAMESPACE_MAX_EFFECT_DURATION,
            backend.reconcile_pdp_context_group_authorized(GtpuSessionSelectorEffectRequest {
                request,
            }),
        )
        .await
        .map_err(|_| GtpuSessionSelectorCoordinatorError::Backend)?;
        let outcome = receipt
            .ok()
            .and_then(GtpuSessionSelectorBackendReceipt::into_effect)
            .ok_or(GtpuSessionSelectorCoordinatorError::Backend)?;
        if !matches!(
            outcome,
            GtpuSessionGroupReconcileOutcome::Activated
                | GtpuSessionGroupReconcileOutcome::ExactAlreadyActive
        ) {
            return Err(GtpuSessionSelectorCoordinatorError::Backend);
        }
        let admission = self
            .installing_admission(&desired, Some(true))
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        if self
            .require_exact_active(backend, desired.clone(), admission)
            .await
            .is_err()
        {
            return Err(GtpuSessionSelectorCoordinatorError::Backend);
        }
        self.activate_claim(&desired)
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)
    }

    async fn require_exact_active<D>(
        &self,
        backend: &D,
        desired: GtpuSessionGroup,
        admission: GtpuSessionSelectorAdmission,
    ) -> Result<(), GtpuSessionSelectorCoordinatorError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        let readback = Self::authorized_readback(backend, desired.clone(), admission).await?;
        matches!(readback, crate::GtpuSessionGroupReadback::Active(ref active) if active == &desired)
            .then_some(())
            .ok_or(GtpuSessionSelectorCoordinatorError::Backend)
    }

    async fn authorized_readback<D>(
        backend: &D,
        expected: GtpuSessionGroup,
        admission: GtpuSessionSelectorAdmission,
    ) -> Result<crate::GtpuSessionGroupReadback, GtpuSessionSelectorCoordinatorError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        let receipt = tokio::time::timeout(
            SELECTOR_NAMESPACE_MAX_EFFECT_DURATION,
            backend.read_pdp_context_group_with_lease(GtpuSessionSelectorReadbackRequest {
                expected,
                admission,
            }),
        )
        .await
        .map_err(|_| GtpuSessionSelectorCoordinatorError::Backend)?;
        receipt
            .ok()
            .and_then(GtpuSessionSelectorBackendReceipt::into_readback)
            .ok_or(GtpuSessionSelectorCoordinatorError::Backend)
    }

    async fn complete_retirement<D>(
        &self,
        backend: &D,
        expected: GtpuSessionGroup,
        admission: GtpuSessionSelectorAdmission,
    ) -> Result<GtpuSessionSelectorRetiredClaim, GtpuSessionSelectorCoordinatorError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        let receipt = tokio::time::timeout(
            SELECTOR_NAMESPACE_MAX_EFFECT_DURATION,
            backend.remove_pdp_context_group_with_lease(GtpuSessionSelectorRemovalRequest {
                expected: expected.clone(),
                admission,
            }),
        )
        .await
        .map_err(|_| GtpuSessionSelectorCoordinatorError::Backend)?;
        match receipt
            .ok()
            .and_then(GtpuSessionSelectorBackendReceipt::into_removal)
        {
            Some(
                GtpuSessionGroupRemovalOutcome::Removed
                | GtpuSessionGroupRemovalOutcome::AlreadyAbsent,
            ) => {}
            Some(_) | None => return Err(GtpuSessionSelectorCoordinatorError::Backend),
        }
        let admission = self
            .retiring_admission(&expected, Some(true))
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let readback = Self::authorized_readback(backend, expected.clone(), admission).await?;
        if !matches!(readback, crate::GtpuSessionGroupReadback::Absent) {
            return Err(GtpuSessionSelectorCoordinatorError::Backend);
        }
        let admission = self
            .retiring_admission(&expected, Some(true))
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let admission = self
            .transition_retired(&admission)
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        Ok(GtpuSessionSelectorRetiredClaim {
            group: expected,
            admission,
        })
    }

    async fn claim_fresh<D>(
        &self,
        backend: &D,
        desired: &GtpuSessionGroup,
    ) -> Result<GtpuSessionSelectorAdmission, GtpuSessionSelectorNamespaceError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        self.ensure_backend_namespace(backend).await?;
        let canonical = CanonicalClaim::from_group(desired);
        for _ in 0..MAX_CAS_RETRIES {
            let (record, mut state) = self.read_state().await?;
            state.bind_or_validate(desired.device_id(), self.maximum_operation_atoms, None)?;
            let claim = canonical
                .clone()
                .with_key(&state.selector_digest_key)
                .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
            let atoms = claim
                .selector_atoms(&state.selector_digest_key)
                .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
            if atoms.len() > self.maximum_operation_atoms {
                return Err(GtpuSessionSelectorNamespaceError::CapacityExhausted);
            }
            if state.groups.contains_key(&claim.group_fingerprint) {
                return Err(GtpuSessionSelectorNamespaceError::GroupClaimed);
            }
            if atoms.iter().any(|atom| {
                state.selectors.contains_key(atom)
                    || state.published_atoms.contains(atom)
                    || state.tombstones.contains(atom)
            }) {
                return Err(GtpuSessionSelectorNamespaceError::SelectorClaimed);
            }
            state.preflight_fresh_claim(atoms.len())?;
            let generation = state.next_generation()?;
            let operation_nonce = random_nonzero_nonce()?;
            let terminal_generation = state.next_generation()?;
            let terminal_operation_nonce = random_nonzero_nonce()?;
            for atom in &atoms {
                state.selectors.insert(
                    *atom,
                    SelectorState::Installing {
                        group: claim.group_fingerprint,
                        generation,
                    },
                );
                state.published_atoms.insert(*atom);
            }
            state.groups.insert(
                claim.group_fingerprint,
                GroupState::Installing {
                    device: claim.device_fingerprint,
                    selectors: claim.selector_set_fingerprint,
                    desired: claim.desired_fingerprint,
                    atoms: atoms.clone(),
                    generation,
                    operation_nonce,
                    terminal_generation,
                    terminal_operation_nonce,
                    backend_started: false,
                },
            );
            let admission = state.issue_admission_with_terminal(
                self.storage_scope_commitment,
                &claim,
                generation,
                operation_nonce,
                SelectorAuthorityCoordinate {
                    generation: terminal_generation,
                    nonce: terminal_operation_nonce,
                },
                None,
                SelectorAdmissionPhase::Installing,
                false,
            )?;
            if self.replace(record.as_ref(), state).await? {
                return Ok(admission);
            }
        }
        Err(GtpuSessionSelectorNamespaceError::Indeterminate)
    }

    async fn claim_reused<D>(
        &self,
        backend: &D,
        desired: &GtpuSessionGroup,
        proof: &crate::GtpuSessionSelectorReuseProof,
    ) -> Result<GtpuSessionSelectorAdmission, GtpuSessionSelectorNamespaceError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        self.ensure_backend_namespace(backend).await?;
        let canonical = CanonicalClaim::from_group(desired);
        let source_canonical = CanonicalClaim::from_group(proof.retired_group());
        if desired.device_id() != proof.retired_group().device_id()
            || desired.id() == proof.retired_group().id()
            || canonical.atoms != source_canonical.atoms
        {
            return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
        }
        for _ in 0..MAX_CAS_RETRIES {
            let (record, mut state) = self.read_state().await?;
            state.bind_or_validate(desired.device_id(), self.maximum_operation_atoms, None)?;
            let claim = canonical
                .clone()
                .with_key(&state.selector_digest_key)
                .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
            let source = source_canonical
                .clone()
                .with_key(&state.selector_digest_key)
                .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
            let atoms = claim
                .selector_atoms(&state.selector_digest_key)
                .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
            let source_is_exact = matches!(state.groups.get(&source.group_fingerprint), Some(GroupState::Retired { device, selectors, desired: source_desired, atoms: source_atoms, successor: None, .. }) if *device == source.device_fingerprint && *selectors == source.selector_set_fingerprint && *source_desired == source.desired_fingerprint && *source_atoms == atoms);
            if state.groups.contains_key(&claim.group_fingerprint)
                || !source_is_exact
                || !atoms.iter().all(|atom| {
                    matches!(state.selectors.get(atom), Some(SelectorState::Retired))
                        && state.tombstones.contains(atom)
                })
            {
                return Err(GtpuSessionSelectorNamespaceError::SelectorClaimed);
            }
            state.preflight_reissue(atoms.len())?;
            let generation = state.next_generation()?;
            let operation_nonce = random_nonzero_nonce()?;
            let terminal_generation = state.next_generation()?;
            let terminal_operation_nonce = random_nonzero_nonce()?;
            let Some(GroupState::Retired {
                device,
                selectors,
                desired: source_desired,
                atoms: source_atoms,
                generation: source_generation,
                operation_nonce: source_nonce,
                successor: None,
            }) = state.groups.get(&source.group_fingerprint).cloned()
            else {
                return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
            };
            state.groups.insert(
                source.group_fingerprint,
                GroupState::Retired {
                    device,
                    selectors,
                    desired: source_desired,
                    atoms: source_atoms,
                    generation: source_generation,
                    operation_nonce: source_nonce,
                    successor: Some(RetiredSuccessor {
                        group: claim.group_fingerprint,
                        generation,
                    }),
                },
            );
            for atom in &atoms {
                state.selectors.insert(
                    *atom,
                    SelectorState::Installing {
                        group: claim.group_fingerprint,
                        generation,
                    },
                );
                state.published_atoms.insert(*atom);
            }
            state.groups.insert(
                claim.group_fingerprint,
                GroupState::Installing {
                    device: claim.device_fingerprint,
                    selectors: claim.selector_set_fingerprint,
                    desired: claim.desired_fingerprint,
                    atoms: atoms.clone(),
                    generation,
                    operation_nonce,
                    terminal_generation,
                    terminal_operation_nonce,
                    backend_started: false,
                },
            );
            let admission = state.issue_admission_with_terminal(
                self.storage_scope_commitment,
                &claim,
                generation,
                operation_nonce,
                SelectorAuthorityCoordinate {
                    generation: terminal_generation,
                    nonce: terminal_operation_nonce,
                },
                None,
                SelectorAdmissionPhase::Installing,
                true,
            )?;
            if self.replace(record.as_ref(), state).await? {
                return Ok(admission);
            }
        }
        Err(GtpuSessionSelectorNamespaceError::Indeterminate)
    }

    async fn read_state(
        &self,
    ) -> Result<(Option<StoredSessionRecord>, NamespaceState), GtpuSessionSelectorNamespaceError>
    {
        let record = self
            .store
            .get(&self.namespace_key)
            .await
            .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
        let state = match record.as_ref() {
            None => {
                #[cfg(test)]
                if self.allows_test_raw_open {
                    return Ok((None, NamespaceState::default()));
                }
                return Err(GtpuSessionSelectorNamespaceError::Unprovisioned);
            }
            Some(record)
                if record.key == self.namespace_key
                    && record.state_class == StateClass::AuthoritativeSession
                    && record.state_type.as_str() == "gtpu-selector-namespace-v1"
                    && record.expires_at.is_none() =>
            {
                NamespaceState::decode(record.payload.as_bytes())
                    .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?
            }
            Some(_) => return Err(GtpuSessionSelectorNamespaceError::Indeterminate),
        };
        self.bound_binding(&state)?;
        Ok((record, state))
    }

    async fn verify_open_bound(&self) -> Result<(), GtpuSessionSelectorNamespaceError> {
        let _ = self.read_state().await?;
        Ok(())
    }

    fn bound_binding(
        &self,
        state: &NamespaceState,
    ) -> Result<GtpuSessionSelectorBackendBinding, GtpuSessionSelectorNamespaceError> {
        if state.lifecycle != NamespaceLifecycle::Bound
            || state.decommission_fence.is_some()
            || state.stable_device != Some(self.stable_device.to_bytes())
            || state.pin_commitment != self.pin_commitment
            || state.storage_scope_commitment != self.storage_scope_commitment
        {
            return Err(GtpuSessionSelectorNamespaceError::ConfigurationMismatch);
        }
        state.binding_with_scope(self.storage_scope_commitment)
    }

    async fn ensure_backend_namespace<D>(
        &self,
        backend: &D,
    ) -> Result<(), GtpuSessionSelectorNamespaceError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        let (_, state) = self.read_state().await?;
        let binding = self.bound_binding(&state)?;
        let receipt = tokio::time::timeout(
            SELECTOR_NAMESPACE_MAX_EFFECT_DURATION,
            backend.acquire_selector_namespace_lease(GtpuSessionSelectorBindingLease { binding }),
        )
        .await
        .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?
        .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
        receipt
            .confirms_binding()
            .then_some(())
            .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)
    }

    async fn read_state_for_provision(
        &self,
    ) -> Result<(Option<StoredSessionRecord>, NamespaceState), GtpuSessionSelectorNamespaceError>
    {
        let record = self
            .store
            .get(&self.namespace_key)
            .await
            .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
        let state = match record.as_ref() {
            None => NamespaceState::default(),
            Some(record)
                if record.key == self.namespace_key
                    && record.state_class == StateClass::AuthoritativeSession
                    && record.state_type.as_str() == "gtpu-selector-namespace-v1"
                    && record.expires_at.is_none() =>
            {
                NamespaceState::decode(record.payload.as_bytes())
                    .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?
            }
            Some(_) => return Err(GtpuSessionSelectorNamespaceError::Indeterminate),
        };
        Ok((record, state))
    }

    async fn provision<D>(&self, backend: &D) -> Result<(), GtpuSessionSelectorNamespaceError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        for _ in 0..MAX_CAS_RETRIES {
            let (record, mut state) = self.read_state_for_provision().await?;
            match state.lifecycle {
                NamespaceLifecycle::Unprovisioned if record.is_none() => {
                    state = NamespaceState::provisioned(
                        self.stable_device,
                        self.pin_commitment,
                        self.storage_scope_commitment,
                    );
                    if self.replace(None, state).await? {
                        continue;
                    }
                }
                NamespaceLifecycle::Provisioned => {
                    state.initialize(self.maximum_operation_atoms)?;
                    if self.replace(record.as_ref(), state).await? {
                        continue;
                    }
                }
                NamespaceLifecycle::Initializing => {
                    if state.stable_device != Some(self.stable_device.to_bytes())
                        || state.pin_commitment != self.pin_commitment
                        || state.storage_scope_commitment != self.storage_scope_commitment
                    {
                        return Err(GtpuSessionSelectorNamespaceError::ConfigurationMismatch);
                    }
                    let binding = state.binding_with_scope(self.storage_scope_commitment)?;
                    let receipt = tokio::time::timeout(
                        SELECTOR_NAMESPACE_MAX_EFFECT_DURATION,
                        backend.provision_selector_namespace_authorized(
                            GtpuSessionSelectorProvisionRequest { binding },
                        ),
                    )
                    .await
                    .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?
                    .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
                    if !receipt.confirms_provisioning() {
                        return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
                    }
                    state.lifecycle = NamespaceLifecycle::Bound;
                    if self.replace(record.as_ref(), state).await? {
                        self.ensure_backend_namespace(backend).await?;
                        return Ok(());
                    }
                }
                NamespaceLifecycle::Bound => {
                    self.bound_binding(&state)?;
                    self.ensure_backend_namespace(backend).await?;
                    return Ok(());
                }
                NamespaceLifecycle::Decommissioned => {
                    return Err(GtpuSessionSelectorNamespaceError::ConfigurationMismatch);
                }
                _ => return Err(GtpuSessionSelectorNamespaceError::Indeterminate),
            }
        }
        Err(GtpuSessionSelectorNamespaceError::Indeterminate)
    }

    async fn decommission_owned<D>(
        &self,
        backend: &D,
    ) -> Result<(), GtpuSessionSelectorCoordinatorError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        for _ in 0..MAX_CAS_RETRIES {
            // The durable worker lease intentionally spans only this one
            // attempt.  Each backend terminal-fence call is required to take
            // and release its bounded host lock before it returns, so every
            // protected-store CAS/readback below is outside that host lock.
            // Releasing the durable lease between retries also makes a lost
            // compare-and-set or an interrupted terminal effect recover from
            // authoritative durable state rather than an in-memory plan.
            let mut lease = self
                .store
                .acquire(&self.namespace_key, self.owner.clone(), self.lease_ttl)
                .await
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
            let attempt = self.decommission_with_lease(backend, &mut lease).await;
            let released = self.store.release(lease).await;
            if released.is_err() {
                return Err(GtpuSessionSelectorCoordinatorError::Namespace);
            }
            match attempt? {
                DecommissionAttempt::Retry => continue,
                DecommissionAttempt::Complete => return Ok(()),
            }
        }
        Err(GtpuSessionSelectorCoordinatorError::Namespace)
    }

    /// Execute one exact terminal-fence attempt while a durable worker lease
    /// is held.  The ordering is deliberately fixed:
    ///
    /// 1. durable lease;
    /// 2. bounded backend binding validation, which releases its host lock;
    /// 3. durable precommit CAS and readback, if needed;
    /// 4. a freshly locked/revalidated exact terminal-capsule operation;
    /// 5. durable final CAS and readback; and
    /// 6. a separately locked exact capsule cleanup/readback.
    ///
    /// In particular, no `SessionStore` operation is awaited from inside an
    /// external backend call.  Backends must retain the same lock discipline
    /// for every terminal-fence port; their opaque receipts are the boundary
    /// that makes that requirement auditable here.
    async fn decommission_with_lease<D>(
        &self,
        backend: &D,
        lease: &mut opc_session_store::LeaseGuard,
    ) -> Result<DecommissionAttempt, GtpuSessionSelectorCoordinatorError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        let (record, mut state) = self
            .read_state_for_provision()
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let Some(record) = record.as_ref() else {
            return Err(GtpuSessionSelectorCoordinatorError::Namespace);
        };
        if state.stable_device != Some(self.stable_device.to_bytes())
            || state.pin_commitment != self.pin_commitment
            || state.storage_scope_commitment != self.storage_scope_commitment
        {
            return Err(GtpuSessionSelectorCoordinatorError::Namespace);
        }
        let binding = state
            .binding_with_scope(self.storage_scope_commitment)
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;

        let fence = match (state.lifecycle, state.decommission_fence) {
            (NamespaceLifecycle::Bound, None) => {
                let absence = tokio::time::timeout(
                    SELECTOR_NAMESPACE_MAX_EFFECT_DURATION,
                    backend.inspect_selector_namespace_decommission_fence(
                        GtpuSessionSelectorDecommissionInspectRequest {
                            binding,
                            expected_fence: None,
                        },
                    ),
                )
                .await
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Backend)?
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Backend)?;
                if !absence.confirms_decommission_fence_absent() {
                    return Err(GtpuSessionSelectorCoordinatorError::Backend);
                }
                state
                    .precommit_decommission()
                    .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
                if self
                    .replace_with_lease(Some(record), state, lease)
                    .await
                    .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?
                {
                    return Ok(DecommissionAttempt::Retry);
                }
                return Ok(DecommissionAttempt::Retry);
            }
            (NamespaceLifecycle::Bound | NamespaceLifecycle::Decommissioned, Some(fence))
                if state.decommission_fence_is_exact(fence) =>
            {
                fence
            }
            _ => return Err(GtpuSessionSelectorCoordinatorError::Namespace),
        };

        let inspection = tokio::time::timeout(
            SELECTOR_NAMESPACE_MAX_EFFECT_DURATION,
            backend.inspect_selector_namespace_decommission_fence(
                GtpuSessionSelectorDecommissionInspectRequest {
                    binding,
                    expected_fence: Some(fence),
                },
            ),
        )
        .await
        .map_err(|_| GtpuSessionSelectorCoordinatorError::Backend)?
        .map_err(|_| GtpuSessionSelectorCoordinatorError::Backend)?;
        if inspection.confirms_decommission_fence_absent() {
            let created = tokio::time::timeout(
                SELECTOR_NAMESPACE_MAX_EFFECT_DURATION,
                backend.create_selector_namespace_decommission_fence(
                    GtpuSessionSelectorDecommissionRequest { binding, fence },
                ),
            )
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Backend)?
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Backend)?;
            if !created.confirms_decommission_fence_exact() {
                return Err(GtpuSessionSelectorCoordinatorError::Backend);
            }
        } else if !inspection.confirms_decommission_fence_exact() {
            return Err(GtpuSessionSelectorCoordinatorError::Backend);
        }

        let readback = tokio::time::timeout(
            SELECTOR_NAMESPACE_MAX_EFFECT_DURATION,
            backend.read_selector_namespace_decommission_fence(
                GtpuSessionSelectorDecommissionReadbackRequest { binding, fence },
            ),
        )
        .await
        .map_err(|_| GtpuSessionSelectorCoordinatorError::Backend)?
        .map_err(|_| GtpuSessionSelectorCoordinatorError::Backend)?;
        if !readback.confirms_decommission_fence_exact() {
            return Err(GtpuSessionSelectorCoordinatorError::Backend);
        }

        if state.lifecycle == NamespaceLifecycle::Bound {
            state.lifecycle = NamespaceLifecycle::Decommissioned;
            if !self
                .replace_with_lease(Some(record), state, lease)
                .await
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?
            {
                return Ok(DecommissionAttempt::Retry);
            }
        }

        // This intentionally reacquires the backend's bounded host lock only
        // after the final durable state readback. It is the terminal cleanup
        // fence: a concurrent stale worker cannot report completion unless
        // the one persisted capsule is still exact.
        let cleanup = tokio::time::timeout(
            SELECTOR_NAMESPACE_MAX_EFFECT_DURATION,
            backend.read_selector_namespace_decommission_fence(
                GtpuSessionSelectorDecommissionReadbackRequest { binding, fence },
            ),
        )
        .await
        .map_err(|_| GtpuSessionSelectorCoordinatorError::Backend)?
        .map_err(|_| GtpuSessionSelectorCoordinatorError::Backend)?;
        if !cleanup.confirms_decommission_fence_exact() {
            return Err(GtpuSessionSelectorCoordinatorError::Backend);
        }
        Ok(DecommissionAttempt::Complete)
    }

    async fn replace(
        &self,
        current: Option<&StoredSessionRecord>,
        state: NamespaceState,
    ) -> Result<bool, GtpuSessionSelectorNamespaceError> {
        let mut lease = self
            .store
            .acquire(&self.namespace_key, self.owner.clone(), self.lease_ttl)
            .await
            .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
        let result = self.replace_with_lease(current, state, &mut lease).await;
        let released = self.store.release(lease).await;
        if released.is_err() {
            return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
        }
        result
    }

    /// Fenced durable replacement using an already-held worker lease.
    ///
    /// The compare-and-set consumes a clone of the guard because store ports
    /// deliberately make the credential affine. The original guard remains
    /// available solely for an explicit release after this sequence; no
    /// second write is made without first renewing it again.
    async fn replace_with_lease(
        &self,
        current: Option<&StoredSessionRecord>,
        state: NamespaceState,
        lease: &mut opc_session_store::LeaseGuard,
    ) -> Result<bool, GtpuSessionSelectorNamespaceError> {
        if !state.is_complete() {
            return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
        }
        let bytes = state.encode();
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(GtpuSessionSelectorNamespaceError::CapacityExhausted);
        }
        let generation = match current {
            Some(record) => record
                .generation
                .next()
                .ok_or(GtpuSessionSelectorNamespaceError::GenerationExhausted)?,
            None => Generation::new(1),
        };
        // Renew immediately before the fenced CAS. This makes a backend that
        // cannot prove lease continuity fail closed, and ensures the exact
        // fence persisted below is the current worker fence rather than an
        // acquire-time observation that might have expired while encoding.
        *lease = self
            .store
            .renew(lease, self.lease_ttl)
            .await
            .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
        let replacement = StoredSessionRecord {
            key: self.namespace_key.clone(),
            generation,
            owner: self.owner.clone(),
            fence: lease.fence(),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("gtpu-selector-namespace-v1"),
            expires_at: None,
            payload: EncryptedSessionPayload::new(bytes),
        };
        let expected_generation = current.map(|record| record.generation);
        match self
            .store
            .compare_and_set(CompareAndSet {
                key: self.namespace_key.clone(),
                lease: lease.clone(),
                expected_generation,
                new_record: replacement.clone(),
            })
            .await
        {
            Ok(CompareAndSetResult::Success) => self.readback_matches(&replacement).await,
            Ok(CompareAndSetResult::Conflict { .. }) => Ok(false),
            Err(_) => self.readback_matches(&replacement).await,
        }
    }

    async fn readback_matches(
        &self,
        expected: &StoredSessionRecord,
    ) -> Result<bool, GtpuSessionSelectorNamespaceError> {
        let observed = self
            .store
            .get(&self.namespace_key)
            .await
            .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
        Ok(
            matches!(observed, Some(record) if record.generation == expected.generation && record.key == expected.key && record.owner == expected.owner && record.fence == expected.fence && record.state_class == expected.state_class && record.state_type == expected.state_type && record.expires_at.is_none() && record.payload.as_bytes() == expected.payload.as_bytes()),
        )
    }

    /// Durably transfer an Installing coordinate from a pre-effect
    /// reservation to its detached backend supervisor.
    ///
    /// The fenced CAS/readback is the last awaited operation before the
    /// caller consumes the returned affine admission into the backend effect.
    /// A process loss before this transition is recoverable only through the
    /// backend's independent no-effect inspection; a loss after it may resume
    /// only the same exact coordinate.
    async fn mark_install_backend_started(
        &self,
        desired: &GtpuSessionGroup,
    ) -> Result<BackendStartHandoff, GtpuSessionSelectorNamespaceError> {
        let canonical = CanonicalClaim::from_group(desired);
        for _ in 0..MAX_CAS_RETRIES {
            let (record, mut state) = self.read_state().await?;
            let claim = canonical
                .clone()
                .with_key(&state.selector_digest_key)
                .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
            let Some(GroupState::Installing {
                device,
                selectors,
                desired: semantic,
                atoms,
                generation,
                operation_nonce,
                terminal_generation,
                terminal_operation_nonce,
                backend_started,
            }) = state.groups.get(&claim.group_fingerprint).cloned()
            else {
                return Err(GtpuSessionSelectorNamespaceError::StaleGeneration);
            };
            if device != claim.device_fingerprint
                || selectors != claim.selector_set_fingerprint
                || semantic != claim.desired_fingerprint
            {
                return Err(GtpuSessionSelectorNamespaceError::StaleGeneration);
            }
            let admission = state.issue_admission_with_terminal(
                self.storage_scope_commitment,
                &claim,
                generation,
                operation_nonce,
                SelectorAuthorityCoordinate {
                    generation: terminal_generation,
                    nonce: terminal_operation_nonce,
                },
                None,
                SelectorAdmissionPhase::Installing,
                false,
            )?;
            if backend_started {
                return Ok(BackendStartHandoff::AlreadyStarted(admission));
            }
            state.groups.insert(
                claim.group_fingerprint,
                GroupState::Installing {
                    device,
                    selectors,
                    desired: semantic,
                    atoms,
                    generation,
                    operation_nonce,
                    terminal_generation,
                    terminal_operation_nonce,
                    backend_started: true,
                },
            );
            if self.replace(record.as_ref(), state).await? {
                return Ok(BackendStartHandoff::Transitioned(admission));
            }
        }
        Err(GtpuSessionSelectorNamespaceError::Indeterminate)
    }

    /// Durably transfer a Retiring coordinate from the exact previous Active
    /// terminal to its detached backend removal supervisor.
    async fn mark_retirement_backend_started(
        &self,
        expected: &GtpuSessionGroup,
    ) -> Result<BackendStartHandoff, GtpuSessionSelectorNamespaceError> {
        let canonical = CanonicalClaim::from_group(expected);
        for _ in 0..MAX_CAS_RETRIES {
            let (record, mut state) = self.read_state().await?;
            let claim = canonical
                .clone()
                .with_key(&state.selector_digest_key)
                .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
            let Some(GroupState::Retiring {
                device,
                selectors,
                desired: semantic,
                atoms,
                generation,
                operation_nonce,
                terminal_generation,
                terminal_operation_nonce,
                previous_terminal,
                backend_started,
            }) = state.groups.get(&claim.group_fingerprint).cloned()
            else {
                return Err(GtpuSessionSelectorNamespaceError::StaleGeneration);
            };
            if device != claim.device_fingerprint
                || selectors != claim.selector_set_fingerprint
                || semantic != claim.desired_fingerprint
            {
                return Err(GtpuSessionSelectorNamespaceError::StaleGeneration);
            }
            let admission = state.issue_admission_with_terminal(
                self.storage_scope_commitment,
                &claim,
                generation,
                operation_nonce,
                SelectorAuthorityCoordinate {
                    generation: terminal_generation,
                    nonce: terminal_operation_nonce,
                },
                Some(previous_terminal),
                SelectorAdmissionPhase::Retiring,
                false,
            )?;
            if backend_started {
                return Ok(BackendStartHandoff::AlreadyStarted(admission));
            }
            state.groups.insert(
                claim.group_fingerprint,
                GroupState::Retiring {
                    device,
                    selectors,
                    desired: semantic,
                    atoms,
                    generation,
                    operation_nonce,
                    terminal_generation,
                    terminal_operation_nonce,
                    previous_terminal,
                    backend_started: true,
                },
            );
            if self.replace(record.as_ref(), state).await? {
                return Ok(BackendStartHandoff::Transitioned(admission));
            }
        }
        Err(GtpuSessionSelectorNamespaceError::Indeterminate)
    }

    async fn activate_claim(
        &self,
        desired: &GtpuSessionGroup,
    ) -> Result<GtpuSessionSelectorActiveClaim, GtpuSessionSelectorNamespaceError> {
        self.transition_phase(desired, 0)
            .await
            .map(GtpuSessionSelectorActiveClaim)
    }

    async fn transition_retiring(
        &self,
        admission: &GtpuSessionSelectorAdmission,
    ) -> Result<GtpuSessionSelectorAdmission, GtpuSessionSelectorNamespaceError> {
        self.transition_phase_for_admission(admission, 1).await
    }

    async fn transition_retired(
        &self,
        admission: &GtpuSessionSelectorAdmission,
    ) -> Result<GtpuSessionSelectorAdmission, GtpuSessionSelectorNamespaceError> {
        self.transition_phase_for_admission(admission, 2).await
    }

    async fn retiring_admission(
        &self,
        desired: &GtpuSessionGroup,
        expected_backend_started: Option<bool>,
    ) -> Result<GtpuSessionSelectorAdmission, GtpuSessionSelectorNamespaceError> {
        let canonical = CanonicalClaim::from_group(desired);
        let (_, state) = self.read_state().await?;
        let claim = canonical
            .with_key(&state.selector_digest_key)
            .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
        let Some(GroupState::Retiring {
            device,
            selectors,
            desired: semantic,
            generation,
            operation_nonce,
            terminal_generation,
            terminal_operation_nonce,
            previous_terminal,
            backend_started,
            ..
        }) = state.groups.get(&claim.group_fingerprint)
        else {
            return Err(GtpuSessionSelectorNamespaceError::StaleGeneration);
        };
        if *device != claim.device_fingerprint
            || *selectors != claim.selector_set_fingerprint
            || *semantic != claim.desired_fingerprint
            || expected_backend_started.is_some_and(|expected| expected != *backend_started)
        {
            return Err(GtpuSessionSelectorNamespaceError::StaleGeneration);
        }
        state.issue_admission_with_terminal(
            self.storage_scope_commitment,
            &claim,
            *generation,
            *operation_nonce,
            SelectorAuthorityCoordinate {
                generation: *terminal_generation,
                nonce: *terminal_operation_nonce,
            },
            Some(*previous_terminal),
            SelectorAdmissionPhase::Retiring,
            false,
        )
    }

    async fn active_admission(
        &self,
        desired: &GtpuSessionGroup,
    ) -> Result<GtpuSessionSelectorAdmission, GtpuSessionSelectorNamespaceError> {
        self.admission_for_final_phase(desired, 0).await
    }

    async fn retired_admission(
        &self,
        desired: &GtpuSessionGroup,
    ) -> Result<GtpuSessionSelectorAdmission, GtpuSessionSelectorNamespaceError> {
        self.admission_for_final_phase(desired, 2).await
    }

    /// Reconstruct the private issuance/recovery descriptor persisted in a
    /// final group row. `phase` is 0 for Active and 2 for Retired.
    async fn admission_for_final_phase(
        &self,
        desired: &GtpuSessionGroup,
        phase: u8,
    ) -> Result<GtpuSessionSelectorAdmission, GtpuSessionSelectorNamespaceError> {
        let canonical = CanonicalClaim::from_group(desired);
        let (_, state) = self.read_state().await?;
        let claim = canonical
            .with_key(&state.selector_digest_key)
            .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
        let descriptor = match state.groups.get(&claim.group_fingerprint) {
            Some(GroupState::Active {
                device,
                selectors,
                desired,
                generation,
                operation_nonce,
                ..
            }) if phase == 0 => (*device, *selectors, *desired, *generation, *operation_nonce),
            Some(GroupState::Retired {
                device,
                selectors,
                desired,
                generation,
                operation_nonce,
                ..
            }) if phase == 2 => (*device, *selectors, *desired, *generation, *operation_nonce),
            _ => return Err(GtpuSessionSelectorNamespaceError::StaleGeneration),
        };
        let (device, selectors, semantic, generation, operation_nonce) = descriptor;
        if device != claim.device_fingerprint
            || selectors != claim.selector_set_fingerprint
            || semantic != claim.desired_fingerprint
        {
            return Err(GtpuSessionSelectorNamespaceError::StaleGeneration);
        }
        state.issue_admission(
            self.storage_scope_commitment,
            &claim,
            generation,
            operation_nonce,
            if phase == 0 {
                SelectorAdmissionPhase::Active
            } else {
                SelectorAdmissionPhase::Retired
            },
            false,
        )
    }

    async fn installing_admission(
        &self,
        desired: &GtpuSessionGroup,
        expected_backend_started: Option<bool>,
    ) -> Result<GtpuSessionSelectorAdmission, GtpuSessionSelectorNamespaceError> {
        let canonical = CanonicalClaim::from_group(desired);
        let (_, state) = self.read_state().await?;
        let claim = canonical
            .with_key(&state.selector_digest_key)
            .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
        let Some(GroupState::Installing {
            device,
            selectors,
            desired: semantic,
            generation,
            operation_nonce,
            terminal_generation,
            terminal_operation_nonce,
            backend_started,
            ..
        }) = state.groups.get(&claim.group_fingerprint)
        else {
            return Err(GtpuSessionSelectorNamespaceError::StaleGeneration);
        };
        if *device != claim.device_fingerprint
            || *selectors != claim.selector_set_fingerprint
            || *semantic != claim.desired_fingerprint
            || expected_backend_started.is_some_and(|expected| expected != *backend_started)
        {
            return Err(GtpuSessionSelectorNamespaceError::StaleGeneration);
        }
        state.issue_admission_with_terminal(
            self.storage_scope_commitment,
            &claim,
            *generation,
            *operation_nonce,
            SelectorAuthorityCoordinate {
                generation: *terminal_generation,
                nonce: *terminal_operation_nonce,
            },
            None,
            SelectorAdmissionPhase::Installing,
            false,
        )
    }

    async fn transition_phase(
        &self,
        desired: &GtpuSessionGroup,
        phase: u8,
    ) -> Result<GtpuSessionSelectorAdmission, GtpuSessionSelectorNamespaceError> {
        let canonical = CanonicalClaim::from_group(desired);
        let (_, state) = self.read_state().await?;
        let claim = canonical
            .with_key(&state.selector_digest_key)
            .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
        let admission = match state.groups.get(&claim.group_fingerprint) {
            Some(GroupState::Installing {
                device,
                selectors,
                desired: semantic,
                generation,
                operation_nonce,
                terminal_generation,
                terminal_operation_nonce,
                ..
            }) if *device == claim.device_fingerprint
                && *selectors == claim.selector_set_fingerprint
                && *semantic == claim.desired_fingerprint =>
            {
                state.issue_admission_with_terminal(
                    self.storage_scope_commitment,
                    &claim,
                    *generation,
                    *operation_nonce,
                    SelectorAuthorityCoordinate {
                        generation: *terminal_generation,
                        nonce: *terminal_operation_nonce,
                    },
                    None,
                    SelectorAdmissionPhase::Installing,
                    false,
                )?
            }
            _ => return Err(GtpuSessionSelectorNamespaceError::StaleGeneration),
        };
        self.transition_phase_for_admission(&admission, phase).await
    }

    async fn transition_phase_for_admission(
        &self,
        admission: &GtpuSessionSelectorAdmission,
        phase: u8,
    ) -> Result<GtpuSessionSelectorAdmission, GtpuSessionSelectorNamespaceError> {
        for _ in 0..MAX_CAS_RETRIES {
            let (record, mut state) = self.read_state().await?;
            let group = state
                .groups
                .get(&admission.group_fingerprint)
                .cloned()
                .ok_or(GtpuSessionSelectorNamespaceError::StaleGeneration)?;
            let successor = match (phase, group) {
                (
                    0,
                    GroupState::Installing {
                        device,
                        selectors,
                        desired,
                        atoms,
                        generation,
                        operation_nonce,
                        terminal_generation,
                        terminal_operation_nonce,
                        backend_started,
                    },
                ) => {
                    if device != admission.device_fingerprint
                        || selectors != admission.selector_set_fingerprint
                        || desired != admission.desired_fingerprint
                        || generation != admission.generation
                        || operation_nonce != admission.operation_nonce
                        || terminal_generation != admission.terminal_generation
                        || terminal_operation_nonce != admission.terminal_operation_nonce
                        || admission.previous_terminal.is_some()
                        || !backend_started
                    {
                        return Err(GtpuSessionSelectorNamespaceError::StaleGeneration);
                    }
                    for atom in &atoms {
                        state.selectors.insert(
                            *atom,
                            SelectorState::Active {
                                group: admission.group_fingerprint,
                                generation: terminal_generation,
                            },
                        );
                        state.published_atoms.insert(*atom);
                    }
                    state.groups.insert(
                        admission.group_fingerprint,
                        GroupState::Active {
                            device,
                            selectors,
                            desired,
                            atoms,
                            generation: terminal_generation,
                            operation_nonce: terminal_operation_nonce,
                        },
                    );
                    admission.with_coordinates(
                        terminal_generation,
                        terminal_operation_nonce,
                        SelectorAuthorityCoordinate {
                            generation: terminal_generation,
                            nonce: terminal_operation_nonce,
                        },
                        None,
                        SelectorAdmissionPhase::Active,
                    )?
                }
                (
                    1,
                    GroupState::Active {
                        device,
                        selectors,
                        desired,
                        atoms,
                        generation,
                        operation_nonce,
                    },
                ) => {
                    if device != admission.device_fingerprint
                        || selectors != admission.selector_set_fingerprint
                        || desired != admission.desired_fingerprint
                        || generation != admission.generation
                        || operation_nonce != admission.operation_nonce
                        || admission.terminal_generation != generation
                        || admission.terminal_operation_nonce != operation_nonce
                        || admission.previous_terminal.is_some()
                    {
                        return Err(GtpuSessionSelectorNamespaceError::StaleGeneration);
                    }
                    let pending_generation = state.next_generation()?;
                    let pending_nonce = random_nonzero_nonce()?;
                    let terminal_generation = state.next_generation()?;
                    let terminal_operation_nonce = random_nonzero_nonce()?;
                    let previous_terminal = SelectorAuthorityCoordinate {
                        generation,
                        nonce: operation_nonce,
                    };
                    for atom in &atoms {
                        state.selectors.insert(
                            *atom,
                            SelectorState::Retiring {
                                group: admission.group_fingerprint,
                                generation: pending_generation,
                            },
                        );
                    }
                    state.groups.insert(
                        admission.group_fingerprint,
                        GroupState::Retiring {
                            device,
                            selectors,
                            desired,
                            atoms,
                            generation: pending_generation,
                            operation_nonce: pending_nonce,
                            terminal_generation,
                            terminal_operation_nonce,
                            previous_terminal,
                            backend_started: false,
                        },
                    );
                    admission.with_coordinates(
                        pending_generation,
                        pending_nonce,
                        SelectorAuthorityCoordinate {
                            generation: terminal_generation,
                            nonce: terminal_operation_nonce,
                        },
                        Some(previous_terminal),
                        SelectorAdmissionPhase::Retiring,
                    )?
                }
                (
                    2,
                    GroupState::Retiring {
                        device,
                        selectors,
                        desired,
                        atoms,
                        generation,
                        operation_nonce,
                        terminal_generation,
                        terminal_operation_nonce,
                        previous_terminal,
                        backend_started,
                    },
                ) => {
                    if device != admission.device_fingerprint
                        || selectors != admission.selector_set_fingerprint
                        || desired != admission.desired_fingerprint
                        || generation != admission.generation
                        || operation_nonce != admission.operation_nonce
                        || terminal_generation != admission.terminal_generation
                        || terminal_operation_nonce != admission.terminal_operation_nonce
                        || admission.previous_terminal != Some(previous_terminal)
                        || !backend_started
                    {
                        return Err(GtpuSessionSelectorNamespaceError::StaleGeneration);
                    }
                    state.preflight_retirement(&atoms)?;
                    for atom in &atoms {
                        state.selectors.insert(*atom, SelectorState::Retired);
                        state.tombstones.insert(*atom);
                    }
                    state.groups.insert(
                        admission.group_fingerprint,
                        GroupState::Retired {
                            device,
                            selectors,
                            desired,
                            atoms,
                            generation: terminal_generation,
                            operation_nonce: terminal_operation_nonce,
                            successor: None,
                        },
                    );
                    admission.with_coordinates(
                        terminal_generation,
                        terminal_operation_nonce,
                        SelectorAuthorityCoordinate {
                            generation: terminal_generation,
                            nonce: terminal_operation_nonce,
                        },
                        None,
                        SelectorAdmissionPhase::Retired,
                    )?
                }
                _ => return Err(GtpuSessionSelectorNamespaceError::StaleGeneration),
            };
            if self.replace(record.as_ref(), state).await? {
                return Ok(successor);
            }
        }
        Err(GtpuSessionSelectorNamespaceError::Indeterminate)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum NamespaceLifecycle {
    #[default]
    Unprovisioned,
    Provisioned,
    Initializing,
    Bound,
    Decommissioned,
}

#[derive(Clone, Default)]
struct NamespaceState {
    lifecycle: NamespaceLifecycle,
    stable_device: Option<[u8; 16]>,
    pin_commitment: [u8; 32],
    storage_scope_commitment: [u8; 32],
    ledger_id: [u8; 16],
    backend_epoch: [u8; 16],
    selector_digest_key: [u8; 32],
    key_commitment: [u8; 32],
    capacity: u32,
    generation: u64,
    /// Present from the durable precommit until the terminal backend marker
    /// is read back. It is retained permanently after decommission so a
    /// rollback/recovery worker has the exact terminal coordinate instead of
    /// inventing a new one.
    decommission_fence: Option<DecommissionFence>,
    selectors: BTreeMap<[u8; 32], SelectorState>,
    groups: BTreeMap<[u8; 32], GroupState>,
    /// Exact, permanent atom-reservation index. An entry is added in the same
    /// CAS that creates an `Installing` group, before the backend effect. It
    /// is never removed: a `Fresh` claim may therefore mean *never reserved*,
    /// not merely absent from the current group or tombstone rows.
    published_atoms: BTreeSet<[u8; 32]>,
    tombstones: BTreeSet<[u8; 32]>,
}

impl NamespaceState {
    fn provisioned(
        stable_device: GtpuSessionDeviceId,
        pin_commitment: [u8; 32],
        storage_scope_commitment: [u8; 32],
    ) -> Self {
        Self {
            lifecycle: NamespaceLifecycle::Provisioned,
            stable_device: Some(stable_device.to_bytes()),
            pin_commitment,
            storage_scope_commitment,
            ..Self::default()
        }
    }

    fn initialize(
        &mut self,
        maximum_atoms: usize,
    ) -> Result<(), GtpuSessionSelectorNamespaceError> {
        if self.lifecycle != NamespaceLifecycle::Provisioned
            || self.stable_device.is_none()
            || self.pin_commitment == [0; 32]
            || self.storage_scope_commitment == [0; 32]
            || self.ledger_id != [0; 16]
            || self.backend_epoch != [0; 16]
            || self.selector_digest_key != [0; 32]
            || self.key_commitment != [0; 32]
            || self.decommission_fence.is_some()
            || !self.selectors.is_empty()
            || !self.groups.is_empty()
            || !self.published_atoms.is_empty()
            || !self.tombstones.is_empty()
        {
            return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
        }
        let capacity = u32::try_from(maximum_atoms)
            .ok()
            .filter(|capacity| {
                *capacity > 0 && *capacity <= SELECTOR_NAMESPACE_MAX_READBACK_ATOMS as u32
            })
            .ok_or(GtpuSessionSelectorNamespaceError::CapacityExhausted)?;
        SysRng
            .try_fill_bytes(&mut self.ledger_id)
            .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
        SysRng
            .try_fill_bytes(&mut self.backend_epoch)
            .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
        SysRng
            .try_fill_bytes(&mut self.selector_digest_key)
            .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
        if self.ledger_id == [0; 16]
            || self.backend_epoch == [0; 16]
            || self.selector_digest_key == [0; 32]
        {
            return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
        }
        let stable_device = self
            .stable_device
            .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
        self.key_commitment = key_commitment(
            &self.selector_digest_key,
            &self.ledger_id,
            &self.pin_commitment,
            &stable_device,
            &self.storage_scope_commitment,
        );
        self.capacity = capacity;
        self.lifecycle = NamespaceLifecycle::Initializing;
        Ok(())
    }

    fn issue_admission(
        &self,
        storage_scope_commitment: [u8; 32],
        claim: &CanonicalClaim,
        generation: GtpuSessionSelectorAuthorityGeneration,
        operation_nonce: [u8; 16],
        phase: SelectorAdmissionPhase,
        retired_reissue: bool,
    ) -> Result<GtpuSessionSelectorAdmission, GtpuSessionSelectorNamespaceError> {
        self.issue_admission_with_terminal(
            storage_scope_commitment,
            claim,
            generation,
            operation_nonce,
            SelectorAuthorityCoordinate {
                generation,
                nonce: operation_nonce,
            },
            None,
            phase,
            retired_reissue,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn issue_admission_with_terminal(
        &self,
        storage_scope_commitment: [u8; 32],
        claim: &CanonicalClaim,
        generation: GtpuSessionSelectorAuthorityGeneration,
        operation_nonce: [u8; 16],
        terminal: SelectorAuthorityCoordinate,
        previous_terminal: Option<SelectorAuthorityCoordinate>,
        phase: SelectorAdmissionPhase,
        retired_reissue: bool,
    ) -> Result<GtpuSessionSelectorAdmission, GtpuSessionSelectorNamespaceError> {
        let claim = claim
            .clone()
            .with_key(&self.selector_digest_key)
            .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
        if operation_nonce == [0; 16] || terminal.nonce == [0; 16] {
            return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
        }
        let terminal_is_current =
            terminal.generation == generation && terminal.nonce == operation_nonce;
        match phase {
            SelectorAdmissionPhase::Installing => {
                if terminal.generation.get() <= generation.get() || previous_terminal.is_some() {
                    return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
                }
            }
            SelectorAdmissionPhase::Retiring => {
                if terminal.generation.get() <= generation.get()
                    || !previous_terminal.is_some_and(|prior| {
                        prior.generation.get() < generation.get() && prior.nonce != [0; 16]
                    })
                {
                    return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
                }
            }
            SelectorAdmissionPhase::Active | SelectorAdmissionPhase::Retired => {
                if !terminal_is_current || previous_terminal.is_some() {
                    return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
                }
            }
        }
        Ok(GtpuSessionSelectorAdmission {
            binding: self.binding_with_scope(storage_scope_commitment)?,
            selector_digest_key: Zeroizing::new(self.selector_digest_key),
            device_fingerprint: claim.device_fingerprint,
            group_fingerprint: claim.group_fingerprint,
            selector_set_fingerprint: claim.selector_set_fingerprint,
            desired_fingerprint: claim.desired_fingerprint,
            generation,
            operation_nonce,
            terminal_generation: terminal.generation,
            terminal_operation_nonce: terminal.nonce,
            previous_terminal,
            phase,
            retired_reissue,
        })
    }

    fn binding_with_scope(
        &self,
        storage_scope_commitment: [u8; 32],
    ) -> Result<GtpuSessionSelectorBackendBinding, GtpuSessionSelectorNamespaceError> {
        let stable_device = self
            .stable_device
            .and_then(GtpuSessionDeviceId::new)
            .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
        if self.ledger_id == [0; 16]
            || self.backend_epoch == [0; 16]
            || self.selector_digest_key == [0; 32]
            || self.pin_commitment == [0; 32]
            || self.storage_scope_commitment == [0; 32]
            || self.storage_scope_commitment != storage_scope_commitment
            || self.key_commitment
                != key_commitment(
                    &self.selector_digest_key,
                    &self.ledger_id,
                    &self.pin_commitment,
                    &stable_device.to_bytes(),
                    &self.storage_scope_commitment,
                )
        {
            return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
        }
        Ok(GtpuSessionSelectorBackendBinding {
            stable_device,
            pin_commitment: self.pin_commitment,
            ledger_id: self.ledger_id,
            backend_epoch: self.backend_epoch,
            storage_scope_commitment,
            selector_key_commitment: self.key_commitment,
        })
    }

    fn decommission_marker_commitment(
        &self,
        terminal: SelectorAuthorityCoordinate,
    ) -> Result<[u8; 32], GtpuSessionSelectorNamespaceError> {
        let stable_device = self
            .stable_device
            .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
        if terminal.nonce == [0; 16]
            || self.pin_commitment == [0; 32]
            || self.storage_scope_commitment == [0; 32]
            || self.ledger_id == [0; 16]
            || self.backend_epoch == [0; 16]
            || self.key_commitment == [0; 32]
            || self.selector_digest_key == [0; 32]
        {
            return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
        }
        let mut codec = Vec::with_capacity(1 + 16 + 32 + 32 + 16 + 16 + 32 + 8 + 16);
        codec.push(1);
        codec.extend_from_slice(&stable_device);
        codec.extend_from_slice(&self.pin_commitment);
        codec.extend_from_slice(&self.storage_scope_commitment);
        codec.extend_from_slice(&self.ledger_id);
        codec.extend_from_slice(&self.backend_epoch);
        codec.extend_from_slice(&self.key_commitment);
        codec.extend_from_slice(&terminal.generation.get().to_be_bytes());
        codec.extend_from_slice(&terminal.nonce);
        Ok(keyed_digest(
            &self.selector_digest_key,
            DECOMMISSION_FENCE_DOMAIN,
            &codec,
        ))
    }

    fn decommission_fence_is_exact(&self, fence: DecommissionFence) -> bool {
        fence.terminal.nonce != [0; 16]
            && fence.terminal.generation.get() <= self.generation
            && self
                .decommission_marker_commitment(fence.terminal)
                .is_ok_and(|expected| bool::from(expected.ct_eq(&fence.marker_commitment)))
    }

    fn precommit_decommission(
        &mut self,
    ) -> Result<DecommissionFence, GtpuSessionSelectorNamespaceError> {
        if self.lifecycle != NamespaceLifecycle::Bound
            || self.decommission_fence.is_some()
            || self.live_group_count() != 0
            || !self
                .groups
                .values()
                .all(|group| matches!(group, GroupState::Retired { .. }))
            || !self
                .selectors
                .values()
                .all(|selector| matches!(selector, SelectorState::Retired))
        {
            return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
        }
        let terminal = SelectorAuthorityCoordinate {
            generation: self.next_generation()?,
            nonce: random_nonzero_nonce()?,
        };
        let fence = DecommissionFence {
            terminal,
            marker_commitment: self.decommission_marker_commitment(terminal)?,
        };
        self.decommission_fence = Some(fence);
        Ok(fence)
    }

    fn bind_or_validate(
        &mut self,
        stable_device: GtpuSessionDeviceId,
        capacity: usize,
        supplied_selector_digest_key: Option<[u8; 32]>,
    ) -> Result<(), GtpuSessionSelectorNamespaceError> {
        if capacity == 0 || capacity > SELECTOR_NAMESPACE_MAX_READBACK_ATOMS {
            return Err(GtpuSessionSelectorNamespaceError::CapacityExhausted);
        }
        let capacity = u32::try_from(capacity)
            .map_err(|_| GtpuSessionSelectorNamespaceError::CapacityExhausted)?;
        match self.stable_device {
            None if self.lifecycle == NamespaceLifecycle::Unprovisioned
                && self.generation == 0
                && self.selectors.is_empty()
                && self.groups.is_empty()
                && self.capacity == 0
                && self.ledger_id == [0; 16]
                && self.backend_epoch == [0; 16]
                && self.selector_digest_key == [0; 32]
                && self.key_commitment == [0; 32] =>
            {
                let mut ledger_id = [0_u8; 16];
                let mut backend_epoch = [0_u8; 16];
                let mut selector_digest_key = [0_u8; 32];
                if let Some(supplied) = supplied_selector_digest_key {
                    selector_digest_key = supplied;
                    // Test-only in-memory authorities receive an explicit
                    // digest key. Derive stable synthetic binding material so
                    // independent test helpers model one shared durable
                    // backend rather than bypassing immutable binding checks.
                    let derived_ledger =
                        keyed_digest(&supplied, STORAGE_DOMAIN, b"test-selector-ledger/v1");
                    let derived_epoch =
                        keyed_digest(&supplied, STORAGE_DOMAIN, b"test-selector-backend-epoch/v1");
                    ledger_id.copy_from_slice(&derived_ledger[..16]);
                    backend_epoch.copy_from_slice(&derived_epoch[..16]);
                } else {
                    SysRng
                        .try_fill_bytes(&mut ledger_id)
                        .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
                    SysRng
                        .try_fill_bytes(&mut backend_epoch)
                        .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
                    SysRng
                        .try_fill_bytes(&mut selector_digest_key)
                        .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
                }
                if ledger_id == [0; 16] || backend_epoch == [0; 16] {
                    return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
                }
                self.stable_device = Some(stable_device.to_bytes());
                self.pin_commitment = test_pin_commitment(&selector_digest_key);
                self.storage_scope_commitment = test_storage_scope_commitment(&selector_digest_key);
                self.ledger_id = ledger_id;
                self.backend_epoch = backend_epoch;
                self.selector_digest_key = selector_digest_key;
                self.key_commitment = key_commitment(
                    &self.selector_digest_key,
                    &self.ledger_id,
                    &self.pin_commitment,
                    &stable_device.to_bytes(),
                    &self.storage_scope_commitment,
                );
                self.capacity = capacity;
                self.lifecycle = NamespaceLifecycle::Bound;
                Ok(())
            }
            Some(bound_device)
                if self.lifecycle == NamespaceLifecycle::Bound
                    && bound_device == stable_device.to_bytes()
                    && self.ledger_id != [0; 16]
                    && self.backend_epoch != [0; 16]
                    && self.selector_digest_key != [0; 32]
                    && self.pin_commitment != [0; 32]
                    && self.storage_scope_commitment != [0; 32]
                    && self.key_commitment
                        == key_commitment(
                            &self.selector_digest_key,
                            &self.ledger_id,
                            &self.pin_commitment,
                            &stable_device.to_bytes(),
                            &self.storage_scope_commitment,
                        )
                    && supplied_selector_digest_key
                        .is_none_or(|key| key == self.selector_digest_key)
                    && self.capacity == capacity =>
            {
                Ok(())
            }
            _ => Err(GtpuSessionSelectorNamespaceError::ConfigurationMismatch),
        }
    }

    /// Preflight a fresh permanent claim before minting its generation or
    /// nonce.  Each dimension is independent: a group row, its known atoms,
    /// and its future tombstone slots are all irrevocably reserved here.
    fn preflight_fresh_claim(&self, atoms: usize) -> Result<(), GtpuSessionSelectorNamespaceError> {
        if atoms == 0 || atoms > SELECTOR_NAMESPACE_MAX_READBACK_ATOMS {
            return Err(GtpuSessionSelectorNamespaceError::CapacityExhausted);
        }
        if self
            .groups
            .len()
            .checked_add(1)
            .is_none_or(|value| value > MAX_PERMANENT_GROUPS)
            || self
                .live_group_count()
                .checked_add(1)
                .is_none_or(|value| value > MAX_LIVE_GROUPS)
            || self
                .selectors
                .len()
                .checked_add(atoms)
                .is_none_or(|value| value > MAX_KNOWN_ATOMS)
            || self
                .published_atoms
                .len()
                .checked_add(atoms)
                .is_none_or(|value| value > MAX_KNOWN_ATOMS)
            || self
                .tombstones
                .len()
                .checked_add(atoms)
                .is_none_or(|value| value > MAX_KNOWN_ATOMS)
            || self
                .group_atom_references()
                .checked_add(atoms)
                .is_none_or(|value| value > MAX_GROUP_ATOM_REFERENCES)
        {
            return Err(GtpuSessionSelectorNamespaceError::CapacityExhausted);
        }
        // Selector row (73 bytes), permanent group row (157 + 32/atom), the
        // append-only historical atom index (32/atom), and the tombstones
        // reserved for its eventual retirement (32/atom).
        let additional = atoms
            .checked_mul(169)
            .and_then(|value| value.checked_add(157))
            .ok_or(GtpuSessionSelectorNamespaceError::CapacityExhausted)?;
        self.preflight_encoded_growth(additional)
    }

    /// A reissue adds one permanent successor row and one immutable edge in
    /// its source row; it replaces, rather than allocates, selector/tombstone
    /// slots.
    fn preflight_reissue(&self, atoms: usize) -> Result<(), GtpuSessionSelectorNamespaceError> {
        if atoms == 0
            || atoms > SELECTOR_NAMESPACE_MAX_READBACK_ATOMS
            || self
                .groups
                .len()
                .checked_add(1)
                .is_none_or(|value| value > MAX_PERMANENT_GROUPS)
            || self
                .live_group_count()
                .checked_add(1)
                .is_none_or(|value| value > MAX_LIVE_GROUPS)
            || self
                .group_atom_references()
                .checked_add(atoms)
                .is_none_or(|value| value > MAX_GROUP_ATOM_REFERENCES)
        {
            return Err(GtpuSessionSelectorNamespaceError::CapacityExhausted);
        }
        let additional = atoms
            .checked_mul(32)
            .and_then(|value| value.checked_add(198))
            .ok_or(GtpuSessionSelectorNamespaceError::CapacityExhausted)?;
        self.preflight_encoded_growth(additional)
    }

    fn preflight_encoded_growth(
        &self,
        additional: usize,
    ) -> Result<(), GtpuSessionSelectorNamespaceError> {
        self.encode()
            .len()
            .checked_add(additional)
            .is_some_and(|next| next <= MAX_RECORD_BYTES)
            .then_some(())
            .ok_or(GtpuSessionSelectorNamespaceError::CapacityExhausted)
    }

    fn live_group_count(&self) -> usize {
        self.groups
            .values()
            .filter(|group| {
                matches!(
                    group,
                    GroupState::Installing { .. }
                        | GroupState::Active { .. }
                        | GroupState::Retiring { .. }
                )
            })
            .count()
    }

    fn group_atom_references(&self) -> usize {
        self.groups
            .values()
            .map(|group| match group {
                GroupState::Installing { atoms, .. }
                | GroupState::Active { atoms, .. }
                | GroupState::Retiring { atoms, .. }
                | GroupState::Retired { atoms, .. } => atoms.len(),
                GroupState::Poisoned => 0,
            })
            .sum()
    }

    /// Retirement only materializes slots reserved by its original fresh
    /// claim. It must never make a new capacity allocation.
    fn preflight_retirement(
        &self,
        atoms: &BTreeSet<[u8; 32]>,
    ) -> Result<(), GtpuSessionSelectorNamespaceError> {
        (atoms.iter().all(|atom| self.selectors.contains_key(atom))
            && self.selectors.len() <= MAX_KNOWN_ATOMS
            && self.tombstones.len() <= MAX_KNOWN_ATOMS)
            .then_some(())
            .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)
    }

    fn next_generation(
        &mut self,
    ) -> Result<GtpuSessionSelectorAuthorityGeneration, GtpuSessionSelectorNamespaceError> {
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(GtpuSessionSelectorNamespaceError::GenerationExhausted)?;
        NonZeroU64::new(self.generation)
            .map(GtpuSessionSelectorAuthorityGeneration)
            .ok_or(GtpuSessionSelectorNamespaceError::GenerationExhausted)
    }

    fn encode(&self) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(b"OPCSN9");
        output.push(match self.lifecycle {
            NamespaceLifecycle::Unprovisioned => 0,
            NamespaceLifecycle::Provisioned => 1,
            NamespaceLifecycle::Initializing => 2,
            NamespaceLifecycle::Bound => 3,
            NamespaceLifecycle::Decommissioned => 4,
        });
        match self.stable_device {
            Some(device) => {
                output.push(1);
                output.extend_from_slice(&device);
            }
            None => output.push(0),
        }
        output.extend_from_slice(&self.pin_commitment);
        output.extend_from_slice(&self.storage_scope_commitment);
        output.extend_from_slice(&self.ledger_id);
        output.extend_from_slice(&self.backend_epoch);
        output.extend_from_slice(&self.selector_digest_key);
        output.extend_from_slice(&self.key_commitment);
        output.extend_from_slice(&self.capacity.to_be_bytes());
        output.extend_from_slice(&self.generation.to_be_bytes());
        match self.decommission_fence {
            None => output.push(0),
            Some(fence) => {
                output.push(1);
                output.extend_from_slice(&fence.terminal.generation.get().to_be_bytes());
                output.extend_from_slice(&fence.terminal.nonce);
                output.extend_from_slice(&fence.marker_commitment);
            }
        }
        output.extend_from_slice(&(self.selectors.len() as u32).to_be_bytes());
        for (digest, state) in &self.selectors {
            output.extend_from_slice(digest);
            match state {
                SelectorState::Installing { group, generation } => {
                    output.push(0);
                    output.extend_from_slice(group);
                    output.extend_from_slice(&generation.get().to_be_bytes());
                }
                SelectorState::Active { group, generation } => {
                    output.push(1);
                    output.extend_from_slice(group);
                    output.extend_from_slice(&generation.get().to_be_bytes());
                }
                SelectorState::Retiring { group, generation } => {
                    output.push(2);
                    output.extend_from_slice(group);
                    output.extend_from_slice(&generation.get().to_be_bytes());
                }
                SelectorState::Retired => output.push(3),
                SelectorState::Poisoned => output.push(4),
            }
        }
        output.extend_from_slice(&(self.groups.len() as u32).to_be_bytes());
        for (digest, state) in &self.groups {
            output.extend_from_slice(digest);
            match state {
                GroupState::Installing {
                    device,
                    selectors,
                    desired,
                    atoms,
                    generation,
                    operation_nonce,
                    terminal_generation,
                    terminal_operation_nonce,
                    backend_started,
                } => {
                    output.push(0);
                    output.extend_from_slice(device);
                    output.extend_from_slice(selectors);
                    output.extend_from_slice(desired);
                    output.extend_from_slice(&generation.get().to_be_bytes());
                    output.extend_from_slice(operation_nonce);
                    output.extend_from_slice(&terminal_generation.get().to_be_bytes());
                    output.extend_from_slice(terminal_operation_nonce);
                    output.push(u8::from(*backend_started));
                    output.extend_from_slice(&(atoms.len() as u32).to_be_bytes());
                    for atom in atoms {
                        output.extend_from_slice(atom);
                    }
                }
                GroupState::Active {
                    device,
                    selectors,
                    desired,
                    atoms,
                    generation,
                    operation_nonce,
                } => {
                    output.push(1);
                    output.extend_from_slice(device);
                    output.extend_from_slice(selectors);
                    output.extend_from_slice(desired);
                    output.extend_from_slice(&generation.get().to_be_bytes());
                    output.extend_from_slice(operation_nonce);
                    output.extend_from_slice(&(atoms.len() as u32).to_be_bytes());
                    for atom in atoms {
                        output.extend_from_slice(atom);
                    }
                }
                GroupState::Retiring {
                    device,
                    selectors,
                    desired,
                    atoms,
                    generation,
                    operation_nonce,
                    terminal_generation,
                    terminal_operation_nonce,
                    previous_terminal,
                    backend_started,
                } => {
                    output.push(2);
                    output.extend_from_slice(device);
                    output.extend_from_slice(selectors);
                    output.extend_from_slice(desired);
                    output.extend_from_slice(&generation.get().to_be_bytes());
                    output.extend_from_slice(operation_nonce);
                    output.extend_from_slice(&terminal_generation.get().to_be_bytes());
                    output.extend_from_slice(terminal_operation_nonce);
                    output.extend_from_slice(&previous_terminal.generation.get().to_be_bytes());
                    output.extend_from_slice(&previous_terminal.nonce);
                    output.push(u8::from(*backend_started));
                    output.extend_from_slice(&(atoms.len() as u32).to_be_bytes());
                    for atom in atoms {
                        output.extend_from_slice(atom);
                    }
                }
                GroupState::Retired {
                    device,
                    selectors,
                    desired,
                    atoms,
                    generation,
                    operation_nonce,
                    successor,
                } => {
                    output.push(3);
                    output.extend_from_slice(device);
                    output.extend_from_slice(selectors);
                    output.extend_from_slice(desired);
                    output.extend_from_slice(&generation.get().to_be_bytes());
                    output.extend_from_slice(operation_nonce);
                    output.extend_from_slice(&(atoms.len() as u32).to_be_bytes());
                    for atom in atoms {
                        output.extend_from_slice(atom);
                    }
                    match successor {
                        None => output.push(0),
                        Some(successor) => {
                            output.push(1);
                            output.extend_from_slice(&successor.group);
                            output.extend_from_slice(&successor.generation.get().to_be_bytes());
                        }
                    }
                }
                GroupState::Poisoned => output.push(4),
            }
        }
        output.extend_from_slice(&(self.published_atoms.len() as u32).to_be_bytes());
        for atom in &self.published_atoms {
            output.extend_from_slice(atom);
        }
        output.extend_from_slice(&(self.tombstones.len() as u32).to_be_bytes());
        for tombstone in &self.tombstones {
            output.extend_from_slice(tombstone);
        }
        output
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > MAX_RECORD_BYTES {
            return None;
        }
        let mut cursor = 0_usize;
        (take(bytes, &mut cursor, 6)? == b"OPCSN9").then_some(())?;
        let lifecycle = match *take(bytes, &mut cursor, 1)?.first()? {
            0 => NamespaceLifecycle::Unprovisioned,
            1 => NamespaceLifecycle::Provisioned,
            2 => NamespaceLifecycle::Initializing,
            3 => NamespaceLifecycle::Bound,
            4 => NamespaceLifecycle::Decommissioned,
            _ => return None,
        };
        let stable_device = match *take(bytes, &mut cursor, 1)?.first()? {
            0 => None,
            1 => Some(take_array(take(bytes, &mut cursor, 16)?)?),
            _ => return None,
        };
        let pin_commitment = take_array(take(bytes, &mut cursor, 32)?)?;
        let storage_scope_commitment = take_array(take(bytes, &mut cursor, 32)?)?;
        let ledger_id = take_array(take(bytes, &mut cursor, 16)?)?;
        let backend_epoch = take_array(take(bytes, &mut cursor, 16)?)?;
        let selector_digest_key = take_array(take(bytes, &mut cursor, 32)?)?;
        let key_commitment = take_array(take(bytes, &mut cursor, 32)?)?;
        let capacity = u32::from_be_bytes(take_array(take(bytes, &mut cursor, 4)?)?);
        let generation = u64::from_be_bytes(take_array(take(bytes, &mut cursor, 8)?)?);
        let decommission_fence = match *take(bytes, &mut cursor, 1)?.first()? {
            0 => None,
            1 => Some(DecommissionFence {
                terminal: SelectorAuthorityCoordinate {
                    generation: GtpuSessionSelectorAuthorityGeneration(NonZeroU64::new(
                        u64::from_be_bytes(take_array(take(bytes, &mut cursor, 8)?)?),
                    )?),
                    nonce: take_array(take(bytes, &mut cursor, 16)?)?,
                },
                marker_commitment: take_array(take(bytes, &mut cursor, 32)?)?,
            }),
            _ => return None,
        };
        let selector_count = u32::from_be_bytes(take_array(take(bytes, &mut cursor, 4)?)?) as usize;
        if selector_count > MAX_KNOWN_ATOMS {
            return None;
        }
        let mut selectors = BTreeMap::new();
        let mut previous_selector = None;
        for _ in 0..selector_count {
            let digest = take_array(take(bytes, &mut cursor, 32)?)?;
            if previous_selector.is_some_and(|previous| previous >= digest) {
                return None;
            }
            previous_selector = Some(digest);
            let tag = *take(bytes, &mut cursor, 1)?.first()?;
            let state = match tag {
                0..=2 => {
                    let group = take_array(take(bytes, &mut cursor, 32)?)?;
                    let generation = NonZeroU64::new(u64::from_be_bytes(take_array(take(
                        bytes,
                        &mut cursor,
                        8,
                    )?)?))?;
                    if tag == 0 {
                        SelectorState::Installing {
                            group,
                            generation: GtpuSessionSelectorAuthorityGeneration(generation),
                        }
                    } else if tag == 1 {
                        SelectorState::Active {
                            group,
                            generation: GtpuSessionSelectorAuthorityGeneration(generation),
                        }
                    } else {
                        SelectorState::Retiring {
                            group,
                            generation: GtpuSessionSelectorAuthorityGeneration(generation),
                        }
                    }
                }
                3 => SelectorState::Retired,
                4 => SelectorState::Poisoned,
                _ => return None,
            };
            selectors.insert(digest, state).is_none().then_some(())?;
        }
        let group_count = u32::from_be_bytes(take_array(take(bytes, &mut cursor, 4)?)?) as usize;
        if group_count > MAX_PERMANENT_GROUPS {
            return None;
        }
        let mut groups = BTreeMap::new();
        let mut previous_group = None;
        for _ in 0..group_count {
            let digest = take_array(take(bytes, &mut cursor, 32)?)?;
            if previous_group.is_some_and(|previous| previous >= digest) {
                return None;
            }
            previous_group = Some(digest);
            let tag = *take(bytes, &mut cursor, 1)?.first()?;
            let state = match tag {
                0..=3 => {
                    let device = take_array(take(bytes, &mut cursor, 32)?)?;
                    let selectors = take_array(take(bytes, &mut cursor, 32)?)?;
                    let desired = take_array(take(bytes, &mut cursor, 32)?)?;
                    let generation = NonZeroU64::new(u64::from_be_bytes(take_array(take(
                        bytes,
                        &mut cursor,
                        8,
                    )?)?))?;
                    let operation_nonce = take_array(take(bytes, &mut cursor, 16)?)?;
                    (operation_nonce != [0; 16]).then_some(())?;
                    let terminal = if tag == 0 || tag == 2 {
                        let terminal_generation =
                            GtpuSessionSelectorAuthorityGeneration(NonZeroU64::new(
                                u64::from_be_bytes(take_array(take(bytes, &mut cursor, 8)?)?),
                            )?);
                        let terminal_operation_nonce = take_array(take(bytes, &mut cursor, 16)?)?;
                        Some(
                            (terminal_operation_nonce != [0; 16]
                                && terminal_generation.get() > generation.get())
                            .then_some(SelectorAuthorityCoordinate {
                                generation: terminal_generation,
                                nonce: terminal_operation_nonce,
                            })?,
                        )
                    } else {
                        None
                    };
                    let previous_terminal = if tag == 2 {
                        let generation = GtpuSessionSelectorAuthorityGeneration(NonZeroU64::new(
                            u64::from_be_bytes(take_array(take(bytes, &mut cursor, 8)?)?),
                        )?);
                        let nonce = take_array(take(bytes, &mut cursor, 16)?)?;
                        Some(
                            (nonce != [0; 16] && generation.get() < terminal?.generation.get())
                                .then_some(SelectorAuthorityCoordinate { generation, nonce })?,
                        )
                    } else {
                        None
                    };
                    let backend_started = if tag == 0 || tag == 2 {
                        match *take(bytes, &mut cursor, 1)?.first()? {
                            0 => false,
                            1 => true,
                            _ => return None,
                        }
                    } else {
                        false
                    };
                    let count =
                        u32::from_be_bytes(take_array(take(bytes, &mut cursor, 4)?)?) as usize;
                    if count > SELECTOR_NAMESPACE_MAX_READBACK_ATOMS {
                        return None;
                    }
                    let mut atoms = BTreeSet::new();
                    let mut previous_atom = None;
                    for _ in 0..count {
                        let atom = take_array(take(bytes, &mut cursor, 32)?)?;
                        if previous_atom.is_some_and(|previous| previous >= atom) {
                            return None;
                        }
                        previous_atom = Some(atom);
                        atoms.insert(atom);
                    }
                    if tag == 0 {
                        GroupState::Installing {
                            device,
                            selectors,
                            desired,
                            atoms,
                            generation: GtpuSessionSelectorAuthorityGeneration(generation),
                            operation_nonce,
                            terminal_generation: terminal?.generation,
                            terminal_operation_nonce: terminal?.nonce,
                            backend_started,
                        }
                    } else if tag == 1 {
                        GroupState::Active {
                            device,
                            selectors,
                            desired,
                            atoms,
                            generation: GtpuSessionSelectorAuthorityGeneration(generation),
                            operation_nonce,
                        }
                    } else if tag == 2 {
                        GroupState::Retiring {
                            device,
                            selectors,
                            desired,
                            atoms,
                            generation: GtpuSessionSelectorAuthorityGeneration(generation),
                            operation_nonce,
                            terminal_generation: terminal?.generation,
                            terminal_operation_nonce: terminal?.nonce,
                            previous_terminal: previous_terminal?,
                            backend_started,
                        }
                    } else {
                        let successor = match *take(bytes, &mut cursor, 1)?.first()? {
                            0 => None,
                            1 => Some(RetiredSuccessor {
                                group: take_array(take(bytes, &mut cursor, 32)?)?,
                                generation: GtpuSessionSelectorAuthorityGeneration(
                                    NonZeroU64::new(u64::from_be_bytes(take_array(take(
                                        bytes,
                                        &mut cursor,
                                        8,
                                    )?)?))?,
                                ),
                            }),
                            _ => return None,
                        };
                        GroupState::Retired {
                            device,
                            selectors,
                            desired,
                            atoms,
                            generation: GtpuSessionSelectorAuthorityGeneration(generation),
                            operation_nonce,
                            successor,
                        }
                    }
                }
                4 => GroupState::Poisoned,
                _ => return None,
            };
            groups.insert(digest, state).is_none().then_some(())?;
        }
        let published_atom_count =
            u32::from_be_bytes(take_array(take(bytes, &mut cursor, 4)?)?) as usize;
        if published_atom_count > MAX_KNOWN_ATOMS {
            return None;
        }
        let mut published_atoms = BTreeSet::new();
        let mut previous_published_atom = None;
        for _ in 0..published_atom_count {
            let atom = take_array(take(bytes, &mut cursor, 32)?)?;
            if previous_published_atom.is_some_and(|previous| previous >= atom) {
                return None;
            }
            previous_published_atom = Some(atom);
            published_atoms.insert(atom);
        }
        let tombstone_count =
            u32::from_be_bytes(take_array(take(bytes, &mut cursor, 4)?)?) as usize;
        if tombstone_count > MAX_KNOWN_ATOMS {
            return None;
        }
        let mut tombstones = BTreeSet::new();
        let mut previous_tombstone = None;
        for _ in 0..tombstone_count {
            let tombstone = take_array(take(bytes, &mut cursor, 32)?)?;
            if previous_tombstone.is_some_and(|previous| previous >= tombstone) {
                return None;
            }
            previous_tombstone = Some(tombstone);
            tombstones.insert(tombstone);
        }
        let state = Self {
            lifecycle,
            stable_device,
            pin_commitment,
            storage_scope_commitment,
            ledger_id,
            backend_epoch,
            selector_digest_key,
            key_commitment,
            capacity,
            generation,
            decommission_fence,
            selectors,
            groups,
            published_atoms,
            tombstones,
        };
        (cursor == bytes.len() && state.is_complete()).then_some(state)
    }

    fn is_complete(&self) -> bool {
        let empty = self.stable_device.is_none()
            && self.pin_commitment == [0; 32]
            && self.storage_scope_commitment == [0; 32]
            && self.generation == 0
            && self.capacity == 0
            && self.ledger_id == [0; 16]
            && self.backend_epoch == [0; 16]
            && self.selector_digest_key == [0; 32]
            && self.key_commitment == [0; 32]
            && self.decommission_fence.is_none()
            && self.selectors.is_empty()
            && self.groups.is_empty()
            && self.published_atoms.is_empty()
            && self.tombstones.is_empty();
        let initialized = self.stable_device.is_some()
            && self.pin_commitment != [0; 32]
            && self.storage_scope_commitment != [0; 32]
            && self.capacity > 0
            && self.ledger_id != [0; 16]
            && self.backend_epoch != [0; 16]
            && self.selector_digest_key != [0; 32]
            && self.key_commitment
                == key_commitment(
                    &self.selector_digest_key,
                    &self.ledger_id,
                    &self.pin_commitment,
                    &self.stable_device.unwrap_or([0; 16]),
                    &self.storage_scope_commitment,
                );
        let provisioned = self.stable_device.is_some()
            && self.pin_commitment != [0; 32]
            && self.storage_scope_commitment != [0; 32]
            && self.generation == 0
            && self.capacity == 0
            && self.ledger_id == [0; 16]
            && self.backend_epoch == [0; 16]
            && self.selector_digest_key == [0; 32]
            && self.key_commitment == [0; 32]
            && self.decommission_fence.is_none()
            && self.selectors.is_empty()
            && self.groups.is_empty()
            && self.published_atoms.is_empty()
            && self.tombstones.is_empty();
        let lifecycle_complete = match self.lifecycle {
            NamespaceLifecycle::Unprovisioned => empty,
            NamespaceLifecycle::Provisioned => provisioned,
            NamespaceLifecycle::Initializing => initialized && self.decommission_fence.is_none(),
            NamespaceLifecycle::Bound => initialized,
            NamespaceLifecycle::Decommissioned => {
                initialized
                    && self.live_group_count() == 0
                    && self.decommission_fence.is_some()
                    && self
                        .groups
                        .values()
                        .all(|group| matches!(group, GroupState::Retired { .. }))
                    && self
                        .selectors
                        .values()
                        .all(|selector| matches!(selector, SelectorState::Retired))
            }
        };
        let stable_device_fingerprint = self.stable_device.map(|device| {
            let mut codec = Vec::with_capacity(17);
            codec.push(1);
            codec.extend_from_slice(&device);
            keyed_digest(&self.selector_digest_key, GROUP_DOMAIN, &codec)
        });
        lifecycle_complete
            && self
                .decommission_fence
                .is_none_or(|fence| self.decommission_fence_is_exact(fence))
            && self.groups.values().all(|group| match group {
                GroupState::Installing {
                    device,
                    atoms,
                    generation,
                    operation_nonce,
                    terminal_generation,
                    terminal_operation_nonce,
                    ..
                } => {
                    stable_device_fingerprint == Some(*device)
                        && !atoms.is_empty()
                        && *operation_nonce != [0; 16]
                        && *terminal_operation_nonce != [0; 16]
                        && generation.get() < terminal_generation.get()
                        && terminal_generation.get() <= self.generation
                }
                GroupState::Retiring {
                    device,
                    atoms,
                    generation,
                    operation_nonce,
                    terminal_generation,
                    terminal_operation_nonce,
                    previous_terminal,
                    ..
                } => {
                    stable_device_fingerprint == Some(*device)
                        && !atoms.is_empty()
                        && *operation_nonce != [0; 16]
                        && *terminal_operation_nonce != [0; 16]
                        && previous_terminal.nonce != [0; 16]
                        && previous_terminal.generation.get() < generation.get()
                        && generation.get() < terminal_generation.get()
                        && terminal_generation.get() <= self.generation
                }
                GroupState::Active { device, atoms, generation, operation_nonce, .. }
                | GroupState::Retired { device, atoms, generation, operation_nonce, .. } => {
                    stable_device_fingerprint == Some(*device)
                        && !atoms.is_empty()
                        && *operation_nonce != [0; 16]
                        && generation.get() <= self.generation
                }
                GroupState::Poisoned => true,
            })
            && self.selectors.values().all(|selector| match selector {
                SelectorState::Installing { generation, .. }
                | SelectorState::Active { generation, .. }
                | SelectorState::Retiring { generation, .. } => generation.get() <= self.generation,
                SelectorState::Retired | SelectorState::Poisoned => true,
            })
            && self.capacity <= SELECTOR_NAMESPACE_MAX_READBACK_ATOMS as u32
            && self.groups.len() <= MAX_PERMANENT_GROUPS
            && self.live_group_count() <= MAX_LIVE_GROUPS
            && self.selectors.len() <= MAX_KNOWN_ATOMS
            && self.published_atoms.len() <= MAX_KNOWN_ATOMS
            && self.tombstones.len() <= MAX_KNOWN_ATOMS
            && self.group_atom_references() <= MAX_GROUP_ATOM_REFERENCES
            // The Installing CAS is also the permanent atom reservation.
            // Any missing atom would let concurrent fresh claims race before
            // either backend effect settles; any mixed bundle is a corrupted
            // cross-lineage transfer and is never recovered by guessing.
            && self.groups.values().all(|group| match group {
                GroupState::Installing { atoms, .. }
                | GroupState::Active { atoms, .. }
                | GroupState::Retiring { atoms, .. }
                | GroupState::Retired { atoms, .. } => {
                    atoms.iter().all(|atom| self.published_atoms.contains(atom))
                }
                GroupState::Poisoned => true,
            })
            && self.groups.iter().all(|(group_digest, group)| match group {
                GroupState::Active {
                    atoms, generation, ..
                } => selector_atoms_for(&self.selectors, *group_digest, *generation, 1) == *atoms,
                GroupState::Installing {
                    atoms, generation, ..
                } => selector_atoms_for(&self.selectors, *group_digest, *generation, 0) == *atoms,
                GroupState::Retiring {
                    atoms, generation, ..
                } => selector_atoms_for(&self.selectors, *group_digest, *generation, 2) == *atoms,
                GroupState::Retired {
                    atoms,
                    successor,
                    ..
                } => {
                    atoms.iter().all(|atom| {
                        self.published_atoms.contains(atom) && self.tombstones.contains(atom)
                    })
                        && successor.is_none_or(|successor| {
                            successor.group != *group_digest
                                && successor.generation.get() <= self.generation
                                && matches!(
                                    self.groups.get(&successor.group),
                                    Some(
                                        GroupState::Installing { generation, .. }
                                        | GroupState::Active { generation, .. }
                                        | GroupState::Retiring { generation, .. }
                                        | GroupState::Retired { generation, .. }
                                    ) if *generation == successor.generation
                                )
                        })
                }
                GroupState::Poisoned => true,
            })
            && self
                .selectors
                .iter()
                .all(|(digest, selector)| match selector {
                    SelectorState::Installing { group, generation } => matches!(
                        self.groups.get(group),
                        Some(GroupState::Installing {
                            generation: group_generation,
                            ..
                        }) if group_generation == generation
                    ),
                    SelectorState::Active { group, generation } => matches!(
                        self.groups.get(group),
                        Some(GroupState::Active {
                            generation: group_generation,
                            ..
                        }) if group_generation == generation
                    ),
                    SelectorState::Retiring { group, generation } => matches!(
                        self.groups.get(group),
                        Some(GroupState::Retiring {
                            generation: group_generation,
                            ..
                        }) if group_generation == generation
                    ),
                    SelectorState::Retired => self.tombstones.contains(digest)
                        && self.groups.values().any(|group| matches!(group, GroupState::Retired { atoms, .. } if atoms.contains(digest))),
                    SelectorState::Poisoned => true,
                })
            && self
                .published_atoms
                .iter()
                .all(|atom| self.selectors.contains_key(atom))
            && self.tombstones.iter().all(|tombstone| self.groups.values().any(|group| matches!(group, GroupState::Retired { atoms, .. } if atoms.contains(tombstone))))
    }
}

fn random_nonzero_nonce() -> Result<[u8; 16], GtpuSessionSelectorNamespaceError> {
    let mut nonce = [0_u8; 16];
    SysRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
    (nonce != [0; 16])
        .then_some(nonce)
        .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)
}

#[cfg(test)]
fn test_nonzero_nonce(
    key: &[u8; 32],
    group: [u8; 32],
    generation: GtpuSessionSelectorAuthorityGeneration,
) -> Result<[u8; 16], GtpuSessionSelectorNamespaceError> {
    let mut codec = Vec::with_capacity(32 + 8);
    codec.extend_from_slice(&group);
    codec.extend_from_slice(&generation.get().to_be_bytes());
    let digest = keyed_digest(key, STORAGE_DOMAIN, &codec);
    let mut nonce = [0_u8; 16];
    nonce.copy_from_slice(&digest[..16]);
    (nonce != [0; 16])
        .then_some(nonce)
        .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)
}

fn selector_atoms_for(
    selectors: &BTreeMap<[u8; 32], SelectorState>,
    group: [u8; 32],
    generation: GtpuSessionSelectorAuthorityGeneration,
    phase: u8,
) -> BTreeSet<[u8; 32]> {
    selectors
        .iter()
        .filter_map(|(digest, state)| match (phase, state) {
            (
                0,
                SelectorState::Installing {
                    group: owner,
                    generation: owner_generation,
                },
            )
            | (
                1,
                SelectorState::Active {
                    group: owner,
                    generation: owner_generation,
                },
            )
            | (
                2,
                SelectorState::Retiring {
                    group: owner,
                    generation: owner_generation,
                },
            ) if *owner == group && *owner_generation == generation => Some(*digest),
            _ => None,
        })
        .collect()
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, length: usize) -> Option<&'a [u8]> {
    let end = cursor.checked_add(length)?;
    let value = bytes.get(*cursor..end)?;
    *cursor = end;
    Some(value)
}

fn take_array<const N: usize>(bytes: &[u8]) -> Option<[u8; N]> {
    bytes.try_into().ok()
}

#[derive(Clone)]
enum SelectorState {
    Installing {
        group: [u8; 32],
        generation: GtpuSessionSelectorAuthorityGeneration,
    },
    Active {
        group: [u8; 32],
        generation: GtpuSessionSelectorAuthorityGeneration,
    },
    Retiring {
        group: [u8; 32],
        generation: GtpuSessionSelectorAuthorityGeneration,
    },
    Retired,
    Poisoned,
}

#[derive(Clone)]
enum GroupState {
    Installing {
        device: [u8; 32],
        selectors: [u8; 32],
        desired: [u8; 32],
        atoms: BTreeSet<[u8; 32]>,
        generation: GtpuSessionSelectorAuthorityGeneration,
        operation_nonce: [u8; 16],
        /// Precommitted terminal Active stamp coordinate.  It is minted in
        /// the same CAS as the pending install coordinate, before the
        /// backend can observe either one.
        terminal_generation: GtpuSessionSelectorAuthorityGeneration,
        terminal_operation_nonce: [u8; 16],
        /// Set by a fenced CAS immediately before the first backend effect.
        /// Recovery never infers that an unstarted intent reached the
        /// dataplane.
        backend_started: bool,
    },
    Active {
        device: [u8; 32],
        selectors: [u8; 32],
        desired: [u8; 32],
        atoms: BTreeSet<[u8; 32]>,
        generation: GtpuSessionSelectorAuthorityGeneration,
        operation_nonce: [u8; 16],
    },
    Retiring {
        device: [u8; 32],
        selectors: [u8; 32],
        desired: [u8; 32],
        atoms: BTreeSet<[u8; 32]>,
        generation: GtpuSessionSelectorAuthorityGeneration,
        operation_nonce: [u8; 16],
        /// Precommitted terminal Retired stamp coordinate.
        terminal_generation: GtpuSessionSelectorAuthorityGeneration,
        terminal_operation_nonce: [u8; 16],
        /// The exact Active terminal that this pending removal replaces.
        previous_terminal: SelectorAuthorityCoordinate,
        /// Set by a fenced CAS immediately before the first backend removal.
        backend_started: bool,
    },
    Retired {
        device: [u8; 32],
        selectors: [u8; 32],
        desired: [u8; 32],
        atoms: BTreeSet<[u8; 32]>,
        generation: GtpuSessionSelectorAuthorityGeneration,
        operation_nonce: [u8; 16],
        /// Written exactly once in the source `Retired` CAS.  This makes a
        /// permanently retired predecessor a single-use lineage edge even
        /// after its successor has itself retired.
        successor: Option<RetiredSuccessor>,
    },
    Poisoned,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct RetiredSuccessor {
    group: [u8; 32],
    generation: GtpuSessionSelectorAuthorityGeneration,
}

#[derive(Clone)]
struct CanonicalClaim {
    stable_device: [u8; 16],
    group_id: [u8; 16],
    atoms: BTreeSet<Vec<u8>>,
    desired: Vec<u8>,
    device_fingerprint: [u8; 32],
    group_fingerprint: [u8; 32],
    selector_set_fingerprint: [u8; 32],
    desired_fingerprint: [u8; 32],
}

#[derive(Clone, Copy)]
struct CanonicalFingerprints {
    device: [u8; 32],
    group: [u8; 32],
    selector_set: [u8; 32],
    desired: [u8; 32],
}

impl CanonicalClaim {
    fn from_group(group: &GtpuSessionGroup) -> Self {
        let mut atom_bytes: BTreeSet<Vec<u8>> = BTreeSet::new();
        for entry in group.entries() {
            let outer = match entry.outer_family() {
                GtpAddressFamily::Ipv4 => GtpuSessionIpFamily::Ipv4,
                GtpAddressFamily::Ipv6 => GtpuSessionIpFamily::Ipv6,
            };
            let inner = match entry.inner_family() {
                GtpAddressFamily::Ipv4 => GtpuSessionIpFamily::Ipv4,
                GtpAddressFamily::Ipv6 => GtpuSessionIpFamily::Ipv6,
            };
            let downlink = GtpuSessionDownlinkKey::new(
                outer,
                inner,
                entry.context().local_teid.get().to_be_bytes(),
            )
            .map(GtpuSessionDownlinkKey::encode);
            // `GtpuSessionEntry` already validates the nonzero TEID invariant.
            if let Some(downlink) = downlink {
                // Fresh admission is defined over elementary authority axes,
                // not the combined uplink map key. Recombining an old PAA
                // with a new mark (or the reverse) must still observe the
                // permanently reserved old atom.
                atom_bytes.insert(atom_codec(b'T', &downlink));
                match entry.inner_paa() {
                    GtpuSessionPaa::Ipv4(address) => {
                        let mut paa = Vec::with_capacity(6);
                        paa.extend_from_slice(&[1, GtpuSessionIpFamily::Ipv4 as u8]);
                        paa.extend_from_slice(&address);
                        atom_bytes.insert(atom_codec(b'P', &paa));
                    }
                    GtpuSessionPaa::Ipv6Prefix(prefix) => {
                        let mut paa = Vec::with_capacity(10);
                        paa.extend_from_slice(&[1, GtpuSessionIpFamily::Ipv6 as u8]);
                        paa.extend_from_slice(&prefix);
                        atom_bytes.insert(atom_codec(b'P', &paa));
                    }
                }
                if let Some(mark) = entry.context().bearer_mark {
                    let mut full_mask_mark = Vec::with_capacity(9);
                    full_mask_mark.push(1);
                    full_mask_mark.extend_from_slice(&u32::MAX.to_be_bytes());
                    full_mask_mark.extend_from_slice(&mark.get().to_be_bytes());
                    atom_bytes.insert(atom_codec(b'M', &full_mask_mark));
                }
            }
        }
        Self {
            stable_device: group.device_id().to_bytes(),
            group_id: group.id().to_bytes(),
            atoms: atom_bytes,
            desired: canonical_desired_bytes(group),
            device_fingerprint: [0; 32],
            group_fingerprint: [0; 32],
            selector_set_fingerprint: [0; 32],
            desired_fingerprint: [0; 32],
        }
    }

    fn with_key(mut self, key: &[u8; 32]) -> Option<Self> {
        let fingerprints = self.fingerprints(key)?;
        self.device_fingerprint = fingerprints.device;
        self.group_fingerprint = fingerprints.group;
        self.selector_set_fingerprint = fingerprints.selector_set;
        self.desired_fingerprint = fingerprints.desired;
        Some(self)
    }

    fn fingerprints(&self, key: &[u8; 32]) -> Option<CanonicalFingerprints> {
        let mut device_codec = Vec::with_capacity(17);
        device_codec.push(1);
        device_codec.extend_from_slice(&self.stable_device);
        let mut group_codec = Vec::with_capacity(33);
        group_codec.push(1);
        group_codec.extend_from_slice(&self.stable_device);
        group_codec.extend_from_slice(&self.group_id);
        let mut set_codec = Vec::with_capacity(3 + self.atoms.len() * 35);
        set_codec.push(1);
        let count = u16::try_from(self.atoms.len()).ok()?;
        set_codec.extend_from_slice(&count.to_be_bytes());
        for atom in &self.atoms {
            set_codec.extend_from_slice(atom);
        }
        Some(CanonicalFingerprints {
            device: keyed_digest(key, GROUP_DOMAIN, &device_codec),
            group: keyed_digest(key, GROUP_DOMAIN, &group_codec),
            selector_set: keyed_digest(key, SET_DOMAIN, &set_codec),
            desired: keyed_digest(key, DESIRED_DOMAIN, &self.desired),
        })
    }

    fn selector_atoms(&self, key: &[u8; 32]) -> Option<BTreeSet<[u8; 32]>> {
        let atoms = self
            .atoms
            .iter()
            .map(|atom| keyed_digest(key, ATOM_DOMAIN, atom))
            .collect::<BTreeSet<_>>();
        (atoms.len() == self.atoms.len()).then_some(atoms)
    }
}

fn atom_codec(tag: u8, bytes: &[u8]) -> Vec<u8> {
    let length = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
    let mut output = Vec::with_capacity(3 + bytes.len());
    output.push(tag);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    output
}

/// Encode every forwarding-semantic input in a stable, unambiguous projection.
/// Selector atoms alone intentionally omit output TEIDs, peer/local endpoints,
/// link attachment, version, and policy.  Those fields must remain bound to
/// the authority permit so a permit minted for one graph cannot publish a
/// semantically different graph with the same selector keys.
fn canonical_desired_bytes(group: &GtpuSessionGroup) -> Vec<u8> {
    let mut output = Vec::new();
    output.push(1);
    output.extend_from_slice(&group.device_id().to_bytes());
    output.extend_from_slice(&group.id().to_bytes());
    let count = u8::try_from(group.entries().len()).unwrap_or(u8::MAX);
    output.push(count);
    for entry in group.entries() {
        let context = entry.context();
        append_ip(&mut output, context.ms_address);
        append_ip(&mut output, context.peer_address);
        append_ip(&mut output, entry.local_outer_address());
        output.extend_from_slice(&context.local_teid.get().to_be_bytes());
        output.extend_from_slice(&context.peer_teid.get().to_be_bytes());
        output.extend_from_slice(&context.link_ifindex.to_be_bytes());
        output.extend_from_slice(&match context.gtp_version {
            crate::GtpVersion::V1 => [1],
        });
        match context.bearer_mark {
            Some(mark) => {
                output.push(1);
                output.extend_from_slice(&mark.get().to_be_bytes());
            }
            None => output.push(0),
        }
        append_downlink_source_port_policy(&mut output, context.downlink_source_port_policy);
        match context.uplink_source_port_policy {
            crate::GtpuUplinkSourcePortPolicy::LegacyServicePort => output.push(0),
            crate::GtpuUplinkSourcePortPolicy::Selected(port) => {
                output.push(1);
                output.extend_from_slice(&port.to_be_bytes());
            }
        }
        match context.egress_dscp {
            Some(dscp) => {
                output.push(1);
                output.push(dscp.get());
            }
            None => output.push(0),
        }
    }
    output
}

fn append_ip(output: &mut Vec<u8>, address: std::net::IpAddr) {
    match address {
        std::net::IpAddr::V4(address) => {
            output.push(4);
            output.extend_from_slice(&address.octets());
        }
        std::net::IpAddr::V6(address) => {
            output.push(6);
            output.extend_from_slice(&address.octets());
        }
    }
}

fn append_downlink_source_port_policy(output: &mut Vec<u8>, policy: crate::GtpuSourcePortPolicy) {
    match policy {
        crate::GtpuSourcePortPolicy::Any => output.push(0),
        crate::GtpuSourcePortPolicy::Exact(port) => {
            output.push(1);
            output.extend_from_slice(&port.to_be_bytes());
        }
        crate::GtpuSourcePortPolicy::InclusiveRange(range) => {
            output.push(2);
            output.extend_from_slice(&range.first().to_be_bytes());
            output.extend_from_slice(&range.last().to_be_bytes());
        }
    }
}

fn key_commitment(
    key: &[u8; 32],
    ledger_id: &[u8; 16],
    pin_commitment: &[u8; 32],
    stable_device: &[u8; 16],
    storage_scope_commitment: &[u8; 32],
) -> [u8; 32] {
    let mut codec = Vec::with_capacity(1 + 16 + 32 + 16 + 32);
    codec.push(1);
    codec.extend_from_slice(ledger_id);
    codec.extend_from_slice(pin_commitment);
    codec.extend_from_slice(stable_device);
    codec.extend_from_slice(storage_scope_commitment);
    keyed_digest(key, SELECTOR_SECRET_COMMITMENT_DOMAIN, &codec)
}

/// Test coordinators use the same opaque, nonzero storage binding for every
/// reconstruction over their deterministic selector secret.  A zero binding
/// is deliberately invalid in the eBPF stamp codec because it would make a
/// test-only authority indistinguishable from an omitted production scope.
fn test_storage_scope_commitment(key: &[u8; 32]) -> [u8; 32] {
    keyed_digest(key, STORAGE_DOMAIN, b"test-storage-scope/v1")
}

/// Test-only raw constructors never receive a production bootstrap.  Their
/// in-process namespace uses a deterministic, nonzero stand-in that cannot
/// cross the protected constructor boundary.
pub(crate) fn test_pin_commitment(key: &[u8; 32]) -> [u8; 32] {
    keyed_digest(key, STORAGE_DOMAIN, b"test-pin-namespace/v1")
}

fn keyed_digest(key: &[u8; 32], domain: &[u8], codec: &[u8]) -> [u8; 32] {
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(key) else {
        return [0; 32];
    };
    mac.update(domain);
    mac.update(codec);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::time::Duration;

    use bytes::Bytes;
    use opc_session_store::{
        OwnerId, SessionKey, SessionKeyType, SessionStore, SqliteSessionBackend, StableId,
    };
    use opc_types::{NetworkFunctionKind, TenantId};

    use crate::{
        GtpPdpContext, GtpVersion, GtpuSessionDeviceId, GtpuSessionEntry, GtpuSessionGroupId,
        GtpuSessionSelectorCoordinatorError, GtpuSourcePortPolicy, GtpuUplinkSourcePortPolicy,
        Teid,
    };

    use super::*;

    fn group(id: u8, device: u8, teid: u32, mark: Option<u32>) -> GtpuSessionGroup {
        group_with_paa(
            id,
            device,
            teid,
            IpAddr::V4(Ipv4Addr::new(10, 23, 0, id)),
            mark,
        )
    }

    fn group_with_paa(
        id: u8,
        device: u8,
        teid: u32,
        paa: IpAddr,
        mark: Option<u32>,
    ) -> GtpuSessionGroup {
        let context = GtpPdpContext {
            local_teid: Teid::new(teid).unwrap(),
            peer_teid: Teid::new(teid + 1).unwrap(),
            ms_address: paa,
            peer_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            link_ifindex: 7,
            downlink_source_port_policy: GtpuSourcePortPolicy::Any,
            gtp_version: GtpVersion::V1,
            bearer_mark: mark.and_then(crate::GtpBearerMark::new),
            egress_dscp: None,
            uplink_source_port_policy: GtpuUplinkSourcePortPolicy::LegacyServicePort,
        };
        GtpuSessionGroup::new(
            GtpuSessionGroupId::new([id; 16]).unwrap(),
            GtpuSessionDeviceId::new([device; 16]).unwrap(),
            vec![GtpuSessionEntry::new(context, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))).unwrap()],
        )
        .unwrap()
    }

    async fn production_authority(
        device_id: GtpuSessionDeviceId,
    ) -> GtpuSessionSelectorNamespaceAuthority<SqliteSessionBackend> {
        let namespace_key = SessionKey {
            tenant: TenantId::from_static("selector-namespace-test"),
            nf_kind: NetworkFunctionKind::from_static("epdg"),
            key_type: SessionKeyType::other("gtpu-selector-namespace")
                .expect("valid test namespace key type"),
            stable_id: StableId::new(Bytes::copy_from_slice(&device_id.to_bytes()))
                .expect("valid test namespace stable ID"),
        };
        GtpuSessionSelectorNamespaceAuthority::open(
            SessionStore::new(
                SqliteSessionBackend::in_memory().expect("in-memory durable namespace backend"),
            ),
            namespace_key,
            OwnerId::new("selector-namespace-test-owner").expect("valid test owner"),
            Duration::from_secs(30),
            32,
        )
        .await
        .expect("durable test authority")
    }

    /// Test-only backend that consumes the public opaque requests at the
    /// authority boundary. It models a terminal dataplane effect without
    /// giving this conformance test a raw admission bypass.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum TerminalFenceOperation {
        InspectAbsent,
        InspectExpectedAbsent,
        InspectExpectedExact,
        Create,
        Readback,
    }

    /// Backend observations used to fault the durable coordinator exactly at
    /// its authority boundary.  `NoEffect` is the only state for which the
    /// dedicated negative-proof port may authorize a false-to-true handoff.
    #[derive(Debug, Default)]
    enum FaultingSelectorDataplaneState {
        #[default]
        NoEffect,
        Pending,
        Active(GtpuSessionGroup),
        Retired,
        Partial,
    }

    #[derive(Debug, Default)]
    struct FaultingSelectorBackend {
        effect_fault: std::sync::atomic::AtomicBool,
        effect_ack_lost: std::sync::atomic::AtomicBool,
        removal_ack_lost: std::sync::atomic::AtomicBool,
        effect_calls: std::sync::atomic::AtomicUsize,
        removal_calls: std::sync::atomic::AtomicUsize,
        dataplane: std::sync::Mutex<FaultingSelectorDataplaneState>,
        no_effect_barrier: std::sync::Mutex<Option<Arc<tokio::sync::Barrier>>>,
        terminal_fence: std::sync::Mutex<Option<[u8; 57]>>,
        terminal_operations: std::sync::Mutex<Vec<TerminalFenceOperation>>,
    }

    impl FaultingSelectorBackend {
        fn set_effect_fault(&self, value: bool) {
            self.effect_fault
                .store(value, std::sync::atomic::Ordering::Release);
        }

        fn set_effect_ack_lost(&self, value: bool) {
            self.effect_ack_lost
                .store(value, std::sync::atomic::Ordering::Release);
        }

        fn set_removal_ack_lost(&self, value: bool) {
            self.removal_ack_lost
                .store(value, std::sync::atomic::Ordering::Release);
        }

        fn set_dataplane(&self, state: FaultingSelectorDataplaneState) {
            *self.dataplane.lock().expect("faulting dataplane lock") = state;
        }

        fn synchronize_no_effect_inspections(&self, participants: usize) {
            *self
                .no_effect_barrier
                .lock()
                .expect("faulting no-effect barrier lock") =
                Some(Arc::new(tokio::sync::Barrier::new(participants)));
        }

        async fn wait_for_no_effect_inspection_peer(&self) {
            let barrier = self
                .no_effect_barrier
                .lock()
                .expect("faulting no-effect barrier lock")
                .clone();
            if let Some(barrier) = barrier {
                barrier.wait().await;
            }
        }

        fn effect_calls(&self) -> usize {
            self.effect_calls.load(std::sync::atomic::Ordering::Acquire)
        }

        fn removal_calls(&self) -> usize {
            self.removal_calls
                .load(std::sync::atomic::Ordering::Acquire)
        }

        fn dataplane_readback(
            &self,
            expected: &GtpuSessionGroup,
        ) -> Result<crate::GtpuSessionGroupReadback, crate::GtpuError> {
            match &*self
                .dataplane
                .lock()
                .map_err(|_| crate::GtpuError::StateIndeterminate {
                    operation: "faulting_selector_dataplane_lock",
                })? {
                FaultingSelectorDataplaneState::Active(active) if active == expected => {
                    Ok(crate::GtpuSessionGroupReadback::Active(active.clone()))
                }
                FaultingSelectorDataplaneState::Retired => {
                    Ok(crate::GtpuSessionGroupReadback::Absent)
                }
                _ => Ok(crate::GtpuSessionGroupReadback::Indeterminate(
                    crate::GtpuSessionGroupIndeterminateReason::IncompleteState,
                )),
            }
        }
    }

    #[async_trait::async_trait]
    impl GtpuDataplaneBackend for FaultingSelectorBackend {
        async fn create_device(
            &self,
            _request: crate::CreateGtpDeviceRequest,
        ) -> Result<crate::GtpDevice, crate::GtpuError> {
            Err(crate::GtpuError::UnsupportedFeature {
                feature: "faulting_selector_test_device",
            })
        }

        async fn resolve_device(&self, _name: &str) -> Result<crate::GtpDevice, crate::GtpuError> {
            Err(crate::GtpuError::UnsupportedFeature {
                feature: "faulting_selector_test_device",
            })
        }

        async fn remove_device(&self, _device: &crate::GtpDevice) -> Result<(), crate::GtpuError> {
            Err(crate::GtpuError::UnsupportedFeature {
                feature: "faulting_selector_test_device",
            })
        }

        async fn install_pdp_context(
            &self,
            _request: crate::GtpPdpContext,
        ) -> Result<(), crate::GtpuError> {
            Err(crate::GtpuError::UnsupportedFeature {
                feature: "faulting_selector_test_pdp",
            })
        }

        async fn remove_pdp_context(
            &self,
            _request: crate::RemovePdpContextRequest,
        ) -> Result<(), crate::GtpuError> {
            Err(crate::GtpuError::UnsupportedFeature {
                feature: "faulting_selector_test_pdp",
            })
        }

        async fn probe(&self) -> Result<crate::GtpuProbe, crate::GtpuError> {
            Err(crate::GtpuError::UnsupportedFeature {
                feature: "faulting_selector_test_probe",
            })
        }

        async fn acquire_selector_namespace_lease(
            &self,
            lease: GtpuSessionSelectorBindingLease,
        ) -> Result<GtpuSessionSelectorBackendReceipt, crate::GtpuError> {
            Ok(lease.confirm())
        }

        async fn provision_selector_namespace_authorized(
            &self,
            request: GtpuSessionSelectorProvisionRequest,
        ) -> Result<GtpuSessionSelectorBackendReceipt, crate::GtpuError> {
            Ok(request.confirm())
        }

        async fn inspect_installing_selector_no_effect(
            &self,
            _expected: &GtpuSessionGroup,
            _admission: &GtpuSessionSelectorAdmission,
        ) -> Result<crate::GtpuSessionSelectorInstallRecovery, crate::GtpuError> {
            self.wait_for_no_effect_inspection_peer().await;
            matches!(
                &*self
                    .dataplane
                    .lock()
                    .map_err(|_| crate::GtpuError::StateIndeterminate {
                        operation: "faulting_selector_dataplane_lock",
                    })?,
                FaultingSelectorDataplaneState::NoEffect
            )
            .then_some(crate::GtpuSessionSelectorInstallRecovery::NoEffect)
            .ok_or(crate::GtpuError::StateIndeterminate {
                operation: "faulting_selector_install_negative_proof",
            })
        }

        async fn inspect_installing_selector_resume(
            &self,
            _expected: &GtpuSessionGroup,
            _admission: &GtpuSessionSelectorAdmission,
        ) -> Result<crate::GtpuSessionSelectorInstallResume, crate::GtpuError> {
            match &*self
                .dataplane
                .lock()
                .map_err(|_| crate::GtpuError::StateIndeterminate {
                    operation: "faulting_selector_dataplane_lock",
                })? {
                FaultingSelectorDataplaneState::NoEffect => {
                    Ok(crate::GtpuSessionSelectorInstallResume::NoEffect)
                }
                FaultingSelectorDataplaneState::Pending => {
                    Ok(crate::GtpuSessionSelectorInstallResume::ExactPendingInstall)
                }
                _ => Err(crate::GtpuError::StateIndeterminate {
                    operation: "faulting_selector_install_resume_proof",
                }),
            }
        }

        async fn inspect_retiring_selector_no_effect(
            &self,
            expected: &GtpuSessionGroup,
            _admission: &GtpuSessionSelectorAdmission,
        ) -> Result<crate::GtpuSessionSelectorRetiringRecovery, crate::GtpuError> {
            self.wait_for_no_effect_inspection_peer().await;
            matches!(
                &*self
                    .dataplane
                    .lock()
                    .map_err(|_| crate::GtpuError::StateIndeterminate {
                        operation: "faulting_selector_dataplane_lock",
                    })?,
                FaultingSelectorDataplaneState::Active(active) if active == expected
            )
            .then_some(crate::GtpuSessionSelectorRetiringRecovery::ExactPreviousActive)
            .ok_or(crate::GtpuError::StateIndeterminate {
                operation: "faulting_selector_retiring_negative_proof",
            })
        }

        async fn inspect_retiring_selector_resume(
            &self,
            expected: &GtpuSessionGroup,
            _admission: &GtpuSessionSelectorAdmission,
        ) -> Result<crate::GtpuSessionSelectorRetiringResume, crate::GtpuError> {
            match &*self
                .dataplane
                .lock()
                .map_err(|_| crate::GtpuError::StateIndeterminate {
                    operation: "faulting_selector_dataplane_lock",
                })? {
                FaultingSelectorDataplaneState::Active(active) if active == expected => {
                    Ok(crate::GtpuSessionSelectorRetiringResume::NoEffect)
                }
                FaultingSelectorDataplaneState::Pending => {
                    Ok(crate::GtpuSessionSelectorRetiringResume::ExactPendingRemove)
                }
                _ => Err(crate::GtpuError::StateIndeterminate {
                    operation: "faulting_selector_retiring_resume_proof",
                }),
            }
        }

        async fn inspect_selector_namespace_decommission_fence(
            &self,
            request: GtpuSessionSelectorDecommissionInspectRequest,
        ) -> Result<GtpuSessionSelectorBackendReceipt, crate::GtpuError> {
            let expected = request.expected_terminal_marker_payload();
            let stored =
                *self
                    .terminal_fence
                    .lock()
                    .map_err(|_| crate::GtpuError::StateIndeterminate {
                        operation: "faulting_selector_terminal_lock",
                    })?;
            self.terminal_operations
                .lock()
                .map_err(|_| crate::GtpuError::StateIndeterminate {
                    operation: "faulting_selector_terminal_lock",
                })?
                .push(match (expected.is_some(), stored.is_some()) {
                    (false, false) => TerminalFenceOperation::InspectAbsent,
                    (true, false) => TerminalFenceOperation::InspectExpectedAbsent,
                    (true, true) => TerminalFenceOperation::InspectExpectedExact,
                    (false, true) => {
                        return Err(crate::GtpuError::StateIndeterminate {
                            operation: "faulting_selector_terminal_conflict",
                        });
                    }
                });
            match (expected, stored) {
                (None, None) | (Some(_), None) => Ok(request.confirm_absent()),
                (Some(expected), Some(stored)) if expected == stored => Ok(request.confirm_exact()),
                _ => Err(crate::GtpuError::StateIndeterminate {
                    operation: "faulting_selector_terminal_conflict",
                }),
            }
        }

        async fn create_selector_namespace_decommission_fence(
            &self,
            request: GtpuSessionSelectorDecommissionRequest,
        ) -> Result<GtpuSessionSelectorBackendReceipt, crate::GtpuError> {
            let expected = request.terminal_marker_payload();
            let mut stored =
                self.terminal_fence
                    .lock()
                    .map_err(|_| crate::GtpuError::StateIndeterminate {
                        operation: "faulting_selector_terminal_lock",
                    })?;
            self.terminal_operations
                .lock()
                .map_err(|_| crate::GtpuError::StateIndeterminate {
                    operation: "faulting_selector_terminal_lock",
                })?
                .push(TerminalFenceOperation::Create);
            match *stored {
                None => *stored = Some(expected),
                Some(existing) if existing == expected => {}
                Some(_) => {
                    return Err(crate::GtpuError::StateIndeterminate {
                        operation: "faulting_selector_terminal_conflict",
                    });
                }
            }
            Ok(request.confirm())
        }

        async fn read_selector_namespace_decommission_fence(
            &self,
            request: GtpuSessionSelectorDecommissionReadbackRequest,
        ) -> Result<GtpuSessionSelectorBackendReceipt, crate::GtpuError> {
            let expected = request.terminal_marker_payload();
            let stored =
                *self
                    .terminal_fence
                    .lock()
                    .map_err(|_| crate::GtpuError::StateIndeterminate {
                        operation: "faulting_selector_terminal_lock",
                    })?;
            self.terminal_operations
                .lock()
                .map_err(|_| crate::GtpuError::StateIndeterminate {
                    operation: "faulting_selector_terminal_lock",
                })?
                .push(TerminalFenceOperation::Readback);
            (stored == Some(expected))
                .then(|| request.confirm_exact())
                .ok_or(crate::GtpuError::StateIndeterminate {
                    operation: "faulting_selector_terminal_conflict",
                })
        }

        async fn reconcile_pdp_context_group_authorized(
            &self,
            request: GtpuSessionSelectorEffectRequest,
        ) -> Result<GtpuSessionSelectorBackendReceipt, crate::GtpuError> {
            let desired = request.desired_group().clone();
            self.effect_calls
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            if self.effect_fault.load(std::sync::atomic::Ordering::Acquire) {
                return Ok(
                    request.complete(GtpuSessionGroupReconcileOutcome::Indeterminate(
                        crate::GtpuSessionGroupIndeterminateReason::IncompleteState,
                    )),
                );
            }
            *self
                .dataplane
                .lock()
                .map_err(|_| crate::GtpuError::StateIndeterminate {
                    operation: "faulting_selector_dataplane_lock",
                })? = FaultingSelectorDataplaneState::Active(desired);
            if self
                .effect_ack_lost
                .load(std::sync::atomic::Ordering::Acquire)
            {
                return Err(crate::GtpuError::StateIndeterminate {
                    operation: "faulting_selector_effect_ack_lost",
                });
            }
            Ok(request.complete(GtpuSessionGroupReconcileOutcome::Activated))
        }

        async fn read_pdp_context_group_with_lease(
            &self,
            request: GtpuSessionSelectorReadbackRequest,
        ) -> Result<GtpuSessionSelectorBackendReceipt, crate::GtpuError> {
            let expected = request.expected_group().clone();
            Ok(request.complete(self.dataplane_readback(&expected)?))
        }

        async fn remove_pdp_context_group_with_lease(
            &self,
            request: GtpuSessionSelectorRemovalRequest,
        ) -> Result<GtpuSessionSelectorBackendReceipt, crate::GtpuError> {
            let expected = request.expected_group().clone();
            self.removal_calls
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            let outcome = {
                let mut dataplane =
                    self.dataplane
                        .lock()
                        .map_err(|_| crate::GtpuError::StateIndeterminate {
                            operation: "faulting_selector_dataplane_lock",
                        })?;
                match &*dataplane {
                    FaultingSelectorDataplaneState::Active(active) if active == &expected => {
                        *dataplane = FaultingSelectorDataplaneState::Retired;
                        GtpuSessionGroupRemovalOutcome::Removed
                    }
                    FaultingSelectorDataplaneState::Retired => {
                        GtpuSessionGroupRemovalOutcome::AlreadyAbsent
                    }
                    _ => {
                        return Err(crate::GtpuError::StateIndeterminate {
                            operation: "faulting_selector_indeterminate_removal",
                        });
                    }
                }
            };
            if self
                .removal_ack_lost
                .load(std::sync::atomic::Ordering::Acquire)
            {
                return Err(crate::GtpuError::StateIndeterminate {
                    operation: "faulting_selector_removal_ack_lost",
                });
            }
            Ok(request.complete(outcome))
        }
    }

    #[test]
    fn claim_is_atomic_across_all_selector_axes_and_generation_is_monotonic() {
        let namespace = InMemoryGtpuSessionSelectorNamespace::default();
        let first = group(1, 1, 0x1000_0001, Some(7));
        let admission = namespace.claim(&first, None).unwrap();
        assert_eq!(admission.generation().get(), 1);

        let collision = group(2, 1, 0x1000_0001, Some(7));
        assert!(matches!(
            namespace.claim(&collision, None),
            Err(GtpuSessionSelectorNamespaceError::SelectorClaimed)
        ));
        let independent = group(3, 1, 0x1000_0003, Some(8));
        let next = namespace
            .claim(&independent, Some(admission.generation()))
            .unwrap();
        assert_eq!(next.generation().get(), 2);
        assert!(matches!(
            namespace.claim(
                &group(4, 1, 0x1000_0004, None),
                Some(admission.generation())
            ),
            Err(GtpuSessionSelectorNamespaceError::StaleGeneration)
        ));
    }

    #[test]
    fn concurrent_claimants_admit_exactly_one_complete_claim() {
        let namespace = Arc::new(InMemoryGtpuSessionSelectorNamespace::default());
        let claimed_group = group(1, 1, 0x1000_0001, None);
        let left = Arc::clone(&namespace);
        let right = Arc::clone(&namespace);
        let first = std::thread::spawn(move || left.claim(&claimed_group, None));
        let competing = group(2, 1, 0x1000_0001, None);
        let second = std::thread::spawn(move || right.claim(&competing, None));
        let outcomes = [first.join().unwrap(), second.join().unwrap()];
        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(
                    outcome,
                    Err(GtpuSessionSelectorNamespaceError::SelectorClaimed)
                ))
                .count(),
            1
        );
    }

    #[test]
    fn retirement_is_permanent_but_allows_explicit_reissue_with_new_generation() {
        let namespace = InMemoryGtpuSessionSelectorNamespace::default();
        let original = group(1, 1, 0x1000_0001, None);
        let admission = namespace.claim(&original, None).unwrap();
        let retiring = namespace.begin_retire(admission).unwrap();
        namespace.finish_retire(retiring).unwrap();
        assert!(matches!(
            namespace.claim(&original, None),
            Err(GtpuSessionSelectorNamespaceError::GroupClaimed)
        ));
        let reissued = GtpuSessionGroup::new(
            GtpuSessionGroupId::new([2; 16]).unwrap(),
            original.device_id(),
            original.entries().to_vec(),
        )
        .unwrap();
        assert_eq!(
            namespace
                .claim_reused(
                    &reissued,
                    &crate::GtpuSessionSelectorReuseProof::after_traffic_drain(original),
                )
                .unwrap()
                .generation()
                .get(),
            4
        );
    }

    #[test]
    fn published_atom_history_is_permanent_and_mixed_install_provenance_is_invalid() {
        let namespace = InMemoryGtpuSessionSelectorNamespace::default();
        let published = group(1, 1, 0x1000_0001, Some(7));
        namespace.claim(&published, None).unwrap();

        let mut state = namespace.state.lock().unwrap().clone();
        assert!(state
            .published_atoms
            .iter()
            .all(|atom| state.selectors.contains_key(atom)));
        state.published_atoms.clear();
        assert!(
            !state.is_complete(),
            "an Active graph without exact per-atom publication history must fail closed"
        );
        assert!(NamespaceState::decode(&state.encode()).is_none());

        let mut state = namespace.state.lock().unwrap().clone();
        let atom = *state
            .published_atoms
            .iter()
            .next()
            .expect("test group has canonical atoms");
        state.published_atoms.remove(&atom);
        assert!(
            !state.is_complete(),
            "a partially historical selector bundle must not be recoverable as fresh or reused"
        );
        assert!(NamespaceState::decode(&state.encode()).is_none());
    }

    #[test]
    fn fresh_rejects_any_reused_elementary_teid_paa_or_full_mask_mark_atom() {
        let namespace = InMemoryGtpuSessionSelectorNamespace::default();
        let old = group_with_paa(
            1,
            1,
            0x1000_0001,
            IpAddr::V4(Ipv4Addr::new(10, 23, 0, 9)),
            Some(7),
        );
        namespace.claim(&old, None).unwrap();

        // TEID is new, but the old canonical IPv4 /32 is not a fresh atom.
        let old_paa_new_mark = group_with_paa(
            2,
            1,
            0x1000_0002,
            IpAddr::V4(Ipv4Addr::new(10, 23, 0, 9)),
            Some(8),
        );
        assert!(matches!(
            namespace.claim(&old_paa_new_mark, None),
            Err(GtpuSessionSelectorNamespaceError::SelectorClaimed)
        ));

        // The PAA and TEID are new, but a nonzero complete mark is itself a
        // permanently reserved routing selector.
        let old_mark_new_paa = group_with_paa(
            3,
            1,
            0x1000_0003,
            IpAddr::V4(Ipv4Addr::new(10, 23, 0, 10)),
            Some(7),
        );
        assert!(matches!(
            namespace.claim(&old_mark_new_paa, None),
            Err(GtpuSessionSelectorNamespaceError::SelectorClaimed)
        ));

        // A changed bundle cannot hide one old family-qualified downlink
        // TEID behind otherwise new PAA and mark atoms.
        let old_teid_changed_bundle = group_with_paa(
            4,
            1,
            0x1000_0001,
            IpAddr::V4(Ipv4Addr::new(10, 23, 0, 11)),
            Some(9),
        );
        assert!(matches!(
            namespace.claim(&old_teid_changed_bundle, None),
            Err(GtpuSessionSelectorNamespaceError::SelectorClaimed)
        ));
    }

    #[test]
    fn retired_predecessor_has_exactly_one_immutable_successor() {
        let namespace = InMemoryGtpuSessionSelectorNamespace::default();
        let original = group(1, 1, 0x1000_0001, None);
        let admission = namespace.claim(&original, None).unwrap();
        namespace
            .finish_retire(namespace.begin_retire(admission).unwrap())
            .unwrap();
        let proof = crate::GtpuSessionSelectorReuseProof::after_traffic_drain(original.clone());
        let first_successor = GtpuSessionGroup::new(
            GtpuSessionGroupId::new([2; 16]).unwrap(),
            original.device_id(),
            original.entries().to_vec(),
        )
        .unwrap();
        let successor_admission = namespace.claim_reused(&first_successor, &proof).unwrap();
        // Even after that successor retires, the original row retains its
        // one-way edge and cannot be used to mint a second lineage branch.
        namespace
            .finish_retire(namespace.begin_retire(successor_admission).unwrap())
            .unwrap();
        let competing_successor = GtpuSessionGroup::new(
            GtpuSessionGroupId::new([3; 16]).unwrap(),
            original.device_id(),
            original.entries().to_vec(),
        )
        .unwrap();
        assert!(matches!(
            namespace.claim_reused(&competing_successor, &proof),
            Err(GtpuSessionSelectorNamespaceError::SelectorClaimed)
        ));
    }

    #[test]
    fn request_rejects_cross_group_or_cross_device_admission_and_redacts() {
        let namespace = InMemoryGtpuSessionSelectorNamespace::default();
        let original = group(1, 1, 0x1000_0001, Some(0x0102_0304));
        let admission = namespace.claim(&original, None).unwrap();
        let wrong_group = group(2, 1, 0x1000_0002, None);
        assert!(matches!(
            crate::GtpuSessionGroupReconcileRequest::new(wrong_group, admission),
            Err(crate::GtpuSessionModelError::SelectorAdmissionMismatch)
        ));
        let debug = format!("{:?}", namespace.claim(&original, None));
        assert!(!debug.contains("10000001"));
        assert!(!debug.contains("01020304"));
    }

    #[test]
    fn stable_group_key_is_distinct_from_complete_forwarding_commitment() {
        let original = group(1, 1, 0x1000_0001, None);
        let mut changed_context = original.entries()[0].context().clone();
        changed_context.peer_teid = Teid::new(0x2000_0001).unwrap();
        let changed = GtpuSessionGroup::new(
            original.id(),
            original.device_id(),
            vec![GtpuSessionEntry::new(
                changed_context,
                original.entries()[0].local_outer_address(),
            )
            .unwrap()],
        )
        .unwrap();
        let original_claim = CanonicalClaim::from_group(&original)
            .with_key(&[0x53; 32])
            .expect("fixed test HMAC key");
        let changed_claim = CanonicalClaim::from_group(&changed)
            .with_key(&[0x53; 32])
            .expect("fixed test HMAC key");
        assert_eq!(
            original_claim.group_fingerprint, changed_claim.group_fingerprint,
            "device plus caller group ID is the stable namespace key"
        );
        assert_eq!(
            original_claim.selector_set_fingerprint, changed_claim.selector_set_fingerprint,
            "a forwarding-only change must not masquerade as a selector change"
        );
        assert_ne!(
            original_claim.desired_fingerprint, changed_claim.desired_fingerprint,
            "the admission binds complete forwarding semantics"
        );

        let namespace = InMemoryGtpuSessionSelectorNamespace::default();
        let admission = namespace.claim(&original, None).unwrap();
        assert!(matches!(
            crate::GtpuSessionGroupReconcileRequest::new(changed, admission),
            Err(crate::GtpuSessionModelError::SelectorAdmissionMismatch)
        ));
    }

    #[tokio::test]
    async fn effect_fault_leaves_durable_installing_intent_non_reissuable() {
        let desired = group(1, 1, 0x1000_0001, None);
        let authority = production_authority(desired.device_id()).await;
        let backend = Arc::new(FaultingSelectorBackend::default());
        authority.provision(backend.as_ref()).await.unwrap();
        backend.set_effect_fault(true);

        assert!(matches!(
            authority
                .reconcile_fresh(backend.clone(), desired.clone())
                .await,
            Err(GtpuSessionSelectorCoordinatorError::Backend)
        ));

        backend.set_effect_fault(false);
        assert!(matches!(
            authority.reconcile_fresh(backend, desired).await,
            Err(GtpuSessionSelectorCoordinatorError::Namespace)
        ));
    }

    #[tokio::test]
    async fn false_install_recovery_only_advances_after_exact_negative_proof() {
        for (case, state) in [
            ("pending", FaultingSelectorDataplaneState::Pending),
            (
                "terminal",
                FaultingSelectorDataplaneState::Active(group(1, 1, 0x1000_0001, None)),
            ),
            ("partial", FaultingSelectorDataplaneState::Partial),
        ] {
            let desired = group(1, 1, 0x1000_0001, None);
            let authority = production_authority(desired.device_id()).await;
            let backend = Arc::new(FaultingSelectorBackend::default());
            authority.provision(backend.as_ref()).await.unwrap();
            authority
                .claim_fresh(backend.as_ref(), &desired)
                .await
                .unwrap();
            backend.set_dataplane(state);

            assert!(
                matches!(
                    authority.recover_install(backend.clone(), desired).await,
                    Err(GtpuSessionSelectorCoordinatorError::Backend),
                ),
                "{case} must not turn Installing(false) into an effect retry"
            );
            assert_eq!(backend.effect_calls(), 0, "{case} must be mutation-free");
        }
    }

    #[tokio::test]
    async fn started_install_recovery_resumes_only_exact_pending_and_recovers_ack_loss() {
        let desired = group(1, 1, 0x1000_0001, None);
        let authority = production_authority(desired.device_id()).await;
        let backend = Arc::new(FaultingSelectorBackend::default());
        authority.provision(backend.as_ref()).await.unwrap();
        authority
            .claim_fresh(backend.as_ref(), &desired)
            .await
            .unwrap();
        assert!(matches!(
            authority
                .mark_install_backend_started(&desired)
                .await
                .unwrap(),
            BackendStartHandoff::Transitioned(_),
        ));
        backend.set_dataplane(FaultingSelectorDataplaneState::Pending);
        let _ = authority
            .recover_install(backend.clone(), desired.clone())
            .await
            .unwrap();
        assert_eq!(backend.effect_calls(), 1);

        let ack_loss_desired = group(2, 1, 0x1000_0002, None);
        let ack_loss_authority = production_authority(ack_loss_desired.device_id()).await;
        let ack_loss_backend = Arc::new(FaultingSelectorBackend::default());
        ack_loss_authority
            .provision(ack_loss_backend.as_ref())
            .await
            .unwrap();
        ack_loss_backend.set_effect_ack_lost(true);
        assert!(matches!(
            ack_loss_authority
                .reconcile_fresh(ack_loss_backend.clone(), ack_loss_desired.clone())
                .await,
            Err(GtpuSessionSelectorCoordinatorError::Backend),
        ));
        assert_eq!(ack_loss_backend.effect_calls(), 1);
        ack_loss_backend.set_effect_ack_lost(false);
        let _ = ack_loss_authority
            .recover_install(ack_loss_backend.clone(), ack_loss_desired)
            .await
            .unwrap();
        assert_eq!(
            ack_loss_backend.effect_calls(),
            1,
            "a confirmed terminal Active readback must settle ACK loss without replay"
        );
    }

    #[tokio::test]
    async fn concurrent_false_install_recovery_has_one_backend_effect_winner() {
        let desired = group(1, 1, 0x1000_0001, None);
        let authority = production_authority(desired.device_id()).await;
        let backend = Arc::new(FaultingSelectorBackend::default());
        authority.provision(backend.as_ref()).await.unwrap();
        authority
            .claim_fresh(backend.as_ref(), &desired)
            .await
            .unwrap();
        backend.synchronize_no_effect_inspections(2);

        let (left, right) = tokio::join!(
            authority.recover_install(backend.clone(), desired.clone()),
            authority.recover_install(backend.clone(), desired),
        );
        assert_eq!(backend.effect_calls(), 1);
        assert!(left.is_ok() || right.is_ok());
    }

    #[tokio::test]
    async fn concurrent_false_retiring_recovery_has_one_backend_effect_winner() {
        let desired = group(1, 1, 0x1000_0001, None);
        let authority = production_authority(desired.device_id()).await;
        let backend = Arc::new(FaultingSelectorBackend::default());
        authority.provision(backend.as_ref()).await.unwrap();
        let active = authority
            .reconcile_fresh(backend.clone(), desired.clone())
            .await
            .unwrap();
        authority.transition_retiring(&active.0).await.unwrap();
        backend.synchronize_no_effect_inspections(2);

        let (left, right) = tokio::join!(
            authority.recover_retiring(backend.clone(), desired.clone()),
            authority.recover_retiring(backend.clone(), desired),
        );
        assert_eq!(backend.removal_calls(), 1);
        assert!(left.is_ok() || right.is_ok());
    }

    #[tokio::test]
    async fn retiring_ack_loss_settles_from_exact_absence_without_replay() {
        let desired = group(1, 1, 0x1000_0001, None);
        let authority = production_authority(desired.device_id()).await;
        let backend = Arc::new(FaultingSelectorBackend::default());
        authority.provision(backend.as_ref()).await.unwrap();
        let active = authority
            .reconcile_fresh(backend.clone(), desired.clone())
            .await
            .unwrap();
        backend.set_removal_ack_lost(true);
        assert!(matches!(
            authority
                .retire(backend.clone(), active, desired.clone())
                .await,
            Err(GtpuSessionSelectorCoordinatorError::Backend),
        ));
        assert_eq!(backend.removal_calls(), 1);
        backend.set_removal_ack_lost(false);
        let _ = authority
            .recover_retiring(backend.clone(), desired)
            .await
            .unwrap();
        assert_eq!(
            backend.removal_calls(),
            1,
            "an exact terminal absence must settle removal ACK loss without replay"
        );
    }

    #[tokio::test]
    async fn decommission_requires_absent_then_exact_durable_terminal_capsule() {
        let desired = group(1, 1, 0x1000_0001, None);
        let authority = production_authority(desired.device_id()).await;
        let backend = Arc::new(FaultingSelectorBackend::default());
        authority.provision(backend.as_ref()).await.unwrap();

        authority.decommission(backend.clone()).await.unwrap();
        assert!(backend
            .terminal_fence
            .lock()
            .expect("terminal fence lock")
            .is_some());
        assert_eq!(
            *backend
                .terminal_operations
                .lock()
                .expect("terminal operation lock"),
            vec![
                TerminalFenceOperation::InspectAbsent,
                TerminalFenceOperation::InspectExpectedAbsent,
                TerminalFenceOperation::Create,
                TerminalFenceOperation::Readback,
                TerminalFenceOperation::Readback,
            ]
        );

        // Recovery converges only the same authenticated capsule; it does not
        // mint a replacement coordinate after the durable terminal CAS.
        authority.decommission(backend.clone()).await.unwrap();
        assert_eq!(
            *backend
                .terminal_operations
                .lock()
                .expect("terminal operation lock"),
            vec![
                TerminalFenceOperation::InspectAbsent,
                TerminalFenceOperation::InspectExpectedAbsent,
                TerminalFenceOperation::Create,
                TerminalFenceOperation::Readback,
                TerminalFenceOperation::Readback,
                TerminalFenceOperation::InspectExpectedExact,
                TerminalFenceOperation::Readback,
                TerminalFenceOperation::Readback,
            ]
        );
    }

    #[test]
    fn durable_authority_recovers_from_readback_and_rejects_replay_after_restart() {
        let store = InMemoryGtpuSessionSelectorNamespaceStore::default();
        let original = group(1, 1, 0x1000_0001, None);
        let authority =
            TestGtpuSessionSelectorNamespaceAuthority::new(store.clone(), [0x53; 32], 32);
        let admission = authority.claim(&original, None).unwrap();
        assert_eq!(admission.generation().get(), 1);

        // A reconstructed coordinator sees the exact committed ledger rather
        // than a process-local cache and cannot mint another claim.
        let restarted = TestGtpuSessionSelectorNamespaceAuthority::new(store, [0x53; 32], 32);
        assert!(matches!(
            restarted.claim(&original, None),
            Err(GtpuSessionSelectorNamespaceError::GroupClaimed)
        ));
    }

    #[test]
    fn durable_authority_retirement_tombstones_group_before_reissue() {
        let store = InMemoryGtpuSessionSelectorNamespaceStore::default();
        let authority = TestGtpuSessionSelectorNamespaceAuthority::new(store, [0x53; 32], 32);
        let original = group(1, 1, 0x1000_0001, None);
        let admission = authority.claim(&original, None).unwrap();
        let active = authority.activate(admission).unwrap();
        let retiring = authority.begin_retire(active).unwrap();
        authority.finish_retire(retiring).unwrap();
        assert!(matches!(
            authority.claim(&original, None),
            Err(GtpuSessionSelectorNamespaceError::GroupClaimed)
        ));
        assert!(matches!(
            authority.claim(&group(2, 1, 0x1000_0001, None), None),
            Err(GtpuSessionSelectorNamespaceError::SelectorClaimed)
        ));
    }

    #[test]
    fn durable_record_rejects_trailing_and_uncommitted_configuration_bytes() {
        let empty = GtpuSessionSelectorNamespaceRecord::empty();
        assert!(NamespaceState::decode(empty.as_bytes()).is_some());
        let mut trailing = empty.as_bytes().to_vec();
        trailing.push(0);
        assert!(NamespaceState::decode(&trailing).is_none());

        let store = InMemoryGtpuSessionSelectorNamespaceStore::default();
        let first = TestGtpuSessionSelectorNamespaceAuthority::new(store.clone(), [0x53; 32], 32);
        first.claim(&group(1, 1, 0x1000_0001, None), None).unwrap();
        let changed_key =
            TestGtpuSessionSelectorNamespaceAuthority::new(store.clone(), [0x54; 32], 32);
        assert!(matches!(
            changed_key.claim(&group(2, 1, 0x1000_0002, None), None),
            Err(GtpuSessionSelectorNamespaceError::ConfigurationMismatch)
        ));
        let smaller_per_operation_bound =
            TestGtpuSessionSelectorNamespaceAuthority::new(store, [0x53; 32], 31);
        assert!(matches!(
            smaller_per_operation_bound.claim(&group(2, 1, 0x1000_0002, None), None),
            Err(GtpuSessionSelectorNamespaceError::ConfigurationMismatch)
        ));
    }

    #[test]
    fn per_operation_atom_bound_rejects_before_effects() {
        let store = InMemoryGtpuSessionSelectorNamespaceStore::default();
        // The caller-facing bound limits a single exact readback only; it
        // never changes the immutable namespace profile persisted in state.
        let too_small =
            TestGtpuSessionSelectorNamespaceAuthority::new(store.clone(), [0x53; 32], 1);
        let original = group(1, 1, 0x1000_0001, None);
        assert!(matches!(
            too_small.claim(&original, None),
            Err(GtpuSessionSelectorNamespaceError::CapacityExhausted)
        ));

        let authority = TestGtpuSessionSelectorNamespaceAuthority::new(store, [0x53; 32], 5);
        let admission = authority.claim(&original, None).unwrap();
        let active = authority.activate(admission).unwrap();
        let retiring = authority.begin_retire(active).unwrap();
        authority.finish_retire(retiring).unwrap();
        // Retirement does not consume a new namespace slot: that capacity was
        // reserved by the original claim, so an unrelated fresh group remains
        // admissible under the fixed global profile.
        assert!(authority
            .claim(&group(2, 1, 0x1000_0002, None), None)
            .is_ok());
    }

    #[test]
    fn v3_codec_rejects_orphaned_or_noncanonical_ledger_rows() {
        let mut device_codec = Vec::from([1]);
        device_codec.extend_from_slice(&[1; 16]);
        let device = keyed_digest(&[9; 32], GROUP_DOMAIN, &device_codec);
        let group = [2; 32];
        let first = [3; 32];
        let second = [4; 32];
        let generation = GtpuSessionSelectorAuthorityGeneration(NonZeroU64::new(1).unwrap());
        let mut atoms = BTreeSet::new();
        atoms.insert(first);
        atoms.insert(second);
        let mut state = NamespaceState {
            lifecycle: NamespaceLifecycle::Bound,
            stable_device: Some([1; 16]),
            pin_commitment: [7; 32],
            storage_scope_commitment: [6; 32],
            ledger_id: [2; 16],
            backend_epoch: [8; 16],
            selector_digest_key: [9; 32],
            key_commitment: key_commitment(&[9; 32], &[2; 16], &[7; 32], &[1; 16], &[6; 32]),
            capacity: SELECTOR_NAMESPACE_MAX_READBACK_ATOMS as u32,
            generation: 2,
            decommission_fence: None,
            selectors: BTreeMap::new(),
            groups: BTreeMap::new(),
            published_atoms: BTreeSet::new(),
            tombstones: BTreeSet::new(),
        };
        state
            .selectors
            .insert(first, SelectorState::Installing { group, generation });
        state
            .selectors
            .insert(second, SelectorState::Installing { group, generation });
        state.published_atoms.insert(first);
        state.published_atoms.insert(second);
        state.groups.insert(
            group,
            GroupState::Installing {
                device,
                selectors: [5; 32],
                desired: [6; 32],
                atoms: atoms.clone(),
                generation,
                operation_nonce: [3; 16],
                terminal_generation: GtpuSessionSelectorAuthorityGeneration(
                    NonZeroU64::new(2).unwrap(),
                ),
                terminal_operation_nonce: [4; 16],
                backend_started: false,
            },
        );
        assert!(state.is_complete());

        let mut altered_device = state.clone();
        if let Some(GroupState::Installing { device, .. }) = altered_device.groups.get_mut(&group) {
            *device = [7; 32];
        }
        assert!(!altered_device.is_complete());
        let mut missing_selector = state.clone();
        missing_selector.selectors.remove(&second);
        assert!(!missing_selector.is_complete());
        let mut extra_pointer = state.clone();
        extra_pointer
            .selectors
            .insert([8; 32], SelectorState::Installing { group, generation });
        assert!(!extra_pointer.is_complete());
        let mut zero_atoms = state.clone();
        if let Some(GroupState::Installing { atoms, .. }) = zero_atoms.groups.get_mut(&group) {
            atoms.clear();
        }
        assert!(!zero_atoms.is_complete());
        let mut zero_nonce = state.clone();
        if let Some(GroupState::Installing {
            operation_nonce, ..
        }) = zero_nonce.groups.get_mut(&group)
        {
            *operation_nonce = [0; 16];
        }
        assert!(!zero_nonce.is_complete());
        let mut orphan_tombstone = state.clone();
        orphan_tombstone.tombstones.insert([10; 32]);
        assert!(!orphan_tombstone.is_complete());
        let mut orphan_retired = state.clone();
        orphan_retired
            .selectors
            .insert([11; 32], SelectorState::Retired);
        orphan_retired.tombstones.insert([11; 32]);
        assert!(!orphan_retired.is_complete());

        let mut encoded = state.encode();
        let selectors_offset = 6 + 1 + 1 + 16 + 32 + 32 + 16 + 16 + 32 + 32 + 4 + 8 + 1 + 4;
        let row_len = 32 + 1 + 32 + 8;
        let first_row = encoded[selectors_offset..selectors_offset + row_len].to_vec();
        let second_row =
            encoded[selectors_offset + row_len..selectors_offset + (2 * row_len)].to_vec();
        encoded[selectors_offset..selectors_offset + row_len].copy_from_slice(&second_row);
        encoded[selectors_offset + row_len..selectors_offset + (2 * row_len)]
            .copy_from_slice(&first_row);
        assert!(NamespaceState::decode(&encoded).is_none());
    }

    #[test]
    fn decommission_fence_persists_one_authenticated_precommitted_coordinate() {
        let key = [0x53; 32];
        let device = GtpuSessionDeviceId::new([1; 16]).unwrap();
        let mut state = NamespaceState::default();
        state
            .bind_or_validate(device, SELECTOR_NAMESPACE_MAX_READBACK_ATOMS, Some(key))
            .unwrap();
        let fence = state.precommit_decommission().unwrap();
        assert!(state.decommission_fence_is_exact(fence));
        let recovered = NamespaceState::decode(&state.encode()).unwrap();
        assert!(recovered.decommission_fence == Some(fence));
        assert!(recovered.decommission_fence_is_exact(fence));

        // The terminal marker may only settle the persisted fence. A recovery
        // record retains the exact same coordinate; it cannot mint a new one.
        state.lifecycle = NamespaceLifecycle::Decommissioned;
        let terminal = NamespaceState::decode(&state.encode()).unwrap();
        assert!(terminal.decommission_fence == Some(fence));

        let mut corrupted = state;
        corrupted
            .decommission_fence
            .as_mut()
            .unwrap()
            .terminal
            .nonce[0] ^= 1;
        assert!(NamespaceState::decode(&corrupted.encode()).is_none());
    }

    #[test]
    fn fixed_profile_worst_case_record_stays_within_plaintext_envelope() {
        let generation = GtpuSessionSelectorAuthorityGeneration(NonZeroU64::new(1).unwrap());
        let mut state = NamespaceState {
            lifecycle: NamespaceLifecycle::Bound,
            stable_device: Some([1; 16]),
            pin_commitment: [7; 32],
            storage_scope_commitment: [6; 32],
            ledger_id: [2; 16],
            backend_epoch: [3; 16],
            selector_digest_key: [4; 32],
            key_commitment: key_commitment(&[4; 32], &[2; 16], &[7; 32], &[1; 16], &[6; 32]),
            capacity: SELECTOR_NAMESPACE_MAX_READBACK_ATOMS as u32,
            generation: 1,
            decommission_fence: None,
            selectors: BTreeMap::new(),
            groups: BTreeMap::new(),
            published_atoms: BTreeSet::new(),
            tombstones: BTreeSet::new(),
        };
        let mut atoms = Vec::with_capacity(MAX_KNOWN_ATOMS);
        for index in 0..MAX_KNOWN_ATOMS {
            let mut atom = [0_u8; 32];
            atom[30..].copy_from_slice(&(index as u16).to_be_bytes());
            state.selectors.insert(atom, SelectorState::Retired);
            state.published_atoms.insert(atom);
            state.tombstones.insert(atom);
            atoms.push(atom);
        }
        let mut device_codec = Vec::from([1]);
        device_codec.extend_from_slice(&[1; 16]);
        let device = keyed_digest(&[4; 32], GROUP_DOMAIN, &device_codec);
        for index in 0..MAX_PERMANENT_GROUPS {
            let mut group = [0_u8; 32];
            group[28..].copy_from_slice(&(index as u32).to_be_bytes());
            let next_index = (index + 1) % MAX_PERMANENT_GROUPS;
            let mut successor_group = [0_u8; 32];
            successor_group[28..].copy_from_slice(&(next_index as u32).to_be_bytes());
            let group_atoms = (0..4)
                .map(|offset| atoms[(index * 4 + offset) % MAX_KNOWN_ATOMS])
                .collect();
            state.groups.insert(
                group,
                GroupState::Retired {
                    device,
                    selectors: [5; 32],
                    desired: [6; 32],
                    atoms: group_atoms,
                    generation,
                    operation_nonce: [7; 16],
                    successor: Some(RetiredSuccessor {
                        group: successor_group,
                        generation,
                    }),
                },
            );
        }
        assert_eq!(state.group_atom_references(), MAX_GROUP_ATOM_REFERENCES);
        let encoded = state.encode();
        assert!(encoded.len() <= MAX_RECORD_BYTES, "{}", encoded.len());
        assert!(NamespaceState::decode(&encoded).is_some());
    }
}
