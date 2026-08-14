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
use std::time::{Duration, Instant, SystemTime};

use aes_gcm_siv::{
    aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
    Aes256GcmSiv,
};
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
const PRE_DECOMMISSION_BOUND_DOMAIN: &[u8] = b"opc/gtpu-selector/pre-decommission-bound/v1\0";
const DECOMMISSION_AEAD_KEY_DOMAIN: &[u8] = b"opc/gtpu-selector/decommission/aead-key/v1\0";
const DECOMMISSION_NONCE_KEY_DOMAIN: &[u8] = b"opc/gtpu-selector/decommission/nonce-key/v1\0";
const DECOMMISSION_AAD_DOMAIN: &[u8] = b"opc/gtpu-selector/decommission/aad/v1\0";
const BACKEND_RECEIPT_DOMAIN: &[u8] = b"opc/gtpu-selector/backend-receipt/v1\0";
const OPERATION_INVENTORY_DOMAIN: &[u8] = b"opc/gtpu-selector/operation-inventory/v1\0";
const BACKEND_MUTATION_WINDOW_DOMAIN: &[u8] = b"opc/gtpu-selector/backend-mutation-window/v1\0";
pub(crate) const DECOMMISSION_CAPSULE_LEN: usize = 110;
const DECOMMISSION_COORDINATE_LEN: usize = 81;
const SELECTOR_LEDGER_KEY_TYPE: &str = "gtpu-selector-ledger-v1";
/// RFC 016's fixed reference-profile plaintext ceiling. The protected-store
/// envelope receives a separate reserve below; larger plaintext profiles are
/// never accepted implicitly.
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
const MAX_CANONICAL_DESIRED_BYTES: usize = 192;
/// Permanent canonical desired descriptors are retained once for every group
/// ever admitted.  This bounded index lets a recovered authority reconstruct
/// the exact 16-byte operation-stamp key rather than trusting a caller to
/// restate a historic group.
const MAX_CANONICAL_DESIRED_RECORDS: usize = MAX_PERMANENT_GROUPS;
const MAX_REUSED_INSTALL_DESCRIPTOR_BYTES: usize =
    1 + 2 + MAX_CANONICAL_DESIRED_BYTES + 1 + (3 * 32) + 8 + 16 + 8;
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

/// Observe one backend step for its bounded result without ever cancelling
/// work that has already been polled.
///
/// Backend adapters may cross into an uncancellable host worker (for example
/// `spawn_blocking`). Dropping their future at the deadline would release the
/// durable worker and namespace gate while that host worker could still hold
/// a current mutation request. On expiry we therefore retain and poll the
/// future to terminal completion, discard its now-late result, and only then
/// let the caller poison/release durable authority. Bounded supervisor slots
/// make a backend that never terminates a fail-closed availability fault
/// rather than a stale-effect race.
async fn settle_selector_backend_step<F, T>(future: F) -> Option<T>
where
    F: Future<Output = T>,
{
    settle_selector_backend_step_within(SELECTOR_NAMESPACE_MAX_EFFECT_DURATION, future).await
}

async fn settle_selector_backend_step_within<F, T>(duration: Duration, future: F) -> Option<T>
where
    F: Future<Output = T>,
{
    tokio::pin!(future);
    match tokio::time::timeout(duration, future.as_mut()).await {
        Ok(value) => Some(value),
        Err(_) => {
            // Do not drop an already-started backend future. In particular,
            // dropping a Tokio blocking-task join does not abort that task.
            let _ = future.await;
            None
        }
    }
}

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
    /// Return the monotonically increasing authority generation inside the
    /// SDK authority boundary. Public callers receive only an opaque value.
    #[must_use]
    pub(crate) const fn get(self) -> u64 {
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
    window: SelectorBackendMutationWindow,
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

    /// Check the short durable-worker fence immediately before the backend
    /// performs terminal-stamp readback or its quiescence barrier.
    #[cfg(test)]
    pub(crate) fn is_current(&self) -> bool {
        self.window.is_current()
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
            window: self.window.into_receipt(),
        }
    }

    /// Complete this one request after the backend has proved exact terminal
    /// retirement, authoritative absence, and a completed RCU grace period.
    pub fn confirm_rcu_grace_period(self) -> GtpuSessionSelectorReuseReceipt {
        GtpuSessionSelectorReuseReceipt {
            retired: self.retired,
            desired: self.desired,
            evidence: crate::GtpuSessionSelectorReuseEvidence::RcuGracePeriodElapsed,
            window: self.window.into_receipt(),
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
    let Some(dataplane_generation) = admission.retired_dataplane_generation else {
        return false;
    };
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
    expected[192..200].copy_from_slice(&dataplane_generation.get().to_be_bytes());
    bool::from(expected.ct_eq(stamp))
}

/// Validate the fixed terminal-retired fields before accepting the one
/// backend-observed dynamic field. The resulting dataplane generation is
/// immediately protected in the `Retired` ledger row; subsequent reuse
/// verification compares the complete 208-byte value in constant time.
fn terminal_retired_stamp_generation(
    admission: &GtpuSessionSelectorAdmission,
    stamp: &[u8; GTPU_SESSION_SELECTOR_STAMP_VALUE_LEN],
) -> Option<NonZeroU64> {
    if admission.phase == SelectorAdmissionPhase::Retired {
        return verifies_terminal_retired_stamp(admission, stamp)
            .then_some(admission.retired_dataplane_generation)
            .flatten();
    }
    if admission.phase != SelectorAdmissionPhase::Retiring {
        return None;
    }
    let binding = admission.binding();
    let mut expected = [0_u8; GTPU_SESSION_SELECTOR_STAMP_VALUE_LEN];
    expected[0] = 1;
    expected[1] = 4;
    expected[2] = 2;
    expected[3] = 3;
    expected[8..16].copy_from_slice(&admission.terminal_generation().get().to_be_bytes());
    expected[16..32].copy_from_slice(&admission.terminal_operation_nonce());
    expected[32..48].copy_from_slice(&binding.backend_epoch());
    expected[64..96].copy_from_slice(&binding.storage_scope_commitment());
    expected[96..128].copy_from_slice(&admission.group_fingerprint());
    expected[128..160].copy_from_slice(&admission.selector_set_fingerprint());
    expected[160..192].copy_from_slice(&admission.desired_fingerprint());
    let generation = NonZeroU64::new(u64::from_be_bytes(stamp[192..200].try_into().ok()?))?;
    (bool::from(expected[..192].ct_eq(&stamp[..192]))
        && bool::from(expected[200..208].ct_eq(&stamp[200..208])))
    .then_some(generation)
}

/// Opaque receipt minted only by consuming one SDK-issued quiescence request.
#[must_use = "a reuse receipt must be consumed by reconciliation"]
pub struct GtpuSessionSelectorReuseReceipt {
    retired: GtpuSessionSelectorRetiredClaim,
    desired: GtpuSessionGroup,
    evidence: crate::GtpuSessionSelectorReuseEvidence,
    window: SelectorBackendMutationWindowReceipt,
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

#[repr(u8)]
#[derive(Clone, Copy)]
enum SelectorBackendRequestKind {
    Binding = 1,
    Provision = 2,
    Effect = 3,
    Readback = 4,
    Removal = 5,
    DecommissionInspect = 6,
    DecommissionCreate = 7,
    DecommissionReadback = 8,
    InstallingNoEffect = 9,
    RetiringNoEffect = 10,
}

#[derive(Clone, Copy)]
pub(crate) struct SelectorBackendReceiptCoordinate([u8; 32]);

impl SelectorBackendReceiptCoordinate {
    fn for_binding_inventory(
        binding: GtpuSessionSelectorBackendBinding,
        inventory: &SelectorOperationStampInventory,
        window: &SelectorBackendMutationWindow,
    ) -> Self {
        let mut digest = Sha256::new();
        digest.update(BACKEND_RECEIPT_DOMAIN);
        digest.update([SelectorBackendRequestKind::Binding as u8]);
        update_receipt_binding(&mut digest, binding);
        digest.update(inventory.summary());
        digest.update(window.coordinate());
        Self(digest.finalize().into())
    }

    fn for_binding_window(
        kind: SelectorBackendRequestKind,
        binding: GtpuSessionSelectorBackendBinding,
        window: &SelectorBackendMutationWindow,
    ) -> Self {
        let mut digest = Sha256::new();
        digest.update(BACKEND_RECEIPT_DOMAIN);
        digest.update([kind as u8]);
        update_receipt_binding(&mut digest, binding);
        digest.update(window.coordinate());
        Self(digest.finalize().into())
    }

    fn for_admission(
        kind: SelectorBackendRequestKind,
        admission: &GtpuSessionSelectorAdmission,
        window: &SelectorBackendMutationWindow,
    ) -> Self {
        let mut digest = Sha256::new();
        digest.update(BACKEND_RECEIPT_DOMAIN);
        digest.update([kind as u8]);
        update_receipt_binding(&mut digest, admission.binding());
        digest.update(admission.device_fingerprint);
        digest.update(admission.group_fingerprint);
        digest.update(admission.selector_set_fingerprint);
        digest.update(admission.desired_fingerprint);
        digest.update(admission.generation.get().to_be_bytes());
        digest.update(admission.operation_nonce);
        digest.update(admission.terminal_generation.get().to_be_bytes());
        digest.update(admission.terminal_operation_nonce);
        match admission.previous_terminal {
            Some(previous) => {
                digest.update([1]);
                digest.update(previous.generation.get().to_be_bytes());
                digest.update(previous.nonce);
            }
            None => digest.update([0; 25]),
        }
        digest.update([
            match admission.phase {
                SelectorAdmissionPhase::Installing => 1,
                SelectorAdmissionPhase::Active => 2,
                SelectorAdmissionPhase::Retiring => 3,
                SelectorAdmissionPhase::Retired => 4,
            },
            u8::from(admission.retired_reissue),
        ]);
        match admission.retired_dataplane_generation {
            Some(generation) => {
                digest.update([1]);
                digest.update(generation.get().to_be_bytes());
            }
            None => digest.update([0; 9]),
        }
        digest.update(window.coordinate());
        Self(digest.finalize().into())
    }

    fn for_decommission(
        kind: SelectorBackendRequestKind,
        binding: GtpuSessionSelectorBackendBinding,
        fence: Option<DecommissionFence>,
        window: &SelectorBackendMutationWindow,
    ) -> Self {
        let mut digest = Sha256::new();
        digest.update(BACKEND_RECEIPT_DOMAIN);
        digest.update([kind as u8]);
        update_receipt_binding(&mut digest, binding);
        match fence {
            Some(fence) => {
                digest.update([1]);
                digest.update(fence.marker_payload());
            }
            None => digest.update([0; DECOMMISSION_CAPSULE_LEN + 1]),
        }
        digest.update(window.coordinate());
        Self(digest.finalize().into())
    }

    fn matches(self, candidate: Self) -> bool {
        bool::from(self.0.ct_eq(&candidate.0))
    }
}

fn update_receipt_binding(digest: &mut Sha256, binding: GtpuSessionSelectorBackendBinding) {
    digest.update(binding.stable_device().to_bytes());
    digest.update(binding.pin_commitment());
    digest.update(binding.ledger_id());
    digest.update(binding.backend_epoch());
    digest.update(binding.storage_scope_commitment());
    digest.update(binding.selector_key_commitment());
}

/// One exact authority coordinate which an operation-stamp inventory entry
/// may name.  This stays crate-private so only the built-in adapter can turn
/// it into its byte-level map value codec.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct SelectorOperationStampCoordinate {
    generation: GtpuSessionSelectorAuthorityGeneration,
    nonce: [u8; 16],
}

impl SelectorOperationStampCoordinate {
    const fn from_authority(coordinate: SelectorAuthorityCoordinate) -> Self {
        Self {
            generation: coordinate.generation,
            nonce: coordinate.nonce,
        }
    }

    pub(crate) const fn generation(self) -> GtpuSessionSelectorAuthorityGeneration {
        self.generation
    }

    pub(crate) const fn nonce(self) -> [u8; 16] {
        self.nonce
    }
}

impl fmt::Debug for SelectorOperationStampCoordinate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SelectorOperationStampCoordinate(<redacted>)")
    }
}

/// The exact lifecycle alternatives for one permanent operation-stamp key.
///
/// Pending rows expose both their precommitted pending and terminal
/// coordinates.  A backend may accept only the alternatives documented by
/// that row; it must never silently discard a key, synthesize a coordinate,
/// or accept a different group under the same 16-byte map key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SelectorOperationStampLifecycleExpectation {
    Installing {
        backend_started: bool,
        pending: SelectorOperationStampCoordinate,
        terminal: SelectorOperationStampCoordinate,
    },
    Active {
        terminal: SelectorOperationStampCoordinate,
    },
    Retiring {
        backend_started: bool,
        pending: SelectorOperationStampCoordinate,
        terminal: SelectorOperationStampCoordinate,
        previous_terminal: SelectorOperationStampCoordinate,
    },
    Retired {
        terminal: SelectorOperationStampCoordinate,
        retired_dataplane_generation: NonZeroU64,
    },
    /// A poison row is terminal for coordinator mutation, but its inventory
    /// expectation retains every exact coordinate needed to classify the
    /// only states that can have resulted from the already-started operation.
    Poisoned {
        phase: u8,
        reason: u8,
        pending: SelectorOperationStampCoordinate,
        terminal: SelectorOperationStampCoordinate,
        previous_terminal: Option<SelectorOperationStampCoordinate>,
        retired_dataplane_generation: Option<NonZeroU64>,
    },
}

/// Lifecycle class for a protected operation-stamp expectation. This is
/// intentionally distinct from admission phases because a poisoned row is
/// terminal and cannot mint an admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SelectorOperationStampLifecycleKind {
    Installing,
    Active,
    Retiring,
    Retired,
    Poisoned,
}

impl fmt::Debug for SelectorOperationStampLifecycleExpectation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SelectorOperationStampLifecycleExpectation(<redacted>)")
    }
}

impl SelectorOperationStampLifecycleExpectation {
    /// Stable discriminant for the protected lifecycle expectation. Built-in
    /// adapters use this with the remaining exact-coordinate accessors while
    /// retaining ownership of the eBPF stamp byte codec.
    pub(crate) const fn kind(self) -> SelectorOperationStampLifecycleKind {
        match self {
            Self::Installing { .. } => SelectorOperationStampLifecycleKind::Installing,
            Self::Active { .. } => SelectorOperationStampLifecycleKind::Active,
            Self::Retiring { .. } => SelectorOperationStampLifecycleKind::Retiring,
            Self::Retired { .. } => SelectorOperationStampLifecycleKind::Retired,
            Self::Poisoned { .. } => SelectorOperationStampLifecycleKind::Poisoned,
        }
    }

    pub(crate) const fn backend_started(self) -> Option<bool> {
        match self {
            Self::Installing {
                backend_started, ..
            }
            | Self::Retiring {
                backend_started, ..
            } => Some(backend_started),
            Self::Active { .. } | Self::Retired { .. } | Self::Poisoned { .. } => None,
        }
    }

    pub(crate) const fn pending(self) -> Option<SelectorOperationStampCoordinate> {
        match self {
            Self::Installing { pending, .. }
            | Self::Retiring { pending, .. }
            | Self::Poisoned { pending, .. } => Some(pending),
            Self::Active { .. } | Self::Retired { .. } => None,
        }
    }

    pub(crate) const fn terminal(self) -> SelectorOperationStampCoordinate {
        match self {
            Self::Installing { terminal, .. }
            | Self::Active { terminal }
            | Self::Retiring { terminal, .. }
            | Self::Retired { terminal, .. }
            | Self::Poisoned { terminal, .. } => terminal,
        }
    }

    pub(crate) const fn previous_terminal(self) -> Option<SelectorOperationStampCoordinate> {
        match self {
            Self::Retiring {
                previous_terminal, ..
            } => Some(previous_terminal),
            Self::Poisoned {
                previous_terminal, ..
            } => previous_terminal,
            Self::Installing { .. } | Self::Active { .. } | Self::Retired { .. } => None,
        }
    }

    pub(crate) const fn retired_dataplane_generation(self) -> Option<NonZeroU64> {
        match self {
            Self::Retired {
                retired_dataplane_generation,
                ..
            }
            | Self::Poisoned {
                retired_dataplane_generation: Some(retired_dataplane_generation),
                ..
            } => Some(retired_dataplane_generation),
            Self::Installing { .. }
            | Self::Active { .. }
            | Self::Retiring { .. }
            | Self::Poisoned {
                retired_dataplane_generation: None,
                ..
            } => None,
        }
    }

    pub(crate) const fn poison_reason(self) -> Option<u8> {
        match self {
            Self::Poisoned { reason, .. } => Some(reason),
            Self::Installing { .. }
            | Self::Active { .. }
            | Self::Retiring { .. }
            | Self::Retired { .. } => None,
        }
    }

    pub(crate) const fn poison_phase(self) -> Option<u8> {
        match self {
            Self::Poisoned { phase, .. } => Some(phase),
            Self::Installing { .. }
            | Self::Active { .. }
            | Self::Retiring { .. }
            | Self::Retired { .. } => None,
        }
    }
}

/// Opaque semantic expectation for exactly one existing operation-stamp key.
/// The backend owns the stamp byte codec; this value supplies the protected,
/// canonical fields it must encode and compare exactly.
#[derive(Clone)]
pub(crate) struct SelectorOperationStampInventoryExpectation {
    group: GtpuSessionGroup,
    device_fingerprint: [u8; 32],
    group_fingerprint: [u8; 32],
    selector_set_fingerprint: [u8; 32],
    desired_fingerprint: [u8; 32],
    lifecycle: SelectorOperationStampLifecycleExpectation,
}

impl SelectorOperationStampInventoryExpectation {
    pub(crate) const fn group(&self) -> &GtpuSessionGroup {
        &self.group
    }

    pub(crate) const fn device_fingerprint(&self) -> [u8; 32] {
        self.device_fingerprint
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

    pub(crate) const fn lifecycle(&self) -> SelectorOperationStampLifecycleExpectation {
        self.lifecycle
    }
}

impl fmt::Debug for SelectorOperationStampInventoryExpectation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SelectorOperationStampInventoryExpectation(<redacted>)")
    }
}

/// Sorted, bounded complete inventory of permanent operation-stamp keys.
/// It is reconstructed exclusively from the protected ledger for every
/// production binding/open check.
#[derive(Clone)]
pub(crate) struct SelectorOperationStampInventory {
    expectations: Vec<SelectorOperationStampInventoryExpectation>,
    summary: [u8; 32],
}

impl SelectorOperationStampInventory {
    pub(crate) fn expectations(&self) -> &[SelectorOperationStampInventoryExpectation] {
        &self.expectations
    }

    const fn summary(&self) -> [u8; 32] {
        self.summary
    }
}

impl fmt::Debug for SelectorOperationStampInventory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SelectorOperationStampInventory(<redacted>)")
    }
}

/// A non-cloneable, short backend mutation authorization. It is minted only
/// after a successful durable lease renewal and carries both monotonic and
/// wall-clock deadlines; a clock ambiguity is always stale.
#[must_use = "a backend mutation window must be consumed by its authorized request"]
pub(crate) struct SelectorBackendMutationWindow {
    coordinate: [u8; 32],
    monotonic_deadline: Instant,
    wall_deadline: SystemTime,
}

impl SelectorBackendMutationWindow {
    fn mint(lease_ttl: Duration) -> Result<Self, GtpuSessionSelectorNamespaceError> {
        let duration = SELECTOR_NAMESPACE_MAX_EFFECT_DURATION.min(lease_ttl / 2);
        if duration.is_zero() {
            return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
        }
        let monotonic_deadline = Instant::now()
            .checked_add(duration)
            .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
        let wall_deadline = SystemTime::now()
            .checked_add(duration)
            .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
        let nonce = random_nonzero_nonce()?;
        let mut digest = Sha256::new();
        digest.update(BACKEND_MUTATION_WINDOW_DOMAIN);
        digest.update(nonce);
        digest.update(duration.as_nanos().to_be_bytes());
        Ok(Self {
            coordinate: digest.finalize().into(),
            monotonic_deadline,
            wall_deadline,
        })
    }

    /// Built-in adapters call this immediately before every host-lock
    /// guarded mutation/readback. It intentionally has no public equivalent.
    pub(crate) fn is_current(&self) -> bool {
        Instant::now() < self.monotonic_deadline
            && SystemTime::now()
                .duration_since(self.wall_deadline)
                .is_err()
    }

    pub(crate) fn into_receipt(self) -> SelectorBackendMutationWindowReceipt {
        SelectorBackendMutationWindowReceipt {
            monotonic_deadline: self.monotonic_deadline,
            wall_deadline: self.wall_deadline,
        }
    }

    const fn coordinate(&self) -> [u8; 32] {
        self.coordinate
    }
}

impl fmt::Debug for SelectorBackendMutationWindow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SelectorBackendMutationWindow(<redacted>)")
    }
}

pub(crate) struct SelectorBackendMutationWindowReceipt {
    monotonic_deadline: Instant,
    wall_deadline: SystemTime,
}

impl SelectorBackendMutationWindowReceipt {
    pub(crate) fn is_current(&self) -> bool {
        Instant::now() < self.monotonic_deadline
            && SystemTime::now()
                .duration_since(self.wall_deadline)
                .is_err()
    }
}

impl fmt::Debug for SelectorBackendMutationWindowReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SelectorBackendMutationWindowReceipt(<redacted>)")
    }
}

/// An opaque lease over one immutable selector namespace binding. It can be
/// consumed only by a backend to confirm the exact binding it acquired.
#[must_use = "a selector binding lease must be consumed by a backend receipt"]
pub struct GtpuSessionSelectorBindingLease {
    binding: GtpuSessionSelectorBackendBinding,
    inventory: SelectorOperationStampInventory,
    window: SelectorBackendMutationWindow,
}

impl GtpuSessionSelectorBindingLease {
    /// Immutable backend namespace binding being leased.
    #[must_use]
    pub const fn binding(&self) -> GtpuSessionSelectorBackendBinding {
        self.binding
    }

    /// Complete protected-ledger expectation set which the built-in adapter
    /// must compare with its complete stamp-map inventory under its host
    /// lock. The list is sorted by the canonical 16-byte group ID key.
    pub(crate) const fn operation_stamp_inventory(&self) -> &SelectorOperationStampInventory {
        &self.inventory
    }

    /// Check the short durable-worker fence immediately before inspecting
    /// the backend inventory. A false result is not retryable with this
    /// request; the coordinator must mint a fresh window after renewal.
    pub(crate) fn is_current(&self) -> bool {
        self.window.is_current()
    }

    fn receipt_coordinate(&self) -> SelectorBackendReceiptCoordinate {
        SelectorBackendReceiptCoordinate::for_binding_inventory(
            self.binding,
            &self.inventory,
            &self.window,
        )
    }

    /// Mint a receipt only after the backend has acquired the exact binding.
    pub fn confirm(self) -> GtpuSessionSelectorBackendReceipt {
        let coordinate = self.receipt_coordinate();
        GtpuSessionSelectorBackendReceipt::binding_confirmed(coordinate, self.window.into_receipt())
    }
}

/// Opaque stopped-installation request for the exact immutable binding.
#[must_use = "a selector provisioning request must be consumed by a backend receipt"]
pub struct GtpuSessionSelectorProvisionRequest {
    binding: GtpuSessionSelectorBackendBinding,
    window: SelectorBackendMutationWindow,
}

impl GtpuSessionSelectorProvisionRequest {
    /// Immutable backend namespace binding being provisioned.
    #[must_use]
    pub const fn binding(&self) -> GtpuSessionSelectorBackendBinding {
        self.binding
    }

    pub(crate) fn is_current(&self) -> bool {
        self.window.is_current()
    }

    fn receipt_coordinate(&self) -> SelectorBackendReceiptCoordinate {
        SelectorBackendReceiptCoordinate::for_binding_window(
            SelectorBackendRequestKind::Provision,
            self.binding,
            &self.window,
        )
    }

    /// Mint a receipt only after complete empty-inventory proof, marker write,
    /// and exact marker readback under the backend's exclusive effect lease.
    pub fn confirm(self) -> GtpuSessionSelectorBackendReceipt {
        let coordinate = self.receipt_coordinate();
        GtpuSessionSelectorBackendReceipt::provisioned(coordinate, self.window.into_receipt())
    }
}

/// SDK-owned recovery inspection request for one exact unstarted Installing
/// coordinate.
///
/// The backend consumes this affine capability while holding its host-global
/// inventory lock. It must check [`Self::is_current`] immediately before and
/// after proving the exact no-effect fact, then settle the request with
/// [`Self::confirm`]. This prevents a structural or mock observation obtained
/// before the worker fence expired from authorizing a later durable handoff.
#[must_use = "a negative recovery inspection must be consumed into a current receipt"]
pub struct GtpuSessionSelectorInstallingNoEffectRequest {
    expected: GtpuSessionGroup,
    admission: GtpuSessionSelectorAdmission,
    window: SelectorBackendMutationWindow,
}

impl GtpuSessionSelectorInstallingNoEffectRequest {
    /// Exact Installing graph whose no-effect state must be proven.
    #[must_use]
    pub const fn expected_group(&self) -> &GtpuSessionGroup {
        &self.expected
    }

    /// Exact durable Installing coordinate being recovered.
    #[must_use]
    pub const fn admission(&self) -> &GtpuSessionSelectorAdmission {
        &self.admission
    }

    /// Check the affine worker fence while the backend retains its inventory
    /// lock. This is crate-visible for the built-in eBPF adapter only.
    pub(crate) fn is_current(&self) -> bool {
        self.window.is_current()
    }

    fn receipt_coordinate(&self) -> SelectorBackendReceiptCoordinate {
        SelectorBackendReceiptCoordinate::for_admission(
            SelectorBackendRequestKind::InstallingNoEffect,
            &self.admission,
            &self.window,
        )
    }

    /// Consume this request into its coordinate-bound no-effect receipt.
    ///
    /// The built-in adapter may call this only after its exact negative proof
    /// and a second currentness check under the same host lock.
    pub(crate) fn confirm(self) -> Option<GtpuSessionSelectorBackendReceipt> {
        if !self.is_current() {
            return None;
        }
        let coordinate = self.receipt_coordinate();
        Some(GtpuSessionSelectorBackendReceipt::installing_no_effect(
            coordinate,
            self.window.into_receipt(),
        ))
    }
}

/// SDK-owned recovery inspection request for one exact unstarted Retiring
/// coordinate.
///
/// The backend consumes this affine capability under its host-global inventory
/// lock only after proving the exact previous Active graph and the absence of
/// every removal artifact. See the Installing counterpart for the required
/// pre- and post-inspection currentness checks.
#[must_use = "a negative recovery inspection must be consumed into a current receipt"]
pub struct GtpuSessionSelectorRetiringNoEffectRequest {
    expected: GtpuSessionGroup,
    admission: GtpuSessionSelectorAdmission,
    window: SelectorBackendMutationWindow,
}

impl GtpuSessionSelectorRetiringNoEffectRequest {
    /// Exact previous Active graph whose no-removal state must be proven.
    #[must_use]
    pub const fn expected_group(&self) -> &GtpuSessionGroup {
        &self.expected
    }

    /// Exact durable Retiring coordinate being recovered.
    #[must_use]
    pub const fn admission(&self) -> &GtpuSessionSelectorAdmission {
        &self.admission
    }

    /// Check the affine worker fence while the backend retains its inventory
    /// lock. This is crate-visible for the built-in eBPF adapter only.
    pub(crate) fn is_current(&self) -> bool {
        self.window.is_current()
    }

    fn receipt_coordinate(&self) -> SelectorBackendReceiptCoordinate {
        SelectorBackendReceiptCoordinate::for_admission(
            SelectorBackendRequestKind::RetiringNoEffect,
            &self.admission,
            &self.window,
        )
    }

    /// Consume this request into its coordinate-bound no-effect receipt.
    ///
    /// The built-in adapter may call this only after its exact negative proof
    /// and a second currentness check under the same host lock.
    pub(crate) fn confirm(self) -> Option<GtpuSessionSelectorBackendReceipt> {
        if !self.is_current() {
            return None;
        }
        let coordinate = self.receipt_coordinate();
        Some(GtpuSessionSelectorBackendReceipt::retiring_no_effect(
            coordinate,
            self.window.into_receipt(),
        ))
    }
}

/// Opaque install/reconcile request issued from one exact Installing
/// coordinate. Backends can inspect its complete semantic graph and binding,
/// but cannot construct an equivalent request or mint another coordinate.
#[must_use = "a selector effect request must be consumed by a backend receipt"]
pub struct GtpuSessionSelectorEffectRequest {
    request: GtpuSessionGroupReconcileRequest,
    window: SelectorBackendMutationWindow,
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

    #[cfg(test)]
    pub(crate) fn is_current(&self) -> bool {
        self.window.is_current()
    }

    fn receipt_coordinate(&self) -> SelectorBackendReceiptCoordinate {
        SelectorBackendReceiptCoordinate::for_admission(
            SelectorBackendRequestKind::Effect,
            self.request.selector_admission(),
            &self.window,
        )
    }

    /// Consume the exact request into the corresponding classified receipt.
    pub fn complete(
        self,
        outcome: GtpuSessionGroupReconcileOutcome,
    ) -> GtpuSessionSelectorBackendReceipt {
        let coordinate = self.receipt_coordinate();
        GtpuSessionSelectorBackendReceipt::effect(coordinate, outcome, self.window.into_receipt())
    }

    pub(crate) fn into_inner(
        self,
    ) -> (
        GtpuSessionGroupReconcileRequest,
        SelectorBackendReceiptCoordinate,
        SelectorBackendMutationWindow,
    ) {
        let coordinate = self.receipt_coordinate();
        (self.request, coordinate, self.window)
    }
}

/// Opaque authorized readback request for one lifecycle coordinate.
#[must_use = "an authorized readback request must be consumed by a backend receipt"]
pub struct GtpuSessionSelectorReadbackRequest {
    expected: GtpuSessionGroup,
    admission: GtpuSessionSelectorAdmission,
    window: SelectorBackendMutationWindow,
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

    pub(crate) const fn admission(&self) -> &GtpuSessionSelectorAdmission {
        &self.admission
    }

    pub(crate) fn is_current(&self) -> bool {
        self.window.is_current()
    }

    fn receipt_coordinate(&self) -> SelectorBackendReceiptCoordinate {
        SelectorBackendReceiptCoordinate::for_admission(
            SelectorBackendRequestKind::Readback,
            &self.admission,
            &self.window,
        )
    }

    /// Consume the request into the backend's exact classified readback.
    pub fn complete(
        self,
        readback: crate::GtpuSessionGroupReadback,
    ) -> GtpuSessionSelectorBackendReceipt {
        let coordinate = self.receipt_coordinate();
        GtpuSessionSelectorBackendReceipt::readback(
            coordinate,
            readback,
            self.window.into_receipt(),
        )
    }

    /// Complete an exact terminal-retired absence readback with the full
    /// stamp just read from the backend's authority map. This API accepts no
    /// caller-selected generation scalar.
    #[must_use]
    pub fn complete_terminal_retired(
        self,
        readback: crate::GtpuSessionGroupReadback,
        stamp: &[u8; GTPU_SESSION_SELECTOR_STAMP_VALUE_LEN],
    ) -> Option<GtpuSessionSelectorBackendReceipt> {
        if !matches!(readback, crate::GtpuSessionGroupReadback::Absent) {
            return None;
        }
        let coordinate = self.receipt_coordinate();
        terminal_retired_stamp_generation(&self.admission, stamp).map(|generation| {
            GtpuSessionSelectorBackendReceipt::readback_terminal_retired(
                coordinate,
                readback,
                generation,
                self.window.into_receipt(),
            )
        })
    }
}

/// Opaque authorized removal request for one exact Retiring coordinate.
#[must_use = "a selector removal request must be consumed by a backend receipt"]
pub struct GtpuSessionSelectorRemovalRequest {
    expected: GtpuSessionGroup,
    admission: GtpuSessionSelectorAdmission,
    window: SelectorBackendMutationWindow,
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

    pub(crate) const fn admission(&self) -> &GtpuSessionSelectorAdmission {
        &self.admission
    }

    pub(crate) fn is_current(&self) -> bool {
        self.window.is_current()
    }

    fn receipt_coordinate(&self) -> SelectorBackendReceiptCoordinate {
        SelectorBackendReceiptCoordinate::for_admission(
            SelectorBackendRequestKind::Removal,
            &self.admission,
            &self.window,
        )
    }

    /// Consume the request into the backend's classified removal receipt.
    pub fn complete(
        self,
        outcome: GtpuSessionGroupRemovalOutcome,
    ) -> GtpuSessionSelectorBackendReceipt {
        let coordinate = self.receipt_coordinate();
        GtpuSessionSelectorBackendReceipt::removal(coordinate, outcome, self.window.into_receipt())
    }

    /// Complete removal only after an authorized backend has written and
    /// exactly read its terminal-retired stamp. The protected receipt retains
    /// the observed nonzero dataplane generation; it is never caller input.
    #[must_use]
    pub fn complete_terminal_retired(
        self,
        outcome: GtpuSessionGroupRemovalOutcome,
        stamp: &[u8; GTPU_SESSION_SELECTOR_STAMP_VALUE_LEN],
    ) -> Option<GtpuSessionSelectorBackendReceipt> {
        if !matches!(
            outcome,
            GtpuSessionGroupRemovalOutcome::Removed | GtpuSessionGroupRemovalOutcome::AlreadyAbsent
        ) {
            return None;
        }
        let coordinate = self.receipt_coordinate();
        terminal_retired_stamp_generation(&self.admission, stamp).map(|generation| {
            GtpuSessionSelectorBackendReceipt::removal_terminal_retired(
                coordinate,
                outcome,
                generation,
                self.window.into_receipt(),
            )
        })
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
    window: SelectorBackendMutationWindow,
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
    pub fn expected_terminal_marker_payload(&self) -> Option<[u8; DECOMMISSION_CAPSULE_LEN]> {
        self.expected_fence.map(DecommissionFence::marker_payload)
    }

    pub(crate) fn is_current(&self) -> bool {
        self.window.is_current()
    }

    fn receipt_coordinate(&self) -> SelectorBackendReceiptCoordinate {
        SelectorBackendReceiptCoordinate::for_decommission(
            SelectorBackendRequestKind::DecommissionInspect,
            self.binding,
            self.expected_fence,
            &self.window,
        )
    }

    /// Consume this request after proving no terminal capsule exists.
    pub fn confirm_absent(self) -> GtpuSessionSelectorBackendReceipt {
        let coordinate = self.receipt_coordinate();
        GtpuSessionSelectorBackendReceipt::decommission_fence_absent(
            coordinate,
            self.window.into_receipt(),
        )
    }

    /// Consume this request after proving the persisted terminal capsule is
    /// byte-for-byte exact.
    pub fn confirm_exact(self) -> GtpuSessionSelectorBackendReceipt {
        let coordinate = self.receipt_coordinate();
        GtpuSessionSelectorBackendReceipt::decommission_fence_exact(
            coordinate,
            self.window.into_receipt(),
        )
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
    window: SelectorBackendMutationWindow,
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
        bool::from(self.fence.predecessor_commitment.ct_eq(&candidate))
    }

    /// Return the versioned, authenticated terminal marker payload that an
    /// external backend persists. It carries the exact precommitted terminal
    /// generation and nonce as well as their binding/keyed authentication;
    /// no selector bytes or selector secret are exposed.
    #[must_use]
    pub fn terminal_marker_payload(&self) -> [u8; DECOMMISSION_CAPSULE_LEN] {
        self.fence.marker_payload()
    }

    /// Validate a backend-read terminal marker payload for this exact opaque
    /// decommission request.
    #[must_use]
    pub fn verifies_terminal_marker_payload(
        &self,
        payload: &[u8; DECOMMISSION_CAPSULE_LEN],
    ) -> bool {
        bool::from(self.terminal_marker_payload().ct_eq(payload))
    }

    pub(crate) fn is_current(&self) -> bool {
        self.window.is_current()
    }

    fn receipt_coordinate(&self) -> SelectorBackendReceiptCoordinate {
        SelectorBackendReceiptCoordinate::for_decommission(
            SelectorBackendRequestKind::DecommissionCreate,
            self.binding,
            Some(self.fence),
            &self.window,
        )
    }

    /// Consume the request only after an exact terminal capsule containing the
    /// committed coordinate has been durably created and read back.
    pub fn confirm(self) -> GtpuSessionSelectorBackendReceipt {
        let coordinate = self.receipt_coordinate();
        GtpuSessionSelectorBackendReceipt::decommission_fence_exact(
            coordinate,
            self.window.into_receipt(),
        )
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
    window: SelectorBackendMutationWindow,
}

impl GtpuSessionSelectorDecommissionReadbackRequest {
    /// Immutable namespace binding whose terminal capsule is read back.
    #[must_use]
    pub const fn binding(&self) -> GtpuSessionSelectorBackendBinding {
        self.binding
    }

    /// Expected versioned terminal capsule bytes.
    #[must_use]
    pub fn terminal_marker_payload(&self) -> [u8; DECOMMISSION_CAPSULE_LEN] {
        self.fence.marker_payload()
    }

    /// Validate a backend-read terminal capsule for this exact request.
    #[must_use]
    pub fn verifies_terminal_marker_payload(
        &self,
        payload: &[u8; DECOMMISSION_CAPSULE_LEN],
    ) -> bool {
        bool::from(self.terminal_marker_payload().ct_eq(payload))
    }

    pub(crate) fn is_current(&self) -> bool {
        self.window.is_current()
    }

    fn receipt_coordinate(&self) -> SelectorBackendReceiptCoordinate {
        SelectorBackendReceiptCoordinate::for_decommission(
            SelectorBackendRequestKind::DecommissionReadback,
            self.binding,
            Some(self.fence),
            &self.window,
        )
    }

    /// Consume the request after an exact durable capsule readback.
    pub fn confirm_exact(self) -> GtpuSessionSelectorBackendReceipt {
        let coordinate = self.receipt_coordinate();
        GtpuSessionSelectorBackendReceipt::decommission_fence_exact(
            coordinate,
            self.window.into_receipt(),
        )
    }
}

/// SDK-minted result of consuming one opaque selector backend request.
///
/// The classification is private: only consuming the matching affine request
/// can mint a receipt, and the SDK accepts it only at that request's exact
/// private coordinate. This rejects stale, replayed, cross-request, and
/// cross-namespace receipts from ordinary callers. The deliberately selected
/// backend adapter is trusted to perform the asserted real effect and exact
/// readback; this coordinate is not cryptographic attestation against malicious
/// code inside that trusted adapter.
#[must_use = "selector backend receipts must be verified by the SDK authority"]
pub struct GtpuSessionSelectorBackendReceipt {
    coordinate: SelectorBackendReceiptCoordinate,
    kind: SelectorBackendReceiptKind,
    window: SelectorBackendMutationWindowReceipt,
}

enum SelectorBackendReceiptKind {
    BindingConfirmed,
    Provisioned,
    InstallingNoEffect,
    RetiringNoEffect,
    DecommissionFenceAbsent,
    DecommissionFenceExact,
    Effect(GtpuSessionGroupReconcileOutcome),
    Readback {
        readback: crate::GtpuSessionGroupReadback,
        terminal_retired_dataplane_generation: Option<NonZeroU64>,
    },
    Removal {
        outcome: GtpuSessionGroupRemovalOutcome,
        terminal_retired_dataplane_generation: Option<NonZeroU64>,
    },
}

impl GtpuSessionSelectorBackendReceipt {
    fn binding_confirmed(
        coordinate: SelectorBackendReceiptCoordinate,
        window: SelectorBackendMutationWindowReceipt,
    ) -> Self {
        Self {
            coordinate,
            kind: SelectorBackendReceiptKind::BindingConfirmed,
            window,
        }
    }

    fn provisioned(
        coordinate: SelectorBackendReceiptCoordinate,
        window: SelectorBackendMutationWindowReceipt,
    ) -> Self {
        Self {
            coordinate,
            kind: SelectorBackendReceiptKind::Provisioned,
            window,
        }
    }

    fn installing_no_effect(
        coordinate: SelectorBackendReceiptCoordinate,
        window: SelectorBackendMutationWindowReceipt,
    ) -> Self {
        Self {
            coordinate,
            kind: SelectorBackendReceiptKind::InstallingNoEffect,
            window,
        }
    }

    fn retiring_no_effect(
        coordinate: SelectorBackendReceiptCoordinate,
        window: SelectorBackendMutationWindowReceipt,
    ) -> Self {
        Self {
            coordinate,
            kind: SelectorBackendReceiptKind::RetiringNoEffect,
            window,
        }
    }

    fn decommission_fence_absent(
        coordinate: SelectorBackendReceiptCoordinate,
        window: SelectorBackendMutationWindowReceipt,
    ) -> Self {
        Self {
            coordinate,
            kind: SelectorBackendReceiptKind::DecommissionFenceAbsent,
            window,
        }
    }

    fn decommission_fence_exact(
        coordinate: SelectorBackendReceiptCoordinate,
        window: SelectorBackendMutationWindowReceipt,
    ) -> Self {
        Self {
            coordinate,
            kind: SelectorBackendReceiptKind::DecommissionFenceExact,
            window,
        }
    }

    pub(crate) fn effect(
        coordinate: SelectorBackendReceiptCoordinate,
        outcome: GtpuSessionGroupReconcileOutcome,
        window: SelectorBackendMutationWindowReceipt,
    ) -> Self {
        Self {
            coordinate,
            kind: SelectorBackendReceiptKind::Effect(outcome),
            window,
        }
    }

    fn readback(
        coordinate: SelectorBackendReceiptCoordinate,
        readback: crate::GtpuSessionGroupReadback,
        window: SelectorBackendMutationWindowReceipt,
    ) -> Self {
        Self {
            coordinate,
            kind: SelectorBackendReceiptKind::Readback {
                readback,
                terminal_retired_dataplane_generation: None,
            },
            window,
        }
    }

    fn readback_terminal_retired(
        coordinate: SelectorBackendReceiptCoordinate,
        readback: crate::GtpuSessionGroupReadback,
        terminal_retired_dataplane_generation: NonZeroU64,
        window: SelectorBackendMutationWindowReceipt,
    ) -> Self {
        Self {
            coordinate,
            kind: SelectorBackendReceiptKind::Readback {
                readback,
                terminal_retired_dataplane_generation: Some(terminal_retired_dataplane_generation),
            },
            window,
        }
    }

    fn removal(
        coordinate: SelectorBackendReceiptCoordinate,
        outcome: GtpuSessionGroupRemovalOutcome,
        window: SelectorBackendMutationWindowReceipt,
    ) -> Self {
        Self {
            coordinate,
            kind: SelectorBackendReceiptKind::Removal {
                outcome,
                terminal_retired_dataplane_generation: None,
            },
            window,
        }
    }

    fn removal_terminal_retired(
        coordinate: SelectorBackendReceiptCoordinate,
        outcome: GtpuSessionGroupRemovalOutcome,
        terminal_retired_dataplane_generation: NonZeroU64,
        window: SelectorBackendMutationWindowReceipt,
    ) -> Self {
        Self {
            coordinate,
            kind: SelectorBackendReceiptKind::Removal {
                outcome,
                terminal_retired_dataplane_generation: Some(terminal_retired_dataplane_generation),
            },
            window,
        }
    }

    fn confirms_binding(&self, expected: SelectorBackendReceiptCoordinate) -> bool {
        self.window.is_current()
            && self.coordinate.matches(expected)
            && matches!(self.kind, SelectorBackendReceiptKind::BindingConfirmed)
    }

    fn confirms_provisioning(&self, expected: SelectorBackendReceiptCoordinate) -> bool {
        self.window.is_current()
            && self.coordinate.matches(expected)
            && matches!(self.kind, SelectorBackendReceiptKind::Provisioned)
    }

    fn confirms_installing_no_effect(&self, expected: SelectorBackendReceiptCoordinate) -> bool {
        self.window.is_current()
            && self.coordinate.matches(expected)
            && matches!(self.kind, SelectorBackendReceiptKind::InstallingNoEffect)
    }

    fn confirms_retiring_no_effect(&self, expected: SelectorBackendReceiptCoordinate) -> bool {
        self.window.is_current()
            && self.coordinate.matches(expected)
            && matches!(self.kind, SelectorBackendReceiptKind::RetiringNoEffect)
    }

    fn confirms_decommission_fence_absent(
        &self,
        expected: SelectorBackendReceiptCoordinate,
    ) -> bool {
        self.window.is_current()
            && self.coordinate.matches(expected)
            && matches!(
                self.kind,
                SelectorBackendReceiptKind::DecommissionFenceAbsent
            )
    }

    fn confirms_decommission_fence_exact(
        &self,
        expected: SelectorBackendReceiptCoordinate,
    ) -> bool {
        self.window.is_current()
            && self.coordinate.matches(expected)
            && matches!(
                self.kind,
                SelectorBackendReceiptKind::DecommissionFenceExact
            )
    }

    fn into_effect(
        self,
        expected: SelectorBackendReceiptCoordinate,
    ) -> Option<GtpuSessionGroupReconcileOutcome> {
        if !self.window.is_current() || !self.coordinate.matches(expected) {
            return None;
        }
        match self.kind {
            SelectorBackendReceiptKind::Effect(outcome) => Some(outcome),
            _ => None,
        }
    }

    fn into_readback(
        self,
        expected: SelectorBackendReceiptCoordinate,
    ) -> Option<AuthorizedSelectorReadback> {
        if !self.window.is_current() || !self.coordinate.matches(expected) {
            return None;
        }
        match self.kind {
            SelectorBackendReceiptKind::Readback {
                readback,
                terminal_retired_dataplane_generation,
            } => Some(AuthorizedSelectorReadback {
                readback,
                terminal_retired_dataplane_generation,
            }),
            _ => None,
        }
    }

    fn into_removal(
        self,
        expected: SelectorBackendReceiptCoordinate,
    ) -> Option<AuthorizedSelectorRemoval> {
        if !self.window.is_current() || !self.coordinate.matches(expected) {
            return None;
        }
        match self.kind {
            SelectorBackendReceiptKind::Removal {
                outcome,
                terminal_retired_dataplane_generation,
            } => Some(AuthorizedSelectorRemoval {
                outcome,
                terminal_retired_dataplane_generation,
            }),
            _ => None,
        }
    }
}

struct AuthorizedSelectorReadback {
    readback: crate::GtpuSessionGroupReadback,
    terminal_retired_dataplane_generation: Option<NonZeroU64>,
}

struct AuthorizedSelectorRemoval {
    outcome: GtpuSessionGroupRemovalOutcome,
    terminal_retired_dataplane_generation: Option<NonZeroU64>,
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
static SELECTOR_NAMESPACE_WORKERS: OnceLock<
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

/// One process-local worker may hold a durable lease for a selector storage
/// scope at a time. `SessionStore` intentionally treats a same-owner acquire
/// as replica recovery and replaces the prior credential; without this gate,
/// two SDK workers in one replica could therefore invalidate each other while
/// an already-minted backend window remained time-current. The bounded
/// supervisor semaphores above retain at most 64 queued operations per scope,
/// while this separate gate owns the complete acquire-to-release lifetime.
fn selector_namespace_worker(storage_scope_commitment: [u8; 32]) -> Arc<tokio::sync::Semaphore> {
    let registry = SELECTOR_NAMESPACE_WORKERS.get_or_init(|| Mutex::new(BTreeMap::new()));
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
    let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
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
    let namespace_worker = selector_namespace_worker(storage_scope_commitment);
    let closed_error = runtime_error.clone();
    // Reserve both bounded supervisor slots before either durable admission or
    // task creation.  Spawning first would make an unbounded number of tasks
    // wait behind the semaphores and would let a caller mistake queued work
    // for a durably owned operation.
    let process_permit = match process_permits.try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            let _ = sender.send(Err(runtime_error));
            return GtpuSessionSelectorOperation {
                receiver,
                closed_error,
            };
        }
    };
    let namespace_permit = match namespace_permits.try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            drop(process_permit);
            let _ = sender.send(Err(runtime_error));
            return GtpuSessionSelectorOperation {
                receiver,
                closed_error,
            };
        }
    };
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            handle.spawn(async move {
                // The pre-reserved permits stay owned by this detached worker
                // until its terminal result is sent. Dropping the caller's
                // observer cannot release either slot or abort the effect.
                let _process_permit = process_permit;
                let _namespace_permit = namespace_permit;
                let _worker_permit = match namespace_worker.acquire_owned().await {
                    Ok(permit) => permit,
                    Err(_) => {
                        let _ = sender.send(Err(runtime_error));
                        return;
                    }
                };
                let result = worker.await;
                let _ = sender.send(result);
            });
        }
        Err(_) => {
            drop(process_permit);
            drop(namespace_permit);
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
///
/// ```compile_fail
/// use opc_gtpu_dataplane::{
///     GtpuDataplaneBackend, GtpuSessionGroup, GtpuSessionSelectorAdmission,
/// };
///
/// async fn cannot_reuse_across_authorized_calls(
///     backend: impl GtpuDataplaneBackend,
///     group: GtpuSessionGroup,
///     admission: GtpuSessionSelectorAdmission,
/// ) {
///     let _ = backend
///         .read_pdp_context_group_authorized(&group, admission)
///         .await;
///     let _ = backend
///         .remove_pdp_context_group_authorized(group, admission)
///         .await;
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
    // Set only from a trusted terminal-retired backend stamp receipt and
    // retained in the protected `Retired` ledger row.
    retired_dataplane_generation: Option<NonZeroU64>,
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

/// Persisted, authenticated terminal coordinate for one namespace-wide
/// decommission. The capsule is deliberately retained in the protected
/// ledger: a restart must not recreate an ostensibly equivalent marker.
#[derive(Clone, Copy, PartialEq, Eq)]
struct DecommissionFence {
    predecessor_commitment: [u8; 32],
    decommissioning: SelectorAuthorityCoordinate,
    decommissioned: SelectorAuthorityCoordinate,
    capsule: [u8; DECOMMISSION_CAPSULE_LEN],
}

impl DecommissionFence {
    const fn marker_payload(self) -> [u8; DECOMMISSION_CAPSULE_LEN] {
        self.capsule
    }
}

impl GtpuSessionSelectorAdmission {
    /// Return the SDK-minted authority generation inside the trusted backend
    /// boundary. Raw lifecycle coordinates are not a public diagnostic API.
    #[must_use]
    pub(crate) const fn generation(&self) -> GtpuSessionSelectorAuthorityGeneration {
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

    pub(crate) fn authorizes_install_effect(&self) -> bool {
        matches!(self.phase, SelectorAdmissionPhase::Installing)
            && self.previous_terminal.is_none()
            && self.operation_nonce != self.terminal_operation_nonce
            && self.terminal_generation.get() > self.generation.get()
    }

    pub(crate) fn authorizes_retirement_effect(&self) -> bool {
        matches!(self.phase, SelectorAdmissionPhase::Retiring)
            && self.previous_terminal.is_some()
            && self.operation_nonce != self.terminal_operation_nonce
            && self.terminal_generation.get() > self.generation.get()
    }

    pub(crate) const fn authorizes_retired_readback(&self) -> bool {
        matches!(self.phase, SelectorAdmissionPhase::Retired)
            && self.retired_dataplane_generation.is_some()
    }

    pub(crate) const fn retired_dataplane_generation(&self) -> Option<NonZeroU64> {
        self.retired_dataplane_generation
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
                if terminal.generation.get() <= generation.get()
                    || terminal.nonce == operation_nonce
                    || previous_terminal.is_some()
                {
                    return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
                }
            }
            SelectorAdmissionPhase::Retiring => {
                if terminal.generation.get() <= generation.get()
                    || terminal.nonce == operation_nonce
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
            retired_dataplane_generation: self.retired_dataplane_generation,
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
        if atoms.len() > SELECTOR_NAMESPACE_MAX_READBACK_ATOMS {
            return Err(GtpuSessionSelectorNamespaceError::CapacityExhausted);
        }
        state.bind_or_validate(
            group.device_id(),
            SELECTOR_NAMESPACE_MAX_READBACK_ATOMS,
            Some(self.key),
        )?;
        state.preflight_fresh_claim(atoms.len())?;
        state.retain_canonical_desired(claim.group_fingerprint, group)?;
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
        state.bind_or_validate(
            desired.device_id(),
            SELECTOR_NAMESPACE_MAX_READBACK_ATOMS,
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
        state.preflight_reissue(atoms.len())?;
        let Some(GroupState::Retired {
            device,
            selectors,
            desired: source_desired,
            atoms: source_atoms,
            activation_generation,
            generation: source_generation,
            operation_nonce: source_nonce,
            retired_dataplane_generation,
            successor: None,
        }) = state.groups.get(&source.group_fingerprint).cloned()
        else {
            return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
        };
        let generation = state.next_generation()?;
        let operation_nonce = test_nonzero_nonce(&self.key, claim.group_fingerprint, generation)?;
        state.retain_canonical_desired(claim.group_fingerprint, desired)?;
        state.groups.insert(
            source.group_fingerprint,
            GroupState::Retired {
                device,
                selectors,
                desired: source_desired,
                atoms: source_atoms,
                activation_generation,
                generation: source_generation,
                operation_nonce: source_nonce,
                retired_dataplane_generation,
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
                activation_generation: generation,
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
            activation_generation,
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
                activation_generation,
                retired_dataplane_generation: terminal_generation.0,
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
            state.retain_canonical_desired(claim.group_fingerprint, group)?;
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
                    reuse: None,
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
            state.retain_canonical_desired(claim.group_fingerprint, desired)?;
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
                activation_generation,
                generation: source_generation,
                operation_nonce: source_nonce,
                retired_dataplane_generation,
                successor: None,
            }) = state.groups.get(&source.group_fingerprint).cloned()
            else {
                return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
            };
            let reuse = ReusedInstallDescriptor::from_proof(
                proof,
                device,
                selectors,
                source_desired,
                source_generation,
                source_nonce,
                retired_dataplane_generation,
            )
            .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
            state.groups.insert(
                source.group_fingerprint,
                GroupState::Retired {
                    device,
                    selectors,
                    desired: source_desired,
                    atoms: source_atoms,
                    activation_generation,
                    generation: source_generation,
                    operation_nonce: source_nonce,
                    retired_dataplane_generation,
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
                    reuse: Some(reuse),
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
                    activation_generation: generation,
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
                activation_generation,
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
                    activation_generation,
                    retired_dataplane_generation: terminal_generation.0,
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
    ///
    /// Opening is an SDK-owned detached operation for the same reason as a
    /// dataplane effect: dropping the caller's observer must not release the
    /// per-namespace worker fence while a backend binding check is still
    /// completing on a blocking host worker.
    pub fn open_protected<D>(
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
        if lease_ttl != SELECTOR_NAMESPACE_MAX_LEASE_TTL {
            return spawn_selector_operation(
                [0; 32],
                GtpuSessionSelectorNamespaceError::UnsuitableStore,
                async { Err(GtpuSessionSelectorNamespaceError::UnsuitableStore) },
            );
        }
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
                authority.verify_open_bound(backend.as_ref()).await?;
                Ok(authority)
            },
        )
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
        if lease_ttl != SELECTOR_NAMESPACE_MAX_LEASE_TTL {
            return spawn_selector_operation(
                [0; 32],
                GtpuSessionSelectorNamespaceError::UnsuitableStore,
                async { Err(GtpuSessionSelectorNamespaceError::UnsuitableStore) },
            );
        }
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
        let mut lease = self
            .acquire_worker_lease()
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let result = async {
            self.claim_fresh_with_lease(backend, &desired, &mut lease)
                .await
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
            let handoff = self
                .mark_install_backend_started_with_lease(&desired, &mut lease)
                .await
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
            match handoff {
                BackendStartHandoff::Transitioned(admission) => {
                    self.effect_and_activate_with_lease(
                        backend, desired, admission, None, &mut lease,
                    )
                    .await
                }
                BackendStartHandoff::AlreadyStarted(admission) => {
                    self.recover_install_after_competing_start(
                        backend, desired, admission, &mut lease,
                    )
                    .await
                }
            }
        }
        .await;
        self.finish_worker_operation(lease, result).await
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
        let mut lease = self
            .acquire_worker_lease()
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let result = async {
            self.ensure_backend_namespace(backend, &mut lease)
                .await
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
            if retired.admission.phase != SelectorAdmissionPhase::Retired
                || !retired.admission.validates(&retired.group)
                || retired.group.device_id() != desired.device_id()
                || retired.group.id() == desired.id()
            {
                return Err(GtpuSessionSelectorCoordinatorError::Namespace);
            }
            let window = self
                .mint_backend_mutation_window(&mut lease)
                .await
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
            let receipt = settle_selector_backend_step(backend.authorize_selector_reuse(
                GtpuSessionSelectorReuseRequest {
                    retired,
                    desired,
                    window,
                },
            ))
            .await
            .ok_or(GtpuSessionSelectorCoordinatorError::Backend)?
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Backend)?;
            let GtpuSessionSelectorReuseReceipt {
                retired,
                desired,
                evidence,
                window,
            } = receipt;
            if !window.is_current()
                || retired.admission.phase != SelectorAdmissionPhase::Retired
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
        .await;
        self.finish_worker_operation(lease, result).await
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
        let mut lease = self
            .acquire_worker_lease()
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let result = async {
            self.claim_reused_with_lease(backend, &desired, &proof, &mut lease)
                .await
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
            let handoff = self
                .mark_install_backend_started_with_lease(&desired, &mut lease)
                .await
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
            match handoff {
                BackendStartHandoff::Transitioned(admission) => {
                    let reuse = match self.installing_reuse_proof(&desired).await {
                        Ok(Some(reuse)) => reuse,
                        Ok(None) | Err(_) => {
                            self.poison_or_namespace(
                                &desired,
                                &admission,
                                PoisonReason::RecoveryIndeterminate,
                                &mut lease,
                            )
                            .await?;
                            return Err(GtpuSessionSelectorCoordinatorError::Namespace);
                        }
                    };
                    self.effect_and_activate_with_lease(
                        backend,
                        desired,
                        admission,
                        Some(reuse),
                        &mut lease,
                    )
                    .await
                }
                BackendStartHandoff::AlreadyStarted(admission) => {
                    self.recover_install_after_competing_start(
                        backend, desired, admission, &mut lease,
                    )
                    .await
                }
            }
        }
        .await;
        self.finish_worker_operation(lease, result).await
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
        let mut lease = self
            .acquire_worker_lease()
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let result = self
            .recover_install_with_lease(backend, desired, &mut lease)
            .await;
        self.finish_worker_operation(lease, result).await
    }

    async fn recover_install_with_lease<D>(
        &self,
        backend: &D,
        desired: GtpuSessionGroup,
        lease: &mut opc_session_store::LeaseGuard,
    ) -> Result<GtpuSessionSelectorActiveClaim, GtpuSessionSelectorCoordinatorError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        self.ensure_backend_namespace(backend, lease)
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        // `Installing(false)` is a durable pre-effect reservation, not a
        // retry permit.  Only independently authenticated complete absence
        // may advance it; a pending, terminal, partial, or malformed backend
        // observation remains fail-closed rather than being reinterpreted as
        // a request to replay the effect.
        if let Ok(admission) = self.installing_admission(&desired, Some(false)).await {
            let window = self
                .mint_backend_mutation_window(lease)
                .await
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
            let request = GtpuSessionSelectorInstallingNoEffectRequest {
                expected: desired.clone(),
                admission,
                window,
            };
            let expected_receipt = request.receipt_coordinate();
            if !request.is_current() {
                return Err(GtpuSessionSelectorCoordinatorError::Backend);
            }
            let receipt = settle_selector_backend_step(
                backend.inspect_installing_selector_no_effect(request),
            )
            .await
            .ok_or(GtpuSessionSelectorCoordinatorError::Backend)?
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Backend)?;
            // The backend could only settle the consumed request after its
            // pre/post-lock currentness checks. Recheck the coordinate-bound
            // receipt immediately on return before the durable handoff.
            if !receipt.confirms_installing_no_effect(expected_receipt) {
                return Err(GtpuSessionSelectorCoordinatorError::Backend);
            }
            let handoff = self
                .mark_install_backend_started_with_lease(&desired, lease)
                .await
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
            // A durable CAS can itself be delayed. Do not let a negative
            // proof that expired while committing the handoff launch an
            // effect; the one-way bit remains for a later exact recovery.
            if !receipt.confirms_installing_no_effect(expected_receipt) {
                return Err(GtpuSessionSelectorCoordinatorError::Backend);
            }
            return match handoff {
                BackendStartHandoff::Transitioned(admission) => {
                    let reuse = match self.installing_reuse_proof(&desired).await {
                        Ok(reuse) => reuse,
                        Err(_) => {
                            self.poison_or_namespace(
                                &desired,
                                &admission,
                                PoisonReason::RecoveryIndeterminate,
                                lease,
                            )
                            .await?;
                            return Err(GtpuSessionSelectorCoordinatorError::Namespace);
                        }
                    };
                    self.effect_and_activate_with_lease(backend, desired, admission, reuse, lease)
                        .await
                }
                BackendStartHandoff::AlreadyStarted(admission) => {
                    self.recover_install_after_competing_start(backend, desired, admission, lease)
                        .await
                }
            };
        }

        let admission = self
            .installing_admission(&desired, Some(true))
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let readback = match self
            .authorized_readback(backend, desired.clone(), admission, lease)
            .await
        {
            Ok(readback) => readback,
            Err(_) => {
                let poison_admission = self
                    .installing_admission(&desired, Some(true))
                    .await
                    .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
                self.poison_or_namespace(
                    &desired,
                    &poison_admission,
                    PoisonReason::RecoveryIndeterminate,
                    lease,
                )
                .await?;
                return Err(GtpuSessionSelectorCoordinatorError::Backend);
            }
        };
        match readback.readback {
            crate::GtpuSessionGroupReadback::Active(ref active) if active == &desired => self
                .activate_claim_with_lease(&desired, lease)
                .await
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace),
            _ => {
                // The worker that consumed the original affine request can
                // outlive its store lease. Reissuing a started coordinate
                // would therefore race that stale worker even when the
                // backend currently reports no effect or an exact pending
                // journal. Only exact terminal readback above may settle;
                // every other started observation is permanently closed.
                let poison_admission = self
                    .installing_admission(&desired, Some(true))
                    .await
                    .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
                self.poison_or_namespace(
                    &desired,
                    &poison_admission,
                    PoisonReason::RecoveryIndeterminate,
                    lease,
                )
                .await?;
                Err(GtpuSessionSelectorCoordinatorError::Backend)
            }
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
        lease: &mut opc_session_store::LeaseGuard,
    ) -> Result<GtpuSessionSelectorActiveClaim, GtpuSessionSelectorCoordinatorError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        let readback_admission = self
            .installing_admission(&desired, Some(true))
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        match self
            .authorized_readback(backend, desired.clone(), readback_admission, lease)
            .await
            .map(|readback| readback.readback)
        {
            Ok(crate::GtpuSessionGroupReadback::Active(active)) if active == desired => self
                .activate_claim_with_lease(&desired, lease)
                .await
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace),
            Ok(_) | Err(_) => {
                self.poison_or_namespace(
                    &desired,
                    &admission,
                    PoisonReason::RecoveryIndeterminate,
                    lease,
                )
                .await?;
                Err(GtpuSessionSelectorCoordinatorError::Backend)
            }
        }
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
        let mut lease = self
            .acquire_worker_lease()
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let result = async {
            self.ensure_backend_namespace(backend, &mut lease)
                .await
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
            let admission = self
                .active_admission(&desired)
                .await
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
            let readback_admission = self
                .active_admission(&desired)
                .await
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
            if self
                .require_exact_active(backend, desired.clone(), readback_admission, &mut lease)
                .await
                .is_err()
            {
                self.poison_or_namespace(
                    &desired,
                    &admission,
                    PoisonReason::RecoveryIndeterminate,
                    &mut lease,
                )
                .await?;
                return Err(GtpuSessionSelectorCoordinatorError::Backend);
            }
            let admission = self
                .active_admission(&desired)
                .await
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
            Ok(GtpuSessionSelectorActiveClaim(admission))
        }
        .await;
        self.finish_worker_operation(lease, result).await
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
        let mut lease = self
            .acquire_worker_lease()
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let result = async {
            self.ensure_backend_namespace(backend, &mut lease)
                .await
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
            let admission = self
                .retired_admission(&expected)
                .await
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
            let readback = match self
                .authorized_readback(backend, expected.clone(), admission, &mut lease)
                .await
            {
                Ok(readback) => readback,
                Err(_) => {
                    let poison_admission = self
                        .retired_admission(&expected)
                        .await
                        .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
                    self.poison_or_namespace(
                        &expected,
                        &poison_admission,
                        PoisonReason::RecoveryIndeterminate,
                        &mut lease,
                    )
                    .await?;
                    return Err(GtpuSessionSelectorCoordinatorError::Backend);
                }
            };
            let admission = self
                .retired_admission(&expected)
                .await
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
            if !matches!(readback.readback, crate::GtpuSessionGroupReadback::Absent)
                || readback.terminal_retired_dataplane_generation
                    != admission.retired_dataplane_generation()
            {
                self.poison_or_namespace(
                    &expected,
                    &admission,
                    PoisonReason::RecoveryIndeterminate,
                    &mut lease,
                )
                .await?;
                return Err(GtpuSessionSelectorCoordinatorError::Backend);
            }
            Ok(GtpuSessionSelectorRetiredClaim {
                group: expected,
                admission,
            })
        }
        .await;
        self.finish_worker_operation(lease, result).await
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
        let mut lease = self
            .acquire_worker_lease()
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let result = self
            .retire_with_lease(backend, active, expected, &mut lease)
            .await;
        self.finish_worker_operation(lease, result).await
    }

    async fn retire_with_lease<D>(
        &self,
        backend: &D,
        active: GtpuSessionSelectorActiveClaim,
        expected: GtpuSessionGroup,
        lease: &mut opc_session_store::LeaseGuard,
    ) -> Result<GtpuSessionSelectorRetiredClaim, GtpuSessionSelectorCoordinatorError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        self.ensure_backend_namespace(backend, lease)
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        if !active.0.validates(&expected) {
            return Err(GtpuSessionSelectorCoordinatorError::Namespace);
        }
        let admission = active.0;
        self.transition_retiring_with_lease(&admission, lease)
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let handoff = self
            .mark_retirement_backend_started_with_lease(&expected, lease)
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        match handoff {
            BackendStartHandoff::Transitioned(admission) => {
                self.complete_retirement_with_lease(backend, expected, admission, lease)
                    .await
            }
            BackendStartHandoff::AlreadyStarted(admission) => {
                self.recover_retiring_after_competing_start(backend, expected, admission, lease)
                    .await
            }
        }
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
        let mut lease = self
            .acquire_worker_lease()
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let result = self
            .recover_retiring_with_lease(backend, expected, &mut lease)
            .await;
        self.finish_worker_operation(lease, result).await
    }

    async fn recover_retiring_with_lease<D>(
        &self,
        backend: &D,
        expected: GtpuSessionGroup,
        lease: &mut opc_session_store::LeaseGuard,
    ) -> Result<GtpuSessionSelectorRetiredClaim, GtpuSessionSelectorCoordinatorError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        self.ensure_backend_namespace(backend, lease)
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        // The Retiring(false) coordinate still represents the exact prior
        // Active graph. A generic structural Active readback cannot prove no
        // remove effect occurred: only the opaque backend inspection below
        // binds that negative fact to the previous terminal stamp.
        if let Ok(admission) = self.retiring_admission(&expected, Some(false)).await {
            let window = self
                .mint_backend_mutation_window(lease)
                .await
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
            let request = GtpuSessionSelectorRetiringNoEffectRequest {
                expected: expected.clone(),
                admission,
                window,
            };
            let expected_receipt = request.receipt_coordinate();
            if !request.is_current() {
                return Err(GtpuSessionSelectorCoordinatorError::Backend);
            }
            let receipt =
                settle_selector_backend_step(backend.inspect_retiring_selector_no_effect(request))
                    .await
                    .ok_or(GtpuSessionSelectorCoordinatorError::Backend)?
                    .map_err(|_| GtpuSessionSelectorCoordinatorError::Backend)?;
            // See Installing recovery: the receipt carries the consumed
            // request's exact window and is checked immediately on return.
            if !receipt.confirms_retiring_no_effect(expected_receipt) {
                return Err(GtpuSessionSelectorCoordinatorError::Backend);
            }
            let handoff = self
                .mark_retirement_backend_started_with_lease(&expected, lease)
                .await
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
            // As above, a stale negative proof may not outlive the durable
            // handoff and authorize the first removal effect.
            if !receipt.confirms_retiring_no_effect(expected_receipt) {
                return Err(GtpuSessionSelectorCoordinatorError::Backend);
            }
            return match handoff {
                BackendStartHandoff::Transitioned(admission) => {
                    self.complete_retirement_with_lease(backend, expected, admission, lease)
                        .await
                }
                BackendStartHandoff::AlreadyStarted(admission) => {
                    self.recover_retiring_after_competing_start(backend, expected, admission, lease)
                        .await
                }
            };
        }

        let admission = self
            .retiring_admission(&expected, Some(true))
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let readback_admission = self
            .retiring_admission(&expected, Some(true))
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let readback = match self
            .authorized_readback(backend, expected.clone(), readback_admission, lease)
            .await
        {
            Ok(readback) => readback,
            Err(_) => {
                self.poison_or_namespace(
                    &expected,
                    &admission,
                    PoisonReason::RecoveryIndeterminate,
                    lease,
                )
                .await?;
                return Err(GtpuSessionSelectorCoordinatorError::Backend);
            }
        };
        if matches!(readback.readback, crate::GtpuSessionGroupReadback::Absent) {
            let Some(retired_dataplane_generation) = readback.terminal_retired_dataplane_generation
            else {
                self.poison_or_namespace(
                    &expected,
                    &admission,
                    PoisonReason::RecoveryIndeterminate,
                    lease,
                )
                .await?;
                return Err(GtpuSessionSelectorCoordinatorError::Backend);
            };
            let admission = self
                .retiring_admission(&expected, Some(true))
                .await
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
            let admission = self
                .transition_retired_with_lease(&admission, retired_dataplane_generation, lease)
                .await
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
            return Ok(GtpuSessionSelectorRetiredClaim {
                group: expected,
                admission,
            });
        }
        // As for install, the worker that consumed the original affine
        // removal request can outlive its store lease. A new worker may
        // settle exact terminal absence above, but must never replay the
        // started removal coordinate.
        self.poison_or_namespace(
            &expected,
            &admission,
            PoisonReason::RecoveryIndeterminate,
            lease,
        )
        .await?;
        Err(GtpuSessionSelectorCoordinatorError::Backend)
    }

    /// Observe only final state after losing the false-to-true Retiring
    /// handoff. It deliberately cannot replay a removal based on a stale
    /// prior-Active proof while the winning supervisor owns that coordinate.
    async fn recover_retiring_after_competing_start<D>(
        &self,
        backend: &D,
        expected: GtpuSessionGroup,
        admission: GtpuSessionSelectorAdmission,
        lease: &mut opc_session_store::LeaseGuard,
    ) -> Result<GtpuSessionSelectorRetiredClaim, GtpuSessionSelectorCoordinatorError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        let readback_admission = self
            .retiring_admission(&expected, Some(true))
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let readback = match self
            .authorized_readback(backend, expected.clone(), readback_admission, lease)
            .await
        {
            Ok(readback)
                if matches!(readback.readback, crate::GtpuSessionGroupReadback::Absent)
                    && readback.terminal_retired_dataplane_generation.is_some() =>
            {
                readback
            }
            Ok(_) | Err(_) => {
                self.poison_or_namespace(
                    &expected,
                    &admission,
                    PoisonReason::RecoveryIndeterminate,
                    lease,
                )
                .await?;
                return Err(GtpuSessionSelectorCoordinatorError::Backend);
            }
        };
        let retired_dataplane_generation = readback
            .terminal_retired_dataplane_generation
            .ok_or(GtpuSessionSelectorCoordinatorError::Namespace)?;
        let admission = self
            .retiring_admission(&expected, Some(true))
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let admission = self
            .transition_retired_with_lease(&admission, retired_dataplane_generation, lease)
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        Ok(GtpuSessionSelectorRetiredClaim {
            group: expected,
            admission,
        })
    }

    async fn effect_and_activate_with_lease<D>(
        &self,
        backend: &D,
        desired: GtpuSessionGroup,
        admission: GtpuSessionSelectorAdmission,
        reuse: Option<crate::GtpuSessionSelectorReuseProof>,
        lease: &mut opc_session_store::LeaseGuard,
    ) -> Result<GtpuSessionSelectorActiveClaim, GtpuSessionSelectorCoordinatorError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        // Retain an independently re-minted exact coordinate solely for a
        // post-effect poison CAS. The request consumes its affine admission.
        let poison_admission = self
            .installing_admission(&desired, Some(true))
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let request = match reuse {
            Some(reuse) => {
                GtpuSessionGroupReconcileRequest::new_reused(desired.clone(), admission, reuse)
            }
            None => GtpuSessionGroupReconcileRequest::new(desired.clone(), admission),
        }
        .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        self.complete_effect_with_lease(backend, desired, poison_admission, request, lease)
            .await
    }

    async fn complete_effect_with_lease<D>(
        &self,
        backend: &D,
        desired: GtpuSessionGroup,
        admission: GtpuSessionSelectorAdmission,
        request: GtpuSessionGroupReconcileRequest,
        lease: &mut opc_session_store::LeaseGuard,
    ) -> Result<GtpuSessionSelectorActiveClaim, GtpuSessionSelectorCoordinatorError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        let window = self
            .mint_backend_mutation_window(lease)
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let request = GtpuSessionSelectorEffectRequest { request, window };
        let expected_receipt = request.receipt_coordinate();
        let receipt =
            settle_selector_backend_step(backend.reconcile_pdp_context_group_authorized(request))
                .await;
        let outcome = match receipt {
            Some(Ok(receipt)) => receipt.into_effect(expected_receipt),
            Some(Err(_)) | None => None,
        };
        if !matches!(
            outcome,
            Some(GtpuSessionGroupReconcileOutcome::Activated)
                | Some(GtpuSessionGroupReconcileOutcome::ExactAlreadyActive)
        ) {
            self.poison_or_namespace(
                &desired,
                &admission,
                PoisonReason::EffectReceiptIndeterminate,
                lease,
            )
            .await?;
            return Err(GtpuSessionSelectorCoordinatorError::Backend);
        }
        let current_admission = self
            .installing_admission(&desired, Some(true))
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        if self
            .require_exact_active(backend, desired.clone(), current_admission, lease)
            .await
            .is_err()
        {
            self.poison_or_namespace(
                &desired,
                &admission,
                PoisonReason::EffectReadbackIndeterminate,
                lease,
            )
            .await?;
            return Err(GtpuSessionSelectorCoordinatorError::Backend);
        }
        match self.activate_claim_with_lease(&desired, lease).await {
            Ok(active) => Ok(active),
            Err(_) => {
                self.poison_or_namespace(
                    &desired,
                    &admission,
                    PoisonReason::EffectReadbackIndeterminate,
                    lease,
                )
                .await?;
                Err(GtpuSessionSelectorCoordinatorError::Namespace)
            }
        }
    }

    async fn require_exact_active<D>(
        &self,
        backend: &D,
        desired: GtpuSessionGroup,
        admission: GtpuSessionSelectorAdmission,
        lease: &mut opc_session_store::LeaseGuard,
    ) -> Result<(), GtpuSessionSelectorCoordinatorError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        let readback = self
            .authorized_readback(backend, desired.clone(), admission, lease)
            .await?;
        matches!(readback.readback, crate::GtpuSessionGroupReadback::Active(ref active) if active == &desired)
            .then_some(())
            .ok_or(GtpuSessionSelectorCoordinatorError::Backend)
    }

    async fn authorized_readback<D>(
        &self,
        backend: &D,
        expected: GtpuSessionGroup,
        admission: GtpuSessionSelectorAdmission,
        lease: &mut opc_session_store::LeaseGuard,
    ) -> Result<AuthorizedSelectorReadback, GtpuSessionSelectorCoordinatorError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        let window = self
            .mint_backend_mutation_window(lease)
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let request = GtpuSessionSelectorReadbackRequest {
            expected,
            admission,
            window,
        };
        let expected_receipt = request.receipt_coordinate();
        let receipt =
            settle_selector_backend_step(backend.read_pdp_context_group_with_lease(request))
                .await
                .ok_or(GtpuSessionSelectorCoordinatorError::Backend)?;
        receipt
            .ok()
            .and_then(|receipt| receipt.into_readback(expected_receipt))
            .ok_or(GtpuSessionSelectorCoordinatorError::Backend)
    }

    async fn complete_retirement_with_lease<D>(
        &self,
        backend: &D,
        expected: GtpuSessionGroup,
        admission: GtpuSessionSelectorAdmission,
        lease: &mut opc_session_store::LeaseGuard,
    ) -> Result<GtpuSessionSelectorRetiredClaim, GtpuSessionSelectorCoordinatorError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        let poison_admission = self
            .retiring_admission(&expected, Some(true))
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let window = self
            .mint_backend_mutation_window(lease)
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let request = GtpuSessionSelectorRemovalRequest {
            expected: expected.clone(),
            admission,
            window,
        };
        let expected_receipt = request.receipt_coordinate();
        let receipt =
            settle_selector_backend_step(backend.remove_pdp_context_group_with_lease(request))
                .await;
        let removal = match receipt {
            Some(Ok(receipt)) => receipt.into_removal(expected_receipt),
            Some(Err(_)) | None => None,
        };
        if !matches!(
            removal.as_ref().map(|removal| removal.outcome.clone()),
            Some(GtpuSessionGroupRemovalOutcome::Removed)
                | Some(GtpuSessionGroupRemovalOutcome::AlreadyAbsent)
        ) {
            self.poison_or_namespace(
                &expected,
                &poison_admission,
                PoisonReason::RemovalReceiptIndeterminate,
                lease,
            )
            .await?;
            return Err(GtpuSessionSelectorCoordinatorError::Backend);
        }
        let Some(removed_dataplane_generation) = removal
            .as_ref()
            .and_then(|removal| removal.terminal_retired_dataplane_generation)
        else {
            self.poison_or_namespace(
                &expected,
                &poison_admission,
                PoisonReason::RemovalReceiptIndeterminate,
                lease,
            )
            .await?;
            return Err(GtpuSessionSelectorCoordinatorError::Backend);
        };
        let admission = self
            .retiring_admission(&expected, Some(true))
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let readback = match self
            .authorized_readback(backend, expected.clone(), admission, lease)
            .await
        {
            Ok(readback) => readback,
            Err(_) => {
                self.poison_or_namespace(
                    &expected,
                    &poison_admission,
                    PoisonReason::RemovalReadbackIndeterminate,
                    lease,
                )
                .await?;
                return Err(GtpuSessionSelectorCoordinatorError::Backend);
            }
        };
        if !matches!(readback.readback, crate::GtpuSessionGroupReadback::Absent)
            || readback.terminal_retired_dataplane_generation != Some(removed_dataplane_generation)
        {
            self.poison_or_namespace(
                &expected,
                &poison_admission,
                PoisonReason::RemovalReadbackIndeterminate,
                lease,
            )
            .await?;
            return Err(GtpuSessionSelectorCoordinatorError::Backend);
        }
        let admission = self
            .retiring_admission(&expected, Some(true))
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let admission = match self
            .transition_retired_with_lease(&admission, removed_dataplane_generation, lease)
            .await
        {
            Ok(admission) => admission,
            Err(_) => {
                self.poison_or_namespace(
                    &expected,
                    &poison_admission,
                    PoisonReason::RemovalReadbackIndeterminate,
                    lease,
                )
                .await?;
                return Err(GtpuSessionSelectorCoordinatorError::Namespace);
            }
        };
        Ok(GtpuSessionSelectorRetiredClaim {
            group: expected,
            admission,
        })
    }

    #[cfg(test)]
    async fn claim_fresh<D>(
        &self,
        backend: &D,
        desired: &GtpuSessionGroup,
    ) -> Result<GtpuSessionSelectorAdmission, GtpuSessionSelectorNamespaceError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        let mut lease = self.acquire_worker_lease().await?;
        let result = self
            .claim_fresh_with_lease(backend, desired, &mut lease)
            .await;
        self.release_worker_lease(lease).await?;
        result
    }

    /// Claim a fresh Installing coordinate while retaining the one durable
    /// worker lease that protects its handoff and terminal acknowledgement.
    async fn claim_fresh_with_lease<D>(
        &self,
        backend: &D,
        desired: &GtpuSessionGroup,
        lease: &mut opc_session_store::LeaseGuard,
    ) -> Result<GtpuSessionSelectorAdmission, GtpuSessionSelectorNamespaceError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        self.ensure_backend_namespace(backend, lease).await?;
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
            state.retain_canonical_desired(claim.group_fingerprint, desired)?;
            let generation = state.next_generation()?;
            let operation_nonce = random_nonzero_nonce()?;
            let terminal_generation = state.next_generation()?;
            let terminal_operation_nonce = random_distinct_nonzero_nonce(operation_nonce)?;
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
                    reuse: None,
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
            if self
                .replace_with_lease(record.as_ref(), state, lease)
                .await?
            {
                return Ok(admission);
            }
        }
        Err(GtpuSessionSelectorNamespaceError::Indeterminate)
    }

    /// Claim a retired-source reissue while retaining the exact durable
    /// worker lease through its Installing handoff.
    #[cfg(test)]
    async fn claim_reused<D>(
        &self,
        backend: &D,
        desired: &GtpuSessionGroup,
        proof: &crate::GtpuSessionSelectorReuseProof,
    ) -> Result<GtpuSessionSelectorAdmission, GtpuSessionSelectorNamespaceError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        let mut lease = self.acquire_worker_lease().await?;
        let result = self
            .claim_reused_with_lease(backend, desired, proof, &mut lease)
            .await;
        self.release_worker_lease(lease).await?;
        result
    }

    /// Claim a retired-source reissue while retaining the exact durable
    /// worker lease through its Installing handoff.
    async fn claim_reused_with_lease<D>(
        &self,
        backend: &D,
        desired: &GtpuSessionGroup,
        proof: &crate::GtpuSessionSelectorReuseProof,
        lease: &mut opc_session_store::LeaseGuard,
    ) -> Result<GtpuSessionSelectorAdmission, GtpuSessionSelectorNamespaceError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        self.ensure_backend_namespace(backend, lease).await?;
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
            state.retain_canonical_desired(claim.group_fingerprint, desired)?;
            let generation = state.next_generation()?;
            let operation_nonce = random_nonzero_nonce()?;
            let terminal_generation = state.next_generation()?;
            let terminal_operation_nonce = random_distinct_nonzero_nonce(operation_nonce)?;
            let Some(GroupState::Retired {
                device,
                selectors,
                desired: source_desired,
                atoms: source_atoms,
                activation_generation,
                generation: source_generation,
                operation_nonce: source_nonce,
                retired_dataplane_generation,
                successor: None,
            }) = state.groups.get(&source.group_fingerprint).cloned()
            else {
                return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
            };
            let reuse = ReusedInstallDescriptor::from_proof(
                proof,
                device,
                selectors,
                source_desired,
                source_generation,
                source_nonce,
                retired_dataplane_generation,
            )
            .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
            state.groups.insert(
                source.group_fingerprint,
                GroupState::Retired {
                    device,
                    selectors,
                    desired: source_desired,
                    atoms: source_atoms,
                    activation_generation,
                    generation: source_generation,
                    operation_nonce: source_nonce,
                    retired_dataplane_generation,
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
                    reuse: Some(reuse),
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
            if self
                .replace_with_lease(record.as_ref(), state, lease)
                .await?
            {
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

    async fn verify_open_bound<D>(
        &self,
        backend: &D,
    ) -> Result<(), GtpuSessionSelectorNamespaceError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        let mut lease = self.acquire_worker_lease().await?;
        let result = self.ensure_backend_namespace(backend, &mut lease).await;
        let released = self.release_worker_lease(lease).await;
        match result {
            Err(error) => Err(error),
            Ok(()) if released.is_ok() => Ok(()),
            Ok(()) => Err(GtpuSessionSelectorNamespaceError::Indeterminate),
        }
    }

    fn bound_binding(
        &self,
        state: &NamespaceState,
    ) -> Result<GtpuSessionSelectorBackendBinding, GtpuSessionSelectorNamespaceError> {
        if state.lifecycle != NamespaceLifecycle::Bound
            || state.decommission_fence.is_some()
            || state.capacity != self.maximum_operation_atoms as u32
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
        lease: &mut opc_session_store::LeaseGuard,
    ) -> Result<(), GtpuSessionSelectorNamespaceError>
    where
        D: GtpuDataplaneBackend + ?Sized,
    {
        let (_, state) = self.read_state().await?;
        let binding = self.bound_binding(&state)?;
        let inventory = state.operation_stamp_inventory(binding)?;
        let window = self.mint_backend_mutation_window(lease).await?;
        let request = GtpuSessionSelectorBindingLease {
            binding,
            inventory,
            window,
        };
        let expected_receipt = request.receipt_coordinate();
        let receipt =
            settle_selector_backend_step(backend.acquire_selector_namespace_lease(request))
                .await
                .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?
                .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
        receipt
            .confirms_binding(expected_receipt)
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
        let mut lease = self.acquire_worker_lease().await?;
        let result = self.provision_with_lease(backend, &mut lease).await;
        let released = self.release_worker_lease(lease).await;
        match result {
            Err(error) => Err(error),
            Ok(()) if released.is_ok() => Ok(()),
            Ok(()) => Err(GtpuSessionSelectorNamespaceError::Indeterminate),
        }
    }

    async fn provision_with_lease<D>(
        &self,
        backend: &D,
        lease: &mut opc_session_store::LeaseGuard,
    ) -> Result<(), GtpuSessionSelectorNamespaceError>
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
                    if self.replace_with_lease(None, state, lease).await? {
                        continue;
                    }
                }
                NamespaceLifecycle::Provisioned => {
                    state.initialize(self.maximum_operation_atoms)?;
                    if self
                        .replace_with_lease(record.as_ref(), state, lease)
                        .await?
                    {
                        continue;
                    }
                }
                NamespaceLifecycle::Initializing => {
                    if state.stable_device != Some(self.stable_device.to_bytes())
                        || state.pin_commitment != self.pin_commitment
                        || state.storage_scope_commitment != self.storage_scope_commitment
                        || state.capacity != self.maximum_operation_atoms as u32
                    {
                        return Err(GtpuSessionSelectorNamespaceError::ConfigurationMismatch);
                    }
                    let binding = state.binding_with_scope(self.storage_scope_commitment)?;
                    let window = self.mint_backend_mutation_window(lease).await?;
                    let request = GtpuSessionSelectorProvisionRequest { binding, window };
                    let expected_receipt = request.receipt_coordinate();
                    let receipt = settle_selector_backend_step(
                        backend.provision_selector_namespace_authorized(request),
                    )
                    .await
                    .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?
                    .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
                    if !receipt.confirms_provisioning(expected_receipt) {
                        return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
                    }
                    state.lifecycle = NamespaceLifecycle::Bound;
                    if self
                        .replace_with_lease(record.as_ref(), state, lease)
                        .await?
                    {
                        self.ensure_backend_namespace(backend, lease).await?;
                        return Ok(());
                    }
                }
                NamespaceLifecycle::Bound => {
                    self.bound_binding(&state)?;
                    self.ensure_backend_namespace(backend, lease).await?;
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
            let attempt = match attempt {
                Err(error) => return Err(error),
                Ok(attempt) if released.is_ok() => attempt,
                Ok(_) => return Err(GtpuSessionSelectorCoordinatorError::Namespace),
            };
            match attempt {
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
            || state.capacity != self.maximum_operation_atoms as u32
        {
            return Err(GtpuSessionSelectorCoordinatorError::Namespace);
        }
        let binding = state
            .binding_with_scope(self.storage_scope_commitment)
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;

        // A Bound namespace must prove the complete persistent operation
        // inventory before beginning an ordinary terminal operation. Once a
        // fence is precommitted, only the exact terminal capsule protocol may
        // proceed, so `operation_stamp_inventory` deliberately rejects that
        // lifecycle and the recovery branch below owns the narrower proof.
        if state.lifecycle == NamespaceLifecycle::Bound {
            self.ensure_backend_namespace(backend, lease)
                .await
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        }

        let fence = match (state.lifecycle, state.decommission_fence) {
            (NamespaceLifecycle::Bound, None) => {
                let window = self
                    .mint_backend_mutation_window(lease)
                    .await
                    .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
                let request = GtpuSessionSelectorDecommissionInspectRequest {
                    binding,
                    expected_fence: None,
                    window,
                };
                let expected_receipt = request.receipt_coordinate();
                let absence = settle_selector_backend_step(
                    backend.inspect_selector_namespace_decommission_fence(request),
                )
                .await
                .ok_or(GtpuSessionSelectorCoordinatorError::Backend)?
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Backend)?;
                if !absence.confirms_decommission_fence_absent(expected_receipt) {
                    return Err(GtpuSessionSelectorCoordinatorError::Backend);
                }
                let predecessor_plaintext = state.encode();
                state
                    .precommit_decommission(record.generation, &predecessor_plaintext)
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
            (
                NamespaceLifecycle::Decommissioning | NamespaceLifecycle::Decommissioned,
                Some(fence),
            ) if state.decommission_fence_is_exact(fence) => fence,
            _ => return Err(GtpuSessionSelectorCoordinatorError::Namespace),
        };

        let window = self
            .mint_backend_mutation_window(lease)
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let request = GtpuSessionSelectorDecommissionInspectRequest {
            binding,
            expected_fence: Some(fence),
            window,
        };
        let expected_inspection = request.receipt_coordinate();
        let inspection = settle_selector_backend_step(
            backend.inspect_selector_namespace_decommission_fence(request),
        )
        .await
        .ok_or(GtpuSessionSelectorCoordinatorError::Backend)?
        .map_err(|_| GtpuSessionSelectorCoordinatorError::Backend)?;
        if inspection.confirms_decommission_fence_absent(expected_inspection) {
            let window = self
                .mint_backend_mutation_window(lease)
                .await
                .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
            let request = GtpuSessionSelectorDecommissionRequest {
                binding,
                fence,
                window,
            };
            let expected_created = request.receipt_coordinate();
            let created = settle_selector_backend_step(
                backend.create_selector_namespace_decommission_fence(request),
            )
            .await
            .ok_or(GtpuSessionSelectorCoordinatorError::Backend)?
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Backend)?;
            if !created.confirms_decommission_fence_exact(expected_created) {
                return Err(GtpuSessionSelectorCoordinatorError::Backend);
            }
        } else if !inspection.confirms_decommission_fence_exact(expected_inspection) {
            return Err(GtpuSessionSelectorCoordinatorError::Backend);
        }

        let window = self
            .mint_backend_mutation_window(lease)
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let request = GtpuSessionSelectorDecommissionReadbackRequest {
            binding,
            fence,
            window,
        };
        let expected_readback = request.receipt_coordinate();
        let readback = settle_selector_backend_step(
            backend.read_selector_namespace_decommission_fence(request),
        )
        .await
        .ok_or(GtpuSessionSelectorCoordinatorError::Backend)?
        .map_err(|_| GtpuSessionSelectorCoordinatorError::Backend)?;
        if !readback.confirms_decommission_fence_exact(expected_readback) {
            return Err(GtpuSessionSelectorCoordinatorError::Backend);
        }

        if state.lifecycle == NamespaceLifecycle::Decommissioning {
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
        let window = self
            .mint_backend_mutation_window(lease)
            .await
            .map_err(|_| GtpuSessionSelectorCoordinatorError::Namespace)?;
        let request = GtpuSessionSelectorDecommissionReadbackRequest {
            binding,
            fence,
            window,
        };
        let expected_cleanup = request.receipt_coordinate();
        let cleanup = settle_selector_backend_step(
            backend.read_selector_namespace_decommission_fence(request),
        )
        .await
        .ok_or(GtpuSessionSelectorCoordinatorError::Backend)?
        .map_err(|_| GtpuSessionSelectorCoordinatorError::Backend)?;
        if !cleanup.confirms_decommission_fence_exact(expected_cleanup) {
            return Err(GtpuSessionSelectorCoordinatorError::Backend);
        }
        Ok(DecommissionAttempt::Complete)
    }

    /// Acquire the sole durable worker lease for an operation. Callers that
    /// cross an Installing/Retiring handoff retain this guard through every
    /// backend observation and terminal fenced CAS; they never reacquire a
    /// competing in-process credential.
    async fn acquire_worker_lease(
        &self,
    ) -> Result<opc_session_store::LeaseGuard, GtpuSessionSelectorNamespaceError> {
        self.store
            .acquire(&self.namespace_key, self.owner.clone(), self.lease_ttl)
            .await
            .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)
    }

    async fn release_worker_lease(
        &self,
        lease: opc_session_store::LeaseGuard,
    ) -> Result<(), GtpuSessionSelectorNamespaceError> {
        self.store
            .release(lease)
            .await
            .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)
    }

    /// Renew immediately before handing authority to a backend. The returned
    /// non-cloneable window remains valid for no more than half the durable
    /// lease (and never more than the fixed backend-effect bound).
    async fn mint_backend_mutation_window(
        &self,
        lease: &mut opc_session_store::LeaseGuard,
    ) -> Result<SelectorBackendMutationWindow, GtpuSessionSelectorNamespaceError> {
        *lease = self
            .store
            .renew(lease, self.lease_ttl)
            .await
            .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
        SelectorBackendMutationWindow::mint(self.lease_ttl)
    }

    /// A release failure means a successful operation can no longer report a
    /// clean handoff, but it must never overwrite the primary failure that
    /// callers need to classify the already-started backend operation.
    async fn finish_worker_operation<T>(
        &self,
        lease: opc_session_store::LeaseGuard,
        result: Result<T, GtpuSessionSelectorCoordinatorError>,
    ) -> Result<T, GtpuSessionSelectorCoordinatorError> {
        let release = self.release_worker_lease(lease).await;
        match result {
            Err(error) => Err(error),
            Ok(value) if release.is_ok() => Ok(value),
            Ok(_) => Err(GtpuSessionSelectorCoordinatorError::Namespace),
        }
    }

    /// After a backend-start handoff, an ambiguous backend observation is
    /// terminal only if the exact fenced poison replacement is durably
    /// readable.  A lost lease, CAS conflict, or readback failure is an
    /// authority failure, not evidence that poison was persisted.
    async fn poison_or_namespace(
        &self,
        desired: &GtpuSessionGroup,
        admission: &GtpuSessionSelectorAdmission,
        reason: PoisonReason,
        lease: &mut opc_session_store::LeaseGuard,
    ) -> Result<(), GtpuSessionSelectorCoordinatorError> {
        self.poison_with_lease(desired, admission, reason, lease)
            .await
            .ok()
            .filter(|persisted| *persisted)
            .map(|_| ())
            .ok_or(GtpuSessionSelectorCoordinatorError::Namespace)
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

    /// Replace only the exact currently durable group coordinate with a
    /// terminal poison record. The lease is renewed by `replace_with_lease`,
    /// and the replacement is accepted only after an exact durable readback.
    /// Therefore a worker that lost its lease, or that races a successor CAS,
    /// cannot poison the successor it no longer owns.
    async fn poison_with_lease(
        &self,
        desired: &GtpuSessionGroup,
        expected: &GtpuSessionSelectorAdmission,
        reason: PoisonReason,
        lease: &mut opc_session_store::LeaseGuard,
    ) -> Result<bool, GtpuSessionSelectorNamespaceError> {
        for _ in 0..MAX_CAS_RETRIES {
            let (record, mut state) = self.read_state().await?;
            let group = state
                .groups
                .get(&expected.group_fingerprint)
                .cloned()
                .ok_or(GtpuSessionSelectorNamespaceError::StaleGeneration)?;
            let canonical = CanonicalClaim::from_group(desired)
                .with_key(&state.selector_digest_key)
                .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
            if canonical.group_fingerprint != expected.group_fingerprint
                || canonical.device_fingerprint != expected.device_fingerprint
                || canonical.selector_set_fingerprint != expected.selector_set_fingerprint
                || canonical.desired_fingerprint != expected.desired_fingerprint
            {
                return Err(GtpuSessionSelectorNamespaceError::StaleGeneration);
            }
            let poison = PoisonRecord::from_group(state.lifecycle, group, reason)
                .ok_or(GtpuSessionSelectorNamespaceError::StaleGeneration)?;
            if poison.generation != expected.generation
                || poison.operation_nonce != expected.operation_nonce
                || poison.terminal_generation.generation != expected.terminal_generation
                || poison.terminal_generation.nonce != expected.terminal_operation_nonce
                || !poison.backend_started
            {
                return Err(GtpuSessionSelectorNamespaceError::StaleGeneration);
            }
            for atom in &poison.atoms {
                state.selectors.insert(
                    *atom,
                    SelectorState::Poisoned {
                        group: expected.group_fingerprint,
                        generation: poison.generation,
                    },
                );
                state.published_atoms.insert(*atom);
            }
            state
                .groups
                .insert(expected.group_fingerprint, GroupState::Poisoned(poison));
            if self
                .replace_with_lease(record.as_ref(), state, lease)
                .await?
            {
                return Ok(true);
            }
        }
        Ok(false)
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
    #[cfg(test)]
    async fn mark_install_backend_started(
        &self,
        desired: &GtpuSessionGroup,
    ) -> Result<BackendStartHandoff, GtpuSessionSelectorNamespaceError> {
        let mut lease = self.acquire_worker_lease().await?;
        let result = self
            .mark_install_backend_started_with_lease(desired, &mut lease)
            .await;
        self.release_worker_lease(lease).await?;
        result
    }

    async fn mark_install_backend_started_with_lease(
        &self,
        desired: &GtpuSessionGroup,
        lease: &mut opc_session_store::LeaseGuard,
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
                reuse,
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
                reuse.is_some(),
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
                    reuse,
                },
            );
            match self.replace_with_lease(record.as_ref(), state, lease).await {
                Ok(true) => return Ok(BackendStartHandoff::Transitioned(admission)),
                Ok(false) => {}
                Err(_) => {
                    // The fenced CAS may have committed before its durable
                    // acknowledgement was lost.  Re-read the exact started
                    // coordinate; callers must recover it, never replay the
                    // stale false-to-true handoff.
                    if let Ok(started) = self.installing_admission(desired, Some(true)).await {
                        return Ok(BackendStartHandoff::AlreadyStarted(started));
                    }
                    return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
                }
            }
        }
        Err(GtpuSessionSelectorNamespaceError::Indeterminate)
    }

    async fn mark_retirement_backend_started_with_lease(
        &self,
        expected: &GtpuSessionGroup,
        lease: &mut opc_session_store::LeaseGuard,
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
                activation_generation,
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
                    activation_generation,
                    previous_terminal,
                    backend_started: true,
                },
            );
            match self.replace_with_lease(record.as_ref(), state, lease).await {
                Ok(true) => return Ok(BackendStartHandoff::Transitioned(admission)),
                Ok(false) => {}
                Err(_) => {
                    if let Ok(started) = self.retiring_admission(expected, Some(true)).await {
                        return Ok(BackendStartHandoff::AlreadyStarted(started));
                    }
                    return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
                }
            }
        }
        Err(GtpuSessionSelectorNamespaceError::Indeterminate)
    }

    async fn activate_claim_with_lease(
        &self,
        desired: &GtpuSessionGroup,
        lease: &mut opc_session_store::LeaseGuard,
    ) -> Result<GtpuSessionSelectorActiveClaim, GtpuSessionSelectorNamespaceError> {
        self.transition_phase_with_lease(desired, 0, lease)
            .await
            .map(GtpuSessionSelectorActiveClaim)
    }

    #[cfg(test)]
    async fn transition_retiring(
        &self,
        admission: &GtpuSessionSelectorAdmission,
    ) -> Result<GtpuSessionSelectorAdmission, GtpuSessionSelectorNamespaceError> {
        let mut lease = self.acquire_worker_lease().await?;
        let result = self
            .transition_retiring_with_lease(admission, &mut lease)
            .await;
        self.release_worker_lease(lease).await?;
        result
    }

    async fn transition_retiring_with_lease(
        &self,
        admission: &GtpuSessionSelectorAdmission,
        lease: &mut opc_session_store::LeaseGuard,
    ) -> Result<GtpuSessionSelectorAdmission, GtpuSessionSelectorNamespaceError> {
        self.transition_phase_for_admission_with_lease(admission, 1, None, lease)
            .await
    }

    async fn transition_retired_with_lease(
        &self,
        admission: &GtpuSessionSelectorAdmission,
        removed_dataplane_generation: NonZeroU64,
        lease: &mut opc_session_store::LeaseGuard,
    ) -> Result<GtpuSessionSelectorAdmission, GtpuSessionSelectorNamespaceError> {
        self.transition_phase_for_admission_with_lease(
            admission,
            2,
            Some(removed_dataplane_generation),
            lease,
        )
        .await
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
            }) if phase == 0 => (
                *device,
                *selectors,
                *desired,
                *generation,
                *operation_nonce,
                None,
            ),
            Some(GroupState::Retired {
                device,
                selectors,
                desired,
                generation,
                operation_nonce,
                retired_dataplane_generation,
                ..
            }) if phase == 2 => (
                *device,
                *selectors,
                *desired,
                *generation,
                *operation_nonce,
                Some(*retired_dataplane_generation),
            ),
            _ => return Err(GtpuSessionSelectorNamespaceError::StaleGeneration),
        };
        let (
            device,
            selectors,
            semantic,
            generation,
            operation_nonce,
            retired_dataplane_generation,
        ) = descriptor;
        if device != claim.device_fingerprint
            || selectors != claim.selector_set_fingerprint
            || semantic != claim.desired_fingerprint
        {
            return Err(GtpuSessionSelectorNamespaceError::StaleGeneration);
        }
        let mut admission = state.issue_admission(
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
        )?;
        admission.retired_dataplane_generation = retired_dataplane_generation;
        Ok(admission)
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
            reuse,
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
            reuse.is_some(),
        )
    }

    /// Reconstruct the exact proof retained by an Installing reissue. A
    /// missing, malformed, or mismatched descriptor is an authority failure
    /// before any backend request can be minted.
    async fn installing_reuse_proof(
        &self,
        desired: &GtpuSessionGroup,
    ) -> Result<Option<crate::GtpuSessionSelectorReuseProof>, GtpuSessionSelectorNamespaceError>
    {
        let canonical = CanonicalClaim::from_group(desired);
        let (_, state) = self.read_state().await?;
        let claim = canonical
            .with_key(&state.selector_digest_key)
            .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
        let Some(GroupState::Installing {
            device,
            selectors,
            desired: semantic,
            reuse,
            ..
        }) = state.groups.get(&claim.group_fingerprint)
        else {
            return Err(GtpuSessionSelectorNamespaceError::StaleGeneration);
        };
        if *device != claim.device_fingerprint
            || *selectors != claim.selector_set_fingerprint
            || *semantic != claim.desired_fingerprint
        {
            return Err(GtpuSessionSelectorNamespaceError::StaleGeneration);
        }
        match reuse {
            Some(descriptor) => descriptor
                .proof(&state.selector_digest_key)
                .map(Some)
                .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate),
            None => Ok(None),
        }
    }

    async fn transition_phase_with_lease(
        &self,
        desired: &GtpuSessionGroup,
        phase: u8,
        lease: &mut opc_session_store::LeaseGuard,
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
                reuse,
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
                    reuse.is_some(),
                )?
            }
            _ => return Err(GtpuSessionSelectorNamespaceError::StaleGeneration),
        };
        self.transition_phase_for_admission_with_lease(&admission, phase, None, lease)
            .await
    }

    async fn transition_phase_for_admission_with_lease(
        &self,
        admission: &GtpuSessionSelectorAdmission,
        phase: u8,
        retired_dataplane_generation: Option<NonZeroU64>,
        lease: &mut opc_session_store::LeaseGuard,
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
                        ..
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
                        || retired_dataplane_generation.is_some()
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
                        || retired_dataplane_generation.is_some()
                    {
                        return Err(GtpuSessionSelectorNamespaceError::StaleGeneration);
                    }
                    let pending_generation = state.next_generation()?;
                    let pending_nonce = random_nonzero_nonce()?;
                    let terminal_generation = state.next_generation()?;
                    let terminal_operation_nonce = random_distinct_nonzero_nonce(pending_nonce)?;
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
                            activation_generation: generation,
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
                        activation_generation,
                        previous_terminal,
                        backend_started,
                    },
                ) => {
                    let retired_dataplane_generation = retired_dataplane_generation
                        .ok_or(GtpuSessionSelectorNamespaceError::StaleGeneration)?;
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
                            activation_generation,
                            retired_dataplane_generation,
                            successor: None,
                        },
                    );
                    let mut retired = admission.with_coordinates(
                        terminal_generation,
                        terminal_operation_nonce,
                        SelectorAuthorityCoordinate {
                            generation: terminal_generation,
                            nonce: terminal_operation_nonce,
                        },
                        None,
                        SelectorAdmissionPhase::Retired,
                    )?;
                    retired.retired_dataplane_generation = Some(retired_dataplane_generation);
                    retired
                }
                _ => return Err(GtpuSessionSelectorNamespaceError::StaleGeneration),
            };
            if self
                .replace_with_lease(record.as_ref(), state, lease)
                .await?
            {
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
    Decommissioning,
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
    selector_digest_key: Zeroizing<[u8; 32]>,
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
    /// Protected canonical desired descriptors for every permanent group.
    /// This is the durable source of operation-stamp key reconstruction.
    canonical_desired: BTreeMap<[u8; 32], Zeroizing<Vec<u8>>>,
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
            || *self.selector_digest_key != [0; 32]
            || self.key_commitment != [0; 32]
            || self.decommission_fence.is_some()
            || !self.selectors.is_empty()
            || !self.groups.is_empty()
            || !self.canonical_desired.is_empty()
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
            .try_fill_bytes(&mut *self.selector_digest_key)
            .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
        if self.ledger_id == [0; 16]
            || self.backend_epoch == [0; 16]
            || *self.selector_digest_key == [0; 32]
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
                if terminal.generation.get() <= generation.get()
                    || terminal.nonce == operation_nonce
                    || previous_terminal.is_some()
                {
                    return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
                }
            }
            SelectorAdmissionPhase::Retiring => {
                if terminal.generation.get() <= generation.get()
                    || terminal.nonce == operation_nonce
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
            selector_digest_key: Zeroizing::new(*self.selector_digest_key),
            device_fingerprint: claim.device_fingerprint,
            group_fingerprint: claim.group_fingerprint,
            selector_set_fingerprint: claim.selector_set_fingerprint,
            desired_fingerprint: claim.desired_fingerprint,
            generation,
            operation_nonce,
            terminal_generation: terminal.generation,
            terminal_operation_nonce: terminal.nonce,
            previous_terminal,
            retired_dataplane_generation: None,
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
            || *self.selector_digest_key == [0; 32]
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

    fn decommission_binding_codec(&self) -> Result<[u8; 145], GtpuSessionSelectorNamespaceError> {
        let stable_device = self
            .stable_device
            .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
        if self.pin_commitment == [0; 32]
            || self.storage_scope_commitment == [0; 32]
            || self.ledger_id == [0; 16]
            || self.backend_epoch == [0; 16]
            || self.key_commitment == [0; 32]
            || *self.selector_digest_key == [0; 32]
        {
            return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
        }
        let mut codec = [0_u8; 145];
        codec[0] = 1;
        codec[1..33].copy_from_slice(&self.pin_commitment);
        codec[33..49].copy_from_slice(&stable_device);
        codec[49..65].copy_from_slice(&self.ledger_id);
        codec[65..97].copy_from_slice(&self.key_commitment);
        codec[97..129].copy_from_slice(&self.storage_scope_commitment);
        codec[129..145].copy_from_slice(&self.backend_epoch);
        Ok(codec)
    }

    fn decommission_fence_is_exact(&self, fence: DecommissionFence) -> bool {
        fence.predecessor_commitment != [0; 32]
            && fence.decommissioning.nonce != [0; 16]
            && fence.decommissioned.nonce != [0; 16]
            && fence.decommissioning.generation.get() < fence.decommissioned.generation.get()
            && fence.decommissioned.generation.get() <= self.generation
            && self.decommission_capsule_is_exact(fence).is_ok()
    }

    fn precommit_decommission(
        &mut self,
        predecessor_generation: Generation,
        predecessor_plaintext: &[u8],
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
        if predecessor_plaintext.len() > MAX_RECORD_BYTES || predecessor_generation.get() == 0 {
            return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
        }
        let mut predecessor_codec = Vec::with_capacity(1 + 8 + 8 + predecessor_plaintext.len());
        predecessor_codec.push(1);
        predecessor_codec.extend_from_slice(&predecessor_generation.get().to_be_bytes());
        predecessor_codec.extend_from_slice(&(predecessor_plaintext.len() as u64).to_be_bytes());
        predecessor_codec.extend_from_slice(predecessor_plaintext);
        let predecessor_commitment = keyed_digest(
            &self.selector_digest_key,
            PRE_DECOMMISSION_BOUND_DOMAIN,
            &predecessor_codec,
        );
        let decommissioning = SelectorAuthorityCoordinate {
            generation: self.next_generation()?,
            nonce: random_nonzero_nonce()?,
        };
        let decommissioned = SelectorAuthorityCoordinate {
            generation: self.next_generation()?,
            nonce: random_nonzero_nonce()?,
        };
        let capsule =
            self.decommission_capsule(predecessor_commitment, decommissioning, decommissioned)?;
        let fence = DecommissionFence {
            predecessor_commitment,
            decommissioning,
            decommissioned,
            capsule,
        };
        self.lifecycle = NamespaceLifecycle::Decommissioning;
        self.decommission_fence = Some(fence);
        Ok(fence)
    }

    fn decommission_capsule(
        &self,
        predecessor_commitment: [u8; 32],
        decommissioning: SelectorAuthorityCoordinate,
        decommissioned: SelectorAuthorityCoordinate,
    ) -> Result<[u8; DECOMMISSION_CAPSULE_LEN], GtpuSessionSelectorNamespaceError> {
        if predecessor_commitment == [0; 32]
            || decommissioning.nonce == [0; 16]
            || decommissioned.nonce == [0; 16]
            || decommissioning.generation.get() >= decommissioned.generation.get()
        {
            return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
        }
        let binding = self.decommission_binding_codec()?;
        let aead_key = Zeroizing::new(keyed_digest(
            &self.selector_digest_key,
            DECOMMISSION_AEAD_KEY_DOMAIN,
            &binding,
        ));
        let nonce_key = Zeroizing::new(keyed_digest(
            &self.selector_digest_key,
            DECOMMISSION_NONCE_KEY_DOMAIN,
            &binding,
        ));
        let mut aad = Vec::with_capacity(DECOMMISSION_AAD_DOMAIN.len() + binding.len());
        aad.extend_from_slice(DECOMMISSION_AAD_DOMAIN);
        aad.extend_from_slice(&binding);
        let mut coordinate = [0_u8; DECOMMISSION_COORDINATE_LEN];
        coordinate[0] = 1;
        coordinate[1..33].copy_from_slice(&predecessor_commitment);
        coordinate[33..41].copy_from_slice(&decommissioning.generation.get().to_be_bytes());
        coordinate[41..57].copy_from_slice(&decommissioning.nonce);
        coordinate[57..65].copy_from_slice(&decommissioned.generation.get().to_be_bytes());
        coordinate[65..81].copy_from_slice(&decommissioned.nonce);
        let nonce = hmac_bytes(&nonce_key, &[aad.as_slice(), coordinate.as_slice()]);
        let cipher = Aes256GcmSiv::new(GenericArray::from_slice(aead_key.as_ref()));
        let mut ciphertext = coordinate;
        let tag = cipher
            .encrypt_in_place_detached(
                GenericArray::from_slice(&nonce[..12]),
                &aad,
                &mut ciphertext,
            )
            .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
        let mut capsule = [0_u8; DECOMMISSION_CAPSULE_LEN];
        capsule[0] = 1;
        capsule[1..13].copy_from_slice(&nonce[..12]);
        capsule[13..94].copy_from_slice(&ciphertext);
        capsule[94..110].copy_from_slice(tag.as_slice());
        Ok(capsule)
    }

    fn decommission_capsule_is_exact(
        &self,
        fence: DecommissionFence,
    ) -> Result<(), GtpuSessionSelectorNamespaceError> {
        let binding = self.decommission_binding_codec()?;
        if fence.capsule[0] != 1 {
            return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
        }
        let aead_key = Zeroizing::new(keyed_digest(
            &self.selector_digest_key,
            DECOMMISSION_AEAD_KEY_DOMAIN,
            &binding,
        ));
        let nonce_key = Zeroizing::new(keyed_digest(
            &self.selector_digest_key,
            DECOMMISSION_NONCE_KEY_DOMAIN,
            &binding,
        ));
        let mut aad = Vec::with_capacity(DECOMMISSION_AAD_DOMAIN.len() + binding.len());
        aad.extend_from_slice(DECOMMISSION_AAD_DOMAIN);
        aad.extend_from_slice(&binding);
        let cipher = Aes256GcmSiv::new(GenericArray::from_slice(aead_key.as_ref()));
        let mut coordinate = [0_u8; DECOMMISSION_COORDINATE_LEN];
        coordinate.copy_from_slice(&fence.capsule[13..94]);
        let tag = GenericArray::clone_from_slice(&fence.capsule[94..110]);
        cipher
            .decrypt_in_place_detached(
                GenericArray::from_slice(&fence.capsule[1..13]),
                &aad,
                &mut coordinate,
                &tag,
            )
            .map_err(|_| GtpuSessionSelectorNamespaceError::Indeterminate)?;
        let expected_nonce = hmac_bytes(&nonce_key, &[aad.as_slice(), coordinate.as_slice()]);
        if coordinate[0] != 1
            || !bool::from(fence.capsule[1..13].ct_eq(&expected_nonce[..12]))
            || !bool::from(coordinate[1..33].ct_eq(&fence.predecessor_commitment))
            || !bool::from(
                coordinate[33..41].ct_eq(&fence.decommissioning.generation.get().to_be_bytes()),
            )
            || !bool::from(coordinate[41..57].ct_eq(&fence.decommissioning.nonce))
            || !bool::from(
                coordinate[57..65].ct_eq(&fence.decommissioned.generation.get().to_be_bytes()),
            )
            || !bool::from(coordinate[65..81].ct_eq(&fence.decommissioned.nonce))
        {
            return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
        }
        Ok(())
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
                && self.pin_commitment == [0; 32]
                && self.storage_scope_commitment == [0; 32]
                && self.selectors.is_empty()
                && self.groups.is_empty()
                && self.canonical_desired.is_empty()
                && self.published_atoms.is_empty()
                && self.tombstones.is_empty()
                && self.capacity == 0
                && self.decommission_fence.is_none()
                && self.ledger_id == [0; 16]
                && self.backend_epoch == [0; 16]
                && *self.selector_digest_key == [0; 32]
                && self.key_commitment == [0; 32] =>
            {
                let mut ledger_id = [0_u8; 16];
                let mut backend_epoch = [0_u8; 16];
                let mut selector_digest_key = Zeroizing::new([0_u8; 32]);
                if let Some(supplied) = supplied_selector_digest_key {
                    selector_digest_key = Zeroizing::new(supplied);
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
                        .try_fill_bytes(&mut *selector_digest_key)
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
                    && *self.selector_digest_key != [0; 32]
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
                        .is_none_or(|key| key == *self.selector_digest_key)
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
                .canonical_desired
                .len()
                .checked_add(1)
                .is_none_or(|value| value > MAX_CANONICAL_DESIRED_RECORDS)
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
        // protected canonical desired index, append-only historical atom
        // index (32/atom), and tombstones reserved for retirement.
        let additional = atoms
            .checked_mul(169)
            .and_then(|value| value.checked_add(157 + 32 + 2 + MAX_CANONICAL_DESIRED_BYTES))
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
                .canonical_desired
                .len()
                .checked_add(1)
                .is_none_or(|value| value > MAX_CANONICAL_DESIRED_RECORDS)
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
            .and_then(|value| {
                value.checked_add(
                    223 + MAX_REUSED_INSTALL_DESCRIPTOR_BYTES
                        + 32
                        + 2
                        + MAX_CANONICAL_DESIRED_BYTES,
                )
            })
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
                GroupState::Poisoned(poison) => poison.atoms.len(),
                GroupState::LegacyPoisoned => 0,
            })
            .sum()
    }

    fn retain_canonical_desired(
        &mut self,
        group_fingerprint: [u8; 32],
        group: &GtpuSessionGroup,
    ) -> Result<(), GtpuSessionSelectorNamespaceError> {
        let desired = canonical_desired_bytes(group);
        if desired.is_empty() || desired.len() > MAX_CANONICAL_DESIRED_BYTES {
            return Err(GtpuSessionSelectorNamespaceError::CapacityExhausted);
        }
        match self.canonical_desired.get(&group_fingerprint) {
            Some(existing) if existing.as_slice() == desired.as_slice() => Ok(()),
            Some(_) => Err(GtpuSessionSelectorNamespaceError::Indeterminate),
            None if self.canonical_desired.len() < MAX_CANONICAL_DESIRED_RECORDS => {
                self.canonical_desired
                    .insert(group_fingerprint, Zeroizing::new(desired));
                Ok(())
            }
            None => Err(GtpuSessionSelectorNamespaceError::CapacityExhausted),
        }
    }

    fn canonical_group_for(&self, group_fingerprint: [u8; 32]) -> Option<GtpuSessionGroup> {
        let desired = self.canonical_desired.get(&group_fingerprint)?;
        let group = decode_canonical_desired(desired)?;
        (canonical_desired_bytes(&group) == **desired).then_some(group)
    }

    fn operation_stamp_inventory(
        &self,
        binding: GtpuSessionSelectorBackendBinding,
    ) -> Result<SelectorOperationStampInventory, GtpuSessionSelectorNamespaceError> {
        if self.lifecycle != NamespaceLifecycle::Bound
            || self.decommission_fence.is_some()
            || self.groups.len() != self.canonical_desired.len()
        {
            return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
        }
        let mut ordered = BTreeMap::new();
        for (group_fingerprint, group_state) in &self.groups {
            let group = self
                .canonical_group_for(*group_fingerprint)
                .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
            let claim = CanonicalClaim::from_group(&group)
                .with_key(&self.selector_digest_key)
                .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
            if claim.group_fingerprint != *group_fingerprint {
                return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
            }
            let (device_fingerprint, selector_set_fingerprint, desired_fingerprint, lifecycle) =
                match group_state {
                    GroupState::Installing {
                        device,
                        selectors,
                        desired,
                        generation,
                        operation_nonce,
                        terminal_generation,
                        terminal_operation_nonce,
                        backend_started,
                        ..
                    } => (
                        *device,
                        *selectors,
                        *desired,
                        SelectorOperationStampLifecycleExpectation::Installing {
                            backend_started: *backend_started,
                            pending: SelectorOperationStampCoordinate {
                                generation: *generation,
                                nonce: *operation_nonce,
                            },
                            terminal: SelectorOperationStampCoordinate {
                                generation: *terminal_generation,
                                nonce: *terminal_operation_nonce,
                            },
                        },
                    ),
                    GroupState::Active {
                        device,
                        selectors,
                        desired,
                        generation,
                        operation_nonce,
                        ..
                    } => (
                        *device,
                        *selectors,
                        *desired,
                        SelectorOperationStampLifecycleExpectation::Active {
                            terminal: SelectorOperationStampCoordinate {
                                generation: *generation,
                                nonce: *operation_nonce,
                            },
                        },
                    ),
                    GroupState::Retiring {
                        device,
                        selectors,
                        desired,
                        generation,
                        operation_nonce,
                        terminal_generation,
                        terminal_operation_nonce,
                        previous_terminal,
                        backend_started,
                        ..
                    } => (
                        *device,
                        *selectors,
                        *desired,
                        SelectorOperationStampLifecycleExpectation::Retiring {
                            backend_started: *backend_started,
                            pending: SelectorOperationStampCoordinate {
                                generation: *generation,
                                nonce: *operation_nonce,
                            },
                            terminal: SelectorOperationStampCoordinate {
                                generation: *terminal_generation,
                                nonce: *terminal_operation_nonce,
                            },
                            previous_terminal: SelectorOperationStampCoordinate::from_authority(
                                *previous_terminal,
                            ),
                        },
                    ),
                    GroupState::Retired {
                        device,
                        selectors,
                        desired,
                        generation,
                        operation_nonce,
                        retired_dataplane_generation,
                        ..
                    } => (
                        *device,
                        *selectors,
                        *desired,
                        SelectorOperationStampLifecycleExpectation::Retired {
                            terminal: SelectorOperationStampCoordinate {
                                generation: *generation,
                                nonce: *operation_nonce,
                            },
                            retired_dataplane_generation: *retired_dataplane_generation,
                        },
                    ),
                    GroupState::Poisoned(poison) => (
                        poison.device,
                        poison.selectors,
                        poison.desired,
                        SelectorOperationStampLifecycleExpectation::Poisoned {
                            phase: poison.phase,
                            reason: poison.reason.tag(),
                            pending: SelectorOperationStampCoordinate {
                                generation: poison.generation,
                                nonce: poison.operation_nonce,
                            },
                            terminal: SelectorOperationStampCoordinate::from_authority(
                                poison.terminal_generation,
                            ),
                            previous_terminal: poison
                                .previous_terminal
                                .map(SelectorOperationStampCoordinate::from_authority),
                            retired_dataplane_generation: poison.retired_dataplane_generation,
                        },
                    ),
                    // An old unit poison lacks the complete canonical
                    // inventory authority and must never serve a Bound open.
                    GroupState::LegacyPoisoned => {
                        return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
                    }
                };
            if device_fingerprint != claim.device_fingerprint
                || selector_set_fingerprint != claim.selector_set_fingerprint
                || desired_fingerprint != claim.desired_fingerprint
            {
                return Err(GtpuSessionSelectorNamespaceError::Indeterminate);
            }
            let key = group.id().to_bytes();
            ordered
                .insert(
                    key,
                    SelectorOperationStampInventoryExpectation {
                        group,
                        device_fingerprint,
                        group_fingerprint: *group_fingerprint,
                        selector_set_fingerprint,
                        desired_fingerprint,
                        lifecycle,
                    },
                )
                .is_none()
                .then_some(())
                .ok_or(GtpuSessionSelectorNamespaceError::Indeterminate)?;
        }
        let expectations: Vec<_> = ordered.into_values().collect();
        if expectations.len() > SELECTOR_NAMESPACE_MAX_STAMP_SLOTS {
            return Err(GtpuSessionSelectorNamespaceError::CapacityExhausted);
        }
        let mut digest = Sha256::new();
        digest.update(OPERATION_INVENTORY_DOMAIN);
        update_receipt_binding(&mut digest, binding);
        for expectation in &expectations {
            digest.update(expectation.group.id().to_bytes());
            digest.update(expectation.device_fingerprint);
            digest.update(expectation.group_fingerprint);
            digest.update(expectation.selector_set_fingerprint);
            digest.update(expectation.desired_fingerprint);
            update_inventory_lifecycle(&mut digest, expectation.lifecycle);
        }
        Ok(SelectorOperationStampInventory {
            expectations,
            summary: digest.finalize().into(),
        })
    }

    fn reused_install_descriptor_is_exact(
        &self,
        successor_group: [u8; 32],
        successor_generation: GtpuSessionSelectorAuthorityGeneration,
        successor_atoms: &BTreeSet<[u8; 32]>,
        descriptor: &ReusedInstallDescriptor,
    ) -> bool {
        let Some(proof) = descriptor.proof(&self.selector_digest_key) else {
            return false;
        };
        let Some(source) =
            CanonicalClaim::from_group(proof.retired_group()).with_key(&self.selector_digest_key)
        else {
            return false;
        };
        let Some(source_atoms) = source.selector_atoms(&self.selector_digest_key) else {
            return false;
        };
        source_atoms == *successor_atoms
            && matches!(
                self.groups.get(&source.group_fingerprint),
                Some(GroupState::Retired {
                    device,
                    selectors,
                    desired,
                    generation,
                    operation_nonce,
                    retired_dataplane_generation,
                    successor: Some(edge),
                    ..
                }) if *device == descriptor.source_device
                    && *selectors == descriptor.source_selectors
                    && *desired == descriptor.source_desired_fingerprint
                    && *generation == descriptor.source_generation
                    && *operation_nonce == descriptor.source_operation_nonce
                    && *retired_dataplane_generation == descriptor.source_retired_dataplane_generation
                    && edge.group == successor_group
                    && edge.generation == successor_generation
            )
    }

    fn successor_lineage_is_exact(&self, successor: RetiredSuccessor) -> bool {
        let immediately_following = |activation: GtpuSessionSelectorAuthorityGeneration| {
            successor
                .generation
                .get()
                .checked_add(1)
                .is_some_and(|generation| generation == activation.get())
        };
        match self.groups.get(&successor.group) {
            Some(GroupState::Installing { generation, .. }) => *generation == successor.generation,
            Some(GroupState::Active { generation, .. }) => immediately_following(*generation),
            Some(GroupState::Retiring {
                activation_generation,
                ..
            })
            | Some(GroupState::Retired {
                activation_generation,
                ..
            }) => immediately_following(*activation_generation),
            Some(GroupState::Poisoned(poison)) => successor
                .generation
                .get()
                .checked_add(u64::from(poison.phase))
                .is_some_and(|generation| generation == poison.generation.get()),
            Some(GroupState::LegacyPoisoned) | None => false,
        }
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
        // OPCSN15 retains the protected canonical desired index and every
        // poisoned-retiring prior terminal coordinate needed for exact
        // operation-stamp inventory reconstruction. Older schemas lack this
        // authority and therefore fail closed on production open.
        output.extend_from_slice(b"OPCSN15");
        output.push(match self.lifecycle {
            NamespaceLifecycle::Unprovisioned => 0,
            NamespaceLifecycle::Provisioned => 1,
            NamespaceLifecycle::Initializing => 2,
            NamespaceLifecycle::Bound => 3,
            NamespaceLifecycle::Decommissioning => 4,
            NamespaceLifecycle::Decommissioned => 5,
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
        output.extend_from_slice(&*self.selector_digest_key);
        output.extend_from_slice(&self.key_commitment);
        output.extend_from_slice(&self.capacity.to_be_bytes());
        output.extend_from_slice(&self.generation.to_be_bytes());
        match self.decommission_fence {
            None => output.push(0),
            Some(fence) => {
                output.push(1);
                output.extend_from_slice(&fence.predecessor_commitment);
                output.extend_from_slice(&fence.decommissioning.generation.get().to_be_bytes());
                output.extend_from_slice(&fence.decommissioning.nonce);
                output.extend_from_slice(&fence.decommissioned.generation.get().to_be_bytes());
                output.extend_from_slice(&fence.decommissioned.nonce);
                output.extend_from_slice(&fence.capsule);
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
                SelectorState::Poisoned { group, generation } => {
                    output.push(4);
                    output.extend_from_slice(group);
                    output.extend_from_slice(&generation.get().to_be_bytes());
                }
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
                    reuse,
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
                    match reuse {
                        None => output.push(0),
                        Some(reuse) => {
                            output.push(1);
                            output.extend_from_slice(
                                &u16::try_from(reuse.source_desired.len())
                                    .unwrap_or(u16::MAX)
                                    .to_be_bytes(),
                            );
                            output.extend_from_slice(&reuse.source_desired);
                            output.push(match reuse.evidence {
                                crate::GtpuSessionSelectorReuseEvidence::TrafficDrained => 0,
                                crate::GtpuSessionSelectorReuseEvidence::RcuGracePeriodElapsed => 1,
                            });
                            output.extend_from_slice(&reuse.source_device);
                            output.extend_from_slice(&reuse.source_selectors);
                            output.extend_from_slice(&reuse.source_desired_fingerprint);
                            output.extend_from_slice(&reuse.source_generation.get().to_be_bytes());
                            output.extend_from_slice(&reuse.source_operation_nonce);
                            output.extend_from_slice(
                                &reuse
                                    .source_retired_dataplane_generation
                                    .get()
                                    .to_be_bytes(),
                            );
                        }
                    }
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
                    activation_generation,
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
                    output.extend_from_slice(&activation_generation.get().to_be_bytes());
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
                    activation_generation,
                    generation,
                    operation_nonce,
                    retired_dataplane_generation,
                    successor,
                } => {
                    output.push(3);
                    output.extend_from_slice(device);
                    output.extend_from_slice(selectors);
                    output.extend_from_slice(desired);
                    output.extend_from_slice(&generation.get().to_be_bytes());
                    output.extend_from_slice(operation_nonce);
                    output.extend_from_slice(&activation_generation.get().to_be_bytes());
                    output.extend_from_slice(&(atoms.len() as u32).to_be_bytes());
                    for atom in atoms {
                        output.extend_from_slice(atom);
                    }
                    output.extend_from_slice(&retired_dataplane_generation.get().to_be_bytes());
                    match successor {
                        None => output.push(0),
                        Some(successor) => {
                            output.push(1);
                            output.extend_from_slice(&successor.group);
                            output.extend_from_slice(&successor.generation.get().to_be_bytes());
                        }
                    }
                }
                GroupState::Poisoned(poison) => {
                    output.push(4);
                    poison.encode(&mut output);
                }
                GroupState::LegacyPoisoned => output.push(5),
            }
        }
        output.extend_from_slice(&(self.canonical_desired.len() as u32).to_be_bytes());
        for (group, desired) in &self.canonical_desired {
            output.extend_from_slice(group);
            output.extend_from_slice(
                &u16::try_from(desired.len())
                    .unwrap_or(u16::MAX)
                    .to_be_bytes(),
            );
            output.extend_from_slice(desired);
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
        let version = take(bytes, &mut cursor, 7)?;
        (version == b"OPCSN15").then_some(())?;
        let lifecycle = match *take(bytes, &mut cursor, 1)?.first()? {
            0 => NamespaceLifecycle::Unprovisioned,
            1 => NamespaceLifecycle::Provisioned,
            2 => NamespaceLifecycle::Initializing,
            3 => NamespaceLifecycle::Bound,
            4 => NamespaceLifecycle::Decommissioning,
            5 => NamespaceLifecycle::Decommissioned,
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
        let selector_digest_key = Zeroizing::new(take_array(take(bytes, &mut cursor, 32)?)?);
        let key_commitment = take_array(take(bytes, &mut cursor, 32)?)?;
        let capacity = u32::from_be_bytes(take_array(take(bytes, &mut cursor, 4)?)?);
        let generation = u64::from_be_bytes(take_array(take(bytes, &mut cursor, 8)?)?);
        let decommission_fence = match *take(bytes, &mut cursor, 1)?.first()? {
            0 => None,
            1 => Some(DecommissionFence {
                predecessor_commitment: take_array(take(bytes, &mut cursor, 32)?)?,
                decommissioning: SelectorAuthorityCoordinate {
                    generation: GtpuSessionSelectorAuthorityGeneration(NonZeroU64::new(
                        u64::from_be_bytes(take_array(take(bytes, &mut cursor, 8)?)?),
                    )?),
                    nonce: take_array(take(bytes, &mut cursor, 16)?)?,
                },
                decommissioned: SelectorAuthorityCoordinate {
                    generation: GtpuSessionSelectorAuthorityGeneration(NonZeroU64::new(
                        u64::from_be_bytes(take_array(take(bytes, &mut cursor, 8)?)?),
                    )?),
                    nonce: take_array(take(bytes, &mut cursor, 16)?)?,
                },
                capsule: take_array(take(bytes, &mut cursor, DECOMMISSION_CAPSULE_LEN)?)?,
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
                4 => SelectorState::Poisoned {
                    group: take_array(take(bytes, &mut cursor, 32)?)?,
                    generation: GtpuSessionSelectorAuthorityGeneration(NonZeroU64::new(
                        u64::from_be_bytes(take_array(take(bytes, &mut cursor, 8)?)?),
                    )?),
                },
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
                                && terminal_operation_nonce != operation_nonce
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
                    let activation_generation = if tag == 2 || tag == 3 {
                        Some(GtpuSessionSelectorAuthorityGeneration(NonZeroU64::new(
                            u64::from_be_bytes(take_array(take(bytes, &mut cursor, 8)?)?),
                        )?))
                    } else {
                        None
                    };
                    if tag == 2
                        && activation_generation != previous_terminal.map(|value| value.generation)
                    {
                        return None;
                    }
                    if tag == 3 && activation_generation?.get() >= generation.get() {
                        return None;
                    }
                    let backend_started = if tag == 0 || tag == 2 {
                        match *take(bytes, &mut cursor, 1)?.first()? {
                            0 => false,
                            1 => true,
                            _ => return None,
                        }
                    } else {
                        false
                    };
                    let reuse = if tag == 0 {
                        match *take(bytes, &mut cursor, 1)?.first()? {
                            0 => None,
                            1 => {
                                let len = usize::from(u16::from_be_bytes(take_array(take(
                                    bytes,
                                    &mut cursor,
                                    2,
                                )?)?));
                                if len > MAX_CANONICAL_DESIRED_BYTES {
                                    return None;
                                }
                                let source_desired =
                                    Zeroizing::new(take(bytes, &mut cursor, len)?.to_vec());
                                let evidence = match *take(bytes, &mut cursor, 1)?.first()? {
                                    0 => crate::GtpuSessionSelectorReuseEvidence::TrafficDrained,
                                    1 => crate::GtpuSessionSelectorReuseEvidence::RcuGracePeriodElapsed,
                                    _ => return None,
                                };
                                let source_device = take_array(take(bytes, &mut cursor, 32)?)?;
                                let source_selectors = take_array(take(bytes, &mut cursor, 32)?)?;
                                let source_desired_fingerprint =
                                    take_array(take(bytes, &mut cursor, 32)?)?;
                                let source_generation = GtpuSessionSelectorAuthorityGeneration(
                                    NonZeroU64::new(u64::from_be_bytes(take_array(take(
                                        bytes,
                                        &mut cursor,
                                        8,
                                    )?)?))?,
                                );
                                let source_operation_nonce =
                                    take_array(take(bytes, &mut cursor, 16)?)?;
                                let source_retired_dataplane_generation = NonZeroU64::new(
                                    u64::from_be_bytes(take_array(take(bytes, &mut cursor, 8)?)?),
                                )?;
                                (source_operation_nonce != [0; 16]
                                    && decode_canonical_desired(&source_desired).is_some())
                                .then_some(ReusedInstallDescriptor {
                                    source_desired,
                                    evidence,
                                    source_device,
                                    source_selectors,
                                    source_desired_fingerprint,
                                    source_generation,
                                    source_operation_nonce,
                                    source_retired_dataplane_generation,
                                })
                            }
                            _ => return None,
                        }
                    } else {
                        None
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
                            reuse,
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
                            activation_generation: activation_generation?,
                            previous_terminal: previous_terminal?,
                            backend_started,
                        }
                    } else {
                        let retired_dataplane_generation = NonZeroU64::new(u64::from_be_bytes(
                            take_array(take(bytes, &mut cursor, 8)?)?,
                        ))?;
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
                            activation_generation: activation_generation?,
                            generation: GtpuSessionSelectorAuthorityGeneration(generation),
                            operation_nonce,
                            retired_dataplane_generation,
                            successor,
                        }
                    }
                }
                4 => GroupState::Poisoned(PoisonRecord::decode(bytes, &mut cursor)?),
                _ => return None,
            };
            groups.insert(digest, state).is_none().then_some(())?;
        }
        let canonical_desired_count =
            u32::from_be_bytes(take_array(take(bytes, &mut cursor, 4)?)?) as usize;
        if canonical_desired_count > MAX_CANONICAL_DESIRED_RECORDS {
            return None;
        }
        let mut canonical_desired = BTreeMap::new();
        let mut previous_canonical_group = None;
        for _ in 0..canonical_desired_count {
            let group = take_array(take(bytes, &mut cursor, 32)?)?;
            if previous_canonical_group.is_some_and(|previous| previous >= group) {
                return None;
            }
            previous_canonical_group = Some(group);
            let length = u16::from_be_bytes(take_array(take(bytes, &mut cursor, 2)?)?) as usize;
            if length == 0 || length > MAX_CANONICAL_DESIRED_BYTES {
                return None;
            }
            let desired = take(bytes, &mut cursor, length)?.to_vec();
            canonical_desired
                .insert(group, Zeroizing::new(desired))
                .is_none()
                .then_some(())?;
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
            canonical_desired,
            published_atoms,
            tombstones,
        };
        (cursor == bytes.len() && state.is_complete()).then_some(state)
    }

    fn canonical_desired_index_is_exact(&self) -> bool {
        self.groups.iter().all(|(group_fingerprint, group_state)| {
            if self
                .canonical_desired
                .get(group_fingerprint)
                .is_none_or(|desired| {
                    desired.is_empty() || desired.len() > MAX_CANONICAL_DESIRED_BYTES
                })
            {
                return false;
            }
            let Some(group) = self.canonical_group_for(*group_fingerprint) else {
                return false;
            };
            let Some(claim) =
                CanonicalClaim::from_group(&group).with_key(&self.selector_digest_key)
            else {
                return false;
            };
            let (device, selectors, desired, atoms) = match group_state {
                GroupState::Installing {
                    device,
                    selectors,
                    desired,
                    atoms,
                    ..
                }
                | GroupState::Active {
                    device,
                    selectors,
                    desired,
                    atoms,
                    ..
                }
                | GroupState::Retiring {
                    device,
                    selectors,
                    desired,
                    atoms,
                    ..
                }
                | GroupState::Retired {
                    device,
                    selectors,
                    desired,
                    atoms,
                    ..
                } => (*device, *selectors, *desired, atoms),
                GroupState::Poisoned(poison) => (
                    poison.device,
                    poison.selectors,
                    poison.desired,
                    &poison.atoms,
                ),
                GroupState::LegacyPoisoned => return false,
            };
            claim.group_fingerprint == *group_fingerprint
                && claim.device_fingerprint == device
                && claim.selector_set_fingerprint == selectors
                && claim.desired_fingerprint == desired
                && claim
                    .selector_atoms(&self.selector_digest_key)
                    .is_some_and(|expected_atoms| expected_atoms == *atoms)
        })
    }

    fn is_complete(&self) -> bool {
        let empty = self.stable_device.is_none()
            && self.pin_commitment == [0; 32]
            && self.storage_scope_commitment == [0; 32]
            && self.generation == 0
            && self.capacity == 0
            && self.ledger_id == [0; 16]
            && self.backend_epoch == [0; 16]
            && *self.selector_digest_key == [0; 32]
            && self.key_commitment == [0; 32]
            && self.decommission_fence.is_none()
            && self.selectors.is_empty()
            && self.groups.is_empty()
            && self.canonical_desired.is_empty()
            && self.published_atoms.is_empty()
            && self.tombstones.is_empty();
        let initialized = self.stable_device.is_some()
            && self.pin_commitment != [0; 32]
            && self.storage_scope_commitment != [0; 32]
            && self.capacity > 0
            && self.ledger_id != [0; 16]
            && self.backend_epoch != [0; 16]
            && *self.selector_digest_key != [0; 32]
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
            && *self.selector_digest_key == [0; 32]
            && self.key_commitment == [0; 32]
            && self.decommission_fence.is_none()
            && self.selectors.is_empty()
            && self.groups.is_empty()
            && self.canonical_desired.is_empty()
            && self.published_atoms.is_empty()
            && self.tombstones.is_empty();
        let lifecycle_complete = match self.lifecycle {
            NamespaceLifecycle::Unprovisioned => empty,
            NamespaceLifecycle::Provisioned => provisioned,
            NamespaceLifecycle::Initializing => initialized && self.decommission_fence.is_none(),
            NamespaceLifecycle::Bound => initialized,
            NamespaceLifecycle::Decommissioning => {
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
            && self.groups.iter().all(|(group_digest, group)| match group {
                GroupState::Installing {
                    device,
                    atoms,
                    generation,
                    operation_nonce,
                    terminal_generation,
                    terminal_operation_nonce,
                    reuse,
                    ..
                } => {
                    stable_device_fingerprint == Some(*device)
                        && !atoms.is_empty()
                        && *operation_nonce != [0; 16]
                        && *terminal_operation_nonce != [0; 16]
                        && *operation_nonce != *terminal_operation_nonce
                        && generation.get() < terminal_generation.get()
                        && terminal_generation.get() <= self.generation
                        && reuse.as_ref().is_none_or(|descriptor| {
                            self.reused_install_descriptor_is_exact(
                                *group_digest,
                                *generation,
                                atoms,
                                descriptor,
                            )
                        })
                }
                GroupState::Retiring {
                    device,
                    atoms,
                    generation,
                    operation_nonce,
                    terminal_generation,
                    terminal_operation_nonce,
                    activation_generation,
                    previous_terminal,
                    ..
                } => {
                    stable_device_fingerprint == Some(*device)
                        && !atoms.is_empty()
                        && *operation_nonce != [0; 16]
                        && *terminal_operation_nonce != [0; 16]
                        && *operation_nonce != *terminal_operation_nonce
                        && previous_terminal.nonce != [0; 16]
                        && *activation_generation == previous_terminal.generation
                        && previous_terminal.generation.get() < generation.get()
                        && generation.get() < terminal_generation.get()
                        && terminal_generation.get() <= self.generation
                }
                GroupState::Active { device, atoms, generation, operation_nonce, .. } => {
                    stable_device_fingerprint == Some(*device)
                        && !atoms.is_empty()
                        && *operation_nonce != [0; 16]
                        && generation.get() <= self.generation
                }
                GroupState::Retired {
                    device,
                    atoms,
                    activation_generation,
                    generation,
                    operation_nonce,
                    ..
                } => {
                    stable_device_fingerprint == Some(*device)
                        && !atoms.is_empty()
                        && *operation_nonce != [0; 16]
                        && activation_generation.get() < generation.get()
                        && generation.get() <= self.generation
                }
                GroupState::Poisoned(poison) => {
                    poison.lifecycle == NamespaceLifecycle::Bound
                        && poison.phase <= 3
                        && stable_device_fingerprint == Some(poison.device)
                        && poison.device != [0; 32]
                        && poison.selectors != [0; 32]
                        && poison.desired != [0; 32]
                        && !poison.atoms.is_empty()
                        && poison.operation_nonce != [0; 16]
                        && poison.terminal_generation.nonce != [0; 16]
                        && poison.backend_started
                        && poison.reason.is_valid_for_phase(poison.phase)
                        && poison.generation.get() <= self.generation
                        && poison.terminal_generation.generation.get() <= self.generation
                        && match poison.phase {
                            0 | 2 => {
                                poison
                                    .generation
                                    .get()
                                    .checked_add(1)
                                    .is_some_and(|next| {
                                        next == poison.terminal_generation.generation.get()
                                    })
                                    && poison.operation_nonce != poison.terminal_generation.nonce
                                    && poison.retired_dataplane_generation.is_none()
                                    && if poison.phase == 2 {
                                        poison.previous_terminal.is_some_and(|previous| {
                                            previous.generation.get() < poison.generation.get()
                                                && previous.nonce != poison.operation_nonce
                                        })
                                    } else {
                                        poison.previous_terminal.is_none()
                                    }
                            }
                            1 => {
                                poison.generation == poison.terminal_generation.generation
                                    && poison.operation_nonce == poison.terminal_generation.nonce
                                    && poison.retired_dataplane_generation.is_none()
                                    && poison.previous_terminal.is_none()
                            }
                            3 => {
                                poison.generation == poison.terminal_generation.generation
                                    && poison.operation_nonce == poison.terminal_generation.nonce
                                    && poison.retired_dataplane_generation.is_some()
                                    && poison.previous_terminal.is_none()
                            }
                            _ => false,
                        }
                }
                GroupState::LegacyPoisoned => true,
            })
            && self.selectors.values().all(|selector| match selector {
                SelectorState::Installing { generation, .. }
                | SelectorState::Active { generation, .. }
                | SelectorState::Retiring { generation, .. } => generation.get() <= self.generation,
                SelectorState::Retired => true,
                SelectorState::Poisoned { generation, .. } => generation.get() <= self.generation,
            })
            && self.capacity <= SELECTOR_NAMESPACE_MAX_READBACK_ATOMS as u32
            && self.groups.len() <= MAX_PERMANENT_GROUPS
            && self.canonical_desired.len() <= MAX_CANONICAL_DESIRED_RECORDS
            && self.canonical_desired.len() == self.groups.len()
            && self.canonical_desired_index_is_exact()
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
                GroupState::Poisoned(poison) => {
                    poison
                        .atoms
                        .iter()
                        .all(|atom| self.published_atoms.contains(atom))
                        && (poison.phase != 3
                            || poison
                                .atoms
                                .iter()
                                .all(|atom| self.tombstones.contains(atom)))
                }
                GroupState::LegacyPoisoned => true,
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
                    generation,
                    successor,
                    ..
                } => {
                    atoms.iter().all(|atom| {
                        self.published_atoms.contains(atom) && self.tombstones.contains(atom)
                    })
                        && successor.is_none_or(|successor| {
                            successor.group != *group_digest
                                && generation.get() < successor.generation.get()
                                && successor.generation.get() <= self.generation
                                && self.successor_lineage_is_exact(successor)
                        })
                }
                GroupState::Poisoned(poison) => selector_atoms_for(
                    &self.selectors,
                    *group_digest,
                    poison.generation,
                    4,
                ) == poison.atoms,
                GroupState::LegacyPoisoned => true,
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
                    SelectorState::Poisoned { group, generation } => matches!(
                        self.groups.get(group),
                        Some(GroupState::Poisoned(poison))
                            if poison.generation == *generation && poison.atoms.contains(digest)
                    ),
                })
            && self
                .published_atoms
                .iter()
                .all(|atom| self.selectors.contains_key(atom))
            && self.tombstones.iter().all(|tombstone| {
                self.groups.values().any(|group| match group {
                    GroupState::Retired { atoms, .. } => atoms.contains(tombstone),
                    GroupState::Poisoned(poison) if poison.phase == 3 => {
                        poison.atoms.contains(tombstone)
                    }
                    _ => false,
                })
            })
    }
}

fn update_inventory_coordinate(digest: &mut Sha256, coordinate: SelectorOperationStampCoordinate) {
    digest.update(coordinate.generation().get().to_be_bytes());
    digest.update(coordinate.nonce());
}

fn update_inventory_lifecycle(
    digest: &mut Sha256,
    lifecycle: SelectorOperationStampLifecycleExpectation,
) {
    match lifecycle {
        SelectorOperationStampLifecycleExpectation::Installing {
            backend_started,
            pending,
            terminal,
        } => {
            digest.update([0, u8::from(backend_started)]);
            update_inventory_coordinate(digest, pending);
            update_inventory_coordinate(digest, terminal);
        }
        SelectorOperationStampLifecycleExpectation::Active { terminal } => {
            digest.update([1]);
            update_inventory_coordinate(digest, terminal);
        }
        SelectorOperationStampLifecycleExpectation::Retiring {
            backend_started,
            pending,
            terminal,
            previous_terminal,
        } => {
            digest.update([2, u8::from(backend_started)]);
            update_inventory_coordinate(digest, pending);
            update_inventory_coordinate(digest, terminal);
            update_inventory_coordinate(digest, previous_terminal);
        }
        SelectorOperationStampLifecycleExpectation::Retired {
            terminal,
            retired_dataplane_generation,
        } => {
            digest.update([3]);
            update_inventory_coordinate(digest, terminal);
            digest.update(retired_dataplane_generation.get().to_be_bytes());
        }
        SelectorOperationStampLifecycleExpectation::Poisoned {
            phase,
            reason,
            pending,
            terminal,
            previous_terminal,
            retired_dataplane_generation,
        } => {
            digest.update([4, phase, reason]);
            update_inventory_coordinate(digest, pending);
            update_inventory_coordinate(digest, terminal);
            match previous_terminal {
                Some(coordinate) => {
                    digest.update([1]);
                    update_inventory_coordinate(digest, coordinate);
                }
                None => digest.update([0; 25]),
            }
            match retired_dataplane_generation {
                Some(generation) => {
                    digest.update([1]);
                    digest.update(generation.get().to_be_bytes());
                }
                None => digest.update([0; 9]),
            }
        }
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

fn random_distinct_nonzero_nonce(
    excluded: [u8; 16],
) -> Result<[u8; 16], GtpuSessionSelectorNamespaceError> {
    for _ in 0..4 {
        let nonce = random_nonzero_nonce()?;
        if nonce != excluded {
            return Ok(nonce);
        }
    }
    Err(GtpuSessionSelectorNamespaceError::Indeterminate)
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
            )
            | (
                4,
                SelectorState::Poisoned {
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
    /// Points at the one durable group poison record. The selector digest is
    /// already a keyed commitment; no raw selector material is retained here.
    Poisoned {
        group: [u8; 32],
        generation: GtpuSessionSelectorAuthorityGeneration,
    },
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
        /// The complete, authenticated predecessor and quiescence evidence
        /// needed to reissue this pending effect after a crash. `None` is a
        /// fresh claim; a reused claim is never recovered by inventing a
        /// fresh request.
        reuse: Option<ReusedInstallDescriptor>,
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
        /// The immutable Active coordinate replaced by this retirement. It
        /// remains in the terminal tombstone so predecessor lineage can be
        /// checked after the successor itself retires.
        activation_generation: GtpuSessionSelectorAuthorityGeneration,
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
        /// The immutable Active generation for this group. A predecessor's
        /// one-time successor link targets the immediately preceding
        /// Installing generation, so retaining this coordinate keeps that
        /// lineage exact across later retirement generations.
        activation_generation: GtpuSessionSelectorAuthorityGeneration,
        generation: GtpuSessionSelectorAuthorityGeneration,
        operation_nonce: [u8; 16],
        /// Exact nonzero generation written by the trusted backend removal
        /// and readback before this durable terminal row was acknowledged.
        retired_dataplane_generation: NonZeroU64,
        /// Written exactly once in the source `Retired` CAS.  This makes a
        /// permanently retired predecessor a single-use lineage edge even
        /// after its successor has itself retired.
        successor: Option<RetiredSuccessor>,
    },
    Poisoned(PoisonRecord),
    /// Terminal sentinel retained for the in-memory legacy-capacity model.
    /// Current production decoding rejects pre-OPCSN15 schemas before a row
    /// can reach this variant.
    #[allow(dead_code)]
    LegacyPoisoned,
}

/// Closed, bounded reason for an authority transition whose backend outcome
/// could no longer be proven.  This is intentionally not a backend error
/// string: backend implementations may include sensitive or unbounded text.
// The repeated suffix is deliberate: every variant names a fail-closed,
// indeterminate durable outcome, never a successful effect classification.
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PoisonReason {
    EffectReceiptIndeterminate,
    EffectReadbackIndeterminate,
    RemovalReceiptIndeterminate,
    RemovalReadbackIndeterminate,
    RecoveryIndeterminate,
}

impl PoisonReason {
    const fn tag(self) -> u8 {
        match self {
            Self::EffectReceiptIndeterminate => 0,
            Self::EffectReadbackIndeterminate => 1,
            Self::RemovalReceiptIndeterminate => 2,
            Self::RemovalReadbackIndeterminate => 3,
            Self::RecoveryIndeterminate => 4,
        }
    }

    const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::EffectReceiptIndeterminate),
            1 => Some(Self::EffectReadbackIndeterminate),
            2 => Some(Self::RemovalReceiptIndeterminate),
            3 => Some(Self::RemovalReadbackIndeterminate),
            4 => Some(Self::RecoveryIndeterminate),
            _ => None,
        }
    }

    const fn is_valid_for_phase(self, phase: u8) -> bool {
        match self {
            Self::EffectReceiptIndeterminate | Self::EffectReadbackIndeterminate => phase == 0,
            Self::RemovalReceiptIndeterminate | Self::RemovalReadbackIndeterminate => phase == 2,
            Self::RecoveryIndeterminate => phase <= 3,
        }
    }
}

/// The current backend-neutral receipt boundary verifies coordinates but does
/// not expose operation-stamp bytes.  Persisting a fabricated byte sequence
/// would be misleading, so the only presently truthful evidence is this
/// explicit bounded classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PoisonStampEvidence {
    NotObserved,
}

impl PoisonStampEvidence {
    const fn tag(self) -> u8 {
        match self {
            Self::NotObserved => 0,
        }
    }

    fn from_tag(tag: u8) -> Option<Self> {
        (tag == 0).then_some(Self::NotObserved)
    }
}

/// Fixed-size durable poison evidence. Every field is a keyed commitment,
/// authority coordinate, closed enum, or bounded atom commitment. This data
/// is inside the protected ledger and has no public diagnostic accessor.
#[derive(Clone)]
struct PoisonRecord {
    lifecycle: NamespaceLifecycle,
    phase: u8,
    device: [u8; 32],
    selectors: [u8; 32],
    desired: [u8; 32],
    atoms: BTreeSet<[u8; 32]>,
    generation: GtpuSessionSelectorAuthorityGeneration,
    operation_nonce: [u8; 16],
    terminal_generation: SelectorAuthorityCoordinate,
    /// The still-authoritative Active stamp coordinate preserved when a
    /// Retiring row becomes poisoned. The adapter needs this to enumerate
    /// every exact stamp value that may remain under the permanent group key.
    previous_terminal: Option<SelectorAuthorityCoordinate>,
    backend_started: bool,
    retired_dataplane_generation: Option<NonZeroU64>,
    reason: PoisonReason,
    stamp_evidence: PoisonStampEvidence,
}

impl PoisonRecord {
    fn encode(&self, output: &mut Vec<u8>) {
        output.push(match self.lifecycle {
            NamespaceLifecycle::Unprovisioned => 0,
            NamespaceLifecycle::Provisioned => 1,
            NamespaceLifecycle::Initializing => 2,
            NamespaceLifecycle::Bound => 3,
            NamespaceLifecycle::Decommissioning => 4,
            NamespaceLifecycle::Decommissioned => 5,
        });
        output.push(self.phase);
        output.extend_from_slice(&self.device);
        output.extend_from_slice(&self.selectors);
        output.extend_from_slice(&self.desired);
        output.extend_from_slice(&self.generation.get().to_be_bytes());
        output.extend_from_slice(&self.operation_nonce);
        output.extend_from_slice(&self.terminal_generation.generation.get().to_be_bytes());
        output.extend_from_slice(&self.terminal_generation.nonce);
        match self.previous_terminal {
            None => output.push(0),
            Some(previous_terminal) => {
                output.push(1);
                output.extend_from_slice(&previous_terminal.generation.get().to_be_bytes());
                output.extend_from_slice(&previous_terminal.nonce);
            }
        }
        output.push(u8::from(self.backend_started));
        match self.retired_dataplane_generation {
            None => output.push(0),
            Some(generation) => {
                output.push(1);
                output.extend_from_slice(&generation.get().to_be_bytes());
            }
        }
        output.push(self.reason.tag());
        output.push(self.stamp_evidence.tag());
        output.extend_from_slice(&(self.atoms.len() as u32).to_be_bytes());
        for atom in &self.atoms {
            output.extend_from_slice(atom);
        }
    }

    fn decode(bytes: &[u8], cursor: &mut usize) -> Option<Self> {
        let lifecycle = match *take(bytes, cursor, 1)?.first()? {
            0 => NamespaceLifecycle::Unprovisioned,
            1 => NamespaceLifecycle::Provisioned,
            2 => NamespaceLifecycle::Initializing,
            3 => NamespaceLifecycle::Bound,
            4 => NamespaceLifecycle::Decommissioning,
            5 => NamespaceLifecycle::Decommissioned,
            _ => return None,
        };
        let phase = *take(bytes, cursor, 1)?.first()?;
        (phase <= 3).then_some(())?;
        let device = take_array(take(bytes, cursor, 32)?)?;
        let selectors = take_array(take(bytes, cursor, 32)?)?;
        let desired = take_array(take(bytes, cursor, 32)?)?;
        let generation = GtpuSessionSelectorAuthorityGeneration(NonZeroU64::new(
            u64::from_be_bytes(take_array(take(bytes, cursor, 8)?)?),
        )?);
        let operation_nonce = take_array(take(bytes, cursor, 16)?)?;
        (operation_nonce != [0; 16]).then_some(())?;
        let terminal_generation = SelectorAuthorityCoordinate {
            generation: GtpuSessionSelectorAuthorityGeneration(NonZeroU64::new(
                u64::from_be_bytes(take_array(take(bytes, cursor, 8)?)?),
            )?),
            nonce: take_array(take(bytes, cursor, 16)?)?,
        };
        (terminal_generation.nonce != [0; 16]).then_some(())?;
        let previous_terminal = match *take(bytes, cursor, 1)?.first()? {
            0 => None,
            1 => Some(SelectorAuthorityCoordinate {
                generation: GtpuSessionSelectorAuthorityGeneration(NonZeroU64::new(
                    u64::from_be_bytes(take_array(take(bytes, cursor, 8)?)?),
                )?),
                nonce: take_array(take(bytes, cursor, 16)?)?,
            }),
            _ => return None,
        };
        previous_terminal
            .is_none_or(|coordinate| coordinate.nonce != [0; 16])
            .then_some(())?;
        let backend_started = match *take(bytes, cursor, 1)?.first()? {
            0 => false,
            1 => true,
            _ => return None,
        };
        let retired_dataplane_generation = match *take(bytes, cursor, 1)?.first()? {
            0 => None,
            1 => Some(NonZeroU64::new(u64::from_be_bytes(take_array(take(
                bytes, cursor, 8,
            )?)?))?),
            _ => return None,
        };
        let reason = PoisonReason::from_tag(*take(bytes, cursor, 1)?.first()?)?;
        let stamp_evidence = PoisonStampEvidence::from_tag(*take(bytes, cursor, 1)?.first()?)?;
        let count = u32::from_be_bytes(take_array(take(bytes, cursor, 4)?)?) as usize;
        if count == 0 || count > SELECTOR_NAMESPACE_MAX_READBACK_ATOMS {
            return None;
        }
        let mut atoms = BTreeSet::new();
        let mut previous = None;
        for _ in 0..count {
            let atom = take_array(take(bytes, cursor, 32)?)?;
            if previous.is_some_and(|prior| prior >= atom) || !atoms.insert(atom) {
                return None;
            }
            previous = Some(atom);
        }
        let record = Self {
            lifecycle,
            phase,
            device,
            selectors,
            desired,
            atoms,
            generation,
            operation_nonce,
            terminal_generation,
            previous_terminal,
            backend_started,
            retired_dataplane_generation,
            reason,
            stamp_evidence,
        };
        (record.lifecycle == NamespaceLifecycle::Bound
            && record.backend_started
            && record.device != [0; 32]
            && record.selectors != [0; 32]
            && record.desired != [0; 32]
            && record.reason.is_valid_for_phase(record.phase)
            && match record.phase {
                0 | 2 => {
                    record
                        .generation
                        .get()
                        .checked_add(1)
                        .is_some_and(|next| next == record.terminal_generation.generation.get())
                        && record.operation_nonce != record.terminal_generation.nonce
                        && record.retired_dataplane_generation.is_none()
                        && if record.phase == 2 {
                            record.previous_terminal.is_some_and(|previous| {
                                previous.generation.get() < record.generation.get()
                                    && previous.nonce != record.operation_nonce
                            })
                        } else {
                            record.previous_terminal.is_none()
                        }
                }
                1 => {
                    record.generation == record.terminal_generation.generation
                        && record.operation_nonce == record.terminal_generation.nonce
                        && record.retired_dataplane_generation.is_none()
                        && record.previous_terminal.is_none()
                }
                3 => {
                    record.generation == record.terminal_generation.generation
                        && record.operation_nonce == record.terminal_generation.nonce
                        && record.retired_dataplane_generation.is_some()
                        && record.previous_terminal.is_none()
                }
                _ => false,
            })
        .then_some(record)
    }

    fn from_group(
        lifecycle: NamespaceLifecycle,
        group: GroupState,
        reason: PoisonReason,
    ) -> Option<Self> {
        let (
            phase,
            device,
            selectors,
            desired,
            atoms,
            generation,
            operation_nonce,
            terminal_generation,
            previous_terminal,
            backend_started,
            retired_dataplane_generation,
        ) = match group {
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
                ..
            } => (
                0,
                device,
                selectors,
                desired,
                atoms,
                generation,
                operation_nonce,
                SelectorAuthorityCoordinate {
                    generation: terminal_generation,
                    nonce: terminal_operation_nonce,
                },
                None,
                backend_started,
                None,
            ),
            GroupState::Active {
                device,
                selectors,
                desired,
                atoms,
                generation,
                operation_nonce,
            } => (
                1,
                device,
                selectors,
                desired,
                atoms,
                generation,
                operation_nonce,
                SelectorAuthorityCoordinate {
                    generation,
                    nonce: operation_nonce,
                },
                None,
                true,
                None,
            ),
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
                ..
            } => (
                2,
                device,
                selectors,
                desired,
                atoms,
                generation,
                operation_nonce,
                SelectorAuthorityCoordinate {
                    generation: terminal_generation,
                    nonce: terminal_operation_nonce,
                },
                Some(previous_terminal),
                backend_started,
                None,
            ),
            GroupState::Retired {
                device,
                selectors,
                desired,
                atoms,
                generation,
                operation_nonce,
                retired_dataplane_generation,
                ..
            } => (
                3,
                device,
                selectors,
                desired,
                atoms,
                generation,
                operation_nonce,
                SelectorAuthorityCoordinate {
                    generation,
                    nonce: operation_nonce,
                },
                None,
                true,
                Some(retired_dataplane_generation),
            ),
            GroupState::Poisoned(_) | GroupState::LegacyPoisoned => return None,
        };
        let record = Self {
            lifecycle,
            phase,
            device,
            selectors,
            desired,
            atoms,
            generation,
            operation_nonce,
            terminal_generation,
            previous_terminal,
            backend_started,
            retired_dataplane_generation,
            reason,
            stamp_evidence: PoisonStampEvidence::NotObserved,
        };
        ((record.phase != 0 && record.phase != 2)
            || record.operation_nonce != record.terminal_generation.nonce)
            .then_some(record)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct RetiredSuccessor {
    group: [u8; 32],
    generation: GtpuSessionSelectorAuthorityGeneration,
}

/// Durable private descriptor for one reused Installing intent. The source
/// semantic graph is retained as the canonical codec so recovery can mint the
/// same `new_reused` request, including its drain/RCU evidence, without
/// trusting a caller to restate a predecessor after the pending CAS.
#[derive(Clone)]
struct ReusedInstallDescriptor {
    source_desired: Zeroizing<Vec<u8>>,
    evidence: crate::GtpuSessionSelectorReuseEvidence,
    source_device: [u8; 32],
    source_selectors: [u8; 32],
    source_desired_fingerprint: [u8; 32],
    source_generation: GtpuSessionSelectorAuthorityGeneration,
    source_operation_nonce: [u8; 16],
    source_retired_dataplane_generation: NonZeroU64,
}

impl ReusedInstallDescriptor {
    fn from_proof(
        proof: &crate::GtpuSessionSelectorReuseProof,
        source_device: [u8; 32],
        source_selectors: [u8; 32],
        source_desired_fingerprint: [u8; 32],
        source_generation: GtpuSessionSelectorAuthorityGeneration,
        source_operation_nonce: [u8; 16],
        source_retired_dataplane_generation: NonZeroU64,
    ) -> Option<Self> {
        let source_desired = canonical_desired_bytes(proof.retired_group());
        (source_desired.len() <= MAX_CANONICAL_DESIRED_BYTES).then_some(Self {
            source_desired: Zeroizing::new(source_desired),
            evidence: proof.evidence(),
            source_device,
            source_selectors,
            source_desired_fingerprint,
            source_generation,
            source_operation_nonce,
            source_retired_dataplane_generation,
        })
    }

    fn proof(
        &self,
        selector_digest_key: &[u8; 32],
    ) -> Option<crate::GtpuSessionSelectorReuseProof> {
        let source_group = decode_canonical_desired(&self.source_desired)?;
        let source = CanonicalClaim::from_group(&source_group).with_key(selector_digest_key)?;
        (source.device_fingerprint == self.source_device
            && source.selector_set_fingerprint == self.source_selectors
            && source.desired_fingerprint == self.source_desired_fingerprint
            && canonical_desired_bytes(&source_group) == *self.source_desired)
            .then_some(())?;
        match self.evidence {
            crate::GtpuSessionSelectorReuseEvidence::TrafficDrained => Some(
                crate::GtpuSessionSelectorReuseProof::after_traffic_drain(source_group),
            ),
            crate::GtpuSessionSelectorReuseEvidence::RcuGracePeriodElapsed => {
                Some(crate::GtpuSessionSelectorReuseProof::after_rcu_grace_period(source_group))
            }
        }
    }
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
                        // RFC 016 §5.1: family tag, prefix length, then the
                        // canonical prefix. The atom codec already provides
                        // the enclosing version/tag/length; it must not grow
                        // an invented inner version byte.
                        paa.extend_from_slice(&[4, 32]);
                        paa.extend_from_slice(&address);
                        atom_bytes.insert(atom_codec(b'P', &paa));
                    }
                    GtpuSessionPaa::Ipv6Prefix(prefix) => {
                        let mut paa = Vec::with_capacity(10);
                        paa.extend_from_slice(&[6, 64]);
                        paa.extend_from_slice(&prefix);
                        atom_bytes.insert(atom_codec(b'P', &paa));
                    }
                }
                if let Some(mark) = entry.context().bearer_mark {
                    // A bearer-mark atom is the nonzero mark in network
                    // order followed by its required full mask. As with PAA,
                    // the outer atom codec owns versioning and framing.
                    let mut full_mask_mark = Vec::with_capacity(8);
                    full_mask_mark.extend_from_slice(&mark.get().to_be_bytes());
                    full_mask_mark.extend_from_slice(&u32::MAX.to_be_bytes());
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

/// Decode only the private canonical group codec emitted above. This is not a
/// caller-input parser: it is the recovery half of the authenticated durable
/// reused-install descriptor. Every field is reconstructed through the public
/// model constructors and the original bytes are re-encoded before use.
fn decode_canonical_desired(bytes: &[u8]) -> Option<GtpuSessionGroup> {
    fn read_ip(bytes: &[u8], cursor: &mut usize) -> Option<std::net::IpAddr> {
        match *take(bytes, cursor, 1)?.first()? {
            4 => Some(std::net::IpAddr::V4(std::net::Ipv4Addr::from(take_array(
                take(bytes, cursor, 4)?,
            )?))),
            6 => Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(take_array(
                take(bytes, cursor, 16)?,
            )?))),
            _ => None,
        }
    }

    let mut cursor = 0_usize;
    (take(bytes, &mut cursor, 1)? == [1]).then_some(())?;
    let device = crate::GtpuSessionDeviceId::new(take_array(take(bytes, &mut cursor, 16)?)?)?;
    let group_id = crate::GtpuSessionGroupId::new(take_array(take(bytes, &mut cursor, 16)?)?)?;
    let count = usize::from(*take(bytes, &mut cursor, 1)?.first()?);
    if !(1..=2).contains(&count) {
        return None;
    }
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let ms_address = read_ip(bytes, &mut cursor)?;
        let peer_address = read_ip(bytes, &mut cursor)?;
        let local_outer_address = read_ip(bytes, &mut cursor)?;
        let local_teid = crate::Teid::new(u32::from_be_bytes(take_array(take(
            bytes,
            &mut cursor,
            4,
        )?)?))?;
        let peer_teid = crate::Teid::new(u32::from_be_bytes(take_array(take(
            bytes,
            &mut cursor,
            4,
        )?)?))?;
        let link_ifindex = u32::from_be_bytes(take_array(take(bytes, &mut cursor, 4)?)?);
        let gtp_version = match *take(bytes, &mut cursor, 1)?.first()? {
            1 => crate::GtpVersion::V1,
            _ => return None,
        };
        let bearer_mark = match *take(bytes, &mut cursor, 1)?.first()? {
            0 => None,
            1 => Some(crate::GtpBearerMark::new(u32::from_be_bytes(take_array(
                take(bytes, &mut cursor, 4)?,
            )?))?),
            _ => return None,
        };
        let downlink_source_port_policy = match *take(bytes, &mut cursor, 1)?.first()? {
            0 => crate::GtpuSourcePortPolicy::Any,
            1 => crate::GtpuSourcePortPolicy::Exact(u16::from_be_bytes(take_array(take(
                bytes,
                &mut cursor,
                2,
            )?)?)),
            2 => crate::GtpuSourcePortPolicy::inclusive_range(
                u16::from_be_bytes(take_array(take(bytes, &mut cursor, 2)?)?),
                u16::from_be_bytes(take_array(take(bytes, &mut cursor, 2)?)?),
            )?,
            _ => return None,
        };
        let uplink_source_port_policy = match *take(bytes, &mut cursor, 1)?.first()? {
            0 => crate::GtpuUplinkSourcePortPolicy::LegacyServicePort,
            1 => crate::GtpuUplinkSourcePortPolicy::selected(u16::from_be_bytes(take_array(
                take(bytes, &mut cursor, 2)?,
            )?))?,
            _ => return None,
        };
        let egress_dscp = match *take(bytes, &mut cursor, 1)?.first()? {
            0 => None,
            1 => Some(crate::DscpCodepoint::new(*take(bytes, &mut cursor, 1)?.first()?).ok()?),
            _ => return None,
        };
        entries.push(
            crate::GtpuSessionEntry::new(
                crate::GtpPdpContext {
                    local_teid,
                    peer_teid,
                    ms_address,
                    peer_address,
                    link_ifindex,
                    downlink_source_port_policy,
                    gtp_version,
                    bearer_mark,
                    uplink_source_port_policy,
                    egress_dscp,
                },
                local_outer_address,
            )
            .ok()?,
        );
    }
    (cursor == bytes.len()).then_some(())?;
    let group = GtpuSessionGroup::new(group_id, device, entries).ok()?;
    (canonical_desired_bytes(&group) == bytes).then_some(group)
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
    let Ok(mut mac) = <Hmac<Sha256> as Mac>::new_from_slice(key) else {
        return [0; 32];
    };
    mac.update(domain);
    mac.update(codec);
    mac.finalize().into_bytes().into()
}

fn hmac_bytes(key: &[u8; 32], chunks: &[&[u8]]) -> [u8; 32] {
    let Ok(mut mac) = <Hmac<Sha256> as Mac>::new_from_slice(key) else {
        return [0; 32];
    };
    for chunk in chunks {
        mac.update(chunk);
    }
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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

    fn test_backend_mutation_window() -> SelectorBackendMutationWindow {
        SelectorBackendMutationWindow::mint(SELECTOR_NAMESPACE_MAX_LEASE_TTL)
            .expect("test mutation window")
    }

    fn test_operation_stamp_inventory() -> SelectorOperationStampInventory {
        SelectorOperationStampInventory {
            expectations: Vec::new(),
            summary: [0x5a; 32],
        }
    }

    fn inventory_generation(value: u64) -> GtpuSessionSelectorAuthorityGeneration {
        GtpuSessionSelectorAuthorityGeneration(NonZeroU64::new(value).expect("nonzero test"))
    }

    fn inventory_matrix_state(
        device: u8,
        teid_offset: u32,
    ) -> (NamespaceState, GtpuSessionSelectorBackendBinding) {
        let mut state = NamespaceState::default();
        let stable_device = GtpuSessionDeviceId::new([device; 16]).expect("test device");
        state
            .bind_or_validate(
                stable_device,
                SELECTOR_NAMESPACE_MAX_READBACK_ATOMS,
                Some([0x51; 32]),
            )
            .expect("bound test inventory state");
        for (index, desired) in [
            group(1, device, 0x1000_0001 + teid_offset, None),
            group(2, device, 0x1000_0002 + teid_offset, None),
            group(3, device, 0x1000_0003 + teid_offset, None),
            group(4, device, 0x1000_0004 + teid_offset, None),
            group(5, device, 0x1000_0005 + teid_offset, None),
        ]
        .into_iter()
        .enumerate()
        {
            let claim = CanonicalClaim::from_group(&desired)
                .with_key(&state.selector_digest_key)
                .expect("canonical matrix claim");
            let atoms = claim
                .selector_atoms(&state.selector_digest_key)
                .expect("matrix selector atoms");
            state
                .retain_canonical_desired(claim.group_fingerprint, &desired)
                .expect("matrix canonical desired");
            let group = match index {
                0 => GroupState::Installing {
                    device: claim.device_fingerprint,
                    selectors: claim.selector_set_fingerprint,
                    desired: claim.desired_fingerprint,
                    atoms,
                    generation: inventory_generation(1),
                    operation_nonce: [0x11; 16],
                    terminal_generation: inventory_generation(2),
                    terminal_operation_nonce: [0x12; 16],
                    backend_started: true,
                    reuse: None,
                },
                1 => GroupState::Active {
                    device: claim.device_fingerprint,
                    selectors: claim.selector_set_fingerprint,
                    desired: claim.desired_fingerprint,
                    atoms,
                    generation: inventory_generation(3),
                    operation_nonce: [0x13; 16],
                },
                2 => GroupState::Retiring {
                    device: claim.device_fingerprint,
                    selectors: claim.selector_set_fingerprint,
                    desired: claim.desired_fingerprint,
                    atoms,
                    generation: inventory_generation(5),
                    operation_nonce: [0x15; 16],
                    terminal_generation: inventory_generation(6),
                    terminal_operation_nonce: [0x16; 16],
                    activation_generation: inventory_generation(4),
                    previous_terminal: SelectorAuthorityCoordinate {
                        generation: inventory_generation(4),
                        nonce: [0x14; 16],
                    },
                    backend_started: false,
                },
                3 => GroupState::Retired {
                    device: claim.device_fingerprint,
                    selectors: claim.selector_set_fingerprint,
                    desired: claim.desired_fingerprint,
                    atoms,
                    activation_generation: inventory_generation(7),
                    generation: inventory_generation(8),
                    operation_nonce: [0x18; 16],
                    retired_dataplane_generation: NonZeroU64::new(9).expect("nonzero test"),
                    successor: None,
                },
                4 => GroupState::Poisoned(PoisonRecord {
                    lifecycle: NamespaceLifecycle::Bound,
                    phase: 2,
                    device: claim.device_fingerprint,
                    selectors: claim.selector_set_fingerprint,
                    desired: claim.desired_fingerprint,
                    atoms,
                    generation: inventory_generation(10),
                    operation_nonce: [0x1a; 16],
                    terminal_generation: SelectorAuthorityCoordinate {
                        generation: inventory_generation(11),
                        nonce: [0x1b; 16],
                    },
                    previous_terminal: Some(SelectorAuthorityCoordinate {
                        generation: inventory_generation(9),
                        nonce: [0x19; 16],
                    }),
                    backend_started: true,
                    retired_dataplane_generation: None,
                    reason: PoisonReason::RemovalReadbackIndeterminate,
                    stamp_evidence: PoisonStampEvidence::NotObserved,
                }),
                _ => unreachable!("five matrix lifecycles"),
            };
            state.groups.insert(claim.group_fingerprint, group);
        }
        state.generation = 11;
        let binding = state
            .binding_with_scope(test_storage_scope_commitment(&[0x51; 32]))
            .expect("matrix binding");
        (state, binding)
    }

    fn assert_inventory_receipt_binding_changes(
        binding: GtpuSessionSelectorBackendBinding,
        baseline: &SelectorOperationStampInventory,
        changed_binding: GtpuSessionSelectorBackendBinding,
        changed: &SelectorOperationStampInventory,
    ) {
        assert_ne!(baseline.summary(), changed.summary());
        let window = test_backend_mutation_window();
        assert_ne!(
            SelectorBackendReceiptCoordinate::for_binding_inventory(binding, baseline, &window).0,
            SelectorBackendReceiptCoordinate::for_binding_inventory(
                changed_binding,
                changed,
                &window,
            )
            .0
        );
    }

    async fn production_authority(
        device_id: GtpuSessionDeviceId,
    ) -> GtpuSessionSelectorNamespaceAuthority<SqliteSessionBackend> {
        let namespace_key = production_namespace_key(device_id);
        raw_production_authority(
            SessionStore::new(
                SqliteSessionBackend::in_memory().expect("in-memory durable namespace backend"),
            ),
            namespace_key,
            "selector-namespace-test-owner",
            32,
        )
        .await
    }

    fn production_namespace_key(device_id: GtpuSessionDeviceId) -> SessionKey {
        SessionKey {
            tenant: TenantId::from_static("selector-namespace-test"),
            nf_kind: NetworkFunctionKind::from_static("epdg"),
            key_type: SessionKeyType::other("gtpu-selector-namespace")
                .expect("valid test namespace key type"),
            stable_id: StableId::new(Bytes::copy_from_slice(&device_id.to_bytes()))
                .expect("valid test namespace stable ID"),
        }
    }

    async fn raw_production_authority(
        store: SessionStore<SqliteSessionBackend>,
        namespace_key: SessionKey,
        owner: &str,
        maximum_atoms: usize,
    ) -> GtpuSessionSelectorNamespaceAuthority<SqliteSessionBackend> {
        raw_production_authority_with_ttl(
            store,
            namespace_key,
            owner,
            Duration::from_secs(30),
            maximum_atoms,
        )
        .await
    }

    async fn raw_production_authority_with_ttl(
        store: SessionStore<SqliteSessionBackend>,
        namespace_key: SessionKey,
        owner: &str,
        lease_ttl: Duration,
        maximum_atoms: usize,
    ) -> GtpuSessionSelectorNamespaceAuthority<SqliteSessionBackend> {
        GtpuSessionSelectorNamespaceAuthority::open(
            store,
            namespace_key,
            OwnerId::new(owner).expect("valid test owner"),
            lease_ttl,
            maximum_atoms,
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

    #[repr(u8)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum TerminalRetiredReadbackMode {
        Exact = 0,
        Unstamped = 1,
        MutatedGeneration = 2,
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
        terminal_inspect_fault: std::sync::atomic::AtomicBool,
        terminal_inspect_delay_millis: std::sync::atomic::AtomicU64,
        no_effect_inspection_delay_millis: std::sync::atomic::AtomicU64,
        hold_no_effect_inspection: std::sync::atomic::AtomicBool,
        no_effect_inspection_entered: tokio::sync::Notify,
        no_effect_inspection_release: tokio::sync::Notify,
        installing_no_effect_inspection_calls: std::sync::atomic::AtomicUsize,
        retiring_no_effect_inspection_calls: std::sync::atomic::AtomicUsize,
        effect_calls: std::sync::atomic::AtomicUsize,
        reused_effect_calls: std::sync::atomic::AtomicUsize,
        provision_calls: std::sync::atomic::AtomicUsize,
        removal_calls: std::sync::atomic::AtomicUsize,
        terminal_retired_readback_mode: std::sync::atomic::AtomicU8,
        dataplane: std::sync::Mutex<FaultingSelectorDataplaneState>,
        terminal_fence: std::sync::Mutex<Option<[u8; DECOMMISSION_CAPSULE_LEN]>>,
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

        fn set_terminal_inspect_fault_after(&self, delay: Duration) {
            self.terminal_inspect_delay_millis.store(
                u64::try_from(delay.as_millis()).expect("test delay fits u64"),
                std::sync::atomic::Ordering::Release,
            );
            self.terminal_inspect_fault
                .store(true, std::sync::atomic::Ordering::Release);
        }

        fn set_no_effect_inspection_delay(&self, delay: Duration) {
            self.no_effect_inspection_delay_millis.store(
                u64::try_from(delay.as_millis()).expect("test delay fits u64"),
                std::sync::atomic::Ordering::Release,
            );
        }

        fn hold_no_effect_inspection(&self) {
            self.hold_no_effect_inspection
                .store(true, std::sync::atomic::Ordering::Release);
        }

        async fn wait_for_no_effect_inspection_entry(&self) {
            self.no_effect_inspection_entered.notified().await;
        }

        fn release_no_effect_inspection(&self) {
            self.hold_no_effect_inspection
                .store(false, std::sync::atomic::Ordering::Release);
            self.no_effect_inspection_release.notify_one();
        }

        async fn wait_for_no_effect_inspection_hold(&self) {
            self.no_effect_inspection_entered.notify_one();
            if self
                .hold_no_effect_inspection
                .load(std::sync::atomic::Ordering::Acquire)
            {
                self.no_effect_inspection_release.notified().await;
            }
        }

        fn set_dataplane(&self, state: FaultingSelectorDataplaneState) {
            *self.dataplane.lock().expect("faulting dataplane lock") = state;
        }

        async fn wait_for_no_effect_inspection_delay(&self) {
            let millis = self
                .no_effect_inspection_delay_millis
                .load(std::sync::atomic::Ordering::Acquire);
            if millis != 0 {
                tokio::time::sleep(Duration::from_millis(millis)).await;
            }
        }

        fn effect_calls(&self) -> usize {
            self.effect_calls.load(std::sync::atomic::Ordering::Acquire)
        }

        fn installing_no_effect_inspection_calls(&self) -> usize {
            self.installing_no_effect_inspection_calls
                .load(std::sync::atomic::Ordering::Acquire)
        }

        fn retiring_no_effect_inspection_calls(&self) -> usize {
            self.retiring_no_effect_inspection_calls
                .load(std::sync::atomic::Ordering::Acquire)
        }

        fn reused_effect_calls(&self) -> usize {
            self.reused_effect_calls
                .load(std::sync::atomic::Ordering::Acquire)
        }

        fn provision_calls(&self) -> usize {
            self.provision_calls
                .load(std::sync::atomic::Ordering::Acquire)
        }

        fn removal_calls(&self) -> usize {
            self.removal_calls
                .load(std::sync::atomic::Ordering::Acquire)
        }

        fn set_terminal_retired_readback_mode(&self, mode: TerminalRetiredReadbackMode) {
            self.terminal_retired_readback_mode
                .store(mode as u8, std::sync::atomic::Ordering::Release);
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

        fn terminal_retired_stamp(
            admission: &GtpuSessionSelectorAdmission,
        ) -> [u8; GTPU_SESSION_SELECTOR_STAMP_VALUE_LEN] {
            let binding = admission.binding();
            let mut stamp = [0_u8; GTPU_SESSION_SELECTOR_STAMP_VALUE_LEN];
            stamp[0] = 1;
            stamp[1] = 4;
            stamp[2] = 2;
            stamp[3] = 3;
            stamp[8..16].copy_from_slice(&admission.terminal_generation().get().to_be_bytes());
            stamp[16..32].copy_from_slice(&admission.terminal_operation_nonce());
            stamp[32..48].copy_from_slice(&binding.backend_epoch());
            stamp[64..96].copy_from_slice(&binding.storage_scope_commitment());
            stamp[96..128].copy_from_slice(&admission.group_fingerprint());
            stamp[128..160].copy_from_slice(&admission.selector_set_fingerprint());
            stamp[160..192].copy_from_slice(&admission.desired_fingerprint());
            let dataplane_generation = admission
                .retired_dataplane_generation()
                .map(NonZeroU64::get)
                .unwrap_or(1);
            stamp[192..200].copy_from_slice(&dataplane_generation.to_be_bytes());
            stamp
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
            if !lease.is_current() {
                return Err(crate::GtpuError::StateIndeterminate {
                    operation: "faulting_selector_binding_window",
                });
            }
            Ok(lease.confirm())
        }

        async fn provision_selector_namespace_authorized(
            &self,
            request: GtpuSessionSelectorProvisionRequest,
        ) -> Result<GtpuSessionSelectorBackendReceipt, crate::GtpuError> {
            if !request.is_current() {
                return Err(crate::GtpuError::StateIndeterminate {
                    operation: "faulting_selector_provision_window",
                });
            }
            self.provision_calls
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            Ok(request.confirm())
        }

        async fn inspect_installing_selector_no_effect(
            &self,
            request: GtpuSessionSelectorInstallingNoEffectRequest,
        ) -> Result<GtpuSessionSelectorBackendReceipt, crate::GtpuError> {
            self.installing_no_effect_inspection_calls
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            self.wait_for_no_effect_inspection_hold().await;
            self.wait_for_no_effect_inspection_delay().await;
            let dataplane =
                self.dataplane
                    .lock()
                    .map_err(|_| crate::GtpuError::StateIndeterminate {
                        operation: "faulting_selector_dataplane_lock",
                    })?;
            if !request.is_current() {
                return Err(crate::GtpuError::StateIndeterminate {
                    operation: "faulting_selector_install_negative_window",
                });
            }
            if !matches!(&*dataplane, FaultingSelectorDataplaneState::NoEffect) {
                return Err(crate::GtpuError::StateIndeterminate {
                    operation: "faulting_selector_install_negative_proof",
                });
            }
            if !request.is_current() {
                return Err(crate::GtpuError::StateIndeterminate {
                    operation: "faulting_selector_install_negative_window",
                });
            }
            request
                .confirm()
                .ok_or(crate::GtpuError::StateIndeterminate {
                    operation: "faulting_selector_install_negative_window",
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
            request: GtpuSessionSelectorRetiringNoEffectRequest,
        ) -> Result<GtpuSessionSelectorBackendReceipt, crate::GtpuError> {
            self.retiring_no_effect_inspection_calls
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            self.wait_for_no_effect_inspection_hold().await;
            self.wait_for_no_effect_inspection_delay().await;
            let dataplane =
                self.dataplane
                    .lock()
                    .map_err(|_| crate::GtpuError::StateIndeterminate {
                        operation: "faulting_selector_dataplane_lock",
                    })?;
            if !request.is_current() {
                return Err(crate::GtpuError::StateIndeterminate {
                    operation: "faulting_selector_retiring_negative_window",
                });
            }
            if !matches!(
                &*dataplane,
                FaultingSelectorDataplaneState::Active(active) if active == request.expected_group()
            ) {
                return Err(crate::GtpuError::StateIndeterminate {
                    operation: "faulting_selector_retiring_negative_proof",
                });
            }
            if !request.is_current() {
                return Err(crate::GtpuError::StateIndeterminate {
                    operation: "faulting_selector_retiring_negative_window",
                });
            }
            request
                .confirm()
                .ok_or(crate::GtpuError::StateIndeterminate {
                    operation: "faulting_selector_retiring_negative_window",
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

        async fn authorize_selector_reuse(
            &self,
            request: GtpuSessionSelectorReuseRequest,
        ) -> Result<GtpuSessionSelectorReuseReceipt, crate::GtpuError> {
            if !request.is_current() {
                return Err(crate::GtpuError::StateIndeterminate {
                    operation: "faulting_selector_reuse_window",
                });
            }
            let stamp = Self::terminal_retired_stamp(&request.retired.admission);
            request
                .verifies_exact_terminal_retired_stamp(&stamp)
                .then_some(request.confirm_traffic_drained())
                .ok_or(crate::GtpuError::StateIndeterminate {
                    operation: "faulting_selector_reuse_stamp",
                })
        }

        async fn inspect_selector_namespace_decommission_fence(
            &self,
            request: GtpuSessionSelectorDecommissionInspectRequest,
        ) -> Result<GtpuSessionSelectorBackendReceipt, crate::GtpuError> {
            let delay_millis = self
                .terminal_inspect_delay_millis
                .load(std::sync::atomic::Ordering::Acquire);
            if delay_millis != 0 {
                tokio::time::sleep(Duration::from_millis(delay_millis)).await;
            }
            if self
                .terminal_inspect_fault
                .load(std::sync::atomic::Ordering::Acquire)
            {
                return Err(crate::GtpuError::StateIndeterminate {
                    operation: "faulting_selector_terminal_inspection",
                });
            }
            if !request.is_current() {
                return Err(crate::GtpuError::StateIndeterminate {
                    operation: "faulting_selector_terminal_inspection_window",
                });
            }
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
            if !request.is_current() {
                return Err(crate::GtpuError::StateIndeterminate {
                    operation: "faulting_selector_terminal_create_window",
                });
            }
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
            if !request.is_current() {
                return Err(crate::GtpuError::StateIndeterminate {
                    operation: "faulting_selector_terminal_readback_window",
                });
            }
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
            if !request.is_current() {
                return Err(crate::GtpuError::StateIndeterminate {
                    operation: "faulting_selector_effect_window",
                });
            }
            let desired = request.desired_group().clone();
            if request.request.selector_provenance().is_some() {
                self.reused_effect_calls
                    .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            }
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
            if !request.is_current() {
                return Err(crate::GtpuError::StateIndeterminate {
                    operation: "faulting_selector_readback_window",
                });
            }
            let expected = request.expected_group().clone();
            let readback = self.dataplane_readback(&expected)?;
            if matches!(
                request.admission.phase,
                SelectorAdmissionPhase::Retiring | SelectorAdmissionPhase::Retired
            ) && matches!(readback, crate::GtpuSessionGroupReadback::Absent)
            {
                let mode = self
                    .terminal_retired_readback_mode
                    .load(std::sync::atomic::Ordering::Acquire);
                if mode == TerminalRetiredReadbackMode::Unstamped as u8 {
                    return Ok(request.complete(readback));
                }
                let mut stamp = Self::terminal_retired_stamp(&request.admission);
                if mode == TerminalRetiredReadbackMode::MutatedGeneration as u8 {
                    stamp[199] ^= 1;
                }
                return request.complete_terminal_retired(readback, &stamp).ok_or(
                    crate::GtpuError::StateIndeterminate {
                        operation: "faulting_selector_terminal_stamp",
                    },
                );
            }
            Ok(request.complete(readback))
        }

        async fn remove_pdp_context_group_with_lease(
            &self,
            request: GtpuSessionSelectorRemovalRequest,
        ) -> Result<GtpuSessionSelectorBackendReceipt, crate::GtpuError> {
            if !request.is_current() {
                return Err(crate::GtpuError::StateIndeterminate {
                    operation: "faulting_selector_removal_window",
                });
            }
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
            let stamp = Self::terminal_retired_stamp(&request.admission);
            request.complete_terminal_retired(outcome, &stamp).ok_or(
                crate::GtpuError::StateIndeterminate {
                    operation: "faulting_selector_terminal_stamp",
                },
            )
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
    fn pending_admission_constructor_rejects_aliased_nonces() {
        let namespace = InMemoryGtpuSessionSelectorNamespace::new([0x53; 32]);
        let admission = namespace
            .claim(&group(1, 1, 0x1000_0001, None), None)
            .unwrap();
        let active = SelectorAuthorityCoordinate {
            generation: admission.generation(),
            nonce: admission.operation_nonce(),
        };
        let installing_generation = GtpuSessionSelectorAuthorityGeneration(
            NonZeroU64::new(admission.generation().get() + 1).unwrap(),
        );
        let installing_nonce = [0x61; 16];
        assert!(matches!(
            admission.with_coordinates(
                installing_generation,
                installing_nonce,
                SelectorAuthorityCoordinate {
                    generation: GtpuSessionSelectorAuthorityGeneration(
                        NonZeroU64::new(installing_generation.get() + 1).unwrap(),
                    ),
                    nonce: installing_nonce,
                },
                None,
                SelectorAdmissionPhase::Installing,
            ),
            Err(GtpuSessionSelectorNamespaceError::Indeterminate)
        ));

        let retiring_generation = GtpuSessionSelectorAuthorityGeneration(
            NonZeroU64::new(installing_generation.get() + 1).unwrap(),
        );
        let retiring_nonce = [0x62; 16];
        assert!(matches!(
            admission.with_coordinates(
                retiring_generation,
                retiring_nonce,
                SelectorAuthorityCoordinate {
                    generation: GtpuSessionSelectorAuthorityGeneration(
                        NonZeroU64::new(retiring_generation.get() + 1).unwrap(),
                    ),
                    nonce: retiring_nonce,
                },
                Some(active),
                SelectorAdmissionPhase::Retiring,
            ),
            Err(GtpuSessionSelectorNamespaceError::Indeterminate)
        ));
    }

    #[test]
    fn backend_receipts_are_bound_to_the_exact_consumed_request() {
        let first_namespace = InMemoryGtpuSessionSelectorNamespace::new([0x53; 32]);
        let second_namespace = InMemoryGtpuSessionSelectorNamespace::new([0x54; 32]);
        let first = group(1, 1, 0x1000_0001, None);
        let second = group(2, 2, 0x1000_0002, None);
        let first_admission = first_namespace.claim(&first, None).unwrap();
        let second_admission = second_namespace.claim(&second, None).unwrap();
        let first_binding = first_admission.binding();
        let second_binding = second_admission.binding();
        let installing = |admission: GtpuSessionSelectorAdmission, terminal_nonce: u8| {
            let generation = admission.generation();
            let operation_nonce = admission.operation_nonce();
            admission
                .with_coordinates(
                    generation,
                    operation_nonce,
                    SelectorAuthorityCoordinate {
                        generation: GtpuSessionSelectorAuthorityGeneration(
                            NonZeroU64::new(generation.get() + 1).unwrap(),
                        ),
                        nonce: [terminal_nonce; 16],
                    },
                    None,
                    SelectorAdmissionPhase::Installing,
                )
                .unwrap()
        };
        let first_admission = installing(first_admission, 0x61);
        let second_admission = installing(second_admission, 0x62);

        let first_request = GtpuSessionSelectorEffectRequest {
            request: GtpuSessionGroupReconcileRequest::new(first, first_admission).unwrap(),
            window: test_backend_mutation_window(),
        };
        let expected = first_request.receipt_coordinate();
        let second_request = GtpuSessionSelectorEffectRequest {
            request: GtpuSessionGroupReconcileRequest::new(second, second_admission).unwrap(),
            window: test_backend_mutation_window(),
        };
        let swapped = second_request.complete(GtpuSessionGroupReconcileOutcome::Activated);
        assert!(swapped.into_effect(expected).is_none());

        let mut mutated = expected;
        mutated.0[0] ^= 1;
        let exact = first_request.complete(GtpuSessionGroupReconcileOutcome::Activated);
        assert!(exact.into_effect(expected).is_some());
        let mutated_receipt = GtpuSessionSelectorBackendReceipt::effect(
            expected,
            GtpuSessionGroupReconcileOutcome::Activated,
            test_backend_mutation_window().into_receipt(),
        );
        assert!(mutated_receipt.into_effect(mutated).is_none());

        let first_lease = GtpuSessionSelectorBindingLease {
            binding: first_binding,
            inventory: test_operation_stamp_inventory(),
            window: test_backend_mutation_window(),
        };
        let expected_binding = first_lease.receipt_coordinate();
        let wrong_binding = GtpuSessionSelectorBindingLease {
            binding: second_binding,
            inventory: test_operation_stamp_inventory(),
            window: test_backend_mutation_window(),
        }
        .confirm();
        assert!(!wrong_binding.confirms_binding(expected_binding));
        assert!(first_lease.confirm().confirms_binding(expected_binding));
    }

    #[test]
    fn backend_receipt_coordinates_cover_every_request_class() {
        let first_namespace = InMemoryGtpuSessionSelectorNamespace::new([0x55; 32]);
        let second_namespace = InMemoryGtpuSessionSelectorNamespace::new([0x56; 32]);
        let first_group = group(3, 3, 0x1000_0003, None);
        let second_group = group(4, 4, 0x1000_0004, None);
        let first_admission = first_namespace.claim(&first_group, None).unwrap();
        let second_admission = second_namespace.claim(&second_group, None).unwrap();
        let first_binding = first_admission.binding();
        let second_binding = second_admission.binding();

        let provision = GtpuSessionSelectorProvisionRequest {
            binding: first_binding,
            window: test_backend_mutation_window(),
        };
        let expected_provision = provision.receipt_coordinate();
        let cross_provision = GtpuSessionSelectorProvisionRequest {
            binding: second_binding,
            window: test_backend_mutation_window(),
        }
        .confirm();
        assert!(!cross_provision.confirms_provisioning(expected_provision));
        assert!(provision
            .confirm()
            .confirms_provisioning(expected_provision));

        let readback = GtpuSessionSelectorReadbackRequest {
            expected: first_group.clone(),
            admission: first_admission,
            window: test_backend_mutation_window(),
        };
        let expected_readback = readback.receipt_coordinate();
        let cross_readback = GtpuSessionSelectorReadbackRequest {
            expected: second_group.clone(),
            admission: second_admission,
            window: test_backend_mutation_window(),
        }
        .complete(crate::GtpuSessionGroupReadback::Active(second_group));
        assert!(cross_readback.into_readback(expected_readback).is_none());
        assert!(readback
            .complete(crate::GtpuSessionGroupReadback::Active(first_group))
            .into_readback(expected_readback)
            .is_some());

        let first_remove_group = group(5, 5, 0x1000_0005, None);
        let second_remove_group = group(6, 6, 0x1000_0006, None);
        let first_removal_namespace = InMemoryGtpuSessionSelectorNamespace::new([0x57; 32]);
        let second_removal_namespace = InMemoryGtpuSessionSelectorNamespace::new([0x58; 32]);
        let first_active = first_removal_namespace
            .claim(&first_remove_group, None)
            .unwrap();
        let second_active = second_removal_namespace
            .claim(&second_remove_group, None)
            .unwrap();
        let retiring = |admission: GtpuSessionSelectorAdmission, nonce: u8| {
            let active = SelectorAuthorityCoordinate {
                generation: admission.generation(),
                nonce: admission.operation_nonce(),
            };
            let retiring_generation = GtpuSessionSelectorAuthorityGeneration(
                NonZeroU64::new(admission.generation().get() + 1).unwrap(),
            );
            let retired_generation = GtpuSessionSelectorAuthorityGeneration(
                NonZeroU64::new(retiring_generation.get() + 1).unwrap(),
            );
            admission
                .with_coordinates(
                    retiring_generation,
                    [nonce; 16],
                    SelectorAuthorityCoordinate {
                        generation: retired_generation,
                        nonce: [nonce.wrapping_add(1); 16],
                    },
                    Some(active),
                    SelectorAdmissionPhase::Retiring,
                )
                .unwrap()
        };
        let first_removal = GtpuSessionSelectorRemovalRequest {
            expected: first_remove_group,
            admission: retiring(first_active, 0x71),
            window: test_backend_mutation_window(),
        };
        let expected_removal = first_removal.receipt_coordinate();
        let cross_removal = GtpuSessionSelectorRemovalRequest {
            expected: second_remove_group,
            admission: retiring(second_active, 0x73),
            window: test_backend_mutation_window(),
        }
        .complete(GtpuSessionGroupRemovalOutcome::Removed);
        assert!(cross_removal.into_removal(expected_removal).is_none());
        assert!(first_removal
            .complete(GtpuSessionGroupRemovalOutcome::Removed)
            .into_removal(expected_removal)
            .is_some());

        let fence = DecommissionFence {
            predecessor_commitment: [0x81; 32],
            decommissioning: SelectorAuthorityCoordinate {
                generation: GtpuSessionSelectorAuthorityGeneration(NonZeroU64::new(2).unwrap()),
                nonce: [0x82; 16],
            },
            decommissioned: SelectorAuthorityCoordinate {
                generation: GtpuSessionSelectorAuthorityGeneration(NonZeroU64::new(3).unwrap()),
                nonce: [0x83; 16],
            },
            capsule: [0x84; DECOMMISSION_CAPSULE_LEN],
        };
        let inspect = GtpuSessionSelectorDecommissionInspectRequest {
            binding: first_binding,
            expected_fence: None,
            window: test_backend_mutation_window(),
        };
        let expected_inspection = inspect.receipt_coordinate();
        let cross_inspection = GtpuSessionSelectorDecommissionInspectRequest {
            binding: second_binding,
            expected_fence: None,
            window: test_backend_mutation_window(),
        }
        .confirm_absent();
        assert!(!cross_inspection.confirms_decommission_fence_absent(expected_inspection));
        assert!(inspect
            .confirm_absent()
            .confirms_decommission_fence_absent(expected_inspection));

        let create = GtpuSessionSelectorDecommissionRequest {
            binding: first_binding,
            fence,
            window: test_backend_mutation_window(),
        };
        let expected_create = create.receipt_coordinate();
        let wrong_class = GtpuSessionSelectorDecommissionReadbackRequest {
            binding: first_binding,
            fence,
            window: test_backend_mutation_window(),
        }
        .confirm_exact();
        assert!(!wrong_class.confirms_decommission_fence_exact(expected_create));
        assert!(create
            .confirm()
            .confirms_decommission_fence_exact(expected_create));

        let readback = GtpuSessionSelectorDecommissionReadbackRequest {
            binding: first_binding,
            fence,
            window: test_backend_mutation_window(),
        };
        let expected_fence_readback = readback.receipt_coordinate();
        let wrong_fence = DecommissionFence {
            capsule: [0x85; DECOMMISSION_CAPSULE_LEN],
            ..fence
        };
        let cross_fence = GtpuSessionSelectorDecommissionReadbackRequest {
            binding: first_binding,
            fence: wrong_fence,
            window: test_backend_mutation_window(),
        }
        .confirm_exact();
        assert!(!cross_fence.confirms_decommission_fence_exact(expected_fence_readback));
        assert!(readback
            .confirm_exact()
            .confirms_decommission_fence_exact(expected_fence_readback));
    }

    #[test]
    fn operation_stamp_inventory_preserves_every_lifecycle_expectation_exactly() {
        let (state, binding) = inventory_matrix_state(1, 0);
        let inventory = state.operation_stamp_inventory(binding).unwrap();
        let expectations = inventory.expectations();
        assert_eq!(expectations.len(), 5);
        assert_eq!(
            expectations
                .iter()
                .map(|expectation| expectation.group().id().to_bytes())
                .collect::<Vec<_>>(),
            vec![[1; 16], [2; 16], [3; 16], [4; 16], [5; 16]],
        );
        for (index, expectation) in expectations.iter().enumerate() {
            let expected_group = group((index + 1) as u8, 1, 0x1000_0001 + index as u32, None);
            let claim = CanonicalClaim::from_group(&expected_group)
                .with_key(&state.selector_digest_key)
                .unwrap();
            assert_eq!(expectation.group(), &expected_group);
            assert_eq!(expectation.device_fingerprint(), claim.device_fingerprint);
            assert_eq!(expectation.group_fingerprint(), claim.group_fingerprint);
            assert_eq!(
                expectation.selector_set_fingerprint(),
                claim.selector_set_fingerprint
            );
            assert_eq!(expectation.desired_fingerprint(), claim.desired_fingerprint);
        }
        let installing = expectations[0].lifecycle();
        assert_eq!(
            installing.kind(),
            SelectorOperationStampLifecycleKind::Installing
        );
        assert_eq!(installing.backend_started(), Some(true));
        assert_eq!(installing.pending().unwrap().generation().get(), 1);
        assert_eq!(installing.pending().unwrap().nonce(), [0x11; 16]);
        assert_eq!(installing.terminal().generation().get(), 2);
        assert_eq!(installing.terminal().nonce(), [0x12; 16]);
        assert_eq!(installing.previous_terminal(), None);
        assert_eq!(installing.retired_dataplane_generation(), None);

        let active = expectations[1].lifecycle();
        assert_eq!(active.kind(), SelectorOperationStampLifecycleKind::Active);
        assert_eq!(active.backend_started(), None);
        assert_eq!(active.pending(), None);
        assert_eq!(active.terminal().generation().get(), 3);
        assert_eq!(active.terminal().nonce(), [0x13; 16]);

        let retiring = expectations[2].lifecycle();
        assert_eq!(
            retiring.kind(),
            SelectorOperationStampLifecycleKind::Retiring
        );
        assert_eq!(retiring.backend_started(), Some(false));
        assert_eq!(retiring.pending().unwrap().generation().get(), 5);
        assert_eq!(retiring.pending().unwrap().nonce(), [0x15; 16]);
        assert_eq!(retiring.terminal().generation().get(), 6);
        assert_eq!(retiring.terminal().nonce(), [0x16; 16]);
        assert_eq!(retiring.previous_terminal().unwrap().generation().get(), 4);
        assert_eq!(retiring.previous_terminal().unwrap().nonce(), [0x14; 16]);
        assert_eq!(retiring.retired_dataplane_generation(), None);

        let retired = expectations[3].lifecycle();
        assert_eq!(retired.kind(), SelectorOperationStampLifecycleKind::Retired);
        assert_eq!(retired.pending(), None);
        assert_eq!(retired.terminal().generation().get(), 8);
        assert_eq!(retired.terminal().nonce(), [0x18; 16]);
        assert_eq!(retired.retired_dataplane_generation().unwrap().get(), 9);

        let poisoned = expectations[4].lifecycle();
        assert_eq!(
            poisoned.kind(),
            SelectorOperationStampLifecycleKind::Poisoned
        );
        assert_eq!(poisoned.poison_phase(), Some(2));
        assert_eq!(
            poisoned.poison_reason(),
            Some(PoisonReason::RemovalReadbackIndeterminate.tag())
        );
        assert_eq!(poisoned.pending().unwrap().generation().get(), 10);
        assert_eq!(poisoned.pending().unwrap().nonce(), [0x1a; 16]);
        assert_eq!(poisoned.terminal().generation().get(), 11);
        assert_eq!(poisoned.terminal().nonce(), [0x1b; 16]);
        assert_eq!(poisoned.previous_terminal().unwrap().generation().get(), 9);
        assert_eq!(poisoned.previous_terminal().unwrap().nonce(), [0x19; 16]);
        assert_eq!(poisoned.retired_dataplane_generation(), None);
    }

    #[test]
    fn operation_stamp_inventory_rejects_duplicate_group_id_map_keys() {
        let (mut state, binding) = inventory_matrix_state(1, 0);
        let replaced = group(2, 1, 0x1000_0002, None);
        let replaced_claim = CanonicalClaim::from_group(&replaced)
            .with_key(&state.selector_digest_key)
            .unwrap();
        let duplicate = group(1, 2, 0x1000_1002, None);
        let duplicate_claim = CanonicalClaim::from_group(&duplicate)
            .with_key(&state.selector_digest_key)
            .unwrap();
        let duplicate_atoms = duplicate_claim
            .selector_atoms(&state.selector_digest_key)
            .unwrap();
        state.groups.remove(&replaced_claim.group_fingerprint);
        state
            .canonical_desired
            .remove(&replaced_claim.group_fingerprint);
        state
            .retain_canonical_desired(duplicate_claim.group_fingerprint, &duplicate)
            .unwrap();
        state.groups.insert(
            duplicate_claim.group_fingerprint,
            GroupState::Active {
                device: duplicate_claim.device_fingerprint,
                selectors: duplicate_claim.selector_set_fingerprint,
                desired: duplicate_claim.desired_fingerprint,
                atoms: duplicate_atoms,
                generation: inventory_generation(3),
                operation_nonce: [0x13; 16],
            },
        );
        assert!(matches!(
            state.operation_stamp_inventory(binding),
            Err(GtpuSessionSelectorNamespaceError::Indeterminate)
        ));
    }

    #[test]
    fn operation_inventory_and_binding_receipts_commit_all_protected_inputs() {
        let (state, binding) = inventory_matrix_state(1, 0);
        let baseline = state.operation_stamp_inventory(binding).unwrap();

        let mut changed_generation = state.clone();
        let installing = CanonicalClaim::from_group(&group(1, 1, 0x1000_0001, None))
            .with_key(&changed_generation.selector_digest_key)
            .unwrap();
        let Some(GroupState::Installing {
            generation,
            terminal_generation,
            ..
        }) = changed_generation
            .groups
            .get_mut(&installing.group_fingerprint)
        else {
            panic!("matrix installing row");
        };
        *generation = inventory_generation(12);
        *terminal_generation = inventory_generation(13);
        changed_generation.generation = 13;
        let changed = changed_generation
            .operation_stamp_inventory(binding)
            .unwrap();
        assert_inventory_receipt_binding_changes(binding, &baseline, binding, &changed);

        let mut changed_canonical = state.clone();
        let original = group(1, 1, 0x1000_0001, None);
        let mut context = original.entries()[0].context().clone();
        context.peer_teid = Teid::new(0x2000_0001).unwrap();
        let changed_group = GtpuSessionGroup::new(
            original.id(),
            original.device_id(),
            vec![
                GtpuSessionEntry::new(context, original.entries()[0].local_outer_address())
                    .unwrap(),
            ],
        )
        .unwrap();
        let changed_claim = CanonicalClaim::from_group(&changed_group)
            .with_key(&changed_canonical.selector_digest_key)
            .unwrap();
        assert_eq!(
            changed_claim.group_fingerprint,
            installing.group_fingerprint
        );
        changed_canonical.canonical_desired.insert(
            changed_claim.group_fingerprint,
            Zeroizing::new(canonical_desired_bytes(&changed_group)),
        );
        let Some(GroupState::Installing { desired, .. }) = changed_canonical
            .groups
            .get_mut(&changed_claim.group_fingerprint)
        else {
            panic!("matrix canonical desired row");
        };
        *desired = changed_claim.desired_fingerprint;
        let changed = changed_canonical
            .operation_stamp_inventory(binding)
            .unwrap();
        assert_inventory_receipt_binding_changes(binding, &baseline, binding, &changed);

        let (changed_device_state, changed_device_binding) = inventory_matrix_state(2, 0);
        let changed = changed_device_state
            .operation_stamp_inventory(changed_device_binding)
            .unwrap();
        assert_inventory_receipt_binding_changes(
            binding,
            &baseline,
            changed_device_binding,
            &changed,
        );

        let (changed_selector_state, changed_selector_binding) = inventory_matrix_state(1, 0x100);
        let changed = changed_selector_state
            .operation_stamp_inventory(changed_selector_binding)
            .unwrap();
        assert_inventory_receipt_binding_changes(
            binding,
            &baseline,
            changed_selector_binding,
            &changed,
        );

        let mut changed_binding = binding;
        changed_binding.backend_epoch[0] ^= 1;
        let changed = state.operation_stamp_inventory(changed_binding).unwrap();
        assert_inventory_receipt_binding_changes(binding, &baseline, changed_binding, &changed);
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
    fn model_claim_applies_the_same_permanent_capacity_preflight_as_production() {
        let namespace = InMemoryGtpuSessionSelectorNamespace::default();
        let desired = group(1, 1, 0x1000_0001, None);
        {
            let mut state = namespace.state.lock().expect("model state lock");
            state
                .bind_or_validate(
                    desired.device_id(),
                    SELECTOR_NAMESPACE_MAX_READBACK_ATOMS,
                    Some(namespace.key),
                )
                .unwrap();
            for index in 0..MAX_PERMANENT_GROUPS {
                let mut fingerprint = [0_u8; 32];
                fingerprint[..8].copy_from_slice(&(index as u64).to_be_bytes());
                state.groups.insert(fingerprint, GroupState::LegacyPoisoned);
            }
        }

        assert!(matches!(
            namespace.claim(&desired, None),
            Err(GtpuSessionSelectorNamespaceError::CapacityExhausted)
        ));
        let state = namespace.state.lock().expect("model state lock");
        assert_eq!(state.groups.len(), MAX_PERMANENT_GROUPS);
        assert_eq!(state.generation, 0, "capacity failure must not mint state");
    }

    #[test]
    fn model_reissue_rejects_missing_or_malformed_predecessor_tombstones() {
        for malformed in [false, true] {
            let namespace = InMemoryGtpuSessionSelectorNamespace::default();
            let original = group(1, 1, 0x1000_0001, None);
            let source = namespace.claim(&original, None).unwrap();
            namespace
                .finish_retire(namespace.begin_retire(source).unwrap())
                .unwrap();
            let successor = GtpuSessionGroup::new(
                GtpuSessionGroupId::new([2; 16]).unwrap(),
                original.device_id(),
                original.entries().to_vec(),
            )
            .unwrap();
            let source_claim = CanonicalClaim::from_group(&original)
                .with_key(&namespace.key)
                .unwrap();
            let successor_claim = CanonicalClaim::from_group(&successor)
                .with_key(&namespace.key)
                .unwrap();
            let before_generation;
            {
                let mut state = namespace.state.lock().expect("model state lock");
                let Some(GroupState::Retired { atoms, .. }) =
                    state.groups.get(&source_claim.group_fingerprint)
                else {
                    panic!("retired source row");
                };
                let atom = *atoms.iter().next().expect("retired source atom");
                state.tombstones.remove(&atom);
                if malformed {
                    state.tombstones.insert([0xff; 32]);
                }
                before_generation = state.generation;
            }

            assert!(matches!(
                namespace.claim_reused(
                    &successor,
                    &crate::GtpuSessionSelectorReuseProof::after_traffic_drain(original),
                ),
                Err(GtpuSessionSelectorNamespaceError::SelectorClaimed)
            ));
            let state = namespace.state.lock().expect("model state lock");
            assert_eq!(state.generation, before_generation);
            assert!(!state
                .groups
                .contains_key(&successor_claim.group_fingerprint));
            assert!(matches!(
                state.groups.get(&source_claim.group_fingerprint),
                Some(GroupState::Retired {
                    successor: None,
                    ..
                })
            ));
        }
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
    fn selector_atom_codec_matches_rfc016_paa_and_mark_golden_bytes() {
        let ipv4 = group_with_paa(
            1,
            1,
            0x1000_0001,
            IpAddr::V4(Ipv4Addr::new(10, 23, 0, 9)),
            Some(0x0102_0304),
        );
        let ipv6 = group_with_paa(
            2,
            1,
            0x1000_0002,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0xabcd, 0, 0, 1)),
            None,
        );
        let ipv4_atoms = CanonicalClaim::from_group(&ipv4).atoms;
        let ipv6_atoms = CanonicalClaim::from_group(&ipv6).atoms;
        let paa_v4 = vec![b'P', 0, 6, 4, 32, 10, 23, 0, 9];
        let paa_v6 = vec![b'P', 0, 10, 6, 64, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1];
        let mark = vec![b'M', 0, 8, 0x01, 0x02, 0x03, 0x04, 0xff, 0xff, 0xff, 0xff];
        assert!(ipv4_atoms.contains(&paa_v4));
        assert!(ipv4_atoms.contains(&mark));
        assert!(ipv6_atoms.contains(&paa_v6));
        assert_eq!(ipv4_atoms.len(), 3, "TEID, PAA, and mark atoms only");
        assert_eq!(ipv6_atoms.len(), 2, "TEID and canonical /64 PAA atoms only");

        // These are codec-level, not merely HMAC-level, adversarial changes:
        // any field/order mutation must cease to be the canonical atom.
        let mut wrong_family = paa_v4.clone();
        wrong_family[3] = 6;
        let mut wrong_prefix = paa_v4.clone();
        wrong_prefix[4] = 64;
        let mut wrong_address = paa_v4.clone();
        wrong_address[8] ^= 1;
        let mut wrong_mark_order = mark.clone();
        wrong_mark_order[3..11].rotate_left(4);
        for mutated in [wrong_family, wrong_prefix, wrong_address, wrong_mark_order] {
            assert!(!ipv4_atoms.contains(&mutated));
            assert_ne!(
                keyed_digest(&[0x53; 32], ATOM_DOMAIN, &mutated),
                keyed_digest(&[0x53; 32], ATOM_DOMAIN, &mark),
                "a raw codec mutation must not collapse to the canonical mark atom"
            );
        }
        assert_ne!(
            keyed_digest(&[0x53; 32], ATOM_DOMAIN, &paa_v4),
            keyed_digest(&[0x53; 32], ATOM_DOMAIN, &paa_v6),
            "family and prefix semantics remain independently committed"
        );
    }

    #[tokio::test]
    async fn retired_stamp_requires_the_exact_persisted_dataplane_generation() {
        let original = group(1, 1, 0x1000_0001, None);
        let successor = group(2, 1, 0x1000_0001, None);
        let authority = production_authority(original.device_id()).await;
        let backend = Arc::new(FaultingSelectorBackend::default());
        authority.provision(backend.as_ref()).await.unwrap();
        let active = authority
            .reconcile_fresh(backend.clone(), original.clone())
            .await
            .unwrap();
        let retired = authority.retire(backend, active, original).await.unwrap();
        let request = GtpuSessionSelectorReuseRequest {
            retired,
            desired: successor,
            window: test_backend_mutation_window(),
        };
        let stamp = FaultingSelectorBackend::terminal_retired_stamp(&request.retired.admission);
        assert!(request.verifies_exact_terminal_retired_stamp(&stamp));

        // A candidate copied from the same receipt except for any byte in
        // the protected backend-observed generation must not authorize reuse.
        for byte in 192..200 {
            let mut mutated = stamp;
            mutated[byte] ^= 1;
            assert!(
                !request.verifies_exact_terminal_retired_stamp(&mutated),
                "mutating terminal dataplane-generation byte {byte} must fail"
            );
        }
    }

    #[tokio::test]
    async fn retired_recovery_requires_exact_generation_stamped_absence() {
        let desired = group(1, 1, 0x1000_0001, None);
        let authority = production_authority(desired.device_id()).await;
        let backend = Arc::new(FaultingSelectorBackend::default());
        authority.provision(backend.as_ref()).await.unwrap();
        let active = authority
            .reconcile_fresh(backend.clone(), desired.clone())
            .await
            .unwrap();
        drop(
            authority
                .retire(backend.clone(), active, desired.clone())
                .await
                .unwrap(),
        );

        backend.set_terminal_retired_readback_mode(TerminalRetiredReadbackMode::Unstamped);
        assert!(matches!(
            authority
                .recover_retired(backend.clone(), desired.clone())
                .await,
            Err(GtpuSessionSelectorCoordinatorError::Backend)
        ));
        let (_, poisoned) = authority.read_state().await.unwrap();
        let claim = CanonicalClaim::from_group(&desired)
            .with_key(&poisoned.selector_digest_key)
            .unwrap();
        assert!(matches!(
            poisoned.groups.get(&claim.group_fingerprint),
            Some(GroupState::Poisoned(poison)) if poison.phase == 3
        ));
        backend.set_terminal_retired_readback_mode(TerminalRetiredReadbackMode::Exact);
        assert!(matches!(
            authority.recover_retired(backend, desired).await,
            Err(GtpuSessionSelectorCoordinatorError::Namespace)
        ));
    }

    #[tokio::test]
    async fn reopening_with_one_under_or_over_capacity_fails_before_backend_mutation() {
        let device = GtpuSessionDeviceId::new([1; 16]).unwrap();
        let namespace_key = SessionKey {
            tenant: TenantId::from_static("selector-capacity-test"),
            nf_kind: NetworkFunctionKind::from_static("epdg"),
            key_type: SessionKeyType::other("gtpu-selector-namespace")
                .expect("valid test namespace key type"),
            stable_id: StableId::new(Bytes::copy_from_slice(&device.to_bytes()))
                .expect("valid test namespace stable ID"),
        };
        let store = SessionStore::new(
            SqliteSessionBackend::in_memory().expect("in-memory durable namespace backend"),
        );
        let backend = Arc::new(FaultingSelectorBackend::default());
        let authority = raw_production_authority(
            store.clone(),
            namespace_key.clone(),
            "selector-capacity-owner",
            32,
        )
        .await;
        authority.provision(backend.as_ref()).await.unwrap();
        assert_eq!(backend.provision_calls(), 1);
        let desired = group(1, 1, 0x1000_0001, None);
        let _active = authority
            .reconcile_fresh(backend.clone(), desired.clone())
            .await
            .unwrap();
        assert_eq!(backend.effect_calls(), 1);

        for maximum_atoms in [31, 33] {
            let reopened = raw_production_authority(
                store.clone(),
                namespace_key.clone(),
                "selector-capacity-reopen",
                maximum_atoms,
            )
            .await;
            assert!(matches!(
                reopened.provision(backend.as_ref()).await,
                Err(GtpuSessionSelectorNamespaceError::ConfigurationMismatch)
            ));
            assert!(matches!(
                reopened
                    .recover_active(backend.clone(), desired.clone())
                    .await,
                Err(GtpuSessionSelectorCoordinatorError::Namespace)
            ));
        }
        assert_eq!(
            backend.provision_calls(),
            1,
            "capacity mismatch must stop before a backend marker, map, or lease mutation"
        );
        assert_eq!(
            backend.effect_calls(),
            1,
            "capacity mismatch must stop recovery before an authorized backend readback"
        );
    }

    #[tokio::test]
    async fn supervisor_rejects_n_plus_one_before_the_worker_future_starts() {
        let scope = [0xa5; 32];
        let namespace = selector_namespace_supervisors(scope);
        let permits = (0..SELECTOR_NAMESPACE_MAX_SUPERVISORS_PER_NAMESPACE)
            .map(|_| {
                namespace
                    .clone()
                    .try_acquire_owned()
                    .expect("test fills every namespace supervisor slot")
            })
            .collect::<Vec<_>>();
        let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_started = Arc::clone(&started);
        let operation = spawn_selector_operation(scope, (), async move {
            worker_started.store(true, std::sync::atomic::Ordering::Release);
            Ok::<(), ()>(())
        });
        assert_eq!(operation.await, Err(()));
        assert!(
            !started.load(std::sync::atomic::Ordering::Acquire),
            "the rejected N+1 worker must not enter a phase or execute its future"
        );
        drop(permits);
    }

    #[tokio::test]
    async fn namespace_worker_gate_survives_observer_drop_and_serializes_before_poll() {
        let scope = [0xa6; 32];
        let first_entered = Arc::new(tokio::sync::Notify::new());
        let release_first = Arc::new(tokio::sync::Notify::new());
        let first_entered_worker = Arc::clone(&first_entered);
        let release_first_worker = Arc::clone(&release_first);
        let first = spawn_selector_operation(scope, (), async move {
            first_entered_worker.notify_one();
            release_first_worker.notified().await;
            Ok::<(), ()>(())
        });
        first_entered.notified().await;
        drop(first);

        let second_started = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let second_started_worker = Arc::clone(&second_started);
        let second = spawn_selector_operation(scope, (), async move {
            second_started_worker.store(true, std::sync::atomic::Ordering::Release);
            Ok::<(), ()>(())
        });
        tokio::task::yield_now().await;
        assert!(
            !second_started.load(std::sync::atomic::Ordering::Acquire),
            "a queued same-scope worker must not be polled before its predecessor finishes"
        );

        release_first.notify_one();
        assert_eq!(second.await, Ok(()));
        assert!(second_started.load(std::sync::atomic::Ordering::Acquire));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn expired_backend_step_drains_blocking_worker_before_releasing_namespace_gate() {
        let scope = [0xa7; 32];
        let blocking_entered = Arc::new(tokio::sync::Notify::new());
        let blocking_completed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (release_blocking, await_release) = std::sync::mpsc::channel::<()>();
        let entered_worker = Arc::clone(&blocking_entered);
        let completed_worker = Arc::clone(&blocking_completed);

        let first = spawn_selector_operation(scope, (), async move {
            settle_selector_backend_step_within(Duration::from_millis(5), async move {
                tokio::task::spawn_blocking(move || {
                    entered_worker.notify_one();
                    await_release.recv().map_err(|_| ())?;
                    completed_worker.store(true, std::sync::atomic::Ordering::Release);
                    Ok::<(), ()>(())
                })
                .await
                .map_err(|_| ())?
            })
            .await
            .ok_or(())?
        });
        blocking_entered.notified().await;
        drop(first);

        // Let the observation deadline expire while the started blocking task
        // remains deliberately held. The detached SDK worker must keep both
        // the backend future and the per-namespace gate alive.
        tokio::time::sleep(Duration::from_millis(20)).await;
        let second_started = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let second_started_worker = Arc::clone(&second_started);
        let second = spawn_selector_operation(scope, (), async move {
            second_started_worker.store(true, std::sync::atomic::Ordering::Release);
            Ok::<(), ()>(())
        });
        tokio::task::yield_now().await;
        assert!(
            !second_started.load(std::sync::atomic::Ordering::Acquire),
            "an expired observation must not cancel its live blocking worker or release the scope gate"
        );
        assert!(
            !blocking_completed.load(std::sync::atomic::Ordering::Acquire),
            "the held blocking worker must still be live at the adversarial deadline"
        );

        release_blocking
            .send(())
            .expect("release the exact test-owned blocking worker");
        assert_eq!(second.await, Ok(()));
        assert!(blocking_completed.load(std::sync::atomic::Ordering::Acquire));
        assert!(second_started.load(std::sync::atomic::Ordering::Acquire));
    }

    #[tokio::test]
    async fn reused_install_recovery_reconstructs_durable_predecessor_provenance() {
        let reusable_paa = IpAddr::V4(Ipv4Addr::new(10, 23, 0, 1));
        let original = group_with_paa(1, 1, 0x1000_0001, reusable_paa, None);
        let successor = group_with_paa(2, 1, 0x1000_0001, reusable_paa, None);
        let authority = production_authority(original.device_id()).await;
        let backend = Arc::new(FaultingSelectorBackend::default());
        authority.provision(backend.as_ref()).await.unwrap();
        let active = authority
            .reconcile_fresh(backend.clone(), original.clone())
            .await
            .unwrap();
        let retired = authority
            .retire(backend.clone(), active, original)
            .await
            .unwrap();
        let GtpuSessionSelectorReuseAuthorization { desired, proof } = authority
            .authorize_reuse(backend.clone(), successor.clone(), retired)
            .await
            .unwrap();

        // Simulate a process loss after the durable Installing(false) CAS.
        // Recovery receives no old authorization object, so it can reach the
        // backend only by reconstructing the retained full source descriptor.
        authority
            .claim_reused(backend.as_ref(), &desired, &proof)
            .await
            .unwrap();
        assert!(
            authority
                .installing_reuse_proof(&successor)
                .await
                .unwrap()
                .is_some(),
            "the pending record retains the exact predecessor proof"
        );
        backend.set_dataplane(FaultingSelectorDataplaneState::NoEffect);
        let _ = authority
            .recover_install(backend.clone(), successor.clone())
            .await
            .unwrap();
        assert_eq!(backend.reused_effect_calls(), 1);

        let second_reusable_paa = IpAddr::V4(Ipv4Addr::new(10, 23, 0, 3));
        let second_original = group_with_paa(3, 1, 0x1000_0003, second_reusable_paa, None);
        let second_successor = group_with_paa(4, 1, 0x1000_0003, second_reusable_paa, None);
        let second_authority = production_authority(second_original.device_id()).await;
        let second_backend = Arc::new(FaultingSelectorBackend::default());
        second_authority
            .provision(second_backend.as_ref())
            .await
            .unwrap();
        let active = second_authority
            .reconcile_fresh(second_backend.clone(), second_original.clone())
            .await
            .unwrap();
        let retired = second_authority
            .retire(second_backend.clone(), active, second_original)
            .await
            .unwrap();
        let authorization = second_authority
            .authorize_reuse(second_backend.clone(), second_successor.clone(), retired)
            .await
            .unwrap();
        second_backend.set_effect_fault(true);
        assert!(matches!(
            second_authority
                .reconcile_reused(second_backend.clone(), authorization)
                .await,
            Err(GtpuSessionSelectorCoordinatorError::Backend)
        ));
        let (_, poisoned) = second_authority.read_state().await.unwrap();
        let successor_claim = CanonicalClaim::from_group(&second_successor)
            .with_key(&poisoned.selector_digest_key)
            .unwrap();
        assert!(matches!(
            poisoned.groups.get(&successor_claim.group_fingerprint),
            Some(GroupState::Poisoned(poison)) if poison.phase == 0 && poison.backend_started
        ));
        assert!(NamespaceState::decode(&poisoned.encode()).is_some());
        second_backend.set_effect_fault(false);
        second_backend.set_dataplane(FaultingSelectorDataplaneState::NoEffect);
        let recovery = second_authority
            .recover_install(second_backend.clone(), second_successor)
            .await;
        assert!(
            matches!(
                recovery,
                Err(GtpuSessionSelectorCoordinatorError::Namespace)
            ),
            "unexpected poisoned recovery result: {recovery:?}"
        );
        assert_eq!(second_backend.reused_effect_calls(), 1);
    }

    #[tokio::test]
    async fn reused_lineage_survives_successor_retirement_and_rejects_coordinate_mutation() {
        let reusable_paa = IpAddr::V4(Ipv4Addr::new(10, 24, 0, 1));
        let original = group_with_paa(1, 1, 0x1000_0001, reusable_paa, None);
        let successor = group_with_paa(2, 1, 0x1000_0001, reusable_paa, None);
        let authority = production_authority(original.device_id()).await;
        let backend = Arc::new(FaultingSelectorBackend::default());
        authority.provision(backend.as_ref()).await.unwrap();
        let active = authority
            .reconcile_fresh(backend.clone(), original.clone())
            .await
            .unwrap();
        let retired = authority
            .retire(backend.clone(), active, original)
            .await
            .unwrap();
        let authorization = authority
            .authorize_reuse(backend.clone(), successor.clone(), retired)
            .await
            .unwrap();
        let successor_active = authority
            .reconcile_reused(backend.clone(), authorization)
            .await
            .unwrap();
        let _ = authority
            .retire(backend, successor_active, successor.clone())
            .await
            .unwrap();

        let (_, state) = authority.read_state().await.unwrap();
        assert!(state.is_complete());
        assert!(NamespaceState::decode(&state.encode()).is_some());

        let successor_claim = CanonicalClaim::from_group(&successor)
            .with_key(&state.selector_digest_key)
            .unwrap();
        let mut mutated = state;
        let Some(GroupState::Retired {
            activation_generation,
            ..
        }) = mutated.groups.get_mut(&successor_claim.group_fingerprint)
        else {
            panic!("successor retirement must persist a terminal tombstone");
        };
        *activation_generation = GtpuSessionSelectorAuthorityGeneration(
            NonZeroU64::new(activation_generation.get().checked_add(1).unwrap()).unwrap(),
        );
        assert!(!mutated.is_complete());
        assert!(NamespaceState::decode(&mutated.encode()).is_none());
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
    async fn effect_fault_durably_poisoned_and_never_auto_cleared() {
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

        let (_, state) = authority.read_state().await.unwrap();
        let claim = CanonicalClaim::from_group(&desired)
            .with_key(&state.selector_digest_key)
            .unwrap();
        let Some(GroupState::Poisoned(poison)) = state.groups.get(&claim.group_fingerprint) else {
            panic!("an ambiguous post-handoff backend error must durably poison");
        };
        assert_eq!(poison.phase, 0);
        assert!(poison.backend_started);
        assert_eq!(poison.reason, PoisonReason::EffectReceiptIndeterminate);
        assert_eq!(poison.stamp_evidence, PoisonStampEvidence::NotObserved);
        assert_eq!(poison.device, claim.device_fingerprint);
        assert_eq!(poison.selectors, claim.selector_set_fingerprint);
        assert_eq!(poison.desired, claim.desired_fingerprint);
        assert!(poison.atoms.iter().all(|atom| matches!(
            state.selectors.get(atom),
            Some(SelectorState::Poisoned { group, generation })
                if *group == claim.group_fingerprint && *generation == poison.generation
        )));
        let encoded = state.encode();
        assert!(
            NamespaceState::decode(&encoded).is_some(),
            "poison survives restart codec"
        );

        backend.set_effect_fault(false);
        assert!(matches!(
            authority.reconcile_fresh(backend, desired).await,
            Err(GtpuSessionSelectorCoordinatorError::Namespace)
        ));
        let (_, after_retry) = authority.read_state().await.unwrap();
        assert!(matches!(
            after_retry.groups.get(&claim.group_fingerprint),
            Some(GroupState::Poisoned(_))
        ));
    }

    #[test]
    fn poison_codec_rejects_mutated_authority_metadata() {
        let mut state = NamespaceState::default();
        state
            .bind_or_validate(
                GtpuSessionDeviceId::new([1; 16]).unwrap(),
                32,
                Some([7; 32]),
            )
            .unwrap();
        let desired = group(1, 1, 0x1000_0001, None);
        let claim = CanonicalClaim::from_group(&desired)
            .with_key(&state.selector_digest_key)
            .unwrap();
        let atoms = claim.selector_atoms(&state.selector_digest_key).unwrap();
        let generation = state.next_generation().unwrap();
        let nonce = test_nonzero_nonce(
            &state.selector_digest_key,
            claim.group_fingerprint,
            generation,
        )
        .unwrap();
        let terminal_generation = state.next_generation().unwrap();
        let terminal_nonce = test_nonzero_nonce(
            &state.selector_digest_key,
            claim.group_fingerprint,
            terminal_generation,
        )
        .unwrap();
        let poison = PoisonRecord {
            lifecycle: NamespaceLifecycle::Bound,
            phase: 0,
            device: claim.device_fingerprint,
            selectors: claim.selector_set_fingerprint,
            desired: claim.desired_fingerprint,
            atoms: atoms.clone(),
            generation,
            operation_nonce: nonce,
            terminal_generation: SelectorAuthorityCoordinate {
                generation: terminal_generation,
                nonce: terminal_nonce,
            },
            previous_terminal: None,
            backend_started: true,
            retired_dataplane_generation: None,
            reason: PoisonReason::EffectReadbackIndeterminate,
            stamp_evidence: PoisonStampEvidence::NotObserved,
        };
        for atom in &atoms {
            state.selectors.insert(
                *atom,
                SelectorState::Poisoned {
                    group: claim.group_fingerprint,
                    generation,
                },
            );
            state.published_atoms.insert(*atom);
        }
        state
            .retain_canonical_desired(claim.group_fingerprint, &desired)
            .unwrap();
        state
            .groups
            .insert(claim.group_fingerprint, GroupState::Poisoned(poison));
        assert!(state.is_complete());
        let encoded = state.encode();
        assert!(NamespaceState::decode(&encoded).is_some());
        let mut aliased_pending_nonce = state.clone();
        let Some(GroupState::Poisoned(poison)) = aliased_pending_nonce
            .groups
            .get_mut(&claim.group_fingerprint)
        else {
            panic!("test constructed poison");
        };
        poison.terminal_generation.nonce = poison.operation_nonce;
        assert!(!aliased_pending_nonce.is_complete());
        assert!(NamespaceState::decode(&aliased_pending_nonce.encode()).is_none());
        let Some(GroupState::Poisoned(poison)) = state.groups.get_mut(&claim.group_fingerprint)
        else {
            panic!("test constructed poison");
        };
        poison.terminal_generation.nonce = [0; 16];
        assert!(NamespaceState::decode(&state.encode()).is_none());
        let Some(GroupState::Poisoned(poison)) = state.groups.get_mut(&claim.group_fingerprint)
        else {
            panic!("test constructed poison");
        };
        poison.terminal_generation.nonce = terminal_nonce;
        poison.backend_started = false;
        assert!(NamespaceState::decode(&state.encode()).is_none());
        let Some(GroupState::Poisoned(poison)) = state.groups.get_mut(&claim.group_fingerprint)
        else {
            panic!("test constructed poison");
        };
        poison.backend_started = true;
        poison.lifecycle = NamespaceLifecycle::Initializing;
        assert!(NamespaceState::decode(&state.encode()).is_none());
        let Some(GroupState::Poisoned(poison)) = state.groups.get_mut(&claim.group_fingerprint)
        else {
            panic!("test constructed poison");
        };
        poison.lifecycle = NamespaceLifecycle::Bound;
        poison.phase = 4;
        assert!(NamespaceState::decode(&state.encode()).is_none());
        let Some(GroupState::Poisoned(poison)) = state.groups.get_mut(&claim.group_fingerprint)
        else {
            panic!("test constructed poison");
        };
        poison.phase = 0;
        poison.retired_dataplane_generation = NonZeroU64::new(1);
        assert!(NamespaceState::decode(&state.encode()).is_none());
        let Some(GroupState::Poisoned(poison)) = state.groups.get_mut(&claim.group_fingerprint)
        else {
            panic!("test constructed poison");
        };
        poison.retired_dataplane_generation = None;
        poison.terminal_generation.generation = GtpuSessionSelectorAuthorityGeneration(
            NonZeroU64::new(terminal_generation.get().checked_add(1).unwrap()).unwrap(),
        );
        assert!(NamespaceState::decode(&state.encode()).is_none());
        let Some(GroupState::Poisoned(poison)) = state.groups.get_mut(&claim.group_fingerprint)
        else {
            panic!("test constructed poison");
        };
        poison.terminal_generation.generation = terminal_generation;
        poison.reason = PoisonReason::RemovalReceiptIndeterminate;
        assert!(NamespaceState::decode(&state.encode()).is_none());
    }

    #[test]
    fn poison_codec_rejects_phase_two_and_three_coordinate_mutations() {
        let mut state = NamespaceState::default();
        state
            .bind_or_validate(
                GtpuSessionDeviceId::new([1; 16]).unwrap(),
                32,
                Some([7; 32]),
            )
            .unwrap();
        let desired = group(1, 1, 0x1000_0001, None);
        let claim = CanonicalClaim::from_group(&desired)
            .with_key(&state.selector_digest_key)
            .unwrap();
        let atoms = claim.selector_atoms(&state.selector_digest_key).unwrap();
        let previous_terminal_generation = state.next_generation().unwrap();
        let previous_terminal_nonce = test_nonzero_nonce(
            &state.selector_digest_key,
            claim.group_fingerprint,
            previous_terminal_generation,
        )
        .unwrap();
        let generation = state.next_generation().unwrap();
        let operation_nonce = test_nonzero_nonce(
            &state.selector_digest_key,
            claim.group_fingerprint,
            generation,
        )
        .unwrap();
        let terminal_generation = state.next_generation().unwrap();
        let terminal_nonce = test_nonzero_nonce(
            &state.selector_digest_key,
            claim.group_fingerprint,
            terminal_generation,
        )
        .unwrap();
        for atom in &atoms {
            state.selectors.insert(
                *atom,
                SelectorState::Poisoned {
                    group: claim.group_fingerprint,
                    generation,
                },
            );
            state.published_atoms.insert(*atom);
        }
        state
            .retain_canonical_desired(claim.group_fingerprint, &desired)
            .unwrap();
        state.groups.insert(
            claim.group_fingerprint,
            GroupState::Poisoned(PoisonRecord {
                lifecycle: NamespaceLifecycle::Bound,
                phase: 2,
                device: claim.device_fingerprint,
                selectors: claim.selector_set_fingerprint,
                desired: claim.desired_fingerprint,
                atoms: atoms.clone(),
                generation,
                operation_nonce,
                terminal_generation: SelectorAuthorityCoordinate {
                    generation: terminal_generation,
                    nonce: terminal_nonce,
                },
                previous_terminal: Some(SelectorAuthorityCoordinate {
                    generation: previous_terminal_generation,
                    nonce: previous_terminal_nonce,
                }),
                backend_started: true,
                retired_dataplane_generation: None,
                reason: PoisonReason::RemovalReadbackIndeterminate,
                stamp_evidence: PoisonStampEvidence::NotObserved,
            }),
        );
        assert!(state.is_complete());
        assert!(NamespaceState::decode(&state.encode()).is_some());
        let binding = state
            .binding_with_scope(test_storage_scope_commitment(&[7; 32]))
            .unwrap();
        let inventory = state.operation_stamp_inventory(binding).unwrap();
        let expectation = inventory
            .expectations()
            .first()
            .expect("one permanent poison stamp key");
        let lifecycle = expectation.lifecycle();
        assert_eq!(
            lifecycle.kind(),
            SelectorOperationStampLifecycleKind::Poisoned
        );
        assert_eq!(lifecycle.poison_phase(), Some(2));
        assert_eq!(
            lifecycle.previous_terminal(),
            Some(SelectorOperationStampCoordinate {
                generation: previous_terminal_generation,
                nonce: previous_terminal_nonce,
            })
        );

        let mut aliased_pending_nonce = state.clone();
        let Some(GroupState::Poisoned(poison)) = aliased_pending_nonce
            .groups
            .get_mut(&claim.group_fingerprint)
        else {
            panic!("test constructed poison");
        };
        poison.terminal_generation.nonce = poison.operation_nonce;
        assert!(!aliased_pending_nonce.is_complete());
        assert!(NamespaceState::decode(&aliased_pending_nonce.encode()).is_none());

        let mut missing_previous_terminal = state.clone();
        let Some(GroupState::Poisoned(poison)) = missing_previous_terminal
            .groups
            .get_mut(&claim.group_fingerprint)
        else {
            panic!("test constructed poison");
        };
        poison.previous_terminal = None;
        assert!(!missing_previous_terminal.is_complete());
        assert!(NamespaceState::decode(&missing_previous_terminal.encode()).is_none());

        let mut non_predecessor_terminal = state.clone();
        let Some(GroupState::Poisoned(poison)) = non_predecessor_terminal
            .groups
            .get_mut(&claim.group_fingerprint)
        else {
            panic!("test constructed poison");
        };
        poison.previous_terminal = Some(SelectorAuthorityCoordinate {
            generation,
            nonce: previous_terminal_nonce,
        });
        assert!(!non_predecessor_terminal.is_complete());
        assert!(NamespaceState::decode(&non_predecessor_terminal.encode()).is_none());

        let mut wrong_phase_two_reason = state.clone();
        let Some(GroupState::Poisoned(poison)) = wrong_phase_two_reason
            .groups
            .get_mut(&claim.group_fingerprint)
        else {
            panic!("test constructed poison");
        };
        poison.reason = PoisonReason::EffectReadbackIndeterminate;
        assert!(NamespaceState::decode(&wrong_phase_two_reason.encode()).is_none());

        let mut retired_phase_two = state.clone();
        let Some(GroupState::Poisoned(poison)) =
            retired_phase_two.groups.get_mut(&claim.group_fingerprint)
        else {
            panic!("test constructed poison");
        };
        poison.retired_dataplane_generation = NonZeroU64::new(7);
        assert!(NamespaceState::decode(&retired_phase_two.encode()).is_none());

        let mut terminal_gap = state.clone();
        let Some(GroupState::Poisoned(poison)) =
            terminal_gap.groups.get_mut(&claim.group_fingerprint)
        else {
            panic!("test constructed poison");
        };
        poison.terminal_generation.generation = GtpuSessionSelectorAuthorityGeneration(
            NonZeroU64::new(terminal_generation.get().checked_add(1).unwrap()).unwrap(),
        );
        terminal_gap.generation = terminal_gap.generation.checked_add(1).unwrap();
        assert!(NamespaceState::decode(&terminal_gap.encode()).is_none());

        let mut phase_three = state;
        let Some(GroupState::Poisoned(poison)) =
            phase_three.groups.get_mut(&claim.group_fingerprint)
        else {
            panic!("test constructed poison");
        };
        poison.phase = 3;
        poison.generation = terminal_generation;
        poison.operation_nonce = terminal_nonce;
        poison.previous_terminal = None;
        poison.retired_dataplane_generation = NonZeroU64::new(7);
        poison.reason = PoisonReason::RecoveryIndeterminate;
        for atom in &atoms {
            phase_three.selectors.insert(
                *atom,
                SelectorState::Poisoned {
                    group: claim.group_fingerprint,
                    generation: terminal_generation,
                },
            );
            phase_three.tombstones.insert(*atom);
        }
        assert!(phase_three.is_complete());
        assert!(NamespaceState::decode(&phase_three.encode()).is_some());

        let mut missing_retired_generation = phase_three.clone();
        let Some(GroupState::Poisoned(poison)) = missing_retired_generation
            .groups
            .get_mut(&claim.group_fingerprint)
        else {
            panic!("test constructed poison");
        };
        poison.retired_dataplane_generation = None;
        assert!(NamespaceState::decode(&missing_retired_generation.encode()).is_none());

        let mut wrong_phase_three_reason = phase_three.clone();
        let Some(GroupState::Poisoned(poison)) = wrong_phase_three_reason
            .groups
            .get_mut(&claim.group_fingerprint)
        else {
            panic!("test constructed poison");
        };
        poison.reason = PoisonReason::RemovalReceiptIndeterminate;
        assert!(NamespaceState::decode(&wrong_phase_three_reason.encode()).is_none());

        let mut mismatched_terminal_nonce = phase_three.clone();
        let Some(GroupState::Poisoned(poison)) = mismatched_terminal_nonce
            .groups
            .get_mut(&claim.group_fingerprint)
        else {
            panic!("test constructed poison");
        };
        poison.operation_nonce = operation_nonce;
        assert!(NamespaceState::decode(&mismatched_terminal_nonce.encode()).is_none());

        let mut mismatched_selector_owner = phase_three.clone();
        let first_atom = *atoms.iter().next().expect("test selector atom");
        mismatched_selector_owner.selectors.insert(
            first_atom,
            SelectorState::Poisoned {
                group: [0x99; 32],
                generation: terminal_generation,
            },
        );
        assert!(NamespaceState::decode(&mismatched_selector_owner.encode()).is_none());

        let mut missing_tombstone = phase_three;
        missing_tombstone.tombstones.remove(&first_atom);
        assert!(NamespaceState::decode(&missing_tombstone.encode()).is_none());
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
                    authority
                        .recover_install(backend.clone(), desired.clone())
                        .await,
                    Err(GtpuSessionSelectorCoordinatorError::Backend),
                ),
                "{case} must not turn Installing(false) into an effect retry"
            );
            assert_eq!(backend.effect_calls(), 0, "{case} must be mutation-free");
            let (_, durable) = authority.read_state().await.unwrap();
            let claim = CanonicalClaim::from_group(&desired)
                .with_key(&durable.selector_digest_key)
                .unwrap();
            assert!(
                matches!(
                    durable.groups.get(&claim.group_fingerprint),
                    Some(GroupState::Installing {
                        backend_started: false,
                        ..
                    })
                ),
                "{case} is a definite pre-effect failure and must not poison"
            );
        }
    }

    #[tokio::test]
    async fn expired_installing_no_effect_request_cannot_handoff_or_effect() {
        let desired = group(1, 1, 0x1000_0001, None);
        let authority = raw_production_authority_with_ttl(
            SessionStore::new(
                SqliteSessionBackend::in_memory().expect("in-memory durable namespace backend"),
            ),
            production_namespace_key(desired.device_id()),
            "selector-expired-installing-negative-proof",
            Duration::from_secs(1),
            32,
        )
        .await;
        let backend = Arc::new(FaultingSelectorBackend::default());
        authority.provision(backend.as_ref()).await.unwrap();
        authority
            .claim_fresh(backend.as_ref(), &desired)
            .await
            .unwrap();
        // The negative request's mutation window is half the worker TTL. The
        // backend checks it while holding its inventory lock, so this delayed
        // structural NoEffect observation cannot settle the request.
        backend.set_no_effect_inspection_delay(Duration::from_millis(750));

        assert!(matches!(
            authority
                .recover_install(backend.clone(), desired.clone())
                .await,
            Err(GtpuSessionSelectorCoordinatorError::Backend)
        ));
        assert_eq!(backend.effect_calls(), 0, "expired proof must not effect");
        let (_, durable) = authority.read_state().await.unwrap();
        let claim = CanonicalClaim::from_group(&desired)
            .with_key(&durable.selector_digest_key)
            .unwrap();
        assert!(matches!(
            durable.groups.get(&claim.group_fingerprint),
            Some(GroupState::Installing {
                backend_started: false,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn expired_retiring_no_effect_request_cannot_handoff_or_remove() {
        let desired = group(1, 1, 0x1000_0001, None);
        let authority = raw_production_authority_with_ttl(
            SessionStore::new(
                SqliteSessionBackend::in_memory().expect("in-memory durable namespace backend"),
            ),
            production_namespace_key(desired.device_id()),
            "selector-expired-retiring-negative-proof",
            Duration::from_secs(1),
            32,
        )
        .await;
        let backend = Arc::new(FaultingSelectorBackend::default());
        authority.provision(backend.as_ref()).await.unwrap();
        let active = authority
            .reconcile_fresh(backend.clone(), desired.clone())
            .await
            .unwrap();
        authority.transition_retiring(&active.0).await.unwrap();
        backend.set_no_effect_inspection_delay(Duration::from_millis(750));

        assert!(matches!(
            authority
                .recover_retiring(backend.clone(), desired.clone())
                .await,
            Err(GtpuSessionSelectorCoordinatorError::Backend)
        ));
        assert_eq!(
            backend.removal_calls(),
            0,
            "expired proof must not remove the exact Active graph"
        );
        let (_, durable) = authority.read_state().await.unwrap();
        let claim = CanonicalClaim::from_group(&desired)
            .with_key(&durable.selector_digest_key)
            .unwrap();
        assert!(matches!(
            durable.groups.get(&claim.group_fingerprint),
            Some(GroupState::Retiring {
                backend_started: false,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn started_install_recovery_poisoned_without_replay_and_recovers_ack_loss() {
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
        assert!(matches!(
            authority
                .recover_install(backend.clone(), desired.clone())
                .await,
            Err(GtpuSessionSelectorCoordinatorError::Backend)
        ));
        assert_eq!(backend.effect_calls(), 0);
        let (_, poisoned) = authority.read_state().await.unwrap();
        let claim = CanonicalClaim::from_group(&desired)
            .with_key(&poisoned.selector_digest_key)
            .unwrap();
        assert!(matches!(
            poisoned.groups.get(&claim.group_fingerprint),
            Some(GroupState::Poisoned(poison))
                if poison.phase == 0
                    && poison.backend_started
                    && poison.reason == PoisonReason::RecoveryIndeterminate
        ));

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
        assert!(matches!(
            ack_loss_authority
                .recover_install(ack_loss_backend.clone(), ack_loss_desired)
                .await,
            Err(GtpuSessionSelectorCoordinatorError::Namespace)
        ));
        assert_eq!(
            ack_loss_backend.effect_calls(),
            1,
            "a poisoned ACK-loss coordinate must never replay its backend effect"
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
        backend.hold_no_effect_inspection();

        let left = authority.recover_install(backend.clone(), desired.clone());
        backend.wait_for_no_effect_inspection_entry().await;
        let right = authority.recover_install(backend.clone(), desired);
        tokio::task::yield_now().await;
        assert_eq!(backend.installing_no_effect_inspection_calls(), 1);
        assert_eq!(backend.effect_calls(), 0);
        backend.release_no_effect_inspection();

        let (left, right) = tokio::join!(left, right);
        assert_eq!(backend.effect_calls(), 1);
        assert_eq!(backend.installing_no_effect_inspection_calls(), 1);
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
        backend.hold_no_effect_inspection();

        let left = authority.recover_retiring(backend.clone(), desired.clone());
        backend.wait_for_no_effect_inspection_entry().await;
        let right = authority.recover_retiring(backend.clone(), desired);
        tokio::task::yield_now().await;
        assert_eq!(backend.retiring_no_effect_inspection_calls(), 1);
        assert_eq!(backend.removal_calls(), 0);
        backend.release_no_effect_inspection();

        let (left, right) = tokio::join!(left, right);
        assert_eq!(backend.removal_calls(), 1);
        assert_eq!(backend.retiring_no_effect_inspection_calls(), 1);
        assert!(left.is_ok() || right.is_ok());
    }

    #[tokio::test]
    async fn expired_started_install_owner_cannot_make_recovery_replay_its_effect() {
        let desired = group(1, 1, 0x1000_0001, None);
        let store = SessionStore::new(
            SqliteSessionBackend::in_memory().expect("in-memory durable namespace backend"),
        );
        let namespace_key = production_namespace_key(desired.device_id());
        let setup = raw_production_authority(
            store.clone(),
            namespace_key.clone(),
            "selector-expired-install-setup",
            32,
        )
        .await;
        let backend = Arc::new(FaultingSelectorBackend::default());
        setup.provision(backend.as_ref()).await.unwrap();
        setup.claim_fresh(backend.as_ref(), &desired).await.unwrap();

        let stale = raw_production_authority_with_ttl(
            store.clone(),
            namespace_key.clone(),
            "selector-expired-install-stale",
            Duration::from_millis(25),
            32,
        )
        .await;
        let recovery = raw_production_authority(
            store,
            namespace_key,
            "selector-expired-install-recovery",
            32,
        )
        .await;
        let mut stale_lease = stale.acquire_worker_lease().await.unwrap();
        let admission = match stale
            .mark_install_backend_started_with_lease(&desired, &mut stale_lease)
            .await
            .unwrap()
        {
            BackendStartHandoff::Transitioned(admission) => admission,
            BackendStartHandoff::AlreadyStarted(_) => panic!("first start owns the handoff"),
        };

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(matches!(
            recovery
                .recover_install(backend.clone(), desired.clone())
                .await,
            Err(GtpuSessionSelectorCoordinatorError::Backend)
        ));
        assert_eq!(
            backend.effect_calls(),
            0,
            "recovery of an expired started coordinate must not replay"
        );
        let (_, poisoned) = recovery.read_state().await.unwrap();
        let claim = CanonicalClaim::from_group(&desired)
            .with_key(&poisoned.selector_digest_key)
            .unwrap();
        assert!(matches!(
            poisoned.groups.get(&claim.group_fingerprint),
            Some(GroupState::Poisoned(poison))
                if poison.phase == 0 && poison.reason == PoisonReason::RecoveryIndeterminate
        ));

        // An affine request holder may resume after its durable lease
        // expires, but its short backend mutation window is already stale.
        // Recovery must therefore poison rather than issue or accept a
        // second effect.
        let request = GtpuSessionGroupReconcileRequest::new(desired.clone(), admission).unwrap();
        let stale_window = SelectorBackendMutationWindow::mint(Duration::from_millis(1)).unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(backend
            .reconcile_pdp_context_group_authorized(GtpuSessionSelectorEffectRequest {
                request,
                window: stale_window,
            })
            .await
            .is_err());
        assert_eq!(backend.effect_calls(), 0);
        let (_, after_stale_effect) = recovery.read_state().await.unwrap();
        assert!(matches!(
            after_stale_effect.groups.get(&claim.group_fingerprint),
            Some(GroupState::Poisoned(poison))
                if poison.phase == 0 && poison.reason == PoisonReason::RecoveryIndeterminate
        ));
        assert!(stale.release_worker_lease(stale_lease).await.is_err());
    }

    #[tokio::test]
    async fn expired_started_retirement_owner_cannot_make_recovery_replay_its_removal() {
        let desired = group(1, 1, 0x1000_0001, None);
        let store = SessionStore::new(
            SqliteSessionBackend::in_memory().expect("in-memory durable namespace backend"),
        );
        let namespace_key = production_namespace_key(desired.device_id());
        let setup = raw_production_authority(
            store.clone(),
            namespace_key.clone(),
            "selector-expired-retirement-setup",
            32,
        )
        .await;
        let backend = Arc::new(FaultingSelectorBackend::default());
        setup.provision(backend.as_ref()).await.unwrap();
        let active = setup
            .reconcile_fresh(backend.clone(), desired.clone())
            .await
            .unwrap();

        let stale = raw_production_authority_with_ttl(
            store.clone(),
            namespace_key.clone(),
            "selector-expired-retirement-stale",
            Duration::from_millis(25),
            32,
        )
        .await;
        let recovery = raw_production_authority(
            store,
            namespace_key,
            "selector-expired-retirement-recovery",
            32,
        )
        .await;
        let mut stale_lease = stale.acquire_worker_lease().await.unwrap();
        stale
            .transition_retiring_with_lease(&active.0, &mut stale_lease)
            .await
            .unwrap();
        let admission = match stale
            .mark_retirement_backend_started_with_lease(&desired, &mut stale_lease)
            .await
            .unwrap()
        {
            BackendStartHandoff::Transitioned(admission) => admission,
            BackendStartHandoff::AlreadyStarted(_) => panic!("first start owns the handoff"),
        };

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(matches!(
            recovery
                .recover_retiring(backend.clone(), desired.clone())
                .await,
            Err(GtpuSessionSelectorCoordinatorError::Backend)
        ));
        assert_eq!(
            backend.removal_calls(),
            0,
            "recovery of an expired started coordinate must not replay"
        );
        let (_, poisoned) = recovery.read_state().await.unwrap();
        let claim = CanonicalClaim::from_group(&desired)
            .with_key(&poisoned.selector_digest_key)
            .unwrap();
        assert!(matches!(
            poisoned.groups.get(&claim.group_fingerprint),
            Some(GroupState::Poisoned(poison))
                if poison.phase == 2 && poison.reason == PoisonReason::RecoveryIndeterminate
        ));

        let stale_window = SelectorBackendMutationWindow::mint(Duration::from_millis(1)).unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(backend
            .remove_pdp_context_group_with_lease(GtpuSessionSelectorRemovalRequest {
                expected: desired,
                admission,
                window: stale_window,
            })
            .await
            .is_err());
        assert_eq!(backend.removal_calls(), 0);
        let (_, after_stale_removal) = recovery.read_state().await.unwrap();
        assert!(matches!(
            after_stale_removal.groups.get(&claim.group_fingerprint),
            Some(GroupState::Poisoned(poison))
                if poison.phase == 2 && poison.reason == PoisonReason::RecoveryIndeterminate
        ));
        assert!(stale.release_worker_lease(stale_lease).await.is_err());
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
        assert!(matches!(
            authority.recover_retiring(backend.clone(), desired).await,
            Err(GtpuSessionSelectorCoordinatorError::Namespace)
        ));
        assert_eq!(
            backend.removal_calls(),
            1,
            "a poisoned ACK-loss coordinate must never replay its backend removal"
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

    #[tokio::test]
    async fn decommission_backend_error_survives_expired_lease_release_failure() {
        let desired = group(1, 1, 0x1000_0001, None);
        let store = SessionStore::new(
            SqliteSessionBackend::in_memory().expect("in-memory durable namespace backend"),
        );
        let namespace_key = production_namespace_key(desired.device_id());
        let setup = raw_production_authority(
            store.clone(),
            namespace_key.clone(),
            "selector-decommission-double-fault-setup",
            32,
        )
        .await;
        let backend = Arc::new(FaultingSelectorBackend::default());
        setup.provision(backend.as_ref()).await.unwrap();
        let short_lease = raw_production_authority_with_ttl(
            store.clone(),
            namespace_key.clone(),
            "selector-decommission-double-fault-worker",
            Duration::from_millis(25),
            32,
        )
        .await;
        backend.set_terminal_inspect_fault_after(Duration::from_millis(100));

        assert!(matches!(
            short_lease.decommission(backend).await,
            Err(GtpuSessionSelectorCoordinatorError::Backend)
        ));

        // The delayed backend fault outlives the first guard. A distinct
        // owner can acquire, proving the original release encountered a stale
        // fence; that secondary failure must not mask the primary backend one.
        let successor = raw_production_authority(
            store,
            namespace_key,
            "selector-decommission-double-fault-successor",
            32,
        )
        .await;
        let lease = successor.acquire_worker_lease().await.unwrap();
        successor.release_worker_lease(lease).await.unwrap();
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
        let mut legacy = empty.as_bytes().to_vec();
        legacy[..7].copy_from_slice(b"OPCSN12");
        assert!(NamespaceState::decode(&legacy).is_none());
        let mut prior_inventory_schema = empty.as_bytes().to_vec();
        prior_inventory_schema[..7].copy_from_slice(b"OPCSN14");
        assert!(NamespaceState::decode(&prior_inventory_schema).is_none());
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
        let desired_group = group(2, 1, 0x1000_0002, None);
        let claim = CanonicalClaim::from_group(&desired_group)
            .with_key(&[9; 32])
            .unwrap();
        let group = claim.group_fingerprint;
        let device = claim.device_fingerprint;
        let atoms = claim.selector_atoms(&[9; 32]).unwrap();
        assert_eq!(atoms.len(), 2);
        let mut atom_iter = atoms.iter().copied();
        let first = atom_iter.next().unwrap();
        let second = atom_iter.next().unwrap();
        let generation = GtpuSessionSelectorAuthorityGeneration(NonZeroU64::new(1).unwrap());
        let mut state = NamespaceState {
            lifecycle: NamespaceLifecycle::Bound,
            stable_device: Some([1; 16]),
            pin_commitment: [7; 32],
            storage_scope_commitment: [6; 32],
            ledger_id: [2; 16],
            backend_epoch: [8; 16],
            selector_digest_key: Zeroizing::new([9; 32]),
            key_commitment: key_commitment(&[9; 32], &[2; 16], &[7; 32], &[1; 16], &[6; 32]),
            capacity: SELECTOR_NAMESPACE_MAX_READBACK_ATOMS as u32,
            generation: 2,
            decommission_fence: None,
            selectors: BTreeMap::new(),
            groups: BTreeMap::new(),
            canonical_desired: BTreeMap::new(),
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
        state
            .retain_canonical_desired(group, &desired_group)
            .unwrap();
        state.groups.insert(
            group,
            GroupState::Installing {
                device,
                selectors: claim.selector_set_fingerprint,
                desired: claim.desired_fingerprint,
                atoms: atoms.clone(),
                generation,
                operation_nonce: [3; 16],
                terminal_generation: GtpuSessionSelectorAuthorityGeneration(
                    NonZeroU64::new(2).unwrap(),
                ),
                terminal_operation_nonce: [4; 16],
                backend_started: false,
                reuse: None,
            },
        );
        assert!(state.is_complete());

        let mut aliased_install = state.clone();
        if let Some(GroupState::Installing {
            operation_nonce,
            terminal_operation_nonce,
            ..
        }) = aliased_install.groups.get_mut(&group)
        {
            *terminal_operation_nonce = *operation_nonce;
        }
        assert!(!aliased_install.is_complete());
        assert!(NamespaceState::decode(&aliased_install.encode()).is_none());

        let retiring_generation =
            GtpuSessionSelectorAuthorityGeneration(NonZeroU64::new(2).unwrap());
        let terminal_retirement_generation =
            GtpuSessionSelectorAuthorityGeneration(NonZeroU64::new(3).unwrap());
        let mut retiring = state.clone();
        retiring.generation = terminal_retirement_generation.get();
        for selector in retiring.selectors.values_mut() {
            *selector = SelectorState::Retiring {
                group,
                generation: retiring_generation,
            };
        }
        retiring.groups.insert(
            group,
            GroupState::Retiring {
                device,
                selectors: claim.selector_set_fingerprint,
                desired: claim.desired_fingerprint,
                atoms: atoms.clone(),
                generation: retiring_generation,
                operation_nonce: [4; 16],
                terminal_generation: terminal_retirement_generation,
                terminal_operation_nonce: [5; 16],
                activation_generation: generation,
                previous_terminal: SelectorAuthorityCoordinate {
                    generation,
                    nonce: [3; 16],
                },
                backend_started: false,
            },
        );
        assert!(retiring.is_complete());
        assert!(NamespaceState::decode(&retiring.encode()).is_some());
        let Some(GroupState::Retiring {
            operation_nonce,
            terminal_operation_nonce,
            ..
        }) = retiring.groups.get_mut(&group)
        else {
            panic!("test constructed retiring record");
        };
        *terminal_operation_nonce = *operation_nonce;
        assert!(!retiring.is_complete());
        assert!(NamespaceState::decode(&retiring.encode()).is_none());

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
        let selectors_offset = 7 + 1 + 1 + 16 + 32 + 32 + 16 + 16 + 32 + 32 + 4 + 8 + 1 + 4;
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
        let predecessor = state.encode();
        let fence = state
            .precommit_decommission(Generation::new(1), &predecessor)
            .unwrap();
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
            .decommissioned
            .nonce[0] ^= 1;
        assert!(NamespaceState::decode(&corrupted.encode()).is_none());
    }

    #[test]
    fn fixed_profile_worst_case_record_stays_within_plaintext_envelope() {
        let mut state = NamespaceState {
            lifecycle: NamespaceLifecycle::Bound,
            stable_device: Some([1; 16]),
            pin_commitment: [7; 32],
            storage_scope_commitment: [6; 32],
            ledger_id: [2; 16],
            backend_epoch: [3; 16],
            selector_digest_key: Zeroizing::new([4; 32]),
            key_commitment: key_commitment(&[4; 32], &[2; 16], &[7; 32], &[1; 16], &[6; 32]),
            capacity: SELECTOR_NAMESPACE_MAX_READBACK_ATOMS as u32,
            generation: (MAX_PERMANENT_GROUPS * 3) as u64,
            decommission_fence: None,
            selectors: BTreeMap::new(),
            groups: BTreeMap::new(),
            canonical_desired: BTreeMap::new(),
            published_atoms: BTreeSet::new(),
            tombstones: BTreeSet::new(),
        };
        let template = group(1, 1, 0x1000_0001, None);
        let mut entries = template.entries().to_vec();
        let mut second_context = template.entries()[0].context().clone();
        second_context.local_teid = Teid::new(0x1000_0002).unwrap();
        second_context.peer_teid = Teid::new(0x1000_0003).unwrap();
        second_context.ms_address = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 2, 0, 0, 0, 1));
        entries.push(
            GtpuSessionEntry::new(second_context, template.entries()[0].local_outer_address())
                .unwrap(),
        );
        let claims: Vec<_> = (0..MAX_PERMANENT_GROUPS)
            .map(|index| {
                let mut id = [0_u8; 16];
                id[12..].copy_from_slice(&((index as u32) + 1).to_be_bytes());
                let desired = GtpuSessionGroup::new(
                    GtpuSessionGroupId::new(id).unwrap(),
                    template.device_id(),
                    entries.clone(),
                )
                .unwrap();
                let claim = CanonicalClaim::from_group(&desired)
                    .with_key(&state.selector_digest_key)
                    .unwrap();
                (desired, claim)
            })
            .collect();
        let atoms = claims[0]
            .1
            .selector_atoms(&state.selector_digest_key)
            .unwrap();
        assert_eq!(atoms.len(), 4);
        for atom in &atoms {
            state.selectors.insert(*atom, SelectorState::Retired);
            state.published_atoms.insert(*atom);
            state.tombstones.insert(*atom);
        }
        for (index, (desired, claim)) in claims.iter().enumerate() {
            let activation_generation = GtpuSessionSelectorAuthorityGeneration(
                NonZeroU64::new((index * 3 + 2) as u64).unwrap(),
            );
            let retirement_generation = GtpuSessionSelectorAuthorityGeneration(
                NonZeroU64::new((index * 3 + 3) as u64).unwrap(),
            );
            state
                .retain_canonical_desired(claim.group_fingerprint, desired)
                .unwrap();
            state.groups.insert(
                claim.group_fingerprint,
                GroupState::Retired {
                    device: claim.device_fingerprint,
                    selectors: claim.selector_set_fingerprint,
                    desired: claim.desired_fingerprint,
                    atoms: atoms.clone(),
                    activation_generation,
                    generation: retirement_generation,
                    operation_nonce: [7; 16],
                    retired_dataplane_generation: NonZeroU64::new(1).unwrap(),
                    successor: None,
                },
            );
        }
        assert_eq!(state.group_atom_references(), MAX_GROUP_ATOM_REFERENCES);
        let encoded = state.encode();
        assert_eq!(MAX_RECORD_BYTES, 512 * 1024);
        assert_eq!(MIN_BACKEND_RECORD_BYTES, 576 * 1024);
        assert!(encoded.len() <= MAX_RECORD_BYTES, "{}", encoded.len());
        assert!(NamespaceState::decode(&encoded).is_some());

        // RFC 016's aggregate reference profile is exact: an already
        // published/tombstoned atom still cannot become a 4,097th durable
        // group reference through a malformed reissue lineage.
        let excess_atom = [0xfe; 32];
        let first_group = state
            .groups
            .values_mut()
            .next()
            .expect("fixed profile contains a group");
        let GroupState::Retired {
            atoms: first_group_atoms,
            ..
        } = first_group
        else {
            panic!("fixed profile contains only retired groups");
        };
        assert!(first_group_atoms.insert(excess_atom));
        assert_eq!(state.group_atom_references(), MAX_GROUP_ATOM_REFERENCES + 1);
        assert!(!state.is_complete());
        assert!(NamespaceState::decode(&state.encode()).is_none());
    }
}
