//! Backend-neutral, fail-closed GTP-U production traffic-proof boundary.
//!
//! [`opc_dataplane_observation`] evaluates bounded structural continuity only;
//! it is explicitly non-authoritative. This module does not promote that
//! assessment by itself. A backend can issue [`GtpuTrafficProof`] only by
//! overriding the backend trait after it independently proves trusted source,
//! exact current dataplane generation, and current revocation authority.

use std::fmt;
use std::num::{NonZeroU128, NonZeroU64};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::sync::{OwnedRwLockReadGuard, RwLock};

use opc_dataplane_observation::{
    BackendIncarnation, CallerOwnershipFence, ClockOriginIdentity, DataplaneSessionGeneration,
    DeviceAttachmentIdentity, ProductOwnerGeneration, ReconcileRevision, SessionGroupIdentity,
    SourceEpoch, TrafficBinding, TrafficContinuityAssessment, TrafficContinuityAssessmentSummary,
    TrafficContinuityPolicy,
};
use opc_gtpu_ebpf_common::trusted_traffic_observation_abi::GtpuTrafficObservationRegistration;
use opc_gtpu_ebpf_common::GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_CHALLENGE_PAYLOAD_LEN;

use crate::GtpuSessionGroup;

/// Why construction of traffic-proof authority was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum GtpuTrafficProofAuthorityError {
    /// The supplied group could not be represented as an exact observation binding.
    InvalidSessionBinding,
    /// The product-owner generation was zero.
    ZeroProductOwnerGeneration,
    /// The reconciliation fence was all zeroes.
    ZeroReconcileFence,
    /// The reconciliation revision was zero.
    ZeroReconcileRevision,
}

impl fmt::Display for GtpuTrafficProofAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSessionBinding => "invalid_session_binding",
            Self::ZeroProductOwnerGeneration => "zero_product_owner_generation",
            Self::ZeroReconcileFence => "zero_reconcile_fence",
            Self::ZeroReconcileRevision => "zero_reconcile_revision",
        })
    }
}

impl std::error::Error for GtpuTrafficProofAuthorityError {}

/// The product's exact, current session-scoped authority for a traffic proof.
///
/// This opaque snapshot retains the exact desired group, immutable continuity
/// policy, nonzero product-owner generation, caller reconcile fence, and
/// reconcile revision. The dataplane generation is deliberately absent: only
/// a trusted adapter obtains and binds that readback value.
///
/// The product must durably prevent ABA reuse: owner generations and reconcile
/// revisions advance, and the reconcile fence rotates, across restore and
/// restart. Register the authority through
/// [`crate::GtpuDataplaneBackend::register_gtpu_traffic_proof_authority`]; only
/// the backend-returned [`GtpuTrafficProofAuthorityStore`] can issue usable
/// leases, and retaining an older authority clone grants no validation power.
/// Each proof begin or retry receives a fresh trusted adapter source epoch, so
/// this product authority is not a per-attempt anti-replay token and may
/// remain unchanged across a retry.
#[derive(Clone)]
pub struct GtpuTrafficProofAuthority {
    binding: GtpuTrafficProofBinding,
    policy: TrafficContinuityPolicy,
}

impl GtpuTrafficProofAuthority {
    /// Construct one exact current product authority snapshot.
    pub fn new(
        desired: GtpuSessionGroup,
        product_owner_generation: u64,
        reconcile_fence: u128,
        reconcile_revision: u64,
        policy: TrafficContinuityPolicy,
    ) -> Result<Self, GtpuTrafficProofAuthorityError> {
        let product_owner_generation_value = NonZeroU64::new(product_owner_generation)
            .ok_or(GtpuTrafficProofAuthorityError::ZeroProductOwnerGeneration)?;
        let reconcile_fence_value = NonZeroU128::new(reconcile_fence)
            .ok_or(GtpuTrafficProofAuthorityError::ZeroReconcileFence)?;
        let reconcile_revision_value = NonZeroU64::new(reconcile_revision)
            .ok_or(GtpuTrafficProofAuthorityError::ZeroReconcileRevision)?;
        let session_group_identity =
            SessionGroupIdentity::new(u128::from_be_bytes(desired.id().to_bytes()))
                .map_err(|_| GtpuTrafficProofAuthorityError::InvalidSessionBinding)?;
        let device_attachment_identity =
            DeviceAttachmentIdentity::new(u128::from_be_bytes(desired.device_id().to_bytes()))
                .map_err(|_| GtpuTrafficProofAuthorityError::InvalidSessionBinding)?;
        let product_owner_generation =
            ProductOwnerGeneration::new(product_owner_generation_value.get())
                .map_err(|_| GtpuTrafficProofAuthorityError::ZeroProductOwnerGeneration)?;
        let reconcile_fence = CallerOwnershipFence::new(reconcile_fence_value.get())
            .map_err(|_| GtpuTrafficProofAuthorityError::ZeroReconcileFence)?;
        let reconcile_revision = ReconcileRevision::new(reconcile_revision_value.get())
            .map_err(|_| GtpuTrafficProofAuthorityError::ZeroReconcileRevision)?;
        Ok(Self {
            binding: GtpuTrafficProofBinding {
                desired,
                session_group_identity,
                device_attachment_identity,
                product_owner_generation_value,
                reconcile_fence_value,
                reconcile_revision_value,
                product_owner_generation,
                reconcile_fence,
                reconcile_revision,
            },
            policy,
        })
    }

    fn exactly_matches(&self, other: &Self) -> bool {
        self.binding.desired == other.binding.desired
            && self.binding.product_owner_generation_value
                == other.binding.product_owner_generation_value
            && self.binding.reconcile_fence_value == other.binding.reconcile_fence_value
            && self.binding.reconcile_revision_value == other.binding.reconcile_revision_value
            && self.policy == other.policy
    }

    /// Return the immutable structural continuity policy for this authority.
    #[must_use]
    pub const fn policy(&self) -> TrafficContinuityPolicy {
        self.policy
    }

    /// Exact desired group, available only to trusted in-crate adapters.
    pub(crate) fn desired(&self) -> &GtpuSessionGroup {
        &self.binding.desired
    }

    /// Product owner generation, available only to trusted in-crate adapters.
    pub(crate) const fn product_owner_generation(&self) -> u64 {
        self.binding.product_owner_generation_value.get()
    }

    /// Reconcile fence, available only to trusted in-crate adapters.
    pub(crate) const fn reconcile_fence(&self) -> u128 {
        self.binding.reconcile_fence_value.get()
    }

    /// Reconcile revision, available only to trusted in-crate adapters.
    pub(crate) const fn reconcile_revision(&self) -> u64 {
        self.binding.reconcile_revision_value.get()
    }

    #[cfg(test)]
    pub(crate) fn invalidation_for_proof(
        &self,
        proof: &GtpuTrafficProof,
    ) -> Option<GtpuTrafficProofInvalidation> {
        self.invalidation_for(&proof.binding, proof.policy)
    }

    pub(crate) fn invalidation_for_snapshot(
        &self,
        proof: &GtpuTrafficProofValidationSnapshot,
    ) -> Option<GtpuTrafficProofInvalidation> {
        self.invalidation_for(&proof.binding, proof.policy)
    }

    pub(crate) fn invalidation_for_session(
        &self,
        session: &GtpuTrafficProofSession,
    ) -> Option<GtpuTrafficProofInvalidation> {
        self.invalidation_for(&session.binding, session.policy)
    }

    fn invalidation_for(
        &self,
        binding: &GtpuTrafficProofBinding,
        policy: TrafficContinuityPolicy,
    ) -> Option<GtpuTrafficProofInvalidation> {
        if self.binding.desired != binding.desired {
            Some(GtpuTrafficProofInvalidation::SessionBindingChanged)
        } else if self.binding.product_owner_generation_value
            != binding.product_owner_generation_value
        {
            Some(GtpuTrafficProofInvalidation::ProductOwnerGenerationChanged)
        } else if self.binding.reconcile_fence_value != binding.reconcile_fence_value {
            Some(GtpuTrafficProofInvalidation::ReconcileFenceChanged)
        } else if self.binding.reconcile_revision_value != binding.reconcile_revision_value {
            Some(GtpuTrafficProofInvalidation::ReconcileRevisionChanged)
        } else if self.policy != policy {
            Some(GtpuTrafficProofInvalidation::PolicyChanged)
        } else {
            None
        }
    }
}

impl fmt::Debug for GtpuTrafficProofAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GtpuTrafficProofAuthority(<redacted>)")
    }
}

/// A redaction-safe reason an authority-store replacement was refused.
///
/// The variants deliberately expose no authority values or session identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum GtpuTrafficProofAuthorityStoreUpdateError {
    /// The candidate names a different session group or device attachment.
    SessionBindingChanged,
    /// The candidate did not advance the reconciliation revision.
    ReconcileRevisionNotIncreasing,
    /// The candidate reused the current reconciliation fence.
    ReconcileFenceUnchanged,
    /// The candidate moved the product-owner generation backwards.
    ProductOwnerGenerationRegressed,
    /// The candidate was exactly the currently stored authority.
    AuthorityUnchanged,
    /// Another authority replacement is queued or in progress.
    ReplacementInProgress,
}

impl fmt::Display for GtpuTrafficProofAuthorityStoreUpdateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SessionBindingChanged => "session_binding_changed",
            Self::ReconcileRevisionNotIncreasing => "reconcile_revision_not_increasing",
            Self::ReconcileFenceUnchanged => "reconcile_fence_unchanged",
            Self::ProductOwnerGenerationRegressed => "product_owner_generation_regressed",
            Self::AuthorityUnchanged => "authority_unchanged",
            Self::ReplacementInProgress => "replacement_in_progress",
        })
    }
}

impl std::error::Error for GtpuTrafficProofAuthorityStoreUpdateError {}

/// Opaque identity minted by one trusted backend for its canonical authority store.
///
/// The value is never exposed through public diagnostics. Binding it in every
/// lease prevents a separately recreated store holding a stale authority
/// snapshot from racing or replacing the product's registered store.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct GtpuTrafficProofAuthorityStoreIdentity {
    backend_incarnation: u64,
    registration: u128,
}

impl GtpuTrafficProofAuthorityStoreIdentity {
    pub(crate) const fn new(backend_incarnation: u64, registration: u128) -> Option<Self> {
        if backend_incarnation == 0 || registration == 0 {
            return None;
        }
        Some(Self {
            backend_incarnation,
            registration,
        })
    }
}

/// Product-owned, generation-fenced storage for the current traffic authority.
///
/// Call [`Self::lease`] before beginning a proof and retain the returned lease
/// through backend validation and the protected use. While that lease exists,
/// [`Self::replace`] waits; this prevents a retained authority clone from being
/// presented as current after reconciliation changes product authority.
#[derive(Clone)]
pub struct GtpuTrafficProofAuthorityStore {
    current: Arc<RwLock<GtpuTrafficProofAuthority>>,
    replacement_active: Arc<AtomicBool>,
    identity: GtpuTrafficProofAuthorityStoreIdentity,
}

impl GtpuTrafficProofAuthorityStore {
    /// Create a store after a trusted backend atomically registered its identity.
    pub(crate) fn registered(
        authority: GtpuTrafficProofAuthority,
        identity: GtpuTrafficProofAuthorityStoreIdentity,
    ) -> Self {
        Self {
            current: Arc::new(RwLock::new(authority)),
            replacement_active: Arc::new(AtomicBool::new(false)),
            identity,
        }
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(authority: GtpuTrafficProofAuthority) -> Self {
        Self::registered(
            authority,
            GtpuTrafficProofAuthorityStoreIdentity::new(1, 1).expect("nonzero test store identity"),
        )
    }

    pub(crate) const fn identity(&self) -> GtpuTrafficProofAuthorityStoreIdentity {
        self.identity
    }

    /// Compare without waiting while a backend-wide operation lock is held.
    ///
    /// `None` means a replacement was queued or active. Tokio's `try_read`
    /// alone can bypass a queued writer, so the replacement marker is checked
    /// both before and after the read guard is acquired. A writer beginning
    /// after the second check waits for the retained read guard, making this
    /// comparison linearize before that replacement.
    pub(crate) fn try_exactly_matches(
        &self,
        authority: &GtpuTrafficProofAuthority,
    ) -> Option<bool> {
        if self.replacement_active.load(Ordering::Acquire) {
            return None;
        }
        let current = self.current.try_read().ok()?;
        if self.replacement_active.load(Ordering::Acquire) {
            return None;
        }
        Some(current.exactly_matches(authority))
    }

    /// Acquire the current authority's non-cloneable validation lease.
    ///
    /// Retain this lease through the async backend validation and every use
    /// protected by that validation. A replacement cannot complete until all
    /// outstanding leases are dropped.
    pub async fn lease(&self) -> GtpuTrafficProofAuthorityLease {
        GtpuTrafficProofAuthorityLease {
            guard: self.current.clone().read_owned().await,
            identity: self.identity,
        }
    }

    /// Replace the exact current authority after anti-ABA validation.
    ///
    /// The candidate must advance the reconciliation revision, rotate its
    /// nonzero fence, retain or advance owner generation, and differ exactly
    /// from the current authority. This waits for existing validation leases,
    /// so reconciliation cannot race a validate-and-use critical section.
    pub async fn replace(
        &self,
        replacement: GtpuTrafficProofAuthority,
    ) -> Result<(), GtpuTrafficProofAuthorityStoreUpdateError> {
        let _replacement =
            GtpuTrafficProofAuthorityStoreReplacement::begin(self.replacement_active.as_ref())
                .ok_or(GtpuTrafficProofAuthorityStoreUpdateError::ReplacementInProgress)?;
        let mut current = self.current.write().await;
        if replacement.binding.desired != current.binding.desired {
            return Err(GtpuTrafficProofAuthorityStoreUpdateError::SessionBindingChanged);
        }
        if replacement.exactly_matches(&current) {
            return Err(GtpuTrafficProofAuthorityStoreUpdateError::AuthorityUnchanged);
        }
        if replacement.reconcile_revision() <= current.reconcile_revision() {
            return Err(GtpuTrafficProofAuthorityStoreUpdateError::ReconcileRevisionNotIncreasing);
        }
        if replacement.reconcile_fence() == current.reconcile_fence() {
            return Err(GtpuTrafficProofAuthorityStoreUpdateError::ReconcileFenceUnchanged);
        }
        if replacement.product_owner_generation() < current.product_owner_generation() {
            return Err(GtpuTrafficProofAuthorityStoreUpdateError::ProductOwnerGenerationRegressed);
        }
        *current = replacement;
        Ok(())
    }
}

/// Cancellation-safe marker covering a queued or active authority writer.
///
/// Only one replacement may wait at a time. Refusing overlapping writers is
/// fail-closed and prevents a backend operation that already owns its global
/// mutation lock from waiting behind a lease retained by another operation.
struct GtpuTrafficProofAuthorityStoreReplacement<'a> {
    active: &'a AtomicBool,
}

impl<'a> GtpuTrafficProofAuthorityStoreReplacement<'a> {
    fn begin(active: &'a AtomicBool) -> Option<Self> {
        active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Self { active })
    }
}

impl Drop for GtpuTrafficProofAuthorityStoreReplacement<'_> {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
    }
}

impl fmt::Debug for GtpuTrafficProofAuthorityStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GtpuTrafficProofAuthorityStore(<redacted>)")
    }
}

/// An opaque, non-cloneable lease over the store's exact current authority.
///
/// The lease holds a synchronization guard until it is dropped. Consume this
/// lease with [`crate::GtpuDataplaneBackend::begin_gtpu_traffic_proof`], or
/// borrow it for [`crate::GtpuDataplaneBackend::validate_gtpu_traffic_proof`]
/// and retain it through the protected use. A standalone authority snapshot,
/// including a stale clone, can do neither.
///
/// ```compile_fail
/// use opc_gtpu_dataplane::{GtpuTrafficProofAuthority, GtpuTrafficProofAuthorityLease};
///
/// fn requires_validation_lease(_: &GtpuTrafficProofAuthorityLease) {}
/// fn stale_snapshot_is_not_a_validation_lease(authority: GtpuTrafficProofAuthority) {
///     requires_validation_lease(&authority);
/// }
/// ```
///
/// ```compile_fail
/// use opc_gtpu_dataplane::{GtpuDataplaneBackend, GtpuTrafficProofAuthority};
///
/// async fn stale_snapshot_cannot_begin(
///     backend: impl GtpuDataplaneBackend,
///     authority: GtpuTrafficProofAuthority,
/// ) {
///     let _ = backend.begin_gtpu_traffic_proof(authority).await;
/// }
/// ```
pub struct GtpuTrafficProofAuthorityLease {
    guard: OwnedRwLockReadGuard<GtpuTrafficProofAuthority>,
    identity: GtpuTrafficProofAuthorityStoreIdentity,
}

impl GtpuTrafficProofAuthorityLease {
    /// Return the immutable structural continuity policy of the leased authority.
    #[must_use]
    pub fn policy(&self) -> TrafficContinuityPolicy {
        self.guard.policy()
    }

    pub(crate) fn authority(&self) -> &GtpuTrafficProofAuthority {
        &self.guard
    }

    pub(crate) const fn store_identity(&self) -> GtpuTrafficProofAuthorityStoreIdentity {
        self.identity
    }
}

impl fmt::Debug for GtpuTrafficProofAuthorityLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GtpuTrafficProofAuthorityLease(<redacted>)")
    }
}

impl GtpuTrafficProofAuthority {
    pub(crate) fn bind_readback(
        &self,
        dataplane_generation: DataplaneSessionGeneration,
        backend_incarnation: BackendIncarnation,
        source_epoch: SourceEpoch,
        clock_origin: ClockOriginIdentity,
        authority: GtpuTrafficProofAuthorityToken,
        registration: GtpuTrafficObservationRegistration,
    ) -> GtpuTrafficProofSession {
        let traffic_binding = self.binding.traffic_binding(
            dataplane_generation,
            backend_incarnation,
            source_epoch,
            clock_origin,
        );
        GtpuTrafficProofSession {
            binding: self.binding.clone(),
            policy: self.policy,
            traffic_binding,
            authority,
            registration,
            proof_issued: false,
            revoker: None,
        }
    }
}

#[derive(Clone)]
struct GtpuTrafficProofBinding {
    desired: GtpuSessionGroup,
    session_group_identity: SessionGroupIdentity,
    device_attachment_identity: DeviceAttachmentIdentity,
    product_owner_generation_value: NonZeroU64,
    reconcile_fence_value: NonZeroU128,
    reconcile_revision_value: NonZeroU64,
    product_owner_generation: ProductOwnerGeneration,
    reconcile_fence: CallerOwnershipFence,
    reconcile_revision: ReconcileRevision,
}

impl GtpuTrafficProofBinding {
    fn traffic_binding(
        &self,
        dataplane_generation: DataplaneSessionGeneration,
        backend_incarnation: BackendIncarnation,
        source_epoch: SourceEpoch,
        clock_origin: ClockOriginIdentity,
    ) -> TrafficBinding {
        TrafficBinding::new(
            self.session_group_identity,
            self.device_attachment_identity,
            dataplane_generation,
            self.product_owner_generation,
            self.reconcile_fence,
            self.reconcile_revision,
            backend_incarnation,
            source_epoch,
            clock_origin,
        )
    }
}

impl fmt::Debug for GtpuTrafficProofBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GtpuTrafficProofBinding(<redacted>)")
    }
}

/// Opaque adapter-owned authority retained for a proof attempt.
///
/// This is crate-visible so a future trusted adapter can bind its own live
/// authority, but public callers cannot mint or inspect it.
#[derive(Clone, Copy)]
pub(crate) struct GtpuTrafficProofAuthorityToken {
    backend_incarnation: u64,
    source_epoch: u64,
    attempt: u64,
}

pub(crate) trait GtpuTrafficProofRevoker: Send + Sync {
    fn revoke(&self, authority: GtpuTrafficProofAuthorityToken);
}

impl GtpuTrafficProofAuthorityToken {
    pub(crate) const fn new(backend_incarnation: u64, source_epoch: u64, attempt: u64) -> Self {
        Self {
            backend_incarnation,
            source_epoch,
            attempt,
        }
    }

    pub(crate) const fn matches(&self, backend_incarnation: u64, source_epoch: u64) -> bool {
        self.backend_incarnation == backend_incarnation && self.source_epoch == source_epoch
    }

    pub(crate) const fn attempt(&self) -> u64 {
        self.attempt
    }
}

/// Opaque, non-cloneable in-progress traffic-proof attempt.
///
/// Only a trusted in-crate backend adapter can construct or inspect its state.
pub struct GtpuTrafficProofSession {
    binding: GtpuTrafficProofBinding,
    policy: TrafficContinuityPolicy,
    traffic_binding: TrafficBinding,
    authority: GtpuTrafficProofAuthorityToken,
    registration: GtpuTrafficObservationRegistration,
    proof_issued: bool,
    revoker: Option<Arc<dyn GtpuTrafficProofRevoker>>,
}

impl GtpuTrafficProofSession {
    /// Build the fixed, authenticated payload for one nonzero challenge sample.
    ///
    /// The returned value contains no subscriber identity or secret. A product
    /// sends it in an ICMP Echo Request from core to access using the returned
    /// exact identifier and sequence. The trusted downlink adapter replaces
    /// the public request authenticator with a private return authenticator
    /// before the packet reaches the access side. Only the corresponding
    /// access-to-core Echo Reply can complete this sample.
    #[must_use]
    pub fn challenge(&self, sample_id: u32) -> Option<GtpuTrafficProofChallenge> {
        self.registration
            .icmp_echo_challenge_payload(sample_id)
            .map(|payload| GtpuTrafficProofChallenge { sample_id, payload })
    }

    pub(crate) fn desired(&self) -> &GtpuSessionGroup {
        &self.binding.desired
    }

    pub(crate) const fn product_owner_generation(&self) -> u64 {
        self.binding.product_owner_generation_value.get()
    }

    pub(crate) const fn reconcile_fence(&self) -> u128 {
        self.binding.reconcile_fence_value.get()
    }

    pub(crate) const fn reconcile_revision(&self) -> u64 {
        self.binding.reconcile_revision_value.get()
    }

    pub(crate) const fn traffic_binding(&self) -> TrafficBinding {
        self.traffic_binding
    }

    pub(crate) const fn policy(&self) -> TrafficContinuityPolicy {
        self.policy
    }

    pub(crate) fn authority(&self) -> &GtpuTrafficProofAuthorityToken {
        &self.authority
    }

    pub(crate) const fn proof_issued(&self) -> bool {
        self.proof_issued
    }

    pub(crate) fn install_revoker(&mut self, revoker: Arc<dyn GtpuTrafficProofRevoker>) {
        self.revoker = Some(revoker);
    }

    pub(crate) fn clone_for_adapter(&self) -> Self {
        Self {
            binding: self.binding.clone(),
            policy: self.policy,
            traffic_binding: self.traffic_binding,
            authority: self.authority,
            registration: self.registration,
            proof_issued: self.proof_issued,
            revoker: None,
        }
    }

    pub(crate) fn mark_proof_issued(&mut self) {
        self.proof_issued = true;
    }

    pub(crate) fn disarm_revoker(&mut self) {
        self.revoker = None;
    }

    pub(crate) fn issue_proof(
        &mut self,
        assessment: TrafficContinuityAssessment,
    ) -> Result<GtpuTrafficProof, GtpuTrafficProofInvalidation> {
        if self.proof_issued {
            return Err(GtpuTrafficProofInvalidation::AuthorityRevoked);
        }
        if !assessment.matches_binding(self.traffic_binding) {
            return Err(GtpuTrafficProofInvalidation::ObservationBindingChanged);
        }
        if !assessment.matches_policy(self.policy) {
            return Err(GtpuTrafficProofInvalidation::PolicyChanged);
        }
        self.proof_issued = true;
        Ok(GtpuTrafficProof {
            binding: self.binding.clone(),
            policy: self.policy,
            authority: self.authority,
            assessment,
        })
    }
}

/// A bounded, non-identifying authenticated traffic-proof challenge.
pub struct GtpuTrafficProofChallenge {
    sample_id: u32,
    payload: [u8; GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_CHALLENGE_PAYLOAD_LEN],
}

impl GtpuTrafficProofChallenge {
    /// Return the caller-selected nonzero sample identifier.
    #[must_use]
    pub const fn sample_id(&self) -> u32 {
        self.sample_id
    }

    /// Return the exact ICMP Echo identifier bound into this challenge.
    ///
    /// This request must travel from core to access. A different identifier
    /// cannot contribute production evidence.
    #[must_use]
    pub const fn identifier(&self) -> u16 {
        (self.sample_id >> 16) as u16
    }

    /// Return the exact ICMP Echo sequence bound into this challenge.
    ///
    /// This request must travel from core to access. A different sequence
    /// cannot contribute production evidence.
    #[must_use]
    pub const fn sequence(&self) -> u16 {
        self.sample_id as u16
    }

    /// Return the exact fixed-size ICMP Echo payload to transmit.
    #[must_use]
    pub const fn payload(&self) -> &[u8; GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_CHALLENGE_PAYLOAD_LEN] {
        &self.payload
    }
}

impl fmt::Debug for GtpuTrafficProofChallenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GtpuTrafficProofChallenge(<redacted>)")
    }
}

impl fmt::Debug for GtpuTrafficProofSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GtpuTrafficProofSession(<redacted>)")
    }
}

impl Drop for GtpuTrafficProofSession {
    fn drop(&mut self) {
        if let Some(revoker) = self.revoker.take() {
            revoker.revoke(self.authority);
        }
    }
}

/// Stable reason a traffic proof is no longer valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum GtpuTrafficProofInvalidation {
    /// The exact desired group or its device attachment changed.
    SessionBindingChanged,
    /// The backend's readback dataplane generation changed.
    DataplaneGenerationChanged,
    /// The product owner's generation changed.
    ProductOwnerGenerationChanged,
    /// The caller's reconcile fence changed.
    ReconcileFenceChanged,
    /// The caller's reconcile revision changed.
    ReconcileRevisionChanged,
    /// The adapter's backend incarnation, source epoch, or clock origin changed.
    ObservationBindingChanged,
    /// The immutable continuity policy no longer exactly matches.
    PolicyChanged,
    /// Observation continuity was lost or could not be established.
    ContinuityLost,
    /// The proof expired according to its bound monotonic clock.
    Expired,
    /// The trusted adapter lost or revoked its issuing authority.
    AuthorityRevoked,
}

impl GtpuTrafficProofInvalidation {
    /// Return a stable, value-free invalidation code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SessionBindingChanged => "session_binding_changed",
            Self::DataplaneGenerationChanged => "dataplane_generation_changed",
            Self::ProductOwnerGenerationChanged => "product_owner_generation_changed",
            Self::ReconcileFenceChanged => "reconcile_fence_changed",
            Self::ReconcileRevisionChanged => "reconcile_revision_changed",
            Self::ObservationBindingChanged => "observation_binding_changed",
            Self::PolicyChanged => "policy_changed",
            Self::ContinuityLost => "continuity_lost",
            Self::Expired => "expired",
            Self::AuthorityRevoked => "authority_revoked",
        }
    }
}

/// Result of polling one traffic-proof attempt.
#[derive(Debug)]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)] // Preserve the established proof-by-value public result API.
pub enum GtpuTrafficProofPoll {
    /// The trusted adapter has not yet completed its bounded assessment.
    Pending,
    /// A final proof was issued under current trusted adapter authority.
    Proven(GtpuTrafficProof),
    /// This affine attempt already issued its one final proof.
    Completed,
    /// The attempt was invalidated and cannot become proven.
    Invalidated(GtpuTrafficProofInvalidation),
}

/// Result of revalidating one final traffic proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum GtpuTrafficProofValidation {
    /// The proof remains current under the adapter's exact live authority.
    Current,
    /// The proof is no longer current.
    Invalidated(GtpuTrafficProofInvalidation),
}

/// Redaction-safe counts and monotonic timing for a final proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GtpuTrafficProofSummary {
    assessment: TrafficContinuityAssessmentSummary,
}

impl GtpuTrafficProofSummary {
    /// Number of retained access-to-core continuity samples.
    #[must_use]
    pub const fn access_to_core_samples(self) -> usize {
        self.assessment.access_to_core_samples()
    }

    /// Number of retained core-to-access continuity samples.
    #[must_use]
    pub const fn core_to_access_samples(self) -> usize {
        self.assessment.core_to_access_samples()
    }

    /// Monotonic time at which the trusted adapter completed its assessment.
    #[must_use]
    pub const fn issued_at(self) -> opc_dataplane_observation::MonotonicTime {
        self.assessment.issued_at()
    }

    /// Exclusive monotonic expiry time for the proof assessment.
    #[must_use]
    pub const fn expires_at(self) -> opc_dataplane_observation::MonotonicTime {
        self.assessment.expires_at()
    }
}

/// Opaque, non-cloneable final traffic proof.
///
/// The proof owns its exact private session binding, immutable policy,
/// adapter authority token, and non-authoritative continuity assessment. Its
/// only public data is the redaction-safe [`GtpuTrafficProofSummary`].
pub struct GtpuTrafficProof {
    binding: GtpuTrafficProofBinding,
    policy: TrafficContinuityPolicy,
    authority: GtpuTrafficProofAuthorityToken,
    assessment: TrafficContinuityAssessment,
}

#[derive(Clone)]
pub(crate) struct GtpuTrafficProofValidationSnapshot {
    binding: GtpuTrafficProofBinding,
    policy: TrafficContinuityPolicy,
    authority: GtpuTrafficProofAuthorityToken,
    summary: GtpuTrafficProofSummary,
}

impl GtpuTrafficProofValidationSnapshot {
    pub(crate) fn from_proof(proof: &GtpuTrafficProof) -> Self {
        Self {
            binding: proof.binding.clone(),
            policy: proof.policy,
            authority: proof.authority,
            summary: proof.summary(),
        }
    }

    pub(crate) const fn policy(&self) -> TrafficContinuityPolicy {
        self.policy
    }

    pub(crate) fn desired(&self) -> &GtpuSessionGroup {
        &self.binding.desired
    }

    pub(crate) const fn product_owner_generation(&self) -> u64 {
        self.binding.product_owner_generation_value.get()
    }

    pub(crate) const fn reconcile_fence(&self) -> u128 {
        self.binding.reconcile_fence_value.get()
    }

    pub(crate) const fn reconcile_revision(&self) -> u64 {
        self.binding.reconcile_revision_value.get()
    }

    pub(crate) const fn authority(&self) -> GtpuTrafficProofAuthorityToken {
        self.authority
    }

    pub(crate) const fn summary(&self) -> GtpuTrafficProofSummary {
        self.summary
    }
}

impl GtpuTrafficProof {
    /// Return counts and monotonic timing only.
    #[must_use]
    pub const fn summary(&self) -> GtpuTrafficProofSummary {
        GtpuTrafficProofSummary {
            assessment: self.assessment.summary(),
        }
    }
}

impl fmt::Debug for GtpuTrafficProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GtpuTrafficProof")
            .field("summary", &self.summary())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::net::{IpAddr, Ipv4Addr};
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;

    use async_trait::async_trait;
    use opc_dataplane_observation::{
        FlowCorrelation, MonotonicTime, SourceOutcome, TrafficContinuityEvaluator,
        TrafficContinuityEvent, TrafficContinuityRecord, TrafficContinuitySource, TrafficDirection,
    };
    use opc_gtpu_ebpf_common::{GtpuSessionGeneration, GtpuTrafficObservationBinding};

    use super::*;
    use crate::{
        GtpDevice, GtpPdpContext, GtpVersion, GtpuCapability, GtpuDataplaneBackend, GtpuError,
        GtpuSessionDeviceId, GtpuSessionEntry, GtpuSessionGroupId, GtpuSourcePortPolicy,
        GtpuUplinkSourcePortPolicy, MockGtpuDataplaneBackend, RemovePdpContextRequest, Teid,
        UnsupportedGtpuDataplaneBackend,
    };

    fn group() -> GtpuSessionGroup {
        let group_id = GtpuSessionGroupId::new([1; 16]).unwrap();
        let device_id = GtpuSessionDeviceId::new([2; 16]).unwrap();
        let context = GtpPdpContext {
            local_teid: Teid::new(1).unwrap(),
            peer_teid: Teid::new(2).unwrap(),
            ms_address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            peer_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            link_ifindex: 7,
            downlink_source_port_policy: GtpuSourcePortPolicy::Any,
            gtp_version: GtpVersion::V1,
            bearer_mark: None,
            egress_dscp: None,
            uplink_source_port_policy: GtpuUplinkSourcePortPolicy::LegacyServicePort,
        };
        let entry =
            GtpuSessionEntry::new(context, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))).unwrap();
        GtpuSessionGroup::new(group_id, device_id, vec![entry]).unwrap()
    }

    fn policy() -> TrafficContinuityPolicy {
        TrafficContinuityPolicy::new(
            2,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(1),
            4,
        )
        .unwrap()
    }

    fn authority() -> GtpuTrafficProofAuthority {
        GtpuTrafficProofAuthority::new(group(), 1, 1, 1, policy()).unwrap()
    }

    fn session(authority: &GtpuTrafficProofAuthority) -> GtpuTrafficProofSession {
        let registration = GtpuTrafficObservationRegistration::new(
            GtpuTrafficObservationBinding::new(
                authority.desired().id(),
                authority.desired().device_id(),
                GtpuSessionGeneration::new(1).unwrap(),
            ),
            1,
            1,
            [1; 16],
            1,
            [2; 16],
        )
        .unwrap();
        authority.bind_readback(
            DataplaneSessionGeneration::new(1).unwrap(),
            BackendIncarnation::new(1).unwrap(),
            SourceEpoch::new(1).unwrap(),
            ClockOriginIdentity::new(1).unwrap(),
            GtpuTrafficProofAuthorityToken::new(1, 1, 1),
            registration,
        )
    }

    #[test]
    fn authority_rejects_every_zero_dimension() {
        assert_eq!(
            GtpuTrafficProofAuthority::new(group(), 0, 1, 1, policy()).unwrap_err(),
            GtpuTrafficProofAuthorityError::ZeroProductOwnerGeneration
        );
        assert_eq!(
            GtpuTrafficProofAuthority::new(group(), 1, 0, 1, policy()).unwrap_err(),
            GtpuTrafficProofAuthorityError::ZeroReconcileFence
        );
        assert_eq!(
            GtpuTrafficProofAuthority::new(group(), 1, 1, 0, policy()).unwrap_err(),
            GtpuTrafficProofAuthorityError::ZeroReconcileRevision
        );
    }

    #[test]
    fn debug_redacts_session_and_owner_authority() {
        let debug = format!("{authority:?}", authority = authority());
        assert_eq!(debug, "GtpuTrafficProofAuthority(<redacted>)");
    }

    #[test]
    fn challenge_binds_exact_identifier_sequence_and_redacts_payload() {
        let session = session(&authority());
        assert!(session.challenge(0).is_none());
        let challenge = session
            .challenge(0x1234_5678)
            .expect("nonzero challenge sample");
        assert_eq!(challenge.sample_id(), 0x1234_5678);
        assert_eq!(challenge.identifier(), 0x1234);
        assert_eq!(challenge.sequence(), 0x5678);
        assert_eq!(challenge.payload().len(), 32);
        assert_eq!(
            format!("{challenge:?}"),
            "GtpuTrafficProofChallenge(<redacted>)"
        );
    }

    #[test]
    fn authority_comparisons_report_the_exact_changed_dimension() {
        let original = authority();
        let session = session(&original);
        let changed_group = GtpuSessionGroup::new(
            GtpuSessionGroupId::new([3; 16]).unwrap(),
            GtpuSessionDeviceId::new([2; 16]).unwrap(),
            vec![GtpuSessionEntry::new(
                GtpPdpContext {
                    local_teid: Teid::new(1).unwrap(),
                    peer_teid: Teid::new(2).unwrap(),
                    ms_address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    peer_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                    link_ifindex: 7,
                    downlink_source_port_policy: GtpuSourcePortPolicy::Any,
                    gtp_version: GtpVersion::V1,
                    bearer_mark: None,
                    egress_dscp: None,
                    uplink_source_port_policy: GtpuUplinkSourcePortPolicy::LegacyServicePort,
                },
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            )
            .unwrap()],
        )
        .unwrap();
        assert_eq!(
            GtpuTrafficProofAuthority::new(changed_group, 1, 1, 1, policy())
                .unwrap()
                .invalidation_for_session(&session),
            Some(GtpuTrafficProofInvalidation::SessionBindingChanged)
        );
        assert_eq!(
            GtpuTrafficProofAuthority::new(group(), 2, 1, 1, policy())
                .unwrap()
                .invalidation_for_session(&session),
            Some(GtpuTrafficProofInvalidation::ProductOwnerGenerationChanged)
        );
        assert_eq!(
            GtpuTrafficProofAuthority::new(group(), 1, 2, 1, policy())
                .unwrap()
                .invalidation_for_session(&session),
            Some(GtpuTrafficProofInvalidation::ReconcileFenceChanged)
        );
        assert_eq!(
            GtpuTrafficProofAuthority::new(group(), 1, 1, 2, policy())
                .unwrap()
                .invalidation_for_session(&session),
            Some(GtpuTrafficProofInvalidation::ReconcileRevisionChanged)
        );
        let changed_policy = TrafficContinuityPolicy::new(
            3,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(1),
            6,
        )
        .unwrap();
        assert_eq!(
            GtpuTrafficProofAuthority::new(group(), 1, 1, 1, changed_policy)
                .unwrap()
                .invalidation_for_session(&session),
            Some(GtpuTrafficProofInvalidation::PolicyChanged)
        );
        assert_eq!(original.invalidation_for_session(&session), None);
    }

    struct Records(Vec<TrafficContinuityRecord>);

    impl TrafficContinuitySource for Records {
        fn next_record(&mut self) -> TrafficContinuityRecord {
            self.0.remove(0)
        }
    }

    fn proven_proof(authority: &GtpuTrafficProofAuthority) -> GtpuTrafficProof {
        let mut session = session(authority);
        let binding = session.traffic_binding();
        let correlation = FlowCorrelation::new(1).unwrap();
        let at = |seconds| MonotonicTime::from_duration_since_origin(Duration::from_secs(seconds));
        let mut source = Records(vec![
            TrafficContinuityRecord::Event(
                TrafficContinuityEvent::new(
                    binding,
                    TrafficDirection::AccessToCore,
                    correlation,
                    1,
                    at(0),
                )
                .unwrap(),
            ),
            TrafficContinuityRecord::Event(
                TrafficContinuityEvent::new(
                    binding,
                    TrafficDirection::CoreToAccess,
                    correlation,
                    2,
                    at(0),
                )
                .unwrap(),
            ),
            TrafficContinuityRecord::Event(
                TrafficContinuityEvent::new(
                    binding,
                    TrafficDirection::AccessToCore,
                    correlation,
                    3,
                    at(1),
                )
                .unwrap(),
            ),
            TrafficContinuityRecord::Event(
                TrafficContinuityEvent::new(
                    binding,
                    TrafficDirection::CoreToAccess,
                    correlation,
                    4,
                    at(1),
                )
                .unwrap(),
            ),
            TrafficContinuityRecord::Outcome(SourceOutcome::Idle),
        ]);
        let mut evaluator = TrafficContinuityEvaluator::new(binding, session.policy());
        let proof = session
            .issue_proof(evaluator.evaluate(&mut source, at(1)).unwrap())
            .unwrap();
        assert!(session.proof_issued());
        assert_eq!(authority.invalidation_for_proof(&proof), None);
        proof
    }

    #[test]
    fn proof_summary_is_bounded_and_redaction_safe() {
        let proof = proven_proof(&authority());
        let summary = proof.summary();
        assert_eq!(summary.access_to_core_samples(), 2);
        assert_eq!(summary.core_to_access_samples(), 2);
        assert!(summary.access_to_core_samples() <= policy().maximum_retained_events());
        assert!(summary.core_to_access_samples() <= policy().maximum_retained_events());
        let debug = format!("{summary:?}");
        assert!(!debug.contains("192.0.2"));
    }

    #[derive(Debug)]
    struct DefaultBackend;

    #[async_trait]
    impl GtpuDataplaneBackend for DefaultBackend {
        async fn create_device(
            &self,
            _request: crate::CreateGtpDeviceRequest,
        ) -> Result<GtpDevice, GtpuError> {
            Err(GtpuError::UnsupportedPlatform)
        }

        async fn resolve_device(&self, _name: &str) -> Result<GtpDevice, GtpuError> {
            Err(GtpuError::UnsupportedPlatform)
        }

        async fn remove_device(&self, _device: &GtpDevice) -> Result<(), GtpuError> {
            Err(GtpuError::UnsupportedPlatform)
        }

        async fn install_pdp_context(&self, _request: GtpPdpContext) -> Result<(), GtpuError> {
            Err(GtpuError::UnsupportedPlatform)
        }

        async fn remove_pdp_context(
            &self,
            _request: RemovePdpContextRequest,
        ) -> Result<(), GtpuError> {
            Err(GtpuError::UnsupportedPlatform)
        }

        async fn probe(&self) -> Result<crate::GtpuProbe, GtpuError> {
            Ok(crate::GtpuProbe::unsupported())
        }
    }

    #[tokio::test]
    async fn default_backend_traffic_proof_operations_fail_closed() {
        let backend = DefaultBackend;
        let authority = authority();
        let proof = proven_proof(&authority);
        let store = GtpuTrafficProofAuthorityStore::new_for_test(authority);
        assert_eq!(
            backend.gtpu_traffic_proof_capability(),
            GtpuCapability::Missing
        );
        assert!(matches!(
            backend.begin_gtpu_traffic_proof(store.lease().await).await,
            Err(GtpuError::UnsupportedFeature {
                feature: "gtpu_traffic_proof"
            })
        ));
        let lease = store.lease().await;
        assert!(matches!(
            backend.validate_gtpu_traffic_proof(&proof, &lease).await,
            Err(GtpuError::UnsupportedFeature {
                feature: "gtpu_traffic_proof"
            })
        ));
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<GtpuTrafficProofSession>();
        assert_send_sync::<GtpuTrafficProof>();
        assert_send_sync::<GtpuTrafficProofAuthority>();
        assert_send_sync::<GtpuTrafficProofAuthorityStore>();
        assert_send_sync::<GtpuTrafficProofAuthorityLease>();
    }

    #[tokio::test]
    async fn mock_and_unsupported_backends_cannot_validate_a_proof() {
        let authority = authority();
        let proof = proven_proof(&authority);
        let store = GtpuTrafficProofAuthorityStore::new_for_test(authority);
        let lease = store.lease().await;
        let mock = MockGtpuDataplaneBackend::new();
        let unsupported = UnsupportedGtpuDataplaneBackend::new();

        assert!(mock
            .validate_gtpu_traffic_proof(&proof, &lease)
            .await
            .is_err());
        assert!(unsupported
            .validate_gtpu_traffic_proof(&proof, &lease)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn authority_store_lease_blocks_replacement_until_dropped() {
        let store = GtpuTrafficProofAuthorityStore::new_for_test(authority());
        let lease = store.lease().await;
        assert_eq!(lease.policy(), authority().policy());
        let replacement = GtpuTrafficProofAuthority::new(group(), 1, 2, 2, policy()).unwrap();
        let replacement_store = store.clone();
        let (started_sender, started_receiver) = tokio::sync::oneshot::channel();
        let (completed_sender, mut completed_receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let _ = started_sender.send(());
            let result = replacement_store.replace(replacement).await;
            let _ = completed_sender.send(result);
        });
        started_receiver.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut completed_receiver)
                .await
                .is_err()
        );
        drop(lease);
        assert_eq!(completed_receiver.await.unwrap(), Ok(()));
    }

    #[tokio::test]
    async fn queued_authority_replacement_is_nonblocking_and_fail_closed() {
        let original = authority();
        let store = GtpuTrafficProofAuthorityStore::new_for_test(original.clone());
        let lease = store.lease().await;
        let replacement = GtpuTrafficProofAuthority::new(group(), 2, 2, 2, policy()).unwrap();
        let mut replacement = Box::pin(store.replace(replacement));
        let mut context = Context::from_waker(Waker::noop());

        // Polling through the write-lock await to Pending deterministically
        // enqueues the writer behind `lease`; no scheduler timing is involved.
        assert!(matches!(
            Future::poll(replacement.as_mut(), &mut context),
            Poll::Pending
        ));
        assert_eq!(store.try_exactly_matches(&original), None);
        assert_eq!(
            store.replace(original.clone()).await,
            Err(GtpuTrafficProofAuthorityStoreUpdateError::ReplacementInProgress)
        );

        drop(lease);
        assert_eq!(replacement.await, Ok(()));
        assert_eq!(store.try_exactly_matches(&original), Some(false));
    }

    #[tokio::test]
    async fn canceled_queued_authority_replacement_releases_contention_marker() {
        let original = authority();
        let store = GtpuTrafficProofAuthorityStore::new_for_test(original.clone());
        let lease = store.lease().await;
        let replacement = GtpuTrafficProofAuthority::new(group(), 2, 2, 2, policy()).unwrap();
        let mut replacement = Box::pin(store.replace(replacement));
        let mut context = Context::from_waker(Waker::noop());

        assert!(matches!(
            Future::poll(replacement.as_mut(), &mut context),
            Poll::Pending
        ));
        assert_eq!(store.try_exactly_matches(&original), None);

        drop(replacement);
        assert_eq!(store.try_exactly_matches(&original), Some(true));
        drop(lease);

        assert_eq!(
            store.replace(original).await,
            Err(GtpuTrafficProofAuthorityStoreUpdateError::AuthorityUnchanged)
        );
    }

    #[tokio::test]
    async fn fresh_lease_observes_exact_authority_invalidation_after_replacement() {
        let original = authority();
        let proof = proven_proof(&original);
        let store = GtpuTrafficProofAuthorityStore::new_for_test(original.clone());
        let stale_clone = original;
        store
            .replace(GtpuTrafficProofAuthority::new(group(), 2, 2, 2, policy()).unwrap())
            .await
            .unwrap();
        let fresh_lease = store.lease().await;

        assert_eq!(
            fresh_lease.authority().invalidation_for_proof(&proof),
            Some(GtpuTrafficProofInvalidation::ProductOwnerGenerationChanged)
        );
        assert_eq!(stale_clone.invalidation_for_proof(&proof), None);
    }

    #[tokio::test]
    async fn authority_store_rejects_rollback_and_aba_replacements() {
        let store = GtpuTrafficProofAuthorityStore::new_for_test(
            GtpuTrafficProofAuthority::new(group(), 2, 2, 2, policy()).unwrap(),
        );
        assert_eq!(
            store
                .replace(GtpuTrafficProofAuthority::new(group(), 2, 2, 2, policy()).unwrap())
                .await,
            Err(GtpuTrafficProofAuthorityStoreUpdateError::AuthorityUnchanged)
        );
        assert_eq!(
            store
                .replace(GtpuTrafficProofAuthority::new(group(), 2, 3, 1, policy()).unwrap())
                .await,
            Err(GtpuTrafficProofAuthorityStoreUpdateError::ReconcileRevisionNotIncreasing)
        );
        assert_eq!(
            store
                .replace(GtpuTrafficProofAuthority::new(group(), 2, 3, 2, policy()).unwrap())
                .await,
            Err(GtpuTrafficProofAuthorityStoreUpdateError::ReconcileRevisionNotIncreasing)
        );
        assert_eq!(
            store
                .replace(GtpuTrafficProofAuthority::new(group(), 2, 2, 3, policy()).unwrap())
                .await,
            Err(GtpuTrafficProofAuthorityStoreUpdateError::ReconcileFenceUnchanged)
        );
        assert_eq!(
            store
                .replace(GtpuTrafficProofAuthority::new(group(), 1, 3, 3, policy()).unwrap())
                .await,
            Err(GtpuTrafficProofAuthorityStoreUpdateError::ProductOwnerGenerationRegressed)
        );
    }

    #[tokio::test]
    async fn authority_store_and_lease_are_redacted_and_send_sync() {
        let store = GtpuTrafficProofAuthorityStore::new_for_test(authority());
        let lease = store.lease().await;
        assert_eq!(
            format!("{store:?}"),
            "GtpuTrafficProofAuthorityStore(<redacted>)"
        );
        assert_eq!(
            format!("{lease:?}"),
            "GtpuTrafficProofAuthorityLease(<redacted>)"
        );
        assert_eq!(
            format!(
                "{:?}",
                GtpuTrafficProofAuthorityStoreUpdateError::ReconcileFenceUnchanged
            ),
            "ReconcileFenceUnchanged"
        );
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<GtpuTrafficProofAuthorityStore>();
        assert_send_sync::<GtpuTrafficProofAuthorityLease>();
    }
}
