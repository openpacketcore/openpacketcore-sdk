//! Backend-neutral, fail-closed GTP-U production traffic-proof boundary.
//!
//! [`opc_dataplane_observation`] evaluates bounded structural continuity only;
//! it is explicitly non-authoritative. This module does not promote that
//! assessment by itself. A backend can issue [`GtpuTrafficProof`] only by
//! overriding the backend trait after it independently proves trusted source,
//! exact current dataplane generation, and current revocation authority.

use std::collections::BTreeSet;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::num::{NonZeroU128, NonZeroU64};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use bytes::BytesMut;
use tokio::sync::{watch, OwnedRwLockReadGuard, RwLock};

use opc_dataplane_observation::{
    BackendIncarnation, CallerOwnershipFence, ClockOriginIdentity, DataplaneSessionGeneration,
    DeviceAttachmentIdentity, ProductOwnerGeneration, ReconcileRevision, SessionGroupIdentity,
    SourceEpoch, TrafficBinding, TrafficContinuityAssessment, TrafficContinuityAssessmentSummary,
    TrafficContinuityPolicy,
};
use opc_gtpu_ebpf_common::trusted_traffic_observation_abi::GtpuTrafficObservationRegistration;
use opc_gtpu_ebpf_common::{
    GtpuEndpointAddress, GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_CHALLENGE_PAYLOAD_LEN,
};
use opc_proto_gtpu::{GtpuHeader, GtpuMessage};
use opc_protocol::{Encode, EncodeContext};

use crate::icmp::build_traffic_proof_icmp_echo_request;
use crate::{GtpAddressFamily, GtpuSessionGroup, GTPU_PORT};

/// A redaction-safe result reported by an independent delivery port.
///
/// A receipt only means that the port accepted responsibility for its local
/// handoff. It never means that a peer received a packet, that a packet
/// traversed GTP-U, or that a traffic proof is valid.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GtpuTrafficProofDispatchReceipt(());

impl GtpuTrafficProofDispatchReceipt {
    /// Construct the sole non-authoritative accepted-handoff receipt.
    #[must_use]
    pub const fn accepted() -> Self {
        Self(())
    }
}

impl fmt::Debug for GtpuTrafficProofDispatchReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GtpuTrafficProofDispatchReceipt(<non_authoritative>)")
    }
}

/// Redaction-safe reason a traffic-proof challenge was not dispatched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum GtpuTrafficProofDispatchError {
    /// The exact backend attempt was closed, replaced, restarted, or invalidated.
    AuthorityRevoked,
    /// The selected inner family is not an entry in the exact live group.
    AddressFamilyUnavailable,
    /// The configured core origin and selected inner family differ.
    CoreOriginFamilyMismatch,
    /// The core origin is not usable unicast or is inside the selected access PAA.
    CoreOriginRejected,
    /// The transport's access destination is unspecified, wrong-family, or outside the exact PAA.
    AccessDestinationRejected,
    /// The transport's source port is zero or not authorized by the exact entry.
    OuterSourcePortRejected,
    /// The live group's outer endpoint pair is not usable unicast transport.
    OuterEndpointRejected,
    /// Sample zero is reserved and cannot be dispatched.
    ZeroSample,
    /// The sample has already been handed to a port and cannot be reused.
    SampleAlreadyHandedOff,
    /// The bounded per-session handoff ledger is full.
    SampleCapacityExhausted,
    /// The SDK could not construct its bounded request.
    RequestConstructionFailed,
    /// No independently configured core-side transport exists.
    TransportUnavailable,
    /// The independently configured transport rejected the bounded request.
    TransportRejected,
    /// The transport failed before it accepted local handoff.
    TransportFailure,
}

impl fmt::Display for GtpuTrafficProofDispatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AuthorityRevoked => "traffic_proof_dispatch_authority_revoked",
            Self::AddressFamilyUnavailable => "traffic_proof_address_family_unavailable",
            Self::CoreOriginFamilyMismatch => "traffic_proof_core_origin_family_mismatch",
            Self::CoreOriginRejected => "traffic_proof_core_origin_rejected",
            Self::AccessDestinationRejected => "traffic_proof_access_destination_rejected",
            Self::OuterSourcePortRejected => "traffic_proof_outer_source_port_rejected",
            Self::OuterEndpointRejected => "traffic_proof_outer_endpoint_rejected",
            Self::ZeroSample => "traffic_proof_zero_sample",
            Self::SampleAlreadyHandedOff => "traffic_proof_sample_already_handed_off",
            Self::SampleCapacityExhausted => "traffic_proof_sample_capacity_exhausted",
            Self::RequestConstructionFailed => "traffic_proof_request_construction_failed",
            Self::TransportUnavailable => "traffic_proof_transport_unavailable",
            Self::TransportRejected => "traffic_proof_transport_rejected",
            Self::TransportFailure => "traffic_proof_transport_failure",
        })
    }
}

impl std::error::Error for GtpuTrafficProofDispatchError {}

/// One atomic transport-policy snapshot used for a core-side challenge handoff.
///
/// The transport owns these deployment values and resolves them together so
/// packet construction cannot combine fields from different configuration
/// revisions. Session callers cannot supply this type to dispatch.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GtpuTrafficProofDispatchRoute {
    core_origin: IpAddr,
    outer_source_port: u16,
    access_destination: IpAddr,
}

impl GtpuTrafficProofDispatchRoute {
    /// Construct one atomic transport route snapshot.
    ///
    /// The SDK validates its addresses and port against the selected live entry
    /// immediately before packet construction; this constructor deliberately
    /// does not turn transport configuration mistakes into an unchecked route.
    #[must_use]
    pub const fn new(
        core_origin: IpAddr,
        outer_source_port: u16,
        access_destination: IpAddr,
    ) -> Self {
        Self {
            core_origin,
            outer_source_port,
            access_destination,
        }
    }

    const fn core_origin(self) -> IpAddr {
        self.core_origin
    }

    const fn outer_source_port(self) -> u16 {
        self.outer_source_port
    }

    const fn access_destination(self) -> IpAddr {
        self.access_destination
    }
}

impl fmt::Debug for GtpuTrafficProofDispatchRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GtpuTrafficProofDispatchRoute(<redacted>)")
    }
}

/// Opaque exact G-PDU prepared for one independent core-side handoff.
///
/// Only [`crate::GtpuDataplaneBackend::dispatch_gtpu_traffic_proof_challenge`]
/// constructs this type.
/// The packet is exposed solely to the delivery port that must send it; no
/// selector, authentication material, or packet-construction API is public.
///
/// ```compile_fail
/// use std::net::SocketAddr;
/// use opc_gtpu_dataplane::GtpuTrafficProofDispatchRequest;
///
/// let request = GtpuTrafficProofDispatchRequest {
///     packet: vec![0x30, 0xff],
///     outer_destination: SocketAddr::from(([192, 0, 2, 2], 2_152)),
///     outer_source: SocketAddr::from(([192, 0, 2, 1], 2_152)),
/// };
/// ```
pub struct GtpuTrafficProofDispatchRequest {
    packet: Vec<u8>,
    outer_destination: SocketAddr,
    outer_source: SocketAddr,
}

impl GtpuTrafficProofDispatchRequest {
    /// Borrow the exact plain G-PDU bytes solely for transmission by this port.
    ///
    /// Implementations must not log, meter, retain, or re-purpose these bytes.
    /// The transport must use the paired outer source and destination fields
    /// below; it must not replace them with caller-derived routing identity.
    #[must_use]
    pub fn packet(&self) -> &[u8] {
        &self.packet
    }

    /// Return the exact outer destination derived from the live session entry.
    ///
    /// This is available only because a core-side transport needs it for its
    /// send operation. Implementations must not log or retain it.
    #[must_use]
    pub const fn outer_destination(&self) -> SocketAddr {
        self.outer_destination
    }

    /// Return the exact allowed outer source derived from the live session entry.
    ///
    /// This is available only because a core-side transport may need to bind
    /// its send socket. Implementations must not log or retain it.
    #[must_use]
    pub const fn outer_source(&self) -> SocketAddr {
        self.outer_source
    }
}

impl fmt::Debug for GtpuTrafficProofDispatchRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GtpuTrafficProofDispatchRequest(<redacted>)")
    }
}

/// Core-side port for independently delivering one bounded traffic challenge.
///
/// This port is deliberately independent of local ingress, AF_PACKET, and tc
/// injection. Its deployment placement, remote endpoint admission, retry, and
/// authentication are consumer policy. Once this method starts, cancellation
/// cannot claim to retract a packet that the transport may already have handed
/// off; callers use a fresh sample for every retry. A successful receipt is
/// explicitly non-authoritative and cannot mint or advance a proof.
#[async_trait::async_trait]
pub trait GtpuTrafficProofDispatchPort: Send + Sync {
    /// Resolve one coherent, deployment-configured transport route for a family.
    ///
    /// Session callers cannot select this value. The SDK checks that it is a
    /// specified address in the exact live entry's PAA; in particular, this
    /// preserves a deployment-resolved IPv6 interface identifier rather than
    /// using the entry's canonical `/64` routing prefix as a host address.
    fn resolve_route(
        &self,
        family: GtpAddressFamily,
    ) -> Result<GtpuTrafficProofDispatchRoute, GtpuTrafficProofDispatchError>;

    /// Hand off one SDK-constructed plain G-PDU to an independent transport.
    async fn dispatch(
        &self,
        request: GtpuTrafficProofDispatchRequest,
    ) -> Result<GtpuTrafficProofDispatchReceipt, GtpuTrafficProofDispatchError>;
}

/// Default fail-closed port for deployments without an independent transport.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnsupportedGtpuTrafficProofDispatchPort;

#[async_trait::async_trait]
impl GtpuTrafficProofDispatchPort for UnsupportedGtpuTrafficProofDispatchPort {
    fn resolve_route(
        &self,
        _family: GtpAddressFamily,
    ) -> Result<GtpuTrafficProofDispatchRoute, GtpuTrafficProofDispatchError> {
        Err(GtpuTrafficProofDispatchError::TransportUnavailable)
    }

    async fn dispatch(
        &self,
        _request: GtpuTrafficProofDispatchRequest,
    ) -> Result<GtpuTrafficProofDispatchReceipt, GtpuTrafficProofDispatchError> {
        Err(GtpuTrafficProofDispatchError::TransportUnavailable)
    }
}

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

    pub(crate) fn invalidation_for_session_snapshot(
        &self,
        session: &GtpuTrafficProofSessionSnapshot,
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

/// Backend-owned monotonic cancellation gate for one dispatch authority.
///
/// A watch channel closes the async race between the last liveness check and
/// a pending transport future. Revocation is monotonic and nonblocking: it
/// cancels cooperative pending dispatch immediately, while a transport that
/// already performed an irreversible handoff remains non-authoritative and
/// cannot contribute to the revoked attempt.
pub(crate) struct GtpuTrafficProofDispatchAuthority {
    live: AtomicBool,
    signal: watch::Sender<bool>,
}

impl GtpuTrafficProofDispatchAuthority {
    pub(crate) fn new() -> Arc<Self> {
        let (signal, _) = watch::channel(true);
        Arc::new(Self {
            live: AtomicBool::new(true),
            signal,
        })
    }

    pub(crate) fn revoke(&self) {
        if self.live.swap(false, Ordering::AcqRel) {
            self.signal.send_replace(false);
        }
    }

    fn subscribe(&self) -> watch::Receiver<bool> {
        self.signal.subscribe()
    }

    fn is_live(&self) -> bool {
        self.live.load(Ordering::Acquire)
    }
}

struct GtpuTrafficProofAuthorityStoreCurrent {
    authority: GtpuTrafficProofAuthority,
    dispatch_authority: Arc<GtpuTrafficProofDispatchAuthority>,
}

impl GtpuTrafficProofAuthorityStoreCurrent {
    fn new(authority: GtpuTrafficProofAuthority) -> Self {
        Self {
            authority,
            dispatch_authority: GtpuTrafficProofDispatchAuthority::new(),
        }
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
    current: Arc<RwLock<GtpuTrafficProofAuthorityStoreCurrent>>,
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
            current: Arc::new(RwLock::new(GtpuTrafficProofAuthorityStoreCurrent::new(
                authority,
            ))),
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
        Some(current.authority.exactly_matches(authority))
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
        if replacement.binding.desired != current.authority.binding.desired {
            return Err(GtpuTrafficProofAuthorityStoreUpdateError::SessionBindingChanged);
        }
        if replacement.exactly_matches(&current.authority) {
            return Err(GtpuTrafficProofAuthorityStoreUpdateError::AuthorityUnchanged);
        }
        if replacement.reconcile_revision() <= current.authority.reconcile_revision() {
            return Err(GtpuTrafficProofAuthorityStoreUpdateError::ReconcileRevisionNotIncreasing);
        }
        if replacement.reconcile_fence() == current.authority.reconcile_fence() {
            return Err(GtpuTrafficProofAuthorityStoreUpdateError::ReconcileFenceUnchanged);
        }
        if replacement.product_owner_generation() < current.authority.product_owner_generation() {
            return Err(GtpuTrafficProofAuthorityStoreUpdateError::ProductOwnerGenerationRegressed);
        }
        current.dispatch_authority.revoke();
        *current = GtpuTrafficProofAuthorityStoreCurrent::new(replacement);
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
    guard: OwnedRwLockReadGuard<GtpuTrafficProofAuthorityStoreCurrent>,
    identity: GtpuTrafficProofAuthorityStoreIdentity,
}

impl GtpuTrafficProofAuthorityLease {
    /// Return the immutable structural continuity policy of the leased authority.
    #[must_use]
    pub fn policy(&self) -> TrafficContinuityPolicy {
        self.guard.authority.policy()
    }

    pub(crate) fn authority(&self) -> &GtpuTrafficProofAuthority {
        &self.guard.authority
    }

    pub(crate) fn dispatch_authority(&self) -> Arc<GtpuTrafficProofDispatchAuthority> {
        Arc::clone(&self.guard.dispatch_authority)
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
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn bind_readback(
        &self,
        dataplane_generation: DataplaneSessionGeneration,
        backend_incarnation: BackendIncarnation,
        source_epoch: SourceEpoch,
        clock_origin: ClockOriginIdentity,
        authority: GtpuTrafficProofAuthorityToken,
        registration: GtpuTrafficObservationRegistration,
        authority_dispatch_gate: Arc<GtpuTrafficProofDispatchAuthority>,
        attempt_dispatch_gate: Arc<GtpuTrafficProofDispatchAuthority>,
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
            authority_dispatch_gate,
            attempt_dispatch_gate,
            proof_issued: false,
            handed_off_samples: BTreeSet::new(),
            owns_attempt_lifecycle: true,
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

    pub(crate) const fn belongs_to_backend(&self, backend_incarnation: u64) -> bool {
        self.backend_incarnation == backend_incarnation
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
    authority_dispatch_gate: Arc<GtpuTrafficProofDispatchAuthority>,
    attempt_dispatch_gate: Arc<GtpuTrafficProofDispatchAuthority>,
    proof_issued: bool,
    handed_off_samples: BTreeSet<u32>,
    owns_attempt_lifecycle: bool,
    revoker: Option<Arc<dyn GtpuTrafficProofRevoker>>,
}

/// Opaque packet preparation retained only across the backend's final live
/// readback. Keeping the request private prevents a caller from bypassing the
/// affine session or changing any session selector before transport handoff.
pub(crate) struct GtpuTrafficProofPreparedDispatch {
    sample_id: u32,
    request: GtpuTrafficProofDispatchRequest,
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

    /// Construct one exact CoreToAccess challenge before final backend readback.
    ///
    /// The caller supplies only the desired inner address family and nonzero
    /// sample. The SDK selects the exact family entry from this live affine
    /// session, obtains the core origin from the transport's deployment policy,
    /// and constructs an optionless/unfragmented IPv4 or base IPv6 ICMP Echo
    /// Request inside a plain G-PDU. It never accepts PAA, TEID, group,
    /// generation, authentication tag, or raw packet bytes from the caller.
    ///
    /// Preparation has no external effect and does not retire the sample. The
    /// owning backend performs its final source/generation/readback preflight
    /// after route resolution and packet construction, then passes the opaque
    /// value to [`Self::dispatch_prepared_challenge`].
    pub(crate) fn prepare_challenge<P>(
        &self,
        port: &P,
        family: GtpAddressFamily,
        sample_id: u32,
    ) -> Result<GtpuTrafficProofPreparedDispatch, GtpuTrafficProofDispatchError>
    where
        P: GtpuTrafficProofDispatchPort + ?Sized,
    {
        if !self.authority_dispatch_gate.is_live() || !self.attempt_dispatch_gate.is_live() {
            return Err(GtpuTrafficProofDispatchError::AuthorityRevoked);
        }
        if sample_id == 0 {
            return Err(GtpuTrafficProofDispatchError::ZeroSample);
        }
        if self.handed_off_samples.contains(&sample_id) {
            return Err(GtpuTrafficProofDispatchError::SampleAlreadyHandedOff);
        }
        if self.handed_off_samples.len() >= self.policy.maximum_retained_events() {
            return Err(GtpuTrafficProofDispatchError::SampleCapacityExhausted);
        }
        let entry = self
            .binding
            .desired
            .entries()
            .iter()
            .find(|entry| entry.inner_family() == family)
            .ok_or(GtpuTrafficProofDispatchError::AddressFamilyUnavailable)?;
        if !is_usable_unicast(entry.context().peer_address)
            || !is_usable_unicast(entry.local_outer_address())
        {
            return Err(GtpuTrafficProofDispatchError::OuterEndpointRejected);
        }
        let route = port.resolve_route(family)?;
        let origin = route.core_origin();
        if GtpAddressFamily::from_ip(origin) != family || entry.inner_family() != family {
            return Err(GtpuTrafficProofDispatchError::CoreOriginFamilyMismatch);
        }
        if !is_usable_unicast(origin)
            || entry.inner_paa().contains(match origin {
                IpAddr::V4(address) => GtpuEndpointAddress::Ipv4(address.octets()),
                IpAddr::V6(address) => GtpuEndpointAddress::Ipv6(address.octets()),
            })
        {
            return Err(GtpuTrafficProofDispatchError::CoreOriginRejected);
        }
        let outer_source_port = route.outer_source_port();
        if outer_source_port == 0
            || !entry
                .context()
                .downlink_source_port_policy
                .permits(outer_source_port)
        {
            return Err(GtpuTrafficProofDispatchError::OuterSourcePortRejected);
        }
        let destination = route.access_destination();
        if !is_usable_unicast(destination)
            || GtpAddressFamily::from_ip(destination) != family
            || !entry.inner_paa().contains(match destination {
                IpAddr::V4(address) => GtpuEndpointAddress::Ipv4(address.octets()),
                IpAddr::V6(address) => GtpuEndpointAddress::Ipv6(address.octets()),
            })
        {
            return Err(GtpuTrafficProofDispatchError::AccessDestinationRejected);
        }
        let challenge = self
            .challenge(sample_id)
            .ok_or(GtpuTrafficProofDispatchError::ZeroSample)?;
        let inner = build_traffic_proof_icmp_echo_request(
            origin,
            destination,
            challenge.identifier(),
            challenge.sequence(),
            challenge.payload(),
        )
        .ok_or(GtpuTrafficProofDispatchError::CoreOriginFamilyMismatch)?;
        let packet = build_plain_gpdu(entry.context().local_teid.get(), &inner)?;
        Ok(GtpuTrafficProofPreparedDispatch {
            sample_id,
            request: GtpuTrafficProofDispatchRequest {
                packet,
                outer_destination: SocketAddr::new(entry.local_outer_address(), GTPU_PORT),
                outer_source: SocketAddr::new(entry.context().peer_address, outer_source_port),
            },
        })
    }

    /// Hand off an opaque prepared challenge after final backend preflight.
    pub(crate) async fn dispatch_prepared_challenge<P>(
        &mut self,
        port: &P,
        prepared: GtpuTrafficProofPreparedDispatch,
    ) -> Result<GtpuTrafficProofDispatchReceipt, GtpuTrafficProofDispatchError>
    where
        P: GtpuTrafficProofDispatchPort + ?Sized,
    {
        let mut authority_liveness = self.authority_dispatch_gate.subscribe();
        let mut attempt_liveness = self.attempt_dispatch_gate.subscribe();
        if !self.authority_dispatch_gate.is_live()
            || !*authority_liveness.borrow_and_update()
            || !self.attempt_dispatch_gate.is_live()
            || !*attempt_liveness.borrow_and_update()
        {
            return Err(GtpuTrafficProofDispatchError::AuthorityRevoked);
        }
        if self.handed_off_samples.contains(&prepared.sample_id) {
            return Err(GtpuTrafficProofDispatchError::SampleAlreadyHandedOff);
        }
        if self.handed_off_samples.len() >= self.policy.maximum_retained_events() {
            return Err(GtpuTrafficProofDispatchError::SampleCapacityExhausted);
        }
        // Retire before awaiting: cancellation cannot establish that a port
        // did not receive or send this request.
        self.handed_off_samples.insert(prepared.sample_id);
        tokio::select! {
            biased;
            changed = authority_liveness.changed() => {
                let _ = changed;
                Err(GtpuTrafficProofDispatchError::AuthorityRevoked)
            }
            changed = attempt_liveness.changed() => {
                let _ = changed;
                Err(GtpuTrafficProofDispatchError::AuthorityRevoked)
            }
            result = port.dispatch(prepared.request) => {
                if self.authority_dispatch_gate.is_live()
                    && *authority_liveness.borrow()
                    && self.attempt_dispatch_gate.is_live()
                    && *attempt_liveness.borrow()
                {
                    result
                } else {
                    Err(GtpuTrafficProofDispatchError::AuthorityRevoked)
                }
            }
        }
    }

    #[cfg(test)]
    async fn dispatch_challenge<P>(
        &mut self,
        port: &P,
        family: GtpAddressFamily,
        sample_id: u32,
    ) -> Result<GtpuTrafficProofDispatchReceipt, GtpuTrafficProofDispatchError>
    where
        P: GtpuTrafficProofDispatchPort + ?Sized,
    {
        let prepared = self.prepare_challenge(port, family, sample_id)?;
        self.dispatch_prepared_challenge(port, prepared).await
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

    pub(crate) fn revoke_attempt_dispatch(&self) {
        self.attempt_dispatch_gate.revoke();
    }

    pub(crate) fn clone_for_adapter(&self) -> Self {
        Self {
            binding: self.binding.clone(),
            policy: self.policy,
            traffic_binding: self.traffic_binding,
            authority: self.authority,
            registration: self.registration,
            authority_dispatch_gate: Arc::clone(&self.authority_dispatch_gate),
            attempt_dispatch_gate: Arc::clone(&self.attempt_dispatch_gate),
            proof_issued: self.proof_issued,
            handed_off_samples: self.handed_off_samples.clone(),
            owns_attempt_lifecycle: false,
            revoker: None,
        }
    }

    pub(crate) fn adapter_snapshot(&self) -> GtpuTrafficProofSessionSnapshot {
        GtpuTrafficProofSessionSnapshot {
            binding: self.binding.clone(),
            policy: self.policy,
            authority: self.authority,
            registration: self.registration,
            authority_dispatch_gate: Arc::clone(&self.authority_dispatch_gate),
            attempt_dispatch_gate: Arc::clone(&self.attempt_dispatch_gate),
            proof_issued: self.proof_issued,
        }
    }

    pub(crate) fn mark_proof_issued(&mut self) {
        self.attempt_dispatch_gate.revoke();
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
        self.attempt_dispatch_gate.revoke();
        self.proof_issued = true;
        Ok(GtpuTrafficProof {
            binding: self.binding.clone(),
            policy: self.policy,
            authority: self.authority,
            assessment,
        })
    }
}

pub(crate) struct GtpuTrafficProofSessionSnapshot {
    binding: GtpuTrafficProofBinding,
    policy: TrafficContinuityPolicy,
    authority: GtpuTrafficProofAuthorityToken,
    registration: GtpuTrafficObservationRegistration,
    authority_dispatch_gate: Arc<GtpuTrafficProofDispatchAuthority>,
    attempt_dispatch_gate: Arc<GtpuTrafficProofDispatchAuthority>,
    proof_issued: bool,
}

impl GtpuTrafficProofSessionSnapshot {
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

    pub(crate) const fn policy(&self) -> TrafficContinuityPolicy {
        self.policy
    }

    pub(crate) const fn authority(&self) -> GtpuTrafficProofAuthorityToken {
        self.authority
    }

    pub(crate) const fn registration(&self) -> GtpuTrafficObservationRegistration {
        self.registration
    }

    pub(crate) fn shares_dispatch_gates(
        &self,
        authority_gate: &Arc<GtpuTrafficProofDispatchAuthority>,
        attempt_gate: &Arc<GtpuTrafficProofDispatchAuthority>,
    ) -> bool {
        Arc::ptr_eq(&self.authority_dispatch_gate, authority_gate)
            && Arc::ptr_eq(&self.attempt_dispatch_gate, attempt_gate)
    }

    pub(crate) const fn proof_issued(&self) -> bool {
        self.proof_issued
    }
}

fn build_plain_gpdu(teid: u32, inner: &[u8]) -> Result<Vec<u8>, GtpuTrafficProofDispatchError> {
    let message = GtpuMessage {
        header: GtpuHeader {
            version: 1,
            protocol_type: true,
            reserved: 0,
            ext_hdr_flag: false,
            seq_num_flag: false,
            npdu_num_flag: false,
            message_type: 0xff,
            length: 0,
            teid,
            sequence_number: None,
            npdu_number: None,
            next_ext_type: None,
            raw_sequence_number: None,
            raw_npdu_number: None,
            raw_next_ext_type: None,
        },
        raw_extension_headers: &[],
        payload: inner,
    };
    let max_message_len = 8_usize
        .checked_add(inner.len())
        .ok_or(GtpuTrafficProofDispatchError::RequestConstructionFailed)?;
    let mut packet = BytesMut::with_capacity(max_message_len);
    message
        .encode(
            &mut packet,
            EncodeContext {
                max_message_len,
                ..EncodeContext::default()
            },
        )
        .map_err(|_| GtpuTrafficProofDispatchError::RequestConstructionFailed)?;
    Ok(packet.to_vec())
}

fn is_usable_unicast(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_multicast()
                && !address.is_broadcast()
                && !address.is_link_local()
        }
        IpAddr::V6(address) => {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_multicast()
                && !address.is_unicast_link_local()
        }
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
        if self.owns_attempt_lifecycle {
            self.attempt_dispatch_gate.revoke();
            if let Some(revoker) = self.revoker.take() {
                revoker.revoke(self.authority);
            }
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
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::Mutex;
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
        authority_with_source_port_policy(GtpuSourcePortPolicy::Any)
    }

    fn authority_with_source_port_policy(
        downlink_source_port_policy: GtpuSourcePortPolicy,
    ) -> GtpuTrafficProofAuthority {
        let context = GtpPdpContext {
            local_teid: Teid::new(1).unwrap(),
            peer_teid: Teid::new(2).unwrap(),
            ms_address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            peer_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            link_ifindex: 7,
            downlink_source_port_policy,
            gtp_version: GtpVersion::V1,
            bearer_mark: None,
            egress_dscp: None,
            uplink_source_port_policy: GtpuUplinkSourcePortPolicy::LegacyServicePort,
        };
        let group = GtpuSessionGroup::new(
            GtpuSessionGroupId::new([1; 16]).unwrap(),
            GtpuSessionDeviceId::new([2; 16]).unwrap(),
            vec![GtpuSessionEntry::new(context, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))).unwrap()],
        )
        .unwrap();
        GtpuTrafficProofAuthority::new(group, 1, 1, 1, policy()).unwrap()
    }

    fn authority_with_outer_endpoints(
        peer_address: IpAddr,
        local_outer_address: IpAddr,
    ) -> GtpuTrafficProofAuthority {
        let ms_address = match (peer_address, local_outer_address) {
            (IpAddr::V4(_), IpAddr::V4(_)) => IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            (IpAddr::V6(_), IpAddr::V6(_)) => {
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x45, 0, 0, 0, 0, 2))
            }
            _ => panic!("test outer endpoints must have one family"),
        };
        let context = GtpPdpContext {
            local_teid: Teid::new(1).unwrap(),
            peer_teid: Teid::new(2).unwrap(),
            ms_address,
            peer_address,
            link_ifindex: 7,
            downlink_source_port_policy: GtpuSourcePortPolicy::Any,
            gtp_version: GtpVersion::V1,
            bearer_mark: None,
            egress_dscp: None,
            uplink_source_port_policy: GtpuUplinkSourcePortPolicy::LegacyServicePort,
        };
        let group = GtpuSessionGroup::new(
            GtpuSessionGroupId::new([1; 16]).unwrap(),
            GtpuSessionDeviceId::new([2; 16]).unwrap(),
            vec![GtpuSessionEntry::new(context, local_outer_address).unwrap()],
        )
        .unwrap();
        GtpuTrafficProofAuthority::new(group, 1, 1, 1, policy()).unwrap()
    }

    fn ipv6_authority() -> GtpuTrafficProofAuthority {
        let context = GtpPdpContext {
            local_teid: Teid::new(3).unwrap(),
            peer_teid: Teid::new(4).unwrap(),
            ms_address: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x45, 0, 0, 0, 0, 2)),
            peer_address: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 1)),
            link_ifindex: 7,
            downlink_source_port_policy: GtpuSourcePortPolicy::Any,
            gtp_version: GtpVersion::V1,
            bearer_mark: None,
            egress_dscp: None,
            uplink_source_port_policy: GtpuUplinkSourcePortPolicy::LegacyServicePort,
        };
        let group = GtpuSessionGroup::new(
            GtpuSessionGroupId::new([3; 16]).unwrap(),
            GtpuSessionDeviceId::new([4; 16]).unwrap(),
            vec![GtpuSessionEntry::new(
                context,
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 2)),
            )
            .unwrap()],
        )
        .unwrap();
        GtpuTrafficProofAuthority::new(group, 1, 1, 1, policy()).unwrap()
    }

    fn session_with_authority_dispatch_gate(
        authority: &GtpuTrafficProofAuthority,
        authority_dispatch_gate: Arc<GtpuTrafficProofDispatchAuthority>,
    ) -> GtpuTrafficProofSession {
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
            authority_dispatch_gate,
            GtpuTrafficProofDispatchAuthority::new(),
        )
    }

    fn session(authority: &GtpuTrafficProofAuthority) -> GtpuTrafficProofSession {
        session_with_authority_dispatch_gate(authority, GtpuTrafficProofDispatchAuthority::new())
    }

    struct CapturedDispatch {
        packet: Vec<u8>,
        destination: SocketAddr,
        source: SocketAddr,
        debug: String,
    }

    struct CapturingPort {
        origin: IpAddr,
        outer_source_port: u16,
        destination: IpAddr,
        result: Result<GtpuTrafficProofDispatchReceipt, GtpuTrafficProofDispatchError>,
        requests: Mutex<Vec<CapturedDispatch>>,
    }

    impl CapturingPort {
        fn accepting(origin: IpAddr) -> Self {
            Self {
                origin,
                outer_source_port: GTPU_PORT,
                destination: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                result: Ok(GtpuTrafficProofDispatchReceipt::accepted()),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn rejecting(origin: IpAddr) -> Self {
            Self {
                origin,
                outer_source_port: GTPU_PORT,
                destination: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                result: Err(GtpuTrafficProofDispatchError::TransportRejected),
                requests: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl GtpuTrafficProofDispatchPort for CapturingPort {
        fn resolve_route(
            &self,
            _family: GtpAddressFamily,
        ) -> Result<GtpuTrafficProofDispatchRoute, GtpuTrafficProofDispatchError> {
            Ok(GtpuTrafficProofDispatchRoute::new(
                self.origin,
                self.outer_source_port,
                self.destination,
            ))
        }

        async fn dispatch(
            &self,
            request: GtpuTrafficProofDispatchRequest,
        ) -> Result<GtpuTrafficProofDispatchReceipt, GtpuTrafficProofDispatchError> {
            self.requests.lock().unwrap().push(CapturedDispatch {
                packet: request.packet().to_vec(),
                destination: request.outer_destination(),
                source: request.outer_source(),
                debug: format!("{request:?}"),
            });
            self.result
        }
    }

    struct PendingPort(IpAddr);

    #[async_trait]
    impl GtpuTrafficProofDispatchPort for PendingPort {
        fn resolve_route(
            &self,
            _family: GtpAddressFamily,
        ) -> Result<GtpuTrafficProofDispatchRoute, GtpuTrafficProofDispatchError> {
            Ok(GtpuTrafficProofDispatchRoute::new(
                self.0,
                GTPU_PORT,
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            ))
        }

        async fn dispatch(
            &self,
            _request: GtpuTrafficProofDispatchRequest,
        ) -> Result<GtpuTrafficProofDispatchReceipt, GtpuTrafficProofDispatchError> {
            std::future::pending().await
        }
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

    #[tokio::test]
    async fn dispatch_builds_an_affine_ipv4_request_before_handoff() {
        let mut session = session(&authority());
        let port = UnsupportedGtpuTrafficProofDispatchPort;

        assert_eq!(
            session
                .dispatch_challenge(&port, GtpAddressFamily::Ipv4, 1)
                .await,
            Err(GtpuTrafficProofDispatchError::TransportUnavailable)
        );
    }

    #[tokio::test]
    async fn dispatch_materializes_exact_ipv4_fixture_and_non_authoritative_receipt() {
        let mut session = session(&authority());
        let sample = 0x1234_5678;
        let challenge = session.challenge(sample).expect("nonzero challenge");
        let port = CapturingPort::accepting(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8)));

        assert_eq!(
            session
                .dispatch_challenge(&port, GtpAddressFamily::Ipv4, sample)
                .await,
            Ok(GtpuTrafficProofDispatchReceipt::accepted())
        );
        assert!(!session.proof_issued(), "receipt must not issue proof");
        let requests = port.requests.lock().unwrap();
        let request = requests.first().expect("one handoff");
        assert_eq!(
            request.destination,
            SocketAddr::from(([192, 0, 2, 2], GTPU_PORT))
        );
        assert_eq!(
            request.source,
            SocketAddr::from(([192, 0, 2, 1], GTPU_PORT))
        );
        assert_eq!(&request.packet[..8], &[0x30, 0xff, 0, 60, 0, 0, 0, 1]);
        let inner = &request.packet[8..];
        assert_eq!(inner.len(), 60);
        assert_eq!(
            &inner[..20],
            &[0x45, 0, 0, 60, 0, 0, 0, 0, 64, 1, 0x46, 0x85, 198, 51, 100, 8, 10, 0, 0, 1]
        );
        assert_eq!(opc_gtpu_ebpf_common::internet_checksum(&inner[..20]), 0);
        assert_eq!(&inner[20..22], &[8, 0]);
        assert_eq!(&inner[24..28], &[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(opc_gtpu_ebpf_common::internet_checksum(&inner[20..]), 0);
        assert_eq!(&inner[28..], challenge.payload());
        assert_eq!(
            format!("{:?}", GtpuTrafficProofDispatchReceipt::accepted()),
            "GtpuTrafficProofDispatchReceipt(<non_authoritative>)"
        );
        assert_eq!(request.debug, "GtpuTrafficProofDispatchRequest(<redacted>)");
    }

    #[tokio::test]
    async fn dispatch_materializes_exact_base_ipv6_fixture_and_checksum() {
        let mut session = session(&ipv6_authority());
        let sample = 0xabcd_ef01;
        let challenge = session.challenge(sample).expect("nonzero challenge");
        let port = CapturingPort::accepting(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0xffff, 0, 0, 0, 0, 8,
        )));
        let mut port = port;
        port.destination = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x45, 0, 0, 0, 0, 2));

        assert!(session
            .dispatch_challenge(&port, GtpAddressFamily::Ipv6, sample)
            .await
            .is_ok());
        let requests = port.requests.lock().unwrap();
        let request = requests.first().expect("one handoff");
        assert_eq!(request.packet.len(), 88);
        assert_eq!(&request.packet[..8], &[0x30, 0xff, 0, 80, 0, 0, 0, 3]);
        let inner = &request.packet[8..];
        assert_eq!(&inner[..8], &[0x60, 0, 0, 0, 0, 40, 58, 64]);
        assert_eq!(
            &inner[8..24],
            &Ipv6Addr::new(0x2001, 0xdb8, 0xffff, 0, 0, 0, 0, 8).octets()
        );
        assert_eq!(
            &inner[24..40],
            &Ipv6Addr::new(0x2001, 0xdb8, 0x45, 0, 0, 0, 0, 2).octets()
        );
        assert_eq!(inner[40], 128);
        assert_eq!(inner[41], 0);
        assert_eq!(&inner[44..48], &[0xab, 0xcd, 0xef, 0x01]);
        let mut checksum_input = Vec::with_capacity(80);
        checksum_input.extend_from_slice(&inner[8..24]);
        checksum_input.extend_from_slice(&inner[24..40]);
        checksum_input.extend_from_slice(&(40_u32).to_be_bytes());
        checksum_input.extend_from_slice(&[0, 0, 0, 58]);
        checksum_input.extend_from_slice(&inner[40..]);
        assert_eq!(opc_gtpu_ebpf_common::internet_checksum(&checksum_input), 0);
        assert_eq!(&inner[48..], challenge.payload());
    }

    #[tokio::test]
    async fn dispatch_rejects_zero_absent_and_wrong_origin_families() {
        let mut session = session(&authority());
        let ipv4 = CapturingPort::accepting(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8)));
        assert_eq!(
            session
                .dispatch_challenge(&ipv4, GtpAddressFamily::Ipv4, 0)
                .await,
            Err(GtpuTrafficProofDispatchError::ZeroSample)
        );
        assert_eq!(
            session
                .dispatch_challenge(&ipv4, GtpAddressFamily::Ipv6, 1)
                .await,
            Err(GtpuTrafficProofDispatchError::AddressFamilyUnavailable)
        );
        let wrong = CapturingPort::accepting(IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(
            session
                .dispatch_challenge(&wrong, GtpAddressFamily::Ipv4, 1)
                .await,
            Err(GtpuTrafficProofDispatchError::CoreOriginFamilyMismatch)
        );
        assert!(wrong.requests.lock().unwrap().is_empty());

        let mut wrong_destination =
            CapturingPort::accepting(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8)));
        wrong_destination.destination = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(
            session
                .dispatch_challenge(&wrong_destination, GtpAddressFamily::Ipv4, 1)
                .await,
            Err(GtpuTrafficProofDispatchError::AccessDestinationRejected)
        );
        let mut unspecified_destination =
            CapturingPort::accepting(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8)));
        unspecified_destination.destination = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        assert_eq!(
            session
                .dispatch_challenge(&unspecified_destination, GtpAddressFamily::Ipv4, 1)
                .await,
            Err(GtpuTrafficProofDispatchError::AccessDestinationRejected)
        );
        let same_paa = CapturingPort::accepting(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(
            session
                .dispatch_challenge(&same_paa, GtpAddressFamily::Ipv4, 1)
                .await,
            Err(GtpuTrafficProofDispatchError::CoreOriginRejected)
        );

        let mut ipv6_session = crate::traffic_observation::tests::session(&ipv6_authority());
        let mut ipv6_same_paa = CapturingPort::accepting(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0x45, 0, 0, 0, 0, 99,
        )));
        ipv6_same_paa.destination = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x45, 0, 0, 0, 0, 2));
        assert_eq!(
            ipv6_session
                .dispatch_challenge(&ipv6_same_paa, GtpAddressFamily::Ipv6, 1)
                .await,
            Err(GtpuTrafficProofDispatchError::CoreOriginRejected)
        );
    }

    #[test]
    fn usable_unicast_predicate_rejects_unsafe_address_classes() {
        for address in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(169, 254, 1, 1),
        ] {
            assert!(!is_usable_unicast(IpAddr::V4(address)));
        }
        for address in [
            Ipv6Addr::UNSPECIFIED,
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
        ] {
            assert!(!is_usable_unicast(IpAddr::V6(address)));
        }
        for address in [
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1)),
        ] {
            assert!(is_usable_unicast(address));
        }
    }

    #[tokio::test]
    async fn dispatch_rejects_non_unicast_inner_and_outer_endpoints() {
        let valid_origin = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8));
        for origin in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(169, 254, 1, 1),
        ] {
            let mut session = session(&authority());
            let port = CapturingPort::accepting(IpAddr::V4(origin));
            assert_eq!(
                session
                    .dispatch_challenge(&port, GtpAddressFamily::Ipv4, 1)
                    .await,
                Err(GtpuTrafficProofDispatchError::CoreOriginRejected)
            );
            assert!(port.requests.lock().unwrap().is_empty());
        }

        for destination in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(169, 254, 1, 1),
        ] {
            let mut session = session(&authority());
            let mut port = CapturingPort::accepting(valid_origin);
            port.destination = IpAddr::V4(destination);
            assert_eq!(
                session
                    .dispatch_challenge(&port, GtpAddressFamily::Ipv4, 1)
                    .await,
                Err(GtpuTrafficProofDispatchError::AccessDestinationRejected)
            );
            assert!(port.requests.lock().unwrap().is_empty());
        }

        for rejected_outer in [
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(169, 254, 1, 1),
        ] {
            for authority in [
                authority_with_outer_endpoints(
                    IpAddr::V4(rejected_outer),
                    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
                ),
                authority_with_outer_endpoints(
                    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                    IpAddr::V4(rejected_outer),
                ),
            ] {
                let mut session = session(&authority);
                let port = CapturingPort::accepting(valid_origin);
                assert_eq!(
                    session
                        .dispatch_challenge(&port, GtpAddressFamily::Ipv4, 1)
                        .await,
                    Err(GtpuTrafficProofDispatchError::OuterEndpointRejected)
                );
                assert!(port.requests.lock().unwrap().is_empty());
            }
        }

        let valid_ipv6_origin = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xffff, 0, 0, 0, 0, 8));
        let valid_ipv6_destination = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x45, 0, 0, 0, 0, 2));
        for rejected in [
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
        ] {
            let mut origin_session = session(&ipv6_authority());
            let mut origin_port = CapturingPort::accepting(IpAddr::V6(rejected));
            origin_port.destination = valid_ipv6_destination;
            assert_eq!(
                origin_session
                    .dispatch_challenge(&origin_port, GtpAddressFamily::Ipv6, 1)
                    .await,
                Err(GtpuTrafficProofDispatchError::CoreOriginRejected)
            );

            let mut destination_session = session(&ipv6_authority());
            let mut destination_port = CapturingPort::accepting(valid_ipv6_origin);
            destination_port.destination = IpAddr::V6(rejected);
            assert_eq!(
                destination_session
                    .dispatch_challenge(&destination_port, GtpAddressFamily::Ipv6, 1)
                    .await,
                Err(GtpuTrafficProofDispatchError::AccessDestinationRejected)
            );

            for authority in [
                authority_with_outer_endpoints(
                    IpAddr::V6(rejected),
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 2)),
                ),
                authority_with_outer_endpoints(
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 1)),
                    IpAddr::V6(rejected),
                ),
            ] {
                let mut outer_session = session(&authority);
                let mut port = CapturingPort::accepting(valid_ipv6_origin);
                port.destination = valid_ipv6_destination;
                assert_eq!(
                    outer_session
                        .dispatch_challenge(&port, GtpAddressFamily::Ipv6, 1)
                        .await,
                    Err(GtpuTrafficProofDispatchError::OuterEndpointRejected)
                );
            }
        }
    }

    #[tokio::test]
    async fn dispatch_validates_transport_source_port_against_exact_entry_policy() {
        let origin = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8));
        let mut any_session = session(&authority_with_source_port_policy(
            GtpuSourcePortPolicy::Any,
        ));
        let any = CapturingPort::accepting(origin);
        assert!(any_session
            .dispatch_challenge(&any, GtpAddressFamily::Ipv4, 1)
            .await
            .is_ok());

        let mut exact_session = session(&authority_with_source_port_policy(
            GtpuSourcePortPolicy::Exact(21_152),
        ));
        let mut exact = CapturingPort::accepting(origin);
        exact.outer_source_port = 21_152;
        assert!(exact_session
            .dispatch_challenge(&exact, GtpAddressFamily::Ipv4, 1)
            .await
            .is_ok());
        let mut exact_rejected = CapturingPort::accepting(origin);
        exact_rejected.outer_source_port = 21_153;
        assert_eq!(
            exact_session
                .dispatch_challenge(&exact_rejected, GtpAddressFamily::Ipv4, 2)
                .await,
            Err(GtpuTrafficProofDispatchError::OuterSourcePortRejected)
        );

        let range = GtpuSourcePortPolicy::inclusive_range(40_000, 40_001).unwrap();
        let mut range_session = session(&authority_with_source_port_policy(range));
        let mut in_range = CapturingPort::accepting(origin);
        in_range.outer_source_port = 40_001;
        assert!(range_session
            .dispatch_challenge(&in_range, GtpAddressFamily::Ipv4, 1)
            .await
            .is_ok());
        let mut zero = CapturingPort::accepting(origin);
        zero.outer_source_port = 0;
        assert_eq!(
            range_session
                .dispatch_challenge(&zero, GtpAddressFamily::Ipv4, 2)
                .await,
            Err(GtpuTrafficProofDispatchError::OuterSourcePortRejected)
        );
    }

    #[tokio::test]
    async fn failed_or_canceled_handoff_cannot_reuse_a_sample_and_ledger_is_bounded() {
        let mut session = session(&authority());
        let origin = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8));
        let rejecting = CapturingPort::rejecting(origin);
        assert_eq!(
            session
                .dispatch_challenge(&rejecting, GtpAddressFamily::Ipv4, 1)
                .await,
            Err(GtpuTrafficProofDispatchError::TransportRejected)
        );
        assert_eq!(
            session
                .dispatch_challenge(&rejecting, GtpAddressFamily::Ipv4, 1)
                .await,
            Err(GtpuTrafficProofDispatchError::SampleAlreadyHandedOff)
        );

        let pending = PendingPort(origin);
        let mut handoff = Box::pin(session.dispatch_challenge(&pending, GtpAddressFamily::Ipv4, 2));
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(
            Future::poll(handoff.as_mut(), &mut context),
            Poll::Pending
        ));
        drop(handoff);
        assert_eq!(
            session
                .dispatch_challenge(&rejecting, GtpAddressFamily::Ipv4, 2)
                .await,
            Err(GtpuTrafficProofDispatchError::SampleAlreadyHandedOff)
        );

        for sample in [3, 4] {
            assert_eq!(
                session
                    .dispatch_challenge(&rejecting, GtpAddressFamily::Ipv4, sample)
                    .await,
                Err(GtpuTrafficProofDispatchError::TransportRejected)
            );
        }
        assert_eq!(
            session
                .dispatch_challenge(&rejecting, GtpAddressFamily::Ipv4, 5)
                .await,
            Err(GtpuTrafficProofDispatchError::SampleCapacityExhausted)
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
        let mut session = session(store.lease().await.authority());
        let port = CapturingPort::accepting(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8)));
        assert_eq!(
            backend
                .dispatch_gtpu_traffic_proof_challenge(
                    &mut session,
                    &port,
                    GtpAddressFamily::Ipv4,
                    1,
                )
                .await,
            Err(GtpuTrafficProofDispatchError::TransportUnavailable)
        );
        assert!(port.requests.lock().unwrap().is_empty());
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
    async fn authority_replacement_revokes_a_pending_dispatch_handoff() {
        let original = authority();
        let store = GtpuTrafficProofAuthorityStore::new_for_test(original.clone());
        let lease = store.lease().await;
        let authority_dispatch_gate = lease.dispatch_authority();
        let mut session = session_with_authority_dispatch_gate(&original, authority_dispatch_gate);
        drop(lease);

        let port = PendingPort(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8)));
        let mut handoff = Box::pin(session.dispatch_challenge(&port, GtpAddressFamily::Ipv4, 1));
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(
            Future::poll(handoff.as_mut(), &mut context),
            Poll::Pending
        ));

        store
            .replace(GtpuTrafficProofAuthority::new(group(), 2, 2, 2, policy()).unwrap())
            .await
            .unwrap();
        assert!(matches!(
            Future::poll(handoff.as_mut(), &mut context),
            Poll::Ready(Err(GtpuTrafficProofDispatchError::AuthorityRevoked))
        ));
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
