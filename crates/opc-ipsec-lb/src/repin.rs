//! Kernel-independent re-pin coordination primitives.

use std::any::Any;
use std::fmt;
use std::num::{NonZeroU128, NonZeroU64};

use opc_ipsec_xfrm::{
    AppliedEspCounterReceipt, EspCounterProofRequirement, EspCounterPublicationGuard,
    EspCounterResumeBinding, EspCounterResumeProofSet, OutboundEspCounterTarget,
    OutboundEspCounterTargetSet, OutboundSaBindingId,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::IpsecLbError;
use crate::failover::{AntiReplayResume, SendIvCounterMode, SendIvForwardJump};
use crate::model::{ClusterNode, IpAddress, SaId, SteerKey, SteeringRule};
use crate::ownership::SessionOwnershipKey;
use crate::ports::{
    OwnershipActivationAuthority, OwnershipFencer, OwnershipRetirementAuthority, OwnershipSource,
    RePinAuditSink, RePinSteeringBackend, RePinSteeringRetirementBackend,
};
use crate::spi::{EntropySource, SystemEntropy};

/// Monotonic ownership fence token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct OwnershipFence(NonZeroU64);

impl OwnershipFence {
    /// Build a non-zero ownership fence token.
    pub fn new(value: u64) -> Result<Self, IpsecLbError> {
        let Some(value) = NonZeroU64::new(value) else {
            return Err(IpsecLbError::invalid_config(
                "fence",
                "fence token must be non-zero",
            ));
        };
        Ok(Self(value))
    }

    /// Return the numeric fence value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Authoritative SA ownership metadata used to prepare a fenced transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipSnapshot {
    owner: ClusterNode,
    fence: OwnershipFence,
}

impl OwnershipSnapshot {
    /// Build an owner/fence snapshot.
    #[must_use]
    pub const fn new(owner: ClusterNode, fence: OwnershipFence) -> Self {
        Self { owner, fence }
    }

    /// Return the authoritative owner.
    #[must_use]
    pub fn owner(&self) -> &ClusterNode {
        &self.owner
    }

    /// Return the authoritative predecessor fence.
    #[must_use]
    pub const fn fence(&self) -> OwnershipFence {
        self.fence
    }
}

/// Stable identity for one ownership transition and all of its retries.
///
/// Callers generate one non-zero, deployment-unique value before starting a
/// re-pin and retain it when replaying the same request. A fresh transition,
/// including a later ABA return to the same owner, MUST use a new value.
///
/// # Unpredictability
///
/// The value MUST be drawn from a cryptographically secure random source, not
/// from a counter, timestamp, or any other guessable sequence. Every other
/// field of a retirement — the SA, the ownership key, the owner
/// [`ClusterNode`], the [`SteeringRule`], and the active fence — is either a
/// public protocol value or a small monotonic integer, so this identity is the
/// only field an unrelated party cannot derive. The retirement boundaries
/// ([`RePinCoordinator::retire_activation`] and
/// [`crate::session_repin::SessionRePinCoordinator::retire`]) match a caller's
/// request against the durable record for *idempotent convergence*, not as an
/// authorization decision; a guessable transition identity therefore turns
/// that exact-match replay into a usable per-SA teardown primitive. Deployments
/// that mint these from a counter are attackable by any party that can reach
/// the coordinator API.
///
/// Use [`OwnershipTransitionId::generate`] rather than drawing the 128 bits by
/// hand; it is the only constructor that satisfies this requirement by
/// construction. [`OwnershipTransitionId::new`] exists for callers restoring an
/// already-minted identity from durable state.
///
/// # Secrecy
///
/// Unpredictability at mint time is only half of the obligation: the value MUST
/// also stay secret for as long as the transition is live. It is the sole
/// authorization factor for
/// [`RePinCoordinator::retire_activation`] — the other gate,
/// the target-shard owner read, is derived entirely from fields of the replayed
/// request and therefore authenticates nothing. Anyone who learns a live
/// transition identity holds a standing per-SA teardown capability until that
/// transition is spent.
///
/// Treat it exactly like key material:
///
/// * **Never log it, export it, or place it in a metric label, trace span, or
///   audit record.** The audit port deliberately carries a
///   [`RePinAuditCorrelationId`] instead of this value so that an ordinary
///   correlation-logging sink cannot become a disclosure path.
/// * Its [`fmt::Debug`] implementation prints `OwnershipTransitionId([redacted])`
///   so that neither it nor any container that derives `Debug` can leak it
///   incidentally. [`OwnershipTransitionId::get`] is the only way to reach the
///   value, and every call site that uses it is a disclosure decision.
/// * At rest it must be encrypted. The session-store record that carries it is
///   plaintext only above the `EncryptingSessionBackend` boundary; production HA
///   deployments MUST wrap the backend, as the crate README requires.
///
/// The disclosure becomes harmless only once the transition is terminally
/// committed to teardown, which is why
/// [`crate::SessionStoreOwnershipFencer::recover_stranded_activation_retirement`]
/// may return it for a `Retiring` record and for no other state.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct OwnershipTransitionId(NonZeroU128);

/// Bounded redraws for a CSPRNG that returns the one rejected 128-bit value.
///
/// A correct source hits zero with probability 2^-128 per draw, so exhausting
/// this budget means the entropy source is broken rather than unlucky.
const MAX_TRANSITION_ID_DRAWS: usize = 8;

impl OwnershipTransitionId {
    /// Build a non-zero transition identity from an already-minted value.
    ///
    /// This is the restore path — deserializing a durable record, or rebuilding
    /// a retained request for a retry. To *mint* a new identity use
    /// [`Self::generate`], which draws the value from a CSPRNG as this type
    /// requires.
    ///
    /// # Errors
    ///
    /// Returns [`IpsecLbError::InvalidConfig`] when `value` is zero.
    pub fn new(value: u128) -> Result<Self, IpsecLbError> {
        let Some(value) = NonZeroU128::new(value) else {
            return Err(IpsecLbError::invalid_config(
                "transition_id",
                "ownership transition ID must be non-zero",
            ));
        };
        Ok(Self(value))
    }

    /// Mint a fresh transition identity from the system CSPRNG.
    ///
    /// This is the constructor every caller minting a new transition should
    /// use: it draws the full 128 bits from the platform's cryptographically
    /// secure random source, satisfying the unpredictability requirement
    /// documented on this type without the caller having to remember it.
    ///
    /// The result is a secret for as long as the transition is live; see the
    /// secrecy obligation on this type before storing or emitting it.
    ///
    /// # Errors
    ///
    /// Returns [`IpsecLbError::EntropyUnavailable`] when the system random
    /// source fails, or when it repeatedly yields the single rejected all-zero
    /// value — either outcome means the source is not usable for key material.
    pub fn generate() -> Result<Self, IpsecLbError> {
        Self::generate_from(&SystemEntropy)
    }

    /// Mint a fresh transition identity from an explicit entropy source.
    ///
    /// Deployments that already own a vetted CSPRNG — and tests that need a
    /// deterministic draw — can supply it here. The source MUST be
    /// cryptographically secure in production; [`Self::generate`] uses the
    /// system source and is the right default.
    ///
    /// # Errors
    ///
    /// Returns [`IpsecLbError::EntropyUnavailable`] when `entropy` fails, or
    /// when it yields the rejected all-zero value on every one of the bounded
    /// redraws.
    pub fn generate_from<E>(entropy: &E) -> Result<Self, IpsecLbError>
    where
        E: EntropySource + ?Sized,
    {
        for _ in 0..MAX_TRANSITION_ID_DRAWS {
            // Declared inside the loop, and zeroized on the way out: a source
            // that returns `Ok(())` after writing only part of `dst` would
            // otherwise let one redraw inherit the previous draw's tail, and
            // the drawn value is 128 bits of live secret either way.
            let mut bytes = Zeroizing::new([0_u8; 16]);
            entropy.fill_bytes(bytes.as_mut_slice())?;
            if let Some(value) = NonZeroU128::new(u128::from_be_bytes(*bytes)) {
                return Ok(Self(value));
            }
        }
        Err(IpsecLbError::EntropyUnavailable)
    }

    /// Return the numeric transition identity.
    ///
    /// Every call is a deliberate disclosure of a live secret. Use it to bind
    /// the identity into a fingerprint, a durable encrypted record, or a
    /// coordinator call — never to log, export, or correlate it. Audit
    /// correlation is served by [`RePinAuditCorrelationId::for_transition`],
    /// which is not reversible.
    #[must_use]
    pub const fn get(self) -> u128 {
        self.0.get()
    }
}

impl fmt::Debug for OwnershipTransitionId {
    /// Redact the value: a live transition identity is the sole authorization
    /// factor for retirement, so it must never reach a log through the `Debug`
    /// of this type or of any container that derives `Debug` around it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OwnershipTransitionId([redacted])")
    }
}

/// Collision-resistant binding of an ownership transition to its full re-pin
/// request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct OwnershipTransitionFingerprint([u8; 32]);

impl OwnershipTransitionFingerprint {
    /// Build an opaque fingerprint for direct ownership-fencer integrations.
    ///
    /// Re-pin callers should use [`RePinRequest::ownership_fingerprint`], which
    /// canonically binds every steering and resume-evidence field.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return the fingerprint bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Source of the resumed SA key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResumeKeySource {
    /// A live standby already held the SA keys before owner loss.
    ///
    /// For a counter-based mode, live mirroring does not make the mirrored send
    /// counter current at the instant of failure, so the resume requires a
    /// forward-jump. Random-IV IKE requires the explicit CSPRNG attestation
    /// instead.
    LiveMirrored,
    /// No standby has keys; the caller must rekey or force UE re-attach.
    RekeyOrReattachFallback,
    /// Persisted key material was read on the re-pin path.
    ///
    /// Counter-based same-SPI use requires a validated outbound IV
    /// forward-jump. Random-IV IKE requires the explicit CSPRNG attestation.
    PersistedKeyMaterial,
}

/// Attestation for an IKE encrypt-then-MAC SA whose outbound IVs are random.
///
/// This evidence is appropriate only when every newly encrypted IKE message
/// obtains an independent, unpredictable IV from a cryptographically secure
/// random source. It is not an IV value, counter, key, or proof generated by
/// the SDK. The IKE protected-payload owner remains responsible for satisfying
/// the attested invariant for the lifetime of the resumed SA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IkeRandomIvAttestation {
    /// Every outbound protected message obtains a fresh independent CSPRNG IV.
    FreshIndependentCsprngIvPerMessage,
}

/// Protocol-specific outbound-IV evidence for a same-SPI resume.
///
/// Counter fields exist only in [`Self::CounterBased`], so an IKE
/// encrypt-then-MAC resume cannot claim placeholder counters. [`Self::Unspecified`]
/// lets legacy or ambiguously decoded evidence reach the validation boundary,
/// where it is rejected without changing ownership or steering.
///
/// Random-IV evidence cannot be constructed without its attestation, nor can
/// it carry dummy counter fields:
///
/// ```compile_fail
/// use opc_ipsec_lb::SameSpiOutboundIvResume;
///
/// let _ = SameSpiOutboundIvResume::IkeRandomIv {
///     checkpointed_send_iv_next: 0,
///     restored_send_iv_next: 0,
/// };
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SameSpiOutboundIvResume {
    /// Legacy, missing, or ambiguously decoded outbound-IV evidence.
    Unspecified,
    /// Resume a protocol-defined monotonic outbound counter.
    CounterBased {
        /// Last checkpointed or mirrored next outbound IV/counter value.
        ///
        /// This is a stale lower bound, not proof that the old owner stopped
        /// before consuming later counter values. ESP checkpoints must be
        /// non-zero, and the ESP counter mode defines peer receive lag relative
        /// to this value minus one.
        checkpointed_send_iv_next: u64,
        /// Next outbound IV/counter value actually restored on the survivor.
        restored_send_iv_next: u64,
        /// Mandatory stale-counter forward-jump evidence.
        ///
        /// `None` is representable so decoded or legacy counter evidence can be
        /// rejected at the re-pin boundary.
        forward_jump: Option<SendIvForwardJump>,
    },
    /// Resume an IKE encrypt-then-MAC SA that uses random outbound IVs.
    ///
    /// No counter or forward-jump fields exist in this variant. It is valid
    /// only for [`SaId::Ike`].
    IkeRandomIv {
        /// Explicit caller attestation of the resumed IKE IV-generation mode.
        attestation: IkeRandomIvAttestation,
    },
}

/// Evidence required before installing an IPsec/IKE same-SPI re-pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SameSpiResume {
    /// SA before owner loss.
    pub previous_sa: SaId,
    /// SA resumed on the survivor.
    pub resumed_sa: SaId,
    /// Outbound-IV safety evidence for the resumed cryptographic mode.
    pub outbound_iv: SameSpiOutboundIvResume,
    /// Inbound anti-replay restore evidence (ESP sequence or IKE Message ID).
    pub anti_replay: AntiReplayResume,
    /// Key-custody path used for the resumed SA.
    pub key_source: ResumeKeySource,
}

impl SameSpiResume {
    /// Validate that this evidence can support near-hitless same-SPI re-pin.
    pub fn validate_for_repin(self, expected_sa: SaId) -> Result<(), IpsecLbError> {
        validate_sa_identifier(expected_sa)?;
        if self.previous_sa != expected_sa || self.resumed_sa != expected_sa {
            return Err(IpsecLbError::unsafe_resume(
                "same-SPI re-pin requires the resumed SA to keep the original protocol and SPI",
            ));
        }
        match self.key_source {
            ResumeKeySource::LiveMirrored | ResumeKeySource::PersistedKeyMaterial => {}
            ResumeKeySource::RekeyOrReattachFallback => {
                return Err(IpsecLbError::unsafe_resume(
                    "rekey or UE re-attach fallback cannot claim same-SPI re-pin",
                ));
            }
        }

        match self.outbound_iv {
            SameSpiOutboundIvResume::Unspecified => {
                return Err(IpsecLbError::unsafe_resume(
                    "same-SPI re-pin requires explicit outbound IV resume evidence",
                ));
            }
            SameSpiOutboundIvResume::CounterBased {
                checkpointed_send_iv_next,
                restored_send_iv_next,
                forward_jump,
            } => {
                let Some(forward_jump) = forward_jump else {
                    return Err(IpsecLbError::unsafe_resume(
                        "counter-based same-SPI re-pin requires send IV forward-jump evidence",
                    ));
                };
                forward_jump.validate_restored_next(
                    expected_sa,
                    checkpointed_send_iv_next,
                    restored_send_iv_next,
                )?;
            }
            SameSpiOutboundIvResume::IkeRandomIv { attestation } => {
                if !matches!(expected_sa, SaId::Ike { .. }) {
                    return Err(IpsecLbError::unsafe_resume(
                        "random-IV same-SPI resume is valid only for an IKE SA",
                    ));
                }
                match attestation {
                    IkeRandomIvAttestation::FreshIndependentCsprngIvPerMessage => {}
                }
            }
        }
        self.anti_replay.validate()
    }
}

/// Request to fence ownership and install a steer override for a resumed SA.
#[derive(Clone, PartialEq, Eq)]
pub struct RePinRequest {
    /// SA being re-pinned.
    pub sa: SaId,
    /// Stable identity reused only for retries of this transition.
    pub transition_id: OwnershipTransitionId,
    /// Exact authoritative fence held by `previous_owner` when prepared.
    /// Obtain it with [`OwnershipSource::sa_ownership`].
    pub previous_fence: OwnershipFence,
    /// Owner expected before the transition.
    pub previous_owner: ClusterNode,
    /// New owner after failover.
    pub new_owner: ClusterNode,
    /// Steering override to install after fencing.
    pub rule: SteeringRule,
    /// Exact destination-scoped key programmed by ownership-aware datapaths.
    ///
    /// The key's protocol and SPI must match both `sa` and `rule`. Its public
    /// destination and routing domain are retained verbatim; the coordinator
    /// never guesses either value from the SPI-only legacy rule.
    pub ownership_key: SessionOwnershipKey,
    /// Durable, key-free identity of the exact outbound XFRM SA and policy.
    ///
    /// This is mandatory for an ESP request and prohibited for an IKE
    /// request. It is correlation only: the live target and opaque receipt are
    /// supplied separately and are never persisted in this request.
    pub outbound_sa_binding_id: Option<OutboundSaBindingId>,
    /// Same-SPI resume evidence.
    pub resume: SameSpiResume,
}

impl RePinRequest {
    /// Construct and validate an IKE same-SPI re-pin request.
    #[allow(clippy::too_many_arguments)]
    pub fn new_ike(
        responder_spi: u64,
        transition_id: OwnershipTransitionId,
        previous_fence: OwnershipFence,
        previous_owner: ClusterNode,
        new_owner: ClusterNode,
        rule: SteeringRule,
        ownership_key: SessionOwnershipKey,
        resume: SameSpiResume,
    ) -> Result<Self, IpsecLbError> {
        let request = Self {
            sa: SaId::Ike { responder_spi },
            transition_id,
            previous_fence,
            previous_owner,
            new_owner,
            rule,
            ownership_key,
            outbound_sa_binding_id: None,
            resume,
        };
        validate_request(&request)?;
        request.resume.validate_for_repin(request.sa)?;
        Ok(request)
    }

    /// Construct and validate an ESP same-SPI re-pin request.
    ///
    /// `inbound_spi` is the peer-to-local SPI used for ingress ownership and
    /// steering. `outbound_sa_binding_id` identifies the distinct
    /// local-to-peer SA and policy that were installed through
    /// `opc-ipsec-xfrm`; it is never inferred from the inbound SPI.
    #[allow(clippy::too_many_arguments)]
    pub fn new_esp(
        inbound_spi: u32,
        outbound_sa_binding_id: OutboundSaBindingId,
        transition_id: OwnershipTransitionId,
        previous_fence: OwnershipFence,
        previous_owner: ClusterNode,
        new_owner: ClusterNode,
        rule: SteeringRule,
        ownership_key: SessionOwnershipKey,
        resume: SameSpiResume,
    ) -> Result<Self, IpsecLbError> {
        let request = Self {
            sa: SaId::Esp { spi: inbound_spi },
            transition_id,
            previous_fence,
            previous_owner,
            new_owner,
            rule,
            ownership_key,
            outbound_sa_binding_id: Some(outbound_sa_binding_id),
            resume,
        };
        validate_request(&request)?;
        request.resume.validate_for_repin(request.sa)?;
        Ok(request)
    }

    /// Hash the complete safety-critical request into a stable transition
    /// fingerprint used by ownership commit and recovery.
    ///
    /// Destination-scoped requests use the v4 domain. It binds the canonical
    /// Host-XDP ownership key in addition to the complete legacy rule and, for
    /// ESP counter resumes, certifies that SDK-issued apply/readback proof was
    /// mandatory. Older SPI-only grants therefore cannot be recovered as if
    /// they carried destination or kernel-counter authority.
    #[must_use]
    pub fn ownership_fingerprint(&self) -> OwnershipTransitionFingerprint {
        let mut hasher = Sha256::new();
        if matches!(
            (self.sa, self.resume.outbound_iv),
            (
                SaId::Esp { .. },
                SameSpiOutboundIvResume::CounterBased { .. }
            )
        ) {
            hasher.update(b"opc-ipsec-lb/repin-transition/v5-destination-scoped-esp-binding");
        } else {
            // Preserve the frozen IKE and non-counter request fingerprint.
            hasher.update(b"opc-ipsec-lb/repin-transition/v4-destination-scoped");
        }
        hash_request_prefix(&mut hasher, self);
        match (self.sa, self.resume.outbound_iv) {
            (
                SaId::Ike { .. },
                SameSpiOutboundIvResume::CounterBased {
                    checkpointed_send_iv_next,
                    restored_send_iv_next,
                    forward_jump,
                },
            ) => {
                hasher.update([1]);
                hash_counter_resume_v1(
                    &mut hasher,
                    self.resume,
                    checkpointed_send_iv_next,
                    restored_send_iv_next,
                    forward_jump,
                );
            }
            (
                SaId::Esp { .. },
                SameSpiOutboundIvResume::CounterBased {
                    checkpointed_send_iv_next,
                    restored_send_iv_next,
                    forward_jump,
                },
            ) => {
                hasher.update([2]);
                hash_counter_resume_v1(
                    &mut hasher,
                    self.resume,
                    checkpointed_send_iv_next,
                    restored_send_iv_next,
                    forward_jump,
                );
            }
            (
                _,
                SameSpiOutboundIvResume::Unspecified | SameSpiOutboundIvResume::IkeRandomIv { .. },
            ) => {
                hasher.update([3]);
                hash_resume_v2(&mut hasher, self.resume);
            }
        }
        OwnershipTransitionFingerprint(hasher.finalize().into())
    }
}

impl fmt::Debug for RePinRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RePinRequest([redacted])")
    }
}

fn hash_request_prefix(hasher: &mut Sha256, request: &RePinRequest) {
    hasher.update(request.transition_id.get().to_be_bytes());
    hasher.update(request.previous_fence.get().to_be_bytes());
    hash_sa(hasher, request.sa);
    hash_bytes(hasher, request.previous_owner.as_str().as_bytes());
    hash_bytes(hasher, request.new_owner.as_str().as_bytes());
    hasher.update(request.rule.shard.get().to_be_bytes());
    hasher.update(request.rule.owner.get().to_be_bytes());
    hash_steer_key(hasher, request.rule.key);
    hash_bytes(hasher, &request.ownership_key.to_canonical_bytes());
    match request.outbound_sa_binding_id {
        Some(id) => {
            hasher.update([1]);
            hasher.update(id.to_bytes());
        }
        None => hasher.update([0]),
    }
}

/// Exact fenced owner update passed to a re-pin steering backend.
///
/// Construction is private to the coordinator so a backend never receives a
/// caller-invented generation. The owner and generation come from the
/// validated rule and authoritative ownership-fence grant respectively.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RePinSteeringUpdate {
    ownership_key: SessionOwnershipKey,
    rule: SteeringRule,
    generation: OwnershipFence,
}

/// Single-use serialization permit for one exact steering ownership key.
///
/// Coordinators acquire this permit before their final authoritative store
/// validation and move it into the steering mutation. Host-XDP binds it to one
/// backend instance and canonical key, then retains it inside the blocking
/// mutation even if the awaiting task is cancelled. The internals are opaque
/// so callers cannot forge, clone, or retarget an already-authorized operation.
#[must_use = "dropping a steering permit abandons the serialized operation"]
pub struct RePinSteeringOperationPermit {
    ownership_key: SessionOwnershipKey,
    evidence: Option<Box<dyn Any + Send + Sync>>,
    esp_counter_publication_guard: Option<EspCounterPublicationGuard>,
    publication_state: RePinPublicationState,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RePinPublicationState {
    NotRequired,
    Armed,
    Authorized,
    Rejected,
}

impl RePinSteeringOperationPermit {
    pub(crate) fn unguarded(ownership_key: SessionOwnershipKey) -> Self {
        Self {
            ownership_key,
            evidence: None,
            esp_counter_publication_guard: None,
            publication_state: RePinPublicationState::NotRequired,
        }
    }

    pub(crate) fn guarded<T>(ownership_key: SessionOwnershipKey, evidence: T) -> Self
    where
        T: Any + Send + Sync,
    {
        Self {
            ownership_key,
            evidence: Some(Box::new(evidence)),
            esp_counter_publication_guard: None,
            publication_state: RePinPublicationState::NotRequired,
        }
    }

    pub(crate) fn guarded_after_counter_publication<T>(
        ownership_key: SessionOwnershipKey,
        evidence: T,
    ) -> Self
    where
        T: Any + Send + Sync,
    {
        Self {
            ownership_key,
            evidence: Some(Box::new(evidence)),
            esp_counter_publication_guard: None,
            publication_state: RePinPublicationState::Authorized,
        }
    }

    fn bind_esp_counter_publication_guard(
        mut self,
        guard: EspCounterPublicationGuard,
    ) -> Result<Self, IpsecLbError> {
        if self.publication_state != RePinPublicationState::NotRequired {
            return Err(IpsecLbError::adapter_contract_violation(
                "repin_operation_permit_counter_guard_duplicate",
            ));
        }
        if self.esp_counter_publication_guard.replace(guard).is_some() {
            return Err(IpsecLbError::adapter_contract_violation(
                "repin_operation_permit_counter_guard_duplicate",
            ));
        }
        self.publication_state = RePinPublicationState::Armed;
        Ok(self)
    }

    pub(crate) const fn has_esp_counter_publication_guard(&self) -> bool {
        matches!(self.publication_state, RePinPublicationState::Armed)
            && self.esp_counter_publication_guard.is_some()
    }

    pub(crate) const fn counter_publication_authorized(&self) -> bool {
        matches!(self.publication_state, RePinPublicationState::Authorized)
    }

    /// Execute one concrete synchronous publication while any bound ESP
    /// counter guard keeps its XFRM actor frozen.
    ///
    /// Backends other than Host-XDP must call this at their exact externally
    /// visible publication cut and return this same permit afterwards. The
    /// closure's output is structurally restricted to a concrete `Result`, so
    /// an unpolled future cannot escape after the guard is released. The call
    /// consumes publication authority on every success and failure path;
    /// invoking it again rejects without executing the closure.
    pub fn publish_with_esp_counter_guard<E>(
        &mut self,
        publication: impl FnOnce() -> Result<(), E>,
    ) -> Result<Result<(), E>, IpsecLbError> {
        if matches!(
            self.publication_state,
            RePinPublicationState::Authorized | RePinPublicationState::Rejected
        ) {
            return Err(IpsecLbError::adapter_contract_violation(
                "repin_operation_permit_publication_already_consumed",
            ));
        }
        // Mark rejected before invoking either the guard or publication. Only
        // an exact successful cut upgrades the terminal state to Authorized;
        // expiry and every inner/outer error stay terminal and fail closed.
        self.publication_state = RePinPublicationState::Rejected;
        let result = match self.esp_counter_publication_guard.take() {
            Some(guard) => guard
                .publish(publication)
                .map_err(|error| IpsecLbError::applied_counter_proof_rejected(error.code())),
            None => Ok(publication()),
        };
        if matches!(&result, Ok(Ok(()))) {
            self.publication_state = RePinPublicationState::Authorized;
        }
        result
    }

    pub(crate) fn into_guarded<T>(self) -> Result<T, IpsecLbError>
    where
        T: Any + Send + Sync,
    {
        if self.publication_state != RePinPublicationState::NotRequired
            || self.esp_counter_publication_guard.is_some()
        {
            return Err(IpsecLbError::adapter_contract_violation(
                "repin_operation_permit_counter_guard_unconsumed",
            ));
        }
        self.evidence
            .ok_or_else(|| {
                IpsecLbError::adapter_contract_violation("repin_operation_permit_missing")
            })?
            .downcast::<T>()
            .map(|value| *value)
            .map_err(|_| {
                IpsecLbError::adapter_contract_violation("repin_operation_permit_mismatched")
            })
    }

    pub(crate) fn into_guarded_with_esp_counter_publication<T>(
        self,
    ) -> Result<(T, Option<EspCounterPublicationGuard>), IpsecLbError>
    where
        T: Any + Send + Sync,
    {
        if !matches!(
            self.publication_state,
            RePinPublicationState::NotRequired | RePinPublicationState::Armed
        ) {
            return Err(IpsecLbError::adapter_contract_violation(
                "repin_operation_permit_publication_already_consumed",
            ));
        }
        let evidence = self
            .evidence
            .ok_or_else(|| {
                IpsecLbError::adapter_contract_violation("repin_operation_permit_missing")
            })?
            .downcast::<T>()
            .map(|value| *value)
            .map_err(|_| {
                IpsecLbError::adapter_contract_violation("repin_operation_permit_mismatched")
            })?;
        Ok((evidence, self.esp_counter_publication_guard))
    }

    /// Return the exact destination-scoped key serialized by this permit.
    #[must_use]
    pub const fn ownership_key(&self) -> SessionOwnershipKey {
        self.ownership_key
    }
}

impl fmt::Debug for RePinSteeringOperationPermit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RePinSteeringOperationPermit([redacted])")
    }
}

impl RePinSteeringUpdate {
    const fn new(request: &RePinRequest, generation: OwnershipFence) -> Self {
        Self {
            ownership_key: request.ownership_key,
            rule: request.rule,
            generation,
        }
    }

    /// Mint the exact steering update for one authoritative first activation.
    ///
    /// This is the activation twin of [`Self::new`]: the owner comes from the
    /// validated rule and the generation from the store-minted activation
    /// grant. It stays crate-private so no caller-invented generation can reach
    /// a steering backend.
    pub(crate) const fn for_activation(
        request: &OwnershipActivationRequest,
        generation: OwnershipFence,
    ) -> Self {
        Self {
            ownership_key: request.ownership_key,
            rule: request.rule,
            generation,
        }
    }

    #[cfg(test)]
    pub(crate) const fn for_test(request: &RePinRequest, generation: OwnershipFence) -> Self {
        Self::new(request, generation)
    }

    /// Return the exact destination-scoped ownership key.
    #[must_use]
    pub const fn ownership_key(self) -> SessionOwnershipKey {
        self.ownership_key
    }

    /// Return the legacy steering rule retained for non-Host-XDP backends.
    #[must_use]
    pub const fn rule(self) -> SteeringRule {
        self.rule
    }

    /// Return the target owner shard.
    #[must_use]
    pub const fn owner(self) -> crate::ShardId {
        self.rule.owner
    }

    /// Return the authoritative ownership generation.
    #[must_use]
    pub const fn generation(self) -> OwnershipFence {
        self.generation
    }
}

impl fmt::Debug for RePinSteeringUpdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RePinSteeringUpdate([redacted])")
    }
}

/// Ownership fence mutation request.
#[derive(Clone, PartialEq, Eq)]
pub struct OwnershipFenceRequest {
    /// SA being fenced.
    pub sa: SaId,
    /// Exact destination-scoped authoritative ownership key.
    pub ownership_key: SessionOwnershipKey,
    /// Stable identity reused only for retries of this transition.
    pub transition_id: OwnershipTransitionId,
    /// Canonical binding to the complete re-pin request.
    pub fingerprint: OwnershipTransitionFingerprint,
    /// Exact predecessor fence that must still be authoritative.
    pub previous_fence: OwnershipFence,
    /// Owner expected before the transition.
    pub previous_owner: ClusterNode,
    /// New owner that receives the monotonic fence.
    pub new_owner: ClusterNode,
}

impl fmt::Debug for OwnershipFenceRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OwnershipFenceRequest([redacted])")
    }
}

/// Successful ownership fence grant.
#[derive(Clone, PartialEq, Eq)]
pub struct OwnershipFenceGrant {
    /// SA that was fenced.
    pub sa: SaId,
    /// Exact destination-scoped authoritative ownership key.
    pub ownership_key: SessionOwnershipKey,
    /// Transition identity committed with the ownership record.
    pub transition_id: OwnershipTransitionId,
    /// Fingerprint committed with the transition.
    pub fingerprint: OwnershipTransitionFingerprint,
    /// Owner holding the granted fence.
    pub owner: ClusterNode,
    /// Monotonic fence token.
    pub fence: OwnershipFence,
}

impl fmt::Debug for OwnershipFenceGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OwnershipFenceGrant([redacted])")
    }
}

/// Request to publish the FIRST destination-scoped owner for one SA.
///
/// A responder installs an inbound SA — and may receive ESP on its
/// receiver-chosen SPI — before any ownership transition has occurred. RFC 4303
/// §2.1 states verbatim: "The SPI is an arbitrary 32-bit value that is used by a
/// receiver to identify the SA to which an incoming packet is bound." The
/// destination-scoped owner map must therefore admit a first, no-predecessor
/// publication for that SPI. (RFC 7296 §1.2 and §2.8 are the IKEv2 events that
/// produce such an SA — the first Child SA of the initial exchange and each
/// rekey's new SPI. That is a paraphrase of those sections, not a quotation.)
///
/// This request deliberately carries no resume, outbound-IV, counter, or
/// anti-replay evidence: no prior SA state is being resumed, so there is
/// nothing to attest. It also carries no predecessor owner or fence, because a
/// first activation has none. Everything that makes the transition
/// authoritative — the generation — is minted by the
/// [`OwnershipActivationAuthority`],
/// never by the caller.
#[derive(Clone, PartialEq, Eq)]
pub struct OwnershipActivationRequest {
    sa: SaId,
    ownership_key: SessionOwnershipKey,
    transition_id: OwnershipTransitionId,
    owner: ClusterNode,
    rule: SteeringRule,
}

impl OwnershipActivationRequest {
    /// Construct and validate a first-activation request for an ESP Child SA.
    ///
    /// `inbound_spi` is the receiver-chosen peer-to-local SPI used for ingress
    /// ownership and steering. There is no outbound SA binding ID because no
    /// outbound counter state is being resumed.
    pub fn new_esp(
        inbound_spi: u32,
        transition_id: OwnershipTransitionId,
        owner: ClusterNode,
        rule: SteeringRule,
        ownership_key: SessionOwnershipKey,
    ) -> Result<Self, IpsecLbError> {
        let request = Self {
            sa: SaId::Esp { spi: inbound_spi },
            ownership_key,
            transition_id,
            owner,
            rule,
        };
        validate_activation_request(&request)?;
        Ok(request)
    }

    /// Construct and validate a first-activation request for an IKE SA.
    pub fn new_ike(
        responder_spi: u64,
        transition_id: OwnershipTransitionId,
        owner: ClusterNode,
        rule: SteeringRule,
        ownership_key: SessionOwnershipKey,
    ) -> Result<Self, IpsecLbError> {
        let request = Self {
            sa: SaId::Ike { responder_spi },
            ownership_key,
            transition_id,
            owner,
            rule,
        };
        validate_activation_request(&request)?;
        Ok(request)
    }

    /// Return the SA receiving its first owner record.
    #[must_use]
    pub const fn sa(&self) -> SaId {
        self.sa
    }

    /// Return the exact destination-scoped ownership key.
    #[must_use]
    pub const fn ownership_key(&self) -> SessionOwnershipKey {
        self.ownership_key
    }

    /// Return the stable identity reused only for retries of this activation.
    #[must_use]
    pub const fn transition_id(&self) -> OwnershipTransitionId {
        self.transition_id
    }

    /// Return the cluster node that must already hold the birth record.
    #[must_use]
    pub const fn owner(&self) -> &ClusterNode {
        &self.owner
    }

    /// Return the steering rule retained for non-Host-XDP backends.
    #[must_use]
    pub const fn rule(&self) -> SteeringRule {
        self.rule
    }

    /// Return the datapath owner shard published into the owner map.
    #[must_use]
    pub const fn map_owner(&self) -> crate::ShardId {
        self.rule.owner
    }

    /// Hash the complete safety-critical activation into a stable fingerprint.
    ///
    /// The domain is distinct from every re-pin transition domain, so an
    /// activation record can never be recovered as a re-pin grant and a re-pin
    /// record can never be recovered as an activation grant.
    #[must_use]
    pub fn activation_fingerprint(&self) -> OwnershipTransitionFingerprint {
        let mut hasher = Sha256::new();
        hasher.update(b"opc-ipsec-lb/ownership-activation/v1-destination-scoped");
        hasher.update(self.transition_id.get().to_be_bytes());
        hash_sa(&mut hasher, self.sa);
        hash_bytes(&mut hasher, self.owner.as_str().as_bytes());
        hasher.update(self.rule.shard.get().to_be_bytes());
        hasher.update(self.rule.owner.get().to_be_bytes());
        hash_steer_key(&mut hasher, self.rule.key);
        hash_bytes(&mut hasher, &self.ownership_key.to_canonical_bytes());
        OwnershipTransitionFingerprint(hasher.finalize().into())
    }
}

impl fmt::Debug for OwnershipActivationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OwnershipActivationRequest([redacted])")
    }
}

/// Authoritative first-activation generation committed by the ownership store.
///
/// Only an activation authority can construct this grant. Its fence is a
/// projection of the store-minted, per-key monotonic fence token, so it is
/// strictly above the durable floor retained for that key — including the floor
/// left behind by a completed retirement.
#[derive(Clone, PartialEq, Eq)]
pub struct OwnershipActivationGrant {
    request: OwnershipActivationRequest,
    fence: OwnershipFence,
}

impl OwnershipActivationGrant {
    pub(crate) const fn new(request: OwnershipActivationRequest, fence: OwnershipFence) -> Self {
        Self { request, fence }
    }

    /// Borrow the exact activation this grant authorizes.
    #[must_use]
    pub const fn request(&self) -> &OwnershipActivationRequest {
        &self.request
    }

    /// Return the committed authoritative activation generation.
    #[must_use]
    pub const fn fence(&self) -> OwnershipFence {
        self.fence
    }
}

impl fmt::Debug for OwnershipActivationGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OwnershipActivationGrant([redacted])")
    }
}

/// Typed result of retiring one activation that never underwent a re-pin.
#[derive(Clone, PartialEq, Eq)]
pub enum OwnershipActivationRetirement {
    /// Host owner/fence state was removed and durable ownership was finalized.
    Finalized(OwnershipRetirementFinalizedProof),
    /// A strictly newer authoritative record won the key and was left alone.
    Superseded(OwnershipRetirementSupersededProof),
}

impl fmt::Debug for OwnershipActivationRetirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Finalized(proof) => f
                .debug_struct("OwnershipActivationRetirement::Finalized")
                .field("disposition", &proof.disposition())
                .finish(),
            Self::Superseded(_) => {
                f.write_str("OwnershipActivationRetirement::Superseded([redacted])")
            }
        }
    }
}

/// A `Retiring` activation rebuilt from durable state after process loss.
///
/// [`RePinCoordinator::retire_activation`] commits a durable `Retiring` record
/// before it calls steering. A caller that loses the in-memory request between
/// those two steps cannot replay the retirement, and the key stays refused for
/// activation forever. This value carries the exact request and `active_fence`
/// that replay needs, reconstructed by
/// [`crate::SessionStoreOwnershipFencer::recover_stranded_activation_retirement`]
/// and verified against the record's own activation fingerprint, so a
/// mis-supplied steering rule or owner is rejected rather than retired.
#[derive(Clone, PartialEq, Eq)]
pub struct StrandedActivationRetirement {
    request: OwnershipActivationRequest,
    active_fence: OwnershipFence,
}

impl StrandedActivationRetirement {
    pub(crate) const fn new(
        request: OwnershipActivationRequest,
        active_fence: OwnershipFence,
    ) -> Self {
        Self {
            request,
            active_fence,
        }
    }

    /// Borrow the exact activation request the stranded retirement replays.
    #[must_use]
    pub const fn request(&self) -> &OwnershipActivationRequest {
        &self.request
    }

    /// Return the exact committed activation fence the replay must pass.
    #[must_use]
    pub const fn active_fence(&self) -> OwnershipFence {
        self.active_fence
    }
}

impl fmt::Debug for StrandedActivationRetirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StrandedActivationRetirement([redacted])")
    }
}

/// Exact committed activation whose ownership and Host-XDP state may retire.
///
/// Construction is private to [`RePinCoordinator`]. The request binds the full
/// activation transition and destination-scoped key, not merely an SPI.
#[derive(Clone, PartialEq, Eq)]
pub struct OwnershipRetirementRequest {
    sa: SaId,
    ownership_key: SessionOwnershipKey,
    transition_id: OwnershipTransitionId,
    fingerprint: OwnershipTransitionFingerprint,
    owner: ClusterNode,
    active_fence: OwnershipFence,
    map_owner: crate::ShardId,
}

impl OwnershipRetirementRequest {
    pub(crate) fn from_committed(request: &RePinRequest, active_fence: OwnershipFence) -> Self {
        Self {
            sa: request.sa,
            ownership_key: request.ownership_key,
            transition_id: request.transition_id,
            fingerprint: request.ownership_fingerprint(),
            owner: request.new_owner.clone(),
            active_fence,
            map_owner: request.rule.owner,
        }
    }

    /// Bind the retirement to a committed first activation instead of a re-pin.
    ///
    /// The fingerprint comes from the activation domain, so this request can
    /// only match a store record that the activation boundary committed.
    pub(crate) fn from_activation(
        request: &OwnershipActivationRequest,
        active_fence: OwnershipFence,
    ) -> Self {
        Self {
            sa: request.sa(),
            ownership_key: request.ownership_key(),
            transition_id: request.transition_id(),
            fingerprint: request.activation_fingerprint(),
            owner: request.owner().clone(),
            active_fence,
            map_owner: request.map_owner(),
        }
    }

    /// Return the exact SA being retired.
    #[must_use]
    pub const fn sa(&self) -> SaId {
        self.sa
    }

    /// Return the destination-scoped ownership key being retired.
    #[must_use]
    pub const fn ownership_key(&self) -> SessionOwnershipKey {
        self.ownership_key
    }

    /// Return the activation transition being retired.
    #[must_use]
    pub const fn transition_id(&self) -> OwnershipTransitionId {
        self.transition_id
    }

    /// Return the exact activation request fingerprint.
    #[must_use]
    pub const fn fingerprint(&self) -> OwnershipTransitionFingerprint {
        self.fingerprint
    }

    /// Return the store owner that committed the activation.
    #[must_use]
    pub const fn owner(&self) -> &ClusterNode {
        &self.owner
    }

    /// Return the completed activation fence.
    #[must_use]
    pub const fn active_fence(&self) -> OwnershipFence {
        self.active_fence
    }

    /// Return the owner shard encoded in the active Host-XDP record.
    #[must_use]
    pub const fn map_owner(&self) -> crate::ShardId {
        self.map_owner
    }
}

impl fmt::Debug for OwnershipRetirementRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OwnershipRetirementRequest([redacted])")
    }
}

/// Opaque durable authority for retiring one exact active ownership record.
///
/// Only an SDK ownership authority can construct this grant. It carries the
/// higher store fence that revoked ordinary activation retry proofs and the
/// exact lower generation that Host-XDP is allowed to remove.
#[derive(Clone, PartialEq, Eq)]
pub struct OwnershipRetirementGrant {
    request: OwnershipRetirementRequest,
    retirement_fence: OwnershipFence,
}

/// Typed result of beginning one durable ownership retirement.
///
/// A strictly newer authoritative record supersedes the retired session's
/// activation. In that case the old saga must leave Host steering untouched
/// and durably record the opaque proof as finalized. This is what lets a
/// `Retiring` session converge after process loss between the session-level
/// cut and a later per-key retirement CAS.
#[derive(Clone, PartialEq, Eq)]
pub enum OwnershipRetirementAdmission {
    /// The exact active lineage is durably reserved under a higher fence and
    /// may proceed through Host cleanup.
    Granted(OwnershipRetirementGrant),
    /// A strictly newer authoritative ownership record won the key and must
    /// be left untouched.
    Superseded(OwnershipRetirementSupersededProof),
}

impl fmt::Debug for OwnershipRetirementAdmission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Granted(_) => f.write_str("OwnershipRetirementAdmission::Granted([redacted])"),
            Self::Superseded(_) => {
                f.write_str("OwnershipRetirementAdmission::Superseded([redacted])")
            }
        }
    }
}

/// Opaque proof that a strictly newer authoritative record superseded an old
/// session retirement before Host cleanup began.
///
/// Only an ownership authority can construct this value. The exact request and
/// observed fence remain private so callers cannot forge a skip-cleanup
/// verdict or leak correlation material through diagnostics.
#[derive(Clone, PartialEq, Eq)]
pub struct OwnershipRetirementSupersededProof {
    request: OwnershipRetirementRequest,
    authoritative_fence: OwnershipFence,
}

impl OwnershipRetirementSupersededProof {
    pub(crate) const fn new(
        request: OwnershipRetirementRequest,
        authoritative_fence: OwnershipFence,
    ) -> Self {
        Self {
            request,
            authoritative_fence,
        }
    }

    pub(crate) const fn request(&self) -> &OwnershipRetirementRequest {
        &self.request
    }

    pub(crate) const fn authoritative_fence(&self) -> OwnershipFence {
        self.authoritative_fence
    }
}

impl fmt::Debug for OwnershipRetirementSupersededProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OwnershipRetirementSupersededProof([redacted])")
    }
}

/// Opaque durable proof that Host cleanup completed before ownership deletion.
///
/// There are exactly two producers, both inside the SDK, and possessing a
/// retirement grant alone is deliberately insufficient to construct one:
///
/// * the session journal, for a multi-SA saga, and only after its exact ordered
///   `CleanupComplete` marker is majority-authoritatively stored — the marker
///   is what preserves cross-SA ordering across process loss;
/// * [`RePinCoordinator::retire_activation`], for a single activation that
///   never re-pinned. There is no cross-SA order to preserve there, so the
///   coordinator issues the proof directly after the steering backend has
///   proven both keyed maps absent, while still holding that key's operation
///   permit. Replaying the identical call after process loss converges,
///   because the durable record stays `Retiring` and every step is idempotent.
#[derive(Clone, PartialEq, Eq)]
pub struct OwnershipCleanupCompleteProof {
    grant: OwnershipRetirementGrant,
}

impl OwnershipCleanupCompleteProof {
    pub(crate) const fn new(grant: OwnershipRetirementGrant) -> Self {
        Self { grant }
    }

    /// Borrow the exact durable retirement grant covered by this marker.
    #[must_use]
    pub const fn grant(&self) -> &OwnershipRetirementGrant {
        &self.grant
    }
}

impl fmt::Debug for OwnershipCleanupCompleteProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OwnershipCleanupCompleteProof([redacted])")
    }
}

impl OwnershipRetirementGrant {
    pub(crate) const fn new(
        request: OwnershipRetirementRequest,
        retirement_fence: OwnershipFence,
    ) -> Self {
        Self {
            request,
            retirement_fence,
        }
    }

    /// Borrow the exact activation being retired.
    #[must_use]
    pub const fn request(&self) -> &OwnershipRetirementRequest {
        &self.request
    }

    /// Return the higher durable store fence that revoked activation.
    #[must_use]
    pub const fn retirement_fence(&self) -> OwnershipFence {
        self.retirement_fence
    }
}

impl fmt::Debug for OwnershipRetirementGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OwnershipRetirementGrant([redacted])")
    }
}

/// Result of finalizing a cleanup-complete ownership retirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OwnershipRetirementFinalization {
    /// The exact durable `Retiring` record was fenced-deleted by this call.
    Deleted,
    /// The exact record had already been deleted by an earlier ambiguous call.
    AlreadyDeleted,
    /// A strictly newer activation now owns the key and was left untouched.
    Superseded,
}

/// Opaque proof that cleanup-complete ownership finalization was attempted.
///
/// The SDK coordinator issues this only after the retirement authority returns
/// a typed deleted, already-deleted, or strictly-superseded verdict.
#[derive(Clone, PartialEq, Eq)]
pub struct OwnershipRetirementFinalizedProof {
    cleanup: OwnershipCleanupCompleteProof,
    disposition: OwnershipRetirementFinalization,
}

impl OwnershipRetirementFinalizedProof {
    fn new(
        cleanup: OwnershipCleanupCompleteProof,
        disposition: OwnershipRetirementFinalization,
    ) -> Self {
        Self {
            cleanup,
            disposition,
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        cleanup: OwnershipCleanupCompleteProof,
        disposition: OwnershipRetirementFinalization,
    ) -> Self {
        Self::new(cleanup, disposition)
    }

    /// Borrow the exact cleanup marker that authorized finalization.
    #[must_use]
    pub const fn cleanup(&self) -> &OwnershipCleanupCompleteProof {
        &self.cleanup
    }

    /// Return the typed finalization verdict.
    #[must_use]
    pub const fn disposition(&self) -> OwnershipRetirementFinalization {
        self.disposition
    }
}

impl fmt::Debug for OwnershipRetirementFinalizedProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnershipRetirementFinalizedProof")
            .field("disposition", &self.disposition)
            .finish_non_exhaustive()
    }
}

/// Host-cleaned retirement awaiting durable `CleanupComplete` publication.
///
/// This value is non-clone and has no public constructor. It retains the exact
/// Host operation permit until the journal marker and ownership finalization
/// complete, preventing a delayed activation from crossing the cleanup cut.
#[must_use = "pending retirement must be journaled or safely retried"]
pub struct PendingOwnershipRetirement {
    grant: OwnershipRetirementGrant,
    _permit: RePinSteeringOperationPermit,
}

impl PendingOwnershipRetirement {
    fn new(grant: OwnershipRetirementGrant, permit: RePinSteeringOperationPermit) -> Self {
        Self {
            grant,
            _permit: permit,
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        grant: OwnershipRetirementGrant,
        permit: RePinSteeringOperationPermit,
    ) -> Self {
        Self::new(grant, permit)
    }

    /// Borrow the exact retirement grant proven clean in Host-XDP.
    #[must_use]
    pub const fn grant(&self) -> &OwnershipRetirementGrant {
        &self.grant
    }
}

impl fmt::Debug for PendingOwnershipRetirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PendingOwnershipRetirement([redacted])")
    }
}

pub(crate) enum OwnershipRetirementStep {
    CleanupPending(PendingOwnershipRetirement),
    Superseded(OwnershipRetirementSupersededProof),
}

/// Evidence presented when resuming work after ownership was committed.
///
/// The fields are construction-private because only a coordinator that has
/// checked a matching fence grant may issue this proof. The proof is still
/// treated as untrusted on retry: [`OwnershipFencer::validate_retry_proof`]
/// must match its SA, owner, and exact fence against authoritative state.
#[derive(Clone, PartialEq, Eq)]
pub struct OwnershipRetryProof {
    sa: SaId,
    ownership_key: SessionOwnershipKey,
    transition_id: OwnershipTransitionId,
    fingerprint: OwnershipTransitionFingerprint,
    owner: ClusterNode,
    fence: OwnershipFence,
}

impl fmt::Debug for OwnershipRetryProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OwnershipRetryProof([redacted])")
    }
}

impl OwnershipRetryProof {
    pub(crate) fn from_grant(grant: &OwnershipFenceGrant) -> Self {
        Self {
            sa: grant.sa,
            ownership_key: grant.ownership_key,
            transition_id: grant.transition_id,
            fingerprint: grant.fingerprint,
            owner: grant.owner.clone(),
            fence: grant.fence,
        }
    }

    /// Return the SA covered by this retry proof.
    #[must_use]
    pub const fn sa(&self) -> SaId {
        self.sa
    }

    /// Return the destination-scoped ownership key covered by this proof.
    #[must_use]
    pub const fn ownership_key(&self) -> SessionOwnershipKey {
        self.ownership_key
    }

    /// Return the ownership transition covered by this proof.
    #[must_use]
    pub const fn transition_id(&self) -> OwnershipTransitionId {
        self.transition_id
    }

    /// Return the complete request fingerprint covered by this proof.
    #[must_use]
    pub const fn fingerprint(&self) -> OwnershipTransitionFingerprint {
        self.fingerprint
    }

    /// Return the owner that must still hold the authoritative fence.
    #[must_use]
    pub fn owner(&self) -> &ClusterNode {
        &self.owner
    }

    /// Return the exact committed fence covered by this proof.
    #[must_use]
    pub const fn fence(&self) -> OwnershipFence {
        self.fence
    }
}

/// Audit event kind emitted by the re-pin coordinator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RePinAuditEventKind {
    /// A validated re-pin attempt is about to mutate ownership.
    Attempt,
    /// Ownership was fenced to the new owner.
    Fenced,
    /// Steering override was installed.
    SteeringInstalled,
    /// Exact destination-scoped steering was durably retired.
    SteeringRetired,
    /// A first destination-scoped owner was published for a key that had no
    /// predecessor owner.
    ///
    /// Activation events set `previous_owner == new_owner` because no ownership
    /// was taken from another node.
    Activated,
    /// Re-pin failed before a verified ownership grant was available.
    ///
    /// Recoverable post-commit failures are returned immediately as
    /// [`RePinPartialFailure`] and deliberately do not wait on best-effort
    /// failure auditing, which could strand the retry state.
    Failed,
}

/// Domain separator for the audit correlation digest.
///
/// Keeps the correlation identity from colliding with any other SHA-256 use in
/// this crate, and versions the preimage so a future change is a new identity
/// rather than a silent reinterpretation.
const REPIN_AUDIT_CORRELATION_DOMAIN: &[u8] = b"opc-ipsec-lb/repin-audit-correlation/v1";

/// Non-reversible correlation identity for re-pin audit records.
///
/// Every event the coordinator emits for one logical transition carries the same
/// value, so a sink can group, deduplicate, and follow a transition across
/// `Attempt` → `Fenced` → `SteeringInstalled` exactly as it could with the raw
/// [`OwnershipTransitionId`] — but the value confers no capability. It is
/// `SHA-256(domain || transition_id)`, so it is safe to log, index, and export.
///
/// Recovering the transition identity from it would require inverting SHA-256 or
/// searching the 128-bit preimage space, which is exactly the unpredictability
/// [`OwnershipTransitionId`] already mandates. That mandate is load-bearing
/// here, and the residual risk is worth stating in numbers rather than as
/// "brute-forceable". The preimage is the 39-byte domain plus the 16-byte
/// identity — 55 bytes, which is exactly one 64-byte SHA-256 block, the
/// cheapest per-guess cost the primitive admits. At roughly 2 × 10^10
/// SHA-256/s, one commodity GPU, a deployment that ignores the mandate is
/// inverted in: under a second for a 32-bit counter; under a minute for a
/// sequential counter below 2^40; about fifteen seconds for millisecond
/// timestamps spanning a decade (about 2^38 values). For the two failure modes
/// [`OwnershipTransitionId`] names — a counter and a timestamp — the search is
/// seconds of work, not a theoretical weakness.
///
/// The domain separator is a compile-time constant with no per-deployment salt,
/// so one precomputed table inverts every deployment's logs at once. This digest
/// defends against reversing a correctly minted identity; it is not a defence
/// against a minting policy that ignores the CSPRNG requirement.
///
/// A keyed MAC would remove the offline search entirely, and was still rejected:
/// an ephemeral key breaks the cross-restart and cross-node correlation this
/// value exists to provide, and a shared key would have to reach every
/// coordinator and every sink. [`RePinCoordinator::new`] takes no key, so
/// adding one is a distribution problem rather than a hashing one. (The crate
/// does run a rotating keyed MAC where distribution is solved — see
/// [`crate::IkeCookieGate`] — so the obstacle is the channel, not the
/// primitive.)
///
/// An operator holding the raw identity can compute the correlation identity
/// with [`Self::for_transition`] to find the matching records; the reverse
/// direction does not exist by design.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct RePinAuditCorrelationId([u8; 32]);

impl RePinAuditCorrelationId {
    /// Derive the audit correlation identity for a transition.
    ///
    /// Deterministic: the same transition always yields the same value, which is
    /// what makes sink-side deduplication and cross-event correlation work.
    #[must_use]
    pub fn for_transition(transition_id: OwnershipTransitionId) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(REPIN_AUDIT_CORRELATION_DOMAIN);
        hasher.update(transition_id.get().to_be_bytes());
        Self(hasher.finalize().into())
    }

    /// Return the correlation digest bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Display for RePinAuditCorrelationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for RePinAuditCorrelationId {
    /// Printed in full, deliberately: unlike the transition identity this value
    /// is not a secret, and a correlation identity that cannot be read from a
    /// log is useless.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RePinAuditCorrelationId({self})")
    }
}

/// Redaction-safe re-pin audit event.
///
/// The non-disclosure guarantee is carried by the *type of each field*, not by
/// the struct: `correlation_id` cannot hold a transition identity, but every
/// field here is public, so adding a field of type [`OwnershipTransitionId`]
/// would reopen the disclosure path for any sink that reads it. The hand-written
/// [`fmt::Debug`] below would not catch that either — it lists fields
/// explicitly, and [`OwnershipTransitionId`]'s own `Debug` is redacted, so a new
/// field would render as `[redacted]` while the field itself still hands the raw
/// value to a sink. `Debug` was never the only way out.
#[derive(Clone, PartialEq, Eq)]
pub struct RePinAuditEvent {
    /// Event kind.
    pub kind: RePinAuditEventKind,
    /// SA being re-pinned.
    pub sa: SaId,
    /// Stable, non-reversible transition correlation identity.
    ///
    /// This is deliberately **not** the [`OwnershipTransitionId`]. That value
    /// authorizes retirement while the transition is live, and an audit sink
    /// that logs its correlation key — the ordinary thing to do with one — would
    /// turn every reader of that log into a holder of a per-SA teardown
    /// capability. See [`RePinAuditCorrelationId`].
    ///
    /// This field is not an idempotency key by itself or when paired only with
    /// [`RePinAuditEventKind`]; sinks deduplicate the complete event so distinct
    /// failed attempts retain their failure codes.
    pub correlation_id: RePinAuditCorrelationId,
    /// Previous owner.
    pub previous_owner: ClusterNode,
    /// New owner.
    pub new_owner: ClusterNode,
    /// Fence token when one has been granted.
    pub fence: Option<OwnershipFence>,
    /// This is deliberately false for coordinator-emitted events. Packet-flow
    /// evidence must be injected separately by the lab/product dataplane.
    pub forwarding_proven: bool,
    /// Stable failure code for failed attempts.
    pub failure_code: Option<&'static str>,
}

impl fmt::Debug for RePinAuditEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RePinAuditEvent")
            .field("kind", &self.kind)
            .field("sa", &"[redacted]")
            .field("correlation_id", &self.correlation_id)
            .field("previous_owner", &"[redacted]")
            .field("new_owner", &"[redacted]")
            .field("fence_present", &self.fence.is_some())
            .field("forwarding_proven", &self.forwarding_proven)
            .field("failure_code", &self.failure_code)
            .finish()
    }
}

impl RePinAuditEvent {
    fn attempt(request: &RePinRequest) -> Self {
        Self {
            kind: RePinAuditEventKind::Attempt,
            sa: request.sa,
            correlation_id: RePinAuditCorrelationId::for_transition(request.transition_id),
            previous_owner: request.previous_owner.clone(),
            new_owner: request.new_owner.clone(),
            fence: None,
            forwarding_proven: false,
            failure_code: None,
        }
    }

    fn fenced(request: &RePinRequest, fence: OwnershipFence) -> Self {
        Self {
            kind: RePinAuditEventKind::Fenced,
            sa: request.sa,
            correlation_id: RePinAuditCorrelationId::for_transition(request.transition_id),
            previous_owner: request.previous_owner.clone(),
            new_owner: request.new_owner.clone(),
            fence: Some(fence),
            forwarding_proven: false,
            failure_code: None,
        }
    }

    fn steering_installed(request: &RePinRequest, fence: OwnershipFence) -> Self {
        Self {
            kind: RePinAuditEventKind::SteeringInstalled,
            sa: request.sa,
            correlation_id: RePinAuditCorrelationId::for_transition(request.transition_id),
            previous_owner: request.previous_owner.clone(),
            new_owner: request.new_owner.clone(),
            fence: Some(fence),
            forwarding_proven: false,
            failure_code: None,
        }
    }

    fn steering_retired(grant: &OwnershipRetirementGrant) -> Self {
        let request = grant.request();
        Self {
            kind: RePinAuditEventKind::SteeringRetired,
            sa: request.sa(),
            correlation_id: RePinAuditCorrelationId::for_transition(request.transition_id()),
            previous_owner: request.owner().clone(),
            new_owner: request.owner().clone(),
            fence: Some(grant.retirement_fence()),
            forwarding_proven: false,
            failure_code: None,
        }
    }

    fn activation_attempt(request: &OwnershipActivationRequest) -> Self {
        Self {
            kind: RePinAuditEventKind::Attempt,
            sa: request.sa(),
            correlation_id: RePinAuditCorrelationId::for_transition(request.transition_id()),
            previous_owner: request.owner().clone(),
            new_owner: request.owner().clone(),
            fence: None,
            forwarding_proven: false,
            failure_code: None,
        }
    }

    fn activated(request: &OwnershipActivationRequest, fence: OwnershipFence) -> Self {
        Self {
            kind: RePinAuditEventKind::Activated,
            sa: request.sa(),
            correlation_id: RePinAuditCorrelationId::for_transition(request.transition_id()),
            previous_owner: request.owner().clone(),
            new_owner: request.owner().clone(),
            fence: Some(fence),
            forwarding_proven: false,
            failure_code: None,
        }
    }

    fn activation_failed(request: &OwnershipActivationRequest, error: &IpsecLbError) -> Self {
        Self {
            kind: RePinAuditEventKind::Failed,
            sa: request.sa(),
            correlation_id: RePinAuditCorrelationId::for_transition(request.transition_id()),
            previous_owner: request.owner().clone(),
            new_owner: request.owner().clone(),
            fence: None,
            forwarding_proven: false,
            failure_code: Some(error_code(error)),
        }
    }

    fn failed(request: &RePinRequest, fence: Option<OwnershipFence>, error: &IpsecLbError) -> Self {
        Self {
            kind: RePinAuditEventKind::Failed,
            sa: request.sa,
            correlation_id: RePinAuditCorrelationId::for_transition(request.transition_id),
            previous_owner: request.previous_owner.clone(),
            new_owner: request.new_owner.clone(),
            fence,
            forwarding_proven: false,
            failure_code: Some(error_code(error)),
        }
    }
}

/// Injected proof that forwarded packets were observed after a re-pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ForwardingProof {
    sa: SaId,
    fence: OwnershipFence,
    observed_packets: NonZeroU64,
}

impl ForwardingProof {
    /// Build a packet-flow proof from an external dataplane observation.
    pub fn new(
        sa: SaId,
        fence: OwnershipFence,
        observed_packets: u64,
    ) -> Result<Self, IpsecLbError> {
        let Some(observed_packets) = NonZeroU64::new(observed_packets) else {
            return Err(IpsecLbError::forwarding_proof_rejected(
                "observed packet count must be non-zero",
            ));
        };
        Ok(Self {
            sa,
            fence,
            observed_packets,
        })
    }

    /// Return the SA covered by this proof.
    #[must_use]
    pub const fn sa(self) -> SaId {
        self.sa
    }

    /// Return the fence covered by this proof.
    #[must_use]
    pub const fn fence(self) -> OwnershipFence {
        self.fence
    }

    /// Return observed packet count.
    #[must_use]
    pub const fn observed_packets(self) -> u64 {
        self.observed_packets.get()
    }
}

/// Result of a fenced re-pin and steering install.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RePinOutcome {
    sa: SaId,
    fence: OwnershipFence,
    rule: SteeringRule,
    forwarding_proven: bool,
}

impl RePinOutcome {
    fn new(sa: SaId, fence: OwnershipFence, rule: SteeringRule) -> Self {
        Self {
            sa,
            fence,
            rule,
            forwarding_proven: false,
        }
    }

    /// Return the ownership fence used for this re-pin.
    #[must_use]
    pub const fn fence(self) -> OwnershipFence {
        self.fence
    }

    /// Return the steering rule installed for this re-pin.
    #[must_use]
    pub const fn rule(self) -> SteeringRule {
        self.rule
    }

    /// True only after an external forwarding proof has been injected.
    #[must_use]
    pub const fn forwarding_proven(self) -> bool {
        self.forwarding_proven
    }

    /// Attach external dataplane proof to the outcome.
    pub fn with_forwarding_proof(mut self, proof: ForwardingProof) -> Result<Self, IpsecLbError> {
        if proof.sa != self.sa {
            return Err(IpsecLbError::forwarding_proof_rejected(
                "proof SA does not match re-pin outcome",
            ));
        }
        if proof.fence != self.fence {
            return Err(IpsecLbError::forwarding_proof_rejected(
                "proof fence does not match re-pin outcome",
            ));
        }
        self.forwarding_proven = true;
        Ok(self)
    }
}

/// First incomplete operation after an authoritative ownership commit.
///
/// Retry resumes at this exact stage and never repeats an earlier successful
/// stage. In particular, a final audit retry cannot reinstall steering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RePinRetryStage {
    /// Record the audit event that ownership was fenced.
    FencedAudit,
    /// Install the steering override.
    SteeringInstall,
    /// Record the audit event that steering was installed.
    SteeringAudit,
}

/// Recoverable state returned when ownership committed but re-pin did not
/// finish.
///
/// Construction is private to prevent callers from selecting a later retry
/// stage and skipping a required side effect. Pass the value back to
/// [`RePinCoordinator::retry`] unchanged. The included ownership proof is
/// always validated by the fencer before retry performs an audit or steering
/// mutation. Callers that need cancellation safety should clone and retain
/// [`RePinPartialFailure::request`] before starting `retry`; replaying that
/// request through [`RePinCoordinator::repin`] recovers the exact current
/// ownership grant before attempting another fence.
#[must_use]
#[derive(PartialEq, Eq)]
pub struct RePinPartialFailure {
    request: RePinRequest,
    retry_proof: OwnershipRetryProof,
    resume_at: RePinRetryStage,
    publication_requirement: EspCounterProofRequirement,
    cause: IpsecLbError,
}

impl fmt::Debug for RePinPartialFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RePinPartialFailure")
            .field("resume_at", &self.resume_at)
            .field("cause", &self.cause)
            .finish_non_exhaustive()
    }
}

impl RePinPartialFailure {
    fn new(
        request: RePinRequest,
        retry_proof: OwnershipRetryProof,
        resume_at: RePinRetryStage,
        publication_requirement: EspCounterProofRequirement,
        cause: IpsecLbError,
    ) -> Self {
        Self {
            request,
            retry_proof,
            resume_at,
            publication_requirement,
            cause,
        }
    }

    /// Return the operation that retry will attempt first.
    #[must_use]
    pub const fn resume_at(&self) -> RePinRetryStage {
        self.resume_at
    }

    /// Return the error that interrupted the latest attempt.
    #[must_use]
    pub const fn cause(&self) -> &IpsecLbError {
        &self.cause
    }

    /// Return the committed ownership fence.
    #[must_use]
    pub const fn fence(&self) -> OwnershipFence {
        self.retry_proof.fence()
    }

    /// Return the proof that retry will validate against authoritative state.
    #[must_use]
    pub const fn retry_proof(&self) -> &OwnershipRetryProof {
        &self.retry_proof
    }

    /// Return the original request for explicit cancellation-safe retention.
    ///
    /// The partial itself remains single-use. Clone this request before
    /// starting [`RePinCoordinator::retry`] when the retry future may be
    /// cancelled, then pass the retained clone to [`RePinCoordinator::repin`]
    /// to recover authoritative ownership state.
    #[must_use]
    pub const fn request(&self) -> &RePinRequest {
        &self.request
    }

    fn with_cause(mut self, cause: IpsecLbError) -> Self {
        self.cause = cause;
        self
    }
}

/// Failure returned by re-pin coordination.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum RePinError {
    /// No matching, trustworthy ownership grant was available to issue a
    /// retry proof.
    ///
    /// This includes a malformed grant returned by a fencer. Such a fencer may
    /// have changed external state, but the coordinator cannot safely trust or
    /// issue a proof for that unverified result. A retained request may be
    /// replayed: `repin` always performs authoritative recovery before trying
    /// another ownership mutation.
    #[error("re-pin failed before a verifiable ownership commit: {0}")]
    BeforeOwnershipCommit(#[source] IpsecLbError),
    /// Ownership committed at the carried fence and remaining work can be
    /// resumed through [`RePinCoordinator::retry`].
    #[error("re-pin is incomplete after ownership commit")]
    AfterOwnershipCommit(Box<RePinPartialFailure>),
}

impl RePinError {
    /// Return the underlying port or validation error.
    #[must_use]
    pub const fn cause(&self) -> &IpsecLbError {
        match self {
            Self::BeforeOwnershipCommit(cause) => cause,
            Self::AfterOwnershipCommit(partial) => partial.cause(),
        }
    }

    /// Consume the error and return recoverable post-commit state, if any.
    #[must_use]
    pub fn into_partial(self) -> Option<RePinPartialFailure> {
        match self {
            Self::BeforeOwnershipCommit(_) => None,
            Self::AfterOwnershipCommit(partial) => Some(*partial),
        }
    }
}

/// Coordinates audited, fenced re-pin before steering override installation.
#[derive(Debug, Clone)]
pub struct RePinCoordinator<B, F, O, A> {
    steering: B,
    fencer: F,
    ownership: O,
    audit: A,
    esp_counter_authority: Option<EspCounterResumeAuthority>,
    #[cfg(test)]
    accept_test_counter_proof: bool,
    #[cfg(test)]
    reject_test_first_publication_guard: bool,
    #[cfg(test)]
    reject_test_first_publication_validation_once: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// In-memory proof material for one coordinator lifetime.
///
/// Keeping the proof set and independently derived live targets together
/// prevents a partially configured coordinator from treating a durable SA ID
/// as authority. Neither member is serialized by the session journal.
#[derive(Clone)]
struct EspCounterResumeAuthority {
    proofs: EspCounterResumeProofSet,
    targets: OutboundEspCounterTargetSet,
}

impl fmt::Debug for EspCounterResumeAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EspCounterResumeAuthority(<redacted>)")
    }
}

impl<B, F, O, A> RePinCoordinator<B, F, O, A>
where
    B: RePinSteeringBackend,
    F: OwnershipFencer,
    O: OwnershipSource,
    A: RePinAuditSink,
{
    /// Build a coordinator from explicit ports.
    ///
    /// Counter-based ESP re-pin is fail-closed until
    /// [`Self::with_esp_counter_resume_receipt`] installs both opaque SDK XFRM
    /// apply/readback evidence and the independently derived live actor target.
    /// IKE counter and random-IV evidence remain product-owned because this
    /// coordinator does not own the IKE state machine.
    #[must_use]
    pub fn new(steering: B, fencer: F, ownership: O, audit: A) -> Self {
        Self {
            steering,
            fencer,
            ownership,
            audit,
            esp_counter_authority: None,
            #[cfg(test)]
            accept_test_counter_proof: false,
            #[cfg(test)]
            reject_test_first_publication_guard: false,
            #[cfg(test)]
            reject_test_first_publication_validation_once: std::sync::Arc::new(
                std::sync::atomic::AtomicBool::new(false),
            ),
        }
    }

    /// Install one opaque receipt and live target for one ESP transition.
    ///
    /// Both values must be produced from the same intended
    /// `InstalledOutboundSaBinding`: the receipt comes from the namespace-bound
    /// apply/readback operation, while the target is derived independently
    /// from that live binding. A recovered receipt cannot authorize a new
    /// ownership mutation.
    #[must_use]
    pub fn with_esp_counter_resume_receipt(
        mut self,
        receipt: AppliedEspCounterReceipt,
        target: OutboundEspCounterTarget,
    ) -> Self {
        self.esp_counter_authority = Some(EspCounterResumeAuthority {
            proofs: EspCounterResumeProofSet::single(receipt),
            targets: OutboundEspCounterTargetSet::single(target),
        });
        self
    }

    /// Install bounded proof and live-target sets for a multi-SA session plan.
    ///
    /// Construction of each set rejects duplicate durable bindings. Validation
    /// also requires an exact target lookup for every counter-based ESP request
    /// before consulting its receipt.
    #[must_use]
    pub fn with_esp_counter_resume_proof_set(
        mut self,
        proofs: EspCounterResumeProofSet,
        targets: OutboundEspCounterTargetSet,
    ) -> Self {
        self.esp_counter_authority = Some(EspCounterResumeAuthority { proofs, targets });
        self
    }

    #[cfg(test)]
    pub(crate) fn with_test_applied_esp_counter_proof(mut self) -> Self {
        self.accept_test_counter_proof = true;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_test_counter_advance_before_first_publication(mut self) -> Self {
        self.reject_test_first_publication_guard = true;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_test_transient_first_publication_validation_failure(self) -> Self {
        self.reject_test_first_publication_validation_once
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self
    }

    /// Validate resume evidence and the target-shard binding, recover or fence
    /// ownership, audit the transition, and install the steering override.
    ///
    /// Recovery is checked before mutation, making a cloned request safe to
    /// replay when cancellation or an ambiguous fencer result may have hidden
    /// a committed grant. A recovered transition resumes at the fenced-audit
    /// stage with the exact current fence.
    pub async fn repin(&self, request: RePinRequest) -> Result<RePinOutcome, RePinError> {
        validate_request(&request).map_err(RePinError::BeforeOwnershipCommit)?;
        request
            .resume
            .validate_for_repin(request.sa)
            .map_err(RePinError::BeforeOwnershipCommit)?;
        let permit = self
            .steering
            .acquire_repin_permit(request.ownership_key)
            .await
            .map_err(RePinError::BeforeOwnershipCommit)?;
        self.validate_target_owner(&request)
            .await
            .map_err(RePinError::BeforeOwnershipCommit)?;

        let fence_request = OwnershipFenceRequest {
            sa: request.sa,
            ownership_key: request.ownership_key,
            transition_id: request.transition_id,
            fingerprint: request.ownership_fingerprint(),
            previous_fence: request.previous_fence,
            previous_owner: request.previous_owner.clone(),
            new_owner: request.new_owner.clone(),
        };
        match self.fencer.recover_fence_grant(&fence_request).await {
            Ok(Some(grant)) => {
                return self.continue_from_grant(request, grant, true, permit).await;
            }
            Ok(None) => {}
            Err(error) => return Err(RePinError::BeforeOwnershipCommit(error)),
        }

        // A caller-declared ESP value cannot authorize the ownership mutation.
        // Require an exact SDK adapter receipt and repeat the target-owner read
        // after that awaited GETSA so no stale shard snapshot reaches fencing.
        self.validate_esp_counter_proof(
            &request,
            EspCounterProofRequirement::BeforeOwnershipCommit,
        )
        .await
        .map_err(RePinError::BeforeOwnershipCommit)?;
        self.validate_target_owner(&request)
            .await
            .map_err(RePinError::BeforeOwnershipCommit)?;

        self.audit
            .record_repin(RePinAuditEvent::attempt(&request))
            .await
            .map_err(RePinError::BeforeOwnershipCommit)?;

        let grant = match self.fencer.fence_sa_owner(fence_request.clone()).await {
            Ok(grant) => grant,
            Err(error) => match self.fencer.recover_fence_grant(&fence_request).await {
                Ok(Some(grant)) => grant,
                Ok(None) => {
                    record_failure(&self.audit, &request, None, &error).await;
                    return Err(RePinError::BeforeOwnershipCommit(error));
                }
                Err(recovery_error) => {
                    record_failure(&self.audit, &request, None, &recovery_error).await;
                    return Err(RePinError::BeforeOwnershipCommit(recovery_error));
                }
            },
        };

        self.continue_from_grant(request, grant, false, permit)
            .await
    }

    async fn continue_from_grant(
        &self,
        request: RePinRequest,
        grant: OwnershipFenceGrant,
        recovered: bool,
        permit: RePinSteeringOperationPermit,
    ) -> Result<RePinOutcome, RePinError> {
        // Do not trust the fencer port blindly: a grant for a different SA or a
        // different owner would install a steering override toward the wrong
        // node. Reject it before any steering mutation.
        validate_grant_matches(&request, &grant).map_err(RePinError::BeforeOwnershipCommit)?;

        let retry_proof = OwnershipRetryProof::from_grant(&grant);
        let publication_requirement = if recovered {
            EspCounterProofRequirement::CommittedRecovery
        } else {
            EspCounterProofRequirement::BeforeFirstPublication
        };
        // A shape-matching successful grant is post-commit by the fencer port
        // contract, but it is not enough to emit an authoritative Fenced audit
        // event. Confirm its exact store-backed fence first. Preserve the
        // single-use retry state on a transient or stale read: retry validates
        // again before any side effect, while a forged proof remains inert.
        if let Err(error) = self.fencer.validate_retry_proof(&retry_proof).await {
            return Err(RePinError::AfterOwnershipCommit(Box::new(
                RePinPartialFailure::new(
                    request,
                    retry_proof,
                    RePinRetryStage::FencedAudit,
                    publication_requirement,
                    error,
                ),
            )));
        }
        if let Err(error) = self
            .validate_esp_counter_proof(&request, publication_requirement)
            .await
        {
            return Err(RePinError::AfterOwnershipCommit(Box::new(
                RePinPartialFailure::new(
                    request,
                    retry_proof,
                    RePinRetryStage::FencedAudit,
                    publication_requirement,
                    error,
                ),
            )));
        }
        self.continue_committed(
            request,
            retry_proof,
            RePinRetryStage::FencedAudit,
            publication_requirement,
            permit,
        )
        .await
    }

    /// Resume a re-pin that stopped after ownership was authoritatively
    /// committed.
    ///
    /// Static safety checks and the target-shard binding are checked again.
    /// Before any audit or steering side effect, the fencer must also confirm
    /// that the proof's exact SA, owner, and fence are still authoritative.
    pub async fn retry(&self, partial: RePinPartialFailure) -> Result<RePinOutcome, RePinError> {
        if let Err(error) = self.validate_pre_commit(&partial.request).await {
            return Err(RePinError::AfterOwnershipCommit(Box::new(
                partial.with_cause(error),
            )));
        }

        if partial.retry_proof.sa != partial.request.sa
            || partial.retry_proof.ownership_key != partial.request.ownership_key
            || partial.retry_proof.transition_id != partial.request.transition_id
            || partial.retry_proof.fingerprint != partial.request.ownership_fingerprint()
            || partial.retry_proof.owner != partial.request.new_owner
        {
            return Err(RePinError::AfterOwnershipCommit(Box::new(
                partial.with_cause(IpsecLbError::ownership_conflict(
                    "retry proof does not match the original SA and new owner",
                )),
            )));
        }

        let permit = match self
            .steering
            .acquire_repin_permit(partial.request.ownership_key)
            .await
        {
            Ok(permit) => permit,
            Err(error) => {
                return Err(RePinError::AfterOwnershipCommit(Box::new(
                    partial.with_cause(error),
                )));
            }
        };

        // `continue_committed` performs the one authoritative proof read before
        // any resumed side effect. Do not pre-read here: fault-point contracts
        // and store-backed authorities must observe exactly one validation.
        self.continue_committed(
            partial.request,
            partial.retry_proof,
            partial.resume_at,
            partial.publication_requirement,
            permit,
        )
        .await
    }

    /// Revalidate and idempotently reconcile one previously completed re-pin.
    ///
    /// This boundary is deliberately read-only with respect to ownership: it
    /// requires recovery of the exact committed transition, verifies its
    /// owner, fence, transition ID, and complete request fingerprint, and then
    /// repeats the exact steering install under the backend's idempotency
    /// contract. It never calls [`OwnershipFencer::fence_sa_owner`] and emits no
    /// new transition audit events. Session-level recovery uses this before
    /// mutating a later SA and again before reporting terminal success, which
    /// detects direct per-SA coordinator use that displaced an earlier prefix.
    pub async fn reconcile_committed(
        &self,
        request: &RePinRequest,
        expected_fence: OwnershipFence,
    ) -> Result<RePinOutcome, IpsecLbError> {
        let permit = self
            .steering
            .acquire_repin_permit(request.ownership_key)
            .await?;
        let outcome = self
            .validate_committed_under_permit(request, expected_fence)
            .await?;
        let counter_guard = self
            .acquire_esp_counter_publication_guard(
                request,
                EspCounterProofRequirement::CommittedRecovery,
            )
            .await?;
        let counter_publication_required = counter_guard.is_some();
        // Keep the actor mutation gate live across the final ownership read so
        // neither authority can drift before the cancellation-safe Host cut.
        self.validate_target_owner(request).await?;
        let permit = match counter_guard {
            Some(guard) => permit.bind_esp_counter_publication_guard(guard)?,
            None => permit,
        };
        let permit = self
            .steering
            .apply_fenced_repin(RePinSteeringUpdate::new(request, expected_fence), permit)
            .await?;
        if permit.has_esp_counter_publication_guard() {
            return Err(IpsecLbError::adapter_contract_violation(
                "repin_backend_returned_unconsumed_counter_guard",
            ));
        }
        if counter_publication_required && !permit.counter_publication_authorized() {
            return Err(IpsecLbError::adapter_contract_violation(
                "repin_backend_returned_unauthorized_counter_publication",
            ));
        }
        Ok(outcome)
    }

    /// Validate one previously completed re-pin without any mutation.
    ///
    /// This performs authoritative recovery and exact retry-proof validation
    /// for the owner, fence, transition ID, and complete request fingerprint,
    /// then rechecks the target shard owner. It never fences ownership,
    /// installs or removes steering, or records an audit event. Session-level
    /// recovery calls this for the whole completed prefix only after every
    /// steering repair has finished, establishing a mutation-free validation
    /// sweep before a later SA mutation or terminal result.
    pub async fn validate_committed(
        &self,
        request: &RePinRequest,
        expected_fence: OwnershipFence,
    ) -> Result<RePinOutcome, IpsecLbError> {
        let _permit = self
            .steering
            .acquire_repin_permit(request.ownership_key)
            .await?;
        self.validate_committed_under_permit(request, expected_fence)
            .await
    }

    async fn validate_committed_under_permit(
        &self,
        request: &RePinRequest,
        expected_fence: OwnershipFence,
    ) -> Result<RePinOutcome, IpsecLbError> {
        self.validate_pre_commit(request).await?;
        let fence_request = OwnershipFenceRequest {
            sa: request.sa,
            ownership_key: request.ownership_key,
            transition_id: request.transition_id,
            fingerprint: request.ownership_fingerprint(),
            previous_fence: request.previous_fence,
            previous_owner: request.previous_owner.clone(),
            new_owner: request.new_owner.clone(),
        };
        let grant = self
            .fencer
            .recover_fence_grant(&fence_request)
            .await?
            .ok_or_else(|| {
                IpsecLbError::ownership_conflict(
                    "completed re-pin has no exact authoritative ownership grant",
                )
            })?;
        validate_grant_matches(request, &grant)?;
        if grant.fence != expected_fence {
            return Err(IpsecLbError::ownership_conflict(
                "completed re-pin fence does not match durable progress",
            ));
        }
        let proof = OwnershipRetryProof::from_grant(&grant);
        self.fencer.validate_retry_proof(&proof).await?;
        self.validate_target_owner(request).await?;
        self.validate_esp_counter_proof(request, EspCounterProofRequirement::CommittedRecovery)
            .await?;
        Ok(RePinOutcome::new(request.sa, grant.fence, request.rule))
    }

    /// Publish the FIRST destination-scoped owner for a newly established SA.
    ///
    /// This is the no-predecessor twin of [`Self::repin`]. It exists because a
    /// responder's inbound SA is reachable on its receiver-chosen SPI from the
    /// moment it is installed, before any ownership transition has happened, so
    /// a destination-scoped owner map has to admit a first publication.
    ///
    /// # Authority
    ///
    /// The caller supplies no generation. The activation authority reads the
    /// authoritative birth record for the exact
    /// [`SessionOwnershipKey`] and mints
    /// the generation from the store's own per-key monotonic fence, which sits
    /// strictly above the durable floor retained for that key — including the
    /// floor a completed retirement left behind. Absence from the datapath maps
    /// is never treated as evidence that a key was never activated.
    ///
    /// Activation is **not** an upsert. A key with no authoritative birth
    /// record fails closed with [`IpsecLbError::NotFound`], so replaying a
    /// stale request cannot resurrect an SA whose record was retired away.
    ///
    /// # Idempotency and cancellation
    ///
    /// Repeating the identical request is safe: the authority recovers the
    /// already-committed grant instead of minting a second generation, and the
    /// steering backend converges the same owner/generation pair. A cancelled
    /// call publishes no partial state — Host-XDP retains the operation permit
    /// inside its blocking mutation and proves exact readback before reporting
    /// success.
    pub async fn activate(
        &self,
        request: &OwnershipActivationRequest,
    ) -> Result<RePinOutcome, IpsecLbError>
    where
        F: OwnershipActivationAuthority,
    {
        validate_activation_request(request)?;
        // Host-XDP checks its per-key operation stripe for poison both before
        // and after taking the stripe gate, so an indeterminate earlier
        // mutation on this key fails activation closed here.
        let permit = self
            .steering
            .acquire_repin_permit(request.ownership_key())
            .await?;
        self.validate_activation_target_owner(request).await?;

        let grant = match self.fencer.recover_activation_grant(request).await? {
            Some(grant) => grant,
            None => {
                self.audit
                    .record_repin(RePinAuditEvent::activation_attempt(request))
                    .await?;
                match self.fencer.activate_ownership(request).await {
                    Ok(grant) => grant,
                    Err(error) => match self.fencer.recover_activation_grant(request).await {
                        Ok(Some(grant)) => grant,
                        Ok(None) => {
                            record_activation_failure(&self.audit, request, &error).await;
                            return Err(error);
                        }
                        Err(recovery_error) => {
                            record_activation_failure(&self.audit, request, &recovery_error).await;
                            return Err(recovery_error);
                        }
                    },
                }
            }
        };
        validate_activation_grant_matches(request, &grant)?;
        // Repeat the target-shard read after the commit so no stale snapshot
        // reaches the cancellation-safe datapath publication.
        self.validate_activation_target_owner(request).await?;

        let permit = self
            .steering
            .apply_fenced_repin(
                RePinSteeringUpdate::for_activation(request, grant.fence()),
                permit,
            )
            .await?;
        if permit.has_esp_counter_publication_guard() {
            return Err(IpsecLbError::adapter_contract_violation(
                "repin_backend_returned_unconsumed_counter_guard",
            ));
        }
        // Retain the operation permit across the final audit write, exactly as
        // `repin` does, so no other keyed mutation interleaves before the
        // activation is recorded.
        self.audit
            .record_repin(RePinAuditEvent::activated(request, grant.fence()))
            .await?;
        drop(permit);
        Ok(RePinOutcome::new(
            request.sa(),
            grant.fence(),
            request.rule(),
        ))
    }

    /// Retire an activation that never underwent a re-pin.
    ///
    /// This is the paired teardown boundary for [`Self::activate`], and it
    /// deliberately reuses the existing durable retirement authority rather
    /// than introducing a second, weaker removal path. The call therefore
    /// remains permit-bearing and generation-checked: it acquires the Host
    /// operation permit first, arms it, requires the authority to match the
    /// exact active transition, fingerprint, owner, and `active_fence`, and
    /// only then removes Host state under a strictly higher retirement fence.
    /// Finalization fenced-deletes the record while the store retains that
    /// key's fence floor, so the retired generation can never be reused.
    ///
    /// The permit is held across every step, including finalization, so a
    /// concurrent activation for the same key cannot cross the cleanup cut.
    ///
    /// Unlike [`crate::session_repin::SessionRePinCoordinator::retire`] this
    /// boundary is single-key and needs no journal: there is no cross-SA
    /// ordering to preserve, and every step is individually idempotent, so
    /// replaying the identical call after process loss converges forward.
    ///
    /// # Caller obligation: retain the request until this returns
    ///
    /// The first phase commits a durable `Retiring` record before any steering
    /// call. If the steering call then fails — including because the process
    /// died — that record stays `Retiring`, and every later
    /// [`Self::activate`] for the key is refused with
    /// `OwnershipConflict("ownership record is retiring")`. Only a replay of
    /// this call with the **exact** original request and `active_fence` clears
    /// it. Callers MUST therefore keep both durably until this returns, exactly
    /// as they would for a [`Self::repin`] retry.
    ///
    /// After process loss a caller that did not retain them can rebuild both
    /// from the durable record with
    /// [`crate::SessionStoreOwnershipFencer::recover_stranded_activation_retirement`],
    /// which needs only the SA, the ownership key, and the deployment's
    /// steering rule.
    ///
    /// # Authorization
    ///
    /// Matching the durable record's transition identity and fingerprint is an
    /// idempotency check, not an authorization decision. Authorization comes
    /// from the caller holding an [`OwnershipTransitionId`] that no other party
    /// can predict, and from the target shard still being owned by the
    /// retiring owner. See [`OwnershipTransitionId`] for the CSPRNG
    /// requirement that assumption rests on.
    ///
    /// That unpredictability is what authorizes a transition while it is live.
    /// It stops being a secret worth keeping the moment this call commits the
    /// durable `Retiring` record: from then on the transition is spent, and the
    /// identity can do nothing but finish its own teardown. Recovery leans on
    /// exactly that — `recover_stranded_activation_retirement` hands the
    /// transition identity back to any caller who can name the SA and its
    /// ownership key, deliberately, so a replacement process can converge a
    /// stranded key forward. The disclosure is sound only because it is gated
    /// on the terminal `Retiring` state; see the security invariant on that
    /// method, which must never be relaxed to a live record.
    pub async fn retire_activation(
        &self,
        request: &OwnershipActivationRequest,
        active_fence: OwnershipFence,
    ) -> Result<OwnershipActivationRetirement, IpsecLbError>
    where
        B: RePinSteeringRetirementBackend,
        F: OwnershipRetirementAuthority,
    {
        validate_activation_request(request)?;
        // Mirror `activate`'s target-owner gate. Retirement is checked before
        // the permit is acquired because a refusal here leaves nothing to
        // release and cannot poison the key's operation stripe; the durable
        // authority remains the serializing decision.
        self.validate_activation_target_owner(request).await?;
        let mut permits = self
            .steering
            .acquire_repin_retirement_permits(vec![request.ownership_key()])
            .await?;
        if permits.len() != 1 {
            return Err(IpsecLbError::adapter_contract_violation(
                "repin_retirement_permit_batch_mismatch",
            ));
        }
        let permit = permits.pop().ok_or_else(|| {
            IpsecLbError::adapter_contract_violation("repin_retirement_permit_batch_mismatch")
        })?;
        if permit.ownership_key() != request.ownership_key() {
            return Err(IpsecLbError::adapter_contract_violation(
                "repin_retirement_permit_key_mismatch",
            ));
        }
        let permit = self.steering.arm_repin_retirement_permit(permit)?;

        let retirement_request = OwnershipRetirementRequest::from_activation(request, active_fence);
        let admission = match self
            .fencer
            .begin_ownership_retirement(retirement_request)
            .await
        {
            Ok(admission) => admission,
            Err(error @ IpsecLbError::OwnershipRetirementIndeterminate) => {
                // Dropping an armed permit poisons the operation stripe; an
                // ambiguous authority result must never be classified safe.
                drop(permit);
                return Err(error);
            }
            Err(error) => {
                self.steering
                    .release_classified_repin_retirement_permit(permit)?;
                return Err(error);
            }
        };
        let grant = match admission {
            OwnershipRetirementAdmission::Granted(grant) => grant,
            OwnershipRetirementAdmission::Superseded(proof) => {
                self.steering
                    .release_classified_repin_retirement_permit(permit)?;
                return Ok(OwnershipActivationRetirement::Superseded(proof));
            }
        };

        let permit = self.steering.retire_fenced_repin(&grant, permit).await?;
        self.audit
            .record_repin(RePinAuditEvent::steering_retired(&grant))
            .await?;
        let finalized = self
            .finalize_retirement_cleanup(OwnershipCleanupCompleteProof::new(grant))
            .await?;
        drop(permit);
        Ok(OwnershipActivationRetirement::Finalized(finalized))
    }

    async fn validate_activation_target_owner(
        &self,
        request: &OwnershipActivationRequest,
    ) -> Result<(), IpsecLbError> {
        match self.ownership.shard_owner(request.map_owner()).await? {
            Some(owner) if owner == *request.owner() => Ok(()),
            Some(_) => Err(IpsecLbError::ownership_conflict(
                "steering target shard is not owned by the activating owner",
            )),
            None => Err(IpsecLbError::ownership_conflict(
                "steering target shard has no authoritative owner",
            )),
        }
    }

    pub(crate) async fn acquire_retirement_permits(
        &self,
        requests: &[RePinRequest],
    ) -> Result<Vec<RePinSteeringOperationPermit>, IpsecLbError>
    where
        B: RePinSteeringRetirementBackend,
    {
        for request in requests {
            validate_request(request)?;
        }
        let keys = requests
            .iter()
            .map(|request| request.ownership_key)
            .collect();
        let permits = self.steering.acquire_repin_retirement_permits(keys).await?;
        if permits.len() != requests.len()
            || permits
                .iter()
                .zip(requests)
                .any(|(permit, request)| permit.ownership_key() != request.ownership_key)
        {
            return Err(IpsecLbError::adapter_contract_violation(
                "repin_retirement_permit_batch_mismatch",
            ));
        }
        Ok(permits)
    }

    pub(crate) async fn validate_retirement_admission(
        &self,
        request: &RePinRequest,
        expected_fence: OwnershipFence,
        permit: &RePinSteeringOperationPermit,
    ) -> Result<(), IpsecLbError>
    where
        B: RePinSteeringRetirementBackend,
    {
        if permit.ownership_key() != request.ownership_key {
            return Err(IpsecLbError::adapter_contract_violation(
                "repin_retirement_permit_key_mismatch",
            ));
        }
        self.validate_pre_commit(request).await?;
        let fence_request = OwnershipFenceRequest {
            sa: request.sa,
            ownership_key: request.ownership_key,
            transition_id: request.transition_id,
            fingerprint: request.ownership_fingerprint(),
            previous_fence: request.previous_fence,
            previous_owner: request.previous_owner.clone(),
            new_owner: request.new_owner.clone(),
        };
        let grant = self
            .fencer
            .recover_fence_grant(&fence_request)
            .await?
            .ok_or_else(|| {
                IpsecLbError::ownership_conflict(
                    "retirement admission has no exact active ownership grant",
                )
            })?;
        validate_grant_matches(request, &grant)?;
        if grant.fence != expected_fence {
            return Err(IpsecLbError::ownership_conflict(
                "retirement admission fence does not match durable progress",
            ));
        }
        self.fencer
            .validate_retry_proof(&OwnershipRetryProof::from_grant(&grant))
            .await
    }

    pub(crate) async fn cleanup_committed_for_retirement(
        &self,
        request: &RePinRequest,
        active_fence: OwnershipFence,
        permit: RePinSteeringOperationPermit,
    ) -> Result<OwnershipRetirementStep, IpsecLbError>
    where
        B: RePinSteeringRetirementBackend,
        F: OwnershipRetirementAuthority,
    {
        validate_request(request)?;
        if permit.ownership_key() != request.ownership_key {
            return Err(IpsecLbError::adapter_contract_violation(
                "repin_retirement_permit_key_mismatch",
            ));
        }
        let permit = self.steering.arm_repin_retirement_permit(permit)?;
        let retirement_request = OwnershipRetirementRequest::from_committed(request, active_fence);
        let admission = match self
            .fencer
            .begin_ownership_retirement(retirement_request)
            .await
        {
            Ok(admission) => admission,
            Err(error @ IpsecLbError::OwnershipRetirementIndeterminate) => {
                drop(permit);
                return Err(error);
            }
            Err(error) => {
                self.steering
                    .release_classified_repin_retirement_permit(permit)?;
                return Err(error);
            }
        };
        let grant = match admission {
            OwnershipRetirementAdmission::Granted(grant) => grant,
            OwnershipRetirementAdmission::Superseded(proof) => {
                self.steering
                    .release_classified_repin_retirement_permit(permit)?;
                return Ok(OwnershipRetirementStep::Superseded(proof));
            }
        };
        let permit = self.steering.retire_fenced_repin(&grant, permit).await?;
        self.audit
            .record_repin(RePinAuditEvent::steering_retired(&grant))
            .await?;
        Ok(OwnershipRetirementStep::CleanupPending(
            PendingOwnershipRetirement::new(grant, permit),
        ))
    }

    pub(crate) async fn finalize_retirement_cleanup(
        &self,
        cleanup: OwnershipCleanupCompleteProof,
    ) -> Result<OwnershipRetirementFinalizedProof, IpsecLbError>
    where
        F: OwnershipRetirementAuthority,
    {
        let disposition = self.fencer.finalize_ownership_retirement(&cleanup).await?;
        Ok(OwnershipRetirementFinalizedProof::new(cleanup, disposition))
    }

    async fn validate_pre_commit(&self, request: &RePinRequest) -> Result<(), IpsecLbError> {
        validate_request(request)?;
        request.resume.validate_for_repin(request.sa)?;

        self.validate_target_owner(request).await
    }

    async fn validate_target_owner(&self, request: &RePinRequest) -> Result<(), IpsecLbError> {
        match self.ownership.shard_owner(request.rule.owner).await? {
            Some(owner) if owner == request.new_owner => Ok(()),
            Some(_) => Err(IpsecLbError::ownership_conflict(
                "steering target shard is not owned by the requested new owner",
            )),
            None => Err(IpsecLbError::ownership_conflict(
                "steering target shard has no authoritative owner",
            )),
        }
    }

    async fn validate_esp_counter_proof(
        &self,
        request: &RePinRequest,
        requirement: EspCounterProofRequirement,
    ) -> Result<(), IpsecLbError> {
        let Some(binding) = esp_counter_binding(request)? else {
            return Ok(());
        };
        #[cfg(test)]
        if self.accept_test_counter_proof {
            if requirement == EspCounterProofRequirement::BeforeFirstPublication
                && self
                    .reject_test_first_publication_validation_once
                    .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(IpsecLbError::applied_counter_proof_rejected(
                    "esp_counter_receipt_exact_state_changed",
                ));
            }
            return Ok(());
        }
        let authority = self.esp_counter_authority.as_ref().ok_or_else(|| {
            IpsecLbError::applied_counter_proof_rejected(
                "esp_counter_proof_authority_not_configured",
            )
        })?;
        let target = authority
            .targets
            .get(&binding.outbound_sa_binding_id())
            .ok_or_else(|| {
                IpsecLbError::applied_counter_proof_rejected("esp_counter_target_absent_or_stale")
            })?;
        authority
            .proofs
            .validate_counter_proof(target, binding, requirement)
            .await
            .map_err(|error| IpsecLbError::applied_counter_proof_rejected(error.code()))
    }

    async fn acquire_esp_counter_publication_guard(
        &self,
        request: &RePinRequest,
        requirement: EspCounterProofRequirement,
    ) -> Result<Option<EspCounterPublicationGuard>, IpsecLbError> {
        let Some(binding) = esp_counter_binding(request)? else {
            return Ok(None);
        };
        #[cfg(test)]
        if self.accept_test_counter_proof {
            if self.reject_test_first_publication_guard
                && requirement == EspCounterProofRequirement::BeforeFirstPublication
            {
                return Err(IpsecLbError::applied_counter_proof_rejected(
                    "esp_counter_receipt_exact_state_changed",
                ));
            }
            return Ok(None);
        }
        let authority = self.esp_counter_authority.as_ref().ok_or_else(|| {
            IpsecLbError::applied_counter_proof_rejected(
                "esp_counter_proof_authority_not_configured",
            )
        })?;
        let target = authority
            .targets
            .get(&binding.outbound_sa_binding_id())
            .ok_or_else(|| {
                IpsecLbError::applied_counter_proof_rejected("esp_counter_target_absent_or_stale")
            })?;
        authority
            .proofs
            .acquire_publication_guard(target, binding, requirement)
            .await
            .map(Some)
            .map_err(|error| IpsecLbError::applied_counter_proof_rejected(error.code()))
    }

    async fn continue_committed(
        &self,
        request: RePinRequest,
        retry_proof: OwnershipRetryProof,
        resume_at: RePinRetryStage,
        publication_requirement: EspCounterProofRequirement,
        permit: RePinSteeringOperationPermit,
    ) -> Result<RePinOutcome, RePinError> {
        let fence = retry_proof.fence;
        let validation_stage = resume_at;

        if let Err(error) = self.fencer.validate_retry_proof(&retry_proof).await {
            return Err(RePinError::AfterOwnershipCommit(Box::new(
                RePinPartialFailure::new(
                    request,
                    retry_proof,
                    validation_stage,
                    publication_requirement,
                    error,
                ),
            )));
        }
        if resume_at == RePinRetryStage::SteeringAudit {
            if let Err(error) = self.validate_target_owner(&request).await {
                return Err(RePinError::AfterOwnershipCommit(Box::new(
                    RePinPartialFailure::new(
                        request,
                        retry_proof,
                        validation_stage,
                        publication_requirement,
                        error,
                    ),
                )));
            }
        }
        if resume_at == RePinRetryStage::SteeringAudit {
            if let Err(error) = self
                .validate_esp_counter_proof(&request, EspCounterProofRequirement::CommittedRecovery)
                .await
            {
                return Err(RePinError::AfterOwnershipCommit(Box::new(
                    RePinPartialFailure::new(
                        request,
                        retry_proof,
                        validation_stage,
                        publication_requirement,
                        error,
                    ),
                )));
            }
        }

        if resume_at == RePinRetryStage::FencedAudit {
            if let Err(error) = self
                .audit
                .record_repin(RePinAuditEvent::fenced(&request, fence))
                .await
            {
                return Err(RePinError::AfterOwnershipCommit(Box::new(
                    RePinPartialFailure::new(
                        request,
                        retry_proof,
                        RePinRetryStage::FencedAudit,
                        publication_requirement,
                        error,
                    ),
                )));
            }
        }

        let _permit = if resume_at != RePinRetryStage::SteeringAudit {
            // The Fenced event is durable evidence that ownership committed,
            // so preserve it even if the target shard drifts afterwards. The
            // actor-issued ESP guard freezes receipt-invalidating XFRM
            // commands across the final owner read and cancellation-safe Host
            // publication. Drift resumes at SteeringInstall.
            let counter_guard = match self
                .acquire_esp_counter_publication_guard(&request, publication_requirement)
                .await
            {
                Ok(guard) => guard,
                Err(error) => {
                    return Err(RePinError::AfterOwnershipCommit(Box::new(
                        RePinPartialFailure::new(
                            request,
                            retry_proof,
                            RePinRetryStage::SteeringInstall,
                            publication_requirement,
                            error,
                        ),
                    )))
                }
            };
            let counter_publication_required = counter_guard.is_some();
            if let Err(error) = self.validate_target_owner(&request).await {
                return Err(RePinError::AfterOwnershipCommit(Box::new(
                    RePinPartialFailure::new(
                        request,
                        retry_proof,
                        RePinRetryStage::SteeringInstall,
                        publication_requirement,
                        error,
                    ),
                )));
            }
            let permit = match counter_guard {
                Some(guard) => match permit.bind_esp_counter_publication_guard(guard) {
                    Ok(permit) => permit,
                    Err(error) => {
                        return Err(RePinError::AfterOwnershipCommit(Box::new(
                            RePinPartialFailure::new(
                                request,
                                retry_proof,
                                RePinRetryStage::SteeringInstall,
                                publication_requirement,
                                error,
                            ),
                        )))
                    }
                },
                None => permit,
            };
            match self
                .steering
                .apply_fenced_repin(RePinSteeringUpdate::new(&request, fence), permit)
                .await
            {
                Ok(permit)
                    if !permit.has_esp_counter_publication_guard()
                        && (!counter_publication_required
                            || permit.counter_publication_authorized()) =>
                {
                    permit
                }
                Ok(permit) => {
                    let code = if permit.has_esp_counter_publication_guard() {
                        "repin_backend_returned_unconsumed_counter_guard"
                    } else {
                        "repin_backend_returned_unauthorized_counter_publication"
                    };
                    let error = IpsecLbError::adapter_contract_violation(code);
                    return Err(RePinError::AfterOwnershipCommit(Box::new(
                        RePinPartialFailure::new(
                            request,
                            retry_proof,
                            RePinRetryStage::SteeringInstall,
                            EspCounterProofRequirement::CommittedRecovery,
                            error,
                        ),
                    )));
                }
                Err(error) => {
                    return Err(RePinError::AfterOwnershipCommit(Box::new(
                        RePinPartialFailure::new(
                            request,
                            retry_proof,
                            RePinRetryStage::SteeringInstall,
                            EspCounterProofRequirement::CommittedRecovery,
                            error,
                        ),
                    )))
                }
            }
        } else {
            permit
        };

        if let Err(error) = self
            .audit
            .record_repin(RePinAuditEvent::steering_installed(&request, fence))
            .await
        {
            return Err(RePinError::AfterOwnershipCommit(Box::new(
                RePinPartialFailure::new(
                    request,
                    retry_proof,
                    RePinRetryStage::SteeringAudit,
                    EspCounterProofRequirement::CommittedRecovery,
                    error,
                ),
            )));
        }

        Ok(RePinOutcome::new(request.sa, fence, request.rule))
    }
}

fn validate_activation_grant_matches(
    request: &OwnershipActivationRequest,
    grant: &OwnershipActivationGrant,
) -> Result<(), IpsecLbError> {
    // Do not trust the authority port blindly: a grant for a different SA,
    // key, transition, or owner would publish a first owner for the wrong
    // identity. Reject it before any steering mutation.
    if grant.request() != request {
        return Err(IpsecLbError::ownership_conflict(
            "activation grant does not match the requested SA and owner",
        ));
    }
    Ok(())
}

fn validate_grant_matches(
    request: &RePinRequest,
    grant: &OwnershipFenceGrant,
) -> Result<(), IpsecLbError> {
    if grant.sa != request.sa
        || grant.ownership_key != request.ownership_key
        || grant.transition_id != request.transition_id
        || grant.fingerprint != request.ownership_fingerprint()
        || grant.owner != request.new_owner
    {
        return Err(IpsecLbError::ownership_conflict(
            "fence grant does not match the requested SA and new owner",
        ));
    }
    if grant.fence <= request.previous_fence {
        return Err(IpsecLbError::ownership_conflict(
            "fence grant did not advance beyond the previous fence",
        ));
    }
    Ok(())
}

fn hash_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn hash_sa(hasher: &mut Sha256, sa: SaId) {
    match sa {
        SaId::Ike { responder_spi } => {
            hasher.update([1]);
            hasher.update(responder_spi.to_be_bytes());
        }
        SaId::Esp { spi } => {
            hasher.update([2]);
            hasher.update(spi.to_be_bytes());
        }
    }
}

fn hash_steer_key(hasher: &mut Sha256, key: SteerKey) {
    match key {
        SteerKey::IkeResponderSpi(spi) => {
            hasher.update([1]);
            hasher.update(spi.to_be_bytes());
        }
        SteerKey::IkeInit {
            initiator_spi,
            source_ip,
        } => {
            hasher.update([2]);
            hasher.update(initiator_spi.to_be_bytes());
            match source_ip {
                IpAddress::V4(octets) => {
                    hasher.update([4]);
                    hasher.update(octets);
                }
                IpAddress::V6(octets) => {
                    hasher.update([6]);
                    hasher.update(octets);
                }
            }
        }
        SteerKey::EspSpi(spi) => {
            hasher.update([3]);
            hasher.update(spi.to_be_bytes());
        }
    }
}

fn hash_counter_resume_v1(
    hasher: &mut Sha256,
    resume: SameSpiResume,
    checkpointed_send_iv_next: u64,
    restored_send_iv_next: u64,
    forward_jump: Option<SendIvForwardJump>,
) {
    hash_sa(hasher, resume.previous_sa);
    hash_sa(hasher, resume.resumed_sa);
    hasher.update(checkpointed_send_iv_next.to_be_bytes());
    hasher.update(restored_send_iv_next.to_be_bytes());
    hash_forward_jump(hasher, forward_jump);
    hash_anti_replay_and_key_source(hasher, resume);
}

fn hash_resume_v2(hasher: &mut Sha256, resume: SameSpiResume) {
    hash_sa(hasher, resume.previous_sa);
    hash_sa(hasher, resume.resumed_sa);
    match resume.outbound_iv {
        SameSpiOutboundIvResume::Unspecified => hasher.update([0]),
        SameSpiOutboundIvResume::CounterBased {
            checkpointed_send_iv_next,
            restored_send_iv_next,
            forward_jump,
        } => {
            hasher.update([1]);
            hasher.update(checkpointed_send_iv_next.to_be_bytes());
            hasher.update(restored_send_iv_next.to_be_bytes());
            hash_forward_jump(hasher, forward_jump);
        }
        SameSpiOutboundIvResume::IkeRandomIv { attestation } => {
            hasher.update([2]);
            match attestation {
                IkeRandomIvAttestation::FreshIndependentCsprngIvPerMessage => {
                    hasher.update([1]);
                }
            }
        }
    }
    hash_anti_replay_and_key_source(hasher, resume);
}

fn hash_forward_jump(hasher: &mut Sha256, forward_jump: Option<SendIvForwardJump>) {
    match forward_jump {
        None => hasher.update([0]),
        Some(jump) => {
            hasher.update([1]);
            hasher.update(jump.forward_jump.to_be_bytes());
            match jump.counter_mode {
                SendIvCounterMode::EspExtendedSequenceNumbers {
                    max_peer_sequence_lag,
                } => {
                    hasher.update([1]);
                    hasher.update(max_peer_sequence_lag.to_be_bytes());
                }
                SendIvCounterMode::IkeAeadExplicitIv64 => hasher.update([2]),
            }
        }
    }
}

fn hash_anti_replay_and_key_source(hasher: &mut Sha256, resume: SameSpiResume) {
    match resume.anti_replay {
        AntiReplayResume::ExactWindowRestore {
            checkpoint_highest_accepted,
            restored_highest_accepted,
        } => {
            hasher.update([1]);
            hasher.update(checkpoint_highest_accepted.to_be_bytes());
            hasher.update(restored_highest_accepted.to_be_bytes());
        }
        AntiReplayResume::BoundedReopening {
            checkpoint_highest_accepted,
            restored_highest_accepted,
            max_reopened_packets,
        } => {
            hasher.update([2]);
            hasher.update(checkpoint_highest_accepted.to_be_bytes());
            hasher.update(restored_highest_accepted.to_be_bytes());
            hasher.update(max_reopened_packets.to_be_bytes());
        }
    }
    hasher.update([match resume.key_source {
        ResumeKeySource::LiveMirrored => 1,
        ResumeKeySource::RekeyOrReattachFallback => 2,
        ResumeKeySource::PersistedKeyMaterial => 3,
    }]);
}

fn esp_counter_binding(
    request: &RePinRequest,
) -> Result<Option<EspCounterResumeBinding>, IpsecLbError> {
    let (
        SaId::Esp { .. },
        SameSpiOutboundIvResume::CounterBased {
            restored_send_iv_next,
            ..
        },
    ) = (request.sa, request.resume.outbound_iv)
    else {
        return Ok(None);
    };
    let outbound_sa_binding_id = request.outbound_sa_binding_id.ok_or_else(|| {
        IpsecLbError::applied_counter_proof_rejected("esp_counter_outbound_sa_binding_missing")
    })?;
    EspCounterResumeBinding::new(
        request.transition_id.get(),
        request.previous_fence.get(),
        outbound_sa_binding_id,
        restored_send_iv_next,
    )
    .map(Some)
    .map_err(|error| IpsecLbError::applied_counter_proof_rejected(error.code()))
}

pub(crate) fn validate_request(request: &RePinRequest) -> Result<(), IpsecLbError> {
    if request.previous_owner == request.new_owner {
        return Err(IpsecLbError::invalid_config(
            "new_owner",
            "re-pin requires a different owner",
        ));
    }
    validate_sa_identifier(request.sa)?;
    match (request.sa, request.rule.key) {
        (SaId::Esp { spi }, SteerKey::EspSpi(rule_spi)) if spi == rule_spi => {}
        (SaId::Ike { responder_spi }, SteerKey::IkeResponderSpi(rule_responder_spi))
            if responder_spi == rule_responder_spi => {}
        _ => {
            return Err(IpsecLbError::invalid_config(
                "rule",
                "re-pin steering key must match the fenced SA protocol and SPI",
            ));
        }
    }
    validate_ownership_key_matches_sa(request.sa, request.ownership_key)?;
    match (request.sa, request.rule.key, request.ownership_key) {
        (SaId::Esp { spi }, SteerKey::EspSpi(rule_spi), SessionOwnershipKey::Esp(key))
            if spi == rule_spi && key.inbound_spi().get() == spi => {}
        (
            SaId::Ike { responder_spi },
            SteerKey::IkeResponderSpi(rule_responder_spi),
            SessionOwnershipKey::EstablishedIke(key),
        ) if responder_spi == rule_responder_spi && key.responder_spi().get() == responder_spi => {}
        _ => {
            return Err(IpsecLbError::invalid_config(
                "ownership_key",
                "destination-scoped ownership key must match the fenced SA protocol and SPI",
            ));
        }
    }
    match (request.sa, request.outbound_sa_binding_id) {
        (SaId::Esp { .. }, Some(_)) | (SaId::Ike { .. }, None) => {}
        (SaId::Esp { .. }, None) => {
            return Err(IpsecLbError::invalid_config(
                "outbound_sa_binding_id",
                "ESP re-pin requires the exact outbound SA binding ID",
            ));
        }
        (SaId::Ike { .. }, Some(_)) => {
            return Err(IpsecLbError::invalid_config(
                "outbound_sa_binding_id",
                "IKE re-pin cannot carry an outbound ESP SA binding ID",
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_activation_request(
    request: &OwnershipActivationRequest,
) -> Result<(), IpsecLbError> {
    validate_sa_identifier(request.sa())?;
    match (request.sa(), request.rule().key) {
        (SaId::Esp { spi }, SteerKey::EspSpi(rule_spi)) if spi == rule_spi => {}
        (SaId::Ike { responder_spi }, SteerKey::IkeResponderSpi(rule_responder_spi))
            if responder_spi == rule_responder_spi => {}
        _ => {
            return Err(IpsecLbError::invalid_config(
                "rule",
                "activation steering key must match the activated SA protocol and SPI",
            ));
        }
    }
    validate_ownership_key_matches_sa(request.sa(), request.ownership_key())?;
    // Redundant by construction, and deliberately kept: the preceding
    // `(sa, rule.key)` match and `validate_ownership_key_matches_sa` already
    // force all three to agree by transitivity, so no input reaches the `_`
    // arm and no test can kill it. It is a fail-closed backstop against a
    // future edit that weakens either of those two checks, and it mirrors the
    // same shape in `validate_request`.
    match (request.sa(), request.rule().key, request.ownership_key()) {
        (SaId::Esp { spi }, SteerKey::EspSpi(rule_spi), SessionOwnershipKey::Esp(key))
            if spi == rule_spi && key.inbound_spi().get() == spi => {}
        (
            SaId::Ike { responder_spi },
            SteerKey::IkeResponderSpi(rule_responder_spi),
            SessionOwnershipKey::EstablishedIke(key),
        ) if responder_spi == rule_responder_spi && key.responder_spi().get() == responder_spi => {}
        _ => {
            return Err(IpsecLbError::invalid_config(
                "ownership_key",
                "destination-scoped ownership key must match the activated SA protocol and SPI",
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_ownership_key_matches_sa(
    sa: SaId,
    ownership_key: SessionOwnershipKey,
) -> Result<(), IpsecLbError> {
    match (sa, ownership_key) {
        (SaId::Esp { spi }, SessionOwnershipKey::Esp(key)) if key.inbound_spi().get() == spi => {
            Ok(())
        }
        (SaId::Ike { responder_spi }, SessionOwnershipKey::EstablishedIke(key))
            if key.responder_spi().get() == responder_spi =>
        {
            Ok(())
        }
        _ => Err(IpsecLbError::invalid_config(
            "ownership_key",
            "ownership key must match the fenced SA protocol and SPI",
        )),
    }
}

pub(crate) fn validate_sa_identifier(sa: SaId) -> Result<(), IpsecLbError> {
    match sa {
        SaId::Esp { spi: 0 } => {
            return Err(IpsecLbError::invalid_config(
                "sa.spi",
                "ESP SPI must be non-zero",
            ));
        }
        SaId::Ike { responder_spi: 0 } => {
            return Err(IpsecLbError::invalid_config(
                "sa.responder_spi",
                "IKE responder SPI must be non-zero",
            ));
        }
        SaId::Esp { .. } | SaId::Ike { .. } => {}
    }
    Ok(())
}

async fn record_failure<A>(
    audit: &A,
    request: &RePinRequest,
    fence: Option<OwnershipFence>,
    error: &IpsecLbError,
) where
    A: RePinAuditSink,
{
    let _ = audit
        .record_repin(RePinAuditEvent::failed(request, fence, error))
        .await;
}

async fn record_activation_failure<A>(
    audit: &A,
    request: &OwnershipActivationRequest,
    error: &IpsecLbError,
) where
    A: RePinAuditSink,
{
    let _ = audit
        .record_repin(RePinAuditEvent::activation_failed(request, error))
        .await;
}

fn error_code(error: &IpsecLbError) -> &'static str {
    match error {
        IpsecLbError::InvalidSpiLayout { .. } => "invalid_spi_layout",
        IpsecLbError::UnknownShard => "unknown_shard",
        IpsecLbError::EmptyShardSet => "empty_shard_set",
        IpsecLbError::DuplicateShard => "duplicate_shard",
        IpsecLbError::TagSpaceExhausted => "tag_space_exhausted",
        IpsecLbError::EntropyUnavailable => "entropy_unavailable",
        IpsecLbError::AllocationAttemptsExhausted => "allocation_attempts_exhausted",
        IpsecLbError::SpiOutOfRange => "spi_out_of_range",
        IpsecLbError::PacketRejected { .. } => "packet_rejected",
        IpsecLbError::Io { .. } => "io",
        IpsecLbError::InvalidConfig { .. } => "invalid_config",
        IpsecLbError::AdapterContractViolation { .. } => "adapter_contract_violation",
        IpsecLbError::Unsupported => "unsupported",
        IpsecLbError::AlreadyExists => "already_exists",
        IpsecLbError::NotFound => "not_found",
        IpsecLbError::XdpLifecycleBusy => "xdp_lifecycle_busy",
        IpsecLbError::XdpUpgradeRequiresDrain => "xdp_upgrade_requires_drain",
        IpsecLbError::XdpUpgradeIndeterminate => "xdp_upgrade_indeterminate",
        IpsecLbError::OwnershipConflict { .. } => "ownership_conflict",
        IpsecLbError::OwnershipRetirementIndeterminate => "ownership_retirement_indeterminate",
        IpsecLbError::ForwardingProofRejected { .. } => "forwarding_proof_rejected",
        IpsecLbError::UnsafeResume { .. } => "unsafe_resume",
        IpsecLbError::AppliedCounterProofRejected { .. } => "applied_counter_proof_rejected",
        IpsecLbError::CookieRejected => "cookie_rejected",
        IpsecLbError::XdpKernelFloorNotMet { .. } => "xdp_kernel_floor_not_met",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::failover::SendIvCounterMode;
    use crate::ownership::{
        DestinationContext, EspEncapsulationKind, EspOwnershipKey, EspSpi,
        EstablishedIkeOwnershipKey, IkeSpi, RoutingDomainTag,
    };
    use crate::spi::FixedEntropy;

    const FORWARD_JUMP: u64 = crate::failover::MIN_SEND_IV_FORWARD_JUMP;
    /// A stand-in for a CSPRNG-drawn transition identity. It is deliberately
    /// wide: the disclosure assertions scan rendered output for its decimal and
    /// hex forms, and a short value would match hex digest text by chance.
    const SECRET_TRANSITION_VALUE: u128 = 0x2f81_a4c6_9d05_7e13_b6f2_48ac_15d9_3e00;
    const FROZEN_AUDIT_CORRELATION_V1: [u8; 32] = [
        0x0c, 0x19, 0x9b, 0x8a, 0x89, 0xb6, 0x1c, 0xf0, 0x6a, 0x1d, 0x0b, 0xe2, 0xc2, 0xba, 0x84,
        0x92, 0xb1, 0xb5, 0x63, 0x7e, 0x69, 0x0a, 0xde, 0xba, 0x0b, 0x62, 0xef, 0x35, 0xb1, 0x52,
        0xa5, 0x9b,
    ];
    const LEGACY_ESP_COUNTER_V1_FINGERPRINT: [u8; 32] = [
        0x7e, 0xeb, 0x23, 0x71, 0xb3, 0xea, 0xbc, 0x7d, 0x94, 0xf9, 0x2e, 0x41, 0x4c, 0xad, 0x9d,
        0xb3, 0x62, 0x2f, 0x10, 0x78, 0xa3, 0x20, 0x32, 0x8e, 0x81, 0xce, 0x8b, 0xd4, 0x09, 0x56,
        0x59, 0xcd,
    ];
    const FROZEN_ESP_COUNTER_V5_FINGERPRINT: [u8; 32] = [
        0xd2, 0xc6, 0xe5, 0x4d, 0x11, 0xd9, 0xbe, 0x2a, 0x2e, 0x2f, 0xb5, 0x5c, 0x07, 0x9b, 0x21,
        0xeb, 0xc8, 0x1a, 0x5c, 0x7e, 0x94, 0x78, 0x71, 0xf6, 0x4a, 0x86, 0x36, 0x59, 0x60, 0x9c,
        0x8e, 0x3c,
    ];
    const FROZEN_ACTIVATION_V1_FINGERPRINT: [u8; 32] = [
        0xe0, 0xdb, 0x36, 0x98, 0xf4, 0x42, 0xb7, 0x41, 0xb0, 0x53, 0xc1, 0xd9, 0x6e, 0xe4, 0x34,
        0x2b, 0x8a, 0xcf, 0x17, 0x81, 0x73, 0x56, 0x33, 0x93, 0x3e, 0x43, 0xa2, 0x0b, 0x85, 0x25,
        0x9d, 0x3f,
    ];
    const FROZEN_RANDOM_IV_V4_FINGERPRINT: [u8; 32] = [
        0x49, 0x1f, 0x33, 0x17, 0x3a, 0x7d, 0xb0, 0x69, 0x33, 0x32, 0x74, 0x0d, 0x00, 0x07, 0x31,
        0x06, 0x40, 0x10, 0xf8, 0x68, 0x13, 0x42, 0x6d, 0xb4, 0x76, 0x28, 0xdd, 0x9c, 0xd5, 0x87,
        0x26, 0xb4,
    ];

    fn ownership_key(sa: SaId) -> SessionOwnershipKey {
        let destination =
            DestinationContext::new(IpAddress::V4([192, 0, 2, 10]), RoutingDomainTag::new(7));
        match sa {
            SaId::Esp { spi } => SessionOwnershipKey::Esp(EspOwnershipKey::new(
                destination,
                EspEncapsulationKind::UdpEncapsulated,
                EspSpi::new(spi).unwrap(),
            )),
            SaId::Ike { responder_spi } => {
                SessionOwnershipKey::EstablishedIke(EstablishedIkeOwnershipKey::new(
                    destination,
                    IkeSpi::new(11).unwrap(),
                    IkeSpi::new(responder_spi).unwrap(),
                ))
            }
        }
    }

    #[test]
    fn steering_publication_permit_is_exactly_once_after_success() {
        let mut permit =
            RePinSteeringOperationPermit::unguarded(ownership_key(SaId::Ike { responder_spi: 7 }));
        let calls = std::cell::Cell::new(0_u8);
        permit
            .publish_with_esp_counter_guard(|| {
                calls.set(calls.get() + 1);
                Ok::<(), ()>(())
            })
            .unwrap()
            .unwrap();
        assert!(permit.counter_publication_authorized());
        let error = permit
            .publish_with_esp_counter_guard(|| {
                calls.set(calls.get() + 1);
                Ok::<(), ()>(())
            })
            .unwrap_err();
        assert!(matches!(
            error,
            IpsecLbError::AdapterContractViolation {
                code: "repin_operation_permit_publication_already_consumed"
            }
        ));
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn steering_publication_permit_is_exactly_once_after_failure() {
        let mut permit =
            RePinSteeringOperationPermit::unguarded(ownership_key(SaId::Ike { responder_spi: 7 }));
        let calls = std::cell::Cell::new(0_u8);
        let first = permit
            .publish_with_esp_counter_guard(|| {
                calls.set(calls.get() + 1);
                Err::<(), _>("injected publication failure")
            })
            .unwrap();
        assert_eq!(first, Err("injected publication failure"));
        assert!(!permit.counter_publication_authorized());
        assert!(permit
            .publish_with_esp_counter_guard(|| {
                calls.set(calls.get() + 1);
                Ok::<(), ()>(())
            })
            .is_err());
        assert_eq!(calls.get(), 1);
    }

    fn outbound_sa_binding_id(sa: SaId) -> Option<OutboundSaBindingId> {
        match sa {
            SaId::Esp { spi } => {
                let mut bytes = [0x33; 32];
                bytes[..4].copy_from_slice(&spi.to_be_bytes());
                Some(OutboundSaBindingId::from_bytes(bytes))
            }
            SaId::Ike { .. } => None,
        }
    }

    fn valid_forward_jump(sa: SaId) -> SendIvForwardJump {
        SendIvForwardJump {
            forward_jump: FORWARD_JUMP,
            counter_mode: match sa {
                SaId::Esp { .. } => SendIvCounterMode::EspExtendedSequenceNumbers {
                    max_peer_sequence_lag: 0,
                },
                SaId::Ike { .. } => SendIvCounterMode::IkeAeadExplicitIv64,
            },
        }
    }

    fn counter_outbound_iv(
        checkpointed_send_iv_next: u64,
        restored_send_iv_next: u64,
        forward_jump: Option<SendIvForwardJump>,
    ) -> SameSpiOutboundIvResume {
        SameSpiOutboundIvResume::CounterBased {
            checkpointed_send_iv_next,
            restored_send_iv_next,
            forward_jump,
        }
    }

    fn valid_resume(sa: SaId, key_source: ResumeKeySource) -> SameSpiResume {
        SameSpiResume {
            previous_sa: sa,
            resumed_sa: sa,
            outbound_iv: counter_outbound_iv(10, 10 + FORWARD_JUMP, Some(valid_forward_jump(sa))),
            anti_replay: AntiReplayResume::ExactWindowRestore {
                checkpoint_highest_accepted: 20,
                restored_highest_accepted: 20,
            },
            key_source,
        }
    }

    fn valid_random_iv_ike_resume(key_source: ResumeKeySource) -> SameSpiResume {
        let sa = SaId::Ike { responder_spi: 1 };
        SameSpiResume {
            previous_sa: sa,
            resumed_sa: sa,
            outbound_iv: SameSpiOutboundIvResume::IkeRandomIv {
                attestation: IkeRandomIvAttestation::FreshIndependentCsprngIvPerMessage,
            },
            anti_replay: AntiReplayResume::ExactWindowRestore {
                checkpoint_highest_accepted: 20,
                restored_highest_accepted: 20,
            },
            key_source,
        }
    }

    fn frozen_counter_v5_request() -> RePinRequest {
        let sa = SaId::Esp { spi: 0x0107 };
        RePinRequest {
            sa,
            transition_id: OwnershipTransitionId::new(7).unwrap(),
            previous_fence: OwnershipFence::new(1).unwrap(),
            previous_owner: ClusterNode::new("worker-a"),
            new_owner: ClusterNode::new("worker-b"),
            rule: SteeringRule {
                shard: crate::model::ShardId::new(1),
                owner: crate::model::ShardId::new(2),
                key: SteerKey::EspSpi(0x0107),
            },
            ownership_key: ownership_key(sa),
            outbound_sa_binding_id: outbound_sa_binding_id(sa),
            resume: valid_resume(sa, ResumeKeySource::LiveMirrored),
        }
    }

    fn frozen_random_iv_v4_request() -> RePinRequest {
        let sa = SaId::Ike { responder_spi: 7 };
        RePinRequest {
            sa,
            transition_id: OwnershipTransitionId::new(7).unwrap(),
            previous_fence: OwnershipFence::new(1).unwrap(),
            previous_owner: ClusterNode::new("worker-a"),
            new_owner: ClusterNode::new("worker-b"),
            rule: SteeringRule {
                shard: crate::model::ShardId::new(1),
                owner: crate::model::ShardId::new(2),
                key: SteerKey::IkeResponderSpi(7),
            },
            ownership_key: ownership_key(sa),
            outbound_sa_binding_id: outbound_sa_binding_id(sa),
            resume: SameSpiResume {
                previous_sa: sa,
                resumed_sa: sa,
                outbound_iv: SameSpiOutboundIvResume::IkeRandomIv {
                    attestation: IkeRandomIvAttestation::FreshIndependentCsprngIvPerMessage,
                },
                anti_replay: AntiReplayResume::ExactWindowRestore {
                    checkpoint_highest_accepted: 20,
                    restored_highest_accepted: 20,
                },
                key_source: ResumeKeySource::LiveMirrored,
            },
        }
    }

    #[test]
    fn same_spi_resume_accepts_valid_jump_for_live_and_persisted_keys() {
        for sa in [SaId::Esp { spi: 1 }, SaId::Ike { responder_spi: 1 }] {
            for key_source in [
                ResumeKeySource::LiveMirrored,
                ResumeKeySource::PersistedKeyMaterial,
            ] {
                valid_resume(sa, key_source).validate_for_repin(sa).unwrap();
            }
        }
    }

    #[test]
    fn same_spi_resume_accepts_random_iv_ike_for_live_and_persisted_keys() {
        let sa = SaId::Ike { responder_spi: 1 };
        for key_source in [
            ResumeKeySource::LiveMirrored,
            ResumeKeySource::PersistedKeyMaterial,
        ] {
            valid_random_iv_ike_resume(key_source)
                .validate_for_repin(sa)
                .unwrap();
        }
    }

    #[test]
    fn esp_counter_ownership_fingerprint_preserves_frozen_v5_encoding() {
        assert_eq!(
            frozen_counter_v5_request()
                .ownership_fingerprint()
                .as_bytes(),
            FROZEN_ESP_COUNTER_V5_FINGERPRINT
        );
    }

    #[test]
    fn random_iv_ownership_fingerprint_preserves_frozen_v4_encoding() {
        let request = frozen_random_iv_v4_request();
        validate_request(&request).unwrap();
        assert_eq!(
            request.ownership_fingerprint().as_bytes(),
            FROZEN_RANDOM_IV_V4_FINGERPRINT
        );
    }

    #[tokio::test]
    async fn legacy_numeric_only_esp_grant_cannot_recover_as_v5_destination_proof() {
        let request = frozen_counter_v5_request();
        let fencer = crate::mock::MockOwnershipFencer::new();
        fencer.set_owner(request.ownership_key, request.previous_owner.clone());

        let committed = fencer
            .fence_sa_owner(OwnershipFenceRequest {
                sa: request.sa,
                ownership_key: request.ownership_key,
                transition_id: request.transition_id,
                fingerprint: OwnershipTransitionFingerprint::from_bytes(
                    LEGACY_ESP_COUNTER_V1_FINGERPRINT,
                ),
                previous_fence: request.previous_fence,
                previous_owner: request.previous_owner.clone(),
                new_owner: request.new_owner.clone(),
            })
            .await
            .unwrap();

        let steering = crate::mock::MockSteeringBackend::new();
        let ownership = crate::mock::MockOwnershipSource::default();
        ownership.set_shard_owner(request.rule.owner, request.new_owner.clone());
        let audit = crate::mock::MockRePinAuditSink::new();
        let coordinator =
            RePinCoordinator::new(steering.clone(), fencer.clone(), ownership, audit.clone());

        assert!(matches!(
            coordinator.repin(request.clone()).await,
            Err(RePinError::BeforeOwnershipCommit(
                IpsecLbError::OwnershipConflict { .. }
            ))
        ));
        assert_ne!(request.ownership_fingerprint(), committed.fingerprint);
        assert_eq!(fencer.operations().len(), 1);
        assert_eq!(fencer.recovery_attempts(), 1);
        assert!(steering.operations().is_empty());
        assert!(audit.events().is_empty());
    }

    #[test]
    fn ownership_fingerprint_binds_every_safety_critical_request_component() {
        let sa = SaId::Esp { spi: 0x0107 };
        let base = frozen_counter_v5_request();
        let expected = base.ownership_fingerprint();
        assert_eq!(expected, base.clone().ownership_fingerprint());

        let mutations = [
            RePinRequest {
                sa: SaId::Esp { spi: 0x0108 },
                ..base.clone()
            },
            RePinRequest {
                transition_id: OwnershipTransitionId::new(8).unwrap(),
                ..base.clone()
            },
            RePinRequest {
                previous_fence: OwnershipFence::new(4).unwrap(),
                ..base.clone()
            },
            RePinRequest {
                previous_owner: ClusterNode::new("worker-x"),
                ..base.clone()
            },
            RePinRequest {
                new_owner: ClusterNode::new("worker-y"),
                ..base.clone()
            },
            RePinRequest {
                rule: SteeringRule {
                    shard: crate::model::ShardId::new(4),
                    ..base.rule
                },
                ..base.clone()
            },
            RePinRequest {
                rule: SteeringRule {
                    owner: crate::model::ShardId::new(3),
                    ..base.rule
                },
                ..base.clone()
            },
            RePinRequest {
                rule: SteeringRule {
                    key: SteerKey::EspSpi(0x0108),
                    ..base.rule
                },
                ..base.clone()
            },
            RePinRequest {
                resume: SameSpiResume {
                    previous_sa: SaId::Esp { spi: 0x0108 },
                    ..base.resume
                },
                ..base.clone()
            },
            RePinRequest {
                resume: SameSpiResume {
                    resumed_sa: SaId::Esp { spi: 0x0108 },
                    ..base.resume
                },
                ..base.clone()
            },
            RePinRequest {
                resume: SameSpiResume {
                    outbound_iv: counter_outbound_iv(
                        11,
                        11 + FORWARD_JUMP,
                        Some(valid_forward_jump(sa)),
                    ),
                    ..base.resume
                },
                ..base.clone()
            },
            RePinRequest {
                resume: SameSpiResume {
                    outbound_iv: counter_outbound_iv(10, 10 + FORWARD_JUMP, None),
                    ..base.resume
                },
                ..base.clone()
            },
            RePinRequest {
                resume: SameSpiResume {
                    outbound_iv: counter_outbound_iv(
                        10,
                        11 + FORWARD_JUMP,
                        Some(SendIvForwardJump {
                            forward_jump: FORWARD_JUMP + 1,
                            counter_mode: SendIvCounterMode::EspExtendedSequenceNumbers {
                                max_peer_sequence_lag: 0,
                            },
                        }),
                    ),
                    ..base.resume
                },
                ..base.clone()
            },
            RePinRequest {
                resume: SameSpiResume {
                    outbound_iv: counter_outbound_iv(
                        10,
                        10 + FORWARD_JUMP,
                        Some(SendIvForwardJump {
                            forward_jump: FORWARD_JUMP,
                            counter_mode: SendIvCounterMode::EspExtendedSequenceNumbers {
                                max_peer_sequence_lag: 1,
                            },
                        }),
                    ),
                    ..base.resume
                },
                ..base.clone()
            },
            RePinRequest {
                resume: SameSpiResume {
                    outbound_iv: counter_outbound_iv(
                        10,
                        10 + FORWARD_JUMP,
                        Some(SendIvForwardJump {
                            forward_jump: FORWARD_JUMP,
                            counter_mode: SendIvCounterMode::IkeAeadExplicitIv64,
                        }),
                    ),
                    ..base.resume
                },
                ..base.clone()
            },
            RePinRequest {
                resume: SameSpiResume {
                    outbound_iv: SameSpiOutboundIvResume::IkeRandomIv {
                        attestation: IkeRandomIvAttestation::FreshIndependentCsprngIvPerMessage,
                    },
                    ..base.resume
                },
                ..base.clone()
            },
            RePinRequest {
                resume: SameSpiResume {
                    outbound_iv: SameSpiOutboundIvResume::Unspecified,
                    ..base.resume
                },
                ..base.clone()
            },
            RePinRequest {
                resume: SameSpiResume {
                    anti_replay: AntiReplayResume::ExactWindowRestore {
                        checkpoint_highest_accepted: 21,
                        restored_highest_accepted: 21,
                    },
                    ..base.resume
                },
                ..base.clone()
            },
            RePinRequest {
                resume: SameSpiResume {
                    anti_replay: AntiReplayResume::BoundedReopening {
                        checkpoint_highest_accepted: 20,
                        restored_highest_accepted: 20,
                        max_reopened_packets: 64,
                    },
                    ..base.resume
                },
                ..base.clone()
            },
            RePinRequest {
                resume: SameSpiResume {
                    key_source: ResumeKeySource::PersistedKeyMaterial,
                    ..base.resume
                },
                ..base.clone()
            },
        ];

        for mutation in mutations {
            assert_ne!(expected, mutation.ownership_fingerprint());
        }
    }

    #[test]
    fn ownership_fingerprint_distinguishes_valid_ike_counter_and_random_iv_modes() {
        let sa = SaId::Ike { responder_spi: 1 };
        let counter = RePinRequest {
            sa,
            transition_id: OwnershipTransitionId::new(9).unwrap(),
            previous_fence: OwnershipFence::new(3).unwrap(),
            previous_owner: ClusterNode::new("worker-a"),
            new_owner: ClusterNode::new("worker-b"),
            rule: SteeringRule {
                shard: crate::model::ShardId::new(1),
                owner: crate::model::ShardId::new(2),
                key: SteerKey::IkeResponderSpi(1),
            },
            ownership_key: ownership_key(sa),
            outbound_sa_binding_id: outbound_sa_binding_id(sa),
            resume: valid_resume(sa, ResumeKeySource::PersistedKeyMaterial),
        };
        let random_iv = RePinRequest {
            resume: valid_random_iv_ike_resume(ResumeKeySource::PersistedKeyMaterial),
            ..counter.clone()
        };

        validate_request(&counter).unwrap();
        validate_request(&random_iv).unwrap();
        assert_ne!(
            counter.ownership_fingerprint(),
            random_iv.ownership_fingerprint()
        );
    }

    #[test]
    fn ownership_transition_id_rejects_zero() {
        assert!(matches!(
            OwnershipTransitionId::new(0),
            Err(IpsecLbError::InvalidConfig {
                field: "transition_id",
                ..
            })
        ));
    }

    /// A live transition identity is the sole authorization factor for
    /// retirement, so its own `Debug` must not print it — otherwise every
    /// container that derives `Debug` around it becomes a disclosure path.
    #[test]
    fn ownership_transition_id_debug_redacts_the_secret_value() {
        let id = OwnershipTransitionId::new(SECRET_TRANSITION_VALUE).unwrap();
        let rendered = format!("{id:?}");
        assert_eq!(rendered, "OwnershipTransitionId([redacted])");
        assert!(!rendered.contains(&id.get().to_string()));
        assert!(!rendered.contains(&format!("{:032x}", id.get())));
    }

    /// The redaction must survive being nested inside a derived `Debug`, which
    /// is how the value would actually reach a log.
    #[test]
    fn ownership_transition_id_debug_redacts_inside_a_derived_container() {
        #[derive(Debug)]
        struct Wrapper {
            transition_id: OwnershipTransitionId,
        }

        let id = OwnershipTransitionId::new(SECRET_TRANSITION_VALUE).unwrap();
        let wrapper = Wrapper { transition_id: id };
        assert_eq!(wrapper.transition_id, id);
        let rendered = format!("{wrapper:?}");
        assert!(rendered.contains("[redacted]"));
        assert!(!rendered.contains(&id.get().to_string()));
    }

    #[test]
    fn ownership_transition_id_generate_draws_distinct_nonzero_values() {
        let mut drawn = std::collections::BTreeSet::new();
        for _ in 0..32 {
            let id = OwnershipTransitionId::generate().expect("system entropy");
            assert_ne!(id.get(), 0);
            assert!(drawn.insert(id.get()), "generate repeated a value");
        }
    }

    /// Pins the draw width and byte order: the identity must consume all 128
    /// bits of the source, big-endian.
    #[test]
    fn ownership_transition_id_generate_from_consumes_128_big_endian_bits() {
        let entropy = FixedEntropy::new((1..=16).collect());
        let id = OwnershipTransitionId::generate_from(&entropy).expect("fixed entropy");
        assert_eq!(id.get(), 0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10);
    }

    /// The one rejected value must stay rejected even when the source insists
    /// on it; a source that only ever yields zero is broken, not unlucky.
    #[test]
    fn ownership_transition_id_generate_from_rejects_an_all_zero_source() {
        let entropy = FixedEntropy::new(vec![0]);
        assert_eq!(
            OwnershipTransitionId::generate_from(&entropy).unwrap_err(),
            IpsecLbError::EntropyUnavailable
        );
    }

    /// A source that reports failure without touching `dst` must not be
    /// mistaken for a usable one.
    ///
    /// This case cannot pin the `?` on its own: `FixedEntropy` leaves the buffer
    /// alone when it errors, so the draw stays all-zero, the non-zero rejection
    /// burns the whole redraw budget, and `EntropyUnavailable` comes back
    /// whether the error was propagated or dropped. The companion test below
    /// supplies the fixture that separates the two.
    #[test]
    fn ownership_transition_id_generate_from_propagates_source_failure() {
        let entropy = FixedEntropy::new(Vec::new());
        assert_eq!(
            OwnershipTransitionId::generate_from(&entropy).unwrap_err(),
            IpsecLbError::EntropyUnavailable
        );
    }

    /// A source that writes `dst` and *then* reports failure must still be
    /// rejected.
    ///
    /// This is an ordinary RNG-adapter shape rather than a contrived one: an
    /// adapter that copies a hardware FIFO out before its health test trips
    /// hands back stale bytes alongside the error. Dropping that error would
    /// mint an identity from exactly those bytes -- here the fully predictable
    /// `0xabab..ab` -- and that identity is both the sole authorization factor
    /// for `retire_activation` and the only secret in the correlation digest's
    /// preimage. Only a source that fails *after* writing tells a propagated
    /// error apart from an expired redraw budget.
    #[test]
    fn ownership_transition_id_generate_from_rejects_a_source_that_fails_after_writing() {
        #[derive(Debug)]
        struct PoisonedEntropy;

        impl EntropySource for PoisonedEntropy {
            fn fill_bytes(&self, dst: &mut [u8]) -> Result<(), IpsecLbError> {
                dst.fill(0xab);
                Err(IpsecLbError::EntropyUnavailable)
            }
        }

        assert_eq!(
            OwnershipTransitionId::generate_from(&PoisonedEntropy).unwrap_err(),
            IpsecLbError::EntropyUnavailable
        );
    }

    /// Audit sinks persist and index this value, so both halves of it are
    /// frozen: changing the domain separator or the hashed field set silently
    /// orphans every already-recorded correlation, and changing the `Display`
    /// rendering does the same to every record keyed on the rendered string --
    /// which is the form that actually reaches a log line, and the form the
    /// README and this type's rustdoc tell operators to compare.
    ///
    /// The rendering is asserted against a literal rather than against another
    /// `Display`, because a `Display`-to-`Display` comparison holds under any
    /// bijection (hex case) and under truncation. Truncation is the one that
    /// costs something: cutting the rendering to eight hex characters collides
    /// two distinct SA transitions in a SIEM at around 10^5 transitions, which
    /// destroys the grouping guarantee this identity exists to provide.
    #[test]
    fn repin_audit_correlation_id_preserves_its_frozen_v1_encoding() {
        let correlation =
            RePinAuditCorrelationId::for_transition(OwnershipTransitionId::new(1).unwrap());
        assert_eq!(correlation.as_bytes(), FROZEN_AUDIT_CORRELATION_V1);
        assert_eq!(
            correlation.to_string(),
            "0c199b8a89b61cf06a1d0be2c2ba8492b1b5637e690adeba0b62ef35b152a59b"
        );
    }

    #[test]
    fn repin_audit_correlation_id_is_stable_and_separates_distinct_transitions() {
        let first = OwnershipTransitionId::new(SECRET_TRANSITION_VALUE).unwrap();
        let second = OwnershipTransitionId::new(SECRET_TRANSITION_VALUE + 1).unwrap();
        assert_eq!(
            RePinAuditCorrelationId::for_transition(first),
            RePinAuditCorrelationId::for_transition(first),
            "correlation must be stable across the events of one transition"
        );
        assert_ne!(
            RePinAuditCorrelationId::for_transition(first),
            RePinAuditCorrelationId::for_transition(second),
            "distinct transitions must not share a correlation identity"
        );
    }

    /// The correlation identity must be a digest, not a re-encoding: no window
    /// of it may reproduce the transition identity's bytes.
    #[test]
    fn repin_audit_correlation_id_does_not_embed_the_transition_identity() {
        let id = OwnershipTransitionId::new(SECRET_TRANSITION_VALUE).unwrap();
        let correlation = RePinAuditCorrelationId::for_transition(id);
        let raw = id.get().to_be_bytes();
        let mut reversed = raw;
        reversed.reverse();
        for window in correlation.as_bytes().windows(raw.len()) {
            assert_ne!(window, raw, "correlation identity leaked the raw value");
            assert_ne!(
                window, reversed,
                "correlation identity leaked the raw value"
            );
        }
        assert!(!correlation
            .to_string()
            .contains(&format!("{:032x}", id.get())));
    }

    /// Every coordinator-emitted audit event must correlate to its transition
    /// without carrying the value that authorizes retiring it. The field's type
    /// makes that structural — a `RePinAuditCorrelationId` cannot hold an
    /// `OwnershipTransitionId` — so this pins the derivation and the rendering.
    #[test]
    fn repin_audit_events_correlate_without_disclosing_the_transition_identity() {
        let transition_id = OwnershipTransitionId::new(SECRET_TRANSITION_VALUE).unwrap();
        let mut request = frozen_counter_v5_request();
        request.transition_id = transition_id;
        let mut activation = frozen_activation_request();
        activation.transition_id = transition_id;
        let fence = OwnershipFence::new(9).unwrap();
        let error = IpsecLbError::Unsupported;

        let events = [
            RePinAuditEvent::attempt(&request),
            RePinAuditEvent::fenced(&request, fence),
            RePinAuditEvent::steering_installed(&request, fence),
            RePinAuditEvent::failed(&request, Some(fence), &error),
            RePinAuditEvent::activation_attempt(&activation),
            RePinAuditEvent::activated(&activation, fence),
            RePinAuditEvent::activation_failed(&activation, &error),
        ];

        let expected = RePinAuditCorrelationId::for_transition(transition_id);
        for event in &events {
            assert_eq!(
                event.correlation_id, expected,
                "every event of one transition must share its correlation identity"
            );
            let rendered = format!("{event:?}");
            assert!(
                !rendered.contains(&SECRET_TRANSITION_VALUE.to_string()),
                "audit event rendering leaked the raw transition identity"
            );
            assert!(
                !rendered.contains(&format!("{SECRET_TRANSITION_VALUE:032x}")),
                "audit event rendering leaked the raw transition identity"
            );
            assert!(
                rendered.contains(&expected.to_string()),
                "audit event rendering must keep the correlation identity readable"
            );
        }
    }

    #[test]
    fn same_spi_resume_rejects_zero_sa_identifiers_directly() {
        for sa in [SaId::Esp { spi: 0 }, SaId::Ike { responder_spi: 0 }] {
            assert!(matches!(
                valid_resume(sa, ResumeKeySource::LiveMirrored).validate_for_repin(sa),
                Err(IpsecLbError::InvalidConfig { .. })
            ));
        }
    }

    #[test]
    fn same_spi_resume_rejects_every_malformed_forward_jump_shape() {
        let sa = SaId::Esp { spi: 0x0101 };

        for key_source in [
            ResumeKeySource::LiveMirrored,
            ResumeKeySource::PersistedKeyMaterial,
        ] {
            let mut missing = valid_resume(sa, key_source);
            missing.outbound_iv = counter_outbound_iv(10, 10 + FORWARD_JUMP, None);
            assert!(matches!(
                missing.validate_for_repin(sa),
                Err(IpsecLbError::UnsafeResume { .. })
            ));
        }

        let mut below_floor = valid_resume(sa, ResumeKeySource::PersistedKeyMaterial);
        below_floor.outbound_iv = counter_outbound_iv(
            10,
            10 + FORWARD_JUMP - 1,
            Some(SendIvForwardJump {
                forward_jump: FORWARD_JUMP - 1,
                counter_mode: SendIvCounterMode::EspExtendedSequenceNumbers {
                    max_peer_sequence_lag: 0,
                },
            }),
        );
        assert!(matches!(
            below_floor.validate_for_repin(sa),
            Err(IpsecLbError::UnsafeResume { .. })
        ));

        let mut wrong_protocol = valid_resume(sa, ResumeKeySource::LiveMirrored);
        wrong_protocol.outbound_iv = counter_outbound_iv(
            10,
            10 + FORWARD_JUMP,
            Some(SendIvForwardJump {
                forward_jump: FORWARD_JUMP,
                counter_mode: SendIvCounterMode::IkeAeadExplicitIv64,
            }),
        );
        assert!(matches!(
            wrong_protocol.validate_for_repin(sa),
            Err(IpsecLbError::UnsafeResume { .. })
        ));

        let mut mismatch = valid_resume(sa, ResumeKeySource::PersistedKeyMaterial);
        mismatch.outbound_iv =
            counter_outbound_iv(10, 10 + FORWARD_JUMP - 1, Some(valid_forward_jump(sa)));
        assert!(matches!(
            mismatch.validate_for_repin(sa),
            Err(IpsecLbError::UnsafeResume { .. })
        ));

        let mut exhausted = valid_resume(sa, ResumeKeySource::PersistedKeyMaterial);
        exhausted.outbound_iv = counter_outbound_iv(
            u64::MAX - FORWARD_JUMP + 1,
            u64::MAX,
            Some(valid_forward_jump(sa)),
        );
        assert!(matches!(
            exhausted.validate_for_repin(sa),
            Err(IpsecLbError::UnsafeResume { .. })
        ));

        let fallback = valid_resume(sa, ResumeKeySource::RekeyOrReattachFallback);
        assert!(matches!(
            fallback.validate_for_repin(sa),
            Err(IpsecLbError::UnsafeResume { .. })
        ));
    }

    #[test]
    fn same_spi_resume_accepts_matching_esp_and_ike_counter_modes_only() {
        let esp = SaId::Esp { spi: 1 };
        let ike = SaId::Ike { responder_spi: 7 };
        valid_resume(esp, ResumeKeySource::LiveMirrored)
            .validate_for_repin(esp)
            .unwrap();
        valid_resume(ike, ResumeKeySource::LiveMirrored)
            .validate_for_repin(ike)
            .unwrap();

        let mut esp_with_ike_counter = valid_resume(esp, ResumeKeySource::LiveMirrored);
        esp_with_ike_counter.outbound_iv = counter_outbound_iv(
            10,
            10 + FORWARD_JUMP,
            Some(SendIvForwardJump {
                forward_jump: FORWARD_JUMP,
                counter_mode: SendIvCounterMode::IkeAeadExplicitIv64,
            }),
        );
        assert!(matches!(
            esp_with_ike_counter.validate_for_repin(esp),
            Err(IpsecLbError::UnsafeResume { .. })
        ));

        let mut ike_with_esp_counter = valid_resume(ike, ResumeKeySource::LiveMirrored);
        ike_with_esp_counter.outbound_iv = counter_outbound_iv(
            10,
            10 + FORWARD_JUMP,
            Some(SendIvForwardJump {
                forward_jump: FORWARD_JUMP,
                counter_mode: SendIvCounterMode::EspExtendedSequenceNumbers {
                    max_peer_sequence_lag: 0,
                },
            }),
        );
        assert!(matches!(
            ike_with_esp_counter.validate_for_repin(ike),
            Err(IpsecLbError::UnsafeResume { .. })
        ));
    }

    #[test]
    fn same_spi_resume_random_iv_mode_rejects_esp_and_unspecified_evidence() {
        let ike = SaId::Ike { responder_spi: 1 };
        let esp = SaId::Esp { spi: 1 };

        let esp_random_iv = SameSpiResume {
            previous_sa: esp,
            resumed_sa: esp,
            outbound_iv: SameSpiOutboundIvResume::IkeRandomIv {
                attestation: IkeRandomIvAttestation::FreshIndependentCsprngIvPerMessage,
            },
            anti_replay: AntiReplayResume::ExactWindowRestore {
                checkpoint_highest_accepted: 20,
                restored_highest_accepted: 20,
            },
            key_source: ResumeKeySource::LiveMirrored,
        };
        assert!(matches!(
            esp_random_iv.validate_for_repin(esp),
            Err(IpsecLbError::UnsafeResume { .. })
        ));

        for sa in [ike, esp] {
            let mut unspecified = valid_resume(sa, ResumeKeySource::PersistedKeyMaterial);
            unspecified.outbound_iv = SameSpiOutboundIvResume::Unspecified;
            assert!(matches!(
                unspecified.validate_for_repin(sa),
                Err(IpsecLbError::UnsafeResume { .. })
            ));
        }
    }

    #[test]
    fn outbound_iv_resume_rejections_do_not_expose_sa_or_counter_values() {
        let sa = SaId::Ike {
            responder_spi: 0x1122_3344_5566_7788,
        };
        let evidence = SameSpiResume {
            previous_sa: sa,
            resumed_sa: sa,
            outbound_iv: SameSpiOutboundIvResume::CounterBased {
                checkpointed_send_iv_next: 987_654_321,
                restored_send_iv_next: 1_234_567_890,
                forward_jump: None,
            },
            anti_replay: AntiReplayResume::ExactWindowRestore {
                checkpoint_highest_accepted: 20,
                restored_highest_accepted: 20,
            },
            key_source: ResumeKeySource::PersistedKeyMaterial,
        };
        let error = evidence.validate_for_repin(sa).unwrap_err();
        let rendered = format!("{error:?} {error}");

        for forbidden in [
            "1122334455667788",
            "1234605616436508552",
            "987654321",
            "1234567890",
        ] {
            assert!(!rendered.contains(forbidden));
        }
    }

    #[test]
    fn same_spi_resume_random_iv_mode_keeps_common_safety_evidence_mandatory() {
        let sa = SaId::Ike { responder_spi: 1 };

        let fallback = valid_random_iv_ike_resume(ResumeKeySource::RekeyOrReattachFallback);
        assert!(matches!(
            fallback.validate_for_repin(sa),
            Err(IpsecLbError::UnsafeResume { .. })
        ));

        let mut identity_mismatch =
            valid_random_iv_ike_resume(ResumeKeySource::PersistedKeyMaterial);
        identity_mismatch.resumed_sa = SaId::Ike { responder_spi: 2 };
        assert!(matches!(
            identity_mismatch.validate_for_repin(sa),
            Err(IpsecLbError::UnsafeResume { .. })
        ));

        let mut replay_rollback = valid_random_iv_ike_resume(ResumeKeySource::LiveMirrored);
        replay_rollback.anti_replay = AntiReplayResume::ExactWindowRestore {
            checkpoint_highest_accepted: 20,
            restored_highest_accepted: 19,
        };
        assert!(matches!(
            replay_rollback.validate_for_repin(sa),
            Err(IpsecLbError::UnsafeResume { .. })
        ));
    }

    #[test]
    fn same_spi_resume_rejects_replay_checkpoint_rollback() {
        let sa = SaId::Esp { spi: 1 };
        let mut replay_rollback = valid_resume(sa, ResumeKeySource::LiveMirrored);
        replay_rollback.anti_replay = AntiReplayResume::ExactWindowRestore {
            checkpoint_highest_accepted: 20,
            restored_highest_accepted: 19,
        };
        assert!(matches!(
            replay_rollback.validate_for_repin(sa),
            Err(IpsecLbError::UnsafeResume { .. })
        ));
    }

    #[test]
    fn repin_request_requires_rule_key_to_match_fenced_sa_protocol_and_spi() {
        let sa = SaId::Esp { spi: 0x0101 };
        let base = RePinRequest {
            sa,
            transition_id: OwnershipTransitionId::new(1).unwrap(),
            previous_fence: OwnershipFence::new(1).unwrap(),
            previous_owner: ClusterNode::new("worker-a"),
            new_owner: ClusterNode::new("worker-b"),
            rule: SteeringRule {
                shard: crate::model::ShardId::new(1),
                owner: crate::model::ShardId::new(2),
                key: SteerKey::EspSpi(0x0101),
            },
            ownership_key: ownership_key(sa),
            outbound_sa_binding_id: outbound_sa_binding_id(sa),
            resume: valid_resume(sa, ResumeKeySource::LiveMirrored),
        };
        validate_request(&base).unwrap();

        let wrong_spi = RePinRequest {
            rule: SteeringRule {
                key: SteerKey::EspSpi(0x0102),
                ..base.rule
            },
            ..base.clone()
        };
        assert!(matches!(
            validate_request(&wrong_spi),
            Err(IpsecLbError::InvalidConfig { field: "rule", .. })
        ));

        let ike_key = RePinRequest {
            rule: SteeringRule {
                key: SteerKey::IkeResponderSpi(1),
                ..base.rule
            },
            ..base
        };
        assert!(matches!(
            validate_request(&ike_key),
            Err(IpsecLbError::InvalidConfig { field: "rule", .. })
        ));

        let ike_sa = SaId::Ike { responder_spi: 7 };
        let ike_request = RePinRequest {
            sa: ike_sa,
            transition_id: OwnershipTransitionId::new(2).unwrap(),
            previous_fence: OwnershipFence::new(1).unwrap(),
            previous_owner: ClusterNode::new("worker-a"),
            new_owner: ClusterNode::new("worker-b"),
            rule: SteeringRule {
                shard: crate::model::ShardId::new(1),
                owner: crate::model::ShardId::new(2),
                key: SteerKey::IkeResponderSpi(7),
            },
            ownership_key: ownership_key(ike_sa),
            outbound_sa_binding_id: outbound_sa_binding_id(ike_sa),
            resume: valid_resume(ike_sa, ResumeKeySource::LiveMirrored),
        };
        validate_request(&ike_request).unwrap();

        let wrong_responder_spi = RePinRequest {
            rule: SteeringRule {
                key: SteerKey::IkeResponderSpi(8),
                ..ike_request.rule
            },
            ..ike_request
        };
        assert!(matches!(
            validate_request(&wrong_responder_spi),
            Err(IpsecLbError::InvalidConfig { field: "rule", .. })
        ));
    }

    #[test]
    fn forwarding_proof_must_match_sa_and_fence() {
        let sa = SaId::Esp { spi: 1 };
        let fence = OwnershipFence::new(7).unwrap();
        assert!(ForwardingProof::new(sa, fence, 0).is_err());

        let outcome = RePinOutcome::new(
            sa,
            fence,
            SteeringRule {
                shard: crate::model::ShardId::new(1),
                owner: crate::model::ShardId::new(2),
                key: crate::model::SteerKey::EspSpi(1),
            },
        );
        let wrong_sa = ForwardingProof::new(SaId::Esp { spi: 2 }, fence, 1).unwrap();
        assert!(matches!(
            outcome.with_forwarding_proof(wrong_sa).unwrap_err(),
            IpsecLbError::ForwardingProofRejected { .. }
        ));
    }

    // ---------------------------------------------------------------------
    // First-activation request validation and fingerprint binding (#561).
    // ---------------------------------------------------------------------

    fn initial_ike_ownership_key() -> SessionOwnershipKey {
        SessionOwnershipKey::InitialIke(crate::ownership::InitialIkeOwnershipKey::new(
            DestinationContext::new(IpAddress::V4([192, 0, 2, 10]), RoutingDomainTag::new(7)),
            crate::ownership::OuterSourceTuple::new(IpAddress::V4([198, 51, 100, 4]), 500),
            IkeSpi::new(11).unwrap(),
            crate::ownership::InitialExchangeDiscriminator::new(1).unwrap(),
        ))
    }

    fn frozen_activation_request() -> OwnershipActivationRequest {
        let sa = SaId::Esp { spi: 0x0107 };
        OwnershipActivationRequest {
            sa,
            ownership_key: ownership_key(sa),
            transition_id: OwnershipTransitionId::new(7).unwrap(),
            owner: ClusterNode::new("worker-b"),
            rule: SteeringRule {
                shard: crate::model::ShardId::new(1),
                owner: crate::model::ShardId::new(2),
                key: SteerKey::EspSpi(0x0107),
            },
        }
    }

    #[test]
    fn activation_fingerprint_preserves_its_frozen_v1_encoding() {
        // A committed activation record stores this value. Changing the domain
        // separator or the hashed field set silently orphans every already
        // committed record, so the encoding is frozen by this constant.
        assert_eq!(
            frozen_activation_request()
                .activation_fingerprint()
                .as_bytes(),
            FROZEN_ACTIVATION_V1_FINGERPRINT
        );
    }

    #[test]
    fn activation_fingerprint_binds_every_safety_critical_request_component() {
        let base = frozen_activation_request();
        let expected = base.activation_fingerprint();
        assert_eq!(expected, base.clone().activation_fingerprint());

        let mutations = [
            OwnershipActivationRequest {
                sa: SaId::Esp { spi: 0x0108 },
                ..base.clone()
            },
            OwnershipActivationRequest {
                transition_id: OwnershipTransitionId::new(8).unwrap(),
                ..base.clone()
            },
            OwnershipActivationRequest {
                owner: ClusterNode::new("worker-y"),
                ..base.clone()
            },
            OwnershipActivationRequest {
                rule: SteeringRule {
                    shard: crate::model::ShardId::new(4),
                    ..base.rule
                },
                ..base.clone()
            },
            OwnershipActivationRequest {
                rule: SteeringRule {
                    owner: crate::model::ShardId::new(3),
                    ..base.rule
                },
                ..base.clone()
            },
            OwnershipActivationRequest {
                rule: SteeringRule {
                    key: SteerKey::EspSpi(0x0108),
                    ..base.rule
                },
                ..base.clone()
            },
            OwnershipActivationRequest {
                ownership_key: ownership_key(SaId::Esp { spi: 0x0108 }),
                ..base.clone()
            },
        ];

        for mutation in mutations {
            assert_ne!(expected, mutation.activation_fingerprint());
        }
    }

    #[test]
    fn activation_and_repin_fingerprints_never_collide_for_the_same_transition() {
        // The rustdoc on `activation_fingerprint` claims an activation record
        // can never be recovered as a re-pin grant and vice versa. This states
        // that invariant directly for an otherwise-identical transition.
        //
        // It is deliberately over-determined: the two domains also hash
        // different field sets, so this assertion alone survives a
        // domain-separator swap. What actually pins each separator is
        // `activation_fingerprint_preserves_its_frozen_v1_encoding` and its
        // re-pin twins.
        let sa = SaId::Esp { spi: 0x0107 };
        let activation = frozen_activation_request();
        let repin = frozen_counter_v5_request();
        assert_eq!(activation.sa, repin.sa);
        assert_eq!(activation.transition_id, repin.transition_id);
        assert_eq!(activation.ownership_key, repin.ownership_key);
        assert_eq!(activation.rule, repin.rule);
        assert_eq!(activation.owner, repin.new_owner);

        assert_ne!(
            activation.activation_fingerprint(),
            repin.ownership_fingerprint()
        );

        // The IKE twin uses the frozen v4 (non-counter) re-pin domain, so cover
        // that separator too rather than only the v5 counter one.
        let ike_activation = OwnershipActivationRequest {
            sa: SaId::Ike { responder_spi: 7 },
            ownership_key: ownership_key(SaId::Ike { responder_spi: 7 }),
            transition_id: OwnershipTransitionId::new(7).unwrap(),
            owner: ClusterNode::new("worker-b"),
            rule: SteeringRule {
                shard: crate::model::ShardId::new(1),
                owner: crate::model::ShardId::new(2),
                key: SteerKey::IkeResponderSpi(7),
            },
        };
        assert_ne!(
            ike_activation.activation_fingerprint(),
            frozen_random_iv_v4_request().ownership_fingerprint()
        );
        assert_ne!(sa, ike_activation.sa);
    }

    #[test]
    fn activation_request_rejects_every_incoherent_sa_rule_and_ownership_key() {
        let esp_key = ownership_key(SaId::Esp { spi: 0x0107 });
        let ike_key = ownership_key(SaId::Ike { responder_spi: 7 });
        let transition = OwnershipTransitionId::new(7).unwrap();
        let owner = ClusterNode::new("worker-b");
        let esp_rule = |key| SteeringRule {
            shard: crate::model::ShardId::new(1),
            owner: crate::model::ShardId::new(2),
            key,
        };

        // (label, built request, expected invalid-config field)
        let esp_cases: [(&str, Result<OwnershipActivationRequest, IpsecLbError>, &str); 5] = [
            (
                "ESP SA carrying an IKE steer key",
                OwnershipActivationRequest::new_esp(
                    0x0107,
                    transition,
                    owner.clone(),
                    esp_rule(SteerKey::IkeResponderSpi(0x0107)),
                    esp_key,
                ),
                "rule",
            ),
            (
                "ESP SA whose steer key names a different SPI",
                OwnershipActivationRequest::new_esp(
                    0x0107,
                    transition,
                    owner.clone(),
                    esp_rule(SteerKey::EspSpi(0x0108)),
                    esp_key,
                ),
                "rule",
            ),
            (
                // 0x0201/0x0202 rather than 0x1/0x2 only because `EspSpi`
                // refuses the reserved 0..=255 range outright.
                "ESP SPI 0x0201 with EspSpi(0x0202) in the ownership key",
                OwnershipActivationRequest::new_esp(
                    0x0201,
                    transition,
                    owner.clone(),
                    esp_rule(SteerKey::EspSpi(0x0201)),
                    ownership_key(SaId::Esp { spi: 0x0202 }),
                ),
                "ownership_key",
            ),
            (
                "ESP SA carrying an established-IKE ownership key",
                OwnershipActivationRequest::new_esp(
                    0x0107,
                    transition,
                    owner.clone(),
                    esp_rule(SteerKey::EspSpi(0x0107)),
                    ike_key,
                ),
                "ownership_key",
            ),
            (
                "ESP SA carrying an initial-IKE ownership key",
                OwnershipActivationRequest::new_esp(
                    0x0107,
                    transition,
                    owner.clone(),
                    esp_rule(SteerKey::EspSpi(0x0107)),
                    initial_ike_ownership_key(),
                ),
                "ownership_key",
            ),
        ];
        for (label, built, field) in esp_cases {
            match built {
                Err(IpsecLbError::InvalidConfig { field: actual, .. }) => {
                    assert_eq!(actual, field, "{label}");
                }
                other => panic!("{label} must be refused, got {other:?}"),
            }
        }

        let ike_cases: [(&str, Result<OwnershipActivationRequest, IpsecLbError>, &str); 3] = [
            (
                "IKE SA carrying an ESP steer key",
                OwnershipActivationRequest::new_ike(
                    7,
                    transition,
                    owner.clone(),
                    esp_rule(SteerKey::EspSpi(7)),
                    ike_key,
                ),
                "rule",
            ),
            (
                "IKE responder-SPI mismatch between the SA and the steer key",
                OwnershipActivationRequest::new_ike(
                    7,
                    transition,
                    owner.clone(),
                    esp_rule(SteerKey::IkeResponderSpi(8)),
                    ike_key,
                ),
                "rule",
            ),
            (
                "IKE responder-SPI mismatch between the SA and the ownership key",
                OwnershipActivationRequest::new_ike(
                    9,
                    transition,
                    owner.clone(),
                    esp_rule(SteerKey::IkeResponderSpi(9)),
                    ike_key,
                ),
                "ownership_key",
            ),
        ];
        for (label, built, field) in ike_cases {
            match built {
                Err(IpsecLbError::InvalidConfig { field: actual, .. }) => {
                    assert_eq!(actual, field, "{label}");
                }
                other => panic!("{label} must be refused, got {other:?}"),
            }
        }

        // A zero SA identifier is refused before any coherence check.
        assert!(matches!(
            OwnershipActivationRequest::new_esp(
                0,
                transition,
                owner.clone(),
                esp_rule(SteerKey::EspSpi(0)),
                esp_key,
            ),
            Err(IpsecLbError::InvalidConfig {
                field: "sa.spi",
                ..
            })
        ));
        assert!(matches!(
            OwnershipActivationRequest::new_ike(
                0,
                transition,
                owner,
                esp_rule(SteerKey::IkeResponderSpi(0)),
                ike_key,
            ),
            Err(IpsecLbError::InvalidConfig {
                field: "sa.responder_spi",
                ..
            })
        ));

        // The coherent shapes still build, so the table is not vacuously green.
        assert!(OwnershipActivationRequest::new_esp(
            0x0107,
            transition,
            ClusterNode::new("worker-b"),
            esp_rule(SteerKey::EspSpi(0x0107)),
            esp_key,
        )
        .is_ok());
        assert!(OwnershipActivationRequest::new_ike(
            7,
            transition,
            ClusterNode::new("worker-b"),
            esp_rule(SteerKey::IkeResponderSpi(7)),
            ike_key,
        )
        .is_ok());
    }
}
