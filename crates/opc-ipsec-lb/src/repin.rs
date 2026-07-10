//! Kernel-independent re-pin coordination primitives.

use std::num::{NonZeroU128, NonZeroU64};

use sha2::{Digest, Sha256};

use crate::error::IpsecLbError;
use crate::failover::{AntiReplayResume, SendIvCounterMode, SendIvForwardJump};
use crate::model::{ClusterNode, IpAddress, SaId, SteerKey, SteeringRule};
use crate::ports::{OwnershipFencer, OwnershipSource, RePinAuditSink, SteeringBackend};

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct OwnershipTransitionId(NonZeroU128);

impl OwnershipTransitionId {
    /// Build a non-zero transition identity.
    pub fn new(value: u128) -> Result<Self, IpsecLbError> {
        let Some(value) = NonZeroU128::new(value) else {
            return Err(IpsecLbError::invalid_config(
                "transition_id",
                "ownership transition ID must be non-zero",
            ));
        };
        Ok(Self(value))
    }

    /// Return the numeric transition identity.
    #[must_use]
    pub const fn get(self) -> u128 {
        self.0.get()
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
    /// Live mirroring does not make the mirrored send counter current at the
    /// instant of failure, so it requires the same forward-jump as persistence.
    LiveMirrored,
    /// No standby has keys; the caller must rekey or force UE re-attach.
    RekeyOrReattachFallback,
    /// Persisted key material was read on the re-pin path.
    ///
    /// Same-SPI use is safe only with a validated outbound IV forward-jump.
    PersistedKeyMaterial,
}

/// Evidence required before installing an IPsec/IKE same-SPI re-pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SameSpiResume {
    /// SA before owner loss.
    pub previous_sa: SaId,
    /// SA resumed on the survivor.
    pub resumed_sa: SaId,
    /// Last checkpointed or mirrored next outbound IV/counter value.
    ///
    /// This is a stale lower bound, not proof that the old owner stopped before
    /// consuming later counter values. ESP checkpoints must be non-zero, and
    /// the ESP counter-mode evidence defines peer receive lag relative to this
    /// value minus one.
    pub checkpointed_send_iv_next: u64,
    /// Next outbound IV/counter value actually restored on the survivor.
    pub restored_send_iv_next: u64,
    /// Mandatory stale-counter forward-jump evidence.
    ///
    /// `None` is representable so decoded or legacy requests can be rejected at
    /// the re-pin boundary. Both persisted and live-mirrored resumes require a
    /// valid proof.
    pub send_iv_forward_jump: Option<SendIvForwardJump>,
    /// Anti-replay restore evidence.
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

        let Some(forward_jump) = self.send_iv_forward_jump else {
            return Err(IpsecLbError::unsafe_resume(
                "same-SPI re-pin requires send IV forward-jump evidence",
            ));
        };
        forward_jump.validate_restored_next(
            expected_sa,
            self.checkpointed_send_iv_next,
            self.restored_send_iv_next,
        )?;
        self.anti_replay.validate()
    }
}

/// Request to fence ownership and install a steer override for a resumed SA.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// Same-SPI resume evidence.
    pub resume: SameSpiResume,
}

impl RePinRequest {
    /// Hash the complete safety-critical request into a stable transition
    /// fingerprint used by ownership commit and recovery.
    #[must_use]
    pub fn ownership_fingerprint(&self) -> OwnershipTransitionFingerprint {
        let mut hasher = Sha256::new();
        hasher.update(b"opc-ipsec-lb/repin-transition/v1");
        hasher.update(self.transition_id.get().to_be_bytes());
        hasher.update(self.previous_fence.get().to_be_bytes());
        hash_sa(&mut hasher, self.sa);
        hash_bytes(&mut hasher, self.previous_owner.as_str().as_bytes());
        hash_bytes(&mut hasher, self.new_owner.as_str().as_bytes());
        hasher.update(self.rule.shard.get().to_be_bytes());
        hasher.update(self.rule.owner.get().to_be_bytes());
        hash_steer_key(&mut hasher, self.rule.key);
        hash_resume(&mut hasher, self.resume);
        OwnershipTransitionFingerprint(hasher.finalize().into())
    }
}

/// Ownership fence mutation request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipFenceRequest {
    /// SA being fenced.
    pub sa: SaId,
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

/// Successful ownership fence grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipFenceGrant {
    /// SA that was fenced.
    pub sa: SaId,
    /// Transition identity committed with the ownership record.
    pub transition_id: OwnershipTransitionId,
    /// Fingerprint committed with the transition.
    pub fingerprint: OwnershipTransitionFingerprint,
    /// Owner holding the granted fence.
    pub owner: ClusterNode,
    /// Monotonic fence token.
    pub fence: OwnershipFence,
}

/// Evidence presented when resuming work after ownership was committed.
///
/// The fields are construction-private because only a coordinator that has
/// checked a matching fence grant may issue this proof. The proof is still
/// treated as untrusted on retry: [`OwnershipFencer::validate_retry_proof`]
/// must match its SA, owner, and exact fence against authoritative state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipRetryProof {
    sa: SaId,
    transition_id: OwnershipTransitionId,
    fingerprint: OwnershipTransitionFingerprint,
    owner: ClusterNode,
    fence: OwnershipFence,
}

impl OwnershipRetryProof {
    pub(crate) fn from_grant(grant: &OwnershipFenceGrant) -> Self {
        Self {
            sa: grant.sa,
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
    /// Re-pin failed before a verified ownership grant was available.
    ///
    /// Recoverable post-commit failures are returned immediately as
    /// [`RePinPartialFailure`] and deliberately do not wait on best-effort
    /// failure auditing, which could strand the retry state.
    Failed,
}

/// Redaction-safe re-pin audit event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RePinAuditEvent {
    /// Event kind.
    pub kind: RePinAuditEventKind,
    /// SA being re-pinned.
    pub sa: SaId,
    /// Stable transition correlation identity.
    ///
    /// This field is not an idempotency key by itself or when paired only with
    /// [`RePinAuditEventKind`]; sinks deduplicate the complete event so distinct
    /// failed attempts retain their failure codes.
    pub transition_id: OwnershipTransitionId,
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

impl RePinAuditEvent {
    fn attempt(request: &RePinRequest) -> Self {
        Self {
            kind: RePinAuditEventKind::Attempt,
            sa: request.sa,
            transition_id: request.transition_id,
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
            transition_id: request.transition_id,
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
            transition_id: request.transition_id,
            previous_owner: request.previous_owner.clone(),
            new_owner: request.new_owner.clone(),
            fence: Some(fence),
            forwarding_proven: false,
            failure_code: None,
        }
    }

    fn failed(request: &RePinRequest, fence: Option<OwnershipFence>, error: &IpsecLbError) -> Self {
        Self {
            kind: RePinAuditEventKind::Failed,
            sa: request.sa,
            transition_id: request.transition_id,
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
/// Retry resumes at this exact stage. Earlier successful stages are never
/// repeated, so a final audit retry cannot reinstall an already-active rule.
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
#[derive(Debug, PartialEq, Eq)]
pub struct RePinPartialFailure {
    request: RePinRequest,
    retry_proof: OwnershipRetryProof,
    resume_at: RePinRetryStage,
    cause: IpsecLbError,
}

impl RePinPartialFailure {
    fn new(
        request: RePinRequest,
        retry_proof: OwnershipRetryProof,
        resume_at: RePinRetryStage,
        cause: IpsecLbError,
    ) -> Self {
        Self {
            request,
            retry_proof,
            resume_at,
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
}

impl<B, F, O, A> RePinCoordinator<B, F, O, A>
where
    B: SteeringBackend,
    F: OwnershipFencer,
    O: OwnershipSource,
    A: RePinAuditSink,
{
    /// Build a coordinator from explicit ports.
    #[must_use]
    pub const fn new(steering: B, fencer: F, ownership: O, audit: A) -> Self {
        Self {
            steering,
            fencer,
            ownership,
            audit,
        }
    }

    /// Validate resume evidence and the target-shard binding, recover or fence
    /// ownership, audit the transition, and install the steering override.
    ///
    /// Recovery is checked before mutation, making a cloned request safe to
    /// replay when cancellation or an ambiguous fencer result may have hidden
    /// a committed grant. A recovered transition resumes at the fenced-audit
    /// stage with the exact current fence.
    pub async fn repin(&self, request: RePinRequest) -> Result<RePinOutcome, RePinError> {
        self.validate_pre_commit(&request)
            .await
            .map_err(RePinError::BeforeOwnershipCommit)?;

        let fence_request = OwnershipFenceRequest {
            sa: request.sa,
            transition_id: request.transition_id,
            fingerprint: request.ownership_fingerprint(),
            previous_fence: request.previous_fence,
            previous_owner: request.previous_owner.clone(),
            new_owner: request.new_owner.clone(),
        };
        match self.fencer.recover_fence_grant(&fence_request).await {
            Ok(Some(grant)) => return self.continue_from_grant(request, grant).await,
            Ok(None) => {}
            Err(error) => return Err(RePinError::BeforeOwnershipCommit(error)),
        }

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

        self.continue_from_grant(request, grant).await
    }

    async fn continue_from_grant(
        &self,
        request: RePinRequest,
        grant: OwnershipFenceGrant,
    ) -> Result<RePinOutcome, RePinError> {
        // Do not trust the fencer port blindly: a grant for a different SA or a
        // different owner would install a steering override toward the wrong
        // node. Reject it before any steering mutation.
        if grant.sa != request.sa
            || grant.transition_id != request.transition_id
            || grant.fingerprint != request.ownership_fingerprint()
            || grant.owner != request.new_owner
        {
            let error = IpsecLbError::ownership_conflict(
                "fence grant does not match the requested SA and new owner",
            );
            return Err(RePinError::BeforeOwnershipCommit(error));
        }

        let retry_proof = OwnershipRetryProof::from_grant(&grant);
        // A shape-matching successful grant is post-commit by the fencer port
        // contract, but it is not enough to emit an authoritative Fenced audit
        // event. Confirm its exact store-backed fence first. Preserve the
        // single-use retry state on a transient or stale read: retry validates
        // again before any side effect, while a forged proof remains inert.
        if let Err(error) = self.fencer.validate_retry_proof(&retry_proof).await {
            return Err(RePinError::AfterOwnershipCommit(Box::new(
                RePinPartialFailure::new(request, retry_proof, RePinRetryStage::FencedAudit, error),
            )));
        }
        self.continue_committed(request, retry_proof, RePinRetryStage::FencedAudit)
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

        // Steering-install resumes validate the proof immediately beside that
        // mutation below. The audit stages need validation here so no audit
        // side effect can occur under a stale or forged proof.
        if partial.resume_at != RePinRetryStage::SteeringInstall {
            if let Err(error) = self.fencer.validate_retry_proof(&partial.retry_proof).await {
                return Err(RePinError::AfterOwnershipCommit(Box::new(
                    partial.with_cause(error),
                )));
            }
        }

        self.continue_committed(partial.request, partial.retry_proof, partial.resume_at)
            .await
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

    async fn continue_committed(
        &self,
        request: RePinRequest,
        retry_proof: OwnershipRetryProof,
        resume_at: RePinRetryStage,
    ) -> Result<RePinOutcome, RePinError> {
        let fence = retry_proof.fence;

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
                        error,
                    ),
                )));
            }
        }

        if matches!(
            resume_at,
            RePinRetryStage::FencedAudit | RePinRetryStage::SteeringInstall
        ) {
            // The initial target-owner read precedes multiple awaited effects.
            // Re-read it and the exact SA fence as late as the current ports
            // permit so a change during fencing/audit fails closed before the
            // steering mutation. Atomic cross-resource ordering still belongs
            // in a fence-aware steering backend.
            if let Err(error) = self.fencer.validate_retry_proof(&retry_proof).await {
                return Err(RePinError::AfterOwnershipCommit(Box::new(
                    RePinPartialFailure::new(
                        request,
                        retry_proof,
                        RePinRetryStage::SteeringInstall,
                        error,
                    ),
                )));
            }
            // The ownership port cannot atomically bind shard and SA records,
            // so leave the target-owner snapshot as the last awaited check
            // before steering. A fence-aware backend is still required for a
            // strict cross-resource atomicity guarantee.
            if let Err(error) = self.validate_target_owner(&request).await {
                return Err(RePinError::AfterOwnershipCommit(Box::new(
                    RePinPartialFailure::new(
                        request,
                        retry_proof,
                        RePinRetryStage::SteeringInstall,
                        error,
                    ),
                )));
            }
            if let Err(error) = self.steering.install_rule(request.rule).await {
                return Err(RePinError::AfterOwnershipCommit(Box::new(
                    RePinPartialFailure::new(
                        request,
                        retry_proof,
                        RePinRetryStage::SteeringInstall,
                        error,
                    ),
                )));
            }
        }

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
                    error,
                ),
            )));
        }

        Ok(RePinOutcome::new(request.sa, fence, request.rule))
    }
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

fn hash_resume(hasher: &mut Sha256, resume: SameSpiResume) {
    hash_sa(hasher, resume.previous_sa);
    hash_sa(hasher, resume.resumed_sa);
    hasher.update(resume.checkpointed_send_iv_next.to_be_bytes());
    hasher.update(resume.restored_send_iv_next.to_be_bytes());
    match resume.send_iv_forward_jump {
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

fn validate_request(request: &RePinRequest) -> Result<(), IpsecLbError> {
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
    Ok(())
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
        IpsecLbError::Unsupported => "unsupported",
        IpsecLbError::AlreadyExists => "already_exists",
        IpsecLbError::NotFound => "not_found",
        IpsecLbError::OwnershipConflict { .. } => "ownership_conflict",
        IpsecLbError::ForwardingProofRejected { .. } => "forwarding_proof_rejected",
        IpsecLbError::UnsafeResume { .. } => "unsafe_resume",
        IpsecLbError::CookieRejected => "cookie_rejected",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::failover::SendIvCounterMode;

    const FORWARD_JUMP: u64 = crate::failover::MIN_SEND_IV_FORWARD_JUMP;

    fn valid_resume(sa: SaId, key_source: ResumeKeySource) -> SameSpiResume {
        let counter_mode = match sa {
            SaId::Esp { .. } => SendIvCounterMode::EspExtendedSequenceNumbers {
                max_peer_sequence_lag: 0,
            },
            SaId::Ike { .. } => SendIvCounterMode::IkeAeadExplicitIv64,
        };
        SameSpiResume {
            previous_sa: sa,
            resumed_sa: sa,
            checkpointed_send_iv_next: 10,
            restored_send_iv_next: 10 + FORWARD_JUMP,
            send_iv_forward_jump: Some(SendIvForwardJump {
                forward_jump: FORWARD_JUMP,
                counter_mode,
            }),
            anti_replay: AntiReplayResume::ExactWindowRestore {
                checkpoint_highest_accepted: 20,
                restored_highest_accepted: 20,
            },
            key_source,
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
    fn ownership_fingerprint_binds_every_safety_critical_request_component() {
        let sa = SaId::Esp { spi: 7 };
        let base = RePinRequest {
            sa,
            transition_id: OwnershipTransitionId::new(7).unwrap(),
            previous_fence: OwnershipFence::new(3).unwrap(),
            previous_owner: ClusterNode::new("worker-a"),
            new_owner: ClusterNode::new("worker-b"),
            rule: SteeringRule {
                shard: crate::model::ShardId::new(1),
                owner: crate::model::ShardId::new(2),
                key: SteerKey::EspSpi(7),
            },
            resume: valid_resume(sa, ResumeKeySource::LiveMirrored),
        };
        let expected = base.ownership_fingerprint();
        assert_eq!(expected, base.clone().ownership_fingerprint());

        let mutations = [
            RePinRequest {
                sa: SaId::Esp { spi: 8 },
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
                    key: SteerKey::EspSpi(8),
                    ..base.rule
                },
                ..base.clone()
            },
            RePinRequest {
                resume: SameSpiResume {
                    previous_sa: SaId::Esp { spi: 8 },
                    ..base.resume
                },
                ..base.clone()
            },
            RePinRequest {
                resume: SameSpiResume {
                    resumed_sa: SaId::Esp { spi: 8 },
                    ..base.resume
                },
                ..base.clone()
            },
            RePinRequest {
                resume: SameSpiResume {
                    checkpointed_send_iv_next: base.resume.checkpointed_send_iv_next + 1,
                    restored_send_iv_next: base.resume.restored_send_iv_next + 1,
                    ..base.resume
                },
                ..base.clone()
            },
            RePinRequest {
                resume: SameSpiResume {
                    send_iv_forward_jump: None,
                    ..base.resume
                },
                ..base.clone()
            },
            RePinRequest {
                resume: SameSpiResume {
                    restored_send_iv_next: base.resume.restored_send_iv_next + 1,
                    send_iv_forward_jump: Some(SendIvForwardJump {
                        forward_jump: FORWARD_JUMP + 1,
                        counter_mode: SendIvCounterMode::EspExtendedSequenceNumbers {
                            max_peer_sequence_lag: 0,
                        },
                    }),
                    ..base.resume
                },
                ..base.clone()
            },
            RePinRequest {
                resume: SameSpiResume {
                    send_iv_forward_jump: Some(SendIvForwardJump {
                        forward_jump: FORWARD_JUMP,
                        counter_mode: SendIvCounterMode::EspExtendedSequenceNumbers {
                            max_peer_sequence_lag: 1,
                        },
                    }),
                    ..base.resume
                },
                ..base.clone()
            },
            RePinRequest {
                resume: SameSpiResume {
                    send_iv_forward_jump: Some(SendIvForwardJump {
                        forward_jump: FORWARD_JUMP,
                        counter_mode: SendIvCounterMode::IkeAeadExplicitIv64,
                    }),
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
    fn ownership_transition_id_rejects_zero() {
        assert!(matches!(
            OwnershipTransitionId::new(0),
            Err(IpsecLbError::InvalidConfig {
                field: "transition_id",
                ..
            })
        ));
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
        let sa = SaId::Esp { spi: 1 };

        for key_source in [
            ResumeKeySource::LiveMirrored,
            ResumeKeySource::PersistedKeyMaterial,
        ] {
            let mut missing = valid_resume(sa, key_source);
            missing.send_iv_forward_jump = None;
            assert!(matches!(
                missing.validate_for_repin(sa),
                Err(IpsecLbError::UnsafeResume { .. })
            ));
        }

        let mut below_floor = valid_resume(sa, ResumeKeySource::PersistedKeyMaterial);
        below_floor.restored_send_iv_next = 10 + FORWARD_JUMP - 1;
        below_floor.send_iv_forward_jump = Some(SendIvForwardJump {
            forward_jump: FORWARD_JUMP - 1,
            counter_mode: SendIvCounterMode::EspExtendedSequenceNumbers {
                max_peer_sequence_lag: 0,
            },
        });
        assert!(matches!(
            below_floor.validate_for_repin(sa),
            Err(IpsecLbError::UnsafeResume { .. })
        ));

        let mut wrong_protocol = valid_resume(sa, ResumeKeySource::LiveMirrored);
        wrong_protocol.send_iv_forward_jump = Some(SendIvForwardJump {
            forward_jump: FORWARD_JUMP,
            counter_mode: SendIvCounterMode::IkeAeadExplicitIv64,
        });
        assert!(matches!(
            wrong_protocol.validate_for_repin(sa),
            Err(IpsecLbError::UnsafeResume { .. })
        ));

        let mut mismatch = valid_resume(sa, ResumeKeySource::PersistedKeyMaterial);
        mismatch.restored_send_iv_next -= 1;
        assert!(matches!(
            mismatch.validate_for_repin(sa),
            Err(IpsecLbError::UnsafeResume { .. })
        ));

        let mut exhausted = valid_resume(sa, ResumeKeySource::PersistedKeyMaterial);
        exhausted.checkpointed_send_iv_next = u64::MAX - FORWARD_JUMP + 1;
        exhausted.restored_send_iv_next = u64::MAX;
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
        esp_with_ike_counter.send_iv_forward_jump = Some(SendIvForwardJump {
            forward_jump: FORWARD_JUMP,
            counter_mode: SendIvCounterMode::IkeAeadExplicitIv64,
        });
        assert!(matches!(
            esp_with_ike_counter.validate_for_repin(esp),
            Err(IpsecLbError::UnsafeResume { .. })
        ));

        let mut ike_with_esp_counter = valid_resume(ike, ResumeKeySource::LiveMirrored);
        ike_with_esp_counter.send_iv_forward_jump = Some(SendIvForwardJump {
            forward_jump: FORWARD_JUMP,
            counter_mode: SendIvCounterMode::EspExtendedSequenceNumbers {
                max_peer_sequence_lag: 0,
            },
        });
        assert!(matches!(
            ike_with_esp_counter.validate_for_repin(ike),
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
        let sa = SaId::Esp { spi: 1 };
        let base = RePinRequest {
            sa,
            transition_id: OwnershipTransitionId::new(1).unwrap(),
            previous_fence: OwnershipFence::new(1).unwrap(),
            previous_owner: ClusterNode::new("worker-a"),
            new_owner: ClusterNode::new("worker-b"),
            rule: SteeringRule {
                shard: crate::model::ShardId::new(1),
                owner: crate::model::ShardId::new(2),
                key: SteerKey::EspSpi(1),
            },
            resume: valid_resume(sa, ResumeKeySource::LiveMirrored),
        };
        validate_request(&base).unwrap();

        let wrong_spi = RePinRequest {
            rule: SteeringRule {
                key: SteerKey::EspSpi(2),
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
}
