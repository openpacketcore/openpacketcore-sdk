//! Kernel-independent re-pin coordination primitives.

use std::num::NonZeroU64;

use crate::error::IpsecLbError;
use crate::failover::{AntiReplayResume, SendIvCounter};
use crate::model::{ClusterNode, SaId, SteeringRule};
use crate::ports::{OwnershipFencer, RePinAuditSink, SteeringBackend};

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

/// Source of the resumed SA key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResumeKeySource {
    /// A live standby already held the SA keys before owner loss.
    LiveMirrored,
    /// No standby has keys; the caller must rekey or force UE re-attach.
    RekeyOrReattachFallback,
    /// Persisted key material was read on the re-pin path.
    PersistedKeyMaterial,
}

/// Evidence required before installing a same-SPI re-pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SameSpiResume {
    /// SA before owner loss.
    pub previous_sa: SaId,
    /// SA resumed on the survivor.
    pub resumed_sa: SaId,
    /// Next outbound IV/counter value previously observed.
    pub previous_send_iv_next: u64,
    /// Next outbound IV/counter value restored on the survivor.
    pub restored_send_iv_next: u64,
    /// Anti-replay restore evidence.
    pub anti_replay: AntiReplayResume,
    /// Key-custody path used for the resumed SA.
    pub key_source: ResumeKeySource,
}

impl SameSpiResume {
    /// Validate that this evidence can support near-hitless same-SPI re-pin.
    pub fn validate_for_repin(self, expected_sa: SaId) -> Result<(), IpsecLbError> {
        if self.previous_sa != expected_sa || self.resumed_sa != expected_sa {
            return Err(IpsecLbError::unsafe_resume(
                "same-SPI re-pin requires the resumed SA to keep the original inbound SPI",
            ));
        }
        match self.key_source {
            ResumeKeySource::LiveMirrored => {}
            ResumeKeySource::RekeyOrReattachFallback => {
                return Err(IpsecLbError::unsafe_resume(
                    "rekey or UE re-attach fallback cannot claim same-SPI re-pin",
                ));
            }
            ResumeKeySource::PersistedKeyMaterial => {
                return Err(IpsecLbError::unsafe_resume(
                    "persisted key material is not allowed on the re-pin path",
                ));
            }
        }
        SendIvCounter::validate_restored_next(
            self.restored_send_iv_next,
            self.previous_send_iv_next,
        )?;
        self.anti_replay.validate()
    }
}

/// Request to fence ownership and install a steer override for a resumed SA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RePinRequest {
    /// SA being re-pinned.
    pub sa: SaId,
    /// Owner expected before the transition.
    pub previous_owner: ClusterNode,
    /// New owner after failover.
    pub new_owner: ClusterNode,
    /// Steering override to install after fencing.
    pub rule: SteeringRule,
    /// Same-SPI resume evidence.
    pub resume: SameSpiResume,
}

/// Ownership fence mutation request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipFenceRequest {
    /// SA being fenced.
    pub sa: SaId,
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
    /// Owner holding the granted fence.
    pub owner: ClusterNode,
    /// Monotonic fence token.
    pub fence: OwnershipFence,
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
    /// Re-pin failed after the initial attempt audit.
    Failed,
}

/// Redaction-safe re-pin audit event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RePinAuditEvent {
    /// Event kind.
    pub kind: RePinAuditEventKind,
    /// SA being re-pinned.
    pub sa: SaId,
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

/// Coordinates audited, fenced re-pin before steering override installation.
#[derive(Debug, Clone)]
pub struct RePinCoordinator<B, F, A> {
    steering: B,
    fencer: F,
    audit: A,
}

impl<B, F, A> RePinCoordinator<B, F, A>
where
    B: SteeringBackend,
    F: OwnershipFencer,
    A: RePinAuditSink,
{
    /// Build a coordinator from explicit ports.
    #[must_use]
    pub const fn new(steering: B, fencer: F, audit: A) -> Self {
        Self {
            steering,
            fencer,
            audit,
        }
    }

    /// Validate resume evidence, fence ownership, audit the transition, and
    /// install the steering override.
    pub async fn repin(&self, request: RePinRequest) -> Result<RePinOutcome, IpsecLbError> {
        validate_request(&request)?;
        request.resume.validate_for_repin(request.sa)?;

        self.audit
            .record_repin(RePinAuditEvent::attempt(&request))
            .await?;

        let fence_request = OwnershipFenceRequest {
            sa: request.sa,
            previous_owner: request.previous_owner.clone(),
            new_owner: request.new_owner.clone(),
        };
        let grant = match self.fencer.fence_sa_owner(fence_request).await {
            Ok(grant) => grant,
            Err(error) => {
                record_failure(&self.audit, &request, None, &error).await;
                return Err(error);
            }
        };

        // Do not trust the fencer port blindly: a grant for a different SA or a
        // different owner would install a steering override toward the wrong
        // node. Reject it before any steering mutation.
        if grant.sa != request.sa || grant.owner != request.new_owner {
            let error = IpsecLbError::ownership_conflict(
                "fence grant does not match the requested SA and new owner",
            );
            record_failure(&self.audit, &request, Some(grant.fence), &error).await;
            return Err(error);
        }

        self.audit
            .record_repin(RePinAuditEvent::fenced(&request, grant.fence))
            .await?;

        if let Err(error) = self.steering.install_rule(request.rule).await {
            record_failure(&self.audit, &request, Some(grant.fence), &error).await;
            return Err(error);
        }

        self.audit
            .record_repin(RePinAuditEvent::steering_installed(&request, grant.fence))
            .await?;
        Ok(RePinOutcome::new(request.sa, grant.fence, request.rule))
    }
}

fn validate_request(request: &RePinRequest) -> Result<(), IpsecLbError> {
    if request.previous_owner == request.new_owner {
        return Err(IpsecLbError::invalid_config(
            "new_owner",
            "re-pin requires a different owner",
        ));
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

    #[test]
    fn same_spi_resume_rejects_key_custody_and_state_rollbacks() {
        let sa = SaId::Esp { spi: 1 };
        let mut resume = SameSpiResume {
            previous_sa: sa,
            resumed_sa: sa,
            previous_send_iv_next: 10,
            restored_send_iv_next: 11,
            anti_replay: AntiReplayResume {
                previous_highest_accepted: 20,
                restored_highest_accepted: 20,
            },
            key_source: ResumeKeySource::LiveMirrored,
        };
        resume.validate_for_repin(sa).unwrap();

        resume.restored_send_iv_next = 9;
        assert!(matches!(
            resume.validate_for_repin(sa).unwrap_err(),
            IpsecLbError::UnsafeResume { .. }
        ));

        resume.restored_send_iv_next = 11;
        resume.key_source = ResumeKeySource::PersistedKeyMaterial;
        assert!(matches!(
            resume.validate_for_repin(sa).unwrap_err(),
            IpsecLbError::UnsafeResume { .. }
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
