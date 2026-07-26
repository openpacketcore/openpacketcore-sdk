//! Reusable ports for VIP advertisement and SWu load balancing.

use async_trait::async_trait;

use crate::error::IpsecLbError;
use crate::model::{
    ClusterNode, SaId, ShardId, SteeringProbe, SteeringRule, VipAdvertisement, VipProbe,
};
use crate::ownership::SessionOwnershipKey;
use crate::repin::{
    OwnershipActivationGrant, OwnershipActivationRequest, OwnershipCleanupCompleteProof,
    OwnershipFenceGrant, OwnershipFenceRequest, OwnershipRetirementAdmission,
    OwnershipRetirementFinalization, OwnershipRetirementGrant, OwnershipRetirementRequest,
    OwnershipRetryProof, OwnershipSnapshot, RePinAuditEvent, RePinSteeringOperationPermit,
    RePinSteeringUpdate,
};
use crate::spi::{RekeyRequest, SpiAllocationRequest, SpiKind, TaggedSpi};

/// Tagged SPI allocator port.
pub trait SpiAllocator: Send + Sync + std::fmt::Debug {
    /// Allocate a fresh tagged inbound SPI.
    fn allocate(&self, request: SpiAllocationRequest) -> Result<TaggedSpi, IpsecLbError>;

    /// Allocate a rekey SPI that preserves the replaced SA's routing tag.
    fn allocate_rekey(&self, request: RekeyRequest) -> Result<TaggedSpi, IpsecLbError>;

    /// Decode a SPI into its routing tag and shard.
    fn decode(&self, kind: SpiKind, value: u64) -> Result<TaggedSpi, IpsecLbError>;
}

/// Steering backend port for XDP, VF, or NIC-offload implementations.
#[async_trait]
pub trait SteeringBackend: Send + Sync + std::fmt::Debug {
    /// Install a steering rule.
    ///
    /// Installing the exact same rule MUST be idempotent. A caller may repeat
    /// the operation after cancellation or an ambiguous acknowledgement; the
    /// backend must converge to one installed rule and return success. A rule
    /// for the same key with a different target remains a conflict unless the
    /// backend implements authoritative fence-aware replacement.
    async fn install_rule(&self, rule: SteeringRule) -> Result<(), IpsecLbError>;

    /// Remove a steering rule.
    async fn remove_rule(&self, rule: SteeringRule) -> Result<(), IpsecLbError>;

    /// Probe backend capability and readiness.
    async fn probe(&self) -> Result<SteeringProbe, IpsecLbError>;
}

/// Steering boundary used by the ownership-fenced re-pin coordinator.
///
/// Unlike [`SteeringBackend`], this port carries the exact destination-scoped
/// ownership key and authoritative generation. Host-XDP implementations must
/// converge the generation, install the owner, and read the exact result back
/// before returning success. Legacy SPI-only backends can opt in explicitly
/// through [`LegacySpiRuleRePinAdapter`]; there is no blanket conversion that
/// can silently discard authority fields.
#[async_trait]
pub trait RePinSteeringBackend: Send + Sync + std::fmt::Debug {
    /// Acquire a single-use operation permit for one exact ownership key.
    ///
    /// The coordinator acquires this before its final authoritative ownership
    /// validation. Backends that do not share an out-of-band mutable datapath
    /// may use the default opaque permit. Host-XDP overrides this with a
    /// backend-and-key-bound striped guard.
    async fn acquire_repin_permit(
        &self,
        ownership_key: SessionOwnershipKey,
    ) -> Result<RePinSteeringOperationPermit, IpsecLbError> {
        Ok(RePinSteeringOperationPermit::unguarded(ownership_key))
    }

    /// Apply one exact ownership-fenced re-pin update.
    ///
    /// The permit is consumed so it remains held inside a detached blocking
    /// mutation after caller cancellation and cannot be replayed.
    async fn apply_fenced_repin(
        &self,
        update: RePinSteeringUpdate,
        permit: RePinSteeringOperationPermit,
    ) -> Result<RePinSteeringOperationPermit, IpsecLbError>;
}

/// Exact Host steering cleanup boundary for a durably retiring activation.
///
/// There is deliberately no blanket implementation. A backend must preserve
/// the higher retirement fence as a fail-closed cut while removing only the
/// exact lower-generation owner, prove both maps absent, and return the
/// consumed permit so the coordinator can retain serialization until durable
/// `CleanupComplete` progress is committed.
#[async_trait]
pub trait RePinSteeringRetirementBackend: RePinSteeringBackend {
    /// Acquire cancellation-safe permits for an exact bounded session batch.
    ///
    /// Implementations must return one permit in the same order as the input
    /// keys. Backends whose serialization domains can collide must acquire
    /// each distinct domain once in a deterministic order and retain those
    /// guards until every returned permit is dropped. This prevents both
    /// self-deadlock and an activation crossing the session `Active` to
    /// `Retiring` durability cut.
    async fn acquire_repin_retirement_permits(
        &self,
        ownership_keys: Vec<SessionOwnershipKey>,
    ) -> Result<Vec<RePinSteeringOperationPermit>, IpsecLbError>;

    /// Arm a verified permit immediately before the owned worker begins the
    /// cancellation-ambiguous retirement CAS.
    ///
    /// Host-XDP poisons the fixed stripe if an armed permit is dropped before
    /// the worker classifies the store as exact `Retiring` or authoritatively
    /// unchanged. The consumed return value prevents reuse.
    fn arm_repin_retirement_permit(
        &self,
        permit: RePinSteeringOperationPermit,
    ) -> Result<RePinSteeringOperationPermit, IpsecLbError>;

    /// Release an armed permit after the ownership authority returned a
    /// conclusively non-ambiguous error.
    ///
    /// This method consumes and classifies the permit. It must not be invoked
    /// when the authority reports an indeterminate outcome; dropping that
    /// permit poisons the Host stripe instead.
    fn release_classified_repin_retirement_permit(
        &self,
        permit: RePinSteeringOperationPermit,
    ) -> Result<(), IpsecLbError>;

    /// Remove one exact durably retired steering activation.
    async fn retire_fenced_repin(
        &self,
        grant: &OwnershipRetirementGrant,
        permit: RePinSteeringOperationPermit,
    ) -> Result<RePinSteeringOperationPermit, IpsecLbError>;
}

/// Explicit compatibility wrapper for SPI-only steering backends.
///
/// This adapter intentionally discards the destination-scoped key and
/// generation after the coordinator has validated them. It is suitable only
/// for legacy backends whose own contract is SPI-rule scoped. Host-XDP does
/// not implement [`SteeringBackend`] and therefore cannot compose through this
/// lossy path.
#[derive(Debug, Clone)]
pub struct LegacySpiRuleRePinAdapter<B> {
    backend: B,
}

impl<B> LegacySpiRuleRePinAdapter<B> {
    /// Opt one legacy SPI-rule backend into the re-pin port.
    #[must_use]
    pub const fn new(backend: B) -> Self {
        Self { backend }
    }

    /// Borrow the wrapped legacy backend.
    #[must_use]
    pub const fn backend(&self) -> &B {
        &self.backend
    }

    /// Consume the wrapper and return the legacy backend.
    #[must_use]
    pub fn into_inner(self) -> B {
        self.backend
    }
}

#[async_trait]
impl<B> RePinSteeringBackend for LegacySpiRuleRePinAdapter<B>
where
    B: SteeringBackend,
{
    async fn apply_fenced_repin(
        &self,
        update: RePinSteeringUpdate,
        permit: RePinSteeringOperationPermit,
    ) -> Result<RePinSteeringOperationPermit, IpsecLbError> {
        if permit.ownership_key() != update.ownership_key() {
            return Err(IpsecLbError::adapter_contract_violation(
                "repin_operation_permit_key_mismatch",
            ));
        }
        if permit.has_esp_counter_publication_guard() {
            return Err(IpsecLbError::adapter_contract_violation(
                "legacy_repin_adapter_rejects_esp_counter_publication_guard",
            ));
        }
        self.backend.install_rule(update.rule()).await?;
        Ok(permit)
    }
}

/// VIP advertisement port.
#[async_trait]
pub trait VipAdvertiser: Send + Sync + std::fmt::Debug {
    /// Advertise a VIP from this node.
    async fn advertise(&self, advertisement: VipAdvertisement) -> Result<(), IpsecLbError>;

    /// Withdraw a VIP from this node.
    ///
    /// [`IpsecLbError::NotFound`] must mean that this exact advertisement is
    /// absent. A coordinator can treat that result as successful convergence
    /// while recovering from an ambiguous earlier provider mutation.
    async fn withdraw(&self, advertisement: VipAdvertisement) -> Result<(), IpsecLbError>;

    /// Probe advertiser capability and readiness.
    async fn probe(&self) -> Result<VipProbe, IpsecLbError>;
}

/// Read-only ownership source for shard and SA owners.
#[async_trait]
pub trait OwnershipSource: Send + Sync + std::fmt::Debug {
    /// Return the current owner for a shard.
    async fn shard_owner(&self, shard: ShardId) -> Result<Option<ClusterNode>, IpsecLbError>;

    /// Return the current authoritative owner and fence for an SA.
    async fn sa_ownership(&self, sa: SaId) -> Result<Option<OwnershipSnapshot>, IpsecLbError>;

    /// Return authoritative ownership for an exact destination-scoped SA key.
    ///
    /// Same-SPI Host-XDP re-pin must use this boundary. The legacy SPI-only
    /// lookup cannot distinguish equal SPIs in different destinations or
    /// routing domains and therefore cannot authorize destination-scoped
    /// publication.
    async fn scoped_sa_ownership(
        &self,
        _key: SessionOwnershipKey,
    ) -> Result<Option<OwnershipSnapshot>, IpsecLbError> {
        Err(IpsecLbError::Unsupported)
    }

    /// Return only the current owner for compatibility/read-only display.
    async fn sa_owner(&self, sa: SaId) -> Result<Option<ClusterNode>, IpsecLbError> {
        Ok(self
            .sa_ownership(sa)
            .await?
            .map(|snapshot| snapshot.owner().clone()))
    }
}

/// Ownership fencing port used before re-pinning a resumed SA.
#[async_trait]
pub trait OwnershipFencer: Send + Sync + std::fmt::Debug {
    /// Recover an authoritative grant for an ownership transition that may
    /// already have committed.
    ///
    /// This read-only operation returns the exact current grant only when the
    /// requested new owner, transition ID, and complete request fingerprint
    /// all match authoritative state; it returns `None` only when the expected
    /// previous owner still holds the exact predecessor fence. Implementations
    /// must fail closed for a missing SA, third owner, mismatched
    /// transition/fingerprint, or malformed state. This lets a caller safely
    /// replay a retained request after cancellation or an ambiguous write
    /// result without minting another fence or accepting stale resume evidence.
    async fn recover_fence_grant(
        &self,
        request: &OwnershipFenceRequest,
    ) -> Result<Option<OwnershipFenceGrant>, IpsecLbError>;

    /// Move ownership to a new owner only if the expected previous owner still
    /// holds the SA, returning a fresh monotonic fence token.
    async fn fence_sa_owner(
        &self,
        request: OwnershipFenceRequest,
    ) -> Result<OwnershipFenceGrant, IpsecLbError>;

    /// Validate that a retry proof still names the exact authoritative SA
    /// owner, committed fence, transition ID, and request fingerprint.
    ///
    /// This operation is read-only. Implementations must fail closed when any
    /// field has changed; checking only the owner/fence is insufficient
    /// because it would trust a stale request after an ABA owner cycle.
    async fn validate_retry_proof(&self, proof: &OwnershipRetryProof) -> Result<(), IpsecLbError>;
}

/// Authority that publishes the FIRST owner record for a newly established SA.
///
/// This is the no-predecessor twin of [`OwnershipFencer`]. It exists because a
/// receiver-chosen inbound SPI is reachable from the moment the responder
/// installs the SA, before any ownership transition has occurred, so a
/// destination-scoped owner map must admit a first publication.
///
/// # Safety contract
///
/// Implementations MUST mint the activation generation themselves from
/// authoritative durable state and MUST NOT accept a caller-supplied one. The
/// minted generation must be strictly above the durable per-key floor,
/// including a floor left behind by a completed retirement — an absent record
/// or an empty datapath map is not evidence that a key was never activated.
/// Activation is a promotion of an existing birth record, never an upsert: a
/// missing record must fail closed with [`IpsecLbError::NotFound`]. A record
/// already held by a different owner or committed by a different transition
/// must fail closed as an ownership conflict rather than being overwritten, and
/// a retiring record must never be activated.
#[async_trait]
pub trait OwnershipActivationAuthority: Send + Sync + std::fmt::Debug {
    /// Commit the first authoritative owner and generation for one exact key.
    async fn activate_ownership(
        &self,
        request: &OwnershipActivationRequest,
    ) -> Result<OwnershipActivationGrant, IpsecLbError>;

    /// Recover an activation that may already have committed.
    ///
    /// This read-only operation returns the exact committed grant only when the
    /// authoritative record names the same owner, transition ID, and complete
    /// activation fingerprint; it returns `None` only when the record is still
    /// an un-transitioned birth record. Every other state fails closed. This
    /// makes an identical retry safe after cancellation or an ambiguous write
    /// without minting a second generation.
    async fn recover_activation_grant(
        &self,
        request: &OwnershipActivationRequest,
    ) -> Result<Option<OwnershipActivationGrant>, IpsecLbError>;
}

/// Durable two-phase authority for retiring exact re-pin ownership.
///
/// `begin_ownership_retirement` atomically advances an exact Active record to
/// non-expiring `Retiring` under a fresh higher fence. Ordinary ownership proof
/// validation must reject that state. Once Host cleanup is durably marked
/// complete by the session journal, `finalize_ownership_retirement` may
/// fenced-delete only that exact record while retaining the store fence floor.
#[async_trait]
pub trait OwnershipRetirementAuthority: Send + Sync + std::fmt::Debug {
    /// Establish or recover the exact durable retirement grant.
    ///
    /// Implementations must return
    /// [`IpsecLbError::OwnershipRetirementIndeterminate`] whenever a mutation
    /// may have committed but exact authoritative readback cannot classify the
    /// outcome. Every other error is a conclusive no-commit/unchanged result.
    /// This distinction is part of the safety contract: the coordinator
    /// releases a Host operation permit after an ordinary classified error,
    /// while an indeterminate result poisons that permit's bounded operation
    /// stripe until process restart. The next keyed operation must still
    /// classify authoritative store state fail-closed.
    async fn begin_ownership_retirement(
        &self,
        request: OwnershipRetirementRequest,
    ) -> Result<OwnershipRetirementAdmission, IpsecLbError>;

    /// Fenced-delete a cleanup-complete retirement without touching a rebirth.
    async fn finalize_ownership_retirement(
        &self,
        cleanup: &OwnershipCleanupCompleteProof,
    ) -> Result<OwnershipRetirementFinalization, IpsecLbError>;
}

/// Audit sink for SA ownership changes and steering re-pins.
///
/// # What a sink may emit
///
/// [`RePinAuditEvent`] is built to be safe to persist and export: it carries a
/// non-reversible [`crate::RePinAuditCorrelationId`] rather than the
/// [`crate::OwnershipTransitionId`] that authorizes retirement, precisely so
/// that a sink logging its correlation key — the ordinary use of one — cannot
/// hand a standing per-SA teardown capability to everyone with log-read access.
/// `sa`, `previous_owner`, and `new_owner` remain operator-visible identifiers;
/// the event's `Debug` redacts them, and an exporting sink should apply its own
/// deployment policy to them.
///
/// A sink MUST NOT reach around this port to record the raw transition
/// identity alongside the event. Correlation is one-way by design: an operator
/// who already holds the raw identity can compute the matching correlation
/// identity with [`crate::RePinAuditCorrelationId::for_transition`].
#[async_trait]
pub trait RePinAuditSink: Send + Sync + std::fmt::Debug {
    /// Record a redaction-safe re-pin audit event.
    ///
    /// Recording an identical full event MUST be idempotent. Re-pin recovery can
    /// repeat an event after an apply-then-cancel or apply-then-error outcome;
    /// sinks must deduplicate that retry rather than append a second event. The
    /// deduplication identity must cover the complete event: neither the
    /// correlation ID alone nor `(correlation_id, kind)` distinguishes separate
    /// failed attempts with different redaction-safe failure codes.
    async fn record_repin(&self, event: RePinAuditEvent) -> Result<(), IpsecLbError>;
}
