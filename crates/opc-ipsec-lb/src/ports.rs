//! Reusable ports for SWu load balancing.

use async_trait::async_trait;

use crate::error::IpsecLbError;
use crate::model::{
    ClusterNode, SaId, ShardId, SteeringProbe, SteeringRule, VipAdvertisement, VipProbe,
};
use crate::repin::{
    OwnershipFenceGrant, OwnershipFenceRequest, OwnershipRetryProof, OwnershipSnapshot,
    RePinAuditEvent,
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

/// VIP advertisement port.
#[async_trait]
pub trait VipAdvertiser: Send + Sync + std::fmt::Debug {
    /// Advertise a SWu VIP from this node.
    async fn advertise(&self, advertisement: VipAdvertisement) -> Result<(), IpsecLbError>;

    /// Withdraw a SWu VIP from this node.
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

/// Audit sink for SA ownership changes and steering re-pins.
#[async_trait]
pub trait RePinAuditSink: Send + Sync + std::fmt::Debug {
    /// Record a redaction-safe re-pin audit event.
    ///
    /// Recording an identical full event MUST be idempotent. Re-pin recovery can
    /// repeat an event after an apply-then-cancel or apply-then-error outcome;
    /// sinks must deduplicate that retry rather than append a second event. The
    /// deduplication identity must cover the complete event: neither the
    /// transition ID alone nor `(transition_id, kind)` distinguishes separate
    /// failed attempts with different redaction-safe failure codes.
    async fn record_repin(&self, event: RePinAuditEvent) -> Result<(), IpsecLbError>;
}
