//! Reusable ports for SWu load balancing.

use async_trait::async_trait;

use crate::error::IpsecLbError;
use crate::model::{
    ClusterNode, SaId, ShardId, SteeringProbe, SteeringRule, VipAdvertisement, VipProbe,
};
use crate::repin::{OwnershipFenceGrant, OwnershipFenceRequest, RePinAuditEvent};
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

    /// Return the current owner for an SA.
    async fn sa_owner(&self, sa: SaId) -> Result<Option<ClusterNode>, IpsecLbError>;
}

/// Ownership fencing port used before re-pinning a resumed SA.
#[async_trait]
pub trait OwnershipFencer: Send + Sync + std::fmt::Debug {
    /// Move ownership to a new owner only if the expected previous owner still
    /// holds the SA, returning a fresh monotonic fence token.
    async fn fence_sa_owner(
        &self,
        request: OwnershipFenceRequest,
    ) -> Result<OwnershipFenceGrant, IpsecLbError>;
}

/// Audit sink for SA ownership changes and steering re-pins.
#[async_trait]
pub trait RePinAuditSink: Send + Sync + std::fmt::Debug {
    /// Record a redaction-safe re-pin audit event.
    async fn record_repin(&self, event: RePinAuditEvent) -> Result<(), IpsecLbError>;
}
