//! Unsupported port implementations.

use async_trait::async_trait;

use crate::error::IpsecLbError;
use crate::model::{
    ClusterNode, SaId, ShardId, SteeringProbe, SteeringRule, VipAdvertisement, VipProbe,
};
use crate::ports::{OwnershipSource, SteeringBackend, VipAdvertiser};

/// Unsupported steering backend.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnsupportedSteeringBackend;

impl UnsupportedSteeringBackend {
    /// Build an unsupported steering backend.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl SteeringBackend for UnsupportedSteeringBackend {
    async fn install_rule(&self, _rule: SteeringRule) -> Result<(), IpsecLbError> {
        Err(IpsecLbError::Unsupported)
    }

    async fn remove_rule(&self, _rule: SteeringRule) -> Result<(), IpsecLbError> {
        Err(IpsecLbError::Unsupported)
    }

    async fn probe(&self) -> Result<SteeringProbe, IpsecLbError> {
        Ok(SteeringProbe::unsupported())
    }
}

/// Unsupported VIP advertiser.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnsupportedVipAdvertiser;

impl UnsupportedVipAdvertiser {
    /// Build an unsupported VIP advertiser.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl VipAdvertiser for UnsupportedVipAdvertiser {
    async fn advertise(&self, _advertisement: VipAdvertisement) -> Result<(), IpsecLbError> {
        Err(IpsecLbError::Unsupported)
    }

    async fn withdraw(&self, _advertisement: VipAdvertisement) -> Result<(), IpsecLbError> {
        Err(IpsecLbError::Unsupported)
    }

    async fn probe(&self) -> Result<VipProbe, IpsecLbError> {
        Ok(VipProbe::unsupported())
    }
}

/// Unsupported ownership source.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnsupportedOwnershipSource;

impl UnsupportedOwnershipSource {
    /// Build an unsupported ownership source.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl OwnershipSource for UnsupportedOwnershipSource {
    async fn shard_owner(&self, _shard: ShardId) -> Result<Option<ClusterNode>, IpsecLbError> {
        Err(IpsecLbError::Unsupported)
    }

    async fn sa_owner(&self, _sa: SaId) -> Result<Option<ClusterNode>, IpsecLbError> {
        Err(IpsecLbError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SteeringBackendKind;

    #[tokio::test]
    async fn unsupported_backend_probes_fail_closed() {
        let probe = UnsupportedSteeringBackend::new().probe().await.unwrap();
        assert_eq!(probe.kind, SteeringBackendKind::Unsupported);
        assert!(!probe.mutation_ready);
        assert!(probe.key_material_free);
    }
}
