//! External-load-balancer VIP advertisement adapter.
//!
//! An external load balancer supplies VIP delivery for this tier. The network
//! function still reconciles fenced ownership locally, but advertise and
//! withdraw requests intentionally do not mutate host route state.

use async_trait::async_trait;

use crate::error::IpsecLbError;
use crate::model::{VipAdvertisement, VipProbe};
use crate::ports::VipAdvertiser;

/// VIP advertiser for deployments where an external load balancer supplies
/// delivery.
///
/// The adapter is stateless and owns no route-programming backend. Both
/// mutations are successful no-ops so callers can use the same fenced
/// ownership coordinator as route-programming advertiser tiers.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExternalLbVipAdvertiser;

impl ExternalLbVipAdvertiser {
    /// Build an external-load-balancer advertiser.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl VipAdvertiser for ExternalLbVipAdvertiser {
    async fn advertise(&self, _advertisement: VipAdvertisement) -> Result<(), IpsecLbError> {
        Ok(())
    }

    async fn withdraw(&self, _advertisement: VipAdvertisement) -> Result<(), IpsecLbError> {
        Ok(())
    }

    async fn probe(&self) -> Result<VipProbe, IpsecLbError> {
        Ok(VipProbe::external_lb())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ClusterNode, IpAddress, VipAdvertiserKind};

    fn advertisement() -> VipAdvertisement {
        VipAdvertisement {
            vip: IpAddress::V4([192, 0, 2, 10]),
            node: ClusterNode::new("node-a"),
        }
    }

    #[tokio::test]
    async fn mutations_are_noops_and_probe_names_external_delivery() {
        let advertiser = ExternalLbVipAdvertiser::new();

        advertiser.advertise(advertisement()).await.unwrap();
        advertiser.withdraw(advertisement()).await.unwrap();

        let probe = advertiser.probe().await.unwrap();
        assert_eq!(probe.kind, VipAdvertiserKind::ExternalLb);
        assert!(probe.platform_supported);
        assert!(probe.mutation_ready);
        assert!(probe
            .details
            .is_some_and(|details| details.contains("external LB") && details.contains("no-op")));
    }
}
