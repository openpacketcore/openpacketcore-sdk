//! BGP VIP advertisement through route export.
//!
//! This adapter programs a host route for the SWu VIP into an
//! operator-selected Linux routing table. A local BGP speaker such as FRR,
//! BIRD, or GoBGP can then redistribute that table by policy. The SDK does not
//! shell out to daemon CLIs or open a direct BGP session from this crate.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use async_trait::async_trait;
use opc_route_steering::{
    IpPrefix, LinuxRouteSteeringBackend, RouteRequest, RouteSteeringBackend, RouteSteeringError,
    RouteSteeringProbe,
};

use crate::error::IpsecLbError;
use crate::model::{IpAddress, VipAdvertisement, VipAdvertiserKind, VipProbe};
use crate::ports::VipAdvertiser;

/// Route-export configuration for BGP VIP advertisement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BgpRouteVipAdvertiserConfig {
    /// Routing table watched or redistributed by the local BGP speaker.
    pub route_table: u32,
    /// Output interface index that owns the VIP route.
    pub oif_ifindex: u32,
    /// Optional route priority/metric.
    pub priority: Option<u32>,
}

impl BgpRouteVipAdvertiserConfig {
    /// Validate the route-export configuration.
    pub fn validate(self) -> Result<(), IpsecLbError> {
        if self.route_table == 0 {
            return Err(IpsecLbError::invalid_config(
                "route_table",
                "route table must be non-zero",
            ));
        }
        if self.oif_ifindex == 0 {
            return Err(IpsecLbError::invalid_config(
                "oif_ifindex",
                "output interface index must be non-zero",
            ));
        }
        Ok(())
    }
}

/// VIP advertiser that exposes SWu VIPs to a local BGP speaker via host routes.
#[derive(Debug, Clone)]
pub struct BgpRouteVipAdvertiser<B = LinuxRouteSteeringBackend> {
    backend: B,
    config: BgpRouteVipAdvertiserConfig,
}

impl BgpRouteVipAdvertiser<LinuxRouteSteeringBackend> {
    /// Build an advertiser using the default Linux route-steering backend.
    pub fn new(config: BgpRouteVipAdvertiserConfig) -> Result<Self, IpsecLbError> {
        Self::with_backend(LinuxRouteSteeringBackend::new(), config)
    }
}

impl<B> BgpRouteVipAdvertiser<B>
where
    B: RouteSteeringBackend,
{
    /// Build an advertiser with an explicit route-steering backend.
    pub fn with_backend(
        backend: B,
        config: BgpRouteVipAdvertiserConfig,
    ) -> Result<Self, IpsecLbError> {
        config.validate()?;
        Ok(Self { backend, config })
    }

    fn route_request(
        &self,
        advertisement: &VipAdvertisement,
    ) -> Result<RouteRequest, IpsecLbError> {
        if advertisement.node.as_str().is_empty() {
            return Err(IpsecLbError::invalid_config(
                "node",
                "advertising node id must be non-empty",
            ));
        }
        let (address, prefix_len) = host_prefix(advertisement.vip);
        Ok(RouteRequest {
            destination: IpPrefix::new(address, prefix_len),
            oif_ifindex: self.config.oif_ifindex,
            table: self.config.route_table,
            priority: self.config.priority,
        })
    }
}

#[async_trait]
impl<B> VipAdvertiser for BgpRouteVipAdvertiser<B>
where
    B: RouteSteeringBackend,
{
    async fn advertise(&self, advertisement: VipAdvertisement) -> Result<(), IpsecLbError> {
        let request = self.route_request(&advertisement)?;
        self.backend
            .install_route(request)
            .await
            .map_err(map_route_error)
    }

    async fn withdraw(&self, advertisement: VipAdvertisement) -> Result<(), IpsecLbError> {
        let request = self.route_request(&advertisement)?;
        self.backend
            .remove_route(request)
            .await
            .map_err(map_route_error)
    }

    async fn probe(&self) -> Result<VipProbe, IpsecLbError> {
        map_probe(self.backend.probe().await.map_err(map_route_error)?)
    }
}

fn host_prefix(vip: IpAddress) -> (IpAddr, u8) {
    match vip {
        IpAddress::V4(octets) => (IpAddr::V4(Ipv4Addr::from(octets)), 32),
        IpAddress::V6(octets) => (IpAddr::V6(Ipv6Addr::from(octets)), 128),
    }
}

fn map_probe(probe: RouteSteeringProbe) -> Result<VipProbe, IpsecLbError> {
    Ok(VipProbe {
        kind: VipAdvertiserKind::Bgp,
        platform_supported: probe.platform_supported,
        mutation_ready: probe.mutation_ready,
        details: if probe.mutation_ready {
            Some("BGP route-export VIP advertisement ready")
        } else {
            Some("BGP route-export backend not mutation ready")
        },
    })
}

fn map_route_error(error: RouteSteeringError) -> IpsecLbError {
    match error {
        RouteSteeringError::UnsupportedPlatform => IpsecLbError::Unsupported,
        RouteSteeringError::AlreadyExists => IpsecLbError::AlreadyExists,
        RouteSteeringError::NotFound => IpsecLbError::NotFound,
        RouteSteeringError::InvalidConfig { .. } => {
            IpsecLbError::invalid_config("bgp_route", "route backend rejected request")
        }
        RouteSteeringError::Io {
            operation,
            kind,
            raw_os_error,
        } => IpsecLbError::Io {
            operation,
            kind,
            raw_os_error,
        },
        _ => IpsecLbError::Unsupported,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ClusterNode;
    use opc_route_steering::{MockOperation, MockRouteSteeringBackend, RouteSteeringBackendKind};

    fn config() -> BgpRouteVipAdvertiserConfig {
        BgpRouteVipAdvertiserConfig {
            route_table: 100,
            oif_ifindex: 42,
            priority: Some(10),
        }
    }

    fn advertisement(vip: IpAddress) -> VipAdvertisement {
        VipAdvertisement {
            vip,
            node: ClusterNode::new("node-a"),
        }
    }

    #[tokio::test]
    async fn advertise_and_withdraw_program_host_routes() {
        let backend = MockRouteSteeringBackend::new();
        let advertiser = BgpRouteVipAdvertiser::with_backend(backend.clone(), config()).unwrap();
        let ad = advertisement(IpAddress::V4([203, 0, 113, 10]));

        advertiser.advertise(ad.clone()).await.unwrap();
        advertiser.withdraw(ad).await.unwrap();

        let route = RouteRequest {
            destination: IpPrefix::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 32),
            oif_ifindex: 42,
            table: 100,
            priority: Some(10),
        };
        assert_eq!(
            backend.operations(),
            vec![
                MockOperation::InstallRoute(route.clone()),
                MockOperation::RemoveRoute(route),
            ]
        );
    }

    #[tokio::test]
    async fn ipv6_vip_uses_128_bit_host_route() {
        let backend = MockRouteSteeringBackend::new();
        let advertiser = BgpRouteVipAdvertiser::with_backend(backend.clone(), config()).unwrap();
        let ad = advertisement(IpAddress::V6([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7,
        ]));

        advertiser.advertise(ad).await.unwrap();

        let operations = backend.operations();
        let MockOperation::InstallRoute(route) = &operations[0] else {
            panic!("expected route install");
        };
        assert_eq!(route.destination.prefix_len, 128);
        assert!(matches!(route.destination.address, IpAddr::V6(_)));
    }

    #[tokio::test]
    async fn probe_maps_route_readiness_to_bgp_vip_probe() {
        let route_probe = RouteSteeringProbe {
            kind: RouteSteeringBackendKind::LinuxKernel,
            platform_supported: true,
            kernel_reachable: true,
            net_admin_capable: true,
            mutation_ready: true,
            details: Some("ready"),
        };
        let backend = MockRouteSteeringBackend::with_probe(route_probe);
        let advertiser = BgpRouteVipAdvertiser::with_backend(backend, config()).unwrap();

        let probe = advertiser.probe().await.unwrap();
        assert_eq!(probe.kind, VipAdvertiserKind::Bgp);
        assert!(probe.platform_supported);
        assert!(probe.mutation_ready);
    }

    #[tokio::test]
    async fn config_and_empty_node_fail_before_backend_mutation() {
        let backend = MockRouteSteeringBackend::new();
        assert!(BgpRouteVipAdvertiser::with_backend(
            backend.clone(),
            BgpRouteVipAdvertiserConfig {
                route_table: 0,
                oif_ifindex: 42,
                priority: None,
            },
        )
        .is_err());

        let advertiser = BgpRouteVipAdvertiser::with_backend(backend.clone(), config()).unwrap();
        let err = advertiser
            .advertise(VipAdvertisement {
                vip: IpAddress::V4([203, 0, 113, 10]),
                node: ClusterNode::new(""),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, IpsecLbError::InvalidConfig { .. }));
        assert!(backend.operations().is_empty());
    }
}
