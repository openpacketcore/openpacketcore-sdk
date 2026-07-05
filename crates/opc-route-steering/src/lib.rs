//! Safe Linux route/rule steering backend model for OpenPacketCore.
//!
//! This crate provides a backend trait for route and rule lifecycle operations,
//! a deterministic mock backend for tests, an unsupported-platform backend, a
//! Linux rtnetlink adapter, and redaction-safe error types. It deliberately
//! does not choose route tables, rule priorities, network namespaces, or product
//! steering policy.
//!
//! Raw Linux rtnetlink syscalls stay in [`opc_linux_route_sys`]; this crate is
//! safe Rust and never performs `unsafe` operations.

#![forbid(unsafe_code)]

pub mod backend;
pub mod error;
pub mod linux;
pub mod mock;
pub mod model;
pub mod unsupported;

pub use backend::RouteSteeringBackend;
pub use error::RouteSteeringError;
pub use linux::{LinuxRouteSteeringBackend, LinuxRouteSteeringBackendConfig};
pub use mock::{MockOperation, MockRouteSteeringBackend};
pub use model::{
    FirewallMark, IpPrefix, RouteRequest, RouteSteeringBackendKind, RouteSteeringProbe, RuleRequest,
};
pub use unsupported::UnsupportedRouteSteeringBackend;

#[cfg(test)]
mod integration_tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn prefix(octets: [u8; 4], prefix_len: u8) -> IpPrefix {
        IpPrefix::new(IpAddr::V4(Ipv4Addr::from(octets)), prefix_len)
    }

    #[tokio::test]
    async fn mock_backend_lifecycle_round_trip() {
        let backend = MockRouteSteeringBackend::new();
        let route = RouteRequest {
            destination: prefix([10, 23, 0, 0], 24),
            oif_ifindex: 42,
            table: 100,
            priority: Some(10),
        };
        let rule = RuleRequest {
            source: Some(prefix([10, 23, 0, 0], 24)),
            destination: None,
            fwmark: Some(FirewallMark {
                value: 0x40,
                mask: 0xff,
            }),
            table: 100,
            priority: 1000,
        };

        backend.install_route(route.clone()).await.unwrap();
        backend.install_rule(rule.clone()).await.unwrap();
        backend.remove_rule(rule).await.unwrap();
        backend.remove_route(route).await.unwrap();
        let probe = backend.probe().await.unwrap();

        assert_eq!(probe.kind, RouteSteeringBackendKind::Mock);
        assert_eq!(backend.operations().len(), 5);
    }

    #[tokio::test]
    async fn unsupported_backend_is_trait_object_safe() {
        let backend: Box<dyn RouteSteeringBackend> =
            Box::new(UnsupportedRouteSteeringBackend::new());
        let probe = backend.probe().await.unwrap();
        assert_eq!(probe, RouteSteeringProbe::unsupported());
    }
}
