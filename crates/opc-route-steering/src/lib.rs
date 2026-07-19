//! Safe Linux route/rule steering backend model for OpenPacketCore.
//!
//! This crate provides a backend trait for route and rule lifecycle operations,
//! conflict-safe typed readback and convergence, a deterministic mock backend
//! for tests, an unsupported-platform backend, a Linux rtnetlink adapter, and
//! redaction-safe error types. It deliberately does not choose route tables,
//! rule priorities, network namespaces, or product steering policy.
//!
//! [`RouteSteeringBackend::converge_route`] and
//! [`RouteSteeringBackend::converge_rule`] distinguish a newly installed object
//! from an exact resident object, a kernel-key conflict, and indeterminate
//! readback. Route convergence compares the effective destination network with
//! host bits cleared, matching Linux FIB representation without changing rule
//! selector semantics. [`RouteSteeringBackend::converge_route_and_rule`]
//! additionally rolls back only a route installed by that same call. The
//! original mutation methods remain available, but their `AlreadyExists` error
//! is not proof of resident equality.
//!
//! The Linux adapter tags only convergence-owned objects with
//! [`LINUX_ROUTE_STEERING_PROTOCOL`]; the original install/remove methods keep
//! their legacy static/untagged wire behavior. Exact cleanup therefore uses
//! [`RouteSteeringBackend::remove_converged_route`] and
//! [`RouteSteeringBackend::remove_converged_rule`], never a legacy delete.
//! Every read/mutation is serialized across clones that share one backend
//! instance. The protocol value is a namespace-local ownership reservation,
//! not authentication: separate backend instances and external netlink writers
//! still require one orchestration-level authority.
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
mod validation;

pub use backend::RouteSteeringBackend;
pub use error::{RouteSteeringError, RouteSteeringFailureClass};
pub use linux::{
    LinuxRouteReadbackLimits, LinuxRouteSteeringBackend, LinuxRouteSteeringBackendConfig,
    LinuxRuleProtocolCapability, LINUX_ROUTE_STEERING_PROTOCOL,
};
pub use mock::{MockFailurePoint, MockObservation, MockOperation, MockRouteSteeringBackend};
pub use model::{
    FirewallMark, IpPrefix, ReadbackIndeterminateReason, RouteConflict, RouteConvergenceOutcome,
    RouteMismatch, RouteReadback, RouteRequest, RouteRuleConvergenceOutcome, RouteRuleRollback,
    RouteSteeringBackendKind, RouteSteeringCapabilities, RouteSteeringProbe, RuleConflict,
    RuleConvergenceOutcome, RuleMismatch, RuleReadback, RuleRequest,
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
