//! Unsupported-platform route-steering backend.

use async_trait::async_trait;

use crate::backend::RouteSteeringBackend;
use crate::error::RouteSteeringError;
use crate::model::{RouteRequest, RouteSteeringCapabilities, RouteSteeringProbe, RuleRequest};

/// Route-steering backend that reports unsupported for every mutation.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnsupportedRouteSteeringBackend;

impl UnsupportedRouteSteeringBackend {
    /// Create a new unsupported backend.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl RouteSteeringBackend for UnsupportedRouteSteeringBackend {
    async fn install_route(&self, _request: RouteRequest) -> Result<(), RouteSteeringError> {
        Err(RouteSteeringError::UnsupportedPlatform)
    }

    async fn remove_route(&self, _request: RouteRequest) -> Result<(), RouteSteeringError> {
        Err(RouteSteeringError::UnsupportedPlatform)
    }

    async fn install_rule(&self, _request: RuleRequest) -> Result<(), RouteSteeringError> {
        Err(RouteSteeringError::UnsupportedPlatform)
    }

    async fn remove_rule(&self, _request: RuleRequest) -> Result<(), RouteSteeringError> {
        Err(RouteSteeringError::UnsupportedPlatform)
    }

    async fn probe(&self) -> Result<RouteSteeringProbe, RouteSteeringError> {
        Ok(RouteSteeringProbe::unsupported())
    }

    async fn capabilities(&self) -> RouteSteeringCapabilities {
        RouteSteeringCapabilities::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        IpPrefix, ReadbackIndeterminateReason, RouteReadback, RouteRequest, RouteRuleRollback,
        RouteSteeringBackendKind, RuleConvergenceOutcome, RuleRequest,
    };
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn unsupported_probe_reports_unsupported() {
        let backend = UnsupportedRouteSteeringBackend::new();
        let probe = backend.probe().await.unwrap();
        assert_eq!(probe.kind, RouteSteeringBackendKind::Unsupported);
        assert!(!probe.platform_supported);
        assert!(!probe.mutation_ready);
        assert_eq!(
            backend.capabilities().await,
            crate::model::RouteSteeringCapabilities::default()
        );
    }

    #[tokio::test]
    async fn unsupported_readback_and_pair_fail_closed_without_mutation() {
        let backend = UnsupportedRouteSteeringBackend::new();
        let prefix = IpPrefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24);
        let route = RouteRequest {
            destination: prefix,
            oif_ifindex: 2,
            table: 100,
            priority: None,
        };
        let rule = RuleRequest {
            source: Some(prefix),
            destination: None,
            fwmark: None,
            table: 100,
            priority: 1000,
        };
        assert_eq!(
            backend.read_route(&route).await.unwrap(),
            RouteReadback::Indeterminate(ReadbackIndeterminateReason::Unsupported)
        );
        let outcome = backend.converge_route_and_rule(route, rule).await.unwrap();
        assert!(matches!(
            outcome.route,
            crate::model::RouteConvergenceOutcome::Indeterminate(
                ReadbackIndeterminateReason::Unsupported
            )
        ));
        assert_eq!(outcome.rule, RuleConvergenceOutcome::NotAttempted);
        assert_eq!(outcome.rollback, RouteRuleRollback::NotNeeded);
    }
}
