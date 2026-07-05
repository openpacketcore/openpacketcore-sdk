//! Deterministic mock route-steering backend.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::backend::RouteSteeringBackend;
use crate::error::RouteSteeringError;
use crate::model::{RouteRequest, RouteSteeringProbe, RuleRequest};

/// One recorded call against the mock backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MockOperation {
    /// Route installation.
    InstallRoute(RouteRequest),
    /// Route removal.
    RemoveRoute(RouteRequest),
    /// Rule installation.
    InstallRule(RuleRequest),
    /// Rule removal.
    RemoveRule(RuleRequest),
    /// Capability probe.
    Probe,
}

/// Deterministic in-memory route-steering backend.
#[derive(Debug, Clone)]
pub struct MockRouteSteeringBackend {
    state: Arc<Mutex<MockState>>,
}

#[derive(Debug)]
struct MockState {
    operations: Vec<MockOperation>,
    routes: BTreeSet<RouteRequest>,
    rules: BTreeSet<RuleRequest>,
    probe_result: RouteSteeringProbe,
    failure: Option<RouteSteeringError>,
}

impl MockRouteSteeringBackend {
    /// Create a mock backend that reports itself as dry-run/mock.
    #[must_use]
    pub fn new() -> Self {
        Self::with_probe(RouteSteeringProbe::mock())
    }

    /// Create a mock backend with a specific probe result.
    #[must_use]
    pub fn with_probe(probe_result: RouteSteeringProbe) -> Self {
        Self {
            state: Arc::new(Mutex::new(MockState {
                operations: Vec::new(),
                routes: BTreeSet::new(),
                rules: BTreeSet::new(),
                probe_result,
                failure: None,
            })),
        }
    }

    /// Inject an error that every subsequent operation will return.
    pub fn set_failure(&self, error: RouteSteeringError) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.failure = Some(error);
    }

    /// Clear any injected failure.
    pub fn clear_failure(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.failure = None;
    }

    /// Return all recorded operations, in order.
    #[must_use]
    pub fn operations(&self) -> Vec<MockOperation> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.operations.clone()
    }

    fn check_failure(state: &MockState) -> Result<(), RouteSteeringError> {
        if let Some(ref error) = state.failure {
            return Err(error.clone());
        }
        Ok(())
    }
}

impl Default for MockRouteSteeringBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RouteSteeringBackend for MockRouteSteeringBackend {
    async fn install_route(&self, request: RouteRequest) -> Result<(), RouteSteeringError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::check_failure(&state)?;
        if !state.routes.insert(request.clone()) {
            return Err(RouteSteeringError::AlreadyExists);
        }
        state.operations.push(MockOperation::InstallRoute(request));
        Ok(())
    }

    async fn remove_route(&self, request: RouteRequest) -> Result<(), RouteSteeringError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::check_failure(&state)?;
        if !state.routes.remove(&request) {
            return Err(RouteSteeringError::NotFound);
        }
        state.operations.push(MockOperation::RemoveRoute(request));
        Ok(())
    }

    async fn install_rule(&self, request: RuleRequest) -> Result<(), RouteSteeringError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::check_failure(&state)?;
        if !state.rules.insert(request.clone()) {
            return Err(RouteSteeringError::AlreadyExists);
        }
        state.operations.push(MockOperation::InstallRule(request));
        Ok(())
    }

    async fn remove_rule(&self, request: RuleRequest) -> Result<(), RouteSteeringError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::check_failure(&state)?;
        if !state.rules.remove(&request) {
            return Err(RouteSteeringError::NotFound);
        }
        state.operations.push(MockOperation::RemoveRule(request));
        Ok(())
    }

    async fn probe(&self) -> Result<RouteSteeringProbe, RouteSteeringError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::check_failure(&state)?;
        state.operations.push(MockOperation::Probe);
        Ok(state.probe_result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{FirewallMark, IpPrefix, RouteSteeringBackendKind};
    use std::net::{IpAddr, Ipv4Addr};

    fn prefix(octets: [u8; 4], prefix_len: u8) -> IpPrefix {
        IpPrefix::new(IpAddr::V4(Ipv4Addr::from(octets)), prefix_len)
    }

    fn route() -> RouteRequest {
        RouteRequest {
            destination: prefix([10, 23, 0, 0], 24),
            oif_ifindex: 42,
            table: 100,
            priority: Some(10),
        }
    }

    fn rule() -> RuleRequest {
        RuleRequest {
            source: Some(prefix([10, 23, 0, 0], 24)),
            destination: None,
            fwmark: Some(FirewallMark {
                value: 0x40,
                mask: 0xff,
            }),
            table: 100,
            priority: 1000,
        }
    }

    #[tokio::test]
    async fn mock_records_route_lifecycle() {
        let backend = MockRouteSteeringBackend::new();
        backend.install_route(route()).await.unwrap();
        backend.remove_route(route()).await.unwrap();

        assert_eq!(
            backend.operations(),
            vec![
                MockOperation::InstallRoute(route()),
                MockOperation::RemoveRoute(route()),
            ]
        );
    }

    #[tokio::test]
    async fn mock_records_rule_lifecycle() {
        let backend = MockRouteSteeringBackend::new();
        backend.install_rule(rule()).await.unwrap();
        backend.remove_rule(rule()).await.unwrap();

        assert_eq!(
            backend.operations(),
            vec![
                MockOperation::InstallRule(rule()),
                MockOperation::RemoveRule(rule()),
            ]
        );
    }

    #[tokio::test]
    async fn mock_duplicate_and_missing_semantics_match_kernel_style() {
        let backend = MockRouteSteeringBackend::new();
        backend.install_route(route()).await.unwrap();
        assert!(matches!(
            backend.install_route(route()).await.unwrap_err(),
            RouteSteeringError::AlreadyExists
        ));
        backend.remove_route(route()).await.unwrap();
        assert!(matches!(
            backend.remove_route(route()).await.unwrap_err(),
            RouteSteeringError::NotFound
        ));
    }

    #[tokio::test]
    async fn mock_probe_returns_configured_result() {
        let probe = RouteSteeringProbe {
            kind: RouteSteeringBackendKind::Mock,
            platform_supported: true,
            kernel_reachable: false,
            net_admin_capable: false,
            mutation_ready: false,
            details: Some("configured"),
        };
        let backend = MockRouteSteeringBackend::with_probe(probe);
        assert_eq!(backend.probe().await.unwrap(), probe);
    }
}
