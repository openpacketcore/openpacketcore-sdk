//! Unsupported-platform route-steering backend.

use async_trait::async_trait;

use crate::backend::RouteSteeringBackend;
use crate::error::RouteSteeringError;
use crate::model::{RouteRequest, RouteSteeringProbe, RuleRequest};

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::RouteSteeringBackendKind;

    #[tokio::test]
    async fn unsupported_probe_reports_unsupported() {
        let backend = UnsupportedRouteSteeringBackend::new();
        let probe = backend.probe().await.unwrap();
        assert_eq!(probe.kind, RouteSteeringBackendKind::Unsupported);
        assert!(!probe.platform_supported);
        assert!(!probe.mutation_ready);
    }
}
