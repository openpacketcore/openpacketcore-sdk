//! Safe route-steering backend trait.

use async_trait::async_trait;

use crate::error::RouteSteeringError;
use crate::model::{RouteRequest, RouteSteeringProbe, RuleRequest};

/// Backend that can mutate Linux route and rule state.
#[async_trait]
pub trait RouteSteeringBackend: Send + Sync + std::fmt::Debug {
    /// Install a route.
    async fn install_route(&self, request: RouteRequest) -> Result<(), RouteSteeringError>;

    /// Remove a route.
    async fn remove_route(&self, request: RouteRequest) -> Result<(), RouteSteeringError>;

    /// Install a rule.
    async fn install_rule(&self, request: RuleRequest) -> Result<(), RouteSteeringError>;

    /// Remove a rule.
    async fn remove_rule(&self, request: RuleRequest) -> Result<(), RouteSteeringError>;

    /// Probe backend capability and reachability.
    async fn probe(&self) -> Result<RouteSteeringProbe, RouteSteeringError>;
}
