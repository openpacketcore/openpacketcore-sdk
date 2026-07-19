use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroU16;

use async_trait::async_trait;
use opc_route_steering::{
    IpPrefix, MockOperation, RouteConflict, RouteMismatch, RouteReadback, RouteRequest,
    RouteSteeringBackend, RouteSteeringError, RouteSteeringProbe, RuleConflict,
    RuleConvergenceOutcome, RuleMismatch, RuleReadback, RuleRequest,
};

#[derive(Debug)]
struct ExternalBackend;

#[async_trait]
impl RouteSteeringBackend for ExternalBackend {
    async fn install_route(&self, _request: RouteRequest) -> Result<(), RouteSteeringError> {
        Ok(())
    }

    async fn remove_route(&self, _request: RouteRequest) -> Result<(), RouteSteeringError> {
        Ok(())
    }

    async fn install_rule(&self, _request: RuleRequest) -> Result<(), RouteSteeringError> {
        Ok(())
    }

    async fn remove_rule(&self, _request: RuleRequest) -> Result<(), RouteSteeringError> {
        Ok(())
    }

    async fn read_route(
        &self,
        request: &RouteRequest,
    ) -> Result<RouteReadback, RouteSteeringError> {
        Ok(RouteReadback::Conflict(RouteConflict::new(
            request.clone(),
            NonZeroU16::MIN,
            RouteMismatch::default(),
        )))
    }

    async fn read_rule(&self, request: &RuleRequest) -> Result<RuleReadback, RouteSteeringError> {
        Ok(RuleReadback::Conflict(RuleConflict::new(
            request.clone(),
            NonZeroU16::MIN,
            RuleMismatch::default(),
        )))
    }

    async fn probe(&self) -> Result<RouteSteeringProbe, RouteSteeringError> {
        Ok(RouteSteeringProbe::mock())
    }
}

fn route() -> RouteRequest {
    RouteRequest {
        destination: IpPrefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 32),
        oif_ifindex: 1,
        table: 100,
        priority: Some(10),
    }
}

fn rule() -> RuleRequest {
    RuleRequest {
        source: Some(IpPrefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 32)),
        destination: None,
        fwmark: None,
        table: 100,
        priority: 1000,
    }
}

// This exhaustive match is an API-compatibility fixture: read observations
// must remain outside the legacy MockOperation enum.
fn legacy_operation_name(operation: MockOperation) -> &'static str {
    match operation {
        MockOperation::InstallRoute(_) => "install_route",
        MockOperation::RemoveRoute(_) => "remove_route",
        MockOperation::InstallRule(_) => "install_rule",
        MockOperation::RemoveRule(_) => "remove_rule",
        MockOperation::Probe => "probe",
    }
}

#[tokio::test]
async fn external_backend_can_construct_typed_conflicts() {
    let backend = ExternalBackend;
    assert!(matches!(
        backend.read_route(&route()).await.unwrap(),
        RouteReadback::Conflict(_)
    ));
    assert!(matches!(
        backend.read_rule(&rule()).await.unwrap(),
        RuleReadback::Conflict(_)
    ));
    assert_eq!(legacy_operation_name(MockOperation::Probe), "probe");

    let capabilities = backend.capabilities().await;
    assert!(capabilities.legacy_mutation);
    assert!(!capabilities.conflict_safe_route_convergence);
    assert!(!capabilities.conflict_safe_rule_convergence);
    assert!(!capabilities.paired_convergence);
    assert!(!capabilities.owned_route_rule_collection);
    assert!(matches!(
        backend.remove_converged_route(route()).await,
        Err(RouteSteeringError::ReadbackIndeterminate { .. })
    ));

    // A third-party backend which implements readback but not convergence must
    // still fail closed without invoking its legacy install path.
    let absent_only = LegacyOnlyBackend;
    assert_eq!(
        absent_only.converge_rule(rule()).await.unwrap(),
        RuleConvergenceOutcome::Indeterminate(
            opc_route_steering::ReadbackIndeterminateReason::Unsupported
        )
    );
}

#[derive(Debug)]
struct LegacyOnlyBackend;

#[async_trait]
impl RouteSteeringBackend for LegacyOnlyBackend {
    async fn install_route(&self, _request: RouteRequest) -> Result<(), RouteSteeringError> {
        panic!("legacy mutation must not be called by default convergence")
    }

    async fn remove_route(&self, _request: RouteRequest) -> Result<(), RouteSteeringError> {
        panic!("legacy mutation must not be called by default convergence")
    }

    async fn install_rule(&self, _request: RuleRequest) -> Result<(), RouteSteeringError> {
        panic!("legacy mutation must not be called by default convergence")
    }

    async fn remove_rule(&self, _request: RuleRequest) -> Result<(), RouteSteeringError> {
        panic!("legacy mutation must not be called by default convergence")
    }

    async fn read_route(
        &self,
        _request: &RouteRequest,
    ) -> Result<RouteReadback, RouteSteeringError> {
        Ok(RouteReadback::Absent)
    }

    async fn read_rule(&self, _request: &RuleRequest) -> Result<RuleReadback, RouteSteeringError> {
        Ok(RuleReadback::Absent)
    }

    async fn probe(&self) -> Result<RouteSteeringProbe, RouteSteeringError> {
        Ok(RouteSteeringProbe::mock())
    }
}
