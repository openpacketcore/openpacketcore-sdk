//! Safe route-steering backend trait.

use async_trait::async_trait;

use crate::collection::{
    OwnedRouteRuleReconcileOutcome, OwnedRouteRuleScope, OwnedRouteRuleSet, OwnedRouteRuleSnapshot,
};
use crate::error::RouteSteeringError;
use crate::model::{
    ReadbackIndeterminateReason, RouteConvergenceOutcome, RouteReadback, RouteRequest,
    RouteRuleConvergenceOutcome, RouteRuleRollback, RouteSteeringCapabilities, RouteSteeringProbe,
    RuleConvergenceOutcome, RuleReadback, RuleRequest,
};
use crate::validation::{
    validate_owned_rule_request, validate_route_request, validate_rule_request,
};

/// Backend that can mutate Linux route and rule state.
#[async_trait]
pub trait RouteSteeringBackend: Send + Sync + std::fmt::Debug {
    /// Install a route using the original backend-specific mutation semantics.
    ///
    /// This legacy method does not prove equality after `AlreadyExists` and
    /// does not create convergence ownership evidence. Prefer
    /// [`Self::converge_route`] for new control-plane integrations.
    async fn install_route(&self, request: RouteRequest) -> Result<(), RouteSteeringError>;

    /// Remove a route using the original backend-specific mutation semantics.
    ///
    /// This legacy method does not prove ownership or resident equality. Use
    /// [`Self::remove_converged_route`] for state created by convergence.
    async fn remove_route(&self, request: RouteRequest) -> Result<(), RouteSteeringError>;

    /// Install a rule using the original backend-specific mutation semantics.
    ///
    /// This legacy method preserves zero-mark and `/0` request compatibility;
    /// prefer [`Self::converge_rule`] where exact rollback is required.
    async fn install_rule(&self, request: RuleRequest) -> Result<(), RouteSteeringError>;

    /// Remove a rule using the original backend-specific mutation semantics.
    ///
    /// This legacy method does not prove ownership or resident equality. Use
    /// [`Self::remove_converged_rule`] for state created by convergence.
    async fn remove_rule(&self, request: RuleRequest) -> Result<(), RouteSteeringError>;

    /// Remove exactly one convergence-owned route.
    ///
    /// The safe default never delegates to legacy deletion because a generic
    /// adapter cannot prove that its delete key is non-wildcard and owned.
    async fn remove_converged_route(
        &self,
        request: RouteRequest,
    ) -> Result<(), RouteSteeringError> {
        validate_route_request(&request)?;
        Err(RouteSteeringError::indeterminate(
            ReadbackIndeterminateReason::Unsupported,
        ))
    }

    /// Remove exactly one convergence-owned rule.
    ///
    /// `/0` selectors and a zero firewall-mark value are rejected because they
    /// cannot identify a non-wildcard Linux deletion.
    async fn remove_converged_rule(&self, request: RuleRequest) -> Result<(), RouteSteeringError> {
        validate_owned_rule_request(&request)?;
        Err(RouteSteeringError::indeterminate(
            ReadbackIndeterminateReason::Unsupported,
        ))
    }

    /// Read back the logical key for a route and compare every modeled field.
    ///
    /// Existing third-party backends remain source compatible and fail closed
    /// as indeterminate until they implement typed readback.
    async fn read_route(
        &self,
        request: &RouteRequest,
    ) -> Result<RouteReadback, RouteSteeringError> {
        validate_route_request(request)?;
        Ok(RouteReadback::Indeterminate(
            ReadbackIndeterminateReason::Unsupported,
        ))
    }

    /// Read back the logical key for a rule and compare every modeled field.
    ///
    /// Existing third-party backends remain source compatible and fail closed
    /// as indeterminate until they implement typed readback.
    async fn read_rule(&self, request: &RuleRequest) -> Result<RuleReadback, RouteSteeringError> {
        validate_rule_request(request)?;
        Ok(RuleReadback::Indeterminate(
            ReadbackIndeterminateReason::Unsupported,
        ))
    }

    /// Install a route or prove that the exact route is already resident.
    async fn converge_route(
        &self,
        request: RouteRequest,
    ) -> Result<RouteConvergenceOutcome, RouteSteeringError> {
        validate_route_request(&request)?;
        match self.read_route(&request).await? {
            RouteReadback::Absent => {}
            RouteReadback::ExactPresent => {
                return Ok(RouteConvergenceOutcome::ExactAlreadyPresent);
            }
            RouteReadback::Conflict(conflict) => {
                return Ok(RouteConvergenceOutcome::Conflict(conflict));
            }
            RouteReadback::Indeterminate(reason) => {
                return Ok(RouteConvergenceOutcome::Indeterminate(reason));
            }
        }
        Ok(RouteConvergenceOutcome::Indeterminate(
            ReadbackIndeterminateReason::Unsupported,
        ))
    }

    /// Install a rule or prove that the exact rule is already resident.
    async fn converge_rule(
        &self,
        request: RuleRequest,
    ) -> Result<RuleConvergenceOutcome, RouteSteeringError> {
        validate_owned_rule_request(&request)?;
        match self.read_rule(&request).await? {
            RuleReadback::Absent => {}
            RuleReadback::ExactPresent => {
                return Ok(RuleConvergenceOutcome::ExactAlreadyPresent);
            }
            RuleReadback::Conflict(conflict) => {
                return Ok(RuleConvergenceOutcome::Conflict(conflict));
            }
            RuleReadback::Indeterminate(reason) => {
                return Ok(RuleConvergenceOutcome::Indeterminate(reason));
            }
        }
        Ok(RuleConvergenceOutcome::Indeterminate(
            ReadbackIndeterminateReason::Unsupported,
        ))
    }

    /// Converge one route/rule pair with backend-owned cancellation semantics.
    ///
    /// Implementations must remove only objects installed by the same call.
    /// The safe default does not mutate either object because a generic adapter
    /// cannot guarantee completion of asynchronous rollback after cancellation.
    async fn converge_route_and_rule(
        &self,
        route: RouteRequest,
        rule: RuleRequest,
    ) -> Result<RouteRuleConvergenceOutcome, RouteSteeringError> {
        validate_route_request(&route)?;
        validate_owned_rule_request(&rule)?;
        Ok(RouteRuleConvergenceOutcome {
            route: RouteConvergenceOutcome::Indeterminate(ReadbackIndeterminateReason::Unsupported),
            rule: RuleConvergenceOutcome::NotAttempted,
            rollback: RouteRuleRollback::NotNeeded,
        })
    }

    /// Enumerate all representable ownership-tagged routes and rules in one
    /// explicit exclusive-writer scope.
    ///
    /// The safe default never infers collection ownership from legacy or
    /// single-candidate mutation support.
    async fn snapshot_owned_route_rules(
        &self,
        _scope: OwnedRouteRuleScope,
    ) -> Result<OwnedRouteRuleSnapshot, RouteSteeringError> {
        Err(RouteSteeringError::indeterminate(
            ReadbackIndeterminateReason::Unsupported,
        ))
    }

    /// Reconcile one complete exclusive-writer scope to authoritative desired
    /// state.
    ///
    /// Implementations must validate a complete bounded snapshot and desired
    /// set before deletion, install and verify desired state first, delete
    /// orphan rules before routes, and finish with a complete exact snapshot.
    /// Their initial recovery readback must also enumerate every bounded
    /// intermediate their own interrupted install-before-delete workflow can
    /// leave. The operation is serialized but is not a kernel-atomic
    /// transaction.
    async fn reconcile_owned_route_rules(
        &self,
        _desired: OwnedRouteRuleSet,
    ) -> Result<OwnedRouteRuleReconcileOutcome, RouteSteeringError> {
        Err(RouteSteeringError::indeterminate(
            ReadbackIndeterminateReason::Unsupported,
        ))
    }

    /// Probe backend capability and reachability.
    async fn probe(&self) -> Result<RouteSteeringProbe, RouteSteeringError>;

    /// Return operation contracts currently available from this adapter.
    ///
    /// Existing third-party implementations remain source compatible and are
    /// reported as legacy-only until they override this method.
    async fn capabilities(&self) -> RouteSteeringCapabilities {
        RouteSteeringCapabilities::legacy_only()
    }
}

pub(crate) fn route_readback_to_convergence(readback: RouteReadback) -> RouteConvergenceOutcome {
    match readback {
        RouteReadback::Absent => RouteConvergenceOutcome::Indeterminate(
            ReadbackIndeterminateReason::VanishedAfterCollision,
        ),
        RouteReadback::ExactPresent => RouteConvergenceOutcome::ExactAlreadyPresent,
        RouteReadback::Conflict(conflict) => RouteConvergenceOutcome::Conflict(conflict),
        RouteReadback::Indeterminate(reason) => RouteConvergenceOutcome::Indeterminate(reason),
    }
}

pub(crate) fn rule_readback_to_convergence(readback: RuleReadback) -> RuleConvergenceOutcome {
    match readback {
        RuleReadback::Absent => RuleConvergenceOutcome::Indeterminate(
            ReadbackIndeterminateReason::VanishedAfterCollision,
        ),
        RuleReadback::ExactPresent => RuleConvergenceOutcome::ExactAlreadyPresent,
        RuleReadback::Conflict(conflict) => RuleConvergenceOutcome::Conflict(conflict),
        RuleReadback::Indeterminate(reason) => RuleConvergenceOutcome::Indeterminate(reason),
    }
}

pub(crate) fn route_readback_after_owned_rollback(
    readback: RouteReadback,
) -> RouteConvergenceOutcome {
    match readback {
        RouteReadback::Absent => RouteConvergenceOutcome::IndeterminateAfterOwnedRollback(
            ReadbackIndeterminateReason::VanishedAfterCollision,
        ),
        RouteReadback::ExactPresent => RouteConvergenceOutcome::InstalledThenRolledBack,
        RouteReadback::Conflict(conflict) => {
            RouteConvergenceOutcome::ConflictAfterOwnedRollback(conflict)
        }
        RouteReadback::Indeterminate(reason) => {
            RouteConvergenceOutcome::IndeterminateAfterOwnedRollback(reason)
        }
    }
}

pub(crate) fn rule_readback_after_owned_rollback(readback: RuleReadback) -> RuleConvergenceOutcome {
    match readback {
        RuleReadback::Absent => RuleConvergenceOutcome::IndeterminateAfterOwnedRollback(
            ReadbackIndeterminateReason::VanishedAfterCollision,
        ),
        RuleReadback::ExactPresent => RuleConvergenceOutcome::IndeterminateAfterOwnedRollback(
            ReadbackIndeterminateReason::VanishedAfterCollision,
        ),
        RuleReadback::Conflict(conflict) => {
            RuleConvergenceOutcome::ConflictAfterOwnedRollback(conflict)
        }
        RuleReadback::Indeterminate(reason) => {
            RuleConvergenceOutcome::IndeterminateAfterOwnedRollback(reason)
        }
    }
}

pub(crate) fn route_readback_failure_class(
    readback: &RouteReadback,
) -> crate::error::RouteSteeringFailureClass {
    match readback {
        RouteReadback::Absent => crate::error::RouteSteeringFailureClass::NotFound,
        RouteReadback::ExactPresent => crate::error::RouteSteeringFailureClass::Io,
        RouteReadback::Conflict(_) => crate::error::RouteSteeringFailureClass::AlreadyExists,
        RouteReadback::Indeterminate(_) => {
            crate::error::RouteSteeringFailureClass::ReadbackIndeterminate
        }
    }
}

pub(crate) fn rule_readback_failure_class(
    readback: &RuleReadback,
) -> crate::error::RouteSteeringFailureClass {
    match readback {
        RuleReadback::Absent => crate::error::RouteSteeringFailureClass::NotFound,
        RuleReadback::ExactPresent => crate::error::RouteSteeringFailureClass::Io,
        RuleReadback::Conflict(_) => crate::error::RouteSteeringFailureClass::AlreadyExists,
        RuleReadback::Indeterminate(_) => {
            crate::error::RouteSteeringFailureClass::ReadbackIndeterminate
        }
    }
}
