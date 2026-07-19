//! Deterministic mock route-steering backend.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU16;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::backend::{
    route_readback_after_owned_rollback, route_readback_failure_class,
    route_readback_to_convergence, rule_readback_after_owned_rollback, rule_readback_failure_class,
    rule_readback_to_convergence, RouteSteeringBackend,
};
use crate::error::{RouteSteeringError, RouteSteeringFailureClass};
use crate::model::{
    RouteConflict, RouteConvergenceOutcome, RouteMismatch, RouteReadback, RouteRequest,
    RouteRuleConvergenceOutcome, RouteRuleRollback, RouteSteeringCapabilities, RouteSteeringProbe,
    RuleConflict, RuleConvergenceOutcome, RuleMismatch, RuleReadback, RuleRequest,
};
use crate::validation::{
    canonical_route_request, validate_owned_rule_request, validate_route_request,
    validate_rule_request,
};

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

/// One typed read observation made by the mock backend.
///
/// Readback was added without extending [`MockOperation`], preserving source
/// compatibility for existing exhaustive matches over that legacy enum.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MockObservation {
    /// Route readback.
    ReadRoute(RouteRequest),
    /// Rule readback.
    ReadRule(RuleRequest),
}

/// Operation boundary where the mock should inject its next targeted failure.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum MockFailurePoint {
    /// Route installation.
    InstallRoute,
    /// Route removal, including owned paired rollback.
    RemoveRoute,
    /// Rule installation.
    InstallRule,
    /// Rule removal.
    RemoveRule,
    /// Route readback.
    ReadRoute,
    /// Rule readback.
    ReadRule,
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
    observations: Vec<MockObservation>,
    routes: BTreeMap<RouteKernelKey, BTreeSet<MockRouteResident>>,
    rules: BTreeMap<RuleKernelKey, BTreeSet<MockRuleResident>>,
    probe_result: RouteSteeringProbe,
    failure: Option<RouteSteeringError>,
    targeted_failures: BTreeMap<MockFailurePoint, RouteSteeringError>,
}

const MAX_MOCK_CANDIDATES_PER_KEY: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct MockRouteResident {
    request: RouteRequest,
    owned: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct MockRuleResident {
    request: RuleRequest,
    owned: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
struct RouteKernelKey(crate::model::IpPrefix);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
struct RuleKernelKey {
    ipv4: bool,
    priority: u32,
}

impl RouteKernelKey {
    fn from_request(request: &RouteRequest) -> Self {
        Self(request.destination)
    }
}

impl RuleKernelKey {
    fn from_request(request: &RuleRequest) -> Self {
        let ipv4 = request
            .source
            .or(request.destination)
            .map(crate::model::IpPrefix::is_ipv4)
            .unwrap_or(true);
        Self {
            ipv4,
            priority: request.priority,
        }
    }
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
                observations: Vec::new(),
                routes: BTreeMap::new(),
                rules: BTreeMap::new(),
                probe_result,
                failure: None,
                targeted_failures: BTreeMap::new(),
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
        state.targeted_failures.clear();
    }

    /// Inject a one-shot error at a specific operation boundary.
    pub fn set_failure_at(&self, point: MockFailurePoint, error: RouteSteeringError) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.targeted_failures.insert(point, error);
    }

    /// Seed an SDK-owned resident route without recording an installation.
    ///
    /// Multiple kernel-valid candidates may share the broad destination
    /// readback key. An identical candidate is idempotent.
    pub fn seed_route(&self, route: RouteRequest) -> Result<(), RouteSteeringError> {
        self.seed_route_with_ownership(route, true)
    }

    /// Seed a foreign resident route for collision and ownership tests.
    pub fn seed_foreign_route(&self, route: RouteRequest) -> Result<(), RouteSteeringError> {
        self.seed_route_with_ownership(route, false)
    }

    /// Seed an SDK-owned resident rule without recording an installation.
    pub fn seed_rule(&self, rule: RuleRequest) -> Result<(), RouteSteeringError> {
        self.seed_rule_with_ownership(rule, true)
    }

    /// Seed a foreign resident rule for collision and ownership tests.
    pub fn seed_foreign_rule(&self, rule: RuleRequest) -> Result<(), RouteSteeringError> {
        self.seed_rule_with_ownership(rule, false)
    }

    fn seed_route_with_ownership(
        &self,
        route: RouteRequest,
        owned: bool,
    ) -> Result<(), RouteSteeringError> {
        validate_route_request(&route)?;
        let route = canonical_route_request(&route);
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let residents = state
            .routes
            .entry(RouteKernelKey::from_request(&route))
            .or_default();
        insert_bounded(
            residents,
            MockRouteResident {
                request: route,
                owned,
            },
        )
    }

    fn seed_rule_with_ownership(
        &self,
        rule: RuleRequest,
        owned: bool,
    ) -> Result<(), RouteSteeringError> {
        if owned {
            validate_owned_rule_request(&rule)?;
        } else {
            validate_rule_request(&rule)?;
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let residents = state
            .rules
            .entry(RuleKernelKey::from_request(&rule))
            .or_default();
        insert_bounded(
            residents,
            MockRuleResident {
                request: rule,
                owned,
            },
        )
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

    /// Return all typed read observations, in order.
    #[must_use]
    pub fn observations(&self) -> Vec<MockObservation> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.observations.clone()
    }

    fn check_failure(
        state: &mut MockState,
        point: MockFailurePoint,
    ) -> Result<(), RouteSteeringError> {
        if let Some(ref error) = state.failure {
            return Err(error.clone());
        }
        if let Some(error) = state.targeted_failures.remove(&point) {
            return Err(error);
        }
        Ok(())
    }

    fn install_route_locked(
        state: &mut MockState,
        request: RouteRequest,
        owned: bool,
    ) -> Result<(), RouteSteeringError> {
        validate_route_request(&request)?;
        Self::check_failure(state, MockFailurePoint::InstallRoute)?;
        let caller_request = request.clone();
        let request = canonical_route_request(&request);
        let key = RouteKernelKey::from_request(&request);
        let resident = MockRouteResident {
            request: request.clone(),
            owned,
        };
        let candidates = state.routes.entry(key).or_default();
        if candidates
            .iter()
            .any(|candidate| candidate.request == request)
        {
            return Err(RouteSteeringError::AlreadyExists);
        }
        insert_bounded(candidates, resident)?;
        state.operations.push(MockOperation::InstallRoute(if owned {
            request
        } else {
            caller_request
        }));
        Ok(())
    }

    fn remove_converged_route_locked(
        state: &mut MockState,
        request: RouteRequest,
    ) -> Result<(), RouteSteeringError> {
        validate_route_request(&request)?;
        Self::check_failure(state, MockFailurePoint::RemoveRoute)?;
        let request = canonical_route_request(&request);
        match Self::classify_route_locked(state, &request)? {
            RouteReadback::ExactPresent => {}
            RouteReadback::Absent => return Err(RouteSteeringError::NotFound),
            RouteReadback::Conflict(_) => return Err(RouteSteeringError::AlreadyExists),
            RouteReadback::Indeterminate(reason) => {
                return Err(RouteSteeringError::indeterminate(reason));
            }
        }
        let key = RouteKernelKey::from_request(&request);
        let remove_key = if let Some(candidates) = state.routes.get_mut(&key) {
            let removed = candidates.remove(&MockRouteResident {
                request: request.clone(),
                owned: true,
            });
            if !removed {
                return Err(RouteSteeringError::indeterminate(
                    crate::model::ReadbackIndeterminateReason::ConcurrentModification,
                ));
            }
            candidates.is_empty()
        } else {
            return Err(RouteSteeringError::indeterminate(
                crate::model::ReadbackIndeterminateReason::ConcurrentModification,
            ));
        };
        if remove_key {
            state.routes.remove(&key);
        }
        state.operations.push(MockOperation::RemoveRoute(request));
        Ok(())
    }

    fn remove_legacy_route_locked(
        state: &mut MockState,
        request: RouteRequest,
    ) -> Result<(), RouteSteeringError> {
        validate_route_request(&request)?;
        Self::check_failure(state, MockFailurePoint::RemoveRoute)?;
        let caller_request = request.clone();
        let request = canonical_route_request(&request);
        let key = RouteKernelKey::from_request(&request);
        let (candidate, remove_key) = {
            let Some(candidates) = state.routes.get_mut(&key) else {
                return Err(RouteSteeringError::NotFound);
            };
            let mut matches = candidates
                .iter()
                .filter(|candidate| candidate.request == request);
            let Some(candidate) = matches.next().cloned() else {
                return Err(RouteSteeringError::NotFound);
            };
            if matches.next().is_some() {
                return Err(RouteSteeringError::AlreadyExists);
            }
            let removed = candidates.remove(&candidate);
            if !removed {
                return Err(RouteSteeringError::indeterminate(
                    crate::model::ReadbackIndeterminateReason::ConcurrentModification,
                ));
            }
            (candidate, candidates.is_empty())
        };
        if remove_key {
            state.routes.remove(&key);
        }
        debug_assert_eq!(candidate.request, request);
        state
            .operations
            .push(MockOperation::RemoveRoute(caller_request));
        Ok(())
    }

    fn install_rule_locked(
        state: &mut MockState,
        request: RuleRequest,
        owned: bool,
    ) -> Result<(), RouteSteeringError> {
        if owned {
            validate_owned_rule_request(&request)?;
        } else {
            validate_rule_request(&request)?;
        }
        Self::check_failure(state, MockFailurePoint::InstallRule)?;
        let key = RuleKernelKey::from_request(&request);
        let resident = MockRuleResident {
            request: request.clone(),
            owned,
        };
        let candidates = state.rules.entry(key).or_default();
        if candidates
            .iter()
            .any(|candidate| candidate.request == request)
        {
            return Err(RouteSteeringError::AlreadyExists);
        }
        insert_bounded(candidates, resident)?;
        state.operations.push(MockOperation::InstallRule(request));
        Ok(())
    }

    fn remove_converged_rule_locked(
        state: &mut MockState,
        request: RuleRequest,
    ) -> Result<(), RouteSteeringError> {
        validate_owned_rule_request(&request)?;
        Self::check_failure(state, MockFailurePoint::RemoveRule)?;
        let key = RuleKernelKey::from_request(&request);
        match Self::classify_rule_locked(state, &request)? {
            RuleReadback::ExactPresent => {}
            RuleReadback::Absent => return Err(RouteSteeringError::NotFound),
            RuleReadback::Conflict(_) => return Err(RouteSteeringError::AlreadyExists),
            RuleReadback::Indeterminate(reason) => {
                return Err(RouteSteeringError::indeterminate(reason));
            }
        }
        let remove_key = if let Some(candidates) = state.rules.get_mut(&key) {
            let removed = candidates.remove(&MockRuleResident {
                request: request.clone(),
                owned: true,
            });
            if !removed {
                return Err(RouteSteeringError::indeterminate(
                    crate::model::ReadbackIndeterminateReason::ConcurrentModification,
                ));
            }
            candidates.is_empty()
        } else {
            return Err(RouteSteeringError::indeterminate(
                crate::model::ReadbackIndeterminateReason::ConcurrentModification,
            ));
        };
        if remove_key {
            state.rules.remove(&key);
        }
        state.operations.push(MockOperation::RemoveRule(request));
        Ok(())
    }

    fn remove_legacy_rule_locked(
        state: &mut MockState,
        request: RuleRequest,
    ) -> Result<(), RouteSteeringError> {
        validate_rule_request(&request)?;
        Self::check_failure(state, MockFailurePoint::RemoveRule)?;
        let key = RuleKernelKey::from_request(&request);
        let (candidate, remove_key) = {
            let Some(candidates) = state.rules.get_mut(&key) else {
                return Err(RouteSteeringError::NotFound);
            };
            let mut matches = candidates
                .iter()
                .filter(|candidate| candidate.request == request);
            let Some(candidate) = matches.next().cloned() else {
                return Err(RouteSteeringError::NotFound);
            };
            if matches.next().is_some() {
                return Err(RouteSteeringError::AlreadyExists);
            }
            let removed = candidates.remove(&candidate);
            if !removed {
                return Err(RouteSteeringError::indeterminate(
                    crate::model::ReadbackIndeterminateReason::ConcurrentModification,
                ));
            }
            (candidate, candidates.is_empty())
        };
        if remove_key {
            state.rules.remove(&key);
        }
        debug_assert_eq!(candidate.request, request);
        state.operations.push(MockOperation::RemoveRule(request));
        Ok(())
    }

    fn read_route_locked(
        state: &mut MockState,
        request: &RouteRequest,
    ) -> Result<RouteReadback, RouteSteeringError> {
        validate_route_request(request)?;
        Self::check_failure(state, MockFailurePoint::ReadRoute)?;
        let request = canonical_route_request(request);
        state
            .observations
            .push(MockObservation::ReadRoute(request.clone()));
        Self::classify_route_locked(state, &request)
    }

    fn read_rule_locked(
        state: &mut MockState,
        request: &RuleRequest,
    ) -> Result<RuleReadback, RouteSteeringError> {
        validate_rule_request(request)?;
        Self::check_failure(state, MockFailurePoint::ReadRule)?;
        state
            .observations
            .push(MockObservation::ReadRule(request.clone()));
        Self::classify_rule_locked(state, request)
    }

    fn classify_route_locked(
        state: &MockState,
        request: &RouteRequest,
    ) -> Result<RouteReadback, RouteSteeringError> {
        let Some(candidates) = state.routes.get(&RouteKernelKey::from_request(request)) else {
            return Ok(RouteReadback::Absent);
        };
        let candidate_count = candidate_count(candidates.len())?;
        let mut aggregate = RouteMismatch::default();
        let mut resident = None;
        let mut exact_count = 0_u16;
        for candidate in candidates {
            let mismatch = RouteMismatch {
                output_interface: candidate.request.oif_ifindex != request.oif_ifindex,
                table: candidate.request.table != request.table,
                priority: candidate.request.priority != request.priority,
                kernel_semantics: !candidate.owned,
            };
            aggregate.output_interface |= mismatch.output_interface;
            aggregate.table |= mismatch.table;
            aggregate.priority |= mismatch.priority;
            aggregate.kernel_semantics |= mismatch.kernel_semantics;
            if candidate.owned && candidate.request == *request {
                exact_count = exact_count.saturating_add(1);
            }
            if resident
                .as_ref()
                .is_none_or(|current: &RouteRequest| candidate.request < *current)
            {
                resident = Some(candidate.request.clone());
            }
        }
        if candidates.len() == 1 && exact_count == 1 {
            return Ok(RouteReadback::ExactPresent);
        }
        resident
            .map(|resident| {
                RouteReadback::Conflict(RouteConflict::new(resident, candidate_count, aggregate))
            })
            .ok_or_else(|| {
                RouteSteeringError::indeterminate(
                    crate::model::ReadbackIndeterminateReason::ConcurrentModification,
                )
            })
    }

    fn classify_rule_locked(
        state: &MockState,
        request: &RuleRequest,
    ) -> Result<RuleReadback, RouteSteeringError> {
        let Some(candidates) = state.rules.get(&RuleKernelKey::from_request(request)) else {
            return Ok(RuleReadback::Absent);
        };
        let candidate_count = candidate_count(candidates.len())?;
        let mut aggregate = RuleMismatch::default();
        let mut resident = None;
        let mut exact_count = 0_u16;
        for candidate in candidates {
            let mismatch = RuleMismatch {
                source: candidate.request.source != request.source,
                destination: candidate.request.destination != request.destination,
                firewall_mark: candidate.request.fwmark != request.fwmark,
                table: candidate.request.table != request.table,
                kernel_semantics: !candidate.owned,
            };
            aggregate.source |= mismatch.source;
            aggregate.destination |= mismatch.destination;
            aggregate.firewall_mark |= mismatch.firewall_mark;
            aggregate.table |= mismatch.table;
            aggregate.kernel_semantics |= mismatch.kernel_semantics;
            if candidate.owned && candidate.request == *request {
                exact_count = exact_count.saturating_add(1);
            }
            if resident
                .as_ref()
                .is_none_or(|current: &RuleRequest| candidate.request < *current)
            {
                resident = Some(candidate.request.clone());
            }
        }
        if candidates.len() == 1 && exact_count == 1 {
            return Ok(RuleReadback::ExactPresent);
        }
        resident
            .map(|resident| {
                RuleReadback::Conflict(RuleConflict::new(resident, candidate_count, aggregate))
            })
            .ok_or_else(|| {
                RouteSteeringError::indeterminate(
                    crate::model::ReadbackIndeterminateReason::ConcurrentModification,
                )
            })
    }

    fn converge_route_locked(
        state: &mut MockState,
        request: RouteRequest,
    ) -> Result<RouteConvergenceOutcome, RouteSteeringError> {
        match Self::read_route_locked(state, &request)? {
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
        match Self::install_route_locked(state, request.clone(), true) {
            Ok(()) => match Self::read_route_locked(state, &request) {
                Ok(RouteReadback::ExactPresent) => Ok(RouteConvergenceOutcome::Installed),
                Ok(readback) => {
                    let primary = route_readback_failure_class(&readback);
                    match Self::remove_converged_route_locked(state, request) {
                        Ok(()) => Ok(route_readback_after_owned_rollback(readback)),
                        Err(rollback) => Err(RouteSteeringError::RollbackFailed {
                            primary,
                            rollback: rollback.class(),
                        }),
                    }
                }
                Err(primary) => match Self::remove_converged_route_locked(state, request) {
                    Ok(()) => Err(primary),
                    Err(rollback) => Err(RouteSteeringError::RollbackFailed {
                        primary: primary.class(),
                        rollback: rollback.class(),
                    }),
                },
            },
            Err(RouteSteeringError::AlreadyExists) => Ok(route_readback_to_convergence(
                Self::read_route_locked(state, &request)?,
            )),
            Err(error) => Err(error),
        }
    }

    fn converge_rule_locked(
        state: &mut MockState,
        request: RuleRequest,
    ) -> Result<RuleConvergenceOutcome, RouteSteeringError> {
        validate_owned_rule_request(&request)?;
        match Self::read_rule_locked(state, &request)? {
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
        match Self::install_rule_locked(state, request.clone(), true) {
            Ok(()) => match Self::read_rule_locked(state, &request) {
                Ok(RuleReadback::ExactPresent) => Ok(RuleConvergenceOutcome::Installed),
                Ok(readback) => {
                    let primary = rule_readback_failure_class(&readback);
                    match Self::remove_converged_rule_locked(state, request) {
                        Ok(()) => Ok(rule_readback_after_owned_rollback(readback)),
                        Err(rollback) => Err(RouteSteeringError::RollbackFailed {
                            primary,
                            rollback: rollback.class(),
                        }),
                    }
                }
                Err(primary) => match Self::remove_converged_rule_locked(state, request) {
                    Ok(()) => Err(primary),
                    Err(rollback) => Err(RouteSteeringError::RollbackFailed {
                        primary: primary.class(),
                        rollback: rollback.class(),
                    }),
                },
            },
            Err(RouteSteeringError::AlreadyExists) => Ok(rule_readback_to_convergence(
                Self::read_rule_locked(state, &request)?,
            )),
            Err(error) => Err(error),
        }
    }
}

fn insert_bounded<T: Ord>(set: &mut BTreeSet<T>, value: T) -> Result<(), RouteSteeringError> {
    if !set.contains(&value) && set.len() >= MAX_MOCK_CANDIDATES_PER_KEY {
        return Err(RouteSteeringError::indeterminate(
            crate::model::ReadbackIndeterminateReason::LimitExceeded,
        ));
    }
    set.insert(value);
    Ok(())
}

fn candidate_count(len: usize) -> Result<NonZeroU16, RouteSteeringError> {
    let value = u16::try_from(len).map_err(|_| {
        RouteSteeringError::indeterminate(crate::model::ReadbackIndeterminateReason::LimitExceeded)
    })?;
    NonZeroU16::new(value).ok_or_else(|| {
        RouteSteeringError::indeterminate(
            crate::model::ReadbackIndeterminateReason::ConcurrentModification,
        )
    })
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
        Self::install_route_locked(&mut state, request, false)
    }

    async fn remove_route(&self, request: RouteRequest) -> Result<(), RouteSteeringError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::remove_legacy_route_locked(&mut state, request)
    }

    async fn install_rule(&self, request: RuleRequest) -> Result<(), RouteSteeringError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::install_rule_locked(&mut state, request, false)
    }

    async fn remove_rule(&self, request: RuleRequest) -> Result<(), RouteSteeringError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::remove_legacy_rule_locked(&mut state, request)
    }

    async fn remove_converged_route(
        &self,
        request: RouteRequest,
    ) -> Result<(), RouteSteeringError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::remove_converged_route_locked(&mut state, request)
    }

    async fn remove_converged_rule(&self, request: RuleRequest) -> Result<(), RouteSteeringError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::remove_converged_rule_locked(&mut state, request)
    }

    async fn read_route(
        &self,
        request: &RouteRequest,
    ) -> Result<RouteReadback, RouteSteeringError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::read_route_locked(&mut state, request)
    }

    async fn read_rule(&self, request: &RuleRequest) -> Result<RuleReadback, RouteSteeringError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::read_rule_locked(&mut state, request)
    }

    async fn converge_route(
        &self,
        request: RouteRequest,
    ) -> Result<RouteConvergenceOutcome, RouteSteeringError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::converge_route_locked(&mut state, request)
    }

    async fn converge_rule(
        &self,
        request: RuleRequest,
    ) -> Result<RuleConvergenceOutcome, RouteSteeringError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::converge_rule_locked(&mut state, request)
    }

    async fn converge_route_and_rule(
        &self,
        route: RouteRequest,
        rule: RuleRequest,
    ) -> Result<RouteRuleConvergenceOutcome, RouteSteeringError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        validate_route_request(&route)?;
        validate_owned_rule_request(&rule)?;

        let route_outcome = Self::converge_route_locked(&mut state, route.clone())?;

        if !matches!(
            route_outcome,
            RouteConvergenceOutcome::Installed | RouteConvergenceOutcome::ExactAlreadyPresent
        ) {
            let rollback = if route_outcome_has_owned_rollback(&route_outcome) {
                RouteRuleRollback::RemovedOwnedRoute
            } else {
                RouteRuleRollback::NotNeeded
            };
            return Ok(RouteRuleConvergenceOutcome {
                route: route_outcome,
                rule: RuleConvergenceOutcome::NotAttempted,
                rollback,
            });
        }

        let route_owned = matches!(route_outcome, RouteConvergenceOutcome::Installed);
        let rule_result = Self::converge_rule_locked(&mut state, rule);

        match rule_result {
            Ok(rule_outcome)
                if matches!(
                    rule_outcome,
                    RuleConvergenceOutcome::Installed | RuleConvergenceOutcome::ExactAlreadyPresent
                ) =>
            {
                Ok(RouteRuleConvergenceOutcome {
                    route: route_outcome,
                    rule: rule_outcome,
                    rollback: RouteRuleRollback::NotNeeded,
                })
            }
            Ok(rule_outcome) if route_owned => {
                match Self::remove_converged_route_locked(&mut state, route) {
                    Ok(()) => Ok(RouteRuleConvergenceOutcome {
                        route: RouteConvergenceOutcome::InstalledThenRolledBack,
                        rollback: if rule_outcome_has_owned_rollback(&rule_outcome) {
                            RouteRuleRollback::RemovedOwnedRouteAndRule
                        } else {
                            RouteRuleRollback::RemovedOwnedRoute
                        },
                        rule: rule_outcome,
                    }),
                    Err(rollback) => Err(RouteSteeringError::RollbackFailed {
                        primary: convergence_failure_class(&rule_outcome),
                        rollback: rollback.class(),
                    }),
                }
            }
            Ok(rule_outcome) => Ok(RouteRuleConvergenceOutcome {
                route: route_outcome,
                rollback: if rule_outcome_has_owned_rollback(&rule_outcome) {
                    RouteRuleRollback::RemovedOwnedRule
                } else {
                    RouteRuleRollback::NotNeeded
                },
                rule: rule_outcome,
            }),
            Err(primary) if route_owned => {
                match Self::remove_converged_route_locked(&mut state, route) {
                    Ok(()) => Err(primary),
                    Err(rollback) => Err(RouteSteeringError::RollbackFailed {
                        primary: primary.class(),
                        rollback: rollback.class(),
                    }),
                }
            }
            Err(primary) => Err(primary),
        }
    }

    async fn probe(&self) -> Result<RouteSteeringProbe, RouteSteeringError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::check_failure(&mut state, MockFailurePoint::Probe)?;
        state.operations.push(MockOperation::Probe);
        Ok(state.probe_result)
    }

    async fn capabilities(&self) -> RouteSteeringCapabilities {
        RouteSteeringCapabilities::mock()
    }
}

fn convergence_failure_class(outcome: &RuleConvergenceOutcome) -> RouteSteeringFailureClass {
    match outcome {
        RuleConvergenceOutcome::Conflict(_)
        | RuleConvergenceOutcome::ConflictAfterOwnedRollback(_) => {
            RouteSteeringFailureClass::AlreadyExists
        }
        RuleConvergenceOutcome::Indeterminate(_)
        | RuleConvergenceOutcome::IndeterminateAfterOwnedRollback(_)
        | RuleConvergenceOutcome::NotAttempted => RouteSteeringFailureClass::ReadbackIndeterminate,
        RuleConvergenceOutcome::Installed | RuleConvergenceOutcome::ExactAlreadyPresent => {
            RouteSteeringFailureClass::Io
        }
    }
}

fn route_outcome_has_owned_rollback(outcome: &RouteConvergenceOutcome) -> bool {
    matches!(
        outcome,
        RouteConvergenceOutcome::ConflictAfterOwnedRollback(_)
            | RouteConvergenceOutcome::IndeterminateAfterOwnedRollback(_)
            | RouteConvergenceOutcome::InstalledThenRolledBack
    )
}

fn rule_outcome_has_owned_rollback(outcome: &RuleConvergenceOutcome) -> bool {
    matches!(
        outcome,
        RuleConvergenceOutcome::ConflictAfterOwnedRollback(_)
            | RuleConvergenceOutcome::IndeterminateAfterOwnedRollback(_)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{FirewallMark, IpPrefix, RouteSteeringBackendKind};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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

    fn noncanonical_routes() -> [RouteRequest; 2] {
        [
            RouteRequest {
                destination: prefix([192, 0, 2, 129], 24),
                oif_ifindex: 42,
                table: 100,
                priority: Some(10),
            },
            RouteRequest {
                destination: IpPrefix::new(
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 1, 2, 3, 4, 5, 6)),
                    64,
                ),
                oif_ifindex: 42,
                table: 100,
                priority: Some(10),
            },
        ]
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
    async fn legacy_route_operation_log_preserves_exact_caller_request() {
        let cases = [
            RouteRequest {
                destination: prefix([192, 0, 2, 0], 24),
                oif_ifindex: 42,
                table: 100,
                priority: Some(0),
            },
            RouteRequest {
                destination: IpPrefix::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 128),
                oif_ifindex: 42,
                table: 100,
                priority: None,
            },
            RouteRequest {
                destination: IpPrefix::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 128),
                oif_ifindex: 42,
                table: 100,
                priority: Some(0),
            },
        ];

        for request in cases {
            let backend = MockRouteSteeringBackend::new();
            backend.install_route(request.clone()).await.unwrap();
            backend.remove_route(request.clone()).await.unwrap();
            assert_eq!(
                backend.operations(),
                vec![
                    MockOperation::InstallRoute(request.clone()),
                    MockOperation::RemoveRoute(request),
                ]
            );
        }
    }

    #[tokio::test]
    async fn route_network_canonicalization_matches_linux_and_preserves_legacy_logs() {
        for request in noncanonical_routes() {
            let canonical = canonical_route_request(&request);
            assert_ne!(canonical.destination, request.destination);

            let backend = MockRouteSteeringBackend::new();
            assert_eq!(
                backend.converge_route(request.clone()).await.unwrap(),
                RouteConvergenceOutcome::Installed
            );
            assert_eq!(
                backend.read_route(&request).await.unwrap(),
                RouteReadback::ExactPresent
            );
            assert_eq!(
                backend.operations(),
                vec![MockOperation::InstallRoute(canonical.clone())]
            );
            backend
                .remove_converged_route(request.clone())
                .await
                .unwrap();
            assert_eq!(
                backend.operations(),
                vec![
                    MockOperation::InstallRoute(canonical.clone()),
                    MockOperation::RemoveRoute(canonical),
                ]
            );

            let legacy = MockRouteSteeringBackend::new();
            legacy.install_route(request.clone()).await.unwrap();
            legacy.remove_route(request.clone()).await.unwrap();
            assert_eq!(
                legacy.operations(),
                vec![
                    MockOperation::InstallRoute(request.clone()),
                    MockOperation::RemoveRoute(request),
                ]
            );
        }
    }

    #[tokio::test]
    async fn owned_route_operation_log_uses_kernel_canonical_priority() {
        let backend = MockRouteSteeringBackend::new();
        let request = RouteRequest {
            destination: IpPrefix::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 128),
            oif_ifindex: 42,
            table: 100,
            priority: None,
        };
        assert_eq!(
            backend.converge_route(request.clone()).await.unwrap(),
            RouteConvergenceOutcome::Installed
        );

        let mut canonical = request;
        canonical.priority = Some(1024);
        assert_eq!(
            backend.operations(),
            vec![MockOperation::InstallRoute(canonical)]
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
    async fn mock_rejects_the_same_invalid_requests_as_linux() {
        let backend = MockRouteSteeringBackend::new();
        let mut invalid_route = route();
        invalid_route.oif_ifindex = 0;
        assert!(matches!(
            backend.install_route(invalid_route).await,
            Err(RouteSteeringError::InvalidConfig {
                field: "route.oif_ifindex",
                ..
            })
        ));

        let invalid_rule = RuleRequest {
            source: None,
            destination: None,
            fwmark: None,
            table: 100,
            priority: 1000,
        };
        assert!(matches!(
            backend.read_rule(&invalid_rule).await,
            Err(RouteSteeringError::InvalidConfig {
                field: "rule.selector",
                ..
            })
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
        assert_eq!(
            backend.capabilities().await,
            RouteSteeringCapabilities::mock()
        );
    }

    #[tokio::test]
    async fn legacy_rule_mutation_accepts_zero_mark_and_default_prefix() {
        let backend = MockRouteSteeringBackend::new();
        let legacy = RuleRequest {
            source: Some(prefix([0, 0, 0, 0], 0)),
            destination: None,
            fwmark: Some(crate::model::FirewallMark {
                value: 0,
                mask: 0xff,
            }),
            table: 100,
            priority: 1000,
        };
        backend.install_rule(legacy.clone()).await.unwrap();
        assert!(matches!(
            backend.read_rule(&legacy).await.unwrap(),
            RuleReadback::Conflict(_)
        ));
        assert!(matches!(
            backend.converge_rule(legacy.clone()).await,
            Err(RouteSteeringError::InvalidConfig { .. })
        ));
        backend.remove_rule(legacy).await.unwrap();
    }

    #[tokio::test]
    async fn exact_route_and_rule_retries_are_classified() {
        let backend = MockRouteSteeringBackend::new();
        backend.seed_route(route()).unwrap();
        backend.seed_rule(rule()).unwrap();

        assert_eq!(
            backend.converge_route(route()).await.unwrap(),
            RouteConvergenceOutcome::ExactAlreadyPresent
        );
        assert_eq!(
            backend.converge_rule(rule()).await.unwrap(),
            RuleConvergenceOutcome::ExactAlreadyPresent
        );
    }

    #[tokio::test]
    async fn kernel_key_collisions_report_every_modeled_mismatch() {
        let backend = MockRouteSteeringBackend::new();
        let mut resident_route = route();
        resident_route.oif_ifindex = 77;
        resident_route.table = 200;
        resident_route.priority = None;
        backend.seed_route(resident_route.clone()).unwrap();

        let route_conflict = match backend.read_route(&route()).await.unwrap() {
            RouteReadback::Conflict(conflict) => conflict,
            other => panic!("unexpected route readback: {other:?}"),
        };
        assert_eq!(route_conflict.resident(), &resident_route);
        assert_eq!(route_conflict.candidate_count().get(), 1);
        assert_eq!(
            route_conflict.mismatch(),
            RouteMismatch {
                output_interface: true,
                table: true,
                priority: true,
                kernel_semantics: false,
            }
        );

        let mut resident_rule = rule();
        resident_rule.source = None;
        resident_rule.destination = Some(prefix([192, 0, 2, 0], 24));
        resident_rule.fwmark = None;
        resident_rule.table = 200;
        backend.seed_rule(resident_rule.clone()).unwrap();
        let rule_conflict = match backend.read_rule(&rule()).await.unwrap() {
            RuleReadback::Conflict(conflict) => conflict,
            other => panic!("unexpected rule readback: {other:?}"),
        };
        assert_eq!(rule_conflict.resident(), &resident_rule);
        assert_eq!(
            rule_conflict.mismatch(),
            RuleMismatch {
                source: true,
                destination: true,
                firewall_mark: true,
                table: true,
                kernel_semantics: false,
            }
        );
    }

    #[tokio::test]
    async fn mock_multimap_matches_linux_exact_plus_conflict_semantics() {
        let backend = MockRouteSteeringBackend::new();
        backend.seed_route(route()).unwrap();
        let mut second_route = route();
        second_route.priority = Some(11);
        backend.seed_route(second_route).unwrap();
        let route_conflict = match backend.read_route(&route()).await.unwrap() {
            RouteReadback::Conflict(conflict) => conflict,
            other => panic!("unexpected route readback: {other:?}"),
        };
        assert_eq!(route_conflict.candidate_count().get(), 2);
        assert!(route_conflict.mismatch().priority);
        assert!(!route_conflict.mismatch().kernel_semantics);
        assert!(matches!(
            backend.remove_converged_route(route()).await,
            Err(RouteSteeringError::AlreadyExists)
        ));

        let backend = MockRouteSteeringBackend::new();
        backend.seed_rule(rule()).unwrap();
        let mut second_rule = rule();
        second_rule.table += 1;
        backend.seed_rule(second_rule).unwrap();
        let rule_conflict = match backend.read_rule(&rule()).await.unwrap() {
            RuleReadback::Conflict(conflict) => conflict,
            other => panic!("unexpected rule readback: {other:?}"),
        };
        assert_eq!(rule_conflict.candidate_count().get(), 2);
        assert!(rule_conflict.mismatch().table);
        assert!(!rule_conflict.mismatch().kernel_semantics);
        assert!(matches!(
            backend.remove_converged_rule(rule()).await,
            Err(RouteSteeringError::AlreadyExists)
        ));
    }

    #[tokio::test]
    async fn mock_foreign_candidates_are_conflicts_and_never_removed() {
        let backend = MockRouteSteeringBackend::new();
        backend.seed_foreign_route(route()).unwrap();
        assert!(matches!(
            backend.install_route(route()).await,
            Err(RouteSteeringError::AlreadyExists)
        ));
        let conflict = match backend.read_route(&route()).await.unwrap() {
            RouteReadback::Conflict(conflict) => conflict,
            other => panic!("unexpected route readback: {other:?}"),
        };
        assert!(conflict.mismatch().kernel_semantics);
        assert!(matches!(
            backend.converge_route(route()).await.unwrap(),
            RouteConvergenceOutcome::Conflict(_)
        ));
        assert!(matches!(
            backend.remove_converged_route(route()).await,
            Err(RouteSteeringError::AlreadyExists)
        ));

        let backend = MockRouteSteeringBackend::new();
        backend.seed_foreign_rule(rule()).unwrap();
        assert!(matches!(
            backend.install_rule(rule()).await,
            Err(RouteSteeringError::AlreadyExists)
        ));
        let conflict = match backend.read_rule(&rule()).await.unwrap() {
            RuleReadback::Conflict(conflict) => conflict,
            other => panic!("unexpected rule readback: {other:?}"),
        };
        assert!(conflict.mismatch().kernel_semantics);
        assert!(matches!(
            backend.converge_rule(rule()).await.unwrap(),
            RuleConvergenceOutcome::Conflict(_)
        ));
        assert!(matches!(
            backend.remove_converged_rule(rule()).await,
            Err(RouteSteeringError::AlreadyExists)
        ));
    }

    #[tokio::test]
    async fn mock_route_priorities_are_canonicalized_by_family() {
        let backend = MockRouteSteeringBackend::new();
        let mut ipv4_none = route();
        ipv4_none.priority = None;
        backend.seed_route(ipv4_none.clone()).unwrap();
        let mut ipv4_zero = ipv4_none.clone();
        ipv4_zero.priority = Some(0);
        assert_eq!(
            backend.read_route(&ipv4_zero).await.unwrap(),
            RouteReadback::ExactPresent
        );

        let ipv6_none = RouteRequest {
            destination: IpPrefix::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 128),
            oif_ifindex: 42,
            table: 100,
            priority: None,
        };
        backend.seed_route(ipv6_none.clone()).unwrap();
        let mut ipv6_zero = ipv6_none.clone();
        ipv6_zero.priority = Some(0);
        assert_eq!(
            backend.read_route(&ipv6_zero).await.unwrap(),
            RouteReadback::ExactPresent
        );
        let observed = backend.observations();
        assert!(matches!(
            observed.last(),
            Some(MockObservation::ReadRoute(RouteRequest {
                priority: Some(1024),
                ..
            }))
        ));
    }

    #[tokio::test]
    async fn mark_only_rules_share_the_linux_ipv4_priority_key() {
        let backend = MockRouteSteeringBackend::new();
        let mark_only = RuleRequest {
            source: None,
            destination: None,
            fwmark: rule().fwmark,
            table: rule().table,
            priority: rule().priority,
        };
        backend.seed_rule(mark_only).unwrap();
        assert!(matches!(
            backend.read_rule(&rule()).await.unwrap(),
            RuleReadback::Conflict(_)
        ));
    }

    #[tokio::test]
    async fn paired_exact_exact_and_installed_exact_do_not_remove_preexisting_state() {
        let exact = MockRouteSteeringBackend::new();
        exact.seed_route(route()).unwrap();
        exact.seed_rule(rule()).unwrap();
        let outcome = exact
            .converge_route_and_rule(route(), rule())
            .await
            .unwrap();
        assert_eq!(outcome.route, RouteConvergenceOutcome::ExactAlreadyPresent);
        assert_eq!(outcome.rule, RuleConvergenceOutcome::ExactAlreadyPresent);
        assert_eq!(outcome.rollback, RouteRuleRollback::NotNeeded);
        assert!(!exact
            .operations()
            .iter()
            .any(|operation| matches!(operation, MockOperation::RemoveRoute(_))));

        let installed = MockRouteSteeringBackend::new();
        installed.seed_rule(rule()).unwrap();
        let outcome = installed
            .converge_route_and_rule(route(), rule())
            .await
            .unwrap();
        assert_eq!(outcome.route, RouteConvergenceOutcome::Installed);
        assert_eq!(outcome.rule, RuleConvergenceOutcome::ExactAlreadyPresent);
        assert_eq!(outcome.rollback, RouteRuleRollback::NotNeeded);
        assert_eq!(
            installed.read_route(&route()).await.unwrap(),
            RouteReadback::ExactPresent
        );
    }

    #[tokio::test]
    async fn paired_rule_conflict_rolls_back_only_the_route_owned_by_this_attempt() {
        let backend = MockRouteSteeringBackend::new();
        let mut conflicting_rule = rule();
        conflicting_rule.table = 200;
        backend.seed_rule(conflicting_rule).unwrap();

        let outcome = backend
            .converge_route_and_rule(route(), rule())
            .await
            .unwrap();
        assert_eq!(
            outcome.route,
            RouteConvergenceOutcome::InstalledThenRolledBack
        );
        assert!(matches!(outcome.rule, RuleConvergenceOutcome::Conflict(_)));
        assert_eq!(outcome.rollback, RouteRuleRollback::RemovedOwnedRoute);
        assert_eq!(
            backend.read_route(&route()).await.unwrap(),
            RouteReadback::Absent
        );

        let preexisting = MockRouteSteeringBackend::new();
        preexisting.seed_route(route()).unwrap();
        preexisting
            .seed_rule({
                let mut value = rule();
                value.table = 200;
                value
            })
            .unwrap();
        let outcome = preexisting
            .converge_route_and_rule(route(), rule())
            .await
            .unwrap();
        assert_eq!(outcome.route, RouteConvergenceOutcome::ExactAlreadyPresent);
        assert!(matches!(outcome.rule, RuleConvergenceOutcome::Conflict(_)));
        assert_eq!(outcome.rollback, RouteRuleRollback::NotNeeded);
        assert_eq!(
            preexisting.read_route(&route()).await.unwrap(),
            RouteReadback::ExactPresent
        );
    }

    #[tokio::test]
    async fn paired_operational_error_rolls_back_and_preserves_both_failure_classes() {
        let backend = MockRouteSteeringBackend::new();
        backend.set_failure_at(
            MockFailurePoint::InstallRule,
            RouteSteeringError::io(
                "install_rule",
                std::io::Error::new(std::io::ErrorKind::PermissionDenied, "redacted"),
            ),
        );
        let error = backend
            .converge_route_and_rule(route(), rule())
            .await
            .unwrap_err();
        assert_eq!(error.class(), RouteSteeringFailureClass::Io);
        assert_eq!(
            backend.read_route(&route()).await.unwrap(),
            RouteReadback::Absent
        );

        let rollback_failure = MockRouteSteeringBackend::new();
        rollback_failure.set_failure_at(
            MockFailurePoint::InstallRule,
            RouteSteeringError::io(
                "install_rule",
                std::io::Error::new(std::io::ErrorKind::PermissionDenied, "redacted"),
            ),
        );
        rollback_failure.set_failure_at(
            MockFailurePoint::RemoveRoute,
            RouteSteeringError::io(
                "remove_route",
                std::io::Error::new(std::io::ErrorKind::TimedOut, "redacted"),
            ),
        );
        assert!(matches!(
            rollback_failure
                .converge_route_and_rule(route(), rule())
                .await
                .unwrap_err(),
            RouteSteeringError::RollbackFailed {
                primary: RouteSteeringFailureClass::Io,
                rollback: RouteSteeringFailureClass::Io,
            }
        ));
    }
}
