//! Bounded collection-safe route/rule ownership models.

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;

use crate::error::RouteSteeringError;
use crate::model::{IpPrefix, RouteRequest, RuleRequest};
use crate::validation::{
    canonical_route_priority, canonical_route_request, validate_owned_rule_request,
    validate_route_request,
};

/// Maximum number of convergence-owned routes in one authoritative set.
///
/// The matching rule limit is separate because a product may temporarily own
/// an unequal number of routes and rules while recovering crash orphans.
pub const MAX_OWNED_ROUTE_COLLECTION_ENTRIES: usize = 50_000;

/// Maximum number of convergence-owned rules in one authoritative set.
pub const MAX_OWNED_RULE_COLLECTION_ENTRIES: usize = 50_000;

pub(crate) const MAX_TRANSIENT_OWNED_ROUTE_COLLECTION_ENTRIES: usize =
    MAX_OWNED_ROUTE_COLLECTION_ENTRIES * 2;
pub(crate) const MAX_TRANSIENT_OWNED_RULE_COLLECTION_ENTRIES: usize =
    MAX_OWNED_RULE_COLLECTION_ENTRIES * 2;

/// Phase in which a serialized owned collection reconciliation stopped.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OwnedRouteRuleReconcilePhase {
    /// Installing routes missing from desired state.
    InstallRoutes,
    /// Installing rules missing from desired state.
    InstallRules,
    /// Verifying every desired object before garbage collection.
    VerifyDesired,
    /// Removing stale owned rules.
    RemoveRules,
    /// Removing stale owned routes.
    RemoveRoutes,
    /// Verifying the final complete owned snapshot.
    VerifyFinal,
}

/// Address family owned by one route/rule collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum RouteSteeringIpFamily {
    /// IPv4 routes and rules.
    Ipv4,
    /// IPv6 routes and rules.
    Ipv6,
}

/// Explicit exclusive-writer scope for one owned route/rule collection.
///
/// A scope owns one rule family/priority and one route family/table/output-
/// interface/metric tuple under the backend's namespace-local ownership
/// protocol. Reconciliation enumerates and garbage-collects only objects in
/// this scope. Constructing the value is an assertion that the caller is the
/// sole orchestrated writer for that scope; the Linux ownership marker is a
/// reservation, not authentication against another process deliberately
/// reusing it.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct OwnedRouteRuleScope {
    family: RouteSteeringIpFamily,
    table: u32,
    output_interface: u32,
    route_priority: Option<u32>,
    rule_priority: u32,
}

impl OwnedRouteRuleScope {
    /// Build an exclusive owned collection scope.
    ///
    /// `route_priority` is canonicalized like Linux route readback: IPv4 zero
    /// becomes absent, while IPv6 absent/zero becomes the effective metric
    /// `1024`.
    ///
    /// # Errors
    ///
    /// Returns [`RouteSteeringError::InvalidConfig`] for a zero table, output
    /// interface, or rule priority, or an output interface outside Linux's
    /// signed index range.
    pub fn new(
        family: RouteSteeringIpFamily,
        table: u32,
        output_interface: u32,
        route_priority: Option<u32>,
        rule_priority: u32,
    ) -> Result<Self, RouteSteeringError> {
        let address = match family {
            RouteSteeringIpFamily::Ipv4 => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            RouteSteeringIpFamily::Ipv6 => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        };
        let representative = RouteRequest {
            destination: IpPrefix::new(address, 0),
            oif_ifindex: output_interface,
            table,
            priority: route_priority,
        };
        validate_route_request(&representative)?;
        if rule_priority == 0 {
            return Err(RouteSteeringError::invalid_config(
                "owned.scope.rule_priority",
                "priority must be nonzero",
            ));
        }
        Ok(Self {
            family,
            table,
            output_interface,
            route_priority: canonical_route_priority(&representative),
            rule_priority,
        })
    }

    /// Address family owned by this collection.
    #[must_use]
    pub const fn family(self) -> RouteSteeringIpFamily {
        self.family
    }

    /// Route table required for every route and rule in this collection.
    #[must_use]
    pub const fn table(self) -> u32 {
        self.table
    }

    /// Output interface required for every route in this collection.
    #[must_use]
    pub const fn output_interface(self) -> u32 {
        self.output_interface
    }

    /// Canonical route metric required for every route in this collection.
    #[must_use]
    pub const fn route_priority(self) -> Option<u32> {
        self.route_priority
    }

    /// Rule priority exclusively owned by this collection in its family.
    #[must_use]
    pub const fn rule_priority(self) -> u32 {
        self.rule_priority
    }

    pub(crate) fn contains_route(self, route: &RouteRequest) -> bool {
        prefix_family(route.destination) == self.family
            && route.table == self.table
            && route.oif_ifindex == self.output_interface
            && route.priority == self.route_priority
    }

    pub(crate) fn contains_rule_key(self, rule: &RuleRequest) -> bool {
        rule_family(rule) == self.family && rule.priority == self.rule_priority
    }

    pub(crate) fn contains_rule(self, rule: &RuleRequest) -> bool {
        self.contains_rule_key(rule) && rule.table == self.table
    }
}

impl fmt::Debug for OwnedRouteRuleScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedRouteRuleScope")
            .field("family", &self.family)
            .field("table", &self.table)
            .field("output_interface", &self.output_interface)
            .field("route_priority", &self.route_priority)
            .field("rule_priority", &self.rule_priority)
            .finish()
    }
}

/// Authoritative desired state for one route-steering ownership protocol.
///
/// Construction validates and sorts every member, rejects duplicates and
/// broad route-key ambiguity, and permits same-family/same-priority rule
/// siblings only when they are source-only rules with provably disjoint,
/// non-wildcard prefixes. An empty set is valid and means garbage-collect all
/// representable objects owned by this writer.
#[derive(Clone, PartialEq, Eq)]
pub struct OwnedRouteRuleSet {
    scope: OwnedRouteRuleScope,
    routes: Vec<RouteRequest>,
    rules: Vec<RuleRequest>,
}

impl OwnedRouteRuleSet {
    /// Validate and build an authoritative owned route/rule set.
    ///
    /// # Errors
    ///
    /// Returns [`RouteSteeringError::InvalidConfig`] when a member is invalid,
    /// either collection bound is exceeded, a route destination key repeats,
    /// a rule repeats exactly, or same-priority rules are not provably
    /// disjoint source-only selectors.
    pub fn new(
        scope: OwnedRouteRuleScope,
        routes: Vec<RouteRequest>,
        rules: Vec<RuleRequest>,
    ) -> Result<Self, RouteSteeringError> {
        validate_and_sort_collection(
            scope,
            routes,
            rules,
            MAX_OWNED_ROUTE_COLLECTION_ENTRIES,
            MAX_OWNED_RULE_COLLECTION_ENTRIES,
        )
        .map(|(routes, rules)| Self {
            scope,
            routes,
            rules,
        })
    }

    /// Exclusive-writer scope for this desired set.
    #[must_use]
    pub const fn scope(&self) -> OwnedRouteRuleScope {
        self.scope
    }

    /// Canonical owned routes in deterministic order.
    #[must_use]
    pub fn routes(&self) -> &[RouteRequest] {
        &self.routes
    }

    /// Owned rules in deterministic order.
    #[must_use]
    pub fn rules(&self) -> &[RuleRequest] {
        &self.rules
    }

    /// Consume the set into its scope and canonical route and rule vectors.
    #[must_use]
    pub fn into_parts(self) -> (OwnedRouteRuleScope, Vec<RouteRequest>, Vec<RuleRequest>) {
        (self.scope, self.routes, self.rules)
    }
}

impl fmt::Debug for OwnedRouteRuleSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedRouteRuleSet")
            .field("route_count", &self.routes.len())
            .field("rule_count", &self.rules.len())
            .finish()
    }
}

/// Bounded, enumerable snapshot of all representable objects owned by one
/// route-steering writer in the current network namespace.
///
/// The snapshot contains no foreign objects. A backend must fail the snapshot
/// operation instead of omitting an ownership-tagged object it cannot model.
#[derive(Clone, PartialEq, Eq)]
pub struct OwnedRouteRuleSnapshot {
    scope: OwnedRouteRuleScope,
    routes: Vec<RouteRequest>,
    rules: Vec<RuleRequest>,
}

impl OwnedRouteRuleSnapshot {
    /// Build a validated snapshot for an external backend implementation.
    ///
    /// # Errors
    ///
    /// Returns the same validation errors as [`OwnedRouteRuleSet::new`].
    pub fn new(
        scope: OwnedRouteRuleScope,
        routes: Vec<RouteRequest>,
        rules: Vec<RuleRequest>,
    ) -> Result<Self, RouteSteeringError> {
        validate_and_sort_collection(
            scope,
            routes,
            rules,
            MAX_OWNED_ROUTE_COLLECTION_ENTRIES,
            MAX_OWNED_RULE_COLLECTION_ENTRIES,
        )
        .map(|(routes, rules)| Self {
            scope,
            routes,
            rules,
        })
    }

    pub(crate) fn new_transient(
        scope: OwnedRouteRuleScope,
        routes: Vec<RouteRequest>,
        rules: Vec<RuleRequest>,
    ) -> Result<Self, RouteSteeringError> {
        validate_and_sort_collection(
            scope,
            routes,
            rules,
            MAX_TRANSIENT_OWNED_ROUTE_COLLECTION_ENTRIES,
            MAX_TRANSIENT_OWNED_RULE_COLLECTION_ENTRIES,
        )
        .map(|(routes, rules)| Self {
            scope,
            routes,
            rules,
        })
    }

    /// Exclusive-writer scope represented by this snapshot.
    #[must_use]
    pub const fn scope(&self) -> OwnedRouteRuleScope {
        self.scope
    }

    /// Canonical owned routes in deterministic order.
    #[must_use]
    pub fn routes(&self) -> &[RouteRequest] {
        &self.routes
    }

    /// Owned rules in deterministic order.
    #[must_use]
    pub fn rules(&self) -> &[RuleRequest] {
        &self.rules
    }

    /// Consume the snapshot into its scope and canonical route and rule vectors.
    #[must_use]
    pub fn into_parts(self) -> (OwnedRouteRuleScope, Vec<RouteRequest>, Vec<RuleRequest>) {
        (self.scope, self.routes, self.rules)
    }

    pub(crate) fn matches_desired(&self, desired: &OwnedRouteRuleSet) -> bool {
        self.scope == desired.scope && self.routes == desired.routes && self.rules == desired.rules
    }
}

impl fmt::Debug for OwnedRouteRuleSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedRouteRuleSnapshot")
            .field("route_count", &self.routes.len())
            .field("rule_count", &self.rules.len())
            .finish()
    }
}

/// Successful authoritative owned route/rule reconciliation evidence.
///
/// A successful result proves the final owned snapshot exactly equals the
/// requested set. Counts distinguish exact retry/adoption from installation
/// and crash-orphan garbage collection without exposing selector values.
#[derive(Clone, PartialEq, Eq)]
pub struct OwnedRouteRuleReconcileOutcome {
    /// Final exact owned-state snapshot.
    pub snapshot: OwnedRouteRuleSnapshot,
    /// Routes already exact before this attempt.
    pub retained_routes: usize,
    /// Routes installed and verified by this attempt.
    pub installed_routes: usize,
    /// Stale owned routes removed by this attempt.
    pub removed_routes: usize,
    /// Rules already exact before this attempt.
    pub retained_rules: usize,
    /// Rules installed and verified by this attempt.
    pub installed_rules: usize,
    /// Stale owned rules removed by this attempt.
    pub removed_rules: usize,
}

impl fmt::Debug for OwnedRouteRuleReconcileOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedRouteRuleReconcileOutcome")
            .field("final_route_count", &self.snapshot.routes.len())
            .field("final_rule_count", &self.snapshot.rules.len())
            .field("retained_routes", &self.retained_routes)
            .field("installed_routes", &self.installed_routes)
            .field("removed_routes", &self.removed_routes)
            .field("retained_rules", &self.retained_rules)
            .field("installed_rules", &self.installed_rules)
            .field("removed_rules", &self.removed_rules)
            .finish()
    }
}

pub(crate) fn reconcile_incomplete(
    phase: OwnedRouteRuleReconcilePhase,
    installed_routes: usize,
    installed_rules: usize,
    removed_routes: usize,
    removed_rules: usize,
    failure: &RouteSteeringError,
) -> RouteSteeringError {
    RouteSteeringError::ReconcileIncomplete {
        phase,
        installed_routes,
        installed_rules,
        removed_routes,
        removed_rules,
        failure: failure.class(),
        rollback_failure: None,
    }
}

pub(crate) fn reconcile_rollback_incomplete(
    phase: OwnedRouteRuleReconcilePhase,
    installed_routes: usize,
    installed_rules: usize,
    removed_routes: usize,
    removed_rules: usize,
    failure: &RouteSteeringError,
    rollback_failure: crate::error::RouteSteeringFailureClass,
) -> RouteSteeringError {
    RouteSteeringError::ReconcileIncomplete {
        phase,
        installed_routes,
        installed_rules,
        removed_routes,
        removed_rules,
        failure: failure.class(),
        rollback_failure: Some(rollback_failure),
    }
}

fn validate_and_sort_collection(
    scope: OwnedRouteRuleScope,
    routes: Vec<RouteRequest>,
    mut rules: Vec<RuleRequest>,
    max_routes: usize,
    max_rules: usize,
) -> Result<(Vec<RouteRequest>, Vec<RuleRequest>), RouteSteeringError> {
    if routes.len() > max_routes {
        return Err(RouteSteeringError::invalid_config(
            "owned.routes",
            "owned route collection exceeds the supported bound",
        ));
    }
    if rules.len() > max_rules {
        return Err(RouteSteeringError::invalid_config(
            "owned.rules",
            "owned rule collection exceeds the supported bound",
        ));
    }

    let mut routes = routes
        .into_iter()
        .map(|route| {
            validate_route_request(&route)?;
            let route = canonical_route_request(&route);
            if !scope.contains_route(&route) {
                return Err(RouteSteeringError::invalid_config(
                    "owned.routes",
                    "route is outside the exclusive collection scope",
                ));
            }
            Ok(route)
        })
        .collect::<Result<Vec<_>, RouteSteeringError>>()?;
    for rule in &rules {
        validate_owned_rule_request(rule)?;
        if !scope.contains_rule(rule) {
            return Err(RouteSteeringError::invalid_config(
                "owned.rules",
                "rule is outside the exclusive collection scope",
            ));
        }
    }
    routes.sort_unstable();
    rules.sort_unstable();

    for adjacent in routes.windows(2) {
        if adjacent[0].destination == adjacent[1].destination {
            return Err(RouteSteeringError::invalid_config(
                "owned.routes",
                "owned routes repeat an effective destination key",
            ));
        }
    }
    if rules.windows(2).any(|adjacent| adjacent[0] == adjacent[1]) {
        return Err(RouteSteeringError::invalid_config(
            "owned.rules",
            "owned rules contain an exact duplicate",
        ));
    }
    validate_same_priority_rule_siblings(&rules)?;
    Ok((routes, rules))
}

fn validate_same_priority_rule_siblings(rules: &[RuleRequest]) -> Result<(), RouteSteeringError> {
    let mut groups = BTreeMap::<(bool, u32), Vec<IpPrefix>>::new();
    for rule in rules {
        groups
            .entry((rule_is_ipv4(rule), rule.priority))
            .or_default()
            .push(match (rule.source, rule.destination, rule.fwmark) {
                (Some(source), None, None) => source,
                _ => {
                    // A sole rule at its family/priority needs no sibling
                    // disjointness proof. Record a sentinel and reject only if
                    // another member actually shares this broad kernel key.
                    IpPrefix::new(unspecified_address(rule_is_ipv4(rule)), 0)
                }
            });
    }

    for prefixes in groups.values_mut().filter(|group| group.len() > 1) {
        if prefixes.iter().any(|prefix| prefix.prefix_len == 0) {
            return Err(RouteSteeringError::invalid_config(
                "owned.rules",
                "same-priority siblings must be source-only non-wildcard rules",
            ));
        }
        prefixes.sort_unstable_by_key(|prefix| prefix_range(*prefix));
        let mut previous_end = None;
        for prefix in prefixes {
            let (start, end) = prefix_range(*prefix);
            if previous_end.is_some_and(|prior| start <= prior) {
                return Err(RouteSteeringError::invalid_config(
                    "owned.rules",
                    "same-priority source selectors overlap",
                ));
            }
            previous_end = Some(end);
        }
    }
    Ok(())
}

pub(crate) fn rule_is_ipv4(rule: &RuleRequest) -> bool {
    rule.source
        .or(rule.destination)
        .map(IpPrefix::is_ipv4)
        .unwrap_or(true)
}

pub(crate) fn rule_family(rule: &RuleRequest) -> RouteSteeringIpFamily {
    if rule_is_ipv4(rule) {
        RouteSteeringIpFamily::Ipv4
    } else {
        RouteSteeringIpFamily::Ipv6
    }
}

fn prefix_family(prefix: IpPrefix) -> RouteSteeringIpFamily {
    if prefix.is_ipv4() {
        RouteSteeringIpFamily::Ipv4
    } else {
        RouteSteeringIpFamily::Ipv6
    }
}

fn unspecified_address(ipv4: bool) -> IpAddr {
    if ipv4 {
        IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
    }
}

fn prefix_range(prefix: IpPrefix) -> (u128, u128) {
    match prefix.address {
        IpAddr::V4(address) => {
            let host_bits = 32_u32.saturating_sub(u32::from(prefix.prefix_len));
            let mask = u32::MAX.checked_shl(host_bits).unwrap_or(0);
            let start = u32::from(address) & mask;
            (u128::from(start), u128::from(start | !mask))
        }
        IpAddr::V6(address) => {
            let host_bits = 128_u32.saturating_sub(u32::from(prefix.prefix_len));
            let mask = u128::MAX.checked_shl(host_bits).unwrap_or(0);
            let start = u128::from(address) & mask;
            (start, start | !mask)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn source_rule(host: u8) -> RuleRequest {
        RuleRequest {
            source: Some(IpPrefix::new(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, host)),
                32,
            )),
            destination: None,
            fwmark: None,
            table: 1000,
            priority: 900,
        }
    }

    fn scope() -> OwnedRouteRuleScope {
        OwnedRouteRuleScope::new(RouteSteeringIpFamily::Ipv4, 1000, 42, Some(10), 900).unwrap()
    }

    #[test]
    fn same_priority_disjoint_sources_are_valid_and_redacted() {
        let set =
            OwnedRouteRuleSet::new(scope(), Vec::new(), vec![source_rule(11), source_rule(10)])
                .unwrap();
        assert_eq!(set.rules()[0], source_rule(10));
        let debug = format!("{set:?}");
        assert_eq!(debug, "OwnedRouteRuleSet { route_count: 0, rule_count: 2 }");
        assert!(!debug.contains("192.0.2"));
    }

    #[test]
    fn same_priority_overlap_and_non_source_siblings_are_rejected() {
        let mut broad = source_rule(0);
        broad.source = Some(IpPrefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24));
        assert!(OwnedRouteRuleSet::new(scope(), Vec::new(), vec![broad, source_rule(10)]).is_err());

        let mut marked = source_rule(11);
        marked.source = None;
        marked.fwmark = Some(crate::model::FirewallMark {
            value: 7,
            mask: u32::MAX,
        });
        assert!(
            OwnedRouteRuleSet::new(scope(), Vec::new(), vec![source_rule(10), marked]).is_err()
        );
    }
}
