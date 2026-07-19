//! Safe model types for route/rule steering operations.

use std::fmt;
use std::net::IpAddr;
use std::num::NonZeroU16;

/// IP prefix used by routes and rules.
///
/// Construction preserves the supplied address. Route convergence uses the
/// effective network address with host bits cleared; rule selectors retain
/// their supplied address semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct IpPrefix {
    /// Prefix address.
    pub address: IpAddr,
    /// Prefix length.
    pub prefix_len: u8,
}

impl IpPrefix {
    /// Build an IP prefix.
    #[must_use]
    pub const fn new(address: IpAddr, prefix_len: u8) -> Self {
        Self {
            address,
            prefix_len,
        }
    }

    /// True when the prefix is IPv4.
    #[must_use]
    pub const fn is_ipv4(self) -> bool {
        matches!(self.address, IpAddr::V4(_))
    }
}

/// Optional firewall mark selector for rule steering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct FirewallMark {
    /// Mark value.
    pub value: u32,
    /// Mark mask.
    pub mask: u32,
}

/// Route installation/removal request.
#[derive(Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct RouteRequest {
    /// Destination prefix.
    ///
    /// Conflict-safe route readback and convergence use the effective network
    /// address with host bits cleared. Legacy Linux install/remove mutation
    /// continues to emit the caller-supplied address bytes.
    pub destination: IpPrefix,
    /// Output interface index.
    pub oif_ifindex: u32,
    /// Linux route table.
    pub table: u32,
    /// Optional route metric/priority.
    ///
    /// Linux canonicalizes IPv4 `None`/zero to no metric and IPv6
    /// `None`/zero to the effective metric `1024`.
    pub priority: Option<u32>,
}

impl fmt::Debug for RouteRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RouteRequest")
            .field("destination", &RedactedPrefix(self.destination))
            .field("oif_ifindex", &self.oif_ifindex)
            .field("table", &self.table)
            .field("priority", &self.priority)
            .finish()
    }
}

/// Rule installation/removal request.
#[derive(Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct RuleRequest {
    /// Optional source prefix selector.
    ///
    /// Legacy mutation and readback accept `/0` to preserve the address family
    /// selected by existing callers. Conflict-safe convergence rejects `/0`
    /// because Linux rule deletion treats it as a wildcard.
    pub source: Option<IpPrefix>,
    /// Optional destination prefix selector.
    ///
    /// Legacy mutation and readback accept `/0`; see [`Self::source`].
    pub destination: Option<IpPrefix>,
    /// Optional firewall mark and nonzero mask selector.
    ///
    /// A mark-only rule uses Linux's IPv4 default family. Legacy mutation and
    /// readback accept a zero mark value, while conflict-safe convergence
    /// rejects it because Linux deletion treats it as a wildcard.
    pub fwmark: Option<FirewallMark>,
    /// Linux route table to look up.
    pub table: u32,
    /// Rule priority.
    pub priority: u32,
}

impl fmt::Debug for RuleRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuleRequest")
            .field("source", &self.source.map(RedactedPrefix))
            .field("destination", &self.destination.map(RedactedPrefix))
            .field("fwmark", &self.fwmark.map(|_| "<redacted>"))
            .field("table", &self.table)
            .field("priority", &self.priority)
            .finish()
    }
}

struct RedactedPrefix(IpPrefix);

impl fmt::Debug for RedactedPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let family = if self.0.is_ipv4() { "ipv4" } else { "ipv6" };
        f.debug_struct("IpPrefix")
            .field("family", &family)
            .field("address", &"<redacted>")
            .field("prefix_len", &self.0.prefix_len)
            .finish()
    }
}

/// Stable reason that route/rule readback could not prove resident identity.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReadbackIndeterminateReason {
    /// The backend or running platform does not support typed readback.
    Unsupported,
    /// The platform cannot preserve the ownership marker required for exact
    /// rule convergence and removal.
    OwnershipMarkerUnsupported,
    /// The kernel did not complete a bounded multipart dump.
    IncompleteReply,
    /// A reply was malformed, truncated, or contradicted its own metadata.
    MalformedReply,
    /// A configured byte, datagram, message, or candidate bound was exceeded.
    LimitExceeded,
    /// Kernel state could not be read because the backend was unavailable.
    BackendUnavailable,
    /// A colliding kernel object contains semantics outside this crate's model.
    UnrepresentableObject,
    /// An exclusive-create collision disappeared before it could be read back.
    VanishedAfterCollision,
    /// State changed while one serialized operation was being verified.
    ConcurrentModification,
}

/// Fields that differ on a colliding resident route.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct RouteMismatch {
    /// The output interface differs.
    pub output_interface: bool,
    /// The route table differs.
    pub table: bool,
    /// The optional route metric/priority differs.
    pub priority: bool,
    /// Fixed kernel semantics or extra attributes cannot match the request.
    pub kernel_semantics: bool,
}

/// Bounded evidence for resident routes sharing the requested destination key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteConflict {
    resident: RouteRequest,
    candidate_count: NonZeroU16,
    mismatch: RouteMismatch,
}

impl RouteConflict {
    /// Build conflict evidence from a typed resident and a nonzero candidate count.
    ///
    /// This constructor is public so external [`crate::RouteSteeringBackend`]
    /// implementations can return the same validated evidence as the built-in
    /// adapters. [`NonZeroU16`] prevents an impossible zero-candidate conflict.
    #[must_use]
    pub const fn new(
        resident: RouteRequest,
        candidate_count: NonZeroU16,
        mismatch: RouteMismatch,
    ) -> Self {
        Self {
            resident,
            candidate_count,
            mismatch,
        }
    }

    /// First deterministic resident identity. Its `Debug` output is redacted.
    #[must_use]
    pub const fn resident(&self) -> &RouteRequest {
        &self.resident
    }

    /// Number of colliding candidates observed in the bounded dump.
    #[must_use]
    pub const fn candidate_count(&self) -> NonZeroU16 {
        self.candidate_count
    }

    /// Aggregate mismatch fields across all colliding candidates.
    #[must_use]
    pub const fn mismatch(&self) -> RouteMismatch {
        self.mismatch
    }
}

/// Fields that differ on a colliding resident policy rule.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct RuleMismatch {
    /// The source selector differs.
    pub source: bool,
    /// The destination selector differs.
    pub destination: bool,
    /// The firewall mark or mask differs.
    pub firewall_mark: bool,
    /// The lookup table differs.
    pub table: bool,
    /// Fixed kernel semantics or extra attributes cannot match the request.
    pub kernel_semantics: bool,
}

/// Bounded evidence for resident rules sharing the requested family/priority key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleConflict {
    resident: RuleRequest,
    candidate_count: NonZeroU16,
    mismatch: RuleMismatch,
}

impl RuleConflict {
    /// Build conflict evidence from a typed resident and a nonzero candidate count.
    ///
    /// This constructor is public so external [`crate::RouteSteeringBackend`]
    /// implementations can return the same validated evidence as the built-in
    /// adapters. [`NonZeroU16`] prevents an impossible zero-candidate conflict.
    #[must_use]
    pub const fn new(
        resident: RuleRequest,
        candidate_count: NonZeroU16,
        mismatch: RuleMismatch,
    ) -> Self {
        Self {
            resident,
            candidate_count,
            mismatch,
        }
    }

    /// First deterministic resident identity. Its `Debug` output is redacted.
    #[must_use]
    pub const fn resident(&self) -> &RuleRequest {
        &self.resident
    }

    /// Number of colliding candidates observed in the bounded dump.
    #[must_use]
    pub const fn candidate_count(&self) -> NonZeroU16 {
        self.candidate_count
    }

    /// Aggregate mismatch fields across all colliding candidates.
    #[must_use]
    pub const fn mismatch(&self) -> RuleMismatch {
        self.mismatch
    }
}

/// Typed result of reading back a route's logical destination key.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteReadback {
    /// No resident route shares the requested destination key.
    Absent,
    /// Exactly one fully representable resident route matches every field.
    ExactPresent,
    /// At least one resident route shares the key but differs from the request.
    Conflict(RouteConflict),
    /// The backend could not prove absence, equality, or conflict safely.
    Indeterminate(ReadbackIndeterminateReason),
}

/// Typed result of reading back a rule's address-family/priority key.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleReadback {
    /// No resident rule shares the requested key.
    Absent,
    /// Exactly one fully representable resident rule matches every field.
    ExactPresent,
    /// At least one resident rule shares the key but differs from the request.
    Conflict(RuleConflict),
    /// The backend could not prove absence, equality, or conflict safely.
    Indeterminate(ReadbackIndeterminateReason),
}

/// Outcome of converging one route.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteConvergenceOutcome {
    /// This attempt installed the route.
    Installed,
    /// The exact route was already resident.
    ExactAlreadyPresent,
    /// A colliding non-equal route is resident.
    Conflict(RouteConflict),
    /// Safe convergence could not determine resident state.
    Indeterminate(ReadbackIndeterminateReason),
    /// A post-install collision was detected and the route owned by this call was removed.
    ConflictAfterOwnedRollback(RouteConflict),
    /// Post-install state was indeterminate and the route owned by this call was removed.
    IndeterminateAfterOwnedRollback(ReadbackIndeterminateReason),
    /// This attempt installed the route and then removed it during owned rollback.
    InstalledThenRolledBack,
    /// Route convergence was intentionally not attempted.
    NotAttempted,
}

/// Outcome of converging one rule.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleConvergenceOutcome {
    /// This attempt installed the rule.
    Installed,
    /// The exact rule was already resident.
    ExactAlreadyPresent,
    /// A colliding non-equal rule is resident.
    Conflict(RuleConflict),
    /// Safe convergence could not determine resident state.
    Indeterminate(ReadbackIndeterminateReason),
    /// A post-install collision was detected and the rule owned by this call was removed.
    ConflictAfterOwnedRollback(RuleConflict),
    /// Post-install state was indeterminate and the rule owned by this call was removed.
    IndeterminateAfterOwnedRollback(ReadbackIndeterminateReason),
    /// Rule convergence was intentionally not attempted.
    NotAttempted,
}

/// Rollback performed by a paired route/rule convergence attempt.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteRuleRollback {
    /// No rollback was needed; no pre-existing object is ever removed.
    NotNeeded,
    /// The route installed by this same attempt was removed after rule failure.
    RemovedOwnedRoute,
    /// A rule installed by this attempt was removed after post-install verification.
    RemovedOwnedRule,
    /// Both objects installed by this attempt were removed safely.
    RemovedOwnedRouteAndRule,
}

/// Complete, typed result for a paired route and policy-rule convergence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRuleConvergenceOutcome {
    /// Route-side result, including owned rollback when applicable.
    pub route: RouteConvergenceOutcome,
    /// Rule-side result.
    pub rule: RuleConvergenceOutcome,
    /// Which objects this attempt rolled back after installing them itself.
    pub rollback: RouteRuleRollback,
}

/// Effective operation families implemented by a route-steering backend.
///
/// This is separate from [`RouteSteeringProbe`]: capabilities describe which
/// contracts an adapter implements, while the probe reports current platform,
/// privilege, and reachability state. In particular, legacy mutation support
/// is not evidence that conflict-safe convergence or exact owned removal is
/// available.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct RouteSteeringCapabilities {
    /// The original best-effort install/remove methods are implemented.
    pub legacy_mutation: bool,
    /// Typed route readback, convergence, and owned removal are implemented.
    pub conflict_safe_route_convergence: bool,
    /// Typed rule readback, convergence, and owned removal are implemented.
    pub conflict_safe_rule_convergence: bool,
    /// Cancellation-safe paired route/rule convergence is implemented.
    pub paired_convergence: bool,
    /// Bounded exclusive-scope owned route/rule snapshot and authoritative
    /// reconciliation are implemented and may be attempted fail closed.
    ///
    /// For the Linux backend this is an attempt capability, not proof that the
    /// running kernel retained the rule ownership marker. Inspect
    /// `LinuxRouteSteeringBackend::rule_protocol_capability` when marker
    /// attestation is required; `Unknown` and `ExpectedByKernelVersion` permit
    /// a self-verifying bootstrap attempt, while only `Confirmed` is positive
    /// readback evidence.
    pub owned_route_rule_collection: bool,
}

impl RouteSteeringCapabilities {
    /// Capabilities for a backend that implements only the original mutation API.
    #[must_use]
    pub const fn legacy_only() -> Self {
        Self {
            legacy_mutation: true,
            conflict_safe_route_convergence: false,
            conflict_safe_rule_convergence: false,
            paired_convergence: false,
            owned_route_rule_collection: false,
        }
    }

    /// Capabilities for the deterministic mock backend.
    #[must_use]
    pub const fn mock() -> Self {
        Self {
            legacy_mutation: true,
            conflict_safe_route_convergence: true,
            conflict_safe_rule_convergence: true,
            paired_convergence: true,
            owned_route_rule_collection: true,
        }
    }
}

/// Kind of route-steering backend implementation.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum RouteSteeringBackendKind {
    /// Backend is not implemented for the current platform.
    #[default]
    Unsupported,
    /// Backend talks to Linux rtnetlink.
    LinuxKernel,
    /// In-memory mock backend.
    Mock,
}

/// Capability and health probe for a route-steering backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RouteSteeringProbe {
    /// Kind of backend that produced the probe.
    pub kind: RouteSteeringBackendKind,
    /// The platform supports route steering.
    pub platform_supported: bool,
    /// The backend believes it can reach rtnetlink.
    pub kernel_reachable: bool,
    /// The process has the privileges needed to mutate routes/rules.
    pub net_admin_capable: bool,
    /// Mutating operations appear ready.
    pub mutation_ready: bool,
    /// Optional human-readable detail; static so the probe stays `Copy`.
    pub details: Option<&'static str>,
}

impl RouteSteeringProbe {
    /// Probe result for the in-memory mock backend.
    #[must_use]
    pub const fn mock() -> Self {
        Self {
            kind: RouteSteeringBackendKind::Mock,
            platform_supported: true,
            kernel_reachable: false,
            net_admin_capable: false,
            mutation_ready: false,
            details: Some("dry-run/mock backend"),
        }
    }

    /// Probe result for an unsupported platform.
    #[must_use]
    pub const fn unsupported() -> Self {
        Self {
            kind: RouteSteeringBackendKind::Unsupported,
            platform_supported: false,
            kernel_reachable: false,
            net_admin_capable: false,
            mutation_ready: false,
            details: Some("route steering operations are not supported on this platform"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn prefix_tracks_address_family() {
        assert!(IpPrefix::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 32).is_ipv4());
        assert!(!IpPrefix::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 128).is_ipv4());
    }

    #[test]
    fn probe_defaults_are_unsupported() {
        let probe = RouteSteeringProbe::default();
        assert_eq!(probe.kind, RouteSteeringBackendKind::Unsupported);
        assert!(!probe.mutation_ready);
    }

    #[test]
    fn request_debug_redacts_addresses_and_firewall_marks() {
        let route = RouteRequest {
            destination: IpPrefix::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)), 32),
            oif_ifindex: 42,
            table: 100,
            priority: Some(7),
        };
        let rule = RuleRequest {
            source: Some(route.destination),
            destination: None,
            fwmark: Some(FirewallMark {
                value: 0xdead_beef,
                mask: u32::MAX,
            }),
            table: 100,
            priority: 1000,
        };

        let route_debug = format!("{route:?}");
        let rule_debug = format!("{rule:?}");
        assert!(!route_debug.contains("198.51.100.9"));
        assert!(!rule_debug.contains("198.51.100.9"));
        assert!(!rule_debug.contains("deadbeef"));
        assert!(route_debug.contains("<redacted>"));
        assert!(rule_debug.contains("<redacted>"));
    }
}
