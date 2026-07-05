//! Safe model types for route/rule steering operations.

use std::net::IpAddr;

/// IP prefix used by routes and rules.
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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct RouteRequest {
    /// Destination prefix.
    pub destination: IpPrefix,
    /// Output interface index.
    pub oif_ifindex: u32,
    /// Linux route table.
    pub table: u32,
    /// Optional route metric/priority.
    pub priority: Option<u32>,
}

/// Rule installation/removal request.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct RuleRequest {
    /// Optional source prefix selector.
    pub source: Option<IpPrefix>,
    /// Optional destination prefix selector.
    pub destination: Option<IpPrefix>,
    /// Optional firewall mark selector.
    pub fwmark: Option<FirewallMark>,
    /// Linux route table to look up.
    pub table: u32,
    /// Rule priority.
    pub priority: u32,
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
}
