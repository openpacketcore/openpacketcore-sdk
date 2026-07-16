//! Shared model types for SWu load balancing.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Worker shard identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct ShardId(u16);

impl ShardId {
    /// Build a shard identifier.
    #[must_use]
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Return the numeric shard identifier.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Cluster node or pod identity used by LB ports.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct ClusterNode {
    id: String,
}

impl ClusterNode {
    /// Build a node identity.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self { id: id.into() }
    }

    /// Return the stable node identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.id
    }
}

/// IP address without depending on platform socket types in public wire models.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum IpAddress {
    /// IPv4 address.
    V4([u8; 4]),
    /// IPv6 address.
    V6([u8; 16]),
}

impl IpAddress {
    /// True when the address is IPv4.
    #[must_use]
    pub const fn is_ipv4(self) -> bool {
        matches!(self, Self::V4(_))
    }

    /// Return a stable byte slice representation.
    #[must_use]
    pub fn octets(self) -> Vec<u8> {
        match self {
            Self::V4(octets) => octets.to_vec(),
            Self::V6(octets) => octets.to_vec(),
        }
    }
}

impl From<Ipv4Addr> for IpAddress {
    fn from(value: Ipv4Addr) -> Self {
        Self::V4(value.octets())
    }
}

impl From<Ipv6Addr> for IpAddress {
    fn from(value: Ipv6Addr) -> Self {
        Self::V6(value.octets())
    }
}

/// Security association identity visible to the steering layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum SaId {
    /// IKE SA keyed by responder SPI.
    Ike {
        /// IKE responder SPI selected by the ePDG/NF.
        responder_spi: u64,
    },
    /// ESP Child SA keyed by inbound ESP SPI.
    Esp {
        /// Inbound ESP SPI.
        spi: u32,
    },
}

/// Key used by the steering decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SteerKey {
    /// IKE message with a non-zero responder SPI.
    IkeResponderSpi(u64),
    /// Initial IKE_SA_INIT before the responder SPI exists.
    IkeInit {
        /// Initiator SPI from the IKE header.
        initiator_spi: u64,
        /// Source IP address observed at the edge.
        source_ip: IpAddress,
    },
    /// ESP-in-UDP packet keyed by ESP SPI.
    EspSpi(u32),
}

/// Steering action selected for a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SteerAction {
    /// Route to the selected shard.
    Shard(ShardId),
    /// Drop or consume at the edge with an explicit reason.
    EdgeDrop(&'static str),
    /// Require fragment reassembly before a safe steering decision can be made.
    NeedsReassembly,
}

/// Kind of steering backend implementation.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SteeringBackendKind {
    /// Backend is unsupported on this platform.
    #[default]
    Unsupported,
    /// In-memory mock backend.
    Mock,
    /// Host XDP backend.
    HostXdp,
    /// SR-IOV VF or AF_XDP backend.
    VfXdp,
    /// NIC/DPU offload backend.
    NicOffload,
    /// Floating-VIP delivery on a converged shared-L2 deployment.
    ///
    /// The VIP delivers packets to the selected node directly, so steering
    /// mutations satisfy the backend contract as intentional no-ops rather
    /// than programming a host, VF, or NIC datapath.
    VipDelivered,
}

/// Capability and readiness probe for a steering backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SteeringProbe {
    /// Backend kind.
    pub kind: SteeringBackendKind,
    /// Platform can support this backend.
    pub platform_supported: bool,
    /// Backend can satisfy steering mutation requests.
    ///
    /// This means concrete datapath mutation for XDP/offload backends. For
    /// [`SteeringBackendKind::VipDelivered`], mutations are intentional no-ops
    /// because the floating VIP supplies delivery.
    pub mutation_ready: bool,
    /// Backend is key-material-free by construction.
    pub key_material_free: bool,
    /// Optional static detail.
    pub details: Option<&'static str>,
}

impl SteeringProbe {
    /// Probe result for floating-VIP delivery on a converged shared L2.
    ///
    /// This production tier satisfies steering mutations as intentional
    /// no-ops. It does not claim host/VF XDP, NIC offload, or datapath rule
    /// programming; packet delivery is supplied by the floating VIP.
    #[must_use]
    pub const fn vip_delivered() -> Self {
        Self {
            kind: SteeringBackendKind::VipDelivered,
            platform_supported: true,
            mutation_ready: true,
            key_material_free: true,
            details: Some("floating VIP supplies packet delivery; steering mutations are no-ops"),
        }
    }

    /// Probe result for a mock backend.
    #[must_use]
    pub const fn mock() -> Self {
        Self {
            kind: SteeringBackendKind::Mock,
            platform_supported: true,
            mutation_ready: true,
            key_material_free: true,
            details: Some("mock steering backend"),
        }
    }

    /// Probe result for an unsupported backend.
    #[must_use]
    pub const fn unsupported() -> Self {
        Self {
            kind: SteeringBackendKind::Unsupported,
            platform_supported: false,
            mutation_ready: false,
            key_material_free: true,
            details: Some("steering backend unsupported"),
        }
    }
}

/// Steering rule installed into a backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SteeringRule {
    /// Routing tag or decoded shard.
    pub shard: ShardId,
    /// Owner that should receive matching traffic.
    pub owner: ShardId,
    /// Steering key matched by the backend.
    pub key: SteerKey,
}

/// Kind of VIP advertiser.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum VipAdvertiserKind {
    /// Unsupported.
    #[default]
    Unsupported,
    /// In-memory mock.
    Mock,
    /// BGP advertiser.
    Bgp,
    /// VRRP advertiser.
    Vrrp,
    /// VIP delivery is supplied by an external load balancer.
    ///
    /// Advertisement mutations are intentional no-ops in this tier; a
    /// coordinator can track fenced ownership without local route changes.
    ExternalLb,
}

/// VIP advertisement request.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VipAdvertisement {
    /// Virtual IP address.
    pub vip: IpAddress,
    /// Node owning or advertising the VIP.
    pub node: ClusterNode,
}

/// VIP advertiser probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VipProbe {
    /// Advertiser kind.
    pub kind: VipAdvertiserKind,
    /// Advertiser tier is available in this deployment.
    pub platform_supported: bool,
    /// Advertiser can satisfy advertisement mutation requests.
    ///
    /// For [`VipAdvertiserKind::ExternalLb`], requests are intentional no-ops
    /// because the external load balancer supplies delivery.
    pub mutation_ready: bool,
    /// Optional static detail.
    pub details: Option<&'static str>,
}

impl VipProbe {
    /// Probe result for externally supplied VIP delivery.
    ///
    /// This tier satisfies advertisement requests as intentional no-ops and
    /// never claims local route programming.
    #[must_use]
    pub const fn external_lb() -> Self {
        Self {
            kind: VipAdvertiserKind::ExternalLb,
            platform_supported: true,
            mutation_ready: true,
            details: Some("external LB supplies delivery; VIP advertisement is a no-op"),
        }
    }

    /// Probe result for a mock advertiser.
    #[must_use]
    pub const fn mock() -> Self {
        Self {
            kind: VipAdvertiserKind::Mock,
            platform_supported: true,
            mutation_ready: true,
            details: Some("mock VIP advertiser"),
        }
    }

    /// Probe result for an unsupported advertiser.
    #[must_use]
    pub const fn unsupported() -> Self {
        Self {
            kind: VipAdvertiserKind::Unsupported,
            platform_supported: false,
            mutation_ready: false,
            details: Some("VIP advertisement unsupported"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_defaults_fail_closed() {
        assert_eq!(
            SteeringProbe::default().kind,
            SteeringBackendKind::Unsupported
        );
        assert!(!SteeringProbe::default().mutation_ready);
        assert_eq!(VipProbe::default().kind, VipAdvertiserKind::Unsupported);
    }

    #[test]
    fn vip_delivered_probe_is_production_ready_without_datapath_claims() {
        let probe = SteeringProbe::vip_delivered();

        assert_eq!(probe.kind, SteeringBackendKind::VipDelivered);
        assert_ne!(probe.kind, SteeringBackendKind::Mock);
        assert!(probe.platform_supported);
        assert!(probe.mutation_ready);
        assert!(probe.key_material_free);
        assert_eq!(
            probe.details,
            Some("floating VIP supplies packet delivery; steering mutations are no-ops")
        );
    }

    #[test]
    fn external_lb_probe_is_ready_without_route_mutation_claims() {
        let probe = VipProbe::external_lb();

        assert_eq!(probe.kind, VipAdvertiserKind::ExternalLb);
        assert_ne!(probe.kind, VipAdvertiserKind::Mock);
        assert!(probe.platform_supported);
        assert!(probe.mutation_ready);
        assert_eq!(
            probe.details,
            Some("external LB supplies delivery; VIP advertisement is a no-op")
        );
    }

    #[test]
    fn ip_address_tracks_family() {
        assert!(IpAddress::from(Ipv4Addr::LOCALHOST).is_ipv4());
        assert!(!IpAddress::from(Ipv6Addr::LOCALHOST).is_ipv4());
    }
}
