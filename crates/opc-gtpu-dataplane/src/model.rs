//! Safe model types for Linux GTP-U dataplane backend operations.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroU32;

use opc_types::DscpCodepoint;

/// Default GTP-U UDP port.
pub const GTPU_PORT: u16 = 2152;
/// Default PDP context hash size used by libgtpnl examples.
pub const DEFAULT_PDP_HASHSIZE: u32 = 131_072;

/// GTP Tunnel Endpoint Identifier.
///
/// TEIDs are treated as sensitive routing/session handles. `Debug` and
/// `Display` never emit the raw value.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct Teid(NonZeroU32);

impl Teid {
    /// Create a TEID. Returns `None` for zero, which is not valid for GTPv1 PDP
    /// contexts.
    #[must_use]
    pub const fn new(value: u32) -> Option<Self> {
        match NonZeroU32::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Return the raw TEID value for kernel encoding.
    ///
    /// Callers must not expose this value through logs or diagnostics.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

impl fmt::Debug for Teid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Teid").field(&"<redacted>").finish()
    }
}

impl fmt::Display for Teid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted-teid>")
    }
}

/// Linux GTP netdevice role.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum GtpRole {
    /// Gateway side (`GTP_ROLE_GGSN`), appropriate for GGSN/P-GW/ePDG gateway behavior.
    #[default]
    Ggsn,
    /// Serving side (`GTP_ROLE_SGSN`).
    Sgsn,
}

/// Supported GTP user-plane version.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum GtpVersion {
    /// GTP-U version 1.
    #[default]
    V1,
}

/// Address family used to remove a PDP context.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GtpAddressFamily {
    /// IPv4 MS/UE address family.
    Ipv4,
    /// IPv6 MS/UE address family.
    Ipv6,
}

impl GtpAddressFamily {
    /// Derive a GTP address family from an IP address.
    #[must_use]
    pub const fn from_ip(address: IpAddr) -> Self {
        match address {
            IpAddr::V4(_) => Self::Ipv4,
            IpAddr::V6(_) => Self::Ipv6,
        }
    }
}

/// Linux `gtp` netdevice identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GtpDevice {
    /// Interface name.
    pub name: String,
    /// Interface index.
    pub ifindex: u32,
}

/// Request to create a Linux `gtp` netdevice.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CreateGtpDeviceRequest {
    /// Interface name.
    pub name: String,
    /// Linux GTP role.
    pub role: GtpRole,
    /// UDP address bound before passing the GTP-U socket to the kernel.
    pub bind_address: IpAddr,
    /// UDP port bound before passing the GTP-U socket to the kernel.
    pub bind_port: u16,
    /// Optional PDP hash size. The default request uses
    /// [`DEFAULT_PDP_HASHSIZE`], mirroring libgtpnl examples.
    pub pdp_hashsize: Option<u32>,
}

impl CreateGtpDeviceRequest {
    /// Build a GGSN-role GTP device request bound to `0.0.0.0:2152`.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            role: GtpRole::Ggsn,
            bind_address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            bind_port: GTPU_PORT,
            pdp_hashsize: Some(DEFAULT_PDP_HASHSIZE),
        }
    }
}

impl fmt::Debug for CreateGtpDeviceRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateGtpDeviceRequest")
            .field("name", &self.name)
            .field("role", &self.role)
            .field("bind_address", &"<redacted>")
            .field("bind_port", &self.bind_port)
            .field("pdp_hashsize", &self.pdp_hashsize)
            .finish()
    }
}

/// GTP-U PDP context programmed into the Linux `gtp` kernel module.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct GtpPdpContext {
    /// Incoming/local S2b-U/N3 TEID.
    pub local_teid: Teid,
    /// Outgoing peer PGW/UPF TEID.
    pub peer_teid: Teid,
    /// MS/UE packet-data-network address.
    pub ms_address: IpAddr,
    /// Peer PGW/UPF GTP-U address.
    pub peer_address: IpAddr,
    /// GTP netdevice ifindex.
    pub link_ifindex: u32,
    /// GTP version.
    pub gtp_version: GtpVersion,
    /// Optional fixed DSCP stamped on the outer uplink IP header.
    ///
    /// The Linux eBPF backend supports this per PDP context. Backends whose
    /// [`GtpuProbe::egress_dscp_marking`] is not [`GtpuCapability::Available`]
    /// reject `Some` rather than silently ignoring it. `None` preserves the
    /// backend's pre-DSCP packet and kernel-message behavior.
    pub egress_dscp: Option<DscpCodepoint>,
}

impl fmt::Debug for GtpPdpContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GtpPdpContext")
            .field("local_teid", &self.local_teid)
            .field("peer_teid", &self.peer_teid)
            .field("ms_address", &"<redacted>")
            .field("peer_address", &"<redacted>")
            .field("link_ifindex", &self.link_ifindex)
            .field("gtp_version", &self.gtp_version)
            .field("egress_dscp", &self.egress_dscp)
            .finish()
    }
}

/// Request to remove a GTP-U PDP context.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RemovePdpContextRequest {
    /// Incoming/local S2b-U/N3 TEID.
    pub local_teid: Teid,
    /// GTP netdevice ifindex.
    pub link_ifindex: u32,
    /// GTP version.
    pub gtp_version: GtpVersion,
    /// MS/UE address family used by the kernel lookup.
    pub address_family: GtpAddressFamily,
}

impl RemovePdpContextRequest {
    /// Build a remove request from an installed PDP context.
    #[must_use]
    pub fn from_context(context: &GtpPdpContext) -> Self {
        Self {
            local_teid: context.local_teid,
            link_ifindex: context.link_ifindex,
            gtp_version: context.gtp_version,
            address_family: GtpAddressFamily::from_ip(context.ms_address),
        }
    }
}

impl fmt::Debug for RemovePdpContextRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemovePdpContextRequest")
            .field("local_teid", &self.local_teid)
            .field("link_ifindex", &self.link_ifindex)
            .field("gtp_version", &self.gtp_version)
            .field("address_family", &self.address_family)
            .finish()
    }
}

/// Kind of GTP-U backend implementation.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum GtpuBackendKind {
    /// Backend is not implemented for the current platform.
    #[default]
    Unsupported,
    /// Backend talks to the Linux kernel GTP netlink interfaces.
    LinuxKernel,
    /// Backend drives tc clsact eBPF GTP-U datapath programs.
    LinuxEbpf,
    /// In-memory mock/dry-run backend for tests and offline development.
    Mock,
}

/// Capability state reported by a GTP-U backend probe.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum GtpuCapability {
    /// Capability state has not been determined.
    #[default]
    Unknown,
    /// The capability is available for production mutations.
    Available,
    /// The backend cannot provide the capability.
    Missing,
    /// The capability exists but current process privileges are insufficient.
    PermissionDenied,
}

/// Capability and health probe for a GTP-U backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GtpuProbe {
    /// Kind of backend that produced the probe.
    pub kind: GtpuBackendKind,
    /// The platform supports Linux GTP-U operations.
    pub platform_supported: bool,
    /// The backend believes it can reach route and generic netlink.
    pub kernel_reachable: bool,
    /// The Linux `gtp` generic-netlink family is present.
    pub gtp_module_present: bool,
    /// The process has `CAP_NET_ADMIN` in its effective set.
    pub net_admin_capable: bool,
    /// The process can load eBPF programs (`CAP_BPF` or `CAP_SYS_ADMIN`).
    /// Only probed by the eBPF backend; the netlink backend leaves it false.
    pub bpf_capable: bool,
    /// Kernel BTF (`/sys/kernel/btf/vmlinux`) is available for CO-RE loads.
    /// Only probed by the eBPF backend; the netlink backend leaves it false.
    pub btf_present: bool,
    /// Mutating operations appear ready: kernel reachable, module present,
    /// NET_ADMIN available, and the UDP GTP-U socket can be bound.
    pub mutation_ready: bool,
    /// Ability to stamp a fixed per-PDP DSCP on uplink outer IP headers.
    pub egress_dscp_marking: GtpuCapability,
    /// Optional human-readable detail; static so the probe stays `Copy`.
    pub details: Option<&'static str>,
}

impl GtpuProbe {
    /// Probe result for the in-memory mock backend.
    pub const fn mock() -> Self {
        Self {
            kind: GtpuBackendKind::Mock,
            platform_supported: true,
            kernel_reachable: false,
            gtp_module_present: false,
            net_admin_capable: false,
            bpf_capable: false,
            btf_present: false,
            mutation_ready: false,
            egress_dscp_marking: GtpuCapability::Missing,
            details: Some("dry-run/mock backend"),
        }
    }

    /// Probe result for an unsupported platform.
    pub const fn unsupported() -> Self {
        Self {
            kind: GtpuBackendKind::Unsupported,
            platform_supported: false,
            kernel_reachable: false,
            gtp_module_present: false,
            net_admin_capable: false,
            bpf_capable: false,
            btf_present: false,
            mutation_ready: false,
            egress_dscp_marking: GtpuCapability::Missing,
            details: Some("GTP-U dataplane operations are not supported on this platform"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn teid_rejects_zero_and_redacts_debug_display() {
        assert_eq!(Teid::new(0), None);
        let teid = Teid::new(0x1234_5678).unwrap();
        assert_eq!(teid.get(), 0x1234_5678);
        assert!(!format!("{teid:?}").contains("12345678"));
        assert!(!teid.to_string().contains("12345678"));
    }

    #[test]
    fn default_device_request_uses_gateway_defaults() {
        let req = CreateGtpDeviceRequest::new("gtp0");
        assert_eq!(req.name, "gtp0");
        assert_eq!(req.role, GtpRole::Ggsn);
        assert_eq!(req.bind_address, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(req.bind_port, GTPU_PORT);
        assert_eq!(req.pdp_hashsize, Some(DEFAULT_PDP_HASHSIZE));
    }

    #[test]
    fn pdp_context_debug_redacts_teids_and_addresses() {
        let ctx = GtpPdpContext {
            local_teid: Teid::new(0x1234_5678).unwrap(),
            peer_teid: Teid::new(0x8765_4321).unwrap(),
            ms_address: IpAddr::V4(Ipv4Addr::new(10, 23, 0, 2)),
            peer_address: IpAddr::V6(Ipv6Addr::LOCALHOST),
            link_ifindex: 7,
            gtp_version: GtpVersion::V1,
            egress_dscp: None,
        };
        let debug = format!("{ctx:?}");
        assert!(!debug.contains("12345678"));
        assert!(!debug.contains("87654321"));
        assert!(!debug.contains("10.23.0.2"));
        assert!(!debug.contains("::1"));
    }

    #[test]
    fn remove_request_derives_family_from_context() {
        let ctx = GtpPdpContext {
            local_teid: Teid::new(1).unwrap(),
            peer_teid: Teid::new(2).unwrap(),
            ms_address: IpAddr::V6(Ipv6Addr::LOCALHOST),
            peer_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            link_ifindex: 9,
            gtp_version: GtpVersion::V1,
            egress_dscp: None,
        };
        let remove = RemovePdpContextRequest::from_context(&ctx);
        assert_eq!(remove.local_teid, ctx.local_teid);
        assert_eq!(remove.link_ifindex, 9);
        assert_eq!(remove.address_family, GtpAddressFamily::Ipv6);
    }
}
