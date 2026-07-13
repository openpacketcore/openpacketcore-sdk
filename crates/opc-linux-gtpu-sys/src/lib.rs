//! Narrow Linux GTP-U rtnetlink and generic-netlink UAPI boundary.
//!
//! This crate owns raw Linux socket syscalls and selected UAPI constants needed
//! by the safe GTP-U dataplane backend. It deliberately does not implement
//! GTP-U packet encoding, PDP lifecycle policy, route steering, XFRM policy, or
//! product deployment defaults.

#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

use std::io;

#[cfg(all(target_os = "linux", not(opc_linux_gtpu_sys_force_unsupported)))]
mod linux;
#[cfg_attr(
    all(target_os = "linux", not(opc_linux_gtpu_sys_force_unsupported)),
    allow(dead_code)
)]
mod unsupported;

#[cfg(all(target_os = "linux", not(opc_linux_gtpu_sys_force_unsupported)))]
use linux as platform;
#[cfg(any(not(target_os = "linux"), opc_linux_gtpu_sys_force_unsupported))]
use unsupported as platform;

/// Linux netlink protocol number for route netlink.
pub const NETLINK_ROUTE: i32 = 0;
/// Linux netlink protocol number for generic netlink.
pub const NETLINK_GENERIC: i32 = 16;

/// Netlink close-on-exec/nonblocking socket.
#[derive(Debug)]
pub struct NetlinkSocket {
    inner: platform::NetlinkSocket,
}

impl NetlinkSocket {
    /// Borrow the underlying Linux file descriptor.
    #[cfg(all(target_os = "linux", not(opc_linux_gtpu_sys_force_unsupported)))]
    pub fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

/// Bound UDP socket passed to the kernel GTP-U netdevice.
#[derive(Debug)]
pub struct GtpuUdpSocket {
    inner: platform::GtpuUdpSocket,
}

impl GtpuUdpSocket {
    /// Return the raw file descriptor number needed by `IFLA_GTP_FD1`.
    #[must_use]
    pub fn raw_fd(&self) -> i32 {
        self.inner.raw_fd()
    }
}

/// IP address accepted by the raw GTP-U UDP socket binder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GtpuIpAddress {
    /// IPv4 address as four octets.
    Ipv4([u8; 4]),
    /// IPv6 address as sixteen octets.
    Ipv6([u8; 16]),
}

/// UDP bind request for a GTP-U socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GtpuUdpBind {
    /// Local address to bind.
    pub address: GtpuIpAddress,
    /// Local UDP port in host byte order.
    pub port: u16,
}

/// Open a nonblocking close-on-exec `NETLINK_ROUTE` socket bound to the process.
pub fn open_route_netlink_socket() -> io::Result<NetlinkSocket> {
    platform::open_netlink_socket(NETLINK_ROUTE).map(|inner| NetlinkSocket { inner })
}

/// Open a nonblocking close-on-exec `NETLINK_GENERIC` socket bound to the process.
pub fn open_generic_netlink_socket() -> io::Result<NetlinkSocket> {
    platform::open_netlink_socket(NETLINK_GENERIC).map(|inner| NetlinkSocket { inner })
}

/// Open and bind a UDP socket for GTP-U user-plane traffic.
pub fn open_gtpu_udp_socket(bind: GtpuUdpBind) -> io::Result<GtpuUdpSocket> {
    platform::open_gtpu_udp_socket(bind).map(|inner| GtpuUdpSocket { inner })
}

/// Return the interface index for `name` in the current network namespace.
pub fn ifindex_by_name(name: &str) -> io::Result<u32> {
    platform::ifindex_by_name(name)
}

/// Send one raw netlink message buffer to the kernel.
pub fn send_message(socket: &NetlinkSocket, payload: &[u8]) -> io::Result<usize> {
    platform::send_message(&socket.inner, payload)
}

/// Receive one raw netlink message buffer from the kernel.
///
/// # Datagram sizing
///
/// Netlink is a datagram protocol. If `buffer` is smaller than the kernel's
/// pending datagram, the kernel would silently drop the excess bytes when
/// `recv` is called with `flags=0`. To avoid silent truncation, this wrapper
/// passes `MSG_TRUNC` and returns an [`io::Error`] of kind
/// [`io::ErrorKind::InvalidData`] if the real datagram length exceeds
/// `buffer.len()`.
pub fn receive_message(socket: &NetlinkSocket, buffer: &mut [u8]) -> io::Result<usize> {
    platform::receive_message(&socket.inner, buffer)
}

/// Netlink request flag.
pub const NLM_F_REQUEST: u16 = 0x0001;
/// Netlink multipart response flag.
pub const NLM_F_MULTI: u16 = 0x0002;
/// Netlink acknowledge request flag.
pub const NLM_F_ACK: u16 = 0x0004;
/// Netlink echo request flag.
pub const NLM_F_ECHO: u16 = 0x0008;
/// Netlink root dump flag.
pub const NLM_F_ROOT: u16 = 0x0100;
/// Netlink match dump flag.
pub const NLM_F_MATCH: u16 = 0x0200;
/// Netlink atomic dump flag.
pub const NLM_F_ATOMIC: u16 = 0x0400;
/// Netlink dump flag combination.
pub const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;
/// Netlink replacement flag for create/update operations.
pub const NLM_F_REPLACE: u16 = 0x0100;
/// Netlink exclusive-create flag.
pub const NLM_F_EXCL: u16 = 0x0200;
/// Netlink create flag.
pub const NLM_F_CREATE: u16 = 0x0400;
/// Netlink append flag.
pub const NLM_F_APPEND: u16 = 0x0800;

/// Netlink no-op control message.
pub const NLMSG_NOOP: u16 = 0x1;
/// Netlink error or acknowledge control message.
pub const NLMSG_ERROR: u16 = 0x2;
/// Netlink multipart completion control message.
pub const NLMSG_DONE: u16 = 0x3;
/// Netlink overrun control message.
pub const NLMSG_OVERRUN: u16 = 0x4;

/// Create a network link.
pub const RTM_NEWLINK: u16 = 16;
/// Delete a network link.
pub const RTM_DELLINK: u16 = 17;
/// Query a network link.
pub const RTM_GETLINK: u16 = 18;

/// Create a traffic-control filter.
pub const RTM_NEWTFILTER: u16 = 44;
/// Delete a traffic-control filter.
pub const RTM_DELTFILTER: u16 = 45;
/// Query traffic-control filters.
pub const RTM_GETTFILTER: u16 = 46;

/// Traffic-control attribute: classifier kind string.
pub const TCA_KIND: u16 = 1;
/// Traffic-control attribute: classifier-specific options nest.
pub const TCA_OPTIONS: u16 = 2;
/// cls_bpf attribute: attached BPF program name.
pub const TCA_BPF_NAME: u16 = 7;
/// cls_bpf attribute: attached BPF program identifier.
pub const TCA_BPF_ID: u16 = 11;

/// tc parent handle for the clsact ingress hook.
pub const TC_H_CLSACT_INGRESS: u32 = 0xFFFF_FFF2;
/// tc parent handle for the clsact egress hook.
pub const TC_H_CLSACT_EGRESS: u32 = 0xFFFF_FFF3;

/// Linux address family unspecified.
pub const AF_UNSPEC: u8 = 0;
/// Linux IPv4 address family.
pub const AF_INET: u8 = 2;
/// Linux IPv6 address family.
pub const AF_INET6: u8 = 10;

/// Interface is administratively up.
pub const IFF_UP: u32 = 0x1;

/// Link attribute: interface name.
pub const IFLA_IFNAME: u16 = 3;
/// Link attribute: link information nest.
pub const IFLA_LINKINFO: u16 = 18;
/// Link-info attribute: device kind string.
pub const IFLA_INFO_KIND: u16 = 1;
/// Link-info attribute: device-kind-specific data nest.
pub const IFLA_INFO_DATA: u16 = 2;

/// GTP link-info attribute: GTPv0 socket fd.
pub const IFLA_GTP_FD0: u16 = 1;
/// GTP link-info attribute: GTPv1-U socket fd.
pub const IFLA_GTP_FD1: u16 = 2;
/// GTP link-info attribute: PDP hash size.
pub const IFLA_GTP_PDP_HASHSIZE: u16 = 3;
/// GTP link-info attribute: SGSN/GGSN role.
pub const IFLA_GTP_ROLE: u16 = 4;
/// GTP link-info attribute: kernel creates sockets.
pub const IFLA_GTP_CREATE_SOCKETS: u16 = 5;
/// GTP link-info attribute: restart counter.
pub const IFLA_GTP_RESTART_COUNT: u16 = 6;
/// GTP link-info attribute: local IPv4 address.
pub const IFLA_GTP_LOCAL: u16 = 7;
/// GTP link-info attribute: local IPv6 address.
pub const IFLA_GTP_LOCAL6: u16 = 8;

/// Linux GTP role for GGSN/P-GW-side tunnel endpoint behavior.
pub const GTP_ROLE_GGSN: u32 = 0;
/// Linux GTP role for SGSN-side tunnel endpoint behavior.
pub const GTP_ROLE_SGSN: u32 = 1;

/// Generic netlink control family id.
pub const GENL_ID_CTRL: u16 = 0x10;
/// Generic netlink control command: get family by name/id.
pub const CTRL_CMD_GETFAMILY: u8 = 3;
/// Generic netlink control family version.
pub const CTRL_VERSION: u8 = 1;
/// Generic netlink control attr: family id.
pub const CTRL_ATTR_FAMILY_ID: u16 = 1;
/// Generic netlink control attr: family name.
pub const CTRL_ATTR_FAMILY_NAME: u16 = 2;

/// Linux GTP generic-netlink family name.
pub const GTP_GENL_NAME: &str = "gtp";
/// Linux GTP generic-netlink family version used by libgtpnl.
pub const GTP_GENL_VERSION: u8 = 0;
/// GTP generic-netlink command: create PDP context.
pub const GTP_CMD_NEWPDP: u8 = 0;
/// GTP generic-netlink command: delete PDP context.
pub const GTP_CMD_DELPDP: u8 = 1;
/// GTP generic-netlink command: get PDP context.
pub const GTP_CMD_GETPDP: u8 = 2;
/// GTP generic-netlink command: echo request.
pub const GTP_CMD_ECHOREQ: u8 = 3;

/// GTP version 0.
pub const GTP_V0: u32 = 0;
/// GTP version 1.
pub const GTP_V1: u32 = 1;

/// GTP PDP attribute: link ifindex.
pub const GTPA_LINK: u16 = 1;
/// GTP PDP attribute: GTP version.
pub const GTPA_VERSION: u16 = 2;
/// GTP PDP attribute: GTPv0 tunnel id.
pub const GTPA_TID: u16 = 3;
/// GTP PDP attribute: IPv4 peer address.
pub const GTPA_PEER_ADDRESS: u16 = 4;
/// GTP PDP attribute: IPv4 MS/UE address.
pub const GTPA_MS_ADDRESS: u16 = 5;
/// GTP PDP attribute: GTPv0 flow id.
pub const GTPA_FLOW: u16 = 6;
/// GTP PDP attribute: target netns fd.
pub const GTPA_NET_NS_FD: u16 = 7;
/// GTP PDP attribute: incoming/local GTPv1 TEID.
pub const GTPA_I_TEI: u16 = 8;
/// GTP PDP attribute: outgoing/peer GTPv1 TEID.
pub const GTPA_O_TEI: u16 = 9;
/// GTP PDP attribute: padding.
pub const GTPA_PAD: u16 = 10;
/// GTP PDP attribute: IPv6 peer address.
pub const GTPA_PEER_ADDR6: u16 = 11;
/// GTP PDP attribute: IPv6 MS/UE address.
pub const GTPA_MS_ADDR6: u16 = 12;
/// GTP PDP attribute: MS/UE address family.
pub const GTPA_FAMILY: u16 = 13;

/// Netlink message header layout.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct NetlinkMessageHeader {
    /// Total message length including this header.
    pub length: u32,
    /// Message type.
    pub message_type: u16,
    /// Netlink flags.
    pub flags: u16,
    /// Caller-supplied sequence number.
    pub sequence: u32,
    /// Netlink port identifier.
    pub port_id: u32,
}

/// Netlink route/generic attribute header.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct RouteAttributeHeader {
    /// Attribute length including this header.
    pub length: u16,
    /// Attribute type.
    pub attr_type: u16,
}

/// Linux `struct ifinfomsg` used by rtnetlink link operations.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct IfInfoMessage {
    /// Address family.
    pub family: u8,
    /// Padding byte.
    pub pad: u8,
    /// Device type.
    pub device_type: u16,
    /// Interface index.
    pub index: i32,
    /// Interface flags.
    pub flags: u32,
    /// Interface change mask.
    pub change: u32,
}

/// Linux `struct genlmsghdr` used by generic netlink messages.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct GenericNetlinkHeader {
    /// Generic netlink command.
    pub command: u8,
    /// Generic netlink family version.
    pub version: u8,
    /// Reserved field.
    pub reserved: u16,
}

/// Linux `struct nlmsgerr` prefix used by netlink ACK/error responses.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct NetlinkErrorMessage {
    /// Negative errno on failure, or zero for success.
    pub error: i32,
    /// Header of the request being acknowledged.
    pub message: NetlinkMessageHeader,
}

/// Align a netlink message or route attribute length to the Linux 4-byte boundary.
#[must_use]
pub const fn align_to_netlink(value: usize) -> Option<usize> {
    match value.checked_add(3) {
        Some(padded) => Some(padded & !3),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{align_of, offset_of, size_of};

    #[test]
    fn constants_cover_gtpu_rtnl_and_genl_values() {
        assert_eq!(NETLINK_ROUTE, 0);
        assert_eq!(NETLINK_GENERIC, 16);
        assert_eq!(NLM_F_REQUEST, 0x0001);
        assert_eq!(NLM_F_ACK, 0x0004);
        assert_eq!(NLM_F_DUMP, 0x0300);
        assert_eq!(NLM_F_EXCL, 0x0200);
        assert_eq!(NLM_F_CREATE, 0x0400);
        assert_eq!(NLMSG_ERROR, 0x2);
        assert_eq!(NLMSG_DONE, 0x3);
        assert_eq!(RTM_NEWLINK, 16);
        assert_eq!(RTM_DELLINK, 17);
        assert_eq!(RTM_NEWTFILTER, 44);
        assert_eq!(RTM_DELTFILTER, 45);
        assert_eq!(RTM_GETTFILTER, 46);
        assert_eq!(TCA_KIND, 1);
        assert_eq!(TCA_OPTIONS, 2);
        assert_eq!(TCA_BPF_NAME, 7);
        assert_eq!(TCA_BPF_ID, 11);
        assert_eq!(TC_H_CLSACT_INGRESS, 0xFFFF_FFF2);
        assert_eq!(TC_H_CLSACT_EGRESS, 0xFFFF_FFF3);
        assert_eq!(AF_UNSPEC, 0);
        assert_eq!(AF_INET, 2);
        assert_eq!(AF_INET6, 10);
        assert_eq!(IFLA_IFNAME, 3);
        assert_eq!(IFLA_LINKINFO, 18);
        assert_eq!(IFLA_INFO_KIND, 1);
        assert_eq!(IFLA_INFO_DATA, 2);
        assert_eq!(IFLA_GTP_FD0, 1);
        assert_eq!(IFLA_GTP_FD1, 2);
        assert_eq!(IFLA_GTP_PDP_HASHSIZE, 3);
        assert_eq!(IFLA_GTP_ROLE, 4);
        assert_eq!(IFLA_GTP_CREATE_SOCKETS, 5);
        assert_eq!(IFLA_GTP_RESTART_COUNT, 6);
        assert_eq!(IFLA_GTP_LOCAL, 7);
        assert_eq!(IFLA_GTP_LOCAL6, 8);
        assert_eq!(GTP_ROLE_GGSN, 0);
        assert_eq!(GTP_ROLE_SGSN, 1);
        assert_eq!(GENL_ID_CTRL, 0x10);
        assert_eq!(CTRL_CMD_GETFAMILY, 3);
        assert_eq!(CTRL_ATTR_FAMILY_ID, 1);
        assert_eq!(CTRL_ATTR_FAMILY_NAME, 2);
        assert_eq!(GTP_GENL_NAME, "gtp");
        assert_eq!(GTP_CMD_NEWPDP, 0);
        assert_eq!(GTP_CMD_DELPDP, 1);
        assert_eq!(GTP_CMD_GETPDP, 2);
        assert_eq!(GTP_V0, 0);
        assert_eq!(GTP_V1, 1);
        assert_eq!(GTPA_LINK, 1);
        assert_eq!(GTPA_VERSION, 2);
        assert_eq!(GTPA_PEER_ADDRESS, 4);
        assert_eq!(GTPA_MS_ADDRESS, 5);
        assert_eq!(GTPA_I_TEI, 8);
        assert_eq!(GTPA_O_TEI, 9);
        assert_eq!(GTPA_PEER_ADDR6, 11);
        assert_eq!(GTPA_MS_ADDR6, 12);
        assert_eq!(GTPA_FAMILY, 13);
    }

    #[test]
    fn netlink_alignment_is_checked() {
        assert_eq!(align_to_netlink(0), Some(0));
        assert_eq!(align_to_netlink(1), Some(4));
        assert_eq!(align_to_netlink(4), Some(4));
        assert_eq!(align_to_netlink(5), Some(8));
        assert_eq!(align_to_netlink(usize::MAX), None);
    }

    #[test]
    fn uapi_layout_matches_linux_headers() {
        assert_eq!(size_of::<NetlinkMessageHeader>(), 16);
        assert_eq!(align_of::<NetlinkMessageHeader>(), 4);
        assert_eq!(size_of::<RouteAttributeHeader>(), 4);
        assert_eq!(size_of::<IfInfoMessage>(), 16);
        assert_eq!(offset_of!(IfInfoMessage, index), 4);
        assert_eq!(offset_of!(IfInfoMessage, flags), 8);
        assert_eq!(offset_of!(IfInfoMessage, change), 12);
        assert_eq!(size_of::<GenericNetlinkHeader>(), 4);
        assert_eq!(size_of::<NetlinkErrorMessage>(), 20);
        assert_eq!(offset_of!(NetlinkErrorMessage, message), 4);
    }
}
