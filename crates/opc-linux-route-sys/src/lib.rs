//! Narrow Linux rtnetlink route/rule UAPI boundary for OpenPacketCore.
//!
//! This crate owns raw Linux socket syscalls and selected UAPI constants needed
//! by the safe route-steering wrapper. It deliberately does not implement route
//! policy, table allocation, namespace management, or product deployment
//! defaults.

#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

use std::io;

#[cfg(all(target_os = "linux", not(opc_linux_route_sys_force_unsupported)))]
mod linux;
#[cfg_attr(
    all(target_os = "linux", not(opc_linux_route_sys_force_unsupported)),
    allow(dead_code)
)]
mod unsupported;

#[cfg(all(target_os = "linux", not(opc_linux_route_sys_force_unsupported)))]
use linux as platform;
#[cfg(any(not(target_os = "linux"), opc_linux_route_sys_force_unsupported))]
use unsupported as platform;

/// Linux netlink protocol number for route netlink.
pub const NETLINK_ROUTE: i32 = 0;

/// Netlink close-on-exec/nonblocking route socket.
#[derive(Debug)]
pub struct NetlinkSocket {
    inner: platform::NetlinkSocket,
}

impl NetlinkSocket {
    /// Borrow the underlying Linux file descriptor.
    #[cfg(all(target_os = "linux", not(opc_linux_route_sys_force_unsupported)))]
    pub fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

/// Open a nonblocking close-on-exec `NETLINK_ROUTE` socket bound to the process.
pub fn open_route_netlink_socket() -> io::Result<NetlinkSocket> {
    platform::open_netlink_socket().map(|inner| NetlinkSocket { inner })
}

/// Send one raw rtnetlink message buffer to the kernel.
pub fn send_message(socket: &NetlinkSocket, payload: &[u8]) -> io::Result<usize> {
    platform::send_message(&socket.inner, payload)
}

/// Receive one raw rtnetlink message buffer from the kernel.
///
/// # Datagram sizing
///
/// Netlink is a datagram protocol. If `buffer` is smaller than the kernel's
/// pending datagram, the kernel would silently drop the excess bytes when
/// `recv` is called with `flags=0`. To avoid silent truncation, this wrapper
/// passes `MSG_TRUNC` and returns an [`io::Error`] of kind
/// [`io::ErrorKind::InvalidData`] if the real datagram length exceeds
/// `buffer.len()`. It also verifies the source `sockaddr_nl` identifies the
/// kernel (port and multicast group zero) before exposing any bytes.
pub fn receive_message(socket: &NetlinkSocket, buffer: &mut [u8]) -> io::Result<usize> {
    platform::receive_message(&socket.inner, buffer)
}

/// Netlink request flag.
pub const NLM_F_REQUEST: u16 = 0x0001;
/// Netlink multipart response flag.
pub const NLM_F_MULTI: u16 = 0x0002;
/// Netlink acknowledge request flag.
pub const NLM_F_ACK: u16 = 0x0004;
/// Netlink dump was interrupted and its result is inconsistent.
pub const NLM_F_DUMP_INTR: u16 = 0x0010;
/// Netlink dump was filtered as requested.
pub const NLM_F_DUMP_FILTERED: u16 = 0x0020;
/// Netlink replacement flag for create/update operations.
pub const NLM_F_REPLACE: u16 = 0x0100;
/// Netlink root-selection flag used by dump requests.
pub const NLM_F_ROOT: u16 = 0x0100;
/// Netlink match-selection flag used by dump requests.
pub const NLM_F_MATCH: u16 = 0x0200;
/// Netlink dump request (`NLM_F_ROOT | NLM_F_MATCH`).
pub const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;
/// Netlink exclusive-create flag.
pub const NLM_F_EXCL: u16 = 0x0200;
/// Netlink create flag.
pub const NLM_F_CREATE: u16 = 0x0400;

/// Netlink error or acknowledge control message.
pub const NLMSG_ERROR: u16 = 0x2;
/// Netlink multipart completion control message.
pub const NLMSG_DONE: u16 = 0x3;
/// Netlink receive overrun control message.
pub const NLMSG_OVERRUN: u16 = 0x4;
/// Netlink no-op control message.
pub const NLMSG_NOOP: u16 = 0x1;

/// Add a route.
pub const RTM_NEWROUTE: u16 = 24;
/// Delete a route.
pub const RTM_DELROUTE: u16 = 25;
/// Read routes.
pub const RTM_GETROUTE: u16 = 26;
/// Add a rule.
pub const RTM_NEWRULE: u16 = 32;
/// Delete a rule.
pub const RTM_DELRULE: u16 = 33;
/// Read rules.
pub const RTM_GETRULE: u16 = 34;

/// Linux address family unspecified.
pub const AF_UNSPEC: u8 = 0;
/// Linux IPv4 address family.
pub const AF_INET: u8 = 2;
/// Linux IPv6 address family.
pub const AF_INET6: u8 = 10;

/// Unspecified route table marker used when table is carried as an attribute.
pub const RT_TABLE_UNSPEC: u8 = 0;
/// Compatibility marker used by kernel dumps when the full table is an attribute.
pub const RT_TABLE_COMPAT: u8 = 252;
/// Main Linux route table.
pub const RT_TABLE_MAIN: u32 = 254;
/// Static route protocol.
pub const RTPROT_STATIC: u8 = 4;
/// Global route scope.
pub const RT_SCOPE_UNIVERSE: u8 = 0;
/// Unicast route type.
pub const RTN_UNICAST: u8 = 1;

/// Route attribute: destination prefix.
pub const RTA_DST: u16 = 1;
/// Route attribute: output interface index.
pub const RTA_OIF: u16 = 4;
/// Route attribute: metric/priority.
pub const RTA_PRIORITY: u16 = 6;
/// Route attribute: non-identity kernel cache metadata.
pub const RTA_CACHEINFO: u16 = 12;
/// Route attribute: route table as u32.
pub const RTA_TABLE: u16 = 15;
/// Route attribute: IPv6 router preference.
pub const RTA_PREF: u16 = 20;
/// Neutral/default IPv6 router preference (`medium`).
pub const ICMPV6_ROUTER_PREF_MEDIUM: u8 = 0;

/// Rule action: lookup table.
pub const FR_ACT_TO_TBL: u8 = 1;
/// Rule attribute: destination selector.
pub const FRA_DST: u16 = 1;
/// Rule attribute: source selector.
pub const FRA_SRC: u16 = 2;
/// Rule attribute: priority.
pub const FRA_PRIORITY: u16 = 6;
/// Rule attribute: firewall mark value.
pub const FRA_FWMARK: u16 = 10;
/// Rule attribute: suppress routes with an interface group.
pub const FRA_SUPPRESS_IFGROUP: u16 = 13;
/// Rule attribute: suppress routes with a prefix length.
pub const FRA_SUPPRESS_PREFIXLEN: u16 = 14;
/// Rule attribute: table as u32.
pub const FRA_TABLE: u16 = 15;
/// Rule attribute: firewall mark mask.
pub const FRA_FWMASK: u16 = 16;
/// Rule alignment-padding attribute.
pub const FRA_PAD: u16 = 18;
/// Rule originator protocol attribute.
pub const FRA_PROTOCOL: u16 = 21;

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

/// Netlink route attribute header.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct RouteAttributeHeader {
    /// Attribute length including this header.
    pub length: u16,
    /// Attribute type.
    pub attr_type: u16,
}

/// Linux `struct rtmsg` used by route operations.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct RouteMessage {
    /// Address family.
    pub family: u8,
    /// Destination prefix length.
    pub destination_prefix_len: u8,
    /// Source prefix length.
    pub source_prefix_len: u8,
    /// TOS selector.
    pub tos: u8,
    /// Route table.
    pub table: u8,
    /// Route protocol.
    pub protocol: u8,
    /// Route scope.
    pub scope: u8,
    /// Route type.
    pub route_type: u8,
    /// Route flags.
    pub flags: u32,
}

/// Linux `struct fib_rule_hdr` used by rule operations.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct FibRuleHeader {
    /// Address family.
    pub family: u8,
    /// Destination prefix length.
    pub destination_prefix_len: u8,
    /// Source prefix length.
    pub source_prefix_len: u8,
    /// TOS selector.
    pub tos: u8,
    /// Rule table.
    pub table: u8,
    /// Reserved byte.
    pub reserved1: u8,
    /// Reserved byte.
    pub reserved2: u8,
    /// Rule action.
    pub action: u8,
    /// Rule flags.
    pub flags: u32,
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
    fn constants_cover_route_and_rule_values() {
        assert_eq!(NETLINK_ROUTE, 0);
        assert_eq!(NLM_F_REQUEST, 0x0001);
        assert_eq!(NLM_F_ACK, 0x0004);
        assert_eq!(NLM_F_DUMP_INTR, 0x0010);
        assert_eq!(NLM_F_DUMP, 0x0300);
        assert_eq!(NLMSG_OVERRUN, 0x4);
        assert_eq!(NLM_F_CREATE, 0x0400);
        assert_eq!(RTM_NEWROUTE, 24);
        assert_eq!(RTM_DELROUTE, 25);
        assert_eq!(RTM_GETROUTE, 26);
        assert_eq!(RTM_NEWRULE, 32);
        assert_eq!(RTM_DELRULE, 33);
        assert_eq!(RTM_GETRULE, 34);
        assert_eq!(AF_INET, 2);
        assert_eq!(AF_INET6, 10);
        assert_eq!(RT_TABLE_MAIN, 254);
        assert_eq!(RTPROT_STATIC, 4);
        assert_eq!(RTN_UNICAST, 1);
        assert_eq!(RTA_DST, 1);
        assert_eq!(RTA_OIF, 4);
        assert_eq!(RTA_PRIORITY, 6);
        assert_eq!(RTA_TABLE, 15);
        assert_eq!(FR_ACT_TO_TBL, 1);
        assert_eq!(FRA_DST, 1);
        assert_eq!(FRA_SRC, 2);
        assert_eq!(FRA_PRIORITY, 6);
        assert_eq!(FRA_FWMARK, 10);
        assert_eq!(FRA_SUPPRESS_IFGROUP, 13);
        assert_eq!(FRA_SUPPRESS_PREFIXLEN, 14);
        assert_eq!(FRA_TABLE, 15);
        assert_eq!(FRA_FWMASK, 16);
        assert_eq!(FRA_PAD, 18);
        assert_eq!(FRA_PROTOCOL, 21);
    }

    #[test]
    fn uapi_layout_matches_linux_headers() {
        assert_eq!(size_of::<NetlinkMessageHeader>(), 16);
        assert_eq!(align_of::<NetlinkMessageHeader>(), 4);
        assert_eq!(size_of::<RouteAttributeHeader>(), 4);
        assert_eq!(size_of::<RouteMessage>(), 12);
        assert_eq!(offset_of!(RouteMessage, table), 4);
        assert_eq!(size_of::<FibRuleHeader>(), 12);
        assert_eq!(offset_of!(FibRuleHeader, action), 7);
        assert_eq!(size_of::<NetlinkErrorMessage>(), 20);
    }

    #[test]
    fn netlink_alignment_is_checked() {
        assert_eq!(align_to_netlink(0), Some(0));
        assert_eq!(align_to_netlink(1), Some(4));
        assert_eq!(align_to_netlink(5), Some(8));
        assert_eq!(align_to_netlink(usize::MAX), None);
    }
}
