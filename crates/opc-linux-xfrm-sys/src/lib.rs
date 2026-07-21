//! Narrow Linux XFRM netlink UAPI boundary for OpenPacketCore.
//!
//! This crate owns the raw Linux `NETLINK_XFRM` socket boundary and selected
//! `repr(C)` UAPI structs needed by the safe IPsec/XFRM wrapper. It deliberately
//! does not implement IKE, ESP processing, SA/SPD policy, namespace management,
//! or product deployment defaults.

#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

use std::io;
use std::path::{Path, PathBuf};

#[cfg(all(target_os = "linux", not(opc_linux_xfrm_sys_force_unsupported)))]
mod linux;
#[cfg_attr(
    all(target_os = "linux", not(opc_linux_xfrm_sys_force_unsupported)),
    allow(dead_code)
)]
mod unsupported;

#[cfg(all(target_os = "linux", not(opc_linux_xfrm_sys_force_unsupported)))]
use linux as platform;
#[cfg(any(not(target_os = "linux"), opc_linux_xfrm_sys_force_unsupported))]
use unsupported as platform;

/// Linux netlink protocol number for XFRM.
pub const NETLINK_XFRM: i32 = 6;

/// Netlink close-on-exec/nonblocking raw XFRM socket.
#[derive(Debug)]
pub struct NetlinkSocket {
    inner: platform::NetlinkSocket,
}

/// An open directory anchored inside the verified Linux BPF filesystem.
///
/// The descriptor remains open for the lifetime of this value. [`Self::proc_path`]
/// may therefore be used to give path-only BPF APIs a race-free reference to
/// the exact directory that was opened and verified.
#[derive(Debug)]
pub struct BpffsDirectory {
    inner: platform::BpffsDirectory,
}

impl BpffsDirectory {
    /// Return a `/proc/self/fd` path for the held directory descriptor.
    #[must_use]
    pub fn proc_path(&self) -> PathBuf {
        self.inner.proc_path()
    }
}

impl NetlinkSocket {
    /// Borrow the underlying Linux file descriptor.
    #[cfg(all(target_os = "linux", not(opc_linux_xfrm_sys_force_unsupported)))]
    pub fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

/// Open a nonblocking close-on-exec `NETLINK_XFRM` socket bound to the process.
pub fn open_netlink_socket() -> io::Result<NetlinkSocket> {
    platform::open_netlink_socket().map(|inner| NetlinkSocket { inner })
}

/// Send one raw netlink XFRM message buffer to the kernel.
pub fn send_message(socket: &NetlinkSocket, payload: &[u8]) -> io::Result<usize> {
    platform::send_message(&socket.inner, payload)
}

/// Receive one raw netlink XFRM message buffer from the kernel.
///
/// # Datagram sizing
///
/// Netlink is a datagram protocol. If `buffer` is smaller than the kernel's
/// pending datagram, the kernel would silently drop the excess bytes when
/// `recv` is called with `flags=0`. To avoid silent truncation, this wrapper
/// passes `MSG_TRUNC` and returns an [`io::Error`] of kind
/// [`io::ErrorKind::InvalidData`] if the real datagram length exceeds
/// `buffer.len()`.
///
/// A truncation error is terminal for that datagram: `MSG_TRUNC` still consumes
/// the message. Callers should size buffers to the largest expected XFRM
/// response and treat truncation as an indeterminate operation result.
pub fn receive_message(socket: &NetlinkSocket, buffer: &mut [u8]) -> io::Result<usize> {
    platform::receive_message(&socket.inner, buffer)
}

/// Open or create a directory strictly beneath `/sys/fs/bpf`.
///
/// Every component is resolved relative to an already-open directory with
/// Linux `openat2(2)` using `RESOLVE_BENEATH`, `RESOLVE_NO_SYMLINKS`, and
/// `RESOLVE_NO_MAGICLINKS`. The final descriptor is accepted only when
/// `fstatfs(2)` reports `BPF_FS_MAGIC`.
pub fn open_or_create_bpffs_directory(relative: &Path) -> io::Result<BpffsDirectory> {
    platform::open_or_create_bpffs_directory(relative).map(|inner| BpffsDirectory { inner })
}

/// Netlink request flag.
pub const NLM_F_REQUEST: u16 = 0x0001;
/// Netlink multipart response flag.
pub const NLM_F_MULTI: u16 = 0x0002;
/// Netlink acknowledge request flag.
pub const NLM_F_ACK: u16 = 0x0004;
/// Netlink echo request flag.
pub const NLM_F_ECHO: u16 = 0x0008;
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

/// Base XFRM netlink message number.
pub const XFRM_MSG_BASE: u16 = 0x10;
/// Add a new Security Association.
pub const XFRM_MSG_NEWSA: u16 = XFRM_MSG_BASE;
/// Delete a Security Association.
pub const XFRM_MSG_DELSA: u16 = XFRM_MSG_BASE + 1;
/// Query Security Associations.
pub const XFRM_MSG_GETSA: u16 = XFRM_MSG_BASE + 2;
/// Add a new Security Policy.
pub const XFRM_MSG_NEWPOLICY: u16 = XFRM_MSG_BASE + 3;
/// Delete a Security Policy.
pub const XFRM_MSG_DELPOLICY: u16 = XFRM_MSG_BASE + 4;
/// Query Security Policies.
pub const XFRM_MSG_GETPOLICY: u16 = XFRM_MSG_BASE + 5;
/// Allocate an SPI.
pub const XFRM_MSG_ALLOCSPI: u16 = XFRM_MSG_BASE + 6;
/// Update a Security Policy.
pub const XFRM_MSG_UPDPOLICY: u16 = XFRM_MSG_BASE + 9;
/// Update a Security Association.
pub const XFRM_MSG_UPDSA: u16 = XFRM_MSG_BASE + 10;
/// Flush Security Associations.
pub const XFRM_MSG_FLUSHSA: u16 = XFRM_MSG_BASE + 12;
/// Flush Security Policies.
pub const XFRM_MSG_FLUSHPOLICY: u16 = XFRM_MSG_BASE + 13;
/// Relocate one exactly identified Security Association.
///
/// This is the single-state migration UAPI added after the older
/// policy-coupled `XFRM_MSG_MIGRATE`. It is keyed by
/// [`XfrmUserMigrateState::id`] plus [`XfrmUserMigrateState::old_mark`].
pub const XFRM_MSG_MIGRATE_STATE: u16 = XFRM_MSG_BASE + 25;

/// XFRM inbound policy direction.
pub const XFRM_POLICY_IN: u8 = 0;
/// XFRM outbound policy direction.
pub const XFRM_POLICY_OUT: u8 = 1;
/// XFRM forwarded policy direction.
pub const XFRM_POLICY_FWD: u8 = 2;
/// XFRM policy allows matching packets.
pub const XFRM_POLICY_ALLOW: u8 = 0;
/// XFRM policy blocks matching packets.
pub const XFRM_POLICY_BLOCK: u8 = 1;

/// XFRM transport mode.
pub const XFRM_MODE_TRANSPORT: u8 = 0;
/// XFRM tunnel mode.
pub const XFRM_MODE_TUNNEL: u8 = 1;
/// XFRM route optimization mode.
pub const XFRM_MODE_ROUTEOPTIMIZATION: u8 = 2;
/// XFRM in-trigger mode.
pub const XFRM_MODE_IN_TRIGGER: u8 = 3;
/// XFRM BEET mode.
pub const XFRM_MODE_BEET: u8 = 4;

/// XFRM optional authentication algorithm attribute.
pub const XFRMA_ALG_AUTH: u16 = 1;
/// XFRM optional encryption algorithm attribute.
pub const XFRMA_ALG_CRYPT: u16 = 2;
/// XFRM optional compression algorithm attribute.
pub const XFRMA_ALG_COMP: u16 = 3;
/// XFRM optional UDP encapsulation template attribute.
pub const XFRMA_ENCAP: u16 = 4;
/// XFRM optional policy template attribute.
pub const XFRMA_TMPL: u16 = 5;
/// XFRM legacy replay sequence/bitmap attribute.
pub const XFRMA_REPLAY_VAL: u16 = 10;
/// XFRM optional source address attribute.
pub const XFRMA_SRCADDR: u16 = 13;
/// Dynamic last-use timestamp attribute emitted by GETSA.
pub const XFRMA_LASTUSED: u16 = 15;
/// XFRM policy-type attribute.
pub const XFRMA_POLICY_TYPE: u16 = 16;
/// XFRM optional combined-mode AEAD algorithm attribute.
pub const XFRMA_ALG_AEAD: u16 = 18;
/// XFRM optional authentication algorithm with truncation attribute.
pub const XFRMA_ALG_AUTH_TRUNC: u16 = 20;
/// XFRM optional packet mark attribute.
pub const XFRMA_MARK: u16 = 21;
/// XFRM ESN replay sequence/bitmap attribute.
pub const XFRMA_REPLAY_ESN_VAL: u16 = 23;
/// Empty netlink alignment attribute.
pub const XFRMA_PAD: u16 = 27;
/// XFRM post-transform output skb-mark value attribute.
pub const XFRMA_SET_MARK: u16 = 29;
/// XFRM post-transform output skb-mark mask attribute.
pub const XFRMA_SET_MARK_MASK: u16 = 30;
/// XFRM optional interface identifier attribute.
pub const XFRMA_IF_ID: u16 = 31;
/// Optional Security Association direction attribute.
pub const XFRMA_SA_DIR: u16 = 34;

/// Main Security Policy Database policy type.
pub const XFRM_POLICY_TYPE_MAIN: u8 = 0;
/// Outbound Security Association direction.
pub const XFRM_SA_DIR_OUT: u8 = 2;

/// XFRM state uses Extended Sequence Numbers.
pub const XFRM_STATE_ESN: u8 = 0x80;

/// Do not inherit hardware offload when relocating an SA.
pub const XFRM_MIGRATE_STATE_CLEAR_OFFLOAD: u32 = 1;
/// Rewrite a host-to-host selector from the new SA endpoints.
pub const XFRM_MIGRATE_STATE_UPDATE_H2H_SEL: u32 = 2;
/// All currently defined `XFRM_MSG_MIGRATE_STATE` flags.
pub const XFRM_MIGRATE_STATE_KNOWN_FLAGS: u32 =
    XFRM_MIGRATE_STATE_CLEAR_OFFLOAD | XFRM_MIGRATE_STATE_UPDATE_H2H_SEL;
/// Architecture-correct Linux `EINVAL` errno.
pub const LINUX_EINVAL: i32 = libc::EINVAL;
/// Architecture-correct Linux `ENOPROTOOPT` errno.
pub const LINUX_ENOPROTOOPT: i32 = libc::ENOPROTOOPT;

/// Netlink message header layout used by XFRM requests and responses.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct NetlinkMessageHeader {
    /// Total message length including this header.
    pub length: u32,
    /// Message type, for example [`XFRM_MSG_NEWSA`].
    pub message_type: u16,
    /// Netlink flags such as [`NLM_F_REQUEST`] and [`NLM_F_ACK`].
    pub flags: u16,
    /// Caller-supplied sequence number.
    pub sequence: u32,
    /// Netlink port identifier.
    pub port_id: u32,
}

/// Netlink route-attribute header used for XFRM attributes.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RouteAttributeHeader {
    /// Attribute length including this header.
    pub length: u16,
    /// Attribute type, for example [`XFRMA_ALG_CRYPT`].
    pub attr_type: u16,
}

/// Linux `xfrm_address_t` represented as four native-endian words.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct XfrmAddress {
    /// Raw address words exactly as carried by the Linux UAPI union.
    pub words: [u32; 4],
}

impl XfrmAddress {
    /// Build an address from raw UAPI words.
    pub const fn from_words(words: [u32; 4]) -> Self {
        Self { words }
    }

    /// Build an IPv4 address whose in-memory bytes match the supplied octets.
    pub const fn from_ipv4_octets(octets: [u8; 4]) -> Self {
        Self {
            words: [u32::from_ne_bytes(octets), 0, 0, 0],
        }
    }

    /// Build an IPv6 address whose in-memory bytes match the supplied octets.
    pub const fn from_ipv6_octets(octets: [u8; 16]) -> Self {
        Self {
            words: [
                u32::from_ne_bytes([octets[0], octets[1], octets[2], octets[3]]),
                u32::from_ne_bytes([octets[4], octets[5], octets[6], octets[7]]),
                u32::from_ne_bytes([octets[8], octets[9], octets[10], octets[11]]),
                u32::from_ne_bytes([octets[12], octets[13], octets[14], octets[15]]),
            ],
        }
    }
}

/// Linux `struct xfrm_id`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct XfrmId {
    /// Destination address.
    pub destination: XfrmAddress,
    /// Security Parameter Index in network byte order.
    pub spi_network_order: u32,
    /// Transform protocol, for example `IPPROTO_ESP`.
    pub proto: u8,
}

/// Linux `struct xfrm_selector`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct XfrmSelector {
    /// Destination address selector.
    pub destination: XfrmAddress,
    /// Source address selector.
    pub source: XfrmAddress,
    /// Destination port in network byte order.
    pub destination_port: u16,
    /// Destination port mask in network byte order.
    pub destination_port_mask: u16,
    /// Source port in network byte order.
    pub source_port: u16,
    /// Source port mask in network byte order.
    pub source_port_mask: u16,
    /// Address family such as `AF_INET` or `AF_INET6`.
    pub family: u16,
    /// Destination prefix length.
    pub destination_prefix_len: u8,
    /// Source prefix length.
    pub source_prefix_len: u8,
    /// Upper-layer protocol selector.
    pub proto: u8,
    /// Interface index selector.
    pub ifindex: i32,
    /// Kernel uid selector.
    pub user: u32,
}

/// Linux `struct xfrm_lifetime_cfg`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct XfrmLifetimeConfig {
    /// Soft byte limit.
    pub soft_byte_limit: u64,
    /// Hard byte limit.
    pub hard_byte_limit: u64,
    /// Soft packet limit.
    pub soft_packet_limit: u64,
    /// Hard packet limit.
    pub hard_packet_limit: u64,
    /// Soft add-time expiry in seconds.
    pub soft_add_expires_seconds: u64,
    /// Hard add-time expiry in seconds.
    pub hard_add_expires_seconds: u64,
    /// Soft use-time expiry in seconds.
    pub soft_use_expires_seconds: u64,
    /// Hard use-time expiry in seconds.
    pub hard_use_expires_seconds: u64,
}

/// Linux `struct xfrm_lifetime_cur`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct XfrmLifetimeCurrent {
    /// Current byte count.
    pub bytes: u64,
    /// Current packet count.
    pub packets: u64,
    /// Creation time.
    pub add_time: u64,
    /// First-use time.
    pub use_time: u64,
}

/// Linux `struct xfrm_stats`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct XfrmStats {
    /// Replay window.
    pub replay_window: u32,
    /// Replay failures.
    pub replay: u32,
    /// Integrity failures.
    pub integrity_failed: u32,
}

/// Linux `struct xfrm_usersa_info`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct XfrmUserSaInfo {
    /// Packet selector.
    pub selector: XfrmSelector,
    /// Destination/protocol/SPI identity.
    pub id: XfrmId,
    /// Source tunnel endpoint.
    pub source_address: XfrmAddress,
    /// Configured lifetime limits.
    pub lifetime_config: XfrmLifetimeConfig,
    /// Current lifetime counters.
    pub lifetime_current: XfrmLifetimeCurrent,
    /// Kernel XFRM statistics.
    pub stats: XfrmStats,
    /// Replay sequence number.
    pub sequence: u32,
    /// Request identifier.
    pub request_id: u32,
    /// Address family.
    pub family: u16,
    /// XFRM mode.
    pub mode: u8,
    /// Replay window size.
    pub replay_window: u8,
    /// XFRM state flags from the kernel UAPI, such as NOECN or DECAP_DSCP.
    pub flags: u8,
}

/// Linux `struct xfrm_usersa_id` used by SA delete/query requests.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct XfrmUserSaId {
    /// Destination address.
    pub destination: XfrmAddress,
    /// Security Parameter Index in network byte order.
    pub spi_network_order: u32,
    /// Address family.
    pub family: u16,
    /// Transform protocol, for example `IPPROTO_ESP`.
    pub proto: u8,
}

/// Linux `struct xfrm_userpolicy_info`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct XfrmUserPolicyInfo {
    /// Packet selector.
    pub selector: XfrmSelector,
    /// Configured lifetime limits.
    pub lifetime_config: XfrmLifetimeConfig,
    /// Current lifetime counters.
    pub lifetime_current: XfrmLifetimeCurrent,
    /// Policy priority.
    pub priority: u32,
    /// Kernel policy index.
    pub index: u32,
    /// Direction such as [`XFRM_POLICY_OUT`].
    pub direction: u8,
    /// Action such as [`XFRM_POLICY_ALLOW`].
    pub action: u8,
    /// XFRM policy flags from the kernel UAPI.
    pub flags: u8,
    /// Sharing mode.
    pub share: u8,
}

/// Linux `struct xfrm_userpolicy_id` used by policy delete/query requests.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct XfrmUserPolicyId {
    /// Packet selector.
    pub selector: XfrmSelector,
    /// Kernel policy index, or zero when matching by selector and direction.
    pub index: u32,
    /// Direction such as [`XFRM_POLICY_OUT`].
    pub direction: u8,
}

/// Linux `struct xfrm_user_migrate_state` used to relocate one exact SA.
///
/// The request preserves an SA's cryptographic and replay state while changing
/// its outer endpoints. Optional netlink attributes carry changes such as a
/// replacement UDP encapsulation template.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct XfrmUserMigrateState {
    /// Current destination/family/protocol/SPI identity.
    pub id: XfrmUserSaId,
    /// New outer destination address.
    pub new_destination: XfrmAddress,
    /// New outer source address.
    pub new_source: XfrmAddress,
    /// Current SA lookup mark.
    pub old_mark: XfrmMark,
    /// Selector to install on the relocated SA.
    pub new_selector: XfrmSelector,
    /// Request identifier to install on the relocated SA.
    pub new_request_id: u32,
    /// Flags from `XFRM_MIGRATE_STATE_*`.
    pub flags: u32,
    /// Address family for the new outer endpoints.
    pub new_family: u16,
    /// Reserved field; callers must encode zero.
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

/// Linux `struct xfrm_user_tmpl`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct XfrmUserTemplate {
    /// Destination/protocol/SPI identity.
    pub id: XfrmId,
    /// Address family.
    pub family: u16,
    /// Source tunnel endpoint.
    pub source_address: XfrmAddress,
    /// Request identifier.
    pub request_id: u32,
    /// XFRM mode.
    pub mode: u8,
    /// Sharing mode.
    pub share: u8,
    /// Whether this template is optional.
    pub optional: u8,
    /// Allowed authentication algorithms bitmap.
    pub auth_algorithms: u32,
    /// Allowed encryption algorithms bitmap.
    pub encryption_algorithms: u32,
    /// Allowed compression algorithms bitmap.
    pub compression_algorithms: u32,
}

/// Linux `struct xfrm_userspi_info`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct XfrmUserSpiInfo {
    /// SA info prefix.
    pub info: XfrmUserSaInfo,
    /// Minimum SPI allocation bound in host/native byte order.
    pub min_spi: u32,
    /// Maximum SPI allocation bound in host/native byte order.
    pub max_spi: u32,
}

/// Fixed prefix of Linux `struct xfrm_algo` before key bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct XfrmAlgoHeader {
    /// NUL-terminated algorithm name buffer.
    pub name: [u8; XFRM_ALG_NAME_LEN],
    /// Algorithm key length in bits.
    pub key_len_bits: u32,
}

impl Default for XfrmAlgoHeader {
    fn default() -> Self {
        Self {
            name: [0; XFRM_ALG_NAME_LEN],
            key_len_bits: 0,
        }
    }
}

/// Fixed prefix of Linux `struct xfrm_algo_auth` before key bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct XfrmAlgoAuthHeader {
    /// NUL-terminated algorithm name buffer.
    pub name: [u8; XFRM_ALG_NAME_LEN],
    /// Algorithm key length in bits.
    pub key_len_bits: u32,
    /// Authentication truncation length in bits.
    pub truncation_len_bits: u32,
}

impl Default for XfrmAlgoAuthHeader {
    fn default() -> Self {
        Self {
            name: [0; XFRM_ALG_NAME_LEN],
            key_len_bits: 0,
            truncation_len_bits: 0,
        }
    }
}

/// Linux `struct xfrm_mark`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct XfrmMark {
    /// Mark value.
    pub value: u32,
    /// Mark mask.
    pub mask: u32,
}

/// Linux `struct xfrm_encap_tmpl`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct XfrmEncapTemplate {
    /// Encapsulation type.
    pub encap_type: u16,
    /// UDP source port in network byte order.
    pub source_port: u16,
    /// UDP destination port in network byte order.
    pub destination_port: u16,
    /// Original address.
    pub original_address: XfrmAddress,
}

/// Maximum Linux XFRM algorithm name length.
pub const XFRM_ALG_NAME_LEN: usize = 64;

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
    fn constants_cover_xfrm_sa_policy_and_mode_values() {
        assert_eq!(NETLINK_XFRM, 6);
        assert_eq!(NLM_F_REQUEST, 0x0001);
        assert_eq!(NLM_F_MULTI, 0x0002);
        assert_eq!(NLM_F_ACK, 0x0004);
        assert_eq!(NLM_F_ECHO, 0x0008);
        assert_eq!(NLM_F_REPLACE, 0x0100);
        assert_eq!(NLM_F_EXCL, 0x0200);
        assert_eq!(NLM_F_CREATE, 0x0400);
        assert_eq!(NLM_F_APPEND, 0x0800);
        assert_eq!(NLMSG_NOOP, 0x1);
        assert_eq!(NLMSG_ERROR, 0x2);
        assert_eq!(NLMSG_DONE, 0x3);
        assert_eq!(NLMSG_OVERRUN, 0x4);
        assert_eq!(XFRM_MSG_BASE, 0x10);
        assert_eq!(XFRM_MSG_NEWSA, 0x10);
        assert_eq!(XFRM_MSG_DELSA, 0x11);
        assert_eq!(XFRM_MSG_GETSA, 0x12);
        assert_eq!(XFRM_MSG_NEWPOLICY, 0x13);
        assert_eq!(XFRM_MSG_DELPOLICY, 0x14);
        assert_eq!(XFRM_MSG_GETPOLICY, 0x15);
        assert_eq!(XFRM_MSG_ALLOCSPI, 0x16);
        assert_eq!(XFRM_MSG_UPDPOLICY, 0x19);
        assert_eq!(XFRM_MSG_UPDSA, 0x1A);
        assert_eq!(XFRM_MSG_FLUSHSA, 0x1C);
        assert_eq!(XFRM_MSG_FLUSHPOLICY, 0x1D);
        assert_eq!(XFRM_MSG_MIGRATE_STATE, 0x29);
        assert_eq!(XFRM_POLICY_IN, 0);
        assert_eq!(XFRM_POLICY_OUT, 1);
        assert_eq!(XFRM_POLICY_FWD, 2);
        assert_eq!(XFRM_POLICY_ALLOW, 0);
        assert_eq!(XFRM_POLICY_BLOCK, 1);
        assert_eq!(XFRM_MODE_TRANSPORT, 0);
        assert_eq!(XFRM_MODE_TUNNEL, 1);
        assert_eq!(XFRM_MODE_ROUTEOPTIMIZATION, 2);
        assert_eq!(XFRM_MODE_IN_TRIGGER, 3);
        assert_eq!(XFRM_MODE_BEET, 4);
        assert_eq!(XFRMA_ALG_AUTH, 1);
        assert_eq!(XFRMA_ALG_CRYPT, 2);
        assert_eq!(XFRMA_ALG_COMP, 3);
        assert_eq!(XFRMA_ENCAP, 4);
        assert_eq!(XFRMA_TMPL, 5);
        assert_eq!(XFRMA_REPLAY_VAL, 10);
        assert_eq!(XFRMA_SRCADDR, 13);
        assert_eq!(XFRMA_LASTUSED, 15);
        assert_eq!(XFRMA_POLICY_TYPE, 16);
        assert_eq!(XFRMA_ALG_AEAD, 18);
        assert_eq!(XFRMA_ALG_AUTH_TRUNC, 20);
        assert_eq!(XFRMA_MARK, 21);
        assert_eq!(XFRMA_REPLAY_ESN_VAL, 23);
        assert_eq!(XFRMA_PAD, 27);
        assert_eq!(XFRMA_IF_ID, 31);
        assert_eq!(XFRMA_SA_DIR, 34);
        assert_eq!(XFRMA_SET_MARK, 29);
        assert_eq!(XFRMA_SET_MARK_MASK, 30);
        assert_eq!(XFRM_STATE_ESN, 0x80);
        assert_eq!(XFRM_POLICY_TYPE_MAIN, 0);
        assert_eq!(XFRM_SA_DIR_OUT, 2);
        assert_eq!(XFRM_MIGRATE_STATE_CLEAR_OFFLOAD, 1);
        assert_eq!(XFRM_MIGRATE_STATE_UPDATE_H2H_SEL, 2);
        assert_eq!(XFRM_MIGRATE_STATE_KNOWN_FLAGS, 3);
        assert_eq!(LINUX_EINVAL, libc::EINVAL);
        assert_eq!(LINUX_ENOPROTOOPT, libc::ENOPROTOOPT);
    }

    #[test]
    fn address_constructors_preserve_wire_octets_in_memory() {
        let ipv4 = XfrmAddress::from_ipv4_octets([192, 0, 2, 1]);
        assert_eq!(ipv4.words[0].to_ne_bytes(), [192, 0, 2, 1]);
        assert_eq!(ipv4.words[1..], [0, 0, 0]);

        let octets = [0x20, 0x01, 0x0d, 0xb8, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        let ipv6 = XfrmAddress::from_ipv6_octets(octets);
        let mut observed = [0_u8; 16];
        observed[0..4].copy_from_slice(&ipv6.words[0].to_ne_bytes());
        observed[4..8].copy_from_slice(&ipv6.words[1].to_ne_bytes());
        observed[8..12].copy_from_slice(&ipv6.words[2].to_ne_bytes());
        observed[12..16].copy_from_slice(&ipv6.words[3].to_ne_bytes());
        assert_eq!(observed, octets);
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
    fn uapi_layout_matches_linux_xfrm_headers() {
        assert_eq!(size_of::<NetlinkMessageHeader>(), 16);
        assert_eq!(align_of::<NetlinkMessageHeader>(), 4);
        assert_eq!(size_of::<RouteAttributeHeader>(), 4);
        assert_eq!(size_of::<XfrmAddress>(), 16);
        assert_eq!(align_of::<XfrmAddress>(), 4);
        assert_eq!(size_of::<XfrmId>(), 24);
        assert_eq!(offset_of!(XfrmId, spi_network_order), 16);
        assert_eq!(offset_of!(XfrmId, proto), 20);
        assert_eq!(size_of::<XfrmSelector>(), 56);
        assert_eq!(offset_of!(XfrmSelector, family), 40);
        assert_eq!(offset_of!(XfrmSelector, ifindex), 48);
        assert_eq!(size_of::<XfrmLifetimeConfig>(), 64);
        assert_eq!(align_of::<XfrmLifetimeConfig>(), 8);
        assert_eq!(size_of::<XfrmLifetimeCurrent>(), 32);
        assert_eq!(size_of::<XfrmStats>(), 12);
        assert_eq!(size_of::<XfrmUserSaInfo>(), 224);
        assert_eq!(offset_of!(XfrmUserSaInfo, id), 56);
        assert_eq!(offset_of!(XfrmUserSaInfo, lifetime_config), 96);
        assert_eq!(offset_of!(XfrmUserSaInfo, request_id), 208);
        assert_eq!(offset_of!(XfrmUserSaInfo, family), 212);
        assert_eq!(size_of::<XfrmUserSaId>(), 24);
        assert_eq!(offset_of!(XfrmUserSaId, family), 20);
        assert_eq!(offset_of!(XfrmUserSaId, proto), 22);
        assert_eq!(size_of::<XfrmUserPolicyInfo>(), 168);
        assert_eq!(offset_of!(XfrmUserPolicyInfo, priority), 152);
        assert_eq!(offset_of!(XfrmUserPolicyInfo, direction), 160);
        assert_eq!(size_of::<XfrmUserPolicyId>(), 64);
        assert_eq!(offset_of!(XfrmUserPolicyId, index), 56);
        assert_eq!(offset_of!(XfrmUserPolicyId, direction), 60);
        assert_eq!(size_of::<XfrmUserMigrateState>(), 132);
        assert_eq!(align_of::<XfrmUserMigrateState>(), 4);
        assert_eq!(offset_of!(XfrmUserMigrateState, new_destination), 24);
        assert_eq!(offset_of!(XfrmUserMigrateState, new_source), 40);
        assert_eq!(offset_of!(XfrmUserMigrateState, old_mark), 56);
        assert_eq!(offset_of!(XfrmUserMigrateState, new_selector), 64);
        assert_eq!(offset_of!(XfrmUserMigrateState, new_request_id), 120);
        assert_eq!(offset_of!(XfrmUserMigrateState, flags), 124);
        assert_eq!(offset_of!(XfrmUserMigrateState, new_family), 128);
        assert_eq!(offset_of!(XfrmUserMigrateState, reserved), 130);
        assert_eq!(size_of::<NetlinkErrorMessage>(), 20);
        assert_eq!(offset_of!(NetlinkErrorMessage, message), 4);
        assert_eq!(size_of::<XfrmUserTemplate>(), 64);
        assert_eq!(offset_of!(XfrmUserTemplate, source_address), 28);
        assert_eq!(offset_of!(XfrmUserTemplate, request_id), 44);
        assert_eq!(offset_of!(XfrmUserTemplate, auth_algorithms), 52);
        assert_eq!(size_of::<XfrmUserSpiInfo>(), 232);
        assert_eq!(offset_of!(XfrmUserSpiInfo, min_spi), 224);
        assert_eq!(size_of::<XfrmAlgoHeader>(), 68);
        assert_eq!(size_of::<XfrmAlgoAuthHeader>(), 72);
        assert_eq!(size_of::<XfrmMark>(), 8);
        assert_eq!(size_of::<XfrmEncapTemplate>(), 24);
        assert_eq!(offset_of!(XfrmEncapTemplate, original_address), 8);
    }
}
