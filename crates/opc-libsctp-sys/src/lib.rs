//! Narrow Linux SCTP socket UAPI boundary for OpenPacketCore.
//!
//! This crate is intentionally small: it owns the `unsafe` syscall boundary
//! required by ADR 0017 and exposes typed helpers for the safe `opc-sctp` crate.
//! It is not a protocol codec and it does not parse NGAP/NAS payloads.

#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::num::{NonZeroU16, NonZeroU32};
use std::os::fd::{BorrowedFd, OwnedFd};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(not(target_os = "linux"))]
mod unsupported;

#[cfg(target_os = "linux")]
use linux as platform;
#[cfg(not(target_os = "linux"))]
use unsupported as platform;

/// Linux SCTP association identifier.
pub type AssocId = i32;

/// Maximum number of socket addresses accepted by the bounded SCTP helpers.
///
/// Linux represents bindx/connectx address sets as one packed option buffer.
/// Keeping a fixed public ceiling prevents an untrusted configuration from
/// causing an unbounded allocation at the socket boundary.
pub const MAX_SCTP_ADDRESSES: usize = 64;

/// IP address family used when opening an SCTP socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    /// IPv4 socket.
    Ipv4,
    /// IPv6 socket.
    Ipv6,
}

/// SCTP socket style.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketStyle {
    /// One-to-one SCTP sockets use `SOCK_STREAM`.
    OneToOne,
    /// One-to-many SCTP sockets use `SOCK_SEQPACKET`.
    OneToMany,
}

/// Result of a nonblocking connect attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectStatus {
    /// The association connected immediately.
    Connected,
    /// The association is in progress and the fd should be polled writable.
    InProgress,
}

/// SCTP INIT parameters applied before bind/connect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitMsg {
    /// Number of outbound streams requested.
    pub outbound_streams: u16,
    /// Maximum inbound streams accepted.
    pub inbound_streams: u16,
    /// Maximum INIT retransmission attempts.
    pub max_attempts: u16,
    /// Maximum INIT timeout in milliseconds.
    pub max_init_timeout_ms: u16,
}

/// SCTP retransmission-timeout values to update.
///
/// Omitted values retain the kernel's current setting. Durations are in
/// milliseconds. On Linux, association identifier zero is ignored for a
/// one-to-one socket and selects `SCTP_FUTURE_ASSOC` for a one-to-many
/// endpoint, so the values become defaults for future associations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RtoParameters {
    /// Association to update, or zero for one-to-one/current or one-to-many/future use.
    pub assoc_id: AssocId,
    /// Initial retransmission timeout.
    pub initial_ms: Option<NonZeroU32>,
    /// Maximum retransmission timeout.
    pub max_ms: Option<NonZeroU32>,
    /// Minimum retransmission timeout.
    pub min_ms: Option<NonZeroU32>,
}

/// SCTP heartbeat and retransmission values for peer paths.
///
/// `peer_addr = None` selects the RFC 6458 wildcard and applies the values to
/// all paths. An explicit zero heartbeat interval is distinct from omission:
/// it requests the standardized zero-delay mode, while still including the
/// path RTO and jitter. On Linux, association identifier zero is ignored for
/// one-to-one sockets and selects `SCTP_FUTURE_ASSOC` for one-to-many
/// endpoints, so wildcard values become defaults for future associations.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct PeerAddressParameters {
    /// Association to update, or zero for one-to-one/current or one-to-many/future use.
    pub assoc_id: AssocId,
    /// Specific peer path, or all peer paths when omitted.
    pub peer_addr: Option<SocketAddr>,
    /// Heartbeat interval in milliseconds.
    pub heartbeat_interval_ms: Option<u32>,
    /// Retransmissions before the selected path is considered unreachable.
    pub path_max_retransmissions: Option<NonZeroU16>,
}

impl fmt::Debug for PeerAddressParameters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerAddressParameters")
            .field("assoc_id", &self.assoc_id)
            .field("peer_addr", &self.peer_addr.map(|_| "<redacted>"))
            .field("heartbeat_interval_ms", &self.heartbeat_interval_ms)
            .field("path_max_retransmissions", &self.path_max_retransmissions)
            .finish()
    }
}

/// SCTP event subscriptions exposed through the legacy `SCTP_EVENTS` option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventSubscriptions {
    /// Data I/O events.
    pub data_io: bool,
    /// Association state events.
    pub association: bool,
    /// Peer address reachability events.
    pub address: bool,
    /// Send-failure events.
    pub send_failure: bool,
    /// Peer error events.
    pub peer_error: bool,
    /// Shutdown events.
    pub shutdown: bool,
    /// Partial-delivery events.
    pub partial_delivery: bool,
    /// Adaptation-layer events.
    pub adaptation_layer: bool,
    /// Authentication events.
    pub authentication: bool,
    /// Sender-dry events.
    pub sender_dry: bool,
}

impl Default for EventSubscriptions {
    fn default() -> Self {
        Self {
            // Off by default: `SCTP_RECVRCVINFO` already delivers per-message
            // receive info, and subscribing the legacy `sctp_sndrcvinfo`
            // ancillary as well doubles the cmsgs per DATA message.
            data_io: false,
            association: true,
            address: true,
            send_failure: true,
            peer_error: true,
            shutdown: true,
            partial_delivery: true,
            adaptation_layer: false,
            authentication: false,
            sender_dry: true,
        }
    }
}

/// SCTP send metadata passed as `SCTP_SNDINFO`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendInfo {
    /// SCTP stream identifier.
    pub stream_id: u16,
    /// SCTP send flags.
    pub flags: u16,
    /// Payload protocol identifier in network byte order.
    pub ppid_network_order: u32,
    /// Caller context.
    pub context: u32,
    /// Target association for one-to-many sockets. Use zero for one-to-one.
    pub assoc_id: AssocId,
}

/// SCTP receive metadata from `SCTP_RCVINFO`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecvInfo {
    /// SCTP stream identifier.
    pub stream_id: u16,
    /// Stream sequence number.
    pub ssn: u16,
    /// SCTP receive flags.
    pub flags: u16,
    /// Payload protocol identifier in network byte order.
    pub ppid_network_order: u32,
    /// Transmission sequence number.
    pub tsn: u32,
    /// Cumulative TSN.
    pub cumulative_tsn: u32,
    /// Caller context.
    pub context: u32,
    /// Source association.
    pub assoc_id: AssocId,
}

/// Flags returned with one received message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecvFlags {
    /// Message is an SCTP notification, not user payload.
    pub notification: bool,
    /// End-of-record marker was present.
    pub end_of_record: bool,
    /// Payload was truncated because the caller buffer was too small.
    pub payload_truncated: bool,
    /// Ancillary control data was truncated.
    pub control_truncated: bool,
}

/// Received byte count and optional SCTP metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Received {
    /// Number of payload bytes written into the caller buffer.
    pub bytes: usize,
    /// Parsed SCTP receive info when present.
    pub info: Option<RecvInfo>,
    /// Message flags.
    pub flags: RecvFlags,
}

/// Open a nonblocking close-on-exec SCTP socket.
pub fn open_socket(family: AddressFamily, style: SocketStyle) -> io::Result<OwnedFd> {
    platform::open_socket(family, style)
}

/// Bind an SCTP socket to one local address.
pub fn bind(fd: BorrowedFd<'_>, addr: &SocketAddr) -> io::Result<()> {
    platform::bind(fd, addr)
}

/// Atomically bind an SCTP socket to a bounded set of local addresses.
///
/// All addresses must use one family and port. Callers that have exactly one
/// address should use [`bind`] to preserve the ordinary socket path.
pub fn bind_addresses(fd: BorrowedFd<'_>, addrs: &[SocketAddr]) -> io::Result<()> {
    platform::bind_addresses(fd, addrs)
}

/// Start listening on an SCTP socket that accepts inbound associations.
pub fn listen(fd: BorrowedFd<'_>, backlog: i32) -> io::Result<()> {
    platform::listen(fd, backlog)
}

/// Accept one one-to-one SCTP association.
pub fn accept(fd: BorrowedFd<'_>) -> io::Result<(OwnedFd, SocketAddr)> {
    platform::accept(fd)
}

/// Start a nonblocking connect to one peer address.
pub fn connect(fd: BorrowedFd<'_>, addr: &SocketAddr) -> io::Result<ConnectStatus> {
    platform::connect(fd, addr)
}

/// Start a nonblocking SCTP connect using a bounded peer address set.
///
/// All addresses must use one family and port. Callers that have exactly one
/// address should use [`connect`] to preserve the ordinary socket path.
pub fn connect_addresses(fd: BorrowedFd<'_>, addrs: &[SocketAddr]) -> io::Result<ConnectStatus> {
    platform::connect_addresses(fd, addrs)
}

/// Return the local SCTP addresses for an endpoint or association.
pub fn local_addresses(fd: BorrowedFd<'_>, assoc_id: AssocId) -> io::Result<Vec<SocketAddr>> {
    platform::local_addresses(fd, assoc_id)
}

/// Return the peer SCTP addresses for an association.
pub fn peer_addresses(fd: BorrowedFd<'_>, assoc_id: AssocId) -> io::Result<Vec<SocketAddr>> {
    platform::peer_addresses(fd, assoc_id)
}

/// Return the current primary peer address for a one-to-one association.
pub fn peer_primary_address(fd: BorrowedFd<'_>) -> io::Result<SocketAddr> {
    platform::peer_primary_address(fd)
}

/// Return whether an I/O error means the kernel cannot provide static
/// multihoming for this socket.
#[must_use]
pub fn is_multihoming_unavailable(error: &io::Error) -> bool {
    platform::is_multihoming_unavailable(error)
}

/// Return whether an I/O error means the kernel lacks an SCTP capability.
#[must_use]
pub fn is_sctp_capability_unavailable(error: &io::Error) -> bool {
    platform::is_sctp_capability_unavailable(error)
}

/// Return the pending socket error after a nonblocking connect completes.
pub fn socket_error(fd: BorrowedFd<'_>) -> io::Result<Option<io::Error>> {
    platform::socket_error(fd)
}

/// Set SCTP INIT parameters.
pub fn set_initmsg(fd: BorrowedFd<'_>, init: InitMsg) -> io::Result<()> {
    platform::set_initmsg(fd, init)
}

/// Update SCTP retransmission-timeout parameters.
pub fn set_rto_parameters(fd: BorrowedFd<'_>, parameters: RtoParameters) -> io::Result<()> {
    platform::set_rto_parameters(fd, parameters)
}

/// Update heartbeat and path retransmission parameters.
pub fn set_peer_address_parameters(
    fd: BorrowedFd<'_>,
    parameters: PeerAddressParameters,
) -> io::Result<()> {
    platform::set_peer_address_parameters(fd, parameters)
}

/// Select the peer address used as the local association's primary path.
///
/// The address must be one of the association's current peer addresses.
pub fn set_primary_peer_address(
    fd: BorrowedFd<'_>,
    assoc_id: AssocId,
    peer_addr: &SocketAddr,
) -> io::Result<()> {
    platform::set_primary_peer_address(fd, assoc_id, peer_addr)
}

/// Enable or disable SCTP_NODELAY.
pub fn set_nodelay(fd: BorrowedFd<'_>, enabled: bool) -> io::Result<()> {
    platform::set_nodelay(fd, enabled)
}

/// Enable receipt of `SCTP_RCVINFO` ancillary metadata.
pub fn set_recv_rcvinfo(fd: BorrowedFd<'_>, enabled: bool) -> io::Result<()> {
    platform::set_recv_rcvinfo(fd, enabled)
}

/// Subscribe to SCTP association/address/shutdown events.
pub fn set_events(fd: BorrowedFd<'_>, events: EventSubscriptions) -> io::Result<()> {
    platform::set_events(fd, events)
}

/// Send one SCTP message with stream/PPID metadata.
pub fn send_msg(fd: BorrowedFd<'_>, payload: &[u8], info: SendInfo) -> io::Result<usize> {
    platform::send_msg(fd, payload, info)
}

/// Receive one SCTP message and its metadata.
pub fn recv_msg(fd: BorrowedFd<'_>, buffer: &mut [u8]) -> io::Result<Received> {
    platform::recv_msg(fd, buffer)
}

/// SCTP unordered-delivery flag.
pub const SCTP_UNORDERED_FLAG: u16 = platform::SCTP_UNORDERED_FLAG;

/// SCTP notification flag as returned by `recvmsg`.
pub const SCTP_NOTIFICATION_FLAG: i32 = platform::SCTP_NOTIFICATION_FLAG;

/// SCTP association-change notification type.
pub const SCTP_ASSOC_CHANGE_NOTIFICATION: u16 = platform::SCTP_ASSOC_CHANGE_NOTIFICATION;

/// SCTP peer-address-change notification type.
pub const SCTP_PEER_ADDR_CHANGE_NOTIFICATION: u16 = platform::SCTP_PEER_ADDR_CHANGE_NOTIFICATION;

/// SCTP shutdown notification type.
pub const SCTP_SHUTDOWN_EVENT_NOTIFICATION: u16 = platform::SCTP_SHUTDOWN_EVENT_NOTIFICATION;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_event_subscription_covers_lifecycle_events() {
        let events = EventSubscriptions::default();
        assert!(
            !events.data_io,
            "SCTP_RECVRCVINFO supersedes the legacy data_io ancillary"
        );
        assert!(events.association);
        assert!(events.address);
        assert!(events.shutdown);
        assert!(events.sender_dry);
    }

    #[test]
    fn notification_types_match_linux_uapi_values() {
        assert_eq!(SCTP_ASSOC_CHANGE_NOTIFICATION, 0x8001);
        assert_eq!(SCTP_PEER_ADDR_CHANGE_NOTIFICATION, 0x8002);
        assert_eq!(SCTP_SHUTDOWN_EVENT_NOTIFICATION, 0x8005);
    }

    #[test]
    fn peer_address_parameters_debug_redacts_address() {
        let parameters = PeerAddressParameters {
            peer_addr: Some("192.0.2.44:3868".parse().unwrap()),
            ..PeerAddressParameters::default()
        };

        let debug = format!("{parameters:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("192.0.2.44"));
        assert!(!debug.contains("3868"));
    }
}
