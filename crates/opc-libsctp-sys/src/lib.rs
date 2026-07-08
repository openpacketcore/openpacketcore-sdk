//! Narrow Linux SCTP socket UAPI boundary for OpenPacketCore.
//!
//! This crate is intentionally small: it owns the `unsafe` syscall boundary
//! required by ADR 0017 and exposes typed helpers for the safe `opc-sctp` crate.
//! It is not a protocol codec and it does not parse NGAP/NAS payloads.

#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::io;
use std::net::SocketAddr;
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

/// Return the pending socket error after a nonblocking connect completes.
pub fn socket_error(fd: BorrowedFd<'_>) -> io::Result<Option<io::Error>> {
    platform::socket_error(fd)
}

/// Set SCTP INIT parameters.
pub fn set_initmsg(fd: BorrowedFd<'_>, init: InitMsg) -> io::Result<()> {
    platform::set_initmsg(fd, init)
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
}
