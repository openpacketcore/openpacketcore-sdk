//! Bounded datagram adapters and the authenticated redirect effect boundary.

#[cfg(test)]
use std::collections::VecDeque;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use opc_ipsec_lb_ebpf_common::{IngressRedirectFrameHeader, IngressRedirectFrameKind};
use opc_session_store::{Clock, FencedOwnershipCache, FencedOwnershipGeneration};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, watch, Notify};
use tokio::task::JoinHandle;

use super::{
    increment, AuthenticatedIngressRedirectData, AuthenticatedIngressRedirectFrame,
    DeliveredIngressRedirectPacket, IngressRedirectError, IngressRedirectMtuBudget,
    IngressRedirectPeerSession, IngressRedirectProtectionEpoch, IngressRedirectReceiptCode,
    SealedIngressRedirectFrame, UDP_HEADER_BYTES,
};
use crate::{RoutingDomainTag, SessionOwnershipKey};

const MAX_DATAGRAM_BYTES: usize = 65_507;
const MAX_ADAPTER_QUEUE_PACKETS: usize = 65_536;

/// Stable, redaction-safe datagram-adapter failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum IngressRedirectDatagramError {
    /// Endpoint, MTU, or queue construction input was invalid.
    #[error("invalid ingress redirect datagram configuration")]
    InvalidConfiguration,
    /// The adapter rejected a datagram beyond its exact receive/send ceiling.
    #[error("ingress redirect datagram exceeds adapter ceiling")]
    DatagramTooLarge,
    /// Linux reported `EMSGSIZE` after the connected path MTU decreased.
    #[error("ingress redirect datagram exceeds refreshed path MTU")]
    PathMtuExceeded {
        /// Refreshed maximum UDP payload bytes.
        maximum_datagram_size: usize,
        /// Refreshed complete outer path MTU.
        effective_path_mtu: u16,
    },
    /// The deterministic adapter queue was full.
    #[error("ingress redirect datagram queue is full")]
    QueueFull,
    /// The adapter was closed.
    #[error("ingress redirect datagram adapter is closed")]
    Closed,
    /// Socket I/O failed without exposing endpoint or payload details.
    #[error("ingress redirect datagram I/O failed")]
    Io,
    /// A datagram operation exceeded the bounded peer profile deadline.
    #[error("ingress redirect datagram operation timed out")]
    TimedOut,
}

impl IngressRedirectDatagramError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidConfiguration => "redirect_datagram_invalid_configuration",
            Self::DatagramTooLarge => "redirect_datagram_too_large",
            Self::PathMtuExceeded { .. } => "redirect_datagram_path_mtu_exceeded",
            Self::QueueFull => "redirect_datagram_queue_full",
            Self::Closed => "redirect_datagram_closed",
            Self::Io => "redirect_datagram_io_failed",
            Self::TimedOut => "redirect_datagram_timed_out",
        }
    }
}

/// Connected, message-preserving datagram boundary for one authenticated peer.
///
/// Implementations must return exactly one complete datagram per `receive`
/// call. The endpoint verifies the adapter's local and peer addresses against
/// the authenticated control manifest before starting. The outbound ceiling
/// must conservatively reflect the largest datagram the adapter can send
/// without IP fragmentation and must never increase during one adapter's
/// lifetime.
#[async_trait]
pub trait IngressRedirectDatagram: Send + Sync + fmt::Debug {
    /// Send one exact datagram to the already-bound peer.
    async fn send(&self, datagram: &[u8]) -> Result<(), IngressRedirectDatagramError>;

    /// Receive one exact datagram from the already-bound peer.
    async fn receive(&self) -> Result<Vec<u8>, IngressRedirectDatagramError>;

    /// Local endpoint bound by this adapter.
    fn local_endpoint(&self) -> SocketAddr;

    /// Sole peer accepted by this adapter.
    fn peer_endpoint(&self) -> SocketAddr;

    /// Largest complete inbound datagram this adapter accepts.
    fn maximum_receive_datagram_size(&self) -> usize;

    /// Current largest outbound datagram the adapter can send without fragmentation.
    ///
    /// Implementations that cannot prove an independent send ceiling may use
    /// the authenticated receive ceiling. Runtime-discovered reductions must
    /// be retained monotonically.
    fn maximum_send_datagram_size(&self) -> usize {
        self.maximum_receive_datagram_size()
    }
}

/// Deterministic bounded in-memory datagram adapter for conformance tests.
pub struct InMemoryIngressRedirectDatagram {
    local_endpoint: SocketAddr,
    peer_endpoint: SocketAddr,
    maximum_receive_datagram_size: usize,
    maximum_send_datagram_size: usize,
    outbound: mpsc::Sender<Vec<u8>>,
    inbound: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
}

impl InMemoryIngressRedirectDatagram {
    /// Create a connected pair with exact per-family MTU ceilings.
    ///
    /// Unlike a kernel UDP socket, this test adapter may pair different
    /// address families so conformance tests can prove both family ceilings.
    pub fn pair(
        first_endpoint: SocketAddr,
        second_endpoint: SocketAddr,
        steering_path_mtu: u16,
        queue_packets: usize,
    ) -> Result<(Self, Self), IngressRedirectDatagramError> {
        if first_endpoint == second_endpoint
            || first_endpoint.port() == 0
            || second_endpoint.port() == 0
            || queue_packets == 0
            || queue_packets > MAX_ADAPTER_QUEUE_PACKETS
        {
            return Err(IngressRedirectDatagramError::InvalidConfiguration);
        }
        let first_receive = maximum_udp_payload(steering_path_mtu, first_endpoint.ip())?;
        let second_receive = maximum_udp_payload(steering_path_mtu, second_endpoint.ip())?;
        let (first_to_second_tx, first_to_second_rx) = mpsc::channel(queue_packets);
        let (second_to_first_tx, second_to_first_rx) = mpsc::channel(queue_packets);
        Ok((
            Self {
                local_endpoint: first_endpoint,
                peer_endpoint: second_endpoint,
                maximum_receive_datagram_size: first_receive,
                maximum_send_datagram_size: second_receive,
                outbound: first_to_second_tx,
                inbound: tokio::sync::Mutex::new(second_to_first_rx),
            },
            Self {
                local_endpoint: second_endpoint,
                peer_endpoint: first_endpoint,
                maximum_receive_datagram_size: second_receive,
                maximum_send_datagram_size: first_receive,
                outbound: second_to_first_tx,
                inbound: tokio::sync::Mutex::new(first_to_second_rx),
            },
        ))
    }
}

impl fmt::Debug for InMemoryIngressRedirectDatagram {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InMemoryIngressRedirectDatagram")
            .field("endpoints", &"[redacted]")
            .field(
                "maximum_receive_datagram_size",
                &self.maximum_receive_datagram_size,
            )
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl IngressRedirectDatagram for InMemoryIngressRedirectDatagram {
    async fn send(&self, datagram: &[u8]) -> Result<(), IngressRedirectDatagramError> {
        if datagram.is_empty() || datagram.len() > self.maximum_send_datagram_size {
            return Err(IngressRedirectDatagramError::DatagramTooLarge);
        }
        let permit = self.outbound.try_reserve().map_err(|error| match error {
            mpsc::error::TrySendError::Full(()) => IngressRedirectDatagramError::QueueFull,
            mpsc::error::TrySendError::Closed(()) => IngressRedirectDatagramError::Closed,
        })?;
        permit.send(datagram.to_vec());
        Ok(())
    }

    async fn receive(&self) -> Result<Vec<u8>, IngressRedirectDatagramError> {
        let datagram = self
            .inbound
            .lock()
            .await
            .recv()
            .await
            .ok_or(IngressRedirectDatagramError::Closed)?;
        if datagram.is_empty() || datagram.len() > self.maximum_receive_datagram_size {
            return Err(IngressRedirectDatagramError::DatagramTooLarge);
        }
        Ok(datagram)
    }

    fn local_endpoint(&self) -> SocketAddr {
        self.local_endpoint
    }

    fn peer_endpoint(&self) -> SocketAddr {
        self.peer_endpoint
    }

    fn maximum_receive_datagram_size(&self) -> usize {
        self.maximum_receive_datagram_size
    }

    fn maximum_send_datagram_size(&self) -> usize {
        self.maximum_send_datagram_size
    }
}

/// Connected UDP adapter that accepts datagrams only from one kernel-bound peer.
pub struct UdpIngressRedirectDatagram {
    socket: UdpSocket,
    local_endpoint: SocketAddr,
    peer_endpoint: SocketAddr,
    maximum_receive_datagram_size: usize,
    maximum_send_datagram_size: AtomicUsize,
    configured_steering_path_mtu: u16,
}

impl UdpIngressRedirectDatagram {
    /// Bind and connect a UDP socket with exact outer-MTU accounting.
    ///
    /// A connected socket is deliberate: source addresses returned by a
    /// datagram are never used as identity. Peer authority comes only from the
    /// authenticated manifest checked by [`IngressRedirectEndpoint::start`].
    /// On Linux this also sets and verifies IPv4/IPv6 `DO` path-MTU discovery,
    /// queries the connected route's PMTU, and retains only downward send-ceiling
    /// changes. Construction fails closed on platforms without that proof.
    pub async fn bind(
        local_endpoint: SocketAddr,
        peer_endpoint: SocketAddr,
        steering_path_mtu: u16,
    ) -> Result<Self, IngressRedirectDatagramError> {
        if validate_socket_endpoint(local_endpoint).is_err()
            || validate_socket_endpoint(peer_endpoint).is_err()
            || local_endpoint.is_ipv4() != peer_endpoint.is_ipv4()
        {
            return Err(IngressRedirectDatagramError::InvalidConfiguration);
        }
        let maximum_receive_datagram_size =
            maximum_udp_payload(steering_path_mtu, local_endpoint.ip())?;
        let socket = UdpSocket::bind(local_endpoint)
            .await
            .map_err(|_| IngressRedirectDatagramError::Io)?;
        socket
            .connect(peer_endpoint)
            .await
            .map_err(|_| IngressRedirectDatagramError::Io)?;
        let maximum_send_datagram_size =
            configure_connected_udp_pmtu(&socket, peer_endpoint.ip(), steering_path_mtu)?;
        let local_endpoint = socket
            .local_addr()
            .map_err(|_| IngressRedirectDatagramError::Io)?;
        Ok(Self {
            socket,
            local_endpoint,
            peer_endpoint,
            maximum_receive_datagram_size,
            maximum_send_datagram_size: AtomicUsize::new(maximum_send_datagram_size),
            configured_steering_path_mtu: steering_path_mtu,
        })
    }

    fn refresh_send_ceiling(&self) -> Result<usize, IngressRedirectDatagramError> {
        let refreshed = connected_udp_send_ceiling(
            &self.socket,
            self.peer_endpoint.ip(),
            self.configured_steering_path_mtu,
        );
        retain_proven_send_ceiling(&self.maximum_send_datagram_size, refreshed)
    }
}

fn retain_proven_send_ceiling(
    ceiling: &AtomicUsize,
    refreshed: Result<usize, IngressRedirectDatagramError>,
) -> Result<usize, IngressRedirectDatagramError> {
    let refreshed = refreshed?;
    let _ = ceiling.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
        Some(current.min(refreshed))
    });
    Ok(ceiling.load(Ordering::Acquire))
}

impl fmt::Debug for UdpIngressRedirectDatagram {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UdpIngressRedirectDatagram")
            .field("endpoints", &"[redacted]")
            .field(
                "maximum_receive_datagram_size",
                &self.maximum_receive_datagram_size,
            )
            .field(
                "maximum_send_datagram_size",
                &self.maximum_send_datagram_size.load(Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl IngressRedirectDatagram for UdpIngressRedirectDatagram {
    async fn send(&self, datagram: &[u8]) -> Result<(), IngressRedirectDatagramError> {
        let maximum_send_datagram_size = self.refresh_send_ceiling()?;
        if datagram.is_empty() || datagram.len() > maximum_send_datagram_size {
            return Err(IngressRedirectDatagramError::DatagramTooLarge);
        }
        let sent = match self.socket.send(datagram).await {
            Ok(sent) => sent,
            Err(error) if io_error_is_message_too_large(&error) => {
                let maximum_datagram_size = self.refresh_send_ceiling()?;
                let outer_headers = match self.peer_endpoint.ip() {
                    IpAddr::V4(_) => super::IPV4_HEADER_BYTES + UDP_HEADER_BYTES,
                    IpAddr::V6(_) => super::IPV6_HEADER_BYTES + UDP_HEADER_BYTES,
                };
                let effective_path_mtu = maximum_datagram_size
                    .checked_add(outer_headers)
                    .and_then(|value| u16::try_from(value).ok())
                    .ok_or(IngressRedirectDatagramError::Io)?;
                return Err(IngressRedirectDatagramError::PathMtuExceeded {
                    maximum_datagram_size,
                    effective_path_mtu,
                });
            }
            Err(_) => return Err(IngressRedirectDatagramError::Io),
        };
        if sent != datagram.len() {
            return Err(IngressRedirectDatagramError::Io);
        }
        Ok(())
    }

    async fn receive(&self) -> Result<Vec<u8>, IngressRedirectDatagramError> {
        let buffer_len = self
            .maximum_receive_datagram_size
            .checked_add(1)
            .ok_or(IngressRedirectDatagramError::InvalidConfiguration)?;
        let mut buffer = vec![0_u8; buffer_len];
        let received = self
            .socket
            .recv(&mut buffer)
            .await
            .map_err(|_| IngressRedirectDatagramError::Io)?;
        if received == 0 || received > self.maximum_receive_datagram_size {
            return Err(IngressRedirectDatagramError::DatagramTooLarge);
        }
        buffer.truncate(received);
        Ok(buffer)
    }

    fn local_endpoint(&self) -> SocketAddr {
        self.local_endpoint
    }

    fn peer_endpoint(&self) -> SocketAddr {
        self.peer_endpoint
    }

    fn maximum_receive_datagram_size(&self) -> usize {
        self.maximum_receive_datagram_size
    }

    fn maximum_send_datagram_size(&self) -> usize {
        self.maximum_send_datagram_size.load(Ordering::Acquire)
    }
}

#[cfg(target_os = "linux")]
fn configure_connected_udp_pmtu(
    socket: &UdpSocket,
    peer: IpAddr,
    configured_steering_path_mtu: u16,
) -> Result<usize, IngressRedirectDatagramError> {
    use rustix::net::sockopt::{
        ip_mtu_discover, ipv6_mtu_discover, set_ip_mtu_discover, set_ipv6_mtu_discover,
        Ipv4PathMtuDiscovery, Ipv6PathMtuDiscovery,
    };

    match peer {
        IpAddr::V4(_) => {
            set_ip_mtu_discover(socket, Ipv4PathMtuDiscovery::DO)
                .map_err(|_| IngressRedirectDatagramError::InvalidConfiguration)?;
            if ip_mtu_discover(socket)
                .map_err(|_| IngressRedirectDatagramError::InvalidConfiguration)?
                != Ipv4PathMtuDiscovery::DO
            {
                return Err(IngressRedirectDatagramError::InvalidConfiguration);
            }
        }
        IpAddr::V6(_) => {
            set_ipv6_mtu_discover(socket, Ipv6PathMtuDiscovery::DO)
                .map_err(|_| IngressRedirectDatagramError::InvalidConfiguration)?;
            if ipv6_mtu_discover(socket)
                .map_err(|_| IngressRedirectDatagramError::InvalidConfiguration)?
                != Ipv6PathMtuDiscovery::DO
            {
                return Err(IngressRedirectDatagramError::InvalidConfiguration);
            }
        }
    }
    connected_udp_send_ceiling(socket, peer, configured_steering_path_mtu)
}

#[cfg(not(target_os = "linux"))]
fn configure_connected_udp_pmtu(
    _socket: &UdpSocket,
    _peer: IpAddr,
    _configured_steering_path_mtu: u16,
) -> Result<usize, IngressRedirectDatagramError> {
    Err(IngressRedirectDatagramError::InvalidConfiguration)
}

#[cfg(target_os = "linux")]
fn connected_udp_send_ceiling(
    socket: &UdpSocket,
    peer: IpAddr,
    configured_steering_path_mtu: u16,
) -> Result<usize, IngressRedirectDatagramError> {
    let kernel_path_mtu = match peer {
        IpAddr::V4(_) => rustix::net::sockopt::ip_mtu(socket),
        IpAddr::V6(_) => rustix::net::sockopt::ipv6_mtu(socket),
    }
    .map_err(|_| IngressRedirectDatagramError::Io)?;
    let effective_path_mtu = kernel_path_mtu.min(u32::from(configured_steering_path_mtu));
    let effective_path_mtu = u16::try_from(effective_path_mtu)
        .map_err(|_| IngressRedirectDatagramError::InvalidConfiguration)?;
    maximum_udp_payload(effective_path_mtu, peer)
}

#[cfg(not(target_os = "linux"))]
fn connected_udp_send_ceiling(
    _socket: &UdpSocket,
    _peer: IpAddr,
    _configured_steering_path_mtu: u16,
) -> Result<usize, IngressRedirectDatagramError> {
    Err(IngressRedirectDatagramError::InvalidConfiguration)
}

#[cfg(target_os = "linux")]
fn io_error_is_message_too_large(error: &std::io::Error) -> bool {
    rustix::io::Errno::from_io_error(error) == Some(rustix::io::Errno::MSGSIZE)
}

#[cfg(not(target_os = "linux"))]
fn io_error_is_message_too_large(_error: &std::io::Error) -> bool {
    false
}

fn maximum_udp_payload(
    steering_path_mtu: u16,
    endpoint: IpAddr,
) -> Result<usize, IngressRedirectDatagramError> {
    let ip_header = match endpoint {
        IpAddr::V4(_) => super::IPV4_HEADER_BYTES,
        IpAddr::V6(_) => super::IPV6_HEADER_BYTES,
    };
    usize::from(steering_path_mtu)
        .checked_sub(ip_header + UDP_HEADER_BYTES)
        .filter(|value| *value > 0 && *value <= MAX_DATAGRAM_BYTES)
        .ok_or(IngressRedirectDatagramError::InvalidConfiguration)
}

fn validate_socket_endpoint(endpoint: SocketAddr) -> Result<(), IngressRedirectDatagramError> {
    if endpoint.port() == 0 || endpoint.ip().is_unspecified() || endpoint.ip().is_multicast() {
        return Err(IngressRedirectDatagramError::InvalidConfiguration);
    }
    match endpoint {
        SocketAddr::V4(address) if address.ip().is_broadcast() => {
            Err(IngressRedirectDatagramError::InvalidConfiguration)
        }
        SocketAddr::V6(address) if address.flowinfo() != 0 || address.scope_id() != 0 => {
            Err(IngressRedirectDatagramError::InvalidConfiguration)
        }
        _ => Ok(()),
    }
}

/// Redaction-safe failure returned by a caller-owned packet-too-big hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("ingress redirect packet-too-big reporter failed")]
pub struct IngressRedirectPacketTooBigReportError;

/// Original packet and exact effective MTU supplied only to the mandatory hook.
pub struct IngressRedirectPacketTooBigEvent<'a> {
    packet: &'a [u8],
    ownership_key: SessionOwnershipKey,
    maximum_original_packet: usize,
}

impl IngressRedirectPacketTooBigEvent<'_> {
    /// Exact original packet available to the caller-owned ICMP/PTB policy.
    #[must_use]
    pub fn packet(&self) -> &[u8] {
        self.packet
    }

    /// Destination-scoped key used to select the caller's feedback boundary.
    #[must_use]
    pub const fn ownership_key(&self) -> SessionOwnershipKey {
        self.ownership_key
    }

    /// Largest original packet that fits the authenticated steering path.
    #[must_use]
    pub const fn maximum_original_packet(&self) -> usize {
        self.maximum_original_packet
    }

    /// Routing domain for feedback routing without exposing it through Debug.
    #[must_use]
    pub const fn routing_domain(&self) -> RoutingDomainTag {
        self.ownership_key.destination().routing_domain()
    }
}

impl fmt::Debug for IngressRedirectPacketTooBigEvent<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IngressRedirectPacketTooBigEvent")
            .field("packet", &"[redacted]")
            .field("ownership_key", &"[redacted]")
            .field("maximum_original_packet", &self.maximum_original_packet)
            .finish()
    }
}

/// Mandatory caller-owned policy for producing ICMP/PTB feedback.
#[async_trait]
pub trait IngressRedirectPacketTooBigReporter: Send + Sync + fmt::Debug {
    /// Report one packet that cannot fit the exact authenticated redirect MTU.
    async fn report(
        &self,
        event: IngressRedirectPacketTooBigEvent<'_>,
    ) -> Result<(), IngressRedirectPacketTooBigReportError>;
}

/// Proven reason an endpoint-owned operation never handed a frame to a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IngressRedirectNotSentReason {
    /// The original packet exceeded the current effective steering ceiling.
    PacketTooLarge,
    /// Mandatory packet-too-big feedback did not complete successfully.
    PacketTooBigFeedbackFailed,
    /// A bounded local queue had no capacity before the first send attempt.
    QueueFull,
    /// The connected datagram boundary rejected the frame before transmission.
    TransportRejected,
    /// The absolute operation deadline elapsed before a send attempt began.
    DeadlineElapsed,
}

/// Terminal observation from an endpoint-owned redirect or forward operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IngressRedirectOperationOutcome {
    /// The SDK can prove no peer-visible delivery attempt occurred.
    NotSent(IngressRedirectNotSentReason),
    /// A correlated authenticated receipt committed the peer's admission result.
    AuthenticatedReceipt(IngressRedirectReceiptCode),
    /// A frame may have reached the peer, but no authenticated receipt proved it.
    DeliveryOutcomeUnknown,
}

/// Cancellation-safe observation handle for one endpoint-owned operation.
///
/// The endpoint task owns sealing, pending correlation, retries, and cleanup.
/// Dropping this handle stops observation only; it does not cancel, reseal, or
/// restart the operation.
#[must_use = "dropping the handle does not cancel the endpoint-owned operation"]
pub struct IngressRedirectOperation {
    result: Option<oneshot::Receiver<IngressRedirectOperationOutcome>>,
    completed: Option<IngressRedirectOperationOutcome>,
}

impl IngressRedirectOperation {
    fn pending(result: oneshot::Receiver<IngressRedirectOperationOutcome>) -> Self {
        Self {
            result: Some(result),
            completed: None,
        }
    }

    fn completed(outcome: IngressRedirectOperationOutcome) -> Self {
        Self {
            result: None,
            completed: Some(outcome),
        }
    }

    /// Wait for the terminal observation without transferring operation ownership.
    ///
    /// Cancelling this wait leaves the receiver and endpoint-owned worker intact;
    /// a later call resumes observation of the same operation.
    pub async fn wait(&mut self) -> IngressRedirectOperationOutcome {
        if let Some(outcome) = self.completed {
            return outcome;
        }
        let outcome = match self.result.as_mut() {
            Some(result) => result
                .await
                .unwrap_or(IngressRedirectOperationOutcome::DeliveryOutcomeUnknown),
            None => IngressRedirectOperationOutcome::DeliveryOutcomeUnknown,
        };
        self.result = None;
        self.completed = Some(outcome);
        outcome
    }
}

impl fmt::Debug for IngressRedirectOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IngressRedirectOperation")
            .field("completed", &self.completed.is_some())
            .finish_non_exhaustive()
    }
}

/// One authenticated inbound packet admitted to the bounded application queue.
///
/// Forwardable packets retain their authenticated hop count and can only be
/// sent onward by consuming them through [`IngressRedirectEndpoint::begin_forward`].
/// This prevents product routing policy from accidentally resetting a cycle to
/// hop one.
pub enum IngressRedirectInboundOutcome {
    /// This process is the exact fresh fenced owner.
    Delivered(DeliveredIngressRedirectPacket),
    /// Ownership evidence permits selecting another authenticated peer.
    Forwardable(ForwardableIngressRedirectPacket),
    /// A terminal typed rejection that must not be forwarded.
    Rejected(RejectedIngressRedirectPacket),
}

impl IngressRedirectInboundOutcome {
    /// Receipt committed for this exact authenticated frame.
    #[must_use]
    pub const fn receipt_code(&self) -> IngressRedirectReceiptCode {
        match self {
            Self::Delivered(_) => IngressRedirectReceiptCode::Delivered,
            Self::Forwardable(packet) => packet.receipt_code,
            Self::Rejected(packet) => packet.receipt_code,
        }
    }
}

impl fmt::Debug for IngressRedirectInboundOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Delivered(packet) => formatter.debug_tuple("Delivered").field(packet).finish(),
            Self::Forwardable(packet) => {
                formatter.debug_tuple("Forwardable").field(packet).finish()
            }
            Self::Rejected(packet) => formatter.debug_tuple("Rejected").field(packet).finish(),
        }
    }
}

/// Consuming capability for routing one authenticated packet to another peer.
pub struct ForwardableIngressRedirectPacket {
    data: AuthenticatedIngressRedirectData,
    receipt_code: IngressRedirectReceiptCode,
    source_session: Arc<IngressRedirectPeerSession>,
    valid_until: Instant,
}

impl ForwardableIngressRedirectPacket {
    /// Typed reason that made the local receiver non-terminally reject it.
    #[must_use]
    pub const fn receipt_code(&self) -> IngressRedirectReceiptCode {
        self.receipt_code
    }

    /// Authenticated redirect count retained for the next forwarding hop.
    #[must_use]
    pub const fn hop_count(&self) -> u8 {
        self.data.hop_count()
    }

    /// Authenticated loop bound retained for the next forwarding hop.
    #[must_use]
    pub const fn hop_limit(&self) -> u8 {
        self.data.hop_limit()
    }

    /// Canonical destination-scoped key used to select the next peer.
    #[must_use]
    pub const fn ownership_key(&self) -> SessionOwnershipKey {
        self.data.ownership_key()
    }

    #[cfg(test)]
    fn packet(&self) -> &[u8] {
        self.data.packet()
    }
}

impl fmt::Debug for ForwardableIngressRedirectPacket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ForwardableIngressRedirectPacket")
            .field("receipt_code", &self.receipt_code)
            .field("frame_identity", &"[redacted]")
            .field("ownership_key", &"[redacted]")
            .field("packet", &"[redacted]")
            .field("hop_count", &self.data.hop_count())
            .field("hop_limit", &self.data.hop_limit())
            .finish()
    }
}

/// Terminal authenticated rejection retained for bounded application evidence.
pub struct RejectedIngressRedirectPacket {
    data: AuthenticatedIngressRedirectData,
    receipt_code: IngressRedirectReceiptCode,
}

impl RejectedIngressRedirectPacket {
    /// Typed terminal rejection committed to the sender.
    #[must_use]
    pub const fn receipt_code(&self) -> IngressRedirectReceiptCode {
        self.receipt_code
    }

    /// Authenticated redirect count at rejection.
    #[must_use]
    pub const fn hop_count(&self) -> u8 {
        self.data.hop_count()
    }

    /// Authenticated loop bound at rejection.
    #[must_use]
    pub const fn hop_limit(&self) -> u8 {
        self.data.hop_limit()
    }

    /// Original packet by borrow for caller-owned typed feedback policy.
    #[must_use]
    pub fn packet(&self) -> &[u8] {
        self.data.packet()
    }
}

impl fmt::Debug for RejectedIngressRedirectPacket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RejectedIngressRedirectPacket")
            .field("receipt_code", &self.receipt_code)
            .field("frame_identity", &"[redacted]")
            .field("ownership_key", &"[redacted]")
            .field("packet", &"[redacted]")
            .field("packet_len", &self.data.packet().len())
            .field("hop_count", &self.data.hop_count())
            .field("hop_limit", &self.data.hop_limit())
            .finish()
    }
}

/// Fixed-cardinality, redaction-safe endpoint transport counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IngressRedirectEndpointMetricsSnapshot {
    /// Data frames handed to the datagram adapter, including first attempts.
    pub send_attempts: u64,
    /// Exact sealed-frame retries after a missing receipt.
    pub retries: u64,
    /// Redirects acknowledged as admitted to the peer delivery queue.
    pub delivery_receipts: u64,
    /// Authenticated typed rejection receipts.
    pub rejection_receipts: u64,
    /// Redirects that exhausted their bounded receipt policy.
    pub receipt_timeouts: u64,
    /// Authenticated receipts with no active local correlation.
    pub uncorrelated_receipts: u64,
    /// Impossible active identity collisions rejected before map mutation.
    pub pending_identity_collisions: u64,
    /// Exact committed receipts replayed for exact-frame retransmissions.
    pub cached_receipts_replayed: u64,
    /// New data frames shed before authentication because receipt retention was full.
    pub receipt_cache_load_shed: u64,
    /// Reserved receipt slots that could not be committed; no effect was published.
    pub receipt_cache_commit_failures: u64,
    /// Current reserved plus committed receipt entries.
    pub receipt_cache_entries_current: u64,
    /// Peak reserved plus committed receipt entries.
    pub receipt_cache_entries_peak: u64,
    /// Authenticated exact-owner packets admitted to the delivery queue.
    pub delivery_admissions: u64,
    /// Exact-owner packets materialized after dequeue-time revalidation.
    pub delivery_materialized: u64,
    /// Queued capabilities rejected by dequeue-time lifetime/fence validation.
    pub delivery_capability_stale_drops: u64,
    /// Datagrams rejected by the adapter or endpoint ceiling.
    pub transport_drops: u64,
    /// Outbound or inbound bounded queue rejections.
    pub queue_drops: u64,
    /// Oversize sends for which the mandatory feedback hook was invoked.
    pub packet_too_big_reports: u64,
    /// Feedback-hook failures.
    pub packet_too_big_report_failures: u64,
    /// Number of receipt latency samples.
    pub receipt_latency_samples: u64,
    /// Saturating aggregate receipt latency in microseconds.
    pub receipt_latency_total_micros: u64,
    /// Maximum observed receipt latency in microseconds.
    pub receipt_latency_max_micros: u64,
}

#[derive(Default)]
struct EndpointMetrics {
    send_attempts: AtomicU64,
    retries: AtomicU64,
    delivery_receipts: AtomicU64,
    rejection_receipts: AtomicU64,
    receipt_timeouts: AtomicU64,
    uncorrelated_receipts: AtomicU64,
    pending_identity_collisions: AtomicU64,
    cached_receipts_replayed: AtomicU64,
    receipt_cache_load_shed: AtomicU64,
    receipt_cache_commit_failures: AtomicU64,
    delivery_admissions: AtomicU64,
    delivery_materialized: AtomicU64,
    delivery_capability_stale_drops: AtomicU64,
    transport_drops: AtomicU64,
    queue_drops: AtomicU64,
    packet_too_big_reports: AtomicU64,
    packet_too_big_report_failures: AtomicU64,
    receipt_latency_samples: AtomicU64,
    receipt_latency_total_micros: AtomicU64,
    receipt_latency_max_micros: AtomicU64,
}

impl EndpointMetrics {
    fn snapshot(&self) -> IngressRedirectEndpointMetricsSnapshot {
        IngressRedirectEndpointMetricsSnapshot {
            send_attempts: self.send_attempts.load(Ordering::Relaxed),
            retries: self.retries.load(Ordering::Relaxed),
            delivery_receipts: self.delivery_receipts.load(Ordering::Relaxed),
            rejection_receipts: self.rejection_receipts.load(Ordering::Relaxed),
            receipt_timeouts: self.receipt_timeouts.load(Ordering::Relaxed),
            uncorrelated_receipts: self.uncorrelated_receipts.load(Ordering::Relaxed),
            pending_identity_collisions: self.pending_identity_collisions.load(Ordering::Relaxed),
            cached_receipts_replayed: self.cached_receipts_replayed.load(Ordering::Relaxed),
            receipt_cache_load_shed: self.receipt_cache_load_shed.load(Ordering::Relaxed),
            receipt_cache_commit_failures: self
                .receipt_cache_commit_failures
                .load(Ordering::Relaxed),
            receipt_cache_entries_current: 0,
            receipt_cache_entries_peak: 0,
            delivery_admissions: self.delivery_admissions.load(Ordering::Relaxed),
            delivery_materialized: self.delivery_materialized.load(Ordering::Relaxed),
            delivery_capability_stale_drops: self
                .delivery_capability_stale_drops
                .load(Ordering::Relaxed),
            transport_drops: self.transport_drops.load(Ordering::Relaxed),
            queue_drops: self.queue_drops.load(Ordering::Relaxed),
            packet_too_big_reports: self.packet_too_big_reports.load(Ordering::Relaxed),
            packet_too_big_report_failures: self
                .packet_too_big_report_failures
                .load(Ordering::Relaxed),
            receipt_latency_samples: self.receipt_latency_samples.load(Ordering::Relaxed),
            receipt_latency_total_micros: self.receipt_latency_total_micros.load(Ordering::Relaxed),
            receipt_latency_max_micros: self.receipt_latency_max_micros.load(Ordering::Relaxed),
        }
    }

    fn record_latency(&self, elapsed: Duration) {
        let micros = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        increment(&self.receipt_latency_samples);
        let _ = self.receipt_latency_total_micros.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |value| Some(value.saturating_add(micros)),
        );
        let _ = self
            .receipt_latency_max_micros
            .fetch_max(micros, Ordering::Relaxed);
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct FrameIdentity {
    epoch: u64,
    sequence: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum EndpointPhase {
    Active = 0,
    Draining = 1,
    Stopped = 2,
    Failed = 3,
}

impl EndpointPhase {
    fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Active,
            1 => Self::Draining,
            2 => Self::Stopped,
            _ => Self::Failed,
        }
    }
}

struct EndpointLifecycle {
    phase: AtomicU8,
    active_operations: AtomicUsize,
    shutdown_driver_started: AtomicBool,
    terminal_error: Mutex<Option<IngressRedirectError>>,
    phase_changed: watch::Sender<EndpointPhase>,
    operation_finished: Notify,
}

impl EndpointLifecycle {
    fn new() -> Arc<Self> {
        let (phase_changed, _) = watch::channel(EndpointPhase::Active);
        Arc::new(Self {
            phase: AtomicU8::new(EndpointPhase::Active as u8),
            active_operations: AtomicUsize::new(0),
            shutdown_driver_started: AtomicBool::new(false),
            terminal_error: Mutex::new(None),
            phase_changed,
            operation_finished: Notify::new(),
        })
    }

    fn phase(&self) -> EndpointPhase {
        EndpointPhase::from_u8(self.phase.load(Ordering::Acquire))
    }

    fn try_admit(self: &Arc<Self>) -> Result<EndpointOperationGuard, IngressRedirectError> {
        if self.phase() != EndpointPhase::Active {
            return Err(self.admission_error());
        }
        self.active_operations
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                active.checked_add(1)
            })
            .map_err(|_| IngressRedirectError::StateUnavailable)?;
        if self.phase() == EndpointPhase::Active {
            Ok(EndpointOperationGuard {
                lifecycle: Arc::clone(self),
            })
        } else {
            self.finish_operation();
            Err(self.admission_error())
        }
    }

    fn admission_error(&self) -> IngressRedirectError {
        self.terminal_error
            .lock()
            .ok()
            .and_then(|error| *error)
            .unwrap_or(IngressRedirectError::ShuttingDown)
    }

    fn begin_draining(&self) {
        if self
            .phase
            .compare_exchange(
                EndpointPhase::Active as u8,
                EndpointPhase::Draining as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            self.phase_changed.send_replace(EndpointPhase::Draining);
        }
    }

    fn fail(&self, error: IngressRedirectError) {
        if let Ok(mut terminal) = self.terminal_error.lock() {
            if terminal.is_none() {
                *terminal = Some(error);
            }
        }
        let prior = self
            .phase
            .swap(EndpointPhase::Failed as u8, Ordering::AcqRel);
        if EndpointPhase::from_u8(prior) != EndpointPhase::Failed {
            self.phase_changed.send_replace(EndpointPhase::Failed);
        }
        self.operation_finished.notify_waiters();
    }

    fn mark_stopped(&self) {
        if self.phase() == EndpointPhase::Failed {
            self.operation_finished.notify_waiters();
            return;
        }
        self.phase
            .store(EndpointPhase::Stopped as u8, Ordering::Release);
        self.phase_changed.send_replace(EndpointPhase::Stopped);
        self.operation_finished.notify_waiters();
    }

    fn finish_operation(&self) {
        let prior = self.active_operations.fetch_sub(1, Ordering::AcqRel);
        if prior <= 1 {
            self.operation_finished.notify_waiters();
        }
    }

    async fn wait_for_operations(&self) {
        loop {
            let notified = self.operation_finished.notified();
            if self.active_operations.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }

    async fn wait_terminal(&self) -> Result<(), IngressRedirectError> {
        let mut changed = self.phase_changed.subscribe();
        loop {
            match self.phase() {
                EndpointPhase::Stopped => return Ok(()),
                EndpointPhase::Failed => return Err(self.admission_error()),
                EndpointPhase::Active | EndpointPhase::Draining => {}
            }
            if changed.changed().await.is_err() {
                return Err(IngressRedirectError::StateUnavailable);
            }
        }
    }
}

struct EndpointOperationGuard {
    lifecycle: Arc<EndpointLifecycle>,
}

impl Drop for EndpointOperationGuard {
    fn drop(&mut self) {
        self.lifecycle.finish_operation();
    }
}

struct QueueUsage {
    packets: usize,
    bytes: usize,
}

struct QueueBudget {
    maximum_packets: usize,
    maximum_bytes: usize,
    usage: Mutex<QueueUsage>,
}

impl QueueBudget {
    fn new(maximum_packets: usize, maximum_bytes: usize) -> Arc<Self> {
        Arc::new(Self {
            maximum_packets,
            maximum_bytes,
            usage: Mutex::new(QueueUsage {
                packets: 0,
                bytes: 0,
            }),
        })
    }

    fn try_acquire(self: &Arc<Self>, bytes: usize) -> Result<QueuePermit, IngressRedirectError> {
        let mut usage = self
            .usage
            .lock()
            .map_err(|_| IngressRedirectError::StateUnavailable)?;
        let next_packets = usage
            .packets
            .checked_add(1)
            .ok_or(IngressRedirectError::QueueFull)?;
        let next_bytes = usage
            .bytes
            .checked_add(bytes)
            .ok_or(IngressRedirectError::QueueFull)?;
        if next_packets > self.maximum_packets || next_bytes > self.maximum_bytes {
            return Err(IngressRedirectError::QueueFull);
        }
        usage.packets = next_packets;
        usage.bytes = next_bytes;
        drop(usage);
        Ok(QueuePermit {
            budget: Arc::clone(self),
            bytes,
        })
    }
}

struct QueuePermit {
    budget: Arc<QueueBudget>,
    bytes: usize,
}

impl Drop for QueuePermit {
    fn drop(&mut self) {
        if let Ok(mut usage) = self.budget.usage.lock() {
            usage.packets = usage.packets.saturating_sub(1);
            usage.bytes = usage.bytes.saturating_sub(self.bytes);
        }
    }
}

struct DeliveryEnvelope {
    data: AuthenticatedIngressRedirectData,
    committed_code: IngressRedirectReceiptCode,
    valid_until: Instant,
    _permit: QueuePermit,
}

struct PendingReceipt {
    result: oneshot::Sender<Result<IngressRedirectReceiptCode, IngressRedirectError>>,
}

struct PendingRegistration {
    pending: Arc<Mutex<BTreeMap<FrameIdentity, PendingReceipt>>>,
    identity: FrameIdentity,
}

impl Drop for PendingRegistration {
    fn drop(&mut self) {
        if let Ok(mut pending) = self.pending.lock() {
            pending.remove(&self.identity);
        }
    }
}

struct CachedReceipt {
    frame_digest: [u8; 32],
    receipt: Arc<[u8]>,
    data_epoch: u64,
    receipt_epoch: u64,
    expires_at: Instant,
}

enum ReceiptCacheEntry {
    Reserved { frame_digest: [u8; 32] },
    Committed(CachedReceipt),
}

struct CachedReceiptMatch {
    receipt: Arc<[u8]>,
    data_epoch: u64,
    receipt_epoch: u64,
    expires_at: Instant,
}

struct ReceiptCache {
    capacity: usize,
    lifetime: Duration,
    entries: BTreeMap<FrameIdentity, ReceiptCacheEntry>,
    expiry_index: BTreeSet<(Instant, FrameIdentity)>,
    peak_entries: usize,
    #[cfg(test)]
    fail_next_commit: bool,
}

impl ReceiptCache {
    fn new(capacity: usize, lifetime: Duration) -> Self {
        Self {
            capacity,
            lifetime,
            entries: BTreeMap::new(),
            expiry_index: BTreeSet::new(),
            peak_entries: 0,
            #[cfg(test)]
            fail_next_commit: false,
        }
    }

    fn exact_receipt(
        &mut self,
        identity: FrameIdentity,
        frame_digest: &[u8; 32],
        now: Instant,
    ) -> Option<CachedReceiptMatch> {
        self.purge_expired(now);
        self.entries.get(&identity).and_then(|entry| match entry {
            ReceiptCacheEntry::Committed(entry)
                if entry.frame_digest.ct_eq(frame_digest).unwrap_u8() == 1 =>
            {
                Some(CachedReceiptMatch {
                    receipt: Arc::clone(&entry.receipt),
                    data_epoch: entry.data_epoch,
                    receipt_epoch: entry.receipt_epoch,
                    expires_at: entry.expires_at,
                })
            }
            ReceiptCacheEntry::Reserved { .. } | ReceiptCacheEntry::Committed(_) => None,
        })
    }

    fn reserve(
        cache: &Arc<Mutex<Self>>,
        identity: FrameIdentity,
        frame_digest: [u8; 32],
        now: Instant,
    ) -> Result<Option<ReceiptCacheReservation>, IngressRedirectError> {
        let mut locked = cache
            .lock()
            .map_err(|_| IngressRedirectError::StateUnavailable)?;
        locked.purge_expired(now);
        if locked.entries.contains_key(&identity) {
            return Ok(None);
        }
        if locked.entries.len() >= locked.capacity {
            return Err(IngressRedirectError::QueueFull);
        }
        locked
            .entries
            .insert(identity, ReceiptCacheEntry::Reserved { frame_digest });
        locked.peak_entries = locked.peak_entries.max(locked.entries.len());
        drop(locked);
        Ok(Some(ReceiptCacheReservation {
            cache: Arc::clone(cache),
            identity,
            frame_digest,
            active: true,
        }))
    }

    fn expiry(
        &self,
        now: Instant,
        data_epoch_valid_until: Instant,
        receipt_epoch_valid_until: Instant,
    ) -> Result<Instant, IngressRedirectError> {
        now.checked_add(self.lifetime)
            .map(|cache_deadline| {
                cache_deadline
                    .min(data_epoch_valid_until)
                    .min(receipt_epoch_valid_until)
            })
            .filter(|deadline| *deadline > now)
            .ok_or(IngressRedirectError::StateUnavailable)
    }

    fn commit_reserved(
        &mut self,
        identity: FrameIdentity,
        frame_digest: [u8; 32],
        receipt: Arc<[u8]>,
        data_epoch: u64,
        receipt_epoch: u64,
        expires_at: Instant,
    ) -> Result<(), IngressRedirectError> {
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next_commit) {
            return Err(IngressRedirectError::StateUnavailable);
        }
        let Some(ReceiptCacheEntry::Reserved {
            frame_digest: reserved_digest,
        }) = self.entries.get(&identity)
        else {
            return Err(IngressRedirectError::StateUnavailable);
        };
        if reserved_digest.ct_eq(&frame_digest).unwrap_u8() != 1 {
            return Err(IngressRedirectError::StateUnavailable);
        }
        self.entries.insert(
            identity,
            ReceiptCacheEntry::Committed(CachedReceipt {
                frame_digest,
                receipt,
                data_epoch,
                receipt_epoch,
                expires_at,
            }),
        );
        self.expiry_index.insert((expires_at, identity));
        Ok(())
    }

    fn purge_expired(&mut self, now: Instant) {
        while let Some(&(expires_at, identity)) = self.expiry_index.first() {
            if now < expires_at {
                break;
            }
            self.expiry_index.pop_first();
            let expired = self.entries.get(&identity).is_some_and(|entry| {
                matches!(
                    entry,
                    ReceiptCacheEntry::Committed(entry) if entry.expires_at == expires_at
                )
            });
            if expired {
                self.entries.remove(&identity);
            }
        }
    }

    fn remove(&mut self, identity: FrameIdentity) {
        if let Some(ReceiptCacheEntry::Committed(entry)) = self.entries.remove(&identity) {
            self.expiry_index.remove(&(entry.expires_at, identity));
        }
    }

    fn current_entries(&self) -> usize {
        self.entries.len()
    }

    fn peak_entries(&self) -> usize {
        self.peak_entries
    }
}

struct ReceiptCacheReservation {
    cache: Arc<Mutex<ReceiptCache>>,
    identity: FrameIdentity,
    frame_digest: [u8; 32],
    active: bool,
}

impl ReceiptCacheReservation {
    fn identity(&self) -> FrameIdentity {
        self.identity
    }

    fn commit(
        mut self,
        receipt: Arc<[u8]>,
        data_epoch: u64,
        receipt_epoch: u64,
        expires_at: Instant,
    ) -> Result<(), IngressRedirectError> {
        self.cache
            .lock()
            .map_err(|_| IngressRedirectError::StateUnavailable)?
            .commit_reserved(
                self.identity,
                self.frame_digest,
                receipt,
                data_epoch,
                receipt_epoch,
                expires_at,
            )?;
        self.active = false;
        Ok(())
    }
}

impl Drop for ReceiptCacheReservation {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Ok(mut cache) = self.cache.lock() {
            let matches_reservation = cache.entries.get(&self.identity).is_some_and(|entry| {
                matches!(
                    entry,
                    ReceiptCacheEntry::Reserved { frame_digest }
                        if frame_digest.ct_eq(&self.frame_digest).unwrap_u8() == 1
                )
            });
            if matches_reservation {
                cache.remove(self.identity);
            }
        }
    }
}

struct EndpointInner<C>
where
    C: Clock + 'static,
{
    session: Arc<IngressRedirectPeerSession>,
    ownership: Arc<FencedOwnershipCache<C>>,
    datagram: Arc<dyn IngressRedirectDatagram>,
    delivery: mpsc::Sender<DeliveryEnvelope>,
    inbound_budget: Arc<QueueBudget>,
    pending: Arc<Mutex<BTreeMap<FrameIdentity, PendingReceipt>>>,
    receipt_cache: Arc<Mutex<ReceiptCache>>,
    metrics: Arc<EndpointMetrics>,
    lifecycle: Arc<EndpointLifecycle>,
}

/// Bounded authenticated redirect sender and sole datagram receive task.
pub struct IngressRedirectEndpoint<C>
where
    C: Clock + 'static,
{
    inner: Arc<EndpointInner<C>>,
    reporter: Arc<dyn IngressRedirectPacketTooBigReporter>,
    outbound_budget: Arc<QueueBudget>,
    runtime: tokio::runtime::Handle,
    stop_receive: watch::Sender<bool>,
    receive_task: Mutex<Option<JoinHandle<()>>>,
}

impl<C> IngressRedirectEndpoint<C>
where
    C: Clock + 'static,
{
    /// Start one bounded endpoint from an authenticated session and exact
    /// committed ownership cache.
    ///
    /// The mandatory reporter makes oversize handling observable. Adapter
    /// endpoints and receive MTU must exactly match the mTLS-authenticated
    /// manifest before the sole receive task is spawned. Starting an endpoint
    /// permanently consumes the peer session, including after endpoint shutdown
    /// or drop; reuse could split receipt correlation across independent pending
    /// maps and is rejected with [`IngressRedirectError::EndpointAlreadyConsumed`].
    pub fn start(
        session: Arc<IngressRedirectPeerSession>,
        ownership: Arc<FencedOwnershipCache<C>>,
        datagram: Arc<dyn IngressRedirectDatagram>,
        reporter: Arc<dyn IngressRedirectPacketTooBigReporter>,
    ) -> Result<(Self, IngressRedirectDeliveryReceiver), IngressRedirectError> {
        if datagram.local_endpoint() != session.local_udp_endpoint()
            || datagram.peer_endpoint() != session.peer_udp_endpoint()
        {
            return Err(IngressRedirectError::PeerIdentityMismatch);
        }
        let expected_receive = maximum_udp_payload(
            session.profile().steering_path_mtu(),
            session.local_udp_endpoint().ip(),
        )
        .map_err(|_| IngressRedirectError::InvalidPeerManifest)?;
        if datagram.maximum_receive_datagram_size() != expected_receive {
            return Err(IngressRedirectError::InvalidPeerManifest);
        }
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| IngressRedirectError::StateUnavailable)?;
        let profile = session.profile();
        let (delivery_tx, delivery_rx) = mpsc::channel(profile.queue_packets());
        let inbound_budget = QueueBudget::new(profile.queue_packets(), profile.queue_bytes());
        let outbound_budget = QueueBudget::new(profile.queue_packets(), profile.queue_bytes());
        let metrics = Arc::new(EndpointMetrics::default());
        let lifecycle = EndpointLifecycle::new();
        session.consume_for_endpoint()?;
        let inner = Arc::new(EndpointInner {
            session,
            ownership,
            datagram,
            delivery: delivery_tx,
            inbound_budget,
            pending: Arc::new(Mutex::new(BTreeMap::new())),
            receipt_cache: Arc::new(Mutex::new(ReceiptCache::new(
                profile.receipt_cache_entries(),
                profile.receipt_retry_horizon(),
            ))),
            metrics,
            lifecycle: Arc::clone(&lifecycle),
        });
        let (stop_receive, stop_receive_rx) = watch::channel(false);
        let receive_task = runtime.spawn(run_receive_loop(Arc::clone(&inner), stop_receive_rx));
        let receiver = IngressRedirectDeliveryReceiver {
            delivery: delivery_rx,
            validator: Arc::new(EndpointDeliveryValidator {
                session: Arc::clone(&inner.session),
                ownership: Arc::clone(&inner.ownership),
                metrics: Arc::clone(&inner.metrics),
            }),
            lifecycle,
        };
        Ok((
            Self {
                inner,
                reporter,
                outbound_budget,
                runtime,
                stop_receive,
                receive_task: Mutex::new(Some(receive_task)),
            },
            receiver,
        ))
    }

    /// Return fixed-cardinality per-peer transport counters.
    #[must_use]
    pub fn metrics(&self) -> IngressRedirectEndpointMetricsSnapshot {
        let mut snapshot = self.inner.metrics.snapshot();
        if let Ok(mut cache) = self.inner.receipt_cache.lock() {
            cache.purge_expired(Instant::now());
            snapshot.receipt_cache_entries_current =
                u64::try_from(cache.current_entries()).unwrap_or(u64::MAX);
            snapshot.receipt_cache_entries_peak =
                u64::try_from(cache.peak_entries()).unwrap_or(u64::MAX);
        }
        snapshot
    }

    /// Begin one endpoint-owned first-hop redirect operation.
    ///
    /// Admission, the absolute retry deadline, sealing, and receipt
    /// registration complete synchronously. Dropping the returned observation
    /// handle does not cancel or restart the operation.
    pub fn begin_redirect(
        &self,
        packet: &[u8],
        ownership_key: SessionOwnershipKey,
        ownership_generation: FencedOwnershipGeneration,
    ) -> Result<IngressRedirectOperation, IngressRedirectError> {
        let operation_guard = self.inner.lifecycle.try_admit()?;
        if packet.is_empty() {
            return Err(IngressRedirectError::InvalidOriginalPacket);
        }
        let started_at = Instant::now();
        let (_, deadline) = self.operation_deadline_from(started_at)?;
        let maximum_original_packet = self.maximum_original_packet(ownership_key)?;
        let queue_permit = match self.outbound_budget.try_acquire(packet.len()) {
            Ok(permit) => permit,
            Err(IngressRedirectError::QueueFull) => {
                self.inner.session.metrics.record_queue_drop();
                increment(&self.inner.metrics.queue_drops);
                return Ok(IngressRedirectOperation::completed(
                    IngressRedirectOperationOutcome::NotSent(
                        IngressRedirectNotSentReason::QueueFull,
                    ),
                ));
            }
            Err(error) => return Err(error),
        };
        let packet = packet.to_vec();
        if packet.len() > maximum_original_packet {
            return Ok(self.begin_packet_too_big(
                packet,
                ownership_key,
                maximum_original_packet,
                queue_permit,
                operation_guard,
                deadline,
            ));
        }
        let sealed = self.inner.session.seal_data_for_endpoint(
            &packet,
            ownership_key,
            ownership_generation,
            deadline,
        )?;
        self.begin_sealed_operation(
            sealed,
            packet,
            ownership_key,
            queue_permit,
            operation_guard,
            started_at,
            deadline,
        )
    }

    /// Forward one authenticated non-owner outcome to this endpoint's peer.
    ///
    /// The capability is consumed and its authenticated hop count is checked
    /// and incremented by the peer session. There is no endpoint API that can
    /// turn this value back into a first-hop redirect.
    pub fn begin_forward(
        &self,
        packet: ForwardableIngressRedirectPacket,
        ownership_generation: FencedOwnershipGeneration,
    ) -> Result<IngressRedirectOperation, IngressRedirectError> {
        let operation_guard = self.inner.lifecycle.try_admit()?;
        let ForwardableIngressRedirectPacket {
            data,
            source_session,
            valid_until,
            ..
        } = packet;
        let started_at = Instant::now();
        if started_at >= valid_until
            || source_session
                .receive_epoch_valid_until(data.epoch().get(), started_at)
                .is_err()
        {
            return Err(IngressRedirectError::DeliveryCapabilityStale);
        }
        let ownership_key = data.ownership_key();
        let (_, deadline) = self.operation_deadline_from(started_at)?;
        let maximum_original_packet = self.maximum_original_packet(ownership_key)?;
        let queue_permit = match self.outbound_budget.try_acquire(data.packet().len()) {
            Ok(permit) => permit,
            Err(IngressRedirectError::QueueFull) => {
                self.inner.session.metrics.record_queue_drop();
                increment(&self.inner.metrics.queue_drops);
                return Ok(IngressRedirectOperation::completed(
                    IngressRedirectOperationOutcome::NotSent(
                        IngressRedirectNotSentReason::QueueFull,
                    ),
                ));
            }
            Err(error) => return Err(error),
        };
        if data.packet().len() > maximum_original_packet {
            return Ok(self.begin_packet_too_big(
                data.packet,
                ownership_key,
                maximum_original_packet,
                queue_permit,
                operation_guard,
                deadline,
            ));
        }
        let sealed = self.inner.session.seal_forwarded_data_for_endpoint(
            &data,
            ownership_generation,
            deadline,
        )?;
        let original_packet = data.packet;
        self.begin_sealed_operation(
            sealed,
            original_packet,
            ownership_key,
            queue_permit,
            operation_guard,
            started_at,
            deadline,
        )
    }

    fn operation_deadline_from(
        &self,
        started_at: Instant,
    ) -> Result<(Instant, Instant), IngressRedirectError> {
        let attempts = u32::from(self.inner.session.profile().max_retries())
            .checked_add(1)
            .ok_or(IngressRedirectError::StateUnavailable)?;
        let total = self
            .inner
            .session
            .profile()
            .receipt_timeout()
            .checked_mul(attempts)
            .ok_or(IngressRedirectError::StateUnavailable)?;
        let deadline = started_at
            .checked_add(total)
            .ok_or(IngressRedirectError::StateUnavailable)?;
        Ok((started_at, deadline))
    }

    fn maximum_original_packet(
        &self,
        ownership_key: SessionOwnershipKey,
    ) -> Result<usize, IngressRedirectError> {
        let key_len = ownership_key.to_canonical_bytes().len();
        let budget = IngressRedirectMtuBudget::new(
            self.inner.session.profile(),
            self.inner.session.peer_udp_endpoint().ip(),
            key_len,
        )?;
        let adapter_packet_ceiling = self
            .inner
            .datagram
            .maximum_send_datagram_size()
            .saturating_sub(budget.redirect_overhead());
        Ok(budget.maximum_original_packet().min(adapter_packet_ceiling))
    }

    fn begin_packet_too_big(
        &self,
        packet: Vec<u8>,
        ownership_key: SessionOwnershipKey,
        maximum_original_packet: usize,
        queue_permit: QueuePermit,
        operation_guard: EndpointOperationGuard,
        deadline: Instant,
    ) -> IngressRedirectOperation {
        let (result_tx, result_rx) = oneshot::channel();
        let reporter = Arc::clone(&self.reporter);
        let metrics = Arc::clone(&self.inner.metrics);
        let session = Arc::clone(&self.inner.session);
        self.runtime.spawn(async move {
            let _queue_permit = queue_permit;
            increment(&session.metrics.oversize_drops);
            increment(&metrics.packet_too_big_reports);
            let event = IngressRedirectPacketTooBigEvent {
                packet: &packet,
                ownership_key,
                maximum_original_packet,
            };
            let remaining = deadline.saturating_duration_since(Instant::now());
            let outcome = if !remaining.is_zero()
                && matches!(
                    tokio::time::timeout(remaining, reporter.report(event)).await,
                    Ok(Ok(()))
                ) {
                IngressRedirectOperationOutcome::NotSent(
                    IngressRedirectNotSentReason::PacketTooLarge,
                )
            } else if remaining.is_zero() {
                IngressRedirectOperationOutcome::NotSent(
                    IngressRedirectNotSentReason::DeadlineElapsed,
                )
            } else {
                increment(&metrics.packet_too_big_report_failures);
                IngressRedirectOperationOutcome::NotSent(
                    IngressRedirectNotSentReason::PacketTooBigFeedbackFailed,
                )
            };
            drop(operation_guard);
            let _ = result_tx.send(outcome);
        });
        IngressRedirectOperation::pending(result_rx)
    }

    #[allow(clippy::too_many_arguments)]
    fn begin_sealed_operation(
        &self,
        sealed: SealedIngressRedirectFrame,
        packet: Vec<u8>,
        ownership_key: SessionOwnershipKey,
        queue_permit: QueuePermit,
        operation_guard: EndpointOperationGuard,
        started_at: Instant,
        deadline: Instant,
    ) -> Result<IngressRedirectOperation, IngressRedirectError> {
        let identity = FrameIdentity {
            epoch: sealed.epoch.get(),
            sequence: sealed.sequence,
        };
        let (receipt_tx, receipt_rx) = oneshot::channel();
        {
            let mut pending = self
                .inner
                .pending
                .lock()
                .map_err(|_| IngressRedirectError::StateUnavailable)?;
            if pending.len() >= self.inner.session.profile().queue_packets() {
                increment(&self.inner.metrics.queue_drops);
                return Err(IngressRedirectError::QueueFull);
            }
            if pending.contains_key(&identity) {
                increment(&self.inner.metrics.pending_identity_collisions);
                return Err(IngressRedirectError::StateUnavailable);
            }
            pending.insert(identity, PendingReceipt { result: receipt_tx });
        }
        let registration = PendingRegistration {
            pending: Arc::clone(&self.inner.pending),
            identity,
        };
        let (result_tx, result_rx) = oneshot::channel();
        let context = OutboundOperationContext {
            inner: Arc::clone(&self.inner),
            reporter: Arc::clone(&self.reporter),
            sealed,
            packet,
            ownership_key,
            _queue_permit: queue_permit,
            _registration: registration,
            _operation_guard: operation_guard,
            receipt: receipt_rx,
            started_at,
            deadline,
        };
        self.runtime.spawn(async move {
            let outcome = run_outbound_operation(context).await;
            let _ = result_tx.send(outcome);
        });
        Ok(IngressRedirectOperation::pending(result_rx))
    }

    #[cfg(test)]
    async fn redirect(
        &self,
        packet: &[u8],
        ownership_key: SessionOwnershipKey,
        ownership_generation: FencedOwnershipGeneration,
    ) -> Result<IngressRedirectReceiptCode, IngressRedirectError> {
        let mut operation = self.begin_redirect(packet, ownership_key, ownership_generation)?;
        test_operation_result(operation.wait().await)
    }

    #[cfg(test)]
    async fn forward(
        &self,
        packet: ForwardableIngressRedirectPacket,
        ownership_generation: FencedOwnershipGeneration,
    ) -> Result<IngressRedirectReceiptCode, IngressRedirectError> {
        let mut operation = self.begin_forward(packet, ownership_generation)?;
        test_operation_result(operation.wait().await)
    }

    /// Drain admitted operations, then stop and reap the sole receive task.
    ///
    /// New operations are rejected as soon as draining begins. The detached
    /// shutdown coordinator continues if one caller cancels its wait, concurrent
    /// callers observe the same terminal lifecycle proof, and repeated calls are
    /// safe. Committed inbound queue entries remain available to the receiver.
    pub async fn shutdown(&self) -> Result<(), IngressRedirectError> {
        self.inner.lifecycle.begin_draining();
        if self
            .inner
            .lifecycle
            .shutdown_driver_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let task = match self.receive_task.lock() {
                Ok(mut task) => task.take(),
                Err(_) => {
                    self.inner
                        .lifecycle
                        .fail(IngressRedirectError::StateUnavailable);
                    return Err(IngressRedirectError::StateUnavailable);
                }
            };
            let lifecycle = Arc::clone(&self.inner.lifecycle);
            let stop_receive = self.stop_receive.clone();
            self.runtime.spawn(async move {
                lifecycle.wait_for_operations().await;
                let _ = stop_receive.send(true);
                if let Some(task) = task {
                    if task.await.is_err() {
                        lifecycle.fail(IngressRedirectError::StateUnavailable);
                        return;
                    }
                }
                lifecycle.mark_stopped();
            });
        }
        self.inner.lifecycle.wait_terminal().await
    }
}

#[cfg(test)]
fn test_operation_result(
    outcome: IngressRedirectOperationOutcome,
) -> Result<IngressRedirectReceiptCode, IngressRedirectError> {
    match outcome {
        IngressRedirectOperationOutcome::AuthenticatedReceipt(code) => Ok(code),
        IngressRedirectOperationOutcome::NotSent(IngressRedirectNotSentReason::PacketTooLarge) => {
            Err(IngressRedirectError::PacketTooLarge)
        }
        IngressRedirectOperationOutcome::NotSent(
            IngressRedirectNotSentReason::PacketTooBigFeedbackFailed,
        ) => Err(IngressRedirectError::PacketTooBigFeedbackFailed),
        IngressRedirectOperationOutcome::NotSent(IngressRedirectNotSentReason::QueueFull) => {
            Err(IngressRedirectError::QueueFull)
        }
        IngressRedirectOperationOutcome::NotSent(
            IngressRedirectNotSentReason::TransportRejected,
        ) => Err(IngressRedirectError::TransportFailed),
        IngressRedirectOperationOutcome::NotSent(IngressRedirectNotSentReason::DeadlineElapsed)
        | IngressRedirectOperationOutcome::DeliveryOutcomeUnknown => {
            Err(IngressRedirectError::ReceiptTimeout)
        }
    }
}

struct OutboundOperationContext<C>
where
    C: Clock + 'static,
{
    inner: Arc<EndpointInner<C>>,
    reporter: Arc<dyn IngressRedirectPacketTooBigReporter>,
    sealed: SealedIngressRedirectFrame,
    packet: Vec<u8>,
    ownership_key: SessionOwnershipKey,
    _queue_permit: QueuePermit,
    _registration: PendingRegistration,
    _operation_guard: EndpointOperationGuard,
    receipt: oneshot::Receiver<Result<IngressRedirectReceiptCode, IngressRedirectError>>,
    started_at: Instant,
    deadline: Instant,
}

async fn run_outbound_operation<C>(
    mut context: OutboundOperationContext<C>,
) -> IngressRedirectOperationOutcome
where
    C: Clock + 'static,
{
    let mut delivery_possible = false;
    let maximum_attempts = context
        .inner
        .session
        .profile()
        .max_retries()
        .saturating_add(1);
    for attempt in 0..maximum_attempts {
        let now = Instant::now();
        if now >= context.deadline || now >= context.sealed.valid_until {
            if delivery_possible {
                increment(&context.inner.metrics.receipt_timeouts);
                return IngressRedirectOperationOutcome::DeliveryOutcomeUnknown;
            }
            return IngressRedirectOperationOutcome::NotSent(
                IngressRedirectNotSentReason::DeadlineElapsed,
            );
        }
        let slice_deadline = now
            .checked_add(context.inner.session.profile().receipt_timeout())
            .map(|deadline| deadline.min(context.deadline))
            .unwrap_or(context.deadline);
        let sleep = tokio::time::sleep_until(tokio::time::Instant::from_std(slice_deadline));
        tokio::pin!(sleep);
        let datagram = Arc::clone(&context.inner.datagram);
        let metrics = Arc::clone(&context.inner.metrics);
        let sealed = Arc::clone(&context.sealed.bytes);
        let send = async move {
            if attempt > 0 {
                increment(&metrics.retries);
            }
            increment(&metrics.send_attempts);
            datagram.send(sealed.as_ref()).await
        };
        tokio::pin!(send);
        let mut send_complete = false;
        loop {
            tokio::select! {
                biased;
                receipt = &mut context.receipt => {
                    return match receipt {
                        Ok(Ok(code)) => {
                            context.inner.metrics.record_latency(context.started_at.elapsed());
                            if code == IngressRedirectReceiptCode::Delivered {
                                increment(&context.inner.metrics.delivery_receipts);
                            } else {
                                increment(&context.inner.metrics.rejection_receipts);
                            }
                            IngressRedirectOperationOutcome::AuthenticatedReceipt(code)
                        }
                        Ok(Err(_)) | Err(_) => {
                            IngressRedirectOperationOutcome::DeliveryOutcomeUnknown
                        }
                    };
                }
                sent = &mut send, if !send_complete => {
                    send_complete = true;
                    match sent {
                        Ok(()) => delivery_possible = true,
                        Err(IngressRedirectDatagramError::Io | IngressRedirectDatagramError::TimedOut) => {
                            increment(&context.inner.metrics.transport_drops);
                            delivery_possible = true;
                        }
                        Err(
                            IngressRedirectDatagramError::DatagramTooLarge
                            | IngressRedirectDatagramError::PathMtuExceeded { .. },
                        ) => {
                            increment(&context.inner.metrics.transport_drops);
                            let maximum_original_packet = current_original_packet_ceiling(
                                context.inner.as_ref(),
                                context.ownership_key,
                            );
                            increment(&context.inner.session.metrics.oversize_drops);
                            increment(&context.inner.metrics.packet_too_big_reports);
                            let event = IngressRedirectPacketTooBigEvent {
                                packet: &context.packet,
                                ownership_key: context.ownership_key,
                                maximum_original_packet,
                            };
                            let remaining = context
                                .deadline
                                .saturating_duration_since(Instant::now());
                            let reported = !remaining.is_zero()
                                && matches!(
                                    tokio::time::timeout(
                                        remaining,
                                        context.reporter.report(event),
                                    )
                                    .await,
                                    Ok(Ok(()))
                                );
                            if !reported {
                                increment(&context.inner.metrics.packet_too_big_report_failures);
                            }
                            return if delivery_possible {
                                IngressRedirectOperationOutcome::DeliveryOutcomeUnknown
                            } else if reported {
                                IngressRedirectOperationOutcome::NotSent(
                                    IngressRedirectNotSentReason::PacketTooLarge,
                                )
                            } else {
                                IngressRedirectOperationOutcome::NotSent(
                                    IngressRedirectNotSentReason::PacketTooBigFeedbackFailed,
                                )
                            };
                        }
                        Err(IngressRedirectDatagramError::QueueFull) => {
                            increment(&context.inner.metrics.queue_drops);
                            return if delivery_possible {
                                IngressRedirectOperationOutcome::DeliveryOutcomeUnknown
                            } else {
                                IngressRedirectOperationOutcome::NotSent(
                                    IngressRedirectNotSentReason::QueueFull,
                                )
                            };
                        }
                        Err(
                            IngressRedirectDatagramError::InvalidConfiguration
                            | IngressRedirectDatagramError::Closed,
                        ) => {
                            increment(&context.inner.metrics.transport_drops);
                            return if delivery_possible {
                                IngressRedirectOperationOutcome::DeliveryOutcomeUnknown
                            } else {
                                IngressRedirectOperationOutcome::NotSent(
                                    IngressRedirectNotSentReason::TransportRejected,
                                )
                            };
                        }
                    }
                }
                () = &mut sleep => {
                    if !send_complete {
                        increment(&context.inner.metrics.transport_drops);
                        delivery_possible = true;
                    }
                    break;
                }
            }
        }
    }
    if delivery_possible {
        increment(&context.inner.metrics.receipt_timeouts);
        IngressRedirectOperationOutcome::DeliveryOutcomeUnknown
    } else {
        IngressRedirectOperationOutcome::NotSent(IngressRedirectNotSentReason::TransportRejected)
    }
}

fn current_original_packet_ceiling<C>(
    inner: &EndpointInner<C>,
    ownership_key: SessionOwnershipKey,
) -> usize
where
    C: Clock + 'static,
{
    let key_len = ownership_key.to_canonical_bytes().len();
    IngressRedirectMtuBudget::new(
        inner.session.profile(),
        inner.session.peer_udp_endpoint().ip(),
        key_len,
    )
    .ok()
    .map(|budget| {
        inner
            .datagram
            .maximum_send_datagram_size()
            .saturating_sub(budget.redirect_overhead())
            .min(budget.maximum_original_packet())
    })
    .unwrap_or(0)
}

impl<C> fmt::Debug for IngressRedirectEndpoint<C>
where
    C: Clock + 'static,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IngressRedirectEndpoint")
            .field("peer", &"[redacted]")
            .field("session", &"[redacted]")
            .finish_non_exhaustive()
    }
}

impl<C> Drop for IngressRedirectEndpoint<C>
where
    C: Clock + 'static,
{
    fn drop(&mut self) {
        let _ = self.stop_receive.send(true);
        if !matches!(
            self.inner.lifecycle.phase(),
            EndpointPhase::Stopped | EndpointPhase::Failed
        ) {
            self.inner
                .lifecycle
                .fail(IngressRedirectError::ShuttingDown);
            resolve_all_pending(&self.inner.pending, IngressRedirectError::ShuttingDown);
        }
        if let Ok(mut task) = self.receive_task.lock() {
            if let Some(task) = task.take() {
                task.abort();
            }
        }
    }
}

/// Single-consumer bounded queue of packets admitted at the ownership effect point.
pub struct IngressRedirectDeliveryReceiver {
    delivery: mpsc::Receiver<DeliveryEnvelope>,
    validator: Arc<dyn DeliveryValidator>,
    lifecycle: Arc<EndpointLifecycle>,
}

impl IngressRedirectDeliveryReceiver {
    /// Receive one typed outcome after revalidating its exact committed authority.
    ///
    /// A terminal endpoint drains already-committed envelopes before returning
    /// its terminal error. Queue byte/packet budget is released before return.
    pub async fn receive(&mut self) -> Result<IngressRedirectInboundOutcome, IngressRedirectError> {
        let mut phase_changed = self.lifecycle.phase_changed.subscribe();
        loop {
            match self.delivery.try_recv() {
                Ok(envelope) => return self.validator.materialize(envelope),
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    return Err(self.lifecycle.admission_error());
                }
                Err(mpsc::error::TryRecvError::Empty) => {}
            }
            if matches!(
                self.lifecycle.phase(),
                EndpointPhase::Stopped | EndpointPhase::Failed
            ) {
                return Err(self.lifecycle.admission_error());
            }
            tokio::select! {
                biased;
                envelope = self.delivery.recv() => {
                    if let Some(envelope) = envelope {
                        return self.validator.materialize(envelope);
                    }
                }
                changed = phase_changed.changed() => {
                    if changed.is_err() {
                        return Err(IngressRedirectError::StateUnavailable);
                    }
                }
            }
        }
    }
}

trait DeliveryValidator: Send + Sync {
    fn materialize(
        &self,
        envelope: DeliveryEnvelope,
    ) -> Result<IngressRedirectInboundOutcome, IngressRedirectError>;
}

struct EndpointDeliveryValidator<C>
where
    C: Clock + 'static,
{
    session: Arc<IngressRedirectPeerSession>,
    ownership: Arc<FencedOwnershipCache<C>>,
    metrics: Arc<EndpointMetrics>,
}

impl<C> DeliveryValidator for EndpointDeliveryValidator<C>
where
    C: Clock + 'static,
{
    fn materialize(
        &self,
        envelope: DeliveryEnvelope,
    ) -> Result<IngressRedirectInboundOutcome, IngressRedirectError> {
        let DeliveryEnvelope {
            data,
            committed_code,
            valid_until,
            _permit,
        } = envelope;
        let now = Instant::now();
        if now >= valid_until
            || self
                .session
                .receive_epoch_valid_until(data.epoch().get(), now)
                .is_err()
        {
            self.session.metrics.record_delivery_capability_stale();
            increment(&self.metrics.delivery_capability_stale_drops);
            return Err(IngressRedirectError::DeliveryCapabilityStale);
        }
        let validation = self
            .session
            .revalidate_delivery_evidence(&data, &self.ownership);
        let current_code = match validation {
            Ok(_) => IngressRedirectReceiptCode::Delivered,
            Err(error) => receipt_code_for_delivery_error(error)
                .ok_or(IngressRedirectError::DeliveryCapabilityStale)?,
        };
        if current_code != committed_code {
            self.session.metrics.record_delivery_capability_stale();
            increment(&self.metrics.delivery_capability_stale_drops);
            return Err(IngressRedirectError::DeliveryCapabilityStale);
        }
        match validation {
            Ok(ownership_generation) => {
                self.session.metrics.record_delivered();
                increment(&self.metrics.delivery_materialized);
                Ok(IngressRedirectInboundOutcome::Delivered(
                    DeliveredIngressRedirectPacket {
                        ownership_key: data.ownership_key,
                        ownership_generation,
                        hop_count: data.hop_count,
                        packet: data.packet,
                    },
                ))
            }
            Err(error) if delivery_error_is_forwardable(error) => Ok(
                IngressRedirectInboundOutcome::Forwardable(ForwardableIngressRedirectPacket {
                    data,
                    receipt_code: committed_code,
                    source_session: Arc::clone(&self.session),
                    valid_until,
                }),
            ),
            Err(_) => Ok(IngressRedirectInboundOutcome::Rejected(
                RejectedIngressRedirectPacket {
                    data,
                    receipt_code: committed_code,
                },
            )),
        }
    }
}

impl fmt::Debug for IngressRedirectDeliveryReceiver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IngressRedirectDeliveryReceiver")
            .finish_non_exhaustive()
    }
}

async fn run_receive_loop<C>(inner: Arc<EndpointInner<C>>, mut shutdown: watch::Receiver<bool>)
where
    C: Clock + 'static,
{
    let mut terminal_error = IngressRedirectError::ShuttingDown;
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            received = inner.datagram.receive() => {
                match received {
                    Ok(datagram) => handle_datagram(&inner, datagram).await,
                    Err(
                        IngressRedirectDatagramError::DatagramTooLarge
                        | IngressRedirectDatagramError::PathMtuExceeded { .. },
                    ) => {
                        increment(&inner.metrics.transport_drops);
                    }
                    Err(_) => {
                        increment(&inner.metrics.transport_drops);
                        terminal_error = IngressRedirectError::TransportFailed;
                        inner.lifecycle.fail(terminal_error);
                        break;
                    }
                }
            }
        }
    }
    resolve_all_pending(&inner.pending, terminal_error);
}

async fn handle_datagram<C>(inner: &Arc<EndpointInner<C>>, datagram: Vec<u8>)
where
    C: Clock + 'static,
{
    let frame_digest: [u8; 32] = Sha256::digest(&datagram).into();
    let mut reservation = None;
    if let Ok(header) = IngressRedirectFrameHeader::decode(&datagram) {
        if header.kind() == IngressRedirectFrameKind::Data {
            let identity = FrameIdentity {
                epoch: header.epoch(),
                sequence: header.sequence(),
            };
            let now = Instant::now();
            let cached = inner
                .receipt_cache
                .lock()
                .ok()
                .and_then(|mut cache| cache.exact_receipt(identity, &frame_digest, now));
            if let Some(cached) = cached {
                let valid = now < cached.expires_at
                    && inner
                        .session
                        .receive_epoch_valid_until(cached.data_epoch, now)
                        .is_ok()
                    && inner
                        .session
                        .receive_epoch_valid_until(cached.receipt_epoch, now)
                        .is_ok();
                if valid {
                    increment(&inner.metrics.cached_receipts_replayed);
                    if send_datagram_bounded(
                        inner.datagram.as_ref(),
                        &cached.receipt,
                        inner.session.profile().receipt_timeout(),
                    )
                    .await
                    .is_err()
                    {
                        increment(&inner.metrics.transport_drops);
                    }
                    return;
                }
                if let Ok(mut cache) = inner.receipt_cache.lock() {
                    cache.remove(identity);
                }
            }
            match ReceiptCache::reserve(
                &inner.receipt_cache,
                identity,
                frame_digest,
                Instant::now(),
            ) {
                Ok(Some(reserved)) => reservation = Some(reserved),
                Ok(None) => {}
                Err(IngressRedirectError::QueueFull) => {
                    inner.session.metrics.record_queue_drop();
                    increment(&inner.metrics.queue_drops);
                    increment(&inner.metrics.receipt_cache_load_shed);
                    return;
                }
                Err(_) => return,
            }
        }
    }

    match inner.session.open(&datagram) {
        Ok(AuthenticatedIngressRedirectFrame::Receipt(receipt)) => {
            let identity = FrameIdentity {
                epoch: receipt.acknowledged_epoch().get(),
                sequence: receipt.acknowledged_sequence(),
            };
            let sender = inner
                .pending
                .lock()
                .ok()
                .and_then(|mut pending| pending.remove(&identity));
            if let Some(pending) = sender {
                let _ = pending.result.send(Ok(receipt.code()));
            } else {
                increment(&inner.metrics.uncorrelated_receipts);
            }
        }
        Ok(AuthenticatedIngressRedirectFrame::Data(data)) => {
            if inner.lifecycle.phase() == EndpointPhase::Active {
                if let Some(reservation) = reservation {
                    process_authenticated_data(inner, data, reservation).await;
                }
            }
        }
        Err(_) => {}
    }
}

async fn process_authenticated_data<C>(
    inner: &Arc<EndpointInner<C>>,
    data: AuthenticatedIngressRedirectData,
    reservation: ReceiptCacheReservation,
) where
    C: Clock + 'static,
{
    let identity = reservation.identity();
    let packet_len = data.packet().len();
    let permit = match inner.inbound_budget.try_acquire(packet_len) {
        Ok(permit) => permit,
        Err(IngressRedirectError::QueueFull) => {
            inner.session.metrics.record_queue_drop();
            increment(&inner.metrics.queue_drops);
            commit_and_send_receipt(inner, reservation, IngressRedirectReceiptCode::QueueFull)
                .await;
            return;
        }
        Err(_) => return,
    };
    let delivery_permit = match inner.delivery.clone().try_reserve_owned() {
        Ok(permit) => permit,
        Err(_) => {
            drop(permit);
            inner.session.metrics.record_queue_drop();
            increment(&inner.metrics.queue_drops);
            commit_and_send_receipt(inner, reservation, IngressRedirectReceiptCode::QueueFull)
                .await;
            return;
        }
    };
    let code = match inner
        .session
        .validate_delivery_evidence(&data, &inner.ownership)
    {
        Ok(_) => IngressRedirectReceiptCode::Delivered,
        Err(error) => {
            let Some(code) = receipt_code_for_delivery_error(error) else {
                return;
            };
            code
        }
    };
    let receipt = match inner.session.seal_receipt_for_cache(
        IngressRedirectProtectionEpoch(identity.epoch),
        identity.sequence,
        code,
    ) {
        Ok(receipt) => receipt,
        Err(_) => return,
    };
    let valid_until = match cache_receipt(inner, reservation, &receipt) {
        Ok(valid_until) => valid_until,
        Err(_) => return,
    };
    let _delivery = delivery_permit.send(DeliveryEnvelope {
        data,
        committed_code: code,
        valid_until,
        _permit: permit,
    });
    if code == IngressRedirectReceiptCode::Delivered {
        inner.session.metrics.record_delivery_admitted();
        increment(&inner.metrics.delivery_admissions);
    }
    if send_datagram_bounded(
        inner.datagram.as_ref(),
        receipt.bytes.as_ref(),
        inner.session.profile().receipt_timeout(),
    )
    .await
    .is_err()
    {
        increment(&inner.metrics.transport_drops);
    }
}

async fn commit_and_send_receipt<C>(
    inner: &Arc<EndpointInner<C>>,
    reservation: ReceiptCacheReservation,
    code: IngressRedirectReceiptCode,
) where
    C: Clock + 'static,
{
    let identity = reservation.identity();
    let Ok(receipt) = inner.session.seal_receipt_for_cache(
        IngressRedirectProtectionEpoch(identity.epoch),
        identity.sequence,
        code,
    ) else {
        return;
    };
    if cache_receipt(inner, reservation, &receipt).is_err() {
        return;
    }
    if send_datagram_bounded(
        inner.datagram.as_ref(),
        receipt.bytes.as_ref(),
        inner.session.profile().receipt_timeout(),
    )
    .await
    .is_err()
    {
        increment(&inner.metrics.transport_drops);
    }
}

fn cache_receipt<C>(
    inner: &EndpointInner<C>,
    reservation: ReceiptCacheReservation,
    receipt: &SealedIngressRedirectFrame,
) -> Result<Instant, IngressRedirectError>
where
    C: Clock + 'static,
{
    let committed = (|| {
        let identity = reservation.identity();
        let now = Instant::now();
        let cache = inner
            .receipt_cache
            .lock()
            .map_err(|_| IngressRedirectError::StateUnavailable)?;
        let data_epoch_valid_until = inner
            .session
            .receive_epoch_valid_until(identity.epoch, now)?;
        let receipt_epoch_valid_until = inner
            .session
            .receive_epoch_valid_until(receipt.epoch.get(), now)?
            .min(receipt.valid_until);
        let expires_at = cache.expiry(now, data_epoch_valid_until, receipt_epoch_valid_until)?;
        drop(cache);
        reservation.commit(
            Arc::clone(&receipt.bytes),
            identity.epoch,
            receipt.epoch.get(),
            expires_at,
        )?;
        Ok(data_epoch_valid_until)
    })();
    if committed.is_err() {
        increment(&inner.metrics.receipt_cache_commit_failures);
    }
    committed
}

fn delivery_error_is_forwardable(error: IngressRedirectError) -> bool {
    matches!(
        error,
        IngressRedirectError::NotOwner
            | IngressRedirectError::OwnershipMissing
            | IngressRedirectError::OwnershipViewStale
            | IngressRedirectError::UnprovenOwnershipGeneration
    )
}

fn receipt_code_for_delivery_error(
    error: IngressRedirectError,
) -> Option<IngressRedirectReceiptCode> {
    match error {
        IngressRedirectError::NotOwner => Some(IngressRedirectReceiptCode::NotOwner),
        IngressRedirectError::StaleOwnershipGeneration => {
            Some(IngressRedirectReceiptCode::StaleOwnershipGeneration)
        }
        IngressRedirectError::OwnershipViewStale => {
            Some(IngressRedirectReceiptCode::OwnershipViewStale)
        }
        IngressRedirectError::QueueFull => Some(IngressRedirectReceiptCode::QueueFull),
        IngressRedirectError::HopLimitReached => Some(IngressRedirectReceiptCode::HopLimitReached),
        IngressRedirectError::ClassificationMismatch => {
            Some(IngressRedirectReceiptCode::ClassificationMismatch)
        }
        IngressRedirectError::OwnershipMissing => {
            Some(IngressRedirectReceiptCode::OwnershipMissing)
        }
        IngressRedirectError::UnprovenOwnershipGeneration => {
            Some(IngressRedirectReceiptCode::ReceiverViewBehind)
        }
        IngressRedirectError::RoutingDomainNotAuthorized => {
            Some(IngressRedirectReceiptCode::RoutingDomainNotAuthorized)
        }
        _ => None,
    }
}

async fn send_datagram_bounded(
    datagram: &dyn IngressRedirectDatagram,
    frame: &[u8],
    deadline: Duration,
) -> Result<(), IngressRedirectDatagramError> {
    tokio::time::timeout(deadline, datagram.send(frame))
        .await
        .map_err(|_| IngressRedirectDatagramError::TimedOut)?
}

fn resolve_all_pending(
    pending: &Mutex<BTreeMap<FrameIdentity, PendingReceipt>>,
    error: IngressRedirectError,
) {
    let senders = pending
        .lock()
        .map(|mut pending| {
            std::mem::take(&mut *pending)
                .into_values()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    for pending in senders {
        let _ = pending.result.send(Err(error));
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    use opc_session_store::{
        Clock, FakeSessionBackend, FencedOwnershipCacheConfig, FencedOwnershipCacheSeed,
        FencedOwnershipError, FencedOwnershipKey, FencedOwnershipMetadata,
        FencedOwnershipMutationId, FencedOwnershipNamespace, FencedOwnershipRecord,
        FencedOwnershipStore, OwnerId, TokioVirtualClock,
    };
    use opc_types::{NetworkFunctionKind, TenantId, Timestamp};

    use super::*;
    use crate::{DestinationContext, EspEncapsulationKind, EspOwnershipKey, EspSpi, IpAddress};

    fn owner(value: &str) -> OwnerId {
        OwnerId::new(value).unwrap_or_else(|error| panic!("valid test owner: {error}"))
    }

    fn test_profile() -> super::super::IngressRedirectProfile {
        super::super::IngressRedirectProfile::production(1_500)
            .and_then(|profile| profile.with_rotation_overlap(Duration::from_secs(5)))
            .and_then(|profile| profile.with_receipt_policy(Duration::from_millis(10), 2))
            .unwrap_or_else(|error| panic!("valid test profile: {error}"))
    }

    #[derive(Debug, Clone)]
    struct ManualClock {
        now: Arc<Mutex<Timestamp>>,
    }

    impl ManualClock {
        fn new() -> Self {
            Self {
                now: Arc::new(Mutex::new(Timestamp::now_utc())),
            }
        }

        fn advance(&self, duration: time::Duration) {
            let mut now = self
                .now
                .lock()
                .unwrap_or_else(|error| panic!("manual clock lock: {error}"));
            let advanced = now
                .as_offset_datetime()
                .checked_add(duration)
                .unwrap_or_else(|| panic!("representable manual clock advance"));
            *now = Timestamp::from_offset_datetime(advanced);
        }
    }

    impl Clock for ManualClock {
        fn now_utc(&self) -> Timestamp {
            *self
                .now
                .lock()
                .unwrap_or_else(|error| panic!("manual clock lock: {error}"))
        }
    }

    fn ownership_key() -> SessionOwnershipKey {
        SessionOwnershipKey::Esp(EspOwnershipKey::new(
            DestinationContext::new(IpAddress::V4([192, 0, 2, 10]), RoutingDomainTag::new(7)),
            EspEncapsulationKind::Native,
            EspSpi::new(0x0102_0304).unwrap_or_else(|error| panic!("valid SPI: {error}")),
        ))
    }

    fn synthetic_native_esp_packet(length: usize) -> Vec<u8> {
        assert!((28..=usize::from(u16::MAX)).contains(&length));
        let mut packet = vec![0x5a_u8; length];
        packet[0] = 0x45;
        packet[1] = 0;
        packet[2..4].copy_from_slice(&(length as u16).to_be_bytes());
        packet[4..8].fill(0);
        packet[8] = 64;
        packet[9] = 50;
        packet[10..12].fill(0);
        packet[12..16].copy_from_slice(&[198, 51, 100, 7]);
        packet[16..20].copy_from_slice(&[192, 0, 2, 10]);
        packet[20..24].copy_from_slice(&0x0102_0304_u32.to_be_bytes());
        packet[24..28].copy_from_slice(&1_u32.to_be_bytes());
        packet
    }

    fn test_sessions(
        profile: super::super::IngressRedirectProfile,
    ) -> (
        Arc<IngressRedirectPeerSession>,
        Arc<IngressRedirectPeerSession>,
    ) {
        let first_endpoint: SocketAddr = "127.0.0.1:32001"
            .parse()
            .unwrap_or_else(|error| panic!("valid endpoint: {error}"));
        let second_endpoint: SocketAddr = "127.0.0.1:32002"
            .parse()
            .unwrap_or_else(|error| panic!("valid endpoint: {error}"));
        let first_digest = super::super::sender_identity_digest("spiffe://example.test/a");
        let second_digest = super::super::sender_identity_digest("spiffe://example.test/b");
        let first_to_second = [0x11; 32];
        let second_to_first = [0x22; 32];
        let mut first = IngressRedirectPeerSession::for_test(
            profile,
            owner("owner-a"),
            owner("owner-b"),
            9,
            first_to_second,
            second_to_first,
            [1, 2, 3, 4],
            [5, 6, 7, 8],
            first_digest,
            second_digest,
        );
        first.local_udp_endpoint = first_endpoint;
        first.peer_udp_endpoint = second_endpoint;
        let mut second = IngressRedirectPeerSession::for_test(
            profile,
            owner("owner-b"),
            owner("owner-a"),
            9,
            second_to_first,
            first_to_second,
            [5, 6, 7, 8],
            [1, 2, 3, 4],
            second_digest,
            first_digest,
        );
        second.local_udp_endpoint = second_endpoint;
        second.peer_udp_endpoint = first_endpoint;
        (Arc::new(first), Arc::new(second))
    }

    async fn ownership_record(
        claimed_owner: &str,
    ) -> (
        FencedOwnershipRecord,
        FencedOwnershipNamespace,
        TokioVirtualClock,
    ) {
        let namespace = FencedOwnershipNamespace::new(
            TenantId::new("redirect-transport-tests")
                .unwrap_or_else(|error| panic!("valid tenant: {error}")),
            NetworkFunctionKind::new("epdg")
                .unwrap_or_else(|error| panic!("valid NF kind: {error}")),
        );
        let clock = TokioVirtualClock::new();
        let store =
            FencedOwnershipStore::new(FakeSessionBackend::new(), namespace.clone(), clock.clone());
        let key = FencedOwnershipKey::new(ownership_key().to_canonical_bytes())
            .unwrap_or_else(|error| panic!("valid ownership key: {error}"));
        let record = store
            .claim(
                FencedOwnershipMutationId::from_bytes([7; 16]),
                key,
                owner(claimed_owner),
                Duration::from_secs(60),
                FencedOwnershipMetadata::empty(),
            )
            .await
            .unwrap_or_else(|error| panic!("claim ownership: {error}"))
            .into_inner();
        (record, namespace, clock)
    }

    async fn two_ownership_generations(
        claimed_owner: &str,
    ) -> (
        FencedOwnershipRecord,
        FencedOwnershipRecord,
        FencedOwnershipNamespace,
        TokioVirtualClock,
    ) {
        let namespace = FencedOwnershipNamespace::new(
            TenantId::new("redirect-transport-generation-tests")
                .unwrap_or_else(|error| panic!("valid tenant: {error}")),
            NetworkFunctionKind::new("epdg")
                .unwrap_or_else(|error| panic!("valid NF kind: {error}")),
        );
        let clock = TokioVirtualClock::new();
        let store =
            FencedOwnershipStore::new(FakeSessionBackend::new(), namespace.clone(), clock.clone());
        let key = FencedOwnershipKey::new(ownership_key().to_canonical_bytes())
            .unwrap_or_else(|error| panic!("valid ownership key: {error}"));
        let first = store
            .claim(
                FencedOwnershipMutationId::from_bytes([8; 16]),
                key,
                owner(claimed_owner),
                Duration::from_secs(60),
                FencedOwnershipMetadata::empty(),
            )
            .await
            .unwrap_or_else(|error| panic!("claim first ownership generation: {error}"))
            .into_inner();
        let token = first.fence_token();
        let second = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match store
                    .renew(
                        FencedOwnershipMutationId::from_bytes([9; 16]),
                        &token,
                        Duration::from_secs(60),
                    )
                    .await
                {
                    Ok(record) => break record.into_inner(),
                    Err(FencedOwnershipError::Contended) => tokio::task::yield_now().await,
                    Err(error) => panic!("renew ownership generation: {error}"),
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("ownership generation renewal completed"));
        assert!(second.generation() > first.generation());
        (first, second, namespace, clock)
    }

    fn ownership_cache(
        record: FencedOwnershipRecord,
        namespace: FencedOwnershipNamespace,
        clock: TokioVirtualClock,
    ) -> Arc<FencedOwnershipCache<TokioVirtualClock>> {
        let cache = FencedOwnershipCache::new(
            namespace.clone(),
            clock.clone(),
            FencedOwnershipCacheConfig {
                max_staleness: Duration::from_secs(30),
                max_entries: 8,
                max_retained_bytes: 8 * 1_024,
            },
        )
        .unwrap_or_else(|error| panic!("construct ownership cache: {error}"));
        let seed = FencedOwnershipCacheSeed::from_caller_proven_snapshot(
            namespace,
            [record],
            0,
            clock.now_utc(),
        )
        .unwrap_or_else(|error| panic!("construct coherent seed: {error}"));
        cache
            .seed(seed)
            .unwrap_or_else(|error| panic!("seed ownership cache: {error}"));
        Arc::new(cache)
    }

    fn ownership_cache_with_manual_clock(
        record: FencedOwnershipRecord,
        namespace: FencedOwnershipNamespace,
        clock: ManualClock,
        max_staleness: Duration,
    ) -> Arc<FencedOwnershipCache<ManualClock>> {
        let cache = FencedOwnershipCache::new(
            namespace.clone(),
            clock.clone(),
            FencedOwnershipCacheConfig {
                max_staleness,
                max_entries: 8,
                max_retained_bytes: 8 * 1_024,
            },
        )
        .unwrap_or_else(|error| panic!("construct manual-clock ownership cache: {error}"));
        let seed = FencedOwnershipCacheSeed::from_caller_proven_snapshot(
            namespace,
            [record],
            0,
            clock.now_utc(),
        )
        .unwrap_or_else(|error| panic!("construct coherent manual-clock seed: {error}"));
        cache
            .seed(seed)
            .unwrap_or_else(|error| panic!("seed manual-clock ownership cache: {error}"));
        Arc::new(cache)
    }

    #[derive(Default)]
    struct RecordingReporter {
        calls: AtomicUsize,
        packet_len: AtomicUsize,
        maximum: AtomicUsize,
    }

    impl fmt::Debug for RecordingReporter {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("RecordingReporter")
                .finish_non_exhaustive()
        }
    }

    #[async_trait]
    impl IngressRedirectPacketTooBigReporter for RecordingReporter {
        async fn report(
            &self,
            event: IngressRedirectPacketTooBigEvent<'_>,
        ) -> Result<(), IngressRedirectPacketTooBigReportError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.packet_len
                .store(event.packet().len(), Ordering::Relaxed);
            self.maximum
                .store(event.maximum_original_packet(), Ordering::Relaxed);
            Ok(())
        }
    }

    struct HangingReporter;

    impl fmt::Debug for HangingReporter {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("HangingReporter")
                .finish_non_exhaustive()
        }
    }

    #[async_trait]
    impl IngressRedirectPacketTooBigReporter for HangingReporter {
        async fn report(
            &self,
            _event: IngressRedirectPacketTooBigEvent<'_>,
        ) -> Result<(), IngressRedirectPacketTooBigReportError> {
            std::future::pending().await
        }
    }

    struct NeverSendDatagram {
        inner: Arc<InMemoryIngressRedirectDatagram>,
    }

    struct SendThenHangDatagram {
        inner: Arc<InMemoryIngressRedirectDatagram>,
    }

    struct LateReceiptBeforeRetryDatagram {
        inner: Arc<InMemoryIngressRedirectDatagram>,
        receipt: Mutex<
            Option<oneshot::Sender<Result<IngressRedirectReceiptCode, IngressRedirectError>>>,
        >,
        sends: AtomicUsize,
    }

    struct FailingSendDatagram {
        inner: Arc<InMemoryIngressRedirectDatagram>,
        error: IngressRedirectDatagramError,
        sends: AtomicUsize,
    }

    struct ShrinkingSendDatagram {
        inner: Arc<InMemoryIngressRedirectDatagram>,
        ceiling: AtomicUsize,
        shrunk_ceiling: usize,
        fail_next: AtomicBool,
    }

    struct ScriptedSendDatagram {
        inner: Arc<InMemoryIngressRedirectDatagram>,
        errors: Mutex<VecDeque<IngressRedirectDatagramError>>,
        sends: AtomicUsize,
    }

    impl fmt::Debug for ScriptedSendDatagram {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("ScriptedSendDatagram")
                .field("frames", &"[redacted]")
                .finish_non_exhaustive()
        }
    }

    #[async_trait]
    impl IngressRedirectDatagram for ScriptedSendDatagram {
        async fn send(&self, _datagram: &[u8]) -> Result<(), IngressRedirectDatagramError> {
            self.sends.fetch_add(1, Ordering::Relaxed);
            self.errors
                .lock()
                .map_err(|_| IngressRedirectDatagramError::Io)?
                .pop_front()
                .map_or(Err(IngressRedirectDatagramError::Closed), Err)
        }

        async fn receive(&self) -> Result<Vec<u8>, IngressRedirectDatagramError> {
            self.inner.receive().await
        }

        fn local_endpoint(&self) -> SocketAddr {
            self.inner.local_endpoint()
        }

        fn peer_endpoint(&self) -> SocketAddr {
            self.inner.peer_endpoint()
        }

        fn maximum_receive_datagram_size(&self) -> usize {
            self.inner.maximum_receive_datagram_size()
        }
    }

    struct FailingReceiveDatagram {
        inner: Arc<InMemoryIngressRedirectDatagram>,
    }

    impl fmt::Debug for FailingReceiveDatagram {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("FailingReceiveDatagram")
                .finish_non_exhaustive()
        }
    }

    #[async_trait]
    impl IngressRedirectDatagram for FailingReceiveDatagram {
        async fn send(&self, datagram: &[u8]) -> Result<(), IngressRedirectDatagramError> {
            self.inner.send(datagram).await
        }

        async fn receive(&self) -> Result<Vec<u8>, IngressRedirectDatagramError> {
            Err(IngressRedirectDatagramError::Io)
        }

        fn local_endpoint(&self) -> SocketAddr {
            self.inner.local_endpoint()
        }

        fn peer_endpoint(&self) -> SocketAddr {
            self.inner.peer_endpoint()
        }

        fn maximum_receive_datagram_size(&self) -> usize {
            self.inner.maximum_receive_datagram_size()
        }
    }

    impl fmt::Debug for ShrinkingSendDatagram {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("ShrinkingSendDatagram")
                .field("ceiling", &self.ceiling.load(Ordering::Relaxed))
                .field("frames", &"[redacted]")
                .finish_non_exhaustive()
        }
    }

    #[async_trait]
    impl IngressRedirectDatagram for ShrinkingSendDatagram {
        async fn send(&self, _datagram: &[u8]) -> Result<(), IngressRedirectDatagramError> {
            if self.fail_next.swap(false, Ordering::AcqRel) {
                self.ceiling.store(self.shrunk_ceiling, Ordering::Release);
                let effective_path_mtu = u16::try_from(
                    self.shrunk_ceiling + super::super::IPV4_HEADER_BYTES + UDP_HEADER_BYTES,
                )
                .unwrap_or(0);
                return Err(IngressRedirectDatagramError::PathMtuExceeded {
                    maximum_datagram_size: self.shrunk_ceiling,
                    effective_path_mtu,
                });
            }
            Err(IngressRedirectDatagramError::DatagramTooLarge)
        }

        async fn receive(&self) -> Result<Vec<u8>, IngressRedirectDatagramError> {
            self.inner.receive().await
        }

        fn local_endpoint(&self) -> SocketAddr {
            self.inner.local_endpoint()
        }

        fn peer_endpoint(&self) -> SocketAddr {
            self.inner.peer_endpoint()
        }

        fn maximum_receive_datagram_size(&self) -> usize {
            self.inner.maximum_receive_datagram_size()
        }

        fn maximum_send_datagram_size(&self) -> usize {
            self.ceiling.load(Ordering::Acquire)
        }
    }

    impl fmt::Debug for FailingSendDatagram {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("FailingSendDatagram")
                .field("error", &self.error)
                .field("frames", &"[redacted]")
                .finish_non_exhaustive()
        }
    }

    #[async_trait]
    impl IngressRedirectDatagram for FailingSendDatagram {
        async fn send(&self, _datagram: &[u8]) -> Result<(), IngressRedirectDatagramError> {
            self.sends.fetch_add(1, Ordering::Relaxed);
            Err(self.error)
        }

        async fn receive(&self) -> Result<Vec<u8>, IngressRedirectDatagramError> {
            self.inner.receive().await
        }

        fn local_endpoint(&self) -> SocketAddr {
            self.inner.local_endpoint()
        }

        fn peer_endpoint(&self) -> SocketAddr {
            self.inner.peer_endpoint()
        }

        fn maximum_receive_datagram_size(&self) -> usize {
            self.inner.maximum_receive_datagram_size()
        }
    }

    impl fmt::Debug for SendThenHangDatagram {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("SendThenHangDatagram")
                .field("frames", &"[redacted]")
                .finish_non_exhaustive()
        }
    }

    impl fmt::Debug for LateReceiptBeforeRetryDatagram {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("LateReceiptBeforeRetryDatagram")
                .field("frames", &"[redacted]")
                .finish_non_exhaustive()
        }
    }

    #[async_trait]
    impl IngressRedirectDatagram for LateReceiptBeforeRetryDatagram {
        async fn send(&self, _datagram: &[u8]) -> Result<(), IngressRedirectDatagramError> {
            self.sends.fetch_add(1, Ordering::Relaxed);
            let mut first_poll = true;
            std::future::poll_fn(|_context| {
                if first_poll {
                    first_poll = false;
                    return std::task::Poll::Pending;
                }
                if let Some(receipt) = self
                    .receipt
                    .lock()
                    .ok()
                    .and_then(|mut receipt| receipt.take())
                {
                    let _ = receipt.send(Ok(IngressRedirectReceiptCode::Delivered));
                }
                std::task::Poll::Pending
            })
            .await
        }

        async fn receive(&self) -> Result<Vec<u8>, IngressRedirectDatagramError> {
            self.inner.receive().await
        }

        fn local_endpoint(&self) -> SocketAddr {
            self.inner.local_endpoint()
        }

        fn peer_endpoint(&self) -> SocketAddr {
            self.inner.peer_endpoint()
        }

        fn maximum_receive_datagram_size(&self) -> usize {
            self.inner.maximum_receive_datagram_size()
        }
    }

    #[async_trait]
    impl IngressRedirectDatagram for SendThenHangDatagram {
        async fn send(&self, datagram: &[u8]) -> Result<(), IngressRedirectDatagramError> {
            self.inner.send(datagram).await?;
            std::future::pending().await
        }

        async fn receive(&self) -> Result<Vec<u8>, IngressRedirectDatagramError> {
            self.inner.receive().await
        }

        fn local_endpoint(&self) -> SocketAddr {
            self.inner.local_endpoint()
        }

        fn peer_endpoint(&self) -> SocketAddr {
            self.inner.peer_endpoint()
        }

        fn maximum_receive_datagram_size(&self) -> usize {
            self.inner.maximum_receive_datagram_size()
        }
    }

    impl fmt::Debug for NeverSendDatagram {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("NeverSendDatagram")
                .field("frames", &"[redacted]")
                .finish_non_exhaustive()
        }
    }

    #[async_trait]
    impl IngressRedirectDatagram for NeverSendDatagram {
        async fn send(&self, _datagram: &[u8]) -> Result<(), IngressRedirectDatagramError> {
            std::future::pending().await
        }

        async fn receive(&self) -> Result<Vec<u8>, IngressRedirectDatagramError> {
            self.inner.receive().await
        }

        fn local_endpoint(&self) -> SocketAddr {
            self.inner.local_endpoint()
        }

        fn peer_endpoint(&self) -> SocketAddr {
            self.inner.peer_endpoint()
        }

        fn maximum_receive_datagram_size(&self) -> usize {
            self.inner.maximum_receive_datagram_size()
        }
    }

    struct DropFirstReceiptDatagram {
        inner: Arc<InMemoryIngressRedirectDatagram>,
        dropped: AtomicBool,
        first_receipt: Mutex<Option<Vec<u8>>>,
        replay_was_exact: AtomicBool,
        first_data: Mutex<Option<Vec<u8>>>,
    }

    impl DropFirstReceiptDatagram {
        fn new(inner: Arc<InMemoryIngressRedirectDatagram>) -> Self {
            Self {
                inner,
                dropped: AtomicBool::new(false),
                first_receipt: Mutex::new(None),
                replay_was_exact: AtomicBool::new(false),
                first_data: Mutex::new(None),
            }
        }
    }

    impl fmt::Debug for DropFirstReceiptDatagram {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("DropFirstReceiptDatagram")
                .field("frames", &"[redacted]")
                .finish_non_exhaustive()
        }
    }

    #[async_trait]
    impl IngressRedirectDatagram for DropFirstReceiptDatagram {
        async fn send(&self, datagram: &[u8]) -> Result<(), IngressRedirectDatagramError> {
            let is_receipt = IngressRedirectFrameHeader::decode(datagram)
                .is_ok_and(|header| header.kind() == IngressRedirectFrameKind::Receipt);
            if is_receipt && !self.dropped.swap(true, Ordering::Relaxed) {
                if let Ok(mut receipt) = self.first_receipt.lock() {
                    *receipt = Some(datagram.to_vec());
                }
                return Ok(());
            }
            if is_receipt {
                let exact = self
                    .first_receipt
                    .lock()
                    .ok()
                    .and_then(|receipt| receipt.as_ref().map(|first| first == datagram))
                    .unwrap_or(false);
                self.replay_was_exact.store(exact, Ordering::Relaxed);
            }
            self.inner.send(datagram).await
        }

        async fn receive(&self) -> Result<Vec<u8>, IngressRedirectDatagramError> {
            let datagram = self.inner.receive().await?;
            if IngressRedirectFrameHeader::decode(&datagram)
                .is_ok_and(|header| header.kind() == IngressRedirectFrameKind::Data)
            {
                if let Ok(mut first_data) = self.first_data.lock() {
                    if first_data.is_none() {
                        *first_data = Some(datagram.clone());
                    }
                }
            }
            Ok(datagram)
        }

        fn local_endpoint(&self) -> SocketAddr {
            self.inner.local_endpoint()
        }

        fn peer_endpoint(&self) -> SocketAddr {
            self.inner.peer_endpoint()
        }

        fn maximum_receive_datagram_size(&self) -> usize {
            self.inner.maximum_receive_datagram_size()
        }
    }

    #[tokio::test]
    async fn maximum_mtu_round_trip_preserves_exact_packet_once() {
        let profile = test_profile();
        let (first_session, second_session) = test_sessions(profile);
        let (record, namespace, clock) = ownership_record("owner-b").await;
        let generation = record.generation();
        let first_cache = ownership_cache(record.clone(), namespace.clone(), clock.clone());
        let second_cache = ownership_cache(record, namespace, clock);
        let (first_datagram, second_datagram) = InMemoryIngressRedirectDatagram::pair(
            first_session.local_udp_endpoint(),
            second_session.local_udp_endpoint(),
            profile.steering_path_mtu(),
            profile.queue_packets(),
        )
        .unwrap_or_else(|error| panic!("in-memory pair: {error}"));
        let reporter = Arc::new(RecordingReporter::default());
        let (first, _first_rx) = IngressRedirectEndpoint::start(
            Arc::clone(&first_session),
            first_cache,
            Arc::new(first_datagram),
            reporter.clone(),
        )
        .unwrap_or_else(|error| panic!("start first: {error}"));
        let (second, mut second_rx) = IngressRedirectEndpoint::start(
            Arc::clone(&second_session),
            second_cache,
            Arc::new(second_datagram),
            reporter,
        )
        .unwrap_or_else(|error| panic!("start second: {error}"));
        let budget = IngressRedirectMtuBudget::new(
            profile,
            second_session.local_udp_endpoint().ip(),
            ownership_key().to_canonical_bytes().len(),
        )
        .unwrap_or_else(|error| panic!("MTU budget: {error}"));
        let packet = synthetic_native_esp_packet(budget.maximum_original_packet());
        assert_eq!(
            first.redirect(&packet, ownership_key(), generation).await,
            Ok(IngressRedirectReceiptCode::Delivered)
        );
        let outcome = second_rx
            .receive()
            .await
            .unwrap_or_else(|error| panic!("receive exact packet: {error}"));
        let IngressRedirectInboundOutcome::Delivered(delivered) = outcome else {
            panic!("expected delivered outcome")
        };
        assert_eq!(delivered.packet(), packet);
        assert_eq!(second_session.metrics().delivered, 1);
        assert_eq!(first.metrics().delivery_receipts, 1);
        first
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown first: {error}"));
        second
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown second: {error}"));
    }

    #[tokio::test]
    async fn superseded_generation_precedes_owner_mismatch_with_exact_receipt() {
        let profile = test_profile();
        let (first_session, second_session) = test_sessions(profile);
        let (superseded, current, namespace, clock) = two_ownership_generations("owner-c").await;
        let first_cache = ownership_cache(current.clone(), namespace.clone(), clock.clone());
        let second_cache = ownership_cache(current, namespace, clock);
        let (first_datagram, second_datagram) = InMemoryIngressRedirectDatagram::pair(
            first_session.local_udp_endpoint(),
            second_session.local_udp_endpoint(),
            profile.steering_path_mtu(),
            profile.queue_packets(),
        )
        .unwrap_or_else(|error| panic!("in-memory pair: {error}"));
        let reporter = Arc::new(RecordingReporter::default());
        let (first, _first_rx) = IngressRedirectEndpoint::start(
            first_session,
            first_cache,
            Arc::new(first_datagram),
            reporter.clone(),
        )
        .unwrap_or_else(|error| panic!("start first: {error}"));
        let (second, mut second_rx) = IngressRedirectEndpoint::start(
            Arc::clone(&second_session),
            second_cache,
            Arc::new(second_datagram),
            reporter,
        )
        .unwrap_or_else(|error| panic!("start second: {error}"));
        let packet = synthetic_native_esp_packet(128);

        assert_eq!(
            first
                .redirect(&packet, ownership_key(), superseded.generation())
                .await,
            Ok(IngressRedirectReceiptCode::StaleOwnershipGeneration)
        );
        let IngressRedirectInboundOutcome::Rejected(rejected) = second_rx
            .receive()
            .await
            .unwrap_or_else(|error| panic!("receive stale-generation rejection: {error}"))
        else {
            panic!("stale generation must be terminal")
        };
        assert_eq!(
            rejected.receipt_code(),
            IngressRedirectReceiptCode::StaleOwnershipGeneration
        );
        assert_eq!(first.metrics().rejection_receipts, 1);
        assert_eq!(second_session.metrics().stale_generation_drops, 1);
        assert_eq!(second_session.metrics().receiver_view_behind_drops, 0);
        assert_eq!(second_session.metrics().not_owner_drops, 0);
        assert_eq!(second_session.metrics().delivered, 0);
        first
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown first: {error}"));
        second
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown second: {error}"));
    }

    #[tokio::test]
    async fn newer_sender_generation_is_forwardable_receiver_view_behind() {
        let profile = test_profile();
        let (first_session, second_session) = test_sessions(profile);
        let (committed, newer, namespace, clock) = two_ownership_generations("owner-b").await;
        let first_cache = ownership_cache(committed.clone(), namespace.clone(), clock.clone());
        let second_cache = ownership_cache(committed, namespace, clock);
        let (first_datagram, second_datagram) = InMemoryIngressRedirectDatagram::pair(
            first_session.local_udp_endpoint(),
            second_session.local_udp_endpoint(),
            profile.steering_path_mtu(),
            profile.queue_packets(),
        )
        .unwrap_or_else(|error| panic!("in-memory pair: {error}"));
        let reporter = Arc::new(RecordingReporter::default());
        let (first, _first_rx) = IngressRedirectEndpoint::start(
            first_session,
            first_cache,
            Arc::new(first_datagram),
            reporter.clone(),
        )
        .unwrap_or_else(|error| panic!("start first: {error}"));
        let (second, mut second_rx) = IngressRedirectEndpoint::start(
            Arc::clone(&second_session),
            second_cache,
            Arc::new(second_datagram),
            reporter,
        )
        .unwrap_or_else(|error| panic!("start second: {error}"));
        let packet = synthetic_native_esp_packet(128);

        assert_eq!(
            first
                .redirect(&packet, ownership_key(), newer.generation())
                .await,
            Ok(IngressRedirectReceiptCode::ReceiverViewBehind)
        );
        let IngressRedirectInboundOutcome::Forwardable(forwardable) = second_rx
            .receive()
            .await
            .unwrap_or_else(|error| panic!("receive view-behind outcome: {error}"))
        else {
            panic!("a newer sender generation must remain forwardable")
        };
        assert_eq!(
            forwardable.receipt_code(),
            IngressRedirectReceiptCode::ReceiverViewBehind
        );
        assert_eq!(forwardable.packet(), packet);
        assert_eq!(forwardable.ownership_key(), ownership_key());
        assert_eq!(second_session.metrics().receiver_view_behind_drops, 1);
        assert_eq!(second_session.metrics().delivered, 0);
        first
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown first: {error}"));
        second
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown second: {error}"));
    }

    #[tokio::test]
    async fn stale_committed_view_is_forwardable_with_exact_receipt_and_counter() {
        let profile = test_profile();
        let (first_session, second_session) = test_sessions(profile);
        let (record, namespace, clock) = ownership_record("owner-b").await;
        let generation = record.generation();
        let first_cache = ownership_cache(record.clone(), namespace.clone(), clock);
        let manual_clock = ManualClock::new();
        let second_cache = ownership_cache_with_manual_clock(
            record,
            namespace,
            manual_clock.clone(),
            Duration::from_secs(5),
        );
        manual_clock.advance(time::Duration::seconds(6));
        let (first_datagram, second_datagram) = InMemoryIngressRedirectDatagram::pair(
            first_session.local_udp_endpoint(),
            second_session.local_udp_endpoint(),
            profile.steering_path_mtu(),
            profile.queue_packets(),
        )
        .unwrap_or_else(|error| panic!("in-memory pair: {error}"));
        let reporter = Arc::new(RecordingReporter::default());
        let (first, _first_rx) = IngressRedirectEndpoint::start(
            first_session,
            first_cache,
            Arc::new(first_datagram),
            reporter.clone(),
        )
        .unwrap_or_else(|error| panic!("start first: {error}"));
        let (second, mut second_rx) = IngressRedirectEndpoint::start(
            Arc::clone(&second_session),
            second_cache,
            Arc::new(second_datagram),
            reporter,
        )
        .unwrap_or_else(|error| panic!("start second: {error}"));
        let packet = synthetic_native_esp_packet(128);

        assert_eq!(
            first.redirect(&packet, ownership_key(), generation).await,
            Ok(IngressRedirectReceiptCode::OwnershipViewStale)
        );
        let IngressRedirectInboundOutcome::Forwardable(forwardable) = second_rx
            .receive()
            .await
            .unwrap_or_else(|error| panic!("receive stale-view outcome: {error}"))
        else {
            panic!("stale ownership evidence must remain forwardable")
        };
        assert_eq!(
            forwardable.receipt_code(),
            IngressRedirectReceiptCode::OwnershipViewStale
        );
        assert_eq!(second_session.metrics().ownership_view_stale_drops, 1);
        assert_eq!(second_session.metrics().delivered, 0);
        first
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown first: {error}"));
        second
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown second: {error}"));
    }

    #[tokio::test]
    async fn dequeue_revalidates_exact_ownership_and_rejects_expired_capability() {
        let profile = test_profile();
        let (first_session, second_session) = test_sessions(profile);
        let (record, namespace, clock) = ownership_record("owner-b").await;
        let generation = record.generation();
        let first_cache = ownership_cache(record.clone(), namespace.clone(), clock);
        let manual_clock = ManualClock::new();
        let second_cache = ownership_cache_with_manual_clock(
            record,
            namespace,
            manual_clock.clone(),
            Duration::from_secs(5),
        );
        let (first_datagram, second_datagram) = InMemoryIngressRedirectDatagram::pair(
            first_session.local_udp_endpoint(),
            second_session.local_udp_endpoint(),
            profile.steering_path_mtu(),
            profile.queue_packets(),
        )
        .unwrap_or_else(|error| panic!("in-memory pair: {error}"));
        let reporter = Arc::new(RecordingReporter::default());
        let (first, _first_rx) = IngressRedirectEndpoint::start(
            first_session,
            first_cache,
            Arc::new(first_datagram),
            reporter.clone(),
        )
        .unwrap_or_else(|error| panic!("start first: {error}"));
        let (second, mut second_rx) = IngressRedirectEndpoint::start(
            Arc::clone(&second_session),
            second_cache,
            Arc::new(second_datagram),
            reporter,
        )
        .unwrap_or_else(|error| panic!("start second: {error}"));
        let packet = synthetic_native_esp_packet(128);
        assert_eq!(
            first.redirect(&packet, ownership_key(), generation).await,
            Ok(IngressRedirectReceiptCode::Delivered)
        );
        manual_clock.advance(time::Duration::seconds(6));
        assert!(matches!(
            second_rx.receive().await,
            Err(IngressRedirectError::DeliveryCapabilityStale)
        ));
        let metrics = second_session.metrics();
        assert_eq!(metrics.delivery_admissions, 1);
        assert_eq!(metrics.delivery_capability_stale_drops, 1);
        assert_eq!(metrics.delivered, 0);
        first
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown first: {error}"));
        second
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown second: {error}"));
    }

    #[tokio::test]
    async fn classification_mismatch_is_terminal_and_never_counted_delivered() {
        let profile = test_profile();
        let (first_session, second_session) = test_sessions(profile);
        let (record, namespace, clock) = ownership_record("owner-b").await;
        let generation = record.generation();
        let first_cache = ownership_cache(record.clone(), namespace.clone(), clock.clone());
        let second_cache = ownership_cache(record, namespace, clock);
        let (first_datagram, second_datagram) = InMemoryIngressRedirectDatagram::pair(
            first_session.local_udp_endpoint(),
            second_session.local_udp_endpoint(),
            profile.steering_path_mtu(),
            profile.queue_packets(),
        )
        .unwrap_or_else(|error| panic!("in-memory pair: {error}"));
        let reporter = Arc::new(RecordingReporter::default());
        let (first, _first_rx) = IngressRedirectEndpoint::start(
            first_session,
            first_cache,
            Arc::new(first_datagram),
            reporter.clone(),
        )
        .unwrap_or_else(|error| panic!("start first: {error}"));
        let (second, mut second_rx) = IngressRedirectEndpoint::start(
            Arc::clone(&second_session),
            second_cache,
            Arc::new(second_datagram),
            reporter,
        )
        .unwrap_or_else(|error| panic!("start second: {error}"));
        let mut mismatched_packet = synthetic_native_esp_packet(128);
        mismatched_packet[19] = 11;

        assert_eq!(
            first
                .redirect(&mismatched_packet, ownership_key(), generation)
                .await,
            Ok(IngressRedirectReceiptCode::ClassificationMismatch)
        );
        let IngressRedirectInboundOutcome::Rejected(rejected) = second_rx
            .receive()
            .await
            .unwrap_or_else(|error| panic!("receive classification rejection: {error}"))
        else {
            panic!("classification mismatch must be terminal")
        };
        assert_eq!(
            rejected.receipt_code(),
            IngressRedirectReceiptCode::ClassificationMismatch
        );
        assert_eq!(second_session.metrics().classification_drops, 1);
        assert_eq!(second_session.metrics().delivered, 0);
        first
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown first: {error}"));
        second
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown second: {error}"));
    }

    #[tokio::test]
    async fn unauthenticated_tamper_never_enters_the_delivery_queue() {
        let profile = test_profile();
        let (first_session, second_session) = test_sessions(profile);
        let (record, namespace, clock) = ownership_record("owner-b").await;
        let generation = record.generation();
        let second_cache = ownership_cache(record, namespace, clock);
        let (sender_datagram, second_datagram) = InMemoryIngressRedirectDatagram::pair(
            first_session.local_udp_endpoint(),
            second_session.local_udp_endpoint(),
            profile.steering_path_mtu(),
            profile.queue_packets(),
        )
        .unwrap_or_else(|error| panic!("in-memory pair: {error}"));
        let (second, mut second_rx) = IngressRedirectEndpoint::start(
            Arc::clone(&second_session),
            second_cache,
            Arc::new(second_datagram),
            Arc::new(RecordingReporter::default()),
        )
        .unwrap_or_else(|error| panic!("start second: {error}"));
        let packet = synthetic_native_esp_packet(128);
        let mut tampered = first_session
            .seal_data(&packet, ownership_key(), generation)
            .unwrap_or_else(|error| panic!("seal authenticated data: {error}"));
        let last = tampered
            .last_mut()
            .unwrap_or_else(|| panic!("sealed frame has authentication tag"));
        *last ^= 0x01;
        sender_datagram
            .send(&tampered)
            .await
            .unwrap_or_else(|error| panic!("inject tampered frame: {error}"));
        tokio::time::timeout(Duration::from_millis(100), async {
            while second_session.metrics().authentication_drops == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("tampered frame was processed"));
        assert!(
            tokio::time::timeout(Duration::from_millis(20), second_rx.receive())
                .await
                .is_err(),
            "unauthenticated data must not enter any delivery outcome queue"
        );
        assert_eq!(second_session.metrics().authentication_drops, 1);
        assert_eq!(second_session.metrics().delivered, 0);
        second
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown second: {error}"));
    }

    #[tokio::test]
    async fn lost_receipt_retries_exact_frame_and_delivers_once_then_expired_capture_replays() {
        let profile = test_profile();
        let (first_session, second_session) = test_sessions(profile);
        let (record, namespace, clock) = ownership_record("owner-b").await;
        let generation = record.generation();
        let first_cache = ownership_cache(record.clone(), namespace.clone(), clock.clone());
        let second_cache = ownership_cache(record, namespace, clock);
        let (first_datagram, second_datagram) = InMemoryIngressRedirectDatagram::pair(
            first_session.local_udp_endpoint(),
            second_session.local_udp_endpoint(),
            profile.steering_path_mtu(),
            profile.queue_packets(),
        )
        .unwrap_or_else(|error| panic!("in-memory pair: {error}"));
        let first_datagram = Arc::new(first_datagram);
        let second_wrapper = Arc::new(DropFirstReceiptDatagram::new(Arc::new(second_datagram)));
        let reporter = Arc::new(RecordingReporter::default());
        let (first, _first_rx) = IngressRedirectEndpoint::start(
            Arc::clone(&first_session),
            first_cache,
            first_datagram.clone(),
            reporter.clone(),
        )
        .unwrap_or_else(|error| panic!("start first: {error}"));
        let (second, mut second_rx) = IngressRedirectEndpoint::start(
            Arc::clone(&second_session),
            second_cache,
            second_wrapper.clone(),
            reporter,
        )
        .unwrap_or_else(|error| panic!("start second: {error}"));
        let packet = synthetic_native_esp_packet(128);
        assert_eq!(
            first.redirect(&packet, ownership_key(), generation).await,
            Ok(IngressRedirectReceiptCode::Delivered)
        );
        let outcome = second_rx
            .receive()
            .await
            .unwrap_or_else(|error| panic!("one delivery: {error}"));
        assert!(matches!(
            outcome,
            IngressRedirectInboundOutcome::Delivered(_)
        ));
        assert!(second_wrapper.replay_was_exact.load(Ordering::Relaxed));
        assert_eq!(second.metrics().cached_receipts_replayed, 1);
        assert_eq!(second_session.metrics().delivered, 1);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), second_rx.receive())
                .await
                .is_err()
        );

        let captured = second_wrapper
            .first_data
            .lock()
            .ok()
            .and_then(|frame| frame.clone())
            .unwrap_or_else(|| panic!("captured first data frame"));
        let header = IngressRedirectFrameHeader::decode(&captured)
            .unwrap_or_else(|error| panic!("captured header: {error}"));
        let identity = FrameIdentity {
            epoch: header.epoch(),
            sequence: header.sequence(),
        };
        let digest: [u8; 32] = Sha256::digest(&captured).into();
        {
            let mut cache = second
                .inner
                .receipt_cache
                .lock()
                .unwrap_or_else(|_| panic!("receipt cache"));
            let after_expiry = Instant::now()
                .checked_add(profile.rotation_overlap())
                .and_then(|instant| instant.checked_add(Duration::from_millis(1)))
                .unwrap_or_else(|| panic!("valid future instant"));
            assert!(cache
                .exact_receipt(identity, &digest, after_expiry)
                .is_none());
        }
        first_datagram
            .send(&captured)
            .await
            .unwrap_or_else(|error| panic!("inject captured replay: {error}"));
        tokio::time::timeout(Duration::from_millis(100), async {
            while second_session.metrics().replay_drops == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("captured replay processed"));
        assert_eq!(second_session.metrics().replay_drops, 1);
        assert_eq!(second_session.metrics().delivered, 1);
        first
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown first: {error}"));
        second
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown second: {error}"));
    }

    #[tokio::test]
    async fn dropping_observation_after_send_does_not_cancel_or_reseal_operation() {
        let profile = test_profile();
        let (first_session, second_session) = test_sessions(profile);
        let (record, namespace, clock) = ownership_record("owner-b").await;
        let generation = record.generation();
        let first_cache = ownership_cache(record.clone(), namespace.clone(), clock.clone());
        let second_cache = ownership_cache(record, namespace, clock);
        let (first_datagram, second_datagram) = InMemoryIngressRedirectDatagram::pair(
            first_session.local_udp_endpoint(),
            second_session.local_udp_endpoint(),
            profile.steering_path_mtu(),
            profile.queue_packets(),
        )
        .unwrap_or_else(|error| panic!("in-memory pair: {error}"));
        let second_datagram = Arc::new(DropFirstReceiptDatagram::new(Arc::new(second_datagram)));
        let reporter = Arc::new(RecordingReporter::default());
        let (first, _first_rx) = IngressRedirectEndpoint::start(
            first_session,
            first_cache,
            Arc::new(first_datagram),
            reporter.clone(),
        )
        .unwrap_or_else(|error| panic!("start first: {error}"));
        let (second, mut second_rx) =
            IngressRedirectEndpoint::start(second_session, second_cache, second_datagram, reporter)
                .unwrap_or_else(|error| panic!("start second: {error}"));
        let packet = synthetic_native_esp_packet(128);
        let operation = first
            .begin_redirect(&packet, ownership_key(), generation)
            .unwrap_or_else(|error| panic!("begin redirect: {error}"));
        assert!(matches!(
            second_rx.receive().await,
            Ok(IngressRedirectInboundOutcome::Delivered(_))
        ));
        drop(operation);
        tokio::time::timeout(Duration::from_millis(100), async {
            while first.metrics().delivery_receipts == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("endpoint-owned operation completed after observer drop"));
        assert_eq!(first.metrics().send_attempts, 2);
        assert_eq!(second.metrics().cached_receipts_replayed, 1);
        first
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown first: {error}"));
        second
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown second: {error}"));
    }

    #[tokio::test]
    async fn cached_receipt_never_outlives_acknowledged_epoch_authentication() {
        let profile = test_profile();
        let (first_session, mut second_session) = test_sessions(profile);
        let hard_deadline = Instant::now()
            .checked_add(Duration::from_millis(250))
            .unwrap_or_else(|| panic!("valid near expiry"));
        {
            let session = Arc::get_mut(&mut second_session)
                .unwrap_or_else(|| panic!("unshared second session"));
            let state = session
                .epochs
                .get_mut()
                .unwrap_or_else(|_| panic!("epoch state"));
            let epoch = Arc::get_mut(&mut state.current)
                .unwrap_or_else(|| panic!("unshared current epoch"));
            epoch.hard_authenticated_deadline = hard_deadline;
        }
        let (record, namespace, clock) = ownership_record("owner-b").await;
        let generation = record.generation();
        let first_cache = ownership_cache(record.clone(), namespace.clone(), clock.clone());
        let second_cache = ownership_cache(record, namespace, clock);
        let (first_datagram, second_datagram) = InMemoryIngressRedirectDatagram::pair(
            first_session.local_udp_endpoint(),
            second_session.local_udp_endpoint(),
            profile.steering_path_mtu(),
            profile.queue_packets(),
        )
        .unwrap_or_else(|error| panic!("in-memory pair: {error}"));
        let first_datagram = Arc::new(first_datagram);
        let second_wrapper = Arc::new(DropFirstReceiptDatagram::new(Arc::new(second_datagram)));
        second_wrapper.dropped.store(true, Ordering::Relaxed);
        let reporter = Arc::new(RecordingReporter::default());
        let (first, _first_rx) = IngressRedirectEndpoint::start(
            first_session,
            first_cache,
            first_datagram.clone(),
            reporter.clone(),
        )
        .unwrap_or_else(|error| panic!("start first: {error}"));
        let (second, mut second_rx) = IngressRedirectEndpoint::start(
            Arc::clone(&second_session),
            second_cache,
            second_wrapper.clone(),
            reporter,
        )
        .unwrap_or_else(|error| panic!("start second: {error}"));
        let packet = synthetic_native_esp_packet(128);
        assert_eq!(
            first.redirect(&packet, ownership_key(), generation).await,
            Ok(IngressRedirectReceiptCode::Delivered)
        );
        assert!(matches!(
            second_rx.receive().await,
            Ok(IngressRedirectInboundOutcome::Delivered(_))
        ));
        let captured = second_wrapper
            .first_data
            .lock()
            .ok()
            .and_then(|frame| frame.clone())
            .unwrap_or_else(|| panic!("captured authenticated data"));
        tokio::time::sleep_until(tokio::time::Instant::from_std(hard_deadline)).await;
        first_datagram
            .send(&captured)
            .await
            .unwrap_or_else(|error| panic!("inject post-expiry capture: {error}"));
        tokio::time::timeout(Duration::from_millis(100), async {
            while second_session.metrics().authentication_expired_drops == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("post-expiry frame processed"));
        assert_eq!(second.metrics().cached_receipts_replayed, 0);
        assert_eq!(second_session.metrics().authentication_expired_drops, 1);
        assert_eq!(second_session.metrics().delivered, 1);
        first
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown first: {error}"));
        second
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown second: {error}"));
    }

    #[test]
    fn receipt_cache_sheds_while_live_then_progresses_after_retry_horizon() {
        let lifetime = Duration::from_secs(5);
        let cache = Arc::new(Mutex::new(ReceiptCache::new(1, lifetime)));
        let now = Instant::now();
        let valid_until = now
            .checked_add(lifetime)
            .unwrap_or_else(|| panic!("valid cache deadline"));
        let first = FrameIdentity {
            epoch: 1,
            sequence: 1,
        };
        let second = FrameIdentity {
            epoch: 1,
            sequence: 2,
        };
        let first_reservation = ReceiptCache::reserve(&cache, first, [1; 32], now)
            .unwrap_or_else(|error| panic!("reserve first cache slot: {error}"))
            .unwrap_or_else(|| panic!("vacant first cache identity"));
        let first_expiry = cache
            .lock()
            .unwrap_or_else(|_| panic!("receipt cache lock"))
            .expiry(now, valid_until, valid_until)
            .unwrap_or_else(|error| panic!("first cache expiry: {error}"));
        first_reservation
            .commit(Arc::from([0x11_u8].as_slice()), 1, 2, first_expiry)
            .unwrap_or_else(|error| panic!("commit first cache slot: {error}"));
        assert!(matches!(
            ReceiptCache::reserve(&cache, second, [2; 32], now),
            Err(IngressRedirectError::QueueFull)
        ));
        let cached = cache
            .lock()
            .unwrap_or_else(|_| panic!("receipt cache lock"))
            .exact_receipt(first, &[1; 32], now)
            .unwrap_or_else(|| panic!("exact live receipt"));
        assert_eq!(cached.data_epoch, 1);
        assert_eq!(cached.receipt_epoch, 2);
        assert_eq!(cached.receipt.as_ref(), &[0x11]);
        assert!(cache
            .lock()
            .unwrap_or_else(|_| panic!("receipt cache lock"))
            .exact_receipt(second, &[2; 32], now)
            .is_none());
        let after_expiry = valid_until
            .checked_add(Duration::from_nanos(1))
            .unwrap_or_else(|| panic!("valid post-expiry instant"));
        let second_reservation = ReceiptCache::reserve(&cache, second, [2; 32], after_expiry)
            .unwrap_or_else(|error| panic!("reserve after retry horizon: {error}"))
            .unwrap_or_else(|| panic!("expired identity vacated the cache"));
        let second_expiry = after_expiry
            .checked_add(lifetime)
            .unwrap_or_else(|| panic!("valid second expiry"));
        second_reservation
            .commit(Arc::from([0x22_u8].as_slice()), 1, 2, second_expiry)
            .unwrap_or_else(|error| panic!("commit after retry horizon: {error}"));
        let mut cache = cache
            .lock()
            .unwrap_or_else(|_| panic!("receipt cache lock"));
        assert_eq!(cache.current_entries(), 1);
        assert_eq!(cache.peak_entries(), 1);
        assert_eq!(
            cache
                .exact_receipt(second, &[2; 32], after_expiry)
                .unwrap_or_else(|| panic!("second exact receipt"))
                .receipt
                .as_ref(),
            &[0x22]
        );
    }

    #[tokio::test]
    async fn public_forwarding_path_terminates_two_node_cycle_at_hop_bound() {
        let profile = test_profile()
            .with_hop_limit(3)
            .unwrap_or_else(|error| panic!("valid hop limit: {error}"));
        let (first_session, second_session) = test_sessions(profile);
        let (record, namespace, clock) = ownership_record("owner-c").await;
        let generation = record.generation();
        let first_cache = ownership_cache(record.clone(), namespace.clone(), clock.clone());
        let second_cache = ownership_cache(record, namespace, clock);
        let (first_datagram, second_datagram) = InMemoryIngressRedirectDatagram::pair(
            first_session.local_udp_endpoint(),
            second_session.local_udp_endpoint(),
            profile.steering_path_mtu(),
            profile.queue_packets(),
        )
        .unwrap_or_else(|error| panic!("in-memory pair: {error}"));
        let reporter = Arc::new(RecordingReporter::default());
        let (first, mut first_rx) = IngressRedirectEndpoint::start(
            Arc::clone(&first_session),
            first_cache,
            Arc::new(first_datagram),
            reporter.clone(),
        )
        .unwrap_or_else(|error| panic!("start first: {error}"));
        let (second, mut second_rx) = IngressRedirectEndpoint::start(
            Arc::clone(&second_session),
            second_cache,
            Arc::new(second_datagram),
            reporter,
        )
        .unwrap_or_else(|error| panic!("start second: {error}"));
        let packet = synthetic_native_esp_packet(128);
        assert_eq!(
            first.redirect(&packet, ownership_key(), generation).await,
            Ok(IngressRedirectReceiptCode::NotOwner)
        );
        let IngressRedirectInboundOutcome::Forwardable(at_second) = second_rx
            .receive()
            .await
            .unwrap_or_else(|error| panic!("first hop: {error}"))
        else {
            panic!("first hop must be forwardable")
        };
        assert_eq!(
            at_second.receipt_code(),
            IngressRedirectReceiptCode::NotOwner
        );
        assert_eq!(at_second.hop_count(), 1);
        assert_eq!(at_second.packet(), packet);
        assert_eq!(at_second.ownership_key(), ownership_key());
        assert_eq!(second_session.metrics().not_owner_drops, 1);
        assert_eq!(second_session.metrics().delivered, 0);
        assert_eq!(
            second.forward(at_second, generation).await,
            Ok(IngressRedirectReceiptCode::NotOwner)
        );
        let IngressRedirectInboundOutcome::Forwardable(at_first) = first_rx
            .receive()
            .await
            .unwrap_or_else(|error| panic!("second hop: {error}"))
        else {
            panic!("second hop must be forwardable")
        };
        assert_eq!(
            at_first.receipt_code(),
            IngressRedirectReceiptCode::NotOwner
        );
        assert_eq!(at_first.hop_count(), 2);
        assert_eq!(at_first.packet(), packet);
        assert_eq!(at_first.ownership_key(), ownership_key());
        assert_eq!(
            first.forward(at_first, generation).await,
            Ok(IngressRedirectReceiptCode::HopLimitReached)
        );
        let IngressRedirectInboundOutcome::Rejected(at_bound) = second_rx
            .receive()
            .await
            .unwrap_or_else(|error| panic!("bounded rejection: {error}"))
        else {
            panic!("hop bound must be terminal")
        };
        assert_eq!(at_bound.hop_count(), 3);
        assert_eq!(
            at_bound.receipt_code(),
            IngressRedirectReceiptCode::HopLimitReached
        );
        assert_eq!(second_session.metrics().hop_limit_drops, 1);
        first
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown first: {error}"));
        second
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown second: {error}"));
    }

    #[tokio::test]
    async fn oversize_redirect_fires_mandatory_borrowed_feedback_once() {
        let profile = test_profile();
        let (first_session, second_session) = test_sessions(profile);
        let (record, namespace, clock) = ownership_record("owner-b").await;
        let generation = record.generation();
        let first_cache = ownership_cache(record.clone(), namespace.clone(), clock.clone());
        let second_cache = ownership_cache(record, namespace, clock);
        let (first_datagram, second_datagram) = InMemoryIngressRedirectDatagram::pair(
            first_session.local_udp_endpoint(),
            second_session.local_udp_endpoint(),
            profile.steering_path_mtu(),
            profile.queue_packets(),
        )
        .unwrap_or_else(|error| panic!("in-memory pair: {error}"));
        let reporter = Arc::new(RecordingReporter::default());
        let (first, _first_rx) = IngressRedirectEndpoint::start(
            Arc::clone(&first_session),
            first_cache,
            Arc::new(first_datagram),
            reporter.clone(),
        )
        .unwrap_or_else(|error| panic!("start first: {error}"));
        let (second, _second_rx) = IngressRedirectEndpoint::start(
            second_session,
            second_cache,
            Arc::new(second_datagram),
            Arc::new(RecordingReporter::default()),
        )
        .unwrap_or_else(|error| panic!("start second: {error}"));
        let budget = IngressRedirectMtuBudget::new(
            profile,
            first.inner.session.peer_udp_endpoint().ip(),
            ownership_key().to_canonical_bytes().len(),
        )
        .unwrap_or_else(|error| panic!("MTU budget: {error}"));
        assert_eq!(
            first.redirect(&[], ownership_key(), generation).await,
            Err(IngressRedirectError::InvalidOriginalPacket)
        );
        assert_eq!(reporter.calls.load(Ordering::Relaxed), 0);
        let packet = synthetic_native_esp_packet(budget.maximum_original_packet() + 1);
        assert_eq!(
            first.redirect(&packet, ownership_key(), generation).await,
            Err(IngressRedirectError::PacketTooLarge)
        );
        assert_eq!(reporter.calls.load(Ordering::Relaxed), 1);
        assert_eq!(reporter.packet_len.load(Ordering::Relaxed), packet.len());
        assert_eq!(
            reporter.maximum.load(Ordering::Relaxed),
            budget.maximum_original_packet()
        );
        assert_eq!(first.metrics().packet_too_big_reports, 1);
        first
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown first: {error}"));
        second
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown second: {error}"));
    }

    #[tokio::test]
    async fn oversize_feedback_is_bounded_by_the_same_outbound_queue_budget() {
        let profile = test_profile()
            .with_queue_limits(1, 4_096)
            .unwrap_or_else(|error| panic!("valid bounded queue: {error}"));
        let (first_session, second_session) = test_sessions(profile);
        let (record, namespace, clock) = ownership_record("owner-b").await;
        let generation = record.generation();
        let first_cache = ownership_cache(record, namespace, clock);
        let (first_datagram, _unserved_peer) = InMemoryIngressRedirectDatagram::pair(
            first_session.local_udp_endpoint(),
            second_session.local_udp_endpoint(),
            profile.steering_path_mtu(),
            profile.queue_packets(),
        )
        .unwrap_or_else(|error| panic!("in-memory pair: {error}"));
        let (first, _receiver) = IngressRedirectEndpoint::start(
            Arc::clone(&first_session),
            first_cache,
            Arc::new(first_datagram),
            Arc::new(HangingReporter),
        )
        .unwrap_or_else(|error| panic!("start endpoint: {error}"));
        let budget = IngressRedirectMtuBudget::new(
            profile,
            first_session.peer_udp_endpoint().ip(),
            ownership_key().to_canonical_bytes().len(),
        )
        .unwrap_or_else(|error| panic!("MTU budget: {error}"));
        let packet = synthetic_native_esp_packet(budget.maximum_original_packet() + 1);
        let mut first_operation = first
            .begin_redirect(&packet, ownership_key(), generation)
            .unwrap_or_else(|error| panic!("begin first oversize operation: {error}"));
        let mut second_operation = first
            .begin_redirect(&packet, ownership_key(), generation)
            .unwrap_or_else(|error| panic!("begin second oversize operation: {error}"));
        assert_eq!(
            second_operation.wait().await,
            IngressRedirectOperationOutcome::NotSent(IngressRedirectNotSentReason::QueueFull)
        );
        assert_eq!(
            first_operation.wait().await,
            IngressRedirectOperationOutcome::NotSent(
                IngressRedirectNotSentReason::PacketTooBigFeedbackFailed
            )
        );
        let metrics = first.metrics();
        assert_eq!(metrics.packet_too_big_reports, 1);
        assert_eq!(metrics.queue_drops, 1);
        first
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown endpoint: {error}"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn delayed_ptb_task_cannot_restart_the_absolute_operation_deadline() {
        let profile = test_profile();
        let (first_session, second_session) = test_sessions(profile);
        let (record, namespace, clock) = ownership_record("owner-b").await;
        let generation = record.generation();
        let first_cache = ownership_cache(record, namespace, clock);
        let (first_datagram, _unserved_peer) = InMemoryIngressRedirectDatagram::pair(
            first_session.local_udp_endpoint(),
            second_session.local_udp_endpoint(),
            profile.steering_path_mtu(),
            profile.queue_packets(),
        )
        .unwrap_or_else(|error| panic!("in-memory pair: {error}"));
        let reporter = Arc::new(RecordingReporter::default());
        let (first, _receiver) = IngressRedirectEndpoint::start(
            Arc::clone(&first_session),
            first_cache,
            Arc::new(first_datagram),
            reporter.clone(),
        )
        .unwrap_or_else(|error| panic!("start endpoint: {error}"));
        let budget = IngressRedirectMtuBudget::new(
            profile,
            first_session.peer_udp_endpoint().ip(),
            ownership_key().to_canonical_bytes().len(),
        )
        .unwrap_or_else(|error| panic!("MTU budget: {error}"));
        let packet = synthetic_native_esp_packet(budget.maximum_original_packet() + 1);
        let mut operation = first
            .begin_redirect(&packet, ownership_key(), generation)
            .unwrap_or_else(|error| panic!("begin oversize operation: {error}"));
        std::thread::sleep(
            profile
                .receipt_retry_horizon()
                .saturating_add(Duration::from_millis(10)),
        );
        assert_eq!(
            operation.wait().await,
            IngressRedirectOperationOutcome::NotSent(IngressRedirectNotSentReason::DeadlineElapsed)
        );
        assert_eq!(reporter.calls.load(Ordering::Relaxed), 0);
        first
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown endpoint: {error}"));
    }

    #[tokio::test]
    async fn runtime_path_mtu_shrink_reports_exact_new_ceiling_before_any_delivery() {
        let profile = test_profile();
        let (first_session, second_session) = test_sessions(profile);
        let (record, namespace, clock) = ownership_record("owner-b").await;
        let generation = record.generation();
        let first_cache = ownership_cache(record, namespace, clock);
        let (first_datagram, _unserved_peer) = InMemoryIngressRedirectDatagram::pair(
            first_session.local_udp_endpoint(),
            second_session.local_udp_endpoint(),
            profile.steering_path_mtu(),
            profile.queue_packets(),
        )
        .unwrap_or_else(|error| panic!("in-memory pair: {error}"));
        let initial_ceiling = first_datagram.maximum_send_datagram_size();
        let shrunk_ceiling = 700;
        let datagram = Arc::new(ShrinkingSendDatagram {
            inner: Arc::new(first_datagram),
            ceiling: AtomicUsize::new(initial_ceiling),
            shrunk_ceiling,
            fail_next: AtomicBool::new(true),
        });
        let reporter = Arc::new(RecordingReporter::default());
        let (first, _receiver) =
            IngressRedirectEndpoint::start(first_session, first_cache, datagram, reporter.clone())
                .unwrap_or_else(|error| panic!("start shrinking endpoint: {error}"));
        let budget = IngressRedirectMtuBudget::new(
            profile,
            second_session.local_udp_endpoint().ip(),
            ownership_key().to_canonical_bytes().len(),
        )
        .unwrap_or_else(|error| panic!("MTU budget: {error}"));
        let expected_maximum = shrunk_ceiling.saturating_sub(budget.redirect_overhead());
        let packet = synthetic_native_esp_packet(expected_maximum + 1);
        let mut operation = first
            .begin_redirect(&packet, ownership_key(), generation)
            .unwrap_or_else(|error| panic!("begin redirect before shrink: {error}"));
        assert_eq!(
            operation.wait().await,
            IngressRedirectOperationOutcome::NotSent(IngressRedirectNotSentReason::PacketTooLarge)
        );
        assert_eq!(reporter.calls.load(Ordering::Relaxed), 1);
        assert_eq!(reporter.packet_len.load(Ordering::Relaxed), packet.len());
        assert_eq!(reporter.maximum.load(Ordering::Relaxed), expected_maximum);
        first
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown shrinking endpoint: {error}"));
    }

    #[tokio::test]
    async fn full_or_closed_delivery_queue_returns_and_caches_typed_queue_rejection() {
        let profile = test_profile()
            .with_queue_limits(1, 4_096)
            .unwrap_or_else(|error| panic!("valid bounded queue: {error}"));
        let (first_session, second_session) = test_sessions(profile);
        let (record, namespace, clock) = ownership_record("owner-b").await;
        let generation = record.generation();
        let first_cache = ownership_cache(record.clone(), namespace.clone(), clock.clone());
        let second_cache = ownership_cache(record, namespace, clock);
        let (first_datagram, second_datagram) = InMemoryIngressRedirectDatagram::pair(
            first_session.local_udp_endpoint(),
            second_session.local_udp_endpoint(),
            profile.steering_path_mtu(),
            profile.queue_packets(),
        )
        .unwrap_or_else(|error| panic!("in-memory pair: {error}"));
        let second_datagram = Arc::new(DropFirstReceiptDatagram::new(Arc::new(second_datagram)));
        second_datagram.dropped.store(true, Ordering::Relaxed);
        let reporter = Arc::new(RecordingReporter::default());
        let (first, _first_rx) = IngressRedirectEndpoint::start(
            Arc::clone(&first_session),
            first_cache,
            Arc::new(first_datagram),
            reporter.clone(),
        )
        .unwrap_or_else(|error| panic!("start first: {error}"));
        let (second, mut second_rx) = IngressRedirectEndpoint::start(
            Arc::clone(&second_session),
            second_cache,
            second_datagram.clone(),
            reporter,
        )
        .unwrap_or_else(|error| panic!("start second: {error}"));
        let first_packet = synthetic_native_esp_packet(128);
        assert_eq!(
            first
                .redirect(&first_packet, ownership_key(), generation)
                .await,
            Ok(IngressRedirectReceiptCode::Delivered)
        );
        second_datagram.dropped.store(false, Ordering::Relaxed);
        if let Ok(mut first_receipt) = second_datagram.first_receipt.lock() {
            *first_receipt = None;
        }
        let second_packet = synthetic_native_esp_packet(129);
        assert_eq!(
            first
                .redirect(&second_packet, ownership_key(), generation)
                .await,
            Ok(IngressRedirectReceiptCode::QueueFull)
        );
        assert_eq!(second.metrics().queue_drops, 1);
        assert_eq!(second.metrics().cached_receipts_replayed, 1);
        assert!(second_datagram.replay_was_exact.load(Ordering::Relaxed));
        assert_eq!(second_session.metrics().delivery_admissions, 1);
        assert_eq!(second_session.metrics().delivered, 0);
        let first_outcome = second_rx
            .receive()
            .await
            .unwrap_or_else(|error| panic!("first queued outcome: {error}"));
        assert!(matches!(
            first_outcome,
            IngressRedirectInboundOutcome::Delivered(_)
        ));
        drop(second_rx);
        assert_eq!(
            first
                .redirect(&second_packet, ownership_key(), generation)
                .await,
            Ok(IngressRedirectReceiptCode::QueueFull)
        );
        assert_eq!(second.metrics().queue_drops, 2);
        assert_eq!(second.metrics().cached_receipts_replayed, 1);
        assert_eq!(second_session.metrics().delivered, 1);
        first
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown first: {error}"));
        second
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown second: {error}"));
    }

    #[tokio::test]
    async fn receipt_cache_pressure_rejects_before_open_without_uncached_receipt() {
        let profile = test_profile();
        let (first_session, second_session) = test_sessions(profile);
        let (record, namespace, clock) = ownership_record("owner-b").await;
        let generation = record.generation();
        let first_cache = ownership_cache(record.clone(), namespace.clone(), clock.clone());
        let second_cache = ownership_cache(record, namespace, clock);
        let (first_datagram, second_datagram) = InMemoryIngressRedirectDatagram::pair(
            first_session.local_udp_endpoint(),
            second_session.local_udp_endpoint(),
            profile.steering_path_mtu(),
            profile.queue_packets(),
        )
        .unwrap_or_else(|error| panic!("in-memory pair: {error}"));
        let reporter = Arc::new(RecordingReporter::default());
        let (first, _first_rx) = IngressRedirectEndpoint::start(
            first_session,
            first_cache,
            Arc::new(first_datagram),
            reporter.clone(),
        )
        .unwrap_or_else(|error| panic!("start first: {error}"));
        let (second, mut second_rx) = IngressRedirectEndpoint::start(
            Arc::clone(&second_session),
            second_cache,
            Arc::new(second_datagram),
            reporter,
        )
        .unwrap_or_else(|error| panic!("start second: {error}"));
        *second
            .inner
            .receipt_cache
            .lock()
            .unwrap_or_else(|_| panic!("receipt cache lock")) =
            ReceiptCache::new(0, profile.rotation_overlap());
        let packet = synthetic_native_esp_packet(128);
        assert!(matches!(
            first.redirect(&packet, ownership_key(), generation).await,
            Err(IngressRedirectError::ReceiptTimeout)
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(20), second_rx.receive())
                .await
                .is_err(),
            "cache exhaustion must not publish an application effect"
        );
        assert_eq!(second_session.metrics().delivered, 0);
        assert_eq!(
            second.metrics().receipt_cache_load_shed,
            u64::from(profile.max_retries()).saturating_add(1)
        );
        first
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown first: {error}"));
        second
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown second: {error}"));
    }

    #[tokio::test]
    async fn receipt_cache_commit_failure_publishes_no_effect_and_sends_no_receipt() {
        let profile = test_profile();
        let (first_session, second_session) = test_sessions(profile);
        let (record, namespace, clock) = ownership_record("owner-b").await;
        let generation = record.generation();
        let first_cache = ownership_cache(record.clone(), namespace.clone(), clock.clone());
        let second_cache = ownership_cache(record, namespace, clock);
        let (first_datagram, second_datagram) = InMemoryIngressRedirectDatagram::pair(
            first_session.local_udp_endpoint(),
            second_session.local_udp_endpoint(),
            profile.steering_path_mtu(),
            profile.queue_packets(),
        )
        .unwrap_or_else(|error| panic!("in-memory pair: {error}"));
        let reporter = Arc::new(RecordingReporter::default());
        let (first, _first_rx) = IngressRedirectEndpoint::start(
            first_session,
            first_cache,
            Arc::new(first_datagram),
            reporter.clone(),
        )
        .unwrap_or_else(|error| panic!("start first: {error}"));
        let (second, mut second_rx) = IngressRedirectEndpoint::start(
            Arc::clone(&second_session),
            second_cache,
            Arc::new(second_datagram),
            reporter,
        )
        .unwrap_or_else(|error| panic!("start second: {error}"));
        second
            .inner
            .receipt_cache
            .lock()
            .unwrap_or_else(|_| panic!("receipt cache lock"))
            .fail_next_commit = true;

        let packet = synthetic_native_esp_packet(128);
        assert_eq!(
            first.redirect(&packet, ownership_key(), generation).await,
            Err(IngressRedirectError::ReceiptTimeout)
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(20), second_rx.receive())
                .await
                .is_err(),
            "an uncommitted receipt must never publish an application effect"
        );
        let metrics = second.metrics();
        assert_eq!(metrics.receipt_cache_commit_failures, 1);
        assert_eq!(metrics.receipt_cache_entries_current, 0);
        assert_eq!(metrics.delivery_admissions, 0);
        assert_eq!(second_session.metrics().delivery_admissions, 0);
        first
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown first: {error}"));
        second
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown second: {error}"));
    }

    #[tokio::test]
    async fn queued_delivery_capability_remains_valid_beyond_receipt_retry_horizon() {
        let profile = test_profile();
        let (first_session, second_session) = test_sessions(profile);
        let (record, namespace, clock) = ownership_record("owner-b").await;
        let generation = record.generation();
        let first_cache = ownership_cache(record.clone(), namespace.clone(), clock.clone());
        let second_cache = ownership_cache(record, namespace, clock);
        let (first_datagram, second_datagram) = InMemoryIngressRedirectDatagram::pair(
            first_session.local_udp_endpoint(),
            second_session.local_udp_endpoint(),
            profile.steering_path_mtu(),
            profile.queue_packets(),
        )
        .unwrap_or_else(|error| panic!("in-memory pair: {error}"));
        let reporter = Arc::new(RecordingReporter::default());
        let (first, _first_rx) = IngressRedirectEndpoint::start(
            first_session,
            first_cache,
            Arc::new(first_datagram),
            reporter.clone(),
        )
        .unwrap_or_else(|error| panic!("start first: {error}"));
        let (second, mut second_rx) = IngressRedirectEndpoint::start(
            Arc::clone(&second_session),
            second_cache,
            Arc::new(second_datagram),
            reporter,
        )
        .unwrap_or_else(|error| panic!("start second: {error}"));
        let packet = synthetic_native_esp_packet(128);
        assert_eq!(
            first.redirect(&packet, ownership_key(), generation).await,
            Ok(IngressRedirectReceiptCode::Delivered)
        );
        tokio::time::sleep(
            profile
                .receipt_retry_horizon()
                .saturating_add(Duration::from_millis(10)),
        )
        .await;
        let outcome = second_rx
            .receive()
            .await
            .unwrap_or_else(|error| panic!("delivery remains epoch-authorized: {error}"));
        assert!(matches!(
            outcome,
            IngressRedirectInboundOutcome::Delivered(_)
        ));
        let metrics = second.metrics();
        assert_eq!(metrics.delivery_admissions, 1);
        assert_eq!(metrics.delivery_materialized, 1);
        assert_eq!(metrics.delivery_capability_stale_drops, 0);
        assert_eq!(second_session.metrics().delivered, 1);
        first
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown first: {error}"));
        second
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown second: {error}"));
    }

    #[tokio::test]
    async fn shutdown_drains_endpoint_owned_receipt_wait_before_reaping_receiver() {
        let profile = test_profile();
        let (first_session, second_session) = test_sessions(profile);
        let (record, namespace, clock) = ownership_record("owner-b").await;
        let generation = record.generation();
        let first_cache = ownership_cache(record, namespace, clock);
        let (first_datagram, _unserved_peer) = InMemoryIngressRedirectDatagram::pair(
            first_session.local_udp_endpoint(),
            second_session.local_udp_endpoint(),
            profile.steering_path_mtu(),
            profile.queue_packets(),
        )
        .unwrap_or_else(|error| panic!("in-memory pair: {error}"));
        let reporter = Arc::new(RecordingReporter::default());
        let (first, mut first_rx) = IngressRedirectEndpoint::start(
            first_session,
            first_cache,
            Arc::new(first_datagram),
            reporter,
        )
        .unwrap_or_else(|error| panic!("start first: {error}"));
        let first = Arc::new(first);
        let packet = synthetic_native_esp_packet(128);
        let mut operation = first
            .begin_redirect(&packet, ownership_key(), generation)
            .unwrap_or_else(|error| panic!("begin redirect: {error}"));
        let redirect = tokio::spawn(async move { operation.wait().await });
        tokio::time::timeout(Duration::from_millis(100), async {
            while first.metrics().send_attempts == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("first send attempt observed"));
        first
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown and reap: {error}"));
        assert_eq!(
            redirect
                .await
                .unwrap_or_else(|error| panic!("redirect task joined: {error}")),
            IngressRedirectOperationOutcome::DeliveryOutcomeUnknown
        );
        assert!(matches!(
            first_rx.receive().await,
            Err(IngressRedirectError::ShuttingDown)
        ));
        first
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("idempotent shutdown: {error}"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn scheduler_delay_cannot_extend_the_absolute_operation_deadline() {
        let profile = test_profile();
        let (first_session, second_session) = test_sessions(profile);
        let (record, namespace, clock) = ownership_record("owner-b").await;
        let generation = record.generation();
        let first_cache = ownership_cache(record, namespace, clock);
        let (first_datagram, _unserved_peer) = InMemoryIngressRedirectDatagram::pair(
            first_session.local_udp_endpoint(),
            second_session.local_udp_endpoint(),
            profile.steering_path_mtu(),
            profile.queue_packets(),
        )
        .unwrap_or_else(|error| panic!("in-memory pair: {error}"));
        let datagram = Arc::new(FailingSendDatagram {
            inner: Arc::new(first_datagram),
            error: IngressRedirectDatagramError::Closed,
            sends: AtomicUsize::new(0),
        });
        let (first, _receiver) = IngressRedirectEndpoint::start(
            first_session,
            first_cache,
            datagram.clone(),
            Arc::new(RecordingReporter::default()),
        )
        .unwrap_or_else(|error| panic!("start first: {error}"));
        let packet = synthetic_native_esp_packet(128);
        let mut operation = first
            .begin_redirect(&packet, ownership_key(), generation)
            .unwrap_or_else(|error| panic!("begin redirect: {error}"));
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(
            operation.wait().await,
            IngressRedirectOperationOutcome::NotSent(IngressRedirectNotSentReason::DeadlineElapsed)
        );
        assert_eq!(datagram.sends.load(Ordering::Relaxed), 0);
        first
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown first: {error}"));
    }

    #[test]
    fn lifecycle_admission_fails_closed_instead_of_wrapping_active_count() {
        let lifecycle = EndpointLifecycle::new();
        lifecycle
            .active_operations
            .store(usize::MAX, Ordering::Release);
        assert!(matches!(
            lifecycle.try_admit(),
            Err(IngressRedirectError::StateUnavailable)
        ));
        assert_eq!(
            lifecycle.active_operations.load(Ordering::Acquire),
            usize::MAX
        );
    }

    #[test]
    fn captured_runtime_drives_operations_started_without_an_entered_runtime() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap_or_else(|error| panic!("build test runtime: {error}"));
        let profile = test_profile();
        let (first_session, second_session) = test_sessions(profile);
        let (first, second, mut second_rx, generation) = runtime.block_on(async {
            let (record, namespace, clock) = ownership_record("owner-b").await;
            let generation = record.generation();
            let first_cache = ownership_cache(record.clone(), namespace.clone(), clock.clone());
            let second_cache = ownership_cache(record, namespace, clock);
            let (first_datagram, second_datagram) = InMemoryIngressRedirectDatagram::pair(
                first_session.local_udp_endpoint(),
                second_session.local_udp_endpoint(),
                profile.steering_path_mtu(),
                profile.queue_packets(),
            )
            .unwrap_or_else(|error| panic!("in-memory pair: {error}"));
            let reporter = Arc::new(RecordingReporter::default());
            let (first, _first_rx) = IngressRedirectEndpoint::start(
                Arc::clone(&first_session),
                first_cache,
                Arc::new(first_datagram),
                reporter.clone(),
            )
            .unwrap_or_else(|error| panic!("start first: {error}"));
            let (second, second_rx) = IngressRedirectEndpoint::start(
                Arc::clone(&second_session),
                second_cache,
                Arc::new(second_datagram),
                reporter,
            )
            .unwrap_or_else(|error| panic!("start second: {error}"));
            (first, second, second_rx, generation)
        });

        let packet = synthetic_native_esp_packet(128);
        let mut operation = first
            .begin_redirect(&packet, ownership_key(), generation)
            .unwrap_or_else(|error| panic!("begin outside runtime: {error}"));
        assert_eq!(
            runtime.block_on(operation.wait()),
            IngressRedirectOperationOutcome::AuthenticatedReceipt(
                IngressRedirectReceiptCode::Delivered
            )
        );
        assert!(matches!(
            runtime.block_on(second_rx.receive()),
            Ok(IngressRedirectInboundOutcome::Delivered(_))
        ));
        runtime
            .block_on(first.shutdown())
            .unwrap_or_else(|error| panic!("shutdown first: {error}"));
        runtime
            .block_on(second.shutdown())
            .unwrap_or_else(|error| panic!("shutdown second: {error}"));
    }

    #[tokio::test]
    async fn near_expiry_epoch_is_not_sealed_without_the_full_retry_horizon() {
        let profile = test_profile();
        let (mut first_session, second_session) = test_sessions(profile);
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(20))
            .unwrap_or_else(|| panic!("valid near deadline"));
        {
            let session = Arc::get_mut(&mut first_session)
                .unwrap_or_else(|| panic!("unshared first session"));
            let state = session
                .epochs
                .get_mut()
                .unwrap_or_else(|_| panic!("epoch state"));
            let epoch = Arc::get_mut(&mut state.current)
                .unwrap_or_else(|| panic!("unshared current epoch"));
            epoch.hard_authenticated_deadline = deadline;
        }
        let (record, namespace, clock) = ownership_record("owner-b").await;
        let generation = record.generation();
        let first_cache = ownership_cache(record, namespace, clock);
        let (first_datagram, _unserved_peer) = InMemoryIngressRedirectDatagram::pair(
            first_session.local_udp_endpoint(),
            second_session.local_udp_endpoint(),
            profile.steering_path_mtu(),
            profile.queue_packets(),
        )
        .unwrap_or_else(|error| panic!("in-memory pair: {error}"));
        let (first, _receiver) = IngressRedirectEndpoint::start(
            Arc::clone(&first_session),
            first_cache,
            Arc::new(first_datagram),
            Arc::new(RecordingReporter::default()),
        )
        .unwrap_or_else(|error| panic!("start first: {error}"));
        let packet = synthetic_native_esp_packet(128);
        assert!(matches!(
            first.begin_redirect(&packet, ownership_key(), generation),
            Err(IngressRedirectError::AuthenticationExpired)
        ));
        assert_eq!(first_session.metrics().frames_sealed, 0);
        first
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown first: {error}"));
    }

    #[tokio::test]
    async fn terminal_send_error_after_ambiguous_attempt_is_outcome_unknown() {
        let profile = test_profile();
        let (first_session, second_session) = test_sessions(profile);
        let (record, namespace, clock) = ownership_record("owner-b").await;
        let generation = record.generation();
        let first_cache = ownership_cache(record, namespace, clock);
        let (first_datagram, _unserved_peer) = InMemoryIngressRedirectDatagram::pair(
            first_session.local_udp_endpoint(),
            second_session.local_udp_endpoint(),
            profile.steering_path_mtu(),
            profile.queue_packets(),
        )
        .unwrap_or_else(|error| panic!("in-memory pair: {error}"));
        let datagram = Arc::new(ScriptedSendDatagram {
            inner: Arc::new(first_datagram),
            errors: Mutex::new(VecDeque::from([
                IngressRedirectDatagramError::Io,
                IngressRedirectDatagramError::Closed,
            ])),
            sends: AtomicUsize::new(0),
        });
        let (first, _receiver) = IngressRedirectEndpoint::start(
            first_session,
            first_cache,
            datagram.clone(),
            Arc::new(RecordingReporter::default()),
        )
        .unwrap_or_else(|error| panic!("start first: {error}"));
        let packet = synthetic_native_esp_packet(128);
        let mut operation = first
            .begin_redirect(&packet, ownership_key(), generation)
            .unwrap_or_else(|error| panic!("begin redirect: {error}"));
        assert_eq!(
            operation.wait().await,
            IngressRedirectOperationOutcome::DeliveryOutcomeUnknown
        );
        assert_eq!(datagram.sends.load(Ordering::Relaxed), 2);
        first
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown first: {error}"));
    }

    #[tokio::test]
    async fn receive_failure_is_terminal_and_rejects_all_later_operations() {
        let profile = test_profile();
        let (first_session, second_session) = test_sessions(profile);
        let (record, namespace, clock) = ownership_record("owner-b").await;
        let generation = record.generation();
        let first_cache = ownership_cache(record, namespace, clock);
        let (first_datagram, _unserved_peer) = InMemoryIngressRedirectDatagram::pair(
            first_session.local_udp_endpoint(),
            second_session.local_udp_endpoint(),
            profile.steering_path_mtu(),
            profile.queue_packets(),
        )
        .unwrap_or_else(|error| panic!("in-memory pair: {error}"));
        let (first, mut receiver) = IngressRedirectEndpoint::start(
            Arc::clone(&first_session),
            first_cache,
            Arc::new(FailingReceiveDatagram {
                inner: Arc::new(first_datagram),
            }),
            Arc::new(RecordingReporter::default()),
        )
        .unwrap_or_else(|error| panic!("start first: {error}"));
        tokio::time::timeout(Duration::from_millis(100), async {
            while first.inner.lifecycle.phase() != EndpointPhase::Failed {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("receive failure became terminal"));
        let packet = synthetic_native_esp_packet(128);
        assert!(matches!(
            first.begin_redirect(&packet, ownership_key(), generation),
            Err(IngressRedirectError::TransportFailed)
        ));
        assert!(matches!(
            receiver.receive().await,
            Err(IngressRedirectError::TransportFailed)
        ));
        assert_eq!(
            first.shutdown().await,
            Err(IngressRedirectError::TransportFailed)
        );
        assert!(matches!(
            IngressRedirectEndpoint::start(
                first_session,
                Arc::clone(&first.inner.ownership),
                Arc::clone(&first.inner.datagram),
                Arc::new(RecordingReporter::default()),
            ),
            Err(IngressRedirectError::EndpointAlreadyConsumed)
        ));
    }

    #[tokio::test]
    async fn delivery_receiver_drains_committed_envelopes_before_terminal_shutdown() {
        let profile = test_profile();
        let (first_session, second_session) = test_sessions(profile);
        let (record, namespace, clock) = ownership_record("owner-b").await;
        let generation = record.generation();
        let first_cache = ownership_cache(record.clone(), namespace.clone(), clock.clone());
        let second_cache = ownership_cache(record, namespace, clock);
        let (first_datagram, second_datagram) = InMemoryIngressRedirectDatagram::pair(
            first_session.local_udp_endpoint(),
            second_session.local_udp_endpoint(),
            profile.steering_path_mtu(),
            profile.queue_packets(),
        )
        .unwrap_or_else(|error| panic!("in-memory pair: {error}"));
        let reporter = Arc::new(RecordingReporter::default());
        let (first, _first_rx) = IngressRedirectEndpoint::start(
            first_session,
            first_cache,
            Arc::new(first_datagram),
            reporter.clone(),
        )
        .unwrap_or_else(|error| panic!("start first: {error}"));
        let (second, mut second_rx) = IngressRedirectEndpoint::start(
            second_session,
            second_cache,
            Arc::new(second_datagram),
            reporter,
        )
        .unwrap_or_else(|error| panic!("start second: {error}"));
        let packet = synthetic_native_esp_packet(128);
        assert_eq!(
            first.redirect(&packet, ownership_key(), generation).await,
            Ok(IngressRedirectReceiptCode::Delivered)
        );
        second
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown second: {error}"));
        let delivered = second_rx
            .receive()
            .await
            .unwrap_or_else(|error| panic!("drain committed delivery: {error}"));
        let IngressRedirectInboundOutcome::Delivered(delivered) = delivered else {
            panic!("committed delivery outcome")
        };
        assert_eq!(delivered.packet(), packet);
        assert!(matches!(
            second_rx.receive().await,
            Err(IngressRedirectError::ShuttingDown)
        ));
        first
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown first: {error}"));
    }

    #[tokio::test]
    async fn one_peer_session_is_permanently_consumed_after_first_endpoint_start() {
        let profile = test_profile();
        let (first_session, second_session) = test_sessions(profile);
        let (record, namespace, clock) = ownership_record("owner-b").await;
        let first_cache = ownership_cache(record, namespace, clock);
        let (first_datagram, _unserved_peer) = InMemoryIngressRedirectDatagram::pair(
            first_session.local_udp_endpoint(),
            second_session.local_udp_endpoint(),
            profile.steering_path_mtu(),
            profile.queue_packets(),
        )
        .unwrap_or_else(|error| panic!("in-memory pair: {error}"));
        let datagram = Arc::new(first_datagram);
        let reporter = Arc::new(RecordingReporter::default());
        let (first, _first_rx) = IngressRedirectEndpoint::start(
            Arc::clone(&first_session),
            Arc::clone(&first_cache),
            datagram.clone(),
            reporter.clone(),
        )
        .unwrap_or_else(|error| panic!("start first endpoint: {error}"));

        assert!(matches!(
            IngressRedirectEndpoint::start(
                Arc::clone(&first_session),
                Arc::clone(&first_cache),
                datagram.clone(),
                reporter.clone(),
            ),
            Err(IngressRedirectError::EndpointAlreadyConsumed)
        ));

        first
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown first endpoint: {error}"));
        assert!(matches!(
            IngressRedirectEndpoint::start(first_session, first_cache, datagram, reporter),
            Err(IngressRedirectError::EndpointAlreadyConsumed)
        ));
    }

    #[tokio::test]
    async fn hung_adapter_and_ptb_hook_are_bounded_and_shutdown_still_reaps() {
        let profile = test_profile();
        let (first_session, second_session) = test_sessions(profile);
        let (record, namespace, clock) = ownership_record("owner-b").await;
        let generation = record.generation();
        let first_cache = ownership_cache(record, namespace, clock);
        let (first_datagram, _unserved_peer) = InMemoryIngressRedirectDatagram::pair(
            first_session.local_udp_endpoint(),
            second_session.local_udp_endpoint(),
            profile.steering_path_mtu(),
            profile.queue_packets(),
        )
        .unwrap_or_else(|error| panic!("in-memory pair: {error}"));
        let never_send = Arc::new(NeverSendDatagram {
            inner: Arc::new(first_datagram),
        });
        let (first, _first_rx) = IngressRedirectEndpoint::start(
            Arc::clone(&first_session),
            first_cache,
            never_send,
            Arc::new(HangingReporter),
        )
        .unwrap_or_else(|error| panic!("start first: {error}"));
        let packet = synthetic_native_esp_packet(128);
        let mut operation = first
            .begin_redirect(&packet, ownership_key(), generation)
            .unwrap_or_else(|error| panic!("begin hung send: {error}"));
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(100), operation.wait())
                .await
                .unwrap_or_else(|_| panic!("bounded adapter send")),
            IngressRedirectOperationOutcome::DeliveryOutcomeUnknown
        );
        assert_eq!(first.metrics().transport_drops, 3);
        assert_eq!(first.metrics().receipt_timeouts, 1);
        let budget = IngressRedirectMtuBudget::new(
            profile,
            first_session.peer_udp_endpoint().ip(),
            ownership_key().to_canonical_bytes().len(),
        )
        .unwrap_or_else(|error| panic!("MTU budget: {error}"));
        let oversize = synthetic_native_esp_packet(budget.maximum_original_packet() + 1);
        let mut operation = first
            .begin_redirect(&oversize, ownership_key(), generation)
            .unwrap_or_else(|error| panic!("begin oversize redirect: {error}"));
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(100), operation.wait())
                .await
                .unwrap_or_else(|_| panic!("bounded PTB reporter")),
            IngressRedirectOperationOutcome::NotSent(
                IngressRedirectNotSentReason::PacketTooBigFeedbackFailed
            )
        );
        tokio::time::timeout(Duration::from_millis(100), first.shutdown())
            .await
            .unwrap_or_else(|_| panic!("bounded shutdown"))
            .unwrap_or_else(|error| panic!("shutdown and reap: {error}"));
    }

    #[tokio::test]
    async fn adapter_send_errors_preserve_terminal_outcomes_and_metrics() {
        let cases = [
            (
                IngressRedirectDatagramError::QueueFull,
                IngressRedirectOperationOutcome::NotSent(IngressRedirectNotSentReason::QueueFull),
                1,
                0,
                1,
                0,
            ),
            (
                IngressRedirectDatagramError::DatagramTooLarge,
                IngressRedirectOperationOutcome::NotSent(
                    IngressRedirectNotSentReason::PacketTooLarge,
                ),
                1,
                1,
                0,
                0,
            ),
            (
                IngressRedirectDatagramError::InvalidConfiguration,
                IngressRedirectOperationOutcome::NotSent(
                    IngressRedirectNotSentReason::TransportRejected,
                ),
                1,
                1,
                0,
                0,
            ),
            (
                IngressRedirectDatagramError::Closed,
                IngressRedirectOperationOutcome::NotSent(
                    IngressRedirectNotSentReason::TransportRejected,
                ),
                1,
                1,
                0,
                0,
            ),
            (
                IngressRedirectDatagramError::Io,
                IngressRedirectOperationOutcome::DeliveryOutcomeUnknown,
                3,
                3,
                0,
                1,
            ),
            (
                IngressRedirectDatagramError::TimedOut,
                IngressRedirectOperationOutcome::DeliveryOutcomeUnknown,
                3,
                3,
                0,
                1,
            ),
        ];

        for (adapter_error, expected, sends, transport_drops, queue_drops, receipt_timeouts) in
            cases
        {
            let profile = test_profile();
            let (first_session, second_session) = test_sessions(profile);
            let (record, namespace, clock) = ownership_record("owner-b").await;
            let generation = record.generation();
            let first_cache = ownership_cache(record, namespace, clock);
            let (first_datagram, _unserved_peer) = InMemoryIngressRedirectDatagram::pair(
                first_session.local_udp_endpoint(),
                second_session.local_udp_endpoint(),
                profile.steering_path_mtu(),
                profile.queue_packets(),
            )
            .unwrap_or_else(|error| panic!("in-memory pair: {error}"));
            let datagram = Arc::new(FailingSendDatagram {
                inner: Arc::new(first_datagram),
                error: adapter_error,
                sends: AtomicUsize::new(0),
            });
            let (first, _first_rx) = IngressRedirectEndpoint::start(
                first_session,
                first_cache,
                datagram.clone(),
                Arc::new(RecordingReporter::default()),
            )
            .unwrap_or_else(|error| panic!("start first: {error}"));
            let packet = synthetic_native_esp_packet(128);
            let mut operation = first
                .begin_redirect(&packet, ownership_key(), generation)
                .unwrap_or_else(|error| panic!("begin adapter error operation: {error}"));
            assert_eq!(
                tokio::time::timeout(Duration::from_millis(100), operation.wait())
                    .await
                    .unwrap_or_else(|_| panic!("bounded adapter error {adapter_error:?}")),
                expected,
                "adapter error {adapter_error:?}",
            );
            let metrics = first.metrics();
            assert_eq!(datagram.sends.load(Ordering::Relaxed), sends);
            assert_eq!(metrics.send_attempts, sends as u64);
            assert_eq!(metrics.retries, sends.saturating_sub(1) as u64);
            assert_eq!(metrics.transport_drops, transport_drops);
            assert_eq!(metrics.queue_drops, queue_drops);
            assert_eq!(metrics.receipt_timeouts, receipt_timeouts);
            first
                .shutdown()
                .await
                .unwrap_or_else(|error| panic!("shutdown failed adapter endpoint: {error}"));
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn late_receipt_wins_before_retry_send_is_polled_or_counted() {
        let profile = test_profile();
        let (first_session, second_session) = test_sessions(profile);
        let (record, namespace, clock) = ownership_record("owner-b").await;
        let generation = record.generation();
        let first_cache = ownership_cache(record, namespace, clock);
        let (first_datagram, _unserved_peer) = InMemoryIngressRedirectDatagram::pair(
            first_session.local_udp_endpoint(),
            second_session.local_udp_endpoint(),
            profile.steering_path_mtu(),
            profile.queue_packets(),
        )
        .unwrap_or_else(|error| panic!("in-memory pair: {error}"));
        let datagram = Arc::new(LateReceiptBeforeRetryDatagram {
            inner: Arc::new(first_datagram),
            receipt: Mutex::new(None),
            sends: AtomicUsize::new(0),
        });
        let (first, _receiver) = IngressRedirectEndpoint::start(
            first_session,
            first_cache,
            datagram.clone(),
            Arc::new(RecordingReporter::default()),
        )
        .unwrap_or_else(|error| panic!("start first: {error}"));
        let packet = synthetic_native_esp_packet(128);
        let mut operation = first
            .begin_redirect(&packet, ownership_key(), generation)
            .unwrap_or_else(|error| panic!("begin redirect: {error}"));
        let receipt = first
            .inner
            .pending
            .lock()
            .unwrap_or_else(|error| panic!("pending receipt: {error}"))
            .pop_first()
            .map(|(_, pending)| pending.result)
            .unwrap_or_else(|| panic!("registered receipt"));
        *datagram
            .receipt
            .lock()
            .unwrap_or_else(|error| panic!("late receipt gate: {error}")) = Some(receipt);

        assert_eq!(
            tokio::time::timeout(Duration::from_millis(100), operation.wait())
                .await
                .unwrap_or_else(|_| panic!("late receipt completed operation")),
            IngressRedirectOperationOutcome::AuthenticatedReceipt(
                IngressRedirectReceiptCode::Delivered
            )
        );
        assert_eq!(datagram.sends.load(Ordering::Relaxed), 1);
        assert_eq!(first.metrics().send_attempts, 1);
        assert_eq!(first.metrics().retries, 0);
        first
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown first: {error}"));
    }

    #[tokio::test]
    async fn receipt_can_complete_within_same_deadline_while_send_future_stalls() {
        let profile = test_profile();
        let (first_session, second_session) = test_sessions(profile);
        let (record, namespace, clock) = ownership_record("owner-b").await;
        let generation = record.generation();
        let first_cache = ownership_cache(record.clone(), namespace.clone(), clock.clone());
        let second_cache = ownership_cache(record, namespace, clock);
        let (first_datagram, second_datagram) = InMemoryIngressRedirectDatagram::pair(
            first_session.local_udp_endpoint(),
            second_session.local_udp_endpoint(),
            profile.steering_path_mtu(),
            profile.queue_packets(),
        )
        .unwrap_or_else(|error| panic!("in-memory pair: {error}"));
        let reporter = Arc::new(RecordingReporter::default());
        let (first, _first_rx) = IngressRedirectEndpoint::start(
            first_session,
            first_cache,
            Arc::new(SendThenHangDatagram {
                inner: Arc::new(first_datagram),
            }),
            reporter.clone(),
        )
        .unwrap_or_else(|error| panic!("start first: {error}"));
        let (second, mut second_rx) = IngressRedirectEndpoint::start(
            second_session,
            second_cache,
            Arc::new(second_datagram),
            reporter,
        )
        .unwrap_or_else(|error| panic!("start second: {error}"));
        let packet = synthetic_native_esp_packet(128);
        assert_eq!(
            tokio::time::timeout(
                Duration::from_millis(100),
                first.redirect(&packet, ownership_key(), generation),
            )
            .await
            .unwrap_or_else(|_| panic!("receipt won shared attempt deadline")),
            Ok(IngressRedirectReceiptCode::Delivered)
        );
        assert!(matches!(
            second_rx.receive().await,
            Ok(IngressRedirectInboundOutcome::Delivered(_))
        ));
        assert_eq!(first.metrics().send_attempts, 1);
        assert_eq!(first.metrics().retries, 0);
        first
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown first: {error}"));
        second
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown second: {error}"));
    }

    #[tokio::test]
    async fn hung_receipt_send_cannot_wedge_sole_receiver_or_shutdown() {
        let profile = test_profile();
        let (first_session, second_session) = test_sessions(profile);
        let (record, namespace, clock) = ownership_record("owner-b").await;
        let generation = record.generation();
        let first_cache = ownership_cache(record.clone(), namespace.clone(), clock.clone());
        let second_cache = ownership_cache(record, namespace, clock);
        let (first_datagram, second_datagram) = InMemoryIngressRedirectDatagram::pair(
            first_session.local_udp_endpoint(),
            second_session.local_udp_endpoint(),
            profile.steering_path_mtu(),
            profile.queue_packets(),
        )
        .unwrap_or_else(|error| panic!("in-memory pair: {error}"));
        let reporter = Arc::new(RecordingReporter::default());
        let (first, _first_rx) = IngressRedirectEndpoint::start(
            first_session,
            first_cache,
            Arc::new(first_datagram),
            reporter.clone(),
        )
        .unwrap_or_else(|error| panic!("start first: {error}"));
        let (second, mut second_rx) = IngressRedirectEndpoint::start(
            second_session,
            second_cache,
            Arc::new(NeverSendDatagram {
                inner: Arc::new(second_datagram),
            }),
            reporter,
        )
        .unwrap_or_else(|error| panic!("start second: {error}"));
        let packet = synthetic_native_esp_packet(128);
        assert_eq!(
            tokio::time::timeout(
                Duration::from_millis(200),
                first.redirect(&packet, ownership_key(), generation),
            )
            .await
            .unwrap_or_else(|_| panic!("bounded receipt retry policy")),
            Err(IngressRedirectError::ReceiptTimeout)
        );
        assert!(matches!(
            second_rx.receive().await,
            Ok(IngressRedirectInboundOutcome::Delivered(_))
        ));
        tokio::time::timeout(Duration::from_millis(100), async {
            while second.metrics().transport_drops < 3 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("all receipt sends reached their bound"));
        assert_eq!(second.metrics().transport_drops, 3);
        tokio::time::timeout(Duration::from_millis(100), second.shutdown())
            .await
            .unwrap_or_else(|_| panic!("receipt task shutdown bounded"))
            .unwrap_or_else(|error| panic!("shutdown second: {error}"));
        first
            .shutdown()
            .await
            .unwrap_or_else(|error| panic!("shutdown first: {error}"));
    }

    #[test]
    fn transient_pmtu_refresh_failure_retains_the_last_proven_ceiling() {
        let ceiling = AtomicUsize::new(1_200);
        assert_eq!(
            retain_proven_send_ceiling(&ceiling, Err(IngressRedirectDatagramError::Io)),
            Err(IngressRedirectDatagramError::Io)
        );
        assert_eq!(ceiling.load(Ordering::Acquire), 1_200);
        assert_eq!(retain_proven_send_ceiling(&ceiling, Ok(1_000)), Ok(1_000));
        assert_eq!(ceiling.load(Ordering::Acquire), 1_000);
        assert_eq!(retain_proven_send_ceiling(&ceiling, Ok(1_100)), Ok(1_000));
        assert_eq!(ceiling.load(Ordering::Acquire), 1_000);
    }

    #[tokio::test]
    async fn connected_udp_loopback_preserves_datagrams_and_rejects_truncation() {
        let reserve_first = std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap_or_else(|error| panic!("reserve first port: {error}"));
        let first_endpoint = reserve_first
            .local_addr()
            .unwrap_or_else(|error| panic!("first address: {error}"));
        let reserve_second = std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap_or_else(|error| panic!("reserve second port: {error}"));
        let second_endpoint = reserve_second
            .local_addr()
            .unwrap_or_else(|error| panic!("second address: {error}"));
        drop(reserve_first);
        drop(reserve_second);
        let first = UdpIngressRedirectDatagram::bind(first_endpoint, second_endpoint, 1_280)
            .await
            .unwrap_or_else(|error| panic!("bind first adapter: {error}"));
        let second = UdpIngressRedirectDatagram::bind(second_endpoint, first_endpoint, 1_280)
            .await
            .unwrap_or_else(|error| panic!("bind second adapter: {error}"));
        #[cfg(target_os = "linux")]
        {
            assert_eq!(
                rustix::net::sockopt::ip_mtu_discover(&first.socket)
                    .unwrap_or_else(|error| panic!("read IPv4 PMTU policy: {error}")),
                rustix::net::sockopt::Ipv4PathMtuDiscovery::DO
            );
            assert_eq!(
                first.maximum_send_datagram_size(),
                1_280 - super::super::IPV4_HEADER_BYTES - UDP_HEADER_BYTES
            );
            let message_too_large = std::io::Error::from(rustix::io::Errno::MSGSIZE);
            assert!(io_error_is_message_too_large(&message_too_large));
        }
        let exact = vec![0x5a; second.maximum_receive_datagram_size()];
        first
            .send(&exact)
            .await
            .unwrap_or_else(|error| panic!("send exact datagram: {error}"));
        assert_eq!(
            second
                .receive()
                .await
                .unwrap_or_else(|error| panic!("receive exact datagram: {error}")),
            exact
        );
        let oversize = vec![0x6b; second.maximum_receive_datagram_size() + 1];
        assert_eq!(
            first.send(&oversize).await,
            Err(IngressRedirectDatagramError::DatagramTooLarge)
        );
        drop(first);
        let raw_sender = UdpSocket::bind(first_endpoint)
            .await
            .unwrap_or_else(|error| panic!("bind raw oversize sender: {error}"));
        raw_sender
            .connect(second_endpoint)
            .await
            .unwrap_or_else(|error| panic!("connect raw oversize sender: {error}"));
        raw_sender
            .send(&oversize)
            .await
            .unwrap_or_else(|error| panic!("inject oversize datagram: {error}"));
        assert_eq!(
            second.receive().await,
            Err(IngressRedirectDatagramError::DatagramTooLarge)
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn connected_ipv6_udp_enforces_do_path_mtu_discovery() {
        let Ok(reserve_first) = std::net::UdpSocket::bind("[::1]:0") else {
            return;
        };
        let first_endpoint = reserve_first
            .local_addr()
            .unwrap_or_else(|error| panic!("first IPv6 address: {error}"));
        let reserve_second = std::net::UdpSocket::bind("[::1]:0")
            .unwrap_or_else(|error| panic!("reserve second IPv6 port: {error}"));
        let second_endpoint = reserve_second
            .local_addr()
            .unwrap_or_else(|error| panic!("second IPv6 address: {error}"));
        drop(reserve_first);
        drop(reserve_second);
        let first = UdpIngressRedirectDatagram::bind(first_endpoint, second_endpoint, 1_280)
            .await
            .unwrap_or_else(|error| panic!("bind first IPv6 adapter: {error}"));
        let _second = UdpIngressRedirectDatagram::bind(second_endpoint, first_endpoint, 1_280)
            .await
            .unwrap_or_else(|error| panic!("bind second IPv6 adapter: {error}"));
        assert_eq!(
            rustix::net::sockopt::ipv6_mtu_discover(&first.socket)
                .unwrap_or_else(|error| panic!("read IPv6 PMTU policy: {error}")),
            rustix::net::sockopt::Ipv6PathMtuDiscovery::DO
        );
        assert_eq!(
            first.maximum_send_datagram_size(),
            1_280 - super::super::IPV6_HEADER_BYTES - UDP_HEADER_BYTES
        );
    }

    #[tokio::test]
    async fn in_memory_asymmetric_family_pair_enforces_each_peer_send_ceiling() {
        let first_endpoint: SocketAddr = "192.0.2.1:32001"
            .parse()
            .unwrap_or_else(|error| panic!("valid v4 endpoint: {error}"));
        let second_endpoint: SocketAddr = "[2001:db8::2]:32002"
            .parse()
            .unwrap_or_else(|error| panic!("valid v6 endpoint: {error}"));
        let (first, second) =
            InMemoryIngressRedirectDatagram::pair(first_endpoint, second_endpoint, 1_500, 2)
                .unwrap_or_else(|error| panic!("asymmetric pair: {error}"));
        let first_to_second_exact = vec![0x11; 1_500 - 40 - UDP_HEADER_BYTES];
        first
            .send(&first_to_second_exact)
            .await
            .unwrap_or_else(|error| panic!("v6 ceiling exact: {error}"));
        assert_eq!(
            second
                .receive()
                .await
                .unwrap_or_else(|error| panic!("receive v6 ceiling: {error}")),
            first_to_second_exact
        );
        assert_eq!(
            first
                .send(&vec![0x22; 1_500 - 40 - UDP_HEADER_BYTES + 1])
                .await,
            Err(IngressRedirectDatagramError::DatagramTooLarge)
        );
        let second_to_first_exact = vec![0x33; 1_500 - 20 - UDP_HEADER_BYTES];
        second
            .send(&second_to_first_exact)
            .await
            .unwrap_or_else(|error| panic!("v4 ceiling exact: {error}"));
        assert_eq!(
            first
                .receive()
                .await
                .unwrap_or_else(|error| panic!("receive v4 ceiling: {error}")),
            second_to_first_exact
        );
        assert_eq!(
            second
                .send(&vec![0x44; 1_500 - 20 - UDP_HEADER_BYTES + 1])
                .await,
            Err(IngressRedirectDatagramError::DatagramTooLarge)
        );
    }

    #[tokio::test]
    async fn udp_adapter_rejects_family_mismatch_and_unsafe_endpoints_before_io() {
        let valid_v4: SocketAddr = "127.0.0.1:32001"
            .parse()
            .unwrap_or_else(|error| panic!("valid v4 endpoint: {error}"));
        let valid_v6: SocketAddr = "[::1]:32002"
            .parse()
            .unwrap_or_else(|error| panic!("valid v6 endpoint: {error}"));
        assert!(matches!(
            UdpIngressRedirectDatagram::bind(valid_v4, valid_v6, 1_500).await,
            Err(IngressRedirectDatagramError::InvalidConfiguration)
        ));
        for unsafe_endpoint in [
            "0.0.0.0:32002",
            "224.0.0.1:32002",
            "255.255.255.255:32002",
            "127.0.0.1:0",
        ] {
            let endpoint: SocketAddr = unsafe_endpoint
                .parse()
                .unwrap_or_else(|error| panic!("parse unsafe endpoint: {error}"));
            assert!(matches!(
                UdpIngressRedirectDatagram::bind(valid_v4, endpoint, 1_500).await,
                Err(IngressRedirectDatagramError::InvalidConfiguration)
            ));
            assert!(matches!(
                UdpIngressRedirectDatagram::bind(endpoint, valid_v4, 1_500).await,
                Err(IngressRedirectDatagramError::InvalidConfiguration)
            ));
        }
        let scoped_v6 = SocketAddr::V6(std::net::SocketAddrV6::new(
            "fe80::1"
                .parse()
                .unwrap_or_else(|error| panic!("link-local v6: {error}")),
            32003,
            1,
            2,
        ));
        assert!(matches!(
            UdpIngressRedirectDatagram::bind(valid_v6, scoped_v6, 1_500).await,
            Err(IngressRedirectDatagramError::InvalidConfiguration)
        ));
    }

    #[test]
    fn data_receipt_outcome_and_ptb_debug_are_redacted() {
        let profile = test_profile();
        let (sender, receiver) = test_sessions(profile);
        let packet = synthetic_native_esp_packet(128);
        let sealed = sender
            .seal_data_with_generation(&packet, ownership_key().to_canonical_bytes(), 3, 1)
            .unwrap_or_else(|error| panic!("seal frame: {error}"));
        let AuthenticatedIngressRedirectFrame::Data(data) = receiver
            .open(&sealed)
            .unwrap_or_else(|error| panic!("open frame: {error}"))
        else {
            panic!("data frame")
        };
        let data_debug = format!("{data:?}");
        assert!(data_debug.contains("[redacted]"));
        assert!(!data_debug.contains("192.0.2.10"));
        assert!(!data_debug.contains("01020304"));
        let valid_until = receiver
            .receive_epoch_valid_until(data.epoch().get(), Instant::now())
            .unwrap_or_else(|error| panic!("receive epoch is valid: {error}"));
        let forwardable = ForwardableIngressRedirectPacket {
            data,
            receipt_code: IngressRedirectReceiptCode::NotOwner,
            source_session: Arc::clone(&receiver),
            valid_until,
        };
        let outcome_debug = format!(
            "{:?}",
            IngressRedirectInboundOutcome::Forwardable(forwardable)
        );
        assert!(outcome_debug.contains("[redacted]"));
        assert!(!outcome_debug.contains("192.0.2.10"));
        let event = IngressRedirectPacketTooBigEvent {
            packet: &packet,
            ownership_key: ownership_key(),
            maximum_original_packet: 64,
        };
        let event_debug = format!("{event:?}");
        assert!(event_debug.contains("[redacted]"));
        assert!(!event_debug.contains("192.0.2.10"));
        let receipt = super::super::AuthenticatedIngressRedirectReceipt {
            acknowledged_epoch: IngressRedirectProtectionEpoch(0x1122_3344_5566_7788),
            acknowledged_sequence: 0x8877_6655_4433_2211,
            code: IngressRedirectReceiptCode::Delivered,
        };
        let receipt_debug = format!("{receipt:?}");
        assert!(receipt_debug.contains("[redacted]"));
        assert!(!receipt_debug.contains("1234605616436508552"));
        assert!(!receipt_debug.contains("9833440827789222417"));
    }
}
