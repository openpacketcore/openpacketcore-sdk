//! Safe SCTP transport foundation for OpenPacketCore.
//!
//! The crate keeps all unsafe Linux SCTP UAPI work in `opc-libsctp-sys` and
//! exposes a safe async API for one-to-one and one-to-many SCTP sockets.

#![forbid(unsafe_code)]

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bytes::Bytes;
#[cfg(target_os = "linux")]
use bytes::BytesMut;
use thiserror::Error;

#[cfg(target_os = "linux")]
use std::os::fd::{AsFd, OwnedFd};
#[cfg(target_os = "linux")]
use tokio::io::unix::AsyncFd;

/// NGAP SCTP payload protocol identifier, per 3GPP N2 usage.
pub const NGAP_PPID: PayloadProtocolIdentifier = PayloadProtocolIdentifier::new(60);

/// Host-order SCTP payload protocol identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PayloadProtocolIdentifier(u32);

impl PayloadProtocolIdentifier {
    /// Create a host-order PPID.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Return the host-order value.
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Convert to the network-order representation used by SCTP ancillary data.
    pub const fn to_network_order(self) -> u32 {
        self.0.to_be()
    }

    /// Convert from the network-order representation used by SCTP ancillary data.
    pub const fn from_network_order(value: u32) -> Self {
        Self(u32::from_be(value))
    }
}

impl fmt::Display for PayloadProtocolIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// SCTP socket mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SctpMode {
    /// One-to-one SCTP sockets.
    OneToOne,
    /// One-to-many SCTP sockets.
    OneToMany,
}

/// Delivery ordering for one message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryOrder {
    /// Ordered delivery within the SCTP stream.
    Ordered,
    /// Unordered delivery.
    Unordered,
}

/// INIT parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitConfig {
    /// Number of outbound streams requested.
    pub outbound_streams: u16,
    /// Maximum inbound streams accepted.
    pub inbound_streams: u16,
    /// Maximum INIT retransmission attempts.
    pub max_attempts: u16,
    /// Maximum INIT timeout in milliseconds.
    pub max_init_timeout_ms: u16,
}

impl Default for InitConfig {
    fn default() -> Self {
        Self {
            outbound_streams: 16,
            inbound_streams: 16,
            max_attempts: 4,
            max_init_timeout_ms: 1000,
        }
    }
}

/// Optional RTO policy. Non-default values are intentionally rejected today.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RtoConfig {
    /// Initial RTO in milliseconds.
    pub initial_ms: Option<u32>,
    /// Minimum RTO in milliseconds.
    pub min_ms: Option<u32>,
    /// Maximum RTO in milliseconds.
    pub max_ms: Option<u32>,
}

/// Optional heartbeat policy. Non-default values are intentionally rejected today.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HeartbeatConfig {
    /// Heartbeat interval in milliseconds.
    pub interval_ms: Option<u32>,
    /// Path retransmission threshold.
    pub path_max_retrans: Option<u16>,
}

/// SCTP endpoint configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SctpEndpointConfig {
    /// Socket mode.
    pub mode: SctpMode,
    /// Local bind addresses. Exactly one address is supported today.
    pub local_addrs: Vec<SocketAddr>,
    /// INIT parameters.
    pub init: InitConfig,
    /// Enable SCTP_NODELAY.
    pub nodelay: bool,
    /// Maximum payload bytes accepted by receive operations.
    pub max_message_bytes: usize,
    /// Optional RTO policy.
    pub rto: RtoConfig,
    /// Optional heartbeat policy.
    pub heartbeat: HeartbeatConfig,
}

impl SctpEndpointConfig {
    /// Build a one-to-one endpoint config bound to one address.
    pub fn one_to_one(local_addr: SocketAddr) -> Self {
        Self {
            mode: SctpMode::OneToOne,
            local_addrs: vec![local_addr],
            init: InitConfig::default(),
            nodelay: true,
            max_message_bytes: 1024 * 1024,
            rto: RtoConfig::default(),
            heartbeat: HeartbeatConfig::default(),
        }
    }

    /// Build a one-to-many endpoint config bound to one address.
    pub fn one_to_many(local_addr: SocketAddr) -> Self {
        let mut config = Self::one_to_one(local_addr);
        config.mode = SctpMode::OneToMany;
        config
    }

    /// Validate capability-honest v0.1 constraints.
    pub fn validate(&self) -> Result<(), SctpError> {
        validate_common(
            &self.local_addrs,
            self.init,
            self.max_message_bytes,
            self.rto,
            self.heartbeat,
            "local_addrs",
        )
    }
}

/// SCTP client association configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SctpConnectConfig {
    /// Optional local bind address. At most one address is supported today.
    pub local_addrs: Vec<SocketAddr>,
    /// Remote peer addresses. Exactly one address is supported today.
    pub remote_addrs: Vec<SocketAddr>,
    /// INIT parameters.
    pub init: InitConfig,
    /// Enable SCTP_NODELAY.
    pub nodelay: bool,
    /// Maximum payload bytes accepted by receive operations.
    pub max_message_bytes: usize,
    /// Optional RTO policy.
    pub rto: RtoConfig,
    /// Optional heartbeat policy.
    pub heartbeat: HeartbeatConfig,
}

impl SctpConnectConfig {
    /// Build a client association config to one remote address.
    pub fn new(remote_addr: SocketAddr) -> Self {
        Self {
            local_addrs: Vec::new(),
            remote_addrs: vec![remote_addr],
            init: InitConfig::default(),
            nodelay: true,
            max_message_bytes: 1024 * 1024,
            rto: RtoConfig::default(),
            heartbeat: HeartbeatConfig::default(),
        }
    }

    /// Validate capability-honest v0.1 constraints.
    pub fn validate(&self) -> Result<(), SctpError> {
        validate_common(
            &self.remote_addrs,
            self.init,
            self.max_message_bytes,
            self.rto,
            self.heartbeat,
            "remote_addrs",
        )?;
        if self.local_addrs.len() > 1 {
            return Err(SctpError::UnsupportedFeature {
                feature: "static multihoming local bind",
            });
        }
        if let (Some(local), Some(remote)) = (self.local_addrs.first(), self.remote_addrs.first()) {
            validate_same_family(local, remote)?;
        }
        Ok(())
    }
}

/// Outbound SCTP message metadata and payload.
#[derive(Debug, Clone)]
pub struct OutboundMessage {
    /// Payload bytes.
    pub payload: Bytes,
    /// SCTP stream identifier.
    pub stream_id: u16,
    /// Payload protocol identifier.
    pub ppid: PayloadProtocolIdentifier,
    /// Ordered or unordered delivery.
    pub order: DeliveryOrder,
    /// Target association for one-to-many sockets. Use zero for one-to-one.
    pub assoc_id: i32,
}

impl OutboundMessage {
    /// Create an ordered message.
    pub fn ordered(payload: Bytes, stream_id: u16, ppid: PayloadProtocolIdentifier) -> Self {
        Self {
            payload,
            stream_id,
            ppid,
            order: DeliveryOrder::Ordered,
            assoc_id: 0,
        }
    }
}

/// Inbound SCTP message metadata and payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundMessage {
    /// Payload bytes.
    pub payload: Bytes,
    /// SCTP stream identifier.
    pub stream_id: u16,
    /// Payload protocol identifier.
    pub ppid: PayloadProtocolIdentifier,
    /// Ordered or unordered delivery flag observed from SCTP metadata.
    pub order: DeliveryOrder,
    /// Source association identifier.
    pub assoc_id: i32,
    /// True when the message is an SCTP notification, not user payload.
    pub notification: bool,
    /// True when the caller buffer truncated payload.
    pub truncated: bool,
}

/// Error type for safe SCTP operations. Display text is payload-free.
#[derive(Debug, Error)]
pub enum SctpError {
    /// SCTP is available only on Linux in this crate.
    #[error("SCTP transport is supported only on Linux")]
    UnsupportedPlatform,
    /// A requested SCTP feature is not implemented by this capability profile.
    #[error("SCTP feature is unsupported: {feature}")]
    UnsupportedFeature {
        /// Stable feature label.
        feature: &'static str,
    },
    /// Configuration failed validation.
    #[error("invalid SCTP config field '{field}': {reason}")]
    InvalidConfig {
        /// Stable field label.
        field: &'static str,
        /// Payload-free reason.
        reason: &'static str,
    },
    /// Kernel or socket I/O failed.
    #[error("SCTP {operation} failed")]
    Io {
        /// Stable operation label.
        operation: &'static str,
        /// Source I/O error.
        #[source]
        source: io::Error,
    },
}

/// SCTP metric snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SctpMetricsSnapshot {
    /// Transmitted messages.
    pub tx_messages: u64,
    /// Transmitted payload bytes.
    pub tx_bytes: u64,
    /// Received messages.
    pub rx_messages: u64,
    /// Received payload bytes.
    pub rx_bytes: u64,
    /// Accepted associations.
    pub accepted_associations: u64,
    /// I/O errors observed.
    pub io_errors: u64,
}

/// Low-cardinality SCTP metrics handle.
#[derive(Debug, Clone, Default)]
pub struct SctpMetrics {
    inner: Arc<SctpMetricsInner>,
}

#[derive(Debug, Default)]
struct SctpMetricsInner {
    tx_messages: AtomicU64,
    tx_bytes: AtomicU64,
    rx_messages: AtomicU64,
    rx_bytes: AtomicU64,
    accepted_associations: AtomicU64,
    io_errors: AtomicU64,
}

impl SctpMetrics {
    /// Return a point-in-time snapshot.
    pub fn snapshot(&self) -> SctpMetricsSnapshot {
        SctpMetricsSnapshot {
            tx_messages: self.inner.tx_messages.load(Ordering::Relaxed),
            tx_bytes: self.inner.tx_bytes.load(Ordering::Relaxed),
            rx_messages: self.inner.rx_messages.load(Ordering::Relaxed),
            rx_bytes: self.inner.rx_bytes.load(Ordering::Relaxed),
            accepted_associations: self.inner.accepted_associations.load(Ordering::Relaxed),
            io_errors: self.inner.io_errors.load(Ordering::Relaxed),
        }
    }

    #[cfg(any(target_os = "linux", test))]
    fn record_tx(&self, bytes: usize) {
        self.inner.tx_messages.fetch_add(1, Ordering::Relaxed);
        self.inner
            .tx_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    #[cfg(any(target_os = "linux", test))]
    fn record_rx(&self, bytes: usize) {
        self.inner.rx_messages.fetch_add(1, Ordering::Relaxed);
        self.inner
            .rx_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    #[cfg(any(target_os = "linux", test))]
    fn record_accept(&self) {
        self.inner
            .accepted_associations
            .fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(any(target_os = "linux", test))]
    fn record_io_error(&self) {
        self.inner.io_errors.fetch_add(1, Ordering::Relaxed);
    }
}

/// Health summary for an SCTP endpoint or association.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SctpHealth {
    /// Platform SCTP support is available.
    pub platform_supported: bool,
    /// Socket is open from the wrapper perspective.
    pub socket_open: bool,
    /// Configured socket mode.
    pub mode: SctpMode,
}

/// Bound SCTP endpoint.
#[derive(Debug)]
pub struct SctpEndpoint {
    imp: platform::Endpoint,
}

/// Connected one-to-one SCTP association.
#[derive(Debug)]
pub struct SctpAssociation {
    imp: platform::Association,
}

impl SctpEndpoint {
    /// Bind an SCTP endpoint.
    pub fn bind(config: SctpEndpointConfig) -> Result<Self, SctpError> {
        config.validate()?;
        platform::bind_endpoint(config).map(|imp| Self { imp })
    }

    /// Accept a one-to-one SCTP association.
    pub async fn accept(&self) -> Result<SctpAssociation, SctpError> {
        self.imp.accept().await.map(|imp| SctpAssociation { imp })
    }

    /// Send one message on a one-to-many endpoint.
    pub async fn send(&self, message: OutboundMessage) -> Result<usize, SctpError> {
        self.imp.send(message).await
    }

    /// Receive one message on a one-to-many endpoint.
    pub async fn recv(&self) -> Result<InboundMessage, SctpError> {
        self.imp.recv().await
    }

    /// Return endpoint health.
    pub fn health(&self) -> SctpHealth {
        self.imp.health()
    }

    /// Return endpoint metrics.
    pub fn metrics(&self) -> SctpMetricsSnapshot {
        self.imp.metrics()
    }
}

impl SctpAssociation {
    /// Connect one SCTP association.
    pub async fn connect(config: SctpConnectConfig) -> Result<Self, SctpError> {
        config.validate()?;
        platform::connect_association(config)
            .await
            .map(|imp| Self { imp })
    }

    /// Send one message.
    pub async fn send(&self, message: OutboundMessage) -> Result<usize, SctpError> {
        self.imp.send(message).await
    }

    /// Receive one message.
    pub async fn recv(&self) -> Result<InboundMessage, SctpError> {
        self.imp.recv().await
    }

    /// Return association health.
    pub fn health(&self) -> SctpHealth {
        self.imp.health()
    }

    /// Return association metrics.
    pub fn metrics(&self) -> SctpMetricsSnapshot {
        self.imp.metrics()
    }
}

fn validate_common(
    addresses: &[SocketAddr],
    init: InitConfig,
    max_message_bytes: usize,
    rto: RtoConfig,
    heartbeat: HeartbeatConfig,
    address_field: &'static str,
) -> Result<(), SctpError> {
    if addresses.is_empty() {
        return Err(SctpError::InvalidConfig {
            field: address_field,
            reason: "at least one address is required",
        });
    }
    if addresses.len() > 1 {
        return Err(SctpError::UnsupportedFeature {
            feature: "static multihoming",
        });
    }
    if init.outbound_streams == 0 {
        return Err(SctpError::InvalidConfig {
            field: "init.outbound_streams",
            reason: "must be greater than zero",
        });
    }
    if init.inbound_streams == 0 {
        return Err(SctpError::InvalidConfig {
            field: "init.inbound_streams",
            reason: "must be greater than zero",
        });
    }
    if max_message_bytes == 0 {
        return Err(SctpError::InvalidConfig {
            field: "max_message_bytes",
            reason: "must be greater than zero",
        });
    }
    if rto != RtoConfig::default() {
        return Err(SctpError::UnsupportedFeature {
            feature: "custom RTO parameters",
        });
    }
    if heartbeat != HeartbeatConfig::default() {
        return Err(SctpError::UnsupportedFeature {
            feature: "custom heartbeat parameters",
        });
    }
    Ok(())
}

fn validate_same_family(left: &SocketAddr, right: &SocketAddr) -> Result<(), SctpError> {
    if left.is_ipv4() == right.is_ipv4() {
        Ok(())
    } else {
        Err(SctpError::InvalidConfig {
            field: "address_family",
            reason: "local and remote addresses must use the same IP family",
        })
    }
}

#[cfg(target_os = "linux")]
fn sys_init(init: InitConfig) -> opc_libsctp_sys::InitMsg {
    opc_libsctp_sys::InitMsg {
        outbound_streams: init.outbound_streams,
        inbound_streams: init.inbound_streams,
        max_attempts: init.max_attempts,
        max_init_timeout_ms: init.max_init_timeout_ms,
    }
}

#[cfg(target_os = "linux")]
fn sys_family(addr: &SocketAddr) -> opc_libsctp_sys::AddressFamily {
    if addr.is_ipv4() {
        opc_libsctp_sys::AddressFamily::Ipv4
    } else {
        opc_libsctp_sys::AddressFamily::Ipv6
    }
}

#[cfg(target_os = "linux")]
fn sys_style(mode: SctpMode) -> opc_libsctp_sys::SocketStyle {
    match mode {
        SctpMode::OneToOne => opc_libsctp_sys::SocketStyle::OneToOne,
        SctpMode::OneToMany => opc_libsctp_sys::SocketStyle::OneToMany,
    }
}

#[cfg(any(target_os = "linux", test))]
fn sys_send_info(message: &OutboundMessage) -> opc_libsctp_sys::SendInfo {
    let mut flags = 0_u16;
    if message.order == DeliveryOrder::Unordered {
        flags |= opc_libsctp_sys::SCTP_UNORDERED_FLAG;
    }
    opc_libsctp_sys::SendInfo {
        stream_id: message.stream_id,
        flags,
        ppid_network_order: message.ppid.to_network_order(),
        context: 0,
        assoc_id: message.assoc_id,
    }
}

#[cfg(target_os = "linux")]
fn map_recv(received: opc_libsctp_sys::Received, buffer: BytesMut) -> InboundMessage {
    let info = received.info.unwrap_or(opc_libsctp_sys::RecvInfo {
        stream_id: 0,
        ssn: 0,
        flags: 0,
        ppid_network_order: 0,
        tsn: 0,
        cumulative_tsn: 0,
        context: 0,
        assoc_id: 0,
    });
    let order = if (info.flags & opc_libsctp_sys::SCTP_UNORDERED_FLAG) != 0 {
        DeliveryOrder::Unordered
    } else {
        DeliveryOrder::Ordered
    };
    InboundMessage {
        payload: buffer.freeze(),
        stream_id: info.stream_id,
        ppid: PayloadProtocolIdentifier::from_network_order(info.ppid_network_order),
        order,
        assoc_id: info.assoc_id,
        notification: received.flags.notification,
        truncated: received.flags.payload_truncated || received.flags.control_truncated,
    }
}

#[cfg(target_os = "linux")]
fn io_err(operation: &'static str, source: io::Error) -> SctpError {
    SctpError::Io { operation, source }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;

    #[derive(Debug)]
    pub struct Endpoint {
        socket: Arc<SctpSocket>,
        mode: SctpMode,
    }

    #[derive(Debug)]
    pub struct Association {
        socket: Arc<SctpSocket>,
        mode: SctpMode,
    }

    #[derive(Debug)]
    struct SctpSocket {
        fd: AsyncFd<OwnedFd>,
        max_message_bytes: usize,
        metrics: SctpMetrics,
    }

    pub fn bind_endpoint(config: SctpEndpointConfig) -> Result<Endpoint, SctpError> {
        let local = config.local_addrs[0];
        let fd = opc_libsctp_sys::open_socket(sys_family(&local), sys_style(config.mode))
            .map_err(|source| io_err("socket", source))?;
        configure_fd(fd.as_fd(), config.init, config.nodelay)?;
        opc_libsctp_sys::bind(fd.as_fd(), &local).map_err(|source| io_err("bind", source))?;
        if config.mode == SctpMode::OneToOne {
            opc_libsctp_sys::listen(fd.as_fd(), 128).map_err(|source| io_err("listen", source))?;
        }
        let async_fd = AsyncFd::new(fd).map_err(|source| io_err("async_fd", source))?;
        Ok(Endpoint {
            socket: Arc::new(SctpSocket {
                fd: async_fd,
                max_message_bytes: config.max_message_bytes,
                metrics: SctpMetrics::default(),
            }),
            mode: config.mode,
        })
    }

    pub async fn connect_association(config: SctpConnectConfig) -> Result<Association, SctpError> {
        let remote = config.remote_addrs[0];
        let fd = opc_libsctp_sys::open_socket(sys_family(&remote), sys_style(SctpMode::OneToOne))
            .map_err(|source| io_err("socket", source))?;
        configure_fd(fd.as_fd(), config.init, config.nodelay)?;
        if let Some(local) = config.local_addrs.first() {
            opc_libsctp_sys::bind(fd.as_fd(), local).map_err(|source| io_err("bind", source))?;
        }
        let status = opc_libsctp_sys::connect(fd.as_fd(), &remote)
            .map_err(|source| io_err("connect", source))?;
        let async_fd = AsyncFd::new(fd).map_err(|source| io_err("async_fd", source))?;
        let socket = Arc::new(SctpSocket {
            fd: async_fd,
            max_message_bytes: config.max_message_bytes,
            metrics: SctpMetrics::default(),
        });
        if status == opc_libsctp_sys::ConnectStatus::InProgress {
            wait_connected(&socket).await?;
        }
        Ok(Association {
            socket,
            mode: SctpMode::OneToOne,
        })
    }

    impl Endpoint {
        pub async fn accept(&self) -> Result<Association, SctpError> {
            if self.mode != SctpMode::OneToOne {
                return Err(SctpError::InvalidConfig {
                    field: "mode",
                    reason: "accept is valid only for one-to-one sockets",
                });
            }
            loop {
                let mut guard = self
                    .socket
                    .fd
                    .readable()
                    .await
                    .map_err(|source| io_err("accept_ready", source))?;
                match guard.try_io(|inner| opc_libsctp_sys::accept(inner.get_ref().as_fd())) {
                    Ok(Ok((fd, _peer))) => {
                        let async_fd =
                            AsyncFd::new(fd).map_err(|source| io_err("async_fd", source))?;
                        self.socket.metrics.record_accept();
                        return Ok(Association {
                            socket: Arc::new(SctpSocket {
                                fd: async_fd,
                                max_message_bytes: self.socket.max_message_bytes,
                                metrics: self.socket.metrics.clone(),
                            }),
                            mode: SctpMode::OneToOne,
                        });
                    }
                    Ok(Err(source)) => {
                        self.socket.metrics.record_io_error();
                        return Err(io_err("accept", source));
                    }
                    Err(_would_block) => continue,
                }
            }
        }

        pub async fn send(&self, message: OutboundMessage) -> Result<usize, SctpError> {
            if self.mode != SctpMode::OneToMany {
                return Err(SctpError::InvalidConfig {
                    field: "mode",
                    reason: "endpoint send is valid only for one-to-many sockets",
                });
            }
            self.socket.send(message).await
        }

        pub async fn recv(&self) -> Result<InboundMessage, SctpError> {
            if self.mode != SctpMode::OneToMany {
                return Err(SctpError::InvalidConfig {
                    field: "mode",
                    reason: "endpoint recv is valid only for one-to-many sockets",
                });
            }
            self.socket.recv().await
        }

        pub fn health(&self) -> SctpHealth {
            SctpHealth {
                platform_supported: true,
                socket_open: true,
                mode: self.mode,
            }
        }

        pub fn metrics(&self) -> SctpMetricsSnapshot {
            self.socket.metrics.snapshot()
        }
    }

    impl Association {
        pub async fn send(&self, message: OutboundMessage) -> Result<usize, SctpError> {
            self.socket.send(message).await
        }

        pub async fn recv(&self) -> Result<InboundMessage, SctpError> {
            self.socket.recv().await
        }

        pub fn health(&self) -> SctpHealth {
            SctpHealth {
                platform_supported: true,
                socket_open: true,
                mode: self.mode,
            }
        }

        pub fn metrics(&self) -> SctpMetricsSnapshot {
            self.socket.metrics.snapshot()
        }
    }

    impl SctpSocket {
        async fn send(&self, message: OutboundMessage) -> Result<usize, SctpError> {
            let info = sys_send_info(&message);
            loop {
                let mut guard = self
                    .fd
                    .writable()
                    .await
                    .map_err(|source| io_err("send_ready", source))?;
                match guard.try_io(|inner| {
                    opc_libsctp_sys::send_msg(inner.get_ref().as_fd(), &message.payload, info)
                }) {
                    Ok(Ok(bytes)) => {
                        self.metrics.record_tx(bytes);
                        tracing::trace!(bytes, stream_id = message.stream_id, ppid = %message.ppid, "sctp message sent");
                        return Ok(bytes);
                    }
                    Ok(Err(source)) => {
                        self.metrics.record_io_error();
                        return Err(io_err("send", source));
                    }
                    Err(_would_block) => continue,
                }
            }
        }

        async fn recv(&self) -> Result<InboundMessage, SctpError> {
            let mut buffer = BytesMut::zeroed(self.max_message_bytes);
            loop {
                let mut guard = self
                    .fd
                    .readable()
                    .await
                    .map_err(|source| io_err("recv_ready", source))?;
                match guard
                    .try_io(|inner| opc_libsctp_sys::recv_msg(inner.get_ref().as_fd(), &mut buffer))
                {
                    Ok(Ok(received)) => {
                        buffer.truncate(received.bytes);
                        self.metrics.record_rx(received.bytes);
                        let message = map_recv(received, buffer);
                        tracing::trace!(
                            bytes = message.payload.len(),
                            stream_id = message.stream_id,
                            ppid = %message.ppid,
                            notification = message.notification,
                            "sctp message received"
                        );
                        return Ok(message);
                    }
                    Ok(Err(source)) => {
                        self.metrics.record_io_error();
                        return Err(io_err("recv", source));
                    }
                    Err(_would_block) => continue,
                }
            }
        }
    }

    fn configure_fd(
        fd: std::os::fd::BorrowedFd<'_>,
        init: InitConfig,
        nodelay: bool,
    ) -> Result<(), SctpError> {
        opc_libsctp_sys::set_initmsg(fd, sys_init(init))
            .map_err(|source| io_err("set_initmsg", source))?;
        opc_libsctp_sys::set_nodelay(fd, nodelay)
            .map_err(|source| io_err("set_nodelay", source))?;
        opc_libsctp_sys::set_recv_rcvinfo(fd, true)
            .map_err(|source| io_err("set_recv_rcvinfo", source))?;
        opc_libsctp_sys::set_events(fd, opc_libsctp_sys::EventSubscriptions::default())
            .map_err(|source| io_err("set_events", source))?;
        Ok(())
    }

    async fn wait_connected(socket: &SctpSocket) -> Result<(), SctpError> {
        loop {
            let mut guard = socket
                .fd
                .writable()
                .await
                .map_err(|source| io_err("connect_ready", source))?;
            match guard.try_io(|inner| opc_libsctp_sys::socket_error(inner.get_ref().as_fd())) {
                Ok(Ok(None)) => return Ok(()),
                Ok(Ok(Some(source))) => {
                    socket.metrics.record_io_error();
                    return Err(io_err("connect", source));
                }
                Ok(Err(source)) => {
                    socket.metrics.record_io_error();
                    return Err(io_err("connect", source));
                }
                Err(_would_block) => continue,
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use super::*;

    #[derive(Debug)]
    pub struct Endpoint;

    #[derive(Debug)]
    pub struct Association;

    pub fn bind_endpoint(_config: SctpEndpointConfig) -> Result<Endpoint, SctpError> {
        Err(SctpError::UnsupportedPlatform)
    }

    pub async fn connect_association(_config: SctpConnectConfig) -> Result<Association, SctpError> {
        Err(SctpError::UnsupportedPlatform)
    }

    impl Endpoint {
        pub async fn accept(&self) -> Result<Association, SctpError> {
            let _ = self;
            Err(SctpError::UnsupportedPlatform)
        }

        pub async fn send(&self, message: OutboundMessage) -> Result<usize, SctpError> {
            let _ = (self, message);
            Err(SctpError::UnsupportedPlatform)
        }

        pub async fn recv(&self) -> Result<InboundMessage, SctpError> {
            let _ = self;
            Err(SctpError::UnsupportedPlatform)
        }

        pub fn health(&self) -> SctpHealth {
            let _ = self;
            SctpHealth {
                platform_supported: false,
                socket_open: false,
                mode: SctpMode::OneToOne,
            }
        }

        pub fn metrics(&self) -> SctpMetricsSnapshot {
            let _ = self;
            SctpMetricsSnapshot::default()
        }
    }

    impl Association {
        pub async fn send(&self, message: OutboundMessage) -> Result<usize, SctpError> {
            let _ = (self, message);
            Err(SctpError::UnsupportedPlatform)
        }

        pub async fn recv(&self) -> Result<InboundMessage, SctpError> {
            let _ = self;
            Err(SctpError::UnsupportedPlatform)
        }

        pub fn health(&self) -> SctpHealth {
            let _ = self;
            SctpHealth {
                platform_supported: false,
                socket_open: false,
                mode: SctpMode::OneToOne,
            }
        }

        pub fn metrics(&self) -> SctpMetricsSnapshot {
            let _ = self;
            SctpMetricsSnapshot::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ngap_ppid_network_order_round_trip() {
        let network = NGAP_PPID.to_network_order();
        assert_eq!(
            PayloadProtocolIdentifier::from_network_order(network),
            NGAP_PPID
        );
        assert_eq!(NGAP_PPID.get(), 60);
    }

    #[test]
    fn endpoint_config_rejects_empty_addresses() {
        let mut config = SctpEndpointConfig::one_to_one("127.0.0.1:38412".parse().unwrap());
        config.local_addrs.clear();
        assert!(matches!(
            config.validate(),
            Err(SctpError::InvalidConfig {
                field: "local_addrs",
                ..
            })
        ));
    }

    #[test]
    fn endpoint_config_rejects_multihoming_until_bindx_boundary_exists() {
        let mut config = SctpEndpointConfig::one_to_one("127.0.0.1:38412".parse().unwrap());
        config.local_addrs.push("127.0.0.2:38412".parse().unwrap());
        assert!(matches!(
            config.validate(),
            Err(SctpError::UnsupportedFeature {
                feature: "static multihoming"
            })
        ));
    }

    #[test]
    fn config_rejects_custom_rto_and_heartbeat_until_layouts_are_bound() {
        let mut config = SctpEndpointConfig::one_to_one("127.0.0.1:38412".parse().unwrap());
        config.rto.initial_ms = Some(100);
        assert!(matches!(
            config.validate(),
            Err(SctpError::UnsupportedFeature {
                feature: "custom RTO parameters"
            })
        ));

        let mut config = SctpEndpointConfig::one_to_one("127.0.0.1:38412".parse().unwrap());
        config.heartbeat.interval_ms = Some(1000);
        assert!(matches!(
            config.validate(),
            Err(SctpError::UnsupportedFeature {
                feature: "custom heartbeat parameters"
            })
        ));
    }

    #[test]
    fn connect_config_rejects_address_family_mismatch() {
        let mut config = SctpConnectConfig::new("[::1]:38412".parse().unwrap());
        config.local_addrs.push("127.0.0.1:0".parse().unwrap());
        assert!(matches!(
            config.validate(),
            Err(SctpError::InvalidConfig {
                field: "address_family",
                ..
            })
        ));
    }

    #[test]
    fn outbound_unordered_sets_sctp_flag() {
        let mut message = OutboundMessage::ordered(Bytes::from_static(b"abc"), 7, NGAP_PPID);
        message.order = DeliveryOrder::Unordered;
        let info = sys_send_info(&message);
        assert_eq!(info.stream_id, 7);
        assert_eq!(info.ppid_network_order, NGAP_PPID.to_network_order());
        assert_ne!(info.flags & opc_libsctp_sys::SCTP_UNORDERED_FLAG, 0);
    }

    #[test]
    fn metrics_snapshot_counts_without_labels() {
        let metrics = SctpMetrics::default();
        metrics.record_tx(11);
        metrics.record_rx(13);
        metrics.record_accept();
        metrics.record_io_error();
        assert_eq!(
            metrics.snapshot(),
            SctpMetricsSnapshot {
                tx_messages: 1,
                tx_bytes: 11,
                rx_messages: 1,
                rx_bytes: 13,
                accepted_associations: 1,
                io_errors: 1,
            }
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn bind_fails_closed_on_unsupported_platform() {
        let config = SctpEndpointConfig::one_to_one("127.0.0.1:38412".parse().unwrap());
        assert!(matches!(
            SctpEndpoint::bind(config),
            Err(SctpError::UnsupportedPlatform)
        ));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires Linux kernel SCTP support"]
    async fn loopback_one_to_one_smoke() {
        let server_addr: SocketAddr = "127.0.0.1:38412".parse().unwrap();
        let server = SctpEndpoint::bind(SctpEndpointConfig::one_to_one(server_addr)).unwrap();
        let client = SctpAssociation::connect(SctpConnectConfig::new(server_addr))
            .await
            .unwrap();
        let accepted = server.accept().await.unwrap();

        client
            .send(OutboundMessage::ordered(
                Bytes::from_static(b"ngap"),
                0,
                NGAP_PPID,
            ))
            .await
            .unwrap();
        let received = accepted.recv().await.unwrap();
        assert_eq!(received.payload, Bytes::from_static(b"ngap"));
        assert_eq!(received.ppid, NGAP_PPID);
    }
}
