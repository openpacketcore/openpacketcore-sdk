//! Safe SCTP transport foundation for OpenPacketCore.
//!
//! The crate keeps all unsafe Linux SCTP UAPI work in `opc-libsctp-sys` and
//! exposes a safe async API for one-to-one and one-to-many SCTP sockets.

#![forbid(unsafe_code)]

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use bytes::Bytes;
#[cfg(target_os = "linux")]
use bytes::BytesMut;
use thiserror::Error;

#[cfg(target_os = "linux")]
use std::os::fd::{AsFd, OwnedFd};
#[cfg(target_os = "linux")]
use tokio::io::unix::AsyncFd;

#[cfg(target_os = "linux")]
const SCTP_RECV_CHUNK_BYTES: usize = 64 * 1024;

/// Maximum number of addresses accepted in one static SCTP multihoming set.
pub const MAX_STATIC_MULTIHOMING_ADDRESSES: usize = opc_libsctp_sys::MAX_SCTP_ADDRESSES;

/// NGAP SCTP payload protocol identifier, per 3GPP N2 usage.
pub const NGAP_PPID: PayloadProtocolIdentifier = PayloadProtocolIdentifier::new(60);

/// Diameter SCTP payload protocol identifier for clear-text SCTP DATA chunks.
///
/// RFC 6733 assigns PPID 46 to Diameter over SCTP without DTLS.
pub const DIAMETER_SCTP_PPID: PayloadProtocolIdentifier = PayloadProtocolIdentifier::new(46);

/// Diameter SCTP payload protocol identifier for DTLS/SCTP DATA chunks.
///
/// RFC 6733 assigns PPID 47 to Diameter over protected DTLS/SCTP.
pub const DIAMETER_DTLS_SCTP_PPID: PayloadProtocolIdentifier = PayloadProtocolIdentifier::new(47);

/// Default SCTP stream used by the Diameter SCTP helper.
pub const DIAMETER_DEFAULT_STREAM_ID: u16 = 0;

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
    /// Local bind addresses. Multiple addresses form one static multihoming set.
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

    /// Validate endpoint constraints before opening a socket.
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
    /// Optional local bind addresses for the association.
    pub local_addrs: Vec<SocketAddr>,
    /// Remote peer address set, passed to the kernel in the configured order.
    /// Path selection within the set is owned by the SCTP stack.
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

    /// Validate association constraints before opening a socket.
    pub fn validate(&self) -> Result<(), SctpError> {
        validate_common(
            &self.remote_addrs,
            self.init,
            self.max_message_bytes,
            self.rto,
            self.heartbeat,
            "remote_addrs",
        )?;
        if !self.local_addrs.is_empty() {
            validate_address_set(&self.local_addrs, "local_addrs")?;
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

/// Security profile for Diameter over SCTP metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiameterSctpSecurity {
    /// Diameter carried directly in SCTP DATA chunks.
    ClearText,
    /// Diameter carried in protected DTLS/SCTP DATA chunks.
    Dtls,
}

impl DiameterSctpSecurity {
    /// Return the PPID required for this Diameter SCTP security profile.
    #[must_use]
    pub const fn ppid(self) -> PayloadProtocolIdentifier {
        match self {
            Self::ClearText => DIAMETER_SCTP_PPID,
            Self::Dtls => DIAMETER_DTLS_SCTP_PPID,
        }
    }
}

/// Diameter SCTP peer transport intent for one resolved remote address.
#[derive(Clone, PartialEq, Eq)]
pub struct DiameterSctpPeer {
    /// Resolved remote Diameter peer address.
    pub remote_addr: SocketAddr,
    /// Optional local bind address.
    pub local_addr: Option<SocketAddr>,
    /// Diameter SCTP security profile.
    pub security: DiameterSctpSecurity,
    /// Maximum SCTP user payload accepted for one Diameter message.
    pub max_message_bytes: usize,
}

impl fmt::Debug for DiameterSctpPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DiameterSctpPeer")
            .field("remote_addr", &"<redacted>")
            .field("local_addr", &self.local_addr.map(|_| "<redacted>"))
            .field("security", &self.security)
            .field("max_message_bytes", &self.max_message_bytes)
            .finish()
    }
}

impl DiameterSctpPeer {
    /// Create a clear-text Diameter SCTP peer intent for one remote address.
    #[must_use]
    pub fn new(remote_addr: SocketAddr) -> Self {
        let default_config = SctpConnectConfig::new(remote_addr);
        Self {
            remote_addr,
            local_addr: None,
            security: DiameterSctpSecurity::ClearText,
            max_message_bytes: default_config.max_message_bytes,
        }
    }

    /// Return a copy that binds the SCTP association from one local address.
    #[must_use]
    pub fn with_local_addr(mut self, local_addr: SocketAddr) -> Self {
        self.local_addr = Some(local_addr);
        self
    }

    /// Return a copy that uses the requested Diameter SCTP security profile.
    #[must_use]
    pub fn with_security(mut self, security: DiameterSctpSecurity) -> Self {
        self.security = security;
        self
    }

    /// Return a copy that uses the requested maximum message size.
    #[must_use]
    pub fn with_max_message_bytes(mut self, max_message_bytes: usize) -> Self {
        self.max_message_bytes = max_message_bytes;
        self
    }

    /// Build and validate the SDK SCTP client association configuration.
    ///
    /// # Errors
    ///
    /// Returns [`DiameterSctpError`] when the projected SCTP config violates
    /// the capability profile, including unsupported multihoming or invalid
    /// address-family combinations.
    pub fn sctp_connect_config(&self) -> Result<SctpConnectConfig, DiameterSctpError> {
        let mut config = SctpConnectConfig::new(self.remote_addr);
        if let Some(local_addr) = self.local_addr {
            config.local_addrs.push(local_addr);
        }
        config.max_message_bytes = self.max_message_bytes;
        config.validate().map_err(DiameterSctpError::from)?;
        Ok(config)
    }

    /// Wrap an encoded Diameter message with outbound SCTP metadata.
    #[must_use]
    pub fn outbound_message(&self, payload: Bytes) -> OutboundMessage {
        OutboundMessage::ordered(payload, DIAMETER_DEFAULT_STREAM_ID, self.security.ppid())
    }

    /// Validate inbound SCTP metadata before Diameter payload decode.
    ///
    /// # Errors
    ///
    /// Returns [`DiameterSctpError`] when SCTP delivered a notification, a
    /// truncated payload, or a message tagged with the wrong Diameter PPID.
    pub fn validate_inbound_message(
        &self,
        message: &InboundMessage,
    ) -> Result<(), DiameterSctpError> {
        if message.notification {
            return Err(DiameterSctpError::Notification);
        }
        if message.truncated {
            return Err(DiameterSctpError::Truncated);
        }
        let expected = self.security.ppid();
        if message.ppid != expected {
            return Err(DiameterSctpError::WrongPpid {
                expected: expected.get(),
                actual: message.ppid.get(),
            });
        }
        Ok(())
    }

    /// Return inbound payload bytes after SCTP metadata validation.
    ///
    /// # Errors
    ///
    /// Returns [`DiameterSctpError`] for the same metadata failures as
    /// [`Self::validate_inbound_message`].
    pub fn inbound_payload<'a>(
        &self,
        message: &'a InboundMessage,
    ) -> Result<&'a Bytes, DiameterSctpError> {
        self.validate_inbound_message(message)?;
        Ok(&message.payload)
    }

    /// Open a live SDK SCTP association to this Diameter peer.
    ///
    /// # Errors
    ///
    /// Returns [`DiameterSctpError`] when config validation fails or the
    /// association cannot be opened on the current platform/runtime.
    pub async fn connect_association(&self) -> Result<DiameterSctpAssociation, DiameterSctpError> {
        let config = self.sctp_connect_config()?;
        DiameterSctpAssociation::connect_with_config(config, self.security).await
    }
}

/// Live Diameter SCTP association opened by SDK SCTP.
#[derive(Debug)]
pub struct DiameterSctpAssociation {
    peer: DiameterSctpPeer,
    association: SctpAssociation,
}

impl DiameterSctpAssociation {
    /// Open a Diameter-framed association from an explicit SCTP client config.
    ///
    /// This is the Diameter counterpart to [`SctpAssociation::connect`] and
    /// preserves the complete local and remote address sets in `config`.
    /// Callers can therefore use static SCTP multihoming without duplicating
    /// the SDK's Diameter PPID and notification handling. The first configured
    /// remote and local addresses are exposed through [`Self::peer`] only as
    /// the primary transport intent; SCTP remains authoritative for path
    /// selection across the full validated sets.
    ///
    /// # Errors
    ///
    /// Returns [`DiameterSctpError::SctpConfig`] when `config` is invalid, or
    /// [`DiameterSctpError::SctpConnect`] when the platform, kernel, namespace,
    /// or peer cannot open the requested association. A host that lacks static
    /// multihoming reports [`SctpError::CapabilityUnavailable`]; this function
    /// never silently reduces the configured address sets.
    pub async fn connect_with_config(
        config: SctpConnectConfig,
        security: DiameterSctpSecurity,
    ) -> Result<Self, DiameterSctpError> {
        config.validate().map_err(DiameterSctpError::from)?;
        let Some(&remote_addr) = config.remote_addrs.first() else {
            return Err(DiameterSctpError::from(SctpError::InvalidConfig {
                field: "remote_addrs",
                reason: "must contain at least one address",
            }));
        };
        let peer = DiameterSctpPeer {
            remote_addr,
            local_addr: config.local_addrs.first().copied(),
            security,
            max_message_bytes: config.max_message_bytes,
        };
        let association = SctpAssociation::connect(config)
            .await
            .map_err(DiameterSctpError::connect)?;
        Ok(Self { peer, association })
    }

    /// Return the configured Diameter SCTP peer intent.
    #[must_use]
    pub const fn peer(&self) -> &DiameterSctpPeer {
        &self.peer
    }

    /// Send one encoded Diameter payload with the peer's required PPID.
    ///
    /// # Errors
    ///
    /// Returns [`DiameterSctpError`] when the SDK SCTP send fails.
    pub async fn send_diameter_payload(&self, payload: Bytes) -> Result<usize, DiameterSctpError> {
        self.association
            .send(self.peer.outbound_message(payload))
            .await
            .map_err(DiameterSctpError::send)
    }

    /// Receive one Diameter payload after SCTP metadata validation.
    ///
    /// SCTP event notifications (COMM_UP, peer address change, sender-dry,
    /// ...) interleave with data on the association and are skipped: they are
    /// transport events, not Diameter payloads. Callers bound the read with
    /// their own response timeout.
    ///
    /// # Errors
    ///
    /// Returns [`DiameterSctpError`] when receive fails or the SCTP metadata is
    /// not valid for this peer's Diameter security profile.
    pub async fn recv_diameter_payload(&self) -> Result<Bytes, DiameterSctpError> {
        loop {
            let message = self
                .association
                .recv()
                .await
                .map_err(DiameterSctpError::recv)?;
            if message.notification {
                // A shutdown notification is followed by the association
                // actually closing, so the next recv surfaces
                // `SctpError::Closed` instead of spinning here.
                continue;
            }
            self.peer.validate_inbound_message(&message)?;
            return Ok(message.payload);
        }
    }

    /// Return SDK SCTP association health.
    #[must_use]
    pub fn health(&self) -> SctpHealth {
        self.association.health()
    }

    /// Return SDK SCTP association metrics.
    #[must_use]
    pub fn metrics(&self) -> SctpMetricsSnapshot {
        self.association.metrics()
    }
}

/// Redaction-safe outcome for one Diameter SCTP connect attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiameterSctpConnectOutcome {
    /// SDK opened a live SCTP association.
    Connected,
    /// SDK reports SCTP is unavailable on this platform.
    UnsupportedPlatform,
    /// SDK rejected or failed the connect attempt.
    Failed,
}

impl DiameterSctpConnectOutcome {
    /// Stable machine name for this outcome.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::Failed => "failed",
        }
    }
}

/// Redaction-safe projection for one Diameter SCTP connect attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiameterSctpConnectProjection {
    /// Connect attempt outcome.
    pub outcome: DiameterSctpConnectOutcome,
    /// Whether a live SCTP association was opened.
    pub connected: bool,
    /// Whether the attempt failed because SCTP is unsupported on this host.
    pub unsupported_platform: bool,
    /// Stable error code for failed attempts.
    pub error_code: Option<&'static str>,
}

impl DiameterSctpConnectProjection {
    /// Build a projection for a successful connect attempt.
    #[must_use]
    pub const fn connected() -> Self {
        Self {
            outcome: DiameterSctpConnectOutcome::Connected,
            connected: true,
            unsupported_platform: false,
            error_code: None,
        }
    }

    /// Build a projection for a failed precondition or runtime attempt.
    #[must_use]
    pub const fn failed(error_code: &'static str) -> Self {
        Self {
            outcome: DiameterSctpConnectOutcome::Failed,
            connected: false,
            unsupported_platform: false,
            error_code: Some(error_code),
        }
    }

    /// Build a projection from a failed connect attempt.
    #[must_use]
    pub fn from_error(error: &DiameterSctpError) -> Self {
        let unsupported_platform = error.is_unsupported_platform();
        Self {
            outcome: if unsupported_platform {
                DiameterSctpConnectOutcome::UnsupportedPlatform
            } else {
                DiameterSctpConnectOutcome::Failed
            },
            connected: false,
            unsupported_platform,
            error_code: Some(error.as_str()),
        }
    }
}

/// Error type for Diameter SCTP transport intent and metadata validation.
#[derive(Debug)]
pub enum DiameterSctpError {
    /// SDK SCTP config validation failed.
    SctpConfig(SctpError),
    /// SDK SCTP connect failed.
    SctpConnect(SctpError),
    /// SDK SCTP send failed.
    SctpSend(SctpError),
    /// SDK SCTP receive failed.
    SctpRecv(SctpError),
    /// SCTP delivered a notification instead of a Diameter payload.
    Notification,
    /// SCTP reported payload truncation.
    Truncated,
    /// SCTP PPID did not match the selected Diameter security profile.
    WrongPpid {
        /// Expected PPID.
        expected: u32,
        /// Observed PPID.
        actual: u32,
    },
}

impl DiameterSctpError {
    fn connect(error: SctpError) -> Self {
        Self::SctpConnect(error)
    }

    fn send(error: SctpError) -> Self {
        Self::SctpSend(error)
    }

    fn recv(error: SctpError) -> Self {
        Self::SctpRecv(error)
    }

    /// Stable machine-readable error code for evidence and status projection.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::SctpConfig(_) => "diameter_sctp_config_error",
            Self::SctpConnect(SctpError::UnsupportedPlatform) => {
                "diameter_sctp_unsupported_platform"
            }
            Self::SctpConnect(SctpError::CapabilityUnavailable { .. }) => {
                "diameter_sctp_capability_unavailable"
            }
            Self::SctpConnect(_) => "diameter_sctp_connect_error",
            Self::SctpSend(_) => "diameter_sctp_send_error",
            Self::SctpRecv(_) => "diameter_sctp_recv_error",
            Self::Notification => "diameter_sctp_notification",
            Self::Truncated => "diameter_sctp_truncated_payload",
            Self::WrongPpid { .. } => "diameter_sctp_wrong_ppid",
        }
    }

    /// Return whether the connect failed because SCTP is unsupported.
    #[must_use]
    pub const fn is_unsupported_platform(&self) -> bool {
        matches!(self, Self::SctpConnect(SctpError::UnsupportedPlatform))
    }
}

impl From<SctpError> for DiameterSctpError {
    fn from(error: SctpError) -> Self {
        Self::SctpConfig(error)
    }
}

impl fmt::Display for DiameterSctpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SctpConfig(error) => write!(f, "diameter_sctp_config_error: {error}"),
            Self::SctpConnect(SctpError::UnsupportedPlatform) => {
                f.write_str("diameter_sctp_unsupported_platform")
            }
            Self::SctpConnect(error) => write!(f, "diameter_sctp_connect_error: {error}"),
            Self::SctpSend(error) => write!(f, "diameter_sctp_send_error: {error}"),
            Self::SctpRecv(error) => write!(f, "diameter_sctp_recv_error: {error}"),
            Self::Notification => f.write_str("diameter_sctp_notification"),
            Self::Truncated => f.write_str("diameter_sctp_truncated_payload"),
            Self::WrongPpid { expected, actual } => {
                write!(
                    f,
                    "diameter_sctp_wrong_ppid: expected {expected}, actual {actual}"
                )
            }
        }
    }
}

impl std::error::Error for DiameterSctpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SctpConfig(error)
            | Self::SctpConnect(error)
            | Self::SctpSend(error)
            | Self::SctpRecv(error) => Some(error),
            Self::Notification | Self::Truncated | Self::WrongPpid { .. } => None,
        }
    }
}

/// Parsed SCTP notification event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SctpEvent {
    /// Association state changed.
    AssociationChange {
        /// Kernel SCTP association state value.
        state: u16,
        /// Kernel SCTP association error value.
        error: u16,
        /// Outbound stream count reported by the kernel.
        outbound_streams: u16,
        /// Inbound stream count reported by the kernel.
        inbound_streams: u16,
        /// Association identifier.
        assoc_id: i32,
    },
    /// Peer shutdown notification.
    Shutdown {
        /// Association identifier.
        assoc_id: i32,
    },
    /// Notification type not decoded by this crate yet.
    Unknown {
        /// Kernel SCTP notification type.
        notification_type: u16,
    },
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
    /// Parsed SCTP event when this message is a known notification.
    pub event: Option<SctpEvent>,
    /// True when the caller buffer truncated payload.
    pub truncated: bool,
    /// True when the kernel truncated ancillary control data. The payload is
    /// intact, but SCTP metadata (stream/PPID/association) may be incomplete.
    pub control_truncated: bool,
}

/// Error type for safe SCTP operations. Display text is payload-free.
#[derive(Debug, Error)]
pub enum SctpError {
    /// SCTP is available only on Linux in this crate.
    #[error("SCTP transport is supported only on Linux")]
    UnsupportedPlatform,
    /// A requested SCTP feature is outside this capability profile.
    #[error("SCTP feature is unsupported: {feature}")]
    UnsupportedFeature {
        /// Stable feature label.
        feature: &'static str,
    },
    /// The API supports a feature, but this kernel or namespace does not.
    #[error("SCTP capability is unavailable: {capability}")]
    CapabilityUnavailable {
        /// Stable capability label suitable for fallback policy.
        capability: &'static str,
        /// Kernel error that established unavailability.
        #[source]
        source: io::Error,
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
    /// The peer closed the association or socket.
    #[error("SCTP association is closed")]
    Closed,
    /// The kernel accepted only part of a message send.
    #[error("SCTP short send: expected {expected} bytes, sent {actual}")]
    ShortSend {
        /// Expected payload byte count.
        expected: usize,
        /// Actual byte count accepted by the kernel.
        actual: usize,
    },
    /// A received SCTP message exceeded the configured receive cap.
    #[error("SCTP message exceeded max_message_bytes ({max_message_bytes})")]
    MessageTooLarge {
        /// Configured receive cap.
        max_message_bytes: usize,
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

/// Capabilities available from this build of the SCTP transport.
///
/// A Linux kernel or container policy can still reject multihoming for a
/// particular socket. That case is returned as
/// [`SctpError::CapabilityUnavailable`] so consumers can explicitly retry a
/// single-address configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SctpCapabilities {
    /// This build has a supported SCTP platform implementation.
    pub platform_supported: bool,
    /// This build exposes bounded static bindx/connectx support.
    pub static_multihoming: bool,
}

/// Return SCTP capabilities for the current build target.
#[must_use]
pub const fn capabilities() -> SctpCapabilities {
    SctpCapabilities {
        platform_supported: cfg!(target_os = "linux"),
        static_multihoming: cfg!(target_os = "linux"),
    }
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

    /// Return the addresses the kernel bound to this endpoint.
    pub fn local_addresses(&self) -> Result<Vec<SocketAddr>, SctpError> {
        self.imp.local_addresses()
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

    /// Return the local addresses active on this association.
    pub fn local_addresses(&self) -> Result<Vec<SocketAddr>, SctpError> {
        self.imp.local_addresses()
    }

    /// Return the peer addresses active on this association.
    pub fn peer_addresses(&self) -> Result<Vec<SocketAddr>, SctpError> {
        self.imp.peer_addresses()
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
    validate_address_set(addresses, address_field)?;
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

fn validate_address_set(
    addresses: &[SocketAddr],
    address_field: &'static str,
) -> Result<(), SctpError> {
    let Some(first) = addresses.first() else {
        return Err(SctpError::InvalidConfig {
            field: address_field,
            reason: "at least one address is required",
        });
    };
    if addresses.len() > MAX_STATIC_MULTIHOMING_ADDRESSES {
        return Err(SctpError::InvalidConfig {
            field: address_field,
            reason: "address count exceeds the bounded maximum",
        });
    }
    if addresses
        .iter()
        .any(|address| address.is_ipv4() != first.is_ipv4())
    {
        return Err(SctpError::InvalidConfig {
            field: "address_family",
            reason: "all addresses must use the same IP family",
        });
    }
    if addresses
        .iter()
        .any(|address| address.port() != first.port())
    {
        return Err(SctpError::InvalidConfig {
            field: address_field,
            reason: "all addresses must use the same port",
        });
    }
    if addresses.len() > 1
        && addresses
            .iter()
            .any(|address| address.ip().is_unspecified())
    {
        return Err(SctpError::InvalidConfig {
            field: address_field,
            reason: "wildcard addresses cannot be combined with an address set",
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
    let event = if received.flags.notification {
        parse_sctp_event(&buffer)
    } else {
        None
    };
    InboundMessage {
        payload: buffer.freeze(),
        stream_id: info.stream_id,
        ppid: PayloadProtocolIdentifier::from_network_order(info.ppid_network_order),
        order,
        assoc_id: info.assoc_id,
        notification: received.flags.notification,
        event,
        truncated: received.flags.payload_truncated,
        control_truncated: received.flags.control_truncated,
    }
}

#[cfg(any(target_os = "linux", test))]
fn parse_sctp_event(payload: &[u8]) -> Option<SctpEvent> {
    let notification_type = read_u16_ne(payload, 0)?;
    let declared_len = read_u32_ne(payload, 4)? as usize;
    if declared_len < 8 || declared_len > payload.len() {
        return None;
    }
    let payload = &payload[..declared_len];

    match notification_type {
        opc_libsctp_sys::SCTP_ASSOC_CHANGE_NOTIFICATION => Some(SctpEvent::AssociationChange {
            state: read_u16_ne(payload, 8)?,
            error: read_u16_ne(payload, 10)?,
            outbound_streams: read_u16_ne(payload, 12)?,
            inbound_streams: read_u16_ne(payload, 14)?,
            assoc_id: read_i32_ne(payload, 16)?,
        }),
        opc_libsctp_sys::SCTP_SHUTDOWN_EVENT_NOTIFICATION => Some(SctpEvent::Shutdown {
            assoc_id: read_i32_ne(payload, 8)?,
        }),
        other => Some(SctpEvent::Unknown {
            notification_type: other,
        }),
    }
}

#[cfg(any(target_os = "linux", test))]
fn read_u16_ne(bytes: &[u8], offset: usize) -> Option<u16> {
    let slice = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_ne_bytes([slice[0], slice[1]]))
}

#[cfg(any(target_os = "linux", test))]
fn read_u32_ne(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_ne_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

#[cfg(any(target_os = "linux", test))]
fn read_i32_ne(bytes: &[u8], offset: usize) -> Option<i32> {
    let slice = bytes.get(offset..offset.checked_add(4)?)?;
    Some(i32::from_ne_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

#[cfg(target_os = "linux")]
fn io_err(operation: &'static str, source: io::Error) -> SctpError {
    SctpError::Io { operation, source }
}

#[cfg(target_os = "linux")]
fn multihoming_io_err(operation: &'static str, source: io::Error) -> SctpError {
    if opc_libsctp_sys::is_multihoming_unavailable(&source) {
        SctpError::CapabilityUnavailable {
            capability: "static_multihoming",
            source,
        }
    } else {
        io_err(operation, source)
    }
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
        closed: AtomicBool,
    }

    pub fn bind_endpoint(config: SctpEndpointConfig) -> Result<Endpoint, SctpError> {
        let local = config.local_addrs[0];
        let fd = opc_libsctp_sys::open_socket(sys_family(&local), sys_style(config.mode))
            .map_err(|source| io_err("socket", source))?;
        configure_fd(fd.as_fd(), config.init, config.nodelay)?;
        if config.local_addrs.len() == 1 {
            opc_libsctp_sys::bind(fd.as_fd(), &local).map_err(|source| io_err("bind", source))?;
        } else {
            opc_libsctp_sys::bind_addresses(fd.as_fd(), &config.local_addrs)
                .map_err(|source| multihoming_io_err("bind_addresses", source))?;
        }
        opc_libsctp_sys::listen(fd.as_fd(), 128).map_err(|source| io_err("listen", source))?;
        let async_fd = AsyncFd::new(fd).map_err(|source| io_err("async_fd", source))?;
        Ok(Endpoint {
            socket: Arc::new(SctpSocket {
                fd: async_fd,
                max_message_bytes: config.max_message_bytes,
                metrics: SctpMetrics::default(),
                closed: AtomicBool::new(false),
            }),
            mode: config.mode,
        })
    }

    pub async fn connect_association(config: SctpConnectConfig) -> Result<Association, SctpError> {
        let remote = config.remote_addrs[0];
        let fd = opc_libsctp_sys::open_socket(sys_family(&remote), sys_style(SctpMode::OneToOne))
            .map_err(|source| io_err("socket", source))?;
        configure_fd(fd.as_fd(), config.init, config.nodelay)?;
        if config.local_addrs.len() == 1 {
            opc_libsctp_sys::bind(fd.as_fd(), &config.local_addrs[0])
                .map_err(|source| io_err("bind", source))?;
        } else if !config.local_addrs.is_empty() {
            opc_libsctp_sys::bind_addresses(fd.as_fd(), &config.local_addrs)
                .map_err(|source| multihoming_io_err("bind_addresses", source))?;
        }
        let status = if config.remote_addrs.len() == 1 {
            opc_libsctp_sys::connect(fd.as_fd(), &remote)
                .map_err(|source| io_err("connect", source))?
        } else {
            opc_libsctp_sys::connect_addresses(fd.as_fd(), &config.remote_addrs)
                .map_err(|source| multihoming_io_err("connect_addresses", source))?
        };
        let async_fd = AsyncFd::new(fd).map_err(|source| io_err("async_fd", source))?;
        let socket = Arc::new(SctpSocket {
            fd: async_fd,
            max_message_bytes: config.max_message_bytes,
            metrics: SctpMetrics::default(),
            closed: AtomicBool::new(false),
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
                                closed: AtomicBool::new(false),
                            }),
                            mode: SctpMode::OneToOne,
                        });
                    }
                    Ok(Err(source)) if source.kind() == io::ErrorKind::Interrupted => continue,
                    Ok(Err(source)) => {
                        self.socket.mark_closed();
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
                socket_open: self.socket.is_open(),
                mode: self.mode,
            }
        }

        pub fn metrics(&self) -> SctpMetricsSnapshot {
            self.socket.metrics.snapshot()
        }

        pub fn local_addresses(&self) -> Result<Vec<SocketAddr>, SctpError> {
            opc_libsctp_sys::local_addresses(self.socket.fd.get_ref().as_fd(), 0)
                .map_err(|source| io_err("local_addresses", source))
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
                socket_open: self.socket.is_open(),
                mode: self.mode,
            }
        }

        pub fn metrics(&self) -> SctpMetricsSnapshot {
            self.socket.metrics.snapshot()
        }

        pub fn local_addresses(&self) -> Result<Vec<SocketAddr>, SctpError> {
            opc_libsctp_sys::local_addresses(self.socket.fd.get_ref().as_fd(), 0)
                .map_err(|source| io_err("local_addresses", source))
        }

        pub fn peer_addresses(&self) -> Result<Vec<SocketAddr>, SctpError> {
            opc_libsctp_sys::peer_addresses(self.socket.fd.get_ref().as_fd(), 0)
                .map_err(|source| io_err("peer_addresses", source))
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
                        if bytes != message.payload.len() {
                            self.mark_closed();
                            self.metrics.record_io_error();
                            return Err(SctpError::ShortSend {
                                expected: message.payload.len(),
                                actual: bytes,
                            });
                        }
                        self.metrics.record_tx(bytes);
                        tracing::trace!(bytes, stream_id = message.stream_id, ppid = %message.ppid, "sctp message sent");
                        return Ok(bytes);
                    }
                    Ok(Err(source)) if source.kind() == io::ErrorKind::Interrupted => continue,
                    Ok(Err(source)) => {
                        self.mark_closed();
                        self.metrics.record_io_error();
                        return Err(io_err("send", source));
                    }
                    Err(_would_block) => continue,
                }
            }
        }

        async fn recv(&self) -> Result<InboundMessage, SctpError> {
            let mut payload = BytesMut::new();
            let mut first_received = None;
            let mut payload_truncated = false;
            let mut control_truncated = false;
            loop {
                let remaining = self.max_message_bytes.saturating_sub(payload.len());
                if remaining == 0 {
                    self.mark_closed();
                    self.metrics.record_io_error();
                    return Err(SctpError::MessageTooLarge {
                        max_message_bytes: self.max_message_bytes,
                    });
                }
                let chunk_len = remaining.min(SCTP_RECV_CHUNK_BYTES);
                let mut buffer = BytesMut::zeroed(chunk_len);
                let received = self.recv_chunk(&mut buffer).await?;
                if received.bytes == 0 && !received.flags.notification {
                    self.mark_closed();
                    self.metrics.record_io_error();
                    return Err(SctpError::Closed);
                }
                buffer.truncate(received.bytes);

                if received.flags.notification {
                    self.metrics.record_rx(received.bytes);
                    let message = map_recv(received, buffer);
                    tracing::trace!(
                        bytes = message.payload.len(),
                        stream_id = message.stream_id,
                        ppid = %message.ppid,
                        notification = message.notification,
                        "sctp notification received"
                    );
                    return Ok(message);
                }

                let first = first_received.get_or_insert(received);
                payload_truncated |= received.flags.payload_truncated;
                control_truncated |= received.flags.control_truncated;
                payload.extend_from_slice(&buffer);

                if received.flags.end_of_record {
                    let mut complete = *first;
                    complete.bytes = payload.len();
                    complete.flags.end_of_record = true;
                    complete.flags.payload_truncated = payload_truncated;
                    complete.flags.control_truncated = control_truncated;
                    self.metrics.record_rx(payload.len());
                    let message = map_recv(complete, payload);
                    tracing::trace!(
                        bytes = message.payload.len(),
                        stream_id = message.stream_id,
                        ppid = %message.ppid,
                        notification = message.notification,
                        "sctp message received"
                    );
                    return Ok(message);
                }
                if payload.len() >= self.max_message_bytes {
                    self.mark_closed();
                    self.metrics.record_io_error();
                    return Err(SctpError::MessageTooLarge {
                        max_message_bytes: self.max_message_bytes,
                    });
                }
            }
        }

        async fn recv_chunk(
            &self,
            buffer: &mut BytesMut,
        ) -> Result<opc_libsctp_sys::Received, SctpError> {
            loop {
                let mut guard = self
                    .fd
                    .readable()
                    .await
                    .map_err(|source| io_err("recv_ready", source))?;
                match guard
                    .try_io(|inner| opc_libsctp_sys::recv_msg(inner.get_ref().as_fd(), buffer))
                {
                    Ok(Ok(received)) => return Ok(received),
                    Ok(Err(source)) if source.kind() == io::ErrorKind::Interrupted => continue,
                    Ok(Err(source)) => {
                        self.mark_closed();
                        self.metrics.record_io_error();
                        return Err(io_err("recv", source));
                    }
                    Err(_would_block) => continue,
                }
            }
        }

        fn is_open(&self) -> bool {
            !self.closed.load(Ordering::Relaxed)
        }

        fn mark_closed(&self) {
            self.closed.store(true, Ordering::Relaxed);
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
                    socket.mark_closed();
                    socket.metrics.record_io_error();
                    return Err(io_err("connect", source));
                }
                Ok(Err(source)) if source.kind() == io::ErrorKind::Interrupted => continue,
                Ok(Err(source)) => {
                    socket.mark_closed();
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

        pub fn local_addresses(&self) -> Result<Vec<SocketAddr>, SctpError> {
            let _ = self;
            Err(SctpError::UnsupportedPlatform)
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

        pub fn local_addresses(&self) -> Result<Vec<SocketAddr>, SctpError> {
            let _ = self;
            Err(SctpError::UnsupportedPlatform)
        }

        pub fn peer_addresses(&self) -> Result<Vec<SocketAddr>, SctpError> {
            let _ = self;
            Err(SctpError::UnsupportedPlatform)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn diameter_peer() -> DiameterSctpPeer {
        DiameterSctpPeer::new("127.0.0.1:3868".parse().unwrap())
    }

    fn diameter_inbound(ppid: PayloadProtocolIdentifier) -> InboundMessage {
        InboundMessage {
            payload: Bytes::from_static(b"diameter"),
            stream_id: DIAMETER_DEFAULT_STREAM_ID,
            ppid,
            order: DeliveryOrder::Ordered,
            assoc_id: 7,
            notification: false,
            event: None,
            truncated: false,
            control_truncated: false,
        }
    }

    fn push_u16_ne(out: &mut Vec<u8>, value: u16) {
        out.extend_from_slice(&value.to_ne_bytes());
    }

    fn push_u32_ne(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(&value.to_ne_bytes());
    }

    fn push_i32_ne(out: &mut Vec<u8>, value: i32) {
        out.extend_from_slice(&value.to_ne_bytes());
    }

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
    fn diameter_ppids_match_rfc_6733_values() {
        assert_eq!(DIAMETER_SCTP_PPID.get(), 46);
        assert_eq!(DIAMETER_DTLS_SCTP_PPID.get(), 47);
        assert_eq!(DiameterSctpSecurity::ClearText.ppid(), DIAMETER_SCTP_PPID);
        assert_eq!(DiameterSctpSecurity::Dtls.ppid(), DIAMETER_DTLS_SCTP_PPID);

        let network = DIAMETER_SCTP_PPID.to_network_order();
        assert_eq!(
            PayloadProtocolIdentifier::from_network_order(network),
            DIAMETER_SCTP_PPID
        );
    }

    #[test]
    fn parses_assoc_change_notification_event() {
        let mut payload = Vec::new();
        push_u16_ne(
            &mut payload,
            opc_libsctp_sys::SCTP_ASSOC_CHANGE_NOTIFICATION,
        );
        push_u16_ne(&mut payload, 0);
        push_u32_ne(&mut payload, 20);
        push_u16_ne(&mut payload, 1);
        push_u16_ne(&mut payload, 0);
        push_u16_ne(&mut payload, 16);
        push_u16_ne(&mut payload, 32);
        push_i32_ne(&mut payload, 7);

        assert_eq!(
            parse_sctp_event(&payload),
            Some(SctpEvent::AssociationChange {
                state: 1,
                error: 0,
                outbound_streams: 16,
                inbound_streams: 32,
                assoc_id: 7,
            })
        );
    }

    #[test]
    fn parses_shutdown_notification_event() {
        let mut payload = Vec::new();
        push_u16_ne(
            &mut payload,
            opc_libsctp_sys::SCTP_SHUTDOWN_EVENT_NOTIFICATION,
        );
        push_u16_ne(&mut payload, 0);
        push_u32_ne(&mut payload, 12);
        push_i32_ne(&mut payload, 9);

        assert_eq!(
            parse_sctp_event(&payload),
            Some(SctpEvent::Shutdown { assoc_id: 9 })
        );
    }

    #[test]
    fn diameter_peer_projects_sctp_connect_config() {
        let peer = diameter_peer()
            .with_local_addr("127.0.0.1:0".parse().unwrap())
            .with_max_message_bytes(4096);

        let config = peer.sctp_connect_config().unwrap();

        assert_eq!(config.remote_addrs, vec![peer.remote_addr]);
        assert_eq!(config.local_addrs, vec![peer.local_addr.unwrap()]);
        assert_eq!(config.max_message_bytes, 4096);
        assert!(config.nodelay);
    }

    #[test]
    fn diameter_peer_rejects_invalid_sctp_config() {
        let peer = diameter_peer().with_local_addr("[::1]:0".parse().unwrap());

        let error = peer.sctp_connect_config().unwrap_err();

        assert!(matches!(error, DiameterSctpError::SctpConfig(_)));
        assert_eq!(error.as_str(), "diameter_sctp_config_error");
        assert_eq!(
            DiameterSctpConnectProjection::from_error(&error),
            DiameterSctpConnectProjection {
                outcome: DiameterSctpConnectOutcome::Failed,
                connected: false,
                unsupported_platform: false,
                error_code: Some("diameter_sctp_config_error"),
            }
        );
    }

    #[test]
    fn diameter_peer_rejects_zero_max_message_bytes() {
        let peer = diameter_peer().with_max_message_bytes(0);

        let error = peer.sctp_connect_config().unwrap_err();

        assert!(matches!(error, DiameterSctpError::SctpConfig(_)));
        assert_eq!(error.as_str(), "diameter_sctp_config_error");
    }

    #[tokio::test]
    async fn diameter_connect_rejects_invalid_config_before_socket_open() {
        let peer = diameter_peer().with_local_addr("[::1]:0".parse().unwrap());

        let error = peer.connect_association().await.unwrap_err();

        assert!(matches!(error, DiameterSctpError::SctpConfig(_)));
        assert_eq!(error.as_str(), "diameter_sctp_config_error");
    }

    #[tokio::test]
    async fn diameter_explicit_connect_rejects_invalid_config_before_socket_open() {
        let mut config = SctpConnectConfig::new("127.0.0.1:3868".parse().unwrap());
        config.remote_addrs.clear();

        let error =
            DiameterSctpAssociation::connect_with_config(config, DiameterSctpSecurity::ClearText)
                .await
                .unwrap_err();

        assert!(matches!(error, DiameterSctpError::SctpConfig(_)));
        assert_eq!(error.as_str(), "diameter_sctp_config_error");
    }

    #[test]
    fn diameter_capability_unavailable_has_distinct_error_code() {
        let error = DiameterSctpError::SctpConnect(SctpError::CapabilityUnavailable {
            capability: "static_multihoming",
            source: std::io::Error::from(std::io::ErrorKind::Unsupported),
        });

        assert_eq!(error.as_str(), "diameter_sctp_capability_unavailable");
        assert!(!error.is_unsupported_platform());
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn diameter_connect_reports_unsupported_platform_on_non_linux() {
        let error = diameter_peer().connect_association().await.unwrap_err();

        assert!(matches!(
            error,
            DiameterSctpError::SctpConnect(SctpError::UnsupportedPlatform)
        ));
        assert_eq!(error.as_str(), "diameter_sctp_unsupported_platform");

        let projection = DiameterSctpConnectProjection::from_error(&error);
        assert_eq!(
            projection.outcome,
            DiameterSctpConnectOutcome::UnsupportedPlatform
        );
        assert!(!projection.connected);
        assert!(projection.unsupported_platform);
        assert_eq!(
            projection.error_code,
            Some("diameter_sctp_unsupported_platform")
        );
    }

    #[test]
    fn diameter_outbound_message_uses_selected_ppid() {
        let clear = diameter_peer().outbound_message(Bytes::from_static(b"diameter"));
        assert_eq!(clear.stream_id, DIAMETER_DEFAULT_STREAM_ID);
        assert_eq!(clear.ppid, DIAMETER_SCTP_PPID);
        assert_eq!(clear.order, DeliveryOrder::Ordered);

        let protected = diameter_peer()
            .with_security(DiameterSctpSecurity::Dtls)
            .outbound_message(Bytes::from_static(b"diameter"));
        assert_eq!(protected.ppid, DIAMETER_DTLS_SCTP_PPID);
    }

    #[test]
    fn diameter_inbound_validation_rejects_non_payload_conditions() {
        let peer = diameter_peer();

        let mut notification = diameter_inbound(DIAMETER_SCTP_PPID);
        notification.notification = true;
        let error = peer.validate_inbound_message(&notification).unwrap_err();
        assert_eq!(error.as_str(), "diameter_sctp_notification");

        let mut truncated = diameter_inbound(DIAMETER_SCTP_PPID);
        truncated.truncated = true;
        let error = peer.validate_inbound_message(&truncated).unwrap_err();
        assert_eq!(error.as_str(), "diameter_sctp_truncated_payload");
    }

    #[test]
    fn diameter_inbound_validation_checks_selected_ppid() {
        let peer = diameter_peer();
        let message = diameter_inbound(DIAMETER_SCTP_PPID);

        let payload = peer.inbound_payload(&message).unwrap();

        assert_eq!(payload, &Bytes::from_static(b"diameter"));

        let error = peer
            .validate_inbound_message(&diameter_inbound(DIAMETER_DTLS_SCTP_PPID))
            .unwrap_err();
        assert!(matches!(
            error,
            DiameterSctpError::WrongPpid {
                expected: 46,
                actual: 47
            }
        ));
        assert_eq!(error.as_str(), "diameter_sctp_wrong_ppid");
    }

    #[test]
    fn diameter_connect_projection_classifies_success_and_failures() {
        let connected = DiameterSctpConnectProjection::connected();
        assert_eq!(connected.outcome, DiameterSctpConnectOutcome::Connected);
        assert_eq!(connected.outcome.as_str(), "connected");
        assert!(connected.connected);
        assert!(!connected.unsupported_platform);
        assert_eq!(connected.error_code, None);

        let failed = DiameterSctpConnectProjection::failed("diameter_peer_unresolved");
        assert_eq!(failed.outcome, DiameterSctpConnectOutcome::Failed);
        assert_eq!(failed.outcome.as_str(), "failed");
        assert!(!failed.connected);
        assert!(!failed.unsupported_platform);
        assert_eq!(failed.error_code, Some("diameter_peer_unresolved"));

        let unsupported = DiameterSctpError::SctpConnect(SctpError::UnsupportedPlatform);
        let projection = DiameterSctpConnectProjection::from_error(&unsupported);
        assert_eq!(
            projection.outcome,
            DiameterSctpConnectOutcome::UnsupportedPlatform
        );
        assert_eq!(projection.outcome.as_str(), "unsupported_platform");
        assert!(!projection.connected);
        assert!(projection.unsupported_platform);
        assert_eq!(
            projection.error_code,
            Some("diameter_sctp_unsupported_platform")
        );

        let failed = DiameterSctpError::SctpSend(SctpError::UnsupportedFeature {
            feature: "test-only",
        });
        let projection = DiameterSctpConnectProjection::from_error(&failed);
        assert_eq!(projection.outcome, DiameterSctpConnectOutcome::Failed);
        assert!(!projection.connected);
        assert!(!projection.unsupported_platform);
        assert_eq!(projection.error_code, Some("diameter_sctp_send_error"));
    }

    #[test]
    fn diameter_peer_debug_redacts_socket_addresses() {
        let peer = diameter_peer().with_local_addr("127.0.0.1:0".parse().unwrap());

        let debug = format!("{peer:?}");

        assert!(debug.contains("DiameterSctpPeer"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("127.0.0.1"));
        assert!(!debug.contains("3868"));
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
    fn endpoint_config_accepts_bounded_same_family_multihoming() {
        let mut config = SctpEndpointConfig::one_to_one("127.0.0.1:38412".parse().unwrap());
        config.local_addrs.push("127.0.0.2:38412".parse().unwrap());
        assert!(config.validate().is_ok());

        config.local_addrs.push("[::1]:38412".parse().unwrap());
        assert!(matches!(
            config.validate(),
            Err(SctpError::InvalidConfig {
                field: "address_family",
                ..
            })
        ));
    }

    #[test]
    fn config_rejects_mixed_ports_and_unbounded_address_sets() {
        let mut mixed_ports = SctpEndpointConfig::one_to_one("127.0.0.1:38412".parse().unwrap());
        mixed_ports
            .local_addrs
            .push("127.0.0.2:38413".parse().unwrap());
        assert!(matches!(
            mixed_ports.validate(),
            Err(SctpError::InvalidConfig {
                field: "local_addrs",
                ..
            })
        ));

        let mut wildcard = SctpEndpointConfig::one_to_one("0.0.0.0:38412".parse().unwrap());
        wildcard
            .local_addrs
            .push("127.0.0.1:38412".parse().unwrap());
        assert!(matches!(
            wildcard.validate(),
            Err(SctpError::InvalidConfig {
                field: "local_addrs",
                ..
            })
        ));

        let mut unbounded = SctpEndpointConfig::one_to_one("127.0.0.1:38412".parse().unwrap());
        unbounded.local_addrs = (1..=MAX_STATIC_MULTIHOMING_ADDRESSES)
            .map(|last| {
                SocketAddr::new(std::net::Ipv4Addr::new(127, 0, 0, last as u8).into(), 38412)
            })
            .collect();
        assert!(unbounded.validate().is_ok());
        unbounded
            .local_addrs
            .push("127.0.1.1:38412".parse().unwrap());
        assert!(matches!(
            unbounded.validate(),
            Err(SctpError::InvalidConfig {
                field: "local_addrs",
                ..
            })
        ));
    }

    #[test]
    fn capabilities_advertise_static_multihoming_on_linux() {
        let capabilities = capabilities();
        assert_eq!(capabilities.platform_supported, cfg!(target_os = "linux"));
        assert_eq!(capabilities.static_multihoming, cfg!(target_os = "linux"));
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
    fn connect_config_validates_every_local_and_remote_address() {
        let mut config = SctpConnectConfig::new("127.0.0.1:38412".parse().unwrap());
        config.remote_addrs.push("127.0.0.2:38412".parse().unwrap());
        config.local_addrs.extend([
            "127.0.0.3:0".parse::<SocketAddr>().unwrap(),
            "127.0.0.4:0".parse::<SocketAddr>().unwrap(),
        ]);
        assert!(config.validate().is_ok());

        config.remote_addrs.push("[::1]:38412".parse().unwrap());
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
    async fn recv_data(association: &SctpAssociation) -> InboundMessage {
        loop {
            let message = association.recv().await.unwrap();
            if !message.notification {
                return message;
            }
        }
    }

    #[cfg(target_os = "linux")]
    struct SctpPathDrop {
        delete_rules: Vec<Vec<String>>,
    }

    #[cfg(target_os = "linux")]
    impl SctpPathDrop {
        fn install(server_ip: &str, server_port: u16) -> Self {
            let port = server_port.to_string();
            let rules = [
                vec![
                    "-p",
                    "sctp",
                    "-s",
                    server_ip,
                    "--sport",
                    port.as_str(),
                    "-j",
                    "DROP",
                ],
                vec![
                    "-p",
                    "sctp",
                    "-d",
                    server_ip,
                    "--dport",
                    port.as_str(),
                    "-j",
                    "DROP",
                ],
            ];
            let mut guard = Self {
                delete_rules: Vec::with_capacity(rules.len()),
            };
            for rule in rules {
                let mut insert = vec!["-w", "5", "-I", "OUTPUT", "1"];
                insert.extend(rule.iter().copied());
                run_iptables(&insert);

                let mut delete = vec![
                    "-w".to_string(),
                    "5".to_string(),
                    "-D".to_string(),
                    "OUTPUT".to_string(),
                ];
                delete.extend(rule.into_iter().map(str::to_string));
                guard.delete_rules.push(delete);
            }
            guard
        }

        fn remove(mut self) {
            while let Some(rule) = self.delete_rules.last() {
                let status = std::process::Command::new("sudo")
                    .arg("-n")
                    .arg("iptables")
                    .args(rule)
                    .status()
                    .expect("remove iptables SCTP qualification rule");
                assert!(
                    status.success(),
                    "iptables SCTP qualification cleanup failed"
                );
                self.delete_rules.pop();
            }
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for SctpPathDrop {
        fn drop(&mut self) {
            for rule in self.delete_rules.iter().rev() {
                let _ = std::process::Command::new("sudo")
                    .arg("-n")
                    .arg("iptables")
                    .args(rule)
                    .status();
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn run_iptables(args: &[&str]) {
        let status = std::process::Command::new("sudo")
            .arg("-n")
            .arg("iptables")
            .args(args)
            .status()
            .expect("execute iptables for SCTP qualification");
        assert!(status.success(), "iptables SCTP qualification rule failed");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires Linux kernel SCTP support"]
    async fn loopback_data_message_reports_intact_metadata() {
        let server_addr: SocketAddr = "127.0.0.1:38413".parse().unwrap();
        let server = SctpEndpoint::bind(SctpEndpointConfig::one_to_one(server_addr)).unwrap();
        let client = SctpAssociation::connect(SctpConnectConfig::new(server_addr))
            .await
            .unwrap();
        let accepted = server.accept().await.unwrap();

        let payload = Bytes::from(vec![0x5A_u8; 300]);
        client
            .send(OutboundMessage::ordered(
                payload.clone(),
                1,
                DIAMETER_SCTP_PPID,
            ))
            .await
            .unwrap();

        let received = recv_data(&accepted).await;
        assert_eq!(received.payload, payload);
        assert!(!received.truncated);
        assert!(!received.control_truncated);
        assert_eq!(received.stream_id, 1);
        assert_eq!(received.ppid, DIAMETER_SCTP_PPID);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires Linux kernel SCTP support"]
    async fn loopback_multi_chunk_message_is_not_reported_truncated() {
        let server_addr: SocketAddr = "127.0.0.1:38414".parse().unwrap();
        let server = SctpEndpoint::bind(SctpEndpointConfig::one_to_one(server_addr)).unwrap();
        let client = SctpAssociation::connect(SctpConnectConfig::new(server_addr))
            .await
            .unwrap();
        let accepted = server.accept().await.unwrap();

        // Larger than SCTP_RECV_CHUNK_BYTES so receive spans multiple chunks.
        let payload = Bytes::from(vec![0xC3_u8; 100_000]);
        client
            .send(OutboundMessage::ordered(
                payload.clone(),
                2,
                DIAMETER_SCTP_PPID,
            ))
            .await
            .unwrap();

        let received = recv_data(&accepted).await;
        assert_eq!(received.payload.len(), payload.len());
        assert_eq!(received.payload, payload);
        assert!(!received.truncated);
        assert!(!received.control_truncated);
        assert_eq!(received.stream_id, 2);
        assert_eq!(received.ppid, DIAMETER_SCTP_PPID);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires Linux kernel SCTP support"]
    async fn loopback_oversized_message_still_fails_closed() {
        let server_addr: SocketAddr = "127.0.0.1:38415".parse().unwrap();
        let mut config = SctpEndpointConfig::one_to_one(server_addr);
        config.max_message_bytes = 1024;
        let server = SctpEndpoint::bind(config).unwrap();
        let client = SctpAssociation::connect(SctpConnectConfig::new(server_addr))
            .await
            .unwrap();
        let accepted = server.accept().await.unwrap();

        client
            .send(OutboundMessage::ordered(
                Bytes::from(vec![0x7E_u8; 4096]),
                0,
                DIAMETER_SCTP_PPID,
            ))
            .await
            .unwrap();

        loop {
            match accepted.recv().await {
                Ok(message) if message.notification => continue,
                Ok(message) => panic!(
                    "oversized message was delivered ({} bytes)",
                    message.payload.len()
                ),
                Err(SctpError::MessageTooLarge { max_message_bytes }) => {
                    assert_eq!(max_message_bytes, 1024);
                    break;
                }
                Err(error) => panic!("unexpected receive error: {error}"),
            }
        }
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
        let received = recv_data(&accepted).await;
        assert_eq!(received.payload, Bytes::from_static(b"ngap"));
        assert_eq!(received.ppid, NGAP_PPID);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires Linux kernel SCTP multihoming support"]
    async fn loopback_static_multihoming_binds_and_connects_full_sets() {
        let mut server_config = SctpEndpointConfig::one_to_one("127.0.0.1:0".parse().unwrap());
        server_config
            .local_addrs
            .push("127.0.0.2:0".parse().unwrap());
        let server = SctpEndpoint::bind(server_config).unwrap();
        let mut server_addresses = server.local_addresses().unwrap();
        server_addresses.sort_unstable();
        assert_eq!(server_addresses.len(), 2);
        assert_eq!(server_addresses[0].ip().to_string(), "127.0.0.1");
        assert_eq!(server_addresses[1].ip().to_string(), "127.0.0.2");
        assert_ne!(server_addresses[0].port(), 0);
        assert_eq!(server_addresses[0].port(), server_addresses[1].port());

        let mut client_config = SctpConnectConfig::new(server_addresses[0]);
        client_config.remote_addrs = server_addresses.clone();
        client_config.local_addrs = vec![
            "127.0.0.3:0".parse().unwrap(),
            "127.0.0.4:0".parse().unwrap(),
        ];
        let client = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            SctpAssociation::connect(client_config),
        )
        .await
        .expect("multihomed connect timed out")
        .unwrap();
        let accepted = tokio::time::timeout(std::time::Duration::from_secs(5), server.accept())
            .await
            .expect("multihomed accept timed out")
            .unwrap();

        let mut client_local = client.local_addresses().unwrap();
        client_local.sort_unstable();
        assert_eq!(client_local.len(), 2);
        assert_eq!(client_local[0].ip().to_string(), "127.0.0.3");
        assert_eq!(client_local[1].ip().to_string(), "127.0.0.4");

        let mut client_peer = client.peer_addresses().unwrap();
        client_peer.sort_unstable();
        assert_eq!(client_peer, server_addresses);

        client
            .send(OutboundMessage::ordered(
                Bytes::from_static(b"multihomed-sctp"),
                0,
                NGAP_PPID,
            ))
            .await
            .unwrap();
        let received =
            tokio::time::timeout(std::time::Duration::from_secs(5), recv_data(&accepted))
                .await
                .expect("multihomed payload timed out");
        assert_eq!(received.payload, Bytes::from_static(b"multihomed-sctp"));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires Linux kernel SCTP multihoming support"]
    async fn loopback_diameter_uses_explicit_multihoming_config() {
        let mut server_config = SctpEndpointConfig::one_to_one("127.0.0.1:0".parse().unwrap());
        server_config
            .local_addrs
            .push("127.0.0.2:0".parse().unwrap());
        let server = SctpEndpoint::bind(server_config).unwrap();
        let mut server_addresses = server.local_addresses().unwrap();
        server_addresses.sort_unstable();

        let mut client_config = SctpConnectConfig::new(server_addresses[0]);
        client_config.remote_addrs = server_addresses.clone();
        client_config.local_addrs = vec![
            "127.0.0.3:0".parse().unwrap(),
            "127.0.0.4:0".parse().unwrap(),
        ];
        let client = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            DiameterSctpAssociation::connect_with_config(
                client_config,
                DiameterSctpSecurity::ClearText,
            ),
        )
        .await
        .expect("multihomed Diameter connect timed out")
        .unwrap();
        let accepted = tokio::time::timeout(std::time::Duration::from_secs(5), server.accept())
            .await
            .expect("multihomed Diameter association was not accepted")
            .unwrap();

        let outbound = Bytes::from_static(b"diameter-multihomed-request");
        client
            .send_diameter_payload(outbound.clone())
            .await
            .unwrap();
        let received =
            tokio::time::timeout(std::time::Duration::from_secs(5), recv_data(&accepted))
                .await
                .expect("multihomed Diameter request timed out");
        assert_eq!(received.payload, outbound);
        assert_eq!(received.ppid, DIAMETER_SCTP_PPID);

        let inbound = Bytes::from_static(b"diameter-multihomed-answer");
        accepted
            .send(OutboundMessage::ordered(
                inbound.clone(),
                DIAMETER_DEFAULT_STREAM_ID,
                DIAMETER_SCTP_PPID,
            ))
            .await
            .unwrap();
        let received = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.recv_diameter_payload(),
        )
        .await
        .expect("multihomed Diameter answer timed out")
        .unwrap();
        assert_eq!(received, inbound);
        assert_eq!(client.peer().remote_addr, server_addresses[0]);
        assert_eq!(client.peer().security, DiameterSctpSecurity::ClearText);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires Linux SCTP plus passwordless sudo for path isolation"]
    async fn static_multihoming_survives_primary_path_drop() {
        let mut server_config = SctpEndpointConfig::one_to_one("127.0.0.1:0".parse().unwrap());
        server_config
            .local_addrs
            .push("127.0.0.2:0".parse().unwrap());
        let server = SctpEndpoint::bind(server_config).unwrap();
        let mut server_addresses = server.local_addresses().unwrap();
        server_addresses.sort_unstable();
        let server_port = server_addresses[0].port();

        // Keep the secondary server address unreachable while the association
        // forms, proving that the first address is the live initial path.
        let secondary_block = SctpPathDrop::install("127.0.0.2", server_port);
        let mut client_config = SctpConnectConfig::new(server_addresses[0]);
        client_config.remote_addrs = server_addresses;
        client_config.local_addrs = vec![
            "127.0.0.3:0".parse().unwrap(),
            "127.0.0.4:0".parse().unwrap(),
        ];
        let client = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            SctpAssociation::connect(client_config),
        )
        .await
        .expect("primary SCTP path did not connect")
        .unwrap();
        let accepted = tokio::time::timeout(std::time::Duration::from_secs(5), server.accept())
            .await
            .expect("primary SCTP path was not accepted")
            .unwrap();
        client
            .send(OutboundMessage::ordered(
                Bytes::from_static(b"primary-path"),
                0,
                NGAP_PPID,
            ))
            .await
            .unwrap();
        let primary = tokio::time::timeout(std::time::Duration::from_secs(5), recv_data(&accepted))
            .await
            .expect("primary-path payload timed out");
        assert_eq!(primary.payload, Bytes::from_static(b"primary-path"));

        // Make the configured secondary address reachable, then remove the
        // established primary. Delivery must continue on the same association.
        secondary_block.remove();
        let primary_block = SctpPathDrop::install("127.0.0.1", server_port);
        client
            .send(OutboundMessage::ordered(
                Bytes::from_static(b"survived-path-failover"),
                0,
                NGAP_PPID,
            ))
            .await
            .unwrap();
        let failed_over =
            tokio::time::timeout(std::time::Duration::from_secs(45), recv_data(&accepted))
                .await
                .expect("SCTP association did not fail over to the secondary path");
        primary_block.remove();
        assert_eq!(
            failed_over.payload,
            Bytes::from_static(b"survived-path-failover")
        );
    }

    #[cfg(target_os = "linux")]
    async fn diameter_loopback(
        server_addr: SocketAddr,
    ) -> (SctpEndpoint, DiameterSctpAssociation, SctpAssociation) {
        let server = SctpEndpoint::bind(SctpEndpointConfig::one_to_one(server_addr)).unwrap();
        let client = DiameterSctpPeer::new(server_addr)
            .connect_association()
            .await
            .unwrap();
        let accepted = server.accept().await.unwrap();
        (server, client, accepted)
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires Linux kernel SCTP support"]
    async fn loopback_recv_diameter_payload_skips_leading_notification() {
        let server_addr: SocketAddr = "127.0.0.1:38416".parse().unwrap();
        let (_server, client, accepted) = diameter_loopback(server_addr).await;

        // The client's first inbound message is the COMM_UP association
        // notification; the Diameter payload sent here arrives after it.
        let payload = Bytes::from_static(b"diameter-cea");
        accepted
            .send(OutboundMessage::ordered(
                payload.clone(),
                DIAMETER_DEFAULT_STREAM_ID,
                DIAMETER_SCTP_PPID,
            ))
            .await
            .unwrap();

        let received = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.recv_diameter_payload(),
        )
        .await
        .expect("recv_diameter_payload timed out")
        .unwrap();
        assert_eq!(received, payload);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires Linux kernel SCTP support"]
    async fn loopback_recv_diameter_payload_still_rejects_wrong_ppid() {
        let server_addr: SocketAddr = "127.0.0.1:38417".parse().unwrap();
        let (_server, client, accepted) = diameter_loopback(server_addr).await;

        accepted
            .send(OutboundMessage::ordered(
                Bytes::from_static(b"diameter"),
                DIAMETER_DEFAULT_STREAM_ID,
                DIAMETER_DTLS_SCTP_PPID,
            ))
            .await
            .unwrap();

        let error = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.recv_diameter_payload(),
        )
        .await
        .expect("recv_diameter_payload timed out")
        .unwrap_err();
        assert!(matches!(
            error,
            DiameterSctpError::WrongPpid {
                expected: 46,
                actual: 47
            }
        ));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires Linux kernel SCTP support"]
    async fn loopback_recv_diameter_payload_surfaces_close_after_shutdown() {
        let server_addr: SocketAddr = "127.0.0.1:38418".parse().unwrap();
        let (server, client, accepted) = diameter_loopback(server_addr).await;

        // Close the peer side: the client sees the shutdown notification,
        // skips it, and the next receive must report Closed, not spin.
        drop(accepted);
        drop(server);

        let error = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.recv_diameter_payload(),
        )
        .await
        .expect("recv_diameter_payload timed out")
        .unwrap_err();
        assert!(matches!(
            error,
            DiameterSctpError::SctpRecv(SctpError::Closed)
        ));
        assert_eq!(error.as_str(), "diameter_sctp_recv_error");
    }
}
