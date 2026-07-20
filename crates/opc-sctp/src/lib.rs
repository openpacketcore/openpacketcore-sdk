//! Safe SCTP transport foundation for OpenPacketCore.
//!
//! The crate keeps all unsafe Linux SCTP UAPI work in `opc-libsctp-sys` and
//! exposes a safe async API for one-to-one and one-to-many SCTP sockets.
//! Diameter helpers in this crate are explicitly unprotected SCTP framing:
//! PPID metadata does not establish DTLS, authenticate a peer, or prove that
//! an association is protected. Deployments must provide and attest a separate
//! protection mechanism such as IPsec, or use a real protected Diameter
//! transport outside this crate.

#![forbid(unsafe_code)]

use std::fmt;
use std::io;
use std::net::SocketAddr;
#[cfg(any(target_os = "linux", test))]
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
#[cfg(any(target_os = "linux", test))]
use std::sync::{Mutex, RwLock};

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

#[cfg(any(target_os = "linux", test))]
const SCTP_PEER_ADDR_CHANGE_BYTES: usize = 148;

/// Maximum number of addresses accepted in one static SCTP multihoming set.
pub const MAX_STATIC_MULTIHOMING_ADDRESSES: usize = opc_libsctp_sys::MAX_SCTP_ADDRESSES;

/// NGAP SCTP payload protocol identifier, per 3GPP N2 usage.
pub const NGAP_PPID: PayloadProtocolIdentifier = PayloadProtocolIdentifier::new(60);

/// Diameter SCTP payload protocol identifier for clear-text SCTP DATA chunks.
///
/// RFC 6733 assigns PPID 46 to Diameter over SCTP without DTLS.
pub const DIAMETER_SCTP_PPID: PayloadProtocolIdentifier = PayloadProtocolIdentifier::new(46);

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

/// Optional SCTP retransmission-timeout policy.
///
/// Omitted values retain the kernel setting. Explicit values must be nonzero
/// and internally ordered as `min_ms <= initial_ms <= max_ms` for every pair
/// that is present.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RtoConfig {
    /// Initial RTO in milliseconds.
    pub initial_ms: Option<u32>,
    /// Minimum RTO in milliseconds.
    pub min_ms: Option<u32>,
    /// Maximum RTO in milliseconds.
    pub max_ms: Option<u32>,
}

/// Optional SCTP peer-path heartbeat policy.
///
/// Omitted values retain the kernel setting. An explicit zero heartbeat
/// interval requests RFC 6458 zero-delay mode; the path RTO and jitter still
/// apply. `path_max_retrans` must be nonzero when supplied.
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

/// Protection provided by an ordinary [`DiameterSctpPeer`] association.
///
/// The only supported value is [`Self::Unprotected`]. It does not attest an
/// external IPsec deployment. A future in-SDK protected Diameter transport
/// must use an association type that can prove its authenticated handshake,
/// rather than adding a PPID-only value here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiameterSctpProtection {
    /// Ordinary SCTP with no SDK-provided encryption or peer authentication.
    Unprotected,
}

/// Legacy Diameter SCTP selector retained for a fail-closed migration.
///
/// This selector never establishes transport security. New code must use the
/// explicitly unprotected `DiameterSctpPeer::new_unprotected` and
/// `DiameterSctpAssociation::connect_unprotected_with_config` entry points.
/// A legacy request for `Dtls` returns
/// [`DiameterSctpError::ProtectedTransportUnavailable`] before socket setup or
/// payload framing.
#[deprecated(
    since = "0.2.0",
    note = "PPID metadata is not transport security; use explicitly unprotected Diameter SCTP APIs or a real protected transport"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiameterSctpSecurity {
    /// Legacy name for the explicitly unprotected PPID-46 path.
    ClearText,
    /// Unsupported legacy request; every SDK compatibility entry point rejects it.
    Dtls,
}

#[allow(deprecated)]
impl DiameterSctpSecurity {
    const fn require_unprotected(self) -> Result<(), DiameterSctpError> {
        match self {
            Self::ClearText => Ok(()),
            Self::Dtls => Err(DiameterSctpError::ProtectedTransportUnavailable),
        }
    }
}

/// Inbound PPID compatibility policy for Diameter over SCTP.
///
/// Strict validation is the production default. The legacy-zero mode is an
/// explicit interoperability escape hatch for non-conforming peers on the
/// unprotected PPID-46 path; it never changes outbound PPIDs and cannot enable
/// PPID-47 framing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DiameterInboundPpidPolicy {
    /// Require the unprotected Diameter-over-SCTP PPID 46.
    #[default]
    Strict,
    /// Also accept inbound PPID 0 for clear-text Diameter.
    AcceptLegacyZero,
}

/// Outbound PPID compatibility policy for Diameter over SCTP.
///
/// RFC PPID 46 is the production default. The legacy-zero mode is an explicit
/// interoperability escape hatch for non-conforming clear-text peers that
/// require PPID 0 in both directions. It does not affect inbound validation
/// and cannot enable PPID 47 framing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DiameterOutboundPpidPolicy {
    /// Emit the registered unprotected Diameter-over-SCTP PPID 46.
    #[default]
    Standard,
    /// Emit legacy PPID 0 for a specifically configured clear-text peer.
    LegacyZero,
}

impl DiameterOutboundPpidPolicy {
    const fn ppid(self) -> PayloadProtocolIdentifier {
        match self {
            Self::Standard => DIAMETER_SCTP_PPID,
            Self::LegacyZero => PayloadProtocolIdentifier::new(0),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiameterInboundPpidKind {
    Standard,
    LegacyZero,
}

impl DiameterInboundPpidPolicy {
    const fn classify(self, actual: PayloadProtocolIdentifier) -> Option<DiameterInboundPpidKind> {
        if actual.get() == DIAMETER_SCTP_PPID.get() {
            Some(DiameterInboundPpidKind::Standard)
        } else if matches!(self, Self::AcceptLegacyZero) && actual.get() == 0 {
            Some(DiameterInboundPpidKind::LegacyZero)
        } else {
            None
        }
    }
}

#[derive(Debug, Default)]
struct DiameterLegacyZeroPpidObserver {
    accepted_messages: AtomicU64,
    warning_emitted: AtomicBool,
}

impl DiameterLegacyZeroPpidObserver {
    fn record_accept(&self) -> bool {
        self.accepted_messages.fetch_add(1, Ordering::Relaxed);
        !self.warning_emitted.swap(true, Ordering::Relaxed)
    }

    fn accepted_messages(&self) -> u64 {
        self.accepted_messages.load(Ordering::Relaxed)
    }
}

/// Diameter SCTP peer transport intent for one resolved remote address.
#[derive(Clone, PartialEq, Eq)]
pub struct DiameterSctpPeer {
    /// Resolved remote Diameter peer address.
    pub remote_addr: SocketAddr,
    /// Optional local bind address.
    pub local_addr: Option<SocketAddr>,
    /// Transport protection supplied by this SDK association.
    pub protection: DiameterSctpProtection,
    /// Inbound Diameter PPID compatibility policy.
    pub inbound_ppid_policy: DiameterInboundPpidPolicy,
    /// Outbound Diameter PPID compatibility policy.
    pub outbound_ppid_policy: DiameterOutboundPpidPolicy,
    /// Maximum SCTP user payload accepted for one Diameter message.
    pub max_message_bytes: usize,
}

impl fmt::Debug for DiameterSctpPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DiameterSctpPeer")
            .field("remote_addr", &"<redacted>")
            .field("local_addr", &self.local_addr.map(|_| "<redacted>"))
            .field("protection", &self.protection)
            .field("inbound_ppid_policy", &self.inbound_ppid_policy)
            .field("outbound_ppid_policy", &self.outbound_ppid_policy)
            .field("max_message_bytes", &self.max_message_bytes)
            .finish()
    }
}

impl DiameterSctpPeer {
    /// Create an explicitly unprotected Diameter SCTP peer intent.
    ///
    /// Outbound payloads use PPID 46. This constructor does not establish or
    /// attest DTLS, TLS, IPsec, peer authentication, or confidentiality.
    #[must_use]
    pub fn new_unprotected(remote_addr: SocketAddr) -> Self {
        let default_config = SctpConnectConfig::new(remote_addr);
        Self {
            remote_addr,
            local_addr: None,
            protection: DiameterSctpProtection::Unprotected,
            inbound_ppid_policy: DiameterInboundPpidPolicy::Strict,
            outbound_ppid_policy: DiameterOutboundPpidPolicy::Standard,
            max_message_bytes: default_config.max_message_bytes,
        }
    }

    /// Create a legacy clear-text peer intent.
    ///
    /// This compatibility constructor is unprotected and is retained only to
    /// provide a compiler-visible migration to [`Self::new_unprotected`].
    #[deprecated(
        since = "0.2.0",
        note = "use DiameterSctpPeer::new_unprotected to acknowledge that ordinary SCTP is not a protected transport"
    )]
    #[must_use]
    pub fn new(remote_addr: SocketAddr) -> Self {
        Self::new_unprotected(remote_addr)
    }

    /// Return a copy that binds the SCTP association from one local address.
    #[must_use]
    pub fn with_local_addr(mut self, local_addr: SocketAddr) -> Self {
        self.local_addr = Some(local_addr);
        self
    }

    /// Return a copy that uses the requested inbound Diameter PPID policy.
    ///
    /// [`DiameterInboundPpidPolicy::AcceptLegacyZero`] affects unprotected
    /// inbound messages only. Outbound messages continue to use
    /// [`DIAMETER_SCTP_PPID`], and PPID 47 is never enabled.
    #[must_use]
    pub fn with_inbound_ppid_policy(mut self, policy: DiameterInboundPpidPolicy) -> Self {
        self.inbound_ppid_policy = policy;
        self
    }

    /// Return a copy that uses the requested outbound Diameter PPID policy.
    ///
    /// [`DiameterOutboundPpidPolicy::LegacyZero`] is an explicit
    /// interoperability escape hatch for a non-conforming clear-text peer. It
    /// does not change [`Self::inbound_ppid_policy`], and PPID 47 is never
    /// enabled.
    #[must_use]
    pub fn with_outbound_ppid_policy(mut self, policy: DiameterOutboundPpidPolicy) -> Self {
        self.outbound_ppid_policy = policy;
        self
    }

    /// Apply a legacy Diameter SCTP selector during migration.
    ///
    /// `ClearText` retains this explicitly unprotected peer. `Dtls` fails
    /// closed because this crate has no DTLS record layer or authenticated
    /// protected-association type.
    ///
    /// # Errors
    ///
    /// Returns [`DiameterSctpError::ProtectedTransportUnavailable`] for
    /// `DiameterSctpSecurity::Dtls`. No peer capable of framing or connecting
    /// is returned in that case.
    #[allow(deprecated)]
    #[deprecated(
        since = "0.2.0",
        note = "use DiameterSctpPeer::new_unprotected or a real protected Diameter transport"
    )]
    pub fn with_security(self, security: DiameterSctpSecurity) -> Result<Self, DiameterSctpError> {
        security.require_unprotected()?;
        Ok(self)
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

    /// Wrap an encoded Diameter message with the configured unprotected PPID.
    #[must_use]
    pub fn outbound_message(&self, payload: Bytes) -> OutboundMessage {
        OutboundMessage::ordered(
            payload,
            DIAMETER_DEFAULT_STREAM_ID,
            self.outbound_ppid_policy.ppid(),
        )
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
        self.classify_inbound_message(message).map(|_| ())
    }

    fn classify_inbound_message(
        &self,
        message: &InboundMessage,
    ) -> Result<DiameterInboundPpidKind, DiameterSctpError> {
        if message.notification {
            return Err(DiameterSctpError::Notification);
        }
        if message.truncated {
            return Err(DiameterSctpError::Truncated);
        }
        self.inbound_ppid_policy
            .classify(message.ppid)
            .ok_or(DiameterSctpError::WrongPpid {
                expected: DIAMETER_SCTP_PPID.get(),
                actual: message.ppid.get(),
            })
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
        DiameterSctpAssociation::connect_unprotected_with_config_and_ppid_policies(
            config,
            self.inbound_ppid_policy,
            self.outbound_ppid_policy,
        )
        .await
    }
}

/// One item received from a live Diameter SCTP association.
#[derive(Clone, PartialEq, Eq)]
pub enum DiameterSctpInbound {
    /// Diameter payload that passed notification, truncation, and PPID checks.
    Payload(Bytes),
    /// SCTP transport notification, decoded when its type is supported.
    Notification(Option<SctpEvent>),
}

impl fmt::Debug for DiameterSctpInbound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Payload(payload) => f
                .debug_struct("Payload")
                .field("bytes", &payload.len())
                .finish(),
            Self::Notification(event) => f.debug_tuple("Notification").field(event).finish(),
        }
    }
}

/// Live Diameter SCTP association opened by SDK SCTP.
#[derive(Debug)]
pub struct DiameterSctpAssociation {
    peer: DiameterSctpPeer,
    association: SctpAssociation,
    legacy_zero_ppid_observer: DiameterLegacyZeroPpidObserver,
}

impl DiameterSctpAssociation {
    /// Open an explicitly unprotected Diameter-framed SCTP association.
    ///
    /// This is the Diameter counterpart to [`SctpAssociation::connect`] and
    /// preserves the complete local and remote address sets in `config`.
    /// Callers can therefore use static SCTP multihoming without duplicating
    /// the SDK's Diameter PPID and notification handling. The first configured
    /// remote and local addresses are exposed through [`Self::peer`] only as
    /// the primary transport intent; SCTP remains authoritative for path
    /// selection across the full validated sets.
    ///
    /// This entry point always uses [`DiameterInboundPpidPolicy::Strict`]. Use
    /// [`Self::connect_unprotected_with_config_and_inbound_ppid_policy`] for an
    /// explicit per-association compatibility policy.
    ///
    /// # Errors
    ///
    /// Returns [`DiameterSctpError::SctpConfig`] when `config` is invalid, or
    /// [`DiameterSctpError::SctpConnect`] when the platform, kernel, namespace,
    /// or peer cannot open the requested association. A host that lacks static
    /// multihoming reports [`SctpError::CapabilityUnavailable`]; this function
    /// never silently reduces the configured address sets.
    pub async fn connect_unprotected_with_config(
        config: SctpConnectConfig,
    ) -> Result<Self, DiameterSctpError> {
        Self::connect_unprotected_with_config_and_inbound_ppid_policy(
            config,
            DiameterInboundPpidPolicy::Strict,
        )
        .await
    }

    /// Open an explicitly unprotected association with an inbound PPID policy.
    ///
    /// This is the opt-in counterpart to
    /// [`Self::connect_unprotected_with_config`]. It
    /// preserves complete static-multihoming address sets and applies `policy`
    /// only to inbound Diameter metadata. Outbound messages always use PPID 46.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::connect_unprotected_with_config`].
    pub async fn connect_unprotected_with_config_and_inbound_ppid_policy(
        config: SctpConnectConfig,
        policy: DiameterInboundPpidPolicy,
    ) -> Result<Self, DiameterSctpError> {
        Self::connect_unprotected_with_config_and_ppid_policies(
            config,
            policy,
            DiameterOutboundPpidPolicy::Standard,
        )
        .await
    }

    /// Open an explicitly unprotected association with independent inbound
    /// and outbound PPID policies.
    ///
    /// This is the only static-multihoming entry point that can opt into
    /// outbound legacy PPID 0. The policies remain independent: selecting
    /// outbound legacy framing does not weaken strict inbound validation.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::connect_unprotected_with_config`].
    pub async fn connect_unprotected_with_config_and_ppid_policies(
        config: SctpConnectConfig,
        inbound_policy: DiameterInboundPpidPolicy,
        outbound_policy: DiameterOutboundPpidPolicy,
    ) -> Result<Self, DiameterSctpError> {
        config.validate().map_err(DiameterSctpError::from)?;
        let peer = Self::peer_from_connect_config(&config, inbound_policy, outbound_policy)?;
        let association = SctpAssociation::connect(config)
            .await
            .map_err(DiameterSctpError::connect)?;
        Ok(Self {
            peer,
            association,
            legacy_zero_ppid_observer: DiameterLegacyZeroPpidObserver::default(),
        })
    }

    /// Open a legacy Diameter-framed SCTP association.
    ///
    /// `ClearText` delegates to the explicitly unprotected PPID-46 path.
    /// `Dtls` fails before SCTP configuration validation or socket setup.
    ///
    /// # Errors
    ///
    /// Returns [`DiameterSctpError::ProtectedTransportUnavailable`] when
    /// `security` requests DTLS, or the errors documented by
    /// [`Self::connect_unprotected_with_config`] for the legacy clear-text path.
    #[allow(deprecated)]
    #[deprecated(
        since = "0.2.0",
        note = "use connect_unprotected_with_config or a real protected Diameter transport"
    )]
    pub async fn connect_with_config(
        config: SctpConnectConfig,
        security: DiameterSctpSecurity,
    ) -> Result<Self, DiameterSctpError> {
        security.require_unprotected()?;
        Self::connect_unprotected_with_config(config).await
    }

    /// Open a legacy association with an explicit inbound PPID policy.
    ///
    /// `Dtls` always fails before SCTP configuration validation or socket
    /// setup. The inbound compatibility policy cannot weaken that result.
    ///
    /// # Errors
    ///
    /// Returns [`DiameterSctpError::ProtectedTransportUnavailable`] when
    /// `security` requests DTLS, or the errors documented by
    /// [`Self::connect_unprotected_with_config_and_inbound_ppid_policy`] for
    /// the legacy clear-text path.
    #[allow(deprecated)]
    #[deprecated(
        since = "0.2.0",
        note = "use connect_unprotected_with_config_and_inbound_ppid_policy or a real protected Diameter transport"
    )]
    pub async fn connect_with_config_and_inbound_ppid_policy(
        config: SctpConnectConfig,
        security: DiameterSctpSecurity,
        policy: DiameterInboundPpidPolicy,
    ) -> Result<Self, DiameterSctpError> {
        security.require_unprotected()?;
        Self::connect_unprotected_with_config_and_inbound_ppid_policy(config, policy).await
    }

    fn peer_from_connect_config(
        config: &SctpConnectConfig,
        inbound_policy: DiameterInboundPpidPolicy,
        outbound_policy: DiameterOutboundPpidPolicy,
    ) -> Result<DiameterSctpPeer, DiameterSctpError> {
        let Some(&remote_addr) = config.remote_addrs.first() else {
            return Err(DiameterSctpError::from(SctpError::InvalidConfig {
                field: "remote_addrs",
                reason: "must contain at least one address",
            }));
        };
        Ok(DiameterSctpPeer {
            remote_addr,
            local_addr: config.local_addrs.first().copied(),
            protection: DiameterSctpProtection::Unprotected,
            inbound_ppid_policy: inbound_policy,
            outbound_ppid_policy: outbound_policy,
            max_message_bytes: config.max_message_bytes,
        })
    }

    /// Return the configured Diameter SCTP peer intent.
    #[must_use]
    pub const fn peer(&self) -> &DiameterSctpPeer {
        &self.peer
    }

    /// Send one encoded Diameter payload with the peer's configured
    /// unprotected PPID.
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

    /// Receive one validated Diameter payload or SCTP transport notification.
    ///
    /// This event-capable boundary preserves wire ordering. Notifications are
    /// returned before any payload truncation or PPID checks, matching the
    /// existing [`Self::recv_diameter_payload`] filtering behavior. Payloads
    /// are returned only after the same validation and legacy-PPID accounting
    /// used by that convenience method.
    ///
    /// # Errors
    ///
    /// Returns [`DiameterSctpError`] when receive fails or non-notification
    /// SCTP metadata is invalid for this unprotected Diameter framing profile.
    pub async fn recv(&self) -> Result<DiameterSctpInbound, DiameterSctpError> {
        let message = self
            .association
            .recv()
            .await
            .map_err(DiameterSctpError::recv)?;
        if message.notification {
            return Ok(DiameterSctpInbound::Notification(message.event));
        }
        let ppid_kind = self.peer.classify_inbound_message(&message)?;
        if matches!(ppid_kind, DiameterInboundPpidKind::LegacyZero)
            && self.legacy_zero_ppid_observer.record_accept()
        {
            tracing::warn!(
                event = "diameter_sctp_legacy_zero_ppid_accepted",
                "accepted legacy inbound Diameter SCTP PPID 0"
            );
        }
        Ok(DiameterSctpInbound::Payload(message.payload))
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
    /// not valid for this unprotected Diameter framing profile.
    pub async fn recv_diameter_payload(&self) -> Result<Bytes, DiameterSctpError> {
        loop {
            match self.recv().await? {
                DiameterSctpInbound::Payload(payload) => return Ok(payload),
                DiameterSctpInbound::Notification(_) => {
                    // A shutdown notification is followed by the association
                    // actually closing, so the next recv surfaces
                    // `SctpError::Closed` instead of spinning here.
                }
            }
        }
    }

    /// Return SDK SCTP association health.
    #[must_use]
    pub fn health(&self) -> SctpHealth {
        self.association.health()
    }

    /// Return bounded per-path health for this Diameter SCTP association.
    ///
    /// The snapshot is initialized from the distinct configured set, or the
    /// bounded kernel-reported set for an accepted association. Path state is
    /// updated before [`Self::recv`] returns each peer-address-change
    /// notification. A made-primary event is reconciled best-effort with the
    /// kernel's current primary; if that health-only query fails, the event is
    /// still returned and the last known designation is preserved.
    #[must_use]
    pub fn peer_path_health(&self) -> Vec<SctpPathHealth> {
        self.association.peer_path_health()
    }

    /// Select the peer address used as this Diameter association's primary path.
    ///
    /// The supplied address must match a current peer path. On success the
    /// local SCTP stack sends future traffic on that path when it is usable;
    /// SCTP remains responsible for failover.
    ///
    /// # Errors
    ///
    /// Returns [`SctpError`] when the address is not a current peer path or
    /// the kernel rejects primary-path selection.
    pub fn set_primary_peer_path(&self, peer_addr: SocketAddr) -> Result<(), SctpError> {
        self.association.set_primary_peer_path(peer_addr)
    }

    /// Return SDK SCTP association metrics.
    #[must_use]
    pub fn metrics(&self) -> SctpMetricsSnapshot {
        let mut snapshot = self.association.metrics();
        snapshot.accepted_legacy_diameter_zero_ppid_messages =
            self.legacy_zero_ppid_observer.accepted_messages();
        snapshot
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
    /// A legacy caller requested a protected transport that this crate cannot establish.
    ProtectedTransportUnavailable,
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
    /// SCTP PPID did not match the unprotected Diameter framing profile.
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
            Self::ProtectedTransportUnavailable => "diameter_sctp_protected_transport_unavailable",
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
            Self::ProtectedTransportUnavailable => {
                f.write_str("diameter_sctp_protected_transport_unavailable")
            }
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
            Self::ProtectedTransportUnavailable
            | Self::Notification
            | Self::Truncated
            | Self::WrongPpid { .. } => None,
        }
    }
}

/// Parsed SCTP notification event.
#[derive(Clone, Copy, PartialEq, Eq)]
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
    /// One peer path changed state.
    PeerAddrChange {
        /// Peer path address reported by the kernel.
        peer_addr: SocketAddr,
        /// Typed peer path transition.
        state: SctpPeerAddrState,
        /// Kernel error value associated with the transition.
        error: i32,
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

impl fmt::Debug for SctpEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AssociationChange {
                state,
                error,
                outbound_streams,
                inbound_streams,
                assoc_id,
            } => f
                .debug_struct("AssociationChange")
                .field("state", state)
                .field("error", error)
                .field("outbound_streams", outbound_streams)
                .field("inbound_streams", inbound_streams)
                .field("assoc_id", assoc_id)
                .finish(),
            Self::PeerAddrChange {
                state,
                error,
                assoc_id,
                ..
            } => f
                .debug_struct("PeerAddrChange")
                .field("peer_addr", &"<redacted>")
                .field("state", state)
                .field("error", error)
                .field("assoc_id", assoc_id)
                .finish(),
            Self::Shutdown { assoc_id } => f
                .debug_struct("Shutdown")
                .field("assoc_id", assoc_id)
                .finish(),
            Self::Unknown { notification_type } => f
                .debug_struct("Unknown")
                .field("notification_type", notification_type)
                .finish(),
        }
    }
}

/// State carried by a Linux `SCTP_PEER_ADDR_CHANGE` notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SctpPeerAddrState {
    /// The peer address became available.
    Available,
    /// The peer address became unreachable.
    Unreachable,
    /// The peer address was removed from the association.
    Removed,
    /// The peer address was added to the association.
    Added,
    /// The peer address became the primary path.
    MadePrimary,
    /// The peer address was confirmed by the SCTP stack.
    Confirmed,
    /// The peer address entered potentially-failed state.
    PotentiallyFailed,
    /// State value not recognized by this SDK version.
    Unknown(i32),
}

impl SctpPeerAddrState {
    #[cfg(any(target_os = "linux", test))]
    const fn from_kernel(value: i32) -> Self {
        match value {
            0 => Self::Available,
            1 => Self::Unreachable,
            2 => Self::Removed,
            3 => Self::Added,
            4 => Self::MadePrimary,
            5 => Self::Confirmed,
            6 => Self::PotentiallyFailed,
            other => Self::Unknown(other),
        }
    }

    /// Stable machine name for the transition.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Unreachable => "unreachable",
            Self::Removed => "removed",
            Self::Added => "added",
            Self::MadePrimary => "made_primary",
            Self::Confirmed => "confirmed",
            Self::PotentiallyFailed => "potentially_failed",
            Self::Unknown(_) => "unknown",
        }
    }
}

/// Current health classification for one peer SCTP path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SctpPathStatus {
    /// No reachability event has been observed yet.
    Unknown,
    /// The SCTP stack reports the path as available or confirmed.
    Reachable,
    /// The SCTP stack reports the path as potentially failed.
    PotentiallyFailed,
    /// The SCTP stack reports the path as unreachable.
    Unreachable,
    /// The path was removed from the association.
    Removed,
}

impl SctpPathStatus {
    /// Stable machine name for the path status.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Reachable => "reachable",
            Self::PotentiallyFailed => "potentially_failed",
            Self::Unreachable => "unreachable",
            Self::Removed => "removed",
        }
    }
}

/// Redaction-safe health for one peer SCTP path.
#[derive(Clone, PartialEq, Eq)]
pub struct SctpPathHealth {
    /// Peer address represented by this path.
    pub peer_addr: SocketAddr,
    /// Current reachability classification derived from kernel events.
    pub status: SctpPathStatus,
    /// Whether this is the initial or most recently selected primary path.
    ///
    /// The first configured or kernel-reported peer address initializes the
    /// estimate. `SCTP_ADDR_MADE_PRIM` changes the designation; removal clears
    /// it. Reachability transitions do not change which path is designated
    /// primary.
    pub primary: bool,
}

impl fmt::Debug for SctpPathHealth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SctpPathHealth")
            .field("peer_addr", &"<redacted>")
            .field("status", &self.status)
            .field("primary", &self.primary)
            .finish()
    }
}

/// Inbound SCTP message metadata and payload.
#[derive(Clone, PartialEq, Eq)]
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

impl fmt::Debug for InboundMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InboundMessage")
            .field("payload_bytes", &self.payload.len())
            .field("stream_id", &self.stream_id)
            .field("ppid", &self.ppid)
            .field("order", &self.order)
            .field("assoc_id", &self.assoc_id)
            .field("notification", &self.notification)
            .field("event", &self.event)
            .field("truncated", &self.truncated)
            .field("control_truncated", &self.control_truncated)
            .finish()
    }
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
    /// Legacy inbound Diameter PPID 0 messages accepted by this association.
    ///
    /// This remains zero for generic SCTP endpoints and associations.
    pub accepted_legacy_diameter_zero_ppid_messages: u64,
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
            accepted_legacy_diameter_zero_ppid_messages: 0,
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

#[cfg(any(target_os = "linux", test))]
#[derive(Debug)]
struct SctpPathTracker {
    paths: RwLock<Vec<SctpPathHealth>>,
}

#[cfg(any(target_os = "linux", test))]
impl SctpPathTracker {
    fn new(peer_addrs: &[SocketAddr]) -> Self {
        let mut paths = Vec::with_capacity(peer_addrs.len().min(MAX_STATIC_MULTIHOMING_ADDRESSES));
        for peer_addr in peer_addrs
            .iter()
            .copied()
            .take(MAX_STATIC_MULTIHOMING_ADDRESSES)
        {
            if paths
                .iter()
                .any(|path: &SctpPathHealth| same_sctp_path(path.peer_addr, peer_addr))
            {
                continue;
            }
            paths.push(SctpPathHealth {
                peer_addr,
                status: SctpPathStatus::Unknown,
                primary: paths.is_empty(),
            });
        }
        Self {
            paths: RwLock::new(paths),
        }
    }

    fn snapshot(&self) -> Vec<SctpPathHealth> {
        match self.paths.read() {
            Ok(paths) => paths.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    fn record(&self, event: SctpEvent) {
        let SctpEvent::PeerAddrChange {
            peer_addr, state, ..
        } = event
        else {
            return;
        };
        self.record_path_change(peer_addr, state);
    }

    fn initialize_primary_reachable(&self, peer_addr: SocketAddr) {
        self.mark_primary_with_status(peer_addr, Some(SctpPathStatus::Reachable));
    }

    fn mark_primary(&self, peer_addr: SocketAddr) {
        self.mark_primary_with_status(peer_addr, None);
    }

    fn mark_primary_with_status(&self, peer_addr: SocketAddr, status: Option<SctpPathStatus>) {
        let mut paths = match self.paths.write() {
            Ok(paths) => paths,
            Err(poisoned) => poisoned.into_inner(),
        };
        let primary_index = if let Some(primary_index) = paths
            .iter()
            .position(|path| same_sctp_path(path.peer_addr, peer_addr))
        {
            primary_index
        } else if paths.len() < MAX_STATIC_MULTIHOMING_ADDRESSES {
            let primary_index = paths.len();
            paths.push(SctpPathHealth {
                peer_addr,
                status: SctpPathStatus::Unknown,
                primary: false,
            });
            primary_index
        } else if let Some(primary_index) = paths
            .iter()
            .position(|path| path.status == SctpPathStatus::Removed)
        {
            paths[primary_index] = SctpPathHealth {
                peer_addr,
                status: SctpPathStatus::Unknown,
                primary: false,
            };
            primary_index
        } else {
            let Some(primary_index) = paths.iter().rposition(|path| !path.primary) else {
                return;
            };
            paths[primary_index] = SctpPathHealth {
                peer_addr,
                status: SctpPathStatus::Unknown,
                primary: false,
            };
            primary_index
        };
        for path in paths.iter_mut() {
            path.primary = false;
        }
        paths[primary_index].primary = true;
        if let Some(status) = status {
            paths[primary_index].status = status;
        }
    }

    fn record_path_change(&self, peer_addr: SocketAddr, state: SctpPeerAddrState) {
        let mut paths = match self.paths.write() {
            Ok(paths) => paths,
            Err(poisoned) => poisoned.into_inner(),
        };
        let path_index = if let Some(path_index) = paths
            .iter()
            .position(|path| same_sctp_path(path.peer_addr, peer_addr))
        {
            path_index
        } else if paths.len() < MAX_STATIC_MULTIHOMING_ADDRESSES {
            let path_index = paths.len();
            paths.push(SctpPathHealth {
                peer_addr,
                status: SctpPathStatus::Unknown,
                primary: false,
            });
            path_index
        } else if let Some(path_index) = paths
            .iter()
            .position(|path| path.status == SctpPathStatus::Removed)
        {
            paths[path_index] = SctpPathHealth {
                peer_addr,
                status: SctpPathStatus::Unknown,
                primary: false,
            };
            path_index
        } else if state == SctpPeerAddrState::MadePrimary {
            let Some(path_index) = paths.iter().rposition(|path| !path.primary) else {
                return;
            };
            paths[path_index] = SctpPathHealth {
                peer_addr,
                status: SctpPathStatus::Unknown,
                primary: false,
            };
            path_index
        } else {
            return;
        };
        if state == SctpPeerAddrState::MadePrimary {
            for path in paths.iter_mut() {
                path.primary = false;
            }
        }
        let path = &mut paths[path_index];
        match state {
            SctpPeerAddrState::Available | SctpPeerAddrState::Confirmed => {
                path.status = SctpPathStatus::Reachable;
            }
            SctpPeerAddrState::Unreachable => {
                path.status = SctpPathStatus::Unreachable;
            }
            SctpPeerAddrState::Removed => {
                path.status = SctpPathStatus::Removed;
                path.primary = false;
            }
            SctpPeerAddrState::PotentiallyFailed => {
                path.status = SctpPathStatus::PotentiallyFailed;
            }
            SctpPeerAddrState::Added | SctpPeerAddrState::Unknown(_) => {
                path.status = SctpPathStatus::Unknown;
            }
            SctpPeerAddrState::MadePrimary => {}
        }
        if state == SctpPeerAddrState::MadePrimary {
            path.primary = true;
        }
    }
}

#[cfg(any(target_os = "linux", test))]
fn same_sctp_path(left: SocketAddr, right: SocketAddr) -> bool {
    match (left, right) {
        (SocketAddr::V4(left), SocketAddr::V4(right)) => left == right,
        (SocketAddr::V6(left), SocketAddr::V6(right)) => {
            left.ip() == right.ip()
                && left.port() == right.port()
                && left.scope_id() == right.scope_id()
        }
        (SocketAddr::V4(_), SocketAddr::V6(_)) | (SocketAddr::V6(_), SocketAddr::V4(_)) => false,
    }
}

#[cfg(any(target_os = "linux", test))]
fn lock_path_control(gate: &Mutex<()>) -> std::sync::MutexGuard<'_, ()> {
    match gate.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(any(target_os = "linux", test))]
fn set_primary_path_serialized<CurrentPeers, SelectPrimary>(
    gate: &Mutex<()>,
    tracker: &SctpPathTracker,
    requested_peer: SocketAddr,
    current_peers: CurrentPeers,
    select_primary: SelectPrimary,
) -> Result<(), SctpError>
where
    CurrentPeers: FnOnce() -> Result<Vec<SocketAddr>, SctpError>,
    SelectPrimary: FnOnce(SocketAddr) -> Result<(), SctpError>,
{
    let _control_guard = lock_path_control(gate);
    let canonical_peer = current_peers()?
        .into_iter()
        .find(|candidate| same_sctp_path(*candidate, requested_peer))
        .ok_or(SctpError::InvalidConfig {
            field: "peer_addr",
            reason: "must be a current peer address",
        })?;
    select_primary(canonical_peer)?;
    tracker.mark_primary(canonical_peer);
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn record_path_event_serialized<CurrentPrimary>(
    gate: &Mutex<()>,
    tracker: &SctpPathTracker,
    event: SctpEvent,
    current_primary: CurrentPrimary,
) where
    CurrentPrimary: FnOnce() -> Option<SocketAddr>,
{
    let _control_guard = lock_path_control(gate);
    if matches!(
        event,
        SctpEvent::PeerAddrChange {
            state: SctpPeerAddrState::MadePrimary,
            ..
        }
    ) {
        // A notification may have been dequeued before a concurrent explicit
        // selection acquired the gate. Reconcile with the kernel rather than
        // allowing that stale event to roll the tracker back.
        if let Some(primary_peer) = current_primary() {
            tracker.mark_primary(primary_peer);
        }
    } else {
        tracker.record(event);
    }
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
    ///
    /// Concurrent active calls are serialized so path events are processed in
    /// kernel receive order before this returns. A made-primary event is
    /// reconciled best-effort with the kernel's current primary; if that
    /// health-only query fails, the event is returned while the last known
    /// designation is preserved. A receive future is not cancellation-safe
    /// after it starts consuming a multi-chunk SCTP record.
    pub async fn recv(&self) -> Result<InboundMessage, SctpError> {
        self.imp.recv().await
    }

    /// Return association health.
    pub fn health(&self) -> SctpHealth {
        self.imp.health()
    }

    /// Return bounded peer-path health for this association.
    ///
    /// Non-primary paths begin as [`SctpPathStatus::Unknown`]; the connected
    /// or accepted primary begins reachable when the kernel reports it.
    /// Peer-address-change notifications update the snapshot before
    /// [`Self::recv`] returns them, except that a made-primary reconciliation
    /// query failure preserves the last known designation while still
    /// returning the event. IPv6 flow information is deliberately not part of
    /// path identity, following RFC 3493 guidance for system-produced socket
    /// addresses.
    #[must_use]
    pub fn peer_path_health(&self) -> Vec<SctpPathHealth> {
        self.imp.peer_path_health()
    }

    /// Select the peer address used as this association's primary path.
    ///
    /// The supplied address must match a current peer path. A successful
    /// selection updates [`Self::peer_path_health`] immediately; SCTP can
    /// still fail over when the selected path is unavailable. Concurrent
    /// selections and received path notifications are serialized with the
    /// kernel mutation and health update.
    ///
    /// # Errors
    ///
    /// Returns [`SctpError::InvalidConfig`] when `peer_addr` is not a current
    /// path, [`SctpError::CapabilityUnavailable`] when the kernel lacks the
    /// option, or [`SctpError::Io`] for another socket failure.
    pub fn set_primary_peer_path(&self, peer_addr: SocketAddr) -> Result<(), SctpError> {
        self.imp.set_primary_peer_path(peer_addr)
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
    validate_rto_config(rto)?;
    validate_heartbeat_config(heartbeat)?;
    Ok(())
}

fn validate_rto_config(rto: RtoConfig) -> Result<(), SctpError> {
    if [rto.initial_ms, rto.min_ms, rto.max_ms]
        .into_iter()
        .flatten()
        .any(|value| value == 0)
    {
        return Err(SctpError::InvalidConfig {
            field: "rto",
            reason: "explicit timeout values must be greater than zero",
        });
    }
    if matches!((rto.min_ms, rto.max_ms), (Some(min), Some(max)) if min > max) {
        return Err(SctpError::InvalidConfig {
            field: "rto",
            reason: "min_ms must not exceed max_ms",
        });
    }
    if matches!((rto.initial_ms, rto.min_ms), (Some(initial), Some(min)) if initial < min) {
        return Err(SctpError::InvalidConfig {
            field: "rto",
            reason: "initial_ms must not be below min_ms",
        });
    }
    if matches!((rto.initial_ms, rto.max_ms), (Some(initial), Some(max)) if initial > max) {
        return Err(SctpError::InvalidConfig {
            field: "rto",
            reason: "initial_ms must not exceed max_ms",
        });
    }
    Ok(())
}

fn validate_heartbeat_config(heartbeat: HeartbeatConfig) -> Result<(), SctpError> {
    if heartbeat.path_max_retrans == Some(0) {
        return Err(SctpError::InvalidConfig {
            field: "heartbeat.path_max_retrans",
            reason: "must be greater than zero when supplied",
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
    let available_len = payload.len();
    let notification_type = read_u16_ne(payload, 0)?;
    let declared_len = read_u32_ne(payload, 4)? as usize;
    if declared_len < 8 || declared_len > payload.len() {
        return None;
    }
    if notification_type == opc_libsctp_sys::SCTP_PEER_ADDR_CHANGE_NOTIFICATION
        && (declared_len != SCTP_PEER_ADDR_CHANGE_BYTES
            || available_len != SCTP_PEER_ADDR_CHANGE_BYTES)
    {
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
        opc_libsctp_sys::SCTP_PEER_ADDR_CHANGE_NOTIFICATION => Some(SctpEvent::PeerAddrChange {
            peer_addr: parse_peer_addr_change_socket_addr(payload)?,
            state: SctpPeerAddrState::from_kernel(read_i32_ne(payload, 136)?),
            error: read_i32_ne(payload, 140)?,
            assoc_id: read_i32_ne(payload, 144)?,
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
fn parse_peer_addr_change_socket_addr(payload: &[u8]) -> Option<SocketAddr> {
    const SOCKADDR_STORAGE_OFFSET: usize = 8;
    const SOCKADDR_STORAGE_BYTES: usize = 128;
    const LINUX_AF_INET: u16 = 2;
    const LINUX_AF_INET6: u16 = 10;

    if payload.len() != SCTP_PEER_ADDR_CHANGE_BYTES {
        return None;
    }
    let storage = payload.get(
        SOCKADDR_STORAGE_OFFSET..SOCKADDR_STORAGE_OFFSET.checked_add(SOCKADDR_STORAGE_BYTES)?,
    )?;
    match read_u16_ne(storage, 0)? {
        LINUX_AF_INET => {
            let port = read_u16_be(storage, 2)?;
            let octets: [u8; 4] = storage.get(4..8)?.try_into().ok()?;
            let address = Ipv4Addr::from(octets);
            Some(SocketAddr::V4(SocketAddrV4::new(address, port)))
        }
        LINUX_AF_INET6 => {
            let port = read_u16_be(storage, 2)?;
            // Linux embeds `sockaddr_in6` in this notification. Its port and
            // flowinfo fields are network-order, while scope_id is native.
            // Existing getpeername/getpaddrs conversion intentionally mirrors
            // std/libc's raw flowinfo representation; path identity therefore
            // ignores flowinfo rather than conflating the two APIs.
            let flowinfo = read_u32_be(storage, 4)?;
            let octets: [u8; 16] = storage.get(8..24)?.try_into().ok()?;
            let address = Ipv6Addr::from(octets);
            let scope_id = read_u32_ne(storage, 24)?;
            Some(SocketAddr::V6(SocketAddrV6::new(
                address, port, flowinfo, scope_id,
            )))
        }
        _ => None,
    }
}

#[cfg(any(target_os = "linux", test))]
fn read_u16_ne(bytes: &[u8], offset: usize) -> Option<u16> {
    let slice = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_ne_bytes([slice[0], slice[1]]))
}

#[cfg(any(target_os = "linux", test))]
fn read_u16_be(bytes: &[u8], offset: usize) -> Option<u16> {
    let slice = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_be_bytes([slice[0], slice[1]]))
}

#[cfg(any(target_os = "linux", test))]
fn read_u32_ne(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_ne_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

#[cfg(any(target_os = "linux", test))]
fn read_u32_be(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
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
    if opc_libsctp_sys::is_sctp_capability_unavailable(&source) {
        SctpError::CapabilityUnavailable {
            capability: "static_multihoming",
            source,
        }
    } else {
        io_err(operation, source)
    }
}

#[cfg(target_os = "linux")]
fn path_control_io_err(
    operation: &'static str,
    capability: &'static str,
    source: io::Error,
) -> SctpError {
    if opc_libsctp_sys::is_sctp_capability_unavailable(&source) {
        SctpError::CapabilityUnavailable { capability, source }
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
        peer_paths: SctpPathTracker,
        recv_gate: tokio::sync::Mutex<()>,
        path_control_gate: Mutex<()>,
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
        configure_fd(
            fd.as_fd(),
            config.init,
            config.nodelay,
            config.rto,
            config.heartbeat,
        )?;
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
        let peer_paths = SctpPathTracker::new(&config.remote_addrs);
        let fd = opc_libsctp_sys::open_socket(sys_family(&remote), sys_style(SctpMode::OneToOne))
            .map_err(|source| io_err("socket", source))?;
        configure_fd(
            fd.as_fd(),
            config.init,
            config.nodelay,
            config.rto,
            config.heartbeat,
        )?;
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
        if let Ok(primary_peer) = opc_libsctp_sys::peer_primary_address(socket.fd.get_ref().as_fd())
        {
            peer_paths.initialize_primary_reachable(primary_peer);
        }
        Ok(Association {
            socket,
            mode: SctpMode::OneToOne,
            peer_paths,
            recv_gate: tokio::sync::Mutex::new(()),
            path_control_gate: Mutex::new(()),
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
                    Ok(Ok((fd, peer))) => {
                        let mut peer_addrs = match opc_libsctp_sys::peer_addresses(fd.as_fd(), 0) {
                            Ok(peer_addrs) if !peer_addrs.is_empty() => peer_addrs,
                            Ok(_) | Err(_) => vec![peer],
                        };
                        if let Some(peer_index) = peer_addrs
                            .iter()
                            .position(|peer_addr| same_sctp_path(*peer_addr, peer))
                        {
                            peer_addrs.swap(0, peer_index);
                        } else {
                            peer_addrs.insert(0, peer);
                            peer_addrs.truncate(MAX_STATIC_MULTIHOMING_ADDRESSES);
                        }
                        let peer_paths = SctpPathTracker::new(&peer_addrs);
                        peer_paths.initialize_primary_reachable(peer);
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
                            peer_paths,
                            recv_gate: tokio::sync::Mutex::new(()),
                            path_control_gate: Mutex::new(()),
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
            let _recv_guard = self.recv_gate.lock().await;
            let message = self.socket.recv().await?;
            if let Some(event) = message.event {
                record_path_event_serialized(
                    &self.path_control_gate,
                    &self.peer_paths,
                    event,
                    || opc_libsctp_sys::peer_primary_address(self.socket.fd.get_ref().as_fd()).ok(),
                );
            }
            Ok(message)
        }

        pub fn health(&self) -> SctpHealth {
            SctpHealth {
                platform_supported: true,
                socket_open: self.socket.is_open(),
                mode: self.mode,
            }
        }

        pub fn peer_path_health(&self) -> Vec<SctpPathHealth> {
            self.peer_paths.snapshot()
        }

        pub fn set_primary_peer_path(&self, peer_addr: SocketAddr) -> Result<(), SctpError> {
            set_primary_path_serialized(
                &self.path_control_gate,
                &self.peer_paths,
                peer_addr,
                || {
                    opc_libsctp_sys::peer_addresses(self.socket.fd.get_ref().as_fd(), 0)
                        .map_err(|source| io_err("peer_addresses", source))
                },
                |canonical_peer_addr| {
                    opc_libsctp_sys::set_primary_peer_address(
                        self.socket.fd.get_ref().as_fd(),
                        0,
                        &canonical_peer_addr,
                    )
                    .map_err(|source| {
                        path_control_io_err(
                            "set_primary_peer_address",
                            "primary_path_selection",
                            source,
                        )
                    })
                },
            )
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
        rto: RtoConfig,
        heartbeat: HeartbeatConfig,
    ) -> Result<(), SctpError> {
        opc_libsctp_sys::set_initmsg(fd, sys_init(init))
            .map_err(|source| io_err("set_initmsg", source))?;
        opc_libsctp_sys::set_nodelay(fd, nodelay)
            .map_err(|source| io_err("set_nodelay", source))?;
        opc_libsctp_sys::set_recv_rcvinfo(fd, true)
            .map_err(|source| io_err("set_recv_rcvinfo", source))?;
        opc_libsctp_sys::set_events(fd, opc_libsctp_sys::EventSubscriptions::default())
            .map_err(|source| io_err("set_events", source))?;
        if rto != RtoConfig::default() {
            opc_libsctp_sys::set_rto_parameters(
                fd,
                opc_libsctp_sys::RtoParameters {
                    assoc_id: 0,
                    initial_ms: rto.initial_ms.and_then(std::num::NonZeroU32::new),
                    max_ms: rto.max_ms.and_then(std::num::NonZeroU32::new),
                    min_ms: rto.min_ms.and_then(std::num::NonZeroU32::new),
                },
            )
            .map_err(|source| path_control_io_err("set_rto_parameters", "path_tuning", source))?;
        }
        if heartbeat != HeartbeatConfig::default() {
            opc_libsctp_sys::set_peer_address_parameters(
                fd,
                opc_libsctp_sys::PeerAddressParameters {
                    assoc_id: 0,
                    peer_addr: None,
                    heartbeat_interval_ms: heartbeat.interval_ms,
                    path_max_retransmissions: heartbeat
                        .path_max_retrans
                        .and_then(std::num::NonZeroU16::new),
                },
            )
            .map_err(|source| {
                path_control_io_err("set_peer_address_parameters", "path_tuning", source)
            })?;
        }
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

        pub fn peer_path_health(&self) -> Vec<SctpPathHealth> {
            let _ = self;
            Vec::new()
        }

        pub fn set_primary_peer_path(&self, peer_addr: SocketAddr) -> Result<(), SctpError> {
            let _ = (self, peer_addr);
            Err(SctpError::UnsupportedPlatform)
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
        DiameterSctpPeer::new_unprotected("127.0.0.1:3868".parse().unwrap())
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

    fn reserved_diameter_dtls_ppid() -> PayloadProtocolIdentifier {
        PayloadProtocolIdentifier::new(47)
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

    fn peer_addr_change_notification(
        peer_addr: SocketAddr,
        state: i32,
        error: i32,
        assoc_id: i32,
    ) -> Vec<u8> {
        let mut payload = Vec::with_capacity(SCTP_PEER_ADDR_CHANGE_BYTES);
        push_u16_ne(
            &mut payload,
            opc_libsctp_sys::SCTP_PEER_ADDR_CHANGE_NOTIFICATION,
        );
        push_u16_ne(&mut payload, 0);
        push_u32_ne(&mut payload, SCTP_PEER_ADDR_CHANGE_BYTES as u32);
        let mut storage = [0_u8; 128];
        match peer_addr {
            SocketAddr::V4(addr) => {
                storage[0..2].copy_from_slice(&2_u16.to_ne_bytes());
                storage[2..4].copy_from_slice(&addr.port().to_be_bytes());
                storage[4..8].copy_from_slice(&addr.ip().octets());
            }
            SocketAddr::V6(addr) => {
                storage[0..2].copy_from_slice(&10_u16.to_ne_bytes());
                storage[2..4].copy_from_slice(&addr.port().to_be_bytes());
                storage[4..8].copy_from_slice(&addr.flowinfo().to_be_bytes());
                storage[8..24].copy_from_slice(&addr.ip().octets());
                storage[24..28].copy_from_slice(&addr.scope_id().to_ne_bytes());
            }
        }
        payload.extend_from_slice(&storage);
        push_i32_ne(&mut payload, state);
        push_i32_ne(&mut payload, error);
        push_i32_ne(&mut payload, assoc_id);
        payload
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
    fn unprotected_diameter_ppid_matches_rfc_6733_value() {
        assert_eq!(DIAMETER_SCTP_PPID.get(), 46);

        let network = DIAMETER_SCTP_PPID.to_network_order();
        assert_eq!(
            PayloadProtocolIdentifier::from_network_order(network),
            DIAMETER_SCTP_PPID
        );
    }

    #[test]
    fn diameter_ppid_policies_default_to_standard_and_survive_peer_builders() {
        assert_eq!(
            DiameterInboundPpidPolicy::default(),
            DiameterInboundPpidPolicy::Strict
        );
        assert_eq!(
            diameter_peer().inbound_ppid_policy,
            DiameterInboundPpidPolicy::Strict
        );
        assert_eq!(
            DiameterOutboundPpidPolicy::default(),
            DiameterOutboundPpidPolicy::Standard
        );
        assert_eq!(
            diameter_peer().outbound_ppid_policy,
            DiameterOutboundPpidPolicy::Standard
        );
        assert_eq!(
            diameter_peer().protection,
            DiameterSctpProtection::Unprotected
        );
        assert_eq!(
            diameter_peer()
                .with_inbound_ppid_policy(DiameterInboundPpidPolicy::AcceptLegacyZero)
                .inbound_ppid_policy,
            DiameterInboundPpidPolicy::AcceptLegacyZero
        );
        assert_eq!(
            diameter_peer()
                .with_outbound_ppid_policy(DiameterOutboundPpidPolicy::LegacyZero)
                .outbound_ppid_policy,
            DiameterOutboundPpidPolicy::LegacyZero
        );
    }

    #[test]
    fn diameter_legacy_zero_observer_counts_and_warns_once_per_association() {
        let observer = DiameterLegacyZeroPpidObserver::default();

        assert!(observer.record_accept());
        assert!(!observer.record_accept());
        assert_eq!(observer.accepted_messages(), 2);
    }

    #[test]
    fn diameter_inbound_debug_does_not_expose_payload() {
        let inbound = DiameterSctpInbound::Payload(Bytes::from_static(b"diameter-secret"));
        let debug = format!("{inbound:?}");

        assert!(debug.contains("bytes"));
        assert!(!debug.contains("diameter-secret"));

        let message = diameter_inbound(DIAMETER_SCTP_PPID);
        let message_debug = format!("{message:?}");
        assert!(message_debug.contains("payload_bytes"));
        assert!(!message_debug.contains("diameter"));
    }

    #[test]
    fn parses_assoc_change_notification_event() {
        assert_eq!(opc_libsctp_sys::SCTP_ASSOC_CHANGE_NOTIFICATION, 0x8001);
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
        assert_eq!(opc_libsctp_sys::SCTP_SHUTDOWN_EVENT_NOTIFICATION, 0x8005);
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
    fn parses_ipv4_peer_addr_change_notification_event() {
        assert_eq!(opc_libsctp_sys::SCTP_PEER_ADDR_CHANGE_NOTIFICATION, 0x8002);
        let peer_addr = "192.0.2.10:3868".parse().unwrap();
        let payload = peer_addr_change_notification(peer_addr, 1, 113, 17);

        assert_eq!(
            parse_sctp_event(&payload),
            Some(SctpEvent::PeerAddrChange {
                peer_addr,
                state: SctpPeerAddrState::Unreachable,
                error: 113,
                assoc_id: 17,
            })
        );
    }

    #[test]
    fn parses_ipv6_peer_addr_change_notification_event() {
        // Independently authored Linux `sctp_paddr_change` fixture. In
        // particular, nonzero sin6_flowinfo is encoded in network order.
        let mut payload = [0_u8; 148];
        payload[0..2]
            .copy_from_slice(&opc_libsctp_sys::SCTP_PEER_ADDR_CHANGE_NOTIFICATION.to_ne_bytes());
        payload[4..8].copy_from_slice(&148_u32.to_ne_bytes());
        payload[8..10].copy_from_slice(&10_u16.to_ne_bytes());
        payload[10..12].copy_from_slice(&3868_u16.to_be_bytes());
        payload[12..16].copy_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        payload[16..32].copy_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20,
        ]);
        payload[32..36].copy_from_slice(&3_u32.to_ne_bytes());
        payload[136..140].copy_from_slice(&4_i32.to_ne_bytes());
        payload[140..144].copy_from_slice(&0_i32.to_ne_bytes());
        payload[144..148].copy_from_slice(&21_i32.to_ne_bytes());
        let peer_addr = SocketAddr::V6(SocketAddrV6::new(
            "2001:db8::20".parse().unwrap(),
            3868,
            0x0102_0304,
            3,
        ));

        assert_eq!(
            parse_sctp_event(payload.as_slice()),
            Some(SctpEvent::PeerAddrChange {
                peer_addr,
                state: SctpPeerAddrState::MadePrimary,
                error: 0,
                assoc_id: 21,
            })
        );
    }

    #[test]
    fn peer_addr_change_state_values_match_linux_uapi() {
        assert_eq!(
            SctpPeerAddrState::from_kernel(0),
            SctpPeerAddrState::Available
        );
        assert_eq!(
            SctpPeerAddrState::from_kernel(1),
            SctpPeerAddrState::Unreachable
        );
        assert_eq!(
            SctpPeerAddrState::from_kernel(2),
            SctpPeerAddrState::Removed
        );
        assert_eq!(SctpPeerAddrState::from_kernel(3), SctpPeerAddrState::Added);
        assert_eq!(
            SctpPeerAddrState::from_kernel(4),
            SctpPeerAddrState::MadePrimary
        );
        assert_eq!(
            SctpPeerAddrState::from_kernel(5),
            SctpPeerAddrState::Confirmed
        );
        assert_eq!(
            SctpPeerAddrState::from_kernel(6),
            SctpPeerAddrState::PotentiallyFailed
        );
        assert_eq!(
            SctpPeerAddrState::from_kernel(77),
            SctpPeerAddrState::Unknown(77)
        );
    }

    #[test]
    fn rejects_malformed_peer_addr_change_notifications() {
        let peer_addr = "192.0.2.10:3868".parse().unwrap();
        let payload = peer_addr_change_notification(peer_addr, 0, 0, 1);

        assert_eq!(parse_sctp_event(&payload[..147]), None);

        let mut oversized = payload.clone();
        oversized.push(0);
        oversized[4..8].copy_from_slice(&149_u32.to_ne_bytes());
        assert_eq!(parse_sctp_event(&oversized), None);

        let mut trailing = payload.clone();
        trailing.push(0);
        assert_eq!(parse_sctp_event(&trailing), None);

        let mut unknown_family = payload;
        unknown_family[8..10].copy_from_slice(&99_u16.to_ne_bytes());
        assert_eq!(parse_sctp_event(&unknown_family), None);
    }

    #[test]
    fn peer_addr_event_and_health_debug_redact_addresses() {
        let peer_addr: SocketAddr = "192.0.2.10:3868".parse().unwrap();
        let event = SctpEvent::PeerAddrChange {
            peer_addr,
            state: SctpPeerAddrState::Available,
            error: 0,
            assoc_id: 7,
        };
        let event_debug = format!("{event:?}");
        assert!(event_debug.contains("<redacted>"));
        assert!(!event_debug.contains("192.0.2.10"));

        let health = SctpPathHealth {
            peer_addr,
            status: SctpPathStatus::Reachable,
            primary: true,
        };
        let health_debug = format!("{health:?}");
        assert!(health_debug.contains("<redacted>"));
        assert!(!health_debug.contains("192.0.2.10"));
    }

    #[test]
    fn sctp_health_original_struct_literal_remains_source_compatible() {
        let health = SctpHealth {
            platform_supported: true,
            socket_open: true,
            mode: SctpMode::OneToOne,
        };

        assert!(health.platform_supported);
        assert!(health.socket_open);
        assert_eq!(health.mode, SctpMode::OneToOne);
    }

    #[test]
    fn path_tracker_ignores_ipv6_flowinfo_for_identity() {
        let address: Ipv6Addr = "2001:db8::20".parse().unwrap();
        let configured = SocketAddr::V6(SocketAddrV6::new(address, 3868, 0, 3));
        let raw_current = SocketAddr::V6(SocketAddrV6::new(address, 3868, 0x0403_0201, 3));
        let notification = SocketAddr::V6(SocketAddrV6::new(address, 3868, 0x0102_0304, 3));
        let tracker = SctpPathTracker::new(&[configured]);

        tracker.initialize_primary_reachable(raw_current);
        tracker.record(SctpEvent::PeerAddrChange {
            peer_addr: notification,
            state: SctpPeerAddrState::Confirmed,
            error: 0,
            assoc_id: 7,
        });

        assert_eq!(
            tracker.snapshot(),
            vec![SctpPathHealth {
                peer_addr: configured,
                status: SctpPathStatus::Reachable,
                primary: true,
            }]
        );
    }

    #[test]
    fn path_tracker_preserves_order_and_applies_transitions() {
        let first: SocketAddr = "192.0.2.10:3868".parse().unwrap();
        let second: SocketAddr = "192.0.2.11:3868".parse().unwrap();
        let tracker = SctpPathTracker::new(&[first, second]);
        assert_eq!(
            tracker.snapshot(),
            vec![
                SctpPathHealth {
                    peer_addr: first,
                    status: SctpPathStatus::Unknown,
                    primary: true,
                },
                SctpPathHealth {
                    peer_addr: second,
                    status: SctpPathStatus::Unknown,
                    primary: false,
                },
            ]
        );

        tracker.record(SctpEvent::PeerAddrChange {
            peer_addr: second,
            state: SctpPeerAddrState::MadePrimary,
            error: 0,
            assoc_id: 7,
        });
        tracker.record(SctpEvent::PeerAddrChange {
            peer_addr: first,
            state: SctpPeerAddrState::PotentiallyFailed,
            error: 0,
            assoc_id: 7,
        });

        let paths = tracker.snapshot();
        assert_eq!(paths[0].status, SctpPathStatus::PotentiallyFailed);
        assert!(!paths[0].primary);
        assert_eq!(paths[1].status, SctpPathStatus::Unknown);
        assert!(paths[1].primary);
    }

    #[test]
    fn path_tracker_keeps_primary_designation_across_reachability_changes() {
        let first: SocketAddr = "192.0.2.10:3868".parse().unwrap();
        let second: SocketAddr = "192.0.2.11:3868".parse().unwrap();
        let tracker = SctpPathTracker::new(&[first, second]);

        tracker.record(SctpEvent::PeerAddrChange {
            peer_addr: first,
            state: SctpPeerAddrState::Unreachable,
            error: 113,
            assoc_id: 7,
        });
        let paths = tracker.snapshot();
        assert!(paths[0].primary);
        assert_eq!(paths[0].status, SctpPathStatus::Unreachable);

        tracker.record(SctpEvent::PeerAddrChange {
            peer_addr: first,
            state: SctpPeerAddrState::Available,
            error: 0,
            assoc_id: 7,
        });
        let paths = tracker.snapshot();
        assert!(paths[0].primary);
        assert_eq!(paths[0].status, SctpPathStatus::Reachable);

        tracker.record(SctpEvent::PeerAddrChange {
            peer_addr: first,
            state: SctpPeerAddrState::PotentiallyFailed,
            error: 0,
            assoc_id: 7,
        });
        let paths = tracker.snapshot();
        assert!(paths[0].primary);
        assert_eq!(paths[0].status, SctpPathStatus::PotentiallyFailed);

        tracker.record(SctpEvent::PeerAddrChange {
            peer_addr: second,
            state: SctpPeerAddrState::MadePrimary,
            error: 0,
            assoc_id: 7,
        });
        let paths = tracker.snapshot();
        assert!(!paths[0].primary);
        assert!(paths[1].primary);
        assert_eq!(paths[1].status, SctpPathStatus::Unknown);
    }

    #[test]
    fn explicit_primary_selection_does_not_manufacture_reachability() {
        let first: SocketAddr = "192.0.2.10:3868".parse().unwrap();
        let second: SocketAddr = "192.0.2.11:3868".parse().unwrap();
        let tracker = SctpPathTracker::new(&[first, second]);
        tracker.record(SctpEvent::PeerAddrChange {
            peer_addr: second,
            state: SctpPeerAddrState::PotentiallyFailed,
            error: 0,
            assoc_id: 7,
        });

        tracker.mark_primary(second);

        let paths = tracker.snapshot();
        assert!(!paths[0].primary);
        assert!(paths[1].primary);
        assert_eq!(paths[1].status, SctpPathStatus::PotentiallyFailed);
    }

    #[test]
    fn made_primary_event_preserves_unhealthy_path_status() {
        let first: SocketAddr = "192.0.2.10:3868".parse().unwrap();
        let second: SocketAddr = "192.0.2.11:3868".parse().unwrap();
        for state in [
            SctpPeerAddrState::PotentiallyFailed,
            SctpPeerAddrState::Unreachable,
        ] {
            let expected_status = match state {
                SctpPeerAddrState::PotentiallyFailed => SctpPathStatus::PotentiallyFailed,
                SctpPeerAddrState::Unreachable => SctpPathStatus::Unreachable,
                _ => unreachable!("test enumerates only unhealthy states"),
            };
            let tracker = SctpPathTracker::new(&[first, second]);
            tracker.record(SctpEvent::PeerAddrChange {
                peer_addr: second,
                state,
                error: 0,
                assoc_id: 7,
            });
            tracker.record(SctpEvent::PeerAddrChange {
                peer_addr: second,
                state: SctpPeerAddrState::MadePrimary,
                error: 0,
                assoc_id: 7,
            });

            let paths = tracker.snapshot();
            assert!(!paths[0].primary);
            assert!(paths[1].primary);
            assert_eq!(paths[1].status, expected_status);
        }
    }

    #[test]
    fn primary_selection_serializes_kernel_and_tracker_updates() {
        let first: SocketAddr = "192.0.2.10:3868".parse().unwrap();
        let second: SocketAddr = "192.0.2.11:3868".parse().unwrap();
        let peers = vec![first, second];
        let gate = Arc::new(Mutex::new(()));
        let tracker = Arc::new(SctpPathTracker::new(&peers));
        let kernel_primary = Arc::new(Mutex::new(first));
        let (first_selected_tx, first_selected_rx) = std::sync::mpsc::channel();
        let (release_first_tx, release_first_rx) = std::sync::mpsc::channel();

        let first_gate = Arc::clone(&gate);
        let first_tracker = Arc::clone(&tracker);
        let first_kernel_primary = Arc::clone(&kernel_primary);
        let first_peers = peers.clone();
        let first_worker = std::thread::spawn(move || {
            set_primary_path_serialized(
                &first_gate,
                &first_tracker,
                first,
                || Ok(first_peers),
                |canonical_peer| {
                    *first_kernel_primary.lock().unwrap() = canonical_peer;
                    first_selected_tx.send(()).unwrap();
                    release_first_rx.recv().unwrap();
                    Ok(())
                },
            )
        });
        first_selected_rx.recv().unwrap();

        let (second_started_tx, second_started_rx) = std::sync::mpsc::channel();
        let (second_entered_tx, second_entered_rx) = std::sync::mpsc::channel();
        let second_gate = Arc::clone(&gate);
        let second_tracker = Arc::clone(&tracker);
        let second_kernel_primary = Arc::clone(&kernel_primary);
        let second_worker = std::thread::spawn(move || {
            second_started_tx.send(()).unwrap();
            set_primary_path_serialized(
                &second_gate,
                &second_tracker,
                second,
                || {
                    second_entered_tx.send(()).unwrap();
                    Ok(peers)
                },
                |canonical_peer| {
                    *second_kernel_primary.lock().unwrap() = canonical_peer;
                    Ok(())
                },
            )
        });
        second_started_rx.recv().unwrap();
        assert!(matches!(
            second_entered_rx.recv_timeout(std::time::Duration::from_millis(100)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));

        release_first_tx.send(()).unwrap();
        first_worker.join().unwrap().unwrap();
        second_worker.join().unwrap().unwrap();
        assert_eq!(*kernel_primary.lock().unwrap(), second);
        let paths = tracker.snapshot();
        assert_eq!(paths.iter().filter(|path| path.primary).count(), 1);
        assert!(paths
            .iter()
            .any(|path| path.peer_addr == second && path.primary));
    }

    #[test]
    fn delayed_made_primary_event_reconciles_with_kernel_after_setter() {
        let first: SocketAddr = "192.0.2.10:3868".parse().unwrap();
        let second: SocketAddr = "192.0.2.11:3868".parse().unwrap();
        let peers = vec![first, second];
        let gate = Mutex::new(());
        let tracker = SctpPathTracker::new(&peers);
        let kernel_primary = Mutex::new(first);
        let stale_event = SctpEvent::PeerAddrChange {
            peer_addr: first,
            state: SctpPeerAddrState::MadePrimary,
            error: 0,
            assoc_id: 7,
        };

        // Model a notification that has already left the socket receive queue,
        // followed by a complete explicit selection before event application.
        set_primary_path_serialized(
            &gate,
            &tracker,
            second,
            || Ok(peers),
            |canonical_peer| {
                *kernel_primary.lock().unwrap() = canonical_peer;
                Ok(())
            },
        )
        .unwrap();
        record_path_event_serialized(&gate, &tracker, stale_event, || {
            Some(*kernel_primary.lock().unwrap())
        });

        let paths = tracker.snapshot();
        assert_eq!(paths.iter().filter(|path| path.primary).count(), 1);
        assert!(paths
            .iter()
            .any(|path| path.peer_addr == second && path.primary));

        // A failed health-only reconciliation must not regress to the stale
        // event address or turn notification delivery into a receive failure.
        record_path_event_serialized(&gate, &tracker, stale_event, || None);
        assert!(tracker
            .snapshot()
            .iter()
            .any(|path| path.peer_addr == second && path.primary));
    }

    #[test]
    fn path_tracker_maps_reachability_and_removal_states() {
        let peer_addr: SocketAddr = "192.0.2.10:3868".parse().unwrap();
        let tracker = SctpPathTracker::new(&[peer_addr]);
        for (state, expected_status) in [
            (SctpPeerAddrState::Available, SctpPathStatus::Reachable),
            (
                SctpPeerAddrState::PotentiallyFailed,
                SctpPathStatus::PotentiallyFailed,
            ),
            (SctpPeerAddrState::Unreachable, SctpPathStatus::Unreachable),
            (SctpPeerAddrState::Added, SctpPathStatus::Unknown),
            (SctpPeerAddrState::Confirmed, SctpPathStatus::Reachable),
            (SctpPeerAddrState::Removed, SctpPathStatus::Removed),
            (SctpPeerAddrState::Unknown(99), SctpPathStatus::Unknown),
        ] {
            tracker.record(SctpEvent::PeerAddrChange {
                peer_addr,
                state,
                error: 0,
                assoc_id: 7,
            });
            assert_eq!(tracker.snapshot()[0].status, expected_status);
        }
    }

    #[test]
    fn path_tracker_bounds_notification_discovered_paths() {
        let configured: Vec<_> = (1..=MAX_STATIC_MULTIHOMING_ADDRESSES)
            .map(|host| SocketAddr::from(([192, 0, 2, host as u8], 3868)))
            .collect();
        let tracker = SctpPathTracker::new(&configured);
        tracker.record(SctpEvent::PeerAddrChange {
            peer_addr: "198.51.100.1:3868".parse().unwrap(),
            state: SctpPeerAddrState::Available,
            error: 0,
            assoc_id: 7,
        });

        assert_eq!(tracker.snapshot().len(), MAX_STATIC_MULTIHOMING_ADDRESSES);
    }

    #[test]
    fn path_tracker_reuses_removed_slot_for_new_kernel_path() {
        let configured: Vec<_> = (1..=MAX_STATIC_MULTIHOMING_ADDRESSES)
            .map(|host| SocketAddr::from(([192, 0, 2, host as u8], 3868)))
            .collect();
        let tracker = SctpPathTracker::new(&configured);
        tracker.record(SctpEvent::PeerAddrChange {
            peer_addr: configured[0],
            state: SctpPeerAddrState::Removed,
            error: 0,
            assoc_id: 7,
        });
        let replacement: SocketAddr = "198.51.100.1:3868".parse().unwrap();
        tracker.record(SctpEvent::PeerAddrChange {
            peer_addr: replacement,
            state: SctpPeerAddrState::Available,
            error: 0,
            assoc_id: 7,
        });

        let paths = tracker.snapshot();
        assert_eq!(paths.len(), MAX_STATIC_MULTIHOMING_ADDRESSES);
        assert!(paths.iter().any(|path| {
            path.peer_addr == replacement && path.status == SctpPathStatus::Reachable
        }));
        assert!(!paths.iter().any(|path| path.peer_addr == configured[0]));
    }

    #[test]
    fn path_tracker_prioritizes_new_primary_at_capacity() {
        let configured: Vec<_> = (1..=MAX_STATIC_MULTIHOMING_ADDRESSES)
            .map(|host| SocketAddr::from(([192, 0, 2, host as u8], 3868)))
            .collect();
        let tracker = SctpPathTracker::new(&configured);
        let replacement: SocketAddr = "198.51.100.1:3868".parse().unwrap();
        tracker.record(SctpEvent::PeerAddrChange {
            peer_addr: replacement,
            state: SctpPeerAddrState::MadePrimary,
            error: 0,
            assoc_id: 7,
        });

        let paths = tracker.snapshot();
        assert_eq!(paths.len(), MAX_STATIC_MULTIHOMING_ADDRESSES);
        let primary_paths: Vec<_> = paths.iter().filter(|path| path.primary).collect();
        assert_eq!(primary_paths.len(), 1);
        assert_eq!(primary_paths[0].peer_addr, replacement);
        assert_eq!(primary_paths[0].status, SctpPathStatus::Unknown);
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
    fn diameter_multihomed_connect_projection_preserves_ppid_policies() {
        let mut config = SctpConnectConfig::new("127.0.0.1:3868".parse().unwrap());
        config.remote_addrs.push("127.0.0.2:3868".parse().unwrap());
        config.local_addrs = vec![
            "127.0.0.3:0".parse().unwrap(),
            "127.0.0.4:0".parse().unwrap(),
        ];
        config.validate().unwrap();

        let peer = DiameterSctpAssociation::peer_from_connect_config(
            &config,
            DiameterInboundPpidPolicy::AcceptLegacyZero,
            DiameterOutboundPpidPolicy::LegacyZero,
        )
        .unwrap();

        assert_eq!(peer.remote_addr, config.remote_addrs[0]);
        assert_eq!(peer.local_addr, Some(config.local_addrs[0]));
        assert_eq!(peer.protection, DiameterSctpProtection::Unprotected);
        assert_eq!(
            peer.inbound_ppid_policy,
            DiameterInboundPpidPolicy::AcceptLegacyZero
        );
        assert_eq!(
            peer.outbound_ppid_policy,
            DiameterOutboundPpidPolicy::LegacyZero
        );
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

        let error = DiameterSctpAssociation::connect_unprotected_with_config(config)
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
    fn diameter_outbound_message_defaults_to_46_and_supports_explicit_legacy_zero() {
        let unprotected = diameter_peer().outbound_message(Bytes::from_static(b"diameter"));
        assert_eq!(unprotected.stream_id, DIAMETER_DEFAULT_STREAM_ID);
        assert_eq!(unprotected.ppid, DIAMETER_SCTP_PPID);
        assert_ne!(unprotected.ppid, reserved_diameter_dtls_ppid());
        assert_eq!(unprotected.order, DeliveryOrder::Ordered);

        let compatibility = diameter_peer()
            .with_inbound_ppid_policy(DiameterInboundPpidPolicy::AcceptLegacyZero)
            .outbound_message(Bytes::from_static(b"diameter"));
        assert_eq!(compatibility.ppid, DIAMETER_SCTP_PPID);

        let outbound_legacy = diameter_peer()
            .with_outbound_ppid_policy(DiameterOutboundPpidPolicy::LegacyZero)
            .outbound_message(Bytes::from_static(b"diameter"));
        assert_eq!(outbound_legacy.ppid, PayloadProtocolIdentifier::new(0));
        assert_eq!(
            diameter_peer()
                .with_outbound_ppid_policy(DiameterOutboundPpidPolicy::LegacyZero)
                .inbound_ppid_policy,
            DiameterInboundPpidPolicy::Strict
        );
    }

    #[test]
    fn diameter_inbound_validation_rejects_non_payload_conditions() {
        let peer =
            diameter_peer().with_inbound_ppid_policy(DiameterInboundPpidPolicy::AcceptLegacyZero);

        let mut notification = diameter_inbound(NGAP_PPID);
        notification.notification = true;
        notification.truncated = true;
        let error = peer.validate_inbound_message(&notification).unwrap_err();
        assert_eq!(error.as_str(), "diameter_sctp_notification");

        let mut truncated = diameter_inbound(NGAP_PPID);
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
            .validate_inbound_message(&diameter_inbound(reserved_diameter_dtls_ppid()))
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
    fn diameter_strict_inbound_policy_rejects_legacy_zero_ppid() {
        let error = diameter_peer()
            .validate_inbound_message(&diameter_inbound(PayloadProtocolIdentifier::new(0)))
            .unwrap_err();

        assert!(matches!(
            error,
            DiameterSctpError::WrongPpid {
                expected: 46,
                actual: 0
            }
        ));
    }

    #[test]
    fn diameter_legacy_zero_policy_accepts_zero_and_standard_cleartext_ppid() {
        let peer =
            diameter_peer().with_inbound_ppid_policy(DiameterInboundPpidPolicy::AcceptLegacyZero);
        let legacy = diameter_inbound(PayloadProtocolIdentifier::new(0));
        let standard = diameter_inbound(DIAMETER_SCTP_PPID);

        assert_eq!(
            peer.inbound_payload(&legacy).unwrap(),
            &Bytes::from_static(b"diameter")
        );
        assert_eq!(
            peer.inbound_payload(&standard).unwrap(),
            &Bytes::from_static(b"diameter")
        );
    }

    #[test]
    fn diameter_legacy_zero_policy_rejects_every_other_cleartext_ppid() {
        let peer =
            diameter_peer().with_inbound_ppid_policy(DiameterInboundPpidPolicy::AcceptLegacyZero);
        let error = peer
            .validate_inbound_message(&diameter_inbound(NGAP_PPID))
            .unwrap_err();

        assert!(matches!(
            error,
            DiameterSctpError::WrongPpid {
                expected: 46,
                actual: 60
            }
        ));
        assert_eq!(error.as_str(), "diameter_sctp_wrong_ppid");
    }

    #[test]
    #[allow(deprecated)]
    fn diameter_legacy_dtls_peer_selector_fails_before_payload_framing() {
        let error = diameter_peer()
            .with_security(DiameterSctpSecurity::Dtls)
            .unwrap_err();

        assert!(matches!(
            error,
            DiameterSctpError::ProtectedTransportUnavailable
        ));
        assert_eq!(
            error.as_str(),
            "diameter_sctp_protected_transport_unavailable"
        );
        assert_eq!(error.to_string(), error.as_str());
    }

    #[allow(deprecated)]
    #[tokio::test]
    async fn diameter_legacy_dtls_connect_fails_before_config_or_socket_setup() {
        let mut invalid_config = SctpConnectConfig::new("127.0.0.1:3868".parse().unwrap());
        invalid_config.remote_addrs.clear();

        let strict_error = DiameterSctpAssociation::connect_with_config(
            invalid_config.clone(),
            DiameterSctpSecurity::Dtls,
        )
        .await
        .unwrap_err();
        assert!(matches!(
            strict_error,
            DiameterSctpError::ProtectedTransportUnavailable
        ));

        let compatibility_error =
            DiameterSctpAssociation::connect_with_config_and_inbound_ppid_policy(
                invalid_config,
                DiameterSctpSecurity::Dtls,
                DiameterInboundPpidPolicy::AcceptLegacyZero,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            compatibility_error,
            DiameterSctpError::ProtectedTransportUnavailable
        ));

        let projection = DiameterSctpConnectProjection::from_error(&compatibility_error);
        assert_eq!(projection.outcome, DiameterSctpConnectOutcome::Failed);
        assert!(!projection.connected);
        assert_eq!(
            projection.error_code,
            Some("diameter_sctp_protected_transport_unavailable")
        );
    }

    #[allow(deprecated)]
    #[test]
    fn diameter_legacy_cleartext_selector_migrates_only_to_unprotected() {
        let peer = diameter_peer()
            .with_security(DiameterSctpSecurity::ClearText)
            .unwrap();
        let outbound = peer.outbound_message(Bytes::from_static(b"diameter"));

        assert_eq!(outbound.ppid, DIAMETER_SCTP_PPID);
        assert_ne!(outbound.ppid, reserved_diameter_dtls_ppid());
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
    fn config_accepts_valid_custom_rto_and_heartbeat() {
        let mut config = SctpEndpointConfig::one_to_one("127.0.0.1:38412".parse().unwrap());
        config.rto = RtoConfig {
            initial_ms: Some(500),
            min_ms: Some(100),
            max_ms: Some(2_000),
        };
        config.heartbeat = HeartbeatConfig {
            interval_ms: Some(0),
            path_max_retrans: Some(3),
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn config_rejects_ambiguous_or_internally_unordered_path_tuning() {
        for rto in [
            RtoConfig {
                initial_ms: Some(0),
                ..RtoConfig::default()
            },
            RtoConfig {
                min_ms: Some(0),
                ..RtoConfig::default()
            },
            RtoConfig {
                max_ms: Some(0),
                ..RtoConfig::default()
            },
            RtoConfig {
                min_ms: Some(500),
                max_ms: Some(400),
                ..RtoConfig::default()
            },
            RtoConfig {
                initial_ms: Some(99),
                min_ms: Some(100),
                ..RtoConfig::default()
            },
            RtoConfig {
                initial_ms: Some(501),
                max_ms: Some(500),
                ..RtoConfig::default()
            },
        ] {
            let mut config = SctpConnectConfig::new("127.0.0.1:38412".parse().unwrap());
            config.rto = rto;
            assert!(matches!(
                config.validate(),
                Err(SctpError::InvalidConfig { field: "rto", .. })
            ));
        }

        let mut config = SctpConnectConfig::new("127.0.0.1:38412".parse().unwrap());
        config.heartbeat.path_max_retrans = Some(0);
        assert!(matches!(
            config.validate(),
            Err(SctpError::InvalidConfig {
                field: "heartbeat.path_max_retrans",
                ..
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
                accepted_legacy_diameter_zero_ppid_messages: 0,
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
    async fn concurrent_association_receives_preserve_multi_chunk_messages() {
        let server_addr: SocketAddr = "127.0.0.1:38421".parse().unwrap();
        let server = SctpEndpoint::bind(SctpEndpointConfig::one_to_one(server_addr)).unwrap();
        let client = SctpAssociation::connect(SctpConnectConfig::new(server_addr))
            .await
            .unwrap();
        let accepted = server.accept().await.unwrap();
        let first_payload = Bytes::from(vec![0xA1_u8; 100_000]);
        let second_payload = Bytes::from(vec![0xB2_u8; 100_000]);

        let send_both = async {
            client
                .send(OutboundMessage::ordered(
                    first_payload.clone(),
                    1,
                    DIAMETER_SCTP_PPID,
                ))
                .await
                .unwrap();
            client
                .send(OutboundMessage::ordered(
                    second_payload.clone(),
                    2,
                    DIAMETER_SCTP_PPID,
                ))
                .await
                .unwrap();
        };
        let receive_both = async { tokio::join!(recv_data(&accepted), recv_data(&accepted)) };
        let (_, (first_received, second_received)) =
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                tokio::join!(send_both, receive_both)
            })
            .await
            .expect("concurrent multi-chunk receive timed out");

        let mut received = [first_received, second_received];
        received.sort_by_key(|message| message.payload.first().copied());
        assert_eq!(received[0].payload, first_payload);
        assert_eq!(received[0].stream_id, 1);
        assert_eq!(received[1].payload, second_payload);
        assert_eq!(received[1].stream_id, 2);
        assert!(received.iter().all(|message| {
            !message.truncated && !message.control_truncated && message.ppid == DIAMETER_SCTP_PPID
        }));
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

        assert_eq!(
            client.peer_path_health(),
            vec![SctpPathHealth {
                peer_addr: server_addr,
                status: SctpPathStatus::Reachable,
                primary: true,
            }]
        );
        let mut accepted_health_addrs: Vec<_> = accepted
            .peer_path_health()
            .into_iter()
            .map(|path| path.peer_addr)
            .collect();
        accepted_health_addrs.sort_unstable();
        let mut accepted_kernel_addrs = accepted.peer_addresses().unwrap();
        accepted_kernel_addrs.sort_unstable();
        assert_eq!(accepted_health_addrs, accepted_kernel_addrs);

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
        server_config.rto = RtoConfig {
            initial_ms: Some(500),
            min_ms: Some(100),
            max_ms: Some(2_000),
        };
        server_config.heartbeat = HeartbeatConfig {
            interval_ms: Some(250),
            path_max_retrans: Some(2),
        };
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
        client_config.rto = RtoConfig {
            initial_ms: Some(500),
            min_ms: Some(100),
            max_ms: Some(2_000),
        };
        client_config.heartbeat = HeartbeatConfig {
            interval_ms: Some(250),
            path_max_retrans: Some(2),
        };
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

        let client_paths = client.peer_path_health();
        assert_eq!(client_paths.len(), 2);
        assert_eq!(client_paths[0].peer_addr, server_addresses[0]);
        assert_eq!(client_paths[1].peer_addr, server_addresses[1]);
        let primary_paths: Vec<_> = client_paths.iter().filter(|path| path.primary).collect();
        assert_eq!(primary_paths.len(), 1);
        assert_eq!(primary_paths[0].status, SctpPathStatus::Reachable);
        assert!(server_addresses.contains(&primary_paths[0].peer_addr));
        let mut accepted_health_addrs: Vec<_> = accepted
            .peer_path_health()
            .into_iter()
            .map(|path| path.peer_addr)
            .collect();
        accepted_health_addrs.sort_unstable();
        let mut accepted_kernel_addrs = accepted.peer_addresses().unwrap();
        accepted_kernel_addrs.sort_unstable();
        assert_eq!(accepted_health_addrs, accepted_kernel_addrs);

        let mut client_local = client.local_addresses().unwrap();
        client_local.sort_unstable();
        assert_eq!(client_local.len(), 2);
        assert_eq!(client_local[0].ip().to_string(), "127.0.0.3");
        assert_eq!(client_local[1].ip().to_string(), "127.0.0.4");

        let mut client_peer = client.peer_addresses().unwrap();
        client_peer.sort_unstable();
        assert_eq!(client_peer, server_addresses);

        let unknown_peer = SocketAddr::new(
            "127.0.0.9".parse::<std::net::IpAddr>().unwrap(),
            server_addresses[0].port(),
        );
        assert!(matches!(
            client.set_primary_peer_path(unknown_peer),
            Err(SctpError::InvalidConfig {
                field: "peer_addr",
                ..
            })
        ));
        client.set_primary_peer_path(server_addresses[1]).unwrap();
        let selected_primary: Vec<_> = client
            .peer_path_health()
            .into_iter()
            .filter(|path| path.primary)
            .collect();
        assert_eq!(selected_primary.len(), 1);
        assert_eq!(selected_primary[0].peer_addr, server_addresses[1]);

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
        client_config.rto = RtoConfig {
            initial_ms: Some(500),
            min_ms: Some(100),
            max_ms: Some(2_000),
        };
        client_config.heartbeat = HeartbeatConfig {
            interval_ms: Some(250),
            path_max_retrans: Some(2),
        };
        let client = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            DiameterSctpAssociation::connect_unprotected_with_config_and_inbound_ppid_policy(
                client_config,
                DiameterInboundPpidPolicy::AcceptLegacyZero,
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
                PayloadProtocolIdentifier::new(0),
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
        assert_eq!(client.peer_path_health().len(), 2);
        client.set_primary_peer_path(server_addresses[1]).unwrap();
        assert_eq!(
            client
                .peer_path_health()
                .into_iter()
                .find(|path| path.primary)
                .map(|path| path.peer_addr),
            Some(server_addresses[1])
        );
        assert_eq!(
            client.peer().inbound_ppid_policy,
            DiameterInboundPpidPolicy::AcceptLegacyZero
        );
        assert_eq!(
            client.metrics().accepted_legacy_diameter_zero_ppid_messages,
            1
        );
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
        let client = DiameterSctpPeer::new_unprotected(server_addr)
            .connect_association()
            .await
            .unwrap();
        let accepted = server.accept().await.unwrap();
        (server, client, accepted)
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires Linux kernel SCTP support"]
    async fn loopback_diameter_legacy_zero_policy_is_inbound_only_and_counted() {
        let server_addr: SocketAddr = "127.0.0.1:38419".parse().unwrap();
        let server = SctpEndpoint::bind(SctpEndpointConfig::one_to_one(server_addr)).unwrap();
        let client = DiameterSctpPeer::new_unprotected(server_addr)
            .with_inbound_ppid_policy(DiameterInboundPpidPolicy::AcceptLegacyZero)
            .connect_association()
            .await
            .unwrap();
        let accepted = server.accept().await.unwrap();

        let outbound = Bytes::from_static(b"diameter-cer");
        client
            .send_diameter_payload(outbound.clone())
            .await
            .unwrap();
        let received = recv_data(&accepted).await;
        assert_eq!(received.payload, outbound);
        assert_eq!(received.ppid, DIAMETER_SCTP_PPID);

        for (payload, ppid) in [
            (
                Bytes::from_static(b"legacy-zero-cea"),
                PayloadProtocolIdentifier::new(0),
            ),
            (Bytes::from_static(b"standard-diameter"), DIAMETER_SCTP_PPID),
            (
                Bytes::from_static(b"second-legacy-zero"),
                PayloadProtocolIdentifier::new(0),
            ),
        ] {
            accepted
                .send(OutboundMessage::ordered(
                    payload.clone(),
                    DIAMETER_DEFAULT_STREAM_ID,
                    ppid,
                ))
                .await
                .unwrap();
            assert_eq!(client.recv_diameter_payload().await.unwrap(), payload);
        }

        assert_eq!(
            client.peer().inbound_ppid_policy,
            DiameterInboundPpidPolicy::AcceptLegacyZero
        );
        assert_eq!(
            client.metrics().accepted_legacy_diameter_zero_ppid_messages,
            2
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires Linux kernel SCTP support"]
    async fn loopback_diameter_explicit_legacy_zero_outbound_does_not_weaken_inbound() {
        let server_addr: SocketAddr = "127.0.0.1:38420".parse().unwrap();
        let server = SctpEndpoint::bind(SctpEndpointConfig::one_to_one(server_addr)).unwrap();
        let client = DiameterSctpPeer::new_unprotected(server_addr)
            .with_outbound_ppid_policy(DiameterOutboundPpidPolicy::LegacyZero)
            .connect_association()
            .await
            .unwrap();
        let accepted = server.accept().await.unwrap();

        let outbound = Bytes::from_static(b"legacy-zero-diameter-cer");
        client
            .send_diameter_payload(outbound.clone())
            .await
            .unwrap();
        let received = recv_data(&accepted).await;
        assert_eq!(received.payload, outbound);
        assert_eq!(received.ppid, PayloadProtocolIdentifier::new(0));
        assert_eq!(
            client.peer().inbound_ppid_policy,
            DiameterInboundPpidPolicy::Strict
        );
        assert_eq!(
            client.peer().outbound_ppid_policy,
            DiameterOutboundPpidPolicy::LegacyZero
        );

        accepted
            .send(OutboundMessage::ordered(
                Bytes::from_static(b"legacy-zero-diameter-cea"),
                DIAMETER_DEFAULT_STREAM_ID,
                PayloadProtocolIdentifier::new(0),
            ))
            .await
            .unwrap();
        let error = client.recv_diameter_payload().await.unwrap_err();
        assert!(matches!(
            error,
            DiameterSctpError::WrongPpid {
                expected: 46,
                actual: 0
            }
        ));
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
    async fn loopback_diameter_recv_surfaces_transport_notification() {
        let server_addr: SocketAddr = "127.0.0.1:38420".parse().unwrap();
        let (_server, client, _accepted) = diameter_loopback(server_addr).await;

        let inbound = tokio::time::timeout(std::time::Duration::from_secs(5), client.recv())
            .await
            .expect("Diameter SCTP notification timed out")
            .unwrap();
        assert!(matches!(
            inbound,
            DiameterSctpInbound::Notification(Some(
                SctpEvent::AssociationChange { .. } | SctpEvent::PeerAddrChange { .. }
            ))
        ));
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
                reserved_diameter_dtls_ppid(),
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
