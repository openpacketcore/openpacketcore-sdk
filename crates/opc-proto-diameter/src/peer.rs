//! Transport-neutral Diameter peer procedure helpers.
//!
//! This module implements RFC 6733 base peer procedure builders/parsers and
//! capability intersection helpers without owning TCP/SCTP connections, realm
//! routing, watchdog thresholds, failover, or deployment readiness policy.
//!
//! @spec IETF RFC6733 5.3
//! @spec IETF RFC6733 5.4
//! @spec IETF RFC6733 5.5
//! @req REQ-IETF-RFC6733-PEER-001

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str;

use bytes::{BufMut, Bytes, BytesMut};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeError, DecodeErrorCode, Encode, EncodeContext, EncodeError,
    EncodeErrorCode, SpecRef, UnknownIePolicy,
};

use crate::base::{
    self, APPLICATION_ID_RELAY, AVP_ACCT_APPLICATION_ID, AVP_AUTH_APPLICATION_ID,
    AVP_DISCONNECT_CAUSE, AVP_ERROR_MESSAGE, AVP_FAILED_AVP, AVP_FIRMWARE_REVISION,
    AVP_HOST_IP_ADDRESS, AVP_INBAND_SECURITY_ID, AVP_ORIGIN_HOST, AVP_ORIGIN_REALM,
    AVP_ORIGIN_STATE_ID, AVP_PRODUCT_NAME, AVP_RESULT_CODE, AVP_SUPPORTED_VENDOR_ID, AVP_VENDOR_ID,
    AVP_VENDOR_SPECIFIC_APPLICATION_ID, COMMAND_CAPABILITIES_EXCHANGE, COMMAND_DEVICE_WATCHDOG,
    COMMAND_DISCONNECT_PEER, RESULT_CODE_DIAMETER_NO_COMMON_APPLICATION,
    RESULT_CODE_DIAMETER_SUCCESS,
};
use crate::dictionary::{CommandKind, Dictionary, DictionarySet};
use crate::{
    ApplicationId, AvpCode, AvpHeader, CommandCode, CommandFlags, FlagRequirement, Header, Message,
    OwnedMessage, RawAvp, VendorId, DIAMETER_HEADER_LEN, MAX_U24,
};

static PEER_DICTIONARY_REFS: [&Dictionary; 1] = [base::dictionary()];

/// Dictionary set used by the peer helpers.
pub static PEER_DICTIONARIES: DictionarySet<'static> = DictionarySet::new(&PEER_DICTIONARY_REFS);

/// Diameter base peer procedures named by RFC 6733.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerProcedure {
    /// Capabilities exchange procedure.
    CapabilitiesExchange,
    /// Device watchdog procedure.
    DeviceWatchdog,
    /// Disconnect peer procedure.
    DisconnectPeer,
}

impl PeerProcedure {
    /// Return the Diameter command code for this peer procedure.
    pub const fn command_code(self) -> CommandCode {
        match self {
            Self::CapabilitiesExchange => COMMAND_CAPABILITIES_EXCHANGE,
            Self::DeviceWatchdog => COMMAND_DEVICE_WATCHDOG,
            Self::DisconnectPeer => COMMAND_DISCONNECT_PEER,
        }
    }

    /// Return the request command dictionary name for this procedure.
    pub const fn request_name(self) -> &'static str {
        match self {
            Self::CapabilitiesExchange => "Capabilities-Exchange-Request",
            Self::DeviceWatchdog => "Device-Watchdog-Request",
            Self::DisconnectPeer => "Disconnect-Peer-Request",
        }
    }

    /// Return the answer command dictionary name for this procedure.
    pub const fn answer_name(self) -> &'static str {
        match self {
            Self::CapabilitiesExchange => "Capabilities-Exchange-Answer",
            Self::DeviceWatchdog => "Device-Watchdog-Answer",
            Self::DisconnectPeer => "Disconnect-Peer-Answer",
        }
    }

    fn spec_section(self, kind: CommandKind) -> &'static str {
        match (self, kind) {
            (Self::CapabilitiesExchange, CommandKind::Request) => "5.3.1",
            (Self::CapabilitiesExchange, CommandKind::Answer) => "5.3.2",
            (Self::DisconnectPeer, CommandKind::Request) => "5.4.1",
            (Self::DisconnectPeer, CommandKind::Answer) => "5.4.2",
            (Self::DeviceWatchdog, CommandKind::Request) => "5.5.1",
            (Self::DeviceWatchdog, CommandKind::Answer) => "5.5.2",
        }
    }
}

/// Return the peer procedure for a base command code, if one is known.
pub const fn procedure_for_command(command_code: CommandCode) -> Option<PeerProcedure> {
    if command_code.get() == COMMAND_CAPABILITIES_EXCHANGE.get() {
        Some(PeerProcedure::CapabilitiesExchange)
    } else if command_code.get() == COMMAND_DEVICE_WATCHDOG.get() {
        Some(PeerProcedure::DeviceWatchdog)
    } else if command_code.get() == COMMAND_DISCONNECT_PEER.get() {
        Some(PeerProcedure::DisconnectPeer)
    } else {
        None
    }
}

/// Return the peer procedure and request/answer role for a decoded header.
pub fn classify_header(header: &Header) -> Option<(PeerProcedure, CommandKind)> {
    procedure_for_command(header.command_code)
        .map(|procedure| (procedure, header.flags.command_kind()))
}

/// Build command flags for a peer request.
pub const fn peer_request_flags(procedure: PeerProcedure) -> CommandFlags {
    match procedure {
        PeerProcedure::CapabilitiesExchange
        | PeerProcedure::DeviceWatchdog
        | PeerProcedure::DisconnectPeer => CommandFlags::request(false),
    }
}

/// Build command flags for a peer answer.
pub const fn peer_answer_flags(procedure: PeerProcedure, error: bool) -> CommandFlags {
    match procedure {
        PeerProcedure::CapabilitiesExchange
        | PeerProcedure::DeviceWatchdog
        | PeerProcedure::DisconnectPeer => CommandFlags::answer(false, error),
    }
}

/// Transport-neutral Diameter peer identity used by base procedures.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerIdentity {
    /// RFC 6733 Origin-Host value.
    pub origin_host: String,
    /// RFC 6733 Origin-Realm value.
    pub origin_realm: String,
}

impl PeerIdentity {
    /// Create a peer identity from Origin-Host and Origin-Realm values.
    pub fn new(origin_host: impl Into<String>, origin_realm: impl Into<String>) -> Self {
        Self {
            origin_host: origin_host.into(),
            origin_realm: origin_realm.into(),
        }
    }

    fn validate_for_encode(&self, section: &'static str) -> Result<(), EncodeError> {
        if self.origin_host.is_empty() {
            return Err(encode_structural_error(
                "diameter peer Origin-Host must not be empty",
                section,
            ));
        }
        if self.origin_realm.is_empty() {
            return Err(encode_structural_error(
                "diameter peer Origin-Realm must not be empty",
                section,
            ));
        }
        Ok(())
    }
}

/// RFC 6733 Host-IP-Address value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HostIpAddress {
    /// IPv4 Host-IP-Address with AddressType 1.
    Ipv4([u8; 4]),
    /// IPv6 Host-IP-Address with AddressType 2.
    Ipv6([u8; 16]),
}

impl HostIpAddress {
    /// Create an IPv4 Host-IP-Address from wire-order octets.
    pub const fn ipv4(octets: [u8; 4]) -> Self {
        Self::Ipv4(octets)
    }

    /// Create an IPv6 Host-IP-Address from wire-order octets.
    pub const fn ipv6(octets: [u8; 16]) -> Self {
        Self::Ipv6(octets)
    }

    fn append_value(self, dst: &mut BytesMut) {
        match self {
            Self::Ipv4(octets) => {
                dst.put_u16(1);
                dst.put_slice(&octets);
            }
            Self::Ipv6(octets) => {
                dst.put_u16(2);
                dst.put_slice(&octets);
            }
        }
    }

    fn decode_value(value: &[u8], offset: usize) -> Result<Self, DecodeError> {
        match value {
            [0, 1, a, b, c, d] => Ok(Self::Ipv4([*a, *b, *c, *d])),
            [0, 2, rest @ ..] if rest.len() == 16 => {
                let mut octets = [0_u8; 16];
                octets.copy_from_slice(rest);
                Ok(Self::Ipv6(octets))
            }
            [0, 1, ..] | [0, 2, ..] => Err(DecodeError::new(
                DecodeErrorCode::InvalidLength {
                    reason: "diameter Host-IP-Address value length does not match its address family",
                },
                offset,
            )
            .with_spec_ref(peer_spec("5.3.5"))),
            [family_hi, family_lo, ..] => {
                let family = u16::from_be_bytes([*family_hi, *family_lo]);
                Err(DecodeError::new(
                    DecodeErrorCode::InvalidEnumValue {
                        field: "Host-IP-Address AddressType",
                        value: u64::from(family),
                    },
                    offset,
                )
                .with_spec_ref(peer_spec("5.3.5")))
            }
            _ => Err(DecodeError::new(
                DecodeErrorCode::InvalidLength {
                    reason: "diameter Host-IP-Address value must contain an address family and address bytes",
                },
                offset,
            )
            .with_spec_ref(peer_spec("5.3.5"))),
        }
    }
}

impl From<Ipv4Addr> for HostIpAddress {
    fn from(value: Ipv4Addr) -> Self {
        Self::Ipv4(value.octets())
    }
}

impl From<Ipv6Addr> for HostIpAddress {
    fn from(value: Ipv6Addr) -> Self {
        Self::Ipv6(value.octets())
    }
}

/// Vendor-specific Diameter application advertised during capabilities exchange.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VendorSpecificApplication {
    /// Vendor identifiers associated with the advertised application.
    pub vendor_ids: Vec<VendorId>,
    /// Authentication application identifier, when this advertises an auth app.
    pub auth_application_id: Option<ApplicationId>,
    /// Accounting application identifier, when this advertises an accounting app.
    pub acct_application_id: Option<ApplicationId>,
}

impl VendorSpecificApplication {
    /// Create a vendor-specific authentication application advertisement.
    pub fn auth(vendor_id: VendorId, application_id: ApplicationId) -> Self {
        Self {
            vendor_ids: vec![vendor_id],
            auth_application_id: Some(application_id),
            acct_application_id: None,
        }
    }

    /// Create a vendor-specific accounting application advertisement.
    pub fn acct(vendor_id: VendorId, application_id: ApplicationId) -> Self {
        Self {
            vendor_ids: vec![vendor_id],
            auth_application_id: None,
            acct_application_id: Some(application_id),
        }
    }

    fn validate_for_encode(&self, section: &'static str) -> Result<(), EncodeError> {
        if self.vendor_ids.len() != 1 {
            return Err(encode_structural_error(
                "diameter Vendor-Specific-Application-Id requires exactly one Vendor-Id",
                section,
            ));
        }
        if self.auth_application_id.is_some() == self.acct_application_id.is_some() {
            return Err(encode_structural_error(
                "diameter Vendor-Specific-Application-Id requires exactly one Auth-Application-Id or Acct-Application-Id",
                section,
            ));
        }
        Ok(())
    }
}

/// Capabilities exchanged by Diameter peers in CER/CEA messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerCapabilities {
    /// Peer identity AVPs.
    pub identity: PeerIdentity,
    /// Host-IP-Address AVPs advertised by the peer.
    pub host_ip_addresses: Vec<HostIpAddress>,
    /// Vendor-Id AVP value.
    pub vendor_id: VendorId,
    /// Product-Name AVP value.
    pub product_name: String,
    /// Optional Origin-State-Id AVP value.
    pub origin_state_id: Option<u32>,
    /// Optional Firmware-Revision AVP value.
    pub firmware_revision: Option<u32>,
    /// Supported-Vendor-Id AVP values.
    pub supported_vendor_ids: Vec<VendorId>,
    /// Auth-Application-Id AVP values.
    pub auth_application_ids: Vec<ApplicationId>,
    /// Acct-Application-Id AVP values.
    pub acct_application_ids: Vec<ApplicationId>,
    /// Vendor-Specific-Application-Id AVP values.
    pub vendor_specific_applications: Vec<VendorSpecificApplication>,
    /// Inband-Security-Id AVP values.
    pub inband_security_ids: Vec<u32>,
}

impl PeerCapabilities {
    /// Create base peer capabilities with required CER/CEA fields.
    pub fn new(
        identity: PeerIdentity,
        host_ip_addresses: Vec<HostIpAddress>,
        vendor_id: VendorId,
        product_name: impl Into<String>,
    ) -> Self {
        Self {
            identity,
            host_ip_addresses,
            vendor_id,
            product_name: product_name.into(),
            origin_state_id: None,
            firmware_revision: None,
            supported_vendor_ids: Vec::new(),
            auth_application_ids: Vec::new(),
            acct_application_ids: Vec::new(),
            vendor_specific_applications: Vec::new(),
            inband_security_ids: Vec::new(),
        }
    }

    fn validate_for_encode(&self, section: &'static str) -> Result<(), EncodeError> {
        self.identity.validate_for_encode(section)?;
        if self.host_ip_addresses.is_empty() {
            return Err(encode_structural_error(
                "diameter peer capabilities require at least one Host-IP-Address",
                section,
            ));
        }
        if self.product_name.is_empty() {
            return Err(encode_structural_error(
                "diameter peer Product-Name must not be empty",
                section,
            ));
        }
        for vendor_id in &self.supported_vendor_ids {
            if vendor_id.get() == 0 {
                return Err(encode_structural_error(
                    "diameter Supported-Vendor-Id must not be zero",
                    "5.3.6",
                ));
            }
        }
        for application in &self.vendor_specific_applications {
            application.validate_for_encode(section)?;
        }
        Ok(())
    }
}

/// Optional diagnostic AVPs carried by Diameter answer messages.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnswerDiagnostics {
    /// Optional Error-Message AVP value.
    pub error_message: Option<String>,
    /// Raw Failed-AVP grouped values, preserving each AVP value exactly.
    pub failed_avps: Vec<Bytes>,
}

impl AnswerDiagnostics {
    /// Return true when no diagnostic AVPs are present.
    pub fn is_empty(&self) -> bool {
        self.error_message.is_none() && self.failed_avps.is_empty()
    }
}

/// Parsed Capabilities-Exchange-Answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilitiesExchangeAnswer {
    /// Result-Code AVP value.
    pub result_code: u32,
    /// Peer capabilities carried by the answer.
    pub capabilities: PeerCapabilities,
    /// Optional diagnostic AVPs carried by the answer.
    pub diagnostics: AnswerDiagnostics,
}

/// Parsed Capabilities-Exchange protocol-error answer that follows the
/// RFC 6733 section 7.2 error grammar without full capability AVPs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilitiesExchangeErrorAnswer {
    /// Protocol-error Result-Code AVP value.
    pub result_code: u32,
    /// Origin-Host and Origin-Realm AVPs carried by the error answer.
    pub identity: PeerIdentity,
    /// Optional diagnostic AVPs carried by the answer.
    pub diagnostics: AnswerDiagnostics,
}

/// Disconnect-Cause AVP values used by DPR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DisconnectCause {
    /// Peer is rebooting.
    Rebooting,
    /// Peer is too busy to continue the connection.
    Busy,
    /// Peer does not want to talk to the remote peer.
    DoNotWantToTalkToYou,
}

impl DisconnectCause {
    /// Return the RFC 6733 enumerated wire value.
    pub const fn value(self) -> u32 {
        match self {
            Self::Rebooting => 0,
            Self::Busy => 1,
            Self::DoNotWantToTalkToYou => 2,
        }
    }

    fn decode(value: u32, offset: usize) -> Result<Self, DecodeError> {
        match value {
            0 => Ok(Self::Rebooting),
            1 => Ok(Self::Busy),
            2 => Ok(Self::DoNotWantToTalkToYou),
            other => Err(DecodeError::new(
                DecodeErrorCode::InvalidEnumValue {
                    field: "Disconnect-Cause",
                    value: u64::from(other),
                },
                offset,
            )
            .with_spec_ref(peer_spec("5.4.3"))),
        }
    }
}

/// Parsed Disconnect-Peer-Request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisconnectPeerRequest {
    /// Origin-Host and Origin-Realm AVPs.
    pub identity: PeerIdentity,
    /// Disconnect-Cause AVP value.
    pub disconnect_cause: DisconnectCause,
    /// Optional Origin-State-Id AVP value.
    pub origin_state_id: Option<u32>,
}

/// Parsed Device-Watchdog-Request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceWatchdogRequest {
    /// Origin-Host and Origin-Realm AVPs.
    pub identity: PeerIdentity,
    /// Optional Origin-State-Id AVP value.
    pub origin_state_id: Option<u32>,
}

/// Parsed Device-Watchdog-Answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceWatchdogAnswer {
    /// Result-Code AVP value.
    pub result_code: u32,
    /// Origin-Host and Origin-Realm AVPs.
    pub identity: PeerIdentity,
    /// Optional Origin-State-Id AVP value.
    pub origin_state_id: Option<u32>,
    /// Optional diagnostic AVPs carried by the answer.
    pub diagnostics: AnswerDiagnostics,
}

/// Parsed Disconnect-Peer-Answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisconnectPeerAnswer {
    /// Result-Code AVP value.
    pub result_code: u32,
    /// Origin-Host and Origin-Realm AVPs.
    pub identity: PeerIdentity,
    /// Optional Origin-State-Id AVP value.
    pub origin_state_id: Option<u32>,
    /// Optional diagnostic AVPs carried by the answer.
    pub diagnostics: AnswerDiagnostics,
}

/// Capability intersection computed from two CER/CEA capability sets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityNegotiation {
    /// Common application identifiers computed across Auth-Application-Id,
    /// Acct-Application-Id, and Vendor-Specific-Application-Id application
    /// identifiers, preserving local order and ignoring nested VSA Vendor-Id
    /// values per RFC 6733 section 5.3.
    pub application_ids: Vec<ApplicationId>,
    /// Whether either peer advertises the Diameter Relay Application Id, which
    /// RFC 6733 treats as sufficient for a common-application readiness result.
    pub relay_application: bool,
    /// Common Supported-Vendor-Id values, preserving local order.
    pub supported_vendor_ids: Vec<VendorId>,
    /// Common Auth-Application-Id values, preserving local order.
    pub auth_application_ids: Vec<ApplicationId>,
    /// Common Acct-Application-Id values, preserving local order.
    pub acct_application_ids: Vec<ApplicationId>,
    /// Common Vendor-Specific-Application-Id values.
    pub vendor_specific_applications: Vec<VendorSpecificApplication>,
    /// Common Inband-Security-Id values, preserving local order.
    pub inband_security_ids: Vec<u32>,
}

impl CapabilityNegotiation {
    /// Return true when at least one auth, accounting, or vendor-specific
    /// application is common to both peers, or either peer advertises relay.
    pub fn has_common_application(&self) -> bool {
        !self.application_ids.is_empty()
            || self.relay_application
            || !self.auth_application_ids.is_empty()
            || !self.acct_application_ids.is_empty()
            || !self.vendor_specific_applications.is_empty()
    }

    /// Return the Capabilities-Exchange-Answer Result-Code for this negotiation.
    pub fn cea_result_code(&self) -> u32 {
        if self.has_common_application() {
            RESULT_CODE_DIAMETER_SUCCESS
        } else {
            RESULT_CODE_DIAMETER_NO_COMMON_APPLICATION
        }
    }
}

/// Product-neutral policy used to decide whether negotiated Diameter peer
/// capabilities are sufficient for a live peer session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSessionPolicy {
    /// Application identifiers accepted by product policy. When empty, any
    /// common non-relay application is accepted.
    pub accepted_application_ids: Vec<ApplicationId>,
    /// Inband-Security-Id values accepted by product policy. When empty, any
    /// in-band security intersection is accepted.
    pub accepted_inband_security_ids: Vec<u32>,
    /// Whether the Diameter Relay Application can satisfy common-application
    /// readiness when no accepted application identifier is configured.
    pub allow_relay_application: bool,
    /// Consecutive missed watchdog threshold. Values below one are treated as
    /// one by the state machine.
    pub watchdog_miss_threshold: usize,
}

impl Default for PeerSessionPolicy {
    fn default() -> Self {
        Self {
            accepted_application_ids: Vec::new(),
            accepted_inband_security_ids: Vec::new(),
            allow_relay_application: true,
            watchdog_miss_threshold: 3,
        }
    }
}

impl PeerSessionPolicy {
    /// Return a policy that accepts any common Diameter application.
    #[must_use]
    pub fn any_common_application() -> Self {
        Self::default()
    }

    /// Return a copy that accepts the supplied application identifier.
    #[must_use]
    pub fn accept_application(mut self, application_id: ApplicationId) -> Self {
        self.accepted_application_ids.push(application_id);
        self
    }

    /// Return a copy that accepts the supplied Inband-Security-Id value.
    #[must_use]
    pub fn accept_inband_security(mut self, security_id: u32) -> Self {
        self.accepted_inband_security_ids.push(security_id);
        self
    }

    /// Return a copy that does not allow relay-only readiness.
    #[must_use]
    pub fn without_relay_application(mut self) -> Self {
        self.allow_relay_application = false;
        self
    }

    /// Return a copy with a custom missed-watchdog threshold.
    #[must_use]
    pub fn with_watchdog_miss_threshold(mut self, threshold: usize) -> Self {
        self.watchdog_miss_threshold = threshold.max(1);
        self
    }
}

/// Transport-neutral Diameter peer session state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerSessionState {
    /// No peer-control evidence has been observed.
    Idle,
    /// A CER was sent or received and capability readiness is pending.
    CapabilitiesPending,
    /// Capabilities are negotiated and no liveness probe is outstanding.
    Negotiated,
    /// A DWR was sent and a matching liveness answer is pending.
    WatchdogProbing,
    /// The peer is negotiated but recent liveness evidence is weak.
    Degraded,
    /// The peer requested disconnect and local drain is in progress.
    Draining,
    /// A local DPR was sent and DPA is pending.
    Disconnecting,
    /// The session failed closed.
    Failed,
    /// The caller should attempt a reconnect.
    Reconnecting,
    /// The caller should wait before reconnecting.
    Backoff,
}

impl PeerSessionState {
    /// Stable machine name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::CapabilitiesPending => "capabilities_pending",
            Self::Negotiated => "negotiated",
            Self::WatchdogProbing => "watchdog_probing",
            Self::Degraded => "degraded",
            Self::Draining => "draining",
            Self::Disconnecting => "disconnecting",
            Self::Failed => "failed",
            Self::Reconnecting => "reconnecting",
            Self::Backoff => "backoff",
        }
    }
}

/// Transport-neutral Diameter peer session event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerSessionEvent {
    /// A CER was sent.
    CapabilitiesRequestSent,
    /// A CER was received.
    CapabilitiesRequestReceived,
    /// A CEA was accepted.
    CapabilitiesAnswerAccepted,
    /// A CEA was rejected by result code or policy.
    CapabilitiesAnswerRejected,
    /// A protocol-error CEA was observed.
    CapabilitiesProtocolError,
    /// A DWR was sent.
    WatchdogRequestSent,
    /// A DWR was received.
    WatchdogRequestReceived,
    /// A DWA was accepted.
    WatchdogAnswerAccepted,
    /// A DWA was rejected by result code.
    WatchdogAnswerRejected,
    /// A watchdog answer was missed.
    WatchdogMissed,
    /// A DPR was sent.
    DisconnectRequestSent,
    /// A DPR was received.
    DisconnectRequestReceived,
    /// A DPA was sent.
    DisconnectAnswerSent,
    /// A DPA was received.
    DisconnectAnswerReceived,
    /// A reconnect was requested.
    ReconnectScheduled,
    /// A reconnect backoff was entered.
    BackoffEntered,
    /// A reconnect backoff elapsed.
    BackoffElapsed,
    /// The session failed for an external reason.
    Failure,
}

impl PeerSessionEvent {
    /// Stable machine name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CapabilitiesRequestSent => "capabilities_request_sent",
            Self::CapabilitiesRequestReceived => "capabilities_request_received",
            Self::CapabilitiesAnswerAccepted => "capabilities_answer_accepted",
            Self::CapabilitiesAnswerRejected => "capabilities_answer_rejected",
            Self::CapabilitiesProtocolError => "capabilities_protocol_error",
            Self::WatchdogRequestSent => "watchdog_request_sent",
            Self::WatchdogRequestReceived => "watchdog_request_received",
            Self::WatchdogAnswerAccepted => "watchdog_answer_accepted",
            Self::WatchdogAnswerRejected => "watchdog_answer_rejected",
            Self::WatchdogMissed => "watchdog_missed",
            Self::DisconnectRequestSent => "disconnect_request_sent",
            Self::DisconnectRequestReceived => "disconnect_request_received",
            Self::DisconnectAnswerSent => "disconnect_answer_sent",
            Self::DisconnectAnswerReceived => "disconnect_answer_received",
            Self::ReconnectScheduled => "reconnect_scheduled",
            Self::BackoffEntered => "backoff_entered",
            Self::BackoffElapsed => "backoff_elapsed",
            Self::Failure => "failure",
        }
    }
}

/// Stable redaction-safe blocker emitted by the Diameter peer session helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerSessionBlocker {
    /// Capability exchange has not completed.
    CapabilitiesExchangePending,
    /// CEA Result-Code was not success.
    CapabilitiesResultNotSuccess,
    /// CEA was a protocol-error answer.
    CapabilitiesProtocolError,
    /// No common Diameter application was negotiated.
    NoCommonApplication,
    /// No accepted application identifier was negotiated.
    AcceptedApplicationMissing,
    /// No accepted Inband-Security-Id value was negotiated.
    AcceptedInbandSecurityMissing,
    /// A DWA is pending.
    WatchdogAnswerPending,
    /// DWA Result-Code was not success.
    WatchdogResultNotSuccess,
    /// A watchdog answer was missed but the threshold has not been exceeded.
    WatchdogMissed,
    /// Missed watchdog threshold was exceeded.
    WatchdogMissThresholdExceeded,
    /// Disconnect drain is in progress.
    DisconnectInProgress,
    /// The peer requested disconnect.
    PeerRequestedDisconnect,
    /// DPA Result-Code was not success.
    DisconnectResultNotSuccess,
    /// Reconnect backoff is active.
    ReconnectBackoff,
    /// The session failed closed.
    SessionFailed,
}

impl PeerSessionBlocker {
    /// Stable machine-readable blocker code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CapabilitiesExchangePending => "diameter_peer_capabilities_pending",
            Self::CapabilitiesResultNotSuccess => "diameter_peer_capabilities_result_not_success",
            Self::CapabilitiesProtocolError => "diameter_peer_capabilities_protocol_error",
            Self::NoCommonApplication => "diameter_peer_no_common_application",
            Self::AcceptedApplicationMissing => "diameter_peer_accepted_application_missing",
            Self::AcceptedInbandSecurityMissing => "diameter_peer_accepted_inband_security_missing",
            Self::WatchdogAnswerPending => "diameter_peer_watchdog_answer_pending",
            Self::WatchdogResultNotSuccess => "diameter_peer_watchdog_result_not_success",
            Self::WatchdogMissed => "diameter_peer_watchdog_missed",
            Self::WatchdogMissThresholdExceeded => "diameter_peer_watchdog_miss_threshold_exceeded",
            Self::DisconnectInProgress => "diameter_peer_disconnect_in_progress",
            Self::PeerRequestedDisconnect => "diameter_peer_disconnect_requested",
            Self::DisconnectResultNotSuccess => "diameter_peer_disconnect_result_not_success",
            Self::ReconnectBackoff => "diameter_peer_reconnect_backoff",
            Self::SessionFailed => "diameter_peer_session_failed",
        }
    }
}

/// Redaction-safe readiness projection for a Diameter peer session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSessionReadiness {
    /// Current session state.
    pub state: PeerSessionState,
    /// Whether capability negotiation is complete and no probe is outstanding.
    pub negotiated: bool,
    /// Whether a watchdog probe is outstanding.
    pub probing: bool,
    /// Whether the session is degraded but not failed.
    pub degraded: bool,
    /// Whether the session failed closed.
    pub failed: bool,
    /// Whether disconnect drain is in progress.
    pub draining: bool,
    /// Whether reconnect work is required or delayed by backoff.
    pub reconnecting: bool,
    /// Whether the peer is ready for product traffic.
    pub traffic_ready: bool,
    /// Stable blockers in evaluation order.
    pub blockers: Vec<PeerSessionBlocker>,
}

/// Projection of a CEA or received CER into generic session readiness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSessionCapabilityProjection {
    /// Result-Code used for this projection.
    pub result_code: u32,
    /// Whether any accepted common application exists.
    pub has_common_application: bool,
    /// Whether relay application negotiation contributed readiness.
    pub relay_application_common: bool,
    /// Whether configured accepted application policy passed.
    pub accepted_application_common: bool,
    /// Whether configured accepted in-band security policy passed.
    pub accepted_inband_security_common: bool,
    /// Whether diagnostic AVPs were present in the CEA.
    pub diagnostics_present: bool,
    /// Whether the capability evidence is accepted.
    pub accepted: bool,
    /// Stable blockers in evaluation order.
    pub blockers: Vec<PeerSessionBlocker>,
}

/// Projection of DWA liveness evidence into generic session readiness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSessionWatchdogProjection {
    /// DWA Result-Code, when a DWA was observed.
    pub result_code: Option<u32>,
    /// Optional peer Origin-State-Id from DWA or DWR evidence.
    pub origin_state_id: Option<u32>,
    /// Whether diagnostic AVPs were present in the DWA.
    pub diagnostics_present: bool,
    /// Consecutive missed watchdog answers.
    pub missed_watchdogs: usize,
    /// Whether the liveness evidence is accepted.
    pub alive: bool,
    /// Stable blockers in evaluation order.
    pub blockers: Vec<PeerSessionBlocker>,
}

/// Projection of DPR/DPA drain evidence into generic session readiness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSessionDisconnectProjection {
    /// DPA Result-Code, when a DPA was observed or sent.
    pub result_code: Option<u32>,
    /// Whether the peer initiated the disconnect.
    pub peer_requested: bool,
    /// Whether the disconnect was acknowledged with success.
    pub acknowledged: bool,
    /// Whether reconnect should be scheduled after drain.
    pub reconnect_intent: bool,
    /// Stable blockers in evaluation order.
    pub blockers: Vec<PeerSessionBlocker>,
}

/// One emitted transition from the Diameter peer session helper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSessionTransition {
    /// Event that caused the transition.
    pub event: PeerSessionEvent,
    /// State before the event.
    pub previous_state: PeerSessionState,
    /// State after the event.
    pub state: PeerSessionState,
    /// Readiness after the event.
    pub readiness: PeerSessionReadiness,
}

/// Redaction-safe snapshot of a Diameter peer session helper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSessionSnapshot {
    /// Current session state.
    pub state: PeerSessionState,
    /// Current readiness projection.
    pub readiness: PeerSessionReadiness,
    /// CER messages sent by this session.
    pub capabilities_requests_sent: usize,
    /// CER messages received by this session.
    pub capabilities_requests_received: usize,
    /// CEA messages observed by this session.
    pub capabilities_answers_observed: usize,
    /// Protocol-error CEA messages observed by this session.
    pub capabilities_protocol_errors_observed: usize,
    /// DWR messages sent by this session.
    pub watchdog_requests_sent: usize,
    /// DWR messages received by this session.
    pub watchdog_requests_received: usize,
    /// DWA messages observed by this session.
    pub watchdog_answers_observed: usize,
    /// Consecutive missed DWA events.
    pub missed_watchdogs: usize,
    /// DPR messages sent by this session.
    pub disconnect_requests_sent: usize,
    /// DPR messages received by this session.
    pub disconnect_requests_received: usize,
    /// DPA messages observed or sent by this session.
    pub disconnect_answers_observed: usize,
    /// Reconnect intents emitted by this session.
    pub reconnects_scheduled: usize,
    /// Backoff entries emitted by this session.
    pub backoffs_entered: usize,
}

/// Diameter peer session state-machine error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerSessionError {
    /// Operation is not valid in the current state.
    InvalidTransition {
        /// Operation attempted.
        operation: &'static str,
        /// Current state.
        state: PeerSessionState,
    },
}

impl PeerSessionError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidTransition { .. } => "diameter_peer_session_invalid_transition",
        }
    }
}

impl fmt::Display for PeerSessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTransition { operation, state } => write!(
                f,
                "diameter_peer_session_invalid_transition: operation {operation}, state {}",
                state.as_str()
            ),
        }
    }
}

impl std::error::Error for PeerSessionError {}

/// Transport-neutral Diameter peer session state machine.
#[derive(Clone)]
pub struct PeerSession {
    local_capabilities: PeerCapabilities,
    policy: PeerSessionPolicy,
    state: PeerSessionState,
    remote_capabilities: Option<PeerCapabilities>,
    last_capability_projection: Option<PeerSessionCapabilityProjection>,
    last_watchdog_projection: Option<PeerSessionWatchdogProjection>,
    last_disconnect_projection: Option<PeerSessionDisconnectProjection>,
    last_blockers: Vec<PeerSessionBlocker>,
    capabilities_requests_sent: usize,
    capabilities_requests_received: usize,
    capabilities_answers_observed: usize,
    capabilities_protocol_errors_observed: usize,
    watchdog_requests_sent: usize,
    watchdog_requests_received: usize,
    watchdog_answers_observed: usize,
    missed_watchdogs: usize,
    disconnect_requests_sent: usize,
    disconnect_requests_received: usize,
    disconnect_answers_observed: usize,
    reconnects_scheduled: usize,
    backoffs_entered: usize,
}

impl fmt::Debug for PeerSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerSession")
            .field("state", &self.state)
            .field("policy", &self.policy)
            .field(
                "has_remote_capabilities",
                &self.remote_capabilities.is_some(),
            )
            .field(
                "capabilities_requests_sent",
                &self.capabilities_requests_sent,
            )
            .field(
                "capabilities_requests_received",
                &self.capabilities_requests_received,
            )
            .field(
                "capabilities_answers_observed",
                &self.capabilities_answers_observed,
            )
            .field("watchdog_requests_sent", &self.watchdog_requests_sent)
            .field("watchdog_answers_observed", &self.watchdog_answers_observed)
            .field("missed_watchdogs", &self.missed_watchdogs)
            .field("disconnect_requests_sent", &self.disconnect_requests_sent)
            .field(
                "disconnect_requests_received",
                &self.disconnect_requests_received,
            )
            .field("reconnects_scheduled", &self.reconnects_scheduled)
            .field("backoffs_entered", &self.backoffs_entered)
            .finish()
    }
}

impl PeerSession {
    /// Create a session that accepts any common Diameter application.
    #[must_use]
    pub fn new(local_capabilities: PeerCapabilities) -> Self {
        Self::with_policy(local_capabilities, PeerSessionPolicy::default())
    }

    /// Create a session with an explicit readiness policy.
    #[must_use]
    pub fn with_policy(local_capabilities: PeerCapabilities, policy: PeerSessionPolicy) -> Self {
        Self {
            local_capabilities,
            policy,
            state: PeerSessionState::Idle,
            remote_capabilities: None,
            last_capability_projection: None,
            last_watchdog_projection: None,
            last_disconnect_projection: None,
            last_blockers: Vec::new(),
            capabilities_requests_sent: 0,
            capabilities_requests_received: 0,
            capabilities_answers_observed: 0,
            capabilities_protocol_errors_observed: 0,
            watchdog_requests_sent: 0,
            watchdog_requests_received: 0,
            watchdog_answers_observed: 0,
            missed_watchdogs: 0,
            disconnect_requests_sent: 0,
            disconnect_requests_received: 0,
            disconnect_answers_observed: 0,
            reconnects_scheduled: 0,
            backoffs_entered: 0,
        }
    }

    /// Return the current state.
    #[must_use]
    pub const fn state(&self) -> PeerSessionState {
        self.state
    }

    /// Return the session readiness policy.
    #[must_use]
    pub const fn policy(&self) -> &PeerSessionPolicy {
        &self.policy
    }

    /// Return the last capability projection, if one exists.
    #[must_use]
    pub const fn last_capability_projection(&self) -> Option<&PeerSessionCapabilityProjection> {
        self.last_capability_projection.as_ref()
    }

    /// Return the last watchdog projection, if one exists.
    #[must_use]
    pub const fn last_watchdog_projection(&self) -> Option<&PeerSessionWatchdogProjection> {
        self.last_watchdog_projection.as_ref()
    }

    /// Return the last disconnect projection, if one exists.
    #[must_use]
    pub const fn last_disconnect_projection(&self) -> Option<&PeerSessionDisconnectProjection> {
        self.last_disconnect_projection.as_ref()
    }

    /// Project a CEA without mutating session state.
    #[must_use]
    pub fn project_capabilities_answer(
        &self,
        answer: &CapabilitiesExchangeAnswer,
    ) -> PeerSessionCapabilityProjection {
        self.project_capabilities(
            answer.result_code,
            &answer.capabilities,
            !answer.diagnostics.is_empty(),
        )
    }

    /// Project a protocol-error CEA without mutating session state.
    #[must_use]
    pub fn project_capabilities_protocol_error_answer(
        &self,
        answer: &CapabilitiesExchangeErrorAnswer,
    ) -> PeerSessionCapabilityProjection {
        let mut blockers = vec![
            PeerSessionBlocker::CapabilitiesProtocolError,
            PeerSessionBlocker::CapabilitiesResultNotSuccess,
            PeerSessionBlocker::NoCommonApplication,
        ];
        if !self.policy.accepted_application_ids.is_empty() {
            blockers.push(PeerSessionBlocker::AcceptedApplicationMissing);
        }
        if !self.policy.accepted_inband_security_ids.is_empty() {
            blockers.push(PeerSessionBlocker::AcceptedInbandSecurityMissing);
        }
        PeerSessionCapabilityProjection {
            result_code: answer.result_code,
            has_common_application: false,
            relay_application_common: false,
            accepted_application_common: false,
            accepted_inband_security_common: false,
            diagnostics_present: !answer.diagnostics.is_empty(),
            accepted: false,
            blockers,
        }
    }

    /// Mark a CER as sent.
    #[must_use]
    pub fn capabilities_request_sent(&mut self) -> PeerSessionTransition {
        let previous = self.state;
        self.capabilities_requests_sent = self.capabilities_requests_sent.saturating_add(1);
        self.state = PeerSessionState::CapabilitiesPending;
        self.remote_capabilities = None;
        self.last_capability_projection = None;
        self.last_watchdog_projection = None;
        self.last_disconnect_projection = None;
        self.last_blockers.clear();
        self.missed_watchdogs = 0;
        self.transition(PeerSessionEvent::CapabilitiesRequestSent, previous)
    }

    /// Observe a decoded CER from the peer.
    #[must_use]
    pub fn capabilities_request_received(
        &mut self,
        remote: PeerCapabilities,
    ) -> PeerSessionTransition {
        let previous = self.state;
        self.capabilities_requests_received = self.capabilities_requests_received.saturating_add(1);
        let negotiated = negotiate_capabilities(&self.local_capabilities, &remote);
        let result_code = negotiated.cea_result_code();
        let projection = self.project_capabilities(result_code, &remote, false);
        self.remote_capabilities = Some(remote);
        self.apply_capability_projection(projection);
        self.transition(PeerSessionEvent::CapabilitiesRequestReceived, previous)
    }

    /// Observe a decoded CEA from the peer.
    #[must_use]
    pub fn observe_capabilities_answer(
        &mut self,
        answer: &CapabilitiesExchangeAnswer,
    ) -> PeerSessionTransition {
        let previous = self.state;
        self.capabilities_answers_observed = self.capabilities_answers_observed.saturating_add(1);
        self.remote_capabilities = Some(answer.capabilities.clone());
        let projection = self.project_capabilities_answer(answer);
        let accepted = projection.accepted;
        self.apply_capability_projection(projection);
        self.transition(
            if accepted {
                PeerSessionEvent::CapabilitiesAnswerAccepted
            } else {
                PeerSessionEvent::CapabilitiesAnswerRejected
            },
            previous,
        )
    }

    /// Observe a decoded protocol-error CEA from the peer.
    #[must_use]
    pub fn observe_capabilities_protocol_error_answer(
        &mut self,
        answer: &CapabilitiesExchangeErrorAnswer,
    ) -> PeerSessionTransition {
        let previous = self.state;
        self.capabilities_protocol_errors_observed =
            self.capabilities_protocol_errors_observed.saturating_add(1);
        let projection = self.project_capabilities_protocol_error_answer(answer);
        self.apply_capability_projection(projection);
        self.transition(PeerSessionEvent::CapabilitiesProtocolError, previous)
    }

    /// Mark a DWR as sent.
    ///
    /// # Errors
    ///
    /// Returns [`PeerSessionError`] when capability negotiation has not
    /// completed or the session is draining, reconnecting, or failed.
    pub fn watchdog_request_sent(&mut self) -> Result<PeerSessionTransition, PeerSessionError> {
        if !matches!(
            self.state,
            PeerSessionState::Negotiated | PeerSessionState::Degraded
        ) {
            return Err(PeerSessionError::InvalidTransition {
                operation: "watchdog_request_sent",
                state: self.state,
            });
        }
        let previous = self.state;
        self.watchdog_requests_sent = self.watchdog_requests_sent.saturating_add(1);
        self.state = PeerSessionState::WatchdogProbing;
        self.last_blockers = vec![PeerSessionBlocker::WatchdogAnswerPending];
        self.last_watchdog_projection = Some(PeerSessionWatchdogProjection {
            result_code: None,
            origin_state_id: None,
            diagnostics_present: false,
            missed_watchdogs: self.missed_watchdogs,
            alive: false,
            blockers: self.last_blockers.clone(),
        });
        Ok(self.transition(PeerSessionEvent::WatchdogRequestSent, previous))
    }

    /// Observe a decoded DWR from the peer.
    #[must_use]
    pub fn observe_watchdog_request(
        &mut self,
        request: &DeviceWatchdogRequest,
    ) -> PeerSessionTransition {
        let previous = self.state;
        self.watchdog_requests_received = self.watchdog_requests_received.saturating_add(1);
        self.last_watchdog_projection = Some(PeerSessionWatchdogProjection {
            result_code: None,
            origin_state_id: request.origin_state_id,
            diagnostics_present: false,
            missed_watchdogs: self.missed_watchdogs,
            alive: !matches!(self.state, PeerSessionState::Failed),
            blockers: self.readiness_blockers(),
        });
        self.transition(PeerSessionEvent::WatchdogRequestReceived, previous)
    }

    /// Observe a decoded DWA from the peer.
    ///
    /// # Errors
    ///
    /// Returns [`PeerSessionError`] when no negotiated session or outstanding
    /// watchdog probe exists.
    pub fn observe_watchdog_answer(
        &mut self,
        answer: &DeviceWatchdogAnswer,
    ) -> Result<PeerSessionTransition, PeerSessionError> {
        if !matches!(
            self.state,
            PeerSessionState::WatchdogProbing
                | PeerSessionState::Degraded
                | PeerSessionState::Negotiated
        ) {
            return Err(PeerSessionError::InvalidTransition {
                operation: "observe_watchdog_answer",
                state: self.state,
            });
        }
        let previous = self.state;
        self.watchdog_answers_observed = self.watchdog_answers_observed.saturating_add(1);
        let mut blockers = Vec::new();
        if answer.result_code != RESULT_CODE_DIAMETER_SUCCESS {
            blockers.push(PeerSessionBlocker::WatchdogResultNotSuccess);
        }
        let alive = blockers.is_empty();
        self.missed_watchdogs = if alive { 0 } else { self.missed_watchdogs };
        self.state = if alive {
            PeerSessionState::Negotiated
        } else {
            PeerSessionState::Degraded
        };
        self.last_blockers = blockers.clone();
        self.last_watchdog_projection = Some(PeerSessionWatchdogProjection {
            result_code: Some(answer.result_code),
            origin_state_id: answer.origin_state_id,
            diagnostics_present: !answer.diagnostics.is_empty(),
            missed_watchdogs: self.missed_watchdogs,
            alive,
            blockers,
        });
        Ok(self.transition(
            if alive {
                PeerSessionEvent::WatchdogAnswerAccepted
            } else {
                PeerSessionEvent::WatchdogAnswerRejected
            },
            previous,
        ))
    }

    /// Record one missed watchdog answer.
    ///
    /// # Errors
    ///
    /// Returns [`PeerSessionError`] when no negotiated session or outstanding
    /// watchdog probe exists.
    pub fn watchdog_missed(&mut self) -> Result<PeerSessionTransition, PeerSessionError> {
        if !matches!(
            self.state,
            PeerSessionState::WatchdogProbing
                | PeerSessionState::Degraded
                | PeerSessionState::Negotiated
        ) {
            return Err(PeerSessionError::InvalidTransition {
                operation: "watchdog_missed",
                state: self.state,
            });
        }
        let previous = self.state;
        self.missed_watchdogs = self.missed_watchdogs.saturating_add(1);
        let threshold = self.policy.watchdog_miss_threshold.max(1);
        let threshold_exceeded = self.missed_watchdogs >= threshold;
        let blocker = if threshold_exceeded {
            PeerSessionBlocker::WatchdogMissThresholdExceeded
        } else {
            PeerSessionBlocker::WatchdogMissed
        };
        self.state = if threshold_exceeded {
            PeerSessionState::Failed
        } else {
            PeerSessionState::Degraded
        };
        self.last_blockers = vec![blocker];
        self.last_watchdog_projection = Some(PeerSessionWatchdogProjection {
            result_code: None,
            origin_state_id: None,
            diagnostics_present: false,
            missed_watchdogs: self.missed_watchdogs,
            alive: false,
            blockers: self.last_blockers.clone(),
        });
        Ok(self.transition(PeerSessionEvent::WatchdogMissed, previous))
    }

    /// Mark a local DPR as sent.
    #[must_use]
    pub fn disconnect_request_sent(&mut self, _cause: DisconnectCause) -> PeerSessionTransition {
        let previous = self.state;
        self.disconnect_requests_sent = self.disconnect_requests_sent.saturating_add(1);
        self.state = PeerSessionState::Disconnecting;
        self.last_blockers = vec![PeerSessionBlocker::DisconnectInProgress];
        self.last_disconnect_projection = Some(PeerSessionDisconnectProjection {
            result_code: None,
            peer_requested: false,
            acknowledged: false,
            reconnect_intent: false,
            blockers: self.last_blockers.clone(),
        });
        self.transition(PeerSessionEvent::DisconnectRequestSent, previous)
    }

    /// Observe a decoded DPR from the peer.
    #[must_use]
    pub fn observe_disconnect_request(
        &mut self,
        _request: &DisconnectPeerRequest,
    ) -> PeerSessionTransition {
        let previous = self.state;
        self.disconnect_requests_received = self.disconnect_requests_received.saturating_add(1);
        self.state = PeerSessionState::Draining;
        self.last_blockers = vec![
            PeerSessionBlocker::PeerRequestedDisconnect,
            PeerSessionBlocker::DisconnectInProgress,
        ];
        self.last_disconnect_projection = Some(PeerSessionDisconnectProjection {
            result_code: None,
            peer_requested: true,
            acknowledged: false,
            reconnect_intent: false,
            blockers: self.last_blockers.clone(),
        });
        self.transition(PeerSessionEvent::DisconnectRequestReceived, previous)
    }

    /// Mark a local DPA as sent in response to a peer DPR.
    #[must_use]
    pub fn disconnect_answer_sent(
        &mut self,
        answer: &DisconnectPeerAnswer,
    ) -> PeerSessionTransition {
        let previous = self.state;
        self.disconnect_answers_observed = self.disconnect_answers_observed.saturating_add(1);
        self.apply_disconnect_answer(answer, true);
        self.transition(PeerSessionEvent::DisconnectAnswerSent, previous)
    }

    /// Observe a decoded DPA from the peer.
    #[must_use]
    pub fn observe_disconnect_answer(
        &mut self,
        answer: &DisconnectPeerAnswer,
    ) -> PeerSessionTransition {
        let previous = self.state;
        self.disconnect_answers_observed = self.disconnect_answers_observed.saturating_add(1);
        self.apply_disconnect_answer(answer, false);
        self.transition(PeerSessionEvent::DisconnectAnswerReceived, previous)
    }

    /// Move to reconnecting state.
    #[must_use]
    pub fn schedule_reconnect(&mut self) -> PeerSessionTransition {
        let previous = self.state;
        self.reconnects_scheduled = self.reconnects_scheduled.saturating_add(1);
        self.state = PeerSessionState::Reconnecting;
        self.last_blockers.clear();
        self.transition(PeerSessionEvent::ReconnectScheduled, previous)
    }

    /// Move to reconnect backoff state.
    #[must_use]
    pub fn enter_backoff(&mut self) -> PeerSessionTransition {
        let previous = self.state;
        self.backoffs_entered = self.backoffs_entered.saturating_add(1);
        self.state = PeerSessionState::Backoff;
        self.last_blockers = vec![PeerSessionBlocker::ReconnectBackoff];
        self.transition(PeerSessionEvent::BackoffEntered, previous)
    }

    /// Mark reconnect backoff elapsed.
    #[must_use]
    pub fn backoff_elapsed(&mut self) -> PeerSessionTransition {
        let previous = self.state;
        self.reconnects_scheduled = self.reconnects_scheduled.saturating_add(1);
        self.state = PeerSessionState::Reconnecting;
        self.last_blockers.clear();
        self.transition(PeerSessionEvent::BackoffElapsed, previous)
    }

    /// Fail the session closed with a stable blocker.
    #[must_use]
    pub fn fail(&mut self, blocker: PeerSessionBlocker) -> PeerSessionTransition {
        let previous = self.state;
        self.state = PeerSessionState::Failed;
        self.last_blockers = vec![blocker];
        self.transition(PeerSessionEvent::Failure, previous)
    }

    /// Return the current redaction-safe readiness projection.
    #[must_use]
    pub fn readiness(&self) -> PeerSessionReadiness {
        let blockers = self.readiness_blockers();
        PeerSessionReadiness {
            state: self.state,
            negotiated: self.state == PeerSessionState::Negotiated,
            probing: self.state == PeerSessionState::WatchdogProbing,
            degraded: self.state == PeerSessionState::Degraded,
            failed: self.state == PeerSessionState::Failed,
            draining: matches!(
                self.state,
                PeerSessionState::Draining | PeerSessionState::Disconnecting
            ),
            reconnecting: matches!(
                self.state,
                PeerSessionState::Reconnecting | PeerSessionState::Backoff
            ),
            traffic_ready: self.state == PeerSessionState::Negotiated,
            blockers,
        }
    }

    /// Return a redaction-safe snapshot.
    #[must_use]
    pub fn snapshot(&self) -> PeerSessionSnapshot {
        PeerSessionSnapshot {
            state: self.state,
            readiness: self.readiness(),
            capabilities_requests_sent: self.capabilities_requests_sent,
            capabilities_requests_received: self.capabilities_requests_received,
            capabilities_answers_observed: self.capabilities_answers_observed,
            capabilities_protocol_errors_observed: self.capabilities_protocol_errors_observed,
            watchdog_requests_sent: self.watchdog_requests_sent,
            watchdog_requests_received: self.watchdog_requests_received,
            watchdog_answers_observed: self.watchdog_answers_observed,
            missed_watchdogs: self.missed_watchdogs,
            disconnect_requests_sent: self.disconnect_requests_sent,
            disconnect_requests_received: self.disconnect_requests_received,
            disconnect_answers_observed: self.disconnect_answers_observed,
            reconnects_scheduled: self.reconnects_scheduled,
            backoffs_entered: self.backoffs_entered,
        }
    }

    fn project_capabilities(
        &self,
        result_code: u32,
        remote: &PeerCapabilities,
        diagnostics_present: bool,
    ) -> PeerSessionCapabilityProjection {
        let negotiated = negotiate_capabilities(&self.local_capabilities, remote);
        let common_non_relay_application = !negotiated.application_ids.is_empty();
        let has_common_application = common_non_relay_application
            || (self.policy.allow_relay_application && negotiated.relay_application);
        let accepted_application_common = self.policy.accepted_application_ids.is_empty()
            || self
                .policy
                .accepted_application_ids
                .iter()
                .any(|application_id| negotiated.application_ids.contains(application_id));
        let accepted_inband_security_common = self.policy.accepted_inband_security_ids.is_empty()
            || self
                .policy
                .accepted_inband_security_ids
                .iter()
                .any(|security_id| negotiated.inband_security_ids.contains(security_id));
        let mut blockers = Vec::new();
        if result_code != RESULT_CODE_DIAMETER_SUCCESS {
            blockers.push(PeerSessionBlocker::CapabilitiesResultNotSuccess);
        }
        if !has_common_application {
            blockers.push(PeerSessionBlocker::NoCommonApplication);
        }
        if !accepted_application_common {
            blockers.push(PeerSessionBlocker::AcceptedApplicationMissing);
        }
        if !accepted_inband_security_common {
            blockers.push(PeerSessionBlocker::AcceptedInbandSecurityMissing);
        }
        PeerSessionCapabilityProjection {
            result_code,
            has_common_application,
            relay_application_common: negotiated.relay_application,
            accepted_application_common,
            accepted_inband_security_common,
            diagnostics_present,
            accepted: blockers.is_empty(),
            blockers,
        }
    }

    fn apply_capability_projection(&mut self, projection: PeerSessionCapabilityProjection) {
        self.missed_watchdogs = 0;
        self.last_watchdog_projection = None;
        self.last_disconnect_projection = None;
        self.last_blockers = projection.blockers.clone();
        self.state = if projection.accepted {
            PeerSessionState::Negotiated
        } else {
            PeerSessionState::Failed
        };
        self.last_capability_projection = Some(projection);
    }

    fn apply_disconnect_answer(&mut self, answer: &DisconnectPeerAnswer, peer_requested: bool) {
        let mut blockers = Vec::new();
        if answer.result_code != RESULT_CODE_DIAMETER_SUCCESS {
            blockers.push(PeerSessionBlocker::DisconnectResultNotSuccess);
        }
        let acknowledged = blockers.is_empty();
        self.state = if acknowledged {
            PeerSessionState::Reconnecting
        } else {
            PeerSessionState::Failed
        };
        self.last_blockers = blockers.clone();
        self.last_disconnect_projection = Some(PeerSessionDisconnectProjection {
            result_code: Some(answer.result_code),
            peer_requested,
            acknowledged,
            reconnect_intent: acknowledged,
            blockers,
        });
    }

    fn transition(
        &self,
        event: PeerSessionEvent,
        previous_state: PeerSessionState,
    ) -> PeerSessionTransition {
        PeerSessionTransition {
            event,
            previous_state,
            state: self.state,
            readiness: self.readiness(),
        }
    }

    fn readiness_blockers(&self) -> Vec<PeerSessionBlocker> {
        match self.state {
            PeerSessionState::Idle | PeerSessionState::CapabilitiesPending => {
                vec![PeerSessionBlocker::CapabilitiesExchangePending]
            }
            PeerSessionState::Negotiated => Vec::new(),
            PeerSessionState::WatchdogProbing => vec![PeerSessionBlocker::WatchdogAnswerPending],
            PeerSessionState::Degraded | PeerSessionState::Failed => {
                if self.last_blockers.is_empty() {
                    vec![PeerSessionBlocker::SessionFailed]
                } else {
                    self.last_blockers.clone()
                }
            }
            PeerSessionState::Draining | PeerSessionState::Disconnecting => {
                vec![PeerSessionBlocker::DisconnectInProgress]
            }
            PeerSessionState::Reconnecting => Vec::new(),
            PeerSessionState::Backoff => vec![PeerSessionBlocker::ReconnectBackoff],
        }
    }
}

/// Intersect two Diameter peer capability sets without making transport policy decisions.
pub fn negotiate_capabilities(
    local: &PeerCapabilities,
    remote: &PeerCapabilities,
) -> CapabilityNegotiation {
    let local_application_ids = advertised_non_relay_application_ids(local);
    let remote_application_ids = advertised_non_relay_application_ids(remote);
    CapabilityNegotiation {
        application_ids: common_copy(&local_application_ids, &remote_application_ids),
        relay_application: advertises_relay_application(local)
            || advertises_relay_application(remote),
        supported_vendor_ids: common_copy(
            &local.supported_vendor_ids,
            &remote.supported_vendor_ids,
        ),
        auth_application_ids: common_copy(
            &local.auth_application_ids,
            &remote.auth_application_ids,
        ),
        acct_application_ids: common_copy(
            &local.acct_application_ids,
            &remote.acct_application_ids,
        ),
        vendor_specific_applications: common_vendor_specific_applications(
            &local.vendor_specific_applications,
            &remote.vendor_specific_applications,
        ),
        inband_security_ids: common_copy(&local.inband_security_ids, &remote.inband_security_ids),
    }
}

/// Return whether two capability sets share at least one Diameter application.
pub fn has_common_application(local: &PeerCapabilities, remote: &PeerCapabilities) -> bool {
    negotiate_capabilities(local, remote).has_common_application()
}

/// Return the CEA Result-Code implied by two peer capability sets.
pub fn cea_result_code(local: &PeerCapabilities, remote: &PeerCapabilities) -> u32 {
    negotiate_capabilities(local, remote).cea_result_code()
}

/// Return whether a Result-Code requires the Diameter E bit on an answer.
///
/// This reflects RFC 6733 section 7.2, which links the E bit to answers carrying
/// a protocol-error Result-Code in the 3xxx range. It does not return true for
/// permanent-failure (5xxx) or transient-failure (4xxx) result codes. In
/// particular, a Capabilities-Exchange-Answer with
/// `DIAMETER_NO_COMMON_APPLICATION` (5010) will not have the E bit set by this
/// helper, because 5010 is not a protocol error even though the capability
/// exchange failed.
pub const fn result_code_requires_error_bit(result_code: u32) -> bool {
    result_code >= 3000 && result_code < 4000
}

/// Build a Capabilities-Exchange-Request message.
pub fn build_capabilities_exchange_request(
    capabilities: &PeerCapabilities,
    hop_by_hop_identifier: u32,
    end_to_end_identifier: u32,
    ctx: EncodeContext,
) -> Result<OwnedMessage, EncodeError> {
    let section = PeerProcedure::CapabilitiesExchange.spec_section(CommandKind::Request);
    capabilities.validate_for_encode(section)?;
    let mut raw_avps = BytesMut::new();
    append_capability_avps(&mut raw_avps, capabilities, ctx, section)?;
    build_message(
        peer_request_flags(PeerProcedure::CapabilitiesExchange),
        COMMAND_CAPABILITIES_EXCHANGE,
        raw_avps,
        hop_by_hop_identifier,
        end_to_end_identifier,
        ctx,
        section,
    )
}

/// Parse a Capabilities-Exchange-Request message.
pub fn parse_capabilities_exchange_request(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<PeerCapabilities, DecodeError> {
    let section = PeerProcedure::CapabilitiesExchange.spec_section(CommandKind::Request);
    ensure_peer_header(
        message,
        PeerProcedure::CapabilitiesExchange,
        CommandKind::Request,
    )?;
    collect_procedure_avps(message.raw_avps, ctx, section)?.into_capabilities(section)
}

/// Build a Capabilities-Exchange-Answer message.
pub fn build_capabilities_exchange_answer(
    answer: &CapabilitiesExchangeAnswer,
    hop_by_hop_identifier: u32,
    end_to_end_identifier: u32,
    ctx: EncodeContext,
) -> Result<OwnedMessage, EncodeError> {
    let section = PeerProcedure::CapabilitiesExchange.spec_section(CommandKind::Answer);
    answer.capabilities.validate_for_encode(section)?;
    let mut raw_avps = BytesMut::new();
    append_u32_avp(
        &mut raw_avps,
        AVP_RESULT_CODE,
        answer.result_code,
        true,
        ctx,
    )?;
    append_capability_avps(&mut raw_avps, &answer.capabilities, ctx, section)?;
    append_answer_diagnostics(&mut raw_avps, &answer.diagnostics, ctx)?;
    build_message(
        peer_answer_flags(
            PeerProcedure::CapabilitiesExchange,
            result_code_requires_error_bit(answer.result_code),
        ),
        COMMAND_CAPABILITIES_EXCHANGE,
        raw_avps,
        hop_by_hop_identifier,
        end_to_end_identifier,
        ctx,
        section,
    )
}

/// Parse a Capabilities-Exchange-Answer message.
pub fn parse_capabilities_exchange_answer(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<CapabilitiesExchangeAnswer, DecodeError> {
    let section = PeerProcedure::CapabilitiesExchange.spec_section(CommandKind::Answer);
    ensure_peer_header(
        message,
        PeerProcedure::CapabilitiesExchange,
        CommandKind::Answer,
    )?;
    let avps = collect_procedure_avps(message.raw_avps, ctx, section)?;
    let result_code = require_field(
        avps.result_code.clone(),
        "diameter CEA requires Result-Code",
        section,
    )?;
    let diagnostics = avps.diagnostics();
    Ok(CapabilitiesExchangeAnswer {
        result_code,
        capabilities: avps.into_capabilities(section)?,
        diagnostics,
    })
}

/// Build a minimal Capabilities-Exchange-Answer protocol-error message.
pub fn build_capabilities_exchange_error_answer(
    answer: &CapabilitiesExchangeErrorAnswer,
    hop_by_hop_identifier: u32,
    end_to_end_identifier: u32,
    ctx: EncodeContext,
) -> Result<OwnedMessage, EncodeError> {
    let section = PeerProcedure::CapabilitiesExchange.spec_section(CommandKind::Answer);
    if !result_code_requires_error_bit(answer.result_code) {
        return Err(encode_structural_error(
            "diameter CEA error answer Result-Code must be a protocol-error value",
            "7.2",
        ));
    }
    answer.identity.validate_for_encode(section)?;
    let mut raw_avps = BytesMut::new();
    append_u32_avp(
        &mut raw_avps,
        AVP_RESULT_CODE,
        answer.result_code,
        true,
        ctx,
    )?;
    append_identity_avps(&mut raw_avps, &answer.identity, ctx)?;
    append_answer_diagnostics(&mut raw_avps, &answer.diagnostics, ctx)?;
    build_message(
        peer_answer_flags(PeerProcedure::CapabilitiesExchange, true),
        COMMAND_CAPABILITIES_EXCHANGE,
        raw_avps,
        hop_by_hop_identifier,
        end_to_end_identifier,
        ctx,
        section,
    )
}

/// Parse a minimal Capabilities-Exchange-Answer protocol-error message.
pub fn parse_capabilities_exchange_error_answer(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<CapabilitiesExchangeErrorAnswer, DecodeError> {
    let section = PeerProcedure::CapabilitiesExchange.spec_section(CommandKind::Answer);
    ensure_peer_header(
        message,
        PeerProcedure::CapabilitiesExchange,
        CommandKind::Answer,
    )?;
    if !message.header.flags.is_error() {
        return Err(decode_structural_error(
            "diameter CEA error answer requires the error flag",
            4,
            "7.2",
        ));
    }
    let avps = collect_procedure_avps(message.raw_avps, ctx, section)?;
    let result_code = require_field(
        avps.result_code.clone(),
        "diameter CEA error answer requires Result-Code",
        section,
    )?;
    if !result_code_requires_error_bit(result_code) {
        return Err(decode_structural_error(
            "diameter CEA error answer Result-Code must be a protocol-error value",
            DIAMETER_HEADER_LEN,
            "7.2",
        ));
    }
    Ok(CapabilitiesExchangeErrorAnswer {
        result_code,
        identity: avps.identity(section)?,
        diagnostics: avps.diagnostics(),
    })
}

/// Build a Device-Watchdog-Request message.
pub fn build_device_watchdog_request(
    request: &DeviceWatchdogRequest,
    hop_by_hop_identifier: u32,
    end_to_end_identifier: u32,
    ctx: EncodeContext,
) -> Result<OwnedMessage, EncodeError> {
    let section = PeerProcedure::DeviceWatchdog.spec_section(CommandKind::Request);
    request.identity.validate_for_encode(section)?;
    let mut raw_avps = BytesMut::new();
    append_identity_avps(&mut raw_avps, &request.identity, ctx)?;
    append_origin_state_id_avp(&mut raw_avps, request.origin_state_id, ctx)?;
    build_message(
        peer_request_flags(PeerProcedure::DeviceWatchdog),
        COMMAND_DEVICE_WATCHDOG,
        raw_avps,
        hop_by_hop_identifier,
        end_to_end_identifier,
        ctx,
        section,
    )
}

/// Parse a Device-Watchdog-Request message.
pub fn parse_device_watchdog_request(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<DeviceWatchdogRequest, DecodeError> {
    let section = PeerProcedure::DeviceWatchdog.spec_section(CommandKind::Request);
    ensure_peer_header(message, PeerProcedure::DeviceWatchdog, CommandKind::Request)?;
    let avps = collect_procedure_avps(message.raw_avps, ctx, section)?;
    Ok(DeviceWatchdogRequest {
        identity: avps.identity(section)?,
        origin_state_id: avps.origin_state_id(),
    })
}

/// Build a Device-Watchdog-Answer message.
pub fn build_device_watchdog_answer(
    answer: &DeviceWatchdogAnswer,
    hop_by_hop_identifier: u32,
    end_to_end_identifier: u32,
    ctx: EncodeContext,
) -> Result<OwnedMessage, EncodeError> {
    let section = PeerProcedure::DeviceWatchdog.spec_section(CommandKind::Answer);
    answer.identity.validate_for_encode(section)?;
    let mut raw_avps = BytesMut::new();
    append_u32_avp(
        &mut raw_avps,
        AVP_RESULT_CODE,
        answer.result_code,
        true,
        ctx,
    )?;
    append_identity_avps(&mut raw_avps, &answer.identity, ctx)?;
    append_origin_state_id_avp(&mut raw_avps, answer.origin_state_id, ctx)?;
    append_answer_diagnostics(&mut raw_avps, &answer.diagnostics, ctx)?;
    build_message(
        peer_answer_flags(
            PeerProcedure::DeviceWatchdog,
            result_code_requires_error_bit(answer.result_code),
        ),
        COMMAND_DEVICE_WATCHDOG,
        raw_avps,
        hop_by_hop_identifier,
        end_to_end_identifier,
        ctx,
        section,
    )
}

/// Parse a Device-Watchdog-Answer message.
pub fn parse_device_watchdog_answer(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<DeviceWatchdogAnswer, DecodeError> {
    let section = PeerProcedure::DeviceWatchdog.spec_section(CommandKind::Answer);
    ensure_peer_header(message, PeerProcedure::DeviceWatchdog, CommandKind::Answer)?;
    let avps = collect_procedure_avps(message.raw_avps, ctx, section)?;
    let result_code = require_field(
        avps.result_code.clone(),
        "diameter DWA requires Result-Code",
        section,
    )?;
    Ok(DeviceWatchdogAnswer {
        result_code,
        identity: avps.identity(section)?,
        origin_state_id: avps.origin_state_id(),
        diagnostics: avps.diagnostics(),
    })
}

/// Build a Disconnect-Peer-Request message.
pub fn build_disconnect_peer_request(
    request: &DisconnectPeerRequest,
    hop_by_hop_identifier: u32,
    end_to_end_identifier: u32,
    ctx: EncodeContext,
) -> Result<OwnedMessage, EncodeError> {
    let section = PeerProcedure::DisconnectPeer.spec_section(CommandKind::Request);
    request.identity.validate_for_encode(section)?;
    let mut raw_avps = BytesMut::new();
    append_identity_avps(&mut raw_avps, &request.identity, ctx)?;
    append_origin_state_id_avp(&mut raw_avps, request.origin_state_id, ctx)?;
    append_u32_avp(
        &mut raw_avps,
        AVP_DISCONNECT_CAUSE,
        request.disconnect_cause.value(),
        true,
        ctx,
    )?;
    build_message(
        peer_request_flags(PeerProcedure::DisconnectPeer),
        COMMAND_DISCONNECT_PEER,
        raw_avps,
        hop_by_hop_identifier,
        end_to_end_identifier,
        ctx,
        section,
    )
}

/// Parse a Disconnect-Peer-Request message.
pub fn parse_disconnect_peer_request(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<DisconnectPeerRequest, DecodeError> {
    let section = PeerProcedure::DisconnectPeer.spec_section(CommandKind::Request);
    ensure_peer_header(message, PeerProcedure::DisconnectPeer, CommandKind::Request)?;
    let avps = collect_procedure_avps(message.raw_avps, ctx, section)?;
    let disconnect_cause = require_field(
        avps.disconnect_cause.clone(),
        "diameter DPR requires Disconnect-Cause",
        section,
    )?;
    Ok(DisconnectPeerRequest {
        identity: avps.identity(section)?,
        disconnect_cause,
        origin_state_id: avps.origin_state_id(),
    })
}

/// Build a Disconnect-Peer-Answer message.
pub fn build_disconnect_peer_answer(
    answer: &DisconnectPeerAnswer,
    hop_by_hop_identifier: u32,
    end_to_end_identifier: u32,
    ctx: EncodeContext,
) -> Result<OwnedMessage, EncodeError> {
    let section = PeerProcedure::DisconnectPeer.spec_section(CommandKind::Answer);
    answer.identity.validate_for_encode(section)?;
    let mut raw_avps = BytesMut::new();
    append_u32_avp(
        &mut raw_avps,
        AVP_RESULT_CODE,
        answer.result_code,
        true,
        ctx,
    )?;
    append_identity_avps(&mut raw_avps, &answer.identity, ctx)?;
    append_origin_state_id_avp(&mut raw_avps, answer.origin_state_id, ctx)?;
    append_answer_diagnostics(&mut raw_avps, &answer.diagnostics, ctx)?;
    build_message(
        peer_answer_flags(
            PeerProcedure::DisconnectPeer,
            result_code_requires_error_bit(answer.result_code),
        ),
        COMMAND_DISCONNECT_PEER,
        raw_avps,
        hop_by_hop_identifier,
        end_to_end_identifier,
        ctx,
        section,
    )
}

/// Parse a Disconnect-Peer-Answer message.
pub fn parse_disconnect_peer_answer(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<DisconnectPeerAnswer, DecodeError> {
    let section = PeerProcedure::DisconnectPeer.spec_section(CommandKind::Answer);
    ensure_peer_header(message, PeerProcedure::DisconnectPeer, CommandKind::Answer)?;
    let avps = collect_procedure_avps(message.raw_avps, ctx, section)?;
    let result_code = require_field(
        avps.result_code.clone(),
        "diameter DPA requires Result-Code",
        section,
    )?;
    Ok(DisconnectPeerAnswer {
        result_code,
        identity: avps.identity(section)?,
        origin_state_id: avps.origin_state_id(),
        diagnostics: avps.diagnostics(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FieldValue<T> {
    value: T,
    offset: usize,
}

impl<T> FieldValue<T> {
    fn new(value: T, offset: usize) -> Self {
        Self { value, offset }
    }
}

#[derive(Debug, Default)]
struct ProcedureAvps {
    origin_host: Option<FieldValue<String>>,
    origin_realm: Option<FieldValue<String>>,
    result_code: Option<FieldValue<u32>>,
    disconnect_cause: Option<FieldValue<DisconnectCause>>,
    error_message: Option<FieldValue<String>>,
    failed_avps: Vec<Bytes>,
    host_ip_addresses: Vec<HostIpAddress>,
    vendor_id: Option<FieldValue<VendorId>>,
    product_name: Option<FieldValue<String>>,
    origin_state_id: Option<FieldValue<u32>>,
    firmware_revision: Option<FieldValue<u32>>,
    supported_vendor_ids: Vec<VendorId>,
    auth_application_ids: Vec<ApplicationId>,
    acct_application_ids: Vec<ApplicationId>,
    vendor_specific_applications: Vec<VendorSpecificApplication>,
    inband_security_ids: Vec<u32>,
}

impl ProcedureAvps {
    fn identity(&self, section: &'static str) -> Result<PeerIdentity, DecodeError> {
        Ok(PeerIdentity {
            origin_host: require_field_ref(
                &self.origin_host,
                "diameter peer procedure requires Origin-Host",
                section,
            )?
            .clone(),
            origin_realm: require_field_ref(
                &self.origin_realm,
                "diameter peer procedure requires Origin-Realm",
                section,
            )?
            .clone(),
        })
    }

    fn origin_state_id(&self) -> Option<u32> {
        self.origin_state_id.as_ref().map(|field| field.value)
    }

    fn diagnostics(&self) -> AnswerDiagnostics {
        AnswerDiagnostics {
            error_message: self.error_message.as_ref().map(|field| field.value.clone()),
            failed_avps: self.failed_avps.clone(),
        }
    }

    fn into_capabilities(self, section: &'static str) -> Result<PeerCapabilities, DecodeError> {
        if self.host_ip_addresses.is_empty() {
            return Err(decode_structural_error(
                "diameter capabilities exchange requires Host-IP-Address",
                DIAMETER_HEADER_LEN,
                section,
            ));
        }
        Ok(PeerCapabilities {
            identity: PeerIdentity {
                origin_host: require_field(
                    self.origin_host,
                    "diameter capabilities exchange requires Origin-Host",
                    section,
                )?,
                origin_realm: require_field(
                    self.origin_realm,
                    "diameter capabilities exchange requires Origin-Realm",
                    section,
                )?,
            },
            host_ip_addresses: self.host_ip_addresses,
            vendor_id: require_field(
                self.vendor_id,
                "diameter capabilities exchange requires Vendor-Id",
                section,
            )?,
            product_name: require_field(
                self.product_name,
                "diameter capabilities exchange requires Product-Name",
                section,
            )?,
            origin_state_id: self.origin_state_id.map(|field| field.value),
            firmware_revision: self.firmware_revision.map(|field| field.value),
            supported_vendor_ids: self.supported_vendor_ids,
            auth_application_ids: self.auth_application_ids,
            acct_application_ids: self.acct_application_ids,
            vendor_specific_applications: self.vendor_specific_applications,
            inband_security_ids: self.inband_security_ids,
        })
    }
}

fn append_capability_avps(
    dst: &mut BytesMut,
    capabilities: &PeerCapabilities,
    ctx: EncodeContext,
    section: &'static str,
) -> Result<(), EncodeError> {
    append_identity_avps(dst, &capabilities.identity, ctx)?;
    for address in &capabilities.host_ip_addresses {
        append_address_avp(dst, *address, ctx)?;
    }
    append_u32_avp(dst, AVP_VENDOR_ID, capabilities.vendor_id.get(), true, ctx)?;
    append_utf8_avp(
        dst,
        AVP_PRODUCT_NAME,
        &capabilities.product_name,
        false,
        ctx,
    )?;
    if let Some(origin_state_id) = capabilities.origin_state_id {
        append_u32_avp(dst, AVP_ORIGIN_STATE_ID, origin_state_id, true, ctx)?;
    }
    for vendor_id in &capabilities.supported_vendor_ids {
        append_u32_avp(dst, AVP_SUPPORTED_VENDOR_ID, vendor_id.get(), true, ctx)?;
    }
    for application_id in &capabilities.auth_application_ids {
        append_u32_avp(
            dst,
            AVP_AUTH_APPLICATION_ID,
            application_id.get(),
            true,
            ctx,
        )?;
    }
    for security_id in &capabilities.inband_security_ids {
        append_u32_avp(dst, AVP_INBAND_SECURITY_ID, *security_id, true, ctx)?;
    }
    for application_id in &capabilities.acct_application_ids {
        append_u32_avp(
            dst,
            AVP_ACCT_APPLICATION_ID,
            application_id.get(),
            true,
            ctx,
        )?;
    }
    for application in &capabilities.vendor_specific_applications {
        append_vendor_specific_application_avp(dst, application, ctx, section)?;
    }
    if let Some(firmware_revision) = capabilities.firmware_revision {
        append_u32_avp(dst, AVP_FIRMWARE_REVISION, firmware_revision, false, ctx)?;
    }
    Ok(())
}

fn append_identity_avps(
    dst: &mut BytesMut,
    identity: &PeerIdentity,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    append_utf8_avp(dst, AVP_ORIGIN_HOST, &identity.origin_host, true, ctx)?;
    append_utf8_avp(dst, AVP_ORIGIN_REALM, &identity.origin_realm, true, ctx)
}

fn append_origin_state_id_avp(
    dst: &mut BytesMut,
    origin_state_id: Option<u32>,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    if let Some(origin_state_id) = origin_state_id {
        append_u32_avp(dst, AVP_ORIGIN_STATE_ID, origin_state_id, true, ctx)?;
    }
    Ok(())
}

fn append_answer_diagnostics(
    dst: &mut BytesMut,
    diagnostics: &AnswerDiagnostics,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    if let Some(error_message) = diagnostics.error_message.as_ref() {
        append_utf8_avp(dst, AVP_ERROR_MESSAGE, error_message, false, ctx)?;
    }
    for failed_avp in &diagnostics.failed_avps {
        append_avp(dst, AvpHeader::ietf(AVP_FAILED_AVP, true), failed_avp, ctx)?;
    }
    Ok(())
}

fn append_vendor_specific_application_avp(
    dst: &mut BytesMut,
    application: &VendorSpecificApplication,
    ctx: EncodeContext,
    section: &'static str,
) -> Result<(), EncodeError> {
    application.validate_for_encode(section)?;
    let mut value = BytesMut::new();
    for vendor_id in &application.vendor_ids {
        append_u32_avp(&mut value, AVP_VENDOR_ID, vendor_id.get(), true, ctx)?;
    }
    if let Some(application_id) = application.auth_application_id {
        append_u32_avp(
            &mut value,
            AVP_AUTH_APPLICATION_ID,
            application_id.get(),
            true,
            ctx,
        )?;
    }
    if let Some(application_id) = application.acct_application_id {
        append_u32_avp(
            &mut value,
            AVP_ACCT_APPLICATION_ID,
            application_id.get(),
            true,
            ctx,
        )?;
    }
    append_avp(
        dst,
        AvpHeader::ietf(AVP_VENDOR_SPECIFIC_APPLICATION_ID, true),
        &value,
        ctx,
    )
}

fn append_utf8_avp(
    dst: &mut BytesMut,
    code: AvpCode,
    value: &str,
    mandatory: bool,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    append_avp(dst, AvpHeader::ietf(code, mandatory), value.as_bytes(), ctx)
}

fn append_u32_avp(
    dst: &mut BytesMut,
    code: AvpCode,
    value: u32,
    mandatory: bool,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    append_avp(
        dst,
        AvpHeader::ietf(code, mandatory),
        &value.to_be_bytes(),
        ctx,
    )
}

fn append_address_avp(
    dst: &mut BytesMut,
    value: HostIpAddress,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    let mut encoded_value = BytesMut::new();
    value.append_value(&mut encoded_value);
    append_avp(
        dst,
        AvpHeader::ietf(AVP_HOST_IP_ADDRESS, true),
        &encoded_value,
        ctx,
    )
}

fn append_avp(
    dst: &mut BytesMut,
    header: AvpHeader,
    value: &[u8],
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    let avp = RawAvp {
        header,
        value,
        padding: &[],
    };
    let canonical_ctx = EncodeContext {
        raw_preserving: false,
        ..ctx
    };
    avp.encode(dst, canonical_ctx)
}

fn build_message(
    flags: CommandFlags,
    command_code: CommandCode,
    raw_avps: BytesMut,
    hop_by_hop_identifier: u32,
    end_to_end_identifier: u32,
    ctx: EncodeContext,
    section: &'static str,
) -> Result<OwnedMessage, EncodeError> {
    let length = DIAMETER_HEADER_LEN
        .checked_add(raw_avps.len())
        .ok_or_else(EncodeError::length_overflow)?;
    if length > MAX_U24 as usize {
        return Err(EncodeError::length_overflow().with_spec_ref(peer_spec(section)));
    }
    ctx.check_capacity(length)?;
    let length = u32::try_from(length).map_err(|_| EncodeError::length_overflow())?;
    Ok(OwnedMessage {
        header: Header::new(
            flags,
            command_code,
            base::APPLICATION_ID_COMMON_MESSAGES,
            hop_by_hop_identifier,
            end_to_end_identifier,
        )
        .with_length(length),
        raw_avps: raw_avps.freeze(),
    })
}

fn ensure_peer_header(
    message: &Message<'_>,
    procedure: PeerProcedure,
    kind: CommandKind,
) -> Result<(), DecodeError> {
    let section = procedure.spec_section(kind);
    if message.header.command_code != procedure.command_code() {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidEnumValue {
                field: "Diameter peer command code",
                value: u64::from(message.header.command_code.get()),
            },
            5,
        )
        .with_spec_ref(peer_spec(section)));
    }
    if message.header.flags.command_kind() != kind {
        return Err(decode_structural_error(
            "diameter peer procedure request/answer flag does not match parser",
            4,
            section,
        ));
    }
    if message.header.flags.is_proxiable() {
        return Err(decode_structural_error(
            "diameter base peer procedures must not set the proxiable flag",
            4,
            section,
        ));
    }
    if kind == CommandKind::Request && message.header.flags.is_error() {
        return Err(decode_structural_error(
            "diameter peer requests must not set the error flag",
            4,
            section,
        ));
    }
    if message.header.application_id != base::APPLICATION_ID_COMMON_MESSAGES {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidEnumValue {
                field: "Diameter peer Application-Id",
                value: u64::from(message.header.application_id.get()),
            },
            8,
        )
        .with_spec_ref(peer_spec(section)));
    }
    Ok(())
}

fn collect_procedure_avps(
    raw_avps: &[u8],
    ctx: DecodeContext,
    section: &'static str,
) -> Result<ProcedureAvps, DecodeError> {
    let mut parsed = ProcedureAvps::default();
    for_each_avp(raw_avps, ctx, DIAMETER_HEADER_LEN, 0, |offset, avp| {
        let value_offset = offset_add(offset, avp.header.header_len(), section)?;
        validate_peer_avp_flags(&avp.header, offset)?;
        if avp.header.vendor_id.is_some() {
            return handle_unknown_avp(ctx, &avp, offset, section);
        }
        let code = avp.header.code;
        if code == AVP_ORIGIN_HOST {
            let value = parse_string_value(avp.value, value_offset, "6.3")?;
            set_once(&mut parsed.origin_host, value, offset, section)
        } else if code == AVP_ORIGIN_REALM {
            let value = parse_string_value(avp.value, value_offset, "6.4")?;
            set_once(&mut parsed.origin_realm, value, offset, section)
        } else if code == AVP_RESULT_CODE {
            let value = parse_u32_value(avp.value, value_offset, "7.1")?;
            set_once(&mut parsed.result_code, value, offset, section)
        } else if code == AVP_DISCONNECT_CAUSE {
            let value = parse_u32_value(avp.value, value_offset, "5.4.3")?;
            let cause = DisconnectCause::decode(value, value_offset)?;
            set_once(&mut parsed.disconnect_cause, cause, offset, section)
        } else if code == AVP_ERROR_MESSAGE {
            let value = parse_utf8_value(avp.value, value_offset, "7.3")?;
            set_once(&mut parsed.error_message, value, offset, section)
        } else if code == AVP_FAILED_AVP {
            parsed.failed_avps.push(Bytes::copy_from_slice(avp.value));
            Ok(())
        } else if code == AVP_HOST_IP_ADDRESS {
            parsed
                .host_ip_addresses
                .push(HostIpAddress::decode_value(avp.value, value_offset)?);
            Ok(())
        } else if code == AVP_VENDOR_ID {
            let value = VendorId::new(parse_u32_value(avp.value, value_offset, "5.3.3")?);
            set_once(&mut parsed.vendor_id, value, offset, section)
        } else if code == AVP_PRODUCT_NAME {
            let value = parse_string_value(avp.value, value_offset, "5.3.7")?;
            set_once(&mut parsed.product_name, value, offset, section)
        } else if code == AVP_ORIGIN_STATE_ID {
            let value = parse_u32_value(avp.value, value_offset, "8.16")?;
            set_once(&mut parsed.origin_state_id, value, offset, section)
        } else if code == AVP_FIRMWARE_REVISION {
            let value = parse_u32_value(avp.value, value_offset, "5.3.4")?;
            set_once(&mut parsed.firmware_revision, value, offset, section)
        } else if code == AVP_SUPPORTED_VENDOR_ID {
            let value = parse_u32_value(avp.value, value_offset, "5.3.6")?;
            if value == 0 {
                return Err(decode_structural_error(
                    "diameter Supported-Vendor-Id must not be zero",
                    value_offset,
                    "5.3.6",
                ));
            }
            parsed.supported_vendor_ids.push(VendorId::new(value));
            Ok(())
        } else if code == AVP_AUTH_APPLICATION_ID {
            parsed
                .auth_application_ids
                .push(ApplicationId::new(parse_u32_value(
                    avp.value,
                    value_offset,
                    "6.8",
                )?));
            Ok(())
        } else if code == AVP_ACCT_APPLICATION_ID {
            parsed
                .acct_application_ids
                .push(ApplicationId::new(parse_u32_value(
                    avp.value,
                    value_offset,
                    "6.9",
                )?));
            Ok(())
        } else if code == AVP_INBAND_SECURITY_ID {
            parsed
                .inband_security_ids
                .push(parse_u32_value(avp.value, value_offset, "6.10")?);
            Ok(())
        } else if code == AVP_VENDOR_SPECIFIC_APPLICATION_ID {
            parsed
                .vendor_specific_applications
                .push(parse_vendor_specific_application(
                    &avp,
                    ctx,
                    value_offset,
                    section,
                )?);
            Ok(())
        } else {
            handle_unknown_avp(ctx, &avp, offset, section)
        }
    })?;
    Ok(parsed)
}

fn parse_vendor_specific_application(
    avp: &RawAvp<'_>,
    ctx: DecodeContext,
    value_offset: usize,
    section: &'static str,
) -> Result<VendorSpecificApplication, DecodeError> {
    let child_depth = 1;
    let mut vendor_id: Option<FieldValue<VendorId>> = None;
    let mut auth_application_id = None;
    let mut acct_application_id = None;
    for_each_avp(
        avp.value,
        ctx,
        value_offset,
        child_depth,
        |offset, child| {
            let child_value_offset = offset_add(offset, child.header.header_len(), section)?;
            validate_peer_avp_flags(&child.header, offset)?;
            if child.header.vendor_id.is_some() {
                return handle_unknown_avp(ctx, &child, offset, section);
            }
            let code = child.header.code;
            if code == AVP_VENDOR_ID {
                let value =
                    VendorId::new(parse_u32_value(child.value, child_value_offset, "5.3.3")?);
                set_once(&mut vendor_id, value, offset, section)
            } else if code == AVP_AUTH_APPLICATION_ID {
                let value =
                    ApplicationId::new(parse_u32_value(child.value, child_value_offset, "6.8")?);
                set_once(&mut auth_application_id, value, offset, section)
            } else if code == AVP_ACCT_APPLICATION_ID {
                let value =
                    ApplicationId::new(parse_u32_value(child.value, child_value_offset, "6.9")?);
                set_once(&mut acct_application_id, value, offset, section)
            } else {
                handle_unknown_avp(ctx, &child, offset, section)
            }
        },
    )?;
    let vendor_id = require_field_at(
        vendor_id,
        "diameter Vendor-Specific-Application-Id requires Vendor-Id",
        value_offset,
        section,
    )?;
    if auth_application_id.is_some() == acct_application_id.is_some() {
        return Err(decode_structural_error(
            "diameter Vendor-Specific-Application-Id requires exactly one Auth-Application-Id or Acct-Application-Id",
            value_offset,
            section,
        ));
    }
    Ok(VendorSpecificApplication {
        vendor_ids: vec![vendor_id],
        auth_application_id: auth_application_id.map(|field| field.value),
        acct_application_id: acct_application_id.map(|field| field.value),
    })
}

fn for_each_avp<F>(
    input: &[u8],
    ctx: DecodeContext,
    base_offset: usize,
    depth: usize,
    mut visit: F,
) -> Result<(), DecodeError>
where
    F: FnMut(usize, RawAvp<'_>) -> Result<(), DecodeError>,
{
    if depth > ctx.max_depth {
        return Err(
            DecodeError::new(DecodeErrorCode::DepthExceeded, base_offset)
                .with_spec_ref(peer_spec("4")),
        );
    }
    let mut remaining = input;
    let mut relative_offset = 0usize;
    let mut avp_count = 0usize;
    while !remaining.is_empty() {
        let offset = offset_add(base_offset, relative_offset, "4")?;
        avp_count = avp_count.checked_add(1).ok_or_else(|| {
            DecodeError::new(DecodeErrorCode::LengthOverflow, offset).with_spec_ref(peer_spec("4"))
        })?;
        if avp_count > ctx.max_ies {
            return Err(DecodeError::new(DecodeErrorCode::IeCountExceeded, offset)
                .with_spec_ref(peer_spec("4")));
        }
        let before = remaining.len();
        let (next, avp) = match RawAvp::decode(remaining, ctx) {
            Ok(decoded) => decoded,
            Err(error) => return Err(shift_peer_error(error, offset)),
        };
        visit(offset, avp)?;
        let consumed = before.checked_sub(next.len()).ok_or_else(|| {
            DecodeError::new(DecodeErrorCode::LengthOverflow, offset).with_spec_ref(peer_spec("4"))
        })?;
        relative_offset = relative_offset.checked_add(consumed).ok_or_else(|| {
            DecodeError::new(DecodeErrorCode::LengthOverflow, offset).with_spec_ref(peer_spec("4"))
        })?;
        remaining = next;
    }
    Ok(())
}

fn parse_string_value(
    value: &[u8],
    offset: usize,
    section: &'static str,
) -> Result<String, DecodeError> {
    let parsed = parse_utf8_value(value, offset, section)?;
    if parsed.is_empty() {
        return Err(decode_structural_error(
            "diameter UTF-8 or DiameterIdentity AVP must not be empty",
            offset,
            section,
        ));
    }
    Ok(parsed)
}

fn parse_utf8_value(
    value: &[u8],
    offset: usize,
    section: &'static str,
) -> Result<String, DecodeError> {
    let parsed = str::from_utf8(value).map_err(|_| {
        decode_structural_error(
            "diameter UTF-8 or DiameterIdentity AVP is not valid UTF-8",
            offset,
            section,
        )
    })?;
    Ok(parsed.to_owned())
}

fn parse_u32_value(value: &[u8], offset: usize, section: &'static str) -> Result<u32, DecodeError> {
    match value {
        [a, b, c, d] => Ok(u32::from_be_bytes([*a, *b, *c, *d])),
        _ => Err(DecodeError::new(
            DecodeErrorCode::InvalidLength {
                reason: "diameter Unsigned32 or Enumerated AVP value must be four octets",
            },
            offset,
        )
        .with_spec_ref(peer_spec(section))),
    }
}

fn handle_unknown_avp(
    ctx: DecodeContext,
    avp: &RawAvp<'_>,
    offset: usize,
    section: &'static str,
) -> Result<(), DecodeError> {
    if ctx.unknown_ie_policy == UnknownIePolicy::Reject || avp.header.flags.is_mandatory() {
        Err(DecodeError::new(DecodeErrorCode::UnknownCriticalIe, offset)
            .with_spec_ref(peer_spec(section)))
    } else {
        Ok(())
    }
}

fn set_once<T>(
    slot: &mut Option<FieldValue<T>>,
    value: T,
    offset: usize,
    section: &'static str,
) -> Result<(), DecodeError> {
    if slot.is_some() {
        return Err(DecodeError::new(DecodeErrorCode::DuplicateIe, offset)
            .with_spec_ref(peer_spec(section)));
    }
    *slot = Some(FieldValue::new(value, offset));
    Ok(())
}

fn validate_peer_avp_flags(header: &AvpHeader, offset: usize) -> Result<(), DecodeError> {
    // Look up the AVP by its actual code+Vendor-Id key so that a vendor-namespace
    // AVP whose code collides with a base AVP code is validated against its own
    // dictionary entry (if present) rather than the base definition. RFC 6733
    // section 4.1 identifies an AVP by code plus Vendor-Id.
    let Some(definition) = PEER_DICTIONARIES.find_avp(header.key()) else {
        return Ok(());
    };
    let flags = definition.flags();
    let section = definition.spec_ref().section();
    // PEER_DICTIONARIES currently contains only base AVPs, so V/P MustBeSet is
    // unreachable today. Match those requirements defensively so a future
    // vendor-specific entry added to the peer dictionary set is enforced.
    match flags.vendor() {
        FlagRequirement::MustBeSet if header.vendor_id.is_none() => {
            return Err(decode_structural_error(
                "diameter AVP V-bit must be set per dictionary",
                offset,
                section,
            ));
        }
        FlagRequirement::MustBeUnset if header.vendor_id.is_some() => {
            return Err(decode_structural_error(
                "diameter AVP V-bit must not be set per dictionary",
                offset,
                section,
            ));
        }
        _ => {}
    }
    match flags.mandatory() {
        FlagRequirement::MustBeSet if !header.flags.is_mandatory() => {
            return Err(decode_structural_error(
                "diameter AVP M-bit must be set per dictionary",
                offset,
                section,
            ));
        }
        FlagRequirement::MustBeUnset if header.flags.is_mandatory() => {
            return Err(decode_structural_error(
                "diameter AVP M-bit must not be set per dictionary",
                offset,
                section,
            ));
        }
        _ => {}
    }
    match flags.protected() {
        FlagRequirement::MustBeSet if !header.flags.is_protected() => {
            return Err(decode_structural_error(
                "diameter AVP P-bit must be set per dictionary",
                offset,
                section,
            ));
        }
        FlagRequirement::MustBeUnset if header.flags.is_protected() => {
            return Err(decode_structural_error(
                "diameter AVP P-bit must not be set per dictionary",
                offset,
                section,
            ));
        }
        _ => {}
    }
    Ok(())
}

fn require_field<T>(
    field: Option<FieldValue<T>>,
    reason: &'static str,
    section: &'static str,
) -> Result<T, DecodeError> {
    require_field_at(field, reason, DIAMETER_HEADER_LEN, section)
}

fn require_field_at<T>(
    field: Option<FieldValue<T>>,
    reason: &'static str,
    offset: usize,
    section: &'static str,
) -> Result<T, DecodeError> {
    match field {
        Some(field) => Ok(field.value),
        None => Err(decode_structural_error(reason, offset, section)),
    }
}

fn require_field_ref<'a, T>(
    field: &'a Option<FieldValue<T>>,
    reason: &'static str,
    section: &'static str,
) -> Result<&'a T, DecodeError> {
    match field {
        Some(field) => Ok(&field.value),
        None => Err(decode_structural_error(
            reason,
            DIAMETER_HEADER_LEN,
            section,
        )),
    }
}

fn common_copy<T: Copy + Eq>(local: &[T], remote: &[T]) -> Vec<T> {
    let mut common = Vec::new();
    for value in local {
        if remote.contains(value) && !common.contains(value) {
            common.push(*value);
        }
    }
    common
}

fn advertised_non_relay_application_ids(capabilities: &PeerCapabilities) -> Vec<ApplicationId> {
    let mut application_ids = Vec::new();
    for application_id in &capabilities.auth_application_ids {
        push_non_relay_application_id(&mut application_ids, *application_id);
    }
    for application_id in &capabilities.acct_application_ids {
        push_non_relay_application_id(&mut application_ids, *application_id);
    }
    for application in &capabilities.vendor_specific_applications {
        if let Some(application_id) = vendor_specific_application_id(application) {
            push_non_relay_application_id(&mut application_ids, application_id);
        }
    }
    application_ids
}

fn push_non_relay_application_id(application_ids: &mut Vec<ApplicationId>, value: ApplicationId) {
    if value != APPLICATION_ID_RELAY && !application_ids.contains(&value) {
        application_ids.push(value);
    }
}

fn advertises_relay_application(capabilities: &PeerCapabilities) -> bool {
    capabilities
        .auth_application_ids
        .contains(&APPLICATION_ID_RELAY)
        || capabilities
            .acct_application_ids
            .contains(&APPLICATION_ID_RELAY)
        || capabilities
            .vendor_specific_applications
            .iter()
            .any(|application| {
                vendor_specific_application_id(application) == Some(APPLICATION_ID_RELAY)
            })
}

fn common_vendor_specific_applications(
    local: &[VendorSpecificApplication],
    remote: &[VendorSpecificApplication],
) -> Vec<VendorSpecificApplication> {
    let mut common = Vec::new();
    for local_application in local {
        let has_remote_match = remote.iter().any(|remote_application| {
            same_vendor_specific_application_id(local_application, remote_application)
        });
        let already_recorded = common
            .iter()
            .any(|existing| same_vendor_specific_application_id(existing, local_application));
        if has_remote_match && !already_recorded {
            common.push(local_application.clone());
        }
    }
    common
}

fn same_vendor_specific_application_id(
    left: &VendorSpecificApplication,
    right: &VendorSpecificApplication,
) -> bool {
    (left.auth_application_id.is_some() && left.auth_application_id == right.auth_application_id)
        || (left.acct_application_id.is_some()
            && left.acct_application_id == right.acct_application_id)
}

fn vendor_specific_application_id(
    application: &VendorSpecificApplication,
) -> Option<ApplicationId> {
    application
        .auth_application_id
        .or(application.acct_application_id)
}

fn offset_add(base: usize, delta: usize, section: &'static str) -> Result<usize, DecodeError> {
    base.checked_add(delta).ok_or_else(|| {
        DecodeError::new(DecodeErrorCode::LengthOverflow, base).with_spec_ref(peer_spec(section))
    })
}

fn shift_peer_error(error: DecodeError, base_offset: usize) -> DecodeError {
    let offset = match base_offset.checked_add(error.offset()) {
        Some(offset) => offset,
        None => return DecodeError::new(DecodeErrorCode::LengthOverflow, base_offset),
    };
    let shifted = DecodeError::new(error.code().clone(), offset);
    match error.spec_ref().cloned() {
        Some(spec_ref) => shifted.with_spec_ref(spec_ref),
        None => shifted,
    }
}

fn decode_structural_error(
    reason: &'static str,
    offset: usize,
    section: &'static str,
) -> DecodeError {
    DecodeError::new(DecodeErrorCode::Structural { reason }, offset)
        .with_spec_ref(peer_spec(section))
}

fn encode_structural_error(reason: &'static str, section: &'static str) -> EncodeError {
    EncodeError::new(EncodeErrorCode::Structural { reason }).with_spec_ref(peer_spec(section))
}

fn peer_spec(section: &'static str) -> SpecRef {
    SpecRef::new("ietf", "RFC6733", section)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::{
        INBAND_SECURITY_ID_NO_INBAND_SECURITY, RESULT_CODE_DIAMETER_COMMAND_UNSUPPORTED,
        RESULT_CODE_DIAMETER_NO_COMMON_APPLICATION, RESULT_CODE_DIAMETER_SUCCESS,
    };
    use crate::{AvpFlags, AVP_HEADER_LEN};
    use bytes::Bytes;
    use opc_protocol::{DecodeErrorCode, ValidationLevel};

    fn sample_capabilities() -> PeerCapabilities {
        let mut capabilities = PeerCapabilities::new(
            PeerIdentity::new("aaa1.example.net", "example.net"),
            vec![HostIpAddress::ipv4([192, 0, 2, 10])],
            VendorId::new(10415),
            "opc-diameter-test",
        );
        capabilities.origin_state_id = Some(7);
        capabilities.firmware_revision = Some(11);
        capabilities.supported_vendor_ids.push(VendorId::new(10415));
        capabilities
            .auth_application_ids
            .push(ApplicationId::new(16_777_251));
        capabilities
            .acct_application_ids
            .push(ApplicationId::new(3));
        capabilities
            .vendor_specific_applications
            .push(VendorSpecificApplication::auth(
                VendorId::new(10415),
                ApplicationId::new(16_777_251),
            ));
        capabilities
            .inband_security_ids
            .push(INBAND_SECURITY_ID_NO_INBAND_SECURITY);
        capabilities
    }

    fn encode_owned(message: &OwnedMessage) -> Bytes {
        let mut encoded = BytesMut::new();
        if let Err(error) = message.encode(&mut encoded, EncodeContext::default()) {
            panic!("message encode failed: {error}");
        }
        encoded.freeze()
    }

    fn decode_message(encoded: &[u8]) -> Message<'_> {
        match Message::decode(encoded, DecodeContext::default()) {
            Ok((remaining, decoded)) => {
                assert!(remaining.is_empty());
                decoded
            }
            Err(error) => panic!("message decode failed: {error}"),
        }
    }

    fn decode_peer_message_conservatively(encoded: &[u8]) -> Message<'_> {
        match Message::decode_with_dictionary(
            encoded,
            DecodeContext::conservative(),
            PEER_DICTIONARIES,
        ) {
            Ok((remaining, decoded)) => {
                assert!(remaining.is_empty());
                decoded
            }
            Err(error) => panic!("conservative peer message decode failed: {error}"),
        }
    }

    fn assert_conservative_dictionary_duplicate(message: &OwnedMessage) {
        let encoded = encode_owned(message);
        let result = Message::decode_with_dictionary(
            &encoded,
            DecodeContext::conservative(),
            PEER_DICTIONARIES,
        );
        assert!(matches!(
            result,
            Err(error) if matches!(error.code(), DecodeErrorCode::DuplicateIe)
        ));
    }

    #[test]
    fn multihomed_cer_and_cea_round_trip_with_conservative_dictionary_decode() {
        let mut capabilities = sample_capabilities();
        capabilities
            .host_ip_addresses
            .push(HostIpAddress::ipv4([198, 51, 100, 20]));

        let request = match build_capabilities_exchange_request(
            &capabilities,
            0x0102_0304,
            0x0506_0708,
            EncodeContext::default(),
        ) {
            Ok(message) => message,
            Err(error) => panic!("multihomed CER build failed: {error}"),
        };
        let encoded_request = encode_owned(&request);
        let decoded_request = decode_peer_message_conservatively(&encoded_request);
        match parse_capabilities_exchange_request(&decoded_request, DecodeContext::conservative()) {
            Ok(parsed) => assert_eq!(parsed, capabilities),
            Err(error) => panic!("multihomed CER parse failed: {error}"),
        }

        let answer = CapabilitiesExchangeAnswer {
            result_code: RESULT_CODE_DIAMETER_SUCCESS,
            capabilities,
            diagnostics: AnswerDiagnostics::default(),
        };
        let built_answer = match build_capabilities_exchange_answer(
            &answer,
            0x0102_0304,
            0x0506_0708,
            EncodeContext::default(),
        ) {
            Ok(message) => message,
            Err(error) => panic!("multihomed CEA build failed: {error}"),
        };
        let encoded_answer = encode_owned(&built_answer);
        let decoded_answer = decode_peer_message_conservatively(&encoded_answer);
        match parse_capabilities_exchange_answer(&decoded_answer, DecodeContext::conservative()) {
            Ok(parsed) => assert_eq!(parsed, answer),
            Err(error) => panic!("multihomed CEA parse failed: {error}"),
        }
    }

    #[test]
    fn raw_conservative_decode_retains_blanket_duplicate_rejection() {
        let mut capabilities = sample_capabilities();
        capabilities
            .host_ip_addresses
            .push(HostIpAddress::ipv4([198, 51, 100, 20]));
        let request = match build_capabilities_exchange_request(
            &capabilities,
            0x0102_0304,
            0x0506_0708,
            EncodeContext::default(),
        ) {
            Ok(message) => message,
            Err(error) => panic!("multihomed CER build failed: {error}"),
        };
        let encoded = encode_owned(&request);

        let result = Message::decode(&encoded, DecodeContext::conservative());
        assert!(matches!(
            result,
            Err(error) if matches!(error.code(), DecodeErrorCode::DuplicateIe)
        ));
    }

    #[test]
    fn capabilities_dictionary_rejects_singleton_duplicates() {
        let mut duplicate_origin_host = BytesMut::new();
        for host in ["aaa1.example.net", "aaa2.example.net"] {
            if let Err(error) = append_utf8_avp(
                &mut duplicate_origin_host,
                AVP_ORIGIN_HOST,
                host,
                true,
                EncodeContext::default(),
            ) {
                panic!("Origin-Host AVP build failed: {error}");
            }
        }
        let request = match build_message(
            peer_request_flags(PeerProcedure::CapabilitiesExchange),
            COMMAND_CAPABILITIES_EXCHANGE,
            duplicate_origin_host,
            1,
            2,
            EncodeContext::default(),
            "5.3.1",
        ) {
            Ok(message) => message,
            Err(error) => panic!("duplicate Origin-Host CER build failed: {error}"),
        };
        assert_conservative_dictionary_duplicate(&request);

        let mut duplicate_result_code = BytesMut::new();
        for result_code in [
            RESULT_CODE_DIAMETER_SUCCESS,
            RESULT_CODE_DIAMETER_NO_COMMON_APPLICATION,
        ] {
            if let Err(error) = append_u32_avp(
                &mut duplicate_result_code,
                AVP_RESULT_CODE,
                result_code,
                true,
                EncodeContext::default(),
            ) {
                panic!("Result-Code AVP build failed: {error}");
            }
        }
        let answer = match build_message(
            peer_answer_flags(PeerProcedure::CapabilitiesExchange, false),
            COMMAND_CAPABILITIES_EXCHANGE,
            duplicate_result_code,
            1,
            2,
            EncodeContext::default(),
            "5.3.2",
        ) {
            Ok(message) => message,
            Err(error) => panic!("duplicate Result-Code CEA build failed: {error}"),
        };
        assert_conservative_dictionary_duplicate(&answer);

        let mut failed_value = BytesMut::new();
        if let Err(error) = append_utf8_avp(
            &mut failed_value,
            AVP_ORIGIN_HOST,
            "invalid.example.net",
            true,
            EncodeContext::default(),
        ) {
            panic!("nested Failed-AVP value build failed: {error}");
        }
        let mut duplicate_failed_avp = BytesMut::new();
        for _ in 0..2 {
            if let Err(error) = append_avp(
                &mut duplicate_failed_avp,
                AvpHeader::ietf(AVP_FAILED_AVP, true),
                &failed_value,
                EncodeContext::default(),
            ) {
                panic!("Failed-AVP build failed: {error}");
            }
        }
        let answer = match build_message(
            peer_answer_flags(PeerProcedure::CapabilitiesExchange, true),
            COMMAND_CAPABILITIES_EXCHANGE,
            duplicate_failed_avp,
            1,
            2,
            EncodeContext::default(),
            "5.3.2",
        ) {
            Ok(message) => message,
            Err(error) => panic!("duplicate Failed-AVP CEA build failed: {error}"),
        };
        assert_conservative_dictionary_duplicate(&answer);
    }

    #[test]
    fn watchdog_and_disconnect_dictionary_decode_rejects_duplicates() {
        for procedure in [PeerProcedure::DeviceWatchdog, PeerProcedure::DisconnectPeer] {
            for kind in [CommandKind::Request, CommandKind::Answer] {
                let mut duplicate_origin_host = BytesMut::new();
                for host in ["aaa1.example.net", "aaa2.example.net"] {
                    if let Err(error) = append_utf8_avp(
                        &mut duplicate_origin_host,
                        AVP_ORIGIN_HOST,
                        host,
                        true,
                        EncodeContext::default(),
                    ) {
                        panic!("Origin-Host AVP build failed: {error}");
                    }
                }
                let flags = match kind {
                    CommandKind::Request => peer_request_flags(procedure),
                    CommandKind::Answer => peer_answer_flags(procedure, false),
                };
                let message = match build_message(
                    flags,
                    procedure.command_code(),
                    duplicate_origin_host,
                    1,
                    2,
                    EncodeContext::default(),
                    procedure.spec_section(kind),
                ) {
                    Ok(message) => message,
                    Err(error) => panic!("peer message build failed: {error}"),
                };
                assert_conservative_dictionary_duplicate(&message);
            }
        }
    }

    #[test]
    fn classifies_device_watchdog_answer() {
        let header = Header::new(
            peer_answer_flags(PeerProcedure::DeviceWatchdog, false),
            COMMAND_DEVICE_WATCHDOG,
            ApplicationId::new(0),
            1,
            2,
        );
        assert_eq!(
            classify_header(&header),
            Some((PeerProcedure::DeviceWatchdog, CommandKind::Answer))
        );
    }

    #[test]
    fn capabilities_exchange_request_builder_parser_round_trip() {
        let capabilities = sample_capabilities();
        let raw_preserving_ctx = EncodeContext {
            raw_preserving: true,
            ..EncodeContext::default()
        };
        let built = match build_capabilities_exchange_request(
            &capabilities,
            0x0102_0304,
            0x0506_0708,
            raw_preserving_ctx,
        ) {
            Ok(message) => message,
            Err(error) => panic!("CER build failed: {error}"),
        };
        let encoded = encode_owned(&built);
        let message = decode_message(&encoded);
        assert_eq!(
            classify_header(&message.header),
            Some((PeerProcedure::CapabilitiesExchange, CommandKind::Request))
        );
        let parsed = match parse_capabilities_exchange_request(&message, DecodeContext::default()) {
            Ok(parsed) => parsed,
            Err(error) => panic!("CER parse failed: {error}"),
        };
        assert_eq!(parsed, capabilities);
    }

    #[test]
    fn capabilities_exchange_answer_negotiates_common_capabilities() {
        let mut local = sample_capabilities();
        local.auth_application_ids.push(ApplicationId::new(99));
        local.supported_vendor_ids.push(VendorId::new(1));

        let mut remote = sample_capabilities();
        remote.auth_application_ids = vec![ApplicationId::new(16_777_251)];
        remote.supported_vendor_ids = vec![VendorId::new(10415), VendorId::new(2)];
        remote.inband_security_ids = vec![INBAND_SECURITY_ID_NO_INBAND_SECURITY];

        let answer = CapabilitiesExchangeAnswer {
            result_code: RESULT_CODE_DIAMETER_SUCCESS,
            capabilities: remote.clone(),
            diagnostics: AnswerDiagnostics::default(),
        };
        let built =
            match build_capabilities_exchange_answer(&answer, 0x10, 0x20, EncodeContext::default())
            {
                Ok(message) => message,
                Err(error) => panic!("CEA build failed: {error}"),
            };
        let encoded = encode_owned(&built);
        let message = decode_message(&encoded);
        let parsed = match parse_capabilities_exchange_answer(&message, DecodeContext::default()) {
            Ok(parsed) => parsed,
            Err(error) => panic!("CEA parse failed: {error}"),
        };
        assert_eq!(parsed.result_code, RESULT_CODE_DIAMETER_SUCCESS);
        assert_eq!(parsed.capabilities, remote);
        assert!(parsed.diagnostics.is_empty());

        let negotiated = negotiate_capabilities(&local, &parsed.capabilities);
        assert_eq!(
            negotiated.application_ids,
            vec![ApplicationId::new(16_777_251), ApplicationId::new(3)]
        );
        assert!(!negotiated.relay_application);
        assert_eq!(negotiated.supported_vendor_ids, vec![VendorId::new(10415)]);
        assert_eq!(
            negotiated.auth_application_ids,
            vec![ApplicationId::new(16_777_251)]
        );
        assert_eq!(negotiated.acct_application_ids, vec![ApplicationId::new(3)]);
        assert_eq!(negotiated.vendor_specific_applications.len(), 1);
        assert_eq!(
            negotiated.inband_security_ids,
            vec![INBAND_SECURITY_ID_NO_INBAND_SECURITY]
        );
        assert!(negotiated.has_common_application());
        assert_eq!(negotiated.cea_result_code(), RESULT_CODE_DIAMETER_SUCCESS);
    }

    #[test]
    fn cea_result_helper_and_failed_avp_diagnostics_round_trip() {
        let mut local = sample_capabilities();
        local.auth_application_ids.clear();
        local.acct_application_ids.clear();
        local.vendor_specific_applications.clear();

        let mut remote = sample_capabilities();
        remote.auth_application_ids.clear();
        remote.acct_application_ids.clear();
        remote.vendor_specific_applications.clear();

        let negotiated = negotiate_capabilities(&local, &remote);
        assert!(negotiated.application_ids.is_empty());
        assert!(!negotiated.relay_application);
        assert!(!negotiated.has_common_application());
        assert!(!has_common_application(&local, &remote));
        assert_eq!(
            negotiated.cea_result_code(),
            RESULT_CODE_DIAMETER_NO_COMMON_APPLICATION
        );
        assert_eq!(
            cea_result_code(&local, &remote),
            RESULT_CODE_DIAMETER_NO_COMMON_APPLICATION
        );

        let mut failed_avp_value = BytesMut::new();
        if let Err(error) = append_utf8_avp(
            &mut failed_avp_value,
            AVP_ORIGIN_REALM,
            "example.net",
            true,
            EncodeContext::default(),
        ) {
            panic!("Failed-AVP value build failed: {error}");
        }
        let answer = CapabilitiesExchangeAnswer {
            result_code: RESULT_CODE_DIAMETER_COMMAND_UNSUPPORTED,
            capabilities: remote,
            diagnostics: AnswerDiagnostics {
                error_message: Some("unsupported command".to_string()),
                failed_avps: vec![failed_avp_value.freeze()],
            },
        };
        let built =
            match build_capabilities_exchange_answer(&answer, 0x11, 0x22, EncodeContext::default())
            {
                Ok(message) => message,
                Err(error) => panic!("CEA error answer build failed: {error}"),
            };
        let encoded = encode_owned(&built);
        let message = decode_message(&encoded);
        assert!(message.header.flags.is_error());
        let parsed = match parse_capabilities_exchange_answer(&message, DecodeContext::default()) {
            Ok(parsed) => parsed,
            Err(error) => panic!("CEA error answer parse failed: {error}"),
        };
        assert_eq!(parsed.diagnostics, answer.diagnostics);
    }

    #[test]
    fn vendor_specific_application_common_result_ignores_nested_vendor_id() {
        let application_id = ApplicationId::new(16_777_251);
        let local_application =
            VendorSpecificApplication::auth(VendorId::new(10415), application_id);
        let remote_application =
            VendorSpecificApplication::auth(VendorId::new(4_242), application_id);

        let mut local = sample_capabilities();
        local.auth_application_ids.clear();
        local.acct_application_ids.clear();
        local.vendor_specific_applications = vec![local_application.clone()];

        let mut remote = sample_capabilities();
        remote.auth_application_ids.clear();
        remote.acct_application_ids.clear();
        remote.vendor_specific_applications = vec![remote_application];

        let negotiated = negotiate_capabilities(&local, &remote);
        assert_eq!(negotiated.application_ids, vec![application_id]);
        assert_eq!(
            negotiated.vendor_specific_applications,
            vec![local_application]
        );
        assert!(negotiated.has_common_application());
        assert_eq!(negotiated.cea_result_code(), RESULT_CODE_DIAMETER_SUCCESS);
    }

    #[test]
    fn relay_advertisement_counts_as_common_application() {
        let mut local = sample_capabilities();
        local.auth_application_ids.clear();
        local.acct_application_ids.clear();
        local.vendor_specific_applications.clear();

        let mut remote = sample_capabilities();
        remote.auth_application_ids = vec![APPLICATION_ID_RELAY];
        remote.acct_application_ids.clear();
        remote.vendor_specific_applications.clear();

        let negotiated = negotiate_capabilities(&local, &remote);
        assert!(negotiated.application_ids.is_empty());
        assert!(negotiated.relay_application);
        assert!(negotiated.has_common_application());
        assert!(has_common_application(&local, &remote));
        assert_eq!(
            cea_result_code(&local, &remote),
            RESULT_CODE_DIAMETER_SUCCESS
        );
    }

    fn negotiated_session() -> PeerSession {
        let local = sample_capabilities();
        let remote = sample_capabilities();
        let policy = PeerSessionPolicy::default()
            .accept_application(ApplicationId::new(16_777_251))
            .accept_inband_security(INBAND_SECURITY_ID_NO_INBAND_SECURITY)
            .with_watchdog_miss_threshold(2);
        let mut session = PeerSession::with_policy(local, policy);
        let _transition = session.capabilities_request_sent();
        let answer = CapabilitiesExchangeAnswer {
            result_code: RESULT_CODE_DIAMETER_SUCCESS,
            capabilities: remote,
            diagnostics: AnswerDiagnostics::default(),
        };
        let _transition = session.observe_capabilities_answer(&answer);
        session
    }

    #[test]
    fn peer_session_accepts_capabilities_and_watchdog_liveness() {
        let mut session = negotiated_session();

        assert_eq!(session.state(), PeerSessionState::Negotiated);
        let readiness = session.readiness();
        assert!(readiness.negotiated);
        assert!(readiness.traffic_ready);
        assert!(readiness.blockers.is_empty());
        match session.last_capability_projection() {
            Some(projection) => {
                assert!(projection.accepted);
                assert!(projection.accepted_application_common);
                assert!(projection.accepted_inband_security_common);
            }
            None => panic!("capability projection missing"),
        }

        let transition = match session.watchdog_request_sent() {
            Ok(transition) => transition,
            Err(error) => panic!("watchdog request transition failed: {error}"),
        };
        assert_eq!(transition.event, PeerSessionEvent::WatchdogRequestSent);
        assert_eq!(transition.state, PeerSessionState::WatchdogProbing);
        assert_eq!(
            transition.readiness.blockers,
            vec![PeerSessionBlocker::WatchdogAnswerPending]
        );

        let answer = DeviceWatchdogAnswer {
            result_code: RESULT_CODE_DIAMETER_SUCCESS,
            identity: PeerIdentity::new("aaa-peer.example.net", "example.net"),
            origin_state_id: Some(9),
            diagnostics: AnswerDiagnostics::default(),
        };
        let transition = match session.observe_watchdog_answer(&answer) {
            Ok(transition) => transition,
            Err(error) => panic!("watchdog answer transition failed: {error}"),
        };
        assert_eq!(transition.event, PeerSessionEvent::WatchdogAnswerAccepted);
        assert_eq!(transition.state, PeerSessionState::Negotiated);
        assert!(transition.readiness.traffic_ready);
        match session.last_watchdog_projection() {
            Some(projection) => {
                assert!(projection.alive);
                assert_eq!(projection.origin_state_id, Some(9));
                assert_eq!(projection.missed_watchdogs, 0);
            }
            None => panic!("watchdog projection missing"),
        }

        let snapshot = session.snapshot();
        assert_eq!(snapshot.capabilities_requests_sent, 1);
        assert_eq!(snapshot.capabilities_answers_observed, 1);
        assert_eq!(snapshot.watchdog_requests_sent, 1);
        assert_eq!(snapshot.watchdog_answers_observed, 1);
    }

    #[test]
    fn peer_session_rejects_protocol_errors_and_policy_misses() {
        let local = sample_capabilities();
        let mut remote = sample_capabilities();
        remote.auth_application_ids.clear();
        remote.acct_application_ids.clear();
        remote.vendor_specific_applications.clear();
        remote.inband_security_ids.clear();
        let policy = PeerSessionPolicy::default()
            .without_relay_application()
            .accept_application(ApplicationId::new(16_777_251))
            .accept_inband_security(INBAND_SECURITY_ID_NO_INBAND_SECURITY);
        let mut session = PeerSession::with_policy(local.clone(), policy.clone());
        let answer = CapabilitiesExchangeAnswer {
            result_code: RESULT_CODE_DIAMETER_SUCCESS,
            capabilities: remote,
            diagnostics: AnswerDiagnostics::default(),
        };

        let transition = session.observe_capabilities_answer(&answer);

        assert_eq!(
            transition.event,
            PeerSessionEvent::CapabilitiesAnswerRejected
        );
        assert_eq!(transition.state, PeerSessionState::Failed);
        assert_eq!(
            transition.readiness.blockers,
            vec![
                PeerSessionBlocker::NoCommonApplication,
                PeerSessionBlocker::AcceptedApplicationMissing,
                PeerSessionBlocker::AcceptedInbandSecurityMissing,
            ]
        );
        match session.last_capability_projection() {
            Some(projection) => {
                assert!(!projection.accepted);
                assert_eq!(projection.result_code, RESULT_CODE_DIAMETER_SUCCESS);
            }
            None => panic!("capability projection missing"),
        }

        let mut session = PeerSession::with_policy(local, policy);
        let error_answer = CapabilitiesExchangeErrorAnswer {
            result_code: RESULT_CODE_DIAMETER_COMMAND_UNSUPPORTED,
            identity: PeerIdentity::new("aaa-error.example.net", "example.net"),
            diagnostics: AnswerDiagnostics::default(),
        };
        let transition = session.observe_capabilities_protocol_error_answer(&error_answer);
        assert_eq!(
            transition.event,
            PeerSessionEvent::CapabilitiesProtocolError
        );
        assert_eq!(transition.state, PeerSessionState::Failed);
        assert_eq!(
            transition.readiness.blockers,
            vec![
                PeerSessionBlocker::CapabilitiesProtocolError,
                PeerSessionBlocker::CapabilitiesResultNotSuccess,
                PeerSessionBlocker::NoCommonApplication,
                PeerSessionBlocker::AcceptedApplicationMissing,
                PeerSessionBlocker::AcceptedInbandSecurityMissing,
            ]
        );
    }

    #[test]
    fn peer_session_watchdog_misses_degrade_then_fail() {
        let mut session = negotiated_session();
        match session.watchdog_request_sent() {
            Ok(_transition) => {}
            Err(error) => panic!("watchdog request transition failed: {error}"),
        }

        let transition = match session.watchdog_missed() {
            Ok(transition) => transition,
            Err(error) => panic!("watchdog miss transition failed: {error}"),
        };

        assert_eq!(transition.state, PeerSessionState::Degraded);
        assert!(transition.readiness.degraded);
        assert_eq!(
            transition.readiness.blockers,
            vec![PeerSessionBlocker::WatchdogMissed]
        );

        match session.watchdog_request_sent() {
            Ok(_transition) => {}
            Err(error) => panic!("second watchdog request transition failed: {error}"),
        }
        let transition = match session.watchdog_missed() {
            Ok(transition) => transition,
            Err(error) => panic!("second watchdog miss transition failed: {error}"),
        };

        assert_eq!(transition.state, PeerSessionState::Failed);
        assert!(transition.readiness.failed);
        assert_eq!(
            transition.readiness.blockers,
            vec![PeerSessionBlocker::WatchdogMissThresholdExceeded]
        );
        assert_eq!(session.snapshot().missed_watchdogs, 2);
    }

    #[test]
    fn peer_session_disconnect_and_reconnect_projection() {
        let mut session = negotiated_session();
        let request = DisconnectPeerRequest {
            identity: PeerIdentity::new("aaa-peer.example.net", "example.net"),
            disconnect_cause: DisconnectCause::Busy,
            origin_state_id: Some(11),
        };

        let transition = session.observe_disconnect_request(&request);

        assert_eq!(
            transition.event,
            PeerSessionEvent::DisconnectRequestReceived
        );
        assert_eq!(transition.state, PeerSessionState::Draining);
        assert!(transition.readiness.draining);
        match session.last_disconnect_projection() {
            Some(projection) => {
                assert!(projection.peer_requested);
                assert!(!projection.acknowledged);
            }
            None => panic!("disconnect projection missing"),
        }

        let answer = DisconnectPeerAnswer {
            result_code: RESULT_CODE_DIAMETER_SUCCESS,
            identity: PeerIdentity::new("aaa-local.example.net", "example.net"),
            origin_state_id: Some(12),
            diagnostics: AnswerDiagnostics::default(),
        };
        let transition = session.disconnect_answer_sent(&answer);
        assert_eq!(transition.event, PeerSessionEvent::DisconnectAnswerSent);
        assert_eq!(transition.state, PeerSessionState::Reconnecting);
        assert!(transition.readiness.reconnecting);
        match session.last_disconnect_projection() {
            Some(projection) => {
                assert!(projection.acknowledged);
                assert!(projection.reconnect_intent);
            }
            None => panic!("disconnect projection missing"),
        }

        let transition = session.enter_backoff();
        assert_eq!(transition.state, PeerSessionState::Backoff);
        assert_eq!(
            transition.readiness.blockers,
            vec![PeerSessionBlocker::ReconnectBackoff]
        );
        let transition = session.backoff_elapsed();
        assert_eq!(transition.state, PeerSessionState::Reconnecting);
        assert!(transition.readiness.blockers.is_empty());
        assert_eq!(session.snapshot().backoffs_entered, 1);
        assert_eq!(session.snapshot().reconnects_scheduled, 1);
    }

    #[test]
    fn peer_session_invalid_transition_and_debug_are_redaction_safe() {
        let mut session = PeerSession::new(sample_capabilities());

        let error = match session.watchdog_request_sent() {
            Ok(transition) => panic!("unexpected transition: {transition:?}"),
            Err(error) => error,
        };

        assert_eq!(error.as_str(), "diameter_peer_session_invalid_transition");
        assert_eq!(
            format!("{error}"),
            "diameter_peer_session_invalid_transition: operation watchdog_request_sent, state idle"
        );
        assert_eq!(PeerSessionState::Backoff.as_str(), "backoff");
        assert_eq!(
            PeerSessionEvent::CapabilitiesAnswerAccepted.as_str(),
            "capabilities_answer_accepted"
        );
        assert_eq!(
            PeerSessionBlocker::WatchdogMissThresholdExceeded.as_str(),
            "diameter_peer_watchdog_miss_threshold_exceeded"
        );

        let debug = format!("{session:?}");
        assert!(debug.contains("PeerSession"));
        assert!(!debug.contains("aaa1.example.net"));
        assert!(!debug.contains("192.0.2.10"));
    }

    #[test]
    fn common_application_ids_are_computed_across_advertisement_forms() {
        let application_id = ApplicationId::new(16_777_272);
        let mut local = sample_capabilities();
        local.auth_application_ids = vec![application_id];
        local.acct_application_ids.clear();
        local.vendor_specific_applications.clear();

        let mut remote = sample_capabilities();
        remote.auth_application_ids.clear();
        remote.acct_application_ids.clear();
        remote.vendor_specific_applications = vec![VendorSpecificApplication::auth(
            VendorId::new(10415),
            application_id,
        )];

        let negotiated = negotiate_capabilities(&local, &remote);
        assert_eq!(negotiated.application_ids, vec![application_id]);
        assert!(negotiated.auth_application_ids.is_empty());
        assert!(negotiated.vendor_specific_applications.is_empty());
        assert!(negotiated.has_common_application());
        assert_eq!(negotiated.cea_result_code(), RESULT_CODE_DIAMETER_SUCCESS);
    }

    #[test]
    fn minimal_cea_error_answer_preserves_empty_message_and_failed_avp() {
        let identity = PeerIdentity::new("aaa-error.example.net", "example.net");
        let mut failed_avp_value = BytesMut::new();
        if let Err(error) = append_utf8_avp(
            &mut failed_avp_value,
            AVP_ORIGIN_REALM,
            "example.net",
            true,
            EncodeContext::default(),
        ) {
            panic!("Failed-AVP value build failed: {error}");
        }

        let answer = CapabilitiesExchangeErrorAnswer {
            result_code: RESULT_CODE_DIAMETER_COMMAND_UNSUPPORTED,
            identity,
            diagnostics: AnswerDiagnostics {
                error_message: Some(String::new()),
                failed_avps: vec![failed_avp_value.freeze()],
            },
        };
        let built = match build_capabilities_exchange_error_answer(
            &answer,
            0x1111_1111,
            0x2222_2222,
            EncodeContext::default(),
        ) {
            Ok(message) => message,
            Err(error) => panic!("minimal CEA error answer build failed: {error}"),
        };
        let encoded = encode_owned(&built);
        let message = decode_message(&encoded);
        assert!(message.header.flags.is_error());
        let parsed =
            match parse_capabilities_exchange_error_answer(&message, DecodeContext::default()) {
                Ok(parsed) => parsed,
                Err(error) => panic!("minimal CEA error answer parse failed: {error}"),
            };
        assert_eq!(parsed, answer);
    }

    #[test]
    fn supported_vendor_id_zero_is_rejected_for_encode_and_parse() {
        let mut capabilities = sample_capabilities();
        capabilities.supported_vendor_ids = vec![VendorId::new(0)];
        let build_result = build_capabilities_exchange_request(
            &capabilities,
            0x0102_0304,
            0x0506_0708,
            EncodeContext::default(),
        );
        assert!(matches!(
            build_result,
            Err(error) if matches!(error.code(), EncodeErrorCode::Structural { .. })
        ));

        let valid = sample_capabilities();
        let mut raw_avps = BytesMut::new();
        if let Err(error) =
            append_identity_avps(&mut raw_avps, &valid.identity, EncodeContext::default())
        {
            panic!("identity AVP build failed: {error}");
        }
        if let Err(error) = append_address_avp(
            &mut raw_avps,
            valid.host_ip_addresses[0],
            EncodeContext::default(),
        ) {
            panic!("Host-IP-Address AVP build failed: {error}");
        }
        if let Err(error) = append_u32_avp(
            &mut raw_avps,
            AVP_VENDOR_ID,
            valid.vendor_id.get(),
            true,
            EncodeContext::default(),
        ) {
            panic!("Vendor-Id AVP build failed: {error}");
        }
        if let Err(error) = append_utf8_avp(
            &mut raw_avps,
            AVP_PRODUCT_NAME,
            &valid.product_name,
            false,
            EncodeContext::default(),
        ) {
            panic!("Product-Name AVP build failed: {error}");
        }
        if let Err(error) = append_u32_avp(
            &mut raw_avps,
            AVP_SUPPORTED_VENDOR_ID,
            0,
            true,
            EncodeContext::default(),
        ) {
            panic!("Supported-Vendor-Id AVP build failed: {error}");
        }
        let built = match build_message(
            peer_request_flags(PeerProcedure::CapabilitiesExchange),
            COMMAND_CAPABILITIES_EXCHANGE,
            raw_avps,
            0x10,
            0x20,
            EncodeContext::default(),
            "5.3.1",
        ) {
            Ok(message) => message,
            Err(error) => panic!("CER build failed: {error}"),
        };
        let encoded = encode_owned(&built);
        let message = decode_message(&encoded);
        let parse_result = parse_capabilities_exchange_request(&message, DecodeContext::default());
        assert!(matches!(
            parse_result,
            Err(error) if matches!(error.code(), DecodeErrorCode::Structural { .. })
        ));
    }

    #[test]
    fn watchdog_and_disconnect_builders_parse_without_transport_state() {
        let identity = PeerIdentity::new("aaa2.example.net", "example.net");
        let dwr_request = DeviceWatchdogRequest {
            identity: identity.clone(),
            origin_state_id: Some(21),
        };
        let dwr = match build_device_watchdog_request(&dwr_request, 1, 2, EncodeContext::default())
        {
            Ok(message) => message,
            Err(error) => panic!("DWR build failed: {error}"),
        };
        let encoded = encode_owned(&dwr);
        let message = decode_message(&encoded);
        match parse_device_watchdog_request(&message, DecodeContext::default()) {
            Ok(parsed) => assert_eq!(parsed, dwr_request),
            Err(error) => panic!("DWR parse failed: {error}"),
        }

        let dwa_answer = DeviceWatchdogAnswer {
            result_code: RESULT_CODE_DIAMETER_SUCCESS,
            identity: identity.clone(),
            origin_state_id: Some(22),
            diagnostics: AnswerDiagnostics::default(),
        };
        let dwa = match build_device_watchdog_answer(&dwa_answer, 3, 4, EncodeContext::default()) {
            Ok(message) => message,
            Err(error) => panic!("DWA build failed: {error}"),
        };
        let encoded = encode_owned(&dwa);
        let message = decode_message(&encoded);
        match parse_device_watchdog_answer(&message, DecodeContext::default()) {
            Ok(parsed) => assert_eq!(parsed, dwa_answer),
            Err(error) => panic!("DWA parse failed: {error}"),
        }

        let dpr_request = DisconnectPeerRequest {
            identity: identity.clone(),
            disconnect_cause: DisconnectCause::Busy,
            origin_state_id: Some(23),
        };
        let dpr = match build_disconnect_peer_request(&dpr_request, 5, 6, EncodeContext::default())
        {
            Ok(message) => message,
            Err(error) => panic!("DPR build failed: {error}"),
        };
        let encoded = encode_owned(&dpr);
        let message = decode_message(&encoded);
        match parse_disconnect_peer_request(&message, DecodeContext::default()) {
            Ok(parsed) => assert_eq!(parsed, dpr_request),
            Err(error) => panic!("DPR parse failed: {error}"),
        }

        let mut failed_avp_value = BytesMut::new();
        if let Err(error) = append_utf8_avp(
            &mut failed_avp_value,
            AVP_ORIGIN_HOST,
            "bad.example.net",
            true,
            EncodeContext::default(),
        ) {
            panic!("Failed-AVP value build failed: {error}");
        }
        let dpa_answer = DisconnectPeerAnswer {
            result_code: RESULT_CODE_DIAMETER_COMMAND_UNSUPPORTED,
            identity,
            origin_state_id: Some(24),
            diagnostics: AnswerDiagnostics {
                error_message: Some("unsupported command".to_string()),
                failed_avps: vec![failed_avp_value.freeze()],
            },
        };
        let dpa = match build_disconnect_peer_answer(&dpa_answer, 7, 8, EncodeContext::default()) {
            Ok(message) => message,
            Err(error) => panic!("DPA build failed: {error}"),
        };
        let encoded = encode_owned(&dpa);
        let message = decode_message(&encoded);
        assert!(message.header.flags.is_error());
        match parse_disconnect_peer_answer(&message, DecodeContext::default()) {
            Ok(parsed) => assert_eq!(parsed, dpa_answer),
            Err(error) => panic!("DPA parse failed: {error}"),
        }
    }

    #[test]
    fn procedure_parser_rejects_missing_mandatory_identity_avp() {
        let mut raw_avps = BytesMut::new();
        if let Err(error) = append_utf8_avp(
            &mut raw_avps,
            AVP_ORIGIN_HOST,
            "aaa3.example.net",
            true,
            EncodeContext::default(),
        ) {
            panic!("AVP build failed: {error}");
        }
        let built = match build_message(
            peer_request_flags(PeerProcedure::DeviceWatchdog),
            COMMAND_DEVICE_WATCHDOG,
            raw_avps,
            1,
            2,
            EncodeContext::default(),
            "5.5.1",
        ) {
            Ok(message) => message,
            Err(error) => panic!("message build failed: {error}"),
        };
        let encoded = encode_owned(&built);
        let message = decode_message(&encoded);
        let result = parse_device_watchdog_request(&message, DecodeContext::default());
        assert!(matches!(
            result,
            Err(error) if matches!(error.code(), DecodeErrorCode::Structural { .. })
        ));
    }

    #[test]
    fn procedure_parser_rejects_duplicate_and_empty_identity_avps() {
        let identity = PeerIdentity::new("aaa3.example.net", "example.net");
        let mut duplicate_raw_avps = BytesMut::new();
        if let Err(error) =
            append_identity_avps(&mut duplicate_raw_avps, &identity, EncodeContext::default())
        {
            panic!("identity AVP build failed: {error}");
        }
        if let Err(error) = append_utf8_avp(
            &mut duplicate_raw_avps,
            AVP_ORIGIN_HOST,
            "aaa3b.example.net",
            true,
            EncodeContext::default(),
        ) {
            panic!("duplicate Origin-Host AVP build failed: {error}");
        }
        let built = match build_message(
            peer_request_flags(PeerProcedure::DeviceWatchdog),
            COMMAND_DEVICE_WATCHDOG,
            duplicate_raw_avps,
            1,
            2,
            EncodeContext::default(),
            "5.5.1",
        ) {
            Ok(message) => message,
            Err(error) => panic!("message build failed: {error}"),
        };
        let encoded = encode_owned(&built);
        let message = decode_message(&encoded);
        let result = parse_device_watchdog_request(&message, DecodeContext::default());
        assert!(matches!(
            result,
            Err(error) if matches!(error.code(), DecodeErrorCode::DuplicateIe)
        ));

        let mut empty_raw_avps = BytesMut::new();
        if let Err(error) = append_utf8_avp(
            &mut empty_raw_avps,
            AVP_ORIGIN_HOST,
            "",
            true,
            EncodeContext::default(),
        ) {
            panic!("empty Origin-Host AVP build failed: {error}");
        }
        if let Err(error) = append_utf8_avp(
            &mut empty_raw_avps,
            AVP_ORIGIN_REALM,
            "example.net",
            true,
            EncodeContext::default(),
        ) {
            panic!("Origin-Realm AVP build failed: {error}");
        }
        let built = match build_message(
            peer_request_flags(PeerProcedure::DeviceWatchdog),
            COMMAND_DEVICE_WATCHDOG,
            empty_raw_avps,
            3,
            4,
            EncodeContext::default(),
            "5.5.1",
        ) {
            Ok(message) => message,
            Err(error) => panic!("message build failed: {error}"),
        };
        let encoded = encode_owned(&built);
        let message = decode_message(&encoded);
        let result = parse_device_watchdog_request(&message, DecodeContext::default());
        assert!(matches!(
            result,
            Err(error) if matches!(error.code(), DecodeErrorCode::Structural { .. })
        ));
    }

    #[test]
    fn host_ip_address_ipv6_and_rejection_paths_are_covered() {
        let ipv6 = [0x20, 0x01, 0x0d, 0xb8, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        let mut capabilities = sample_capabilities();
        capabilities.host_ip_addresses = vec![HostIpAddress::ipv6(ipv6)];
        let built = match build_capabilities_exchange_request(
            &capabilities,
            0x33,
            0x44,
            EncodeContext::default(),
        ) {
            Ok(message) => message,
            Err(error) => panic!("CER build failed: {error}"),
        };
        let encoded = encode_owned(&built);
        let message = decode_message(&encoded);
        let parsed = match parse_capabilities_exchange_request(&message, DecodeContext::default()) {
            Ok(parsed) => parsed,
            Err(error) => panic!("CER parse failed: {error}"),
        };
        assert_eq!(parsed.host_ip_addresses, vec![HostIpAddress::ipv6(ipv6)]);

        let wrong_ipv4_length = HostIpAddress::decode_value(&[0, 1, 192, 0, 2], 10);
        assert!(matches!(
            wrong_ipv4_length,
            Err(error) if matches!(error.code(), DecodeErrorCode::InvalidLength { .. })
        ));
        let unknown_family = HostIpAddress::decode_value(&[0, 99, 1, 2], 10);
        assert!(matches!(
            unknown_family,
            Err(error) if matches!(
                error.code(),
                DecodeErrorCode::InvalidEnumValue {
                    field: "Host-IP-Address AddressType",
                    value: 99
                }
            )
        ));
        let missing_family = HostIpAddress::decode_value(&[0], 10);
        assert!(matches!(
            missing_family,
            Err(error) if matches!(error.code(), DecodeErrorCode::InvalidLength { .. })
        ));
    }

    #[test]
    fn parser_rejects_unknown_mandatory_avp() {
        let identity = PeerIdentity::new("aaa4.example.net", "example.net");
        let mut raw_avps = BytesMut::new();
        if let Err(error) = append_identity_avps(&mut raw_avps, &identity, EncodeContext::default())
        {
            panic!("identity AVP build failed: {error}");
        }
        if let Err(error) = append_avp(
            &mut raw_avps,
            AvpHeader::ietf(AvpCode::new(9_999), true),
            b"x",
            EncodeContext::default(),
        ) {
            panic!("unknown AVP build failed: {error}");
        }
        let built = match build_message(
            peer_request_flags(PeerProcedure::DeviceWatchdog),
            COMMAND_DEVICE_WATCHDOG,
            raw_avps,
            1,
            2,
            EncodeContext::default(),
            "5.5.1",
        ) {
            Ok(message) => message,
            Err(error) => panic!("message build failed: {error}"),
        };
        let encoded = encode_owned(&built);
        let message = decode_message(&encoded);
        let result = parse_device_watchdog_request(&message, DecodeContext::default());
        assert!(matches!(
            result,
            Err(error) if matches!(error.code(), DecodeErrorCode::UnknownCriticalIe)
        ));
    }

    #[test]
    fn typed_parser_policy_accepts_or_rejects_unknown_non_mandatory_avp() {
        let identity = PeerIdentity::new("aaa4.example.net", "example.net");
        let mut raw_avps = BytesMut::new();
        if let Err(error) = append_identity_avps(&mut raw_avps, &identity, EncodeContext::default())
        {
            panic!("identity AVP build failed: {error}");
        }
        if let Err(error) = append_avp(
            &mut raw_avps,
            AvpHeader::ietf(AvpCode::new(9_999), false),
            b"x",
            EncodeContext::default(),
        ) {
            panic!("unknown AVP build failed: {error}");
        }
        let built = match build_message(
            peer_request_flags(PeerProcedure::DeviceWatchdog),
            COMMAND_DEVICE_WATCHDOG,
            raw_avps,
            1,
            2,
            EncodeContext::default(),
            "5.5.1",
        ) {
            Ok(message) => message,
            Err(error) => panic!("message build failed: {error}"),
        };
        let encoded = encode_owned(&built);
        let message = decode_message(&encoded);

        for policy in [UnknownIePolicy::Drop, UnknownIePolicy::Preserve] {
            let ctx = DecodeContext {
                unknown_ie_policy: policy,
                ..DecodeContext::default()
            };
            let parsed = parse_device_watchdog_request(&message, ctx);
            assert!(
                parsed.is_ok(),
                "typed parser must accept non-mandatory unknown AVP under {policy:?}, got {parsed:?}"
            );
        }

        let reject = DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Reject,
            ..DecodeContext::default()
        };
        let rejected = parse_device_watchdog_request(&message, reject);
        assert!(matches!(
            rejected,
            Err(error) if matches!(error.code(), DecodeErrorCode::UnknownCriticalIe)
        ));
    }

    #[test]
    fn parser_rejects_depth_limit_for_vendor_specific_application_id() {
        let capabilities = sample_capabilities();
        let built = match build_capabilities_exchange_request(
            &capabilities,
            1,
            2,
            EncodeContext::default(),
        ) {
            Ok(message) => message,
            Err(error) => panic!("CER build failed: {error}"),
        };
        let encoded = encode_owned(&built);
        let message = decode_message(&encoded);
        let shallow = DecodeContext {
            max_depth: 0,
            validation_level: ValidationLevel::Strict,
            ..DecodeContext::default()
        };
        let result = parse_capabilities_exchange_request(&message, shallow);
        assert!(matches!(
            result,
            Err(error) if matches!(error.code(), DecodeErrorCode::DepthExceeded)
        ));
    }

    #[test]
    fn parser_rejects_disconnect_cause_enum_outside_rfc_range() {
        let identity = PeerIdentity::new("aaa5.example.net", "example.net");
        let mut raw_avps = BytesMut::new();
        if let Err(error) = append_identity_avps(&mut raw_avps, &identity, EncodeContext::default())
        {
            panic!("identity AVP build failed: {error}");
        }
        if let Err(error) = append_u32_avp(
            &mut raw_avps,
            AVP_DISCONNECT_CAUSE,
            9,
            true,
            EncodeContext::default(),
        ) {
            panic!("Disconnect-Cause AVP build failed: {error}");
        }
        let built = match build_message(
            peer_request_flags(PeerProcedure::DisconnectPeer),
            COMMAND_DISCONNECT_PEER,
            raw_avps,
            1,
            2,
            EncodeContext::default(),
            "5.4.1",
        ) {
            Ok(message) => message,
            Err(error) => panic!("message build failed: {error}"),
        };
        let encoded = encode_owned(&built);
        let message = decode_message(&encoded);
        let result = parse_disconnect_peer_request(&message, DecodeContext::default());
        assert!(matches!(
            result,
            Err(error) if matches!(
                error.code(),
                DecodeErrorCode::InvalidEnumValue {
                    field: "Disconnect-Cause",
                    value: 9
                }
            )
        ));
    }

    #[test]
    fn parser_rejects_reserved_flags_in_procedure_avps_under_strict_validation() {
        let avp_with_reserved_flag = [
            0,
            0,
            1,
            8,
            AvpFlags::MANDATORY | 0x01,
            0,
            0,
            AVP_HEADER_LEN as u8,
        ];
        let built = match build_message(
            peer_request_flags(PeerProcedure::DeviceWatchdog),
            COMMAND_DEVICE_WATCHDOG,
            BytesMut::from(&avp_with_reserved_flag[..]),
            1,
            2,
            EncodeContext::default(),
            "5.5.1",
        ) {
            Ok(message) => message,
            Err(error) => panic!("message build failed: {error}"),
        };
        let encoded = encode_owned(&built);
        // Decode through the normal Message::decode path so the test tracks the
        // code path callers use, while keeping the strict validation inside the
        // procedure parser rather than the top-level AVP validator.
        let message = decode_message(&encoded);
        let result = parse_device_watchdog_request(&message, DecodeContext::conservative());
        assert!(matches!(
            result,
            Err(error) if matches!(
                error.code(),
                DecodeErrorCode::Structural {
                    reason: "diameter AVP reserved flag bits must be zero"
                }
            )
        ));
    }

    #[test]
    fn vendor_specific_application_requires_exactly_one_vendor_id() {
        let mut multi_vendor =
            VendorSpecificApplication::auth(VendorId::new(10415), ApplicationId::new(16_777_251));
        multi_vendor.vendor_ids.push(VendorId::new(123));

        let mut capabilities = sample_capabilities();
        capabilities.vendor_specific_applications = vec![multi_vendor];
        let build_result = build_capabilities_exchange_request(
            &capabilities,
            0x0102_0304,
            0x0506_0708,
            EncodeContext::default(),
        );
        assert!(matches!(
            build_result,
            Err(error) if matches!(error.code(), EncodeErrorCode::Structural { .. })
        ));

        let identity = PeerIdentity::new("aaa-vsai.example.net", "example.net");
        let mut raw_avps = BytesMut::new();
        if let Err(error) = append_identity_avps(&mut raw_avps, &identity, EncodeContext::default())
        {
            panic!("identity AVP build failed: {error}");
        }
        if let Err(error) = append_address_avp(
            &mut raw_avps,
            HostIpAddress::ipv4([192, 0, 2, 1]),
            EncodeContext::default(),
        ) {
            panic!("Host-IP-Address AVP build failed: {error}");
        }
        if let Err(error) = append_u32_avp(
            &mut raw_avps,
            AVP_VENDOR_ID,
            10415,
            true,
            EncodeContext::default(),
        ) {
            panic!("Vendor-Id AVP build failed: {error}");
        }
        if let Err(error) = append_utf8_avp(
            &mut raw_avps,
            AVP_PRODUCT_NAME,
            "test",
            false,
            EncodeContext::default(),
        ) {
            panic!("Product-Name AVP build failed: {error}");
        }

        let mut vsai_value = BytesMut::new();
        if let Err(error) = append_u32_avp(
            &mut vsai_value,
            AVP_VENDOR_ID,
            10415,
            true,
            EncodeContext::default(),
        ) {
            panic!("nested Vendor-Id AVP build failed: {error}");
        }
        if let Err(error) = append_u32_avp(
            &mut vsai_value,
            AVP_VENDOR_ID,
            123,
            true,
            EncodeContext::default(),
        ) {
            panic!("duplicate nested Vendor-Id AVP build failed: {error}");
        }
        if let Err(error) = append_u32_avp(
            &mut vsai_value,
            AVP_AUTH_APPLICATION_ID,
            16_777_251,
            true,
            EncodeContext::default(),
        ) {
            panic!("nested Auth-Application-Id AVP build failed: {error}");
        }
        if let Err(error) = append_avp(
            &mut raw_avps,
            AvpHeader::ietf(AVP_VENDOR_SPECIFIC_APPLICATION_ID, true),
            &vsai_value,
            EncodeContext::default(),
        ) {
            panic!("Vendor-Specific-Application-Id AVP build failed: {error}");
        }

        let built = match build_message(
            peer_request_flags(PeerProcedure::CapabilitiesExchange),
            COMMAND_CAPABILITIES_EXCHANGE,
            raw_avps,
            0x10,
            0x20,
            EncodeContext::default(),
            "5.3.1",
        ) {
            Ok(message) => message,
            Err(error) => panic!("CER build failed: {error}"),
        };
        let encoded = encode_owned(&built);
        let message = decode_message(&encoded);
        let parse_result = parse_capabilities_exchange_request(&message, DecodeContext::default());
        assert!(matches!(
            parse_result,
            Err(error) if matches!(error.code(), DecodeErrorCode::DuplicateIe)
        ));
    }

    #[test]
    fn parser_rejects_base_dictionary_flag_violations_in_procedure_avps() {
        let identity = PeerIdentity::new("aaa-flags.example.net", "example.net");

        // Origin-Host without the M bit.
        let mut origin_host_missing_m = BytesMut::new();
        if let Err(error) = append_avp(
            &mut origin_host_missing_m,
            AvpHeader::ietf(AVP_ORIGIN_HOST, false).with_flags(AvpFlags::new(false, false, false)),
            identity.origin_host.as_bytes(),
            EncodeContext::default(),
        ) {
            panic!("Origin-Host AVP build failed: {error}");
        }
        if let Err(error) = append_utf8_avp(
            &mut origin_host_missing_m,
            AVP_ORIGIN_REALM,
            &identity.origin_realm,
            true,
            EncodeContext::default(),
        ) {
            panic!("Origin-Realm AVP build failed: {error}");
        }
        let built = match build_message(
            peer_request_flags(PeerProcedure::DeviceWatchdog),
            COMMAND_DEVICE_WATCHDOG,
            origin_host_missing_m,
            1,
            2,
            EncodeContext::default(),
            "5.5.1",
        ) {
            Ok(message) => message,
            Err(error) => panic!("message build failed: {error}"),
        };
        let encoded = encode_owned(&built);
        let message = decode_message(&encoded);
        let result = parse_device_watchdog_request(&message, DecodeContext::default());
        assert!(matches!(
            result,
            Err(error) if matches!(
                error.code(),
                DecodeErrorCode::Structural {
                    reason: "diameter AVP M-bit must be set per dictionary"
                }
            )
        ));

        // Product-Name with the M bit set.
        let mut product_name_with_m = BytesMut::new();
        if let Err(error) = append_identity_avps(
            &mut product_name_with_m,
            &identity,
            EncodeContext::default(),
        ) {
            panic!("identity AVP build failed: {error}");
        }
        if let Err(error) = append_address_avp(
            &mut product_name_with_m,
            HostIpAddress::ipv4([192, 0, 2, 1]),
            EncodeContext::default(),
        ) {
            panic!("Host-IP-Address AVP build failed: {error}");
        }
        if let Err(error) = append_u32_avp(
            &mut product_name_with_m,
            AVP_VENDOR_ID,
            10415,
            true,
            EncodeContext::default(),
        ) {
            panic!("Vendor-Id AVP build failed: {error}");
        }
        if let Err(error) = append_avp(
            &mut product_name_with_m,
            AvpHeader::ietf(AVP_PRODUCT_NAME, false).with_flags(AvpFlags::new(false, true, false)),
            b"opc-diameter-test",
            EncodeContext::default(),
        ) {
            panic!("Product-Name AVP build failed: {error}");
        }
        let built = match build_message(
            peer_request_flags(PeerProcedure::CapabilitiesExchange),
            COMMAND_CAPABILITIES_EXCHANGE,
            product_name_with_m,
            1,
            2,
            EncodeContext::default(),
            "5.3.1",
        ) {
            Ok(message) => message,
            Err(error) => panic!("message build failed: {error}"),
        };
        let encoded = encode_owned(&built);
        let message = decode_message(&encoded);
        let result = parse_capabilities_exchange_request(&message, DecodeContext::default());
        assert!(matches!(
            result,
            Err(error) if matches!(
                error.code(),
                DecodeErrorCode::Structural {
                    reason: "diameter AVP M-bit must not be set per dictionary"
                }
            )
        ));

        // Error-Message with the P bit set.
        let mut error_message_with_p = BytesMut::new();
        if let Err(error) = append_u32_avp(
            &mut error_message_with_p,
            AVP_RESULT_CODE,
            RESULT_CODE_DIAMETER_SUCCESS,
            true,
            EncodeContext::default(),
        ) {
            panic!("Result-Code AVP build failed: {error}");
        }
        if let Err(error) = append_identity_avps(
            &mut error_message_with_p,
            &identity,
            EncodeContext::default(),
        ) {
            panic!("identity AVP build failed: {error}");
        }
        if let Err(error) = append_address_avp(
            &mut error_message_with_p,
            HostIpAddress::ipv4([192, 0, 2, 1]),
            EncodeContext::default(),
        ) {
            panic!("Host-IP-Address AVP build failed: {error}");
        }
        if let Err(error) = append_u32_avp(
            &mut error_message_with_p,
            AVP_VENDOR_ID,
            10415,
            true,
            EncodeContext::default(),
        ) {
            panic!("Vendor-Id AVP build failed: {error}");
        }
        if let Err(error) = append_utf8_avp(
            &mut error_message_with_p,
            AVP_PRODUCT_NAME,
            "opc-diameter-test",
            false,
            EncodeContext::default(),
        ) {
            panic!("Product-Name AVP build failed: {error}");
        }
        if let Err(error) = append_avp(
            &mut error_message_with_p,
            AvpHeader::ietf(AVP_ERROR_MESSAGE, false).with_flags(AvpFlags::new(false, false, true)),
            b"diagnostic",
            EncodeContext::default(),
        ) {
            panic!("Error-Message AVP build failed: {error}");
        }
        let built = match build_message(
            peer_answer_flags(PeerProcedure::CapabilitiesExchange, false),
            COMMAND_CAPABILITIES_EXCHANGE,
            error_message_with_p,
            1,
            2,
            EncodeContext::default(),
            "5.3.2",
        ) {
            Ok(message) => message,
            Err(error) => panic!("message build failed: {error}"),
        };
        let encoded = encode_owned(&built);
        let message = decode_message(&encoded);
        let result = parse_capabilities_exchange_answer(&message, DecodeContext::default());
        assert!(matches!(
            result,
            Err(error) if matches!(
                error.code(),
                DecodeErrorCode::Structural {
                    reason: "diameter AVP P-bit must not be set per dictionary"
                }
            )
        ));
    }

    #[test]
    fn error_answer_guards_reject_invalid_result_codes_and_missing_error_flag() {
        let identity = PeerIdentity::new("aaa-err.example.net", "example.net");

        let success_error_answer = CapabilitiesExchangeErrorAnswer {
            result_code: RESULT_CODE_DIAMETER_SUCCESS,
            identity: identity.clone(),
            diagnostics: AnswerDiagnostics::default(),
        };
        let build_result = build_capabilities_exchange_error_answer(
            &success_error_answer,
            0x1111_1111,
            0x2222_2222,
            EncodeContext::default(),
        );
        assert!(matches!(
            build_result,
            Err(error) if matches!(error.code(), EncodeErrorCode::Structural { .. })
        ));

        let valid_error_answer = CapabilitiesExchangeErrorAnswer {
            result_code: RESULT_CODE_DIAMETER_COMMAND_UNSUPPORTED,
            identity: identity.clone(),
            diagnostics: AnswerDiagnostics::default(),
        };
        let built = match build_capabilities_exchange_error_answer(
            &valid_error_answer,
            0x1111_1111,
            0x2222_2222,
            EncodeContext::default(),
        ) {
            Ok(message) => message,
            Err(error) => panic!("valid error answer build failed: {error}"),
        };
        let mut encoded = BytesMut::from(encode_owned(&built));
        encoded[4] &= !CommandFlags::ERROR;
        let message = decode_message(&encoded);
        let parse_result =
            parse_capabilities_exchange_error_answer(&message, DecodeContext::default());
        assert!(matches!(
            parse_result,
            Err(error) if matches!(
                error.code(),
                DecodeErrorCode::Structural {
                    reason: "diameter CEA error answer requires the error flag"
                }
            )
        ));

        let mut raw_avps = BytesMut::new();
        if let Err(error) = append_u32_avp(
            &mut raw_avps,
            AVP_RESULT_CODE,
            RESULT_CODE_DIAMETER_NO_COMMON_APPLICATION,
            true,
            EncodeContext::default(),
        ) {
            panic!("Result-Code AVP build failed: {error}");
        }
        if let Err(error) = append_identity_avps(&mut raw_avps, &identity, EncodeContext::default())
        {
            panic!("identity AVP build failed: {error}");
        }
        let built = match build_message(
            peer_answer_flags(PeerProcedure::CapabilitiesExchange, true),
            COMMAND_CAPABILITIES_EXCHANGE,
            raw_avps,
            0x1111_1111,
            0x2222_2222,
            EncodeContext::default(),
            "7.2",
        ) {
            Ok(message) => message,
            Err(error) => panic!("error answer build failed: {error}"),
        };
        let encoded = encode_owned(&built);
        let message = decode_message(&encoded);
        let parse_result =
            parse_capabilities_exchange_error_answer(&message, DecodeContext::default());
        assert!(matches!(
            parse_result,
            Err(error) if matches!(
                error.code(),
                DecodeErrorCode::Structural {
                    reason: "diameter CEA error answer Result-Code must be a protocol-error value"
                }
            )
        ));
    }

    #[test]
    fn vendor_avp_with_base_code_collision_is_not_flag_validated() {
        let identity = PeerIdentity::new("aaa-vendor.example.net", "example.net");
        let mut raw_avps = BytesMut::new();
        if let Err(error) = append_identity_avps(&mut raw_avps, &identity, EncodeContext::default())
        {
            panic!("identity AVP build failed: {error}");
        }
        // A vendor-specific AVP whose code collides with Origin-Host (264) and
        // deliberately violates the base dictionary's M-bit rule. Under a
        // permissive unknown-IE policy it must be ignored, not rejected by the
        // base dictionary's V-bit/M-bit rules.
        if let Err(error) = append_avp(
            &mut raw_avps,
            AvpHeader::vendor(AVP_ORIGIN_HOST, VendorId::new(12345), false),
            b"vendor.example.net",
            EncodeContext::default(),
        ) {
            panic!("vendor Origin-Host AVP build failed: {error}");
        }
        let built = match build_message(
            peer_request_flags(PeerProcedure::DeviceWatchdog),
            COMMAND_DEVICE_WATCHDOG,
            raw_avps,
            1,
            2,
            EncodeContext::default(),
            "5.5.1",
        ) {
            Ok(message) => message,
            Err(error) => panic!("message build failed: {error}"),
        };
        let encoded = encode_owned(&built);
        let message = decode_message(&encoded);
        let result = parse_device_watchdog_request(&message, DecodeContext::default());
        assert!(
            result.is_ok(),
            "expected vendor AVP to be ignored, got {result:?}"
        );
    }

    #[test]
    fn vendor_specific_application_missing_vendor_id_reports_grouped_offset() {
        let identity = PeerIdentity::new("h.example.net", "example.net");
        let mut raw_avps = BytesMut::new();
        if let Err(error) = append_identity_avps(&mut raw_avps, &identity, EncodeContext::default())
        {
            panic!("identity AVP build failed: {error}");
        }
        if let Err(error) = append_address_avp(
            &mut raw_avps,
            HostIpAddress::ipv4([192, 0, 2, 1]),
            EncodeContext::default(),
        ) {
            panic!("Host-IP-Address AVP build failed: {error}");
        }
        if let Err(error) = append_u32_avp(
            &mut raw_avps,
            AVP_VENDOR_ID,
            10415,
            true,
            EncodeContext::default(),
        ) {
            panic!("Vendor-Id AVP build failed: {error}");
        }
        if let Err(error) = append_utf8_avp(
            &mut raw_avps,
            AVP_PRODUCT_NAME,
            "test",
            false,
            EncodeContext::default(),
        ) {
            panic!("Product-Name AVP build failed: {error}");
        }

        // Grouped VSAI containing only Auth-Application-Id; nested Vendor-Id is missing.
        let mut vsai_value = BytesMut::new();
        if let Err(error) = append_u32_avp(
            &mut vsai_value,
            AVP_AUTH_APPLICATION_ID,
            16_777_251,
            true,
            EncodeContext::default(),
        ) {
            panic!("nested Auth-Application-Id AVP build failed: {error}");
        }
        if let Err(error) = append_avp(
            &mut raw_avps,
            AvpHeader::ietf(AVP_VENDOR_SPECIFIC_APPLICATION_ID, true),
            &vsai_value,
            EncodeContext::default(),
        ) {
            panic!("Vendor-Specific-Application-Id AVP build failed: {error}");
        }

        let built = match build_message(
            peer_request_flags(PeerProcedure::CapabilitiesExchange),
            COMMAND_CAPABILITIES_EXCHANGE,
            raw_avps,
            0x10,
            0x20,
            EncodeContext::default(),
            "5.3.1",
        ) {
            Ok(message) => message,
            Err(error) => panic!("CER build failed: {error}"),
        };
        let encoded = encode_owned(&built);
        let message = decode_message(&encoded);
        match parse_capabilities_exchange_request(&message, DecodeContext::default()) {
            Ok(_) => panic!("expected missing nested Vendor-Id to fail"),
            Err(error) => {
                assert!(matches!(error.code(), DecodeErrorCode::Structural { .. }));
                // Error offset must point at the grouped VSAI value, not the Diameter message header.
                // 20 (header) + 24 (Origin-Host) + 20 (Origin-Realm) + 16 (Host-IP-Address)
                // + 12 (Vendor-Id) + 12 (Product-Name) + 8 (VSAI AVP header) = 112.
                assert_eq!(error.offset(), 112);
            }
        }
    }
}
