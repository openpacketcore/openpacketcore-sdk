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
use std::num::NonZeroU64;
use std::str;
use std::sync::Arc;

use bytes::{BufMut, Bytes, BytesMut};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeError, DecodeErrorCode, Encode, EncodeContext, EncodeError,
    EncodeErrorCode, SpecRef, UnknownIePolicy,
};

use crate::base::{
    self, APPLICATION_ID_COMMON_MESSAGES, APPLICATION_ID_RELAY, AVP_ACCT_APPLICATION_ID,
    AVP_AUTH_APPLICATION_ID, AVP_DISCONNECT_CAUSE, AVP_ERROR_MESSAGE, AVP_FAILED_AVP,
    AVP_FIRMWARE_REVISION, AVP_HOST_IP_ADDRESS, AVP_INBAND_SECURITY_ID, AVP_ORIGIN_HOST,
    AVP_ORIGIN_REALM, AVP_ORIGIN_STATE_ID, AVP_PRODUCT_NAME, AVP_RESULT_CODE,
    AVP_SUPPORTED_VENDOR_ID, AVP_VENDOR_ID, AVP_VENDOR_SPECIFIC_APPLICATION_ID,
    COMMAND_CAPABILITIES_EXCHANGE, COMMAND_DEVICE_WATCHDOG, COMMAND_DISCONNECT_PEER,
    INBAND_SECURITY_ID_NO_INBAND_SECURITY, INBAND_SECURITY_ID_TLS,
    RESULT_CODE_DIAMETER_NO_COMMON_APPLICATION, RESULT_CODE_DIAMETER_NO_COMMON_SECURITY,
    RESULT_CODE_DIAMETER_SUCCESS,
};
use crate::dictionary::{CommandKind, Dictionary, DictionarySet};
use crate::parser_error::{
    DiameterGroupedAvpSetFailureKind, DiameterGroupedAvpSetProvenance, DiameterParserError,
};
use crate::{
    ApplicationId, AvpCode, AvpDefinition, AvpHeader, AvpKey, CommandCode, CommandFlags,
    FlagRequirement, Header, Message, OwnedMessage, RawAvp, VendorId, DIAMETER_HEADER_LEN, MAX_U24,
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

fn is_capabilities_header(header: &Header, kind: CommandKind) -> bool {
    is_peer_procedure_header(header, PeerProcedure::CapabilitiesExchange, kind)
}

fn is_peer_procedure_header(header: &Header, procedure: PeerProcedure, kind: CommandKind) -> bool {
    header.command_code == procedure.command_code()
        && header.application_id == APPLICATION_ID_COMMON_MESSAGES
        && header.flags.command_kind() == kind
        && !header.flags.is_proxiable()
        && (kind == CommandKind::Answer || !header.flags.is_error())
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

/// Return whether one DiameterIdentity value satisfies the SDK's shared wire
/// contract: nonempty ASCII. This intentionally does not impose a narrower
/// punctuation or DNS-label grammar.
#[must_use]
pub fn is_valid_diameter_identity(value: &str) -> bool {
    !value.is_empty() && value.is_ascii()
}

impl PeerIdentity {
    /// Create a peer identity from Origin-Host and Origin-Realm values.
    pub fn new(origin_host: impl Into<String>, origin_realm: impl Into<String>) -> Self {
        Self {
            origin_host: origin_host.into(),
            origin_realm: origin_realm.into(),
        }
    }

    /// Compare the RFC 6733 DiameterIdentity semantics of both the FQDN-like
    /// Origin-Host and realm. Wire spelling remains structurally available via
    /// the derived `Eq`/`Hash`, while authorization and peer binding must use
    /// this ASCII case-insensitive comparison.
    pub fn semantically_eq(&self, other: &Self) -> bool {
        self.origin_host.eq_ignore_ascii_case(&other.origin_host)
            && self.origin_realm.eq_ignore_ascii_case(&other.origin_realm)
    }

    fn validate_for_encode(&self, section: &'static str) -> Result<(), EncodeError> {
        if !is_valid_diameter_identity(&self.origin_host) {
            return Err(encode_structural_error(
                "diameter peer Origin-Host must be nonempty ASCII",
                section,
            ));
        }
        if !is_valid_diameter_identity(&self.origin_realm) {
            return Err(encode_structural_error(
                "diameter peer Origin-Realm must be nonempty ASCII",
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

/// Transport-protection mechanism required for a Diameter connection.
///
/// RFC 6733 `Inband-Security-Id` value 1 advertises support for both TLS/TCP
/// and DTLS/SCTP. The selected transport kind is therefore retained
/// separately from the wire capability value. `Unprotected` records the
/// explicit no-in-band-security result and never represents a protected
/// transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PeerProtectionMechanism {
    /// No in-band protection was negotiated.
    Unprotected,
    /// TLS/TCP, established either directly or after in-band negotiation.
    TlsTcp,
    /// DTLS/SCTP, established either directly or after in-band negotiation.
    DtlsSctp,
}

impl PeerProtectionMechanism {
    /// Return the corresponding RFC 6733 `Inband-Security-Id` value when this
    /// mechanism is negotiated in band.
    #[must_use]
    pub const fn inband_security_id(self) -> u32 {
        match self {
            Self::Unprotected => INBAND_SECURITY_ID_NO_INBAND_SECURITY,
            Self::TlsTcp | Self::DtlsSctp => INBAND_SECURITY_ID_TLS,
        }
    }

    /// Return whether this mechanism represents mutually authenticated
    /// transport protection after successful caller attestation.
    #[must_use]
    pub const fn is_protected(self) -> bool {
        matches!(self, Self::TlsTcp | Self::DtlsSctp)
    }

    /// Stable machine name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unprotected => "unprotected",
            Self::TlsTcp => "tls_tcp",
            Self::DtlsSctp => "dtls_sctp",
        }
    }
}

/// RFC 6733 sequencing for mutually authenticated transport protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PeerProtectionSequence {
    /// Complete protection before sending or accepting any Diameter message.
    DirectBeforeCapabilities,
    /// Negotiate protection in CER/CEA, then complete it before application
    /// traffic.
    InbandAfterCapabilities,
}

impl PeerProtectionSequence {
    /// Stable machine name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DirectBeforeCapabilities => "direct_before_capabilities",
            Self::InbandAfterCapabilities => "inband_after_capabilities",
        }
    }
}

/// Valid protected-transport requirement for one Diameter peer.
///
/// Private fields prevent constructing an unprotected or sequence-less
/// requirement. Callers select one of the four typed constructors and can then
/// inspect the retained mechanism and RFC 6733 sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerProtectionRequirement {
    mechanism: PeerProtectionMechanism,
    sequence: PeerProtectionSequence,
}

impl PeerProtectionRequirement {
    /// Require mutually authenticated TLS/TCP before CER/CEA.
    #[must_use]
    pub const fn direct_tls_tcp() -> Self {
        Self {
            mechanism: PeerProtectionMechanism::TlsTcp,
            sequence: PeerProtectionSequence::DirectBeforeCapabilities,
        }
    }

    /// Require CER/CEA-negotiated, mutually authenticated TLS/TCP.
    #[must_use]
    pub const fn inband_tls_tcp() -> Self {
        Self {
            mechanism: PeerProtectionMechanism::TlsTcp,
            sequence: PeerProtectionSequence::InbandAfterCapabilities,
        }
    }

    /// Require mutually authenticated DTLS/SCTP before CER/CEA.
    #[must_use]
    pub const fn direct_dtls_sctp() -> Self {
        Self {
            mechanism: PeerProtectionMechanism::DtlsSctp,
            sequence: PeerProtectionSequence::DirectBeforeCapabilities,
        }
    }

    /// Require CER/CEA-negotiated, mutually authenticated DTLS/SCTP.
    #[must_use]
    pub const fn inband_dtls_sctp() -> Self {
        Self {
            mechanism: PeerProtectionMechanism::DtlsSctp,
            sequence: PeerProtectionSequence::InbandAfterCapabilities,
        }
    }

    /// Return the required protected transport mechanism.
    #[must_use]
    pub const fn mechanism(self) -> PeerProtectionMechanism {
        self.mechanism
    }

    /// Return when protection must complete relative to CER/CEA.
    #[must_use]
    pub const fn sequence(self) -> PeerProtectionSequence {
        self.sequence
    }
}

/// Product-neutral protection mode applied to the peer lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PeerProtectionPolicy {
    /// Preserve the existing explicit no-in-band-security behavior. This mode
    /// never reports protected readiness and does not accept a TLS-only
    /// capability result.
    CompatibilityUnprotected,
    /// Require the typed mechanism and RFC 6733 protection sequence.
    Require(PeerProtectionRequirement),
}

impl PeerProtectionPolicy {
    /// Stable machine name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CompatibilityUnprotected => "compatibility_unprotected",
            Self::Require(requirement) => match (requirement.mechanism(), requirement.sequence()) {
                (
                    PeerProtectionMechanism::TlsTcp,
                    PeerProtectionSequence::DirectBeforeCapabilities,
                ) => "require_direct_tls_tcp",
                (
                    PeerProtectionMechanism::TlsTcp,
                    PeerProtectionSequence::InbandAfterCapabilities,
                ) => "require_inband_tls_tcp",
                (
                    PeerProtectionMechanism::DtlsSctp,
                    PeerProtectionSequence::DirectBeforeCapabilities,
                ) => "require_direct_dtls_sctp",
                (
                    PeerProtectionMechanism::DtlsSctp,
                    PeerProtectionSequence::InbandAfterCapabilities,
                ) => "require_inband_dtls_sctp",
                (PeerProtectionMechanism::Unprotected, _) => "invalid_protection_requirement",
            },
        }
    }

    const fn requires_generation_binding(self) -> bool {
        matches!(self, Self::Require(_))
    }

    /// Return the typed protected-transport requirement, if protection is
    /// required.
    #[must_use]
    pub const fn requirement(self) -> Option<PeerProtectionRequirement> {
        match self {
            Self::CompatibilityUnprotected => None,
            Self::Require(requirement) => Some(requirement),
        }
    }
}

/// Opaque generation of one logical Diameter transport connection.
///
/// The transport allocates a process-unique, monotonically increasing nonzero
/// value for every connection candidate, including both sides of a
/// simultaneous-open race. The value is redacted from diagnostics so it cannot
/// become a high-cardinality label.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerSessionGeneration(NonZeroU64);

impl PeerSessionGeneration {
    /// Wrap one transport-owned, process-unique connection generation.
    #[must_use]
    pub const fn new(value: NonZeroU64) -> Self {
        Self(value)
    }
}

impl fmt::Debug for PeerSessionGeneration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PeerSessionGeneration(<redacted>)")
    }
}

/// Opaque generation of one protection establishment attempt.
///
/// Values are scoped to a [`PeerSessionGeneration`] and are not credentials or
/// transport keying material.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerProtectionGeneration(NonZeroU64);

impl fmt::Debug for PeerProtectionGeneration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PeerProtectionGeneration(<redacted>)")
    }
}

/// Error returned when capability evidence is presented on the wrong logical
/// Diameter connection generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PeerSessionBindingError {
    /// The binding belongs to an earlier connection generation.
    StaleGeneration,
    /// A new connection generation did not advance monotonically.
    GenerationNotAdvanced,
}

impl PeerSessionBindingError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StaleGeneration => "diameter_peer_binding_stale_generation",
            Self::GenerationNotAdvanced => "diameter_peer_binding_generation_not_advanced",
        }
    }
}

impl fmt::Display for PeerSessionBindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for PeerSessionBindingError {}

/// Opaque, request-like fact authorizing completion of the current protection
/// attempt.
///
/// The token is bound to one logical [`PeerSession`] instance, its current
/// connection generation, the current protection generation, and the selected
/// mechanism. A token retained across reconnect or a replacement negotiation
/// cannot complete the new attempt.
#[derive(Clone)]
pub struct PeerProtectionPending {
    authority: Arc<PeerSessionAuthority>,
    session_generation: PeerSessionGeneration,
    protection_generation: PeerProtectionGeneration,
    mechanism: PeerProtectionMechanism,
    sequence: PeerProtectionSequence,
}

impl PartialEq for PeerProtectionPending {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.authority, &other.authority)
            && self.session_generation == other.session_generation
            && self.protection_generation == other.protection_generation
            && self.mechanism == other.mechanism
            && self.sequence == other.sequence
    }
}

impl Eq for PeerProtectionPending {}

impl PeerProtectionPending {
    /// Return the logical connection generation bound to this attempt.
    #[must_use]
    pub const fn session_generation(&self) -> PeerSessionGeneration {
        self.session_generation
    }

    /// Return the protection-attempt generation.
    #[must_use]
    pub const fn protection_generation(&self) -> PeerProtectionGeneration {
        self.protection_generation
    }

    /// Return the negotiated protection mechanism.
    #[must_use]
    pub const fn mechanism(&self) -> PeerProtectionMechanism {
        self.mechanism
    }

    /// Return the RFC 6733 sequencing bound to this attempt.
    #[must_use]
    pub const fn sequence(&self) -> PeerProtectionSequence {
        self.sequence
    }
}

impl fmt::Debug for PeerProtectionPending {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerProtectionPending")
            .field("session_generation", &self.session_generation)
            .field("protection_generation", &self.protection_generation)
            .field("mechanism", &self.mechanism)
            .field("sequence", &self.sequence)
            .finish()
    }
}

/// Redaction-safe evidence that the caller attested mutually authenticated
/// protection for an exact pending attempt.
///
/// This is state-machine evidence, not a certificate, channel binding, or
/// cryptographic proof. The transport implementation remains responsible for
/// verifying the TLS peer before invoking the attestation method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerProtectionEvidence {
    session_generation: PeerSessionGeneration,
    protection_generation: PeerProtectionGeneration,
    mechanism: PeerProtectionMechanism,
    sequence: PeerProtectionSequence,
}

impl PeerProtectionEvidence {
    /// Return the logical connection generation covered by the evidence.
    #[must_use]
    pub const fn session_generation(self) -> PeerSessionGeneration {
        self.session_generation
    }

    /// Return the protection-attempt generation covered by the evidence.
    #[must_use]
    pub const fn protection_generation(self) -> PeerProtectionGeneration {
        self.protection_generation
    }

    /// Return the attested protection mechanism.
    #[must_use]
    pub const fn mechanism(self) -> PeerProtectionMechanism {
        self.mechanism
    }

    /// Return the RFC 6733 sequence used to establish this protection.
    #[must_use]
    pub const fn sequence(self) -> PeerProtectionSequence {
        self.sequence
    }

    /// Return whether this evidence represents mutually authenticated
    /// protected readiness.
    #[must_use]
    pub const fn is_mutually_authenticated(self) -> bool {
        self.mechanism.is_protected()
    }
}

/// Typed reason that a negotiated protection attempt failed closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PeerProtectionFailure {
    /// The transport handshake failed or was interrupted.
    HandshakeFailed,
    /// The transport peer did not pass mutual identity authentication.
    PeerAuthenticationFailed,
    /// A capability update attempted to replace required protection with an
    /// unprotected or contradictory mechanism.
    DowngradeRejected,
    /// Protection policy selected a mechanism this boundary cannot attest.
    UnsupportedMechanism,
    /// Protected-session evidence arrived through a legacy,
    /// generation-unbound control method.
    UnboundCapabilityEvidence,
    /// A hostile command was presented before protection became ready.
    CommandBeforeProtection,
    /// A bounded generation counter was exhausted.
    GenerationExhausted,
    /// The surrounding peer session failed for another reason.
    SessionFailed,
}

impl PeerProtectionFailure {
    /// Stable machine-readable failure code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HandshakeFailed => "diameter_peer_protection_handshake_failed",
            Self::PeerAuthenticationFailed => "diameter_peer_protection_peer_authentication_failed",
            Self::DowngradeRejected => "diameter_peer_protection_downgrade_rejected",
            Self::UnsupportedMechanism => "diameter_peer_protection_mechanism_unsupported",
            Self::UnboundCapabilityEvidence => {
                "diameter_peer_protection_capability_evidence_unbound"
            }
            Self::CommandBeforeProtection => "diameter_peer_command_before_protection_ready",
            Self::GenerationExhausted => "diameter_peer_protection_generation_exhausted",
            Self::SessionFailed => "diameter_peer_protection_session_failed",
        }
    }
}

/// Typed protection lifecycle projected by [`PeerSession`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PeerProtectionState {
    /// Capability negotiation has not selected an in-band protection result.
    NotNegotiated,
    /// No in-band protection was selected; application traffic may follow the
    /// existing explicit-unprotected behavior but protected readiness is false.
    Unprotected,
    /// A direct or in-band protected mechanism is awaiting caller attestation.
    Pending,
    /// The current protection generation was attested as mutually authenticated.
    Protected,
    /// Protection failed closed.
    Failed,
}

impl PeerProtectionState {
    /// Stable machine name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotNegotiated => "not_negotiated",
            Self::Unprotected => "unprotected",
            Self::Pending => "pending",
            Self::Protected => "protected",
            Self::Failed => "failed",
        }
    }
}

/// Redaction-safe protection readiness for a Diameter peer session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerProtectionReadiness {
    /// Current protection lifecycle state.
    state: PeerProtectionState,
    /// Negotiated mechanism, when one was selected.
    mechanism: Option<PeerProtectionMechanism>,
    /// RFC 6733 protection sequence, when protection is required.
    sequence: Option<PeerProtectionSequence>,
    /// Current logical connection generation.
    session_generation: Option<PeerSessionGeneration>,
    /// Current protection-attempt generation, when one exists.
    protection_generation: Option<PeerProtectionGeneration>,
    /// Whether mutually authenticated protected transport is ready.
    protected_ready: bool,
    /// Whether both the protection sequence and capability exchange permit
    /// non-CER/CEA traffic. Direct attestation alone leaves this false until
    /// CER/CEA succeeds.
    traffic_permitted: bool,
    /// Stable failure reason, when protection failed closed.
    failure: Option<PeerProtectionFailure>,
}

impl PeerProtectionReadiness {
    /// Return the current protection lifecycle state.
    #[must_use]
    pub const fn state(self) -> PeerProtectionState {
        self.state
    }

    /// Return the negotiated mechanism, when present.
    #[must_use]
    pub const fn mechanism(self) -> Option<PeerProtectionMechanism> {
        self.mechanism
    }

    /// Return the required RFC 6733 protection sequence, when present.
    #[must_use]
    pub const fn sequence(self) -> Option<PeerProtectionSequence> {
        self.sequence
    }

    /// Return the current redacted connection generation.
    #[must_use]
    pub const fn session_generation(self) -> Option<PeerSessionGeneration> {
        self.session_generation
    }

    /// Return the current redacted protection-attempt generation.
    #[must_use]
    pub const fn protection_generation(self) -> Option<PeerProtectionGeneration> {
        self.protection_generation
    }

    /// Return whether mutually authenticated SDK transport protection is ready.
    #[must_use]
    pub const fn protected_ready(self) -> bool {
        self.protected_ready
    }

    /// Return whether non-CER/CEA traffic is permitted by protection state.
    #[must_use]
    pub const fn traffic_permitted(self) -> bool {
        self.traffic_permitted
    }

    /// Return the stable failure reason, when protection failed closed.
    #[must_use]
    pub const fn failure(self) -> Option<PeerProtectionFailure> {
        self.failure
    }
}

/// Protection transition emitted after an explicit caller completion or
/// failure attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PeerProtectionEvent {
    /// Mutually authenticated TLS completion was accepted.
    Established,
    /// A current protection attempt failed closed.
    Failed,
}

impl PeerProtectionEvent {
    /// Stable machine name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Established => "established",
            Self::Failed => "failed",
        }
    }
}

/// One protection-specific transition and its resulting session readiness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerProtectionTransition {
    /// Event that caused the transition.
    event: PeerProtectionEvent,
    /// Protection state before the transition.
    previous_state: PeerProtectionState,
    /// Protection state after the transition.
    state: PeerProtectionState,
    /// Protection readiness after the transition.
    protection: PeerProtectionReadiness,
    /// Generic peer readiness after the transition.
    session: PeerSessionReadiness,
}

impl PeerProtectionTransition {
    /// Return the protection event.
    #[must_use]
    pub const fn event(&self) -> PeerProtectionEvent {
        self.event
    }

    /// Return the protection state before the event.
    #[must_use]
    pub const fn previous_state(&self) -> PeerProtectionState {
        self.previous_state
    }

    /// Return the protection state after the event.
    #[must_use]
    pub const fn state(&self) -> PeerProtectionState {
        self.state
    }

    /// Return protection readiness after the event.
    #[must_use]
    pub const fn protection(&self) -> PeerProtectionReadiness {
        self.protection
    }

    /// Return generic peer readiness after the event.
    #[must_use]
    pub const fn session(&self) -> &PeerSessionReadiness {
        &self.session
    }
}

/// Protection-attempt completion error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PeerProtectionError {
    /// The token belongs to an earlier connection generation.
    StaleSessionGeneration,
    /// The token belongs to an earlier protection attempt.
    StaleProtectionGeneration,
    /// No protection completion is pending.
    NotPending {
        /// Current protection state.
        state: PeerProtectionState,
    },
    /// The attested mechanism does not match the negotiated mechanism.
    MechanismMismatch {
        /// Negotiated mechanism.
        expected: PeerProtectionMechanism,
        /// Mechanism claimed by the caller.
        actual: PeerProtectionMechanism,
    },
}

impl PeerProtectionError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StaleSessionGeneration => "diameter_peer_protection_stale_session_generation",
            Self::StaleProtectionGeneration => {
                "diameter_peer_protection_stale_protection_generation"
            }
            Self::NotPending { .. } => "diameter_peer_protection_not_pending",
            Self::MechanismMismatch { .. } => "diameter_peer_protection_mechanism_mismatch",
        }
    }
}

impl fmt::Display for PeerProtectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaleSessionGeneration | Self::StaleProtectionGeneration => {
                f.write_str(self.as_str())
            }
            Self::NotPending { state } => {
                write!(f, "{}: state {}", self.as_str(), state.as_str())
            }
            Self::MechanismMismatch { expected, actual } => write!(
                f,
                "{}: expected {}, actual {}",
                self.as_str(),
                expected.as_str(),
                actual.as_str()
            ),
        }
    }
}

impl std::error::Error for PeerProtectionError {}

/// Diameter message direction evaluated at the peer-session boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PeerMessageDirection {
    /// Message arrived from the peer.
    Inbound,
    /// Message will be sent to the peer.
    Outbound,
}

impl PeerMessageDirection {
    /// Stable machine name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
        }
    }
}

/// Error returned by generation-bound CER/CEA handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PeerCapabilityBoundaryError {
    /// The supplied connection generation is stale.
    StaleGeneration,
    /// The Diameter header is not the required CER or CEA role.
    InvalidCapabilitiesHeader,
    /// The message does not correlate to the retained capability transaction.
    TransactionMismatch,
    /// A conflicting transaction or the opposite CER role already occupies
    /// this connection generation.
    ConflictingTransaction,
    /// The committed CEA result does not match the retained CER projection.
    AnswerOutcomeMismatch,
    /// The committed CEA security advertisement does not match local support
    /// or the selected transport mechanism.
    AnswerSecurityMismatch,
    /// The CEA error flag does not match its Result-Code family.
    AnswerErrorBitMismatch,
    /// The current session state does not accept another capability exchange.
    InvalidSessionState,
}

impl PeerCapabilityBoundaryError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StaleGeneration => "diameter_peer_capability_stale_generation",
            Self::InvalidCapabilitiesHeader => "diameter_peer_capability_invalid_header",
            Self::TransactionMismatch => "diameter_peer_capability_transaction_mismatch",
            Self::ConflictingTransaction => "diameter_peer_capability_transaction_conflict",
            Self::AnswerOutcomeMismatch => "diameter_peer_capability_answer_outcome_mismatch",
            Self::AnswerSecurityMismatch => "diameter_peer_capability_answer_security_mismatch",
            Self::AnswerErrorBitMismatch => "diameter_peer_capability_answer_error_bit_mismatch",
            Self::InvalidSessionState => "diameter_peer_capability_invalid_session_state",
        }
    }
}

impl fmt::Display for PeerCapabilityBoundaryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for PeerCapabilityBoundaryError {}

/// Error returned while preparing the exact responder CEA bytes for emission.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PeerCapabilityAnswerPreparationError {
    /// Capability state, transaction, result, or security validation failed.
    Boundary(PeerCapabilityBoundaryError),
    /// Canonical typed CEA construction or serialization failed.
    Encode(EncodeError),
}

impl PeerCapabilityAnswerPreparationError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Boundary(error) => error.as_str(),
            Self::Encode(_) => "diameter_peer_capability_answer_encode_failed",
        }
    }
}

impl fmt::Display for PeerCapabilityAnswerPreparationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Boundary(error) => error.fmt(f),
            Self::Encode(_) => f.write_str(self.as_str()),
        }
    }
}

impl std::error::Error for PeerCapabilityAnswerPreparationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Boundary(error) => Some(error),
            Self::Encode(error) => Some(error),
        }
    }
}

impl From<PeerCapabilityBoundaryError> for PeerCapabilityAnswerPreparationError {
    fn from(error: PeerCapabilityBoundaryError) -> Self {
        Self::Boundary(error)
    }
}

impl From<EncodeError> for PeerCapabilityAnswerPreparationError {
    fn from(error: EncodeError) -> Self {
        Self::Encode(error)
    }
}

/// Coarse command class evaluated by the additive peer admission boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PeerCommandClass {
    /// CER or CEA.
    CapabilitiesExchange,
    /// DWR or DWA.
    DeviceWatchdog,
    /// DPR or DPA.
    DisconnectPeer,
    /// Any non-base application command.
    Application,
}

impl PeerCommandClass {
    /// Classify a decoded Diameter header without relying on caller-supplied
    /// command labels.
    #[must_use]
    pub fn from_header(header: &Header) -> Self {
        match procedure_for_command(header.command_code) {
            Some(PeerProcedure::CapabilitiesExchange) => Self::CapabilitiesExchange,
            Some(PeerProcedure::DeviceWatchdog) => Self::DeviceWatchdog,
            Some(PeerProcedure::DisconnectPeer) => Self::DisconnectPeer,
            None => Self::Application,
        }
    }

    /// Stable machine name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CapabilitiesExchange => "capabilities_exchange",
            Self::DeviceWatchdog => "device_watchdog",
            Self::DisconnectPeer => "disconnect_peer",
            Self::Application => "application",
        }
    }
}

/// Redaction-safe successful command admission evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerCommandAdmission {
    /// Admitted command class.
    command: PeerCommandClass,
    /// Admitted message direction.
    direction: PeerMessageDirection,
    /// Logical connection generation that was admitted.
    session_generation: Option<PeerSessionGeneration>,
    /// Active protection mechanism, if policy selected one.
    mechanism: Option<PeerProtectionMechanism>,
    /// RFC 6733 protection sequence backing the admission, when required.
    sequence: Option<PeerProtectionSequence>,
    /// Protection generation covering this admission, when attested.
    protection_generation: Option<PeerProtectionGeneration>,
    /// Whether admission is backed by mutually authenticated protection.
    protected: bool,
}

impl PeerCommandAdmission {
    /// Return the admitted command class.
    #[must_use]
    pub const fn command(self) -> PeerCommandClass {
        self.command
    }

    /// Return the admitted message direction.
    #[must_use]
    pub const fn direction(self) -> PeerMessageDirection {
        self.direction
    }

    /// Return the exact redacted connection generation.
    #[must_use]
    pub const fn session_generation(self) -> Option<PeerSessionGeneration> {
        self.session_generation
    }

    /// Return the negotiated mechanism.
    #[must_use]
    pub const fn mechanism(self) -> Option<PeerProtectionMechanism> {
        self.mechanism
    }

    /// Return the RFC 6733 protection sequence backing this admission.
    #[must_use]
    pub const fn sequence(self) -> Option<PeerProtectionSequence> {
        self.sequence
    }

    /// Return the attested protection generation, when protected.
    #[must_use]
    pub const fn protection_generation(self) -> Option<PeerProtectionGeneration> {
        self.protection_generation
    }

    /// Return whether mutually authenticated SDK transport protection backs
    /// this admission.
    #[must_use]
    pub const fn is_protected(self) -> bool {
        self.protected
    }
}

/// Error returned when a command class is not admissible in the current peer
/// or protection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PeerCommandAdmissionError {
    /// The supplied connection generation is stale or unbound.
    StaleGeneration,
    /// Protection has not completed or has failed closed.
    ProtectionNotReady {
        /// Rejected command class.
        command: PeerCommandClass,
        /// Current protection state.
        protection_state: PeerProtectionState,
    },
    /// The generic peer session is not ready for this command class.
    SessionNotReady {
        /// Rejected command class.
        command: PeerCommandClass,
        /// Current peer state.
        state: PeerSessionState,
    },
}

impl PeerCommandAdmissionError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StaleGeneration => "diameter_peer_command_stale_generation",
            Self::ProtectionNotReady { .. } => "diameter_peer_command_protection_not_ready",
            Self::SessionNotReady { .. } => "diameter_peer_command_session_not_ready",
        }
    }
}

impl fmt::Display for PeerCommandAdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaleGeneration => f.write_str(self.as_str()),
            Self::ProtectionNotReady {
                command,
                protection_state,
            } => write!(
                f,
                "{}: command {}, protection state {}",
                self.as_str(),
                command.as_str(),
                protection_state.as_str()
            ),
            Self::SessionNotReady { command, state } => write!(
                f,
                "{}: command {}, session state {}",
                self.as_str(),
                command.as_str(),
                state.as_str()
            ),
        }
    }
}

impl std::error::Error for PeerCommandAdmissionError {}

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

/// Exact canonical responder CEA bytes admitted and consumed by a peer session.
///
/// Construction is available only through
/// [`PeerSession::prepare_capabilities_answer_on`]. The session consumes the
/// retained inbound CER transaction before returning this value, so a second
/// CEA cannot be prepared for the same request. The wire bytes are immutable and
/// are the only responder CEA representation admitted by the protected-session
/// boundary.
#[derive(PartialEq, Eq)]
pub struct PeerCapabilitiesAnswerEmission {
    wire: Bytes,
    readiness: PeerSessionReadiness,
}

impl fmt::Debug for PeerCapabilitiesAnswerEmission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerCapabilitiesAnswerEmission")
            .field("wire", &"<redacted>")
            .field("wire_len", &self.wire.len())
            .field("readiness", &self.readiness)
            .finish()
    }
}

impl PeerCapabilitiesAnswerEmission {
    /// Return the exact immutable CEA bytes to emit on the bound connection.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.wire
    }

    /// Consume the emission facade and return its exact immutable CEA bytes.
    #[must_use]
    pub fn into_bytes(self) -> Bytes {
        self.wire
    }

    /// Return readiness after the CEA transaction was consumed.
    #[must_use]
    pub const fn readiness(&self) -> &PeerSessionReadiness {
        &self.readiness
    }
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
    /// Whether configured in-band security policy passed, or whether that
    /// field is not applicable because direct protection already completed.
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

/// Error returned by an exact-generation peer lifecycle operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PeerSessionBoundError {
    /// The event belongs to a stale or unbound transport generation.
    StaleGeneration,
    /// The current peer state does not accept the requested operation.
    InvalidTransition {
        /// Stable operation name.
        operation: &'static str,
        /// Current peer state.
        state: PeerSessionState,
    },
    /// The exact command header was not admissible in the current peer state.
    CommandNotAdmitted {
        /// Stable lifecycle operation name.
        operation: &'static str,
        /// Typed command-admission rejection.
        reason: PeerCommandAdmissionError,
    },
    /// The supplied header does not match the lifecycle operation's Diameter
    /// procedure and request/answer role.
    InvalidPeerHeader {
        /// Stable lifecycle operation name.
        operation: &'static str,
    },
}

impl PeerSessionBoundError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StaleGeneration => "diameter_peer_lifecycle_stale_generation",
            Self::InvalidTransition { .. } => "diameter_peer_lifecycle_invalid_transition",
            Self::CommandNotAdmitted { .. } => "diameter_peer_lifecycle_command_not_admitted",
            Self::InvalidPeerHeader { .. } => "diameter_peer_lifecycle_invalid_header",
        }
    }

    fn from_session(error: PeerSessionError) -> Self {
        match error {
            PeerSessionError::InvalidTransition { operation, state } => {
                Self::InvalidTransition { operation, state }
            }
        }
    }
}

impl fmt::Display for PeerSessionBoundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaleGeneration => f.write_str(self.as_str()),
            Self::InvalidTransition { operation, state } => write!(
                f,
                "{}: operation {operation}, state {}",
                self.as_str(),
                state.as_str()
            ),
            Self::CommandNotAdmitted { operation, reason } => write!(
                f,
                "{}: operation {operation}, reason {}",
                self.as_str(),
                reason.as_str()
            ),
            Self::InvalidPeerHeader { operation } => {
                write!(f, "{}: operation {operation}", self.as_str())
            }
        }
    }
}

impl std::error::Error for PeerSessionBoundError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerProtectionLifecycle {
    NotNegotiated,
    Unprotected,
    Pending {
        generation: PeerProtectionGeneration,
        requirement: PeerProtectionRequirement,
    },
    Protected {
        evidence: PeerProtectionEvidence,
    },
    Failed {
        mechanism: Option<PeerProtectionMechanism>,
        sequence: Option<PeerProtectionSequence>,
        generation: Option<PeerProtectionGeneration>,
        failure: PeerProtectionFailure,
    },
}

#[derive(Debug)]
struct PeerSessionAuthority;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerCapabilityRole {
    Initiator,
    Responder,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct PeerCapabilityTransaction {
    hop_by_hop_identifier: u32,
    end_to_end_identifier: u32,
}

impl PeerCapabilityTransaction {
    fn from_header(header: &Header) -> Self {
        Self {
            hop_by_hop_identifier: header.hop_by_hop_identifier,
            end_to_end_identifier: header.end_to_end_identifier,
        }
    }

    fn matches(self, header: &Header) -> bool {
        self.hop_by_hop_identifier == header.hop_by_hop_identifier
            && self.end_to_end_identifier == header.end_to_end_identifier
    }
}

/// Transport-neutral Diameter peer session state machine.
pub struct PeerSession {
    authority: Arc<PeerSessionAuthority>,
    local_capabilities: PeerCapabilities,
    policy: PeerSessionPolicy,
    protection_policy: PeerProtectionPolicy,
    state: PeerSessionState,
    session_generation: Option<PeerSessionGeneration>,
    next_protection_generation: u64,
    protection: PeerProtectionLifecycle,
    capabilities_request_outstanding: bool,
    outbound_capability_transaction: Option<PeerCapabilityTransaction>,
    inbound_capability_transaction: Option<PeerCapabilityTransaction>,
    capability_role: Option<PeerCapabilityRole>,
    selected_protection: Option<PeerProtectionMechanism>,
    capability_evidence_generation_bound: bool,
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

impl Clone for PeerSession {
    fn clone(&self) -> Self {
        let protection_was_authoritative = self.protection_policy.requires_generation_binding()
            && self.session_generation.is_some();
        Self {
            authority: Arc::new(PeerSessionAuthority),
            local_capabilities: self.local_capabilities.clone(),
            policy: self.policy.clone(),
            protection_policy: self.protection_policy,
            state: if protection_was_authoritative {
                PeerSessionState::Failed
            } else {
                self.state
            },
            session_generation: self.session_generation,
            next_protection_generation: self.next_protection_generation,
            protection: if protection_was_authoritative {
                PeerProtectionLifecycle::Failed {
                    mechanism: self.protection_readiness().mechanism,
                    sequence: self.protection_readiness().sequence,
                    generation: self.protection_readiness().protection_generation,
                    failure: PeerProtectionFailure::SessionFailed,
                }
            } else {
                self.protection
            },
            capabilities_request_outstanding: if protection_was_authoritative {
                false
            } else {
                self.capabilities_request_outstanding
            },
            outbound_capability_transaction: if protection_was_authoritative {
                None
            } else {
                self.outbound_capability_transaction
            },
            inbound_capability_transaction: if protection_was_authoritative {
                None
            } else {
                self.inbound_capability_transaction
            },
            capability_role: if protection_was_authoritative {
                None
            } else {
                self.capability_role
            },
            selected_protection: if protection_was_authoritative {
                None
            } else {
                self.selected_protection
            },
            capability_evidence_generation_bound: if protection_was_authoritative {
                false
            } else {
                self.capability_evidence_generation_bound
            },
            remote_capabilities: self.remote_capabilities.clone(),
            last_capability_projection: self.last_capability_projection.clone(),
            last_watchdog_projection: self.last_watchdog_projection.clone(),
            last_disconnect_projection: self.last_disconnect_projection.clone(),
            last_blockers: if protection_was_authoritative {
                vec![PeerSessionBlocker::SessionFailed]
            } else {
                self.last_blockers.clone()
            },
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
}

impl fmt::Debug for PeerSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerSession")
            .field("state", &self.state)
            .field("protection", &self.protection_readiness())
            .field("policy", &self.policy)
            .field("protection_policy", &self.protection_policy)
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
        Self::with_policy_and_protection(
            local_capabilities,
            policy,
            PeerProtectionPolicy::CompatibilityUnprotected,
        )
    }

    /// Create a session with explicit capability and transport-protection
    /// policy.
    #[must_use]
    pub fn with_policy_and_protection(
        local_capabilities: PeerCapabilities,
        policy: PeerSessionPolicy,
        protection_policy: PeerProtectionPolicy,
    ) -> Self {
        Self {
            authority: Arc::new(PeerSessionAuthority),
            local_capabilities,
            policy,
            protection_policy,
            state: PeerSessionState::Idle,
            session_generation: None,
            next_protection_generation: 0,
            protection: PeerProtectionLifecycle::NotNegotiated,
            capabilities_request_outstanding: false,
            outbound_capability_transaction: None,
            inbound_capability_transaction: None,
            capability_role: None,
            selected_protection: None,
            capability_evidence_generation_bound: false,
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

    /// Return the exact local capabilities used by this session.
    #[must_use]
    pub const fn local_capabilities(&self) -> &PeerCapabilities {
        &self.local_capabilities
    }

    /// Return the session transport-protection policy.
    #[must_use]
    pub const fn protection_policy(&self) -> PeerProtectionPolicy {
        self.protection_policy
    }

    /// Bind this state machine to a new exact transport connection generation.
    ///
    /// The generation must be process-unique and monotonically greater than
    /// the preceding generation supplied to this session. Binding a new
    /// generation revokes all pending or established protection evidence
    /// before any readiness is reported. A direct requirement creates its
    /// pending protection token at this boundary; an in-band requirement waits
    /// for the correlated CER/CEA.
    ///
    /// # Errors
    ///
    /// Returns [`PeerSessionBindingError::GenerationNotAdvanced`] when a
    /// generation is reused or moves backwards.
    pub fn begin_connection_generation(
        &mut self,
        generation: PeerSessionGeneration,
    ) -> Result<(), PeerSessionBindingError> {
        if self
            .session_generation
            .is_some_and(|current| generation.0 <= current.0)
        {
            return Err(PeerSessionBindingError::GenerationNotAdvanced);
        }
        self.session_generation = Some(generation);
        self.next_protection_generation = 0;
        self.protection = PeerProtectionLifecycle::NotNegotiated;
        self.capabilities_request_outstanding = false;
        self.outbound_capability_transaction = None;
        self.inbound_capability_transaction = None;
        self.capability_role = None;
        self.selected_protection = None;
        self.capability_evidence_generation_bound = false;
        self.state = PeerSessionState::Idle;
        self.remote_capabilities = None;
        self.last_capability_projection = None;
        self.last_watchdog_projection = None;
        self.last_disconnect_projection = None;
        self.last_blockers.clear();
        self.missed_watchdogs = 0;
        if let Some(requirement) = self.protection_policy.requirement() {
            if requirement.sequence() == PeerProtectionSequence::DirectBeforeCapabilities {
                self.start_pending_protection(requirement);
            }
        }
        Ok(())
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

    /// Return the current typed protection readiness.
    ///
    /// `protected_ready` becomes true only after this session accepts an exact
    /// current-generation attestation for the required mutually authenticated
    /// TLS/TCP or DTLS/SCTP mechanism. `traffic_permitted` additionally requires
    /// successful CER/CEA. Explicit no-in-band-security negotiation keeps
    /// `protected_ready` false.
    #[must_use]
    pub const fn protection_readiness(&self) -> PeerProtectionReadiness {
        match self.protection {
            PeerProtectionLifecycle::NotNegotiated => PeerProtectionReadiness {
                state: PeerProtectionState::NotNegotiated,
                mechanism: None,
                sequence: match self.protection_policy.requirement() {
                    Some(requirement) => Some(requirement.sequence()),
                    None => None,
                },
                session_generation: self.session_generation,
                protection_generation: None,
                protected_ready: false,
                traffic_permitted: false,
                failure: None,
            },
            PeerProtectionLifecycle::Unprotected => PeerProtectionReadiness {
                state: PeerProtectionState::Unprotected,
                mechanism: Some(PeerProtectionMechanism::Unprotected),
                sequence: None,
                session_generation: self.session_generation,
                protection_generation: None,
                protected_ready: false,
                traffic_permitted: true,
                failure: None,
            },
            PeerProtectionLifecycle::Pending {
                generation,
                requirement,
            } => PeerProtectionReadiness {
                state: PeerProtectionState::Pending,
                mechanism: Some(requirement.mechanism()),
                sequence: Some(requirement.sequence()),
                session_generation: self.session_generation,
                protection_generation: Some(generation),
                protected_ready: false,
                traffic_permitted: false,
                failure: None,
            },
            PeerProtectionLifecycle::Protected { evidence } => PeerProtectionReadiness {
                state: PeerProtectionState::Protected,
                mechanism: Some(evidence.mechanism()),
                sequence: Some(evidence.sequence()),
                session_generation: self.session_generation,
                protection_generation: Some(evidence.protection_generation()),
                protected_ready: evidence.is_mutually_authenticated(),
                traffic_permitted: evidence.is_mutually_authenticated()
                    && matches!(
                        self.state,
                        PeerSessionState::Negotiated
                            | PeerSessionState::WatchdogProbing
                            | PeerSessionState::Degraded
                    ),
                failure: None,
            },
            PeerProtectionLifecycle::Failed {
                mechanism,
                sequence,
                generation,
                failure,
            } => PeerProtectionReadiness {
                state: PeerProtectionState::Failed,
                mechanism,
                sequence,
                session_generation: self.session_generation,
                protection_generation: generation,
                protected_ready: false,
                traffic_permitted: false,
                failure: Some(failure),
            },
        }
    }

    /// Return the opaque token for the current direct or in-band protection
    /// establishment attempt.
    #[must_use]
    pub fn pending_protection(&self) -> Option<PeerProtectionPending> {
        match (self.protection, self.session_generation) {
            (
                PeerProtectionLifecycle::Pending {
                    generation,
                    requirement,
                },
                Some(session_generation),
            ) => Some(PeerProtectionPending {
                authority: Arc::clone(&self.authority),
                session_generation,
                protection_generation: generation,
                mechanism: requirement.mechanism(),
                sequence: requirement.sequence(),
            }),
            (
                PeerProtectionLifecycle::NotNegotiated
                | PeerProtectionLifecycle::Unprotected
                | PeerProtectionLifecycle::Protected { .. }
                | PeerProtectionLifecycle::Failed { .. },
                _,
            ) => None,
            (PeerProtectionLifecycle::Pending { .. }, None) => None,
        }
    }

    /// Return accepted protection evidence for the current session generation.
    #[must_use]
    pub const fn protection_evidence(&self) -> Option<PeerProtectionEvidence> {
        match self.protection {
            PeerProtectionLifecycle::Protected { evidence } => Some(evidence),
            PeerProtectionLifecycle::NotNegotiated
            | PeerProtectionLifecycle::Unprotected
            | PeerProtectionLifecycle::Pending { .. }
            | PeerProtectionLifecycle::Failed { .. } => None,
        }
    }

    /// Attest that the exact current protection attempt completed with the
    /// selected mutually authenticated transport mechanism.
    ///
    /// The caller must invoke this only after its TLS/TCP or DTLS/SCTP
    /// implementation has completed the handshake and verified both local and
    /// remote identities. This state-machine boundary does not perform transport
    /// protection or certificate validation itself.
    ///
    /// # Errors
    ///
    /// Returns [`PeerProtectionError`] for a stale, non-pending, or wrong-
    /// mechanism token. Stale errors do not mutate current readiness. A
    /// current-attempt mechanism mismatch fails the session closed.
    pub fn attest_mutually_authenticated_protection(
        &mut self,
        pending: &PeerProtectionPending,
        mechanism: PeerProtectionMechanism,
    ) -> Result<PeerProtectionTransition, PeerProtectionError> {
        let (session_generation, generation) =
            self.validate_pending_protection(pending, mechanism)?;
        let previous_state = self.protection_readiness().state;
        let evidence = PeerProtectionEvidence {
            session_generation,
            protection_generation: generation,
            mechanism,
            sequence: pending.sequence(),
        };
        self.protection = PeerProtectionLifecycle::Protected { evidence };
        if self.capability_exchange_complete() {
            self.state = PeerSessionState::Negotiated;
            self.last_blockers.clear();
        } else {
            self.state = match pending.sequence() {
                PeerProtectionSequence::DirectBeforeCapabilities => PeerSessionState::Idle,
                PeerProtectionSequence::InbandAfterCapabilities => {
                    PeerSessionState::CapabilitiesPending
                }
            };
            self.last_blockers = vec![PeerSessionBlocker::CapabilitiesExchangePending];
        }
        Ok(self.protection_transition(PeerProtectionEvent::Established, previous_state))
    }

    /// Fail the exact current protection attempt with a stable, redaction-safe
    /// reason.
    ///
    /// # Errors
    ///
    /// Returns [`PeerProtectionError`] when the supplied token is stale or no
    /// longer pending. A rejected stale failure cannot poison the current
    /// session generation.
    pub fn fail_pending_protection(
        &mut self,
        pending: &PeerProtectionPending,
        failure: PeerProtectionFailure,
    ) -> Result<PeerProtectionTransition, PeerProtectionError> {
        let mechanism = pending.mechanism();
        let (_session_generation, generation) =
            self.validate_pending_protection(pending, mechanism)?;
        let previous_state = self.protection_readiness().state;
        self.fail_protection_lifecycle(
            Some(mechanism),
            Some(pending.sequence()),
            Some(generation),
            failure,
        );
        Ok(self.protection_transition(PeerProtectionEvent::Failed, previous_state))
    }

    /// Evaluate whether a decoded Diameter header may cross the current peer
    /// and protection boundary on an exact connection generation.
    ///
    /// Direct protection admits no Diameter bytes until attestation, then admits
    /// only CER/CEA until capability success. In-band protection admits only the
    /// correlated CER/CEA first, then no Diameter message while the selected
    /// handshake is pending.
    /// Explicitly unprotected negotiation preserves existing traffic behavior
    /// but produces admission with `protected == false`.
    ///
    /// # Errors
    ///
    /// Returns [`PeerCommandAdmissionError`] when protection or generic peer
    /// state does not admit the command.
    pub fn admit_message(
        &self,
        generation: PeerSessionGeneration,
        direction: PeerMessageDirection,
        header: &Header,
    ) -> Result<PeerCommandAdmission, PeerCommandAdmissionError> {
        if self.session_generation != Some(generation) {
            return Err(PeerCommandAdmissionError::StaleGeneration);
        }
        let command = PeerCommandClass::from_header(header);
        let protection = self.protection_readiness();
        let terminal_disconnect_answer = command == PeerCommandClass::DisconnectPeer
            && header.flags.command_kind() == CommandKind::Answer
            && match direction {
                PeerMessageDirection::Inbound => self.state == PeerSessionState::Disconnecting,
                PeerMessageDirection::Outbound => self.state == PeerSessionState::Draining,
            };
        if !terminal_disconnect_answer
            && (protection.state == PeerProtectionState::Pending
                || protection.state == PeerProtectionState::Failed)
        {
            return Err(PeerCommandAdmissionError::ProtectionNotReady {
                command,
                protection_state: protection.state,
            });
        }

        let session_ready = match command {
            PeerCommandClass::CapabilitiesExchange => {
                self.capabilities_header_is_admissible(direction, header)
            }
            PeerCommandClass::Application => self.state == PeerSessionState::Negotiated,
            PeerCommandClass::DeviceWatchdog => matches!(
                self.state,
                PeerSessionState::Negotiated
                    | PeerSessionState::WatchdogProbing
                    | PeerSessionState::Degraded
            ),
            PeerCommandClass::DisconnectPeer => match header.flags.command_kind() {
                CommandKind::Request => matches!(
                    self.state,
                    PeerSessionState::Negotiated
                        | PeerSessionState::WatchdogProbing
                        | PeerSessionState::Degraded
                ),
                CommandKind::Answer => terminal_disconnect_answer,
            },
        };
        if !session_ready {
            return Err(PeerCommandAdmissionError::SessionNotReady {
                command,
                state: self.state,
            });
        }

        Ok(PeerCommandAdmission {
            command,
            direction,
            session_generation: self.session_generation,
            mechanism: protection.mechanism,
            sequence: protection.sequence,
            protection_generation: protection.protection_generation,
            protected: protection.protected_ready,
        })
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
        let direct_protection = self
            .protection_policy
            .requirement()
            .is_some_and(|requirement| {
                requirement.sequence() == PeerProtectionSequence::DirectBeforeCapabilities
            });
        if !direct_protection && !self.policy.accepted_inband_security_ids.is_empty() {
            blockers.push(PeerSessionBlocker::AcceptedInbandSecurityMissing);
        }
        PeerSessionCapabilityProjection {
            result_code: answer.result_code,
            has_common_application: false,
            relay_application_common: false,
            accepted_application_common: false,
            accepted_inband_security_common: direct_protection,
            diagnostics_present: !answer.diagnostics.is_empty(),
            accepted: false,
            blockers,
        }
    }

    /// Mark a CER as sent.
    #[must_use]
    pub fn capabilities_request_sent(&mut self) -> PeerSessionTransition {
        if let Some(requirement) = self.protection_policy.requirement() {
            let previous = self.state;
            self.fail_protection_lifecycle(
                Some(requirement.mechanism()),
                Some(requirement.sequence()),
                self.protection_readiness().protection_generation,
                PeerProtectionFailure::UnboundCapabilityEvidence,
            );
            return self.transition(PeerSessionEvent::Failure, previous);
        }
        self.capabilities_request_sent_inner()
    }

    /// Mark an exact-generation CER as sent on the protected-session path.
    ///
    /// Retransmission with the same Diameter identifiers is accepted. A
    /// different outstanding CER on the same generation fails without
    /// replacing the retained transaction.
    ///
    /// # Errors
    ///
    /// Returns [`PeerCapabilityBoundaryError`] for a stale generation,
    /// non-CER header, or conflicting outstanding transaction.
    pub fn capabilities_request_sent_on(
        &mut self,
        generation: PeerSessionGeneration,
        header: &Header,
    ) -> Result<PeerSessionTransition, PeerCapabilityBoundaryError> {
        self.validate_capability_generation(generation)?;
        if !self.capability_phase_is_available() {
            return Err(PeerCapabilityBoundaryError::InvalidSessionState);
        }
        if !matches!(
            self.state,
            PeerSessionState::Idle | PeerSessionState::CapabilitiesPending
        ) {
            return Err(PeerCapabilityBoundaryError::InvalidSessionState);
        }
        if !is_capabilities_header(header, CommandKind::Request) {
            return Err(PeerCapabilityBoundaryError::InvalidCapabilitiesHeader);
        }
        if self.capability_role == Some(PeerCapabilityRole::Responder) {
            return Err(PeerCapabilityBoundaryError::ConflictingTransaction);
        }
        let transaction = PeerCapabilityTransaction::from_header(header);
        match self.outbound_capability_transaction {
            Some(current) if current != transaction => {
                return Err(PeerCapabilityBoundaryError::ConflictingTransaction);
            }
            Some(_) => {}
            None => {
                self.capability_role = Some(PeerCapabilityRole::Initiator);
                self.outbound_capability_transaction = Some(transaction);
            }
        }
        Ok(self.capabilities_request_sent_inner())
    }

    fn capabilities_request_sent_inner(&mut self) -> PeerSessionTransition {
        let previous = self.state;
        self.capabilities_requests_sent = self.capabilities_requests_sent.saturating_add(1);
        self.capabilities_request_outstanding = true;
        self.state = PeerSessionState::CapabilitiesPending;
        if self.inbound_capability_transaction.is_none() {
            self.remote_capabilities = None;
            self.last_capability_projection = None;
            self.selected_protection = None;
            if !self.direct_protection_is_attested() {
                self.protection = PeerProtectionLifecycle::NotNegotiated;
            }
        }
        self.last_watchdog_projection = None;
        self.last_disconnect_projection = None;
        self.last_blockers = vec![PeerSessionBlocker::CapabilitiesExchangePending];
        self.missed_watchdogs = 0;
        self.transition(PeerSessionEvent::CapabilitiesRequestSent, previous)
    }

    /// Observe a decoded CER from the peer.
    #[must_use]
    pub fn capabilities_request_received(
        &mut self,
        remote: PeerCapabilities,
    ) -> PeerSessionTransition {
        if let Some(requirement) = self.protection_policy.requirement() {
            let previous = self.state;
            self.fail_protection_lifecycle(
                Some(requirement.mechanism()),
                Some(requirement.sequence()),
                self.protection_readiness().protection_generation,
                PeerProtectionFailure::UnboundCapabilityEvidence,
            );
            return self.transition(PeerSessionEvent::Failure, previous);
        }
        self.capabilities_request_received_inner(remote, false)
    }

    /// Observe an exact-generation decoded CER on the protected-session path.
    ///
    /// The matching CEA must subsequently be committed with
    /// [`PeerSession::prepare_capabilities_answer_on`]. That commit creates an
    /// in-band protection attempt or, for already-attested direct protection,
    /// completes capability readiness. An initiator CER on this same generation
    /// is rejected; simultaneous-open election is owned by the transport facade.
    ///
    /// # Errors
    ///
    /// Returns [`PeerCapabilityBoundaryError`] for a stale generation,
    /// non-CER header, or conflicting inbound transaction.
    pub fn capabilities_request_received_on(
        &mut self,
        generation: PeerSessionGeneration,
        header: &Header,
        remote: PeerCapabilities,
    ) -> Result<PeerSessionTransition, PeerCapabilityBoundaryError> {
        self.validate_capability_generation(generation)?;
        if !self.capability_phase_is_available() {
            return Err(PeerCapabilityBoundaryError::InvalidSessionState);
        }
        if !matches!(
            self.state,
            PeerSessionState::Idle | PeerSessionState::CapabilitiesPending
        ) {
            return Err(PeerCapabilityBoundaryError::InvalidSessionState);
        }
        if !is_capabilities_header(header, CommandKind::Request) {
            return Err(PeerCapabilityBoundaryError::InvalidCapabilitiesHeader);
        }
        if self.capability_role == Some(PeerCapabilityRole::Initiator) {
            return Err(PeerCapabilityBoundaryError::ConflictingTransaction);
        }
        let transaction = PeerCapabilityTransaction::from_header(header);
        match self.inbound_capability_transaction {
            Some(current) if current != transaction => {
                return Err(PeerCapabilityBoundaryError::ConflictingTransaction);
            }
            Some(_) => {}
            None => {
                self.capability_role = Some(PeerCapabilityRole::Responder);
                self.inbound_capability_transaction = Some(transaction);
            }
        }
        Ok(self.capabilities_request_received_inner(remote, true))
    }

    fn capabilities_request_received_inner(
        &mut self,
        remote: PeerCapabilities,
        generation_bound: bool,
    ) -> PeerSessionTransition {
        let previous = self.state;
        self.capabilities_requests_received = self.capabilities_requests_received.saturating_add(1);
        let negotiated = negotiate_capabilities(&self.local_capabilities, &remote);
        let mut result_code = negotiated.cea_result_code();
        if result_code == RESULT_CODE_DIAMETER_SUCCESS
            && !self.protection_security_is_common(&negotiated)
        {
            result_code = RESULT_CODE_DIAMETER_NO_COMMON_SECURITY;
        }
        let projection = self.project_capabilities(result_code, &remote, false);
        self.remote_capabilities = Some(remote.clone());
        self.apply_capability_projection(projection, &remote, generation_bound);
        self.transition(PeerSessionEvent::CapabilitiesRequestReceived, previous)
    }

    /// Prepare and consume the exact matching CEA for a generation-bound CER.
    ///
    /// This is the sole responder-side emission boundary. It validates the
    /// typed Result-Code and, for in-band protection, security advertisement;
    /// canonically builds and serializes the CEA with the retained request
    /// identifiers; and consumes the inbound transaction before returning
    /// immutable bytes. Direct protection parses but does not negotiate
    /// `Inband-Security-Id`. Callers emit
    /// only [`PeerCapabilitiesAnswerEmission::as_bytes`]; header-only outbound
    /// CEA admission is deliberately unavailable.
    ///
    /// # Errors
    ///
    /// Returns [`PeerCapabilityAnswerPreparationError`] for a stale generation,
    /// missing transaction, contradictory typed answer content, or canonical
    /// construction/serialization failure. A failed preparation does not consume
    /// the request, while a successful preparation is one-shot.
    pub fn prepare_capabilities_answer_on(
        &mut self,
        generation: PeerSessionGeneration,
        answer: &CapabilitiesExchangeAnswer,
        ctx: EncodeContext,
    ) -> Result<PeerCapabilitiesAnswerEmission, PeerCapabilityAnswerPreparationError> {
        self.validate_capability_generation(generation)?;
        let Some(transaction) = self.inbound_capability_transaction else {
            return Err(PeerCapabilityBoundaryError::TransactionMismatch.into());
        };
        self.validate_capabilities_answer_commit(answer)?;
        let message = build_capabilities_exchange_answer(
            answer,
            transaction.hop_by_hop_identifier,
            transaction.end_to_end_identifier,
            ctx,
        )?;
        self.validate_capabilities_answer_error_bit(&message.header, answer.result_code)?;
        let mut wire = BytesMut::new();
        message.encode(&mut wire, ctx)?;

        self.inbound_capability_transaction = None;
        if self.state != PeerSessionState::Failed {
            self.finish_capability_phase();
        }
        Ok(PeerCapabilitiesAnswerEmission {
            wire: wire.freeze(),
            readiness: self.readiness(),
        })
    }

    /// Observe a decoded CEA from the peer.
    #[must_use]
    pub fn observe_capabilities_answer(
        &mut self,
        answer: &CapabilitiesExchangeAnswer,
    ) -> PeerSessionTransition {
        if let Some(requirement) = self.protection_policy.requirement() {
            let previous = self.state;
            self.fail_protection_lifecycle(
                Some(requirement.mechanism()),
                Some(requirement.sequence()),
                self.protection_readiness().protection_generation,
                PeerProtectionFailure::UnboundCapabilityEvidence,
            );
            return self.transition(PeerSessionEvent::Failure, previous);
        }
        self.observe_capabilities_answer_inner(answer, false)
    }

    /// Observe an exact-generation decoded CEA on the protected-session path.
    ///
    /// # Errors
    ///
    /// Returns [`PeerCapabilityBoundaryError`] for a stale generation,
    /// non-CEA header, or transaction mismatch.
    pub fn observe_capabilities_answer_on(
        &mut self,
        generation: PeerSessionGeneration,
        header: &Header,
        answer: &CapabilitiesExchangeAnswer,
    ) -> Result<PeerSessionTransition, PeerCapabilityBoundaryError> {
        self.validate_capability_generation(generation)?;
        if !is_capabilities_header(header, CommandKind::Answer) {
            return Err(PeerCapabilityBoundaryError::InvalidCapabilitiesHeader);
        }
        let Some(transaction) = self.outbound_capability_transaction else {
            return Err(PeerCapabilityBoundaryError::TransactionMismatch);
        };
        if !transaction.matches(header) {
            return Err(PeerCapabilityBoundaryError::TransactionMismatch);
        }
        self.validate_capabilities_answer_error_bit(header, answer.result_code)?;
        self.outbound_capability_transaction = None;
        self.capabilities_request_outstanding = false;
        Ok(self.observe_capabilities_answer_inner(answer, true))
    }

    fn observe_capabilities_answer_inner(
        &mut self,
        answer: &CapabilitiesExchangeAnswer,
        generation_bound: bool,
    ) -> PeerSessionTransition {
        let previous = self.state;
        self.capabilities_answers_observed = self.capabilities_answers_observed.saturating_add(1);
        self.capabilities_request_outstanding = false;
        self.remote_capabilities = Some(answer.capabilities.clone());
        let projection = self.project_capabilities_answer(answer);
        let capability_accepted = projection.accepted;
        self.apply_capability_projection(projection, &answer.capabilities, generation_bound);
        let accepted = capability_accepted && self.state != PeerSessionState::Failed;
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
        if let Some(requirement) = self.protection_policy.requirement() {
            let previous = self.state;
            self.fail_protection_lifecycle(
                Some(requirement.mechanism()),
                Some(requirement.sequence()),
                self.protection_readiness().protection_generation,
                PeerProtectionFailure::UnboundCapabilityEvidence,
            );
            return self.transition(PeerSessionEvent::Failure, previous);
        }
        self.observe_capabilities_protocol_error_answer_inner(answer)
    }

    /// Observe an exact-generation protocol-error CEA.
    ///
    /// # Errors
    ///
    /// Returns [`PeerCapabilityBoundaryError`] for a stale generation,
    /// non-CEA header, or transaction mismatch.
    pub fn observe_capabilities_protocol_error_answer_on(
        &mut self,
        generation: PeerSessionGeneration,
        header: &Header,
        answer: &CapabilitiesExchangeErrorAnswer,
    ) -> Result<PeerSessionTransition, PeerCapabilityBoundaryError> {
        self.validate_capability_generation(generation)?;
        if !is_capabilities_header(header, CommandKind::Answer) {
            return Err(PeerCapabilityBoundaryError::InvalidCapabilitiesHeader);
        }
        let Some(transaction) = self.outbound_capability_transaction else {
            return Err(PeerCapabilityBoundaryError::TransactionMismatch);
        };
        if !transaction.matches(header) {
            return Err(PeerCapabilityBoundaryError::TransactionMismatch);
        }
        self.validate_capabilities_answer_error_bit(header, answer.result_code)?;
        self.outbound_capability_transaction = None;
        self.capabilities_request_outstanding = false;
        Ok(self.observe_capabilities_protocol_error_answer_inner(answer))
    }

    fn observe_capabilities_protocol_error_answer_inner(
        &mut self,
        answer: &CapabilitiesExchangeErrorAnswer,
    ) -> PeerSessionTransition {
        let previous = self.state;
        self.capabilities_protocol_errors_observed =
            self.capabilities_protocol_errors_observed.saturating_add(1);
        let projection = self.project_capabilities_protocol_error_answer(answer);
        self.apply_rejected_capability_projection(projection);
        self.transition(PeerSessionEvent::CapabilitiesProtocolError, previous)
    }

    /// Mark a DWR as sent.
    ///
    /// # Errors
    ///
    /// Returns [`PeerSessionError`] when capability negotiation has not
    /// completed or the session is draining, reconnecting, or failed.
    pub fn watchdog_request_sent(&mut self) -> Result<PeerSessionTransition, PeerSessionError> {
        if self.protection_policy.requires_generation_binding() {
            return Err(PeerSessionError::InvalidTransition {
                operation: "watchdog_request_sent_unbound",
                state: self.state,
            });
        }
        self.watchdog_request_sent_inner()
    }

    /// Mark a DWR as sent on the exact current transport generation.
    ///
    /// # Errors
    ///
    /// Returns [`PeerSessionBoundError`] for stale connection evidence or an
    /// invalid peer-state transition.
    pub fn watchdog_request_sent_on(
        &mut self,
        generation: PeerSessionGeneration,
        header: &Header,
    ) -> Result<PeerSessionTransition, PeerSessionBoundError> {
        self.validate_lifecycle_message(
            generation,
            PeerMessageDirection::Outbound,
            header,
            PeerProcedure::DeviceWatchdog,
            CommandKind::Request,
            "watchdog_request_sent",
        )?;
        self.watchdog_request_sent_inner()
            .map_err(PeerSessionBoundError::from_session)
    }

    fn watchdog_request_sent_inner(&mut self) -> Result<PeerSessionTransition, PeerSessionError> {
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
        if self.protection_policy.requires_generation_binding() {
            return self.transition(PeerSessionEvent::Failure, self.state);
        }
        self.observe_watchdog_request_inner(request)
    }

    /// Observe a decoded DWR on the exact current transport generation.
    ///
    /// # Errors
    ///
    /// Returns [`PeerSessionBoundError::StaleGeneration`] without mutation
    /// when the request belongs to an earlier transport.
    pub fn observe_watchdog_request_on(
        &mut self,
        generation: PeerSessionGeneration,
        header: &Header,
        request: &DeviceWatchdogRequest,
    ) -> Result<PeerSessionTransition, PeerSessionBoundError> {
        self.validate_lifecycle_message(
            generation,
            PeerMessageDirection::Inbound,
            header,
            PeerProcedure::DeviceWatchdog,
            CommandKind::Request,
            "observe_watchdog_request",
        )?;
        Ok(self.observe_watchdog_request_inner(request))
    }

    fn observe_watchdog_request_inner(
        &mut self,
        request: &DeviceWatchdogRequest,
    ) -> PeerSessionTransition {
        let previous = self.state;
        if matches!(self.protection, PeerProtectionLifecycle::Pending { .. }) {
            let readiness = self.protection_readiness();
            self.fail_protection_lifecycle(
                readiness.mechanism,
                readiness.sequence,
                readiness.protection_generation,
                PeerProtectionFailure::CommandBeforeProtection,
            );
            return self.transition(PeerSessionEvent::Failure, previous);
        }
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
        if self.protection_policy.requires_generation_binding() {
            return Err(PeerSessionError::InvalidTransition {
                operation: "observe_watchdog_answer_unbound",
                state: self.state,
            });
        }
        self.observe_watchdog_answer_inner(answer)
    }

    /// Observe a decoded DWA on the exact current transport generation.
    ///
    /// # Errors
    ///
    /// Returns [`PeerSessionBoundError`] for stale connection evidence or an
    /// invalid peer-state transition.
    pub fn observe_watchdog_answer_on(
        &mut self,
        generation: PeerSessionGeneration,
        header: &Header,
        answer: &DeviceWatchdogAnswer,
    ) -> Result<PeerSessionTransition, PeerSessionBoundError> {
        self.validate_lifecycle_message(
            generation,
            PeerMessageDirection::Inbound,
            header,
            PeerProcedure::DeviceWatchdog,
            CommandKind::Answer,
            "observe_watchdog_answer",
        )?;
        self.observe_watchdog_answer_inner(answer)
            .map_err(PeerSessionBoundError::from_session)
    }

    fn observe_watchdog_answer_inner(
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
        if self.protection_policy.requires_generation_binding() {
            return Err(PeerSessionError::InvalidTransition {
                operation: "watchdog_missed_unbound",
                state: self.state,
            });
        }
        self.watchdog_missed_inner()
    }

    /// Record a missed watchdog on the exact current transport generation.
    ///
    /// # Errors
    ///
    /// Returns [`PeerSessionBoundError`] for stale connection evidence or an
    /// invalid peer-state transition.
    pub fn watchdog_missed_on(
        &mut self,
        generation: PeerSessionGeneration,
    ) -> Result<PeerSessionTransition, PeerSessionBoundError> {
        self.validate_lifecycle_generation(generation)?;
        self.watchdog_missed_inner()
            .map_err(PeerSessionBoundError::from_session)
    }

    fn watchdog_missed_inner(&mut self) -> Result<PeerSessionTransition, PeerSessionError> {
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
        if threshold_exceeded {
            self.revoke_protection(PeerProtectionFailure::SessionFailed);
        }
        Ok(self.transition(PeerSessionEvent::WatchdogMissed, previous))
    }

    /// Mark a local DPR as sent.
    #[must_use]
    pub fn disconnect_request_sent(&mut self, cause: DisconnectCause) -> PeerSessionTransition {
        if self.protection_policy.requires_generation_binding() {
            return self.transition(PeerSessionEvent::Failure, self.state);
        }
        self.disconnect_request_sent_inner(cause)
    }

    /// Mark a local DPR as sent on the exact current transport generation.
    ///
    /// # Errors
    ///
    /// Returns [`PeerSessionBoundError::StaleGeneration`] without mutation
    /// when the request belongs to an earlier transport.
    pub fn disconnect_request_sent_on(
        &mut self,
        generation: PeerSessionGeneration,
        header: &Header,
        cause: DisconnectCause,
    ) -> Result<PeerSessionTransition, PeerSessionBoundError> {
        self.validate_lifecycle_message(
            generation,
            PeerMessageDirection::Outbound,
            header,
            PeerProcedure::DisconnectPeer,
            CommandKind::Request,
            "disconnect_request_sent",
        )?;
        Ok(self.disconnect_request_sent_inner(cause))
    }

    fn disconnect_request_sent_inner(&mut self, _cause: DisconnectCause) -> PeerSessionTransition {
        let previous = self.state;
        if matches!(self.protection, PeerProtectionLifecycle::Pending { .. }) {
            let readiness = self.protection_readiness();
            self.fail_protection_lifecycle(
                readiness.mechanism,
                readiness.sequence,
                readiness.protection_generation,
                PeerProtectionFailure::CommandBeforeProtection,
            );
            return self.transition(PeerSessionEvent::Failure, previous);
        }
        self.disconnect_requests_sent = self.disconnect_requests_sent.saturating_add(1);
        self.revoke_protection(PeerProtectionFailure::SessionFailed);
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
        request: &DisconnectPeerRequest,
    ) -> PeerSessionTransition {
        if self.protection_policy.requires_generation_binding() {
            return self.transition(PeerSessionEvent::Failure, self.state);
        }
        self.observe_disconnect_request_inner(request)
    }

    /// Observe a decoded DPR on the exact current transport generation.
    ///
    /// # Errors
    ///
    /// Returns [`PeerSessionBoundError::StaleGeneration`] without mutation
    /// when the request belongs to an earlier transport.
    pub fn observe_disconnect_request_on(
        &mut self,
        generation: PeerSessionGeneration,
        header: &Header,
        request: &DisconnectPeerRequest,
    ) -> Result<PeerSessionTransition, PeerSessionBoundError> {
        self.validate_lifecycle_message(
            generation,
            PeerMessageDirection::Inbound,
            header,
            PeerProcedure::DisconnectPeer,
            CommandKind::Request,
            "observe_disconnect_request",
        )?;
        Ok(self.observe_disconnect_request_inner(request))
    }

    fn observe_disconnect_request_inner(
        &mut self,
        _request: &DisconnectPeerRequest,
    ) -> PeerSessionTransition {
        let previous = self.state;
        if matches!(self.protection, PeerProtectionLifecycle::Pending { .. }) {
            let readiness = self.protection_readiness();
            self.fail_protection_lifecycle(
                readiness.mechanism,
                readiness.sequence,
                readiness.protection_generation,
                PeerProtectionFailure::CommandBeforeProtection,
            );
            return self.transition(PeerSessionEvent::Failure, previous);
        }
        self.disconnect_requests_received = self.disconnect_requests_received.saturating_add(1);
        self.revoke_protection(PeerProtectionFailure::SessionFailed);
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
        if self.protection_policy.requires_generation_binding() {
            return self.transition(PeerSessionEvent::Failure, self.state);
        }
        self.disconnect_answer_sent_inner(answer)
    }

    /// Mark a local DPA as sent on the exact current transport generation.
    ///
    /// # Errors
    ///
    /// Returns [`PeerSessionBoundError::StaleGeneration`] without mutation
    /// when the answer belongs to an earlier transport.
    pub fn disconnect_answer_sent_on(
        &mut self,
        generation: PeerSessionGeneration,
        header: &Header,
        answer: &DisconnectPeerAnswer,
    ) -> Result<PeerSessionTransition, PeerSessionBoundError> {
        self.validate_lifecycle_message(
            generation,
            PeerMessageDirection::Outbound,
            header,
            PeerProcedure::DisconnectPeer,
            CommandKind::Answer,
            "disconnect_answer_sent",
        )?;
        Ok(self.disconnect_answer_sent_inner(answer))
    }

    fn disconnect_answer_sent_inner(
        &mut self,
        answer: &DisconnectPeerAnswer,
    ) -> PeerSessionTransition {
        let previous = self.state;
        if matches!(self.protection, PeerProtectionLifecycle::Pending { .. }) {
            let readiness = self.protection_readiness();
            self.fail_protection_lifecycle(
                readiness.mechanism,
                readiness.sequence,
                readiness.protection_generation,
                PeerProtectionFailure::CommandBeforeProtection,
            );
            return self.transition(PeerSessionEvent::Failure, previous);
        }
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
        if self.protection_policy.requires_generation_binding() {
            return self.transition(PeerSessionEvent::Failure, self.state);
        }
        self.observe_disconnect_answer_inner(answer)
    }

    /// Observe a decoded DPA on the exact current transport generation.
    ///
    /// # Errors
    ///
    /// Returns [`PeerSessionBoundError::StaleGeneration`] without mutation
    /// when the answer belongs to an earlier transport.
    pub fn observe_disconnect_answer_on(
        &mut self,
        generation: PeerSessionGeneration,
        header: &Header,
        answer: &DisconnectPeerAnswer,
    ) -> Result<PeerSessionTransition, PeerSessionBoundError> {
        self.validate_lifecycle_message(
            generation,
            PeerMessageDirection::Inbound,
            header,
            PeerProcedure::DisconnectPeer,
            CommandKind::Answer,
            "observe_disconnect_answer",
        )?;
        Ok(self.observe_disconnect_answer_inner(answer))
    }

    fn observe_disconnect_answer_inner(
        &mut self,
        answer: &DisconnectPeerAnswer,
    ) -> PeerSessionTransition {
        let previous = self.state;
        if matches!(self.protection, PeerProtectionLifecycle::Pending { .. }) {
            let readiness = self.protection_readiness();
            self.fail_protection_lifecycle(
                readiness.mechanism,
                readiness.sequence,
                readiness.protection_generation,
                PeerProtectionFailure::CommandBeforeProtection,
            );
            return self.transition(PeerSessionEvent::Failure, previous);
        }
        self.disconnect_answers_observed = self.disconnect_answers_observed.saturating_add(1);
        self.apply_disconnect_answer(answer, false);
        self.transition(PeerSessionEvent::DisconnectAnswerReceived, previous)
    }

    /// Move to reconnecting state.
    #[must_use]
    pub fn schedule_reconnect(&mut self) -> PeerSessionTransition {
        if self.protection_policy.requires_generation_binding() {
            return self.transition(PeerSessionEvent::Failure, self.state);
        }
        self.schedule_reconnect_inner()
    }

    /// Move the exact current transport generation to reconnecting state.
    ///
    /// # Errors
    ///
    /// Returns [`PeerSessionBoundError::StaleGeneration`] without mutation
    /// for an event from an earlier transport.
    pub fn schedule_reconnect_on(
        &mut self,
        generation: PeerSessionGeneration,
    ) -> Result<PeerSessionTransition, PeerSessionBoundError> {
        self.validate_lifecycle_generation(generation)?;
        Ok(self.schedule_reconnect_inner())
    }

    fn schedule_reconnect_inner(&mut self) -> PeerSessionTransition {
        let previous = self.state;
        self.reconnects_scheduled = self.reconnects_scheduled.saturating_add(1);
        self.revoke_protection(PeerProtectionFailure::SessionFailed);
        self.state = PeerSessionState::Reconnecting;
        self.last_blockers.clear();
        self.transition(PeerSessionEvent::ReconnectScheduled, previous)
    }

    /// Move to reconnect backoff state.
    #[must_use]
    pub fn enter_backoff(&mut self) -> PeerSessionTransition {
        if self.protection_policy.requires_generation_binding() {
            return self.transition(PeerSessionEvent::Failure, self.state);
        }
        self.enter_backoff_inner()
    }

    /// Move the exact current transport generation into reconnect backoff.
    ///
    /// # Errors
    ///
    /// Returns [`PeerSessionBoundError::StaleGeneration`] without mutation
    /// for an event from an earlier transport.
    pub fn enter_backoff_on(
        &mut self,
        generation: PeerSessionGeneration,
    ) -> Result<PeerSessionTransition, PeerSessionBoundError> {
        self.validate_lifecycle_generation(generation)?;
        Ok(self.enter_backoff_inner())
    }

    fn enter_backoff_inner(&mut self) -> PeerSessionTransition {
        let previous = self.state;
        self.backoffs_entered = self.backoffs_entered.saturating_add(1);
        self.revoke_protection(PeerProtectionFailure::SessionFailed);
        self.state = PeerSessionState::Backoff;
        self.last_blockers = vec![PeerSessionBlocker::ReconnectBackoff];
        self.transition(PeerSessionEvent::BackoffEntered, previous)
    }

    /// Mark reconnect backoff elapsed.
    #[must_use]
    pub fn backoff_elapsed(&mut self) -> PeerSessionTransition {
        if self.protection_policy.requires_generation_binding() {
            return self.transition(PeerSessionEvent::Failure, self.state);
        }
        self.backoff_elapsed_inner()
    }

    /// Mark reconnect backoff elapsed for the exact current generation.
    ///
    /// # Errors
    ///
    /// Returns [`PeerSessionBoundError::StaleGeneration`] without mutation
    /// for an event from an earlier transport.
    pub fn backoff_elapsed_on(
        &mut self,
        generation: PeerSessionGeneration,
    ) -> Result<PeerSessionTransition, PeerSessionBoundError> {
        self.validate_lifecycle_generation(generation)?;
        Ok(self.backoff_elapsed_inner())
    }

    fn backoff_elapsed_inner(&mut self) -> PeerSessionTransition {
        let previous = self.state;
        self.reconnects_scheduled = self.reconnects_scheduled.saturating_add(1);
        self.revoke_protection(PeerProtectionFailure::SessionFailed);
        self.state = PeerSessionState::Reconnecting;
        self.last_blockers.clear();
        self.transition(PeerSessionEvent::BackoffElapsed, previous)
    }

    /// Fail the session closed with a stable blocker.
    #[must_use]
    pub fn fail(&mut self, blocker: PeerSessionBlocker) -> PeerSessionTransition {
        if self.protection_policy.requires_generation_binding() {
            return self.transition(PeerSessionEvent::Failure, self.state);
        }
        self.fail_inner(blocker)
    }

    /// Fail the exact current transport generation closed.
    ///
    /// # Errors
    ///
    /// Returns [`PeerSessionBoundError::StaleGeneration`] without mutation
    /// for an event from an earlier transport.
    pub fn fail_on(
        &mut self,
        generation: PeerSessionGeneration,
        blocker: PeerSessionBlocker,
    ) -> Result<PeerSessionTransition, PeerSessionBoundError> {
        self.validate_lifecycle_generation(generation)?;
        Ok(self.fail_inner(blocker))
    }

    fn fail_inner(&mut self, blocker: PeerSessionBlocker) -> PeerSessionTransition {
        let previous = self.state;
        self.revoke_protection(PeerProtectionFailure::SessionFailed);
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
            traffic_ready: self.state == PeerSessionState::Negotiated
                && self.protection_readiness().traffic_permitted,
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
        let accepted_inband_security_common = match self.protection_policy {
            PeerProtectionPolicy::CompatibilityUnprotected => {
                let no_inband_common = negotiated
                    .inband_security_ids
                    .contains(&INBAND_SECURITY_ID_NO_INBAND_SECURITY);
                let selector_accepts_no_inband =
                    self.policy.accepted_inband_security_ids.is_empty()
                        || self
                            .policy
                            .accepted_inband_security_ids
                            .contains(&INBAND_SECURITY_ID_NO_INBAND_SECURITY);
                no_inband_common && selector_accepts_no_inband
            }
            PeerProtectionPolicy::Require(requirement) => match requirement.sequence() {
                PeerProtectionSequence::DirectBeforeCapabilities => true,
                PeerProtectionSequence::InbandAfterCapabilities => {
                    negotiated
                        .inband_security_ids
                        .contains(&INBAND_SECURITY_ID_TLS)
                        && (self.policy.accepted_inband_security_ids.is_empty()
                            || self
                                .policy
                                .accepted_inband_security_ids
                                .contains(&INBAND_SECURITY_ID_TLS))
                }
            },
        };
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

    fn protection_security_is_common(&self, negotiated: &CapabilityNegotiation) -> bool {
        match self.protection_policy {
            PeerProtectionPolicy::CompatibilityUnprotected => negotiated
                .inband_security_ids
                .contains(&INBAND_SECURITY_ID_NO_INBAND_SECURITY),
            PeerProtectionPolicy::Require(requirement) => match requirement.sequence() {
                PeerProtectionSequence::DirectBeforeCapabilities => true,
                PeerProtectionSequence::InbandAfterCapabilities => negotiated
                    .inband_security_ids
                    .contains(&INBAND_SECURITY_ID_TLS),
            },
        }
    }

    fn apply_capability_projection(
        &mut self,
        projection: PeerSessionCapabilityProjection,
        remote: &PeerCapabilities,
        generation_bound: bool,
    ) {
        self.missed_watchdogs = 0;
        self.last_watchdog_projection = None;
        self.last_disconnect_projection = None;
        let mechanism = self.selected_protection_for(remote);
        if self
            .selected_protection
            .is_some_and(|selected| selected != mechanism)
        {
            self.last_capability_projection = Some(projection);
            self.fail_protection_lifecycle(
                Some(mechanism),
                self.protection_policy
                    .requirement()
                    .map(|requirement| requirement.sequence()),
                self.protection_readiness().protection_generation,
                PeerProtectionFailure::DowngradeRejected,
            );
            return;
        }
        if !projection.accepted {
            self.apply_rejected_capability_projection(projection);
            return;
        }

        if mechanism.is_protected() && !generation_bound {
            self.last_capability_projection = Some(projection);
            self.fail_protection_lifecycle(
                Some(mechanism),
                self.protection_policy
                    .requirement()
                    .map(|requirement| requirement.sequence()),
                None,
                PeerProtectionFailure::UnboundCapabilityEvidence,
            );
            return;
        }
        self.selected_protection = Some(mechanism);
        self.capability_evidence_generation_bound |= generation_bound;
        self.last_capability_projection = Some(projection);
        self.finish_capability_phase();
    }

    fn apply_rejected_capability_projection(
        &mut self,
        projection: PeerSessionCapabilityProjection,
    ) {
        self.missed_watchdogs = 0;
        self.last_watchdog_projection = None;
        self.last_disconnect_projection = None;
        self.last_blockers = projection.blockers.clone();
        self.state = PeerSessionState::Failed;
        self.protection = PeerProtectionLifecycle::Failed {
            mechanism: self.selected_protection,
            sequence: self
                .protection_policy
                .requirement()
                .map(|requirement| requirement.sequence()),
            generation: self.protection_readiness().protection_generation,
            failure: PeerProtectionFailure::SessionFailed,
        };
        self.last_capability_projection = Some(projection);
    }

    fn selected_protection_for(&self, remote: &PeerCapabilities) -> PeerProtectionMechanism {
        let negotiated = negotiate_capabilities(&self.local_capabilities, remote);
        match self.protection_policy {
            PeerProtectionPolicy::CompatibilityUnprotected => PeerProtectionMechanism::Unprotected,
            PeerProtectionPolicy::Require(requirement) => match requirement.sequence() {
                PeerProtectionSequence::DirectBeforeCapabilities => requirement.mechanism(),
                PeerProtectionSequence::InbandAfterCapabilities => {
                    if negotiated
                        .inband_security_ids
                        .contains(&INBAND_SECURITY_ID_TLS)
                    {
                        requirement.mechanism()
                    } else {
                        PeerProtectionMechanism::Unprotected
                    }
                }
            },
        }
    }

    fn finish_capability_phase(&mut self) {
        if self.capabilities_request_outstanding
            || self.outbound_capability_transaction.is_some()
            || self.inbound_capability_transaction.is_some()
        {
            self.state = PeerSessionState::CapabilitiesPending;
            self.last_blockers = vec![PeerSessionBlocker::CapabilitiesExchangePending];
            return;
        }

        match (self.protection_policy, self.selected_protection) {
            (
                PeerProtectionPolicy::CompatibilityUnprotected,
                Some(PeerProtectionMechanism::Unprotected),
            ) => {
                self.protection = PeerProtectionLifecycle::Unprotected;
                self.state = PeerSessionState::Negotiated;
                self.last_blockers.clear();
            }
            (PeerProtectionPolicy::Require(requirement), Some(mechanism))
                if mechanism == requirement.mechanism()
                    && self.capability_evidence_generation_bound
                    && self.session_generation.is_some() =>
            {
                match requirement.sequence() {
                    PeerProtectionSequence::DirectBeforeCapabilities => {
                        if self.direct_protection_is_attested() {
                            self.state = PeerSessionState::Negotiated;
                            self.last_blockers.clear();
                        } else {
                            self.fail_protection_lifecycle(
                                Some(requirement.mechanism()),
                                Some(requirement.sequence()),
                                self.protection_readiness().protection_generation,
                                PeerProtectionFailure::UnboundCapabilityEvidence,
                            );
                        }
                    }
                    PeerProtectionSequence::InbandAfterCapabilities => {
                        self.start_pending_protection(requirement);
                    }
                }
            }
            (PeerProtectionPolicy::Require(requirement), Some(mechanism))
                if mechanism != requirement.mechanism() =>
            {
                self.fail_protection_lifecycle(
                    Some(requirement.mechanism()),
                    Some(requirement.sequence()),
                    self.protection_readiness().protection_generation,
                    PeerProtectionFailure::DowngradeRejected,
                );
            }
            (PeerProtectionPolicy::Require(requirement), Some(_)) => {
                self.fail_protection_lifecycle(
                    Some(requirement.mechanism()),
                    Some(requirement.sequence()),
                    self.protection_readiness().protection_generation,
                    PeerProtectionFailure::UnboundCapabilityEvidence,
                );
            }
            (_, None) | (PeerProtectionPolicy::CompatibilityUnprotected, Some(_)) => {
                self.state = PeerSessionState::CapabilitiesPending;
                self.last_blockers = vec![PeerSessionBlocker::CapabilitiesExchangePending];
            }
        }
    }

    fn start_pending_protection(&mut self, requirement: PeerProtectionRequirement) {
        if matches!(self.protection, PeerProtectionLifecycle::Pending { .. }) {
            self.state = match requirement.sequence() {
                PeerProtectionSequence::DirectBeforeCapabilities => PeerSessionState::Idle,
                PeerProtectionSequence::InbandAfterCapabilities => {
                    PeerSessionState::CapabilitiesPending
                }
            };
            self.last_blockers = vec![PeerSessionBlocker::CapabilitiesExchangePending];
            return;
        }
        let Some(next) = self.next_protection_generation.checked_add(1) else {
            self.fail_protection_lifecycle(
                Some(requirement.mechanism()),
                Some(requirement.sequence()),
                None,
                PeerProtectionFailure::GenerationExhausted,
            );
            return;
        };
        let Some(nonzero) = NonZeroU64::new(next) else {
            self.fail_protection_lifecycle(
                Some(requirement.mechanism()),
                Some(requirement.sequence()),
                None,
                PeerProtectionFailure::GenerationExhausted,
            );
            return;
        };
        let generation = PeerProtectionGeneration(nonzero);
        self.next_protection_generation = next;
        self.protection = PeerProtectionLifecycle::Pending {
            generation,
            requirement,
        };
        self.state = match requirement.sequence() {
            PeerProtectionSequence::DirectBeforeCapabilities => PeerSessionState::Idle,
            PeerProtectionSequence::InbandAfterCapabilities => {
                PeerSessionState::CapabilitiesPending
            }
        };
        self.last_blockers = vec![PeerSessionBlocker::CapabilitiesExchangePending];
    }

    fn validate_pending_protection(
        &mut self,
        pending: &PeerProtectionPending,
        mechanism: PeerProtectionMechanism,
    ) -> Result<(PeerSessionGeneration, PeerProtectionGeneration), PeerProtectionError> {
        if !Arc::ptr_eq(&pending.authority, &self.authority) {
            return Err(PeerProtectionError::StaleSessionGeneration);
        }
        let Some(session_generation) = self.session_generation else {
            return Err(PeerProtectionError::StaleSessionGeneration);
        };
        if pending.session_generation != session_generation {
            return Err(PeerProtectionError::StaleSessionGeneration);
        }
        let PeerProtectionLifecycle::Pending {
            generation,
            requirement,
        } = self.protection
        else {
            return Err(PeerProtectionError::NotPending {
                state: self.protection_readiness().state,
            });
        };
        if pending.protection_generation != generation || pending.sequence != requirement.sequence()
        {
            return Err(PeerProtectionError::StaleProtectionGeneration);
        }
        let expected = requirement.mechanism();
        if pending.mechanism != expected || mechanism != expected {
            self.fail_protection_lifecycle(
                Some(expected),
                Some(requirement.sequence()),
                Some(generation),
                PeerProtectionFailure::DowngradeRejected,
            );
            return Err(PeerProtectionError::MechanismMismatch {
                expected,
                actual: mechanism,
            });
        }
        Ok((session_generation, generation))
    }

    fn direct_protection_is_attested(&self) -> bool {
        let Some(requirement) = self.protection_policy.requirement() else {
            return false;
        };
        if requirement.sequence() != PeerProtectionSequence::DirectBeforeCapabilities {
            return false;
        }
        matches!(
            (self.protection, self.session_generation),
            (PeerProtectionLifecycle::Protected { evidence }, Some(session_generation))
                if evidence.session_generation() == session_generation
                    && evidence.mechanism() == requirement.mechanism()
                    && evidence.sequence() == requirement.sequence()
        )
    }

    fn capability_phase_is_available(&self) -> bool {
        match self.protection_policy.requirement() {
            None => matches!(self.protection, PeerProtectionLifecycle::NotNegotiated),
            Some(requirement)
                if requirement.sequence() == PeerProtectionSequence::InbandAfterCapabilities =>
            {
                matches!(self.protection, PeerProtectionLifecycle::NotNegotiated)
            }
            Some(_) => self.direct_protection_is_attested(),
        }
    }

    fn capability_exchange_complete(&self) -> bool {
        self.last_capability_projection
            .as_ref()
            .is_some_and(|projection| projection.accepted)
            && self.selected_protection.is_some()
            && !self.capabilities_request_outstanding
            && self.outbound_capability_transaction.is_none()
            && self.inbound_capability_transaction.is_none()
    }

    fn validate_capability_generation(
        &self,
        generation: PeerSessionGeneration,
    ) -> Result<(), PeerCapabilityBoundaryError> {
        if self.session_generation == Some(generation) {
            Ok(())
        } else {
            Err(PeerCapabilityBoundaryError::StaleGeneration)
        }
    }

    fn validate_lifecycle_generation(
        &self,
        generation: PeerSessionGeneration,
    ) -> Result<(), PeerSessionBoundError> {
        if self.session_generation == Some(generation) {
            Ok(())
        } else {
            Err(PeerSessionBoundError::StaleGeneration)
        }
    }

    fn validate_lifecycle_message(
        &self,
        generation: PeerSessionGeneration,
        direction: PeerMessageDirection,
        header: &Header,
        procedure: PeerProcedure,
        kind: CommandKind,
        operation: &'static str,
    ) -> Result<(), PeerSessionBoundError> {
        self.validate_lifecycle_generation(generation)?;
        if !is_peer_procedure_header(header, procedure, kind) {
            return Err(PeerSessionBoundError::InvalidPeerHeader { operation });
        }
        self.admit_message(generation, direction, header)
            .map(|_admission| ())
            .map_err(|reason| PeerSessionBoundError::CommandNotAdmitted { operation, reason })
    }

    fn validate_capabilities_answer_commit(
        &self,
        answer: &CapabilitiesExchangeAnswer,
    ) -> Result<(), PeerCapabilityBoundaryError> {
        let Some(projection) = self.last_capability_projection.as_ref() else {
            return Err(PeerCapabilityBoundaryError::InvalidSessionState);
        };
        if answer.result_code != projection.result_code {
            return Err(PeerCapabilityBoundaryError::AnswerOutcomeMismatch);
        }
        let direct_protection = self
            .protection_policy
            .requirement()
            .is_some_and(|requirement| {
                requirement.sequence() == PeerProtectionSequence::DirectBeforeCapabilities
            });
        if !direct_protection
            && !same_effective_inband_security_support(
                &answer.capabilities.inband_security_ids,
                &self.local_capabilities.inband_security_ids,
            )
        {
            return Err(PeerCapabilityBoundaryError::AnswerSecurityMismatch);
        }
        if projection.accepted && !direct_protection {
            let Some(mechanism) = self.selected_protection else {
                return Err(PeerCapabilityBoundaryError::InvalidSessionState);
            };
            if !effective_inband_security_ids(&answer.capabilities.inband_security_ids)
                .contains(&mechanism.inband_security_id())
            {
                return Err(PeerCapabilityBoundaryError::AnswerSecurityMismatch);
            }
        }
        Ok(())
    }

    fn validate_capabilities_answer_error_bit(
        &self,
        header: &Header,
        result_code: u32,
    ) -> Result<(), PeerCapabilityBoundaryError> {
        if header.flags.is_error() != result_code_requires_error_bit(result_code) {
            Err(PeerCapabilityBoundaryError::AnswerErrorBitMismatch)
        } else {
            Ok(())
        }
    }

    fn capabilities_header_is_admissible(
        &self,
        direction: PeerMessageDirection,
        header: &Header,
    ) -> bool {
        if !self.capability_phase_is_available()
            || !matches!(
                self.state,
                PeerSessionState::Idle | PeerSessionState::CapabilitiesPending
            )
        {
            return false;
        }
        match (direction, header.flags.command_kind()) {
            (PeerMessageDirection::Inbound, CommandKind::Request) => {
                is_capabilities_header(header, CommandKind::Request)
                    && self
                        .capability_role
                        .is_none_or(|role| role == PeerCapabilityRole::Responder)
                    && self
                        .inbound_capability_transaction
                        .is_none_or(|transaction| transaction.matches(header))
            }
            (PeerMessageDirection::Outbound, CommandKind::Request) => {
                is_capabilities_header(header, CommandKind::Request)
                    && self
                        .capability_role
                        .is_none_or(|role| role == PeerCapabilityRole::Initiator)
                    && self
                        .outbound_capability_transaction
                        .is_none_or(|transaction| transaction.matches(header))
            }
            (PeerMessageDirection::Inbound, CommandKind::Answer) => {
                is_capabilities_header(header, CommandKind::Answer)
                    && self
                        .outbound_capability_transaction
                        .is_some_and(|transaction| transaction.matches(header))
            }
            (PeerMessageDirection::Outbound, CommandKind::Answer) => false,
        }
    }

    fn fail_protection_lifecycle(
        &mut self,
        mechanism: Option<PeerProtectionMechanism>,
        sequence: Option<PeerProtectionSequence>,
        generation: Option<PeerProtectionGeneration>,
        failure: PeerProtectionFailure,
    ) {
        self.protection = PeerProtectionLifecycle::Failed {
            mechanism,
            sequence,
            generation,
            failure,
        };
        self.capabilities_request_outstanding = false;
        self.outbound_capability_transaction = None;
        self.inbound_capability_transaction = None;
        self.capability_role = None;
        self.state = PeerSessionState::Failed;
        self.last_blockers = vec![PeerSessionBlocker::SessionFailed];
    }

    fn revoke_protection(&mut self, failure: PeerProtectionFailure) {
        let readiness = self.protection_readiness();
        self.protection = PeerProtectionLifecycle::Failed {
            mechanism: readiness.mechanism,
            sequence: readiness.sequence,
            generation: readiness.protection_generation,
            failure,
        };
        self.capabilities_request_outstanding = false;
        self.outbound_capability_transaction = None;
        self.inbound_capability_transaction = None;
        self.capability_role = None;
    }

    fn protection_transition(
        &self,
        event: PeerProtectionEvent,
        previous_state: PeerProtectionState,
    ) -> PeerProtectionTransition {
        PeerProtectionTransition {
            event,
            previous_state,
            state: self.protection_readiness().state,
            protection: self.protection_readiness(),
            session: self.readiness(),
        }
    }

    fn apply_disconnect_answer(&mut self, answer: &DisconnectPeerAnswer, peer_requested: bool) {
        let mut blockers = Vec::new();
        if answer.result_code != RESULT_CODE_DIAMETER_SUCCESS {
            blockers.push(PeerSessionBlocker::DisconnectResultNotSuccess);
        }
        let acknowledged = blockers.is_empty();
        self.revoke_protection(PeerProtectionFailure::SessionFailed);
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
    let local_inband_security_ids = effective_inband_security_ids(&local.inband_security_ids);
    let remote_inband_security_ids = effective_inband_security_ids(&remote.inband_security_ids);
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
        inband_security_ids: common_copy(local_inband_security_ids, remote_inband_security_ids),
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

fn ensure_result_code_error_bit(
    header: &Header,
    result_code: u32,
    section: &'static str,
) -> Result<(), DecodeError> {
    if header.flags.is_error() == result_code_requires_error_bit(result_code) {
        Ok(())
    } else {
        Err(decode_structural_error(
            "diameter CEA error flag does not match Result-Code family",
            4,
            section,
        ))
    }
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
    parse_capabilities_exchange_request_with_provenance(message, ctx)
        .map_err(DiameterParserError::into_decode_error)
}

/// Parse a Capabilities-Exchange-Request while retaining typed provenance for
/// an omitted mandatory AVP or invalid grouped `Vendor-Specific-Application-Id`
/// child set.
pub fn parse_capabilities_exchange_request_with_provenance(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<PeerCapabilities, DiameterParserError> {
    let section = PeerProcedure::CapabilitiesExchange.spec_section(CommandKind::Request);
    ensure_peer_header(
        message,
        PeerProcedure::CapabilitiesExchange,
        CommandKind::Request,
    )
    .map_err(|error| DiameterParserError::decoded(message, error))?;
    collect_procedure_avps_with_provenance(message.raw_avps, ctx, section)
        .map_err(|error| error.into_parser_error(message, PeerProcedure::CapabilitiesExchange))?
        .into_request_capabilities(message, section)
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
    ensure_result_code_error_bit(&message.header, result_code, section)?;
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
    let avps = collect_procedure_avps(message.raw_avps, ctx, section)?;
    let result_code = require_field(
        avps.result_code.clone(),
        "diameter CEA error answer requires Result-Code",
        section,
    )?;
    ensure_result_code_error_bit(&message.header, result_code, "7.2")?;
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
    parse_device_watchdog_request_with_provenance(message, ctx)
        .map_err(DiameterParserError::into_decode_error)
}

/// Parse a Device-Watchdog-Request while retaining typed provenance for an
/// omitted mandatory AVP.
pub fn parse_device_watchdog_request_with_provenance(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<DeviceWatchdogRequest, DiameterParserError> {
    let section = PeerProcedure::DeviceWatchdog.spec_section(CommandKind::Request);
    ensure_peer_header(message, PeerProcedure::DeviceWatchdog, CommandKind::Request)
        .map_err(|error| DiameterParserError::decoded(message, error))?;
    let avps = collect_procedure_avps_with_provenance(message.raw_avps, ctx, section)
        .map_err(|error| error.into_parser_error(message, PeerProcedure::DeviceWatchdog))?;
    Ok(DeviceWatchdogRequest {
        identity: avps.request_identity(message, PeerProcedure::DeviceWatchdog, section)?,
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
    parse_disconnect_peer_request_with_provenance(message, ctx)
        .map_err(DiameterParserError::into_decode_error)
}

/// Parse a Disconnect-Peer-Request while retaining typed provenance for an
/// omitted mandatory AVP.
pub fn parse_disconnect_peer_request_with_provenance(
    message: &Message<'_>,
    ctx: DecodeContext,
) -> Result<DisconnectPeerRequest, DiameterParserError> {
    let section = PeerProcedure::DisconnectPeer.spec_section(CommandKind::Request);
    ensure_peer_header(message, PeerProcedure::DisconnectPeer, CommandKind::Request)
        .map_err(|error| DiameterParserError::decoded(message, error))?;
    let avps = collect_procedure_avps_with_provenance(message.raw_avps, ctx, section)
        .map_err(|error| error.into_parser_error(message, PeerProcedure::DisconnectPeer))?;
    let disconnect_cause = require_request_field(
        avps.disconnect_cause.clone(),
        "diameter DPR requires Disconnect-Cause",
        AVP_DISCONNECT_CAUSE,
        message,
        PeerProcedure::DisconnectPeer,
        section,
    )?;
    Ok(DisconnectPeerRequest {
        identity: avps.request_identity(message, PeerProcedure::DisconnectPeer, section)?,
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

enum ProcedureAvpParseError {
    Decode(Box<DecodeError>),
    MissingNested {
        error: Box<DecodeError>,
        definition: &'static AvpDefinition,
        parent_definition: &'static AvpDefinition,
        parent_offset: usize,
    },
    GroupedSet {
        error: Box<DecodeError>,
        definitions: Vec<&'static AvpDefinition>,
        parent_definition: &'static AvpDefinition,
        parent_offset: usize,
        failure_kind: DiameterGroupedAvpSetFailureKind,
    },
}

impl ProcedureAvpParseError {
    fn decode_error(&self) -> &DecodeError {
        match self {
            Self::Decode(error)
            | Self::MissingNested { error, .. }
            | Self::GroupedSet { error, .. } => error.as_ref(),
        }
    }

    fn into_decode_error(self) -> DecodeError {
        match self {
            Self::Decode(error)
            | Self::MissingNested { error, .. }
            | Self::GroupedSet { error, .. } => *error,
        }
    }

    fn into_parser_error(
        self,
        message: &Message<'_>,
        procedure: PeerProcedure,
    ) -> DiameterParserError {
        match self {
            Self::Decode(error) => DiameterParserError::decoded(message, *error),
            Self::MissingNested {
                error,
                definition,
                parent_definition,
                parent_offset,
            } => DiameterParserError::missing_with_parent(
                message,
                *error,
                definition,
                parent_definition,
                parent_offset,
                APPLICATION_ID_COMMON_MESSAGES,
                procedure.command_code(),
            ),
            Self::GroupedSet {
                error,
                definitions,
                parent_definition,
                parent_offset,
                failure_kind,
            } => DiameterParserError::grouped_avp_set(
                message,
                *error,
                DiameterGroupedAvpSetProvenance::for_request(
                    &definitions,
                    parent_definition,
                    parent_offset,
                    APPLICATION_ID_COMMON_MESSAGES,
                    procedure.command_code(),
                    failure_kind,
                ),
            ),
        }
    }
}

impl From<DecodeError> for ProcedureAvpParseError {
    fn from(error: DecodeError) -> Self {
        Self::Decode(Box::new(error))
    }
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

    fn request_identity(
        &self,
        message: &Message<'_>,
        procedure: PeerProcedure,
        section: &'static str,
    ) -> Result<PeerIdentity, DiameterParserError> {
        Ok(PeerIdentity {
            origin_host: require_request_field_ref(
                &self.origin_host,
                "diameter peer procedure requires Origin-Host",
                AVP_ORIGIN_HOST,
                message,
                procedure,
                section,
            )?
            .clone(),
            origin_realm: require_request_field_ref(
                &self.origin_realm,
                "diameter peer procedure requires Origin-Realm",
                AVP_ORIGIN_REALM,
                message,
                procedure,
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

    fn into_request_capabilities(
        self,
        message: &Message<'_>,
        section: &'static str,
    ) -> Result<PeerCapabilities, DiameterParserError> {
        let procedure = PeerProcedure::CapabilitiesExchange;
        if self.host_ip_addresses.is_empty() {
            return Err(missing_request_field_error(
                message,
                procedure,
                AVP_HOST_IP_ADDRESS,
                "diameter capabilities exchange requires Host-IP-Address",
                section,
            ));
        }
        Ok(PeerCapabilities {
            identity: PeerIdentity {
                origin_host: require_request_field(
                    self.origin_host,
                    "diameter capabilities exchange requires Origin-Host",
                    AVP_ORIGIN_HOST,
                    message,
                    procedure,
                    section,
                )?,
                origin_realm: require_request_field(
                    self.origin_realm,
                    "diameter capabilities exchange requires Origin-Realm",
                    AVP_ORIGIN_REALM,
                    message,
                    procedure,
                    section,
                )?,
            },
            host_ip_addresses: self.host_ip_addresses,
            vendor_id: require_request_field(
                self.vendor_id,
                "diameter capabilities exchange requires Vendor-Id",
                AVP_VENDOR_ID,
                message,
                procedure,
                section,
            )?,
            product_name: require_request_field(
                self.product_name,
                "diameter capabilities exchange requires Product-Name",
                AVP_PRODUCT_NAME,
                message,
                procedure,
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
    crate::append_canonical_avp(dst, header, value, ctx)
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
    collect_procedure_avps_with_provenance(raw_avps, ctx, section)
        .map_err(ProcedureAvpParseError::into_decode_error)
}

fn collect_procedure_avps_with_provenance(
    raw_avps: &[u8],
    ctx: DecodeContext,
    section: &'static str,
) -> Result<ProcedureAvps, ProcedureAvpParseError> {
    let mut parsed = ProcedureAvps::default();
    let mut nested_error = None;
    let result = for_each_avp(raw_avps, ctx, DIAMETER_HEADER_LEN, 0, |offset, avp| {
        let value_offset = offset_add(offset, avp.header.header_len(), section)?;
        validate_peer_avp_flags(&avp.header, offset)?;
        if avp.header.vendor_id.is_some() {
            return handle_unknown_avp(ctx, &avp, offset, section);
        }
        let code = avp.header.code;
        if code == AVP_ORIGIN_HOST {
            let value = parse_diameter_identity_value(avp.value, value_offset, "6.3")?;
            set_once(&mut parsed.origin_host, value, offset, section)
        } else if code == AVP_ORIGIN_REALM {
            let value = parse_diameter_identity_value(avp.value, value_offset, "6.4")?;
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
            match parse_vendor_specific_application(&avp, ctx, offset, value_offset, section) {
                Ok(application) => {
                    parsed.vendor_specific_applications.push(application);
                    Ok(())
                }
                Err(error) => {
                    let decode_error = error.decode_error().clone();
                    nested_error = Some(error);
                    Err(decode_error)
                }
            }
        } else {
            handle_unknown_avp(ctx, &avp, offset, section)
        }
    });
    match result {
        Ok(()) => Ok(parsed),
        Err(error) => {
            Err(nested_error.unwrap_or_else(|| ProcedureAvpParseError::Decode(Box::new(error))))
        }
    }
}

fn parse_vendor_specific_application(
    avp: &RawAvp<'_>,
    ctx: DecodeContext,
    parent_offset: usize,
    value_offset: usize,
    section: &'static str,
) -> Result<VendorSpecificApplication, ProcedureAvpParseError> {
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
    let vendor_id = match vendor_id {
        Some(field) => field.value,
        None => {
            let error = decode_structural_error(
                "diameter Vendor-Specific-Application-Id requires Vendor-Id",
                value_offset,
                section,
            );
            let vendor_definition = base::dictionary().find_avp(AvpKey::ietf(AVP_VENDOR_ID));
            let parent_definition =
                base::dictionary().find_avp(AvpKey::ietf(AVP_VENDOR_SPECIFIC_APPLICATION_ID));
            return Err(match (vendor_definition, parent_definition) {
                (Some(definition), Some(parent_definition)) => {
                    ProcedureAvpParseError::MissingNested {
                        error: Box::new(error),
                        definition,
                        parent_definition,
                        parent_offset,
                    }
                }
                _ => ProcedureAvpParseError::Decode(Box::new(error)),
            });
        }
    };
    if auth_application_id.is_none() && acct_application_id.is_none() {
        return Err(vendor_specific_application_set_error(
            value_offset,
            parent_offset,
            section,
            DiameterGroupedAvpSetFailureKind::MissingOneOf,
        ));
    }
    if auth_application_id.is_some() && acct_application_id.is_some() {
        return Err(vendor_specific_application_set_error(
            value_offset,
            parent_offset,
            section,
            DiameterGroupedAvpSetFailureKind::MutuallyExclusivePresent,
        ));
    }
    Ok(VendorSpecificApplication {
        vendor_ids: vec![vendor_id],
        auth_application_id: auth_application_id.map(|field| field.value),
        acct_application_id: acct_application_id.map(|field| field.value),
    })
}

fn vendor_specific_application_set_error(
    value_offset: usize,
    parent_offset: usize,
    section: &'static str,
    failure_kind: DiameterGroupedAvpSetFailureKind,
) -> ProcedureAvpParseError {
    let error = decode_structural_error(
        "diameter Vendor-Specific-Application-Id requires exactly one Auth-Application-Id or Acct-Application-Id",
        value_offset,
        section,
    );
    let auth = base::dictionary().find_avp(AvpKey::ietf(AVP_AUTH_APPLICATION_ID));
    let acct = base::dictionary().find_avp(AvpKey::ietf(AVP_ACCT_APPLICATION_ID));
    let parent = base::dictionary().find_avp(AvpKey::ietf(AVP_VENDOR_SPECIFIC_APPLICATION_ID));
    match (auth, acct, parent) {
        (Some(auth), Some(acct), Some(parent_definition)) => ProcedureAvpParseError::GroupedSet {
            error: Box::new(error),
            definitions: vec![auth, acct],
            parent_definition,
            parent_offset,
            failure_kind,
        },
        _ => ProcedureAvpParseError::Decode(Box::new(error)),
    }
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

fn parse_diameter_identity_value(
    value: &[u8],
    offset: usize,
    section: &'static str,
) -> Result<String, DecodeError> {
    let parsed = parse_string_value(value, offset, section)?;
    if !is_valid_diameter_identity(&parsed) {
        return Err(decode_structural_error(
            "DiameterIdentity AVP must contain nonempty ASCII",
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

fn require_request_field<T>(
    field: Option<FieldValue<T>>,
    reason: &'static str,
    avp_code: AvpCode,
    message: &Message<'_>,
    procedure: PeerProcedure,
    section: &'static str,
) -> Result<T, DiameterParserError> {
    match field {
        Some(field) => Ok(field.value),
        None => Err(missing_request_field_error(
            message, procedure, avp_code, reason, section,
        )),
    }
}

fn require_request_field_ref<'a, T>(
    field: &'a Option<FieldValue<T>>,
    reason: &'static str,
    avp_code: AvpCode,
    message: &Message<'_>,
    procedure: PeerProcedure,
    section: &'static str,
) -> Result<&'a T, DiameterParserError> {
    match field {
        Some(field) => Ok(&field.value),
        None => Err(missing_request_field_error(
            message, procedure, avp_code, reason, section,
        )),
    }
}

fn missing_request_field_error(
    message: &Message<'_>,
    procedure: PeerProcedure,
    avp_code: AvpCode,
    reason: &'static str,
    section: &'static str,
) -> DiameterParserError {
    let error = decode_structural_error(reason, DIAMETER_HEADER_LEN, section);
    let key = AvpKey::ietf(avp_code);
    match base::dictionary().find_avp(key) {
        Some(definition) => DiameterParserError::missing_for_definition(
            message,
            error,
            definition,
            APPLICATION_ID_COMMON_MESSAGES,
            procedure.command_code(),
        ),
        None => DiameterParserError::decoded(message, error),
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

const DEFAULT_INBAND_SECURITY_IDS: [u32; 1] = [INBAND_SECURITY_ID_NO_INBAND_SECURITY];

fn effective_inband_security_ids(security_ids: &[u32]) -> &[u32] {
    if security_ids.is_empty() {
        &DEFAULT_INBAND_SECURITY_IDS
    } else {
        security_ids
    }
}

fn same_effective_inband_security_support(left: &[u32], right: &[u32]) -> bool {
    let left = effective_inband_security_ids(left);
    let right = effective_inband_security_ids(right);
    left.iter().all(|value| right.contains(value)) && right.iter().all(|value| left.contains(value))
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
    use opc_protocol::{DecodeErrorCode, Encode, ValidationLevel};

    #[test]
    fn peer_identity_semantics_are_ascii_case_insensitive_without_changing_structural_eq() {
        let canonical = PeerIdentity::new("aaa.example.net", "example.net");
        let case_variant = PeerIdentity::new("AAA.Example.NET", "EXAMPLE.Net");
        let other_host = PeerIdentity::new("other.example.net", "example.net");

        assert_ne!(canonical, case_variant);
        assert!(canonical.semantically_eq(&case_variant));
        assert!(!canonical.semantically_eq(&other_host));
    }

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
        remote.inband_security_ids = vec![INBAND_SECURITY_ID_TLS];
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
                    reason: "diameter CEA error flag does not match Result-Code family"
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
                    reason: "diameter CEA error flag does not match Result-Code family"
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
