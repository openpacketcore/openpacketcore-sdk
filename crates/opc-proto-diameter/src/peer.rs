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
    ApplicationId, AvpCode, AvpHeader, AvpKey, CommandCode, CommandFlags, FlagRequirement, Header,
    Message, OwnedMessage, RawAvp, VendorId, DIAMETER_HEADER_LEN, MAX_U24,
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
    let vendor_id = require_field(
        vendor_id,
        "diameter Vendor-Specific-Application-Id requires Vendor-Id",
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
    let key = AvpKey::ietf(header.code);
    let Some(definition) = PEER_DICTIONARIES.find_avp(key) else {
        return Ok(());
    };
    let flags = definition.flags();
    let section = definition.spec_ref().section();
    if flags.vendor() == FlagRequirement::MustBeUnset && header.vendor_id.is_some() {
        return Err(decode_structural_error(
            "diameter AVP V-bit must not be set per base dictionary",
            offset,
            section,
        ));
    }
    if flags.mandatory() == FlagRequirement::MustBeSet && !header.flags.is_mandatory() {
        return Err(decode_structural_error(
            "diameter AVP M-bit must be set per base dictionary",
            offset,
            section,
        ));
    }
    if flags.mandatory() == FlagRequirement::MustBeUnset && header.flags.is_mandatory() {
        return Err(decode_structural_error(
            "diameter AVP M-bit must not be set per base dictionary",
            offset,
            section,
        ));
    }
    if flags.protected() == FlagRequirement::MustBeUnset && header.flags.is_protected() {
        return Err(decode_structural_error(
            "diameter AVP P-bit must not be set per base dictionary",
            offset,
            section,
        ));
    }
    Ok(())
}

fn require_field<T>(
    field: Option<FieldValue<T>>,
    reason: &'static str,
    section: &'static str,
) -> Result<T, DecodeError> {
    match field {
        Some(field) => Ok(field.value),
        None => Err(decode_structural_error(
            reason,
            DIAMETER_HEADER_LEN,
            section,
        )),
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
                    reason: "diameter AVP M-bit must be set per base dictionary"
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
                    reason: "diameter AVP M-bit must not be set per base dictionary"
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
                    reason: "diameter AVP P-bit must not be set per base dictionary"
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
}
