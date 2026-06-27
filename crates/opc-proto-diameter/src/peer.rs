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

use bytes::{BufMut, BytesMut};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeError, DecodeErrorCode, Encode, EncodeContext, EncodeError,
    EncodeErrorCode, SpecRef, UnknownIePolicy,
};

use crate::base::{
    self, AVP_ACCT_APPLICATION_ID, AVP_AUTH_APPLICATION_ID, AVP_DISCONNECT_CAUSE,
    AVP_FIRMWARE_REVISION, AVP_HOST_IP_ADDRESS, AVP_INBAND_SECURITY_ID, AVP_ORIGIN_HOST,
    AVP_ORIGIN_REALM, AVP_ORIGIN_STATE_ID, AVP_PRODUCT_NAME, AVP_RESULT_CODE,
    AVP_SUPPORTED_VENDOR_ID, AVP_VENDOR_ID, AVP_VENDOR_SPECIFIC_APPLICATION_ID,
    COMMAND_CAPABILITIES_EXCHANGE, COMMAND_DEVICE_WATCHDOG, COMMAND_DISCONNECT_PEER,
};
use crate::dictionary::{CommandKind, Dictionary, DictionarySet};
use crate::{
    ApplicationId, AvpCode, AvpHeader, CommandCode, CommandFlags, Header, Message, OwnedMessage,
    RawAvp, VendorId, DIAMETER_HEADER_LEN, MAX_U24,
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
        if self.vendor_ids.is_empty() {
            return Err(encode_structural_error(
                "diameter Vendor-Specific-Application-Id requires at least one Vendor-Id",
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
        for application in &self.vendor_specific_applications {
            application.validate_for_encode(section)?;
        }
        Ok(())
    }
}

/// Parsed Diameter answer carrying a Result-Code and peer identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerAnswer {
    /// Result-Code AVP value.
    pub result_code: u32,
    /// Origin-Host and Origin-Realm AVPs.
    pub identity: PeerIdentity,
}

/// Parsed Capabilities-Exchange-Answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilitiesExchangeAnswer {
    /// Result-Code AVP value.
    pub result_code: u32,
    /// Peer capabilities carried by the answer.
    pub capabilities: PeerCapabilities,
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
}

/// Capability intersection computed from two CER/CEA capability sets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityNegotiation {
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

/// Intersect two Diameter peer capability sets without making transport policy decisions.
pub fn negotiate_capabilities(
    local: &PeerCapabilities,
    remote: &PeerCapabilities,
) -> CapabilityNegotiation {
    CapabilityNegotiation {
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
    capabilities: &PeerCapabilities,
    result_code: u32,
    hop_by_hop_identifier: u32,
    end_to_end_identifier: u32,
    ctx: EncodeContext,
) -> Result<OwnedMessage, EncodeError> {
    let section = PeerProcedure::CapabilitiesExchange.spec_section(CommandKind::Answer);
    capabilities.validate_for_encode(section)?;
    let mut raw_avps = BytesMut::new();
    append_u32_avp(&mut raw_avps, AVP_RESULT_CODE, result_code, true, ctx)?;
    append_capability_avps(&mut raw_avps, capabilities, ctx, section)?;
    build_message(
        peer_answer_flags(PeerProcedure::CapabilitiesExchange, false),
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
    Ok(CapabilitiesExchangeAnswer {
        result_code,
        capabilities: avps.into_capabilities(section)?,
    })
}

/// Build a Device-Watchdog-Request message.
pub fn build_device_watchdog_request(
    identity: &PeerIdentity,
    hop_by_hop_identifier: u32,
    end_to_end_identifier: u32,
    ctx: EncodeContext,
) -> Result<OwnedMessage, EncodeError> {
    let section = PeerProcedure::DeviceWatchdog.spec_section(CommandKind::Request);
    identity.validate_for_encode(section)?;
    let mut raw_avps = BytesMut::new();
    append_identity_avps(&mut raw_avps, identity, ctx)?;
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
) -> Result<PeerIdentity, DecodeError> {
    let section = PeerProcedure::DeviceWatchdog.spec_section(CommandKind::Request);
    ensure_peer_header(message, PeerProcedure::DeviceWatchdog, CommandKind::Request)?;
    collect_procedure_avps(message.raw_avps, ctx, section)?.into_identity(section)
}

/// Build a Device-Watchdog-Answer message.
pub fn build_device_watchdog_answer(
    identity: &PeerIdentity,
    result_code: u32,
    hop_by_hop_identifier: u32,
    end_to_end_identifier: u32,
    ctx: EncodeContext,
) -> Result<OwnedMessage, EncodeError> {
    let section = PeerProcedure::DeviceWatchdog.spec_section(CommandKind::Answer);
    identity.validate_for_encode(section)?;
    let mut raw_avps = BytesMut::new();
    append_u32_avp(&mut raw_avps, AVP_RESULT_CODE, result_code, true, ctx)?;
    append_identity_avps(&mut raw_avps, identity, ctx)?;
    build_message(
        peer_answer_flags(PeerProcedure::DeviceWatchdog, false),
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
) -> Result<PeerAnswer, DecodeError> {
    let section = PeerProcedure::DeviceWatchdog.spec_section(CommandKind::Answer);
    ensure_peer_header(message, PeerProcedure::DeviceWatchdog, CommandKind::Answer)?;
    let avps = collect_procedure_avps(message.raw_avps, ctx, section)?;
    let result_code = require_field(
        avps.result_code.clone(),
        "diameter DWA requires Result-Code",
        section,
    )?;
    Ok(PeerAnswer {
        result_code,
        identity: avps.into_identity(section)?,
    })
}

/// Build a Disconnect-Peer-Request message.
pub fn build_disconnect_peer_request(
    identity: &PeerIdentity,
    disconnect_cause: DisconnectCause,
    hop_by_hop_identifier: u32,
    end_to_end_identifier: u32,
    ctx: EncodeContext,
) -> Result<OwnedMessage, EncodeError> {
    let section = PeerProcedure::DisconnectPeer.spec_section(CommandKind::Request);
    identity.validate_for_encode(section)?;
    let mut raw_avps = BytesMut::new();
    append_identity_avps(&mut raw_avps, identity, ctx)?;
    append_u32_avp(
        &mut raw_avps,
        AVP_DISCONNECT_CAUSE,
        disconnect_cause.value(),
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
        identity: avps.into_identity(section)?,
        disconnect_cause,
    })
}

/// Build a Disconnect-Peer-Answer message.
pub fn build_disconnect_peer_answer(
    identity: &PeerIdentity,
    result_code: u32,
    hop_by_hop_identifier: u32,
    end_to_end_identifier: u32,
    ctx: EncodeContext,
) -> Result<OwnedMessage, EncodeError> {
    let section = PeerProcedure::DisconnectPeer.spec_section(CommandKind::Answer);
    identity.validate_for_encode(section)?;
    let mut raw_avps = BytesMut::new();
    append_u32_avp(&mut raw_avps, AVP_RESULT_CODE, result_code, true, ctx)?;
    append_identity_avps(&mut raw_avps, identity, ctx)?;
    build_message(
        peer_answer_flags(PeerProcedure::DisconnectPeer, false),
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
) -> Result<PeerAnswer, DecodeError> {
    let section = PeerProcedure::DisconnectPeer.spec_section(CommandKind::Answer);
    ensure_peer_header(message, PeerProcedure::DisconnectPeer, CommandKind::Answer)?;
    let avps = collect_procedure_avps(message.raw_avps, ctx, section)?;
    let result_code = require_field(
        avps.result_code.clone(),
        "diameter DPA requires Result-Code",
        section,
    )?;
    Ok(PeerAnswer {
        result_code,
        identity: avps.into_identity(section)?,
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
    fn into_identity(self, section: &'static str) -> Result<PeerIdentity, DecodeError> {
        Ok(PeerIdentity {
            origin_host: require_field(
                self.origin_host,
                "diameter peer procedure requires Origin-Host",
                section,
            )?,
            origin_realm: require_field(
                self.origin_realm,
                "diameter peer procedure requires Origin-Realm",
                section,
            )?,
        })
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
            parsed
                .supported_vendor_ids
                .push(VendorId::new(parse_u32_value(
                    avp.value,
                    value_offset,
                    "5.3.6",
                )?));
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
                    offset,
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
    avp_offset: usize,
    value_offset: usize,
    section: &'static str,
) -> Result<VendorSpecificApplication, DecodeError> {
    let child_depth = 1;
    if child_depth > ctx.max_depth {
        return Err(DecodeError::new(DecodeErrorCode::DepthExceeded, avp_offset)
            .with_spec_ref(peer_spec(section)));
    }
    let mut vendor_ids = Vec::new();
    let mut auth_application_id = None;
    let mut acct_application_id = None;
    for_each_avp(
        avp.value,
        ctx,
        value_offset,
        child_depth,
        |offset, child| {
            let child_value_offset = offset_add(offset, child.header.header_len(), section)?;
            if child.header.vendor_id.is_some() {
                return handle_unknown_avp(ctx, &child, offset, section);
            }
            let code = child.header.code;
            if code == AVP_VENDOR_ID {
                vendor_ids.push(VendorId::new(parse_u32_value(
                    child.value,
                    child_value_offset,
                    "5.3.3",
                )?));
                Ok(())
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
    if vendor_ids.is_empty() {
        return Err(decode_structural_error(
            "diameter Vendor-Specific-Application-Id requires Vendor-Id",
            value_offset,
            section,
        ));
    }
    if auth_application_id.is_some() == acct_application_id.is_some() {
        return Err(decode_structural_error(
            "diameter Vendor-Specific-Application-Id requires exactly one Auth-Application-Id or Acct-Application-Id",
            value_offset,
            section,
        ));
    }
    Ok(VendorSpecificApplication {
        vendor_ids,
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
    let parsed = str::from_utf8(value).map_err(|_| {
        decode_structural_error(
            "diameter UTF-8 or DiameterIdentity AVP is not valid UTF-8",
            offset,
            section,
        )
    })?;
    if parsed.is_empty() {
        return Err(decode_structural_error(
            "diameter UTF-8 or DiameterIdentity AVP must not be empty",
            offset,
            section,
        ));
    }
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

fn common_copy<T: Copy + Eq>(local: &[T], remote: &[T]) -> Vec<T> {
    let mut common = Vec::new();
    for value in local {
        if remote.contains(value) && !common.contains(value) {
            common.push(*value);
        }
    }
    common
}

fn common_vendor_specific_applications(
    local: &[VendorSpecificApplication],
    remote: &[VendorSpecificApplication],
) -> Vec<VendorSpecificApplication> {
    let mut common = Vec::new();
    for local_application in local {
        for remote_application in remote {
            if local_application.auth_application_id == remote_application.auth_application_id
                && local_application.acct_application_id == remote_application.acct_application_id
            {
                let vendor_ids = common_copy(
                    &local_application.vendor_ids,
                    &remote_application.vendor_ids,
                );
                if !vendor_ids.is_empty() {
                    let candidate = VendorSpecificApplication {
                        vendor_ids,
                        auth_application_id: local_application.auth_application_id,
                        acct_application_id: local_application.acct_application_id,
                    };
                    if !common.contains(&candidate) {
                        common.push(candidate);
                    }
                }
            }
        }
    }
    common
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
    use crate::base::{INBAND_SECURITY_ID_NO_INBAND_SECURITY, RESULT_CODE_DIAMETER_SUCCESS};
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

        let built = match build_capabilities_exchange_answer(
            &remote,
            RESULT_CODE_DIAMETER_SUCCESS,
            0x10,
            0x20,
            EncodeContext::default(),
        ) {
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

        let negotiated = negotiate_capabilities(&local, &parsed.capabilities);
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
    }

    #[test]
    fn watchdog_and_disconnect_builders_parse_without_transport_state() {
        let identity = PeerIdentity::new("aaa2.example.net", "example.net");
        let dwr = match build_device_watchdog_request(&identity, 1, 2, EncodeContext::default()) {
            Ok(message) => message,
            Err(error) => panic!("DWR build failed: {error}"),
        };
        let encoded = encode_owned(&dwr);
        let message = decode_message(&encoded);
        match parse_device_watchdog_request(&message, DecodeContext::default()) {
            Ok(parsed) => assert_eq!(parsed, identity),
            Err(error) => panic!("DWR parse failed: {error}"),
        }

        let dwa = match build_device_watchdog_answer(
            &identity,
            RESULT_CODE_DIAMETER_SUCCESS,
            3,
            4,
            EncodeContext::default(),
        ) {
            Ok(message) => message,
            Err(error) => panic!("DWA build failed: {error}"),
        };
        let encoded = encode_owned(&dwa);
        let message = decode_message(&encoded);
        match parse_device_watchdog_answer(&message, DecodeContext::default()) {
            Ok(parsed) => {
                assert_eq!(parsed.identity, identity);
                assert_eq!(parsed.result_code, RESULT_CODE_DIAMETER_SUCCESS);
            }
            Err(error) => panic!("DWA parse failed: {error}"),
        }

        let dpr = match build_disconnect_peer_request(
            &identity,
            DisconnectCause::Busy,
            5,
            6,
            EncodeContext::default(),
        ) {
            Ok(message) => message,
            Err(error) => panic!("DPR build failed: {error}"),
        };
        let encoded = encode_owned(&dpr);
        let message = decode_message(&encoded);
        match parse_disconnect_peer_request(&message, DecodeContext::default()) {
            Ok(parsed) => {
                assert_eq!(parsed.identity, identity);
                assert_eq!(parsed.disconnect_cause, DisconnectCause::Busy);
            }
            Err(error) => panic!("DPR parse failed: {error}"),
        }

        let dpa = match build_disconnect_peer_answer(
            &identity,
            RESULT_CODE_DIAMETER_SUCCESS,
            7,
            8,
            EncodeContext::default(),
        ) {
            Ok(message) => message,
            Err(error) => panic!("DPA build failed: {error}"),
        };
        let encoded = encode_owned(&dpa);
        let message = decode_message(&encoded);
        match parse_disconnect_peer_answer(&message, DecodeContext::default()) {
            Ok(parsed) => {
                assert_eq!(parsed.identity, identity);
                assert_eq!(parsed.result_code, RESULT_CODE_DIAMETER_SUCCESS);
            }
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
        let message = Message {
            header: built.header.clone(),
            raw_avps: &built.raw_avps,
            tail: &[],
        };
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
}
