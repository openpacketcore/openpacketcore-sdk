//! Typed GTP-U path and tunnel-management messages.
//!
//! The models in this module deliberately stop at the protocol boundary.
//! UDP tuple selection, peer admission, rate limiting, tunnel lookup, and the
//! decision to send an End Marker remain consumer responsibilities.
//!
//! The implemented clauses are TS 29.281 Release 18 §5.1, §5.2.1,
//! §5.2.2.1, §7.2.1-§7.2.3, §7.3.1-§7.3.2, §8.1-§8.6, and §8.8.
//! Tunnel Status (§7.3.3 and §8.7) is explicitly not implemented by this
//! module.
//!
//! @spec 3GPP TS29281 R18 5.1, 5.2.1, 5.2.2.1, 7.2.1-7.2.3, 7.3.1-7.3.2, 8.1-8.6, 8.8
//! @req REQ-3GPP-TS29281-R18-CONTROL-CODEC-001
//! @conformance control-codec-subset

use std::{
    borrow::Cow,
    error::Error,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZeroU32,
};

use bytes::{BufMut, Bytes, BytesMut};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeError, DecodeErrorCode, Encode, EncodeContext,
    UnknownIePolicy, ValidationLevel,
};

use crate::{
    GtpuExtensionChain, GtpuExtensionChainError, GtpuExtensionChainMalformedReason,
    GtpuExtensionHeaderRecipient, GtpuExtensionHeaderType, GtpuHeader, GtpuMessage,
    PduSessionContainer, PduSessionContainerError, GTPU_EXT_PDU_SESSION_CONTAINER,
    GTPU_EXT_UDP_PORT,
};

/// GTP-U Echo Request message type.
pub const GTPU_MESSAGE_ECHO_REQUEST: u8 = 1;
/// GTP-U Echo Response message type.
pub const GTPU_MESSAGE_ECHO_RESPONSE: u8 = 2;
/// GTP-U Error Indication message type.
pub const GTPU_MESSAGE_ERROR_INDICATION: u8 = 26;
/// GTP-U Supported Extension Headers Notification message type.
pub const GTPU_MESSAGE_SUPPORTED_EXTENSION_HEADERS_NOTIFICATION: u8 = 31;
/// GTP-U End Marker message type.
pub const GTPU_MESSAGE_END_MARKER: u8 = 254;

const IE_RECOVERY: u8 = 14;
const IE_TEID_DATA_I: u8 = 16;
const IE_GTPU_PEER_ADDRESS: u8 = 133;
const IE_EXTENSION_HEADER_TYPE_LIST: u8 = 141;
const IE_GTPU_TUNNEL_STATUS: u8 = 230;
const IE_RECOVERY_TIME_STAMP: u8 = 231;
const IE_PRIVATE_EXTENSION: u8 = 255;
const MAX_CONTROL_IES: usize = 256;

/// Stable, redaction-safe GTP-U control-codec failure classification.
///
/// Type identifiers are protocol metadata and may be reported. Packet bytes,
/// TEIDs, peer addresses, and private-extension values are never retained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GtpuControlCodecErrorCode {
    /// The generic GTP-U frame could not be decoded.
    Framing {
        /// Redaction-safe generic framing classification.
        code: DecodeErrorCode,
    },
    /// The message type is not one of the typed control procedures.
    UnsupportedMessageType,
    /// Bytes followed the one declared GTP-U datagram boundary.
    TrailingBytes,
    /// Header flags violate the selected control procedure.
    InvalidHeaderFlags,
    /// The header TEID violates the selected control procedure.
    InvalidHeaderTeid,
    /// An unsupported extension requires comprehension by an endpoint.
    UnsupportedRequiredExtension {
        /// Extension-header type from the packet.
        extension_type: u8,
    },
    /// A known extension header is not valid for this control procedure.
    UnexpectedExtension {
        /// Extension-header type from the packet.
        extension_type: u8,
    },
    /// An extension header has a procedure-invalid content length.
    InvalidExtensionLength,
    /// The raw extension chain is structurally malformed.
    MalformedExtensionChain {
        /// Stable structural reason without packet bytes.
        reason: GtpuExtensionChainMalformedReason,
    },
    /// A PDU Session Container is outside the supported complete subset.
    MalformedPduSessionContainer {
        /// Stable semantic reason without packet values.
        reason: PduSessionContainerError,
    },
    /// More than one PDU Session Container was present.
    DuplicatePduSessionContainer,
    /// The IE list ended inside a fixed or declared-width IE.
    TruncatedIe,
    /// A TLV or known fixed-width IE has an invalid length.
    InvalidIeLength {
        /// Information-element type from the packet.
        ie_type: u8,
    },
    /// A TV-format IE is unknown, so its boundary cannot be skipped safely.
    UnknownTvIe {
        /// Information-element type from the packet.
        ie_type: u8,
    },
    /// An unknown TLV was rejected by the decode policy.
    UnknownIe {
        /// Information-element type from the packet.
        ie_type: u8,
    },
    /// A known IE is not valid for this control procedure.
    UnexpectedIe {
        /// Information-element type from the packet.
        ie_type: u8,
    },
    /// A singleton IE occurred more than once.
    DuplicateIe {
        /// Information-element type from the packet.
        ie_type: u8,
    },
    /// A mandatory IE was absent.
    MissingMandatoryIe {
        /// Information-element type required by the procedure.
        ie_type: u8,
    },
    /// Signalling IEs were not sorted by ascending type.
    IesOutOfOrder,
    /// The configured IE-count bound was exceeded.
    IeCountExceeded,
    /// An IE value violates its semantic constraints.
    InvalidIeValue {
        /// Information-element type containing the invalid value.
        ie_type: u8,
    },
    /// A builder-owned model violates an encoding invariant.
    InvalidModel,
    /// Checked length arithmetic overflowed.
    LengthOverflow,
    /// The encoded message exceeds the requested output capacity.
    CapacityExceeded,
}

impl GtpuControlCodecErrorCode {
    /// Stable machine-readable code.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Framing { .. } => "gtpu_control_framing",
            Self::UnsupportedMessageType => "gtpu_control_unsupported_message_type",
            Self::TrailingBytes => "gtpu_control_trailing_bytes",
            Self::InvalidHeaderFlags => "gtpu_control_invalid_header_flags",
            Self::InvalidHeaderTeid => "gtpu_control_invalid_header_teid",
            Self::UnsupportedRequiredExtension { .. } => {
                "gtpu_control_unsupported_required_extension"
            }
            Self::UnexpectedExtension { .. } => "gtpu_control_unexpected_extension",
            Self::InvalidExtensionLength => "gtpu_control_invalid_extension_length",
            Self::MalformedExtensionChain { .. } => "gtpu_control_malformed_extension_chain",
            Self::MalformedPduSessionContainer { .. } => {
                "gtpu_control_malformed_pdu_session_container"
            }
            Self::DuplicatePduSessionContainer => "gtpu_control_duplicate_pdu_session_container",
            Self::TruncatedIe => "gtpu_control_truncated_ie",
            Self::InvalidIeLength { .. } => "gtpu_control_invalid_ie_length",
            Self::UnknownTvIe { .. } => "gtpu_control_unknown_tv_ie",
            Self::UnknownIe { .. } => "gtpu_control_unknown_ie",
            Self::UnexpectedIe { .. } => "gtpu_control_unexpected_ie",
            Self::DuplicateIe { .. } => "gtpu_control_duplicate_ie",
            Self::MissingMandatoryIe { .. } => "gtpu_control_missing_mandatory_ie",
            Self::IesOutOfOrder => "gtpu_control_ies_out_of_order",
            Self::IeCountExceeded => "gtpu_control_ie_count_exceeded",
            Self::InvalidIeValue { .. } => "gtpu_control_invalid_ie_value",
            Self::InvalidModel => "gtpu_control_invalid_model",
            Self::LengthOverflow => "gtpu_control_length_overflow",
            Self::CapacityExceeded => "gtpu_control_capacity_exceeded",
        }
    }
}

/// Redaction-safe error returned by the typed GTP-U control codec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GtpuControlCodecError {
    code: GtpuControlCodecErrorCode,
    offset: usize,
}

impl GtpuControlCodecError {
    fn new(code: GtpuControlCodecErrorCode, offset: usize) -> Self {
        Self { code, offset }
    }

    /// Stable failure classification.
    #[must_use]
    pub const fn code(&self) -> &GtpuControlCodecErrorCode {
        &self.code
    }

    /// Zero-based byte offset from the start of the GTP-U datagram.
    ///
    /// A missing mandatory IE reports the end of the declared datagram.
    /// Model and encoding failures, which have no input datagram, report zero.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// Stable machine-readable code.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        self.code.as_str()
    }
}

impl fmt::Display for GtpuControlCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.code {
            GtpuControlCodecErrorCode::MalformedExtensionChain { reason } => write!(
                formatter,
                "{}: {} at offset {}",
                self.as_str(),
                reason.as_str(),
                self.offset
            ),
            GtpuControlCodecErrorCode::MalformedPduSessionContainer { reason } => write!(
                formatter,
                "{}: {} at offset {}",
                self.as_str(),
                reason.as_str(),
                self.offset
            ),
            _ => write!(formatter, "{} at offset {}", self.as_str(), self.offset),
        }
    }
}

impl Error for GtpuControlCodecError {}

/// Redaction-safe GTP-U tunnel endpoint identifier.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GtpuTunnelEndpointId(u32);

impl GtpuTunnelEndpointId {
    /// Construct a TEID, including zero for backward-compatible tunnel peers.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Return the on-wire value.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }
}

impl fmt::Debug for GtpuTunnelEndpointId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GtpuTunnelEndpointId(<redacted>)")
    }
}

/// Recovery IE for GTP-U Echo Response.
///
/// TS 29.281 requires senders to encode zero and receivers to ignore the
/// received counter, so the typed model intentionally carries no counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GtpuRecovery;

/// Optional Recovery Time Stamp IE.
#[derive(Clone, PartialEq, Eq)]
pub struct GtpuRecoveryTimeStamp {
    seconds_since_1900: u32,
    additional_data: Bytes,
}

impl GtpuRecoveryTimeStamp {
    /// Construct the canonical standardized four-octet timestamp value.
    ///
    /// Future extension bytes can only enter this model through decoding and
    /// are retained solely so an accepted received IE can be re-encoded.
    #[must_use]
    pub fn new(seconds_since_1900: u32) -> Self {
        Self {
            seconds_since_1900,
            additional_data: Bytes::new(),
        }
    }

    fn from_received(seconds_since_1900: u32, additional_data: Bytes) -> Self {
        Self {
            seconds_since_1900,
            additional_data,
        }
    }

    /// Seconds since 1900-01-01 in NTP timestamp format.
    #[must_use]
    pub const fn seconds_since_1900(&self) -> u32 {
        self.seconds_since_1900
    }

    /// Received future-extension bytes following the standardized timestamp.
    ///
    /// Canonically constructed values always return an empty slice.
    #[must_use]
    pub fn additional_data(&self) -> &[u8] {
        &self.additional_data
    }
}

impl fmt::Debug for GtpuRecoveryTimeStamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GtpuRecoveryTimeStamp")
            .field("seconds_since_1900", &"<redacted>")
            .field("additional_data_len", &self.additional_data.len())
            .finish()
    }
}

/// Optional Private Extension IE.
#[derive(Clone, PartialEq, Eq)]
pub struct GtpuPrivateExtension {
    extension_identifier: u16,
    value: Bytes,
}

impl GtpuPrivateExtension {
    /// Construct a private extension.
    #[must_use]
    pub fn new(extension_identifier: u16, value: Bytes) -> Self {
        Self {
            extension_identifier,
            value,
        }
    }

    /// IANA private-enterprise extension identifier.
    #[must_use]
    pub const fn extension_identifier(&self) -> u16 {
        self.extension_identifier
    }

    /// Opaque vendor value.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

impl fmt::Debug for GtpuPrivateExtension {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GtpuPrivateExtension")
            .field("extension_identifier", &self.extension_identifier)
            .field("value_len", &self.value.len())
            .finish()
    }
}

/// Preserved unknown TLV IE.
#[derive(Clone, PartialEq, Eq)]
pub struct GtpuUnknownControlIe {
    ie_type: u8,
    value: Bytes,
}

impl GtpuUnknownControlIe {
    /// Unknown TLV type.
    #[must_use]
    pub const fn ie_type(&self) -> u8 {
        self.ie_type
    }

    /// Preserved value bytes.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

impl fmt::Debug for GtpuUnknownControlIe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GtpuUnknownControlIe")
            .field("ie_type", &self.ie_type)
            .field("value_len", &self.value.len())
            .finish()
    }
}

/// GTP-U Peer Address IE with redacted diagnostics.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct GtpuPeerAddress(IpAddr);

impl GtpuPeerAddress {
    /// Construct a peer-address IE.
    #[must_use]
    pub const fn new(address: IpAddr) -> Self {
        Self(address)
    }

    /// Return the address for transport/session correlation.
    #[must_use]
    pub const fn address(self) -> IpAddr {
        self.0
    }
}

impl fmt::Debug for GtpuPeerAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            IpAddr::V4(_) => formatter.write_str("GtpuPeerAddress::V4(<redacted>)"),
            IpAddr::V6(_) => formatter.write_str("GtpuPeerAddress::V6(<redacted>)"),
        }
    }
}

/// Duplicate-free supported extension-header type list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GtpuExtensionHeaderTypeList(Vec<GtpuExtensionHeaderType>);

impl GtpuExtensionHeaderTypeList {
    /// Validate and construct a supported-type list.
    ///
    /// # Errors
    ///
    /// Returns [`GtpuControlCodecError`] for a zero (terminal) type, a
    /// duplicate, or more entries than the non-zero `u8` type domain. An empty
    /// list is valid: TS 29.281 §8.5 defines a list of `n` types and does not
    /// require `n` to be positive.
    pub fn new(
        types: impl IntoIterator<Item = GtpuExtensionHeaderType>,
    ) -> Result<Self, GtpuControlCodecError> {
        let mut bounded_types = Vec::new();
        let mut seen = [false; 256];
        for header_type in types {
            let value = header_type.value();
            if value == 0 || seen[usize::from(value)] || bounded_types.len() == u8::MAX as usize {
                return Err(invalid_value(IE_EXTENSION_HEADER_TYPE_LIST, 0));
            }
            seen[usize::from(value)] = true;
            bounded_types.push(header_type);
        }
        Ok(Self(bounded_types))
    }

    /// Supported extension types in received or builder-supplied order.
    #[must_use]
    pub fn as_slice(&self) -> &[GtpuExtensionHeaderType] {
        &self.0
    }
}

#[derive(Clone, PartialEq, Eq, Default)]
struct OptionalControlIes {
    recovery_time_stamp: Option<GtpuRecoveryTimeStamp>,
    private_extensions: Vec<GtpuPrivateExtension>,
    unknown_ies: Vec<GtpuUnknownControlIe>,
}

impl fmt::Debug for OptionalControlIes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OptionalControlIes")
            .field("recovery_time_stamp", &self.recovery_time_stamp)
            .field("private_extension_count", &self.private_extensions.len())
            .field("unknown_ie_count", &self.unknown_ies.len())
            .finish()
    }
}

/// Typed Echo Request.
#[derive(Clone, PartialEq, Eq)]
pub struct GtpuEchoRequest {
    sequence_number: u16,
    optional: OptionalControlIes,
    extensions: GtpuExtensionChain,
}

impl GtpuEchoRequest {
    /// Construct an Echo Request using a path-scoped sequence number.
    #[must_use]
    pub fn new(sequence_number: u16) -> Self {
        Self {
            sequence_number,
            optional: OptionalControlIes::default(),
            extensions: GtpuExtensionChain::none(),
        }
    }

    /// Sequence number that an Echo Response must copy.
    #[must_use]
    pub const fn sequence_number(&self) -> u16 {
        self.sequence_number
    }

    /// Set the optional Recovery Time Stamp.
    #[must_use]
    pub fn with_recovery_time_stamp(mut self, value: GtpuRecoveryTimeStamp) -> Self {
        self.optional.recovery_time_stamp = Some(value);
        self
    }

    /// Append a repeatable Private Extension.
    pub fn push_private_extension(&mut self, value: GtpuPrivateExtension) {
        self.optional.private_extensions.push(value);
    }

    /// Optional Recovery Time Stamp.
    #[must_use]
    pub const fn recovery_time_stamp(&self) -> Option<&GtpuRecoveryTimeStamp> {
        self.optional.recovery_time_stamp.as_ref()
    }

    /// Private Extensions in received/builder order.
    #[must_use]
    pub fn private_extensions(&self) -> &[GtpuPrivateExtension] {
        &self.optional.private_extensions
    }

    /// Unknown TLVs preserved by the decode policy.
    #[must_use]
    pub fn unknown_ies(&self) -> &[GtpuUnknownControlIe] {
        &self.optional.unknown_ies
    }

    /// Raw-preserved extension-header chain.
    #[must_use]
    pub const fn extension_chain(&self) -> &GtpuExtensionChain {
        &self.extensions
    }
}

impl fmt::Debug for GtpuEchoRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GtpuEchoRequest")
            .field("sequence_number", &self.sequence_number)
            .field("optional", &self.optional)
            .field("extensions", &self.extensions)
            .finish()
    }
}

/// Typed Echo Response.
#[derive(Clone, PartialEq, Eq)]
pub struct GtpuEchoResponse {
    sequence_number: u16,
    recovery: GtpuRecovery,
    optional: OptionalControlIes,
    extensions: GtpuExtensionChain,
}

impl GtpuEchoResponse {
    /// Construct an Echo Response with the mandatory canonical `Recovery=0`.
    #[must_use]
    pub fn new(sequence_number: u16) -> Self {
        Self {
            sequence_number,
            recovery: GtpuRecovery,
            optional: OptionalControlIes::default(),
            extensions: GtpuExtensionChain::none(),
        }
    }

    /// Construct a response that copies an Echo Request sequence number.
    #[must_use]
    pub fn for_request(request: &GtpuEchoRequest) -> Self {
        Self::new(request.sequence_number())
    }

    /// Copied request sequence number.
    #[must_use]
    pub const fn sequence_number(&self) -> u16 {
        self.sequence_number
    }

    /// Mandatory Recovery IE. Its canonical wire value is always zero.
    #[must_use]
    pub const fn recovery(&self) -> GtpuRecovery {
        self.recovery
    }

    /// Set the optional Recovery Time Stamp.
    #[must_use]
    pub fn with_recovery_time_stamp(mut self, value: GtpuRecoveryTimeStamp) -> Self {
        self.optional.recovery_time_stamp = Some(value);
        self
    }

    /// Append a repeatable Private Extension.
    pub fn push_private_extension(&mut self, value: GtpuPrivateExtension) {
        self.optional.private_extensions.push(value);
    }

    /// Unknown TLVs preserved by the decode policy.
    #[must_use]
    pub fn unknown_ies(&self) -> &[GtpuUnknownControlIe] {
        &self.optional.unknown_ies
    }

    /// Optional Recovery Time Stamp.
    #[must_use]
    pub const fn recovery_time_stamp(&self) -> Option<&GtpuRecoveryTimeStamp> {
        self.optional.recovery_time_stamp.as_ref()
    }

    /// Private Extensions in received/builder order.
    #[must_use]
    pub fn private_extensions(&self) -> &[GtpuPrivateExtension] {
        &self.optional.private_extensions
    }

    /// Raw-preserved extension-header chain.
    #[must_use]
    pub const fn extension_chain(&self) -> &GtpuExtensionChain {
        &self.extensions
    }
}

impl fmt::Debug for GtpuEchoResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GtpuEchoResponse")
            .field("sequence_number", &self.sequence_number)
            .field("recovery", &self.recovery)
            .field("optional", &self.optional)
            .field("extensions", &self.extensions)
            .finish()
    }
}

/// Typed Error Indication.
#[derive(Clone, PartialEq, Eq)]
pub struct GtpuErrorIndication {
    teid_data_i: GtpuTunnelEndpointId,
    peer_address: GtpuPeerAddress,
    triggering_udp_source_port: Option<u16>,
    optional: OptionalControlIes,
    extensions: GtpuExtensionChain,
}

impl GtpuErrorIndication {
    /// Construct an Error Indication for the non-zero TEID from the triggering
    /// G-PDU and that packet's destination GTP-U address.
    #[must_use]
    pub fn new(teid_data_i: NonZeroU32, peer_address: IpAddr) -> Self {
        Self {
            teid_data_i: GtpuTunnelEndpointId::new(teid_data_i.get()),
            peer_address: GtpuPeerAddress::new(peer_address),
            triggering_udp_source_port: None,
            optional: OptionalControlIes::default(),
            extensions: GtpuExtensionChain::none(),
        }
    }

    /// Add or replace the optional UDP Port extension header from the
    /// triggering G-PDU while retaining unrelated decoded extension headers.
    ///
    /// # Errors
    ///
    /// Returns [`GtpuExtensionChainError`] if the retained extension chain is
    /// inconsistent and therefore cannot be mutated safely.
    pub fn with_triggering_udp_source_port(
        mut self,
        port: u16,
    ) -> Result<Self, GtpuExtensionChainError> {
        self.extensions = self.extensions.upsert_udp_port(port)?;
        self.triggering_udp_source_port = Some(port);
        Ok(self)
    }

    /// TEID Data I copied from the triggering G-PDU.
    #[must_use]
    pub const fn teid_data_i(&self) -> GtpuTunnelEndpointId {
        self.teid_data_i
    }

    /// Destination GTP-U address copied from the triggering G-PDU.
    #[must_use]
    pub const fn peer_address(&self) -> GtpuPeerAddress {
        self.peer_address
    }

    /// Optional triggering UDP source port.
    #[must_use]
    pub const fn triggering_udp_source_port(&self) -> Option<u16> {
        self.triggering_udp_source_port
    }

    /// Set the optional Recovery Time Stamp.
    #[must_use]
    pub fn with_recovery_time_stamp(mut self, value: GtpuRecoveryTimeStamp) -> Self {
        self.optional.recovery_time_stamp = Some(value);
        self
    }

    /// Append a repeatable Private Extension.
    pub fn push_private_extension(&mut self, value: GtpuPrivateExtension) {
        self.optional.private_extensions.push(value);
    }

    /// Unknown TLVs preserved by the decode policy.
    #[must_use]
    pub fn unknown_ies(&self) -> &[GtpuUnknownControlIe] {
        &self.optional.unknown_ies
    }

    /// Optional Recovery Time Stamp.
    #[must_use]
    pub const fn recovery_time_stamp(&self) -> Option<&GtpuRecoveryTimeStamp> {
        self.optional.recovery_time_stamp.as_ref()
    }

    /// Private Extensions in received/builder order.
    #[must_use]
    pub fn private_extensions(&self) -> &[GtpuPrivateExtension] {
        &self.optional.private_extensions
    }

    /// Raw-preserved extension-header chain.
    #[must_use]
    pub const fn extension_chain(&self) -> &GtpuExtensionChain {
        &self.extensions
    }
}

impl fmt::Debug for GtpuErrorIndication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GtpuErrorIndication")
            .field("teid_data_i", &self.teid_data_i)
            .field("peer_address", &self.peer_address)
            .field(
                "triggering_udp_source_port_present",
                &self.triggering_udp_source_port.is_some(),
            )
            .field("optional", &self.optional)
            .field("extensions", &self.extensions)
            .finish()
    }
}

/// Typed Supported Extension Headers Notification.
#[derive(Clone, PartialEq, Eq)]
pub struct GtpuSupportedExtensionHeadersNotification {
    supported_types: GtpuExtensionHeaderTypeList,
    private_extensions: Vec<GtpuPrivateExtension>,
    unknown_ies: Vec<GtpuUnknownControlIe>,
    extensions: GtpuExtensionChain,
}

impl GtpuSupportedExtensionHeadersNotification {
    /// Construct the notification with its supported-type list.
    #[must_use]
    pub fn new(supported_types: GtpuExtensionHeaderTypeList) -> Self {
        Self {
            supported_types,
            private_extensions: Vec::new(),
            unknown_ies: Vec::new(),
            extensions: GtpuExtensionChain::none(),
        }
    }

    /// Supported extension-header types.
    #[must_use]
    pub const fn supported_types(&self) -> &GtpuExtensionHeaderTypeList {
        &self.supported_types
    }

    /// Append a repeatable Private Extension.
    pub fn push_private_extension(&mut self, value: GtpuPrivateExtension) {
        self.private_extensions.push(value);
    }

    /// Unknown TLVs preserved by the decode policy.
    #[must_use]
    pub fn unknown_ies(&self) -> &[GtpuUnknownControlIe] {
        &self.unknown_ies
    }

    /// Private Extensions in received/builder order.
    #[must_use]
    pub fn private_extensions(&self) -> &[GtpuPrivateExtension] {
        &self.private_extensions
    }

    /// Raw-preserved extension-header chain.
    #[must_use]
    pub const fn extension_chain(&self) -> &GtpuExtensionChain {
        &self.extensions
    }
}

impl fmt::Debug for GtpuSupportedExtensionHeadersNotification {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GtpuSupportedExtensionHeadersNotification")
            .field("supported_types", &self.supported_types)
            .field("private_extension_count", &self.private_extensions.len())
            .field("unknown_ie_count", &self.unknown_ies.len())
            .field("extensions", &self.extensions)
            .finish()
    }
}

/// Typed End Marker.
#[derive(Clone, PartialEq, Eq)]
pub struct GtpuEndMarker {
    teid: GtpuTunnelEndpointId,
    private_extensions: Vec<GtpuPrivateExtension>,
    unknown_ies: Vec<GtpuUnknownControlIe>,
    extensions: GtpuExtensionChain,
}

impl GtpuEndMarker {
    /// Construct an End Marker for a tunnel.
    #[must_use]
    pub fn new(teid: GtpuTunnelEndpointId) -> Self {
        Self {
            teid,
            private_extensions: Vec::new(),
            unknown_ies: Vec::new(),
            extensions: GtpuExtensionChain::none(),
        }
    }

    /// Tunnel whose payload stream has ended.
    #[must_use]
    pub const fn teid(&self) -> GtpuTunnelEndpointId {
        self.teid
    }

    /// Attach the standardized PDU Session Container extension used by an
    /// applicable 5GS End Marker.
    ///
    /// This typed builder cannot attach the UDP Port extension or arbitrary
    /// procedure-inapplicable extension headers. It places the container first
    /// while retaining unrelated optional unknown headers in their relative
    /// order, and rebuilds the container from its typed value so sender-spare
    /// bits are zero.
    ///
    /// # Errors
    ///
    /// Returns [`GtpuExtensionChainError`] if the container is invalid or the
    /// retained chain cannot be safely rebuilt as a structurally valid GTP-U
    /// extension-header chain.
    pub fn with_pdu_session_container(
        mut self,
        container: PduSessionContainer,
    ) -> Result<Self, GtpuExtensionChainError> {
        self.extensions = self.extensions.upsert_pdu_session_container(&container)?;
        Ok(self)
    }

    /// Append a repeatable Private Extension.
    pub fn push_private_extension(&mut self, value: GtpuPrivateExtension) {
        self.private_extensions.push(value);
    }

    /// Unknown TLVs preserved by the decode policy.
    #[must_use]
    pub fn unknown_ies(&self) -> &[GtpuUnknownControlIe] {
        &self.unknown_ies
    }

    /// Private Extensions in received/builder order.
    #[must_use]
    pub fn private_extensions(&self) -> &[GtpuPrivateExtension] {
        &self.private_extensions
    }

    /// Raw-preserved extension-header chain.
    #[must_use]
    pub const fn extension_chain(&self) -> &GtpuExtensionChain {
        &self.extensions
    }
}

impl fmt::Debug for GtpuEndMarker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GtpuEndMarker")
            .field("teid", &self.teid)
            .field("private_extension_count", &self.private_extensions.len())
            .field("unknown_ie_count", &self.unknown_ies.len())
            .field("extensions", &self.extensions)
            .finish()
    }
}

/// Typed GTP-U control message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GtpuControlMessage {
    /// Echo Request path-management message.
    EchoRequest(GtpuEchoRequest),
    /// Echo Response path-management message.
    EchoResponse(GtpuEchoResponse),
    /// Error Indication tunnel-management message.
    ErrorIndication(GtpuErrorIndication),
    /// Supported Extension Headers Notification path-management message.
    SupportedExtensionHeadersNotification(GtpuSupportedExtensionHeadersNotification),
    /// End Marker tunnel-management message.
    EndMarker(GtpuEndMarker),
}

/// A generic frame that has crossed the typed network-receive boundary.
///
/// Construction reapplies the caller's hard decode limits and all generic
/// frame invariants that a public `GtpuMessage` can otherwise bypass. The
/// received TS 29.281 spare bit is deliberately not a sender-canonicality
/// check at this boundary.
struct ValidatedControlFrame {
    message_type: u8,
    payload_base: usize,
    message_end: usize,
    extensions: GtpuExtensionChain,
    udp_port: Option<(u16, usize)>,
}

impl ValidatedControlFrame {
    fn new(message: &GtpuMessage<'_>, ctx: DecodeContext) -> Result<Self, GtpuControlCodecError> {
        let (payload_base, message_end) = validate_generic_frame_model(message, ctx)?;
        let message_type = message.header.message_type;
        if !matches!(
            message_type,
            GTPU_MESSAGE_ECHO_REQUEST
                | GTPU_MESSAGE_ECHO_RESPONSE
                | GTPU_MESSAGE_ERROR_INDICATION
                | GTPU_MESSAGE_SUPPORTED_EXTENSION_HEADERS_NOTIFICATION
                | GTPU_MESSAGE_END_MARKER
        ) {
            return Err(GtpuControlCodecError::new(
                GtpuControlCodecErrorCode::UnsupportedMessageType,
                1,
            ));
        }

        let (extensions, udp_port) = parse_extensions(message, message_type, ctx)?;
        Ok(Self {
            message_type,
            payload_base,
            message_end,
            extensions,
            udp_port,
        })
    }
}

impl GtpuControlMessage {
    /// Decode one typed GTP-U control message and return any following bytes.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe typed error for malformed framing, invalid
    /// procedure flags/cardinality, unsupported comprehension-required
    /// extensions, or malformed IEs.
    pub fn decode(
        input: &[u8],
        ctx: DecodeContext,
    ) -> Result<(&[u8], Self), GtpuControlCodecError> {
        let mut frame_ctx = ctx;
        frame_ctx.unknown_ie_policy = UnknownIePolicy::Preserve;
        // TS 29.281 §5.1 tells network receivers to ignore the spare bit. Use
        // the generic structural parser here, then reapply the caller's hard
        // limits and typed semantic checks at `ValidatedControlFrame` below.
        // Generic Strict decode remains available as a sender-canonicality
        // profile and continues to require the spare bit to be zero.
        frame_ctx.validation_level = ValidationLevel::Structural;
        let (tail, message) = GtpuMessage::decode(input, frame_ctx)
            .map_err(|error| framing(error.code().clone(), error.offset()))?;
        let control = Self::from_message(&message, ctx)?;
        Ok((tail, control))
    }

    /// Decode exactly one complete GTP-U control datagram.
    ///
    /// Unlike [`Self::decode`], this datagram boundary rejects bytes following
    /// the GTP-U Length field instead of returning them as a stream tail.
    ///
    /// # Errors
    ///
    /// Returns the same typed failures as [`Self::decode`] and
    /// [`GtpuControlCodecErrorCode::TrailingBytes`] for an overlong datagram.
    pub fn decode_datagram(
        input: &[u8],
        ctx: DecodeContext,
    ) -> Result<Self, GtpuControlCodecError> {
        let (tail, message) = Self::decode(input, ctx)?;
        if !tail.is_empty() {
            return Err(GtpuControlCodecError::new(
                GtpuControlCodecErrorCode::TrailingBytes,
                input.len().saturating_sub(tail.len()),
            ));
        }
        Ok(message)
    }

    /// Convert a structurally decoded GTP-U frame into a typed control model.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the frame is not a supported control
    /// procedure or violates its header, extension, or IE contract.
    pub fn from_message(
        message: &GtpuMessage<'_>,
        ctx: DecodeContext,
    ) -> Result<Self, GtpuControlCodecError> {
        let validated = ValidatedControlFrame::new(message, ctx)?;
        let ValidatedControlFrame {
            message_type,
            payload_base,
            message_end,
            extensions,
            udp_port,
        } = validated;
        let parsed = parse_ies(message.payload, payload_base, ctx)?;

        match message_type {
            GTPU_MESSAGE_ECHO_REQUEST => {
                validate_zero_teid_and_sequence(message)?;
                reject_udp_port(udp_port)?;
                reject_unexpected(&parsed, &[IE_RECOVERY_TIME_STAMP, IE_PRIVATE_EXTENSION])?;
                Ok(Self::EchoRequest(GtpuEchoRequest {
                    sequence_number: required_sequence(message)?,
                    optional: parsed.into_optional(),
                    extensions,
                }))
            }
            GTPU_MESSAGE_ECHO_RESPONSE => {
                validate_zero_teid_and_sequence(message)?;
                reject_udp_port(udp_port)?;
                reject_unexpected(
                    &parsed,
                    &[IE_RECOVERY, IE_RECOVERY_TIME_STAMP, IE_PRIVATE_EXTENSION],
                )?;
                if !parsed.recovery {
                    return Err(missing(IE_RECOVERY, message_end));
                }
                Ok(Self::EchoResponse(GtpuEchoResponse {
                    sequence_number: required_sequence(message)?,
                    recovery: GtpuRecovery,
                    optional: parsed.into_optional(),
                    extensions,
                }))
            }
            GTPU_MESSAGE_ERROR_INDICATION => {
                validate_zero_teid_and_sequence(message)?;
                reject_unexpected(
                    &parsed,
                    &[
                        IE_TEID_DATA_I,
                        IE_GTPU_PEER_ADDRESS,
                        IE_RECOVERY_TIME_STAMP,
                        IE_PRIVATE_EXTENSION,
                    ],
                )?;
                let teid_data_i = parsed
                    .teid_data_i
                    .ok_or_else(|| missing(IE_TEID_DATA_I, message_end))?;
                if teid_data_i.value() == 0 {
                    return Err(invalid_value(
                        IE_TEID_DATA_I,
                        parsed.offset_of(IE_TEID_DATA_I).unwrap_or(payload_base),
                    ));
                }
                let peer_address = parsed
                    .peer_address
                    .ok_or_else(|| missing(IE_GTPU_PEER_ADDRESS, message_end))?;
                Ok(Self::ErrorIndication(GtpuErrorIndication {
                    teid_data_i,
                    peer_address,
                    triggering_udp_source_port: udp_port.map(|(port, _)| port),
                    optional: parsed.into_optional(),
                    extensions,
                }))
            }
            GTPU_MESSAGE_SUPPORTED_EXTENSION_HEADERS_NOTIFICATION => {
                validate_zero_teid_and_sequence(message)?;
                reject_udp_port(udp_port)?;
                reject_unexpected(
                    &parsed,
                    &[IE_EXTENSION_HEADER_TYPE_LIST, IE_PRIVATE_EXTENSION],
                )?;
                let supported_types = parsed
                    .extension_header_type_list
                    .ok_or_else(|| missing(IE_EXTENSION_HEADER_TYPE_LIST, message_end))?;
                Ok(Self::SupportedExtensionHeadersNotification(
                    GtpuSupportedExtensionHeadersNotification {
                        supported_types,
                        private_extensions: parsed.private_extensions,
                        unknown_ies: parsed.unknown_ies,
                        extensions,
                    },
                ))
            }
            GTPU_MESSAGE_END_MARKER => {
                if message.header.seq_num_flag {
                    return Err(GtpuControlCodecError::new(
                        GtpuControlCodecErrorCode::InvalidHeaderFlags,
                        0,
                    ));
                }
                reject_udp_port(udp_port)?;
                reject_unexpected(&parsed, &[IE_PRIVATE_EXTENSION])?;
                Ok(Self::EndMarker(GtpuEndMarker {
                    teid: GtpuTunnelEndpointId::new(message.header.teid),
                    private_extensions: parsed.private_extensions,
                    unknown_ies: parsed.unknown_ies,
                    extensions,
                }))
            }
            _ => Err(GtpuControlCodecError::new(
                GtpuControlCodecErrorCode::UnsupportedMessageType,
                1,
            )),
        }
    }

    /// Encode a canonical GTP-U control message.
    ///
    /// Canonical Echo Responses always emit `Recovery=0`; Error Indication and
    /// Supported Extension Headers Notification emit zero in their
    /// receiver-ignored Sequence Number field. End Marker rebuilds a known PDU
    /// Session Container from its typed value, puts it first, and preserves the
    /// relative order of unrelated optional unknown extension headers.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the model exceeds GTPv1 or caller capacity
    /// limits or an internally retained extension chain is inconsistent.
    pub fn to_bytes(&self, ctx: EncodeContext) -> Result<Bytes, GtpuControlCodecError> {
        let (message_type, teid, sequence_number, extensions, ies) = match self {
            Self::EchoRequest(value) => {
                ensure_control_ie_count(optional_ie_count(&value.optional, false)?)?;
                (
                    GTPU_MESSAGE_ECHO_REQUEST,
                    0,
                    Some(value.sequence_number),
                    Cow::Borrowed(&value.extensions),
                    ie_refs_optional(&value.optional, false),
                )
            }
            Self::EchoResponse(value) => {
                ensure_control_ie_count(optional_ie_count(&value.optional, true)?)?;
                (
                    GTPU_MESSAGE_ECHO_RESPONSE,
                    0,
                    Some(value.sequence_number),
                    Cow::Borrowed(&value.extensions),
                    ie_refs_optional(&value.optional, true),
                )
            }
            Self::ErrorIndication(value) => {
                if value.teid_data_i.value() == 0 {
                    return Err(GtpuControlCodecError::new(
                        GtpuControlCodecErrorCode::InvalidModel,
                        0,
                    ));
                }
                ensure_control_ie_count(error_ie_count(value)?)?;
                (
                    GTPU_MESSAGE_ERROR_INDICATION,
                    0,
                    Some(0),
                    Cow::Borrowed(&value.extensions),
                    ie_refs_error(value),
                )
            }
            Self::SupportedExtensionHeadersNotification(value) => {
                ensure_control_ie_count(supported_ie_count(value)?)?;
                (
                    GTPU_MESSAGE_SUPPORTED_EXTENSION_HEADERS_NOTIFICATION,
                    0,
                    Some(0),
                    Cow::Borrowed(&value.extensions),
                    ie_refs_supported(value),
                )
            }
            Self::EndMarker(value) => {
                ensure_control_ie_count(end_marker_ie_count(value)?)?;
                let extensions = value
                    .extensions
                    .canonicalize_pdu_session_container()
                    .map_err(|_| {
                        GtpuControlCodecError::new(GtpuControlCodecErrorCode::InvalidModel, 0)
                    })?;
                (
                    GTPU_MESSAGE_END_MARKER,
                    value.teid.value(),
                    None,
                    Cow::Owned(extensions),
                    ie_refs_end_marker(value),
                )
            }
        };
        encode_control_frame(
            message_type,
            teid,
            sequence_number,
            extensions.as_ref(),
            ies,
            ctx,
        )
    }
}

fn validate_zero_teid_and_sequence(message: &GtpuMessage<'_>) -> Result<(), GtpuControlCodecError> {
    if message.header.teid != 0 {
        return Err(GtpuControlCodecError::new(
            GtpuControlCodecErrorCode::InvalidHeaderTeid,
            4,
        ));
    }
    if !message.header.seq_num_flag || message.header.sequence_number.is_none() {
        return Err(GtpuControlCodecError::new(
            GtpuControlCodecErrorCode::InvalidHeaderFlags,
            0,
        ));
    }
    Ok(())
}

fn required_sequence(message: &GtpuMessage<'_>) -> Result<u16, GtpuControlCodecError> {
    message
        .header
        .sequence_number
        .ok_or_else(|| GtpuControlCodecError::new(GtpuControlCodecErrorCode::InvalidHeaderFlags, 8))
}

fn validate_generic_frame_model(
    message: &GtpuMessage<'_>,
    ctx: DecodeContext,
) -> Result<(usize, usize), GtpuControlCodecError> {
    let header = &message.header;
    if header.version != 1 {
        return Err(framing(
            DecodeErrorCode::InvalidEnumValue {
                field: "version",
                value: u64::from(header.version),
            },
            0,
        ));
    }
    if !header.protocol_type {
        return Err(framing(
            DecodeErrorCode::InvalidEnumValue {
                field: "protocol_type",
                value: 0,
            },
            0,
        ));
    }
    if header.ext_hdr_flag
        && header
            .next_ext_type
            .is_none_or(|extension_type| extension_type == 0)
    {
        return Err(GtpuControlCodecError::new(
            GtpuControlCodecErrorCode::InvalidHeaderFlags,
            11,
        ));
    }

    let has_optional_fields = header.ext_hdr_flag || header.seq_num_flag || header.npdu_num_flag;
    let raw_fields_match_optional_block = if has_optional_fields {
        header.raw_sequence_number.is_some()
            && header.raw_npdu_number.is_some()
            && header.raw_next_ext_type.is_some()
    } else {
        header.raw_sequence_number.is_none()
            && header.raw_npdu_number.is_none()
            && header.raw_next_ext_type.is_none()
    };
    if !raw_fields_match_optional_block {
        return Err(framing(
            DecodeErrorCode::Structural {
                reason: "optional header raw-field contract mismatch",
            },
            8,
        ));
    }

    if header.seq_num_flag != header.sequence_number.is_some()
        || header.npdu_num_flag != header.npdu_number.is_some()
        || header.ext_hdr_flag != header.next_ext_type.is_some()
    {
        return Err(framing(
            DecodeErrorCode::Structural {
                reason: "optional header flag/model contract mismatch",
            },
            8,
        ));
    }
    if (header.seq_num_flag && header.sequence_number != header.raw_sequence_number)
        || (header.npdu_num_flag && header.npdu_number != header.raw_npdu_number)
        || (header.ext_hdr_flag && header.next_ext_type != header.raw_next_ext_type)
    {
        return Err(framing(
            DecodeErrorCode::Structural {
                reason: "active optional field differs from retained wire field",
            },
            8,
        ));
    }
    if !header.ext_hdr_flag && !message.raw_extension_headers.is_empty() {
        return Err(framing(
            DecodeErrorCode::Structural {
                reason: "extension bytes present while extension header flag is clear",
            },
            12,
        ));
    }

    let optional_header_len = usize::from(has_optional_fields)
        .checked_mul(4)
        .ok_or_else(length_overflow)?;
    let declared_body_len = optional_header_len
        .checked_add(message.raw_extension_headers.len())
        .and_then(|length| length.checked_add(message.payload.len()))
        .ok_or_else(length_overflow)?;
    let message_end = 8usize
        .checked_add(declared_body_len)
        .ok_or_else(length_overflow)?;
    let header_declared_end = 8usize
        .checked_add(usize::from(header.length))
        .ok_or_else(length_overflow)?;
    if message_end > ctx.max_message_len || header_declared_end > ctx.max_message_len {
        return Err(framing(DecodeErrorCode::MessageLengthExceeded, 0));
    }
    let representable_body_len = u16::try_from(declared_body_len).map_err(|_| {
        framing(
            DecodeErrorCode::InvalidLength {
                reason: "decoded frame exceeds the GTP-U Length field",
            },
            2,
        )
    })?;
    if header.length != representable_body_len {
        return Err(framing(
            DecodeErrorCode::InvalidLength {
                reason: "declared length does not match decoded frame",
            },
            2,
        ));
    }

    let payload_base = 8usize
        .checked_add(optional_header_len)
        .and_then(|base| base.checked_add(message.raw_extension_headers.len()))
        .ok_or_else(length_overflow)?;
    Ok((payload_base, message_end))
}

fn reject_udp_port(port: Option<(u16, usize)>) -> Result<(), GtpuControlCodecError> {
    if let Some((_, offset)) = port {
        Err(GtpuControlCodecError::new(
            GtpuControlCodecErrorCode::UnexpectedExtension {
                extension_type: GTPU_EXT_UDP_PORT,
            },
            offset,
        ))
    } else {
        Ok(())
    }
}

fn parse_extensions(
    message: &GtpuMessage<'_>,
    message_type: u8,
    ctx: DecodeContext,
) -> Result<(GtpuExtensionChain, Option<(u16, usize)>), GtpuControlCodecError> {
    let mut udp_port = None;
    let mut pdu_session_container = None;
    let mut header_count = 0usize;
    let mut offset = 12usize;
    for extension in message.extensions() {
        let next_header_count = header_count.checked_add(1).ok_or_else(length_overflow)?;
        if next_header_count > ctx.max_depth {
            return Err(framing(DecodeErrorCode::DepthExceeded, offset));
        }
        if next_header_count > ctx.max_ies {
            return Err(framing(DecodeErrorCode::IeCountExceeded, offset));
        }
        let extension = extension.map_err(|error| {
            GtpuControlCodecError::new(
                GtpuControlCodecErrorCode::MalformedExtensionChain {
                    reason: malformed_extension_reason(&error),
                },
                offset,
            )
        })?;
        header_count = next_header_count;
        let header_type = GtpuExtensionHeaderType::new(extension.ext_type);
        match classify_control_extension(extension.ext_type, message_type) {
            ControlExtensionDisposition::UdpPort => {
                if extension.content.len() != 2 {
                    return Err(GtpuControlCodecError::new(
                        GtpuControlCodecErrorCode::InvalidExtensionLength,
                        offset,
                    ));
                }
                if udp_port.is_some() {
                    return Err(GtpuControlCodecError::new(
                        GtpuControlCodecErrorCode::UnexpectedExtension {
                            extension_type: GTPU_EXT_UDP_PORT,
                        },
                        offset,
                    ));
                }
                udp_port = Some((
                    u16::from_be_bytes([extension.content[0], extension.content[1]]),
                    offset,
                ));
            }
            ControlExtensionDisposition::PduSessionContainer => {
                if pdu_session_container.is_some() {
                    return Err(GtpuControlCodecError::new(
                        GtpuControlCodecErrorCode::DuplicatePduSessionContainer,
                        offset,
                    ));
                }
                let container = PduSessionContainer::decode_with_reason(&extension).map_err(
                    |(reason, _)| {
                        GtpuControlCodecError::new(
                            GtpuControlCodecErrorCode::MalformedPduSessionContainer { reason },
                            offset,
                        )
                    },
                )?;
                pdu_session_container = Some(container);
            }
            ControlExtensionDisposition::StandardizedButInapplicable => {
                return Err(GtpuControlCodecError::new(
                    GtpuControlCodecErrorCode::UnexpectedExtension {
                        extension_type: extension.ext_type,
                    },
                    offset,
                ));
            }
            ControlExtensionDisposition::Unknown => {
                if header_type
                    .unsupported_requires_comprehension_by(GtpuExtensionHeaderRecipient::Endpoint)
                {
                    return Err(GtpuControlCodecError::new(
                        GtpuControlCodecErrorCode::UnsupportedRequiredExtension {
                            extension_type: extension.ext_type,
                        },
                        offset,
                    ));
                }
            }
        }
        offset = offset
            .checked_add(extension.content.len())
            .and_then(|value| value.checked_add(2))
            .ok_or_else(length_overflow)?;
    }
    let consumed = offset.checked_sub(12).ok_or_else(length_overflow)?;
    if consumed != message.raw_extension_headers.len() {
        return Err(GtpuControlCodecError::new(
            GtpuControlCodecErrorCode::MalformedExtensionChain {
                reason: GtpuExtensionChainMalformedReason::TrailingBytes,
            },
            offset,
        ));
    }
    let first_extension_type = message
        .header
        .ext_hdr_flag
        .then_some(message.header.next_ext_type)
        .flatten()
        .filter(|value| *value != 0);
    let chain = GtpuExtensionChain {
        first_extension_type,
        raw_headers: Bytes::copy_from_slice(message.raw_extension_headers),
        header_count,
        pdu_session_container,
    };
    Ok((chain, udp_port))
}

fn malformed_extension_reason(error: &DecodeError) -> GtpuExtensionChainMalformedReason {
    match error.code() {
        DecodeErrorCode::InvalidLength {
            reason: "extension header units is zero",
        } => GtpuExtensionChainMalformedReason::LengthUnitsZero,
        DecodeErrorCode::LengthOverflow => GtpuExtensionChainMalformedReason::LengthOverflow,
        _ => GtpuExtensionChainMalformedReason::Truncated,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControlExtensionDisposition {
    UdpPort,
    PduSessionContainer,
    StandardizedButInapplicable,
    Unknown,
}

fn classify_control_extension(extension_type: u8, message_type: u8) -> ControlExtensionDisposition {
    match extension_type {
        GTPU_EXT_UDP_PORT if message_type == GTPU_MESSAGE_ERROR_INDICATION => {
            ControlExtensionDisposition::UdpPort
        }
        GTPU_EXT_PDU_SESSION_CONTAINER if message_type == GTPU_MESSAGE_END_MARKER => {
            ControlExtensionDisposition::PduSessionContainer
        }
        // TS 29.281 Release 18.4.0 figure 5.2.1-3. All listed values other
        // than the two procedure-specific cases above are standardized but
        // inapplicable to this typed signalling subset. They must not be
        // mistaken for forward-compatible unknown optional extensions.
        0x01
        | 0x02
        | 0x03
        | 0x04
        | 0x20
        | GTPU_EXT_UDP_PORT
        | 0x81
        | 0x82
        | 0x83
        | 0x84
        | GTPU_EXT_PDU_SESSION_CONTAINER
        | 0x86
        | 0xc0
        | 0xc1
        | 0xc2 => ControlExtensionDisposition::StandardizedButInapplicable,
        _ => ControlExtensionDisposition::Unknown,
    }
}

#[derive(Default)]
struct ParsedIes {
    recovery: bool,
    teid_data_i: Option<GtpuTunnelEndpointId>,
    peer_address: Option<GtpuPeerAddress>,
    extension_header_type_list: Option<GtpuExtensionHeaderTypeList>,
    recovery_time_stamp: Option<GtpuRecoveryTimeStamp>,
    private_extensions: Vec<GtpuPrivateExtension>,
    unknown_ies: Vec<GtpuUnknownControlIe>,
    known_ie_offsets: Vec<(u8, usize)>,
}

impl ParsedIes {
    fn into_optional(self) -> OptionalControlIes {
        OptionalControlIes {
            recovery_time_stamp: self.recovery_time_stamp,
            private_extensions: self.private_extensions,
            unknown_ies: self.unknown_ies,
        }
    }

    fn offset_of(&self, ie_type: u8) -> Option<usize> {
        self.known_ie_offsets
            .iter()
            .find_map(|(present_type, offset)| (*present_type == ie_type).then_some(*offset))
    }
}

fn parse_ies(
    payload: &[u8],
    payload_base: usize,
    ctx: DecodeContext,
) -> Result<ParsedIes, GtpuControlCodecError> {
    let mut parsed = ParsedIes::default();
    let mut offset = 0usize;
    let mut count = 0usize;
    let mut previous_type = None;

    while offset < payload.len() {
        let datagram_offset = payload_base
            .checked_add(offset)
            .ok_or_else(length_overflow)?;
        count = count.saturating_add(1);
        if count > ctx.max_ies || count > MAX_CONTROL_IES {
            return Err(GtpuControlCodecError::new(
                GtpuControlCodecErrorCode::IeCountExceeded,
                datagram_offset,
            ));
        }
        let ie_type = payload[offset];
        if previous_type.is_some_and(|previous| ie_type < previous) {
            return Err(GtpuControlCodecError::new(
                GtpuControlCodecErrorCode::IesOutOfOrder,
                datagram_offset,
            ));
        }
        previous_type = Some(ie_type);

        match ie_type {
            IE_RECOVERY => {
                require_bytes(payload, offset, 2, datagram_offset)?;
                if parsed.recovery {
                    return Err(duplicate(ie_type, datagram_offset));
                }
                // The restart counter is explicitly receiver-ignored.
                parsed.recovery = true;
                parsed.known_ie_offsets.push((ie_type, datagram_offset));
                offset += 2;
            }
            IE_TEID_DATA_I => {
                require_bytes(payload, offset, 5, datagram_offset)?;
                if parsed.teid_data_i.is_some() {
                    return Err(duplicate(ie_type, datagram_offset));
                }
                parsed.teid_data_i = Some(GtpuTunnelEndpointId::new(u32::from_be_bytes([
                    payload[offset + 1],
                    payload[offset + 2],
                    payload[offset + 3],
                    payload[offset + 4],
                ])));
                parsed.known_ie_offsets.push((ie_type, datagram_offset));
                offset += 5;
            }
            0..=127 => {
                return Err(GtpuControlCodecError::new(
                    GtpuControlCodecErrorCode::UnknownTvIe { ie_type },
                    datagram_offset,
                ));
            }
            _ => {
                require_bytes(payload, offset, 3, datagram_offset)?;
                let value_len = usize::from(u16::from_be_bytes([
                    payload[offset + 1],
                    payload[offset + 2],
                ]));
                let value_start = offset.checked_add(3).ok_or_else(length_overflow)?;
                let end = value_start
                    .checked_add(value_len)
                    .ok_or_else(length_overflow)?;
                if end > payload.len() {
                    return Err(GtpuControlCodecError::new(
                        GtpuControlCodecErrorCode::TruncatedIe,
                        datagram_offset,
                    ));
                }
                let value = &payload[value_start..end];
                match ie_type {
                    IE_GTPU_PEER_ADDRESS => {
                        if parsed.peer_address.is_some() {
                            return Err(duplicate(ie_type, datagram_offset));
                        }
                        let address = match value {
                            [a, b, c, d] => IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)),
                            bytes if bytes.len() == 16 => {
                                let octets: [u8; 16] = bytes
                                    .try_into()
                                    .map_err(|_| invalid_length(ie_type, datagram_offset))?;
                                IpAddr::V6(Ipv6Addr::from(octets))
                            }
                            _ => return Err(invalid_length(ie_type, datagram_offset)),
                        };
                        parsed.peer_address = Some(GtpuPeerAddress::new(address));
                        parsed.known_ie_offsets.push((ie_type, datagram_offset));
                    }
                    IE_EXTENSION_HEADER_TYPE_LIST => {
                        if parsed.extension_header_type_list.is_some() {
                            return Err(duplicate(ie_type, datagram_offset));
                        }
                        let types = value.iter().copied().map(GtpuExtensionHeaderType::new);
                        parsed.extension_header_type_list =
                            Some(GtpuExtensionHeaderTypeList::new(types).map_err(|_| {
                                invalid_value(IE_EXTENSION_HEADER_TYPE_LIST, datagram_offset)
                            })?);
                        parsed.known_ie_offsets.push((ie_type, datagram_offset));
                    }
                    IE_GTPU_TUNNEL_STATUS => {
                        return Err(GtpuControlCodecError::new(
                            GtpuControlCodecErrorCode::UnexpectedIe { ie_type },
                            datagram_offset,
                        ));
                    }
                    IE_RECOVERY_TIME_STAMP => {
                        if parsed.recovery_time_stamp.is_some() {
                            return Err(duplicate(ie_type, datagram_offset));
                        }
                        if value.len() < 4 {
                            return Err(invalid_length(ie_type, datagram_offset));
                        }
                        parsed.recovery_time_stamp = Some(GtpuRecoveryTimeStamp::from_received(
                            u32::from_be_bytes([value[0], value[1], value[2], value[3]]),
                            Bytes::copy_from_slice(&value[4..]),
                        ));
                        parsed.known_ie_offsets.push((ie_type, datagram_offset));
                    }
                    IE_PRIVATE_EXTENSION => {
                        if value.len() < 2 {
                            return Err(invalid_length(ie_type, datagram_offset));
                        }
                        parsed.private_extensions.push(GtpuPrivateExtension::new(
                            u16::from_be_bytes([value[0], value[1]]),
                            Bytes::copy_from_slice(&value[2..]),
                        ));
                        parsed.known_ie_offsets.push((ie_type, datagram_offset));
                    }
                    _ => match ctx.unknown_ie_policy {
                        UnknownIePolicy::Drop => {}
                        UnknownIePolicy::Preserve => {
                            parsed.unknown_ies.push(GtpuUnknownControlIe {
                                ie_type,
                                value: Bytes::copy_from_slice(value),
                            });
                        }
                        UnknownIePolicy::Reject => {
                            return Err(GtpuControlCodecError::new(
                                GtpuControlCodecErrorCode::UnknownIe { ie_type },
                                datagram_offset,
                            ));
                        }
                    },
                }
                offset = end;
            }
        }
    }

    Ok(parsed)
}

fn reject_unexpected(parsed: &ParsedIes, allowed: &[u8]) -> Result<(), GtpuControlCodecError> {
    for (ie_type, offset) in &parsed.known_ie_offsets {
        if !allowed.contains(ie_type) {
            return Err(GtpuControlCodecError::new(
                GtpuControlCodecErrorCode::UnexpectedIe { ie_type: *ie_type },
                *offset,
            ));
        }
    }
    Ok(())
}

fn require_bytes(
    payload: &[u8],
    offset: usize,
    required: usize,
    datagram_offset: usize,
) -> Result<(), GtpuControlCodecError> {
    if payload.len().saturating_sub(offset) < required {
        Err(GtpuControlCodecError::new(
            GtpuControlCodecErrorCode::TruncatedIe,
            datagram_offset,
        ))
    } else {
        Ok(())
    }
}

fn duplicate(ie_type: u8, offset: usize) -> GtpuControlCodecError {
    GtpuControlCodecError::new(GtpuControlCodecErrorCode::DuplicateIe { ie_type }, offset)
}

fn missing(ie_type: u8, datagram_end: usize) -> GtpuControlCodecError {
    GtpuControlCodecError::new(
        GtpuControlCodecErrorCode::MissingMandatoryIe { ie_type },
        datagram_end,
    )
}

fn invalid_length(ie_type: u8, offset: usize) -> GtpuControlCodecError {
    GtpuControlCodecError::new(
        GtpuControlCodecErrorCode::InvalidIeLength { ie_type },
        offset,
    )
}

fn invalid_value(ie_type: u8, offset: usize) -> GtpuControlCodecError {
    GtpuControlCodecError::new(
        GtpuControlCodecErrorCode::InvalidIeValue { ie_type },
        offset,
    )
}

fn framing(code: DecodeErrorCode, offset: usize) -> GtpuControlCodecError {
    GtpuControlCodecError::new(GtpuControlCodecErrorCode::Framing { code }, offset)
}

fn length_overflow() -> GtpuControlCodecError {
    GtpuControlCodecError::new(GtpuControlCodecErrorCode::LengthOverflow, 0)
}

enum ControlIeRef<'a> {
    Recovery,
    Teid(GtpuTunnelEndpointId),
    PeerAddress(GtpuPeerAddress),
    ExtensionTypes(&'a GtpuExtensionHeaderTypeList),
    RecoveryTimeStamp(&'a GtpuRecoveryTimeStamp),
    Private(&'a GtpuPrivateExtension),
    Unknown(&'a GtpuUnknownControlIe),
}

impl ControlIeRef<'_> {
    fn ie_type(&self) -> u8 {
        match self {
            Self::Recovery => IE_RECOVERY,
            Self::Teid(_) => IE_TEID_DATA_I,
            Self::PeerAddress(_) => IE_GTPU_PEER_ADDRESS,
            Self::ExtensionTypes(_) => IE_EXTENSION_HEADER_TYPE_LIST,
            Self::RecoveryTimeStamp(_) => IE_RECOVERY_TIME_STAMP,
            Self::Private(_) => IE_PRIVATE_EXTENSION,
            Self::Unknown(value) => value.ie_type,
        }
    }

    fn wire_len(&self) -> Result<usize, GtpuControlCodecError> {
        match self {
            Self::Recovery => Ok(2),
            Self::Teid(_) => Ok(5),
            Self::PeerAddress(value) => Ok(match value.address() {
                IpAddr::V4(_) => 7,
                IpAddr::V6(_) => 19,
            }),
            Self::ExtensionTypes(value) => tlv_wire_len(value.0.len()),
            Self::RecoveryTimeStamp(value) => tlv_wire_len(
                value
                    .additional_data
                    .len()
                    .checked_add(4)
                    .ok_or_else(length_overflow)?,
            ),
            Self::Private(value) => tlv_wire_len(
                value
                    .value
                    .len()
                    .checked_add(2)
                    .ok_or_else(length_overflow)?,
            ),
            Self::Unknown(value) => tlv_wire_len(value.value.len()),
        }
    }

    fn encode(&self, destination: &mut BytesMut) -> Result<(), GtpuControlCodecError> {
        match self {
            Self::Recovery => {
                destination.put_u8(IE_RECOVERY);
                destination.put_u8(0);
            }
            Self::Teid(value) => {
                destination.put_u8(IE_TEID_DATA_I);
                destination.put_u32(value.value());
            }
            Self::PeerAddress(value) => {
                destination.put_u8(IE_GTPU_PEER_ADDRESS);
                match value.address() {
                    IpAddr::V4(address) => {
                        destination.put_u16(4);
                        destination.put_slice(&address.octets());
                    }
                    IpAddr::V6(address) => {
                        destination.put_u16(16);
                        destination.put_slice(&address.octets());
                    }
                }
            }
            Self::ExtensionTypes(value) => {
                put_tlv_header(destination, IE_EXTENSION_HEADER_TYPE_LIST, value.0.len())?;
                for header_type in &value.0 {
                    destination.put_u8(header_type.value());
                }
            }
            Self::RecoveryTimeStamp(value) => {
                let length = value
                    .additional_data
                    .len()
                    .checked_add(4)
                    .ok_or_else(length_overflow)?;
                put_tlv_header(destination, IE_RECOVERY_TIME_STAMP, length)?;
                destination.put_u32(value.seconds_since_1900);
                destination.put_slice(&value.additional_data);
            }
            Self::Private(value) => {
                let length = value
                    .value
                    .len()
                    .checked_add(2)
                    .ok_or_else(length_overflow)?;
                put_tlv_header(destination, IE_PRIVATE_EXTENSION, length)?;
                destination.put_u16(value.extension_identifier);
                destination.put_slice(&value.value);
            }
            Self::Unknown(value) => {
                put_tlv_header(destination, value.ie_type, value.value.len())?;
                destination.put_slice(&value.value);
            }
        }
        Ok(())
    }
}

fn tlv_wire_len(value_len: usize) -> Result<usize, GtpuControlCodecError> {
    let _ = u16::try_from(value_len).map_err(|_| length_overflow())?;
    value_len.checked_add(3).ok_or_else(length_overflow)
}

fn put_tlv_header(
    destination: &mut BytesMut,
    ie_type: u8,
    value_len: usize,
) -> Result<(), GtpuControlCodecError> {
    let value_len = u16::try_from(value_len).map_err(|_| length_overflow())?;
    destination.put_u8(ie_type);
    destination.put_u16(value_len);
    Ok(())
}

fn ie_refs_optional(optional: &OptionalControlIes, recovery: bool) -> Vec<ControlIeRef<'_>> {
    let mut values = Vec::new();
    if recovery {
        values.push(ControlIeRef::Recovery);
    }
    if let Some(value) = &optional.recovery_time_stamp {
        values.push(ControlIeRef::RecoveryTimeStamp(value));
    }
    values.extend(
        optional
            .private_extensions
            .iter()
            .map(ControlIeRef::Private),
    );
    values.extend(optional.unknown_ies.iter().map(ControlIeRef::Unknown));
    values
}

fn optional_ie_count(
    optional: &OptionalControlIes,
    recovery: bool,
) -> Result<usize, GtpuControlCodecError> {
    usize::from(recovery)
        .checked_add(usize::from(optional.recovery_time_stamp.is_some()))
        .and_then(|value| value.checked_add(optional.private_extensions.len()))
        .and_then(|value| value.checked_add(optional.unknown_ies.len()))
        .ok_or_else(length_overflow)
}

fn error_ie_count(value: &GtpuErrorIndication) -> Result<usize, GtpuControlCodecError> {
    2usize
        .checked_add(usize::from(value.optional.recovery_time_stamp.is_some()))
        .and_then(|count| count.checked_add(value.optional.private_extensions.len()))
        .and_then(|count| count.checked_add(value.optional.unknown_ies.len()))
        .ok_or_else(length_overflow)
}

fn supported_ie_count(
    value: &GtpuSupportedExtensionHeadersNotification,
) -> Result<usize, GtpuControlCodecError> {
    1usize
        .checked_add(value.private_extensions.len())
        .and_then(|count| count.checked_add(value.unknown_ies.len()))
        .ok_or_else(length_overflow)
}

fn end_marker_ie_count(value: &GtpuEndMarker) -> Result<usize, GtpuControlCodecError> {
    value
        .private_extensions
        .len()
        .checked_add(value.unknown_ies.len())
        .ok_or_else(length_overflow)
}

fn ensure_control_ie_count(count: usize) -> Result<(), GtpuControlCodecError> {
    if count > MAX_CONTROL_IES {
        Err(GtpuControlCodecError::new(
            GtpuControlCodecErrorCode::IeCountExceeded,
            0,
        ))
    } else {
        Ok(())
    }
}

fn ie_refs_error(value: &GtpuErrorIndication) -> Vec<ControlIeRef<'_>> {
    let mut values = vec![
        ControlIeRef::Teid(value.teid_data_i),
        ControlIeRef::PeerAddress(value.peer_address),
    ];
    if let Some(time_stamp) = &value.optional.recovery_time_stamp {
        values.push(ControlIeRef::RecoveryTimeStamp(time_stamp));
    }
    values.extend(
        value
            .optional
            .private_extensions
            .iter()
            .map(ControlIeRef::Private),
    );
    values.extend(value.optional.unknown_ies.iter().map(ControlIeRef::Unknown));
    values
}

fn ie_refs_supported(value: &GtpuSupportedExtensionHeadersNotification) -> Vec<ControlIeRef<'_>> {
    let mut values = vec![ControlIeRef::ExtensionTypes(&value.supported_types)];
    values.extend(value.private_extensions.iter().map(ControlIeRef::Private));
    values.extend(value.unknown_ies.iter().map(ControlIeRef::Unknown));
    values
}

fn ie_refs_end_marker(value: &GtpuEndMarker) -> Vec<ControlIeRef<'_>> {
    let mut values = Vec::new();
    values.extend(value.private_extensions.iter().map(ControlIeRef::Private));
    values.extend(value.unknown_ies.iter().map(ControlIeRef::Unknown));
    values
}

fn encode_control_frame(
    message_type: u8,
    teid: u32,
    sequence_number: Option<u16>,
    extensions: &GtpuExtensionChain,
    mut ies: Vec<ControlIeRef<'_>>,
    ctx: EncodeContext,
) -> Result<Bytes, GtpuControlCodecError> {
    extensions
        .validate_consistency()
        .map_err(|_| GtpuControlCodecError::new(GtpuControlCodecErrorCode::InvalidModel, 0))?;
    if ies.len() > MAX_CONTROL_IES {
        return Err(GtpuControlCodecError::new(
            GtpuControlCodecErrorCode::IeCountExceeded,
            0,
        ));
    }
    ies.sort_by_key(ControlIeRef::ie_type);
    let payload_len = ies.iter().try_fold(0usize, |total, ie| {
        total
            .checked_add(ie.wire_len()?)
            .ok_or_else(length_overflow)
    })?;

    // Preflight the exact final GTP-U datagram size, including the u16 Length
    // field domain, before allocating or writing the serialized IE payload.
    let optional_header_len = usize::from(sequence_number.is_some() || extensions.has_headers())
        .checked_mul(4)
        .ok_or_else(length_overflow)?;
    let bytes_after_mandatory_header = optional_header_len
        .checked_add(extensions.raw_headers.len())
        .and_then(|value| value.checked_add(payload_len))
        .ok_or_else(length_overflow)?;
    let _ = u16::try_from(bytes_after_mandatory_header).map_err(|_| length_overflow())?;
    let required = 8usize
        .checked_add(bytes_after_mandatory_header)
        .ok_or_else(length_overflow)?;
    if required > ctx.max_message_len {
        return Err(GtpuControlCodecError::new(
            GtpuControlCodecErrorCode::CapacityExceeded,
            0,
        ));
    }

    let mut payload = BytesMut::with_capacity(payload_len);
    for ie in &ies {
        ie.encode(&mut payload)?;
    }

    let message = GtpuMessage {
        header: GtpuHeader {
            version: 1,
            protocol_type: true,
            reserved: 0,
            ext_hdr_flag: extensions.has_headers(),
            seq_num_flag: sequence_number.is_some(),
            npdu_num_flag: false,
            message_type,
            length: 0,
            teid,
            sequence_number,
            npdu_number: None,
            next_ext_type: extensions.first_extension_type,
            raw_sequence_number: None,
            raw_npdu_number: None,
            raw_next_ext_type: None,
        },
        raw_extension_headers: &extensions.raw_headers,
        payload: &payload,
    };
    let encoded_required = message.wire_len(ctx).map_err(|error| match error.code() {
        opc_protocol::EncodeErrorCode::CapacityExceeded { .. } => {
            GtpuControlCodecError::new(GtpuControlCodecErrorCode::CapacityExceeded, 0)
        }
        opc_protocol::EncodeErrorCode::LengthOverflow => {
            GtpuControlCodecError::new(GtpuControlCodecErrorCode::LengthOverflow, 0)
        }
        opc_protocol::EncodeErrorCode::Structural { .. } => {
            GtpuControlCodecError::new(GtpuControlCodecErrorCode::InvalidModel, 0)
        }
    })?;
    if encoded_required != required {
        return Err(GtpuControlCodecError::new(
            GtpuControlCodecErrorCode::InvalidModel,
            0,
        ));
    }
    let mut destination = BytesMut::with_capacity(required);
    message
        .encode(&mut destination, ctx)
        .map_err(|error| match error.code() {
            opc_protocol::EncodeErrorCode::CapacityExceeded { .. } => {
                GtpuControlCodecError::new(GtpuControlCodecErrorCode::CapacityExceeded, 0)
            }
            opc_protocol::EncodeErrorCode::LengthOverflow => {
                GtpuControlCodecError::new(GtpuControlCodecErrorCode::LengthOverflow, 0)
            }
            opc_protocol::EncodeErrorCode::Structural { .. } => {
                GtpuControlCodecError::new(GtpuControlCodecErrorCode::InvalidModel, 0)
            }
        })?;
    Ok(destination.freeze())
}
