//! IKE over UDP and NAT traversal datagram classification.
//!
//! @spec IETF RFC3948 2.1, 2.2
//! @req REQ-IETF-RFC3948-NATT-CLASSIFY-001

use core::fmt;

use opc_protocol::{DecodeContext, DecodeErrorCode};

use crate::{Ikev2MessageRejection, Ikev2UnknownCriticalPayloadMessage, Message};

/// UDP port assigned to IKE.
pub const IKE_UDP_PORT: u16 = 500;

/// UDP port assigned to IKE NAT traversal.
pub const IKE_NAT_TRAVERSAL_UDP_PORT: u16 = 4500;

/// NAT-T keepalive octet defined by RFC 3948.
pub const NAT_TRAVERSAL_KEEPALIVE: u8 = 0xff;

const NON_ESP_MARKER: [u8; 4] = [0, 0, 0, 0];
const NON_ESP_MARKER_LEN: usize = NON_ESP_MARKER.len();
const ESP_HEADER_PREFIX_LEN: usize = 8;

/// Classify an ingress IKE/NAT-T UDP datagram with [`DecodeContext::default`].
///
/// The returned value borrows from `datagram`; packet bytes are not copied.
#[must_use]
pub fn classify_ike_nat_traversal_datagram(
    udp_destination_port: u16,
    datagram: &[u8],
) -> NatTraversalClassification<'_> {
    inspect_ike_nat_traversal_datagram(udp_destination_port, datagram).into_classification()
}

/// Classify an ingress IKE/NAT-T UDP datagram with explicit decode limits.
///
/// The returned value borrows from `datagram`; packet bytes are not copied.
#[must_use]
pub fn classify_ike_nat_traversal_datagram_with_context(
    udp_destination_port: u16,
    datagram: &[u8],
    ctx: DecodeContext,
) -> NatTraversalClassification<'_> {
    inspect_ike_nat_traversal_datagram_with_context(udp_destination_port, datagram, ctx)
        .into_classification()
}

/// Classify an ingress IKE/NAT-T UDP datagram while retaining a typed
/// unknown-critical rejection sidecar.
///
/// The ordinary classification remains available through
/// [`NatTraversalInspection::classification`] and uses the existing public
/// classification enum. Ordinary valid classifications are unchanged.
/// Rejection precedence is intentionally hardened: malformed offender framing
/// remains malformed, and bytes beyond the declared IKE boundary classify as
/// trailing even when the declared message also contains an unknown critical
/// payload.
#[must_use]
pub fn inspect_ike_nat_traversal_datagram(
    udp_destination_port: u16,
    datagram: &[u8],
) -> NatTraversalInspection<'_> {
    inspect_ike_nat_traversal_datagram_with_context(
        udp_destination_port,
        datagram,
        DecodeContext::default(),
    )
}

/// Classify an ingress IKE/NAT-T UDP datagram with explicit decode limits
/// while retaining a typed unknown-critical rejection sidecar.
#[must_use]
pub fn inspect_ike_nat_traversal_datagram_with_context(
    udp_destination_port: u16,
    datagram: &[u8],
    ctx: DecodeContext,
) -> NatTraversalInspection<'_> {
    match udp_destination_port {
        IKE_UDP_PORT => inspect_ike_datagram(NatTraversalIkeTransport::Udp500, datagram, ctx),
        IKE_NAT_TRAVERSAL_UDP_PORT => inspect_udp_4500_datagram(datagram, ctx),
        port => NatTraversalInspection::classified(NatTraversalClassification::Rejected(
            NatTraversalRejection::UnsupportedPort {
                udp_destination_port: port,
            },
        )),
    }
}

fn inspect_udp_4500_datagram(datagram: &[u8], ctx: DecodeContext) -> NatTraversalInspection<'_> {
    if datagram == [NAT_TRAVERSAL_KEEPALIVE].as_slice() {
        return NatTraversalInspection::classified(NatTraversalClassification::NatKeepalive(
            NatTraversalKeepalive { datagram },
        ));
    }

    if datagram.starts_with(&NON_ESP_MARKER) {
        return inspect_ike_datagram(NatTraversalIkeTransport::Udp4500NonEspMarker, datagram, ctx);
    }

    if datagram.len() < ESP_HEADER_PREFIX_LEN {
        return NatTraversalInspection::classified(NatTraversalClassification::Rejected(
            NatTraversalRejection::RuntEspCandidate { datagram },
        ));
    }

    let spi = u32::from_be_bytes([datagram[0], datagram[1], datagram[2], datagram[3]]);
    let sequence_number = u32::from_be_bytes([datagram[4], datagram[5], datagram[6], datagram[7]]);
    NatTraversalInspection::classified(NatTraversalClassification::EspCandidate(
        NatTraversalEspCandidate {
            datagram,
            spi,
            sequence_number,
        },
    ))
}

fn inspect_ike_datagram(
    transport: NatTraversalIkeTransport,
    datagram: &[u8],
    ctx: DecodeContext,
) -> NatTraversalInspection<'_> {
    let ike_bytes = match transport {
        NatTraversalIkeTransport::Udp500 => datagram,
        NatTraversalIkeTransport::Udp4500NonEspMarker => &datagram[NON_ESP_MARKER_LEN..],
    };

    match Message::decode_with_rejection(ike_bytes, ctx) {
        Ok(([], message)) => NatTraversalInspection::classified(NatTraversalClassification::Ike(
            NatTraversalIkeMessage {
                transport,
                datagram,
                ike_bytes,
                message,
            },
        )),
        Ok((_tail, message)) => NatTraversalInspection::classified(
            NatTraversalClassification::Rejected(NatTraversalRejection::TrailingIkeBytes {
                transport,
                declared_len: usize::try_from(message.header.length).unwrap_or(usize::MAX),
                actual_len: ike_bytes.len(),
            }),
        ),
        Err(Ikev2MessageRejection::Malformed(error)) => NatTraversalInspection::classified(
            NatTraversalClassification::Rejected(NatTraversalRejection::MalformedIke {
                transport,
                decode_code: NatTraversalIkeDecodeErrorCode::from(error.code()),
            }),
        ),
        Err(Ikev2MessageRejection::UnknownCriticalPayload(rejection)) => {
            if rejection.has_trailing_bytes() {
                NatTraversalInspection::classified(NatTraversalClassification::Rejected(
                    NatTraversalRejection::TrailingIkeBytes {
                        transport,
                        declared_len: rejection.declared_len(),
                        actual_len: ike_bytes.len(),
                    },
                ))
            } else {
                NatTraversalInspection {
                    classification: NatTraversalClassification::Rejected(
                        NatTraversalRejection::MalformedIke {
                            transport,
                            decode_code: NatTraversalIkeDecodeErrorCode::UnknownCriticalPayload,
                        },
                    ),
                    unknown_critical_payload: Some(NatTraversalUnknownCriticalPayload {
                        transport,
                        rejection,
                    }),
                }
            }
        }
    }
}

/// Source-compatible NAT traversal classification enum plus an optional typed
/// unknown-critical rejection sidecar.
#[derive(Clone, PartialEq, Eq)]
pub struct NatTraversalInspection<'a> {
    classification: NatTraversalClassification<'a>,
    unknown_critical_payload: Option<NatTraversalUnknownCriticalPayload>,
}

impl<'a> NatTraversalInspection<'a> {
    fn classified(classification: NatTraversalClassification<'a>) -> Self {
        Self {
            classification,
            unknown_critical_payload: None,
        }
    }

    /// Ordinary source-compatible coarse classification outcome.
    #[must_use]
    pub const fn classification(&self) -> &NatTraversalClassification<'a> {
        &self.classification
    }

    /// Consume the inspection and return its ordinary classification.
    #[must_use]
    pub fn into_classification(self) -> NatTraversalClassification<'a> {
        self.classification
    }

    /// Typed unknown-critical rejection, when complete framing established it.
    #[must_use]
    pub const fn unknown_critical_payload(&self) -> Option<NatTraversalUnknownCriticalPayload> {
        self.unknown_critical_payload
    }

    /// Stable machine-readable classification code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.classification.code()
    }

    /// Return whether the ordinary classification accepts the datagram.
    #[must_use]
    pub const fn is_accepted(&self) -> bool {
        self.classification.is_accepted()
    }
}

impl fmt::Debug for NatTraversalInspection<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NatTraversalInspection")
            .field("classification", &self.classification)
            .field("unknown_critical_payload", &self.unknown_critical_payload)
            .finish()
    }
}

/// Transport-qualified unknown-critical IKE message fact.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NatTraversalUnknownCriticalPayload {
    transport: NatTraversalIkeTransport,
    rejection: Ikev2UnknownCriticalPayloadMessage,
}

impl NatTraversalUnknownCriticalPayload {
    /// Stable machine-readable rejection code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.rejection.code()
    }

    /// Transport encapsulation used by the rejected IKE message.
    #[must_use]
    pub const fn transport(self) -> NatTraversalIkeTransport {
        self.transport
    }

    /// UDP destination port that selected the transport.
    #[must_use]
    pub const fn udp_destination_port(self) -> u16 {
        self.transport.udp_destination_port()
    }

    /// Generic message-bound unknown-critical fact.
    #[must_use]
    pub const fn rejection(self) -> Ikev2UnknownCriticalPayloadMessage {
        self.rejection
    }
}

impl fmt::Debug for NatTraversalUnknownCriticalPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NatTraversalUnknownCriticalPayload")
            .field("transport", &self.transport)
            .field("rejection", &self.rejection)
            .finish()
    }
}

/// IKE/NAT-T datagram classification outcome.
#[derive(Clone, PartialEq, Eq)]
pub enum NatTraversalClassification<'a> {
    /// Decoded IKE message on UDP/500 or UDP/4500 with the non-ESP marker.
    Ike(NatTraversalIkeMessage<'a>),
    /// RFC 3948 NAT-T keepalive on UDP/4500.
    NatKeepalive(NatTraversalKeepalive<'a>),
    /// UDP/4500 datagram that is large enough to be handed to ESP handling.
    EspCandidate(NatTraversalEspCandidate<'a>),
    /// Datagram rejected before protocol handling.
    Rejected(NatTraversalRejection<'a>),
}

impl NatTraversalClassification<'_> {
    /// Stable machine-readable classification code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Ike(message) => message.transport.code(),
            Self::NatKeepalive(_) => "natt_keepalive",
            Self::EspCandidate(_) => "natt_esp_candidate",
            Self::Rejected(rejection) => rejection.code(),
        }
    }

    /// Return `true` when the datagram is an IKE control packet.
    #[must_use]
    pub const fn is_ike(&self) -> bool {
        matches!(self, Self::Ike(_))
    }

    /// Return `true` when the datagram is accepted for downstream handling.
    #[must_use]
    pub const fn is_accepted(&self) -> bool {
        !matches!(self, Self::Rejected(_))
    }
}

impl fmt::Debug for NatTraversalClassification<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ike(message) => f.debug_tuple("Ike").field(message).finish(),
            Self::NatKeepalive(keepalive) => {
                f.debug_tuple("NatKeepalive").field(keepalive).finish()
            }
            Self::EspCandidate(candidate) => {
                f.debug_tuple("EspCandidate").field(candidate).finish()
            }
            Self::Rejected(rejection) => f.debug_tuple("Rejected").field(rejection).finish(),
        }
    }
}

/// Transport wrapper for a decoded IKE message.
#[derive(Clone, PartialEq, Eq)]
pub struct NatTraversalIkeMessage<'a> {
    transport: NatTraversalIkeTransport,
    datagram: &'a [u8],
    ike_bytes: &'a [u8],
    message: Message<'a>,
}

impl<'a> NatTraversalIkeMessage<'a> {
    /// Stable machine-readable accepted IKE classification code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.transport.code()
    }

    /// Transport encapsulation used by this IKE message.
    #[must_use]
    pub const fn transport(&self) -> NatTraversalIkeTransport {
        self.transport
    }

    /// UDP destination port that selected this transport.
    #[must_use]
    pub const fn udp_destination_port(&self) -> u16 {
        self.transport.udp_destination_port()
    }

    /// Complete UDP datagram bytes.
    #[must_use]
    pub const fn datagram(&self) -> &'a [u8] {
        self.datagram
    }

    /// IKE message bytes after removing any NAT-T non-ESP marker.
    #[must_use]
    pub const fn ike_bytes(&self) -> &'a [u8] {
        self.ike_bytes
    }

    /// Decoded zero-copy IKE message shell.
    #[must_use]
    pub const fn message(&self) -> &Message<'a> {
        &self.message
    }

    /// Consume the wrapper and return the decoded IKE message shell.
    #[must_use]
    pub fn into_message(self) -> Message<'a> {
        self.message
    }
}

impl fmt::Debug for NatTraversalIkeMessage<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NatTraversalIkeMessage")
            .field("transport", &self.transport)
            .field("datagram_len", &self.datagram.len())
            .field("ike_len", &self.ike_bytes.len())
            .field("exchange_type", &self.message.header.exchange_type)
            .field("message_id", &self.message.header.message_id)
            .finish_non_exhaustive()
    }
}

/// RFC 3948 NAT-T keepalive datagram.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NatTraversalKeepalive<'a> {
    datagram: &'a [u8],
}

impl<'a> NatTraversalKeepalive<'a> {
    /// Complete UDP datagram bytes.
    #[must_use]
    pub const fn datagram(&self) -> &'a [u8] {
        self.datagram
    }
}

impl fmt::Debug for NatTraversalKeepalive<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NatTraversalKeepalive")
            .field("datagram_len", &self.datagram.len())
            .finish()
    }
}

/// UDP/4500 ESP candidate with the first ESP header words parsed.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NatTraversalEspCandidate<'a> {
    datagram: &'a [u8],
    spi: u32,
    sequence_number: u32,
}

impl<'a> NatTraversalEspCandidate<'a> {
    /// Complete UDP datagram bytes.
    #[must_use]
    pub const fn datagram(&self) -> &'a [u8] {
        self.datagram
    }

    /// ESP Security Parameters Index.
    #[must_use]
    pub const fn spi(&self) -> u32 {
        self.spi
    }

    /// ESP sequence number.
    #[must_use]
    pub const fn sequence_number(&self) -> u32 {
        self.sequence_number
    }
}

impl fmt::Debug for NatTraversalEspCandidate<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NatTraversalEspCandidate")
            .field("datagram_len", &self.datagram.len())
            .field("has_spi", &true)
            .field("has_sequence_number", &true)
            .finish()
    }
}

/// Datagram rejection outcome.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum NatTraversalRejection<'a> {
    /// UDP destination port is neither 500 nor 4500.
    UnsupportedPort {
        /// UDP destination port observed by the caller.
        udp_destination_port: u16,
    },
    /// IKE bytes could not be decoded.
    MalformedIke {
        /// Transport encapsulation used by the datagram.
        transport: NatTraversalIkeTransport,
        /// Stable mapped IKE decode error class.
        decode_code: NatTraversalIkeDecodeErrorCode,
    },
    /// IKE message decoded but left bytes beyond the declared IKE length.
    TrailingIkeBytes {
        /// Transport encapsulation used by the datagram.
        transport: NatTraversalIkeTransport,
        /// IKE length declared by the fixed header.
        declared_len: usize,
        /// IKE bytes supplied to the decoder.
        actual_len: usize,
    },
    /// UDP/4500 datagram is not a keepalive, not IKE, and too short for ESP.
    RuntEspCandidate {
        /// Complete UDP datagram bytes.
        datagram: &'a [u8],
    },
}

impl NatTraversalRejection<'_> {
    /// Stable machine-readable rejection code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedPort { .. } => "natt_unsupported_udp_port",
            Self::MalformedIke { decode_code, .. } => decode_code.code(),
            Self::TrailingIkeBytes { .. } => "ike_trailing_bytes",
            Self::RuntEspCandidate { .. } => "natt_esp_runt",
        }
    }

    /// UDP destination port when the rejection is associated with a known port.
    #[must_use]
    pub const fn udp_destination_port(&self) -> Option<u16> {
        match self {
            Self::UnsupportedPort {
                udp_destination_port,
            } => Some(*udp_destination_port),
            Self::MalformedIke { transport, .. } | Self::TrailingIkeBytes { transport, .. } => {
                Some(transport.udp_destination_port())
            }
            Self::RuntEspCandidate { .. } => Some(IKE_NAT_TRAVERSAL_UDP_PORT),
        }
    }

    /// Length of the rejected datagram when still available.
    #[must_use]
    pub const fn datagram_len(&self) -> Option<usize> {
        match self {
            Self::UnsupportedPort { .. } => None,
            Self::MalformedIke { .. } | Self::TrailingIkeBytes { .. } => None,
            Self::RuntEspCandidate { datagram } => Some(datagram.len()),
        }
    }
}

impl fmt::Debug for NatTraversalRejection<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPort {
                udp_destination_port,
            } => f
                .debug_struct("UnsupportedPort")
                .field("udp_destination_port", udp_destination_port)
                .finish(),
            Self::MalformedIke {
                transport,
                decode_code,
            } => f
                .debug_struct("MalformedIke")
                .field("transport", transport)
                .field("decode_code", decode_code)
                .finish(),
            Self::TrailingIkeBytes {
                transport,
                declared_len,
                actual_len,
            } => f
                .debug_struct("TrailingIkeBytes")
                .field("transport", transport)
                .field("declared_len", declared_len)
                .field("actual_len", actual_len)
                .finish(),
            Self::RuntEspCandidate { datagram } => f
                .debug_struct("RuntEspCandidate")
                .field("datagram_len", &datagram.len())
                .field("minimum_len", &ESP_HEADER_PREFIX_LEN)
                .finish(),
        }
    }
}

/// IKE transport selected by UDP destination port and NAT-T marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NatTraversalIkeTransport {
    /// IKE sent directly on UDP/500.
    Udp500,
    /// IKE sent on UDP/4500 after the four-byte non-ESP marker.
    Udp4500NonEspMarker,
}

impl NatTraversalIkeTransport {
    /// Stable machine-readable accepted IKE classification code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Udp500 => "ike_udp_500",
            Self::Udp4500NonEspMarker => "natt_ike_non_esp_marker",
        }
    }

    /// UDP destination port used by this transport.
    #[must_use]
    pub const fn udp_destination_port(self) -> u16 {
        match self {
            Self::Udp500 => IKE_UDP_PORT,
            Self::Udp4500NonEspMarker => IKE_NAT_TRAVERSAL_UDP_PORT,
        }
    }
}

/// Stable IKE decode error class used by NAT-T classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NatTraversalIkeDecodeErrorCode {
    /// IKE bytes ended before a required field was complete.
    Truncated,
    /// IKE header or payload length was invalid.
    InvalidLength,
    /// IKE message exceeded caller-supplied decode limits.
    MessageLengthExceeded,
    /// IKE length arithmetic overflowed platform bounds.
    LengthOverflow,
    /// IKE field carried an unsupported enum value.
    InvalidEnumValue,
    /// IKE payload chain contained an unknown critical payload.
    UnknownCriticalPayload,
    /// IKE payload count exceeded caller-supplied decode limits.
    PayloadCountExceeded,
    /// IKE bytes failed a structural validation rule.
    Structural,
}

impl NatTraversalIkeDecodeErrorCode {
    /// Stable machine-readable decode error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Truncated => "ike_truncated",
            Self::InvalidLength => "ike_invalid_length",
            Self::MessageLengthExceeded => "ike_message_length_exceeded",
            Self::LengthOverflow => "ike_length_overflow",
            Self::InvalidEnumValue => "ike_invalid_enum_value",
            Self::UnknownCriticalPayload => "ike_unknown_critical_payload",
            Self::PayloadCountExceeded => "ike_payload_count_exceeded",
            Self::Structural => "ike_structural_error",
        }
    }
}

impl From<&DecodeErrorCode> for NatTraversalIkeDecodeErrorCode {
    fn from(value: &DecodeErrorCode) -> Self {
        match value {
            DecodeErrorCode::Truncated => Self::Truncated,
            DecodeErrorCode::InvalidLength { .. } => Self::InvalidLength,
            DecodeErrorCode::MessageLengthExceeded => Self::MessageLengthExceeded,
            DecodeErrorCode::LengthOverflow => Self::LengthOverflow,
            DecodeErrorCode::InvalidEnumValue { .. } => Self::InvalidEnumValue,
            DecodeErrorCode::UnknownCriticalIe => Self::UnknownCriticalPayload,
            DecodeErrorCode::IeCountExceeded => Self::PayloadCountExceeded,
            DecodeErrorCode::Structural { .. } => Self::Structural,
            _ => Self::Structural,
        }
    }
}
