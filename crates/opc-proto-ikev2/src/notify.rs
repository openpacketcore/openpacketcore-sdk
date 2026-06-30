//! IKEv2 Notify payload helpers for COOKIE retry boundaries.
//!
//! @spec IETF RFC7296 2.6, 3.10
//! @req REQ-IETF-RFC7296-NOTIFY-COOKIE-001

use std::{error::Error, fmt};

use bytes::Bytes;
use opc_protocol::{DecodeContext, DecodeError};

use crate::{
    header::{Header, HeaderFlags, EXCHANGE_TYPE_IKE_SA_INIT},
    message::{Message, OwnedMessage},
    payload::{PayloadType, RawPayload, GENERIC_PAYLOAD_HEADER_LEN},
    HEADER_LEN,
};

/// IKEv2 Notify Message Type for COOKIE.
///
/// @spec IETF RFC7296 2.6; IANA IKEv2 Notify Message Status Types
/// @req REQ-IETF-RFC7296-NOTIFY-COOKIE-CONST-001
/// @conformance boundary-only
pub const IKEV2_NOTIFY_COOKIE: u16 = 16_390;

/// IKEv2 Notify Message Type for NAT_DETECTION_SOURCE_IP.
///
/// @spec IETF RFC7296 2.23; IANA IKEv2 Notify Message Status Types
/// @req REQ-IETF-RFC7296-NATD-CONST-001
/// @conformance boundary-only
pub const IKEV2_NOTIFY_NAT_DETECTION_SOURCE_IP: u16 = 16_388;

/// IKEv2 Notify Message Type for NAT_DETECTION_DESTINATION_IP.
///
/// @spec IETF RFC7296 2.23; IANA IKEv2 Notify Message Status Types
/// @req REQ-IETF-RFC7296-NATD-CONST-002
/// @conformance boundary-only
pub const IKEV2_NOTIFY_NAT_DETECTION_DESTINATION_IP: u16 = 16_389;

/// IKEv2 Notify Message Type for COOKIE2.
///
/// @spec IETF RFC4555; IANA IKEv2 Notify Message Status Types
/// @req REQ-IETF-RFC7296-NOTIFY-COOKIE-CONST-002
/// @conformance boundary-only
pub const IKEV2_NOTIFY_COOKIE2: u16 = 16_401;

/// Protocol ID used by IKE-level notifications with no protocol-specific SPI.
pub const IKEV2_NOTIFY_PROTOCOL_ID_NONE: u8 = 0;

const NOTIFY_FIXED_BODY_LEN: usize = 4;

/// Borrowed typed view of a cleartext IKEv2 Notify payload body.
///
/// `Debug` reports only byte lengths for SPI and notification data.
///
/// @spec IETF RFC7296 3.10
/// @req REQ-IETF-RFC7296-NOTIFY-VIEW-001
/// @conformance boundary-only
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ikev2NotifyPayload<'a> {
    /// Security Protocol ID.
    pub protocol_id: u8,
    /// SPI size in octets.
    pub spi_size: u8,
    /// Notify Message Type.
    pub notify_message_type: u16,
    /// SPI bytes, if any.
    pub spi: &'a [u8],
    /// Notification data bytes.
    pub notification_data: &'a [u8],
}

impl<'a> Ikev2NotifyPayload<'a> {
    /// Decode a typed Notify payload from a raw generic payload.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2NotifyPayloadError`] when the raw payload is not Notify
    /// or the Notify body is structurally malformed.
    pub fn decode(raw: RawPayload<'a>) -> Result<Self, Ikev2NotifyPayloadError> {
        if raw.payload_type != PayloadType::Notify {
            return Err(Ikev2NotifyPayloadError::NotNotifyPayload);
        }
        Self::decode_body(raw.body)
    }

    /// Decode a typed Notify payload from a cleartext Notify body.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2NotifyPayloadError`] when the Notify body is structurally
    /// malformed.
    pub fn decode_body(body: &'a [u8]) -> Result<Self, Ikev2NotifyPayloadError> {
        if body.len() < NOTIFY_FIXED_BODY_LEN {
            return Err(Ikev2NotifyPayloadError::BodyTooShort);
        }
        let protocol_id = body[0];
        let spi_size = body[1];
        let notify_message_type = u16::from_be_bytes([body[2], body[3]]);
        let spi_len = usize::from(spi_size);
        let spi_start = NOTIFY_FIXED_BODY_LEN;
        let data_start = spi_start
            .checked_add(spi_len)
            .ok_or(Ikev2NotifyPayloadError::SpiLengthExceedsBody)?;
        if data_start > body.len() {
            return Err(Ikev2NotifyPayloadError::SpiLengthExceedsBody);
        }
        Ok(Self {
            protocol_id,
            spi_size,
            notify_message_type,
            spi: &body[spi_start..data_start],
            notification_data: &body[data_start..],
        })
    }

    /// Return true when this is a COOKIE Notify payload.
    pub const fn is_cookie(self) -> bool {
        self.notify_message_type == IKEV2_NOTIFY_COOKIE
    }

    /// Return true when this is a NAT_DETECTION_SOURCE_IP Notify payload.
    pub const fn is_nat_detection_source_ip(self) -> bool {
        self.notify_message_type == IKEV2_NOTIFY_NAT_DETECTION_SOURCE_IP
    }

    /// Return true when this is a NAT_DETECTION_DESTINATION_IP Notify payload.
    pub const fn is_nat_detection_destination_ip(self) -> bool {
        self.notify_message_type == IKEV2_NOTIFY_NAT_DETECTION_DESTINATION_IP
    }

    /// Return true when this is either NAT-D Notify payload type.
    pub const fn is_nat_detection(self) -> bool {
        self.is_nat_detection_source_ip() || self.is_nat_detection_destination_ip()
    }

    /// Return true when this is a COOKIE2 Notify payload.
    pub const fn is_cookie2(self) -> bool {
        self.notify_message_type == IKEV2_NOTIFY_COOKIE2
    }

    /// Return true when Protocol ID and SPI Size have the cookie-compatible shape.
    pub const fn has_empty_protocol_spi(self) -> bool {
        self.protocol_id == IKEV2_NOTIFY_PROTOCOL_ID_NONE && self.spi_size == 0
    }
}

impl fmt::Debug for Ikev2NotifyPayload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2NotifyPayload")
            .field("protocol_id", &self.protocol_id)
            .field("spi_size", &self.spi_size)
            .field("notify_message_type", &self.notify_message_type)
            .field("spi_len", &self.spi.len())
            .field("notification_data_len", &self.notification_data.len())
            .finish()
    }
}

/// Error returned while decoding a typed Notify payload view.
///
/// @spec IETF RFC7296 3.10
/// @req REQ-IETF-RFC7296-NOTIFY-VIEW-ERROR-001
/// @conformance boundary-only
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2NotifyPayloadError {
    /// The raw generic payload type was not Notify.
    NotNotifyPayload,
    /// Notify body ended before Protocol ID, SPI Size, and Notify Message Type.
    BodyTooShort,
    /// SPI Size extends past the Notify body.
    SpiLengthExceedsBody,
}

impl Ikev2NotifyPayloadError {
    /// Stable machine-readable error code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotNotifyPayload => "ike_notify_not_notify_payload",
            Self::BodyTooShort => "ike_notify_body_too_short",
            Self::SpiLengthExceedsBody => "ike_notify_spi_length_exceeds_body",
        }
    }
}

impl fmt::Display for Ikev2NotifyPayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for Ikev2NotifyPayloadError {}

/// Borrowed COOKIE Notify observation from an IKE_SA_INIT request.
///
/// `Debug` reports the cookie length but not the cookie bytes.
///
/// @spec IETF RFC7296 2.6
/// @req REQ-IETF-RFC7296-NOTIFY-COOKIE-EXTRACT-001
/// @conformance boundary-only
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ikev2CookieNotify<'a> {
    /// Byte offset of the COOKIE Notify generic payload from the payload region.
    pub offset: usize,
    /// Typed Notify payload view.
    pub notify: Ikev2NotifyPayload<'a>,
}

impl<'a> Ikev2CookieNotify<'a> {
    /// Return the responder-supplied cookie bytes.
    pub const fn cookie(self) -> &'a [u8] {
        self.notify.notification_data
    }
}

impl fmt::Debug for Ikev2CookieNotify<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2CookieNotify")
            .field("offset", &self.offset)
            .field("notify_message_type", &self.notify.notify_message_type)
            .field("cookie_len", &self.notify.notification_data.len())
            .finish()
    }
}

/// Error returned while building an IKE_SA_INIT COOKIE response.
///
/// @spec IETF RFC7296 2.6
/// @req REQ-IETF-RFC7296-NOTIFY-COOKIE-BUILD-ERROR-001
/// @conformance boundary-only
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2CookieNotifyBuildError {
    /// The input header was not an IKE_SA_INIT exchange.
    NotIkeSaInit,
    /// The input header was already a response.
    ResponseHeader,
    /// IKE_SA_INIT request Message ID was not zero.
    MessageIdNonZero,
    /// IKE_SA_INIT request carried a non-zero responder SPI.
    ResponderSpiNonZero,
    /// The Notify payload or complete message length exceeded IKEv2 fields.
    LengthOverflow,
}

impl Ikev2CookieNotifyBuildError {
    /// Stable machine-readable error code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotIkeSaInit => "ike_cookie_response_not_ike_sa_init",
            Self::ResponseHeader => "ike_cookie_response_from_response_header",
            Self::MessageIdNonZero => "ike_cookie_response_message_id_non_zero",
            Self::ResponderSpiNonZero => "ike_cookie_response_responder_spi_non_zero",
            Self::LengthOverflow => "ike_cookie_response_length_overflow",
        }
    }
}

impl fmt::Display for Ikev2CookieNotifyBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for Ikev2CookieNotifyBuildError {}

/// Error returned while extracting a COOKIE Notify from an IKE_SA_INIT request.
///
/// @spec IETF RFC7296 2.6, 3.10
/// @req REQ-IETF-RFC7296-NOTIFY-COOKIE-EXTRACT-ERROR-001
/// @conformance boundary-only
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ikev2CookieNotifyExtractError {
    /// The input message was not an IKE_SA_INIT exchange.
    NotIkeSaInit,
    /// The input message was a response.
    ResponseMessage,
    /// IKE_SA_INIT request Message ID was not zero.
    MessageIdNonZero,
    /// IKE_SA_INIT request carried a non-zero responder SPI.
    ResponderSpiNonZero,
    /// The generic payload chain could not be walked.
    PayloadDecode(DecodeError),
    /// A Notify payload body was structurally malformed.
    NotifyDecode(Ikev2NotifyPayloadError),
    /// COOKIE Notify Protocol ID or SPI Size was not zero.
    InvalidCookieShape,
    /// More than one COOKIE Notify payload was present.
    DuplicateCookieNotify,
}

impl Ikev2CookieNotifyExtractError {
    /// Stable machine-readable error code.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NotIkeSaInit => "ike_cookie_extract_not_ike_sa_init",
            Self::ResponseMessage => "ike_cookie_extract_response_message",
            Self::MessageIdNonZero => "ike_cookie_extract_message_id_non_zero",
            Self::ResponderSpiNonZero => "ike_cookie_extract_responder_spi_non_zero",
            Self::PayloadDecode(_) => "ike_cookie_extract_payload_decode_error",
            Self::NotifyDecode(_) => "ike_cookie_extract_notify_decode_error",
            Self::InvalidCookieShape => "ike_cookie_extract_invalid_cookie_shape",
            Self::DuplicateCookieNotify => "ike_cookie_extract_duplicate_cookie_notify",
        }
    }
}

impl fmt::Display for Ikev2CookieNotifyExtractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for Ikev2CookieNotifyExtractError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::PayloadDecode(error) => Some(error),
            Self::NotifyDecode(error) => Some(error),
            _ => None,
        }
    }
}

/// Build an IKE_SA_INIT response containing a single COOKIE Notify payload.
///
/// The caller owns cookie generation, HMAC/source binding, secret rotation, and
/// admission policy. The SDK only emits the RFC 7296 IKE and Notify payload
/// shape.
///
/// # Errors
///
/// Returns [`Ikev2CookieNotifyBuildError`] when the supplied header is not an
/// initial IKE_SA_INIT request or the cookie is too large for IKEv2 payload
/// length fields.
pub fn build_ike_sa_init_cookie_response(
    request_header: &Header,
    cookie: &[u8],
) -> Result<OwnedMessage, Ikev2CookieNotifyBuildError> {
    validate_cookie_response_request_header(request_header)?;

    let raw_payloads = build_cookie_notify_payload(cookie)?;
    let total_len = HEADER_LEN
        .checked_add(raw_payloads.len())
        .ok_or(Ikev2CookieNotifyBuildError::LengthOverflow)?;
    let total_len_u32 =
        u32::try_from(total_len).map_err(|_| Ikev2CookieNotifyBuildError::LengthOverflow)?;
    let mut header = Header::new(
        request_header.initiator_spi,
        0,
        PayloadType::Notify,
        EXCHANGE_TYPE_IKE_SA_INIT,
        HeaderFlags::from_bits(request_header.flags.initiator(), true, false),
        request_header.message_id,
    );
    header.length = total_len_u32;

    Ok(OwnedMessage {
        header,
        raw_payloads: Bytes::from(raw_payloads),
    })
}

/// Extract zero or one COOKIE Notify from a cleartext IKE_SA_INIT request.
///
/// COOKIE2 and other Notify payloads are parsed by [`Ikev2NotifyPayload`] but
/// ignored by this COOKIE-specific extractor. Duplicate COOKIE Notify payloads
/// fail closed with a stable error code.
///
/// # Errors
///
/// Returns [`Ikev2CookieNotifyExtractError`] when the message is not an
/// IKE_SA_INIT request, the payload chain is malformed, a COOKIE Notify has an
/// invalid cookie shape, or duplicate COOKIE Notify payloads are present.
pub fn extract_ike_sa_init_cookie_notify<'a>(
    message: &Message<'a>,
    ctx: DecodeContext,
) -> Result<Option<Ikev2CookieNotify<'a>>, Ikev2CookieNotifyExtractError> {
    validate_ike_sa_init_request_header(&message.header)?;

    let mut cookie = None;
    for raw in message.payloads_with_context(ctx) {
        let raw = raw.map_err(Ikev2CookieNotifyExtractError::PayloadDecode)?;
        if raw.payload_type != PayloadType::Notify {
            continue;
        }
        let notify =
            Ikev2NotifyPayload::decode(raw).map_err(Ikev2CookieNotifyExtractError::NotifyDecode)?;
        if !notify.is_cookie() {
            continue;
        }
        if !notify.has_empty_protocol_spi() || !notify.spi.is_empty() {
            return Err(Ikev2CookieNotifyExtractError::InvalidCookieShape);
        }
        if cookie.is_some() {
            return Err(Ikev2CookieNotifyExtractError::DuplicateCookieNotify);
        }
        cookie = Some(Ikev2CookieNotify {
            offset: raw.offset,
            notify,
        });
    }

    Ok(cookie)
}

fn validate_ike_sa_init_request_header(
    header: &Header,
) -> Result<(), Ikev2CookieNotifyExtractError> {
    if header.exchange_type != EXCHANGE_TYPE_IKE_SA_INIT {
        return Err(Ikev2CookieNotifyExtractError::NotIkeSaInit);
    }
    if header.flags.response() {
        return Err(Ikev2CookieNotifyExtractError::ResponseMessage);
    }
    if header.message_id != 0 {
        return Err(Ikev2CookieNotifyExtractError::MessageIdNonZero);
    }
    if header.responder_spi != 0 {
        return Err(Ikev2CookieNotifyExtractError::ResponderSpiNonZero);
    }
    Ok(())
}

fn validate_cookie_response_request_header(
    header: &Header,
) -> Result<(), Ikev2CookieNotifyBuildError> {
    if header.exchange_type != EXCHANGE_TYPE_IKE_SA_INIT {
        return Err(Ikev2CookieNotifyBuildError::NotIkeSaInit);
    }
    if header.flags.response() {
        return Err(Ikev2CookieNotifyBuildError::ResponseHeader);
    }
    if header.message_id != 0 {
        return Err(Ikev2CookieNotifyBuildError::MessageIdNonZero);
    }
    if header.responder_spi != 0 {
        return Err(Ikev2CookieNotifyBuildError::ResponderSpiNonZero);
    }
    Ok(())
}

fn build_cookie_notify_payload(cookie: &[u8]) -> Result<Vec<u8>, Ikev2CookieNotifyBuildError> {
    let notify_body_len = NOTIFY_FIXED_BODY_LEN
        .checked_add(cookie.len())
        .ok_or(Ikev2CookieNotifyBuildError::LengthOverflow)?;
    let payload_len = GENERIC_PAYLOAD_HEADER_LEN
        .checked_add(notify_body_len)
        .ok_or(Ikev2CookieNotifyBuildError::LengthOverflow)?;
    let payload_len_u16 =
        u16::try_from(payload_len).map_err(|_| Ikev2CookieNotifyBuildError::LengthOverflow)?;

    let mut payload = Vec::with_capacity(payload_len);
    payload.push(PayloadType::NoNext.as_u8());
    payload.push(0);
    payload.extend_from_slice(&payload_len_u16.to_be_bytes());
    payload.push(IKEV2_NOTIFY_PROTOCOL_ID_NONE);
    payload.push(0);
    payload.extend_from_slice(&IKEV2_NOTIFY_COOKIE.to_be_bytes());
    payload.extend_from_slice(cookie);
    Ok(payload)
}
