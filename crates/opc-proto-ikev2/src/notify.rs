//! IKEv2 Notify payload registry and COOKIE retry helpers.
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

/// IKEv2 Notify error type for UNSUPPORTED_CRITICAL_PAYLOAD.
///
/// @spec IETF RFC7296 3.10.1
/// @conformance boundary-only
pub const IKEV2_NOTIFY_UNSUPPORTED_CRITICAL_PAYLOAD: u16 = 1;

/// IKEv2 Notify error type for INVALID_IKE_SPI.
///
/// @spec IETF RFC7296 3.10.1
/// @conformance boundary-only
pub const IKEV2_NOTIFY_INVALID_IKE_SPI: u16 = 4;

/// IKEv2 Notify error type for INVALID_MAJOR_VERSION.
///
/// @spec IETF RFC7296 3.10.1
/// @conformance boundary-only
pub const IKEV2_NOTIFY_INVALID_MAJOR_VERSION: u16 = 5;

/// IKEv2 Notify error type for INVALID_SYNTAX.
///
/// @spec IETF RFC7296 3.10.1
/// @conformance boundary-only
pub const IKEV2_NOTIFY_INVALID_SYNTAX: u16 = 7;

/// IKEv2 Notify error type for INVALID_MESSAGE_ID.
///
/// @spec IETF RFC7296 3.10.1
/// @conformance boundary-only
pub const IKEV2_NOTIFY_INVALID_MESSAGE_ID: u16 = 9;

/// IKEv2 Notify error type for INVALID_SPI.
///
/// @spec IETF RFC7296 3.10.1
/// @conformance boundary-only
pub const IKEV2_NOTIFY_INVALID_SPI: u16 = 11;

/// IKEv2 Notify error type for NO_PROPOSAL_CHOSEN.
///
/// @spec IETF RFC7296 3.10.1
/// @conformance boundary-only
pub const IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN: u16 = 14;

/// IKEv2 Notify error type for INVALID_KE_PAYLOAD.
///
/// @spec IETF RFC7296 3.10.1
/// @conformance boundary-only
pub const IKEV2_NOTIFY_INVALID_KE_PAYLOAD: u16 = 17;

/// IKEv2 Notify error type for AUTHENTICATION_FAILED.
///
/// @spec IETF RFC7296 3.10.1
/// @conformance boundary-only
pub const IKEV2_NOTIFY_AUTHENTICATION_FAILED: u16 = 24;

/// IKEv2 Notify error type for SINGLE_PAIR_REQUIRED.
///
/// @spec IETF RFC7296 3.10.1
/// @conformance boundary-only
pub const IKEV2_NOTIFY_SINGLE_PAIR_REQUIRED: u16 = 34;

/// IKEv2 Notify error type for NO_ADDITIONAL_SAS.
///
/// @spec IETF RFC7296 3.10.1
/// @conformance boundary-only
pub const IKEV2_NOTIFY_NO_ADDITIONAL_SAS: u16 = 35;

/// IKEv2 Notify error type for INTERNAL_ADDRESS_FAILURE.
///
/// @spec IETF RFC7296 3.10.1
/// @conformance boundary-only
pub const IKEV2_NOTIFY_INTERNAL_ADDRESS_FAILURE: u16 = 36;

/// IKEv2 Notify error type for FAILED_CP_REQUIRED.
///
/// @spec IETF RFC7296 3.10.1
/// @conformance boundary-only
pub const IKEV2_NOTIFY_FAILED_CP_REQUIRED: u16 = 37;

/// IKEv2 Notify error type for TS_UNACCEPTABLE.
///
/// @spec IETF RFC7296 3.10.1
/// @conformance boundary-only
pub const IKEV2_NOTIFY_TS_UNACCEPTABLE: u16 = 38;

/// IKEv2 Notify error type for INVALID_SELECTORS.
///
/// @spec IETF RFC7296 3.10.1
/// @conformance boundary-only
pub const IKEV2_NOTIFY_INVALID_SELECTORS: u16 = 39;

/// IKEv2 Notify error type for TEMPORARY_FAILURE.
///
/// @spec IETF RFC7296 3.10.1
/// @conformance boundary-only
pub const IKEV2_NOTIFY_TEMPORARY_FAILURE: u16 = 43;

/// IKEv2 Notify error type for CHILD_SA_NOT_FOUND.
///
/// @spec IETF RFC7296 3.10.1
/// @conformance boundary-only
pub const IKEV2_NOTIFY_CHILD_SA_NOT_FOUND: u16 = 44;

/// 3GPP private IKEv2 Notify error type for AUTHORIZATION_REJECTED.
///
/// TS 24.302 uses this value when an ePDG rejects tunnel establishment because
/// the user is barred from non-3GPP access or the subscribed APN. The product
/// remains responsible for choosing this outcome from trusted authorization
/// state.
///
/// @spec 3GPP TS24.302 7.4.1.2, 8.1.2.2
/// @conformance boundary-only
pub const IKEV2_NOTIFY_AUTHORIZATION_REJECTED: u16 = 9_003;

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

/// IKEv2 Notify Message Type for COOKIE.
///
/// @spec IETF RFC7296 2.6; IANA IKEv2 Notify Message Status Types
/// @req REQ-IETF-RFC7296-NOTIFY-COOKIE-CONST-001
/// @conformance boundary-only
pub const IKEV2_NOTIFY_COOKIE: u16 = 16_390;

/// IKEv2 Notify Message Type for REKEY_SA.
///
/// A CREATE_CHILD_SA exchange that replaces an existing Child SA carries this
/// status notify with the protocol ID and inbound AH/ESP SPI of the SA being
/// rekeyed. The notification data field is empty.
///
/// @spec IETF RFC7296 1.3.3, 3.10.1; IANA IKEv2 Notify Message Status Types
/// @conformance boundary-only
pub const IKEV2_NOTIFY_REKEY_SA: u16 = 16_393;

/// IKEv2 Notify Message Type for COOKIE2.
///
/// @spec IETF RFC4555; IANA IKEv2 Notify Message Status Types
/// @req REQ-IETF-RFC7296-NOTIFY-COOKIE-CONST-002
/// @conformance boundary-only
pub const IKEV2_NOTIFY_COOKIE2: u16 = 16_401;

/// IKEv2 Notify Message Type for EAP_ONLY_AUTHENTICATION.
///
/// A peer includes this status notify in its IKE_AUTH request to signal that it
/// accepts EAP-only mutual authentication, so the responder need not send a
/// certificate and signature AUTH.
///
/// @spec IETF RFC5998; IANA IKEv2 Notify Message Status Types
/// @conformance boundary-only
pub const IKEV2_NOTIFY_EAP_ONLY_AUTHENTICATION: u16 = 16_417;

/// IKEv2 Notify Message Type for 3GPP DEVICE_IDENTITY.
///
/// @spec 3GPP TS24.302 8.2.9.2
/// @conformance boundary-only
pub const IKEV2_NOTIFY_DEVICE_IDENTITY: u16 = 41_101;

/// IKEv2 Notify Message Type for 3GPP P_CSCF_RESELECTION_SUPPORT.
///
/// A UE includes this status Notify in an IKE_AUTH request to indicate support
/// for the P-CSCF restoration extension over untrusted WLAN.
///
/// @spec 3GPP TS24.302 7.2.1, 7.4.1.1, 8.1.2.3, 8.2.9.4
/// @conformance boundary-only
pub const IKEV2_NOTIFY_P_CSCF_RESELECTION_SUPPORT: u16 = 41_304;

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

    /// Return true when this is a canonical EAP_ONLY_AUTHENTICATION Notify.
    ///
    /// RFC 5998 requires Protocol ID zero, SPI Size zero, no SPI, and no
    /// notification data. This helper validates that complete shape rather
    /// than recognizing Notify Message Type 16417 alone.
    ///
    /// This compatibility predicate loses the distinction between an
    /// unrelated Notify and a malformed type-16417 Notify. Use
    /// [`decode_ikev2_eap_only_authentication_notify`] for new code.
    ///
    /// @spec IETF RFC5998 3
    #[deprecated(
        note = "use decode_ikev2_eap_only_authentication_notify for typed shape validation"
    )]
    pub const fn is_eap_only_authentication(self) -> bool {
        self.notify_message_type == IKEV2_NOTIFY_EAP_ONLY_AUTHENTICATION
            && self.protocol_id == IKEV2_NOTIFY_PROTOCOL_ID_NONE
            && self.spi_size == 0
            && self.spi.is_empty()
            && self.notification_data.is_empty()
    }

    /// Return true when this is a 3GPP DEVICE_IDENTITY Notify payload.
    pub const fn is_device_identity(self) -> bool {
        self.notify_message_type == IKEV2_NOTIFY_DEVICE_IDENTITY
    }

    /// Return true for a received 3GPP AUTHORIZATION_REJECTED Notify body.
    ///
    /// The typed form has no SPI and no notification data. RFC 7296 requires
    /// receivers to ignore Protocol ID when SPI Size is zero, so that field is
    /// deliberately not inspected here. Senders use
    /// [`Ikev2NotifyPayloadBuild::authorization_rejected`](crate::Ikev2NotifyPayloadBuild::authorization_rejected)
    /// to emit the canonical Protocol ID zero representation.
    ///
    /// @spec 3GPP TS24.302 8.1.2.2; IETF RFC7296 3.10
    pub const fn is_authorization_rejected(self) -> bool {
        self.notify_message_type == IKEV2_NOTIFY_AUTHORIZATION_REJECTED
            && self.spi_size == 0
            && self.spi.is_empty()
            && self.notification_data.is_empty()
    }

    /// Return true when Protocol ID and SPI Size have the cookie-compatible shape.
    pub const fn has_empty_protocol_spi(self) -> bool {
        self.protocol_id == IKEV2_NOTIFY_PROTOCOL_ID_NONE && self.spi_size == 0
    }
}

/// Validated RFC 5998 EAP_ONLY_AUTHENTICATION signal.
///
/// Values can only be obtained by validating a decoded Notify with
/// [`decode_ikev2_eap_only_authentication_notify`] or an opened IKE_AUTH
/// payload set with
/// [`Ikev2IkeAuthCleartextPayloads::eap_only_authentication`](crate::Ikev2IkeAuthCleartextPayloads::eap_only_authentication).
///
/// @spec IETF RFC5998 3
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ikev2EapOnlyAuthentication {
    _private: (),
}

impl fmt::Debug for Ikev2EapOnlyAuthentication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ikev2EapOnlyAuthentication")
    }
}

/// Structural failure for a type-16417 EAP_ONLY_AUTHENTICATION Notify.
///
/// Validation reports the first invalid field in RFC 5998 wire order:
/// Protocol ID, SPI Size, SPI bytes, then notification data. Variants contain
/// no packet bytes or peer identifiers.
///
/// @spec IETF RFC5998 3
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2EapOnlyAuthenticationNotifyError {
    /// Protocol ID was not zero.
    ProtocolIdNonzero,
    /// The declared SPI Size was not zero.
    SpiSizeNonzero,
    /// SPI bytes were present despite a zero SPI Size.
    SpiNonempty,
    /// Notification data was present.
    NotificationDataNonempty,
}

impl Ikev2EapOnlyAuthenticationNotifyError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProtocolIdNonzero => "ike_eap_only_authentication_protocol_id_nonzero",
            Self::SpiSizeNonzero => "ike_eap_only_authentication_spi_size_nonzero",
            Self::SpiNonempty => "ike_eap_only_authentication_spi_nonempty",
            Self::NotificationDataNonempty => {
                "ike_eap_only_authentication_notification_data_nonempty"
            }
        }
    }
}

impl fmt::Display for Ikev2EapOnlyAuthenticationNotifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for Ikev2EapOnlyAuthenticationNotifyError {}

/// Decode one RFC 5998 EAP_ONLY_AUTHENTICATION Notify occurrence.
///
/// An unrelated Notify returns `Ok(None)`. A canonical type-16417 Notify
/// returns `Ok(Some(_))`. A type-16417 Notify with any non-canonical structural
/// field returns a typed error while the original lossless
/// [`Ikev2NotifyPayload`] remains owned by the caller.
///
/// # Errors
///
/// Returns [`Ikev2EapOnlyAuthenticationNotifyError`] when a type-16417 Notify
/// has nonzero Protocol ID or SPI Size, nonempty SPI bytes, or nonempty
/// notification data.
///
/// @spec IETF RFC5998 3
pub const fn decode_ikev2_eap_only_authentication_notify(
    notify: Ikev2NotifyPayload<'_>,
) -> Result<Option<Ikev2EapOnlyAuthentication>, Ikev2EapOnlyAuthenticationNotifyError> {
    if notify.notify_message_type != IKEV2_NOTIFY_EAP_ONLY_AUTHENTICATION {
        return Ok(None);
    }
    if notify.protocol_id != IKEV2_NOTIFY_PROTOCOL_ID_NONE {
        return Err(Ikev2EapOnlyAuthenticationNotifyError::ProtocolIdNonzero);
    }
    if notify.spi_size != 0 {
        return Err(Ikev2EapOnlyAuthenticationNotifyError::SpiSizeNonzero);
    }
    if !notify.spi.is_empty() {
        return Err(Ikev2EapOnlyAuthenticationNotifyError::SpiNonempty);
    }
    if !notify.notification_data.is_empty() {
        return Err(Ikev2EapOnlyAuthenticationNotifyError::NotificationDataNonempty);
    }
    Ok(Some(Ikev2EapOnlyAuthentication { _private: () }))
}

/// Validated 3GPP P_CSCF_RESELECTION_SUPPORT signal.
///
/// Values can only be obtained by validating a decoded Notify with
/// [`decode_ikev2_pcscf_reselection_support_notify`].
///
/// @spec 3GPP TS24.302 8.2.9.4
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ikev2PcscfReselectionSupport {
    _private: (),
}

impl fmt::Debug for Ikev2PcscfReselectionSupport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ikev2PcscfReselectionSupport")
    }
}

/// Structural failure for a type-41304 P_CSCF_RESELECTION_SUPPORT Notify.
///
/// Validation reports the first invalid field in TS 24.302 wire order:
/// Protocol ID, SPI Size, SPI bytes, then notification data. Variants contain
/// no packet bytes, endpoint addresses, or subscriber identity.
///
/// @spec 3GPP TS24.302 8.2.9.4
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2PcscfReselectionSupportNotifyError {
    /// Protocol ID was not zero.
    ProtocolIdNonzero,
    /// The declared SPI Size was not zero.
    SpiSizeNonzero,
    /// SPI bytes were present despite a zero SPI Size.
    SpiNonempty,
    /// Notification data was present.
    NotificationDataNonempty,
}

impl Ikev2PcscfReselectionSupportNotifyError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProtocolIdNonzero => "ike_pcscf_reselection_support_protocol_id_nonzero",
            Self::SpiSizeNonzero => "ike_pcscf_reselection_support_spi_size_nonzero",
            Self::SpiNonempty => "ike_pcscf_reselection_support_spi_nonempty",
            Self::NotificationDataNonempty => {
                "ike_pcscf_reselection_support_notification_data_nonempty"
            }
        }
    }
}

impl fmt::Display for Ikev2PcscfReselectionSupportNotifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for Ikev2PcscfReselectionSupportNotifyError {}

/// Decode one 3GPP P_CSCF_RESELECTION_SUPPORT Notify occurrence.
///
/// An unrelated Notify returns `Ok(None)`. A canonical type-41304 Notify
/// returns `Ok(Some(_))`. A type-41304 Notify with any non-canonical structural
/// field returns a typed error while the original lossless
/// [`Ikev2NotifyPayload`] remains owned by the caller.
///
/// # Errors
///
/// Returns [`Ikev2PcscfReselectionSupportNotifyError`] when a type-41304
/// Notify has nonzero Protocol ID or SPI Size, nonempty SPI bytes, or nonempty
/// notification data.
///
/// @spec 3GPP TS24.302 8.2.9.4
pub const fn decode_ikev2_pcscf_reselection_support_notify(
    notify: Ikev2NotifyPayload<'_>,
) -> Result<Option<Ikev2PcscfReselectionSupport>, Ikev2PcscfReselectionSupportNotifyError> {
    if notify.notify_message_type != IKEV2_NOTIFY_P_CSCF_RESELECTION_SUPPORT {
        return Ok(None);
    }
    if notify.protocol_id != IKEV2_NOTIFY_PROTOCOL_ID_NONE {
        return Err(Ikev2PcscfReselectionSupportNotifyError::ProtocolIdNonzero);
    }
    if notify.spi_size != 0 {
        return Err(Ikev2PcscfReselectionSupportNotifyError::SpiSizeNonzero);
    }
    if !notify.spi.is_empty() {
        return Err(Ikev2PcscfReselectionSupportNotifyError::SpiNonempty);
    }
    if !notify.notification_data.is_empty() {
        return Err(Ikev2PcscfReselectionSupportNotifyError::NotificationDataNonempty);
    }
    Ok(Some(Ikev2PcscfReselectionSupport { _private: () }))
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
        // RFC 7296 §3.1: the responder MUST clear the Initiator flag in its
        // messages, so the cookie challenge never inherits the request's I bit.
        HeaderFlags::from_bits(false, true, false),
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
