//! Typed 3GPP DEVICE_IDENTITY IKEv2 Notify support.
//!
//! @spec 3GPP TS24.302 7.4.5, 8.2.9.2
//! @req REQ-3GPP-TS24302-DEVICE-IDENTITY-001
//! @conformance boundary-only

use std::{error::Error, fmt};

use opc_types::{Imei15, Imeisv};

use crate::{
    notify::{Ikev2NotifyPayload, IKEV2_NOTIFY_DEVICE_IDENTITY, IKEV2_NOTIFY_PROTOCOL_ID_NONE},
    sa_init::{encode_notify_payload_build, Ikev2NotifyPayloadBuild},
};

const LENGTH_FIELD_LEN: usize = 2;
const IDENTITY_TYPE_LEN: usize = 1;
const REQUEST_COMBINED_LEN: usize = IDENTITY_TYPE_LEN;
const TBCD_IDENTITY_LEN: usize = 8;
const RESPONSE_COMBINED_LEN: usize = IDENTITY_TYPE_LEN + TBCD_IDENTITY_LEN;

/// Device identity type carried by a 3GPP DEVICE_IDENTITY Notify payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ikev2DeviceIdentityType {
    /// International Mobile Equipment Identity.
    Imei,
    /// International Mobile Equipment Identity and Software Version.
    Imeisv,
}

impl Ikev2DeviceIdentityType {
    /// Wire value used by TS 24.302.
    pub const fn value(self) -> u8 {
        match self {
            Self::Imei => 1,
            Self::Imeisv => 2,
        }
    }

    /// Stable redaction-safe label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Imei => "imei",
            Self::Imeisv => "imeisv",
        }
    }

    fn from_value(value: u8) -> Result<Self, Ikev2DeviceIdentityNotifyError> {
        match value {
            1 => Ok(Self::Imei),
            2 => Ok(Self::Imeisv),
            _ => Err(Ikev2DeviceIdentityNotifyError::ReservedIdentityType),
        }
    }
}

/// Validated identity carried by a DEVICE_IDENTITY response.
#[derive(Clone, PartialEq, Eq)]
pub enum Ikev2DeviceIdentity {
    /// Validated IMEI.
    Imei(Imei15),
    /// Validated IMEISV.
    Imeisv(Imeisv),
}

impl Ikev2DeviceIdentity {
    /// Return the associated TS 24.302 identity type.
    pub const fn identity_type(&self) -> Ikev2DeviceIdentityType {
        match self {
            Self::Imei(_) => Ikev2DeviceIdentityType::Imei,
            Self::Imeisv(_) => Ikev2DeviceIdentityType::Imeisv,
        }
    }

    /// Stable redaction-safe label for the identity variant.
    pub const fn as_str(&self) -> &'static str {
        self.identity_type().as_str()
    }

    /// Borrow the IMEI when this is the IMEI variant.
    pub const fn imei(&self) -> Option<&Imei15> {
        match self {
            Self::Imei(value) => Some(value),
            Self::Imeisv(_) => None,
        }
    }

    /// Borrow the IMEISV when this is the IMEISV variant.
    pub const fn imeisv(&self) -> Option<&Imeisv> {
        match self {
            Self::Imei(_) => None,
            Self::Imeisv(value) => Some(value),
        }
    }
}

impl fmt::Debug for Ikev2DeviceIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ikev2DeviceIdentity")
            .field("identity_type", &self.identity_type())
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Typed DEVICE_IDENTITY request or response.
///
/// A request identifies the desired identity type and has no Identity Value.
/// A response carries exactly one validated IMEI or IMEISV.
#[derive(Clone, PartialEq, Eq)]
pub enum Ikev2DeviceIdentityNotify {
    /// Empty-value request for a particular device identity type.
    Request(Ikev2DeviceIdentityType),
    /// Response carrying a validated device identity.
    Response(Ikev2DeviceIdentity),
}

impl Ikev2DeviceIdentityNotify {
    /// Return the identity type requested or returned.
    pub const fn identity_type(&self) -> Ikev2DeviceIdentityType {
        match self {
            Self::Request(identity_type) => *identity_type,
            Self::Response(identity) => identity.identity_type(),
        }
    }

    /// Return true only for an empty-value request.
    pub const fn is_request(&self) -> bool {
        matches!(self, Self::Request(_))
    }

    /// Borrow the response identity, if present.
    pub const fn response(&self) -> Option<&Ikev2DeviceIdentity> {
        match self {
            Self::Request(_) => None,
            Self::Response(identity) => Some(identity),
        }
    }

    /// Stable redaction-safe outcome label.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Request(Ikev2DeviceIdentityType::Imei) => "device_identity_request_imei",
            Self::Request(Ikev2DeviceIdentityType::Imeisv) => "device_identity_request_imeisv",
            Self::Response(Ikev2DeviceIdentity::Imei(_)) => "device_identity_response_imei",
            Self::Response(Ikev2DeviceIdentity::Imeisv(_)) => "device_identity_response_imeisv",
        }
    }
}

impl fmt::Debug for Ikev2DeviceIdentityNotify {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ikev2DeviceIdentityNotify")
            .field("outcome", &self.as_str())
            .field("identity_type", &self.identity_type())
            .finish()
    }
}

/// Decode a generic Notify view as a 3GPP DEVICE_IDENTITY request or response.
///
/// This decoder validates the exact IKE-level shape before examining the
/// notification data. It allocates only after the identity type and fixed
/// eight-octet TBCD length have been validated.
///
/// # Errors
///
/// Returns [`Ikev2DeviceIdentityNotifyError`] for a wrong Notify shape,
/// inconsistent length, reserved type, or malformed device identity.
pub fn decode_ikev2_device_identity_notify(
    notify: Ikev2NotifyPayload<'_>,
) -> Result<Ikev2DeviceIdentityNotify, Ikev2DeviceIdentityNotifyError> {
    if notify.notify_message_type != IKEV2_NOTIFY_DEVICE_IDENTITY {
        return Err(Ikev2DeviceIdentityNotifyError::WrongNotifyType);
    }
    if notify.protocol_id != IKEV2_NOTIFY_PROTOCOL_ID_NONE {
        return Err(Ikev2DeviceIdentityNotifyError::ProtocolIdNotZero);
    }
    if notify.spi_size != 0 || !notify.spi.is_empty() {
        return Err(Ikev2DeviceIdentityNotifyError::SpiNotEmpty);
    }

    let data = notify.notification_data;
    if data.len() < LENGTH_FIELD_LEN + IDENTITY_TYPE_LEN {
        return Err(Ikev2DeviceIdentityNotifyError::NotificationDataTooShort);
    }
    let declared_len = usize::from(u16::from_be_bytes([data[0], data[1]]));
    let actual_len = data.len() - LENGTH_FIELD_LEN;
    if declared_len != actual_len {
        return Err(Ikev2DeviceIdentityNotifyError::DeclaredLengthMismatch);
    }
    let identity_type = Ikev2DeviceIdentityType::from_value(data[2])?;
    let identity_value = &data[LENGTH_FIELD_LEN + IDENTITY_TYPE_LEN..];

    if declared_len == REQUEST_COMBINED_LEN {
        return Ok(Ikev2DeviceIdentityNotify::Request(identity_type));
    }
    if declared_len != RESPONSE_COMBINED_LEN || identity_value.len() != TBCD_IDENTITY_LEN {
        return Err(Ikev2DeviceIdentityNotifyError::IdentityValueLength);
    }

    let identity = match identity_type {
        Ikev2DeviceIdentityType::Imei => {
            Ikev2DeviceIdentity::Imei(decode_imei_tbcd(identity_value)?)
        }
        Ikev2DeviceIdentityType::Imeisv => {
            Ikev2DeviceIdentity::Imeisv(decode_imeisv_tbcd(identity_value)?)
        }
    };
    Ok(Ikev2DeviceIdentityNotify::Response(identity))
}

/// Build a DEVICE_IDENTITY request with an empty Identity Value.
///
/// # Errors
///
/// Returns [`Ikev2DeviceIdentityNotifyBuildError`] if the generic Notify body
/// builder rejects the fixed TS 24.302 shape.
pub fn build_ikev2_device_identity_request(
    identity_type: Ikev2DeviceIdentityType,
) -> Result<Vec<u8>, Ikev2DeviceIdentityNotifyBuildError> {
    let notification_data = vec![0, REQUEST_COMBINED_LEN as u8, identity_type.value()];
    build_notify_body(notification_data)
}

/// Build a DEVICE_IDENTITY response containing a validated TBCD identity.
///
/// # Errors
///
/// Returns [`Ikev2DeviceIdentityNotifyBuildError`] if the generic Notify body
/// builder rejects the fixed TS 24.302 shape.
pub fn build_ikev2_device_identity_response(
    identity: &Ikev2DeviceIdentity,
) -> Result<Vec<u8>, Ikev2DeviceIdentityNotifyBuildError> {
    let mut notification_data = Vec::with_capacity(LENGTH_FIELD_LEN + RESPONSE_COMBINED_LEN);
    notification_data.extend_from_slice(&(RESPONSE_COMBINED_LEN as u16).to_be_bytes());
    notification_data.push(identity.identity_type().value());
    match identity {
        Ikev2DeviceIdentity::Imei(value) => encode_tbcd(value.as_str(), &mut notification_data),
        Ikev2DeviceIdentity::Imeisv(value) => encode_tbcd(value.as_str(), &mut notification_data),
    }
    build_notify_body(notification_data)
}

fn build_notify_body(
    notification_data: Vec<u8>,
) -> Result<Vec<u8>, Ikev2DeviceIdentityNotifyBuildError> {
    encode_notify_payload_build(&Ikev2NotifyPayloadBuild {
        protocol_id: IKEV2_NOTIFY_PROTOCOL_ID_NONE,
        spi: Vec::new(),
        notify_message_type: IKEV2_NOTIFY_DEVICE_IDENTITY,
        notification_data,
    })
    .map_err(|_| Ikev2DeviceIdentityNotifyBuildError::NotifyBody)
}

fn encode_tbcd(digits: &str, output: &mut Vec<u8>) {
    let bytes = digits.as_bytes();
    for pair in bytes.chunks(2) {
        let low = pair[0] - b'0';
        let high = pair.get(1).map_or(0x0f, |digit| *digit - b'0');
        output.push(low | (high << 4));
    }
}

fn decode_imei_tbcd(value: &[u8]) -> Result<Imei15, Ikev2DeviceIdentityNotifyError> {
    if value.len() != TBCD_IDENTITY_LEN {
        return Err(Ikev2DeviceIdentityNotifyError::IdentityValueLength);
    }
    if value[7] >> 4 != 0x0f {
        return Err(Ikev2DeviceIdentityNotifyError::InvalidImeiEndMark);
    }
    let digits = decode_tbcd_digits(value, true)?;
    Imei15::new(digits).map_err(|_| Ikev2DeviceIdentityNotifyError::InvalidImei)
}

fn decode_imeisv_tbcd(value: &[u8]) -> Result<Imeisv, Ikev2DeviceIdentityNotifyError> {
    if value.len() != TBCD_IDENTITY_LEN {
        return Err(Ikev2DeviceIdentityNotifyError::IdentityValueLength);
    }
    let digits = decode_tbcd_digits(value, false)?;
    Imeisv::new(digits).map_err(|_| Ikev2DeviceIdentityNotifyError::InvalidImeisv)
}

fn decode_tbcd_digits(value: &[u8], imei: bool) -> Result<String, Ikev2DeviceIdentityNotifyError> {
    let digit_count = if imei { 15 } else { 16 };
    let mut digits = String::with_capacity(digit_count);
    for (index, octet) in value.iter().copied().enumerate() {
        let low = octet & 0x0f;
        let high = octet >> 4;
        if low > 9 {
            return Err(Ikev2DeviceIdentityNotifyError::InvalidTbcdDigit);
        }
        digits.push(char::from(b'0' + low));
        if imei && index == TBCD_IDENTITY_LEN - 1 {
            continue;
        }
        if high > 9 {
            return Err(Ikev2DeviceIdentityNotifyError::InvalidTbcdDigit);
        }
        digits.push(char::from(b'0' + high));
    }
    Ok(digits)
}

/// Fail-closed DEVICE_IDENTITY decoding errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2DeviceIdentityNotifyError {
    /// Notify Message Type was not 41101.
    WrongNotifyType,
    /// Protocol ID was not zero.
    ProtocolIdNotZero,
    /// SPI Size or SPI value was nonempty.
    SpiNotEmpty,
    /// Notification data omitted the length or identity type.
    NotificationDataTooShort,
    /// Declared combined length did not match the exact remaining bytes.
    DeclaredLengthMismatch,
    /// Identity Type was neither IMEI nor IMEISV.
    ReservedIdentityType,
    /// Identity Value was neither empty nor exactly eight octets.
    IdentityValueLength,
    /// A TBCD identity digit used a non-decimal nibble or internal padding.
    InvalidTbcdDigit,
    /// The final high nibble of an IMEI was not the required `0xF` end mark.
    InvalidImeiEndMark,
    /// The decoded IMEI failed digit or check-digit validation.
    InvalidImei,
    /// The decoded IMEISV failed digit validation.
    InvalidImeisv,
}

impl Ikev2DeviceIdentityNotifyError {
    /// Stable redaction-safe error label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WrongNotifyType => "ike_device_identity_wrong_notify_type",
            Self::ProtocolIdNotZero => "ike_device_identity_protocol_id_not_zero",
            Self::SpiNotEmpty => "ike_device_identity_spi_not_empty",
            Self::NotificationDataTooShort => "ike_device_identity_data_too_short",
            Self::DeclaredLengthMismatch => "ike_device_identity_length_mismatch",
            Self::ReservedIdentityType => "ike_device_identity_reserved_type",
            Self::IdentityValueLength => "ike_device_identity_value_length",
            Self::InvalidTbcdDigit => "ike_device_identity_invalid_tbcd_digit",
            Self::InvalidImeiEndMark => "ike_device_identity_invalid_imei_end_mark",
            Self::InvalidImei => "ike_device_identity_invalid_imei",
            Self::InvalidImeisv => "ike_device_identity_invalid_imeisv",
        }
    }
}

impl fmt::Display for Ikev2DeviceIdentityNotifyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Error for Ikev2DeviceIdentityNotifyError {}

/// DEVICE_IDENTITY Notify body build error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2DeviceIdentityNotifyBuildError {
    /// The generic Notify builder rejected the fixed body shape.
    NotifyBody,
}

impl Ikev2DeviceIdentityNotifyBuildError {
    /// Stable redaction-safe error label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotifyBody => "ike_device_identity_notify_build_failed",
        }
    }
}

impl fmt::Display for Ikev2DeviceIdentityNotifyBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Error for Ikev2DeviceIdentityNotifyBuildError {}
