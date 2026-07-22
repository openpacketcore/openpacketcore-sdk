//! Typed SWm WLAN access-location context.
//!
//! The public values in this module deliberately keep raw AVP construction
//! sealed. Location-bearing values have redacted diagnostics, while explicit
//! accessors remain available to consumers that need to apply product policy.
//!
//! @spec 3GPP TS29273 5.2.3.22, 5.2.3.24, 7.2.2.1.2
//! @spec IETF RFC5580 4.1-4.3, 6
//! @spec IETF RFC4776 3
//! @spec IETF RFC6848 3.2
//! @spec IANA Method Tokens registry (snapshot 2022-09-15)
//! @spec IANA Civic Address Types registry (snapshot 2014-04-11)
//! @spec ETSI ES283034 7.3.3

use std::{collections::HashSet, error::Error, fmt, str};

use bytes::BytesMut;
use opc_protocol::{
    DecodeContext, DecodeError, DecodeErrorCode, EncodeContext, EncodeError, SpecRef,
};
use url::Url;

use crate::avp::dictionary::Redacted;
use crate::dictionary::{AvpCardinality, AvpKey, CommandAvpRule};
use crate::{AvpCode, AvpHeader, RawAvp, VendorId};

use super::{
    append_diameter_eap_extensions, builder_helpers, retain_diameter_eap_extension,
    DiameterEapRetention, SwmAdditionalAvp, SwmDiameterEapExtensionMetadata, VENDOR_ID_3GPP,
};

/// ETSI vendor identifier used by `Logical-Access-ID`.
pub const VENDOR_ID_ETSI: VendorId = VendorId::new(13_019);

/// Access-Network-Info grouped AVP code (3GPP TS 29.273 section 5.2.3.24).
pub const AVP_ACCESS_NETWORK_INFO: AvpCode = AvpCode::new(1526);
/// SSID AVP code (3GPP TS 29.273 section 5.2.3.22).
pub const AVP_SSID: AvpCode = AvpCode::new(1524);
/// BSSID AVP code (3GPP TS 32.299).
pub const AVP_BSSID: AvpCode = AvpCode::new(2716);
/// Operator-Name AVP code (RFC 5580 section 4.1).
pub const AVP_OPERATOR_NAME: AvpCode = AvpCode::new(126);
/// Location-Information AVP code (RFC 5580 section 4.2).
pub const AVP_LOCATION_INFORMATION: AvpCode = AvpCode::new(127);
/// Location-Data AVP code (RFC 5580 section 4.3).
pub const AVP_LOCATION_DATA: AvpCode = AvpCode::new(128);
/// Logical-Access-ID AVP code (ETSI ES 283 034 section 7.3.3).
pub const AVP_LOGICAL_ACCESS_ID: AvpCode = AvpCode::new(302);
/// User-Location-Info-Time AVP code (3GPP TS 29.212 section 5.3.101).
pub const AVP_USER_LOCATION_INFO_TIME: AvpCode = AvpCode::new(2812);

const MAX_SSID_LEN: usize = 32;
const BSSID_TEXT_LEN: usize = 17;
const MAX_OPERATOR_NAME_VALUE_LEN: usize = 253;
const MAX_LOCATION_INFORMATION_VALUE_LEN: usize = 251;
const MIN_LOCATION_INFORMATION_VALUE_LEN: usize = 21;
const LOCATION_INFORMATION_FIXED_LEN: usize = 20;
const MAX_LOCATION_DATA_VALUE_LEN: usize = 253;
const MIN_CIVIC_LOCATION_DATA_VALUE_LEN: usize = 4;
const MAX_CIVIC_ADDRESS_WIRE_LEN: usize = MAX_LOCATION_DATA_VALUE_LEN - 2;
// After the two-octet country code, every RFC 4776 civic element consumes at
// least its type and length octets. This is the exact maximum representable by
// the enclosing RFC 5580 Location-Data bound, not a second policy limit.
const MAX_CIVIC_ELEMENTS: usize = (MAX_CIVIC_ADDRESS_WIRE_LEN - 2) / 2;

pub(super) static ACCESS_NETWORK_INFO_AVP_RULES: [CommandAvpRule; 6] = [
    CommandAvpRule::new(
        AvpKey::vendor(AVP_SSID, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_BSSID, VENDOR_ID_3GPP),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(
        AvpKey::ietf(AVP_LOCATION_INFORMATION),
        AvpCardinality::ZeroOrOne,
    ),
    CommandAvpRule::new(AvpKey::ietf(AVP_LOCATION_DATA), AvpCardinality::ZeroOrOne),
    CommandAvpRule::new(AvpKey::ietf(AVP_OPERATOR_NAME), AvpCardinality::ZeroOrOne),
    CommandAvpRule::new(
        AvpKey::vendor(AVP_LOGICAL_ACCESS_ID, VENDOR_ID_ETSI),
        AvpCardinality::ZeroOrOne,
    ),
];

/// Stable, value-free error categories for SWm location-context construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SwmLocationContextErrorCode {
    /// SSID is empty, too long, or otherwise not representable as UTF-8.
    InvalidSsid,
    /// BSSID is not a valid individual, nonzero 48-bit IEEE address.
    InvalidBssid,
    /// Location method token is not in the supported IANA registry snapshot.
    InvalidLocationMethod,
    /// Civic country code is not two upper-case ASCII letters.
    InvalidCountryCode,
    /// Civic address element exceeds the one-octet RFC 4776 length.
    InvalidCivicElement,
    /// Civic address element uses an unregistered or reserved CAtype.
    InvalidCivicAddressType,
    /// Civic address element value violates its registered CAtype format.
    InvalidCivicAddressValue,
    /// Encoded civic address exceeds the RFC 5580 Diameter payload bound.
    CivicAddressTooLong,
    /// Civic Location-Information and Location-Data are not both present.
    IncompleteCivicLocation,
    /// Civic Location-Information and Location-Data indexes disagree.
    LocationIndexMismatch,
    /// SWm civic location does not describe the access-network entity.
    InvalidLocationEntity,
    /// An originated access-network value omitted every locator without policy evidence.
    MissingAccessLocator,
    /// Receive-only location provenance was used outside an immutable parsed replay.
    InvalidReplayProvenance,
    /// Operator realm is not a valid ASCII registered-domain form.
    InvalidOperatorRealm,
    /// E.212 operator identifier is not a five- or six-digit MCC/MNC value.
    InvalidOperatorE212,
    /// Logical access identifier is empty.
    InvalidLogicalAccessId,
}

impl SwmLocationContextErrorCode {
    /// Return a stable machine-readable code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidSsid => "swm_location_invalid_ssid",
            Self::InvalidBssid => "swm_location_invalid_bssid",
            Self::InvalidLocationMethod => "swm_location_invalid_method",
            Self::InvalidCountryCode => "swm_location_invalid_country_code",
            Self::InvalidCivicElement => "swm_location_invalid_civic_element",
            Self::InvalidCivicAddressType => "swm_location_invalid_civic_address_type",
            Self::InvalidCivicAddressValue => "swm_location_invalid_civic_address_value",
            Self::CivicAddressTooLong => "swm_location_civic_address_too_long",
            Self::IncompleteCivicLocation => "swm_location_incomplete_civic_pair",
            Self::LocationIndexMismatch => "swm_location_index_mismatch",
            Self::InvalidLocationEntity => "swm_location_invalid_entity",
            Self::MissingAccessLocator => "swm_location_missing_access_locator",
            Self::InvalidReplayProvenance => "swm_location_invalid_replay_provenance",
            Self::InvalidOperatorRealm => "swm_location_invalid_operator_realm",
            Self::InvalidOperatorE212 => "swm_location_invalid_operator_e212",
            Self::InvalidLogicalAccessId => "swm_location_invalid_logical_access_id",
        }
    }
}

/// Redaction-safe SWm location-context construction error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwmLocationContextError {
    code: SwmLocationContextErrorCode,
}

impl SwmLocationContextError {
    pub(super) const fn new(code: SwmLocationContextErrorCode) -> Self {
        Self { code }
    }

    /// Return the typed error category.
    #[must_use]
    pub const fn code(self) -> SwmLocationContextErrorCode {
        self.code
    }
}

impl fmt::Display for SwmLocationContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl Error for SwmLocationContextError {}

/// A validated 3GPP WLAN SSID containing 1 through 32 UTF-8 octets.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmWlanSsid(Redacted<String>);

impl SwmWlanSsid {
    /// Validate and retain a WLAN SSID.
    pub fn try_new(value: impl AsRef<str>) -> Result<Self, SwmLocationContextError> {
        let value = value.as_ref();
        if value.is_empty() || value.len() > MAX_SSID_LEN {
            return Err(SwmLocationContextError::new(
                SwmLocationContextErrorCode::InvalidSsid,
            ));
        }
        Ok(Self(Redacted::from(value.to_owned())))
    }

    /// Reveal the SSID to an explicitly authorized consumer.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }
}

impl fmt::Debug for SwmWlanSsid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SwmWlanSsid(<redacted>)")
    }
}

/// A typed IEEE 802.11 48-bit basic service set identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SwmBasicServiceSetIdentifier([u8; 6]);

impl SwmBasicServiceSetIdentifier {
    /// Validate and construct a BSSID from its six network-order octets.
    ///
    /// Group addresses, the all-zero address, and the broadcast address are
    /// not valid BSS identifiers and are rejected before the value can enter
    /// the typed model.
    pub fn try_from_octets(octets: [u8; 6]) -> Result<Self, SwmLocationContextError> {
        let value = Self(octets);
        value.validate()?;
        Ok(value)
    }

    /// Return the six BSSID octets.
    #[must_use]
    pub const fn octets(self) -> [u8; 6] {
        self.0
    }

    fn encode_text(self) -> [u8; BSSID_TEXT_LEN] {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        let mut encoded = [b'-'; BSSID_TEXT_LEN];
        let mut octet_index = 0;
        while octet_index < self.0.len() {
            let output_index = octet_index * 3;
            let octet = self.0[octet_index];
            encoded[output_index] = HEX[usize::from(octet >> 4)];
            encoded[output_index + 1] = HEX[usize::from(octet & 0x0f)];
            octet_index += 1;
        }
        encoded
    }

    fn from_text(value: &[u8]) -> Result<Self, SwmLocationContextError> {
        if value.len() != BSSID_TEXT_LEN {
            return Err(SwmLocationContextError::new(
                SwmLocationContextErrorCode::InvalidBssid,
            ));
        }
        let separator = value[2];
        if !matches!(separator, b'-' | b':') {
            return Err(SwmLocationContextError::new(
                SwmLocationContextErrorCode::InvalidBssid,
            ));
        }
        let mut octets = [0_u8; 6];
        for (index, octet) in octets.iter_mut().enumerate() {
            let input_index = index * 3;
            let Some(high) = hex_nibble(value[input_index]) else {
                return Err(SwmLocationContextError::new(
                    SwmLocationContextErrorCode::InvalidBssid,
                ));
            };
            let Some(low) = hex_nibble(value[input_index + 1]) else {
                return Err(SwmLocationContextError::new(
                    SwmLocationContextErrorCode::InvalidBssid,
                ));
            };
            if index < 5 && value[input_index + 2] != separator {
                return Err(SwmLocationContextError::new(
                    SwmLocationContextErrorCode::InvalidBssid,
                ));
            }
            *octet = (high << 4) | low;
        }
        Self::try_from_octets(octets)
    }

    fn validate(self) -> Result<(), SwmLocationContextError> {
        if self.0[0] & 0x01 != 0
            || self.0.iter().all(|octet| *octet == 0)
            || self.0.iter().all(|octet| *octet == u8::MAX)
        {
            return Err(SwmLocationContextError::new(
                SwmLocationContextErrorCode::InvalidBssid,
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for SwmBasicServiceSetIdentifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SwmBasicServiceSetIdentifier(<redacted>)")
    }
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'A'..=b'F' => Some(value - b'A' + 10),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

/// RFC 5580 entity carried in Location-Information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwmLocationEntity {
    /// Location of the user's client device.
    UserDevice,
    /// Location of the access-network/RADIUS client.
    AccessNetwork,
    /// A subsequently registered entity value.
    Other(u8),
}

impl SwmLocationEntity {
    /// Return the RFC 5580 wire value.
    #[must_use]
    pub const fn value(self) -> u8 {
        match self {
            Self::UserDevice => 0,
            Self::AccessNetwork => 1,
            Self::Other(value) => value,
        }
    }

    const fn from_value(value: u8) -> Self {
        match value {
            0 => Self::UserDevice,
            1 => Self::AccessNetwork,
            other => Self::Other(other),
        }
    }
}

/// An RFC 1305 64-bit NTP timestamp used by RFC 5580.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SwmNtpTimestamp64(u64);

impl SwmNtpTimestamp64 {
    /// Construct a timestamp from its exact 64-bit NTP representation.
    #[must_use]
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    /// Return the exact 64-bit NTP representation.
    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }
}

impl fmt::Debug for SwmNtpTimestamp64 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SwmNtpTimestamp64(<redacted>)")
    }
}

/// A validated IANA PIDF-LO location-method token.
///
/// Both originated and received values must be present in the IANA Method
/// Tokens registry snapshot dated 2022-09-15. Future registry additions are
/// rejected until the SDK registry snapshot is updated.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmLocationMethod(Redacted<String>);

impl SwmLocationMethod {
    /// Validate a token for locally originated location information.
    pub fn try_new(value: impl AsRef<str>) -> Result<Self, SwmLocationContextError> {
        let value = value.as_ref();
        if !valid_location_method_token(value) || !is_registered_location_method(value) {
            return Err(SwmLocationContextError::new(
                SwmLocationContextErrorCode::InvalidLocationMethod,
            ));
        }
        Ok(Self(Redacted::from(value.to_owned())))
    }

    /// Reveal the method token to an explicitly authorized consumer.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }
}

impl fmt::Debug for SwmLocationMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SwmLocationMethod(<redacted>)")
    }
}

fn valid_location_method_token(value: &str) -> bool {
    let max_len = MAX_LOCATION_INFORMATION_VALUE_LEN - LOCATION_INFORMATION_FIXED_LEN;
    !value.is_empty()
        && value.len() <= max_len
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

// IANA Method Tokens registry snapshot dated 2022-09-15. Keep this list
// explicit so originated values cannot silently become unregistered wire data;
// receiving an unregistered token fails closed until this snapshot is updated.
fn is_registered_location_method(value: &str) -> bool {
    matches!(
        value,
        "A-GNSS"
            | "A-GPS"
            | "AOA"
            | "best-guess"
            | "Cell"
            | "DBH"
            | "DBH2"
            | "DBH_HELO"
            | "Derived"
            | "Derived-RevGeo"
            | "DerivedRevGeo-LVF"
            | "Device-Assisted_A-GPS"
            | "Device-Assisted_EOTD"
            | "Device-Based_A-GPS"
            | "Device-Based_EOTD"
            | "DHCP"
            | "E-CID"
            | "ELS-BLE"
            | "ELS-WiFi"
            | "GNSS"
            | "GPS"
            | "Handset_AFLT"
            | "Handset_BLE"
            | "Handset_EFLT"
            | "Handset_WiFi"
            | "Hybrid_A-GPS"
            | "hybridAGPS_AFLT"
            | "hybridCellSector_AFLT"
            | "hybridCellSector_AGPS"
            | "hybridOTDOA_A-GNSS"
            | "hybridOTDOA_AGPS"
            | "hybridRFPatternMatch_AGPS"
            | "hybridTDOA_A-GNSS"
            | "hybridTDOA_AOA"
            | "hybridTDOA_AGPS"
            | "hybridTDOA_AGPS_AOA"
            | "hybridWiFi_AGPS"
            | "IPDL"
            | "LLDP-MED"
            | "Manual"
            | "Manual-FIXED"
            | "Manual-RESD"
            | "MBS"
            | "MPL"
            | "NEAD-BLE"
            | "NEAD-WiFi"
            | "networkRFFingerprinting"
            | "networkTDOA"
            | "networkTOA"
            | "NMR"
            | "OTDOA"
            | "Proximity"
            | "RFID"
            | "RSSI"
            | "RSSI-RTT"
            | "RTT"
            | "TA"
            | "TA-NMR"
            | "Triangulation"
            | "UTDOA"
            | "Wiremap"
            | "802.11"
    )
}

/// Typed civic-profile Location-Information metadata (RFC 5580 section 4.2).
#[derive(Clone, PartialEq, Eq)]
pub struct SwmCivicLocationInformation {
    index: u16,
    entity: SwmLocationEntity,
    sighting_time: SwmNtpTimestamp64,
    time_to_live: SwmNtpTimestamp64,
    method: SwmLocationMethod,
}

impl SwmCivicLocationInformation {
    /// Construct civic location metadata. The profile code is fixed to zero
    /// as required by 3GPP TS 29.273 section 5.2.3.24.
    #[must_use]
    pub const fn new(
        index: u16,
        entity: SwmLocationEntity,
        sighting_time: SwmNtpTimestamp64,
        time_to_live: SwmNtpTimestamp64,
        method: SwmLocationMethod,
    ) -> Self {
        Self {
            index,
            entity,
            sighting_time,
            time_to_live,
            method,
        }
    }

    /// Return the association index.
    #[must_use]
    pub const fn index(&self) -> u16 {
        self.index
    }

    /// Return the location entity.
    #[must_use]
    pub const fn entity(&self) -> SwmLocationEntity {
        self.entity
    }

    /// Return the sighting time.
    #[must_use]
    pub const fn sighting_time(&self) -> SwmNtpTimestamp64 {
        self.sighting_time
    }

    /// Return the RFC 5580 time-to-live timestamp.
    #[must_use]
    pub const fn time_to_live(&self) -> SwmNtpTimestamp64 {
        self.time_to_live
    }

    /// Return the registered location method token.
    #[must_use]
    pub const fn method(&self) -> &SwmLocationMethod {
        &self.method
    }
}

impl fmt::Debug for SwmCivicLocationInformation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SwmCivicLocationInformation(<redacted>)")
    }
}

/// One RFC 4776 civic-address element.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmCivicAddressElement {
    civic_address_type: u8,
    value: Redacted<String>,
}

impl SwmCivicAddressElement {
    /// Validate one registered UTF-8 civic-address component.
    ///
    /// CAtype membership follows the IANA Civic Address Types registry
    /// snapshot dated 2014-04-11. Registry-defined value formats are also
    /// enforced for language (0), location type (29), and script (128).
    /// Extension CAtype 40 accepts any bounded RFC 6848 structural namespace
    /// URI, XML local-name, and nonempty text triple.
    pub fn try_new(
        civic_address_type: u8,
        value: impl AsRef<str>,
    ) -> Result<Self, SwmLocationContextError> {
        let value = value.as_ref();
        if value.len() > usize::from(u8::MAX) {
            return Err(SwmLocationContextError::new(
                SwmLocationContextErrorCode::InvalidCivicElement,
            ));
        }
        if !is_registered_civic_address_type(civic_address_type) {
            return Err(SwmLocationContextError::new(
                SwmLocationContextErrorCode::InvalidCivicAddressType,
            ));
        }
        if !valid_civic_address_value(civic_address_type, value) {
            return Err(SwmLocationContextError::new(
                SwmLocationContextErrorCode::InvalidCivicAddressValue,
            ));
        }
        Ok(Self {
            civic_address_type,
            value: Redacted::from(value.to_owned()),
        })
    }

    /// Return the IANA civic-address type.
    #[must_use]
    pub const fn civic_address_type(&self) -> u8 {
        self.civic_address_type
    }

    /// Reveal the component to an explicitly authorized consumer.
    #[must_use]
    pub fn value(&self) -> &str {
        self.value.as_ref()
    }
}

const fn is_registered_civic_address_type(value: u8) -> bool {
    matches!(value, 0..=6 | 16..=40 | 128)
}

fn valid_civic_address_value(civic_address_type: u8, value: &str) -> bool {
    match civic_address_type {
        0 => valid_language_tag(value),
        29 => is_registered_location_type(value),
        40 => valid_extension_civic_address(value),
        128 => valid_script_tag(value),
        _ => true,
    }
}

fn valid_language_tag(value: &str) -> bool {
    if value == "i-default" {
        return true;
    }
    let mut subtags = value.split('-');
    let Some(primary) = subtags.next() else {
        return false;
    };
    !primary.is_empty()
        && primary.len() <= 8
        && primary.bytes().all(|byte| byte.is_ascii_alphabetic())
        && subtags.all(|subtag| {
            !subtag.is_empty()
                && subtag.len() <= 8
                && subtag.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
}

fn valid_script_tag(value: &str) -> bool {
    let bytes = value.as_bytes();
    matches!(bytes, [first, second, third, fourth]
        if first.is_ascii_uppercase()
            && second.is_ascii_lowercase()
            && third.is_ascii_lowercase()
            && fourth.is_ascii_lowercase())
}

fn valid_extension_civic_address(value: &str) -> bool {
    let mut fields = value.splitn(3, ' ');
    let Some(namespace) = fields.next() else {
        return false;
    };
    let Some(local_name) = fields.next() else {
        return false;
    };
    let Some(extension_value) = fields.next() else {
        return false;
    };
    valid_namespace_uri(namespace)
        && valid_xml_local_name(local_name)
        && valid_xml_text(extension_value)
        && !extension_value.starts_with(' ')
}

fn valid_namespace_uri(value: &str) -> bool {
    if !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return false;
    }
    let bytes = value.as_bytes();
    let mut cursor = 0_usize;
    while cursor < bytes.len() {
        if bytes[cursor] == b'%' {
            let Some(encoded) = bytes.get(cursor + 1..cursor + 3) else {
                return false;
            };
            if !encoded.iter().all(u8::is_ascii_hexdigit) {
                return false;
            }
            cursor += 3;
        } else {
            cursor += 1;
        }
    }
    Url::parse(value).is_ok()
}

fn valid_xml_local_name(value: &str) -> bool {
    let mut characters = value.chars();
    characters.next().is_some_and(is_xml_ncname_start) && characters.all(is_xml_ncname_character)
}

fn is_xml_ncname_start(value: char) -> bool {
    matches!(
        value,
        'A'..='Z'
            | '_'
            | 'a'..='z'
            | '\u{C0}'..='\u{D6}'
            | '\u{D8}'..='\u{F6}'
            | '\u{F8}'..='\u{2FF}'
            | '\u{370}'..='\u{37D}'
            | '\u{37F}'..='\u{1FFF}'
            | '\u{200C}'..='\u{200D}'
            | '\u{2070}'..='\u{218F}'
            | '\u{2C00}'..='\u{2FEF}'
            | '\u{3001}'..='\u{D7FF}'
            | '\u{F900}'..='\u{FDCF}'
            | '\u{FDF0}'..='\u{FFFD}'
            | '\u{10000}'..='\u{EFFFF}'
    )
}

fn is_xml_ncname_character(value: char) -> bool {
    is_xml_ncname_start(value)
        || matches!(
            value,
            '-' | '.' | '0'..='9' | '\u{B7}' | '\u{300}'..='\u{36F}' | '\u{203F}'..='\u{2040}'
        )
}

fn valid_xml_text(value: &str) -> bool {
    !value.is_empty()
        && value.chars().all(|character| {
            matches!(
                character,
                '\u{9}'
                    | '\u{A}'
                    | '\u{D}'
                    | '\u{20}'..='\u{D7FF}'
                    | '\u{E000}'..='\u{FFFD}'
                    | '\u{10000}'..='\u{10FFFF}'
            )
        })
}

// IANA Location Types registry snapshot dated 2024-07-08. CAtype 29 values
// are registry tokens rather than free-form civic text.
fn is_registered_location_type(value: &str) -> bool {
    matches!(
        value,
        "aircraft"
            | "airport"
            | "arena"
            | "automobile"
            | "bank"
            | "bar"
            | "bus"
            | "bicycle"
            | "bus-station"
            | "cafe"
            | "campground"
            | "care-facility"
            | "classroom"
            | "club"
            | "construction"
            | "convention-center"
            | "detached-unit"
            | "fire-station"
            | "government"
            | "hospital"
            | "hotel"
            | "industrial"
            | "landmark-address"
            | "library"
            | "motorcycle"
            | "municipal-garage"
            | "museum"
            | "office"
            | "other"
            | "outdoors"
            | "parking"
            | "phone-box"
            | "place-of-worship"
            | "post-office"
            | "prison"
            | "public"
            | "public-transport"
            | "residence"
            | "restaurant"
            | "school"
            | "shopping-area"
            | "stadium"
            | "store"
            | "street"
            | "theater"
            | "toll-booth"
            | "town-hall"
            | "train"
            | "train-station"
            | "truck"
            | "underway"
            | "unknown"
            | "utilitybox"
            | "warehouse"
            | "waste-transfer-facility"
            | "water"
            | "water-facility"
            | "watercraft"
            | "youth-camp"
    )
}

impl fmt::Debug for SwmCivicAddressElement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmCivicAddressElement")
            .field("civic_address_type", &self.civic_address_type)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// RFC 4776 civic address embedded by RFC 5580.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmCivicAddress {
    country_code: [u8; 2],
    elements: Vec<SwmCivicAddressElement>,
}

impl SwmCivicAddress {
    /// Validate a civic address and its exact RFC 5580 payload bound.
    pub fn try_new(
        country_code: [u8; 2],
        elements: Vec<SwmCivicAddressElement>,
    ) -> Result<Self, SwmLocationContextError> {
        if !country_code.iter().all(u8::is_ascii_uppercase) {
            return Err(SwmLocationContextError::new(
                SwmLocationContextErrorCode::InvalidCountryCode,
            ));
        }
        if elements.len() > MAX_CIVIC_ELEMENTS {
            return Err(SwmLocationContextError::new(
                SwmLocationContextErrorCode::CivicAddressTooLong,
            ));
        }
        let mut encoded_len = country_code.len();
        for element in &elements {
            encoded_len = encoded_len
                .checked_add(2)
                .and_then(|len| len.checked_add(element.value.as_ref().len()))
                .ok_or_else(|| {
                    SwmLocationContextError::new(SwmLocationContextErrorCode::CivicAddressTooLong)
                })?;
        }
        if encoded_len > MAX_CIVIC_ADDRESS_WIRE_LEN {
            return Err(SwmLocationContextError::new(
                SwmLocationContextErrorCode::CivicAddressTooLong,
            ));
        }
        Ok(Self {
            country_code,
            elements,
        })
    }

    /// Return the ISO 3166 alpha-2 country code bytes.
    #[must_use]
    pub const fn country_code(&self) -> [u8; 2] {
        self.country_code
    }

    /// Return the ordered civic-address elements.
    #[must_use]
    pub fn elements(&self) -> &[SwmCivicAddressElement] {
        &self.elements
    }

    fn encoded_len(&self) -> usize {
        self.elements
            .iter()
            .fold(2, |len, element| len + 2 + element.value.as_ref().len())
    }
}

impl fmt::Debug for SwmCivicAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmCivicAddress")
            .field("element_count", &self.elements.len())
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Typed civic-profile Location-Data (RFC 5580 sections 4.3 and 4.3.1).
#[derive(Clone, PartialEq, Eq)]
pub struct SwmCivicLocationData {
    index: u16,
    address: SwmCivicAddress,
}

impl SwmCivicLocationData {
    /// Construct civic Location-Data for one association index.
    #[must_use]
    pub const fn new(index: u16, address: SwmCivicAddress) -> Self {
        Self { index, address }
    }

    /// Return the association index.
    #[must_use]
    pub const fn index(&self) -> u16 {
        self.index
    }

    /// Return the civic address.
    #[must_use]
    pub const fn address(&self) -> &SwmCivicAddress {
        &self.address
    }
}

impl fmt::Debug for SwmCivicLocationData {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SwmCivicLocationData(<redacted>)")
    }
}

/// Operator-name namespaces admitted by 3GPP TS 29.273.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwmAccessNetworkOperatorNamespace {
    /// Namespace `1`: registered realm/domain name.
    Realm,
    /// Namespace `2`: E.212 MCC followed by a two- or three-digit MNC.
    E212,
}

/// A validated operator name in one of the namespaces admitted by SWm.
///
/// The representation is sealed so callers cannot construct an invalid realm
/// or E.212 identifier by directly selecting a public enum variant.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmAccessNetworkOperatorName {
    namespace: SwmAccessNetworkOperatorNamespace,
    value: Redacted<String>,
}

impl SwmAccessNetworkOperatorName {
    /// Validate a namespace-1 realm operator name.
    pub fn try_realm(value: impl Into<String>) -> Result<Self, SwmLocationContextError> {
        let value = value.into();
        if !valid_registered_domain(&value) || value.len() + 1 > MAX_OPERATOR_NAME_VALUE_LEN {
            return Err(SwmLocationContextError::new(
                SwmLocationContextErrorCode::InvalidOperatorRealm,
            ));
        }
        Ok(Self {
            namespace: SwmAccessNetworkOperatorNamespace::Realm,
            value: Redacted::from(value),
        })
    }

    /// Validate a namespace-2 E.212 MCC/MNC operator name.
    pub fn try_e212(value: impl Into<String>) -> Result<Self, SwmLocationContextError> {
        let value = value.into();
        if !matches!(value.len(), 5 | 6) || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(SwmLocationContextError::new(
                SwmLocationContextErrorCode::InvalidOperatorE212,
            ));
        }
        Ok(Self {
            namespace: SwmAccessNetworkOperatorNamespace::E212,
            value: Redacted::from(value),
        })
    }

    /// Return the RFC 5580 ASCII namespace identifier.
    #[must_use]
    pub const fn namespace_id(&self) -> u8 {
        match self.namespace {
            SwmAccessNetworkOperatorNamespace::Realm => b'1',
            SwmAccessNetworkOperatorNamespace::E212 => b'2',
        }
    }

    /// Return the typed operator namespace.
    #[must_use]
    pub const fn namespace(&self) -> SwmAccessNetworkOperatorNamespace {
        self.namespace
    }

    /// Reveal the operator name to an explicitly authorized consumer.
    #[must_use]
    pub fn value(&self) -> &str {
        self.value.as_ref()
    }
}

impl fmt::Debug for SwmAccessNetworkOperatorName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.namespace {
            SwmAccessNetworkOperatorNamespace::Realm => {
                formatter.write_str("SwmAccessNetworkOperatorName::Realm(<redacted>)")
            }
            SwmAccessNetworkOperatorNamespace::E212 => {
                formatter.write_str("SwmAccessNetworkOperatorName::E212(<redacted>)")
            }
        }
    }
}

fn valid_registered_domain(value: &str) -> bool {
    let value = value.strip_suffix('.').unwrap_or(value);
    !value.is_empty()
        && value.is_ascii()
        && value.len() <= 252
        && value.split('.').all(|label| {
            let bytes = label.as_bytes();
            !bytes.is_empty()
                && bytes.len() <= 63
                && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
                && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
                && bytes
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        })
}

/// Opaque ETSI Logical-Access-ID value.
///
/// The wire format does not distinguish an RFC 3046 Circuit-ID from a
/// technology-independent identifier and ETSI ES 283 034 places no common
/// length cap on the latter. The enclosing encode/decode context therefore
/// supplies the allocation bound. A producer originating a Circuit-ID remains
/// responsible for RFC 3046's one-octet sub-option length.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmLogicalAccessId(Redacted<Vec<u8>>);

impl SwmLogicalAccessId {
    /// Validate a nonempty circuit or technology-independent access ID.
    pub fn try_new(value: Vec<u8>) -> Result<Self, SwmLocationContextError> {
        if value.is_empty() {
            return Err(SwmLocationContextError::new(
                SwmLocationContextErrorCode::InvalidLogicalAccessId,
            ));
        }
        Ok(Self(Redacted::from(value)))
    }

    /// Reveal the identifier to an explicitly authorized consumer.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl fmt::Debug for SwmLogicalAccessId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SwmLogicalAccessId(<redacted>)")
    }
}

/// Parser-retained optional children from Access-Network-Info's extension wildcard.
///
/// Raw values are sealed: locally originated values are empty, while a typed
/// parser may populate the collection for bounded replay. Only value-free
/// metadata is exposed.
#[derive(Default, Clone, PartialEq, Eq)]
pub struct SwmAccessNetworkInfoExtensions {
    avps: Vec<SwmAdditionalAvp>,
}

impl SwmAccessNetworkInfoExtensions {
    /// Iterate over ordered, value-free extension metadata.
    pub fn metadata(&self) -> impl ExactSizeIterator<Item = SwmDiameterEapExtensionMetadata> + '_ {
        self.avps
            .iter()
            .map(SwmDiameterEapExtensionMetadata::from_retained)
    }

    /// Return the retained extension count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.avps.len()
    }

    /// Return whether no optional child was retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.avps.is_empty()
    }

    fn retained_avps(&self) -> &[SwmAdditionalAvp] {
        &self.avps
    }
}

impl fmt::Debug for SwmAccessNetworkInfoExtensions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmAccessNetworkInfoExtensions")
            .field("avp_count", &self.avps.len())
            .finish()
    }
}

/// Required initial locator evidence for locally originated Access-Network-Info.
///
/// TS 29.273 requires at least one BSSID, access-point civic address, or
/// Logical-Access-ID unless the TWAN operator has explicitly chosen to omit
/// those locators. Requiring this value at construction prevents an accidental
/// SSID-only answer from silently claiming that policy exception.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SwmAccessNetworkLocatorEvidence {
    /// A validated BSSID identifies the attached access point.
    Bssid(SwmBasicServiceSetIdentifier),
    /// A matching civic Location-Information/Location-Data pair identifies it.
    Civic {
        /// Civic profile metadata.
        information: SwmCivicLocationInformation,
        /// Civic address data with the same association index.
        data: SwmCivicLocationData,
    },
    /// An ETSI Logical-Access-ID identifies the access point.
    LogicalAccessId(SwmLogicalAccessId),
    /// The TWAN operator policy deliberately omitted all three locators.
    OmittedByOperatorPolicy,
}

impl fmt::Debug for SwmAccessNetworkLocatorEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Bssid(_) => "SwmAccessNetworkLocatorEvidence::Bssid(<redacted>)",
            Self::Civic { .. } => "SwmAccessNetworkLocatorEvidence::Civic(<redacted>)",
            Self::LogicalAccessId(_) => {
                "SwmAccessNetworkLocatorEvidence::LogicalAccessId(<redacted>)"
            }
            Self::OmittedByOperatorPolicy => {
                "SwmAccessNetworkLocatorEvidence::OmittedByOperatorPolicy"
            }
        })
    }
}

/// Locator provenance retained by a typed Access-Network-Info value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwmAccessNetworkLocatorStatus {
    /// At least one locator is present.
    Present,
    /// An originator explicitly applied the TS 29.273 operator-policy exception.
    OmittedByOperatorPolicy,
    /// No locator appeared in a received value; no policy provenance is invented.
    AbsentOnReceive,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SwmAccessNetworkValueOrigin {
    Originated,
    Received,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum SwmLocationEncodePurpose {
    Origination,
    ParsedReplay,
}

/// Typed 3GPP Access-Network-Info value.
///
/// Values returned by the parser remain receive-derived after cloning and
/// every public mutator. They can only be emitted through their immutable
/// parsed answer envelope. Construct a fresh complete originated value through
/// [`Self::try_new`] when producing a new answer.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmAccessNetworkInfo {
    ssid: SwmWlanSsid,
    bssid: Option<SwmBasicServiceSetIdentifier>,
    location_information: Option<SwmCivicLocationInformation>,
    location_data: Option<SwmCivicLocationData>,
    operator_name: Option<SwmAccessNetworkOperatorName>,
    logical_access_id: Option<SwmLogicalAccessId>,
    locator_status: SwmAccessNetworkLocatorStatus,
    value_origin: SwmAccessNetworkValueOrigin,
    extensions: SwmAccessNetworkInfoExtensions,
}

impl SwmAccessNetworkInfo {
    /// Start an originated access-network value with its required SSID and
    /// locator or explicit operator-policy omission evidence.
    pub fn try_new(
        ssid: SwmWlanSsid,
        evidence: SwmAccessNetworkLocatorEvidence,
    ) -> Result<Self, SwmLocationContextError> {
        let mut value = Self {
            ssid,
            bssid: None,
            location_information: None,
            location_data: None,
            operator_name: None,
            logical_access_id: None,
            locator_status: SwmAccessNetworkLocatorStatus::Present,
            value_origin: SwmAccessNetworkValueOrigin::Originated,
            extensions: SwmAccessNetworkInfoExtensions::default(),
        };
        match evidence {
            SwmAccessNetworkLocatorEvidence::Bssid(bssid) => value.bssid = Some(bssid),
            SwmAccessNetworkLocatorEvidence::Civic { information, data } => {
                value = value.with_civic_location(information, data)?;
            }
            SwmAccessNetworkLocatorEvidence::LogicalAccessId(logical_access_id) => {
                value.logical_access_id = Some(logical_access_id);
            }
            SwmAccessNetworkLocatorEvidence::OmittedByOperatorPolicy => {
                value.locator_status = SwmAccessNetworkLocatorStatus::OmittedByOperatorPolicy;
            }
        }
        value.validate_for_encode(SwmLocationEncodePurpose::Origination)?;
        Ok(value)
    }

    /// Add a basic service set identifier.
    #[must_use]
    pub fn with_bssid(mut self, bssid: SwmBasicServiceSetIdentifier) -> Self {
        self.bssid = Some(bssid);
        self.locator_status = SwmAccessNetworkLocatorStatus::Present;
        self
    }

    /// Add one associated civic Location-Information/Location-Data pair.
    pub fn with_civic_location(
        mut self,
        information: SwmCivicLocationInformation,
        data: SwmCivicLocationData,
    ) -> Result<Self, SwmLocationContextError> {
        if information.index() != data.index() {
            return Err(SwmLocationContextError::new(
                SwmLocationContextErrorCode::LocationIndexMismatch,
            ));
        }
        if information.entity() != SwmLocationEntity::AccessNetwork {
            return Err(SwmLocationContextError::new(
                SwmLocationContextErrorCode::InvalidLocationEntity,
            ));
        }
        self.location_information = Some(information);
        self.location_data = Some(data);
        self.locator_status = SwmAccessNetworkLocatorStatus::Present;
        Ok(self)
    }

    /// Add the access-network operator name.
    ///
    /// No mutator promotes a parser-created value into an originated value. A
    /// caller adapting parsed facts for a new answer must construct a fresh,
    /// complete value with [`Self::try_new`].
    #[must_use]
    pub fn with_operator_name(mut self, operator_name: SwmAccessNetworkOperatorName) -> Self {
        self.operator_name = Some(operator_name);
        self
    }

    /// Add an ETSI Logical-Access-ID.
    #[must_use]
    pub fn with_logical_access_id(mut self, logical_access_id: SwmLogicalAccessId) -> Self {
        self.logical_access_id = Some(logical_access_id);
        self.locator_status = SwmAccessNetworkLocatorStatus::Present;
        self
    }

    /// Return the WLAN SSID.
    #[must_use]
    pub const fn ssid(&self) -> &SwmWlanSsid {
        &self.ssid
    }

    /// Return the optional BSSID.
    #[must_use]
    pub const fn bssid(&self) -> Option<SwmBasicServiceSetIdentifier> {
        self.bssid
    }

    /// Return optional civic location metadata.
    #[must_use]
    pub const fn location_information(&self) -> Option<&SwmCivicLocationInformation> {
        self.location_information.as_ref()
    }

    /// Return optional civic location data.
    #[must_use]
    pub const fn location_data(&self) -> Option<&SwmCivicLocationData> {
        self.location_data.as_ref()
    }

    /// Return the optional access-network operator name.
    #[must_use]
    pub const fn operator_name(&self) -> Option<&SwmAccessNetworkOperatorName> {
        self.operator_name.as_ref()
    }

    /// Return the optional Logical-Access-ID.
    #[must_use]
    pub const fn logical_access_id(&self) -> Option<&SwmLogicalAccessId> {
        self.logical_access_id.as_ref()
    }

    /// Return sealed optional-child retention metadata.
    #[must_use]
    pub const fn extensions(&self) -> &SwmAccessNetworkInfoExtensions {
        &self.extensions
    }

    /// Return the locator provenance carried by this value.
    #[must_use]
    pub const fn locator_status(&self) -> SwmAccessNetworkLocatorStatus {
        self.locator_status
    }

    pub(super) fn validate_for_encode(
        &self,
        purpose: SwmLocationEncodePurpose,
    ) -> Result<(), SwmLocationContextError> {
        self.validate_common()?;
        let locator_present = self.locator_present();
        match (
            purpose,
            self.value_origin,
            self.extensions.is_empty(),
            locator_present,
            self.locator_status,
        ) {
            (
                SwmLocationEncodePurpose::Origination,
                SwmAccessNetworkValueOrigin::Originated,
                true,
                true,
                SwmAccessNetworkLocatorStatus::Present,
            )
            | (
                SwmLocationEncodePurpose::Origination,
                SwmAccessNetworkValueOrigin::Originated,
                true,
                false,
                SwmAccessNetworkLocatorStatus::OmittedByOperatorPolicy,
            )
            | (
                SwmLocationEncodePurpose::ParsedReplay,
                SwmAccessNetworkValueOrigin::Received,
                _,
                true,
                SwmAccessNetworkLocatorStatus::Present,
            )
            | (
                SwmLocationEncodePurpose::ParsedReplay,
                SwmAccessNetworkValueOrigin::Received,
                _,
                false,
                SwmAccessNetworkLocatorStatus::AbsentOnReceive,
            ) => Ok(()),
            (
                SwmLocationEncodePurpose::Origination,
                SwmAccessNetworkValueOrigin::Originated,
                true,
                _,
                _,
            ) => Err(SwmLocationContextError::new(
                SwmLocationContextErrorCode::MissingAccessLocator,
            )),
            _ => Err(SwmLocationContextError::new(
                SwmLocationContextErrorCode::InvalidReplayProvenance,
            )),
        }
    }

    pub(super) fn validate_received(&self) -> Result<(), SwmLocationContextError> {
        self.validate_for_encode(SwmLocationEncodePurpose::ParsedReplay)
    }

    fn validate_common(&self) -> Result<(), SwmLocationContextError> {
        if let Some(bssid) = self.bssid {
            bssid.validate()?;
        }
        if self.location_information.is_some() != self.location_data.is_some() {
            return Err(SwmLocationContextError::new(
                SwmLocationContextErrorCode::IncompleteCivicLocation,
            ));
        }
        if self
            .location_information
            .as_ref()
            .zip(self.location_data.as_ref())
            .is_some_and(|(information, data)| information.index() != data.index())
        {
            return Err(SwmLocationContextError::new(
                SwmLocationContextErrorCode::LocationIndexMismatch,
            ));
        }
        if self
            .location_information
            .as_ref()
            .is_some_and(|information| information.entity() != SwmLocationEntity::AccessNetwork)
        {
            return Err(SwmLocationContextError::new(
                SwmLocationContextErrorCode::InvalidLocationEntity,
            ));
        }
        Ok(())
    }

    fn locator_present(&self) -> bool {
        self.bssid.is_some()
            || self.location_information.is_some()
            || self.logical_access_id.is_some()
    }
}

impl fmt::Debug for SwmAccessNetworkInfo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmAccessNetworkInfo")
            .field("ssid", &"<redacted>")
            .field("bssid_present", &self.bssid.is_some())
            .field(
                "location_information_present",
                &self.location_information.is_some(),
            )
            .field("location_data_present", &self.location_data.is_some())
            .field("operator_name_present", &self.operator_name.is_some())
            .field(
                "logical_access_id_present",
                &self.logical_access_id.is_some(),
            )
            .field("locator_status", &self.locator_status)
            .field("extensions", &self.extensions)
            .finish()
    }
}

/// Typed Diameter `Time` for the last-known WLAN location timestamp.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SwmUserLocationInfoTime(u32);

impl SwmUserLocationInfoTime {
    /// Construct from the exact four-octet NTP-seconds representation used by
    /// RFC 6733 `Time`.
    #[must_use]
    pub const fn from_ntp_seconds(value: u32) -> Self {
        Self(value)
    }

    /// Return the exact NTP-seconds wire value.
    #[must_use]
    pub const fn ntp_seconds(self) -> u32 {
        self.0
    }
}

impl fmt::Debug for SwmUserLocationInfoTime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SwmUserLocationInfoTime(<redacted>)")
    }
}

/// Explicit evidence explaining why WLAN location has no accompanying time.
///
/// TS 29.273 recommends the timestamp when WLAN Location Information is
/// present, but permits it to be unavailable. The distinction prevents a
/// locally originated answer from dropping the timestamp accidentally while
/// preserving honest provenance for a received answer that omitted it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SwmUserLocationInfoTimeOmission {
    provenance: SwmUserLocationInfoTimeOmissionProvenance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum SwmUserLocationInfoTimeOmissionProvenance {
    Unavailable,
    ReceivedWithoutTimestamp,
}

impl SwmUserLocationInfoTimeOmission {
    /// Record that an originating implementation has no timestamp available.
    #[must_use]
    pub const fn unavailable() -> Self {
        Self {
            provenance: SwmUserLocationInfoTimeOmissionProvenance::Unavailable,
        }
    }

    pub(super) const fn received_without_timestamp() -> Self {
        Self {
            provenance: SwmUserLocationInfoTimeOmissionProvenance::ReceivedWithoutTimestamp,
        }
    }

    /// Return whether this evidence was derived from a received omission.
    #[must_use]
    pub const fn was_absent_on_receive(self) -> bool {
        matches!(
            self.provenance,
            SwmUserLocationInfoTimeOmissionProvenance::ReceivedWithoutTimestamp
        )
    }
}

pub(super) fn append_access_network_info_avp(
    dst: &mut BytesMut,
    access: &SwmAccessNetworkInfo,
    purpose: SwmLocationEncodePurpose,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    access
        .validate_for_encode(purpose)
        .map_err(location_encode_error)?;
    let mut value = BytesMut::new();
    builder_helpers::append_avp(
        &mut value,
        AvpHeader::vendor(AVP_SSID, VENDOR_ID_3GPP, false),
        access.ssid.as_str().as_bytes(),
        ctx,
    )?;
    if let Some(bssid) = access.bssid {
        builder_helpers::append_avp(
            &mut value,
            AvpHeader::vendor(AVP_BSSID, VENDOR_ID_3GPP, true),
            &bssid.encode_text(),
            ctx,
        )?;
    }
    if let Some(information) = access.location_information.as_ref() {
        let encoded = encode_location_information(information);
        builder_helpers::append_avp(
            &mut value,
            AvpHeader::ietf(AVP_LOCATION_INFORMATION, false),
            &encoded,
            ctx,
        )?;
    }
    if let Some(data) = access.location_data.as_ref() {
        let encoded = encode_location_data(data)?;
        builder_helpers::append_avp(
            &mut value,
            AvpHeader::ietf(AVP_LOCATION_DATA, false),
            &encoded,
            ctx,
        )?;
    }
    if let Some(operator) = access.operator_name.as_ref() {
        let mut encoded = Vec::with_capacity(operator.value().len() + 1);
        encoded.push(operator.namespace_id());
        encoded.extend_from_slice(operator.value().as_bytes());
        builder_helpers::append_avp(
            &mut value,
            AvpHeader::ietf(AVP_OPERATOR_NAME, false),
            &encoded,
            ctx,
        )?;
    }
    if let Some(logical_access_id) = access.logical_access_id.as_ref() {
        builder_helpers::append_avp(
            &mut value,
            AvpHeader::vendor(AVP_LOGICAL_ACCESS_ID, VENDOR_ID_ETSI, false),
            logical_access_id.as_bytes(),
            ctx,
        )?;
    }
    append_diameter_eap_extensions(
        &mut value,
        access.extensions.retained_avps(),
        ctx,
        "5.2.3.24",
    )?;
    builder_helpers::append_avp(
        dst,
        AvpHeader::vendor(AVP_ACCESS_NETWORK_INFO, VENDOR_ID_3GPP, false),
        &value,
        ctx,
    )
}

pub(super) fn append_user_location_info_time_avp(
    dst: &mut BytesMut,
    timestamp: SwmUserLocationInfoTime,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    builder_helpers::append_vendor_u32_avp(
        dst,
        AVP_USER_LOCATION_INFO_TIME,
        VENDOR_ID_3GPP,
        timestamp.ntp_seconds(),
        false,
        ctx,
    )
}

pub(super) fn parse_access_network_info(
    avp: &RawAvp<'_>,
    ctx: DecodeContext,
    offset: usize,
    value_offset: usize,
    depth: usize,
    retention: &mut DiameterEapRetention,
) -> Result<SwmAccessNetworkInfo, DecodeError> {
    validate_3gpp_m_agnostic_p_clear(&avp.header, offset, "5.2.3.24")?;
    let mut ssid = None;
    let mut bssid = None;
    let mut location_information = None;
    let mut location_data = None;
    let mut operator_name = None;
    let mut logical_access_id = None;
    let mut extensions = Vec::new();
    let mut extension_keys = HashSet::new();
    builder_helpers::for_each_avp(
        avp.value,
        ctx,
        value_offset,
        depth,
        |child_offset, child| {
            let child_value_offset =
                builder_helpers::offset_add(child_offset, child.header.header_len(), "5.2.3.24")?;
            if child
                .header
                .vendor_id
                .is_some_and(|vendor_id| vendor_id.get() == 0)
            {
                return Err(DecodeError::new(
                    DecodeErrorCode::Structural {
                        reason: "Access-Network-Info Vendor-Id field must not contain zero",
                    },
                    child_offset,
                )
                .with_spec_ref(SpecRef::new("ietf", "RFC6733", "4.1.1")));
            }
            let key = child.header.key();
            if key == AvpKey::vendor(AVP_SSID, VENDOR_ID_3GPP) {
                validate_3gpp_m_agnostic_p_clear(&child.header, child_offset, "5.2.3.22")?;
                if !(1..=MAX_SSID_LEN).contains(&child.value.len()) {
                    return Err(location_decode_error(
                        SwmLocationContextError::new(SwmLocationContextErrorCode::InvalidSsid),
                        child_value_offset,
                    ));
                }
                let value = str::from_utf8(child.value).map_err(|_| {
                    location_decode_error(
                        SwmLocationContextError::new(SwmLocationContextErrorCode::InvalidSsid),
                        child_value_offset,
                    )
                })?;
                let value = SwmWlanSsid::try_new(value)
                    .map_err(|error| location_decode_error(error, child_value_offset))?;
                builder_helpers::set_once(&mut ssid, value, child_offset, "5.2.3.24")?;
            } else if key == AvpKey::vendor(AVP_BSSID, VENDOR_ID_3GPP) {
                validate_bssid_flags(&child.header, child_offset)?;
                if child.value.len() != BSSID_TEXT_LEN || str::from_utf8(child.value).is_err() {
                    return Err(location_decode_error(
                        SwmLocationContextError::new(SwmLocationContextErrorCode::InvalidBssid),
                        child_value_offset,
                    ));
                }
                let value = SwmBasicServiceSetIdentifier::from_text(child.value)
                    .map_err(|error| location_decode_error(error, child_value_offset))?;
                builder_helpers::set_once(&mut bssid, value, child_offset, "5.2.3.24")?;
            } else if key == AvpKey::ietf(AVP_LOCATION_INFORMATION) {
                validate_ietf_p_permitted_m_agnostic(&child.header, child_offset, "4.2")?;
                let value = parse_location_information(child.value, child_value_offset)?;
                builder_helpers::set_once(
                    &mut location_information,
                    value,
                    child_offset,
                    "5.2.3.24",
                )?;
            } else if key == AvpKey::ietf(AVP_LOCATION_DATA) {
                validate_ietf_p_permitted_m_agnostic(&child.header, child_offset, "4.3")?;
                let value = parse_location_data(child.value, child_value_offset)?;
                builder_helpers::set_once(&mut location_data, value, child_offset, "5.2.3.24")?;
            } else if key == AvpKey::ietf(AVP_OPERATOR_NAME) {
                validate_ietf_p_permitted_m_agnostic(&child.header, child_offset, "4.1")?;
                let value = parse_operator_name(child.value, child_value_offset)?;
                builder_helpers::set_once(&mut operator_name, value, child_offset, "5.2.3.24")?;
            } else if key == AvpKey::vendor(AVP_LOGICAL_ACCESS_ID, VENDOR_ID_ETSI) {
                validate_etsi_p_permitted_m_agnostic(&child.header, child_offset, "7.3.3")?;
                let value = SwmLogicalAccessId::try_new(child.value.to_vec())
                    .map_err(|error| location_decode_error(error, child_value_offset))?;
                builder_helpers::set_once(&mut logical_access_id, value, child_offset, "5.2.3.24")?;
            } else {
                retain_diameter_eap_extension(
                    ctx,
                    &child,
                    child_offset,
                    "5.2.3.24",
                    &mut extension_keys,
                    retention,
                    &mut extensions,
                )?;
            }
            Ok(())
        },
    )?;
    let ssid = ssid.ok_or_else(|| {
        location_structural_error(
            "Access-Network-Info requires an SSID child",
            value_offset,
            "5.2.3.24",
        )
    })?;
    let locator_status =
        if bssid.is_some() || location_information.is_some() || logical_access_id.is_some() {
            SwmAccessNetworkLocatorStatus::Present
        } else {
            SwmAccessNetworkLocatorStatus::AbsentOnReceive
        };
    let parsed = SwmAccessNetworkInfo {
        ssid,
        bssid,
        location_information,
        location_data,
        operator_name,
        logical_access_id,
        locator_status,
        value_origin: SwmAccessNetworkValueOrigin::Received,
        extensions: SwmAccessNetworkInfoExtensions { avps: extensions },
    };
    parsed
        .validate_received()
        .map_err(|error| location_decode_error(error, value_offset))?;
    Ok(parsed)
}

pub(super) fn parse_user_location_info_time(
    avp: &RawAvp<'_>,
    offset: usize,
    value_offset: usize,
) -> Result<SwmUserLocationInfoTime, DecodeError> {
    validate_user_location_info_time_flags(&avp.header, offset)?;
    let value = match avp.value {
        [a, b, c, d] => u32::from_be_bytes([*a, *b, *c, *d]),
        _ => {
            return Err(DecodeError::new(
                DecodeErrorCode::InvalidLength {
                    reason: "User-Location-Info-Time must contain four octets",
                },
                value_offset,
            )
            .with_spec_ref(SpecRef::new("3gpp", "TS29212", "5.3.101")));
        }
    };
    Ok(SwmUserLocationInfoTime::from_ntp_seconds(value))
}

fn encode_location_information(information: &SwmCivicLocationInformation) -> Vec<u8> {
    let mut encoded =
        Vec::with_capacity(LOCATION_INFORMATION_FIXED_LEN + information.method.as_str().len());
    encoded.extend_from_slice(&information.index.to_be_bytes());
    encoded.push(0);
    encoded.push(information.entity.value());
    encoded.extend_from_slice(&information.sighting_time.bits().to_be_bytes());
    encoded.extend_from_slice(&information.time_to_live.bits().to_be_bytes());
    encoded.extend_from_slice(information.method.as_str().as_bytes());
    encoded
}

fn encode_location_data(data: &SwmCivicLocationData) -> Result<Vec<u8>, EncodeError> {
    let mut encoded = Vec::with_capacity(2 + data.address.encoded_len());
    encoded.extend_from_slice(&data.index.to_be_bytes());
    encoded.extend_from_slice(&data.address.country_code);
    for element in &data.address.elements {
        let length = u8::try_from(element.value.as_ref().len()).map_err(|_| {
            location_encode_error(SwmLocationContextError::new(
                SwmLocationContextErrorCode::InvalidCivicElement,
            ))
        })?;
        encoded.push(element.civic_address_type);
        encoded.push(length);
        encoded.extend_from_slice(element.value.as_ref().as_bytes());
    }
    Ok(encoded)
}

fn parse_location_information(
    value: &[u8],
    offset: usize,
) -> Result<SwmCivicLocationInformation, DecodeError> {
    if !(MIN_LOCATION_INFORMATION_VALUE_LEN..=MAX_LOCATION_INFORMATION_VALUE_LEN)
        .contains(&value.len())
    {
        return Err(rfc5580_structural_error(
            "Location-Information violates RFC 5580 payload bounds",
            offset,
            "4.2",
        ));
    }
    if value[2] != 0 {
        let code_offset = builder_helpers::offset_add(offset, 2, "5.2.3.24")?;
        return Err(location_structural_error(
            "SWm Location-Information must select the civic profile code",
            code_offset,
            "5.2.3.24",
        ));
    }
    let method_offset = builder_helpers::offset_add(offset, LOCATION_INFORMATION_FIXED_LEN, "4.2")?;
    let method = str::from_utf8(&value[LOCATION_INFORMATION_FIXED_LEN..]).map_err(|_| {
        rfc5580_structural_error(
            "Location-Information method is not valid ASCII",
            method_offset,
            "4.2",
        )
    })?;
    let method = SwmLocationMethod::try_new(method)
        .map_err(|error| location_decode_error(error, method_offset))?;
    Ok(SwmCivicLocationInformation {
        index: u16::from_be_bytes([value[0], value[1]]),
        entity: SwmLocationEntity::from_value(value[3]),
        sighting_time: SwmNtpTimestamp64::from_bits(u64::from_be_bytes([
            value[4], value[5], value[6], value[7], value[8], value[9], value[10], value[11],
        ])),
        time_to_live: SwmNtpTimestamp64::from_bits(u64::from_be_bytes([
            value[12], value[13], value[14], value[15], value[16], value[17], value[18], value[19],
        ])),
        method,
    })
}

fn parse_location_data(value: &[u8], offset: usize) -> Result<SwmCivicLocationData, DecodeError> {
    if !(MIN_CIVIC_LOCATION_DATA_VALUE_LEN..=MAX_LOCATION_DATA_VALUE_LEN).contains(&value.len()) {
        return Err(rfc5580_structural_error(
            "civic Location-Data violates RFC 5580 payload bounds",
            offset,
            "4.3.1",
        ));
    }
    let index = u16::from_be_bytes([value[0], value[1]]);
    let country_code = [value[2], value[3]];
    let mut elements = Vec::new();
    let mut cursor = 4_usize;
    while cursor < value.len() {
        let cursor_offset = builder_helpers::offset_add(offset, cursor, "4.3.1")?;
        if elements.len() >= MAX_CIVIC_ELEMENTS || value.len() - cursor < 2 {
            return Err(rfc4776_structural_error(
                "civic Location-Data contains a malformed element header",
                cursor_offset,
                "3.3",
            ));
        }
        let civic_address_type = value[cursor];
        let element_len = usize::from(value[cursor + 1]);
        cursor += 2;
        let element_offset = builder_helpers::offset_add(offset, cursor, "3.3")?;
        let element_end = cursor.checked_add(element_len).ok_or_else(|| {
            DecodeError::new(DecodeErrorCode::LengthOverflow, element_offset)
                .with_spec_ref(SpecRef::new("ietf", "RFC4776", "3.3"))
        })?;
        let element_value = value.get(cursor..element_end).ok_or_else(|| {
            rfc4776_structural_error(
                "civic Location-Data element length exceeds the AVP payload",
                element_offset,
                "3.3",
            )
        })?;
        let element_value = str::from_utf8(element_value).map_err(|_| {
            rfc4776_structural_error(
                "civic Location-Data element is not valid UTF-8",
                element_offset,
                "3.4",
            )
        })?;
        elements.push(
            SwmCivicAddressElement::try_new(civic_address_type, element_value)
                .map_err(|error| location_decode_error(error, element_offset))?,
        );
        cursor = element_end;
    }
    let country_offset = builder_helpers::offset_add(offset, 2, "4.3.1")?;
    let address = SwmCivicAddress::try_new(country_code, elements)
        .map_err(|error| location_decode_error(error, country_offset))?;
    Ok(SwmCivicLocationData { index, address })
}

fn parse_operator_name(
    value: &[u8],
    offset: usize,
) -> Result<SwmAccessNetworkOperatorName, DecodeError> {
    if !(2..=MAX_OPERATOR_NAME_VALUE_LEN).contains(&value.len()) {
        return Err(rfc5580_structural_error(
            "Operator-Name violates RFC 5580 payload bounds",
            offset,
            "4.1",
        ));
    }
    let name_offset = builder_helpers::offset_add(offset, 1, "4.1")?;
    let name = str::from_utf8(&value[1..])
        .map_err(|_| {
            rfc5580_structural_error("Operator-Name is not valid ASCII", name_offset, "4.1")
        })?
        .to_owned();
    let parsed = match value[0] {
        b'1' => SwmAccessNetworkOperatorName::try_realm(name),
        b'2' => SwmAccessNetworkOperatorName::try_e212(name),
        _ => {
            return Err(location_structural_error(
                "SWm Operator-Name namespace must be Realm or E212",
                offset,
                "5.2.3.24",
            ));
        }
    };
    parsed.map_err(|error| location_decode_error(error, name_offset))
}

fn validate_3gpp_m_agnostic_p_clear(
    header: &AvpHeader,
    offset: usize,
    section: &'static str,
) -> Result<(), DecodeError> {
    if header.vendor_id != Some(VENDOR_ID_3GPP) || header.flags.is_protected() {
        let flags_offset = builder_helpers::offset_add(offset, 4, section)?;
        return Err(location_structural_error(
            "understood SWm 3GPP location AVP must set V and clear P",
            flags_offset,
            section,
        ));
    }
    Ok(())
}

fn validate_bssid_flags(header: &AvpHeader, offset: usize) -> Result<(), DecodeError> {
    if header.vendor_id != Some(VENDOR_ID_3GPP) {
        let flags_offset = builder_helpers::offset_add(offset, 4, "7.2.30A")?;
        return Err(DecodeError::new(
            DecodeErrorCode::Structural {
                reason: "BSSID AVP must use the 3GPP vendor identity",
            },
            flags_offset,
        )
        .with_spec_ref(SpecRef::new("3gpp", "TS32299", "7.2.30A")));
    }
    Ok(())
}

fn validate_user_location_info_time_flags(
    header: &AvpHeader,
    offset: usize,
) -> Result<(), DecodeError> {
    if header.vendor_id != Some(VENDOR_ID_3GPP) {
        let flags_offset = builder_helpers::offset_add(offset, 4, "5.3.101")?;
        return Err(DecodeError::new(
            DecodeErrorCode::Structural {
                reason: "User-Location-Info-Time must use the 3GPP vendor identity",
            },
            flags_offset,
        )
        .with_spec_ref(SpecRef::new("3gpp", "TS29212", "5.3.101")));
    }
    Ok(())
}

fn validate_ietf_p_permitted_m_agnostic(
    header: &AvpHeader,
    offset: usize,
    section: &'static str,
) -> Result<(), DecodeError> {
    if header.vendor_id.is_some() {
        let flags_offset = builder_helpers::offset_add(offset, 4, section)?;
        return Err(rfc5580_structural_error(
            "RFC 5580 location AVP must clear V",
            flags_offset,
            section,
        ));
    }
    Ok(())
}

fn validate_etsi_p_permitted_m_agnostic(
    header: &AvpHeader,
    offset: usize,
    section: &'static str,
) -> Result<(), DecodeError> {
    if header.vendor_id != Some(VENDOR_ID_ETSI) {
        let flags_offset = builder_helpers::offset_add(offset, 4, section)?;
        return Err(etsi_structural_error(
            "Logical-Access-ID must use the ETSI vendor identity",
            flags_offset,
            section,
        ));
    }
    Ok(())
}

pub(super) fn location_encode_error(error: SwmLocationContextError) -> EncodeError {
    EncodeError::new(opc_protocol::EncodeErrorCode::Structural {
        reason: location_context_error_reason(error.code()),
    })
    .with_spec_ref(location_context_error_spec(error.code()))
}

pub(super) fn location_decode_error(error: SwmLocationContextError, offset: usize) -> DecodeError {
    DecodeError::new(
        DecodeErrorCode::Structural {
            reason: location_context_error_reason(error.code()),
        },
        offset,
    )
    .with_spec_ref(location_context_error_spec(error.code()))
}

const fn location_context_error_reason(code: SwmLocationContextErrorCode) -> &'static str {
    match code {
        SwmLocationContextErrorCode::InvalidSsid => {
            "SWm Access-Network-Info contains an invalid SSID"
        }
        SwmLocationContextErrorCode::InvalidBssid => {
            "SWm Access-Network-Info contains an invalid BSSID"
        }
        SwmLocationContextErrorCode::InvalidLocationMethod => {
            "SWm Location-Information contains an invalid method token"
        }
        SwmLocationContextErrorCode::InvalidCountryCode => {
            "SWm civic Location-Data contains an invalid country code"
        }
        SwmLocationContextErrorCode::InvalidCivicElement => {
            "SWm civic Location-Data contains an invalid element"
        }
        SwmLocationContextErrorCode::InvalidCivicAddressType => {
            "SWm civic Location-Data contains an unregistered CAtype"
        }
        SwmLocationContextErrorCode::InvalidCivicAddressValue => {
            "SWm civic Location-Data contains a value invalid for its CAtype"
        }
        SwmLocationContextErrorCode::CivicAddressTooLong => {
            "SWm civic Location-Data exceeds its bounded wire length"
        }
        SwmLocationContextErrorCode::IncompleteCivicLocation => {
            "SWm civic location requires matching Information and Data AVPs"
        }
        SwmLocationContextErrorCode::LocationIndexMismatch => {
            "SWm civic location association indexes do not match"
        }
        SwmLocationContextErrorCode::InvalidLocationEntity => {
            "SWm civic location must identify the access-network entity"
        }
        SwmLocationContextErrorCode::MissingAccessLocator => {
            "originated SWm Access-Network-Info requires a locator or omission evidence"
        }
        SwmLocationContextErrorCode::InvalidReplayProvenance => {
            "received SWm location state may only be emitted by immutable parsed replay"
        }
        SwmLocationContextErrorCode::InvalidOperatorRealm => {
            "SWm Operator-Name contains an invalid realm"
        }
        SwmLocationContextErrorCode::InvalidOperatorE212 => {
            "SWm Operator-Name contains an invalid E212 value"
        }
        SwmLocationContextErrorCode::InvalidLogicalAccessId => {
            "SWm Logical-Access-ID must not be empty"
        }
    }
}

fn location_context_error_spec(code: SwmLocationContextErrorCode) -> SpecRef {
    match code {
        SwmLocationContextErrorCode::InvalidSsid => SpecRef::new("3gpp", "TS29273", "5.2.3.22"),
        SwmLocationContextErrorCode::InvalidBssid => SpecRef::new("3gpp", "TS32299", "7.2.30A"),
        SwmLocationContextErrorCode::InvalidLocationMethod => {
            SpecRef::new("ietf", "RFC5580", "4.2")
        }
        SwmLocationContextErrorCode::InvalidCountryCode
        | SwmLocationContextErrorCode::InvalidCivicElement
        | SwmLocationContextErrorCode::InvalidCivicAddressType
        | SwmLocationContextErrorCode::InvalidCivicAddressValue => {
            SpecRef::new("ietf", "RFC4776", "3")
        }
        SwmLocationContextErrorCode::CivicAddressTooLong => SpecRef::new("ietf", "RFC5580", "4.3"),
        SwmLocationContextErrorCode::IncompleteCivicLocation
        | SwmLocationContextErrorCode::LocationIndexMismatch
        | SwmLocationContextErrorCode::InvalidLocationEntity
        | SwmLocationContextErrorCode::MissingAccessLocator
        | SwmLocationContextErrorCode::InvalidReplayProvenance => {
            SpecRef::new("3gpp", "TS29273", "5.2.3.24")
        }
        SwmLocationContextErrorCode::InvalidOperatorRealm
        | SwmLocationContextErrorCode::InvalidOperatorE212 => {
            SpecRef::new("ietf", "RFC5580", "4.1")
        }
        SwmLocationContextErrorCode::InvalidLogicalAccessId => {
            SpecRef::new("etsi", "ES283034", "7.3.3")
        }
    }
}

fn location_structural_error(
    reason: &'static str,
    offset: usize,
    section: &'static str,
) -> DecodeError {
    DecodeError::new(DecodeErrorCode::Structural { reason }, offset)
        .with_spec_ref(SpecRef::new("3gpp", "TS29273", section))
}

fn rfc5580_structural_error(
    reason: &'static str,
    offset: usize,
    section: &'static str,
) -> DecodeError {
    DecodeError::new(DecodeErrorCode::Structural { reason }, offset)
        .with_spec_ref(SpecRef::new("ietf", "RFC5580", section))
}

fn rfc4776_structural_error(
    reason: &'static str,
    offset: usize,
    section: &'static str,
) -> DecodeError {
    DecodeError::new(DecodeErrorCode::Structural { reason }, offset)
        .with_spec_ref(SpecRef::new("ietf", "RFC4776", section))
}

fn etsi_structural_error(
    reason: &'static str,
    offset: usize,
    section: &'static str,
) -> DecodeError {
    DecodeError::new(DecodeErrorCode::Structural { reason }, offset)
        .with_spec_ref(SpecRef::new("etsi", "ES283034", section))
}
