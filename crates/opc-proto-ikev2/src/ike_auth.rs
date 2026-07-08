//! Typed cleartext IKE_AUTH payload views, builders, and Child SA helpers.
//!
//! These helpers operate on the cleartext payload chain after an `SK` payload is
//! opened, or before it is sealed. They intentionally do not own EAP-AKA',
//! subscriber policy, retransmission state, XFRM programming, or product traffic
//! readiness.
//!
//! @spec IETF RFC7296 2.16, 3.2, 3.5, 3.8, 3.10, 3.11, 3.13, 3.15
//! @req REQ-IETF-RFC7296-IKE-AUTH-CLEARTEXT-001

use std::{error::Error, fmt};

use bytes::Bytes;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{
    notify::{Ikev2NotifyPayload, Ikev2NotifyPayloadError, IKEV2_NOTIFY_REKEY_SA},
    payload::{PayloadChain, PayloadType, RawPayload, GENERIC_PAYLOAD_HEADER_LEN},
    sa_init::{
        encode_ke_payload_build, encode_nonce_payload_build, encode_notify_payload_build,
        encode_sa_payload_build, Ikev2KeyExchangePayloadBuild, Ikev2NoncePayloadBuild,
        Ikev2NotifyPayloadBuild, Ikev2SaInitBuildError, Ikev2SaPayload, Ikev2SaPayloadBuild,
        Ikev2SaPayloadError, Ikev2SaProposal, Ikev2SaProposalBuild, Ikev2SaTransform,
        Ikev2SaTransformBuild, Ikev2TransformAttributeBuild, Ikev2TransformAttributeBuildValue,
        Ikev2TransformAttributeValue,
    },
    sa_init_crypto::{Ikev2PrfAlgorithm, Ikev2SaInitCryptoProfile, Ikev2SaInitKeyMaterial},
};

const ID_FIXED_BODY_LEN: usize = 4;
const AUTH_FIXED_BODY_LEN: usize = 4;
const CERT_FIXED_BODY_LEN: usize = 1;
const CP_FIXED_BODY_LEN: usize = 4;
const CP_ATTR_HEADER_LEN: usize = 4;
const TS_FIXED_BODY_LEN: usize = 4;
const TS_SELECTOR_HEADER_LEN: usize = 8;
const DELETE_FIXED_BODY_LEN: usize = 4;
const TS_IPV4_ADDR_LEN: usize = 4;
const TS_IPV6_ADDR_LEN: usize = 16;
/// Traffic Selector type for IPv4 address ranges.
pub const IKEV2_TS_IPV4_ADDR_RANGE: u8 = 7;
/// Traffic Selector type for IPv6 address ranges.
pub const IKEV2_TS_IPV6_ADDR_RANGE: u8 = 8;

/// IKEv2 Security Protocol Identifier for the IKE SA.
///
/// @spec IETF RFC7296 3.3.1; IANA IKEv2 Security Protocol Identifiers
pub const IKEV2_SECURITY_PROTOCOL_ID_IKE: u8 = 1;

/// IKEv2 Security Protocol Identifier for AH Child SAs.
///
/// @spec IETF RFC7296 3.3.1; IANA IKEv2 Security Protocol Identifiers
pub const IKEV2_SECURITY_PROTOCOL_ID_AH: u8 = 2;

/// IKEv2 Security Protocol Identifier for ESP Child SAs.
///
/// @spec IETF RFC7296 3.3.1; IANA IKEv2 Security Protocol Identifiers
pub const IKEV2_SECURITY_PROTOCOL_ID_ESP: u8 = 3;

/// IKE SA Delete payload SPI size.
pub const IKEV2_IKE_SA_DELETE_SPI_SIZE: u8 = 0;

/// AH/ESP Child SA SPI size in IKEv2 Delete and REKEY_SA Notify payloads.
pub const IKEV2_IPSEC_SPI_SIZE: u8 = 4;

const IKEV2_NONCE_MIN_LEN: usize = 16;
const IKEV2_NONCE_MAX_LEN: usize = 256;
const IKEV2_AUTH_KEY_PAD: &[u8] = b"Key Pad for IKEv2";

/// IKEv2 AUTH Method 2, Shared Key Message Integrity Code.
pub const IKEV2_AUTH_METHOD_SHARED_KEY_MIC: u8 = 2;

/// IKEv2 Certificate Encoding 4, "X.509 Certificate - Signature".
///
/// @spec IETF RFC7296 3.6; IANA IKEv2 Certificate Encodings
pub const IKEV2_CERT_ENCODING_X509_SIGNATURE: u8 = 4;

/// Borrowed typed view of an IKEv2 IDi or IDr payload.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ikev2IdentificationPayload<'a> {
    /// Identification type.
    pub id_type: u8,
    /// Identification data bytes.
    pub id_data: &'a [u8],
}

impl<'a> Ikev2IdentificationPayload<'a> {
    /// Decode IDi or IDr from a raw payload.
    pub fn decode(raw: RawPayload<'a>) -> Result<Self, Ikev2IkeAuthPayloadError> {
        match raw.payload_type {
            PayloadType::IdentificationInitiator | PayloadType::IdentificationResponder => {
                Self::decode_body(raw.body)
            }
            _ => Err(Ikev2IkeAuthPayloadError::UnexpectedPayloadType),
        }
    }

    /// Decode IDi or IDr body bytes.
    pub fn decode_body(body: &'a [u8]) -> Result<Self, Ikev2IkeAuthPayloadError> {
        if body.len() < ID_FIXED_BODY_LEN {
            return Err(Ikev2IkeAuthPayloadError::IdentificationTooShort);
        }
        if body[1..ID_FIXED_BODY_LEN].iter().any(|byte| *byte != 0) {
            return Err(Ikev2IkeAuthPayloadError::ReservedNonZero);
        }
        if body[0] == 0 {
            return Err(Ikev2IkeAuthPayloadError::InvalidIdentificationType);
        }
        let id_data = &body[ID_FIXED_BODY_LEN..];
        if id_data.is_empty() {
            return Err(Ikev2IkeAuthPayloadError::IdentificationDataEmpty);
        }
        Ok(Self {
            id_type: body[0],
            id_data,
        })
    }

    /// Rebuild the ID payload body used by RFC 7296 AUTH signed-octets input.
    ///
    /// The decoded view has already verified that the reserved bytes were zero,
    /// so this produces the byte-equivalent `IDi'`/`IDr'` body.
    pub fn to_payload_body(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ID_FIXED_BODY_LEN + self.id_data.len());
        out.push(self.id_type);
        out.extend_from_slice(&[0, 0, 0]);
        out.extend_from_slice(self.id_data);
        out
    }
}

impl fmt::Debug for Ikev2IdentificationPayload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2IdentificationPayload")
            .field("id_type", &self.id_type)
            .field("id_data_len", &self.id_data.len())
            .finish()
    }
}

/// Borrowed typed view of an IKEv2 AUTH payload.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ikev2AuthenticationPayload<'a> {
    /// Authentication method.
    pub auth_method: u8,
    /// Authentication data bytes.
    pub auth_data: &'a [u8],
}

impl<'a> Ikev2AuthenticationPayload<'a> {
    /// Decode AUTH from a raw payload.
    pub fn decode(raw: RawPayload<'a>) -> Result<Self, Ikev2IkeAuthPayloadError> {
        if raw.payload_type != PayloadType::Authentication {
            return Err(Ikev2IkeAuthPayloadError::UnexpectedPayloadType);
        }
        Self::decode_body(raw.body)
    }

    /// Decode AUTH body bytes.
    pub fn decode_body(body: &'a [u8]) -> Result<Self, Ikev2IkeAuthPayloadError> {
        if body.len() < AUTH_FIXED_BODY_LEN {
            return Err(Ikev2IkeAuthPayloadError::AuthenticationTooShort);
        }
        if body[1..AUTH_FIXED_BODY_LEN].iter().any(|byte| *byte != 0) {
            return Err(Ikev2IkeAuthPayloadError::ReservedNonZero);
        }
        if body[0] == 0 {
            return Err(Ikev2IkeAuthPayloadError::InvalidAuthenticationMethod);
        }
        let auth_data = &body[AUTH_FIXED_BODY_LEN..];
        if auth_data.is_empty() {
            return Err(Ikev2IkeAuthPayloadError::AuthenticationDataEmpty);
        }
        Ok(Self {
            auth_method: body[0],
            auth_data,
        })
    }
}

impl fmt::Debug for Ikev2AuthenticationPayload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2AuthenticationPayload")
            .field("auth_method", &self.auth_method)
            .field("auth_data_len", &self.auth_data.len())
            .finish()
    }
}

/// Borrowed typed view of an IKEv2 CERT payload.
///
/// `Debug` reports only the certificate data length, never the bytes.
///
/// @spec IETF RFC7296 3.6
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ikev2CertificatePayload<'a> {
    /// Certificate Encoding.
    pub cert_encoding: u8,
    /// Certificate Data bytes.
    pub cert_data: &'a [u8],
}

impl<'a> Ikev2CertificatePayload<'a> {
    /// Decode CERT from a raw payload.
    pub fn decode(raw: RawPayload<'a>) -> Result<Self, Ikev2IkeAuthPayloadError> {
        if raw.payload_type != PayloadType::Certificate {
            return Err(Ikev2IkeAuthPayloadError::UnexpectedPayloadType);
        }
        Self::decode_body(raw.body)
    }

    /// Decode CERT body bytes.
    pub fn decode_body(body: &'a [u8]) -> Result<Self, Ikev2IkeAuthPayloadError> {
        if body.len() < CERT_FIXED_BODY_LEN {
            return Err(Ikev2IkeAuthPayloadError::CertificateTooShort);
        }
        if body[0] == 0 {
            return Err(Ikev2IkeAuthPayloadError::InvalidCertificateEncoding);
        }
        let cert_data = &body[CERT_FIXED_BODY_LEN..];
        if cert_data.is_empty() {
            return Err(Ikev2IkeAuthPayloadError::CertificateDataEmpty);
        }
        Ok(Self {
            cert_encoding: body[0],
            cert_data,
        })
    }
}

impl fmt::Debug for Ikev2CertificatePayload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2CertificatePayload")
            .field("cert_encoding", &self.cert_encoding)
            .field("cert_data_len", &self.cert_data.len())
            .finish()
    }
}

/// Borrowed typed view of an IKEv2 CERTREQ payload.
///
/// The Certification Authority field may be empty; when present it carries
/// concatenated SHA-1 hashes of trusted CA SubjectPublicKeyInfo values for
/// encoding 4.
///
/// @spec IETF RFC7296 3.7
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ikev2CertificateRequestPayload<'a> {
    /// Certificate Encoding.
    pub cert_encoding: u8,
    /// Certification Authority bytes.
    pub ca_data: &'a [u8],
}

impl<'a> Ikev2CertificateRequestPayload<'a> {
    /// Decode CERTREQ from a raw payload.
    pub fn decode(raw: RawPayload<'a>) -> Result<Self, Ikev2IkeAuthPayloadError> {
        if raw.payload_type != PayloadType::CertificateRequest {
            return Err(Ikev2IkeAuthPayloadError::UnexpectedPayloadType);
        }
        Self::decode_body(raw.body)
    }

    /// Decode CERTREQ body bytes.
    pub fn decode_body(body: &'a [u8]) -> Result<Self, Ikev2IkeAuthPayloadError> {
        if body.len() < CERT_FIXED_BODY_LEN {
            return Err(Ikev2IkeAuthPayloadError::CertificateRequestTooShort);
        }
        if body[0] == 0 {
            return Err(Ikev2IkeAuthPayloadError::InvalidCertificateEncoding);
        }
        Ok(Self {
            cert_encoding: body[0],
            ca_data: &body[CERT_FIXED_BODY_LEN..],
        })
    }
}

impl fmt::Debug for Ikev2CertificateRequestPayload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2CertificateRequestPayload")
            .field("cert_encoding", &self.cert_encoding)
            .field("ca_data_len", &self.ca_data.len())
            .finish()
    }
}

/// Borrowed typed view of an IKEv2 EAP payload.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ikev2EapPayload<'a> {
    /// Complete EAP packet bytes.
    pub packet: &'a [u8],
}

impl<'a> Ikev2EapPayload<'a> {
    /// Decode EAP from a raw payload.
    pub fn decode(raw: RawPayload<'a>) -> Result<Self, Ikev2IkeAuthPayloadError> {
        if raw.payload_type != PayloadType::ExtensibleAuthentication {
            return Err(Ikev2IkeAuthPayloadError::UnexpectedPayloadType);
        }
        Self::decode_body(raw.body)
    }

    /// Decode EAP body bytes.
    pub fn decode_body(body: &'a [u8]) -> Result<Self, Ikev2IkeAuthPayloadError> {
        if body.is_empty() {
            return Err(Ikev2IkeAuthPayloadError::EapPacketEmpty);
        }
        Ok(Self { packet: body })
    }
}

impl fmt::Debug for Ikev2EapPayload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2EapPayload")
            .field("packet_len", &self.packet.len())
            .finish()
    }
}

/// Borrowed typed view of an IKEv2 Configuration payload.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2ConfigurationPayload<'a> {
    /// Configuration payload type.
    pub config_type: u8,
    /// Configuration attributes.
    pub attributes: Vec<Ikev2ConfigurationAttribute<'a>>,
}

impl<'a> Ikev2ConfigurationPayload<'a> {
    /// Decode CP from a raw payload.
    pub fn decode(raw: RawPayload<'a>) -> Result<Self, Ikev2IkeAuthPayloadError> {
        if raw.payload_type != PayloadType::Configuration {
            return Err(Ikev2IkeAuthPayloadError::UnexpectedPayloadType);
        }
        Self::decode_body(raw.body)
    }

    /// Decode CP body bytes.
    pub fn decode_body(body: &'a [u8]) -> Result<Self, Ikev2IkeAuthPayloadError> {
        if body.len() < CP_FIXED_BODY_LEN {
            return Err(Ikev2IkeAuthPayloadError::ConfigurationTooShort);
        }
        if body[1..CP_FIXED_BODY_LEN].iter().any(|byte| *byte != 0) {
            return Err(Ikev2IkeAuthPayloadError::ReservedNonZero);
        }
        if body[0] == 0 {
            return Err(Ikev2IkeAuthPayloadError::InvalidConfigurationType);
        }
        let mut attributes = Vec::new();
        let mut remaining = &body[CP_FIXED_BODY_LEN..];
        while !remaining.is_empty() {
            if remaining.len() < CP_ATTR_HEADER_LEN {
                return Err(Ikev2IkeAuthPayloadError::ConfigurationAttributeTooShort);
            }
            let attribute_type = u16::from_be_bytes([remaining[0], remaining[1]]);
            let len = usize::from(u16::from_be_bytes([remaining[2], remaining[3]]));
            let value_start = CP_ATTR_HEADER_LEN;
            let value_end = value_start
                .checked_add(len)
                .ok_or(Ikev2IkeAuthPayloadError::ConfigurationAttributeLengthExceedsBody)?;
            if value_end > remaining.len() {
                return Err(Ikev2IkeAuthPayloadError::ConfigurationAttributeLengthExceedsBody);
            }
            attributes.push(Ikev2ConfigurationAttribute {
                attribute_type,
                value: &remaining[value_start..value_end],
            });
            remaining = &remaining[value_end..];
        }
        Ok(Self {
            config_type: body[0],
            attributes,
        })
    }
}

impl fmt::Debug for Ikev2ConfigurationPayload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2ConfigurationPayload")
            .field("config_type", &self.config_type)
            .field("attribute_count", &self.attributes.len())
            .field("attributes", &self.attributes)
            .finish()
    }
}

/// Borrowed typed view of one CP attribute.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ikev2ConfigurationAttribute<'a> {
    /// Attribute type.
    pub attribute_type: u16,
    /// Attribute value bytes.
    pub value: &'a [u8],
}

impl fmt::Debug for Ikev2ConfigurationAttribute<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2ConfigurationAttribute")
            .field("attribute_type", &self.attribute_type)
            .field("value_len", &self.value.len())
            .finish()
    }
}

/// Borrowed typed view of an IKEv2 TSi or TSr payload.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2TrafficSelectorPayload<'a> {
    /// Traffic selectors in wire order.
    pub selectors: Vec<Ikev2TrafficSelector<'a>>,
}

impl<'a> Ikev2TrafficSelectorPayload<'a> {
    /// Decode TSi or TSr from a raw payload.
    pub fn decode(raw: RawPayload<'a>) -> Result<Self, Ikev2IkeAuthPayloadError> {
        match raw.payload_type {
            PayloadType::TrafficSelectorInitiator | PayloadType::TrafficSelectorResponder => {
                Self::decode_body(raw.body)
            }
            _ => Err(Ikev2IkeAuthPayloadError::UnexpectedPayloadType),
        }
    }

    /// Decode TSi or TSr body bytes.
    pub fn decode_body(body: &'a [u8]) -> Result<Self, Ikev2IkeAuthPayloadError> {
        if body.len() < TS_FIXED_BODY_LEN {
            return Err(Ikev2IkeAuthPayloadError::TrafficSelectorPayloadTooShort);
        }
        let count = usize::from(body[0]);
        if count == 0 {
            return Err(Ikev2IkeAuthPayloadError::TrafficSelectorMissing);
        }
        if body[1..TS_FIXED_BODY_LEN].iter().any(|byte| *byte != 0) {
            return Err(Ikev2IkeAuthPayloadError::ReservedNonZero);
        }

        let mut selectors = Vec::with_capacity(count);
        let mut remaining = &body[TS_FIXED_BODY_LEN..];
        for _ in 0..count {
            if remaining.len() < TS_SELECTOR_HEADER_LEN {
                return Err(Ikev2IkeAuthPayloadError::TrafficSelectorTooShort);
            }
            let selector_len = usize::from(u16::from_be_bytes([remaining[2], remaining[3]]));
            if selector_len < TS_SELECTOR_HEADER_LEN {
                return Err(Ikev2IkeAuthPayloadError::TrafficSelectorLengthTooShort);
            }
            if selector_len > remaining.len() {
                return Err(Ikev2IkeAuthPayloadError::TrafficSelectorLengthExceedsBody);
            }
            let address_bytes = selector_len - TS_SELECTOR_HEADER_LEN;
            if address_bytes == 0 || !address_bytes.is_multiple_of(2) {
                return Err(Ikev2IkeAuthPayloadError::TrafficSelectorAddressLengthInvalid);
            }
            let address_len = address_bytes / 2;
            if address_len != TS_IPV4_ADDR_LEN && address_len != TS_IPV6_ADDR_LEN {
                return Err(Ikev2IkeAuthPayloadError::TrafficSelectorAddressLengthInvalid);
            }
            let ts_type = remaining[0];
            if expected_ts_address_len(ts_type).is_none() {
                return Err(Ikev2IkeAuthPayloadError::TrafficSelectorTypeUnsupported);
            }
            if expected_ts_address_len(ts_type) != Some(address_len) {
                return Err(Ikev2IkeAuthPayloadError::TrafficSelectorAddressLengthInvalid);
            }
            let start_port = u16::from_be_bytes([remaining[4], remaining[5]]);
            let end_port = u16::from_be_bytes([remaining[6], remaining[7]]);
            if start_port > end_port {
                return Err(Ikev2IkeAuthPayloadError::TrafficSelectorPortRangeInvalid);
            }
            let start_address =
                &remaining[TS_SELECTOR_HEADER_LEN..TS_SELECTOR_HEADER_LEN + address_len];
            let end_address = &remaining
                [TS_SELECTOR_HEADER_LEN + address_len..TS_SELECTOR_HEADER_LEN + address_bytes];
            if start_address > end_address {
                return Err(Ikev2IkeAuthPayloadError::TrafficSelectorAddressRangeInvalid);
            }
            selectors.push(Ikev2TrafficSelector {
                ts_type,
                ip_protocol_id: remaining[1],
                start_port,
                end_port,
                start_address,
                end_address,
            });
            remaining = &remaining[selector_len..];
        }
        if !remaining.is_empty() {
            return Err(Ikev2IkeAuthPayloadError::TrafficSelectorCountMismatch);
        }
        Ok(Self { selectors })
    }
}

impl fmt::Debug for Ikev2TrafficSelectorPayload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2TrafficSelectorPayload")
            .field("selector_count", &self.selectors.len())
            .field("selectors", &self.selectors)
            .finish()
    }
}

/// Borrowed typed view of one Traffic Selector.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ikev2TrafficSelector<'a> {
    /// Traffic selector type.
    pub ts_type: u8,
    /// IP protocol ID, or zero for any.
    pub ip_protocol_id: u8,
    /// Inclusive start port.
    pub start_port: u16,
    /// Inclusive end port.
    pub end_port: u16,
    /// Start address bytes, 4 bytes for IPv4 or 16 bytes for IPv6.
    pub start_address: &'a [u8],
    /// End address bytes, 4 bytes for IPv4 or 16 bytes for IPv6.
    pub end_address: &'a [u8],
}

impl fmt::Debug for Ikev2TrafficSelector<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2TrafficSelector")
            .field("ts_type", &self.ts_type)
            .field("ip_protocol_id", &self.ip_protocol_id)
            .field("start_port", &self.start_port)
            .field("end_port", &self.end_port)
            .field("address_len", &self.start_address.len())
            .finish()
    }
}

/// Borrowed typed view of a Delete payload.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2DeletePayload<'a> {
    /// Protocol ID.
    pub protocol_id: u8,
    /// SPI values in wire order.
    pub spis: Vec<&'a [u8]>,
}

impl<'a> Ikev2DeletePayload<'a> {
    /// Decode Delete from a raw payload.
    pub fn decode(raw: RawPayload<'a>) -> Result<Self, Ikev2IkeAuthPayloadError> {
        if raw.payload_type != PayloadType::Delete {
            return Err(Ikev2IkeAuthPayloadError::UnexpectedPayloadType);
        }
        Self::decode_body(raw.body)
    }

    /// Decode Delete body bytes.
    pub fn decode_body(body: &'a [u8]) -> Result<Self, Ikev2IkeAuthPayloadError> {
        if body.len() < DELETE_FIXED_BODY_LEN {
            return Err(Ikev2IkeAuthPayloadError::DeleteTooShort);
        }
        let protocol_id = body[0];
        let spi_size = usize::from(body[1]);
        let count = usize::from(u16::from_be_bytes([body[2], body[3]]));
        let expected = DELETE_FIXED_BODY_LEN
            .checked_add(
                spi_size
                    .checked_mul(count)
                    .ok_or(Ikev2IkeAuthPayloadError::DeleteLengthOverflow)?,
            )
            .ok_or(Ikev2IkeAuthPayloadError::DeleteLengthOverflow)?;
        if expected != body.len() {
            return Err(Ikev2IkeAuthPayloadError::DeleteSpiLengthMismatch);
        }
        let mut spis = Vec::with_capacity(count);
        let mut remaining = &body[DELETE_FIXED_BODY_LEN..];
        for _ in 0..count {
            let (spi, rest) = remaining.split_at(spi_size);
            spis.push(spi);
            remaining = rest;
        }
        Ok(Self { protocol_id, spis })
    }

    /// Encode this Delete payload body.
    ///
    /// The SPI Size field is inferred from the first SPI, or zero when no SPI
    /// values are present. Use [`build_delete_payload_body`] when the caller
    /// needs to validate an explicit SPI Size field.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2IkeAuthBuildError`] when the Delete shape is invalid for
    /// the protocol ID or exceeds IKEv2 size fields.
    pub fn encode_body(&self) -> Result<Vec<u8>, Ikev2IkeAuthBuildError> {
        let spi_size = match self.spis.first() {
            Some(spi) => {
                u8::try_from(spi.len()).map_err(|_| Ikev2IkeAuthBuildError::DeleteSpiTooLong)?
            }
            None => IKEV2_IKE_SA_DELETE_SPI_SIZE,
        };
        build_delete_payload_body(self.protocol_id, spi_size, &self.spis)
    }
}

impl fmt::Debug for Ikev2DeletePayload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2DeletePayload")
            .field("protocol_id", &self.protocol_id)
            .field("spi_count", &self.spis.len())
            .field("spi_size", &self.spis.first().map_or(0, |spi| spi.len()))
            .finish()
    }
}

/// Typed cleartext payload projection for an IKE_AUTH exchange body.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Ikev2IkeAuthCleartextPayloads<'a> {
    /// IDi payloads.
    pub identification_initiators: Vec<Ikev2IdentificationPayload<'a>>,
    /// IDr payloads.
    pub identification_responders: Vec<Ikev2IdentificationPayload<'a>>,
    /// AUTH payloads.
    pub authentications: Vec<Ikev2AuthenticationPayload<'a>>,
    /// CERT payloads in wire order.
    pub certificates: Vec<Ikev2CertificatePayload<'a>>,
    /// CERTREQ payloads in wire order.
    pub certificate_requests: Vec<Ikev2CertificateRequestPayload<'a>>,
    /// EAP payloads.
    pub eap: Vec<Ikev2EapPayload<'a>>,
    /// CP payloads.
    pub configurations: Vec<Ikev2ConfigurationPayload<'a>>,
    /// SA payloads.
    pub security_associations: Vec<Ikev2SaPayload<'a>>,
    /// TSi payloads.
    pub traffic_selectors_initiator: Vec<Ikev2TrafficSelectorPayload<'a>>,
    /// TSr payloads.
    pub traffic_selectors_responder: Vec<Ikev2TrafficSelectorPayload<'a>>,
    /// Notify payloads.
    pub notifies: Vec<Ikev2NotifyPayload<'a>>,
    /// Delete payloads.
    pub deletes: Vec<Ikev2DeletePayload<'a>>,
    /// Count of other non-critical payloads preserved by raw payload type.
    pub other_payload_count: usize,
}

impl fmt::Debug for Ikev2IkeAuthCleartextPayloads<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2IkeAuthCleartextPayloads")
            .field("idi_count", &self.identification_initiators.len())
            .field("idr_count", &self.identification_responders.len())
            .field("auth_count", &self.authentications.len())
            .field("cert_count", &self.certificates.len())
            .field("certreq_count", &self.certificate_requests.len())
            .field("eap_count", &self.eap.len())
            .field("cp_count", &self.configurations.len())
            .field("sa_count", &self.security_associations.len())
            .field("tsi_count", &self.traffic_selectors_initiator.len())
            .field("tsr_count", &self.traffic_selectors_responder.len())
            .field("notify_count", &self.notifies.len())
            .field("delete_count", &self.deletes.len())
            .field("other_payload_count", &self.other_payload_count)
            .finish()
    }
}

impl Ikev2IkeAuthCleartextPayloads<'_> {
    /// Return true when the peer sent an RFC 5998 EAP_ONLY_AUTHENTICATION
    /// status notify, signalling it accepts EAP-only mutual authentication and
    /// the responder may omit CERT payloads and signature AUTH.
    pub fn eap_only_authentication_requested(&self) -> bool {
        self.notifies
            .iter()
            .any(|notify| notify.is_eap_only_authentication())
    }
}

/// Decode an opened IKE_AUTH cleartext payload chain.
///
/// `first_payload` is the payload type carried in the outer `SK` generic header.
pub fn decode_ike_auth_cleartext_payloads(
    first_payload: PayloadType,
    cleartext_payloads: &[u8],
) -> Result<Ikev2IkeAuthCleartextPayloads<'_>, Ikev2IkeAuthPayloadError> {
    let chain = PayloadChain::new(first_payload, cleartext_payloads);
    let mut out = Ikev2IkeAuthCleartextPayloads::default();
    for payload in chain.iter() {
        let payload = payload.map_err(|_| Ikev2IkeAuthPayloadError::PayloadDecode)?;
        match payload.payload_type {
            PayloadType::IdentificationInitiator => out
                .identification_initiators
                .push(Ikev2IdentificationPayload::decode(payload)?),
            PayloadType::IdentificationResponder => out
                .identification_responders
                .push(Ikev2IdentificationPayload::decode(payload)?),
            PayloadType::Authentication => out
                .authentications
                .push(Ikev2AuthenticationPayload::decode(payload)?),
            PayloadType::Certificate => out
                .certificates
                .push(Ikev2CertificatePayload::decode(payload)?),
            PayloadType::CertificateRequest => out
                .certificate_requests
                .push(Ikev2CertificateRequestPayload::decode(payload)?),
            PayloadType::ExtensibleAuthentication => {
                out.eap.push(Ikev2EapPayload::decode(payload)?)
            }
            PayloadType::Configuration => out
                .configurations
                .push(Ikev2ConfigurationPayload::decode(payload)?),
            PayloadType::SecurityAssociation => out
                .security_associations
                .push(Ikev2SaPayload::decode(payload).map_err(Ikev2IkeAuthPayloadError::Sa)?),
            PayloadType::TrafficSelectorInitiator => out
                .traffic_selectors_initiator
                .push(Ikev2TrafficSelectorPayload::decode(payload)?),
            PayloadType::TrafficSelectorResponder => out
                .traffic_selectors_responder
                .push(Ikev2TrafficSelectorPayload::decode(payload)?),
            PayloadType::Notify => out.notifies.push(
                Ikev2NotifyPayload::decode(payload).map_err(Ikev2IkeAuthPayloadError::Notify)?,
            ),
            PayloadType::Delete => out.deletes.push(Ikev2DeletePayload::decode(payload)?),
            _ => out.other_payload_count = out.other_payload_count.saturating_add(1),
        }
    }
    Ok(out)
}

/// Owned payload body ready to be chained inside an IKE_AUTH cleartext exchange.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2IkeAuthPayloadBuild {
    /// Payload type.
    pub payload_type: PayloadType,
    /// Payload body bytes, excluding the generic payload header.
    pub body: Vec<u8>,
}

impl fmt::Debug for Ikev2IkeAuthPayloadBuild {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2IkeAuthPayloadBuild")
            .field("payload_type", &self.payload_type)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// Owned IDi/IDr payload builder input.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2IdentificationPayloadBuild {
    /// Identification type.
    pub id_type: u8,
    /// Identification data bytes.
    pub id_data: Vec<u8>,
}

impl fmt::Debug for Ikev2IdentificationPayloadBuild {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2IdentificationPayloadBuild")
            .field("id_type", &self.id_type)
            .field("id_data_len", &self.id_data.len())
            .finish()
    }
}

/// Owned AUTH payload builder input.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2AuthenticationPayloadBuild {
    /// Authentication method.
    pub auth_method: u8,
    /// Authentication data bytes.
    pub auth_data: Vec<u8>,
}

impl fmt::Debug for Ikev2AuthenticationPayloadBuild {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2AuthenticationPayloadBuild")
            .field("auth_method", &self.auth_method)
            .field("auth_data_len", &self.auth_data.len())
            .finish()
    }
}

/// Owned CERT payload builder input.
///
/// `Debug` reports only the certificate data length, never the bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2CertificatePayloadBuild {
    /// Certificate Encoding.
    pub cert_encoding: u8,
    /// Certificate Data bytes.
    pub cert_data: Vec<u8>,
}

impl fmt::Debug for Ikev2CertificatePayloadBuild {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2CertificatePayloadBuild")
            .field("cert_encoding", &self.cert_encoding)
            .field("cert_data_len", &self.cert_data.len())
            .finish()
    }
}

/// Owned CERTREQ payload builder input.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2CertificateRequestPayloadBuild {
    /// Certificate Encoding.
    pub cert_encoding: u8,
    /// Certification Authority bytes; may be empty.
    pub ca_data: Vec<u8>,
}

impl fmt::Debug for Ikev2CertificateRequestPayloadBuild {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2CertificateRequestPayloadBuild")
            .field("cert_encoding", &self.cert_encoding)
            .field("ca_data_len", &self.ca_data.len())
            .finish()
    }
}

/// Owned CP attribute builder input.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2ConfigurationAttributeBuild {
    /// Attribute type.
    pub attribute_type: u16,
    /// Attribute value bytes.
    pub value: Vec<u8>,
}

impl fmt::Debug for Ikev2ConfigurationAttributeBuild {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2ConfigurationAttributeBuild")
            .field("attribute_type", &self.attribute_type)
            .field("value_len", &self.value.len())
            .finish()
    }
}

/// Owned CP payload builder input.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2ConfigurationPayloadBuild {
    /// Configuration payload type.
    pub config_type: u8,
    /// Attributes.
    pub attributes: Vec<Ikev2ConfigurationAttributeBuild>,
}

impl fmt::Debug for Ikev2ConfigurationPayloadBuild {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2ConfigurationPayloadBuild")
            .field("config_type", &self.config_type)
            .field("attribute_count", &self.attributes.len())
            .field("attributes", &self.attributes)
            .finish()
    }
}

/// Owned Traffic Selector builder input.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2TrafficSelectorBuild {
    /// Traffic selector type.
    pub ts_type: u8,
    /// IP protocol ID, or zero for any.
    pub ip_protocol_id: u8,
    /// Inclusive start port.
    pub start_port: u16,
    /// Inclusive end port.
    pub end_port: u16,
    /// Start address bytes, 4 bytes for IPv4 or 16 bytes for IPv6.
    pub start_address: Vec<u8>,
    /// End address bytes, 4 bytes for IPv4 or 16 bytes for IPv6.
    pub end_address: Vec<u8>,
}

impl fmt::Debug for Ikev2TrafficSelectorBuild {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2TrafficSelectorBuild")
            .field("ts_type", &self.ts_type)
            .field("ip_protocol_id", &self.ip_protocol_id)
            .field("start_port", &self.start_port)
            .field("end_port", &self.end_port)
            .field("start_address_len", &self.start_address.len())
            .field("end_address_len", &self.end_address.len())
            .finish()
    }
}

/// Owned TSi/TSr payload builder input.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2TrafficSelectorPayloadBuild {
    /// Traffic selectors.
    pub selectors: Vec<Ikev2TrafficSelectorBuild>,
}

impl fmt::Debug for Ikev2TrafficSelectorPayloadBuild {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2TrafficSelectorPayloadBuild")
            .field("selector_count", &self.selectors.len())
            .field("selectors", &self.selectors)
            .finish()
    }
}

/// Builder input for a CREATE_CHILD_SA Child-SA rekey request payload set.
///
/// This emits only the cleartext payload bodies that belong inside the
/// protected `SK` payload. The product remains responsible for IKE header
/// construction, sealing, retransmission, and timeout policy.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2CreateChildSaRekeyRequestBuild {
    /// Protocol ID of the existing Child SA being rekeyed, AH or ESP.
    pub rekeyed_protocol_id: u8,
    /// Inbound SPI of the existing Child SA being rekeyed.
    pub rekeyed_spi: Vec<u8>,
    /// SA proposal for the replacement Child SA.
    pub security_association: Ikev2SaPayloadBuild,
    /// Initiator nonce payload.
    pub nonce: Ikev2NoncePayloadBuild,
    /// Optional initiator KE payload for PFS.
    pub key_exchange: Option<Ikev2KeyExchangePayloadBuild>,
    /// Proposed initiator traffic selectors.
    pub traffic_selectors_initiator: Ikev2TrafficSelectorPayloadBuild,
    /// Proposed responder traffic selectors.
    pub traffic_selectors_responder: Ikev2TrafficSelectorPayloadBuild,
}

impl fmt::Debug for Ikev2CreateChildSaRekeyRequestBuild {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2CreateChildSaRekeyRequestBuild")
            .field("rekeyed_protocol_id", &self.rekeyed_protocol_id)
            .field("rekeyed_spi_len", &self.rekeyed_spi.len())
            .field("security_association", &self.security_association)
            .field("nonce_len", &self.nonce.nonce.len())
            .field("key_exchange_present", &self.key_exchange.is_some())
            .field(
                "traffic_selectors_initiator",
                &self.traffic_selectors_initiator,
            )
            .field(
                "traffic_selectors_responder",
                &self.traffic_selectors_responder,
            )
            .finish()
    }
}

/// Builder input for a CREATE_CHILD_SA Child-SA rekey response payload set.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2CreateChildSaRekeyResponseBuild {
    /// Accepted SA proposal for the replacement Child SA.
    pub security_association: Ikev2SaPayloadBuild,
    /// Responder nonce payload.
    pub nonce: Ikev2NoncePayloadBuild,
    /// Optional responder KE payload when PFS was used.
    pub key_exchange: Option<Ikev2KeyExchangePayloadBuild>,
    /// Accepted initiator traffic selectors.
    pub traffic_selectors_initiator: Ikev2TrafficSelectorPayloadBuild,
    /// Accepted responder traffic selectors.
    pub traffic_selectors_responder: Ikev2TrafficSelectorPayloadBuild,
}

impl fmt::Debug for Ikev2CreateChildSaRekeyResponseBuild {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2CreateChildSaRekeyResponseBuild")
            .field("security_association", &self.security_association)
            .field("nonce_len", &self.nonce.nonce.len())
            .field("key_exchange_present", &self.key_exchange.is_some())
            .field(
                "traffic_selectors_initiator",
                &self.traffic_selectors_initiator,
            )
            .field(
                "traffic_selectors_responder",
                &self.traffic_selectors_responder,
            )
            .finish()
    }
}

/// IKE_AUTH peer whose AUTH payload is being computed or verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2IkeAuthPeer {
    /// Initiator AUTH uses `SK_pi` and is bound to the first IKE_SA_INIT request
    /// plus responder nonce.
    Initiator,
    /// Responder AUTH uses `SK_pr` and is bound to the first IKE_SA_INIT
    /// response plus initiator nonce.
    Responder,
}

impl Ikev2IkeAuthPeer {
    fn sk_p(self, key_material: &Ikev2SaInitKeyMaterial) -> &[u8] {
        match self {
            Self::Initiator => key_material.sk_pi(),
            Self::Responder => key_material.sk_pr(),
        }
    }
}

/// Transcript inputs used to compute RFC 7296 IKE_AUTH signed octets.
#[derive(Clone, Copy)]
pub struct Ikev2IkeAuthSignedOctets<'a> {
    /// Peer whose AUTH payload is being computed or verified.
    pub peer: Ikev2IkeAuthPeer,
    /// Exact first IKE_SA_INIT message for this peer's signed-octets formula.
    ///
    /// Use message 1 for initiator AUTH and message 2 for responder AUTH.
    pub ike_sa_init_message: &'a [u8],
    /// Peer nonce value bytes, excluding the Nonce payload header.
    ///
    /// Use `Nr` for initiator AUTH and `Ni` for responder AUTH.
    pub peer_nonce: &'a [u8],
    /// Exact ID payload body (`IDi'` or `IDr'`), including the ID type octet and
    /// three reserved zero octets but excluding the generic payload header.
    pub identity_payload_body: &'a [u8],
}

impl fmt::Debug for Ikev2IkeAuthSignedOctets<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2IkeAuthSignedOctets")
            .field("peer", &self.peer)
            .field("ike_sa_init_message_len", &self.ike_sa_init_message.len())
            .field("peer_nonce_len", &self.peer_nonce.len())
            .field(
                "identity_payload_body_len",
                &self.identity_payload_body.len(),
            )
            .finish()
    }
}

/// Build an IDi payload body.
pub fn build_ike_auth_identification_payload(
    input: &Ikev2IdentificationPayloadBuild,
) -> Result<Vec<u8>, Ikev2IkeAuthBuildError> {
    if input.id_type == 0 {
        return Err(Ikev2IkeAuthBuildError::InvalidIdentificationType);
    }
    if input.id_data.is_empty() {
        return Err(Ikev2IkeAuthBuildError::IdentificationDataEmpty);
    }
    let mut out = Vec::with_capacity(ID_FIXED_BODY_LEN + input.id_data.len());
    out.push(input.id_type);
    out.extend_from_slice(&[0, 0, 0]);
    out.extend_from_slice(&input.id_data);
    Ok(out)
}

/// Build an AUTH payload body.
pub fn build_ike_auth_authentication_payload(
    input: &Ikev2AuthenticationPayloadBuild,
) -> Result<Vec<u8>, Ikev2IkeAuthBuildError> {
    if input.auth_method == 0 {
        return Err(Ikev2IkeAuthBuildError::InvalidAuthenticationMethod);
    }
    if input.auth_data.is_empty() {
        return Err(Ikev2IkeAuthBuildError::AuthenticationDataEmpty);
    }
    let mut out = Vec::with_capacity(AUTH_FIXED_BODY_LEN + input.auth_data.len());
    out.push(input.auth_method);
    out.extend_from_slice(&[0, 0, 0]);
    out.extend_from_slice(&input.auth_data);
    Ok(out)
}

/// Build a CERT payload body.
pub fn build_ike_auth_certificate_payload(
    input: &Ikev2CertificatePayloadBuild,
) -> Result<Vec<u8>, Ikev2IkeAuthBuildError> {
    if input.cert_encoding == 0 {
        return Err(Ikev2IkeAuthBuildError::InvalidCertificateEncoding);
    }
    if input.cert_data.is_empty() {
        return Err(Ikev2IkeAuthBuildError::CertificateDataEmpty);
    }
    let mut out = Vec::with_capacity(CERT_FIXED_BODY_LEN + input.cert_data.len());
    out.push(input.cert_encoding);
    out.extend_from_slice(&input.cert_data);
    Ok(out)
}

/// Build a CERTREQ payload body.
///
/// The Certification Authority field is caller-supplied opaque bytes; for
/// encoding 4 it must be a concatenation of 20-octet SHA-1 hashes of trusted CA
/// SubjectPublicKeyInfo values, and it may be empty.
pub fn build_ike_auth_certreq_payload(
    input: &Ikev2CertificateRequestPayloadBuild,
) -> Result<Vec<u8>, Ikev2IkeAuthBuildError> {
    if input.cert_encoding == 0 {
        return Err(Ikev2IkeAuthBuildError::InvalidCertificateEncoding);
    }
    let mut out = Vec::with_capacity(CERT_FIXED_BODY_LEN + input.ca_data.len());
    out.push(input.cert_encoding);
    out.extend_from_slice(&input.ca_data);
    Ok(out)
}

/// Build a Notify payload body for an IKE_AUTH cleartext chain.
pub fn build_ike_auth_notify_payload(
    input: &Ikev2NotifyPayloadBuild,
) -> Result<Vec<u8>, Ikev2IkeAuthBuildError> {
    encode_notify_payload_build(input).map_err(|_| Ikev2IkeAuthBuildError::NotifySpiTooLong)
}

/// Build a Delete payload body.
///
/// The output is the RFC 7296 §3.11 Delete body:
/// Protocol ID, SPI Size, Num of SPIs, and the concatenated SPI values.
///
/// # Errors
///
/// Returns [`Ikev2IkeAuthBuildError`] when the protocol/SPI shape is invalid
/// or the SPI count exceeds the two-octet field.
pub fn build_delete_payload_body(
    protocol_id: u8,
    spi_size: u8,
    spis: &[&[u8]],
) -> Result<Vec<u8>, Ikev2IkeAuthBuildError> {
    validate_delete_payload_shape(protocol_id, spi_size, spis)?;
    let spi_count =
        u16::try_from(spis.len()).map_err(|_| Ikev2IkeAuthBuildError::DeleteSpiCountTooLong)?;
    let spi_bytes_len = usize::from(spi_size)
        .checked_mul(spis.len())
        .ok_or(Ikev2IkeAuthBuildError::LengthOverflow)?;
    let mut out = Vec::with_capacity(
        DELETE_FIXED_BODY_LEN
            .checked_add(spi_bytes_len)
            .ok_or(Ikev2IkeAuthBuildError::LengthOverflow)?,
    );
    out.push(protocol_id);
    out.push(spi_size);
    out.extend_from_slice(&spi_count.to_be_bytes());
    for spi in spis {
        out.extend_from_slice(spi);
    }
    Ok(out)
}

/// Build a Delete payload body from a typed Delete view.
///
/// # Errors
///
/// Returns [`Ikev2IkeAuthBuildError`] when the Delete shape is invalid for the
/// protocol ID or exceeds IKEv2 size fields.
pub fn build_ike_auth_delete_payload(
    input: &Ikev2DeletePayload<'_>,
) -> Result<Vec<u8>, Ikev2IkeAuthBuildError> {
    input.encode_body()
}

fn validate_delete_payload_shape(
    protocol_id: u8,
    spi_size: u8,
    spis: &[&[u8]],
) -> Result<(), Ikev2IkeAuthBuildError> {
    match protocol_id {
        IKEV2_SECURITY_PROTOCOL_ID_IKE => {
            if spi_size != IKEV2_IKE_SA_DELETE_SPI_SIZE || !spis.is_empty() {
                return Err(Ikev2IkeAuthBuildError::DeleteIkeSaSpiInvalid);
            }
        }
        IKEV2_SECURITY_PROTOCOL_ID_AH | IKEV2_SECURITY_PROTOCOL_ID_ESP => {
            if spi_size != IKEV2_IPSEC_SPI_SIZE {
                return Err(Ikev2IkeAuthBuildError::DeleteIpsecSpiSizeInvalid);
            }
            if spis.is_empty() {
                return Err(Ikev2IkeAuthBuildError::DeleteSpiMissing);
            }
        }
        _ => return Err(Ikev2IkeAuthBuildError::DeleteProtocolIdUnsupported),
    }

    for spi in spis {
        if spi.len() > usize::from(u8::MAX) {
            return Err(Ikev2IkeAuthBuildError::DeleteSpiTooLong);
        }
        if spi.len() != usize::from(spi_size) {
            return Err(Ikev2IkeAuthBuildError::DeleteSpiSizeMismatch);
        }
    }
    Ok(())
}

/// Returns the IKE_AUTH shared-key AUTH payload body length for `profile`.
///
/// This is a keying-material-free sizing helper for callers that must construct
/// an outer `SK` associated-data prefix before sealing. It is exactly the fixed
/// AUTH body header plus the negotiated PRF output length.
pub const fn ike_auth_shared_key_authentication_payload_body_len(
    profile: Ikev2SaInitCryptoProfile,
) -> usize {
    AUTH_FIXED_BODY_LEN + profile.prf().output_len()
}

/// Compute AUTH data for IKEv2 Shared Key Message Integrity Code.
///
/// This is the generic mechanism used by EAP-authenticated IKE_AUTH when the
/// AAA/EAP layer supplies shared keying material. It computes:
///
/// `prf(prf(auth_keying_material, "Key Pad for IKEv2"), signed_octets)`
///
/// where `signed_octets` is the RFC 7296 transcript binding using `SK_pi` or
/// `SK_pr` according to [`Ikev2IkeAuthSignedOctets::peer`].
///
/// # Errors
///
/// Returns [`Ikev2IkeAuthVerificationError`] when transcript inputs or keying
/// material are structurally invalid for AUTH.
pub fn compute_ike_auth_shared_key_mic(
    profile: Ikev2SaInitCryptoProfile,
    key_material: &Ikev2SaInitKeyMaterial,
    signed_octets: Ikev2IkeAuthSignedOctets<'_>,
    auth_keying_material: &[u8],
) -> Result<Vec<u8>, Ikev2IkeAuthVerificationError> {
    validate_signed_octets(signed_octets)?;
    if auth_keying_material.is_empty() {
        return Err(Ikev2IkeAuthVerificationError::AuthenticationKeyEmpty);
    }

    let signed = build_signed_octets(profile.prf(), key_material, signed_octets)?;
    let auth_key = ike_auth_prf(profile.prf(), auth_keying_material, IKEV2_AUTH_KEY_PAD)?;
    let mic = ike_auth_prf(profile.prf(), &auth_key, &signed)?;
    Ok(mic.to_vec())
}

/// Verify an AUTH payload using IKEv2 Shared Key Message Integrity Code.
///
/// The comparison is constant-time after validating that the received AUTH data
/// has the expected PRF output length.
///
/// # Errors
///
/// Returns [`Ikev2IkeAuthVerificationError`] when the AUTH method is not method
/// 2, the inputs are structurally invalid, or the received AUTH bytes do not
/// match the transcript-bound MIC.
pub fn verify_ike_auth_shared_key_mic(
    profile: Ikev2SaInitCryptoProfile,
    key_material: &Ikev2SaInitKeyMaterial,
    signed_octets: Ikev2IkeAuthSignedOctets<'_>,
    auth_keying_material: &[u8],
    authentication: &Ikev2AuthenticationPayload<'_>,
) -> Result<(), Ikev2IkeAuthVerificationError> {
    if authentication.auth_method != IKEV2_AUTH_METHOD_SHARED_KEY_MIC {
        return Err(
            Ikev2IkeAuthVerificationError::UnsupportedAuthenticationMethod {
                method: authentication.auth_method,
            },
        );
    }

    let expected = compute_ike_auth_shared_key_mic(
        profile,
        key_material,
        signed_octets,
        auth_keying_material,
    )?;
    if authentication.auth_data.len() != expected.len() {
        return Err(Ikev2IkeAuthVerificationError::AuthenticationDataLength {
            expected: expected.len(),
            actual: authentication.auth_data.len(),
        });
    }
    if bool::from(authentication.auth_data.ct_eq(&expected)) {
        Ok(())
    } else {
        Err(Ikev2IkeAuthVerificationError::AuthenticationFailed)
    }
}

/// Build a CP payload body.
pub fn build_ike_auth_configuration_payload(
    input: &Ikev2ConfigurationPayloadBuild,
) -> Result<Vec<u8>, Ikev2IkeAuthBuildError> {
    if input.config_type == 0 {
        return Err(Ikev2IkeAuthBuildError::InvalidConfigurationType);
    }
    let mut out = Vec::new();
    out.push(input.config_type);
    out.extend_from_slice(&[0, 0, 0]);
    for attribute in &input.attributes {
        let len = u16::try_from(attribute.value.len())
            .map_err(|_| Ikev2IkeAuthBuildError::LengthOverflow)?;
        out.extend_from_slice(&attribute.attribute_type.to_be_bytes());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&attribute.value);
    }
    Ok(out)
}

/// Build a TSi or TSr payload body.
pub fn build_ike_auth_traffic_selector_payload(
    input: &Ikev2TrafficSelectorPayloadBuild,
) -> Result<Vec<u8>, Ikev2IkeAuthBuildError> {
    let selector_count =
        u8::try_from(input.selectors.len()).map_err(|_| Ikev2IkeAuthBuildError::LengthOverflow)?;
    if selector_count == 0 {
        return Err(Ikev2IkeAuthBuildError::TrafficSelectorMissing);
    }
    let mut out = Vec::new();
    out.push(selector_count);
    out.extend_from_slice(&[0, 0, 0]);
    for selector in &input.selectors {
        let address_len = selector.start_address.len();
        if expected_ts_address_len(selector.ts_type).is_none() {
            return Err(Ikev2IkeAuthBuildError::TrafficSelectorTypeUnsupported);
        }
        if address_len != selector.end_address.len()
            || expected_ts_address_len(selector.ts_type) != Some(address_len)
        {
            return Err(Ikev2IkeAuthBuildError::TrafficSelectorAddressLengthInvalid);
        }
        if selector.start_port > selector.end_port {
            return Err(Ikev2IkeAuthBuildError::TrafficSelectorPortRangeInvalid);
        }
        if selector.start_address > selector.end_address {
            return Err(Ikev2IkeAuthBuildError::TrafficSelectorAddressRangeInvalid);
        }
        let selector_len = TS_SELECTOR_HEADER_LEN
            .checked_add(address_len)
            .and_then(|len| len.checked_add(address_len))
            .ok_or(Ikev2IkeAuthBuildError::LengthOverflow)?;
        let selector_len_u16 =
            u16::try_from(selector_len).map_err(|_| Ikev2IkeAuthBuildError::LengthOverflow)?;
        out.push(selector.ts_type);
        out.push(selector.ip_protocol_id);
        out.extend_from_slice(&selector_len_u16.to_be_bytes());
        out.extend_from_slice(&selector.start_port.to_be_bytes());
        out.extend_from_slice(&selector.end_port.to_be_bytes());
        out.extend_from_slice(&selector.start_address);
        out.extend_from_slice(&selector.end_address);
    }
    Ok(out)
}

/// Build an SA payload body for an IKE_AUTH or CREATE_CHILD_SA cleartext chain.
///
/// # Errors
///
/// Returns [`Ikev2IkeAuthBuildError`] when the SA proposal builder is malformed
/// or exceeds IKEv2 size fields.
pub fn build_ike_auth_sa_payload(
    input: &Ikev2SaPayloadBuild,
) -> Result<Vec<u8>, Ikev2IkeAuthBuildError> {
    encode_sa_payload_build(input).map_err(Ikev2IkeAuthBuildError::SecurityAssociation)
}

/// Build a generic IKE_AUTH cleartext payload chain.
pub fn build_ike_auth_cleartext_payload_chain(
    entries: &[Ikev2IkeAuthPayloadBuild],
) -> Result<(PayloadType, Bytes), Ikev2IkeAuthBuildError> {
    let first = entries
        .first()
        .map(|entry| entry.payload_type)
        .ok_or(Ikev2IkeAuthBuildError::NoPayloads)?;
    let mut out = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        if entry.payload_type == PayloadType::NoNext
            || matches!(entry.payload_type, PayloadType::Unknown(_))
        {
            return Err(Ikev2IkeAuthBuildError::InvalidPayloadType);
        }
        let next_payload = entries
            .get(index + 1)
            .map(|next| next.payload_type)
            .unwrap_or(PayloadType::NoNext);
        let payload_len = GENERIC_PAYLOAD_HEADER_LEN
            .checked_add(entry.body.len())
            .ok_or(Ikev2IkeAuthBuildError::LengthOverflow)?;
        let payload_len_u16 =
            u16::try_from(payload_len).map_err(|_| Ikev2IkeAuthBuildError::LengthOverflow)?;
        out.push(next_payload.as_u8());
        out.push(0);
        out.extend_from_slice(&payload_len_u16.to_be_bytes());
        out.extend_from_slice(&entry.body);
    }
    Ok((first, Bytes::from(out)))
}

/// Product-neutral Child SA negotiation intent.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2ChildSaNegotiation {
    /// Selected SA proposal number.
    pub proposal_number: u8,
    /// Selected proposal protocol ID.
    pub protocol_id: u8,
    /// Initiator SPI from the selected proposal.
    pub initiator_spi: Vec<u8>,
    /// Selected transforms copied from the accepted proposal.
    pub transforms: Vec<Ikev2SaTransformBuild>,
    /// Selected initiator traffic selector.
    pub initiator_traffic_selector: Ikev2TrafficSelectorBuild,
    /// Selected responder traffic selector.
    pub responder_traffic_selector: Ikev2TrafficSelectorBuild,
}

impl fmt::Debug for Ikev2ChildSaNegotiation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2ChildSaNegotiation")
            .field("proposal_number", &self.proposal_number)
            .field("protocol_id", &self.protocol_id)
            .field("initiator_spi_len", &self.initiator_spi.len())
            .field("transform_count", &self.transforms.len())
            .field("transforms", &self.transforms)
            .field(
                "initiator_traffic_selector",
                &self.initiator_traffic_selector,
            )
            .field(
                "responder_traffic_selector",
                &self.responder_traffic_selector,
            )
            .finish()
    }
}

/// Product-neutral Child SA proposal policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ikev2ChildSaNegotiationPolicy {
    /// Accepted protocol IDs, for example ESP.
    pub accepted_protocol_ids: Vec<u8>,
    /// Required transform constraints. Every entry must match one selected
    /// transform in a proposal.
    pub required_transforms: Vec<Ikev2ChildSaTransformRequirement>,
    /// Accepted initiator traffic selectors. Empty means accept any offered TSi
    /// and select the first one.
    pub accepted_initiator_traffic_selectors: Vec<Ikev2TrafficSelectorBuild>,
    /// Accepted responder traffic selectors. Empty means accept any offered TSr
    /// and select the first one.
    pub accepted_responder_traffic_selectors: Vec<Ikev2TrafficSelectorBuild>,
}

/// One required Child SA transform constraint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ikev2ChildSaTransformRequirement {
    /// Required transform type.
    pub transform_type: u8,
    /// Accepted transform IDs for this type. Empty means any transform ID for
    /// the required type is acceptable.
    pub accepted_transform_ids: Vec<u16>,
}

/// Payload builders for a product-neutral Child SA response.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2ChildSaResponsePayloads {
    /// Response SA payload body entry.
    pub security_association: Ikev2IkeAuthPayloadBuild,
    /// Response TSi payload body entry.
    pub traffic_selectors_initiator: Ikev2IkeAuthPayloadBuild,
    /// Response TSr payload body entry.
    pub traffic_selectors_responder: Ikev2IkeAuthPayloadBuild,
}

impl fmt::Debug for Ikev2ChildSaResponsePayloads {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2ChildSaResponsePayloads")
            .field("security_association", &self.security_association)
            .field(
                "traffic_selectors_initiator",
                &self.traffic_selectors_initiator,
            )
            .field(
                "traffic_selectors_responder",
                &self.traffic_selectors_responder,
            )
            .finish()
    }
}

/// Payload builders for a Child-SA rekey CREATE_CHILD_SA request.
///
/// The fields are named by payload role. When building the protected
/// cleartext chain, the RFC 7296 order is `N(REKEY_SA), SA, Ni, [KEi], TSi,
/// TSr`.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2CreateChildSaRekeyRequestPayloads {
    /// REKEY_SA Notify payload body entry.
    pub rekey_notify: Ikev2IkeAuthPayloadBuild,
    /// Replacement SA proposal payload body entry.
    pub security_association: Ikev2IkeAuthPayloadBuild,
    /// Initiator Nonce payload body entry.
    pub nonce: Ikev2IkeAuthPayloadBuild,
    /// Optional initiator KE payload body entry for PFS.
    pub key_exchange: Option<Ikev2IkeAuthPayloadBuild>,
    /// TSi payload body entry.
    pub traffic_selectors_initiator: Ikev2IkeAuthPayloadBuild,
    /// TSr payload body entry.
    pub traffic_selectors_responder: Ikev2IkeAuthPayloadBuild,
}

impl Ikev2CreateChildSaRekeyRequestPayloads {
    /// Return payload entries in RFC 7296 CREATE_CHILD_SA request order.
    pub fn into_payloads(self) -> Vec<Ikev2IkeAuthPayloadBuild> {
        let mut payloads = Vec::with_capacity(if self.key_exchange.is_some() { 6 } else { 5 });
        payloads.push(self.rekey_notify);
        payloads.push(self.security_association);
        payloads.push(self.nonce);
        if let Some(key_exchange) = self.key_exchange {
            payloads.push(key_exchange);
        }
        payloads.push(self.traffic_selectors_initiator);
        payloads.push(self.traffic_selectors_responder);
        payloads
    }
}

impl fmt::Debug for Ikev2CreateChildSaRekeyRequestPayloads {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2CreateChildSaRekeyRequestPayloads")
            .field("rekey_notify", &self.rekey_notify)
            .field("security_association", &self.security_association)
            .field("nonce", &self.nonce)
            .field("key_exchange_present", &self.key_exchange.is_some())
            .field(
                "traffic_selectors_initiator",
                &self.traffic_selectors_initiator,
            )
            .field(
                "traffic_selectors_responder",
                &self.traffic_selectors_responder,
            )
            .finish()
    }
}

/// Payload builders for a Child-SA rekey CREATE_CHILD_SA response.
///
/// The RFC 7296 order is `SA, Nr, [KEr], TSi, TSr`.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2CreateChildSaRekeyResponsePayloads {
    /// Accepted SA payload body entry.
    pub security_association: Ikev2IkeAuthPayloadBuild,
    /// Responder Nonce payload body entry.
    pub nonce: Ikev2IkeAuthPayloadBuild,
    /// Optional responder KE payload body entry for PFS.
    pub key_exchange: Option<Ikev2IkeAuthPayloadBuild>,
    /// TSi payload body entry.
    pub traffic_selectors_initiator: Ikev2IkeAuthPayloadBuild,
    /// TSr payload body entry.
    pub traffic_selectors_responder: Ikev2IkeAuthPayloadBuild,
}

impl Ikev2CreateChildSaRekeyResponsePayloads {
    /// Return payload entries in RFC 7296 CREATE_CHILD_SA response order.
    pub fn into_payloads(self) -> Vec<Ikev2IkeAuthPayloadBuild> {
        let mut payloads = Vec::with_capacity(if self.key_exchange.is_some() { 5 } else { 4 });
        payloads.push(self.security_association);
        payloads.push(self.nonce);
        if let Some(key_exchange) = self.key_exchange {
            payloads.push(key_exchange);
        }
        payloads.push(self.traffic_selectors_initiator);
        payloads.push(self.traffic_selectors_responder);
        payloads
    }
}

impl fmt::Debug for Ikev2CreateChildSaRekeyResponsePayloads {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2CreateChildSaRekeyResponsePayloads")
            .field("security_association", &self.security_association)
            .field("nonce", &self.nonce)
            .field("key_exchange_present", &self.key_exchange.is_some())
            .field(
                "traffic_selectors_initiator",
                &self.traffic_selectors_initiator,
            )
            .field(
                "traffic_selectors_responder",
                &self.traffic_selectors_responder,
            )
            .finish()
    }
}

/// Select the first Child SA proposal and traffic selectors matching policy.
///
/// This helper deliberately stops at product-neutral negotiation intent. It does
/// not choose subscriber policy, allocate responder SPIs, or install XFRM state.
pub fn negotiate_child_sa(
    sa: &Ikev2SaPayload<'_>,
    tsi: &Ikev2TrafficSelectorPayload<'_>,
    tsr: &Ikev2TrafficSelectorPayload<'_>,
    policy: &Ikev2ChildSaNegotiationPolicy,
) -> Result<Ikev2ChildSaNegotiation, Ikev2ChildSaNegotiationError> {
    if policy.accepted_protocol_ids.is_empty() {
        return Err(Ikev2ChildSaNegotiationError::NoAcceptedProtocolIds);
    }
    validate_child_sa_transform_requirements(&policy.required_transforms)?;
    if tsi.selectors.is_empty() || tsr.selectors.is_empty() {
        return Err(Ikev2ChildSaNegotiationError::TrafficSelectorMissing);
    }

    let mut saw_accepted_protocol = false;
    let mut saw_transforms = false;
    let mut selected = None;
    for proposal in &sa.proposals {
        if !policy.accepted_protocol_ids.contains(&proposal.protocol_id) {
            continue;
        }
        saw_accepted_protocol = true;
        if proposal.transforms.is_empty() {
            continue;
        }
        saw_transforms = true;
        if let Some(transforms) =
            select_transforms_for_policy(proposal, &policy.required_transforms)
        {
            selected = Some((proposal, transforms));
            break;
        }
    }
    let (proposal, transforms) = match selected {
        Some(selection) => selection,
        None if !saw_accepted_protocol => {
            return Err(Ikev2ChildSaNegotiationError::NoSupportedProposal)
        }
        None if !saw_transforms => return Err(Ikev2ChildSaNegotiationError::NoTransforms),
        None => return Err(Ikev2ChildSaNegotiationError::NoSupportedProposal),
    };

    let initiator_traffic_selector =
        select_traffic_selector(&tsi.selectors, &policy.accepted_initiator_traffic_selectors)
            .ok_or(Ikev2ChildSaNegotiationError::TrafficSelectorMismatch)?;
    let responder_traffic_selector =
        select_traffic_selector(&tsr.selectors, &policy.accepted_responder_traffic_selectors)
            .ok_or(Ikev2ChildSaNegotiationError::TrafficSelectorMismatch)?;

    Ok(Ikev2ChildSaNegotiation {
        proposal_number: proposal.proposal_number,
        protocol_id: proposal.protocol_id,
        initiator_spi: proposal.spi.to_vec(),
        transforms,
        initiator_traffic_selector: traffic_selector_build_from_view(initiator_traffic_selector),
        responder_traffic_selector: traffic_selector_build_from_view(responder_traffic_selector),
    })
}

/// Build response SA/TS payload entries from negotiated Child SA intent.
///
/// `responder_spi` is supplied by the product-owned SPI allocator. The SDK uses
/// it only as opaque bytes in the response SA proposal.
///
/// # Errors
///
/// Returns [`Ikev2IkeAuthBuildError`] when the responder SPI or selected
/// payloads cannot be encoded.
pub fn build_child_sa_response_payloads(
    negotiation: &Ikev2ChildSaNegotiation,
    responder_spi: Vec<u8>,
) -> Result<Ikev2ChildSaResponsePayloads, Ikev2IkeAuthBuildError> {
    if responder_spi.is_empty() {
        return Err(Ikev2IkeAuthBuildError::ChildSaResponderSpiMissing);
    }
    let sa_body = build_ike_auth_sa_payload(&Ikev2SaPayloadBuild {
        proposals: vec![Ikev2SaProposalBuild {
            proposal_number: negotiation.proposal_number,
            protocol_id: negotiation.protocol_id,
            spi: responder_spi,
            transforms: negotiation.transforms.clone(),
        }],
    })?;
    let tsi_body = build_ike_auth_traffic_selector_payload(&Ikev2TrafficSelectorPayloadBuild {
        selectors: vec![negotiation.initiator_traffic_selector.clone()],
    })?;
    let tsr_body = build_ike_auth_traffic_selector_payload(&Ikev2TrafficSelectorPayloadBuild {
        selectors: vec![negotiation.responder_traffic_selector.clone()],
    })?;

    Ok(Ikev2ChildSaResponsePayloads {
        security_association: Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::SecurityAssociation,
            body: sa_body,
        },
        traffic_selectors_initiator: Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::TrafficSelectorInitiator,
            body: tsi_body,
        },
        traffic_selectors_responder: Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::TrafficSelectorResponder,
            body: tsr_body,
        },
    })
}

/// Build CREATE_CHILD_SA payload entries for rekeying an AH/ESP Child SA.
///
/// The returned entries are suitable for
/// [`build_ike_auth_cleartext_payload_chain`] and preserve the RFC 7296
/// request order `N(REKEY_SA), SA, Ni, [KEi], TSi, TSr`.
///
/// # Errors
///
/// Returns [`Ikev2IkeAuthBuildError`] when any payload cannot be encoded or the
/// REKEY_SA protocol/SPI shape is invalid.
pub fn build_create_child_sa_rekey_request_payloads(
    input: &Ikev2CreateChildSaRekeyRequestBuild,
) -> Result<Ikev2CreateChildSaRekeyRequestPayloads, Ikev2IkeAuthBuildError> {
    validate_rekey_child_sa_spi(input.rekeyed_protocol_id, &input.rekeyed_spi)?;

    let rekey_notify = build_ike_auth_notify_payload(&Ikev2NotifyPayloadBuild {
        protocol_id: input.rekeyed_protocol_id,
        spi: input.rekeyed_spi.clone(),
        notify_message_type: IKEV2_NOTIFY_REKEY_SA,
        notification_data: Vec::new(),
    })?;
    let sa_body = build_ike_auth_sa_payload(&input.security_association)?;
    let nonce_body =
        encode_nonce_payload_build(&input.nonce).map_err(Ikev2IkeAuthBuildError::Nonce)?;
    let key_exchange = input
        .key_exchange
        .as_ref()
        .map(|key_exchange| {
            encode_ke_payload_build(key_exchange)
                .map(|body| Ikev2IkeAuthPayloadBuild {
                    payload_type: PayloadType::KeyExchange,
                    body,
                })
                .map_err(Ikev2IkeAuthBuildError::KeyExchange)
        })
        .transpose()?;
    let tsi_body = build_ike_auth_traffic_selector_payload(&input.traffic_selectors_initiator)?;
    let tsr_body = build_ike_auth_traffic_selector_payload(&input.traffic_selectors_responder)?;

    Ok(Ikev2CreateChildSaRekeyRequestPayloads {
        rekey_notify: Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::Notify,
            body: rekey_notify,
        },
        security_association: Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::SecurityAssociation,
            body: sa_body,
        },
        nonce: Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::Nonce,
            body: nonce_body,
        },
        key_exchange,
        traffic_selectors_initiator: Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::TrafficSelectorInitiator,
            body: tsi_body,
        },
        traffic_selectors_responder: Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::TrafficSelectorResponder,
            body: tsr_body,
        },
    })
}

/// Build CREATE_CHILD_SA response payload entries for rekeying a Child SA.
///
/// The returned entries are suitable for
/// [`build_ike_auth_cleartext_payload_chain`] and preserve the RFC 7296
/// response order `SA, Nr, [KEr], TSi, TSr`.
///
/// # Errors
///
/// Returns [`Ikev2IkeAuthBuildError`] when any payload cannot be encoded.
pub fn build_create_child_sa_rekey_response_payloads(
    input: &Ikev2CreateChildSaRekeyResponseBuild,
) -> Result<Ikev2CreateChildSaRekeyResponsePayloads, Ikev2IkeAuthBuildError> {
    let sa_body = build_ike_auth_sa_payload(&input.security_association)?;
    let nonce_body =
        encode_nonce_payload_build(&input.nonce).map_err(Ikev2IkeAuthBuildError::Nonce)?;
    let key_exchange = input
        .key_exchange
        .as_ref()
        .map(|key_exchange| {
            encode_ke_payload_build(key_exchange)
                .map(|body| Ikev2IkeAuthPayloadBuild {
                    payload_type: PayloadType::KeyExchange,
                    body,
                })
                .map_err(Ikev2IkeAuthBuildError::KeyExchange)
        })
        .transpose()?;
    let tsi_body = build_ike_auth_traffic_selector_payload(&input.traffic_selectors_initiator)?;
    let tsr_body = build_ike_auth_traffic_selector_payload(&input.traffic_selectors_responder)?;

    Ok(Ikev2CreateChildSaRekeyResponsePayloads {
        security_association: Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::SecurityAssociation,
            body: sa_body,
        },
        nonce: Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::Nonce,
            body: nonce_body,
        },
        key_exchange,
        traffic_selectors_initiator: Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::TrafficSelectorInitiator,
            body: tsi_body,
        },
        traffic_selectors_responder: Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::TrafficSelectorResponder,
            body: tsr_body,
        },
    })
}

fn validate_rekey_child_sa_spi(protocol_id: u8, spi: &[u8]) -> Result<(), Ikev2IkeAuthBuildError> {
    match protocol_id {
        IKEV2_SECURITY_PROTOCOL_ID_AH | IKEV2_SECURITY_PROTOCOL_ID_ESP => {}
        _ => return Err(Ikev2IkeAuthBuildError::InvalidRekeyProtocolId),
    }
    if spi.len() != usize::from(IKEV2_IPSEC_SPI_SIZE) {
        return Err(Ikev2IkeAuthBuildError::RekeySpiLengthInvalid);
    }
    Ok(())
}

fn validate_child_sa_transform_requirements(
    requirements: &[Ikev2ChildSaTransformRequirement],
) -> Result<(), Ikev2ChildSaNegotiationError> {
    if requirements.is_empty() {
        return Err(Ikev2ChildSaNegotiationError::NoTransformRequirements);
    }
    for (index, requirement) in requirements.iter().enumerate() {
        if requirements[..index]
            .iter()
            .any(|seen| seen.transform_type == requirement.transform_type)
        {
            return Err(Ikev2ChildSaNegotiationError::DuplicateTransformRequirement);
        }
    }
    Ok(())
}

fn select_transforms_for_policy(
    proposal: &Ikev2SaProposal<'_>,
    requirements: &[Ikev2ChildSaTransformRequirement],
) -> Option<Vec<Ikev2SaTransformBuild>> {
    requirements
        .iter()
        .map(|requirement| {
            proposal
                .transforms
                .iter()
                .find(|transform| {
                    transform.transform_type == requirement.transform_type
                        && (requirement.accepted_transform_ids.is_empty()
                            || requirement
                                .accepted_transform_ids
                                .contains(&transform.transform_id))
                })
                .map(transform_build_from_view)
        })
        .collect()
}

fn select_traffic_selector<'a, 'b>(
    offered: &'b [Ikev2TrafficSelector<'a>],
    accepted: &[Ikev2TrafficSelectorBuild],
) -> Option<&'b Ikev2TrafficSelector<'a>> {
    if accepted.is_empty() {
        return offered.first();
    }
    offered.iter().find(|selector| {
        accepted
            .iter()
            .any(|candidate| traffic_selector_matches(selector, candidate))
    })
}

fn traffic_selector_matches(
    selector: &Ikev2TrafficSelector<'_>,
    candidate: &Ikev2TrafficSelectorBuild,
) -> bool {
    selector.ts_type == candidate.ts_type
        && selector.ip_protocol_id == candidate.ip_protocol_id
        && selector.start_port == candidate.start_port
        && selector.end_port == candidate.end_port
        && selector.start_address == candidate.start_address.as_slice()
        && selector.end_address == candidate.end_address.as_slice()
}

fn traffic_selector_build_from_view(
    selector: &Ikev2TrafficSelector<'_>,
) -> Ikev2TrafficSelectorBuild {
    Ikev2TrafficSelectorBuild {
        ts_type: selector.ts_type,
        ip_protocol_id: selector.ip_protocol_id,
        start_port: selector.start_port,
        end_port: selector.end_port,
        start_address: selector.start_address.to_vec(),
        end_address: selector.end_address.to_vec(),
    }
}

const fn expected_ts_address_len(ts_type: u8) -> Option<usize> {
    match ts_type {
        IKEV2_TS_IPV4_ADDR_RANGE => Some(TS_IPV4_ADDR_LEN),
        IKEV2_TS_IPV6_ADDR_RANGE => Some(TS_IPV6_ADDR_LEN),
        _ => None,
    }
}

fn transform_build_from_view(transform: &Ikev2SaTransform<'_>) -> Ikev2SaTransformBuild {
    Ikev2SaTransformBuild {
        transform_type: transform.transform_type,
        transform_id: transform.transform_id,
        attributes: transform
            .attributes
            .iter()
            .map(|attribute| Ikev2TransformAttributeBuild {
                attribute_type: attribute.attribute_type,
                value: match attribute.value {
                    Ikev2TransformAttributeValue::Tv(value) => {
                        Ikev2TransformAttributeBuildValue::Tv(value)
                    }
                    Ikev2TransformAttributeValue::Tlv(bytes) => {
                        Ikev2TransformAttributeBuildValue::Tlv(bytes.to_vec())
                    }
                },
            })
            .collect(),
    }
}

pub(crate) fn validate_signed_octets(
    signed_octets: Ikev2IkeAuthSignedOctets<'_>,
) -> Result<(), Ikev2IkeAuthVerificationError> {
    if signed_octets.ike_sa_init_message.is_empty() {
        return Err(Ikev2IkeAuthVerificationError::SaInitMessageEmpty);
    }
    if !(IKEV2_NONCE_MIN_LEN..=IKEV2_NONCE_MAX_LEN).contains(&signed_octets.peer_nonce.len()) {
        return Err(Ikev2IkeAuthVerificationError::NonceLengthInvalid {
            len: signed_octets.peer_nonce.len(),
        });
    }
    if signed_octets.identity_payload_body.len() < ID_FIXED_BODY_LEN {
        return Err(Ikev2IkeAuthVerificationError::IdentityPayloadTooShort);
    }
    if signed_octets.identity_payload_body[1..ID_FIXED_BODY_LEN]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(Ikev2IkeAuthVerificationError::ReservedNonZero);
    }
    if signed_octets.identity_payload_body[0] == 0 {
        return Err(Ikev2IkeAuthVerificationError::InvalidIdentificationType);
    }
    if signed_octets.identity_payload_body[ID_FIXED_BODY_LEN..].is_empty() {
        return Err(Ikev2IkeAuthVerificationError::IdentityDataEmpty);
    }
    Ok(())
}

pub(crate) fn build_signed_octets(
    prf: Ikev2PrfAlgorithm,
    key_material: &Ikev2SaInitKeyMaterial,
    signed_octets: Ikev2IkeAuthSignedOctets<'_>,
) -> Result<Zeroizing<Vec<u8>>, Ikev2IkeAuthVerificationError> {
    let macked_id = ike_auth_prf(
        prf,
        signed_octets.peer.sk_p(key_material),
        signed_octets.identity_payload_body,
    )?;
    let len = signed_octets
        .ike_sa_init_message
        .len()
        .checked_add(signed_octets.peer_nonce.len())
        .and_then(|value| value.checked_add(macked_id.len()))
        .ok_or(Ikev2IkeAuthVerificationError::LengthOverflow)?;
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    out.extend_from_slice(signed_octets.ike_sa_init_message);
    out.extend_from_slice(signed_octets.peer_nonce);
    out.extend_from_slice(&macked_id);
    Ok(out)
}

fn ike_auth_prf(
    algorithm: Ikev2PrfAlgorithm,
    key: &[u8],
    data: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Ikev2IkeAuthVerificationError> {
    if key.is_empty() {
        return Err(Ikev2IkeAuthVerificationError::PrfKeyEmpty);
    }
    match algorithm {
        Ikev2PrfAlgorithm::HmacSha2_256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(key)
                .map_err(|_| Ikev2IkeAuthVerificationError::PrfKeyInvalid { len: key.len() })?;
            mac.update(data);
            Ok(Zeroizing::new(mac.finalize().into_bytes().to_vec()))
        }
        Ikev2PrfAlgorithm::HmacSha2_384 => {
            let mut mac = Hmac::<Sha384>::new_from_slice(key)
                .map_err(|_| Ikev2IkeAuthVerificationError::PrfKeyInvalid { len: key.len() })?;
            mac.update(data);
            Ok(Zeroizing::new(mac.finalize().into_bytes().to_vec()))
        }
    }
}

/// Error returned while decoding an IKE_AUTH cleartext payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ikev2IkeAuthPayloadError {
    /// Payload type was not valid for the decoder.
    UnexpectedPayloadType,
    /// Generic payload-chain decode failed.
    PayloadDecode,
    /// Reserved bytes were not zero.
    ReservedNonZero,
    /// ID body ended before the fixed header.
    IdentificationTooShort,
    /// ID type was zero.
    InvalidIdentificationType,
    /// ID data was empty.
    IdentificationDataEmpty,
    /// AUTH body ended before the fixed header.
    AuthenticationTooShort,
    /// AUTH method was zero.
    InvalidAuthenticationMethod,
    /// AUTH data was empty.
    AuthenticationDataEmpty,
    /// CERT body ended before the Certificate Encoding octet.
    CertificateTooShort,
    /// CERT or CERTREQ Certificate Encoding was zero.
    InvalidCertificateEncoding,
    /// CERT Certificate Data was empty.
    CertificateDataEmpty,
    /// CERTREQ body ended before the Certificate Encoding octet.
    CertificateRequestTooShort,
    /// EAP packet was empty.
    EapPacketEmpty,
    /// CP body ended before the fixed header.
    ConfigurationTooShort,
    /// CP type was zero.
    InvalidConfigurationType,
    /// CP attribute ended before its fixed header.
    ConfigurationAttributeTooShort,
    /// CP attribute length exceeded the body.
    ConfigurationAttributeLengthExceedsBody,
    /// TS body ended before the fixed header.
    TrafficSelectorPayloadTooShort,
    /// TS payload had no selectors.
    TrafficSelectorMissing,
    /// TS selector ended before the fixed header.
    TrafficSelectorTooShort,
    /// TS selector length was shorter than the fixed header.
    TrafficSelectorLengthTooShort,
    /// TS selector length exceeded the payload body.
    TrafficSelectorLengthExceedsBody,
    /// TS selector type was not an IPv4 or IPv6 address range.
    TrafficSelectorTypeUnsupported,
    /// TS selector address length was not IPv4 or IPv6.
    TrafficSelectorAddressLengthInvalid,
    /// TS selector port range had start greater than end.
    TrafficSelectorPortRangeInvalid,
    /// TS selector address range had start greater than end.
    TrafficSelectorAddressRangeInvalid,
    /// TS selector count did not match the body.
    TrafficSelectorCountMismatch,
    /// Delete body ended before the fixed header.
    DeleteTooShort,
    /// Delete length arithmetic overflowed.
    DeleteLengthOverflow,
    /// Delete SPI length/count did not match the body.
    DeleteSpiLengthMismatch,
    /// SA payload decode failed.
    Sa(Ikev2SaPayloadError),
    /// Notify payload decode failed.
    Notify(Ikev2NotifyPayloadError),
}

impl Ikev2IkeAuthPayloadError {
    /// Stable machine-readable error code.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::UnexpectedPayloadType => "ike_auth_unexpected_payload_type",
            Self::PayloadDecode => "ike_auth_payload_decode_error",
            Self::ReservedNonZero => "ike_auth_reserved_non_zero",
            Self::IdentificationTooShort => "ike_auth_id_too_short",
            Self::InvalidIdentificationType => "ike_auth_id_invalid_type",
            Self::IdentificationDataEmpty => "ike_auth_id_data_empty",
            Self::AuthenticationTooShort => "ike_auth_auth_too_short",
            Self::InvalidAuthenticationMethod => "ike_auth_auth_invalid_method",
            Self::AuthenticationDataEmpty => "ike_auth_auth_data_empty",
            Self::CertificateTooShort => "ike_auth_cert_too_short",
            Self::InvalidCertificateEncoding => "ike_auth_cert_invalid_encoding",
            Self::CertificateDataEmpty => "ike_auth_cert_data_empty",
            Self::CertificateRequestTooShort => "ike_auth_certreq_too_short",
            Self::EapPacketEmpty => "ike_auth_eap_packet_empty",
            Self::ConfigurationTooShort => "ike_auth_cp_too_short",
            Self::InvalidConfigurationType => "ike_auth_cp_invalid_type",
            Self::ConfigurationAttributeTooShort => "ike_auth_cp_attribute_too_short",
            Self::ConfigurationAttributeLengthExceedsBody => {
                "ike_auth_cp_attribute_length_exceeds_body"
            }
            Self::TrafficSelectorPayloadTooShort => "ike_auth_ts_payload_too_short",
            Self::TrafficSelectorMissing => "ike_auth_ts_missing",
            Self::TrafficSelectorTooShort => "ike_auth_ts_too_short",
            Self::TrafficSelectorLengthTooShort => "ike_auth_ts_length_too_short",
            Self::TrafficSelectorLengthExceedsBody => "ike_auth_ts_length_exceeds_body",
            Self::TrafficSelectorTypeUnsupported => "ike_auth_ts_type_unsupported",
            Self::TrafficSelectorAddressLengthInvalid => "ike_auth_ts_address_length_invalid",
            Self::TrafficSelectorPortRangeInvalid => "ike_auth_ts_port_range_invalid",
            Self::TrafficSelectorAddressRangeInvalid => "ike_auth_ts_address_range_invalid",
            Self::TrafficSelectorCountMismatch => "ike_auth_ts_count_mismatch",
            Self::DeleteTooShort => "ike_auth_delete_too_short",
            Self::DeleteLengthOverflow => "ike_auth_delete_length_overflow",
            Self::DeleteSpiLengthMismatch => "ike_auth_delete_spi_length_mismatch",
            Self::Sa(_) => "ike_auth_sa_decode_error",
            Self::Notify(_) => "ike_auth_notify_decode_error",
        }
    }
}

impl fmt::Display for Ikev2IkeAuthPayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for Ikev2IkeAuthPayloadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Sa(error) => Some(error),
            Self::Notify(error) => Some(error),
            _ => None,
        }
    }
}

/// Error returned while building IKE_AUTH cleartext payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2IkeAuthBuildError {
    /// No payloads were supplied for the chain.
    NoPayloads,
    /// Payload type cannot be encoded in a concrete chain entry.
    InvalidPayloadType,
    /// Length exceeded IKEv2 16-bit payload length fields.
    LengthOverflow,
    /// ID type was zero.
    InvalidIdentificationType,
    /// ID data was empty.
    IdentificationDataEmpty,
    /// AUTH method was zero.
    InvalidAuthenticationMethod,
    /// AUTH data was empty.
    AuthenticationDataEmpty,
    /// CERT or CERTREQ Certificate Encoding was zero.
    InvalidCertificateEncoding,
    /// CERT Certificate Data was empty.
    CertificateDataEmpty,
    /// Notify SPI exceeded the one-octet SPI Size field.
    NotifySpiTooLong,
    /// Delete SPI exceeded the one-octet SPI Size field.
    DeleteSpiTooLong,
    /// Delete SPI count exceeded the two-octet Num of SPIs field.
    DeleteSpiCountTooLong,
    /// Delete SPI Size did not match at least one SPI length.
    DeleteSpiSizeMismatch,
    /// Delete payload had an unsupported protocol ID.
    DeleteProtocolIdUnsupported,
    /// IKE SA Delete carried a non-zero SPI Size or SPI list.
    DeleteIkeSaSpiInvalid,
    /// AH/ESP Delete did not carry the required 4-octet SPI Size.
    DeleteIpsecSpiSizeInvalid,
    /// AH/ESP Delete did not include any SPI values.
    DeleteSpiMissing,
    /// REKEY_SA Notify used a protocol ID other than AH or ESP.
    InvalidRekeyProtocolId,
    /// REKEY_SA Notify SPI was not the AH/ESP four-octet SPI.
    RekeySpiLengthInvalid,
    /// CP type was zero.
    InvalidConfigurationType,
    /// TS payload had no selectors.
    TrafficSelectorMissing,
    /// TS selector type was not an IPv4 or IPv6 address range.
    TrafficSelectorTypeUnsupported,
    /// TS address length was not matching IPv4 or IPv6.
    TrafficSelectorAddressLengthInvalid,
    /// TS selector port range had start greater than end.
    TrafficSelectorPortRangeInvalid,
    /// TS selector address range had start greater than end.
    TrafficSelectorAddressRangeInvalid,
    /// SA payload builder was malformed.
    SecurityAssociation(Ikev2SaInitBuildError),
    /// Nonce payload builder was malformed.
    Nonce(Ikev2SaInitBuildError),
    /// KE payload builder was malformed.
    KeyExchange(Ikev2SaInitBuildError),
    /// Child SA response builder was missing responder SPI bytes.
    ChildSaResponderSpiMissing,
}

impl Ikev2IkeAuthBuildError {
    /// Stable machine-readable error code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoPayloads => "ike_auth_build_no_payloads",
            Self::InvalidPayloadType => "ike_auth_build_invalid_payload_type",
            Self::LengthOverflow => "ike_auth_build_length_overflow",
            Self::InvalidIdentificationType => "ike_auth_build_id_invalid_type",
            Self::IdentificationDataEmpty => "ike_auth_build_id_data_empty",
            Self::InvalidAuthenticationMethod => "ike_auth_build_auth_invalid_method",
            Self::AuthenticationDataEmpty => "ike_auth_build_auth_data_empty",
            Self::InvalidCertificateEncoding => "ike_auth_build_cert_invalid_encoding",
            Self::CertificateDataEmpty => "ike_auth_build_cert_data_empty",
            Self::NotifySpiTooLong => "ike_auth_build_notify_spi_too_long",
            Self::DeleteSpiTooLong => "ike_auth_build_delete_spi_too_long",
            Self::DeleteSpiCountTooLong => "ike_auth_build_delete_spi_count_too_long",
            Self::DeleteSpiSizeMismatch => "ike_auth_build_delete_spi_size_mismatch",
            Self::DeleteProtocolIdUnsupported => "ike_auth_build_delete_protocol_id_unsupported",
            Self::DeleteIkeSaSpiInvalid => "ike_auth_build_delete_ike_sa_spi_invalid",
            Self::DeleteIpsecSpiSizeInvalid => "ike_auth_build_delete_ipsec_spi_size_invalid",
            Self::DeleteSpiMissing => "ike_auth_build_delete_spi_missing",
            Self::InvalidRekeyProtocolId => "ike_auth_build_rekey_protocol_id_invalid",
            Self::RekeySpiLengthInvalid => "ike_auth_build_rekey_spi_length_invalid",
            Self::InvalidConfigurationType => "ike_auth_build_cp_invalid_type",
            Self::TrafficSelectorMissing => "ike_auth_build_ts_missing",
            Self::TrafficSelectorTypeUnsupported => "ike_auth_build_ts_type_unsupported",
            Self::TrafficSelectorAddressLengthInvalid => "ike_auth_build_ts_address_length_invalid",
            Self::TrafficSelectorPortRangeInvalid => "ike_auth_build_ts_port_range_invalid",
            Self::TrafficSelectorAddressRangeInvalid => "ike_auth_build_ts_address_range_invalid",
            Self::SecurityAssociation(_) => "ike_auth_build_sa_payload",
            Self::Nonce(_) => "ike_auth_build_nonce_payload",
            Self::KeyExchange(_) => "ike_auth_build_ke_payload",
            Self::ChildSaResponderSpiMissing => "ike_auth_build_child_sa_responder_spi_missing",
        }
    }
}

impl fmt::Display for Ikev2IkeAuthBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for Ikev2IkeAuthBuildError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SecurityAssociation(error) => Some(error),
            Self::Nonce(error) => Some(error),
            Self::KeyExchange(error) => Some(error),
            _ => None,
        }
    }
}

/// Error returned while computing or verifying IKE_AUTH AUTH data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2IkeAuthVerificationError {
    /// The first IKE_SA_INIT transcript message was empty.
    SaInitMessageEmpty,
    /// The peer nonce length was outside the RFC 7296 range.
    NonceLengthInvalid {
        /// Supplied nonce length.
        len: usize,
    },
    /// Identity payload body ended before the fixed ID header.
    IdentityPayloadTooShort,
    /// Reserved bytes were not zero.
    ReservedNonZero,
    /// ID type was zero.
    InvalidIdentificationType,
    /// ID data was empty.
    IdentityDataEmpty,
    /// AUTH keying material was empty.
    AuthenticationKeyEmpty,
    /// PRF key was empty.
    PrfKeyEmpty,
    /// PRF key was rejected by the HMAC implementation.
    PrfKeyInvalid {
        /// Supplied key length.
        len: usize,
    },
    /// Length arithmetic overflowed while constructing signed octets.
    LengthOverflow,
    /// AUTH method is unsupported by this verifier.
    UnsupportedAuthenticationMethod {
        /// AUTH method from the payload.
        method: u8,
    },
    /// Received AUTH data length did not match the negotiated PRF output.
    AuthenticationDataLength {
        /// Expected AUTH data length.
        expected: usize,
        /// Actual AUTH data length.
        actual: usize,
    },
    /// AUTH data did not match the transcript-bound expected value.
    AuthenticationFailed,
    /// Signature AUTH data framing was malformed (RFC 7427 length prefix,
    /// AlgorithmIdentifier, or signature bytes).
    SignatureEncodingInvalid,
    /// Signature AlgorithmIdentifier is not supported by this verifier.
    SignatureAlgorithmUnsupported,
    /// Supplied key type does not match the AUTH method or signature algorithm.
    SignatureKeyMismatch,
    /// Producing the signature failed inside the signing backend.
    SignatureComputationFailed,
    /// Signature did not verify over the transcript-bound signed octets.
    SignatureVerificationFailed,
}

impl Ikev2IkeAuthVerificationError {
    /// Stable machine-readable error code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SaInitMessageEmpty => "ike_auth_verify_sa_init_message_empty",
            Self::NonceLengthInvalid { .. } => "ike_auth_verify_nonce_length_invalid",
            Self::IdentityPayloadTooShort => "ike_auth_verify_identity_payload_too_short",
            Self::ReservedNonZero => "ike_auth_verify_reserved_non_zero",
            Self::InvalidIdentificationType => "ike_auth_verify_identity_invalid_type",
            Self::IdentityDataEmpty => "ike_auth_verify_identity_data_empty",
            Self::AuthenticationKeyEmpty => "ike_auth_verify_auth_key_empty",
            Self::PrfKeyEmpty => "ike_auth_verify_prf_key_empty",
            Self::PrfKeyInvalid { .. } => "ike_auth_verify_prf_key_invalid",
            Self::LengthOverflow => "ike_auth_verify_length_overflow",
            Self::UnsupportedAuthenticationMethod { .. } => {
                "ike_auth_verify_unsupported_auth_method"
            }
            Self::AuthenticationDataLength { .. } => "ike_auth_verify_auth_data_length",
            Self::AuthenticationFailed => "ike_auth_verify_authentication_failed",
            Self::SignatureEncodingInvalid => "ike_auth_verify_signature_encoding_invalid",
            Self::SignatureAlgorithmUnsupported => {
                "ike_auth_verify_signature_algorithm_unsupported"
            }
            Self::SignatureKeyMismatch => "ike_auth_verify_signature_key_mismatch",
            Self::SignatureComputationFailed => "ike_auth_verify_signature_computation_failed",
            Self::SignatureVerificationFailed => "ike_auth_verify_signature_verification_failed",
        }
    }
}

impl fmt::Display for Ikev2IkeAuthVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for Ikev2IkeAuthVerificationError {}

/// Error returned while selecting a product-neutral Child SA proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2ChildSaNegotiationError {
    /// Policy has no accepted protocol IDs.
    NoAcceptedProtocolIds,
    /// Policy did not require any Child SA transforms.
    NoTransformRequirements,
    /// Policy repeated a Child SA transform type requirement.
    DuplicateTransformRequirement,
    /// No proposal had an accepted protocol ID.
    NoSupportedProposal,
    /// Selected proposal had no transforms.
    NoTransforms,
    /// TSi or TSr was empty.
    TrafficSelectorMissing,
    /// No offered TSi or TSr matched the supplied selector policy.
    TrafficSelectorMismatch,
}

impl Ikev2ChildSaNegotiationError {
    /// Stable machine-readable error code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoAcceptedProtocolIds => "ike_child_sa_no_accepted_protocol_ids",
            Self::NoTransformRequirements => "ike_child_sa_no_transform_requirements",
            Self::DuplicateTransformRequirement => "ike_child_sa_duplicate_transform_requirement",
            Self::NoSupportedProposal => "ike_child_sa_no_supported_proposal",
            Self::NoTransforms => "ike_child_sa_no_transforms",
            Self::TrafficSelectorMissing => "ike_child_sa_traffic_selector_missing",
            Self::TrafficSelectorMismatch => "ike_child_sa_traffic_selector_mismatch",
        }
    }
}

impl fmt::Display for Ikev2ChildSaNegotiationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for Ikev2ChildSaNegotiationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ike_auth_prf_returns_zeroizing_output() {
        let output: Zeroizing<Vec<u8>> =
            match ike_auth_prf(Ikev2PrfAlgorithm::HmacSha2_256, b"key", b"data") {
                Ok(output) => output,
                Err(error) => panic!("unexpected PRF error: {error:?}"),
            };

        assert_eq!(output.len(), Ikev2PrfAlgorithm::HmacSha2_256.output_len());
    }
}
