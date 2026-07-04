//! Typed cleartext IKE_SA_INIT payload views and builders.
//!
//! @spec IETF RFC7296 3.3, 3.4, 3.7, 3.9, 3.10, 3.12
//! @req REQ-IETF-RFC7296-SA-INIT-PAYLOADS-001

use std::{error::Error, fmt};

use bytes::Bytes;
use opc_protocol::{DecodeContext, DecodeError};

use crate::{
    header::{Header, HeaderFlags, EXCHANGE_TYPE_IKE_SA_INIT},
    message::{Message, OwnedMessage},
    notify::{Ikev2NotifyPayload, Ikev2NotifyPayloadError},
    payload::{PayloadType, RawPayload, GENERIC_PAYLOAD_HEADER_LEN},
    HEADER_LEN,
};

const PROPOSAL_HEADER_LEN: usize = 8;
const TRANSFORM_HEADER_LEN: usize = 8;
const TRANSFORM_ATTRIBUTE_HEADER_LEN: usize = 4;
const KE_FIXED_BODY_LEN: usize = 4;
const NOTIFY_FIXED_BODY_LEN: usize = 4;
const PROPOSAL_MORE: u8 = 2;
const TRANSFORM_MORE: u8 = 3;
const IKEV2_NONCE_MIN_LEN: usize = 16;
const IKEV2_NONCE_MAX_LEN: usize = 256;
const ATTRIBUTE_TYPE_MASK: u16 = 0x7fff;
const ATTRIBUTE_TV_FLAG: u16 = 0x8000;

/// Borrowed typed view of an IKEv2 Security Association payload.
///
/// `Debug` reports proposal and transform metadata but never raw SPI or
/// attribute bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2SaPayload<'a> {
    /// Decoded Proposal substructures.
    pub proposals: Vec<Ikev2SaProposal<'a>>,
}

impl<'a> Ikev2SaPayload<'a> {
    /// Decode a typed SA payload from a raw generic payload.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2SaPayloadError`] when the raw payload is not an SA
    /// payload or any Proposal/Transform substructure is malformed.
    pub fn decode(raw: RawPayload<'a>) -> Result<Self, Ikev2SaPayloadError> {
        if raw.payload_type != PayloadType::SecurityAssociation {
            return Err(Ikev2SaPayloadError::NotSaPayload);
        }
        Self::decode_body(raw.body)
    }

    /// Decode a typed SA payload from an SA body.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2SaPayloadError`] when Proposal/Transform substructures
    /// are malformed.
    pub fn decode_body(body: &'a [u8]) -> Result<Self, Ikev2SaPayloadError> {
        if body.is_empty() {
            return Err(Ikev2SaPayloadError::MissingProposal);
        }

        let mut proposals = Vec::new();
        let mut remaining = body;
        while !remaining.is_empty() {
            if remaining.len() < PROPOSAL_HEADER_LEN {
                return Err(Ikev2SaPayloadError::ProposalTooShort);
            }
            let last = remaining[0];
            if last != 0 && last != PROPOSAL_MORE {
                return Err(Ikev2SaPayloadError::InvalidProposalLastMarker);
            }
            let proposal_len = usize::from(u16::from_be_bytes([remaining[2], remaining[3]]));
            if proposal_len < PROPOSAL_HEADER_LEN {
                return Err(Ikev2SaPayloadError::ProposalLengthTooShort);
            }
            if proposal_len > remaining.len() {
                return Err(Ikev2SaPayloadError::ProposalLengthExceedsBody);
            }

            let proposal_body = &remaining[..proposal_len];
            let spi_size = usize::from(proposal_body[6]);
            let transform_count = usize::from(proposal_body[7]);
            if transform_count == 0 {
                return Err(Ikev2SaPayloadError::MissingTransform);
            }
            let spi_start = PROPOSAL_HEADER_LEN;
            let transform_start = spi_start
                .checked_add(spi_size)
                .ok_or(Ikev2SaPayloadError::ProposalLengthExceedsBody)?;
            if transform_start > proposal_body.len() {
                return Err(Ikev2SaPayloadError::ProposalSpiLengthExceedsBody);
            }
            let transforms = decode_transforms(&proposal_body[transform_start..], transform_count)?;
            proposals.push(Ikev2SaProposal {
                proposal_number: proposal_body[4],
                protocol_id: proposal_body[5],
                spi_size: proposal_body[6],
                spi: &proposal_body[spi_start..transform_start],
                transforms,
            });

            remaining = &remaining[proposal_len..];
            match (last, remaining.is_empty()) {
                (0, true) | (PROPOSAL_MORE, false) => {}
                (0, false) => return Err(Ikev2SaPayloadError::ProposalMarkedLastWithTrailingBytes),
                (PROPOSAL_MORE, true) => {
                    return Err(Ikev2SaPayloadError::ProposalMarkedMoreWithoutNext);
                }
                _ => return Err(Ikev2SaPayloadError::InvalidProposalLastMarker),
            }
        }

        Ok(Self { proposals })
    }
}

impl fmt::Debug for Ikev2SaPayload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2SaPayload")
            .field("proposal_count", &self.proposals.len())
            .field("proposals", &self.proposals)
            .finish()
    }
}

/// Borrowed typed view of one SA Proposal substructure.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2SaProposal<'a> {
    /// Proposal number.
    pub proposal_number: u8,
    /// Security Protocol ID.
    pub protocol_id: u8,
    /// SPI size in octets.
    pub spi_size: u8,
    /// Proposal SPI bytes.
    pub spi: &'a [u8],
    /// Decoded Transform substructures.
    pub transforms: Vec<Ikev2SaTransform<'a>>,
}

impl fmt::Debug for Ikev2SaProposal<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2SaProposal")
            .field("proposal_number", &self.proposal_number)
            .field("protocol_id", &self.protocol_id)
            .field("spi_size", &self.spi_size)
            .field("spi_len", &self.spi.len())
            .field("transform_count", &self.transforms.len())
            .field("transforms", &self.transforms)
            .finish()
    }
}

/// Borrowed typed view of one SA Transform substructure.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2SaTransform<'a> {
    /// Transform Type.
    pub transform_type: u8,
    /// Transform ID.
    pub transform_id: u16,
    /// Transform attributes.
    pub attributes: Vec<Ikev2TransformAttribute<'a>>,
}

impl fmt::Debug for Ikev2SaTransform<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2SaTransform")
            .field("transform_type", &self.transform_type)
            .field("transform_id", &self.transform_id)
            .field("attribute_count", &self.attributes.len())
            .field("attributes", &self.attributes)
            .finish()
    }
}

/// Borrowed typed view of one SA Transform attribute.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ikev2TransformAttribute<'a> {
    /// Attribute type with the TV/TLV flag removed.
    pub attribute_type: u16,
    /// Attribute value.
    pub value: Ikev2TransformAttributeValue<'a>,
}

impl fmt::Debug for Ikev2TransformAttribute<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("Ikev2TransformAttribute");
        debug.field("attribute_type", &self.attribute_type);
        match self.value {
            Ikev2TransformAttributeValue::Tv(value) => {
                debug.field("format", &"tv").field("value", &value);
            }
            Ikev2TransformAttributeValue::Tlv(bytes) => {
                debug
                    .field("format", &"tlv")
                    .field("value_len", &bytes.len());
            }
        }
        debug.finish()
    }
}

/// Transform attribute value format.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Ikev2TransformAttributeValue<'a> {
    /// Type-value format with a 16-bit value.
    Tv(u16),
    /// Type-length-value format with borrowed value bytes.
    Tlv(&'a [u8]),
}

impl fmt::Debug for Ikev2TransformAttributeValue<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tv(value) => f.debug_tuple("Tv").field(value).finish(),
            Self::Tlv(bytes) => f
                .debug_struct("Tlv")
                .field("value_len", &bytes.len())
                .finish(),
        }
    }
}

/// Error returned while decoding an SA payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2SaPayloadError {
    /// The raw generic payload type was not SA.
    NotSaPayload,
    /// SA body did not contain a Proposal.
    MissingProposal,
    /// Proposal substructure ended before the fixed header.
    ProposalTooShort,
    /// Proposal Last Substructure marker was not valid for IKEv2.
    InvalidProposalLastMarker,
    /// Proposal length was shorter than the fixed Proposal header.
    ProposalLengthTooShort,
    /// Proposal length exceeded the SA body.
    ProposalLengthExceedsBody,
    /// Proposal SPI Size exceeded the Proposal body.
    ProposalSpiLengthExceedsBody,
    /// Proposal had no Transform substructures.
    MissingTransform,
    /// Proposal was marked last but trailing bytes remained.
    ProposalMarkedLastWithTrailingBytes,
    /// Proposal was marked more but no next Proposal was present.
    ProposalMarkedMoreWithoutNext,
    /// Transform substructure ended before the fixed header.
    TransformTooShort,
    /// Transform Last Substructure marker was not valid for IKEv2.
    InvalidTransformLastMarker,
    /// Transform length was shorter than the fixed Transform header.
    TransformLengthTooShort,
    /// Transform length exceeded the Proposal body.
    TransformLengthExceedsBody,
    /// Transform count did not match the Proposal header.
    TransformCountMismatch,
    /// Transform was marked last before the Proposal transform count ended.
    TransformMarkedLastBeforeCount,
    /// Transform was marked more on the final counted transform.
    TransformMarkedMoreOnLastCount,
    /// Transform attribute ended before its fixed header.
    AttributeTooShort,
    /// TLV attribute length exceeded the Transform body.
    AttributeLengthExceedsBody,
}

impl Ikev2SaPayloadError {
    /// Stable machine-readable error code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotSaPayload => "ike_sa_init_sa_not_sa_payload",
            Self::MissingProposal => "ike_sa_init_sa_missing_proposal",
            Self::ProposalTooShort => "ike_sa_init_sa_proposal_too_short",
            Self::InvalidProposalLastMarker => "ike_sa_init_sa_invalid_proposal_last_marker",
            Self::ProposalLengthTooShort => "ike_sa_init_sa_proposal_length_too_short",
            Self::ProposalLengthExceedsBody => "ike_sa_init_sa_proposal_length_exceeds_body",
            Self::ProposalSpiLengthExceedsBody => "ike_sa_init_sa_proposal_spi_length_exceeds_body",
            Self::MissingTransform => "ike_sa_init_sa_missing_transform",
            Self::ProposalMarkedLastWithTrailingBytes => {
                "ike_sa_init_sa_proposal_marked_last_with_trailing_bytes"
            }
            Self::ProposalMarkedMoreWithoutNext => {
                "ike_sa_init_sa_proposal_marked_more_without_next"
            }
            Self::TransformTooShort => "ike_sa_init_sa_transform_too_short",
            Self::InvalidTransformLastMarker => "ike_sa_init_sa_invalid_transform_last_marker",
            Self::TransformLengthTooShort => "ike_sa_init_sa_transform_length_too_short",
            Self::TransformLengthExceedsBody => "ike_sa_init_sa_transform_length_exceeds_body",
            Self::TransformCountMismatch => "ike_sa_init_sa_transform_count_mismatch",
            Self::TransformMarkedLastBeforeCount => {
                "ike_sa_init_sa_transform_marked_last_before_count"
            }
            Self::TransformMarkedMoreOnLastCount => {
                "ike_sa_init_sa_transform_marked_more_on_last_count"
            }
            Self::AttributeTooShort => "ike_sa_init_sa_attribute_too_short",
            Self::AttributeLengthExceedsBody => "ike_sa_init_sa_attribute_length_exceeds_body",
        }
    }
}

impl fmt::Display for Ikev2SaPayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for Ikev2SaPayloadError {}

/// Borrowed typed view of an IKEv2 Key Exchange payload.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ikev2KeyExchangePayload<'a> {
    /// Diffie-Hellman Group number.
    pub dh_group: u16,
    /// Key Exchange data bytes.
    pub key_exchange_data: &'a [u8],
}

impl<'a> Ikev2KeyExchangePayload<'a> {
    /// Decode a typed KE payload from a raw generic payload.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2KeyExchangePayloadError`] when the raw payload is not KE
    /// or the KE body is malformed.
    pub fn decode(raw: RawPayload<'a>) -> Result<Self, Ikev2KeyExchangePayloadError> {
        if raw.payload_type != PayloadType::KeyExchange {
            return Err(Ikev2KeyExchangePayloadError::NotKeyExchangePayload);
        }
        Self::decode_body(raw.body)
    }

    /// Decode a typed KE payload from a KE body.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2KeyExchangePayloadError`] when the KE body is malformed.
    pub fn decode_body(body: &'a [u8]) -> Result<Self, Ikev2KeyExchangePayloadError> {
        if body.len() < KE_FIXED_BODY_LEN {
            return Err(Ikev2KeyExchangePayloadError::BodyTooShort);
        }
        let dh_group = u16::from_be_bytes([body[0], body[1]]);
        if dh_group == 0 {
            return Err(Ikev2KeyExchangePayloadError::InvalidDhGroup);
        }
        if body[2] != 0 || body[3] != 0 {
            return Err(Ikev2KeyExchangePayloadError::ReservedNonZero);
        }
        let key_exchange_data = &body[KE_FIXED_BODY_LEN..];
        if key_exchange_data.is_empty() {
            return Err(Ikev2KeyExchangePayloadError::EmptyKeyExchangeData);
        }
        Ok(Self {
            dh_group,
            key_exchange_data,
        })
    }
}

impl fmt::Debug for Ikev2KeyExchangePayload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2KeyExchangePayload")
            .field("dh_group", &self.dh_group)
            .field("key_exchange_data_len", &self.key_exchange_data.len())
            .finish()
    }
}

/// Error returned while decoding a KE payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2KeyExchangePayloadError {
    /// The raw generic payload type was not KE.
    NotKeyExchangePayload,
    /// KE body ended before group and reserved fields.
    BodyTooShort,
    /// DH Group was zero.
    InvalidDhGroup,
    /// Reserved field was not zero.
    ReservedNonZero,
    /// KE data was empty.
    EmptyKeyExchangeData,
}

impl Ikev2KeyExchangePayloadError {
    /// Stable machine-readable error code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotKeyExchangePayload => "ike_sa_init_ke_not_ke_payload",
            Self::BodyTooShort => "ike_sa_init_ke_body_too_short",
            Self::InvalidDhGroup => "ike_sa_init_ke_invalid_dh_group",
            Self::ReservedNonZero => "ike_sa_init_ke_reserved_non_zero",
            Self::EmptyKeyExchangeData => "ike_sa_init_ke_empty_key_exchange_data",
        }
    }
}

impl fmt::Display for Ikev2KeyExchangePayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for Ikev2KeyExchangePayloadError {}

/// Borrowed typed view of an IKEv2 Nonce payload.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ikev2NoncePayload<'a> {
    /// Nonce bytes.
    pub nonce: &'a [u8],
}

impl<'a> Ikev2NoncePayload<'a> {
    /// Decode a typed Nonce payload from a raw generic payload.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2NoncePayloadError`] when the raw payload is not Nonce or
    /// the Nonce length is outside the RFC 7296 range.
    pub fn decode(raw: RawPayload<'a>) -> Result<Self, Ikev2NoncePayloadError> {
        if raw.payload_type != PayloadType::Nonce {
            return Err(Ikev2NoncePayloadError::NotNoncePayload);
        }
        Self::decode_body(raw.body)
    }

    /// Decode a typed Nonce payload from a Nonce body.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2NoncePayloadError`] when the Nonce length is outside the
    /// RFC 7296 range.
    pub fn decode_body(body: &'a [u8]) -> Result<Self, Ikev2NoncePayloadError> {
        validate_nonce_len(body.len())?;
        Ok(Self { nonce: body })
    }
}

impl fmt::Debug for Ikev2NoncePayload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2NoncePayload")
            .field("nonce_len", &self.nonce.len())
            .finish()
    }
}

/// Error returned while decoding a Nonce payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2NoncePayloadError {
    /// The raw generic payload type was not Nonce.
    NotNoncePayload,
    /// Nonce was shorter than 16 octets.
    NonceTooShort,
    /// Nonce was longer than 256 octets.
    NonceTooLong,
}

impl Ikev2NoncePayloadError {
    /// Stable machine-readable error code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotNoncePayload => "ike_sa_init_nonce_not_nonce_payload",
            Self::NonceTooShort => "ike_sa_init_nonce_too_short",
            Self::NonceTooLong => "ike_sa_init_nonce_too_long",
        }
    }
}

impl fmt::Display for Ikev2NoncePayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for Ikev2NoncePayloadError {}

/// Borrowed typed view of an IKEv2 Vendor ID payload.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ikev2VendorIdPayload<'a> {
    /// Vendor ID bytes.
    pub vendor_id: &'a [u8],
}

impl<'a> Ikev2VendorIdPayload<'a> {
    /// Decode a typed Vendor ID payload from a raw generic payload.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2VendorIdPayloadError`] when the raw payload is not Vendor
    /// ID.
    pub fn decode(raw: RawPayload<'a>) -> Result<Self, Ikev2VendorIdPayloadError> {
        if raw.payload_type != PayloadType::VendorId {
            return Err(Ikev2VendorIdPayloadError::NotVendorIdPayload);
        }
        Ok(Self {
            vendor_id: raw.body,
        })
    }
}

impl fmt::Debug for Ikev2VendorIdPayload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2VendorIdPayload")
            .field("vendor_id_len", &self.vendor_id.len())
            .finish()
    }
}

/// Error returned while decoding a Vendor ID payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2VendorIdPayloadError {
    /// The raw generic payload type was not Vendor ID.
    NotVendorIdPayload,
}

impl Ikev2VendorIdPayloadError {
    /// Stable machine-readable error code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotVendorIdPayload => "ike_sa_init_vendor_id_not_vendor_id_payload",
        }
    }
}

impl fmt::Display for Ikev2VendorIdPayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for Ikev2VendorIdPayloadError {}

/// Typed cleartext payload projection for an IKE_SA_INIT request.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2SaInitPayloads<'a> {
    /// Required SA payload.
    pub security_association: Ikev2SaPayload<'a>,
    /// Required KE payload.
    pub key_exchange: Ikev2KeyExchangePayload<'a>,
    /// Required Nonce payload.
    pub nonce: Ikev2NoncePayload<'a>,
    /// Optional Notify payloads.
    pub notifies: Vec<Ikev2NotifyPayload<'a>>,
    /// Optional Vendor ID payloads.
    pub vendor_ids: Vec<Ikev2VendorIdPayload<'a>>,
    /// Count of other non-critical payloads preserved by raw payload type.
    pub other_payload_count: usize,
}

impl fmt::Debug for Ikev2SaInitPayloads<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2SaInitPayloads")
            .field("security_association", &self.security_association)
            .field("key_exchange", &self.key_exchange)
            .field("nonce", &self.nonce)
            .field("notify_count", &self.notifies.len())
            .field("vendor_id_count", &self.vendor_ids.len())
            .field("other_payload_count", &self.other_payload_count)
            .finish()
    }
}

/// Error returned while projecting IKE_SA_INIT request payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ikev2SaInitPayloadError {
    /// Message exchange type was not IKE_SA_INIT.
    NotIkeSaInit,
    /// Message was a response, not an initiator request.
    ResponseMessage,
    /// IKE_SA_INIT request Message ID was not zero.
    MessageIdNonZero,
    /// IKE_SA_INIT request carried a non-zero responder SPI.
    ResponderSpiNonZero,
    /// The generic payload chain could not be walked.
    PayloadDecode(DecodeError),
    /// Required SA payload was missing.
    MissingSecurityAssociation,
    /// Required KE payload was missing.
    MissingKeyExchange,
    /// Required Nonce payload was missing.
    MissingNonce,
    /// More than one SA payload was present.
    DuplicateSecurityAssociation,
    /// More than one KE payload was present.
    DuplicateKeyExchange,
    /// More than one Nonce payload was present.
    DuplicateNonce,
    /// SA payload body was malformed.
    SecurityAssociation(Ikev2SaPayloadError),
    /// KE payload body was malformed.
    KeyExchange(Ikev2KeyExchangePayloadError),
    /// Nonce payload body was malformed.
    Nonce(Ikev2NoncePayloadError),
    /// Notify payload body was malformed.
    Notify(Ikev2NotifyPayloadError),
}

impl Ikev2SaInitPayloadError {
    /// Stable machine-readable error code.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NotIkeSaInit => "ike_sa_init_payloads_not_ike_sa_init",
            Self::ResponseMessage => "ike_sa_init_payloads_response_message",
            Self::MessageIdNonZero => "ike_sa_init_payloads_message_id_non_zero",
            Self::ResponderSpiNonZero => "ike_sa_init_payloads_responder_spi_non_zero",
            Self::PayloadDecode(_) => "ike_sa_init_payloads_payload_decode_error",
            Self::MissingSecurityAssociation => "ike_sa_init_payloads_missing_sa",
            Self::MissingKeyExchange => "ike_sa_init_payloads_missing_ke",
            Self::MissingNonce => "ike_sa_init_payloads_missing_nonce",
            Self::DuplicateSecurityAssociation => "ike_sa_init_payloads_duplicate_sa",
            Self::DuplicateKeyExchange => "ike_sa_init_payloads_duplicate_ke",
            Self::DuplicateNonce => "ike_sa_init_payloads_duplicate_nonce",
            Self::SecurityAssociation(_) => "ike_sa_init_payloads_sa_decode_error",
            Self::KeyExchange(_) => "ike_sa_init_payloads_ke_decode_error",
            Self::Nonce(_) => "ike_sa_init_payloads_nonce_decode_error",
            Self::Notify(_) => "ike_sa_init_payloads_notify_decode_error",
        }
    }
}

impl fmt::Display for Ikev2SaInitPayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for Ikev2SaInitPayloadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::PayloadDecode(error) => Some(error),
            Self::SecurityAssociation(error) => Some(error),
            Self::KeyExchange(error) => Some(error),
            Self::Nonce(error) => Some(error),
            Self::Notify(error) => Some(error),
            _ => None,
        }
    }
}

/// Decode required and supported optional cleartext payloads from an
/// IKE_SA_INIT request.
///
/// # Errors
///
/// Returns [`Ikev2SaInitPayloadError`] when the message is not a valid
/// IKE_SA_INIT request shape, required payloads are missing/duplicated, or a
/// supported payload body is structurally malformed.
pub fn decode_ike_sa_init_request_payloads<'a>(
    message: &Message<'a>,
    ctx: DecodeContext,
) -> Result<Ikev2SaInitPayloads<'a>, Ikev2SaInitPayloadError> {
    validate_sa_init_request_header(&message.header)?;

    let mut security_association = None;
    let mut key_exchange = None;
    let mut nonce = None;
    let mut notifies = Vec::new();
    let mut vendor_ids = Vec::new();
    let mut other_payload_count = 0;

    for raw in message.payloads_with_context(ctx) {
        let raw = raw.map_err(Ikev2SaInitPayloadError::PayloadDecode)?;
        match raw.payload_type {
            PayloadType::SecurityAssociation => {
                if security_association.is_some() {
                    return Err(Ikev2SaInitPayloadError::DuplicateSecurityAssociation);
                }
                security_association = Some(
                    Ikev2SaPayload::decode(raw)
                        .map_err(Ikev2SaInitPayloadError::SecurityAssociation)?,
                );
            }
            PayloadType::KeyExchange => {
                if key_exchange.is_some() {
                    return Err(Ikev2SaInitPayloadError::DuplicateKeyExchange);
                }
                key_exchange = Some(
                    Ikev2KeyExchangePayload::decode(raw)
                        .map_err(Ikev2SaInitPayloadError::KeyExchange)?,
                );
            }
            PayloadType::Nonce => {
                if nonce.is_some() {
                    return Err(Ikev2SaInitPayloadError::DuplicateNonce);
                }
                nonce =
                    Some(Ikev2NoncePayload::decode(raw).map_err(Ikev2SaInitPayloadError::Nonce)?);
            }
            PayloadType::Notify => {
                notifies.push(
                    Ikev2NotifyPayload::decode(raw).map_err(Ikev2SaInitPayloadError::Notify)?,
                );
            }
            PayloadType::VendorId => vendor_ids.push(Ikev2VendorIdPayload {
                vendor_id: raw.body,
            }),
            _ => other_payload_count += 1,
        }
    }

    Ok(Ikev2SaInitPayloads {
        security_association: security_association
            .ok_or(Ikev2SaInitPayloadError::MissingSecurityAssociation)?,
        key_exchange: key_exchange.ok_or(Ikev2SaInitPayloadError::MissingKeyExchange)?,
        nonce: nonce.ok_or(Ikev2SaInitPayloadError::MissingNonce)?,
        notifies,
        vendor_ids,
        other_payload_count,
    })
}

/// Owned SA payload builder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ikev2SaPayloadBuild {
    /// Proposal substructures.
    pub proposals: Vec<Ikev2SaProposalBuild>,
}

/// Owned SA Proposal builder.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2SaProposalBuild {
    /// Proposal number.
    pub proposal_number: u8,
    /// Security Protocol ID.
    pub protocol_id: u8,
    /// Proposal SPI bytes.
    pub spi: Vec<u8>,
    /// Transform substructures.
    pub transforms: Vec<Ikev2SaTransformBuild>,
}

impl fmt::Debug for Ikev2SaProposalBuild {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2SaProposalBuild")
            .field("proposal_number", &self.proposal_number)
            .field("protocol_id", &self.protocol_id)
            .field("spi_len", &self.spi.len())
            .field("transform_count", &self.transforms.len())
            .field("transforms", &self.transforms)
            .finish()
    }
}

/// Owned SA Transform builder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ikev2SaTransformBuild {
    /// Transform Type.
    pub transform_type: u8,
    /// Transform ID.
    pub transform_id: u16,
    /// Transform attributes.
    pub attributes: Vec<Ikev2TransformAttributeBuild>,
}

/// Owned SA Transform attribute builder.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2TransformAttributeBuild {
    /// Attribute type without the TV/TLV flag.
    pub attribute_type: u16,
    /// Attribute value.
    pub value: Ikev2TransformAttributeBuildValue,
}

impl fmt::Debug for Ikev2TransformAttributeBuild {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2TransformAttributeBuild")
            .field("attribute_type", &self.attribute_type)
            .field("value", &self.value)
            .finish()
    }
}

/// Owned SA Transform attribute value builder.
#[derive(Clone, PartialEq, Eq)]
pub enum Ikev2TransformAttributeBuildValue {
    /// Type-value format with a 16-bit value.
    Tv(u16),
    /// Type-length-value format with owned value bytes.
    Tlv(Vec<u8>),
}

impl fmt::Debug for Ikev2TransformAttributeBuildValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tv(value) => f.debug_tuple("Tv").field(value).finish(),
            Self::Tlv(bytes) => f
                .debug_struct("Tlv")
                .field("value_len", &bytes.len())
                .finish(),
        }
    }
}

/// Owned KE payload builder.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2KeyExchangePayloadBuild {
    /// Diffie-Hellman Group number.
    pub dh_group: u16,
    /// Key Exchange data bytes.
    pub key_exchange_data: Vec<u8>,
}

impl fmt::Debug for Ikev2KeyExchangePayloadBuild {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2KeyExchangePayloadBuild")
            .field("dh_group", &self.dh_group)
            .field("key_exchange_data_len", &self.key_exchange_data.len())
            .finish()
    }
}

/// Owned Nonce payload builder.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2NoncePayloadBuild {
    /// Nonce bytes.
    pub nonce: Vec<u8>,
}

impl fmt::Debug for Ikev2NoncePayloadBuild {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2NoncePayloadBuild")
            .field("nonce_len", &self.nonce.len())
            .finish()
    }
}

/// Owned Notify payload builder.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2NotifyPayloadBuild {
    /// Security Protocol ID.
    pub protocol_id: u8,
    /// SPI bytes.
    pub spi: Vec<u8>,
    /// Notify Message Type.
    pub notify_message_type: u16,
    /// Notification data bytes.
    pub notification_data: Vec<u8>,
}

impl fmt::Debug for Ikev2NotifyPayloadBuild {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2NotifyPayloadBuild")
            .field("protocol_id", &self.protocol_id)
            .field("spi_len", &self.spi.len())
            .field("notify_message_type", &self.notify_message_type)
            .field("notification_data_len", &self.notification_data.len())
            .finish()
    }
}

/// IKE_SA_INIT response cleartext payload builder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ikev2SaInitResponsePayloads {
    /// Required response SA payload.
    pub security_association: Ikev2SaPayloadBuild,
    /// Required response KE payload.
    pub key_exchange: Ikev2KeyExchangePayloadBuild,
    /// Required response Nonce payload.
    pub nonce: Ikev2NoncePayloadBuild,
    /// Optional response Notify payloads appended after Nonce.
    pub notifies: Vec<Ikev2NotifyPayloadBuild>,
}

/// Error returned while building typed IKE_SA_INIT payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2SaInitBuildError {
    /// Input header was not IKE_SA_INIT.
    NotIkeSaInit,
    /// Input header was already a response.
    ResponseHeader,
    /// IKE_SA_INIT request Message ID was not zero.
    MessageIdNonZero,
    /// IKE_SA_INIT request carried a non-zero responder SPI.
    ResponderSpiNonZero,
    /// Caller supplied a zero responder SPI for the response.
    MissingResponderSpi,
    /// SA builder had no Proposal substructures.
    MissingProposal,
    /// Proposal number was zero.
    InvalidProposalNumber,
    /// Proposal Protocol ID was zero.
    InvalidProposalProtocolId,
    /// Proposal SPI was too long for the SPI Size field.
    ProposalSpiTooLong,
    /// Proposal had no Transform substructures.
    MissingTransform,
    /// Transform Type was zero.
    InvalidTransformType,
    /// Attribute type exceeded the 15-bit IKEv2 attribute type field.
    AttributeTypeTooLarge,
    /// KE DH Group was zero.
    InvalidDhGroup,
    /// KE data was empty.
    EmptyKeyExchangeData,
    /// Nonce was shorter than 16 octets.
    NonceTooShort,
    /// Nonce was longer than 256 octets.
    NonceTooLong,
    /// Notify SPI was too long for the SPI Size field.
    NotifySpiTooLong,
    /// Payload, substructure, or message length overflowed IKEv2 fields.
    LengthOverflow,
}

impl Ikev2SaInitBuildError {
    /// Stable machine-readable error code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotIkeSaInit => "ike_sa_init_build_not_ike_sa_init",
            Self::ResponseHeader => "ike_sa_init_build_from_response_header",
            Self::MessageIdNonZero => "ike_sa_init_build_message_id_non_zero",
            Self::ResponderSpiNonZero => "ike_sa_init_build_request_responder_spi_non_zero",
            Self::MissingResponderSpi => "ike_sa_init_build_missing_responder_spi",
            Self::MissingProposal => "ike_sa_init_build_missing_proposal",
            Self::InvalidProposalNumber => "ike_sa_init_build_invalid_proposal_number",
            Self::InvalidProposalProtocolId => "ike_sa_init_build_invalid_proposal_protocol_id",
            Self::ProposalSpiTooLong => "ike_sa_init_build_proposal_spi_too_long",
            Self::MissingTransform => "ike_sa_init_build_missing_transform",
            Self::InvalidTransformType => "ike_sa_init_build_invalid_transform_type",
            Self::AttributeTypeTooLarge => "ike_sa_init_build_attribute_type_too_large",
            Self::InvalidDhGroup => "ike_sa_init_build_invalid_dh_group",
            Self::EmptyKeyExchangeData => "ike_sa_init_build_empty_key_exchange_data",
            Self::NonceTooShort => "ike_sa_init_build_nonce_too_short",
            Self::NonceTooLong => "ike_sa_init_build_nonce_too_long",
            Self::NotifySpiTooLong => "ike_sa_init_build_notify_spi_too_long",
            Self::LengthOverflow => "ike_sa_init_build_length_overflow",
        }
    }
}

impl fmt::Display for Ikev2SaInitBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for Ikev2SaInitBuildError {}

/// Build an IKE_SA_INIT response containing SA, KE, Nonce, and optional Notify
/// payloads with canonical generic-payload chaining.
///
/// # Errors
///
/// Returns [`Ikev2SaInitBuildError`] when the request header is not an initial
/// IKE_SA_INIT request or any supplied typed payload exceeds IKEv2 size fields.
pub fn build_ike_sa_init_response(
    request_header: &Header,
    responder_spi: u64,
    payloads: &Ikev2SaInitResponsePayloads,
) -> Result<OwnedMessage, Ikev2SaInitBuildError> {
    validate_response_request_header(request_header)?;
    if responder_spi == 0 {
        return Err(Ikev2SaInitBuildError::MissingResponderSpi);
    }

    let mut entries = Vec::with_capacity(3 + payloads.notifies.len());
    entries.push((
        PayloadType::SecurityAssociation,
        encode_sa_payload_build(&payloads.security_association)?,
    ));
    entries.push((
        PayloadType::KeyExchange,
        encode_ke_payload_build(&payloads.key_exchange)?,
    ));
    entries.push((
        PayloadType::Nonce,
        encode_nonce_payload_build(&payloads.nonce)?,
    ));
    for notify in &payloads.notifies {
        entries.push((PayloadType::Notify, encode_notify_payload_build(notify)?));
    }

    let (first_payload, raw_payloads) = encode_payload_chain(&entries)?;
    let total_len = HEADER_LEN
        .checked_add(raw_payloads.len())
        .ok_or(Ikev2SaInitBuildError::LengthOverflow)?;
    let total_len_u32 =
        u32::try_from(total_len).map_err(|_| Ikev2SaInitBuildError::LengthOverflow)?;
    let mut header = Header::new(
        request_header.initiator_spi,
        responder_spi,
        first_payload,
        EXCHANGE_TYPE_IKE_SA_INIT,
        // RFC 7296 §3.1: the responder MUST clear the Initiator flag in its
        // messages, so the response never inherits the request's I bit.
        HeaderFlags::from_bits(false, true, false),
        request_header.message_id,
    );
    header.length = total_len_u32;

    Ok(OwnedMessage {
        header,
        raw_payloads: Bytes::from(raw_payloads),
    })
}

fn decode_transforms<'a>(
    mut remaining: &'a [u8],
    expected_count: usize,
) -> Result<Vec<Ikev2SaTransform<'a>>, Ikev2SaPayloadError> {
    let mut transforms = Vec::with_capacity(expected_count);
    for index in 0..expected_count {
        if remaining.len() < TRANSFORM_HEADER_LEN {
            return Err(Ikev2SaPayloadError::TransformTooShort);
        }
        let last = remaining[0];
        if last != 0 && last != TRANSFORM_MORE {
            return Err(Ikev2SaPayloadError::InvalidTransformLastMarker);
        }
        let transform_len = usize::from(u16::from_be_bytes([remaining[2], remaining[3]]));
        if transform_len < TRANSFORM_HEADER_LEN {
            return Err(Ikev2SaPayloadError::TransformLengthTooShort);
        }
        if transform_len > remaining.len() {
            return Err(Ikev2SaPayloadError::TransformLengthExceedsBody);
        }

        let transform = &remaining[..transform_len];
        let attributes = decode_transform_attributes(&transform[TRANSFORM_HEADER_LEN..])?;
        transforms.push(Ikev2SaTransform {
            transform_type: transform[4],
            transform_id: u16::from_be_bytes([transform[6], transform[7]]),
            attributes,
        });
        remaining = &remaining[transform_len..];

        let is_final_count = index + 1 == expected_count;
        match (last, is_final_count) {
            (0, true) | (TRANSFORM_MORE, false) => {}
            (0, false) => return Err(Ikev2SaPayloadError::TransformMarkedLastBeforeCount),
            (TRANSFORM_MORE, true) => {
                return Err(Ikev2SaPayloadError::TransformMarkedMoreOnLastCount)
            }
            _ => return Err(Ikev2SaPayloadError::InvalidTransformLastMarker),
        }
    }

    if !remaining.is_empty() {
        return Err(Ikev2SaPayloadError::TransformCountMismatch);
    }
    Ok(transforms)
}

fn decode_transform_attributes<'a>(
    mut remaining: &'a [u8],
) -> Result<Vec<Ikev2TransformAttribute<'a>>, Ikev2SaPayloadError> {
    let mut attributes = Vec::new();
    while !remaining.is_empty() {
        if remaining.len() < TRANSFORM_ATTRIBUTE_HEADER_LEN {
            return Err(Ikev2SaPayloadError::AttributeTooShort);
        }
        let raw_type = u16::from_be_bytes([remaining[0], remaining[1]]);
        let attribute_type = raw_type & ATTRIBUTE_TYPE_MASK;
        if (raw_type & ATTRIBUTE_TV_FLAG) != 0 {
            let value = u16::from_be_bytes([remaining[2], remaining[3]]);
            attributes.push(Ikev2TransformAttribute {
                attribute_type,
                value: Ikev2TransformAttributeValue::Tv(value),
            });
            remaining = &remaining[TRANSFORM_ATTRIBUTE_HEADER_LEN..];
        } else {
            let len = usize::from(u16::from_be_bytes([remaining[2], remaining[3]]));
            let value_start = TRANSFORM_ATTRIBUTE_HEADER_LEN;
            let value_end = value_start
                .checked_add(len)
                .ok_or(Ikev2SaPayloadError::AttributeLengthExceedsBody)?;
            if value_end > remaining.len() {
                return Err(Ikev2SaPayloadError::AttributeLengthExceedsBody);
            }
            attributes.push(Ikev2TransformAttribute {
                attribute_type,
                value: Ikev2TransformAttributeValue::Tlv(&remaining[value_start..value_end]),
            });
            remaining = &remaining[value_end..];
        }
    }
    Ok(attributes)
}

pub(crate) fn encode_sa_payload_build(
    payload: &Ikev2SaPayloadBuild,
) -> Result<Vec<u8>, Ikev2SaInitBuildError> {
    if payload.proposals.is_empty() {
        return Err(Ikev2SaInitBuildError::MissingProposal);
    }
    let mut out = Vec::new();
    for (index, proposal) in payload.proposals.iter().enumerate() {
        encode_proposal_build(&mut out, proposal, index + 1 == payload.proposals.len())?;
    }
    Ok(out)
}

fn encode_proposal_build(
    out: &mut Vec<u8>,
    proposal: &Ikev2SaProposalBuild,
    is_last: bool,
) -> Result<(), Ikev2SaInitBuildError> {
    if proposal.proposal_number == 0 {
        return Err(Ikev2SaInitBuildError::InvalidProposalNumber);
    }
    if proposal.protocol_id == 0 {
        return Err(Ikev2SaInitBuildError::InvalidProposalProtocolId);
    }
    let spi_size =
        u8::try_from(proposal.spi.len()).map_err(|_| Ikev2SaInitBuildError::ProposalSpiTooLong)?;
    let transform_count = u8::try_from(proposal.transforms.len())
        .map_err(|_| Ikev2SaInitBuildError::LengthOverflow)?;
    if transform_count == 0 {
        return Err(Ikev2SaInitBuildError::MissingTransform);
    }

    let mut transforms = Vec::new();
    for (index, transform) in proposal.transforms.iter().enumerate() {
        encode_transform_build(
            &mut transforms,
            transform,
            index + 1 == proposal.transforms.len(),
        )?;
    }

    let proposal_len = PROPOSAL_HEADER_LEN
        .checked_add(proposal.spi.len())
        .and_then(|len| len.checked_add(transforms.len()))
        .ok_or(Ikev2SaInitBuildError::LengthOverflow)?;
    let proposal_len_u16 =
        u16::try_from(proposal_len).map_err(|_| Ikev2SaInitBuildError::LengthOverflow)?;

    out.push(if is_last { 0 } else { PROPOSAL_MORE });
    out.push(0);
    out.extend_from_slice(&proposal_len_u16.to_be_bytes());
    out.push(proposal.proposal_number);
    out.push(proposal.protocol_id);
    out.push(spi_size);
    out.push(transform_count);
    out.extend_from_slice(&proposal.spi);
    out.extend_from_slice(&transforms);
    Ok(())
}

fn encode_transform_build(
    out: &mut Vec<u8>,
    transform: &Ikev2SaTransformBuild,
    is_last: bool,
) -> Result<(), Ikev2SaInitBuildError> {
    if transform.transform_type == 0 {
        return Err(Ikev2SaInitBuildError::InvalidTransformType);
    }
    let mut attributes = Vec::new();
    for attribute in &transform.attributes {
        encode_attribute_build(&mut attributes, attribute)?;
    }
    let transform_len = TRANSFORM_HEADER_LEN
        .checked_add(attributes.len())
        .ok_or(Ikev2SaInitBuildError::LengthOverflow)?;
    let transform_len_u16 =
        u16::try_from(transform_len).map_err(|_| Ikev2SaInitBuildError::LengthOverflow)?;

    out.push(if is_last { 0 } else { TRANSFORM_MORE });
    out.push(0);
    out.extend_from_slice(&transform_len_u16.to_be_bytes());
    out.push(transform.transform_type);
    out.push(0);
    out.extend_from_slice(&transform.transform_id.to_be_bytes());
    out.extend_from_slice(&attributes);
    Ok(())
}

fn encode_attribute_build(
    out: &mut Vec<u8>,
    attribute: &Ikev2TransformAttributeBuild,
) -> Result<(), Ikev2SaInitBuildError> {
    if attribute.attribute_type > ATTRIBUTE_TYPE_MASK {
        return Err(Ikev2SaInitBuildError::AttributeTypeTooLarge);
    }
    match &attribute.value {
        Ikev2TransformAttributeBuildValue::Tv(value) => {
            out.extend_from_slice(&(attribute.attribute_type | ATTRIBUTE_TV_FLAG).to_be_bytes());
            out.extend_from_slice(&value.to_be_bytes());
        }
        Ikev2TransformAttributeBuildValue::Tlv(bytes) => {
            let len_u16 =
                u16::try_from(bytes.len()).map_err(|_| Ikev2SaInitBuildError::LengthOverflow)?;
            out.extend_from_slice(&attribute.attribute_type.to_be_bytes());
            out.extend_from_slice(&len_u16.to_be_bytes());
            out.extend_from_slice(bytes);
        }
    }
    Ok(())
}

pub(crate) fn encode_ke_payload_build(
    payload: &Ikev2KeyExchangePayloadBuild,
) -> Result<Vec<u8>, Ikev2SaInitBuildError> {
    if payload.dh_group == 0 {
        return Err(Ikev2SaInitBuildError::InvalidDhGroup);
    }
    if payload.key_exchange_data.is_empty() {
        return Err(Ikev2SaInitBuildError::EmptyKeyExchangeData);
    }
    let mut out = Vec::with_capacity(KE_FIXED_BODY_LEN + payload.key_exchange_data.len());
    out.extend_from_slice(&payload.dh_group.to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&payload.key_exchange_data);
    Ok(out)
}

pub(crate) fn encode_nonce_payload_build(
    payload: &Ikev2NoncePayloadBuild,
) -> Result<Vec<u8>, Ikev2SaInitBuildError> {
    validate_nonce_len_for_build(payload.nonce.len())?;
    Ok(payload.nonce.clone())
}

pub(crate) fn encode_notify_payload_build(
    payload: &Ikev2NotifyPayloadBuild,
) -> Result<Vec<u8>, Ikev2SaInitBuildError> {
    let spi_size =
        u8::try_from(payload.spi.len()).map_err(|_| Ikev2SaInitBuildError::NotifySpiTooLong)?;
    let mut out = Vec::with_capacity(
        NOTIFY_FIXED_BODY_LEN + payload.spi.len() + payload.notification_data.len(),
    );
    out.push(payload.protocol_id);
    out.push(spi_size);
    out.extend_from_slice(&payload.notify_message_type.to_be_bytes());
    out.extend_from_slice(&payload.spi);
    out.extend_from_slice(&payload.notification_data);
    Ok(out)
}

fn encode_payload_chain(
    entries: &[(PayloadType, Vec<u8>)],
) -> Result<(PayloadType, Vec<u8>), Ikev2SaInitBuildError> {
    let first = entries
        .first()
        .map(|(payload_type, _)| *payload_type)
        .ok_or(Ikev2SaInitBuildError::LengthOverflow)?;
    let mut out = Vec::new();
    for (index, (payload_type, body)) in entries.iter().enumerate() {
        let next_payload = entries
            .get(index + 1)
            .map(|(next, _)| *next)
            .unwrap_or(PayloadType::NoNext);
        let payload_len = GENERIC_PAYLOAD_HEADER_LEN
            .checked_add(body.len())
            .ok_or(Ikev2SaInitBuildError::LengthOverflow)?;
        let payload_len_u16 =
            u16::try_from(payload_len).map_err(|_| Ikev2SaInitBuildError::LengthOverflow)?;
        let _ = payload_type;
        out.push(next_payload.as_u8());
        out.push(0);
        out.extend_from_slice(&payload_len_u16.to_be_bytes());
        out.extend_from_slice(body);
    }
    Ok((first, out))
}

fn validate_sa_init_request_header(header: &Header) -> Result<(), Ikev2SaInitPayloadError> {
    if header.exchange_type != EXCHANGE_TYPE_IKE_SA_INIT {
        return Err(Ikev2SaInitPayloadError::NotIkeSaInit);
    }
    if header.flags.response() {
        return Err(Ikev2SaInitPayloadError::ResponseMessage);
    }
    if header.message_id != 0 {
        return Err(Ikev2SaInitPayloadError::MessageIdNonZero);
    }
    if header.responder_spi != 0 {
        return Err(Ikev2SaInitPayloadError::ResponderSpiNonZero);
    }
    Ok(())
}

fn validate_response_request_header(header: &Header) -> Result<(), Ikev2SaInitBuildError> {
    if header.exchange_type != EXCHANGE_TYPE_IKE_SA_INIT {
        return Err(Ikev2SaInitBuildError::NotIkeSaInit);
    }
    if header.flags.response() {
        return Err(Ikev2SaInitBuildError::ResponseHeader);
    }
    if header.message_id != 0 {
        return Err(Ikev2SaInitBuildError::MessageIdNonZero);
    }
    if header.responder_spi != 0 {
        return Err(Ikev2SaInitBuildError::ResponderSpiNonZero);
    }
    Ok(())
}

fn validate_nonce_len(len: usize) -> Result<(), Ikev2NoncePayloadError> {
    if len < IKEV2_NONCE_MIN_LEN {
        return Err(Ikev2NoncePayloadError::NonceTooShort);
    }
    if len > IKEV2_NONCE_MAX_LEN {
        return Err(Ikev2NoncePayloadError::NonceTooLong);
    }
    Ok(())
}

fn validate_nonce_len_for_build(len: usize) -> Result<(), Ikev2SaInitBuildError> {
    if len < IKEV2_NONCE_MIN_LEN {
        return Err(Ikev2SaInitBuildError::NonceTooShort);
    }
    if len > IKEV2_NONCE_MAX_LEN {
        return Err(Ikev2SaInitBuildError::NonceTooLong);
    }
    Ok(())
}
