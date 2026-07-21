//! Typed P-CSCF restoration configuration exchange support.
//!
//! 3GPP TS 24.302 section 7.2.3.2 uses an authenticated IKEv2
//! `INFORMATIONAL` exchange to signal P-CSCF restoration. This module owns the
//! RFC 7651 configuration attribute identifiers, relays a bounded typed list of
//! P-CSCF addresses in the request, and validates the procedure's required
//! empty per-family response echo. IKE SA protection, retransmission, address
//! selection, and product policy remain caller-owned.

use core::fmt;
use std::{error::Error, net::Ipv4Addr, net::Ipv6Addr};

use bytes::Bytes;
use opc_protocol::{DecodeContext, DecodeErrorCode, UnknownIePolicy, ValidationLevel};

use crate::{
    build_ike_auth_cleartext_payload_chain, build_ike_auth_configuration_payload,
    dedicated_bearer::Ikev2UnknownNonCriticalPayload,
    header::{Header, EXCHANGE_TYPE_INFORMATIONAL},
    ike_auth::{
        Ikev2ConfigurationAttribute, Ikev2ConfigurationAttributeBuild, Ikev2ConfigurationPayload,
        Ikev2ConfigurationPayloadBuild, Ikev2IkeAuthBuildError, Ikev2IkeAuthPayloadBuild,
        Ikev2IkeAuthPayloadError,
    },
    notify::{Ikev2NotifyPayload, Ikev2NotifyPayloadError},
    payload::{PayloadChain, PayloadType},
    sa_init::Ikev2VendorIdPayload,
    validation::Ikev2ValidationProfile,
};

const IKEV2_CONFIGURATION_TYPE_REQUEST: u8 = 1;
const IKEV2_CONFIGURATION_TYPE_REPLY: u8 = 2;
const IKEV2_CONFIGURATION_ATTRIBUTE_P_CSCF_IP4_ADDRESS: u16 = 20;
const IKEV2_CONFIGURATION_ATTRIBUTE_P_CSCF_IP6_ADDRESS: u16 = 21;
const IKEV2_NOTIFY_STATUS_TYPES_MIN: u16 = 16_384;

/// Maximum number of P-CSCF addresses accepted in one restoration request.
///
/// This implementation limit deliberately shares the conservative decode
/// context's 128-entry ceiling. It is a resource-safety bound rather than a
/// 3GPP limit.
pub const IKEV2_PCSCF_RESTORATION_MAX_ADDRESSES: usize = DecodeContext::conservative().max_ies;

/// One typed P-CSCF address to relay in a restoration request.
///
/// `Debug` intentionally reports only the address family. The address remains
/// available to the wire builder through the typed variants but is never
/// rendered by SDK diagnostics.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ikev2PcscfRestorationAddress {
    /// An IPv4 P-CSCF address encoded in RFC 7651 attribute type 20.
    Ipv4(Ipv4Addr),
    /// An IPv6 P-CSCF address encoded in RFC 7651 attribute type 21.
    Ipv6(Ipv6Addr),
}

impl Ikev2PcscfRestorationAddress {
    const fn family(self) -> Ikev2PcscfRestorationAddressFamilies {
        match self {
            Self::Ipv4(_) => Ikev2PcscfRestorationAddressFamilies::Ipv4,
            Self::Ipv6(_) => Ikev2PcscfRestorationAddressFamilies::Ipv6,
        }
    }

    fn value_bytes(self) -> Vec<u8> {
        match self {
            Self::Ipv4(address) => address.octets().to_vec(),
            Self::Ipv6(address) => address.octets().to_vec(),
        }
    }
}

impl fmt::Debug for Ikev2PcscfRestorationAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2PcscfRestorationAddress")
            .field("family", &self.family())
            .field("address", &"[REDACTED]")
            .finish()
    }
}

/// Address families requested by a P-CSCF restoration exchange.
///
/// The type cannot represent an empty family set. It records the non-empty
/// family projection of a validated P-CSCF address list or reply.
///
/// @spec 3GPP TS 24.302 7.2.3.2; IETF RFC 7651 3-4
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ikev2PcscfRestorationAddressFamilies {
    /// The request carries IPv4 values; the reply echoes one empty IPv4 attribute.
    Ipv4,
    /// The request carries IPv6 values; the reply echoes one empty IPv6 attribute.
    Ipv6,
    /// The request carries both families; the reply echoes one empty attribute each.
    DualStack,
}

impl Ikev2PcscfRestorationAddressFamilies {
    fn from_presence(ipv4: bool, ipv6: bool) -> Option<Self> {
        match (ipv4, ipv6) {
            (true, false) => Some(Self::Ipv4),
            (false, true) => Some(Self::Ipv6),
            (true, true) => Some(Self::DualStack),
            (false, false) => None,
        }
    }
}

/// Immutable opened-payload request ready for one-time IKEv2 sealing.
///
/// Callers should seal this value once and cache the complete protected IKEv2
/// message for exact retransmission. The family selection is retained so the
/// eventual reply can be correlated without reconstructing request state.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2PcscfRestorationRequest {
    address_families: Ikev2PcscfRestorationAddressFamilies,
    address_count: usize,
    first_payload: PayloadType,
    bytes: Bytes,
}

impl Ikev2PcscfRestorationRequest {
    /// Address families carried by the request.
    pub const fn address_families(&self) -> Ikev2PcscfRestorationAddressFamilies {
        self.address_families
    }

    /// Number of address entries encoded in the request, including repeats.
    pub const fn address_count(&self) -> usize {
        self.address_count
    }

    /// First inner payload type to place in the outer `SK` payload header.
    pub const fn first_payload(&self) -> PayloadType {
        self.first_payload
    }

    /// Exact generic-payload-chain bytes.
    pub fn bytes(&self) -> &Bytes {
        &self.bytes
    }

    /// Consume the request into its wire components and retained correlation state.
    pub fn into_parts(
        self,
    ) -> (
        Ikev2PcscfRestorationAddressFamilies,
        usize,
        PayloadType,
        Bytes,
    ) {
        (
            self.address_families,
            self.address_count,
            self.first_payload,
            self.bytes,
        )
    }
}

impl fmt::Debug for Ikev2PcscfRestorationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2PcscfRestorationRequest")
            .field("address_families", &self.address_families)
            .field("address_count", &self.address_count)
            .field("first_payload", &self.first_payload)
            .field("encoded_len", &self.bytes.len())
            .finish()
    }
}

/// Strict borrowed view of a P-CSCF restoration `CFG_REPLY`.
///
/// RFC 7296 extension material is retained without exposing its bytes through
/// `Debug`. Unknown critical payloads and error-range Notify payloads never
/// appear here because they fail the exchange during decoding.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2PcscfRestorationResponse<'a> {
    address_families: Ikev2PcscfRestorationAddressFamilies,
    unsupported_configuration_attributes: Vec<Ikev2ConfigurationAttribute<'a>>,
    vendor_ids: Vec<Ikev2VendorIdPayload<'a>>,
    unrecognized_notifies: Vec<Ikev2NotifyPayload<'a>>,
    unknown_noncritical_payloads: Vec<Ikev2UnknownNonCriticalPayload<'a>>,
}

impl<'a> Ikev2PcscfRestorationResponse<'a> {
    /// Address families echoed by the peer.
    pub const fn address_families(&self) -> Ikev2PcscfRestorationAddressFamilies {
        self.address_families
    }

    /// Unsupported `CFG_REPLY` attributes retained under preserve policy.
    ///
    /// RFC-mandated ignore semantics normalize [`UnknownIePolicy::Reject`] to
    /// preservation at this boundary. Explicit [`UnknownIePolicy::Drop`]
    /// leaves this collection empty.
    pub fn unsupported_configuration_attributes(&self) -> &[Ikev2ConfigurationAttribute<'a>] {
        &self.unsupported_configuration_attributes
    }

    /// RFC 7296 Vendor ID payloads retained in received order.
    pub fn vendor_ids(&self) -> &[Ikev2VendorIdPayload<'a>] {
        &self.vendor_ids
    }

    /// Status-range Notify payloads retained under preserve policy.
    ///
    /// RFC-mandated ignore semantics normalize [`UnknownIePolicy::Reject`] to
    /// preservation at this boundary. Explicit [`UnknownIePolicy::Drop`]
    /// leaves this collection empty. Error-range Notify payloads (`< 16384`)
    /// fail the exchange under every policy.
    pub fn unrecognized_notifies(&self) -> &[Ikev2NotifyPayload<'a>] {
        &self.unrecognized_notifies
    }

    /// Unknown non-critical payloads retained under preserve policy.
    ///
    /// RFC-mandated ignore semantics normalize [`UnknownIePolicy::Reject`] to
    /// preservation at this boundary. Explicit [`UnknownIePolicy::Drop`]
    /// leaves this collection empty.
    pub fn unknown_noncritical_payloads(&self) -> &[Ikev2UnknownNonCriticalPayload<'a>] {
        &self.unknown_noncritical_payloads
    }
}

impl fmt::Debug for Ikev2PcscfRestorationResponse<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2PcscfRestorationResponse")
            .field("address_families", &self.address_families)
            .field(
                "unsupported_configuration_attribute_count",
                &self.unsupported_configuration_attributes.len(),
            )
            .field("vendor_id_count", &self.vendor_ids.len())
            .field(
                "unrecognized_notify_count",
                &self.unrecognized_notifies.len(),
            )
            .field(
                "unknown_noncritical_payload_count",
                &self.unknown_noncritical_payloads.len(),
            )
            .finish()
    }
}

/// Stable P-CSCF restoration builder, decoder, or correlation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Ikev2PcscfRestorationError {
    /// The request did not contain any P-CSCF addresses.
    AddressListEmpty,
    /// The request exceeded the SDK resource bound.
    AddressListTooLong {
        /// Supplied address count.
        actual: usize,
        /// Enforced maximum.
        maximum: usize,
    },
    /// The IKE exchange type was not `INFORMATIONAL`.
    WrongExchangeType {
        /// Received exchange type.
        actual: u8,
    },
    /// A response header omitted the response flag.
    ResponseFlagMissing,
    /// An IKE SPI was zero after IKE SA establishment.
    IkeSpiZero,
    /// Opened payload bytes exceeded the conservative network limit.
    MessageTooLarge {
        /// Received payload-chain size.
        actual: usize,
        /// Enforced maximum.
        maximum: usize,
    },
    /// The generic IKEv2 payload chain was malformed or truncated.
    PayloadChain,
    /// The response contained an unknown payload with its Critical bit set.
    UnknownCriticalPayload,
    /// The exchange omitted its Configuration payload.
    ConfigurationPayloadMissing,
    /// The exchange contained more than one Configuration payload.
    ConfigurationPayloadDuplicate,
    /// The exchange contained a known payload invalid for this reply shape.
    UnexpectedPayloadType {
        /// Received payload type.
        actual: PayloadType,
    },
    /// The Configuration payload used the wrong configuration type.
    WrongConfigurationType {
        /// Required configuration type.
        expected: u8,
        /// Received configuration type.
        actual: u8,
    },
    /// The Configuration payload contained neither P-CSCF family attribute.
    AddressFamilyMissing,
    /// A P-CSCF address-family attribute appeared more than once.
    AddressFamilyDuplicate {
        /// Duplicated family.
        family: Ikev2PcscfRestorationAddressFamilies,
    },
    /// A P-CSCF address-family attribute carried a prohibited value.
    AddressValueNotEmpty {
        /// Attribute family.
        family: Ikev2PcscfRestorationAddressFamilies,
        /// Received value length.
        actual_len: usize,
    },
    /// The responder reported an error-range Notify and failed the request.
    PeerErrorNotify {
        /// IKEv2 error-range Notify Message Type (`< 16384`).
        notify_message_type: u16,
        /// Security Protocol ID carried by the Notify.
        protocol_id: u8,
    },
    /// The response did not echo exactly the requested address families.
    AddressFamiliesMismatch {
        /// Requested family selection.
        expected: Ikev2PcscfRestorationAddressFamilies,
        /// Echoed family selection.
        actual: Ikev2PcscfRestorationAddressFamilies,
    },
    /// The response did not correlate with the request IKE header.
    ResponseCorrelationMismatch,
    /// The existing Configuration payload decoder rejected the body.
    Payload(Ikev2IkeAuthPayloadError),
    /// The existing typed Notify decoder rejected the body.
    Notify(Ikev2NotifyPayloadError),
    /// The existing payload builder rejected canonical output.
    Build(Ikev2IkeAuthBuildError),
}

impl Ikev2PcscfRestorationError {
    /// Stable machine-readable error code.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::AddressListEmpty => "ikev2_pcscf_restoration_address_list_empty",
            Self::AddressListTooLong { .. } => "ikev2_pcscf_restoration_address_list_too_long",
            Self::WrongExchangeType { .. } => "ikev2_pcscf_restoration_exchange_type_wrong",
            Self::ResponseFlagMissing => "ikev2_pcscf_restoration_response_flag_missing",
            Self::IkeSpiZero => "ikev2_pcscf_restoration_ike_spi_zero",
            Self::MessageTooLarge { .. } => "ikev2_pcscf_restoration_message_too_large",
            Self::PayloadChain => "ikev2_pcscf_restoration_payload_chain_invalid",
            Self::UnknownCriticalPayload => "ikev2_pcscf_restoration_unknown_critical_payload",
            Self::ConfigurationPayloadMissing => "ikev2_pcscf_restoration_configuration_missing",
            Self::ConfigurationPayloadDuplicate => {
                "ikev2_pcscf_restoration_configuration_duplicate"
            }
            Self::UnexpectedPayloadType { .. } => "ikev2_pcscf_restoration_payload_unexpected",
            Self::WrongConfigurationType { .. } => {
                "ikev2_pcscf_restoration_configuration_type_wrong"
            }
            Self::AddressFamilyMissing => "ikev2_pcscf_restoration_address_family_missing",
            Self::AddressFamilyDuplicate { .. } => {
                "ikev2_pcscf_restoration_address_family_duplicate"
            }
            Self::AddressValueNotEmpty { .. } => "ikev2_pcscf_restoration_address_value_not_empty",
            Self::PeerErrorNotify { .. } => "ikev2_pcscf_restoration_peer_error_notify",
            Self::AddressFamiliesMismatch { .. } => {
                "ikev2_pcscf_restoration_address_families_mismatch"
            }
            Self::ResponseCorrelationMismatch => {
                "ikev2_pcscf_restoration_response_correlation_mismatch"
            }
            Self::Payload(_) => "ikev2_pcscf_restoration_payload_invalid",
            Self::Notify(_) => "ikev2_pcscf_restoration_notify_invalid",
            Self::Build(_) => "ikev2_pcscf_restoration_build_invalid",
        }
    }
}

impl fmt::Display for Ikev2PcscfRestorationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for Ikev2PcscfRestorationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Payload(error) => Some(error),
            Self::Notify(error) => Some(error),
            Self::Build(error) => Some(error),
            _ => None,
        }
    }
}

/// Build a canonical P-CSCF restoration `CFG_REQUEST` opened-payload chain.
///
/// Every supplied address becomes one valued RFC 7651 configuration attribute
/// with its exact four- or sixteen-octet network representation. Input order is
/// retained because TS 23.380 requires the ePDG to forward the PGW-provided
/// list. Repeated entries are retained exactly; downstream P-CSCF selection can
/// depend on the received list's order.
///
/// @spec 3GPP TS 23.380 5.6.5.2; 3GPP TS 24.302 7.4.2.1; IETF RFC 7651 3-4
///
/// # Errors
///
/// Returns [`Ikev2PcscfRestorationError`] for an empty or over-bound address
/// list, or if the underlying canonical encoders cannot represent the request.
pub fn build_ikev2_pcscf_restoration_request(
    addresses: &[Ikev2PcscfRestorationAddress],
) -> Result<Ikev2PcscfRestorationRequest, Ikev2PcscfRestorationError> {
    if addresses.is_empty() {
        return Err(Ikev2PcscfRestorationError::AddressListEmpty);
    }
    if addresses.len() > IKEV2_PCSCF_RESTORATION_MAX_ADDRESSES {
        return Err(Ikev2PcscfRestorationError::AddressListTooLong {
            actual: addresses.len(),
            maximum: IKEV2_PCSCF_RESTORATION_MAX_ADDRESSES,
        });
    }
    let mut ipv4 = false;
    let mut ipv6 = false;
    let mut attributes = Vec::with_capacity(addresses.len());
    for address in addresses {
        let attribute_type = match address {
            Ikev2PcscfRestorationAddress::Ipv4(_) => {
                ipv4 = true;
                IKEV2_CONFIGURATION_ATTRIBUTE_P_CSCF_IP4_ADDRESS
            }
            Ikev2PcscfRestorationAddress::Ipv6(_) => {
                ipv6 = true;
                IKEV2_CONFIGURATION_ATTRIBUTE_P_CSCF_IP6_ADDRESS
            }
        };
        attributes.push(Ikev2ConfigurationAttributeBuild {
            attribute_type,
            value: address.value_bytes(),
        });
    }
    let address_families = Ikev2PcscfRestorationAddressFamilies::from_presence(ipv4, ipv6)
        .ok_or(Ikev2PcscfRestorationError::AddressListEmpty)?;
    let body = build_ike_auth_configuration_payload(&Ikev2ConfigurationPayloadBuild {
        config_type: IKEV2_CONFIGURATION_TYPE_REQUEST,
        attributes,
    })
    .map_err(Ikev2PcscfRestorationError::Build)?;
    let (first_payload, bytes) =
        build_ike_auth_cleartext_payload_chain(&[Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::Configuration,
            body,
        }])
        .map_err(Ikev2PcscfRestorationError::Build)?;
    Ok(Ikev2PcscfRestorationRequest {
        address_families,
        address_count: addresses.len(),
        first_payload,
        bytes,
    })
}

/// Decode a strict P-CSCF restoration `CFG_REPLY` opened-payload chain.
///
/// The response must contain exactly one `CFG_REPLY`, at least one P-CSCF
/// family attribute, no duplicate known P-CSCF attributes, and no values on
/// those known attributes. Unsupported Configuration attributes, Vendor IDs,
/// unrecognized status-range Notify payloads, and unknown non-critical
/// payloads are retained for extension-aware callers. Error-range Notify and
/// unknown critical payloads fail the exchange. Use
/// [`validate_ikev2_pcscf_restoration_response_correlation`] to require an
/// exact requested-family acknowledgement and correlate the IKE headers.
///
/// # Errors
///
/// Returns [`Ikev2PcscfRestorationError`] for a malformed response header,
/// payload chain, Configuration payload, attribute set, or value.
pub fn decode_ikev2_pcscf_restoration_response<'a>(
    header: &Header,
    first_payload: PayloadType,
    cleartext_payloads: &'a [u8],
) -> Result<Ikev2PcscfRestorationResponse<'a>, Ikev2PcscfRestorationError> {
    let mut context = DecodeContext::conservative();
    context.unknown_ie_policy = UnknownIePolicy::Preserve;
    decode_ikev2_pcscf_restoration_response_with_context(
        header,
        first_payload,
        cleartext_payloads,
        context,
    )
}

/// Decode a P-CSCF restoration `CFG_REPLY` with explicit parser limits.
///
/// Structural validation is always upgraded to strict. Caller-supplied byte
/// and payload-count limits remain authoritative. The unknown-IE policy
/// controls retention of unsupported Configuration attributes, unrecognized
/// status Notify payloads, and unknown non-critical payloads. RFC 7296 requires
/// those classes to be ignored, so [`UnknownIePolicy::Reject`] is normalized to
/// [`UnknownIePolicy::Preserve`]. Vendor IDs are known standard payloads and
/// are always retained. Error-range Notify payloads and unknown critical
/// payloads fail closed under every policy.
///
/// # Errors
///
/// Returns the same failures as
/// [`decode_ikev2_pcscf_restoration_response`].
pub fn decode_ikev2_pcscf_restoration_response_with_context<'a>(
    header: &Header,
    first_payload: PayloadType,
    cleartext_payloads: &'a [u8],
    mut context: DecodeContext,
) -> Result<Ikev2PcscfRestorationResponse<'a>, Ikev2PcscfRestorationError> {
    validate_response_header(header)?;
    if cleartext_payloads.len() > context.max_message_len {
        return Err(Ikev2PcscfRestorationError::MessageTooLarge {
            actual: cleartext_payloads.len(),
            maximum: context.max_message_len,
        });
    }
    context.validation_level = ValidationLevel::Strict;
    if context.unknown_ie_policy == UnknownIePolicy::Reject {
        context.unknown_ie_policy = UnknownIePolicy::Preserve;
    }
    let mut configuration = None;
    let mut vendor_ids = Vec::new();
    let mut unrecognized_notifies = Vec::new();
    let mut unknown_noncritical_payloads = Vec::new();
    for raw in PayloadChain::new(first_payload, cleartext_payloads).iter_with_context(context) {
        let raw = raw.map_err(|error| match error.code() {
            DecodeErrorCode::UnknownCriticalIe => {
                Ikev2PcscfRestorationError::UnknownCriticalPayload
            }
            _ => Ikev2PcscfRestorationError::PayloadChain,
        })?;
        match raw.payload_type {
            PayloadType::Configuration => {
                if configuration.is_some() {
                    return Err(Ikev2PcscfRestorationError::ConfigurationPayloadDuplicate);
                }
                configuration = Some(
                    Ikev2ConfigurationPayload::decode_with_profile(
                        raw,
                        Ikev2ValidationProfile::NetworkReceive,
                    )
                    .map_err(Ikev2PcscfRestorationError::Payload)?,
                );
            }
            PayloadType::Notify => {
                let notify =
                    Ikev2NotifyPayload::decode(raw).map_err(Ikev2PcscfRestorationError::Notify)?;
                if notify.notify_message_type < IKEV2_NOTIFY_STATUS_TYPES_MIN {
                    return Err(Ikev2PcscfRestorationError::PeerErrorNotify {
                        notify_message_type: notify.notify_message_type,
                        protocol_id: notify.protocol_id,
                    });
                }
                preserve_unrecognized_notify(
                    &mut unrecognized_notifies,
                    notify,
                    context.unknown_ie_policy,
                );
            }
            PayloadType::VendorId => vendor_ids.push(Ikev2VendorIdPayload {
                vendor_id: raw.body,
            }),
            PayloadType::Unknown(payload_type) => {
                preserve_unknown_noncritical(
                    &mut unknown_noncritical_payloads,
                    payload_type,
                    raw.body,
                    context.unknown_ie_policy,
                );
            }
            actual => {
                return Err(Ikev2PcscfRestorationError::UnexpectedPayloadType { actual });
            }
        }
    }
    let configuration =
        configuration.ok_or(Ikev2PcscfRestorationError::ConfigurationPayloadMissing)?;
    if configuration.config_type != IKEV2_CONFIGURATION_TYPE_REPLY {
        return Err(Ikev2PcscfRestorationError::WrongConfigurationType {
            expected: IKEV2_CONFIGURATION_TYPE_REPLY,
            actual: configuration.config_type,
        });
    }
    let (address_families, unsupported_configuration_attributes) =
        decode_empty_address_families(&configuration.attributes, context.unknown_ie_policy)?;
    Ok(Ikev2PcscfRestorationResponse {
        address_families,
        unsupported_configuration_attributes,
        vendor_ids,
        unrecognized_notifies,
        unknown_noncritical_payloads,
    })
}

/// Validate exact request/response IKE header and family-echo correlation.
///
/// The request and response must use `INFORMATIONAL`, share both IKE SPIs and
/// Message ID, carry opposite Initiator flags, and use the expected request and
/// response flags. The response must echo exactly the families retained by the
/// immutable request.
///
/// # Errors
///
/// Returns [`Ikev2PcscfRestorationError::ResponseCorrelationMismatch`] for a
/// header mismatch, or
/// [`Ikev2PcscfRestorationError::AddressFamiliesMismatch`] for an inexact
/// family echo.
pub fn validate_ikev2_pcscf_restoration_response_correlation(
    request_header: &Header,
    response_header: &Header,
    request: &Ikev2PcscfRestorationRequest,
    response: &Ikev2PcscfRestorationResponse<'_>,
) -> Result<(), Ikev2PcscfRestorationError> {
    if request_header.flags.response()
        || !response_header.flags.response()
        || request_header.exchange_type != EXCHANGE_TYPE_INFORMATIONAL
        || response_header.exchange_type != EXCHANGE_TYPE_INFORMATIONAL
        || request_header.initiator_spi == 0
        || request_header.responder_spi == 0
        || request_header.initiator_spi != response_header.initiator_spi
        || request_header.responder_spi != response_header.responder_spi
        || request_header.message_id != response_header.message_id
        || request_header.flags.initiator() == response_header.flags.initiator()
    {
        return Err(Ikev2PcscfRestorationError::ResponseCorrelationMismatch);
    }
    if request.address_families != response.address_families {
        return Err(Ikev2PcscfRestorationError::AddressFamiliesMismatch {
            expected: request.address_families,
            actual: response.address_families,
        });
    }
    Ok(())
}

fn decode_empty_address_families<'a>(
    attributes: &[Ikev2ConfigurationAttribute<'a>],
    unknown_policy: UnknownIePolicy,
) -> Result<
    (
        Ikev2PcscfRestorationAddressFamilies,
        Vec<Ikev2ConfigurationAttribute<'a>>,
    ),
    Ikev2PcscfRestorationError,
> {
    let mut ipv4 = false;
    let mut ipv6 = false;
    let mut unsupported = Vec::new();
    for attribute in attributes {
        match attribute.attribute_type {
            IKEV2_CONFIGURATION_ATTRIBUTE_P_CSCF_IP4_ADDRESS => {
                validate_empty_address_attribute(
                    attribute,
                    Ikev2PcscfRestorationAddressFamilies::Ipv4,
                    &mut ipv4,
                )?;
            }
            IKEV2_CONFIGURATION_ATTRIBUTE_P_CSCF_IP6_ADDRESS => {
                validate_empty_address_attribute(
                    attribute,
                    Ikev2PcscfRestorationAddressFamilies::Ipv6,
                    &mut ipv6,
                )?;
            }
            _ => preserve_unsupported_configuration_attribute(
                &mut unsupported,
                *attribute,
                unknown_policy,
            ),
        }
    }
    let families = Ikev2PcscfRestorationAddressFamilies::from_presence(ipv4, ipv6)
        .ok_or(Ikev2PcscfRestorationError::AddressFamilyMissing)?;
    Ok((families, unsupported))
}

fn preserve_unsupported_configuration_attribute<'a>(
    output: &mut Vec<Ikev2ConfigurationAttribute<'a>>,
    attribute: Ikev2ConfigurationAttribute<'a>,
    policy: UnknownIePolicy,
) {
    match policy {
        UnknownIePolicy::Preserve | UnknownIePolicy::Reject => output.push(attribute),
        UnknownIePolicy::Drop => {}
    }
}

fn preserve_unrecognized_notify<'a>(
    output: &mut Vec<Ikev2NotifyPayload<'a>>,
    notify: Ikev2NotifyPayload<'a>,
    policy: UnknownIePolicy,
) {
    match policy {
        UnknownIePolicy::Preserve | UnknownIePolicy::Reject => output.push(notify),
        UnknownIePolicy::Drop => {}
    }
}

fn preserve_unknown_noncritical<'a>(
    output: &mut Vec<Ikev2UnknownNonCriticalPayload<'a>>,
    payload_type: u8,
    body: &'a [u8],
    policy: UnknownIePolicy,
) {
    match policy {
        UnknownIePolicy::Preserve | UnknownIePolicy::Reject => {
            output.push(Ikev2UnknownNonCriticalPayload { payload_type, body });
        }
        UnknownIePolicy::Drop => {}
    }
}

fn validate_empty_address_attribute(
    attribute: &Ikev2ConfigurationAttribute<'_>,
    family: Ikev2PcscfRestorationAddressFamilies,
    seen: &mut bool,
) -> Result<(), Ikev2PcscfRestorationError> {
    if *seen {
        return Err(Ikev2PcscfRestorationError::AddressFamilyDuplicate { family });
    }
    if !attribute.value.is_empty() {
        return Err(Ikev2PcscfRestorationError::AddressValueNotEmpty {
            family,
            actual_len: attribute.value.len(),
        });
    }
    *seen = true;
    Ok(())
}

fn validate_response_header(header: &Header) -> Result<(), Ikev2PcscfRestorationError> {
    if header.exchange_type != EXCHANGE_TYPE_INFORMATIONAL {
        return Err(Ikev2PcscfRestorationError::WrongExchangeType {
            actual: header.exchange_type,
        });
    }
    if !header.flags.response() {
        return Err(Ikev2PcscfRestorationError::ResponseFlagMissing);
    }
    if header.initiator_spi == 0 || header.responder_spi == 0 {
        return Err(Ikev2PcscfRestorationError::IkeSpiZero);
    }
    Ok(())
}
