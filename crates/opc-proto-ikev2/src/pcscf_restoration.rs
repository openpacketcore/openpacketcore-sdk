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

/// First configuration-attribute type reserved for private use.
///
/// RFC 4306 3.15.1 states "Values 16384-32767 are for private use among
/// mutually consenting parties", and the IANA IKEv2 Configuration Payload
/// Attribute Types registry records the same split. RFC 7296 obsoleted RFC
/// 4306 and defers the ranges to that registry rather than restating them.
/// Everything below is registered or unassigned, so a caller may not name it.
const IKEV2_CONFIGURATION_ATTRIBUTE_PRIVATE_USE_MIN: u16 = 16_384;

/// Last configuration-attribute type reserved for private use.
const IKEV2_CONFIGURATION_ATTRIBUTE_PRIVATE_USE_MAX: u16 = 32_767;

/// Largest representable configuration-attribute type.
///
/// RFC 7296 3.15.1 reserves the top bit of the attribute-type field, so a type
/// is fifteen significant bits; `ike_auth` masks received types with the same
/// value.
const IKEV2_CONFIGURATION_ATTRIBUTE_TYPE_MAX: u16 = 0x7fff;

/// The configuration-attribute types carrying a P-CSCF address.
///
/// RFC 7651 4 registers `P_CSCF_IP4_ADDRESS = 20` and `P_CSCF_IP6_ADDRESS =
/// 21`, and those remain the default. That registration is dated September
/// 2015 and deployed equipment predates it: RFC 7296 3.15.1 reserves
/// 16384-32767 for private use (RFC 4306 3.15.1, and the IANA registry), RFC
/// 7651 4 itself notes that "some implementations" already used private-use
/// values, and peers are observed
/// negotiating P-CSCF on a private-use type with type 20 absent in both
/// directions.
///
/// A responder that answers a private-use request on type 20 is answering on a
/// type the asking peer never mentioned, so the pair is caller-supplied rather
/// than fixed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ikev2PcscfAttributeTypes {
    ipv4: u16,
    ipv6: u16,
}

impl Default for Ikev2PcscfAttributeTypes {
    fn default() -> Self {
        Self::registered()
    }
}

impl Ikev2PcscfAttributeTypes {
    /// The RFC 7651 4 registered pair, 20 and 21.
    #[must_use]
    pub const fn registered() -> Self {
        Self {
            ipv4: IKEV2_CONFIGURATION_ATTRIBUTE_P_CSCF_IP4_ADDRESS,
            ipv6: IKEV2_CONFIGURATION_ATTRIBUTE_P_CSCF_IP6_ADDRESS,
        }
    }

    /// Construct a caller-chosen pair.
    ///
    /// Each family accepts either its own RFC 7651 4 registered type or a
    /// private-use type (16384-32767, per the IANA IKEv2 Configuration Payload
    /// Attribute Types registry and RFC 4306 3.15.1). Every other code point is refused:
    /// the registered space below 20/21 names unrelated attributes such as
    /// `INTERNAL_IP4_ADDRESS` and `INTERNAL_IP4_DNS`, and emitting a P-CSCF
    /// address on one of those would have the peer interpret it as that
    /// attribute instead, while decoding on one would read an unrelated
    /// attribute as a P-CSCF echo. The unassigned range is reserved for
    /// future expert-review allocation and is refused for the same reason.
    ///
    /// This also forbids naming the *other* family's registered type, so the
    /// pair cannot be transposed.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2PcscfRestorationError::AttributeTypeOutOfRange`] if
    /// either type sets the reserved bit,
    /// [`Ikev2PcscfRestorationError::AttributeTypeNotAvailable`] if either is
    /// a registered or unassigned code point this procedure may not claim, and
    /// [`Ikev2PcscfRestorationError::AttributeTypesNotDistinct`] if both
    /// families name the same type, which would make a decoded attribute
    /// ambiguous.
    pub fn new(ipv4: u16, ipv6: u16) -> Result<Self, Ikev2PcscfRestorationError> {
        for (attribute_type, registered) in [
            (ipv4, IKEV2_CONFIGURATION_ATTRIBUTE_P_CSCF_IP4_ADDRESS),
            (ipv6, IKEV2_CONFIGURATION_ATTRIBUTE_P_CSCF_IP6_ADDRESS),
        ] {
            if attribute_type > IKEV2_CONFIGURATION_ATTRIBUTE_TYPE_MAX {
                return Err(Ikev2PcscfRestorationError::AttributeTypeOutOfRange {
                    attribute_type,
                    maximum: IKEV2_CONFIGURATION_ATTRIBUTE_TYPE_MAX,
                });
            }
            let private_use = (IKEV2_CONFIGURATION_ATTRIBUTE_PRIVATE_USE_MIN
                ..=IKEV2_CONFIGURATION_ATTRIBUTE_PRIVATE_USE_MAX)
                .contains(&attribute_type);
            if attribute_type != registered && !private_use {
                return Err(Ikev2PcscfRestorationError::AttributeTypeNotAvailable {
                    attribute_type,
                    registered,
                });
            }
        }
        if ipv4 == ipv6 {
            return Err(Ikev2PcscfRestorationError::AttributeTypesNotDistinct {
                attribute_type: ipv4,
            });
        }
        Ok(Self { ipv4, ipv6 })
    }

    /// Attribute type carrying an IPv4 P-CSCF address.
    #[must_use]
    pub const fn ipv4(self) -> u16 {
        self.ipv4
    }

    /// Attribute type carrying an IPv6 P-CSCF address.
    #[must_use]
    pub const fn ipv6(self) -> u16 {
        self.ipv6
    }
}

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
    attribute_types: Ikev2PcscfAttributeTypes,
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

    /// Configuration-attribute types this request was built on.
    #[must_use]
    pub const fn attribute_types(&self) -> Ikev2PcscfAttributeTypes {
        self.attribute_types
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
    attribute_types: Ikev2PcscfAttributeTypes,
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

    /// Configuration-attribute types the echo was recognized on.
    ///
    /// A relaying node should answer on the type it was asked on: a peer that
    /// requested on a private-use type has no reason to consume a reply
    /// delivered on the RFC 7651 registered type.
    pub const fn attribute_types(&self) -> Ikev2PcscfAttributeTypes {
        self.attribute_types
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
    /// A configuration-attribute type set the RFC 7296 3.15.1 reserved bit.
    AttributeTypeOutOfRange {
        /// Supplied attribute type.
        attribute_type: u16,
        /// Largest representable type.
        maximum: u16,
    },
    /// A configuration-attribute type this procedure may not claim.
    ///
    /// Only the family's own RFC 7651 4 registered type or a private-use type
    /// is available; every other code point is registered to an unrelated
    /// attribute or is unassigned.
    AttributeTypeNotAvailable {
        /// Supplied attribute type.
        attribute_type: u16,
        /// The registered type for that family.
        registered: u16,
    },
    /// Both address families named the same configuration-attribute type.
    AttributeTypesNotDistinct {
        /// The type supplied for both families.
        attribute_type: u16,
    },
    /// The reply echoed the families on different attribute types than the
    /// request asked on.
    AttributeTypesMismatch {
        /// Types the request used.
        expected: Ikev2PcscfAttributeTypes,
        /// Types the reply was decoded against.
        actual: Ikev2PcscfAttributeTypes,
    },
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
            Self::AttributeTypeOutOfRange { .. } => {
                "ikev2_pcscf_restoration_attribute_type_out_of_range"
            }
            Self::AttributeTypeNotAvailable { .. } => {
                "ikev2_pcscf_restoration_attribute_type_not_available"
            }
            Self::AttributeTypesNotDistinct { .. } => {
                "ikev2_pcscf_restoration_attribute_types_not_distinct"
            }
            Self::AttributeTypesMismatch { .. } => {
                "ikev2_pcscf_restoration_attribute_types_mismatch"
            }
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
    build_ikev2_pcscf_restoration_request_with_attribute_types(
        addresses,
        Ikev2PcscfAttributeTypes::registered(),
    )
}

/// Build a P-CSCF restoration request on caller-chosen attribute types.
///
/// Identical to [`build_ikev2_pcscf_restoration_request`] except that the
/// configuration-attribute types are supplied rather than fixed at the RFC 7651
/// registered pair. Use this to reach a peer that negotiates P-CSCF on a
/// private-use type; see [`Ikev2PcscfAttributeTypes`].
///
/// @spec 3GPP TS 23.380 5.6.5.2; 3GPP TS 24.302 7.4.2.1; IETF RFC 7651 3-4;
/// IETF RFC 7296 3.15.1
///
/// # Errors
///
/// Returns the same failures as [`build_ikev2_pcscf_restoration_request`].
pub fn build_ikev2_pcscf_restoration_request_with_attribute_types(
    addresses: &[Ikev2PcscfRestorationAddress],
    attribute_types: Ikev2PcscfAttributeTypes,
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
                attribute_types.ipv4()
            }
            Ikev2PcscfRestorationAddress::Ipv6(_) => {
                ipv6 = true;
                attribute_types.ipv6()
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
        attribute_types,
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

/// Decode a P-CSCF restoration `CFG_REPLY` on caller-chosen attribute types.
///
/// Identical to [`decode_ikev2_pcscf_restoration_response`] except that the
/// echoed families are recognized on the supplied pair. An attribute on any
/// other type is treated as unsupported and retained under the unknown-IE
/// policy exactly as before, so a reply on the wrong type fails as a missing
/// family rather than being silently accepted.
///
/// @spec IETF RFC 7651 3-4; IETF RFC 7296 3.15.1
///
/// # Errors
///
/// Returns the same failures as
/// [`decode_ikev2_pcscf_restoration_response`].
pub fn decode_ikev2_pcscf_restoration_response_with_attribute_types<'a>(
    header: &Header,
    first_payload: PayloadType,
    cleartext_payloads: &'a [u8],
    attribute_types: Ikev2PcscfAttributeTypes,
) -> Result<Ikev2PcscfRestorationResponse<'a>, Ikev2PcscfRestorationError> {
    let mut context = DecodeContext::conservative();
    context.unknown_ie_policy = UnknownIePolicy::Preserve;
    decode_ikev2_pcscf_restoration_response_with_context_and_attribute_types(
        header,
        first_payload,
        cleartext_payloads,
        context,
        attribute_types,
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
    context: DecodeContext,
) -> Result<Ikev2PcscfRestorationResponse<'a>, Ikev2PcscfRestorationError> {
    decode_ikev2_pcscf_restoration_response_with_context_and_attribute_types(
        header,
        first_payload,
        cleartext_payloads,
        context,
        Ikev2PcscfAttributeTypes::registered(),
    )
}

/// Decode a `CFG_REPLY` with explicit parser limits and attribute types.
///
/// The union of [`decode_ikev2_pcscf_restoration_response_with_context`] and
/// [`decode_ikev2_pcscf_restoration_response_with_attribute_types`].
///
/// @spec IETF RFC 7651 3-4; IETF RFC 7296 3.15.1
///
/// # Errors
///
/// Returns the same failures as
/// [`decode_ikev2_pcscf_restoration_response`].
pub fn decode_ikev2_pcscf_restoration_response_with_context_and_attribute_types<'a>(
    header: &Header,
    first_payload: PayloadType,
    cleartext_payloads: &'a [u8],
    mut context: DecodeContext,
    attribute_types: Ikev2PcscfAttributeTypes,
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
    let (address_families, unsupported_configuration_attributes) = decode_empty_address_families(
        &configuration.attributes,
        context.unknown_ie_policy,
        attribute_types,
    )?;
    Ok(Ikev2PcscfRestorationResponse {
        address_families,
        attribute_types,
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
    // Compare only the families this exchange actually carried. Comparing the
    // whole pair would reject an exchange whose octets are byte-identical to a
    // compliant one, on the strength of a type for a family that was never
    // sent or echoed.
    let families = request.address_families;
    let ipv4_exchanged = matches!(
        families,
        Ikev2PcscfRestorationAddressFamilies::Ipv4
            | Ikev2PcscfRestorationAddressFamilies::DualStack
    );
    let ipv6_exchanged = matches!(
        families,
        Ikev2PcscfRestorationAddressFamilies::Ipv6
            | Ikev2PcscfRestorationAddressFamilies::DualStack
    );
    if (ipv4_exchanged && request.attribute_types.ipv4() != response.attribute_types.ipv4())
        || (ipv6_exchanged && request.attribute_types.ipv6() != response.attribute_types.ipv6())
    {
        return Err(Ikev2PcscfRestorationError::AttributeTypesMismatch {
            expected: request.attribute_types,
            actual: response.attribute_types,
        });
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
    attribute_types: Ikev2PcscfAttributeTypes,
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
        // The recognized types are runtime values, so this cannot be a match.
        if attribute.attribute_type == attribute_types.ipv4() {
            validate_empty_address_attribute(
                attribute,
                Ikev2PcscfRestorationAddressFamilies::Ipv4,
                &mut ipv4,
            )?;
        } else if attribute.attribute_type == attribute_types.ipv6() {
            validate_empty_address_attribute(
                attribute,
                Ikev2PcscfRestorationAddressFamilies::Ipv6,
                &mut ipv6,
            )?;
        } else {
            preserve_unsupported_configuration_attribute(
                &mut unsupported,
                *attribute,
                unknown_policy,
            );
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
