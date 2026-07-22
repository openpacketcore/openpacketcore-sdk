//! Typed SWm APN-Configuration authorization projection.
//!
//! The public [`ApnConfiguration`] remains the wire-core model, with typed QoS
//! and AMBR values. Parsed and newly originated standardized children are held
//! in sealed, ordered supplemental state and exposed through
//! [`SwmApnConfigurationView`]. This prevents a cloned answer whose public APN
//! vector was reordered or whose core was changed from silently associating
//! supplemental values with the wrong APN.

use bytes::BytesMut;
use opc_protocol::{
    DecodeContext, DecodeError, DecodeErrorCode, EncodeContext, EncodeError, SpecRef,
};
use std::{collections::HashSet, error::Error, fmt, net::IpAddr, slice, str};

use super::{
    append_ambr_avp, append_eps_subscribed_qos_profile_avp, builder_helpers, dea_authorization,
    missing_child_error, mobility, parse_ambr, parse_eps_subscribed_qos_profile,
    retain_diameter_eap_extension, ApnConfiguration, DiameterEapRetention, PdnType, Redacted,
    SwmAdditionalAvp, SwmApnOiReplacement, SwmChargingCharacteristics, SwmDiameterEapAnswer,
    SwmDiameterEapExtensionMetadata, SwmDiameterEapRequestEnvelope,
    SwmLocallyConfiguredMobilityMode, SwmMip6AgentInfo, SwmMip6FeatureVector,
    SwmVisitedNetworkIdentifier, AVP_3GPP_CHARGING_CHARACTERISTICS, AVP_AMBR,
    AVP_APN_CONFIGURATION, AVP_APN_OI_REPLACEMENT, AVP_CONTEXT_IDENTIFIER,
    AVP_EPS_SUBSCRIBED_QOS_PROFILE, AVP_MIP6_AGENT_INFO, AVP_PDN_TYPE, AVP_SERVICE_SELECTION,
    AVP_VISITED_NETWORK_IDENTIFIER, MAX_SWM_DIAMETER_EAP_ROUTING_AVPS, VENDOR_ID_3GPP,
};
use crate::{AvpCode, AvpHeader, RawAvp};

/// Served-Party-IP-Address AVP code (3GPP TS 32.299 section 7.2.187).
pub const AVP_SERVED_PARTY_IP_ADDRESS: AvpCode = AvpCode::new(848);
/// VPLMN-Dynamic-Address-Allowed AVP code (3GPP TS 29.272 section 7.3.38).
pub const AVP_VPLMN_DYNAMIC_ADDRESS_ALLOWED: AvpCode = AvpCode::new(1432);
/// PDN-GW-Allocation-Type AVP code (3GPP TS 29.272 section 7.3.44).
pub const AVP_PDN_GW_ALLOCATION_TYPE: AvpCode = AvpCode::new(1438);
/// Interworking-5GS-Indicator AVP code (3GPP TS 29.272 section 7.3.231).
pub const AVP_INTERWORKING_5GS_INDICATOR: AvpCode = AvpCode::new(1706);

pub(super) const MAX_SWM_APN_CONFIGURATIONS: usize = 128;
const MAX_SERVED_PARTY_IP_ADDRESSES: usize = 2;
const MAX_SPECIFIC_APN_INFOS: usize = 128;
const MAX_SPECIFIC_APN_INFO_CHILDREN: usize = 128;

/// Specific-APN-Info AVP code (3GPP TS 29.272 section 7.3.82).
pub const AVP_SPECIFIC_APN_INFO: AvpCode = AvpCode::new(1472);

// The exact nine APN-Configuration children prohibited by TS 29.273 section
// 8.2.3.7. Recognizing only these vendor-aware identities prevents the
// extension wildcard from promoting prohibited data without rejecting other
// TS 29.272 extension children that remain valid opaque wire material.
const AVP_LIPA_PERMISSION: AvpCode = AvpCode::new(1618);
const AVP_RESTORATION_PRIORITY: AvpCode = AvpCode::new(1663);
const AVP_SIPTO_LOCAL_NETWORK_PERMISSION: AvpCode = AvpCode::new(1665);
const AVP_WLAN_OFFLOADABILITY: AvpCode = AvpCode::new(1667);
const AVP_NON_IP_PDN_TYPE_INDICATOR: AvpCode = AvpCode::new(1681);
const AVP_NON_IP_DATA_DELIVERY_MECHANISM: AvpCode = AvpCode::new(1682);
const AVP_SCEF_REALM: AvpCode = AvpCode::new(1684);
const AVP_PREFERRED_DATA_MODE: AvpCode = AvpCode::new(1686);
const AVP_SCEF_ID: AvpCode = AvpCode::new(3125);

/// Whether dynamic address assignment through a VPLMN PDN gateway is allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwmVplmnDynamicAddressAllowed {
    /// A PDN gateway in the VPLMN is not allowed.
    NotAllowed,
    /// A PDN gateway in the VPLMN is allowed.
    Allowed,
}

impl SwmVplmnDynamicAddressAllowed {
    const fn value(self) -> u32 {
        match self {
            Self::NotAllowed => 0,
            Self::Allowed => 1,
        }
    }

    fn from_value(value: u32, offset: usize) -> Result<Self, DecodeError> {
        match value {
            0 => Ok(Self::NotAllowed),
            1 => Ok(Self::Allowed),
            other => Err(invalid_enum(
                "VPLMN-Dynamic-Address-Allowed",
                other,
                offset,
                "7.3.38",
            )),
        }
    }
}

/// Provenance of a PDN gateway identity carried in MIP6-Agent-Info.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwmPdnGwAllocationType {
    /// The gateway was statically provisioned by the operator.
    Static,
    /// The gateway was selected dynamically by another node.
    Dynamic,
}

impl SwmPdnGwAllocationType {
    const fn value(self) -> u32 {
        match self {
            Self::Static => 0,
            Self::Dynamic => 1,
        }
    }

    fn from_value(value: u32, offset: usize) -> Result<Self, DecodeError> {
        match value {
            0 => Ok(Self::Static),
            1 => Ok(Self::Dynamic),
            other => Err(invalid_enum(
                "PDN-GW-Allocation-Type",
                other,
                offset,
                "7.3.44",
            )),
        }
    }
}

/// Whether EPS/5GS interworking is subscribed for one APN.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwmInterworking5gsIndicator {
    /// Interworking is not subscribed (also the absent default).
    NotSubscribed,
    /// Interworking is subscribed.
    Subscribed,
}

impl SwmInterworking5gsIndicator {
    const fn value(self) -> u32 {
        match self {
            Self::NotSubscribed => 0,
            Self::Subscribed => 1,
        }
    }

    fn from_value(value: u32, offset: usize) -> Result<Self, DecodeError> {
        match value {
            0 => Ok(Self::NotSubscribed),
            1 => Ok(Self::Subscribed),
            other => Err(invalid_enum(
                "Interworking-5GS-Indicator",
                other,
                offset,
                "7.3.231",
            )),
        }
    }
}

/// Stable class for a rejected complete APN authorization configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SwmApnConfigurationErrorCode {
    /// More APN configurations than the bounded profile permits were supplied.
    TooManyConfigurations,
    /// Context-Identifier was zero.
    ZeroContextIdentifier,
    /// Context-Identifier was repeated.
    DuplicateContextIdentifier,
    /// Service-Selection was empty.
    EmptyServiceSelection,
    /// Service-Selection was not a valid APN network identifier.
    InvalidServiceSelection,
    /// Service-Selection was repeated.
    DuplicateServiceSelection,
    /// More than two static served-party addresses were supplied.
    TooManyServedPartyAddresses,
    /// More than one address of one IP family was supplied.
    DuplicateServedPartyAddressFamily,
    /// An IPv6 static prefix had nonzero lower 64 bits.
    NoncanonicalIpv6Prefix,
    /// The supplied address cannot represent an assignable static UE address.
    InvalidServedPartyAddress,
    /// A served-party address family contradicted PDN-Type.
    PdnTypeAddressMismatch,
    /// PDN-GW-Allocation-Type was supplied without MIP6-Agent-Info.
    AllocationWithoutGateway,
    /// Visited-Network-Identifier was supplied for a non-dynamic gateway.
    VisitedNetworkWithoutDynamicGateway,
    /// Ordered supplemental state no longer correlates to the complete core.
    SupplementalCorrelationMismatch,
    /// The proposed default Context-Identifier did not resolve to one APN.
    DefaultContextIdentifierMissing,
    /// APN material was attached to a non-success answer.
    ResultNotExactSuccess,
    /// APN material was attached to an emergency request.
    EmergencyRequest,
    /// The answer did not correlate to the request used by the checked mutator.
    RequestMismatch,
    /// The requested Service-Selection was absent from the returned profile.
    RequestedApnMissing,
    /// The selected mobility mode cannot carry the supplied APN fields.
    MobilityModeMismatch,
    /// The PDN type is preserved on the raw wire model but cannot be authorized.
    UnsupportedPdnType,
    /// A wildcard profile is a correlated wire fact, not a broad authorization grant.
    WildcardAuthorizationUnsupported,
    /// Specific-APN-Info was attached to a non-wildcard APN configuration.
    SpecificApnInfoRequiresWildcard,
    /// More Specific-APN-Info values than the bounded profile permits were supplied.
    TooManySpecificApnInfos,
}

/// Redaction-safe failure from complete APN construction or correlation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwmApnConfigurationError {
    code: SwmApnConfigurationErrorCode,
}

impl SwmApnConfigurationError {
    const fn new(code: SwmApnConfigurationErrorCode) -> Self {
        Self { code }
    }

    /// Return the stable machine-readable failure class.
    #[must_use]
    pub const fn code(self) -> SwmApnConfigurationErrorCode {
        self.code
    }

    /// Return a stable value-free label suitable for metrics and audit events.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self.code {
            SwmApnConfigurationErrorCode::TooManyConfigurations => {
                "swm_apn_configuration_count_exceeded"
            }
            SwmApnConfigurationErrorCode::ZeroContextIdentifier => {
                "swm_apn_context_identifier_zero"
            }
            SwmApnConfigurationErrorCode::DuplicateContextIdentifier => {
                "swm_apn_context_identifier_duplicate"
            }
            SwmApnConfigurationErrorCode::EmptyServiceSelection => {
                "swm_apn_service_selection_empty"
            }
            SwmApnConfigurationErrorCode::InvalidServiceSelection => {
                "swm_apn_service_selection_invalid"
            }
            SwmApnConfigurationErrorCode::DuplicateServiceSelection => {
                "swm_apn_service_selection_duplicate"
            }
            SwmApnConfigurationErrorCode::TooManyServedPartyAddresses => {
                "swm_apn_served_party_address_count_exceeded"
            }
            SwmApnConfigurationErrorCode::DuplicateServedPartyAddressFamily => {
                "swm_apn_served_party_address_family_duplicate"
            }
            SwmApnConfigurationErrorCode::NoncanonicalIpv6Prefix => {
                "swm_apn_served_party_ipv6_prefix_noncanonical"
            }
            SwmApnConfigurationErrorCode::InvalidServedPartyAddress => {
                "swm_apn_served_party_address_invalid"
            }
            SwmApnConfigurationErrorCode::PdnTypeAddressMismatch => {
                "swm_apn_pdn_type_address_mismatch"
            }
            SwmApnConfigurationErrorCode::AllocationWithoutGateway => {
                "swm_apn_gateway_allocation_without_gateway"
            }
            SwmApnConfigurationErrorCode::VisitedNetworkWithoutDynamicGateway => {
                "swm_apn_visited_network_without_dynamic_gateway"
            }
            SwmApnConfigurationErrorCode::SupplementalCorrelationMismatch => {
                "swm_apn_supplemental_correlation_mismatch"
            }
            SwmApnConfigurationErrorCode::DefaultContextIdentifierMissing => {
                "swm_apn_default_context_identifier_missing"
            }
            SwmApnConfigurationErrorCode::ResultNotExactSuccess => {
                "swm_apn_result_not_exact_success"
            }
            SwmApnConfigurationErrorCode::EmergencyRequest => "swm_apn_emergency_request",
            SwmApnConfigurationErrorCode::RequestMismatch => "swm_apn_request_mismatch",
            SwmApnConfigurationErrorCode::RequestedApnMissing => {
                "swm_apn_requested_service_selection_missing"
            }
            SwmApnConfigurationErrorCode::MobilityModeMismatch => "swm_apn_mobility_mode_mismatch",
            SwmApnConfigurationErrorCode::UnsupportedPdnType => "swm_apn_pdn_type_unsupported",
            SwmApnConfigurationErrorCode::WildcardAuthorizationUnsupported => {
                "swm_apn_wildcard_authorization_unsupported"
            }
            SwmApnConfigurationErrorCode::SpecificApnInfoRequiresWildcard => {
                "swm_specific_apn_info_requires_wildcard"
            }
            SwmApnConfigurationErrorCode::TooManySpecificApnInfos => {
                "swm_specific_apn_info_count_exceeded"
            }
        }
    }
}

impl fmt::Display for SwmApnConfigurationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Error for SwmApnConfigurationError {}

/// Validated APN network identifier used by authorization policy.
///
/// The value follows TS 23.003 section 9.1.1: its label-length encoding is at
/// most 63 octets, labels have alphanumeric boundaries and only alphanumeric
/// or `-` interior characters, reserved `rac`/`lac`/`sgsn`/`rnc` prefixes and
/// the terminal `gprs` label are forbidden, and matching is case-insensitive.
/// The retained policy form is normalized to lowercase. Diagnostic formatting
/// is always redacted. The request wildcard `*` is
/// deliberately not an identifier; use [`SwmRequestedApn`] for request
/// selection.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SwmApnNetworkIdentifier(Redacted<String>);

impl SwmApnNetworkIdentifier {
    /// Validate and retain one APN network identifier.
    pub fn new(value: impl AsRef<str>) -> Result<Self, SwmApnConfigurationError> {
        let value = value.as_ref();
        validate_apn_network_identifier(value)?;
        let mut value = value.to_owned();
        value.make_ascii_lowercase();
        Ok(Self(Redacted::from(value)))
    }

    /// Borrow the validated identifier for protocol and policy comparison.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }
}

impl fmt::Debug for SwmApnNetworkIdentifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SwmApnNetworkIdentifier(REDACTED)")
    }
}

/// Validated service selection from an SWm request.
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum SwmRequestedApn {
    /// Exact `*`, requesting the subscription default APN.
    Wildcard,
    /// One exact APN network identifier.
    NetworkIdentifier(SwmApnNetworkIdentifier),
}

impl SwmRequestedApn {
    /// Parse an exact wildcard or a validated APN network identifier.
    pub fn new(value: impl AsRef<str>) -> Result<Self, SwmApnConfigurationError> {
        let value = value.as_ref();
        if value == "*" {
            Ok(Self::Wildcard)
        } else {
            SwmApnNetworkIdentifier::new(value).map(Self::NetworkIdentifier)
        }
    }

    /// Return whether this is the exact default-APN wildcard.
    #[must_use]
    pub const fn is_wildcard(&self) -> bool {
        matches!(self, Self::Wildcard)
    }

    fn matches_core(&self, core: &ApnConfiguration) -> bool {
        match self {
            Self::Wildcard => core.service_selection.as_ref() == "*",
            Self::NetworkIdentifier(identifier) => core
                .service_selection
                .as_ref()
                .eq_ignore_ascii_case(identifier.as_str()),
        }
    }
}

impl fmt::Debug for SwmRequestedApn {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wildcard => formatter.write_str("SwmRequestedApn::Wildcard"),
            Self::NetworkIdentifier(_) => {
                formatter.write_str("SwmRequestedApn::NetworkIdentifier(REDACTED)")
            }
        }
    }
}

/// One concrete APN and registered PDN-GW nested below a wildcard subscription.
///
/// TS 29.272 section 7.3.82 permits this grouped value only in a wildcard
/// `APN-Configuration`. The APN is validated and normalized before allocation,
/// and parser-retained optional children remain sealed and redaction-safe.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmSpecificApnInfo {
    service_selection: SwmApnNetworkIdentifier,
    mip6_agent_info: SwmMip6AgentInfo,
    visited_network_identifier: Option<SwmVisitedNetworkIdentifier>,
    additional_avps: Vec<SwmAdditionalAvp>,
}

impl SwmSpecificApnInfo {
    /// Construct one concrete wildcard-subscription APN/PDN-GW pair.
    #[must_use]
    pub fn new(
        service_selection: SwmApnNetworkIdentifier,
        mip6_agent_info: SwmMip6AgentInfo,
        visited_network_identifier: Option<SwmVisitedNetworkIdentifier>,
    ) -> Self {
        Self {
            service_selection,
            mip6_agent_info,
            visited_network_identifier,
            additional_avps: Vec::new(),
        }
    }

    /// Borrow the exact concrete APN network identifier.
    #[must_use]
    pub const fn service_selection(&self) -> &SwmApnNetworkIdentifier {
        &self.service_selection
    }

    /// Borrow the registered PDN-GW identity.
    #[must_use]
    pub const fn mip6_agent_info(&self) -> &SwmMip6AgentInfo {
        &self.mip6_agent_info
    }

    /// Borrow the optional PLMN in which the registered gateway was allocated.
    #[must_use]
    pub const fn visited_network_identifier(&self) -> Option<&SwmVisitedNetworkIdentifier> {
        self.visited_network_identifier.as_ref()
    }

    /// Iterate over value-free metadata for retained optional extension children.
    pub fn extension_metadata(
        &self,
    ) -> impl ExactSizeIterator<Item = SwmDiameterEapExtensionMetadata> + '_ {
        self.additional_avps
            .iter()
            .map(SwmDiameterEapExtensionMetadata::from_retained)
    }
}

impl fmt::Debug for SwmSpecificApnInfo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmSpecificApnInfo")
            .field("service_selection", &"<redacted>")
            .field("mip6_agent_info", &"<redacted>")
            .field(
                "visited_network_identifier_present",
                &self.visited_network_identifier.is_some(),
            )
            .field("extension_count", &self.additional_avps.len())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct SwmApnConfigurationSupplement {
    bound_core: Option<ApnConfiguration>,
    served_party_ip_addresses: Vec<IpAddr>,
    vplmn_dynamic_address_allowed: Option<SwmVplmnDynamicAddressAllowed>,
    mip6_agent_info: Option<SwmMip6AgentInfo>,
    visited_network_identifier: Option<SwmVisitedNetworkIdentifier>,
    pdn_gw_allocation_type: Option<SwmPdnGwAllocationType>,
    charging_characteristics: Option<SwmChargingCharacteristics>,
    apn_oi_replacement: Option<SwmApnOiReplacement>,
    interworking_5gs_indicator: Option<SwmInterworking5gsIndicator>,
    specific_apn_infos: Vec<SwmSpecificApnInfo>,
    additional_avps: Vec<SwmAdditionalAvp>,
}

impl SwmApnConfigurationSupplement {
    fn unbound() -> Self {
        Self {
            bound_core: None,
            served_party_ip_addresses: Vec::new(),
            vplmn_dynamic_address_allowed: None,
            mip6_agent_info: None,
            visited_network_identifier: None,
            pdn_gw_allocation_type: None,
            charging_characteristics: None,
            apn_oi_replacement: None,
            interworking_5gs_indicator: None,
            specific_apn_infos: Vec::new(),
            additional_avps: Vec::new(),
        }
    }

    // The two callers perform borrowed core/supplement validation immediately
    // before this sole cloning boundary.
    fn bind_core_after_validation(&mut self, core: &ApnConfiguration) {
        self.bound_core = Some(core.clone());
    }

    fn requires_network_based_mobility(&self, core: &ApnConfiguration) -> bool {
        core.eps_subscribed_qos_profile.is_some()
            || core.ambr.is_some()
            || !self.served_party_ip_addresses.is_empty()
            || self.vplmn_dynamic_address_allowed.is_some()
            || self.visited_network_identifier.is_some()
            || self.pdn_gw_allocation_type.is_some()
            || self.charging_characteristics.is_some()
            || self.apn_oi_replacement.is_some()
            || self.interworking_5gs_indicator.is_some()
            || !self.specific_apn_infos.is_empty()
    }
}

impl fmt::Debug for SwmApnConfigurationSupplement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmApnConfigurationSupplement")
            .field(
                "context_identifier",
                &self.bound_core.as_ref().map(|core| core.context_identifier),
            )
            .field(
                "served_party_ip_address_count",
                &self.served_party_ip_addresses.len(),
            )
            .field(
                "vplmn_dynamic_address_allowed_present",
                &self.vplmn_dynamic_address_allowed.is_some(),
            )
            .field("mip6_agent_info_present", &self.mip6_agent_info.is_some())
            .field(
                "visited_network_identifier_present",
                &self.visited_network_identifier.is_some(),
            )
            .field(
                "pdn_gw_allocation_type_present",
                &self.pdn_gw_allocation_type.is_some(),
            )
            .field(
                "charging_characteristics_present",
                &self.charging_characteristics.is_some(),
            )
            .field(
                "apn_oi_replacement_present",
                &self.apn_oi_replacement.is_some(),
            )
            .field(
                "interworking_5gs_indicator_present",
                &self.interworking_5gs_indicator.is_some(),
            )
            .field("specific_apn_info_count", &self.specific_apn_infos.len())
            .field("extension_count", &self.additional_avps.len())
            .finish()
    }
}

/// A complete, wire-valid APN configuration ready for the checked DEA mutator.
///
/// A wildcard configuration may contain typed [`SwmSpecificApnInfo`] entries
/// for origination. It remains unsuitable as a broad authorization grant and
/// is therefore rejected by the strict response's policy accessor.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmAuthorizedApnConfiguration {
    core: ApnConfiguration,
    supplement: SwmApnConfigurationSupplement,
}

impl SwmAuthorizedApnConfiguration {
    /// Validate an APN wire core with no supplemental fields.
    pub fn new(core: ApnConfiguration) -> Result<Self, SwmApnConfigurationError> {
        Self::builder(core).build()
    }

    /// Start an order-independent builder for standardized supplemental fields.
    #[must_use]
    pub fn builder(core: ApnConfiguration) -> SwmAuthorizedApnConfigurationBuilder {
        let supplement = SwmApnConfigurationSupplement::unbound();
        SwmAuthorizedApnConfigurationBuilder { core, supplement }
    }

    pub(super) fn from_parsed(
        core: ApnConfiguration,
        supplement: SwmApnConfigurationSupplement,
    ) -> Result<Self, SwmApnConfigurationError> {
        validate_authorized_configuration(&core, &supplement)?;
        Ok(Self { core, supplement })
    }

    pub(super) const fn supplement(&self) -> &SwmApnConfigurationSupplement {
        &self.supplement
    }

    /// Borrow the typed wire core.
    #[must_use]
    pub const fn core(&self) -> &ApnConfiguration {
        &self.core
    }

    /// Return the validated APN network identifier.
    pub fn network_identifier(&self) -> Result<SwmApnNetworkIdentifier, SwmApnConfigurationError> {
        SwmApnNetworkIdentifier::new(self.core.service_selection.as_ref())
    }

    /// Borrow the complete validated authorization value inside a correlated boundary.
    #[must_use]
    pub(super) const fn as_view(&self) -> SwmApnConfigurationView<'_> {
        SwmApnConfigurationView {
            core: &self.core,
            supplement: Some(&self.supplement),
        }
    }
}

impl fmt::Debug for SwmAuthorizedApnConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmAuthorizedApnConfiguration")
            .field("context_identifier", &self.core.context_identifier)
            .field("service_selection", &"<redacted>")
            .field("pdn_type", &self.core.pdn_type)
            .field("supplement_sealed", &true)
            .finish()
    }
}

/// Order-independent builder for one complete APN authorization value.
#[derive(Clone)]
pub struct SwmAuthorizedApnConfigurationBuilder {
    core: ApnConfiguration,
    supplement: SwmApnConfigurationSupplement,
}

impl SwmAuthorizedApnConfigurationBuilder {
    /// Add one static IPv4 address or canonical IPv6 `/64` prefix.
    ///
    /// At most one value of each family and two total values are accepted.
    pub fn add_served_party_ip_address(
        mut self,
        address: IpAddr,
    ) -> Result<Self, SwmApnConfigurationError> {
        validate_new_served_party_address(&self.supplement.served_party_ip_addresses, address)?;
        self.supplement.served_party_ip_addresses.push(address);
        Ok(self)
    }

    /// Set the VPLMN dynamic-address permission.
    #[must_use]
    pub const fn with_vplmn_dynamic_address_allowed(
        mut self,
        value: SwmVplmnDynamicAddressAllowed,
    ) -> Self {
        self.supplement.vplmn_dynamic_address_allowed = Some(value);
        self
    }

    /// Set the canonical PDN-gateway identity.
    #[must_use]
    pub fn with_mip6_agent_info(mut self, value: SwmMip6AgentInfo) -> Self {
        self.supplement.mip6_agent_info = Some(value);
        self
    }

    /// Set the visited PLMN in which a dynamic gateway was allocated.
    #[must_use]
    pub fn with_visited_network_identifier(mut self, value: SwmVisitedNetworkIdentifier) -> Self {
        self.supplement.visited_network_identifier = Some(value);
        self
    }

    /// Set whether the supplied gateway identity is static or dynamic.
    #[must_use]
    pub const fn with_pdn_gw_allocation_type(mut self, value: SwmPdnGwAllocationType) -> Self {
        self.supplement.pdn_gw_allocation_type = Some(value);
        self
    }

    /// Set the canonical two-octet charging characteristics.
    #[must_use]
    pub const fn with_charging_characteristics(
        mut self,
        value: SwmChargingCharacteristics,
    ) -> Self {
        self.supplement.charging_characteristics = Some(value);
        self
    }

    /// Set the validated APN operator-identifier replacement.
    #[must_use]
    pub fn with_apn_oi_replacement(mut self, value: SwmApnOiReplacement) -> Self {
        self.supplement.apn_oi_replacement = Some(value);
        self
    }

    /// Set the EPS/5GS interworking subscription indicator.
    #[must_use]
    pub const fn with_interworking_5gs_indicator(
        mut self,
        value: SwmInterworking5gsIndicator,
    ) -> Self {
        self.supplement.interworking_5gs_indicator = Some(value);
        self
    }

    /// Append one ordered concrete APN/PDN-GW pair to a wildcard profile.
    pub fn add_specific_apn_info(
        mut self,
        value: SwmSpecificApnInfo,
    ) -> Result<Self, SwmApnConfigurationError> {
        if self.core.service_selection.as_ref() != "*" {
            return Err(SwmApnConfigurationError::new(
                SwmApnConfigurationErrorCode::SpecificApnInfoRequiresWildcard,
            ));
        }
        if self.supplement.specific_apn_infos.len() >= MAX_SPECIFIC_APN_INFOS {
            return Err(SwmApnConfigurationError::new(
                SwmApnConfigurationErrorCode::TooManySpecificApnInfos,
            ));
        }
        self.supplement.specific_apn_infos.push(value);
        Ok(self)
    }

    /// Validate all cardinality, family, and gateway relationships.
    pub fn build(mut self) -> Result<SwmAuthorizedApnConfiguration, SwmApnConfigurationError> {
        validate_originated_configuration_values(&self.core, &self.supplement)?;
        self.supplement.bind_core_after_validation(&self.core);
        Ok(SwmAuthorizedApnConfiguration {
            core: self.core,
            supplement: self.supplement,
        })
    }
}

impl fmt::Debug for SwmAuthorizedApnConfigurationBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmAuthorizedApnConfigurationBuilder")
            .field("context_identifier", &self.core.context_identifier)
            .field("service_selection", &"<redacted>")
            .field("pdn_type", &self.core.pdn_type)
            .field("supplement", &self.supplement)
            .finish()
    }
}

/// Borrowed complete APN view combining the legacy core and sealed supplement.
#[derive(Clone, Copy)]
pub struct SwmApnConfigurationView<'a> {
    core: &'a ApnConfiguration,
    supplement: Option<&'a SwmApnConfigurationSupplement>,
}

impl<'a> SwmApnConfigurationView<'a> {
    /// Borrow the typed APN wire core.
    #[must_use]
    pub const fn core(self) -> &'a ApnConfiguration {
        self.core
    }

    /// Borrow ordered static served-party addresses.
    #[must_use]
    pub fn served_party_ip_addresses(self) -> &'a [IpAddr] {
        self.supplement
            .map_or(&[], |supplement| &supplement.served_party_ip_addresses)
    }

    /// Return the optional VPLMN dynamic-address permission.
    #[must_use]
    pub fn vplmn_dynamic_address_allowed(self) -> Option<SwmVplmnDynamicAddressAllowed> {
        self.supplement
            .and_then(|supplement| supplement.vplmn_dynamic_address_allowed)
    }

    /// Return the effective VPLMN permission, including the absent default.
    #[must_use]
    pub fn effective_vplmn_dynamic_address_allowed(self) -> SwmVplmnDynamicAddressAllowed {
        self.vplmn_dynamic_address_allowed()
            .unwrap_or(SwmVplmnDynamicAddressAllowed::NotAllowed)
    }

    /// Borrow the optional canonical PDN-gateway identity.
    #[must_use]
    pub fn mip6_agent_info(self) -> Option<&'a SwmMip6AgentInfo> {
        self.supplement
            .and_then(|supplement| supplement.mip6_agent_info.as_ref())
    }

    /// Borrow the optional visited-network identifier.
    #[must_use]
    pub fn visited_network_identifier(self) -> Option<&'a SwmVisitedNetworkIdentifier> {
        self.supplement
            .and_then(|supplement| supplement.visited_network_identifier.as_ref())
    }

    /// Return the explicitly present gateway-allocation provenance.
    ///
    /// When a gateway is present and this AVP is absent, TS 29.272 defines the
    /// effective allocation as static; use
    /// [`Self::effective_pdn_gw_allocation_type`] when wire presence is not
    /// required.
    #[must_use]
    pub fn pdn_gw_allocation_type(self) -> Option<SwmPdnGwAllocationType> {
        self.supplement
            .and_then(|supplement| supplement.pdn_gw_allocation_type)
    }

    /// Return the effective gateway allocation, including the absent default.
    #[must_use]
    pub fn effective_pdn_gw_allocation_type(self) -> Option<SwmPdnGwAllocationType> {
        self.mip6_agent_info().map(|_| {
            self.pdn_gw_allocation_type()
                .unwrap_or(SwmPdnGwAllocationType::Static)
        })
    }

    /// Return the optional per-APN charging characteristics.
    #[must_use]
    pub fn charging_characteristics(self) -> Option<SwmChargingCharacteristics> {
        self.supplement
            .and_then(|supplement| supplement.charging_characteristics)
    }

    /// Borrow the optional per-APN operator-identifier replacement.
    #[must_use]
    pub fn apn_oi_replacement(self) -> Option<&'a SwmApnOiReplacement> {
        self.supplement
            .and_then(|supplement| supplement.apn_oi_replacement.as_ref())
    }

    /// Return the optional EPS/5GS interworking indicator.
    #[must_use]
    pub fn interworking_5gs_indicator(self) -> Option<SwmInterworking5gsIndicator> {
        self.supplement
            .and_then(|supplement| supplement.interworking_5gs_indicator)
    }

    /// Return the effective 5GS interworking value, including the absent default.
    #[must_use]
    pub fn effective_interworking_5gs_indicator(self) -> SwmInterworking5gsIndicator {
        self.interworking_5gs_indicator()
            .unwrap_or(SwmInterworking5gsIndicator::NotSubscribed)
    }

    /// Borrow ordered named APN/PDN-GW pairs carried by a wildcard profile.
    #[must_use]
    pub fn specific_apn_infos(self) -> &'a [SwmSpecificApnInfo] {
        self.supplement
            .map_or(&[], |supplement| &supplement.specific_apn_infos)
    }

    /// Iterate over value-free metadata for retained optional extension children.
    pub fn extension_metadata(
        self,
    ) -> impl ExactSizeIterator<Item = SwmDiameterEapExtensionMetadata> + 'a {
        self.supplement
            .map(|supplement| supplement.additional_avps.as_slice())
            .unwrap_or_default()
            .iter()
            .map(SwmDiameterEapExtensionMetadata::from_retained)
    }
}

impl fmt::Debug for SwmApnConfigurationView<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmApnConfigurationView")
            .field("context_identifier", &self.core.context_identifier)
            .field("service_selection", &"<redacted>")
            .field("pdn_type", &self.core.pdn_type)
            .field("supplement", &self.supplement)
            .finish()
    }
}

/// Exact-size iterator over complete ordered APN views.
pub struct SwmApnConfigurationViews<'a> {
    cores: slice::Iter<'a, ApnConfiguration>,
    supplements: &'a [SwmApnConfigurationSupplement],
    index: usize,
}

impl<'a> Iterator for SwmApnConfigurationViews<'a> {
    type Item = SwmApnConfigurationView<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let core = self.cores.next()?;
        let supplement = if self.supplements.is_empty() {
            None
        } else {
            self.supplements.get(self.index)
        };
        self.index = self.index.saturating_add(1);
        Some(SwmApnConfigurationView { core, supplement })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.cores.size_hint()
    }
}

impl ExactSizeIterator for SwmApnConfigurationViews<'_> {}

impl SwmDiameterEapAnswer {
    /// Atomically replace APN cores and supplements for one exact retained DER.
    ///
    /// The operation requires exact base success, rejects emergency DERs,
    /// verifies request/answer identity and mobility selection, and ensures an
    /// explicitly requested APN is represented. Network-based-only fields are
    /// rejected unless the DEA selected GTPv2 or PMIPv6. A non-network-based
    /// profile must carry a canonical gateway identity for every APN, and an
    /// explicit DEA feature vector must select integrated HA discovery. This
    /// compatibility helper retains the answer's current default pointer; use
    /// [`Self::set_authorized_apn_profile_for`] to replace both atomically.
    pub fn set_authorized_apn_configurations_for(
        &mut self,
        request: &SwmDiameterEapRequestEnvelope,
        configurations: Vec<SwmAuthorizedApnConfiguration>,
    ) -> Result<(), SwmApnConfigurationError> {
        let default_context_identifier = self.default_context_identifier;
        self.set_authorized_apn_profile_for(request, default_context_identifier, configurations)
    }

    /// Atomically replace the default pointer, APN cores, and supplements.
    ///
    /// This is the complete profile-replacement boundary. Validation happens
    /// before any field is changed, so a missing proposed default, request
    /// mismatch, or invalid APN leaves the prior profile intact.
    pub fn set_authorized_apn_profile_for(
        &mut self,
        request: &SwmDiameterEapRequestEnvelope,
        default_context_identifier: Option<u32>,
        configurations: Vec<SwmAuthorizedApnConfiguration>,
    ) -> Result<(), SwmApnConfigurationError> {
        validate_checked_mutation(self, request, default_context_identifier, &configurations)?;

        let mut cores = Vec::with_capacity(configurations.len());
        let mut supplements = Vec::with_capacity(configurations.len());
        for configuration in configurations {
            cores.push(configuration.core);
            supplements.push(configuration.supplement);
        }
        self.default_context_identifier = default_context_identifier;
        self.apn_configurations = cores;
        self.extensions.apn_configurations = supplements;
        Ok(())
    }
}

impl super::SwmDiameterEapRequest {
    /// Return the validated typed APN selection, when Service-Selection exists.
    ///
    /// Consumers making authorization decisions should use this checked view
    /// rather than matching the public wire-compatible string directly.
    pub fn requested_apn(&self) -> Result<Option<SwmRequestedApn>, SwmApnConfigurationError> {
        self.service_selection
            .as_ref()
            .map(|value| SwmRequestedApn::new(value.as_ref()))
            .transpose()
    }
}

impl super::SwmCorrelatedDiameterEapResponse {
    /// Borrow structurally valid ordered APN wire views after authenticated-peer,
    /// connection-generation, and complete DER/DEA correlation.
    ///
    /// Wildcard and future PDN values remain observable here as correlated wire
    /// facts. Use [`Self::authorized_apn_configurations`] for policy-safe broad
    /// authorization values.
    pub fn apn_configuration_views(
        &self,
    ) -> Result<SwmApnConfigurationViews<'_>, SwmApnConfigurationError> {
        let answer = correlated_application_answer(self)?;
        validate_structural_view_access(answer)?;
        Ok(configuration_views(answer))
    }

    /// Resolve the default APN as a correlated, structurally valid wire view.
    pub fn default_apn_configuration_view(
        &self,
    ) -> Result<Option<SwmApnConfigurationView<'_>>, SwmApnConfigurationError> {
        let answer = correlated_application_answer(self)?;
        let mut views = self.apn_configuration_views()?;
        let Some(default_context_identifier) = answer.default_context_identifier else {
            return Ok(None);
        };
        Ok(views.find(|view| view.core.context_identifier == default_context_identifier))
    }

    /// Borrow policy-consumable APN authorizations after strict correlation.
    ///
    /// This accessor additionally rejects wildcard parents and unknown PDN
    /// values so they cannot become broad authorization grants.
    pub fn authorized_apn_configurations(
        &self,
    ) -> Result<SwmApnConfigurationViews<'_>, SwmApnConfigurationError> {
        let answer = correlated_application_answer(self)?;
        validate_authorized_view_access(answer)?;
        Ok(configuration_views(answer))
    }
}

pub(super) fn append_apn_configuration_avp(
    dst: &mut BytesMut,
    core: &ApnConfiguration,
    supplement: Option<&SwmApnConfigurationSupplement>,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    if let Some(supplement) = supplement {
        validate_wire_configuration(core, supplement)
            .map_err(|_| encode_apn_error("APN-Configuration supplemental values are invalid"))?;
    }

    let mut value = BytesMut::new();
    builder_helpers::append_vendor_u32_avp(
        &mut value,
        AVP_CONTEXT_IDENTIFIER,
        VENDOR_ID_3GPP,
        core.context_identifier,
        true,
        ctx,
    )?;
    if let Some(supplement) = supplement {
        for address in &supplement.served_party_ip_addresses {
            let mut encoded = BytesMut::new();
            builder_helpers::encode_address_value(&mut encoded, *address);
            builder_helpers::append_avp(
                &mut value,
                AvpHeader::vendor(AVP_SERVED_PARTY_IP_ADDRESS, VENDOR_ID_3GPP, true),
                &encoded,
                ctx,
            )?;
        }
    }
    builder_helpers::append_vendor_u32_avp(
        &mut value,
        AVP_PDN_TYPE,
        VENDOR_ID_3GPP,
        core.pdn_type.value(),
        true,
        ctx,
    )?;
    builder_helpers::append_utf8_avp(
        &mut value,
        AVP_SERVICE_SELECTION,
        core.service_selection.as_ref(),
        true,
        ctx,
    )?;
    if let Some(profile) = core.eps_subscribed_qos_profile.as_ref() {
        append_eps_subscribed_qos_profile_avp(&mut value, profile, ctx)?;
    }
    if let Some(supplement) = supplement {
        if let Some(allowed) = supplement.vplmn_dynamic_address_allowed {
            builder_helpers::append_vendor_u32_avp(
                &mut value,
                AVP_VPLMN_DYNAMIC_ADDRESS_ALLOWED,
                VENDOR_ID_3GPP,
                allowed.value(),
                true,
                ctx,
            )?;
        }
        if let Some(info) = supplement.mip6_agent_info.as_ref() {
            mobility::append_mip6_agent_info_avp(&mut value, info, ctx)?;
        }
        if let Some(identifier) = supplement.visited_network_identifier.as_ref() {
            builder_helpers::append_avp(
                &mut value,
                AvpHeader::vendor(AVP_VISITED_NETWORK_IDENTIFIER, VENDOR_ID_3GPP, true),
                identifier.as_str().as_bytes(),
                ctx,
            )?;
        }
        if let Some(allocation) = supplement.pdn_gw_allocation_type {
            builder_helpers::append_vendor_u32_avp(
                &mut value,
                AVP_PDN_GW_ALLOCATION_TYPE,
                VENDOR_ID_3GPP,
                allocation.value(),
                true,
                ctx,
            )?;
        }
        if let Some(charging) = supplement.charging_characteristics {
            dea_authorization::append_charging_characteristics_avp(&mut value, charging, ctx)?;
        }
    }
    if let Some(ambr) = core.ambr.as_ref() {
        append_ambr_avp(&mut value, ambr, ctx)?;
    }
    if let Some(supplement) = supplement {
        for specific in &supplement.specific_apn_infos {
            append_specific_apn_info_avp(&mut value, specific, ctx)?;
        }
        if let Some(apn_oi) = supplement.apn_oi_replacement.as_ref() {
            dea_authorization::append_apn_oi_replacement_avp(&mut value, apn_oi, ctx)?;
        }
        if let Some(interworking) = supplement.interworking_5gs_indicator {
            builder_helpers::append_vendor_u32_avp(
                &mut value,
                AVP_INTERWORKING_5GS_INDICATOR,
                VENDOR_ID_3GPP,
                interworking.value(),
                false,
                ctx,
            )?;
        }
        append_sealed_extensions(&mut value, &supplement.additional_avps, ctx, "7.3.35")?;
    }
    builder_helpers::append_avp(
        dst,
        AvpHeader::vendor(AVP_APN_CONFIGURATION, VENDOR_ID_3GPP, true),
        &value,
        ctx,
    )
}

fn append_specific_apn_info_avp(
    dst: &mut BytesMut,
    specific: &SwmSpecificApnInfo,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    validate_apn_network_identifier(specific.service_selection.as_str()).map_err(|_| {
        encode_apn_error_for("Specific-APN-Info Service-Selection is invalid", "7.3.82")
    })?;
    let known_children = 2usize + usize::from(specific.visited_network_identifier.is_some());
    if known_children.saturating_add(specific.additional_avps.len())
        > MAX_SPECIFIC_APN_INFO_CHILDREN
    {
        return Err(encode_apn_error_for(
            "Specific-APN-Info child count exceeds its bound",
            "7.3.82",
        ));
    }
    let mut value = BytesMut::new();
    builder_helpers::append_utf8_avp(
        &mut value,
        AVP_SERVICE_SELECTION,
        specific.service_selection.as_str(),
        true,
        ctx,
    )?;
    mobility::append_mip6_agent_info_avp(&mut value, &specific.mip6_agent_info, ctx)?;
    if let Some(identifier) = specific.visited_network_identifier.as_ref() {
        builder_helpers::append_avp(
            &mut value,
            AvpHeader::vendor(AVP_VISITED_NETWORK_IDENTIFIER, VENDOR_ID_3GPP, true),
            identifier.as_str().as_bytes(),
            ctx,
        )?;
    }
    append_sealed_extensions(&mut value, &specific.additional_avps, ctx, "7.3.82")?;
    builder_helpers::append_avp(
        dst,
        AvpHeader::vendor(AVP_SPECIFIC_APN_INFO, VENDOR_ID_3GPP, true),
        &value,
        ctx,
    )
}

fn parse_specific_apn_info(
    outer: &RawAvp<'_>,
    ctx: DecodeContext,
    outer_offset: usize,
    value_offset: usize,
    depth: usize,
    retention: &mut DiameterEapRetention,
) -> Result<SwmSpecificApnInfo, DecodeError> {
    validate_understood_specific_apn_flags(outer, outer_offset)?;
    validate_group_length(
        outer.value,
        36,
        value_offset,
        "Specific-APN-Info is too short for its required children",
        "7.3.82",
    )?;

    let mut service_selection = None;
    let mut mip6_agent_info = None;
    let mut visited_network_identifier = None;
    let mut additional_avps = Vec::new();
    let mut additional_keys = HashSet::new();
    let mut child_count = 0usize;
    builder_helpers::for_each_avp(outer.value, ctx, value_offset, depth, |offset, avp| {
        child_count = child_count.checked_add(1).ok_or_else(|| {
            DecodeError::new(DecodeErrorCode::LengthOverflow, offset)
                .with_spec_ref(SpecRef::new("ietf", "RFC6733", "4"))
        })?;
        if child_count > MAX_SPECIFIC_APN_INFO_CHILDREN {
            return Err(DecodeError::new(DecodeErrorCode::IeCountExceeded, offset)
                .with_spec_ref(SpecRef::new("3gpp", "TS29272", "7.3.82")));
        }
        reject_zero_vendor(&avp, offset)?;
        let child_value_offset =
            builder_helpers::offset_add(offset, avp.header.header_len(), "7.3.82")?;
        let key = avp.header.key();
        if key == crate::dictionary::AvpKey::ietf(AVP_SERVICE_SELECTION) {
            validate_base_mandatory(&avp, offset, "RFC5778", "6.2")?;
            let parsed = parse_specific_service_selection(avp.value, child_value_offset)?;
            builder_helpers::set_once(&mut service_selection, parsed, offset, "7.3.82")?;
        } else if key == crate::dictionary::AvpKey::ietf(AVP_MIP6_AGENT_INFO) {
            let parsed = mobility::parse_mip6_agent_info(
                &avp,
                ctx,
                offset,
                child_value_offset,
                depth + 1,
                retention,
            )?;
            builder_helpers::set_once(&mut mip6_agent_info, parsed, offset, "7.3.82")?;
        } else if key
            == crate::dictionary::AvpKey::vendor(AVP_VISITED_NETWORK_IDENTIFIER, VENDOR_ID_3GPP)
        {
            validate_vendor_mandatory(&avp, offset, "7.3.105")?;
            let parsed = SwmVisitedNetworkIdentifier::from_wire(avp.value, child_value_offset)?;
            builder_helpers::set_once(&mut visited_network_identifier, parsed, offset, "7.3.82")?;
        } else {
            retain_diameter_eap_extension(
                ctx,
                &avp,
                offset,
                "7.3.82",
                &mut additional_keys,
                retention,
                &mut additional_avps,
            )?;
        }
        Ok(())
    })?;

    Ok(SwmSpecificApnInfo {
        service_selection: service_selection.ok_or_else(|| {
            specific_missing_child(value_offset, "Specific-APN-Info requires Service-Selection")
        })?,
        mip6_agent_info: mip6_agent_info.ok_or_else(|| {
            specific_missing_child(value_offset, "Specific-APN-Info requires MIP6-Agent-Info")
        })?,
        visited_network_identifier,
        additional_avps,
    })
}

pub(super) fn parse_apn_configuration(
    outer: &RawAvp<'_>,
    ctx: DecodeContext,
    outer_offset: usize,
    value_offset: usize,
    depth: usize,
    retention: &mut DiameterEapRetention,
) -> Result<(ApnConfiguration, SwmApnConfigurationSupplement), DecodeError> {
    validate_understood_outer_apn_flags(outer, outer_offset)?;
    validate_group_length(
        outer.value,
        44,
        value_offset,
        "APN-Configuration is too short for its required children",
        "7.3.35",
    )?;
    let mut context_identifier = None;
    let mut service_selection = None;
    let mut pdn_type = None;
    let mut eps_subscribed_qos_profile = None;
    let mut ambr = None;
    let mut served_party_ip_addresses = Vec::new();
    let mut vplmn_dynamic_address_allowed = None;
    let mut mip6_agent_info = None;
    let mut visited_network_identifier = None;
    let mut pdn_gw_allocation_type = None;
    let mut charging_characteristics = None;
    let mut apn_oi_replacement = None;
    let mut interworking_5gs_indicator = None;
    let mut specific_apn_infos = Vec::new();
    let mut additional_avps = Vec::new();
    let mut additional_keys = HashSet::new();

    builder_helpers::for_each_avp(outer.value, ctx, value_offset, depth, |offset, avp| {
        reject_zero_vendor(&avp, offset)?;
        let child_value_offset =
            builder_helpers::offset_add(offset, avp.header.header_len(), "7.3.35")?;
        let key = avp.header.key();
        if key == crate::dictionary::AvpKey::vendor(AVP_CONTEXT_IDENTIFIER, VENDOR_ID_3GPP) {
            validate_vendor_mandatory(&avp, offset, "7.3.27")?;
            let parsed = builder_helpers::parse_u32_value(avp.value, child_value_offset, "7.3.27")?;
            builder_helpers::set_once(&mut context_identifier, parsed, offset, "7.3.35")?;
        } else if key
            == crate::dictionary::AvpKey::vendor(AVP_SERVED_PARTY_IP_ADDRESS, VENDOR_ID_3GPP)
        {
            validate_served_party_ip_address_flags(&avp, offset)?;
            if served_party_ip_addresses.len() >= MAX_SERVED_PARTY_IP_ADDRESSES {
                return Err(DecodeError::new(DecodeErrorCode::IeCountExceeded, offset)
                    .with_spec_ref(SpecRef::new("3gpp", "TS29272", "7.3.35")));
            }
            let address =
                builder_helpers::parse_address_value(avp.value, child_value_offset, "4.3.1")?;
            validate_new_served_party_address(&served_party_ip_addresses, address)
                .map_err(|error| decode_configuration_error(error, offset))?;
            served_party_ip_addresses.push(address);
        } else if key == crate::dictionary::AvpKey::vendor(AVP_PDN_TYPE, VENDOR_ID_3GPP) {
            validate_vendor_mandatory(&avp, offset, "7.3.62")?;
            let parsed = builder_helpers::parse_u32_value(avp.value, child_value_offset, "7.3.62")?;
            builder_helpers::set_once(
                &mut pdn_type,
                PdnType::from_value(parsed),
                offset,
                "7.3.35",
            )?;
        } else if key == crate::dictionary::AvpKey::ietf(AVP_SERVICE_SELECTION) {
            validate_base_mandatory(&avp, offset, "RFC5778", "6.2")?;
            let parsed =
                parse_wire_service_selection_value(avp.value, child_value_offset, true, "7.3.35")?;
            builder_helpers::set_once(&mut service_selection, parsed, offset, "7.3.35")?;
        } else if key
            == crate::dictionary::AvpKey::vendor(AVP_EPS_SUBSCRIBED_QOS_PROFILE, VENDOR_ID_3GPP)
        {
            validate_vendor_mandatory(&avp, offset, "7.3.37")?;
            let parsed =
                parse_eps_subscribed_qos_profile(avp.value, ctx, child_value_offset, depth + 1)?;
            builder_helpers::set_once(&mut eps_subscribed_qos_profile, parsed, offset, "7.3.35")?;
        } else if key
            == crate::dictionary::AvpKey::vendor(AVP_VPLMN_DYNAMIC_ADDRESS_ALLOWED, VENDOR_ID_3GPP)
        {
            validate_vendor_mandatory(&avp, offset, "7.3.38")?;
            let raw = builder_helpers::parse_u32_value(avp.value, child_value_offset, "7.3.38")?;
            let parsed = SwmVplmnDynamicAddressAllowed::from_value(raw, child_value_offset)?;
            builder_helpers::set_once(
                &mut vplmn_dynamic_address_allowed,
                parsed,
                offset,
                "7.3.35",
            )?;
        } else if key == crate::dictionary::AvpKey::ietf(AVP_MIP6_AGENT_INFO) {
            validate_base_mandatory(&avp, offset, "RFC5447", "4.2.1")?;
            let parsed = mobility::parse_mip6_agent_info(
                &avp,
                ctx,
                offset,
                child_value_offset,
                depth + 1,
                retention,
            )?;
            builder_helpers::set_once(&mut mip6_agent_info, parsed, offset, "7.3.35")?;
        } else if key
            == crate::dictionary::AvpKey::vendor(AVP_VISITED_NETWORK_IDENTIFIER, VENDOR_ID_3GPP)
        {
            validate_vendor_mandatory(&avp, offset, "9.2.3.1.2")?;
            let parsed = SwmVisitedNetworkIdentifier::from_wire(avp.value, child_value_offset)?;
            builder_helpers::set_once(&mut visited_network_identifier, parsed, offset, "7.3.35")?;
        } else if key
            == crate::dictionary::AvpKey::vendor(AVP_PDN_GW_ALLOCATION_TYPE, VENDOR_ID_3GPP)
        {
            validate_vendor_mandatory(&avp, offset, "7.3.44")?;
            let raw = builder_helpers::parse_u32_value(avp.value, child_value_offset, "7.3.44")?;
            let parsed = SwmPdnGwAllocationType::from_value(raw, child_value_offset)?;
            builder_helpers::set_once(&mut pdn_gw_allocation_type, parsed, offset, "7.3.35")?;
        } else if key
            == crate::dictionary::AvpKey::vendor(AVP_3GPP_CHARGING_CHARACTERISTICS, VENDOR_ID_3GPP)
        {
            validate_vendor_optional_protected_may(&avp, offset, "TS29061", "16.4.7")?;
            let parsed = dea_authorization::parse_charging_characteristics(
                &avp,
                offset,
                child_value_offset,
            )?;
            builder_helpers::set_once(&mut charging_characteristics, parsed, offset, "7.3.35")?;
        } else if key == crate::dictionary::AvpKey::vendor(AVP_AMBR, VENDOR_ID_3GPP) {
            validate_vendor_mandatory(&avp, offset, "7.3.41")?;
            let parsed = parse_ambr(avp.value, ctx, child_value_offset, depth + 1)?;
            builder_helpers::set_once(&mut ambr, parsed, offset, "7.3.35")?;
        } else if key == crate::dictionary::AvpKey::vendor(AVP_APN_OI_REPLACEMENT, VENDOR_ID_3GPP) {
            validate_vendor_mandatory(&avp, offset, "7.3.32")?;
            let parsed =
                dea_authorization::parse_apn_oi_replacement(&avp, offset, child_value_offset)?;
            builder_helpers::set_once(&mut apn_oi_replacement, parsed, offset, "7.3.35")?;
        } else if key
            == crate::dictionary::AvpKey::vendor(AVP_INTERWORKING_5GS_INDICATOR, VENDOR_ID_3GPP)
        {
            validate_vendor_optional(&avp, offset, "7.3.231")?;
            let raw = builder_helpers::parse_u32_value(avp.value, child_value_offset, "7.3.231")?;
            let parsed = SwmInterworking5gsIndicator::from_value(raw, child_value_offset)?;
            builder_helpers::set_once(&mut interworking_5gs_indicator, parsed, offset, "7.3.35")?;
        } else if key == crate::dictionary::AvpKey::vendor(AVP_SPECIFIC_APN_INFO, VENDOR_ID_3GPP) {
            if specific_apn_infos.len() >= MAX_SPECIFIC_APN_INFOS {
                return Err(DecodeError::new(DecodeErrorCode::IeCountExceeded, offset)
                    .with_spec_ref(SpecRef::new("3gpp", "TS29272", "7.3.82")));
            }
            specific_apn_infos.push(parse_specific_apn_info(
                &avp,
                ctx,
                offset,
                child_value_offset,
                depth + 1,
                retention,
            )?);
        } else if is_swm_inapplicable_child(key) {
            return Err(DecodeError::new(
                DecodeErrorCode::Structural {
                    reason:
                        "TS 29.272 APN child is not applicable to the SWm authorization profile",
                },
                offset,
            )
            .with_spec_ref(SpecRef::new("3gpp", "TS29273", "8.2.3.7")));
        } else {
            retain_diameter_eap_extension(
                ctx,
                &avp,
                offset,
                "7.3.35",
                &mut additional_keys,
                retention,
                &mut additional_avps,
            )?;
        }
        Ok(())
    })?;

    let core = ApnConfiguration {
        context_identifier: context_identifier.ok_or_else(|| {
            missing_child_error(value_offset, "missing Context-Identifier child AVP")
        })?,
        service_selection: service_selection.ok_or_else(|| {
            missing_child_error(value_offset, "missing Service-Selection child AVP")
        })?,
        pdn_type: pdn_type
            .ok_or_else(|| missing_child_error(value_offset, "missing PDN-Type child AVP"))?,
        eps_subscribed_qos_profile,
        ambr,
    };
    let mut supplement = SwmApnConfigurationSupplement {
        bound_core: None,
        served_party_ip_addresses,
        vplmn_dynamic_address_allowed,
        mip6_agent_info,
        visited_network_identifier,
        pdn_gw_allocation_type,
        charging_characteristics,
        apn_oi_replacement,
        interworking_5gs_indicator,
        specific_apn_infos,
        additional_avps,
    };
    validate_wire_configuration_values(&core, &supplement)
        .map_err(|error| decode_configuration_error(error, value_offset))?;
    supplement.bind_core_after_validation(&core);
    Ok((core, supplement))
}

pub(super) fn validate_profile(answer: &SwmDiameterEapAnswer) -> Result<(), &'static str> {
    if answer.apn_configurations.len() > MAX_SWM_APN_CONFIGURATIONS {
        return Err("SWm DEA contains too many APN-Configuration AVPs");
    }
    if !answer.result.is_diameter_success()
        && (answer.default_context_identifier.is_some() || !answer.apn_configurations.is_empty())
    {
        return Err("SWm DEA APN profile material requires DIAMETER_SUCCESS");
    }
    if answer.default_context_identifier == Some(0) {
        return Err("SWm DEA default Context-Identifier must not be zero");
    }
    if validate_supplement_alignment(answer).is_err() {
        return Err("SWm DEA APN supplemental state does not match the ordered APN profile");
    }

    let mut context_identifiers = HashSet::new();
    let mut service_selections: Vec<&str> = Vec::new();
    for (index, core) in answer.apn_configurations.iter().enumerate() {
        if core.context_identifier == 0 {
            return Err("SWm DEA APN-Configuration Context-Identifier must not be zero");
        }
        if !context_identifiers.insert(core.context_identifier) {
            return Err("SWm DEA APN-Configuration Context-Identifier values must be unique");
        }
        validate_wire_service_selection(core.service_selection.as_ref())
            .map_err(|_| "SWm DEA APN-Configuration Service-Selection is invalid")?;
        if service_selections
            .iter()
            .any(|present| present.eq_ignore_ascii_case(core.service_selection.as_ref()))
        {
            return Err("SWm DEA APN-Configuration Service-Selection values must be unique");
        }
        service_selections.push(core.service_selection.as_ref());
        if let Some(supplement) = answer.extensions.apn_configurations.get(index) {
            if validate_wire_configuration(core, supplement).is_err() {
                return Err("SWm DEA APN-Configuration supplemental values are inconsistent");
            }
        }
    }
    if let Some(default_context_identifier) = answer.default_context_identifier {
        if !context_identifiers.contains(&default_context_identifier) {
            return Err("SWm DEA default Context-Identifier must identify an APN-Configuration");
        }
    }
    Ok(())
}

pub(super) fn validate_for_request(
    request: &SwmDiameterEapRequestEnvelope,
    answer: &SwmDiameterEapAnswer,
) -> Result<(), &'static str> {
    if !answer.apn_configurations.is_empty() && request.request().requests_emergency_services() {
        return Err("SWm DEA APN-Configuration is prohibited for an emergency DER");
    }
    if let Some(requested) = request
        .request()
        .requested_apn()
        .map_err(|_| "SWm DER Service-Selection is invalid")?
    {
        if !answer.apn_configurations.is_empty() && requested.is_wildcard() {
            if answer.default_context_identifier.is_none() {
                return Err("SWm DEA APN profile does not identify a default for wildcard DER");
            }
        } else if !answer.apn_configurations.is_empty()
            && !answer
                .apn_configurations
                .iter()
                .enumerate()
                .any(|(index, configuration)| {
                    requested_matches_configuration(
                        &requested,
                        configuration,
                        answer.extensions.apn_configurations.get(index),
                    )
                })
        {
            return Err("SWm DEA APN profile does not contain the DER Service-Selection");
        }
    }
    if !answer.apn_configurations.is_empty() {
        match super::effective_mobility_mode(request, answer) {
            Some(SwmLocallyConfiguredMobilityMode::NetworkBased) => {}
            Some(SwmLocallyConfiguredMobilityMode::LocalIpAddressAssignment) => {
                if answer.mip6_feature_vector.is_some_and(|features| {
                    !features.contains(SwmMip6FeatureVector::MIP6_INTEGRATED)
                }) || answer
                    .apn_configurations
                    .iter()
                    .enumerate()
                    .any(|(index, core)| {
                        answer
                            .extensions
                            .apn_configurations
                            .get(index)
                            .is_none_or(|supplement| {
                                !local_assignment_configuration_is_valid(core, supplement)
                            })
                    })
                {
                    return Err("SWm DEA APN profile conflicts with local IP-address assignment");
                }
            }
            None => return Err("SWm DEA APN profile lacks mobility-mode provenance"),
        }
    }
    Ok(())
}

fn validate_checked_mutation(
    answer: &SwmDiameterEapAnswer,
    request: &SwmDiameterEapRequestEnvelope,
    default_context_identifier: Option<u32>,
    configurations: &[SwmAuthorizedApnConfiguration],
) -> Result<(), SwmApnConfigurationError> {
    if configurations.len() > MAX_SWM_APN_CONFIGURATIONS {
        return Err(SwmApnConfigurationError::new(
            SwmApnConfigurationErrorCode::TooManyConfigurations,
        ));
    }
    if default_context_identifier == Some(0) {
        return Err(SwmApnConfigurationError::new(
            SwmApnConfigurationErrorCode::ZeroContextIdentifier,
        ));
    }
    if !configurations.is_empty() && !answer.result.is_diameter_success() {
        return Err(SwmApnConfigurationError::new(
            SwmApnConfigurationErrorCode::ResultNotExactSuccess,
        ));
    }
    let request_facts = request.request();
    if answer.session_id.as_ref() != request_facts.session_id.as_ref()
        || answer.auth_application_id != request_facts.auth_application_id
        || answer.auth_request_type != request_facts.auth_request_type
        || !super::mobility_answer_matches_offer(
            request_facts.mip6_feature_vector,
            answer.mip6_feature_vector,
            answer.result.is_diameter_success(),
        )
    {
        return Err(SwmApnConfigurationError::new(
            SwmApnConfigurationErrorCode::RequestMismatch,
        ));
    }
    if !configurations.is_empty() && request_facts.requests_emergency_services() {
        return Err(SwmApnConfigurationError::new(
            SwmApnConfigurationErrorCode::EmergencyRequest,
        ));
    }

    let mut context_identifiers = HashSet::with_capacity(configurations.len());
    let mut service_selections: Vec<&str> = Vec::with_capacity(configurations.len());
    for configuration in configurations {
        validate_originated_configuration(&configuration.core, &configuration.supplement)?;
        if !context_identifiers.insert(configuration.core.context_identifier) {
            return Err(SwmApnConfigurationError::new(
                SwmApnConfigurationErrorCode::DuplicateContextIdentifier,
            ));
        }
        if service_selections.iter().any(|present| {
            present.eq_ignore_ascii_case(configuration.core.service_selection.as_ref())
        }) {
            return Err(SwmApnConfigurationError::new(
                SwmApnConfigurationErrorCode::DuplicateServiceSelection,
            ));
        }
        service_selections.push(configuration.core.service_selection.as_ref());
    }
    if let Some(default_context_identifier) = default_context_identifier {
        if !context_identifiers.contains(&default_context_identifier) {
            return Err(SwmApnConfigurationError::new(
                SwmApnConfigurationErrorCode::DefaultContextIdentifierMissing,
            ));
        }
    }
    if let Some(requested) = request_facts.requested_apn()? {
        if !configurations.is_empty() && requested.is_wildcard() {
            if default_context_identifier.is_none() {
                return Err(SwmApnConfigurationError::new(
                    SwmApnConfigurationErrorCode::DefaultContextIdentifierMissing,
                ));
            }
        } else if !configurations.is_empty()
            && !configurations.iter().any(|configuration| {
                requested_matches_configuration(
                    &requested,
                    &configuration.core,
                    Some(&configuration.supplement),
                )
            })
        {
            return Err(SwmApnConfigurationError::new(
                SwmApnConfigurationErrorCode::RequestedApnMissing,
            ));
        }
    }

    if !configurations.is_empty() {
        match super::effective_mobility_mode(request, answer) {
            Some(SwmLocallyConfiguredMobilityMode::NetworkBased) => {}
            Some(SwmLocallyConfiguredMobilityMode::LocalIpAddressAssignment) => {
                if answer.mip6_feature_vector.is_some_and(|features| {
                    !features.contains(SwmMip6FeatureVector::MIP6_INTEGRATED)
                }) || configurations.iter().any(|configuration| {
                    !local_assignment_configuration_is_valid(
                        &configuration.core,
                        &configuration.supplement,
                    )
                }) {
                    return Err(SwmApnConfigurationError::new(
                        SwmApnConfigurationErrorCode::MobilityModeMismatch,
                    ));
                }
            }
            None => {
                return Err(SwmApnConfigurationError::new(
                    SwmApnConfigurationErrorCode::MobilityModeMismatch,
                ));
            }
        }
    }
    Ok(())
}

fn local_assignment_configuration_is_valid(
    core: &ApnConfiguration,
    supplement: &SwmApnConfigurationSupplement,
) -> bool {
    !supplement.requires_network_based_mobility(core) && supplement.mip6_agent_info.is_some()
}

fn requested_matches_configuration(
    requested: &SwmRequestedApn,
    core: &ApnConfiguration,
    supplement: Option<&SwmApnConfigurationSupplement>,
) -> bool {
    requested.matches_core(core)
        || matches!(requested, SwmRequestedApn::NetworkIdentifier(_))
            && core.service_selection.as_ref() == "*"
            && supplement.is_some_and(|supplement| {
                supplement.specific_apn_infos.iter().any(|specific| {
                    matches!(requested, SwmRequestedApn::NetworkIdentifier(identifier)
                        if specific.service_selection.as_str() == identifier.as_str())
                })
            })
}

fn validate_supplement_alignment(
    answer: &SwmDiameterEapAnswer,
) -> Result<(), SwmApnConfigurationError> {
    let supplements = &answer.extensions.apn_configurations;
    if supplements.is_empty() {
        return Ok(());
    }
    if supplements.len() != answer.apn_configurations.len()
        || supplements
            .iter()
            .zip(&answer.apn_configurations)
            .any(|(supplement, core)| supplement.bound_core.as_ref() != Some(core))
    {
        return Err(SwmApnConfigurationError::new(
            SwmApnConfigurationErrorCode::SupplementalCorrelationMismatch,
        ));
    }
    Ok(())
}

fn correlated_application_answer(
    response: &super::SwmCorrelatedDiameterEapResponse,
) -> Result<&SwmDiameterEapAnswer, SwmApnConfigurationError> {
    match response.response() {
        super::SwmDiameterEapResponse::Application(answer) => Ok(answer),
        super::SwmDiameterEapResponse::GenericError(_) => Err(SwmApnConfigurationError::new(
            SwmApnConfigurationErrorCode::ResultNotExactSuccess,
        )),
    }
}

fn configuration_views(answer: &SwmDiameterEapAnswer) -> SwmApnConfigurationViews<'_> {
    SwmApnConfigurationViews {
        cores: answer.apn_configurations.iter(),
        supplements: &answer.extensions.apn_configurations,
        index: 0,
    }
}

fn validate_structural_view_access(
    answer: &SwmDiameterEapAnswer,
) -> Result<(), SwmApnConfigurationError> {
    if answer.apn_configurations.len() > MAX_SWM_APN_CONFIGURATIONS {
        return Err(SwmApnConfigurationError::new(
            SwmApnConfigurationErrorCode::TooManyConfigurations,
        ));
    }
    if (!answer.apn_configurations.is_empty() || answer.default_context_identifier.is_some())
        && !answer.result.is_diameter_success()
    {
        return Err(SwmApnConfigurationError::new(
            SwmApnConfigurationErrorCode::ResultNotExactSuccess,
        ));
    }
    validate_supplement_alignment(answer)?;

    let mut context_identifiers = HashSet::with_capacity(answer.apn_configurations.len());
    let mut service_selections: Vec<&str> = Vec::with_capacity(answer.apn_configurations.len());
    for (index, core) in answer.apn_configurations.iter().enumerate() {
        if let Some(supplement) = answer.extensions.apn_configurations.get(index) {
            validate_wire_configuration(core, supplement)?;
        } else {
            validate_wire_configuration_values(core, &SwmApnConfigurationSupplement::unbound())?;
        }
        if !context_identifiers.insert(core.context_identifier) {
            return Err(SwmApnConfigurationError::new(
                SwmApnConfigurationErrorCode::DuplicateContextIdentifier,
            ));
        }
        if service_selections
            .iter()
            .any(|present| present.eq_ignore_ascii_case(core.service_selection.as_ref()))
        {
            return Err(SwmApnConfigurationError::new(
                SwmApnConfigurationErrorCode::DuplicateServiceSelection,
            ));
        }
        service_selections.push(core.service_selection.as_ref());
    }
    if let Some(default_context_identifier) = answer.default_context_identifier {
        if !context_identifiers.contains(&default_context_identifier) {
            return Err(SwmApnConfigurationError::new(
                SwmApnConfigurationErrorCode::DefaultContextIdentifierMissing,
            ));
        }
    }
    Ok(())
}

fn validate_authorized_view_access(
    answer: &SwmDiameterEapAnswer,
) -> Result<(), SwmApnConfigurationError> {
    validate_structural_view_access(answer)?;
    for (index, core) in answer.apn_configurations.iter().enumerate() {
        if let Some(supplement) = answer.extensions.apn_configurations.get(index) {
            validate_authorized_configuration(core, supplement)?;
        } else {
            validate_authorized_configuration_values(
                core,
                &SwmApnConfigurationSupplement::unbound(),
            )?;
        }
    }
    Ok(())
}

fn validate_authorized_configuration(
    core: &ApnConfiguration,
    supplement: &SwmApnConfigurationSupplement,
) -> Result<(), SwmApnConfigurationError> {
    validate_wire_configuration(core, supplement)?;
    validate_authorized_configuration_values_after_wire(core)
}

fn validate_authorized_configuration_values(
    core: &ApnConfiguration,
    supplement: &SwmApnConfigurationSupplement,
) -> Result<(), SwmApnConfigurationError> {
    validate_wire_configuration_values(core, supplement)?;
    validate_authorized_configuration_values_after_wire(core)
}

fn validate_authorized_configuration_values_after_wire(
    core: &ApnConfiguration,
) -> Result<(), SwmApnConfigurationError> {
    if core.service_selection.as_ref() == "*" {
        return Err(SwmApnConfigurationError::new(
            SwmApnConfigurationErrorCode::WildcardAuthorizationUnsupported,
        ));
    }
    validate_apn_network_identifier(core.service_selection.as_ref())?;
    if matches!(core.pdn_type, PdnType::Other(_)) {
        return Err(SwmApnConfigurationError::new(
            SwmApnConfigurationErrorCode::UnsupportedPdnType,
        ));
    }
    Ok(())
}

fn validate_originated_configuration(
    core: &ApnConfiguration,
    supplement: &SwmApnConfigurationSupplement,
) -> Result<(), SwmApnConfigurationError> {
    validate_wire_configuration(core, supplement)?;
    validate_originated_configuration_values_after_wire(core)
}

fn validate_originated_configuration_values(
    core: &ApnConfiguration,
    supplement: &SwmApnConfigurationSupplement,
) -> Result<(), SwmApnConfigurationError> {
    validate_wire_configuration_values(core, supplement)?;
    validate_originated_configuration_values_after_wire(core)
}

fn validate_originated_configuration_values_after_wire(
    core: &ApnConfiguration,
) -> Result<(), SwmApnConfigurationError> {
    if matches!(core.pdn_type, PdnType::Other(_)) {
        return Err(SwmApnConfigurationError::new(
            SwmApnConfigurationErrorCode::UnsupportedPdnType,
        ));
    }
    Ok(())
}

fn validate_wire_configuration(
    core: &ApnConfiguration,
    supplement: &SwmApnConfigurationSupplement,
) -> Result<(), SwmApnConfigurationError> {
    validate_wire_configuration_values(core, supplement)?;
    if supplement.bound_core.as_ref() != Some(core) {
        return Err(SwmApnConfigurationError::new(
            SwmApnConfigurationErrorCode::SupplementalCorrelationMismatch,
        ));
    }
    Ok(())
}

fn validate_wire_configuration_values(
    core: &ApnConfiguration,
    supplement: &SwmApnConfigurationSupplement,
) -> Result<(), SwmApnConfigurationError> {
    if core.context_identifier == 0 {
        return Err(SwmApnConfigurationError::new(
            SwmApnConfigurationErrorCode::ZeroContextIdentifier,
        ));
    }
    validate_wire_service_selection(core.service_selection.as_ref())?;
    if supplement.specific_apn_infos.len() > MAX_SPECIFIC_APN_INFOS {
        return Err(SwmApnConfigurationError::new(
            SwmApnConfigurationErrorCode::TooManySpecificApnInfos,
        ));
    }
    if !supplement.specific_apn_infos.is_empty() && core.service_selection.as_ref() != "*" {
        return Err(SwmApnConfigurationError::new(
            SwmApnConfigurationErrorCode::SpecificApnInfoRequiresWildcard,
        ));
    }
    validate_served_party_addresses(core.pdn_type, &supplement.served_party_ip_addresses)?;
    if supplement.pdn_gw_allocation_type.is_some() && supplement.mip6_agent_info.is_none() {
        return Err(SwmApnConfigurationError::new(
            SwmApnConfigurationErrorCode::AllocationWithoutGateway,
        ));
    }
    if supplement.visited_network_identifier.is_some()
        && supplement.pdn_gw_allocation_type != Some(SwmPdnGwAllocationType::Dynamic)
    {
        return Err(SwmApnConfigurationError::new(
            SwmApnConfigurationErrorCode::VisitedNetworkWithoutDynamicGateway,
        ));
    }
    Ok(())
}

fn validate_served_party_addresses(
    pdn_type: PdnType,
    addresses: &[IpAddr],
) -> Result<(), SwmApnConfigurationError> {
    if addresses.len() > MAX_SERVED_PARTY_IP_ADDRESSES {
        return Err(SwmApnConfigurationError::new(
            SwmApnConfigurationErrorCode::TooManyServedPartyAddresses,
        ));
    }
    let mut ipv4 = false;
    let mut ipv6 = false;
    for address in addresses {
        match address {
            IpAddr::V4(address) if !valid_static_ipv4(*address) => {
                return Err(SwmApnConfigurationError::new(
                    SwmApnConfigurationErrorCode::InvalidServedPartyAddress,
                ));
            }
            IpAddr::V4(_) if ipv4 => {
                return Err(SwmApnConfigurationError::new(
                    SwmApnConfigurationErrorCode::DuplicateServedPartyAddressFamily,
                ));
            }
            IpAddr::V4(_) => ipv4 = true,
            IpAddr::V6(address) if ipv6 => {
                return Err(SwmApnConfigurationError::new(
                    SwmApnConfigurationErrorCode::DuplicateServedPartyAddressFamily,
                ));
            }
            IpAddr::V6(address) if address.octets()[8..].iter().any(|octet| *octet != 0) => {
                return Err(SwmApnConfigurationError::new(
                    SwmApnConfigurationErrorCode::NoncanonicalIpv6Prefix,
                ));
            }
            IpAddr::V6(address) if !valid_static_ipv6(*address) => {
                return Err(SwmApnConfigurationError::new(
                    SwmApnConfigurationErrorCode::InvalidServedPartyAddress,
                ));
            }
            IpAddr::V6(_) => ipv6 = true,
        }
    }
    let compatible = match pdn_type {
        PdnType::Ipv4 => !ipv6,
        PdnType::Ipv6 => !ipv4,
        PdnType::Ipv4v6 | PdnType::Ipv4OrIpv6 => true,
        PdnType::Other(_) => addresses.is_empty(),
    };
    if !compatible {
        return Err(SwmApnConfigurationError::new(
            SwmApnConfigurationErrorCode::PdnTypeAddressMismatch,
        ));
    }
    Ok(())
}

fn validate_new_served_party_address(
    existing: &[IpAddr],
    address: IpAddr,
) -> Result<(), SwmApnConfigurationError> {
    if existing.len() >= MAX_SERVED_PARTY_IP_ADDRESSES {
        return Err(SwmApnConfigurationError::new(
            SwmApnConfigurationErrorCode::TooManyServedPartyAddresses,
        ));
    }
    if existing.iter().any(|present| {
        matches!(
            (present, address),
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
        )
    }) {
        return Err(SwmApnConfigurationError::new(
            SwmApnConfigurationErrorCode::DuplicateServedPartyAddressFamily,
        ));
    }
    if let IpAddr::V6(address) = address {
        if address.octets()[8..].iter().any(|octet| *octet != 0) {
            return Err(SwmApnConfigurationError::new(
                SwmApnConfigurationErrorCode::NoncanonicalIpv6Prefix,
            ));
        }
        if !valid_static_ipv6(address) {
            return Err(SwmApnConfigurationError::new(
                SwmApnConfigurationErrorCode::InvalidServedPartyAddress,
            ));
        }
    } else if let IpAddr::V4(address) = address {
        if !valid_static_ipv4(address) {
            return Err(SwmApnConfigurationError::new(
                SwmApnConfigurationErrorCode::InvalidServedPartyAddress,
            ));
        }
    }
    Ok(())
}

fn valid_static_ipv4(address: std::net::Ipv4Addr) -> bool {
    !address.is_unspecified()
        && !address.is_broadcast()
        && !address.is_multicast()
        && !address.is_loopback()
        && !address.is_link_local()
}

fn valid_static_ipv6(address: std::net::Ipv6Addr) -> bool {
    !address.is_unspecified()
        && !address.is_multicast()
        && !address.is_loopback()
        && !address.is_unicast_link_local()
}

fn validate_apn_network_identifier(value: &str) -> Result<(), SwmApnConfigurationError> {
    if value.is_empty() {
        return Err(SwmApnConfigurationError::new(
            SwmApnConfigurationErrorCode::EmptyServiceSelection,
        ));
    }
    let encoded_len = value.len().saturating_add(1);
    let reserved_prefix = ["rac", "lac", "sgsn", "rnc"].into_iter().any(|prefix| {
        value
            .get(..prefix.len())
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix))
    });
    let terminal_gprs = value
        .rsplit('.')
        .next()
        .is_some_and(|label| label.eq_ignore_ascii_case("gprs"));
    if value == "*"
        || encoded_len > 63
        || reserved_prefix
        || terminal_gprs
        || !value.is_ascii()
        || !value.split('.').all(|label| {
            let bytes = label.as_bytes();
            !bytes.is_empty()
                && bytes.len() <= 63
                && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
                && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
                && bytes
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        })
    {
        return Err(SwmApnConfigurationError::new(
            SwmApnConfigurationErrorCode::InvalidServiceSelection,
        ));
    }
    Ok(())
}

pub(super) fn valid_requested_apn(value: &str) -> bool {
    validate_wire_service_selection(value).is_ok()
}

pub(super) fn parse_requested_apn_wire_value(
    value: &[u8],
    value_offset: usize,
) -> Result<Redacted<String>, DecodeError> {
    parse_wire_service_selection_value(value, value_offset, true, "6.2")
}

fn parse_wire_service_selection_value(
    value: &[u8],
    value_offset: usize,
    allow_wildcard: bool,
    section: &'static str,
) -> Result<Redacted<String>, DecodeError> {
    let parsed =
        validate_wire_service_selection_bytes(value, value_offset, allow_wildcard, section)?;
    Ok(Redacted::from(parsed.to_owned()))
}

fn parse_specific_service_selection(
    value: &[u8],
    value_offset: usize,
) -> Result<SwmApnNetworkIdentifier, DecodeError> {
    let parsed = validate_wire_service_selection_bytes(value, value_offset, false, "7.3.82")?;
    SwmApnNetworkIdentifier::new(parsed)
        .map_err(|error| decode_configuration_error_for(error, value_offset, "7.3.82"))
}

fn validate_wire_service_selection_bytes<'a>(
    value: &'a [u8],
    value_offset: usize,
    allow_wildcard: bool,
    section: &'static str,
) -> Result<&'a str, DecodeError> {
    let parsed = str::from_utf8(value).map_err(|_| {
        DecodeError::new(
            DecodeErrorCode::Structural {
                reason: "Service-Selection must contain valid UTF-8",
            },
            value_offset,
        )
        .with_spec_ref(SpecRef::new("ietf", "RFC5778", "6.2"))
    })?;
    let validation = if allow_wildcard {
        validate_wire_service_selection(parsed)
    } else {
        validate_apn_network_identifier(parsed)
    };
    validation.map_err(|error| decode_configuration_error_for(error, value_offset, section))?;
    Ok(parsed)
}

fn validate_wire_service_selection(value: &str) -> Result<(), SwmApnConfigurationError> {
    if value == "*" {
        Ok(())
    } else {
        validate_apn_network_identifier(value)
    }
}

fn validate_vendor_mandatory(
    avp: &RawAvp<'_>,
    offset: usize,
    section: &'static str,
) -> Result<(), DecodeError> {
    if avp.header.vendor_id != Some(VENDOR_ID_3GPP) || avp.header.flags.is_protected() {
        return Err(flags_error(
            "APN child must set 3GPP V and clear P; received M is application-agnostic",
            offset,
            section,
        ));
    }
    Ok(())
}

fn validate_understood_outer_apn_flags(avp: &RawAvp<'_>, offset: usize) -> Result<(), DecodeError> {
    if avp.header.vendor_id != Some(VENDOR_ID_3GPP) || avp.header.flags.is_protected() {
        return Err(DecodeError::new(
            DecodeErrorCode::Structural {
                reason: "APN-Configuration must set 3GPP V and clear P",
            },
            offset,
        )
        .with_spec_ref(SpecRef::new("3gpp", "TS29273", "7.2.3.1/1 note 2")));
    }
    Ok(())
}

fn validate_understood_specific_apn_flags(
    avp: &RawAvp<'_>,
    offset: usize,
) -> Result<(), DecodeError> {
    if avp.header.code != AVP_SPECIFIC_APN_INFO
        || avp.header.vendor_id != Some(VENDOR_ID_3GPP)
        || avp.header.flags.is_protected()
    {
        return Err(flags_error(
            "Specific-APN-Info must use code 1472, set 3GPP V, and clear P; received M is application-agnostic",
            offset,
            "7.3.82",
        ));
    }
    Ok(())
}

fn validate_group_length(
    value: &[u8],
    minimum: usize,
    value_offset: usize,
    reason: &'static str,
    section: &'static str,
) -> Result<(), DecodeError> {
    if value.len() < minimum {
        return Err(
            DecodeError::new(DecodeErrorCode::InvalidLength { reason }, value_offset)
                .with_spec_ref(SpecRef::new("3gpp", "TS29272", section)),
        );
    }
    Ok(())
}

fn specific_missing_child(offset: usize, reason: &'static str) -> DecodeError {
    DecodeError::new(DecodeErrorCode::Structural { reason }, offset)
        .with_spec_ref(SpecRef::new("3gpp", "TS29272", "7.3.82"))
}

fn validate_served_party_ip_address_flags(
    avp: &RawAvp<'_>,
    offset: usize,
) -> Result<(), DecodeError> {
    if avp.header.vendor_id != Some(VENDOR_ID_3GPP) || avp.header.flags.is_protected() {
        return Err(DecodeError::new(
            DecodeErrorCode::Structural {
                reason:
                    "Served-Party-IP-Address must set 3GPP V and clear P; received M is application-agnostic",
            },
            offset,
        )
        .with_spec_ref(SpecRef::new("3gpp", "TS32299", "7.2.187")));
    }
    Ok(())
}

fn validate_vendor_optional(
    avp: &RawAvp<'_>,
    offset: usize,
    section: &'static str,
) -> Result<(), DecodeError> {
    if avp.header.vendor_id != Some(VENDOR_ID_3GPP) || avp.header.flags.is_protected() {
        return Err(flags_error(
            "APN child must set 3GPP V and clear P; received M is application-agnostic",
            offset,
            section,
        ));
    }
    Ok(())
}

fn validate_vendor_optional_protected_may(
    avp: &RawAvp<'_>,
    offset: usize,
    document: &'static str,
    section: &'static str,
) -> Result<(), DecodeError> {
    if avp.header.vendor_id != Some(VENDOR_ID_3GPP) {
        return Err(DecodeError::new(
            DecodeErrorCode::Structural {
                reason:
                    "APN child must set 3GPP V and may set P; received M is application-agnostic",
            },
            offset,
        )
        .with_spec_ref(SpecRef::new("3gpp", document, section)));
    }
    Ok(())
}

fn validate_base_mandatory(
    avp: &RawAvp<'_>,
    offset: usize,
    document: &'static str,
    section: &'static str,
) -> Result<(), DecodeError> {
    if avp.header.vendor_id.is_some() || avp.header.flags.is_protected() {
        return Err(DecodeError::new(
            DecodeErrorCode::Structural {
                reason: "APN base child must clear V/P; received M is application-agnostic",
            },
            offset,
        )
        .with_spec_ref(SpecRef::new("ietf", document, section)));
    }
    Ok(())
}

fn reject_zero_vendor(avp: &RawAvp<'_>, offset: usize) -> Result<(), DecodeError> {
    if avp.header.vendor_id.is_some_and(|vendor| vendor.get() == 0) {
        return Err(DecodeError::new(
            DecodeErrorCode::Structural {
                reason: "APN child Vendor-Id field must not contain zero",
            },
            offset,
        )
        .with_spec_ref(SpecRef::new("ietf", "RFC6733", "4.1.1")));
    }
    Ok(())
}

fn is_swm_inapplicable_child(key: crate::dictionary::AvpKey) -> bool {
    [
        AVP_LIPA_PERMISSION,
        AVP_RESTORATION_PRIORITY,
        AVP_SIPTO_LOCAL_NETWORK_PERMISSION,
        AVP_WLAN_OFFLOADABILITY,
        AVP_NON_IP_PDN_TYPE_INDICATOR,
        AVP_NON_IP_DATA_DELIVERY_MECHANISM,
        AVP_SCEF_ID,
        AVP_SCEF_REALM,
        AVP_PREFERRED_DATA_MODE,
    ]
    .into_iter()
    .any(|code| key == crate::dictionary::AvpKey::vendor(code, VENDOR_ID_3GPP))
}

fn append_sealed_extensions(
    dst: &mut BytesMut,
    avps: &[SwmAdditionalAvp],
    ctx: EncodeContext,
    section: &'static str,
) -> Result<(), EncodeError> {
    if avps.len() > MAX_SWM_DIAMETER_EAP_ROUTING_AVPS {
        return Err(encode_apn_error_for(
            "APN-Configuration extension count exceeds its bound",
            section,
        ));
    }
    for avp in avps {
        if avp.header().flags.is_mandatory()
            || avp
                .header()
                .vendor_id
                .is_some_and(|vendor| vendor.get() == 0)
        {
            return Err(encode_apn_error_for(
                "retained APN-Configuration extension is not safe to re-emit",
                section,
            ));
        }
        avp.append_to(dst, ctx)?;
    }
    Ok(())
}

fn invalid_enum(
    field: &'static str,
    value: u32,
    offset: usize,
    section: &'static str,
) -> DecodeError {
    DecodeError::new(
        DecodeErrorCode::InvalidEnumValue {
            field,
            value: u64::from(value),
        },
        offset,
    )
    .with_spec_ref(SpecRef::new("3gpp", "TS29272", section))
}

fn flags_error(reason: &'static str, offset: usize, section: &'static str) -> DecodeError {
    DecodeError::new(DecodeErrorCode::Structural { reason }, offset)
        .with_spec_ref(SpecRef::new("3gpp", "TS29272", section))
}

fn decode_configuration_error(error: SwmApnConfigurationError, offset: usize) -> DecodeError {
    decode_configuration_error_for(error, offset, "7.3.35")
}

fn decode_configuration_error_for(
    error: SwmApnConfigurationError,
    offset: usize,
    section: &'static str,
) -> DecodeError {
    let reason = match error.code() {
        SwmApnConfigurationErrorCode::TooManyServedPartyAddresses => {
            "APN-Configuration has too many Served-Party-IP-Address children"
        }
        SwmApnConfigurationErrorCode::DuplicateServedPartyAddressFamily => {
            "APN-Configuration repeats a Served-Party-IP-Address family"
        }
        SwmApnConfigurationErrorCode::NoncanonicalIpv6Prefix => {
            "APN-Configuration IPv6 served-party prefix has nonzero lower 64 bits"
        }
        SwmApnConfigurationErrorCode::InvalidServedPartyAddress => {
            "APN-Configuration served-party value is not an assignable static address"
        }
        SwmApnConfigurationErrorCode::PdnTypeAddressMismatch => {
            "APN-Configuration served-party address contradicts PDN-Type"
        }
        SwmApnConfigurationErrorCode::AllocationWithoutGateway => {
            "APN-Configuration PDN-GW-Allocation-Type requires MIP6-Agent-Info"
        }
        SwmApnConfigurationErrorCode::VisitedNetworkWithoutDynamicGateway => {
            "APN-Configuration Visited-Network-Identifier requires dynamic gateway allocation"
        }
        SwmApnConfigurationErrorCode::ZeroContextIdentifier => {
            "APN-Configuration Context-Identifier must not be zero"
        }
        SwmApnConfigurationErrorCode::EmptyServiceSelection => {
            "APN-Configuration Service-Selection must not be empty"
        }
        SwmApnConfigurationErrorCode::SupplementalCorrelationMismatch => {
            "APN-Configuration supplemental state does not match its complete core"
        }
        _ => "APN-Configuration values are inconsistent",
    };
    DecodeError::new(DecodeErrorCode::Structural { reason }, offset)
        .with_spec_ref(SpecRef::new("3gpp", "TS29272", section))
}

fn encode_apn_error(reason: &'static str) -> EncodeError {
    encode_apn_error_for(reason, "7.3.35")
}

fn encode_apn_error_for(reason: &'static str, section: &'static str) -> EncodeError {
    EncodeError::new(opc_protocol::EncodeErrorCode::Structural { reason })
        .with_spec_ref(SpecRef::new("3gpp", "TS29272", section))
}
