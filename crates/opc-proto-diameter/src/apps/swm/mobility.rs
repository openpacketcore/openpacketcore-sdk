//! RFC 5447 home-agent information and SWm gateway authorization context.
//!
//! The same [`SwmMip6AgentInfo`] codec is used for the top-level SWm DEA
//! `MIP6-Agent-Info` and the `MIP6-Agent-Info` nested in 3GPP
//! `Emergency-Info`. Parsed gateway identities are deliberately only wire
//! facts. Request-bound construction and correlated authorization use
//! separate types so consumers can distinguish syntactically valid wire facts
//! from a gateway accepted through an explicit caller-authorization boundary.

use bytes::{BufMut, BytesMut};
use opc_protocol::{
    DecodeContext, DecodeError, DecodeErrorCode, DuplicateIePolicy, EncodeContext, EncodeError,
    SpecRef, UnknownIePolicy,
};
use std::{collections::HashSet, error::Error, fmt, net::IpAddr, net::Ipv6Addr};

use super::{
    builder_helpers, lifecycle::SwmAdditionalAvp, DiameterEapRetention, Redacted,
    SwmDiameterEapAnswer, SwmDiameterEapRequest, SwmDiameterEapRequestEnvelope, SwmDiameterResult,
};
use crate::{base, AvpCode, AvpHeader, RawAvp};

/// RFC 5447 MIP6-Agent-Info AVP code.
pub const AVP_MIP6_AGENT_INFO: AvpCode = AvpCode::new(486);
/// RFC 4004 MIP-Home-Agent-Address AVP code.
pub const AVP_MIP_HOME_AGENT_ADDRESS: AvpCode = AvpCode::new(334);
/// RFC 4004 MIP-Home-Agent-Host AVP code.
pub const AVP_MIP_HOME_AGENT_HOST: AvpCode = AvpCode::new(348);
/// RFC 5447 MIP6-Home-Link-Prefix AVP code.
pub const AVP_MIP6_HOME_LINK_PREFIX: AvpCode = AvpCode::new(125);
/// 3GPP TS 29.272 Emergency-Info AVP code.
pub const AVP_EMERGENCY_INFO: AvpCode = AvpCode::new(1687);

pub(super) const MAX_MIP6_AGENT_INFO_CHILDREN: usize = 128;
const MAX_MIP6_AGENT_INFO_ADDRESSES: usize = 2;
const MIP6_HOME_LINK_PREFIX_VALUE_LEN: usize = 17;

/// Stable reason code for an invalid typed gateway identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SwmGatewayContextErrorCode {
    /// Neither a home-agent address nor a home-agent host was supplied.
    MissingGatewayIdentity,
    /// More than two home-agent addresses were supplied.
    TooManyGatewayAddresses,
    /// A DiameterIdentity was empty or contained non-ASCII data.
    InvalidGatewayHostIdentity,
    /// The home-link prefix length exceeded 128 bits.
    InvalidHomeLinkPrefixLength,
    /// Bits outside the declared home-link prefix were nonzero.
    NonzeroHomeLinkPrefixTrailingBits,
    /// The retained DER did not request emergency service.
    RequestNotEmergency,
    /// A request-bound context was used with a different DER.
    RequestBindingMismatch,
    /// Gateway authorization material did not accompany exact base success.
    ResultNotExactSuccess,
    /// Emergency gateway authorization was required but absent.
    EmergencyGatewayMissing,
}

/// Redaction-safe failure while constructing or authorizing gateway context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwmGatewayContextError {
    code: SwmGatewayContextErrorCode,
}

impl SwmGatewayContextError {
    const fn new(code: SwmGatewayContextErrorCode) -> Self {
        Self { code }
    }

    /// Return the stable machine-readable reason code.
    #[must_use]
    pub const fn code(self) -> SwmGatewayContextErrorCode {
        self.code
    }

    /// Return a stable, value-free diagnostic label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self.code {
            SwmGatewayContextErrorCode::MissingGatewayIdentity => "swm_gateway_identity_missing",
            SwmGatewayContextErrorCode::TooManyGatewayAddresses => {
                "swm_gateway_address_count_exceeded"
            }
            SwmGatewayContextErrorCode::InvalidGatewayHostIdentity => {
                "swm_gateway_host_identity_invalid"
            }
            SwmGatewayContextErrorCode::InvalidHomeLinkPrefixLength => {
                "swm_home_link_prefix_length_invalid"
            }
            SwmGatewayContextErrorCode::NonzeroHomeLinkPrefixTrailingBits => {
                "swm_home_link_prefix_trailing_bits_nonzero"
            }
            SwmGatewayContextErrorCode::RequestNotEmergency => "swm_request_not_emergency",
            SwmGatewayContextErrorCode::RequestBindingMismatch => {
                "swm_gateway_request_binding_mismatch"
            }
            SwmGatewayContextErrorCode::ResultNotExactSuccess => {
                "swm_gateway_result_not_exact_success"
            }
            SwmGatewayContextErrorCode::EmergencyGatewayMissing => "swm_emergency_gateway_missing",
        }
    }
}

impl fmt::Display for SwmGatewayContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Error for SwmGatewayContextError {}

/// Exact RFC 4004 host identity nested in MIP6-Agent-Info.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmMipHomeAgentHost {
    destination_realm: Redacted<String>,
    destination_host: Redacted<String>,
    additional_avps: Vec<SwmAdditionalAvp>,
}

impl SwmMipHomeAgentHost {
    /// Construct one nonempty ASCII Destination-Realm/Destination-Host pair.
    pub fn new(
        destination_realm: impl Into<String>,
        destination_host: impl Into<String>,
    ) -> Result<Self, SwmGatewayContextError> {
        let destination_realm = destination_realm.into();
        let destination_host = destination_host.into();
        if !valid_diameter_identity(&destination_realm)
            || !valid_diameter_identity(&destination_host)
        {
            return Err(SwmGatewayContextError::new(
                SwmGatewayContextErrorCode::InvalidGatewayHostIdentity,
            ));
        }
        Ok(Self {
            destination_realm: destination_realm.into(),
            destination_host: destination_host.into(),
            additional_avps: Vec::new(),
        })
    }

    /// Borrow the Destination-Realm value.
    #[must_use]
    pub fn destination_realm(&self) -> &str {
        self.destination_realm.as_ref()
    }

    /// Borrow the Destination-Host value.
    #[must_use]
    pub fn destination_host(&self) -> &str {
        self.destination_host.as_ref()
    }

    /// Return the number of sealed optional extension children.
    #[must_use]
    pub fn extension_count(&self) -> usize {
        self.additional_avps.len()
    }
}

impl fmt::Debug for SwmMipHomeAgentHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmMipHomeAgentHost")
            .field("destination_realm", &"<redacted>")
            .field("destination_host", &"<redacted>")
            .field("extension_count", &self.additional_avps.len())
            .finish()
    }
}

/// RFC 5447 IPv6 home-link prefix with canonical zero trailing bits.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SwmMip6HomeLinkPrefix {
    prefix_len: u8,
    prefix: Ipv6Addr,
}

impl SwmMip6HomeLinkPrefix {
    /// Construct a prefix, rejecting lengths above 128 and nonzero host bits.
    pub fn new(prefix: Ipv6Addr, prefix_len: u8) -> Result<Self, SwmGatewayContextError> {
        if prefix_len > 128 {
            return Err(SwmGatewayContextError::new(
                SwmGatewayContextErrorCode::InvalidHomeLinkPrefixLength,
            ));
        }
        if !prefix_has_zero_trailing_bits(prefix.octets(), prefix_len) {
            return Err(SwmGatewayContextError::new(
                SwmGatewayContextErrorCode::NonzeroHomeLinkPrefixTrailingBits,
            ));
        }
        Ok(Self { prefix_len, prefix })
    }

    /// Return the prefix length in bits.
    #[must_use]
    pub const fn prefix_len(self) -> u8 {
        self.prefix_len
    }

    /// Return the canonical IPv6 prefix value.
    #[must_use]
    pub const fn prefix(self) -> Ipv6Addr {
        self.prefix
    }
}

impl fmt::Debug for SwmMip6HomeLinkPrefix {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SwmMip6HomeLinkPrefix(<redacted>)")
    }
}

/// Identity selected from RFC 5447 MIP6-Agent-Info.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SwmMip6AgentSelection<'a> {
    /// One or two addresses, in received or configured order.
    Addresses(&'a [IpAddr]),
    /// The exact Destination-Realm/Destination-Host pair.
    Host(&'a SwmMipHomeAgentHost),
}

impl fmt::Debug for SwmMip6AgentSelection<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Addresses(addresses) => formatter
                .debug_tuple("SwmMip6AgentSelection::Addresses")
                .field(&format_args!("{} redacted address(es)", addresses.len()))
                .finish(),
            Self::Host(_) => formatter.write_str("SwmMip6AgentSelection::Host(<redacted>)"),
        }
    }
}

/// Canonical RFC 5447 MIP6-Agent-Info value.
///
/// Up to two addresses are retained in wire order. When addresses and a host
/// are both present, [`Self::selection`] returns the addresses, implementing
/// RFC 5447 section 4.2.1 precedence without discarding the host fallback.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmMip6AgentInfo {
    home_agent_addresses: Vec<IpAddr>,
    home_agent_host: Option<SwmMipHomeAgentHost>,
    home_link_prefix: Option<SwmMip6HomeLinkPrefix>,
    additional_avps: Vec<SwmAdditionalAvp>,
}

impl SwmMip6AgentInfo {
    /// Construct a bounded home-agent identity.
    pub fn new(
        home_agent_addresses: Vec<IpAddr>,
        home_agent_host: Option<SwmMipHomeAgentHost>,
        home_link_prefix: Option<SwmMip6HomeLinkPrefix>,
    ) -> Result<Self, SwmGatewayContextError> {
        validate_agent_identity(&home_agent_addresses, home_agent_host.as_ref())?;
        Ok(Self {
            home_agent_addresses,
            home_agent_host,
            home_link_prefix,
            additional_avps: Vec::new(),
        })
    }

    /// Borrow addresses in their received or configured order.
    #[must_use]
    pub fn home_agent_addresses(&self) -> &[IpAddr] {
        &self.home_agent_addresses
    }

    /// Borrow the optional host fallback.
    #[must_use]
    pub const fn home_agent_host(&self) -> Option<&SwmMipHomeAgentHost> {
        self.home_agent_host.as_ref()
    }

    /// Return the optional home-link prefix.
    #[must_use]
    pub const fn home_link_prefix(&self) -> Option<SwmMip6HomeLinkPrefix> {
        self.home_link_prefix
    }

    /// Select the RFC-preferred identity without discarding alternatives.
    ///
    /// Values produced by the public constructor or decoder always return
    /// `Some`; the optional shape keeps the accessor total without relying on
    /// a panic if an invariant is broken by future internal changes.
    #[must_use]
    pub fn selection(&self) -> Option<SwmMip6AgentSelection<'_>> {
        if self.home_agent_addresses.is_empty() {
            self.home_agent_host
                .as_ref()
                .map(SwmMip6AgentSelection::Host)
        } else {
            Some(SwmMip6AgentSelection::Addresses(&self.home_agent_addresses))
        }
    }

    /// Return the number of sealed optional extension children.
    #[must_use]
    pub fn extension_count(&self) -> usize {
        self.additional_avps.len()
    }
}

impl fmt::Debug for SwmMip6AgentInfo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmMip6AgentInfo")
            .field("address_count", &self.home_agent_addresses.len())
            .field("host_present", &self.home_agent_host.is_some())
            .field("home_link_prefix_present", &self.home_link_prefix.is_some())
            .field("extension_count", &self.additional_avps.len())
            .finish()
    }
}

/// 3GPP Emergency-Info value backed by the canonical RFC 5447 codec.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmEmergencyInfo {
    pdn_gateway: SwmMip6AgentInfo,
    additional_avps: Vec<SwmAdditionalAvp>,
}

impl SwmEmergencyInfo {
    fn new(pdn_gateway: SwmMip6AgentInfo) -> Self {
        Self {
            pdn_gateway,
            additional_avps: Vec::new(),
        }
    }

    /// Borrow the emergency PDN-GW identity.
    #[must_use]
    pub const fn pdn_gateway(&self) -> &SwmMip6AgentInfo {
        &self.pdn_gateway
    }

    /// Return the number of sealed optional Emergency-Info children.
    #[must_use]
    pub fn extension_count(&self) -> usize {
        self.additional_avps.len()
    }
}

impl fmt::Debug for SwmEmergencyInfo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmEmergencyInfo")
            .field("pdn_gateway", &"<redacted>")
            .field("extension_count", &self.additional_avps.len())
            .finish()
    }
}

/// Parsed or request-bound gateway fields carried by one SWm DEA.
///
/// Accessors expose untrusted wire facts. Received clients should prefer the
/// authorization methods on [`super::SwmCorrelatedDiameterEapResponse`]; a
/// trusted originated/server boundary can use
/// [`super::SwmCorrelatedDiameterEapExchange`].
#[derive(Clone, PartialEq, Eq, Default)]
pub struct SwmDeaGatewayContext {
    pub(super) chained_s2b_s8_serving_gateway: Option<SwmMip6AgentInfo>,
    pub(super) emergency_info: Option<SwmEmergencyInfo>,
}

impl SwmDeaGatewayContext {
    /// Borrow the optional top-level chained-S2b-S8 serving-gateway identity.
    #[must_use]
    pub const fn chained_s2b_s8_serving_gateway(&self) -> Option<&SwmMip6AgentInfo> {
        self.chained_s2b_s8_serving_gateway.as_ref()
    }

    /// Borrow untrusted parsed Emergency-Info wire material.
    #[must_use]
    pub const fn emergency_info(&self) -> Option<&SwmEmergencyInfo> {
        self.emergency_info.as_ref()
    }

    /// Return whether neither gateway field is present.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.chained_s2b_s8_serving_gateway.is_none() && self.emergency_info.is_none()
    }
}

impl fmt::Debug for SwmDeaGatewayContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmDeaGatewayContext")
            .field(
                "chained_s2b_s8_serving_gateway_present",
                &self.chained_s2b_s8_serving_gateway.is_some(),
            )
            .field("emergency_info_present", &self.emergency_info.is_some())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
struct SwmDeaRequestBinding {
    request: SwmDiameterEapRequestEnvelope,
}

impl SwmDeaRequestBinding {
    fn new(request: &SwmDiameterEapRequestEnvelope) -> Self {
        Self {
            request: request.clone(),
        }
    }

    fn matches(&self, request: &SwmDiameterEapRequestEnvelope) -> bool {
        self.request.transaction() == request.transaction()
            && self.request.same_replay_payload(request)
    }
}

impl fmt::Debug for SwmDeaRequestBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmDeaRequestBinding")
            .field("transaction", &self.request.transaction())
            .field("request", &"<redacted>")
            .finish()
    }
}

/// Request-bound outbound SWm DEA gateway authorization material.
///
/// This type has no raw-boolean condition setter. Its constructors name and
/// bind the exact standards condition being asserted by the trusted AAA or
/// local-routing boundary.
#[derive(Clone, PartialEq, Eq)]
pub struct SwmRequestBoundDeaGatewayContext {
    binding: SwmDeaRequestBinding,
    context: SwmDeaGatewayContext,
}

impl SwmRequestBoundDeaGatewayContext {
    /// Bind a chained-S2b-S8 Serving-GW identity to one exact DER.
    #[must_use]
    pub fn chained_s2b_s8(
        request: &SwmDiameterEapRequestEnvelope,
        serving_gateway: SwmMip6AgentInfo,
    ) -> Self {
        Self {
            binding: SwmDeaRequestBinding::new(request),
            context: SwmDeaGatewayContext {
                chained_s2b_s8_serving_gateway: Some(serving_gateway),
                emergency_info: None,
            },
        }
    }

    /// Bind an HSS-derived emergency PDN-GW for an authenticated non-roaming
    /// user to one exact emergency DER.
    pub fn authenticated_non_roaming_emergency_from_hss(
        request: &SwmDiameterEapRequestEnvelope,
        pdn_gateway: SwmMip6AgentInfo,
    ) -> Result<Self, SwmGatewayContextError> {
        ensure_emergency_request(request.request())?;
        Ok(Self {
            binding: SwmDeaRequestBinding::new(request),
            context: SwmDeaGatewayContext {
                chained_s2b_s8_serving_gateway: None,
                emergency_info: Some(SwmEmergencyInfo::new(pdn_gateway)),
            },
        })
    }

    /// Add HSS-derived authenticated non-roaming emergency context for the
    /// same exact DER already bound to this value.
    pub fn with_authenticated_non_roaming_emergency_from_hss(
        mut self,
        request: &SwmDiameterEapRequestEnvelope,
        pdn_gateway: SwmMip6AgentInfo,
    ) -> Result<Self, SwmGatewayContextError> {
        if !self.binding.matches(request) {
            return Err(SwmGatewayContextError::new(
                SwmGatewayContextErrorCode::RequestBindingMismatch,
            ));
        }
        ensure_emergency_request(request.request())?;
        self.context.emergency_info = Some(SwmEmergencyInfo::new(pdn_gateway));
        Ok(self)
    }

    pub(super) fn validate_for(
        &self,
        request: &SwmDiameterEapRequestEnvelope,
        result: SwmDiameterResult,
    ) -> Result<(), SwmGatewayContextError> {
        if !self.binding.matches(request) {
            return Err(SwmGatewayContextError::new(
                SwmGatewayContextErrorCode::RequestBindingMismatch,
            ));
        }
        if !result.is_diameter_success() {
            return Err(SwmGatewayContextError::new(
                SwmGatewayContextErrorCode::ResultNotExactSuccess,
            ));
        }
        if self.context.emergency_info.is_some() {
            ensure_emergency_request(request.request())?;
        }
        Ok(())
    }

    pub(super) const fn context(&self) -> &SwmDeaGatewayContext {
        &self.context
    }
}

impl fmt::Debug for SwmRequestBoundDeaGatewayContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SwmRequestBoundDeaGatewayContext")
            .field("binding", &self.binding)
            .field("context", &self.context)
            .finish()
    }
}

/// Caller assertion supplied by the trusted local routing boundary.
///
/// Construction records the call site's assertion; it does not independently
/// prove deployment routing state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwmChainedS2bS8Authorization {
    _private: (),
}

impl SwmChainedS2bS8Authorization {
    /// Assert that the correlated exchange belongs to a chained S2b-S8 flow.
    #[must_use]
    pub const fn from_trusted_routing_context() -> Self {
        Self { _private: () }
    }
}

/// Caller assertion supplied by the trusted AAA/session boundary.
///
/// Construction records the call site's assertion; it does not independently
/// prove authentication, roaming status, or HSS provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwmAuthenticatedNonRoamingEmergencyAuthorization {
    _private: (),
}

impl SwmAuthenticatedNonRoamingEmergencyAuthorization {
    /// Assert authenticated, non-roaming status and HSS provenance.
    #[must_use]
    pub const fn from_trusted_hss_context() -> Self {
        Self { _private: () }
    }
}

/// Opaque result of request correlation plus explicit caller authorization.
///
/// The result records that the SDK checks and the caller assertion completed;
/// it is not independent proof of the caller-owned routing or AAA facts.
pub struct SwmAuthorizedGateway<'a> {
    gateway: &'a SwmMip6AgentInfo,
}

impl SwmAuthorizedGateway<'_> {
    /// Borrow the authorized canonical gateway identity.
    #[must_use]
    pub const fn gateway(&self) -> &SwmMip6AgentInfo {
        self.gateway
    }
}

impl fmt::Debug for SwmAuthorizedGateway<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SwmAuthorizedGateway(<redacted>)")
    }
}

pub(super) fn authorize_chained_gateway<'a>(
    answer: &'a SwmDiameterEapAnswer,
    _authorization: SwmChainedS2bS8Authorization,
) -> Result<Option<SwmAuthorizedGateway<'a>>, SwmGatewayContextError> {
    if !answer.result.is_diameter_success() {
        return Err(SwmGatewayContextError::new(
            SwmGatewayContextErrorCode::ResultNotExactSuccess,
        ));
    }
    Ok(answer
        .gateway_context()
        .chained_s2b_s8_serving_gateway()
        .map(|gateway| SwmAuthorizedGateway { gateway }))
}

pub(super) fn authorize_emergency_gateway<'a>(
    request: &SwmDiameterEapRequest,
    answer: &'a SwmDiameterEapAnswer,
    _authorization: SwmAuthenticatedNonRoamingEmergencyAuthorization,
) -> Result<SwmAuthorizedGateway<'a>, SwmGatewayContextError> {
    if !answer.result.is_diameter_success() {
        return Err(SwmGatewayContextError::new(
            SwmGatewayContextErrorCode::ResultNotExactSuccess,
        ));
    }
    ensure_emergency_request(request)?;
    let emergency = answer.gateway_context().emergency_info().ok_or_else(|| {
        SwmGatewayContextError::new(SwmGatewayContextErrorCode::EmergencyGatewayMissing)
    })?;
    Ok(SwmAuthorizedGateway {
        gateway: emergency.pdn_gateway(),
    })
}

pub(super) fn gateway_context_unavailable() -> SwmGatewayContextError {
    SwmGatewayContextError::new(SwmGatewayContextErrorCode::ResultNotExactSuccess)
}

pub(super) fn append_gateway_context(
    dst: &mut BytesMut,
    context: &SwmDeaGatewayContext,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    if let Some(serving_gateway) = context.chained_s2b_s8_serving_gateway.as_ref() {
        append_mip6_agent_info_avp(dst, serving_gateway, ctx)?;
    }
    if let Some(emergency_info) = context.emergency_info.as_ref() {
        append_emergency_info_avp(dst, emergency_info, ctx)?;
    }
    Ok(())
}

fn append_mip6_agent_info_avp(
    dst: &mut BytesMut,
    info: &SwmMip6AgentInfo,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    validate_agent_identity(&info.home_agent_addresses, info.home_agent_host.as_ref())
        .map_err(|_| encode_gateway_error("MIP6-Agent-Info identity is invalid", "4.2.1"))?;
    let mut value = BytesMut::new();
    for address in &info.home_agent_addresses {
        let mut address_value = BytesMut::new();
        builder_helpers::encode_address_value(&mut address_value, *address);
        builder_helpers::append_avp(
            &mut value,
            AvpHeader::ietf(AVP_MIP_HOME_AGENT_ADDRESS, true),
            &address_value,
            ctx,
        )?;
    }
    if let Some(host) = info.home_agent_host.as_ref() {
        append_mip_home_agent_host_avp(&mut value, host, ctx)?;
    }
    if let Some(prefix) = info.home_link_prefix {
        let mut prefix_value = BytesMut::with_capacity(MIP6_HOME_LINK_PREFIX_VALUE_LEN);
        prefix_value.put_u8(prefix.prefix_len());
        prefix_value.extend_from_slice(&prefix.prefix().octets());
        builder_helpers::append_avp(
            &mut value,
            AvpHeader::ietf(AVP_MIP6_HOME_LINK_PREFIX, true),
            &prefix_value,
            ctx,
        )?;
    }
    append_sealed_extensions(&mut value, &info.additional_avps, ctx, "4.2.1")?;
    builder_helpers::append_avp(dst, AvpHeader::ietf(AVP_MIP6_AGENT_INFO, true), &value, ctx)
}

fn append_mip_home_agent_host_avp(
    dst: &mut BytesMut,
    host: &SwmMipHomeAgentHost,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    if !valid_diameter_identity(host.destination_realm())
        || !valid_diameter_identity(host.destination_host())
    {
        return Err(encode_gateway_error(
            "MIP-Home-Agent-Host identities are invalid",
            "7.11",
        ));
    }
    let mut value = BytesMut::new();
    builder_helpers::append_utf8_avp(
        &mut value,
        base::AVP_DESTINATION_REALM,
        host.destination_realm(),
        true,
        ctx,
    )?;
    builder_helpers::append_utf8_avp(
        &mut value,
        base::AVP_DESTINATION_HOST,
        host.destination_host(),
        true,
        ctx,
    )?;
    append_sealed_extensions(&mut value, &host.additional_avps, ctx, "7.11")?;
    builder_helpers::append_avp(
        dst,
        AvpHeader::ietf(AVP_MIP_HOME_AGENT_HOST, true),
        &value,
        ctx,
    )
}

fn append_emergency_info_avp(
    dst: &mut BytesMut,
    emergency: &SwmEmergencyInfo,
    ctx: EncodeContext,
) -> Result<(), EncodeError> {
    let mut value = BytesMut::new();
    append_mip6_agent_info_avp(&mut value, emergency.pdn_gateway(), ctx)?;
    append_sealed_extensions(&mut value, &emergency.additional_avps, ctx, "7.3.210")?;
    builder_helpers::append_avp(
        dst,
        AvpHeader::vendor(AVP_EMERGENCY_INFO, super::VENDOR_ID_3GPP, false),
        &value,
        ctx,
    )
}

pub(super) fn parse_mip6_agent_info(
    avp: &RawAvp<'_>,
    ctx: DecodeContext,
    outer_offset: usize,
    value_offset: usize,
    depth: usize,
    retention: &mut DiameterEapRetention,
) -> Result<SwmMip6AgentInfo, DecodeError> {
    validate_swm_mip6_agent_info_outer(avp, outer_offset)?;
    let mut addresses = Vec::new();
    let mut host = None;
    let mut prefix = None;
    let mut additional_avps = Vec::new();
    let mut additional_keys = HashSet::new();
    let mut child_count = 0usize;
    builder_helpers::for_each_avp(avp.value, ctx, value_offset, depth, |offset, child| {
        account_group_child(&mut child_count, offset, "4.2.1")?;
        reject_zero_vendor(&child, offset, "4.2.1")?;
        let child_value_offset =
            builder_helpers::offset_add(offset, child.header.header_len(), "4.2.1")?;
        match child.header.code {
            AVP_MIP_HOME_AGENT_ADDRESS => {
                validate_known_base_avp(&child, offset, AVP_MIP_HOME_AGENT_ADDRESS, "4.2.2")?;
                if addresses.len() >= MAX_MIP6_AGENT_INFO_ADDRESSES {
                    return Err(DecodeError::new(DecodeErrorCode::IeCountExceeded, offset)
                        .with_spec_ref(SpecRef::new("ietf", "RFC5447", "4.2.1")));
                }
                let address =
                    builder_helpers::parse_address_value(child.value, child_value_offset, "4.2.2")?;
                addresses.push(address);
            }
            AVP_MIP_HOME_AGENT_HOST => {
                validate_known_base_avp(&child, offset, AVP_MIP_HOME_AGENT_HOST, "4.2.3")?;
                let parsed = parse_mip_home_agent_host(
                    child.value,
                    ctx,
                    child_value_offset,
                    depth + 1,
                    retention,
                )?;
                builder_helpers::set_once(&mut host, parsed, offset, "4.2.1")?;
            }
            AVP_MIP6_HOME_LINK_PREFIX => {
                validate_known_base_avp(&child, offset, AVP_MIP6_HOME_LINK_PREFIX, "4.2.4")?;
                let parsed = parse_home_link_prefix(child.value, child_value_offset)?;
                builder_helpers::set_once(&mut prefix, parsed, offset, "4.2.1")?;
            }
            _ => retain_unknown_child(
                &child,
                ctx,
                offset,
                "4.2.1",
                &mut additional_keys,
                retention,
                &mut additional_avps,
            )?,
        }
        Ok(())
    })?;
    validate_agent_identity(&addresses, host.as_ref()).map_err(|error| {
        decode_gateway_error_at(error_reason(error.code()), value_offset, "4.2.1")
    })?;
    Ok(SwmMip6AgentInfo {
        home_agent_addresses: addresses,
        home_agent_host: host,
        home_link_prefix: prefix,
        additional_avps,
    })
}

pub(super) fn parse_emergency_info(
    avp: &RawAvp<'_>,
    ctx: DecodeContext,
    outer_offset: usize,
    value_offset: usize,
    depth: usize,
    retention: &mut DiameterEapRetention,
) -> Result<SwmEmergencyInfo, DecodeError> {
    validate_emergency_outer(avp, outer_offset)?;
    let mut pdn_gateway = None;
    let mut additional_avps = Vec::new();
    let mut additional_keys = HashSet::new();
    let mut child_count = 0usize;
    builder_helpers::for_each_avp(avp.value, ctx, value_offset, depth, |offset, child| {
        account_group_child(&mut child_count, offset, "7.3.210")?;
        reject_zero_vendor(&child, offset, "7.3.210")?;
        let child_value_offset =
            builder_helpers::offset_add(offset, child.header.header_len(), "7.3.210")?;
        if child.header.code == AVP_MIP6_AGENT_INFO {
            let parsed = parse_mip6_agent_info(
                &child,
                ctx,
                offset,
                child_value_offset,
                depth + 1,
                retention,
            )?;
            builder_helpers::set_once(&mut pdn_gateway, parsed, offset, "7.3.210")?;
        } else {
            retain_unknown_child(
                &child,
                ctx,
                offset,
                "7.3.210",
                &mut additional_keys,
                retention,
                &mut additional_avps,
            )?;
        }
        Ok(())
    })?;
    let pdn_gateway = pdn_gateway.ok_or_else(|| {
        decode_gateway_error_at(
            "Emergency-Info requires MIP6-Agent-Info",
            value_offset,
            "7.3.210",
        )
    })?;
    Ok(SwmEmergencyInfo {
        pdn_gateway,
        additional_avps,
    })
}

fn parse_mip_home_agent_host(
    value: &[u8],
    ctx: DecodeContext,
    base_offset: usize,
    depth: usize,
    retention: &mut DiameterEapRetention,
) -> Result<SwmMipHomeAgentHost, DecodeError> {
    let mut destination_realm = None;
    let mut destination_host = None;
    let mut additional_avps = Vec::new();
    let mut additional_keys = HashSet::new();
    let mut child_count = 0usize;
    builder_helpers::for_each_avp(value, ctx, base_offset, depth, |offset, child| {
        account_group_child(&mut child_count, offset, "7.11")?;
        reject_zero_vendor(&child, offset, "7.11")?;
        let child_value_offset =
            builder_helpers::offset_add(offset, child.header.header_len(), "7.11")?;
        match child.header.code {
            base::AVP_DESTINATION_REALM => {
                validate_known_base_avp(&child, offset, base::AVP_DESTINATION_REALM, "6.6")?;
                let parsed = parse_diameter_identity(child.value, child_value_offset, "6.6")?;
                builder_helpers::set_once(&mut destination_realm, parsed, offset, "7.11")?;
            }
            base::AVP_DESTINATION_HOST => {
                validate_known_base_avp(&child, offset, base::AVP_DESTINATION_HOST, "6.5")?;
                let parsed = parse_diameter_identity(child.value, child_value_offset, "6.5")?;
                builder_helpers::set_once(&mut destination_host, parsed, offset, "7.11")?;
            }
            _ => retain_unknown_child(
                &child,
                ctx,
                offset,
                "7.11",
                &mut additional_keys,
                retention,
                &mut additional_avps,
            )?,
        }
        Ok(())
    })?;
    let destination_realm = destination_realm.ok_or_else(|| {
        decode_gateway_error_at(
            "MIP-Home-Agent-Host requires Destination-Realm",
            base_offset,
            "7.11",
        )
    })?;
    let destination_host = destination_host.ok_or_else(|| {
        decode_gateway_error_at(
            "MIP-Home-Agent-Host requires Destination-Host",
            base_offset,
            "7.11",
        )
    })?;
    Ok(SwmMipHomeAgentHost {
        destination_realm,
        destination_host,
        additional_avps,
    })
}

fn parse_home_link_prefix(
    value: &[u8],
    value_offset: usize,
) -> Result<SwmMip6HomeLinkPrefix, DecodeError> {
    if value.len() != MIP6_HOME_LINK_PREFIX_VALUE_LEN {
        return Err(DecodeError::new(
            DecodeErrorCode::InvalidLength {
                reason: "MIP6-Home-Link-Prefix must contain 17 octets",
            },
            value_offset,
        )
        .with_spec_ref(SpecRef::new("ietf", "RFC5447", "4.2.4")));
    }
    let prefix_len = value[0];
    let mut octets = [0_u8; 16];
    octets.copy_from_slice(&value[1..]);
    SwmMip6HomeLinkPrefix::new(Ipv6Addr::from(octets), prefix_len)
        .map_err(|error| decode_gateway_error_at(error_reason(error.code()), value_offset, "4.2.4"))
}

fn validate_agent_identity(
    addresses: &[IpAddr],
    host: Option<&SwmMipHomeAgentHost>,
) -> Result<(), SwmGatewayContextError> {
    if addresses.is_empty() && host.is_none() {
        return Err(SwmGatewayContextError::new(
            SwmGatewayContextErrorCode::MissingGatewayIdentity,
        ));
    }
    if addresses.len() > MAX_MIP6_AGENT_INFO_ADDRESSES {
        return Err(SwmGatewayContextError::new(
            SwmGatewayContextErrorCode::TooManyGatewayAddresses,
        ));
    }
    Ok(())
}

fn ensure_emergency_request(request: &SwmDiameterEapRequest) -> Result<(), SwmGatewayContextError> {
    if request.requests_emergency_services() {
        Ok(())
    } else {
        Err(SwmGatewayContextError::new(
            SwmGatewayContextErrorCode::RequestNotEmergency,
        ))
    }
}

fn valid_diameter_identity(value: &str) -> bool {
    !value.is_empty() && value.is_ascii()
}

fn prefix_has_zero_trailing_bits(octets: [u8; 16], prefix_len: u8) -> bool {
    let full_octets = usize::from(prefix_len / 8);
    let partial_bits = prefix_len % 8;
    let trailing_start = if partial_bits == 0 {
        full_octets
    } else {
        let trailing_mask = (1_u8 << (8 - partial_bits)) - 1;
        if octets[full_octets] & trailing_mask != 0 {
            return false;
        }
        full_octets + 1
    };
    octets[trailing_start..].iter().all(|octet| *octet == 0)
}

fn parse_diameter_identity(
    value: &[u8],
    value_offset: usize,
    section: &'static str,
) -> Result<Redacted<String>, DecodeError> {
    let parsed = builder_helpers::parse_string_value(value, value_offset, section)?;
    if !valid_diameter_identity(&parsed) {
        return Err(decode_gateway_error_at(
            "DiameterIdentity must be nonempty ASCII",
            value_offset,
            section,
        ));
    }
    Ok(parsed.into())
}

fn validate_known_base_avp(
    avp: &RawAvp<'_>,
    offset: usize,
    expected_code: AvpCode,
    section: &'static str,
) -> Result<(), DecodeError> {
    if avp.header.code != expected_code
        || avp.header.vendor_id.is_some()
        || !avp.header.flags.is_mandatory()
        || avp.header.flags.is_protected()
    {
        return Err(decode_gateway_error_at(
            "known mobility AVP must use its base identity, set M, and clear V/P",
            offset,
            section,
        ));
    }
    Ok(())
}

fn validate_swm_mip6_agent_info_outer(avp: &RawAvp<'_>, offset: usize) -> Result<(), DecodeError> {
    if avp.header.code != AVP_MIP6_AGENT_INFO
        || avp.header.vendor_id.is_some()
        || avp.header.flags.is_protected()
    {
        return Err(DecodeError::new(
            DecodeErrorCode::Structural {
                reason: "SWm MIP6-Agent-Info must clear V/P",
            },
            offset,
        )
        .with_spec_ref(SpecRef::new("3gpp", "TS29273", "7.2.3.1/2 note 2")));
    }
    Ok(())
}

fn validate_emergency_outer(avp: &RawAvp<'_>, offset: usize) -> Result<(), DecodeError> {
    if avp.header.code != AVP_EMERGENCY_INFO {
        return Err(decode_gateway_error_at(
            "Emergency-Info uses an unexpected AVP code",
            offset,
            "7.3.210",
        ));
    }
    // TS 29.272 table 7.3.1 permits either M-bit value for Emergency-Info,
    // while requiring the 3GPP V bit and prohibiting P. Keep that contract
    // explicit instead of accidentally accepting flags not named by the spec.
    super::validate_3gpp_m_bit_agnostic_flags(&avp.header, offset, "TS29272", "7.3.210")
}

fn reject_zero_vendor(
    avp: &RawAvp<'_>,
    offset: usize,
    _section: &'static str,
) -> Result<(), DecodeError> {
    if avp.header.vendor_id.is_some_and(|vendor| vendor.get() == 0) {
        return Err(DecodeError::new(
            DecodeErrorCode::Structural {
                reason: "nested mobility AVP Vendor-Id field must not contain zero",
            },
            offset,
        )
        .with_spec_ref(SpecRef::new("ietf", "RFC6733", "4.1.1")));
    }
    Ok(())
}

fn account_group_child(
    child_count: &mut usize,
    offset: usize,
    section: &'static str,
) -> Result<(), DecodeError> {
    if *child_count >= MAX_MIP6_AGENT_INFO_CHILDREN {
        return Err(DecodeError::new(DecodeErrorCode::IeCountExceeded, offset)
            .with_spec_ref(SpecRef::new("ietf", "RFC5447", section)));
    }
    *child_count += 1;
    Ok(())
}

fn retain_unknown_child(
    avp: &RawAvp<'_>,
    ctx: DecodeContext,
    offset: usize,
    section: &'static str,
    additional_keys: &mut HashSet<crate::dictionary::AvpKey>,
    retention: &mut DiameterEapRetention,
    additional_avps: &mut Vec<SwmAdditionalAvp>,
) -> Result<(), DecodeError> {
    if avp.header.flags.is_mandatory() || ctx.unknown_ie_policy == UnknownIePolicy::Reject {
        return builder_helpers::handle_unknown_avp(ctx, avp, offset, section);
    }
    if ctx.duplicate_ie_policy == DuplicateIePolicy::Reject
        && !additional_keys.insert(avp.header.key())
    {
        return Err(DecodeError::new(DecodeErrorCode::DuplicateIe, offset)
            .with_spec_ref(SpecRef::new("ietf", "RFC5447", section)));
    }
    if ctx.unknown_ie_policy == UnknownIePolicy::Preserve {
        retention.account(avp, offset, section, ctx)?;
        additional_avps.push(SwmAdditionalAvp::from_raw_exact(avp));
    }
    Ok(())
}

fn append_sealed_extensions(
    dst: &mut BytesMut,
    additional_avps: &[SwmAdditionalAvp],
    ctx: EncodeContext,
    section: &'static str,
) -> Result<(), EncodeError> {
    if additional_avps.len() > MAX_MIP6_AGENT_INFO_CHILDREN {
        return Err(encode_gateway_error(
            "mobility extension child count exceeds its bound",
            section,
        ));
    }
    for avp in additional_avps {
        if avp.header().flags.is_mandatory()
            || avp
                .header()
                .vendor_id
                .is_some_and(|vendor| vendor.get() == 0)
        {
            return Err(encode_gateway_error(
                "sealed mobility extension child is invalid",
                section,
            ));
        }
        avp.append_to(dst, ctx)?;
    }
    Ok(())
}

fn error_reason(code: SwmGatewayContextErrorCode) -> &'static str {
    match code {
        SwmGatewayContextErrorCode::MissingGatewayIdentity => {
            "MIP6-Agent-Info requires an address or host identity"
        }
        SwmGatewayContextErrorCode::TooManyGatewayAddresses => {
            "MIP6-Agent-Info contains more than two addresses"
        }
        SwmGatewayContextErrorCode::InvalidGatewayHostIdentity => {
            "MIP-Home-Agent-Host identity is invalid"
        }
        SwmGatewayContextErrorCode::InvalidHomeLinkPrefixLength => {
            "MIP6-Home-Link-Prefix length exceeds 128"
        }
        SwmGatewayContextErrorCode::NonzeroHomeLinkPrefixTrailingBits => {
            "MIP6-Home-Link-Prefix has nonzero trailing bits"
        }
        SwmGatewayContextErrorCode::RequestNotEmergency
        | SwmGatewayContextErrorCode::RequestBindingMismatch
        | SwmGatewayContextErrorCode::ResultNotExactSuccess
        | SwmGatewayContextErrorCode::EmergencyGatewayMissing => {
            "SWm gateway authorization context is invalid"
        }
    }
}

fn encode_gateway_error(reason: &'static str, section: &'static str) -> EncodeError {
    EncodeError::new(opc_protocol::EncodeErrorCode::Structural { reason })
        .with_spec_ref(SpecRef::new("ietf", "RFC5447", section))
}

fn decode_gateway_error_at(
    reason: &'static str,
    offset: usize,
    section: &'static str,
) -> DecodeError {
    DecodeError::new(DecodeErrorCode::Structural { reason }, offset)
        .with_spec_ref(SpecRef::new("ietf", "RFC5447", section))
}
